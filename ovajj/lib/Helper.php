<?php
/**
 * Ovajj Payment Gateway for WHMCS - shared helper library.
 *
 * Implements only what is documented at https://ovajj.com/api-docs:
 *   - Header authentication (X-Environment, X-Merchant-Key, X-API-Key)
 *   - HMAC-SHA256 request signing: "timestamp.METHOD.path_with_query.raw_body"
 *   - POST /api/v1/initiate-payment
 *   - GET  /api/v1/verify-payment/{trxId}
 *   - POST /api/v1/refund-payment
 */

namespace WHMCS\Module\Gateway\Ovajj;

use WHMCS\Database\Capsule;

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

class Helper
{
    const BASE_URL = 'https://ovajj.com';
    const MODULE = 'ovajj';

    /** Documented minimum payment_amount. */
    const MIN_AMOUNT = 1.00;

    /** Max age (seconds) of the "timestamp" field in a webhook body. */
    const WEBHOOK_TOLERANCE = 3600;

    /* ---------------------------------------------------------------- *
     * Configuration
     * ---------------------------------------------------------------- */

    /** Returns 'production' or 'sandbox'. Anything unknown falls back to sandbox (fail-safe). */
    public static function environment(array $params)
    {
        return (isset($params['environment']) && $params['environment'] === 'production')
            ? 'production'
            : 'sandbox';
    }

    /**
     * Credentials for the configured environment.
     * One credential set; it must match the selected environment.
     */
    public static function credentials(array $params)
    {
        $env = self::environment($params);

        $c = [
            'environment'   => $env,
            'merchantKey'   => trim((string) ($params['merchantKey'] ?? '')),
            'apiKey'        => trim((string) ($params['apiKey'] ?? '')),
            'apiSecret'     => trim((string) ($params['apiSecret'] ?? '')),
            'webhookSecret' => '', // docs: webhooks are signed with the API secret
        ];
        $c['complete'] = ($c['merchantKey'] !== '' && $c['apiKey'] !== '' && $c['apiSecret'] !== '');

        return $c;
    }

    /** All secret strings, used to mask WHMCS module-log output. */
    public static function secretList(array $creds)
    {
        return array_values(array_filter([
            $creds['merchantKey'] ?? '',
            $creds['apiKey'] ?? '',
            $creds['apiSecret'] ?? '',
            $creds['webhookSecret'] ?? '',
        ], 'strlen'));
    }

    /* ---------------------------------------------------------------- *
     * Small utilities
     * ---------------------------------------------------------------- */

    /** Strip control characters and cap length (for anything that is logged or sent). */
    public static function clean($value, $max = 200)
    {
        $value = preg_replace('/[\x00-\x1F\x7F]/u', ' ', (string) $value);
        if ($value === null) {
            $value = '';
        }
        return function_exists('mb_substr') ? mb_substr($value, 0, $max) : substr($value, 0, $max);
    }

    /** Decimal string with 2 places. */
    public static function money($amount)
    {
        return number_format((float) $amount, 2, '.', '');
    }

    /** Integer minor units - used for exact amount comparison. */
    public static function minor($amount)
    {
        return (int) round(((float) $amount) * 100);
    }

    public static function isValidTrxId($id)
    {
        return is_string($id) && preg_match('/^[A-Za-z0-9_\-]{4,100}$/', $id) === 1;
    }

    public static function systemUrl()
    {
        $url = '';
        if (class_exists('\WHMCS\Config\Setting')) {
            $url = (string) \WHMCS\Config\Setting::getValue('SystemURL');
        }
        return rtrim($url, '/') . '/';
    }

    /** Send a small JSON response and stop. */
    public static function respond($httpCode, $message, array $extra = [])
    {
        if (!headers_sent()) {
            http_response_code((int) $httpCode);
            header('Content-Type: application/json');
            header('Cache-Control: no-store');
        }
        echo json_encode(array_merge(['status' => $message], $extra));
        exit;
    }

    /* ---------------------------------------------------------------- *
     * Order reference + IPN URL token (invoice binding)
     * ---------------------------------------------------------------- */

    /**
     * Unique ref_trx (max 60 chars per docs): INV{invoiceId}-{nonce}-{hmac12}.
     * The nonce keeps retries unique (the API has a DUPLICATE_REFERENCE error);
     * the HMAC makes the reference unforgeable.
     */
    public static function makeRef($invoiceId, array $creds)
    {
        $nonce = dechex(time()) . bin2hex(random_bytes(3));
        $sig = substr(hash_hmac('sha256', $invoiceId . '|' . $nonce, $creds['apiSecret']), 0, 12);
        return 'INV' . (int) $invoiceId . '-' . $nonce . '-' . $sig;
    }

    /** Returns the invoice ID encoded in one of our refs, or null if it is not (validly) ours. */
    public static function parseRef($ref, array $creds)
    {
        if (!is_string($ref) || !preg_match('/^INV(\d+)-([a-f0-9]+)-([a-f0-9]{12})$/', $ref, $m)) {
            return null;
        }
        $expected = substr(hash_hmac('sha256', $m[1] . '|' . $m[2], $creds['apiSecret']), 0, 12);
        return hash_equals($expected, $m[3]) ? (int) $m[1] : null;
    }

    /** Token appended to our ipn_url so a callback can only ever act on the invoice it was created for. */
    public static function ipnToken($invoiceId, array $creds)
    {
        return substr(hash_hmac('sha256', 'ovajj-ipn|' . (int) $invoiceId, $creds['apiSecret']), 0, 32);
    }

    /* ---------------------------------------------------------------- *
     * WHMCS data access
     * ---------------------------------------------------------------- */

    /**
     * Authoritative invoice data: status, outstanding balance and the invoice currency code.
     * Returns null if the invoice cannot be loaded.
     */
    public static function invoiceContext($invoiceId)
    {
        $r = localAPI('GetInvoice', ['invoiceid' => (int) $invoiceId]);
        if (!is_array($r) || ($r['result'] ?? '') !== 'success') {
            return null;
        }

        $userId = (int) $r['userid'];
        $currency = Capsule::table('tblclients')
            ->join('tblcurrencies', 'tblclients.currency', '=', 'tblcurrencies.id')
            ->where('tblclients.id', $userId)
            ->value('tblcurrencies.code');

        return [
            'id'       => (int) $invoiceId,
            'userid'   => $userId,
            'status'   => (string) ($r['status'] ?? ''),
            'balance'  => (float) (isset($r['balance']) ? $r['balance'] : ($r['total'] ?? 0)),
            'currency' => strtoupper((string) $currency),
        ];
    }

    /** True if a WHMCS transaction with this ID has already been recorded. */
    public static function transactionExists($trxId)
    {
        return Capsule::table('tblaccounts')->where('transid', $trxId)->exists();
    }

    /** MySQL advisory lock - serialises concurrent webhooks for the same invoice. */
    public static function acquireLock($name, $timeout = 15)
    {
        $row = Capsule::connection()->selectOne('SELECT GET_LOCK(?, ?) AS l', [$name, (int) $timeout]);
        return $row && (int) $row->l === 1;
    }

    public static function releaseLock($name)
    {
        try {
            Capsule::connection()->selectOne('SELECT RELEASE_LOCK(?) AS l', [$name]);
        } catch (\Exception $e) {
            // Lock is released automatically when the connection closes.
        }
    }

    /* ---------------------------------------------------------------- *
     * Logging
     * ---------------------------------------------------------------- */

    /** Detailed module log; only when "Debug Logging" is enabled. Secrets are masked by WHMCS. */
    public static function debug(array $params, $action, $request, $response, array $creds = [])
    {
        if (($params['debugLogging'] ?? '') !== 'on' || !function_exists('logModuleCall')) {
            return;
        }
        logModuleCall(self::MODULE, $action, $request, $response, '', self::secretList($creds));
    }

    /* ---------------------------------------------------------------- *
     * Signed API client
     * ---------------------------------------------------------------- */

    /**
     * Perform a signed request.
     *
     * @return array{ok:bool,http:int,data:?array,error:?string,transient:bool}
     *         "transient" = worth retrying later (network error, 429, 5xx).
     */
    public static function apiRequest(array $creds, $method, $path, ?array $payload = null)
    {
        $result = ['ok' => false, 'http' => 0, 'data' => null, 'error' => null, 'transient' => false];

        if (!function_exists('curl_init')) {
            $result['error'] = 'The PHP cURL extension is not installed.';
            return $result;
        }

        $method = strtoupper($method);
        $body = '';
        if ($payload !== null) {
            $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($body === false) {
                $result['error'] = 'Could not encode request body as JSON.';
                return $result;
            }
        }

        // Signature payload per docs: timestamp.HTTP_METHOD.path_with_query.raw_body
        // (the raw body is empty for GET). The exact same $body string is sent below.
        $timestamp = (string) time();
        $signature = hash_hmac('sha256', $timestamp . '.' . $method . '.' . $path . '.' . $body, $creds['apiSecret']);

        $headers = [
            'Accept: application/json',
            'X-Environment: ' . $creds['environment'],
            'X-Merchant-Key: ' . $creds['merchantKey'],
            'X-API-Key: ' . $creds['apiKey'],
            'X-Timestamp: ' . $timestamp,
            'X-Signature: sha256=' . $signature,
        ];
        if ($method === 'POST') {
            $headers[] = 'Content-Type: application/json';
        }

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => self::BASE_URL . $path,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => $headers,
        ]);
        if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTPS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        }
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $raw = curl_exec($ch);
        $curlError = curl_error($ch);
        $http = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $result['http'] = $http;

        if ($raw === false) {
            $result['error'] = 'Network error: ' . self::clean($curlError);
            $result['transient'] = true;
            return $result;
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $result['error'] = 'Invalid (non-JSON) response from Ovajj, HTTP ' . $http;
            $result['transient'] = ($http >= 500 || $http === 429);
            return $result;
        }

        $result['data'] = $data;

        if ($http >= 200 && $http < 300 && !(array_key_exists('success', $data) && $data['success'] === false)) {
            $result['ok'] = true;
            return $result;
        }

        $msg = $data['message'] ?? ($data['error'] ?? 'Request failed');
        if (is_array($msg)) {
            $msg = json_encode($msg);
        }
        $code = isset($data['error_code']) ? ' [' . self::clean($data['error_code'], 50) . ']' : '';
        $result['error'] = 'HTTP ' . $http . $code . ': ' . self::clean($msg);
        $result['transient'] = ($http === 429 || $http >= 500);

        return $result;
    }
}
