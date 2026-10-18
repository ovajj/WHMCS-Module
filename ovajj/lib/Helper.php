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

    /* ---------------------------------------------------------------- *
     * Currency conversion (optional): wallet currency, live/fixed rate
     * ---------------------------------------------------------------- */

    const SESSIONS_TABLE = 'mod_ovajj_sessions';
    const RATES_TABLE    = 'mod_ovajj_rates';
    const RATE_API       = 'https://open.er-api.com/v6/latest/';
    const RATE_TTL       = 3600;    // fresh cache: 1 hour
    const RATE_STALE_MAX = 172800;  // last known rate usable for 48 h if the provider is unreachable

    private static $tablesReady = false;

    /** Creates the module's own tables on first use (no WHMCS core tables are touched). */
    public static function ensureTables()
    {
        if (self::$tablesReady) {
            return;
        }
        $schema = Capsule::schema();

        if (!$schema->hasTable(self::SESSIONS_TABLE)) {
            $schema->create(self::SESSIONS_TABLE, function ($t) {
                $t->increments('id');
                $t->integer('invoice_id')->index();
                $t->string('ref_trx', 80)->unique();
                $t->string('invoice_currency', 10);
                $t->decimal('invoice_amount', 16, 2);
                $t->string('pay_currency', 10);
                $t->decimal('pay_amount', 16, 2);
                $t->decimal('rate', 20, 8);
                $t->string('rate_mode', 10);
                $t->string('trx_id', 100)->nullable()->index();
                $t->integer('created_at');
            });
        }
        if (!$schema->hasTable(self::RATES_TABLE)) {
            $schema->create(self::RATES_TABLE, function ($t) {
                $t->string('pair', 20)->primary();
                $t->decimal('rate', 20, 8)->default(0);
                $t->integer('fetched_at')->default(0); // for pair "_backoff": the time until which fetching is paused
            });
        }
        self::$tablesReady = true;
    }

    /** Default WHMCS currency code (used for the Fixed rate). */
    public static function defaultCurrency()
    {
        return strtoupper((string) Capsule::table('tblcurrencies')->where('default', 1)->value('code'));
    }

    /** Last known rate (fresh or stale) WITHOUT any network call - safe for the admin settings page. */
    public static function cachedRate($base, $quote)
    {
        self::ensureTables();
        $row = Capsule::table(self::RATES_TABLE)->where('pair', strtoupper($base . '/' . $quote))->first();
        return ($row && (float) $row->rate > 0) ? (float) $row->rate : null;
    }

    /**
     * Live rate: 1 {base} = X {quote}. Returns 0.0 when no usable rate exists - the caller must then
     * refuse the payment instead of guessing.
     */
    public static function liveRate($base, $quote)
    {
        self::ensureTables();
        $base = strtoupper($base);
        $quote = strtoupper($quote);
        $pair = $base . '/' . $quote;

        $row = Capsule::table(self::RATES_TABLE)->where('pair', $pair)->first();
        if ($row && (float) $row->rate > 0 && (time() - (int) $row->fetched_at) < self::RATE_TTL) {
            return (float) $row->rate;
        }

        $backoff = Capsule::table(self::RATES_TABLE)->where('pair', '_backoff')->value('fetched_at');
        if ((int) $backoff < time()) {
            $res = self::fetchRate($base, $quote);
            if ($res['rate'] > 0) {
                Capsule::table(self::RATES_TABLE)->updateOrInsert(
                    ['pair' => $pair],
                    ['rate' => $res['rate'], 'fetched_at' => time()]
                );
                return $res['rate'];
            }
            Capsule::table(self::RATES_TABLE)->updateOrInsert(
                ['pair' => '_backoff'],
                ['rate' => 0, 'fetched_at' => time() + $res['backoff']]
            );
        }

        // Provider unavailable or backing off: last known rate, but not an old one.
        if ($row && (float) $row->rate > 0 && (time() - (int) $row->fetched_at) <= self::RATE_STALE_MAX) {
            return (float) $row->rate;
        }
        return 0.0;
    }

    /** open.er-api.com: free, no key, attribution required, cache allowed, 429 = blocked for 20 min. */
    private static function fetchRate($base, $quote)
    {
        $out = ['rate' => 0.0, 'backoff' => 300];
        if (!function_exists('curl_init')) {
            return $out;
        }
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => self::RATE_API . rawurlencode($base),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => ['Accept: application/json'],
        ]);
        $raw = curl_exec($ch);
        $http = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http === 429) {
            $out['backoff'] = 1260;
            return $out;
        }
        $data = ($raw !== false) ? json_decode($raw, true) : null;
        if ($http !== 200 || !is_array($data)
            || ($data['result'] ?? '') !== 'success'
            || strtoupper((string) ($data['base_code'] ?? '')) !== $base) {
            return $out;
        }
        $rate = $data['rates'][$quote] ?? null;
        if (is_numeric($rate) && (float) $rate > 0 && (float) $rate < 10000000) {
            $out['rate'] = (float) $rate;
        }
        return $out;
    }

    /** Settings-page hint; reads saved settings and the cached rate only (no network). */
    public static function rateHint()
    {
        $hint = 'Live rates are fetched automatically and cached for 1 hour. '
            . '<a href="https://www.exchangerate-api.com" target="_blank" rel="noopener">Rates By Exchange Rate API</a>.';
        try {
            $wallet = strtoupper(trim((string) Capsule::table('tblpaymentgateways')
                ->where('gateway', self::MODULE)->where('setting', 'walletCurrency')->value('value')));
            $default = self::defaultCurrency();
            if ($wallet !== '' && $default !== '' && $wallet !== $default) {
                $known = self::cachedRate($wallet, $default);
                $hint .= $known
                    ? ' Last known rate: 1 ' . $wallet . ' = ' . rtrim(rtrim(number_format($known, 6, '.', ''), '0'), '.') . ' ' . $default . '.'
                    : ' No rate has been fetched yet; it is fetched at the first payment.';
            }
        } catch (\Exception $e) {
            // Never break the settings page over a hint.
        }
        return $hint;
    }

    /**
     * Amount and currency actually sent to Ovajj for an invoice.
     * Wallet currency empty or equal to the invoice currency => no conversion.
     * Fixed rate applies to invoices in the default WHMCS currency; other currencies use the live rate.
     *
     * @return array{amount:float,currency:string,rate:float,mode:string,error:?string}
     */
    public static function paymentAmount(array $params, array $ctx)
    {
        $inv = $ctx['currency'];
        $wallet = strtoupper(trim((string) ($params['walletCurrency'] ?? '')));

        if ($wallet === '' || $wallet === $inv) {
            return ['amount' => $ctx['balance'], 'currency' => $inv, 'rate' => 1.0, 'mode' => 'none', 'error' => null];
        }

        // Rate meaning: 1 {wallet currency} = {rate} {invoice currency}.
        $useFixed = (($params['rateMode'] ?? 'live') === 'fixed') && $inv === self::defaultCurrency();
        if ($useFixed) {
            $mode = 'fixed';
            $rate = (float) str_replace(',', '.', trim((string) ($params['fixedRate'] ?? '')));
        } else {
            $mode = 'live';
            $rate = self::liveRate($wallet, $inv);
        }
        if ($rate <= 0) {
            return ['amount' => 0.0, 'currency' => $wallet, 'rate' => 0.0, 'mode' => $mode,
                'error' => 'No usable exchange rate for ' . $wallet . '/' . $inv . ' (' . $mode . ' mode)'];
        }

        return [
            'amount'   => (float) number_format($ctx['balance'] / $rate, 2, '.', ''),
            'currency' => $wallet,
            'rate'     => $rate,
            'mode'     => $mode,
            'error'    => null,
        ];
    }

    /* ------------ payment sessions (what each checkout asked Ovajj for) ------------ */

    public static function saveSession(array $row)
    {
        self::ensureTables();
        $row['created_at'] = time();
        Capsule::table(self::SESSIONS_TABLE)->insert($row);
    }

    public static function hasSessions($invoiceId)
    {
        self::ensureTables();
        return Capsule::table(self::SESSIONS_TABLE)->where('invoice_id', (int) $invoiceId)->exists();
    }

    /** The session a payment belongs to: by ref_trx, else any session of this invoice with the same amount/currency. */
    public static function findSession($invoiceId, $refTrx, $currency, $payMinor)
    {
        self::ensureTables();
        $q = Capsule::table(self::SESSIONS_TABLE)->where('invoice_id', (int) $invoiceId);

        if ($refTrx !== '') {
            $row = (clone $q)->where('ref_trx', $refTrx)->first();
            if ($row) {
                return (array) $row;
            }
        }
        foreach ((clone $q)->orderBy('id', 'desc')->limit(20)->get() as $row) {
            if (strtoupper($row->pay_currency) === strtoupper($currency) && self::minor($row->pay_amount) === (int) $payMinor) {
                return (array) $row;
            }
        }
        return null;
    }

    public static function markSessionPaid($sessionId, $trxId)
    {
        Capsule::table(self::SESSIONS_TABLE)->where('id', (int) $sessionId)->update(['trx_id' => $trxId]);
    }

    public static function sessionByTrx($trxId)
    {
        self::ensureTables();
        $row = Capsule::table(self::SESSIONS_TABLE)->where('trx_id', $trxId)->first();
        return $row ? (array) $row : null;
    }
}
