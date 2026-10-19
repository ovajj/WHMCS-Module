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
    const VERSION = '2.2.0';

    /** Currency Ovajj is charged in unless the admin types another code (USD is the rail used in every Ovajj example). */
    const DEFAULT_PROCESSING_CURRENCY = 'USD';

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

    /** The "Processing Currency" setting: any currency code typed by the admin, default USD. */
    public static function processingCurrency(array $params)
    {
        $code = strtoupper(preg_replace('/[^A-Za-z]/', '', (string) ($params['processingCurrency'] ?? '')));
        return $code !== '' ? substr($code, 0, 10) : self::DEFAULT_PROCESSING_CURRENCY;
    }

    /** Decimal places used for amounts in a currency (crypto majors need 8, everything else 2). */
    public static function decimals($currency)
    {
        return in_array(strtoupper((string) $currency), ['BTC', 'ETH'], true) ? 8 : 2;
    }

    /** Amount formatted with the currency's precision. */
    public static function fmt($amount, $currency)
    {
        return number_format((float) $amount, self::decimals($currency), '.', '');
    }

    /** Human-readable exchange rate (tiny crypto rates need more digits). */
    public static function fmtRate($rate)
    {
        $rate = (float) $rate;
        return rtrim(rtrim(number_format($rate, $rate < 1 ? 12 : 6, '.', ''), '0'), '.');
    }

    /** Integer smallest-units (cents, satoshi ...) for exact, currency-aware comparison. */
    public static function units($amount, $currency)
    {
        return (int) round(((float) $amount) * pow(10, self::decimals($currency)));
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
     * Currency conversion: every invoice currency -> the Processing Currency (default USD), live or fixed rate
     * ---------------------------------------------------------------- */

    const SESSIONS_TABLE = 'mod_ovajj_sessions';
    const RATES_TABLE    = 'mod_ovajj_rates';
    const RATE_API       = 'https://open.er-api.com/v6/latest/';           // fiat: any country's currency
    const CRYPTO_API     = 'https://api.coinbase.com/v2/prices/';          // BTC / ETH / USDT spot price in USD
    const CRYPTO         = ['BTC', 'ETH', 'USDT'];
    const RATE_TTL       = 3600;    // fresh cache: 1 hour
    const RATE_STALE_MAX = 172800;  // last known rate usable for 48 h if the provider is unreachable

    private static $tablesReady = false;

    /** Creates/upgrades the module's own tables on first use (no WHMCS core tables are touched). */
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
                $t->decimal('invoice_amount', 24, 8);
                $t->string('pay_currency', 10);
                $t->decimal('pay_amount', 24, 8);
                $t->decimal('rate', 36, 12);
                $t->string('rate_mode', 10);
                $t->string('trx_id', 100)->nullable()->index();
                $t->integer('created_at');
            });
        }
        if (!$schema->hasTable(self::RATES_TABLE)) {
            $schema->create(self::RATES_TABLE, function ($t) {
                $t->string('pair', 24)->primary();
                $t->decimal('rate', 36, 12)->default(0);
                $t->integer('fetched_at')->default(0); // for "_backoff_*" rows: time until which fetching is paused
            });
        }

        // v2.0.0 upgrade: v1.1 tables stored 2 decimals; crypto needs 8 for amounts and 12 for rates.
        $schemaVersion = (int) Capsule::table(self::RATES_TABLE)->where('pair', '_schema')->value('fetched_at');
        if ($schemaVersion < 3) {
            try {
                Capsule::statement('ALTER TABLE `' . self::SESSIONS_TABLE . '` MODIFY `invoice_amount` DECIMAL(24,8) NOT NULL, MODIFY `pay_amount` DECIMAL(24,8) NOT NULL, MODIFY `rate` DECIMAL(36,12) NOT NULL');
                Capsule::statement('ALTER TABLE `' . self::RATES_TABLE . '` MODIFY `rate` DECIMAL(36,12) NOT NULL DEFAULT 0, MODIFY `pair` VARCHAR(24) NOT NULL');
                Capsule::table(self::RATES_TABLE)->updateOrInsert(['pair' => '_schema'], ['rate' => 0, 'fetched_at' => 3]);
            } catch (\Exception $e) {
                // Will be retried on the next request; payments in 2-decimal currencies are unaffected.
            }
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
     *
     * base is the Processing Currency; quote is the invoice currency, which can be
     * any fiat currency the rate provider knows.
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

        $rate = self::fetchRate($base, $quote);
        if ($rate > 0) {
            Capsule::table(self::RATES_TABLE)->updateOrInsert(
                ['pair' => $pair],
                ['rate' => $rate, 'fetched_at' => time()]
            );
            return $rate;
        }

        // Provider unavailable or backing off: last known rate, but not an old one.
        if ($row && (float) $row->rate > 0 && (time() - (int) $row->fetched_at) <= self::RATE_STALE_MAX) {
            return (float) $row->rate;
        }
        return 0.0;
    }

    private static function backoffActive($key)
    {
        return (int) Capsule::table(self::RATES_TABLE)->where('pair', '_backoff_' . $key)->value('fetched_at') > time();
    }

    private static function setBackoff($key, $seconds)
    {
        Capsule::table(self::RATES_TABLE)->updateOrInsert(
            ['pair' => '_backoff_' . $key],
            ['rate' => 0, 'fetched_at' => time() + (int) $seconds]
        );
    }

    /** Small JSON GET used by the rate providers. @return array{http:int,data:?array} */
    private static function getJson($url)
    {
        if (!function_exists('curl_init')) {
            return ['http' => 0, 'data' => null];
        }
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
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
        return ['http' => $http, 'data' => ($raw !== false) ? json_decode($raw, true) : null];
    }

    /**
     * 1 {base} = X {quote} for any combination of fiat currencies and BTC / ETH / USDT.
     * Fiat-to-fiat uses the fiat provider directly; anything involving crypto is resolved through USD.
     */
    private static function fetchRate($base, $quote)
    {
        $baseCrypto = in_array($base, self::CRYPTO, true);
        $quoteCrypto = in_array($quote, self::CRYPTO, true);

        if (!$baseCrypto && !$quoteCrypto) {
            return self::fetchFiat($base, $quote);
        }

        $uBase = self::usdPerUnit($base);
        if ($uBase <= 0) {
            return 0.0;
        }
        $uQuote = self::usdPerUnit($quote);
        return $uQuote > 0 ? $uBase / $uQuote : 0.0;
    }

    /** Value of one unit of a currency in USD (0.0 when unknown). */
    private static function usdPerUnit($currency)
    {
        if ($currency === 'USD') {
            return 1.0;
        }
        if (in_array($currency, self::CRYPTO, true)) {
            return self::fetchCryptoUsd($currency);
        }
        $fx = self::fetchFiat('USD', $currency); // 1 USD = $fx {currency}
        return $fx > 0 ? 1.0 / $fx : 0.0;
    }

    /** open.er-api.com: free, no key, any country's currency, attribution required, 429 = blocked 20 min. */
    private static function fetchFiat($base, $quote)
    {
        if (self::backoffActive('fx')) {
            return 0.0;
        }
        $res = self::getJson(self::RATE_API . rawurlencode($base));
        if ($res['http'] === 429) {
            self::setBackoff('fx', 1260);
            return 0.0;
        }
        $d = $res['data'];
        if ($res['http'] !== 200 || !is_array($d)
            || ($d['result'] ?? '') !== 'success'
            || strtoupper((string) ($d['base_code'] ?? '')) !== $base) {
            self::setBackoff('fx', 300);
            return 0.0;
        }
        $rate = $d['rates'][$quote] ?? null;
        if (!is_numeric($rate) || (float) $rate <= 0 || (float) $rate > 1.0E+15) {
            // The provider does not list this currency: no rate, no payment (never guess).
            return 0.0;
        }
        return (float) $rate;
    }

    /** Coinbase public spot price (no key): price of 1 {BTC|ETH|USDT} in USD. */
    private static function fetchCryptoUsd($symbol)
    {
        if (self::backoffActive('cb')) {
            return 0.0;
        }
        $res = self::getJson(self::CRYPTO_API . rawurlencode($symbol) . '-USD/spot');
        $amount = (is_array($res['data']) && isset($res['data']['data']['amount'])) ? $res['data']['data']['amount'] : null;
        if ($res['http'] !== 200 || !is_numeric($amount) || (float) $amount <= 0 || (float) $amount > 1.0E+12) {
            self::setBackoff('cb', 300);
            return 0.0;
        }
        return (float) $amount;
    }

    /** Settings-page hint with both rate sources and their live feeds; reads the cache only (no network). */
    public static function rateHint()
    {
        $hint = 'Live rates are cached for 1 hour.<br>'
            . '<strong>USD, EUR, GBP and all other fiat currencies:</strong> '
            . '<a href="https://www.exchangerate-api.com" target="_blank" rel="noopener">Rates By Exchange Rate API</a> '
            . '(live feed: <a href="https://open.er-api.com/v6/latest/USD" target="_blank" rel="noopener">open.er-api.com/v6/latest/USD</a>)<br>'
            . '<strong>BTC, ETH and USDT:</strong> '
            . '<a href="https://www.coinbase.com/price" target="_blank" rel="noopener">Coinbase</a> '
            . '(live feed: <a href="https://api.coinbase.com/v2/prices/BTC-USD/spot" target="_blank" rel="noopener">api.coinbase.com/v2/prices/BTC-USD/spot</a>)';
        try {
            $saved = (string) Capsule::table('tblpaymentgateways')
                ->where('gateway', self::MODULE)->where('setting', 'processingCurrency')->value('value');
            $wallet = self::processingCurrency(['processingCurrency' => $saved]);
            $default = self::defaultCurrency();
            if ($wallet !== '' && $default !== '' && $wallet !== $default) {
                $known = self::cachedRate($wallet, $default);
                $hint .= '<br>' . ($known
                    ? 'Last known rate: 1 ' . $wallet . ' = ' . self::fmtRate($known) . ' ' . $default . '.'
                    : 'No rate has been fetched yet; it is fetched at the first payment.');
            }
        } catch (\Exception $e) {
            // Never break the settings page over a hint.
        }
        return $hint;
    }

    /**
     * Amount and currency actually sent to Ovajj for an invoice.
     * Invoices already in the Processing Currency are not converted; every other currency is converted to it.
     * Fixed rate applies to invoices in the default WHMCS currency; other currencies use the live rate.
     *
     * @return array{amount:float,currency:string,rate:float,mode:string,error:?string}
     */
    public static function paymentAmount(array $params, array $ctx)
    {
        $inv = $ctx['currency'];
        $wallet = self::processingCurrency($params);

        if ($wallet === $inv) {
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
            'amount'   => (float) number_format($ctx['balance'] / $rate, self::decimals($wallet), '.', ''),
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
    public static function findSession($invoiceId, $refTrx, $currency, $payUnits)
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
            if (strtoupper($row->pay_currency) === strtoupper($currency) && self::units($row->pay_amount, $row->pay_currency) === (int) $payUnits) {
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
