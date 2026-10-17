<?php
/**
 * Ovajj IPN (webhook) handler.
 *
 * An invoice is marked paid ONLY when ALL of the following hold:
 *   1. X-Signature (HMAC-SHA256 of the raw body) is valid for the configured environment.
 *   2. The per-invoice token in our ipn_url is valid (binds the callback to ONE invoice).
 *   3. The webhook says status=completed and is for the configured environment.
 *   4. GET /api/v1/verify-payment/{trx_id} independently returns status=success.
 *   5. Currency and amount match the WHMCS invoice (authoritative).
 *   6. The invoice is still unpaid and the Ovajj trx_id has not been recorded before.
 *
 * HTTP codes: 200 handled/ignored, 4xx rejected (do not retry), 5xx temporary (please retry).
 */

require_once __DIR__ . '/../../../init.php';
App::load_function('gateway');
App::load_function('invoice');
require_once __DIR__ . '/../ovajj/lib/Helper.php';

use WHMCS\Module\Gateway\Ovajj\Helper;

$gatewayModuleName = 'ovajj';
$gatewayParams = getGatewayVariables($gatewayModuleName);
if (empty($gatewayParams['type'])) {
    Helper::respond(503, 'module_not_activated');
}
$name = $gatewayParams['name'];

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    Helper::respond(405, 'method_not_allowed');
}

$creds = Helper::credentials($gatewayParams);
if (!$creds['complete']) {
    logTransaction($name, ['reason' => 'Webhook received but credentials for "' . $creds['environment'] . '" are not configured'], 'Configuration Error');
    Helper::respond(503, 'not_configured');
}

// ---- 1. Raw body (needed byte-exact for the signature) -------------------------------------
$raw = (string) file_get_contents('php://input', false, null, 0, 65537);
if (strlen($raw) > 65536) {
    Helper::respond(413, 'payload_too_large');
}

// ---- 2. Signature --------------------------------------------------------------------------
// Docs: X-Signature = HMAC-SHA256(raw body, secret), hex, optionally prefixed "sha256=".
// The docs mention both "API secret" and "webhook secret"; accept either configured value.
$provided = strtolower(trim((string) ($_SERVER['HTTP_X_SIGNATURE'] ?? '')));
if (strpos($provided, 'sha256=') === 0) {
    $provided = substr($provided, 7);
}

$secrets = array_values(array_unique(array_filter([$creds['webhookSecret'], $creds['apiSecret']], 'strlen')));
$signatureOk = false;
if ($provided !== '' && preg_match('/^[a-f0-9]{64}$/', $provided)) {
    foreach ($secrets as $secret) {
        if (hash_equals(hash_hmac('sha256', $raw, $secret), $provided)) {
            $signatureOk = true;
            break;
        }
    }
}
if (!$signatureOk) {
    // Never log headers or the body of an unauthenticated request.
    logTransaction($name, [
        'reason'      => 'Webhook signature verification failed',
        'environment' => $creds['environment'],
        'remote_ip'   => Helper::clean($_SERVER['REMOTE_ADDR'] ?? '', 45),
    ], 'Invalid Signature');
    Helper::respond(401, 'invalid_signature');
}

// ---- 3. Parse + sanity-check ---------------------------------------------------------------
$payload = json_decode($raw, true);
if (!is_array($payload) || !isset($payload['data']) || !is_array($payload['data'])) {
    logTransaction($name, ['reason' => 'Malformed webhook JSON (signature was valid)'], 'Malformed Request');
    Helper::respond(400, 'malformed_payload');
}
$data = $payload['data'];

$event  = Helper::clean($payload['event'] ?? '', 50);
$status = strtolower(Helper::clean($payload['status'] ?? '', 30));

// Environment isolation: a sandbox notification must never settle a live invoice (and vice-versa).
$hdrEnv  = strtolower(trim((string) ($_SERVER['HTTP_X_ENVIRONMENT'] ?? '')));
$bodyEnv = strtolower((string) ($data['environment'] ?? ''));
$envMismatch = ($hdrEnv !== '' && $hdrEnv !== $creds['environment'])
    || ($bodyEnv !== '' && $bodyEnv !== $creds['environment'])
    || (isset($data['is_sandbox']) && ((bool) $data['is_sandbox']) !== ($creds['environment'] === 'sandbox'));

// Replay window (the body carries a unix "timestamp"). Idempotency below covers replays inside the window.
$tsStale = isset($payload['timestamp']) && is_numeric($payload['timestamp'])
    && abs(time() - (int) $payload['timestamp']) > Helper::WEBHOOK_TOLERANCE;

// Invoice binding via our own ipn_url token.
$invoiceId = (int) ($_GET['invoice'] ?? 0);
$token = (string) ($_GET['t'] ?? '');
if ($invoiceId <= 0 || $token === '' || !hash_equals(Helper::ipnToken($invoiceId, $creds), $token)) {
    logTransaction($name, ['reason' => 'Invalid or missing invoice token on IPN URL', 'invoice' => $invoiceId], 'Unauthorized');
    Helper::respond(403, 'invalid_token');
}

// Aborts the script with a WHMCS log entry if the invoice does not exist.
$invoiceId = checkCbInvoiceID($invoiceId, $name);

$trxId = $data['trx_id'] ?? ($payload['trx_id'] ?? '');
$refTrx = isset($data['ref_trx']) ? (string) $data['ref_trx'] : '';

// Safe, minimal log context (no customer details, no headers).
$logCtx = [
    'invoice'     => $invoiceId,
    'event'       => $event,
    'status'      => $status,
    'ref_trx'     => Helper::clean($refTrx, 80),
    'trx_id'      => is_string($trxId) ? Helper::clean($trxId, 100) : '',
    'amount'      => isset($data['amount']) ? Helper::clean($data['amount'], 30) : '',
    'currency'    => Helper::clean($data['currency_code'] ?? '', 10),
    'environment' => $bodyEnv ?: $hdrEnv,
];

if ($envMismatch) {
    logTransaction($name, $logCtx + ['reason' => 'Environment mismatch: module is set to "' . $creds['environment'] . '"'], 'Rejected');
    Helper::respond(400, 'environment_mismatch');
}
if ($tsStale) {
    logTransaction($name, $logCtx + ['reason' => 'Webhook timestamp outside allowed window (possible replay)'], 'Rejected');
    Helper::respond(400, 'stale_timestamp');
}

// If the echoed ref_trx is one of OUR references it must point at the same invoice as the URL token.
$refInvoice = Helper::parseRef($refTrx, $creds);
if ($refInvoice !== null && $refInvoice !== $invoiceId) {
    logTransaction($name, $logCtx + ['reason' => 'ref_trx belongs to a different invoice'], 'Rejected');
    Helper::respond(400, 'invoice_mismatch');
}

// ---- 4. Non-payment events -----------------------------------------------------------------
if ($event === 'payment.refunded' || $status === 'refunded') {
    // Informational. Refunds are issued from WHMCS (Refund button) or by Ovajj staff;
    // this notice never changes invoice state on its own.
    logTransaction($name, $logCtx + [
        'refund_trx_id'   => Helper::clean($data['refund_trx_id'] ?? '', 100),
        'refunded_amount' => Helper::clean($data['refunded_amount'] ?? '', 30),
        'fully_refunded'  => !empty($data['fully_refunded']),
    ], 'Refund Notice');
    Helper::respond(200, 'refund_noted');
}

if ($status !== 'completed') {
    $label = in_array($status, ['pending', 'processing'], true) ? 'Pending'
        : (in_array($status, ['failed', 'cancelled', 'canceled', 'expired'], true) ? 'Failure' : 'Ignored');
    logTransaction($name, $logCtx + ['result' => 'Not a completed payment - invoice left unchanged'], $label);
    Helper::respond(200, 'noted_' . ($status ?: 'unknown'));
}

// ---- 5. status=completed: independently verify before touching the invoice ------------------
if (!Helper::isValidTrxId($trxId)) {
    // Verification needs Ovajj's trx_id. Never mark paid on the webhook alone.
    logTransaction($name, $logCtx + ['reason' => 'Completed webhook has no usable data.trx_id; cannot verify. Contact Ovajj support (see README, "Known limitations").'], 'Verification Impossible');
    Helper::respond(422, 'missing_trx_id');
}

if (!is_numeric($data['amount'] ?? null) || empty($data['currency_code'])) {
    logTransaction($name, $logCtx + ['reason' => 'Webhook missing amount/currency'], 'Malformed Request');
    Helper::respond(400, 'malformed_payload');
}
$hookMinor = Helper::minor($data['amount']);
$hookCurrency = strtoupper((string) $data['currency_code']);

// Cheap duplicate check first - avoids an API call for repeated deliveries.
if (Helper::transactionExists($trxId)) {
    logTransaction($name, $logCtx + ['result' => 'Transaction already recorded - duplicate delivery ignored'], 'Duplicate');
    Helper::respond(200, 'already_processed');
}

$verify = Helper::apiRequest($creds, 'GET', '/api/v1/verify-payment/' . rawurlencode($trxId));
Helper::debug($gatewayParams, 'verify-payment', ['trx_id' => $trxId], ['http' => $verify['http'], 'error' => $verify['error'], 'data' => $verify['data']], $creds);

if (!$verify['ok']) {
    logTransaction($name, $logCtx + ['reason' => 'Verification request failed: ' . $verify['error']], 'Verification Failed');
    // Temporary problem -> 503 so Ovajj can retry. Hard failure (401/404/...) -> 502.
    Helper::respond($verify['transient'] ? 503 : 502, 'verification_failed');
}

$v = $verify['data'];
$vStatus = strtolower((string) ($v['status'] ?? ''));

if ($vStatus === 'pending') {
    logTransaction($name, $logCtx + ['result' => 'Verify API reports payment still pending'], 'Pending');
    Helper::respond(503, 'still_pending');
}
if ($vStatus !== 'success') {
    logTransaction($name, $logCtx + ['reason' => 'Webhook said completed but verify API says "' . Helper::clean($vStatus, 30) . '" - NOT recording payment'], 'Verification Mismatch');
    Helper::respond(409, 'verification_mismatch');
}
if (!isset($v['trx_id']) || $v['trx_id'] !== $trxId) {
    logTransaction($name, $logCtx + ['reason' => 'Verify API returned a different trx_id'], 'Verification Mismatch');
    Helper::respond(409, 'verification_mismatch');
}
if (!empty($v['fully_refunded']) || (isset($v['refunded_amount']) && (float) $v['refunded_amount'] > 0)) {
    logTransaction($name, $logCtx + ['reason' => 'Transaction already (partly) refunded at Ovajj - NOT recording payment'], 'Verification Mismatch');
    Helper::respond(409, 'already_refunded');
}

// ---- 6. Record under an invoice-level lock (serialises concurrent webhooks) -----------------
$lockName = 'ovajj_inv_' . $invoiceId;
if (!Helper::acquireLock($lockName, 15)) {
    logTransaction($name, $logCtx + ['reason' => 'Could not obtain invoice lock'], 'Temporary Failure');
    Helper::respond(503, 'busy');
}

// exit() skips finally blocks, so release the lock explicitly before every response.
$finish = function ($code, $msg) use ($lockName) {
    Helper::releaseLock($lockName);
    Helper::respond($code, $msg);
};

// Re-check inside the lock: another delivery may have won the race.
if (Helper::transactionExists($trxId)) {
    logTransaction($name, $logCtx + ['result' => 'Transaction already recorded (concurrent delivery)'], 'Duplicate');
    $finish(200, 'already_processed');
}

// Fresh invoice state - the authoritative amount/currency come from WHMCS, not from Ovajj.
$ctx = Helper::invoiceContext($invoiceId);
if (!$ctx) {
    logTransaction($name, $logCtx + ['reason' => 'Could not load invoice'], 'Failure');
    $finish(500, 'invoice_unavailable');
}

if (!in_array($ctx['status'], ['Unpaid', 'Payment Pending'], true)) {
    // e.g. Paid (customer paid twice / paid elsewhere) or Cancelled. Needs manual review/refund.
    logTransaction($name, $logCtx + [
        'reason' => 'Invoice status is "' . $ctx['status'] . '" - payment NOT applied. Review ' . Helper::clean($trxId, 100) . ' manually (refund if needed).',
    ], 'Invoice Not Payable');
    $finish(200, 'invoice_not_payable');
}

// Currency: webhook and verify must both equal the invoice currency. No conversion, ever.
$vCurrency = strtoupper((string) ($v['currency'] ?? ''));
if ($hookCurrency !== $ctx['currency'] || $vCurrency !== $ctx['currency']) {
    logTransaction($name, $logCtx + [
        'reason' => 'Currency mismatch (invoice ' . $ctx['currency'] . ', webhook ' . $hookCurrency . ', verify ' . $vCurrency . ')',
    ], 'Currency Mismatch');
    $finish(409, 'currency_mismatch');
}

// Amount: webhook "data.amount" is the gross charge and must equal the amount due.
// verify "amount" may be reported net of Ovajj's fee (docs example: amount 237.5 + fee 12.5),
// so accept either amount or amount+fee equal to the amount due, with a 1-cent
// tolerance because Ovajj rounds the fee and the net amount separately
// (e.g. 49.50 charged -> verify amount 49.01 + fee 0.50 = 49.51).
$dueMinor = Helper::minor($ctx['balance']);
$vAmount = isset($v['amount']) && is_numeric($v['amount']) ? (float) $v['amount'] : null;
$vFee = isset($v['fee']) && is_numeric($v['fee']) && (float) $v['fee'] >= 0 ? (float) $v['fee'] : 0.0;

$hookOk = ($hookMinor === $dueMinor);
$verifyOk = $vAmount !== null
    && (abs(Helper::minor($vAmount) - $dueMinor) <= 1
        || abs(Helper::minor($vAmount + $vFee) - $dueMinor) <= 1);

if (!$hookOk || !$verifyOk) {
    logTransaction($name, $logCtx + [
        'reason'     => 'Amount mismatch',
        'amount_due' => Helper::money($ctx['balance']),
        'verify_amount' => $vAmount,
        'verify_fee'    => $vFee,
    ], 'Amount Mismatch');
    $finish(409, 'amount_mismatch');
}

// Record the verified payment. Fee is the Ovajj processing fee reported by verify-payment.
$paymentAmount = Helper::money($ctx['balance']);
$paymentFee = ($vFee > 0 && $vFee < $ctx['balance']) ? Helper::money($vFee) : 0;

addInvoicePayment($invoiceId, $trxId, $paymentAmount, $paymentFee, $gatewayModuleName);

logTransaction($name, $logCtx + [
    'result'   => 'Payment verified and recorded',
    'recorded' => $paymentAmount . ' ' . $ctx['currency'],
    'fee'      => $paymentFee,
], 'Successful');

$finish(200, 'processed');
