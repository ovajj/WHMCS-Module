<?php
/**
 * Ovajj - create a hosted-checkout session and redirect the customer.
 *
 * Security:
 *  - POST only; WHMCS validates the CSRF token (generate_token) for client-area POSTs.
 *  - The customer must be logged in AND own the invoice.
 *  - Amount and currency come from WHMCS (never from the request).
 *  - All credentials stay server-side; the customer only ever sees a generic error.
 */

require_once __DIR__ . '/../../../init.php';
App::load_function('gateway');
App::load_function('invoice');
require_once __DIR__ . '/lib/Helper.php';

use WHMCS\Database\Capsule;
use WHMCS\Module\Gateway\Ovajj\Helper;

$systemUrl = Helper::systemUrl();

/** Redirect back to the invoice with WHMCS' standard "payment failed" notice. */
function ovajj_pay_fail($invoiceId, $systemUrl)
{
    $target = $invoiceId > 0
        ? $systemUrl . 'viewinvoice.php?id=' . (int) $invoiceId . '&paymentfailed=true'
        : $systemUrl . 'clientarea.php?action=invoices';
    header('Location: ' . $target, true, 303);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Location: ' . $systemUrl . 'clientarea.php?action=invoices', true, 303);
    exit;
}

$invoiceId = (int) ($_POST['invoiceid'] ?? 0);
if ($invoiceId <= 0) {
    ovajj_pay_fail(0, $systemUrl);
}

$gatewayParams = getGatewayVariables('ovajj');
if (empty($gatewayParams['type'])) {
    ovajj_pay_fail($invoiceId, $systemUrl);
}
$name = $gatewayParams['name'];

// --- Who is logged in? ---
$clientId = 0;
if (class_exists('\WHMCS\Authentication\CurrentUser')) {
    $currentUser = new \WHMCS\Authentication\CurrentUser();
    $client = $currentUser->client();
    if ($client) {
        $clientId = (int) $client->id;
    }
}
if ($clientId === 0 && !empty($_SESSION['uid'])) {
    $clientId = (int) $_SESSION['uid'];
}
if ($clientId === 0) {
    header('Location: ' . $systemUrl . 'clientarea.php', true, 303); // WHMCS shows the login form
    exit;
}

// --- Invoice must exist, belong to this client, and be payable ---
$ctx = Helper::invoiceContext($invoiceId);
if (!$ctx || $ctx['userid'] !== $clientId) {
    logTransaction($name, ['reason' => 'Initiation blocked: invoice not found or not owned by client', 'invoice' => $invoiceId, 'client' => $clientId], 'Unauthorized');
    ovajj_pay_fail(0, $systemUrl);
}
if (!in_array($ctx['status'], ['Unpaid', 'Payment Pending'], true) || $ctx['balance'] <= 0) {
    ovajj_pay_fail($invoiceId, $systemUrl);
}
if ($ctx['balance'] < Helper::MIN_AMOUNT) {
    logTransaction($name, ['reason' => 'Amount below Ovajj minimum', 'invoice' => $invoiceId, 'amount' => Helper::money($ctx['balance'])], 'Failure');
    ovajj_pay_fail($invoiceId, $systemUrl);
}
if ($ctx['currency'] === '') {
    ovajj_pay_fail($invoiceId, $systemUrl);
}

// --- Credentials / environment sanity ---
$creds = Helper::credentials($gatewayParams);
if (!$creds['complete']) {
    logTransaction($name, ['reason' => 'Credentials for "' . $creds['environment'] . '" are not configured'], 'Configuration Error');
    ovajj_pay_fail($invoiceId, $systemUrl);
}
if ($creds['environment'] === 'production' && strpos($systemUrl, 'https://') !== 0) {
    logTransaction($name, ['reason' => 'WHMCS SystemURL must use HTTPS in production'], 'Configuration Error');
    ovajj_pay_fail($invoiceId, $systemUrl);
}

// --- Build request ---
$clientRow = Capsule::table('tblclients')->where('id', $clientId)->first(['firstname', 'lastname', 'email']);

$description = 'Invoice #' . $invoiceId;

$ref = Helper::makeRef($invoiceId, $creds);
$ipnToken = Helper::ipnToken($invoiceId, $creds);

$payload = [
    'payment_amount'   => (float) Helper::money($ctx['balance']),
    'currency_code'    => $ctx['currency'],
    'ref_trx'          => $ref,
    'description'      => $description,
    'success_redirect' => $systemUrl . 'viewinvoice.php?id=' . $invoiceId . '&paymentsuccess=true',
    'cancel_redirect'  => $systemUrl . 'viewinvoice.php?id=' . $invoiceId . '&paymentfailed=true',
    'ipn_url'          => $systemUrl . 'modules/gateways/callback/ovajj.php?invoice=' . $invoiceId . '&t=' . $ipnToken,
];

if ($clientRow) {
    $custName = Helper::clean(trim($clientRow->firstname . ' ' . $clientRow->lastname), 100);
    if ($custName !== '') {
        $payload['customer_name'] = $custName;
    }
    if (filter_var($clientRow->email, FILTER_VALIDATE_EMAIL) && strlen($clientRow->email) <= 100) {
        $payload['customer_email'] = $clientRow->email;
    }
}

// --- Call Ovajj ---
$res = Helper::apiRequest($creds, 'POST', '/api/v1/initiate-payment', $payload);
Helper::debug($gatewayParams, 'initiate-payment', $payload, ['http' => $res['http'], 'error' => $res['error'], 'data' => $res['data']], $creds);

$logBase = [
    'invoice'     => $invoiceId,
    'ref_trx'     => $ref,
    'environment' => $creds['environment'],
    'amount'      => Helper::money($ctx['balance']),
    'currency'    => $ctx['currency'],
];

if (!$res['ok']) {
    logTransaction($name, $logBase + ['api_http' => $res['http'], 'error' => $res['error']], 'Initiation Failed');
    ovajj_pay_fail($invoiceId, $systemUrl);
}

$data = $res['data'];
$paymentUrl = isset($data['payment_url']) && is_string($data['payment_url']) ? trim($data['payment_url']) : '';
$parts = $paymentUrl !== '' ? parse_url($paymentUrl) : false;

// The response echoes what we asked for in "info"; make sure it matches before redirecting.
$info = isset($data['info']) && is_array($data['info']) ? $data['info'] : [];
$echoOk = (!isset($info['ref_trx']) || $info['ref_trx'] === $ref)
    && (!isset($info['amount']) || Helper::minor($info['amount']) === Helper::minor($ctx['balance']))
    && (!isset($info['currency_code']) || strtoupper((string) $info['currency_code']) === $ctx['currency'])
    && (!isset($info['environment']) || $info['environment'] === $creds['environment']);

if (!$parts || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host']) || !$echoOk) {
    logTransaction($name, $logBase + ['error' => 'Unexpected initiate-payment response (missing/invalid payment_url or mismatched echo)'], 'Initiation Failed');
    ovajj_pay_fail($invoiceId, $systemUrl);
}

logTransaction($name, $logBase + ['result' => 'Checkout session created'], 'Initiated');

header('Location: ' . preg_replace('/[\r\n]/', '', $paymentUrl), true, 303);
exit;
