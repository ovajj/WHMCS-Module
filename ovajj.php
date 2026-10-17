<?php
/**
 * Ovajj Payment Gateway module for WHMCS.
 *
 * Flow:
 *   1. link()          renders a "Pay Now" form (no API call happens just by viewing an invoice).
 *   2. ovajj/pay.php   (logged-in customer, CSRF-protected POST) creates the Ovajj hosted-checkout
 *                      session and redirects the customer to payment_url.
 *   3. callback/ovajj.php  receives the signed IPN, re-verifies the payment server-to-server and
 *                      only then records it with addInvoicePayment().
 *   4. refund()        calls POST /api/v1/refund-payment.
 *
 * @see https://ovajj.com/api-docs
 */

if (!defined('WHMCS')) {
    die('This file cannot be accessed directly');
}

require_once __DIR__ . '/ovajj/lib/Helper.php';

use WHMCS\Module\Gateway\Ovajj\Helper;

function ovajj_MetaData()
{
    return [
        'DisplayName'                 => 'Ovajj Payment Gateway',
        'APIVersion'                  => '1.1',
        'DisableLocalCredtCardInput'  => true,
        'DisableLocalCreditCardInput' => true,
        'TokenisedStorage'            => false,
    ];
}

function ovajj_config()
{
    return [
        'FriendlyName' => [
            'Type'  => 'System',
            'Value' => 'Ovajj Payment Gateway',
        ],
        'environment' => [
            'FriendlyName' => 'Environment',
            'Type'         => 'dropdown',
            'Options'      => [
                'sandbox'    => 'Sandbox (test - no real money)',
                'production' => 'Live (production)',
            ],
            'Default'      => 'sandbox',
            'Description'  => 'The credentials below must belong to the selected environment. When you switch, replace all three together.',
        ],
        'merchantKey' => [
            'FriendlyName' => 'Merchant Key',
            'Type'         => 'text',
            'Size'         => '40',
            'Description'  => 'Ovajj Dashboard &rarr; Merchant &rarr; Config. Sandbox keys start with <code>test_</code>.',
        ],
        'apiKey' => [
            'FriendlyName' => 'API Key',
            'Type'         => 'password',
            'Size'         => '40',
        ],
        'apiSecret' => [
            'FriendlyName' => 'API Secret (Client Secret)',
            'Type'         => 'password',
            'Size'         => '40',
            'Description'  => 'Signs API requests and verifies webhooks. Never exposed to the browser.',
        ],
        'debugLogging' => [
            'FriendlyName' => 'Debug Logging',
            'Type'         => 'yesno',
            'Description'  => 'Write detailed API diagnostics to Utilities &rarr; Logs &rarr; Module Log (credentials are masked).',
        ],
    ];
}

/**
 * Invoice page payment button. Deliberately makes NO API call: the session is created only
 * when the customer clicks, via ovajj/pay.php.
 */
function ovajj_link($params)
{
    $invoiceId = (int) $params['invoiceid'];
    $creds = Helper::credentials($params);

    if (!$creds['complete']) {
        logActivity('Ovajj: gateway credentials for the "' . $creds['environment'] . '" environment are not configured.');
        return '<div class="alert alert-warning">This payment method is temporarily unavailable.</div>';
    }

    // Currency is never converted silently. "Convert To For Processing" is not supported.
    if (!empty($params['basecurrency'])
        && strtoupper((string) $params['currency']) !== strtoupper((string) $params['basecurrency'])) {
        return '<div class="alert alert-warning">This payment method cannot process this invoice currency.</div>';
    }

    if ((float) $params['amount'] < Helper::MIN_AMOUNT) {
        return '<div class="alert alert-warning">The amount due is below the minimum accepted by this payment method.</div>';
    }

    $action = Helper::systemUrl() . 'modules/gateways/ovajj/pay.php';
    $token = function_exists('generate_token') ? generate_token('form') : '';
    $label = !empty($params['langpaynow']) ? $params['langpaynow'] : 'Pay Now';

    return '<form method="post" action="' . htmlspecialchars($action, ENT_QUOTES) . '">'
        . $token
        . '<input type="hidden" name="invoiceid" value="' . $invoiceId . '">'
        . '<input type="submit" class="btn btn-primary" value="' . htmlspecialchars($label, ENT_QUOTES) . '">'
        . '</form>';
}

/**
 * Refund via POST /api/v1/refund-payment.
 *
 * Idempotency: ref_refund is derived from (transaction, amount, current hour), so an admin
 * retry after a timeout can never refund twice. Consequence: two identical partial refunds of the
 * same transaction inside one clock hour are treated by Ovajj as one.
 */
function ovajj_refund($params)
{
    $creds = Helper::credentials($params);
    if (!$creds['complete']) {
        return ['status' => 'error', 'rawdata' => 'Ovajj credentials are not configured.'];
    }

    $transId = (string) $params['transid'];
    if (!Helper::isValidTrxId($transId)) {
        return ['status' => 'error', 'rawdata' => 'Invalid original transaction ID.'];
    }

    $amount = (float) $params['amount'];
    if ($amount <= 0) {
        return ['status' => 'error', 'rawdata' => 'Invalid refund amount.'];
    }

    $payload = [
        'trx_id'     => $transId,
        'amount'     => (float) Helper::money($amount),
        'reason'     => 'Refund for WHMCS invoice #' . (int) $params['invoiceid'],
        'ref_refund' => 'WHMCS-' . substr(hash('sha256', $transId . '|' . Helper::minor($amount) . '|' . gmdate('YmdH')), 0, 32),
    ];

    $res = Helper::apiRequest($creds, 'POST', '/api/v1/refund-payment', $payload);
    Helper::debug($params, 'refund-payment', $payload, ['http' => $res['http'], 'error' => $res['error'], 'data' => $res['data']], $creds);

    $data = $res['data'];
    if ($res['ok'] && is_array($data) && ($data['status'] ?? '') === 'success' && !empty($data['refund_trx_id'])) {
        return [
            'status'  => 'success',
            'rawdata' => $data,
            'transid' => (string) $data['refund_trx_id'],
            'fee'     => 0, // Ovajj does not return the original processing fee.
        ];
    }

    return [
        'status'  => 'declined',
        'rawdata' => $res['error'] ?: ($data ?: 'Refund was not accepted by Ovajj.'),
    ];
}
