# Ovajj Payment Gateway for WHMCS

Unofficial module, not affiliated with or endorsed by Ovajj.

Native WHMCS gateway module (`ovajj`) for the Ovajj hosted-checkout API
(<https://ovajj.com/api-docs>). Targets **WHMCS 8.x, PHP 7.4+, cURL**.

> **Status:** built from the public API docs and tried on a live WHMCS install, but there are no automated tests
> and it has not been independently audited. Run the sandbox test plan below before any live use.

## Files

```
modules/gateways/ovajj.php                 Gateway: config, Pay Now button, refund
modules/gateways/ovajj/pay.php             Creates the Ovajj checkout session, redirects customer
modules/gateways/ovajj/lib/Helper.php      Signed API client + shared helpers
modules/gateways/ovajj/whmcs.json          Name/description shown in Apps & Integrations
modules/gateways/callback/ovajj.php        IPN (webhook) handler
```

## Installation

1. Upload the `modules/` folder contents into your WHMCS root (no core files are changed).
2. Admin → **System Settings → Payment Gateways → All Payment Gateways** → activate
   **Ovajj Payment Gateway**.
3. Fill in the credentials (below), save.
4. Requirements: WHMCS `SystemURL` must be public and **HTTPS** (Ovajj must reach the webhook).

## Ovajj-side configuration

1. Ovajj Dashboard → Merchant → Config: copy **Merchant Key, API Key, Client Secret** for
   sandbox (`test_` prefix) and, once approved, production.
2. Ensure each invoice currency is enabled for the merchant **and** has an active receiver wallet.
3. Merchant → Config → *Payment Gateway Controls*: enable the gateways customers should see.
4. No webhook URL needs to be entered: the module sends a per-invoice `ipn_url` with every request.

| WHMCS field | Meaning |
|---|---|
| Environment | Dropdown: **Sandbox** or **Live**. |
| Merchant Key, API Key, API Secret | Must belong to the selected environment. When switching environment, replace all three together. |
| Debug Logging | Detailed API diagnostics in Module Log (credentials masked). |

## Payment flow

1. Customer opens an unpaid invoice → **Pay Now** (a CSRF-protected POST; viewing the invoice makes no API call).
2. `pay.php` checks login + invoice ownership + payable status, takes amount/currency **from WHMCS**,
   calls `POST /api/v1/initiate-payment`, validates the response, redirects to `payment_url`.
3. Customer pays on Ovajj. Redirect back to the invoice shows WHMCS's standard notice only.
4. Ovajj POSTs the IPN. The handler verifies signature, environment, invoice token, then calls
   `GET /api/v1/verify-payment/{trx_id}`, checks currency/amount, and only then calls `addInvoicePayment()`.

**Reaching the success URL never marks an invoice paid.**

## Supported statuses

| Ovajj | Handling |
|---|---|
| `completed` (webhook) + `success` (verify) | Verified → payment recorded with Ovajj `trx_id` |
| `pending` | Logged; HTTP 503 if verify still pending so Ovajj can retry; invoice untouched |
| `failed` / cancelled / expired | Logged only; invoice untouched |
| `refunded` (`payment.refunded` IPN) | Logged as "Refund Notice"; invoice untouched |

Refunds: the WHMCS **Refund** button on a transaction calls `POST /api/v1/refund-payment`
(full or partial, idempotent `ref_refund`).

## Security checklist

- [x] HMAC-SHA256 signature on every API request (`timestamp.METHOD.path.body`)
- [x] Webhook signature verified (constant-time) over the raw body before parsing
- [x] Independent server-side `verify-payment` before recording
- [x] Per-invoice HMAC token on `ipn_url` + HMAC-signed `ref_trx` (prevents invoice ID manipulation)
- [x] Sandbox ↔ live isolation (header, body `environment`, `is_sandbox` must match config)
- [x] Currency and amount validated against WHMCS invoice; no silent conversion
- [x] Idempotency: transaction-ID check + MySQL advisory lock per invoice
- [x] Replay window on webhook `timestamp` (1 h) plus idempotency
- [x] Already-paid / cancelled invoices never receive a second payment (logged for manual review)
- [x] HTTPS-only cURL, TLS verification on, no redirects, 10 s connect / 30 s total timeouts
- [x] Secrets never logged or sent to the browser; customers see only generic errors
- [x] No core file changes, no third-party dependencies
- [ ] **You:** keep WHMCS and PHP updated, restrict admin access, back up before going live

## Sandbox test plan

Use `sandbox` credentials only (docs: demo wallet `123456789` / PIN `123456`, voucher `TESTVOUCHER`;
sandbox payments auto-succeed).

| # | Test | Expected |
|---|---|---|
| 1 | Pay a small invoice | Invoice Paid; transaction ID = Ovajj `trx_id`; log "Successful" |
| 2 | Cancel on Ovajj checkout | Returns to invoice with failure notice; stays Unpaid |
| 3 | Failed / pending payment | Stays Unpaid; log "Failure"/"Pending" |
| 4 | Wrong API key/secret | Customer sees generic failure; log "Initiation Failed" with HTTP 401 |
| 5 | Replay a webhook with a modified body | 401, log "Invalid Signature" |
| 6 | Re-send the same valid webhook | 200 `already_processed`; no second payment |
| 7 | Send two identical webhooks simultaneously | Exactly one payment |
| 8 | Webhook to another invoice's URL / bad `t=` | 403 |
| 9 | Amount edited after session creation (change invoice) | Log "Amount Mismatch", not paid |
| 10 | Invoice currency not enabled in Ovajj | Initiation fails with 422 logged |
| 11 | Pay an already-paid invoice | Log "Invoice Not Payable"; no extra payment |
| 12 | Block outbound HTTPS to ovajj.com | Verification returns 503; invoice untouched |
| 13 | Open an expired `payment_url` | Ovajj-side expiry; customer clicks Pay Now again for a fresh session |
| 14 | Sandbox webhook while module set to Production | 400 `environment_mismatch` |
| 15 | Full and partial refund from WHMCS | Success; repeat within the hour is not double-refunded |

## Troubleshooting

| Symptom | Check |
|---|---|
| "Temporarily unavailable" on invoice | Credentials for the selected environment are empty (Activity Log) |
| Pay Now returns to invoice with failure | Gateway Transaction Log → "Initiation Failed" row has the API error (currency/wallet/401/422) |
| Paid at Ovajj but invoice Unpaid | Transaction Log: "Invalid Signature" (secret mismatch → set Webhook Secret), "Verification Impossible" (no `trx_id`), or nothing (webhook can't reach your site) |
| 401 from API | Merchant Key, API Key and Secret must all be of the same environment |
| 429 | Ovajj rate limit (120/min default) |
| Clock errors | Server time must be within ~300 s of real time (signed timestamps) |

## Known limitations / API uncertainties (confirm with Ovajj)

1. **`trx_id` in the webhook.** `verify-payment` needs Ovajj's transaction ID, but the documented
   webhook example shows only `data.ref_trx`. The docs elsewhere refer to `data.trx_id`, which this module
   requires. If it is absent the module refuses to mark the invoice paid (log: "Verification Impossible").
   Ask Ovajj to confirm the field; do not work around it by trusting the webhook alone.
2. **Webhook secret.** Webhooks are verified with the API Secret. If Ovajj says its webhook secret differs, the module needs a small change.
3. **`amount` vs `fee` in verify.** The example shows amount 237.5 / fee 12.5 for a 250 payment. The module
   accepts `amount` or `amount + fee` equal to the invoice balance (±1 cent, because Ovajj rounds fee and net separately) and records the fee.
4. **`X-Signature` prefix.** Docs show both `sha256=…` and bare hex; requests use `sha256=` (as the cURL examples do).
5. **Redirect parameters.** The docs do not say whether success/cancel redirects carry parameters, so the module
   does not rely on them; the IPN is the only settlement path.
6. **Refunds** reverse the Ovajj ledger; Ovajj returns the money to the buyer's card, and the original processing
   fee is not returned. Identical partial refunds within one clock hour are collapsed by design.
7. **"Convert To For Processing"** (WHMCS currency conversion) is unsupported; such invoices show an unavailable notice.
8. Minimum amount is 1.00 (documented). Recurring/subscription endpoints are not used.
9. The docs host sample uses placeholder text from another product ("DigiKash"); the module uses only `https://ovajj.com`.

## License

MIT - see the [LICENSE](LICENSE) file.
