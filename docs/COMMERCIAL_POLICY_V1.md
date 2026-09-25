# SENTINEL APEX Commercial Policy v1 (owner decision, 2026-09-24)

This file records the production commercial policy and how the platform
enforces it. `config/commercial-contract.json` stays the canonical source for
prices, quotas and the cancellation clause ("Cancel any time; access runs to
the end of the paid period. No pro-rata refund."). This policy is consistent
with it.

## Decisions

| Area | Decision | Enforced by |
|---|---|---|
| Refunds | 7-day conditional money-back guarantee on a customer's first purchase, merchant-approved. No automatic or self-service refunds. No partial or pro-rata refunds after the guarantee period. | `workers/revenue-engine/src/billing-routes.js` |
| Manual payments | Public UPI / NEFT / crypto payment proof is retired. Enterprise bank transfer only against an approved quote/PO (separate accounts-receivable workflow, not built here). | Gateway `POST /api/payment/manual-notify` and revenue-engine `POST /api/payments/submit` answer **410** |
| Checkout | PRO, Enterprise and MSSP are recurring and sold only as Razorpay Subscriptions. One-time Orders only for explicit one-time SKUs (none on sale). | `upgrade.html` (no fallback); gateway `create-order` answers **409 subscription_required** for recurring tiers |
| GST | Invoices only from operator-supplied, CA-confirmed configuration. CGST+SGST when the supplier state equals the place of supply, otherwise IGST. | `workers/revenue-engine/src/gst.js`, `billing-ledger.js` |

## Before this ships: merge preconditions

Once this change is deployed, **a plan/cycle without a live Razorpay Plan ID
cannot be bought online.** The page tells the buyer no payment was taken, and
there is no one-time fallback. Before merging:

1. Create the six Razorpay Plans (PRO / ENTERPRISE / MSSP x monthly / annual)
   at the INR amounts in `workers/intel-gateway/src/pricing-data.json`, and set
   them on the revenue engine:
   ```
   cd workers/revenue-engine
   npx wrangler secret put RAZORPAY_PLAN_ID_PRO_MONTHLY
   npx wrangler secret put RAZORPAY_PLAN_ID_PRO_ANNUAL
   npx wrangler secret put RAZORPAY_PLAN_ID_ENTERPRISE_MONTHLY
   npx wrangler secret put RAZORPAY_PLAN_ID_ENTERPRISE_ANNUAL
   npx wrangler secret put RAZORPAY_PLAN_ID_MSSP_MONTHLY
   npx wrangler secret put RAZORPAY_PLAN_ID_MSSP_ANNUAL
   ```
2. Confirm all six are live: `GET https://revenue.intel.cyberdudebivash.com/api/health`
   with `X-Admin-Secret` must show every `razorpay_plan_ids_configured` value `true`.
3. In the Razorpay Dashboard, point a webhook at
   `https://intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay`
   (secret = `RAZORPAY_WEBHOOK_SECRET`) with these events:
   `subscription.authenticated`, `subscription.activated`, `subscription.charged`,
   `subscription.pending`, `subscription.halted`, `subscription.cancelled`,
   `subscription.completed`, `payment.failed`, `refund.created`,
   `refund.processed`, `refund.failed`, `payment.dispute.created`.

## GST invoice activation

Until `GST_INVOICE_CONFIG` is set and complete, every captured charge is still
recorded on the ledger. Its invoice is **held** (`gst_config_incomplete`) and
can be issued later. Nothing legal is hard-coded or inferred.

```
npx wrangler secret put GST_INVOICE_CONFIG
{
  "supplier_legal_name": "<exactly as on the GST registration>",
  "supplier_trade_name": "<trade name, optional>",
  "supplier_gstin": "21ARKPN8270G1ZP",
  "supplier_address": "<principal place of business exactly as on the GST registration>",
  "sac": { "subscription": "<CA-confirmed SAC, 99xxxx>" },
  "gst_rate_percent": <CA-confirmed rate>,
  "invoice_prefix": "CDB",
  "confirmed_by": "<CA / firm>",
  "confirmed_on": "YYYY-MM-DD"
}
```

- **Invoice numbers** are `CDB/26-27/000001`: prefix, Indian financial year
  (April-March, IST), then a 6-digit serial per financial year. CGST Rules
  r.46(b) caps the number at **16 characters**. The proposed
  `CDB-SA/26-27/000001` is 19, so it is refused, and any prefix over 3
  characters is refused. Serials come from one D1 transaction:
  `UNIQUE(fy, seq)`, `UNIQUE(invoice_number)`, `UNIQUE(payment_id)`, with no
  gaps even under concurrent webhooks.
- **Amounts**: the Razorpay charge is the total. Taxable value = total / (1 + rate).
- **Place of supply**: the recipient's GSTIN state; else the declared billing
  state; else the supplier's location (no recipient address on record).
- **Held for review, never guessed**: recipients outside India (export
  treatment), non-INR payments, registered buyers without name + address, and
  unregistered buyers at or above INR 50,000 without name, address and state
  (r.46(e)). Resolve with `POST /api/v2/billing/invoices/issue`.
- **Refunded invoices** are flagged `refunded_credit_note_required`. Credit
  notes are not generated yet.

## Refund workflow

```
customer request -> eligibility -> admin approve/reject -> Razorpay refund (server-side)
  -> refund.* webhook -> ledger + request reconciled -> entitlement revoked + subscription cancelled -> audit events
```

- Eligibility (at request time): the account's **first** captured payment,
  within **7 calendar days**, no refund yet, and no dispute
  (`payment.dispute.*` marks the payment).
- The amount is never read from a request. It is the ledger amount (written
  from Razorpay's signed webhook) and must equal Razorpay's captured amount at
  approval time.
- A request exists at most once per payment (`UNIQUE(payment_id)`). Approval
  is compare-and-set, so concurrent approvals refund once. A retried approval
  adopts an existing Razorpay refund instead of refunding twice.
- Revocation happens on `refund.created` / `refund.processed`, including
  refunds made directly in the Razorpay Dashboard.

| Route | Auth | Purpose |
|---|---|---|
| `POST /api/v2/billing/refunds/request` | customer `X-API-Key`, or `X-Admin-Secret` + `{email}` | File a request (no money moves) |
| `GET /api/v2/billing/refunds?status=pending_review` | `X-Admin-Secret` | Review queue |
| `POST /api/v2/billing/refunds/approve` `{request_id, note}` | `X-Admin-Secret` | Refund via Razorpay |
| `POST /api/v2/billing/refunds/reject` `{request_id, note}` | `X-Admin-Secret` | Decline |
| `POST /api/v2/billing/subscriptions/cancel` | customer `X-API-Key` | Cancel at cycle end (no refund) |
| `GET /api/v2/billing/invoices` | customer `X-API-Key` / admin `?email=` | List invoices |
| `GET /api/v2/billing/invoices/view?number=&format=html` | owner or admin | Invoice (JSON or HTML) |
| `GET /api/v2/billing/invoices/holds` | `X-Admin-Secret` | Held invoices and reasons |
| `POST /api/v2/billing/invoices/issue` | `X-Admin-Secret` | Complete recipient details, issue |

## Known gaps (not in this change)

- **Gumroad** still sells USD 30-day / 12-month grants that do not renew.
  That is a one-time payment for a recurring service, which decision 3 rules
  out for Razorpay. Deciding Gumroad's future (memberships, or USD Razorpay
  plans) is open.
- GST **credit notes** for refunded invoices; **export** (LUT) invoicing;
  **e-invoicing (IRN)** if aggregate turnover crosses the threshold.
- Enterprise **quote/PO -> bank transfer** accounts-receivable workflow.
- One-time orders bought **before** this change are refunded from the Razorpay
  Dashboard. The gateway's existing `refund.*` webhook revokes their keys.
- The revenue engine cannot write the gateway's `jwt_deny` marker, so after a
  refund an already-issued dashboard JWT can last up to its 24h expiry. API
  keys are denied immediately (`subscription_status: refunded`, `expires_at`).
