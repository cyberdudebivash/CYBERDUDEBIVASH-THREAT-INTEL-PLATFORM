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
- **Held for review, never guessed**: non-INR payments, exports that fail a
  LUT condition (next section), registered buyers without name + address,
  and unregistered buyers at or above INR 50,000 without name, address and
  state (r.46(e)). Resolve with `POST /api/v2/billing/invoices/issue`.

## Export of services under LUT (2026-09-25)

IGST Act s.2(6) and s.16(3)(a); CGST Rules r.96A. A supply to a recipient
outside India is invoiced **zero-rated** (IGST 0%, no tax carved out of the
amount). The invoice carries the declaration "SUPPLY MEANT FOR EXPORT UNDER
LETTER OF UNDERTAKING WITHOUT PAYMENT OF INTEGRATED TAX", the LUT ARN, and
place of supply 96 with the country. This only happens when every condition
the platform can evidence holds; otherwise the invoice is held:

| Condition | Evidence | Hold reason |
|---|---|---|
| LUT accepted for the invoice's financial year | `luts` in `GST_INVOICE_CONFIG` | `export_lut_not_configured_for_<fy>` |
| Recipient name, address, country | checkout (Outside India + ISO country), or admin | `export_recipient_name_address_country_required` |
| Consideration in convertible foreign exchange | Razorpay's `international` flag on the payment; an operator confirmation with a FIRC/BRC reference; or (PO) the FIRC recorded at reconciliation | `export_foreign_exchange_not_evidenced` |

```
"luts": [ { "arn": "<LUT ARN>", "financial_year": "26-27" } ]
```

File a new LUT each financial year and add it before 1 April. A refund of an
export invoice gets a zero-rated credit note. Whether a particular receipt
qualifies as convertible foreign exchange (for example, an international card
settled in INR by Razorpay) is for your CA to confirm; the operator
confirmation path exists for exactly that.

Confirm realisation for a held Razorpay export:
`POST /api/v2/billing/invoices/issue {payment_id, export_realisation_confirmed: true, export_realisation_reference: "FIRC-..."}`.
- **Refunded invoices get credit notes** (next section).

## GST credit notes (2026-09-25)

CGST Act s.34 and CGST Rules r.53. Every refund that Razorpay reports as
**processed** gets exactly one credit note against the payment's invoice.
This covers refunds from approved requests and refunds made in the Dashboard.

- **Refund ledger:** `billing_refunds` is written from `refund.created` and
  `refund.processed` (`refund_id` PRIMARY KEY). Its status only moves forward.
- **Numbering:** `CN/26-27/000001`, a separate consecutive series per
  financial year of the note date. `credit_note_prefix` in
  `GST_INVOICE_CONFIG` is optional (default `CN`). It must differ from the
  invoice prefix and keep the number within 16 characters. The serial comes
  from the same single-transaction allocation as invoices:
  `UNIQUE(fy, seq)`, `UNIQUE(credit_note_number)`, `UNIQUE(refund_id)`.
- **Contents:** the original invoice number and date, the reason,
  supplier/recipient, place of supply, and the **same supply type and
  rate** as the invoice. The tax is carved out of the refunded amount.
  Partial refunds each get their own note.
- **Never over-credited:** credit notes for a payment never total more than
  its invoice. This is enforced inside the issuing transaction, so
  concurrent refunds cannot overshoot either. An excess is held
  (`credit_would_exceed_invoice_total`).
- **Invoice status** becomes `partially_credited`, then `credited`.
- **Held invoice:** a refund processed while its invoice is held gets its
  credit note automatically right after the invoice is issued.
- **s.34(2) deadline:** each note records `gst_adjustment.deadline`
  (30 November after the invoice's financial year) and `within_deadline`.
  A note issued after that date is still a valid commercial credit, but it
  no longer reduces output tax.

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
| `GET /api/v2/billing/credit-notes` | customer `X-API-Key` / admin `?email=` | List credit notes |
| `GET /api/v2/billing/credit-notes/view?number=&format=html` | owner or admin | Credit note (JSON or HTML) |
| `GET /api/v2/billing/credit-notes/pending` | `X-Admin-Secret` | Processed refunds without a credit note |
| `POST /api/v2/billing/credit-notes/issue` `{refund_id}` | `X-Admin-Secret` | Retry a held credit note |

## Gumroad memberships (2026-09-25)

Recurring plans on Gumroad are sold as **memberships**. The gateway webhook
(`workers/intel-gateway/src/gumroad-lifecycle.js`, `handleWebhookGumroad`)
handles every Gumroad ping:

| Ping | Effect |
|---|---|
| first sale | provisions one key, mapped by `subscription_id` and `sale_id` |
| recurring charge (`is_recurring_charge`, or a sale on an already-mapped subscription) | **extends the same key** by one cycle from the later of the current expiry and the charge time; a redelivery extends once; a lapsed or cancelled membership that charges again is reactivated |
| charge on a `refunded` / `suspended` key | not reactivated; flagged `renewal_requires_review` |
| `cancelled` | access continues to the end of the paid period |
| `ended` | access revoked |
| `refunded` (any charge) | key `refunded`, access revoked |
| `disputed` (not won) | key `suspended` (an operator can reactivate if the dispute is won) |

Before this change, each monthly renewal would have minted a new key, and a
refund ping was swallowed as "already provisioned".

**Cutover (owner action).** Create a membership product per plan and cycle in
the Gumroad dashboard: PRO and Enterprise, monthly and yearly, at the same USD
prices. Put each permalink in `GUMROAD_MEMBERSHIP_URLS` in `upgrade.html`.
A plan/cycle with a membership URL is sold as the membership ("renews
monthly/yearly"). One without keeps the legacy one-time grant, labelled
"30-day grant, no auto-renew". `terms.html` and `pricing.html` are accurate
in both states. Existing grant holders keep access to the end of their paid
period; their refunds and chargebacks are handled the same way when the sale
was provisioned after this change.

## Enterprise quote -> PO -> invoice -> bank transfer (2026-09-25)

The only bank-transfer path. Public manual payment proof stays retired.
Module: `workers/revenue-engine/src/enterprise-po.js`, table `enterprise_quotes`.

```
sent --(customer: PO number + date, quote token)--> accepted
accepted --(finance: approve)--> invoiced          (tax invoice, shared GST engine)
invoiced --(finance: reconcile UTR [+TDS] [+FIRC])--> paid --> provisioned (API key by email)
sent/accepted --> cancelled (admin)      sent --(after valid_until)--> expired
```

- **Price:** ENTERPRISE INR 4,16,000 or MSSP INR 8,33,000 for 12 months, from
  the canonical contract (a drift test pins them to
  `config/commercial-contract.json`). A different price needs
  `custom_amount_inr` plus a `price_reason`, both recorded. As on Razorpay,
  the domestic amount is GST-inclusive; an export is zero-rated.
- **Customer capability:** `HMAC(REVENUE_ADMIN_SECRET, "quote:"+id)`, returned
  once at creation. Send the view link to the customer; it opens only that
  quote. A wrong token and a missing quote look the same.
- **Invoice:** a tax invoice (series `CDB/...`) with the PO number in the line
  description, payable by bank transfer. The same hold rules apply, including
  LUT for exports (`bank_realisation_pending` until the FIRC arrives). Cannot
  be issued before the PO; approving twice gives one invoice.
- **Reconciliation:** received amount + TDS must equal the invoice total
  exactly. TDS needs a section (for example 194J), is capped at 20%, and is
  not allowed on an export. The bank reference (UTR/SWIFT) is `UNIQUE`: one
  transfer settles one invoice. An export needs the FIRC/e-BRC reference.
- **Entitlement:** `provisionCustomer` runs exactly once
  (`paid -> provisioning -> provisioned`). A failure returns the quote to
  `paid` for `POST /quotes/provision`. The key goes to the customer by the
  welcome email; responses show only a 12-character hint.
- An invoiced quote cannot be cancelled. Reverse it with a credit note.

| Route | Auth | Purpose |
|---|---|---|
| `POST /api/v2/billing/quotes` | admin | Create (`email, company_name, billing_address, gstin or billing_state [+billing_country], tier`) |
| `GET /api/v2/billing/quotes?status=` | admin | List |
| `GET /api/v2/billing/quotes/view?id=&token=[&format=html]` | quote token / admin | Quotation |
| `POST /api/v2/billing/quotes/accept` `{id, token, po_number, po_date}` | quote token | Customer accepts with a PO |
| `POST /api/v2/billing/quotes/invoice` `{id}` | admin | Approve the PO and issue the tax invoice |
| `POST /api/v2/billing/quotes/reconcile` `{id, amount_received_paise, tds_paise?, tds_section?, bank_reference, received_on, firc_reference?}` | admin | Match the transfer and provision |
| `POST /api/v2/billing/quotes/provision` `{id}` | admin | Retry provisioning |
| `POST /api/v2/billing/quotes/cancel` `{id, note}` | admin | Cancel before invoicing |

## Known gaps (not in this change)

- **Gumroad membership products** themselves (owner action, see the cutover
  above). Until they exist, Gumroad keeps selling the labelled one-time grant.
- Gumroad sales provisioned **before** 2026-09-25 have no `sale_id` → key
  mapping. A refund ping for one is flagged (`noted_no_mapping`) for manual
  revocation.
- **e-invoicing (IRN)** if aggregate turnover crosses the threshold; filing
  invoices and credit notes in GSTR-1 (operator).
- PO terms other than 12 months, PO renewals, and refunds of bank-transfer
  payments (made by bank, then recorded manually).
- One-time orders bought **before** this change are refunded from the Razorpay
  Dashboard. The gateway's existing `refund.*` webhook revokes their keys.
- Refund revocation is immediate across API keys and already-issued JWTs.
  The revenue engine writes `jwt_deny:<customer_id>` into the shared
  `API_KEYS_KV` namespace when Razorpay confirms a refund; gateway bearer
  authentication and APEX mesh admission check that marker on every JWT
  request. The marker outlives the maximum JWT lifetime and is cleared only
  by a genuine new paid activation.
