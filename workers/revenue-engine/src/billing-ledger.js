// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Revenue Engine: billing ledger (D1)
//
// The authoritative record of money received through Razorpay Subscriptions,
// the GST invoices issued against it, and refund requests. Everything that
// moves money or issues a tax document reads amounts from here (captured
// from Razorpay's signed webhook), never from a browser.
//
// Integrity is enforced by the database, not by read-then-write:
//   billing_payments.payment_id   PRIMARY KEY   one ledger row per payment
//   invoices.payment_id           UNIQUE        one invoice per payment
//   invoices.invoice_number       UNIQUE
//   invoices(fy, seq)             UNIQUE        CGST Rules r.46(b) serials
//   refund_requests.payment_id    UNIQUE        one refund request per payment
// The invoice serial is taken and the invoice row inserted in ONE D1 batch
// (a transaction): a duplicate webhook that loses the UNIQUE(payment_id) race
// rolls the whole batch back, so no serial number is ever skipped.
//
// Tables are created idempotently on first use (and are also listed in
// revenue-crm/schema.sql), so a deploy never depends on a manual migration.
// =============================================================================

import {
  financialYear, istDate, placeOfSupply, splitInclusiveTax,
  parseGstInvoiceConfig, GST_STATES, creditNoteAdjustmentDeadline, lutFor, GST_FOREIGN_POS_CODE,
} from "./gst.js";

export const BILLING_SCHEMA = [
  `CREATE TABLE IF NOT EXISTS billing_payments (
    payment_id      TEXT PRIMARY KEY,
    provider        TEXT NOT NULL DEFAULT 'razorpay',
    provider_sub_id TEXT,
    email           TEXT NOT NULL,
    tier            TEXT NOT NULL,
    billing_cycle   TEXT NOT NULL,
    amount_paise    INTEGER NOT NULL CHECK (amount_paise > 0),
    currency        TEXT NOT NULL,
    captured_at     TEXT NOT NULL,
    buyer_gstin     TEXT NOT NULL DEFAULT '',
    buyer_vat_id    TEXT NOT NULL DEFAULT '',
    billing_state   TEXT NOT NULL DEFAULT '',
    billing_name    TEXT NOT NULL DEFAULT '',
    billing_address TEXT NOT NULL DEFAULT '',
    invoice_status  TEXT NOT NULL DEFAULT 'pending',
    invoice_hold_reason TEXT NOT NULL DEFAULT '',
    refund_status   TEXT NOT NULL DEFAULT 'none',
    refunded_paise  INTEGER NOT NULL DEFAULT 0,
    disputed        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_billing_payments_email ON billing_payments (email, captured_at)`,
  `CREATE TABLE IF NOT EXISTS invoice_sequences (
    fy       TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS invoices (
    id              TEXT PRIMARY KEY,
    invoice_number  TEXT NOT NULL UNIQUE,
    fy              TEXT NOT NULL,
    seq             INTEGER NOT NULL,
    payment_id      TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL,
    invoice_date    TEXT NOT NULL,
    issued_at       TEXT NOT NULL,
    document        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'issued',
    UNIQUE (fy, seq)
  )`,
  `CREATE TABLE IF NOT EXISTS refund_requests (
    id                 TEXT PRIMARY KEY,
    payment_id         TEXT NOT NULL UNIQUE,
    email              TEXT NOT NULL,
    status             TEXT NOT NULL,
    reason             TEXT NOT NULL DEFAULT '',
    amount_paise       INTEGER NOT NULL,
    requested_at       TEXT NOT NULL,
    decided_at         TEXT,
    decision_note      TEXT NOT NULL DEFAULT '',
    razorpay_refund_id TEXT UNIQUE,
    last_error         TEXT NOT NULL DEFAULT '',
    updated_at         TEXT NOT NULL
  )`,
  // Refunds as Razorpay reports them (refund.* webhooks): the authority for
  // credit notes, whether the refund came from a request or the Dashboard.
  `CREATE TABLE IF NOT EXISTS billing_refunds (
    refund_id    TEXT PRIMARY KEY,
    payment_id   TEXT NOT NULL,
    amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    processed_at TEXT
  )`,
  `CREATE INDEX IF NOT EXISTS idx_billing_refunds_payment ON billing_refunds (payment_id)`,
  // Enterprise quote -> PO -> invoice -> bank transfer -> reconciliation ->
  // entitlement (enterprise-po.js). bank_reference is UNIQUE: one bank
  // transfer can settle only one invoice.
  `CREATE TABLE IF NOT EXISTS enterprise_quotes (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL,
    company_name        TEXT NOT NULL,
    billing_address     TEXT NOT NULL,
    billing_state       TEXT NOT NULL DEFAULT '',
    billing_country     TEXT NOT NULL DEFAULT '',
    buyer_gstin         TEXT NOT NULL DEFAULT '',
    tier                TEXT NOT NULL,
    term_months         INTEGER NOT NULL,
    amount_paise        INTEGER NOT NULL CHECK (amount_paise > 0),
    price_basis         TEXT NOT NULL,
    price_reason        TEXT NOT NULL DEFAULT '',
    valid_until         TEXT NOT NULL,
    status              TEXT NOT NULL,
    po_number           TEXT NOT NULL DEFAULT '',
    po_date             TEXT NOT NULL DEFAULT '',
    accepted_at         TEXT,
    invoice_number      TEXT NOT NULL DEFAULT '',
    invoice_hold_reason TEXT NOT NULL DEFAULT '',
    bank_reference      TEXT UNIQUE,
    received_paise      INTEGER,
    tds_paise           INTEGER,
    tds_section         TEXT NOT NULL DEFAULT '',
    received_on         TEXT NOT NULL DEFAULT '',
    firc_reference      TEXT NOT NULL DEFAULT '',
    reconciled_at       TEXT,
    api_key_hint        TEXT NOT NULL DEFAULT '',
    provisioned_at      TEXT,
    cancel_note         TEXT NOT NULL DEFAULT '',
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_enterprise_quotes_status ON enterprise_quotes (status, created_at)`,
  `CREATE TABLE IF NOT EXISTS credit_note_sequences (
    fy       TEXT PRIMARY KEY,
    last_seq INTEGER NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS credit_notes (
    id                 TEXT PRIMARY KEY,
    credit_note_number TEXT NOT NULL UNIQUE,
    fy                 TEXT NOT NULL,
    seq                INTEGER NOT NULL,
    refund_id          TEXT NOT NULL UNIQUE,
    payment_id         TEXT NOT NULL,
    invoice_number     TEXT NOT NULL,
    email              TEXT NOT NULL,
    total_paise        INTEGER NOT NULL,
    note_date          TEXT NOT NULL,
    issued_at          TEXT NOT NULL,
    document           TEXT NOT NULL,
    UNIQUE (fy, seq)
  )`,
];

// Additive column migrations, applied after BILLING_SCHEMA. A table that
// already exists in production never gains columns from CREATE TABLE IF NOT
// EXISTS, so new columns arrive here; "duplicate column" means already applied.
export const BILLING_MIGRATIONS = [
  // Export of services (2026-09-25): buyer country, Razorpay's own
  // "international" flag (card/method issued outside India: evidence of a
  // foreign-currency payment), and how realisation was evidenced.
  `ALTER TABLE billing_payments ADD COLUMN billing_country TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE billing_payments ADD COLUMN payment_international INTEGER NOT NULL DEFAULT 0`,
  `ALTER TABLE billing_payments ADD COLUMN export_basis TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE billing_payments ADD COLUMN export_reference TEXT NOT NULL DEFAULT ''`,
];

const _schemaReady = new WeakSet();

/** Creates the billing tables and applies column migrations once per D1 binding per isolate. */
export async function ensureBillingSchema(db) {
  if (!db) throw new Error("CRM_DB binding is required for billing");
  if (_schemaReady.has(db)) return;
  await db.batch(BILLING_SCHEMA.map((sql) => db.prepare(sql)));
  for (const sql of BILLING_MIGRATIONS) {
    try { await db.prepare(sql).run(); } catch (err) {
      if (!/duplicate column/i.test(String(err && err.message))) throw err;
    }
  }
  _schemaReady.add(db);
}

// --- payments ----------------------------------------------------------------

/**
 * Records a captured Razorpay payment for a subscription. Idempotent on
 * payment_id (a redelivered webhook inserts nothing). Returns the stored row.
 */
export async function recordCapturedPayment(db, { payment, providerSubId, email, tier, billingCycle, buyer }) {
  await ensureBillingSchema(db);
  if (!payment || !payment.id) throw new Error("recordCapturedPayment: payment entity required");
  if (payment.status !== "captured") throw new Error(`recordCapturedPayment: payment ${payment.id} is ${payment.status}, not captured`);
  if (!Number.isInteger(payment.amount) || payment.amount <= 0) throw new Error("recordCapturedPayment: invalid amount");
  const capturedAt = payment.created_at ? new Date(payment.created_at * 1000).toISOString() : new Date().toISOString();
  const b = buyer || {};
  await db.prepare(
    `INSERT INTO billing_payments (payment_id, provider_sub_id, email, tier, billing_cycle, amount_paise, currency,
       captured_at, buyer_gstin, buyer_vat_id, billing_state, billing_name, billing_address, created_at,
       billing_country, payment_international)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT (payment_id) DO NOTHING`
  ).bind(
    payment.id, providerSubId || null, email, tier, billingCycle || "monthly", payment.amount,
    String(payment.currency || "INR").toUpperCase(), capturedAt,
    b.gstin || "", b.vat_id || "", b.billing_state || "", b.billing_name || "", b.billing_address || "",
    new Date().toISOString(), b.billing_country || "", payment.international === true ? 1 : 0,
  ).run();
  return await getPayment(db, payment.id);
}

export async function getPayment(db, paymentId) {
  await ensureBillingSchema(db);
  return await db.prepare(`SELECT * FROM billing_payments WHERE payment_id = ?`).bind(paymentId).first();
}

/** The customer's first-ever payment (the only one the 7-day guarantee can cover). */
export async function firstPaymentFor(db, email) {
  await ensureBillingSchema(db);
  return await db.prepare(
    `SELECT * FROM billing_payments WHERE email = ? ORDER BY captured_at ASC, payment_id ASC LIMIT 1`
  ).bind(email).first();
}

export async function markDisputed(db, paymentId) {
  await ensureBillingSchema(db);
  const r = await db.prepare(`UPDATE billing_payments SET disputed = 1 WHERE payment_id = ?`).bind(paymentId).run();
  return (r.meta && r.meta.changes) || 0;
}

/** Applies a refund reported by Razorpay (webhook). Never lowers refunded_paise. */
export async function applyRefundToPayment(db, paymentId, { refundedPaise, status }) {
  await ensureBillingSchema(db);
  const r = await db.prepare(
    `UPDATE billing_payments SET refunded_paise = MAX(refunded_paise, ?), refund_status = ? WHERE payment_id = ?`
  ).bind(refundedPaise, status, paymentId).run();
  if ((r.meta && r.meta.changes) && status === "refunded") {
    // Flags an uncredited invoice until its credit note exists; never
    // overwrites a credited status (a redelivered refund webhook).
    await db.prepare(`UPDATE invoices SET status = 'refunded_credit_note_required' WHERE payment_id = ? AND status = 'issued'`).bind(paymentId).run();
  }
  return (r.meta && r.meta.changes) || 0;
}

// --- invoices ----------------------------------------------------------------

const INVOICE_SERIAL_MAX = 999999; // six digits keeps the number within 16 characters
const B2C_DETAILS_THRESHOLD_PAISE = 50000 * 100; // CGST Rules r.46(e): recipient details at >= INR 50,000

/**
 * Why this payment cannot be invoiced automatically, or null when it can.
 * Nothing here guesses a legal field: a hold is resolved by an operator.
 */
export function invoiceHoldReason(row, cfg) {
  if (!cfg.ok) return "gst_config_incomplete:" + cfg.missing.join(",");
  if (row.currency !== "INR") return "non_inr_payment_requires_review";
  const pos = placeOfSupply({ buyerGstin: row.buyer_gstin, billingState: row.billing_state, supplierStateCode: cfg.config.supplier_state_code });
  if (pos.export) return exportHoldReason(row, cfg.config);
  if (row.buyer_gstin && (!row.billing_name || !row.billing_address)) return "registered_recipient_name_and_address_required";
  if (!row.buyer_gstin && row.amount_paise >= B2C_DETAILS_THRESHOLD_PAISE &&
      (!row.billing_name || !row.billing_address || !row.billing_state)) {
    return "unregistered_recipient_details_required_at_or_above_50000";
  }
  return null;
}

/**
 * Export of services under LUT (IGST Act s.2(6), s.16(3)(a); CGST Rules
 * r.96A). Issued zero-rated only when every condition the platform can
 * evidence holds; everything else is held for a person to decide.
 *   - a LUT accepted for the invoice's financial year (config)
 *   - recipient name, address and country (outside India)
 *   - consideration in convertible foreign exchange: Razorpay's own
 *     "international" flag on the payment, an operator's confirmation, or
 *     (purchase orders) bank realisation recorded at reconciliation
 */
export function exportHoldReason(row, c) {
  const fy = financialYear(row.captured_at);
  if (!lutFor(c, fy)) return "export_lut_not_configured_for_" + fy;
  if (!row.billing_name || !row.billing_address || !row.billing_country) return "export_recipient_name_address_country_required";
  if (!row.payment_international && !["operator_confirmed", "bank_realisation_pending"].includes(row.export_basis)) {
    return "export_foreign_exchange_not_evidenced";
  }
  return null;
}

function buildExportInvoiceDocument(row, c) {
  const lut = lutFor(c, financialYear(row.captured_at));
  return {
    schema: "cdb-gst-invoice/1.0",
    invoice_date: istDate(row.captured_at),
    supplier: {
      legal_name: c.supplier_legal_name, trade_name: c.supplier_trade_name, gstin: c.supplier_gstin,
      address: c.supplier_address, state_code: c.supplier_state_code, state_name: c.supplier_state_name,
    },
    recipient: {
      name: row.billing_name, address: row.billing_address, email: row.email, country: row.billing_country,
      gstin: null, registered: false,
    },
    place_of_supply: { state_code: GST_FOREIGN_POS_CODE, state_name: "Other Countries", country: row.billing_country, basis: "recipient_outside_india" },
    supply_type: "export_under_lut",
    reverse_charge: false,
    export: {
      declaration: "SUPPLY MEANT FOR EXPORT UNDER LETTER OF UNDERTAKING WITHOUT PAYMENT OF INTEGRATED TAX",
      lut_arn: lut.arn, lut_financial_year: lut.financial_year,
      realisation_basis: row.payment_international ? "razorpay_international_payment" : row.export_basis,
      realisation_reference: row.export_reference || null,
    },
    line_items: [{
      description: row.description || `SENTINEL APEX ${row.tier} subscription (${row.billing_cycle})`,
      sac: c.sac_subscription, quantity: 1, taxable_value_paise: row.amount_paise,
    }],
    tax: {
      rate_percent: 0, cgst_rate_percent: 0, sgst_rate_percent: 0, igst_rate_percent: 0,
      taxable_paise: row.amount_paise, cgst_paise: 0, sgst_paise: 0, igst_paise: 0, tax_paise: 0, total_paise: row.amount_paise,
    },
    amount_basis: "Zero-rated export of services: no GST charged.",
    currency: "INR",
    payment: row.payment_block,
    config_confirmed_by: c.confirmed_by, config_confirmed_on: c.confirmed_on,
  };
}

function buildInvoiceDocument(row, c) {
  if (placeOfSupply({ buyerGstin: row.buyer_gstin, billingState: row.billing_state, supplierStateCode: c.supplier_state_code }).export) {
    return buildExportInvoiceDocument(row, c);
  }
  const pos = placeOfSupply({ buyerGstin: row.buyer_gstin, billingState: row.billing_state, supplierStateCode: c.supplier_state_code });
  const intra = pos.code === c.supplier_state_code;
  const tax = splitInclusiveTax(row.amount_paise, c.gst_rate_percent, intra);
  return {
    schema: "cdb-gst-invoice/1.0",
    invoice_date: istDate(row.captured_at),
    supplier: {
      legal_name: c.supplier_legal_name, trade_name: c.supplier_trade_name, gstin: c.supplier_gstin,
      address: c.supplier_address, state_code: c.supplier_state_code, state_name: c.supplier_state_name,
    },
    recipient: {
      name: row.billing_name || null, address: row.billing_address || null, email: row.email,
      gstin: row.buyer_gstin || null, registered: !!row.buyer_gstin,
    },
    place_of_supply: { state_code: pos.code, state_name: GST_STATES[pos.code] || null, basis: pos.basis },
    supply_type: intra ? "intra_state" : "inter_state",
    reverse_charge: false,
    line_items: [{
      description: row.description || `SENTINEL APEX ${row.tier} subscription (${row.billing_cycle})`,
      sac: c.sac_subscription, quantity: 1, taxable_value_paise: tax.taxable_paise,
    }],
    tax: {
      rate_percent: c.gst_rate_percent,
      cgst_rate_percent: intra ? c.gst_rate_percent / 2 : 0, sgst_rate_percent: intra ? c.gst_rate_percent / 2 : 0,
      igst_rate_percent: intra ? 0 : c.gst_rate_percent,
      ...tax,
    },
    amount_basis: "The amount charged is the total, inclusive of GST.",
    currency: "INR",
    payment: row.payment_block,
    config_confirmed_by: c.confirmed_by, config_confirmed_on: c.confirmed_on,
  };
}

/**
 * The one invoice issuer. `key` is the invoice's unique source (a Razorpay
 * payment id, or "po:<quote id>"); `row` carries the subject in ledger
 * shape; `onHold(reason)` / `issuedStmt` record the outcome on the source's
 * own table (issuedStmt runs inside the issuing transaction).
 * @returns {{ status: "issued", invoice } | { status: "held", reason }}
 */
export async function issueInvoiceCore(db, env, { key, row, onHold, issuedStmt }) {
  await ensureBillingSchema(db);
  const existing = await getInvoiceByPayment(db, key);
  if (existing) return { status: "issued", invoice: existing };
  const cfg = parseGstInvoiceConfig(env.GST_INVOICE_CONFIG);
  const hold = invoiceHoldReason(row, cfg);
  if (hold) {
    await onHold(hold);
    return { status: "held", reason: hold };
  }
  const c = cfg.config;
  const fy = financialYear(row.captured_at);
  const doc = buildInvoiceDocument(row, c);
  const id = "inv_" + crypto.randomUUID().replace(/-/g, "").slice(0, 20);
  const notYet = `NOT EXISTS (SELECT 1 FROM invoices WHERE payment_id = ?)`;
  // One D1 batch = one transaction. The serial is incremented and read back
  // by the INSERT inside that transaction, so concurrent issuers serialize on
  // the database: no retry, no gap, no duplicate. For an already-invoiced
  // source both statements are no-ops, so no serial is consumed. A UNIQUE
  // violation (a concurrent issue for the same source) rolls it all back.
  try {
    await db.batch([
      db.prepare(`INSERT INTO invoice_sequences (fy, last_seq) VALUES (?, 0) ON CONFLICT (fy) DO NOTHING`).bind(fy),
      db.prepare(`UPDATE invoice_sequences SET last_seq = last_seq + 1 WHERE fy = ? AND last_seq < ? AND ${notYet}`)
        .bind(fy, INVOICE_SERIAL_MAX, key),
      db.prepare(
        `INSERT INTO invoices (id, invoice_number, fy, seq, payment_id, email, invoice_date, issued_at, document)
         SELECT ?, ? || '/' || fy || '/' || printf('%06d', last_seq), fy, last_seq, ?, ?, ?, ?, ?
           FROM invoice_sequences WHERE fy = ? AND last_seq > 0 AND ${notYet}`
      ).bind(id, c.invoice_prefix, key, row.email, doc.invoice_date, new Date().toISOString(), JSON.stringify(doc), fy, key),
      issuedStmt,
    ]);
  } catch (err) {
    const raced = await getInvoiceByPayment(db, key);
    if (raced) return { status: "issued", invoice: raced };
    throw err;
  }
  const issued = await getInvoiceByPayment(db, key);
  if (!issued) throw new Error(`issueInvoiceCore: no invoice after issuance for ${key} (serial space for ${fy} exhausted?)`);
  return { status: "issued", invoice: issued };
}

/**
 * Issues the GST invoice for a recorded Razorpay payment, or records why it
 * is held. Idempotent: an existing invoice for the payment is returned.
 * @returns {{ status: "issued", invoice } | { status: "held", reason }}
 */
export async function issueInvoiceForPayment(db, env, paymentId) {
  await ensureBillingSchema(db);
  const existing = await getInvoiceByPayment(db, paymentId);
  if (existing) return { status: "issued", invoice: existing };
  const ledger = await getPayment(db, paymentId);
  if (!ledger) throw new Error(`issueInvoiceForPayment: no ledger row for ${paymentId}`);
  const row = { ...ledger, payment_block: { provider: "razorpay", payment_id: ledger.payment_id,
    subscription_id: ledger.provider_sub_id, captured_at: ledger.captured_at } };
  const result = await issueInvoiceCore(db, env, {
    key: paymentId, row,
    onHold: (reason) => db.prepare(`UPDATE billing_payments SET invoice_status = 'held', invoice_hold_reason = ? WHERE payment_id = ?`)
      .bind(reason, paymentId).run(),
    issuedStmt: db.prepare(`UPDATE billing_payments SET invoice_status = 'issued', invoice_hold_reason = '' WHERE payment_id = ?
                AND EXISTS (SELECT 1 FROM invoices WHERE payment_id = ?)`).bind(paymentId, paymentId),
  });
  if (result.status !== "issued") return result;
  // A payment refunded while its invoice was held gets its credit notes now.
  await issuePendingCreditNotesForPayment(db, env, paymentId);
  return { status: "issued", invoice: await getInvoiceByPayment(db, paymentId) };
}

// The number and serial are the database's (assigned in the issuing
// transaction); the stored document carries everything else.
function _invoiceRow(r) {
  if (!r) return null;
  return { ...r, document: { ...JSON.parse(r.document), invoice_number: r.invoice_number, financial_year: r.fy, serial: r.seq } };
}

export async function getInvoiceByPayment(db, paymentId) {
  await ensureBillingSchema(db);
  return _invoiceRow(await db.prepare(`SELECT * FROM invoices WHERE payment_id = ?`).bind(paymentId).first());
}

export async function getInvoiceByNumber(db, number) {
  await ensureBillingSchema(db);
  return _invoiceRow(await db.prepare(`SELECT * FROM invoices WHERE invoice_number = ?`).bind(number).first());
}

export async function listInvoicesFor(db, email) {
  await ensureBillingSchema(db);
  const { results } = await db.prepare(
    `SELECT invoice_number, invoice_date, payment_id, status FROM invoices WHERE email = ? ORDER BY fy DESC, seq DESC LIMIT 100`
  ).bind(email).all();
  return results || [];
}

/** A customer's captured payments, newest first (Billing Center). Never the buyer's tax details. */
export async function listPaymentsFor(db, email) {
  await ensureBillingSchema(db);
  const { results } = await db.prepare(
    `SELECT payment_id, provider_sub_id, tier, billing_cycle, amount_paise, currency, captured_at,
            invoice_status, refund_status, refunded_paise, disputed
       FROM billing_payments WHERE email = ? ORDER BY captured_at DESC LIMIT 100`
  ).bind(email).all();
  return results || [];
}

export async function listInvoiceHolds(db) {
  await ensureBillingSchema(db);
  const { results } = await db.prepare(
    `SELECT payment_id, email, tier, amount_paise, currency, captured_at, invoice_hold_reason
       FROM billing_payments WHERE invoice_status = 'held' ORDER BY captured_at ASC LIMIT 500`
  ).all();
  return results || [];
}

/** Operator completes recipient details for a held payment (never amounts). */
export async function completeRecipientDetails(db, paymentId, { billing_name, billing_address, billing_state, billing_country, export_realisation_confirmed, export_reference }) {
  await ensureBillingSchema(db);
  const r = await db.prepare(
    `UPDATE billing_payments SET
       billing_name = COALESCE(NULLIF(?, ''), billing_name),
       billing_address = COALESCE(NULLIF(?, ''), billing_address),
       billing_state = COALESCE(NULLIF(?, ''), billing_state),
       billing_country = COALESCE(NULLIF(?, ''), billing_country),
       export_basis = CASE WHEN ? = 1 THEN 'operator_confirmed' ELSE export_basis END,
       export_reference = CASE WHEN ? = 1 THEN ? ELSE export_reference END
     WHERE payment_id = ? AND invoice_status != 'issued'`
  ).bind(billing_name || "", billing_address || "", billing_state || "", billing_country || "",
    export_realisation_confirmed === true ? 1 : 0, export_realisation_confirmed === true ? 1 : 0, export_reference || "", paymentId).run();
  return (r.meta && r.meta.changes) || 0;
}

// --- refund requests -----------------------------------------------------------

export async function getRefundRequest(db, id) {
  await ensureBillingSchema(db);
  return await db.prepare(`SELECT * FROM refund_requests WHERE id = ?`).bind(id).first();
}

export async function getRefundRequestByPayment(db, paymentId) {
  await ensureBillingSchema(db);
  return await db.prepare(`SELECT * FROM refund_requests WHERE payment_id = ?`).bind(paymentId).first();
}

export async function listRefundRequests(db, status) {
  await ensureBillingSchema(db);
  const q = status
    ? db.prepare(`SELECT * FROM refund_requests WHERE status = ? ORDER BY requested_at ASC LIMIT 200`).bind(status)
    : db.prepare(`SELECT * FROM refund_requests ORDER BY requested_at DESC LIMIT 200`);
  const { results } = await q.all();
  return results || [];
}

/** Inserts a request; returns null when one already exists for the payment (UNIQUE). */
export async function insertRefundRequest(db, { id, paymentId, email, reason, amountPaise, now }) {
  await ensureBillingSchema(db);
  const r = await db.prepare(
    `INSERT INTO refund_requests (id, payment_id, email, status, reason, amount_paise, requested_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (payment_id) DO NOTHING`
  ).bind(id, paymentId, email, "pending_review", reason, amountPaise, now, now).run();
  return (r.meta && r.meta.changes) ? await getRefundRequest(db, id) : null;
}

/**
 * Compare-and-set on status: exactly one caller wins a transition. Returns
 * the number of rows changed (0 when the request was not in `from`).
 */
export async function transitionRefundRequest(db, id, from, to, patch = {}) {
  await ensureBillingSchema(db);
  const fromList = Array.isArray(from) ? from : [from];
  const sets = ["status = ?", "updated_at = ?"];
  const vals = [to, new Date().toISOString()];
  for (const [k, v] of Object.entries(patch)) {
    if (!["decided_at", "decision_note", "razorpay_refund_id", "last_error"].includes(k)) throw new Error("bad refund patch key " + k);
    sets.push(`${k} = ?`);
    vals.push(v);
  }
  const r = await db.prepare(
    `UPDATE refund_requests SET ${sets.join(", ")} WHERE id = ? AND status IN (${fromList.map(() => "?").join(",")})`
  ).bind(...vals, id, ...fromList).run();
  return (r.meta && r.meta.changes) || 0;
}

// --- refunds + credit notes (CGST Act s.34, CGST Rules r.53) ------------------

/**
 * Records a refund Razorpay reported (idempotent on refund_id; status only
 * moves forward to "processed"). Returns the stored row.
 */
export async function recordRefund(db, { refundId, paymentId, amountPaise, status, atIso }) {
  await ensureBillingSchema(db);
  if (!refundId || !paymentId) throw new Error("recordRefund: refund and payment ids required");
  if (!Number.isInteger(amountPaise) || amountPaise <= 0) throw new Error("recordRefund: invalid amount");
  const processed = status === "processed";
  await db.prepare(
    `INSERT INTO billing_refunds (refund_id, payment_id, amount_paise, status, created_at, processed_at)
     VALUES (?,?,?,?,?,?)
     ON CONFLICT (refund_id) DO UPDATE SET
       status = CASE WHEN billing_refunds.status = 'processed' THEN 'processed' ELSE excluded.status END,
       processed_at = COALESCE(billing_refunds.processed_at, excluded.processed_at)`
  ).bind(refundId, paymentId, amountPaise, status, atIso, processed ? atIso : null).run();
  return await db.prepare(`SELECT * FROM billing_refunds WHERE refund_id = ?`).bind(refundId).first();
}

function _creditNoteRow(r) {
  if (!r) return null;
  return { ...r, document: { ...JSON.parse(r.document), credit_note_number: r.credit_note_number, financial_year: r.fy, serial: r.seq } };
}

export async function getCreditNoteByRefund(db, refundId) {
  await ensureBillingSchema(db);
  return _creditNoteRow(await db.prepare(`SELECT * FROM credit_notes WHERE refund_id = ?`).bind(refundId).first());
}

export async function getCreditNoteByNumber(db, number) {
  await ensureBillingSchema(db);
  return _creditNoteRow(await db.prepare(`SELECT * FROM credit_notes WHERE credit_note_number = ?`).bind(number).first());
}

export async function listCreditNotesFor(db, email) {
  await ensureBillingSchema(db);
  const { results } = await db.prepare(
    `SELECT credit_note_number, note_date, invoice_number, payment_id, total_paise FROM credit_notes
      WHERE email = ? ORDER BY fy DESC, seq DESC LIMIT 100`
  ).bind(email).all();
  return results || [];
}

/** Processed refunds that have no credit note yet (and why, when known). */
export async function listPendingCreditNotes(db) {
  await ensureBillingSchema(db);
  const { results } = await db.prepare(
    `SELECT r.refund_id, r.payment_id, r.amount_paise, r.processed_at, i.invoice_number
       FROM billing_refunds r
       LEFT JOIN credit_notes c ON c.refund_id = r.refund_id
       LEFT JOIN invoices i ON i.payment_id = r.payment_id
      WHERE r.status = 'processed' AND c.refund_id IS NULL
      ORDER BY r.processed_at ASC LIMIT 500`
  ).all();
  return results || [];
}

/**
 * Issues the credit note for one processed refund against the payment's
 * invoice, or reports why it is held. Idempotent on refund_id. The serial
 * is allocated inside one D1 batch exactly as for invoices, and the INSERT
 * itself refuses to credit more than the invoice total.
 * @returns {{ status: "issued", credit_note } | { status: "held", reason }}
 */
export async function issueCreditNoteForRefund(db, env, refundId) {
  await ensureBillingSchema(db);
  const existing = await getCreditNoteByRefund(db, refundId);
  if (existing) return { status: "issued", credit_note: existing };
  const refund = await db.prepare(`SELECT * FROM billing_refunds WHERE refund_id = ?`).bind(refundId).first();
  if (!refund) throw new Error(`issueCreditNoteForRefund: no refund ${refundId}`);
  if (refund.status !== "processed") return { status: "held", reason: "refund_not_processed" };
  const invoice = await getInvoiceByPayment(db, refund.payment_id);
  if (!invoice) return { status: "held", reason: "invoice_not_issued" };
  const cfg = parseGstInvoiceConfig(env.GST_INVOICE_CONFIG);
  if (!cfg.ok) return { status: "held", reason: "gst_config_incomplete:" + cfg.missing.join(",") };
  const c = cfg.config;
  const inv = invoice.document;
  const credited = await db.prepare(`SELECT COALESCE(SUM(total_paise), 0) AS t FROM credit_notes WHERE payment_id = ?`)
    .bind(refund.payment_id).first();
  if (credited.t + refund.amount_paise > inv.tax.total_paise) return { status: "held", reason: "credit_would_exceed_invoice_total" };

  const noteAt = refund.processed_at || new Date().toISOString();
  const fy = financialYear(noteAt);
  const noteDate = istDate(noteAt);
  const intra = inv.supply_type === "intra_state";
  const zeroRated = inv.supply_type === "export_under_lut";
  const tax = zeroRated
    ? { taxable_paise: refund.amount_paise, cgst_paise: 0, sgst_paise: 0, igst_paise: 0, tax_paise: 0, total_paise: refund.amount_paise }
    : splitInclusiveTax(refund.amount_paise, inv.tax.rate_percent, intra);
  const deadline = creditNoteAdjustmentDeadline(inv.financial_year);
  const doc = {
    schema: "cdb-gst-credit-note/1.0",
    note_date: noteDate,
    original_invoice: { invoice_number: inv.invoice_number, invoice_date: inv.invoice_date, financial_year: inv.financial_year },
    reason: "Refund of the invoiced payment",
    supplier: inv.supplier,
    recipient: inv.recipient,
    place_of_supply: inv.place_of_supply,
    supply_type: inv.supply_type,
    reverse_charge: false,
    line_items: [{ description: "Credit against " + inv.line_items[0].description, sac: inv.line_items[0].sac, quantity: 1,
      taxable_value_paise: tax.taxable_paise }],
    tax: {
      rate_percent: inv.tax.rate_percent,
      cgst_rate_percent: intra ? inv.tax.rate_percent / 2 : 0, sgst_rate_percent: intra ? inv.tax.rate_percent / 2 : 0,
      igst_rate_percent: intra || zeroRated ? 0 : inv.tax.rate_percent, ...tax,
    },
    ...(zeroRated ? { export: inv.export } : {}),
    currency: "INR",
    refund: { provider: "razorpay", refund_id: refund.refund_id, payment_id: refund.payment_id, processed_at: refund.processed_at },
    gst_adjustment: { deadline, within_deadline: noteDate <= deadline },
    config_confirmed_by: c.confirmed_by, config_confirmed_on: c.confirmed_on,
  };
  const id = "cn_" + crypto.randomUUID().replace(/-/g, "").slice(0, 20);
  const notYet = `NOT EXISTS (SELECT 1 FROM credit_notes WHERE refund_id = ?)`;
  // The over-credit guard is re-checked inside the transaction, so two
  // concurrent refunds on one payment cannot together exceed the invoice.
  const fits = `(SELECT COALESCE(SUM(total_paise), 0) FROM credit_notes WHERE payment_id = ?) + ? <= ?`;
  try {
    await db.batch([
      db.prepare(`INSERT INTO credit_note_sequences (fy, last_seq) VALUES (?, 0) ON CONFLICT (fy) DO NOTHING`).bind(fy),
      db.prepare(`UPDATE credit_note_sequences SET last_seq = last_seq + 1 WHERE fy = ? AND last_seq < ? AND ${notYet} AND ${fits}`)
        .bind(fy, INVOICE_SERIAL_MAX, refundId, refund.payment_id, refund.amount_paise, inv.tax.total_paise),
      db.prepare(
        `INSERT INTO credit_notes (id, credit_note_number, fy, seq, refund_id, payment_id, invoice_number, email, total_paise,
                                   note_date, issued_at, document)
         SELECT ?, ? || '/' || fy || '/' || printf('%06d', last_seq), fy, last_seq, ?, ?, ?, ?, ?, ?, ?, ?
           FROM credit_note_sequences WHERE fy = ? AND last_seq > 0 AND ${notYet} AND ${fits}`
      ).bind(id, c.credit_note_prefix, refundId, refund.payment_id, inv.invoice_number, invoice.email, refund.amount_paise,
        noteDate, new Date().toISOString(), JSON.stringify(doc), fy, refundId, refund.payment_id, refund.amount_paise, inv.tax.total_paise),
      db.prepare(
        `UPDATE invoices SET status = CASE
            WHEN (SELECT COALESCE(SUM(total_paise), 0) FROM credit_notes WHERE payment_id = ?) >= ? THEN 'credited'
            ELSE 'partially_credited' END
          WHERE payment_id = ? AND EXISTS (SELECT 1 FROM credit_notes WHERE refund_id = ?)`
      ).bind(refund.payment_id, inv.tax.total_paise, refund.payment_id, refundId),
    ]);
  } catch (err) {
    const raced = await getCreditNoteByRefund(db, refundId);
    if (raced) return { status: "issued", credit_note: raced };
    throw err;
  }
  const issued = await getCreditNoteByRefund(db, refundId);
  if (issued) return { status: "issued", credit_note: issued };
  return { status: "held", reason: "credit_would_exceed_invoice_total" };
}

/** Credit notes for every processed refund of a payment that lacks one. */
export async function issuePendingCreditNotesForPayment(db, env, paymentId) {
  await ensureBillingSchema(db);
  const { results } = await db.prepare(
    `SELECT r.refund_id FROM billing_refunds r LEFT JOIN credit_notes c ON c.refund_id = r.refund_id
      WHERE r.payment_id = ? AND r.status = 'processed' AND c.refund_id IS NULL ORDER BY r.processed_at ASC`
  ).bind(paymentId).all();
  const out = [];
  for (const r of results || []) out.push(await issueCreditNoteForRefund(db, env, r.refund_id));
  return out;
}
