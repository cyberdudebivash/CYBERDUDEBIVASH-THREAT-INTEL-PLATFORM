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
  parseGstInvoiceConfig, GST_STATES,
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
];

const _schemaReady = new WeakSet();

/** Creates the billing tables once per D1 binding per isolate. */
export async function ensureBillingSchema(db) {
  if (!db) throw new Error("CRM_DB binding is required for billing");
  if (_schemaReady.has(db)) return;
  await db.batch(BILLING_SCHEMA.map((sql) => db.prepare(sql)));
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
       captured_at, buyer_gstin, buyer_vat_id, billing_state, billing_name, billing_address, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT (payment_id) DO NOTHING`
  ).bind(
    payment.id, providerSubId || null, email, tier, billingCycle || "monthly", payment.amount,
    String(payment.currency || "INR").toUpperCase(), capturedAt,
    b.gstin || "", b.vat_id || "", b.billing_state || "", b.billing_name || "", b.billing_address || "",
    new Date().toISOString(),
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
    await db.prepare(`UPDATE invoices SET status = 'refunded_credit_note_required' WHERE payment_id = ?`).bind(paymentId).run();
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
  if (pos.export) return "recipient_outside_india_export_requires_review";
  if (row.buyer_gstin && (!row.billing_name || !row.billing_address)) return "registered_recipient_name_and_address_required";
  if (!row.buyer_gstin && row.amount_paise >= B2C_DETAILS_THRESHOLD_PAISE &&
      (!row.billing_name || !row.billing_address || !row.billing_state)) {
    return "unregistered_recipient_details_required_at_or_above_50000";
  }
  return null;
}

function buildInvoiceDocument(row, c) {
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
      description: `SENTINEL APEX ${row.tier} subscription (${row.billing_cycle})`,
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
    payment: { provider: "razorpay", payment_id: row.payment_id, subscription_id: row.provider_sub_id, captured_at: row.captured_at },
    config_confirmed_by: c.confirmed_by, config_confirmed_on: c.confirmed_on,
  };
}

/**
 * Issues the GST invoice for a recorded payment, or records why it is held.
 * Idempotent: an existing invoice for the payment is returned unchanged.
 * @returns {{ status: "issued", invoice } | { status: "held", reason }}
 */
export async function issueInvoiceForPayment(db, env, paymentId) {
  await ensureBillingSchema(db);
  const existing = await getInvoiceByPayment(db, paymentId);
  if (existing) return { status: "issued", invoice: existing };
  const row = await getPayment(db, paymentId);
  if (!row) throw new Error(`issueInvoiceForPayment: no ledger row for ${paymentId}`);
  const cfg = parseGstInvoiceConfig(env.GST_INVOICE_CONFIG);
  const hold = invoiceHoldReason(row, cfg);
  if (hold) {
    await db.prepare(`UPDATE billing_payments SET invoice_status = 'held', invoice_hold_reason = ? WHERE payment_id = ?`)
      .bind(hold, paymentId).run();
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
  // payment both statements are no-ops, so no serial is consumed. A UNIQUE
  // violation (a concurrent issue for the same payment) rolls it all back.
  try {
    await db.batch([
      db.prepare(`INSERT INTO invoice_sequences (fy, last_seq) VALUES (?, 0) ON CONFLICT (fy) DO NOTHING`).bind(fy),
      db.prepare(`UPDATE invoice_sequences SET last_seq = last_seq + 1 WHERE fy = ? AND last_seq < ? AND ${notYet}`)
        .bind(fy, INVOICE_SERIAL_MAX, paymentId),
      db.prepare(
        `INSERT INTO invoices (id, invoice_number, fy, seq, payment_id, email, invoice_date, issued_at, document)
         SELECT ?, ? || '/' || fy || '/' || printf('%06d', last_seq), fy, last_seq, ?, ?, ?, ?, ?
           FROM invoice_sequences WHERE fy = ? AND last_seq > 0 AND ${notYet}`
      ).bind(id, c.invoice_prefix, paymentId, row.email, doc.invoice_date, new Date().toISOString(), JSON.stringify(doc), fy, paymentId),
      db.prepare(`UPDATE billing_payments SET invoice_status = 'issued', invoice_hold_reason = '' WHERE payment_id = ?
                  AND EXISTS (SELECT 1 FROM invoices WHERE payment_id = ?)`).bind(paymentId, paymentId),
    ]);
  } catch (err) {
    const raced = await getInvoiceByPayment(db, paymentId);
    if (raced) return { status: "issued", invoice: raced };
    throw err;
  }
  const issued = await getInvoiceByPayment(db, paymentId);
  if (!issued) throw new Error(`issueInvoiceForPayment: no invoice after issuance for ${paymentId} (serial space for ${fy} exhausted?)`);
  return { status: "issued", invoice: issued };
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

export async function listInvoiceHolds(db) {
  await ensureBillingSchema(db);
  const { results } = await db.prepare(
    `SELECT payment_id, email, tier, amount_paise, currency, captured_at, invoice_hold_reason
       FROM billing_payments WHERE invoice_status = 'held' ORDER BY captured_at ASC LIMIT 500`
  ).all();
  return results || [];
}

/** Operator completes recipient details for a held payment (never amounts). */
export async function completeRecipientDetails(db, paymentId, { billing_name, billing_address, billing_state }) {
  await ensureBillingSchema(db);
  const r = await db.prepare(
    `UPDATE billing_payments SET
       billing_name = COALESCE(NULLIF(?, ''), billing_name),
       billing_address = COALESCE(NULLIF(?, ''), billing_address),
       billing_state = COALESCE(NULLIF(?, ''), billing_state)
     WHERE payment_id = ? AND invoice_status != 'issued'`
  ).bind(billing_name || "", billing_address || "", billing_state || "", paymentId).run();
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
