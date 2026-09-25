// GST credit notes (CGST Act s.34, CGST Rules r.53), 2026-09-25. Every refund
// Razorpay reports as processed gets one credit note against the payment's
// invoice: own consecutive series, same supply type and rate, never more
// than the invoice total. D1 is real SQLite (helpers/d1-sqlite.js); webhook
// signatures are computed for real.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import { parseGstInvoiceConfig, creditNoteAdjustmentDeadline, gstinCheckChar, financialYear } from "../gst.js";
import {
  recordCapturedPayment, issueInvoiceForPayment, getInvoiceByPayment, recordRefund, issueCreditNoteForRefund,
} from "../billing-ledger.js";
import {
  handleCreditNoteView, handleCreditNoteList, handleCreditNotesPending, handleCreditNoteIssue, handleInvoiceIssue,
  renderCreditNoteHtml,
} from "../billing-routes.js";
import { handleBillingWebhook } from "../subscription-engine.js";

const ADMIN = "admin-secret-test";
const WHSEC = "whsec_test";
const CONFIG = {
  supplier_legal_name: "Test Supplier Legal Name", supplier_gstin: "21ARKPN8270G1ZP",
  supplier_address: "Registered address line, City, Odisha 751001", sac: { subscription: "998315" },
  gst_rate_percent: 18, invoice_prefix: "CDB", confirmed_by: "Test CA", confirmed_on: "2026-09-24",
};
const ctx = { waitUntil: () => {} };

function fakeKV() {
  const store = new Map();
  return {
    store,
    async get(k, o) { const v = store.get(k); if (v === undefined) return null; return (o === "json" || o?.type === "json") ? JSON.parse(v) : v; },
    async put(k, v) { store.set(k, typeof v === "string" ? v : JSON.stringify(v)); },
    async delete(k) { store.delete(k); },
  };
}

function makeEnv(config = CONFIG) {
  return {
    CRM_DB: createD1(), REVENUE_CRM_KV: fakeKV(), API_KEYS_KV: fakeKV(), REVENUE_ADMIN_SECRET: ADMIN,
    RAZORPAY_WEBHOOK_SECRET: WHSEC, ...(config ? { GST_INVOICE_CONFIG: JSON.stringify(config) } : {}),
  };
}

async function invoicedPayment(env, { id = "pay_1", amount = 410000, email = "buyer@example.com", buyer = {} } = {}) {
  await recordCapturedPayment(env.CRM_DB, {
    payment: { id, amount, currency: "INR", status: "captured", created_at: Math.floor(Date.now() / 1000) - 3600 },
    providerSubId: "sub_1", email, tier: "PRO", billingCycle: "monthly", buyer,
  });
  return issueInvoiceForPayment(env.CRM_DB, env, id);
}

function signed(body, eventId) {
  const raw = JSON.stringify(body);
  const sig = crypto.createHmac("sha256", WHSEC).update(raw).digest("hex");
  return new Request("https://revenue.intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Razorpay-Signature": sig, "X-Razorpay-Event-Id": eventId }, body: raw,
  });
}
const refundEvent = (event, id, paymentId, amount) => ({
  event, payload: { refund: { entity: { id, payment_id: paymentId, amount, status: event.split(".")[1], created_at: Math.floor(Date.now() / 1000) } } },
});
const get = (path, headers = {}) => new Request("https://revenue.intel.cyberdudebivash.com" + path, { headers });
const post = (path, body, headers = {}) => new Request("https://revenue.intel.cyberdudebivash.com" + path, {
  method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const cnRows = async (env) => (await env.CRM_DB.prepare("SELECT * FROM credit_notes ORDER BY seq").all()).results;

// --- config + deadline ------------------------------------------------------------

test("credit-note prefix: defaults to CN, 16-character limit, must differ from the invoice prefix", () => {
  assert.equal(parseGstInvoiceConfig(CONFIG).config.credit_note_prefix, "CN");
  assert.equal(parseGstInvoiceConfig({ ...CONFIG, credit_note_prefix: "CDB" }).ok, false, "same series as invoices");
  assert.equal(parseGstInvoiceConfig({ ...CONFIG, credit_note_prefix: "CRNOTE" }).ok, false, "number would exceed 16 characters");
  assert.equal(parseGstInvoiceConfig({ ...CONFIG, credit_note_prefix: "CRN" }).config.credit_note_prefix, "CRN");
});

test("s.34(2) deadline is 30 November after the invoice's financial year", () => {
  assert.equal(creditNoteAdjustmentDeadline("26-27"), "2027-11-30");
  assert.throws(() => creditNoteAdjustmentDeadline("2026"));
});

// --- issuance through the webhook ------------------------------------------------------

test("a processed full refund issues one credit note that reverses the invoice", async () => {
  const env = makeEnv();
  const inv = (await invoicedPayment(env)).invoice.document;
  await handleBillingWebhook(signed(refundEvent("refund.created", "rfnd_1", "pay_1", 410000), "e1"), env, ctx, "rid");
  assert.equal((await cnRows(env)).length, 0, "no credit note until the refund is processed");
  await handleBillingWebhook(signed(refundEvent("refund.processed", "rfnd_1", "pay_1", 410000), "e2"), env, ctx, "rid");
  await handleBillingWebhook(signed(refundEvent("refund.processed", "rfnd_1", "pay_1", 410000), "e3"), env, ctx, "rid");
  const rows = await cnRows(env);
  assert.equal(rows.length, 1, "one credit note per refund, redeliveries included");
  const fy = financialYear(Date.now());
  assert.equal(rows[0].credit_note_number, `CN/${fy}/000001`);
  const doc = (await handleCreditNoteView(get(`/x?number=${encodeURIComponent(rows[0].credit_note_number)}`, { "X-Admin-Secret": ADMIN }), env));
  const cn = (await doc.json()).credit_note;
  assert.equal(cn.original_invoice.invoice_number, inv.invoice_number);
  assert.equal(cn.original_invoice.invoice_date, inv.invoice_date);
  assert.equal(cn.supply_type, inv.supply_type);
  assert.deepEqual(cn.tax, { ...inv.tax }, "a full credit reverses exactly the invoiced tax");
  assert.equal(cn.gst_adjustment.deadline, creditNoteAdjustmentDeadline(inv.financial_year));
  assert.equal(cn.gst_adjustment.within_deadline, true);
  assert.equal((await getInvoiceByPayment(env.CRM_DB, "pay_1")).status, "credited");
  const invSeq = await env.CRM_DB.prepare("SELECT last_seq FROM invoice_sequences").first();
  assert.equal(invSeq.last_seq, 1, "credit notes do not consume invoice serials");
});

test("partial refunds: one note each, consecutive, capped at the invoice total", async () => {
  const env = makeEnv();
  await invoicedPayment(env);
  for (const [id, amt] of [["r_a", 123000], ["r_b", 287000]]) {
    await recordRefund(env.CRM_DB, { refundId: id, paymentId: "pay_1", amountPaise: amt, status: "processed", atIso: new Date().toISOString() });
  }
  assert.equal((await issueCreditNoteForRefund(env.CRM_DB, env, "r_a")).status, "issued");
  assert.equal((await getInvoiceByPayment(env.CRM_DB, "pay_1")).status, "partially_credited");
  assert.equal((await issueCreditNoteForRefund(env.CRM_DB, env, "r_b")).status, "issued");
  assert.equal((await getInvoiceByPayment(env.CRM_DB, "pay_1")).status, "credited");
  const rows = await cnRows(env);
  assert.deepEqual(rows.map((r) => r.seq), [1, 2]);
  assert.equal(rows.reduce((a, r) => a + r.total_paise, 0), 410000);
  for (const r of rows) {
    const t = JSON.parse(r.document).tax;
    assert.equal(t.taxable_paise + t.cgst_paise + t.sgst_paise + t.igst_paise, r.total_paise);
  }
  await recordRefund(env.CRM_DB, { refundId: "r_c", paymentId: "pay_1", amountPaise: 100, status: "processed", atIso: new Date().toISOString() });
  const over = await issueCreditNoteForRefund(env.CRM_DB, env, "r_c");
  assert.equal(over.reason, "credit_would_exceed_invoice_total");
  assert.equal((await cnRows(env)).length, 2);
});

test("concurrent refunds cannot together credit more than the invoice", async () => {
  const env = makeEnv();
  await invoicedPayment(env);
  const ids = ["r1", "r2", "r3", "r4"];
  for (const id of ids) {
    await recordRefund(env.CRM_DB, { refundId: id, paymentId: "pay_1", amountPaise: 246000, status: "processed", atIso: new Date().toISOString() });
  }
  const results = await Promise.all(ids.map((id) => issueCreditNoteForRefund(env.CRM_DB, env, id)));
  assert.equal(results.filter((r) => r.status === "issued").length, 1, "only one 60% credit fits");
  const rows = await cnRows(env);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].seq, 1, "no serial consumed by the refused notes");
});

test("a refund while the invoice is held gets its credit note right after the invoice", async () => {
  const env = makeEnv(null);
  await invoicedPayment(env);
  await handleBillingWebhook(signed(refundEvent("refund.processed", "rfnd_h", "pay_1", 410000), "e1"), env, ctx, "rid");
  assert.equal((await cnRows(env)).length, 0, "no invoice yet, so no credit note");
  const pending = await (await handleCreditNotesPending(get("/x", { "X-Admin-Secret": ADMIN }), env)).json();
  assert.deepEqual(pending.pending.map((p) => p.refund_id), ["rfnd_h"]);
  env.GST_INVOICE_CONFIG = JSON.stringify(CONFIG);
  const res = await handleInvoiceIssue(post("/x", { payment_id: "pay_1" }, { "X-Admin-Secret": ADMIN }), env, ctx, "rid");
  assert.equal(res.status, 200);
  const rows = await cnRows(env);
  assert.equal(rows.length, 1, "credit note follows the invoice automatically");
  assert.equal(rows[0].invoice_number, (await getInvoiceByPayment(env.CRM_DB, "pay_1")).invoice_number);
});

test("an inter-state invoice is credited with IGST", async () => {
  const env = makeEnv();
  const ka = "29AAAAA0000A1Z" + gstinCheckChar("29AAAAA0000A1Z");
  await invoicedPayment(env, { buyer: { gstin: ka, billing_state: "29", billing_name: "Acme Pvt Ltd", billing_address: "12 MG Road, Bengaluru 560001" } });
  await recordRefund(env.CRM_DB, { refundId: "r_ka", paymentId: "pay_1", amountPaise: 410000, status: "processed", atIso: new Date().toISOString() });
  const cn = (await issueCreditNoteForRefund(env.CRM_DB, env, "r_ka")).credit_note.document;
  assert.equal(cn.supply_type, "inter_state");
  assert.ok(cn.tax.igst_paise > 0);
  assert.equal(cn.tax.cgst_paise + cn.tax.sgst_paise, 0);
  assert.equal(cn.recipient.gstin, ka);
});

test("an unprocessed refund is never credited", async () => {
  const env = makeEnv();
  await invoicedPayment(env);
  await recordRefund(env.CRM_DB, { refundId: "r_p", paymentId: "pay_1", amountPaise: 410000, status: "created", atIso: new Date().toISOString() });
  assert.equal((await issueCreditNoteForRefund(env.CRM_DB, env, "r_p")).reason, "refund_not_processed");
});

// --- access ----------------------------------------------------------------------------

test("customers read only their own credit notes; operators retry pending ones", async () => {
  const env = makeEnv();
  await invoicedPayment(env);
  await recordRefund(env.CRM_DB, { refundId: "r_x", paymentId: "pay_1", amountPaise: 410000, status: "processed", atIso: new Date().toISOString() });
  const unauth = await handleCreditNoteIssue(post("/x", { refund_id: "r_x" }, { "X-API-Key": "k1" }), env, ctx, "rid");
  assert.equal(unauth.status, 401);
  const issued = await handleCreditNoteIssue(post("/x", { refund_id: "r_x" }, { "X-Admin-Secret": ADMIN }), env, ctx, "rid");
  assert.equal(issued.status, 200);
  const n = encodeURIComponent((await issued.json()).credit_note_number);
  env.REVENUE_CRM_KV.store.set("apikey:k1", JSON.stringify({ email: "buyer@example.com", status: "active" }));
  env.REVENUE_CRM_KV.store.set("apikey:k2", JSON.stringify({ email: "other@example.com", status: "active" }));
  const own = await handleCreditNoteView(get(`/x?number=${n}&format=html`, { "X-API-Key": "k1" }), env);
  assert.equal(own.status, 200);
  assert.match(own.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal((await handleCreditNoteView(get(`/x?number=${n}`, { "X-API-Key": "k2" }), env)).status, 404);
  assert.equal((await handleCreditNoteView(get(`/x?number=${n}`), env)).status, 401);
  const list = await (await handleCreditNoteList(get("/x", { "X-API-Key": "k1" }), env)).json();
  assert.equal(list.credit_notes.length, 1);
  assert.equal((await (await handleCreditNoteList(get("/x", { "X-API-Key": "k2" }), env)).json()).credit_notes.length, 0);
});

test("credit note HTML escapes every field", () => {
  const html = renderCreditNoteHtml({
    credit_note_number: "CN/26-27/000001", note_date: "2026-09-25", reason: "<script>alert(1)</script>",
    original_invoice: { invoice_number: "CDB/26-27/000001", invoice_date: "2026-09-24" },
    place_of_supply: { state_name: "Odisha", state_code: "21" }, supply_type: "intra_state",
    supplier: { legal_name: "<img src=x onerror=alert(1)>", trade_name: "", address: "a&b", gstin: "21ARKPN8270G1ZP" },
    recipient: { name: "\"><b>x</b>", address: null, email: "x@example.com", gstin: null },
    line_items: [{ description: "<i>d</i>", sac: "998315", taxable_value_paise: 100 }],
    tax: { cgst_rate_percent: 9, sgst_rate_percent: 9, cgst_paise: 9, sgst_paise: 9, taxable_paise: 100, total_paise: 118 },
    refund: { refund_id: "rfnd_1", payment_id: "pay_1" },
  });
  assert.ok(!/<script>|<img |<b>x|<i>d/.test(html));
  assert.match(html, /&lt;script&gt;/);
});
