// Export of services under LUT and the enterprise quote -> PO -> invoice ->
// bank transfer -> reconciliation -> entitlement workflow (2026-09-25).
// D1 is real SQLite (helpers/d1-sqlite.js); KV is in-memory; Razorpay
// webhook signatures are computed for real; provisionCustomer() runs for real.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import { parseGstInvoiceConfig, normalizeBillingCountry, financialYear, gstinCheckChar } from "../gst.js";
import {
  recordCapturedPayment, issueInvoiceForPayment, getInvoiceByPayment, recordRefund, issueCreditNoteForRefund,
  ensureBillingSchema, getPayment,
} from "../billing-ledger.js";
import { handleInvoiceIssue, renderInvoiceHtml, handleInvoiceList } from "../billing-routes.js";
import { handleBillingWebhook, handleBillingSubscriptionCreate } from "../subscription-engine.js";
import {
  PO_ANNUAL_PRICE_INR, handleQuoteCreate, handleQuoteView, handleQuoteAccept, handleQuoteCancel, handleQuoteInvoice,
  handleQuoteReconcile, handleQuoteProvision, getQuote, quoteToken, renderQuoteHtml,
} from "../enterprise-po.js";

const ADMIN = "admin-secret-test";
const WHSEC = "whsec_test";
const FY = financialYear(Date.now());
const BASE = {
  supplier_legal_name: "Test Supplier Legal Name", supplier_gstin: "21ARKPN8270G1ZP",
  supplier_address: "Registered address line, City, Odisha 751001", sac: { subscription: "998315" },
  gst_rate_percent: 18, invoice_prefix: "CDB", confirmed_by: "Test CA", confirmed_on: "2026-09-24",
};
const WITH_LUT = { ...BASE, luts: [{ arn: "AD2104260012345", financial_year: FY }] };
const ctx = { waitUntil: () => {} };
const KA = "29AAAAA0000A1Z" + gstinCheckChar("29AAAAA0000A1Z");
const OD = "21AAAAA0000A1Z" + gstinCheckChar("21AAAAA0000A1Z");

function fakeKV() {
  const store = new Map();
  return {
    store, failPrefix: null,
    async get(k, o) { const v = store.get(k); if (v === undefined) return null; return (o === "json" || o?.type === "json") ? JSON.parse(v) : v; },
    async put(k, v) {
      // One injected failure on the first write under failPrefix (provisionCustomer's customer record).
      if (this.failPrefix && k.startsWith(this.failPrefix)) { this.failPrefix = null; throw new Error("kv down"); }
      store.set(k, typeof v === "string" ? v : JSON.stringify(v));
    },
    async delete(k) { store.delete(k); },
    async list() { return { keys: [], list_complete: true }; },
  };
}
function makeEnv(config = WITH_LUT, extra = {}) {
  return {
    CRM_DB: createD1(), REVENUE_CRM_KV: fakeKV(), API_KEYS_KV: fakeKV(), EMAIL_QUEUE_KV: fakeKV(),
    REVENUE_ADMIN_SECRET: ADMIN, RAZORPAY_WEBHOOK_SECRET: WHSEC, RAZORPAY_KEY_ID: "rzp_test", RAZORPAY_KEY_SECRET: "rzp_secret",
    ...(config ? { GST_INVOICE_CONFIG: JSON.stringify(config) } : {}), ...extra,
  };
}
const post = (body, headers = {}) => new Request("https://revenue.intel.cyberdudebivash.com/x", {
  method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
const get = (qs, headers = {}) => new Request("https://revenue.intel.cyberdudebivash.com/x" + qs, { headers });
const ADMIN_H = { "X-Admin-Secret": ADMIN };
function signed(body, eventId) {
  const raw = JSON.stringify(body);
  const sig = crypto.createHmac("sha256", WHSEC).update(raw).digest("hex");
  return new Request("https://revenue.intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Razorpay-Signature": sig, "X-Razorpay-Event-Id": eventId }, body: raw,
  });
}
const FOREIGN = { billing_state: "OUTSIDE_INDIA", billing_country: "US", billing_name: "Acme Inc", billing_address: "1 Main St, Austin TX 78701" };
async function exportPayment(env, { id = "pay_x", international = true, buyer = FOREIGN } = {}) {
  await recordCapturedPayment(env.CRM_DB, {
    payment: { id, amount: 410000, currency: "INR", status: "captured", created_at: Math.floor(Date.now() / 1000) - 60, international },
    providerSubId: "sub_x", email: "intl@example.com", tier: "PRO", billingCycle: "monthly", buyer,
  });
  return issueInvoiceForPayment(env.CRM_DB, env, id);
}

// ================================ EXPORT (LUT) ================================

test("LUT config: per financial year, ARN required, no duplicates", () => {
  assert.deepEqual(parseGstInvoiceConfig(WITH_LUT).config.luts, [{ arn: "AD2104260012345", financial_year: FY }]);
  assert.equal(parseGstInvoiceConfig({ ...BASE, luts: [{ arn: "x", financial_year: FY }] }).ok, false);
  assert.equal(parseGstInvoiceConfig({ ...BASE, luts: [{ arn: "AD2104260012345", financial_year: "26-28" }] }).ok, false);
  assert.equal(parseGstInvoiceConfig({ ...BASE, luts: [{ arn: "AD2104260012345", financial_year: FY }, { arn: "AD2104260099999", financial_year: FY }] }).ok, false);
  assert.deepEqual(parseGstInvoiceConfig(BASE).config.luts, [], "LUT is optional");
  assert.equal(normalizeBillingCountry("IN").ok, false);
  assert.equal(normalizeBillingCountry("zz").ok, false);
  assert.equal(normalizeBillingCountry("de").value, "DE");
});

test("an international payment from a buyer outside India is invoiced zero-rated under LUT", async () => {
  const env = makeEnv();
  const r = await exportPayment(env);
  assert.equal(r.status, "issued", r.reason);
  const d = r.invoice.document;
  assert.equal(d.supply_type, "export_under_lut");
  assert.equal(d.place_of_supply.state_code, "96");
  assert.equal(d.place_of_supply.country, "US");
  assert.equal(d.tax.tax_paise, 0);
  assert.equal(d.tax.igst_paise, 0);
  assert.equal(d.tax.total_paise, 410000);
  assert.equal(d.tax.taxable_paise, 410000, "nothing carved out: no GST charged");
  assert.equal(d.export.lut_arn, "AD2104260012345");
  assert.equal(d.export.realisation_basis, "razorpay_international_payment");
  assert.match(d.export.declaration, /WITHOUT PAYMENT OF INTEGRATED TAX/);
  const html = renderInvoiceHtml(d);
  assert.match(html, /LETTER OF UNDERTAKING/);
  assert.match(html, /AD2104260012345/);
  assert.match(html, /Country: US/);
});

test("export holds: no LUT for the year, missing recipient details, no foreign-exchange evidence", async () => {
  assert.equal((await exportPayment(makeEnv(BASE))).reason, `export_lut_not_configured_for_${FY}`);
  assert.equal((await exportPayment(makeEnv(), { buyer: { billing_state: "OUTSIDE_INDIA", billing_country: "US" } })).reason,
    "export_recipient_name_address_country_required");
  assert.equal((await exportPayment(makeEnv(), { international: false })).reason, "export_foreign_exchange_not_evidenced");
});

test("an operator can confirm realisation (with a FIRC/BRC reference) and issue", async () => {
  const env = makeEnv();
  await exportPayment(env, { international: false });
  const noRef = await handleInvoiceIssue(post({ payment_id: "pay_x", export_realisation_confirmed: true }, ADMIN_H), env, ctx, "rid");
  assert.equal(noRef.status, 400);
  const ok = await handleInvoiceIssue(post({ payment_id: "pay_x", export_realisation_confirmed: true,
    export_realisation_reference: "FIRC-2026-0042" }, ADMIN_H), env, ctx, "rid");
  assert.equal(ok.status, 200);
  const d = (await getInvoiceByPayment(env.CRM_DB, "pay_x")).document;
  assert.equal(d.export.realisation_basis, "operator_confirmed");
  assert.equal(d.export.realisation_reference, "FIRC-2026-0042");
});

test("a refund of an export invoice gets a zero-rated credit note", async () => {
  const env = makeEnv();
  await exportPayment(env);
  await recordRefund(env.CRM_DB, { refundId: "rf_x", paymentId: "pay_x", amountPaise: 410000, status: "processed", atIso: new Date().toISOString() });
  const cn = (await issueCreditNoteForRefund(env.CRM_DB, env, "rf_x")).credit_note.document;
  assert.equal(cn.supply_type, "export_under_lut");
  assert.equal(cn.tax.tax_paise, 0);
  assert.equal(cn.tax.total_paise, 410000);
  assert.equal(cn.export.lut_arn, "AD2104260012345");
});

test("checkout: country only outside India, never India, recorded on the subscription", async () => {
  const env = makeEnv(WITH_LUT, { RAZORPAY_PLAN_ID_PRO_MONTHLY: "plan_pro_m" });
  const real = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (u, init) => { calls.push(JSON.parse(init.body)); return Response.json({ id: "sub_NEW", status: "created" }); };
  try {
    const bad1 = await handleBillingSubscriptionCreate(post({ email: "b@example.com", tier: "PRO", billing_state: "27", billing_country: "US" }), env, ctx, "rid");
    assert.equal(bad1.status, 400);
    const bad2 = await handleBillingSubscriptionCreate(post({ email: "b@example.com", tier: "PRO", billing_state: "OUTSIDE_INDIA", billing_country: "IN" }), env, ctx, "rid");
    assert.equal(bad2.status, 400);
    const ok = await handleBillingSubscriptionCreate(post({ email: "b@example.com", tier: "PRO", ...FOREIGN }), env, ctx, "rid");
    assert.equal(ok.status, 200);
    assert.equal(calls.at(-1).notes.billing_country, "US");
  } finally { globalThis.fetch = real; }
});

test("the webhook carries the buyer's country and Razorpay's international flag to the ledger", async () => {
  const env = makeEnv();
  env.REVENUE_CRM_KV.store.set("razorpay_sub:sub_W", JSON.stringify({ email: "w@example.com", tier: "PRO", billing_cycle: "monthly",
    status: "active", internal_sub_id: "sub_int", api_key: "k_w", buyer: { ...FOREIGN, gstin: "", vat_id: "" } }));
  const ev = { event: "subscription.charged", payload: {
    subscription: { entity: { id: "sub_W", current_start: 1, current_end: 2, notes: {} } },
    payment: { entity: { id: "pay_W", amount: 410000, currency: "INR", status: "captured", created_at: Math.floor(Date.now() / 1000), international: true } } } };
  assert.equal((await handleBillingWebhook(signed(ev, "e1"), env, ctx, "rid")).status, 200);
  const row = await getPayment(env.CRM_DB, "pay_W");
  assert.equal(row.billing_country, "US");
  assert.equal(row.payment_international, 1);
  assert.equal((await getInvoiceByPayment(env.CRM_DB, "pay_W")).document.supply_type, "export_under_lut");
});

test("column migrations upgrade a billing_payments table created before them", async () => {
  const db = createD1();
  // The pre-export table (as deployed by #517), with a row in it.
  db.sqlite.exec(`CREATE TABLE billing_payments (payment_id TEXT PRIMARY KEY, provider TEXT NOT NULL DEFAULT 'razorpay',
    provider_sub_id TEXT, email TEXT NOT NULL, tier TEXT NOT NULL, billing_cycle TEXT NOT NULL, amount_paise INTEGER NOT NULL,
    currency TEXT NOT NULL, captured_at TEXT NOT NULL, buyer_gstin TEXT NOT NULL DEFAULT '', buyer_vat_id TEXT NOT NULL DEFAULT '',
    billing_state TEXT NOT NULL DEFAULT '', billing_name TEXT NOT NULL DEFAULT '', billing_address TEXT NOT NULL DEFAULT '',
    invoice_status TEXT NOT NULL DEFAULT 'pending', invoice_hold_reason TEXT NOT NULL DEFAULT '', refund_status TEXT NOT NULL DEFAULT 'none',
    refunded_paise INTEGER NOT NULL DEFAULT 0, disputed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)`);
  db.sqlite.exec(`INSERT INTO billing_payments (payment_id, email, tier, billing_cycle, amount_paise, currency, captured_at, created_at)
    VALUES ('pay_old','o@example.com','PRO','monthly',410000,'INR','2026-09-24T00:00:00Z','2026-09-24T00:00:00Z')`);
  await ensureBillingSchema(db);
  const old = await getPayment(db, "pay_old");
  assert.equal(old.billing_country, "");
  assert.equal(old.payment_international, 0);
  await ensureBillingSchema(db); // idempotent per isolate
});

// ============================ ENTERPRISE PO WORKFLOW ===========================

test("PO prices equal the canonical commercial contract (annual INR)", () => {
  const contract = JSON.parse(readFileSync(new URL("../../../../config/commercial-contract.json", import.meta.url), "utf8"));
  assert.equal(PO_ANNUAL_PRICE_INR.ENTERPRISE, contract.tiers.enterprise.inr_annual);
  assert.equal(PO_ANNUAL_PRICE_INR.MSSP, contract.tiers.mssp.inr_annual);
});

const QUOTE = { email: "cfo@acme.in", company_name: "Acme Security Pvt Ltd", billing_address: "12 MG Road, Bengaluru 560001",
  gstin: KA, tier: "ENTERPRISE" };

async function createQuote(env, over = {}) {
  const res = await handleQuoteCreate(post({ ...QUOTE, ...over }, ADMIN_H), env, ctx, "rid");
  const body = await res.json();
  return { res, body, id: body.acceptance?.id, token: body.acceptance?.token };
}
async function acceptedQuote(env, over = {}) {
  const q = await createQuote(env, over);
  await handleQuoteAccept(post({ id: q.id, token: q.token, po_number: "PO-7781", po_date: "2026-09-25" }), env, ctx, "rid");
  return q;
}
async function invoicedQuote(env, over = {}) {
  const q = await acceptedQuote(env, over);
  const r = await handleQuoteInvoice(post({ id: q.id }, ADMIN_H), env, ctx, "rid");
  return { ...q, invoice: await r.json() };
}

test("quote creation: admin only, canonical price, custom price needs a reason, place of supply required", async () => {
  const env = makeEnv();
  assert.equal((await handleQuoteCreate(post(QUOTE), env, ctx, "rid")).status, 401);
  const q = await createQuote(env);
  assert.equal(q.res.status, 201);
  assert.equal(q.body.quote.amount_paise, 416000 * 100);
  assert.equal(q.body.quote.billing_state, "29", "state follows the GSTIN");
  assert.equal(q.token, await quoteToken(env, q.id));
  assert.equal((await createQuote(env, { custom_amount_inr: 350000 })).res.status, 400, "no reason");
  const c = await createQuote(env, { custom_amount_inr: 350000, price_reason: "Multi-year strategic partner discount approved" });
  assert.equal(c.body.quote.amount_paise, 35000000);
  assert.equal((await getQuote(env.CRM_DB, c.id)).price_basis, "custom");
  assert.equal((await createQuote(env, { gstin: undefined })).res.status, 400, "no GSTIN and no state");
  assert.equal((await createQuote(env, { gstin: undefined, billing_state: "OUTSIDE_INDIA" })).res.status, 400, "no country");
  assert.equal((await createQuote(env, { tier: "PRO" })).res.status, 400);
  assert.equal((await createQuote(env, { term_months: 24 })).res.status, 400);
});

test("quote view and acceptance need the quote's own token; unknown looks the same", async () => {
  const env = makeEnv();
  const q = await createQuote(env);
  const other = await createQuote(env);
  assert.equal((await handleQuoteView(get(`?id=${q.id}&token=${other.token}`), env)).status, 404);
  assert.equal((await handleQuoteView(get(`?id=qt_00000000000000000000&token=${q.token}`), env)).status, 404);
  const html = await handleQuoteView(get(`?id=${q.id}&token=${q.token}&format=html`), env);
  assert.equal(html.status, 200);
  assert.match(html.headers.get("content-security-policy"), /default-src 'none'/);
  const view = await (await handleQuoteView(get(`?id=${q.id}&token=${q.token}`), env)).json();
  assert.ok(!("bank_reference" in view.quote) && !("price_reason" in view.quote), "no internal fields");
  assert.equal((await handleQuoteAccept(post({ id: q.id, token: other.token, po_number: "PO-1", po_date: "2026-09-25" }), env, ctx, "rid")).status, 404);
  const ok = await handleQuoteAccept(post({ id: q.id, token: q.token, po_number: "PO-1", po_date: "2026-09-25" }), env, ctx, "rid");
  assert.equal(ok.status, 200);
  assert.equal((await handleQuoteAccept(post({ id: q.id, token: q.token, po_number: "PO-1", po_date: "2026-09-25" }), env, ctx, "rid")).status, 200, "idempotent");
  assert.equal((await handleQuoteAccept(post({ id: q.id, token: q.token, po_number: "PO-2", po_date: "2026-09-25" }), env, ctx, "rid")).status, 409);
});

test("an expired quote cannot be accepted", async () => {
  const env = makeEnv();
  const q = await createQuote(env);
  await env.CRM_DB.prepare("UPDATE enterprise_quotes SET valid_until = '2020-01-01T00:00:00Z' WHERE id = ?").bind(q.id).run();
  const r = await handleQuoteAccept(post({ id: q.id, token: q.token, po_number: "PO-1", po_date: "2026-09-25" }), env, ctx, "rid");
  assert.equal(r.status, 410);
  assert.equal((await getQuote(env.CRM_DB, q.id)).status, "expired");
});

test("PO invoice: only after acceptance, one invoice, IGST to another state, held without GST config", async () => {
  const env = makeEnv();
  const q = await createQuote(env);
  assert.equal((await handleQuoteInvoice(post({ id: q.id }, ADMIN_H), env, ctx, "rid")).status, 409, "no PO yet");
  await handleQuoteAccept(post({ id: q.id, token: q.token, po_number: "PO-7781", po_date: "2026-09-25" }), env, ctx, "rid");
  const [a, b] = await Promise.all([
    handleQuoteInvoice(post({ id: q.id }, ADMIN_H), env, ctx, "rid"),
    handleQuoteInvoice(post({ id: q.id }, ADMIN_H), env, ctx, "rid"),
  ]);
  const numbers = [(await a.json()).invoice_number, (await b.json()).invoice_number];
  assert.equal(numbers[0], numbers[1], "one invoice even when approved twice at once");
  assert.equal((await env.CRM_DB.prepare("SELECT COUNT(*) n FROM invoices").first()).n, 1);
  const inv = await getInvoiceByPayment(env.CRM_DB, "po:" + q.id);
  assert.equal(inv.document.supply_type, "inter_state");
  assert.equal(inv.document.tax.total_paise, 41600000);
  assert.match(inv.document.line_items[0].description, /PO PO-7781/);
  assert.equal(inv.document.payment.provider, "bank_transfer");
  const quote = await getQuote(env.CRM_DB, q.id);
  assert.equal(quote.status, "invoiced");
  assert.equal(quote.invoice_number, numbers[0]);

  const env2 = makeEnv(null);
  const q2 = await acceptedQuote(env2);
  const held = await handleQuoteInvoice(post({ id: q2.id }, ADMIN_H), env2, ctx, "rid");
  assert.equal(held.status, 409);
  assert.match((await getQuote(env2.CRM_DB, q2.id)).invoice_hold_reason, /^gst_config_incomplete/);
  assert.equal((await getQuote(env2.CRM_DB, q2.id)).status, "accepted");
  env2.GST_INVOICE_CONFIG = JSON.stringify(WITH_LUT);
  assert.equal((await handleQuoteInvoice(post({ id: q2.id }, ADMIN_H), env2, ctx, "rid")).status, 200);
});

test("PO invoices appear in the customer's invoice list", async () => {
  const env = makeEnv();
  await invoicedQuote(env, { gstin: OD });
  env.REVENUE_CRM_KV.store.set("apikey:k1", JSON.stringify({ email: "cfo@acme.in", status: "active" }));
  const list = await (await handleInvoiceList(get("", { "X-API-Key": "k1" }), env)).json();
  assert.equal(list.invoices.length, 1);
  assert.equal((await getInvoiceByPayment(env.CRM_DB, list.invoices[0].payment_id)).document.supply_type, "intra_state");
});

test("reconciliation: exact match with TDS, one bank transfer per invoice, provisions once", async () => {
  const env = makeEnv();
  const q = await invoicedQuote(env);
  const total = 41600000;
  const base = { id: q.id, bank_reference: "UTR0000123456", received_on: "2026-09-25" };
  const mismatch = await handleQuoteReconcile(post({ ...base, amount_received_paise: total - 1 }, ADMIN_H), env, ctx, "rid");
  assert.equal(mismatch.status, 409);
  const noSection = await handleQuoteReconcile(post({ ...base, amount_received_paise: total * 0.9, tds_paise: total * 0.1 }, ADMIN_H), env, ctx, "rid");
  assert.equal(noSection.status, 400);
  const [r1, r2] = await Promise.all([
    handleQuoteReconcile(post({ ...base, amount_received_paise: total * 0.9, tds_paise: total * 0.1, tds_section: "194J" }, ADMIN_H), env, ctx, "rid"),
    handleQuoteReconcile(post({ ...base, amount_received_paise: total * 0.9, tds_paise: total * 0.1, tds_section: "194J" }, ADMIN_H), env, ctx, "rid"),
  ]);
  const bodies = [await r1.json(), await r2.json()];
  assert.equal(bodies.filter((b) => b.status === "provisioned" && !b.duplicate).length, 1, "provisioned exactly once");
  const provisioned = bodies.find((b) => b.status === "provisioned" && !b.duplicate);
  assert.equal(provisioned.api_key_hint.length, 12);
  const keys = [...env.API_KEYS_KV.store.keys()];
  assert.equal(keys.length, 1, "one entitlement");
  assert.ok(keys[0].length > 12 && !JSON.stringify(bodies).includes(keys[0]), "only a hint in the response; the key goes by email");
  assert.equal(provisioned.api_key_hint, keys[0].slice(0, 12));
  assert.equal(JSON.parse(env.API_KEYS_KV.store.get(keys[0])).tier, "ENTERPRISE");
  const quote = await getQuote(env.CRM_DB, q.id);
  assert.equal(quote.status, "provisioned");
  assert.equal(quote.tds_section, "194J");

  // The same bank transfer cannot settle a second invoice.
  const q2 = await invoicedQuote(env);
  const reuse = await handleQuoteReconcile(post({ ...base, id: q2.id, amount_received_paise: total }, ADMIN_H), env, ctx, "rid");
  assert.equal(reuse.status, 409);
  assert.equal((await reuse.json()).error, "bank_reference_already_used");
  assert.equal((await getQuote(env.CRM_DB, q2.id)).status, "invoiced");
});

test("reconciliation is admin-only and never before the invoice", async () => {
  const env = makeEnv();
  const q = await acceptedQuote(env);
  const body = { id: q.id, amount_received_paise: 41600000, bank_reference: "UTR1", received_on: "2026-09-25" };
  assert.equal((await handleQuoteReconcile(post(body), env, ctx, "rid")).status, 401);
  assert.equal((await handleQuoteReconcile(post({ ...body, bank_reference: "UTR0001" }, ADMIN_H), env, ctx, "rid")).status, 409);
});

test("export PO: zero-rated under LUT with realisation pending; FIRC required, no TDS", async () => {
  const env = makeEnv();
  const q = await invoicedQuote(env, { gstin: undefined, billing_state: "OUTSIDE_INDIA", billing_country: "SG",
    company_name: "Lion City Security Pte Ltd", billing_address: "1 Raffles Place, Singapore 048616" });
  const inv = await getInvoiceByPayment(env.CRM_DB, "po:" + q.id);
  assert.equal(inv.document.supply_type, "export_under_lut");
  assert.equal(inv.document.export.realisation_basis, "bank_realisation_pending");
  const base = { id: q.id, amount_received_paise: 41600000, bank_reference: "SWIFT2026ABC", received_on: "2026-09-25" };
  assert.equal((await handleQuoteReconcile(post(base, ADMIN_H), env, ctx, "rid")).status, 400, "FIRC required");
  assert.equal((await handleQuoteReconcile(post({ ...base, amount_received_paise: 37440000, tds_paise: 4160000, tds_section: "194J",
    firc_reference: "FIRC-9" }, ADMIN_H), env, ctx, "rid")).status, 400, "no TDS abroad");
  const ok = await handleQuoteReconcile(post({ ...base, firc_reference: "FIRC-2026-77" }, ADMIN_H), env, ctx, "rid");
  assert.equal(ok.status, 200);
  assert.equal((await getQuote(env.CRM_DB, q.id)).firc_reference, "FIRC-2026-77");
});

test("a provisioning failure keeps the payment reconciled and can be retried", async () => {
  const env = makeEnv();
  const q = await invoicedQuote(env);
  env.REVENUE_CRM_KV.failPrefix = "customer:";
  const r = await handleQuoteReconcile(post({ id: q.id, amount_received_paise: 41600000, bank_reference: "UTR555", received_on: "2026-09-25" }, ADMIN_H), env, ctx, "rid");
  assert.equal(r.status, 502);
  assert.equal((await getQuote(env.CRM_DB, q.id)).status, "paid");
  const retry = await handleQuoteProvision(post({ id: q.id }, ADMIN_H), env, ctx, "rid");
  assert.equal(retry.status, 200);
  assert.equal((await getQuote(env.CRM_DB, q.id)).status, "provisioned");
  assert.equal((await handleQuoteProvision(post({ id: q.id }, ADMIN_H), env, ctx, "rid")).status, 200, "idempotent");
  assert.equal(env.API_KEYS_KV.store.size, 1, "a repeated provision call never mints a second entitlement");
});

test("cancellation: before the invoice only", async () => {
  const env = makeEnv();
  const a = await acceptedQuote(env);
  assert.equal((await handleQuoteCancel(post({ id: a.id, note: "budget moved" }, ADMIN_H), env, ctx, "rid")).status, 200);
  const b = await invoicedQuote(env);
  assert.equal((await handleQuoteCancel(post({ id: b.id }, ADMIN_H), env, ctx, "rid")).status, 409);
});

test("quote HTML escapes every field", () => {
  const html = renderQuoteHtml({ id: "qt_x", status: "sent", valid_until: "2026-10-25T00:00:00Z", company_name: "<script>x</script>",
    billing_address: "a&b", billing_country: null, buyer_gstin: null, email: "e@x.com", plan: "<b>p</b>", term_months: 12,
    amount_paise: 100, amount_basis: "x", po_number: "\"><img src=x>", po_date: "2026-09-25", invoice_number: null });
  assert.ok(!/<script>|<b>p|<img /.test(html));
});
