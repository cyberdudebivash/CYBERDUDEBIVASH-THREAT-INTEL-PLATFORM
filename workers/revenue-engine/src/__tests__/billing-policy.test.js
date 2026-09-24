// Owner commercial policy (2026-09-24): billing ledger, GST invoices and the
// merchant-approved 7-day refund workflow. D1 is real SQLite (helpers/
// d1-sqlite.js); Razorpay's API is a recorded fake; webhook signatures are
// computed for real.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import {
  financialYear, istDate, placeOfSupply, splitInclusiveTax, formatInvoiceNumber, parseGstInvoiceConfig,
  normalizeBuyerTaxId, normalizeBillingState, normalizeBillingName, gstinCheckChar,
} from "../gst.js";
import {
  recordCapturedPayment, issueInvoiceForPayment, getPayment, completeRecipientDetails, getInvoiceByPayment,
} from "../billing-ledger.js";
import {
  handleRefundRequest, handleRefundApprove, handleRefundReject, handleRefundList, handleInvoiceView,
  handleInvoiceIssue, renderInvoiceHtml, REFUND_WINDOW_MS,
} from "../billing-routes.js";
import { handleBillingWebhook, handleBillingSubscriptionCreate } from "../subscription-engine.js";

const ADMIN = "admin-secret-test";
const WHSEC = "whsec_test";
const GST_CONFIG = JSON.stringify({
  supplier_legal_name: "Test Supplier Legal Name", supplier_trade_name: "Test Trade",
  supplier_gstin: "21ARKPN8270G1ZP", supplier_address: "Registered address line, City, Odisha 751001",
  sac: { subscription: "998315" }, gst_rate_percent: 18, invoice_prefix: "CDB",
  confirmed_by: "Test CA", confirmed_on: "2026-09-24",
});

function fakeKV(initial = {}) {
  const store = new Map(Object.entries(initial).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]));
  return {
    store,
    async get(key, opts) {
      const v = store.get(key);
      if (v === undefined) return null;
      const type = typeof opts === "string" ? opts : opts?.type;
      return type === "json" ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, typeof value === "string" ? value : JSON.stringify(value)); },
    async delete(key) { store.delete(key); },
  };
}

function makeEnv(extra = {}) {
  return {
    CRM_DB: createD1(), REVENUE_CRM_KV: fakeKV(), API_KEYS_KV: fakeKV(),
    REVENUE_ADMIN_SECRET: ADMIN, RAZORPAY_KEY_ID: "rzp_test", RAZORPAY_KEY_SECRET: "rzp_secret",
    RAZORPAY_WEBHOOK_SECRET: WHSEC, ...extra,
  };
}

/** Razorpay API fake: records calls; `payments` is Razorpay's own view. */
function fakeRazorpay({ payments = {}, refunds = {}, failRefund = false, refundDelayMs = 0 } = {}) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    const method = (init.method || "GET").toUpperCase();
    const body = init.body ? JSON.parse(init.body) : null;
    calls.push({ method, url, body });
    let m;
    if ((m = url.match(/\/v1\/payments\/([^/]+)\/refund$/)) && method === "POST") {
      if (failRefund) return new Response(JSON.stringify({ error: { description: "bank down" } }), { status: 502 });
      // A slow refund call: Razorpay's payment shows the refund only after it returns.
      if (refundDelayMs) await new Promise((res) => setTimeout(res, refundDelayMs));
      const r = { id: "rfnd_" + (calls.length), payment_id: m[1], amount: body.amount, status: "pending" };
      (refunds[m[1]] ||= []).push(r);
      payments[m[1]].amount_refunded = (payments[m[1]].amount_refunded || 0) + body.amount;
      return Response.json(r);
    }
    if ((m = url.match(/\/v1\/payments\/([^/]+)\/refunds$/))) return Response.json({ items: refunds[m[1]] || [] });
    if ((m = url.match(/\/v1\/payments\/([^/]+)$/))) {
      return payments[m[1]] ? Response.json(payments[m[1]]) : new Response("{}", { status: 404 });
    }
    if ((m = url.match(/\/v1\/subscriptions\/([^/]+)\/cancel$/))) return Response.json({ id: m[1], status: "cancelled" });
    if (url.endsWith("/v1/subscriptions")) return Response.json({ id: "sub_NEW", status: "created" });
    return new Response("{}", { status: 404 });
  };
  return { calls, payments, refunds, restore: () => { globalThis.fetch = real; } };
}

const nowSec = () => Math.floor(Date.now() / 1000);

async function seedPayment(env, { id = "pay_1", email = "buyer@example.com", amount = 410000, ageSec = 3600, sub = "sub_1", tier = "PRO", buyer = {} } = {}) {
  return recordCapturedPayment(env.CRM_DB, {
    payment: { id, amount, currency: "INR", status: "captured", created_at: nowSec() - ageSec },
    providerSubId: sub, email, tier, billingCycle: "monthly", buyer,
  });
}

function customerKey(env, key, email) {
  env.REVENUE_CRM_KV.store.set(`apikey:${key}`, JSON.stringify({ key, email, status: "active" }));
}

function post(path, body, headers = {}) {
  return new Request("https://revenue.intel.cyberdudebivash.com" + path, {
    method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body),
  });
}
function get(path, headers = {}) {
  return new Request("https://revenue.intel.cyberdudebivash.com" + path, { headers });
}
const ctx = { waitUntil: () => {} };

// --- GST rules ------------------------------------------------------------------

test("financial year and invoice date are evaluated in IST, April to March", () => {
  assert.equal(financialYear("2026-03-31T18:29:59Z"), "25-26", "23:59:59 IST on 31 March");
  assert.equal(financialYear("2026-03-31T18:30:00Z"), "26-27", "00:00 IST on 1 April");
  assert.equal(financialYear("2027-01-15T00:00:00Z"), "26-27");
  assert.equal(istDate("2026-09-24T20:00:00Z"), "2026-09-25");
});

test("invoice numbers stay within the 16-character r.46(b) limit", () => {
  assert.equal(formatInvoiceNumber("CDB", "26-27", 1), "CDB/26-27/000001");
  assert.equal("CDB/26-27/000001".length, 16);
  assert.throws(() => formatInvoiceNumber("CDB-SA", "26-27", 1), /exceeds 16/, "CDB-SA/26-27/000001 is 19 characters");
});

test("place of supply: GSTIN state, declared state, supplier location, export", () => {
  const sup = "21";
  assert.deepEqual(placeOfSupply({ buyerGstin: "29AAAAA0000A1Z" + gstinCheckChar("29AAAAA0000A1Z"), supplierStateCode: sup }),
    { code: "29", basis: "recipient_gstin", export: false });
  assert.equal(placeOfSupply({ billingState: "27", supplierStateCode: sup }).code, "27");
  assert.deepEqual(placeOfSupply({ supplierStateCode: sup }), { code: "21", basis: "supplier_location_no_recipient_address", export: false });
  assert.equal(placeOfSupply({ billingState: "OUTSIDE_INDIA", supplierStateCode: sup }).export, true);
});

test("tax is carved out of the amount charged: CGST+SGST intra-state, IGST inter-state", () => {
  const intra = splitInclusiveTax(410000, 18, true);
  assert.equal(intra.taxable_paise + intra.cgst_paise + intra.sgst_paise, 410000);
  assert.equal(intra.taxable_paise, 347458);
  assert.equal(intra.igst_paise, 0);
  const inter = splitInclusiveTax(410000, 18, false);
  assert.equal(inter.taxable_paise + inter.igst_paise, 410000);
  assert.equal(inter.cgst_paise + inter.sgst_paise, 0);
});

test("GST config: every legal field is required; nothing defaults", () => {
  const empty = parseGstInvoiceConfig(undefined);
  assert.equal(empty.ok, false);
  const partial = parseGstInvoiceConfig({ supplier_gstin: "21ARKPN8270G1ZP", gst_rate_percent: 18 });
  assert.equal(partial.ok, false);
  for (const k of ["supplier_legal_name", "supplier_address", "sac.subscription", "invoice_prefix", "confirmed_by", "confirmed_on"]) {
    assert.ok(partial.missing.includes(k), k);
  }
  assert.equal(parseGstInvoiceConfig({ ...JSON.parse(GST_CONFIG), supplier_gstin: "21ARKPN8270G1Z5" }).ok, false, "bad GSTIN check");
  const ok = parseGstInvoiceConfig(GST_CONFIG);
  assert.equal(ok.ok, true);
  assert.equal(ok.config.supplier_state_code, "21");
});

test("buyer inputs are validated at the boundary", () => {
  assert.equal(normalizeBuyerTaxId("22AAAAA0000A1Z5").ok, false);
  assert.equal(normalizeBillingState("21").value, "21");
  assert.equal(normalizeBillingState("25").ok, false, "retired state code");
  assert.equal(normalizeBillingName("<script>").ok, false);
  assert.equal(normalizeBillingName("Acme Security Pvt Ltd").value, "Acme Security Pvt Ltd");
});

// --- invoices on the ledger -------------------------------------------------------

test("no GST config: payment recorded, invoice held, no serial consumed", async () => {
  const env = makeEnv();
  await seedPayment(env);
  const r = await issueInvoiceForPayment(env.CRM_DB, env, "pay_1");
  assert.equal(r.status, "held");
  assert.match(r.reason, /^gst_config_incomplete:/);
  assert.equal((await getPayment(env.CRM_DB, "pay_1")).invoice_status, "held");
  const seq = await env.CRM_DB.prepare("SELECT COUNT(*) n FROM invoice_sequences").first();
  assert.equal(seq.n, 0);
});

test("configured: B2C invoice issued from the supplier location, idempotent", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  await seedPayment(env);
  const a = await issueInvoiceForPayment(env.CRM_DB, env, "pay_1");
  assert.equal(a.status, "issued");
  const doc = a.invoice.document;
  assert.equal(doc.invoice_number, `CDB/${financialYear(Date.now() - 3600e3)}/000001`);
  assert.equal(doc.supply_type, "intra_state");
  assert.equal(doc.place_of_supply.basis, "supplier_location_no_recipient_address");
  assert.equal(doc.line_items[0].sac, "998315");
  assert.equal(doc.tax.total_paise, 410000);
  const b = await issueInvoiceForPayment(env.CRM_DB, env, "pay_1");
  assert.equal(b.invoice.invoice_number, doc.invoice_number, "same payment, same invoice");
  const seq = await env.CRM_DB.prepare("SELECT last_seq FROM invoice_sequences").first();
  assert.equal(seq.last_seq, 1);
});

test("concurrent issuance: consecutive serials, no gaps, no duplicates", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  const n = 20;
  for (let i = 0; i < n; i++) await seedPayment(env, { id: `pay_c${i}`, email: `c${i}@example.com` });
  // Each payment issued twice, all at once (redelivered webhooks included).
  const ids = [...Array(n).keys()].flatMap((i) => [`pay_c${i}`, `pay_c${i}`]);
  const results = await Promise.all(ids.map((id) => issueInvoiceForPayment(env.CRM_DB, env, id)));
  assert.ok(results.every((r) => r.status === "issued"));
  const rows = (await env.CRM_DB.prepare("SELECT seq, payment_id FROM invoices ORDER BY seq").all()).results;
  assert.equal(rows.length, n, "exactly one invoice per payment");
  assert.deepEqual(rows.map((r) => r.seq), [...Array(n).keys()].map((i) => i + 1), "serials 1..n with no gap");
  assert.equal((await env.CRM_DB.prepare("SELECT last_seq FROM invoice_sequences").first()).last_seq, n);
});

test("registered buyer: held until name and address exist, then IGST for another state", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  const ka = "29AAAAA0000A1Z" + gstinCheckChar("29AAAAA0000A1Z");
  await seedPayment(env, { buyer: { gstin: ka, billing_state: "29" } });
  const held = await issueInvoiceForPayment(env.CRM_DB, env, "pay_1");
  assert.equal(held.reason, "registered_recipient_name_and_address_required");
  await completeRecipientDetails(env.CRM_DB, "pay_1", { billing_name: "Acme Security Pvt Ltd", billing_address: "12 MG Road, Bengaluru 560001" });
  const ok = await issueInvoiceForPayment(env.CRM_DB, env, "pay_1");
  assert.equal(ok.status, "issued");
  assert.equal(ok.invoice.document.supply_type, "inter_state");
  assert.equal(ok.invoice.document.place_of_supply.state_code, "29");
  assert.ok(ok.invoice.document.tax.igst_paise > 0);
});

test("export and high-value unregistered sales are held for review, never guessed", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  await seedPayment(env, { id: "pay_x", buyer: { billing_state: "OUTSIDE_INDIA" } });
  assert.equal((await issueInvoiceForPayment(env.CRM_DB, env, "pay_x")).reason, "recipient_outside_india_export_requires_review");
  await seedPayment(env, { id: "pay_m", email: "m@example.com", amount: 8330000, tier: "MSSP" });
  assert.equal((await issueInvoiceForPayment(env.CRM_DB, env, "pay_m")).reason, "unregistered_recipient_details_required_at_or_above_50000");
});

test("invoice HTML escapes every field", () => {
  const html = renderInvoiceHtml({
    invoice_number: "CDB/26-27/000001", invoice_date: "2026-09-25",
    place_of_supply: { state_name: "Odisha", state_code: "21" }, supply_type: "intra_state",
    supplier: { legal_name: "<img src=x onerror=alert(1)>", trade_name: "", address: "a&b", gstin: "21ARKPN8270G1ZP", state_name: "Odisha", state_code: "21" },
    recipient: { name: "\"><script>alert(1)</script>", address: null, email: "x@example.com", gstin: null },
    line_items: [{ description: "<b>x</b>", sac: "998315", quantity: 1, taxable_value_paise: 100 }],
    tax: { cgst_rate_percent: 9, sgst_rate_percent: 9, cgst_paise: 9, sgst_paise: 9, taxable_paise: 100, total_paise: 118 },
    payment: { payment_id: "pay_1", subscription_id: null }, amount_basis: "x",
  });
  assert.ok(!/<script>|<img |<b>x/.test(html));
  assert.match(html, /&lt;script&gt;/);
});

// --- refund workflow ----------------------------------------------------------------

test("customer files a refund request within 7 days: pending review, no money moves", async () => {
  const env = makeEnv();
  await seedPayment(env);
  customerKey(env, "cdb_pro_key1", "buyer@example.com");
  const rp = fakeRazorpay();
  try {
    const res = await handleRefundRequest(post("/api/v2/billing/refunds/request", { reason: "not a fit", amount: 1 }, { "X-API-Key": "cdb_pro_key1" }), env, ctx, "rid");
    assert.equal(res.status, 202);
    const body = await res.json();
    assert.equal(body.status, "pending_review");
    const again = await handleRefundRequest(post("/api/v2/billing/refunds/request", {}, { "X-API-Key": "cdb_pro_key1" }), env, ctx, "rid");
    assert.equal((await again.json()).duplicate, true);
    assert.equal(rp.calls.length, 0, "a request never calls Razorpay");
    const row = await env.CRM_DB.prepare("SELECT amount_paise FROM refund_requests").first();
    assert.equal(row.amount_paise, 410000, "amount is the ledger amount, not the posted one");
  } finally { rp.restore(); }
});

test("refund eligibility: first purchase only, 7-day window, auth required", async () => {
  const env = makeEnv();
  await seedPayment(env, { id: "pay_old", ageSec: REFUND_WINDOW_MS / 1000 + 60 });
  await seedPayment(env, { id: "pay_renewal", ageSec: 60 });
  customerKey(env, "k1", "buyer@example.com");
  const late = await handleRefundRequest(post("/api/v2/billing/refunds/request", {}, { "X-API-Key": "k1" }), env, ctx, "rid");
  assert.equal(late.status, 422);
  assert.equal((await late.json()).error, "outside_guarantee_window", "a renewal inside 7 days is not a first purchase");
  const anon = await handleRefundRequest(post("/api/v2/billing/refunds/request", {}), env, ctx, "rid");
  assert.equal(anon.status, 401);
  const bogus = await handleRefundRequest(post("/api/v2/billing/refunds/request", {}, { "X-API-Key": "nope" }), env, ctx, "rid");
  assert.equal(bogus.status, 401);
});

async function pendingRequest(env) {
  await seedPayment(env);
  customerKey(env, "k1", "buyer@example.com");
  const res = await handleRefundRequest(post("/api/v2/billing/refunds/request", { reason: "x" }, { "X-API-Key": "k1" }), env, ctx, "rid");
  return (await res.json()).request_id;
}

test("admin approval refunds the ledger amount server-side and cancels the subscription", async () => {
  const env = makeEnv();
  const id = await pendingRequest(env);
  const rp = fakeRazorpay({ payments: { pay_1: { id: "pay_1", status: "captured", amount: 410000, amount_refunded: 0 } } });
  try {
    const res = await handleRefundApprove(post("/api/v2/billing/refunds/approve", { request_id: id, amount: 999999 }, { "X-Admin-Secret": ADMIN }), env, ctx, "rid");
    assert.equal(res.status, 200, JSON.stringify(await res.clone().json()));
    const refundCalls = rp.calls.filter((c) => c.method === "POST" && c.url.endsWith("/refund"));
    assert.equal(refundCalls.length, 1);
    assert.equal(refundCalls[0].body.amount, 410000, "ledger amount, never the request body");
    assert.ok(rp.calls.some((c) => c.url.endsWith("/subscriptions/sub_1/cancel")));
    const row = await env.CRM_DB.prepare("SELECT status, razorpay_refund_id FROM refund_requests WHERE id = ?").bind(id).first();
    assert.equal(row.status, "refund_initiated");
    assert.ok(row.razorpay_refund_id);
  } finally { rp.restore(); }
});

test("only an admin can approve, reject or list", async () => {
  const env = makeEnv();
  const id = await pendingRequest(env);
  const rp = fakeRazorpay({ payments: { pay_1: { id: "pay_1", status: "captured", amount: 410000 } } });
  try {
    const cust = { "X-API-Key": "k1" };
    assert.equal((await handleRefundApprove(post("/x", { request_id: id }, cust), env, ctx, "rid")).status, 401);
    assert.equal((await handleRefundReject(post("/x", { request_id: id }, cust), env, ctx, "rid")).status, 401);
    assert.equal((await handleRefundList(get("/x", cust), env)).status, 401);
    assert.equal(rp.calls.length, 0);
  } finally { rp.restore(); }
});

test("two concurrent approvals refund once", async () => {
  const env = makeEnv();
  const id = await pendingRequest(env);
  // Both approvers read the payment before either refund call returns: only
  // the compare-and-set on the request status stops a second refund.
  const rp = fakeRazorpay({ payments: { pay_1: { id: "pay_1", status: "captured", amount: 410000, amount_refunded: 0 } }, refundDelayMs: 50 });
  try {
    const hdr = { "X-Admin-Secret": ADMIN };
    await Promise.all([
      handleRefundApprove(post("/x", { request_id: id }, hdr), env, ctx, "rid"),
      handleRefundApprove(post("/x", { request_id: id }, hdr), env, ctx, "rid"),
    ]);
    assert.equal(rp.calls.filter((c) => c.method === "POST" && c.url.endsWith("/refund")).length, 1);
  } finally { rp.restore(); }
});

test("a retried approval adopts an existing refund instead of refunding twice", async () => {
  const env = makeEnv();
  const id = await pendingRequest(env);
  const rp = fakeRazorpay({ payments: { pay_1: { id: "pay_1", status: "captured", amount: 410000, amount_refunded: 0 } }, failRefund: true });
  try {
    const hdr = { "X-Admin-Secret": ADMIN };
    const first = await handleRefundApprove(post("/x", { request_id: id }, hdr), env, ctx, "rid");
    assert.equal(first.status, 502);
    // The refund actually went through at Razorpay (response lost).
    rp.payments.pay_1.amount_refunded = 410000;
    rp.refunds.pay_1 = [{ id: "rfnd_lost", payment_id: "pay_1", amount: 410000 }];
    const second = await handleRefundApprove(post("/x", { request_id: id }, hdr), env, ctx, "rid");
    assert.equal(second.status, 200);
    assert.equal((await second.json()).razorpay_refund_id, "rfnd_lost");
    assert.equal(rp.calls.filter((c) => c.method === "POST" && c.url.endsWith("/refund")).length, 1, "only the first (lost) attempt");
  } finally { rp.restore(); }
});

test("approval is blocked when Razorpay's amount differs or the payment is disputed", async () => {
  const env = makeEnv();
  const id = await pendingRequest(env);
  const rp = fakeRazorpay({ payments: { pay_1: { id: "pay_1", status: "captured", amount: 1, amount_refunded: 0 } } });
  try {
    const hdr = { "X-Admin-Secret": ADMIN };
    const mismatch = await handleRefundApprove(post("/x", { request_id: id }, hdr), env, ctx, "rid");
    assert.equal((await mismatch.json()).error, "amount_mismatch");
    await env.CRM_DB.prepare("UPDATE billing_payments SET disputed = 1").run();
    const disputed = await handleRefundApprove(post("/x", { request_id: id }, hdr), env, ctx, "rid");
    assert.equal((await disputed.json()).error, "payment_disputed");
    assert.equal(rp.calls.filter((c) => c.url.endsWith("/refund")).length, 0);
  } finally { rp.restore(); }
});

test("a rejected request cannot then be approved", async () => {
  const env = makeEnv();
  const id = await pendingRequest(env);
  const hdr = { "X-Admin-Secret": ADMIN };
  assert.equal((await handleRefundReject(post("/x", { request_id: id, note: "used the export quota" }, hdr), env, ctx, "rid")).status, 200);
  const rp = fakeRazorpay();
  try {
    const res = await handleRefundApprove(post("/x", { request_id: id }, hdr), env, ctx, "rid");
    assert.equal(res.status, 409);
    assert.equal(rp.calls.length, 0);
  } finally { rp.restore(); }
});

// --- webhook reconciliation -----------------------------------------------------------

function signed(body, eventId) {
  const raw = JSON.stringify(body);
  const sig = crypto.createHmac("sha256", WHSEC).update(raw).digest("hex");
  return new Request("https://revenue.intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay", {
    method: "POST", headers: { "X-Razorpay-Signature": sig, "X-Razorpay-Event-Id": eventId }, body: raw,
  });
}

test("a captured subscription charge is recorded on the ledger and invoiced once", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  env.REVENUE_CRM_KV.store.set("razorpay_sub:sub_W", JSON.stringify({
    email: "w@example.com", tier: "PRO", billing_cycle: "monthly", status: "active", internal_sub_id: "sub_int", api_key: "k_w",
    buyer: { gstin: "", vat_id: "", billing_state: "27", billing_name: "", billing_address: "" },
  }));
  const charged = { event: "subscription.charged", payload: {
    subscription: { entity: { id: "sub_W", current_start: nowSec(), current_end: nowSec() + 30 * 86400, notes: {} } },
    payment: { entity: { id: "pay_W", amount: 410000, currency: "INR", status: "captured", created_at: nowSec(), invoice_id: "inv_rzp" } } } };
  assert.equal((await handleBillingWebhook(signed(charged, "evt_1"), env, ctx, "rid")).status, 200);
  assert.equal((await handleBillingWebhook(signed(charged, "evt_2"), env, ctx, "rid")).status, 200, "redelivery under a new event id");
  const pays = (await env.CRM_DB.prepare("SELECT * FROM billing_payments").all()).results;
  assert.equal(pays.length, 1);
  const inv = await getInvoiceByPayment(env.CRM_DB, "pay_W");
  assert.equal(inv.document.place_of_supply.state_code, "27");
  assert.equal(inv.document.supply_type, "inter_state");
  assert.equal((await env.CRM_DB.prepare("SELECT COUNT(*) n FROM invoices").first()).n, 1);
});

test("refund.processed revokes the entitlement and flags the invoice for a credit note", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  const id = await pendingRequest(env);
  await issueInvoiceForPayment(env.CRM_DB, env, "pay_1");
  env.REVENUE_CRM_KV.store.set("razorpay_sub:sub_1", JSON.stringify({ email: "buyer@example.com", tier: "PRO", status: "active", api_key: "cdb_live_key" }));
  env.API_KEYS_KV.store.set("cdb_live_key", JSON.stringify({ tier: "PRO", email: "buyer@example.com", expires_at: "2099-01-01T00:00:00Z" }));
  const rp = fakeRazorpay({ payments: { pay_1: { id: "pay_1", status: "captured", amount: 410000, amount_refunded: 0 } } });
  try {
    await handleRefundApprove(post("/x", { request_id: id }, { "X-Admin-Secret": ADMIN }), env, ctx, "rid");
  } finally { rp.restore(); }
  const evt = { event: "refund.processed", payload: { refund: { entity: { id: "rfnd_9", payment_id: "pay_1", amount: 410000, status: "processed" } } } };
  assert.equal((await handleBillingWebhook(signed(evt, "evt_r1"), env, ctx, "rid")).status, 200);
  const key = JSON.parse(env.API_KEYS_KV.store.get("cdb_live_key"));
  assert.equal(key.subscription_status, "refunded");
  assert.ok(Date.parse(key.expires_at) <= Date.now());
  assert.equal((await getPayment(env.CRM_DB, "pay_1")).refund_status, "refunded");
  assert.equal((await env.CRM_DB.prepare("SELECT status FROM refund_requests WHERE id = ?").bind(id).first()).status, "refunded");
  assert.equal((await getInvoiceByPayment(env.CRM_DB, "pay_1")).status, "refunded_credit_note_required");
});

test("a dispute webhook blocks the guarantee for that payment", async () => {
  const env = makeEnv();
  await seedPayment(env);
  customerKey(env, "k1", "buyer@example.com");
  const evt = { event: "payment.dispute.created", payload: { dispute: { entity: { id: "disp_1", payment_id: "pay_1" } } } };
  assert.equal((await handleBillingWebhook(signed(evt, "evt_d1"), env, ctx, "rid")).status, 200);
  const res = await handleRefundRequest(post("/x", {}, { "X-API-Key": "k1" }), env, ctx, "rid");
  assert.equal((await res.json()).error, "payment_disputed");
});

// --- invoice access ---------------------------------------------------------------------

test("customers read only their own invoices; unknown and foreign look the same", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  await seedPayment(env);
  const inv = await issueInvoiceForPayment(env.CRM_DB, env, "pay_1");
  const n = encodeURIComponent(inv.invoice.invoice_number);
  customerKey(env, "k1", "buyer@example.com");
  customerKey(env, "k2", "other@example.com");
  const own = await handleInvoiceView(get(`/x?number=${n}&format=html`, { "X-API-Key": "k1" }), env);
  assert.equal(own.status, 200);
  assert.match(own.headers.get("content-security-policy"), /default-src 'none'/);
  assert.equal((await handleInvoiceView(get(`/x?number=${n}`, { "X-API-Key": "k2" }), env)).status, 404);
  assert.equal((await handleInvoiceView(get(`/x?number=CDB%2F26-27%2F999999`, { "X-API-Key": "k1" }), env)).status, 404);
  assert.equal((await handleInvoiceView(get(`/x?number=${n}`), env)).status, 401);
});

test("admin completes held recipient details and issues; amounts cannot be edited", async () => {
  const env = makeEnv({ GST_INVOICE_CONFIG: GST_CONFIG });
  await seedPayment(env, { id: "pay_m", amount: 8330000, tier: "MSSP" });
  const hdr = { "X-Admin-Secret": ADMIN };
  const res = await handleInvoiceIssue(post("/x", {
    payment_id: "pay_m", billing_name: "Acme MSSP Pvt Ltd", billing_address: "1 Park Street, Kolkata 700016",
    billing_state: "19", amount_paise: 1,
  }, hdr), env, ctx, "rid");
  assert.equal(res.status, 200);
  const inv = await getInvoiceByPayment(env.CRM_DB, "pay_m");
  assert.equal(inv.document.tax.total_paise, 8330000);
  assert.equal(inv.document.place_of_supply.state_code, "19");
  assert.equal((await handleInvoiceIssue(post("/x", { payment_id: "pay_m" }, { "X-API-Key": "k" }), env, ctx, "rid")).status, 401);
});

// --- checkout carries buyer details -------------------------------------------------------

test("subscription checkout validates the buyer GSTIN and records it on the subscription", async () => {
  const env = makeEnv({ RAZORPAY_PLAN_ID_PRO_MONTHLY: "plan_pro_m" });
  const rp = fakeRazorpay();
  try {
    const bad = await handleBillingSubscriptionCreate(post("/x", { email: "b@example.com", tier: "PRO", gstin: "22AAAAA0000A1Z5" }), env, ctx, "rid");
    assert.equal(bad.status, 400);
    assert.equal(rp.calls.length, 0);
    const good = await handleBillingSubscriptionCreate(post("/x", {
      email: "b@example.com", tier: "PRO", billing_cycle: "monthly", gstin: "21arkpn8270g1zp", billing_name: "Acme Pvt Ltd",
    }), env, ctx, "rid");
    assert.equal(good.status, 200);
    const sent = rp.calls.find((c) => c.url.endsWith("/v1/subscriptions")).body;
    assert.equal(sent.notes.gstin, "21ARKPN8270G1ZP");
    assert.equal(sent.notes.billing_state, "21", "state follows the GSTIN");
    const link = JSON.parse(env.REVENUE_CRM_KV.store.get("razorpay_sub:sub_NEW"));
    assert.equal(link.buyer.gstin, "21ARKPN8270G1ZP");
  } finally { rp.restore(); }
});

test("revenue-crm/schema.sql carries the same billing DDL the engine creates", async () => {
  const { readFileSync } = await import("node:fs");
  const { BILLING_SCHEMA } = await import("../billing-ledger.js");
  const norm = (s) => s.replace(/\s+/g, " ").trim();
  const sql = norm(readFileSync(new URL("../../../../revenue-crm/schema.sql", import.meta.url), "utf8"));
  for (const stmt of BILLING_SCHEMA) assert.ok(sql.includes(norm(stmt)), "schema.sql is missing: " + norm(stmt).slice(0, 80));
});

test("customer cancellation is scheduled at cycle end: no refund, access kept until then", async () => {
  const { handleSubscriptionCancel } = await import("../billing-routes.js");
  const env = makeEnv();
  await seedPayment(env, { sub: "sub_C" });
  customerKey(env, "k1", "buyer@example.com");
  env.API_KEYS_KV.store.set("k_live", JSON.stringify({ expires_at: "2099-01-01T00:00:00Z" }));
  const rp = fakeRazorpay();
  try {
    const res = await handleSubscriptionCancel(post("/x", {}, { "X-API-Key": "k1" }), env, ctx, "rid");
    assert.equal(res.status, 200);
    const call = rp.calls.find((c) => c.url.endsWith("/subscriptions/sub_C/cancel"));
    assert.deepEqual(call.body, { cancel_at_cycle_end: 1 });
    assert.ok(!rp.calls.some((c) => c.url.includes("/refund")), "cancellation never refunds");
    assert.equal(JSON.parse(env.API_KEYS_KV.store.get("k_live")).expires_at, "2099-01-01T00:00:00Z", "access unchanged until Razorpay ends the cycle");
    assert.equal((await handleSubscriptionCancel(post("/x", {}), env, ctx, "rid")).status, 401);
  } finally { rp.restore(); }
});
