// S13/S22/S23: commercial readiness verdict, operator queue, admin health
// summary. Every credential here is a TEST-ONLY fixture.
import assert from "node:assert/strict";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import { planResponse, canonicalPlan } from "./helpers/razorpay-plans.js";

// Razorpay fake for the S19 Plan price check: canonical Plans, unless a test
// overrides one id in planOverrides.
const planOverrides = new Map();
globalThis.fetch = async (input) => {
  const url = typeof input === "string" ? input : input.url;
  const m = url.match(/\/v1\/plans\/([^/?]+)$/);
  if (m && planOverrides.has(m[1])) return Response.json(planOverrides.get(m[1]));
  return planResponse(url) || new Response("{}", { status: 404 });
};
import { buildCommercialReadiness, buildOperationsQueue, handleCommercialReadiness } from "../commercial-readiness.js";
import { handleRevenueEngineHealth } from "../index.js";
import { recordCapturedPayment, insertRefundRequest, transitionRefundRequest, recordRefund, markDisputed, ensureBillingSchema } from "../billing-ledger.js";

const ADMIN = "admin_TEST_ONLY";
const SECRETS = {
  RAZORPAY_KEY_ID: "rzp_live_TEST_ONLY_keyid", RAZORPAY_KEY_SECRET: "TEST_ONLY_key_secret_value",
  RAZORPAY_WEBHOOK_SECRET: "TEST_ONLY_webhook_secret_value", RAZORPAY_ACCOUNT_ID: "acc_TEST_ONLY",
  SLACK_WEBHOOK_URL: "https://hooks.slack.test/TEST_ONLY_path",
};
const PLANS = {
  RAZORPAY_PLAN_ID_PRO_MONTHLY: "plan_TEST_ONLY_pro_monthly", RAZORPAY_PLAN_ID_PRO_ANNUAL: "plan_TEST_ONLY_pro_annual",
  RAZORPAY_PLAN_ID_ENTERPRISE_MONTHLY: "plan_TEST_ONLY_enterprise_monthly", RAZORPAY_PLAN_ID_ENTERPRISE_ANNUAL: "plan_TEST_ONLY_enterprise_annual",
  RAZORPAY_PLAN_ID_MSSP_MONTHLY: "plan_TEST_ONLY_mssp_monthly", RAZORPAY_PLAN_ID_MSSP_ANNUAL: "plan_TEST_ONLY_mssp_annual",
};
const NOW = Date.parse("2026-09-25T06:00:00Z"); // FY 26-27
const GST = (luts) => JSON.stringify({
  supplier_legal_name: "Test Supplier Legal Name", supplier_trade_name: "Test Trade",
  supplier_gstin: "21ARKPN8270G1ZP", supplier_address: "Registered address line, City, Odisha 751001",
  sac: { subscription: "998315" }, gst_rate_percent: 18, invoice_prefix: "CDB",
  confirmed_by: "Test CA", confirmed_on: "2026-09-24", ...(luts ? { luts } : {}),
});

function kv() {
  const m = new Map();
  return { async get(k) { return m.get(k) ?? null; }, async put(k, v) { m.set(k, v); }, async delete(k) { m.delete(k); } };
}
function readyEnv(extra = {}) {
  return {
    REVENUE_ADMIN_SECRET: ADMIN, CRM_DB: createD1(), REVENUE_CRM_KV: kv(), API_KEYS_KV: kv(),
    ...SECRETS, ...PLANS, GST_INVOICE_CONFIG: GST([{ arn: "AD2104260012345", financial_year: "26-27" }]), ...extra,
  };
}
const byId = (r, id) => r.checks.find((c) => c.id === id);

test("an unconfigured deployment is BLOCKED, naming every blocker with its fix", async () => {
  const r = await buildCommercialReadiness({}, NOW);
  assert.equal(r.verdict, "BLOCKED");
  for (const id of ["razorpay_api_keys", "razorpay_webhook_secret", "razorpay_plan_ids", "api_keys_kv", "revenue_crm_kv", "billing_ledger"]) {
    assert.ok(r.blockers.includes(id), `blocker ${id}`);
    assert.ok(byId(r, id).fix, `${id} says how to fix it`);
  }
  assert.equal(r.queue, null, "no ledger, no queue");
});

test("a fully configured live deployment is READY with no warnings and an empty queue", async () => {
  const r = await buildCommercialReadiness(readyEnv(), NOW);
  assert.equal(r.verdict, "READY", JSON.stringify(r.checks.filter((c) => !c.ok)));
  assert.deepEqual(r.warnings, []);
  assert.equal(r.queue.attention, 0);
});

test("test-mode Razorpay keys block go-live; a single missing Plan ID blocks and is named", async () => {
  const r = await buildCommercialReadiness(readyEnv({ RAZORPAY_KEY_ID: "rzp_test_TEST_ONLY", RAZORPAY_PLAN_ID_MSSP_ANNUAL: undefined }), NOW);
  assert.equal(r.verdict, "BLOCKED");
  assert.deepEqual(r.blockers.sort(), ["razorpay_live_mode", "razorpay_plan_ids"]);
  assert.match(byId(r, "razorpay_live_mode").detail, /test mode/);
  assert.match(byId(r, "razorpay_plan_ids").detail, /mssp_annual/);
  assert.match(byId(r, "razorpay_plan_ids").fix, /RAZORPAY_PLAN_ID_MSSP_ANNUAL/);
});

test("GST, LUT, account binding and alerts are warnings, not blockers (invoices are held, never guessed)", async () => {
  const r = await buildCommercialReadiness(readyEnv({ GST_INVOICE_CONFIG: undefined, RAZORPAY_ACCOUNT_ID: undefined, SLACK_WEBHOOK_URL: undefined }), NOW);
  assert.equal(r.verdict, "READY");
  assert.deepEqual(r.warnings.sort(), ["gst_invoice_config", "operator_alerts", "razorpay_account_binding"]);
  const noLut = await buildCommercialReadiness(readyEnv({ GST_INVOICE_CONFIG: GST() }), NOW);
  assert.deepEqual(noLut.warnings, ["export_lut_current_fy"]);
  assert.match(byId(noLut, "export_lut_current_fy").detail, /26-27/);
});

test("within 30 days of 1 April, a missing next-year LUT is flagged", async () => {
  const march = Date.parse("2027-03-10T06:00:00Z");
  const r = await buildCommercialReadiness(readyEnv({ GST_INVOICE_CONFIG: GST([{ arn: "AD2104260012345", financial_year: "26-27" }]) }), march);
  assert.deepEqual(r.warnings, ["export_lut_next_fy"]);
  assert.match(byId(r, "export_lut_next_fy").detail, /27-28/);
});

test("no secret value, Plan ID or GST configuration content appears in the response", async () => {
  const env = readyEnv({ RAZORPAY_KEY_ID: "rzp_test_TEST_ONLY_leakcheck" });
  const raw = JSON.stringify(await buildCommercialReadiness(env, NOW));
  for (const v of [...Object.values(SECRETS), ...Object.values(PLANS), "rzp_test_TEST_ONLY_leakcheck", "21ARKPN8270G1ZP", "AD2104260012345", "Test Supplier Legal Name"]) {
    assert.equal(raw.includes(v), false, `leaked ${v}`);
  }
});

test("operator queue: counts, ages and overdue flags from the ledger; no customer data", async () => {
  const env = readyEnv();
  const db = env.CRM_DB;
  await ensureBillingSchema(db);
  const iso = (msAgo) => new Date(NOW - msAgo).toISOString();
  const pay = (id, email) => recordCapturedPayment(db, {
    payment: { id, amount: 410000, currency: "INR", status: "captured", created_at: Math.floor((NOW - 3600e3) / 1000) },
    providerSubId: "sub_" + id, email, tier: "PRO", billingCycle: "monthly", buyer: {},
  });
  for (const [id, email] of [["pay_A", "a@example.com"], ["pay_B", "b@example.com"], ["pay_C", "c@example.com"], ["pay_D", "d@example.com"]]) await pay(id, email);
  // A: pending refund, 3 days old (overdue). B: approved, Razorpay refund never started (stuck).
  await insertRefundRequest(db, { id: "rfr_A", paymentId: "pay_A", email: "a@example.com", reason: "", amountPaise: 410000, now: iso(3 * 86400e3) });
  await insertRefundRequest(db, { id: "rfr_B", paymentId: "pay_B", email: "b@example.com", reason: "", amountPaise: 410000, now: iso(86400e3) });
  await transitionRefundRequest(db, "rfr_B", "pending_review", "approved", { decided_at: iso(2 * 3600e3) });
  // C: processed refund with no credit note (no invoice: GST held). D: disputed.
  await recordRefund(db, { refundId: "rfnd_C", paymentId: "pay_C", amountPaise: 410000, status: "processed", atIso: iso(3600e3) });
  await markDisputed(db, "pay_D");
  await db.prepare(`UPDATE billing_payments SET invoice_status = 'held', invoice_hold_reason = 'gst_config_incomplete'`).run();
  const now = new Date(NOW).toISOString();
  await db.prepare(`INSERT INTO enterprise_quotes (id, email, company_name, billing_address, tier, term_months, amount_paise, price_basis, valid_until, status, created_at, updated_at)
    VALUES ('q1','e@example.com','Co','Addr line 1','ENTERPRISE',12,100,'contract','2027-01-01','accepted',?,?),
           ('q2','f@example.com','Co','Addr line 1','ENTERPRISE',12,100,'contract','2027-01-01','invoiced',?,?)`).bind(now, now, now, now).run();

  const q = await buildOperationsQueue(db, NOW);
  assert.deepEqual(
    { count: q.items.refund_requests_to_decide.count, overdue: q.items.refund_requests_to_decide.overdue, age: q.items.refund_requests_to_decide.oldest_age_hours },
    { count: 1, overdue: 1, age: 72 });
  assert.equal(q.items.refunds_approved_not_started.overdue, 1);
  assert.equal(q.items.credit_notes_to_issue.count, 1);
  assert.equal(q.items.disputes_open.count, 1);
  assert.equal(q.items.invoice_holds.count, 4);
  assert.deepEqual(q.items.invoice_holds.by_reason, { gst_config_incomplete: 4 });
  assert.equal(q.items.quotes_to_invoice.count, 1);
  assert.equal(q.items.quotes_awaiting_payment.count, 1);
  assert.equal(q.attention, 1 + 1 + 4 + 1 + 1 + 1, "buyer-side waits (bank transfer) are not operator attention");
  const raw = JSON.stringify(q);
  for (const pii of ["a@example.com", "pay_A", "rfr_A", "e@example.com"]) assert.equal(raw.includes(pii), false, `queue leaks ${pii}`);
});

test("route: admin only; health gives admins the summary and anonymous callers nothing new", async () => {
  const env = readyEnv({ RAZORPAY_WEBHOOK_SECRET: undefined });
  const get = (h = {}) => new Request("https://revenue.intel.cyberdudebivash.com/api/v2/billing/admin/readiness", { headers: h });
  assert.equal((await handleCommercialReadiness(get(), env)).status, 401);
  assert.equal((await handleCommercialReadiness(get({ "X-Admin-Secret": "wrong" }), env)).status, 401);
  const full = await (await handleCommercialReadiness(get({ "X-Admin-Secret": ADMIN }), env)).json();
  assert.equal(full.verdict, "BLOCKED");
  assert.deepEqual(full.blockers, ["razorpay_webhook_secret"]);

  const h = (hdr) => new Request("https://revenue.intel.cyberdudebivash.com/api/health", { headers: hdr });
  const admin = await (await handleRevenueEngineHealth(h({ "X-Admin-Secret": ADMIN }), env, "rid")).json();
  assert.deepEqual(admin.commercial, { verdict: "BLOCKED", blockers: ["razorpay_webhook_secret"], warnings: [], queue_attention: 0 });
  const anon = await (await handleRevenueEngineHealth(h({}), env, "rid")).json();
  assert.equal(anon.commercial, undefined);
  assert.deepEqual(Object.keys(anon).sort(), ["engine", "generated_at", "status", "version"]);
});

test("a configured Plan charging the wrong amount blocks go-live and names the fix (S19)", async () => {
  planOverrides.set("plan_TEST_ONLY_enterprise_annual", { ...canonicalPlan("plan_TEST_ONLY_enterprise_annual"), item: { amount: 100, currency: "INR" } });
  try {
    const r = await buildCommercialReadiness(readyEnv(), NOW);
    assert.equal(r.verdict, "BLOCKED");
    assert.deepEqual(r.blockers, ["razorpay_plan_prices"]);
    assert.match(byId(r, "razorpay_plan_prices").detail, /enterprise_annual \(amount_mismatch\)/);
    assert.match(byId(r, "razorpay_plan_prices").fix, /RAZORPAY_PLAN_ID_ENTERPRISE_ANNUAL.*4,16,000 per year/);
  } finally { planOverrides.clear(); }
});
