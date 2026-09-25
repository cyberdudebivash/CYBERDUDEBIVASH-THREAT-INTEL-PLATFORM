// S28: the billing canary, certified against both real Workers in-process
// (the production entry points wrangler deploys), sharing one API_KEYS_KV,
// with Razorpay in TEST mode faked at the network edge. Proves the canary
// passes on a correct deployment and FAILS on the defects it exists to catch.
// Every credential here is a TEST-ONLY fixture.
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { test } from "node:test";

import { EXIT, runPublicChecks, runAdminChecks, runTestCheckout, readinessProvesTestMode } from "./canary-lib.mjs";
import revenueWorker from "../../workers/revenue-engine/src/production-entry.js";
import gatewayWorker from "../../workers/intel-gateway/src/production-entry.js";
import { createD1 } from "../../workers/revenue-engine/src/__tests__/helpers/d1-sqlite.js";
import { canonicalPlan } from "../../workers/revenue-engine/src/__tests__/helpers/razorpay-plans.js";

const ROOT = new URL("../../", import.meta.url);
const ADMIN = "revenue_admin_TEST_ONLY";

function kv() {
  const m = new Map();
  return {
    store: m,
    async get(k, o) { const v = m.get(k); if (v === undefined) return null; return (o === "json" || o?.type === "json") ? JSON.parse(v) : v; },
    async put(k, v) { m.set(k, typeof v === "string" ? v : JSON.stringify(v)); },
    async delete(k) { m.delete(k); },
    async list({ prefix = "" } = {}) { return { keys: [...m.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })), list_complete: true }; },
  };
}

const PLANS = {
  RAZORPAY_PLAN_ID_PRO_MONTHLY: "plan_TEST_ONLY_pro_monthly", RAZORPAY_PLAN_ID_PRO_ANNUAL: "plan_TEST_ONLY_pro_annual",
  RAZORPAY_PLAN_ID_ENTERPRISE_MONTHLY: "plan_TEST_ONLY_enterprise_monthly", RAZORPAY_PLAN_ID_ENTERPRISE_ANNUAL: "plan_TEST_ONLY_enterprise_annual",
  RAZORPAY_PLAN_ID_MSSP_MONTHLY: "plan_TEST_ONLY_mssp_monthly", RAZORPAY_PLAN_ID_MSSP_ANNUAL: "plan_TEST_ONLY_mssp_annual",
};

let n = 0;
function deployment({ keyId = "rzp_test_TEST_ONLY_key", planOverride = null, pages = {} } = {}) {
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  const API_KEYS_KV = kv();
  const revenueEnv = {
    CRM_DB: createD1(), REVENUE_CRM_KV: kv(), EMAIL_QUEUE_KV: kv(), API_KEYS_KV,
    REVENUE_ADMIN_SECRET: ADMIN, RAZORPAY_KEY_ID: keyId, RAZORPAY_KEY_SECRET: "TEST_ONLY_key_secret",
    RAZORPAY_WEBHOOK_SECRET: "TEST_ONLY_webhook_secret", ...PLANS,
  };
  const gatewayEnv = {
    INTEL_R2: { get: async () => null }, API_KEYS_KV, RATE_LIMIT_KV: kv(), SECURITY_HUB_KV: kv(), ANALYTICS_KV: kv(), REVENUE_CRM_KV: kv(),
    CDB_JWT_SECRET: "jwt_TEST_ONLY", ADMIN_SECRET: "gateway_admin_TEST_ONLY", GUMROAD_WEBHOOK_SECRET: "gumroad_TEST_ONLY",
  };
  const ip = `192.0.2.${++n}`;
  const ctx = { waitUntil() {} };
  // Razorpay TEST mode at the network edge; any other outbound call is refused.
  const razorpay = async (url, init = {}) => {
    const m = url.match(/\/v1\/plans\/([^/?]+)$/);
    if (m) return Response.json(planOverride && planOverride[m[1]] ? planOverride[m[1]] : canonicalPlan(m[1]));
    if (url.endsWith("/v1/subscriptions") && (init.method || "GET") === "POST") return Response.json({ id: `sub_TEST_ONLY_${++n}`, status: "created" });
    return new Response("{}", { status: 404 });
  };
  const call = (worker, env, host) => async (method, path, { headers = {}, body, raw } = {}) => {
    const h = { "cf-connecting-ip": ip, ...headers };
    if (body !== undefined && !raw && !h["Content-Type"]) h["Content-Type"] = "application/json";
    const real = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const url = typeof input === "string" ? input : input.url;
      return url.startsWith("https://api.razorpay.com/") ? razorpay(url, init) : new Response("{}", { status: 200 });
    };
    try {
      const res = await worker.fetch(new Request(`https://${host}${path}`, {
        method, headers: h, body: body === undefined ? undefined : (raw ? body : JSON.stringify(body)),
      }), env, ctx);
      const text = await res.text();
      let json = null;
      try { json = JSON.parse(text); } catch { json = null; }
      return { status: res.status, body: json, text };
    } finally { globalThis.fetch = real; }
  };
  const revenue = call(revenueWorker, revenueEnv, "revenue.intel.cyberdudebivash.com");
  const gateway = call(gatewayWorker, gatewayEnv, "intel.cyberdudebivash.com");
  // intel.cyberdudebivash.com: /api/v2/billing/* is routed to the revenue
  // engine (wrangler.toml); root pages are the static site.
  const intel = async (method, path, opts) => {
    if (path.startsWith("/api/v2/billing/")) return revenue(method, path, opts);
    const page = path.match(/^\/([a-z0-9-]+\.html)$/);
    if (page) {
      if (page[1] in pages) return pages[page[1]] === null ? { status: 404, body: null, text: "" } : { status: 200, body: null, text: pages[page[1]] };
      const file = new URL(page[1], ROOT);
      return existsSync(file) ? { status: 200, body: null, text: readFileSync(file, "utf8") } : { status: 404, body: null, text: "" };
    }
    return gateway(method, path, opts);
  };
  return { intel, revenue, revenueEnv };
}

const failed = (steps) => steps.filter((s) => !s.ok).map((s) => s.step);

test("public canary passes against a correct deployment and mutates nothing", async () => {
  const d = deployment();
  const steps = await runPublicChecks(d);
  assert.deepEqual(failed(steps), [], JSON.stringify(steps.filter((s) => !s.ok)));
  assert.equal(steps.length, 15, "every public boundary is probed");
  assert.equal(d.revenueEnv.API_KEYS_KV.store.size, 0, "no key minted");
});

test("admin canary: readable readiness; test mode is BLOCKED, so the live gate fails and admin mode reports it", async () => {
  const d = deployment();
  const admin = await runAdminChecks(d, ADMIN, { requireReady: false });
  assert.deepEqual(failed(admin.steps), []);
  assert.equal(admin.readiness.verdict, "BLOCKED");
  assert.ok(admin.readiness.blockers.includes("razorpay_live_mode"));
  const live = await runAdminChecks(d, ADMIN, { requireReady: true });
  assert.deepEqual(failed(live.steps), ["readiness_verdict"]);
  const wrong = await runAdminChecks(d, "wrong_secret", { requireReady: false });
  assert.ok(failed(wrong.steps).includes("readiness_readable"));
});

test("test-checkout runs only when readiness proves a test-mode key", async () => {
  const test = await runAdminChecks(deployment(), ADMIN, { requireReady: false });
  assert.equal(readinessProvesTestMode(test.readiness), true);
  const live = await runAdminChecks(deployment({ keyId: "rzp_live_TEST_ONLY_key" }), ADMIN, { requireReady: false });
  assert.equal(readinessProvesTestMode(live.readiness), false, "never on live keys");
  assert.equal(readinessProvesTestMode(null), false, "never without a verdict");
  assert.equal(EXIT.LIVE_MODE_REFUSED, 13);
});

test("test checkout: created after the Plan price check, test key, retry reused, status needs payment proof", async () => {
  const d = deployment();
  const steps = await runTestCheckout(d, { email: "billing-canary+run@example.com" });
  assert.deepEqual(failed(steps), [], JSON.stringify(steps));
});

// --- the canary catches what it exists to catch -----------------------------------

test("canary FAILS when a Razorpay Plan charges the wrong amount", async () => {
  const d = deployment({ planOverride: { plan_TEST_ONLY_pro_monthly: { ...canonicalPlan("plan_TEST_ONLY_pro_monthly"), item: { amount: 100, currency: "INR" } } } });
  assert.ok(failed(await runTestCheckout(d, { email: "billing-canary+bad@example.com" })).includes("test_checkout_created_after_plan_price_check"));
  const admin = await runAdminChecks(d, ADMIN, { requireReady: false });
  assert.ok(admin.readiness.blockers.includes("razorpay_plan_prices"));
});

test("canary FAILS when the Billing Center page is missing or the admin page is truncated", async () => {
  const d = deployment({ pages: { "billing.html": null, "admin.html": "<html><script>setTimeout(() => { t.style." } });
  const f = failed(await runPublicChecks(d));
  assert.ok(f.includes("billing_center_page_served"));
  assert.ok(f.includes("admin_page_complete"));
});

test("canary FAILS when a webhook secret is missing (500 is not a refusal: real payments would be rejected too)", async () => {
  const d = deployment();
  delete d.revenueEnv.RAZORPAY_WEBHOOK_SECRET;
  const steps = await runPublicChecks(d);
  const s = steps.find((x) => x.step === "razorpay_webhook_refuses_bad_signature");
  assert.equal(s.ok, false);
  assert.match(s.detail.finding, /RAZORPAY_WEBHOOK_SECRET not configured/);
});
