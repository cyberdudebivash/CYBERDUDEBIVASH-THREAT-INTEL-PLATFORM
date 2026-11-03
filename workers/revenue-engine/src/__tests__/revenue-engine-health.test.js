import assert from "node:assert/strict";
import { test } from "node:test";
import { handleRevenueEngineHealth } from "../index.js";

// ---------------------------------------------------------------------------
// GET /api/health -- specifically the razorpay_plan_ids_configured block
// added so "are Plan IDs actually configured" can be answered by reading a
// public JSON endpoint instead of guessing or creating a real Razorpay
// subscription against production to find out. Booleans only, built off the
// same PLAN_ID_ENV_KEYS map handleBillingSubscriptionCreate's 503 check
// reads -- a tier/cycle reported false here is exactly the one that falls
// back to the one-time-order flow in upgrade.html.
//
// A security report demonstrated this endpoint's full detail (engine name,
// binding presence, Razorpay integration state) being readable by anyone,
// unauthenticated -- see handleRevenueEngineHealth's own comment for the
// fix. The detailed-response tests below now authenticate the same way a
// real operator would (X-Admin-Secret matching REVENUE_ADMIN_SECRET); the
// last test in this file is the actual regression test for the fix itself.
// ---------------------------------------------------------------------------

const ADMIN_SECRET = "test-revenue-admin-secret";

function adminHealthRequest(extraHeaders = {}) {
  return new Request("https://x.test/api/health", {
    headers: { "X-Admin-Secret": ADMIN_SECRET, ...extraHeaders },
  });
}

test("handleRevenueEngineHealth: reports all six tier/cycle Plan IDs as false when none are set", async () => {
  const env = { REVENUE_ADMIN_SECRET: ADMIN_SECRET };
  const res = await handleRevenueEngineHealth(adminHealthRequest(), env, "rid_test");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.checks.razorpay_plan_ids_configured, {
    pro_monthly: false, pro_annual: false,
    enterprise_monthly: false, enterprise_annual: false,
    mssp_monthly: false, mssp_annual: false,
  });
});

test("handleRevenueEngineHealth: reports exactly the configured tier/cycle combinations as true", async () => {
  const env = {
    REVENUE_ADMIN_SECRET: ADMIN_SECRET,
    RAZORPAY_PLAN_ID_PRO_MONTHLY: "plan_live_pro_m",
    RAZORPAY_PLAN_ID_ENTERPRISE_ANNUAL: "plan_live_ent_a",
  };
  const res = await handleRevenueEngineHealth(adminHealthRequest(), env, "rid_test");
  const body = await res.json();
  assert.deepEqual(body.checks.razorpay_plan_ids_configured, {
    pro_monthly: true, pro_annual: false,
    enterprise_monthly: false, enterprise_annual: true,
    mssp_monthly: false, mssp_annual: false,
  });
});

test("handleRevenueEngineHealth: never leaks the actual Plan ID values, only booleans", async () => {
  const env = { REVENUE_ADMIN_SECRET: ADMIN_SECRET, RAZORPAY_PLAN_ID_MSSP_ANNUAL: "plan_super_secret_do_not_leak" };
  const res = await handleRevenueEngineHealth(adminHealthRequest(), env, "rid_test");
  const raw = JSON.stringify(await res.json());
  assert.ok(!raw.includes("plan_super_secret_do_not_leak"));
});

test("handleRevenueEngineHealth: degrades cleanly with no KV/D1 bindings at all", async () => {
  const env = { REVENUE_ADMIN_SECRET: ADMIN_SECRET };
  const res = await handleRevenueEngineHealth(adminHealthRequest(), env, "rid_test");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.checks.revenue_crm_kv, "not_bound");
  assert.equal(body.checks.crm_db, "not_bound");
});

test("handleRevenueEngineHealth: an unauthenticated caller gets only status/engine/version/generated_at -- no checks, no binding names, no integration state", async () => {
  const env = { REVENUE_ADMIN_SECRET: ADMIN_SECRET, RAZORPAY_KEY_ID: "rzp_live_should_not_leak" };
  const res = await handleRevenueEngineHealth(new Request("https://x.test/api/health"), env, "rid_test");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(Object.keys(body).sort(), ["engine", "generated_at", "release_sha", "status", "version"]);
  assert.equal(body.status, "ok");
  assert.ok(!("checks" in body));
});

test("handleRevenueEngineHealth: a wrong X-Admin-Secret is treated as unauthenticated, not a 401/500", async () => {
  const env = { REVENUE_ADMIN_SECRET: ADMIN_SECRET };
  const res = await handleRevenueEngineHealth(adminHealthRequest({ "X-Admin-Secret": "wrong-secret" }), env, "rid_test");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(!("checks" in body));
});

test("handleRevenueEngineHealth: public SHA is validated, non-secret, and never reveals binding state", async () => {
  const sha = "a".repeat(40);
  const env = { REVENUE_ADMIN_SECRET: ADMIN_SECRET,
    ENGINE_RELEASE_SHA: sha,
    RAZORPAY_KEY_SECRET: "test_only_must_never_leak"
  };
  const publicResponse = await handleRevenueEngineHealth(new Request("https://x.test/api/health"), env, "rid_test");
  assert.equal(publicResponse.status, 200);
  const body = await publicResponse.json();
  assert.equal(body.release_sha, sha);
  assert.ok(!("checks" in body));
  assert.ok(!JSON.stringify(body).includes("test_only_must_never_leak"));

  const adminResponse = await handleRevenueEngineHealth(adminHealthRequest(), env, "rid_test");
  assert.equal((await adminResponse.json()).release_sha, sha);

  for (const value of [undefined, null, "", "abc", "A".repeat(40), "b".repeat(39), "z".repeat(40), 33]) {
    const badEnv = { ...env, ENGINE_RELEASE_SHA: value };
    const res = await handleRevenueEngineHealth(new Request("https://x.test/api/health"), badEnv, "rid_test");
    assert.equal((await res.json()).release_sha, null, "bad SHA must not be represented as valid");
  }
});
