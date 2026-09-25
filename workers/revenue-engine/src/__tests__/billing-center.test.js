// Billing Center (S6-S12): GET /api/v2/billing/account and persisted,
// idempotent cancellation. Every identifier is a TEST-ONLY fixture;
// Razorpay's API is a recorded fake.
import assert from "node:assert/strict";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import { recordCapturedPayment, insertRefundRequest } from "../billing-ledger.js";
import { handleBillingAccount, handleSubscriptionCancel } from "../billing-routes.js";

const ctx = { waitUntil() {} };
const EMAIL = "buyer@example.com";

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

function makeEnv() {
  return {
    CRM_DB: createD1(), REVENUE_CRM_KV: fakeKV(), API_KEYS_KV: fakeKV(),
    RAZORPAY_KEY_ID: "rzp_test_TEST_ONLY", RAZORPAY_KEY_SECRET: "rzp_secret_TEST_ONLY",
  };
}

const kvGet = (env, key) => JSON.parse(env.REVENUE_CRM_KV.store.get(key));

function customerKey(env, key, email = EMAIL, status = "active") {
  env.REVENUE_CRM_KV.store.set(`apikey:${key}`, JSON.stringify({ key, email, status }));
}

async function seedPayment(env, { id = "pay_TEST_ONLY_1", email = EMAIL, ageSec = 3600, sub = "sub_TEST_ONLY_1" } = {}) {
  await recordCapturedPayment(env.CRM_DB, {
    payment: { id, amount: 410000, currency: "INR", status: "captured", created_at: Math.floor(Date.now() / 1000) - ageSec },
    providerSubId: sub, email, tier: "PRO", billingCycle: "monthly", buyer: { billing_state: "27", gstin: "", billing_name: "" },
  });
}

function seedActiveSub(env, sub = "sub_TEST_ONLY_1", email = EMAIL) {
  const periodEnd = new Date(Date.now() + 20 * 86400e3).toISOString();
  env.REVENUE_CRM_KV.store.set(`razorpay_sub:${sub}`, JSON.stringify({
    razorpay_subscription_id: sub, email, tier: "PRO", billing_cycle: "monthly", status: "active",
    internal_sub_id: "isub_1", api_key: "k_live", current_period_end: periodEnd,
  }));
  env.REVENUE_CRM_KV.store.set("sub:isub_1", JSON.stringify({ id: "isub_1", email, tier: "PRO", status: "active", current_period_end: periodEnd }));
  return periodEnd;
}

function get(headers = {}) {
  return new Request("https://intel.cyberdudebivash.com/api/v2/billing/account", { headers });
}
function cancelReq(key) {
  return new Request("https://intel.cyberdudebivash.com/api/v2/billing/subscriptions/cancel", {
    method: "POST", headers: { "content-type": "application/json", ...(key ? { "X-API-Key": key } : {}) }, body: "{}",
  });
}

async function withRazorpay(fn, { failCancel = false } = {}) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    calls.push({ url, method: (init.method || "GET").toUpperCase(), body: init.body ? JSON.parse(init.body) : null });
    if (/\/v1\/subscriptions\/[^/]+\/cancel$/.test(url)) {
      return failCancel ? new Response("{}", { status: 502 }) : Response.json({ status: "active" });
    }
    return new Response("{}", { status: 404 });
  };
  try { return await fn(calls); } finally { globalThis.fetch = real; }
}

// ── account API ─────────────────────────────────────────────────────────────

test("account: needs a current API key; superseded, revoked and unknown keys are refused", async () => {
  const env = makeEnv();
  customerKey(env, "k_old", EMAIL, "superseded");
  customerKey(env, "k_rev", EMAIL, "revoked");
  assert.equal((await handleBillingAccount(get(), env)).status, 401);
  assert.equal((await handleBillingAccount(get({ "X-API-Key": "k_unknown" }), env)).status, 401);
  for (const k of ["k_old", "k_rev"]) {
    const res = await handleBillingAccount(get({ "X-API-Key": k }), env);
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "key_not_current");
  }
});

test("account: shows own subscription, payments, invoices and refund position from the authoritative records", async () => {
  const env = makeEnv();
  customerKey(env, "k1");
  await seedPayment(env);
  const periodEnd = seedActiveSub(env);
  const res = await handleBillingAccount(get({ "X-API-Key": "k1" }), env);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.account.email, EMAIL);
  assert.equal(body.subscription.subscription_id, "sub_TEST_ONLY_1");
  assert.equal(body.subscription.status, "active");
  assert.equal(body.subscription.tier, "PRO");
  assert.equal(body.subscription.current_period_end, periodEnd);
  assert.equal(body.subscription.renews, true);
  assert.equal(body.subscription.cancel_scheduled, false);
  assert.equal(body.payments.length, 1);
  assert.equal(body.payments[0].amount_paise, 410000);
  assert.equal(body.payments[0].invoice_status, "pending", "invoice not yet issued for this ledger row");
  assert.equal("billing_address" in body.payments[0], false, "buyer tax details are not echoed");
  assert.deepEqual(body.invoices, []);
  assert.deepEqual(body.credit_notes, []);
  assert.equal(body.refund.eligible, true);
  assert.equal(body.actions.can_cancel, true);
  assert.equal(body.actions.can_request_refund, true);
  assert.equal(body.api_key, undefined, "the account view never returns a key");
  // The link's api_key must not leak through the subscription block either.
  assert.equal(JSON.stringify(body).includes("k_live"), false);
});

test("account: scoped to the key's email; another customer's data never appears", async () => {
  const env = makeEnv();
  customerKey(env, "k_a", "a@example.com");
  await seedPayment(env, { id: "pay_TEST_ONLY_B", email: "b@example.com", sub: "sub_TEST_ONLY_B" });
  seedActiveSub(env, "sub_TEST_ONLY_B", "b@example.com");
  const url = "https://intel.cyberdudebivash.com/api/v2/billing/account?email=b@example.com";
  const body = await (await handleBillingAccount(new Request(url, { headers: { "X-API-Key": "k_a" } }), env)).json();
  assert.equal(body.account.email, "a@example.com");
  assert.deepEqual(body.payments, []);
  assert.equal(body.subscription, null);
  assert.equal(body.refund.eligible, false);
  assert.equal(body.actions.can_cancel, false);
});

test("account: outside the 7-day window, refund is not offered and the reason is given", async () => {
  const env = makeEnv();
  customerKey(env, "k1");
  await seedPayment(env, { ageSec: 8 * 86400 });
  seedActiveSub(env);
  const body = await (await handleBillingAccount(get({ "X-API-Key": "k1" }), env)).json();
  assert.equal(body.refund.eligible, false);
  assert.equal(body.refund.code, "outside_guarantee_window");
  assert.ok(body.refund.window_ends_at);
  assert.equal(body.actions.can_request_refund, false);
});

test("account: an existing refund request is shown with its status and not offered again", async () => {
  const env = makeEnv();
  customerKey(env, "k1");
  await seedPayment(env);
  seedActiveSub(env);
  await insertRefundRequest(env.CRM_DB, { id: "rfr_TEST_ONLY", paymentId: "pay_TEST_ONLY_1", email: EMAIL, reason: "x", amountPaise: 410000, now: new Date().toISOString() });
  const body = await (await handleBillingAccount(get({ "X-API-Key": "k1" }), env)).json();
  assert.equal(body.refund.eligible, false);
  assert.equal(body.refund.code, "already_requested");
  assert.equal(body.refund.request.status, "pending_review");
  assert.equal(body.refund.request.status_label, "Under review");
});

test("account: a customer with no purchase gets an empty, honest account", async () => {
  const env = makeEnv();
  customerKey(env, "k_free");
  const body = await (await handleBillingAccount(get({ "X-API-Key": "k_free" }), env)).json();
  assert.equal(body.subscription, null);
  assert.deepEqual(body.payments, []);
  assert.equal(body.refund.code, "no_eligible_payment");
  assert.deepEqual(body.actions, { can_cancel: false, can_request_refund: false });
});

// ── cancellation persistence ────────────────────────────────────────────────

test("cancel: recorded on the provider link and internal subscription; access unchanged; account shows it", async () => {
  const env = makeEnv();
  customerKey(env, "k1");
  await seedPayment(env);
  const periodEnd = seedActiveSub(env);
  env.API_KEYS_KV.store.set("k_live", JSON.stringify({ expires_at: periodEnd }));
  await withRazorpay(async (calls) => {
    const res = await handleSubscriptionCancel(cancelReq("k1"), env, ctx, "rid");
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.status, "cancel_scheduled");
    assert.equal(body.access_until, periodEnd);
    assert.deepEqual(calls.find((c) => c.url.endsWith("/cancel")).body, { cancel_at_cycle_end: 1 });
    assert.ok(!calls.some((c) => c.url.includes("/refund")), "cancellation never refunds");
  });
  const link = kvGet(env, "razorpay_sub:sub_TEST_ONLY_1");
  assert.equal(link.status, "active", "still active until Razorpay ends the cycle");
  assert.equal(link.cancel_at_cycle_end, true);
  assert.ok(link.cancel_scheduled_at);
  assert.equal(kvGet(env, "sub:isub_1").cancel_at_period_end, true);
  assert.equal(JSON.parse(env.API_KEYS_KV.store.get("k_live")).expires_at, periodEnd, "access kept to period end");

  const acct = await (await handleBillingAccount(get({ "X-API-Key": "k1" }), env)).json();
  assert.equal(acct.subscription.cancel_scheduled, true);
  assert.equal(acct.subscription.renews, false);
  assert.equal(acct.actions.can_cancel, false);
});

test("cancel: a repeated request answers from the record without calling Razorpay again", async () => {
  const env = makeEnv();
  customerKey(env, "k1");
  await seedPayment(env);
  seedActiveSub(env);
  await withRazorpay(async (calls) => {
    const first = await (await handleSubscriptionCancel(cancelReq("k1"), env, ctx, "rid")).json();
    const again = await handleSubscriptionCancel(cancelReq("k1"), env, ctx, "rid");
    assert.equal(again.status, 200);
    const body = await again.json();
    assert.equal(body.duplicate, true);
    assert.equal(body.cancel_scheduled_at, first.cancel_scheduled_at);
    assert.equal(calls.filter((c) => c.url.endsWith("/cancel")).length, 1);
  });
});

test("cancel: an ended subscription answers 409 without a provider call; a Razorpay failure records nothing", async () => {
  const env = makeEnv();
  customerKey(env, "k1");
  await seedPayment(env);
  seedActiveSub(env);
  await withRazorpay(async (calls) => {
    const res = await handleSubscriptionCancel(cancelReq("k1"), env, ctx, "rid");
    assert.equal(res.status, 502);
    assert.equal(kvGet(env, "razorpay_sub:sub_TEST_ONLY_1").cancel_scheduled_at, undefined);
    assert.equal(calls.length, 1);
  }, { failCancel: true });
  const link = kvGet(env, "razorpay_sub:sub_TEST_ONLY_1");
  env.REVENUE_CRM_KV.store.set("razorpay_sub:sub_TEST_ONLY_1", JSON.stringify({ ...link, status: "refunded" }));
  await withRazorpay(async (calls) => {
    const res = await handleSubscriptionCancel(cancelReq("k1"), env, ctx, "rid");
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "subscription_ended");
    assert.equal(calls.length, 0);
  });
  const acct = await (await handleBillingAccount(get({ "X-API-Key": "k1" }), env)).json();
  assert.equal(acct.subscription.status, "refunded");
  assert.equal(acct.actions.can_cancel, false);
});
