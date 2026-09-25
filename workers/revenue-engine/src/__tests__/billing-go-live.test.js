// P0 revenue go-live: checkout idempotency (S5) and webhook admission (S15).
// Every Razorpay identifier here is a TEST-ONLY fixture (prefix "TEST_ONLY"),
// never production configuration. Razorpay's API is a recorded fake; webhook
// signatures are computed for real.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import { planResponse } from "./helpers/razorpay-plans.js";
import { handleBillingWebhook, handleBillingSubscriptionCreate } from "../subscription-engine.js";

const WHSEC = "whsec_TEST_ONLY";
const TEST_PLAN = "plan_TEST_ONLY_pro_monthly";
const ctx = { waitUntil() {} };

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
    RAZORPAY_KEY_ID: "rzp_test_TEST_ONLY", RAZORPAY_KEY_SECRET: "rzp_secret_TEST_ONLY",
    RAZORPAY_WEBHOOK_SECRET: WHSEC, RAZORPAY_PLAN_ID_PRO_MONTHLY: TEST_PLAN, ...extra,
  };
}

function post(body) {
  return new Request("https://intel.cyberdudebivash.com/api/v2/billing/subscriptions/create", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
}

/** Razorpay create-subscription fake: each call mints a new id. */
async function withRazorpay(fn) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    // Plan reads (S19 price verification) are not subscription creations.
    const plan = planResponse(url);
    if (plan) return plan;
    calls.push({ url, body: init.body ? JSON.parse(init.body) : null });
    if (url.endsWith("/v1/subscriptions")) return Response.json({ id: `sub_TEST_ONLY_${calls.length}`, status: "created" });
    return new Response("{}", { status: 404 });
  };
  try { return await fn(calls); } finally { globalThis.fetch = real; }
}

function signed(body, eventId) {
  const raw = JSON.stringify(body);
  const sig = crypto.createHmac("sha256", WHSEC).update(raw).digest("hex");
  const headers = { "Content-Type": "application/json", "X-Razorpay-Signature": sig };
  if (eventId) headers["X-Razorpay-Event-Id"] = eventId;
  return new Request("https://intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay", { method: "POST", headers, body: raw });
}

// ── S5: subscription-create idempotency ─────────────────────────────────────

test("a retried checkout reuses the unpaid subscription instead of creating a second one", async () => {
  const env = makeEnv();
  await withRazorpay(async (calls) => {
    const buyer = { email: "buyer@example.com", tier: "PRO", billing_cycle: "monthly", billing_state: "27" };
    const a = await (await handleBillingSubscriptionCreate(post(buyer), env, ctx, "rid")).json();
    const b = await (await handleBillingSubscriptionCreate(post(buyer), env, ctx, "rid")).json();
    assert.equal(calls.length, 1, "only one Razorpay subscription is created");
    assert.equal(b.subscription_id, a.subscription_id);
    assert.equal(b.reused, true);
    // Different buyer details (tax invoice data) are a different checkout.
    const c = await (await handleBillingSubscriptionCreate(post({ ...buyer, billing_state: "29" }), env, ctx, "rid")).json();
    assert.notEqual(c.subscription_id, a.subscription_id);
    assert.equal(calls.length, 2);
  });
});

test("a paid (no longer 'created') subscription is never handed out again", async () => {
  const env = makeEnv();
  await withRazorpay(async (calls) => {
    const buyer = { email: "buyer@example.com", tier: "PRO", billing_cycle: "monthly" };
    const a = await (await handleBillingSubscriptionCreate(post(buyer), env, ctx, "rid")).json();
    const link = JSON.parse(env.REVENUE_CRM_KV.store.get(`razorpay_sub:${a.subscription_id}`));
    env.REVENUE_CRM_KV.store.set(`razorpay_sub:${a.subscription_id}`, JSON.stringify({ ...link, status: "authenticated" }));
    const b = await (await handleBillingSubscriptionCreate(post(buyer), env, ctx, "rid")).json();
    assert.notEqual(b.subscription_id, a.subscription_id);
    assert.equal(calls.length, 2);
  });
});

test("an email with a live subscription on the same tier is sent to the Billing Center, not billed twice", async () => {
  const env = makeEnv();
  const future = new Date(Date.now() + 10 * 86400e3).toISOString();
  env.REVENUE_CRM_KV.store.set("sub:email:buyer@example.com", JSON.stringify({ tier: "PRO", status: "active", current_period_end: future }));
  await withRazorpay(async (calls) => {
    const res = await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "PRO" }), env, ctx, "rid");
    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.error, "already_subscribed");
    assert.equal(body.billing_center_url, "/billing.html");
    assert.equal(calls.length, 0);
    // An upgrade to another tier, or a lapsed / cancelled record, may buy.
    assert.equal((await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "ENTERPRISE" }), makeEnv({
      REVENUE_CRM_KV: env.REVENUE_CRM_KV, RAZORPAY_PLAN_ID_ENTERPRISE_MONTHLY: "plan_TEST_ONLY_ent_monthly",
    }), ctx, "rid")).status, 200);
    env.REVENUE_CRM_KV.store.set("sub:email:buyer@example.com", JSON.stringify({ tier: "PRO", status: "cancelled", current_period_end: future }));
    assert.equal((await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "PRO" }), env, ctx, "rid")).status, 200);
    env.REVENUE_CRM_KV.store.set("sub:email:buyer@example.com", JSON.stringify({ tier: "PRO", status: "active", current_period_end: new Date(Date.now() - 1000).toISOString() }));
    assert.equal((await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "PRO", billing_state: "10" }), env, ctx, "rid")).status, 200);
  });
});

test("a missing Plan ID fails before any provider call (no payment UI can open)", async () => {
  const env = makeEnv({ RAZORPAY_PLAN_ID_PRO_ANNUAL: undefined });
  await withRazorpay(async (calls) => {
    const res = await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "PRO", billing_cycle: "annual" }), env, ctx, "rid");
    assert.equal(res.status, 503);
    const body = await res.json();
    assert.equal(body.subscription_id, undefined);
    assert.equal(calls.length, 0);
  });
});

test("the browser cannot set the price: amount / plan_id in the request are ignored", async () => {
  const env = makeEnv();
  await withRazorpay(async (calls) => {
    await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "PRO", amount: 1, plan_id: "plan_attacker" }), env, ctx, "rid");
    assert.equal(calls[0].body.plan_id, TEST_PLAN);
    assert.equal("amount" in calls[0].body, false);
  });
});

// ── S15: webhook admission ──────────────────────────────────────────────────

test("account binding: once RAZORPAY_ACCOUNT_ID is set, a foreign or missing account_id is refused without mutation", async () => {
  const env = makeEnv({ RAZORPAY_ACCOUNT_ID: "acc_TEST_ONLY_A" });
  const base = { event: "subscription.authenticated", payload: { subscription: { entity: { id: "sub_x", notes: {} } } } };
  for (const [i, account_id] of [["1", "acc_TEST_ONLY_B"], ["2", undefined]]) {
    const res = await handleBillingWebhook(signed({ ...base, account_id }, `evt_acc_${i}`), env, ctx, "rid");
    assert.equal(res.status, 403);
    assert.equal(env.REVENUE_CRM_KV.store.has(`rzp_sub_event:evt_acc_${i}`), false);
    assert.equal(env.REVENUE_CRM_KV.store.has("razorpay_sub:sub_x"), false);
  }
  const ok = await handleBillingWebhook(signed({ ...base, account_id: "acc_TEST_ONLY_A" }, "evt_acc_3"), env, ctx, "rid");
  assert.equal(ok.status, 200);
  assert.equal(env.REVENUE_CRM_KV.store.has("rzp_sub_event:evt_acc_3"), true);
});

test("webhook order: unsigned body never reaches the allowlist, idempotency or entitlement", async () => {
  const env = makeEnv();
  const raw = JSON.stringify({ event: "subscription.activated", payload: { subscription: { entity: { id: "sub_forged", notes: { email: "x@example.com", tier: "MSSP" } } } } });
  const res = await handleBillingWebhook(new Request("https://intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Razorpay-Signature": "ab".repeat(32), "X-Razorpay-Event-Id": "evt_forged" }, body: raw,
  }), env, ctx, "rid");
  assert.equal(res.status, 401);
  assert.equal(env.REVENUE_CRM_KV.store.has("rzp_sub_event:evt_forged"), false);
  assert.equal(env.API_KEYS_KV.store.size, 0);
});

test("unknown signed events are neither applied nor recorded as processed, so a later allowlisted replay still works", async () => {
  const env = makeEnv();
  for (const event of ["order.paid", "invoice.paid", "", "subscription.activated.extra"]) {
    const res = await handleBillingWebhook(signed({ event, payload: {} }, "evt_same"), env, ctx, "rid");
    assert.equal((await res.json()).status, "ignored");
  }
  assert.equal(env.REVENUE_CRM_KV.store.has("rzp_sub_event:evt_same"), false);
});
