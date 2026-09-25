// S19 pricing fail-closed: Razorpay bills whatever the Plan behind
// RAZORPAY_PLAN_ID_* holds. A checkout is created only for a Plan whose
// currency, amount and period equal the canonical price. Every Razorpay
// identifier here is a TEST-ONLY fixture; Razorpay's API is a recorded fake.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import { canonicalPlan } from "./helpers/razorpay-plans.js";
import {
  handleBillingSubscriptionCreate, planMatchesCanonical, canonicalPlanPaise, verifyPlanPrice,
} from "../subscription-engine.js";

const ctx = { waitUntil() {} };
const PLAN = "plan_TEST_ONLY_pro_monthly";

function kv() {
  const m = new Map();
  return {
    store: m,
    async get(k, o) { const v = m.get(k); if (v === undefined) return null; return (o === "json" || o?.type === "json") ? JSON.parse(v) : v; },
    async put(k, v) { m.set(k, v); }, async delete(k) { m.delete(k); },
  };
}
const env = (extra = {}) => ({
  CRM_DB: createD1(), REVENUE_CRM_KV: kv(), API_KEYS_KV: kv(),
  RAZORPAY_KEY_ID: "rzp_live_TEST_ONLY", RAZORPAY_KEY_SECRET: "TEST_ONLY_secret", RAZORPAY_PLAN_ID_PRO_MONTHLY: PLAN, ...extra,
});
const post = (body) => new Request("https://intel.cyberdudebivash.com/api/v2/billing/subscriptions/create", {
  method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
});

/** Razorpay fake: `plan` is what GET /v1/plans/{id} returns (null -> 404, "down" -> network error). */
async function withRazorpay(plan, fn) {
  const calls = { plans: 0, subs: 0 };
  const real = globalThis.fetch;
  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.url;
    if (/\/v1\/plans\//.test(url)) {
      calls.plans++;
      const p = typeof plan === "function" ? plan() : plan;
      if (p === "down") throw new TypeError("fetch failed");
      return p ? Response.json(p) : new Response("{}", { status: 404 });
    }
    if (url.endsWith("/v1/subscriptions")) { calls.subs++; return Response.json({ id: `sub_TEST_ONLY_${calls.subs}`, status: "created" }); }
    return new Response("{}", { status: 404 });
  };
  try { return await fn(calls); } finally { globalThis.fetch = real; }
}

test("canonical prices equal config/commercial-contract.json for every paid tier and cycle", () => {
  const contract = JSON.parse(readFileSync(new URL("../../../../config/commercial-contract.json", import.meta.url), "utf8"));
  for (const [tier, id] of [["PRO", "pro"], ["ENTERPRISE", "enterprise"], ["MSSP", "mssp"]]) {
    assert.equal(canonicalPlanPaise(tier, "monthly"), contract.tiers[id].inr_monthly * 100, `${tier} monthly`);
    assert.equal(canonicalPlanPaise(tier, "annual"), contract.tiers[id].inr_annual * 100, `${tier} annual`);
  }
  assert.equal(canonicalPlanPaise("FREE", "monthly"), null);
});

test("plan comparison: amount, currency and period must all match; annual accepts yearly/1 or monthly/12", () => {
  const ok = canonicalPlan("plan_pro_monthly");
  assert.equal(planMatchesCanonical(ok, "PRO", "monthly").ok, true);
  assert.equal(planMatchesCanonical({ ...ok, item: { ...ok.item, amount: 410001 } }, "PRO", "monthly").reason, "amount_mismatch");
  assert.equal(planMatchesCanonical({ ...ok, item: { ...ok.item, currency: "USD" } }, "PRO", "monthly").reason, "currency_mismatch");
  assert.equal(planMatchesCanonical({ ...ok, interval: 3 }, "PRO", "monthly").reason, "period_mismatch");
  assert.equal(planMatchesCanonical(ok, "ENTERPRISE", "monthly").reason, "amount_mismatch", "a PRO plan configured for Enterprise");
  const annual = canonicalPlan("plan_pro_annual");
  assert.equal(planMatchesCanonical(annual, "PRO", "annual").ok, true);
  assert.equal(planMatchesCanonical({ ...annual, period: "monthly", interval: 12 }, "PRO", "annual").ok, true);
  assert.equal(planMatchesCanonical({ ...annual, period: "monthly", interval: 1 }, "PRO", "annual").reason, "period_mismatch");
  assert.equal(planMatchesCanonical(null, "PRO", "monthly").reason, "plan_unreadable");
});

for (const [name, plan, reason] of [
  ["a Plan charging the wrong amount", { ...canonicalPlan(PLAN), item: { amount: 41000, currency: "INR" } }, "amount_mismatch"],
  ["a Plan in the wrong currency", { ...canonicalPlan(PLAN), item: { amount: 410000, currency: "USD" } }, "currency_mismatch"],
  ["an annual Plan configured as monthly", { ...canonicalPlan(PLAN), period: "yearly" }, "period_mismatch"],
  ["a Plan Razorpay cannot find", null, "plan_unreadable"],
  ["Razorpay unreachable", "down", "plan_unreadable"],
]) {
  test(`checkout refused (no subscription, no payment UI) for ${name}`, async () => {
    const e = env();
    await withRazorpay(plan, async (calls) => {
      const res = await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "PRO" }), e, ctx, "rid");
      assert.equal(res.status, 503);
      const body = await res.json();
      assert.equal(body.error, "plan_price_unverified");
      assert.match(body.message, /No payment was taken/);
      assert.equal(body.subscription_id, undefined);
      assert.equal(calls.subs, 0, "no Razorpay subscription is created");
    });
    const verdict = await withRazorpay(plan, () => verifyPlanPrice(e, "PRO", "monthly", PLAN));
    assert.equal(verdict.reason, reason);
  });
}

test("a verified Plan is cached for an hour; a failed check is not cached, so a fixed Plan sells at once", async () => {
  const e = env();
  let current = { ...canonicalPlan(PLAN), item: { amount: 1, currency: "INR" } };
  await withRazorpay(() => current, async (calls) => {
    assert.equal((await handleBillingSubscriptionCreate(post({ email: "a@example.com", tier: "PRO" }), e, ctx, "rid")).status, 503);
    current = canonicalPlan(PLAN); // operator fixes the Plan
    assert.equal((await handleBillingSubscriptionCreate(post({ email: "b@example.com", tier: "PRO" }), e, ctx, "rid")).status, 200);
    assert.equal((await handleBillingSubscriptionCreate(post({ email: "c@example.com", tier: "PRO" }), e, ctx, "rid")).status, 200);
    assert.equal(calls.plans, 2, "the verified Plan is read once, then served from cache");
    assert.equal(calls.subs, 2);
  });
});

test("the Plan check runs before any other Razorpay call and never reads the price from the request", async () => {
  const e = env();
  await withRazorpay(canonicalPlan(PLAN), async (calls) => {
    const res = await handleBillingSubscriptionCreate(post({ email: "buyer@example.com", tier: "PRO", amount: 1, plan_amount: 1 }), e, ctx, "rid");
    assert.equal(res.status, 200);
    assert.equal(calls.plans, 1);
  });
});
