/**
 * Recurring billing moved to Razorpay Subscriptions (2026-09-24). Razorpay
 * also delivers payment.captured / order.paid for every subscription charge
 * (a Payment carrying an invoice_id). The gateway's one-time-order webhook
 * must not provision those -- revenue-engine owns subscription
 * entitlements -- or each charge would mint a second API key.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHmac } from "node:crypto";

import worker from "../index.js";

const SECRET = "whsec-test";

function fakeKV() {
  const m = new Map();
  return {
    store: m,
    get: async (k, o) => {
      const v = m.get(k);
      if (v === undefined) return null;
      return o === "json" || (o && o.type === "json") ? JSON.parse(v) : v;
    },
    put: async (k, v) => { m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    list: async () => ({ keys: [], list_complete: true }),
  };
}

async function deliver(payload) {
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  const env = {
    INTEL_R2: { get: async () => null },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(),
    ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test", RAZORPAY_WEBHOOK_SECRET: SECRET,
  };
  const raw = JSON.stringify(payload);
  const sig = createHmac("sha256", SECRET).update(raw).digest("hex");
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("{}", { status: 200 });
  const waits = [];
  try {
    const res = await worker.fetch(new Request("https://intel.cyberdudebivash.com/api/webhooks/razorpay", {
      method: "POST", headers: { "content-type": "application/json", "x-razorpay-signature": sig }, body: raw,
    }), env, { waitUntil: (p) => waits.push(p) });
    await Promise.allSettled(waits);
    return { res, body: await res.json(), env };
  } finally {
    globalThis.fetch = realFetch;
  }
}

const SUB_PAYMENT = {
  id: "pay_SUB1", amount: 410000, currency: "INR", status: "captured", order_id: "order_S1",
  invoice_id: "inv_S1", email: "buyer@example.com", notes: {},
};

for (const event of ["payment.captured", "order.paid"]) {
  test(`${event} for a subscription charge provisions nothing in the gateway`, async () => {
    const { res, body, env } = await deliver({ event, payload: { payment: { entity: SUB_PAYMENT } } });
    assert.equal(res.status, 200);
    assert.equal(body.status, "ignored_subscription_payment");
    assert.equal(env.API_KEYS_KV.store.size, 0, "no API key may be minted");
    assert.equal(env.SECURITY_HUB_KV.store.get("payment_key_map:pay_SUB1"), undefined);
  });
}

test("a payment arriving with a subscription entity is ignored too", async () => {
  const { body, env } = await deliver({ event: "payment.captured", payload: {
    payment: { entity: { ...SUB_PAYMENT, invoice_id: null } }, subscription: { entity: { id: "sub_1" } } } });
  assert.equal(body.status, "ignored_subscription_payment");
  assert.equal(env.API_KEYS_KV.store.size, 0);
});

test("a one-time order payment is still provisioned (unchanged path)", async () => {
  const { body } = await deliver({ event: "payment.captured", payload: { payment: { entity: {
    id: "pay_ONE1", amount: 410000, currency: "INR", status: "captured", order_id: "order_O1", invoice_id: null,
    email: "buyer@example.com", notes: { tier: "PRO", email: "buyer@example.com", billing: "monthly" } } } } });
  assert.equal(body.status, "provisioned");
});
