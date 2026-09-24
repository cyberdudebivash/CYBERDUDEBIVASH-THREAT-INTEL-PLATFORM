/**
 * Owner commercial policy (2026-09-24): public manual payment proof
 * (UPI / NEFT / crypto) is retired. POST /api/payment/manual-notify answers
 * 410 manual_payment_retired and has no side effect: no KV record, no
 * Telegram alert, no audit write. Review ids issued before the retirement
 * stay readable through GET /api/payment/status.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import worker from "../index.js";

function fakeKV(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    store: m,
    writes: 0,
    get: async (k, o) => {
      const v = m.get(k);
      if (v === undefined) return null;
      return o === "json" || (o && o.type === "json") ? JSON.parse(v) : v;
    },
    async put(k, v) { this.writes += 1; m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    list: async () => ({ keys: [], list_complete: true }),
  };
}

function harness(securityHubSeed = {}) {
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  const env = {
    INTEL_R2: { get: async () => null },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(securityHubSeed),
    ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
    TELEGRAM_BOT_TOKEN: "tg-test", TELEGRAM_CHAT_ID: "1",
  };
  const outbound = [];
  const realFetch = globalThis.fetch;
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const call = async (path, init) => {
    globalThis.fetch = async (input) => {
      outbound.push(typeof input === "string" ? input : input.url);
      return new Response("{}", { status: 200 });
    };
    try {
      const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com${path}`, init), env, ctx);
      await Promise.allSettled(waits);
      return { res, body: await res.json() };
    } finally {
      globalThis.fetch = realFetch;
    }
  };
  return { call, env, outbound };
}

const PROOF = {
  name: "Mallory", email: "attacker@example.invalid", plan: "ENTERPRISE", payment_method: "upi",
  transaction_id: "UTR-FORGED-123", amount: "41600", currency: "INR",
};

test("POST /api/payment/manual-notify answers 410 manual_payment_retired", async () => {
  const { call } = harness();
  const { res, body } = await call("/api/payment/manual-notify", {
    method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.20" },
    body: JSON.stringify(PROOF),
  });
  assert.equal(res.status, 410);
  assert.equal(body.error, "manual_payment_retired");
  assert.match(body.message, /no longer available/);
  assert.match(res.headers.get("cache-control") || "", /no-store/);
  assert.ok(!("review_id" in body), "no review id may be issued");
});

test("a retired manual proof writes nothing and alerts no one", async () => {
  const { call, env, outbound } = harness();
  await call("/api/payment/manual-notify", {
    method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.21" },
    body: JSON.stringify(PROOF),
  });
  for (const k of env.SECURITY_HUB_KV.store.keys()) {
    assert.ok(!k.startsWith("manual_payment:"), `manual payment record written: ${k}`);
  }
  assert.equal(env.API_KEYS_KV.store.size, 0, "no API key may be provisioned");
  assert.ok(!outbound.some((u) => /telegram/i.test(u)), "no Telegram alert may be sent");
});

test("GET /api/payment/status still answers for a review id issued before the retirement", async () => {
  const reviewId = "CDB-LEGACY-0011223344556677";
  const { call } = harness({
    [`manual_payment:${reviewId}`]: JSON.stringify({ review_id: reviewId, plan: "PRO", payment_method: "upi", status: "activated", created_at: "2026-09-01T00:00:00Z" }),
  });
  const { res, body } = await call(`/api/payment/status?review_id=${reviewId}`, { method: "GET" });
  assert.equal(res.status, 200);
  assert.equal(body.status, "activated");
});
