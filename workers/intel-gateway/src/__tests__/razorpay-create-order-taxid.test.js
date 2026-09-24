/**
 * P0 checkout (2026-09-24): the buyer's GSTIN/VAT number reaches the
 * Razorpay order.
 *
 * upgrade.html has always posted `gstin` to POST
 * /api/payment/razorpay/create-order, but the handler dropped it, so no
 * order carried the buyer's tax id for a GST invoice. The handler now
 * validates it (tax-id.js, same rules as js/checkout.js) and records it
 * in the order notes; an invalid GSTIN is refused before Razorpay is called.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import worker from "../index.js";
import { normalizeBuyerTaxId, gstinCheckChar } from "../tax-id.js";

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

function harness() {
  const edge = new Map();
  globalThis.caches = {
    default: { match: async (req) => edge.get(req.url), put: async (req, res) => { edge.set(req.url, res); } },
  };
  const env = {
    INTEL_R2: { get: async () => null },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(),
    ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
    RAZORPAY_KEY_ID: "rzp_test_key", RAZORPAY_KEY_SECRET: "rzp_test_secret",
  };
  const orders = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = typeof input === "string" ? input : input.url;
    if (url === "https://api.razorpay.com/v1/orders") {
      const body = JSON.parse(init.body);
      orders.push(body);
      return new Response(JSON.stringify({ id: "order_T1", amount: body.amount, currency: body.currency, notes: body.notes }),
        { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response("{}", { status: 404 });
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const createOrder = async (payload) => {
    try {
      const res = await worker.fetch(new Request("https://intel.cyberdudebivash.com/api/payment/razorpay/create-order", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.9" },
        body: JSON.stringify(payload),
      }), env, ctx);
      await Promise.allSettled(waits);
      return { res, body: await res.json() };
    } finally {
      globalThis.fetch = realFetch;
    }
  };
  return { createOrder, orders };
}

test("GSTIN check character follows the GSTN mod-36 scheme", () => {
  assert.equal(gstinCheckChar("21ARKPN8270G1Z"), "P", "the seller's own published GSTIN");
  assert.equal(gstinCheckChar("22AAAAA0000A1Z"), "C");
});

test("normalizeBuyerTaxId: empty is fine, GSTIN checked, VAT charset bounded", () => {
  assert.deepEqual(normalizeBuyerTaxId(undefined), { ok: true, value: "", kind: null });
  assert.deepEqual(normalizeBuyerTaxId("  "), { ok: true, value: "", kind: null });
  assert.deepEqual(normalizeBuyerTaxId(" 21arkpn8270g1zp "), { ok: true, value: "21ARKPN8270G1ZP", kind: "gstin" });
  assert.equal(normalizeBuyerTaxId("22AAAAA0000A1Z5").ok, false, "wrong check character");
  assert.equal(normalizeBuyerTaxId("123456789012345").ok, false, "15 characters must be a GSTIN");
  assert.deepEqual(normalizeBuyerTaxId("DE123456789"), { ok: true, value: "DE123456789", kind: "vat" });
  assert.equal(normalizeBuyerTaxId("<b>x</b>").ok, false);
  assert.equal(normalizeBuyerTaxId("A".repeat(21)).ok, false);
  assert.equal(normalizeBuyerTaxId({ gstin: "x" }).ok, false, "non-string input");
});

test("create-order records a valid buyer GSTIN in the Razorpay order notes", async () => {
  const { createOrder, orders } = harness();
  const { res, body } = await createOrder({ tier: "PRO", email: "buyer@example.com", billing: "monthly", gstin: "21arkpn8270g1zp" });
  assert.equal(res.status, 200, JSON.stringify(body));
  assert.equal(body.order_id, "order_T1");
  assert.equal(orders.length, 1);
  assert.equal(orders[0].notes.gstin, "21ARKPN8270G1ZP");
  assert.equal(orders[0].notes.tier, "PRO");
  assert.equal(orders[0].currency, "INR");
  assert.ok(!("vat_id" in orders[0].notes));
});

test("create-order records a foreign VAT number as vat_id", async () => {
  const { createOrder, orders } = harness();
  const { res } = await createOrder({ tier: "PRO", email: "buyer@example.com", gstin: "DE123456789" });
  assert.equal(res.status, 200);
  assert.equal(orders[0].notes.vat_id, "DE123456789");
  assert.ok(!("gstin" in orders[0].notes));
});

test("create-order refuses an invalid GSTIN before calling Razorpay", async () => {
  const { createOrder, orders } = harness();
  const { res, body } = await createOrder({ tier: "PRO", email: "buyer@example.com", gstin: "22AAAAA0000A1Z5" });
  assert.equal(res.status, 400);
  assert.equal(body.field, "gstin");
  assert.match(body.error, /GSTIN/);
  assert.equal(orders.length, 0, "no Razorpay order may be created");
});

test("create-order without a tax id is unchanged (no tax keys in notes)", async () => {
  const { createOrder, orders } = harness();
  const { res } = await createOrder({ tier: "ENTERPRISE", email: "buyer@example.com", billing: "annual" });
  assert.equal(res.status, 200);
  assert.deepEqual(Object.keys(orders[0].notes).sort(), ["billing", "email", "platform", "tier"]);
  assert.equal(orders[0].amount, 41600000);
});
