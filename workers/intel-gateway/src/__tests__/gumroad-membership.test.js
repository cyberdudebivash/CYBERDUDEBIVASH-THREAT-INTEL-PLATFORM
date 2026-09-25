/**
 * Gumroad memberships (owner commercial policy, 2026-09-25): recurring
 * services are sold as recurring memberships. Gumroad posts a "sale" ping for
 * every membership charge (new sale_id, same subscription_id,
 * is_recurring_charge), and pings again with refunded / disputed.
 *
 *   - a renewal extends the membership's existing key, never mints a second
 *   - a redelivered renewal extends once
 *   - a refund / dispute of any sale ends that entitlement (the ping reuses
 *     the sale_id, so it must not be swallowed by sale idempotency)
 *   - a charge never silently reactivates a refunded or suspended key
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import worker from "../index.js";
import { classifyGumroadPing, renewedExpiry, renewalMayReactivate, BILLING_CYCLE_DAYS } from "../gumroad-lifecycle.js";

const SECRET = "gumroad-test-secret";

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
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  const env = {
    INTEL_R2: { get: async () => null },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(),
    ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
    GUMROAD_WEBHOOK_SECRET: SECRET, SUBSCRIPTION_EXPIRY_ENABLED: "true",
  };
  const ping = async (fields) => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () => new Response("{}", { status: 200 });
    const waits = [];
    try {
      const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com/api/webhooks/gumroad?secret=${SECRET}`, {
        method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(fields).toString(),
      }), env, { waitUntil: (p) => waits.push(p) });
      await Promise.allSettled(waits);
      return { res, body: await res.json() };
    } finally {
      globalThis.fetch = realFetch;
    }
  };
  const keys = () => [...env.API_KEYS_KV.store.keys()];
  const record = (k) => JSON.parse(env.API_KEYS_KV.store.get(k));
  return { env, ping, keys, record };
}

const FIRST = {
  sale_id: "s_1", email: "buyer@example.com", product_name: "SENTINEL APEX PRO Membership", permalink: "pxyfcb",
  price: "4900", subscription_id: "sub_G1", recurrence: "monthly", sale_timestamp: "2026-09-01T00:00:00Z",
};
const RENEWAL = { ...FIRST, sale_id: "s_2", is_recurring_charge: "true", sale_timestamp: "2026-10-01T00:00:00Z" };

// --- pure rules ---------------------------------------------------------------

test("ping classification: money-back first, then cancellation, renewal, sale", () => {
  assert.equal(classifyGumroadPing({ ...RENEWAL, refunded: "true" }), "refund");
  assert.equal(classifyGumroadPing({ ...FIRST, disputed: "true" }), "dispute");
  assert.equal(classifyGumroadPing({ ...FIRST, disputed: "true", dispute_won: "true" }), "sale", "a won dispute is not a revocation");
  assert.equal(classifyGumroadPing({ subscription_id: "x", cancelled: "true" }), "cancellation");
  assert.equal(classifyGumroadPing(RENEWAL), "renewal");
  assert.equal(classifyGumroadPing(FIRST), "sale");
});

test("renewed expiry: one cycle from the later of current expiry and charge time", () => {
  const early = renewedExpiry("2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z", "monthly");
  assert.equal(early, new Date(Date.parse("2026-10-02T00:00:00Z") + 30 * 86400000).toISOString(), "no paid time lost");
  const lapsed = renewedExpiry("2026-09-01T00:00:00Z", "2026-10-15T00:00:00Z", "annual");
  assert.equal(lapsed, new Date(Date.parse("2026-10-15T00:00:00Z") + 365 * 86400000).toISOString(), "no backdated period");
  assert.equal(BILLING_CYCLE_DAYS.monthly, 30);
  assert.equal(renewalMayReactivate("cancelled"), true);
  assert.equal(renewalMayReactivate("refunded"), false);
  assert.equal(renewalMayReactivate("suspended"), false);
});

// --- webhook ------------------------------------------------------------------

test("first membership sale provisions one key mapped by subscription and sale", async () => {
  const h = harness();
  const { body } = await h.ping(FIRST);
  assert.equal(body.status, "provisioned");
  assert.equal(h.keys().length, 1);
  const key = h.keys()[0];
  assert.equal(h.env.SECURITY_HUB_KV.store.get("gumroad_sub_key_map:sub_G1"), key);
  assert.equal(h.env.SECURITY_HUB_KV.store.get("gumroad_sale_key_map:s_1"), key);
});

test("a renewal charge extends the same key; redelivery extends once", async () => {
  const h = harness();
  await h.ping(FIRST);
  const key = h.keys()[0];
  const before = h.record(key).expires_at;
  const r1 = await h.ping(RENEWAL);
  assert.equal(r1.body.status, "renewed");
  assert.equal(h.keys().length, 1, "no second key minted");
  const after = h.record(key).expires_at;
  assert.equal(after, renewedExpiry(before, RENEWAL.sale_timestamp, "monthly"));
  const r2 = await h.ping(RENEWAL);
  assert.equal(r2.body.status, "already_provisioned");
  assert.equal(h.record(key).expires_at, after, "extended exactly once");
  assert.equal(h.env.SECURITY_HUB_KV.store.get("gumroad_sale_key_map:s_2"), key);
});

test("a renewal without is_recurring_charge is still recognised by its subscription", async () => {
  const h = harness();
  await h.ping(FIRST);
  const { body } = await h.ping({ ...FIRST, sale_id: "s_3", sale_timestamp: "2026-10-01T00:00:00Z" });
  assert.equal(body.status, "renewed");
  assert.equal(h.keys().length, 1);
});

test("a restarted (ended) membership that charges again is active again", async () => {
  const h = harness();
  await h.ping(FIRST);
  const key = h.keys()[0];
  await h.ping({ subscription_id: "sub_G1", ended: "true" });
  assert.equal(h.record(key).subscription_status, "cancelled");
  const { body } = await h.ping(RENEWAL);
  assert.equal(body.status, "renewed");
  assert.equal(h.record(key).subscription_status, "active");
});

test("a charge on a refunded key does not restore access", async () => {
  const h = harness();
  await h.ping(FIRST);
  const key = h.keys()[0];
  await h.ping({ ...FIRST, refunded: "true" });
  const { body } = await h.ping(RENEWAL);
  assert.equal(body.status, "renewal_requires_review");
  assert.equal(h.record(key).subscription_status, "refunded");
});

test("a refund ping reusing the sale_id revokes access (not swallowed as already provisioned)", async () => {
  const h = harness();
  await h.ping(FIRST);
  const key = h.keys()[0];
  const { body } = await h.ping({ ...FIRST, refunded: "true" });
  assert.equal(body.status, "refunded");
  assert.equal(h.record(key).subscription_status, "refunded");
});

test("refunding a renewal charge revokes the membership's key", async () => {
  const h = harness();
  await h.ping(FIRST);
  await h.ping(RENEWAL);
  const key = h.keys()[0];
  const { body } = await h.ping({ ...RENEWAL, refunded: "true" });
  assert.equal(body.status, "refunded");
  assert.equal(h.record(key).subscription_status, "refunded");
});

test("a chargeback suspends access; a won dispute changes nothing", async () => {
  const h = harness();
  await h.ping(FIRST);
  const key = h.keys()[0];
  const won = await h.ping({ ...FIRST, disputed: "true", dispute_won: "true" });
  assert.equal(won.body.status, "already_provisioned");
  assert.equal(h.record(key).subscription_status, undefined);
  const lost = await h.ping({ ...FIRST, disputed: "true" });
  assert.equal(lost.body.status, "suspended");
  assert.equal(h.record(key).subscription_status, "suspended");
});

test("cancelling keeps access to the end of the period; ending revokes (unchanged)", async () => {
  const h = harness();
  await h.ping(FIRST);
  const key = h.keys()[0];
  const c = await h.ping({ subscription_id: "sub_G1", cancelled: "true" });
  assert.equal(c.body.status, "cancellation_recorded");
  assert.equal(h.record(key).subscription_status, undefined);
  const e = await h.ping({ subscription_id: "sub_G1", ended: "true" });
  assert.equal(e.body.status, "cancelled");
});

test("a renewal with no usable mapping still gives the paying customer access", async () => {
  const h = harness();
  const { body } = await h.ping({ ...RENEWAL, subscription_id: "sub_unknown" });
  assert.equal(body.status, "provisioned");
  assert.equal(h.keys().length, 1);
});

test("a refund for an unknown sale is flagged, not ignored", async () => {
  const h = harness();
  const { body } = await h.ping({ ...FIRST, sale_id: "s_legacy", subscription_id: "", refunded: "true" });
  assert.equal(body.status, "noted_no_mapping");
});
