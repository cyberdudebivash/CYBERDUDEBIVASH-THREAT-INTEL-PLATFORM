// S10 cross-worker revocation certification.
//
// The revenue engine decides entitlement (Razorpay webhooks); intel-gateway
// enforces it on every API call. The only thing the two Workers share is the
// API_KEYS_KV namespace. This suite runs BOTH real Workers against ONE shared
// API_KEYS_KV: revenue-engine handleBillingWebhook() writes it, the real
// intel-gateway router (worker.fetch) reads it. For every lifecycle event it
// proves the customer's API key AND a Bearer JWT the customer obtained
// BEFORE the event (POST /api/auth/login) are denied or restored at the
// gateway immediately -- no 24-hour JWT window.
//
// Every identifier is a TEST-ONLY fixture; webhook signatures are real HMACs.
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";

import { createD1 } from "./helpers/d1-sqlite.js";
import { handleBillingWebhook, revokeEntitlementForSubscription } from "../subscription-engine.js";
import gateway from "../../../intel-gateway/src/index.js";

const WHSEC = "whsec_TEST_ONLY_xworker";
const SUB = "sub_TEST_ONLY_xw";
const EMAIL = "xworker@example.com";
const ctx = { waitUntil() {} };

function fakeKV() {
  const store = new Map();
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
    async list() { return { keys: [], list_complete: true }; },
  };
}

let worlds = 0;

/** One shared API_KEYS_KV; each Worker gets its own other bindings. */
function world() {
  // A distinct client IP per simulated customer: the gateway's per-isolate
  // login throttling must not couple independent tests.
  const ip = `198.51.100.${++worlds}`;
  const API_KEYS_KV = fakeKV();
  const revenue = {
    CRM_DB: createD1(), REVENUE_CRM_KV: fakeKV(), API_KEYS_KV,
    RAZORPAY_KEY_ID: "rzp_test_TEST_ONLY", RAZORPAY_KEY_SECRET: "rzp_secret_TEST_ONLY", RAZORPAY_WEBHOOK_SECRET: WHSEC,
  };
  const gw = {
    API_KEYS_KV, RATE_LIMIT_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt_TEST_ONLY_xworker", ADMIN_SECRET: "admin_TEST_ONLY",
  };
  let n = 0;
  const webhook = async (event, subPatch = {}, extra = {}) => {
    const body = {
      event, account_id: undefined,
      payload: {
        subscription: { entity: { id: SUB, status: event.split(".")[1], current_start: Math.floor(Date.now() / 1000),
          current_end: Math.floor(Date.now() / 1000) + 30 * 86400, notes: { email: EMAIL, tier: "PRO", billing_cycle: "monthly" }, ...subPatch } },
        ...extra,
      },
    };
    const raw = JSON.stringify(body);
    const sig = crypto.createHmac("sha256", WHSEC).update(raw).digest("hex");
    const res = await handleBillingWebhook(new Request("https://intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay", {
      method: "POST", body: raw,
      headers: { "Content-Type": "application/json", "X-Razorpay-Signature": sig, "X-Razorpay-Event-Id": `evt_TEST_ONLY_${++n}` },
    }), revenue, ctx, "rid");
    assert.equal(res.status, 200, `${event} webhook accepted`);
  };
  const call = async (path, headers = {}, init = {}) => {
    const res = await gateway.fetch(new Request(`https://intel.cyberdudebivash.com${path}`, {
      ...init, headers: { "cf-connecting-ip": ip, ...headers },
    }), gw, ctx);
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  const validateKey = async (key) => (await call("/api/auth/validate", { "X-API-Key": key })).body.valid === true;
  const validateJwt = async (jwt) => (await call("/api/auth/validate", { Authorization: `Bearer ${jwt}` })).body.valid === true;
  const login = async (key) => {
    const r = await call("/api/auth/login", { "Content-Type": "application/json" }, { method: "POST", body: JSON.stringify({ api_key: key }) });
    return r.status === 200 ? r.body.token : null;
  };
  const apiKey = () => JSON.parse(revenue.REVENUE_CRM_KV.store.get(`razorpay_sub:${SUB}`)).api_key;
  return { revenue, gw, webhook, validateKey, validateJwt, login, apiKey };
}

async function activeCustomer() {
  const w = world();
  await w.webhook("subscription.activated");
  const key = w.apiKey();
  assert.ok(key, "activation provisioned a key");
  assert.equal(await w.validateKey(key), true, "gateway accepts the key the revenue engine provisioned");
  const jwt = await w.login(key);
  assert.ok(jwt, "gateway issues a JWT for the active key");
  assert.equal(await w.validateJwt(jwt), true);
  return { ...w, key, jwt };
}

test("activation: the revenue engine's key is live at the gateway, for API key and JWT", async () => {
  await activeCustomer();
});

test("refund: key and pre-issued JWT denied at the gateway at once; no new JWT can be obtained", async () => {
  const w = await activeCustomer();
  await revokeEntitlementForSubscription(w.revenue, SUB, "refunded", "rid");
  assert.equal(await w.validateKey(w.key), false, "API key denied");
  assert.equal(await w.validateJwt(w.jwt), false, "JWT issued before the refund denied");
  assert.equal(await w.login(w.key), null, "no fresh JWT for a refunded key");
});

test("halted (renewal failed): key and pre-issued JWT denied at the gateway at once", async () => {
  const w = await activeCustomer();
  await w.webhook("subscription.halted");
  assert.equal(await w.validateKey(w.key), false, "API key denied");
  assert.equal(await w.validateJwt(w.jwt), false, "JWT issued before the halt denied");
  assert.equal(await w.login(w.key), null, "no fresh JWT while halted");
});

let payN = 0;
const captured = () => ({ payment: { entity: {
  id: `pay_TEST_ONLY_${++payN}`, status: "captured", amount: 410000, currency: "INR", created_at: Math.floor(Date.now() / 1000),
} } });

// Owner decision 2026-09-25: a halted subscription reactivates automatically
// on a later captured charge -- the same key, never a second one.
test("halted then a captured charge: the same key and a new JWT work again; the old deny marker is cleared", async () => {
  const w = await activeCustomer();
  await w.webhook("subscription.halted");
  assert.equal(await w.validateKey(w.key), false);
  await w.webhook("subscription.charged", {}, captured());
  assert.equal(w.apiKey(), w.key, "the same key is restored, no second key is issued");
  assert.equal(await w.validateKey(w.key), true, "API key works again");
  const rec = JSON.parse(w.gw.API_KEYS_KV.store.get(w.key));
  assert.equal(rec.subscription_status, "active");
  assert.ok(Date.parse(rec.expires_at) > Date.now() + 20 * 86400e3, "access runs to Razorpay's new period end");
  const jwt2 = await w.login(w.key);
  assert.ok(jwt2, "a new JWT can be obtained");
  assert.equal(await w.validateJwt(jwt2), true, "deny marker cleared");
  assert.equal(JSON.parse(w.revenue.REVENUE_CRM_KV.store.get(`razorpay_sub:${SUB}`)).status, "active");
});

test("halted then subscription.activated with a captured payment: recovery of the same key, not a second provisioning", async () => {
  const w = await activeCustomer();
  const keysBefore = [...w.gw.API_KEYS_KV.store.keys()].filter((k) => !k.startsWith("jwt_deny:")).length;
  await w.webhook("subscription.halted");
  await w.webhook("subscription.activated", {}, captured());
  assert.equal(w.apiKey(), w.key);
  assert.equal(await w.validateKey(w.key), true);
  assert.equal([...w.gw.API_KEYS_KV.store.keys()].filter((k) => !k.startsWith("jwt_deny:")).length, keysBefore, "no new key minted");
});

test("halted then a charge WITHOUT a captured payment: access stays denied", async () => {
  const w = await activeCustomer();
  await w.webhook("subscription.halted");
  await w.webhook("subscription.charged");
  await w.webhook("subscription.charged", {}, { payment: { entity: { id: "pay_TEST_ONLY_failed", status: "failed", amount: 410000, currency: "INR" } } });
  assert.equal(await w.validateKey(w.key), false, "API key stays denied");
  assert.equal(await w.validateJwt(w.jwt), false, "JWT stays denied");
  assert.equal(await w.login(w.key), null);
});

test("refunded or cancelled subscriptions are never revived by a later captured charge", async () => {
  for (const end of ["refund", "subscription.cancelled"]) {
    const w = await activeCustomer();
    await w.webhook("subscription.halted");
    if (end === "refund") await revokeEntitlementForSubscription(w.revenue, SUB, "refunded", "rid");
    else await w.webhook(end);
    await w.webhook("subscription.charged", {}, captured());
    await w.webhook("subscription.activated", {}, captured());
    assert.equal(await w.validateKey(w.key), false, `${end}: API key stays denied`);
    assert.equal(await w.validateJwt(w.jwt), false, `${end}: JWT stays denied`);
    assert.equal(await w.login(w.key), null, `${end}: no new JWT`);
  }
});

test("cancelled / completed at cycle end: key and pre-issued JWT denied at the gateway at once", async () => {
  for (const event of ["subscription.cancelled", "subscription.completed"]) {
    const w = await activeCustomer();
    await w.webhook(event);
    assert.equal(await w.validateKey(w.key), false, `${event}: API key denied`);
    assert.equal(await w.validateJwt(w.jwt), false, `${event}: JWT issued before the end denied`);
    assert.equal(await w.login(w.key), null, `${event}: no fresh JWT`);
  }
});

test("a late charged event after cancellation does not restore access at the gateway", async () => {
  const w = await activeCustomer();
  await w.webhook("subscription.cancelled");
  await w.webhook("subscription.charged");
  assert.equal(await w.validateKey(w.key), false, "API key stays denied");
  assert.equal(await w.validateJwt(w.jwt), false, "JWT stays denied");
});

test("renewal (charged while active) keeps access and never writes a deny marker", async () => {
  const w = await activeCustomer();
  await w.webhook("subscription.charged");
  assert.equal(await w.validateKey(w.key), true);
  assert.equal(await w.validateJwt(w.jwt), true);
  assert.equal([...w.gw.API_KEYS_KV.store.keys()].some((k) => k.startsWith("jwt_deny:")), false);
});

test("pending (payment retrying) keeps access: past_due is a grace state, not a deny state", async () => {
  const w = await activeCustomer();
  await w.webhook("subscription.pending");
  assert.equal(await w.validateKey(w.key), true);
  assert.equal(await w.validateJwt(w.jwt), true);
});

test("contract: each terminal event writes its own status, and the gateway classes every one as a deny state", async () => {
  // Both deny mechanisms must agree: the key's status (not only its expiry)
  // is a gateway deny state, so neither side can drift silently.
  const { SUBSCRIPTION_STATUS_VALID_STATES, SUBSCRIPTION_STATUS_DENY_STATES, evaluateKeyRecordAccess } =
    await import("../../../intel-gateway/src/subscription-lifecycle.js");
  const cases = [
    ["subscription.halted", "suspended"],
    ["subscription.cancelled", "cancelled"],
    ["subscription.completed", "cancelled"],
    ["refund", "refunded"],
  ];
  for (const [event, expected] of cases) {
    const w = await activeCustomer();
    if (event === "refund") await revokeEntitlementForSubscription(w.revenue, SUB, "refunded", "rid");
    else await w.webhook(event);
    const rec = JSON.parse(w.gw.API_KEYS_KV.store.get(w.key));
    assert.equal(rec.subscription_status, expected, `${event} writes '${expected}'`);
    assert.ok(SUBSCRIPTION_STATUS_VALID_STATES.has(expected), `gateway recognises '${expected}'`);
    assert.ok(SUBSCRIPTION_STATUS_DENY_STATES.has(expected), `gateway denies '${expected}'`);
    // Independent of the expiry: the status alone denies.
    assert.equal(evaluateKeyRecordAccess({ ...rec, expires_at: null }).allowed, false, `${event}: status alone denies`);
    const customerId = rec.customer_id;
    assert.ok(w.gw.API_KEYS_KV.store.has(`jwt_deny:${customerId}`), `${event}: jwt_deny written for ${customerId}`);
  }
  // A non-terminal event writes no gateway status at all.
  const w = await activeCustomer();
  await w.webhook("subscription.pending");
  assert.equal(JSON.parse(w.gw.API_KEYS_KV.store.get(w.key)).subscription_status, undefined);
});

test("refund then Razorpay's cancellation: the key keeps 'refunded' and stays denied", async () => {
  const w = await activeCustomer();
  await revokeEntitlementForSubscription(w.revenue, SUB, "refunded", "rid");
  await w.webhook("subscription.cancelled");
  assert.equal(JSON.parse(w.gw.API_KEYS_KV.store.get(w.key)).subscription_status, "refunded");
  assert.equal(await w.validateKey(w.key), false);
  assert.equal(await w.validateJwt(w.jwt), false);
});

test("a key refunded or cancelled at the gateway (admin) is not revived by a halted subscription's recovery", async () => {
  for (const status of ["refunded", "cancelled"]) {
    const w = await activeCustomer();
    await w.webhook("subscription.halted");
    // Gateway-side decision (PATCH /api/admin/keys/{key}/status) while the
    // revenue engine still holds the subscription as halted.
    const rec = JSON.parse(w.gw.API_KEYS_KV.store.get(w.key));
    w.gw.API_KEYS_KV.store.set(w.key, JSON.stringify({ ...rec, subscription_status: status }));
    await w.webhook("subscription.charged", {}, captured());
    assert.equal(JSON.parse(w.gw.API_KEYS_KV.store.get(w.key)).subscription_status, status, `${status} label kept`);
    assert.equal(await w.validateKey(w.key), false, `${status}: API key stays denied`);
    assert.equal(await w.login(w.key), null, `${status}: no new JWT`);
  }
});
