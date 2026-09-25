import assert from "node:assert/strict";
import crypto from "node:crypto";
import { test } from "node:test";
import { handleBillingWebhook, handleBillingSubscriptionStatus } from "../subscription-engine.js";

// ---------------------------------------------------------------------------
// Phase 2 (Razorpay Subscriptions): coverage for handleBillingWebhook(), the
// single entry point that turns a Razorpay webhook delivery into an
// entitlement change on a real customer's API key. No network calls -- KV is
// faked in-memory; the HMAC signature is computed with the same algorithm
// verifyRazorpayHmac() checks against (HMAC-SHA256 hex digest), so signature
// verification runs for real rather than being bypassed.
// ---------------------------------------------------------------------------

// Matches real Cloudflare KV .get(key, type) semantics for both call forms
// used in this codebase: the string shorthand ("json") subscription-engine.js
// actually uses, and the {type} object form. A fake that only understood one
// form would silently misreport pass/fail here.
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
    async put(key, value) {
      store.set(key, typeof value === "string" ? value : JSON.stringify(value));
    },
    async delete(key) {
      store.delete(key);
    },
  };
}

function signedRequest(bodyObj, { secret = "whsec_test", eventId } = {}) {
  const raw = JSON.stringify(bodyObj);
  const sig = crypto.createHmac("sha256", secret).update(raw).digest("hex");
  const headers = { "Content-Type": "application/json", "X-Razorpay-Signature": sig };
  if (eventId) headers["X-Razorpay-Event-Id"] = eventId;
  return new Request("https://revenue.intel.cyberdudebivash.com/api/v2/billing/webhooks/razorpay", {
    method: "POST", headers, body: raw,
  });
}

function chargedPayload({ providerId, currentStart = 1767225600, currentEnd = 1769904000, paymentId }) {
  return {
    event: "subscription.charged",
    payload: {
      subscription: { entity: { id: providerId, current_start: currentStart, current_end: currentEnd, notes: {} } },
      payment: { entity: { id: paymentId } },
    },
  };
}

test("handleBillingWebhook: missing RAZORPAY_WEBHOOK_SECRET fails closed with 500, not a crash", async () => {
  const env = { REVENUE_CRM_KV: fakeKV(), API_KEYS_KV: fakeKV() };
  const req = new Request("https://x.test/api/v2/billing/webhooks/razorpay", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  const res = await handleBillingWebhook(req, env, {}, "rid_test");
  assert.equal(res.status, 500);
});

test("handleBillingWebhook: invalid signature is rejected with 401 and writes no subscription/provider-link record", async () => {
  const env = { REVENUE_CRM_KV: fakeKV(), API_KEYS_KV: fakeKV(), RAZORPAY_WEBHOOK_SECRET: "whsec_test" };
  const req = new Request("https://x.test/api/v2/billing/webhooks/razorpay", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Razorpay-Signature": "00".repeat(32) },
    body: JSON.stringify({ event: "subscription.charged", payload: {} }),
  });
  const res = await handleBillingWebhook(req, env, {}, "rid_test");
  assert.equal(res.status, 401);
  // A rejected signature still legitimately logs a telemetry counter
  // (events:{day}:subscription_webhook_sig_fail) -- that's audit trail, not
  // a bug. What must NOT happen is any sub:/razorpay_sub: record appearing.
  const keys = [...env.REVENUE_CRM_KV.store.keys()];
  assert.ok(keys.every(k => !k.startsWith("sub:") && !k.startsWith("razorpay_sub:")), `unexpected record keys: ${keys}`);
  assert.equal(env.API_KEYS_KV.store.size, 0);
});

test("handleBillingWebhook: subscription.charged for an already-CANCELLED subscription must not restore API key access", async () => {
  // Reproduces a real Razorpay delivery pattern this handler explicitly
  // anticipates elsewhere (idempotency claiming, out-of-order safety): a
  // customer cancels, the internal record correctly moves to CANCELLED and
  // the key is expired -- then a stale/delayed "subscription.charged" event
  // for a charge that was already in flight before the cancellation lands
  // afterward. tryTransition() correctly refuses cancelled -> active and
  // leaves sub:isub_1 untouched (that part already works). The bug: the two
  // *other* effects of this branch -- extending the live API key's
  // expires_at and flipping the provider link back to "active" -- ran
  // unconditionally, undoing the cancellation through a side door even
  // though the authoritative record correctly rejected it.
  const env = {
    REVENUE_CRM_KV: fakeKV({
      "sub:isub_1": {
        id: "isub_1", email: "cancelled@customer.test", tier: "PRO", status: "cancelled",
        billing_cycle: "monthly", cancelled_at: "2026-08-01T00:00:00.000Z",
      },
      "razorpay_sub:rzp_sub_1": {
        razorpay_subscription_id: "rzp_sub_1", email: "cancelled@customer.test", tier: "PRO",
        billing_cycle: "monthly", status: "cancelled", internal_sub_id: "isub_1",
        internal_customer_id: "cust_1", api_key: "sk_live_test1",
      },
    }),
    API_KEYS_KV: fakeKV({
      "sk_live_test1": { tier: "PRO", customer_id: "cust_1", expires_at: "2026-08-01T00:00:00.000Z" },
    }),
    RAZORPAY_WEBHOOK_SECRET: "whsec_test",
  };

  const req = signedRequest(
    chargedPayload({ providerId: "rzp_sub_1", paymentId: "pay_late_1" }),
    { eventId: "evt_late_charge_1" }
  );
  const res = await handleBillingWebhook(req, env, {}, "rid_test");
  assert.equal(res.status, 200);

  const subAfter = await env.REVENUE_CRM_KV.get("sub:isub_1", "json");
  assert.equal(subAfter.status, "cancelled", "internal subscription record must stay cancelled");

  const keyAfter = await env.API_KEYS_KV.get("sk_live_test1", "json");
  assert.equal(
    keyAfter.expires_at, "2026-08-01T00:00:00.000Z",
    "a late/out-of-order charge event for a cancelled subscription must not extend API key access"
  );

  const linkAfter = await env.REVENUE_CRM_KV.get("razorpay_sub:rzp_sub_1", "json");
  assert.equal(linkAfter.status, "cancelled", "provider link must not be flipped back to active for a rejected transition");
});

test("handleBillingWebhook: subscription.charged for an ACTIVE subscription renews normally", async () => {
  const env = {
    REVENUE_CRM_KV: fakeKV({
      "sub:isub_2": {
        id: "isub_2", email: "paying@customer.test", tier: "PRO", status: "active",
        billing_cycle: "monthly", renewal_count: 2,
      },
      "razorpay_sub:rzp_sub_2": {
        razorpay_subscription_id: "rzp_sub_2", email: "paying@customer.test", tier: "PRO",
        billing_cycle: "monthly", status: "active", internal_sub_id: "isub_2",
        api_key: "sk_live_test2", renewal_count: 2,
      },
    }),
    API_KEYS_KV: fakeKV({
      "sk_live_test2": { tier: "PRO", customer_id: "cust_2", expires_at: "2026-08-01T00:00:00.000Z" },
    }),
    RAZORPAY_WEBHOOK_SECRET: "whsec_test",
  };

  const req = signedRequest(
    chargedPayload({ providerId: "rzp_sub_2", paymentId: "pay_ontime_1" }),
    { eventId: "evt_ontime_1" }
  );
  const res = await handleBillingWebhook(req, env, {}, "rid_test");
  assert.equal(res.status, 200);

  const expectedExpiry = new Date(1769904000 * 1000).toISOString();

  const subAfter = await env.REVENUE_CRM_KV.get("sub:isub_2", "json");
  assert.equal(subAfter.status, "active");
  assert.equal(subAfter.renewal_count, 3);
  assert.equal(subAfter.current_period_end, expectedExpiry);

  const keyAfter = await env.API_KEYS_KV.get("sk_live_test2", "json");
  assert.equal(keyAfter.expires_at, expectedExpiry, "a valid renewal must extend the live API key's expiry");

  const linkAfter = await env.REVENUE_CRM_KV.get("razorpay_sub:rzp_sub_2", "json");
  assert.equal(linkAfter.status, "active");
  assert.equal(linkAfter.renewal_count, 3);
});

test("handleBillingWebhook: a delayed/out-of-order charged event with an OLDER period end must not regress a paying customer's expiry", async () => {
  // ACTIVE -> ACTIVE is a valid self-transition (an ordinary renewal), so
  // tryTransition() alone doesn't catch this: Razorpay's webhook delivery
  // is at-least-once and NOT ordering-guaranteed, so an earlier charge's
  // event can arrive after a later charge's event already recorded a newer
  // current_period_end. Applying the stale (older) value would push the
  // live API key's expires_at backward -- silently locking out a customer
  // who has already paid through the later date.
  const NEWER_END = 1780000000; // already recorded, further in the future
  const OLDER_END = 1769904000; // this delayed event's (stale) current_end
  const newerIso = new Date(NEWER_END * 1000).toISOString();

  const env = {
    REVENUE_CRM_KV: fakeKV({
      "sub:isub_4": {
        id: "isub_4", email: "paying2@customer.test", tier: "PRO", status: "active",
        billing_cycle: "monthly", renewal_count: 5, current_period_end: newerIso,
      },
      "razorpay_sub:rzp_sub_4": {
        razorpay_subscription_id: "rzp_sub_4", email: "paying2@customer.test", tier: "PRO",
        billing_cycle: "monthly", status: "active", internal_sub_id: "isub_4",
        api_key: "sk_live_test4", renewal_count: 5, current_period_end: newerIso,
      },
    }),
    API_KEYS_KV: fakeKV({
      "sk_live_test4": { tier: "PRO", customer_id: "cust_4", expires_at: newerIso },
    }),
    RAZORPAY_WEBHOOK_SECRET: "whsec_test",
  };

  const req = signedRequest(
    chargedPayload({ providerId: "rzp_sub_4", paymentId: "pay_delayed_1", currentEnd: OLDER_END }),
    { eventId: "evt_delayed_1" }
  );
  const res = await handleBillingWebhook(req, env, {}, "rid_test");
  assert.equal(res.status, 200);

  const subAfter = await env.REVENUE_CRM_KV.get("sub:isub_4", "json");
  assert.equal(subAfter.current_period_end, newerIso, "must keep the later period end, not the stale delayed one");

  const keyAfter = await env.API_KEYS_KV.get("sk_live_test4", "json");
  assert.equal(keyAfter.expires_at, newerIso, "a delayed event must not push a paying customer's key expiry backward");

  const linkAfter = await env.REVENUE_CRM_KV.get("razorpay_sub:rzp_sub_4", "json");
  assert.equal(linkAfter.current_period_end, newerIso);
});

test("handleBillingWebhook: redelivery of the same event id is not reprocessed (Razorpay is at-least-once)", async () => {
  const env = {
    REVENUE_CRM_KV: fakeKV({
      "sub:isub_3": { id: "isub_3", email: "dup@customer.test", tier: "PRO", status: "active", billing_cycle: "monthly", renewal_count: 0 },
      "razorpay_sub:rzp_sub_3": { razorpay_subscription_id: "rzp_sub_3", email: "dup@customer.test", tier: "PRO", billing_cycle: "monthly", status: "active", internal_sub_id: "isub_3", api_key: "sk_live_test3", renewal_count: 0 },
    }),
    API_KEYS_KV: fakeKV({ "sk_live_test3": { tier: "PRO", customer_id: "cust_3", expires_at: "2026-08-01T00:00:00.000Z" } }),
    RAZORPAY_WEBHOOK_SECRET: "whsec_test",
  };

  const payload = chargedPayload({ providerId: "rzp_sub_3", paymentId: "pay_dup_1" });
  const res1 = await handleBillingWebhook(signedRequest(payload, { eventId: "evt_dup_1" }), env, {}, "rid1");
  assert.equal(res1.status, 200);

  const res2 = await handleBillingWebhook(signedRequest(payload, { eventId: "evt_dup_1" }), env, {}, "rid2");
  assert.equal(res2.status, 200);
  const body2 = await res2.json();
  assert.equal(body2.status, "already_processed");

  const subAfter = await env.REVENUE_CRM_KV.get("sub:isub_3", "json");
  assert.equal(subAfter.renewal_count, 1, "a redelivered event must not increment renewal_count a second time");
});

test("handleBillingWebhook: subscription.charged with no provider link logs an anomaly and does not throw", async () => {
  const env = { REVENUE_CRM_KV: fakeKV(), API_KEYS_KV: fakeKV(), RAZORPAY_WEBHOOK_SECRET: "whsec_test" };
  const req = signedRequest(
    chargedPayload({ providerId: "rzp_sub_unknown", paymentId: "pay_orphan_1" }),
    { eventId: "evt_orphan_1" }
  );
  const res = await handleBillingWebhook(req, env, {}, "rid_test");
  assert.equal(res.status, 200);
});

// ---------------------------------------------------------------------------
// GET /api/v2/billing/subscriptions/status -- the checkout page polls this
// after Razorpay Checkout's handler fires, since subscription activation is
// webhook-driven (async), unlike the one-time-order flow's synchronous
// /verify call.
// ---------------------------------------------------------------------------

const KEY_SECRET = "key_secret_test";

// Mirrors Razorpay's own signature formula for a subscription checkout
// completion: HMAC_SHA256(payment_id + "|" + subscription_id, key_secret).
// verifyRazorpayHmac() (subscription-engine.js) checks against exactly this.
function statusSignature(paymentId, subscriptionId, secret = KEY_SECRET) {
  return crypto.createHmac("sha256", secret).update(`${paymentId}|${subscriptionId}`).digest("hex");
}

function statusRequest({ subscriptionId, paymentId = "pay_test1", signature } = {}) {
  const params = new URLSearchParams();
  if (subscriptionId !== undefined) params.set("subscription_id", subscriptionId);
  if (paymentId !== undefined) params.set("payment_id", paymentId);
  const sig = signature !== undefined ? signature
    : (subscriptionId !== undefined && paymentId !== undefined ? statusSignature(paymentId, subscriptionId) : undefined);
  if (sig !== undefined) params.set("signature", sig);
  return new Request(`https://x.test/api/v2/billing/subscriptions/status?${params.toString()}`, { method: "GET" });
}

test("handleBillingSubscriptionStatus: missing subscription_id is a 400, not a crash", async () => {
  const env = { REVENUE_CRM_KV: fakeKV(), RAZORPAY_KEY_SECRET: KEY_SECRET };
  const res = await handleBillingSubscriptionStatus(statusRequest({}), env, {}, "rid_test");
  assert.equal(res.status, 400);
});

test("handleBillingSubscriptionStatus: missing payment_id/signature is a 400", async () => {
  const env = { REVENUE_CRM_KV: fakeKV(), RAZORPAY_KEY_SECRET: KEY_SECRET };
  const res = await handleBillingSubscriptionStatus(
    new Request("https://x.test/api/v2/billing/subscriptions/status?subscription_id=rzp_sub_live", { method: "GET" }),
    env, {}, "rid_test"
  );
  assert.equal(res.status, 400);
});

test("handleBillingSubscriptionStatus: an invalid signature is rejected with 401, never reaches the KV lookup", async () => {
  const env = { REVENUE_CRM_KV: fakeKV(), RAZORPAY_KEY_SECRET: KEY_SECRET };
  const res = await handleBillingSubscriptionStatus(
    statusRequest({ subscriptionId: "rzp_sub_live", paymentId: "pay_test1", signature: "00".repeat(32) }),
    env, {}, "rid_test"
  );
  assert.equal(res.status, 401);
});

test("handleBillingSubscriptionStatus: IDOR -- knowing only another customer's subscription_id cannot retrieve its api_key", async () => {
  // Reproduces CodeRabbit's finding: subscription_id is not a secret (the
  // browser holds it, Razorpay's own Checkout widget receives it) -- an
  // attacker's real-world position is "I have victim's subscription_id" and
  // nothing else. Without RAZORPAY_KEY_SECRET (server-only, never sent to
  // any client), they cannot produce a signature that verifies for it, so a
  // guessed/copied signature must be rejected before the KV lookup ever
  // returns victim's record.
  const env = {
    REVENUE_CRM_KV: fakeKV({
      "razorpay_sub:rzp_sub_victim": {
        razorpay_subscription_id: "rzp_sub_victim", email: "victim@customer.test",
        tier: "ENTERPRISE", billing_cycle: "annual", status: "active", api_key: "sk_live_victim_key",
      },
    }),
    RAZORPAY_KEY_SECRET: KEY_SECRET,
  };
  const res = await handleBillingSubscriptionStatus(
    statusRequest({ subscriptionId: "rzp_sub_victim", paymentId: "pay_attacker_guess", signature: "deadbeef".repeat(8) }),
    env, {}, "rid_test"
  );
  assert.equal(res.status, 401);
});

test("handleBillingSubscriptionStatus: unknown subscription_id is a 404", async () => {
  const env = { REVENUE_CRM_KV: fakeKV(), RAZORPAY_KEY_SECRET: KEY_SECRET };
  const res = await handleBillingSubscriptionStatus(statusRequest({ subscriptionId: "rzp_sub_never_seen" }), env, {}, "rid_test");
  assert.equal(res.status, 404);
});

test("handleBillingSubscriptionStatus: 'created' (not yet paid) status never includes an api_key", async () => {
  const env = {
    REVENUE_CRM_KV: fakeKV({
      "razorpay_sub:rzp_sub_pending": {
        razorpay_subscription_id: "rzp_sub_pending", email: "waiting@customer.test",
        tier: "PRO", billing_cycle: "monthly", status: "created",
      },
    }),
    RAZORPAY_KEY_SECRET: KEY_SECRET,
  };
  const res = await handleBillingSubscriptionStatus(statusRequest({ subscriptionId: "rzp_sub_pending" }), env, {}, "rid_test");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, "created");
  assert.equal(body.api_key, undefined, "no key must be handed out before the subscription is actually active");
});

test("handleBillingSubscriptionStatus: 'active' status includes the provisioned api_key", async () => {
  const env = {
    REVENUE_CRM_KV: fakeKV({
      "razorpay_sub:rzp_sub_live": {
        razorpay_subscription_id: "rzp_sub_live", email: "paid@customer.test",
        tier: "ENTERPRISE", billing_cycle: "annual", status: "active", api_key: "sk_live_abc123",
      },
    }),
    RAZORPAY_KEY_SECRET: KEY_SECRET,
  };
  const res = await handleBillingSubscriptionStatus(statusRequest({ subscriptionId: "rzp_sub_live" }), env, {}, "rid_test");
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body, { status: "active", tier: "ENTERPRISE", billing_cycle: "annual", api_key: "sk_live_abc123" });
});
