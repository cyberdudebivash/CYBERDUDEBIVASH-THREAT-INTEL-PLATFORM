import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluateKeyRecordAccess } from "../subscription-lifecycle.js";

// ---------------------------------------------------------------------------
// Mission v185.0 Phase 1/3: unit coverage for the normalized subscription
// lifecycle decision function. evaluateKeyRecordAccess() is the single
// pure function resolveAuth() (index.js) delegates to. Imported directly
// from subscription-lifecycle.js (not index.js) -- a small dependency-free
// module extracted in v185.6 specifically so this file can run under plain
// `node --test` without pulling in index.js's full import chain (which
// transitively fails Node's native ESM loader via pricing.js's
// pricing-data.json import -- see subscription-lifecycle.js's header
// comment for the full explanation). No KV, no network, no Cloudflare-
// specific globals either way -- this was always a pure-function test.
// ---------------------------------------------------------------------------

test("a record with no expires_at and no subscription_status is allowed (pre-v185.5 key shape)", () => {
  const result = evaluateKeyRecordAccess({ tier: "PRO", customer_id: "old@customer.test" });
  assert.equal(result.allowed, true);
  assert.equal(result.error, null);
});

test("a record with subscription_status: 'active' is allowed", () => {
  const result = evaluateKeyRecordAccess({ subscription_status: "active" });
  assert.equal(result.allowed, true);
});

test("a record with subscription_status: 'past_due' is allowed (grace period, not a deny state)", () => {
  const result = evaluateKeyRecordAccess({ subscription_status: "past_due" });
  assert.equal(result.allowed, true, "past_due must not deny -- Mission Phase 3 does not require immediate denial on payment failure");
});

for (const denyState of ["cancelled", "refunded", "suspended", "expired"]) {
  test(`a record with subscription_status: '${denyState}' is denied`, () => {
    const result = evaluateKeyRecordAccess({ subscription_status: denyState });
    assert.equal(result.allowed, false);
    assert.equal(result.error, `subscription_${denyState}`);
  });
}

test("an unrecognized subscription_status string fails closed, not open", () => {
  const result = evaluateKeyRecordAccess({ subscription_status: "totally_made_up_status" });
  assert.equal(result.allowed, false, "Mission Phase 1: unknown state must fail closed");
  assert.equal(result.error, "subscription_status_invalid");
});

test("a revoked key is rejected even when the subscription record is active, past_due or legacy", () => {
  for (const subscription_status of [undefined, "active", "past_due"]) {
    const record = { tier: "PRO", status: "revoked" };
    if (subscription_status) record.subscription_status = subscription_status;
    assert.deepEqual(evaluateKeyRecordAccess(record),
      { allowed: false, error: "key_revoked" }, String(subscription_status));
  }
});

test("valid legacy key status and past_due subscription preserve customer access", () => {
  for (const record of [
    { tier: "PRO", status: "active" },
    { tier: "PRO", status: "active", subscription_status: "past_due" },
    { tier: "PRO", subscription_status: "active" },
  ]) assert.equal(evaluateKeyRecordAccess(record).allowed, true);
});

test("expired revoked key retains canonical expiry error precedence", () => {
  assert.equal(evaluateKeyRecordAccess({
    status: "revoked", expires_at: new Date(Date.now() - 60000).toISOString(),
  }).error, "key_expired");
});

test("expires_at in the past denies regardless of subscription_status being active", () => {
  const result = evaluateKeyRecordAccess({
    subscription_status: "active",
    expires_at: new Date(Date.now() - 86400000).toISOString(),
  });
  assert.equal(result.allowed, false);
  assert.equal(result.error, "key_expired");
});

test("expires_at check runs before subscription_status check (expired wins as the more specific reason)", () => {
  // Both conditions are independently denying here; asserting the exact
  // error confirms which one resolveAuth() will actually surface/log.
  const result = evaluateKeyRecordAccess({
    subscription_status: "cancelled",
    expires_at: new Date(Date.now() - 86400000).toISOString(),
  });
  assert.equal(result.error, "key_expired");
});

test("expires_at in the future does not deny", () => {
  const result = evaluateKeyRecordAccess({
    expires_at: new Date(Date.now() + 86400000).toISOString(),
  });
  assert.equal(result.allowed, true);
});

test("expires_at: null (shadow-mode default when SUBSCRIPTION_EXPIRY_ENABLED=false) never denies", () => {
  const result = evaluateKeyRecordAccess({ expires_at: null, subscription_status: "active" });
  assert.equal(result.allowed, true);
});
