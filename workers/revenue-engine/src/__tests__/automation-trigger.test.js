import assert from "node:assert/strict";
import { test } from "node:test";
import { automationTrigger } from "../index.js";

// ---------------------------------------------------------------------------
// POST /api/automation/trigger had no authentication at all: any external
// caller could POST an arbitrary `email` and fire any of its seven trigger
// cases, relaying email to any address through this platform's own SendGrid
// sending reputation with no rate limit. Found while wiring intel-gateway's
// new daily-quota 80% alert into this endpoint. The only file that ever
// called it (revenue-crm/frontend-injection.js) is never actually included
// in any real page, so there was no live legitimate caller to preserve.
// ---------------------------------------------------------------------------

function triggerRequest(body, { adminSecret } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (adminSecret !== undefined) headers["X-Admin-Secret"] = adminSecret;
  return new Request("https://revenue.intel.cyberdudebivash.com/api/automation/trigger", {
    method: "POST", headers, body: JSON.stringify(body),
  });
}

function fakeEnv() {
  return { REVENUE_ADMIN_SECRET: "test_admin_secret", REVENUE_CRM_KV: fakeKV(), EMAIL_QUEUE_KV: fakeKV() };
}

test("automationTrigger: an unauthenticated request is rejected with 401, no email queued", async () => {
  const env = fakeEnv();
  const res = await automationTrigger(
    triggerRequest({ trigger: "usage_100pct", email: "victim@example.com" }),
    env, "rid_test"
  );
  assert.equal(res.status, 401);
  assert.equal(env.EMAIL_QUEUE_KV.store.size, 0, "no email should be queued for an unauthenticated request");
});

test("automationTrigger: an incorrect X-Admin-Secret is rejected with 401, no email queued", async () => {
  const env = fakeEnv();
  const res = await automationTrigger(
    triggerRequest({ trigger: "usage_100pct", email: "victim@example.com" }, { adminSecret: "wrong_secret" }),
    env, "rid_test"
  );
  assert.equal(res.status, 401);
  assert.equal(env.EMAIL_QUEUE_KV.store.size, 0);
});

test("automationTrigger: the correct X-Admin-Secret is accepted and queues the email", async () => {
  const env = fakeEnv();
  const res = await automationTrigger(
    triggerRequest({ trigger: "usage_80pct", email: "real-customer@example.com", context: "api" }, { adminSecret: "test_admin_secret" }),
    env, "rid_test"
  );
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, "triggered");
  assert.equal(env.EMAIL_QUEUE_KV.store.size, 1, "the email must actually be queued once authorized");
});

test("automationTrigger: authenticated request with unbound email queue returns 503, not triggered", async () => {
  const env = fakeEnv();
  delete env.EMAIL_QUEUE_KV;
  const res = await automationTrigger(
    triggerRequest({ trigger: "usage_80pct", email: "customer@example.test" },
      { adminSecret: "test_admin_secret" }),
    env, "rid_test"
  );
  assert.equal(res.status, 503);
  assert.deepEqual(await res.json(), { error: "email_queue_unavailable" });
  assert.equal(env.REVENUE_CRM_KV.store.size, 0, "no misleading queue or event mutation");
});

test("automationTrigger: malformed email queue binding returns 503 without pretending delivery", async () => {
  const env = fakeEnv();
  env.EMAIL_QUEUE_KV = { get: async () => null }; // no put capability
  const res = await automationTrigger(
    triggerRequest({ trigger: "usage_80pct", email: "customer@example.test" },
      { adminSecret: "test_admin_secret" }),
    env, "rid_test"
  );
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, "email_queue_unavailable");
});

test("automationTrigger: authentication still fails first even if email queue is unbound", async () => {
  const env = fakeEnv();
  delete env.EMAIL_QUEUE_KV;
  const res = await automationTrigger(
    triggerRequest({ trigger: "usage_80pct", email: "victim@example.test" }),
    env, "rid_test"
  );
  assert.equal(res.status, 401);
});

test("automationTrigger: failed queue put must never return a success receipt", async () => {
  const env = fakeEnv();
  env.EMAIL_QUEUE_KV.put = async () => { throw new Error("synthetic KV write failed"); };
  await assert.rejects(
    () => automationTrigger(
      triggerRequest({ trigger: "usage_80pct", email: "customer@example.test" },
        { adminSecret: "test_admin_secret" }),
      env, "rid_test"
    ),
    /synthetic KV write failed/
  );
});

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
