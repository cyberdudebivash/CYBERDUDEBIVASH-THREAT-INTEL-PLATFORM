/**
 * AUTHENTICATION VALIDITY != INTELLIGENCE FRESHNESS  (P0 Phase 3B)
 *
 * enterprise-trust-center.html authenticated customers by calling
 * /api/health, which since #488 answers a structured 503 while the feed is
 * stale. A paying customer with a valid key was therefore shown "Invalid API
 * key" whenever intelligence was stale -- and the same page let ANY key
 * through on 401 or on a network error. It now calls /api/auth/validate.
 *
 * This suite drives the real router across the 2x2 matrix and proves:
 *   - /api/auth/validate's verdict depends only on the credential;
 *   - /api/health's verdict depends only on freshness (the stale fixture is
 *     genuinely stale: /api/health answers 503 in the stale column);
 *   - the page calls /api/auth/validate, requires valid === true, and fails
 *     closed (no /api/health auth probe, no 401/offline pass-through).
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import worker from "../index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..", "..");
const VALID_KEY = "cdb_pro_test_0123456789abcdef0123456789abcdef";
const INVALID_KEY = "cdb_pro_test_ffffffffffffffffffffffffffffffff";

function fakeKV(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
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

const iso = (offsetSec) => new Date(Date.now() + offsetSec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const feed = (generatedAt) => JSON.stringify({
  generated_at: generatedAt, count: 1, items: [{ id: "intel--live", severity: "HIGH" }],
});
const FEEDS = {
  fresh: feed(iso(-600)),            // 10 min old
  stale: feed(iso(-7 * 24 * 3600)),  // 7 days old (contract max is 6h)
};

function harness(feedState, keyTier = "PRO") {
  const edge = new Map();
  globalThis.caches = {
    default: {
      match: async (req) => edge.get(req.url),
      put: async (req, res) => { edge.set(req.url, res); },
    },
  };
  const env = {
    INTEL_R2: {
      get: async (key) => (key === "api/v1/intel/latest.json" ? { text: async () => FEEDS[feedState] } : null),
    },
    RATE_LIMIT_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    API_KEYS_KV: fakeKV({
      [VALID_KEY]: JSON.stringify({ tier: keyTier, customer_id: "cust_test_1", status: "active" }),
    }),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const invoke = async (path, key, options = {}) => {
    const headers = { "cf-connecting-ip": "198.51.100.9", ...(options.headers || {}) };
    if (key) headers["X-API-Key"] = key;
    const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com${path}`, {
      method: options.method || "GET", headers, ...(options.body !== undefined ? { body: options.body } : {}),
    }), env, ctx);
    await Promise.allSettled(waits);
    return { status: res.status, body: await res.json() };
  };
  // Test-only mutation point: simulate outages AFTER a real JWT was issued.
  invoke.env = env;
  return invoke;
}

const CASES = [
  { cred: "valid",   key: VALID_KEY,   feed: "fresh", valid: true,  health: 200 },
  { cred: "valid",   key: VALID_KEY,   feed: "stale", valid: true,  health: 503 },
  { cred: "invalid", key: INVALID_KEY, feed: "fresh", valid: false, health: 200 },
  { cred: "invalid", key: INVALID_KEY, feed: "stale", valid: false, health: 503 },
];

for (const c of CASES) {
  test(`${c.cred} credential + ${c.feed} feed -> valid=${c.valid}, /api/health ${c.health}`, async () => {
    const call = harness(c.feed);
    const v = await call("/api/auth/validate", c.key);
    assert.equal(v.status, 200);
    assert.equal(v.body.valid, c.valid, JSON.stringify(v.body));
    if (c.valid) assert.equal(v.body.tier, "PRO");
    // The freshness dimension is real in this fixture. Probed anonymously:
    // the gateway 401s an invalid key on every /api/* route except
    // /api/auth/*, which is exactly why /api/health could not be an auth test.
    const h = await call("/api/health");
    assert.equal(h.status, c.health, JSON.stringify(h.body));
  });
}

test("trust center authenticates via /api/auth/validate and fails closed", () => {
  const src = readFileSync(join(ROOT, "enterprise-trust-center.html"), "utf-8");
  const fn = src.slice(src.indexOf("function auth()"), src.indexOf("function hdrs("));
  assert.match(fn, /\/api\/auth\/validate/);
  assert.match(fn, /body\.valid === true/);
  assert.doesNotMatch(fn, /fetch\([^)]*\/api\/health/, "freshness endpoint must not be used as an auth test");
  assert.doesNotMatch(fn, /status === 401/, "a 401 must never unlock the page");
  // The catch branch must not call loadAll (the old offline fail-open).
  const catchBranch = fn.slice(fn.lastIndexOf(".catch("));
  assert.doesNotMatch(catchBranch, /loadAll\(/);
});

test("onboarding key-verification step uses /api/auth/validate, not the nonexistent /api/v1/health", () => {
  const src = readFileSync(join(ROOT, "onboarding.html"), "utf-8");
  assert.match(src, /intel\.cyberdudebivash\.com\/api\/auth\/validate/);
  assert.doesNotMatch(src, /intel\.cyberdudebivash\.com\/api\/v1\/health\b/);
});

for (const malformedTier of [null, "pro", "UNKNOWN", "constructor", "__proto__"]) {
  test("invalid tier " + String(malformedTier) + " must never grant a gateway entitlement", async () => {
    const call = harness("fresh", malformedTier);
    const result = await call("/api/auth/validate", VALID_KEY);
    assert.equal(result.status, 200);
    assert.equal(result.body.valid, false, JSON.stringify(result.body));
    assert.equal(result.body.tier, "free");
  });
}

for (const invalidTier of [null, "pro", "UNKNOWN", "constructor", "__proto__"]) {
  test("login does not mint a JWT from a malformed subscription tier " + String(invalidTier), async () => {
    const call = harness("fresh", invalidTier);
    const result = await call("/api/auth/login", null, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ api_key: VALID_KEY }),
    });
    assert.equal(result.status, 401, JSON.stringify(result.body));
    assert.equal(result.body.code, "invalid_tier");
    assert.equal(result.body.token, undefined, "No bearer credential may be issued");
  });
}

test("an explicitly provisioned PRO key can still obtain a scoped JWT", async () => {
  const call = harness("fresh", "PRO");
  const result = await call("/api/auth/login", null, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: VALID_KEY }),
  });
  assert.equal(result.status, 200, JSON.stringify(result.body));
  assert.equal(result.body.tier, "PRO");
  assert.equal(typeof result.body.token, "string");
  assert.equal(result.body.token.split(".").length, 3);
});

test("JWT revocation and its authority outages fail closed without breaking valid customers", async () => {
  const call = harness("fresh", "PRO");
  const login = await call("/api/auth/login", null, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ api_key: VALID_KEY }),
  });
  assert.equal(login.status, 200, JSON.stringify(login.body));
  const token = login.body.token;
  assert.equal(typeof token, "string");
  const validate = () => call("/api/auth/validate", null, {
    headers: { Authorization: "Bearer " + token },
  });
  const live = await validate();
  assert.equal(live.status, 200);
  assert.equal(live.body.valid, true, "a genuine PRO customer remains authenticated");
  assert.equal(live.body.tier, "PRO");

  // Billing-deny mirror and self-service revocation have independent reads.
  await call.env.SECURITY_HUB_KV.put("jwt_revoked:" + token.slice(-24), "1");
  const revoked = await validate();
  assert.equal(revoked.body.valid, false, "logout revocation is honored");
  await call.env.SECURITY_HUB_KV.delete("jwt_revoked:" + token.slice(-24));

  const goodSecurityGet = call.env.SECURITY_HUB_KV.get;
  call.env.SECURITY_HUB_KV.get = async () => { throw Error("private KV outage"); };
  const revocationUnavailable = await validate();
  assert.equal(revocationUnavailable.status, 503);
  assert.equal(revocationUnavailable.body.valid, false, "unknown JWT revocation state must never grant paid access");
  assert.equal(revocationUnavailable.body.tier, "free");
  assert.equal(revocationUnavailable.body.code, "auth_service_unavailable");
  assert.equal(JSON.stringify(revocationUnavailable.body).includes("private KV outage"), false);
  call.env.SECURITY_HUB_KV.get = goodSecurityGet;
  assert.equal((await validate()).body.valid, true, "access recovers when authority recovers");

  const goodBillingGet = call.env.API_KEYS_KV.get;
  call.env.API_KEYS_KV.get = async key => {
    if (key.startsWith("jwt_deny:")) throw Error("private billing mirror outage");
    return goodBillingGet(key);
  };
  const billingUnavailable = await validate();
  assert.equal(billingUnavailable.status, 503);
  assert.equal(billingUnavailable.body.valid, false, "legacy billing denial mirror outages must never grant access");
  call.env.API_KEYS_KV.get = goodBillingGet;
  assert.equal((await validate()).body.valid, true, "normal PRO JWT remains valid after recovery");

  const knownBilling = call.env.API_KEYS_KV;
  call.env.API_KEYS_KV = undefined;
  const missingMirror = await validate();
  assert.equal(missingMirror.status, 503);
  assert.equal(missingMirror.body.valid, false, "missing legacy denial binding must fail closed");
  call.env.API_KEYS_KV = knownBilling;
  assert.equal((await validate()).body.valid, true, "customer restored with both authorities present");
});

test("auth-validation distinguishes an API key authority outage from invalid credentials", async () => {
  const call = harness("fresh");
  const normal = await call("/api/auth/validate", VALID_KEY);
  assert.equal(normal.status, 200);
  assert.equal(normal.body.valid, true);
  const goodGet = call.env.API_KEYS_KV.get;
  call.env.API_KEYS_KV.get = async () => { throw Error("private credentials unavailable"); };
  const unavailable = await call("/api/auth/validate", VALID_KEY);
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.valid, false);
  assert.equal(unavailable.body.tier, "free");
  assert.equal(unavailable.body.code, "auth_service_unavailable");
  assert.ok(!JSON.stringify(unavailable.body).includes("private credentials"));
  call.env.API_KEYS_KV.get = goodGet;
  assert.equal((await call("/api/auth/validate", VALID_KEY)).body.valid, true);
  const wrong = await call("/api/auth/validate", INVALID_KEY);
  assert.equal(wrong.status, 200);
  assert.equal(wrong.body.valid, false);
});
