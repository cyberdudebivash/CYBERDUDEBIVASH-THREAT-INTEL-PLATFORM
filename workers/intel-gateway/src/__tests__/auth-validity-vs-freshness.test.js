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

function harness(feedState) {
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
      [VALID_KEY]: JSON.stringify({ tier: "PRO", customer_id: "cust_test_1", status: "active" }),
    }),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  return async (path, key) => {
    const headers = { "cf-connecting-ip": "198.51.100.9" };
    if (key) headers["X-API-Key"] = key;
    const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com${path}`, { headers }), env, ctx);
    await Promise.allSettled(waits);
    return { status: res.status, body: await res.json() };
  };
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
