import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import worker from "../index.js";
import {
  classifyManifestFreshness,
  evaluatePublicIntelligence,
  healthEdgeTtlSeconds,
  MAX_PUBLIC_MANIFEST_AGE_HOURS,
  MAX_FUTURE_SKEW_HOURS,
  GENERATED_AT_PATTERN,
} from "../freshness-contract.js";

// ---------------------------------------------------------------------------
// P0 health freshness contract (2026-09-24).
//
// Verified live before this change: GET /api/health -> HTTP 200
// {"status":"ok"} while /api/feed.json and /api/v1/intel/latest.json served
// generated_at 2026-08-26T09:55:27Z -- four weeks stale. These tests pin:
//   * 200/"ok" ONLY for present, valid, non-empty, fresh intelligence;
//   * 503 with a machine-readable reason for stale / empty / malformed /
//     missing / invalid / grossly-future / unreadable intelligence;
//   * the same classification as the Python upload guard and release gate
//     (shared vectors in config/public_freshness_contract_vectors.json);
//   * no secret-presence flags or storage topology in the public response;
//   * the edge cache never holds an operator response and never keeps a
//     healthy response past the freshness boundary;
//   * /api/health/live stays 200 regardless of data (deploy liveness).
// ---------------------------------------------------------------------------

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../../..");
const CONTRACT = JSON.parse(fs.readFileSync(path.join(REPO, "config/public_freshness_contract.json"), "utf8"));
const VECTORS = JSON.parse(fs.readFileSync(path.join(REPO, "config/public_freshness_contract_vectors.json"), "utf8"));

const NOW = Date.parse("2026-09-24T06:00:00Z");
const isoAgo = (seconds) => new Date(NOW - seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const feed = (overrides = {}) => ({
  generated_at: isoAgo(3600),
  count: 2,
  items: [{ id: "intel--a", severity: "HIGH" }, { id: "intel--b", severity: "CRITICAL" }],
  ...overrides,
});

// ── contract parity ─────────────────────────────────────────────────────────

test("JS contract constants equal config/public_freshness_contract.json", () => {
  assert.equal(MAX_PUBLIC_MANIFEST_AGE_HOURS, CONTRACT.max_public_manifest_age_hours);
  assert.equal(MAX_FUTURE_SKEW_HOURS, CONTRACT.max_future_skew_hours);
  assert.equal(GENERATED_AT_PATTERN, CONTRACT.generated_at_pattern);
});

for (const v of VECTORS.vectors) {
  test(`shared vector ${v.name} -> ${v.state}`, () => {
    const r = classifyManifestFreshness(v.generated_at, Date.parse(VECTORS.now));
    assert.equal(r.state, v.state);
    assert.equal(r.age_seconds, v.age_seconds);
  });
}

// ── evaluator ───────────────────────────────────────────────────────────────

test("fresh, non-empty feed -> ok / 200", () => {
  const e = evaluatePublicIntelligence(feed(), NOW);
  assert.equal(e.status, "ok");
  assert.equal(e.http_status, 200);
  assert.equal(e.reason, null);
  assert.equal(e.intelligence.advisory_count, 2);
});

test("exact threshold boundary is fresh (inclusive); one second over is degraded", () => {
  const max = MAX_PUBLIC_MANIFEST_AGE_HOURS * 3600;
  assert.equal(evaluatePublicIntelligence(feed({ generated_at: isoAgo(max) }), NOW).http_status, 200);
  const over = evaluatePublicIntelligence(feed({ generated_at: isoAgo(max + 1) }), NOW);
  assert.equal(over.http_status, 503);
  assert.equal(over.status, "degraded");
  assert.equal(over.reason, "intelligence_stale");
});

test("the 2026-08-26 incident manifest must NOT be ok", () => {
  const e = evaluatePublicIntelligence(feed({ generated_at: "2026-08-26T09:55:27Z" }), NOW);
  assert.equal(e.status, "degraded");
  assert.equal(e.http_status, 503);
  assert.equal(e.intelligence.status, "stale");
});

test("empty feed -> 503 unhealthy", () => {
  const e = evaluatePublicIntelligence(feed({ items: [], count: 0 }), NOW);
  assert.deepEqual([e.http_status, e.status, e.reason], [503, "unhealthy", "no_intelligence_items"]);
});

test("items without a valid id do not count as intelligence", () => {
  const e = evaluatePublicIntelligence(feed({ items: [{}, null, "x", { id: "  " }], count: 4 }), NOW);
  assert.equal(e.reason, "no_intelligence_items");
});

test("malformed feed structures -> 503 invalid_feed_structure", () => {
  for (const bad of ["not json object", [1, 2], { generated_at: isoAgo(60) }, { items: "x" }]) {
    const e = evaluatePublicIntelligence(bad, NOW);
    assert.deepEqual([e.http_status, e.reason], [503, "invalid_feed_structure"], JSON.stringify(bad));
  }
});

test("missing / invalid generated_at -> 503", () => {
  assert.equal(evaluatePublicIntelligence(feed({ generated_at: undefined }), NOW).reason, "generated_at_missing");
  assert.equal(evaluatePublicIntelligence(feed({ generated_at: "not-a-date" }), NOW).reason, "generated_at_invalid");
  assert.equal(evaluatePublicIntelligence(feed({ generated_at: "2026-02-30T00:00:00Z" }), NOW).reason, "generated_at_invalid");
});

test("future timestamp within pipeline clock-skew is fresh; grossly future is unhealthy", () => {
  const skew = MAX_FUTURE_SKEW_HOURS * 3600;
  assert.equal(evaluatePublicIntelligence(feed({ generated_at: isoAgo(-(skew - 60)) }), NOW).http_status, 200);
  const e = evaluatePublicIntelligence(feed({ generated_at: "2099-01-01T00:00:00Z" }), NOW);
  assert.deepEqual([e.http_status, e.status, e.reason], [503, "unhealthy", "generated_at_in_future"]);
});

test("count/items mismatch is a publication-integrity failure", () => {
  const e = evaluatePublicIntelligence(feed({ count: 99 }), NOW);
  assert.deepEqual([e.http_status, e.reason, e.checks.publication_integrity], [503, "publication_count_mismatch", "count_mismatch"]);
});

test("storage read failure (null) never pretends freshness", () => {
  const e = evaluatePublicIntelligence(null, NOW);
  assert.deepEqual([e.http_status, e.status, e.reason, e.intelligence.status], [503, "unhealthy", "feed_unavailable", "unavailable"]);
  assert.equal(e.intelligence.generated_at, null);
});

test("edge TTL never outlives the freshness boundary", () => {
  const max = MAX_PUBLIC_MANIFEST_AGE_HOURS * 3600;
  assert.equal(healthEdgeTtlSeconds(evaluatePublicIntelligence(feed({ generated_at: isoAgo(60) }), NOW), 300), 300);
  assert.equal(healthEdgeTtlSeconds(evaluatePublicIntelligence(feed({ generated_at: isoAgo(max - 42) }), NOW), 300), 42);
  assert.equal(healthEdgeTtlSeconds(evaluatePublicIntelligence(feed({ generated_at: isoAgo(max + 1) }), NOW), 300), 0);
});

// ── route level (real Worker fetch entry) ───────────────────────────────────

function fakeKV() {
  const m = new Map();
  return {
    get: async (k, o) => { const v = m.get(k); return v === undefined ? null : (o === "json" || (o && o.type === "json") ? JSON.parse(v) : v); },
    put: async (k, v) => { m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    list: async () => ({ keys: [], list_complete: true }),
  };
}

function harness(r2Get) {
  const edge = new Map();
  globalThis.caches = {
    default: {
      match: async (req) => edge.get(req.url),
      put: async (req, res) => { edge.set(req.url, res); },
    },
  };
  const env = {
    INTEL_R2: { get: r2Get },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const call = async (p, headers = {}) => {
    const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com${p}`, { headers }), env, ctx);
    await Promise.all(waits);
    return { res, body: await res.json() };
  };
  return { call, edge };
}

const r2With = (obj) => async (key) =>
  key === "api/v1/intel/latest.json" ? { text: async () => (typeof obj === "string" ? obj : JSON.stringify(obj)) } : null;
const liveFeed = (generatedAt) => ({ generated_at: generatedAt, count: 1, items: [{ id: "intel--live", severity: "HIGH" }] });
const nowIso = (offsetSeconds = 0) => new Date(Date.now() + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

// Every key the public response is allowed to carry. Anything else (in
// particular secret-presence flags and storage topology) fails the test.
const PUBLIC_TOP_LEVEL = new Set([
  "status", "service", "version", "reason", "advisory_count", "critical_count", "kev_confirmed", "last_sync",
  "feed_index", "platform_reachable", "intelligence_available", "intelligence", "checks", "generated_at",
]);
const PUBLIC_CHECKS = new Set([
  "gateway", "worker_runtime", "intelligence_available", "intelligence_freshness", "publication_integrity", "feed_index",
]);
const FORBIDDEN = /jwt|secret|razorpay|resend|admin|kv_|r2_|bucket|namespace|account|binding|token|security/i;

test("route: fresh feed -> 200 ok, preserved envelope, no sensitive fields", async () => {
  const { call } = harness(r2With(liveFeed(nowIso(-600))));
  const { res, body } = await call("/api/health");
  assert.equal(res.status, 200);
  assert.equal(body.status, "ok");
  for (const k of ["version", "advisory_count", "last_sync", "feed_index", "platform_reachable", "intelligence_available", "generated_at"]) {
    assert.ok(k in body, `existing consumer field ${k} must be preserved`);
  }
  assert.equal(body.checks.gateway, "ok");
  for (const k of Object.keys(body)) assert.ok(PUBLIC_TOP_LEVEL.has(k), `unexpected public field ${k}`);
  for (const k of Object.keys(body.checks)) assert.ok(PUBLIC_CHECKS.has(k), `unexpected public check ${k}`);
  const serialized = JSON.stringify(Object.keys(body)) + JSON.stringify(Object.keys(body.checks));
  assert.ok(!FORBIDDEN.test(serialized), `public health leaks: ${serialized}`);
  assert.equal(res.headers.get("x-sentinel-edge-ttl"), null, "internal TTL header must be stripped");
});

test("route: 2026-08-26 stale feed -> 503 degraded, never cached", async () => {
  const { call, edge } = harness(r2With(liveFeed("2026-08-26T09:55:27Z")));
  const { res, body } = await call("/api/health");
  assert.equal(res.status, 503);
  assert.equal(body.status, "degraded");
  assert.equal(body.reason, "intelligence_stale");
  assert.equal(edge.size, 0);
});

test("route: R2 failure (throws) and R2 miss -> 503 unhealthy, not fresh", async () => {
  for (const r2 of [async () => { throw new Error("r2 down"); }, async () => null]) {
    const { call } = harness(r2);
    const { res, body } = await call("/api/health");
    assert.equal(res.status, 503);
    assert.equal(body.reason, "feed_unavailable");
    assert.equal(body.intelligence.status, "unavailable");
  }
});

test("route: malformed stored JSON and empty feed -> 503", async () => {
  let r = await harness(r2With("{not json")).call("/api/health");
  assert.deepEqual([r.res.status, r.body.reason], [503, "feed_unavailable"]);
  r = await harness(r2With({ generated_at: nowIso(-60), count: 0, items: [] })).call("/api/health");
  assert.deepEqual([r.res.status, r.body.reason], [503, "no_intelligence_items"]);
});

test("route: admin response carries operator fields, is private and never enters the edge cache", async () => {
  const { call, edge } = harness(r2With(liveFeed(nowIso(-600))));
  await call("/api/health"); // public call populates the shared cache
  assert.equal(edge.size, 1);
  const cachedBefore = edge.get("https://intel.cyberdudebivash.com/api/health");
  const { res, body } = await call("/api/health", { "X-Admin-Key": "admin-test" });
  assert.equal(res.status, 200);
  assert.equal(body.checks.jwt_configured, true, "operator view keeps jwt_configured");
  assert.ok("kv_rate_limit" in body.checks && "r2_intel" in body.checks && body.security);
  assert.match(res.headers.get("cache-control") || "", /no-store/);
  assert.equal(edge.get("https://intel.cyberdudebivash.com/api/health"), cachedBefore, "admin body must not overwrite the shared cache");
});

test("route: cached healthy response TTL is capped at the freshness boundary", async () => {
  const max = MAX_PUBLIC_MANIFEST_AGE_HOURS * 3600;
  const { call, edge } = harness(r2With(liveFeed(nowIso(-(max - 90)))));
  await call("/api/health");
  const cc = edge.get("https://intel.cyberdudebivash.com/api/health").headers.get("cache-control");
  const ttl = Number(/max-age=(\d+)/.exec(cc)[1]);
  assert.ok(ttl > 0 && ttl <= 90, `edge TTL ${ttl} must not exceed the ~90s left before the feed turns stale`);
});

test("route: /api/health/live is 200 even when intelligence is stale or unavailable, and reads no storage", async () => {
  let r2Reads = 0;
  const { call } = harness(async () => { r2Reads += 1; return null; });
  const { res, body } = await call("/api/health/live");
  assert.equal(res.status, 200);
  assert.equal(body.status, "alive");
  assert.equal(r2Reads, 0);
});
