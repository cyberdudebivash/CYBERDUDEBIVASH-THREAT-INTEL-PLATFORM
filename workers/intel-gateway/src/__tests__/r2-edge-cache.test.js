/**
 * Contract tests for the R2 edge cache.
 *
 * The bar is degradation-safety: this sits in front of production data
 * reads, so every failure mode must fall through to R2 rather than break
 * the request.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { cachedR2Json, buildCacheKey, DEFAULT_TTL_SECONDS } from "../r2-edge-cache.js";

function fakeR2(objects = {}) {
  const stats = { gets: 0 };
  return {
    stats,
    INTEL_R2: {
      async get(k) {
        stats.gets++;
        if (!(k in objects)) return null;
        const body = objects[k];
        return { async text() { return body; } };
      },
    },
  };
}

function fakeCache() {
  const store = new Map();
  const stats = { matches: 0, puts: 0 };
  return {
    stats,
    async match(req) {
      stats.matches++;
      const v = store.get(req.url);
      return v ? new Response(v) : undefined;
    },
    async put(req, res) { stats.puts++; store.set(req.url, await res.text()); },
  };
}

test("cache miss reads R2 and populates the cache", async () => {
  const env = fakeR2({ "intel/reg.json": JSON.stringify({ a: 1 }) });
  const cache = fakeCache();
  const out = await cachedR2Json(env, "intel/reg.json", { cache });
  assert.deepEqual(out, { a: 1 });
  assert.equal(env.stats.gets, 1);
  assert.equal(cache.stats.puts, 1);
});

test("cache hit serves without touching R2 -- the whole point", async () => {
  const env = fakeR2({ "intel/reg.json": JSON.stringify({ a: 1 }) });
  const cache = fakeCache();
  await cachedR2Json(env, "intel/reg.json", { cache });
  assert.equal(env.stats.gets, 1);
  for (let i = 0; i < 25; i++) {
    const out = await cachedR2Json(env, "intel/reg.json", { cache });
    assert.deepEqual(out, { a: 1 });
  }
  assert.equal(env.stats.gets, 1, "26 requests must cost exactly 1 R2 operation");
});

test("missing R2 object returns null and is not cached", async () => {
  const env = fakeR2();
  const cache = fakeCache();
  assert.equal(await cachedR2Json(env, "intel/absent.json", { cache }), null);
  assert.equal(cache.stats.puts, 0, "absence must never be cached");
});

test("malformed JSON returns null and is not cached", async () => {
  const env = fakeR2({ "intel/bad.json": "{not json" });
  const cache = fakeCache();
  assert.equal(await cachedR2Json(env, "intel/bad.json", { cache }), null);
  assert.equal(cache.stats.puts, 0, "a corrupt object must never be cached");
});

test("DEGRADATION: a throwing cache.match still serves from R2", async () => {
  const env = fakeR2({ "k": JSON.stringify({ ok: true }) });
  const cache = {
    async match() { throw new Error("cache exploded"); },
    async put() {},
  };
  assert.deepEqual(await cachedR2Json(env, "k", { cache }), { ok: true });
});

test("DEGRADATION: a throwing cache.put still returns the data", async () => {
  const env = fakeR2({ "k": JSON.stringify({ ok: true }) });
  const cache = {
    async match() { return undefined; },
    async put() { throw new Error("put failed"); },
  };
  assert.deepEqual(await cachedR2Json(env, "k", { cache }), { ok: true },
    "failing to populate a cache must not fail a request that has its data");
});

test("DEGRADATION: no Cache API at all falls through to R2", async () => {
  const env = fakeR2({ "k": JSON.stringify({ ok: true }) });
  assert.deepEqual(await cachedR2Json(env, "k", { cache: null }), { ok: true });
  assert.equal(env.stats.gets, 1);
});

test("DEGRADATION: absent INTEL_R2 binding returns null, does not throw", async () => {
  assert.equal(await cachedR2Json({}, "k", { cache: fakeCache() }), null);
  assert.equal(await cachedR2Json(undefined, "k", { cache: fakeCache() }), null);
});

test("distinct R2 keys never share a cache entry", async () => {
  const env = fakeR2({ a: JSON.stringify({ v: "a" }), b: JSON.stringify({ v: "b" }) });
  const cache = fakeCache();
  assert.deepEqual(await cachedR2Json(env, "a", { cache }), { v: "a" });
  assert.deepEqual(await cachedR2Json(env, "b", { cache }), { v: "b" });
});

test("cache keys are internal and cannot collide with a customer URL", () => {
  const k = buildCacheKey("intel/frontend_capability_registry.json");
  assert.ok(k.url.startsWith("https://r2-edge-cache.sentinel-apex.internal/"));
  assert.ok(!k.url.includes("intel.cyberdudebivash.com"));
});

test("keys needing escaping round-trip safely", async () => {
  const key = "intel/a b/c?d=1&e#f.json";
  const env = fakeR2({ [key]: JSON.stringify({ ok: 1 }) });
  const cache = fakeCache();
  assert.deepEqual(await cachedR2Json(env, key, { cache }), { ok: 1 });
  assert.deepEqual(await cachedR2Json(env, key, { cache }), { ok: 1 });
  assert.equal(env.stats.gets, 1, "escaped key must still hit cache on repeat");
});

test("ctx.waitUntil is used for the cache write when provided", async () => {
  const env = fakeR2({ k: JSON.stringify({ ok: 1 }) });
  const cache = fakeCache();
  const pending = [];
  await cachedR2Json(env, "k", { cache, ctx: { waitUntil: (p) => pending.push(p) } });
  assert.equal(pending.length, 1, "write should be deferred off the response path");
  await Promise.all(pending);
  assert.equal(cache.stats.puts, 1);
});

test("default TTL is a sane positive number", () => {
  assert.ok(Number.isInteger(DEFAULT_TTL_SECONDS) && DEFAULT_TTL_SECONDS > 0);
});
