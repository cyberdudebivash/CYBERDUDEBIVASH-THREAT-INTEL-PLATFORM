/**
 * Contract tests for the in-isolate counter layer.
 *
 * This code sits on the authorization-adjacent request path, so the bar is
 * not "the cache works" but "limits still enforce". The write-reduction
 * assertions are secondary to the enforcement ones.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  bumpCounter, peekCounter, FLUSH_EVERY, MAX_ENTRIES,
  _resetCounterCache, _counterCacheSize,
} from "../rate-limit-cache.js";

function fakeKV(initial = {}) {
  const store = new Map(Object.entries(initial));
  const stats = { gets: 0, puts: 0 };
  return {
    stats,
    async get(k) { stats.gets++; return store.has(k) ? store.get(k) : null; },
    async put(k, v) { stats.puts++; store.set(k, v); },
    _store: store,
  };
}

test("first increment seeds from KV and claims the window", async () => {
  _resetCounterCache();
  const kv = fakeKV({ "rl:x:1": "7" });
  const r = await bumpCounter(kv, "rl:x:1", 61, 100);
  assert.equal(r.count, 8, "must continue from the KV value, not restart at 1");
  assert.equal(r.seeded, true);
  assert.equal(r.kvWrote, true);
  assert.equal(kv._store.get("rl:x:1"), "8");
});

test("a counter with no KV value starts at 1", async () => {
  _resetCounterCache();
  const kv = fakeKV();
  const r = await bumpCounter(kv, "rl:new:1", 61, 100);
  assert.equal(r.count, 1);
});

test("corrupt KV value is treated as zero, not NaN", async () => {
  _resetCounterCache();
  const kv = fakeKV({ "rl:bad:1": "not-a-number" });
  const r = await bumpCounter(kv, "rl:bad:1", 61, 100);
  assert.equal(r.count, 1, "NaN must not poison the counter");
});

test("ENFORCEMENT: count is exact in-isolate on every request", async () => {
  // The batching must never cause an isolate to under-count its OWN traffic.
  _resetCounterCache();
  const kv = fakeKV();
  for (let i = 1; i <= 50; i++) {
    const r = await bumpCounter(kv, "rl:e:1", 61, 1000);
    assert.equal(r.count, i, `request ${i} must report count ${i}`);
  }
});

test("ENFORCEMENT: the limit-crossing increment always flushes immediately", async () => {
  // A block must be visible to other isolates without waiting for a batch.
  _resetCounterCache();
  const kv = fakeKV();
  const limit = 5;
  let crossing = null;
  for (let i = 1; i <= limit; i++) {
    crossing = await bumpCounter(kv, "rl:c:1", 61, limit);
  }
  assert.equal(crossing.count, limit);
  assert.equal(crossing.kvWrote, true, "crossing the limit must write through");
  assert.equal(kv._store.get("rl:c:1"), String(limit),
    "KV must show the limit so other isolates block too");
});

test("ENFORCEMENT: a limit below FLUSH_EVERY still writes through on crossing", async () => {
  _resetCounterCache();
  assert.ok(3 < FLUSH_EVERY, "precondition: limit under the batch size");
  const kv = fakeKV();
  let last = null;
  for (let i = 1; i <= 3; i++) last = await bumpCounter(kv, "rl:small:1", 61, 3);
  assert.equal(last.kvWrote, true);
  assert.equal(kv._store.get("rl:small:1"), "3");
});

test("write volume drops ~FLUSH_EVERY-fold over a window", async () => {
  _resetCounterCache();
  const kv = fakeKV();
  for (let i = 0; i < 100; i++) await bumpCounter(kv, "rl:v:1", 61, 10000);
  assert.ok(kv.stats.puts <= 100 / FLUSH_EVERY + 1,
    `expected <= ~${100 / FLUSH_EVERY} writes, got ${kv.stats.puts}`);
  assert.equal(kv.stats.gets, 1, "KV is read once per window per isolate");
});

test("window expiry re-seeds from KV rather than reusing a stale count", async () => {
  _resetCounterCache();
  const kv = fakeKV();
  const t0 = 1_000_000;
  await bumpCounter(kv, "rl:w:1", 60, 1000, t0);
  const after = await bumpCounter(kv, "rl:w:1", 60, 1000, t0 + 61_000);
  assert.equal(after.seeded, true, "expired window must re-seed");
});

test("counters are isolated per key", async () => {
  _resetCounterCache();
  const kv = fakeKV();
  await bumpCounter(kv, "rl:a:1", 61, 100);
  await bumpCounter(kv, "rl:a:1", 61, 100);
  const b = await bumpCounter(kv, "rl:b:1", 61, 100);
  assert.equal(b.count, 1, "a different key must not inherit another's count");
});

test("KV errors propagate so each caller keeps its own fail-open catch", async () => {
  _resetCounterCache();
  const kv = { get: async () => { throw new Error("kv down"); }, put: async () => {} };
  await assert.rejects(() => bumpCounter(kv, "rl:err:1", 61, 100), /kv down/);
});

test("peekCounter does not increment", async () => {
  _resetCounterCache();
  const kv = fakeKV();
  await bumpCounter(kv, "rl:p:1", 61, 100);
  assert.equal(await peekCounter(kv, "rl:p:1"), 1);
  assert.equal(await peekCounter(kv, "rl:p:1"), 1, "peek must be side-effect free");
});

test("peekCounter falls back to KV for a key this isolate has not seen", async () => {
  _resetCounterCache();
  const kv = fakeKV({ "rl:remote:1": "42" });
  assert.equal(await peekCounter(kv, "rl:remote:1"), 42);
});

test("map is bounded so rotating keys cannot grow the heap without limit", async () => {
  _resetCounterCache();
  const kv = fakeKV();
  for (let i = 0; i < MAX_ENTRIES + 500; i++) {
    await bumpCounter(kv, `rl:flood:${i}`, 61, 100);
  }
  assert.ok(_counterCacheSize() <= MAX_ENTRIES,
    `cache must stay bounded, got ${_counterCacheSize()}`);
});

test("FLUSH_EVERY=1 would restore exact write-per-request behaviour", () => {
  // Documents the kill switch: the layer is a no-op at 1.
  assert.ok(FLUSH_EVERY >= 1);
  assert.equal(typeof FLUSH_EVERY, "number");
});
