/**
 * workers/intel-gateway/src/rate-limit-cache.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX -- In-isolate counter layer for KV budgets
 * ===========================================================================
 * Cuts Workers KV WRITE volume on the request path by roughly an order of
 * magnitude, without changing any limit, any response shape, or any
 * customer-visible behaviour.
 *
 * WHY THIS EXISTS
 * ---------------
 * Five hot-path counters -- checkRateLimit, checkDailyQuota,
 * checkWebPlaneRateLimit, checkWebPlaneDailyQuota and the SWARM preflight
 * limiter -- each did KV.get() then KV.put() on EVERY allowed request. So a
 * single authenticated API call cost 1-4 KV writes.
 *
 * Cloudflare KV write allowances make that the platform's binding scale
 * limit, well before CPU or request count:
 *     Workers Free   1,000 writes/day    -> ~250-1,000 requests/day
 *     Workers Paid   1M writes/month     -> ~16,600 requests/day before overage
 * A worldwide launch would exhaust the write budget long before anything
 * else, and when it does, KV.put() starts failing -- degrading rate limiting
 * and quota enforcement exactly when traffic is highest.
 *
 * WHAT THIS CHANGES (and what it deliberately does not)
 * -----------------------------------------------------
 * Counting moves into the isolate. KV stays the cross-isolate source of
 * truth, but is written every FLUSH_EVERY increments instead of every one.
 *
 * The honest trade-off: between flushes an isolate can serve up to
 * FLUSH_EVERY - 1 requests beyond a limit before other isolates observe the
 * count. That is a real, bounded loss of precision, and it is acceptable
 * here for a specific reason -- KV is EVENTUALLY CONSISTENT, with reads
 * served from a colo cache that can lag writes by up to ~60s. Per-colo
 * enforcement drift already existed; this changes the granularity of an
 * approximation, not an exact guarantee into an approximate one.
 *
 * Two cases are never batched, because they are the ones that matter:
 *   * the first increment in a window (seeds from KV, claims the window), and
 *   * the increment that crosses the limit (flushed immediately, so a block
 *     becomes visible to every other isolate without waiting).
 *
 * FAIL-OPEN is preserved exactly. Every existing counter returns "allowed"
 * on a KV error, on the principle that a transient KV outage must not become
 * a customer-facing outage. This layer keeps that posture and adds no new
 * failure mode: if the cache is empty or stale, behaviour degrades to the
 * original read-through path.
 *
 * Memory is bounded: entries expire with their window and the map is capped
 * (MAX_ENTRIES) with oldest-first eviction, so a hostile spread of keys can
 * not grow an isolate's heap without limit.
 */

// Flush to KV every N increments. 1 restores the original
// write-per-request behaviour exactly, which makes this layer a no-op and is
// the documented kill switch if a limit ever needs to be exact.
export const FLUSH_EVERY = 10;

// Hard ceiling on tracked keys per isolate. Each entry is small (a few
// numbers), but an attacker rotating IPs must not be able to grow the map
// without bound. Oldest entries are evicted first; an evicted key simply
// falls back to the read-through KV path on its next request.
export const MAX_ENTRIES = 10000;

/** @type {Map<string, {count:number, flushed:number, expiresAt:number}>} */
const counters = new Map();

/** Test seam: drop all in-isolate state. */
export function _resetCounterCache() {
  counters.clear();
}

/** Test seam: current tracked key count. */
export function _counterCacheSize() {
  return counters.size;
}

function evictIfNeeded(now) {
  if (counters.size <= MAX_ENTRIES) return;
  for (const [k, v] of counters) {
    if (v.expiresAt <= now) counters.delete(k);
    if (counters.size <= MAX_ENTRIES) return;
  }
  // Still over budget after expiry sweep: drop oldest insertions (Map
  // preserves insertion order) until back under the cap.
  for (const k of counters.keys()) {
    counters.delete(k);
    if (counters.size <= MAX_ENTRIES) return;
  }
}

/**
 * Increment a KV-backed counter, batching writes.
 *
 * @param {object} kv          KV namespace binding (RATE_LIMIT_KV etc).
 * @param {string} key         Counter key.
 * @param {number} ttlSeconds  KV expirationTtl for the key.
 * @param {number} limit       Threshold this counter is enforced against.
 *                             Used only to force a flush on the crossing
 *                             increment; pass Infinity for pure metering.
 * @param {number} [now]       Injectable clock (ms) for tests.
 * @returns {Promise<{count:number, kvWrote:boolean, seeded:boolean}>}
 *          count is the value AFTER this increment.
 * @throws  Propagates KV errors so each caller keeps its own fail-open catch.
 */
export async function bumpCounter(kv, key, ttlSeconds, limit, now = Date.now()) {
  let entry = counters.get(key);

  if (!entry || entry.expiresAt <= now) {
    // First touch in this window for this isolate: read KV so the window is
    // seeded with whatever other isolates have already recorded, then write
    // immediately to claim it. This is the one unavoidable write per window
    // per isolate.
    const raw = await kv.get(key);
    const base = raw ? parseInt(raw, 10) : 0;
    const seededCount = (Number.isFinite(base) ? base : 0) + 1;
    entry = {
      count: seededCount,
      flushed: seededCount,
      expiresAt: now + ttlSeconds * 1000,
    };
    counters.set(key, entry);
    evictIfNeeded(now);
    await kv.put(key, String(seededCount), { expirationTtl: ttlSeconds });
    return { count: seededCount, kvWrote: true, seeded: true };
  }

  entry.count += 1;

  const crossedLimit = entry.count >= limit && entry.flushed < limit;
  const dueForFlush = entry.count - entry.flushed >= FLUSH_EVERY;

  if (crossedLimit || dueForFlush) {
    entry.flushed = entry.count;
    await kv.put(key, String(entry.count), { expirationTtl: ttlSeconds });
    return { count: entry.count, kvWrote: true, seeded: false };
  }

  return { count: entry.count, kvWrote: false, seeded: false };
}

/**
 * Read a counter without incrementing, preferring in-isolate state.
 * Falls back to KV when this isolate has not seen the key in this window.
 */
export async function peekCounter(kv, key, now = Date.now()) {
  const entry = counters.get(key);
  if (entry && entry.expiresAt > now) return entry.count;
  const raw = await kv.get(key);
  const parsed = raw ? parseInt(raw, 10) : 0;
  return Number.isFinite(parsed) ? parsed : 0;
}
