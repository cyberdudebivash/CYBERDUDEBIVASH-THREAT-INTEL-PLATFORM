/**
 * workers/intel-gateway/src/r2-edge-cache.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX -- Edge cache for R2-backed JSON reads
 * =======================================================================
 * Serves R2-backed JSON from the Cloudflare edge cache instead of hitting R2
 * on every request. Cuts both latency and per-request R2 operation cost.
 *
 * MEASURED PROBLEM
 * ----------------
 * Eleven P-layer handlers load JSON from R2 via `env.INTEL_R2.get()` on the
 * request path (26 call sites), and NOT ONE used the Workers Cache API.
 *
 * P41's capability registry is the only one of those endpoints that is
 * public by design, so it is the one whose real cost is externally
 * observable. Measured against live production, five consecutive samples:
 *
 *     /api/v1/p41/capabilities   16 KB    ttfb 2.6 - 5.5 s
 *     /api/feed                1.2 MB    ttfb 0.25 - 0.32 s
 *
 * A 16 KB response was 10-20x slower than a 1.2 MB one over the identical
 * path, consistently breaching the platform's own "< 2s p95 computed"
 * budget. The other ten handlers are auth-gated and return 401 before
 * reaching their R2 read, so their latency could not be measured from
 * outside -- but they share this exact code pattern.
 *
 * Setting `Cache-Control` on the response, as those handlers already do, is
 * only a hint to downstream caches. A Worker-generated response is not
 * edge-cached unless the Worker puts it in the cache itself, which is what
 * this does.
 *
 * COST
 * ----
 * Every uncached request was one R2 Class B operation. Under the platform's
 * Cloudflare budget mandate, a cache hit costs nothing, so this removes an
 * R2 operation per request per endpoint that adopts it.
 *
 * SAFETY
 * ------
 * Read-only and degradation-safe. A cache miss, a cache error, or a
 * Cache API that is absent (Node tests, older runtimes) all fall through to
 * the original R2 read, so behaviour is never worse than before. A cache
 * WRITE failure is swallowed deliberately: failing to populate a cache must
 * never fail a customer request that already has its data.
 *
 * Cache keys are synthetic and internal (a URL built from the R2 key). They
 * never collide with a customer-facing URL, so nothing a customer requests
 * can poison or read this namespace.
 */

// Synthetic origin for internal cache keys. Never routed; never a real URL.
const CACHE_KEY_ORIGIN = "https://r2-edge-cache.sentinel-apex.internal/";

export const DEFAULT_TTL_SECONDS = 300;

/** Build the synthetic Request used as this R2 key's cache key. */
export function buildCacheKey(r2Key, origin = CACHE_KEY_ORIGIN) {
  return new Request(origin + encodeURIComponent(r2Key));
}

/**
 * Load JSON from R2, preferring the edge cache.
 *
 * @param {object}  env            Worker env (needs INTEL_R2).
 * @param {string}  r2Key          Object key in the intel bucket.
 * @param {object}  [opts]
 * @param {number}  [opts.ttlSeconds]  Edge TTL. Default 300.
 * @param {object}  [opts.cache]   Cache instance; defaults to caches.default.
 *                                 Injectable so this is testable off-Workers.
 * @param {object}  [opts.ctx]     Optional ExecutionContext. When supplied the
 *                                 cache write runs in waitUntil so the customer
 *                                 does not pay for it.
 * @returns {Promise<any|null>}    Parsed JSON, or null when the key is absent.
 */
export async function cachedR2Json(env, r2Key, opts = {}) {
  const ttlSeconds = opts.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const cache = opts.cache ?? globalThis.caches?.default ?? null;
  const cacheKey = cache ? buildCacheKey(r2Key) : null;

  if (cache) {
    try {
      const hit = await cache.match(cacheKey);
      if (hit) return await hit.json();
    } catch (_) {
      // A broken cache must never block the read -- fall through to R2.
    }
  }

  const obj = await env?.INTEL_R2?.get(r2Key);
  if (!obj) return null;

  const text = await obj.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (_) {
    // Malformed object in the bucket: behave exactly as the previous
    // _loadR2Json callers did on a parse failure, and never cache it.
    return null;
  }

  if (cache) {
    const write = (async () => {
      try {
        await cache.put(
          cacheKey,
          new Response(text, {
            headers: {
              "content-type": "application/json; charset=utf-8",
              "cache-control": `public, max-age=${ttlSeconds}`,
            },
          }),
        );
      } catch (_) {
        // Populating the cache is best-effort by design.
      }
    })();
    if (opts.ctx?.waitUntil) opts.ctx.waitUntil(write);
    else await write;
  }

  return parsed;
}
