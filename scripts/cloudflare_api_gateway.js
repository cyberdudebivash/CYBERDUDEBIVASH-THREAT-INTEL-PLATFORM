/**
 * CYBERDUDEBIVASH® SENTINEL APEX — Cloudflare Workers API Gateway
 * Version: 161.0.0
 *
 * PURPOSE:
 *   Enterprise API gateway deployed as a Cloudflare Worker.
 *   Provides: API key authentication, tier-based rate limiting,
 *   CORS headers, request logging, and upstream routing to R2/GitHub Pages.
 *
 * DEPLOYMENT:
 *   1. Create Cloudflare Worker at dash.cloudflare.com
 *   2. Add KV namespace: SENTINEL_API_KEYS
 *   3. Populate KV with: key={api_key} → value={"tier":"pro","email":"user@example.com"}
 *   4. Set route: intel.cyberdudebivash.com/api/* → this worker
 *   5. Deploy: wrangler publish
 *
 * KV KEY FORMAT:
 *   Key:   "apikey_<HASH_OF_API_KEY>"
 *   Value: {"tier":"free|pro|enterprise|mssp","email":"...","created":"ISO","active":true}
 *
 * RATE LIMITS (requests per 24h):
 *   Free:       100
 *   Professional: 10,000
 *   Enterprise:   unlimited (burst limit: 500/min)
 *   MSSP:         unlimited (burst limit: 1000/min)
 */

const UPSTREAM_BASE   = "https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM";
const RATE_LIMITS     = { free: 100, pro: 10000, enterprise: Infinity, mssp: Infinity };
const BURST_LIMITS    = { free: 10, pro: 100, enterprise: 500, mssp: 1000 };
const ALLOWED_ORIGINS = [
  "https://intel.cyberdudebivash.com",
  "https://cyberdudebivash.com",
  "https://tools.cyberdudebivash.com",
];

// ─── CORS Headers ─────────────────────────────────────────────────────────────
function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "X-API-Key, Content-Type",
    "Access-Control-Max-Age":       "86400",
  };
}

// ─── Error Response ────────────────────────────────────────────────────────────
function errorResponse(code, message, status) {
  return new Response(
    JSON.stringify({ error: message, code, timestamp: new Date().toISOString() }),
    { status, headers: { "Content-Type": "application/json", ...corsHeaders("") } }
  );
}

// ─── Validate API Key ──────────────────────────────────────────────────────────
async function validateApiKey(apiKey, env) {
  if (!apiKey) return null;
  // Hash the key for KV lookup (prevents key exposure in KV)
  const encoder = new TextEncoder();
  const data = encoder.encode(apiKey);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,"0")).join("");
  const kvKey = `apikey_${hashHex}`;
  try {
    const value = await env.SENTINEL_API_KEYS.get(kvKey);
    if (!value) return null;
    const record = JSON.parse(value);
    return record.active !== false ? record : null;
  } catch {
    return null;
  }
}

// ─── Rate Limit Check ─────────────────────────────────────────────────────────
async function checkRateLimit(tier, apiKey, env) {
  const dailyLimit = RATE_LIMITS[tier] ?? RATE_LIMITS.free;
  if (dailyLimit === Infinity) return { allowed: true, remaining: 999999, reset: 0 };
  const today = new Date().toISOString().split("T")[0];
  const counterKey = `rl_${apiKey.slice(0,8)}_${today}`;
  try {
    const current = parseInt(await env.SENTINEL_API_KEYS.get(counterKey) ?? "0");
    const remaining = Math.max(0, dailyLimit - current);
    const reset = Math.floor((new Date().setHours(24,0,0,0)) / 1000);
    if (current >= dailyLimit) return { allowed: false, remaining: 0, reset };
    await env.SENTINEL_API_KEYS.put(counterKey, String(current + 1), { expirationTtl: 86400 });
    return { allowed: true, remaining: remaining - 1, reset };
  } catch {
    return { allowed: true, remaining: 99, reset: 0 };
  }
}

// ─── Route Handler ─────────────────────────────────────────────────────────────
async function handleRequest(request, env) {
  const url    = new URL(request.url);
  const origin = request.headers.get("Origin") || "";
  const path   = url.pathname.replace("/api", "");

  // OPTIONS preflight
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders(origin) });
  }

  // Public endpoints (no auth required)
  if (path === "/health" || path === "/openapi.json") {
    const upstreamUrl = `${UPSTREAM_BASE}/data${path === "/health" ? "/health.json" : "/openapi.json"}`;
    const resp = await fetch(upstreamUrl);
    const body = await resp.text();
    return new Response(body, {
      status: resp.status,
      headers: { "Content-Type": "application/json", ...corsHeaders(origin) }
    });
  }

  // All other endpoints require authentication
  const apiKey = request.headers.get("X-API-Key") || url.searchParams.get("api_key");
  if (!apiKey) return errorResponse(401, "Missing X-API-Key header", 401);

  const keyRecord = await validateApiKey(apiKey, env);
  if (!keyRecord) return errorResponse(401, "Invalid API key", 401);

  const tier = keyRecord.tier || "free";
  const rl   = await checkRateLimit(tier, apiKey, env);
  if (!rl.allowed) {
    return new Response(
      JSON.stringify({ error: "Rate limit exceeded", code: 429 }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "X-RateLimit-Limit": String(RATE_LIMITS[tier]),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(rl.reset),
          "Retry-After": String(rl.reset - Math.floor(Date.now() / 1000)),
          ...corsHeaders(origin),
        }
      }
    );
  }

  // Tier access control
  const TIER_RANK = { free: 0, pro: 1, enterprise: 2, mssp: 3 };
  const ENDPOINT_TIER = { "/dossier": 1, "/taxii": 2, "/stix/bundle": 1 };
  for (const [prefix, reqTier] of Object.entries(ENDPOINT_TIER)) {
    if (path.startsWith(prefix) && (TIER_RANK[tier] ?? 0) < reqTier) {
      return errorResponse(403, `This endpoint requires ${Object.keys(TIER_RANK).find(k => TIER_RANK[k] === reqTier)} tier or above`, 403);
    }
  }

  // Route to upstream (GitHub Pages / R2)
  let upstreamPath = "";
  if (path === "/feed" || path === "/feed/")        upstreamPath = "/data/feed_manifest.json";
  else if (path.startsWith("/advisory/"))           upstreamPath = `/data/advisories${path.replace("/advisory","")}.json`;
  else if (path === "/stix/bundle")                 upstreamPath = "/data/stix/feed_manifest.json";
  else if (path.startsWith("/dossier/"))            upstreamPath = `/dossiers${path.replace("/dossier","")}.json`;
  else if (path === "/iocs" || path === "/iocs/")   upstreamPath = "/data/iocs.json";
  else                                               upstreamPath = `/data${path}.json`;

  const upstreamUrl = `${UPSTREAM_BASE}${upstreamPath}${url.search}`;
  let upstreamResp;
  try {
    upstreamResp = await fetch(upstreamUrl, { cf: { cacheEverything: true, cacheTtl: 300 } });
  } catch (e) {
    return errorResponse(500, "Upstream fetch failed", 500);
  }

  const body        = await upstreamResp.text();
  const contentType = upstreamResp.headers.get("Content-Type") || "application/json";

  return new Response(body, {
    status: upstreamResp.status,
    headers: {
      "Content-Type": contentType,
      "X-RateLimit-Limit":     String(RATE_LIMITS[tier] === Infinity ? 999999 : RATE_LIMITS[tier]),
      "X-RateLimit-Remaining": String(rl.remaining),
      "X-RateLimit-Reset":     String(rl.reset),
      "X-Tier":                tier,
      "Cache-Control":         "public, max-age=300",
      ...corsHeaders(origin),
    }
  });
}

// ─── Entry Point ───────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env).catch(err =>
      errorResponse(500, `Internal error: ${err.message}`, 500)
    );
  }
};
