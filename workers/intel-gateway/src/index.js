// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Edge Intelligence Gateway v109.0
// LOCKDOWN + R2 ARCHITECTURE
// Data flow: GitHub Actions → Cloudflare R2 (private) → Worker → API clients
// Intel data NEVER stored in public GitHub repo.
// Secrets: ADMIN_SECRET, GITHUB_TOKEN (set via: npx wrangler secret put)
// =============================================================================

const CONFIG = {
  GATEWAY_VERSION: "109.0",
  GATEWAY_NAME: "SENTINEL-APEX",
  BYPASS_FEED_CACHE: false,
  CACHE_TTL: { FEED: 180, REPORT: 3600, CRITICAL: 90, HEALTH: 30 },
  TIERS: { FREE: "free", PREMIUM: "premium", ENTERPRISE: "enterprise" },
  RATE_LIMITS:  { free: 60,  premium: 500,  enterprise: 2000 },
  FEED_LIMITS:  { free: 20,  premium: 500,  enterprise: 2000 },
  IP_RATE_LIMIT: 200,
  ABUSE_BAN_THRESHOLD: 50,
  ANALYTICS_TTL: 60 * 60 * 24 * 90,
  GITHUB_REPO: "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM",
  GITHUB_BRANCH: "main",
  MANIFEST_PATH: "data/stix/feed_manifest.json",
  DOCS_URL: "https://intel.cyberdudebivash.com/api-docs",
};
// ── Utilities ──────────────────────────────────────────────────────────────────

function generateReqId() {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return "req_" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function sha256hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Gateway": `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, X-Api-Key, Content-Type",
      ...extraHeaders,
    },
  });
}

function extractApiKey(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) { const k = auth.slice(7).trim(); if (k) return k; }
  const xkey = request.headers.get("X-Api-Key");
  if (xkey?.trim()) return xkey.trim();
  const qp = new URL(request.url).searchParams.get("api_key");
  if (qp?.trim()) return qp.trim();
  return null;
}

function getClientIP(request) {
  return request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
}

async function hashIP(ip) {
  return (await sha256hex("ip:" + ip)).slice(0, 16);
}

// ── Rate Limiting — Sliding Window ────────────────────────────────────────────

async function slidingWindowCheck(prefix, id, limitPerMin, kv) {
  if (!kv) return { allowed: true, remaining: limitPerMin, limit: limitPerMin };
  const now = Date.now();
  const curr = Math.floor(now / 60000);
  const prev = curr - 1;
  const elapsed = now % 60000;
  const [cv, pv] = await Promise.all([kv.get(`${prefix}:${id}:${curr}`), kv.get(`${prefix}:${id}:${prev}`)]);
  const cc = parseInt(cv || "0"), pc = parseInt(pv || "0");
  const sliding = Math.floor(pc * (1 - elapsed / 60000)) + cc;
  if (sliding >= limitPerMin) {
    return { allowed: false, remaining: 0, limit: limitPerMin, retryAfter: Math.ceil((60000 - elapsed) / 1000) };
  }
  await kv.put(`${prefix}:${id}:${curr}`, String(cc + 1), { expirationTtl: 120 });
  return { allowed: true, remaining: limitPerMin - sliding - 1, limit: limitPerMin };
}

// ── API Key Resolution — v109 HARD LOCKDOWN ────────────────────────────────────

async function resolveApiKey(request, env) {
  const rawKey = extractApiKey(request);
  if (!rawKey) return { valid: false, reason: "key_required" };
  if (!env?.API_KEYS_KV) return { valid: false, reason: "auth_unavailable" };
  try {
    const hash = await sha256hex(rawKey);
    const keyId = hash.slice(0, 16);
    const stored = await env.API_KEYS_KV.get(`apikey:${keyId}`, { type: "json" });
    if (!stored) return { valid: false, key_id: keyId, reason: "invalid_key" };
    if (stored.expires_at && new Date(stored.expires_at) < new Date()) return { valid: false, key_id: keyId, reason: "key_expired" };
    if (stored.revoked) return { valid: false, key_id: keyId, reason: "key_revoked" };
    return { valid: true, tier: stored.tier || CONFIG.TIERS.FREE, key_id: keyId, label: stored.label, created_at: stored.created_at };
  } catch { return { valid: false, reason: "auth_error" }; }
}

// ── Abuse Tracking ────────────────────────────────────────────────────────────

async function trackAbuseAttempt(ip, env) {
  if (!env?.RATE_LIMIT_KV) return;
  const h = await hashIP(ip);
  const k = `abuse:${h}:${Math.floor(Date.now() / 86400000)}`;
  const v = parseInt(await env.RATE_LIMIT_KV.get(k) || "0");
  await env.RATE_LIMIT_KV.put(k, String(v + 1), { expirationTtl: 86400 }).catch(() => {});
}

async function isIPBanned(ip, env) {
  if (!env?.RATE_LIMIT_KV) return false;
  const h = await hashIP(ip);
  const k = `abuse:${h}:${Math.floor(Date.now() / 86400000)}`;
  return parseInt(await env.RATE_LIMIT_KV.get(k) || "0") >= CONFIG.ABUSE_BAN_THRESHOLD;
}

// ── Analytics ─────────────────────────────────────────────────────────────────

async function recordAnalytics(env, keyId, endpoint, tier, code) {
  if (!env?.ANALYTICS_KV) return;
  try {
    const d = new Date().toISOString().slice(0, 10);
    const ttl = CONFIG.ANALYTICS_TTL;
    const inc = async (k) => {
      const v = parseInt(await env.ANALYTICS_KV.get(k) || "0");
      await env.ANALYTICS_KV.put(k, String(v + 1), { expirationTtl: ttl });
    };
    await Promise.all([
      inc(`analytics:day:${d}:${endpoint}`),
      inc(`analytics:tier:${d}:${tier}`),
      inc(`analytics:status:${d}:${code}`),
      keyId ? inc(`analytics:key:${keyId}:${d}`) : Promise.resolve(),
    ]);
  } catch { /* non-critical */ }
}

// ── Data Layer: R2 → KV Cache → GitHub Fallback ───────────────────────────────

function normaliseManifestData(data) {
  if (!data) return null;
  let items = null;
  if (Array.isArray(data.advisories) && data.advisories.length > 0) items = data.advisories;
  else if (Array.isArray(data.reports) && data.reports.length > 0) items = data.reports;
  else if (Array.isArray(data) && data.length > 0) items = data;
  else if (Array.isArray(data.items) && data.items.length > 0) items = data.items;
  else if (Array.isArray(data.entries) && data.entries.length > 0) items = data.entries;
  else if (Array.isArray(data.feed) && data.feed.length > 0) items = data.feed;
  else if (Array.isArray(data.data) && data.data.length > 0) items = data.data;
  if (!items || items.length === 0) return null;
  return {
    reports: items,
    generated_at: data.generated_at || new Date().toISOString(),
    total_reports: items.length,
    source_meta: { version: data.version || "unknown", platform: data.platform || "SENTINEL-APEX", entry_count: items.length },
  };
}

async function fetchFromGitHub(path, env, bypassCache = false) {
  const url = `https://raw.githubusercontent.com/${CONFIG.GITHUB_REPO}/${CONFIG.GITHUB_BRANCH}/${path}`;
  const headers = { "User-Agent": `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`, "Accept": "application/json" };
  if (env?.GITHUB_TOKEN) headers["Authorization"] = `token ${env.GITHUB_TOKEN}`;
  const cfOpts = bypassCache ? { cf: { cacheEverything: false, cacheTtl: 0 } } : { cf: { cacheEverything: true, cacheTtl: 300 } };
  const res = await fetch(url, { headers, ...cfOpts });
  if (!res.ok) {
    const hint = res.status === 404 && !env?.GITHUB_TOKEN ? " (Set GITHUB_TOKEN: npx wrangler secret put GITHUB_TOKEN)" : "";
    throw new Error(`GitHub HTTP ${res.status}${hint}`);
  }
  return res.json();
}

async function fetchReportsIndex(env) {
  const cacheKey = "idx:reports";
  // SOURCE 1: Cloudflare R2 (primary — private, no public exposure)
  if (env?.INTEL_R2) {
    try {
      const obj = await env.INTEL_R2.get("intel/feed_manifest.json");
      if (obj) {
        const raw = await obj.json();
        const norm = normaliseManifestData(raw);
        if (norm?.reports?.length > 0) {
          if (env.RATE_LIMIT_KV) await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(norm), { expirationTtl: CONFIG.CACHE_TTL.FEED }).catch(() => {});
          return norm;
        }
      }
    } catch (e) { console.error("[R2]", e.message); }
  }
  // SOURCE 2: KV warm cache
  if (env?.RATE_LIMIT_KV && !CONFIG.BYPASS_FEED_CACHE) {
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey, { type: "json" });
      if (cached?.reports?.length > 0) return cached;
      if (cached !== null) await env.RATE_LIMIT_KV.delete(cacheKey).catch(() => {});
    } catch { /* fall through */ }
  }
  // SOURCE 3: GitHub raw (fallback — GITHUB_TOKEN required for private repo)
  const raw = await fetchFromGitHub(CONFIG.MANIFEST_PATH, env, true);
  const norm = normaliseManifestData(raw);
  if (!norm?.reports?.length) throw new Error("Manifest empty. Seed R2 bucket or ensure GITHUB_TOKEN is set.");
  if (env?.RATE_LIMIT_KV) await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(norm), { expirationTtl: CONFIG.CACHE_TTL.FEED }).catch(() => {});
  return norm;
}

// ── Upgrade CTAs ──────────────────────────────────────────────────────────────

function getUpgradeCTA(tier) {
  if (tier === CONFIG.TIERS.ENTERPRISE) return null;
  if (tier === CONFIG.TIERS.PREMIUM) return { message: "Upgrade to Enterprise for unlimited access + SLA", upgrade_url: "https://cyberdudebivash.com/sentinel-enterprise" };
  return { message: `Free tier: ${CONFIG.FEED_LIMITS.free} items/req. Premium: ${CONFIG.FEED_LIMITS.premium}.`, upgrade_url: "https://cyberdudebivash.com/sentinel-premium", benefits: ["500 items/req", "500 req/min", "Priority support"] };
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async function handleFeed(request, env, auth, rid) {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || String(CONFIG.FEED_LIMITS[auth.tier])), CONFIG.FEED_LIMITS[auth.tier]);
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1"));
  const severity = url.searchParams.get("severity");
  const search = url.searchParams.get("q");
  try {
    const index = await fetchReportsIndex(env);
    let items = index.reports;
    if (severity) { const s = severity.toLowerCase(); items = items.filter(r => (r.severity || r.risk_level || r.cvss_severity || "").toLowerCase() === s); }
    if (search) { const q = search.toLowerCase(); items = items.filter(r => (r.title || r.name || r.id || "").toLowerCase().includes(q) || (r.description || r.summary || "").toLowerCase().includes(q) || (r.cve_id || "").toLowerCase().includes(q)); }
    const total = items.length, totalPages = Math.ceil(total / limit) || 1, offset = (page - 1) * limit;
    const pageItems = items.slice(offset, offset + limit);
    const resp = {
      status: "ok", gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`, request_id: rid, tier: auth.tier,
      data: {
        reports: pageItems,
        pagination: { page, limit, total_items: total, total_pages: totalPages, has_next: page < totalPages, has_prev: page > 1 },
        meta: { generated_at: index.generated_at, total_in_feed: index.total_reports, filtered_total: total, source_meta: index.source_meta },
      },
    };
    const cta = getUpgradeCTA(auth.tier);
    if (cta) resp.upgrade = cta;
    await recordAnalytics(env, auth.key_id, "feed", auth.tier, 200);
    return jsonResponse(resp);
  } catch (err) {
    console.error("[handleFeed]", err.message);
    await recordAnalytics(env, auth.key_id, "feed_error", auth.tier, 503);
    return jsonResponse({ error: "upstream_error", message: "Unable to fetch intelligence feed. Please try again shortly.", request_id: rid, docs: CONFIG.DOCS_URL, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` }, 503);
  }
}

async function handleReport(request, env, auth, rid, reportId) {
  const cacheKey = `report:${reportId}`;
  if (env?.RATE_LIMIT_KV) {
    const cached = await env.RATE_LIMIT_KV.get(cacheKey, { type: "json" }).catch(() => null);
    if (cached) { await recordAnalytics(env, auth.key_id, "report_cached", auth.tier, 200); return jsonResponse({ status: "ok", request_id: rid, tier: auth.tier, data: cached, cached: true, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` }); }
  }
  try {
    const index = await fetchReportsIndex(env);
    const report = index.reports.find(r => r.id === reportId || r.cve_id === reportId || r.advisory_id === reportId);
    if (!report) { await recordAnalytics(env, auth.key_id, "report_404", auth.tier, 404); return jsonResponse({ error: "not_found", message: `Report '${reportId}' not found.`, request_id: rid, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` }, 404); }
    const ttl = (report.severity || "").toLowerCase() === "critical" ? CONFIG.CACHE_TTL.CRITICAL : CONFIG.CACHE_TTL.REPORT;
    if (env?.RATE_LIMIT_KV) await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(report), { expirationTtl: ttl }).catch(() => {});
    await recordAnalytics(env, auth.key_id, "report", auth.tier, 200);
    return jsonResponse({ status: "ok", request_id: rid, tier: auth.tier, data: report, cached: false, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` });
  } catch { return jsonResponse({ error: "upstream_error", message: "Unable to retrieve report.", request_id: rid, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` }, 503); }
}

async function handleHealth(request, env, rid) {
  const checks = { gateway: "ok", kv_rate_limit: "unknown", kv_api_keys: "unknown", r2_intel: "unknown", feed_index: "unknown" };
  if (env?.RATE_LIMIT_KV) { try { await env.RATE_LIMIT_KV.put("health:ping", "1", { expirationTtl: 10 }); checks.kv_rate_limit = "ok"; } catch { checks.kv_rate_limit = "error"; } } else checks.kv_rate_limit = "not_bound";
  if (env?.API_KEYS_KV) { try { await env.API_KEYS_KV.get("health:ping"); checks.kv_api_keys = "ok"; } catch { checks.kv_api_keys = "error"; } } else checks.kv_api_keys = "not_bound";
  if (env?.INTEL_R2) { try { const m = await env.INTEL_R2.head("intel/feed_manifest.json"); checks.r2_intel = m ? "ok" : "empty"; } catch { checks.r2_intel = "error"; } } else checks.r2_intel = "not_bound";
  if (env?.RATE_LIMIT_KV) { try { const c = await env.RATE_LIMIT_KV.get("idx:reports", { type: "json" }); checks.feed_index = c?.total_reports > 0 ? `cached:${c.total_reports}_items` : "not_cached"; } catch { checks.feed_index = "error"; } }
  const allOk = Object.values(checks).every(v => v === "ok" || v.startsWith("cached:"));
  return jsonResponse({ status: allOk ? "healthy" : "degraded", version: CONFIG.GATEWAY_VERSION, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`, timestamp: new Date().toISOString(), checks, request_id: rid }, allOk ? 200 : 207);
}

async function handleValidateKey(request, env, rid) {
  const rawKey = extractApiKey(request);
  if (!rawKey) return jsonResponse({ valid: false, reason: "No API key provided", request_id: rid }, 400);
  const auth = await resolveApiKey(request, env);
  if (auth.valid) return jsonResponse({ valid: true, tier: auth.tier, key_id: auth.key_id, label: auth.label, created_at: auth.created_at, request_id: rid });
  return jsonResponse({ valid: false, reason: auth.reason, request_id: rid }, 401);
}

async function handleAnalytics(request, env, auth, rid) {
  if (!env?.ANALYTICS_KV) return jsonResponse({ error: "analytics_unavailable", request_id: rid }, 503);
  const today = new Date().toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  const [tf, te, yf, kt] = await Promise.all([env.ANALYTICS_KV.get(`analytics:day:${today}:feed`), env.ANALYTICS_KV.get(`analytics:day:${today}:feed_error`), env.ANALYTICS_KV.get(`analytics:day:${yesterday}:feed`), auth.key_id ? env.ANALYTICS_KV.get(`analytics:key:${auth.key_id}:${today}`) : Promise.resolve(null)]);
  return jsonResponse({ status: "ok", request_id: rid, tier: auth.tier, analytics: { today: { date: today, feed_requests: parseInt(tf || "0"), errors: parseInt(te || "0") }, yesterday: { date: yesterday, feed_requests: parseInt(yf || "0") }, your_key: { today_requests: parseInt(kt || "0"), key_id: auth.key_id } }, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` });
}

async function handleCacheBust(request, env, rid) {
  const secret = env?.ADMIN_SECRET;
  const provided = request.headers.get("X-Admin-Secret");
  if (!secret || provided !== secret) return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
  const key = (new URL(request.url).searchParams.get("key") || "idx:reports").replace(/[^a-z0-9_:\-\.]/gi, "");
  if (!env?.RATE_LIMIT_KV) return jsonResponse({ error: "kv_unavailable", request_id: rid }, 503);
  await env.RATE_LIMIT_KV.delete(key);
  return jsonResponse({ success: true, key, deleted: true, timestamp: new Date().toISOString(), request_id: rid });
}

async function handleAdminCreateKey(request, env, rid) {
  const secret = env?.ADMIN_SECRET;
  const provided = request.headers.get("X-Admin-Secret");
  if (!secret || provided !== secret) return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "kv_unavailable", request_id: rid }, 503);
  let body; try { body = await request.json(); } catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }
  const tier = body.tier || CONFIG.TIERS.FREE;
  if (!Object.values(CONFIG.TIERS).includes(tier)) return jsonResponse({ error: "invalid_tier", valid_tiers: Object.values(CONFIG.TIERS), request_id: rid }, 400);
  const rawBytes = crypto.getRandomValues(new Uint8Array(32));
  const rawKey = "CDB-" + tier.toUpperCase().slice(0, 3) + "-" + Array.from(rawBytes).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32).toUpperCase();
  const hash = await sha256hex(rawKey);
  const keyId = hash.slice(0, 16);
  const record = { tier, label: body.label || "API Key", key_id: keyId, created_at: new Date().toISOString(), expires_at: body.expires_at || null, revoked: false };
  await env.API_KEYS_KV.put(`apikey:${keyId}`, JSON.stringify(record));
  return jsonResponse({ success: true, api_key: rawKey, key_id: keyId, tier, label: record.label, created_at: record.created_at, warning: "Store this key securely — it cannot be retrieved again.", request_id: rid }, 201);
}

// ── Main Router ────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const rid = generateReqId();
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method.toUpperCase();

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Authorization, X-Api-Key, Content-Type, X-Admin-Secret", "Access-Control-Max-Age": "86400" } });
    }

    // IP rate limiting + abuse check (all endpoints)
    const clientIP = getClientIP(request);
    if (await isIPBanned(clientIP, env)) return jsonResponse({ error: "ip_banned", message: "Your IP has been temporarily blocked.", request_id: rid }, 429);
    const ipHash = await hashIP(clientIP);
    const ipCheck = await slidingWindowCheck("ip", ipHash, CONFIG.IP_RATE_LIMIT, env?.RATE_LIMIT_KV);
    if (!ipCheck.allowed) return jsonResponse({ error: "ip_rate_limited", message: "Too many requests from this IP.", retry_after: ipCheck.retryAfter, request_id: rid }, 429, { "Retry-After": String(ipCheck.retryAfter || 60) });

    // ── Public endpoints ──────────────────────────────────────────────────────
    if (pathname.startsWith("/api/health")) return handleHealth(request, env, rid);
    if (pathname.startsWith("/api/keys/validate")) return handleValidateKey(request, env, rid);

    // ── Admin endpoints (X-Admin-Secret verified internally) ─────────────────
    if (pathname.startsWith("/api/admin/cache/bust") && method === "POST") return handleCacheBust(request, env, rid);
    if (pathname.startsWith("/api/admin/keys/create") && method === "POST") return handleAdminCreateKey(request, env, rid);
    if (pathname.startsWith("/api/admin")) {
      if (!env?.ADMIN_SECRET || request.headers.get("X-Admin-Secret") !== env.ADMIN_SECRET) return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
      return jsonResponse({ error: "not_found", message: "Admin endpoint not found.", available: ["/api/admin/cache/bust", "/api/admin/keys/create"], request_id: rid }, 404);
    }

    // ── ALL OTHER ENDPOINTS: API KEY REQUIRED (v109 LOCKDOWN) ────────────────
    const auth = await resolveApiKey(request, env);
    if (!auth.valid) {
      if (auth.reason === "invalid_key" || auth.reason === "key_expired") await trackAbuseAttempt(clientIP, env);
      return jsonResponse({ error: auth.reason === "key_required" ? "api_key_required" : "unauthorized", message: auth.reason === "key_required" ? "API key required. Use: Authorization: Bearer <key>" : `API key rejected: ${auth.reason}`, reason: auth.reason, acquire_key: "https://intel.cyberdudebivash.com/get-api-key", docs: CONFIG.DOCS_URL, request_id: rid }, 401);
    }

    // Per-key rate limiting
    const rateLimit = CONFIG.RATE_LIMITS[auth.tier] || CONFIG.RATE_LIMITS.free;
    const keyCheck = await slidingWindowCheck("key", auth.key_id, rateLimit, env?.RATE_LIMIT_KV);
    if (!keyCheck.allowed) {
      await recordAnalytics(env, auth.key_id, "rate_limited", auth.tier, 429);
      return jsonResponse({ error: "rate_limited", message: `Rate limit exceeded. ${auth.tier}: ${rateLimit} req/min.`, limit: keyCheck.limit, retry_after: keyCheck.retryAfter, request_id: rid, upgrade: getUpgradeCTA(auth.tier) }, 429, { "Retry-After": String(keyCheck.retryAfter || 60), "X-RateLimit-Remaining": "0" });
    }

    if (pathname === "/api/feed" && method === "GET") return handleFeed(request, env, auth, rid);
    if (pathname.startsWith("/api/feed/") && method === "GET") { const id = decodeURIComponent(pathname.slice("/api/feed/".length)); if (id) return handleReport(request, env, auth, rid, id); }
    if (pathname.startsWith("/api/analytics") && method === "GET") return handleAnalytics(request, env, auth, rid);

    return jsonResponse({ error: "not_found", message: `Endpoint '${pathname}' not found.`, available: ["GET /api/feed", "GET /api/feed/:id", "GET /api/health", "GET /api/analytics", "GET /api/keys/validate", "POST /api/admin/cache/bust", "POST /api/admin/keys/create"], docs: CONFIG.DOCS_URL, request_id: rid, gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` }, 404);
  },
};
