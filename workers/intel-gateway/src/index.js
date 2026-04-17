// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Edge Intelligence Gateway v112.0
// R2-ONLY ARCHITECTURE — Blogger dependency REMOVED
// Data flow: GitHub Actions → Cloudflare R2 (private) → Worker → API clients
// Intel data NEVER stored in public GitHub repo (EMBEDDED_INTEL obsolete).
// Secrets: ADMIN_SECRET, GITHUB_TOKEN (set via: npx wrangler secret put)
// v112.0: Added /api/ai endpoint family (AI panels, MITRE heatmap, risk engine)
// =============================================================================

const CONFIG = {
  GATEWAY_VERSION:   "112.1",  // v112.1: P0 FIX — sort preview by timestamp DESC + risk DESC
  GATEWAY_NAME:      "SENTINEL-APEX",
  BYPASS_FEED_CACHE: false,
  // P0 FIX v111.0: Reduced cache TTLs to ensure dashboard reflects fresh R2 data
  // quickly after each pipeline run. KV cache is busted by workflow on every run.
  CACHE_TTL: {
    FEED:    60,    // seconds — authenticated feed (was 180, reduced for freshness)
    PREVIEW: 90,    // seconds — public preview (was 300, reduced to 90s)
    REPORT:  1800,
    CRITICAL: 60,
    HEALTH:   15,
  },
  TIERS: {
    FREE:       "free",
    PREMIUM:    "premium",
    ENTERPRISE: "enterprise",
  },
  RATE_LIMITS: { free: 60,   premium: 500,  enterprise: 2000 },
  FEED_LIMITS: { free: 20,   premium: 500,  enterprise: 2000 },
  PREVIEW_LIMIT:       10,   // public preview items
  IP_RATE_LIMIT:       200,
  ABUSE_BAN_THRESHOLD: 50,
  ANALYTICS_TTL:       60 * 60 * 24 * 90,  // 90 days
  GITHUB_REPO:         "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM",
  GITHUB_BRANCH:       "main",
  MANIFEST_PATH:       "data/stix/feed_manifest.json",
  DOCS_URL:            "https://intel.cyberdudebivash.com/api-docs",
  GET_KEY_URL:         "https://intel.cyberdudebivash.com/get-api-key",
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
      "Content-Type":                "application/json",
      "X-Gateway":                   `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      // P0 FIX v111.0: Prevent browser/CDN caching of intel responses.
      // Worker KV TTL is the authoritative cache layer.
      "Cache-Control":               "no-cache, no-store, must-revalidate",
      "Pragma":                      "no-cache",
      "Expires":                     "0",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods":"GET, POST, OPTIONS",
      "Access-Control-Allow-Headers":"Authorization, X-Api-Key, Content-Type, X-Admin-Secret",
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
  const now     = Date.now();
  const curr    = Math.floor(now / 60000);
  const prev    = curr - 1;
  const elapsed = now % 60000;
  const [cv, pv] = await Promise.all([
    kv.get(`${prefix}:${id}:${curr}`),
    kv.get(`${prefix}:${id}:${prev}`),
  ]);
  const cc = parseInt(cv || "0"), pc = parseInt(pv || "0");
  const sliding = Math.floor(pc * (1 - elapsed / 60000)) + cc;
  if (sliding >= limitPerMin) {
    return { allowed: false, remaining: 0, limit: limitPerMin,
             retryAfter: Math.ceil((60000 - elapsed) / 1000) };
  }
  await kv.put(`${prefix}:${id}:${curr}`, String(cc + 1), { expirationTtl: 120 });
  return { allowed: true, remaining: limitPerMin - sliding - 1, limit: limitPerMin };
}

// ── API Key Resolution ─────────────────────────────────────────────────────────

async function resolveApiKey(request, env) {
  const rawKey = extractApiKey(request);
  if (!rawKey) return { valid: false, reason: "key_required" };
  if (!env?.API_KEYS_KV) return { valid: false, reason: "auth_unavailable" };
  try {
    const hash    = await sha256hex(rawKey);
    const keyId   = hash.slice(0, 16);
    const stored  = await env.API_KEYS_KV.get(`apikey:${keyId}`, { type: "json" });
    if (!stored) return { valid: false, key_id: keyId, reason: "invalid_key" };
    if (stored.expires_at && new Date(stored.expires_at) < new Date())
      return { valid: false, key_id: keyId, reason: "key_expired" };
    if (stored.revoked)
      return { valid: false, key_id: keyId, reason: "key_revoked" };
    return {
      valid:      true,
      tier:       stored.tier || CONFIG.TIERS.FREE,
      key_id:     keyId,
      label:      stored.label,
      created_at: stored.created_at,
    };
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
    const d   = new Date().toISOString().slice(0, 10);
    const ttl = CONFIG.ANALYTICS_TTL;
    const inc = async (k) => {
      const v = parseInt(await env.ANALYTICS_KV.get(k) || "0");
      await env.ANALYTICS_KV.put(k, String(v + 1), { expirationTtl: ttl });
    };
    await Promise.all([
      inc(`analytics:day:${d}:${endpoint}`),
      inc(`analytics:tier:${d}:${tier || "anon"}`),
      inc(`analytics:status:${d}:${code}`),
      keyId ? inc(`analytics:key:${keyId}:${d}`) : Promise.resolve(),
    ]);
  } catch { /* non-critical */ }
}

// ── Data Layer: R2 → KV Cache → GitHub Fallback ───────────────────────────────

function normaliseManifestData(data) {
  if (!data) return null;
  let items = null;
  if (Array.isArray(data.advisories) && data.advisories.length > 0)  items = data.advisories;
  else if (Array.isArray(data.reports)  && data.reports.length > 0)  items = data.reports;
  else if (Array.isArray(data)          && data.length > 0)           items = data;
  else if (Array.isArray(data.items)    && data.items.length > 0)     items = data.items;
  else if (Array.isArray(data.entries)  && data.entries.length > 0)   items = data.entries;
  else if (Array.isArray(data.feed)     && data.feed.length > 0)      items = data.feed;
  else if (Array.isArray(data.data)     && data.data.length > 0)      items = data.data;
  if (!items || items.length === 0) return null;
  return {
    reports:     items,
    generated_at: data.generated_at || new Date().toISOString(),
    total_reports: items.length,
    source_meta: {
      version:     data.version     || "unknown",
      platform:    data.platform    || "SENTINEL-APEX",
      entry_count: items.length,
    },
  };
}

async function fetchFromGitHub(path, env, bypassCache = false) {
  const url     = `https://raw.githubusercontent.com/${CONFIG.GITHUB_REPO}/${CONFIG.GITHUB_BRANCH}/${path}`;
  const headers = {
    "User-Agent": `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    "Accept":     "application/json",
  };
  if (env?.GITHUB_TOKEN) headers["Authorization"] = `token ${env.GITHUB_TOKEN}`;
  const cfOpts  = bypassCache
    ? { cf: { cacheEverything: false, cacheTtl: 0 } }
    : { cf: { cacheEverything: true,  cacheTtl: 300 } };
  const res = await fetch(url, { headers, ...cfOpts });
  if (!res.ok) {
    const hint = res.status === 404 && !env?.GITHUB_TOKEN
      ? " (GITHUB_TOKEN not set — set via: npx wrangler secret put GITHUB_TOKEN)"
      : "";
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
        const raw  = await obj.json();
        const norm = normaliseManifestData(raw);
        if (norm?.reports?.length > 0) {
          // Warm KV cache after successful R2 read
          if (env.RATE_LIMIT_KV) {
            await env.RATE_LIMIT_KV.put(
              cacheKey,
              JSON.stringify(norm),
              { expirationTtl: CONFIG.CACHE_TTL.FEED }
            ).catch(() => {});
          }
          return norm;
        }
      }
    } catch (e) { console.error("[R2]", e.message); }
  }

  // SOURCE 2: KV warm cache (avoids R2 egress on repeated requests)
  if (env?.RATE_LIMIT_KV && !CONFIG.BYPASS_FEED_CACHE) {
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey, { type: "json" });
      if (cached?.reports?.length > 0) return cached;
      if (cached !== null) await env.RATE_LIMIT_KV.delete(cacheKey).catch(() => {});
    } catch { /* fall through */ }
  }

  // SOURCE 3: GitHub raw (emergency fallback — GITHUB_TOKEN required for private repo)
  const raw  = await fetchFromGitHub(CONFIG.MANIFEST_PATH, env, true);
  const norm = normaliseManifestData(raw);
  if (!norm?.reports?.length) {
    throw new Error(
      "Manifest empty after all sources exhausted. " +
      "Trigger R2 sync: Actions > R2 Intel Data Sync > Run workflow"
    );
  }
  if (env?.RATE_LIMIT_KV) {
    await env.RATE_LIMIT_KV.put(
      cacheKey,
      JSON.stringify(norm),
      { expirationTtl: CONFIG.CACHE_TTL.FEED }
    ).catch(() => {});
  }
  return norm;
}

// ── Upgrade CTAs ──────────────────────────────────────────────────────────────

function getUpgradeCTA(tier) {
  if (tier === CONFIG.TIERS.ENTERPRISE) return null;
  if (tier === CONFIG.TIERS.PREMIUM) {
    return {
      message:     "Upgrade to Enterprise for unlimited access + dedicated SLA",
      upgrade_url: "https://cyberdudebivash.com/sentinel-enterprise",
    };
  }
  return {
    message:     `Free tier: ${CONFIG.FEED_LIMITS.free} items/req. Upgrade to Premium for ${CONFIG.FEED_LIMITS.premium}+.`,
    upgrade_url: "https://cyberdudebivash.com/sentinel-premium",
    benefits:    ["500 items/req", "500 req/min", "Priority support", "Full CVE/IOC/TTP data"],
  };
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// ── PUBLIC: /api/preview — No API key required ────────────────────────────────
async function handlePreview(request, env, rid) {
  const cacheKey = "idx:preview";

  // Check KV preview cache (5 min TTL)
  if (env?.RATE_LIMIT_KV) {
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey, { type: "json" });
      if (cached) {
        await recordAnalytics(env, null, "preview_cached", "anon", 200);
        return jsonResponse({
          status:      "ok",
          gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
          request_id:  rid,
          preview:     cached,
          get_api_key: CONFIG.GET_KEY_URL,
          docs:        CONFIG.DOCS_URL,
          cached:      true,
        });
      }
    } catch { /* fall through */ }
  }

  try {
    const index     = await fetchReportsIndex(env);
    // Filter: remove brand/identity entries and deduplicate by title
    const seenTitles = new Set();
    const cleanItems = index.reports.filter(item => {
      const t = (item.title || "").trim();
      if (!t) return false;
      // Remove company branding entries that got into the feed
      if (t.includes("CYBERDUDEBIVASH® PRIVATE LIMITED") ||
          t.includes("OFFICIAL WORKPLACE") ||
          t.includes("GST & PAN VERIFIED")) return false;
      // Deduplicate by title
      if (seenTitles.has(t)) return false;
      seenTitles.add(t);
      return true;
    });
    // v112.1 P0 FIX: Sort by timestamp DESC (newest first), then risk_score DESC.
    // Without this, preview returns the first 10 items in manifest file order,
    // which are old bootstrap/historical entries with stale timestamps and low risk scores.
    // pipeline writes oldest entries first → new entries appended at end → slice(0,10) = always stale.
    cleanItems.sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      if (tb !== ta) return tb - ta;
      const ra = typeof a.risk_score === 'number' ? a.risk_score
               : typeof a.cvss_score === 'number' ? a.cvss_score : 0;
      const rb = typeof b.risk_score === 'number' ? b.risk_score
               : typeof b.cvss_score === 'number' ? b.cvss_score : 0;
      return rb - ra;
    });
    const allItems  = cleanItems;
    const preview   = allItems.slice(0, CONFIG.PREVIEW_LIMIT).map(item => {
      // P0 FIX v111.0: Include full MITRE/TTP/IOC data in preview response.
      // Previously stripped — caused MITRE=0 on dashboard.
      let rawDesc = item.description || item.summary || "";
      rawDesc = rawDesc.replace(/^Tactical cluster:\s*/i, "").trim();
      if (!rawDesc) rawDesc = item.title || "";
      const iocCount = Array.isArray(item.iocs) ? item.iocs.length : 0;
      const ttpCount = Array.isArray(item.ttps) ? item.ttps.length : 0;
      const enrich   = [];
      if (iocCount > 0) enrich.push(`${iocCount} IOC${iocCount > 1 ? "s" : ""}`);
      if (ttpCount > 0) enrich.push(`${ttpCount} TTP${ttpCount > 1 ? "s" : ""}`);
      if (item.source) enrich.push(`Source: ${item.source}`);
      const description = enrich.length > 0 ? `${rawDesc} [${enrich.join(" | ")}]` : rawDesc;
      return {
        id:          item.id          || item.advisory_id || item.cve_id || "unknown",
        title:       item.title       || item.name         || item.cve_id || "Untitled",
        severity:    item.severity    || item.risk_level   || "UNKNOWN",
        description,
        tags:        item.tags        || item.categories   || [],
        threat_type: item.threat_type || item.type         || "General",
        risk_score:  typeof item.risk_score === "number" ? item.risk_score
                   : typeof item.cvss_score === "number" ? item.cvss_score : 0,
        // P0 FIX: Include full arrays (not just counts) for MITRE heatmap
        iocs:        Array.isArray(item.iocs)  ? item.iocs  : [],
        ttps:        Array.isArray(item.ttps)  ? item.ttps  : [],
        ioc_count:   iocCount,
        ttp_count:   ttpCount,
        confidence:  item.confidence  || 0,
        timestamp:   item.timestamp   || null,
        source:      item.source      || "SENTINEL-APEX",
        stix_bundle: item.stix_bundle || null,
        kev_present: item.kev_present || false,
        epss_score:  item.epss_score  || null,
        cvss_score:  item.cvss_score  || null,
      };
    });

    const previewPayload = {
      items:         preview,
      total_preview: preview.length,
      total_in_feed: allItems.length,
      generated_at:  index.generated_at,
      note:          `Preview: latest ${CONFIG.PREVIEW_LIMIT} of ${allItems.length} unique threat intel items. Get an API key for full access.`,
    };

    // Cache preview payload
    if (env?.RATE_LIMIT_KV) {
      await env.RATE_LIMIT_KV.put(
        cacheKey,
        JSON.stringify(previewPayload),
        { expirationTtl: CONFIG.CACHE_TTL.PREVIEW }
      ).catch(() => {});
    }

    await recordAnalytics(env, null, "preview", "anon", 200);
    return jsonResponse({
      status:      "ok",
      gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      request_id:  rid,
      preview:     previewPayload,
      get_api_key: CONFIG.GET_KEY_URL,
      docs:        CONFIG.DOCS_URL,
      cached:      false,
    });
  } catch (err_) {
    console.error("[handlePreview]", err_.message);
    await recordAnalytics(env, null, "preview_error", "anon", 503);
    return jsonResponse({
      error:      "upstream_error",
      message:    "Preview temporarily unavailable. Please try again shortly.",
      request_id: rid,
      docs:       CONFIG.DOCS_URL,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 503);
  }
}

// ── AUTHENTICATED: /api/feed ───────────────────────────────────────────────────
async function handleFeed(request, env, auth, rid) {
  const url      = new URL(request.url);
  const limit    = Math.min(
    parseInt(url.searchParams.get("limit") || String(CONFIG.FEED_LIMITS[auth.tier])),
    CONFIG.FEED_LIMITS[auth.tier]
  );
  const page     = Math.max(1, parseInt(url.searchParams.get("page") || "1"));
  const severity = url.searchParams.get("severity");
  const search   = url.searchParams.get("q");

  try {
    const index = await fetchReportsIndex(env);
    // Deduplicate and filter brand entries from the full feed
    const seenFeed = new Set();
    let items = index.reports.filter(item => {
      const t = (item.title || "").trim();
      if (!t) return false;
      if (t.includes("CYBERDUDEBIVASH® PRIVATE LIMITED") ||
          t.includes("OFFICIAL WORKPLACE") ||
          t.includes("GST & PAN VERIFIED")) return false;
      if (seenFeed.has(t)) return false;
      seenFeed.add(t);
      // Enrich description
      const raw = (item.description || "").replace(/^Tactical cluster:\s*/i, "").trim() || t;
      item.description = raw;
      return true;
    });

    if (severity) {
      const s = severity.toLowerCase();
      items = items.filter(r =>
        (r.severity || r.risk_level || r.cvss_severity || "").toLowerCase() === s
      );
    }
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(r =>
        (r.title || r.name || r.id || "").toLowerCase().includes(q) ||
        (r.description || r.summary || "").toLowerCase().includes(q) ||
        (r.cve_id || "").toLowerCase().includes(q)
      );
    }

    const total      = items.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const offset     = (page - 1) * limit;
    const pageItems  = items.slice(offset, offset + limit);

    const resp = {
      status:     "ok",
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      request_id: rid,
      tier:       auth.tier,
      data: {
        reports:    pageItems,
        pagination: {
          page,
          limit,
          total_items:  total,
          total_pages:  totalPages,
          has_next:     page < totalPages,
          has_prev:     page > 1,
        },
        meta: {
          generated_at:    index.generated_at,
          total_in_feed:   index.total_reports,
          filtered_total:  total,
          source_meta:     index.source_meta,
        },
      },
    };

    const cta = getUpgradeCTA(auth.tier);
    if (cta) resp.upgrade = cta;

    await recordAnalytics(env, auth.key_id, "feed", auth.tier, 200);
    return jsonResponse(resp);
  } catch (err_) {
    console.error("[handleFeed]", err_.message);
    await recordAnalytics(env, auth.key_id, "feed_error", auth.tier, 503);
    return jsonResponse({
      error:      "upstream_error",
      message:    "Unable to fetch intelligence feed. Please try again shortly.",
      request_id: rid,
      docs:       CONFIG.DOCS_URL,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 503);
  }
}

async function handleReport(request, env, auth, rid, reportId) {
  const cacheKey = `report:${reportId}`;
  if (env?.RATE_LIMIT_KV) {
    const cached = await env.RATE_LIMIT_KV.get(cacheKey, { type: "json" }).catch(() => null);
    if (cached) {
      await recordAnalytics(env, auth.key_id, "report_cached", auth.tier, 200);
      return jsonResponse({
        status:     "ok",
        request_id: rid,
        tier:       auth.tier,
        data:       cached,
        cached:     true,
        gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      });
    }
  }
  try {
    const index  = await fetchReportsIndex(env);
    const report = index.reports.find(
      r => r.id === reportId || r.cve_id === reportId || r.advisory_id === reportId
    );
    if (!report) {
      await recordAnalytics(env, auth.key_id, "report_404", auth.tier, 404);
      return jsonResponse({
        error:      "not_found",
        message:    `Report '${reportId}' not found.`,
        request_id: rid,
        gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      }, 404);
    }
    const ttl = (report.severity || "").toLowerCase() === "critical"
      ? CONFIG.CACHE_TTL.CRITICAL
      : CONFIG.CACHE_TTL.REPORT;
    if (env?.RATE_LIMIT_KV) {
      await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(report), { expirationTtl: ttl })
        .catch(() => {});
    }
    await recordAnalytics(env, auth.key_id, "report", auth.tier, 200);
    return jsonResponse({
      status:     "ok",
      request_id: rid,
      tier:       auth.tier,
      data:       report,
      cached:     false,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    });
  } catch {
    return jsonResponse({
      error:      "upstream_error",
      message:    "Unable to retrieve report.",
      request_id: rid,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 503);
  }
}

async function handleHealth(request, env, rid) {
  const checks = {
    gateway:       "ok",
    kv_rate_limit: "unknown",
    kv_api_keys:   "unknown",
    r2_intel:      "unknown",
    feed_index:    "unknown",
  };

  if (env?.RATE_LIMIT_KV) {
    try {
      await env.RATE_LIMIT_KV.put("health:ping", "1", { expirationTtl: 10 });
      checks.kv_rate_limit = "ok";
    } catch { checks.kv_rate_limit = "error"; }
  } else checks.kv_rate_limit = "not_bound";

  if (env?.API_KEYS_KV) {
    try { await env.API_KEYS_KV.get("health:ping"); checks.kv_api_keys = "ok"; }
    catch { checks.kv_api_keys = "error"; }
  } else checks.kv_api_keys = "not_bound";

  if (env?.INTEL_R2) {
    try {
      const m = await env.INTEL_R2.head("intel/feed_manifest.json");
      checks.r2_intel = m ? "ok" : "empty";
    } catch { checks.r2_intel = "error"; }
  } else checks.r2_intel = "not_bound";

  if (env?.RATE_LIMIT_KV) {
    try {
      const c = await env.RATE_LIMIT_KV.get("idx:reports", { type: "json" });
      checks.feed_index = c?.total_reports > 0
        ? `cached:${c.total_reports}_items`
        : "not_cached";
    } catch { checks.feed_index = "error"; }
  }

  const allOk = Object.values(checks).every(v => v === "ok" || v.startsWith("cached:"));
  return jsonResponse({
    status:     allOk ? "healthy" : "degraded",
    version:    CONFIG.GATEWAY_VERSION,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    timestamp:  new Date().toISOString(),
    checks,
    request_id: rid,
  }, allOk ? 200 : 207);
}

async function handleValidateKey(request, env, rid) {
  const rawKey = extractApiKey(request);
  if (!rawKey) return jsonResponse({ valid: false, reason: "No API key provided", request_id: rid }, 400);
  const auth = await resolveApiKey(request, env);
  if (auth.valid) {
    return jsonResponse({
      valid:      true,
      tier:       auth.tier,
      key_id:     auth.key_id,
      label:      auth.label,
      created_at: auth.created_at,
      request_id: rid,
    });
  }
  return jsonResponse({ valid: false, reason: auth.reason, request_id: rid }, 401);
}

async function handleAnalytics(request, env, auth, rid) {
  if (!env?.ANALYTICS_KV) return jsonResponse({ error: "analytics_unavailable", request_id: rid }, 503);
  const today     = new Date().toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  const [tf, te, yf, kt] = await Promise.all([
    env.ANALYTICS_KV.get(`analytics:day:${today}:feed`),
    env.ANALYTICS_KV.get(`analytics:day:${today}:feed_error`),
    env.ANALYTICS_KV.get(`analytics:day:${yesterday}:feed`),
    auth.key_id ? env.ANALYTICS_KV.get(`analytics:key:${auth.key_id}:${today}`) : Promise.resolve(null),
  ]);
  return jsonResponse({
    status:     "ok",
    request_id: rid,
    tier:       auth.tier,
    analytics: {
      today:     { date: today,     feed_requests: parseInt(tf || "0"), errors: parseInt(te || "0") },
      yesterday: { date: yesterday, feed_requests: parseInt(yf || "0") },
      your_key:  { today_requests: parseInt(kt || "0"), key_id: auth.key_id },
    },
    gateway: `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// ── AI Intelligence Endpoint — /api/ai/* ──────────────────────────────────────
// Serves AI analysis panels, MITRE heatmap data, and risk engine outputs.
// Data is generated by scripts/generate_ai_endpoints.py and uploaded to R2.

async function fetchAIData(env, r2Key, kvKey, ttlSeconds) {
  // SOURCE 1: KV cache (fast path)
  if (env?.RATE_LIMIT_KV) {
    try {
      const cached = await env.RATE_LIMIT_KV.get(kvKey, { type: "json" });
      if (cached) return { data: cached, cached: true };
    } catch { /* fall through */ }
  }
  // SOURCE 2: R2 (authoritative)
  if (env?.INTEL_R2) {
    try {
      const obj = await env.INTEL_R2.get(r2Key);
      if (obj) {
        const data = await obj.json();
        if (data && (data.panels || data.analysis || data.mitre_techniques || data.reports)) {
          // Warm KV cache
          if (env.RATE_LIMIT_KV) {
            await env.RATE_LIMIT_KV.put(kvKey, JSON.stringify(data), { expirationTtl: ttlSeconds })
              .catch(() => {});
          }
          return { data, cached: false };
        }
      }
    } catch (e) { console.error(`[R2-AI] ${r2Key}:`, e.message); }
  }
  // SOURCE 3: Derive AI data from the live feed (real-time fallback)
  // Build MITRE heatmap data from the feed manifest when R2 AI data is missing
  try {
    const index = await fetchReportsIndex(env);
    if (r2Key.includes("ai_index") || r2Key.includes("analyze")) {
      // Build live AI summary from feed
      const reports = index.reports || [];
      const mitreTech = {};
      const riskDist  = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      let totalIocs = 0, totalTtps = 0, kevCount = 0;
      for (const r of reports) {
        // MITRE technique frequency
        for (const ttp of (r.ttps || [])) {
          if (ttp) mitreTech[ttp] = (mitreTech[ttp] || 0) + 1;
        }
        const sev = (r.severity || "MEDIUM").toUpperCase();
        if (riskDist[sev] !== undefined) riskDist[sev]++;
        totalIocs += Array.isArray(r.iocs) ? r.iocs.length : 0;
        totalTtps += Array.isArray(r.ttps) ? r.ttps.length : 0;
        if (r.kev_present) kevCount++;
      }
      const topTechniques = Object.entries(mitreTech)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 25)
        .map(([technique, count]) => ({ technique, count }));
      const aiIndex = {
        version:      "112.0",
        generated_at: index.generated_at || new Date().toISOString(),
        platform:     "CYBERDUDEBIVASH SENTINEL APEX",
        ai_engine:    "APEX-v112",
        status:       "OPERATIONAL",
        derived_from: "live_feed",
        summary: {
          total_advisories: reports.length,
          severity_distribution: riskDist,
          total_iocs:  totalIocs,
          total_ttps:  totalTtps,
          kev_entries: kevCount,
          mitre_techniques_seen: Object.keys(mitreTech).length,
        },
        mitre_heatmap: {
          status:     "active",
          techniques: topTechniques,
          total_unique_techniques: Object.keys(mitreTech).length,
        },
        panels: {
          threat_analysis: {
            status:      "active",
            description: "AI-powered threat analysis using CVSSv3, EPSS, and MITRE ATT&CK",
            total_threats: reports.length,
            critical: riskDist.CRITICAL,
            high:     riskDist.HIGH,
          },
          risk_engine: {
            status:  "active",
            model:   "CDB-RISK-ENGINE-v23",
            factors: ["CVSSv3", "EPSS", "CISA_KEV", "MITRE_ATT&CK", "IOC_density", "actor_confidence"],
          },
          mitre_coverage: {
            status: "active",
            unique_techniques: Object.keys(mitreTech).length,
            top_techniques:    topTechniques.slice(0, 10),
          },
          ioc_intelligence: {
            status:     "active",
            total_iocs: totalIocs,
            kev_count:  kevCount,
          },
        },
      };
      if (env?.RATE_LIMIT_KV) {
        await env.RATE_LIMIT_KV.put(kvKey, JSON.stringify(aiIndex), { expirationTtl: 120 }).catch(() => {});
      }
      return { data: aiIndex, cached: false, derived: true };
    }
  } catch (e) { console.error("[AI-FALLBACK]", e.message); }
  return null;
}

async function handleAI(request, env, rid, subpath) {
  // Public endpoint — no API key required for index and heatmap data
  // Full analysis requires API key (enforced by caller for /analyze, /respond, /correlate)

  const pathMap = {
    ""          : { r2: "ai/ai_index.json",    kv: "ai:index",     ttl: 120 },
    "index"     : { r2: "ai/ai_index.json",    kv: "ai:index",     ttl: 120 },
    "analyze"   : { r2: "ai/analyze.json",     kv: "ai:analyze",   ttl: 120 },
    "respond"   : { r2: "ai/respond.json",     kv: "ai:respond",   ttl: 180 },
    "correlate" : { r2: "ai/correlate.json",   kv: "ai:correlate", ttl: 180 },
    "heatmap"   : { r2: "ai/ai_index.json",    kv: "ai:index",     ttl: 120 },
  };

  const key = subpath.replace(/^\/+|\/+$/g, "").toLowerCase();
  const cfg = pathMap[key] || pathMap[""];

  try {
    const result = await fetchAIData(env, cfg.r2, cfg.kv, cfg.ttl);
    if (!result) {
      return jsonResponse({
        error:      "ai_data_unavailable",
        message:    "AI intelligence data not yet generated. Run the sentinel-blogger workflow.",
        request_id: rid,
        gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      }, 503);
    }
    await recordAnalytics(env, null, `ai_${key || "index"}`, "anon", 200);
    return jsonResponse({
      status:      "ok",
      gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      request_id:  rid,
      cached:      result.cached,
      derived:     result.derived || false,
      data:        result.data,
    });
  } catch (err_) {
    console.error("[handleAI]", err_.message);
    return jsonResponse({
      error:      "ai_engine_error",
      message:    "AI endpoint error. Please try again.",
      request_id: rid,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 503);
  }
}

async function handleCacheBust(request, env, rid) {
  const secret   = env?.ADMIN_SECRET;
  const provided = request.headers.get("X-Admin-Secret");
  if (!secret || provided !== secret) {
    return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
  }
  const key = (new URL(request.url).searchParams.get("key") || "idx:reports")
    .replace(/[^a-z0-9_:\-\.]/gi, "");
  if (!env?.RATE_LIMIT_KV) return jsonResponse({ error: "kv_unavailable", request_id: rid }, 503);
  await env.RATE_LIMIT_KV.delete(key);
  const alsoDeleted = [];
  // Also bust preview + AI caches when busting feed cache
  if (key === "idx:reports") {
    for (const extra of ["idx:preview", "ai:index", "ai:analyze", "ai:respond", "ai:correlate"]) {
      await env.RATE_LIMIT_KV.delete(extra).catch(() => {});
      alsoDeleted.push(extra);
    }
  }
  return jsonResponse({
    success:     true,
    key,
    deleted:     true,
    also_deleted: alsoDeleted,
    timestamp:   new Date().toISOString(),
    request_id:  rid,
  });
}

async function handleAdminCreateKey(request, env, rid) {
  const secret   = env?.ADMIN_SECRET;
  const provided = request.headers.get("X-Admin-Secret");
  if (!secret || provided !== secret) {
    return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
  }
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "kv_unavailable", request_id: rid }, 503);
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }
  const tier = body.tier || CONFIG.TIERS.FREE;
  if (!Object.values(CONFIG.TIERS).includes(tier)) {
    return jsonResponse({
      error:       "invalid_tier",
      valid_tiers: Object.values(CONFIG.TIERS),
      request_id:  rid,
    }, 400);
  }
  const rawBytes = crypto.getRandomValues(new Uint8Array(32));
  const rawKey   = "CDB-" + tier.toUpperCase().slice(0, 3) + "-" +
    Array.from(rawBytes).map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 32).toUpperCase();
  const hash   = await sha256hex(rawKey);
  const keyId  = hash.slice(0, 16);
  const record = {
    tier,
    label:      body.label || "API Key",
    key_id:     keyId,
    created_at: new Date().toISOString(),
    expires_at: body.expires_at || null,
    revoked:    false,
  };
  await env.API_KEYS_KV.put(`apikey:${keyId}`, JSON.stringify(record));
  return jsonResponse({
    success:    true,
    api_key:    rawKey,
    key_id:     keyId,
    tier,
    label:      record.label,
    created_at: record.created_at,
    warning:    "Store this key securely — it cannot be retrieved again.",
    request_id: rid,
  }, 201);
}

// ── Main Router ────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const rid      = generateReqId();
    const url      = new URL(request.url);
    const { pathname } = url;
    const method   = request.method.toUpperCase();

    // CORS preflight
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin":  "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Authorization, X-Api-Key, Content-Type, X-Admin-Secret",
          "Access-Control-Max-Age":       "86400",
        },
      });
    }

    // IP rate limiting + abuse check (all endpoints)
    const clientIP = getClientIP(request);
    if (await isIPBanned(clientIP, env)) {
      return jsonResponse({
        error:      "ip_banned",
        message:    "Your IP has been temporarily blocked due to excessive invalid requests.",
        request_id: rid,
      }, 429);
    }
    const ipHash  = await hashIP(clientIP);
    const ipCheck = await slidingWindowCheck("ip", ipHash, CONFIG.IP_RATE_LIMIT, env?.RATE_LIMIT_KV);
    if (!ipCheck.allowed) {
      return jsonResponse({
        error:       "ip_rate_limited",
        message:     "Too many requests from this IP. Please slow down.",
        retry_after: ipCheck.retryAfter,
        request_id:  rid,
      }, 429, { "Retry-After": String(ipCheck.retryAfter || 60) });
    }

    // ── Public endpoints (no API key required) ────────────────────────────────
    if (pathname.startsWith("/api/preview"))          return handlePreview(request, env, rid);
    if (pathname.startsWith("/api/health"))            return handleHealth(request, env, rid);
    if (pathname.startsWith("/api/keys/validate"))     return handleValidateKey(request, env, rid);
    // AI endpoints — public (index/heatmap) or authenticated (analyze/respond/correlate)
    if (pathname.startsWith("/api/ai")) {
      const aiSub = pathname.slice("/api/ai".length);
      // Full AI analysis endpoints require authentication
      if (aiSub.startsWith("/analyze") || aiSub.startsWith("/respond") || aiSub.startsWith("/correlate")) {
        const auth = await resolveApiKey(request, env);
        if (!auth.valid) {
          return jsonResponse({
            error:       "api_key_required",
            message:     "API key required for full AI analysis. Use Authorization: Bearer <key>.",
            acquire_key: CONFIG.GET_KEY_URL,
            request_id:  rid,
          }, 401);
        }
      }
      return handleAI(request, env, rid, aiSub);
    }

    // ── Admin endpoints (X-Admin-Secret verified internally) ─────────────────
    if (pathname.startsWith("/api/admin/cache/bust") && method === "POST")
      return handleCacheBust(request, env, rid);
    if (pathname.startsWith("/api/admin/keys/create") && method === "POST")
      return handleAdminCreateKey(request, env, rid);
    if (pathname.startsWith("/api/admin")) {
      if (!env?.ADMIN_SECRET || request.headers.get("X-Admin-Secret") !== env.ADMIN_SECRET) {
        return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
      }
      return jsonResponse({
        error:     "not_found",
        message:   "Admin endpoint not found.",
        available: ["/api/admin/cache/bust", "/api/admin/keys/create"],
        request_id: rid,
      }, 404);
    }

    // ── ALL REMAINING ENDPOINTS: API KEY REQUIRED ─────────────────────────────
    const auth = await resolveApiKey(request, env);
    if (!auth.valid) {
      if (auth.reason === "invalid_key" || auth.reason === "key_expired") {
        await trackAbuseAttempt(clientIP, env);
      }
      return jsonResponse({
        error:       auth.reason === "key_required" ? "api_key_required" : "unauthorized",
        message:     auth.reason === "key_required"
          ? "API key required. Use Authorization: Bearer <key> or X-Api-Key header."
          : `API key rejected: ${auth.reason}`,
        reason:      auth.reason,
        acquire_key: CONFIG.GET_KEY_URL,
        docs:        CONFIG.DOCS_URL,
        request_id:  rid,
      }, 401);
    }

    // Per-key sliding-window rate limit
    const rateLimit = CONFIG.RATE_LIMITS[auth.tier] || CONFIG.RATE_LIMITS.free;
    const keyCheck  = await slidingWindowCheck("key", auth.key_id, rateLimit, env?.RATE_LIMIT_KV);
    if (!keyCheck.allowed) {
      await recordAnalytics(env, auth.key_id, "rate_limited", auth.tier, 429);
      return jsonResponse({
        error:      "rate_limited",
        message:    `Rate limit exceeded. ${auth.tier}: ${rateLimit} req/min.`,
        limit:      keyCheck.limit,
        retry_after: keyCheck.retryAfter,
        request_id:  rid,
        upgrade:     getUpgradeCTA(auth.tier),
      }, 429, {
        "Retry-After":       String(keyCheck.retryAfter || 60),
        "X-RateLimit-Remaining": "0",
      });
    }

    // Authenticated route dispatch
    if (pathname === "/api/feed" && method === "GET")
      return handleFeed(request, env, auth, rid);
    if (pathname.startsWith("/api/feed/") && method === "GET") {
      const id = decodeURIComponent(pathname.slice("/api/feed/".length));
      if (id) return handleReport(request, env, auth, rid, id);
    }
    if (pathname.startsWith("/api/analytics") && method === "GET")
      return handleAnalytics(request, env, auth, rid);

    return jsonResponse({
      error:   "not_found",
      message: `Endpoint '${pathname}' not found.`,
      available: [
        "GET  /api/preview              (public — no key required)",
        "GET  /api/health               (public)",
        "GET  /api/keys/validate        (public)",
        "GET  /api/ai                   (public — AI index + MITRE heatmap)",
        "GET  /api/ai/heatmap           (public — MITRE ATT&CK heatmap)",
        "GET  /api/ai/analyze           (requires API key — full threat analysis)",
        "GET  /api/ai/respond           (requires API key — SOAR playbooks)",
        "GET  /api/ai/correlate         (requires API key — actor correlation)",
        "GET  /api/feed                 (requires API key)",
        "GET  /api/feed/:id             (requires API key)",
        "GET  /api/analytics            (requires API key)",
        "POST /api/admin/cache/bust     (requires X-Admin-Secret)",
        "POST /api/admin/keys/create    (requires X-Admin-Secret)",
      ],
      docs:       CONFIG.DOCS_URL,
      request_id: rid,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 404);
  },
};
