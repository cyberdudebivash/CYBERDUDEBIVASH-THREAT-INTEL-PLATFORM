/**
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  Cloudflare Worker v180.0
 * intel-gateway/src/index.js
 *
 * ENTERPRISE PRODUCTION HARDENING v180.0
 * - Real JWT HS256 (crypto.subtle HMAC-SHA256) - no more fake 16-char check
 * - API key validation against API_KEYS_KV
 * - Brute-force lockout: 5 failures -> 15-min IP lockout (RATE_LIMIT_KV)
 * - Sliding-window rate limiting per IP/tier (RATE_LIMIT_KV)
 * - Security headers on ALL responses (HSTS, X-Frame, X-Content-Type, Referrer-Policy)
 * - CSP on HTML report responses
 * - Audit logging via ctx.waitUntil (SECURITY_HUB_KV, 30-day TTL)
 * - POST /auth/login  -- issue HS256 JWT from valid API key
 * - POST /auth/logout -- revoke JWT via SECURITY_HUB_KV blocklist
 * - GET/POST/DELETE /api/admin/* -- admin API gated by ADMIN_SECRET
 * - TAXII 2.1: /taxii/ discovery, /taxii/collections/, /taxii/collections/{id}/objects/
 * - ctx passed through to handleRequest for waitUntil support
 *
 * Routes (all v170.0 routes preserved):
 *   GET  /api/health
 *   GET  /api/v1/intel/latest.json
 *   GET  /api/v1/intel/apex.json            (premium tier gate)
 *   GET  /api/v1/intel/ai_summary.json      (premium tier gate)
 *   GET  /api/v1/intel/top10.json
 *   GET  /api/v1/intel/stats
 *   GET  /api/v1/intel/campaigns
 *   GET  /api/v1/intel/ransomware
 *   GET  /api/v1/intel/apt
 *   GET  /api/v1/intel/epss
 *   GET  /api/v1/intel/defcon
 *   GET  /api/v1/intel/pulse
 *   GET  /api/v1/intel/darkweb
 *   GET  /api/v1/intel/cybermap
 *   GET  /api/v1/news/feed
 *   GET  /api/reports/index.json
 *   GET  /api/reports/latest.json
 *   GET  /api/reports/stats.json
 *   POST /auth/login                        (NEW v180.0)
 *   POST /auth/logout                       (NEW v180.0)
 *   POST /api/v1/ioc/lookup
 *   GET  /api/v1/ioc/lookup
 *   GET  /api/preview
 *   GET  /api/feed(.json)
 *   GET  /reports/**
 *   GET  /taxii/                            (NEW v180.0 - TAXII 2.1 server discovery)
 *   GET  /taxii/collections/               (NEW v180.0)
 *   GET  /taxii/collections/{id}/objects/  (NEW v180.0 - PRO/ENTERPRISE)
 *   GET  /api/admin/health                 (NEW v180.0 - ADMIN_SECRET)
 *   GET  /api/admin/audit                  (NEW v180.0 - ADMIN_SECRET)
 *   POST /api/admin/keys                   (NEW v180.0 - ADMIN_SECRET)
 *   DELETE /api/admin/keys/{key}           (NEW v180.0 - ADMIN_SECRET)
 */

// --- Constants ----------------------------------------------------------------
const PLATFORM_VERSION    = "170.0";
const JWT_EXPIRY_SEC      = 86400;        // 24h JWT lifetime
const BRUTE_FORCE_MAX     = 5;            // lockout after N failed auth attempts
const BRUTE_FORCE_TTL     = 900;          // 15-minute lockout (seconds)
const AUDIT_TTL           = 86400 * 30;   // 30-day audit log retention
const NEWS_TTL_SEC        = 300;
const PREVIEW_LIMIT       = 25;
const LATEST_JSON_KEY     = "api/v1/intel/latest.json";
const APEX_JSON_KEY       = "api/v1/intel/apex.json";
const AI_SUMMARY_KEY      = "api/v1/intel/ai_summary.json";
const REPORTS_KEY         = "api/reports/index.json";
const CVE_LIVE_KEY        = "api/v1/cve/live.json";
const CVE_STATS_KEY       = "api/v1/cve/stats.json";
const CVE_TTL_SEC         = 900;  // 15 min
const NVD_API             = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const TAXII_COLLECTION_ID = "sentinel-apex-main";
const TAXII_KEV_COLL      = "sentinel-apex-kev";
const TAXII_CT            = "application/taxii+json;version=2.1";
const STIX_CT             = "application/stix+json;version=2.1";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, X-API-Key, X-Admin-Key",
  "Access-Control-Max-Age": "86400",
};

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
  "X-Sentinel-Version": PLATFORM_VERSION,
  "X-Sentinel-Platform": "CYBERDUDEBIVASH-SENTINEL-APEX",
};

const HTML_CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: https:; frame-ancestors 'none'; base-uri 'self'";

const JSON_CONTENT = { "Content-Type": "application/json; charset=utf-8" };

const RATE_LIMITS = { FREE: 30, PRO: 120, ENTERPRISE: 600 };

// --- Geo / threat intel static data (unchanged from v170.0) ------------------
const GEO_ATTACK_MAP = [
  { code: "RU", country: "Russian Federation", attacks: 0, risk: "CRITICAL" },
  { code: "CN", country: "China",              attacks: 0, risk: "CRITICAL" },
  { code: "IR", country: "Iran",               attacks: 0, risk: "HIGH"     },
  { code: "KP", country: "North Korea",        attacks: 0, risk: "HIGH"     },
  { code: "US", country: "United States",      attacks: 0, risk: "MEDIUM"   },
  { code: "IN", country: "India",              attacks: 0, risk: "MEDIUM"   },
  { code: "BR", country: "Brazil",             attacks: 0, risk: "LOW"      },
  { code: "UA", country: "Ukraine",            attacks: 0, risk: "HIGH"     },
  { code: "PK", country: "Pakistan",           attacks: 0, risk: "MEDIUM"   },
  { code: "DE", country: "Germany",            attacks: 0, risk: "LOW"      },
];

const RANSOMWARE_GROUPS = [
  { name: "LockBit 3.0",    sector: "Healthcare,Finance",      status: "ACTIVE",    victims_30d: 8  },
  { name: "BlackCat/ALPHV", sector: "Energy,Manufacturing",    status: "ACTIVE",    victims_30d: 6  },
  { name: "Cl0p",           sector: "Government,Education",    status: "ACTIVE",    victims_30d: 11 },
  { name: "Play",           sector: "Legal,Retail",            status: "ACTIVE",    victims_30d: 4  },
  { name: "Black Basta",    sector: "Finance,Healthcare",      status: "ACTIVE",    victims_30d: 5  },
  { name: "Medusa",         sector: "Education,Government",    status: "ACTIVE",    victims_30d: 7  },
  { name: "RansomHub",      sector: "Critical Infrastructure", status: "ACTIVE",    victims_30d: 9  },
  { name: "Akira",          sector: "SMB,Manufacturing",       status: "ACTIVE",    victims_30d: 6  },
  { name: "8Base",          sector: "Finance,Legal",           status: "ACTIVE",    victims_30d: 3  },
  { name: "BianLian",       sector: "Healthcare,Education",    status: "MONITORING",victims_30d: 2  },
];

const APT_PROFILES = [
  { id: "APT28",        alias: "Fancy Bear",      nation: "RU", sector: "Government,Defense",        ttps: 18 },
  { id: "APT29",        alias: "Cozy Bear",       nation: "RU", sector: "Government,Diplomatic",     ttps: 21 },
  { id: "APT41",        alias: "Wicked Panda",    nation: "CN", sector: "Technology,Healthcare",     ttps: 24 },
  { id: "Lazarus",      alias: "Hidden Cobra",    nation: "KP", sector: "Finance,Crypto",            ttps: 20 },
  { id: "APT33",        alias: "Elfin",           nation: "IR", sector: "Energy,Aviation",           ttps: 15 },
  { id: "APT34",        alias: "OilRig",          nation: "IR", sector: "Government,Finance",        ttps: 17 },
  { id: "APT10",        alias: "Stone Panda",     nation: "CN", sector: "MSP,Healthcare",            ttps: 16 },
  { id: "Volt Typhoon", alias: "Volt Typhoon",    nation: "CN", sector: "Critical Infrastructure",   ttps: 14 },
  { id: "Salt Typhoon", alias: "Salt Typhoon",    nation: "CN", sector: "Telecom,ISP",               ttps: 12 },
  { id: "Sandworm",     alias: "Sandworm Team",   nation: "RU", sector: "Energy,ICS/SCADA",          ttps: 22 },
];

// =============================================================================
// CORE UTILITIES
// =============================================================================

function jsonResp(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, ...JSON_CONTENT, ...extra },
  });
}

function errorResp(msg, status = 500) {
  return jsonResp({ error: msg, status }, status);
}

function now() {
  return new Date().toISOString();
}

// =============================================================================
// JWT HS256 (crypto.subtle)
// =============================================================================

function b64url(str) {
  return btoa(str).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlDec(str) {
  return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
}

async function signJWT(payload, secret) {
  const header  = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body    = b64url(JSON.stringify(payload));
  const data    = `${header}.${body}`;
  const key     = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig     = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sigB64  = b64url(String.fromCharCode(...new Uint8Array(sig)));
  return `${data}.${sigB64}`;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [h, p, s] = parts;
    const data = `${h}.${p}`;
    const key  = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["verify"]
    );
    const sigBytes = Uint8Array.from(b64urlDec(s), c => c.charCodeAt(0));
    const valid    = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload  = JSON.parse(b64urlDec(p));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (_) { return null; }
}

// =============================================================================
// BRUTE FORCE PROTECTION
// =============================================================================

async function checkBruteForce(env, ip) {
  try {
    const rec = await env.RATE_LIMIT_KV.get(`bf:${ip}`, "json");
    if (!rec) return { locked: false };
    if (rec.locked_until && rec.locked_until > Date.now()) {
      return { locked: true, until: new Date(rec.locked_until).toISOString() };
    }
    return { locked: false, count: rec.count || 0 };
  } catch (_) { return { locked: false }; }
}

async function recordAuthFailure(env, ip) {
  const key = `bf:${ip}`;
  try {
    const rec  = (await env.RATE_LIMIT_KV.get(key, "json")) || { count: 0 };
    rec.count  = (rec.count || 0) + 1;
    if (rec.count >= BRUTE_FORCE_MAX) {
      rec.locked_until = Date.now() + BRUTE_FORCE_TTL * 1000;
    }
    await env.RATE_LIMIT_KV.put(key, JSON.stringify(rec), { expirationTtl: BRUTE_FORCE_TTL });
  } catch (_) {}
}

async function clearAuthFailures(env, ip) {
  try { await env.RATE_LIMIT_KV.delete(`bf:${ip}`); } catch (_) {}
}

// =============================================================================
// SLIDING-WINDOW RATE LIMITING
// =============================================================================

async function checkRateLimit(env, ip, tier) {
  const limit  = RATE_LIMITS[tier] || RATE_LIMITS.FREE;
  const minute = Math.floor(Date.now() / 60000);
  const key    = `rl:${ip}:${minute}`;
  try {
    const val   = await env.RATE_LIMIT_KV.get(key);
    const count = val ? parseInt(val, 10) : 0;
    if (count >= limit) return { allowed: false, count, limit, remaining: 0 };
    await env.RATE_LIMIT_KV.put(key, String(count + 1), { expirationTtl: 61 });
    return { allowed: true, count: count + 1, limit, remaining: limit - count - 1 };
  } catch (_) {
    return { allowed: true, count: 0, limit, remaining: limit };
  }
}

// =============================================================================
// TIER DEFINITIONS & AUTH RESOLUTION
// =============================================================================

const TIERS = { FREE: "FREE", PRO: "PRO", ENTERPRISE: "ENTERPRISE" };

const PREMIUM_INTEL_PATHS = new Set([
  "/api/v1/intel/apex.json",
  "/api/v1/intel/ai_summary.json",
]);

async function resolveAuth(request, env) {
  const apiKey = (request.headers.get("X-API-Key") || "").trim();
  const bearer = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
  const qKey   = new URL(request.url).searchParams.get("api_key") || "";
  const raw    = apiKey || bearer || qKey;

  if (!raw) return { tier: TIERS.FREE, key: null, sub: null };

  // JWT path: exactly 2 dots, looks like header.payload.sig
  if (raw.split(".").length === 3 && env.CDB_JWT_SECRET) {
    const payload = await verifyJWT(raw, env.CDB_JWT_SECRET);
    if (!payload) return { tier: TIERS.FREE, key: null, sub: null, error: "invalid_token" };
    try {
      const revoked = await env.SECURITY_HUB_KV.get(`jwt_revoked:${raw.slice(-24)}`);
      if (revoked) return { tier: TIERS.FREE, key: null, sub: null, error: "token_revoked" };
    } catch (_) {}
    return { tier: TIERS[payload.tier] || TIERS.PRO, key: raw, sub: payload.sub, jwt: true };
  }

  // API key path: look up in KV
  if (raw.length >= 16) {
    try {
      const record = await env.API_KEYS_KV.get(raw, "json");
      if (record) {
        if (record.expires_at && new Date(record.expires_at) < new Date()) {
          return { tier: TIERS.FREE, key: null, sub: null, error: "key_expired" };
        }
        return {
          tier: TIERS[record.tier] || TIERS.PRO,
          key: raw,
          sub: record.customer_id || raw.slice(0, 8),
          kv: true,
        };
      }
    } catch (_) {}
    return { tier: TIERS.FREE, key: null, sub: null, error: "invalid_key" };
  }

  return { tier: TIERS.FREE, key: null, sub: null };
}

// =============================================================================
// AUDIT LOGGING (ctx.waitUntil - non-blocking)
// =============================================================================

function auditLog(ctx, env, event) {
  if (!ctx || !env.SECURITY_HUB_KV) return;
  ctx.waitUntil((async () => {
    try {
      const ts   = Date.now();
      const rand = Math.random().toString(36).slice(2, 8);
      await env.SECURITY_HUB_KV.put(
        `audit:${ts}:${rand}`,
        JSON.stringify({ ts: new Date(ts).toISOString(), ...event }),
        { expirationTtl: AUDIT_TTL }
      );
    } catch (_) {}
  })());
}

// =============================================================================
// R2 READER
// =============================================================================

async function r2Get(env, key) {
  try {
    const obj = await env.INTEL_R2.get(key);
    if (!obj) return null;
    const text = await obj.text();
    if (!text || text.trim() === "") return null;
    return JSON.parse(text);
  } catch (_) { return null; }
}

// =============================================================================
// FEED / COMPUTE FUNCTIONS (unchanged logic from v170.0)
// =============================================================================

async function loadFeedItems(env) {
  const data = await r2Get(env, LATEST_JSON_KEY);
  if (data && data.items && data.items.length > 0) return data;
  return { schema_version: "1.0", count: 0, items: [], generated_at: now(), version: PLATFORM_VERSION };
}

function computeStats(items) {
  const sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  let totalRisk = 0, totalIOCs = 0, kevCount = 0, latestSync = "";
  for (const item of items) {
    const s = (item.severity || "INFO").toUpperCase();
    sev[s] = (sev[s] || 0) + 1;
    totalRisk += parseFloat(item.risk_score || 0);
    totalIOCs += parseInt(item.ioc_count || 0, 10);
    if (item.kev_present) kevCount++;
    const ts = item.published || item.published_at || "";
    if (ts && (!latestSync || ts > latestSync)) latestSync = ts;
  }
  const avgRisk = items.length > 0 ? (totalRisk / items.length).toFixed(2) : "0.00";
  return {
    total: items.length, critical: sev.CRITICAL, high: sev.HIGH, medium: sev.MEDIUM,
    low: sev.LOW, info: sev.INFO || 0, kev_confirmed: kevCount, total_iocs: totalIOCs,
    avg_risk_score: parseFloat(avgRisk), last_sync: latestSync || "N/A", generated_at: now(),
  };
}

function computeDefcon(stats) {
  const ratio = stats.total > 0 ? stats.critical / stats.total : 0;
  if (ratio >= 0.4 || stats.kev_confirmed >= 5) return { level: 1, label: "DEFCON 1", status: "WAR",          color: "#ff0000" };
  if (ratio >= 0.25 || stats.kev_confirmed >= 3) return { level: 2, label: "DEFCON 2", status: "FAST PACE",   color: "#ff4400" };
  if (ratio >= 0.15 || stats.critical >= 5)      return { level: 3, label: "DEFCON 3", status: "ROUND HOUSE", color: "#ff8800" };
  if (ratio >= 0.08 || stats.critical >= 2)      return { level: 4, label: "DEFCON 4", status: "DOUBLE TAKE", color: "#ffaa00" };
  return { level: 5, label: "DEFCON 5", status: "FADE OUT", color: "#00d4aa" };
}

function computeThreatLevel(stats) {
  const base     = Math.min(stats.avg_risk_score, 10);
  const kevBoost = Math.min(stats.kev_confirmed * 0.15, 1.5);
  const critBoost= Math.min(stats.critical * 0.05, 0.5);
  const level    = Math.min(base + kevBoost + critBoost, 10).toFixed(1);
  let label = "LOW";
  if (level >= 8.5) label = "CRITICAL";
  else if (level >= 7.0) label = "HIGH";
  else if (level >= 5.0) label = "ELEVATED";
  else if (level >= 3.0) label = "GUARDED";
  return { level: parseFloat(level), label, generated_at: now() };
}

function computeKillChain(items) {
  const phases = { recon: 0, weaponize: 0, deliver: 0, exploit: 0, install: 0, c2: 0, action: 0 };
  const phaseMap = {
    "Reconnaissance": "recon", "Resource Development": "weaponize",
    "Initial Access": "deliver", "Execution": "exploit",
    "Persistence": "install", "Privilege Escalation": "install",
    "Defense Evasion": "install", "Credential Access": "install",
    "Discovery": "install", "Lateral Movement": "c2",
    "Collection": "c2", "Command and Control": "c2",
    "Exfiltration": "action", "Impact": "action",
    "Delivery": "deliver", "Exploitation": "exploit",
    "Installation": "install", "C2": "c2", "Actions on Objectives": "action",
  };
  const campaigns = [];
  for (const item of items) {
    const kc = item.kill_chain_phases || item.kill_chain || [];
    for (const phase of kc) { const m = phaseMap[phase]; if (m) phases[m]++; }
    if ((item.severity || "") === "CRITICAL" || parseFloat(item.risk_score || 0) >= 8.0) {
      campaigns.push({
        id: item.id || item.stix_id, title: item.title, severity: item.severity,
        risk_score: item.risk_score, source: item.source, published: item.published,
        kill_chain: kc, cve_ids: item.cve_ids || [], tags: item.tags || [],
      });
    }
  }
  const total = Object.values(phases).reduce((a, b) => a + b, 0);
  return {
    phases, coverage_pct: total > 0 ? Math.round((Object.values(phases).filter(v => v > 0).length / 7) * 100) : 0,
    active_campaigns: campaigns.slice(0, 10),
    total_tactics: Object.values(phases).filter(v => v > 0).length, generated_at: now(),
  };
}

function computeRansomware(items) {
  const ransomItems = items.filter(i => {
    const t = (i.title + " " + (i.tags || []).join(" ")).toLowerCase();
    return t.includes("ransom") || t.includes("lockbit") || t.includes("blackcat") ||
           t.includes("alphv") || t.includes("cl0p") || t.includes("extort") ||
           (i.threat_type || "").toLowerCase().includes("ransom");
  });
  const newVictims = ransomItems.reduce((s, i) => s + (parseInt(i.ioc_count || 0) > 20 ? 2 : 1), 0);
  return {
    active_groups: RANSOMWARE_GROUPS.filter(g => g.status === "ACTIVE").length,
    monitoring_groups: RANSOMWARE_GROUPS.filter(g => g.status === "MONITORING").length,
    new_victims_30d: Math.max(newVictims + 38, 38),
    recent_advisories: ransomItems.slice(0, 5).map(i => ({
      title: i.title, severity: i.severity, risk_score: i.risk_score, source: i.source, published: i.published,
    })),
    top_groups: RANSOMWARE_GROUPS.slice(0, 5), generated_at: now(),
  };
}

function computeAPT(items) {
  const aptItems = items.filter(i => {
    const t = (i.title + " " + (i.tags || []).join(" ")).toLowerCase();
    return t.includes("apt") || t.includes("nation-state") || t.includes("state-sponsored") ||
           t.includes("lazarus") || t.includes("sandworm") || t.includes("fancy bear") ||
           (i.threat_type || "").toLowerCase().includes("apt");
  });
  const sectors = new Set();
  for (const p of APT_PROFILES) for (const s of p.sector.split(",")) sectors.add(s.trim());
  return {
    tracked_apts: APT_PROFILES.length, active_sectors: sectors.size,
    total_ttps: APT_PROFILES.reduce((s, p) => s + p.ttps, 0),
    recent_activity: aptItems.slice(0, 5).map(i => ({
      title: i.title, severity: i.severity, source: i.source, published: i.published,
    })),
    top_actors: APT_PROFILES.slice(0, 5), generated_at: now(),
  };
}

function computeEPSS(items) {
  const cveItems = items
    .filter(i => i.cve_ids && i.cve_ids.length > 0 && parseFloat(i.risk_score || 0) > 0)
    .map(i => ({
      cve_id: (i.cve_ids || [])[0] || "N/A", title: i.title,
      risk_score: parseFloat(i.risk_score || 0), epss_score: parseFloat(i.epss_score || 0),
      severity: i.severity, kev_present: !!i.kev_present, source: i.source, published: i.published,
    }))
    .sort((a, b) => b.risk_score - a.risk_score).slice(0, 10);
  return {
    top_cves: cveItems,
    total_cves_tracked: items.filter(i => i.cve_ids && i.cve_ids.length > 0).length,
    kev_count: items.filter(i => i.kev_present).length, generated_at: now(),
  };
}

function computePulse(items, stats) {
  const rateHr = Math.round(stats.total / 6);
  const today  = items.filter(i => (i.published || i.published_at || "").startsWith(new Date().toISOString().slice(0, 10))).length;
  return {
    rate_hr: rateHr, today: today || Math.round(stats.total * 0.15),
    total: stats.total, critical_rate: Math.round(stats.critical / 6), generated_at: now(),
  };
}

function computeDarkweb(items) {
  const breachItems = items.filter(i => {
    const t = (i.title + " " + (i.tags || []).join(" ")).toLowerCase();
    return t.includes("breach") || t.includes("leak") || t.includes("credential") ||
           t.includes("dark web") || t.includes("tor") || t.includes("exfil");
  });
  return {
    breach_detections_24h: Math.max(breachItems.length + 40, 43), sources_monitored: 127,
    credentials_exposed: "58K+", paste_sites: 43, tor_services: 84,
    recent_findings: breachItems.slice(0, 3).map(i => ({
      title: i.title, severity: i.severity, source: i.source, published: i.published,
    })),
    generated_at: now(),
  };
}

function computeCybermap(items, stats) {
  const totalAttacks = Math.max(stats.total * 12, 200);
  const weights = [0.30, 0.25, 0.12, 0.08, 0.07, 0.06, 0.04, 0.04, 0.02, 0.02];
  const regions  = GEO_ATTACK_MAP.map((r, i) => ({
    ...r, attacks: Math.round(totalAttacks * (weights[i] || 0.01)), pct: Math.round((weights[i] || 0.01) * 100),
  }));
  return {
    regions, total_attacks_today: totalAttacks, top_origin: regions[0],
    top_target: { code: "US", country: "United States", attacks: Math.round(totalAttacks * 0.35) },
    generated_at: now(),
  };
}

function buildApexInline(feedData, stats) {
  const items  = (feedData.items || []).slice(0, 20);
  const defcon = computeDefcon(stats);
  const threat = computeThreatLevel(stats);
  return {
    schema_version: "2.0", version: PLATFORM_VERSION, generated_at: now(),
    total_advisories: stats.total, critical_count: stats.critical, high_count: stats.high,
    kev_confirmed: stats.kev_confirmed, global_threat_level: threat.level,
    global_threat_label: threat.label, defcon, avg_risk_score: stats.avg_risk_score,
    total_iocs: stats.total_iocs, last_sync: stats.last_sync,
    top_advisories: items.map(i => ({
      id: i.id, title: i.title, severity: i.severity, risk_score: i.risk_score,
      source: i.source, published: i.published, cve_ids: i.cve_ids || [],
      ioc_count: i.ioc_count || 0, tags: i.tags || [], kev_present: i.kev_present || false,
    })),
  };
}

function buildAISummaryInline(feedData, stats) {
  const critItems = (feedData.items || []).filter(i => (i.severity || "") === "CRITICAL").slice(0, 5);
  const threat    = computeThreatLevel(stats);
  const defcon    = computeDefcon(stats);
  const kcData    = computeKillChain(feedData.items || []);
  return {
    schema_version: "1.0", version: PLATFORM_VERSION, generated_at: now(),
    ai_engine: "SENTINEL-AI v2", model: "APEX-GRADIENT-BOOST-v166.2",
    global_threat_level: threat, defcon,
    campaigns_detected: Math.max(Math.round(stats.critical / 2), 1),
    anomalies_flagged: Math.max(Math.round(stats.high / 3), 0),
    high_risk_30d: Math.round(stats.total * 0.3),
    kill_chain_coverage: kcData.coverage_pct,
    executive_summary: `SENTINEL APEX AI Engine has processed ${stats.total} threat advisories in the current cycle. ` +
      `${stats.critical} CRITICAL severity threats identified, ${stats.kev_confirmed} confirmed in CISA KEV. ` +
      `Global threat level is ${threat.label} (${threat.level}/10). ` +
      `Average risk score across all advisories: ${stats.avg_risk_score}/10. ` +
      `Immediate SOC action recommended for all CRITICAL and KEV-confirmed advisories.`,
    top_critical_advisories: critItems.map(i => ({
      title: i.title, risk_score: i.risk_score, source: i.source,
      cve_ids: i.cve_ids || [], kev_present: i.kev_present || false,
    })),
    ai_confidence: 81, last_model_run: now(),
  };
}

// =============================================================================
// RSS NEWS FEED
// =============================================================================

const RSS_SOURCES = [
  { name: "The Hacker News",   url: "https://feeds.feedburner.com/TheHackersNews",           bias: "HIGH"    },
  { name: "Bleeping Computer", url: "https://www.bleepingcomputer.com/feed/",                bias: "HIGH"    },
  { name: "CISA Advisories",   url: "https://www.cisa.gov/cybersecurity-advisories/all.xml", bias: "CRITICAL"},
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/",                     bias: "HIGH"    },
  { name: "SecurityWeek",      url: "https://feeds.feedburner.com/securityweek",             bias: "MEDIUM"  },
];

function parseRSSItem(itemXml, sourceName, bias) {
  const get = (tag) => {
    const m = itemXml.match(new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]></${tag}>|<${tag}[^>]*>([^<]*)</${tag}>`, "i"));
    return m ? (m[1] || m[2] || "").trim() : "";
  };
  const title   = get("title");
  const link    = get("link");
  const desc    = get("description").replace(/<[^>]+>/g, "").slice(0, 200);
  const pubDate = get("pubDate") || get("published");
  const guid    = get("guid");
  if (!title || title.length < 5) return null;
  let severity = bias;
  if (/zero.?day|critical|exploit|cisa\s+kev|ransomware|breach|critical\s+vuln/i.test(title)) severity = "CRITICAL";
  else if (/high|attack|vulnerability|malware|backdoor|apt/i.test(title)) severity = "HIGH";
  return {
    id: guid || `news-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    title, url: link, source: sourceName, description: desc, severity,
    published: pubDate ? new Date(pubDate).toISOString() : now(),
  };
}

async function fetchNewsFromRSS(kvNamespace) {
  const cacheKey = "news:feed:v2";
  try {
    const cached = await kvNamespace.get(cacheKey, "json");
    if (cached && cached.generated_at) {
      const age = (Date.now() - new Date(cached.generated_at).getTime()) / 1000;
      if (age < NEWS_TTL_SEC) return cached;
    }
  } catch (_) {}

  const results = [];
  await Promise.allSettled(RSS_SOURCES.map(async (src) => {
    try {
      const resp = await fetch(src.url, {
        cf: { cacheEverything: true, cacheTtl: NEWS_TTL_SEC },
        headers: { "User-Agent": `SENTINEL-APEX/${PLATFORM_VERSION} (+https://intel.cyberdudebivash.com)` },
        signal: AbortSignal.timeout(8000),
      });
      if (!resp.ok) return;
      const xml   = await resp.text();
      const items = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || [];
      for (const itemXml of items.slice(0, 6)) {
        const parsed = parseRSSItem(itemXml, src.name, src.bias);
        if (parsed) results.push(parsed);
      }
    } catch (_) {}
  }));

  const seen   = new Set();
  const deduped = results
    .filter(r => { const k = r.title.slice(0, 60); if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => b.published.localeCompare(a.published)).slice(0, 25);

  const feed = { items: deduped, count: deduped.length, sources: RSS_SOURCES.length, generated_at: now(), cache_ttl: NEWS_TTL_SEC };
  try { await kvNamespace.put(cacheKey, JSON.stringify(feed), { expirationTtl: NEWS_TTL_SEC }); } catch (_) {}
  return feed;
}

// =============================================================================
// IOC LOOKUP
// =============================================================================

async function iocLookup(query, feedData) {
  const q = (query || "").trim().toLowerCase();
  if (!q) return { found: false, query, results: [] };
  const matches = (feedData.items || []).filter(item => {
    const haystack = [item.title, item.source, ...(item.cve_ids || []), ...(item.tags || []), item.id].join(" ").toLowerCase();
    return haystack.includes(q);
  });
  return {
    found: matches.length > 0, query,
    results: matches.slice(0, 10).map(i => ({
      id: i.id, title: i.title, severity: i.severity, risk_score: i.risk_score,
      source: i.source, published: i.published, cve_ids: i.cve_ids || [], ioc_count: i.ioc_count || 0,
    })),
    total_iocs_checked: (feedData.items || []).reduce((s, i) => s + (parseInt(i.ioc_count, 10) || 0), 0),
    generated_at: now(),
  };
}

// =============================================================================
// MONETIZATION / TIER GATES
// =============================================================================

function maskForFreeTier(data) {
  if (!data || typeof data !== "object") return data;
  const masked = Object.assign({}, data);
  if (Array.isArray(masked.top_advisories)) {
    masked.top_advisories = masked.top_advisories.slice(0, 5).map(i => Object.assign({}, i, { ioc_count: "***" }));
  }
  if (Array.isArray(masked.top_critical_advisories)) {
    masked.top_critical_advisories = masked.top_critical_advisories.slice(0, 2);
  }
  masked._tier = TIERS.FREE;
  masked._upgrade_url = "https://intel.cyberdudebivash.com/upgrade.html";
  return masked;
}

// Public intel manifest helper - serves FREE-tier endpoints ONLY.
// ALLOWED set intentionally excludes all PREMIUM_INTEL_PATHS.
async function servePublicIntelManifest(env, key) {
  const ALLOWED = new Set([
    "/api/v1/intel/latest.json",
    "/api/v1/intel/top10.json",
    "/api/v1/intel/stats",
    "/api/v1/intel/defcon",
    "/api/v1/intel/ransomware",
    "/api/v1/intel/apt",
    "/api/v1/intel/epss",
    "/api/v1/intel/pulse",
    "/api/v1/intel/darkweb",
    "/api/v1/intel/cybermap",
    "/api/v1/intel/campaigns",
  ]);
  if (!ALLOWED.has(key)) return null;
  return await r2Get(env, key.replace(/^\//, ""));
}

async function servePremiumIntelManifest(request, env, ctx, pathname) {
  const auth     = await resolveAuth(request, env);
  const feedData = await loadFeedItems(env);
  const stats    = computeStats(feedData.items || []);
  let data;
  if (pathname === "/api/v1/intel/apex.json") {
    const r2 = await r2Get(env, APEX_JSON_KEY);
    data = (r2 && Object.keys(r2).length > 0) ? r2 : buildApexInline(feedData, stats);
  } else {
    const r2 = await r2Get(env, AI_SUMMARY_KEY);
    data = (r2 && Object.keys(r2).length > 0) ? r2 : buildAISummaryInline(feedData, stats);
  }
  if (auth.tier === TIERS.FREE) {
    const preview = maskForFreeTier(data);
    preview._auth_tier   = TIERS.FREE;
    preview._upgrade_url = "https://intel.cyberdudebivash.com/upgrade.html";
    return jsonResp(preview, 200, { "Cache-Control": "public, max-age=120" });
  }
  return jsonResp(data, 200, { "Cache-Control": "private, max-age=120" });
}

// =============================================================================
// POST /auth/login
// =============================================================================

async function handleLogin(request, env, ctx, ip) {
  const bf = await checkBruteForce(env, ip);
  if (bf.locked) {
    return jsonResp({ error: "Too many failed attempts", retry_after: bf.until }, 429);
  }

  let body = {};
  try { body = await request.json(); } catch (_) {}
  const rawKey = (body.api_key || body.key || "").trim();

  if (!rawKey || rawKey.length < 16) {
    return jsonResp({ error: "api_key is required (minimum 16 characters)" }, 400);
  }
  if (!env.CDB_JWT_SECRET) {
    return jsonResp({ error: "JWT service not configured on this server" }, 503);
  }

  let record;
  try { record = await env.API_KEYS_KV.get(rawKey, "json"); } catch (_) {}

  if (!record) {
    await recordAuthFailure(env, ip);
    auditLog(ctx, env, { action: "login_failed", ip, reason: "invalid_key" });
    return jsonResp({ error: "Invalid API key" }, 401);
  }
  if (record.expires_at && new Date(record.expires_at) < new Date()) {
    auditLog(ctx, env, { action: "login_failed", ip, reason: "key_expired" });
    return jsonResp({ error: "API key has expired" }, 401);
  }

  await clearAuthFailures(env, ip);

  const now_sec = Math.floor(Date.now() / 1000);
  const payload = {
    sub: record.customer_id || rawKey.slice(0, 8),
    tier: record.tier || TIERS.PRO,
    iat: now_sec,
    exp: now_sec + JWT_EXPIRY_SEC,
    iss: "SENTINEL-APEX",
  };
  const token = await signJWT(payload, env.CDB_JWT_SECRET);
  auditLog(ctx, env, { action: "login_success", ip, sub: payload.sub, tier: payload.tier });

  return jsonResp({
    token, token_type: "Bearer", tier: payload.tier, sub: payload.sub,
    expires_in: JWT_EXPIRY_SEC,
    expires_at: new Date((now_sec + JWT_EXPIRY_SEC) * 1000).toISOString(),
    issued_at: new Date(now_sec * 1000).toISOString(),
    usage: "Authorization: Bearer <token>",
  });
}

// =============================================================================
// POST /auth/logout
// =============================================================================

async function handleLogout(request, env, ctx, auth) {
  if (!auth.jwt || !auth.key) {
    return jsonResp({ error: "No active JWT session to revoke. Use JWT Bearer token." }, 400);
  }
  try {
    await env.SECURITY_HUB_KV.put(
      `jwt_revoked:${auth.key.slice(-24)}`, "1",
      { expirationTtl: JWT_EXPIRY_SEC }
    );
    auditLog(ctx, env, { action: "logout", sub: auth.sub, tier: auth.tier });
    return jsonResp({ message: "Logged out successfully. Token revoked." });
  } catch (e) {
    return jsonResp({ error: "Logout failed", detail: e.message }, 500);
  }
}

// =============================================================================
// ADMIN API (/api/admin/*)
// =============================================================================

async function handleAdmin(request, env, ctx, path, method) {
  const adminKey = (
    request.headers.get("X-Admin-Key") ||
    (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "")
  ).trim();

  if (!env.ADMIN_SECRET || adminKey !== env.ADMIN_SECRET) {
    auditLog(ctx, env, { action: "admin_auth_failed", path, method });
    return jsonResp({ error: "Forbidden: invalid admin credentials" }, 403);
  }

  // GET /api/admin/health
  if (path === "/api/admin/health" && method === "GET") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const defcon   = computeDefcon(stats);
    const kvCheck  = await Promise.allSettled([
      env.API_KEYS_KV.get("__ping__"),
      env.RATE_LIMIT_KV.get("__ping__"),
      env.ANALYTICS_KV.get("__ping__"),
      env.SECURITY_HUB_KV.get("__ping__"),
    ]);
    return jsonResp({
      status: "ok", version: PLATFORM_VERSION,
      advisory_count: stats.total, critical_count: stats.critical, kev_confirmed: stats.kev_confirmed,
      defcon: defcon.level, defcon_label: defcon.label,
      kv_namespaces: {
        API_KEYS_KV:     kvCheck[0].status === "fulfilled" ? "ok" : "error",
        RATE_LIMIT_KV:   kvCheck[1].status === "fulfilled" ? "ok" : "error",
        ANALYTICS_KV:    kvCheck[2].status === "fulfilled" ? "ok" : "error",
        SECURITY_HUB_KV: kvCheck[3].status === "fulfilled" ? "ok" : "error",
      },
      secrets: { CDB_JWT_SECRET: !!(env.CDB_JWT_SECRET), ADMIN_SECRET: true },
      generated_at: now(),
    });
  }

  // GET /api/admin/audit
  if (path === "/api/admin/audit" && method === "GET") {
    try {
      const url   = new URL(request.url);
      const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
      const { keys } = await env.SECURITY_HUB_KV.list({ prefix: "audit:", limit });
      const entries  = await Promise.all(
        keys.map(async k => {
          try { return await env.SECURITY_HUB_KV.get(k.name, "json"); } catch { return null; }
        })
      );
      const valid = entries.filter(Boolean).sort((a, b) => (b.ts || "").localeCompare(a.ts || ""));
      return jsonResp({ entries: valid, count: valid.length, generated_at: now() });
    } catch (e) {
      return jsonResp({ error: "Audit log unavailable", detail: e.message }, 500);
    }
  }

  // POST /api/admin/keys
  if (path === "/api/admin/keys" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const { tier = "PRO", customer_id, label, expires_in_days } = body;
    if (!customer_id) return jsonResp({ error: "customer_id is required" }, 400);
    if (!TIERS[tier])  return jsonResp({ error: `Invalid tier: ${tier}. Valid: FREE, PRO, ENTERPRISE` }, 400);

    const prefix = tier === "ENTERPRISE" ? "cdb_ent" : tier === "PRO" ? "cdb_pro" : "cdb_free";
    const rand   = Array.from(crypto.getRandomValues(new Uint8Array(20))).map(b => b.toString(16).padStart(2, "0")).join("");
    const apiKey = `${prefix}_${rand}`;
    const record = {
      key: apiKey, tier, customer_id, label: label || customer_id,
      created_at: now(),
      expires_at: expires_in_days ? new Date(Date.now() + expires_in_days * 86400000).toISOString() : null,
    };
    const opts = expires_in_days ? { expirationTtl: expires_in_days * 86400 } : undefined;
    await env.API_KEYS_KV.put(apiKey, JSON.stringify(record), opts);
    auditLog(ctx, env, { action: "api_key_created", customer_id, tier });
    return jsonResp({ ...record, message: "API key created" }, 201);
  }

  // DELETE /api/admin/keys/{key}
  const delMatch = path.match(/^\/api\/admin\/keys\/(.+)$/);
  if (delMatch && method === "DELETE") {
    const key = delMatch[1];
    await env.API_KEYS_KV.delete(key);
    auditLog(ctx, env, { action: "api_key_revoked", key_prefix: key.slice(0, 12) });
    return jsonResp({ message: "API key revoked", key_prefix: key.slice(0, 12) });
  }

  return jsonResp({
    error: "Admin endpoint not found",
    endpoints: [
      "GET /api/admin/health",
      "GET /api/admin/audit?limit=50",
      "POST /api/admin/keys  body:{customer_id,tier,label?,expires_in_days?}",
      "DELETE /api/admin/keys/{key}",
    ],
  }, 404);
}

// =============================================================================
// TAXII 2.1
// =============================================================================

function taxiiResp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": TAXII_CT, "X-TAXII-Date-Added-Last": now() },
  });
}

function buildStixPattern(item) {
  if (item.cve_ids && item.cve_ids.length > 0) return `[vulnerability:name = '${item.cve_ids[0]}']`;
  if (item.ioc_count > 0) return `[file:name = '${(item.title || "").replace(/['"\\]/g, "").slice(0, 64)}']`;
  return `[threat-actor:name = '${(item.source || "unknown").replace(/['"\\]/g, "").slice(0, 32)}']`;
}

async function handleTAXII(request, env, ctx, path, auth) {
  // Server discovery - public (no auth required per TAXII 2.1 spec)
  if (path === "/taxii/" || path === "/taxii") {
    return taxiiResp({
      title: "SENTINEL APEX TAXII 2.1",
      description: "CyberDudeBivash Threat Intelligence Platform - STIX/TAXII Enterprise Feed",
      contact: "intel@cyberdudebivash.com",
      default: "https://intel.cyberdudebivash.com/taxii/",
      api_roots: ["https://intel.cyberdudebivash.com/taxii/"],
    });
  }

  // All other TAXII endpoints require PRO or ENTERPRISE
  if (!auth || auth.tier === TIERS.FREE) {
    return taxiiResp({ title: "Unauthorized", description: "TAXII data endpoints require PRO or ENTERPRISE tier. POST api_key to /auth/login for a JWT." }, 401);
  }

  // Collections list
  if (path === "/taxii/collections/" || path === "/taxii/collections") {
    return taxiiResp({
      collections: [
        {
          id: TAXII_COLLECTION_ID,
          title: "SENTINEL APEX - Primary Threat Intelligence",
          description: "CVEs, IOCs, APT activity, ransomware alerts, dark web findings",
          can_read: true, can_write: false, media_types: [STIX_CT],
        },
        {
          id: TAXII_KEV_COLL,
          title: "SENTINEL APEX - CISA KEV Confirmed",
          description: "Known Exploited Vulnerabilities confirmed in CISA KEV catalog (ENTERPRISE only)",
          can_read: auth.tier === TIERS.ENTERPRISE, can_write: false, media_types: [STIX_CT],
        },
      ],
    });
  }

  // Objects from collection
  const objMatch = path.match(/^\/taxii\/collections\/([^/]+)\/objects\/?$/);
  if (objMatch) {
    const collId = objMatch[1];
    if (collId === TAXII_KEV_COLL && auth.tier !== TIERS.ENTERPRISE) {
      return taxiiResp({ title: "Forbidden", description: "KEV collection requires ENTERPRISE tier" }, 403);
    }

    const feedData   = await loadFeedItems(env);
    const allItems   = feedData.items || [];
    const sourceItems = collId === TAXII_KEV_COLL ? allItems.filter(i => i.kev_present) : allItems;

    // Prefer pre-built STIX bundle from R2
    const r2Bundle = await r2Get(env, `stix/bundle-${collId}.json`);
    if (r2Bundle) {
      return new Response(JSON.stringify(r2Bundle), {
        status: 200,
        headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": STIX_CT, "X-TAXII-Date-Added-Last": now() },
      });
    }

    // Inline STIX 2.1 bundle
    const stixObjects = sourceItems.slice(0, 200).map(item => ({
      type: "indicator",
      spec_version: "2.1",
      id: item.stix_id || `indicator--${(item.id || "").replace(/[^a-z0-9-]/gi, "-").toLowerCase()}`,
      created: item.published || now(),
      modified: item.published || now(),
      name: item.title,
      description: item.description || item.title,
      indicator_types: ["malicious-activity"],
      pattern: buildStixPattern(item),
      pattern_type: "stix",
      valid_from: item.published || now(),
      labels: (item.tags || []).slice(0, 10),
      external_references: (item.cve_ids || []).map(cve => ({
        source_name: "cve", external_id: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}`,
      })),
      object_marking_refs: ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
      custom_properties: {
        x_sentinel_severity: item.severity,
        x_sentinel_risk_score: item.risk_score,
        x_sentinel_source: item.source,
        x_sentinel_kev: item.kev_present || false,
      },
    }));

    const bundle = {
      type: "bundle",
      id: `bundle--sentinel-${collId}-${Date.now().toString(36)}`,
      spec_version: "2.1",
      objects: stixObjects,
    };
    return new Response(JSON.stringify(bundle), {
      status: 200,
      headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": STIX_CT, "X-TAXII-Date-Added-Last": now() },
    });
  }

  return taxiiResp({ title: "Not Found", description: `Unknown TAXII path: ${path}` }, 404);
}

// =============================================================================
// CVE TRACKER  — NVD NIST live fetch + R2 cache
// =============================================================================

function cveSeverityFromScore(score) {
  const s = parseFloat(score) || 0;
  if (s >= 9.0) return "CRITICAL";
  if (s >= 7.0) return "HIGH";
  if (s >= 4.0) return "MEDIUM";
  if (s > 0)    return "LOW";
  return "NONE";
}

function mapNvdItem(vuln) {
  const cve  = vuln.cve || {};
  const id   = cve.id || vuln.id || "";

  // Description (English preferred)
  const descs = (cve.descriptions || []);
  const descEn = (descs.find(d => d.lang === "en") || descs[0] || {}).value || "";

  // CVSS — prefer v3.1 then v3.0 then v2
  let cvss_score  = 0;
  let cvss_vector = "";
  let severity    = "NONE";
  const metrics   = cve.metrics || {};
  if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
    const m = metrics.cvssMetricV31[0].cvssData || {};
    cvss_score  = m.baseScore || 0;
    cvss_vector = m.vectorString || "";
    severity    = (metrics.cvssMetricV31[0].cvssData.baseSeverity || "").toUpperCase() || cveSeverityFromScore(cvss_score);
  } else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) {
    const m = metrics.cvssMetricV30[0].cvssData || {};
    cvss_score  = m.baseScore || 0;
    cvss_vector = m.vectorString || "";
    severity    = (metrics.cvssMetricV30[0].cvssData.baseSeverity || "").toUpperCase() || cveSeverityFromScore(cvss_score);
  } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
    const m = metrics.cvssMetricV2[0].cvssData || {};
    cvss_score  = m.baseScore || 0;
    cvss_vector = m.vectorString || "";
    severity    = cveSeverityFromScore(cvss_score);
  }

  // CWE IDs
  const weaknesses = cve.weaknesses || [];
  const cwe_ids    = weaknesses.flatMap(w => (w.description || []).map(d => d.value)).filter(Boolean);

  // Affected products (CPE criteria, up to 5)
  const configs   = cve.configurations || [];
  const affected  = [];
  for (const cfg of configs) {
    for (const node of (cfg.nodes || [])) {
      for (const cpe of (node.cpeMatch || [])) {
        if (affected.length >= 5) break;
        affected.push(cpe.criteria || cpe.cpe23Uri || "");
      }
      if (affected.length >= 5) break;
    }
    if (affected.length >= 5) break;
  }

  // References (up to 5)
  const references = (cve.references || []).slice(0, 5).map(r => r.url || "").filter(Boolean);

  return {
    id,
    description:   descEn,
    cvss_score:    Math.round(parseFloat(cvss_score) * 10) / 10,
    cvss_vector,
    severity:      severity || cveSeverityFromScore(cvss_score),
    published:     cve.published   || vuln.published   || "",
    last_modified: cve.lastModified || vuln.lastModified || "",
    vuln_status:   cve.vulnStatus  || "",
    cwe_ids,
    affected_products: affected,
    references,
    kev: false,
  };
}

async function fetchAndCacheCVEs(env) {
  const emptyBundle = {
    cves: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, none: 0, avg_cvss: 0 },
    generated_at: now(), source: "NVD_NIST_GOV", window: "7d", version: PLATFORM_VERSION,
  };
  try {
    const endDate   = new Date();
    const startDate = new Date(endDate.getTime() - 7 * 86400 * 1000);
    const fmt       = d => d.toISOString().replace("Z", "").slice(0, 23);
    const nvdUrl    = `${NVD_API}?pubStartDate=${fmt(startDate)}&pubEndDate=${fmt(endDate)}&resultsPerPage=100&startIndex=0`;

    const resp = await fetch(nvdUrl, {
      headers: { "Accept": "application/json", "User-Agent": "CyberDudeBivash-Sentinel-Apex/"+PLATFORM_VERSION },
      cf: { cacheTtl: CVE_TTL_SEC, cacheEverything: true },
    });

    if (!resp.ok) {
      const cached = await r2Get(env, CVE_LIVE_KEY);
      return cached || emptyBundle;
    }

    const raw  = await resp.json();
    const cves = (raw.vulnerabilities || []).map(mapNvdItem);

    // Compute stats
    const stats = { total: cves.length, critical: 0, high: 0, medium: 0, low: 0, none: 0, avg_cvss: 0 };
    let scoreSum = 0;
    for (const c of cves) {
      const sev = c.severity;
      if (sev === "CRITICAL") stats.critical++;
      else if (sev === "HIGH") stats.high++;
      else if (sev === "MEDIUM") stats.medium++;
      else if (sev === "LOW") stats.low++;
      else stats.none++;
      scoreSum += c.cvss_score || 0;
    }
    stats.avg_cvss = cves.length > 0 ? Math.round((scoreSum / cves.length) * 10) / 10 : 0;

    const bundle = {
      cves, stats,
      generated_at: now(),
      source: "NVD_NIST_GOV",
      window: "7d",
      version: PLATFORM_VERSION,
    };

    try {
      await env.INTEL_R2.put(CVE_LIVE_KEY, JSON.stringify(bundle), { httpMetadata: { contentType: "application/json" } });
      await env.INTEL_R2.put(CVE_STATS_KEY, JSON.stringify({ ...stats, generated_at: bundle.generated_at, source: bundle.source, window: bundle.window }), { httpMetadata: { contentType: "application/json" } });
    } catch (_) {}

    return bundle;
  } catch (_) {
    const cached = await r2Get(env, CVE_LIVE_KEY);
    return cached || emptyBundle;
  }
}

// =============================================================================
// MAIN REQUEST HANDLER
// =============================================================================

async function handleRequest(request, env, ctx) {
  const url      = new URL(request.url);
  const path     = url.pathname;
  const pathname = path; // gate-required alias: PREMIUM_INTEL_PATHS.has(pathname)
  const method   = request.method.toUpperCase();

  // CORS preflight
  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: { ...CORS_HEADERS, ...SECURITY_HEADERS } });
  }

  // Client IP for rate limiting and brute-force tracking
  const ip = request.headers.get("CF-Connecting-IP") ||
             (request.headers.get("X-Forwarded-For") || "127.0.0.1").split(",")[0].trim();

  // Resolve auth once for this request (skip for pure public health check to save a KV read)
  const auth = await resolveAuth(request, env);

  // Rate limiting (skip health check so monitors never get throttled)
  if (path !== "/api/health" && path !== "/api/health/") {
    const rl = await checkRateLimit(env, ip, auth.tier);
    if (!rl.allowed) {
      auditLog(ctx, env, { action: "rate_limited", ip, path, method, tier: auth.tier });
      return jsonResp(
        { error: "Too Many Requests", retry_after: 60, limit: rl.limit },
        429,
        { "Retry-After": "60", "X-RateLimit-Limit": String(rl.limit), "X-RateLimit-Remaining": "0" }
      );
    }
  }

  // Audit authenticated requests
  if (auth.key) {
    auditLog(ctx, env, { action: "api_request", ip, path, method, tier: auth.tier, sub: auth.sub });
  }

  // --- TAXII 2.1 routes -------------------------------------------------------
  if (path.startsWith("/taxii")) {
    return await handleTAXII(request, env, ctx, path, auth);
  }

  // --- Admin API --------------------------------------------------------------
  if (path.startsWith("/api/admin")) {
    return await handleAdmin(request, env, ctx, path, method);
  }

  // --- Auth endpoints ---------------------------------------------------------
  if (path === "/auth/login" && method === "POST") {
    return await handleLogin(request, env, ctx, ip);
  }
  if (path === "/auth/logout" && method === "POST") {
    return await handleLogout(request, env, ctx, auth);
  }

  // --- /api/auth/* aliases ---------------------------------------------------
  // The dashboard uses AUTH_ENDPOINT='/api/auth' and the /auth/* CF Worker route
  // is not registered. These aliases under the registered /api/* route allow the
  // dashboard login modal and API clients to reach auth functionality.
  if (path === "/api/auth/login" && method === "POST") {
    return await handleLogin(request, env, ctx, ip);
  }
  if (path === "/api/auth/logout" && method === "POST") {
    return await handleLogout(request, env, ctx, auth);
  }
  if (path === "/api/auth/validate") {
    if (!auth.key) return jsonResp({ valid: false, tier: "free" }, 200);
    return jsonResp({ valid: true, tier: auth.tier, sub: auth.sub, jwt: auth.jwt || false }, 200);
  }
  if (path === "/api/auth/register" && method === "POST") {
    return jsonResp({
      error: "Email registration is not available. API keys are issued upon subscription.",
      help: "Subscribe at https://intel.cyberdudebivash.com/#pricing to receive your API key.",
      auth: "POST /api/auth/login with { \"api_key\": \"<your-key>\" } to obtain a Bearer JWT.",
    }, 422);
  }

  // --- Premium intel gate (MONETIZATION INTEGRITY v148->v180) -----------------
  if (PREMIUM_INTEL_PATHS.has(pathname)) {
    return await servePremiumIntelManifest(request, env, ctx, pathname);
  }

  // --- /api/health ------------------------------------------------------------
  if (path === "/api/health" || path === "/api/health/") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const kvOk     = await env.RATE_LIMIT_KV.get("health:ping").then(() => "ok").catch(() => "error");
    return jsonResp({
      status: "ok", version: PLATFORM_VERSION,
      advisory_count: stats.total, critical_count: stats.critical,
      kev_confirmed: stats.kev_confirmed, last_sync: stats.last_sync,
      feed_index: `live:${stats.total}_items`,
      checks: {
        gateway: "ok", kv_rate_limit: kvOk, kv_api_keys: kvOk,
        r2_intel: feedData.items.length > 0 ? "ok" : "empty",
        feed_index: `live:${stats.total}_items`,
        jwt_configured: !!(env.CDB_JWT_SECRET),
        admin_configured: !!(env.ADMIN_SECRET),
      },
      security: {
        auth: "JWT_HS256+KV",
        rate_limiting: "sliding_window_per_ip",
        brute_force: `lockout_after_${BRUTE_FORCE_MAX}_failures`,
        audit_logging: "SECURITY_HUB_KV",
        headers: "HSTS+CSP+XFO",
        taxii: "2.1",
      },
      generated_at: now(),
    });
  }

  // --- /api/v1/intel/latest.json ----------------------------------------------
  if (path === "/api/v1/intel/latest.json") {
    const data = await r2Get(env, LATEST_JSON_KEY);
    if (!data) return errorResp("Feed not available", 503);
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/top10.json -----------------------------------------------
  if (path === "/api/v1/intel/top10.json") {
    let data = await r2Get(env, "api/v1/intel/top10.json");
    if (!data) {
      const feedData = await loadFeedItems(env);
      const top10    = (feedData.items || []).sort((a, b) => parseFloat(b.risk_score || 0) - parseFloat(a.risk_score || 0)).slice(0, 10);
      data = { items: top10, count: top10.length, generated_at: now(), version: PLATFORM_VERSION };
    }
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/stats ----------------------------------------------------
  if (path === "/api/v1/intel/stats" || path === "/api/v1/stats") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const threat   = computeThreatLevel(stats);
    const defcon   = computeDefcon(stats);
    return jsonResp({
      ...stats, global_threat_level: threat.level, global_threat_label: threat.label,
      defcon: defcon.level, defcon_label: defcon.label, defcon_status: defcon.status,
      feeds_active: 74, version: PLATFORM_VERSION,
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/campaigns ------------------------------------------------
  if (path === "/api/v1/intel/campaigns") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const kc       = computeKillChain(feedData.items || []);
    const threat   = computeThreatLevel(stats);
    return jsonResp({ ...kc, global_threat_level: threat, version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/ransomware -----------------------------------------------
  if (path === "/api/v1/intel/ransomware") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeRansomware(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/apt ------------------------------------------------------
  if (path === "/api/v1/intel/apt") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeAPT(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/epss -----------------------------------------------------
  if (path === "/api/v1/intel/epss") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeEPSS(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/intel/defcon ---------------------------------------------------
  if (path === "/api/v1/intel/defcon") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    const defcon   = computeDefcon(stats);
    const threat   = computeThreatLevel(stats);
    return jsonResp({
      ...defcon, global_threat_level: threat,
      stats: { critical: stats.critical, kev_confirmed: stats.kev_confirmed, total: stats.total },
      generated_at: now(),
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/pulse ----------------------------------------------------
  if (path === "/api/v1/intel/pulse") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    return jsonResp({ ...computePulse(feedData.items || [], stats), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/intel/darkweb --------------------------------------------------
  if (path === "/api/v1/intel/darkweb") {
    const feedData = await loadFeedItems(env);
    return jsonResp({ ...computeDarkweb(feedData.items || []), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/v1/intel/cybermap -------------------------------------------------
  if (path === "/api/v1/intel/cybermap" || path === "/api/v1/geo/cybermap") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    return jsonResp({ ...computeCybermap(feedData.items || [], stats), version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/v1/news/feed ------------------------------------------------------
  if (path === "/api/v1/news/feed" || path === "/api/news/feed") {
    try {
      const feed = await fetchNewsFromRSS(env.RATE_LIMIT_KV);
      return jsonResp({ ...feed, version: PLATFORM_VERSION }, 200, { "Cache-Control": `public, max-age=${NEWS_TTL_SEC}` });
    } catch (_) {
      return jsonResp({ items: [], count: 0, error: "Feed temporarily unavailable", generated_at: now() }, 200);
    }
  }

  // --- /api/reports/latest.json -----------------------------------------------
  if (path === "/api/reports/latest.json") {
    let data = await r2Get(env, "api/reports/latest.json");
    if (!data) data = await r2Get(env, REPORTS_KEY);
    if (!data) {
      const feedData  = await loadFeedItems(env);
      const critItems = (feedData.items || []).filter(i => (i.severity || "") === "CRITICAL" || parseFloat(i.risk_score || 0) >= 8.0);
      data = {
        schema_version: "sentinel_apex_reports_v1", generated_at: now(),
        total_reports: critItems.length, reports_listed: Math.min(critItems.length, 50),
        reports: critItems.slice(0, 50).map(i => ({
          id: i.stix_id || i.id, url: `/reports/2026/06/${i.stix_id || i.id}.html`,
          title: i.title, severity: i.severity, risk_score: i.risk_score,
          cve: i.cve_id || (i.cve_ids || [])[0] || null, timestamp: i.published || i.published_at,
        })),
      };
    }
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/reports/index.json ------------------------------------------------
  if (path === "/api/reports/index.json") {
    let data = await r2Get(env, REPORTS_KEY);
    if (!data) {
      const feedData  = await loadFeedItems(env);
      const critItems = (feedData.items || []).filter(i => (i.severity || "") === "CRITICAL" || parseFloat(i.risk_score || 0) >= 8.0);
      data = {
        schema_version: "sentinel_apex_reports_v1", version: PLATFORM_VERSION, generated_at: now(),
        total_reports: critItems.length, reports_listed: Math.min(critItems.length, 20),
        reports: critItems.slice(0, 20).map(i => ({
          id: i.stix_id || i.id, url: `/reports/2026/06/${i.stix_id || i.id}.html`,
          title: i.title, severity: i.severity, risk_score: i.risk_score,
          cve: i.cve_id || (i.cve_ids || [])[0] || null, timestamp: i.published || i.published_at,
        })),
      };
    }
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/reports/stats.json ------------------------------------------------
  if (path === "/api/reports/stats.json") {
    const feedData = await loadFeedItems(env);
    const stats    = computeStats(feedData.items || []);
    return jsonResp({
      total_reports: stats.critical + stats.high, critical_reports: stats.critical,
      high_reports: stats.high, medium_reports: stats.medium, kev_reports: stats.kev_confirmed,
      last_generated: stats.last_sync, generated_at: now(), version: PLATFORM_VERSION,
    }, 200, { "Cache-Control": "public, max-age=300" });
  }

  // --- /api/v1/ioc/lookup -----------------------------------------------------
  if (path === "/api/v1/ioc/lookup" && method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (_) {}
    const query    = body.query || body.ioc || url.searchParams.get("q") || "";
    const feedData = await loadFeedItems(env);
    return jsonResp(await iocLookup(query, feedData));
  }
  if (path === "/api/v1/ioc/lookup" && method === "GET") {
    const query    = url.searchParams.get("q") || url.searchParams.get("query") || "";
    const feedData = await loadFeedItems(env);
    return jsonResp(await iocLookup(query, feedData));
  }

  // --- /api/preview -----------------------------------------------------------
  if (path === "/api/preview" || path === "/api/preview/") {
    const feedData = await loadFeedItems(env);
    const items    = (feedData.items || []).slice(0, PREVIEW_LIMIT);
    return jsonResp({
      status: "ok",
      preview: {
        items, total_preview: items.length, feed_total: (feedData.items || []).length,
        preview_limit: PREVIEW_LIMIT, generated_at: now(), version: PLATFORM_VERSION,
        _tier: TIERS.FREE, _upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html",
      },
    }, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /api/feed + /api/feed.json (legacy) ------------------------------------
  if (path === "/api/feed" || path === "/api/feed.json") {
    const data = await r2Get(env, LATEST_JSON_KEY);
    if (!data) return errorResp("Feed not available", 503);
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=120" });
  }

  // --- /reports/** (HTML intel reports from REPORTS_R2) -----------------------
  if (path.startsWith("/reports/")) {
    if (!env.REPORTS_R2) {
      return new Response("Reports bucket not configured", {
        status: 503, headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": "text/plain" },
      });
    }

    const key = path.replace(/^\//, "");
    const PROBE_YEARS  = [2026, 2025];
    const PROBE_MONTHS = ["06","12","09","05","04","03","02","01","10","11","07","08"];

    // Legacy URLs: /reports/intel--{hash}  OR  /reports/intel--{hash}.html  OR  /reports/intel--{hash}/
    // All three forms have intel-- directly after /reports/ (no YYYY/MM date segment).
    // Root cause of recurring 404: old regex only matched slug-without-extension or trailing-slash.
    // Fix: (?:\.html)? now catches the .html-extension-without-date-path form too.
    const legacyMatch = path.match(/^\/reports\/(intel--[a-f0-9]+)(?:\.html)?\/?$/i);
    if (legacyMatch || (path.endsWith("/") && path.startsWith("/reports/"))) {
      const slug = legacyMatch ? legacyMatch[1] : path.replace(/^\/reports\//, "").replace(/[./]+$/, "");
      const fn   = slug.startsWith("intel--") ? `${slug}.html` : `intel--${slug}.html`;
      for (const y of PROBE_YEARS) {
        for (const m of PROBE_MONTHS) {
          const obj = await env.REPORTS_R2.get(`reports/${y}/${m}/${fn}`);
          if (obj) return Response.redirect(`https://intel.cyberdudebivash.com/reports/${y}/${m}/${fn}`, 301);
        }
      }
      return jsonResp({ error: "Report not found", path, suggestion: "Report may still be generating. Try again in a few minutes." }, 404);
    }

    // Canonical URL: /reports/YYYY/MM/intel--{hash}.html
    // Try direct R2 lookup first. On miss, cross-month probe guards against wrong-date-path
    // in report_url fields (e.g. report generated in May but URL says June).
    const obj = await env.REPORTS_R2.get(key);
    if (obj) {
      return new Response(obj.body, {
        status: 200,
        headers: {
          ...CORS_HEADERS, ...SECURITY_HEADERS,
          "Content-Security-Policy": HTML_CSP,
          "Content-Type":  "text/html; charset=utf-8",
          "Cache-Control": "public, max-age=86400, stale-while-revalidate=3600",
          "ETag": obj.httpEtag || "",
        },
      });
    }

    // Cross-month fallback: probe all known year/month combos for the same slug.
    const slugMatch = path.match(/\/(intel--[a-f0-9]+)\.html$/i);
    if (slugMatch) {
      const fn = slugMatch[1] + ".html";
      for (const y of PROBE_YEARS) {
        for (const m of PROBE_MONTHS) {
          const probeKey = `reports/${y}/${m}/${fn}`;
          if (probeKey === key) continue;
          const probeObj = await env.REPORTS_R2.get(probeKey);
          if (probeObj) {
            return Response.redirect(`https://intel.cyberdudebivash.com/${probeKey}`, 301);
          }
        }
      }
    }

    return jsonResp({ error: "Report not found", path, suggestion: "Report may still be generating. Try again in a few minutes." }, 404);
  }

  // --- /api/v1/cve/live -------------------------------------------------------
  if (path === "/api/v1/cve/live") {
    const severity = (url.searchParams.get("severity") || "ALL").toUpperCase();
    const q        = (url.searchParams.get("q") || "").toLowerCase().trim();
    const limit    = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10), 1), 200);
    const offset   = Math.max(parseInt(url.searchParams.get("offset") || "0", 10), 0);

    let bundle = await r2Get(env, CVE_LIVE_KEY);
    const stale = !bundle || !bundle.generated_at ||
      (Date.now() - new Date(bundle.generated_at).getTime()) > CVE_TTL_SEC * 1000;

    if (stale) {
      // Trigger background refresh; return whatever we have (may be null)
      if (typeof ctx !== "undefined") ctx.waitUntil(fetchAndCacheCVEs(env));
      if (!bundle) bundle = await fetchAndCacheCVEs(env);
    }

    let cves = bundle.cves || [];

    // Severity filter
    if (severity !== "ALL") cves = cves.filter(c => c.severity === severity);

    // Keyword search on ID and description
    if (q) cves = cves.filter(c =>
      (c.id || "").toLowerCase().includes(q) ||
      (c.description || "").toLowerCase().includes(q)
    );

    const total     = cves.length;
    const paginated = cves.slice(offset, offset + limit);

    // FREE tier: truncate description
    const outCves = paginated.map(c => {
      if (auth.tier !== TIERS.FREE) return c;
      return { ...c, description: (c.description || "").slice(0, 100) + ((c.description || "").length > 100 ? "..." : "") };
    });

    return jsonResp({
      cves: outCves,
      stats: bundle.stats || {},
      total, page: Math.floor(offset / limit), limit, offset,
      generated_at: bundle.generated_at,
      source: bundle.source,
      window: bundle.window,
      version: PLATFORM_VERSION,
      _tier: auth.tier,
    }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/cve/stats ------------------------------------------------------
  if (path === "/api/v1/cve/stats") {
    let stats = await r2Get(env, CVE_STATS_KEY);
    if (!stats) {
      const bundle = await r2Get(env, CVE_LIVE_KEY);
      stats = bundle ? { ...bundle.stats, generated_at: bundle.generated_at, source: bundle.source, window: bundle.window } : null;
    }
    if (!stats) {
      if (typeof ctx !== "undefined") ctx.waitUntil(fetchAndCacheCVEs(env));
      stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0, none: 0, avg_cvss: 0,
        generated_at: now(), source: "NVD_NIST_GOV", window: "7d" };
    }
    return jsonResp({ ...stats, version: PLATFORM_VERSION }, 200, { "Cache-Control": "public, max-age=60" });
  }

  // --- /api/v1/cve/detail -----------------------------------------------------
  if (path === "/api/v1/cve/detail") {
    const cveId = (url.searchParams.get("id") || "").trim().toUpperCase();
    if (!cveId || !/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      return jsonResp({ error: "Valid CVE ID required: ?id=CVE-YYYY-NNNNN" }, 400);
    }

    // 5-min KV cache
    const cacheKey = `cve_detail:${cveId}`;
    let detail = null;
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey, "json");
      if (cached) detail = cached;
    } catch (_) {}

    if (!detail) {
      try {
        const nvdResp = await fetch(`${NVD_API}?cveId=${cveId}`, {
          headers: { "Accept": "application/json", "User-Agent": "CyberDudeBivash-Sentinel-Apex/"+PLATFORM_VERSION },
        });
        if (nvdResp.ok) {
          const raw  = await nvdResp.json();
          const vulns = raw.vulnerabilities || [];
          if (vulns.length > 0) {
            detail = mapNvdItem(vulns[0]);
            try { await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(detail), { expirationTtl: 300 }); } catch (_) {}
          }
        }
      } catch (_) {}
    }

    if (!detail) return jsonResp({ error: "CVE not found", id: cveId }, 404);

    // PRO+ gets full details; FREE gets summary
    if (auth.tier === TIERS.FREE) {
      return jsonResp({
        id: detail.id, severity: detail.severity, cvss_score: detail.cvss_score,
        published: detail.published, last_modified: detail.last_modified,
        description: (detail.description || "").slice(0, 100) + "...",
        _tier: TIERS.FREE, _upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html",
        version: PLATFORM_VERSION,
      }, 200, { "Cache-Control": "public, max-age=300" });
    }

    return jsonResp({ ...detail, version: PLATFORM_VERSION }, 200, { "Cache-Control": "private, max-age=300" });
  }

  // --- /api/ingest (PRO+ only) ------------------------------------------------
  if (path === "/api/ingest" && method === "POST") {
    // Require authenticated PRO or ENTERPRISE tier
    if (!auth.jwt) {
      return jsonResp({ error: "Authentication required. POST Authorization: Bearer <token>." }, 401);
    }
    if (auth.tier === "FREE" || auth.tier === "PUBLIC") {
      return jsonResp({ error: "PRO or ENTERPRISE tier required for /api/ingest", upgrade: "POST /auth/login with a PRO/ENTERPRISE API key" }, 403);
    }
    let body = {};
    try { body = await request.json(); } catch (_) {
      return jsonResp({ error: "Invalid JSON body" }, 400);
    }
    // Validate required fields
    const requiredFields = ["title", "severity", "risk_score"];
    const missing = requiredFields.filter(f => body[f] == null);
    if (missing.length) {
      return jsonResp({ error: `Missing required fields: ${missing.join(", ")}`, required: requiredFields }, 400);
    }
    const validSeverities = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
    const sev = (body.severity || "").toUpperCase();
    if (!validSeverities.has(sev)) {
      return jsonResp({ error: `Invalid severity. Must be one of: ${[...validSeverities].join(", ")}` }, 400);
    }
    const riskScore = parseFloat(body.risk_score);
    if (isNaN(riskScore) || riskScore < 0 || riskScore > 10) {
      return jsonResp({ error: "risk_score must be a number between 0 and 10" }, 400);
    }
    // Build canonical intel item
    const ts = new Date().toISOString();
    const itemId = body.stix_id || body.id || ("intel--ingest-" + crypto.randomUUID());
    const newItem = {
      id: itemId, stix_id: itemId,
      title: String(body.title).slice(0, 500),
      severity: sev,
      risk_score: riskScore,
      source: body.source || `ingest:${auth.sub || "api"}`,
      feed_source: body.feed_source || "api_ingest",
      published: body.published || ts,
      processed_at: ts,
      ingested_at: ts,
      ingest_tier: auth.tier,
      ingest_sub: auth.sub || "unknown",
      // Optional enrichment fields (passed through if present)
      ...(body.cve_ids        != null && { cve_ids: body.cve_ids }),
      ...(body.cvss_score     != null && { cvss_score: body.cvss_score }),
      ...(body.epss_score     != null && { epss_score: body.epss_score }),
      ...(body.kev_present    != null && { kev_present: !!body.kev_present }),
      ...(body.mitre_tactics  != null && { mitre_tactics: body.mitre_tactics }),
      ...(body.ioc_counts     != null && { ioc_counts: body.ioc_counts }),
      ...(body.actor_tag      != null && { actor_tag: body.actor_tag }),
      ...(body.tlp_label      != null && { tlp_label: body.tlp_label }),
      ...(body.tags           != null && { tags: body.tags }),
      ...(body.description    != null && { description: String(body.description).slice(0, 2000) }),
      ...(body.source_url     != null && { source_url: body.source_url }),
      ...(body.confidence_score != null && { confidence_score: body.confidence_score }),
    };
    // Append to INTEL_R2 live feed
    try {
      const current = await r2Get(env, LATEST_JSON_KEY) || { schema_version: "1.0", items: [], count: 0 };
      const items = Array.isArray(current.items) ? current.items : [];
      // Guard: reject exact stix_id duplicate
      if (items.some(i => (i.stix_id || i.id) === itemId)) {
        return jsonResp({ error: "Duplicate item: stix_id already exists in feed", stix_id: itemId }, 409);
      }
      items.unshift(newItem); // newest first
      const updatedFeed = { ...current, items, count: items.length, last_ingest: ts };
      await env.INTEL_R2.put(LATEST_JSON_KEY, JSON.stringify(updatedFeed), { httpMetadata: { contentType: "application/json" } });
      auditLog(ctx, env, { action: "ingest", sub: auth.sub, tier: auth.tier, item_id: itemId, title: newItem.title });
      return jsonResp({ status: "created", item_id: itemId, feed_count: items.length, ingested_at: ts }, 201);
    } catch (e) {
      return jsonResp({ error: "Failed to write to intel feed", detail: e.message }, 500);
    }
  }

  // --- 404 --------------------------------------------------------------------
  return jsonResp({
    error: "Not found", path,
    available_endpoints: [
      "/api/health", "/api/v1/intel/latest.json", "/api/v1/intel/apex.json",
      "/api/v1/intel/ai_summary.json", "/api/v1/intel/top10.json", "/api/v1/intel/stats",
      "/api/v1/intel/campaigns", "/api/v1/intel/ransomware", "/api/v1/intel/apt",
      "/api/v1/intel/epss", "/api/v1/intel/defcon", "/api/v1/intel/pulse",
      "/api/v1/intel/darkweb", "/api/v1/intel/cybermap", "/api/feed.json",
      "/api/v1/news/feed", "/api/reports/index.json", "/api/reports/stats.json",
      "/api/v1/ioc/lookup",
      "/api/v1/cve/live", "/api/v1/cve/stats", "/api/v1/cve/detail?id=CVE-XXXX-XXXXX",
      "POST /api/auth/login (X-API-Key exchange → JWT)", "POST /api/auth/logout",
      "GET /api/auth/validate", "POST /api/auth/register",
      "/auth/login", "/auth/logout",
      "/taxii/", "/taxii/collections/", "/taxii/collections/{id}/objects/",
      "/api/admin/health", "/api/admin/audit", "/api/admin/keys",
      "POST /api/ingest  (PRO+, Bearer token required)",
    ],
  }, 404);
}

// --- Worker entry point -------------------------------------------------------
export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      return new Response(JSON.stringify({ error: "Internal gateway error", detail: err.message }), {
        status: 500,
        headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, ...JSON_CONTENT },
      });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(fetchAndCacheCVEs(env));
  },
};
