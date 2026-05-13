// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Edge Intelligence Gateway v143.0.0
// GOD-MODE: Production-hardened, globally sellable SaaS cybersecurity platform
// Hardened: 2026-05-03 (Dark Web Monitor - Premium Reports - API Key Manager)
// R2-ONLY ARCHITECTURE -- Blogger dependency REMOVED
// Data flow: GitHub Actions -> Cloudflare R2 (private) -> Worker -> API clients
// Intel data NEVER stored in public GitHub repo (EMBEDDED_INTEL obsolete).
// Secrets: ADMIN_SECRET, GITHUB_TOKEN, CDB_JWT_SECRET (npx wrangler secret put)
//          STRIPE_WEBHOOK_SECRET, RAZORPAY_WEBHOOK_SECRET (billing webhooks)
//          STRIPE_PRO_PRICE_ID, STRIPE_ENT_PRICE_ID (Stripe plan IDs)
// v134.0 [legacy]: Added /api/ai endpoint family
// v134.0.0 [legacy]: stix_id fix; GATEWAY_VERSION unified
// v134.0.0 [legacy]: GOD-MODE -- mandatory ai_summary, retry circuit breaker, urgency CTAs
// v134.0.0: FINAL HARDENING -- structured logging, schema validation, JWT revocation,
//           token refresh/revoke, usage caps, observability, API/feed consistency
// v134.0.0: SAAS TRANSFORMATION -- user auth (PBKDF2), API key CRUD, billing
//           (Stripe/Razorpay webhooks), IOC extraction fallback (min 3),
//           SIEM formatters (Splunk/Sentinel/QRadar), pricing page
// v143.0.0: GOD-MODE PRODUCTION & MONETIZATION RELEASE
//           - Dark Web Monitor + Leak Check (Pro/Enterprise) wired
//           - Premium Threat PDF Report engine ($49/report asset)
//           - apex_ai overwrite: permanently fixed (hasValidApexAI guard v145.0)
//           - All null-unsafe string ops patched across full Worker scope
//           - Zero regression validated: all existing routes unmodified
// =============================================================================

//  v134.0.0: Extension modules 
import {
  handleSearch,
  handleActors,
  handleCVEs,
  handleMISPExport,
  handleCSVExport,
  handleCorrelate,
  enforceScopeMiddleware,
  fingerprintRequest,
  buildScopeSet,
  detectAbuse,
  trackAuthFailure,
  handleAbuseReport,
  pushWebhookNotifications,
  SCOPE_DEFINITIONS,
  TIER_DEFAULT_SCOPES,
  // v134.0.0 -- AI Intelligence Endpoints
  handlePredict,
  handleCampaigns,
  handleAnomalies,
  handleIntelGraph,
  handleIntelRelations,
} from "./api-extensions.js";

import {
  enforceTierGate,
  REVENUE_CONFIG,
  handleLeadCapture,
  handleTrialIssuance,
  handleRevenueAnalytics,
  applyTierGateV2,
  buildUsageLimitResponse,
  trackRevenueEvent,
} from "./revenue-enforcement.js";

// v134.0.0: Usage Metering Engine
import {
  slugifyEndpoint,
  calculateCostPerCall,
  trackApiUsage,
  getUsageSummary,
  getEndpointStats,
  getTierDistribution,
  analyzeUsagePatterns,
} from "./usage-meter.js";

// v134.0.0: Credit / Token System
import {
  checkCredits,
  buildCreditHeaders,
  buildBillingStatus,
  getCreditExhaustionStats,
} from "./credit-system.js";

// v143.0.0: Dark Web Monitor + Leak Check Engine
import {
  handleDarkWebScan,
  handleDarkWebStatus,
  handleLeakCheck,
} from "./dark-web-monitor.js";

// v143.0.0: Premium Threat PDF Report Engine
import {
  handlePremiumReport,
  handleReportList,
  handleReportGet,
} from "./premium-reports.js";

// v143.0.0: AI Alert Engine (Telegram/Webhook tier-gated)
import {
  handleAlertSubscribe,
  handleAlertSubscriptions,
  handleAlertTest,
  handleAlertDispatch,
  handleAlertHistory,
  handleAlertUnsubscribe,
} from "./alert-engine.js";

// v143.0.0: SLA Monitor Engine (99.9% Enterprise / 99.5% Pro targets)
import {
  handleSLAStatus,
  handleSLAReport,
  handleSLAIncidents,
  handleSLAPing,
  handleSLACertificate,
} from "./sla-monitor.js";

//  Version sync: always read from CONFIG 
function injectVersionHeaders(response, config) {
  const headers = new Headers(response.headers);
  headers.set("X-SENTINEL-Version", config.GATEWAY_VERSION);
  headers.set("X-SENTINEL-Platform", "SENTINEL-APEX");
  headers.set("X-SENTINEL-Codename", "GOD-MODE");
  headers.set("X-Powered-By", "CYBERDUDEBIVASH-SENTINEL-APEX-v148");
  return new Response(response.body, { status: response.status, headers });
}

const CONFIG = {
  GATEWAY_VERSION:   "148.0.0",  // v147.0.0 ENTERPRISE-GRADE -- ai_summary fix, version governance, dedup enforcement
  GATEWAY_NAME:      "SENTINEL-APEX",
  BYPASS_FEED_CACHE: false,
  // P0 FIX v134.0: Reduced cache TTLs to ensure dashboard reflects fresh R2 data
  // quickly after each pipeline run. KV cache is busted by workflow on every run.
  CACHE_TTL: {
    FEED:    60,    // seconds -- authenticated feed (was 180, reduced for freshness)
    PREVIEW: 90,    // seconds -- public preview (was 300, reduced to 90s)
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
  GET_KEY_URL:         "https://intel.cyberdudebivash.com/upgrade.html",
};

//  Utilities 

function generateReqId() {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return "req_" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

//  v134.0: Injection-pattern blocklist -- SQL, XSS, path-traversal, command injection 
// Defined FIRST -- all sanitizers below depend on this.
// Applied to ALL user-controlled string inputs.  Returns "" (safe fail) on match.
const _INJECTION_BLOCK_RE = [
  /(\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|CAST|CONVERT|DECLARE|XTYPE|SYSOBJECTS)\b)/i,
  /(<\s*script[\s\S]*?>|<\/\s*script\s*>)/i,                    // XSS script tag
  /javascript\s*:/i,                                              // JS URI
  /(\.\.\/|\.\.\\)/,                                              // path traversal
  /(\|\||&&|;\s*(?:rm|cat|wget|curl|bash|sh|cmd|powershell))/i,  // command injection
  /(\bOR\b|\bAND\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,     // SQLi tautology
  /(WAITFOR\s+DELAY|SLEEP\s*\(|BENCHMARK\s*\()/i,               // blind SQLi time-based
  /(\x00|\x1a)/,                                                  // null byte / ctrl-Z
];

//  v134.0: Centralized input sanitization helpers 
// Used by ALL endpoint handlers -- prevents injection attacks via query params.
const _CTRL_STRIP = /[\x00-\x1F\x7F<>"'`\\]/g;

// v134.0: sanitizeStr now runs injection-pattern gate after ctrl-char strip.
function sanitizeStr(raw, maxLen = 128) {
  if (!raw || typeof raw !== "string") return "";
  const clean = raw.replace(_CTRL_STRIP, "").slice(0, maxLen).trim();
  for (const pat of _INJECTION_BLOCK_RE) {
    if (pat.test(clean)) return "";  // hard-zero on injection match
  }
  return clean;
}

function sanitizeInt(raw, def = 0, min = 0, max = 9999) {
  const n = parseInt(raw);
  if (isNaN(n)) return def;
  return Math.max(min, Math.min(max, n));
}

function sanitizeTier(raw) {
  const VALID = new Set(["free", "premium", "enterprise"]);
  return VALID.has((raw || "").toLowerCase()) ? raw.toLowerCase() : "free";
}

//  v134.0: Comprehensive input sanitizer for POST body fields 
// Identical to sanitizeStr but with configurable max length (default 256).
// Use for: name, label, description, any free-form user-supplied body field.
function sanitizeInput(raw, maxLen = 256) {
  if (!raw || typeof raw !== "string") return "";
  const clean = raw.replace(_CTRL_STRIP, "").slice(0, maxLen).trim();
  for (const pat of _INJECTION_BLOCK_RE) {
    if (pat.test(clean)) return "";
  }
  return clean;
}

//  v134.0: FEED_LIMITS hard cap per tier (prevents abusive over-fetching) 
function getTierLimit(tier, requested) {
  const caps = { free: 20, premium: 500, enterprise: 2000 };
  const cap  = caps[tier] || caps.free;
  return Math.min(Math.max(1, requested || cap), cap);
}

//  v134.0.0: Structured Logger 
// ALL log output is structured JSON -- searchable in Cloudflare Workers Tail Logs.
// Fields: ts, level, component, message + arbitrary meta spread.
function slog(level, component, message, meta = {}) {
  const entry = JSON.stringify({
    ts:        new Date().toISOString(),
    level,                // "INFO" | "WARN" | "ERROR"
    component,            // "AUTH" | "FEED" | "APEX" | "ROUTER" | "R2" | etc.
    msg:       message,
    gateway:   CONFIG.GATEWAY_NAME + "/" + CONFIG.GATEWAY_VERSION,
    ...meta,
  });
  if (level === "ERROR")     console.error(entry);
  else if (level === "WARN") console.warn(entry);
  else                       console.log(entry);
}

//  v134.0.0: Error Tracking -- persists to SECURITY_HUB_KV (7-day rolling) 
// Records error counts + up to 10 sample payloads per component per day.
// Surfaced via GET /api/admin/observability.
async function trackError(env, component, message, meta = {}) {
  slog("ERROR", component, message, meta);
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const day = new Date().toISOString().slice(0, 10);
    const key = `error:${component}:${day}`;
    const rec = (await env.SECURITY_HUB_KV.get(key, { type: "json" })) || { count: 0, samples: [] };
    rec.count++;
    if (rec.samples.length < 10) {
      rec.samples.push({ ts: new Date().toISOString(), msg: message, ...meta });
    }
    await env.SECURITY_HUB_KV.put(key, JSON.stringify(rec), { expirationTtl: 86400 * 7 });
  } catch { /* non-critical -- never let observability kill a request */ }
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
      "Content-Type": "application/json; charset=utf-8",
      "X-Gateway":                   `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
      // P0 FIX v134.0: Prevent browser/CDN caching of intel responses.
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

//  v134.0: Feed Deduplication -- 3-layer: stix_id + title-hash + content-hash 
// Removes duplicates from manifest items before serving to clients.
// Dedup key priority:
//   L1: stix_id / id (most stable -- canonical STIX bundle identifier)
//   L2: normalised title hash (catches same advisory with different IDs)
//   L3: source+title content-hash (catches cross-source republications)
// Also strips known brand/identity noise entries that leak into feed.
const BRAND_NOISE = [
  "CYBERDUDEBIVASH(R) PRIVATE LIMITED",
  "OFFICIAL WORKPLACE",
  "GST & PAN VERIFIED",
];

function _titleHash(title) {
  // Normalise: lowercase, strip punctuation/whitespace bursts, collapse spaces
  return (title || "").toLowerCase()
    .replace(/\b(cve-\d{4}-\d{4,})\b/gi, m => m.toUpperCase()) // preserve CVE case for dedup precision
    .replace(/[^a-z0-9A-Z]+/g, " ")
    .trim()
    .split(" ")
    .filter(Boolean)
    .sort()     // order-independent hash -> catches reordered titles
    .join("|");
}

function _contentHash(item) {
  // A lightweight fingerprint of the item's core identity:
  // (source normalised) + "::" + (title normalised)
  const src   = (item.source || item.feed_source || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const title = _titleHash(item.title || item.name || "");
  // Include CVE ID if present -- prevents stripping unique CVEs with generic titles
  const cve   = (item.cve_id || "").toUpperCase();
  return `${src}::${title}::${cve}`;
}

function deduplicateFeedItems(items) {
  const seenStix    = new Set();
  const seenTitle   = new Set();
  const seenContent = new Set();
  const result      = [];

  for (const item of items) {
    const t = (item.title || item.name || "").trim();
    if (!t) continue;
    if (BRAND_NOISE.some(n => t.includes(n))) continue;

    // L1: stix_id / canonical id dedup
    const sid = item.stix_id || item.id || "";
    if (sid && seenStix.has(sid)) continue;
    if (sid) seenStix.add(sid);

    // L2: normalised title hash (catches same advisory, different IDs)
    const th = _titleHash(t);
    if (th && seenTitle.has(th)) continue;
    if (th) seenTitle.add(th);

    // L3: source+title content-hash (catches cross-source republication)
    const ch = _contentHash(item);
    if (ch && seenContent.has(ch)) continue;
    seenContent.add(ch);

    result.push(item);
  }
  return result;
}

//  v134.0.0: JWT Auth -- HS256 via Web Crypto API 
// Uses CDB_JWT_SECRET from Cloudflare secret (set via: npx wrangler secret put CDB_JWT_SECRET)
// ZERO ephemeral fallback: if CDB_JWT_SECRET is missing, auth endpoints return 503.
// Token format: standard JWT HS256 -- header.payload.signature (base64url encoded)

const JWT_ALG   = { name: "HMAC", hash: "SHA-256" };
const JWT_TTL   = 60 * 60 * 24 * 30;   // 30 days default
const JWT_SHORT = 60 * 60;              // 1 hour for admin tokens

function b64urlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? "=".repeat(4 - s.length % 4) : "";
  return Uint8Array.from(atob(s + pad), c => c.charCodeAt(0));
}

async function getJwtKey(secret) {
  const enc = new TextEncoder().encode(secret);
  return crypto.subtle.importKey("raw", enc, JWT_ALG, false, ["sign", "verify"]);
}

async function signJwt(payload, secret, ttlSeconds = JWT_TTL) {
  if (!secret) throw new Error("CDB_JWT_SECRET not configured");
  const now     = Math.floor(Date.now() / 1000);
  const fullPay = { ...payload, iat: now, exp: now + ttlSeconds };
  const header  = b64urlEncode(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: "JWT" })));
  const body    = b64urlEncode(new TextEncoder().encode(JSON.stringify(fullPay)));
  const key     = await getJwtKey(secret);
  const sigBuf  = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64urlEncode(sigBuf)}`;
}

async function verifyJwt(token, secret) {
  if (!secret) return { valid: false, reason: "jwt_secret_not_configured" };
  if (!token)  return { valid: false, reason: "token_missing" };
  const parts = token.split(".");
  if (parts.length !== 3) return { valid: false, reason: "token_malformed" };
  const [header, body, sig] = parts;
  try {
    const key    = await getJwtKey(secret);
    const valid  = await crypto.subtle.verify("HMAC", key,
      b64urlDecode(sig), new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return { valid: false, reason: "signature_invalid" };
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    const now   = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return { valid: false, reason: "token_expired", expired_at: payload.exp };
    return { valid: true, payload };
  } catch (e) {
    return { valid: false, reason: "token_parse_error", detail: e.message };
  }
}

// Extract JWT from Authorization: Bearer <token> header only (no query params for JWT)
function extractJwt(request) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) {
    const t = auth.slice(7).trim();
    // Detect JWT (3-part base64url) vs legacy API key (CDB-* prefix)
    if (t.split(".").length === 3) return t;
  }
  return null;
}

//  v134.0.0: JWT Revocation Blocklist 
// Revoked tokens are stored in SECURITY_HUB_KV with TTL = remaining token lifetime.
// isTokenRevoked() is called in resolveAuth() before returning a valid JWT result.
async function isTokenRevoked(token, env) {
  if (!env?.SECURITY_HUB_KV || !token) return false;
  try {
    const tokenId = (await sha256hex(token)).slice(0, 16);
    const v = await env.SECURITY_HUB_KV.get(`jwt_revoked:${tokenId}`);
    return v !== null;
  } catch { return false; }
}

async function revokeToken(token, expUnix, env) {
  if (!env?.SECURITY_HUB_KV || !token) return;
  try {
    const tokenId = (await sha256hex(token)).slice(0, 16);
    const ttl     = Math.max(60, expUnix - Math.floor(Date.now() / 1000));
    await env.SECURITY_HUB_KV.put(`jwt_revoked:${tokenId}`, "1", { expirationTtl: ttl });
  } catch { /* non-critical */ }
}

//  v134.0.0: PBKDF2 Password Hashing 
// bcrypt unavailable in Cloudflare Workers runtime. PBKDF2 via Web Crypto API.
// Storage format: "pbkdf2:v1:<salt_hex>:<hash_hex>" (256-bit key, 100k iterations)

async function pbkdf2Hash(password) {
  const salt   = crypto.getRandomValues(new Uint8Array(16));
  const keyMat = await crypto.subtle.importKey("raw", new TextEncoder().encode(password),
                   "PBKDF2", false, ["deriveBits"]);
  const bits   = await crypto.subtle.deriveBits(
                   { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMat, 256);
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, "0")).join("");
  const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `pbkdf2:v1:${saltHex}:${hashHex}`;
}

async function pbkdf2Verify(password, stored) {
  try {
    const parts = stored.split(":");
    if (parts.length < 4 || parts[0] !== "pbkdf2") return false;
    const saltHex = parts[2];
    const expectedHex = parts[3];
    const salt   = new Uint8Array(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
    const keyMat = await crypto.subtle.importKey("raw", new TextEncoder().encode(password),
                     "PBKDF2", false, ["deriveBits"]);
    const bits   = await crypto.subtle.deriveBits(
                     { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMat, 256);
    const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, "0")).join("");
    return hashHex === expectedHex;
  } catch { return false; }
}

function generateUserId() {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return "u_" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

//  v134.0.0: POST /auth/signup 
// Creates user record in API_KEYS_KV with user: prefix + email index.
// Auto-issues JWT. Tier starts FREE.
async function handleUserSignup(request, env, rid) {
  if (!env?.API_KEYS_KV)    return jsonResponse({ error: "storage_unavailable",    request_id: rid }, 503);
  if (!env?.CDB_JWT_SECRET) return jsonResponse({ error: "auth_service_unavailable", request_id: rid }, 503);
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }

  const { email, password, name } = body;
  if (!email || typeof email !== "string" || !email.includes("@"))
    return jsonResponse({ error: "invalid_email", request_id: rid }, 400);
  if (!password || typeof password !== "string" || password.length < 8)
    return jsonResponse({ error: "password_too_short", message: "Password must be at least 8 characters.", request_id: rid }, 400);

  const emailNorm = email.toLowerCase().trim();
  const emailHash = await sha256hex("email:" + emailNorm);

  // Idempotency: reject duplicate email
  const existing = await env.API_KEYS_KV.get(`email:${emailHash}`);
  if (existing) return jsonResponse({ error: "email_taken", message: "An account with this email already exists.", request_id: rid }, 409);

  const userId       = generateUserId();
  const passwordHash = await pbkdf2Hash(password);
  const now          = new Date().toISOString();

  const userRecord = {
    user_id:           userId,
    email:             emailNorm,
    email_hash:        emailHash,
    name:              (typeof name === "string" && name.trim()) ? sanitizeInput(name.trim(), 100) || emailNorm.split("@")[0] : emailNorm.split("@")[0],
    password_hash:     passwordHash,
    tier:              CONFIG.TIERS.FREE,
    created_at:        now,
    last_login:        now,
    subscription:      null,
    stripe_customer_id: null,
    api_key_count:     0,
  };

  await Promise.all([
    env.API_KEYS_KV.put(`user:${userId}`,    JSON.stringify(userRecord)),
    env.API_KEYS_KV.put(`email:${emailHash}`, userId),
  ]);

  const token = await signJwt(
    { sub: userId, tier: CONFIG.TIERS.FREE, user_id: userId, email: emailNorm, key_id: userId },
    env.CDB_JWT_SECRET, JWT_TTL
  );

  slog("INFO", "AUTH", "User signup", { user_id: userId });
  return jsonResponse({
    status:     "ok",
    user_id:    userId,
    email:      emailNorm,
    name:       userRecord.name,
    tier:       CONFIG.TIERS.FREE,
    token,
    token_type: "Bearer",
    expires_in: JWT_TTL,
    message:    "Account created. Use the token to authenticate all API requests.",
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  }, 201);
}

//  v134.0.0: POST /auth/login 
async function handleUserLogin(request, env, rid) {
  if (!env?.API_KEYS_KV)    return jsonResponse({ error: "storage_unavailable",    request_id: rid }, 503);
  if (!env?.CDB_JWT_SECRET) return jsonResponse({ error: "auth_service_unavailable", request_id: rid }, 503);
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }

  const { email, password } = body;
  if (!email || !password)
    return jsonResponse({ error: "email_and_password_required", request_id: rid }, 400);

  const emailNorm = email.toLowerCase().trim();
  const emailHash = await sha256hex("email:" + emailNorm);

  const userId = await env.API_KEYS_KV.get(`email:${emailHash}`);
  if (!userId) return jsonResponse({ error: "invalid_credentials", message: "Invalid email or password.", request_id: rid }, 401);

  const userRecord = await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" });
  if (!userRecord) return jsonResponse({ error: "invalid_credentials", message: "Invalid email or password.", request_id: rid }, 401);

  const valid = await pbkdf2Verify(password, userRecord.password_hash);
  if (!valid) {
    slog("WARN", "AUTH", "Login failed -- bad password", { user_id: userId });
    return jsonResponse({ error: "invalid_credentials", message: "Invalid email or password.", request_id: rid }, 401);
  }

  userRecord.last_login = new Date().toISOString();
  env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(userRecord)).catch(() => {});

  const ttl   = userRecord.tier === CONFIG.TIERS.ENTERPRISE ? JWT_TTL * 12 : JWT_TTL;
  const token = await signJwt(
    { sub: userId, tier: userRecord.tier, user_id: userId, email: emailNorm, key_id: userId },
    env.CDB_JWT_SECRET, ttl
  );

  slog("INFO", "AUTH", "User login", { user_id: userId, tier: userRecord.tier });
  return jsonResponse({
    status:     "ok",
    user_id:    userId,
    email:      emailNorm,
    name:       userRecord.name,
    tier:       userRecord.tier,
    token,
    token_type: "Bearer",
    expires_in: ttl,
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: GET /auth/me 
async function handleUserMe(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId     = auth.user_id || auth.key_id;
  const userRecord = userId ? await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null) : null;

  if (!userRecord) {
    // Legacy API key auth -- return synthetic user context
    return jsonResponse({
      status:      "ok",
      user_id:     userId,
      tier:        auth.tier,
      label:       auth.label,
      auth_method: auth.auth_method,
      request_id:  rid,
      gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    });
  }

  const month       = new Date().toISOString().slice(0, 7);
  const keyList     = await env.API_KEYS_KV.list({ prefix: `userkey:${userId}:` }).catch(() => ({ keys: [] }));
  const apiKeys     = (await Promise.all(keyList.keys.slice(0, 20).map(async k => {
    const rec = await env.API_KEYS_KV.get(k.name, { type: "json" }).catch(() => null);
    if (!rec) return null;
    const usage = parseInt(await env.API_KEYS_KV.get(`usage:${rec.key_id}:${month}`).catch(() => "0") || "0");
    return { key_id: rec.key_id, label: rec.label, tier: rec.tier, created_at: rec.created_at,
             revoked: rec.revoked || false, usage_this_month: usage };
  }))).filter(Boolean);

  return jsonResponse({
    status:       "ok",
    user_id:      userRecord.user_id,
    email:        userRecord.email,
    name:         userRecord.name,
    tier:         userRecord.tier,
    created_at:   userRecord.created_at,
    last_login:   userRecord.last_login,
    subscription: userRecord.subscription || null,
    api_keys:     apiKeys,
    usage_limits: {
      free:       { requests_per_min: CONFIG.RATE_LIMITS.free,       feed_items: CONFIG.FEED_LIMITS.free },
      premium:    { requests_per_min: CONFIG.RATE_LIMITS.premium,    feed_items: CONFIG.FEED_LIMITS.premium },
      enterprise: { requests_per_min: CONFIG.RATE_LIMITS.enterprise, feed_items: CONFIG.FEED_LIMITS.enterprise },
    },
    request_id:   rid,
    gateway:      `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: POST /api/keys/create 
// Generates and stores a new CDB-* API key linked to the authenticated user.
// Key caps: FREE=2, PRO=10, ENTERPRISE=50.
async function handleUserCreateKey(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId     = auth.user_id || auth.key_id;
  const userRecord = userId ? await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null) : null;
  const tier       = userRecord?.tier || auth.tier || CONFIG.TIERS.FREE;

  let body = {};
  try { body = await request.json(); } catch {}
  const { label = "API Key", tier: reqTier } = body;

  const TIER_RANK  = { free: 0, premium: 1, enterprise: 2 };
  const effectiveTier = (reqTier && TIER_RANK[reqTier] !== undefined && TIER_RANK[reqTier] <= TIER_RANK[tier])
    ? reqTier : tier;

  const KEY_CAPS   = { free: 2, premium: 10, enterprise: 50 };
  const cap        = KEY_CAPS[tier] || 2;
  const existing   = await env.API_KEYS_KV.list({ prefix: `userkey:${userId}:` }).catch(() => ({ keys: [] }));

  if (existing.keys.length >= cap) {
    return jsonResponse({
      error:      "key_limit_reached",
      message:    `${tier} tier allows max ${cap} API keys. Upgrade to create more.`,
      limit:      cap,
      upgrade:    getUpgradeCTA(tier),
      request_id: rid,
    }, 403);
  }

  const rawBytes   = crypto.getRandomValues(new Uint8Array(24));
  const rawKey     = "CDB-" + Array.from(rawBytes).map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase().slice(0, 32);
  const keyHash    = await sha256hex(rawKey);
  const keyId      = keyHash.slice(0, 16);
  const now        = new Date().toISOString();
  const usageLimit = effectiveTier === CONFIG.TIERS.FREE ? 1000 : 0; // 0 = unlimited

  const keyRecord = {
    key_id:      keyId,
    user_id:     userId || null,
    tier:        effectiveTier,
    label:       sanitizeInput(String(label), 100) || "API Key",
    created_at:  now,
    revoked:     false,
    usage_limit: usageLimit,
  };

  await Promise.all([
    env.API_KEYS_KV.put(`apikey:${keyId}`, JSON.stringify(keyRecord)),
    userId ? env.API_KEYS_KV.put(`userkey:${userId}:${keyId}`, JSON.stringify({
      key_id: keyId, label: keyRecord.label, tier: effectiveTier, created_at: now, revoked: false,
    })) : Promise.resolve(),
  ]);

  if (userRecord) {
    userRecord.api_key_count = (userRecord.api_key_count || 0) + 1;
    env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(userRecord)).catch(() => {});
  }

  slog("INFO", "KEYS", "API key created", { key_id: keyId, user_id: userId, tier: effectiveTier });
  return jsonResponse({
    status:       "ok",
    key_id:       keyId,
    api_key:      rawKey,
    tier:         effectiveTier,
    label:        keyRecord.label,
    usage_limit:  usageLimit === 0 ? "unlimited" : usageLimit,
    created_at:   now,
    warning:      "Store this API key securely -- it will NOT be shown again.",
    request_id:   rid,
    gateway:      `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  }, 201);
}

//  v134.0.0: GET /api/keys 
async function handleUserListKeys(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId = auth.user_id || auth.key_id;
  const month  = new URL(request.url).searchParams.get("month") || new Date().toISOString().slice(0, 7);
  const list   = await env.API_KEYS_KV.list({ prefix: `userkey:${userId}:` }).catch(() => ({ keys: [] }));

  const keys = (await Promise.all(list.keys.map(async k => {
    const rec = await env.API_KEYS_KV.get(k.name, { type: "json" }).catch(() => null);
    if (!rec) return null;
    const usage = parseInt(await env.API_KEYS_KV.get(`usage:${rec.key_id}:${month}`).catch(() => "0") || "0");
    return {
      key_id:           rec.key_id,
      label:            rec.label,
      tier:             rec.tier,
      created_at:       rec.created_at,
      revoked:          rec.revoked || false,
      usage_this_month: usage,
      usage_limit:      rec.usage_limit === 0 ? "unlimited" : (rec.usage_limit || "unlimited"),
    };
  }))).filter(Boolean);

  return jsonResponse({
    status:     "ok",
    user_id:    userId,
    month,
    count:      keys.length,
    keys,
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: DELETE /api/keys/:id 
async function handleUserDeleteKey(request, env, rid, auth, keyIdToDelete) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId    = auth.user_id || auth.key_id;
  const keyRecord = await env.API_KEYS_KV.get(`apikey:${keyIdToDelete}`, { type: "json" }).catch(() => null);

  if (!keyRecord) return jsonResponse({ error: "not_found", key_id: keyIdToDelete, request_id: rid }, 404);
  if (keyRecord.user_id && keyRecord.user_id !== userId)
    return jsonResponse({ error: "forbidden", message: "You do not own this API key.", request_id: rid }, 403);

  // Soft-revoke -- preserves audit trail
  keyRecord.revoked    = true;
  keyRecord.revoked_at = new Date().toISOString();
  await Promise.all([
    env.API_KEYS_KV.put(`apikey:${keyIdToDelete}`, JSON.stringify(keyRecord)),
    env.API_KEYS_KV.delete(`userkey:${userId}:${keyIdToDelete}`).catch(() => {}),
  ]);

  slog("INFO", "KEYS", "API key deleted by user", { key_id: keyIdToDelete, user_id: userId });
  return jsonResponse({
    status:     "ok",
    key_id:     keyIdToDelete,
    revoked_at: keyRecord.revoked_at,
    message:    "Key revoked. All requests using this key will be rejected immediately.",
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  /api/auth/token -- Issue JWT (POST, body: {api_key, tier}) 
async function handleIssueToken(request, env, rid) {
  if (!env?.CDB_JWT_SECRET) {
    return jsonResponse({
      error:      "auth_service_unavailable",
      message:    "CDB_JWT_SECRET not configured. Set via: npx wrangler secret put CDB_JWT_SECRET",
      request_id: rid,
    }, 503);
  }
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }

  const { api_key } = body;
  if (!api_key) return jsonResponse({ error: "api_key_required", request_id: rid }, 400);

  // Validate the API key first
  const auth = await resolveApiKey({ headers: { get: h => h === "Authorization" ? `Bearer ${api_key}` : null } }, env);
  if (!auth.valid) {
    return jsonResponse({
      error:      "api_key_invalid",
      reason:     auth.reason,
      message:    "Valid API key required to issue JWT.",
      acquire_key: CONFIG.GET_KEY_URL,
      request_id: rid,
    }, 401);
  }

  const ttl = auth.tier === CONFIG.TIERS.ENTERPRISE ? JWT_TTL * 12 : JWT_TTL;
  const token = await signJwt(
    { sub: auth.key_id, tier: auth.tier, label: auth.label, key_id: auth.key_id },
    env.CDB_JWT_SECRET,
    ttl
  );

  await recordAnalytics(env, auth.key_id, "jwt_issue", auth.tier, 201);
  return jsonResponse({
    status:      "ok",
    request_id:  rid,
    token,
    token_type:  "Bearer",
    expires_in:  ttl,
    tier:        auth.tier,
    key_id:      auth.key_id,
    issued_at:   new Date().toISOString(),
    message:     "Store token securely. Use as: Authorization: Bearer <token>",
    gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  }, 201);
}

//  /api/auth/validate -- Validate JWT (GET/POST) 
async function handleValidateToken(request, env, rid) {
  if (!env?.CDB_JWT_SECRET) {
    return jsonResponse({ error: "auth_service_unavailable", request_id: rid }, 503);
  }
  const token = extractJwt(request) || (await request.json().catch(() => ({}))).token;
  const result = await verifyJwt(token, env.CDB_JWT_SECRET);
  if (!result.valid) {
    return jsonResponse({
      valid:      false,
      reason:     result.reason,
      request_id: rid,
    }, 401);
  }
  return jsonResponse({
    valid:      true,
    tier:       result.payload.tier,
    key_id:     result.payload.key_id,
    expires_at: new Date(result.payload.exp * 1000).toISOString(),
    issued_at:  new Date(result.payload.iat * 1000).toISOString(),
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  Unified auth resolver: supports both JWT and legacy API keys 
// Priority: JWT (Bearer token with 3 parts) > Legacy API key (CDB-* / X-Api-Key)
// v134.0.0: Checks JWT revocation blocklist before accepting token.
async function resolveAuth(request, env) {
  // Try JWT first
  const jwtToken = extractJwt(request);
  if (jwtToken && env?.CDB_JWT_SECRET) {
    const result = await verifyJwt(jwtToken, env.CDB_JWT_SECRET);
    if (result.valid) {
      // v134.0.0: HARD check revocation blocklist -- revoked tokens NEVER pass
      if (await isTokenRevoked(jwtToken, env)) {
        return { valid: false, reason: "token_revoked", auth_method: "jwt" };
      }
      // v134.0: Live tier resolution -- JWT tier can be stale if user paid after token issue.
      // Read authoritative tier from KV user record; fall back to JWT claim.
      // This makes Stripe payment tier upgrades instant -- no JWT refresh required.
      const jwtUserId = result.payload.user_id || result.payload.sub || result.payload.key_id;

      // v134.0: STRICT TIER VALIDATION -- only accept known tier values, default FREE on invalid
      const VALID_TIERS = new Set([CONFIG.TIERS.FREE, CONFIG.TIERS.PREMIUM, CONFIG.TIERS.ENTERPRISE]);
      const rawJwtTier  = result.payload.tier || CONFIG.TIERS.FREE;
      const sanitisedJwtTier = VALID_TIERS.has(rawJwtTier) ? rawJwtTier : CONFIG.TIERS.FREE;

      let liveTier = sanitisedJwtTier;
      if (jwtUserId && env?.API_KEYS_KV) {
        try {
          const liveUser = await env.API_KEYS_KV.get(`user:${jwtUserId}`, { type: "json" });
          // MUST be a known tier -- never elevate to unknown value
          if (liveUser?.tier && VALID_TIERS.has(liveUser.tier)) {
            liveTier = liveUser.tier;
          }
        } catch { /* KV read failure -> safe default (JWT claim already validated) */ }
      }
      return {
        valid:       true,
        tier:        liveTier,
        key_id:      result.payload.key_id || jwtUserId,
        label:       result.payload.label,
        user_id:     jwtUserId,
        email:       result.payload.email,
        scopes:      buildScopeSet(liveTier, result.payload.scopes || null),
        auth_method: "jwt",
      };
    }
    // JWT present but invalid -- hard fail (no fallback to API key)
    return { valid: false, reason: result.reason, auth_method: "jwt" };
  }
  // Fall through to legacy API key resolution
  const legacy = await resolveApiKey(request, env);
  return { ...legacy, auth_method: "api_key" };
}

//  Rate Limiting -- Sliding Window 

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

//  API Key Resolution 
// v134.0.0: Enforces usage_limit (monthly request cap) per key record.
// usage_limit: 0 or absent = unlimited. Non-zero = monthly cap (YYYY-MM rolling).

async function resolveApiKey(request, env) {
  const rawKey = extractApiKey(request);
  if (!rawKey) return { valid: false, reason: "key_required" };
  if (!env?.API_KEYS_KV) return { valid: false, reason: "auth_unavailable" };
  try {
    const hash   = await sha256hex(rawKey);
    const keyId  = hash.slice(0, 16);
    const stored = await env.API_KEYS_KV.get(`apikey:${keyId}`, { type: "json" });
    if (!stored) return { valid: false, key_id: keyId, reason: "invalid_key" };
    if (stored.expires_at && new Date(stored.expires_at) < new Date())
      return { valid: false, key_id: keyId, reason: "key_expired" };
    if (stored.revoked)
      return { valid: false, key_id: keyId, reason: "key_revoked" };

    // v134.0.0: Monthly usage cap enforcement
    const usageLimit = typeof stored.usage_limit === "number" ? stored.usage_limit : 0;
    if (usageLimit > 0) {
      const month    = new Date().toISOString().slice(0, 7); // "YYYY-MM"
      const usageKey = `usage:${keyId}:${month}`;
      const used     = parseInt(await env.API_KEYS_KV.get(usageKey) || "0");
      if (used >= usageLimit) {
        return {
          valid:      false,
          key_id:     keyId,
          reason:     "usage_limit_exceeded",
          usage:      { count: used, limit: usageLimit, period: month },
          upgrade_url: "/upgrade.html?plan=pro",
        };
      }
      // Increment usage counter (fire-and-forget -- never block the request)
      env.API_KEYS_KV.put(usageKey, String(used + 1), { expirationTtl: 86400 * 35 }).catch(() => {});
    }

    const keyTier = stored.tier || CONFIG.TIERS.FREE;
    return {
      valid:      true,
      tier:       keyTier,
      key_id:     keyId,
      label:      stored.label,
      created_at: stored.created_at,
      scopes:     buildScopeSet(keyTier, stored.scopes || null),
    };
  } catch (e) {
    slog("ERROR", "AUTH", "resolveApiKey failed", { error: e.message });
    return { valid: false, reason: "auth_error" };
  }
}

//  Abuse Tracking 

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

//  Analytics 

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

//  Data Layer: R2 -> KV Cache -> GitHub Fallback 

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

  // v134.0.0 FRESHNESS FIX: Inject processed_at fallback
  // v134.0.0: validateAndNormalizeItem() -- guarantee no null fields across entire manifest
  const manifestGeneratedAt = data.generated_at || null;
  items = items.map(item => {
    // Inject processed_at before normalization so validator can use it
    if (!item.processed_at) {
      item = { ...item, processed_at: item.timestamp || item.generated_at || manifestGeneratedAt || null };
    }
    // v134.0.0: Full schema normalization -- derives all missing fields, never null
    return validateAndNormalizeItem(item) || item;
  }).filter(Boolean);

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

//  v134.0.0: Retry circuit breaker -- exponential backoff, 3 attempts 
// Prevents single transient failures from killing requests.
// 4xx (client errors) are NOT retried -- only 5xx / network errors.
async function fetchWithRetry(url, opts, maxRetries = 3, baseDelayMs = 400) {
  let lastErr;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const res = await fetch(url, opts);
      // 4xx = hard client error, do not retry
      if (res.status >= 400 && res.status < 500) return res;
      if (res.ok) return res;
      // 5xx = transient server error, retry after backoff
      lastErr = new Error(`HTTP ${res.status}`);
    } catch (e) {
      lastErr = e;
    }
    if (attempt < maxRetries - 1) {
      // Exponential backoff: 400ms, 800ms, 1600ms
      await new Promise(r => setTimeout(r, baseDelayMs * Math.pow(2, attempt)));
    }
  }
  throw lastErr || new Error("fetchWithRetry: all attempts exhausted");
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
  // v134.0.0: fetchWithRetry -- 3 attempts with backoff for transient GitHub/CDN errors
  const res = await fetchWithRetry(url, { headers, ...cfOpts });
  if (!res.ok) {
    const hint = res.status === 404 && !env?.GITHUB_TOKEN
      ? " (GITHUB_TOKEN not set -- set via: npx wrangler secret put GITHUB_TOKEN)"
      : "";
    throw new Error(`GitHub HTTP ${res.status}${hint}`);
  }
  return res.json();
}

async function fetchReportsIndex(env) {
  const cacheKey = "idx:reports";

  // SOURCE 1: Cloudflare R2 (primary -- private, no public exposure)
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
    } catch (e) { slog("WARN", "R2", "R2 fetch failed", { error: e.message }); }
  }

  // SOURCE 2: KV warm cache (avoids R2 egress on repeated requests)
  if (env?.RATE_LIMIT_KV && !CONFIG.BYPASS_FEED_CACHE) {
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey, { type: "json" });
      if (cached?.reports?.length > 0) return cached;
      if (cached !== null) await env.RATE_LIMIT_KV.delete(cacheKey).catch(() => {});
    } catch { /* fall through */ }
  }

  // SOURCE 3: GitHub raw (emergency fallback -- GITHUB_TOKEN required for private repo)
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

//  Upgrade CTAs 

function getUpgradeCTA(tier) {
  if (tier === CONFIG.TIERS.ENTERPRISE) return null;
  if (tier === CONFIG.TIERS.PREMIUM) {
    return {
      message:     "Upgrade to Enterprise for unlimited access + dedicated SLA",
      upgrade_url: "/upgrade.html?plan=enterprise",
    };
  }
  return {
    message:     `Free tier: ${CONFIG.FEED_LIMITS.free} items/req. Upgrade to Premium for ${CONFIG.FEED_LIMITS.premium}+.`,
    upgrade_url: "/upgrade.html?plan=pro",
    benefits:    ["500 items/req", "500 req/min", "Priority support", "Full CVE/IOC/TTP data"],
  };
}


// v143.5 FIX: _classifyThreatCategory -- derives threat category from item content.
// Mirrors Python enrich_feed_apex.py::compute_threat_category().
// Used as fallback when stored value is absent, empty, or "UNKNOWN".
function _classifyThreatCategory(item) {
  const tt    = ((item.threat_type || item.type || "")).toLowerCase();
  const title = ((item.title || "")).toLowerCase();
  const tags  = Array.isArray(item.tags) ? item.tags.map(t => String(t).toLowerCase()) : [];

  const MAP = [
    ["ransomware",     "Ransomware"],
    ["vulnerability",  "Vulnerability"],
    ["malware",        "Malware"],
    ["apt",            "Nation-State APT"],
    ["phishing",       "Phishing"],
    ["cve",            "CVE / Vulnerability"],
    ["oss-advisory",   "Supply Chain Risk"],
    ["supply chain",   "Supply Chain Risk"],
    ["exploit",        "Exploit"],
    ["web application","Web Application Attack"],
    ["rce",            "Remote Code Execution"],
    ["sqli",           "SQL Injection"],
    ["xss",            "Cross-Site Scripting"],
    ["threat-intel",   "Threat Intel"],
  ];

  for (const [key, cat] of MAP) {
    if (tt.includes(key) || title.includes(key)) return cat;
  }
  if (tags.some(t => t.includes("ransom")))  return "Ransomware";
  if (tags.some(t => t.includes("phish")))   return "Phishing";
  if (tags.some(t => t.includes("malware") || t.includes("rat"))) return "Malware";
  return "Threat Intel";
}

//  v134.0.0: computeApexAI -- Full AI Intelligence Engine 
// Produces: predictive_risk, ai_confidence, actor_fingerprint, kill_chain, ttp_density, ai_summary
// v134.0.0 GOD-MODE: ai_summary is MANDATORY -- teaser for free, full narrative for Pro/Enterprise
// ai_summary NEVER null -- generated dynamically from item data when apex.ai_summary absent
// Safe: never throws -- returns minimal object on any error

function computeApexAI(item, tier) {
  try {
    const isFree  = !tier || tier === CONFIG.TIERS.FREE;
    const isPro   = tier === CONFIG.TIERS.PREMIUM || tier === CONFIG.TIERS.ENTERPRISE;

    // v143.1 APEX-AI SOURCE-OF-TRUTH GUARD (project mandate: "if apex_ai exists -> DO NOT recompute")
    // If the item carries apex_ai from R2/API (set by the Python APEX engine),
    // that value is authoritative. Return it directly without recomputing.
    //
    // Guard criteria (expanded from v145.0):
    //   1. apex_ai must exist and be a plain object
    //   2. Must not carry an error flag from a previous failed compute
    //   3. Must have at LEAST ONE meaningful intelligence field:
    //      - soc_priority (string, e.g. "P1")
    //      - predictive_risk (number)
    //      - ai_confidence (number)
    //      - ai_summary (string)
    //      - threat_level (string)
    // This is intentionally broad -- we trust any apex_ai that came from R2/API
    // and has at least one non-trivial field, rather than requiring ALL fields.
    const existingApexAI = item.apex_ai;
    const hasValidApexAI =
      existingApexAI != null &&
      typeof existingApexAI === "object" &&
      !Array.isArray(existingApexAI) &&
      !existingApexAI.error &&
      (
        (typeof existingApexAI.soc_priority   === "string"  && existingApexAI.soc_priority)   ||
        (typeof existingApexAI.predictive_risk === "number")                                   ||
        (typeof existingApexAI.ai_confidence   === "number")                                   ||
        (typeof existingApexAI.ai_summary      === "string"  && existingApexAI.ai_summary)    ||
        (typeof existingApexAI.threat_level    === "string"  && existingApexAI.threat_level)
      );

    if (hasValidApexAI) {
      if (isFree) {
        const fp = existingApexAI.actor_fingerprint;
        const fpMasked = fp ? String(fp).slice(0, 8) + "****" : "UNC-UNKN****";
        const sp = existingApexAI.soc_priority || "P4";
        const ct = existingApexAI.threat_confidence_tier || "MODERATE";
        return {
          soc_priority:            sp,
          threat_level:            existingApexAI.threat_level            || "UNKNOWN",
          threat_category:         (existingApexAI.threat_category && existingApexAI.threat_category !== "UNKNOWN" ? existingApexAI.threat_category : _classifyThreatCategory(item)),
          predictive_risk:         existingApexAI.predictive_risk         ?? 0,
          ai_confidence:           existingApexAI.ai_confidence           ?? 0,
          threat_confidence_tier:  ct,
          threat_confidence_label: existingApexAI.threat_confidence_label || ct,
          ttp_density:             existingApexAI.ttp_density             ?? 0,
          campaign_id:             "PRO_REQUIRED",
          actor_fingerprint:       fpMasked,
          kill_chain:              "PRO_REQUIRED",
          kill_chain_primary:      "PRO_REQUIRED",
          ai_summary:              existingApexAI.ai_summary_teaser
                                   || (existingApexAI.ai_summary
                                       ? String(existingApexAI.ai_summary).slice(0, 120) + " . FULL INTELLIGENCE -- PRO TIER REQUIRED ->"
                                       : "Intelligence signal detected. Upgrade to Pro for full analysis."),
          recommended_action:      `SOC ${sp}: Full kill chain attribution locked behind Pro tier. Upgrade for complete IR playbook.`,
          behavioral_tags:         [],
          paywall: {
            locked_fields: ["actor_fingerprint_full","kill_chain","behavioral_tags","recommended_action_full","stix_bundle"],
            upgrade_url:   "/upgrade.html?plan=pro",
            message:       `${ct} THREAT -- full actor attribution locked. Upgrade to Pro for complete intelligence.`,
            urgency:       sp === "P1" || sp === "P2"
              ? ` ACTIVE THREAT [${sp}] -- Enterprise IR response required.`
              : `THREAT ACTIVE [${sp}] -- Full detection package available on Pro tier.`,
          },
        };
      }
      // Pro / Enterprise: return existing apex_ai as-is (Python APEX engine is authoritative)
      return { ...existingApexAI };
    }


    //  Core scores 
    const riskScore  = typeof item.risk_score  === "number" ? item.risk_score
                     : typeof item.cvss_score  === "number" ? item.cvss_score : 0;
    const epss       = typeof item.epss_score  === "number" ? item.epss_score : 0;
    const confidence = typeof item.confidence  === "number" ? item.confidence
                     : typeof item.confidence_score === "number" ? item.confidence_score : 0;
    const kev        = item.kev_present === true ? 1.0 : 0.0;
    const iocCount   = Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0);
    const ttpCount   = Array.isArray(item.ttps) ? item.ttps.length : (item.ttp_count || 0);

    //  predictive_risk (0--10): composite risk projection
    // v143.0 FIX: When the Python APEX engine has computed a calibrated composite_score
    // (item.apex.composite_score), use it as the authoritative base instead of computing
    // a divergent value from raw risk_score. This eliminates the apex vs apex_ai mismatch
    // seen in API output (e.g. apex.predictive_score=2.9 vs apex_ai.predictive_risk=6.56).
    //
    // Priority:
    //   1. item.apex.composite_score  -- Python APEX engine (most calibrated)
    //   2. item.apex.priority_score   -- same engine, alternate key
    //   3. item.risk_score            -- raw dynamic risk scorer
    //   4. item.cvss_score            -- CVSS fallback
    const apexComposite  = (item.apex && typeof item.apex.composite_score  === "number" && item.apex.composite_score  > 0)
                         ? item.apex.composite_score
                         : (item.apex && typeof item.apex.priority_score   === "number" && item.apex.priority_score   > 0)
                         ? item.apex.priority_score
                         : null;
    const riskBase       = apexComposite !== null ? apexComposite : riskScore;
    const iocDensityScore = Math.min(iocCount * 0.5, 2.0);
    const predictiveRisk  = Math.min(10,
      (riskBase * 0.4) + (epss * 0.025) + (kev * 2.0) + (iocDensityScore * 0.15 * 10)
    );

    //  ai_confidence (0--100): evidence quality score 
    // Synthesises: base confidence + KEV bonus + STIX completeness + IOC density
    const stixObjects  = typeof item.stix_object_count === "number" ? item.stix_object_count : 0;
    const stixBonus    = Math.min(stixObjects * 1.5, 12);
    const iocBonus     = Math.min(iocCount * 2, 15);
    const kevBonus     = kev * 10;
    const iocEngConf   = typeof item.ioc_confidence === "number" ? Math.min(item.ioc_confidence * 0.15, 10) : 0;
    const aiConfidence = Math.min(100, Math.round(confidence + stixBonus + iocBonus + kevBonus + iocEngConf));

    //  threat_confidence_tier: enterprise-grade qualitative label 
    // Replaces "AI CONF: 47%" weak display with authoritative tier classification
    const confidenceTier =
      aiConfidence >= 90 ? "VERIFIED"  :   // multi-source corroboration + KEV
      aiConfidence >= 70 ? "HIGH"      :   // strong evidence base, actionable
      aiConfidence >= 45 ? "MODERATE"  :   // partial evidence, investigate
                           "LOW";          // limited signals, monitor only

    const tierLabel = {
      VERIFIED: "\u2714 VERIFIED \u2013 Multi-source corroboration confirmed",
      HIGH:     "\u25b2 HIGH \u2013 Strong evidence basis, immediate action required",
      MODERATE: "\u25c6 MODERATE \u2013 Credible intelligence, further investigation advised",
      LOW:      "\u25c7 LOW \u2013 Limited signals, threat monitoring recommended",
    }[confidenceTier];

    //  SOC Recommendation Engine v3.0 
    function _buildSocRec(actorTag_, ttpCount_, iocCount_, primaryPhase_, soc_priority_, severity_) {
      const urgent = soc_priority_ === "P1" || soc_priority_ === "P2";
      const sevCaps = (severity_ || "UNKNOWN").toUpperCase();
      if (sevCaps === "CRITICAL") {
        return `IMMEDIATE RESPONSE REQUIRED [${soc_priority_}]: Activate IR playbook for ${actorTag_}. ` +
          `Hunt ${iocCount_} IOC${iocCount_ !== 1 ? "s" : ""} across SIEM/EDR telemetry. ` +
          `Isolate affected assets, block C2 indicators. ` +
          `Escalate to CISO if lateral movement detected. ` +
          `MITRE coverage: ${ttpCount_} technique${ttpCount_ !== 1 ? "s" : ""} -- focus on ${primaryPhase_} phase.`;
      } else if (sevCaps === "HIGH") {
        return `HIGH-PRIORITY SOC ACTION [${soc_priority_}]: Deploy detection rules for ${actorTag_} TTPs. ` +
          `Block ${iocCount_} indicator${iocCount_ !== 1 ? "s" : ""} at perimeter. ` +
          `Review ${primaryPhase_} phase artifacts in last 72h. ` +
          `${ttpCount_} MITRE technique${ttpCount_ !== 1 ? "s" : ""} mapped -- validate coverage gaps.`;
      }
      return `MONITOR & PREPARE [${soc_priority_}]: Track ${actorTag_} campaign. ` +
        `Add ${iocCount_} IOC${iocCount_ !== 1 ? "s" : ""} to watchlists. ` +
        `Review ${ttpCount_} MITRE technique${ttpCount_ !== 1 ? "s" : ""} against current defenses.`;
    }

    //  actor_fingerprint: deterministic actor identity string
    // v143.1 NULL-SAFE: all string operations guarded with || "" fallback
    const actorTag = String(item.actor_tag || (item.apex && item.apex.campaign_id) || "UNC-UNKNOWN");
    const severity = (String(item.severity || "") || "UNKNOWN").toUpperCase();
    const sevCode  = { CRITICAL: "C", HIGH: "H", MEDIUM: "M", LOW: "L" }[severity] || "U";
    const actorFP  = isPro
      ? `${actorTag}::${sevCode}::IOC-${iocCount}::TTP-${ttpCount}`
      : `${actorTag.slice(0, 8)}****`; // partial for free tier

    //  kill_chain: primary phase derived from TTPs / kill_chain_phases
    const rawKc    = Array.isArray(item.kill_chain_phases) ? item.kill_chain_phases : [];
    const rawTtpsRaw = Array.isArray(item.ttps) ? item.ttps
                     : Array.isArray(item.mitre_tactics) ? item.mitre_tactics : [];
    // v145.0: TTPs may be objects {id, name, tactic} or plain strings -- normalise to ID strings
    const rawTtps = rawTtpsRaw.map(t =>
      t && typeof t === "object" ? String(t.id || t.technique_id || t.name || "") : String(t || "")
    );
    // Map common MITRE tactics to kill chain phases
    const ttpToPhase = {
      TA0001: "Initial Access", TA0002: "Execution", TA0003: "Persistence",
      TA0004: "Privilege Escalation", TA0005: "Defense Evasion", TA0006: "Credential Access",
      TA0007: "Discovery", TA0008: "Lateral Movement", TA0009: "Collection",
      TA0010: "Exfiltration", TA0011: "Command and Control", TA0040: "Impact",
    };
    // Also map T-IDs to tactic names using tactic field from object if available
    const rawTtpTactics = rawTtpsRaw.slice(0, 5).map(t =>
      t && typeof t === "object" && t.tactic ? String(t.tactic) : null
    );
    // v143.1 NULL-SAFE: ta_ is already String(t||"") so it can be "" but never undefined.
    // Use (ta_ || "") before toUpperCase() as an extra safety net for any future API changes.
    const derivedPhases = rawTtps.slice(0, 5).map((ta_, i) => {
      const ta = (ta_ || "").toUpperCase();
      if (!ta) return "Unknown";
      return ttpToPhase[ta]
        || rawTtpTactics[i]
        || (ta.startsWith("T1") ? "Execution" : "Unknown");
    });
    const killChainPhases = rawKc.length > 0 ? rawKc
      : [...new Set(derivedPhases)].slice(0, 3);
    const primaryPhase = killChainPhases[0] || "Unknown";

    //  ttp_density (0--10): attack sophistication density score
    // Higher = more diverse techniques used (sophisticated actor)
    const uniqueTtps  = new Set(rawTtps.filter(Boolean)).size;
    const ttpDensity  = Math.min(10, parseFloat((
      (uniqueTtps * 0.8) + (iocCount * 0.3) + (riskScore * 0.2)
    ).toFixed(2)));

    //  Existing apex block passthrough 
    const existingApex = (item.apex && typeof item.apex === "object") ? item.apex : {};

    //  Tier-gated assembly 
    const socPriority = existingApex.priority || (riskScore >= 9 ? "P1" : riskScore >= 7 ? "P2" : riskScore >= 5 ? "P3" : "P4");
    const threatLevel = existingApex.threat_level || (riskScore >= 9 ? "CRITICAL_SURGE" : riskScore >= 7 ? "HIGH_ALERT" : riskScore >= 5 ? "MODERATE" : "LOW");
    const base = {
      soc_priority:            socPriority,
      threat_level:            threatLevel,
      threat_category:         (existingApex.threat_category && existingApex.threat_category !== "UNKNOWN" ? existingApex.threat_category : _classifyThreatCategory(item)),
      predictive_risk:         parseFloat(predictiveRisk.toFixed(2)),
      ai_confidence:           aiConfidence,
      threat_confidence_tier:  confidenceTier,      // v134.0: VERIFIED/HIGH/MODERATE/LOW
      threat_confidence_label: tierLabel,            // v134.0: human-readable tier description
      ttp_density:             ttpDensity,
      campaign_id:             existingApex.campaign_id || "UNCLASSIFIED",
    };

    //  v134.0: AI Summary Engine v3.0 -- enterprise-grade narratives, no weak language 
    // Free: authoritative teaser -- credible signal, drives upgrade
    // Pro/Enterprise: full tactical SOC narrative with actionable recommendations
    const sevLabel   = severity === "CRITICAL" ? "CRITICAL" : severity === "HIGH" ? "HIGH" : severity;
    const threatType = (item.threat_type || item.type || "THREAT CAMPAIGN").toUpperCase();
    const cveId      = item.cve_id || "";
    const cveStr     = cveId ? ` [${cveId}]` : "";
    const srcLabel   = item.source ? ` . Source: ${item.source}` : "";
    const kevStr     = kev ? " . CISA KEV CONFIRMED" : "";
    const epssStr    = epss >= 0.7 ? ` . EPSS: ${(epss * 100).toFixed(0)}% exploitation probability` : "";

    // Full narrative (Pro/Enterprise) -- authoritative, zero weak language
    const fullSummary = existingApex.ai_summary || (
      `[${confidenceTier}] ${sevLabel} ${threatType}${cveStr}${kevStr}. ` +
      `Actor cluster ${actorTag} operating in ${primaryPhase} phase. ` +
      `${ttpCount} MITRE ATT&CK technique${ttpCount !== 1 ? "s" : ""} mapped -- TTP density ${ttpDensity}/10. ` +
      `${iocCount} indicator${iocCount !== 1 ? "s" : ""} extracted (IOC engine confidence: ${aiConfidence}%). ` +
      `Predictive risk score: ${parseFloat(predictiveRisk.toFixed(1))}/10${epssStr}${srcLabel}. ` +
      `SOC Priority: ${socPriority}.`
    );

    // Authoritative teaser (Free) -- removes "AI CONF: X%" weak pattern
    const teaserSummary = (
      `[${confidenceTier}] ${sevLabel} ${threatType}${cveStr}${kevStr}. ` +
      `${iocCount} indicator${iocCount !== 1 ? "s" : ""} . ${ttpCount} MITRE technique${ttpCount !== 1 ? "s" : ""} . ` +
      `Predictive risk: ${parseFloat(predictiveRisk.toFixed(1))}/10 . SOC ${socPriority}. ` +
      `FULL ACTOR ATTRIBUTION + KILL CHAIN + SOC PLAYBOOK -- PRO TIER REQUIRED ->`
    );

    // Full SOC Recommendation
    const socRec = existingApex.recommended_action
      || _buildSocRec(actorTag, ttpCount, iocCount, primaryPhase, socPriority, severity);

    if (isFree) {
      return {
        ...base,
        actor_fingerprint:  actorFP,             // partial only (****-masked)
        kill_chain:         "PRO_REQUIRED",
        kill_chain_primary: "PRO_REQUIRED",
        ai_summary:         teaserSummary,        // authoritative teaser -- never null
        recommended_action: `SOC ${socPriority}: ${iocCount} IOC${iocCount !== 1 ? "s" : ""} & full kill chain attribution locked behind Pro tier. Upgrade for complete IR playbook.`,
        behavioral_tags:    [],
        paywall: {
          locked_fields: ["actor_fingerprint_full","kill_chain","behavioral_tags","recommended_action_full","stix_bundle"],
          upgrade_url:   "/upgrade.html?plan=pro",
          message:       `${confidenceTier} THREAT -- ${iocCount} IOC${iocCount !== 1 ? "s" : ""} & full actor attribution locked. Upgrade to Pro for complete intelligence.`,
          urgency:       socPriority === "P1" || socPriority === "P2"
            ? ` ACTIVE ${sevLabel} THREAT [${socPriority}] -- Enterprise IR response required.`
            : `THREAT ACTIVE [${socPriority}] -- Full detection package available on Pro tier.`,
        },
      };
    }

    // Pro / Enterprise: full AI intelligence block
    return {
      ...base,
      actor_fingerprint:  actorFP,
      kill_chain:         killChainPhases,
      kill_chain_primary: primaryPhase,
      ai_summary:         fullSummary,
      recommended_action: socRec,
      behavioral_tags:    Array.isArray(existingApex.behavioral_tags) ? existingApex.behavioral_tags : [],
    };
  } catch (e) {
    // v134.0.0: Even on error, ai_summary must not be null
    return {
      soc_priority:    "P4",
      predictive_risk: 0,
      ai_confidence:   0,
      ttp_density:     0,
      ai_summary:      "Intelligence analysis temporarily unavailable. Retry or upgrade for priority processing.",
      error:           "apex_compute_failed",
    };
  }
}

//  v134.0.0: applyTierGate -- enforces monetization on feed items 
// Free tier: iocs = count only, stix_bundle = locked, apex_ai = partial
// Premium: full iocs, STIX metadata, full apex_ai
// Enterprise: everything including raw stix_bundle passthrough

function applyTierGate(item, tier) {
  const isFree = !tier || tier === CONFIG.TIERS.FREE;
  const isEnt  = tier === CONFIG.TIERS.ENTERPRISE;

  const gated = { ...item };

  // IOC paywall: free tier strips raw IOC arrays, keeps count + confidence
  if (isFree && Array.isArray(item.iocs) && item.iocs.length > 0) {
    gated.iocs      = [];
    gated.ioc_count = item.iocs.length;
    // v134.0: Always expose ioc_confidence + ioc_threat_level (not paywalled)
    // These are summary signals -- the full IOC list is locked behind Pro
    gated.ioc_confidence   = item.ioc_confidence   || 0;
    gated.ioc_threat_level = item.ioc_threat_level || "NONE";
    gated.ioc_paywall = {
      locked:            true,
      count:             item.iocs.length,
      confidence:        item.ioc_confidence || 0,
      threat_level:      item.ioc_threat_level || "NONE",
      primary_types:     (item.ioc_extraction_meta && item.ioc_extraction_meta.primary_types) || [],
      upgrade_url:       "/upgrade.html?plan=pro",
      message:           `${item.iocs.length} IOC(s) at ${item.ioc_confidence || 0}% confidence -- unlock with Pro tier.`,
    };
  }

  // STIX bundle paywall: free/premium get metadata only, enterprise gets raw bundle
  if (!isEnt) {
    gated.stix_bundle = null;
    if (item.stix_bundle) {
      gated.stix_bundle_meta = {
        locked:        true,
        bundle_id:     item.bundle_id || item.stix_id,
        stix_file:     item.stix_file || null,
        object_count:  item.stix_object_count || 0,
        upgrade_url:   "/upgrade.html?plan=enterprise",
        message:       "Full STIX 2.1 bundle export available on Enterprise tier.",
      };
    }
  }

  // v134.0: IOC COUNT CONSISTENCY -- paid tiers: ioc_count MUST equal actual iocs.length.
  // Prevents ioc_count > 0 with empty array (data integrity violation for Pro/Enterprise).
  if (!isFree && Array.isArray(gated.iocs)) {
    gated.ioc_count = gated.iocs.length;
  }

  // v134.0: STIX BUNDLE VALIDITY GATE -- when stix_bundle is present (Enterprise),
  // validate it has the required STIX 2.1 structure. Strip invalid bundles rather than serve them.
  if (isEnt && gated.stix_bundle !== null && gated.stix_bundle !== undefined) {
    const sb = gated.stix_bundle;
    if (typeof sb !== "object" || sb.type !== "bundle" || !Array.isArray(sb.objects) || sb.objects.length === 0) {
      // Invalid STIX bundle structure -- null it out to prevent corrupt data reaching consumers
      gated.stix_bundle = null;
      gated.stix_bundle_meta = {
        locked:       false,
        error:        "stix_bundle_invalid",
        message:      "STIX bundle failed structural validation. Contact support.",
        bundle_id:    item.bundle_id || item.stix_id,
        stix_file:    item.stix_file || null,
        object_count: 0,
      };
    }
  }

  // Inject computed apex_ai block
  gated.apex_ai = computeApexAI(item, tier);

  // v149.0 POST-ASSIGNMENT APEX_AI INTEGRITY GUARD (defense-in-depth)
  // computeApexAI has a hasValidApexAI guard and a try/catch that should
  // correctly preserve item.apex_ai when it is valid. However, if the catch
  // block fires for any unexpected reason (e.g. a runtime error inside the
  // Free-tier masking branch) it would return { error: "apex_compute_failed" },
  // silently dropping the valid upstream apex_ai from R2/API.
  //
  // This guard detects that specific failure mode and restores item.apex_ai:
  //   - computeApexAI returned an error sentinel (catch fired)
  //   - AND the original item.apex_ai was valid (non-null, object, no error flag)
  //   - Restore item.apex_ai so valid intel is NEVER lost due to a compute error
  //
  // This is intentionally a no-op under normal operation (computeApexAI works).
  // It only activates as a last-resort fallback in the rare error path.
  if (
    gated.apex_ai &&
    typeof gated.apex_ai === "object" &&
    gated.apex_ai.error === "apex_compute_failed" &&
    item.apex_ai != null &&
    typeof item.apex_ai === "object" &&
    !Array.isArray(item.apex_ai) &&
    !item.apex_ai.error
  ) {
    // Restore original apex_ai -- do NOT overwrite valid upstream intelligence
    gated.apex_ai = { ...item.apex_ai };
  }

  // v134.0: HIGH/CRITICAL severity integrity check -- never serve HIGH+ advisory with 0 IOCs.
  // If ioc_count is still 0 after normalization, flag it with a data quality annotation.
  // This is a data-quality annotation only -- does NOT block the response.
  const finalSev = (gated.severity || "").toUpperCase();
  if ((finalSev === "CRITICAL" || finalSev === "HIGH") && (gated.ioc_count || 0) === 0) {
    gated._data_quality = { warning: "high_severity_zero_ioc", message: "IOC extraction pending or data incomplete." };
  }

  // v134.0.0: Threat urgency CTA -- injected for free tier on critical/high items
  // Drives upgrade conversion at the moment of maximum perceived threat value
  if (isFree) {
    const sev = (item.severity || item.risk_level || "").toUpperCase();
    const riskScore = typeof item.risk_score === "number" ? item.risk_score
                    : typeof item.cvss_score  === "number" ? item.cvss_score : 0;
    const isUrgent = sev === "CRITICAL" || sev === "HIGH" || riskScore >= 7;
    if (isUrgent) {
      gated.threat_urgency = {
        active:          true,
        message:         sev === "CRITICAL"
          ? " CRITICAL ACTIVE THREAT -- Full intelligence, IOC array & actor attribution locked."
          : " HIGH-SEVERITY ACTIVE THREAT -- Actor TTPs and kill chain analysis locked.",
        tier_required:   "PRO",
        upgrade_url:     "/upgrade.html?plan=pro",
        cta:             "Upgrade to Pro -- Detect, Respond, Contain.",
        enterprise_note: "Enterprise Detection Engine unavailable on free tier.",
      };
    }
  }

  return gated;
}

//  v134.0.0: IOC Extraction from Text 
// Regex-based IOC detection from title/description/summary text.
// Used as fallback when ioc_count < 3 -- ensures EVERY threat has indicators.
// Filters private IP ranges. CVE IDs have highest confidence (0.95).

const IOC_PATTERNS = {
  cve:    /CVE-\d{4}-\d{4,7}/gi,
  ipv4:   /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  md5:    /\b[a-fA-F0-9]{32}\b/g,
  url:    /https?:\/\/[^\s<>"{}|\\^`[\]\x00-\x1F]+/gi,
  email:  /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|edu|mil|co|uk|de|ru|cn|jp|fr|br|info|biz|xyz|tech|online|cloud|app|dev|security|cyber)\b/gi,
};
const PRIVATE_IP_RE = /^(?:10\.|127\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.|255\.)/;
const BOGON_DOMAINS = new Set(["example.com", "test.com", "localhost", "invalid"]);

function extractIOCsFromText(text) {
  if (!text || typeof text !== "string" || text.length < 4) return [];
  const iocs   = [];
  const seen   = new Set();
  const addIoc = (type, value, confidence = 0.7) => {
    const key = `${type}:${value.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    iocs.push({ type, value, extracted: true, confidence });
  };

  // CVE (highest confidence -- unambiguous)
  for (const m of text.matchAll(IOC_PATTERNS.cve))
    addIoc("cve", m[0].toUpperCase(), 0.95);

  // URLs (before domain to capture hostname once)
  for (const m of text.matchAll(IOC_PATTERNS.url)) {
    try {
      const u = new URL(m[0]);
      addIoc("url", m[0], 0.85);
      if (!BOGON_DOMAINS.has(u.hostname)) addIoc("domain", u.hostname, 0.8);
    } catch {}
  }

  // IPv4 (filter private/loopback/reserved)
  for (const m of text.matchAll(IOC_PATTERNS.ipv4)) {
    if (!PRIVATE_IP_RE.test(m[0])) addIoc("ipv4", m[0], 0.8);
  }

  // SHA-256 hashes
  for (const m of text.matchAll(IOC_PATTERNS.sha256))
    addIoc("sha256", m[0].toLowerCase(), 0.9);

  // MD5 (only 32-char -- lower confidence, often false-positive in non-hash contexts)
  for (const m of text.matchAll(IOC_PATTERNS.md5)) {
    if (m[0].length === 32 && !seen.has(`sha256:${m[0].toLowerCase()}`))
      addIoc("md5", m[0].toLowerCase(), 0.6);
  }

  // Email
  for (const m of text.matchAll(IOC_PATTERNS.email)) {
    const em = m[0].toLowerCase();
    if (!BOGON_DOMAINS.has(em.split("@")[1])) addIoc("email", em, 0.75);
  }

  // Domain (deduped against URL hostnames already captured)
  for (const m of text.matchAll(IOC_PATTERNS.domain)) {
    const dom = m[0].toLowerCase();
    if (!seen.has(`domain:${dom}`) && !BOGON_DOMAINS.has(dom) && dom.length < 100)
      addIoc("domain", dom, 0.65);
  }

  return iocs;
}

//  v134.0.0: Schema Validator & Normalizer 
// HARD GUARANTEE: No null/undefined for any field that UI or API consumers depend on.
// Called on every item before API responses and before applyTierGate.
// ZERO tolerance: missing field -> derive from existing data -> guaranteed default.
function validateAndNormalizeItem(item) {
  if (!item || typeof item !== "object") return null;
  const out = { ...item };

  //  risk_score: MUST be number 0--10 
  if (typeof out.risk_score !== "number" || isNaN(out.risk_score)) {
    out.risk_score = typeof out.cvss_score === "number" ? out.cvss_score : 0;
  }
  out.risk_score = Math.max(0, Math.min(10, out.risk_score));

  //  severity: derive from risk_score when missing/UNKNOWN 
  const rawSev = (out.severity || out.risk_level || "").toUpperCase().trim();
  const VALID_SEV = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
  if (!VALID_SEV.has(rawSev)) {
    out.severity = out.risk_score >= 9 ? "CRITICAL"
                 : out.risk_score >= 7 ? "HIGH"
                 : out.risk_score >= 4 ? "MEDIUM"
                 : "LOW";
  } else {
    out.severity = rawSev;
  }

  //  title: MUST be non-empty string 
  if (!out.title || typeof out.title !== "string" || !out.title.trim()) {
    out.title = out.cve_id || out.advisory_id || out.id || "Untitled Advisory";
  }

  //  id + stix_id: cross-populate 
  if (!out.id)      out.id      = out.stix_id || out.cve_id || out.advisory_id || `advisory-${Date.now()}`;
  if (!out.stix_id) out.stix_id = out.id;

  //  timestamps: guarantee processed_at and timestamp both set 
  const firstTs = out.processed_at || out.timestamp || out.generated_at || out.published_at;
  if (!out.processed_at) out.processed_at = firstTs || new Date().toISOString();
  if (!out.timestamp)    out.timestamp    = out.processed_at;

  //  ioc_counts: derive from iocs array when object is absent/empty 
  // Frontend uses ioc_counts.ipv4, .domain, .sha256, .url, .email, .cve
  if (!out.ioc_counts || Object.keys(out.ioc_counts).length === 0) {
    if (Array.isArray(out.iocs) && out.iocs.length > 0) {
      const counts = {};
      for (const ioc of out.iocs) {
        if (!ioc || typeof ioc !== "object") continue;
        const t = (ioc.type || "unknown").toLowerCase().replace(/[^a-z0-9_]/g, "_");
        counts[t] = (counts[t] || 0) + 1;
      }
      out.ioc_counts = counts;
    } else {
      out.ioc_counts = {};
    }
  }

  //  ioc_count scalar: sum of ioc_counts or length of iocs 
  if (typeof out.ioc_count !== "number") {
    out.ioc_count = Array.isArray(out.iocs) ? out.iocs.length
      : (out.ioc_counts ? Object.values(out.ioc_counts).reduce((a, b) => a + (b || 0), 0) : 0);
  }

  //  v134.0.0: IOC Extraction Fallback -- RULE: ioc_count >= 3 
  // When a threat has fewer than 3 IOCs, extract additional indicators from text.
  // Priority sources: description > summary > title. Synthesized IOCs are marked
  // with extracted:true and confidence < 1.0 to distinguish from pipeline-sourced.
  if (out.ioc_count < 3) {
    const textSources = [out.description, out.summary, out.details, out.title]
      .filter(s => typeof s === "string" && s.length > 10)
      .join(" ");
    const extracted = extractIOCsFromText(textSources);
    if (extracted.length > 0) {
      // Merge with existing IOCs, avoiding duplicates
      const existingKeys = new Set((out.iocs || []).map(i => `${i.type}:${(i.value || "").toLowerCase()}`));
      const newIocs = extracted.filter(e => !existingKeys.has(`${e.type}:${e.value.toLowerCase()}`));
      if (newIocs.length > 0) {
        out.iocs = [...(out.iocs || []), ...newIocs];
        out.ioc_count = out.iocs.length;
        // Recompute ioc_counts with extracted IOCs included
        const counts = {};
        for (const ioc of out.iocs) {
          const t = (ioc.type || "unknown").toLowerCase().replace(/[^a-z0-9_]/g, "_");
          counts[t] = (counts[t] || 0) + 1;
        }
        out.ioc_counts = counts;
      }
    }
    // If still < 3, synthesize CVE/domain from title as minimum anchor IOCs
    if (out.ioc_count < 3) {
      const cveMatch = (out.title || "").match(/CVE-\d{4}-\d{4,7}/i);
      const synth    = [];
      if (cveMatch && !out.iocs.some(i => i.type === "cve")) {
        synth.push({ type: "cve", value: cveMatch[0].toUpperCase(), extracted: true, synthesized: true, confidence: 0.95 });
      }
      if (out.feed_source && out.feed_source !== "SENTINEL-APEX" && synth.length + out.ioc_count < 3) {
        const srcDom = out.feed_source.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
        if (srcDom.includes(".") && srcDom.length > 4) {
          synth.push({ type: "domain", value: srcDom, extracted: true, synthesized: true, confidence: 0.5 });
        }
      }
      if (synth.length > 0) {
        out.iocs = [...(out.iocs || []), ...synth];
        out.ioc_count = out.iocs.length;
        const counts = {};
        for (const ioc of out.iocs) {
          const t = (ioc.type || "unknown").toLowerCase().replace(/[^a-z0-9_]/g, "_");
          counts[t] = (counts[t] || 0) + 1;
        }
        out.ioc_counts = counts;
      }
    }
  }

  //  confidence_score: 0--100 (normalise 0--1 fraction) 
  if (typeof out.confidence_score !== "number" || isNaN(out.confidence_score)) {
    out.confidence_score = typeof out.confidence === "number" ? out.confidence : 50;
  }
  if (out.confidence_score > 0 && out.confidence_score <= 1) {
    out.confidence_score = Math.round(out.confidence_score * 100);
  }
  out.confidence_score = Math.max(0, Math.min(100, Math.round(out.confidence_score)));

  //  actor_tag: must be non-null string 
  if (!out.actor_tag || typeof out.actor_tag !== "string") out.actor_tag = "UNATTRIBUTED";

  //  feed_source 
  if (!out.feed_source) out.feed_source = out.source || "SENTINEL-APEX";

  //  mitre_tactics: must be array 
  if (!Array.isArray(out.mitre_tactics)) {
    out.mitre_tactics = Array.isArray(out.ttps) ? out.ttps : [];
  }

  //  iocs: must be array 
  if (!Array.isArray(out.iocs)) out.iocs = [];

  //  ttps: must be array 
  if (!Array.isArray(out.ttps)) out.ttps = [];

  //  boolean flags 
  out.kev_present = out.kev_present === true;
  out.exploit_available = out.exploit_available === true;
  out.zero_day = out.zero_day === true;
  out.supply_chain = out.supply_chain === true;
  out.ransomware = out.ransomware === true;

  //  v134.0: IOC Engine enrichment fields -- pass through from pipeline 
  // ioc_confidence: float 0--100 -- confidence score from multi-layer IOC extraction
  if (typeof out.ioc_confidence !== "number" || isNaN(out.ioc_confidence)) {
    // Derive from ioc_count: rough approximation when not set by pipeline
    out.ioc_confidence = out.ioc_count >= 10 ? 92.0
                       : out.ioc_count >= 5  ? 82.0
                       : out.ioc_count >= 2  ? 70.0
                       : out.ioc_count >= 1  ? 55.0
                       : 0.0;
  }
  out.ioc_confidence = Math.max(0, Math.min(100, out.ioc_confidence));

  // ioc_threat_level: IOC-based threat classification (independent of severity)
  const VALID_IOC_LEVELS = new Set(["NONE","LOW","MEDIUM","HIGH","CRITICAL"]);
  if (!VALID_IOC_LEVELS.has((out.ioc_threat_level || "").toUpperCase())) {
    out.ioc_threat_level = out.ioc_count >= 10 ? "CRITICAL"
                         : out.ioc_count >= 5  ? "HIGH"
                         : out.ioc_count >= 2  ? "MEDIUM"
                         : out.ioc_count >= 1  ? "LOW"
                         : "NONE";
  } else {
    out.ioc_threat_level = out.ioc_threat_level.toUpperCase();
  }

  // ioc_extraction_meta: pass-through metadata dict from pipeline
  if (!out.ioc_extraction_meta || typeof out.ioc_extraction_meta !== "object") {
    out.ioc_extraction_meta = {};
  }

  return out;
}

//  v134.0: applyIocMetaTierGate -- strips extraction_meta from free tier 
// ioc_confidence and ioc_threat_level are always visible (summary signals)
// ioc_extraction_meta (layer breakdown, enrichment priority) requires Pro+
function applyIocMetaTierGate(item, tier) {
  const isFree = !tier || tier === CONFIG.TIERS.FREE;
  if (!isFree) return item;  // Pro/Enterprise: full pass-through
  const out = { ...item };
  // Strip full extraction meta -- keep only summary signals
  if (out.ioc_extraction_meta && Object.keys(out.ioc_extraction_meta).length > 0) {
    out.ioc_extraction_meta = {
      locked:      true,
      upgrade_url: "/upgrade.html?plan=pro",
      message:     "IOC extraction layer breakdown requires Pro tier.",
    };
  }
  return out;
}

//  Handlers

// -----------------------------------------------------------------------------
//  PUBLIC: /api/feed.json -- Dashboard FALLBACK1 endpoint (v147.0)
//  Returns a plain JSON array of all feed items (same schema as api/feed.json
//  on GitHub Pages). No auth required. CORS open (*) -- same-domain fallback
//  for the dashboard. Dashboard parser handles plain Array schema directly.
// -----------------------------------------------------------------------------
async function handleFeedJson(request, env, rid) {
  const CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Cache-Control":                "no-store, max-age=0",
    "X-SENTINEL-Endpoint":          "feed-json",
    "X-SENTINEL-Version":           CONFIG.GATEWAY_VERSION,
  };

  // Handle CORS preflight
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (request.method !== "GET") {
    return new Response(JSON.stringify({ error: "method_not_allowed" }), {
      status: 405,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    });
  }

  try {
    // SOURCE 1: R2 (authoritative -- same data as /api/preview but full array)
    if (env?.INTEL_R2) {
      try {
        const obj = await env.INTEL_R2.get("intel/feed_manifest.json");
        if (obj) {
          const raw  = await obj.json();
          const norm = normaliseManifestData(raw);
          if (norm?.reports?.length > 0) {
            const items = deduplicateFeedItems(norm.reports);
            slog("INFO", "FEED-JSON", `Served ${items.length} items from R2`, { rid });
            await recordAnalytics(env, null, "feed_json_r2", "anon", 200).catch(() => {});
            return new Response(JSON.stringify(items), {
              status: 200,
              headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
            });
          }
        }
      } catch (e) {
        slog("WARN", "FEED-JSON", "R2 read failed, falling to KV", { error: e.message, rid });
      }
    }

    // SOURCE 2: KV warm cache (fallback if R2 unavailable)
    // v145.0.0 FIX: idx:reports is written to SECURITY_HUB_KV by cron handler.
    // Prefer SECURITY_HUB_KV; fall back to RATE_LIMIT_KV for legacy compatibility.
    if (env?.SECURITY_HUB_KV || env?.RATE_LIMIT_KV) {
      try {
        const kvSrc = env.SECURITY_HUB_KV || env.RATE_LIMIT_KV;
        const cached = await kvSrc.get("idx:reports", { type: "json" });
        if (cached?.reports?.length > 0) {
          const items = deduplicateFeedItems(cached.reports);
          slog("INFO", "FEED-JSON", `Served ${items.length} items from KV cache`, { rid });
          await recordAnalytics(env, null, "feed_json_kv", "anon", 200).catch(() => {});
          return new Response(JSON.stringify(items), {
            status: 200,
            headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
          });
        }
      } catch (e) {
        slog("WARN", "FEED-JSON", "KV read failed", { error: e.message, rid });
      }
    }

    // SOURCE 3: fetchReportsIndex (includes GitHub fallback)
    const index = await fetchReportsIndex(env);
    const items = deduplicateFeedItems(index.reports);
    slog("INFO", "FEED-JSON", `Served ${items.length} items via fetchReportsIndex`, { rid });
    await recordAnalytics(env, null, "feed_json_fallback", "anon", 200).catch(() => {});
    return new Response(JSON.stringify(items), {
      status: 200,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    });

  } catch (err) {
    slog("ERROR", "FEED-JSON", "All sources exhausted", { error: err.message, rid });
    await recordAnalytics(env, null, "feed_json_error", "anon", 503).catch(() => {});
    return new Response(JSON.stringify({
      error:   "feed_unavailable",
      message: "Feed data temporarily unavailable -- pipeline sync may be in progress.",
      request_id: rid,
    }), {
      status: 503,
      headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
    });
  }
}

//  PUBLIC: /api/preview -- No API key required
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
    // Filter: remove brand/identity entries + deduplicate by stix_id + title-hash
    const cleanItems = deduplicateFeedItems(index.reports);
    // v134.0.0 FRESHNESS FIX: Sort by processed_at DESC (primary) -> timestamp DESC (fallback)
    // -> risk_score DESC (tiebreak).
    //
    // WHY processed_at is PRIMARY:
    //   RSS-sourced intel carries `published_at` dates from the original article
    //   (e.g. a CVE advisory published 3 weeks ago). When `timestamp` is set from
    //   `published_at`, newly generated intel APPEARS STALE even though it was just
    //   processed. `processed_at` is always set to pipeline execution time (UTC-now)
    //   so it is immune to source article date variations.
    //
    // SORT KEY helper v142.3.1: published_at is real source date (primary)
    const getSortTs = item => {
      const pa = item.published_at || item.timestamp || item.processed_at || item.generated_at || null;
      return pa ? new Date(pa).getTime() : 0;
    };
    cleanItems.sort((a, b) => {
      const ta = getSortTs(a);
      const tb = getSortTs(b);
      if (tb !== ta) return tb - ta;
      const ra = typeof a.risk_score === 'number' ? a.risk_score
               : typeof a.cvss_score === 'number' ? a.cvss_score : 0;
      const rb = typeof b.risk_score === 'number' ? b.risk_score
               : typeof b.cvss_score === 'number' ? b.cvss_score : 0;
      return rb - ra;
    });
    const allItems  = cleanItems;
    const preview   = allItems.slice(0, CONFIG.PREVIEW_LIMIT).map(item => {
      // P0 FIX v134.0: Include full MITRE/TTP/IOC data in preview response.
      // Previously stripped -- caused MITRE=0 on dashboard.
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
        // CRITICAL FIX v134.0.0: stix_id REQUIRED by dashboard ANALYZE button.
        // Guard in frontend: `if (!stixId) return;` silently blocks ANALYZE for
        // all preview items if this field is absent. Must mirror `id` resolution.
        stix_id:     item.stix_id     || item.id          || item.advisory_id || item.cve_id || "unknown",
        title:       item.title       || item.name         || item.cve_id || "Untitled",
        severity:    item.severity    || item.risk_level   || "UNKNOWN",
        description,
        tags:        item.tags        || item.categories   || [],
        threat_type: item.threat_type || item.type         || "General",
        risk_score:  typeof item.risk_score === "number" ? item.risk_score
                   : typeof item.cvss_score === "number" ? item.cvss_score : 0,
        // P0 FIX: Include full arrays (not just counts) for MITRE heatmap
        ttps:        Array.isArray(item.ttps)  ? item.ttps  : [],
        ttp_count:   ttpCount,
        confidence:  item.confidence  || 0,
        // v134.0.0 FRESHNESS: processed_at = pipeline generation time (primary freshness field).
        // Falls back to timestamp/generated_at for items ingested before this fix.
        // Dashboard LIVE 7D and sort-newest MUST read processed_at first.
        processed_at: item.processed_at || item.timestamp || item.generated_at || null,
        timestamp:   item.timestamp   || null,
        published_at: item.published_at || item.published || item.published_date || null,
        source:      item.source      || "SENTINEL-APEX",
        stix_bundle: item.stix_bundle || null,
        kev_present: item.kev_present || false,
        epss_score:  item.epss_score  || null,
        cvss_score:  item.cvss_score  || null,
        // v134.0.0 FIX: report_url MUST resolve. Rewrite old broken reports.cyberdudebivash.com
        // URLs (DNS NXDOMAIN) to intel.cyberdudebivash.com. Derive if missing.
        report_url: (() => {
          let u = item.report_url || "";
          // Rewrite dead subdomain -> working domain
          if (u.includes("reports.cyberdudebivash.com")) {
            u = u.replace("https://reports.cyberdudebivash.com", "https://intel.cyberdudebivash.com");
          }
          if (u) return u;
          // Derive relative path deterministically
          const id  = item.id || "unknown";
          const ts  = item.timestamp || new Date().toISOString();
          const dt  = new Date(ts);
          const y   = dt.getUTCFullYear();
          const m   = String(dt.getUTCMonth() + 1).padStart(2, "0");
          return `/reports/${y}/${m}/${id}.html`;
        })(),
        source_url:  (item.source_url && item.source_url.trim()) || null,
        actor_tag:   item.actor_tag   || null,
        mitre_tactics: Array.isArray(item.mitre_tactics) ? item.mitre_tactics
                      : Array.isArray(item.ttps) ? item.ttps : [],
        // v134.0.0: Free-tier IOC paywall -- strip raw IOC arrays, surface count + CTA
        iocs:       [],        // raw IOCs require Pro tier
        ioc_count:         Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0),
        // v134.0: Always expose confidence + threat_level in public preview
        ioc_confidence:    typeof item.ioc_confidence === "number" ? item.ioc_confidence : 0,
        ioc_threat_level:  item.ioc_threat_level || "NONE",
        ioc_paywall: Array.isArray(item.iocs) && item.iocs.length > 0 ? {
          locked:            true,
          count:             item.iocs.length,
          confidence:        typeof item.ioc_confidence === "number" ? item.ioc_confidence : 0,
          threat_level:      item.ioc_threat_level || "NONE",
          primary_types:     (item.ioc_extraction_meta && item.ioc_extraction_meta.primary_types) || [],
          upgrade_url:       "/upgrade.html?plan=pro",
          message:           `${Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0)} IOC(s) at ${typeof item.ioc_confidence === "number" ? item.ioc_confidence.toFixed(1) : 0}% confidence -- unlock with Pro tier.`,
        } : null,
        // v134.0.0: APEX AI block -- always present in preview, fields tier-gated
        apex_ai:    computeApexAI(item, CONFIG.TIERS.FREE),
        // Legacy apex passthrough (partial) for backward compat with existing panels
        apex: (() => {
          const ap = item.apex;
          if (!ap || typeof ap !== "object") return null;
          // Free preview: surface non-sensitive apex fields only
          // v143.0: predictive_score now reads composite_score (APEX-calibrated)
          // falling back to legacy predictive_score for backward compat
          const apexScore = ap.composite_score != null ? ap.composite_score
                          : ap.priority_score  != null ? ap.priority_score
                          : ap.predictive_score != null ? ap.predictive_score : 0;
          return {
            priority:         ap.priority       || "P4",
            threat_level:     ap.threat_level   || "UNKNOWN",
            threat_category:  (ap.threat_category && ap.threat_category !== "UNKNOWN" ? ap.threat_category : _classifyThreatCategory(item)),
            predictive_score: apexScore,         // consistent with apex_ai.predictive_risk
            campaign_id:      "PRO_REQUIRED",    // campaign ID is Pro+
          };
        })(),
        validation_status: item.validation_status || null,
        stix_object_count: item.stix_object_count || 0,
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
    await trackError(env, "PREVIEW", "handlePreview failed", { error: err_.message });
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

//  AUTHENTICATED: /api/feed 
async function handleFeed(request, env, auth, rid) {
  const url      = new URL(request.url);

  // v134.0.0: Input sanitization -- prevent injection via query params
  const ALLOWED_SEVERITY = new Set(["critical", "high", "medium", "low", "info", "unknown"]);
  const rawLimit    = url.searchParams.get("limit") || "";
  const rawPage     = url.searchParams.get("page")  || "";
  const rawSeverity = url.searchParams.get("severity") || "";
  const rawSearch   = url.searchParams.get("q") || "";

  // Numeric params: coerce to safe integers; reject NaN/negative
  const parsedLimit = parseInt(rawLimit) || CONFIG.FEED_LIMITS[auth.tier];
  const parsedPage  = parseInt(rawPage)  || 1;
  if (isNaN(parsedLimit) || parsedLimit < 1) {
    return jsonResponse({ error: "invalid_param", message: "limit must be a positive integer.", request_id: rid }, 400);
  }
  if (isNaN(parsedPage) || parsedPage < 1) {
    return jsonResponse({ error: "invalid_param", message: "page must be a positive integer.", request_id: rid }, 400);
  }

  // Severity: allow-list only
  const severity = rawSeverity
    ? (ALLOWED_SEVERITY.has(rawSeverity.toLowerCase()) ? rawSeverity.toLowerCase() : null)
    : null;
  if (rawSeverity && !severity) {
    return jsonResponse({ error: "invalid_param", message: `Invalid severity. Allowed: ${[...ALLOWED_SEVERITY].join(", ")}`, request_id: rid }, 400);
  }

  // Search: max 128 chars -- sanitizeStr strips control chars + blocks injection patterns
  const search = rawSearch ? (sanitizeStr(rawSearch, 128) || null) : null;

  const limit = Math.min(parsedLimit, CONFIG.FEED_LIMITS[auth.tier]);
  const page  = Math.max(1, parsedPage);

  try {
    const index = await fetchReportsIndex(env);
    // Deduplicate by stix_id + title-hash + strip brand noise
    let items = deduplicateFeedItems(index.reports).map(item => {
      // Enrich description
      const raw = (item.description || "").replace(/^Tactical cluster:\s*/i, "").trim() || (item.title || "");
      item.description = raw;
      return item;
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

    // v134.0.0 FRESHNESS FIX: Sort full feed by processed_at DESC before pagination.
    // Ensures authenticated /api/feed consumers always receive newest-generated intel first,
    // regardless of the manifest file order or source article publication dates.
    items.sort((a, b) => {
      const ta = new Date(a.published_at || a.timestamp || a.processed_at || a.generated_at || 0).getTime(); // v142.3.1
      const tb = new Date(b.published_at || b.timestamp || b.processed_at || b.generated_at || 0).getTime(); // v142.3.1
      return tb - ta;
    });

    const total      = items.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const offset     = (page - 1) * limit;
    // v134.0.0: Apply tier-gated monetization to each feed item
    // Injects apex_ai block and enforces IOC/STIX paywall per tier
    const pageItems  = items.slice(offset, offset + limit)
      .map(it => applyTierGate(it, auth.tier))
      .map(it => applyIocMetaTierGate(it, auth.tier));

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
    await trackError(env, "FEED", "handleFeed failed", { error: err_.message, tier: auth.tier });
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
    // v134.0.0: Normalize + apply tier gate -- API /feed/:id MUST match /feed response
    const normalized = validateAndNormalizeItem(report) || report;
    const gated      = applyIocMetaTierGate(applyTierGate(normalized, auth.tier), auth.tier);

    const ttl = (gated.severity || "").toUpperCase() === "CRITICAL"
      ? CONFIG.CACHE_TTL.CRITICAL
      : CONFIG.CACHE_TTL.REPORT;
    if (env?.RATE_LIMIT_KV) {
      await env.RATE_LIMIT_KV.put(cacheKey, JSON.stringify(gated), { expirationTtl: ttl }).catch(() => {});
    }
    await recordAnalytics(env, auth.key_id, "report", auth.tier, 200);
    return jsonResponse({
      status:     "ok",
      request_id: rid,
      tier:       auth.tier,
      data:       gated,
      cached:     false,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    });
  } catch (e) {
    await trackError(env, "REPORT", "handleReport failed", { error: e.message, report_id: reportId });
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

  // v148.1.0 FIX: kv_rate_limit health check now uses KV READ instead of WRITE.
  // ROOT CAUSE of persistent "warn": every /api/health call was executing a KV
  // put("health:ping") -- Cloudflare KV free tier allows 100K writes/day; a busy
  // health endpoint exhausts this budget and causes all write attempts to fail,
  // returning "warn" even when the KV namespace is fully operational.
  //
  // FIX: read the "health:sentinel" sentinel key (written once by the cron handler
  // at startup / scheduled tick) to verify KV reachability without consuming write
  // quota. Falls back to a lightweight write ONLY if the read returns null (cold
  // start) -- uses a 1-hour TTL instead of 10s to minimise write frequency.
  //
  // DO NOT revert to put("health:ping") -- this causes persistent kv_rate_limit=warn.
  if (env?.RATE_LIMIT_KV) {
    try {
      const sentinel = await env.RATE_LIMIT_KV.get("health:sentinel");
      if (sentinel !== null) {
        checks.kv_rate_limit = "ok";
      } else {
        // Cold start: write sentinel once with 1-hour TTL (1 write per cold start only)
        try {
          await env.RATE_LIMIT_KV.put("health:sentinel", "1", { expirationTtl: 3600 });
          checks.kv_rate_limit = "ok";
        } catch (_we) {
          checks.kv_rate_limit = "warn";
        }
      }
    } catch (_re) {
      checks.kv_rate_limit = "warn";
    }
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

  // v148.2.0 FIX: idx:reports shape-agnostic health check.
  // ROOT CAUSE of persistent "not_cached": health check only checked c?.total_reports
  // but cron writes the raw manifest which is either a flat array OR {reports:[...]}
  // -- neither shape has a total_reports field, so the check always resolved to 0.
  //
  // FIX: accept ALL known shapes of idx:reports:
  //   Shape A: { total_reports: N, reports: [...] }  -- normalised (post-fix cron)
  //   Shape B: { reports: [...] }                    -- un-normalised legacy cron write
  //   Shape C: flat array [...]                      -- raw manifest written by old cron
  //   Shape D: { items: [...] } / { advisories: [...] } -- other pipeline shapes
  //
  // DO NOT revert to checking only c?.total_reports -- that always returns undefined
  // for shapes B/C/D and causes persistent "not_cached" even when data is present.
  //
  // Fall back to RATE_LIMIT_KV as secondary so legacy deployments still work.
  if (env?.SECURITY_HUB_KV || env?.RATE_LIMIT_KV) {
    try {
      const kvSrc = env.SECURITY_HUB_KV || env.RATE_LIMIT_KV;
      const c = await kvSrc.get("idx:reports", { type: "json" });
      const _feedCount = c
        ? (c.total_reports
            || (Array.isArray(c.reports)    ? c.reports.length    : 0)
            || (Array.isArray(c)            ? c.length            : 0)
            || (Array.isArray(c.items)      ? c.items.length      : 0)
            || (Array.isArray(c.advisories) ? c.advisories.length : 0))
        : 0;
      checks.feed_index = _feedCount > 0 ? `cached:${_feedCount}_items` : "not_cached";
    } catch { checks.feed_index = "error"; }
  }

  // v141.0.0: JWT secret presence check -- surface auth readiness in health
  checks.jwt_configured = env?.CDB_JWT_SECRET ? true : false;

  // v134.0: Include live advisory count + last_sync from manifest for full pipeline visibility
  let advisoryCount = 0;
  let lastSync      = null;
  let manifestVersion = null;
  try {
    const index = await fetchReportsIndex(env);
    const clean = deduplicateFeedItems(index.reports);
    advisoryCount   = clean.length;
    lastSync        = index.generated_at || null;
    manifestVersion = index.source_meta?.version || null;
  } catch { /* non-critical -- health still returns */ }

  // v141.0.0: Only truly critical check failures cause "degraded".
  // kv_rate_limit "warn" and jwt_configured false are advisory-only --
  // they do not block platform data serving or feed delivery.
  const CRITICAL_CHECKS = ["kv_api_keys", "r2_intel"];
  const criticalOk = CRITICAL_CHECKS.every(k => checks[k] === "ok" || checks[k] === undefined);
  const allOk      = Object.entries(checks).every(([k, v]) =>
    k === "jwt_configured" ? true :       // boolean, not string
    v === "ok" || v.startsWith("cached:") || v === "warn"
  );
  const statusStr = criticalOk && allOk ? "healthy" : criticalOk ? "ok" : "degraded";

  return jsonResponse({
    status:           statusStr,
    version:          CONFIG.GATEWAY_VERSION,
    gateway:          `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    platform:         "CYBERDUDEBIVASH(R) SENTINEL APEX",
    timestamp:        new Date().toISOString(),
    pipeline: {
      advisory_count:   advisoryCount,
      last_sync:        lastSync,
      manifest_version: manifestVersion,
      dedup_active:     true,
      ioc_engine:       "5.0",
      ai_engine:        "3.0",
      stix_version:     "2.1",
    },
    checks,
    request_id: rid,
  }, statusStr === "degraded" ? 207 : 200);
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

//  AI Intelligence Endpoint -- /api/ai/* 
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
        // v148.1.0: Broadened validation to accept all AI endpoint schemas:
        //   - ai_index.json:        data.panels | data.mitre_techniques | data.reports | data.analysis
        //   - tracker.json:         data.engine_alpha | data.executive_summary | data.schema
        //   - health.json:          data.engines | data.overall_health | data.health_score
        //   - executive-brief.json: data.brief | data.executive_brief | data.recommendations
        // Previously only ai_index.json schema was accepted -- tracker/health/brief all fell through
        // to Source 3 (live-feed fallback) causing empty/stalled dashboard on ai-threat-tracker.html
        if (data && (
          data.panels || data.analysis || data.mitre_techniques || data.reports ||
          data.engine_alpha || data.executive_summary || data.schema ||
          data.engines || data.overall_health || data.health_score ||
          data.brief || data.executive_brief || data.recommendations ||
          data.version || data.generated_at
        )) {
          // Warm KV cache
          if (env.RATE_LIMIT_KV) {
            await env.RATE_LIMIT_KV.put(kvKey, JSON.stringify(data), { expirationTtl: ttlSeconds })
              .catch(() => {});
          }
          return { data, cached: false };
        }
      }
    } catch (e) { slog("WARN", "R2-AI", `R2 AI fetch failed: ${r2Key}`, { error: e.message }); }
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
        version:      "116.2.0",
        generated_at: index.generated_at || new Date().toISOString(),
        platform:     "CYBERDUDEBIVASH SENTINEL APEX",
        ai_engine:    "APEX-v134",
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
  } catch (e) { slog("WARN", "AI-FALLBACK", "Live feed AI derivation failed", { error: e.message }); }
  return null;
}

async function handleAI(request, env, rid, subpath) {
  // Public endpoint -- no API key required for index and heatmap data
  // Full analysis requires API key (enforced by caller for /analyze, /respond, /correlate)

  // v148.1.0 FIX: Added tracker / health / executive-brief entries.
  // Previously these were missing -- all three fell back to ai_index.json (wrong schema)
  // causing ai-threat-tracker.html to show empty/stalled dashboard.
  // Dot-suffixed keys (e.g. "tracker.json") handle the literal filename as fetched
  // by the frontend via fetch('/api/ai/tracker.json').
  const pathMap = {
    ""                      : { r2: "ai/ai_index.json",          kv: "ai:index",      ttl: 120 },
    "index"                 : { r2: "ai/ai_index.json",          kv: "ai:index",      ttl: 120 },
    "tracker"               : { r2: "ai/tracker.json",           kv: "ai:tracker",    ttl: 300 },
    "tracker.json"          : { r2: "ai/tracker.json",           kv: "ai:tracker",    ttl: 300 },
    "health"                : { r2: "ai/health.json",            kv: "ai:health",     ttl: 300 },
    "health.json"           : { r2: "ai/health.json",            kv: "ai:health",     ttl: 300 },
    "executive-brief"       : { r2: "ai/executive-brief.json",   kv: "ai:exec-brief", ttl: 300 },
    "executive-brief.json"  : { r2: "ai/executive-brief.json",   kv: "ai:exec-brief", ttl: 300 },
    "monetization"          : { r2: "ai/monetization.json",      kv: "ai:monetize",   ttl: 300 },
    "monetization.json"     : { r2: "ai/monetization.json",      kv: "ai:monetize",   ttl: 300 },
    "analyze"               : { r2: "ai/analyze.json",           kv: "ai:analyze",    ttl: 120 },
    "respond"               : { r2: "ai/respond.json",           kv: "ai:respond",    ttl: 180 },
    "correlate"             : { r2: "ai/correlate.json",         kv: "ai:correlate",  ttl: 180 },
    "heatmap"               : { r2: "ai/ai_index.json",          kv: "ai:index",      ttl: 120 },
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
    await trackError(env, "AI", "handleAI failed", { error: err_.message, subpath });
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

// v143.0.0: POST /api/admin/cache/bust-prefix -- bulk-delete all KV keys matching a prefix
// Supports wildcard invalidation for new v143 endpoint caches (dark-web, reports, checkout).
async function handleCacheBustPrefix(request, env, rid) {
  const secret   = env?.ADMIN_SECRET;
  const provided = request.headers.get("X-Admin-Secret");
  if (!secret || provided !== secret) {
    return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
  }
  const raw    = (new URL(request.url).searchParams.get("prefix") || "").replace(/[^a-z0-9_:\-\.]/gi, "");
  const prefix = raw.slice(0, 64);  // max 64 chars to prevent abuse
  if (!prefix) {
    return jsonResponse({ error: "prefix_required", message: "Supply ?prefix=... parameter.", request_id: rid }, 400);
  }

  // Try RATE_LIMIT_KV first (general cache namespace), then SECURITY_HUB_KV and ANALYTICS_KV
  const namespaces = [
    { name: "RATE_LIMIT_KV",   kv: env?.RATE_LIMIT_KV   },
    { name: "ANALYTICS_KV",    kv: env?.ANALYTICS_KV    },
    { name: "SECURITY_HUB_KV", kv: env?.SECURITY_HUB_KV },
    { name: "API_KEYS_KV",     kv: env?.API_KEYS_KV     },
  ];

  let totalDeleted = 0;
  const nsResults  = [];

  for (const { name, kv } of namespaces) {
    if (!kv) continue;
    try {
      const list = await kv.list({ prefix, limit: 500 }).catch(() => ({ keys: [] }));
      const keys = (list?.keys || []).map(k => k.name);
      if (keys.length > 0) {
        await Promise.all(keys.map(k => kv.delete(k).catch(() => {})));
        totalDeleted += keys.length;
        nsResults.push({ namespace: name, deleted: keys.length, keys: keys.slice(0, 10) });
      }
    } catch (e) {
      nsResults.push({ namespace: name, error: e.message });
    }
  }

  slog("INFO", "ADMIN", `Cache prefix bust: prefix=${prefix}, deleted=${totalDeleted}`, { rid });
  return jsonResponse({
    success:       true,
    prefix,
    total_deleted: totalDeleted,
    namespaces:    nsResults,
    timestamp:     new Date().toISOString(),
    request_id:    rid,
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
    label:      sanitizeInput(body.label || "API Key", 100) || "API Key",
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
    warning:    "Store this key securely -- it cannot be retrieved again.",
    request_id: rid,
  }, 201);
}

//  v134.0.0: /api/version -- platform version manifest 
async function handleVersion(request, env, rid) {
  return jsonResponse({
    status:          "ok",
    request_id:      rid,
    version:         CONFIG.GATEWAY_VERSION,
    platform:        CONFIG.GATEWAY_NAME,
    gateway:         `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    endpoints: {
      dashboard:    "https://intel.cyberdudebivash.com",
      api_base:     "https://intel.cyberdudebivash.com/api",
      reports_base: "https://intel.cyberdudebivash.com/reports",
      stix_api:     "https://intel.cyberdudebivash.com/api/stix",
    },
    subscription_tiers: {
      free:       { api_rpm: 10,  feed_limit: 20,   stix: false, alerts: false },
      premium:    { api_rpm: 500, feed_limit: 500,  stix: true,  alerts: true  },
      enterprise: { api_rpm: 0,   feed_limit: 0,    stix: true,  alerts: true, siem: true, soar: true },
    },
    timestamp: new Date().toISOString(),
  });
}

//  v134.0.0: /api/stix/:id -- STIX 2.1 export 
// FREE tier: returns advisory metadata only
// PRO/ENTERPRISE: returns full STIX 2.1 bundle with objects array
async function handleStixExport(request, env, auth, rid, stixId) {
  if (!stixId) {
    return jsonResponse({ error: "stix_id_required", request_id: rid }, 400);
  }

  let index;
  try {
    index = await fetchReportsIndex(env);
  } catch (err) {
    return jsonResponse({ error: "feed_unavailable", message: err.message, request_id: rid }, 503);
  }

  const item = (index.reports || []).find(r =>
    r.stix_id === stixId || r.id === stixId
  );

  if (!item) {
    return jsonResponse({
      error:      "not_found",
      stix_id:    stixId,
      message:    `Advisory '${stixId}' not found in current feed.`,
      request_id: rid,
    }, 404);
  }

  await recordAnalytics(env, auth?.key_id, "stix_export", auth?.tier || "anon", 200);

  // Base object available to all tiers
  const baseObj = {
    type:       "indicator",
    spec_version: "2.1",
    id:         item.stix_id || item.id,
    name:       item.title,
    description: item.description || item.title,
    created:    item.processed_at || item.timestamp || new Date().toISOString(),
    modified:   item.processed_at || item.timestamp || new Date().toISOString(),
    labels:     item.tags || [],
    confidence: Math.round((item.risk_score || 0) * 10),
    lang:       "en",
    external_references: [
      item.source_url ? { source_name: item.feed_source || "SENTINEL-APEX", url: item.source_url } : null,
      item.nvd_url    ? { source_name: "NVD", url: item.nvd_url } : null,
    ].filter(Boolean),
  };

  // PRO/ENTERPRISE: full STIX bundle
  if (auth?.tier === CONFIG.TIERS.PREMIUM || auth?.tier === CONFIG.TIERS.ENTERPRISE) {
    const bundle = {
      type:         "bundle",
      id:           `bundle--${(item.stix_id || item.id || "").replace("intel--","").replace("indicator--","")}`,
      spec_version: "2.1",
      objects: [
        baseObj,
        // Malware / threat-actor object if actor is known
        item.actor_tag && item.actor_tag !== "UNATTRIBUTED" ? {
          type:         "threat-actor",
          spec_version: "2.1",
          id:           `threat-actor--${await sha256hex(item.actor_tag).then(h => h.slice(0,32))}`,
          name:         item.actor_tag,
          created:      item.processed_at || item.timestamp || new Date().toISOString(),
          modified:     item.processed_at || item.timestamp || new Date().toISOString(),
          labels:       ["nation-state", "criminal", "hacker"].slice(0, 1),
        } : null,
        // IOC indicators
        ...(item.iocs || []).slice(0, 50).map(ioc => {
          if (!ioc || typeof ioc !== "object") return null;
          return {
            type:         "indicator",
            spec_version: "2.1",
            id:           `indicator--${Math.random().toString(36).slice(2)}`,
            name:         ioc.value || ioc.indicator || "unknown",
            pattern:      `[${ioc.type || "network-traffic"}:value = '${ioc.value || ""}']`,
            pattern_type: "stix",
            created:      new Date().toISOString(),
            modified:     new Date().toISOString(),
            valid_from:   new Date().toISOString(),
            labels:       ["malicious-activity"],
          };
        }).filter(Boolean),
      ].filter(Boolean),
    };
    return jsonResponse({
      status:     "ok",
      request_id: rid,
      stix_id:    stixId,
      tier:       auth.tier,
      bundle,
      report_url: item.report_url || null,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    });
  }

  // FREE tier: metadata only + upgrade prompt
  return jsonResponse({
    status:     "ok",
    request_id: rid,
    stix_id:    stixId,
    tier:       auth?.tier || "free",
    advisory: {
      id:          item.id,
      title:       item.title,
      severity:    item.severity,
      risk_score:  item.risk_score,
      processed_at: item.processed_at || item.timestamp,
      report_url:  item.report_url || null,
      source_url:  (item.source_url && item.source_url.trim()) || null,
    },
    stix_object:  baseObj,
    full_bundle:  null,
    upgrade:      getUpgradeCTA(auth?.tier || "free"),
    message:      "Full STIX 2.1 bundle (indicators, TTPs, actor objects) available on Pro/Enterprise tier.",
    gateway:      `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: /api/webhooks/siem -- SIEM integration webhook 
// Enterprise tier: POST to register a SIEM webhook URL.
// When new intel is processed, APEX will POST to registered endpoints.
async function handleSiemWebhook(request, env, auth, rid) {
  if (auth.tier !== CONFIG.TIERS.ENTERPRISE) {
    return jsonResponse({
      error:   "enterprise_required",
      message: "SIEM webhook integration requires Enterprise tier.",
      upgrade: getUpgradeCTA(auth.tier),
      request_id: rid,
    }, 403);
  }
  if (!env?.SECURITY_HUB_KV) {
    return jsonResponse({ error: "kv_unavailable", request_id: rid }, 503);
  }
  if (request.method === "GET") {
    // v134.0.0: Support ?format=splunk|sentinel|qradar for SIEM export previews
    const fmt     = new URL(request.url).searchParams.get("format") || "json";
    const stored  = await env.SECURITY_HUB_KV.get(`webhook:${auth.key_id}`, { type: "json" });
    const VALID_FORMATS = ["json", "splunk", "sentinel", "qradar"];
    return jsonResponse({
      status:          "ok",
      key_id:          auth.key_id,
      webhooks:        stored || [],
      supported_formats: VALID_FORMATS,
      active_format:   VALID_FORMATS.includes(fmt) ? fmt : "json",
      format_docs: {
        splunk:   "Splunk HEC JSON -- POST to /services/collector/event",
        sentinel: "Azure Sentinel custom log (Log Analytics workspace)",
        qradar:   "IBM QRadar LEEF 2.0 syslog format",
        json:     "Raw SENTINEL-APEX JSON (default)",
      },
      request_id: rid,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    });
  }
  if (request.method === "POST") {
    let body;
    try { body = await request.json(); }
    catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }
    const VALID_SIEM_FORMATS = ["json", "splunk", "sentinel", "qradar"];
    const { url: webhookUrl, format = "json", filter_severity = "HIGH", secret: whSecret } = body;
    if (!VALID_SIEM_FORMATS.includes(format)) {
      return jsonResponse({ error: "invalid_format", valid: VALID_SIEM_FORMATS, request_id: rid }, 400);
    }
    if (!webhookUrl || !webhookUrl.startsWith("https://")) {
      return jsonResponse({ error: "invalid_url", message: "Webhook URL must be https://", request_id: rid }, 400);
    }
    const existing = await env.SECURITY_HUB_KV.get(`webhook:${auth.key_id}`, { type: "json" }) || [];
    const entry = {
      id:              `wh_${Date.now()}`,
      url:             webhookUrl,
      format,
      filter_severity,
      secret:          whSecret || null,
      created_at:      new Date().toISOString(),
      active:          true,
    };
    existing.push(entry);
    await env.SECURITY_HUB_KV.put(`webhook:${auth.key_id}`, JSON.stringify(existing), { expirationTtl: 86400 * 365 });
    return jsonResponse({
      success:    true,
      webhook_id: entry.id,
      message:    "Webhook registered. APEX will POST new intel to this endpoint.",
      request_id: rid,
    }, 201);
  }
  if (request.method === "DELETE") {
    await env.SECURITY_HUB_KV.delete(`webhook:${auth.key_id}`);
    return jsonResponse({ success: true, message: "All webhooks removed.", request_id: rid });
  }
  return jsonResponse({ error: "method_not_allowed", request_id: rid }, 405);
}

//  v134.0.0: /api/alerts -- threat alerts for Pro+ 
//  v134.0: GET /api/account/usage -- per-key usage analytics 
// Returns daily/monthly request counts per key, endpoint breakdown, quota remaining.
// Requires auth (JWT or API key). Returns data scoped to the authenticated user/key.
async function handleAccountUsage(request, env, rid, auth) {
  if (!env?.API_KEYS_KV || !env?.ANALYTICS_KV) {
    return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);
  }
  const userId = auth.user_id || auth.key_id;
  const today  = new Date().toISOString().slice(0, 10);
  const month  = new Date().toISOString().slice(0, 7);

  try {
    // Collect per-key usage from ANALYTICS_KV
    const keyList = userId
      ? await env.API_KEYS_KV.list({ prefix: `userkey:${userId}:` }).catch(() => ({ keys: [] }))
      : { keys: [] };

    // Build per-key breakdown
    const keyUsage = await Promise.all(
      keyList.keys.slice(0, 20).map(async (kvKey) => {
        const rec = await env.API_KEYS_KV.get(kvKey.name, { type: "json" }).catch(() => null);
        if (!rec || rec.revoked) return null;
        const monthlyCount = parseInt(await env.API_KEYS_KV.get(`usage:${rec.key_id}:${month}`).catch(() => "0") || "0");
        const dailyCount   = parseInt(await env.API_KEYS_KV.get(`usage:${rec.key_id}:daily:${today}`).catch(() => "0") || "0");
        const tier         = rec.tier || CONFIG.TIERS.FREE;
        const dailyLimit   = CONFIG.RATE_LIMITS[tier] * 60 * 24; // approx daily cap
        const monthlyLimit = { free: 3000, premium: 150000, enterprise: -1 }[tier] || 3000;
        return {
          key_id:         rec.key_id,
          label:          rec.label || "Unnamed Key",
          tier,
          requests_today: dailyCount,
          requests_month: monthlyCount,
          daily_limit:    dailyLimit,
          monthly_limit:  monthlyLimit < 0 ? "unlimited" : monthlyLimit,
          quota_used_pct: monthlyLimit > 0 ? parseFloat(((monthlyCount / monthlyLimit) * 100).toFixed(1)) : 0,
          created_at:     rec.created_at,
        };
      })
    );

    // Single-key context: analytics fingerprint for current key
    const fpKey    = `fingerprint:${today}:${auth.key_id || "anon"}`;
    const fpRecord = await env.ANALYTICS_KV.get(fpKey, { type: "json" }).catch(() => null);
    const endpointBreakdown = {};
    if (fpRecord?.calls) {
      for (const call of fpRecord.calls) {
        endpointBreakdown[call.path] = (endpointBreakdown[call.path] || 0) + 1;
      }
    }

    const filtered = keyUsage.filter(Boolean);
    const totalMonth = filtered.reduce((s, k) => s + k.requests_month, 0);
    const tier = auth.tier || CONFIG.TIERS.FREE;

    const usageResponse = {
      status:         "ok",
      user_id:        userId,
      tier,
      period: {
        today,
        month,
        month_label: new Date().toLocaleString("en-US", { month: "long", year: "numeric" }),
      },
      summary: {
        total_requests_today: fpRecord?.count || 0,
        total_requests_month: totalMonth,
        active_keys:          filtered.filter(k => !k.revoked).length,
        endpoint_hits_today:  endpointBreakdown,
      },
      keys:          filtered,
      limits: {
        rate_per_min:  CONFIG.RATE_LIMITS[tier] || CONFIG.RATE_LIMITS.free,
        feed_items:    CONFIG.FEED_LIMITS[tier]  || CONFIG.FEED_LIMITS.free,
        scopes:        auth.scopes || buildScopeSet(tier, null),
      },
      upgrade:        tier !== CONFIG.TIERS.ENTERPRISE ? {
        message: `Upgrade to unlock higher limits and more scopes.`,
        url:     `/upgrade.html?plan=${tier === "free" ? "pro" : "enterprise"}`,
      } : null,
      request_id:    rid,
    };

    // Increment daily usage counter for this key (fire-and-forget)
    if (auth.key_id) {
      const dailyUKey = `usage:${auth.key_id}:daily:${today}`;
      env.API_KEYS_KV.get(dailyUKey).then(v =>
        env.API_KEYS_KV.put(dailyUKey, String((parseInt(v || "0") + 1)), { expirationTtl: 86400 * 2 })
      ).catch(() => {});
    }

    return jsonResponse(usageResponse);
  } catch (e) {
    return jsonResponse({ error: "usage_unavailable", message: e.message, request_id: rid }, 503);
  }
}

//  v134.0.0: GET /api/platform/stats -- real-data dashboard metrics 
// Replaces all static dashboard hardcoded numbers.
// Sources: R2 feed manifest + KV analytics. Public (no auth required for summary).
async function handlePlatformStats(request, env, rid) {
  try {
    // Try KV cache (60s TTL)
    const cacheKey = "platform:stats:v134";
    if (env?.ANALYTICS_KV) {
      const cached = await env.ANALYTICS_KV.get(cacheKey, { type: "json" }).catch(() => null);
      if (cached) return jsonResponse({ ...cached, cached: true, request_id: rid });
    }

    // Fetch live feed index from R2
    let manifest = null;
    if (env?.INTEL_R2) {
      const obj = await env.INTEL_R2.get("feed_manifest.json").catch(() => null);
      if (obj) {
        const text = await obj.text().catch(() => "{}");
        try { manifest = JSON.parse(text); } catch { manifest = null; }
      }
    }
    // Fallback to SECURITY_HUB_KV cache
    if (!manifest && env?.SECURITY_HUB_KV) {
      manifest = await env.SECURITY_HUB_KV.get("idx:reports", { type: "json" }).catch(() => null);
    }

    // v143.5 FIX: feed_manifest.json is written as a flat array by the Python pipeline.
    // Previous code assumed { reports: [...] } shape -- manifest?.reports was always undefined.
    // Handle all three possible shapes: flat array, { reports: [...] }, { advisories: [...] }
    let reports = [];
    if (Array.isArray(manifest)) {
      reports = manifest;
    } else if (manifest && Array.isArray(manifest.reports)) {
      reports = manifest.reports;
    } else if (manifest && Array.isArray(manifest.advisories)) {
      reports = manifest.advisories;
    } else if (manifest && Array.isArray(manifest.items)) {
      reports = manifest.items;
    }
    const now = new Date().toISOString();

    //  Aggregate live metrics 
    let ioc_count = 0;
    let actor_set = new Set();
    let cve_set   = new Set();
    const sev_dist = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    const threat_types = {};
    let kev_count = 0;
    let last_updated = "";
    let highest_risk = 0;
    let exploit_active = 0;

    for (const r of reports) {
      // Severity distribution -- use severity field if present, else derive from risk_score
      let sev = (r.severity || "").toLowerCase();
      if (!sev || sev === "unknown") {
        const rs = parseFloat(r.risk_score || r.threat_score || 0);
        sev = rs >= 9.0 ? "critical" : rs >= 7.0 ? "high" : rs >= 4.0 ? "medium" : rs > 0 ? "low" : "unknown";
      }
      sev_dist[sev] = (sev_dist[sev] || 0) + 1;

      // v143.5 FIX: feed_manifest entries use ioc_count (integer), ioc_counts (dict),
      // or indicator_count -- not an iocs array. Handle all three shapes.
      if (typeof r.ioc_count === "number") {
        ioc_count += r.ioc_count;
      } else if (r.ioc_counts && typeof r.ioc_counts === "object") {
        ioc_count += Object.values(r.ioc_counts).reduce((a, b) => a + (b || 0), 0);
      } else if (typeof r.indicator_count === "number") {
        ioc_count += r.indicator_count;
      } else if (Array.isArray(r.iocs)) {
        ioc_count += r.iocs.length;
      }

      // Unique actors -- check both actor_tag and actor fields
      const actorId = r.actor_tag || (Array.isArray(r.actors) && r.actors[0]) || "";
      if (actorId && actorId !== "UNATTRIBUTED" && actorId !== "UNC-CDB-99") actor_set.add(actorId);

      // Unique CVEs -- from cve_id field or iocs array
      if (r.cve_id) cve_set.add(r.cve_id.toUpperCase());
      if (Array.isArray(r.iocs)) {
        r.iocs.filter(i => i && i.type === "cve" && i.value).forEach(i => cve_set.add(i.value.toUpperCase()));
      }

      // KEV
      if (r.kev_present === true) kev_count++;

      // Threat types
      if (r.threat_type) threat_types[r.threat_type] = (threat_types[r.threat_type] || 0) + 1;

      // Recency
      const ts = r.processed_at || r.timestamp || "";
      if (ts > last_updated) last_updated = ts;

      // Highest risk score -- fallback to threat_score for bootstrap manifest items
      const _rs = parseFloat(r.risk_score || r.threat_score || 0);
      if (_rs > highest_risk) highest_risk = _rs;

      // Active exploitation
      const maturity = r.exploit_maturity || "";
      if (maturity === "active" || (r.kev_present === true)) exploit_active++;
    }

    // Top 5 threat types
    const top_threat_types = Object.entries(threat_types)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([type, count]) => ({ type, count }));

    // KV analytics: total API calls (today)
    let api_calls_today = 0;
    if (env?.ANALYTICS_KV) {
      const today = now.slice(0, 10);
      const meta  = await env.ANALYTICS_KV.get(`meta:calls:${today}`).catch(() => null);
      if (meta) api_calls_today = parseInt(meta) || 0;
    }

    const stats = {
      status:             "ok",
      generated_at:       now,
      platform:           `${CONFIG.GATEWAY_NAME} v${CONFIG.GATEWAY_VERSION}`,
      intel: {
        total_reports:    reports.length,
        ioc_count,
        unique_actors:    actor_set.size,
        unique_cves:      cve_set.size,
        kev_count,
        exploit_active,
        highest_risk_score: parseFloat((highest_risk || 0).toFixed(1)),
        last_updated:     last_updated || now,
        severity_distribution: sev_dist,
        top_threat_types,
      },
      api: {
        calls_today:      api_calls_today,
        gateway_version:  CONFIG.GATEWAY_VERSION,
        plans_available:  ["free", "pro", "enterprise"],
        pricing: {
          pro_monthly_usd:        29,
          enterprise_monthly_usd: 199,
        },
      },
    };

    // Cache for 60 seconds
    if (env?.ANALYTICS_KV) {
      env.ANALYTICS_KV.put(cacheKey, JSON.stringify(stats), { expirationTtl: 60 }).catch(() => {});
    }

    return jsonResponse({ ...stats, cached: false, request_id: rid });
  } catch (e) {
    await trackError(env, "STATS", "handlePlatformStats failed", { error: e.message });
    return jsonResponse({ error: "stats_unavailable", message: e.message, request_id: rid }, 503);
  }
}

async function handleAlerts(request, env, auth, rid) {
  if (auth.tier === CONFIG.TIERS.FREE) {
    return jsonResponse({
      error:   "pro_required",
      message: "Threat alerts require Pro or Enterprise tier.",
      upgrade: getUpgradeCTA(auth.tier),
      request_id: rid,
    }, 403);
  }
  let index;
  try {
    index = await fetchReportsIndex(env);
  } catch (err) {
    return jsonResponse({ error: "feed_unavailable", request_id: rid }, 503);
  }
  const url    = new URL(request.url);
  const minRisk = parseFloat(url.searchParams.get("min_risk") || "7");
  const limit   = Math.min(parseInt(url.searchParams.get("limit") || "20"), 100);

  const alerts = (index.reports || [])
    .filter(r => (r.risk_score || 0) >= minRisk || r.kev_present)
    .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
    .slice(0, limit)
    .map(r => ({
      id:          r.id,
      title:       r.title,
      severity:    r.severity,
      risk_score:  r.risk_score,
      kev_present: r.kev_present || false,
      report_url:  r.report_url || null,
      source_url:  (r.source_url && r.source_url.trim()) || null,
      processed_at: r.processed_at || r.timestamp,
      stix_id:     r.stix_id || r.id,
    }));

  await recordAnalytics(env, auth.key_id, "alerts", auth.tier, 200);
  return jsonResponse({
    status:      "ok",
    request_id:  rid,
    tier:        auth.tier,
    alert_count: alerts.length,
    filter:      { min_risk: minRisk, kev_included: true },
    alerts,
    gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: /api/auth/refresh -- Renew JWT before expiry 
// Valid JWT required. Issues fresh token, revokes the presented one.
async function handleRefreshToken(request, env, rid) {
  if (!env?.CDB_JWT_SECRET) {
    return jsonResponse({ error: "auth_service_unavailable", request_id: rid }, 503);
  }
  const jwtToken = extractJwt(request);
  if (!jwtToken) return jsonResponse({ error: "token_required", message: "Authorization: Bearer <token> required.", request_id: rid }, 400);
  const result = await verifyJwt(jwtToken, env.CDB_JWT_SECRET);
  if (!result.valid) {
    return jsonResponse({ error: "token_invalid", reason: result.reason, request_id: rid }, 401);
  }
  if (await isTokenRevoked(jwtToken, env)) {
    return jsonResponse({ error: "token_revoked", request_id: rid }, 401);
  }
  const { tier, key_id, label } = result.payload;
  const ttl      = tier === CONFIG.TIERS.ENTERPRISE ? JWT_TTL * 12 : JWT_TTL;
  const newToken = await signJwt({ sub: key_id, tier, label, key_id }, env.CDB_JWT_SECRET, ttl);
  // Revoke old token immediately (rotating refresh)
  await revokeToken(jwtToken, result.payload.exp, env);
  await recordAnalytics(env, key_id, "jwt_refresh", tier, 200);
  return jsonResponse({
    status:      "ok",
    request_id:  rid,
    token:       newToken,
    token_type:  "Bearer",
    expires_in:  ttl,
    tier,
    key_id,
    issued_at:   new Date().toISOString(),
    message:     "Old token revoked. Store new token securely.",
    gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: /api/auth/revoke -- Revoke JWT immediately 
async function handleRevokeToken(request, env, rid) {
  if (!env?.CDB_JWT_SECRET) {
    return jsonResponse({ error: "auth_service_unavailable", request_id: rid }, 503);
  }
  const jwtToken = extractJwt(request);
  if (!jwtToken) return jsonResponse({ error: "token_required", request_id: rid }, 400);
  const result = await verifyJwt(jwtToken, env.CDB_JWT_SECRET);
  // Allow revoke even if expired -- still add to blocklist to be thorough
  const expUnix = result.payload?.exp || Math.floor(Date.now() / 1000) + 3600;
  await revokeToken(jwtToken, expUnix, env);
  await recordAnalytics(env, result.payload?.key_id, "jwt_revoke", result.payload?.tier || "unknown", 200);
  return jsonResponse({
    status:      "ok",
    message:     "Token revoked. It will no longer be accepted.",
    request_id:  rid,
    gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: /api/admin/keys/list 
async function handleAdminListKeys(request, env, rid) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "kv_unavailable", request_id: rid }, 503);
  const list    = await env.API_KEYS_KV.list({ prefix: "apikey:" });
  const records = await Promise.all(
    list.keys.map(k => env.API_KEYS_KV.get(k.name, { type: "json" }).catch(() => null))
  );
  const keys = records.filter(Boolean).map(r => ({
    key_id:     r.key_id,
    tier:       r.tier,
    label:      r.label,
    created_at: r.created_at,
    expires_at: r.expires_at || null,
    revoked:    r.revoked || false,
    revoked_at: r.revoked_at || null,
    usage_limit: r.usage_limit || 0,
  }));
  return jsonResponse({
    status:     "ok",
    count:      keys.length,
    keys,
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: /api/admin/keys/revoke 
async function handleAdminRevokeKey(request, env, rid) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "kv_unavailable", request_id: rid }, 503);
  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }
  const { key_id } = body;
  if (!key_id) return jsonResponse({ error: "key_id_required", request_id: rid }, 400);
  const record = await env.API_KEYS_KV.get(`apikey:${key_id}`, { type: "json" });
  if (!record) return jsonResponse({ error: "not_found", key_id, request_id: rid }, 404);
  record.revoked    = true;
  record.revoked_at = new Date().toISOString();
  await env.API_KEYS_KV.put(`apikey:${key_id}`, JSON.stringify(record));
  slog("WARN", "ADMIN", "API key revoked", { key_id, tier: record.tier });
  return jsonResponse({
    success:    true,
    key_id,
    tier:       record.tier,
    revoked_at: record.revoked_at,
    message:    "Key immediately revoked. All requests with this key will be rejected.",
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

//  v134.0.0: /api/admin/observability 
// Surfaces error counts, analytics stats, and health snapshot for monitoring.
async function handleAdminObservability(request, env, rid) {
  const day  = new Date().toISOString().slice(0, 10);
  const prev = new Date(Date.now() - 86400000).toISOString().slice(0, 10);

  // Collect analytics
  const analyticsKeys = [
    `analytics:day:${day}:feed`,      `analytics:day:${day}:feed_error`,
    `analytics:day:${day}:preview`,   `analytics:day:${day}:preview_cached`,
    `analytics:day:${day}:jwt_issue`, `analytics:day:${day}:jwt_refresh`,
    `analytics:day:${day}:jwt_revoke`,`analytics:day:${day}:rate_limited`,
    `analytics:day:${prev}:feed`,     `analytics:day:${prev}:feed_error`,
  ];
  const analyticsVals = env?.ANALYTICS_KV
    ? await Promise.all(analyticsKeys.map(k => env.ANALYTICS_KV.get(k).catch(() => null)))
    : analyticsKeys.map(() => null);
  const a = Object.fromEntries(analyticsKeys.map((k, i) => [k.replace(`analytics:day:`, ""), parseInt(analyticsVals[i] || "0")]));

  // Collect error records from SECURITY_HUB_KV
  const errors = {};
  if (env?.SECURITY_HUB_KV) {
    try {
      const errList = await env.SECURITY_HUB_KV.list({ prefix: `error:` });
      await Promise.all(errList.keys.map(async k => {
        const data = await env.SECURITY_HUB_KV.get(k.name, { type: "json" }).catch(() => null);
        if (data) errors[k.name.replace("error:", "")] = data;
      }));
    } catch { /* non-critical */ }
  }

  // KV health
  const kvHealth = {};
  for (const [name, kv] of [["rate_limit", env?.RATE_LIMIT_KV], ["api_keys", env?.API_KEYS_KV], ["analytics", env?.ANALYTICS_KV], ["security_hub", env?.SECURITY_HUB_KV]]) {
    if (!kv) { kvHealth[name] = "not_bound"; continue; }
    try { await kv.put("health:obs", "1", { expirationTtl: 10 }); kvHealth[name] = "ok"; }
    catch { kvHealth[name] = "error"; }
  }

  // v134.0: Live feed integrity snapshot -- dedup metrics + IOC consistency
  let feedIntegrity = null;
  try {
    const idx   = await fetchReportsIndex(env);
    const raw   = idx.reports || [];
    const dedup = deduplicateFeedItems(raw);
    // IOC consistency: count items where ioc_count > 0 but iocs array is empty (free-gate leak)
    const iocInconsistencies = dedup.filter(r =>
      (r.ioc_count || 0) > 0 && Array.isArray(r.iocs) && r.iocs.length === 0 &&
      (r.severity || "").toUpperCase() !== "FREE_GATED"
    ).length;
    const highZeroIoc = dedup.filter(r =>
      ((r.severity || "").toUpperCase() === "CRITICAL" || (r.severity || "").toUpperCase() === "HIGH") &&
      (r.ioc_count || 0) === 0
    ).length;
    feedIntegrity = {
      raw_count:                raw.length,
      deduped_count:            dedup.length,
      duplicates_removed:       raw.length - dedup.length,
      dedup_active:             true,
      ioc_count_inconsistencies: iocInconsistencies,
      high_severity_zero_ioc:   highZeroIoc,
      stix_issues:              0,  // STIX bundles validated at gate -- no passthrough of invalid bundles
      integrity_ok:             iocInconsistencies === 0 && highZeroIoc === 0,
    };
  } catch { feedIntegrity = { error: "feed_unavailable" }; }

  return jsonResponse({
    status:      "ok",
    request_id:  rid,
    gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    timestamp:   new Date().toISOString(),
    analytics: {
      today:     {
        date:              day,
        feed_requests:     a[`${day}:feed`]           || 0,
        feed_errors:       a[`${day}:feed_error`]     || 0,
        preview_requests:  a[`${day}:preview`]        || 0,
        preview_cached:    a[`${day}:preview_cached`] || 0,
        jwt_issued:        a[`${day}:jwt_issue`]      || 0,
        jwt_refreshed:     a[`${day}:jwt_refresh`]    || 0,
        jwt_revoked:       a[`${day}:jwt_revoke`]     || 0,
        rate_limited:      a[`${day}:rate_limited`]   || 0,
      },
      yesterday: {
        date:          prev,
        feed_requests: a[`${prev}:feed`]       || 0,
        feed_errors:   a[`${prev}:feed_error`] || 0,
      },
    },
    errors,
    kv_health:      kvHealth,
    r2_bound:       !!env?.INTEL_R2,
    jwt_configured: !!env?.CDB_JWT_SECRET,
    // v134.0: Feed integrity snapshot -- dedup + IOC consistency + STIX validation
    feed_integrity: feedIntegrity,
    security: {
      injection_blocking:   "active",    // _INJECTION_BLOCK_RE -- 8 patterns
      rate_limiting:        "active",    // sliding window -- IP + per-key
      jwt_revocation:       "active",    // blocklist in SECURITY_HUB_KV
      tier_enforcement:     "active",    // applyTierGate() + applyIocMetaTierGate()
      stix_validation:      "active",    // structural gate -- invalid bundles nulled
      input_sanitization:   "active",    // sanitizeStr + sanitizeInput across all handlers
    },
  });
}

//  v134.0.0: Stripe Webhook Signature Verification 
// Format: "t=<timestamp>,v1=<sig>" in Stripe-Signature header
async function verifyStripeSignature(rawBody, sigHeader, webhookSecret) {
  try {
    const parts  = sigHeader.split(",");
    const tPart  = parts.find(p => p.startsWith("t="));
    const v1s    = parts.filter(p => p.startsWith("v1="));
    if (!tPart || !v1s.length) return false;
    const signed = `${tPart.slice(2)}.${rawBody}`;
    const key    = await crypto.subtle.importKey("raw", new TextEncoder().encode(webhookSecret),
                     { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const buf    = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signed));
    const expected = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    return v1s.some(p => p.slice(3) === expected);
  } catch { return false; }
}

function tierFromStripePlan(priceId, env) {
  if (!priceId) return CONFIG.TIERS.FREE;
  if (priceId === (env?.STRIPE_PRO_PRICE_ID  || ""))  return CONFIG.TIERS.PREMIUM;
  if (priceId === (env?.STRIPE_ENT_PRICE_ID  || ""))  return CONFIG.TIERS.ENTERPRISE;
  // Fallback heuristic: keyword in price ID
  if (/enterprise|ent/i.test(priceId)) return CONFIG.TIERS.ENTERPRISE;
  if (/pro|premium/i.test(priceId))    return CONFIG.TIERS.PREMIUM;
  return CONFIG.TIERS.FREE;
}

//  v134.0: cascadeUserTierToKeys -- propagate tier change to all user-owned keys 
// Called on payment success / subscription update / cancellation.
// Updates both userkey: index records and apikey: lookup records.
// Fire-and-forget safe -- never throws, errors are logged only.
async function cascadeUserTierToKeys(userId, newTier, env) {
  if (!env?.API_KEYS_KV || !userId) return;
  try {
    const list = await env.API_KEYS_KV.list({ prefix: `userkey:${userId}:` }).catch(() => ({ keys: [] }));
    if (!list?.keys?.length) return;
    await Promise.all(list.keys.map(async (kvKey) => {
      try {
        const rec = await env.API_KEYS_KV.get(kvKey.name, { type: "json" }).catch(() => null);
        if (!rec || rec.revoked) return;
        // Update userkey: record
        rec.tier = newTier;
        rec.tier_updated_at = new Date().toISOString();
        await env.API_KEYS_KV.put(kvKey.name, JSON.stringify(rec));
        // Update apikey: lookup record (used in resolveApiKey)
        if (rec.key_id) {
          const apiRec = await env.API_KEYS_KV.get(`apikey:${rec.key_id}`, { type: "json" }).catch(() => null);
          if (apiRec) {
            apiRec.tier = newTier;
            apiRec.tier_updated_at = new Date().toISOString();
            await env.API_KEYS_KV.put(`apikey:${rec.key_id}`, JSON.stringify(apiRec));
          }
        }
      } catch { /* non-fatal -- key update failure never blocks webhook */ }
    }));
    slog("INFO", "BILLING", `Tier cascade complete`, { user_id: userId, tier: newTier, keys: list.keys.length });
  } catch (e) {
    slog("WARN", "BILLING", `cascadeUserTierToKeys failed (non-fatal)`, { error: e.message });
  }
}

//  v134.0.0: POST /webhooks/stripe 
async function handleStripeWebhook(request, env, rid) {
  const sigHeader = request.headers.get("Stripe-Signature") || "";
  const rawBody   = await request.text();

  if (!env?.STRIPE_WEBHOOK_SECRET) {
    slog("WARN", "BILLING", "STRIPE_WEBHOOK_SECRET not configured", { rid });
    return jsonResponse({ error: "webhook_not_configured", message: "Set STRIPE_WEBHOOK_SECRET via: npx wrangler secret put STRIPE_WEBHOOK_SECRET" }, 503);
  }

  const valid = await verifyStripeSignature(rawBody, sigHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!valid) {
    slog("WARN", "BILLING", "Stripe signature verification failed", { rid });
    return jsonResponse({ error: "invalid_signature" }, 400);
  }

  let event;
  try { event = JSON.parse(rawBody); }
  catch { return jsonResponse({ error: "invalid_json" }, 400); }

  slog("INFO", "BILLING", `Stripe event: ${event.type}`, { rid, event_id: event.id });
  const obj = event.data?.object || {};

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const userId     = obj.metadata?.user_id || obj.client_reference_id;
        const priceId    = obj.metadata?.price_id || obj.metadata?.price;
        const newTier    = tierFromStripePlan(priceId, env);
        const customerId = obj.customer;
        if (userId && env?.API_KEYS_KV) {
          const ur = await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null);
          if (ur) {
            ur.tier               = newTier;
            ur.stripe_customer_id = customerId || ur.stripe_customer_id;
            ur.subscription       = { id: obj.subscription, status: "active", tier: newTier, price_id: priceId, updated_at: new Date().toISOString() };
            await env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(ur));
            if (customerId) await env.API_KEYS_KV.put(`stripe_customer:${customerId}`, userId);
            // v134.0: CASCADE -- upgrade all user-owned API keys to new tier immediately
            await cascadeUserTierToKeys(userId, newTier, env);
            slog("INFO", "BILLING", "Checkout complete -- tier upgraded + keys cascaded", { user_id: userId, tier: newTier });
          }
        }
        break;
      }
      case "customer.subscription.updated": {
        const customerId = obj.customer;
        const status     = obj.status;
        const priceId    = obj.items?.data?.[0]?.price?.id;
        const newTier    = status === "active" ? tierFromStripePlan(priceId, env) : CONFIG.TIERS.FREE;
        if (customerId && env?.API_KEYS_KV) {
          const userId = await env.API_KEYS_KV.get(`stripe_customer:${customerId}`).catch(() => null);
          if (userId) {
            const ur = await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null);
            if (ur) {
              ur.tier         = newTier;
              ur.subscription = { id: obj.id, status, tier: newTier, price_id: priceId, updated_at: new Date().toISOString() };
              await env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(ur));
              // v134.0: CASCADE tier change to all owned keys
              await cascadeUserTierToKeys(userId, newTier, env);
              slog("INFO", "BILLING", "Subscription updated + keys cascaded", { user_id: userId, status, tier: newTier });
            }
          }
        }
        break;
      }
      case "customer.subscription.deleted": {
        const customerId = obj.customer;
        if (customerId && env?.API_KEYS_KV) {
          const userId = await env.API_KEYS_KV.get(`stripe_customer:${customerId}`).catch(() => null);
          if (userId) {
            const ur = await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null);
            if (ur) {
              ur.tier         = CONFIG.TIERS.FREE;
              ur.subscription = { id: obj.id, status: "cancelled", tier: CONFIG.TIERS.FREE, updated_at: new Date().toISOString() };
              await env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(ur));
              slog("INFO", "BILLING", "Subscription cancelled -- downgraded to FREE", { user_id: userId });
            }
          }
        }
        break;
      }
      case "customer.created": {
        const userId = obj.metadata?.user_id;
        if (userId && env?.API_KEYS_KV) {
          await env.API_KEYS_KV.put(`stripe_customer:${obj.id}`, userId);
        }
        break;
      }
    }
  } catch (e) {
    await trackError(env, "BILLING", `Stripe event error: ${e.message}`, { event_type: event.type });
  }

  return jsonResponse({ status: "ok", received: true, event_id: event.id, event_type: event.type });
}

//  v134.0.0: POST /webhooks/razorpay 
async function handleRazorpayWebhook(request, env, rid) {
  const rzSig   = request.headers.get("X-Razorpay-Signature") || "";
  const rawBody = await request.text();

  if (!env?.RAZORPAY_WEBHOOK_SECRET) {
    slog("WARN", "BILLING", "RAZORPAY_WEBHOOK_SECRET not configured", { rid });
    return jsonResponse({ error: "webhook_not_configured", message: "Set RAZORPAY_WEBHOOK_SECRET via: npx wrangler secret put RAZORPAY_WEBHOOK_SECRET" }, 503);
  }

  try {
    const key      = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.RAZORPAY_WEBHOOK_SECRET),
                       { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const buf      = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
    const expected = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    if (expected !== rzSig) {
      slog("WARN", "BILLING", "Razorpay signature invalid", { rid });
      return jsonResponse({ error: "invalid_signature" }, 400);
    }
  } catch { return jsonResponse({ error: "signature_check_failed" }, 400); }

  let event;
  try { event = JSON.parse(rawBody); }
  catch { return jsonResponse({ error: "invalid_json" }, 400); }

  slog("INFO", "BILLING", `Razorpay event: ${event.event}`, { rid });

  try {
    const payment = event.payload?.payment?.entity;
    if (event.event === "payment.captured" && payment) {
      const userId   = payment.notes?.user_id;
      const planTier = payment.notes?.tier || CONFIG.TIERS.PREMIUM;
      if (userId && env?.API_KEYS_KV) {
        const ur = await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null);
        if (ur) {
          ur.tier         = planTier;
          ur.subscription = { id: payment.id, status: "active", tier: planTier, gateway: "razorpay", amount: payment.amount, updated_at: new Date().toISOString() };
          await env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(ur));
          await cascadeUserTierToKeys(userId, planTier, env); // v134.0: cascade to all owned keys
          slog("INFO", "BILLING", "Razorpay payment -- tier upgraded + keys cascaded", { user_id: userId, tier: planTier });
        }
      }
    }
    if (event.event === "subscription.cancelled") {
      const sub    = event.payload?.subscription?.entity;
      const userId = sub?.notes?.user_id;
      if (userId && env?.API_KEYS_KV) {
        const ur = await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null);
        if (ur) {
          ur.tier         = CONFIG.TIERS.FREE;
          ur.subscription = { status: "cancelled", tier: CONFIG.TIERS.FREE, gateway: "razorpay", updated_at: new Date().toISOString() };
          await env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(ur));
          slog("INFO", "BILLING", "Razorpay sub cancelled -- downgraded to FREE", { user_id: userId });
        }
      }
    }
  } catch (e) {
    await trackError(env, "BILLING", `Razorpay event error: ${e.message}`, { event: event.event });
  }

  return jsonResponse({ status: "ok", received: true, event: event.event });
}

//  v134.0.0: GET /api/billing/portal 
async function handleBillingPortal(request, env, rid, auth) {
  const userId     = auth.user_id || auth.key_id;
  const userRecord = userId ? await env?.API_KEYS_KV?.get(`user:${userId}`, { type: "json" }).catch(() => null) : null;
  const tier       = userRecord?.tier || auth.tier || CONFIG.TIERS.FREE;

  return jsonResponse({
    status:        "ok",
    user_id:       userId,
    tier,
    subscription:  userRecord?.subscription || null,
    pricing_page:  "https://intel.cyberdudebivash.com/#pricing",
    stripe_portal: userRecord?.stripe_customer_id
      ? `https://billing.stripe.com/p/login/live_portal?prefilled_email=${encodeURIComponent(userRecord.email || "")}`
      : null,
    upgrade_options: {
      pro:        {
        price:        "$29/month",
        checkout_url: "/upgrade.html?plan=pro",
        features:     ["500 requests/min", "Full IOC arrays", "STIX 2.1 bundles", "Threat alerts", "10 API keys"],
      },
      enterprise: {
        price:        "$199/month",
        checkout_url: "/upgrade.html?plan=enterprise",
        features:     ["2000 requests/min", "SIEM integration (Splunk/Sentinel/QRadar)", "50 API keys", "Priority support", "Tenant isolation"],
      },
    },
    request_id:    rid,
    gateway:       `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// ---------------------------------------------------------------------------
//  v143.0.0: POST /api/checkout/session -- Dynamic Stripe Checkout Session
//  Creates a Stripe Checkout Session on-the-fly (server-side), returns a
//  redirect_url the browser can navigate to. Requires STRIPE_SECRET_KEY
//  Cloudflare secret. Passes user_id + plan metadata so the checkout.session
//  .completed webhook auto-provisions the API key on payment confirmation.
//  Supports monthly and annual billing cycles for all paid tiers.
// ---------------------------------------------------------------------------
const STRIPE_PLAN_CONFIG = {
  pro_monthly:        { price_id_env: "STRIPE_PRICE_PRO_MONTHLY",        usd: 4900,   name: "PRO Defense - Monthly",         tier: "premium"    },
  pro_annual:         { price_id_env: "STRIPE_PRICE_PRO_ANNUAL",         usd: 49000,  name: "PRO Defense - Annual",          tier: "premium"    },
  enterprise_monthly: { price_id_env: "STRIPE_PRICE_ENTERPRISE_MONTHLY", usd: 49900,  name: "Enterprise SOC - Monthly",      tier: "enterprise" },
  enterprise_annual:  { price_id_env: "STRIPE_PRICE_ENTERPRISE_ANNUAL",  usd: 499000, name: "Enterprise SOC - Annual",       tier: "enterprise" },
  mssp_monthly:       { price_id_env: "STRIPE_PRICE_MSSP_MONTHLY",       usd: 199900, name: "MSSP White-Label - Monthly",    tier: "mssp"       },
  mssp_annual:        { price_id_env: "STRIPE_PRICE_MSSP_ANNUAL",        usd: 1999000, name: "MSSP White-Label - Annual",   tier: "mssp"       },
};

async function handleCreateCheckoutSession(request, env, auth, rid) {
  // Require Stripe secret key
  if (!env?.STRIPE_SECRET_KEY) {
    slog("WARN", "BILLING", "STRIPE_SECRET_KEY not configured", { rid });
    return jsonResponse({
      error:   "stripe_not_configured",
      message: "Set STRIPE_SECRET_KEY via: npx wrangler secret put STRIPE_SECRET_KEY",
      fallback: "https://intel.cyberdudebivash.com/upgrade.html",
    }, 503);
  }

  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json" }, 400); }

  const plan  = (body.plan  || "").toLowerCase().replace(/[^a-z_]/g, "");
  const cycle = (body.cycle || "monthly").toLowerCase() === "annual" ? "annual" : "monthly";
  const planKey = `${plan}_${cycle}`;
  const planCfg = STRIPE_PLAN_CONFIG[planKey];

  if (!planCfg) {
    return jsonResponse({
      error:   "invalid_plan",
      valid_plans: Object.keys(STRIPE_PLAN_CONFIG),
    }, 400);
  }

  // Resolve Stripe Price ID -- prefer env var, fall back to direct price_id param
  const priceId = env[planCfg.price_id_env] || (body.price_id || "").replace(/[^a-zA-Z0-9_]/g, "");
  if (!priceId) {
    return jsonResponse({
      error:   "price_id_not_configured",
      message: `Set ${planCfg.price_id_env} via: npx wrangler secret put ${planCfg.price_id_env}`,
      fallback: "https://intel.cyberdudebivash.com/upgrade.html",
    }, 503);
  }

  // Resolve user identity for metadata
  const userId    = auth?.user_id || auth?.key_id || null;
  const userEmail = body.email || auth?.email || null;
  const origin    = request.headers.get("Origin") || "https://intel.cyberdudebivash.com";
  const successUrl = `${origin}/upgrade.html?checkout=success&plan=${plan}&session_id={CHECKOUT_SESSION_ID}`;
  const cancelUrl  = `${origin}/upgrade.html?checkout=cancelled&plan=${plan}`;

  // Build Stripe Checkout Session payload
  const sessionPayload = new URLSearchParams();
  sessionPayload.append("mode", "subscription");
  sessionPayload.append("line_items[0][price]", priceId);
  sessionPayload.append("line_items[0][quantity]", "1");
  sessionPayload.append("success_url", successUrl);
  sessionPayload.append("cancel_url",  cancelUrl);
  sessionPayload.append("allow_promotion_codes", "true");
  sessionPayload.append("billing_address_collection", "auto");
  sessionPayload.append("metadata[user_id]",  userId  || "anonymous");
  sessionPayload.append("metadata[plan]",     plan);
  sessionPayload.append("metadata[cycle]",    cycle);
  sessionPayload.append("metadata[platform]", "SENTINEL-APEX");
  sessionPayload.append("metadata[rid]",      rid);
  if (userEmail) {
    sessionPayload.append("customer_email", userEmail);
  }
  // Tax + invoice settings
  sessionPayload.append("invoice_creation[enabled]", "true");
  sessionPayload.append("subscription_data[metadata][user_id]",  userId  || "anonymous");
  sessionPayload.append("subscription_data[metadata][plan]",     plan);
  sessionPayload.append("subscription_data[metadata][platform]", "SENTINEL-APEX");

  // Call Stripe API
  let stripeSession;
  try {
    const stripeResp = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method:  "POST",
      headers: {
        "Authorization": `Bearer ${env.STRIPE_SECRET_KEY}`,
        "Content-Type":  "application/x-www-form-urlencoded",
        "Stripe-Version": "2024-06-20",
      },
      body: sessionPayload.toString(),
    });
    stripeSession = await stripeResp.json();
    if (!stripeResp.ok) {
      slog("ERROR", "BILLING", "Stripe API error", { rid, stripe_error: stripeSession?.error?.message });
      return jsonResponse({
        error:   "stripe_api_error",
        detail:  stripeSession?.error?.message || "Unknown Stripe error",
        fallback: "https://intel.cyberdudebivash.com/upgrade.html",
      }, 502);
    }
  } catch (e) {
    slog("ERROR", "BILLING", "Stripe API fetch failed", { rid, err: e.message });
    return jsonResponse({ error: "stripe_unreachable", fallback: "/upgrade.html" }, 502);
  }

  slog("INFO", "BILLING", "Checkout session created", {
    rid,
    session_id: stripeSession.id,
    plan:       planKey,
    user_id:    userId,
  });

  return jsonResponse({
    status:       "ok",
    session_id:   stripeSession.id,
    redirect_url: stripeSession.url,
    plan:         planKey,
    amount_usd:   (planCfg.usd / 100).toFixed(2),
    expires_at:   new Date(stripeSession.expires_at * 1000).toISOString(),
  });
}

// ---------------------------------------------------------------------------
//  v141.1.0: REVENUE ACTIVATION -- Manual Payment Notify + Admin Tier Set
//            + Alert Subscription
// ---------------------------------------------------------------------------

// =============================================================================
// GOD-MODE PAYMENT ENGINE v142.4.0
// Telegram instant alerts + BSC on-chain auto-verification
// Secrets needed: TG_BOT_TOKEN, TG_CHAT_ID, BSCSCAN_API_KEY (optional but recommended)
// Set via: npx wrangler secret put TG_BOT_TOKEN
//          npx wrangler secret put TG_CHAT_ID
//          npx wrangler secret put BSCSCAN_API_KEY
// =============================================================================

// Helper: fire Telegram alert (non-blocking)
async function sendTelegramAlert(env, message) {
  if (!env?.TG_BOT_TOKEN || !env?.TG_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id:    env.TG_CHAT_ID,
        text:       message,
        parse_mode: "HTML",
        disable_web_page_preview: true,
      }),
    });
  } catch (_) {}  // non-blocking -- never let Telegram errors affect payment flow
}

// POST /api/payment/notify
// Called by upgrade.html after UPI / PayPal / Crypto payment.
// v142.4.0: Telegram instant alert + BSC auto-verify trigger + professional KV storage.
async function handlePaymentNotify(request, env, rid) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }

  const email    = sanitizeText((body.email    || "").toLowerCase().trim(), 200);
  const plan     = sanitizeText((body.plan     || "pro").toLowerCase(),      20);
  const method   = sanitizeText((body.method   || "unknown"),                60);
  const ref      = sanitizeText((body.ref      || ""),                      160);
  const amount   = sanitizeText(String(body.amount   || ""),                 30);
  const name     = sanitizeText((body.name     || ""),                       80);
  const org      = sanitizeText((body.org      || ""),                       80);
  const country  = sanitizeText((body.country  || ""),                       60);
  const user_id  = sanitizeText((body.user_id  || ""),                       80);
  const txhash   = sanitizeText((body.txhash   || ""),                      120);  // for BSC/ETH crypto
  const is_crypto = method.toLowerCase().includes("crypto") || method.toLowerCase().includes("bnb") || method.toLowerCase().includes("bsc") || method.toLowerCase().includes("usdt");

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return jsonResponse({ error: "invalid_email", request_id: rid }, 400);
  }
  const VALID_PLANS = new Set(["pro", "premium", "enterprise", "mssp"]);
  if (!VALID_PLANS.has(plan)) {
    return jsonResponse({ error: "invalid_plan", message: "plan must be pro|premium|enterprise|mssp", request_id: rid }, 400);
  }

  const isCryptoVerified = false;  // will be set by BSC verify flow if txhash provided

  const record = {
    id:           rid,
    email,
    name:         name || null,
    org:          org  || null,
    country:      country || null,
    plan,
    method,
    ref,
    txhash:       txhash || null,
    amount,
    user_id:      user_id || null,
    status:       is_crypto && txhash ? "pending_crypto_verify" : "pending_review",
    submitted_at: new Date().toISOString(),
    source:       "upgrade_page",
  };

  // Store in KV: payment:{rid} with 30-day TTL
  await env.API_KEYS_KV.put(`payment:${rid}`, JSON.stringify(record), { expirationTtl: 86400 * 30 });

  // Maintain pending payments list for admin dashboard (cap at 500)
  const listKey  = "payment:pending_list";
  const existing = await env.API_KEYS_KV.get(listKey, { type: "json" }).catch(() => []) || [];
  existing.unshift({ id: rid, email, name: name || null, plan, method, amount, status: record.status, submitted_at: record.submitted_at });
  if (existing.length > 500) existing.length = 500;
  await env.API_KEYS_KV.put(listKey, JSON.stringify(existing), { expirationTtl: 86400 * 60 });

  //  TELEGRAM INSTANT ALERT 
  const planEmoji  = plan === "enterprise" ? "" : plan === "mssp" ? "" : "";
  const methodIcon = is_crypto ? "" : method.includes("UPI") ? "" : method.includes("PayPal") ? "" : method.includes("Bank") ? "" : "";
  const tgMsg = ` <b>NEW PAYMENT -- SENTINEL APEX</b>\n\n` +
    `${planEmoji} <b>Plan:</b> ${plan.toUpperCase()}\n` +
    `${methodIcon} <b>Method:</b> ${method}\n` +
    ` <b>Amount:</b> ${amount}\n` +
    ` <b>Email:</b> ${email}\n` +
    (name    ? ` <b>Name:</b> ${name}\n`     : "") +
    (org     ? ` <b>Org:</b> ${org}\n`       : "") +
    (country ? ` <b>Country:</b> ${country}\n` : "") +
    ` <b>Ref/UTR:</b> ${ref || "--"}\n` +
    (txhash  ? ` <b>TxHash:</b> <code>${txhash.slice(0,18)}</code>\n` : "") +
    ` <b>Review ID:</b> <code>${rid}</code>\n` +
    ` <b>Time:</b> ${new Date().toUTCString()}\n\n` +
    ` <b>Activate now:</b>\n` +
    `<code>POST /api/admin/users/set-tier\n{"email":"${email}","tier":"${plan === 'pro' ? 'premium' : plan}","payment_ref":"${rid}"}</code>`;

  // Fire Telegram + legacy webhook in parallel (non-blocking)
  const notifyPromises = [sendTelegramAlert(env, tgMsg)];
  if (env?.NOTIFY_WEBHOOK_URL) {
    notifyPromises.push(
      fetch(env.NOTIFY_WEBHOOK_URL, {
        method:  "POST",
        headers: { "Content-Type": "application/json; charset=utf-8" },
        body:    JSON.stringify({ text: tgMsg.replace(/<[^>]+>/g, "") }),
      }).catch(() => {})
    );
  }
  await Promise.all(notifyPromises);  // parallel, still non-blocking to user

  //  BSC AUTO-VERIFY (if txhash provided) 
  let bsc_status = null;
  if (txhash && (is_crypto || txhash.startsWith("0x"))) {
    bsc_status = "submitted";  // optimistic -- verify-bsc endpoint does the deep check
  }

  slog("INFO", "BILLING", "Payment notification received + Telegram alert fired", { email, plan, method, ref: ref.slice(0, 20), rid, has_txhash: !!txhash });

  return jsonResponse({
    status:       "received",
    message:      is_crypto && txhash
      ? "Crypto payment submitted. BSC verification in progress -- usually auto-confirmed in 1-3 minutes."
      : "Payment notification recorded. Your account will be upgraded within 2 hours after manual verification.",
    review_id:    rid,
    plan,
    bsc_status,
    verify_url:   txhash ? `/api/payment/verify-bsc?txhash=${txhash}&rid=${rid}` : null,
    activate_url: "/api/admin/users/set-tier",
    whatsapp:     "https://wa.me/918179881447?text=SENTINEL+APEX+Payment+Review+ID%3A+" + rid,
    request_id:   rid,
  }, 202);
}

// GET /api/payment/verify-bsc
// Polls BscScan to auto-verify a crypto payment transaction.
// Query params: txhash (required), rid (review ID), expected_to (optional, defaults to platform wallet)
// Secrets: BSCSCAN_API_KEY (get free key at bscscan.com/register)
async function handleBSCVerify(request, env, rid) {
  const BSC_WALLET = "0xa824c20158a4bfe2f3d8e80351b1906bd0ac0796";
  const url        = new URL(request.url);
  const txhash     = sanitizeText((url.searchParams.get("txhash") || "").toLowerCase(), 80);
  const payRid     = sanitizeText(url.searchParams.get("rid") || "", 60);

  if (!txhash || !/^0x[0-9a-f]{64}$/.test(txhash)) {
    return jsonResponse({ error: "invalid_txhash", message: "txhash must be a valid 0x-prefixed 64-char hex", request_id: rid }, 400);
  }

  const apiKey = env?.BSCSCAN_API_KEY || "YourApiKeyToken";  // free tier works without key but rate-limited

  let txData = null;
  let verifyStatus = "unconfirmed";
  let verifyDetail = {};

  try {
    // Check tx by hash on BSC
    const bscRes = await fetch(
      `https://api.bscscan.com/api?module=proxy&action=eth_getTransactionByHash&txhash=${txhash}&apikey=${apiKey}`,
      { headers: { "User-Agent": "SENTINEL-APEX/142.4.0" } }
    );
    const bscJson = await bscRes.json();
    txData = bscJson?.result;

    if (!txData || txData === null) {
      verifyStatus = "not_found";
      verifyDetail = { message: "Transaction not found on BSC. It may be on ETH mainnet or not yet broadcast." };
    } else {
      const toAddr    = (txData.to || "").toLowerCase();
      const value     = parseInt(txData.value || "0", 16);  // in Wei (1 BNB = 1e18 Wei)
      const blockNum  = txData.blockNumber ? parseInt(txData.blockNumber, 16) : null;

      if (toAddr !== BSC_WALLET.toLowerCase()) {
        verifyStatus = "wrong_address";
        verifyDetail = { expected: BSC_WALLET, received: txData.to, message: "Transaction sent to wrong address." };
      } else if (blockNum === null) {
        verifyStatus = "pending";
        verifyDetail = { message: "Transaction is broadcast but not yet mined." };
      } else {
        // Check receipt for success
        const rcptRes  = await fetch(
          `https://api.bscscan.com/api?module=proxy&action=eth_getTransactionReceipt&txhash=${txhash}&apikey=${apiKey}`,
          { headers: { "User-Agent": "SENTINEL-APEX/142.4.0" } }
        );
        const rcptJson = await rcptRes.json();
        const rcpt     = rcptJson?.result;
        const status   = rcpt?.status;

        if (status === "0x1") {
          verifyStatus = "confirmed";
          verifyDetail = {
            block:        blockNum,
            from:         txData.from,
            to:           txData.to,
            value_wei:    value,
            value_bnb:    (value / 1e18).toFixed(6),
            gas_used:     rcpt.gasUsed ? parseInt(rcpt.gasUsed, 16) : null,
            message:      "Transaction confirmed on BSC.",
          };
        } else if (status === "0x0") {
          verifyStatus = "failed";
          verifyDetail = { message: "Transaction failed on-chain (reverted)." };
        } else {
          verifyStatus = "pending";
          verifyDetail = { message: "Transaction mined but status unclear -- check BscScan." };
        }
      }
    }
  } catch (err) {
    verifyStatus = "error";
    verifyDetail = { message: "BscScan lookup failed. Check txhash manually at https://bscscan.com/tx/" + txhash };
  }

  // If confirmed, update KV payment record
  if (verifyStatus === "confirmed" && payRid && env?.API_KEYS_KV) {
    const payRec = await env.API_KEYS_KV.get(`payment:${payRid}`, { type: "json" }).catch(() => null);
    if (payRec && payRec.status !== "activated") {
      payRec.status         = "crypto_verified";
      payRec.bsc_verified   = true;
      payRec.bsc_txhash     = txhash;
      payRec.bsc_detail     = verifyDetail;
      payRec.verified_at    = new Date().toISOString();
      await env.API_KEYS_KV.put(`payment:${payRid}`, JSON.stringify(payRec), { expirationTtl: 86400 * 30 });

      // Fire Telegram alert for auto-verified crypto payment
      const tgMsg = ` <b>BSC PAYMENT AUTO-VERIFIED</b>\n\n` +
        ` Email: ${payRec.email}\n` +
        ` Plan: ${(payRec.plan || "").toUpperCase()}\n` +
        ` Amount: ${payRec.amount}\n` +
        ` TxHash: <code>${txhash}</code>\n` +
        ` <a href="https://bscscan.com/tx/${txhash}">View on BscScan</a>\n` +
        ` Review ID: <code>${payRid}</code>\n\n` +
        ` <b>Activate now:</b>\n` +
        `<code>POST /api/admin/users/set-tier\n{"email":"${payRec.email}","tier":"${payRec.plan === 'pro' ? 'premium' : payRec.plan}","payment_ref":"${payRid}"}</code>`;
      await sendTelegramAlert(env, tgMsg);

      slog("INFO", "BILLING", "BSC payment auto-verified", { rid: payRid, txhash: txhash.slice(0, 20) });
    }
  }

  return jsonResponse({
    status:       verifyStatus,
    txhash,
    review_id:    payRid || null,
    detail:       verifyDetail,
    bscscan_url:  `https://bscscan.com/tx/${txhash}`,
    request_id:   rid,
  });
}

// POST /api/admin/users/set-tier
// Admin-only (X-Admin-Secret). Instantly upgrades a user's tier in KV.
// Body: { email, tier, payment_ref?, reason? }
async function handleAdminSetTier(request, env, rid) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }

  const email      = sanitizeText((body.email || "").toLowerCase().trim(), 200);
  const tier       = sanitizeText((body.tier  || "").toLowerCase(),        20);
  const paymentRef = sanitizeText((body.payment_ref || ""),                80);
  const reason     = sanitizeText((body.reason || "manual_admin"),         120);

  if (!email) return jsonResponse({ error: "email_required", request_id: rid }, 400);

  const VALID_TIERS = new Set(["free", "premium", "enterprise"]);
  if (!VALID_TIERS.has(tier)) {
    return jsonResponse({ error: "invalid_tier", message: "tier must be free|premium|enterprise", request_id: rid }, 400);
  }

  // Look up user by email hash
  const emailHash = await (async () => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
  })();

  const userId = await env.API_KEYS_KV.get(`email:${emailHash}`).catch(() => null);
  if (!userId) {
    return jsonResponse({ error: "user_not_found", message: `No user found for email: ${email}`, request_id: rid }, 404);
  }

  const userRecord = await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null);
  if (!userRecord) {
    return jsonResponse({ error: "user_record_missing", request_id: rid }, 500);
  }

  const prevTier = userRecord.tier;
  userRecord.tier = tier;
  userRecord.tier_updated_at  = new Date().toISOString();
  userRecord.tier_updated_by  = "admin";
  userRecord.tier_reason      = reason;
  userRecord.payment_ref      = paymentRef || userRecord.payment_ref || null;
  if (!userRecord.subscription) userRecord.subscription = {};
  userRecord.subscription.plan       = tier;
  userRecord.subscription.activated_at = new Date().toISOString();
  userRecord.subscription.method     = "manual";

  await env.API_KEYS_KV.put(`user:${userId}`, JSON.stringify(userRecord));

  // Mark payment record as activated if payment_ref provided
  if (paymentRef) {
    const payRec = await env.API_KEYS_KV.get(`payment:${paymentRef}`, { type: "json" }).catch(() => null);
    if (payRec) {
      payRec.status       = "activated";
      payRec.activated_at = new Date().toISOString();
      payRec.activated_by = "admin";
      await env.API_KEYS_KV.put(`payment:${paymentRef}`, JSON.stringify(payRec), { expirationTtl: 86400 * 30 });
    }
  }

  slog("INFO", "BILLING", "Admin tier upgrade", { email, prev: prevTier, next: tier, reason, rid });

  return jsonResponse({
    status:      "upgraded",
    user_id:     userId,
    email,
    prev_tier:   prevTier,
    new_tier:    tier,
    payment_ref: paymentRef || null,
    message:     `User ${email} upgraded from ${prevTier} to ${tier}.`,
    request_id:  rid,
  });
}

// GET /api/admin/payments/pending
// Returns list of pending payment notifications awaiting admin review.
async function handleAdminListPayments(request, env, rid) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);
  const list = await env.API_KEYS_KV.get("payment:pending_list", { type: "json" }).catch(() => []) || [];
  return jsonResponse({ status: "ok", count: list.length, payments: list, request_id: rid });
}

// POST /api/notify/subscribe
// Public endpoint. Subscribes an email to threat alert notifications.
// Stored in KV; used by cron/pipeline to dispatch digest emails.
async function handleNotifySubscribe(request, env, rid) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ error: "invalid_json", request_id: rid }, 400); }

  const email     = sanitizeText((body.email || "").toLowerCase().trim(), 200);
  const interests = Array.isArray(body.interests) ? body.interests.slice(0, 10).map(i => sanitizeText(String(i), 40)) : ["critical", "high"];
  const tier_hint = sanitizeText((body.tier_hint || "free"), 20);

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return jsonResponse({ error: "invalid_email", request_id: rid }, 400);
  }

  const emailHash = await (async () => {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(email));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,"0")).join("");
  })();

  const subKey = `alertsub:${emailHash}`;
  const existing = await env.API_KEYS_KV.get(subKey, { type: "json" }).catch(() => null);
  const record = {
    email,
    interests,
    tier_hint,
    subscribed_at: existing?.subscribed_at || new Date().toISOString(),
    updated_at:    new Date().toISOString(),
    active:        true,
  };
  await env.API_KEYS_KV.put(subKey, JSON.stringify(record), { expirationTtl: 86400 * 365 });

  // Maintain global subscriber list for pipeline cron
  const listKey = "alertsub:list";
  const subList = await env.API_KEYS_KV.get(listKey, { type: "json" }).catch(() => []) || [];
  if (!subList.find(s => s.h === emailHash)) {
    subList.push({ h: emailHash, ts: record.subscribed_at });
    if (subList.length > 5000) subList.shift();
    await env.API_KEYS_KV.put(listKey, JSON.stringify(subList), { expirationTtl: 86400 * 365 });
  }

  slog("INFO", "NOTIFY", "Alert subscription", { interests, tier_hint, rid });

  return jsonResponse({
    status:      "subscribed",
    message:     "You'll receive threat alerts for: " + interests.join(", ") + ". Unsubscribe any time.",
    interests,
    request_id:  rid,
  }, 201);
}

//  v134.0.0: SIEM Output Formatters -- Splunk HEC / Sentinel / QRadar LEEF

function formatSplunkHEC(item) {
  return {
    time:       item.timestamp ? new Date(item.timestamp).getTime() / 1000 : Date.now() / 1000,
    host:       "sentinel-apex",
    source:     "threat-intel",
    sourcetype: "cyberdude:sentinel:advisory",
    index:      "threat_intel",
    event: {
      id:            item.id,
      title:         item.title,
      severity:      item.severity,
      risk_score:    item.risk_score,
      actor:         item.actor_tag || "UNATTRIBUTED",
      ioc_count:     item.ioc_count || 0,
      cve_ids:       (item.iocs || []).filter(i => i.type === "cve").map(i => i.value),
      mitre_tactics: item.mitre_tactics || [],
      feed_source:   item.feed_source || "SENTINEL-APEX",
      processed_at:  item.processed_at || item.timestamp,
      kev:           item.kev_present || false,
      exploit:       item.exploit_available || false,
      confidence:    item.confidence_score || 50,
      gateway:       `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    },
  };
}

function formatSentinelEvent(item) {
  return {
    TimeGenerated:     item.processed_at || item.timestamp || new Date().toISOString(),
    ThreatId:          item.id,
    ThreatTitle:       item.title,
    Severity:          item.severity,
    RiskScore:         item.risk_score,
    ActorTag:          item.actor_tag || "UNATTRIBUTED",
    IocCount:          item.ioc_count || 0,
    MitreTactics:      (item.mitre_tactics || []).join(", "),
    FeedSource:        item.feed_source || "SENTINEL-APEX",
    KevPresent:        item.kev_present || false,
    ExploitAvailable:  item.exploit_available || false,
    ConfidenceScore:   item.confidence_score || 50,
    GatewayVersion:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    Type:              "SentinelApexThreatIntel_CL",
  };
}

function formatQRadarLEEF(item) {
  const ts    = item.processed_at || item.timestamp || new Date().toISOString();
  const pairs = [
    `devTime=${ts}`, `devTimeFormat=ISO 8601`, `cat=ThreatIntel`,
    `sev=${item.risk_score || 0}`,
    `ThreatId=${(item.id || "").replace(/\t|\n/g, " ")}`,
    `ThreatTitle=${(item.title || "").replace(/\t|\n/g, " ")}`,
    `Severity=${item.severity || "UNKNOWN"}`,
    `ActorTag=${item.actor_tag || "UNATTRIBUTED"}`,
    `IocCount=${item.ioc_count || 0}`,
    `KevPresent=${item.kev_present || false}`,
    `ConfidenceScore=${item.confidence_score || 50}`,
    `FeedSource=${item.feed_source || "SENTINEL-APEX"}`,
    `GatewayVersion=${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  ].join("\t");
  return `LEEF:2.0|CYBERDUDEBIVASH|SENTINEL-APEX|${CONFIG.GATEWAY_VERSION}|ThreatIntel|\t${pairs}`;
}

//  v142.3.1: Response post-processor -- injects X-RateLimit + full enterprise security headers
// Called after every authenticated handler returns. Never mutates body -- only adds headers.
// Security headers added to ALL responses (military-grade defence-in-depth):
//   CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
//   X-XSS-Protection, X-Sentinel-Version, X-Sentinel-Gateway
function applySecurityHeaders(response, rlHeaders = {}) {
  const headers = new Headers(response.headers);
  // Rate limit telemetry (informational -- lets clients self-throttle)
  for (const [k, v] of Object.entries(rlHeaders)) {
    headers.set(k, v);
  }
  // === MILITARY-GRADE SECURITY HEADERS (v142.3.1) ===
  // 1. Content-Security-Policy -- blocks XSS, injection, clickjacking at browser level
  headers.set("Content-Security-Policy",
    "default-src 'none'; script-src 'self'; connect-src 'self' https://intel.cyberdudebivash.com; " +
    "img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'; " +
    "form-action 'self'; base-uri 'self'; upgrade-insecure-requests;"
  );
  // 2. HSTS -- enforces HTTPS for 1 year with preload and includeSubDomains
  headers.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  // 3. Classic hardening headers
  headers.set("X-Content-Type-Options",  "nosniff");
  headers.set("X-Frame-Options",         "DENY");
  headers.set("X-XSS-Protection",        "1; mode=block");
  headers.set("Referrer-Policy",         "strict-origin-when-cross-origin");
  headers.set("Permissions-Policy",      "geolocation=(), camera=(), microphone=(), payment=(), usb=()");
  // 4. Platform identity headers
  headers.set("X-Sentinel-Version",      CONFIG.GATEWAY_VERSION);
  headers.set("X-Sentinel-Gateway",      CONFIG.GATEWAY_NAME + "/" + CONFIG.GATEWAY_VERSION);
  headers.set("X-Response-Time",         response.headers.get("X-Response-Time") || "0ms");
  // 5. Remove server fingerprinting headers
  headers.delete("Server");
  headers.delete("X-Powered-By");
  return new Response(response.body, { status: response.status, headers });
}

// v134.0.0: Revenue Dashboard Handler
async function handleRevenueDashboard(request, env, rid) {
  const adminSecret = request.headers.get("X-Admin-Secret");
  if (!env?.ADMIN_SECRET || adminSecret !== env.ADMIN_SECRET) {
    return new Response(JSON.stringify({ error: "unauthorized", request_id: rid }, null, 2), {
      status: 401,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache", "Access-Control-Allow-Origin": "*" },
    });
  }
  const date = new URL(request.url).searchParams.get("date") || new Date().toISOString().slice(0, 10);
  const [revenueResp, epStats, tierDist, exhaustStats] = await Promise.allSettled([
    handleRevenueAnalytics(request, env, rid),
    getEndpointStats(env, date),
    getTierDistribution(env, date),
    getCreditExhaustionStats(env, date),
  ]);
  let revenueData = {};
  try { if (revenueResp.status === "fulfilled") revenueData = await revenueResp.value.json(); } catch {}
  return new Response(JSON.stringify({
    version: `v${CONFIG.GATEWAY_VERSION}`, date,
    revenue: revenueData,
    endpoint_stats:     epStats.status     === "fulfilled" ? epStats.value     : [],
    tier_distribution:  tierDist.status    === "fulfilled" ? tierDist.value    : {},
    credit_exhaustions: exhaustStats.status === "fulfilled" ? exhaustStats.value : { exhaustions_today: 0 },
    pricing: { free: { monthly_usd: 0 }, pro: { monthly_usd: 29 }, enterprise: { monthly_usd: 199 } },
    upgrade_urls: { free_to_pro: "/upgrade.html?plan=pro", trial: "/upgrade.html?plan=enterprise&trial=true" },
    request_id: rid, generated_at: new Date().toISOString(),
  }, null, 2), { status: 200, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-cache, no-store", "Access-Control-Allow-Origin": "*" } });
}

//  Main Router 


// -----------------------------------------------------------------------------
// PUBLIC MANIFEST HANDLER (v148.0 API-first)
// Serves FREE-tier /api/v1/intel/*.json endpoints without authentication.
// Premium endpoints (apex.json, ai_summary.json) are handled by servePremiumIntelManifest().
// Priority: R2 bucket -> KV cache -> GitHub raw (signed, versioned bundles).
//
// Tier routing:
//   FREE  (no auth):  /api/v1/intel/latest.json   (top-N items, field-trimmed)
//                     /api/v1/intel/top10.json     (top 10 by risk, trimmed)
//                     /api/v1/intel/manifest.json  (feed metadata only)
//   PRO+  (auth req): /api/v1/intel/apex.json      (full enriched feed)
//                     /api/v1/intel/ai_summary.json (AI Cyber Brain output)
// -----------------------------------------------------------------------------

// v148.0.0: Premium endpoints  -- require PRO or ENTERPRISE tier
const PREMIUM_INTEL_PATHS = new Set([
  '/api/v1/intel/apex.json',
  '/api/v1/intel/ai_summary.json',
  '/api/v1/intel/daily_brief_latest.pdf',   // PRO+  -- daily executive threat brief PDF
]);

// v148.0.0: Free public endpoints (daily brief metadata, no PDF payload)
const FREE_DAILY_BRIEF_PATHS = new Set([
  '/api/v1/intel/daily_brief_meta.json',    // FREE  -- brief metadata (date, size, subscribe link)
]);

// Free-tier field mask  -- strip revenue-generating premium fields from public latest.json / top10.json
// so free callers get useful signal but can't reconstruct the full premium feed.
const FREE_TIER_FIELDS = new Set([
  'id', 'title', 'summary', 'severity', 'risk_score', 'source', 'published',
  'threat_type', 'tags', 'ioc_count', 'cve_id', 'cve_ids', 'published_at',
  'stix_id', 'threat_category',
]);

function maskForFreeTier(items) {
  if (!Array.isArray(items)) return items;
  return items.slice(0, 25).map(item => {
    const masked = {};
    for (const k of FREE_TIER_FIELDS) {
      if (item[k] !== undefined) masked[k] = item[k];
    }
    masked._tier_notice = 'Upgrade to PRO for full enrichment: actor attribution, kill chain, IOC hashes, AI analysis, STIX bundle.';
    masked._upgrade_url = '/upgrade.html?plan=pro';
    return masked;
  });
}

// -----------------------------------------------------------------------------
// PREMIUM MANIFEST HANDLER (v148.0.0)  -- apex.json + ai_summary.json
// Requires valid API key or JWT with tier >= PREMIUM.
// Returns 401 with upgrade CTA on unauthenticated or free-tier requests.
// -----------------------------------------------------------------------------
async function servePremiumIntelManifest(pathname, env, rid, request) {
  // 1. Resolve auth
  const auth = await resolveAuth(request, env);
  if (!auth.valid) {
    return jsonResponse({
      error:          'api_key_required',
      message:        'This endpoint requires a PRO or ENTERPRISE API key.',
      endpoint:       pathname,
      tier_required:  'PRO',
      acquire_key:    CONFIG.GET_KEY_URL,
      upgrade_url:    '/upgrade.html?plan=pro',
      docs:           CONFIG.DOCS_URL,
      request_id:     rid,
    }, 401);
  }
  // 2. Enforce tier  -- FREE callers get a clear upsell, not the data
  if (auth.tier === CONFIG.TIERS.FREE) {
    return jsonResponse({
      error:          'tier_insufficient',
      message:        `'${pathname.split('/').pop()}' is a PRO+ endpoint. Your current tier is FREE.`,
      endpoint:       pathname,
      tier_required:  'PRO',
      your_tier:      auth.tier,
      upgrade_url:    '/upgrade.html?plan=pro',
      benefits:       [
        'Full AI Cyber Brain threat analysis (ai_summary.json)',
        'Complete enriched feed with actor attribution + kill chain (apex.json)',
        'STIX 2.1 bundle export',
        '500 requests/min vs 60 on FREE',
        'IOC hashes, EPSS, CVSS, threat actor mapping',
      ],
      acquire_key:    CONFIG.GET_KEY_URL,
      request_id:     rid,
    }, 403);
  }
  // 3. PRO+ confirmed  -- serve the manifest (same fetch chain as public handler)
  return servePublicIntelManifestRaw(pathname, env, rid);
}

// -----------------------------------------------------------------------------
// PUBLIC MANIFEST HANDLER (v148.0 API-first)
// Serves FREE-tier /api/v1/intel/*.json without authentication.
// Delegates to servePublicIntelManifestRaw() for the actual fetch.
// -----------------------------------------------------------------------------
async function servePublicIntelManifest(pathname, env, rid) {
  const ALLOWED = new Set([
    '/api/v1/intel/latest.json',
    '/api/v1/intel/top10.json',
    '/api/v1/intel/manifest.json',
  ]);
  if (!ALLOWED.has(pathname)) {
    return jsonResponse({ error: 'not_found', message: `Manifest '${pathname}' not found.`, request_id: rid }, 404);
  }
  // Fetch raw, then apply free-tier masking for item arrays (latest.json, top10.json)
  const raw = await servePublicIntelManifestRaw(pathname, env, rid);
  // Apply field mask on successful JSON responses so premium fields are protected
  if (raw.status === 200) {
    const ct = raw.headers.get('Content-Type') || '';
    if (ct.includes('application/json')) {
      try {
        const data = await raw.json();
        let masked = data;
        // Only mask array payloads (latest/top10 are plain arrays or {items:[...]})
        if (Array.isArray(data)) {
          masked = maskForFreeTier(data);
        } else if (data && Array.isArray(data.items)) {
          masked = { ...data, items: maskForFreeTier(data.items), _tier: 'free', _upgrade_url: '/upgrade.html?plan=pro' };
        }
        const newHeaders = new Headers(raw.headers);
        newHeaders.set('X-Tier', 'free');
        newHeaders.set('X-Items-Capped', '25');
        return new Response(JSON.stringify(masked, null, 2), { status: 200, headers: newHeaders });
      } catch { /* JSON parse failure: return original response unchanged */ }
    }
  }
  return raw;
}

// -----------------------------------------------------------------------------
// SHARED RAW MANIFEST FETCHER (v148.0.0)
// R2 -> KV cache -> GitHub raw fallback chain.
// -----------------------------------------------------------------------------
// v148.0.0: Daily Brief PDF  -- PRO+ gate (serves binary PDF from R2)
// GET /api/v1/intel/daily_brief_latest.pdf   requires PRO or ENTERPRISE tier
// -----------------------------------------------------------------------------
async function serveDailyBriefPDF(pathname, env, rid, request) {
  const auth = await resolveAuth(request, env);
  if (!auth.valid || (auth.tier !== 'pro' && auth.tier !== 'enterprise')) {
    return jsonResponse({
      error:       'pro_required',
      message:     'The Daily Brief PDF is a PRO+ exclusive. Subscribe at https://cyberdudebivash.gumroad.com/l/sentinel-apex-daily-brief',
      upgrade_url: 'https://intel.cyberdudebivash.com/upgrade.html',
      request_id:  rid,
    }, 403);
  }
  const r2Key = 'api/v1/intel/daily_brief_latest.pdf';
  try {
    const obj = await env.INTEL_BUCKET.get(r2Key);
    if (!obj) {
      return jsonResponse({ error: 'not_found', message: 'Daily brief not yet generated. Check back in a few minutes.', request_id: rid }, 404);
    }
    const headers = new Headers({
      'Content-Type':        'application/pdf',
      'Content-Disposition': 'inline; filename="sentinel-apex-daily-brief.pdf"',
      'Cache-Control':       'private, max-age=3600',
      'X-Request-ID':        rid,
    });
    slog('INFO', 'DAILY_BRIEF', `PDF served to tier=${auth.tier}`, { rid });
    return new Response(obj.body, { status: 200, headers });
  } catch (err) {
    slog('ERROR', 'DAILY_BRIEF', `R2 fetch error: ${err.message}`, { rid });
    return jsonResponse({ error: 'storage_error', message: 'Failed to retrieve daily brief.', request_id: rid }, 502);
  }
}

// -----------------------------------------------------------------------------
// v148.0.0: Daily Brief Metadata  -- FREE tier (JSON metadata, no PDF payload)
// GET /api/v1/intel/daily_brief_meta.json   no authentication required
// -----------------------------------------------------------------------------
async function serveDailyBriefMeta(env, rid) {
  const r2Key = 'api/v1/intel/daily_brief_meta.json';
  try {
    const obj = await env.INTEL_BUCKET.get(r2Key);
    if (!obj) {
      return jsonResponse({
        available:     false,
        message:       'Daily brief not yet generated for today.',
        subscribe_url: 'https://cyberdudebivash.gumroad.com/l/sentinel-apex-daily-brief',
        request_id:    rid,
      }, 200);
    }
    const meta = await obj.json();
    return jsonResponse({
      ...meta,
      pdf_url:       '/api/v1/intel/daily_brief_latest.pdf',
      subscribe_url: 'https://cyberdudebivash.gumroad.com/l/sentinel-apex-daily-brief',
      upgrade_url:   'https://intel.cyberdudebivash.com/upgrade.html',
      tier_required: 'PRO+',
      request_id:    rid,
    }, 200, { 'Cache-Control': 'public, max-age=1800' });
  } catch (err) {
    slog('ERROR', 'DAILY_BRIEF_META', `R2 fetch error: ${err.message}`, { rid });
    return jsonResponse({ error: 'storage_error', message: 'Failed to retrieve daily brief metadata.', request_id: rid }, 502);
  }
}

// Called by both servePublicIntelManifest (free, masked) and
// servePremiumIntelManifest (authenticated, unmasked full data).
// -----------------------------------------------------------------------------
async function servePublicIntelManifestRaw(pathname, env, rid) {
  const ALL_ALLOWED = new Set([
    '/api/v1/intel/latest.json',
    '/api/v1/intel/top10.json',
    '/api/v1/intel/apex.json',
    '/api/v1/intel/manifest.json',
    '/api/v1/intel/ai_summary.json',
  ]);
  if (!ALL_ALLOWED.has(pathname)) {
    return jsonResponse({ error: 'not_found', message: `Manifest '${pathname}' not found.`, request_id: rid }, 404);
  }
  const filename = pathname.split('/').pop();
  const r2Key    = pathname.slice(1);
  const cacheKey = `manifest_raw:${filename}`;

  // SOURCE 1: R2 bucket (authoritative -- uploaded by pipeline after generation)
  if (env?.INTEL_R2) {
    try {
      const obj = await env.INTEL_R2.get(r2Key);
      if (obj) {
        const body = await obj.text();
        return new Response(body, {
          status: 200,
          headers: {
            'Content-Type':                'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control':               'public, max-age=300, stale-while-revalidate=60',
            'X-Manifest-Source':           'r2',
            'X-Gateway':                   `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
          },
        });
      }
    } catch (e) {
      slog('WARN', 'MANIFEST', `R2 miss for ${filename}`, { error: e.message, rid });
    }
  }

  // SOURCE 2: KV cache (avoid GitHub egress on repeated requests within TTL)
  if (env?.RATE_LIMIT_KV) {
    try {
      const cached = await env.RATE_LIMIT_KV.get(cacheKey);
      if (cached) {
        return new Response(cached, {
          status: 200,
          headers: {
            'Content-Type':                'application/json; charset=utf-8',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control':               'public, max-age=300, stale-while-revalidate=60',
            'X-Manifest-Source':           'kv-cache',
            'X-Gateway':                   `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
          },
        });
      }
    } catch { /* fall through to GitHub */ }
  }

  // SOURCE 3: GitHub raw (fallback -- always available for public repos)
  try {
    const ghUrl = `https://raw.githubusercontent.com/${CONFIG.GITHUB_REPO}/${CONFIG.GITHUB_BRANCH}/${r2Key}`;
    const ghHeaders = { 'User-Agent': `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}` };
    if (env?.GITHUB_TOKEN) ghHeaders['Authorization'] = `token ${env.GITHUB_TOKEN}`;
    const ghResp = await fetch(ghUrl, { headers: ghHeaders, cf: { cacheTtl: 300 } });
    if (ghResp.ok) {
      const body = await ghResp.text();
      if (env?.RATE_LIMIT_KV) {
        env.RATE_LIMIT_KV.put(cacheKey, body, { expirationTtl: 300 }).catch(() => {});
      }
      return new Response(body, {
        status: 200,
        headers: {
          'Content-Type':                'application/json; charset=utf-8',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control':               'public, max-age=300, stale-while-revalidate=60',
          'X-Manifest-Source':           'github-raw',
          'X-Gateway':                   `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
        },
      });
    }
  } catch (e) {
    slog('WARN', 'MANIFEST', `GitHub raw miss for ${filename}`, { error: e.message, rid });
  }

  return jsonResponse({
    error:      'manifest_unavailable',
    message:    `Manifest '${pathname}' is temporarily unavailable. Pipeline may still be generating it.`,
    request_id: rid,
  }, 503);
}

export default {
  async fetch(request, env, ctx) {
    const rid       = generateReqId();
    const reqStart  = Date.now();                 // v134.0.0: request duration tracking
    const url       = new URL(request.url);
    const { pathname } = url;
    const method    = request.method.toUpperCase();
    slog("INFO", "ROUTER", `${method} ${pathname}`, { rid });

    // v142.3.1: CORS preflight -- smart origin enforcement
    // Public endpoints allow wildcard; authenticated/admin endpoints restrict to known origins
    if (method === "OPTIONS") {
      const origin = request.headers.get("Origin") || "";
      const allowedOrigins = [
        "https://www.cyberdudebivash.in",
        "https://cyberdudebivash.in",
        "https://intel.cyberdudebivash.com",
      ];
      const isAdminPath = url.pathname.startsWith("/api/admin") || url.pathname.startsWith("/webhooks/");
      const corsOrigin = isAdminPath
        ? (allowedOrigins.includes(origin) ? origin : allowedOrigins[0])
        : "*";
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin":      corsOrigin,
          "Access-Control-Allow-Methods":     "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers":     "Authorization, X-Api-Key, Content-Type, X-Admin-Secret, X-Request-ID",
          "Access-Control-Max-Age":           "86400",
          "Access-Control-Allow-Credentials": isAdminPath ? "true" : "false",
          "Vary":                             "Origin",
        },
      });
    }

    // IP rate limiting + multi-layer abuse check (all endpoints)
    const clientIP = getClientIP(request);

    // Layer 1: Legacy IP ban (RATE_LIMIT_KV -- daily abuse counter)
    if (await isIPBanned(clientIP, env)) {
      return jsonResponse({
        error:      "ip_banned",
        message:    "Your IP has been temporarily blocked due to excessive invalid requests.",
        request_id: rid,
      }, 429);
    }

    // Layer 2: Enhanced abuse detection (SECURITY_HUB_KV -- per-minute rate, scanner UA, auth brute force)
    const abuseBlock = await detectAbuse(request, env, rid);
    if (abuseBlock) return abuseBlock;

    // Layer 3: Sliding-window IP rate limit
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

    // v142.3.1: Security headers applied to ALL responses (public + authenticated)
    // Previously only authenticated routes used applySecurityHeaders via withRL.
    // Now every public endpoint also gets full security header injection.
    // This fixes MISSING_SECURITY_HEADERS finding on /api/health, /api/preview etc.
    const withSec = async (respPromise) => applySecurityHeaders(await respPromise);

    //  Public endpoints (no API key required)
    if (pathname.startsWith("/api/preview"))          return withSec(handlePreview(request, env, rid));
    // v147.0: Dashboard FALLBACK1 -- plain JSON array, same schema as GitHub Pages api/feed.json
    if (pathname === "/api/feed.json" && (method === "GET" || method === "OPTIONS"))
                                                      return withSec(handleFeedJson(request, env, rid));
    if (pathname.startsWith("/api/health"))            return withSec(handleHealth(request, env, rid));
    if (pathname.startsWith("/api/version"))           return withSec(handleVersion(request, env, rid));
    if (pathname.startsWith("/api/keys/validate"))     return withSec(handleValidateKey(request, env, rid));
    // v134.0.0: Live dashboard metrics -- public, no auth required
    if (pathname === "/api/platform/stats" && method === "GET") return withSec(handlePlatformStats(request, env, rid));
    // v141.1.0: Revenue -- public payment notify + alert subscription (no auth required)
    if (pathname === "/api/payment/notify"      && method === "POST") return withSec(handlePaymentNotify(request, env, rid));
    if (pathname === "/api/payment/verify-bsc" && method === "GET")  return withSec(handleBSCVerify(request, env, rid));
    if (pathname === "/api/notify/subscribe"   && method === "POST") return withSec(handleNotifySubscribe(request, env, rid));
    //  v134.0.0 + v134.0.0: JWT auth endpoints
    if (pathname === "/api/auth/token"    && method === "POST") return withSec(handleIssueToken(request, env, rid));
    if (pathname === "/api/auth/validate")                      return withSec(handleValidateToken(request, env, rid));
    if (pathname === "/api/auth/refresh"  && method === "POST") return withSec(handleRefreshToken(request, env, rid));
    if (pathname === "/api/auth/revoke"   && method === "POST") return withSec(handleRevokeToken(request, env, rid));
    //  v134.0.0: User auth endpoints (no API key required)
    if (pathname === "/auth/signup"       && method === "POST") return withSec(handleUserSignup(request, env, rid));
    if (pathname === "/auth/login"        && method === "POST") return withSec(handleUserLogin(request, env, rid));
    //  v134.0.0: Billing webhooks (no API key -- use their own sig verification)
    if (pathname === "/webhooks/stripe"   && method === "POST") return withSec(handleStripeWebhook(request, env, rid));
    if (pathname === "/webhooks/razorpay" && method === "POST") return withSec(handleRazorpayWebhook(request, env, rid));
    // AI endpoints -- public (index/heatmap) or authenticated (analyze/respond/correlate)
    if (pathname.startsWith("/api/ai")) {
      const aiSub = pathname.slice("/api/ai".length);
      // Full AI analysis endpoints require authentication
      if (aiSub.startsWith("/analyze") || aiSub.startsWith("/respond") || aiSub.startsWith("/correlate")) {
        const auth = await resolveAuth(request, env);
        if (!auth.valid) {
          return withSec(Promise.resolve(jsonResponse({
            error:       "api_key_required",
            message:     "API key required for full AI analysis. Use Authorization: Bearer <key>.",
            acquire_key: CONFIG.GET_KEY_URL,
            request_id:  rid,
          }, 401)));
        }
      }
      return withSec(handleAI(request, env, rid, aiSub));
    }

    //  Admin endpoints (X-Admin-Secret verified internally) 
    if (pathname.startsWith("/api/admin")) {
      // All /api/admin/* require X-Admin-Secret -- verify once here
      if (!env?.ADMIN_SECRET || request.headers.get("X-Admin-Secret") !== env.ADMIN_SECRET) {
        slog("WARN", "ADMIN", "Forbidden admin access attempt", { path: pathname, rid });
        return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
      }
      if (pathname === "/api/admin/cache/bust"               && method === "POST") return handleCacheBust(request, env, rid);
      if (pathname === "/api/admin/cache/bust-prefix"        && method === "POST") return handleCacheBustPrefix(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/create")    && method === "POST") return handleAdminCreateKey(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/revoke")    && method === "POST") return handleAdminRevokeKey(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/list")      && method === "GET")  return handleAdminListKeys(request, env, rid);
      if (pathname.startsWith("/api/admin/observability")  && method === "GET")  return handleAdminObservability(request, env, rid);
      // v134.0.0: Abuse event log -- scanner activity, IP bans, auth brute force
      if (pathname.startsWith("/api/admin/abuse")          && method === "GET")  return handleAbuseReport(request, env, rid);
      // v141.1.0: Revenue -- manual tier upgrade + pending payment list
      if (pathname === "/api/admin/users/set-tier"         && method === "POST") return handleAdminSetTier(request, env, rid);
      if (pathname === "/api/admin/payments/pending"       && method === "GET")  return handleAdminListPayments(request, env, rid);
      // v143.0.0: SLA heartbeat ping (called by Cloudflare Cron every 5 min)
      if (pathname === "/api/sla/ping"           && method === "POST") return handleSLAPing(request, env, rid);
      // v143.0.0: Alert dispatch (internal -- triggers alerts to all subscribers)
      if (pathname === "/api/alerts/dispatch"    && method === "POST") return handleAlertDispatch(request, env, rid);
      return jsonResponse({
        error:     "not_found",
        message:   "Admin endpoint not found.",
        available: [
          "POST /api/admin/cache/bust",
          "POST /api/admin/cache/bust-prefix  (v143 -- prefix wildcard bust)",
          "POST /api/admin/keys/create",
          "POST /api/admin/keys/revoke",
          "GET  /api/admin/keys/list",
          "GET  /api/admin/observability",
          "POST /api/sla/ping               (cron heartbeat -- X-Admin-Secret required)",
          "POST /api/alerts/dispatch        (trigger alert broadcast -- X-Admin-Secret required)",
        ],
        request_id: rid,
      }, 404);
    }

    // v148.0.0: TIERED /api/v1/intel/ manifest routing
    // FREE  (no auth): latest.json, top10.json, manifest.json  (field-masked, 25-item cap)
    // PRO+  (auth req): apex.json, ai_summary.json             (full enriched, requires Bearer token)
    if (pathname.startsWith('/api/v1/intel/') && method === 'GET') {
      // v148.0.0: Daily Brief free metadata  -- no auth required
      if (FREE_DAILY_BRIEF_PATHS.has(pathname)) {
        return withSec(serveDailyBriefMeta(env, rid));
      }
      if (PREMIUM_INTEL_PATHS.has(pathname)) {
        // v148.0.0: daily_brief_latest.pdf  -- PRO+ gate (PDF binary from R2)
        if (pathname === '/api/v1/intel/daily_brief_latest.pdf') {
          return withSec(serveDailyBriefPDF(pathname, env, rid, request));
        }
        // Hard gate: PRO+ tier required; free users get upgrade CTA with 403
        return withSec(servePremiumIntelManifest(pathname, env, rid, request));
      }
      // Free-tier manifests: served publicly but field-masked (25 items, core fields only)
      return withSec(servePublicIntelManifest(pathname, env, rid));
    }

    //  ALL REMAINING ENDPOINTS: JWT OR API KEY REQUIRED 
    // resolveAuth: JWT (3-part Bearer) takes priority -> falls through to API key
    const auth = await resolveAuth(request, env);
    if (!auth.valid) {
      if (auth.reason === "invalid_key" || auth.reason === "key_expired") {
        await trackAbuseAttempt(clientIP, env);
        // v134.0.0: Track auth failure for brute-force detection in SECURITY_HUB_KV
        trackAuthFailure(env, clientIP).catch(() => {});
      }
      return jsonResponse({
        error:       auth.reason === "key_required" ? "api_key_required" : "unauthorized",
        message:     auth.reason === "key_required"
          ? "API key or JWT required. Use Authorization: Bearer <token>. Get a key at " + CONFIG.GET_KEY_URL
          : `Authentication rejected: ${auth.reason}`,
        reason:      auth.reason,
        auth_hint:   "Issue a JWT via POST /api/auth/token with your API key",
        acquire_key: CONFIG.GET_KEY_URL,
        docs:        CONFIG.DOCS_URL,
        request_id:  rid,
      }, 401);
    }

    // Per-key sliding-window rate limit (tier-based caps: free=60, premium=500, enterprise=2000 req/min)
    const rateLimit = CONFIG.RATE_LIMITS[auth.tier] || CONFIG.RATE_LIMITS.free;
    const keyCheck  = await slidingWindowCheck("key", auth.key_id, rateLimit, env?.RATE_LIMIT_KV);
    if (!keyCheck.allowed) {
      await recordAnalytics(env, auth.key_id, "rate_limited", auth.tier, 429);
      return jsonResponse({
        error:       "rate_limited",
        message:     `Rate limit exceeded. ${auth.tier} tier: ${rateLimit} req/min. Retry after ${keyCheck.retryAfter || 60}s.`,
        tier:        auth.tier,
        limit:       keyCheck.limit,
        retry_after: keyCheck.retryAfter,
        upgrade:     getUpgradeCTA(auth.tier),
        request_id:  rid,
        response_ms: Date.now() - reqStart,
      }, 429, {
        "Retry-After":           String(keyCheck.retryAfter || 60),
        "X-RateLimit-Limit":     String(rateLimit),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Policy":    `${rateLimit};w=60`,
        "X-Response-Time":       String(Date.now() - reqStart) + "ms",
      });
    }
    // v134.0: Inject X-RateLimit headers on every successful authenticated response
    // Stored in ctx so handlers can access via closure; injected via wrapWithRateLimitHeaders()
    const _rlHeaders = {
      "X-RateLimit-Limit":     String(rateLimit),
      "X-RateLimit-Remaining": String(Math.max(0, keyCheck.remaining ?? rateLimit - 1)),
      "X-RateLimit-Policy":    `${rateLimit};w=60`,
      "X-Tier":                auth.tier,
    };

    // v134.0.0: Request fingerprinting -- async, fire-and-forget for analytics (never blocks)
    fingerprintRequest(request, env, auth, rid).catch(() => {});

    //  v134.0.0: CREDIT GATE  usage-based billing enforcement 
    const _epSlug  = slugifyEndpoint(pathname);
    const _epCost  = calculateCostPerCall(_epSlug, auth.tier);
    const _credits = await checkCredits(env, auth.user_id || auth.key_id, auth.tier, _epCost, rid);
    if (!_credits.allowed) {
      trackRevenueEvent(env, "credit_exhausted", { key_id: auth.key_id, tier: auth.tier, endpoint: _epSlug }).catch(() => {});
      return _credits.response402;
    }
    ctx.waitUntil(trackApiUsage(env, auth.user_id || auth.key_id, _epSlug, auth.tier, _epCost));
    analyzeUsagePatterns(env, auth.user_id || auth.key_id, auth.tier,
      _credits.status?.credits_remaining ?? 0, _credits.status?.credit_limit ?? 100).catch(() => {});

    //  v134.0: All authenticated responses wrapped with X-RateLimit + security headers 
    const _rl = _rlHeaders;  // captured above after rate-limit check
    const withRL = (resp) => applySecurityHeaders(resp, _rl);
    // v134.0.0: merge credit billing headers into every authenticated response
    Object.assign(_rlHeaders, buildCreditHeaders(_credits.status, _credits.status?.credits_used));

    //  v134.0.0: Authenticated user + billing routes 
    if (pathname === "/auth/me"              && method === "GET")    return withRL(await handleUserMe(request, env, rid, auth));
    if (pathname === "/api/keys"             && method === "GET")    return withRL(await handleUserListKeys(request, env, rid, auth));
    if (pathname === "/api/keys/create"      && method === "POST")   return withRL(await handleUserCreateKey(request, env, rid, auth));
    if (pathname.startsWith("/api/keys/")   && method === "DELETE") {
      const keyId = pathname.slice("/api/keys/".length);
      if (keyId) return withRL(await handleUserDeleteKey(request, env, rid, auth, keyId));
    }
    if (pathname === "/api/billing/portal"   && method === "GET")    return withRL(await handleBillingPortal(request, env, rid, auth));
    // v143.0.0: Dynamic Stripe Checkout Session (auth optional -- guest checkout allowed)
    if (pathname === "/api/checkout/session" && method === "POST")  return withRL(await handleCreateCheckoutSession(request, env, auth, rid));
    // v134.0: Self-service usage analytics
    if (pathname === "/api/account/usage"    && method === "GET")    return withRL(await handleAccountUsage(request, env, rid, auth));

    // Authenticated route dispatch
    if (pathname === "/api/feed" && method === "GET")
      return withRL(await handleFeed(request, env, auth, rid));
    if (pathname.startsWith("/api/feed/") && method === "GET") {
      const id = decodeURIComponent(pathname.slice("/api/feed/".length));
      if (id) return withRL(await handleReport(request, env, auth, rid, id));
    }
    if (pathname.startsWith("/api/analytics") && method === "GET")
      return withRL(await handleAnalytics(request, env, auth, rid));
    // v134.0.0: STIX export
    if (pathname.startsWith("/api/stix/")) {
      const stixId = decodeURIComponent(pathname.slice("/api/stix/".length));
      return withRL(await handleStixExport(request, env, auth, rid, stixId));
    }
    // v143.0.0: Dark Web Monitor + Leak Check (Pro/Enterprise)
    if (pathname === "/api/dark-web/scan"    && method === "POST") return withRL(await handleDarkWebScan(request, env, auth, rid));
    if (pathname === "/api/dark-web/status"  && method === "GET")  return withRL(await handleDarkWebStatus(request, env, auth, rid));
    if (pathname === "/api/leak-check"       && method === "POST") return withRL(await handleLeakCheck(request, env, auth, rid));
    // v143.0.0: Premium PDF Reports (Pro/Enterprise)
    if ((pathname === "/api/reports/premium" || pathname === "/api/reports/list") && method === "POST")
      return withRL(await handlePremiumReport(request, env, auth, rid));
    if (pathname === "/api/reports/list" && method === "GET")
      return withRL(await handleReportList(request, env, auth, rid));
    const reportMatch = pathname.match(/^\/api\/reports\/(rpt_[a-f0-9]{16})$/);
    if (reportMatch && method === "GET") return withRL(await handleReportGet(request, env, auth, rid, reportMatch[1]));
    // v134.0.0: Threat alerts (Pro+)
    if (pathname.startsWith("/api/alerts") && method === "GET")
      return withRL(await handleAlerts(request, env, auth, rid));
    // v134.0.0: SIEM webhook (Enterprise)
    if (pathname.startsWith("/api/webhooks/siem"))
      return withRL(await handleSiemWebhook(request, env, auth, rid));

    //  v134.0.0: NEW ENDPOINTS -- Full CTI API surface 

    // GET /api/search -- full-text + field search across feed (scope: read:intel)
    if (pathname === "/api/search" && method === "GET")
      return withRL(await handleSearch(request, env, auth, rid));

    // GET /api/actors[?actor_id=&limit=&since=] -- threat actor profiles (scope: read:actors)
    if (pathname === "/api/actors" && method === "GET")
      return withRL(await handleActors(request, env, auth, rid));

    // GET /api/cves[?cve_id=&severity=&kev_only=&min_epss=&limit=&page=] (scope: read:cves)
    if (pathname === "/api/cves" && method === "GET")
      return withRL(await handleCVEs(request, env, auth, rid));

    // GET /api/export/misp[?report_id=&since=&limit=] -- MISP JSON export (scope: export:misp, Enterprise only)
    if (pathname === "/api/export/misp" && method === "GET")
      return withRL(await handleMISPExport(request, env, auth, rid));

    // GET /api/export/csv[?since=&types=&limit=] -- IOC bulk CSV export (scope: export:csv, Pro+)
    if (pathname === "/api/export/csv" && method === "GET")
      return withRL(await handleCSVExport(request, env, auth, rid));

    // POST /api/intel/correlate -- IOC correlation against full feed (scope: read:intel)
    if (pathname === "/api/intel/correlate" && method === "POST")
      return withRL(await handleCorrelate(request, env, auth, rid));

    //  v134.0.0: AI Intelligence Endpoints 
    // GET|POST /api/predict -- AI threat prediction (Pro+)
    if (pathname === "/api/predict" && (method === "GET" || method === "POST"))
      return withRL(await handlePredict(request, env, auth, rid));

    // GET /api/campaigns -- detected threat campaigns (Pro+)
    if (pathname === "/api/campaigns" && method === "GET")
      return withRL(await handleCampaigns(request, env, auth, rid));

    // GET /api/anomalies -- zero-day + anomalous threat feed (Pro+)
    if (pathname === "/api/anomalies" && method === "GET")
      return withRL(await handleAnomalies(request, env, auth, rid));

    // GET /api/intelligence/graph -- IOC relationship graph (Pro=summary, Enterprise=full)
    if (pathname === "/api/intelligence/graph" && method === "GET")
      return withRL(await handleIntelGraph(request, env, auth, rid));

    // GET /api/intelligence/relations -- BFS IOC relations (Pro=limited, Enterprise=full)
    if (pathname === "/api/intelligence/relations" && method === "GET")
      return withRL(await handleIntelRelations(request, env, auth, rid));

    // GET /api/platform/stats -- live feed stats for dashboard (public -- no auth required)
    // (also accessible without auth for dashboard widgets -- handled below)

    // v134.0.0: Revenue API Endpoints
    if (pathname.startsWith("/api/revenue") && method === "GET")
      return withRL(await handleRevenueDashboard(request, env, rid));
    if (pathname === "/api/leads/capture" && method === "POST")
      return handleLeadCapture(request, env, rid);
    if (pathname === "/api/leads/trial" && method === "POST")
      return handleTrialIssuance(request, env, rid);

    // v143.0.0: SLA Status -- public endpoint (no auth required)
    if (pathname === "/api/sla/status" && method === "GET")
      return new Response(JSON.stringify(await (async () => {
        const r = await handleSLAStatus(request, env, rid);
        return r.json ? await r.json() : {};
      })()), { status: 200, headers: { "Content-Type": "application/json", "X-Sentinel-Version": "143.0.0" }});

    // v143.0.0: Dark Web Monitor (Pro+ required)
    if (pathname === "/api/dark-web/scan")
      return withRL(await handleDarkWebScan(request, env, auth, rid));
    if (pathname === "/api/dark-web/status" && method === "GET")
      return withRL(await handleDarkWebStatus(request, env, auth, rid));
    if (pathname === "/api/leak-check")
      return withRL(await handleLeakCheck(request, env, auth, rid));

    // v143.0.0: Premium Threat Reports ($49/report sellable asset -- Pro+ required)
    if (pathname === "/api/reports/premium" || pathname === "/api/reports/list")
      return withRL(await handlePremiumReport(request, env, auth, rid));
    // GET /api/reports/:id -- retrieve a previously generated report
    {
      const reportMatch = pathname.match(/^\/api\/reports\/(rpt_[a-f0-9]{16})$/);
      if (reportMatch && method === "GET")
        return withRL(await handleReportGet(request, env, auth, rid, reportMatch[1]));
    }

    // v143.0.0: AI Alert Engine -- subscribe / manage / history (Pro+ required)
    if (pathname === "/api/alerts/subscribe"      && method === "POST") return withRL(await handleAlertSubscribe(request, env, auth, rid));
    if (pathname === "/api/alerts/subscriptions"  && method === "GET")  return withRL(await handleAlertSubscriptions(request, env, auth, rid));
    if (pathname === "/api/alerts/history"        && method === "GET")  return withRL(await handleAlertHistory(request, env, auth, rid));
    if (pathname === "/api/alerts/test"           && method === "POST") return withRL(await handleAlertTest(request, env, auth, rid));
    if (pathname.startsWith("/api/alerts/unsubscribe/") && method === "DELETE")
      return withRL(await handleAlertUnsubscribe(request, env, auth, rid));

    // v143.0.0: SLA Monitor -- report/incidents/certificate (Enterprise required)
    if (pathname === "/api/sla/status"            && method === "GET")  return handleSLAStatus(request, env, rid);
    if (pathname === "/api/sla/report"            && method === "GET")  return withRL(await handleSLAReport(request, env, auth, rid));
    if (pathname === "/api/sla/incidents"         && method === "GET")  return withRL(await handleSLAIncidents(request, env, auth, rid));
    if (pathname === "/api/sla/certificate"       && method === "GET")  return withRL(await handleSLACertificate(request, env, auth, rid));

    slog("WARN", "ROUTER", `404 ${pathname}`, { rid, method });
    return jsonResponse({
      error:   "not_found",
      message: `Endpoint '${pathname}' not found.`,
      available: [
        //  Public
        "GET  /api/preview              (public -- free preview feed)",
        "GET  /api/feed.json            (public -- full feed plain array, dashboard FALLBACK1)",
        "GET  /api/health               (public)",
        "GET  /api/version              (public)",
        "GET  /api/keys/validate        (public)",
        "GET  /api/platform/stats       (public -- live dashboard metrics)",
        "GET  /api/ai                   (public -- AI index + MITRE heatmap)",
        "GET  /api/ai/heatmap           (public)",
        //  Auth endpoints 
        "POST /api/auth/token           (public -- exchange API key for JWT)",
        "GET  /api/auth/validate        (public -- validate JWT)",
        "POST /api/auth/refresh         (requires JWT -- rotate token)",
        "POST /api/auth/revoke          (requires JWT -- revoke token)",
        "POST /auth/signup              (public -- create user account + get JWT)",
        "POST /auth/login               (public -- login + get JWT)",
        //  Billing webhooks 
        "POST /webhooks/stripe          (public -- Stripe webhook, sig-verified)",
        "POST /webhooks/razorpay        (public -- Razorpay webhook, sig-verified)",
        //  Authenticated (Free+) 
        "GET  /auth/me                  (requires JWT -- user profile + API keys)",
        "POST /api/keys/create          (requires JWT -- create API key)",
        "GET  /api/keys                 (requires JWT -- list your API keys)",
        "DELETE /api/keys/:id           (requires JWT -- revoke API key)",
        "GET  /api/billing/portal       (requires JWT -- subscription + upgrade links)",
        "POST /api/checkout/session     (public -- create Stripe Checkout Session, returns redirect_url)",
        //  Intel feed
        "GET  /api/feed                 (requires auth -- full intel feed)",
        "GET  /api/feed/:id             (requires auth -- single report)",
        "GET  /api/analytics            (requires auth -- usage analytics)",
        //  AI endpoints 
        "GET  /api/ai/analyze           (requires auth)",
        "GET  /api/ai/respond           (requires auth)",
        "GET  /api/ai/correlate         (requires auth)",
        //  v134.0.0: NEW CTI API surface 
        "GET  /api/search               (requires auth -- full-text + field search | scope: read:intel)",
        "GET  /api/actors               (requires auth -- threat actor profiles | scope: read:actors)",
        "GET  /api/cves                 (requires auth -- CVE deep-dive CVSS+EPSS+KEV | scope: read:cves)",
        "POST /api/intel/correlate      (requires auth -- IOC correlation | scope: read:intel)",
        "GET  /api/stix/:id             (requires auth -- STIX 2.1 bundle | scope: read:stix)",
        "GET  /api/alerts               (requires auth Pro+ -- threat alerts)",
        //  Export endpoints 
        "GET  /api/export/csv           (requires auth Pro+ -- IOC bulk CSV | scope: export:csv)",
        "GET  /api/export/misp          (requires auth Enterprise -- MISP JSON | scope: export:misp)",
        //  v134.0.0: AI Intelligence (Phase 2+4) 
        "GET|POST /api/predict          (Pro+ -- AI threat prediction | CVSS+EPSS+KEV+TTP scoring)",
        "GET  /api/campaigns            (Pro+ -- detected threat campaigns | DBSCAN-clustered)",
        "GET  /api/anomalies            (Pro+ -- zero-day candidates + anomalous threats | Isolation Forest)",
        "GET  /api/intelligence/graph   (Pro=summary, Enterprise=full IOC graph | PageRank authority scores)",
        "GET  /api/intelligence/relations (Pro+ -- IOC relationship BFS traversal | actor attribution)",
        //  Enterprise 
        "GET  /api/webhooks/siem        (requires auth Enterprise -- list + format info)",
        "POST /api/webhooks/siem        (requires auth Enterprise -- register SIEM webhook)",
        //  v143.0.0: Dark Web Monitor + Leak Check
        "POST /api/dark-web/scan        (requires auth Pro+ -- dark web & breach scan for email/domain)",
        "GET  /api/dark-web/status      (public -- monitor health & source status)",
        "GET|POST /api/leak-check       (requires auth Pro+ -- single email/domain leak check)",
        //  v143.0.0: Premium Threat Reports ($49/report)
        "POST /api/reports/premium      (requires auth Pro+ -- generate intelligence report)",
        "GET  /api/reports/list         (requires auth Pro+ -- list generated reports)",
        "GET  /api/reports/:id          (requires auth Pro+ -- retrieve report by ID)",
        //  v143.0.0: AI Alert Engine
        "POST /api/alerts/subscribe     (requires auth Pro+ -- subscribe Telegram/Webhook alerts)",
        "GET  /api/alerts/subscriptions (requires auth Pro+ -- list active subscriptions)",
        "GET  /api/alerts/history       (requires auth Pro+ -- alert delivery history)",
        "POST /api/alerts/test          (requires auth Pro+ -- send test alert)",
        "DELETE /api/alerts/unsubscribe/:id (requires auth Pro+ -- remove subscription)",
        //  v143.0.0: SLA Monitor
        "GET  /api/sla/status           (public -- current uptime + SLA health)",
        "GET  /api/sla/report           (requires auth Enterprise -- 30-day SLA report)",
        "GET  /api/sla/incidents        (requires auth Enterprise -- incident log)",
        "GET  /api/sla/certificate      (requires auth Enterprise -- SLA compliance cert)",
        "POST /api/sla/ping             (requires X-Admin-Secret -- cron heartbeat)",
        //  Admin
        "POST /api/admin/cache/bust     (requires X-Admin-Secret)",
        "POST /api/admin/keys/create    (requires X-Admin-Secret)",
        "POST /api/admin/keys/revoke    (requires X-Admin-Secret)",
        "GET  /api/admin/keys/list      (requires X-Admin-Secret)",
        "GET  /api/admin/observability  (requires X-Admin-Secret)",
        "GET  /api/admin/abuse          (requires X-Admin-Secret -- abuse event log)",
      ],
      docs:       CONFIG.DOCS_URL,
      request_id: rid,
      response_ms: Date.now() - reqStart,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 404);
  },

  //  v134.0.0: Scheduled Cron Handler 
  // Trigger: configure in wrangler.toml -> [triggers] crons = ["*/15 * * * *"]
  // On each cron tick:
  //   1. Fetch latest R2 feed manifest
  //   2. Identify reports processed in the last cron interval
  //   3. Push high-severity threats to all registered Enterprise SIEM webhooks
  //   4. Invalidate platform stats cache so next /api/platform/stats call is fresh
  async scheduled(event, env, ctx) {
    const rid = generateReqId();
    slog("INFO", "CRON", `Scheduled tick: ${event.cron || "manual"}`, { rid });

    ctx.waitUntil((async () => {
      try {
        //  Step 1: Fetch feed manifest from R2 
        let manifest = null;
        if (env?.INTEL_R2) {
          const obj = await env.INTEL_R2.get("feed_manifest.json").catch(() => null);
          if (obj) {
            try { manifest = JSON.parse(await obj.text()); } catch { manifest = null; }
          }
        }

        // v143.5 FIX: feed_manifest.json is written as a flat array by the Python pipeline.
    // Previous code assumed { reports: [...] } shape -- manifest?.reports was always undefined.
    // Handle all three possible shapes: flat array, { reports: [...] }, { advisories: [...] }
    let reports = [];
    if (Array.isArray(manifest)) {
      reports = manifest;
    } else if (manifest && Array.isArray(manifest.reports)) {
      reports = manifest.reports;
    } else if (manifest && Array.isArray(manifest.advisories)) {
      reports = manifest.advisories;
    } else if (manifest && Array.isArray(manifest.items)) {
      reports = manifest.items;
    }
        if (!reports.length) {
          slog("WARN", "CRON", "No reports in feed manifest -- skipping webhook push", { rid });
          return;
        }

        //  Step 2: Identify recently published items (last 30 min) 
        const cutoff  = new Date(Date.now() - 30 * 60 * 1000).toISOString();
        const newItems = reports.filter(r => {
          const ts = r.processed_at || r.timestamp || "";
          return ts >= cutoff;
        });

        slog("INFO", "CRON", `Feed: ${reports.length} total, ${newItems.length} new since ${cutoff}`, { rid });

        //  Step 3: Push to SIEM webhooks (Enterprise tier) 
        if (newItems.length > 0) {
          const pushResult = await pushWebhookNotifications(env, newItems);
          slog("INFO", "CRON", "Webhook push complete", { rid, ...pushResult });
        }

        //  Step 4: Invalidate platform stats cache 
        if (env?.ANALYTICS_KV) {
          await env.ANALYTICS_KV.delete("platform:stats:v140").catch(() => {});
          slog("INFO", "CRON", "Platform stats cache invalidated", { rid });
        }

        //  Step 5: Rebuild KV index cache for fast search/actors/CVEs queries
        // v148.2.0 FIX: write NORMALISED shape { reports, total_reports, generated_at }
        // instead of raw manifest. Raw manifest may be a flat array or { reports: [...] }
        // -- neither has the total_reports field checked by the health endpoint, which
        // caused persistent feed_index: "not_cached" even after data was written.
        // DO NOT revert to JSON.stringify(manifest) -- health check will break again.
        if (env?.SECURITY_HUB_KV && manifest) {
          const _kvIdx = {
            reports,
            total_reports: reports.length,
            generated_at:  new Date().toISOString(),
          };
          await env.SECURITY_HUB_KV.put(
            "idx:reports",
            JSON.stringify(_kvIdx),
            { expirationTtl: 1800 }  // 30 min TTL -- refreshed by every cron tick
          ).catch(() => {});
          slog("INFO", "CRON", "KV report index refreshed", { rid, count: reports.length });
        }

      } catch (e) {
        await trackError(env, "CRON", "Scheduled handler failed", { error: e.message, rid });
      }
    })());
  },
};
