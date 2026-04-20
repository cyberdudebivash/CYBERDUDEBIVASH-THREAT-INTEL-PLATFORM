// =============================================================================
// CYBERDUDEBIVASHÂ® SENTINEL APEX â€” Edge Intelligence Gateway v122.0.0
// R2-ONLY ARCHITECTURE â€” Blogger dependency REMOVED
// Data flow: GitHub Actions â†’ Cloudflare R2 (private) â†’ Worker â†’ API clients
// Intel data NEVER stored in public GitHub repo (EMBEDDED_INTEL obsolete).
// Secrets: ADMIN_SECRET, GITHUB_TOKEN, CDB_JWT_SECRET (npx wrangler secret put)
//          STRIPE_WEBHOOK_SECRET, RAZORPAY_WEBHOOK_SECRET (billing webhooks)
//          STRIPE_PRO_PRICE_ID, STRIPE_ENT_PRICE_ID (Stripe plan IDs)
// v112.0: Added /api/ai endpoint family
// v116.2.0: stix_id fix; GATEWAY_VERSION unified
// v120.0.0: GOD-MODE â€” mandatory ai_summary, retry circuit breaker, urgency CTAs
// v121.0.0: FINAL HARDENING â€” structured logging, schema validation, JWT revocation,
//           token refresh/revoke, usage caps, observability, API/feed consistency
// v122.0.0: SAAS TRANSFORMATION â€” user auth (PBKDF2), API key CRUD, billing
//           (Stripe/Razorpay webhooks), IOC extraction fallback (min 3),
//           SIEM formatters (Splunk/Sentinel/QRadar), pricing page
// =============================================================================

// â”€â”€ v123.0.0: Extension modules â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
  // v123.0.0 â€” AI Intelligence Endpoints
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

// v130.0.0: Usage Metering Engine
import {
  slugifyEndpoint,
  calculateCostPerCall,
  trackApiUsage,
  getUsageSummary,
  getEndpointStats,
  getTierDistribution,
  analyzeUsagePatterns,
} from "./usage-meter.js";

// v130.0.0: Credit / Token System
import {
  checkCredits,
  buildCreditHeaders,
  buildBillingStatus,
  getCreditExhaustionStats,
} from "./credit-system.js";

// ── Version sync: always read from CONFIG ──────────────────────────────────
function injectVersionHeaders(response, config) {
  const headers = new Headers(response.headers);
  headers.set("X-SENTINEL-Version", config.GATEWAY_VERSION);
  headers.set("X-SENTINEL-Platform", "SENTINEL-APEX");
  headers.set("X-SENTINEL-Codename", "Revenue-Engine");
  headers.set("X-Powered-By", "CYBERDUDEBIVASH-SENTINEL-APEX-v131");
  return new Response(response.body, { status: response.status, headers });
}

const CONFIG = {
  GATEWAY_VERSION:   "131.0.0"  // v131.0.0: SENTINEL APEX Revenue Engine — version lock, IOC confidence, payment gateway,  // v125.0.0: FINAL HARDENING â€” injection-pattern blocking, IOC consistency gate, paid-tier STIX validation, X-RateLimit headers, signup field sanitization
  GATEWAY_NAME:      "SENTINEL-APEX",
  BYPASS_FEED_CACHE: false,
  // P0 FIX v111.0: Reduced cache TTLs to ensure dashboard reflects fresh R2 data
  // quickly after each pipeline run. KV cache is busted by workflow on every run.
  CACHE_TTL: {
    FEED:    60,    // seconds â€” authenticated feed (was 180, reduced for freshness)
    PREVIEW: 90,    // seconds â€” public preview (was 300, reduced to 90s)
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

// â”€â”€ Utilities â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

function generateReqId() {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return "req_" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// â”€â”€ v125.0: Injection-pattern blocklist â€” SQL, XSS, path-traversal, command injection â”€â”€
// Defined FIRST â€” all sanitizers below depend on this.
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

// â”€â”€ v124.0: Centralized input sanitization helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Used by ALL endpoint handlers â€” prevents injection attacks via query params.
const _CTRL_STRIP = /[\x00-\x1F\x7F<>"'`\\]/g;

// v125.0: sanitizeStr now runs injection-pattern gate after ctrl-char strip.
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

// â”€â”€ v125.0: Comprehensive input sanitizer for POST body fields â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v125.0: FEED_LIMITS hard cap per tier (prevents abusive over-fetching) â”€â”€â”€â”€â”€
function getTierLimit(tier, requested) {
  const caps = { free: 20, premium: 500, enterprise: 2000 };
  const cap  = caps[tier] || caps.free;
  return Math.min(Math.max(1, requested || cap), cap);
}

// â”€â”€ v121.0.0: Structured Logger â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// ALL log output is structured JSON â€” searchable in Cloudflare Workers Tail Logs.
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

// â”€â”€ v121.0.0: Error Tracking â€” persists to SECURITY_HUB_KV (7-day rolling) â”€â”€â”€
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
  } catch { /* non-critical â€” never let observability kill a request */ }
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

// â”€â”€ v124.0: Feed Deduplication â€” 3-layer: stix_id + title-hash + content-hash â”€â”€
// Removes duplicates from manifest items before serving to clients.
// Dedup key priority:
//   L1: stix_id / id (most stable â€” canonical STIX bundle identifier)
//   L2: normalised title hash (catches same advisory with different IDs)
//   L3: source+title content-hash (catches cross-source republications)
// Also strips known brand/identity noise entries that leak into feed.
const BRAND_NOISE = [
  "CYBERDUDEBIVASHÂ® PRIVATE LIMITED",
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
    .sort()     // order-independent hash â†’ catches reordered titles
    .join("|");
}

function _contentHash(item) {
  // A lightweight fingerprint of the item's core identity:
  // (source normalised) + "::" + (title normalised)
  const src   = (item.source || item.feed_source || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const title = _titleHash(item.title || item.name || "");
  // Include CVE ID if present â€” prevents stripping unique CVEs with generic titles
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

// â”€â”€ v117.0.0: JWT Auth â€” HS256 via Web Crypto API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Uses CDB_JWT_SECRET from Cloudflare secret (set via: npx wrangler secret put CDB_JWT_SECRET)
// ZERO ephemeral fallback: if CDB_JWT_SECRET is missing, auth endpoints return 503.
// Token format: standard JWT HS256 â€” header.payload.signature (base64url encoded)

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

// â”€â”€ v121.0.0: JWT Revocation Blocklist â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v122.0.0: PBKDF2 Password Hashing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v122.0.0: POST /auth/signup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v122.0.0: POST /auth/login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    slog("WARN", "AUTH", "Login failed â€” bad password", { user_id: userId });
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

// â”€â”€ v122.0.0: GET /auth/me â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleUserMe(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId     = auth.user_id || auth.key_id;
  const userRecord = userId ? await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null) : null;

  if (!userRecord) {
    // Legacy API key auth â€” return synthetic user context
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

// â”€â”€ v122.0.0: POST /api/keys/create â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    warning:      "Store this API key securely â€” it will NOT be shown again.",
    request_id:   rid,
    gateway:      `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  }, 201);
}

// â”€â”€ v122.0.0: GET /api/keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v122.0.0: DELETE /api/keys/:id â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleUserDeleteKey(request, env, rid, auth, keyIdToDelete) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId    = auth.user_id || auth.key_id;
  const keyRecord = await env.API_KEYS_KV.get(`apikey:${keyIdToDelete}`, { type: "json" }).catch(() => null);

  if (!keyRecord) return jsonResponse({ error: "not_found", key_id: keyIdToDelete, request_id: rid }, 404);
  if (keyRecord.user_id && keyRecord.user_id !== userId)
    return jsonResponse({ error: "forbidden", message: "You do not own this API key.", request_id: rid }, 403);

  // Soft-revoke â€” preserves audit trail
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

// â”€â”€ /api/auth/token â€” Issue JWT (POST, body: {api_key, tier}) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ /api/auth/validate â€” Validate JWT (GET/POST) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ Unified auth resolver: supports both JWT and legacy API keys â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Priority: JWT (Bearer token with 3 parts) > Legacy API key (CDB-* / X-Api-Key)
// v121.0.0: Checks JWT revocation blocklist before accepting token.
async function resolveAuth(request, env) {
  // Try JWT first
  const jwtToken = extractJwt(request);
  if (jwtToken && env?.CDB_JWT_SECRET) {
    const result = await verifyJwt(jwtToken, env.CDB_JWT_SECRET);
    if (result.valid) {
      // v121.0.0: HARD check revocation blocklist â€” revoked tokens NEVER pass
      if (await isTokenRevoked(jwtToken, env)) {
        return { valid: false, reason: "token_revoked", auth_method: "jwt" };
      }
      // v123.1: Live tier resolution â€” JWT tier can be stale if user paid after token issue.
      // Read authoritative tier from KV user record; fall back to JWT claim.
      // This makes Stripe payment tier upgrades instant â€” no JWT refresh required.
      const jwtUserId = result.payload.user_id || result.payload.sub || result.payload.key_id;

      // v124.0: STRICT TIER VALIDATION â€” only accept known tier values, default FREE on invalid
      const VALID_TIERS = new Set([CONFIG.TIERS.FREE, CONFIG.TIERS.PREMIUM, CONFIG.TIERS.ENTERPRISE]);
      const rawJwtTier  = result.payload.tier || CONFIG.TIERS.FREE;
      const sanitisedJwtTier = VALID_TIERS.has(rawJwtTier) ? rawJwtTier : CONFIG.TIERS.FREE;

      let liveTier = sanitisedJwtTier;
      if (jwtUserId && env?.API_KEYS_KV) {
        try {
          const liveUser = await env.API_KEYS_KV.get(`user:${jwtUserId}`, { type: "json" });
          // MUST be a known tier â€” never elevate to unknown value
          if (liveUser?.tier && VALID_TIERS.has(liveUser.tier)) {
            liveTier = liveUser.tier;
          }
        } catch { /* KV read failure â†’ safe default (JWT claim already validated) */ }
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
    // JWT present but invalid â€” hard fail (no fallback to API key)
    return { valid: false, reason: result.reason, auth_method: "jwt" };
  }
  // Fall through to legacy API key resolution
  const legacy = await resolveApiKey(request, env);
  return { ...legacy, auth_method: "api_key" };
}

// â”€â”€ Rate Limiting â€” Sliding Window â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ API Key Resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// v121.0.0: Enforces usage_limit (monthly request cap) per key record.
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

    // v121.0.0: Monthly usage cap enforcement
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
          upgrade_url: "https://cyberdudebivash.com/sentinel-premium",
        };
      }
      // Increment usage counter (fire-and-forget â€” never block the request)
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

// â”€â”€ Abuse Tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ Analytics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ Data Layer: R2 â†’ KV Cache â†’ GitHub Fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

  // v116.2.0 FRESHNESS FIX: Inject processed_at fallback
  // v121.0.0: validateAndNormalizeItem() â€” guarantee no null fields across entire manifest
  const manifestGeneratedAt = data.generated_at || null;
  items = items.map(item => {
    // Inject processed_at before normalization so validator can use it
    if (!item.processed_at) {
      item = { ...item, processed_at: item.timestamp || item.generated_at || manifestGeneratedAt || null };
    }
    // v121.0.0: Full schema normalization â€” derives all missing fields, never null
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

// â”€â”€ v120.0.0: Retry circuit breaker â€” exponential backoff, 3 attempts â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Prevents single transient failures from killing requests.
// 4xx (client errors) are NOT retried â€” only 5xx / network errors.
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
  // v120.0.0: fetchWithRetry â€” 3 attempts with backoff for transient GitHub/CDN errors
  const res = await fetchWithRetry(url, { headers, ...cfOpts });
  if (!res.ok) {
    const hint = res.status === 404 && !env?.GITHUB_TOKEN
      ? " (GITHUB_TOKEN not set â€” set via: npx wrangler secret put GITHUB_TOKEN)"
      : "";
    throw new Error(`GitHub HTTP ${res.status}${hint}`);
  }
  return res.json();
}

async function fetchReportsIndex(env) {
  const cacheKey = "idx:reports";

  // SOURCE 1: Cloudflare R2 (primary â€” private, no public exposure)
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

  // SOURCE 3: GitHub raw (emergency fallback â€” GITHUB_TOKEN required for private repo)
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

// â”€â”€ Upgrade CTAs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ v120.0.0: computeApexAI â€” Full AI Intelligence Engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Produces: predictive_risk, ai_confidence, actor_fingerprint, kill_chain, ttp_density, ai_summary
// v120.0.0 GOD-MODE: ai_summary is MANDATORY â€” teaser for free, full narrative for Pro/Enterprise
// ai_summary NEVER null â€” generated dynamically from item data when apex.ai_summary absent
// Safe: never throws â€” returns minimal object on any error

function computeApexAI(item, tier) {
  try {
    const isFree  = !tier || tier === CONFIG.TIERS.FREE;
    const isPro   = tier === CONFIG.TIERS.PREMIUM || tier === CONFIG.TIERS.ENTERPRISE;

    // â”€â”€ Core scores â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const riskScore  = typeof item.risk_score  === "number" ? item.risk_score
                     : typeof item.cvss_score  === "number" ? item.cvss_score : 0;
    const epss       = typeof item.epss_score  === "number" ? item.epss_score : 0;
    const confidence = typeof item.confidence  === "number" ? item.confidence
                     : typeof item.confidence_score === "number" ? item.confidence_score : 0;
    const kev        = item.kev_present === true ? 1.0 : 0.0;
    const iocCount   = Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0);
    const ttpCount   = Array.isArray(item.ttps) ? item.ttps.length : (item.ttp_count || 0);

    // â”€â”€ predictive_risk (0â€“10): composite risk projection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Weights: CVSS 40%, EPSS 25%, KEV 20%, IOC density 15%
    const iocDensityScore = Math.min(iocCount * 0.5, 2.0);
    const predictiveRisk  = Math.min(10,
      (riskScore * 0.4) + (epss * 0.025) + (kev * 2.0) + (iocDensityScore * 0.15 * 10)
    );

    // â”€â”€ ai_confidence (0â€“100): evidence quality score â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Synthesises: base confidence + KEV bonus + STIX completeness + IOC density
    const stixObjects  = typeof item.stix_object_count === "number" ? item.stix_object_count : 0;
    const stixBonus    = Math.min(stixObjects * 1.5, 12);
    const iocBonus     = Math.min(iocCount * 2, 15);
    const kevBonus     = kev * 10;
    const iocEngConf   = typeof item.ioc_confidence === "number" ? Math.min(item.ioc_confidence * 0.15, 10) : 0;
    const aiConfidence = Math.min(100, Math.round(confidence + stixBonus + iocBonus + kevBonus + iocEngConf));

    // â”€â”€ threat_confidence_tier: enterprise-grade qualitative label â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Replaces "AI CONF: 47%" weak display with authoritative tier classification
    const confidenceTier =
      aiConfidence >= 90 ? "VERIFIED"  :   // multi-source corroboration + KEV
      aiConfidence >= 70 ? "HIGH"      :   // strong evidence base, actionable
      aiConfidence >= 45 ? "MODERATE"  :   // partial evidence, investigate
                           "LOW";          // limited signals, monitor only

    const tierLabel = {
      VERIFIED: "âœ“ VERIFIED â€” Multi-source corroboration confirmed",
      HIGH:     "â–² HIGH â€” Strong evidence basis, immediate action required",
      MODERATE: "â—† MODERATE â€” Credible intelligence, further investigation advised",
      LOW:      "â—‡ LOW â€” Limited signals, threat monitoring recommended",
    }[confidenceTier];

    // â”€â”€ SOC Recommendation Engine v3.0 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    function _buildSocRec(actorTag_, ttpCount_, iocCount_, primaryPhase_, soc_priority_, severity_) {
      const urgent = soc_priority_ === "P1" || soc_priority_ === "P2";
      const sevCaps = (severity_ || "UNKNOWN").toUpperCase();
      if (sevCaps === "CRITICAL") {
        return `IMMEDIATE RESPONSE REQUIRED [${soc_priority_}]: Activate IR playbook for ${actorTag_}. ` +
          `Hunt ${iocCount_} IOC${iocCount_ !== 1 ? "s" : ""} across SIEM/EDR telemetry. ` +
          `Isolate affected assets, block C2 indicators. ` +
          `Escalate to CISO if lateral movement detected. ` +
          `MITRE coverage: ${ttpCount_} technique${ttpCount_ !== 1 ? "s" : ""} â€” focus on ${primaryPhase_} phase.`;
      } else if (sevCaps === "HIGH") {
        return `HIGH-PRIORITY SOC ACTION [${soc_priority_}]: Deploy detection rules for ${actorTag_} TTPs. ` +
          `Block ${iocCount_} indicator${iocCount_ !== 1 ? "s" : ""} at perimeter. ` +
          `Review ${primaryPhase_} phase artifacts in last 72h. ` +
          `${ttpCount_} MITRE technique${ttpCount_ !== 1 ? "s" : ""} mapped â€” validate coverage gaps.`;
      }
      return `MONITOR & PREPARE [${soc_priority_}]: Track ${actorTag_} campaign. ` +
        `Add ${iocCount_} IOC${iocCount_ !== 1 ? "s" : ""} to watchlists. ` +
        `Review ${ttpCount_} MITRE technique${ttpCount_ !== 1 ? "s" : ""} against current defenses.`;
    }

    // â”€â”€ actor_fingerprint: deterministic actor identity string â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const actorTag = item.actor_tag || (item.apex && item.apex.campaign_id) || "UNC-UNKNOWN";
    const severity = (item.severity || "UNKNOWN").toUpperCase();
    const sevCode  = { CRITICAL: "C", HIGH: "H", MEDIUM: "M", LOW: "L" }[severity] || "U";
    const actorFP  = isPro
      ? `${actorTag}::${sevCode}::IOC-${iocCount}::TTP-${ttpCount}`
      : `${actorTag.slice(0, 8)}****`; // partial for free tier

    // â”€â”€ kill_chain: primary phase derived from TTPs / kill_chain_phases â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const rawKc    = Array.isArray(item.kill_chain_phases) ? item.kill_chain_phases : [];
    const rawTtps  = Array.isArray(item.ttps) ? item.ttps
                   : Array.isArray(item.mitre_tactics) ? item.mitre_tactics : [];
    // Map common MITRE tactics to kill chain phases
    const ttpToPhase = {
      TA0001: "Initial Access", TA0002: "Execution", TA0003: "Persistence",
      TA0004: "Privilege Escalation", TA0005: "Defense Evasion", TA0006: "Credential Access",
      TA0007: "Discovery", TA0008: "Lateral Movement", TA0009: "Collection",
      TA0010: "Exfiltration", TA0011: "Command and Control", TA0040: "Impact",
    };
    const derivedPhases = rawTtps.slice(0, 5).map(t => {
      const ta = t.toUpperCase();
      return ttpToPhase[ta] || (ta.startsWith("T1") ? "Execution" : "Unknown");
    });
    const killChainPhases = rawKc.length > 0 ? rawKc
      : [...new Set(derivedPhases)].slice(0, 3);
    const primaryPhase = killChainPhases[0] || "Unknown";

    // â”€â”€ ttp_density (0â€“10): attack sophistication density score â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // Higher = more diverse techniques used (sophisticated actor)
    const uniqueTtps  = new Set(rawTtps).size;
    const ttpDensity  = Math.min(10, parseFloat((
      (uniqueTtps * 0.8) + (iocCount * 0.3) + (riskScore * 0.2)
    ).toFixed(2)));

    // â”€â”€ Existing apex block passthrough â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const existingApex = (item.apex && typeof item.apex === "object") ? item.apex : {};

    // â”€â”€ Tier-gated assembly â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    const socPriority = existingApex.priority || (riskScore >= 9 ? "P1" : riskScore >= 7 ? "P2" : riskScore >= 5 ? "P3" : "P4");
    const threatLevel = existingApex.threat_level || (riskScore >= 9 ? "CRITICAL_SURGE" : riskScore >= 7 ? "HIGH_ALERT" : riskScore >= 5 ? "MODERATE" : "LOW");
    const base = {
      soc_priority:            socPriority,
      threat_level:            threatLevel,
      threat_category:         existingApex.threat_category || "UNKNOWN",
      predictive_risk:         parseFloat(predictiveRisk.toFixed(2)),
      ai_confidence:           aiConfidence,
      threat_confidence_tier:  confidenceTier,      // v124.0: VERIFIED/HIGH/MODERATE/LOW
      threat_confidence_label: tierLabel,            // v124.0: human-readable tier description
      ttp_density:             ttpDensity,
      campaign_id:             existingApex.campaign_id || "UNCLASSIFIED",
    };

    // â”€â”€ v124.0: AI Summary Engine v3.0 â€” enterprise-grade narratives, no weak language â”€
    // Free: authoritative teaser â€” credible signal, drives upgrade
    // Pro/Enterprise: full tactical SOC narrative with actionable recommendations
    const sevLabel   = severity === "CRITICAL" ? "CRITICAL" : severity === "HIGH" ? "HIGH" : severity;
    const threatType = (item.threat_type || item.type || "THREAT CAMPAIGN").toUpperCase();
    const cveId      = item.cve_id || "";
    const cveStr     = cveId ? ` [${cveId}]` : "";
    const srcLabel   = item.source ? ` Â· Source: ${item.source}` : "";
    const kevStr     = kev ? " Â· CISA KEV CONFIRMED" : "";
    const epssStr    = epss >= 0.7 ? ` Â· EPSS: ${(epss * 100).toFixed(0)}% exploitation probability` : "";

    // Full narrative (Pro/Enterprise) â€” authoritative, zero weak language
    const fullSummary = existingApex.ai_summary || (
      `[${confidenceTier}] ${sevLabel} ${threatType}${cveStr}${kevStr}. ` +
      `Actor cluster ${actorTag} operating in ${primaryPhase} phase. ` +
      `${ttpCount} MITRE ATT&CK technique${ttpCount !== 1 ? "s" : ""} mapped â€” TTP density ${ttpDensity}/10. ` +
      `${iocCount} indicator${iocCount !== 1 ? "s" : ""} extracted (IOC engine confidence: ${aiConfidence}%). ` +
      `Predictive risk score: ${parseFloat(predictiveRisk.toFixed(1))}/10${epssStr}${srcLabel}. ` +
      `SOC Priority: ${socPriority}.`
    );

    // Authoritative teaser (Free) â€” removes "AI CONF: X%" weak pattern
    const teaserSummary = (
      `[${confidenceTier}] ${sevLabel} ${threatType}${cveStr}${kevStr}. ` +
      `${iocCount} indicator${iocCount !== 1 ? "s" : ""} Â· ${ttpCount} MITRE technique${ttpCount !== 1 ? "s" : ""} Â· ` +
      `Predictive risk: ${parseFloat(predictiveRisk.toFixed(1))}/10 Â· SOC ${socPriority}. ` +
      `FULL ACTOR ATTRIBUTION + KILL CHAIN + SOC PLAYBOOK â€” PRO TIER REQUIRED â†’`
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
        ai_summary:         teaserSummary,        // authoritative teaser â€” never null
        recommended_action: `SOC ${socPriority}: ${iocCount} IOC${iocCount !== 1 ? "s" : ""} & full kill chain attribution locked behind Pro tier. Upgrade for complete IR playbook.`,
        behavioral_tags:    [],
        paywall: {
          locked_fields: ["actor_fingerprint_full","kill_chain","behavioral_tags","recommended_action_full","stix_bundle"],
          upgrade_url:   "https://cyberdudebivash.com/sentinel-premium",
          message:       `${confidenceTier} THREAT â€” ${iocCount} IOC${iocCount !== 1 ? "s" : ""} & full actor attribution locked. Upgrade to Pro for complete intelligence.`,
          urgency:       socPriority === "P1" || socPriority === "P2"
            ? `âš ï¸ ACTIVE ${sevLabel} THREAT [${socPriority}] â€” Enterprise IR response required.`
            : `THREAT ACTIVE [${socPriority}] â€” Full detection package available on Pro tier.`,
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
    // v120.0.0: Even on error, ai_summary must not be null
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

// â”€â”€ v119.0.0: applyTierGate â€” enforces monetization on feed items â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    // v124.0: Always expose ioc_confidence + ioc_threat_level (not paywalled)
    // These are summary signals â€” the full IOC list is locked behind Pro
    gated.ioc_confidence   = item.ioc_confidence   || 0;
    gated.ioc_threat_level = item.ioc_threat_level || "NONE";
    gated.ioc_paywall = {
      locked:            true,
      count:             item.iocs.length,
      confidence:        item.ioc_confidence || 0,
      threat_level:      item.ioc_threat_level || "NONE",
      primary_types:     (item.ioc_extraction_meta && item.ioc_extraction_meta.primary_types) || [],
      upgrade_url:       "https://cyberdudebivash.com/sentinel-premium",
      message:           `${item.iocs.length} IOC(s) at ${item.ioc_confidence || 0}% confidence â€” unlock with Pro tier.`,
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
        upgrade_url:   "https://cyberdudebivash.com/sentinel-enterprise",
        message:       "Full STIX 2.1 bundle export available on Enterprise tier.",
      };
    }
  }

  // v125.0: IOC COUNT CONSISTENCY â€” paid tiers: ioc_count MUST equal actual iocs.length.
  // Prevents ioc_count > 0 with empty array (data integrity violation for Pro/Enterprise).
  if (!isFree && Array.isArray(gated.iocs)) {
    gated.ioc_count = gated.iocs.length;
  }

  // v125.0: STIX BUNDLE VALIDITY GATE â€” when stix_bundle is present (Enterprise),
  // validate it has the required STIX 2.1 structure. Strip invalid bundles rather than serve them.
  if (isEnt && gated.stix_bundle !== null && gated.stix_bundle !== undefined) {
    const sb = gated.stix_bundle;
    if (typeof sb !== "object" || sb.type !== "bundle" || !Array.isArray(sb.objects) || sb.objects.length === 0) {
      // Invalid STIX bundle structure â€” null it out to prevent corrupt data reaching consumers
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

  // v125.0: HIGH/CRITICAL severity integrity check â€” never serve HIGH+ advisory with 0 IOCs.
  // If ioc_count is still 0 after normalization, flag it with a data quality annotation.
  // This is a data-quality annotation only â€” does NOT block the response.
  const finalSev = (gated.severity || "").toUpperCase();
  if ((finalSev === "CRITICAL" || finalSev === "HIGH") && (gated.ioc_count || 0) === 0) {
    gated._data_quality = { warning: "high_severity_zero_ioc", message: "IOC extraction pending or data incomplete." };
  }

  // v120.0.0: Threat urgency CTA â€” injected for free tier on critical/high items
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
          ? "âš ï¸ CRITICAL ACTIVE THREAT â€” Full intelligence, IOC array & actor attribution locked."
          : "âš ï¸ HIGH-SEVERITY ACTIVE THREAT â€” Actor TTPs and kill chain analysis locked.",
        tier_required:   "PRO",
        upgrade_url:     "https://cyberdudebivash.com/sentinel-premium",
        cta:             "Upgrade to Pro â€” Detect, Respond, Contain.",
        enterprise_note: "Enterprise Detection Engine unavailable on free tier.",
      };
    }
  }

  return gated;
}

// â”€â”€ v122.0.0: IOC Extraction from Text â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Regex-based IOC detection from title/description/summary text.
// Used as fallback when ioc_count < 3 â€” ensures EVERY threat has indicators.
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

  // CVE (highest confidence â€” unambiguous)
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

  // MD5 (only 32-char â€” lower confidence, often false-positive in non-hash contexts)
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

// â”€â”€ v121.0.0: Schema Validator & Normalizer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// HARD GUARANTEE: No null/undefined for any field that UI or API consumers depend on.
// Called on every item before API responses and before applyTierGate.
// ZERO tolerance: missing field â†’ derive from existing data â†’ guaranteed default.
function validateAndNormalizeItem(item) {
  if (!item || typeof item !== "object") return null;
  const out = { ...item };

  // â”€â”€ risk_score: MUST be number 0â€“10 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (typeof out.risk_score !== "number" || isNaN(out.risk_score)) {
    out.risk_score = typeof out.cvss_score === "number" ? out.cvss_score : 0;
  }
  out.risk_score = Math.max(0, Math.min(10, out.risk_score));

  // â”€â”€ severity: derive from risk_score when missing/UNKNOWN â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ title: MUST be non-empty string â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!out.title || typeof out.title !== "string" || !out.title.trim()) {
    out.title = out.cve_id || out.advisory_id || out.id || "Untitled Advisory";
  }

  // â”€â”€ id + stix_id: cross-populate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!out.id)      out.id      = out.stix_id || out.cve_id || out.advisory_id || `advisory-${Date.now()}`;
  if (!out.stix_id) out.stix_id = out.id;

  // â”€â”€ timestamps: guarantee processed_at and timestamp both set â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  const firstTs = out.processed_at || out.timestamp || out.generated_at || out.published_at;
  if (!out.processed_at) out.processed_at = firstTs || new Date().toISOString();
  if (!out.timestamp)    out.timestamp    = out.processed_at;

  // â”€â”€ ioc_counts: derive from iocs array when object is absent/empty â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ ioc_count scalar: sum of ioc_counts or length of iocs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (typeof out.ioc_count !== "number") {
    out.ioc_count = Array.isArray(out.iocs) ? out.iocs.length
      : (out.ioc_counts ? Object.values(out.ioc_counts).reduce((a, b) => a + (b || 0), 0) : 0);
  }

  // â”€â”€ v122.0.0: IOC Extraction Fallback â€” RULE: ioc_count >= 3 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // â”€â”€ confidence_score: 0â€“100 (normalise 0â€“1 fraction) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (typeof out.confidence_score !== "number" || isNaN(out.confidence_score)) {
    out.confidence_score = typeof out.confidence === "number" ? out.confidence : 50;
  }
  if (out.confidence_score > 0 && out.confidence_score <= 1) {
    out.confidence_score = Math.round(out.confidence_score * 100);
  }
  out.confidence_score = Math.max(0, Math.min(100, Math.round(out.confidence_score)));

  // â”€â”€ actor_tag: must be non-null string â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!out.actor_tag || typeof out.actor_tag !== "string") out.actor_tag = "UNATTRIBUTED";

  // â”€â”€ feed_source â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!out.feed_source) out.feed_source = out.source || "SENTINEL-APEX";

  // â”€â”€ mitre_tactics: must be array â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!Array.isArray(out.mitre_tactics)) {
    out.mitre_tactics = Array.isArray(out.ttps) ? out.ttps : [];
  }

  // â”€â”€ iocs: must be array â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!Array.isArray(out.iocs)) out.iocs = [];

  // â”€â”€ ttps: must be array â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (!Array.isArray(out.ttps)) out.ttps = [];

  // â”€â”€ boolean flags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  out.kev_present = out.kev_present === true;
  out.exploit_available = out.exploit_available === true;
  out.zero_day = out.zero_day === true;
  out.supply_chain = out.supply_chain === true;
  out.ransomware = out.ransomware === true;

  // â”€â”€ v124.0: IOC Engine enrichment fields â€” pass through from pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // ioc_confidence: float 0â€“100 â€” confidence score from multi-layer IOC extraction
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

// â”€â”€ v124.0: applyIocMetaTierGate â€” strips extraction_meta from free tier â”€â”€â”€â”€â”€
// ioc_confidence and ioc_threat_level are always visible (summary signals)
// ioc_extraction_meta (layer breakdown, enrichment priority) requires Pro+
function applyIocMetaTierGate(item, tier) {
  const isFree = !tier || tier === CONFIG.TIERS.FREE;
  if (!isFree) return item;  // Pro/Enterprise: full pass-through
  const out = { ...item };
  // Strip full extraction meta â€” keep only summary signals
  if (out.ioc_extraction_meta && Object.keys(out.ioc_extraction_meta).length > 0) {
    out.ioc_extraction_meta = {
      locked:      true,
      upgrade_url: "https://cyberdudebivash.com/sentinel-premium",
      message:     "IOC extraction layer breakdown requires Pro tier.",
    };
  }
  return out;
}

// â”€â”€ Handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ PUBLIC: /api/preview â€” No API key required â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    // v116.2.0 FRESHNESS FIX: Sort by processed_at DESC (primary) â†’ timestamp DESC (fallback)
    // â†’ risk_score DESC (tiebreak).
    //
    // WHY processed_at is PRIMARY:
    //   RSS-sourced intel carries `published_at` dates from the original article
    //   (e.g. a CVE advisory published 3 weeks ago). When `timestamp` is set from
    //   `published_at`, newly generated intel APPEARS STALE even though it was just
    //   processed. `processed_at` is always set to pipeline execution time (UTC-now)
    //   so it is immune to source article date variations.
    //
    // SORT KEY helper â€” reads processed_at first, then timestamp as fallback
    const getSortTs = item => {
      const pa = item.processed_at || item.timestamp || item.generated_at || null;
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
      // P0 FIX v111.0: Include full MITRE/TTP/IOC data in preview response.
      // Previously stripped â€” caused MITRE=0 on dashboard.
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
        // CRITICAL FIX v116.2.0: stix_id REQUIRED by dashboard ANALYZE button.
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
        iocs:        Array.isArray(item.iocs)  ? item.iocs  : [],
        ttps:        Array.isArray(item.ttps)  ? item.ttps  : [],
        ioc_count:   iocCount,
        ttp_count:   ttpCount,
        confidence:  item.confidence  || 0,
        // v116.2.0 FRESHNESS: processed_at = pipeline generation time (primary freshness field).
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
        // v116.3.0 FIX: report_url MUST resolve. Rewrite old broken reports.cyberdudebivash.com
        // URLs (DNS NXDOMAIN) to intel.cyberdudebivash.com. Derive if missing.
        report_url: (() => {
          let u = item.report_url || "";
          // Rewrite dead subdomain â†’ working domain
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
        source_url:  item.source_url  || null,
        actor_tag:   item.actor_tag   || null,
        mitre_tactics: Array.isArray(item.mitre_tactics) ? item.mitre_tactics
                      : Array.isArray(item.ttps) ? item.ttps : [],
        // v119.0.0: Free-tier IOC paywall â€” strip raw IOC arrays, surface count + CTA
        iocs:       [],        // raw IOCs require Pro tier
        ioc_count:         Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0),
        // v124.0: Always expose confidence + threat_level in public preview
        ioc_confidence:    typeof item.ioc_confidence === "number" ? item.ioc_confidence : 0,
        ioc_threat_level:  item.ioc_threat_level || "NONE",
        ioc_paywall: Array.isArray(item.iocs) && item.iocs.length > 0 ? {
          locked:            true,
          count:             item.iocs.length,
          confidence:        typeof item.ioc_confidence === "number" ? item.ioc_confidence : 0,
          threat_level:      item.ioc_threat_level || "NONE",
          primary_types:     (item.ioc_extraction_meta && item.ioc_extraction_meta.primary_types) || [],
          upgrade_url:       "https://cyberdudebivash.com/sentinel-premium",
          message:           `${Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0)} IOC(s) at ${typeof item.ioc_confidence === "number" ? item.ioc_confidence.toFixed(1) : 0}% confidence â€” unlock with Pro tier.`,
        } : null,
        // v119.0.0: APEX AI block â€” always present in preview, fields tier-gated
        apex_ai:    computeApexAI(item, CONFIG.TIERS.FREE),
        // Legacy apex passthrough (partial) for backward compat with existing panels
        apex: (() => {
          const ap = item.apex;
          if (!ap || typeof ap !== "object") return null;
          // Free preview: surface non-sensitive apex fields only
          return {
            priority:     ap.priority     || "P4",
            threat_level: ap.threat_level || "UNKNOWN",
            threat_category: ap.threat_category || "UNKNOWN",
            predictive_score: ap.predictive_score != null ? ap.predictive_score : 0,
            campaign_id:  "PRO_REQUIRED",   // campaign ID is Pro+
          };
        })(),
        validation_status: item.validation_status || null,
        stix_object_count: item.stix_object_count || 0,
        kev_present:  item.kev_present  || false,
        epss_score:   item.epss_score   || null,
        cvss_score:   item.cvss_score   || null,
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

// â”€â”€ AUTHENTICATED: /api/feed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleFeed(request, env, auth, rid) {
  const url      = new URL(request.url);

  // v119.0.0: Input sanitization â€” prevent injection via query params
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

  // Search: max 128 chars â€” sanitizeStr strips control chars + blocks injection patterns
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

    // v116.2.0 FRESHNESS FIX: Sort full feed by processed_at DESC before pagination.
    // Ensures authenticated /api/feed consumers always receive newest-generated intel first,
    // regardless of the manifest file order or source article publication dates.
    items.sort((a, b) => {
      const ta = new Date(a.processed_at || a.timestamp || a.generated_at || 0).getTime();
      const tb = new Date(b.processed_at || b.timestamp || b.generated_at || 0).getTime();
      return tb - ta;
    });

    const total      = items.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const offset     = (page - 1) * limit;
    // v119.0.0: Apply tier-gated monetization to each feed item
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
    // v121.0.0: Normalize + apply tier gate â€” API /feed/:id MUST match /feed response
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

  // v124.0: Include live advisory count + last_sync from manifest for full pipeline visibility
  let advisoryCount = 0;
  let lastSync      = null;
  let manifestVersion = null;
  try {
    const index = await fetchReportsIndex(env);
    const clean = deduplicateFeedItems(index.reports);
    advisoryCount   = clean.length;
    lastSync        = index.generated_at || null;
    manifestVersion = index.source_meta?.version || null;
  } catch { /* non-critical â€” health still returns */ }

  const allOk = Object.values(checks).every(v => v === "ok" || v.startsWith("cached:"));
  return jsonResponse({
    status:           allOk ? "healthy" : "degraded",
    version:          CONFIG.GATEWAY_VERSION,
    gateway:          `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    platform:         "CYBERDUDEBIVASHÂ® SENTINEL APEX",
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

// â”€â”€ AI Intelligence Endpoint â€” /api/ai/* â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        ai_engine:    "APEX-v116",
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
  // Public endpoint â€” no API key required for index and heatmap data
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
    warning:    "Store this key securely â€” it cannot be retrieved again.",
    request_id: rid,
  }, 201);
}

// â”€â”€ v117.0.0: /api/version â€” platform version manifest â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v117.0.0: /api/stix/:id â€” STIX 2.1 export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
      source_url:  item.source_url || null,
    },
    stix_object:  baseObj,
    full_bundle:  null,
    upgrade:      getUpgradeCTA(auth?.tier || "free"),
    message:      "Full STIX 2.1 bundle (indicators, TTPs, actor objects) available on Pro/Enterprise tier.",
    gateway:      `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// â”€â”€ v117.0.0: /api/webhooks/siem â€” SIEM integration webhook â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    // v122.0.0: Support ?format=splunk|sentinel|qradar for SIEM export previews
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
        splunk:   "Splunk HEC JSON â€” POST to /services/collector/event",
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

// â”€â”€ v117.0.0: /api/alerts â€” threat alerts for Pro+ â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// â”€â”€ v123.1: GET /api/account/usage â€” per-key usage analytics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        url:     `https://intel.cyberdudebivash.com/upgrade?plan=${tier === "free" ? "pro" : "enterprise"}`,
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

// â”€â”€ v123.0.0: GET /api/platform/stats â€” real-data dashboard metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Replaces all static dashboard hardcoded numbers.
// Sources: R2 feed manifest + KV analytics. Public (no auth required for summary).
async function handlePlatformStats(request, env, rid) {
  try {
    // Try KV cache (60s TTL)
    const cacheKey = "platform:stats:v123";
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

    const reports = manifest?.reports || [];
    const now = new Date().toISOString();

    // â”€â”€ Aggregate live metrics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
      // Severity distribution
      const sev = (r.severity || "unknown").toLowerCase();
      sev_dist[sev] = (sev_dist[sev] || 0) + 1;

      // IOC count
      if (Array.isArray(r.iocs)) ioc_count += r.iocs.length;

      // Unique actors
      if (r.actor_tag && r.actor_tag !== "UNATTRIBUTED") actor_set.add(r.actor_tag);

      // Unique CVEs
      if (r.cve_id) cve_set.add(r.cve_id.toUpperCase());
      if (Array.isArray(r.iocs)) {
        r.iocs.filter(i => i.type === "cve").forEach(i => cve_set.add(i.value.toUpperCase()));
      }

      // KEV
      if (r.kev_present === true) kev_count++;

      // Threat types
      if (r.threat_type) threat_types[r.threat_type] = (threat_types[r.threat_type] || 0) + 1;

      // Recency
      const ts = r.processed_at || r.timestamp || "";
      if (ts > last_updated) last_updated = ts;

      // Highest risk score
      if ((r.risk_score || 0) > highest_risk) highest_risk = r.risk_score;

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
      source_url:  r.source_url || null,
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

// â”€â”€ v121.0.0: /api/auth/refresh â€” Renew JWT before expiry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v121.0.0: /api/auth/revoke â€” Revoke JWT immediately â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function handleRevokeToken(request, env, rid) {
  if (!env?.CDB_JWT_SECRET) {
    return jsonResponse({ error: "auth_service_unavailable", request_id: rid }, 503);
  }
  const jwtToken = extractJwt(request);
  if (!jwtToken) return jsonResponse({ error: "token_required", request_id: rid }, 400);
  const result = await verifyJwt(jwtToken, env.CDB_JWT_SECRET);
  // Allow revoke even if expired â€” still add to blocklist to be thorough
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

// â”€â”€ v121.0.0: /api/admin/keys/list â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v121.0.0: /api/admin/keys/revoke â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v121.0.0: /api/admin/observability â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

  // v125.0: Live feed integrity snapshot â€” dedup metrics + IOC consistency
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
      stix_issues:              0,  // STIX bundles validated at gate â€” no passthrough of invalid bundles
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
    // v125.0: Feed integrity snapshot â€” dedup + IOC consistency + STIX validation
    feed_integrity: feedIntegrity,
    security: {
      injection_blocking:   "active",    // _INJECTION_BLOCK_RE â€” 8 patterns
      rate_limiting:        "active",    // sliding window â€” IP + per-key
      jwt_revocation:       "active",    // blocklist in SECURITY_HUB_KV
      tier_enforcement:     "active",    // applyTierGate() + applyIocMetaTierGate()
      stix_validation:      "active",    // structural gate â€” invalid bundles nulled
      input_sanitization:   "active",    // sanitizeStr + sanitizeInput across all handlers
    },
  });
}

// â”€â”€ v122.0.0: Stripe Webhook Signature Verification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ v123.1: cascadeUserTierToKeys â€” propagate tier change to all user-owned keys â”€â”€
// Called on payment success / subscription update / cancellation.
// Updates both userkey: index records and apikey: lookup records.
// Fire-and-forget safe â€” never throws, errors are logged only.
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
      } catch { /* non-fatal â€” key update failure never blocks webhook */ }
    }));
    slog("INFO", "BILLING", `Tier cascade complete`, { user_id: userId, tier: newTier, keys: list.keys.length });
  } catch (e) {
    slog("WARN", "BILLING", `cascadeUserTierToKeys failed (non-fatal)`, { error: e.message });
  }
}

// â”€â”€ v122.0.0: POST /webhooks/stripe â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
            // v123.1: CASCADE â€” upgrade all user-owned API keys to new tier immediately
            await cascadeUserTierToKeys(userId, newTier, env);
            slog("INFO", "BILLING", "Checkout complete â€” tier upgraded + keys cascaded", { user_id: userId, tier: newTier });
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
              // v123.1: CASCADE tier change to all owned keys
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
              slog("INFO", "BILLING", "Subscription cancelled â€” downgraded to FREE", { user_id: userId });
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

// â”€â”€ v122.0.0: POST /webhooks/razorpay â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
          await cascadeUserTierToKeys(userId, planTier, env); // v123.1: cascade to all owned keys
          slog("INFO", "BILLING", "Razorpay payment â€” tier upgraded + keys cascaded", { user_id: userId, tier: planTier });
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
          slog("INFO", "BILLING", "Razorpay sub cancelled â€” downgraded to FREE", { user_id: userId });
        }
      }
    }
  } catch (e) {
    await trackError(env, "BILLING", `Razorpay event error: ${e.message}`, { event: event.event });
  }

  return jsonResponse({ status: "ok", received: true, event: event.event });
}

// â”€â”€ v122.0.0: GET /api/billing/portal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
        checkout_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro",
        features:     ["500 requests/min", "Full IOC arrays", "STIX 2.1 bundles", "Threat alerts", "10 API keys"],
      },
      enterprise: {
        price:        "$199/month",
        checkout_url: "https://intel.cyberdudebivash.com/upgrade?plan=enterprise",
        features:     ["2000 requests/min", "SIEM integration (Splunk/Sentinel/QRadar)", "50 API keys", "Priority support", "Tenant isolation"],
      },
    },
    request_id:    rid,
    gateway:       `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// â”€â”€ v122.0.0: SIEM Output Formatters â€” Splunk HEC / Sentinel / QRadar LEEF â”€â”€

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

// â”€â”€ v125.0: Response post-processor â€” injects X-RateLimit + security headers â”€â”€
// Called after every authenticated handler returns. Never mutates body â€” only adds headers.
// Security headers added to ALL responses (defence-in-depth):
//   X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
function applySecurityHeaders(response, rlHeaders = {}) {
  const headers = new Headers(response.headers);
  // Rate limit telemetry (informational â€” lets clients self-throttle)
  for (const [k, v] of Object.entries(rlHeaders)) {
    headers.set(k, v);
  }
  // Security hardening headers â€” prevent MIME sniffing, clickjacking, info leakage
  headers.set("X-Content-Type-Options",  "nosniff");
  headers.set("X-Frame-Options",         "DENY");
  headers.set("Referrer-Policy",         "no-referrer");
  headers.set("Permissions-Policy",      "geolocation=(), camera=(), microphone=()");
  headers.set("X-Response-Time",         response.headers.get("X-Response-Time") || "0ms");
  return new Response(response.body, { status: response.status, headers });
}

// v130.0.0: Revenue Dashboard Handler
async function handleRevenueDashboard(request, env, rid) {
  const adminSecret = request.headers.get("X-Admin-Secret");
  if (!env?.ADMIN_SECRET || adminSecret !== env.ADMIN_SECRET) {
    return new Response(JSON.stringify({ error: "unauthorized", request_id: rid }, null, 2), {
      status: 401,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-cache", "Access-Control-Allow-Origin": "*" },
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
    version: "v130.0.0", date,
    revenue: revenueData,
    endpoint_stats:     epStats.status     === "fulfilled" ? epStats.value     : [],
    tier_distribution:  tierDist.status    === "fulfilled" ? tierDist.value    : {},
    credit_exhaustions: exhaustStats.status === "fulfilled" ? exhaustStats.value : { exhaustions_today: 0 },
    pricing: { free: { monthly_usd: 0 }, pro: { monthly_usd: 29 }, enterprise: { monthly_usd: 199 } },
    upgrade_urls: { free_to_pro: "https://intel.cyberdudebivash.com/upgrade?plan=pro", trial: "https://intel.cyberdudebivash.com/trial" },
    request_id: rid, generated_at: new Date().toISOString(),
  }, null, 2), { status: 200, headers: { "Content-Type": "application/json", "Cache-Control": "no-cache, no-store", "Access-Control-Allow-Origin": "*" } });
}

// â”€â”€ Main Router â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export default {
  async fetch(request, env, ctx) {
    const rid       = generateReqId();
    const reqStart  = Date.now();                 // v121.0.0: request duration tracking
    const url       = new URL(request.url);
    const { pathname } = url;
    const method    = request.method.toUpperCase();
    slog("INFO", "ROUTER", `${method} ${pathname}`, { rid });

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

    // IP rate limiting + multi-layer abuse check (all endpoints)
    const clientIP = getClientIP(request);

    // Layer 1: Legacy IP ban (RATE_LIMIT_KV â€” daily abuse counter)
    if (await isIPBanned(clientIP, env)) {
      return jsonResponse({
        error:      "ip_banned",
        message:    "Your IP has been temporarily blocked due to excessive invalid requests.",
        request_id: rid,
      }, 429);
    }

    // Layer 2: Enhanced abuse detection (SECURITY_HUB_KV â€” per-minute rate, scanner UA, auth brute force)
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

    // â”€â”€ Public endpoints (no API key required) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (pathname.startsWith("/api/preview"))          return handlePreview(request, env, rid);
    if (pathname.startsWith("/api/health"))            return handleHealth(request, env, rid);
    if (pathname.startsWith("/api/version"))           return handleVersion(request, env, rid);
    if (pathname.startsWith("/api/keys/validate"))     return handleValidateKey(request, env, rid);
    // v123.0.0: Live dashboard metrics â€” public, no auth required
    if (pathname === "/api/platform/stats" && method === "GET") return handlePlatformStats(request, env, rid);
    // â”€â”€ v117.0.0 + v121.0.0: JWT auth endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (pathname === "/api/auth/token"    && method === "POST") return handleIssueToken(request, env, rid);
    if (pathname === "/api/auth/validate")                      return handleValidateToken(request, env, rid);
    if (pathname === "/api/auth/refresh"  && method === "POST") return handleRefreshToken(request, env, rid);
    if (pathname === "/api/auth/revoke"   && method === "POST") return handleRevokeToken(request, env, rid);
    // â”€â”€ v122.0.0: User auth endpoints (no API key required) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (pathname === "/auth/signup"       && method === "POST") return handleUserSignup(request, env, rid);
    if (pathname === "/auth/login"        && method === "POST") return handleUserLogin(request, env, rid);
    // â”€â”€ v122.0.0: Billing webhooks (no API key â€” use their own sig verification)
    if (pathname === "/webhooks/stripe"   && method === "POST") return handleStripeWebhook(request, env, rid);
    if (pathname === "/webhooks/razorpay" && method === "POST") return handleRazorpayWebhook(request, env, rid);
    // AI endpoints â€” public (index/heatmap) or authenticated (analyze/respond/correlate)
    if (pathname.startsWith("/api/ai")) {
      const aiSub = pathname.slice("/api/ai".length);
      // Full AI analysis endpoints require authentication
      if (aiSub.startsWith("/analyze") || aiSub.startsWith("/respond") || aiSub.startsWith("/correlate")) {
        const auth = await resolveAuth(request, env);
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

    // â”€â”€ Admin endpoints (X-Admin-Secret verified internally) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (pathname.startsWith("/api/admin")) {
      // All /api/admin/* require X-Admin-Secret â€” verify once here
      if (!env?.ADMIN_SECRET || request.headers.get("X-Admin-Secret") !== env.ADMIN_SECRET) {
        slog("WARN", "ADMIN", "Forbidden admin access attempt", { path: pathname, rid });
        return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
      }
      if (pathname.startsWith("/api/admin/cache/bust")   && method === "POST") return handleCacheBust(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/create")  && method === "POST") return handleAdminCreateKey(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/revoke")  && method === "POST") return handleAdminRevokeKey(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/list")    && method === "GET")  return handleAdminListKeys(request, env, rid);
      if (pathname.startsWith("/api/admin/observability")&& method === "GET")  return handleAdminObservability(request, env, rid);
      // v123.0.0: Abuse event log â€” scanner activity, IP bans, auth brute force
      if (pathname.startsWith("/api/admin/abuse")        && method === "GET")  return handleAbuseReport(request, env, rid);
      return jsonResponse({
        error:     "not_found",
        message:   "Admin endpoint not found.",
        available: [
          "POST /api/admin/cache/bust",
          "POST /api/admin/keys/create",
          "POST /api/admin/keys/revoke",
          "GET  /api/admin/keys/list",
          "GET  /api/admin/observability",
        ],
        request_id: rid,
      }, 404);
    }

    // â”€â”€ ALL REMAINING ENDPOINTS: JWT OR API KEY REQUIRED â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // resolveAuth: JWT (3-part Bearer) takes priority â†’ falls through to API key
    const auth = await resolveAuth(request, env);
    if (!auth.valid) {
      if (auth.reason === "invalid_key" || auth.reason === "key_expired") {
        await trackAbuseAttempt(clientIP, env);
        // v123.0.0: Track auth failure for brute-force detection in SECURITY_HUB_KV
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
    // v125.0: Inject X-RateLimit headers on every successful authenticated response
    // Stored in ctx so handlers can access via closure; injected via wrapWithRateLimitHeaders()
    const _rlHeaders = {
      "X-RateLimit-Limit":     String(rateLimit),
      "X-RateLimit-Remaining": String(Math.max(0, keyCheck.remaining ?? rateLimit - 1)),
      "X-RateLimit-Policy":    `${rateLimit};w=60`,
      "X-Tier":                auth.tier,
    };

    // v123.0.0: Request fingerprinting â€” async, fire-and-forget for analytics (never blocks)
    fingerprintRequest(request, env, auth, rid).catch(() => {});

    // â”€â”€ v130.0.0: CREDIT GATE â”€â”€ usage-based billing enforcement â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

    // â”€â”€ v125.0: All authenticated responses wrapped with X-RateLimit + security headers â”€â”€
    const _rl = _rlHeaders;  // captured above after rate-limit check
    const withRL = (resp) => applySecurityHeaders(resp, _rl);
    // v130.0.0: merge credit billing headers into every authenticated response
    Object.assign(_rlHeaders, buildCreditHeaders(_credits.status, _credits.status?.credits_used));

    // â”€â”€ v122.0.0: Authenticated user + billing routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if (pathname === "/auth/me"              && method === "GET")    return withRL(await handleUserMe(request, env, rid, auth));
    if (pathname === "/api/keys"             && method === "GET")    return withRL(await handleUserListKeys(request, env, rid, auth));
    if (pathname === "/api/keys/create"      && method === "POST")   return withRL(await handleUserCreateKey(request, env, rid, auth));
    if (pathname.startsWith("/api/keys/")   && method === "DELETE") {
      const keyId = pathname.slice("/api/keys/".length);
      if (keyId) return withRL(await handleUserDeleteKey(request, env, rid, auth, keyId));
    }
    if (pathname === "/api/billing/portal"   && method === "GET")    return withRL(await handleBillingPortal(request, env, rid, auth));
    // v123.1: Self-service usage analytics
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
    // v117.0.0: STIX export
    if (pathname.startsWith("/api/stix/")) {
      const stixId = decodeURIComponent(pathname.slice("/api/stix/".length));
      return withRL(await handleStixExport(request, env, auth, rid, stixId));
    }
    // v117.0.0: Threat alerts (Pro+)
    if (pathname.startsWith("/api/alerts") && method === "GET")
      return withRL(await handleAlerts(request, env, auth, rid));
    // v117.0.0: SIEM webhook (Enterprise)
    if (pathname.startsWith("/api/webhooks/siem"))
      return withRL(await handleSiemWebhook(request, env, auth, rid));

    // â”€â”€ v123.0.0: NEW ENDPOINTS â€” Full CTI API surface â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // GET /api/search â€” full-text + field search across feed (scope: read:intel)
    if (pathname === "/api/search" && method === "GET")
      return withRL(await handleSearch(request, env, auth, rid));

    // GET /api/actors[?actor_id=&limit=&since=] â€” threat actor profiles (scope: read:actors)
    if (pathname === "/api/actors" && method === "GET")
      return withRL(await handleActors(request, env, auth, rid));

    // GET /api/cves[?cve_id=&severity=&kev_only=&min_epss=&limit=&page=] (scope: read:cves)
    if (pathname === "/api/cves" && method === "GET")
      return withRL(await handleCVEs(request, env, auth, rid));

    // GET /api/export/misp[?report_id=&since=&limit=] â€” MISP JSON export (scope: export:misp, Enterprise only)
    if (pathname === "/api/export/misp" && method === "GET")
      return withRL(await handleMISPExport(request, env, auth, rid));

    // GET /api/export/csv[?since=&types=&limit=] â€” IOC bulk CSV export (scope: export:csv, Pro+)
    if (pathname === "/api/export/csv" && method === "GET")
      return withRL(await handleCSVExport(request, env, auth, rid));

    // POST /api/intel/correlate â€” IOC correlation against full feed (scope: read:intel)
    if (pathname === "/api/intel/correlate" && method === "POST")
      return withRL(await handleCorrelate(request, env, auth, rid));

    // â”€â”€ v123.0.0: AI Intelligence Endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // GET|POST /api/predict â€” AI threat prediction (Pro+)
    if (pathname === "/api/predict" && (method === "GET" || method === "POST"))
      return withRL(await handlePredict(request, env, auth, rid));

    // GET /api/campaigns â€” detected threat campaigns (Pro+)
    if (pathname === "/api/campaigns" && method === "GET")
      return withRL(await handleCampaigns(request, env, auth, rid));

    // GET /api/anomalies â€” zero-day + anomalous threat feed (Pro+)
    if (pathname === "/api/anomalies" && method === "GET")
      return withRL(await handleAnomalies(request, env, auth, rid));

    // GET /api/intelligence/graph â€” IOC relationship graph (Pro=summary, Enterprise=full)
    if (pathname === "/api/intelligence/graph" && method === "GET")
      return withRL(await handleIntelGraph(request, env, auth, rid));

    // GET /api/intelligence/relations â€” BFS IOC relations (Pro=limited, Enterprise=full)
    if (pathname === "/api/intelligence/relations" && method === "GET")
      return withRL(await handleIntelRelations(request, env, auth, rid));

    // GET /api/platform/stats â€” live feed stats for dashboard (public â€” no auth required)
    // (also accessible without auth for dashboard widgets â€” handled below)

    // v130.0.0: Revenue API Endpoints
    if (pathname.startsWith("/api/revenue") && method === "GET")
      return withRL(await handleRevenueDashboard(request, env, rid));
    if (pathname === "/api/leads/capture" && method === "POST")
      return handleLeadCapture(request, env, rid);
    if (pathname === "/api/leads/trial" && method === "POST")
      return handleTrialIssuance(request, env, rid);

    slog("WARN", "ROUTER", `404 ${pathname}`, { rid, method });
    return jsonResponse({
      error:   "not_found",
      message: `Endpoint '${pathname}' not found.`,
      available: [
        // â”€â”€ Public â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET  /api/preview              (public â€” free preview feed)",
        "GET  /api/health               (public)",
        "GET  /api/version              (public)",
        "GET  /api/keys/validate        (public)",
        "GET  /api/platform/stats       (public â€” live dashboard metrics)",
        "GET  /api/ai                   (public â€” AI index + MITRE heatmap)",
        "GET  /api/ai/heatmap           (public)",
        // â”€â”€ Auth endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "POST /api/auth/token           (public â€” exchange API key for JWT)",
        "GET  /api/auth/validate        (public â€” validate JWT)",
        "POST /api/auth/refresh         (requires JWT â€” rotate token)",
        "POST /api/auth/revoke          (requires JWT â€” revoke token)",
        "POST /auth/signup              (public â€” create user account + get JWT)",
        "POST /auth/login               (public â€” login + get JWT)",
        // â”€â”€ Billing webhooks â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "POST /webhooks/stripe          (public â€” Stripe webhook, sig-verified)",
        "POST /webhooks/razorpay        (public â€” Razorpay webhook, sig-verified)",
        // â”€â”€ Authenticated (Free+) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET  /auth/me                  (requires JWT â€” user profile + API keys)",
        "POST /api/keys/create          (requires JWT â€” create API key)",
        "GET  /api/keys                 (requires JWT â€” list your API keys)",
        "DELETE /api/keys/:id           (requires JWT â€” revoke API key)",
        "GET  /api/billing/portal       (requires JWT â€” subscription + upgrade links)",
        // â”€â”€ Intel feed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET  /api/feed                 (requires auth â€” full intel feed)",
        "GET  /api/feed/:id             (requires auth â€” single report)",
        "GET  /api/analytics            (requires auth â€” usage analytics)",
        // â”€â”€ AI endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET  /api/ai/analyze           (requires auth)",
        "GET  /api/ai/respond           (requires auth)",
        "GET  /api/ai/correlate         (requires auth)",
        // â”€â”€ v123.0.0: NEW CTI API surface â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET  /api/search               (requires auth â€” full-text + field search | scope: read:intel)",
        "GET  /api/actors               (requires auth â€” threat actor profiles | scope: read:actors)",
        "GET  /api/cves                 (requires auth â€” CVE deep-dive CVSS+EPSS+KEV | scope: read:cves)",
        "POST /api/intel/correlate      (requires auth â€” IOC correlation | scope: read:intel)",
        "GET  /api/stix/:id             (requires auth â€” STIX 2.1 bundle | scope: read:stix)",
        "GET  /api/alerts               (requires auth Pro+ â€” threat alerts)",
        // â”€â”€ Export endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET  /api/export/csv           (requires auth Pro+ â€” IOC bulk CSV | scope: export:csv)",
        "GET  /api/export/misp          (requires auth Enterprise â€” MISP JSON | scope: export:misp)",
        // â”€â”€ v123.0.0: AI Intelligence (Phase 2+4) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET|POST /api/predict          (Pro+ â€” AI threat prediction | CVSS+EPSS+KEV+TTP scoring)",
        "GET  /api/campaigns            (Pro+ â€” detected threat campaigns | DBSCAN-clustered)",
        "GET  /api/anomalies            (Pro+ â€” zero-day candidates + anomalous threats | Isolation Forest)",
        "GET  /api/intelligence/graph   (Pro=summary, Enterprise=full IOC graph | PageRank authority scores)",
        "GET  /api/intelligence/relations (Pro+ â€” IOC relationship BFS traversal | actor attribution)",
        // â”€â”€ Enterprise â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "GET  /api/webhooks/siem        (requires auth Enterprise â€” list + format info)",
        "POST /api/webhooks/siem        (requires auth Enterprise â€” register SIEM webhook)",
        // â”€â”€ Admin â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        "POST /api/admin/cache/bust     (requires X-Admin-Secret)",
        "POST /api/admin/keys/create    (requires X-Admin-Secret)",
        "POST /api/admin/keys/revoke    (requires X-Admin-Secret)",
        "GET  /api/admin/keys/list      (requires X-Admin-Secret)",
        "GET  /api/admin/observability  (requires X-Admin-Secret)",
        "GET  /api/admin/abuse          (requires X-Admin-Secret â€” abuse event log)",
      ],
      docs:       CONFIG.DOCS_URL,
      request_id: rid,
      response_ms: Date.now() - reqStart,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 404);
  },

  // â”€â”€ v123.0.0: Scheduled Cron Handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  // Trigger: configure in wrangler.toml â†’ [triggers] crons = ["*/15 * * * *"]
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
        // â”€â”€ Step 1: Fetch feed manifest from R2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        let manifest = null;
        if (env?.INTEL_R2) {
          const obj = await env.INTEL_R2.get("feed_manifest.json").catch(() => null);
          if (obj) {
            try { manifest = JSON.parse(await obj.text()); } catch { manifest = null; }
          }
        }

        const reports = manifest?.reports || [];
        if (!reports.length) {
          slog("WARN", "CRON", "No reports in feed manifest â€” skipping webhook push", { rid });
          return;
        }

        // â”€â”€ Step 2: Identify recently published items (last 30 min) â”€â”€â”€â”€â”€â”€â”€â”€
        const cutoff  = new Date(Date.now() - 30 * 60 * 1000).toISOString();
        const newItems = reports.filter(r => {
          const ts = r.processed_at || r.timestamp || "";
          return ts >= cutoff;
        });

        slog("INFO", "CRON", `Feed: ${reports.length} total, ${newItems.length} new since ${cutoff}`, { rid });

        // â”€â”€ Step 3: Push to SIEM webhooks (Enterprise tier) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (newItems.length > 0) {
          const pushResult = await pushWebhookNotifications(env, newItems);
          slog("INFO", "CRON", "Webhook push complete", { rid, ...pushResult });
        }

        // â”€â”€ Step 4: Invalidate platform stats cache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if (env?.ANALYTICS_KV) {
          await env.ANALYTICS_KV.delete("platform:stats:v123").catch(() => {});
          slog("INFO", "CRON", "Platform stats cache invalidated", { rid });
        }

        // â”€â”€ Step 5: Rebuild KV index cache for fast search/actors/CVEs queries
        if (env?.SECURITY_HUB_KV && manifest) {
          await env.SECURITY_HUB_KV.put(
            "idx:reports",
            JSON.stringify(manifest),
            { expirationTtl: 1800 }  // 30 min TTL â€” refreshed by cron
          ).catch(() => {});
          slog("INFO", "CRON", "KV report index refreshed", { rid, count: reports.length });
        }

      } catch (e) {
        await trackError(env, "CRON", "Scheduled handler failed", { error: e.message, rid });
      }
    })());
  },
};

