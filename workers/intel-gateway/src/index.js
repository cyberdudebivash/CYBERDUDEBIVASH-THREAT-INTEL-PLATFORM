// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Edge Intelligence Gateway v123.0.0
// R2-ONLY ARCHITECTURE — Blogger dependency REMOVED
// Data flow: GitHub Actions → Cloudflare R2 (private) → Worker → API clients
// Intel data NEVER stored in public GitHub repo (EMBEDDED_INTEL obsolete).
// Secrets: ADMIN_SECRET, GITHUB_TOKEN, CDB_JWT_SECRET (npx wrangler secret put)
//          STRIPE_WEBHOOK_SECRET, RAZORPAY_WEBHOOK_SECRET (billing webhooks)
//          STRIPE_PRO_PRICE_ID, STRIPE_ENT_PRICE_ID (Stripe plan IDs)
// v112.0: Added /api/ai endpoint family
// v116.2.0: stix_id fix; GATEWAY_VERSION unified
// v120.0.0: GOD-MODE — mandatory ai_summary, retry circuit breaker, urgency CTAs
// v121.0.0: FINAL HARDENING — structured logging, schema validation, JWT revocation,
//           token refresh/revoke, usage caps, observability, API/feed consistency
// v122.0.0: SAAS TRANSFORMATION — user auth (PBKDF2), API key CRUD, billing
//           (Stripe/Razorpay webhooks), IOC extraction fallback (min 3),
//           SIEM formatters (Splunk/Sentinel/QRadar), pricing page
// v123.0.0: PRODUCTION HARDENING — replay attack prevention, last_used/usage_count
//           tracking, IOC CSV/JSON export, usage metering API, Elastic SIEM,
//           webhook retry+failure tracking, org/team system, frontend auth sync
// =============================================================================

const CONFIG = {
  GATEWAY_VERSION:   "123.0.0",  // v123.0.0: PRODUCTION HARDENING — replay protect, metering, org, Elastic SIEM
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

// ── v121.0.0: Structured Logger ───────────────────────────────────────────────
// ALL log output is structured JSON — searchable in Cloudflare Workers Tail Logs.
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

// ── v121.0.0: Error Tracking — persists to SECURITY_HUB_KV (7-day rolling) ───
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
  } catch { /* non-critical — never let observability kill a request */ }
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

// ── v117.0.0: JWT Auth — HS256 via Web Crypto API ─────────────────────────────
// Uses CDB_JWT_SECRET from Cloudflare secret (set via: npx wrangler secret put CDB_JWT_SECRET)
// ZERO ephemeral fallback: if CDB_JWT_SECRET is missing, auth endpoints return 503.
// Token format: standard JWT HS256 — header.payload.signature (base64url encoded)

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

// ── v121.0.0: JWT Revocation Blocklist ───────────────────────────────────────
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

// ── v122.0.0: PBKDF2 Password Hashing ────────────────────────────────────────
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

// ── v122.0.0: POST /auth/signup ───────────────────────────────────────────────
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
    name:              (typeof name === "string" && name.trim()) ? name.trim() : emailNorm.split("@")[0],
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

// ── v122.0.0: POST /auth/login ────────────────────────────────────────────────
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
    slog("WARN", "AUTH", "Login failed — bad password", { user_id: userId });
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

// ── v122.0.0: GET /auth/me ────────────────────────────────────────────────────
async function handleUserMe(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId     = auth.user_id || auth.key_id;
  const userRecord = userId ? await env.API_KEYS_KV.get(`user:${userId}`, { type: "json" }).catch(() => null) : null;

  if (!userRecord) {
    // Legacy API key auth — return synthetic user context
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

// ── v122.0.0: POST /api/keys/create ──────────────────────────────────────────
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
    label:       String(label).slice(0, 100),
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
    warning:      "Store this API key securely — it will NOT be shown again.",
    request_id:   rid,
    gateway:      `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  }, 201);
}

// ── v122.0.0: GET /api/keys ───────────────────────────────────────────────────
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

// ── v122.0.0: DELETE /api/keys/:id ───────────────────────────────────────────
async function handleUserDeleteKey(request, env, rid, auth, keyIdToDelete) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId    = auth.user_id || auth.key_id;
  const keyRecord = await env.API_KEYS_KV.get(`apikey:${keyIdToDelete}`, { type: "json" }).catch(() => null);

  if (!keyRecord) return jsonResponse({ error: "not_found", key_id: keyIdToDelete, request_id: rid }, 404);
  if (keyRecord.user_id && keyRecord.user_id !== userId)
    return jsonResponse({ error: "forbidden", message: "You do not own this API key.", request_id: rid }, 403);

  // Soft-revoke — preserves audit trail
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

// ── /api/auth/token — Issue JWT (POST, body: {api_key, tier}) ────────────────
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

// ── /api/auth/validate — Validate JWT (GET/POST) ──────────────────────────────
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

// ── Unified auth resolver: supports both JWT and legacy API keys ──────────────
// Priority: JWT (Bearer token with 3 parts) > Legacy API key (CDB-* / X-Api-Key)
// v121.0.0: Checks JWT revocation blocklist before accepting token.
async function resolveAuth(request, env) {
  // Try JWT first
  const jwtToken = extractJwt(request);
  if (jwtToken && env?.CDB_JWT_SECRET) {
    const result = await verifyJwt(jwtToken, env.CDB_JWT_SECRET);
    if (result.valid) {
      // v121.0.0: HARD check revocation blocklist — revoked tokens NEVER pass
      if (await isTokenRevoked(jwtToken, env)) {
        return { valid: false, reason: "token_revoked", auth_method: "jwt" };
      }
      return {
        valid:       true,
        tier:        result.payload.tier || CONFIG.TIERS.FREE,
        key_id:      result.payload.key_id,
        label:       result.payload.label,
        auth_method: "jwt",
      };
    }
    // JWT present but invalid — hard fail (no fallback to API key)
    return { valid: false, reason: result.reason, auth_method: "jwt" };
  }
  // Fall through to legacy API key resolution
  const legacy = await resolveApiKey(request, env);
  return { ...legacy, auth_method: "api_key" };
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
      // Increment usage counter (fire-and-forget — never block the request)
      env.API_KEYS_KV.put(usageKey, String(used + 1), { expirationTtl: 86400 * 35 }).catch(() => {});
    }

    // v123.0.0: Track last_used + lifetime usage_count (fire-and-forget — never block request)
    const now = new Date().toISOString();
    const updatedRecord = {
      ...stored,
      last_used:   now,
      usage_count: (typeof stored.usage_count === "number" ? stored.usage_count : 0) + 1,
    };
    env.API_KEYS_KV.put(`apikey:${keyId}`, JSON.stringify(updatedRecord)).catch(() => {});

    return {
      valid:       true,
      tier:        stored.tier || CONFIG.TIERS.FREE,
      key_id:      keyId,
      label:       stored.label,
      created_at:  stored.created_at,
      user_id:     stored.user_id || null,
      org_id:      stored.org_id  || null,
      org_role:    stored.org_role || null,
    };
  } catch (e) {
    slog("ERROR", "AUTH", "resolveApiKey failed", { error: e.message });
    return { valid: false, reason: "auth_error" };
  }
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

  // v116.2.0 FRESHNESS FIX: Inject processed_at fallback
  // v121.0.0: validateAndNormalizeItem() — guarantee no null fields across entire manifest
  const manifestGeneratedAt = data.generated_at || null;
  items = items.map(item => {
    // Inject processed_at before normalization so validator can use it
    if (!item.processed_at) {
      item = { ...item, processed_at: item.timestamp || item.generated_at || manifestGeneratedAt || null };
    }
    // v121.0.0: Full schema normalization — derives all missing fields, never null
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

// ── v120.0.0: Retry circuit breaker — exponential backoff, 3 attempts ─────────
// Prevents single transient failures from killing requests.
// 4xx (client errors) are NOT retried — only 5xx / network errors.
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
  // v120.0.0: fetchWithRetry — 3 attempts with backoff for transient GitHub/CDN errors
  const res = await fetchWithRetry(url, { headers, ...cfOpts });
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

// ── v120.0.0: computeApexAI — Full AI Intelligence Engine ─────────────────────
// Produces: predictive_risk, ai_confidence, actor_fingerprint, kill_chain, ttp_density, ai_summary
// v120.0.0 GOD-MODE: ai_summary is MANDATORY — teaser for free, full narrative for Pro/Enterprise
// ai_summary NEVER null — generated dynamically from item data when apex.ai_summary absent
// Safe: never throws — returns minimal object on any error

function computeApexAI(item, tier) {
  try {
    const isFree  = !tier || tier === CONFIG.TIERS.FREE;
    const isPro   = tier === CONFIG.TIERS.PREMIUM || tier === CONFIG.TIERS.ENTERPRISE;

    // ── Core scores ────────────────────────────────────────────────────────────
    const riskScore  = typeof item.risk_score  === "number" ? item.risk_score
                     : typeof item.cvss_score  === "number" ? item.cvss_score : 0;
    const epss       = typeof item.epss_score  === "number" ? item.epss_score : 0;
    const confidence = typeof item.confidence  === "number" ? item.confidence
                     : typeof item.confidence_score === "number" ? item.confidence_score : 0;
    const kev        = item.kev_present === true ? 1.0 : 0.0;
    const iocCount   = Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0);
    const ttpCount   = Array.isArray(item.ttps) ? item.ttps.length : (item.ttp_count || 0);

    // ── predictive_risk (0–10): composite risk projection ──────────────────────
    // Weights: CVSS 40%, EPSS 25%, KEV 20%, IOC density 15%
    const iocDensityScore = Math.min(iocCount * 0.5, 2.0);
    const predictiveRisk  = Math.min(10,
      (riskScore * 0.4) + (epss * 0.025) + (kev * 2.0) + (iocDensityScore * 0.15 * 10)
    );

    // ── ai_confidence (0–100): evidence quality score ──────────────────────────
    // Synthesises: base confidence + KEV bonus + STIX completeness + IOC density
    const stixObjects  = typeof item.stix_object_count === "number" ? item.stix_object_count : 0;
    const stixBonus    = Math.min(stixObjects * 1.5, 12);
    const iocBonus     = Math.min(iocCount * 2, 15);
    const kevBonus     = kev * 10;
    const aiConfidence = Math.min(100, Math.round(confidence + stixBonus + iocBonus + kevBonus));

    // ── actor_fingerprint: deterministic actor identity string ─────────────────
    const actorTag = item.actor_tag || (item.apex && item.apex.campaign_id) || "UNC-UNKNOWN";
    const severity = (item.severity || "UNKNOWN").toUpperCase();
    const sevCode  = { CRITICAL: "C", HIGH: "H", MEDIUM: "M", LOW: "L" }[severity] || "U";
    const actorFP  = isPro
      ? `${actorTag}::${sevCode}::IOC-${iocCount}::TTP-${ttpCount}`
      : `${actorTag.slice(0, 8)}****`; // partial for free tier

    // ── kill_chain: primary phase derived from TTPs / kill_chain_phases ─────────
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

    // ── ttp_density (0–10): attack sophistication density score ─────────────────
    // Higher = more diverse techniques used (sophisticated actor)
    const uniqueTtps  = new Set(rawTtps).size;
    const ttpDensity  = Math.min(10, parseFloat((
      (uniqueTtps * 0.8) + (iocCount * 0.3) + (riskScore * 0.2)
    ).toFixed(2)));

    // ── Existing apex block passthrough ───────────────────────────────────────
    const existingApex = (item.apex && typeof item.apex === "object") ? item.apex : {};

    // ── Tier-gated assembly ───────────────────────────────────────────────────
    const base = {
      soc_priority:    existingApex.priority      || (riskScore >= 9 ? "P1" : riskScore >= 7 ? "P2" : riskScore >= 5 ? "P3" : "P4"),
      threat_level:    existingApex.threat_level  || (riskScore >= 9 ? "CRITICAL_SURGE" : riskScore >= 7 ? "HIGH_ALERT" : riskScore >= 5 ? "MODERATE" : "LOW"),
      threat_category: existingApex.threat_category || "UNKNOWN",
      predictive_risk: parseFloat(predictiveRisk.toFixed(2)),
      ai_confidence:   aiConfidence,
      ttp_density:     ttpDensity,
      campaign_id:     existingApex.campaign_id   || "UNCLASSIFIED",
    };

    // ── v120.0.0: ai_summary is MANDATORY — always generated, never null ─────────
    // Free: intelligence teaser — whets appetite, drives upgrade
    // Pro/Enterprise: full tactical narrative
    const sevLabel   = severity === "CRITICAL" ? "CRITICAL-severity" : severity === "HIGH" ? "HIGH-severity" : severity.toLowerCase() + "-severity";
    const threatType = (item.threat_type || item.type || "threat").toUpperCase();
    const cveId      = item.cve_id || "";
    const cveStr     = cveId ? ` ${cveId}` : "";
    const srcLabel   = item.source ? ` via ${item.source}` : "";

    // Full narrative (Pro/Enterprise)
    const fullSummary = existingApex.ai_summary
      || `${sevLabel.toUpperCase()}${cveStr} — ${threatType} campaign detected${srcLabel}. Actor ${actorTag} leveraging ${ttpCount} technique${ttpCount !== 1 ? "s" : ""} across ${primaryPhase} phase. ${iocCount} indicator${iocCount !== 1 ? "s" : ""} identified (IOC density ${ttpDensity}/10). Predictive risk ${parseFloat(predictiveRisk.toFixed(1))}/10 — AI confidence ${aiConfidence}%. Priority: ${base.soc_priority}. Immediate SOC action required.`;

    // Teaser (Free) — enough to be credible, not enough to be actionable
    const teaserSummary = `⚡ ${sevLabel.toUpperCase()} threat detected${cveStr}. ${iocCount} IOC${iocCount !== 1 ? "s" : ""} identified, ${ttpCount} MITRE technique${ttpCount !== 1 ? "s" : ""} mapped. Predictive risk: ${parseFloat(predictiveRisk.toFixed(1))}/10. [UPGRADE TO PRO FOR FULL AI ANALYSIS →]`;

    if (isFree) {
      // Free: surface priority/risk/confidence but gate fingerprint, kill_chain, full narrative
      return {
        ...base,
        actor_fingerprint:  actorFP,             // partial only (****-masked)
        kill_chain:         "PRO_REQUIRED",       // locked
        kill_chain_primary: "PRO_REQUIRED",
        ai_summary:         teaserSummary,        // v120.0.0: MANDATORY teaser — never null
        recommended_action: "Upgrade to Pro for full SOC recommendations and actor attribution.",
        behavioral_tags:    [],                   // locked
        paywall: {
          locked_fields:   ["actor_fingerprint_full", "kill_chain", "behavioral_tags", "recommended_action_full"],
          upgrade_url:     "https://cyberdudebivash.com/sentinel-premium",
          message:         `ACTIVE THREAT — ${iocCount} IOC${iocCount !== 1 ? "s" : ""} & full kill chain locked. Upgrade to Pro for complete intelligence.`,
          urgency:         base.soc_priority === "P1" || base.soc_priority === "P2"
            ? "⚠️ ACTIVE THREAT — Upgrade required for enterprise detection."
            : "Enterprise detection unavailable on free tier.",
        },
      };
    }

    // Pro / Enterprise: full AI intelligence block
    return {
      ...base,
      actor_fingerprint:  actorFP,
      kill_chain:         killChainPhases,
      kill_chain_primary: primaryPhase,
      ai_summary:         fullSummary,            // v120.0.0: always populated
      recommended_action: existingApex.recommended_action
        || `Investigate ${actorTag} TTPs (${primaryPhase}). Hunt ${iocCount} IOC${iocCount !== 1 ? "s" : ""} across endpoint and network telemetry. Priority: ${base.soc_priority}.`,
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

// ── v119.0.0: applyTierGate — enforces monetization on feed items ─────────────
// Free tier: iocs = count only, stix_bundle = locked, apex_ai = partial
// Premium: full iocs, STIX metadata, full apex_ai
// Enterprise: everything including raw stix_bundle passthrough

function applyTierGate(item, tier) {
  const isFree = !tier || tier === CONFIG.TIERS.FREE;
  const isEnt  = tier === CONFIG.TIERS.ENTERPRISE;

  const gated = { ...item };

  // IOC paywall: free tier strips raw IOC arrays, keeps count
  if (isFree && Array.isArray(item.iocs) && item.iocs.length > 0) {
    gated.iocs      = [];
    gated.ioc_count = item.iocs.length;
    gated.ioc_paywall = {
      locked:      true,
      count:       item.iocs.length,
      upgrade_url: "https://cyberdudebivash.com/sentinel-premium",
      message:     `${item.iocs.length} IOC(s) available on Pro tier.`,
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

  // Inject computed apex_ai block
  gated.apex_ai = computeApexAI(item, tier);

  // v120.0.0: Threat urgency CTA — injected for free tier on critical/high items
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
          ? "⚠️ CRITICAL ACTIVE THREAT — Full intelligence, IOC array & actor attribution locked."
          : "⚠️ HIGH-SEVERITY ACTIVE THREAT — Actor TTPs and kill chain analysis locked.",
        tier_required:   "PRO",
        upgrade_url:     "https://cyberdudebivash.com/sentinel-premium",
        cta:             "Upgrade to Pro — Detect, Respond, Contain.",
        enterprise_note: "Enterprise Detection Engine unavailable on free tier.",
      };
    }
  }

  return gated;
}

// ── v122.0.0: IOC Extraction from Text ───────────────────────────────────────
// Regex-based IOC detection from title/description/summary text.
// Used as fallback when ioc_count < 3 — ensures EVERY threat has indicators.
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

  // CVE (highest confidence — unambiguous)
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

  // MD5 (only 32-char — lower confidence, often false-positive in non-hash contexts)
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

// ── v121.0.0: Schema Validator & Normalizer ───────────────────────────────────
// HARD GUARANTEE: No null/undefined for any field that UI or API consumers depend on.
// Called on every item before API responses and before applyTierGate.
// ZERO tolerance: missing field → derive from existing data → guaranteed default.
function validateAndNormalizeItem(item) {
  if (!item || typeof item !== "object") return null;
  const out = { ...item };

  // ── risk_score: MUST be number 0–10 ──────────────────────────────────────────
  if (typeof out.risk_score !== "number" || isNaN(out.risk_score)) {
    out.risk_score = typeof out.cvss_score === "number" ? out.cvss_score : 0;
  }
  out.risk_score = Math.max(0, Math.min(10, out.risk_score));

  // ── severity: derive from risk_score when missing/UNKNOWN ────────────────────
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

  // ── title: MUST be non-empty string ──────────────────────────────────────────
  if (!out.title || typeof out.title !== "string" || !out.title.trim()) {
    out.title = out.cve_id || out.advisory_id || out.id || "Untitled Advisory";
  }

  // ── id + stix_id: cross-populate ─────────────────────────────────────────────
  if (!out.id)      out.id      = out.stix_id || out.cve_id || out.advisory_id || `advisory-${Date.now()}`;
  if (!out.stix_id) out.stix_id = out.id;

  // ── timestamps: guarantee processed_at and timestamp both set ────────────────
  const firstTs = out.processed_at || out.timestamp || out.generated_at || out.published_at;
  if (!out.processed_at) out.processed_at = firstTs || new Date().toISOString();
  if (!out.timestamp)    out.timestamp    = out.processed_at;

  // ── ioc_counts: derive from iocs array when object is absent/empty ───────────
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

  // ── ioc_count scalar: sum of ioc_counts or length of iocs ────────────────────
  if (typeof out.ioc_count !== "number") {
    out.ioc_count = Array.isArray(out.iocs) ? out.iocs.length
      : (out.ioc_counts ? Object.values(out.ioc_counts).reduce((a, b) => a + (b || 0), 0) : 0);
  }

  // ── v122.0.0: IOC Extraction Fallback — RULE: ioc_count >= 3 ─────────────────
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

  // ── confidence_score: 0–100 (normalise 0–1 fraction) ─────────────────────────
  if (typeof out.confidence_score !== "number" || isNaN(out.confidence_score)) {
    out.confidence_score = typeof out.confidence === "number" ? out.confidence : 50;
  }
  if (out.confidence_score > 0 && out.confidence_score <= 1) {
    out.confidence_score = Math.round(out.confidence_score * 100);
  }
  out.confidence_score = Math.max(0, Math.min(100, Math.round(out.confidence_score)));

  // ── actor_tag: must be non-null string ────────────────────────────────────────
  if (!out.actor_tag || typeof out.actor_tag !== "string") out.actor_tag = "UNATTRIBUTED";

  // ── feed_source ───────────────────────────────────────────────────────────────
  if (!out.feed_source) out.feed_source = out.source || "SENTINEL-APEX";

  // ── mitre_tactics: must be array ─────────────────────────────────────────────
  if (!Array.isArray(out.mitre_tactics)) {
    out.mitre_tactics = Array.isArray(out.ttps) ? out.ttps : [];
  }

  // ── iocs: must be array ───────────────────────────────────────────────────────
  if (!Array.isArray(out.iocs)) out.iocs = [];

  // ── ttps: must be array ───────────────────────────────────────────────────────
  if (!Array.isArray(out.ttps)) out.ttps = [];

  // ── boolean flags ─────────────────────────────────────────────────────────────
  out.kev_present = out.kev_present === true;
  out.exploit_available = out.exploit_available === true;
  out.zero_day = out.zero_day === true;
  out.supply_chain = out.supply_chain === true;
  out.ransomware = out.ransomware === true;

  return out;
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
    // v116.2.0 FRESHNESS FIX: Sort by processed_at DESC (primary) → timestamp DESC (fallback)
    // → risk_score DESC (tiebreak).
    //
    // WHY processed_at is PRIMARY:
    //   RSS-sourced intel carries `published_at` dates from the original article
    //   (e.g. a CVE advisory published 3 weeks ago). When `timestamp` is set from
    //   `published_at`, newly generated intel APPEARS STALE even though it was just
    //   processed. `processed_at` is always set to pipeline execution time (UTC-now)
    //   so it is immune to source article date variations.
    //
    // SORT KEY helper — reads processed_at first, then timestamp as fallback
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
          // Rewrite dead subdomain → working domain
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
        // v119.0.0: Free-tier IOC paywall — strip raw IOC arrays, surface count + CTA
        iocs:       [],        // raw IOCs require Pro tier
        ioc_count:  Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0),
        ioc_paywall: Array.isArray(item.iocs) && item.iocs.length > 0 ? {
          locked:      true,
          count:       item.iocs.length,
          upgrade_url: "https://cyberdudebivash.com/sentinel-premium",
          message:     `${item.iocs.length} IOC(s) unlocked on Pro tier.`,
        } : null,
        // v119.0.0: APEX AI block — always present in preview, fields tier-gated
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

// ── AUTHENTICATED: /api/feed ───────────────────────────────────────────────────
async function handleFeed(request, env, auth, rid) {
  const url      = new URL(request.url);

  // v119.0.0: Input sanitization — prevent injection via query params
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

  // Search: max 128 chars, strip control chars
  const search = rawSearch
    ? rawSearch.replace(/[\x00-\x1F\x7F]/g, "").slice(0, 128).trim()
    : null;

  const limit = Math.min(parsedLimit, CONFIG.FEED_LIMITS[auth.tier]);
  const page  = Math.max(1, parsedPage);

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
    const pageItems  = items.slice(offset, offset + limit).map(it => applyTierGate(it, auth.tier));

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
    // v121.0.0: Normalize + apply tier gate — API /feed/:id MUST match /feed response
    const normalized = validateAndNormalizeItem(report) || report;
    const gated      = applyTierGate(normalized, auth.tier);

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

// ── v117.0.0: /api/version — platform version manifest ───────────────────────
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

// ── v117.0.0: /api/stix/:id — STIX 2.1 export ────────────────────────────────
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

// ── v117.0.0: /api/webhooks/siem — SIEM integration webhook ──────────────────
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
    const VALID_FORMATS = ["json", "splunk", "sentinel", "qradar", "elastic"];
    return jsonResponse({
      status:          "ok",
      key_id:          auth.key_id,
      webhooks:        stored || [],
      supported_formats: VALID_FORMATS,
      active_format:   VALID_FORMATS.includes(fmt) ? fmt : "json",
      format_docs: {
        splunk:   "Splunk HEC JSON — POST to /services/collector/event",
        sentinel: "Azure Sentinel custom log (Log Analytics workspace)",
        qradar:   "IBM QRadar LEEF 2.0 syslog format",
        elastic:  "Elastic Common Schema (ECS 8.x) — Kibana SIEM / Logstash",
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
    const VALID_SIEM_FORMATS = ["json", "splunk", "sentinel", "qradar", "elastic"];
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

// ── v117.0.0: /api/alerts — threat alerts for Pro+ ───────────────────────────
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

// ── v121.0.0: /api/auth/refresh — Renew JWT before expiry ─────────────────────
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

// ── v121.0.0: /api/auth/revoke — Revoke JWT immediately ──────────────────────
async function handleRevokeToken(request, env, rid) {
  if (!env?.CDB_JWT_SECRET) {
    return jsonResponse({ error: "auth_service_unavailable", request_id: rid }, 503);
  }
  const jwtToken = extractJwt(request);
  if (!jwtToken) return jsonResponse({ error: "token_required", request_id: rid }, 400);
  const result = await verifyJwt(jwtToken, env.CDB_JWT_SECRET);
  // Allow revoke even if expired — still add to blocklist to be thorough
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

// ── v121.0.0: /api/admin/keys/list ───────────────────────────────────────────
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

// ── v121.0.0: /api/admin/keys/revoke ─────────────────────────────────────────
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

// ── v121.0.0: /api/admin/observability ───────────────────────────────────────
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
    kv_health: kvHealth,
    r2_bound:  !!env?.INTEL_R2,
    jwt_configured: !!env?.CDB_JWT_SECRET,
  });
}

// ── v123.0.0: GET /api/ioc/export — Pro+ IOC bulk export (CSV or JSON) ────────
// Downloads all IOCs from a specific threat ID or all threats (paginated).
// FREE tier: blocked. PRO+: JSON. ENTERPRISE: CSV + JSON + STIX IOC-only bundle.
async function handleIocExport(request, env, auth, rid) {
  const isPro  = auth.tier === CONFIG.TIERS.PREMIUM || auth.tier === CONFIG.TIERS.ENTERPRISE;
  if (!isPro) {
    return jsonResponse({
      error:      "pro_required",
      message:    "IOC export requires Pro tier or higher.",
      upgrade:    getUpgradeCTA(auth.tier),
      request_id: rid,
    }, 403);
  }

  const url      = new URL(request.url);
  const format   = (url.searchParams.get("format") || "json").toLowerCase();
  const threatId = url.searchParams.get("threat_id") || null;
  const limit    = Math.min(parseInt(url.searchParams.get("limit") || "500"), 2000);

  if (!["json", "csv"].includes(format)) {
    return jsonResponse({ error: "invalid_format", valid: ["json", "csv"], request_id: rid }, 400);
  }

  // Load feed data
  const feedData = await loadFeedData(env);
  if (!feedData?.reports?.length) {
    return jsonResponse({ error: "no_data", message: "Feed data unavailable.", request_id: rid }, 503);
  }

  // Filter by threat_id if provided
  const items = threatId
    ? feedData.reports.filter(r => r.id === threatId || r.stix_id === threatId)
    : feedData.reports.slice(0, limit);

  // Collect all IOCs from matching items
  const allIocs = [];
  for (const item of items) {
    if (!Array.isArray(item.iocs)) continue;
    for (const ioc of item.iocs) {
      if (!ioc || typeof ioc !== "object") continue;
      allIocs.push({
        threat_id:    item.id,
        threat_title: item.title,
        severity:     item.severity,
        type:         ioc.type   || "unknown",
        value:        ioc.value  || "",
        confidence:   typeof ioc.confidence === "number" ? ioc.confidence : 0.7,
        extracted:    ioc.extracted || false,
        processed_at: item.processed_at || item.timestamp,
      });
    }
  }

  await recordAnalytics(env, auth.key_id, "ioc_export", auth.tier, 200);

  if (format === "csv") {
    const header = "threat_id,threat_title,severity,type,value,confidence,extracted,processed_at\n";
    const rows   = allIocs.map(i =>
      [i.threat_id, `"${(i.threat_title || "").replace(/"/g, '""')}"`, i.severity,
       i.type, `"${(i.value || "").replace(/"/g, '""')}"`, i.confidence, i.extracted, i.processed_at]
        .join(",")
    ).join("\n");
    return new Response(header + rows, {
      status: 200,
      headers: {
        "Content-Type":        "text/csv",
        "Content-Disposition": `attachment; filename="sentinel-apex-iocs-${new Date().toISOString().slice(0,10)}.csv"`,
        "X-Gateway":           `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
        "Cache-Control":       "no-cache, no-store",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }

  // JSON format (default)
  return jsonResponse({
    status:      "ok",
    exported_at: new Date().toISOString(),
    tier:        auth.tier,
    count:       allIocs.length,
    threat_filter: threatId || "all",
    iocs:        allIocs,
    request_id:  rid,
    gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// ── v123.0.0: GET /api/usage — Per-key + per-user usage metering ──────────────
// Returns current billing period usage, limits, and key-level breakdown.
async function handleUsageStats(request, env, auth, rid) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId = auth.user_id || auth.key_id;
  const month  = new Date().toISOString().slice(0, 7);
  const today  = new Date().toISOString().slice(0, 10);

  // Current key's monthly usage
  const keyMonthUsage = parseInt(await env.API_KEYS_KV.get(`usage:${auth.key_id}:${month}`).catch(() => "0") || "0");
  const keyDayUsage   = parseInt(await env.ANALYTICS_KV?.get(`analytics:key:${auth.key_id}:${today}`).catch(() => "0") || "0");

  // All keys for this user
  const TIER_CAPS = { free: 1000, premium: 0, enterprise: 0 }; // 0 = unlimited
  const limit     = TIER_CAPS[auth.tier] ?? 1000;
  const keyList   = userId ? await env.API_KEYS_KV.list({ prefix: `userkey:${userId}:` }).catch(() => ({ keys: [] })) : { keys: [] };

  const keyBreakdown = await Promise.all(keyList.keys.slice(0, 20).map(async k => {
    const rec    = await env.API_KEYS_KV.get(k.name, { type: "json" }).catch(() => null);
    if (!rec) return null;
    const mUsage = parseInt(await env.API_KEYS_KV.get(`usage:${rec.key_id}:${month}`).catch(() => "0") || "0");
    const dUsage = parseInt(await env.ANALYTICS_KV?.get(`analytics:key:${rec.key_id}:${today}`).catch(() => "0") || "0");
    return {
      key_id:            rec.key_id,
      label:             rec.label,
      tier:              rec.tier,
      last_used:         rec.last_used || null,
      lifetime_requests: rec.usage_count || 0,
      this_month:        mUsage,
      today:             dUsage,
      monthly_limit:     rec.usage_limit === 0 ? "unlimited" : (rec.usage_limit || limit),
      revoked:           rec.revoked || false,
    };
  }));

  const totalThisMonth = keyBreakdown.filter(Boolean).reduce((s, k) => s + (k.this_month || 0), 0);

  return jsonResponse({
    status:     "ok",
    user_id:    userId,
    tier:       auth.tier,
    period:     month,
    current_key: {
      key_id:      auth.key_id,
      this_month:  keyMonthUsage,
      today:       keyDayUsage,
      monthly_limit: limit === 0 ? "unlimited" : limit,
      pct_used:    limit > 0 ? Math.min(100, Math.round((keyMonthUsage / limit) * 100)) : 0,
    },
    all_keys: {
      count:       keyBreakdown.filter(Boolean).length,
      total_this_month: totalThisMonth,
      breakdown:   keyBreakdown.filter(Boolean),
    },
    rate_limits: {
      requests_per_min: CONFIG.RATE_LIMITS[auth.tier] || CONFIG.RATE_LIMITS.free,
      feed_items:       CONFIG.FEED_LIMITS[auth.tier]  || CONFIG.FEED_LIMITS.free,
    },
    upgrade:    auth.tier !== CONFIG.TIERS.ENTERPRISE ? getUpgradeCTA(auth.tier) : null,
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// ── v123.0.0: Organization / Team System ─────────────────────────────────────
// Orgs allow multiple users to share an Enterprise subscription under one account.
// Roles: owner (full control), admin (manage keys + members), analyst (read-only API).
// Storage: org:<orgId> record + member:<userId>:orgs set + orgkey:<orgId>:<keyId>

function generateOrgId() {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  return "org_" + Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// POST /api/org/create
async function handleOrgCreate(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);
  if (auth.tier !== CONFIG.TIERS.ENTERPRISE) {
    return jsonResponse({
      error:      "enterprise_required",
      message:    "Organizations require Enterprise tier.",
      upgrade:    getUpgradeCTA(auth.tier),
      request_id: rid,
    }, 403);
  }

  let body = {};
  try { body = await request.json(); } catch {}
  const { name: orgName, description = "" } = body;
  if (!orgName || typeof orgName !== "string" || !orgName.trim())
    return jsonResponse({ error: "org_name_required", request_id: rid }, 400);

  const userId = auth.user_id || auth.key_id;
  const orgId  = generateOrgId();
  const now    = new Date().toISOString();

  const orgRecord = {
    org_id:      orgId,
    name:        orgName.trim().slice(0, 100),
    description: String(description).slice(0, 500),
    owner_id:    userId,
    tier:        CONFIG.TIERS.ENTERPRISE,
    created_at:  now,
    member_count: 1,
    members: [{ user_id: userId, role: "owner", joined_at: now }],
    api_key_count: 0,
  };

  await Promise.all([
    env.API_KEYS_KV.put(`org:${orgId}`, JSON.stringify(orgRecord)),
    env.API_KEYS_KV.put(`member_org:${userId}:${orgId}`, JSON.stringify({ org_id: orgId, role: "owner", joined_at: now })),
  ]);

  slog("INFO", "ORG", "Organization created", { org_id: orgId, owner_id: userId });
  return jsonResponse({
    status:     "ok",
    org_id:     orgId,
    name:       orgRecord.name,
    tier:       CONFIG.TIERS.ENTERPRISE,
    owner_id:   userId,
    created_at: now,
    message:    "Organization created. Invite members via POST /api/org/invite.",
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  }, 201);
}

// GET /api/org
async function handleOrgGet(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const userId  = auth.user_id || auth.key_id;
  // Find orgs this user belongs to
  const orgList = await env.API_KEYS_KV.list({ prefix: `member_org:${userId}:` }).catch(() => ({ keys: [] }));
  const orgs    = await Promise.all(orgList.keys.map(async k => {
    const membership = await env.API_KEYS_KV.get(k.name, { type: "json" }).catch(() => null);
    if (!membership) return null;
    const orgRec = await env.API_KEYS_KV.get(`org:${membership.org_id}`, { type: "json" }).catch(() => null);
    if (!orgRec) return null;
    return {
      org_id:        orgRec.org_id,
      name:          orgRec.name,
      tier:          orgRec.tier,
      role:          membership.role,
      member_count:  orgRec.member_count,
      api_key_count: orgRec.api_key_count || 0,
      created_at:    orgRec.created_at,
      joined_at:     membership.joined_at,
    };
  }));

  return jsonResponse({
    status:     "ok",
    user_id:    userId,
    orgs:       orgs.filter(Boolean),
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// POST /api/org/invite — Owner/admin invites a user by email
async function handleOrgInvite(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  let body = {};
  try { body = await request.json(); } catch {}
  const { org_id, email, role = "analyst" } = body;

  if (!org_id || !email)
    return jsonResponse({ error: "org_id_and_email_required", request_id: rid }, 400);

  const VALID_ROLES = ["owner", "admin", "analyst"];
  if (!VALID_ROLES.includes(role))
    return jsonResponse({ error: "invalid_role", valid: VALID_ROLES, request_id: rid }, 400);

  const orgRecord = await env.API_KEYS_KV.get(`org:${org_id}`, { type: "json" }).catch(() => null);
  if (!orgRecord) return jsonResponse({ error: "org_not_found", request_id: rid }, 404);

  const inviterId = auth.user_id || auth.key_id;
  const inviterMembership = orgRecord.members?.find(m => m.user_id === inviterId);
  if (!inviterMembership || !["owner", "admin"].includes(inviterMembership.role)) {
    return jsonResponse({ error: "insufficient_org_role", message: "Only owner or admin can invite members.", request_id: rid }, 403);
  }

  const emailNorm = email.toLowerCase().trim();
  const emailHash = await sha256hex("email:" + emailNorm);
  const targetUserId = await env.API_KEYS_KV.get(`email:${emailHash}`).catch(() => null);

  if (!targetUserId)
    return jsonResponse({ error: "user_not_found", message: "No account found with this email. User must sign up first.", request_id: rid }, 404);

  const now = new Date().toISOString();
  const alreadyMember = orgRecord.members?.some(m => m.user_id === targetUserId);
  if (alreadyMember)
    return jsonResponse({ error: "already_member", request_id: rid }, 409);

  orgRecord.members = [...(orgRecord.members || []), { user_id: targetUserId, role, joined_at: now }];
  orgRecord.member_count = orgRecord.members.length;

  await Promise.all([
    env.API_KEYS_KV.put(`org:${org_id}`, JSON.stringify(orgRecord)),
    env.API_KEYS_KV.put(`member_org:${targetUserId}:${org_id}`, JSON.stringify({ org_id, role, joined_at: now })),
  ]);

  slog("INFO", "ORG", "Member invited", { org_id, target_user: targetUserId, role, invited_by: inviterId });
  return jsonResponse({
    status:     "ok",
    org_id,
    invited_user_id: targetUserId,
    role,
    joined_at:  now,
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  }, 201);
}

// GET /api/org/keys — List API keys registered under an org
async function handleOrgListKeys(request, env, rid, auth) {
  if (!env?.API_KEYS_KV) return jsonResponse({ error: "storage_unavailable", request_id: rid }, 503);

  const url    = new URL(request.url);
  const org_id = url.searchParams.get("org_id");
  if (!org_id) return jsonResponse({ error: "org_id_required", request_id: rid }, 400);

  const orgRecord = await env.API_KEYS_KV.get(`org:${org_id}`, { type: "json" }).catch(() => null);
  if (!orgRecord) return jsonResponse({ error: "org_not_found", request_id: rid }, 404);

  const userId  = auth.user_id || auth.key_id;
  const isMember = orgRecord.members?.some(m => m.user_id === userId);
  if (!isMember) return jsonResponse({ error: "not_org_member", request_id: rid }, 403);

  const month   = new Date().toISOString().slice(0, 7);
  const keyList = await env.API_KEYS_KV.list({ prefix: `orgkey:${org_id}:` }).catch(() => ({ keys: [] }));
  const keys    = (await Promise.all(keyList.keys.map(async k => {
    const rec   = await env.API_KEYS_KV.get(k.name, { type: "json" }).catch(() => null);
    if (!rec) return null;
    const usage = parseInt(await env.API_KEYS_KV.get(`usage:${rec.key_id}:${month}`).catch(() => "0") || "0");
    return { key_id: rec.key_id, label: rec.label, tier: rec.tier, created_by: rec.created_by,
             created_at: rec.created_at, revoked: rec.revoked || false, usage_this_month: usage };
  }))).filter(Boolean);

  return jsonResponse({
    status:     "ok",
    org_id,
    org_name:   orgRecord.name,
    tier:       orgRecord.tier,
    count:      keys.length,
    keys,
    request_id: rid,
    gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
  });
}

// ── v122.0.0: Stripe Webhook Signature Verification ──────────────────────────
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

// ── v122.0.0: POST /webhooks/stripe ──────────────────────────────────────────
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

  // v123.0.0: REPLAY ATTACK PREVENTION
  // 1. Timestamp tolerance: reject events older than 5 minutes (Stripe standard)
  // 2. Nonce dedup: event ID stored in SECURITY_HUB_KV for 10 minutes
  const tPart = sigHeader.split(",").find(p => p.startsWith("t="));
  if (tPart) {
    const evtTs  = parseInt(tPart.slice(2));
    const nowTs  = Math.floor(Date.now() / 1000);
    const drift  = Math.abs(nowTs - evtTs);
    if (drift > 300) { // 5-minute window
      slog("WARN", "BILLING", `Stripe replay rejected — timestamp drift ${drift}s`, { rid });
      return jsonResponse({ error: "replay_detected", detail: "Event timestamp outside tolerance window." }, 400);
    }
  }

  let event;
  try { event = JSON.parse(rawBody); }
  catch { return jsonResponse({ error: "invalid_json" }, 400); }

  // Nonce dedup — event IDs are globally unique per Stripe account
  if (env?.SECURITY_HUB_KV && event.id) {
    const nonceKey = `stripe_nonce:${event.id}`;
    const already  = await env.SECURITY_HUB_KV.get(nonceKey);
    if (already) {
      slog("WARN", "BILLING", `Stripe replay detected — duplicate event ${event.id}`, { rid });
      return jsonResponse({ status: "ok", received: true, note: "duplicate_ignored" });
    }
    // Mark as seen for 10 minutes
    env.SECURITY_HUB_KV.put(nonceKey, "1", { expirationTtl: 600 }).catch(() => {});
  }

  slog("INFO", "BILLING", `Stripe event: ${event.type}`, { rid, event_id: event.id });
  const obj = event.data?.object || {};

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const userId     = obj.metadata?.user_id || obj.client_reference_id;
        const priceId    = obj.metadata?.price_id;
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
            slog("INFO", "BILLING", "Checkout complete — tier upgraded", { user_id: userId, tier: newTier });
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
              slog("INFO", "BILLING", "Subscription updated", { user_id: userId, status, tier: newTier });
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
              slog("INFO", "BILLING", "Subscription cancelled — downgraded to FREE", { user_id: userId });
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

// ── v122.0.0: POST /webhooks/razorpay ────────────────────────────────────────
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

  // v123.0.0: Razorpay replay prevention — deduplicate by event.account_id + event.created_at
  if (env?.SECURITY_HUB_KV && event.account_id && event.created_at) {
    const rzNonceKey = `rz_nonce:${event.account_id}:${event.created_at}`;
    const rzAlready  = await env.SECURITY_HUB_KV.get(rzNonceKey).catch(() => null);
    if (rzAlready) {
      slog("WARN", "BILLING", "Razorpay replay detected", { rid, created_at: event.created_at });
      return jsonResponse({ status: "ok", received: true, note: "duplicate_ignored" });
    }
    // Timestamp tolerance: reject if older than 10 minutes
    const rzDrift = Math.floor(Date.now() / 1000) - (event.created_at || 0);
    if (rzDrift > 600) {
      slog("WARN", "BILLING", `Razorpay replay — timestamp drift ${rzDrift}s`, { rid });
      return jsonResponse({ error: "replay_detected", detail: "Event timestamp outside tolerance window." }, 400);
    }
    env.SECURITY_HUB_KV.put(rzNonceKey, "1", { expirationTtl: 900 }).catch(() => {});
  }

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
          slog("INFO", "BILLING", "Razorpay payment — tier upgraded", { user_id: userId, tier: planTier });
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
          slog("INFO", "BILLING", "Razorpay sub cancelled — downgraded to FREE", { user_id: userId });
        }
      }
    }
  } catch (e) {
    await trackError(env, "BILLING", `Razorpay event error: ${e.message}`, { event: event.event });
  }

  return jsonResponse({ status: "ok", received: true, event: event.event });
}

// ── v122.0.0: GET /api/billing/portal ────────────────────────────────────────
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

// ── v122.0.0: SIEM Output Formatters — Splunk HEC / Sentinel / QRadar LEEF ──

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

// ── v123.0.0: Elastic Common Schema (ECS 8.x) / Elastic SIEM ─────────────────
// Compatible with Elastic Security (Kibana SIEM), Logstash, Filebeat pipelines.
function formatElasticEvent(item) {
  const ts = item.processed_at || item.timestamp || new Date().toISOString();
  const tlp = item.risk_score >= 8 ? "RED" : item.risk_score >= 5 ? "AMBER" : "GREEN";
  return {
    "@timestamp":    ts,
    "ecs.version":   "8.11.0",
    "event": {
      kind:      "alert",
      category:  ["threat"],
      type:      ["indicator"],
      severity:  item.risk_score || 0,
      dataset:   "sentinel_apex.threat_intel",
      module:    "sentinel_apex",
      provider:  "CYBERDUDEBIVASH",
      ingested:  new Date().toISOString(),
    },
    "threat": {
      "indicator": {
        confidence: String(item.confidence_score || 50),
        provider:   "SENTINEL-APEX",
        reference:  item.report_url || item.source_url || null,
        "marking.tlp": tlp,
      },
      "tactic": { name: (item.mitre_tactics || []).slice(0, 3) },
      "software": { name: item.actor_tag || "UNATTRIBUTED" },
    },
    "vulnerability": item.cve_id ? {
      id:       item.cve_id,
      score:    { base: item.cvss_score || item.risk_score || 0 },
      severity: item.severity,
    } : undefined,
    "sentinel_apex": {
      id:          item.id,
      title:       item.title,
      severity:    item.severity,
      risk_score:  item.risk_score,
      actor_tag:   item.actor_tag || "UNATTRIBUTED",
      ioc_count:   item.ioc_count || 0,
      kev_present: item.kev_present || false,
      exploit:     item.exploit_available || false,
      feed_source: item.feed_source || "SENTINEL-APEX",
      gateway:     `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    },
    "labels": {
      sentinel_apex_version: CONFIG.GATEWAY_VERSION,
      tier: "enterprise",
    },
  };
}

// ── v123.0.0: SIEM Webhook Delivery — 3-attempt retry + failure tracking ─────
// Delivers formatted intel to a registered SIEM webhook URL.
// Failures are counted and sampled in SECURITY_HUB_KV (7-day rolling window).
// Optional HMAC-SHA256 signature header for consumer verification.
async function deliverToSiemWebhook(webhookEntry, payload, env) {
  const { id: whId, url: whUrl, format = "json", secret: whSecret } = webhookEntry;
  const maxAttempts = 3;

  let body;
  let contentType = "application/json";
  if      (format === "splunk")   { body = JSON.stringify(formatSplunkHEC(payload)); }
  else if (format === "sentinel") { body = JSON.stringify(formatSentinelEvent(payload)); }
  else if (format === "qradar")   { body = formatQRadarLEEF(payload); contentType = "text/plain"; }
  else if (format === "elastic")  { body = JSON.stringify(formatElasticEvent(payload)); }
  else                             { body = JSON.stringify(payload); }

  const headers = {
    "Content-Type":              contentType,
    "X-Sentinel-Apex-Version":   CONFIG.GATEWAY_VERSION,
    "X-Sentinel-Apex-Event":     payload.id || "unknown",
    "X-Sentinel-Apex-Severity":  payload.severity || "UNKNOWN",
  };

  // Optional HMAC-SHA256 delivery signature so the consumer can verify authenticity
  if (whSecret) {
    try {
      const key    = await crypto.subtle.importKey("raw", new TextEncoder().encode(whSecret),
                       { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
      const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
      headers["X-Sentinel-Apex-Signature"] = Array.from(new Uint8Array(sigBuf))
        .map(b => b.toString(16).padStart(2, "0")).join("");
    } catch { /* signing non-critical — never block delivery */ }
  }

  let lastErr;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const res = await fetch(whUrl, { method: "POST", headers, body });
      if (res.status >= 200 && res.status < 300) {
        slog("INFO", "SIEM", `Delivered to webhook ${whId}`, { format, status: res.status, attempt: attempt + 1 });
        return { success: true, attempt: attempt + 1, status: res.status };
      }
      lastErr = new Error(`HTTP ${res.status}`);
    } catch (e) { lastErr = e; }
    if (attempt < maxAttempts - 1) {
      await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt))); // 500ms, 1s, 2s
    }
  }

  // Persist failure record for observability dashboard
  if (env?.SECURITY_HUB_KV) {
    const failKey = `wh_fail:${whId}:${new Date().toISOString().slice(0, 10)}`;
    const rec     = await env.SECURITY_HUB_KV.get(failKey, { type: "json" }).catch(() => null) || { count: 0, samples: [] };
    rec.count++;
    if (rec.samples.length < 5) rec.samples.push({ ts: new Date().toISOString(), error: lastErr?.message });
    env.SECURITY_HUB_KV.put(failKey, JSON.stringify(rec), { expirationTtl: 86400 * 7 }).catch(() => {});
  }

  slog("ERROR", "SIEM", `Webhook ${whId} failed after ${maxAttempts} attempts`, { error: lastErr?.message });
  return { success: false, attempts: maxAttempts, error: lastErr?.message };
}

// ── Main Router ────────────────────────────────────────────────────────────────

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
    if (pathname.startsWith("/api/version"))           return handleVersion(request, env, rid);
    if (pathname.startsWith("/api/keys/validate"))     return handleValidateKey(request, env, rid);
    // ── v117.0.0 + v121.0.0: JWT auth endpoints ──────────────────────────────
    if (pathname === "/api/auth/token"    && method === "POST") return handleIssueToken(request, env, rid);
    if (pathname === "/api/auth/validate")                      return handleValidateToken(request, env, rid);
    if (pathname === "/api/auth/refresh"  && method === "POST") return handleRefreshToken(request, env, rid);
    if (pathname === "/api/auth/revoke"   && method === "POST") return handleRevokeToken(request, env, rid);
    // ── v122.0.0: User auth endpoints (no API key required) ──────────────────
    if (pathname === "/auth/signup"       && method === "POST") return handleUserSignup(request, env, rid);
    if (pathname === "/auth/login"        && method === "POST") return handleUserLogin(request, env, rid);
    // ── v122.0.0: Billing webhooks (no API key — use their own sig verification)
    if (pathname === "/webhooks/stripe"   && method === "POST") return handleStripeWebhook(request, env, rid);
    if (pathname === "/webhooks/razorpay" && method === "POST") return handleRazorpayWebhook(request, env, rid);
    // AI endpoints — public (index/heatmap) or authenticated (analyze/respond/correlate)
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

    // ── Admin endpoints (X-Admin-Secret verified internally) ─────────────────
    if (pathname.startsWith("/api/admin")) {
      // All /api/admin/* require X-Admin-Secret — verify once here
      if (!env?.ADMIN_SECRET || request.headers.get("X-Admin-Secret") !== env.ADMIN_SECRET) {
        slog("WARN", "ADMIN", "Forbidden admin access attempt", { path: pathname, rid });
        return jsonResponse({ error: "forbidden", message: "Valid X-Admin-Secret required.", request_id: rid }, 403);
      }
      if (pathname.startsWith("/api/admin/cache/bust")   && method === "POST") return handleCacheBust(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/create")  && method === "POST") return handleAdminCreateKey(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/revoke")  && method === "POST") return handleAdminRevokeKey(request, env, rid);
      if (pathname.startsWith("/api/admin/keys/list")    && method === "GET")  return handleAdminListKeys(request, env, rid);
      if (pathname.startsWith("/api/admin/observability")&& method === "GET")  return handleAdminObservability(request, env, rid);
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

    // ── ALL REMAINING ENDPOINTS: JWT OR API KEY REQUIRED ─────────────────────
    // resolveAuth: JWT (3-part Bearer) takes priority → falls through to API key
    const auth = await resolveAuth(request, env);
    if (!auth.valid) {
      if (auth.reason === "invalid_key" || auth.reason === "key_expired") {
        await trackAbuseAttempt(clientIP, env);
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

    // Per-key sliding-window rate limit
    const rateLimit = CONFIG.RATE_LIMITS[auth.tier] || CONFIG.RATE_LIMITS.free;
    const keyCheck  = await slidingWindowCheck("key", auth.key_id, rateLimit, env?.RATE_LIMIT_KV);
    if (!keyCheck.allowed) {
      await recordAnalytics(env, auth.key_id, "rate_limited", auth.tier, 429);
      return jsonResponse({
        error:       "rate_limited",
        message:     `Rate limit exceeded. ${auth.tier}: ${rateLimit} req/min.`,
        limit:       keyCheck.limit,
        retry_after: keyCheck.retryAfter,
        request_id:  rid,
        response_ms: Date.now() - reqStart,
        upgrade:     getUpgradeCTA(auth.tier),
      }, 429, {
        "Retry-After":           String(keyCheck.retryAfter || 60),
        "X-RateLimit-Remaining": "0",
        "X-Response-Time":       String(Date.now() - reqStart) + "ms",
      });
    }

    // ── v122.0.0: Authenticated user + billing routes ────────────────────────
    if (pathname === "/auth/me"              && method === "GET")    return handleUserMe(request, env, rid, auth);
    if (pathname === "/api/keys"             && method === "GET")    return handleUserListKeys(request, env, rid, auth);
    if (pathname === "/api/keys/create"      && method === "POST")   return handleUserCreateKey(request, env, rid, auth);
    if (pathname.startsWith("/api/keys/")   && method === "DELETE") {
      const keyId = pathname.slice("/api/keys/".length);
      if (keyId) return handleUserDeleteKey(request, env, rid, auth, keyId);
    }
    if (pathname === "/api/billing/portal"   && method === "GET")    return handleBillingPortal(request, env, rid, auth);
    // ── v123.0.0: Usage metering + IOC export ────────────────────────────────
    if (pathname === "/api/usage"            && method === "GET")    return handleUsageStats(request, env, rid, auth);
    if (pathname === "/api/ioc/export"       && method === "GET")    return handleIocExport(request, env, rid, auth);
    // ── v123.0.0: Org / team routes ──────────────────────────────────────────
    if (pathname === "/api/org/create"       && method === "POST")   return handleOrgCreate(request, env, rid, auth);
    if (pathname === "/api/org"              && method === "GET")    return handleOrgGet(request, env, rid, auth);
    if (pathname === "/api/org/invite"       && method === "POST")   return handleOrgInvite(request, env, rid, auth);
    if (pathname === "/api/org/keys"         && method === "GET")    return handleOrgListKeys(request, env, rid, auth);

    // Authenticated route dispatch
    if (pathname === "/api/feed" && method === "GET")
      return handleFeed(request, env, auth, rid);
    if (pathname.startsWith("/api/feed/") && method === "GET") {
      const id = decodeURIComponent(pathname.slice("/api/feed/".length));
      if (id) return handleReport(request, env, auth, rid, id);
    }
    if (pathname.startsWith("/api/analytics") && method === "GET")
      return handleAnalytics(request, env, auth, rid);
    // v117.0.0: STIX export
    if (pathname.startsWith("/api/stix/")) {
      const stixId = decodeURIComponent(pathname.slice("/api/stix/".length));
      return handleStixExport(request, env, auth, rid, stixId);
    }
    // v117.0.0: Threat alerts (Pro+)
    if (pathname.startsWith("/api/alerts") && method === "GET")
      return handleAlerts(request, env, auth, rid);
    // v117.0.0: SIEM webhook (Enterprise)
    if (pathname.startsWith("/api/webhooks/siem"))
      return handleSiemWebhook(request, env, auth, rid);

    slog("WARN", "ROUTER", `404 ${pathname}`, { rid, method });
    return jsonResponse({
      error:   "not_found",
      message: `Endpoint '${pathname}' not found.`,
      available: [
        "GET  /api/preview              (public)",
        "GET  /api/health               (public)",
        "GET  /api/version              (public)",
        "GET  /api/keys/validate        (public)",
        "GET  /api/ai                   (public — AI index + MITRE heatmap)",
        "GET  /api/ai/heatmap           (public)",
        "GET  /api/ai/analyze           (requires auth)",
        "GET  /api/ai/respond           (requires auth)",
        "GET  /api/ai/correlate         (requires auth)",
        "POST /api/auth/token           (public — exchange API key for JWT)",
        "GET  /api/auth/validate        (public — validate JWT)",
        "POST /api/auth/refresh         (requires JWT — rotate token)",
        "POST /api/auth/revoke          (requires JWT — revoke token)",
        "POST /auth/signup              (public — create user account + get JWT)",
        "POST /auth/login               (public — login + get JWT)",
        "GET  /auth/me                  (requires JWT — user profile + API keys)",
        "POST /api/keys/create          (requires JWT — create API key)",
        "GET  /api/keys                 (requires JWT — list your API keys)",
        "DELETE /api/keys/:id           (requires JWT — revoke API key)",
        "GET  /api/billing/portal       (requires JWT — subscription + upgrade links)",
        "GET  /api/usage                (requires JWT — usage metering + key stats)",
        "GET  /api/ioc/export           (requires JWT Pro+ — bulk IOC export CSV/JSON)",
        "POST /api/org/create           (requires JWT Enterprise — create organization)",
        "GET  /api/org                  (requires JWT — list your organizations)",
        "POST /api/org/invite           (requires JWT — invite member to org)",
        "GET  /api/org/keys             (requires JWT — list org API keys)",
        "POST /webhooks/stripe          (public — Stripe webhook, sig-verified + replay-protected)",
        "POST /webhooks/razorpay        (public — Razorpay webhook, sig-verified + replay-protected)",
        "GET  /api/feed                 (requires auth)",
        "GET  /api/feed/:id             (requires auth)",
        "GET  /api/analytics            (requires auth)",
        "GET  /api/stix/:id             (requires auth — full bundle Pro+)",
        "GET  /api/alerts               (requires auth Pro+)",
        "GET  /api/webhooks/siem        (requires auth Enterprise — list + format info: splunk/sentinel/qradar/elastic/json)",
        "POST /api/webhooks/siem        (requires auth Enterprise — register webhook with retry delivery)",
        "POST /api/admin/cache/bust     (requires X-Admin-Secret)",
        "POST /api/admin/keys/create    (requires X-Admin-Secret)",
        "POST /api/admin/keys/revoke    (requires X-Admin-Secret)",
        "GET  /api/admin/keys/list      (requires X-Admin-Secret)",
        "GET  /api/admin/observability  (requires X-Admin-Secret)",
      ],
      docs:       CONFIG.DOCS_URL,
      request_id: rid,
      response_ms: Date.now() - reqStart,
      gateway:    `${CONFIG.GATEWAY_NAME}/${CONFIG.GATEWAY_VERSION}`,
    }, 404);
  },
};
