/**
 * CYBER WATCHDOG WEBHOOK SAFETY + SIGNING
 *
 * 1. Destination safety (SSRF / DNS rebinding). A destination URL must be
 *    https, port 443, no credentials, and its hostname must resolve ONLY to
 *    globally routable unicast addresses. The check runs at registration,
 *    at verification, and again immediately before every delivery attempt.
 *    Resolution uses DNS-over-HTTPS (Cloudflare's public resolver) because
 *    the Workers runtime exposes no resolver API. Every A and AAAA answer,
 *    and every CNAME target name, is checked; one forbidden answer rejects
 *    the whole set.
 *
 *    Residual limitation, stated plainly: Workers fetch() resolves the
 *    hostname itself and cannot be pinned to the addresses validated here,
 *    so a resolver that changes its answer between our check and the
 *    connection (DNS rebinding with a TTL near zero) is narrowed, not
 *    eliminated. Mitigations: re-resolution right before each attempt,
 *    https only (the endpoint must also present a valid certificate for the
 *    hostname), port 443 only, redirects never followed, and a destination
 *    must prove control of the endpoint (verification challenge) before it
 *    receives intelligence. Workers egress also cannot reach this platform's
 *    own private network or a cloud metadata service; the checks are defense
 *    in depth, not the only barrier. See docs/CYBER_WATCHDOG_P3.md.
 *
 * 2. Signed delivery contract. signature = hex(HMAC-SHA256(secret,
 *    timestamp + "." + raw_body)). The exact bytes signed are the exact
 *    bytes sent; the body is serialized once per attempt.
 */

import { DELIVERY_POLICY, WEBHOOK_CONTRACT } from "./watchdog-policy.js";

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const BLOCKED_NAME = /^(localhost|metadata|metadata\.google\.internal|instance-data)$/i;
const BLOCKED_SUFFIX = [".localhost", ".local", ".internal", ".lan", ".home", ".corp", ".intranet", ".home.arpa", ".arpa"];

// ---------------------------------------------------------------------------
// Address classification
// ---------------------------------------------------------------------------

export function parseIPv4(text) {
  if (typeof text !== "string") return null;
  const m = text.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((n) => n > 255)) return null;
  return parts;
}

function v4InRange(p, base, bits) {
  const n = ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
  const b = ((base[0] << 24) >>> 0) + (base[1] << 16) + (base[2] << 8) + base[3];
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return ((n & mask) >>> 0) === ((b & mask) >>> 0);
}

// IANA special-purpose IPv4 ranges that are not globally reachable.
const V4_FORBIDDEN = [
  [[0, 0, 0, 0], 8, "unspecified"],
  [[10, 0, 0, 0], 8, "rfc1918"],
  [[100, 64, 0, 0], 10, "shared_cgnat"],
  [[127, 0, 0, 0], 8, "loopback"],
  [[169, 254, 0, 0], 16, "link_local_metadata"],
  [[172, 16, 0, 0], 12, "rfc1918"],
  [[192, 0, 0, 0], 24, "ietf_protocol"],
  [[192, 0, 2, 0], 24, "documentation"],
  [[192, 88, 99, 0], 24, "relay_6to4"],
  [[192, 168, 0, 0], 16, "rfc1918"],
  [[198, 18, 0, 0], 15, "benchmarking"],
  [[198, 51, 100, 0], 24, "documentation"],
  [[203, 0, 113, 0], 24, "documentation"],
  [[224, 0, 0, 0], 4, "multicast"],
  [[240, 0, 0, 0], 4, "reserved"],
];

export function classifyIPv4(parts) {
  for (const [base, bits, why] of V4_FORBIDDEN) {
    if (v4InRange(parts, base, bits)) return { allowed: false, reason: why };
  }
  return { allowed: true, reason: "global" };
}

/** Parses an IPv6 literal (no brackets, no zone) into 8 hextets, or null. */
export function parseIPv6(text) {
  if (typeof text !== "string" || !text.includes(":") || text.includes("%")) return null;
  let s = text.toLowerCase();
  let tail = [];
  const v4 = s.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (v4) {
    const p = parseIPv4(v4[2]);
    if (!p) return null;
    tail = [(p[0] << 8) | p[1], (p[2] << 8) | p[3]];
    s = v4[1] + "0:0";
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const toNums = (h) => (h === "" ? [] : h.split(":").map((x) => (/^[0-9a-f]{1,4}$/.test(x) ? parseInt(x, 16) : NaN)));
  const head = toNums(halves[0]);
  const rest = halves.length === 2 ? toNums(halves[1]) : [];
  if ([...head, ...rest].some((n) => Number.isNaN(n))) return null;
  let out;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    out = [...head, ...new Array(fill).fill(0), ...rest];
  } else {
    out = head;
  }
  if (out.length !== 8) return null;
  if (tail.length) { out[6] = tail[0]; out[7] = tail[1]; }
  return out;
}

export function classifyIPv6(h) {
  if (h.every((x) => x === 0)) return { allowed: false, reason: "unspecified" };
  if (h.slice(0, 7).every((x) => x === 0) && h[7] === 1) return { allowed: false, reason: "loopback" };
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) return { allowed: false, reason: "ipv4_mapped" };
  if (h.slice(0, 6).every((x) => x === 0)) return { allowed: false, reason: "ipv4_compatible" };
  if (h[0] === 0x64 && h[1] === 0xff9b) return { allowed: false, reason: "nat64" };
  // Only 2000::/3 is global unicast. This single rule removes ULA fc00::/7,
  // link-local fe80::/10, multicast ff00::/8, and everything reserved.
  if (h[0] < 0x2000 || h[0] > 0x3fff) return { allowed: false, reason: "non_global_ipv6" };
  if (h[0] === 0x2001 && h[1] < 0x200) return { allowed: false, reason: "ietf_protocol" };
  if (h[0] === 0x2001 && h[1] === 0x0db8) return { allowed: false, reason: "documentation" };
  if (h[0] === 0x2002) return { allowed: false, reason: "relay_6to4" };
  if (h[0] === 0x3fff && h[1] < 0x1000) return { allowed: false, reason: "documentation" };
  return { allowed: true, reason: "global" };
}

export function classifyAddress(text) {
  const raw = String(text || "").replace(/^\[|\]$/g, "");
  const v4 = parseIPv4(raw);
  if (v4) return { family: 4, ...classifyIPv4(v4) };
  const v6 = parseIPv6(raw);
  if (v6) return { family: 6, ...classifyIPv6(v6) };
  return { family: 0, allowed: false, reason: "not_an_address" };
}

export function blockedHostname(name) {
  const host = String(name || "").replace(/\.$/, "").toLowerCase();
  if (!host) return true;
  if (BLOCKED_NAME.test(host)) return true;
  if (BLOCKED_SUFFIX.some((s) => host.endsWith(s))) return true;
  // Single-label names resolve through search domains, never publicly.
  if (!host.includes(".") && !host.includes(":")) return true;
  return false;
}

// ---------------------------------------------------------------------------
// URL + DNS validation
// ---------------------------------------------------------------------------

/**
 * Static checks only. Returns { url, hostname, literal } or { error, message }.
 * WHATWG URL parsing normalizes decimal/hex/short IPv4 forms (2130706433,
 * 0x7f.1) to dotted quads before classification.
 */
export function validateDestinationUrl(input) {
  let url;
  try { url = new URL(String(input || "")); } catch { return { error: "invalid_destination", message: "Webhook URL must be https." }; }
  if (url.protocol !== "https:") return { error: "invalid_destination", message: "Webhook URL must be https." };
  if (url.username || url.password) return { error: "invalid_destination", message: "Webhook URL must not contain credentials." };
  if (url.port && url.port !== "443") return { error: "invalid_destination", message: "Webhook URL must use port 443." };
  if (url.hash) return { error: "invalid_destination", message: "Webhook URL must not contain a fragment." };
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const literal = classifyAddress(hostname);
  if (literal.family) {
    if (!literal.allowed) return { error: "invalid_destination", message: "Webhook host is not allowed." };
  } else if (blockedHostname(hostname)) {
    return { error: "invalid_destination", message: "Webhook host is not allowed." };
  }
  return { url: url.origin + url.pathname + url.search, hostname, literal: literal.family !== 0 };
}

async function dohQuery(name, type, fetchImpl) {
  const q = DOH_ENDPOINT + "?name=" + encodeURIComponent(name) + "&type=" + type;
  const res = await fetchImpl(q, { headers: { Accept: "application/dns-json" }, redirect: "manual" });
  if (!res || !res.ok) throw new Error("doh_http_" + (res && res.status));
  return res.json();
}

/**
 * Resolves A and AAAA for hostname and validates every answer.
 * Returns { ok: true, addresses, cnames } or { ok: false, error, retryable }.
 * error: dns_nxdomain | dns_no_address | dns_unavailable | forbidden_address | forbidden_cname
 */
export async function resolveAndValidate(hostname, fetchImpl) {
  const literal = classifyAddress(hostname);
  if (literal.family) {
    return literal.allowed
      ? { ok: true, addresses: [hostname], cnames: [] }
      : { ok: false, error: "forbidden_address", retryable: false, reason: literal.reason };
  }
  if (blockedHostname(hostname)) return { ok: false, error: "forbidden_cname", retryable: false };
  let answers;
  try {
    answers = await Promise.all([dohQuery(hostname, "A", fetchImpl), dohQuery(hostname, "AAAA", fetchImpl)]);
  } catch {
    return { ok: false, error: "dns_unavailable", retryable: true };
  }
  const addresses = [];
  const cnames = [];
  for (const res of answers) {
    const status = Number(res && res.Status);
    if (status === 3) return { ok: false, error: "dns_nxdomain", retryable: true };
    if (status !== 0) return { ok: false, error: "dns_unavailable", retryable: true };
    for (const a of Array.isArray(res.Answer) ? res.Answer : []) {
      const type = Number(a && a.type);
      const data = String((a && a.data) || "").trim();
      if (type === 5) cnames.push(data.replace(/\.$/, "").toLowerCase());
      else if (type === 1 || type === 28) addresses.push(data);
    }
  }
  for (const c of cnames) {
    const asAddr = classifyAddress(c);
    if ((asAddr.family && !asAddr.allowed) || (!asAddr.family && blockedHostname(c))) {
      return { ok: false, error: "forbidden_cname", retryable: false };
    }
  }
  if (!addresses.length) return { ok: false, error: "dns_no_address", retryable: true };
  for (const addr of addresses) {
    const c = classifyAddress(addr);
    if (!c.allowed) return { ok: false, error: "forbidden_address", retryable: false, reason: c.reason };
  }
  return { ok: true, addresses: [...new Set(addresses)], cnames };
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function generateSigningSecret(randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n))) {
  return "whsec_" + hex(randomBytes(32));
}

/** hex(HMAC-SHA256(secret, `${timestamp}.${rawBody}`)); secret is used as UTF-8 bytes. */
export async function signPayload(secret, timestamp, rawBody) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(String(timestamp) + "." + rawBody));
  return hex(sig);
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/**
 * Reference receiver check (also used by the canary and the sink).
 * Returns { ok, reason }.
 */
export async function verifySignature({ secret, timestamp, signature, rawBody, nowMs = Date.now(), toleranceSeconds = WEBHOOK_CONTRACT.timestamp_tolerance_seconds }) {
  const ts = Number(timestamp);
  if (!Number.isInteger(ts)) return { ok: false, reason: "bad_timestamp" };
  if (Math.abs(Math.floor(nowMs / 1000) - ts) > toleranceSeconds) return { ok: false, reason: "timestamp_outside_tolerance" };
  const m = /^v1=([0-9a-f]{64})$/.exec(String(signature || ""));
  if (!m) return { ok: false, reason: "bad_signature_format" };
  const expected = await signPayload(secret, ts, rawBody);
  return safeEqualHex(expected, m[1]) ? { ok: true, reason: null } : { ok: false, reason: "signature_mismatch" };
}

export async function signedHeaders({ secret, eventId, deliveryId, attempt, rawBody, nowMs = Date.now() }) {
  const ts = Math.floor(nowMs / 1000);
  const sig = await signPayload(secret, ts, rawBody);
  const h = WEBHOOK_CONTRACT.headers;
  return {
    "Content-Type": "application/json",
    "User-Agent": "CYBERDUDEBIVASH-SENTINEL-APEX-CYBER-WATCHDOG/3.0",
    [h.event_id]: eventId,
    [h.delivery_id]: deliveryId,
    [h.timestamp]: String(ts),
    [h.signature]: WEBHOOK_CONTRACT.signature_scheme + "=" + sig,
    [h.version]: WEBHOOK_CONTRACT.version,
    [h.attempt]: String(attempt),
  };
}

// ---------------------------------------------------------------------------
// Delivery outcome classification
// ---------------------------------------------------------------------------

export function parseRetryAfter(value, nowMs = Date.now()) {
  if (value == null || value === "") return null;
  const s = String(value).trim();
  if (/^\d+$/.test(s)) return Number(s);
  const t = Date.parse(s);
  if (!Number.isFinite(t)) return null;
  return Math.max(0, Math.ceil((t - nowMs) / 1000));
}

/**
 * Maps one HTTP attempt to { outcome: delivered|retry|failed, disable, error, retry_after_seconds }.
 * status null means the request did not complete (timeout / network).
 */
export function classifyHttpOutcome(status, retryAfterHeader, nowMs = Date.now()) {
  const p = DELIVERY_POLICY;
  if (status == null) return { outcome: "retry", disable: null, error: "network_or_timeout", retry_after_seconds: null };
  if (status >= 200 && status < 300) return { outcome: "delivered", disable: null, error: null, retry_after_seconds: null };
  if (status >= 300 && status < 400) return { outcome: "failed", disable: null, error: "redirect_not_followed", retry_after_seconds: null };
  if (p.non_retryable_statuses.includes(status)) {
    return { outcome: "failed", disable: p.auto_disable_on_status.includes(status) ? "gone" : null, error: "http_" + status, retry_after_seconds: null };
  }
  const ra = p.retry_after_statuses.includes(status) ? parseRetryAfter(retryAfterHeader, nowMs) : null;
  if (status === 429 || status === 408 || status === 425 || status >= 500) {
    return { outcome: "retry", disable: null, error: "http_" + status, retry_after_seconds: ra };
  }
  return { outcome: "failed", disable: null, error: "http_" + status, retry_after_seconds: null };
}

/** Seconds to wait before attempt number `nextAttempt` (2..max). */
export function retryDelaySeconds(nextAttempt, retryAfterSeconds) {
  const p = DELIVERY_POLICY;
  const base = p.backoff_seconds[Math.min(nextAttempt - 1, p.backoff_seconds.length - 1)] || 0;
  if (retryAfterSeconds == null) return base;
  return Math.min(p.retry_after_max_seconds, Math.max(base, retryAfterSeconds));
}

/**
 * One delivery attempt: re-resolve + validate, sign, POST (redirect manual).
 * Returns { outcome, http_status, error, disable, retry_after_seconds }.
 */
export async function attemptDelivery({ destination, eventId, deliveryId, attempt, rawBody, fetchImpl, dnsFetch, nowMs = Date.now() }) {
  const checked = validateDestinationUrl(destination.url);
  if (checked.error) return { outcome: "failed", http_status: null, error: "invalid_destination", disable: "invalid_destination", retry_after_seconds: null };
  const resolved = await resolveAndValidate(checked.hostname, dnsFetch || fetchImpl);
  if (!resolved.ok) {
    if (resolved.retryable) return { outcome: "retry", http_status: null, error: resolved.error, disable: null, retry_after_seconds: null };
    return { outcome: "failed", http_status: null, error: resolved.error, disable: DELIVERY_POLICY.auto_disable_on_forbidden_address ? "forbidden_address" : null, retry_after_seconds: null };
  }
  const headers = await signedHeaders({ secret: destination.secret, eventId, deliveryId, attempt, rawBody, nowMs });
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DELIVERY_POLICY.timeout_ms);
  try {
    const res = await fetchImpl(checked.url, { method: "POST", redirect: DELIVERY_POLICY.redirect, headers, body: rawBody, signal: ctrl.signal });
    const status = Number(res && res.status);
    const retryAfter = res && res.headers && typeof res.headers.get === "function" ? res.headers.get("Retry-After") : null;
    return { ...classifyHttpOutcome(Number.isFinite(status) ? status : null, retryAfter, nowMs), http_status: Number.isFinite(status) ? status : null };
  } catch {
    return { ...classifyHttpOutcome(null, null, nowMs), http_status: null };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Verification challenge. The endpoint must answer 2xx with JSON
 * {"challenge": "<nonce>"} echoing the nonce it was sent. The challenge is
 * signed with the destination secret like any delivery, so the receiver can
 * also prove it holds the secret before trusting the request.
 */
export async function runVerificationChallenge({ destination, nonce, fetchImpl, dnsFetch, nowMs = Date.now() }) {
  const checked = validateDestinationUrl(destination.url);
  if (checked.error) return { ok: false, error: "invalid_destination" };
  const resolved = await resolveAndValidate(checked.hostname, dnsFetch || fetchImpl);
  if (!resolved.ok) return { ok: false, error: resolved.error };
  const rawBody = JSON.stringify({ type: "watchdog.verification", destination_id: destination.id, challenge: nonce, contract_version: WEBHOOK_CONTRACT.version });
  const deliveryId = "verify:" + destination.id;
  const headers = await signedHeaders({ secret: destination.secret, eventId: deliveryId, deliveryId, attempt: 1, rawBody, nowMs });
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), DELIVERY_POLICY.timeout_ms);
  try {
    const res = await fetchImpl(checked.url, { method: "POST", redirect: DELIVERY_POLICY.redirect, headers, body: rawBody, signal: ctrl.signal });
    const status = Number(res && res.status);
    if (!(status >= 200 && status < 300)) return { ok: false, error: status >= 300 && status < 400 ? "redirect_not_followed" : "http_" + status };
    let body = null;
    try { body = await res.json(); } catch { body = null; }
    if (!body || typeof body.challenge !== "string" || !safeEqualHex(body.challenge, nonce)) return { ok: false, error: "challenge_mismatch" };
    return { ok: true, error: null };
  } catch {
    return { ok: false, error: "network_or_timeout" };
  } finally {
    clearTimeout(timer);
  }
}
