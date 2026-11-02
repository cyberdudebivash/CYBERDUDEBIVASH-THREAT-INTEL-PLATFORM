/**
 * Independent, opt-in HMAC grants for the Revenue Engine customer portal.
 * NOT an admin credential. No KV/D1 writes, provider calls or new bindings.
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const AUD = 'cdb.revenue.customer-portal';
const TTL_SECONDS = 24 * 60 * 60;
const MAX_LEGACY_GRACE_MS = 30 * 24 * 60 * 60 * 1000;
const B64URL = /^[A-Za-z0-9_-]+$/;

/**
 * Stream-limited JSON reader: does not allocate arbitrary attacker-controlled
 * bodies before applying the 2 KiB portal request budget.
 */
export async function readBoundedPortalJson(request) {
  const reader = request?.body?.getReader();
  if (!reader) return { ok: false, status: 400 };
  let used = 0;
  const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) return { ok: false, status: 400 };
      used += value.byteLength;
      if (used > 2048) {
        await reader.cancel().catch(() => {});
        return { ok: false, status: 413 };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(used);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const payload = JSON.parse(decoder.decode(bytes));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload))
      return { ok: false, status: 400 };
    return { ok: true, payload };
  } catch {
    return { ok: false, status: 400 };
  } finally {
    try { reader.releaseLock(); } catch {}
  }
}

export function portalV2Enabled(env) {
  return env?.REVENUE_PORTAL_V2_ENABLED === 'true';
}
function signingSecret(env) {
  const value = env?.REVENUE_PORTAL_HMAC_KEY;
  if (typeof value !== 'string' || encoder.encode(value).length < 32 ||
      value === env?.REVENUE_ADMIN_SECRET) return null;
  return value;
}
export function portalV2Configured(env) {
  return portalV2Enabled(env) && signingSecret(env) !== null;
}
export function legacyPortalAllowed(env, now = Date.now()) {
  if (!portalV2Enabled(env)) return true;
  const raw = env?.REVENUE_PORTAL_LEGACY_ACCEPT_UNTIL;
  if (typeof raw !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(raw)) return false;
  const until = Date.parse(raw);
  return Number.isFinite(until) && Number.isFinite(now) &&
    until > now && until <= now + MAX_LEGACY_GRACE_MS &&
    new Date(until).toISOString().replace('.000Z','Z') === raw;
}
function toB64Url(bytes) {
  let value = '';
  for (const byte of bytes) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function fromB64Url(value) {
  if (typeof value !== 'string' || !value.length || !B64URL.test(value)) return null;
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
  try {
    const data = atob(padded);
    const bytes = Uint8Array.from(data, c => c.charCodeAt(0));
    if (toB64Url(bytes) !== value) return null;
    return bytes;
  } catch { return null; }
}
function sameBytes(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
async function mac(secret, message) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(message)));
}
function normalizedEmail(email) {
  return typeof email === 'string' && email.length <= 254 &&
    email === email.trim().toLowerCase() &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export async function issuePortalTokenV2(env, email, now = Date.now()) {
  const secret = signingSecret(env);
  if (!portalV2Enabled(env) || !secret || !normalizedEmail(email) ||
      !Number.isSafeInteger(now) || now < 0) return null;
  const seconds = Math.floor(now / 1000);
  const nonce = toB64Url(crypto.getRandomValues(new Uint8Array(16)));
  const claims = { v: 2, aud: AUD, sub: email, iat: seconds,
    exp: seconds + TTL_SECONDS, nonce };
  const payload = toB64Url(encoder.encode(JSON.stringify(claims)));
  const signature = toB64Url(await mac(secret, `portal-v2.${payload}`));
  return `v2.${payload}.${signature}`;
}

export async function verifyPortalTokenV2(env, email, token, now = Date.now()) {
  const secret = signingSecret(env);
  if (!portalV2Enabled(env) || !secret || !normalizedEmail(email) ||
      typeof token !== 'string' || token.length > 1024 ||
      !Number.isSafeInteger(now) || now < 0) return false;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v2' || parts[1].length > 512) return false;
  const payloadBytes = fromB64Url(parts[1]);
  const providedSignature = fromB64Url(parts[2]);
  if (!payloadBytes || !providedSignature || providedSignature.length !== 32) return false;
  const expected = await mac(secret, `portal-v2.${parts[1]}`);
  if (!sameBytes(providedSignature, expected)) return false;
  let claims;
  try { claims = JSON.parse(decoder.decode(payloadBytes)); }
  catch { return false; }
  const seconds = Math.floor(now / 1000);
  return claims !== null && typeof claims === 'object' &&
    claims.v === 2 && claims.aud === AUD && claims.sub === email &&
    Number.isSafeInteger(claims.iat) && Number.isSafeInteger(claims.exp) &&
    typeof claims.nonce === 'string' && /^[A-Za-z0-9_-]{22}$/.test(claims.nonce) &&
    claims.iat <= seconds && claims.iat >= seconds - TTL_SECONDS &&
    claims.exp > seconds && claims.exp - claims.iat === TTL_SECONDS;
}
