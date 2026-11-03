/**
 * Opt-in trust-boundary isolation for customer enterprise-quotation capabilities.
 *
 * Default (unset/off/false): the legacy quote HMAC remains unchanged.
 * Enabled: new links are signed using an independently provisioned quote key.
 * Existing legacy customer links need an explicit, bounded migration grace.
 *
 * No KV, D1, external calls, additional Cloudflare products or paid executions.
 */
const utf8 = new TextEncoder();
const TOKEN_PATTERN = /^[0-9a-f]{64}$/;
const MAX_GRACE_MS = 90 * 86_400_000;

function mode(env) {
  const value = env?.REVENUE_QUOTE_V2_ENABLED;
  if (value === undefined || value === null || value === '' ||
      value === 'off' || value === 'false') return 'legacy';
  return value === 'true' ? 'v2' : 'invalid';
}

function v2Key(env) {
  const key = env?.REVENUE_QUOTE_HMAC_KEY;
  if (typeof key !== 'string' || utf8.encode(key).length < 32 ||
      key === env?.REVENUE_ADMIN_SECRET ||
      (env?.REVENUE_PORTAL_HMAC_KEY && key === env.REVENUE_PORTAL_HMAC_KEY)) return null;
  return key;
}

export function quoteV2Enabled(env) {
  return mode(env) === 'v2';
}

export function quoteSigningReady(env) {
  const state = mode(env);
  return state === 'legacy' || (state === 'v2' && Boolean(v2Key(env)));
}

/** Whether previously issued, admin-secret-signed capabilities may still work. */
export function quoteLegacyAllowed(env, atMs = Date.now()) {
  const state = mode(env);
  if (state === 'legacy') return true;
  if (state !== 'v2' || !v2Key(env) || !Number.isFinite(atMs)) return false;
  const grace = env?.REVENUE_QUOTE_LEGACY_ACCEPT_UNTIL;
  const cutover = env?.REVENUE_QUOTE_LEGACY_CUTOVER_AT;
  const format = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  if (typeof grace !== 'string' || typeof cutover !== 'string' ||
      !format.test(grace) || !format.test(cutover)) return false;
  const endMs = Date.parse(grace);
  const startMs = Date.parse(cutover);
  return Number.isFinite(endMs) && Number.isFinite(startMs) &&
    new Date(endMs).toISOString().replace('.000Z', 'Z') === grace &&
    new Date(startMs).toISOString().replace('.000Z', 'Z') === cutover &&
    startMs <= atMs && endMs > atMs && endMs > startMs &&
    endMs - startMs <= MAX_GRACE_MS;
}

async function hmacHex(secret, scope, id) {
  if (typeof secret !== 'string' || secret.length === 0 ||
      typeof id !== 'string' || !/^qt_[0-9a-f]{20}$/.test(id)) return null;
  const key = await crypto.subtle.importKey(
    'raw', utf8.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const bytes = new Uint8Array(await crypto.subtle.sign(
    'HMAC', key, utf8.encode(scope + id)
  ));
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' ||
      !TOKEN_PATTERN.test(a) || !TOKEN_PATTERN.test(b)) return false;
  let diff = 0;
  for (let i = 0; i < 64; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Generates the token for the currently active quote signer; never logs it. */
export async function issueQuoteToken(env, id) {
  const state = mode(env);
  try {
    if (state === 'legacy') return await hmacHex(env?.REVENUE_ADMIN_SECRET, 'quote:', id);
    if (state !== 'v2') return null;
    const key = v2Key(env);
    return key ? await hmacHex(key, 'quote:v2:', id) : null;
  } catch {
    return null;
  }
}

/** Check one quote capability before any quote-data database read. */
export async function verifyQuoteToken(env, id, token, atMs = Date.now()) {
  if (typeof id !== 'string' || !/^qt_[0-9a-f]{20}$/.test(id) ||
      typeof token !== 'string' || !TOKEN_PATTERN.test(token)) return false;
  const state = mode(env);
  if (state === 'invalid' || !quoteSigningReady(env)) return false;
  try {
    // Legacy mode does not change historical behavior.
    if (state === 'legacy') {
      const expected = await hmacHex(env?.REVENUE_ADMIN_SECRET, 'quote:', id);
      return constantTimeHexEqual(token, expected);
    }
    const next = await hmacHex(v2Key(env), 'quote:v2:', id);
    if (constantTimeHexEqual(token, next)) return true;
    if (!quoteLegacyAllowed(env, atMs)) return false;
    const old = await hmacHex(env?.REVENUE_ADMIN_SECRET, 'quote:', id);
    return constantTimeHexEqual(token, old);
  } catch {
    return false;
  }
}
