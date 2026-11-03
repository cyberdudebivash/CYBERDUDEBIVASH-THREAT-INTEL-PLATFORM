/**
 * Revenue Engine operator identity boundary.
 *
 * Intentionally OFF by default. When REVENUE_OPERATOR_ACCESS_MODE=required,
 * every request carrying X-Admin-Secret must also carry a verified Cloudflare
 * Access RS256 JWT for a specifically allowlisted operator identity.
 *
 * JWKS is provisioned as an encrypted Worker secret. No network or KV/D1
 * reads, no new metered Cloudflare services, no logging of JWTs or secrets.
 * This is an additional authorization factor, not a replacement for isAdmin().
 */
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const SKEW_SECONDS = 60;
const MAX_TOKEN_AGE_SECONDS = 24 * 60 * 60;

function b64urlBytes(value, maxLength) {
  if (typeof value !== 'string' || !value || value.length > maxLength ||
      !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/')
      + '='.repeat((4 - value.length % 4) % 4);
    const raw = atob(padded);
    return Uint8Array.from(raw, ch => ch.charCodeAt(0));
  } catch {
    return null;
  }
}

function parseSegment(value, maxLength) {
  const bytes = b64urlBytes(value, maxLength);
  if (!bytes) return null;
  try {
    const parsed = JSON.parse(decoder.decode(bytes));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function configuredIssuer(value) {
  return typeof value === 'string' &&
    /^https:\/\/[a-z0-9][a-z0-9-]*\.cloudflareaccess\.com$/i.test(value);
}

function operatorAllowed(email, value) {
  if (typeof email !== 'string' || typeof value !== 'string' ||
      value.length > 4096 || email.length > 254) return false;
  const normalized = email.trim().toLowerCase();
  const operators = value.split(',').map(v => v.trim().toLowerCase());
  return operators.length > 0 && operators.length <= 20 &&
    operators.every(v => /^[^\s@,]+@[^\s@,]+$/.test(v)) &&
    operators.includes(normalized);
}

function serviceAllowed(commonName, value) {
  if (typeof commonName !== 'string' || typeof value !== 'string' ||
      commonName.length > 256 || value.length > 4096) return false;
  const identifiers = value.split(',').map(v => v.trim());
  return identifiers.length > 0 && identifiers.length <= 20 &&
    identifiers.every(v => /^[A-Za-z0-9._-]{8,256}$/.test(v)) &&
    identifiers.includes(commonName);
}

/**
 * @param {Request} request
 * @param {object} env
 * @param {number} nowSeconds Injected clock for deterministic offline tests.
 * @returns {Promise<boolean>} Does this request meet the configured operator boundary?
 */
export async function authorizeRevenueOperator(request, env, nowSeconds = Math.floor(Date.now() / 1000)) {
  const mode = env?.REVENUE_OPERATOR_ACCESS_MODE;
  if (mode === undefined || mode === null || mode === '' || mode === 'off') return true;
  if (mode !== 'required') return false;

  try {
    const issuer = env.REVENUE_OPERATOR_ACCESS_ISSUER;
    const audience = env.REVENUE_OPERATOR_ACCESS_AUDIENCE;
    const allowlist = env.REVENUE_OPERATOR_ACCESS_EMAILS;
    const jwksString = env.REVENUE_OPERATOR_ACCESS_JWKS;
    if (!configuredIssuer(issuer) ||
        typeof audience !== 'string' || audience.length < 8 || audience.length > 256 ||
        !/^[A-Za-z0-9_-]+$/.test(audience) ||
        typeof jwksString !== 'string' || jwksString.length > 50000 ||
        typeof allowlist !== 'string' || !allowlist.trim()) return false;

    const token = request.headers.get('Cf-Access-Jwt-Assertion');
    if (typeof token !== 'string' || token.length > 8192) return false;
    const sections = token.split('.');
    if (sections.length !== 3) return false;
    const [protectedHeader, payloadPart, signaturePart] = sections;
    const header = parseSegment(protectedHeader, 2048);
    const claims = parseSegment(payloadPart, 4096);
    const signature = b64urlBytes(signaturePart, 4096);
    if (!header || !claims || !signature ||
        header.alg !== 'RS256' || typeof header.kid !== 'string' ||
        header.kid.length < 1 || header.kid.length > 256 ||
        claims.iss !== issuer || claims.type !== 'app' ||
        !(claims.aud === audience || (Array.isArray(claims.aud) && claims.aud.includes(audience))) ||
        typeof claims.sub !== 'string' || claims.sub.length > 256 ||
        !((claims.sub.length > 0 && operatorAllowed(claims.email, allowlist)) ||
          (claims.sub.length === 0 && serviceAllowed(
            claims.common_name, env.REVENUE_OPERATOR_ACCESS_SERVICE_IDS
          )))) return false;

    if (!Number.isInteger(nowSeconds) || nowSeconds <= 0 ||
        !Number.isInteger(claims.iat) || !Number.isInteger(claims.exp) ||
        claims.iat > nowSeconds + SKEW_SECONDS ||
        claims.exp <= nowSeconds ||
        claims.exp <= claims.iat ||
        claims.exp - claims.iat > MAX_TOKEN_AGE_SECONDS ||
        nowSeconds - claims.iat > MAX_TOKEN_AGE_SECONDS ||
        (claims.nbf !== undefined &&
          (!Number.isInteger(claims.nbf) || claims.nbf > nowSeconds + SKEW_SECONDS))) return false;

    const jwks = JSON.parse(jwksString);
    if (!jwks || !Array.isArray(jwks.keys) || jwks.keys.length < 1 ||
        jwks.keys.length > 12) return false;
    const matches = jwks.keys.filter(key => key && key.kid === header.kid &&
      key.kty === 'RSA' && (!key.alg || key.alg === 'RS256') &&
      (!key.use || key.use === 'sig') &&
      (!key.key_ops || (Array.isArray(key.key_ops) && key.key_ops.includes('verify'))));
    if (matches.length !== 1) return false;

    const key = await crypto.subtle.importKey(
      'jwk', matches[0],
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false, ['verify']
    );
    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5', key, signature,
      encoder.encode(protectedHeader + '.' + payloadPart)
    );
  } catch {
    return false;
  }
}
