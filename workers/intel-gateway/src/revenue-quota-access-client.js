/**
 * Optional Cloudflare Access machine identity for the Revenue Engine quota
 * notification caller. No new service, account policy, or token is created.
 *
 * Default: legacy X-Admin-Secret header only. When both new encrypted Worker
 * secrets are explicitly provisioned, attach Access service credentials as
 * documented by Cloudflare. Access must authenticate the HTTP subrequest and
 * issue a signed Cf-Access-Jwt-Assertion to the Revenue Engine origin; the
 * Revenue Engine independently verifies its issuer, audience, signature,
 * expiry and approved service common_name in required mode.
 *
 * Partial/invalid provisioning FAILS CLOSED for this background notification:
 * the caller does not send any request or mark the alert complete. The
 * customer API's core quota decision is unaffected.
 */
export function revenueQuotaAlertHeaders(env) {
  const adminSecret = env?.REVENUE_ADMIN_SECRET;
  if (typeof adminSecret !== 'string' || !adminSecret) return null;

  const id = env?.REVENUE_CF_ACCESS_CLIENT_ID;
  const secret = env?.REVENUE_CF_ACCESS_CLIENT_SECRET;
  const hasId = id !== undefined && id !== null && id !== '';
  const hasSecret = secret !== undefined && secret !== null && secret !== '';
  if (hasId !== hasSecret) return null; // never send one half of a service token

  if (hasId) {
    // Avoid header injection, accidentally copied placeholders and unexpected
    // large/whitespace-bearing credentials. Legacy and new cfast_ tokens
    // are alphanumeric with optional underscore and hyphen.
    if (typeof id !== 'string' || id.length < 8 || id.length > 256 ||
        !/^[A-Za-z0-9._-]+$/.test(id) ||
        typeof secret !== 'string' || secret.length < 24 ||
        secret.length > 256 || !/^[A-Za-z0-9_-]+$/.test(secret)) return null;
  }

  try {
    const headers = new Headers({
      'Content-Type': 'application/json',
      'X-Admin-Secret': adminSecret,
    });
    if (hasId) {
      headers.set('CF-Access-Client-Id', id);
      headers.set('CF-Access-Client-Secret', secret);
    }
    return headers;
  } catch {
    return null;
  }
}
