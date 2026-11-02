# Revenue Engine zero-trust customer-portal migration — HOLD until authorized

## Security incident and blast radius

The existing Revenue Engine used a single `REVENUE_ADMIN_SECRET` for both its privileged administration API and the HMAC that signs perpetual customer-portal URL tokens. The VDP report of 2 November 2026 found that the admin API is publicly reachable and protected by the header; unauthenticated GET /, /health and a nonexistent path returned 401. The preflight `Access-Control-Allow-Methods` list **does not prove unauthenticated mutation**, and `X-Admin-Secret` is not itself an authentication bypass. Nonetheless, accidental disclosure of that secret would affect both privileged admin access and customer portal tokens.

This patch **does not claim to close the admin header/zero-trust perimeter finding**. It removes one credential-reuse path **only after reviewed activation**, with no new Cloudflare service or paid AI requests.

## Independent customer grants

- V2 is **opt-in only**: `REVENUE_PORTAL_V2_ENABLED='true'`. Default/unset behavior and existing issued customer links remain unchanged.
- `REVENUE_PORTAL_HMAC_KEY` is a **different, confidential, cryptographically random** secret, at least 32 bytes; the runtime explicitly rejects reuse of `REVENUE_ADMIN_SECRET`. Supply it only through approved Cloudflare encrypted secrets, not `wrangler.toml`, repo, email, chat, or CI logs.
- Newly issued grants are `v2.<payload>.<HMAC-SHA256>`, scoped to one normalized email and `cdb.revenue.customer-portal`, 24-hour maximum lifetime and cryptographic nonce. HMAC validation is performed before trusting claims. **Grants are bearer tokens**: they are not one-time or individually revocable. No contrary security claim is permitted; a compromised grant remains usable for up to 24 hours or until signing-key rotation.
- New activation URLs use `?email=...#portal=v2....`; the hash fragment is stripped immediately after frontend load and is transmitted only in `Authorization: Bearer` on POST `/api/customer/portal` with email in JSON. Existing query-token GET links are read then stripped from the browser address bar for compatibility.
- V2 requests require a configured dedicated key, JSON POST, a valid signature, and a matching verified subject, before customer KV lookups. No admin header can substitute for a customer bearer.
- Unauthenticated/invalid credentials must not read other customers' profiles or keys. Existing customer output continues to mask API keys.

## Authorized cutover (separate release, never automatic)

1. Confirm production customer inventory, support/reissue path, frontend source and Worker revision, paid transaction workflow and current entitlement authorization. Do not deploy if a portal email could reference an incompatible frontend.
2. Generate a dedicated HMAC key using an approved secure entropy source, store as Cloudflare **secret**, and validate *presence only* on the exact staging/production Worker version. Do not put the value in this document.
3. Set `REVENUE_PORTAL_V2_ENABLED='true'` only after both the portal frontend and Worker have been independently certified and approved together. Do not allow unreviewed configuration changes.
4. To migrate previously emailed links, optionally set `REVENUE_PORTAL_LEGACY_ACCEPT_UNTIL` to an explicitly reviewed UTC second-precision timestamp, at most 30 days in the future. Default after V2 activation is **deny legacy GET**. Expired links must be reissued via support using identity verification; do not silently keep legacy HMACs indefinitely.
5. Run `node --test workers/revenue-engine/src/__tests__/portal-token-v2.test.js` alongside the complete Revenue Engine tests. Verify negative/positive customer-identity cases, key rotation/revocation behavior, CORS, Razorpay signed webhooks, GST invoice, refunds, and accepted customer purchases.
6. Confirm production origin policy, Cloudflare Worker source, exact active route, no surprise auto-deploy, rollback to previous approved release, and a clean cost check under the existing Cloudflare plan. Keep customer billing/data untouched.
7. Release with owner authorization, deterministic deployment provenance, post-deploy authenticated and unauthenticated acceptance and privacy redaction. Prioritize written researcher acknowledgment; do not close the VDP issue until static admin credential exposure is separately reviewed and independently remediated.

## Follow-up security work — not silently included

- Replace the long-lived `X-Admin-Secret` as the sole admin authorization factor with a separately approved operator identity boundary (e.g. Cloudflare Access with verified token audience/issuer and revocation, subject to the no-new-billing constraint). Verify all admin and billing route handlers, including routes dispatched before the central admin gate.
- Obtain route-by-route negative authorization and CORS tests. CORS is a browser restriction, never proof of backend authorization.
- Add bounded, reliable rejection telemetry and throttling without leaking tokens or using non-atomic KV as a security-critical global admission store.
- Plan v2 token revocation and one-time exchange only with an atomic server-side store and a measured resource budget; do not label this 24h bearer link single-use.
