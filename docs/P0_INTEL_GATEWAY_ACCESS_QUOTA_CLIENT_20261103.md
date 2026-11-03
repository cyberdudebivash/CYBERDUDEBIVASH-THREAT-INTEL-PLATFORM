# P0 Revenue Engine Access machine-client migration — Intel Gateway quota alert

Date: 2026-11-03. **Source-only; default-off; production HOLD.**

## Confirmed current trust boundary

Intel Gateway POSTs to the existing Revenue Engine `/api/automation/trigger` using `X-Admin-Secret`. The Revenue Engine's source-level operator gate (merged in PR #958, **off by default in source; live deployment unverified**) requires an authentic Access RS256 JWT in the `Cf-Access-Jwt-Assertion` header **in addition** to `X-Admin-Secret` if `REVENUE_OPERATOR_ACCESS_MODE=required`. Service identities must be signed, issued for the configured application audience, and included in `REVENUE_OPERATOR_ACCESS_SERVICE_IDS`; the operator email allowlist, JWKS, issuer and audience must also be correctly configured. The previous source inventory PR #965 correctly blocks global activation pending an approved client-by-client cutover.

Cloudflare documents service-to-service Access requests with `CF-Access-Client-Id` plus `CF-Access-Client-Secret`; Access authenticates them under an approved Service Auth policy and forwards a signed application JWT to the origin. Reference: https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/ and https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/ .

## Implemented isolated source change

`workers/intel-gateway/src/revenue-quota-access-client.js` builds HTTP headers for this one backend-to-backend quota alert. Legacy behavior is **unchanged** when the optional values are entirely absent: JSON content-type + existing `X-Admin-Secret`. Only when the operator separately provisions **both** encrypted Worker secrets listed below does it append the Cloudflare Access credential pair:

- `REVENUE_CF_ACCESS_CLIENT_ID`
- `REVENUE_CF_ACCESS_CLIENT_SECRET`

Both must be bounded, printable strings without whitespace or header-control characters. If exactly one is configured, an invalid value is supplied or the admin secret is absent, the function returns null and the notification is **not attempted**. This happens before the gateway's alert deduplication marker, so it never falsely marks the customer warned. The customer's paid API request is unaffected. **No Access JWT is manufactured or trusted from gateway code**; only Cloudflare Access can issue the signed assertion and the Revenue Engine verifies it with the already separate operator boundary.

No plaintext credentials, team names, actual Access application IDs or new Cloudflare plans are committed. The current quota alert destination, trigger, payload, email queue, KV binding, 25-hour acknowledgment marker, hourly failure backoff and post-rejection retry are unchanged.

## Required review and activation sequence (not performed)

1. **Cost:** owner confirms the existing Cloudflare account's Zero Trust/Access features, service token, application, policy and request volume fit current prepaid/free usage limits; no new metered service, paid seat or quota expansion without separate approval.
2. **Access policy:** authorized operator provisions/inspects an existing or explicitly approved Access application scoped to the *admin machine path only*, **not the entire public Revenue Engine domain**, because customer checkout and Razorpay webhooks must stay reachable. Configure a Service Auth policy for the least-privilege gateway token.
3. **Secrets:** via approved secret management, set the two encrypted secrets only in the Intel Gateway production environment after completing isolated preflight. Never place token pairs in GitHub workflows, logs, KV records, HTML or public docs.
4. **Origin authentication:** configure an independent approved `REVENUE_OPERATOR_ACCESS_SERVICE_IDS` containing the real service token common_name/Client ID, issuer, expected application audience and Access public key rotation strategy. Verify signature, audience, expiry, subject and service allowlist in an isolated test.
5. **Positive/negative acceptance:** real 200 `status=triggered` must queue a single synthetic authorized warning; wrong/partial service pair, wrong audience, expired or unsigned assertion, X-Admin-Secret-only and invalid token must fail with **zero** email queue writes and **zero** full-day alert markers. Check existing customer API calls continue successfully; confirm Cloudflare edge route and Worker logs show no credentials or emails.
6. **Commercial safety:** verify Razorpay webhook, checkout, entitlement, quotes, refund/admin controls and human operator browser flows. Migrate the remaining **10+** inventoried callers before changing the global `REVENUE_OPERATOR_ACCESS_MODE` value to `required`. Keep PR #965's source-level NO-GO pending separately attested runtime evidence.

## Tests and limitations

`node --test workers/intel-gateway/src/__tests__/revenue-quota-access-client.test.js workers/intel-gateway/src/__tests__/quota-alert-delivery.test.js` validates default legacy headers, complete token pair, invalid/partial pair denial, header injection rejection and integration ordering. The existing Intel Gateway Regression Gate executes these before the comprehensive gateway/commercial/security suites.

These tests do **not** prove an Access application exists, a token can authenticate at Cloudflare, a Worker is deployed, an email is delivered, or that any payment/customer state changed. **Production release and researcher closure remain HOLD.** No live token or privileged action was used.
