# P0 cross-Worker operator Access identity contract — offline integration

Date: 2026-11-03. This is **test-only**, not production activation.

## Risk and objective

PRs #965–#968 introduced an operator-JWT cutover inventory, truthful 80%-quota email acknowledgement, and opt-in gateway machine-client credentials. Component tests independently showed these controls behave as designed. However, neither the gateway tests nor the Revenue Engine operator-JWT tests previously executed the full service-token-header → signed application-JWT → real Revenue Engine request → email KV queue → daily quota-marker contract in a single test. Such integration gaps can cause a deployment that appears healthy while customer usage warnings and upsell opportunities never queue.

## Implemented verification

`workers/intel-gateway/src/__tests__/revenue-access-quota-crossworker.test.js` uses the **actual source** for (1) gateway service-token headers, (2) source quota-alert reservation/acknowledgement, and (3) Revenue Engine's public Worker fetch path, including RS256 JWT enforcement and email queue persistence. A strictly local *synthetic Access proxy* checks the two invented service-token credentials and creates an ephemeral RSA key pair to sign short-lived `Cf-Access-Jwt-Assertion` claims. The harness supplies in-memory KV. All credentials, email addresses, audiences, issuers, and service identities are fabricated test fixtures.

The tests prove, **subject to the synthetic boundary**:
- Valid machine headers + signed and allowlisted service identity + valid admin secret result in one queued synthetic quota warning and the existing 25-hour daily marker.
- Partial/mismatched credentials are refused, without a false full-day success marker or email queue write.
- The **actual Revenue Engine handler** rejects wrong JWT audience, issuer, service identity, and expiry.
- Legacy secret-only requests work with source operator mode explicitly off, but are rejected by the required-mode boundary.
- Wrong admin secret fails even with a valid Access JWT.
- Unbound email KV returns no success acknowledgment, and the gateway retains only its temporary retry marker.

The fast `Intel Gateway Regression Gate` step now runs this integration fixture before the comprehensive gateway unit, commercial mutation, publisher, and security suites. The suite makes no external fetch, sends no email, changes no Cloudflare bindings, and has no payment or metered cloud operation.

## Security, billing, and release HOLD

This test uses a **mock Access policy**, so it does not validate actual Cloudflare Access account configuration, external request forwarding, service-token issuance, real `common_name` claim shape, CORS, real Worker routes, secret rotation, account plan limits, or deployment identity. A green CI run is **not** live authorization. Do not enable `REVENUE_OPERATOR_ACCESS_MODE=required` until each legacy caller in PR #965's inventory is safely migrated with a *real* authorized issuer, audience, signing key, allowlist, Cloudflare Access policy, customer payment/webhook exclusions, bounded cost, and positive/negative live acceptance.

No repository merge alone constitutes production rollout. No real customer email, payment, sale, or revenue is claimed. Researcher reports remain open pending separately verified live negative retests.
