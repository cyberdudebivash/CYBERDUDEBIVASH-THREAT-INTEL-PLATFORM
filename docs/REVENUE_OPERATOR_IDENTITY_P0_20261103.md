# P0 Revenue Engine verified operator-identity boundary — DISABLED BY DEFAULT

**Incident:** Vishal Vijay Pawar report (2026-11-02): publicly reachable admin API with static `X-Admin-Secret`. This branch adds a **second, cryptographically verified operator identity**. It does not claim unauthenticated CRUD or an auth bypass was proven, and it must not be treated as researcher-case closure until production retesting.

## Source behavior and scope

- The default `REVENUE_OPERATOR_ACCESS_MODE` unset or `off` preserves existing customer, billing, webhook, canary, automation and administrator behavior. No automatic configuration changes.
- When `REVENUE_OPERATOR_ACCESS_MODE=required`, **every request presenting `X-Admin-Secret`** must also provide a valid `Cf-Access-Jwt-Assertion` signed with the separately provisioned pinned Cloudflare Access public JWKS; the guard runs **before** pre-gated billing/refund/admin handlers as well as the central CRM gate.
- Verification checks RS256 signature, matching JWKS `kid`, a pinned Cloudflare Access issuer, the exact application audience, nonempty `sub`, a configured exact operator email allowlist, issued/expiry/not-before claims and maximum 24-hour token duration. Invalid/malformed/missing configuration or token fails closed to 403, no CRM / billing handler dispatch. The legacy admin-secret check remains mandatory.
- Customer-facing calls and signed webhooks without `X-Admin-Secret` do **not** acquire new Cloudflare Access dependencies. The endpoint does not log bearer JWTs/secrets.
- Offline JWT verification only: no extra network calls, KV/D1 operations, paid provider invocations or new metered services. No Cloudflare Access product/seat was provisioned by this PR.

## Configuration prerequisites (do not commit values)

For an already-authorized Cloudflare Access application protecting the operator admin path, provision privately as approved Worker secrets/environment configuration:

| Variable | Requirement |
| --- | --- |
| `REVENUE_OPERATOR_ACCESS_MODE` | `required` **only at an approved cutover**, otherwise unset/off |
| `REVENUE_OPERATOR_ACCESS_ISSUER` | Exact `https://<team>.cloudflareaccess.com`; no user-supplied or wildcard issuer |
| `REVENUE_OPERATOR_ACCESS_AUDIENCE` | Exact Access application JWT audience identifier |
| `REVENUE_OPERATOR_ACCESS_EMAILS` | Explicit, case-insensitive comma-separated operator emails (max 20) |
| `REVENUE_OPERATOR_ACCESS_JWKS` | Pinned public JSON Web Key Set from the team's trusted Access certificates endpoint, stored via approved encrypted configuration; **never paste customer/admin secrets or live JWTs** into repository or issue |

Cloudflare Access JWT signing keys rotate. Because the verifier intentionally makes no outbound JWKS requests, the JWKS must be monitored and updated under change control **before** rotation. Unexpected rotation denies privileged calls; it must not trigger silent fallback to the static secret. Access policies (including MFA, device controls and member deprovisioning) remain an independent Cloudflare control and must be verified; JWT verification alone does not assert live session revocation.

## Required pre-activation controls

1. Confirm Cloudflare Access is available **without increasing the current approved Cloudflare bill**, review allowed operators and ownership, enforce MFA and shortest workable Access session.
2. Inventory **every** operator, billing admin, revenue dashboard, watchdog, automation, SLA heartbeat and CI caller that sends `X-Admin-Secret`. Those callers must acquire an approved machine identity/JWT or be migrated first. A global second factor can otherwise break business-critical background operations.
3. Run exact-head offline tests: `node --test workers/revenue-engine/src/__tests__/revenue-operator-identity.test.js`, all existing commercial/billing tests, source syntax, production entrypoint bundling, Wrangler dry-run, CORS and token replay/expiry cases. No live paid customer writes.
4. In a strictly isolated, nonproduction environment configured with `required`, verify valid operator JWT+admin secret succeeds and these all fail: no JWT, wrong signature, wrong issuer, wrong audience, expired/revoked identity, wrong operator, secret-only, JWT-only and altered claims. Check every refund, invoice, quote, CRM and automation admin route, including pre-gated billing handlers.
5. Prepare test credentials only in a vault and obtain independent security signoff, rollback version, customer support readiness, and exact Worker/Pages version parity. Record all denied/authenticated acceptance evidence privately. **Operator-approved production deployment is a distinct action.**
6. On approved activation, monitor successful and denied *counts* without identifiers/tokens, apply upstream Cloudflare Access rate rules if already provisioned at no incremental charge, and verify Razorpay webhook, customer portal, purchase, refund, invoice, license and legitimate automation success. Roll back configuration to the prior reviewed state if authorized business flows fail.

## Limitations / explicit HOLD

- No Access account, policy, certificate, session or billing entitlement can be inferred from repository contents. No new service is provisioned here; configuration remains disabled.
- This is **not full network-level isolation**. A direct origin request is still reachable, but without a valid Access-signed operator token and static secret it cannot reach the protected secret-bearing admin dispatch when the flag is active. Separately protect the public hostname with an approved Cloudflare Access policy, while preserving public webhook and customer endpoints through route/path scoping or distinct hostnames.
- A stale allowlisted JWT may remain cryptographically valid until expiry; to revoke immediately, rotate the pinned issuer keys where appropriate or add a separately approved revocation control. Deprovision operator access at the identity provider; do not promise immediate JWT revocation without evidence.
- Earlier customer portal HMAC separation (merged PR #955) is a different trust boundary and is also opt-in. Do not rotate `REVENUE_ADMIN_SECRET` blindly; older customer quote and portal links may depend on it.
- Researcher disposition: **OPEN / mitigations in source, inactive by default**. Preserve the original report, independently certify live auth behavior and business continuity, then coordinate the outcome with the researcher from `contact@cyberdudebivash.in`.
