# P0 Revenue Engine operator JWT — paying-customer cutover blockers (3 November 2026)

**Source-verified state:** the optional operator factor was added in PR #958, but `REVENUE_OPERATOR_ACCESS_MODE=required` is **not ready for activation**. This document and its offline preflight do **not** infer the actual Cloudflare secret, dashboard state, user session, or deployed Worker SHA. Default/unset mode remains backwards compatible in source. No credentials or live traffic are examined here.

## Why premature activation would cost revenue

When `required`, the Revenue Engine rejects **every request carrying `X-Admin-Secret`** unless it additionally contains an allowed and valid `Cf-Access-Jwt-Assertion`. This includes billing endpoints that dispatch before the central CRM gate. The following caller surfaces were inspected in the repository; each currently contains the legacy header and an expected route, but JWT/MFA/service-token readiness has **not** been independently attested:

| Client/source | Revenue impact on rejection | Required migration and acceptance |
| --- | --- | --- |
| `workers/intel-gateway/src/index.js`: quota alert | Customer 80% usage notice and upgrade opportunity may be lost; current caller ignores upstream failure | Approved machine identity; verify authorized alert is queued once, denied calls queue nothing, failed remote calls are visible |
| `deploy/billing-canary/canary-lib.mjs` | Authorized billing health and commercial-readiness canary blocked | Inject an approved ephemeral JWT under least privilege and prove canary's negative controls remain active |
| `.github/workflows/deploy-revenue-engine.yml` | Post-deploy commercial readiness currently nonblocking and cannot be reported | Approved ephemeral CI machine identity; correct 200/READY and 401/403 denied tests; do not change release to silently succeed |
| `admin.html` | Operator billing queue unreadable | Access-protected operator session and runtime JWT delivery verified with the actual host/CORS/cookie policy |
| `lead-pipeline.html` | Leads, follow-ups and sales pipeline unavailable | As above; test authorized and unauthorized CRM access |
| `revenue-dashboard.html` | Commercial dashboard unreadable | As above |
| `subscription-management.html` | Subscription management unavailable | As above |
| `enterprise-onboarding.html` | Enterprise sales/onboarding console unavailable | As above |
| `payment-status-dashboard.html` | Payment status and reconciliation console unavailable | As above |
| `customer-success.html` | Customer-success scores unavailable | As above |
| `mssp-tenant-dashboard.html` | MSSP tenancy control unavailable | As above |

This is an **initial confirmed source inventory**, not a complete runtime/service-account census. Additional legacy clients outside the repository, in private integrations, archived workflows, or live browser sessions may exist.

## New read-only command

From repository root (Node.js 22):

```bash
node workers/revenue-engine/scripts/operator-cutover-preflight.mjs off
node workers/revenue-engine/scripts/operator-cutover-preflight.mjs required
```

The first command passes **only the source inventory check for an explicitly selected off-mode target**, while reporting all unverified clients. It does not assert the production Worker is off. The second **must fail** and enumerate blockers. Invalid/missing mode or source drift fails closed.

The implementation is pure file inspection; it makes **zero** external network requests, payments, D1/KV reads or writes, Cloudflare API operations, cost-metered calls, email sends or secret reads. The mandatory Revenue Manual Payment Authority Gate runs deterministic positive/negative unit tests and the off-mode read-only inventory. Never interpret CI success as a green light to activate operator Access.

## Cutover exit criteria — all required

1. The owner confirms Cloudflare Access pricing and operator/session entitlements already fit the **current approved** account limit. No new paid seats, services or metering without separate approval.
2. Inventory *all* revenue, admin, billing, quota-alert, monitoring, browser and CI callers, including off-repository integrations. For each: identify the service identity, least-privilege policy, token acquisition/rotation, and recovery owner. Do not store keys/JWTs in GitHub source or issue comments.
3. Migrate clients to signed, audience-bound Access identity in an isolated environment without impacting public customer checkout, Razorpay signed webhooks, activation, API entitlement checks, portal links or quotes.
4. Offline tests and sandbox tests prove: authorized human and service clients succeed; missing JWT, JWT-only, wrong secret, wrong audience, expired token, wrong identity and header spoofing deny **before any billing write**. Verify quota-alert failure handling does not discard paid-customer lifecycle communications.
5. Record exact staged deploy, health/source SHA, operator JWT and browser acceptance, and controlled rollback to off mode. Inspect Cloudflare live configuration using an authorized operator; the offline preflight **cannot do this**.
6. Only after independent review should the inventory be amended with tested migration evidence. Do not mark a caller compatible simply because its source mentions `Cf-Access-Jwt-Assertion`.

**Production disposition: NO-GO for `REVENUE_OPERATOR_ACCESS_MODE=required`.** Separate security-researcher reports remain open until a separately authorized live positive/negative assessment and researcher response. Do not rotate the shared legacy admin key without an approved legacy portal/quote migration, as existing customer links may depend on it.
