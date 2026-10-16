# Enterprise Pilot Release Control — 2026-10-16

Owner: CYBERDUDEBIVASH ECOSYSTEM®
Release scope: SENTINEL APEX AI Security Hub and Threat Intelligence Platform
Release state: **NO-GO until evidence-backed approval**. This document does not authorize production deployment or customer activation.

## Release identification
- Freeze the exact `main` commit SHA, deployed Cloudflare Worker version, Pages deployment ID, database migration version, and UTC/IST timestamps in the release record.
- Do not infer production deployment from a merged PR or successful build.
- Preserve rollback commit, prior deployment identifier, migration reversibility assessment and immutable evidence links.

## Mandatory gates (record PASS/FAIL with evidence and operator)
1. **Identity:** email verification, invite acceptance, login/logout, recovery, session expiry, MFA/SSO when sold, fail-closed unknown domains.
2. **Tenant isolation:** organization provisioning, least-privilege RBAC, deny cross-tenant read/write/export, admin impersonation and role escalation.
3. **Payments:** Razorpay live checkout, server-side signature validation, idempotent replay handling, failure/timeout behavior, refund/chargeback routing, subscription entitlement reconciliation. Never log secrets or payment card data.
4. **Product:** real data sources, permitted IOC exports, quotas, reports, APIs and support paths; no mock/demo outputs represented as live.
5. **Security:** secrets, dependency and SAST review; negative controls for auth, webhooks and object-level authorization; privacy retention and audit trail.
6. **Operations:** health/error metrics, on-call contact contact@cyberdudebivash.in, escalation, restore/rollback drill, Cloudflare quota headroom across shared platforms.
7. **Commercial:** written pilot authorization, legal entity and contracting authority, DPA/security terms where applicable, designated customer admin, agreed service scope and pricing.

## Controlled rollout
- Deploy only a tested SHA. Verify Worker/Pages parity and smoke-test the live environment.
- Pilot by individually approved organization, not by matching email domain alone.
- Invite one verified administrator per approved organization; provision least privilege and verify first successful workflow.
- Observe error rates, entitlement mismatches, authentication failures and Cloudflare usage before expanding.
- Any critical gate failure: pause invitations and paid fulfillment for the affected service, preserve logs, revert to last known-good deploy if safe.

## Sign-off register
| Field | Required evidence |
| --- | --- |
| Git commit / deployment ID | PENDING |
| Test results / negative controls | PENDING |
| Security approval | PENDING |
| Billing and entitlement approval | PENDING |
| Cloudflare quota review | PENDING |
| Customer authorization / agreement | PENDING |
| Rollback verification | PENDING |
| Final release decision | NO-GO pending evidence |

## Communications and business formalities
- Use CYBERDUDEBIVASH ECOSYSTEM® as the public-facing brand; do not represent it as an incorporated company without supporting registration.
- Do not imply HCL, Wipro, Jio, Accenture, JDA, Star Sports, BMC, OCAC or BigBasket are customers, partners or endorse the platform without written authorization.
- Use contact@cyberdudebivash.in for customer support, subject to mailbox deliverability verification.
- Customer invitation must specify pilot scope, support channel, privacy terms, administrator contact, billing status and incident-reporting route.
- Keep an internal customer ledger with authorization status, tenant ID, provisioned admin, plan, contract, onboarding timestamp, first-value workflow and support owner; never commit personal data or credentials to Git.

## GitHub Actions exception
A job with runner_id=0 and zero executed steps is **not** evidence that the application tests passed or failed. Run the same controls independently and attach evidence; do not waive mandatory gates merely because hosted runners are unavailable.
