# P0 — Customer release evidence and sign-off register (Threat Intelligence Platform)

> **Release decision at creation: NO-GO for unrestricted paid customer activation.** A deployed Worker and healthy anonymous feed do **not** prove paid subscription fulfillment, full-fabric swarm operations, tenant isolation, rollback or cost headroom. No customer approval, contract, payment, deployment or account migration is created by this file.
>
> Review date: 2026-10-17 UTC; update each row with verifier identity, timestamp, exact deployed SHA, redacted immutable evidence and operator decision.

## Current deployment observations

| Scope | Observed | Required to close |
| --- | --- | --- |
| Public hostname | `https://intel.cyberdudebivash.com` | Independent customer-network reachability and login test |
| Live gateway | `/api/health/live` responded `alive` at 2026-10-17 07:18 UTC | Recheck during release window |
| Live Worker code SHA | `da0b547752bba2a00f3a72235bb690fc8137938d` | Compare to exact runtime-affecting main; main `c7b07afc` adds release-control docs only |
| Public intel health | `/api/health` `status:ok`, 154 advisories, six-hour freshness policy; 2026-10-17 04:43:48Z feed | Observe fresh publisher cycles and materialized report delivery |
| Live pricing | `/api/pricing` Razorpay primary; `checkout.gumroad.available=false` | Verify configured plans, provider-confirmed payment and owned access |
| Paid subscription → key → report/IOC/export | **NOT VERIFIED END-TO-END** | Exact release authenticated PRO/ENTERPRISE/MSSP certification |
| Eight-agent FULL_FABRIC_COMPLETE mission | **NOT VERIFIED** | All eight actual agents completed, durable paid report, bounded cost and revocation |
| Customer release owner decision | **NOT APPROVED** | Record signed scope-specific decision after remaining gates |

## Commercial, legal and business gates

| ID | Gate | Required proof | Status |
| --- | --- | --- | --- |
| INT-BIZ-01 | Exact proprietor/GST legal seller, bank beneficiary and trade name | Original registration/bank/provider records privately verified; no claim of private limited incorporation | PENDING |
| INT-BIZ-02 | Current offer/SKU/price/renewal terms | Compare every public checkout tier to canonical `config/commercial-contract.json`, `docs/COMMERCIAL_POLICY_V1.md` and server-authoritative Razorpay amount | PENDING |
| INT-BIZ-03 | Accurate vendor procurement pack | Historical false PayPal/UPI, no-auto-renewal, annual refund and incorporation claims withdrawn; buyer-specific review approved | PENDING |
| INT-BIZ-04 | Privacy/DPA disclosure | Current real subprocessors, processing categories, residency limitations, executed transfer schedule if applicable; draft not signed by code | PENDING |
| INT-BIZ-05 | Provider payment, invoice and refunds | Test-only independent Razorpay capture, signed event, exact plan, amount and currency, idempotence, GST invoice or controlled hold, revocation and duplicate recovery | PENDING |
| INT-BIZ-06 | Signed customer agreement/authorization | Legal customer and admin verified; scope, licensing/TLP, limits, term, prices, refunds and incident/support contract accepted | PENDING |
| INT-BIZ-07 | Support and SLA promise evidence | Two-way contact@cyberdudebivash.in mailbox, verified service targets, incident escalation and accountable coverage | PENDING |
| INT-BIZ-08 | Account-level $0 overage requirement | Actual current billing cycle, all ten platforms' usage/headroom, bounded forecast, 20% reserve, rollback (issue #810) | PENDING |

## Product and security acceptance (no status inferred from source code)

| Gate | Evidence needed | Status |
| --- | --- | --- |
| Authenticated FREE/PRO/ENTERPRISE/MSSP and RBAC/tenant isolation | Isolated authorized test identities, exact HEAD, exported 401/403/429 negative controls, no cross-customer read/write or TLP leak | PENDING |
| Strong access lifecycle and key/JWT revocation | Current-head, cross-PoP suspension, reactivation, rotation and free-tier limiter evidence (issue #596) | PENDING |
| Paid report publication, CDN/R2 manifest, fresh feed | Two successful publisher cycles; eligible report accessible, wrong TLP denied, report status reconciled (issue #819) | PENDING |
| Paid IOC exports and analyst workflows | Scoped paid-key exports with genuine IOC values and no anonymous leak; eight-agent complete mission (issue #852) | PENDING |
| Automated payment entitlement and recovery | Signed Razorpay sandbox/test-mode actual provider event, exactly one key and one welcome/redeem flow, refund and replay; old Gumroad links controlled | PENDING |
| Secure CI, dependencies and branch enforcement | Exact-head SAST/gateway/regression; verified required checks/ruleset; no bypass of red gates (issue #817) | PENDING |
| Health, monitoring and rollback | Deployment SHA, safe fallback, health metrics, recovery drill and customer incident response | PENDING |
| Operational cost safety | Account-wide Cloudflare zero-overage attestation; no unbudgeted cron, queue, R2 or billing writers | PENDING |

## Individually authorized customer onboarding — keep private

Never commit customer names, credentials, contracts, payment IDs, signed acceptance or TLP-restricted indicators to GitHub. In a restricted operator/customer file record:

- Customer record identifier; legal organization and contact; verified authoritative representative;
- Signed plan/order form; term, INR amount, tax and billing/invoice contacts; renewal and cancellation terms;
- Approved tenant, verified administrator, least-privilege scopes and API-key delivery method (never email raw key);
- Exact TLP/data-license restrictions and permitted intel exports, support response window;
- Provider-authoritative payment state OR clearly designated no-charge evaluation;
- First paid API/feed/export/report workflow evidence, denial controls, delivery acknowledgment;
- Customer acceptance, support owner, escalation and explicit scope-specific owner sign-off.

**NO WRITTEN AUTHORIZATION → no privileged tenant/customer access or external scanning.** If a charge is captured but an entitlement is absent, preserve the original Razorpay payment, prohibit repeat payment, reconcile provider and D1/gateway records and escalate.

## Release gate ownership and decision

| Formal signer / reviewer | Sign-off state | UTC timestamp / artifact |
| --- | --- | --- |
| Proprietor: business legal entity, terms and signed customer scope | PENDING | PENDING |
| Finance/accounting: GST invoice, captured status, refund controls | PENDING | PENDING |
| Security: tenant/TLP/strong key revocation and full regression | PENDING | PENDING |
| Engineering: publisher/paid exports/8-agent mission, deployment integrity | PENDING | PENDING |
| Operations: 10-platform billing headroom, support, restoration/rollback | PENDING | PENDING |
| Named customer administrator: verified first-value pilot workflow | PENDING | PENDING |
| **Final proprietor commercial release approval** | **NOT APPROVED — NO-GO** | PENDING |

This is a preparatory register only; do not mark PASS because documentation is merged or anonymous HTTP is 200. Customer-specific controlled pilot is possible only after all controls required for that exact offer have documented PASS and an authorized human decision. Do not modify Cloudflare infrastructure or charge a customer as part of the approval process.

References: `docs/releases/2026-10-16-enterprise-pilot-release-control.md`, `docs/CUSTOMER_RELEASE_LEDGER.md`, `docs/COMMERCIAL_POLICY_V1.md`, `docs/PAYMENT_RELEASE_OPERATOR_RUNBOOK.md`, issues #596, #810, #817, #819.
