# P0 — Customer release evidence and sign-off register (Threat Intelligence Platform)

> **Release decision at creation: NO-GO for unrestricted paid customer activation.** A deployed Worker and healthy anonymous feed do **not** prove paid subscription fulfillment, full-fabric swarm operations, tenant isolation, rollback or cost headroom. No customer approval, contract, payment, deployment or account migration is created by this file.
>
> Review date: 2026-10-18 UTC (technical acceptance update). External workflow evidence is linked and scoped; no human commercial sign-off, tax review, customer payment or billing approval was inferred.

## Current deployment observations

| Scope | Observed | Required to close |
| --- | --- | --- |
| Public hostname | `https://intel.cyberdudebivash.com` | Independent customer-network reachability and login test |
| Live gateway | `/api/health/live` responded `alive` at 2026-10-17 07:18 UTC | Recheck during release window |
| Live Worker code SHA | `da0b547752bba2a00f3a72235bb690fc8137938d` | 2026-10-18 V4.47 authenticated certification independently validated gateway runtime-byte parity to the merged release-control commit `536e661ba0c732372e6515d21b10f159452b5ec1`; current main after R2 hardening is `e33417a84d1dca6e53caf80356f27c650db47ab3`, which has not itself been deployed to the gateway |
| Public intel health | 2026-10-18 publisher run `39093734695` **success**, including R2 report publication, report index integrity, feed release gates and freshness; public `/api/health` `status:ok` and feed age **46 seconds** at 05:13 UTC (136 current advisories) | This proves one newly successful cycle, not two independently evidenced cycles or all paid-customer delivery combinations |
| Live pricing | `/api/pricing` Razorpay primary; `checkout.gumroad.available=false` | Verify configured plans, provider-confirmed payment and owned access |
| Paid subscription → key → report/IOC/export | **ENTERPRISE ephemeral-key mission PASSED** at 2026-10-18 05:10 UTC: entitlement preflight, owned durable mission, Markdown/JSON/STIX 2.1 exports and revocation. **Razorpay purchase/capture → paid key → customer fulfillment remains NOT VERIFIED.** | Validate actual provider-authoritative paid purchase and individual customer fulfillment separately; do not extrapolate ENTERPRISE synthetic demo to PRO/MSSP |
| Eight-agent FULL_FABRIC_COMPLETE mission | **PASS (scope: one ephemeral ENTERPRISE production certification)** — 8/8 agents `COMPLETED`, mission `FULL_FABRIC_COMPLETE`, post-certification 9/9, KV key revoked. [Run 39099582582](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/39099582582) | Maintain regression gate, confirm no overage and separately certify true customer purchase/onboarding |
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
| Paid report publication, CDN/R2 manifest, fresh feed | Production publisher run 39093734695 passed R2 publish, report-index integrity, release gates and freshness; independent second full cycle and paid TLP/report delivery matrix not yet confirmed (issue #819) | **PARTIAL PASS — publisher cycle passed; remaining customer gates PENDING** |
| Paid IOC exports and analyst workflows | The scoped Enterprise demo candidate, eight-agent mission, durable read-back and Markdown/JSON/STIX 2.1 exports passed on 2026-10-18; explicit IOC CSV and all-customer negative controls still need separate evidence (issue #852) | **PARTIAL PASS — 8/8 mission; paid customer SKU/export matrix PENDING** |
| Automated payment entitlement and recovery | Signed Razorpay sandbox/test-mode actual provider event, exactly one key and one welcome/redeem flow, refund and replay; old Gumroad links controlled | PENDING |
| Secure CI, dependencies and branch enforcement | Exact-head SAST/gateway/regression; verified required checks/ruleset; no bypass of red gates (issue #817) | PENDING |
| Health, monitoring and rollback | Deployment SHA, safe fallback, health metrics, recovery drill and customer incident response | PENDING |
| Operational cost safety | Account-wide Cloudflare zero-overage attestation; no unbudgeted cron, queue, R2 or billing writers | PENDING |


## Verified October 18 technical evidence — scoped, not a commercial release

- **Production publication:** Workflow [39093734695](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/39093734695) completed successfully, including STAGE 3.5a R2 report publisher, STAGE 3.5.1 report-index integrity, final pipeline health and public freshness gate. No manual duplicate publisher was dispatched.
- **Production authenticated Enterprise mission:** Workflow [39099582582](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/39099582582) completed successfully after the corrected gateway-parity guard compared the runtime code. Eight named agents all reached COMPLETED; final quality `FULL_FABRIC_COMPLETE`; persisted mission, Markdown, JSON and STIX 2.1 outputs verified; post-mission checks 9/9 and temporary credential revocation (canonical denial, KV deletion, local cleanup) PASS.
- **New source/CI:** INT main `e33417a84d1dca6e53caf80356f27c650db47ab3` incorporates draft-previously release control and bounded R2 publisher changes. R2 FinOps newly wired negative tests passed; main gateway deployed runtime SHA remains `da0b547752bba2a00f3a72235bb690fc8137938d`. Do not misrepresent new source as live Worker code.
- **Still NO-GO commercially:** no owner/company legal approval, accountant-reviewed tax seller, signed customer order, Razorpay test-mode captured payment-to-entitlement evidence, current ten-platform Cloudflare billing headroom, support coverage or named customer sign-off. The authenticated E2E demo did not charge a customer and cannot replace those gates.

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
