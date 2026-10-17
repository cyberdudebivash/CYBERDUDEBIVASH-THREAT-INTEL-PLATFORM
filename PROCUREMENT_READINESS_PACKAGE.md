# SENTINEL APEX Threat Intelligence — Enterprise Procurement Review Pack

> **REVIEW COPY — NOT A CUSTOMER CONTRACT, COMPLIANCE CERTIFICATION OR RELEASE APPROVAL.**
> Updated 2026-10-17 to remove historic non-evidenced claims. Procurement may begin, but **paid customer activation remains HOLD** until the specific signed order, technical gates, live payment entitlement and release sign-off are complete.
>
> Supersedes the previous 2026-06-04 package's statements regarding incorporation certificates, PayPal/UPI self-checkout, non-recurring subscriptions, pro-rata annual refunds, guaranteed 24-hour invoices, SOC 2 promises and unapproved account-specific delivery SLAs.

## Supplier identification and authority

| Field | Current procurement position |
| --- | --- |
| Customer-facing trade brand | **CYBERDUDEBIVASH ECOSYSTEM®** |
| Legal form | **Sole proprietorship**, not a private limited company |
| Contracting supplier | [VERIFY exact statutory proprietor name, registered address and GST seller against original records before signature] |
| GST registration | [VERIFY actual GSTIN and statutory seller record before invoicing] |
| Product | SENTINEL APEX Threat Intelligence Platform (https://intel.cyberdudebivash.com) |
| Commercial / support requests | contact@cyberdudebivash.in (confirm two-way deliverability) |
| Bank beneficiary and account | Not advertised: disclose only after bank/Razorpay beneficiary verification and individual written quote |
| Signed enterprise assurance pack | PENDING customer-specific owner/legal approval |

The brand, trademarks and product are not separate incorporated companies. Do not offer a certificate of incorporation for a sole proprietorship. Do not represent historical partners, former employers or third parties as customers or endorsers without written evidence.

## Plans and price authority

The sole controlling contract for product tiers, limits, support, cancellation and invoice treatment is `config/commercial-contract.json`, checked against the live `GET /api/pricing` response. The following rows are review references, **not independent prices**.

| Tier | INR recurring monthly | INR recurring annual | Other commercial terms |
| --- | ---: | ---: | --- |
| FREE | ₹0 | ₹0 | Best-effort public evaluation; no paid entitlement |
| PRO | ₹4,100 | ₹41,000 | 120 requests/min; email response target in current canonical contract |
| ENTERPRISE | ₹41,600 | ₹416,000 | 600 requests/min; support target subject to verified coverage |
| MSSP | ₹83,300 | ₹833,000 | 1,200 requests/min; dedicated coverage requires operator approval |

USD reference prices and quotas must be taken from the same canonical contract and current checkout. Do not independently promise a fixed foreign-exchange settlement rate, tax exception or unlimited seats. Public checkout indicates applicable INR prices include GST; the legal invoice and actual tax breakdown must be verified with a qualified accountant before paid GO.

## Payment and access: actual current policy

1. **Razorpay is the primary automated provider** for recurring PRO, ENTERPRISE and MSSP subscriptions. Verify that the configured plan ID, invoice total, payment status and server-authoritative plan match before providing access. The buyer may cancel the recurring subscription; paid-period access and limitations follow the published `docs/COMMERCIAL_POLICY_V1.md`.
2. **Gumroad must not be offered as an available automated activation path** while `/api/pricing` reports `checkout.gumroad.available=false`. An old direct Gumroad sales link must be reviewed/restricted separately; no success claim based on a paid-but-unprovisioned sale.
3. **No unsupervised UPI, PayPal, crypto, bank transfer or manual-proof upload path.** Individually contracted assisted payments, if approved, require correct vendor identity, quote/PO and explicit reconciliation before access. No instant activation is implied.
4. **Refunds:** The current owner commercial policy provides a conditional **7-day first-purchase money-back request subject to review**, then generally no pro-rata refunds; exact governing policy, jurisdictional rights and actual process must be agreed in the order. The historic blanket "30-day prorated annual refund" claim is withdrawn.
5. **GST and invoices:** Generate paid invoices only from accountant-approved supplier/tax configuration and provider-confirmed captured amounts. If missing, hold invoice issuance for operator correction; do not promise automatic same-day or 24-hour GST invoices without proof.

## Customer-specific procurement packet — required before activation

| Artifact | State / authorised evidence |
| --- | --- |
| Verified legal seller and buyer; applicable tax identifiers | **PENDING** — original records / private customer file |
| Exact signed order form, scope, SKU, limits, price and GST terms | **PENDING** |
| Customer administrator and approved organisation/tenant ID | **PENDING** |
| Verified first-use workflow, paid IOC exports and API-key lifecycle | **PENDING** — fresh exact-deployed version certification |
| Independent Razorpay test payment-to-entitlement/one-time-key flow | **PENDING** — controlled test or separately authorised live case |
| Refund, key revocation and customer support recovery | **PENDING** |
| Privacy and DPA, if required, with correct processor/controller roles | **PENDING** — `docs/DPA_TEMPLATE.md` is **not approved for execution** |
| Subprocessor and data location disclosure | **PENDING** — verified current topology; no region-exclusive guarantee |
| Security questionnaire / true present controls | **PENDING** — fact-checked evidence only; no implied SOC 2/ISO audit |
| Incident response, support mailbox, operational cover and rollback | **PENDING** |
| Cloudflare ten-platform consumption/headroom and zero-overage approval | **PENDING** |
| Proprietor's written customer- and SKU-specific release approval | **NOT GIVEN** |

Enterprise requirements including SSO/SAML, dedicated tenancy, regional data residency, third-party penetration test reports, formal SOC 2/ISO certificates or cyber insurance must be treated **as uncommitted until proven and expressly included in a customer-specific written agreement**. Do not advertise a roadmap target as an available control.

## Service, incident and refund handling

- The canonical commercial contract defines the advertised per-tier support and availability targets; an enterprise-specific SLA should be contracted **only after** verifying real operator staffing, reporting, credits, monitoring, breach response and rollback capacity.
- Customer support contact: **contact@cyberdudebivash.in** (two-way delivery test and responsible operator required).
- Where a payment may have been captured but access not provisioned, first reconcile the original provider order and gateway ledger. **Do not request duplicate payment** or auto-provision access on unverified webhook/request assertions.
- Access or IOC/report distribution must respect TLP, licensing, role, scope, and revocation controls. No fabricated indicators or unauthorised restricted intelligence.
- Controlled evaluation is not a guarantee of unrestricted enterprise-grade commercial readiness.

## Authorization and source-of-truth

- `config/commercial-contract.json` — pricing, quotas and tier commitments.
- `docs/COMMERCIAL_POLICY_V1.md` — current subscription, refund, GST and alternative-payment policy.
- `docs/CUSTOMER_RELEASE_LEDGER.md` — historical technical/blocker evidence; revalidate current status.
- `docs/releases/2026-10-16-enterprise-pilot-release-control.md` — mandatory fail-closed release process.
- `docs/releases/2026-10-17-customer-release-signoff-register.md` — current proposed sign-off/evidence register.
- `docs/DPA_TEMPLATE.md` — unexecuted review draft only.

**Final status: PENDING PROCUREMENT AND OWNER APPROVAL; NO-GO for unrestricted commercial release.**

*Review work neither changes the live product nor signs an agreement on behalf of CYBERDUDEBIVASH or any customer.*
