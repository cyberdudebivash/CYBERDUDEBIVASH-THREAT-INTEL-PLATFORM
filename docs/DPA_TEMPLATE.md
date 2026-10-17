# SENTINEL APEX Threat Intelligence Platform — Data Processing Agreement (DPA) Template

> **DRAFT — NOT APPROVED OR EXECUTED.** This source is not proof of SOC 2 certification, guaranteed regional data residency, an executed international transfer instrument, or an enterprise customer's acceptance. Complete the fields below and obtain business/legal review before providing an execution copy.
>
> Template review date: 2026-10-17. Supersedes the former historical v177 DPA source which asserted unevidenced AWS-region pinning, Stripe/Railway subprocessors, ClickHouse/Redis storage, fixed retention and SOC 2 certification.

## Parties and incorporation

**Customer / controller:** [EXACT LEGAL CUSTOMER NAME], [REGISTERED ADDRESS], acting through [AUTHORISED SIGNATORY].

**Supplier / processor, only for processing genuinely undertaken on behalf of a customer:** [EXACT STATUTORY NAME OF SOLE PROPRIETOR TO VERIFY AGAINST CURRENT GST RECORD], trading as **CYBERDUDEBIVASH ECOSYSTEM®**, [VERIFIED PRINCIPAL PLACE OF BUSINESS].

**Service:** SENTINEL APEX Threat Intelligence Platform (`https://intel.cyberdudebivash.com`). The trade name and the software platform are **not** separate incorporated companies.

**Principal agreement:** [SIGNED MSA / ORDER FORM IDENTIFIER]. **Effective date:** [DATE AGREED BY BOTH PARTIES].

**Contact:** contact@cyberdudebivash.in, subject to deliverability verification before customer onboarding.

If the supplier acts as an independent controller for account, billing, security or operational data, record that role separately in the signed data-role schedule. Do not apply a controller/processor role to all processing without legal and factual review.

## 1. Processing schedule — to complete before execution

| Item | Customer-specific agreed value |
| --- | --- |
| Nature and purpose of processing | [DESCRIBE VERIFIED PRODUCT AND PROCESSING] |
| Categories of individuals | [USER / CONTACT / OTHER VERIFIED CATEGORIES] |
| Categories of personal data | [EMAIL, LOGIN METADATA, API-ACCESS RECORDS, INVOICING DATA AS ACTUALLY PROCESSED] |
| Processing duration and retention | [VERIFIED LIVE STORAGE/RETENTION MATRIX + LEGAL HOLD EXCEPTIONS] |
| Authentication, roles and tenant boundaries | [ACTUAL DEPLOYED BEHAVIOUR AND APPROVED PRIVILEGES] |
| Security measures and limitations | [DEPLOYMENT-SCOPED CONTROLS ANNEX, VERIFIED BY OWNER] |
| Breach escalation contacts and notification obligations | [PARTY CONTACTS, LEGAL DEADLINES, AGREED PRACTICAL CAPABILITY] |
| Data export, correction and deletion process | [VERIFIED ROUTES/OPERATOR PROCESS AND EXCEPTIONS] |
| Subprocessors and specific processing locations | [AUDITED CURRENT PROVIDERS AND RELEVANT DATA FLOWS] |
| International transfer mechanism, if applicable | [EXECUTED SCCs, UK ADDENDUM/IDTA, OR OTHER ACTUALLY VALID INSTRUMENT] |
| Product-specific TLP and intelligence-sharing restrictions | [APPLICABLE POLICY/ORDER TERMS] |

Do not attach historical marketing slides or stale infrastructure diagrams as production evidence. The currently published `privacy.html` accurately states that the platform uses Cloudflare's global edge network and **does not contractually guarantee EU/UK/UAE/US-only regional residency**.

## 2. Operating obligations — draft for negotiated approval

2.1 Each party will follow applicable data protection law for the processing activities and legal roles confirmed in the schedule.

2.2 For processing performed on behalf of the customer as controller, the processor shall act on documented lawful instructions, apply confidentiality and appropriate verified security controls, and assist with data-subject requests to the degree agreed in the signed service and support terms.

2.3 The processor will identify approved subprocessors before processing and apply legally required contractual safeguards. Do not list a vendor as a subprocessor without confirming its actual present role, data categories and locations. Historic references to AWS Ireland/US region pinning, Stripe and Railway are **not** verified infrastructure commitments.

2.4 If a security incident affecting covered personal data occurs, the processor shall follow the notification obligations and deadlines confirmed in the executed agreement and governing law. An aspirational response target is not evidence of a tested 24×7 on-call capability.

2.5 Deletion, retention, export, backup and termination duties must follow the verified technical data-flow inventory and applicable legal retention duties. No absolute erasure timeline or 7-year ClickHouse logging guarantee is offered by this unexecuted template.

2.6 Any permitted security audit, review rights, cost allocation, confidentiality and liability terms must be negotiated in the principal agreement and privacy annex. This template is not a blanket right to third-party penetration testing.

## 3. International transfers, data residency and regulatory statements

3.1 Cloudflare's global edge architecture must be assessed as configured. No jurisdiction-exclusive storage or processing, GDPR compliance certification, SOC 2 attestation, ISO 27001 certification or independent audit report is implied.

3.2 Where required, applicable international transfer documents must be specifically completed and signed with appropriate parties and annexes. A reference to an SCC, UK IDTA or addendum in this draft **does not execute it**.

3.3 For regulated customers, confirm intended data residency, current subprocessor list, tenant segregation, incident response, lawful basis and retention **before** processing restricted personal information. If the customer's requirements cannot be met, **do not onboard that workload**.

3.4 Do not assert payment-provider PCI scope, TLS minimum version, encryption cipher, MFA/SSO, annual external penetration testing or regulatory certification without corresponding current operational evidence and appropriate contract wording.

## 4. Commercial and contractual consistency

The DPA is subordinate to neither a fabricated procurement promise nor a webpage headline. Before execution reconcile:

- Exact statutory seller identity, trade name, address, billing entity and GST invoice policy;
- Scope, tier, usage limits, price, cancellation and refund obligations against `config/commercial-contract.json` and `docs/COMMERCIAL_POLICY_V1.md`;
- Actual Razorpay subscription and fulfillment flow; Gumroad is not an operational secondary automated path while its provisioning remains unavailable;
- The customer-specific order form, intended security role, permitted data, on-call/support capacity and agreed SLAs.

Any statement concerning payment, processing, security or compliance that cannot be evidenced shall be corrected, negotiated or explicitly excluded before signature.

## 5. Agreement and signatures — blank until authentic execution

**Controller's legal name:** [TO COMPLETE]  
**Controller signatory and authority:** [TO VERIFY]  
**Controller signature and date:** [NOT EXECUTED]

**Supplier's verified statutory legal name:** [TO VERIFY]  
**Trading name:** CYBERDUDEBIVASH ECOSYSTEM®  
**Supplier's authorised sole proprietor/signatory:** [TO VERIFY]  
**Supplier signature and date:** [NOT EXECUTED]

**Signed service agreement / annex references:** [NONE RECORDED]  
**Legal/privacy reviewer and review date:** [PENDING]  
**Final customer processing approval:** **NO-GO UNTIL ABOVE ITEMS VERIFIED AND SIGNED**

---

Internal review source only. This document is not legal advice, a compliance certificate, an issued contract or a release authorisation. See `docs/releases/2026-10-16-enterprise-pilot-release-control.md`.
