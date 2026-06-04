# SENTINEL APEX SECURITY QUESTIONNAIRE PACK
## Enterprise Procurement Security Assessment
**Version:** 1.0 | **Date:** 2026-06-04 | **Provider:** CYBERDUDEBIVASH SENTINEL APEX

---

## INSTRUCTIONS

This document answers common security questionnaire questions asked by enterprise procurement teams. Pre-filled responses are provided. Attach this pack to enterprise proposals and security review processes.

---

## SECTION 1 — VENDOR INFORMATION

| Question | Response |
|----------|----------|
| Legal entity name | CYBERDUDEBIVASH |
| Primary contact | Bivash Nayak |
| Contact email | bivash@cyberdudebivash.com |
| Platform URL | https://intel.cyberdudebivash.com |
| Registered country | India |
| GSTIN | 21ARKPN8270G1ZP |
| Data processing location | India (primary) |
| Third-party data processors | Formspree (form submissions), Cloudflare (CDN) |

---

## SECTION 2 — DATA CLASSIFICATION

| Question | Response |
|----------|----------|
| What data do you process? | Customer name, email, company, payment reference, API usage logs |
| Do you process PII? | Yes — limited to contact details and API usage |
| Do you process payment data? | No — payments handled by UPI/PayPal/NEFT providers directly. SENTINEL APEX never stores card numbers or bank credentials. |
| Do you store threat intelligence data? | Yes — public and commercial threat intelligence (CVE, IOC, STIX) |
| Do you process customer's internal security data? | No — SENTINEL APEX pushes intel TO customers. No customer internal data is ingested. |
| Is customer data used for training AI models? | No |

---

## SECTION 3 — ACCESS CONTROL

| Question | Response |
|----------|----------|
| Authentication mechanism | API key (SHA-256 hashed at rest, never stored in plaintext) |
| Multi-factor authentication | Available via API key + JWT dual-token flow |
| Privilege tiers | FREE / STANDARD / TRIAL / PRO / ENTERPRISE / MSSP |
| Key rotation | Customer-initiated on request; operator-initiated on compromise detection |
| Session management | JWT tokens expire in 24 hours |
| Revocation capability | Yes — immediate via revocation registry, takes effect within one API call |

---

## SECTION 4 — ENCRYPTION

| Question | Response |
|----------|----------|
| Data in transit | HTTPS/TLS 1.2+ on all endpoints |
| Data at rest | API keys stored as SHA-256 hashes. JSON files on encrypted storage. |
| Key management | API keys generated via secrets.token_hex(32) — cryptographically secure |
| Certificate management | Cloudflare SSL, auto-renewed |

---

## SECTION 5 — API SECURITY

| Question | Response |
|----------|----------|
| API authentication | API key (X-API-Key header) or JWT Bearer token |
| Rate limiting | Enforced per tier: TRIAL 500/day, PRO 5,000/day, ENT 50,000/day, MSSP 500,000/day |
| Input validation | All API inputs validated and sanitized |
| Error responses | Sanitized — no stack traces or internal paths exposed |
| API versioning | v1 (stable) |
| OpenAPI specification | Available at /data/openapi.json |

---

## SECTION 6 — AVAILABILITY & SLA

| Question | Response |
|----------|----------|
| Uptime target | 99.5% monthly (Enterprise) |
| Scheduled maintenance | 48-hour advance notice |
| Feed freshness | Updated every 6 hours (standard); live webhook push for Enterprise |
| Status monitoring | Operator-monitored |
| Incident response | P0 (platform down): 2-hour response, 24x7; P1: 4-hour response |
| Backup frequency | Daily |
| Recovery time objective | 4 hours (non-critical), 2 hours (P0) |

---

## SECTION 7 — COMPLIANCE & CERTIFICATIONS

| Question | Response |
|----------|----------|
| SOC 2 certification | Not currently certified. SOC 2 roadmap: Q4 2026. |
| ISO 27001 | Not currently certified. Roadmap: 2027. |
| GDPR compliance | Data minimization applied. Customer data used only for service delivery. Right to erasure: contact bivash@cyberdudebivash.com. DPA available on request. |
| CCPA | Customer data not sold to third parties. |
| PCI DSS | Not applicable — no cardholder data processed. |
| CISA alignment | Intelligence sourced from CISA KEV, NIST NVD, and MITRE ATT&CK. |
| TLP compliance | TLP protocol supported on all intelligence output. |

---

## SECTION 8 — DATA RETENTION & DELETION

| Question | Response |
|----------|----------|
| Customer data retention | Active subscription duration + 90 days after termination |
| API log retention | 90 days |
| Right to erasure | Yes — submit request to bivash@cyberdudebivash.com. Processed within 30 days. |
| Data portability | Customer data available in JSON format on request |
| Third-party data sharing | Never — customer data not shared with third parties |

---

## SECTION 9 — VULNERABILITY MANAGEMENT

| Question | Response |
|----------|----------|
| Patch cadence | Critical: 24 hours; High: 7 days; Medium: 30 days |
| Penetration testing | Self-assessed. Third-party pentest roadmap: Q3 2026. |
| Bug bounty | Responsible disclosure: bivash@cyberdudebivash.com |
| Vulnerability disclosure | Notified within 24 hours if customer data is affected |
| Dependency scanning | Python dependencies reviewed on each release |

---

## SECTION 10 — BUSINESS CONTINUITY

| Question | Response |
|----------|----------|
| Business continuity plan | Documented in docs/BCP_DISASTER_RECOVERY.md |
| Geographic redundancy | Primary: India. CDN: Cloudflare global edge. |
| Key person dependency | Bivash Nayak (primary operator). Succession documentation exists. |
| Vendor dependencies | Formspree (form capture), Cloudflare (CDN), GitHub (repository) |
| Exit/migration | Customer data exportable in JSON. No proprietary lock-in format. |

---

## DATA PROCESSING ADDENDUM

A Data Processing Addendum (DPA) aligned with GDPR Article 28 is available upon request.

Contact: bivash@cyberdudebivash.com with subject "DPA Request — [COMPANY NAME]"

The DPA covers:
- Subject matter and duration of processing
- Nature and purpose of processing
- Type of personal data
- Categories of data subjects
- Obligations and rights of the controller (customer)

---

## ADDITIONAL QUESTIONS

For questions not covered above, contact:
- **Email:** bivash@cyberdudebivash.com
- **WhatsApp:** +91 8179881447
- **Response SLA:** 4 hours (Enterprise customers), 24 hours (pre-sales)

---

*Security Questionnaire Pack v1.0 · SENTINEL APEX v177.0 · 2026-06-04*
*CYBERDUDEBIVASH · GSTIN: 21ARKPN8270G1ZP*
