# CYBERDUDEBIVASH® SENTINEL APEX
## Data Processing Agreement (DPA) Template
**SOC 2 Control: P1.3 — GDPR / Data Residency Compliance**
**Version:** 162.0.0 | **Effective Date:** 2026-05-26

---

## Article 1 — Definitions

- **"Controller"**: The enterprise customer or MSSP partner entering into this DPA.
- **"Processor"**: CYBERDUDEBIVASH® SENTINEL APEX (root@cyberdudebivash.in)
- **"Personal Data"**: Any data relating to an identified or identifiable natural person.
- **"Processing"**: Any operation performed on Personal Data.
- **"GDPR"**: EU General Data Protection Regulation 2016/679.

---

## Article 2 — Subject Matter and Duration

2.1 SENTINEL APEX processes Personal Data solely to deliver threat intelligence services as described in the Service Agreement.

2.2 Processing continues for the duration of the subscription and ceases upon termination or expiry.

---

## Article 3 — Nature and Purpose of Processing

| Category | Data Elements | Purpose | Legal Basis |
|----------|--------------|---------|-------------|
| Authentication | API key hash, IP address | Access control | Contract (Art.6(1)(b)) |
| Telemetry | Anonymized usage metrics | Service improvement | Legitimate interest |
| Billing | Name, email, payment tokens | Invoice & subscription | Contract |
| Security logs | Access timestamps, endpoints | Audit & compliance | Legal obligation |

---

## Article 4 — Data Residency and Transfers

4.1 **EU Customers**: Data processed exclusively in `eu-west-1` (Ireland, AWS) — GDPR-compliant jurisdiction.

4.2 **US Customers**: Data processed in `us-east-1` (Virginia) under EU-US Data Privacy Framework.

4.3 **APAC Customers**: Data processed in `ap-south-1` (Mumbai) with local data residency.

4.4 Cross-border transfers rely on Standard Contractual Clauses (SCCs) per GDPR Art.46.

---

## Article 5 — Data Subject Rights

SENTINEL APEX implements the following GDPR data subject rights:

### 5.1 Right to Access (Art.15)
Customers may request a full export of their data via:
```
GET /api/v1/gdpr/export?api_key={key}
```
Response delivered within **30 days** in JSON/CSV format.

### 5.2 Right to Erasure / Data Deletion (Art.17)
Customers may request complete data deletion via:
```
DELETE /api/v1/gdpr/delete?api_key={key}
```
Deletion executed within **30 days**. Compliance logs retained per legal obligation.

### 5.3 Right to Portability (Art.20)
Data export includes all stored: API usage telemetry, alert history, billing records.

### 5.4 Right to Rectification (Art.16)
Contact: root@cyberdudebivash.in | Response within 5 business days.

---

## Article 6 — Security Measures (Art.32)

| Measure | Implementation |
|---------|---------------|
| Encryption at rest | AES-256 (ClickHouse, Redis, S3/R2) |
| Encryption in transit | TLS 1.3 minimum, HSTS enforced |
| Access controls | RBAC (api/rbac.py) + API key + IP allowlist |
| Audit logging | ClickHouse audit_log table — 7-year retention |
| SAST/SCA | GitHub Actions (.github/workflows/sast-security-scan.yml) |
| Vulnerability scanning | SBOM + Trivy weekly scans |
| Pen testing | Annual third-party + quarterly internal red team |

---

## Article 7 — Sub-processors

| Sub-processor | Location | Purpose | DPA Link |
|--------------|---------|---------|----------|
| Amazon Web Services | US/EU/APAC | Cloud infrastructure | aws.amazon.com/compliance/gdpr-center |
| Cloudflare | Global CDN | DDoS protection, R2 storage | cloudflare.com/gdpr |
| Stripe | USA | Payment processing | stripe.com/legal/dpa |
| Railway | USA | API deployment | railway.app/legal |

---

## Article 8 — Data Breach Notification (Art.33/34)

8.1 SENTINEL APEX will notify the Controller within **72 hours** of discovering a Personal Data breach.

8.2 Notification includes: nature of breach, data categories affected, estimated number of individuals, likely consequences, and remediation measures.

---

## Article 9 — Retention and Deletion

| Data Type | Retention Period | Deletion Method |
|-----------|----------------|----------------|
| API access logs | 90 days hot / 1 year cold | Automated TTL (ClickHouse) |
| Audit logs | 7 years (legal requirement) | Secure deletion per NIST 800-88 |
| Billing records | 7 years (tax law) | Archived, encrypted |
| User account data | Duration of subscription + 30 days | Automated deletion API |

---

## Article 10 — Cookie Consent

10.1 The SENTINEL APEX dashboard implements cookie consent per ePrivacy Directive:
- **Strictly necessary**: Authentication tokens (no consent required)
- **Analytics**: Anonymized usage (consent required, opt-in)
- **Preferences**: UI settings (consent required, opt-in)

Cookie consent managed via `assets/js/cookie-consent.js`.

---

## Article 11 — Governing Law

This DPA is governed by the laws of India and, where applicable, the European Union (GDPR).

---

**CONTROLLER SIGNATURE:** _________________ Date: _______
**PROCESSOR (SENTINEL APEX):** CYBERDUDEBIVASH® Date: 2026-05-26

*DPA Version 162.0.0 — Published 2026-05-26 — SOC 2 P1.3 CERTIFIED*
