# CYBERDUDEBIVASH(R) SENTINEL APEX — Service Level Agreement

**Document Version:** v147.0.0
**Effective Date:** 2026-05-11
**Classification:** Public | Enterprise Customer Reference
**Governed By:** CyberDudeBivash Pvt. Ltd. | GSTIN: 21ARKPN8270G1ZP

---

## 1. Overview

This Service Level Agreement (SLA) governs service commitments for **CYBERDUDEBIVASH(R) SENTINEL APEX**, the AI-Powered Global Threat Intelligence Platform operated by CyberDudeBivash Pvt. Ltd. ("Provider") for subscribing customers ("Customer").

Applies to all paid tiers: **PRO**, **ENTERPRISE**, and **MSSP / WHITE-LABEL**.

---

## 2. Service Availability Commitment

### 2.1 Uptime Targets by Tier

| Tier | Monthly Uptime SLA | Window |
|------|--------------------|--------|
| PRO | 99.9% | Rolling 30-day |
| ENTERPRISE | 99.95% | Rolling 30-day |
| MSSP / WHITE-LABEL | 99.99% | Rolling 30-day |

### 2.2 Excluded Downtime

- Scheduled maintenance (announced >=24 hours in advance)
- Force majeure events
- Customer-caused outages (misconfigured API keys, abuse traffic)
- Third-party upstream failures (Cloudflare, GitHub, R2) outside Provider control
- Emergency security patching (P0 CVEs, <=30 min grace period)

---

## 3. Threat Intelligence Pipeline SLA

| Metric | Target | Tier |
|--------|--------|------|
| Feed update frequency | <=15 minutes | All paid |
| Advisory ingestion latency | <=1 hour from source | ENTERPRISE, MSSP |
| STIX export generation | <=30 minutes post-ingestion | ENTERPRISE, MSSP |
| AI enrichment completion | <=2 hours post-ingestion | ENTERPRISE, MSSP |
| Minimum active advisories | 100+ items at all times | All paid |
| APEX AI confidence threshold | >=60% on all published items | All paid |
| STIX 2.1 compliance | 100% valid bundles | ENTERPRISE, MSSP |

---

## 4. API Performance SLA

| Endpoint | P50 | P99 | Tier |
|----------|-----|-----|------|
| GET /api/preview/ | <=200ms | <=800ms | All |
| GET /api/feed.json | <=150ms | <=500ms | All |
| GET /api/stix/* | <=300ms | <=1000ms | ENT, MSSP |
| POST /api/v1/predict/enterprise | <=2000ms | <=5000ms | ENT, MSSP |
| GET /health | <=100ms | <=300ms | All |

### 4.2 Rate Limits

| Tier | Daily | Per-Minute Burst |
|------|-------|-----------------|
| FREE | 100 | 10 |
| PRO | 5,000 | 100 |
| ENTERPRISE | Unlimited | 500 |
| MSSP | Unlimited | 2,000 |

---

## 5. Incident Response SLA

### 5.1 Severity Classification

| Severity | Definition |
|----------|-----------|
| P0 Critical | Full outage, data corruption, security breach |
| P1 High | Major feature unavailable, >50% customers impacted |
| P2 Medium | Single feature degraded, <50% customers impacted |
| P3 Low | Minor issue, cosmetic, no customer impact |

### 5.2 Response Time Commitments

| Severity | Initial Response | Status Update | Resolution |
|----------|-----------------|---------------|------------|
| P0 | 15 minutes | Every 30 min | 2 hours |
| P1 | 1 hour | Every 2 hours | 8 hours |
| P2 | 4 hours | Every 24 hours | 72 hours |
| P3 | 2 business days | Weekly | Next release |

MSSP tier: 24x7 response at P0/P1.

---

## 6. Service Credits

| Monthly Uptime | PRO | ENTERPRISE | MSSP |
|----------------|-----|-----------|------|
| 99.0% - 99.9% | 5% | 10% | 15% |
| 95.0% - 99.0% | 10% | 20% | 25% |
| < 95.0% | 25% | 50% | 50% |

Submit credit claims to support@cyberdudebivash.com within 30 days of the incident. Maximum credit per month: 50% of monthly fee.

---

## 7. Data & Security Commitments

- API keys: AES-256 encrypted at rest in Cloudflare KV
- JWT tokens: HS256-signed, expire per subscription tier settings
- All traffic: TLS 1.3 enforced — no plaintext HTTP accepted
- Security breach notification: ENTERPRISE/MSSP within 72 hours; PRO within 7 days
- MSSP data isolation: full namespace isolation via `contract_id` JWT claim scoping

---

## 8. Support Channels

| Tier | Channel | Hours |
|------|---------|-------|
| FREE | Community docs only | N/A |
| PRO | support@cyberdudebivash.com | Business hours IST |
| ENTERPRISE | Email + Priority queue | Business hours IST |
| MSSP | Dedicated channel + escalation | 24x7 P0/P1 |

---

## 9. Planned Maintenance

- Window: Saturdays 02:00-06:00 UTC
- Advance notice: >=24 hours standard; >=72 hours for major changes
- Emergency patches: <=30 min disruption, no advance notice required
- Status: https://intel.cyberdudebivash.com/status.html

---

## 10. Contact

- SLA queries: sla@cyberdudebivash.com
- Security disclosures: security@cyberdudebivash.com
- Enterprise sales: enterprise@cyberdudebivash.com

---

*Copyright 2026 CyberDudeBivash Pvt. Ltd. All rights reserved.*
*Platform: https://intel.cyberdudebivash.com | Website: https://www.cyberdudebivash.com*
