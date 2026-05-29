# CYBERDUDEBIVASH® SENTINEL APEX
## MSSP Customer Operations Model
**Version:** 1.0 | **Date:** 2026-05-29

---

## SECTION 1 — MSSP OPERATING ARCHITECTURE

### 1.1 MSSP Tier Definitions

| MSSP Tier | Monthly | Tenants Included | Add'l Tenants | White-Label | Dedicated CSM |
|-----------|---------|-----------------|---------------|------------|--------------|
| MSSP Starter | $1,999 | Up to 10 | $149/tenant/mo | Yes | Pooled |
| MSSP Professional | $3,499 | Up to 25 | $99/tenant/mo | Yes | Named |
| MSSP Enterprise | $5,999 | Up to 50 | $79/tenant/mo | Yes | Dedicated |
| MSSP Unlimited | $9,999 | Unlimited | Included | Yes | Dedicated + SE |

### 1.2 MSSP Operational Hierarchy

```
CyberDudeBivash SENTINEL APEX (Platform)
     ↓
MSSP Partner (Tier 1 Operator)
     ↓
     ├── Client Tenant A (e.g., Apex Financial Corp)
     ├── Client Tenant B (e.g., Shield Healthcare Systems)
     ├── Client Tenant C (e.g., Nexus Manufacturing)
     └── Client Tenant N (up to plan limit)
```

**Isolation guarantee:** Zero cross-tenant data visibility. Each tenant has:
- Dedicated API key scoped to tenant namespace
- Isolated intelligence feed (sector-relevant advisories only)
- Separate SOC workspace
- Individual SLA tracking
- Per-tenant billing records
- Per-tenant audit logs

---

## SECTION 2 — MSSP TENANT LIFECYCLE

### 2.1 Tenant Provisioning Process (Target: <30 minutes)

| Step | Action | Owner | Time |
|------|--------|-------|------|
| 1 | MSSP requests new tenant via console or API | MSSP Operator | 2 min |
| 2 | Tenant name, sector, contact info provided | MSSP Operator | 3 min |
| 3 | Platform generates isolated tenant namespace + API key | Automated | 1 min |
| 4 | RBAC roles configured (Tenant Admin, Analyst, Read-Only) | MSSP Operator | 5 min |
| 5 | Sector-relevant intelligence filter applied | Automated | 1 min |
| 6 | Webhook endpoint configured for tenant SIEM | MSSP Operator | 5 min |
| 7 | Tenant onboarding checklist completed | MSSP Operator | 10 min |
| 8 | First advisory delivered to tenant | Automated | Immediate |

**Total provisioning time: <30 minutes**

### 2.2 Tenant States

| State | Definition | Billing |
|-------|------------|---------|
| PROVISIONING | Tenant being configured | No charge |
| ACTIVE | Fully operational | Full billing |
| SUSPENDED | Temporarily inactive (client pause) | 50% billing |
| OFFBOARDING | Client contract ending, data retention active | 30 days at full rate |
| ARCHIVED | Tenant decommissioned, data retained per policy | No charge |

### 2.3 Tenant Decommissioning

1. MSSP requests tenant decommission
2. Platform exports tenant intelligence history as ZIP (advisory list, IOCs, detection history)
3. 30-day data retention window begins
4. Tenant namespace isolated from all API access
5. Day 30: All tenant data deleted. Deletion certificate issued.

---

## SECTION 3 — MSSP INTELLIGENCE OPERATIONS

### 3.1 Per-Tenant Intelligence Customization

Each tenant can be configured with:

| Setting | Options | Impact |
|---------|---------|--------|
| Sector filter | Financial, Healthcare, Industrial, Government, Retail, Technology, Energy | Advisories filtered to sector-relevant threats |
| Severity threshold | CRITICAL only / HIGH+ / MEDIUM+ / ALL | Feed volume control |
| Geography focus | Global / Region-specific | APT and regulatory relevance |
| ATT&CK tactic focus | All tactics / Specific subset | Reduces noise for specialized SOCs |
| Language | English (default), additional on roadmap | Executive report language |

### 3.2 Per-Tenant Deliverables

| Deliverable | Frequency | Format | Recipient |
|-------------|-----------|--------|----------|
| Daily threat digest | Daily | Email + API | Tenant Analyst |
| Weekly intelligence report | Weekly | PDF | Tenant Security Lead |
| Monthly executive brief | Monthly | White-labeled PDF | Tenant CISO |
| ATT&CK coverage update | Monthly | PDF | Tenant Security Architect |
| Incident alert (Critical) | Real-time | Webhook + Email | Tenant SOC |
| Quarterly threat landscape | Quarterly | PDF | Tenant Board (optional) |

### 3.3 White-Label Branding

MSSP partners can configure per-tenant branding:

| Element | Configurable |
|---------|-------------|
| Report header logo | Yes (PNG, min 200×80px) |
| Report company name | Yes |
| Primary brand color | Yes (hex color) |
| Report footer | Yes |
| "Powered by" disclosure | Configurable (optional) |
| Email sender name | Yes (e.g., "Shield Security Intelligence") |
| Portal domain | Yes (e.g., intel.shieldsecurity.com via CNAME) |

---

## SECTION 4 — MSSP SLA OPERATIONS

### 4.1 Per-Tenant SLA Tracking

| SLA Metric | Target | Measurement |
|-----------|--------|-------------|
| Intelligence feed uptime | 99.95% | Monthly calculation per tenant |
| Critical advisory delivery | <15 min | Timestamp: source → tenant webhook |
| API response time (p95) | <300ms | Measured per tenant API key |
| Webhook delivery success rate | >99.5% | Successful deliveries / total attempts |
| Data isolation validation | 100% | Daily cross-tenant leakage test |

### 4.2 SLA Breach Consequences

| Breach Type | MSSP Credit | Customer Credit |
|-------------|-------------|----------------|
| Feed downtime 99.9%–99.95% | 5% monthly credit | MSSP communicates to client |
| Feed downtime 99.5%–99.9% | 10% monthly credit | MSSP communicates to client |
| Feed downtime <99.5% | 20% monthly credit | MSSP communicates to client |
| Data isolation failure (any) | Full monthly credit + incident report | Immediate notification required |

### 4.3 MSSP Incident Response

**Data Isolation Incident (Highest Severity):**
1. Immediate tenant suspension (both affected tenants)
2. Incident report initiated — 1 hour
3. CTO-level notification
4. Forensic audit of cross-tenant access
5. Remediation deployed + verified before tenant reactivation
6. Written incident report delivered to MSSP within 24h
7. Regulatory notification guidance provided if applicable

---

## SECTION 5 — MSSP PARTNER SUCCESS

### 5.1 MSSP Partner Onboarding (Target: 5 days)

| Day | Activity |
|-----|----------|
| 1 | MSSP console access provisioned. Partner training call (2h). |
| 2 | First 3 demo tenants provisioned. Intelligence validation. |
| 3 | White-label configuration. Branding verification. |
| 4 | Webhook + SIEM integration for MSSP's own SOC. |
| 5 | First client tenant provisioned. Go-live verification. |

### 5.2 MSSP Partner Success KPIs

| KPI | Target |
|-----|--------|
| Tenant provisioning time | <30 minutes |
| Partner platform utilization | >80% of tenants active monthly |
| MSSP partner renewal rate | >90% |
| Average tenants per MSSP | Growing (Month 3: 5, Month 12: 15) |
| MSSP NPS | >50 |

### 5.3 MSSP Growth Partnership

**Co-selling program:**
- SENTINEL APEX provides co-branded case studies for MSSP sales
- MSSP receives referral credit for platform feature requests implemented
- Joint GTM for MSSP selling into vertical markets (Financial, Healthcare, Government)
- MSSP partner directory listing on intel.cyberdudebivash.com

---

## SECTION 6 — MSSP BILLING OPERATIONS

### 6.1 Billing Model Options

| Model | Description | Best For |
|-------|-------------|---------|
| Flat monthly | Fixed price per MSSP tier | Predictable tenant count |
| Per-tenant | Base platform fee + per-active-tenant charge | Growing MSS businesses |
| Usage-based | API calls + report generations | High-volume, low-tenant MSS |

### 6.2 Billing Transparency

MSSP console shows:
- Current billing cycle charges
- Per-tenant cost breakdown
- Usage by tenant (API calls, reports, advisories)
- Projected next month billing
- Invoice history (12 months)
- Exportable billing report for client invoicing

---

*MSSP Customer Operations Model v1.0 — CYBERDUDEBIVASH® SENTINEL APEX*
