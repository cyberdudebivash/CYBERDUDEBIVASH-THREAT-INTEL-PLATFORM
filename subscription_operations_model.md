# CYBERDUDEBIVASH® SENTINEL APEX
## Subscription Operations Model
**Version:** 1.0 | **Date:** 2026-05-29

---

## SECTION 1 — SUBSCRIPTION TIER ARCHITECTURE

### Tier Overview

| Plan | Monthly | Annual | Billing | Seat Limit | API Rate |
|------|---------|--------|---------|-----------|---------|
| Free | $0 | $0 | N/A | 1 | 100 req/min |
| Professional | $49 | $499 | Monthly or Annual | 3 | 500 req/min |
| Enterprise | $499 | $4,999 | Annual | 25 | 2,000 req/min |
| MSSP | $1,999 | $19,999 | Annual | Unlimited | 10,000 req/min |
| OEM / Custom | Negotiated | Negotiated | Custom | Custom | Custom |

### Per-Plan Capabilities

| Capability | Free | Pro | Enterprise | MSSP |
|------------|------|-----|------------|------|
| Threat advisories | 10/month | 100/month | Unlimited | Unlimited |
| IOC feed access | None | Partial | Full | Full + Per-Tenant |
| STIX 2.1 bundles | Sample only | Full | Full | Full |
| YARA/Sigma rules | Sample | Full pack | Full pack | Full pack |
| KQL/SPL rules | None | None | Full pack | Full pack |
| ATT&CK Navigator | Read-only | Full | Full | Per-Tenant |
| Graph intelligence | None | Basic | Full | Full |
| SOC workspace | None | 1 analyst | 5 analysts | Unlimited |
| White-label reports | None | None | None | Full |
| Multi-tenant | None | None | None | Up to 50 tenants |
| SLA | None | 99.5% | 99.9% | 99.95% |
| Support | Community | Email 48h | Slack/Email 4h | Dedicated 30m |
| API webhooks | None | 1 webhook | 10 webhooks | Unlimited |
| Dedicated CSM | None | None | Yes | Named Partner CSM |

---

## SECTION 2 — SUBSCRIPTION LIFECYCLE OPERATIONS

### 2.1 Subscription States

```
TRIAL → ACTIVE → [UPGRADED / DOWNGRADED] → [AT_RISK] → RENEWED / CHURNED
```

| State | Definition | Action Required |
|-------|------------|----------------|
| TRIAL | Free plan, never converted | Conversion nurture sequence |
| ACTIVE | Paying, within contract | Standard success motions |
| UPGRADED | Plan tier increased | Welcome to new tier email + CSM kickoff |
| DOWNGRADED | Plan tier decreased | Risk flag + outreach within 24h |
| SUSPENDED | Payment failure | Automated retry + dunning sequence |
| RENEWAL_PENDING | Within 90 days of expiry | Renewal motion activated |
| CHURNED | Cancelled or not renewed | Exit interview + reactivation sequence |

### 2.2 Billing Operations

**Payment Methods:** Credit card (Stripe), ACH/wire (Enterprise+), PO/invoice (Enterprise Annual)

**Billing Cycles:**
- Monthly plans: Auto-renew on subscription anniversary date
- Annual plans: Invoice issued 30 days before expiry
- MSSP: Custom billing per tenant count or flat enterprise rate

**Dunning Sequence (Payment Failure):**
- Day 0: Payment fails → Auto-retry + customer email notification
- Day 3: Retry #2 + warning email
- Day 7: Retry #3 + CSM notification for Enterprise/MSSP
- Day 10: Account suspended (read-only mode, no new intel)
- Day 14: Account deactivated if not resolved
- Day 30: Data retention policy triggers (30-day grace)

### 2.3 Upgrade Motion

**Automated Upgrade Triggers:**
- API usage >80% of tier limit for 3 consecutive days → Upgrade prompt in dashboard
- IOC count >tier limit accessed → Upgrade prompt
- User tries Pro feature on Free tier → In-app paywall + upgrade CTA
- User tries Enterprise feature on Pro tier → Upgrade CTA

**Upgrade Process:**
1. Customer selects new plan in billing portal
2. Prorated credit applied for remaining days on current plan
3. New capabilities available immediately
4. Welcome email + onboarding materials for new tier sent
5. CSM notified (Enterprise/MSSP upgrades)

### 2.4 Downgrade Motion

**Downgrade Policy:**
- Allowed only at renewal date (no mid-cycle downgrades)
- Customer must acknowledge capability reduction (in-app confirmation)
- Data above new tier limits retained for 30 days, then archived
- CSM outreach required within 24h of downgrade request

---

## SECTION 3 — SUBSCRIPTION REVENUE OPERATIONS

### 3.1 MRR/ARR Tracking

| Metric | Formula | Target |
|--------|---------|--------|
| MRR | Sum of monthly recurring revenue across all active subscriptions | Growth 8%/month |
| ARR | MRR × 12 | Year 1: $400K, Year 2: $1.2M |
| New MRR | Revenue from new subscriptions | >20% of total MRR |
| Expansion MRR | Revenue from upgrades of existing customers | >15% of total MRR |
| Churned MRR | Revenue lost from cancellations | <5% of total MRR |
| Net MRR Growth | New MRR + Expansion MRR − Churned MRR | Positive every month |

### 3.2 Cohort Analysis

Track monthly cohorts for:
- 3-month retention rate
- 6-month retention rate
- 12-month retention rate
- Average ARR expansion per cohort
- Churn rate by acquisition channel

### 3.3 Revenue Forecasting Inputs

- Renewal pipeline (ARR at risk)
- Expansion pipeline (qualified upsell opportunities)
- New logo pipeline (sales qualified leads)
- Churn forecast (At Risk health score accounts)

---

## SECTION 4 — CONTRACT OPERATIONS

### 4.1 Contract Types

| Type | Duration | Discount | Payment Terms |
|------|----------|----------|---------------|
| Month-to-month | 30 days | 0% | Credit card on file |
| Annual Prepaid | 12 months | 15% | Invoice net-30 |
| Annual Postpaid | 12 months | 5% | Monthly invoice |
| Multi-Year (2yr) | 24 months | 20% | Annual invoice |
| Multi-Year (3yr) | 36 months | 25% | Annual invoice |

### 4.2 Contract Renewal Workflow

| Timeline | Action | Owner |
|----------|--------|-------|
| T-90 days | Renewal alert triggered | Automated |
| T-90 days | CSM reviews account health | CSM |
| T-60 days | Renewal conversation initiated | CSM / AE |
| T-45 days | Renewal proposal + ROI report sent | CSM |
| T-30 days | Contract redlines (if any) | Legal / AE |
| T-14 days | Final contract sent for signature | AE |
| T-7 days | Escalation if unsigned | VP CS |
| T-0 days | Renewal complete or risk escalation | CRO |

---

*Subscription Operations Model v1.0 — CYBERDUDEBIVASH® SENTINEL APEX*
