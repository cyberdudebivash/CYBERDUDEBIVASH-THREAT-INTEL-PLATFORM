# CUSTOMER JOURNEY AUDIT
## SENTINEL APEX v175.0 — Phase 1 Commercial Readiness Sprint
**Audited:** 2026-06-04 | **Auditor Role:** Principal Customer Acquisition Architect

---

## AUDIT SCOPE

Full trace of the commercial customer lifecycle across all platform touchpoints:

**Visitor → Prospect → Lead → Customer → Active Subscriber → Renewing Customer**

Files audited: `index.html`, `pricing.html`, `upgrade.html`, `PAYMENT-GATEWAY.html`, `get-api-key.html`, `onboarding.html`, `sentinel-onboarding.html`, `customer-portal.html`, `support-center.html`, `billing-center.html`, `revenue-dashboard.html`, `api-docs.html`, `mssp.html`, `enterprise.html`, and backend: `agent/api/auth.py`, `agent/api/rate_limiter.py`.

---

## STAGE 1 — VISITOR (Discovery)

### What exists
- `index.html` — main landing page with threat intelligence feed, paywall gating, and conversion CTAs
- `pricing.html` — plan comparison: Community ₹0, PRO ₹4,100/mo, Enterprise ₹15,000/mo, MSSP $1,999/mo
- `about.html`, `methodology.html`, `trust-center.html` — credibility content
- Conversion tracking deployed (`apex-track.js`) with events: `page_view`, `paywall_hit`, `cta_click`

### Friction Points

| # | Issue | Priority |
|---|-------|----------|
| F1 | Index page does not have a single dominant CTA above the fold — multiple competing buttons create decision paralysis | P0 |
| F2 | Pricing in mixed currencies (₹ for PRO/Enterprise, $ for MSSP) creates confusion for Indian vs. international visitors | P1 |
| F3 | No "Start Here" or guided path for first-time visitors — they land on a live threat feed with no onboarding prompt | P1 |
| F4 | Free Community plan CTA points to `/` (the homepage itself) — not a signup or dashboard page | P0 |
| F5 | 7-day free PRO trial promised on pricing.html — no corresponding trial activation flow found | P0 |

---

## STAGE 2 — PROSPECT (Evaluation)

### What exists
- `demo.html` — interactive demo
- `value-center.html` — ROI calculator
- `demo-conversion-center.html` — demo-to-upgrade funnel
- `methodology.html` — intelligence sourcing transparency
- `enterprise.html` — enterprise-specific positioning

### Friction Points

| # | Issue | Priority |
|---|-------|----------|
| F6 | No lead capture on demo page — visitor explores demo anonymously with no email gate or follow-up mechanism | P0 |
| F7 | `enterprise.html` lacks a "Book a Demo" or "Schedule Call" CTA — enterprise prospects have no direct human contact path | P1 |
| F8 | Value proposition between PRO and ENTERPRISE is unclear — feature differentiation is present but the decision trigger (when to upgrade) is not communicated | P1 |
| F9 | Social proof is generic — no named case studies, no customer logos, no verified testimonials with company names | P2 |

---

## STAGE 3 — LEAD (Intent to Purchase)

### What exists
- `upgrade.html` — plan selection + payment method selection UI
- `PAYMENT-GATEWAY.html` — dedicated payment page with UPI, NEFT, PayPal, Crypto tabs
- `get-api-key.html` — API key request form (uses Formspree: `xpzgkqly`)

### Friction Points

| # | Issue | Priority |
|---|-------|----------|
| F10 | **CRITICAL: Two separate payment journeys exist** — `upgrade.html` and `PAYMENT-GATEWAY.html` operate independently. A prospect may complete payment on PAYMENT-GATEWAY.html but not know to also submit the transaction tracker. Handoff is undefined. | P0 |
| F11 | `upgrade.html` has a payment method selector but no UPI QR code or bank details inline — it routes to a separate page, creating drop-off | P0 |
| F12 | No payment amount confirmation shown before a customer pays — they must remember their selected plan price and enter it manually | P1 |
| F13 | Transaction ID submission form uses a separate Formspree endpoint (`xpzgkqly`) — no automated cross-reference with plan selection data | P0 |
| F14 | After submitting transaction ID, customer receives no SLA commitment on the confirmation screen — only "within 2 hours" for urgent WhatsApp | P1 |

---

## STAGE 4 — CUSTOMER (First Payment)

### What exists
- Payment tracker form on `PAYMENT-GATEWAY.html` (Formspree: `xpzgkqly`)
- WhatsApp support: +91 8179881447
- Email: `bivash@cyberdudebivash.com`
- `billing-center.html` — billing status UI (static data)

### Friction Points

| # | Issue | Priority |
|---|-------|----------|
| F15 | **CRITICAL: API key provisioning is fully manual** — no automated system triggers key generation upon payment verification. The operator must check Formspree, verify payment, generate key, and email it manually | P0 |
| F16 | `billing-center.html` shows hardcoded static data — not connected to any real customer record or subscription state | P0 |
| F17 | Customer has no self-service portal to check their API key status, subscription status, or payment history | P0 |
| F18 | No automated payment confirmation email sent to customer after their transaction ID is submitted | P1 |
| F19 | No payment receipt or invoice generated — required for enterprise procurement and compliance | P1 |

---

## STAGE 5 — ACTIVE SUBSCRIBER (Ongoing Value)

### What exists
- `customer-portal.html` — customer dashboard shell
- `customer-dashboard.html` — usage/intel view
- `api-docs.html` — API documentation
- `support-center.html` — support contact page
- `sla.html` — SLA definitions

### Friction Points

| # | Issue | Priority |
|---|-------|----------|
| F20 | `customer-portal.html` does not authenticate — any visitor can access it. No real customer data is shown | P0 |
| F21 | API quota consumption is not visible to the customer — they cannot see how many requests they've made vs. their tier limit | P1 |
| F22 | Support pathways (email, WhatsApp) are consistent but have no tracked SLA — no ticket ID, no acknowledgement system | P1 |
| F23 | No in-app notifications or alerts when customers hit rate limits or when their subscription is expiring | P2 |

---

## STAGE 6 — RENEWING CUSTOMER (Retention)

### What exists
- `billing-center.html` — billing history shell
- `subscription-billing-center.html` — subscription management shell

### Friction Points

| # | Issue | Priority |
|---|-------|----------|
| F24 | **No renewal reminder system** — no automated email or alert when subscription approaches expiry | P0 |
| F25 | No self-service renewal flow — customer must contact support or re-initiate the full payment process | P0 |
| F26 | Revenue tracking (`revenue-dashboard.html`) reads from `localStorage` — data is lost if browser is cleared or device changes | P0 |
| F27 | No churn prevention mechanism — no exit survey, no downgrade path, no pause option | P2 |

---

## CONSOLIDATED FINDINGS BY PRIORITY

### P0 — Revenue Blockers (Must Fix Before First Customer)

| ID | Finding | Impact |
|----|---------|--------|
| F1 | No dominant above-fold CTA on index.html | Lost conversions at top of funnel |
| F4 | Community plan CTA routes to `/` instead of signup | Broken free-tier acquisition |
| F5 | 7-day free trial promised — no activation flow | Promise vs. reality mismatch |
| F10 | Two disconnected payment journeys (upgrade.html vs PAYMENT-GATEWAY.html) | Prospect confusion, drop-off |
| F13 | Transaction ID submission not linked to plan selection | Manual reconciliation burden |
| F15 | API key provisioning is 100% manual | Operational bottleneck at every sale |
| F16 | billing-center.html has no real data | Unusable post-sale |
| F17 | No customer self-service portal | High support load per customer |
| F20 | customer-portal.html has no auth | Security gap |
| F24 | No renewal reminders | Revenue leakage at subscription end |
| F25 | No self-service renewal flow | Churn at renewal |
| F26 | Revenue tracking in localStorage | Data loss, no audit trail |

### P1 — Conversion & Experience Friction

| ID | Finding | Impact |
|----|---------|--------|
| F2 | Mixed ₹/$ currency display | International confusion |
| F3 | No guided path for first-time visitors | High bounce rate |
| F6 | No lead capture on demo page | Lost warm leads |
| F7 | Enterprise page has no human contact CTA | Lost enterprise deals |
| F8 | PRO vs Enterprise decision trigger unclear | Plan selection hesitation |
| F11 | Payment details not inline on upgrade.html | Drop-off at payment step |
| F12 | No amount confirmation before payment | Errors, wrong amounts paid |
| F14 | No SLA on post-payment confirmation screen | Customer anxiety |
| F18 | No automated payment confirmation email | Trust gap |
| F19 | No invoice/receipt generation | Blocks enterprise procurement |
| F21 | API quota not visible to customer | Support requests, frustration |
| F22 | No support ticket IDs or SLA ack | Unscalable support |

### P2 — Enhancement (Post-Launch Improvement)

| ID | Finding | Impact |
|----|---------|--------|
| F9 | No named customer social proof | Reduced conversion on enterprise deals |
| F23 | No in-app quota/expiry alerts | Reactive support load |
| F27 | No churn prevention mechanisms | Avoidable attrition |

---

## JOURNEY SCORECARD

| Stage | Completeness | Friction Level | Revenue Risk |
|-------|-------------|----------------|--------------|
| Visitor / Discovery | 70% | Medium | Medium |
| Prospect / Evaluation | 60% | High | High |
| Lead / Purchase Intent | 45% | Critical | Critical |
| First Payment | 40% | Critical | Critical |
| Active Subscriber | 50% | High | High |
| Renewal | 20% | Critical | Critical |

**Overall Journey Completeness: 47.5% — NOT COMMERCIALLY READY**

---

## RECOMMENDED PRIORITY FIXES (ORDER OF EXECUTION)

1. Consolidate `upgrade.html` + `PAYMENT-GATEWAY.html` into one unified checkout flow
2. Connect transaction ID submission to plan data automatically
3. Build minimal API key provisioning automation (Formspree webhook → key generation → email delivery)
4. Activate customer auth on `customer-portal.html`
5. Fix Community plan CTA to point to actual free signup
6. Add renewal reminder emails at D-14 and D-3 before expiry
7. Add lead capture to `demo.html`
8. Move revenue tracking to server-side or Google Sheets (eliminate localStorage dependency)

---

*Audit completed: 2026-06-04 | SENTINEL APEX v175.0 Commercial Readiness Sprint*
