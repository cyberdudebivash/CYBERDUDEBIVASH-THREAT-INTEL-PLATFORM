# PLAN SELECTION EXPERIENCE AUDIT
## SENTINEL APEX v175.0 — Phase 2 Commercial Readiness Sprint
**Audited:** 2026-06-04 | **Auditor Role:** Principal SaaS Monetization Architect

---

## AUDIT SCOPE

Files audited: `upgrade.html`, `pricing.html`, `PAYMENT-GATEWAY.html`, `get-api-key.html`

---

## CURRENT PLAN ARCHITECTURE

### Plans as Defined Across Pages

| Plan | pricing.html | upgrade.html | PAYMENT-GATEWAY.html | get-api-key.html |
|------|-------------|--------------|---------------------|-----------------|
| Community / Free | ₹0 | ₹0 | — | Community |
| PRO | ₹4,100/mo | Present | Present | Pro |
| Team | — | — | — | Team (unique to this page) |
| Enterprise | ₹15,000/mo | Present | Present | Enterprise |
| MSSP | $1,999/mo (mssp.html) | — | — | — |

**Finding:** Plan naming is inconsistent across pages. `get-api-key.html` introduces a "Team" tier not shown on `pricing.html` or `upgrade.html`. MSSP is only on `mssp.html` — it does not appear in the main upgrade flow.

---

## UPGRADE.HTML AUDIT

### What Works
- Clean two-column layout (plan selection left, payment summary right)
- Monthly/Annual billing toggle with savings badge visible
- Plan cards display name, price in USD + INR equivalent, brief description
- Plan differentiation is present: Free / PRO / Enterprise labels
- "Popular" badge on PRO plan draws the eye correctly
- Payment method tabs visible (UPI, Bank Transfer, PayPal, Crypto)

### What Fails

#### 1. Pricing Clarity — PARTIAL PASS
- USD prices shown prominently but INR shown smaller below — for an India-first platform, INR should be the primary currency
- Annual pricing math is not immediately visible on the card itself — user must toggle to discover savings
- No explicit "what you save annually" figure in ₹ shown alongside the toggle

**Severity: P1**

#### 2. Feature Clarity — FAIL
- Plan cards on `upgrade.html` show 1-line descriptions only
- No feature comparison table or checklist on the upgrade page itself
- A prospect cannot compare Free vs PRO vs Enterprise features without navigating to `pricing.html`
- The upgrade page assumes the customer has already decided — it is not a decision-making page

**Severity: P0** — Customers who land directly on `upgrade.html` from a CTA have no feature context to commit to a plan.

#### 3. Plan Differentiation — PARTIAL PASS
- PRO is correctly badged as "Popular" / "HOT"
- Enterprise has a distinct label but no MSSP option visible
- No "best for" persona labels (e.g., "Best for: SOC Analysts", "Best for: Enterprise Security Teams", "Best for: MSSPs with 10+ clients")

**Severity: P1**

#### 4. Enterprise Positioning — FAIL
- Enterprise plan on `upgrade.html` shows a price (₹15,000/mo) but enterprise buyers typically expect "Contact Sales" for custom scoping
- No white-glove onboarding language for enterprise
- No mention of SLA, dedicated support, or custom data feeds on the upgrade page

**Severity: P1**

#### 5. MSSP Positioning — FAIL
- MSSP plan is completely absent from `upgrade.html`
- An MSSP arriving on the upgrade page has no path to buy
- `mssp.html` exists but has no "Buy Now" button — only a contact form

**Severity: P0**

#### 6. CTA Placement — PARTIAL PASS
- Each plan card has a CTA button
- CTAs are correctly positioned below plan details
- But: after selecting a plan, the "Proceed to Payment" button is below the fold on mobile — not visible without scrolling

**Severity: P1**

#### 7. Conversion Flow — FAIL
- After selecting a plan and payment method, the user is directed to PAYMENT-GATEWAY.html separately — there is no inline checkout
- Plan selection data (which plan was chosen) is NOT passed to the payment page via URL params consistently
- A customer who selects "PRO - ₹4,100/mo" and lands on PAYMENT-GATEWAY.html must manually identify the correct amount

**Severity: P0**

---

## PRICING.HTML AUDIT

### What Works
- Four plan cards with clear ₹ pricing
- "7-day free PRO trial" banner present
- Feature lists per plan are present and scannable
- Mobile responsive grid

### What Fails

| Issue | Severity |
|-------|---------|
| "7-day free PRO trial · No credit card required" — no trial activation mechanism exists | P0 |
| Community plan CTA points to `/` (homepage) — not a working free access flow | P0 |
| PRO CTA says "Start Free Trial" but routes to upgrade.html without pre-selecting trial | P1 |
| Enterprise CTA says "Contact Sales" but no contact form or calendar link attached | P1 |
| No annual pricing toggle on pricing.html — only monthly rates visible | P1 |
| MSSP not shown on pricing.html — a critical revenue tier is invisible at the top of funnel | P0 |

---

## RECOMMENDED PLAN SELECTION IMPROVEMENTS

### 1. Unified Plan Architecture (Canonical Definition)

Define exactly four plans across ALL pages with consistent naming:

| Plan | Monthly (INR) | Annual (INR) | Target Buyer |
|------|--------------|-------------|-------------|
| **Community** | Free | Free | Security researchers, students |
| **PRO** | ₹4,100 | ₹41,000 (save ₹8,200) | SOC analysts, individual practitioners |
| **Enterprise** | ₹15,000 | ₹1,50,000 (save ₹30,000) | Security teams, CISOs |
| **MSSP** | ₹1,65,000 ($1,999) | Custom | MSSPs, resellers |

Remove "Team" tier from `get-api-key.html` or promote it as a real plan.

### 2. Add Feature Comparison Table to upgrade.html

Embed a condensed comparison table directly on the upgrade page:

```
Feature                    Community   PRO         Enterprise  MSSP
─────────────────────────────────────────────────────────────────
API Calls/day              100         5,000       50,000      500,000
CVE Feed                   Top 10      Full        Full+Custom Full+Custom
STIX 2.1 Exports           ✗           ✓           ✓           ✓
Sigma Rules                ✗           ✓           ✓           ✓
YARA Rules                 ✗           ✗           ✓           ✓
White-label                ✗           ✗           ✗           ✓
Sub-tenants                ✗           ✗           ✗           ✓
Dedicated Support          ✗           Email       Email+WA    Dedicated
SLA                        ✗           ✗           99.5%       99.9%
```

### 3. Add "Best For" Persona Labels

Under each plan name, add one line:
- Community: *"Best for: Security researchers & learners"*
- PRO: *"Best for: SOC analysts & threat hunters"*
- Enterprise: *"Best for: Security teams & enterprise CISOs"*
- MSSP: *"Best for: MSSPs serving 5+ clients"*

### 4. Fix CTAs

| Current CTA | Fix |
|-------------|-----|
| Community → `/` | → `/get-api-key.html?plan=community` |
| PRO → `upgrade.html` | → `upgrade.html?plan=pro` (pre-selected) |
| Enterprise → Contact Sales | → `contact-enterprise.html` with embedded Calendly/form |
| MSSP → Missing | → Add MSSP card with "Contact MSSP Sales" linking to `mssp.html` |
| 7-day trial | Create `trial.html` with email capture + 7-day PRO key delivery |

### 5. Improve Conversion Flow

Pass plan data as URL parameters:
```
upgrade.html?plan=pro&billing=annual
PAYMENT-GATEWAY.html?plan=pro&amount=4100&currency=INR
```

Auto-populate: plan name, amount, billing period on the payment page so no manual re-entry.

### 6. Add Urgency Signals (Non-Deceptive)

- Show "Price valid until [end of current month]" for annual plans
- "API quota resets monthly — upgrade before [date] to maximize this month"
- Real customer count badge if available: "Trusted by X security professionals"

---

## PLAN SELECTION SCORECARD

| Dimension | Score | Notes |
|-----------|-------|-------|
| Pricing Clarity | 6/10 | Mixed currency, no annual on pricing.html |
| Feature Clarity | 4/10 | No comparison table on upgrade.html |
| Plan Differentiation | 5/10 | Inconsistent across pages |
| Enterprise Positioning | 4/10 | No Contact Sales path wired up |
| MSSP Positioning | 2/10 | Absent from main conversion flow |
| CTA Placement | 6/10 | Present but not pre-configured |
| Conversion Flow | 3/10 | Broken plan→payment data handoff |
| **Overall** | **4.3/10** | **Needs significant work** |

---

*Audit completed: 2026-06-04 | SENTINEL APEX v175.0 Commercial Readiness Sprint*
