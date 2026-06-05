# ENTERPRISE SALES PLAN — CYBERDUDEBIVASH® SENTINEL APEX
## Principal Revenue Infrastructure Architect · June 2026

---

## EXECUTIVE SUMMARY

SENTINEL APEX has enterprise-grade intelligence quality that competes with platforms charging $1,200–8,000/month. The Enterprise tier is currently priced at an inconsistent $180–499/month and has no structured sales motion. This plan builds the enterprise sales system from zero to a repeatable $999/month ACV pipeline.

**Target: 10 Enterprise accounts in 90 days = $9,990/month = $119,880/year ARR**

---

## SECTION 1 — ENTERPRISE PAGE AUDIT

### 1.1 Current Enterprise Pages Found

| Page | Status | Issue |
|---|---|---|
| enterprise.html | Exists | Content unknown — no CTI-specific value props confirmed |
| contact-enterprise.html | Exists | Form with no stated SLA, no demo booking |
| dashboard/enterprise_dashboard.html | Exists | Internal dashboard — not sales-facing |
| ENTERPRISE DASHBOARD (nav) | Navigation item | Routes to internal tool, not sales page |

### 1.2 Missing Enterprise Sales Infrastructure

| Asset | Status | Revenue Impact |
|---|---|---|
| Enterprise pricing page | Missing (pricing.html shows wrong $180) | CRITICAL |
| Demo booking system (Calendly/cal.com) | Not found | CRITICAL |
| Enterprise case study / use case | Not found | HIGH |
| ROI calculator | Not found | HIGH |
| Security questionnaire / compliance docs | Not found | HIGH |
| Vendor assessment response template | Not found | HIGH |
| MSA / SLA documentation | Not found | HIGH |
| SOC 2 Type II or equivalent badge | Not found | MEDIUM |
| Integration certification page | Not found | MEDIUM |

---

## SECTION 2 — ENTERPRISE ICP (IDEAL CUSTOMER PROFILE)

### Primary ICP — Tier 1 Enterprise Target

**Who:** Security Operations Manager / VP of Security / CISO
**Company size:** 200–2,000 employees
**Industry:** Financial services, healthcare, technology, energy, retail
**Current pain:** Paying $1,200/month for Recorded Future or pulling free feeds manually
**Budget:** $500–2,000/month pre-approved for CTI
**Decision criteria:** API quality, SIEM integration, STIX 2.1 compliance, coverage depth
**Time to close:** 14–30 days
**Key objection:** "Are you as good as Recorded Future?" → Answer: "Same data, 90% cheaper, STIX 2.1 compliant."

### Secondary ICP — Mid-Market SOC Teams

**Who:** SOC Lead, Detection Engineer, Threat Intel Analyst
**Company size:** 50–200 employees
**Current pain:** Writing detection rules manually, no IOC feed automation
**Budget:** $100–500/month
**Decision criteria:** Sigma/YARA quality, API ease of use, weekly reports
**Time to close:** 3–7 days (self-serve PRO)
**Conversion path:** Free dashboard → PRO trial → auto-convert

### Tertiary ICP — Regional/National Banks & PSUs (India)

**Who:** CISO, IT Security Head
**Industry:** Banking, government, critical infrastructure
**Pain:** DPDP Act compliance, CERT-In incident reporting, IOC blocking
**Budget:** ₹50,000–200,000/month
**Special offer:** DPDP compliance pack + CERT-In advisory format
**Decision criteria:** India-specific threat coverage, local regulatory mapping
**Time to close:** 30–60 days (procurement cycle)

---

## SECTION 3 — ENTERPRISE TRIAL WORKFLOW

### Step 1: Discovery (Day 0)
**Trigger:** Enterprise inquiry form, LinkedIn outreach, inbound demo request, or referred by MSSP partner

**Actions:**
- Automated acknowledgment email within 5 minutes: "We received your inquiry. A member of our team will contact you within 4 business hours."
- CRM entry created with company, contact, source, industry, company size
- SDR/founder assigns priority: Hot (responds same day) / Warm (responds within 4 hours)

---

### Step 2: Discovery Call (Day 1-3)

**Agenda (30 minutes):**
1. [5 min] What does your current CTI stack look like? (Recorded Future? Manual? Nothing?)
2. [5 min] Walk me through your biggest pain in threat detection today
3. [10 min] Live demo of SENTINEL APEX:
   - Show CRITICAL advisory with CISA KEV confirmation
   - Show detection pack (Sigma/YARA/KQL/SPL) auto-generated
   - Show STIX 2.1 bundle
   - Show SIEM webhook demo (if Enterprise)
4. [5 min] Technical fit check: What SIEM are you running?
5. [5 min] Next steps

**Outcome:** Qualified (move to trial) or Not Qualified (nurture sequence)

---

### Step 3: Enterprise Trial Provisioning (Day 3-5)

**14-day Enterprise trial (recommended — double the PRO trial)**

**Trial provisioning checklist:**
- [ ] Enterprise API key issued within 30 minutes of trial start
- [ ] Welcome email with: API key, integration docs, sample SIEM webhook config
- [ ] Calendly link for "30-minute SIEM integration support call"
- [ ] Access to full Enterprise dashboard
- [ ] Pre-built SIEM connector package sent (Splunk SPL / Sentinel KQL / QRadar)

**Day 1 trial email:**
> "Your SENTINEL APEX Enterprise trial is live. Your API key: [KEY]. Watch this 5-minute video to connect it to your SIEM: [LINK]. Book a 30-minute integration call if you need help: [CALENDLY]."

**Day 7 trial email:**
> "Halfway through your trial. Here's what SENTINEL APEX delivered this week: 12 CRITICAL/HIGH advisories, 3 CISA KEV confirmations, 84 IOCs, and 36 detection rules across Sigma/YARA/KQL. Want me to pull a weekly intelligence summary customized for your sector?"

**Day 13 trial email:**
> "Your trial ends tomorrow. I've prepared a 90-day threat briefing for your industry [attach sector brief PDF]. Here's how to convert to Enterprise: [Stripe link]. Your team can be live in under 5 minutes."

---

### Step 4: Enterprise Conversion (Day 14-17)

**Conversion triggers:**
- Trial account has made 100+ API calls → warm signal
- User downloaded STIX bundles → MISP/OpenCTI integration attempt
- User triggered SIEM webhook → active integration
- User exported CSV or detection pack → operational dependency

**Conversion conversation:**
> "Your team made 847 API calls during the trial, downloaded 14 STIX bundles, and your Splunk is now receiving real-time CRITICAL advisories. To keep that running, it's $999/month — here's your invoice. I've also attached a Q3 threat forecast for your sector. Would you like me to schedule your onboarding call for next week?"

**Payment:** Stripe invoice (Enterprise — net 30 terms available, or immediate Stripe checkout)

---

### Step 5: Enterprise Onboarding (Day 17-21)

**2-hour onboarding session (video call):**
1. API authentication + rate limits walkthrough (20 min)
2. SIEM integration: configure webhook push to Splunk/Sentinel (30 min)
3. Detection pack deployment: import Sigma/YARA into EDR (20 min)
4. IOC list upload to firewall/proxy/DNS RPZ (20 min)
5. Configure executive briefing schedule (10 min)
6. Introduce monthly advisory and QBR schedule (20 min)

**Deliverables after onboarding:**
- Completed integration confirmation email
- 30-day threat brief customized for their sector
- Named Slack/Teams channel opened
- Monthly briefing schedule confirmed

---

### Step 6: Enterprise Retention (Month 2+)

**Month 1:** Send weekly intelligence summary every Monday
**Month 1:** Send first monthly threat report (PDF)
**Month 2:** QBR prep — pull usage stats, highlight value delivered
**Month 2:** Upsell conversation: "Want to add the CISO Executive Pack? It auto-generates your monthly board briefing."
**Month 3:** First QBR — present 90-day threat landscape, discuss renewal

**Churn prevention signals:**
- API calls dropping below 50/week → check in immediately
- No new SIEM webhook calls → integration may have broken → proactive support
- No PDF downloads → executive is not seeing value → send pre-formatted briefing

---

## SECTION 4 — ENTERPRISE SALES ASSETS (BUILD LIST)

| Asset | Priority | Description |
|---|---|---|
| Enterprise one-pager (PDF) | P0 | 1-page: APEX vs Recorded Future, pricing, integration |
| SIEM integration guide (PDF) | P0 | Splunk / Sentinel / QRadar step-by-step |
| ROI calculator (web) | P0 | "You save $X vs. Recorded Future + X analyst hours" |
| Security FAQ document | P0 | Data retention, privacy, API security, uptime SLA |
| Case study template | P1 | "How [Company Type] reduced detection time by X%" |
| Vendor security questionnaire response | P1 | Pre-filled VSQ for procurement teams |
| SOC 2 Type II readiness assessment | P2 | Begin compliance path for enterprise trust |
| MSA template (with legal review) | P1 | Standard enterprise contract, net 30 terms |
| Demo environment | P1 | Sandboxed enterprise dashboard for prospects |

---

## SECTION 5 — ENTERPRISE PIPELINE DESIGN

### Pipeline Stages

| Stage | Definition | Target Conversion |
|---|---|---|
| Lead | Contact or form fill | 100% enter pipeline |
| Qualified | Discovery call completed, budget confirmed | 40% of leads |
| Trial Active | Enterprise trial key issued | 75% of qualified |
| Trial Converted | Integration confirmed (API calls > 100) | 60% of trials |
| Closed Won | Stripe payment received | 70% of converted |
| Onboarded | SIEM connected + onboarding call done | 100% of closed won |

### Projected Enterprise Pipeline (90 days)

| Month | Leads | Qualified | Trials | Conversions | Closed | MRR Added |
|---|---|---|---|---|---|---|
| Month 1 | 20 | 8 | 6 | 4 | 3 | $2,997 |
| Month 2 | 30 | 12 | 9 | 6 | 4 | $3,996 |
| Month 3 | 40 | 16 | 12 | 8 | 6 | $5,994 |
| **Total** | **90** | **36** | **27** | **18** | **13** | **$12,987/mo** |

---

## SECTION 6 — ENTERPRISE PRICING STRATEGY

### Current (Broken): $180 (pricing.html) / $499 (payment gateway)
### Recommended: $999/month

**Why $999 and not $499:**
1. Competitive benchmark: Cheapest credible competitor (GreyNoise) is $2,000/month
2. $999 is a rounding point that says "this is a real enterprise product"
3. $499 triggers "this might be a startup side project" skepticism
4. A single incident that APEX detects early is worth $250K–$1.5M (shown in FAIR model on every dossier)
5. SOC managers have $999/month discretionary budgets; amounts above $1,000 often require procurement approval

**Annual billing incentive:** $9,990/year (save $1,998 = 2 months free) — drives upfront ARR, reduces churn risk, improves cash flow

---

*Document Version: 1.0 | CYBERDUDEBIVASH SENTINEL APEX Enterprise Sales Plan*
*Principal Revenue Infrastructure Architect | June 5, 2026*
