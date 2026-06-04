# CUSTOMER SUCCESS PLAYBOOK v177
## SENTINEL APEX — Full Customer Lifecycle Management
**Version:** 1.0 | **Date:** 2026-06-04

---

## OVERVIEW

This playbook governs the customer lifecycle from activation through renewal. It defines the health score model, operator touchpoints, and expansion triggers.

**CS Philosophy:** Every customer who makes their first API call stays. Every customer who doesn't make their first API call within 3 days churns. Activation is the #1 priority.

---

## CUSTOMER LIFECYCLE STAGES

```
TRIAL (Day 0) → ACTIVATED (Day 1-3) → ENGAGED (Day 7+) → HEALTHY (Day 30) → RENEWAL
```

---

## HEALTH SCORE MODEL (0–100)

**Inputs:**
| Signal | Points | Measurement |
|--------|--------|-------------|
| API calls last 7 days (≥100/day avg) | 30 | audit.log |
| SIEM integration confirmed | 20 | Customer confirms via email/WhatsApp |
| Downloaded/accessed STIX bundle | 15 | API log: /api/stix/ endpoint hits |
| Logged into platform dashboard last 7 days | 15 | Platform access log |
| Support ticket resolved successfully | 10 | Operator confirmed |
| Renewed on-time (no grace period) | 10 | Subscription record |
| **TOTAL** | **100** | |

**Health buckets:**
- **≥70 (Healthy):** Quarterly check-in, expansion opportunity
- **40-69 (Moderate):** Monthly check-in, identify friction
- **<40 (At-Risk):** Immediate intervention, understand blocker

---

## DAY 0 — ONBOARDING CHECKLIST

**Trigger:** API key delivered (PRO/Enterprise/MSSP provisioned)

**Operator actions (complete within 4 hours of key delivery):**

```
[ ] Confirm key delivery email sent (template: templates/email/06_api_key_delivered.txt)
[ ] Welcome email includes:
    - API key (or confirmed in prior email)
    - Quickstart link: https://intel.cyberdudebivash.com/docs/quickstart.html
    - FAQ link: https://intel.cyberdudebivash.com/docs/faq.html
    - Support contacts: bivash@cyberdudebivash.com | +91 8179881447
[ ] Customer reference logged in data/customers/active.json
[ ] Subscription logged in data/subscriptions/ledger.json
[ ] WhatsApp message sent (for Enterprise/MSSP): "Hi [NAME], your SENTINEL APEX key is live.
    Let me know when you make your first API call — happy to help if anything doesn't work."
```

**Day 0 welcome email (send immediately after key):**
```
Subject: Welcome to SENTINEL APEX — Your Access is Live [SA-YYYYMMDD-XXXX]

Hi [NAME],

Welcome to SENTINEL APEX.

Your [TIER] API key is active. Reference: [REF_ID]

FIRST STEP (takes 30 seconds):
https://intel.cyberdudebivash.com/docs/quickstart.html

What to do right now:
1. Make your first API call (the quickstart has copy-paste examples)
2. Pull the current threat feed — you'll see today's 73 advisories
3. Download a STIX 2.1 bundle to test ingestion

For [SIEM_PLATFORM] specifically:
[PERSONALIZED: include specific integration note for their SIEM]

I'm available on WhatsApp (+91 8179881447) if you hit any blocker.
Most integrations take under 5 minutes.

— Bivash
```

---

## DAY 3 — ACTIVATION CHECK

**Trigger:** 3 days after key delivery

**Check:** Has the customer made API calls?

**If YES (activated):**
```
Subject: Great — 3 days in. Here's what else you can use.

Hi [NAME],

Glad you're using the API. A few things worth knowing:

1. Sigma detection rules — every HIGH advisory has a Sigma rule you can
   import directly. Try: GET /api/rules/sigma?intel_id=[ANY_HIGH_ADVISORY_ID]

2. STIX bundles — for automated ingestion to MISP/OpenCTI:
   GET /api/stix/[INTEL_ID]

3. Exploitation predictions — 30-day forecasts for all tracked CVEs:
   GET /api/predictions

Any specific integration you want help with?

— Bivash
```

**If NO (not activated):**
```
Subject: Quick check-in — did the API key work?

Hi [NAME],

It's been 3 days since your SENTINEL APEX key was activated.

I haven't seen any API calls from your account, which usually means one of:
a) You haven't had time to test yet (totally fine)
b) There's a technical issue I can fix in 5 minutes

Here's the simplest possible test:
curl -H "X-API-Key: [THEIR_KEY]" https://intel.cyberdudebivash.com/api/feed

If you get a JSON response with advisories — you're live.
If you get an error — reply with the error message and I'll fix it immediately.

— Bivash
```

---

## DAY 7 — ACTIVATION REVIEW

**Trigger:** 7 days after key delivery

**Operator actions:**

```
[ ] Calculate health score (see formula above)
[ ] Log health score in data/customers/active.json
[ ] Send Day 7 email (see below)
[ ] For Enterprise/MSSP: schedule 30-min check-in call
```

**Day 7 email:**
```
Subject: One week in — how's SENTINEL APEX working for you?

Hi [NAME],

It's been a week. Quick check-in.

Based on your usage, you've [integrated/not yet integrated] with [SIEM].

Three questions:
1. Is the API working the way you expected?
2. Is there a specific intelligence type you're not finding? (we have 74 sources)
3. Is there a SIEM feature you'd like that isn't there yet?

Your feedback shapes what we build next.

[If health score < 40]:
I also noticed lower usage than typical. Is there a blocker I can help with?

[If health score >= 70]:
Everything looks great from my side. Let me know if you need anything.

— Bivash
```

---

## DAY 30 — HEALTH ASSESSMENT

**Trigger:** 30 days after key delivery

**Operator actions:**

```
[ ] Full health score calculation
[ ] Review: API call volume trend (up/flat/down?)
[ ] Review: SIEM integration status
[ ] Review: Support tickets (any unresolved?)
[ ] Send Day 30 email
[ ] For Enterprise/MSSP: prepare monthly briefing (see template)
[ ] For at-risk customers (score < 40): personal outreach + offer call
```

**Day 30 email:**
```
Subject: Your first month with SENTINEL APEX — summary + what's next

Hi [NAME],

One month in. Here's a summary of what's happened in your threat landscape:

CRITICAL THREATS THIS MONTH:
[Pull from platform: critical advisories in their sector]

HIGH-PRIORITY CVEs AFFECTING [THEIR_SECTOR]:
[Personalized: pull relevant CVEs based on their SIEM platform or sector]

YOUR USAGE SUMMARY:
- API calls made: [APPROX from audit log]
- Intelligence reports accessed: [APPROX]
- Detection rules downloaded: [APPROX]

NEXT STEPS I RECOMMEND FOR [COMPANY]:
1. [PERSONALIZED: specific integration suggestion]
2. [PERSONALIZED: detection rule to implement]
3. [PERSONALIZED: threat actor to watch]

Looking ahead:
The AI prediction engine is forecasting 87% probability of ransomware escalation
in the next 30 days. I'd recommend pulling the Sigma rules for the top 5
ransomware TTPs from the platform this week.

Any questions — I'm on WhatsApp.

— Bivash
```

---

## RENEWAL WORKFLOW

### Renewal Reminders (automated operator prompts)

| Trigger | Action |
|---------|--------|
| D-30 before expiry | Send renewal_d30.txt (template) |
| D-14 before expiry | Send renewal_d14.txt (template) |
| D-3 before expiry | Send renewal_d3.txt (final) + WhatsApp |
| D+0 (expiry) | Grace period begins (3 days for PRO, 3 days for ENT/MSSP) |
| D+3 | Key suspended — notify customer |
| D+7 | Key revoked if no renewal |

### Renewal Offer (for annual upsell at monthly renewal)

```
Subject: SENTINEL APEX renewal due — annual option saves ₹8,200

Hi [NAME],

Your subscription renews in [X] days.

Quick monthly renewal: https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?plan=[TIER]

OR switch to annual and save:
PRO Annual: ₹41,000/year (vs. ₹49,200 monthly) — save ₹8,200
Enterprise Annual: $4,990/year (vs. $5,988 monthly) — save $998
MSSP Annual: $19,990/year (vs. $23,988 monthly) — save $3,998

Annual customers get: 2 months free + priority support + quarterly briefing.

Let me know which you prefer — I'll update your key immediately.

— Bivash
```

---

## EXPANSION TRIGGERS

**Trigger: Customer has been active 60+ days, health score ≥ 70**

**PRO → Enterprise upsell:**
```
Subject: You're hitting API limits — Enterprise might be worth it

Hi [NAME],

I noticed you're consistently using most of your 5,000 daily API calls.

Enterprise gives you 50,000/day, plus SIEM webhook push for real-time delivery.
At $499/month (or $4,990/year), it's worth it once you're ingesting at scale.

Want to try Enterprise for 14 days to see if it makes a difference?
No payment needed for the trial — just reply and I'll switch your key.

— Bivash
```

**PRO → MSSP conversion (if customer is a security consultancy):**
```
Subject: Are you serving multiple clients? MSSP tier might save you money.

Hi [NAME],

If you're using SENTINEL APEX for multiple clients, our MSSP tier may be
more cost-effective:

MSSP: $1,999/month
- 500,000 API calls/day (covers all your clients)
- Sub-keys for each client (issued within 2 hours)
- White-label Intel Data
- Priority 2-hour support SLA

Break-even: If you have 5+ clients, MSSP costs less than 5× PRO subscriptions.

Worth a conversation? Let me know.

— Bivash
```

---

## CS METRICS TO TRACK

| Metric | Formula | Target |
|--------|---------|--------|
| Day 3 activation rate | Customers with ≥1 API call by Day 3 / all customers | >80% |
| Day 7 health score (avg) | Sum of scores / customer count | >60 |
| Day 30 retention rate | Active at Day 30 / activated | >90% |
| NPS (informal) | Reply sentiment to Day 30 email | Positive |
| Renewal rate | Renewals / due | >85% |
| Expansion rate | Upsells / customers at 60 days | >20% |
| Time to first API call | Avg hours from key delivery to first call | <4 hours |

---

*Customer Success Playbook v177 · SENTINEL APEX v177.0 · 2026-06-04*
