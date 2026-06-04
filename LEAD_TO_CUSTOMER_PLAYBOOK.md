# LEAD TO CUSTOMER PLAYBOOK
## SENTINEL APEX v177.0 — First Customer Conversion Engine
**Version:** 1.0 | **Date:** 2026-06-04

---

## OVERVIEW

This playbook converts platform visitors into paying customers. Every step is operator-executable today with zero additional tooling.

**Conversion Target:** 15% trial-to-paid rate. 7-day average lead-to-close.

---

## STAGE 1 — LEAD CAPTURE

**Trigger:** Visitor sees "🔒 UPGRADE FOR FULL REPORT" on any intel advisory.

**Conversion path:**
1. Visitor clicks upgrade CTA
2. Redirected to `lead-capture.html`
3. Form captures: name, email, company, use case, SIEM platform, org size
4. Reference ID generated: `LC-YYYYMMDD-XXXX`
5. Formspree sends structured submission to operator email
6. Operator adds lead to `data/leads/pipeline.json`

**Lead scoring (auto-calculate on receipt):**
```
Uses SIEM:                +25 points
Org size 251+:            +20 points
Org size 51-250:          +10 points
SOC/Threat Hunting:       +20 points
Financial/Gov/Healthcare: +15 points
Phone provided:           +10 points
Enterprise email domain:  +10 points
MAX SCORE:                 100 points
Qualify threshold:         >= 40
```

**Operator action (within 4 hours of submission):**
- Score the lead
- Score >= 40: Proceed to Stage 2
- Score < 40: Add to newsletter, send platform overview email

---

## STAGE 2 — QUALIFICATION & OUTREACH

**Trigger:** Lead score >= 40

**Personalized outreach email (send within 4 hours):**
```
Subject: Your SENTINEL APEX access is ready — [COMPANY NAME]

Hi [NAME],

Thanks for your interest in SENTINEL APEX.

I'm Bivash — I run the platform.

Based on your use case ([USE_CASE]), here's what will be most relevant for you:

[If SOC/SIEM]:
Our PRO tier gives you:
• Full IOC lists for every advisory (locked on free tier)
• Sigma/YARA/Snort detection rules — ready to import to [THEIR_SIEM]
• Kill chain analysis + actor attribution
• STIX 2.1 bundles for automated ingestion
• 30-day exploitation forecasts
All for ₹4,100/month (cancel anytime, no setup fee).

[If Enterprise/Large org]:
Our Enterprise tier adds:
• 50,000 API calls/day
• SIEM webhook push (real-time)
• Custom briefings
• Priority 4-hour support SLA
At $499/month or $4,990/year.

I'd like to give you a 7-day trial so you can test the API and see the full reports.

To activate your trial:
1. Reply to this email confirming your company domain
2. I'll provision a TRIAL key within 2 hours
3. You get full PRO access for 7 days — no payment required

Sound good?

— Bivash
bivash@cyberdudebivash.com | +91 8179881447
intel.cyberdudebivash.com
```

---

## STAGE 3 — TRIAL ACTIVATION

**Trigger:** Lead responds positively to outreach

**Operator steps:**
```bash
# Generate 7-day TRIAL key
python agent/tools/generate_key.py generate \
  --tier trial \
  --email [LEAD_EMAIL] \
  --ref [LEAD_ID] \
  --days 7

# Update lead status in pipeline.json:
# status: "trial"
# trial_key: [KEY_PREFIX]
# updated_at: [NOW]
```

**Trial activation email:**
```
Subject: Your SENTINEL APEX Trial Key — [LC-XXXXXXXX]

Hi [NAME],

Your 7-day SENTINEL APEX trial is active.

Your API Key: [SA-TRIAL-XXXXXXXXXXXXXXXXXX]
Expires: [DATE]
Reference: [LC-YYYYMMDD-XXXX]

Quick Start (5 minutes):
https://intel.cyberdudebivash.com/docs/quickstart.html

What you can do right now:
1. Make your first API call (see quickstart)
2. Download STIX 2.1 bundles for the Cisco CVE advisory
3. Import detection rules into [THEIR_SIEM]
4. Access full IOC tables for any advisory

If you need help connecting to [SIEM], reply to this email and I'll
walk you through it personally.

— Bivash
```

---

## STAGE 4 — TRIAL ACTIVATION REVIEW (Day 3)

**Trigger:** 3 days after trial key issued

**Check:** Has the customer made API calls?
```bash
# Check key activity in active_keys.json / audit.log
grep "[TRIAL_KEY_HASH]" data/keys/audit.log
```

**If NO API calls made:**
```
Subject: Did you get your first API call working?

Hi [NAME],

I noticed you haven't connected yet — happy to help.

Most common issue: headers.

Here's the exact curl command for your API key:
curl -H "X-API-Key: [THEIR_KEY]" https://intel.cyberdudebivash.com/api/feed

Takes 30 seconds. Want me to help you get it into [THEIR_SIEM]?

— Bivash
```

**If YES API calls made:**
```
Subject: Great start! Here's what else you can do

Hi [NAME],

Saw you've been using the API — great.

Two things worth trying before your trial ends in 4 days:

1. STIX 2.1 bundles — each advisory has a full STIX bundle
   for automated ingestion into OpenCTI / MISP / Sentinel:
   https://intel.cyberdudebivash.com/api/stix/[INTEL_ID]

2. Sigma detection rules — every HIGH/CRITICAL advisory
   has a Sigma rule you can import directly to [THEIR_SIEM]

Want me to pull the detection rules for the Cisco Unified CM
critical CVE from today's feed? Just reply and I'll send them over.

— Bivash
```

---

## STAGE 5 — CONVERSION OFFER (Day 6)

**Trigger:** 6 days after trial key issued (1 day before expiry)

```
Subject: Your trial ends tomorrow — continue for ₹4,100/month

Hi [NAME],

Your 7-day trial ends tomorrow.

If SENTINEL APEX has been useful, here's how to continue:

Option A — PRO Monthly: ₹4,100/month
→ https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?plan=pro&ref=[LEAD_ID]

Option B — PRO Annual: ₹41,000/year (save ₹8,200)
→ https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?plan=pro&billing=annual&ref=[LEAD_ID]

Option C — Enterprise: $499/month (50,000 API calls/day, SIEM webhook, 4-hour SLA)
→ https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?plan=enterprise&ref=[LEAD_ID]

No hidden fees. Cancel any time. Instant key extension.

After payment:
1. Pay via UPI/PayPal/NEFT/Crypto
2. Submit reference ID at intel.cyberdudebivash.com/customer-intake.html
3. Your key is extended within 4 hours

Any questions? Reply here or WhatsApp: +91 8179881447

— Bivash
```

---

## STAGE 6 — POST-TRIAL FOLLOW-UP (Day 8+)

**If no conversion:**
```
Subject: SENTINEL APEX — what held you back?

Hi [NAME],

Your trial ended 2 days ago. I'd love to know what happened.

A few possibilities:
• Budget approval pending? (I can do monthly — ₹4,100 is ~$49)
• Technical blocker? (I'll solve it personally)
• Waiting for a colleague's input? (I can join a 20-min call)
• The platform wasn't the right fit? (Genuinely useful feedback)

Reply with one line and I'll respond within the hour.

No hard sell — I just want to make sure it's not a fixable issue.

— Bivash
```

**If conversion:**
→ Proceed to Customer Success Playbook (Day 0)
→ Update `data/leads/pipeline.json`: status = "paying"
→ Update `data/customers/active.json`

---

## CONVERSION METRICS TO TRACK

| Metric | Formula | Target |
|--------|---------|--------|
| Lead capture rate | Leads / page views | >5% |
| Contact rate | Outreach sent / leads | 100% |
| Trial activation rate | Trials / qualified leads | >50% |
| Trial-to-paid rate | Paid / trials | >15% |
| Time to first API call | Trial start → first call | <10 min |
| Time to close | Lead date → payment date | <7 days |
| ARPU | MRR / paying customers | ₹4,100+ |

---

*Lead to Customer Playbook v1.0 · SENTINEL APEX v177.0 · 2026-06-04*
