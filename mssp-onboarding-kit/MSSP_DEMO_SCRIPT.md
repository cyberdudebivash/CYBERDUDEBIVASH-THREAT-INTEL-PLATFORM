# MSSP DEMO SCRIPT
## SENTINEL APEX v177.0 — 30-Minute MSSP Discovery & Demo
**Version:** 1.0 | **Date:** 2026-06-04

---

## PRE-CALL PREP (5 min before call)

```
[ ] Open intel.cyberdudebivash.com — dashboard live
[ ] Note today's critical/high advisories (for live demo)
[ ] Check feed sync status (API: LIVE badge visible)
[ ] Have MSSP agreement template ready to share screen
[ ] Know prospect's SIEM platform (from inquiry form)
[ ] Know prospect's estimated client count
```

---

## MINUTE 0-5: OPENER & QUALIFICATION

**Script:**
"Thanks for jumping on a call, [NAME]. I'm Bivash — I run SENTINEL APEX.

I saw you manage [X] clients — before I show you the platform, can I ask two quick questions to make sure the demo is relevant?

1. What SIEM platforms are your clients using? [Note: Splunk/Sentinel/QRadar/Elastic/Other]
2. What's your current CTI workflow? Are you pulling intelligence manually, or do you have a feed already?

[Listen — understand their pain. Note: manual research = strong pain. Existing feed = differentiation play.]

Great. Let me show you how SENTINEL APEX solves [their specific pain]."

---

## MINUTE 5-15: LIVE PLATFORM DEMO

### Step 1 — Live Feed (2 min)
"This is the live dashboard. Right now we have [X] advisories.
[Point to critical/high count]

The top-left ticker shows live attacks globally — just context for the client.
The important part is this feed. Let me pull up a CRITICAL advisory."

**[Click a CRITICAL advisory from today's feed]**

"Here's the [CISCO_CVE or VSCODEZERODAY] advisory. Score 9.0/10, public exploit code.
On the free tier — this is all a visitor sees [show the truncated version].
On PRO/Enterprise — which is what your master key gives you — here's the full 20-section report."

**[Demo full PRO report if logged in, or describe sections]**

"Every advisory has:
- Executive summary — CEO/CISO level, 3 bullet points
- Technical analysis — full vulnerability breakdown
- MITRE ATT&CK mapping — 15 techniques mapped
- IOC table — 20+ indicators ready to import
- Sigma/YARA/Snort rules — ready for [THEIR_CLIENTS_SIEM]
- Kill chain analysis
- Financial impact
- Regulatory compliance mapping

This is what you deliver to each client. Your branding, their SIEM."

### Step 2 — SIEM Integration (3 min)
"The integration takes 30 seconds. Here's the API endpoint:

```
GET https://intel.cyberdudebivash.com/api/feed
Header: X-API-Key: [DEMO_KEY]
```

For [THEIR_SIEM] specifically:
[Splunk]: You add this URL to your Splunk HTTP Event Collector
[Sentinel]: You use the TAXII connector — I'll send you the connector config
[QRadar]: You use the reference data import with this endpoint
[Elastic]: Filebeat module, 2-line config

Your clients can be ingesting this in under 5 minutes. I'll walk you through it personally on the onboarding call."

### Step 3 — MSSP Differentiators (3 min)
"What makes the MSSP tier different for your operation:

1. **500,000 API calls/day** — your master key covers all clients. One key, unlimited clients.

2. **Sub-keys** — for clients who need direct integration, I provision a dedicated key per client within 2 hours. You request by email.

3. **White-label** — you deliver this as '[YOUR COMPANY] Threat Intelligence'. Your brand, your client relationship, our intelligence engine.

4. **2-hour P0 support** — if your master key breaks or a client can't connect, I respond within 2 hours, 24x7. On WhatsApp.

5. **Actor intelligence** — we track named APT clusters: APT-29 (Cozy Bear), APT-22, FIN-11, TA-01. When one of these actors is active, you know before your clients' firewalls do.

Right now the AI engine shows 87% probability of ransomware escalation in the next 30 days. Your clients get that forecast automatically."

### Step 4 — Pricing (2 min)
"Pricing is simple.

MSSP tier: $1,999/month or $19,990/year.

Break-even: If you bill 4 clients $500/month for CTI as a service, you're already profitable.
At 10 clients at $200/month each, you make $2,001/month net on the intelligence layer alone.

No per-client licensing. No seat limits. Unlimited sub-keys.

The only thing I ask is you don't share the master key directly with clients — they get sub-keys."

---

## MINUTE 15-22: Q&A & OBJECTION HANDLING

### Common Objections

**"We already have a CTI feed"**
"What are you using? [Listen]
Most of what SENTINEL APEX delivers — the actor attribution, kill chains, Sigma rules, AI predictions — isn't available in commodity feeds. We process 74 sources with our own risk scoring engine.
What would be most useful to compare? I can pull a live advisory on whatever your current feed covers."

**"It's too expensive for our small client base"**
"How many clients are you currently managing?
Even at 2 clients, $1,999/month for a master key works if each client pays $1,000+/month.
At 3 clients, break-even drops to $667/client.
You can also start with a 14-day trial at no cost — see what your clients say before committing."

**"We need SOC 2 before we can use this"**
"Understood. SOC 2 is on our roadmap for Q4 2026.
In the meantime, I can provide: security questionnaire responses, DPA, MSA, and GSTIN.
Many MSSP clients are comfortable with our security posture for an intelligence layer — it's not touching their internal systems.
Would a 14-day trial help you evaluate the risk independently?"

**"Can I have a white-label branded platform?"**
"You can white-label the intelligence output — reports, briefings, STIX bundles. Your clients see your brand.
A dedicated white-label portal (custom subdomain, your logo) is on the v178 roadmap in Q3 2026.
For now, the intelligence is white-labelable; the portal URL would be intel.cyberdudebivash.com."

**"How do we know the feed quality is reliable?"**
"Fair question. Everything comes from verified sources: CISA KEV, NIST NVD, GitHub Security Advisories, BleepingComputer, SecurityAffairs, Vulners.
CISA KEV means everything in the Known Exploited Vulnerabilities catalog is in our feed — that's as reliable as it gets.
MITRE ATT&CK v15 is the world standard for technique mapping.
You can audit any advisory by checking the source URL — every record has one."

---

## MINUTE 22-28: NEXT STEPS

**Script:**
"Here's what I'd suggest as next steps:

1. I'll send you the MSSP agreement — takes 5 minutes to review. No lawyer needed, it's written in plain English.

2. I'll activate a 14-day MSSP trial key. No payment, no commitment. Your master key works exactly like the paid version.

3. You connect it to your test SIEM environment — I'll walk you through it on a 30-minute onboarding call this week.

4. If it works for your clients, you pay. If not, you walk away. No hard sell.

Does that work for you?"

**[Get confirmation on:]**
- [ ] Agreement: OK to send?
- [ ] Trial: Activate? Get their email confirmed.
- [ ] Onboarding call: Best time this week?

---

## MINUTE 28-30: CLOSE

"I'll send the agreement and trial key within 2 hours of this call.

One thing I want you to know: I run this personally. When you WhatsApp me, I respond. When your client has a P0 issue at 2am, I'm on it.

MSSP partners aren't just a revenue line for me — I want you to be able to sell CTI confidently because your intelligence actually works.

Looking forward to it. Talk soon."

---

## POST-CALL CHECKLIST (within 2 hours)

```
[ ] Send MSSP agreement (MSSP_AGREEMENT_TEMPLATE.md as PDF)
[ ] Activate 14-day MSSP trial key:
    python generate_key.py generate --tier mssp --email [EMAIL] --ref MSSP-[DATE]-[ID] --days 14
[ ] Send trial activation email (templates/email/08_mssp_welcome.txt, personalized)
[ ] Book onboarding call (within this week)
[ ] Add to data/mssp/partners.json: status = "trial"
[ ] Add to data/leads/pipeline.json: status = "trial", converted_tier = "MSSP"
```

---

*MSSP Demo Script v1.0 · SENTINEL APEX v177.0 · 2026-06-04*
