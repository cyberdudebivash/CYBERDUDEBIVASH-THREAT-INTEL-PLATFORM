# SENTINEL APEX — 30-Minute Enterprise Demo Script
## v185.0 · For: Fortune 500 SOC Directors, CISOs, Procurement Teams
---

## PRE-DEMO CHECKLIST (T-15 minutes)

- [ ] Dashboard loaded at `intel.cyberdudebivash.com` — confirm live feed active
- [ ] PDF report open (INTERPOL/LockBit or APT dossier with MITRE mapping)
- [ ] STIX 2.1 bundle downloaded and ready to paste into Sentinel / Splunk
- [ ] ROI calculator tab open at `/roi-calculator.html`
- [ ] Second monitor or tab showing pipeline health dashboard
- [ ] Mute notifications on all devices
- [ ] Screen at 1920×1080 minimum, browser zoom 100%

---

## SEGMENT 1: HOOK (0:00 – 3:00)

### Opening line (verbatim):
> "Before I show you the platform, I want to share one number: the average time between a ransomware group publishing a new IOC and an enterprise SOC ingesting it is 14 days. Our platform does it in under 6 hours — automatically. Let me show you how."

### What to show:
1. Open the live dashboard (`/`)
2. Point to the **BREAKING THREAT** ticker — highlight a real advisory from the last 24 hours
3. Click into one advisory to show the full dossier layout
4. Say: *"Every advisory you see here went through a 17-stage enrichment pipeline — MITRE mapping, CVSS/EPSS scoring, IOC extraction, and detection rule generation — all before it landed on your screen."*

### Objection pre-empt:
If they ask "Is this real data?" → *"Every advisory is sourced from live feeds: CISA KEV, NVD, NCSC, OSINT, and sector-specific intel. The STIX 2.1 export contains the source references."*

---

## SEGMENT 2: LIVE INTELLIGENCE WALKTHROUGH (3:00 – 10:00)

### 3:00 — Advisory detail view
- Open any HIGH or CRITICAL severity advisory
- Walk through each section: **Executive Summary → Threat Actor → MITRE ATT&CK Techniques → IOC Table → Detection Rules**
- **Key talking point**: *"Notice the MITRE techniques are clickable. Your SOC can pivot directly to the ATT&CK Navigator from here."*

### 5:00 — IOC Table
- Show the IOC table with OBSERVED vs AI-ENRICHED labels
- **Key talking point**: *"We distinguish between directly observed indicators and AI-inferred IOCs derived from campaign behavioral patterns. The AI-Enriched indicators are the leading edge — they give you predictive coverage before a threat actor publishes their next stage."*
- If they ask about quality: *"Our false-positive rate is monitored per pipeline run. The target is under 5%. Anything above triggers an automatic QC review."*

### 7:00 — Detection Rules (Sigma / KQL / Suricata)
- Expand the detection rules section
- Copy one Sigma rule — paste into a text editor to show real YAML
- **Key talking point**: *"Every advisory generates deployment-ready Sigma, KQL for Microsoft Sentinel, and Suricata rules. Your detection engineers don't write from scratch — they review and deploy. That alone saves 4–6 hours per advisory."*

### 9:00 — STIX 2.1 Export
- Download or show the STIX bundle link
- **Key talking point**: *"The STIX 2.1 bundle is TLP-classified, digitally signed, and ready for ingestion into your TAXII server, Splunk ES, QRadar, or Elastic SIEM. Zero custom integration required for standard platforms."*

---

## SEGMENT 3: API & INTEGRATION DEMO (10:00 – 16:00)

### 10:00 — API overview
- Open `/get-api-key.html`
- Show the endpoint catalog: `/api/feed.json`, `/api/advisories/`, `/api/iocs/`
- **Key talking point**: *"The API is RESTful, JSON-first, and returns structured STIX 2.1 objects. Enterprise tier gets 50,000 requests/day with SIEM webhook push — so instead of polling, your SIEM receives data the moment a new advisory is published."*

### 12:00 — SIEM webhook simulation
- If prepared: show a Splunk or Sentinel JSON alert that came from a webhook push
- If not: describe the flow: *"New advisory → pipeline validates → webhook fires to your SIEM endpoint → alert created in your queue in under 60 seconds."*
- **Key talking point for Splunk shops**: *"We ship a pre-built Splunk ES integration pack — Sigma rules auto-converted to SPL, correlation searches pre-configured, and the IOC lookup table auto-refreshed every 6 hours."*

### 14:00 — CVSS / EPSS Scoring
- Open an advisory showing EPSS score
- **Key talking point**: *"EPSS tells you the probability a CVE will be exploited in the next 30 days. Combined with your asset inventory, this is how you build a mathematically defensible patch priority queue instead of patching everything with CVSS > 7."*

---

## SEGMENT 4: ENTERPRISE DIFFERENTIATION (16:00 – 21:00)

### 16:00 — Platform scale proof points
- Return to homepage, scroll to the metrics strip
- Call out: **43,000+ intel reports · 74 live feeds · 24/7 pipeline**
- **Key talking point**: *"No analyst team generates this volume. This is the equivalent of a 40-person threat intelligence team running 24 hours a day — delivered as an API."*

### 18:00 — ROI Calculator
- Open `/roi-calculator.html`
- Enter their sector and team size if known, otherwise use defaults
- Show the output: prevented breach cost, analyst hours saved, detection coverage improvement
- **Key talking point**: *"One prevented breach at a Fortune 500 healthcare company costs on average $10.9M. Our annual Enterprise plan is $5,988. The math is simple — a single avoided incident delivers 1,800x ROI."*

### 20:00 — Compliance positioning
- Navigate to `/security-compliance.html`
- **Key talking point**: *"SENTINEL APEX output maps directly to NIST CSF 2.0 Identify and Detect functions, ISO 27001 Annex A.8, and SOC 2 Type II continuous monitoring requirements. Your next audit just got easier."*

---

## SEGMENT 5: MSSP / MULTI-TENANT (skip if not MSSP) (21:00 – 25:00)

### If talking to an MSSP:
- Open `/mssp-partner-portal.html`
- Show the tenant list — each client gets an isolated API key, white-labeled dashboard, and independent TLP controls
- **Key talking point**: *"You can provision a new client tenant in under 3 minutes. Each tenant gets scoped feeds, custom branding, and separate billing. You resell our intelligence under your brand with up to 25% revenue share — we handle infrastructure, pipeline, and uptime."*
- Show commission calculator if available, or state: *"If you manage 10 enterprise clients at $499/mo each, your partner commission is $1,247/month from day one."*

---

## SEGMENT 6: CLOSE & NEXT STEPS (25:00 – 30:00)

### 25:00 — Trial offer
- **Verbatim close**:
> "What I'd suggest is this: we spin up a 7-day PRO trial today — no credit card, no commitment. Your team runs it against a real investigation. If it saves two hours of analyst time in the first week, it pays for itself for the next six months. If it doesn't, you cancel and we part friends."

### 27:00 — Objection handling

| Objection | Response |
|-----------|----------|
| "We already have [Mandiant/Recorded Future]" | "We're not replacing strategic intelligence. We're the operational layer — real-time IOCs and deploy-ready detection rules that plug directly into your SIEM. Most teams run both." |
| "We need procurement approval" | "I can provide a formal quote with GST invoice on the same call. Enterprise plans include net-30 invoice billing. I'll send the security assessment package today so your InfoSec team can review in parallel." |
| "Our SIEM team needs to evaluate the API" | "I'll generate a read-only trial API key right now. Endpoints are documented at `/get-api-key.html`. Your team can test integration this afternoon." |
| "Price is too high" | "Enterprise is $499/month — $5,988/year. If your team spends 2 hours/week on manual IOC research, you're spending more than that in analyst salary. Plus we offer annual billing at $399/month, which brings the total to $4,788/year." |
| "What's your uptime SLA?" | "99.9% uptime, contractually backed. Pipeline runs every 6 hours with automated health checks. Critical alerts push via webhook in under 60 seconds. Status page is public." |

### 29:00 — Commit to a next step (always get one)
- Option A: "Start 7-day trial today — I'll send the link and onboarding docs in the next 10 minutes."
- Option B: "Let me send the security questionnaire pack and technical integration spec. Can we schedule a follow-up for Thursday to answer your team's questions?"
- Option C (MSSP): "I'll send the MSSP partner agreement. Once signed, we can provision your white-label environment within 24 hours."

---

## POST-DEMO SEND PACKAGE (send within 1 hour)

1. **One-pager PDF** — key metrics, pricing, integration list
2. **Security questionnaire pre-fill** — SOC 2, GDPR, data residency answers
3. **Sample STIX 2.1 bundle** — from a recent advisory (TLP:GREEN)
4. **Sample Sigma rules pack** — 3 rules from active campaigns
5. **ROI model spreadsheet** — customized to their sector
6. **Enterprise pricing quote** — PDF with GST invoice capability noted
7. **WhatsApp follow-up** — +91 8179881447 within 2 hours of demo

---

## YOUTUBE RECORDING NOTES (for 4K demo video)

**Optimal flow for recording (compress to 12 minutes):**
- Segments 1 → 2 → 3 → 6 (skip MSSP unless MSSP-targeted video)
- Narrate in English with subtitle track
- Highlight cursor on key elements — use cursor highlighter tool
- Show real data (redact client tenant names if visible)
- End with clear CTA: "Start your free trial at intel.cyberdudebivash.com"
- Thumbnail: MITRE ATT&CK matrix with red nodes + platform branding

**Target publish: within 7 days of this audit**
- Title: "Live Demo: AI Threat Intelligence Platform for Enterprise SOC | SENTINEL APEX"
- Description: mention STIX 2.1, MITRE ATT&CK v15, Sigma rules, Fortune 500, MSSP
- Pin in playlist: "Product Demos"

---

*SENTINEL APEX v185.0 · Enterprise Demo Script · Last updated: 2026-06-22*
*Contact: enterprise@cyberdudebivash.com · WhatsApp: +91 8179881447*
