# LinkedIn Launch Post — SENTINEL APEX

## POST VERSION A (Technical — SOC/Detection Engineers)

I just opened up free API access to SENTINEL APEX — the real-time threat intelligence platform I've been building.

What it delivers:
→ IOC feeds (IP, hash, domain, CVE) updated every 4 hours
→ STIX 2.1 structured bundles — import directly into your TIP/SIEM
→ MITRE ATT&CK mapping per indicator (technique + tactic)
→ CISA KEV cross-reference — is this CVE actively exploited right now?
→ EPSS scoring — exploitation probability per vulnerability
→ REST API with JWT auth — integrate in under 10 minutes

Free tier: 60 req/min · 20 threat reports · No credit card
Pro tier ($49/mo): Full IOC arrays · Unlimited reports · STIX 2.1 bundles

Live dashboard + free API key:
👉 https://intel.cyberdudebivash.com

If you're a SOC analyst, threat hunter, or detection engineer — would love your feedback. Built this to solve the problem of fragmented, unstructured threat feeds that don't map to ATT&CK or CISA KEV automatically.

#ThreatIntelligence #SOC #CyberSecurity #STIX #MITREATTACK #ThreatHunting #BlueTeam #APIFirst

---

## POST VERSION B (Business — CISO/Security Leaders)

Most threat intel feeds give you raw IOCs with no context.

SENTINEL APEX gives you:
✓ Is this CVE in CISA's Known Exploited Vulnerabilities list?
✓ What ATT&CK technique does this malware use?
✓ What's the exploitation probability? (EPSS score)
✓ Which kill chain stage is this indicator targeting?
✓ STIX 2.1 bundle — ready for SIEM ingestion

We built a fully automated intelligence pipeline that runs every 4 hours, classifies threats across 12 categories (Ransomware, APT, Vulnerability, etc.), and serves everything via a clean REST API.

Enterprise tier includes native SIEM push to Splunk HEC, Azure Sentinel, and QRadar.

Free tier available — no credit card required.

Pricing: $0 · $49/mo · $149/mo · Enterprise custom
👉 https://intel.cyberdudebivash.com/pricing.html

If your team is manually enriching IOCs or struggling with unstructured feeds — this was built for you.

DM me or apply directly for an enterprise trial.

#CyberSecurity #ThreatIntelligence #CISO #SecurityOperations #SOC #SIEM #Enterprise

---

## POST VERSION C (Announcement — Community/Personal Brand)

Something I've been heads-down building for months: SENTINEL APEX is now live and open for business.

It's a threat intelligence API platform that aggregates data from 12+ sources (NVD, CISA KEV, threat feeds), enriches everything with MITRE ATT&CK mapping and EPSS scoring, and delivers STIX 2.1 structured data via REST API.

The goal: give security teams structured, actionable intelligence — not just raw IOC lists.

I'm opening up:
• Free tier — available right now, no card needed
• Pro tier — $49/month, full IOC arrays + STIX bundles
• Enterprise — SIEM push integration, custom pricing

If you work in security (blue team, CTI, detection engineering, MSSP) — I'd love for you to try it and tell me what you think.

Live at 👉 https://intel.cyberdudebivash.com
Get API key 👉 https://intel.cyberdudebivash.com/get-api-key.html

Thank you to everyone who's supported CYBERDUDEBIVASH along the way. Now let's go earn.

#CyberSecurity #ThreatIntelligence #BuildInPublic #StartupIndia #CyberDudeBivash

---

## FOLLOW-UP COMMENT (Post this as first comment on your own post — boosts reach)

Quick context on the tech stack for those interested:

• Data pipeline: Python + GitHub Actions (runs every 4 hours)
• Edge gateway: Cloudflare Workers (global CDN, sub-10ms latency)
• Auth: JWT with API key management
• Storage: Cloudflare KV + R2
• Format: STIX 2.1, JSON REST, TAXII-compatible

Free tier is genuinely free — same data, just rate-limited and capped at 20 reports. Pro unlocks the full IOC arrays and STIX bundles.

The SIEM push (Enterprise) was the hardest part to build — native Splunk HEC, Azure Log Analytics, and QRadar LEEF without middleware.

Happy to answer technical questions below 👇

---

## DM FOLLOW-UP TEMPLATE (For connections who like/comment on the post)

Hi [Name], thanks for engaging with the SENTINEL APEX post!

Quick question — what does your current threat intel workflow look like? 

Specifically curious whether you're:
a) Manually looking up IOCs during incident response
b) Using an existing feed (AlienVault OTX, VirusTotal, etc.)
c) Building your own pipeline

Asking because APEX might genuinely save your team time depending on the answer. Happy to share a Pro API key for free evaluation if useful.

—Bivash
