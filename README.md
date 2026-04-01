# CYBERDUDEBIVASH® Sentinel APEX
## AI-Powered Cybersecurity Threat Intelligence Platform

[![Platform](https://img.shields.io/badge/Status-LIVE-00e676?style=for-the-badge)](https://intel.cyberdudebivash.com)
[![API](https://img.shields.io/badge/REST_API-Production-00e5ff?style=for-the-badge&logo=fastapi)](https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/docs)
[![Advisories](https://img.shields.io/badge/Advisories-500%2B-ff1744?style=for-the-badge)](https://intel.cyberdudebivash.com)
[![STIX](https://img.shields.io/badge/STIX-2.1_Compliant-b975ff?style=for-the-badge)](https://oasis-open.github.io/cti-documentation/)
[![Telegram](https://img.shields.io/badge/Telegram-Alerts-0088cc?style=for-the-badge&logo=telegram)](https://t.me/cyberdudebivashSentinelApex)
[![License](https://img.shields.io/badge/License-Proprietary-aaaaaa?style=for-the-badge)](https://cyberdudebivash.com)

> **Real-time AI threat intelligence with APEX AI enrichment, automated SOC response, and STIX 2.1 export. Free tier available — no signup required.**

---

## 🔴 Live Platform

| Resource | URL |
|----------|-----|
| 🌐 **Live Dashboard** | [intel.cyberdudebivash.com](https://intel.cyberdudebivash.com) |
| 📡 **Production API** | [Railway — FastAPI](https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/docs) |
| 💰 **Pricing** | [Free / Pro / Enterprise / MSSP](https://intel.cyberdudebivash.com/landing/pricing.html) |
| 📱 **Telegram Alerts** | [t.me/cyberdudebivashSentinelApex](https://t.me/cyberdudebivashSentinelApex) |
| 🛒 **Store** | [https://tools.cyberdudebivash.com/](https://tools.cyberdudebivash.com/) |
| 📝 **Blog** | [blog.cyberdudebivash.com](https://blog.cyberdudebivash.com) |

---

## ⚡ Quick Start — Free Tier (No Signup Required)

```bash
# Get latest threat advisories — zero auth needed
curl https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/v1/intel/latest

# Pro tier — 100 advisories + full APEX AI enrichment
curl -H "X-API-Key: cdb_pro_YOUR_KEY" \
     https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/v1/intel/feed?limit=100

# Available API tiers + pricing
curl https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/v1/tiers

# Onboarding guide
curl https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/v1/onboard
```

---

## 🧠 APEX AI Intelligence Engine — 12 Engines Active

| Engine | Function | Output |
|--------|----------|--------|
| 🎯 **Triage Engine** | P1/P2/P3/P4 SOC priority classification | `apex.priority` |
| 📊 **Predictive Engine** | Attack prediction + probability scoring | `apex.predictive_score` |
| 🗺 **Campaign Tracker** | Deterministic campaign ID + attribution | `apex.campaign_id` |
| 🔬 **Malware Classifier** | Family attribution (Ransomware, RAT...) | `apex.threat_category` |
| 🛡 **Vulnerability Analyst** | CVSS/EPSS/KEV cross-correlation | `apex.risk_factors` |
| ⚡ **Attribution Engine** | Threat actor cluster identification | `apex.behavioral_tags` |
| 🔗 **Supply Chain Detector** | Supply chain compromise signal | `apex.supply_chain_risk` |
| 🧬 **Quantum Risk Assessor** | Post-quantum cryptography exposure | `apex.quantum_risk` |
| 🎭 **Social Eng. Scorer** | Phishing/BEC signal extraction | `apex.social_eng_risk` |
| 🌐 **Correlation Engine** | Cross-advisory threat cluster linking | `apex.ai_summary` |
| 🚨 **Alert Dispatcher** | P1 Telegram + webhook real-time alerts | Alert Engine |
| 🤖 **SOC Response Bot** | Auto firewall block + SOC ticket | Response Engine |

### APEX Enrichment — Live API Response

```json
{
  "title": "CVE-2025-53521 — F5 BIG-IP APM RCE (KEV Confirmed)",
  "risk_score": 10.0,
  "severity": "CRITICAL",
  "kev_present": true,
  "cvss_score": 9.8,
  "epss_score": 26.61,
  "mitre_tactics": ["T1190", "T1059", "T1486"],
  "ioc_counts": {"ipv4": 3, "domain": 5, "sha256": 2, "url": 4},
  "apex": {
    "priority":           "P1",
    "threat_level":       "CRITICAL_SURGE",
    "predictive_score":   9.8,
    "campaign_id":        "CDB-CAMP-A1B2C3D4",
    "threat_category":    "SUPPLY_CHAIN",
    "behavioral_tags":    ["P1_CRITICAL", "SUPPLY_CHAIN", "CRITICAL_SURGE"],
    "ai_summary":         "APEX SOC classified as P1 — immediate response required",
    "recommended_action": "PATCH NOW — P1 critical, SLA 15 minutes, KEV-confirmed exploit"
  }
}
```

---

## 🏗 Platform Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  10+ DATA SOURCES (every 6 hours)                                │
│  CVEfeed · CISA KEV · NVD · BleepingComputer · THN · Krebs     │
└─────────────────────┬────────────────────────────────────────────┘
                      │  GitHub Actions Pipeline
                      ▼
┌──────────────────────────────────────────────────────────────────┐
│  PIPELINE  (sentinel_blogger.py)                                 │
│  ① Fetch + Dedup  ② NVD/EPSS Enrich  ③ VANGUARD IOC           │
│  ④ APEX AI (12 engines)  ⑤ STIX 2.1 Export  ⑥ Blog Publish   │
│  ⑦ Alert Engine → Telegram/Webhook                              │
│  ⑧ Response Engine → Firewall Block + SOC Ticket               │
│  ⑨ Growth Engine → SEO Posts + LinkedIn + Telegram Content     │
└─────────────────────┬────────────────────────────────────────────┘
                      ▼
┌────────────┬────────────┬──────────┬──────────┬─────────────────┐
│ Dashboard  │  REST API  │   Blog   │ Telegram │ SEO Posts       │
│(GitHub PG) │ (Railway)  │(Blogger) │ Alerts   │(data/growth/)   │
└────────────┴────────────┴──────────┴──────────┴─────────────────┘
```

---

## 💰 Pricing

| Plan | Price (USD) | Price (INR) | Rate Limit | Advisories | APEX AI |
|------|-------------|-------------|-----------|------------|---------|
| **Free** | $0/mo | ₹0 | 60 req/hr | 10/req | ✗ |
| **Pro** | $49/mo | ₹4,099 | 1,000 req/hr | 100/req | ✅ Full |
| **Enterprise** | $499/mo | ₹41,599 | 10,000 req/hr | 500/req | ✅ + Bulk |
| **MSSP** | $1,999/mo | ₹1,66,599 | Unlimited | 500/req | ✅ + White-label |

Payment: **Stripe** (international) + **Razorpay** (India/INR) + **Gumroad** (add-ons)

**[→ Get API Access](https://intel.cyberdudebivash.com/landing/pricing.html)**

---

## 📡 API Reference

```
GET  /api/v1/intel/latest          # Latest advisories (free, no key)
GET  /api/v1/intel/feed            # Full paginated feed (Pro+)
GET  /api/v1/intel/search?q=CVE    # Full-text search (Pro+)
GET  /api/v1/intel/by-id/{id}      # Single advisory by STIX ID
GET  /api/v1/stats                 # Platform statistics + APEX metrics
GET  /api/v1/health                # API health check
GET  /api/v1/tiers                 # Pricing tiers info
GET  /api/v1/onboard               # Onboarding quick-start guide
POST /api/v1/subscribe             # Create Stripe/Razorpay checkout session
POST /api/v1/webhooks/stripe       # Stripe webhook (auto key provisioning)
POST /api/v1/webhooks/razorpay     # Razorpay webhook (auto key provisioning)
```

---

## 🔧 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Pipeline** | Python 3.12, GitHub Actions (6h cron) |
| **API** | FastAPI, Uvicorn, Railway (production) |
| **Dashboard** | GitHub Pages, Vanilla JS, STIX 2.1 |
| **AI Engines** | 12 custom Python engines (no LLM dependency) |
| **Storage** | JSON manifests + STIX 2.1 bundles (git-tracked) |
| **Alerts** | Telegram Bot API (P1/CRITICAL threshold) |
| **Payments** | Stripe + Razorpay + Gumroad (fallback) |
| **Email** | SendGrid (API key welcome emails) |
| **Growth** | SEO blog generator + LinkedIn + Telegram content |

---

## 📁 Repository Structure

```
├── agent/                       # Core pipeline agents
│   ├── sentinel_blogger.py      # Main pipeline orchestrator (13 stages)
│   ├── apex_injector.py         # 12-engine APEX AI enrichment
│   ├── alert_engine.py          # Real-time P1 alert engine
│   ├── response_engine.py       # Auto-response SOC engine
│   ├── auto_response/           # Firewall + SOC ticket responders
│   └── monetization/            # API key manager + payment gateway
├── api/
│   └── main.py                  # FastAPI — all endpoints
├── data/
│   ├── stix/feed_manifest.json  # 500-entry live manifest
│   ├── stix/CDB-APEX-*.json     # STIX 2.1 bundles w/ x-cdb-apex-1
│   ├── alerts/alert_state.json  # Alert dedup state (TTL=24h)
│   ├── auto_response/           # Blocked IPs + SOC tickets
│   ├── monetization/            # API keys + payment events
│   └── growth/                  # SEO posts + LinkedIn + Telegram state
├── landing/                     # SaaS frontend (static)
│   ├── index.html               # Landing page (SEO optimised)
│   ├── pricing.html             # Pricing page (Stripe + Razorpay)
│   └── dashboard.html           # Client dashboard (live intel)
├── scripts/
│   ├── pre_deploy_gate.py       # 8-check pre-deploy gate
│   ├── apex_manifest_patcher.py # Backfill APEX into manifest
│   └── growth/                  # Growth engine scripts
│       ├── seo_blog_generator.py       # Daily SEO CVE posts
│       ├── telegram_content_generator.py # Telegram roundup/spotlight
│       └── linkedin_content_generator.py # LinkedIn authority posts
└── .github/workflows/
    └── sentinel-blogger.yml     # CI/CD pipeline (9 stages)
```

---

## 🔍 SEO Keywords

`threat intelligence platform` · `cybersecurity API 2026` · `CVE analysis real-time` ·
`CISA KEV tracker` · `STIX 2.1 API` · `SOC automation platform` · `SOAR integration` ·
`IOC threat feeds` · `APEX AI cybersecurity` · `critical vulnerability alerts` ·
`cybersecurity SaaS` · `MSSP threat intelligence` · `MITRE ATT&CK mapping API` ·
`automated threat response` · `ransomware detection API` · `supply chain threat intel`

---

## 📄 License & Contact

© 2026 **CyberDudeBivash Pvt. Ltd.** All Rights Reserved.
Platform intelligence is for defensive cybersecurity use only.

| | |
|-|-|
| 🌐 Dashboard | [intel.cyberdudebivash.com](https://intel.cyberdudebivash.com) |
| 📖 API Docs | [Railway API](https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/docs) |
| 📱 Telegram | [t.me/cyberdudebivashSentinelApex](https://t.me/cyberdudebivashSentinelApex) |
| 💰 Pricing | [Get API Access](https://intel.cyberdudebivash.com/landing/pricing.html) |
| ✉️ Contact | [bivash@cyberdudebivash.com](mailto:bivash@cyberdudebivash.com) |
