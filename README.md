# 🛡️ CYBERDUDEBIVASH® Sentinel APEX v11.0 — AI-Powered Threat Intelligence Platform

[![Pipeline Status](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/workflows/sentinel-blogger.yml/badge.svg)](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/Platform-Live-00d4aa.svg)](https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/)

> **Production-grade AI-powered threat intelligence platform** with automated multi-source ingestion, dynamic risk scoring, STIX 2.1 export, MITRE ATT&CK mapping, and real-time SOC dashboard.

## 🚀 What's New in v11.0 (APEX ULTRA)

| Feature | v10.1 | v11.0 ULTRA |
|---------|-------|-------------|
| **Risk Scoring** | Static 9.3 | Dynamic multi-factor (IOC, MITRE, CVSS, EPSS, Actor) |
| **Feed Sources** | Single RSS | Multi-feed fusion (6+ high-authority feeds) |
| **IOC Extraction** | IPv4, Domain, Registry | + SHA256, SHA1, MD5, URL, Email, CVE, Artifacts |
| **IOC Validation** | None | Private IP exclusion, false-positive domain filtering |
| **Deduplication** | None | Content-hash based dedup engine |
| **STIX Bundles** | intrusion-set only | Full: indicators, relationships, attack-patterns |
| **Manifest Schema** | 5 fields, 10 entries | 13 fields, 50 entries (severity, confidence, TLP, IOC counts) |
| **Confidence Scoring** | None | Weighted IOC confidence (0-100%) |
| **TLP Classification** | None | TLP:RED / AMBER / GREEN / CLEAR per advisory |
| **Detection Engineering** | Static Sigma | Auto-generated Sigma + YARA per campaign |
| **Dashboard** | Basic cards | Metrics strip, severity filtering, sorting, SOC exports |
| **Rate Limiting** | None | Configurable delay between API calls |

## 🏗️ Architecture

```
RSS Feeds (6+) → Multi-Feed Ingestion → Deduplication Engine
    ↓
IOC Extraction (Enhanced) → Confidence Scoring → Private IP Exclusion
    ↓
MITRE ATT&CK Mapping → Actor Attribution → Dynamic Risk Scoring
    ↓
Sigma/YARA Generation → Elite HTML Report → Blogger API Publish
    ↓
STIX 2.1 Bundle (Full Objects) → Manifest Sync → GitHub Pages Dashboard
```

## 📊 Live Dashboard

**[→ View Live Platform](https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/)**

Features:
- Real-time metrics strip (total advisories, critical count, avg risk)
- Severity-coded intelligence cards (CRITICAL/HIGH/MEDIUM/LOW)
- Client-side filtering and sorting
- SOC export (JSON, CSV, STIX bundle)
- TLP classification badges
- Manifest integrity verification
- GitHub stars counter

## ⚙️ Setup

### Prerequisites
- Python 3.12+
- Google Blogger API credentials
- GitHub repository with Actions enabled

### GitHub Secrets Required
```
BLOG_ID            - Blogger blog ID
REFRESH_TOKEN      - Google OAuth2 refresh token
CLIENT_ID          - Google OAuth2 client ID
CLIENT_SECRET      - Google OAuth2 client secret
VT_API_KEY         - VirusTotal API key (optional)
DISCORD_WEBHOOK    - Discord alert webhook (optional)
SLACK_WEBHOOK      - Slack alert webhook (optional)
```

### Local Development
```bash
pip install -r requirements.txt
python -m tests.verify_pipeline    # Run diagnostics
python -m agent.sentinel_blogger   # Run pipeline
```

## 📁 Project Structure

```
├── .github/workflows/         # GitHub Actions automation
├── agent/
│   ├── sentinel_blogger.py    # Main orchestrator (v11.0)
│   ├── config.py              # Global configuration + design system
│   ├── enricher.py            # Enhanced IOC extraction engine
│   ├── risk_engine.py         # Dynamic risk scoring (NEW)
│   ├── deduplication.py       # Intelligence dedup engine (NEW)
│   ├── export_stix.py         # STIX 2.1 exporter (expanded)
│   ├── mitre_mapper.py        # ATT&CK technique mapping
│   ├── analysis/              # Coverage gap analysis, CVE ranking
│   ├── content/               # Blog post generation
│   ├── formatter/             # Report formatters (daily, weekly, deep-dive)
│   ├── integrations/          # Actor matrix, detection engine, VT, vuln
│   ├── intel/                 # CVE, KEV, malware feeds
│   └── publishers/            # CVE deep-dive publisher
├── data/stix/                 # STIX bundles + feed manifest
├── index.html                 # Live dashboard (v11.0)
└── tests/                     # Pipeline diagnostics
```

## 📜 License

© 2026 CyberDudeBivash Pvt. Ltd. — All rights reserved.

---

**Built with precision by [CyberDudeBivash](https://www.cyberdudebivash.com) — Bhubaneswar, India**
