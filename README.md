# 🛡️ CYBERDUDEBIVASH® Sentinel APEX v11.5 — AI-Powered Threat Intelligence Platform

[![Pipeline Status](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/workflows/sentinel-blogger.yml/badge.svg)](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE.txt)
[![Platform](https://img.shields.io/badge/Platform-Live-00d4aa.svg)](https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/)

> **Production-grade AI-powered threat intelligence platform** with automated multi-source ingestion, dynamic risk scoring, STIX 2.1 export, MITRE ATT&CK mapping, **premium 16-section report generation (2500+ words)**, and real-time SOC dashboard.

## 🚀 What's New in v11.5 (PREMIUM REPORT ENGINE)

| Feature | v11.0 | v11.5 PREMIUM |
|---------|-------|---------------|
| **Report Format** | 5-section thin template (~200 words) | **16-section premium template (2500+ words)** |
| **Source Enrichment** | RSS summary only | **Full source article fetching + enrichment** |
| **Report Template** | Basic IOC list | **CDB Premium Template (competes with CrowdStrike/Mandiant)** |
| **Report Sections** | 5 sections | **16 sections: Exec Summary → Threat Landscape → Technical Deep-Dive → IOCs → MITRE → Detection Engineering → Vulnerability Analysis → Risk Methodology → 24h Response → 7-Day Remediation → Strategic Recommendations → Industry Guidance → Global Trends → CDB Authority → SEO Keywords → Appendix** |
| **Detection Rules** | Empty Sigma/YARA stubs | **Production-ready Sigma, YARA, KQL, SPL, Suricata rules** |
| **MITRE Mapping** | Basic static | **Context-expanded with technique descriptions** |
| **Kill Chain Visual** | None | **Visual infection chain per threat type** |
| **Industry Guidance** | None | **6 sector-specific sections** |

### Preserved from v11.0:
| Feature | Status |
|---------|--------|
| **Risk Scoring** | Dynamic multi-factor (IOC, MITRE, CVSS, EPSS, Actor) |
| **Feed Sources** | Multi-feed fusion (9+ high-authority feeds) |
| **IOC Extraction** | 10 types: IPv4, Domain, URL, SHA256, SHA1, MD5, Email, CVE, Registry, Artifacts |
| **IOC Validation** | Private IP exclusion, false-positive domain filtering |
| **Deduplication** | Content-hash based dedup engine |
| **STIX Bundles** | Full: indicators, relationships, attack-patterns |
| **Manifest Schema** | 13 fields, 50 entries |
| **Confidence Scoring** | Weighted IOC confidence (0-100%) |
| **TLP Classification** | TLP:RED / AMBER / GREEN / CLEAR per advisory |
| **Rate Limiting** | Configurable delay between API calls |

## 🏗️ Architecture

```
RSS Feeds (6+) → Multi-Feed Ingestion → Deduplication Engine
    ↓
IOC Extraction (Enhanced) → Confidence Scoring → Private IP Exclusion
    ↓
MITRE ATT&CK Mapping → Actor Attribution → Dynamic Risk Scoring
    ↓
Source Article Fetcher → Content Enrichment → Full Context Assembly
    ↓
Premium 16-Section Report Generator (2500+ words) → Detection Rules (Sigma/YARA/KQL/SPL)
    ↓
Blogger API Publish → STIX 2.1 Bundle → Manifest Sync → GitHub Pages Dashboard
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
