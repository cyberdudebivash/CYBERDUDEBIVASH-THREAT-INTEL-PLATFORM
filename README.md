# 🛡️ CDB-SENTINEL — Threat Intelligence Platform

**Automated Cyber Threat Intelligence Publisher by CyberDudeBivash Pvt Ltd**

[![Daily Pipeline](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/workflows/sentinel-daily.yml/badge.svg)](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions)
[![Weekly Report](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/workflows/sentinel-weekly.yml/badge.svg)](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions)

---

## What This Does

CDB-SENTINEL automatically monitors global cyber threats and publishes professional, revenue-optimized intelligence reports to [CyberDudeBivash News](https://cyberdudebivash-news.blogspot.com).

**Pipeline:** RSS Feeds → NVD/CISA/MalwareBazaar → Enrichment → Professional HTML → Blogger API → Published

---

## Features

| Capability | Description |
|:--|:--|
| **Multi-Source Intel** | 8 RSS feeds + NVD CVE API + CISA KEV + MalwareBazaar |
| **EPSS Enrichment** | Current probability + 7-day trend + 24h acceleration |
| **Risk Ranking** | CVSS + EPSS + KEV bonus scoring engine |
| **MITRE ATT&CK** | Coverage gap analysis + Navigator heatmap export |
| **Professional HTML** | Inline-styled reports that render beautifully everywhere |
| **Revenue CTAs** | Newsletter, services, tools, consulting — in every post |
| **Deduplication** | State file prevents duplicate publications |
| **Weekly Reports** | Monday mega-reports with top 10 exploited CVEs |
| **Deep Dives** | Individual authority-grade CVE analysis posts |
| **IOC Export** | STIX 2.1 + MISP compatible output |
| **Retry Logic** | Exponential backoff on API failures |
| **Metrics** | Per-run pipeline performance tracking |

---

## Architecture

```
agent/
├── config.py                  # Centralized configuration
├── sentinel_blogger.py        # Daily pipeline orchestrator
├── sentinel_weekly.py         # Weekly mega-report orchestrator
├── blogger_auth.py            # OAuth2 authentication
├── blogger_client.py          # Blogger API client
├── dashboard.py               # Streamlit dashboard
├── content/
│   └── blog_post_generator.py # Premium HTML report generator
├── formatter/
│   ├── cdb_template.py        # Daily report formatter
│   ├── cdb_cve_deep_dive.py   # CVE deep-dive formatter
│   └── cdb_weekly_cve_report.py # Weekly report formatter
├── intel/
│   ├── cve_feed.py            # NVD + EPSS integration
│   ├── kev_feed.py            # CISA KEV feed
│   ├── malware_feed.py        # MalwareBazaar feed
│   └── ioc_export.py          # STIX/MISP export
├── analysis/
│   ├── attack_coverage.py     # ATT&CK gap analysis
│   ├── attack_navigator.py    # Navigator layer export
│   ├── detection_recommendations.py  # Sigma/KQL rules
│   ├── weekly_cve_ranker.py   # Risk-based CVE ranking
│   └── cve_deep_dive_selector.py     # Deep-dive selection
└── publishers/
    └── cve_deep_dive_publisher.py    # Deep-dive publisher
```

---

## Quick Start

### 1. Configure GitHub Secrets

Go to **Settings → Secrets → Actions** and add:

| Secret | Value |
|:--|:--|
| `REFRESH_TOKEN` | Google OAuth refresh token |
| `CLIENT_ID` | Google OAuth client ID |
| `CLIENT_SECRET` | Google OAuth client secret |
| `BLOG_ID` | `1735779547938854877` |

### 2. Run the Pipeline

**GitHub Actions (automated):**
- Daily: Runs every 6 hours automatically
- Weekly: Runs every Monday at 08:00 UTC
- Manual: Actions → Run workflow

**Local:**
```bash
pip install -r requirements.txt

export REFRESH_TOKEN="your-token"
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-secret"
export BLOG_ID="1735779547938854877"

python -m agent.sentinel_blogger     # Daily
python -m agent.sentinel_weekly      # Weekly
```

---

## Revenue Optimization

Every published report includes:

- **Newsletter CTA** — Email capture for subscriber growth
- **Services Promotion** — Pentest, MDR, AI audit, training
- **Tools Showcase** — Open-source tools with GitHub links
- **Consulting CTA** — Direct email consultation requests
- **Ecosystem Links** — Cross-promotion across all CDB properties
- **Professional Branding** — Authority positioning throughout

---

## Security

⚠️ **Never commit credentials to Git.** Use GitHub Secrets or environment variables.

The `.gitignore` file blocks `credentials/`, `token.json`, `.env`, and all sensitive files.

---

## Contact

**CyberDudeBivash Pvt. Ltd.**
- 🌐 [cyberdudebivash.com](https://www.cyberdudebivash.com)
- 📧 bivash@cyberdudebivash.com
- 📞 +91 81798 81447
- 📍 Bhubaneswar, Odisha, India

---

© 2024–2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
