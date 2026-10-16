# CYBERDUDEBIVASH® SENTINEL APEX v201.0

**AI-Powered Global Threat Intelligence Platform** — Real-time IOC feeds, STIX 2.1 exports, MITRE ATT&CK mapping, and enterprise SOC automation.

[![Platform Status](https://img.shields.io/badge/Status-live%20status%20page-00d4aa?style=flat-square)](https://intel.cyberdudebivash.com/status.html)
[![Version](https://img.shields.io/badge/Version-v201.0-blueviolet?style=flat-square)](https://intel.cyberdudebivash.com)
[![Stability](https://img.shields.io/badge/Stability-GOD--MODE-gold?style=flat-square)](https://intel.cyberdudebivash.com)
[![API](https://img.shields.io/badge/API-STIX%202.1-0078d7?style=flat-square)](https://intel.cyberdudebivash.com/api-docs.html)
[![GSTIN](https://img.shields.io/badge/GSTIN-21ARKPN8270G1ZP-lightgrey?style=flat-square)](https://intel.cyberdudebivash.com/trust-center.html)

---

## Live Platform

| Resource | URL |
|---|---|
| **Dashboard** | [intel.cyberdudebivash.com](https://intel.cyberdudebivash.com) |
| **API Preview** | [intel.cyberdudebivash.com/api/preview/](https://intel.cyberdudebivash.com/api/preview/) |
| **API Docs** | [intel.cyberdudebivash.com/api-docs.html](https://intel.cyberdudebivash.com/api-docs.html) |
| **Pricing** | [intel.cyberdudebivash.com/pricing.html](https://intel.cyberdudebivash.com/pricing.html) |
| **Trust Center** | [intel.cyberdudebivash.com/trust-center.html](https://intel.cyberdudebivash.com/trust-center.html) |
| **SLA** | [intel.cyberdudebivash.com/sla.html](https://intel.cyberdudebivash.com/sla.html) |

---

## Platform Metrics

Counts change with every publication, so they are read from the running platform rather than written here.

| Metric | Value |
|---|---|
| Active advisories | Live: `advisory_count` in [`/api/health`](https://intel.cyberdudebivash.com/api/health) |
| Feed freshness | Live: `intelligence.generated_at` / `age_seconds` in `/api/health` (public contract: at most 6 hours old) |
| Intelligence sources | Live: `feed_source_count` in [`/api/metrics`](https://intel.cyberdudebivash.com/api/metrics) |
| Measured uptime | Live: [`/api/sla/status`](https://intel.cyberdudebivash.com/api/sla/status) (`null` until enough samples exist); commitments in [sla.html](https://intel.cyberdudebivash.com/sla.html) |
| STIX 2.1 Bundles | Full export |
| MITRE ATT&CK Coverage | Multi-tactic mapping |
| IOC Validation | Real-time, cross-feed dedup |
| SOC Priority Scoring | P1–P4 with EPSS integration |

---

## What is SENTINEL APEX?

SENTINEL APEX is a production-grade Cyber Threat Intelligence (CTI) platform that:

- **Aggregates** threat intelligence from curated public sources (CISA KEV, NVD, MITRE ATT&CK, vendor and research advisories); the live source count is `feed_source_count` in `/api/metrics`
- **Enriches** every advisory with AI-powered apex_ai blocks: SOC priority, kill chain, actor fingerprint, behavioral tags, campaign IDs
- **Exports** in STIX 2.1 and TAXII 2.1 — plug-and-play with SIEM/SOAR (Splunk, Elastic, Microsoft Sentinel, CrowdStrike)
- **Delivers** a zero-latency dashboard with EMBEDDED_INTEL for instant render — no API round-trip on load
- **Monetizes** with a tiered subscription model (Free / PRO / Enterprise / MSSP) backed by Cloudflare Worker JWT auth

---

## API Quick Start

```bash
# Free tier — no auth required
curl https://intel.cyberdudebivash.com/api/preview/

# Response (truncated)
{
  "status": "ok",
  "preview": {
    "items": [...],
    "total_preview": 25,
    "feed_total": 54,
    "preview_limit": 25,
    "limit": 25,
    "offset": 0,
    "has_more": false,
    "version": "201.0",
    "_tier": "FREE",
    "_upgrade_url": "https://intel.cyberdudebivash.com/upgrade.html"
  }
}
```

```bash
# PRO/Enterprise — JWT Bearer auth
curl -H "Authorization: Bearer $SENTINEL_API_KEY" \
     https://intel.cyberdudebivash.com/api/feed.json
```

### STIX 2.1 Export

```bash
curl -H "Authorization: Bearer $SENTINEL_API_KEY" \
     https://intel.cyberdudebivash.com/api/stix/bundle.json
```

---

## Subscription Tiers

| Feature | Free | PRO / SOC | Enterprise | MSSP |
|---|:---:|:---:|:---:|:---:|
| API requests / minute | 30 | 120 | 600 | 1,200 |
| API requests / day | 50 | 5,000 | 50,000 | 50,000 |
| API keys | — (public endpoints, no key) | 10 | 50 | 100 |
| Seats | 1 | 1 | 10 | 25 |
| IOC visibility | — | Full | Full | Full |
| STIX 2.1 export | — | ✓ | ✓ | ✓ |
| AI enrichment | — | Partial | Full | Full |
| Kill chain detail | — | ✓ | ✓ | ✓ |
| Actor fingerprint | — | ✓ | ✓ | ✓ |
| Uptime commitment | Best effort | 99.5% | 99.9% | 99.9% |
| Incident response | Community | 48h email | 4h email/chat | 1h dedicated |
| White-label | — | — | — | ✓ |
| **Price (USD/mo)** | Free | $49 | $499 | $999 |

Annual: PRO $490, Enterprise $4,990, MSSP $9,990. No free trial; the FREE tier is the evaluation path. The gateway enforces both limits and answers HTTP 429 with `Retry-After` at either cap. Canonical terms: [`config/commercial-contract.json`](config/commercial-contract.json) and [sla.html](https://intel.cyberdudebivash.com/sla.html).

[View full pricing →](https://intel.cyberdudebivash.com/pricing.html)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 SENTINEL APEX v201.0                        │
│                                                             │
│  Curated sources ──► APEX AI Engine ──► STIX 2.1 Bundles  │
│                            │                               │
│                            ▼                               │
│                    Cloudflare Worker                        │
│                   (SENTINEL-APEX/201.0)                    │
│                            │                               │
│          ┌─────────────────┼─────────────────┐            │
│          ▼                 ▼                 ▼             │
│      /api/preview/    /api/feed.json    TAXII 2.1          │
│      (Free tier)      (PRO+)           (Enterprise+)       │
│          │                                                  │
│          ▼                                                  │
│   GitHub Pages Dashboard (instant render via EMBEDDED_INTEL)│
└─────────────────────────────────────────────────────────────┘
```

**Stack:**
- **Frontend:** Static HTML/JS on GitHub Pages — zero latency, global CDN
- **API Gateway:** Cloudflare Worker (JWT, rate limiting, tier enforcement)
- **Storage:** Cloudflare R2 (`sentinel-apex-data`, `sentinel-apex-reports`)
- **CI/CD:** GitHub Actions — 33-stage pipeline, GOD-MODE stability contract
- **AI Engine:** APEX AI enrichment (SOC priority, kill chain, campaign fingerprinting)

---

## Intelligence Quality Contract

Every advisory in the platform carries a fully-populated `apex_ai` block:

```json
{
  "soc_priority": "P1",
  "threat_level": "CRITICAL",
  "threat_category": "Ransomware",
  "predictive_risk": 94.2,
  "ai_confidence": 0.91,
  "kill_chain": ["Execution", "Persistence", "Impact"],
  "kill_chain_primary": "Impact",
  "actor_fingerprint": "LockBit-3.0-affiliate-cluster-7",
  "campaign_id": "CDB-CAMP-2026-0042",
  "behavioral_tags": ["double-extortion", "vuln-exploit", "lateral-movement"],
  "ai_summary": "Critical ransomware campaign exploiting CVE-2026-XXXX...",
  "recommended_action": "Patch immediately. Block IOCs at perimeter.",
  "paywall": false
}
```

---

## Licensing, Privacy & SLA

No independent compliance attestation (SOC 2, ISO 27001 and similar) is held; see the Trust Center for readiness status.

- **Data licensing:** CC BY-NC 4.0 (non-commercial) / commercial subscription required
- **Privacy:** EU GDPR · UK GDPR · UAE PDPL · CCPA compliant
- **GSTIN:** 21ARKPN8270G1ZP (CYBERDUDEBIVASH Pvt. Ltd., India)
- **Export controls:** OFAC / OFSI / EU sanctions compliant
- **SLA:** 99.5% uptime (PRO), 99.9% (Enterprise and MSSP); credits and measurement terms in sla.html

[View Trust Center →](https://intel.cyberdudebivash.com/trust-center.html)
[View SLA →](https://intel.cyberdudebivash.com/sla.html)
[View Terms →](https://intel.cyberdudebivash.com/terms.html)

---

## Enterprise & MSSP

For enterprise licensing, white-label deployment, MSSP agreements, or custom SLAs:

- **Email:** contact@cyberdudebivash.in
- **Enterprise page:** [intel.cyberdudebivash.com/enterprise.html](https://intel.cyberdudebivash.com/enterprise.html)
- **MSSP portal:** [intel.cyberdudebivash.com/mssp.html](https://intel.cyberdudebivash.com/mssp.html)

---

## Security

Vulnerability disclosures: [security@cyberdudebivash.com](mailto:security@cyberdudebivash.com)
Responsible disclosure policy: [/.well-known/security.txt](https://intel.cyberdudebivash.com/.well-known/security.txt)

---

## Pipeline

The platform runs on a 33-stage GOD-MODE CI/CD pipeline:

| Stage Group | Stages | Purpose |
|---|:---:|---|
| Pre-flight | 0.0–0.6 | Syntax, encoding, secrets validation |
| Intelligence | 1–3.1 | Multi-source ingestion, KEV enrichment |
| AI Enrichment | 3.1.3–3.3 | APEX AI scoring, report generation |
| Validation | 3.4–3.9 | Schema validation, manifest sanity |
| API | 3.91–3.94 | Contract tests, embedded intel injection |
| Deploy | 4–5.4 | R2 upload, GitHub Pages deploy, KV cache bust |
| QA | 5.5–5.9 | Regression immunity, monetization gate |

---

&copy; 2026 CYBERDUDEBIVASH® Pvt. Ltd. All rights reserved.
