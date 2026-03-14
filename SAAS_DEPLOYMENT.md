# CYBERDUDEBIVASH SENTINEL APEX — SaaS Transformation Deployment Guide

## Release: v49-v53 SaaS Module Suite
**Date:** 2026-03-14
**Author:** CyberDudeBivash Pvt. Ltd.
**Classification:** INTERNAL — DEPLOYMENT DOCUMENTATION

---

## Module Inventory

| Module | Version | Directory | Purpose |
|--------|---------|-----------|---------|
| Intelligence API | v49 | `agent/v49_intelligence_api/` | FastAPI server with tiered access |
| Attack Surface Monitor | v50 | `agent/v50_attack_surface/` | External ASM scanner |
| Detection Engine | v51 | `agent/v51_detection_engine/` | Automated rule generation |
| Report Engine | v52 | `agent/v52_report_engine/` | Enterprise HTML/STIX reports |
| Subscription System | v53 | `agent/v53_subscription/` | User/org/tier management |
| Enterprise Dashboard | — | `dashboard/enterprise_dashboard.html` | Enhanced SaaS dashboard |

---

## Zero-Regression Compliance

All modules are **strictly additive**:
- ✅ No existing files modified
- ✅ No existing imports changed
- ✅ No existing pipeline dependencies altered
- ✅ Independent data directories under `data/intelligence/`
- ✅ Isolated module directories under `agent/vXX_*/`

---

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements_saas.txt
```

### 2. Start Intelligence API
```bash
# Set admin key for API key management
export CDB_ADMIN_KEY="your-admin-secret"

# Run API server
python -m agent.v49_intelligence_api.api_server
# API available at http://localhost:8900
# Docs at http://localhost:8900/api/docs
```

### 3. Generate API Key
```bash
curl -X POST "http://localhost:8900/api/admin/keys/generate?org_name=TestOrg&tier=PRO" \
  -H "X-Admin-Key: your-admin-secret"
```

### 4. Test API
```bash
# Health check
curl http://localhost:8900/api/health

# IOC search (with API key)
curl "http://localhost:8900/api/ioc/search?q=ransomware" \
  -H "X-API-Key: cdb_<your-key>"

# CVE intelligence
curl "http://localhost:8900/api/cve/intelligence?min_cvss=8.0" \
  -H "X-API-Key: cdb_<your-key>"

# Threat actors
curl "http://localhost:8900/api/threat-actors" \
  -H "X-API-Key: cdb_<your-key>"
```

### 5. Run Detection Engine
```bash
python -m agent.v51_detection_engine.engine
# Outputs to data/intelligence/detection_rules/
```

### 6. Generate Reports
```bash
python -m agent.v52_report_engine.engine --type executive_briefing --days 7
# Outputs HTML + STIX + JSON to data/intelligence/reports/
```

### 7. Run Attack Surface Scan
```bash
python -m agent.v50_attack_surface.scanner example.com
# Outputs to data/intelligence/attack_surface.json
```

---

## Docker Deployment

```bash
# Build
docker build -f Dockerfile.api -t sentinel-apex-api:49.0 .

# Run
docker run -d \
  -p 8900:8900 \
  -e CDB_ADMIN_KEY=your-admin-secret \
  -v ./data:/app/data \
  --name sentinel-api \
  sentinel-apex-api:49.0
```

---

## API Tier Configuration

| Feature | FREE | PRO ($149/mo) | ENTERPRISE ($499/mo) |
|---------|------|---------------|----------------------|
| API calls/month | 5,000 | 100,000 | 1,000,000 |
| IOC search results | 25 | 100 | 500 |
| STIX export | ❌ | ✅ | ✅ |
| Detection rules | ❌ | ✅ | ✅ |
| Campaign intel | ❌ | ✅ | ✅ |
| ASM scans/month | 0 | 10 | Unlimited |
| Reports/month | 2 | 20 | Unlimited |
| SLA | 99.0% | 99.5% | 99.9% |

---

## File Tree (New Files Only)

```
agent/
├── v49_intelligence_api/
│   ├── __init__.py
│   ├── api_server.py          # FastAPI server (main)
│   └── detection_rule_gen.py  # API-embedded rule generator
├── v50_attack_surface/
│   ├── __init__.py
│   └── scanner.py             # Attack surface scanner
├── v51_detection_engine/
│   ├── __init__.py
│   └── engine.py              # Detection rule pipeline
├── v52_report_engine/
│   ├── __init__.py
│   └── engine.py              # Premium report generator
└── v53_subscription/
    ├── __init__.py
    └── manager.py             # SaaS subscription system

dashboard/
└── enterprise_dashboard.html  # Enhanced enterprise UI

data/intelligence/             # Runtime data (auto-created)
├── api_keys.json
├── api_usage.json
├── subscriptions.json
├── subscription_usage.json
├── attack_surface.json
├── reports/
│   ├── *.html
│   ├── *_stix.json
│   └── *.json
└── detection_rules/
    ├── sigma/*.yml
    ├── yara/*.yar
    ├── suricata/*.rules
    └── rule_manifest.json

Dockerfile.api                 # Container image
requirements_saas.txt          # Python dependencies
SAAS_DEPLOYMENT.md            # This file
```

---

## Revenue Channels

1. **API Subscriptions** — Tiered access (FREE/PRO/ENTERPRISE)
2. **Premium Reports** — Enterprise threat briefings
3. **Detection Rule Packs** — Sigma/YARA/Suricata bundles
4. **Attack Surface Monitoring** — Continuous external scanning
5. **STIX Intelligence Feeds** — Machine-readable threat data
6. **Gumroad** — Report packs and tool bundles
7. **Stripe** — Recurring SaaS subscriptions

---

## Integration Points

- **Stripe Webhooks:** POST to `/api/admin/webhooks/stripe` for subscription lifecycle
- **Gumroad License:** Validate via `v53_subscription/manager.py`
- **GitHub Pages:** Deploy `enterprise_dashboard.html` alongside existing `index.html`
- **CI/CD:** Detection engine and report generation can run as GitHub Actions jobs

---

© 2026 CyberDudeBivash Pvt. Ltd. — All Rights Reserved
