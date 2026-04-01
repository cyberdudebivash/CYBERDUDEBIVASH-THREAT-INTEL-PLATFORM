# CHANGELOG — SENTINEL APEX v77.0 → v77.2
**Platform:** intel.cyberdudebivash.com
**Released:** 2026-04-01
**Scope:** 8 New AI Intelligence Engines · Complete REST API Layer · Workflow Hardening

---

## v77.2.0 (2026-04-01) — WORKFLOW + API INTEGRATION

### What's New

**V1 Router mounted in `api/main.py`**
- All `/api/v1/*` endpoints now fully active (threats, IOCs, predict, identity-risk,
  darkweb, risk-score, detections, SOAR, health, engines/status, me)
- Dual import strategy: package import → file loader fallback (zero-crash design)
- `api/__init__.py` created — api directory is now a proper Python package

**`sentinel-blogger.yml` upgraded to v77.2**
- `[FIX-v77.2-A]` PYTHONWARNINGS: Removed invalid `RequestsDependencyWarning` category
- `[FIX-v77.2-B]` `actions/checkout` pinned to v4.2.2 (Node.js 24 — June 2026 deadline)
- `[FIX-v77.2-C]` `actions/setup-python` pinned to v5.4.0 (Node.js 24 compliance)
- `[FIX-v77.2-D]` `GOOGLE_OAUTH_DISABLE_FILE_CACHE=1` added to Stage 1 env
- `[FIX-v77.2-E]` `NVD_API_KEY` fully wired — 50 req/30s NVD rate limit enabled
- `[FIX-v77.2-F]` Stage 5 push: v77.2 reset --soft strategy (no rebase conflicts)

---

## v77.1.0 (2026-04-01) — ENGINE PIPELINE INTEGRATION (Stages 6g–6j)

All 8 new intelligence engines integrated into the main CI/CD pipeline as
optional post-commit enrichment stages (non-blocking — all wrapped in `|| true`).

| Stage | Engine | Output Directory |
|---|---|---|
| 6g | Threat Graph Engine | `data/threat_graph/` |
| 6h | Exploit Intelligence Layer | `data/exploit_intel/` |
| 6i | Enterprise API Directory Bootstrap | `data/auth/`, `data/agentic_intel/` etc. |
| 6j | Agentic AI + Predictive Threat Intelligence | `data/agentic_intel/` |
| 6j | Identity Intel Engine | `data/identity_intel/` |
| 6j | Dark Web Intelligence Engine | `data/darkweb_intel/` |
| 6j | Risk Quantification Engine | `data/risk_quantification/` |
| 6j | MITRE ATT&CK TTP Engine | `data/ttp_engine/` |
| 6j | SOAR Automation Engine | `data/soar_engine/` |

---

## v77.0.0 (2026-04-01) — 8 NEW AI INTELLIGENCE ENGINES + FULL API LAYER

### Engine Layer (agent/)

#### 1. Agentic AI + Predictive Threat Intelligence (`agent/agentic_intel_engine.py`)
- AI-driven threat prediction engine using manifest signal analysis
- Outputs: `predictions.json`, `agent_signals.json`, `supply_chain_risks.json`, `engine_meta.json`
- Features: confidence scoring, threat actor profiling, campaign correlation,
  zero-day prediction signals, supply chain risk assessment
- Output dir: `data/agentic_intel/`

#### 2. Identity Intel Engine (`agent/identity_intel_engine.py`)
- Leaked credential signal processing + identity risk scoring
- Outputs: `identity_risk_index.json`, `leaked_credential_signals.json`,
  `remediation_actions.json`, `engine_meta.json`
- Features: breach correlation, credential exposure tracking, remediation playbooks,
  sector-based risk indexing (finance, healthcare, government priority)
- Output dir: `data/identity_intel/`

#### 3. Dark Web Intelligence Engine (`agent/darkweb_intel_engine.py`)
- Underground forum signal monitoring + threat actor profiling
- Outputs: `actor_profiles.json`, `entity_monitor.json`, `campaign_map.json`,
  `forum_signals.json`, `engine_meta.json`
- Features: actor attribution scoring, entity monitoring (IPs, domains, CVEs),
  darkweb campaign mapping, ransomware group tracking
- Output dir: `data/darkweb_intel/`

#### 4. Risk Quantification Engine (`agent/risk_quantification_engine.py`)
- Financial impact + brand risk quantification per advisory
- Outputs: `financial_impact.json`, `brand_protection.json`, `risk_tiers.json`,
  `portfolio_risk_summary.json`, `engine_meta.json`
- Features: FAIR-inspired loss modeling, sector-weighted exposure, insurance reserve
  estimates, SLA breach probability, portfolio heat map
- Output dir: `data/risk_quantification/`

#### 5. MITRE ATT&CK TTP Engine (`agent/ttp_engine.py`)
- Full Enterprise ATT&CK v14 coverage · auto-generation of detection rules
- Outputs: `ttp_coverage_matrix.json`, `ttp_correlations.json`, `sigma_rules.yml`,
  `yara_rules.yar`, `siem_rules.json`, `engine_meta.json`
- Features: 100+ technique keyword triggers, tactic → technique mapping,
  cross-advisory TTP correlation, Sigma/YARA/SIEM rule auto-generation
- Output dir: `data/ttp_engine/`

#### 6. SOAR Automation Engine (`agent/soar_engine.py`)
- IOC enrichment + SIEM dispatch + automated response actions
- Outputs: `ioc_enrichment.json`, `siem_dispatch_queue.json`, `response_actions.json`,
  `engine_meta.json`
- Features: IOC VirusTotal/Shodan-compatible enrichment stubs, SIEM dispatch
  with criticality queuing, playbook-driven automated response, rollback tracking
- Output dir: `data/soar_engine/`

#### 7. Exploit Intelligence Engine (`agent/exploit_intel_engine.py`)
- KEV + EPSS + PoC exploit tracking and prioritization
- Outputs: `exploit_index.json`, `engine_meta.json`
- Features: exploit chain detection, weaponization probability scoring,
  PoC availability tracking, critical asset exposure mapping
- Output dir: `data/exploit_intel/`

#### 8. Threat Graph Engine (`agent/threat_graph_engine.py`)
- Knowledge graph of threat relationships (actors → campaigns → CVEs → IOCs)
- Outputs: `graph_nodes.json`, `graph_meta.json`
- Features: entity relationship mapping, campaign attribution chains,
  cross-threat correlation, graph-based risk propagation
- Output dir: `data/threat_graph/`

---

### API Layer (api/)

#### `api/auth.py` — Authentication Module
- SHA-256 hashed API key validation (constant-time comparison)
- JWT token issuance + validation (HS256)
- Tier-based permission model: FREE → PRO → ENTERPRISE → MSSP
- Key rotation support, expiry tracking, rate limit metadata

#### `api/billing.py` — Billing Module
- Stripe + Razorpay payment gateway integration stubs
- Subscription lifecycle: create, upgrade, downgrade, cancel
- Invoice generation, payment history, MRR tracking
- Webhook signature verification (Stripe HMAC + Razorpay)

#### `api/subscription.py` — Subscription Manager
- Full subscription state machine (trial → active → past_due → cancelled)
- Grace period handling (7-day past_due → suspended)
- Auto-provisioning of API keys on payment confirmation
- Proration calculation for mid-cycle tier changes

#### `api/schemas.py` — Pydantic Schemas
- Standardized response wrapper: `make_response()` / `make_error()`
- All request/response models: `PredictRequest`, `SOARActionRequest`,
  `ThreatAdvisory`, `IOCRecord`, `IdentityRiskResponse`, `DarkWebResponse`,
  `RiskScoreResponse`, `DetectionResponse`, `SOARActionResponse`
- Field validation, type coercion, OpenAPI schema auto-generation

#### `api/rate_limiter.py` — Rate Limiter
- In-memory sliding window rate limiting (production: swap to Redis)
- Per-key, per-tier quota enforcement
- Quota remaining calculation for `X-RateLimit-*` headers
- Tier limits: FREE=60/hr, PRO=1000/hr, ENTERPRISE=10000/hr, MSSP=unlimited

#### `api/engine_connector.py` — Engine Connector
- Safe reader for all 9 engine output directories
- TTL caching (5-minute default) with threading lock
- Atomic JSON reads — never raises on missing/corrupt files
- Engine file registry: 35+ data file paths pre-mapped
- Functions: `get_predictions()`, `get_identity_risk()`, `get_darkweb_intel()`,
  `get_risk_scores()`, `get_ttp_matrix()`, `get_soar_data()`, `get_detections()`,
  `get_threat_graph()`, `get_exploit_intel()`, `get_manifest()`

#### `api/v1_router.py` — V1 API Router
- All 12 `/api/v1/*` endpoints fully implemented
- Endpoint matrix:

| Endpoint | Method | Tier | Description |
|---|---|---|---|
| `/api/v1/threats` | GET | FREE+ | Paginated threat advisories |
| `/api/v1/threats/{id}` | GET | FREE+ | Single threat by ID or CVE |
| `/api/v1/iocs` | GET | PRO+ | IOC intelligence feed |
| `/api/v1/predict` | POST | PRO+ | Agentic AI predictive analysis |
| `/api/v1/identity-risk` | GET | PRO+ | Identity + stealer log risk |
| `/api/v1/darkweb` | GET | PRO+ | Dark web intelligence |
| `/api/v1/risk-score` | GET | FREE+ | Financial risk quantification |
| `/api/v1/detections` | GET | PRO+ | MITRE ATT&CK + SIEM rules |
| `/api/v1/soar/action` | POST | ENTERPRISE+ | SOAR workflow trigger |
| `/api/v1/health` | GET | Public | Platform health check |
| `/api/v1/engines/status` | GET | FREE+ | All engine status |
| `/api/v1/me` | GET | Any | API key info + quota |

---

## Engine Output Data Schema

```
data/
├── agentic_intel/
│   ├── predictions.json          # AI threat predictions + confidence
│   ├── agent_signals.json        # Extracted threat signals
│   ├── supply_chain_risks.json   # Supply chain risk assessment
│   └── engine_meta.json          # Run metadata
├── identity_intel/
│   ├── identity_risk_index.json  # Per-entity risk scores
│   ├── leaked_credential_signals.json
│   ├── remediation_actions.json
│   └── engine_meta.json
├── darkweb_intel/
│   ├── actor_profiles.json       # Threat actor profiles
│   ├── entity_monitor.json       # Monitored entities
│   ├── campaign_map.json         # Campaign attribution
│   ├── forum_signals.json        # Underground forum signals
│   └── engine_meta.json
├── risk_quantification/
│   ├── financial_impact.json     # $ impact estimates
│   ├── brand_protection.json     # Brand risk scores
│   ├── risk_tiers.json           # Tiered risk classification
│   ├── portfolio_risk_summary.json
│   └── engine_meta.json
├── ttp_engine/
│   ├── ttp_coverage_matrix.json  # ATT&CK coverage map
│   ├── ttp_correlations.json     # Cross-advisory correlations
│   ├── sigma_rules.yml           # Auto-generated Sigma rules
│   ├── yara_rules.yar            # Auto-generated YARA rules
│   ├── siem_rules.json           # SIEM detection rules
│   └── engine_meta.json
├── soar_engine/
│   ├── ioc_enrichment.json       # Enriched IOC records
│   ├── siem_dispatch_queue.json  # SIEM dispatch queue
│   ├── response_actions.json     # Automated response log
│   └── engine_meta.json
├── threat_graph/
│   ├── graph_nodes.json          # Knowledge graph nodes
│   └── graph_meta.json
└── exploit_intel/
    ├── exploit_index.json        # KEV + EPSS + PoC index
    └── engine_meta.json
```

---

## API Quick Start

```bash
# Free tier — no key required
curl https://cyberdudebivash-threat-intel-platform-production.up.railway.app/api/v1/health

# Pro tier — threat feed
curl -H "X-API-Key: YOUR_PRO_KEY" \
  "https://...railway.app/api/v1/threats?limit=50&severity=CRITICAL"

# Pro tier — predictive analysis
curl -X POST -H "X-API-Key: YOUR_PRO_KEY" \
  -H "Content-Type: application/json" \
  -d '{"query": "ransomware supply chain", "horizon_days": 30}' \
  "https://...railway.app/api/v1/predict"

# Enterprise tier — SOAR action
curl -X POST -H "X-API-Key: YOUR_ENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"action_type": "block_ioc", "ioc": "198.51.100.1", "ioc_type": "ipv4", "priority": "P1"}' \
  "https://...railway.app/api/v1/soar/action"
```

---

## Cumulative Platform Metrics (Post v77.0)
| Metric | Value |
|---|---|
| Intelligence engines | 8 new (16 total) |
| API endpoints | 12 new V1 + legacy |
| Workflow stages | 9 stages (6a–6j + 7 + 7b + 8) |
| Active feeds | 40 / 58 configured |
| Archive entries | 583+ (growing daily) |
| CRITICAL advisories | 112+ in manifest |
| TLP:RED advisories | 97+ correctly classified |
| MITRE techniques mapped | 100+ auto-mapped per run |

---

## Files Changed — Complete Push List
```
api/__init__.py                       # NEW: makes api/ a proper Python package
api/auth.py                           # NEW: API key auth + JWT
api/billing.py                        # NEW: Stripe + Razorpay billing
api/subscription.py                   # NEW: subscription lifecycle manager
api/schemas.py                        # NEW: Pydantic schemas + response wrappers
api/rate_limiter.py                   # NEW: per-key rate limiting
api/engine_connector.py               # NEW: engine output reader (9 engines)
api/v1_router.py                      # NEW: all /api/v1/* endpoints
api/main.py                           # UPDATED: v1_router mounted
agent/agentic_intel_engine.py         # NEW: agentic AI predictions engine
agent/identity_intel_engine.py        # NEW: identity/credential risk engine
agent/darkweb_intel_engine.py         # NEW: dark web intel engine
agent/risk_quantification_engine.py   # NEW: financial risk quantification
agent/ttp_engine.py                   # NEW: MITRE ATT&CK TTP engine
agent/soar_engine.py                  # NEW: SOAR automation engine
agent/exploit_intel_engine.py         # NEW: exploit intelligence engine
agent/threat_graph_engine.py          # NEW: threat knowledge graph engine
.github/workflows/sentinel-blogger.yml # UPDATED: v77.2 with stages 6g–6j
CHANGELOG_v77.md                      # this file
```

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
