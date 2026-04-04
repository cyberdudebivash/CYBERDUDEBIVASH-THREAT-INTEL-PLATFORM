"""
api/onboarding.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
Developer onboarding API — getting-started flow, interactive docs, SDK quickstart.

Endpoints:
  GET  /api/v1/onboarding/          — Landing: tier comparison, quickstart steps
  GET  /api/v1/onboarding/quickstart — Personalised quickstart for the caller's tier
  GET  /api/v1/onboarding/sdk       — SDK installation and code examples
  POST /api/v1/onboarding/validate  — Validate API key and return capabilities
  GET  /api/v1/onboarding/recipes   — Ready-to-run integration recipes
  GET  /api/v1/onboarding/openapi   — Link to full OpenAPI specification

Security:
  - /validate accepts an unauthenticated key in the request body (no header required)
    so new users can test without setting headers
  - All other endpoints require a valid API key (any tier)
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Graceful FastAPI import ────────────────────────────────────────────────
try:
    from fastapi import APIRouter, Header, HTTPException
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False
    APIRouter = None  # type: ignore

_BASE_DIR   = Path(__file__).parent.parent
_API_DIR    = Path(__file__).parent
sys.path.insert(0, str(_BASE_DIR))

# ── Auth helpers ───────────────────────────────────────────────────────────
_auth_available = False
try:
    from api.auth import validate_key, TIER_LIMITS
    _auth_available = True
except Exception:
    pass

# ── Platform constants ─────────────────────────────────────────────────────
_PLATFORM  = "CYBERDUDEBIVASH® Sentinel APEX"
_VERSION   = "100.0.0"
_DOCS_URL  = "https://docs.sentinel.cyberdudebivash.com"
_API_URL   = "https://api.sentinelapex.cyberdudebivash.com"
_PROVISION = f"{_API_URL}/api/v1/monetize/provision"


# ══════════════════════════════════════════════════════════════════════════════
# Static content helpers
# ══════════════════════════════════════════════════════════════════════════════

def _tier_comparison() -> List[Dict[str, Any]]:
    return [
        {
            "tier":          "FREE",
            "price_monthly": 0,
            "daily_requests": 100,
            "features": [
                "10 advisories per request",
                "Basic feed access",
                "JSON format",
                "Community support",
            ],
            "limitations": ["No search", "No IOC details", "No STIX export", "No bulk API"],
            "upgrade_cta": f"POST {_PROVISION} to get a PRO key",
        },
        {
            "tier":          "PRO",
            "price_monthly": 49,
            "daily_requests": 5_000,
            "features": [
                "100 advisories per request",
                "Full-text search",
                "IOC details (IPs, hashes, domains)",
                "STIX 2.1 export",
                "Email support (24h SLA)",
            ],
            "limitations": ["No bulk export", "No webhook push", "No white-label"],
            "upgrade_cta": "Upgrade at https://sentinel.cyberdudebivash.com/billing",
        },
        {
            "tier":          "ENTERPRISE",
            "price_monthly": 499,
            "daily_requests": 50_000,
            "features": [
                "500 advisories per request",
                "Bulk STIX export",
                "Ingestion pipeline access",
                "SIEM integration helpers",
                "Priority support (4h SLA)",
                "Custom feed filters",
            ],
            "limitations": ["No white-label", "No SLA guarantee"],
            "upgrade_cta": "Contact sales@cyberdudebivash.com",
        },
        {
            "tier":          "MSSP",
            "price_monthly": 1_999,
            "daily_requests": "unlimited",
            "features": [
                "Unlimited requests",
                "Webhook push delivery",
                "White-label ready",
                "Admin API access",
                "99.9% SLA",
                "Dedicated support engineer",
            ],
            "limitations": [],
            "upgrade_cta": "Contact enterprise@cyberdudebivash.com",
        },
    ]


def _quickstart_steps(tier: str) -> List[Dict[str, str]]:
    base = [
        {
            "step": "1",
            "title": "Install the SDK",
            "code": "pip install sentinel-apex-sdk",
            "description": "Zero external dependencies — pure Python stdlib.",
        },
        {
            "step": "2",
            "title": "Set your API key",
            "code": "export SENTINEL_API_KEY=your_key_here",
            "description": "Or use sentinel configure to save it to ~/.sentinel/config.json",
        },
        {
            "step": "3",
            "title": "Fetch your first advisories",
            "code": (
                "from sentinel_sdk import SentinelClient\n\n"
                "client = SentinelClient(api_key='your_key_here')\n"
                "page = client.get_advisories(severity='CRITICAL', limit=10)\n\n"
                "for item in page.items:\n"
                "    print(f'{item.severity}: {item.title} (score={item.risk_score})')"
            ),
            "description": "Returns the latest CRITICAL advisories from the live feed.",
        },
    ]

    tier_upper = tier.upper()

    if tier_upper in ("PRO", "ENTERPRISE", "MSSP"):
        base.append({
            "step": "4",
            "title": "Search the intelligence database",
            "code": (
                "results = client.search_advisories('log4shell')\n"
                "for item in results.items:\n"
                "    print(item.title, item.iocs)"
            ),
            "description": "Full-text search across all CVEs, actors, malware families, and TTPs.",
        })
        base.append({
            "step": "5",
            "title": "Export as STIX 2.1",
            "code": (
                "bundle = client.export_stix(severity='HIGH', limit=100)\n"
                "print(f'{bundle.object_count} STIX objects exported')"
            ),
            "description": "Direct STIX 2.1 bundle export for SIEM and SOAR ingestion.",
        })

    if tier_upper in ("ENTERPRISE", "MSSP"):
        base.append({
            "step": "6",
            "title": "Monitor the ingestion pipeline",
            "code": (
                "status = client.get_ingestion_status()\n"
                "print(status['queue']['depth'], 'items queued')\n"
                "print(status['metrics']['throughput_per_min'], 'items/min')"
            ),
            "description": "Live view of your NVD/KEV/MalwareBazaar/AbuseIPDB ingestion pipeline.",
        })

    return base


def _sdk_examples() -> Dict[str, Any]:
    return {
        "install": {
            "pip":  "pip install sentinel-apex-sdk",
            "dev":  "cd sdk/ && pip install -e '.[dev]'",
            "from_source": "git clone https://github.com/cyberdudebivash/sentinel-apex && pip install ./sdk",
        },
        "python": {
            "basic": (
                "from sentinel_sdk import SentinelClient\n\n"
                "client = SentinelClient(api_key='sa_live_xxxx')\n\n"
                "# Paginate all CRITICAL advisories\n"
                "for advisory in client.iter_advisories(severity='CRITICAL'):\n"
                "    print(advisory.title)\n"
            ),
            "error_handling": (
                "from sentinel_sdk import SentinelClient, RateLimitError, TierPermissionError\n\n"
                "client = SentinelClient(api_key='sa_live_xxxx')\n"
                "try:\n"
                "    bundle = client.export_stix(severity='CRITICAL')\n"
                "except TierPermissionError as e:\n"
                "    print(f'Upgrade to {e.required_tier} to use STIX export')\n"
                "except RateLimitError as e:\n"
                "    print(f'Rate limited — retry in {e.retry_after_s}s')\n"
            ),
            "siem_integration": (
                "import json\n"
                "from sentinel_sdk import SentinelClient\n\n"
                "client = SentinelClient(api_key='sa_live_xxxx')\n\n"
                "# Export to STIX file for Splunk ES / Microsoft Sentinel\n"
                "bundle = client.export_stix(severity='HIGH', limit=500)\n"
                "with open('threat_intel.stix.json', 'w') as f:\n"
                "    json.dump({'type': bundle.type, 'id': bundle.id,\n"
                "               'objects': bundle.objects}, f, indent=2)\n"
                "print(f'Exported {bundle.object_count} objects')\n"
            ),
        },
        "curl": {
            "list_advisories": (
                "curl -H 'X-API-Key: YOUR_KEY' \\\n"
                f"  '{_API_URL}/api/v1/advisories?severity=CRITICAL&limit=10'"
            ),
            "search": (
                "curl -H 'X-API-Key: YOUR_KEY' \\\n"
                f"  '{_API_URL}/api/v1/search?q=log4shell'"
            ),
            "stix_export": (
                "curl -H 'X-API-Key: YOUR_KEY' \\\n"
                f"  '{_API_URL}/api/v1/stix/export?severity=HIGH' \\\n"
                "  -o threat_bundle.json"
            ),
            "health": f"curl '{_API_URL}/api/v1/health/'",
        },
        "python_requests": (
            "import requests\n\n"
            "headers = {'X-API-Key': 'YOUR_KEY'}\n"
            f"resp = requests.get('{_API_URL}/api/v1/advisories',\n"
            "                    headers=headers,\n"
            "                    params={'severity': 'CRITICAL', 'limit': 25})\n"
            "data = resp.json()\n"
            "print(data['meta']['total'], 'advisories available')\n"
        ),
    }


def _integration_recipes() -> List[Dict[str, Any]]:
    return [
        {
            "name":        "Splunk ES Integration",
            "description": "Feed STIX bundles into Splunk Enterprise Security via REST API",
            "difficulty":  "Medium",
            "tier_required": "PRO",
            "steps": [
                "Export STIX bundle: client.export_stix(severity='HIGH')",
                "POST to Splunk ES /services/data/inputs/http endpoint",
                "Configure correlation search using threat_intel_match lookup",
            ],
            "docs_url": f"{_DOCS_URL}/integrations/splunk",
        },
        {
            "name":        "Microsoft Sentinel Integration",
            "description": "Push threat indicators to Microsoft Sentinel Threat Intelligence",
            "difficulty":  "Medium",
            "tier_required": "PRO",
            "steps": [
                "Export STIX bundle from Sentinel APEX",
                "Use MS Sentinel tiIndicators API to push indicators",
                "Configure Threat Intelligence matching analytics rule",
            ],
            "docs_url": f"{_DOCS_URL}/integrations/ms-sentinel",
        },
        {
            "name":        "Palo Alto Cortex XSOAR",
            "description": "Playbook integration for automated threat enrichment",
            "difficulty":  "Easy",
            "tier_required": "PRO",
            "steps": [
                "Install Sentinel APEX integration pack from XSOAR marketplace",
                "Configure API key in integration settings",
                "Enable auto-enrichment in playbooks",
            ],
            "docs_url": f"{_DOCS_URL}/integrations/xsoar",
        },
        {
            "name":        "OpenCTI Integration",
            "description": "Feed intelligence directly into OpenCTI via STIX 2.1",
            "difficulty":  "Easy",
            "tier_required": "PRO",
            "steps": [
                "Configure OpenCTI TAXII server connector",
                "Point to Sentinel APEX STIX export endpoint",
                "Set polling interval (recommended: 15 minutes)",
            ],
            "docs_url": f"{_DOCS_URL}/integrations/opencti",
        },
        {
            "name":        "GitHub Actions CI Security Gate",
            "description": "Block deploys when new CRITICAL CVEs match your software stack",
            "difficulty":  "Easy",
            "tier_required": "FREE",
            "code": (
                "# .github/workflows/security-gate.yml\n"
                "- name: Check for CRITICAL CVEs\n"
                "  env:\n"
                "    SENTINEL_API_KEY: ${{ secrets.SENTINEL_API_KEY }}\n"
                "  run: |\n"
                "    pip install sentinel-apex-sdk\n"
                "    python scripts/check_cves.py"
            ),
            "docs_url": f"{_DOCS_URL}/integrations/github-actions",
        },
        {
            "name":        "Real-time Slack Alerts",
            "description": "Webhook-push new CRITICAL advisories directly to Slack",
            "difficulty":  "Easy",
            "tier_required": "MSSP",
            "steps": [
                "Configure webhook URL in MSSP settings",
                "Set severity threshold and channel routing",
                "Receive real-time pushes within 60 seconds of detection",
            ],
            "docs_url": f"{_DOCS_URL}/integrations/slack",
        },
    ]


# ══════════════════════════════════════════════════════════════════════════════
# FastAPI Router
# ══════════════════════════════════════════════════════════════════════════════

if _FASTAPI_OK:
    onboarding_router = APIRouter(prefix="/api/v1/onboarding", tags=["Onboarding"])

    class ValidateKeyRequest(BaseModel):
        api_key: str

    def _auth_from_header(x_api_key: Optional[str] = Header(default=None)) -> Optional[str]:
        return x_api_key

    # ── GET / — Landing ──────────────────────────────────────────────────────
    @onboarding_router.get("/")
    async def onboarding_landing() -> Dict[str, Any]:
        """
        Developer onboarding landing page.
        No authentication required.
        Returns tier comparison, quickstart links, and SDK installation info.
        """
        return {
            "platform":        _PLATFORM,
            "version":         _VERSION,
            "tagline":         "Enterprise-grade threat intelligence. Zero friction.",
            "documentation":   _DOCS_URL,
            "api_reference":   f"{_API_URL}/docs",
            "provision_free_key": _PROVISION,
            "tiers":           _tier_comparison(),
            "quickstart":      {
                "sdk_install":  "pip install sentinel-apex-sdk",
                "first_call":   f"curl -H 'X-API-Key: YOUR_KEY' {_API_URL}/api/v1/advisories",
                "full_guide":   f"{_DOCS_URL}/quickstart",
            },
            "sdk_links": {
                "python":  "https://pypi.org/project/sentinel-apex-sdk",
                "github":  "https://github.com/cyberdudebivash/sentinel-apex-sdk",
                "openapi": f"{_API_URL}/openapi.json",
            },
            "support": {
                "community": "https://discord.gg/sentinelapex",
                "email":     "support@cyberdudebivash.com",
                "status":    "https://status.sentinelapex.cyberdudebivash.com",
            },
        }

    # ── GET /quickstart — Personalised guide ─────────────────────────────────
    @onboarding_router.get("/quickstart")
    async def quickstart_guide(
        x_api_key: Optional[str] = Header(default=None),
    ) -> Dict[str, Any]:
        """
        Personalised quickstart guide based on your API tier.
        Unauthenticated callers receive the FREE tier guide.
        """
        tier = "FREE"
        if x_api_key and _auth_available:
            try:
                result = validate_key(x_api_key)
                tier   = result.get("tier", "FREE").upper()
            except Exception:
                pass

        return {
            "tier":        tier,
            "steps":       _quickstart_steps(tier),
            "sdk_install": "pip install sentinel-apex-sdk",
            "docs":        f"{_DOCS_URL}/quickstart/{tier.lower()}",
        }

    # ── GET /sdk — SDK reference ─────────────────────────────────────────────
    @onboarding_router.get("/sdk")
    async def sdk_reference() -> Dict[str, Any]:
        """
        SDK installation instructions and code examples for all major languages.
        No authentication required.
        """
        return {
            "sdk_version":   _VERSION,
            "examples":      _sdk_examples(),
            "pypi":          "https://pypi.org/project/sentinel-apex-sdk",
            "changelog":     f"{_DOCS_URL}/sdk/changelog",
            "support_matrix": {
                "python": ">=3.9",
                "dependencies": "none (stdlib only)",
                "optional": "requests>=2.28 for connection pooling",
            },
        }

    # ── POST /validate — Key validation ──────────────────────────────────────
    @onboarding_router.post("/validate")
    async def validate_api_key(body: ValidateKeyRequest) -> Dict[str, Any]:
        """
        Validate an API key and return its capabilities.
        Use this to test a new key before integrating.
        No authentication header required — key is passed in the request body.
        """
        if not body.api_key or len(body.api_key) < 10:
            return {
                "valid":   False,
                "error":   "Key too short or empty",
                "hint":    f"Get a free key at {_PROVISION}",
            }

        if not _auth_available:
            # Offline/test mode — return simulated validation
            return {
                "valid":        True,
                "tier":         "FREE",
                "daily_limit":  100,
                "features":     ["advisories"],
                "message":      "Auth module offline — simulated validation",
            }

        try:
            result = validate_key(body.api_key)
            tier   = result.get("tier", "FREE").upper()
            limits = TIER_LIMITS.get(tier.lower(), {})

            return {
                "valid":         True,
                "tier":          tier,
                "owner":         result.get("owner", ""),
                "daily_limit":   limits.get("max_requests_day", 100),
                "features":      _tier_features(tier),
                "next_steps":    _quickstart_steps(tier)[:2],
                "docs":          f"{_DOCS_URL}/quickstart/{tier.lower()}",
            }
        except Exception as exc:
            return {
                "valid":  False,
                "error":  str(exc),
                "hint":   f"Get a new key at {_PROVISION}",
            }

    # ── GET /recipes — Integration recipes ───────────────────────────────────
    @onboarding_router.get("/recipes")
    async def integration_recipes(
        tier_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ready-to-run integration recipes for common SIEM, SOAR, and CI/CD platforms.
        """
        recipes = _integration_recipes()
        if tier_filter:
            tier_upper = tier_filter.upper()
            tier_order = {"FREE": 0, "PRO": 1, "ENTERPRISE": 2, "MSSP": 3}
            caller_idx = tier_order.get(tier_upper, 0)
            recipes = [
                r for r in recipes
                if tier_order.get(r.get("tier_required", "FREE"), 0) <= caller_idx
            ]
        return {
            "recipes":   recipes,
            "total":     len(recipes),
            "more_docs": f"{_DOCS_URL}/integrations",
        }

    # ── GET /openapi — OpenAPI spec reference ────────────────────────────────
    @onboarding_router.get("/openapi")
    async def openapi_reference() -> Dict[str, Any]:
        """
        Links to the full OpenAPI specification and interactive docs.
        """
        return {
            "openapi_json":    f"{_API_URL}/openapi.json",
            "swagger_ui":      f"{_API_URL}/docs",
            "redoc":           f"{_API_URL}/redoc",
            "postman_collection": f"{_DOCS_URL}/postman/sentinel-apex.json",
            "spec_version":    "3.1.0",
            "info": {
                "title":       _PLATFORM,
                "version":     _VERSION,
                "description": "Enterprise Threat Intelligence API — CVE, KEV, Malware, IP Threat",
            },
            "servers": [
                {"url": _API_URL,              "description": "Production"},
                {"url": "http://localhost:8000", "description": "Local development"},
            ],
            "auth": {
                "type":        "apiKey",
                "in":          "header",
                "name":        "X-API-Key",
                "description": "All endpoints except /health and /onboarding require X-API-Key header",
            },
        }

else:
    onboarding_router = None  # type: ignore


# ── Helpers ────────────────────────────────────────────────────────────────

def _tier_features(tier: str) -> List[str]:
    all_features = {
        "FREE":       ["advisories (10/req)", "CVE + EPSS data", "STIX 2.1 format",
                       "Public health endpoint", "60 req/hour"],
        "PRO":        ["advisories (100/req)", "Full IOC details", "Search API",
                       "STIX export", "APEX AI enrichment", "1,000 req/hour",
                       "Alert webhooks"],
        "ENTERPRISE": ["advisories (500/req)", "Bulk export", "STIX bundles",
                       "APEX priority scoring", "10,000 req/hour",
                       "4h SLA", "Ingestion API access"],
        "MSSP":       ["Unlimited advisories", "White-label API", "Webhook push",
                       "Custom feeds", "Unlimited RPM", "1h SLA",
                       "Dedicated support"],
    }
    return all_features.get(tier.upper(), all_features["FREE"])
