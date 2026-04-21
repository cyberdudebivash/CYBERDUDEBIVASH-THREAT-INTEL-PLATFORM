#!/usr/bin/env python3
"""
api/paywall_filter.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Tier-Aware Paywall Filter v1.0
===================================================================
Applies field-level access control to API responses based on API key tier.
This is a FILTER LAYER only -- it NEVER modifies source data.
All filtering is done on deep copies.

Tier policy:
  FREE       -- max 3 items, strips IOCs/STIX/kill_chain/behavioral_tags
  PRO        -- full intel, no webhook/bulk-export metadata
  ENTERPRISE -- full intel + all fields
  MSSP       -- full intel + all fields + white-label markers

ZERO REGRESSION:
  - Never raises: all errors return safe degraded output
  - Never mutates source data: deep copy before any strip
  - Never breaks schema: preserves all non-stripped keys
  - Additive only: upgrade_prompt injected, nothing else added

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import copy
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-PAYWALL")

# ---------------------------------------------------------------------------
# Tier constants (mirror api/auth.py -- no import to avoid circular dep)
# ---------------------------------------------------------------------------
TIER_FREE       = "FREE"
TIER_PRO        = "PRO"
TIER_ENTERPRISE = "ENTERPRISE"
TIER_MSSP       = "MSSP"

# ---------------------------------------------------------------------------
# Fields removed from each item for FREE tier
# ---------------------------------------------------------------------------
FREE_STRIP_TOP_LEVEL: tuple = (
    "iocs",
    "stix_bundle",
    "behavioral_tags",
    "raw_indicators",
    "detection_rules",
    "sigma_rules",
    "mitre_techniques_detail",
    "exploit_details",
    "kill_chain",
    "threat_actor_profile",
    "campaign_details",
    "network_indicators",
    "file_indicators",
    "lateral_movement_paths",
)

# Nested keys stripped inside apex_ai for FREE tier
FREE_STRIP_APEX_AI: tuple = (
    "kill_chain",
    "behavioral_analysis",
    "detection_opportunities",
    "attack_chain",
    "countermeasures",
    "pivot_indicators",
)

# Fields stripped for PRO (webhook / bulk metadata not available on PRO)
PRO_STRIP_TOP_LEVEL: tuple = (
    "webhook_payload",
    "bulk_export_url",
    "white_label",
)

# Fields kept for ALL tiers (always visible regardless of tier)
ALWAYS_KEEP: frozenset = frozenset({
    "id", "title", "summary", "severity", "risk_score",
    "published", "source", "source_url", "tlp", "report_url",
    "validation_status", "confidence", "ioc_count",
})

# Max items returned per request for FREE tier
FREE_MAX_ITEMS: int = 3

# Upgrade prompt injected into FREE responses
_UPGRADE_PROMPT = {
    "upgrade_available": True,
    "upgrade_url": "https://intel.cyberdudebivash.com/api",
    "upgrade_message": (
        "Unlock full IOC lists, STIX bundles, kill-chain analysis, "
        "and detection rules. Upgrade to PRO or ENTERPRISE."
    ),
}


# ---------------------------------------------------------------------------
# Core filter functions
# ---------------------------------------------------------------------------

def _strip_fields(item: Dict[str, Any], fields: tuple) -> Dict[str, Any]:
    """Remove specified top-level fields from item dict. Returns same dict."""
    for f in fields:
        item.pop(f, None)
    return item


def _strip_apex_ai_fields(item: Dict[str, Any], fields: tuple) -> Dict[str, Any]:
    """Strip nested fields from item['apex_ai'] if present."""
    apex_ai = item.get("apex_ai")
    if isinstance(apex_ai, dict):
        for f in fields:
            apex_ai.pop(f, None)
    return item


def _redact_ioc_values(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    For FREE tier: replace ioc list with count-only summary.
    Preserves ioc_count field so schema validation passes.
    """
    iocs = item.get("iocs")
    if isinstance(iocs, list) and iocs:
        item["iocs_redacted"] = True
        item["ioc_count"] = len(iocs)
        item.pop("iocs", None)
    return item


def filter_item_free(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply FREE tier filter to a single intel item.
    Strips premium fields, preserves schema structure.
    """
    out = copy.deepcopy(item)
    _redact_ioc_values(out)
    _strip_fields(out, FREE_STRIP_TOP_LEVEL)
    _strip_apex_ai_fields(out, FREE_STRIP_APEX_AI)
    out["tier_limited"] = True
    return out


def filter_item_pro(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply PRO tier filter to a single intel item.
    Removes webhook/bulk metadata only.
    """
    out = copy.deepcopy(item)
    _strip_fields(out, PRO_STRIP_TOP_LEVEL)
    return out


def filter_item_enterprise(item: Dict[str, Any]) -> Dict[str, Any]:
    """ENTERPRISE / MSSP: full access, no field stripping."""
    return copy.deepcopy(item)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def apply_paywall_filter(
    items: List[Dict[str, Any]],
    auth_result: Any,
    include_meta: bool = True,
) -> Dict[str, Any]:
    """
    Apply tier-based paywall filter to a list of intel items.

    Args:
        items:        Raw list of intel advisory dicts from feed_manifest.
        auth_result:  AuthResult object from api/auth.py (or None = FREE).
        include_meta: Whether to include filter metadata in response.

    Returns:
        Dict with keys:
          items         -- filtered list
          total_available -- unfiltered count (shows upgrade value)
          returned      -- actual count in this response
          tier          -- tier used for filtering
          filter_meta   -- metadata about what was filtered (if include_meta)
          upgrade_prompt -- shown for FREE tier only

    NEVER raises. All errors return a safe minimal response.
    """
    try:
        tier = TIER_FREE
        if auth_result is not None:
            tier = str(getattr(auth_result, "tier", TIER_FREE)).upper()
        if tier not in (TIER_FREE, TIER_PRO, TIER_ENTERPRISE, TIER_MSSP):
            tier = TIER_FREE

        total_available = len(items)

        # -- Apply tier-specific filtering ------------------------------------
        if tier == TIER_FREE:
            capped     = items[:FREE_MAX_ITEMS]
            filtered   = [filter_item_free(i) for i in capped]
            meta = {
                "fields_stripped": list(FREE_STRIP_TOP_LEVEL),
                "apex_ai_stripped": list(FREE_STRIP_APEX_AI),
                "items_capped_at": FREE_MAX_ITEMS,
                "iocs_redacted": True,
            }
            result: Dict[str, Any] = {
                "items": filtered,
                "total_available": total_available,
                "returned": len(filtered),
                "tier": tier,
                "upgrade_prompt": _UPGRADE_PROMPT,
            }

        elif tier == TIER_PRO:
            filtered = [filter_item_pro(i) for i in items]
            meta = {
                "fields_stripped": list(PRO_STRIP_TOP_LEVEL),
                "items_capped_at": None,
            }
            result = {
                "items": filtered,
                "total_available": total_available,
                "returned": len(filtered),
                "tier": tier,
            }

        else:  # ENTERPRISE or MSSP
            filtered = [filter_item_enterprise(i) for i in items]
            meta = {"fields_stripped": [], "items_capped_at": None}
            result = {
                "items": filtered,
                "total_available": total_available,
                "returned": len(filtered),
                "tier": tier,
            }

        if include_meta:
            result["filter_meta"] = meta

        return result

    except Exception as e:
        logger.error("apply_paywall_filter failed (safe fallback): %s", e)
        # Safe fallback: return empty items, never crash API
        return {
            "items": [],
            "total_available": 0,
            "returned": 0,
            "tier": "FREE",
            "error": "filter_error",
            "upgrade_prompt": _UPGRADE_PROMPT,
        }


def get_tier_capabilities(tier: str) -> Dict[str, Any]:
    """
    Return human-readable capability summary for a given tier.
    Used by /api/status and upgrade prompts.
    """
    tier = tier.upper()
    caps: Dict[str, Any] = {
        TIER_FREE: {
            "items_per_request": FREE_MAX_ITEMS,
            "ioc_details": False,
            "stix_bundle": False,
            "kill_chain": False,
            "behavioral_tags": False,
            "detection_rules": False,
            "webhook": False,
            "bulk_export": False,
            "price_monthly_usd": 0,
            "upgrade_cta": "Upgrade to PRO for $49/month — unlock full IOC lists, STIX bundles, kill-chain analysis.",
        },
        TIER_PRO: {
            "items_per_request": 100,
            "ioc_details": True,
            "stix_bundle": True,
            "kill_chain": True,
            "behavioral_tags": True,
            "detection_rules": True,
            "webhook": False,
            "bulk_export": False,
            "price_monthly_usd": 49,
            "upgrade_cta": "Upgrade to ENTERPRISE for $499/month — unlock webhooks, bulk export, and dedicated support.",
        },
        TIER_ENTERPRISE: {
            "items_per_request": 500,
            "ioc_details": True,
            "stix_bundle": True,
            "kill_chain": True,
            "behavioral_tags": True,
            "detection_rules": True,
            "webhook": True,
            "bulk_export": True,
            "price_monthly_usd": 499,
            "upgrade_cta": "Contact us for MSSP/white-label pricing.",
        },
        TIER_MSSP: {
            "items_per_request": -1,
            "ioc_details": True,
            "stix_bundle": True,
            "kill_chain": True,
            "behavioral_tags": True,
            "detection_rules": True,
            "webhook": True,
            "bulk_export": True,
            "white_label": True,
            "priority_routing": True,
            "price_monthly_usd": 1999,
            "upgrade_cta": None,
        },
    }
    return caps.get(tier, caps[TIER_FREE])


# ---------------------------------------------------------------------------
# CLI test harness
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    _SAMPLE = [
        {
            "id": f"CDB-TEST-{i:04d}",
            "title": f"Test Advisory {i}",
            "summary": "Test summary",
            "severity": "HIGH",
            "risk_score": 8.5,
            "published": "2026-04-21T00:00:00Z",
            "source": "TestSource",
            "iocs": ["1.2.3.4", "evil.com"],
            "ioc_count": 2,
            "stix_bundle": {"type": "bundle"},
            "kill_chain": ["Initial Access", "Execution"],
            "behavioral_tags": ["ransomware"],
            "apex_ai": {
                "summary": "AI summary",
                "kill_chain": ["T1190"],
                "behavioral_analysis": "detailed",
            },
        }
        for i in range(10)
    ]

    for _tier in ("FREE", "PRO", "ENTERPRISE"):
        class _FakeAuth:
            tier = _tier
        result = apply_paywall_filter(_SAMPLE, _FakeAuth())
        print(f"\n=== {_tier} ===")
        print(f"  returned={result['returned']} / total={result['total_available']}")
        sample_item = result["items"][0] if result["items"] else {}
        print(f"  iocs present: {'iocs' in sample_item}")
        print(f"  stix_bundle present: {'stix_bundle' in sample_item}")
        print(f"  kill_chain present: {'kill_chain' in sample_item}")
        print(f"  upgrade_prompt: {'upgrade_prompt' in result}")
        print(json.dumps(result.get("filter_meta", {}), indent=2))
