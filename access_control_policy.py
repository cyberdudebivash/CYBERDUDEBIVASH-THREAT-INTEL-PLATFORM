#!/usr/bin/env python3
"""
access_control_policy.py — CYBERDUDEBIVASH® SENTINEL APEX v173.0
ACCESS CONTROL GOVERNOR — SINGLE SOURCE OF TRUTH

CANONICAL TIER MODEL (MODEL_C — PERMANENT, MANDATORY, ONLY SUPPORTED ARCHITECTURE)

    PUBLIC      — Summary cards, executive summary, basic MITRE, no IOC/Detection/STIX
    PRO         — Full reports, AI analysis, detection rules (Sigma/YARA/KQL), IOC intel
    ENTERPRISE  — API, STIX, MISP, OpenCTI, SIEM integrations, bulk export, threat feeds
    MSSP        — White label, multi-tenant, managed feeds, SOC integrations

GOVERNANCE RULES:
    1.  This file is the ONLY place where tier permissions are defined.
    2.  Every platform component (dashboard, API, report generator, feed generator,
        STIX generator, export engine, detection engine) MUST import and consume
        policy from this module.
    3.  No component may implement its own access logic.
    4.  This file MUST NOT be modified without explicit governance approval.
    5.  The POLICY_HASH at the bottom is the drift-detection checksum.

DEPRECATED / DISABLED ARCHITECTURES:
    MODEL_A  (Dashboard → Upgrade Only)  — PERMANENTLY DISABLED
    MODEL_B  (Dashboard → Public Full Report) — PERMANENTLY DISABLED

Commercial Impact:
    Violation of this policy = revenue loss + brand damage + enterprise trust breach.
    All components must validate before serving any intelligence content.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger("CDB-ACCESS-POLICY")

# ═══════════════════════════════════════════════════════════════════════════════
# TIER CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

TIER_PUBLIC     = "PUBLIC"
TIER_PRO        = "PRO"
TIER_ENTERPRISE = "ENTERPRISE"
TIER_MSSP       = "MSSP"

# Tier hierarchy — higher index = higher privilege
TIER_ORDER: Dict[str, int] = {
    TIER_PUBLIC:     0,
    TIER_PRO:        1,
    TIER_ENTERPRISE: 2,
    TIER_MSSP:       3,
}

# Legacy tier alias map — normalize incoming tier strings
TIER_ALIAS: Dict[str, str] = {
    "FREE":      TIER_PUBLIC,
    "free":      TIER_PUBLIC,
    "public":    TIER_PUBLIC,
    "STANDARD":  TIER_PUBLIC,
    "standard":  TIER_PUBLIC,
    "PREMIUM":   TIER_PRO,
    "premium":   TIER_PRO,
    "pro":       TIER_PRO,
    "ENTERPRISE":TIER_ENTERPRISE,
    "enterprise":TIER_ENTERPRISE,
    "MSSP":      TIER_MSSP,
    "mssp":      TIER_MSSP,
}

# ═══════════════════════════════════════════════════════════════════════════════
# CANONICAL FIELD PERMISSIONS
# Fields that each tier is permitted to receive in any API response or report.
# Any field NOT listed for a tier is DENIED (deny-by-default).
# ═══════════════════════════════════════════════════════════════════════════════

# Fields available to PUBLIC tier — no sensitive intel
PUBLIC_ALLOWED_FIELDS: FrozenSet[str] = frozenset({
    "id",
    "stix_id",
    "bundle_id",
    "title",
    "risk_score",
    "severity",
    "tlp_label",
    "generated_at",
    "processed_at",
    "timestamp",
    "source_url",          # Source publication URL only — NOT report/dossier URL
    "mitre_tactics",       # Basic MITRE — tactic names only, no technique IDs
    "actor_tag",
    "status",
    "confidence",
    "feed_source",
    "kev_present",
    "validation_status",
    "executive_summary",   # Limited — first paragraph only, see SUMMARY_MAX_CHARS
    # Upgrade / marketing fields
    "upgrade_note",
    "_meta",
})

# Fields BLOCKED from PUBLIC tier regardless of source — these are the critical gates
PUBLIC_BLOCKED_FIELDS: FrozenSet[str] = frozenset({
    # Report links — PUBLIC must NEVER receive direct report URLs
    "report_url",
    "internal_report_url",
    "stix_bundle_url",
    "pdf_url",
    "gumroad_url",
    # IOC data
    "iocs",
    "ioc_counts",
    "ioc_list",
    "indicators",
    "full_iocs",
    # Detection content
    "sigma_rules",
    "yara_rules",
    "kql_queries",
    "suricata_rules",
    "detection_rules",
    "detection_pack",
    "full_detection_content",
    # AI/analytical premium content
    "ai_analysis",
    "apex_ai",
    "full_ai_analysis",
    "threat_context",
    "campaign_intelligence",
    "kill_chain",
    "behavioral_tags",
    # Actor intelligence
    "actor_intelligence",
    "actor_profile",
    "full_actor_intelligence",
    # STIX/structured exports
    "stix_bundle",
    "full_stix",
    "misp_event",
    # Enterprise feed/API fields
    "enterprise_feeds",
    "api_key",
    "webhook_config",
    # MITRE detailed
    "mitre_techniques",    # Technique IDs (T1xxx) are PRO+
    "attack_navigator",
})

# PRO tier: everything PUBLIC gets + premium analytical content
PRO_ALLOWED_FIELDS: FrozenSet[str] = PUBLIC_ALLOWED_FIELDS | frozenset({
    "report_url",
    "internal_report_url",
    "pdf_url",
    "ioc_counts",
    "ioc_list",
    "indicators",
    "sigma_rules",
    "yara_rules",
    "kql_queries",
    "suricata_rules",
    "detection_rules",
    "ai_analysis",
    "apex_ai",
    "threat_context",
    "campaign_intelligence",
    "kill_chain",
    "behavioral_tags",
    "mitre_techniques",
    "attack_navigator",
    "cvss_score",
    "epss_score",
    "actor_tag",
    "actor_profile",
    "full_mitre_mapping",
})

# ENTERPRISE tier: PRO + everything for API/integration layer
ENTERPRISE_ALLOWED_FIELDS: FrozenSet[str] = PRO_ALLOWED_FIELDS | frozenset({
    "stix_bundle",
    "stix_bundle_url",
    "full_stix",
    "misp_event",
    "enterprise_feeds",
    "full_iocs",
    "full_detection_content",
    "full_actor_intelligence",
    "full_ai_analysis",
    "gumroad_url",
    "webhook_config",
    "bulk_export",
    "api_access",
})

# MSSP tier: everything ENTERPRISE + white-label/tenant fields
MSSP_ALLOWED_FIELDS: FrozenSet[str] = ENTERPRISE_ALLOWED_FIELDS | frozenset({
    "tenant_id",
    "white_label_config",
    "managed_feed_config",
    "soc_integration_token",
    "detection_pack",
    "mssp_branding",
    "multi_tenant_routing",
})

TIER_ALLOWED_FIELDS: Dict[str, FrozenSet[str]] = {
    TIER_PUBLIC:     PUBLIC_ALLOWED_FIELDS,
    TIER_PRO:        PRO_ALLOWED_FIELDS,
    TIER_ENTERPRISE: ENTERPRISE_ALLOWED_FIELDS,
    TIER_MSSP:       MSSP_ALLOWED_FIELDS,
}

# ═══════════════════════════════════════════════════════════════════════════════
# FEATURE PERMISSIONS — what capabilities each tier may invoke
# ═══════════════════════════════════════════════════════════════════════════════

TIER_FEATURES: Dict[str, Set[str]] = {
    TIER_PUBLIC: {
        "view_summary",
        "view_dashboard_card",
        "view_executive_summary",
        "view_basic_mitre",
        "view_risk_score",
        "view_severity",
        "view_source",
        "view_date",
        "view_actor_tag",
        "public_api_access",
    },
    TIER_PRO: {
        # Inherits all PUBLIC features + PRO features
        "view_full_report",
        "view_full_ai_analysis",
        "view_full_mitre_mapping",
        "view_detection_rules",
        "view_sigma",
        "view_yara",
        "view_kql",
        "view_suricata",
        "view_ioc_intelligence",
        "view_campaign_intelligence",
        "view_threat_context",
        "view_kill_chain",
        "view_actor_profile",
        "export_pdf",
        "pro_api_access",
    },
    TIER_ENTERPRISE: {
        # Inherits all PRO features + ENTERPRISE features
        "export_stix",
        "export_misp",
        "export_opencti",
        "api_access",
        "siem_integration",
        "webhook_access",
        "bulk_export",
        "threat_feed_syndication",
        "enterprise_api_access",
    },
    TIER_MSSP: {
        # Inherits all ENTERPRISE features + MSSP features
        "white_label",
        "multi_tenant",
        "managed_feeds",
        "detection_pack_distribution",
        "soc_integration",
        "mssp_api_access",
    },
}

# Flatten: each tier includes all features of lower tiers
def _build_cumulative_features() -> Dict[str, Set[str]]:
    result: Dict[str, Set[str]] = {}
    ordered = [TIER_PUBLIC, TIER_PRO, TIER_ENTERPRISE, TIER_MSSP]
    accumulated: Set[str] = set()
    for tier in ordered:
        accumulated = accumulated | TIER_FEATURES[tier]
        result[tier] = set(accumulated)
    return result


TIER_CUMULATIVE_FEATURES: Dict[str, Set[str]] = _build_cumulative_features()

# ═══════════════════════════════════════════════════════════════════════════════
# API RESPONSE GUARDRAILS — fields NEVER allowed in any public API response
# ═══════════════════════════════════════════════════════════════════════════════

API_PUBLIC_BLOCKED: FrozenSet[str] = frozenset({
    "full_iocs",
    "full_detection_content",
    "full_actor_intelligence",
    "full_stix",
    "enterprise_feeds",
    "report_url",
    "internal_report_url",
    "stix_bundle_url",
    "pdf_url",
})

# ═══════════════════════════════════════════════════════════════════════════════
# REPORT METADATA REQUIREMENTS
# Every generated report MUST include these fields.
# ═══════════════════════════════════════════════════════════════════════════════

REQUIRED_REPORT_FIELDS: FrozenSet[str] = frozenset({
    "classification",
    "required_tier",
    "access_policy",
})

REPORT_TIER_CLASSIFICATIONS: Dict[str, Dict[str, str]] = {
    "summary": {
        "classification":  "TLP:GREEN",
        "required_tier":   TIER_PUBLIC,
        "access_policy":   "MODEL_C_PUBLIC",
    },
    "full": {
        "classification":  "TLP:AMBER",
        "required_tier":   TIER_PRO,
        "access_policy":   "MODEL_C_PRO",
    },
    "enterprise": {
        "classification":  "TLP:RED",
        "required_tier":   TIER_ENTERPRISE,
        "access_policy":   "MODEL_C_ENTERPRISE",
    },
    "mssp": {
        "classification":  "TLP:RED+MSSP",
        "required_tier":   TIER_MSSP,
        "access_policy":   "MODEL_C_MSSP",
    },
}

# Summary field limits for PUBLIC tier
SUMMARY_MAX_CHARS = 500   # executive_summary truncation at public tier

# ═══════════════════════════════════════════════════════════════════════════════
# CORE POLICY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_tier(raw_tier: str) -> str:
    """Normalize any incoming tier string to canonical form. Unknown → PUBLIC."""
    if raw_tier in TIER_ORDER:
        return raw_tier
    normalized = TIER_ALIAS.get(raw_tier) or TIER_ALIAS.get(raw_tier.upper())
    if normalized:
        return normalized
    logger.warning(f"[ACCESS-POLICY] Unknown tier '{raw_tier}' — defaulting to PUBLIC")
    return TIER_PUBLIC


def tier_meets_requirement(user_tier: str, required_tier: str) -> bool:
    """
    Return True if user_tier has sufficient privilege for required_tier.
    Both arguments are normalized before comparison.
    """
    ut = normalize_tier(user_tier)
    rt = normalize_tier(required_tier)
    return TIER_ORDER.get(ut, 0) >= TIER_ORDER.get(rt, 0)


def has_feature(user_tier: str, feature: str) -> bool:
    """Return True if user_tier is permitted to use the named feature."""
    ut = normalize_tier(user_tier)
    return feature in TIER_CUMULATIVE_FEATURES.get(ut, set())


def strip_for_tier(data: Dict, user_tier: str) -> Dict:
    """
    Return a copy of `data` with all fields not permitted for `user_tier` removed.
    Also truncates executive_summary for PUBLIC tier.
    Always deny-by-default for PUBLIC_BLOCKED_FIELDS.
    """
    ut = normalize_tier(user_tier)
    allowed = TIER_ALLOWED_FIELDS.get(ut, PUBLIC_ALLOWED_FIELDS)

    stripped = {k: v for k, v in data.items() if k in allowed}

    # Enforce PUBLIC_BLOCKED regardless of allowed-set (belt-and-suspenders)
    if ut == TIER_PUBLIC:
        for blocked_key in PUBLIC_BLOCKED_FIELDS:
            stripped.pop(blocked_key, None)
        # Truncate executive_summary
        if "executive_summary" in stripped and isinstance(stripped["executive_summary"], str):
            if len(stripped["executive_summary"]) > SUMMARY_MAX_CHARS:
                stripped["executive_summary"] = (
                    stripped["executive_summary"][:SUMMARY_MAX_CHARS] + "…"
                )

    return stripped


def validate_api_response(response: Dict, user_tier: str) -> tuple[bool, List[str]]:
    """
    Validate an outgoing API response payload.
    Returns (is_valid, list_of_violations).
    A non-empty violation list means the response MUST be blocked.
    """
    ut = normalize_tier(user_tier)
    violations: List[str] = []

    if ut == TIER_PUBLIC:
        for blocked in API_PUBLIC_BLOCKED:
            if blocked in response:
                violations.append(
                    f"PUBLIC_TIER_FIELD_VIOLATION: '{blocked}' must not appear in public API response"
                )
            # Also scan nested 'entries' array
            for entry in response.get("entries", []) + response.get("results", []):
                if isinstance(entry, dict) and blocked in entry:
                    violations.append(
                        f"PUBLIC_TIER_ENTRY_VIOLATION: entry contains blocked field '{blocked}'"
                    )
                    break

    return len(violations) == 0, violations


def validate_report_metadata(report_meta: Dict) -> tuple[bool, List[str]]:
    """
    Validate that a generated report includes all required governance fields.
    Returns (is_valid, list_of_missing_fields).
    """
    missing = [f for f in REQUIRED_REPORT_FIELDS if f not in report_meta]
    return len(missing) == 0, missing


def get_report_classification(report_type: str) -> Dict[str, str]:
    """
    Return the canonical classification metadata for a given report type.
    report_type: 'summary' | 'full' | 'enterprise' | 'mssp'
    """
    meta = REPORT_TIER_CLASSIFICATIONS.get(report_type)
    if not meta:
        logger.warning(f"[ACCESS-POLICY] Unknown report_type '{report_type}' — defaulting to 'full'")
        meta = REPORT_TIER_CLASSIFICATIONS["full"]
    return dict(meta)


def assert_dashboard_card_safe(card_data: Dict) -> tuple[bool, List[str]]:
    """
    Validate that a dashboard card payload is safe for PUBLIC render.
    The card must NOT contain report_url, pdf_url, or any blocked field.
    Returns (is_safe, violations).
    """
    violations: List[str] = []
    for blocked in PUBLIC_BLOCKED_FIELDS:
        if blocked in card_data and card_data[blocked]:
            violations.append(
                f"DASHBOARD_CARD_VIOLATION: public card contains blocked field '{blocked}'"
            )
    return len(violations) == 0, violations


def build_upgrade_prompt(feature: str, user_tier: str = TIER_PUBLIC) -> Dict[str, str]:
    """
    Build a standardized upgrade prompt when a user attempts to access a
    feature above their tier.
    """
    ut = normalize_tier(user_tier)

    # Determine minimum tier needed
    required = TIER_PUBLIC
    for tier in [TIER_PUBLIC, TIER_PRO, TIER_ENTERPRISE, TIER_MSSP]:
        if feature in TIER_CUMULATIVE_FEATURES.get(tier, set()):
            required = tier
            break

    return {
        "access_denied":  True,
        "required_tier":  required,
        "current_tier":   ut,
        "feature":        feature,
        "upgrade_url":    "/upgrade.html",
        "message": (
            f"This content requires {required} tier access. "
            f"Your current tier: {ut}. "
            f"Upgrade at /upgrade.html"
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# DEPLOYMENT GATE CHECKS
# Called by deployment_gate.py before any deployment is allowed.
# ═══════════════════════════════════════════════════════════════════════════════

def run_policy_checks() -> Dict:
    """
    Run all policy self-checks. Returns a result dict with pass/fail per check.
    This is called by the deployment gate.
    """
    results: Dict = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "policy_version":"v173.0",
        "checks": {},
        "passed":        True,
    }

    def _check(name: str, passed: bool, detail: str = ""):
        results["checks"][name] = {"passed": passed, "detail": detail}
        if not passed:
            results["passed"] = False

    # 1. PUBLIC tier cannot receive report_url
    _check(
        "public_blocked_report_url",
        "report_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC],
        "report_url must not be in PUBLIC allowed fields",
    )

    # 2. PUBLIC tier cannot receive internal_report_url
    _check(
        "public_blocked_internal_report_url",
        "internal_report_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC],
        "internal_report_url must not be in PUBLIC allowed fields",
    )

    # 3. PUBLIC tier cannot receive IOC data
    _check(
        "public_blocked_iocs",
        "full_iocs" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC]
        and "iocs" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC],
        "IOC fields must not be in PUBLIC allowed fields",
    )

    # 4. PUBLIC tier cannot receive detection content
    _check(
        "public_blocked_detection_content",
        all(
            f not in TIER_ALLOWED_FIELDS[TIER_PUBLIC]
            for f in ["sigma_rules", "yara_rules", "kql_queries", "suricata_rules"]
        ),
        "Detection rule fields must not be in PUBLIC allowed fields",
    )

    # 5. PUBLIC tier cannot receive STIX
    _check(
        "public_blocked_stix",
        "stix_bundle" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC]
        and "full_stix" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC],
        "STIX fields must not be in PUBLIC allowed fields",
    )

    # 6. PRO tier gets report_url
    _check(
        "pro_allows_report_url",
        "report_url" in TIER_ALLOWED_FIELDS[TIER_PRO],
        "PRO tier must have access to report_url",
    )

    # 7. ENTERPRISE tier gets STIX
    _check(
        "enterprise_allows_stix",
        "stix_bundle" in TIER_ALLOWED_FIELDS[TIER_ENTERPRISE],
        "ENTERPRISE tier must have access to stix_bundle",
    )

    # 8. view_full_report feature requires PRO or higher
    _check(
        "view_full_report_requires_pro",
        "view_full_report" not in TIER_CUMULATIVE_FEATURES[TIER_PUBLIC]
        and "view_full_report" in TIER_CUMULATIVE_FEATURES[TIER_PRO],
        "view_full_report must require PRO tier",
    )

    # 9. Tier hierarchy is monotonically increasing
    tiers_in_order = [TIER_PUBLIC, TIER_PRO, TIER_ENTERPRISE, TIER_MSSP]
    hierarchy_valid = all(
        TIER_ORDER[tiers_in_order[i]] < TIER_ORDER[tiers_in_order[i + 1]]
        for i in range(len(tiers_in_order) - 1)
    )
    _check("tier_hierarchy_monotonic", hierarchy_valid, "Tier order must be strictly increasing")

    # 10. Required report fields are defined
    _check(
        "required_report_fields_defined",
        len(REQUIRED_REPORT_FIELDS) >= 3,
        "classification, required_tier, access_policy must all be defined",
    )

    results["total_checks"]  = len(results["checks"])
    results["checks_passed"] = sum(1 for c in results["checks"].values() if c["passed"])
    results["checks_failed"] = results["total_checks"] - results["checks_passed"]

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY DRIFT DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

# The canonical hash of this policy's core data structures.
# Generated by compute_policy_hash(). If this changes unexpectedly, a drift
# alert is raised in the deployment gate.
POLICY_CANONICAL_VERSION = "v173.0"

def compute_policy_hash() -> str:
    """
    Compute a deterministic hash of the core policy structures.
    Used to detect unauthorized modifications (policy drift).
    """
    policy_data = {
        "PUBLIC_BLOCKED":     sorted(PUBLIC_BLOCKED_FIELDS),
        "PUBLIC_ALLOWED":     sorted(PUBLIC_ALLOWED_FIELDS),
        "API_PUBLIC_BLOCKED": sorted(API_PUBLIC_BLOCKED),
        "REQUIRED_REPORT_FIELDS": sorted(REQUIRED_REPORT_FIELDS),
        "TIER_ORDER":         TIER_ORDER,
        "REPORT_CLASSIFICATIONS": {
            k: dict(v) for k, v in REPORT_TIER_CLASSIFICATIONS.items()
        },
        "VERSION": POLICY_CANONICAL_VERSION,
    }
    serialized = json.dumps(policy_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# Compute hash at import time — used by drift detector
_POLICY_HASH_AT_IMPORT: str = compute_policy_hash()


def detect_policy_drift(reference_hash: Optional[str] = None) -> Dict:
    """
    Compare current policy hash against a reference.
    If no reference supplied, uses _POLICY_HASH_AT_IMPORT (startup baseline).
    Returns drift report dict.
    """
    current_hash = compute_policy_hash()
    ref = reference_hash or _POLICY_HASH_AT_IMPORT
    drifted = current_hash != ref

    return {
        "drift_detected":     drifted,
        "current_hash":       current_hash,
        "reference_hash":     ref,
        "checked_at":         datetime.now(timezone.utc).isoformat(),
        "policy_version":     POLICY_CANONICAL_VERSION,
        "governance_message": (
            "POLICY DRIFT DETECTED — DEPLOYMENT BLOCKED" if drifted
            else "Policy integrity verified — no drift"
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# AUDIT RECORD
# ═══════════════════════════════════════════════════════════════════════════════

def generate_audit_record() -> Dict:
    """Generate a full audit snapshot of the current policy state."""
    return {
        "schema_version":       "1.0",
        "generated_at":         datetime.now(timezone.utc).isoformat(),
        "policy_version":       POLICY_CANONICAL_VERSION,
        "policy_hash":          compute_policy_hash(),
        "tiers": {
            tier: {
                "order":        TIER_ORDER[tier],
                "allowed_field_count": len(TIER_ALLOWED_FIELDS[tier]),
                "feature_count":       len(TIER_CUMULATIVE_FEATURES[tier]),
            }
            for tier in TIER_ORDER
        },
        "governance": {
            "model_a_disabled":  True,
            "model_b_disabled":  True,
            "model_c_canonical": True,
            "single_source_of_truth": "access_control_policy.py",
        },
        "report_classifications": REPORT_TIER_CLASSIFICATIONS,
        "public_blocked_field_count": len(PUBLIC_BLOCKED_FIELDS),
        "api_public_blocked_field_count": len(API_PUBLIC_BLOCKED),
        "deployment_gate_checks": run_policy_checks()["checks"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# SELF-CHECK ON IMPORT
# ═══════════════════════════════════════════════════════════════════════════════

def _self_check_on_import() -> None:
    """Run critical invariant checks at import time. Raise on failure."""
    # MODEL_B invariant: report_url must NEVER reach PUBLIC tier
    assert "report_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
        "FATAL: report_url in PUBLIC allowed fields — MODEL_B violation"
    assert "internal_report_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
        "FATAL: internal_report_url in PUBLIC allowed fields — MODEL_B violation"
    assert "stix_bundle_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
        "FATAL: stix_bundle_url in PUBLIC allowed fields — MODEL_B violation"

    # MODEL_B invariant: full IOC/detection/STIX must NEVER reach PUBLIC tier
    for field in ("full_iocs", "sigma_rules", "yara_rules", "stix_bundle", "full_stix"):
        assert field not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
            f"FATAL: '{field}' in PUBLIC allowed fields — MODEL_B violation"

    # Tier ordering must be strictly increasing
    tiers = [TIER_PUBLIC, TIER_PRO, TIER_ENTERPRISE, TIER_MSSP]
    for i in range(len(tiers) - 1):
        assert TIER_ORDER[tiers[i]] < TIER_ORDER[tiers[i + 1]], \
            f"FATAL: Tier hierarchy broken at {tiers[i]} → {tiers[i+1]}"

    logger.debug("[ACCESS-POLICY] Import self-check passed — policy integrity verified")


_self_check_on_import()
