#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Commercial Readiness Governor v1.0.0
======================================================================
Implements all 10 Commercial Readiness Mandates.

Mandate 1  — Publication Enforcement   (BLOCK → quarantine, never publish)
Mandate 2  — Attribution Enforcement   (banned actors → null)
Mandate 3  — ATT&CK Enforcement        (technique_ids without evidence → clear)
Mandate 4  — Risk Engine Enforcement   (CRITICAL/HIGH risk=0 → floor)
Mandate 5  — IOC Enforcement           (real_ioc_count derived; misleading counts zeroed)
Mandate 6  — Premium Content Enforce.  (grade F/D items cannot generate premium)
Mandate 7  — API Contract Enforcement  (missing fields → publication denied)
Mandate 8  — Commercial Feed Filters   (Enterprise=A/B, MSSP=A/B/C, Public=A/B/C/D)
Mandate 9  — Dashboard Governance      (KPIs count published items only)
Mandate 10 — GO-LIVE Criteria          (return structured readiness JSON)

Outputs:
  api/feed.json                     — clean full governed feed (no BLOCK items)
  api/feed_public.json              — Grade A/B/C/D only (free tier)
  api/feed_mssp.json                — Grade A/B/C only
  api/feed_enterprise.json          — Grade A/B only
  internal/governance/quarantine.json  — all BLOCK items
  api/governance_status.json        — GO-LIVE criteria result
  data/health/commercial_readiness_governor_report.json

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
GOVERNOR_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [commercial_governor] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Mandate 2: banned actor names and tags ────────────────────────────────────
BANNED_ACTOR_NAMES: frozenset = frozenset([
    "web application threat cluster",
    "vulnerability exploitation cluster",
    "unknown threat actor",
    "untracked threat cluster",
    "unattributed apt cluster",
    "unc-cdb",
    "unattributed threat actor",
    "unknown state-sponsored actor",
    "unknown actor",
    "unattributed",
    "synthetic actor",
])
BANNED_ACTOR_TAG_PREFIXES: Tuple[str, ...] = ("CDB-UNATTR-", "UNC-CDB")

# ── Mandate 3: ATT&CK fields to clear when unverified ────────────────────────
ATTCK_ID_FIELDS = ("attck_technique_ids", "attck_tactics", "actor_ttps", "ttps")

# ── Mandate 4: minimum risk floors ───────────────────────────────────────────
RISK_FLOOR = {
    "CRITICAL": 8.5,
    "HIGH": 7.0,
}
# Additional triggers for floor regardless of severity
KEV_RISK_FLOOR = 7.0
CVSS_CRITICAL_FLOOR = 9.0   # CVSS >= this → floor 8.5
CVSS_HIGH_FLOOR = 7.0       # CVSS >= this (< CRITICAL_FLOOR) → floor 7.0

# ── Mandate 5: operational IOC patterns ──────────────────────────────────────
# Patterns that indicate a FALSE-POSITIVE (advisory/vendor URL, not operational)
FP_IOC_PATTERNS: Tuple[str, ...] = (
    r"nvd\.nist\.gov",
    r"cve\.mitre\.org",
    r"vulners\.com",
    r"cvefeed\.io",
    r"cz\.nic",
    r"\.microsoft\.com/security",
    r"cisa\.gov/known-exploited",
    r"cert\.org/advisories",
    r"blog\.",
    r"advisory",
    r"github\.com/advisories",
    r"securityadvisories\.",
)

# ── Mandate 7: required API contract fields ───────────────────────────────────
CONTRACT_FIELDS = (
    "publication_decision",
    "intelligence_grade",
    "evidence_count",
    "corroboration_count",
    "attribution_status",
    "campaign_status",
    "ioc_quality_score",
    "attck_verification",
    "risk_score_reasoning",
    "analyst_verdict",
)

# ── Mandate 8: tier grade allowlists ─────────────────────────────────────────
TIER_GRADES = {
    "enterprise": frozenset(["A", "B"]),
    "mssp":       frozenset(["A", "B", "C"]),
    "public":     frozenset(["A", "B", "C", "D"]),
}
PUBLISHABLE_DECISIONS = frozenset(["ALLOW", "ALLOW_WITH_WARNING"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def _is_banned_actor(item: Dict) -> bool:
    """Return True if any actor field contains a banned identifier."""
    fields = [
        item.get("actor") or "",
        item.get("actor_tag") or "",
        item.get("actor_name") or "",
        item.get("actor_display_name") or "",
    ]
    text = " ".join(str(f).lower() for f in fields)
    # Check banned names
    for banned in BANNED_ACTOR_NAMES:
        if banned in text:
            return True
    # Check banned tag prefixes
    for field in fields:
        for prefix in BANNED_ACTOR_TAG_PREFIXES:
            if str(field).startswith(prefix):
                return True
    return False


def _is_operational_ioc(value: str) -> bool:
    """Return True if a string looks like a real operational indicator."""
    if not value or not isinstance(value, str):
        return False
    # Skip false positives
    for pattern in FP_IOC_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            return False
    # Rough checks for operational IOCs
    # IPv4
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", value):
        return True
    # Domain (not a URL, not a known FP)
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$", value):
        return True
    # Hash (MD5/SHA1/SHA256)
    if re.match(r"^[0-9a-fA-F]{32}$", value) or \
       re.match(r"^[0-9a-fA-F]{40}$", value) or \
       re.match(r"^[0-9a-fA-F]{64}$", value):
        return True
    # URL (operational, not advisory)
    if value.startswith(("http://", "https://")) and not any(
        re.search(p, value, re.IGNORECASE) for p in FP_IOC_PATTERNS
    ):
        return True
    # Email
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return True
    return False


def _count_real_iocs(item: Dict) -> int:
    """Count genuine operational IOCs in an item."""
    count = 0
    for field in ("iocs", "indicators", "observables"):
        ioc_list = item.get(field) or []
        if isinstance(ioc_list, list):
            for ioc in ioc_list:
                val = ioc.get("value", "") if isinstance(ioc, dict) else str(ioc)
                if _is_operational_ioc(val):
                    count += 1
    # Fallback: check if item has explicit operational IP/domain/hash fields
    for field in ("ip", "domain", "hash", "url", "email"):
        val = item.get(field)
        if val and _is_operational_ioc(str(val)):
            count += 1
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Mandate 2 — Attribution Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def enforce_attribution(item: Dict) -> Tuple[Dict, List[str]]:
    """Null out banned/unverified actor fields. Return (patched_item, audit_log)."""
    log_entries: List[str] = []
    if _is_banned_actor(item):
        banned_val = item.get("actor") or item.get("actor_display_name") or "unknown"
        item["actor"] = None
        item["actor_tag"] = None
        item["actor_name"] = None
        item["actor_display_name"] = None
        item["actor_aliases"] = []
        item["actor_country"] = None
        item["actor_motivation"] = None
        item["actor_sectors"] = []
        item["actor_ttps"] = []
        item["actor_malware"] = []
        item["actor_mitre_id"] = None
        item["actor_threat_level"] = None
        item["verified_actor"] = False
        item["attribution_status"] = "NONE"
        log_entries.append(f"M2: Banned actor '{str(banned_val)[:60]}' nulled — attribution_status=NONE")
    elif not item.get("verified_actor"):
        # Not verified — reflect in attribution_status
        item.setdefault("attribution_status", "UNVERIFIED")
        item["verified_actor"] = False
    return item, log_entries


# ─────────────────────────────────────────────────────────────────────────────
# Mandate 3 — ATT&CK Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def enforce_attck(item: Dict) -> Tuple[Dict, List[str]]:
    """
    If ATT&CK not verified: clear technique_ids and tactics.
    If verified: ensure source_reference, mapping_reason, verification_status present.
    """
    log_entries: List[str] = []
    verification = item.get("attck_verification") or ""
    has_ids = bool(item.get("attck_technique_ids"))
    has_techniques = bool(item.get("attck_techniques"))

    if verification in ("NOT_MAPPED", "NOT_VERIFIED", "", None):
        # No verified ATT&CK — clear ALL technique fields
        if has_ids or has_techniques:
            item["attck_technique_ids"] = []
            item["attck_techniques"] = []
            item["attck_tactics"] = []
            item["mitre_tactics"] = []
            item["ttps"] = []
            log_entries.append(
                f"M3: attck_technique_ids cleared — verification={verification!r} (no evidence)"
            )
        item["attck_verification"] = "NOT_VERIFIED"
    else:
        # Verified — ensure required citation fields on each technique
        techniques = item.get("attck_techniques") or []
        patched_techs = []
        for tech in techniques:
            if isinstance(tech, dict):
                tech.setdefault("source_reference", "")
                tech.setdefault("mapping_reason", "")
                tech.setdefault("verification_status", verification)
            patched_techs.append(tech)
        item["attck_techniques"] = patched_techs

    return item, log_entries


# ─────────────────────────────────────────────────────────────────────────────
# Mandate 4 — Risk Engine Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def enforce_risk_score(item: Dict) -> Tuple[Dict, List[str]]:
    """Apply minimum risk floor for CRITICAL/HIGH and evidence triggers."""
    log_entries: List[str] = []
    current_risk = _safe_float(item.get("risk_score"))
    severity = str(item.get("severity") or "").upper()
    cvss = _safe_float(item.get("cvss_score") or item.get("cvss"))
    kev = bool(item.get("kev"))
    active_exploit = bool(item.get("active_exploitation") or item.get("exploited_in_wild"))

    floor = 0.0
    floor_reason: List[str] = []

    if severity == "CRITICAL":
        floor = max(floor, RISK_FLOOR["CRITICAL"])
        floor_reason.append(f"severity=CRITICAL → floor {RISK_FLOOR['CRITICAL']}")
    elif severity == "HIGH":
        floor = max(floor, RISK_FLOOR["HIGH"])
        floor_reason.append(f"severity=HIGH → floor {RISK_FLOOR['HIGH']}")

    if cvss >= CVSS_CRITICAL_FLOOR:
        floor = max(floor, RISK_FLOOR["CRITICAL"])
        floor_reason.append(f"CVSS={cvss:.1f} ≥ {CVSS_CRITICAL_FLOOR} → floor {RISK_FLOOR['CRITICAL']}")
    elif cvss >= CVSS_HIGH_FLOOR:
        floor = max(floor, RISK_FLOOR["HIGH"])
        floor_reason.append(f"CVSS={cvss:.1f} ≥ {CVSS_HIGH_FLOOR} → floor {RISK_FLOOR['HIGH']}")

    if kev:
        floor = max(floor, KEV_RISK_FLOOR)
        floor_reason.append(f"KEV=true → floor {KEV_RISK_FLOOR}")
    if active_exploit:
        floor = max(floor, KEV_RISK_FLOOR)
        floor_reason.append(f"active_exploitation=true → floor {KEV_RISK_FLOOR}")

    if floor > 0 and current_risk < floor:
        item["risk_score"] = floor
        msg = f"M4: risk_score raised {current_risk:.1f}→{floor:.1f} [{'; '.join(floor_reason)}]"
        log_entries.append(msg)

    # Ensure risk_score_reasoning is a non-empty string
    existing_reasoning = item.get("risk_score_reasoning")
    if not existing_reasoning or (isinstance(existing_reasoning, dict) and not existing_reasoning):
        item["risk_score_reasoning"] = (
            "; ".join(floor_reason) if floor_reason
            else f"deterministic: severity={severity} cvss={cvss:.1f} kev={kev}"
        )
    elif isinstance(existing_reasoning, dict):
        # Convert dict to string summary
        item["risk_score_reasoning"] = json.dumps(existing_reasoning)

    return item, log_entries


# ─────────────────────────────────────────────────────────────────────────────
# Mandate 5 — IOC Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def enforce_ioc_fields(item: Dict) -> Tuple[Dict, List[str]]:
    """Compute real_ioc_count. If 0, zero out misleading ioc_count."""
    log_entries: List[str] = []
    real_count = _count_real_iocs(item)
    item["real_ioc_count"] = real_count

    if real_count == 0:
        old_ioc_count = item.get("ioc_count", 0)
        if old_ioc_count and int(old_ioc_count) > 0:
            # ioc_count was non-zero but no real IOCs found — it was advisory/ref URLs
            item["ioc_count_raw"] = old_ioc_count  # preserve original for audit
            item["ioc_count"] = 0
            log_entries.append(
                f"M5: ioc_count zeroed ({old_ioc_count}→0) — no operational indicators found"
            )

    return item, log_entries


# ─────────────────────────────────────────────────────────────────────────────
# Mandate 7 — API Contract Enforcement
# ─────────────────────────────────────────────────────────────────────────────

def enforce_contract(item: Dict) -> Tuple[bool, List[str]]:
    """Return (contract_met, missing_fields). Publication denied if not met."""
    missing = [f for f in CONTRACT_FIELDS if f not in item]
    return (len(missing) == 0), missing


# ─────────────────────────────────────────────────────────────────────────────
# Mandate 6 — Premium Content Enforcement
# ─────────────────────────────────────────────────────────────────────────────

GRADE_CONTENT_TIER = {
    "A": "executive_intelligence_package",
    "B": "enterprise_dossier",
    "C": "standard_report",
    "D": "short_bulletin",
    "F": "advisory_only",
}
PREMIUM_GRADES = frozenset(["A", "B"])
ENTERPRISE_GRADES = frozenset(["A", "B"])
MSSP_GRADES = frozenset(["A", "B", "C"])

def enforce_premium_content(item: Dict) -> Tuple[Dict, List[str]]:
    """Tag item with allowed content tier. Revoke premium flags for D/F."""
    log_entries: List[str] = []
    grade = item.get("intelligence_grade", "F")
    content_tier = GRADE_CONTENT_TIER.get(grade, "advisory_only")
    item["allowed_content_tier"] = content_tier
    item["premium_eligible"] = grade in PREMIUM_GRADES
    item["enterprise_eligible"] = grade in ENTERPRISE_GRADES
    item["mssp_eligible"] = grade in MSSP_GRADES

    if grade in ("D", "F") and item.get("premium_content"):
        item["premium_content"] = None
        log_entries.append(f"M6: premium_content removed — grade {grade} not eligible")
    if grade == "F" and item.get("tactical_dossier"):
        item["tactical_dossier"] = None
        log_entries.append("M6: tactical_dossier removed — grade F only eligible for advisory")
    if grade == "F" and item.get("executive_report"):
        item["executive_report"] = None
        log_entries.append("M6: executive_report removed — grade F not eligible")

    return item, log_entries


# ─────────────────────────────────────────────────────────────────────────────
# Mandate 1 — Publication Enforcement + Quarantine
# ─────────────────────────────────────────────────────────────────────────────

def enforce_publication_decision(item: Dict) -> Tuple[bool, Dict]:
    """
    Return (should_publish, quarantine_record).
    BLOCK or QUARANTINE → do not publish, send to quarantine.
    """
    decision = item.get("publication_decision", "BLOCK")
    contract_met, missing = enforce_contract(item)

    if not contract_met:
        # Mandate 7: missing contract fields = deny publication
        item["publication_decision"] = "BLOCK"
        item["publication_block_reason"] = f"M7: Missing contract fields: {missing}"
        decision = "BLOCK"

    if decision in ("BLOCK", "QUARANTINE"):
        quarantine_record = {
            "id": item.get("id") or item.get("stix_id", ""),
            "title": item.get("title", ""),
            "publication_decision": decision,
            "intelligence_grade": item.get("intelligence_grade", ""),
            "block_reasons": item.get("block_reasons") or item.get("publication_block_reason", ""),
            "analyst_verdict": item.get("analyst_verdict", ""),
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "mandates_triggered": [],
        }
        return False, quarantine_record

    return True, {}


# ─────────────────────────────────────────────────────────────────────────────
# Core governor: apply all mandates to a single item
# ─────────────────────────────────────────────────────────────────────────────

def govern_item(item: Dict) -> Tuple[Dict, bool, Dict, List[str]]:
    """
    Apply all 10 mandates to a single item.
    Returns: (governed_item, should_publish, quarantine_record, audit_log)
    """
    audit: List[str] = []
    item = dict(item)  # defensive copy

    # M2 — Attribution
    item, log2 = enforce_attribution(item)
    audit.extend(log2)

    # M3 — ATT&CK
    item, log3 = enforce_attck(item)
    audit.extend(log3)

    # M4 — Risk score floor
    item, log4 = enforce_risk_score(item)
    audit.extend(log4)

    # M5 — IOC fields
    item, log5 = enforce_ioc_fields(item)
    audit.extend(log5)

    # M6 — Premium content
    item, log6 = enforce_premium_content(item)
    audit.extend(log6)

    # M1 + M7 — Publication decision (must be last — reads results of all above)
    should_publish, quarantine_record = enforce_publication_decision(item)
    if not should_publish:
        # Tag mandates triggered
        triggered = []
        if log2: triggered.append("M2")
        if log3: triggered.append("M3")
        if log4: triggered.append("M4")
        quarantine_record["mandates_triggered"] = triggered
        audit.append(f"M1: item quarantined — decision={item.get('publication_decision')}")

    # Stamp with governor metadata
    item["governor_version"] = GOVERNOR_VERSION
    item["governed_at"] = datetime.now(timezone.utc).isoformat()
    if audit:
        item["governor_audit_log"] = audit

    return item, should_publish, quarantine_record, audit


# ─────────────────────────────────────────────────────────────────────────────
# Process entire feed
# ─────────────────────────────────────────────────────────────────────────────

def process_feed(items: List[Dict]) -> Dict:
    """
    Apply governance to all items.
    Returns result dict with all tier feeds + quarantine + metrics.
    """
    published: List[Dict] = []
    quarantine: List[Dict] = []

    m2_violations = 0
    m3_violations = 0
    m4_violations = 0
    m5_violations = 0

    for raw_item in items:
        governed, should_publish, q_record, audit = govern_item(raw_item)

        if any("M2:" in a for a in audit): m2_violations += 1
        if any("M3:" in a for a in audit): m3_violations += 1
        if any("M4:" in a for a in audit): m4_violations += 1
        if any("M5:" in a for a in audit): m5_violations += 1

        if should_publish:
            published.append(governed)
        else:
            quarantine.append(q_record)

    # M8 — Tier splits
    feed_enterprise = [i for i in published if i.get("intelligence_grade") in TIER_GRADES["enterprise"]]
    feed_mssp = [i for i in published if i.get("intelligence_grade") in TIER_GRADES["mssp"]]
    feed_public = [i for i in published if i.get("intelligence_grade") in TIER_GRADES["public"]]

    # M9 — Dashboard KPIs (only published)
    grade_dist = Counter(i.get("intelligence_grade", "?") for i in published)
    decision_dist = Counter(i.get("publication_decision", "?") for i in published)
    severity_dist = Counter(i.get("severity", "?") for i in published)

    # M10 — GO-LIVE criteria
    synthetic_actors = sum(1 for i in published if _is_banned_actor(i))
    synthetic_campaigns = sum(1 for i in published if str(i.get("campaign_status", "")) == "SYNTHETIC")
    attck_conflicts = sum(
        1 for i in published
        if i.get("attck_technique_ids") and i.get("attck_verification") in ("NOT_MAPPED", "NOT_VERIFIED", None, "")
    )
    risk_conflicts = sum(
        1 for i in published
        if i.get("severity") in ("CRITICAL", "HIGH") and _safe_float(i.get("risk_score")) == 0
    )
    publication_conflicts = sum(
        1 for i in published
        if i.get("publication_decision") == "BLOCK"
    )
    contract_compliant = sum(1 for i in published if enforce_contract(i)[0])
    contract_compliance_pct = int(contract_compliant / max(len(published), 1) * 100)
    real_ioc_total = sum(i.get("real_ioc_count", 0) for i in published)

    dashboard_go = (publication_conflicts == 0)
    cti_api_go = (contract_compliance_pct == 100)
    mssp_go = (real_ioc_total > 0 and len(feed_mssp) > 0)
    enterprise_go = (
        synthetic_actors == 0
        and synthetic_campaigns == 0
        and attck_conflicts == 0
        and risk_conflicts == 0
        and publication_conflicts == 0
        and len(feed_enterprise) > 0
    )

    # Commercial readiness score
    score = 0
    score += 20 if dashboard_go else 0
    score += 20 if cti_api_go else 0
    score += 20 if mssp_go else 0
    score += 20 if enterprise_go else 0
    score += 10 if synthetic_actors == 0 else 0
    score += 10 if attck_conflicts == 0 else 0

    go_live = {
        "dashboard_status":    "GO" if dashboard_go else "NO-GO",
        "cti_api_status":      "GO" if cti_api_go else "NO-GO",
        "mssp_status":         "GO" if mssp_go else "NO-GO",
        "enterprise_status":   "GO" if enterprise_go else "NO-GO",
        "blocked_items":       len(quarantine),
        "published_items":     len(published),
        "synthetic_actors":    synthetic_actors,
        "synthetic_campaigns": synthetic_campaigns,
        "attack_conflicts":    attck_conflicts,
        "risk_conflicts":      risk_conflicts,
        "publication_conflicts": publication_conflicts,
        "contract_compliance": contract_compliance_pct,
        "real_ioc_total":      real_ioc_total,
        "commercial_readiness_score": score,
        "grade_distribution":  dict(grade_dist),
        "tier_counts": {
            "enterprise": len(feed_enterprise),
            "mssp":       len(feed_mssp),
            "public":     len(feed_public),
        },
        "mandate_violations": {
            "M2_attribution": m2_violations,
            "M3_attck":       m3_violations,
            "M4_risk":        m4_violations,
            "M5_ioc":         m5_violations,
        },
        "dashboard_kpis": {
            "published_items":  len(published),
            "grade_dist":       dict(grade_dist),
            "decision_dist":    dict(decision_dist),
            "severity_dist":    dict(severity_dist),
            "enterprise_items": len(feed_enterprise),
            "mssp_items":       len(feed_mssp),
            "public_items":     len(feed_public),
        },
        "governor_version": GOVERNOR_VERSION,
        "governed_at":      datetime.now(timezone.utc).isoformat(),
    }

    return {
        "published":         published,
        "quarantine":        quarantine,
        "feed_enterprise":   feed_enterprise,
        "feed_mssp":         feed_mssp,
        "feed_public":       feed_public,
        "go_live":           go_live,
    }


# ─────────────────────────────────────────────────────────────────────────────
# I/O helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_feed(path: Path) -> List[Dict]:
    raw = path.read_bytes().rstrip(b"\x00")  # strip stale null bytes
    data = json.loads(raw.decode("utf-8", errors="replace"))
    if isinstance(data, list):
        return data
    return data.get("threats", data.get("items", [data]))


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"SENTINEL APEX Commercial Readiness Governor v{GOVERNOR_VERSION}"
    )
    parser.add_argument(
        "feed", nargs="?",
        default=str(REPO_ROOT / "api" / "feed.json"),
        help="Path to feed JSON"
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Write governed feed back to feed.json (removes BLOCK items)"
    )
    parser.add_argument(
        "--report", default=None,
        help="Write governor report JSON to path"
    )
    parser.add_argument(
        "--gate", action="store_true",
        help="Exit 1 if any GO-LIVE criteria are NO-GO"
    )
    args = parser.parse_args()

    feed_path = Path(args.feed)
    items = _load_feed(feed_path)
    log.info("[governor] Loaded %d items from %s", len(items), feed_path)

    result = process_feed(items)
    go_live = result["go_live"]

    log.info(
        "[governor] Published=%d Quarantined=%d | Enterprise=%d MSSP=%d Public=%d",
        go_live["published_items"], go_live["blocked_items"],
        go_live["tier_counts"]["enterprise"],
        go_live["tier_counts"]["mssp"],
        go_live["tier_counts"]["public"],
    )
    log.info(
        "[governor] M2=%d M3=%d M4=%d M5=%d violations remediated",
        go_live["mandate_violations"]["M2_attribution"],
        go_live["mandate_violations"]["M3_attck"],
        go_live["mandate_violations"]["M4_risk"],
        go_live["mandate_violations"]["M5_ioc"],
    )
    log.info(
        "[governor] GO-LIVE: Dashboard=%s API=%s MSSP=%s Enterprise=%s | Score=%d/100",
        go_live["dashboard_status"],
        go_live["cti_api_status"],
        go_live["mssp_status"],
        go_live["enterprise_status"],
        go_live["commercial_readiness_score"],
    )

    if args.apply:
        # Write clean published feed (no BLOCK items)
        _write_json(feed_path, result["published"])
        log.info("[governor] Governed feed written to %s (%d items)", feed_path, len(result["published"]))

        # Write tier feeds
        # v173.2 MONETIZATION FIX: Strip premium fields before writing public/mssp feeds.
        # Previously writing raw items exposed report_url, apex_ai, stix_bundle_url etc.
        # to free-tier consumers — undercut every Pro/Enterprise upsell.
        try:
            from public_api_sanitizer import sanitize_for_public as _sanitize_pub
            _pub_clean  = [_sanitize_pub(i) for i in result["feed_public"]]
            _mssp_clean = [_sanitize_pub(i) for i in result["feed_mssp"]]
            log.info("[governor] Sanitizer applied: %d public + %d mssp items stripped of premium fields",
                     len(_pub_clean), len(_mssp_clean))
        except ImportError:
            log.warning("[governor] public_api_sanitizer not available — writing unsanitized (non-fatal)")
            _pub_clean  = result["feed_public"]
            _mssp_clean = result["feed_mssp"]
        _write_json(REPO_ROOT / "api" / "feed_enterprise.json", result["feed_enterprise"])
        _write_json(REPO_ROOT / "api" / "feed_mssp.json",       _mssp_clean)
        _write_json(REPO_ROOT / "api" / "feed_public.json",     _pub_clean)
        log.info("[governor] Tier feeds written: enterprise=%d mssp=%d public=%d",
                 len(result["feed_enterprise"]),
                 len(result["feed_mssp"]),
                 len(result["feed_public"]))

        # Write quarantine
        quarantine_path = REPO_ROOT / "internal" / "governance" / "quarantine.json"
        _write_json(quarantine_path, {
            "quarantine_count": len(result["quarantine"]),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "items": result["quarantine"],
        })
        log.info("[governor] Quarantine written: %d items → %s", len(result["quarantine"]), quarantine_path)

        # Write governance status endpoint
        _write_json(REPO_ROOT / "api" / "governance_status.json", go_live)
        log.info("[governor] Governance status endpoint written to api/governance_status.json")

    if args.report:
        report = {
            "governor_version": GOVERNOR_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "go_live": go_live,
            "quarantine_sample": result["quarantine"][:5],
        }
        _write_json(Path(args.report), report)
        log.info("[governor] Report written to %s", args.report)

    if args.gate:
        no_go = [k for k, v in go_live.items() if k.endswith("_status") and v == "NO-GO"]
        if no_go:
            log.error("[governor] GATE FAIL: NO-GO on %s", no_go)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
