#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
ENTERPRISE INTELLIGENCE QUALITY ENGINE v1.0.0
===============================================================================
PURPOSE:
    P1 multi-dimensional quality scoring engine. Produces measurable,
    auditable quality scores for every intelligence object published by
    Sentinel APEX.

    11 DIMENSIONS:
      D01 — Source Diversity Score
      D02 — IOC Enrichment Score
      D03 — CVE Enrichment Score
      D04 — EPSS Score
      D05 — KEV Score
      D06 — Detection Coverage Score
      D07 — Sigma Quality Score
      D08 — STIX Quality Score
      D09 — Report Monetization Score
      D10 — MSSP Readiness Score
      D11 — Enterprise Readiness Score

    AGGREGATE OUTPUTS:
      intelligence_quality     — weighted aggregate (D01-D08)
      enterprise_readiness     — D11
      mssp_readiness           — D10
      api_readiness            — derived from D08 + D02 + D03
      monetization_readiness   — D09

CLI MODES:
    --score  <feed.json>     Score all items; print aggregate + per-item
    --gate   <feed.json>     Exit 1 if aggregate intelligence_quality < 70
    --output <path>          Write full quality report to JSON file
    --api    <path>          Write api/intel_quality.json (dashboard endpoint)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [intel_quality_engine_v2] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-EQEV2")

ENGINE_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent

# ══════════════════════════════════════════════════════════════════════════════
# TRUSTED SOURCE REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

TIER1_SOURCES = frozenset([
    "CISA", "NCSC", "FBI", "NSA", "CERT", "US-CERT",
    "Mandiant", "CrowdStrike", "Microsoft", "Microsoft Security",
    "Microsoft MSRC", "Google Project Zero",
])

TIER2_SOURCES = frozenset([
    "Palo Alto Unit 42", "Recorded Future", "Sophos", "Kaspersky SecureList",
    "Check Point Research", "Trend Micro", "Rapid7", "NIST NVD",
    "GitHub Security Advisory", "abuse.ch", "Google Security Blog",
])

TIER3_SOURCES = frozenset([
    "BleepingComputer", "KrebsOnSecurity", "Wordfence", "WPScan",
    "The Hacker News", "SecurityWeek", "ransomware.live",
])

# Source diversity scoring weights
SOURCE_DIVERSITY_WEIGHTS = {
    "tier1_count": 40,   # points per Tier 1 source
    "tier2_count": 25,   # points per Tier 2 source
    "tier3_count": 10,   # points per Tier 3 source
    "max_score": 100,
}

# IOC type quality weights
IOC_TYPE_WEIGHTS = {
    "ip": 20, "domain": 18, "url": 15, "hash": 25,
    "email": 10, "mutex": 12, "registry": 12, "cve": 8,
    "yara": 30, "sigma": 28, "asn": 8, "cidr": 12,
}

# Detection format quality
DETECTION_FORMAT_SCORES = {
    "sigma": 35, "yara": 30, "kql": 25, "suricata": 22,
    "snort": 18, "splunk": 20, "elastic": 20, "qradar": 18,
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _safe_float(val, default: float = 0.0) -> float:
    try:
        return float(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def _safe_int(val, default: int = 0) -> int:
    try:
        return int(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def _sources(item: Dict) -> List[str]:
    out = []
    for key in ("source", "feed_source", "source_name"):
        s = item.get(key, "")
        if s and s not in out:
            out.append(str(s))
    return [s for s in out if s]


def _ioc_count(item: Dict) -> int:
    return max(
        _safe_int(item.get("ioc_count")),
        len([i for i in (item.get("iocs") or []) if not str(i).startswith("CVE-")])
    )


def _iocs_by_type(item: Dict) -> Dict[str, int]:
    typed = item.get("iocs_by_type", {}) or {}
    if typed:
        return {k: len(v) if isinstance(v, list) else _safe_int(v) for k, v in typed.items()}
    # Infer from raw iocs list
    iocs = item.get("iocs", []) or []
    result: Dict[str, int] = {}
    for ioc in iocs:
        ioc_str = str(ioc)
        if re.match(r"CVE-\d{4}-\d+", ioc_str):
            result["cve"] = result.get("cve", 0) + 1
        elif re.match(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", ioc_str):
            result["ip"] = result.get("ip", 0) + 1
        elif re.match(r"^[a-f0-9]{32,64}$", ioc_str, re.IGNORECASE):
            result["hash"] = result.get("hash", 0) + 1
        elif "." in ioc_str and " " not in ioc_str:
            result["domain"] = result.get("domain", 0) + 1
    return result


def _techniques(item: Dict) -> List[str]:
    techs = (
        item.get("attck_technique_ids")
        or item.get("actor_ttps")
        or item.get("ttps")
        or []
    )
    return [str(t) for t in techs if re.match(r"T\d{4}(\.\d{3})?$", str(t))]


def _detection_bundles(item: Dict) -> Dict:
    """Extract detection content from item."""
    bundle = item.get("detection_bundle", item.get("detections", {})) or {}
    return bundle if isinstance(bundle, dict) else {}


def _stix_objects(item: Dict) -> int:
    return _safe_int(item.get("stix_object_count"))


def _has_stix(item: Dict) -> bool:
    return bool(
        item.get("stix_file")
        or item.get("stix_bundle_url")
        or item.get("stix_id")
        or _stix_objects(item) > 0
    )


# ══════════════════════════════════════════════════════════════════════════════
# DIMENSION SCORERS
# ══════════════════════════════════════════════════════════════════════════════

def d01_source_diversity(item: Dict) -> Tuple[int, Dict]:
    """D01: Source diversity. Tier-weighted multi-source scoring."""
    sources = _sources(item)
    t1 = sum(1 for s in sources if s in TIER1_SOURCES)
    t2 = sum(1 for s in sources if s in TIER2_SOURCES)
    t3 = sum(1 for s in sources if s in TIER3_SOURCES)
    unknown = len(sources) - t1 - t2 - t3

    raw = t1 * 40 + t2 * 25 + t3 * 10 + unknown * 5
    score = min(100, raw)

    breakdown = {"tier1": t1, "tier2": t2, "tier3": t3, "unknown": unknown,
                 "sources": sources}
    return score, breakdown


def d02_ioc_enrichment(item: Dict) -> Tuple[int, Dict]:
    """D02: IOC enrichment quality. Type diversity + count + threat level."""
    ioc_cnt = _ioc_count(item)
    by_type = _iocs_by_type(item)
    type_count = len([k for k, v in by_type.items() if v > 0 and k != "cve"])

    # Base score from count
    count_score = min(40, ioc_cnt * 4)

    # Type diversity bonus
    type_score = min(30, type_count * 10)

    # Quality indicators
    ioc_confidence = _safe_int(item.get("ioc_confidence", 0))
    quality_score = min(20, int(ioc_confidence / 5))

    # Threat level bonus
    threat_map = {"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 2}
    threat_score = threat_map.get(str(item.get("ioc_threat_level", "")).upper(), 0)

    score = min(100, count_score + type_score + quality_score + threat_score)
    breakdown = {
        "ioc_count": ioc_cnt,
        "types": list(by_type.keys()),
        "type_count": type_count,
        "ioc_confidence": ioc_confidence,
    }
    return score, breakdown


def d03_cve_enrichment(item: Dict) -> Tuple[int, Dict]:
    """D03: CVE enrichment depth. CVSS + EPSS + KEV + affected products."""
    score = 0
    breakdown = {}

    cve_ids = item.get("cve_ids", []) or []
    has_cve = bool(cve_ids or item.get("cve_id"))

    if not has_cve:
        return 0, {"note": "No CVE data — dimension not applicable"}

    # CVSS score presence
    cvss = _safe_float(item.get("cvss_score"))
    if cvss > 0:
        score += 25
        breakdown["cvss"] = cvss

    # CVSS vector presence
    if item.get("cvss_vector") or item.get("attack_vector"):
        score += 10
        breakdown["attack_vector"] = item.get("attack_vector", "present")

    # NVD enriched
    if item.get("nvd_enriched") or item.get("nvd_description"):
        score += 15
        breakdown["nvd_enriched"] = True

    # Affected products
    products = item.get("affected_products", []) or []
    if products:
        score += min(20, len(products) * 5)
        breakdown["affected_products"] = len(products)

    # Patch availability
    if item.get("patch_url") or item.get("remediation"):
        score += 15
        breakdown["patch"] = True

    # Multiple CVEs = broader coverage
    if len(cve_ids) > 1:
        score += min(15, len(cve_ids) * 3)
        breakdown["cve_count"] = len(cve_ids)

    return min(100, score), breakdown


def d04_epss_score(item: Dict) -> Tuple[int, Dict]:
    """D04: EPSS data quality and exploitation probability."""
    epss = _safe_float(item.get("epss_score"))
    breakdown = {"epss_raw": epss}

    if epss == 0:
        # Check if CVE exists but EPSS is missing
        has_cve = bool(item.get("cve_ids") or item.get("cve_id"))
        if has_cve:
            breakdown["note"] = "CVE present but EPSS not enriched"
            return 10, breakdown  # Partial credit for having CVE
        return 0, {"note": "No CVE — EPSS not applicable"}

    # Normalize EPSS (0.0-1.0 range) to quality score
    # High EPSS = high risk = higher quality intelligence (more actionable)
    if epss >= 0.5:
        score = 100
    elif epss >= 0.1:
        score = 75
    elif epss >= 0.01:
        score = 50
    else:
        score = 25  # Very low EPSS but enriched

    breakdown["tier"] = (
        "CRITICAL" if epss >= 0.5 else
        "HIGH" if epss >= 0.1 else
        "MEDIUM" if epss >= 0.01 else "LOW"
    )
    return score, breakdown


def d05_kev_score(item: Dict) -> Tuple[int, Dict]:
    """D05: CISA KEV presence and enrichment."""
    in_kev = (
        item.get("kev") == "YES"
        or item.get("kev_present") is True
        or item.get("in_kev") is True
        or item.get("cisa_kev") is True
    )
    has_cve = bool(item.get("cve_ids") or item.get("cve_id"))

    if in_kev:
        return 100, {"kev": True, "note": "Confirmed in CISA KEV catalog"}
    elif has_cve:
        return 20, {"kev": False, "note": "CVE present; not in KEV — checked"}
    else:
        return 0, {"note": "No CVE — KEV not applicable"}


def d06_detection_coverage(item: Dict) -> Tuple[int, Dict]:
    """D06: Detection content coverage across SIEM/EDR/NDR platforms."""
    bundle = _detection_bundles(item)
    score = 0
    breakdown = {"formats": []}

    # Check for detection formats in bundle
    for fmt, fmt_score in DETECTION_FORMAT_SCORES.items():
        if bundle.get(fmt) or item.get(f"{fmt}_rule") or item.get(f"{fmt}_rules"):
            score += fmt_score
            breakdown["formats"].append(fmt)

    # Check apex_ai for detection hints
    apex_ai = item.get("apex_ai", {}) or {}
    if apex_ai.get("detection_rules") or apex_ai.get("sigma"):
        if "sigma" not in breakdown["formats"]:
            score += 20
            breakdown["formats"].append("sigma (apex_ai)")

    # ATT&CK techniques map to detection potential
    techs = _techniques(item)
    if techs:
        score += min(20, len(techs) * 5)
        breakdown["mitre_techniques"] = len(techs)

    return min(100, score), breakdown


def d07_sigma_quality(item: Dict) -> Tuple[int, Dict]:
    """D07: Sigma rule quality — presence, validity, coverage."""
    bundle = _detection_bundles(item)
    sigma_content = (
        bundle.get("sigma")
        or item.get("sigma_rule")
        or item.get("sigma_rules")
        or ""
    )
    breakdown = {}

    if not sigma_content:
        # Check STIX bundle for sigma
        if _has_stix(item):
            breakdown["note"] = "STIX present — Sigma may be embedded"
            return 15, breakdown
        breakdown["note"] = "No Sigma rule detected"
        return 0, breakdown

    sigma_str = json.dumps(sigma_content) if isinstance(sigma_content, (dict, list)) else str(sigma_content)

    score = 30  # Base for presence

    # Quality indicators
    if "logsource" in sigma_str:
        score += 15
        breakdown["logsource"] = True
    if "detection" in sigma_str:
        score += 15
        breakdown["detection_block"] = True
    if "falsepositives" in sigma_str:
        score += 10
        breakdown["falsepositives"] = True
    if "level:" in sigma_str:
        score += 10
        breakdown["level"] = True
    if "tags:" in sigma_str and "attack" in sigma_str.lower():
        score += 15
        breakdown["mitre_tagged"] = True
    if "status: production" in sigma_str.lower() or "status: stable" in sigma_str.lower():
        score += 5
        breakdown["production_status"] = True

    return min(100, score), breakdown


def d08_stix_quality(item: Dict) -> Tuple[int, Dict]:
    """D08: STIX 2.1 quality — presence, object count, richness."""
    breakdown = {}

    if not _has_stix(item):
        breakdown["note"] = "No STIX bundle"
        return 0, breakdown

    score = 20  # Base for having STIX
    obj_count = _stix_objects(item)
    breakdown["stix_object_count"] = obj_count

    # Object count score
    if obj_count >= 20:
        score += 40
    elif obj_count >= 10:
        score += 25
    elif obj_count >= 5:
        score += 15
    elif obj_count > 0:
        score += 5

    # STIX version
    if item.get("stix_version") == "2.1":
        score += 15
        breakdown["stix_version"] = "2.1"

    # External references / relationships
    if item.get("stix_relationships") or obj_count > 15:
        score += 15
        breakdown["relationships"] = True

    # Bundle URL accessible
    if item.get("stix_bundle_url"):
        score += 10
        breakdown["public_url"] = True

    return min(100, score), breakdown


def d09_monetization_score(item: Dict) -> Tuple[int, Dict]:
    """D09: Report monetization readiness — premium content signals."""
    score = 0
    breakdown = {}

    # PDF available
    if item.get("pdf_url") or item.get("pdf_available"):
        score += 20
        breakdown["pdf"] = True

    # Full report URL
    if item.get("report_url"):
        score += 15
        breakdown["report_url"] = True

    # Tier classification
    tier = item.get("cti_tier", item.get("tier", ""))
    if tier == "PREMIUM_CTI":
        score += 25
        breakdown["tier"] = "PREMIUM_CTI"
    elif tier == "FREE_INFORMATIONAL":
        breakdown["tier"] = "FREE_INFORMATIONAL"

    # Confidence >= 70
    conf = item.get("confidence_score", 0) or 0
    if conf >= 70:
        score += 15
        breakdown["confidence_high"] = True

    # STIX bundle (enterprise deliverable)
    if _has_stix(item):
        score += 10
        breakdown["stix"] = True

    # Detection bundle (value-add)
    if _detection_bundles(item):
        score += 15
        breakdown["detections"] = True

    return min(100, score), breakdown


def d10_mssp_readiness(item: Dict) -> Tuple[int, Dict]:
    """D10: MSSP customer delivery readiness."""
    score = 0
    breakdown = {}

    # TLP classification
    tlp = str(item.get("tlp", "") or "").upper()
    if "TLP:AMBER" in tlp or "TLP:RED" in tlp:
        score += 20
        breakdown["tlp"] = tlp
    elif "TLP:GREEN" in tlp or "TLP:CLEAR" in tlp:
        score += 10
        breakdown["tlp"] = tlp

    # IOC count (deployable indicators)
    ioc_cnt = _ioc_count(item)
    if ioc_cnt >= 10:
        score += 25
    elif ioc_cnt >= 5:
        score += 15
    elif ioc_cnt >= 1:
        score += 8

    # Detection coverage
    if _detection_bundles(item):
        score += 20
        breakdown["detections"] = True

    # STIX bundle
    if _has_stix(item):
        score += 15
        breakdown["stix"] = True

    # Severity classification
    sev = str(item.get("severity", "") or "").upper()
    if sev in ("CRITICAL", "HIGH"):
        score += 15
        breakdown["severity"] = sev
    elif sev == "MEDIUM":
        score += 8

    # SOC priority
    soc_priority = _get(item, "apex_ai", "soc_priority") or item.get("soc_priority", "")
    if soc_priority in ("P1", "P2"):
        score += 5
        breakdown["soc_priority"] = soc_priority

    return min(100, score), breakdown


def _get(item: Dict, *keys: str, default=None):
    for k in keys:
        if isinstance(item, dict) and k in item:
            item = item[k]
        else:
            return default
    return item if item is not None else default


def d11_enterprise_readiness(item: Dict) -> Tuple[int, Dict]:
    """D11: Enterprise customer readiness (API, audit, reproducibility)."""
    score = 0
    breakdown = {}

    # Evidence ledger
    if item.get("evidence_ledger"):
        score += 20
        breakdown["evidence_ledger"] = True

    # Source provenance
    if item.get("source_url") and item.get("source_name"):
        score += 15
        breakdown["source_provenance"] = True

    # Content hash (immutability)
    if item.get("content_hash") or item.get("retrieval_timestamp"):
        score += 10
        breakdown["immutability"] = True

    # Validation status
    if item.get("validation_status") == "validated":
        score += 15
        breakdown["validated"] = True
    elif item.get("validation_status"):
        score += 5

    # ATT&CK mapping
    if _techniques(item):
        score += 15
        breakdown["mitre_mapped"] = True

    # Schema version
    if item.get("schema_version"):
        score += 5
        breakdown["schema_version"] = item["schema_version"]

    # Attribution status explicit
    if item.get("attribution_status"):
        score += 10
        breakdown["attribution"] = item["attribution_status"]

    # STIX (reproducible, standard format)
    if _has_stix(item):
        score += 10
        breakdown["stix"] = True

    return min(100, score), breakdown


# ══════════════════════════════════════════════════════════════════════════════
# AGGREGATE SCORER
# ══════════════════════════════════════════════════════════════════════════════

# Dimension weights for intelligence_quality aggregate
DIMENSION_WEIGHTS = {
    "d01_source_diversity":   0.20,
    "d02_ioc_enrichment":     0.20,
    "d03_cve_enrichment":     0.10,
    "d04_epss":               0.05,
    "d05_kev":                0.05,
    "d06_detection_coverage": 0.15,
    "d07_sigma_quality":      0.10,
    "d08_stix_quality":       0.15,
}


def score_item(item: Dict) -> Dict:
    """Score a single intel item across all 11 dimensions."""
    d01, d01b = d01_source_diversity(item)
    d02, d02b = d02_ioc_enrichment(item)
    d03, d03b = d03_cve_enrichment(item)
    d04, d04b = d04_epss_score(item)
    d05, d05b = d05_kev_score(item)
    d06, d06b = d06_detection_coverage(item)
    d07, d07b = d07_sigma_quality(item)
    d08, d08b = d08_stix_quality(item)
    d09, d09b = d09_monetization_score(item)
    d10, d10b = d10_mssp_readiness(item)
    d11, d11b = d11_enterprise_readiness(item)

    # Weighted intelligence quality (D01-D08)
    iq = int(
        d01 * DIMENSION_WEIGHTS["d01_source_diversity"]
        + d02 * DIMENSION_WEIGHTS["d02_ioc_enrichment"]
        + d03 * DIMENSION_WEIGHTS["d03_cve_enrichment"]
        + d04 * DIMENSION_WEIGHTS["d04_epss"]
        + d05 * DIMENSION_WEIGHTS["d05_kev"]
        + d06 * DIMENSION_WEIGHTS["d06_detection_coverage"]
        + d07 * DIMENSION_WEIGHTS["d07_sigma_quality"]
        + d08 * DIMENSION_WEIGHTS["d08_stix_quality"]
    )

    # API readiness = STIX + IOC + CVE enrichment combo
    api_readiness = int(d08 * 0.50 + d02 * 0.30 + d03 * 0.20)

    # Improvement suggestions
    suggestions = []
    if d01 < 50:
        suggestions.append("Enrich with Tier 1/2 source corroboration (CISA, Mandiant, CrowdStrike)")
    if d02 < 30:
        suggestions.append("Extract or enrich IOCs — IPs, hashes, domains from source")
    if d03 < 40 and (item.get("cve_ids") or item.get("cve_id")):
        suggestions.append("Enrich CVE with CVSS score, affected products, patch URL")
    if d04 == 0 and (item.get("cve_ids") or item.get("cve_id")):
        suggestions.append("Add EPSS score from FIRST.org API for CVE items")
    if d06 < 30:
        suggestions.append("Add Sigma/YARA/KQL detection rules for SIEM coverage")
    if d07 < 30:
        suggestions.append("Create production-ready Sigma rule with logsource + ATT&CK tags")
    if d08 < 20:
        suggestions.append("Generate STIX 2.1 bundle with relationships and IOC objects")
    if d09 < 40:
        suggestions.append("Add PDF report and report_url for monetization readiness")
    if d10 < 40:
        suggestions.append("Classify TLP, add deployable IOCs for MSSP delivery")
    if d11 < 50:
        suggestions.append("Add evidence_ledger, content_hash, validation_status for enterprise")

    return {
        "item_id": item.get("id", item.get("stix_id", "unknown")),
        "title": str(item.get("title", ""))[:80],
        "intelligence_quality": iq,
        "enterprise_readiness": d11,
        "mssp_readiness": d10,
        "api_readiness": api_readiness,
        "monetization_readiness": d09,
        "dimensions": {
            "d01_source_diversity": d01,
            "d02_ioc_enrichment": d02,
            "d03_cve_enrichment": d03,
            "d04_epss": d04,
            "d05_kev": d05,
            "d06_detection_coverage": d06,
            "d07_sigma_quality": d07,
            "d08_stix_quality": d08,
            "d09_monetization": d09,
            "d10_mssp_readiness": d10,
            "d11_enterprise_readiness": d11,
        },
        "dimension_breakdowns": {
            "d01": d01b, "d02": d02b, "d03": d03b, "d04": d04b,
            "d05": d05b, "d06": d06b, "d07": d07b, "d08": d08b,
            "d09": d09b, "d10": d10b, "d11": d11b,
        },
        "improvement_suggestions": suggestions,
        "engine_version": ENGINE_VERSION,
        "scored_at": datetime.now(timezone.utc).isoformat(),
    }


def score_feed(items: List[Dict]) -> Dict:
    """Score all items and return aggregate quality metrics."""
    if not items:
        return {
            "error": "Empty feed",
            "intelligence_quality": 0,
            "enterprise_readiness": 0,
            "mssp_readiness": 0,
            "api_readiness": 0,
            "monetization_readiness": 0,
        }

    results = [score_item(i) for i in items]

    def avg(key: str) -> int:
        vals = [r[key] for r in results if isinstance(r.get(key), (int, float))]
        return int(sum(vals) / len(vals)) if vals else 0

    def pct_above(key: str, threshold: int) -> float:
        vals = [r[key] for r in results if isinstance(r.get(key), (int, float))]
        return round(sum(1 for v in vals if v >= threshold) / max(len(vals), 1) * 100, 1)

    iq = avg("intelligence_quality")
    er = avg("enterprise_readiness")
    mr = avg("mssp_readiness")
    ar = avg("api_readiness")
    mo = avg("monetization_readiness")

    # Grade
    def grade(score: int) -> str:
        if score >= 90: return "A"
        if score >= 80: return "B"
        if score >= 70: return "C"
        if score >= 60: return "D"
        return "F"

    # Dimension averages
    dim_avgs = {}
    for dim in [
        "d01_source_diversity", "d02_ioc_enrichment", "d03_cve_enrichment",
        "d04_epss", "d05_kev", "d06_detection_coverage", "d07_sigma_quality",
        "d08_stix_quality", "d09_monetization", "d10_mssp_readiness",
        "d11_enterprise_readiness",
    ]:
        vals = [r["dimensions"].get(dim, 0) for r in results]
        dim_avgs[dim] = int(sum(vals) / len(vals)) if vals else 0

    # Weakest dimensions (below 50)
    weak = sorted(
        [(k, v) for k, v in dim_avgs.items() if v < 50],
        key=lambda x: x[1]
    )[:3]

    return {
        "intelligence_quality": iq,
        "enterprise_readiness": er,
        "mssp_readiness": mr,
        "api_readiness": ar,
        "monetization_readiness": mo,
        "grade": grade(iq),
        "total_items": len(items),
        "items_above_70_iq": pct_above("intelligence_quality", 70),
        "items_above_70_er": pct_above("enterprise_readiness", 70),
        "dimension_averages": dim_avgs,
        "weakest_dimensions": [{"dimension": k, "score": v} for k, v in weak],
        "engine_version": ENGINE_VERSION,
        "scored_at": datetime.now(timezone.utc).isoformat(),
        "item_scores": results,
    }


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def _load_feed(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        log.error("Feed not found: %s", path)
        sys.exit(2)
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    return data.get("items", data.get("data", []))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"SENTINEL APEX Enterprise Intelligence Quality Engine v{ENGINE_VERSION}"
    )
    parser.add_argument("feed", nargs="?",
                        default=str(REPO_ROOT / "api" / "feed.json"))
    parser.add_argument("--score", action="store_true",
                        help="Score all items and print aggregate")
    parser.add_argument("--gate", action="store_true",
                        help="Exit 1 if intelligence_quality < 70")
    parser.add_argument("--output", default=None,
                        help="Write full quality report to JSON file")
    parser.add_argument("--api", action="store_true",
                        help="Write api/intel_quality.json for dashboard")
    args = parser.parse_args()

    items = _load_feed(args.feed)
    log.info("[quality-engine] Scoring %d items from %s", len(items), args.feed)

    summary = score_feed(items)

    log.info(
        "[quality-engine] SCORES: iq=%d(%s) enterprise=%d mssp=%d api=%d monetize=%d | "
        "items=%d weak_dims=%s",
        summary["intelligence_quality"],
        summary["grade"],
        summary["enterprise_readiness"],
        summary["mssp_readiness"],
        summary["api_readiness"],
        summary["monetization_readiness"],
        summary["total_items"],
        [w["dimension"] for w in summary["weakest_dimensions"]],
    )

    if summary["weakest_dimensions"]:
        log.info("[quality-engine] TOP IMPROVEMENT AREAS:")
        for w in summary["weakest_dimensions"]:
            log.info("  %s = %d/100", w["dimension"], w["score"])

    if args.output:
        report = {k: v for k, v in summary.items() if k != "item_scores"}
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        log.info("[quality-engine] Report written to %s", args.output)

    if args.api:
        api_out = REPO_ROOT / "api" / "intel_quality.json"
        api_out.parent.mkdir(parents=True, exist_ok=True)
        api_payload = {
            "intelligence_quality": summary["intelligence_quality"],
            "enterprise_readiness": summary["enterprise_readiness"],
            "mssp_readiness": summary["mssp_readiness"],
            "api_readiness": summary["api_readiness"],
            "monetization_readiness": summary["monetization_readiness"],
            "grade": summary["grade"],
            "total_items": summary["total_items"],
            "items_above_70_iq": summary["items_above_70_iq"],
            "dimension_averages": summary["dimension_averages"],
            "weakest_dimensions": summary["weakest_dimensions"],
            "scored_at": summary["scored_at"],
            "engine_version": ENGINE_VERSION,
        }
        api_out.write_text(json.dumps(api_payload, indent=2), encoding="utf-8")
        log.info("[quality-engine] API endpoint written to %s", api_out)

    if args.gate:
        iq = summary["intelligence_quality"]
        if iq < 70:
            log.error(
                "[quality-engine] GATE FAIL: intelligence_quality=%d (<70 minimum)", iq
            )
            return 1
        log.info("[quality-engine] GATE PASS: intelligence_quality=%d", iq)

    return 0


if __name__ == "__main__":
    sys.exit(main())
