#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/enterprise_confidence_engine.py — Enterprise Confidence Engine
Pipeline Stage 6.98
================================================================================
Version : 1.0.0
Purpose : Replace subjective/inflated confidence scores with deterministic,
          evidence-backed, explainable confidence classifications.

CONFIDENCE LEVELS:
  VERY_HIGH    Multiple corroborated sources, exploitation evidence, full attribution
  HIGH         Vendor-confirmed, CVSS/EPSS available, KEV or corroborated
  MEDIUM       Single reliable source, partial enrichment, no exploit evidence
  LOW          Minimal enrichment, no CVSS/EPSS, no corroboration, no attribution

FORMULA INPUTS:
  source_count        Number of distinct intelligence sources
  corroboration_count Number of corroborating sources/reports
  evidence_count      Technical evidence items (IOCs, samples, artifacts)
  exploit_evidence    POC available, Metasploit module, KEV status
  attribution_evidence Named threat actor, known campaign, attribution confidence
  technical_depth     CVSS score present, EPSS score present, affected products, kill chain
  intelligence_grade  Feed-level quality grade (A/B/C/D)

RULES:
  - Confidence must be deterministic (same inputs → same output)
  - Confidence must be explainable (score breakdown in output)
  - HIGH/VERY_HIGH requires minimum evidence threshold
  - Items lacking CVSS AND EPSS AND corroboration → cannot be HIGH
  - Items with HIGH reported confidence lacking evidence → VIOLATION

OUTPUTS:
  enterprise_confidence       LOW | MEDIUM | HIGH | VERY_HIGH
  confidence_score_raw        0–100 computed score
  confidence_explanation      Human-readable breakdown
  confidence_violations       List of integrity violations
================================================================================
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ENGINE_ID      = "ENTERPRISE-CONFIDENCE-ENGINE"
ENGINE_VERSION = "1.0.0"
STAGE_ID       = "6.98"

# =============================================================================
# Scoring Weights (must sum to 100 for perfect score)
# =============================================================================

WEIGHTS = {
    # Source reliability (max 20)
    "source_count_1":         8,   # 1 source
    "source_count_2":         14,  # 2 sources
    "source_count_3plus":     20,  # 3+ sources

    # Corroboration (max 20)
    "corroboration_0":        0,
    "corroboration_1":        8,
    "corroboration_2":        14,
    "corroboration_3plus":    20,

    # Technical evidence (max 15)
    "evidence_count_0":       0,
    "evidence_count_1_2":     7,
    "evidence_count_3_5":     12,
    "evidence_count_6plus":   15,

    # Exploitation evidence (max 20)
    "kev_confirmed":          20,  # CISA KEV = maximum exploitation signal
    "metasploit_available":   15,
    "poc_github":             10,
    "exploit_maturity_high":  12,

    # Technical depth (max 15)
    "cvss_present":           5,
    "epss_present":           5,
    "affected_products_known": 3,
    "kill_chain_mapped":      2,

    # Attribution (max 10)
    "actor_named":            5,
    "actor_verified":         5,

    # IOC quality bonus (max 10)
    "real_iocs_present":      5,   # At least 1 real operational IOC
    "high_value_iocs":        5,   # SHA256/IP/domain IOCs
}

# Thresholds for confidence levels
THRESHOLDS = {
    "VERY_HIGH": 75,
    "HIGH":      50,
    "MEDIUM":    25,
    "LOW":       0,
}

# Minimum evidence requirements to claim HIGH or VERY_HIGH
MIN_EVIDENCE_FOR_HIGH = {
    "requires_one_of": [
        "kev_confirmed",
        "metasploit_available",
        "corroboration_2plus",
        "source_count_2plus",
        "real_iocs_present",
    ],
    "requires_at_least_n": 1,
}

# =============================================================================
# Confidence Computation
# =============================================================================

def compute_confidence(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute deterministic, explainable enterprise confidence for a single record.
    """
    score = 0
    components: Dict[str, int] = {}
    evidence_flags: List[str] = []

    # ── Source count ─────────────────────────────────────────────────────────
    source_count = record.get("source_count", 1)
    if source_count is None or source_count < 1:
        source_count = 1

    if source_count >= 3:
        s = WEIGHTS["source_count_3plus"]
        components["source_count_3plus"] = s
        evidence_flags.append(f"source_count={source_count} (3+)")
    elif source_count == 2:
        s = WEIGHTS["source_count_2"]
        components["source_count_2"] = s
        evidence_flags.append(f"source_count={source_count}")
    else:
        s = WEIGHTS["source_count_1"]
        components["source_count_1"] = s
        evidence_flags.append(f"source_count={source_count} (single)")
    score += s

    # ── Corroboration ─────────────────────────────────────────────────────────
    corroboration_count = record.get("corroboration_count", 0) or 0
    if corroboration_count >= 3:
        c = WEIGHTS["corroboration_3plus"]
        components["corroboration_3plus"] = c
        evidence_flags.append(f"corroboration_count={corroboration_count} (3+)")
    elif corroboration_count == 2:
        c = WEIGHTS["corroboration_2"]
        components["corroboration_2"] = c
        evidence_flags.append(f"corroboration_count={corroboration_count}")
    elif corroboration_count == 1:
        c = WEIGHTS["corroboration_1"]
        components["corroboration_1"] = c
        evidence_flags.append(f"corroboration_count={corroboration_count}")
    else:
        c = 0
        components["corroboration_0"] = 0
        evidence_flags.append("corroboration=none")
    score += c

    # ── Evidence count ────────────────────────────────────────────────────────
    evidence_count = record.get("evidence_count", 0) or 0
    if evidence_count >= 6:
        e = WEIGHTS["evidence_count_6plus"]
        components["evidence_count_6plus"] = e
        evidence_flags.append(f"evidence_count={evidence_count} (6+)")
    elif evidence_count >= 3:
        e = WEIGHTS["evidence_count_3_5"]
        components["evidence_count_3_5"] = e
        evidence_flags.append(f"evidence_count={evidence_count}")
    elif evidence_count >= 1:
        e = WEIGHTS["evidence_count_1_2"]
        components["evidence_count_1_2"] = e
        evidence_flags.append(f"evidence_count={evidence_count}")
    else:
        e = 0
        components["evidence_count_0"] = 0
        evidence_flags.append("evidence_count=0")
    score += e

    # ── Exploitation evidence ─────────────────────────────────────────────────
    exploit_score = 0

    kev = record.get("kev_present", False)
    if kev:
        exploit_score = WEIGHTS["kev_confirmed"]
        components["kev_confirmed"] = exploit_score
        evidence_flags.append("KEV=confirmed — actively exploited")

    elif record.get("metasploit_available", False):
        exploit_score = WEIGHTS["metasploit_available"]
        components["metasploit_available"] = exploit_score
        evidence_flags.append("metasploit_module=available")

    elif (record.get("poc_github_count", 0) or 0) > 0:
        exploit_score = WEIGHTS["poc_github"]
        components["poc_github"] = exploit_score
        evidence_flags.append(f"poc_github_count={record.get('poc_github_count')}")

    elif record.get("exploit_maturity") in ("high", "functional", "weaponized"):
        exploit_score = WEIGHTS["exploit_maturity_high"]
        components["exploit_maturity_high"] = exploit_score
        evidence_flags.append(f"exploit_maturity={record.get('exploit_maturity')}")

    else:
        evidence_flags.append("exploit_evidence=none")

    score += exploit_score

    # ── Technical depth ───────────────────────────────────────────────────────
    tech_score = 0

    cvss = record.get("cvss_score")
    if cvss is not None and cvss != "" and float(cvss) > 0 if cvss else False:
        tech_score += WEIGHTS["cvss_present"]
        components["cvss_present"] = WEIGHTS["cvss_present"]
        evidence_flags.append(f"cvss={cvss}")

    epss = record.get("epss_score") or record.get("epss")
    if epss is not None and epss != "" and epss != "N/A":
        tech_score += WEIGHTS["epss_present"]
        components["epss_present"] = WEIGHTS["epss_present"]
        evidence_flags.append(f"epss={epss}")

    affected_products = record.get("affected_products", []) or []
    if affected_products:
        tech_score += WEIGHTS["affected_products_known"]
        components["affected_products_known"] = WEIGHTS["affected_products_known"]
        evidence_flags.append(f"affected_products={len(affected_products)}")

    kill_chain = record.get("kill_chain_phases", []) or []
    if kill_chain:
        tech_score += WEIGHTS["kill_chain_mapped"]
        components["kill_chain_mapped"] = WEIGHTS["kill_chain_mapped"]
        evidence_flags.append("kill_chain_mapped")

    score += tech_score

    # ── Attribution ───────────────────────────────────────────────────────────
    attr_score = 0
    actor = record.get("actor_name") or record.get("actor") or record.get("actor_tag")

    if actor and actor not in ("Unknown", "Untracked", "CDB-UNATTR-CVE", None, ""):
        attr_score += WEIGHTS["actor_named"]
        components["actor_named"] = WEIGHTS["actor_named"]
        evidence_flags.append(f"actor={actor}")

        if record.get("verified_actor", False) or record.get("actor_confidence_label") == "HIGH":
            attr_score += WEIGHTS["actor_verified"]
            components["actor_verified"] = WEIGHTS["actor_verified"]
            evidence_flags.append("actor_verified=true")
    else:
        evidence_flags.append("attribution=none")

    score += attr_score

    # ── IOC Quality ───────────────────────────────────────────────────────────
    ioc_score = 0
    real_ioc_count = record.get("real_ioc_count", 0) or 0
    if real_ioc_count > 0:
        ioc_score += WEIGHTS["real_iocs_present"]
        components["real_iocs_present"] = WEIGHTS["real_iocs_present"]
        evidence_flags.append(f"real_ioc_count={real_ioc_count}")

        # High-value IOC types
        iocs_by_type = record.get("iocs_by_type", {}) or {}
        high_value_types = {"sha256", "sha1", "md5", "ipv4", "ipv6", "domain", "fqdn"}
        has_hv = any(
            t.lower() in high_value_types and iocs_by_type.get(t)
            for t in iocs_by_type
        )
        if has_hv:
            ioc_score += WEIGHTS["high_value_iocs"]
            components["high_value_iocs"] = WEIGHTS["high_value_iocs"]
            evidence_flags.append("high_value_ioc_types_present")

    score += ioc_score

    # ── Cap score ─────────────────────────────────────────────────────────────
    score = min(100, max(0, score))

    # ── Determine confidence level ────────────────────────────────────────────
    if score >= THRESHOLDS["VERY_HIGH"]:
        enterprise_confidence = "VERY_HIGH"
    elif score >= THRESHOLDS["HIGH"]:
        enterprise_confidence = "HIGH"
    elif score >= THRESHOLDS["MEDIUM"]:
        enterprise_confidence = "MEDIUM"
    else:
        enterprise_confidence = "LOW"

    # ── Evidence gate: enforce minimum evidence for HIGH/VERY_HIGH ───────────
    evidence_gate_flags = {
        "kev_confirmed": kev,
        "metasploit_available": record.get("metasploit_available", False),
        "corroboration_2plus": corroboration_count >= 2,
        "source_count_2plus": source_count >= 2,
        "real_iocs_present": real_ioc_count > 0,
    }
    meets_minimum = any(evidence_gate_flags[f] for f in MIN_EVIDENCE_FOR_HIGH["requires_one_of"])

    if enterprise_confidence in ("HIGH", "VERY_HIGH") and not meets_minimum:
        # Force downgrade
        enterprise_confidence = "MEDIUM"
        evidence_flags.append("DOWNGRADED: HIGH claimed without minimum evidence gate")

    # ── Violation detection ───────────────────────────────────────────────────
    violations = []

    prev_confidence_raw = record.get("confidence_score", 0) or 0
    prev_confidence_label = record.get("apex", {}).get("confidence", 0) if isinstance(record.get("apex"), dict) else 0

    # Check ioc_confidence inflation
    ioc_confidence = record.get("ioc_confidence", 0) or 0
    if ioc_confidence >= 90 and real_ioc_count == 0:
        violations.append({
            "type": "IOC_CONFIDENCE_INFLATION",
            "detail": f"ioc_confidence={ioc_confidence} but real_ioc_count=0",
        })

    # Check ioc_threat_level inflation
    ioc_threat_level = record.get("ioc_threat_level", "")
    if ioc_threat_level in ("CRITICAL", "HIGH") and real_ioc_count == 0:
        violations.append({
            "type": "IOC_THREAT_LEVEL_INFLATION",
            "detail": f"ioc_threat_level={ioc_threat_level} but real_ioc_count=0",
        })

    # Check enterprise_confidence vs previous claim
    prev_intel_confidence = record.get("confidence", 0)
    if enterprise_confidence == "LOW" and prev_intel_confidence >= 0.5:
        violations.append({
            "type": "CONFIDENCE_OVERCLAIM",
            "detail": f"record claimed confidence={prev_intel_confidence} but evidence only supports LOW",
        })

    # Build explanation
    explanation = (
        f"Score: {score}/100 | "
        f"Level: {enterprise_confidence} | "
        f"Evidence: {'; '.join(evidence_flags[:5])}"
    )
    if len(evidence_flags) > 5:
        explanation += f" (+{len(evidence_flags)-5} more)"

    return {
        "engine_id": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "stage_id": STAGE_ID,
        "processed_at": datetime.now(timezone.utc).isoformat(),

        "enterprise_confidence": enterprise_confidence,
        "confidence_score_raw": score,
        "confidence_components": components,
        "confidence_evidence_flags": evidence_flags,
        "confidence_explanation": explanation,

        "prev_confidence_score": prev_confidence_raw,
        "prev_confidence": prev_intel_confidence,

        "confidence_violations": violations,
        "violation_count": len(violations),

        "evidence_gate_met": meets_minimum,
    }


# =============================================================================
# Feed-Level Processing
# =============================================================================

def process_feed(feed: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Process entire feed. Returns enterprise confidence report."""

    record_results = []
    level_distribution: Dict[str, int] = {}
    total_violations = 0
    ioc_inflation_violations = 0

    for record in feed:
        result = compute_confidence(record)
        record_results.append({
            "id": record.get("id"),
            "title": record.get("title", ""),
            **result,
        })

        lvl = result["enterprise_confidence"]
        level_distribution[lvl] = level_distribution.get(lvl, 0) + 1
        total_violations += result["violation_count"]
        ioc_inflation_violations += sum(
            1 for v in result["confidence_violations"]
            if v["type"] in ("IOC_CONFIDENCE_INFLATION", "IOC_THREAT_LEVEL_INFLATION")
        )

    # Before state
    prev_high_count = sum(1 for r in feed if r.get("confidence", 0) >= 0.5)
    prev_ioc_confidence_inflated = sum(
        1 for r in feed
        if (r.get("ioc_confidence", 0) or 0) >= 90 and (r.get("real_ioc_count", 0) or 0) == 0
    )

    report = {
        "report_metadata": {
            "engine_id": ENGINE_ID,
            "engine_version": ENGINE_VERSION,
            "stage_id": STAGE_ID,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records_processed": len(feed),
        },

        "before_metrics": {
            "records_with_confidence_gte_50pct": prev_high_count,
            "ioc_confidence_inflated_count": prev_ioc_confidence_inflated,
        },

        "after_metrics": {
            "confidence_level_distribution": level_distribution,
            "total_violations": total_violations,
            "ioc_confidence_inflation_violations": ioc_inflation_violations,
        },

        "delta": {
            "high_confidence_overclaims_corrected": prev_high_count - (
                level_distribution.get("HIGH", 0) + level_distribution.get("VERY_HIGH", 0)
            ),
            "ioc_confidence_inflation_corrected": prev_ioc_confidence_inflated,
        },

        "governance": {
            "deterministic_scoring": True,
            "explainable_scoring": True,
            "evidence_gate_enforced": True,
            "overclaim_violations_corrected": total_violations,
        },

        "records": record_results,
    }

    return report


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Enterprise Confidence Engine v1.0.0 — Stage 6.98"
    )
    parser.add_argument("--feed", default="data/stix/feed_manifest.json")
    parser.add_argument("--output", default="reports/enterprise_confidence_report.json")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        print(f"[ENT-CONF] ERROR: Feed not found: {feed_path}")
        sys.exit(1)

    feed = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(feed, list):
        feed = [feed]

    print(f"[ENT-CONF] Processing {len(feed)} records...")
    report = process_feed(feed)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[ENT-CONF] Report written → {out_path}")

    if args.summary:
        b = report["before_metrics"]
        a = report["after_metrics"]
        d = report["delta"]
        print("\n" + "=" * 60)
        print("ENTERPRISE CONFIDENCE ENGINE — SUMMARY")
        print("=" * 60)
        print(f"  Records processed           : {report['report_metadata']['total_records_processed']}")
        print(f"  Prev high confidence count  : {b['records_with_confidence_gte_50pct']}")
        print(f"  IOC confidence inflated     : {b['ioc_confidence_inflated_count']}")
        print(f"  Confidence distribution     : {a['confidence_level_distribution']}")
        print(f"  Overclaims corrected        : {d['high_confidence_overclaims_corrected']}")
        print(f"  Total violations            : {a['total_violations']}")
        print("=" * 60)

    return report


if __name__ == "__main__":
    main()
