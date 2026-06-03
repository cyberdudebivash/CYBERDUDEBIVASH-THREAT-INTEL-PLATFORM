#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/detection_specificity_engine.py — Detection Specificity Engine
Pipeline Stage 6.96
================================================================================
Version : 1.0.0
Purpose : Enforce detection quality standards for enterprise feed publication.
          Block generic, stub, and non-specific detection content.

DETECTION CONFIDENCE CLASSES:
  PRODUCTION      Specific, threat-tied, tested, deployable immediately
  LAB_VALIDATED   Specific content, needs environment tuning before deploy
  HYPOTHESIS      Behaviorally plausible, requires red team validation
  PLACEHOLDER     Generic stub — BLOCKED from enterprise/MSSP publication

GENERIC PATTERN BLOCKLIST (triggers PLACEHOLDER classification):
  generic_eventid_rule      EventID list without specific conditions
  generic_failed_login_rule Generic authentication failure detection
  generic_suricata_stub     NOP sled / generic HTTP pattern
  generic_kql_stub          Generic EventID KQL without threat context
  generic_sigma_stub        Sigma without specific detection logic

RULES:
  - PRODUCTION and LAB_VALIDATED may be published to enterprise feeds
  - HYPOTHESIS may be published to threat-hunter feeds only
  - PLACEHOLDER is BLOCKED from all commercial feeds

OUTPUTS:
  detection_confidence_class   PRODUCTION | LAB_VALIDATED | HYPOTHESIS | PLACEHOLDER
  detection_block_reason       reason if blocked
  detection_specificity_score  0-100
  detection_specificity_report.json
================================================================================
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ENGINE_ID      = "DETECTION-SPECIFICITY-ENGINE"
ENGINE_VERSION = "1.0.0"
STAGE_ID       = "6.96"

# =============================================================================
# Generic Pattern Detection — Sigma
# =============================================================================

# Sigma: Generic EventID list without specific context
SIGMA_GENERIC_EVENTID_RE = re.compile(
    r"EventID\s+in\s*\([^)]*(?:4625|4648|4728|4740|4776|4624|4634|4647|4688)[^)]*\)",
    re.IGNORECASE,
)
# Sigma: Generic status/state checks without CVE/threat context
SIGMA_GENERIC_DETECTION_RE = re.compile(
    r"detection:\s*\n\s*selection:\s*\n\s*\w+\s*[|:]\s*\n",
    re.IGNORECASE | re.MULTILINE,
)
# Sigma: Lacks specific IOC/threat tying (no hash, no IP, no domain, no specific string)
SIGMA_MISSING_SPECIFICS_RE = re.compile(
    r"(?:EventID|event_id)\s+in\s*\(",
    re.IGNORECASE,
)
# Sigma: Generic class label in description
SIGMA_GENERIC_CLASS_RE = re.compile(
    r"Class:\s*GENERIC",
    re.IGNORECASE,
)
# Sigma: Meaningful specific conditions
SIGMA_HAS_SPECIFIC_RE = re.compile(
    r"(?:CommandLine|ParentImage|TargetFilename|DestinationIp|"
    r"DestinationHostname|Hashes|sha256|sha1|md5|"
    r"RegistryKey|PipeName|RuleName|Channel\s*=\s*['\"])",
    re.IGNORECASE,
)

# =============================================================================
# Generic Pattern Detection — KQL
# =============================================================================

# KQL: Generic EventID list
KQL_GENERIC_EVENTID_RE = re.compile(
    r"EventID\s+in\s*\([^)]*(?:4625|4648|4728|4740|4776|4624|4634|4647|4688)[^)]*\)",
    re.IGNORECASE,
)
# KQL: Generic SecurityEvent query without specific filter
KQL_GENERIC_SECURITY_EVENT_RE = re.compile(
    r"SecurityEvent\s*\|\s*where\s+TimeGenerated.*?\|\s*where\s+EventID\s+in",
    re.IGNORECASE | re.DOTALL,
)
# KQL: Meaningful specifics
KQL_HAS_SPECIFIC_RE = re.compile(
    r"(?:CommandLine|InitiatingProcessFileName|"
    r"RemoteIPType\s*==\s*['\"]Public['\"]|"
    r"SHA256\s*==|MD5\s*==|FileName\s+contains|"
    r"tostring\(.*hash|AccountName\s+contains)",
    re.IGNORECASE,
)
# KQL: Missing CVE/threat reference in query
KQL_NO_CVE_CONTEXT_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# =============================================================================
# Generic Pattern Detection — Suricata
# =============================================================================

# Suricata: NOP sled pattern (|90 90 90 90|) — cannot specifically detect a CVE
SURICATA_NOP_SLED_RE = re.compile(
    r'content\s*:\s*["\|]90\s+90\s+90\s+90["\|]',
    re.IGNORECASE,
)
# Suricata: Generic HTTP application attack without specific URI/content
SURICATA_GENERIC_WEB_RE = re.compile(
    r"classtype\s*:\s*web-application-attack.*?content\s*:\s*\"\|90\s+90",
    re.IGNORECASE | re.DOTALL,
)
# Suricata: Generic class label
SURICATA_GENERIC_CLASS_RE = re.compile(
    r"GENERIC",
    re.IGNORECASE,
)
# Suricata: Meaningful specific content
SURICATA_HAS_SPECIFIC_RE = re.compile(
    r"(?:pcre\s*:\s*\"/|uricontent\s*:\s*\"|"
    r"content\s*:\s*\"[^\"]{8,}\"|"
    r"byte_test\s*:|byte_jump\s*:|"
    r"flow\s*:\s*established.*?content\s*:\s*\"(?!\|90))",
    re.IGNORECASE,
)
# Suricata: Has CVE reference in message
SURICATA_HAS_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

# =============================================================================
# Classification Logic
# =============================================================================

def _classify_sigma(sigma_text: str, context: Dict[str, Any]) -> Tuple[str, List[str], int]:
    """
    Returns: (confidence_class, reasons_list, specificity_score)
    """
    if not sigma_text or not sigma_text.strip():
        return "PLACEHOLDER", ["sigma_rule_empty"], 0

    issues = []
    score = 50  # Start at neutral

    # Check for GENERIC class label
    if SIGMA_GENERIC_CLASS_RE.search(sigma_text):
        issues.append("generic_sigma_class_label")
        score -= 25

    # Check for generic EventID list
    if SIGMA_MISSING_SPECIFICS_RE.search(sigma_text) and not SIGMA_HAS_SPECIFIC_RE.search(sigma_text):
        issues.append("generic_eventid_rule")
        score -= 20

    # Check for generic failed login (EventID 4625/4776 without specifics)
    if SIGMA_GENERIC_EVENTID_RE.search(sigma_text) and not SIGMA_HAS_SPECIFIC_RE.search(sigma_text):
        issues.append("generic_failed_login_rule")
        score -= 15

    # Reward specific detection conditions
    if SIGMA_HAS_SPECIFIC_RE.search(sigma_text):
        score += 30

    # Reward CVE reference in sigma
    if re.search(r"CVE-\d{4}-\d+", sigma_text, re.IGNORECASE):
        score += 10

    # Reward specific references in the rule
    if re.search(r"(?:sha256|sha1|md5|CommandLine|DestinationIp)", sigma_text, re.IGNORECASE):
        score += 15

    # Cap score
    score = max(0, min(100, score))

    if "generic_sigma_class_label" in issues or (
        "generic_eventid_rule" in issues and "generic_failed_login_rule" in issues
    ):
        return "PLACEHOLDER", issues, score

    if issues:
        return "HYPOTHESIS", issues, score

    if score >= 75:
        return "LAB_VALIDATED", issues, score

    return "HYPOTHESIS", issues, score


def _classify_kql(kql_text: str, context: Dict[str, Any]) -> Tuple[str, List[str], int]:
    """Returns: (confidence_class, reasons_list, specificity_score)"""
    if not kql_text or not kql_text.strip():
        return "PLACEHOLDER", ["kql_rule_empty"], 0

    issues = []
    score = 50

    # Generic EventID KQL
    if KQL_GENERIC_EVENTID_RE.search(kql_text):
        issues.append("generic_eventid_rule")
        score -= 20

    # Generic SecurityEvent with only EventID filter
    if KQL_GENERIC_SECURITY_EVENT_RE.search(kql_text) and not KQL_HAS_SPECIFIC_RE.search(kql_text):
        issues.append("generic_kql_stub")
        score -= 25

    # Reward specific conditions
    if KQL_HAS_SPECIFIC_RE.search(kql_text):
        score += 35

    # Reward CVE reference
    if KQL_NO_CVE_CONTEXT_RE.search(kql_text):
        score += 10

    # Check comment contains CVE context
    if "// SENTINEL APEX" in kql_text and not KQL_HAS_SPECIFIC_RE.search(kql_text):
        issues.append("generic_kql_stub")
        score -= 10

    score = max(0, min(100, score))

    if "generic_kql_stub" in issues or (
        "generic_eventid_rule" in issues and not KQL_HAS_SPECIFIC_RE.search(kql_text)
    ):
        return "PLACEHOLDER", issues, score

    if issues:
        return "HYPOTHESIS", issues, score

    if score >= 75:
        return "LAB_VALIDATED", issues, score

    return "HYPOTHESIS", issues, score


def _classify_suricata(suricata_text: str, context: Dict[str, Any]) -> Tuple[str, List[str], int]:
    """Returns: (confidence_class, reasons_list, specificity_score)"""
    if not suricata_text or not suricata_text.strip():
        return "PLACEHOLDER", ["suricata_rule_empty"], 0

    issues = []
    score = 50

    # NOP sled — generic exploit attempt, cannot fingerprint specific CVE
    if SURICATA_NOP_SLED_RE.search(suricata_text):
        issues.append("generic_suricata_stub")
        issues.append("nop_sled_not_cve_specific")
        score -= 40

    # Generic class label
    if SURICATA_GENERIC_CLASS_RE.search(suricata_text):
        issues.append("generic_suricata_stub")
        score -= 15

    # Reward specific content
    if SURICATA_HAS_SPECIFIC_RE.search(suricata_text) and not SURICATA_NOP_SLED_RE.search(suricata_text):
        score += 30

    # Reward CVE reference
    if SURICATA_HAS_CVE_RE.search(suricata_text):
        score += 10

    # Reward pcre patterns (specific)
    if re.search(r"pcre\s*:", suricata_text, re.IGNORECASE):
        score += 15

    score = max(0, min(100, score))

    if "generic_suricata_stub" in issues:
        return "PLACEHOLDER", issues, score

    if issues:
        return "HYPOTHESIS", issues, score

    if score >= 75:
        return "LAB_VALIDATED", issues, score

    return "HYPOTHESIS", issues, score


def _resolve_overall_class(
    sigma_class: str,
    kql_class: str,
    suricata_class: str,
    sigma_score: int,
    kql_score: int,
    suricata_score: int,
) -> Tuple[str, float]:
    """
    Resolve the overall detection confidence class from the three rule types.
    The overall class is the WORST of the three (conservative).
    """
    priority = {"PRODUCTION": 4, "LAB_VALIDATED": 3, "HYPOTHESIS": 2, "PLACEHOLDER": 1}

    classes = [sigma_class, kql_class, suricata_class]
    scores = [sigma_score, kql_score, suricata_score]

    # Overall = worst class (min priority)
    worst_class = min(classes, key=lambda c: priority[c])

    # Average score
    avg_score = round(sum(scores) / len(scores), 1)

    return worst_class, avg_score


def classify_detection(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify detection content in a single record.
    Returns detection specificity result.
    """
    sigma = record.get("sigma_rule", "") or ""
    kql   = record.get("kql_query", "") or ""
    suri  = record.get("suricata_rule", "") or ""

    context = {
        "title": record.get("title", ""),
        "cve_id": record.get("cve_id", ""),
        "cvss_score": record.get("cvss_score"),
        "threat_type": record.get("threat_type", ""),
    }

    sigma_class, sigma_issues, sigma_score   = _classify_sigma(sigma, context)
    kql_class, kql_issues, kql_score         = _classify_kql(kql, context)
    suri_class, suri_issues, suri_score      = _classify_suricata(suri, context)

    overall_class, avg_score = _resolve_overall_class(
        sigma_class, kql_class, suri_class,
        sigma_score, kql_score, suri_score,
    )

    # Block decision
    blocked = overall_class == "PLACEHOLDER"
    block_reason = None
    if blocked:
        all_issues = sigma_issues + kql_issues + suri_issues
        block_reason = "; ".join(sorted(set(all_issues)))

    # Publication gates
    publishable_enterprise = overall_class in ("PRODUCTION", "LAB_VALIDATED")
    publishable_threat_hunter = overall_class in ("PRODUCTION", "LAB_VALIDATED", "HYPOTHESIS")

    prev_status = record.get("detection_quality_status", "UNKNOWN")
    prev_production_ready = record.get("detection_production_ready", False)

    # Detect false "production ready" flag
    false_production_flag = prev_production_ready and blocked

    return {
        "engine_id": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "stage_id": STAGE_ID,
        "processed_at": datetime.now(timezone.utc).isoformat(),

        "sigma_class": sigma_class,
        "sigma_issues": sigma_issues,
        "sigma_specificity_score": sigma_score,

        "kql_class": kql_class,
        "kql_issues": kql_issues,
        "kql_specificity_score": kql_score,

        "suricata_class": suri_class,
        "suricata_issues": suri_issues,
        "suricata_specificity_score": suri_score,

        "detection_confidence_class": overall_class,
        "detection_specificity_score": avg_score,
        "detection_blocked": blocked,
        "detection_block_reason": block_reason,

        "publishable_enterprise_feed": publishable_enterprise,
        "publishable_threat_hunter_feed": publishable_threat_hunter,

        "prev_detection_quality_status": prev_status,
        "prev_production_ready_flag": prev_production_ready,
        "false_production_flag_detected": false_production_flag,
    }


# =============================================================================
# Feed-Level Processing
# =============================================================================

def process_feed(feed: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Process entire feed. Returns detection specificity report."""

    record_results = []
    blocked_count = 0
    false_production_flags = 0
    class_distribution: Dict[str, int] = {}
    total_score = 0.0

    for record in feed:
        result = classify_detection(record)
        record_results.append({
            "id": record.get("id"),
            "title": record.get("title", ""),
            **result,
        })

        cls = result["detection_confidence_class"]
        class_distribution[cls] = class_distribution.get(cls, 0) + 1

        if result["detection_blocked"]:
            blocked_count += 1
        if result["false_production_flag_detected"]:
            false_production_flags += 1
        total_score += result["detection_specificity_score"]

    avg_score = round(total_score / len(feed), 1) if feed else 0.0

    # Before state: how many were marked production_ready
    prev_production_ready_count = sum(
        1 for r in feed if r.get("detection_production_ready", False)
    )

    enterprise_publishable = class_distribution.get("PRODUCTION", 0) + class_distribution.get("LAB_VALIDATED", 0)

    report = {
        "report_metadata": {
            "engine_id": ENGINE_ID,
            "engine_version": ENGINE_VERSION,
            "stage_id": STAGE_ID,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records_processed": len(feed),
        },

        "before_metrics": {
            "marked_production_ready": prev_production_ready_count,
            "enterprise_publishable_prev": prev_production_ready_count,
        },

        "after_metrics": {
            "detection_class_distribution": class_distribution,
            "blocked_count": blocked_count,
            "enterprise_publishable": enterprise_publishable,
            "false_production_flags_corrected": false_production_flags,
            "average_specificity_score": avg_score,
        },

        "delta": {
            "enterprise_publishable_reduction": prev_production_ready_count - enterprise_publishable,
            "false_production_flags": false_production_flags,
            "blocked_from_enterprise_feed": blocked_count,
        },

        "governance": {
            "block_placeholder_from_enterprise": True,
            "block_placeholder_from_mssp": True,
            "hypothesis_restricted_to_threat_hunter_feed": True,
            "false_production_flags_must_be_remediated": false_production_flags > 0,
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
        description="SENTINEL APEX Detection Specificity Engine v1.0.0 — Stage 6.96"
    )
    parser.add_argument("--feed", default="data/stix/feed_manifest.json")
    parser.add_argument("--output", default="reports/detection_specificity_report.json")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        print(f"[DETECTION-SPEC] ERROR: Feed not found: {feed_path}")
        sys.exit(1)

    feed = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(feed, list):
        feed = [feed]

    print(f"[DETECTION-SPEC] Processing {len(feed)} records...")
    report = process_feed(feed)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[DETECTION-SPEC] Report written → {out_path}")

    if args.summary:
        b = report["before_metrics"]
        a = report["after_metrics"]
        d = report["delta"]
        print("\n" + "=" * 60)
        print("DETECTION SPECIFICITY ENGINE — SUMMARY")
        print("=" * 60)
        print(f"  Records processed            : {report['report_metadata']['total_records_processed']}")
        print(f"  Prev marked production_ready : {b['marked_production_ready']}")
        print(f"  Class distribution           : {a['detection_class_distribution']}")
        print(f"  Enterprise publishable       : {a['enterprise_publishable']}")
        print(f"  BLOCKED (PLACEHOLDER)        : {a['blocked_count']}")
        print(f"  False production flags fixed : {d['false_production_flags']}")
        print(f"  Avg specificity score        : {a['average_specificity_score']}/100")
        print("=" * 60)

    return report


if __name__ == "__main__":
    main()
