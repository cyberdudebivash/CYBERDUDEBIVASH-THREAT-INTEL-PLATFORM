#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/attack_confidence_engine.py — ATT&CK Confidence Engine
Pipeline Stage 6.97
================================================================================
Version : 1.0.0
Purpose : Enforce ATT&CK technique attribution integrity.
          Prevent derived/speculative mappings from being published
          as observed/confirmed behavior.

CONFIDENCE CLASSES (per technique per record):
  OBSERVED          Direct behavioral evidence observed (log/artifact/IOC)
  VENDOR_CONFIRMED  Vendor advisory explicitly names the technique
  CORROBORATED      Two or more independent sources confirm the technique
  DERIVED           Inferred from CVE type, product category, or description
  SPECULATIVE       Generic assignment without supporting evidence

ENTERPRISE FEED RULES:
  - OBSERVED and VENDOR_CONFIRMED: publishable to all feeds
  - CORROBORATED: publishable to enterprise feed with confidence label
  - DERIVED: publishable with DERIVED label, may NOT be displayed as observed
  - SPECULATIVE: blocked from enterprise feed, allowed in public tier with warning

DERIVATION RULES (evidence-based technique assignment from CVE data):
  Remote Code Execution CVE   → T1190 (DERIVED), T1059 (SPECULATIVE)
  SQL Injection CVE           → T1190 (DERIVED), T1078 (SPECULATIVE)
  Cross-Site Scripting CVE    → T1059.007 (DERIVED)
  File Inclusion CVE          → T1190 (DERIVED), T1083 (SPECULATIVE)
  Authentication Bypass CVE   → T1078 (DERIVED)
  DoS/Resource Consumption    → T1499 (DERIVED)
  SSRF CVE                    → T1090 (DERIVED), T1071 (SPECULATIVE)
  Path Traversal CVE          → T1083 (DERIVED)
  CSRF CVE                    → T1185 (SPECULATIVE)
================================================================================
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ENGINE_ID      = "ATTACK-CONFIDENCE-ENGINE"
ENGINE_VERSION = "1.0.0"
STAGE_ID       = "6.97"

# =============================================================================
# Evidence Signals
# =============================================================================

# Vendor advisory signals in text (raise confidence toward VENDOR_CONFIRMED)
VENDOR_ADVISORY_RE = re.compile(
    r"(?:vendor|advisory|bulletin|patch|security\s+notice|"
    r"security\s+advisory|common\s+vulnerability|nvd|nist|cve\.mitre)",
    re.IGNORECASE,
)

# Observed behavioral evidence signals
OBSERVED_EVIDENCE_RE = re.compile(
    r"(?:actively\s+exploited|in\s+the\s+wild|kev|known\s+exploited|"
    r"confirmed\s+exploitation|incident\s+report|threat\s+actor\s+used|"
    r"attributed\s+to|observed\s+in\s+campaign|deployed\s+by)",
    re.IGNORECASE,
)

# IOC co-presence signals (if record has real IOCs, technique confidence rises)
IOC_CO_PRESENCE_TYPES = {"SHA256", "SHA512", "SHA1", "MD5", "IPV4", "IPV6", "DOMAIN", "FQDN"}

# CVE description → technique mapping rules
# Format: (title/description pattern, technique_id, baseline_confidence)
CVE_TECHNIQUE_RULES: List[Tuple[re.Pattern, str, str, str]] = [
    # (pattern, technique_id, technique_name, baseline_confidence)
    (re.compile(r"(?:remote\s*code\s*exec|rce|arbitrary\s*code|command\s*injection)", re.I),
     "T1190", "Exploit Public-Facing Application", "DERIVED"),

    (re.compile(r"(?:sql\s*injection|sqli)", re.I),
     "T1190", "Exploit Public-Facing Application", "DERIVED"),

    (re.compile(r"(?:cross[\s\-]?site\s*script|xss)", re.I),
     "T1059.007", "JavaScript/JScript", "DERIVED"),

    (re.compile(r"(?:file\s*inclus|path\s*travers|directory\s*travers)", re.I),
     "T1083", "File and Directory Discovery", "DERIVED"),

    (re.compile(r"(?:server[\s\-]?side\s*request\s*forg|ssrf)", re.I),
     "T1090", "Proxy", "DERIVED"),

    (re.compile(r"(?:authentication\s*bypass|auth\s*bypass|improper\s*auth|"
                r"missing\s*auth|broken\s*auth)", re.I),
     "T1078", "Valid Accounts", "DERIVED"),

    (re.compile(r"(?:denial\s*of\s*service|dos|resource\s*consump|"
                r"memory\s*exhaust|cpu\s*exhaust)", re.I),
     "T1499", "Endpoint Denial of Service", "DERIVED"),

    (re.compile(r"(?:privilege\s*escal|privesc|sandbox\s*escape|"
                r"local\s*priv)", re.I),
     "T1068", "Exploitation for Privilege Escalation", "DERIVED"),

    (re.compile(r"(?:cross[\s\-]?site\s*request\s*forg|csrf)", re.I),
     "T1185", "Browser Session Hijacking", "SPECULATIVE"),

    (re.compile(r"(?:use\s*after\s*free|uaf|buffer\s*overflow|"
                r"heap\s*overflow|stack\s*overflow)", re.I),
     "T1190", "Exploit Public-Facing Application", "DERIVED"),

    (re.compile(r"(?:information\s*disclos|data\s*exposure|"
                r"sensitive\s*data|secret\s*leak)", re.I),
     "T1552", "Unsecured Credentials", "SPECULATIVE"),

    # T1059 (scripting) is commonly over-applied — require explicit evidence
    (re.compile(r"(?:script\s*injection|eval\s*injection|template\s*injection)", re.I),
     "T1059", "Command and Scripting Interpreter", "DERIVED"),
]

# Techniques that should NEVER be assigned from CVE title alone without IOC/behavioral evidence
HIGH_CONFIDENCE_REQUIRED = {
    "T1059",    # Scripting — too generic without behavioral evidence
    "T1036",    # Masquerading
    "T1027",    # Obfuscation
    "T1055",    # Process Injection
    "T1003",    # Credential Dumping
    "T1021",    # Remote Services
}

# =============================================================================
# Confidence Assignment
# =============================================================================

def _determine_technique_confidence(
    technique_id: str,
    baseline_confidence: str,
    record: Dict[str, Any],
    title_text: str,
    desc_text: str,
) -> Tuple[str, List[str]]:
    """
    Upgrade or downgrade baseline confidence based on available evidence.
    Returns (final_confidence_class, evidence_notes)
    """
    notes = []
    conf = baseline_confidence

    # Signal 1: KEV (Known Exploited Vulnerability) → VENDOR_CONFIRMED
    if record.get("kev_present", False):
        if conf in ("DERIVED", "SPECULATIVE", "CORROBORATED"):
            conf = "VENDOR_CONFIRMED"
            notes.append("KEV entry — actively exploited, CISA confirmed")

    # Signal 2: Observed exploitation evidence in text
    combined_text = f"{title_text} {desc_text}"
    if OBSERVED_EVIDENCE_RE.search(combined_text):
        if conf in ("DERIVED", "SPECULATIVE"):
            conf = "CORROBORATED"
            notes.append("exploitation language detected in description")

    # Signal 3: Vendor advisory language
    if VENDOR_ADVISORY_RE.search(combined_text):
        if conf == "SPECULATIVE":
            conf = "DERIVED"
            notes.append("vendor advisory context present")

    # Signal 4: Real IOC co-presence (not CVE refs or filenames)
    real_ioc_count = record.get("real_ioc_count", 0)
    if real_ioc_count > 0:
        if conf == "DERIVED":
            conf = "CORROBORATED"
            notes.append(f"{real_ioc_count} real operational IOC(s) co-present")

    # Signal 5: Multiple corroboration sources
    corroboration_count = record.get("corroboration_count", 0)
    if corroboration_count >= 3 and conf in ("DERIVED", "CORROBORATED"):
        conf = "CORROBORATED"
        notes.append(f"corroboration_count={corroboration_count}")

    # Signal 6: High-confidence-required techniques need demotion if no real evidence
    if technique_id in HIGH_CONFIDENCE_REQUIRED and conf not in ("OBSERVED", "VENDOR_CONFIRMED"):
        if real_ioc_count == 0 and not record.get("kev_present", False):
            conf = "SPECULATIVE"
            notes.append(f"{technique_id} requires behavioral evidence — demoted to SPECULATIVE")

    # Protect OBSERVED — never auto-assign from CVE description
    if conf == "OBSERVED" and not (
        OBSERVED_EVIDENCE_RE.search(combined_text) or record.get("kev_present", False)
    ):
        conf = "CORROBORATED"
        notes.append("OBSERVED demoted to CORROBORATED — insufficient direct evidence")

    return conf, notes


def classify_attck(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Classify ATT&CK technique confidence for a single record.
    """
    title = record.get("title", "")
    description = record.get("description", "")
    combined = f"{title} {description}".lower()

    # Existing techniques in the record
    existing_techniques: List[str] = []
    existing_techniques.extend(record.get("ttps", []) or [])
    existing_techniques.extend(record.get("attck_technique_ids", []) or [])
    existing_techniques.extend(record.get("tags", []) or [])

    # Deduplicate
    existing_techniques = list(dict.fromkeys(
        t.strip() for t in existing_techniques
        if re.match(r"^T\d{4}(?:\.\d{3})?$", t.strip())
    ))

    prev_verification = record.get("attck_verification", "UNKNOWN")
    prev_notes = record.get("attck_notes", [])

    classified_techniques = []
    violations = []

    # Step 1: Classify existing techniques using CVE rules
    for tech_id in existing_techniques:
        # Find baseline from CVE rules
        baseline = "SPECULATIVE"  # Default: speculative if no rule matches
        match_note = "no CVE description match — generic assignment"

        for pattern, rule_tech_id, rule_tech_name, rule_baseline in CVE_TECHNIQUE_RULES:
            if rule_tech_id == tech_id and pattern.search(combined):
                baseline = rule_baseline
                match_note = f"matched CVE description pattern for {rule_tech_name}"
                break

        # Determine final confidence
        final_conf, evidence_notes = _determine_technique_confidence(
            tech_id, baseline, record, title, description
        )

        classified_techniques.append({
            "technique_id": tech_id,
            "baseline_confidence": baseline,
            "final_confidence": final_conf,
            "evidence_notes": [match_note] + evidence_notes,
        })

        # Violation: was previously marked EVIDENCE_BASED but is actually DERIVED/SPECULATIVE
        if prev_verification == "EVIDENCE_BASED" and final_conf in ("DERIVED", "SPECULATIVE"):
            violations.append({
                "technique_id": tech_id,
                "violation": "FALSE_EVIDENCE_BASED_CLAIM",
                "prev_verification": prev_verification,
                "corrected_confidence": final_conf,
                "detail": "Technique was labelled EVIDENCE_BASED but evidence only supports DERIVED/SPECULATIVE",
            })

    # Step 2: Auto-derive additional techniques not already present
    auto_derived = []
    for pattern, tech_id, tech_name, baseline in CVE_TECHNIQUE_RULES:
        if pattern.search(combined) and tech_id not in existing_techniques:
            final_conf, evidence_notes = _determine_technique_confidence(
                tech_id, baseline, record, title, description
            )
            auto_derived.append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "baseline_confidence": baseline,
                "final_confidence": final_conf,
                "evidence_notes": ["auto-derived from CVE description"] + evidence_notes,
                "source": "auto_derived",
            })

    # Compute overall verification status
    all_confs = [t["final_confidence"] for t in classified_techniques]
    if all_confs:
        if all(c in ("OBSERVED", "VENDOR_CONFIRMED") for c in all_confs):
            overall_verification = "EVIDENCE_BASED"
        elif any(c in ("OBSERVED", "VENDOR_CONFIRMED", "CORROBORATED") for c in all_confs):
            overall_verification = "PARTIALLY_VERIFIED"
        elif all(c == "DERIVED" for c in all_confs):
            overall_verification = "DERIVED_ONLY"
        else:
            overall_verification = "SPECULATIVE_ONLY"
    else:
        overall_verification = "NO_TECHNIQUES"

    # Enterprise feed publication check
    publishable_enterprise = all(
        t["final_confidence"] in ("OBSERVED", "VENDOR_CONFIRMED", "CORROBORATED", "DERIVED")
        for t in classified_techniques
    )

    return {
        "engine_id": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "stage_id": STAGE_ID,
        "processed_at": datetime.now(timezone.utc).isoformat(),

        "prev_attck_verification": prev_verification,
        "prev_attck_notes": prev_notes,

        "classified_techniques": classified_techniques,
        "auto_derived_techniques": auto_derived,

        "overall_attck_verification": overall_verification,
        "techniques_classified_count": len(classified_techniques),

        "violations": violations,
        "violation_count": len(violations),

        "publishable_enterprise": publishable_enterprise,
        "requires_derived_label": any(
            t["final_confidence"] == "DERIVED" for t in classified_techniques
        ),
        "requires_speculative_warning": any(
            t["final_confidence"] == "SPECULATIVE" for t in classified_techniques
        ),
    }


# =============================================================================
# Feed-Level Processing
# =============================================================================

def process_feed(feed: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Process entire feed. Returns ATT&CK confidence report."""

    record_results = []
    total_violations = 0
    false_evidence_based = 0
    verification_distribution: Dict[str, int] = {}
    confidence_distribution: Dict[str, int] = {}

    for record in feed:
        result = classify_attck(record)
        record_results.append({
            "id": record.get("id"),
            "title": record.get("title", ""),
            **result,
        })

        total_violations += result["violation_count"]
        if result["violation_count"] > 0:
            false_evidence_based += 1

        v = result["overall_attck_verification"]
        verification_distribution[v] = verification_distribution.get(v, 0) + 1

        for t in result["classified_techniques"]:
            c = t["final_confidence"]
            confidence_distribution[c] = confidence_distribution.get(c, 0) + 1

    # Before state
    prev_evidence_based = sum(
        1 for r in feed if r.get("attck_verification") == "EVIDENCE_BASED"
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
            "marked_evidence_based": prev_evidence_based,
            "pct_evidence_based": round(prev_evidence_based / len(feed) * 100, 1) if feed else 0,
        },

        "after_metrics": {
            "verification_distribution": verification_distribution,
            "technique_confidence_distribution": confidence_distribution,
            "false_evidence_based_corrected": false_evidence_based,
            "total_violations": total_violations,
        },

        "delta": {
            "evidence_based_reduction": prev_evidence_based - verification_distribution.get("EVIDENCE_BASED", 0),
            "false_evidence_based_flags": false_evidence_based,
        },

        "governance": {
            "derived_mappings_must_be_labelled": True,
            "speculative_mappings_blocked_from_enterprise": True,
            "false_evidence_based_claims_corrected": false_evidence_based,
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
        description="SENTINEL APEX ATT&CK Confidence Engine v1.0.0 — Stage 6.97"
    )
    parser.add_argument("--feed", default="data/stix/feed_manifest.json")
    parser.add_argument("--output", default="reports/attck_confidence_report.json")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        print(f"[ATT&CK-CONF] ERROR: Feed not found: {feed_path}")
        sys.exit(1)

    feed = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(feed, list):
        feed = [feed]

    print(f"[ATT&CK-CONF] Processing {len(feed)} records...")
    report = process_feed(feed)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[ATT&CK-CONF] Report written → {out_path}")

    if args.summary:
        b = report["before_metrics"]
        a = report["after_metrics"]
        d = report["delta"]
        print("\n" + "=" * 60)
        print("ATT&CK CONFIDENCE ENGINE — SUMMARY")
        print("=" * 60)
        print(f"  Records processed         : {report['report_metadata']['total_records_processed']}")
        print(f"  Prev EVIDENCE_BASED count : {b['marked_evidence_based']} ({b['pct_evidence_based']}%)")
        print(f"  Verification distribution : {a['verification_distribution']}")
        print(f"  Technique confidence dist : {a['technique_confidence_distribution']}")
        print(f"  False EVIDENCE_BASED fixed: {a['false_evidence_based_corrected']}")
        print(f"  Total violations          : {a['total_violations']}")
        print("=" * 60)

    return report


if __name__ == "__main__":
    main()
