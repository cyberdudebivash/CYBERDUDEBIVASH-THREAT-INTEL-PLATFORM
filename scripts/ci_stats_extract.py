#!/usr/bin/env python3
"""
scripts/ci_stats_extract.py
CI helper: extract summary stats from quality report JSON files for workflow display.
Usage: python3 scripts/ci_stats_extract.py <report_key>
  report_key: p21 | p22 | p23
Prints space-separated values on stdout; exits 0 always (non-blocking CI helper).
"""
from __future__ import annotations
import json, pathlib, sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent

_REPORTS: dict = {
    "p21": (
        _ROOT / "data" / "quality" / "p21_certification_report.json",
        lambda d: [
            d.get("total_items", 0),
            d.get("average_score", 0),
            d.get("level_distribution", {}).get("PREMIUM_CERTIFIED", 0),
            d.get("level_distribution", {}).get("ENTERPRISE_READY", 0),
        ],
    ),
    "p22": (
        _ROOT / "data" / "quality" / "p22_contradiction_report.json",
        lambda d: [
            d.get("items_checked", 0),
            d.get("total_contradictions", 0),
            d.get("error_count", 0),
            d.get("warning_count", 0),
        ],
    ),
    "p23": (
        _ROOT / "data" / "quality" / "p23_patch_priority_report.json",
        lambda d: [
            d.get("items_processed", 0),
            d.get("immediate_count", 0),
        ],
    ),
    "p24": (
        _ROOT / "data" / "quality" / "p24_commercial_certification.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("overall_pct", 0),
            d.get("blocker_count", 0),
        ],
    ),
    "p25": (
        _ROOT / "data" / "quality" / "p25_enterprise_trust_gate.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("feed_items", 0),
        ],
    ),
    "p26": (
        _ROOT / "data" / "quality" / "p26_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("quality_summary", {}).get("p26_avg_composite", 0),
        ],
    ),
    "p27": (
        _ROOT / "data" / "quality" / "p27_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p28": (
        _ROOT / "data" / "quality" / "p28_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p29": (
        _ROOT / "data" / "quality" / "p29_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p30": (
        _ROOT / "data" / "quality" / "p30_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p31": (
        _ROOT / "data" / "quality" / "p31_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p32": (
        _ROOT / "data" / "quality" / "p32_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p33": (
        _ROOT / "data" / "quality" / "p33_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p34": (
        _ROOT / "data" / "quality" / "p34_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p35": (
        _ROOT / "data" / "quality" / "p35_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p36": (
        _ROOT / "data" / "quality" / "p36_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p37": (
        _ROOT / "data" / "quality" / "p37_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p38": (
        _ROOT / "data" / "quality" / "p38_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
        ],
    ),
    "p40": (
        _ROOT / "data" / "quality" / "p40_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
            d.get("source_registry", {}).get("total_sources", 0),
        ],
    ),
    "rx_pub_a0": (
        _ROOT / "data" / "quality" / "rx_pub_a0_reports_artifact_manifest.json",
        lambda d: [
            d.get("summary", {}).get("remote_verified", 0),
            d.get("summary", {}).get("stale_or_divergent_or_failed", 0),
            d.get("summary", {}).get("unknown", 0),
            d.get("summary", {}).get("live_verified", 0),
            d.get("summary", {}).get("live_stale_or_divergent_or_missing", 0),
            d.get("summary", {}).get("live_unknown", 0),
            # RX-PUB-A0.6A: appended, not inserted -- existing positional
            # consumers (sentinel-apex.yml's `read -r ... <<<`) keep
            # working unchanged; a consumer that wants the new fields reads
            # further positions.
            d.get("summary", {}).get("live_expected_denial", 0),
            d.get("summary", {}).get("live_resolution_failed", 0),
            d.get("summary", {}).get("live_fetch_failed", 0),
            d.get("summary", {}).get("live_not_processed_deadline", 0),
            d.get("summary", {}).get("publication_gate_bypass", 0),
        ],
    ),
    "frontend_api_coverage": (
        _ROOT / "data" / "quality" / "frontend_api_coverage_report.json",
        lambda d: [
            d.get("total_pages", 0),
            d.get("dynamic_count", 0),
            d.get("static_allowlisted_count", 0),
            d.get("static_unclassified_count", 0),
        ],
    ),
    "capability_registry": (
        _ROOT / "data" / "quality" / "frontend_capability_registry.json",
        lambda d: [
            d.get("total_pages", 0),
            d.get("unclassified_count", 0),
            d.get("customer_ui_orphan_count", 0),
            d.get("by_category", {}).get("CUSTOMER_UI", 0),
            d.get("by_category", {}).get("ADMIN", 0),
            d.get("by_category", {}).get("INTERNAL", 0),
        ],
    ),
    "metric_integrity_contract": (
        _ROOT / "data" / "quality" / "metric_integrity_contract_report.json",
        lambda d: [
            d.get("pages_scanned", 0),
            len(d.get("forbidden_hardcode_findings", [])),
            len(d.get("nav_leakage_findings", [])),
        ],
    ),
    "p41": (
        _ROOT / "data" / "quality" / "p41_certification_report.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("warning_count", 0),
            d.get("passed_count", 0),
            d.get("total_gates", 0),
            d.get("capability_registry", {}).get("customer_ui_count", 0),
        ],
    ),
    "capability_runtime": (
        _ROOT / "data" / "quality" / "capability_runtime_certification.json",
        lambda d: [
            d.get("total_customer_ui", 0),
            d.get("verdict_counts", {}).get("DYNAMIC_VERIFIED", 0),
            d.get("verdict_counts", {}).get("STATIC_VALID", 0),
            d.get("verdict_counts", {}).get("AUTH_GATED", 0),
            d.get("verdict_counts", {}).get("DEGRADED", 0),
            d.get("verdict_counts", {}).get("BROKEN", 0),
            d.get("verdict_counts", {}).get("ORPHANED", 0),
            d.get("verdict_counts", {}).get("MISCLASSIFIED", 0),
        ],
    ),
    # P0 R2 COST INCIDENT FIX (2026-09) -- scripts/r2_cost_guard.py's merged
    # per-run report (data/quality/r2_cost_guard_report.json). overall_status
    # is PASS/BLOCKED across every labeled plan recorded this run (r2_upload.py's
    # bounded data-bucket uploads, r2_report_publisher.py's publish/retire).
    "r2_cost_guard": (
        _ROOT / "data" / "quality" / "r2_cost_guard_report.json",
        lambda d: [
            d.get("overall_status", "UNKNOWN"),
            len(d.get("plans", {})),
            sum(p.get("put", 0) for p in d.get("plans", {}).values()),
            sum(p.get("delete", 0) for p in d.get("plans", {}).values()),
            sum(p.get("estimated_class_a", 0) for p in d.get("plans", {}).values()),
        ],
    ),
}

_FALLBACKS = {
    "p21": "? ? ? ?", "p22": "? ? ? ?", "p23": "? ?",
    "p24": "UNKNOWN 0 0", "p25": "UNKNOWN 0 0", "p26": "UNKNOWN 0 0 0",
    "p27": "UNKNOWN 0 0 0 0", "p28": "UNKNOWN 0 0 0 0",
    "p29": "UNKNOWN 0 0 0 0",
    "p30": "UNKNOWN 0 0 0 0",
    "p31": "UNKNOWN 0 0 0 0",
    "p32": "UNKNOWN 0 0 0 0",
    "p33": "UNKNOWN 0 0 0 0",
    "p34": "UNKNOWN 0 0 0 0",
    "p35": "UNKNOWN 0 0 0 0",
    "p36": "UNKNOWN 0 0 0 0",
    "p37": "UNKNOWN 0 0 0 0",
    "p38": "UNKNOWN 0 0 0 0",
    "p40": "UNKNOWN 0 0 0 0 0",
    "rx_pub_a0": "0 0 0 0 0 0 0 0 0 0 0",
    # CodeRabbit finding on PR #336 (verified, not taken on faith): all-zero
    # fallback values here are indistinguishable from a genuine "0 dynamic
    # pages" reading, so a script crash that leaves no report behind (never
    # reaches its own atomic write) would print a normal-looking coverage
    # notice instead of visibly failing. "?" placeholders match this file's
    # own p21 convention for the same reason (an all-numeric fallback tuple).
    "frontend_api_coverage": "? ? ? ?",
    "capability_registry": "? ? ? ? ? ?",
    "metric_integrity_contract": "? ? ?",
    "p41": "UNKNOWN 0 0 0 0 0",
    "capability_runtime": "0 0 0 0 0 0 0 0",
    "r2_cost_guard": "UNKNOWN 0 0 0 0",
}


def main() -> None:
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in _REPORTS:
        print(_FALLBACKS.get(key, "?"))
        return
    path, extractor = _REPORTS[key]
    try:
        data = json.loads(path.read_bytes())
        print(" ".join(str(v) for v in extractor(data)))
    except Exception:
        print(_FALLBACKS[key])


if __name__ == "__main__":
    main()
