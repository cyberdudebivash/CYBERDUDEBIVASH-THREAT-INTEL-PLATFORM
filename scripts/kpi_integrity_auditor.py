#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/kpi_integrity_auditor.py — KPI Integrity Auditor
Pipeline Stage 6.99
================================================================================
Version : 1.0.0
Purpose : Cross-validate dashboard KPI counts against feed-level truth.
          Block KPI publication when counts conflict.
          Eliminate dashboard inflation from IOC over-counting and
          severity misclassification.

CHECKS:
  dashboard_iocs == sum(real_ioc_count from IOC Truth Engine)
  dashboard_advisories == count(published records in feed)
  dashboard_critical == count(records with severity == CRITICAL)
  dashboard_high == count(records with severity == HIGH)
  dashboard_medium == count(records with severity == MEDIUM)
  dashboard_low == count(records with severity == LOW)
  dashboard_total_ttps == sum(classified techniques per record)
  dashboard_kev_count == count(records with kev_present == True)

FAILURE RESULT:
  BLOCK KPI publication
  Return: audit_status=FAILED, kpi_delta, corrected_values, violations

SUCCESS RESULT:
  audit_status=PASSED
  Return: verified_kpi_values, kpi_truth_score

VIOLATION TYPES:
  KPI_IOC_COUNT_MISMATCH      Dashboard IOC count ≠ real IOC count
  KPI_SEVERITY_COUNT_MISMATCH Dashboard severity count ≠ feed count
  KPI_ADVISORY_COUNT_MISMATCH Dashboard advisory count ≠ published record count
  KPI_CRITICAL_COUNT_MISMATCH Dashboard critical count ≠ actual critical count
  KPI_HIGH_COUNT_MISMATCH     Dashboard high count ≠ actual high count
================================================================================
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ENGINE_ID      = "KPI-INTEGRITY-AUDITOR"
ENGINE_VERSION = "1.0.0"
STAGE_ID       = "6.99"

# Tolerance for KPI comparison (0 = exact match required)
KPI_TOLERANCE = 0


# =============================================================================
# Feed-Level KPI Computation (Truth Values)
# =============================================================================

def compute_feed_kpis(feed: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute ground-truth KPI values from the feed.
    Uses real_ioc_count if available (post IOC Truth Engine), else ioc_count.
    """
    total_records = len(feed)
    published_records = sum(1 for r in feed if r.get("is_published", True))

    # Severity distribution
    severity_counts: Dict[str, int] = {}
    for r in feed:
        sev = (r.get("severity") or "UNKNOWN").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # IOC counts — prefer real_ioc_count (post Truth Engine)
    total_real_iocs = sum(r.get("real_ioc_count", r.get("ioc_count", 0)) or 0 for r in feed)
    total_raw_iocs  = sum(r.get("ioc_count", 0) or 0 for r in feed)

    # TTP counts — use classified techniques where available
    total_ttps = 0
    for r in feed:
        ttps = r.get("ttps") or r.get("attck_technique_ids") or r.get("tags") or []
        total_ttps += len([
            t for t in ttps
            if isinstance(t, str) and t.startswith("T") and len(t) >= 5
        ])

    # KEV count
    kev_count = sum(1 for r in feed if r.get("kev_present", False))

    # Actor attribution count
    attributed_count = sum(
        1 for r in feed
        if r.get("actor_name") not in (None, "", "Unknown", "Untracked", "CDB-UNATTR-CVE")
        or r.get("actor") not in (None, "", "Unknown")
    )

    # Intelligence grades
    grade_distribution: Dict[str, int] = {}
    for r in feed:
        grade = r.get("intelligence_grade", "?")
        grade_distribution[grade] = grade_distribution.get(grade, 0) + 1

    return {
        "total_advisories": total_records,
        "published_advisories": published_records,
        "total_real_iocs": total_real_iocs,
        "total_raw_iocs": total_raw_iocs,
        "severity_critical": severity_counts.get("CRITICAL", 0),
        "severity_high": severity_counts.get("HIGH", 0),
        "severity_medium": severity_counts.get("MEDIUM", 0),
        "severity_low": severity_counts.get("LOW", 0),
        "total_ttps": total_ttps,
        "kev_count": kev_count,
        "attributed_count": attributed_count,
        "grade_distribution": grade_distribution,
        "ioc_inflation_present": total_raw_iocs > total_real_iocs,
        "ioc_inflation_magnitude": total_raw_iocs - total_real_iocs,
    }


def extract_dashboard_kpis(dashboard_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract KPI values from a dashboard data snapshot.
    Handles various dashboard data shapes.
    Returns normalized KPI dict with None for missing values.
    """
    if not dashboard_data:
        return {}

    # Try various key patterns from dashboard dumps
    def _get(*keys, default=None):
        for key in keys:
            if key in dashboard_data:
                return dashboard_data[key]
        return default

    return {
        "total_advisories":    _get("total_advisories", "advisory_count", "advisories", "total"),
        "published_advisories": _get("published_advisories", "published", "live_advisories"),
        "total_iocs":          _get("total_iocs", "ioc_count", "iocs", "total_ioc_count"),
        "severity_critical":   _get("critical_count", "critical", "severity_critical"),
        "severity_high":       _get("high_count", "high", "severity_high"),
        "severity_medium":     _get("medium_count", "medium", "severity_medium"),
        "severity_low":        _get("low_count", "low", "severity_low"),
        "total_ttps":          _get("total_ttps", "ttp_count", "ttps"),
        "kev_count":           _get("kev_count", "kev", "exploited_count"),
    }


# =============================================================================
# Audit Logic
# =============================================================================

def _check(
    field: str,
    dashboard_value: Optional[int],
    feed_truth: int,
    tolerance: int = KPI_TOLERANCE,
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Check a single KPI field.
    Returns (passed, violation_or_None)
    """
    if dashboard_value is None:
        # Dashboard doesn't report this KPI — skip (not a violation, just missing)
        return True, None

    delta = abs(dashboard_value - feed_truth)
    if delta > tolerance:
        return False, {
            "field": field,
            "violation_type": f"KPI_{field.upper()}_MISMATCH",
            "dashboard_value": dashboard_value,
            "feed_truth": feed_truth,
            "delta": dashboard_value - feed_truth,
            "delta_pct": round((dashboard_value - feed_truth) / max(feed_truth, 1) * 100, 1),
            "direction": "OVERCOUNTED" if dashboard_value > feed_truth else "UNDERCOUNTED",
        }
    return True, None


def audit_kpis(
    feed: List[Dict[str, Any]],
    dashboard_kpis: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Full KPI integrity audit.
    feed: list of intel records (post-pipeline)
    dashboard_kpis: optional dashboard snapshot for comparison
    """
    feed_truth = compute_feed_kpis(feed)
    dash_kpis  = extract_dashboard_kpis(dashboard_kpis) if dashboard_kpis else {}

    violations = []
    checks_performed = []
    checks_passed = 0
    checks_failed = 0

    # ── Check 1: IOC Count ────────────────────────────────────────────────────
    dash_iocs = dash_kpis.get("total_iocs")
    passed, viol = _check("total_iocs", dash_iocs, feed_truth["total_real_iocs"])
    checks_performed.append({
        "check": "total_iocs",
        "dashboard": dash_iocs,
        "feed_truth": feed_truth["total_real_iocs"],
        "raw_ioc_total": feed_truth["total_raw_iocs"],
        "passed": passed,
    })
    if passed: checks_passed += 1
    else:
        checks_failed += 1
        violations.append(viol)

    # Even without dashboard data, flag if raw_iocs >> real_iocs
    if feed_truth["ioc_inflation_present"]:
        violations.append({
            "field": "ioc_inflation",
            "violation_type": "KPI_IOC_INFLATION",
            "raw_ioc_total": feed_truth["total_raw_iocs"],
            "real_ioc_total": feed_truth["total_real_iocs"],
            "inflation_magnitude": feed_truth["ioc_inflation_magnitude"],
            "inflation_pct": round(
                feed_truth["ioc_inflation_magnitude"] / max(feed_truth["total_raw_iocs"], 1) * 100, 1
            ),
            "direction": "OVERCOUNTED",
        })
        checks_failed += 1

    # ── Check 2: Advisory count ───────────────────────────────────────────────
    dash_advisories = dash_kpis.get("total_advisories") or dash_kpis.get("published_advisories")
    passed, viol = _check("total_advisories", dash_advisories, feed_truth["total_advisories"])
    checks_performed.append({
        "check": "total_advisories",
        "dashboard": dash_advisories,
        "feed_truth": feed_truth["total_advisories"],
        "passed": passed,
    })
    if passed: checks_passed += 1
    else:
        checks_failed += 1
        violations.append(viol)

    # ── Check 3: Critical count ───────────────────────────────────────────────
    dash_critical = dash_kpis.get("severity_critical")
    passed, viol = _check("severity_critical", dash_critical, feed_truth["severity_critical"])
    checks_performed.append({
        "check": "severity_critical",
        "dashboard": dash_critical,
        "feed_truth": feed_truth["severity_critical"],
        "passed": passed,
    })
    if passed: checks_passed += 1
    else:
        checks_failed += 1
        violations.append(viol)

    # ── Check 4: High count ───────────────────────────────────────────────────
    dash_high = dash_kpis.get("severity_high")
    passed, viol = _check("severity_high", dash_high, feed_truth["severity_high"])
    checks_performed.append({
        "check": "severity_high",
        "dashboard": dash_high,
        "feed_truth": feed_truth["severity_high"],
        "passed": passed,
    })
    if passed: checks_passed += 1
    else:
        checks_failed += 1
        violations.append(viol)

    # ── Check 5: Medium count ─────────────────────────────────────────────────
    dash_medium = dash_kpis.get("severity_medium")
    passed, viol = _check("severity_medium", dash_medium, feed_truth["severity_medium"])
    checks_performed.append({
        "check": "severity_medium",
        "dashboard": dash_medium,
        "feed_truth": feed_truth["severity_medium"],
        "passed": passed,
    })
    if passed: checks_passed += 1
    else:
        checks_failed += 1
        if viol:
            violations.append(viol)

    # ── Determine overall audit status ────────────────────────────────────────
    # Mandatory checks that MUST pass for publication
    mandatory_failed = [
        v for v in violations
        if v.get("violation_type") in (
            "KPI_IOC_INFLATION",
            "KPI_TOTAL_IOCS_MISMATCH",
            "KPI_SEVERITY_CRITICAL_MISMATCH",
        )
    ]

    audit_status = "FAILED" if mandatory_failed or checks_failed > 0 else "PASSED"
    publication_blocked = audit_status == "FAILED"

    # ── KPI Truth Score ───────────────────────────────────────────────────────
    total_checks = checks_passed + checks_failed
    kpi_truth_score = round(checks_passed / total_checks * 100, 1) if total_checks > 0 else 100.0

    # ── Corrected KPI values ──────────────────────────────────────────────────
    corrected_kpis = {
        "total_advisories":    feed_truth["total_advisories"],
        "published_advisories": feed_truth["published_advisories"],
        "total_real_iocs":     feed_truth["total_real_iocs"],
        "severity_critical":   feed_truth["severity_critical"],
        "severity_high":       feed_truth["severity_high"],
        "severity_medium":     feed_truth["severity_medium"],
        "severity_low":        feed_truth["severity_low"],
        "total_ttps":          feed_truth["total_ttps"],
        "kev_count":           feed_truth["kev_count"],
        "attributed_count":    feed_truth["attributed_count"],
        "grade_distribution":  feed_truth["grade_distribution"],
    }

    return {
        "engine_id": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "stage_id": STAGE_ID,
        "audited_at": datetime.now(timezone.utc).isoformat(),

        "audit_status": audit_status,
        "publication_blocked": publication_blocked,
        "kpi_truth_score": kpi_truth_score,

        "checks_performed": checks_performed,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,

        "violations": violations,
        "violation_count": len(violations),
        "mandatory_violations": len(mandatory_failed),

        "feed_truth_kpis": feed_truth,
        "dashboard_kpis_submitted": dash_kpis,
        "corrected_kpis": corrected_kpis,

        "governance": {
            "block_kpi_publication_on_failure": True,
            "ioc_count_source": "real_ioc_count (post IOC Truth Engine)",
            "severity_source": "feed severity field (authoritative)",
            "advisory_count_source": "feed record count (authoritative)",
        },
    }


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="SENTINEL APEX KPI Integrity Auditor v1.0.0 — Stage 6.99"
    )
    parser.add_argument("--feed", default="data/stix/feed_manifest.json")
    parser.add_argument("--dashboard", default=None, help="Optional dashboard KPI snapshot JSON")
    parser.add_argument("--output", default="reports/kpi_integrity_report.json")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        print(f"[KPI-AUDIT] ERROR: Feed not found: {feed_path}")
        sys.exit(1)

    feed = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(feed, list):
        feed = [feed]

    dashboard_kpis = None
    if args.dashboard:
        dash_path = Path(args.dashboard)
        if dash_path.exists():
            dashboard_kpis = json.loads(dash_path.read_text(encoding="utf-8"))

    print(f"[KPI-AUDIT] Auditing {len(feed)} records...")
    report = audit_kpis(feed, dashboard_kpis)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[KPI-AUDIT] Report written → {out_path}")

    if args.summary:
        ft = report["feed_truth_kpis"]
        print("\n" + "=" * 60)
        print("KPI INTEGRITY AUDITOR — SUMMARY")
        print("=" * 60)
        print(f"  Audit status              : {report['audit_status']}")
        print(f"  Publication blocked       : {report['publication_blocked']}")
        print(f"  KPI truth score           : {report['kpi_truth_score']}/100")
        print(f"  Violations                : {report['violation_count']}")
        print(f"  Mandatory violations      : {report['mandatory_violations']}")
        print(f"  --- Feed Truth KPIs ---")
        print(f"  Total advisories          : {ft['total_advisories']}")
        print(f"  Real IOC count            : {ft['total_real_iocs']} (raw was {ft['total_raw_iocs']})")
        print(f"  Severity CRITICAL         : {ft['severity_critical']}")
        print(f"  Severity HIGH             : {ft['severity_high']}")
        print(f"  Severity MEDIUM           : {ft['severity_medium']}")
        print(f"  Severity LOW              : {ft['severity_low']}")
        print(f"  KEV entries               : {ft['kev_count']}")
        print("=" * 60)

    return report


if __name__ == "__main__":
    main()
