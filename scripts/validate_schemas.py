#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Schema Validation + Regression Guard
=======================================================================
Version     : v134.0
Purpose     : Validate api/engines.json and api/ai/*.json schemas before
              deploy. Enforces data contracts so frontend/backend never
              diverge. Exits non-zero if any critical contract is violated.

Contracts enforced:
  - api/engines.json    : 12 engines, each with status + summary wrapper
  - api/ai/analyze.json : top_threats[].priority ∈ {P1,P2,P3,P4}
  - api/ai/respond.json : response_queue[].priority ∈ {P1,P2,P3,P4}
                          sla_hours ∈ {1,4,24} (P1/P2/P3+P4)
  - api/ai/correlate.json : clusters + ttp_graph present
  - No '?' values in any field (regression from Genesis fix)
  - No null/None in priority, risk_score, status, or version fields

Usage:
  python3 scripts/validate_schemas.py [--strict]
  --strict: exit 1 on ANY warning (used in CI pre-deploy gate)
  default : exit 1 on errors only, print warnings
"""

import json
import os
import sys
import argparse
from typing import Any, Dict, List, Tuple

# ─── Constants ────────────────────────────────────────────────────────────────

VALID_PRIORITIES = {"P1", "P2", "P3", "P4"}
VALID_SLA_HOURS  = {1, 4, 24}
VALID_STATUSES   = {"LIVE", "OK", "ACTIVE", "PENDING", "DEGRADED"}
REQUIRED_ENGINES = {
    "G01_SensorNetwork", "G02_ThreatIntel", "G03_VulnMgmt",
    "G04_BehaviorAnalytics", "G05_ThreatHunting", "G06_SOARResponse",
    "G07_IncidentMgmt", "G08_BugHunter", "G09_NexusCorrelation",
    "G10_ThreatActors", "G11_ComplianceGov", "G12_ExecutiveRisk",
}
QUESTION_MARK_FIELDS = {"priority", "risk_score", "status", "version", "actor"}

errors:   List[str] = []
warnings: List[str] = []


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load(path: str) -> Tuple[bool, Any]:
    """Load JSON file. Returns (success, data)."""
    if not os.path.exists(path):
        errors.append(f"MISSING FILE: {path}")
        return False, None
    try:
        with open(path, encoding="utf-8") as f:
            return True, json.load(f)
    except json.JSONDecodeError as e:
        errors.append(f"INVALID JSON [{path}]: {e}")
        return False, None


def _check_no_question_marks(obj: Any, path: str) -> None:
    """Recursively scan for '?' values in tracked fields."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in QUESTION_MARK_FIELDS and v == "?":
                errors.append(f"QUESTION-MARK REGRESSION [{path}]: field '{k}' = '?'")
            _check_no_question_marks(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _check_no_question_marks(item, f"{path}[{i}]")


def _require_field(obj: Dict, field: str, path: str, allow_zero: bool = True) -> Any:
    """Assert field exists and is not None."""
    if field not in obj:
        errors.append(f"MISSING FIELD [{path}]: '{field}' not found")
        return None
    val = obj[field]
    if val is None:
        errors.append(f"NULL FIELD [{path}]: '{field}' is null")
        return None
    if not allow_zero and val == 0:
        warnings.append(f"ZERO VALUE [{path}]: '{field}' = 0")
    return val


def _require_string(obj: Dict, field: str, path: str) -> str | None:
    val = _require_field(obj, field, path)
    if val is not None and not isinstance(val, str):
        errors.append(f"TYPE ERROR [{path}]: '{field}' must be string, got {type(val).__name__}")
        return None
    return val


def _require_int_or_float(obj: Dict, field: str, path: str) -> float | None:
    val = _require_field(obj, field, path)
    if val is not None and not isinstance(val, (int, float)):
        errors.append(f"TYPE ERROR [{path}]: '{field}' must be numeric, got {type(val).__name__}")
        return None
    return val


# ─── api/engines.json ─────────────────────────────────────────────────────────

def validate_engines(path: str = "api/engines.json") -> None:
    ok, data = _load(path)
    if not ok:
        return

    p = "engines.json"
    _require_string(data, "status", p)
    _require_string(data, "version", p)
    _require_string(data, "generated_at", p)

    engines = data.get("engines")
    if not isinstance(engines, dict):
        errors.append(f"[{p}] 'engines' must be a dict, got {type(engines).__name__}")
        return

    # Check all 12 required engines present
    present = set(engines.keys())
    missing = REQUIRED_ENGINES - present
    if missing:
        errors.append(f"[{p}] Missing engines: {sorted(missing)}")

    for eng_id, eng in engines.items():
        ep = f"engines.json.{eng_id}"

        if not isinstance(eng, dict):
            errors.append(f"[{ep}] Engine entry must be dict")
            continue

        status = _require_string(eng, "status", ep)
        if status and status not in VALID_STATUSES:
            warnings.append(f"[{ep}] Unexpected status '{status}'")

        summary = eng.get("summary")
        if summary is None:
            errors.append(f"[{ep}] Missing 'summary' wrapper (renderGenesisEngine() reads eng.summary.*)")
            continue

        if not isinstance(summary, dict):
            errors.append(f"[{ep}] 'summary' must be dict, got {type(summary).__name__}")
            continue

        # Ensure no '?' values in summary (Genesis regression guard)
        for k, v in summary.items():
            if str(v).strip() == "?":
                errors.append(f"[{ep}.summary] field '{k}' = '?' — Genesis regression detected!")

    _check_no_question_marks(data, p)
    print(f"  [engines.json] {len(present)} engines validated ✓")


# ─── api/ai/analyze.json ──────────────────────────────────────────────────────

def validate_analyze(path: str = "api/ai/analyze.json") -> None:
    ok, data = _load(path)
    if not ok:
        return

    p = "analyze.json"
    _require_string(data, "status", p)
    _require_string(data, "version", p)
    _require_string(data, "generated_at", p)
    _require_string(data, "model", p)

    summary = data.get("summary", {})
    _require_int_or_float(summary, "total_threats", p + ".summary", allow_zero=False)
    _require_int_or_float(summary, "critical_count", p + ".summary")
    _require_int_or_float(summary, "kev_count", p + ".summary")

    threats = data.get("top_threats", [])
    if not isinstance(threats, list):
        errors.append(f"[{p}] 'top_threats' must be a list")
        return
    if len(threats) == 0:
        errors.append(f"[{p}] 'top_threats' is EMPTY — AI analysis has no data")
        return

    priority_counts = {k: 0 for k in VALID_PRIORITIES}
    for i, t in enumerate(threats):
        tp = f"{p}.top_threats[{i}]"
        pri = t.get("priority")
        if pri not in VALID_PRIORITIES:
            errors.append(f"[{tp}] Invalid priority '{pri}' — must be P1/P2/P3/P4 (SSoT violation)")
        else:
            priority_counts[pri] += 1
        _require_string(t, "threat_id", tp)
        _require_string(t, "title", tp)
        rs = t.get("risk_score")
        if rs is not None and not isinstance(rs, (int, float)):
            errors.append(f"[{tp}] risk_score must be numeric")

    # KEV items must be P1
    for i, t in enumerate(threats):
        if t.get("kev") is True and t.get("priority") != "P1":
            errors.append(
                f"[{p}.top_threats[{i}]] KEV=true but priority='{t.get('priority')}' — "
                f"SSoT violation: KEV items MUST be P1"
            )

    _check_no_question_marks(data, p)
    print(f"  [analyze.json] {len(threats)} threats: P1={priority_counts['P1']} "
          f"P2={priority_counts['P2']} P3={priority_counts['P3']} P4={priority_counts['P4']} ✓")


# ─── api/ai/respond.json ──────────────────────────────────────────────────────

def validate_respond(path: str = "api/ai/respond.json") -> None:
    ok, data = _load(path)
    if not ok:
        return

    p = "respond.json"
    _require_string(data, "status", p)
    _require_string(data, "version", p)

    summary = data.get("summary", {})
    _require_int_or_float(summary, "total_response_actions", p + ".summary", allow_zero=False)
    _require_int_or_float(summary, "p1_critical", p + ".summary")

    queue = data.get("response_queue", [])
    if not isinstance(queue, list):
        errors.append(f"[{p}] 'response_queue' must be a list")
        return
    if len(queue) == 0:
        errors.append(f"[{p}] 'response_queue' is EMPTY")
        return

    priority_counts = {k: 0 for k in VALID_PRIORITIES}
    for i, a in enumerate(queue):
        ap = f"{p}.response_queue[{i}]"

        pri = a.get("priority")
        if pri not in VALID_PRIORITIES:
            errors.append(f"[{ap}] Invalid priority '{pri}' — must be P1/P2/P3/P4 (SSoT violation)")
        else:
            priority_counts[pri] += 1

        sla = a.get("sla_hours")
        if sla is not None:
            if sla not in VALID_SLA_HOURS:
                errors.append(f"[{ap}] Invalid sla_hours={sla} — must be 1, 4, or 24")
            # Cross-validate: P1 must have sla_hours=1
            if pri == "P1" and sla != 1:
                errors.append(f"[{ap}] P1 action must have sla_hours=1, got {sla}")
            if pri == "P2" and sla != 4:
                errors.append(f"[{ap}] P2 action must have sla_hours=4, got {sla}")

        _require_string(a, "action_id", ap)
        _require_string(a, "incident_title", ap)

    # Verify summary.p1_critical matches actual count
    declared_p1 = summary.get("p1_critical", -1)
    actual_p1 = priority_counts["P1"]
    if declared_p1 != actual_p1:
        warnings.append(
            f"[{p}] summary.p1_critical={declared_p1} but actual P1 count in "
            f"response_queue={actual_p1} — possible mismatch"
        )

    _check_no_question_marks(data, p)
    print(f"  [respond.json] {len(queue)} actions: P1={priority_counts['P1']} "
          f"P2={priority_counts['P2']} P3={priority_counts['P3']} P4={priority_counts['P4']} ✓")


# ─── api/ai/correlate.json ────────────────────────────────────────────────────

def validate_correlate(path: str = "api/ai/correlate.json") -> None:
    ok, data = _load(path)
    if not ok:
        return

    p = "correlate.json"
    _require_string(data, "status", p)
    _require_string(data, "version", p)

    clusters = data.get("threat_clusters", [])
    if not isinstance(clusters, list) or len(clusters) == 0:
        errors.append(f"[{p}] 'threat_clusters' is missing or empty")

    ttp_graph = data.get("ttp_graph", {})
    if not isinstance(ttp_graph, dict):
        errors.append(f"[{p}] 'ttp_graph' must be a dict")
    else:
        kc = ttp_graph.get("kill_chain_coverage", [])
        if not isinstance(kc, list) or len(kc) == 0:
            errors.append(f"[{p}] 'ttp_graph.kill_chain_coverage' is empty — TTP extraction failed")

        co_occ = ttp_graph.get("ttp_co_occurrence", [])
        if not isinstance(co_occ, list) or len(co_occ) == 0:
            warnings.append(f"[{p}] 'ttp_graph.ttp_co_occurrence' is empty")

    shared_cves = data.get("shared_cve_graph", {})
    if not isinstance(shared_cves, dict):
        errors.append(f"[{p}] 'shared_cve_graph' must be a dict")

    _check_no_question_marks(data, p)
    print(f"  [correlate.json] {len(clusters)} clusters, "
          f"{len(ttp_graph.get('kill_chain_coverage', []))} kill-chain phases ✓")


# ─── Priority Consistency Cross-check ─────────────────────────────────────────

def validate_priority_consistency() -> None:
    """
    Cross-validate that items appearing in both analyze.json and respond.json
    use the same priority (P1/P2/P3/P4). Checks KEV=true always maps to P1
    across all endpoints.
    """
    ok_a, analyze  = _load("api/ai/analyze.json")
    ok_r, respond  = _load("api/ai/respond.json")

    if not ok_a or not ok_r:
        warnings.append("[cross-check] Could not load both endpoints for priority consistency check")
        return

    # Build title→priority map from analyze
    analyze_map: Dict[str, str] = {}
    for t in analyze.get("top_threats", []):
        title = (t.get("title") or "")[:100]
        if title:
            analyze_map[title] = t.get("priority", "?")

    # Check respond queue items against analyze map
    mismatches = 0
    for a in respond.get("response_queue", []):
        title = (a.get("incident_title") or "")[:100]
        pri_r = a.get("priority")
        pri_a = analyze_map.get(title)
        if pri_a and pri_r and pri_a != pri_r:
            mismatches += 1
            if mismatches <= 5:  # Limit noise
                warnings.append(
                    f"[cross-check] Priority mismatch for '{title[:60]}': "
                    f"analyze={pri_a} vs respond={pri_r}"
                )

    if mismatches > 5:
        warnings.append(f"[cross-check] ... and {mismatches - 5} more priority mismatches")
    elif mismatches == 0:
        print(f"  [cross-check] Priority consistency PASSED — 0 mismatches across endpoints ✓")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Schema Validator v134")
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 on ANY warning (CI pre-deploy mode)")
    args = parser.parse_args()

    print("=" * 66)
    print("SENTINEL APEX v134 — Schema Validation + Regression Guard")
    print("=" * 66)

    validate_engines()
    validate_analyze()
    validate_respond()
    validate_correlate()
    validate_priority_consistency()

    print()
    if warnings:
        print(f"⚠️  {len(warnings)} WARNING(S):")
        for w in warnings:
            print(f"   WARN  {w}")

    if errors:
        print(f"❌  {len(errors)} ERROR(S) — DATA CONTRACT VIOLATED:")
        for e in errors:
            print(f"   ERROR {e}")
        print()
        print("VALIDATION FAILED — deploy blocked until errors are resolved.")
        return 1

    if args.strict and warnings:
        print()
        print("STRICT MODE: warnings treated as errors — deploy blocked.")
        return 1

    print()
    if not warnings and not errors:
        print("✅ ALL SCHEMA CONTRACTS VALID — deploy cleared.")
    elif warnings and not errors:
        print("✅ SCHEMA VALIDATION PASSED (with warnings — review above).")

    return 0


if __name__ == "__main__":
    sys.exit(main())
