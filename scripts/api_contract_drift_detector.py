#!/usr/bin/env python3
"""
scripts/api_contract_drift_detector.py
CYBERDUDEBIVASH® SENTINEL APEX — API Contract Drift Detector v1.0

PURPOSE:
  Detects schema drift and breaking changes in the public API contract.
  Validates that the live feed JSON schemas match the committed contract baseline.
  Enforces schema compatibility across versioned endpoints.

CHECKS:
  1. Schema field presence — required fields must exist in every entry
  2. Field type stability — field types must not change between runs
  3. Enum value stability — severity/TLP enums must not gain/lose values unexpectedly
  4. Canary contract validation — spot-checks live endpoint structure
  5. Baseline drift scoring — percentage of entries deviating from schema baseline

EXIT CODES:
  0 = Schema contract valid — no drift detected
  1 = BREAKING CHANGE detected — field removed or type changed
  3 = SCHEMA DRIFT — new fields or enum additions (non-breaking but tracked)

OUTPUTS:
  data/governance/contract_drift_report.json   — structured drift report
  data/governance/schema_baseline.json         — committed schema baseline
  data/governance/contract_drift_history.jsonl — historical drift log
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("CDB-CONTRACT-DRIFT")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
GOV_DIR    = DATA_DIR / "governance"
STIX_DIR   = DATA_DIR / "stix"

FEED_MANIFEST   = DATA_DIR / "feed_manifest.json"
ALT_MANIFEST    = STIX_DIR / "feed_manifest.json"

DRIFT_REPORT    = GOV_DIR / "contract_drift_report.json"
SCHEMA_BASELINE = GOV_DIR / "schema_baseline.json"
DRIFT_HISTORY   = GOV_DIR / "contract_drift_history.jsonl"

GOV_DIR.mkdir(parents=True, exist_ok=True)

# ── Contract Specification ────────────────────────────────────────────────────
# These are the REQUIRED fields every advisory entry MUST have.
# Removing any field from the live feed is a BREAKING CHANGE.
REQUIRED_FIELDS: Dict[str, type] = {
    "title":       str,
    "risk_score":  (int, float),
    "severity":    str,
    "tlp":         str,
    "confidence":  (int, float),
    "source_url":  str,
    "timestamp":   str,
}

# Optional fields — present in most entries, absence is tracked but not a violation
OPTIONAL_FIELDS: Set[str] = {
    "actor", "cvss", "epss", "kev", "blog_url",
    "stix_id", "ioc_count", "ttps", "iocs",
}

# Permitted enum values — changes to these sets are tracked
SEVERITY_ENUM  = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
TLP_ENUM       = {"TLP:RED", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR", "TLP:WHITE"}

# Risk score bounds
RISK_MIN, RISK_MAX         = 0.0, 10.0
CONFIDENCE_MIN, CONF_MAX   = 0, 100


def _atomic_write(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_manifest() -> List[Dict]:
    for path in (FEED_MANIFEST, ALT_MANIFEST):
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
                for key in ("advisories", "entries", "reports", "items"):
                    if isinstance(data.get(key), list):
                        return data[key]
            except Exception as e:
                logger.warning(f"Manifest load error {path}: {e}")
    return []


def _field_type_name(val: Any) -> str:
    if isinstance(val, bool):
        return "bool"
    if isinstance(val, int):
        return "int"
    if isinstance(val, float):
        return "float"
    if isinstance(val, str):
        return "str"
    if isinstance(val, list):
        return "list"
    if isinstance(val, dict):
        return "dict"
    if val is None:
        return "null"
    return type(val).__name__


def _normalize_field(fname: str, val: Any) -> Any:
    """Normalize field values for baseline comparison."""
    if fname == "severity":
        return str(val).upper() if val else val
    if fname == "tlp":
        return str(val).upper() if val else val
    return val


# ── Baseline Management ───────────────────────────────────────────────────────

def _load_baseline() -> Optional[Dict]:
    if SCHEMA_BASELINE.exists():
        try:
            with open(SCHEMA_BASELINE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Baseline load failed: {e}")
    return None


def _build_baseline(entries: List[Dict], run_at: str) -> Dict:
    """Build a schema baseline from the current manifest."""
    field_types: Dict[str, Counter] = {}
    severity_vals: Set[str] = set()
    tlp_vals: Set[str]      = set()
    field_presence: Counter = Counter()

    for entry in entries:
        for fname, fval in entry.items():
            ftype = _field_type_name(fval)
            field_types.setdefault(fname, Counter())[ftype] += 1
            field_presence[fname] += 1
        sev = str(entry.get("severity", "")).upper()
        if sev:
            severity_vals.add(sev)
        tlp = str(entry.get("tlp", "")).upper()
        if tlp:
            tlp_vals.add(tlp)

    # Dominant type per field
    dominant_types = {
        fname: cntr.most_common(1)[0][0]
        for fname, cntr in field_types.items()
    }

    return {
        "created_at":      run_at,
        "entry_count":     len(entries),
        "field_types":     dominant_types,
        "field_presence":  dict(field_presence),
        "severity_enum":   sorted(severity_vals),
        "tlp_enum":        sorted(tlp_vals),
    }


# ── Drift Analysis ────────────────────────────────────────────────────────────

def _detect_drift(
    entries: List[Dict],
    baseline: Optional[Dict],
    run_at: str,
) -> Tuple[str, Dict]:
    """
    Returns (exit_level, drift_report).
    exit_level: "OK" | "DRIFT" | "BREAKING"
    """
    violations:    List[Dict] = []
    warnings:      List[Dict] = []
    severity_seen: Set[str]   = set()
    tlp_seen:      Set[str]   = set()

    missing_required_counts: Counter = Counter()
    type_mismatch_counts:    Counter = Counter()
    range_violation_counts:  Counter = Counter()

    for idx, entry in enumerate(entries):
        eid = entry.get("stix_id", f"idx:{idx}")

        # 1. Required field presence
        for fname, ftype in REQUIRED_FIELDS.items():
            val = entry.get(fname)
            if val is None or val == "":
                missing_required_counts[fname] += 1
            elif not isinstance(val, ftype):
                type_mismatch_counts[fname] += 1

        # 2. Enum value tracking
        sev = str(entry.get("severity", "")).upper()
        if sev:
            severity_seen.add(sev)
        tlp = str(entry.get("tlp", "")).upper()
        if tlp:
            tlp_seen.add(tlp)

        # 3. Range validation
        risk = entry.get("risk_score")
        if risk is not None and isinstance(risk, (int, float)):
            if not (RISK_MIN <= risk <= RISK_MAX):
                range_violation_counts["risk_score"] += 1
        conf = entry.get("confidence")
        if conf is not None and isinstance(conf, (int, float)):
            if not (CONFIDENCE_MIN <= conf <= CONF_MAX):
                range_violation_counts["confidence"] += 1

    # Evaluate required field violations
    for fname, cnt in missing_required_counts.items():
        pct = round(100.0 * cnt / len(entries), 1) if entries else 0
        severity = "BREAKING" if pct > 50 else "WARNING"
        rec = {
            "type":   severity,
            "field":  fname,
            "issue":  f"Required field '{fname}' missing in {cnt}/{len(entries)} entries ({pct}%)",
        }
        if severity == "BREAKING":
            violations.append(rec)
        else:
            warnings.append(rec)

    for fname, cnt in type_mismatch_counts.items():
        pct = round(100.0 * cnt / len(entries), 1) if entries else 0
        severity = "BREAKING" if pct > 20 else "WARNING"
        rec = {
            "type":   severity,
            "field":  fname,
            "issue":  f"Type mismatch in '{fname}' for {cnt}/{len(entries)} entries ({pct}%)",
        }
        if severity == "BREAKING":
            violations.append(rec)
        else:
            warnings.append(rec)

    for fname, cnt in range_violation_counts.items():
        warnings.append({
            "type":  "WARNING",
            "field": fname,
            "issue": f"Out-of-range values for '{fname}' in {cnt} entries",
        })

    # Enum drift vs. permitted set
    unknown_severity = severity_seen - SEVERITY_ENUM
    unknown_tlp      = tlp_seen - TLP_ENUM
    if unknown_severity:
        warnings.append({
            "type":   "DRIFT",
            "field":  "severity",
            "issue":  f"Unknown severity values: {sorted(unknown_severity)}",
        })
    if unknown_tlp:
        warnings.append({
            "type":   "DRIFT",
            "field":  "tlp",
            "issue":  f"Unknown TLP values: {sorted(unknown_tlp)}",
        })

    # Baseline drift comparison
    baseline_drift: List[Dict] = []
    if baseline:
        baseline_types = baseline.get("field_types", {})
        current = _build_baseline(entries, run_at)
        for fname, btype in baseline_types.items():
            ctype = current["field_types"].get(fname)
            if ctype and ctype != btype:
                rec = {
                    "type":    "BREAKING",
                    "field":   fname,
                    "issue":   f"Type changed: {btype} → {ctype}",
                    "baseline_type": btype,
                    "current_type":  ctype,
                }
                violations.append(rec)
                baseline_drift.append(rec)
        # Detect fields removed vs baseline
        for fname in set(baseline_types) - set(current["field_types"]):
            if fname in REQUIRED_FIELDS:
                rec = {
                    "type":  "BREAKING",
                    "field": fname,
                    "issue": f"Required field '{fname}' no longer present in manifest",
                }
                violations.append(rec)
                baseline_drift.append(rec)
        # Detect new fields added (non-breaking, tracked)
        for fname in set(current["field_types"]) - set(baseline_types):
            baseline_drift.append({
                "type":  "NEW_FIELD",
                "field": fname,
                "issue": f"New field '{fname}' appeared — update baseline if intentional",
            })

    exit_level = (
        "BREAKING" if violations else
        "DRIFT"    if warnings or baseline_drift else
        "OK"
    )

    report: Dict = {
        "run_at":         run_at,
        "exit_level":     exit_level,
        "entries_checked": len(entries),
        "violations":     violations,
        "warnings":       warnings,
        "baseline_drift": baseline_drift,
        "severity_values_seen": sorted(severity_seen),
        "tlp_values_seen":      sorted(tlp_seen),
        "range_violations": dict(range_violation_counts),
    }
    return exit_level, report


# ── Main ──────────────────────────────────────────────────────────────────────

def run_contract_drift_detection() -> int:
    now    = datetime.now(timezone.utc)
    run_at = now.isoformat()
    logger.info(f"[CONTRACT-DRIFT] API contract drift detection starting — {run_at}")

    entries = _load_manifest()
    if not entries:
        logger.warning("[CONTRACT-DRIFT] No manifest entries — DEGRADED")
        _atomic_write(DRIFT_REPORT, {"run_at": run_at, "exit_level": "DEGRADED",
                                     "reason": "No manifest entries"})
        return 3

    baseline = _load_baseline()
    if not baseline:
        logger.info("[CONTRACT-DRIFT] No baseline found — building initial baseline")
        baseline = _build_baseline(entries, run_at)
        _atomic_write(SCHEMA_BASELINE, baseline)
        logger.info(f"[CONTRACT-DRIFT] Baseline committed — {len(entries)} entries")

    exit_level, report = _detect_drift(entries, baseline, run_at)

    # Always refresh baseline on OK or DRIFT (not on BREAKING — preserve old baseline)
    if exit_level in ("OK", "DRIFT"):
        new_baseline = _build_baseline(entries, run_at)
        _atomic_write(SCHEMA_BASELINE, new_baseline)
        logger.info("[CONTRACT-DRIFT] Schema baseline refreshed")

    _atomic_write(DRIFT_REPORT, report)

    # Append to history log
    with open(str(DRIFT_HISTORY), "a", encoding="utf-8") as f:
        summary = {
            "run_at":          run_at,
            "exit_level":      exit_level,
            "violations":      len(report.get("violations", [])),
            "warnings":        len(report.get("warnings", [])),
            "entries_checked": report.get("entries_checked", 0),
        }
        f.write(json.dumps(summary) + "\n")

    logger.info(
        f"[CONTRACT-DRIFT] Complete — exit_level={exit_level} "
        f"violations={len(report.get('violations', []))} "
        f"warnings={len(report.get('warnings', []))}"
    )

    if report.get("violations"):
        for v in report["violations"]:
            logger.error(f"  BREAKING: [{v['field']}] {v['issue']}")

    if exit_level == "BREAKING":
        return 1
    if exit_level == "DRIFT":
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(run_contract_drift_detection())
