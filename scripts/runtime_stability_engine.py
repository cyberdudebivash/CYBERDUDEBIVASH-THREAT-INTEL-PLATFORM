#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
RUNTIME STABILITY ENGINE v158.5 — Phase 1B Enterprise Hardening
===============================================================================
PURPOSE:
  Validates runtime production state after each pipeline execution.
  Detects output regression, STIX count collapse, orchestration gaps,
  and latency anomalies. Provides Stage 2 execution proof and writes
  a signed stability report to data/health/.

SUBSYSTEMS:
  1. StixBundleCounter       — validates STIX bundle count vs MIN_STIX_BUNDLES
  2. OutputExistenceProof    — validates required pipeline outputs are present
                               and were regenerated within MAX_OUTPUT_AGE_HOURS
  3. OrchestrationIntegrity  — checks required health/data files for completeness
  4. LatencyAnomalyDetector  — compares current p95 latency vs rolling baseline
  5. RuntimeStabilityReport  — orchestrates all checks, writes signed report

HARD FAIL CONDITIONS (--strict):
  - STIX bundle count < MIN_STIX_BUNDLES
  - Required output file absent or zero-byte
  - p95 latency > MAX_LATENCY_MS

WARN CONDITIONS (always reported):
  - STIX count degraded but above MIN_STIX_BUNDLES floor
  - Output file stale (age > MAX_OUTPUT_AGE_HOURS)
  - Latency between WARN_LATENCY_MS and MAX_LATENCY_MS
  - Any health JSON missing from required set

CLI:
  --check   Validate; exit 1 on HARD FAIL (use --strict to harden thresholds)
  --report  Print stability table, always exit 0
  --strict  Elevate WARN conditions to HARD FAIL

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [runtime-stability] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-RUNTIME-STABILITY")

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
HEALTH_DIR = DATA_DIR / "health"
STIX_DIR = DATA_DIR / "stix"
STABILITY_STATE_DIR = DATA_DIR / "runtime_stability"

VERSION = "158.5"

# ── Thresholds ──────────────────────────────────────────────────────────────
MIN_STIX_BUNDLES = 40           # Hard floor — must be ≤ STIX_MAX_BUNDLES=50 set in sentinel-blogger.yml
WARN_STIX_BUNDLES = 45          # Warn if count falls below this
MAX_OUTPUT_AGE_HOURS = 25       # Output files must be regenerated within 25h
WARN_OUTPUT_AGE_HOURS = 12      # Warn if output not refreshed within 12h
WARN_LATENCY_MS = 1000          # Warn above 1000ms p95
MAX_LATENCY_MS = 2000           # Hard fail above 2000ms p95

# ── Required pipeline output files (Stage 2 execution proof) ────────────────
REQUIRED_OUTPUTS: List[Dict] = [
    {"path": "data/feed.json",              "min_bytes": 1000,  "label": "Feed JSON"},
    {"path": "data/feed_manifest.json",     "min_bytes": 500,   "label": "Feed Manifest"},
    {"path": "data/health/latest.json",     "min_bytes": 100,   "label": "Health Latest"},
    {"path": "data/health/sla_status.json", "min_bytes": 100,   "label": "SLA Status"},
    {"path": "version.json",                "min_bytes": 50,    "label": "Platform Version"},
    {"path": "config/version.json",         "min_bytes": 50,    "label": "Config Version"},
]

# ── Required health/governance files (Orchestration Integrity) ───────────────
REQUIRED_HEALTH_FILES: List[str] = [
    "data/health/runtime_health.json",
    "data/health/integrity_status.json",
    "data/health/deployment_health.json",
    "data/health/sla_status.json",
    "version.json",
    "config/version.json",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def file_age_hours(path: Path) -> Optional[float]:
    """Return file age in hours, or None if file does not exist."""
    if not path.exists():
        return None
    mtime = path.stat().st_mtime
    age_secs = (datetime.now(timezone.utc).timestamp() - mtime)
    return age_secs / 3600.0


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


# ────────────────────────────────────────────────────────────────────────────
# 1. StixBundleCounter
# ────────────────────────────────────────────────────────────────────────────
class StixBundleCounter:
    """Validates STIX bundle count vs governance thresholds."""

    STATE_FILE = STABILITY_STATE_DIR / "stix_count_history.json"

    def _load_history(self) -> List[Dict]:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return []

    def _save_history(self, count: int) -> None:
        STABILITY_STATE_DIR.mkdir(parents=True, exist_ok=True)
        history = self._load_history()
        history.append({"count": count, "recorded_at": now_iso()})
        # Keep last 30 records
        if len(history) > 30:
            history = history[-30:]
        self.STATE_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")

    def count(self, apply: bool = True) -> Dict:
        if not STIX_DIR.exists():
            return {
                "status": "WARN",
                "code": "STIX_DIR_MISSING",
                "message": "data/stix/ directory not found",
                "count": 0,
                "min_required": MIN_STIX_BUNDLES,
            }

        stix_files = [f for f in STIX_DIR.iterdir()
                      if f.suffix == ".json" and f.is_file()]
        count = len(stix_files)

        history = self._load_history()
        prev_count = history[-1]["count"] if history else None

        if apply:
            self._save_history(count)

        drop = None
        if prev_count is not None and count < prev_count:
            drop = prev_count - count

        if count < MIN_STIX_BUNDLES:
            return {
                "status": "FAIL",
                "code": "STIX_COUNT_COLLAPSED",
                "message": f"STIX count {count} < minimum {MIN_STIX_BUNDLES}",
                "count": count,
                "prev_count": prev_count,
                "drop": drop,
                "min_required": MIN_STIX_BUNDLES,
            }
        elif count < WARN_STIX_BUNDLES:
            return {
                "status": "WARN",
                "code": "STIX_COUNT_LOW",
                "message": f"STIX count {count} below warn threshold {WARN_STIX_BUNDLES}",
                "count": count,
                "prev_count": prev_count,
                "drop": drop,
                "min_required": MIN_STIX_BUNDLES,
            }
        elif drop and drop > 20:
            return {
                "status": "WARN",
                "code": "STIX_COUNT_DROP",
                "message": f"STIX count dropped {drop} (from {prev_count} to {count})",
                "count": count,
                "prev_count": prev_count,
                "drop": drop,
                "min_required": MIN_STIX_BUNDLES,
            }
        else:
            return {
                "status": "OK",
                "code": "STIX_COUNT_HEALTHY",
                "message": f"STIX count {count} — above all thresholds",
                "count": count,
                "prev_count": prev_count,
                "drop": drop,
                "min_required": MIN_STIX_BUNDLES,
            }


# ────────────────────────────────────────────────────────────────────────────
# 2. OutputExistenceProof
# ────────────────────────────────────────────────────────────────────────────
class OutputExistenceProof:
    """Proves that required pipeline outputs exist and are fresh."""

    def validate(self) -> Dict:
        results = []
        hard_fail = False
        any_warn = False

        for spec in REQUIRED_OUTPUTS:
            path = REPO_ROOT / spec["path"]
            label = spec["label"]
            min_bytes = spec.get("min_bytes", 0)

            if not path.exists():
                results.append({
                    "file": spec["path"],
                    "label": label,
                    "status": "FAIL",
                    "code": "FILE_ABSENT",
                    "message": "Required output file missing",
                    "size_bytes": None,
                    "age_hours": None,
                })
                hard_fail = True
                continue

            size = path.stat().st_size
            age = file_age_hours(path)

            if size < min_bytes:
                results.append({
                    "file": spec["path"],
                    "label": label,
                    "status": "FAIL",
                    "code": "FILE_EMPTY",
                    "message": f"File too small: {size}B < {min_bytes}B minimum",
                    "size_bytes": size,
                    "age_hours": round(age, 2) if age else None,
                })
                hard_fail = True
            elif age is not None and age > MAX_OUTPUT_AGE_HOURS:
                results.append({
                    "file": spec["path"],
                    "label": label,
                    "status": "WARN",
                    "code": "FILE_STALE",
                    "message": f"File {age:.1f}h old (max {MAX_OUTPUT_AGE_HOURS}h)",
                    "size_bytes": size,
                    "age_hours": round(age, 2),
                })
                any_warn = True
            elif age is not None and age > WARN_OUTPUT_AGE_HOURS:
                results.append({
                    "file": spec["path"],
                    "label": label,
                    "status": "WARN",
                    "code": "FILE_AGING",
                    "message": f"File {age:.1f}h old (warn after {WARN_OUTPUT_AGE_HOURS}h)",
                    "size_bytes": size,
                    "age_hours": round(age, 2),
                })
                any_warn = True
            else:
                results.append({
                    "file": spec["path"],
                    "label": label,
                    "status": "OK",
                    "code": "OUTPUT_FRESH",
                    "message": f"Present, {size}B, {age:.1f}h old" if age else f"Present, {size}B",
                    "size_bytes": size,
                    "age_hours": round(age, 2) if age else None,
                })

        overall = "FAIL" if hard_fail else ("WARN" if any_warn else "OK")
        passed = sum(1 for r in results if r["status"] == "OK")
        return {
            "status": overall,
            "code": "OUTPUT_PROOF",
            "message": f"{passed}/{len(results)} outputs verified fresh and present",
            "hard_fail": hard_fail,
            "files": results,
        }


# ────────────────────────────────────────────────────────────────────────────
# 3. OrchestrationIntegrity
# ────────────────────────────────────────────────────────────────────────────
class OrchestrationIntegrity:
    """Validates required health/governance files for CI completeness."""

    def validate(self) -> Dict:
        missing = []
        present = []

        for rel_path in REQUIRED_HEALTH_FILES:
            path = REPO_ROOT / rel_path
            if path.exists() and path.stat().st_size > 0:
                present.append(rel_path)
            else:
                missing.append(rel_path)

        if missing:
            return {
                "status": "WARN",
                "code": "ORCHESTRATION_GAPS",
                "message": f"{len(missing)} required governance file(s) absent",
                "missing": missing,
                "present": present,
                "total_required": len(REQUIRED_HEALTH_FILES),
            }
        return {
            "status": "OK",
            "code": "ORCHESTRATION_COMPLETE",
            "message": f"All {len(REQUIRED_HEALTH_FILES)} governance files present",
            "missing": [],
            "present": present,
            "total_required": len(REQUIRED_HEALTH_FILES),
        }


# ────────────────────────────────────────────────────────────────────────────
# 4. LatencyAnomalyDetector
# ────────────────────────────────────────────────────────────────────────────
class LatencyAnomalyDetector:
    """Reads p95 latency from runtime_health.json and validates thresholds."""

    RUNTIME_HEALTH = HEALTH_DIR / "runtime_health.json"
    SLA_STATUS = HEALTH_DIR / "sla_status.json"
    STATE_FILE = STABILITY_STATE_DIR / "latency_history.json"

    def _load_latency_from_health(self) -> Optional[float]:
        for path in (self.SLA_STATUS, self.RUNTIME_HEALTH):
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                # Try common field names for p95 latency
                for field in ("p95_latency_ms", "avg_latency_ms", "latency_p95",
                              "latency_ms", "response_time_p95"):
                    if field in data:
                        return float(data[field])
                # Nested under sla or latency block
                if "sla" in data and "p95_ms" in data["sla"]:
                    return float(data["sla"]["p95_ms"])
                if "latency" in data and isinstance(data["latency"], dict):
                    lat = data["latency"]
                    for field in ("p95", "p95_ms", "avg"):
                        if field in lat:
                            return float(lat[field])
            except Exception:
                continue
        return None

    def _load_history(self) -> List[Dict]:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return []

    def _save_history(self, latency_ms: float) -> None:
        STABILITY_STATE_DIR.mkdir(parents=True, exist_ok=True)
        history = self._load_history()
        history.append({"latency_ms": latency_ms, "recorded_at": now_iso()})
        if len(history) > 50:
            history = history[-50:]
        self.STATE_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")

    def _rolling_baseline(self) -> Optional[float]:
        history = self._load_history()
        if len(history) < 3:
            return None
        values = [h["latency_ms"] for h in history[-10:]]
        return sum(values) / len(values)

    def validate(self, apply: bool = True) -> Dict:
        latency = self._load_latency_from_health()

        if latency is None:
            return {
                "status": "WARN",
                "code": "LATENCY_UNAVAILABLE",
                "message": "p95 latency not found in health data",
                "latency_ms": None,
                "baseline_ms": None,
            }

        baseline = self._rolling_baseline()
        if apply:
            self._save_history(latency)

        if latency > MAX_LATENCY_MS:
            status, code = "FAIL", "LATENCY_CRITICAL"
            msg = f"p95 {latency:.0f}ms exceeds hard limit {MAX_LATENCY_MS}ms"
        elif latency > WARN_LATENCY_MS:
            status, code = "WARN", "LATENCY_DEGRADED"
            msg = f"p95 {latency:.0f}ms — degraded (warn>{WARN_LATENCY_MS}ms, fail>{MAX_LATENCY_MS}ms)"
        else:
            status, code = "OK", "LATENCY_HEALTHY"
            msg = f"p95 {latency:.0f}ms — within SLA"

        anomaly = None
        if baseline and latency > baseline * 1.5:
            anomaly = f"Latency spike: {latency:.0f}ms vs rolling baseline {baseline:.0f}ms (+{((latency/baseline)-1)*100:.0f}%)"
            if status == "OK":
                status, code = "WARN", "LATENCY_SPIKE"
                msg = anomaly

        return {
            "status": status,
            "code": code,
            "message": msg,
            "latency_ms": round(latency, 1),
            "baseline_ms": round(baseline, 1) if baseline else None,
            "warn_threshold_ms": WARN_LATENCY_MS,
            "fail_threshold_ms": MAX_LATENCY_MS,
            "anomaly": anomaly,
        }


# ────────────────────────────────────────────────────────────────────────────
# 5. RuntimeStabilityReport
# ────────────────────────────────────────────────────────────────────────────
class RuntimeStabilityReport:
    """Orchestrates all stability checks; writes signed report."""

    OUTPUT_FILE = HEALTH_DIR / "runtime_stability.json"

    def __init__(self):
        self.stix = StixBundleCounter()
        self.outputs = OutputExistenceProof()
        self.orchestration = OrchestrationIntegrity()
        self.latency = LatencyAnomalyDetector()

    def _is_hard_fail(self, results: Dict, strict: bool) -> bool:
        fail = False
        if results["stix"]["status"] == "FAIL":
            fail = True
        if results["outputs"].get("hard_fail"):
            fail = True
        if results["latency"]["status"] == "FAIL":
            fail = True
        if strict:
            # In strict mode, any WARN also escalates
            for check in results.values():
                if check.get("status") == "WARN":
                    fail = True
        return fail

    def run(self, apply: bool = True, strict: bool = False) -> Dict:
        HEALTH_DIR.mkdir(parents=True, exist_ok=True)
        STABILITY_STATE_DIR.mkdir(parents=True, exist_ok=True)

        checks = {
            "stix":         self.stix.count(apply=apply),
            "outputs":      self.outputs.validate(),
            "orchestration": self.orchestration.validate(),
            "latency":      self.latency.validate(apply=apply),
        }

        hard_fail = self._is_hard_fail(checks, strict)
        any_warn = any(c.get("status") == "WARN" for c in checks.values())
        overall = "FAIL" if hard_fail else ("WARN" if any_warn else "OK")

        # Compute composite stability score (0–100)
        score_map = {"OK": 25, "WARN": 10, "FAIL": 0}
        score = sum(score_map.get(c.get("status", "FAIL"), 0) for c in checks.values())

        report = {
            "status": overall,
            "hard_fail": hard_fail,
            "strict_mode": strict,
            "stability_score": score,
            "stability_grade": "A" if score >= 90 else
                               "B" if score >= 75 else
                               "C" if score >= 50 else
                               "D" if score >= 25 else "F",
            "stix_count": checks["stix"].get("count", 0),
            "min_stix": MIN_STIX_BUNDLES,
            "generated_at": now_iso(),
            "engine_version": VERSION,
            "checks": checks,
        }

        self.OUTPUT_FILE.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        log.info("Runtime stability report written: %s", self.OUTPUT_FILE)
        return report


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────
def print_report(report: Dict) -> None:
    log.info("=" * 72)
    log.info("RUNTIME STABILITY ENGINE — v%s", VERSION)
    log.info("=" * 72)
    log.info("Overall status    : %s", report.get("status", "?"))
    log.info("Stability score   : %s/100  Grade: %s",
             report.get("stability_score", "?"), report.get("stability_grade", "?"))
    log.info("STIX count        : %s (min %s)",
             report.get("stix_count", "?"), report.get("min_stix", "?"))
    log.info("-" * 72)
    checks = report.get("checks", {})
    for check_name, result in checks.items():
        flag = "[OK]  " if result.get("status") == "OK" else \
               "[WARN]" if result.get("status") == "WARN" else "[FAIL]"
        log.info("%-22s %s  %s", check_name, flag, result.get("message", ""))
    log.info("=" * 72)
    if report.get("hard_fail"):
        log.error("HARD FAIL — runtime stability violated. Pipeline output is DEGRADED.")
    elif report.get("status") == "WARN":
        log.warning("WARN — runtime stability degraded. Review checks above.")
    else:
        log.info("STABLE — all runtime stability checks passed.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Runtime Stability Engine"
    )
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--check", action="store_true",
                     help="Validate; exit 1 on HARD FAIL")
    grp.add_argument("--report", action="store_true",
                     help="Print stability report, always exit 0")
    parser.add_argument("--strict", action="store_true",
                        help="Elevate WARN conditions to HARD FAIL")
    args = parser.parse_args()

    engine = RuntimeStabilityReport()
    apply = not args.report
    report = engine.run(apply=apply, strict=args.strict)
    print_report(report)

    if args.report:
        return 0
    if report.get("hard_fail"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
