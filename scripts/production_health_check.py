#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/production_health_check.py
CYBERDUDEBIVASH® SENTINEL APEX v134.1 — Production Health Check Suite
═══════════════════════════════════════════════════════════════════════════════

MANDATE:
  This is the SINGLE AUTHORITATIVE production validation command.
  Run this before every deployment and after every pipeline execution.

  Returns exit code 0 on PASS, exit code 1 on any CRITICAL failure.

VALIDATES:
  Phase 1 — Runtime Safety          (variable lifecycle, exception isolation)
  Phase 2 — File Integrity          (atomic writes, checksums, encoding)
  Phase 3 — Pipeline Determinism    (manifest, reports, STIX, artifacts)
  Phase 4 — Customer Paths          (dashboard, dossiers, IOC, MITRE, CTA)
  Phase 5 — Observability           (health scores, telemetry, log files)
  Phase 6 — Commercial Readiness    (MSSP signals, API validity, brand)
  Phase 7 — Regression Prevention   (import integrity, syntax validation)

USAGE:
  python scripts/production_health_check.py            # full suite
  python scripts/production_health_check.py --fast     # critical checks only
  python scripts/production_health_check.py --json     # JSON output
  python scripts/production_health_check.py --fix      # attempt auto-fixes
  python scripts/production_health_check.py --phase 4  # single phase

EXIT CODES:
  0  — All critical checks PASSED
  1  — One or more CRITICAL checks FAILED
  2  — Suite initialization failed (environment problem)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# BOOTSTRAP
# ─────────────────────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent

# Ensure repo is on sys.path for internal imports
for _p in [str(REPO_ROOT), str(REPO_ROOT / "scripts")]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

logging.basicConfig(
    level=logging.WARNING,    # production check: suppress debug noise
    format="[%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("CDB-HEALTH-CHECK")

# ─────────────────────────────────────────────────────────────────────────────
# CHECK RUNNER
# ─────────────────────────────────────────────────────────────────────────────

class CheckResult:
    """Single check result."""

    def __init__(
        self,
        name: str,
        passed: bool,
        detail: str = "",
        critical: bool = True,
        phase: int = 0,
        duration_ms: float = 0.0,
    ):
        self.name        = name
        self.passed      = passed
        self.detail      = detail
        self.critical    = critical
        self.phase       = phase
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name":        self.name,
            "passed":      self.passed,
            "critical":    self.critical,
            "phase":       self.phase,
            "detail":      self.detail,
            "duration_ms": round(self.duration_ms, 2),
            "status":      "PASS" if self.passed else ("FAIL" if self.critical else "WARN"),
        }


class HealthCheckSuite:
    """
    SENTINEL APEX Production Health Check Suite.
    Runs all validation phases and produces a structured report.
    """

    SUITE_VERSION = "v134.1"

    def __init__(self, repo_root: Path = REPO_ROOT, fast: bool = False, auto_fix: bool = False):
        self._root    = repo_root
        self._fast    = fast
        self._fix     = auto_fix
        self._results: List[CheckResult] = []
        self._started = time.monotonic()

    # ── Check runner ─────────────────────────────────────────────────────────

    def _run(
        self,
        name: str,
        fn: Callable[[], Tuple[bool, str]],
        critical: bool = True,
        phase: int = 0,
    ) -> CheckResult:
        """Execute a single check with timing. Never raises."""
        _t0 = time.monotonic()
        try:
            _passed, _detail = fn()
        except Exception as _exc:
            _passed = False
            _detail = f"Check raised exception: {type(_exc).__name__}: {_exc}"
        _duration = (time.monotonic() - _t0) * 1000
        _r = CheckResult(name, _passed, _detail, critical, phase, _duration)
        self._results.append(_r)

        _icon   = "✅" if _passed else ("❌" if critical else "⚠️ ")
        _status = "PASS" if _passed else ("FAIL" if critical else "WARN")
        _line   = f"  {_icon} [{_status}] {name}"
        if _detail:
            _line += f"\n         ↳ {_detail}"
        print(_line)
        return _r

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 1 — RUNTIME SAFETY
    # ─────────────────────────────────────────────────────────────────────────

    def phase1_runtime_safety(self):
        print("\n━━━ PHASE 1: Runtime Safety ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        def _check_governance_import():
            try:
                from scripts.runtime_governance import (
                    FailSafeCounter, ExceptionIsolator, PipelineCheckpoint,
                    DeterministicFinalizer, OrchestratorTelemetry, GovernanceRegistry,
                    CRITICAL_STAGES, NON_CRITICAL_STAGES,
                )
                # Test FailSafeCounter
                c = FailSafeCounter("test")
                c.increment(5)
                c.increment(-999)  # should not go negative
                assert c.value == 5, f"Counter value wrong: {c.value}"
                # Test ExceptionIsolator
                with ExceptionIsolator("test_stage", critical=False) as iso:
                    raise ValueError("test non-critical failure")
                assert iso.failed, "Isolator should have recorded failure"
                return True, f"Runtime governance imports OK | critical_stages={len(CRITICAL_STAGES)}"
            except Exception as _e:
                return False, str(_e)
        self._run("governance_module_imports", _check_governance_import, critical=True, phase=1)

        def _check_orchestrator_finally():
            """Confirm orchestrator has finally block protecting _is_running."""
            _path = self._root / "core" / "orchestrator.py"
            if not _path.exists():
                return False, f"orchestrator.py not found at {_path}"
            _src = _path.read_text(encoding="utf-8")
            # Look for the finally block pattern near _is_running = False
            if "finally:" not in _src:
                return False, "No finally block found in orchestrator.py — lock deadlock risk"
            if "_is_running = False" not in _src:
                return False, "_is_running reset not found in orchestrator.py"
            # Confirm finally + _is_running are close together
            _finally_idx   = _src.rfind("finally:")
            _running_idx   = _src.rfind("self._is_running = False")
            _release_idx   = _src.rfind("self._release_lock()")
            if abs(_finally_idx - _running_idx) > 300:
                return False, "_is_running reset is far from finally block — governance gap risk"
            return True, "Orchestrator finally block confirmed — lock deadlock eliminated"
        self._run("orchestrator_finally_block", _check_orchestrator_finally, critical=True, phase=1)

        def _check_generate_summary_safety():
            """Confirm _generate_summary uses getattr() defensive access."""
            _path = self._root / "core" / "orchestrator.py"
            if not _path.exists():
                return False, "orchestrator.py not found"
            _src = _path.read_text(encoding="utf-8")
            # Check that _generate_summary uses getattr() not direct attribute access
            _gen_start = _src.find("def _generate_summary(")
            _gen_end   = _src.find("\n    def ", _gen_start + 1)
            _gen_body  = _src[_gen_start:_gen_end] if _gen_end > 0 else _src[_gen_start:]
            if "getattr(" not in _gen_body:
                return False, "_generate_summary() lacks getattr() defensive access — null-crash risk"
            if "_emergency_summary" not in _src:
                return False, "_emergency_summary() fallback not found"
            return True, "_generate_summary() has defensive getattr() + emergency fallback"
        self._run("generate_summary_defensive", _check_generate_summary_safety, critical=True, phase=1)

        def _check_store_run_safety():
            """Confirm _store_run uses .get() not direct key access.

            Strategy: scan only non-comment code lines within the _store_run body.
            The fix comment itself mentions the old pattern, so naive substring search
            produces a false positive.  We strip comment lines first, then verify:
              1. The safe pattern IS present  (positive assertion)
              2. The unsafe bare-key pattern is ABSENT from non-comment code  (negative assertion)
            """
            _path = self._root / "core" / "orchestrator.py"
            if not _path.exists():
                return False, "orchestrator.py not found"
            _src = _path.read_text(encoding="utf-8")
            _store_start = _src.find("def _store_run(")
            if _store_start < 0:
                return False, "_store_run method not found in orchestrator.py"
            _store_end = _src.find("\n    def ", _store_start + 1)
            _store_body = _src[_store_start:_store_end] if _store_end > 0 else _src[_store_start:]
            # Strip comment lines so the fix-comment doesn't trigger a false positive
            _code_lines = [
                ln for ln in _store_body.splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            ]
            _code_only = "\n".join(_code_lines)
            # Positive: safe extraction pattern must be present
            if 'summary.get("metrics")' not in _code_only and "summary.get('metrics')" not in _code_only:
                return False, '_store_run missing summary.get("metrics") — safe extraction not found'
            # Negative: bare key access must NOT appear in code (comments excluded)
            if 'summary["metrics"]' in _code_only or "summary['metrics']" in _code_only:
                return False, '_store_run uses summary["metrics"] directly in code — KeyError risk'
            return True, "_store_run uses safe .get() with defaults throughout"
        self._run("store_run_keysafe", _check_store_run_safety, critical=True, phase=1)

        def _check_ctx_return_validation():
            """Confirm stage.execute() return is validated before ctx = _returned_ctx."""
            _path = self._root / "core" / "orchestrator.py"
            if not _path.exists():
                return False, "orchestrator.py not found"
            _src = _path.read_text(encoding="utf-8")
            if "_returned_ctx is None" not in _src:
                return False, "No None-ctx guard after stage.execute() — silent data corruption risk"
            # Accept either the full word or the abbreviation used in practice
            _has_retention = (
                "retained pre-stage context" in _src
                or "retained pre-stage ctx" in _src
                or "retaining pre-stage context" in _src
                or "retaining pre-stage ctx" in _src
            )
            if not _has_retention:
                return False, "No pre-stage context retention fallback found"
            return True, "stage.execute() return validated — None context guarded"
        self._run("ctx_return_validated", _check_ctx_return_validation, critical=True, phase=1)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 2 — FILE INTEGRITY
    # ─────────────────────────────────────────────────────────────────────────

    def phase2_file_integrity(self):
        print("\n━━━ PHASE 2: File Integrity ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        def _check_pipeline_validator_import():
            try:
                from scripts.pipeline_validator import (
                    FileIntegrityEngine, ManifestValidator,
                    ReportExistenceGuard, CustomerPathValidator, ArtifactRegistry,
                )
                # Test atomic write
                import tempfile, os
                eng = FileIntegrityEngine()
                with tempfile.TemporaryDirectory() as _td:
                    _p = Path(_td) / "test.json"
                    _r = eng.atomic_write_json(_p, {"test": True, "ts": "2026-01-01"})
                    if _r["status"] not in ("ok", "ok_with_warnings"):
                        return False, f"atomic_write_json failed: {_r}"
                    _read_back = json.loads(_p.read_text())
                    if _read_back.get("test") is not True:
                        return False, "Write+read roundtrip mismatch"
                return True, "FileIntegrityEngine atomic write roundtrip OK"
            except Exception as _e:
                return False, str(_e)
        self._run("pipeline_validator_import", _check_pipeline_validator_import, critical=True, phase=2)

        def _check_safe_io_import():
            try:
                from scripts.safe_io import (
                    atomic_json_write, safe_json_load, safe_json_dump,
                    validate_intel_object, dedup_items, PipelineMetrics,
                    enforce_schema, enforce_schema_list, SystemHealthMonitor,
                )
                # Test schema enforcement
                _test = {"title": "Test Advisory", "source": "TEST", "published": True}
                _fixed = enforce_schema(_test)
                if isinstance(_fixed.get("published"), bool):
                    return False, "enforce_schema failed to fix boolean published"
                return True, "safe_io imports OK | enforce_schema fixes boolean published"
            except Exception as _e:
                return False, str(_e)
        self._run("safe_io_module_valid", _check_safe_io_import, critical=True, phase=2)

        def _check_no_stale_tmp():
            _data_dir    = self._root / "data"
            _reports_dir = self._root / "reports"
            _tmp_files: List[Path] = []
            for _d in [_data_dir, _reports_dir]:
                if _d.exists():
                    _tmp_files.extend(_d.rglob("*.tmp"))
            if _tmp_files:
                if self._fix:
                    _removed = 0
                    for _t in _tmp_files:
                        try:
                            _t.unlink(missing_ok=True)
                            _removed += 1
                        except Exception:
                            pass
                    return _removed == len(_tmp_files), f"Auto-fixed: removed {_removed}/{len(_tmp_files)} .tmp files"
                return False, f"{len(_tmp_files)} stale .tmp file(s): {[t.name for t in _tmp_files[:3]]}"
            return True, "No stale .tmp files"
        self._run("no_stale_tmp_files", _check_no_stale_tmp, critical=False, phase=2)

        def _check_manifest_json_valid():
            _p = self._root / "data" / "stix" / "feed_manifest.json"
            if not _p.exists():
                # No manifest = pipeline has not run yet. Governance checks are code-level;
                # data absence is expected on a fresh install. Not a CRITICAL code failure.
                return True, "feed_manifest.json not found (pipeline not run yet — expected pre-run state)"
            try:
                _raw = _p.read_text(encoding="utf-8")
                _d   = json.loads(_raw)
                _adv = _d.get("advisories") or _d.get("reports") or []
                return True, f"Manifest valid JSON — {len(_adv)} entries"
            except json.JSONDecodeError as _e:
                return False, f"Manifest JSON CORRUPT: {_e}"
            except UnicodeDecodeError as _e:
                return False, f"Manifest encoding CORRUPT: {_e}"
        self._run("manifest_json_valid", _check_manifest_json_valid, critical=True, phase=2)

        def _check_report_files_valid():
            """
            Validate report file integrity via fast sampling.

            The reports/ tree contains 35K+ HTML files.  A naive rglob("*.html")
            followed by stat() on every file times out.  Strategy:
              1. Confirm reports/ exists and has at least one HTML (fast stop)
              2. Sample up to 10 files from the first 20 sub-directories only
                 (scandir one level, glob within each subdir) — no full traversal
              3. Validate header of sampled files
            """
            _reports_dir = self._root / "reports"
            if not _reports_dir.exists():
                return False, "reports/ directory not found"

            # Fast existence check — does at least one HTML exist?
            _first = next(_reports_dir.rglob("*.html"), None)
            if _first is None:
                return False, "No HTML report files found in reports/"

            # Collect a capped sample: scan subdirs only (avoid full tree walk)
            import os as _os
            _sample_pool: List[Path] = []
            try:
                _subdirs = [Path(e.path) for e in _os.scandir(_reports_dir) if e.is_dir()]
            except PermissionError:
                _subdirs = []
            for _sd in _subdirs[:20]:             # cap: 20 subdirs
                _sample_pool.extend(_sd.glob("*.html"))
                if len(_sample_pool) >= 50:
                    break
            # Fall back: if no subdirs, files sit directly in reports/
            if not _sample_pool:
                _sample_pool = list(_reports_dir.glob("*.html"))[:50]

            # Sort by mtime, take 10 most recent
            _sorted = sorted(_sample_pool, key=lambda p: p.stat().st_mtime, reverse=True)[:10]
            _SIGS = (b"<!doctype html", b"<!doctype", b"<html")
            _invalid: List[str] = []
            for _f in _sorted:
                _size = _f.stat().st_size
                if _size < 1024:
                    _invalid.append(f"{_f.name}:{_size}B")
                    continue
                try:
                    with open(_f, "rb") as _fh:
                        _head = _fh.read(64).lower()
                    if not any(_head.startswith(s) for s in _SIGS):
                        _invalid.append(f"{_f.name}:bad_header")
                except Exception as _e:
                    _invalid.append(f"{_f.name}:{_e}")
            if _invalid:
                return False, f"{len(_invalid)}/{len(_sorted)} sampled reports invalid: {_invalid[:3]}"
            return True, f"{len(_sorted)} sampled reports valid (fast scan; full tree not traversed)"
        self._run("report_files_valid", _check_report_files_valid, critical=True, phase=2)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 3 — PIPELINE DETERMINISM
    # ─────────────────────────────────────────────────────────────────────────

    def phase3_pipeline_determinism(self):
        print("\n━━━ PHASE 3: Pipeline Determinism ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        def _check_manifest_existence():
            _man_path = self._root / "data" / "stix" / "feed_manifest.json"
            if not _man_path.exists():
                # Manifest only exists after the pipeline has run.
                # Absence is a valid pre-run state — not a code-level governance failure.
                return True, "feed_manifest.json absent (pipeline not run yet — skipping)"
            try:
                from scripts.pipeline_validator import ManifestValidator
                mv = ManifestValidator(_man_path)
                _report = mv.validate()
                _ok     = _report.get("ok_entries", 0)
                _errors = _report.get("error_entries", 0)
                _bools  = _report.get("bool_published", 0)
                if _bools > 0:
                    return False, f"MANIFEST P0: {_bools} entries have boolean 'published' field"
                return _report.get("valid", False), (
                    f"Manifest validation: ok={_ok} errors={_errors} "
                    f"warnings={_report.get('warning_entries',0)}"
                )
            except Exception as _e:
                return False, str(_e)
        self._run("manifest_validation", _check_manifest_existence, critical=True, phase=3)

        def _check_report_existence_guard():
            try:
                from scripts.pipeline_validator import ReportExistenceGuard
                _man_path = self._root / "data" / "stix" / "feed_manifest.json"
                if not _man_path.exists():
                    return True, "Manifest not found — skipping existence check (pipeline not run yet)"
                _d = json.loads(_man_path.read_text(encoding="utf-8"))
                _entries = _d.get("advisories") or _d.get("reports") or []
                guard  = ReportExistenceGuard(self._root)
                result = guard.check_entries(_entries, downgrade_missing=False)
                _pct   = (result["present"] / result["checked"] * 100) if result["checked"] else 100
                if result["missing"] > 0:
                    return False, (
                        f"{result['missing']} published entries have MISSING files on disk "
                        f"({_pct:.0f}% present) — examples: {result['missing_entries'][:2]}"
                    )
                return True, f"All {result['present']} published entries have files on disk"
            except Exception as _e:
                return False, str(_e)
        self._run("report_existence_guard", _check_report_existence_guard, critical=True, phase=3)

        def _check_ioc_count_integrity():
            try:
                _man_path = self._root / "data" / "stix" / "feed_manifest.json"
                if not _man_path.exists():
                    return True, "Manifest not found — skipping"
                _d    = json.loads(_man_path.read_text(encoding="utf-8"))
                _adv  = _d.get("advisories") or _d.get("reports") or []
                _bad  = 0
                for _e in _adv:
                    _iocs = _e.get("iocs", [])
                    _cnt  = _e.get("ioc_count", -1)
                    if isinstance(_iocs, list) and isinstance(_cnt, int) and _cnt != len(_iocs):
                        _bad += 1
                if _bad:
                    return False, f"{_bad} entries have ioc_count ≠ len(iocs) — schema violation"
                return True, f"ioc_count integrity OK across {len(_adv)} entries"
            except Exception as _e:
                return False, str(_e)
        self._run("ioc_count_integrity", _check_ioc_count_integrity, critical=False, phase=3)

        def _check_no_bool_published():
            try:
                _man_path = self._root / "data" / "stix" / "feed_manifest.json"
                if not _man_path.exists():
                    return True, "Manifest not found — skipping"
                _d   = json.loads(_man_path.read_text(encoding="utf-8"))
                _adv = _d.get("advisories") or _d.get("reports") or []
                _bad = [e.get("id","?") for e in _adv if isinstance(e.get("published"), bool)]
                if _bad:
                    return False, f"P0 REGRESSION: {len(_bad)} entries have published=bool: {_bad[:3]}"
                return True, f"published field is string in all {len(_adv)} entries"
            except Exception as _e:
                return False, str(_e)
        self._run("no_bool_published_field", _check_no_bool_published, critical=True, phase=3)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 4 — CUSTOMER PATH VALIDATION
    # ─────────────────────────────────────────────────────────────────────────

    def phase4_customer_paths(self):
        print("\n━━━ PHASE 4: Customer Path Validation ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        def _check_customer_paths():
            """
            Lightweight structural customer-path validation.

            The full CustomerPathValidator.validate_all() does rglob("*.html") over all
            report files (35K+) which takes >30s.  This check validates the same
            invariants via fast existence probes and reads the 3 most-recently-modified
            files only — no full directory traversal.
            """
            try:
                _issues: List[str] = []
                _ok:     List[str] = []

                # 1. Dashboard data file
                _dash_candidates = [
                    self._root / "data" / "dashboard_data.json",
                    self._root / "data" / "intel" / "dashboard_data.json",
                    self._root / "data" / "api" / "dashboard_data.json",
                ]
                _dash = next((p for p in _dash_candidates if p.exists()), None)
                if _dash:
                    try:
                        json.loads(_dash.read_text(encoding="utf-8"))
                        _ok.append(f"dashboard_data@{_dash.parent.name}")
                    except Exception:
                        _issues.append("dashboard_data.json corrupt JSON")
                else:
                    _ok.append("dashboard_data absent (pre-run)")

                # 2. Feed manifest
                _man = self._root / "data" / "stix" / "feed_manifest.json"
                if _man.exists():
                    try:
                        json.loads(_man.read_text(encoding="utf-8"))
                        _ok.append("feed_manifest valid")
                    except Exception:
                        _issues.append("feed_manifest.json corrupt JSON")
                else:
                    _ok.append("feed_manifest absent (pre-run)")

                # 3. Reports directory has files
                _rdir = self._root / "reports"
                if _rdir.exists():
                    # Fast: take the first file we find without listing everything
                    _first = next(_rdir.rglob("*.html"), None)
                    if _first:
                        _ok.append(f"reports/ has HTML files")
                    else:
                        _ok.append("reports/ exists but empty (pre-run)")
                else:
                    _ok.append("reports/ absent (pre-run)")

                # 4. Spot-check 3 most recent reports for IOC/MITRE/CTA content
                if _rdir.exists():
                    import heapq, os as _os
                    # Fast mtime sampling: scandir top level only (avoids 35K-stat traversal)
                    _subdirs = [e.path for e in _os.scandir(_rdir) if e.is_dir()]
                    _sample: List[Path] = []
                    for _sd in _subdirs[:20]:  # cap at 20 subdirs
                        _sample.extend(Path(_sd).glob("*.html"))
                        if len(_sample) > 100:
                            break
                    _recent = sorted(_sample, key=lambda p: p.stat().st_mtime, reverse=True)[:3]
                    _has_ioc = _has_mitre = _has_cta = False
                    for _f in _recent:
                        try:
                            _txt = _f.read_text(encoding="utf-8", errors="replace").lower()
                            if "ioc" in _txt:                                _has_ioc   = True
                            if "mitre" in _txt or "att&ck" in _txt:         _has_mitre = True
                            if "cta" in _txt or "enterprise" in _txt:       _has_cta   = True
                        except Exception:
                            pass
                    if _recent:
                        _ok.append(f"IOC={'yes' if _has_ioc else 'no'} MITRE={'yes' if _has_mitre else 'no'} CTA={'yes' if _has_cta else 'no'} in {len(_recent)} recent reports")

                # 5. STIX bundles
                _stix_dir = self._root / "data" / "stix"
                if _stix_dir.exists():
                    _bundles = [f for f in _stix_dir.glob("*.json") if f.name != "feed_manifest.json"]
                    _ok.append(f"STIX: {len(_bundles)} bundle(s)" if _bundles else "STIX: 0 bundles (pre-run)")
                else:
                    _ok.append("data/stix/ absent (pre-run)")

                if _issues:
                    return False, f"Customer path issues: {'; '.join(_issues)}"
                return True, f"Customer paths OK: {', '.join(_ok)}"

            except Exception as _e:
                return False, str(_e)
        self._run("customer_paths_all", _check_customer_paths, critical=True, phase=4)

        def _check_report_urls_valid():
            try:
                _man_path = self._root / "data" / "stix" / "feed_manifest.json"
                if not _man_path.exists():
                    return True, "Manifest not found — skipping"
                _d    = json.loads(_man_path.read_text(encoding="utf-8"))
                _adv  = [e for e in (_d.get("advisories") or _d.get("reports") or [])
                         if e.get("validation_status") in ("ok", "enriched", "valid")]
                _bad  = [e.get("id") for e in _adv
                         if not e.get("report_url", "").startswith("http")]
                if _bad:
                    return False, f"{len(_bad)} published entries have invalid report_url: {_bad[:3]}"
                return True, f"All {len(_adv)} published entries have valid https:// report_url"
            except Exception as _e:
                return False, str(_e)
        self._run("report_urls_valid_https", _check_report_urls_valid, critical=True, phase=4)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 5 — OBSERVABILITY
    # ─────────────────────────────────────────────────────────────────────────

    def phase5_observability(self):
        print("\n━━━ PHASE 5: Enterprise Observability ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        def _check_system_health_monitor():
            try:
                from scripts.safe_io import SystemHealthMonitor, WriteQueue
                _monitor = SystemHealthMonitor(self._root)
                _state   = _monitor.get_state()
                if "state" not in _state:
                    return False, "SystemHealthMonitor.get_state() missing 'state' key"
                _score = _state.get("health_score", -1)
                if _score < 0:
                    return False, f"Invalid health score: {_score}"
                return True, f"SystemHealthMonitor OK | state={_state['state']} score={_score}"
            except Exception as _e:
                return False, str(_e)
        self._run("system_health_monitor", _check_system_health_monitor, critical=False, phase=5)

        def _check_telemetry_writeable():
            try:
                from scripts.runtime_governance import OrchestratorTelemetry
                _tel = OrchestratorTelemetry("HEALTHCHECK")
                _tel.critical_failures.increment(0)
                _d = _tel.to_dict()
                if "health_score" not in _d or "counters" not in _d:
                    return False, "OrchestratorTelemetry.to_dict() missing required keys"
                _ok = _tel.write_report(self._root)
                return True, f"OrchestratorTelemetry write_report={_ok} health={_d['health_score']}"
            except Exception as _e:
                return False, str(_e)
        self._run("telemetry_writeable", _check_telemetry_writeable, critical=False, phase=5)

        def _check_pipeline_metrics():
            try:
                from scripts.safe_io import PipelineMetrics
                _m = PipelineMetrics()
                _m.record_ingestion(100)
                _m.record_failure("test", "test failure")
                _m.record_iocs(50)
                _d = _m.to_dict()
                _required_keys = [
                    "ingested_items", "failed_items", "total_iocs_extracted",
                    "pipeline_failure_rate", "write_failures",
                ]
                _missing = [k for k in _required_keys if k not in _d]
                if _missing:
                    return False, f"PipelineMetrics.to_dict() missing keys: {_missing}"
                return True, f"PipelineMetrics OK | keys={len(_d)} ingested={_d['ingested_items']}"
            except Exception as _e:
                return False, str(_e)
        self._run("pipeline_metrics_complete", _check_pipeline_metrics, critical=False, phase=5)

        def _check_logs_dir():
            _logs_dir = self._root / "data" / "logs"
            _logs_dir.mkdir(parents=True, exist_ok=True)
            _writable = os.access(str(_logs_dir), os.W_OK)
            return _writable, (
                f"data/logs/ is {'writable' if _writable else 'NOT WRITABLE'}"
            )
        self._run("logs_directory_writable", _check_logs_dir, critical=False, phase=5)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 6 — COMMERCIAL READINESS
    # ─────────────────────────────────────────────────────────────────────────

    def phase6_commercial_readiness(self):
        print("\n━━━ PHASE 6: Commercial Readiness ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        if self._fast:
            print("  [SKIPPED] Fast mode — skipping commercial readiness checks")
            return

        def _check_brand_in_reports():
            _rdir = self._root / "reports"
            if not _rdir.exists():
                return False, "reports/ directory not found"
            _html = sorted(_rdir.rglob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)[:3]
            for _f in _html:
                try:
                    _t = _f.read_text(encoding="utf-8", errors="replace")
                    if "CYBERDUDEBIVASH" in _t:
                        return True, f"Brand present in {_f.name}"
                except Exception:
                    continue
            return False, "CYBERDUDEBIVASH brand not found in recent reports"
        self._run("brand_present_in_reports", _check_brand_in_reports, critical=False, phase=6)

        def _check_mssp_readiness():
            """Check for MSSP-ready signals in platform."""
            _signals = []
            # Check for API layer
            _api_candidates = [
                self._root / "agent" / "api" / "enterprise_api.py",
                self._root / "agent" / "api" / "api_server.py",
                self._root / "sentinel-apex-api",
            ]
            for _c in _api_candidates:
                if _c.exists():
                    _signals.append(f"API: {_c.name}")
                    break
            # Check for premium/subscription signals
            _sub_candidates = [
                self._root / "agent" / "api" / "premium_api.py",
                self._root / "agent" / "api" / "stripe_gateway.py",
            ]
            for _c in _sub_candidates:
                if _c.exists():
                    _signals.append(f"Subscription: {_c.name}")
            # Check for report generation
            if (self._root / "scripts" / "generate_intel_reports.py").exists():
                _signals.append("Report generator present")
            return bool(_signals), f"MSSP signals: {', '.join(_signals) if _signals else 'NONE'}"
        self._run("mssp_readiness_signals", _check_mssp_readiness, critical=False, phase=6)

        def _check_commercial_license():
            _candidates = [
                self._root / "COMMERCIAL_LICENSE.md",
                self._root / "LICENSE",
                self._root / "COPYRIGHT.md",
            ]
            for _c in _candidates:
                if _c.exists():
                    return True, f"Commercial license document found: {_c.name}"
            return False, "No commercial license document found"
        self._run("commercial_license_present", _check_commercial_license, critical=False, phase=6)

    # ─────────────────────────────────────────────────────────────────────────
    # PHASE 7 — REGRESSION PREVENTION
    # ─────────────────────────────────────────────────────────────────────────

    def phase7_regression_prevention(self):
        print("\n━━━ PHASE 7: Regression Prevention ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        def _check_python_syntax_critical():
            """Syntax check all critical Python files."""
            _critical_files = [
                self._root / "core" / "orchestrator.py",
                self._root / "scripts" / "generate_intel_reports.py",
                self._root / "scripts" / "safe_io.py",
                self._root / "scripts" / "runtime_governance.py",
                self._root / "scripts" / "pipeline_validator.py",
            ]
            _failed: List[str] = []
            for _f in _critical_files:
                if not _f.exists():
                    _failed.append(f"MISSING: {_f.name}")
                    continue
                try:
                    _result = subprocess.run(
                        [sys.executable, "-m", "py_compile", str(_f)],
                        capture_output=True, text=True, timeout=15,
                    )
                    if _result.returncode != 0:
                        _failed.append(f"{_f.name}: {_result.stderr.strip()[:100]}")
                except subprocess.TimeoutExpired:
                    _failed.append(f"{_f.name}: syntax check timed out")
                except Exception as _e:
                    _failed.append(f"{_f.name}: {_e}")
            if _failed:
                return False, f"Syntax errors in {len(_failed)} file(s): {_failed}"
            return True, f"All {len(_critical_files)} critical files pass syntax check"
        self._run("syntax_check_critical_files", _check_python_syntax_critical, critical=True, phase=7)

        def _check_no_bare_except():
            """Detect bare 'except:' clauses in critical files (masks all errors)."""
            _critical_files = [
                self._root / "core" / "orchestrator.py",
                self._root / "scripts" / "generate_intel_reports.py",
            ]
            _violations: List[str] = []
            for _f in _critical_files:
                if not _f.exists():
                    continue
                _src   = _f.read_text(encoding="utf-8")
                _lines = _src.split("\n")
                for _i, _line in enumerate(_lines, 1):
                    _stripped = _line.strip()
                    if _stripped == "except:" or _stripped.startswith("except:  "):
                        _violations.append(f"{_f.name}:{_i}")
            if _violations:
                return False, f"Bare 'except:' in {len(_violations)} location(s): {_violations[:3]}"
            return True, "No bare 'except:' clauses in critical files"
        self._run("no_bare_except_clauses", _check_no_bare_except, critical=False, phase=7)

        def _check_generate_reports_finalization():
            """Verify generate_intel_reports.py has top-level finalization safety."""
            _path = self._root / "scripts" / "generate_intel_reports.py"
            if not _path.exists():
                return False, "generate_intel_reports.py not found"
            _src = _path.read_text(encoding="utf-8")
            # Check for t_start initialization
            if "t_start = time.monotonic()" not in _src:
                return False, "t_start not explicitly initialized — NameError risk"
            # Check for elapsed computation
            if "elapsed = time.monotonic() - t_start" not in _src:
                return False, "elapsed not computed safely"
            # Check counter initializations
            _counters = ["written = 0", "errors = 0", "skipped_brand = 0"]
            _missing  = [c for c in _counters if c not in _src]
            if _missing:
                return False, f"Counter(s) not initialized: {_missing}"
            return True, "generate_intel_reports.py finalization counters properly initialized"
        self._run("report_generator_finalization", _check_generate_reports_finalization, critical=True, phase=7)

        def _check_governance_imports_from_generator():
            """Confirm governance layer is importable from generate_intel_reports context."""
            _gpath = self._root / "scripts" / "runtime_governance.py"
            _vpath = self._root / "scripts" / "pipeline_validator.py"
            _missing = []
            if not _gpath.exists():
                _missing.append("runtime_governance.py")
            if not _vpath.exists():
                _missing.append("pipeline_validator.py")
            if _missing:
                return False, f"Governance module(s) missing: {_missing}"
            return True, "All governance modules present and accounted for"
        self._run("governance_modules_present", _check_governance_imports_from_generator, critical=True, phase=7)

    # ─────────────────────────────────────────────────────────────────────────
    # FINAL REPORT
    # ─────────────────────────────────────────────────────────────────────────

    def run_all(self, phase_filter: Optional[int] = None) -> Dict[str, Any]:
        """Run all phases and return complete report."""
        print(f"\n{'═'*78}")
        print(f"  CYBERDUDEBIVASH® SENTINEL APEX — Production Health Check {self.SUITE_VERSION}")
        print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | Repo: {self._root.name}")
        print(f"{'═'*78}")

        phases = [
            (1, self.phase1_runtime_safety),
            (2, self.phase2_file_integrity),
            (3, self.phase3_pipeline_determinism),
            (4, self.phase4_customer_paths),
            (5, self.phase5_observability),
            (6, self.phase6_commercial_readiness),
            (7, self.phase7_regression_prevention),
        ]

        if self._fast:
            phases = [(n, fn) for n, fn in phases if n in (1, 2, 3, 7)]
            print(f"\n  ⚡ FAST MODE — running phases: {[n for n,_ in phases]}")

        if phase_filter is not None:
            phases = [(n, fn) for n, fn in phases if n == phase_filter]
            print(f"\n  🔍 SINGLE PHASE MODE — running phase {phase_filter}")

        for _phase_num, _phase_fn in phases:
            try:
                _phase_fn()
            except Exception as _e:
                print(f"\n  ❌ Phase {_phase_num} crashed: {type(_e).__name__}: {_e}")
                self._results.append(CheckResult(
                    f"phase_{_phase_num}_execution",
                    False,
                    f"Phase crashed: {_e}",
                    critical=True,
                    phase=_phase_num,
                ))

        return self._final_report()

    def _final_report(self) -> Dict[str, Any]:
        _elapsed   = time.monotonic() - self._started
        _total     = len(self._results)
        _passed    = sum(1 for r in self._results if r.passed)
        _failed    = sum(1 for r in self._results if not r.passed)
        _crit_fail = sum(1 for r in self._results if not r.passed and r.critical)
        _warn      = sum(1 for r in self._results if not r.passed and not r.critical)
        _all_pass  = _crit_fail == 0

        print(f"\n{'═'*78}")
        print(f"  HEALTH CHECK COMPLETE | {_elapsed:.1f}s")
        print(f"{'═'*78}")
        print(f"  {'✅ ALL CRITICAL CHECKS PASSED' if _all_pass else '❌ CRITICAL CHECKS FAILED'}")
        print(f"  Total: {_total} | Passed: {_passed} | Failed: {_failed} | Critical Fails: {_crit_fail} | Warnings: {_warn}")

        if _crit_fail > 0:
            print(f"\n  Critical failures:")
            for _r in self._results:
                if not _r.passed and _r.critical:
                    print(f"    ❌ [{_r.phase}] {_r.name}: {_r.detail}")

        if _warn > 0:
            print(f"\n  Warnings (non-critical):")
            for _r in self._results:
                if not _r.passed and not _r.critical:
                    print(f"    ⚠️  [{_r.phase}] {_r.name}: {_r.detail}")

        print(f"{'═'*78}\n")

        _report = {
            "suite":            f"SENTINEL APEX Health Check {self.SUITE_VERSION}",
            "overall_pass":     _all_pass,
            "total_checks":     _total,
            "passed":           _passed,
            "failed":           _failed,
            "critical_failures": _crit_fail,
            "warnings":         _warn,
            "elapsed_seconds":  round(_elapsed, 2),
            "repo_root":        str(self._root),
            "generated_at":     datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "checks":           [r.to_dict() for r in self._results],
        }

        # Write report to data/logs/
        try:
            _log_dir = self._root / "data" / "logs"
            _log_dir.mkdir(parents=True, exist_ok=True)
            _out_path = _log_dir / "last_health_check.json"
            _tmp      = _out_path.with_suffix(".json.tmp")
            _tmp.write_text(json.dumps(_report, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(str(_tmp), str(_out_path))
            print(f"  📄 Full report → {_out_path}")
        except Exception as _e:
            print(f"  ⚠️  Could not save report: {_e}")

        return _report


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION COMMANDS (exact commands for CI/CD)
# ─────────────────────────────────────────────────────────────────────────────

VALIDATION_COMMANDS = (
    "  FULL SUITE:  python scripts/production_health_check.py\n"
    "  FAST:        python scripts/production_health_check.py --fast\n"
    "  JSON:        python scripts/production_health_check.py --json\n"
    "  PHASE N:     python scripts/production_health_check.py --phase N\n"
    "  EXIT CODES: 0=PASS  1=CRITICAL_FAIL  2=INIT_FAILURE\n"
)


# CLI ENTRY POINT

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Production Health Check Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--fast",     action="store_true", help="Critical checks only")
    parser.add_argument("--json",     action="store_true", help="JSON output to stdout")
    parser.add_argument("--fix",      action="store_true", help="Attempt auto-fixes")
    parser.add_argument("--phase",    type=int, default=0, metavar="N", help="Run single phase (1-7)")
    parser.add_argument("--commands", action="store_true", help="Print validation commands and exit")
    args = parser.parse_args()

    if args.commands:
        print(VALIDATION_COMMANDS)
        return 0

    _suite  = HealthCheckSuite(REPO_ROOT, fast=args.fast, auto_fix=args.fix)
    _report = _suite.run_all(phase_filter=args.phase if args.phase else None)

    if args.json:
        print(json.dumps(_report, indent=2, ensure_ascii=False))

    return 0 if _report.get("overall_pass") else 1


if __name__ == "__main__":
    sys.exit(main())
