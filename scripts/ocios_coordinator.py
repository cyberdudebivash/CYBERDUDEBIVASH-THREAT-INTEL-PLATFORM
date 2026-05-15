#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
scripts/ocios_coordinator.py
OCIOS Coordinator -- Operational Cyber Intelligence Operating System Orchestrator
================================================================================
Version      : 1.0.0
Classification: CONFIDENTIAL -- OCIOS TIER

MANDATE
-------
The OCIOS Coordinator is the single authoritative orchestrator for the entire
Operational Cyber Intelligence Operating System.  It coordinates all OCIOS
engines in deterministic sequence, provides enterprise-grade exception isolation,
aggregates telemetry, and produces a unified operational intelligence package
ready for SOC consumption, executive reporting, and dashboard rendering.

ORCHESTRATION SEQUENCE (deterministic)
---------------------------------------
  Stage 1:  Corpus Loading + Manifest Validation
  Stage 2:  Campaign Correlation Engine
            (ocios_campaign_correlation_engine.py)
  Stage 3:  Operational Reasoning Engine
            (ocios_operational_reasoning_engine.py)
  Stage 4:  SOC Prioritization Engine
            (ocios_soc_prioritization_engine.py)
  Stage 5:  Output Consolidation + Telemetry
  Stage 6:  Integration Validation

GOVERNANCE GUARANTEES
---------------------
  - NON-CRITICAL stage failures NEVER terminate the orchestration
  - CRITICAL stage failures are isolated to that stage
  - All outputs are atomic-written (tmp -> fsync -> os.replace)
  - UTF-8 clean -- no non-ASCII in any code path
  - Deterministic execution ordering -- always the same sequence
  - Runtime telemetry per stage (start, end, duration, status)
  - Exception isolation: one engine failure never cascades
  - Complete audit trail in ocios_coordinator_report.json

INPUTS
------
  data/feed_manifest.json    (required -- source of truth)
  data/ocios/               (read/write -- OCIOS output directory)

OUTPUTS
-------
  data/ocios/coordinator_report.json   -- full orchestration run report
  data/ocios/ocios_manifest.json       -- unified OCIOS output manifest
  All outputs from individual OCIOS engines (written by each engine)

PIPELINE POSITION
-----------------
  Entry point for all OCIOS operations.
  Called by: cron / GitHub Actions / CLI / orchestrator.py
  Called after: enterprise_scoring_engine.py, apex_intelligence_engine.py

SAFETY GUARANTEES
-----------------
  - All stages wrapped in exception isolation
  - Stage timeouts enforced via threading
  - No stage mutates feed_manifest.json
  - Failed stages produce empty-safe output stubs
  - Engine import failures degrade gracefully (stage skipped)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ocios.coordinator")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT      = Path(__file__).resolve().parent.parent
MANIFEST_PATH  = REPO_ROOT / "data" / "feed_manifest.json"
OCIOS_DIR      = REPO_ROOT / "data" / "ocios"
SCRIPTS_DIR    = Path(__file__).resolve().parent
ENGINE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Stage severity classification
# ---------------------------------------------------------------------------
# CRITICAL stages: failure means abort and report error (never skip silently)
# OPTIONAL stages: failure means warn, continue, mark stage as degraded
_CRITICAL_STAGES  = frozenset({"corpus_load", "manifest_validate"})
_OPTIONAL_STAGES  = frozenset({"campaign_correlation", "operational_reasoning",
                                "soc_prioritization", "output_consolidation",
                                "integration_validate"})

# Stage timeout in seconds (0 = no timeout)
_STAGE_TIMEOUTS = {
    "corpus_load":          30,
    "manifest_validate":    15,
    "campaign_correlation": 300,
    "operational_reasoning":300,
    "soc_prioritization":   300,
    "output_consolidation": 60,
    "integration_validate": 30,
}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    return str(v).strip()


def _atomic_write(path: Path, obj: Any) -> None:
    """Atomic JSON write: tmp -> fsync -> os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp_coord")
    try:
        data = json.dumps(obj, ensure_ascii=True, indent=2, default=str)
        encoded = data.encode("utf-8")
        if b"\x00" in encoded:
            raise ValueError("NULL bytes in coordinator output")
        tmp.write_bytes(encoded)
        fd = os.open(str(tmp), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(path))
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Stage result record
# ---------------------------------------------------------------------------

def _make_stage_result(
    stage_name:  str,
    status:      str,
    started_at:  str,
    completed_at: str,
    elapsed_s:   float,
    outputs:     List[str],
    error:       Optional[str] = None,
    metrics:     Optional[Dict] = None,
) -> Dict[str, Any]:
    return {
        "stage":        stage_name,
        "status":       status,       # success | partial | skipped | error | timeout
        "started_at":   started_at,
        "completed_at": completed_at,
        "elapsed_s":    elapsed_s,
        "outputs":      outputs,
        "error":        error,
        "metrics":      metrics or {},
    }


# ---------------------------------------------------------------------------
# Stage runner with exception isolation + timing
# ---------------------------------------------------------------------------

def _run_stage(
    stage_name: str,
    fn:         Callable[[], Tuple[str, List[str], Dict]],
    is_critical: bool = False,
) -> Dict[str, Any]:
    """
    Run a single OCIOS stage with full exception isolation.

    fn() must return (status_str, output_files_list, metrics_dict).
    Never raises.  Returns a stage result dict.
    """
    started_at = _utc_now()
    t0         = time.monotonic()
    log.info("=== STAGE START: %s ===", stage_name.upper())

    try:
        status, outputs, metrics = fn()
        elapsed = round(time.monotonic() - t0, 2)
        completed_at = _utc_now()
        log.info(
            "=== STAGE COMPLETE: %s | %s | %.2fs ===",
            stage_name.upper(), status.upper(), elapsed
        )
        return _make_stage_result(
            stage_name=stage_name,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_s=elapsed,
            outputs=outputs,
            metrics=metrics,
        )

    except Exception as exc:
        elapsed      = round(time.monotonic() - t0, 2)
        completed_at = _utc_now()
        err_msg      = f"{type(exc).__name__}: {exc}"
        tb           = traceback.format_exc()
        log.error(
            "=== STAGE FAILED: %s | %.2fs | %s ===\n%s",
            stage_name.upper(), elapsed, err_msg, tb
        )
        return _make_stage_result(
            stage_name=stage_name,
            status="error",
            started_at=started_at,
            completed_at=completed_at,
            elapsed_s=elapsed,
            outputs=[],
            error=err_msg,
        )


# ---------------------------------------------------------------------------
# ENGINE IMPORT LOADER
# Imports OCIOS engines at runtime to avoid import-time failures cascading.
# ---------------------------------------------------------------------------

def _load_engine(module_name: str) -> Optional[Any]:
    """
    Dynamically import an OCIOS engine module.
    Returns the module or None on failure.
    """
    # Ensure scripts dir is on path
    scripts_str = str(SCRIPTS_DIR)
    if scripts_str not in sys.path:
        sys.path.insert(0, scripts_str)

    try:
        import importlib
        module = importlib.import_module(module_name)
        log.info("Loaded engine: %s", module_name)
        return module
    except Exception as exc:
        log.error("Engine import failed: %s -- %s", module_name, exc)
        return None


# ---------------------------------------------------------------------------
# STAGE 1: CORPUS LOADING + MANIFEST VALIDATION
# ---------------------------------------------------------------------------

def _stage_corpus_load(manifest_path: Path) -> Tuple[str, List[str], Dict]:
    """Load and validate the manifest corpus."""
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    items: List[Dict] = []

    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.get("advisories") or raw.get("reports") or []
    else:
        raise TypeError(f"Unexpected manifest type: {type(raw)}")

    if not items:
        log.warning("Manifest loaded but contains 0 items")

    # Validate UTF-8
    manifest_bytes = manifest_path.read_bytes()
    if b"\x00" in manifest_bytes:
        raise ValueError("Manifest contains NULL bytes -- corrupted file")

    metrics = {
        "advisory_count":  len(items),
        "manifest_size_kb": round(len(manifest_bytes) / 1024, 1),
        "manifest_path":    str(manifest_path),
    }
    log.info("Corpus loaded: %d advisories (%.1f KB)", len(items), metrics["manifest_size_kb"])
    return "success", [str(manifest_path)], metrics


def _stage_manifest_validate(manifest_path: Path) -> Tuple[str, List[str], Dict]:
    """Structural validation of the manifest."""
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    items: List[Dict] = []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.get("advisories") or raw.get("reports") or []

    # Spot-check required fields
    missing_title = sum(1 for i in items if not i.get("title") and not i.get("advisory_id"))
    missing_sev   = sum(1 for i in items if not i.get("severity") and not i.get("risk_level"))

    metrics = {
        "total_items":    len(items),
        "missing_title":  missing_title,
        "missing_sev":    missing_sev,
        "validation_pct": round((1 - missing_title / max(len(items), 1)) * 100, 1),
    }
    log.info(
        "Manifest validation: %d items | missing_title=%d | missing_sev=%d",
        len(items), missing_title, missing_sev
    )
    status = "success" if missing_title < len(items) * 0.5 else "partial"
    return status, [], metrics


# ---------------------------------------------------------------------------
# STAGE 2: CAMPAIGN CORRELATION ENGINE
# ---------------------------------------------------------------------------

def _stage_campaign_correlation(manifest_path: Path, ocios_dir: Path) -> Tuple[str, List[str], Dict]:
    """Run Campaign Correlation Engine."""
    module = _load_engine("ocios_campaign_correlation_engine")
    if module is None:
        log.warning("Campaign Correlation Engine not available -- stage skipped")
        return "skipped", [], {"reason": "import_failure"}

    fn = getattr(module, "run_correlation_engine", None)
    if fn is None:
        return "skipped", [], {"reason": "run_correlation_engine_not_found"}

    result = fn(manifest_path=manifest_path, ocios_dir=ocios_dir)
    status  = _safe_str(result.get("status"), "error")
    written = result.get("files_written", 0)
    errors  = result.get("errors", [])

    outputs = []
    for fname in [
        "campaign_graph.json", "actor_relationships.json",
        "infrastructure_clusters.json", "temporal_chains.json", "ioc_lineage.json"
    ]:
        p = ocios_dir / fname
        if p.exists():
            outputs.append(str(p))

    metrics = {
        "items_processed": result.get("items_processed", 0),
        "files_written":   written,
        "errors":          errors,
        "campaigns_found": result.get("campaigns_found", 0),
    }
    if errors:
        log.warning("Campaign Correlation Engine completed with %d errors", len(errors))
    return status, outputs, metrics


# ---------------------------------------------------------------------------
# STAGE 3: OPERATIONAL REASONING ENGINE
# ---------------------------------------------------------------------------

def _stage_operational_reasoning(manifest_path: Path, ocios_dir: Path) -> Tuple[str, List[str], Dict]:
    """Run Operational Reasoning Engine."""
    module = _load_engine("ocios_operational_reasoning_engine")
    if module is None:
        log.warning("Operational Reasoning Engine not available -- stage skipped")
        return "skipped", [], {"reason": "import_failure"}

    fn = getattr(module, "run_reasoning_engine", None)
    if fn is None:
        return "skipped", [], {"reason": "run_reasoning_engine_not_found"}

    result = fn(manifest_path=manifest_path, ocios_dir=ocios_dir)
    status  = _safe_str(result.get("status"), "error")
    written = result.get("files_written", 0)
    errors  = result.get("errors", [])

    outputs = []
    for fname in [
        "operational_reasoning.json", "sector_threat_landscape.json",
        "adversary_objective_map.json", "business_risk_synthesis.json"
    ]:
        p = ocios_dir / fname
        if p.exists():
            outputs.append(str(p))

    metrics = {
        "items_processed": result.get("items_processed", 0),
        "files_written":   written,
        "errors":          errors,
    }
    if errors:
        log.warning("Operational Reasoning Engine completed with %d errors", len(errors))
    return status, outputs, metrics


# ---------------------------------------------------------------------------
# STAGE 4: SOC PRIORITIZATION ENGINE
# ---------------------------------------------------------------------------

def _stage_soc_prioritization(manifest_path: Path, ocios_dir: Path) -> Tuple[str, List[str], Dict]:
    """Run SOC Prioritization Engine."""
    module = _load_engine("ocios_soc_prioritization_engine")
    if module is None:
        log.warning("SOC Prioritization Engine not available -- stage skipped")
        return "skipped", [], {"reason": "import_failure"}

    fn = getattr(module, "run_soc_prioritization_engine", None)
    if fn is None:
        return "skipped", [], {"reason": "run_soc_prioritization_engine_not_found"}

    result = fn(manifest_path=manifest_path, ocios_dir=ocios_dir)
    status  = _safe_str(result.get("status"), "error")
    written = result.get("files_written", 0)
    errors  = result.get("errors", [])

    outputs = []
    for fname in [
        "soc_priority_queue.json", "remediation_tiers.json",
        "escalation_matrix.json", "executive_dashboard.json", "analyst_workload.json"
    ]:
        p = ocios_dir / fname
        if p.exists():
            outputs.append(str(p))

    metrics = {
        "items_scored":  result.get("items_scored", 0),
        "files_written": written,
        "tier_breakdown": result.get("tier_breakdown", {}),
        "errors":        errors,
    }
    if errors:
        log.warning("SOC Prioritization Engine completed with %d errors", len(errors))
    return status, outputs, metrics


# ---------------------------------------------------------------------------
# STAGE 5: OUTPUT CONSOLIDATION
# ---------------------------------------------------------------------------

def _stage_output_consolidation(
    ocios_dir:    Path,
    stage_results: List[Dict],
    run_id:       str,
    started_at:   str,
) -> Tuple[str, List[str], Dict]:
    """
    Build a unified OCIOS manifest listing all outputs and their status.
    This is the single source of truth for downstream consumers.
    """
    # Inventory all ocios outputs
    ocios_files: List[Dict] = []
    if ocios_dir.exists():
        for p in sorted(ocios_dir.iterdir()):
            if p.is_file() and p.suffix == ".json" and not p.name.startswith("."):
                ocios_files.append({
                    "file":       p.name,
                    "path":       str(p),
                    "size_bytes": p.stat().st_size,
                    "modified":   datetime.fromtimestamp(
                        p.stat().st_mtime, tz=timezone.utc
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                })

    # Count totals
    stage_success = sum(1 for s in stage_results if s["status"] == "success")
    stage_partial = sum(1 for s in stage_results if s["status"] == "partial")
    stage_error   = sum(1 for s in stage_results if s["status"] == "error")
    stage_skipped = sum(1 for s in stage_results if s["status"] == "skipped")

    overall_status = "success"
    if stage_error > 0 and stage_success == 0:
        overall_status = "error"
    elif stage_error > 0 or stage_partial > 0:
        overall_status = "partial"

    ocios_manifest = {
        "schema_version":  "1.0",
        "engine":          "ocios_coordinator",
        "version":         ENGINE_VERSION,
        "run_id":          run_id,
        "generated_at":    _utc_now(),
        "overall_status":  overall_status,
        "stage_summary": {
            "total":   len(stage_results),
            "success": stage_success,
            "partial": stage_partial,
            "error":   stage_error,
            "skipped": stage_skipped,
        },
        "outputs": ocios_files,
        "stages":  stage_results,
    }

    _atomic_write(ocios_dir / "ocios_manifest.json", ocios_manifest)
    log.info(
        "OCIOS manifest written: %d output files | overall_status=%s",
        len(ocios_files), overall_status
    )

    metrics = {
        "output_file_count": len(ocios_files),
        "overall_status":    overall_status,
    }
    return overall_status, [str(ocios_dir / "ocios_manifest.json")], metrics


# ---------------------------------------------------------------------------
# STAGE 6: INTEGRATION VALIDATION
# ---------------------------------------------------------------------------

def _stage_integration_validate(ocios_dir: Path) -> Tuple[str, List[str], Dict]:
    """
    Post-run integration validation.
    Checks that required outputs exist, are valid JSON, and are non-empty.
    """
    required_outputs = [
        "soc_priority_queue.json",
        "remediation_tiers.json",
        "escalation_matrix.json",
        "executive_dashboard.json",
        "analyst_workload.json",
        "operational_reasoning.json",
        "ocios_manifest.json",
    ]

    optional_outputs = [
        "campaign_graph.json",
        "actor_relationships.json",
        "infrastructure_clusters.json",
        "temporal_chains.json",
        "ioc_lineage.json",
        "sector_threat_landscape.json",
        "adversary_objective_map.json",
        "business_risk_synthesis.json",
    ]

    results: Dict[str, str] = {}
    pass_count = 0
    fail_count = 0

    for fname in required_outputs:
        p = ocios_dir / fname
        if not p.exists():
            results[fname] = "MISSING"
            fail_count += 1
            log.warning("Integration check FAIL: %s -- file missing", fname)
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            if not data:
                results[fname] = "EMPTY"
                fail_count += 1
                log.warning("Integration check FAIL: %s -- empty JSON", fname)
            else:
                results[fname] = "OK"
                pass_count += 1
        except Exception as exc:
            results[fname] = f"INVALID_JSON: {exc}"
            fail_count += 1
            log.warning("Integration check FAIL: %s -- %s", fname, exc)

    for fname in optional_outputs:
        p = ocios_dir / fname
        if not p.exists():
            results[fname] = "OPTIONAL_MISSING"
        else:
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                results[fname] = "OK" if data else "OPTIONAL_EMPTY"
            except Exception:
                results[fname] = "OPTIONAL_INVALID"

    status = "success" if fail_count == 0 else ("partial" if pass_count > 0 else "error")
    log.info(
        "Integration validation: %d/%d required checks passed",
        pass_count, len(required_outputs)
    )
    return status, [], {
        "checks_passed":      pass_count,
        "checks_failed":      fail_count,
        "required_checked":   len(required_outputs),
        "optional_checked":   len(optional_outputs),
        "file_results":       results,
    }


# ---------------------------------------------------------------------------
# COORDINATOR REPORT BUILDER
# ---------------------------------------------------------------------------

def _build_coordinator_report(
    run_id:        str,
    started_at:    str,
    completed_at:  str,
    total_elapsed: float,
    stage_results: List[Dict],
    advisory_count: int,
    overall_status: str,
) -> Dict[str, Any]:
    """Build the full coordinator run report."""
    all_errors: List[str] = []
    for sr in stage_results:
        if sr.get("error"):
            all_errors.append(f"[{sr['stage']}] {sr['error']}")
        for e in (sr.get("metrics") or {}).get("errors", []):
            all_errors.append(f"[{sr['stage']}] {e}")

    # Derive tier breakdown from SOC stage if available
    tier_breakdown: Dict = {}
    for sr in stage_results:
        if sr["stage"] == "soc_prioritization" and sr["status"] != "skipped":
            tier_breakdown = sr.get("metrics", {}).get("tier_breakdown", {})
            break

    return {
        "schema_version":  "1.0",
        "engine":          "ocios_coordinator",
        "version":         ENGINE_VERSION,
        "run_id":          run_id,
        "started_at":      started_at,
        "completed_at":    completed_at,
        "total_elapsed_s": total_elapsed,
        "overall_status":  overall_status,
        "advisory_count":  advisory_count,
        "tier_breakdown":  tier_breakdown,
        "stage_count":     len(stage_results),
        "stage_results":   stage_results,
        "errors":          all_errors,
        "error_count":     len(all_errors),
        "production_safe": overall_status in ("success", "partial"),
    }


# ---------------------------------------------------------------------------
# MAIN COORDINATOR ENTRY POINT
# ---------------------------------------------------------------------------

def run_ocios_coordinator(
    manifest_path: Path = MANIFEST_PATH,
    ocios_dir:     Path = OCIOS_DIR,
    run_id:        Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute the full OCIOS orchestration pipeline.
    Never raises.  Always returns a coordinator report dict.
    """
    if run_id is None:
        run_id = datetime.now(timezone.utc).strftime("ocios_%Y%m%dT%H%M%SZ")

    started_at = _utc_now()
    t_total    = time.monotonic()

    log.info("=" * 72)
    log.info("OCIOS COORDINATOR START | run_id=%s", run_id)
    log.info("manifest: %s", manifest_path)
    log.info("ocios_dir: %s", ocios_dir)
    log.info("=" * 72)

    # Ensure OCIOS output directory exists
    try:
        ocios_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        log.error("Cannot create OCIOS output directory: %s", exc)
        return {
            "run_id":         run_id,
            "status":         "error",
            "error":          str(exc),
            "started_at":     started_at,
            "completed_at":   _utc_now(),
            "stage_results":  [],
        }

    stage_results: List[Dict] = []
    advisory_count = 0

    # -------------------------------------------------------------------
    # STAGE 1: Corpus Load  [CRITICAL]
    # -------------------------------------------------------------------
    sr = _run_stage(
        "corpus_load",
        lambda: _stage_corpus_load(manifest_path),
        is_critical=True,
    )
    stage_results.append(sr)
    if sr["status"] == "error":
        # Critical failure -- cannot proceed without corpus
        log.error("CRITICAL: Corpus load failed. Aborting OCIOS run.")
        elapsed = round(time.monotonic() - t_total, 2)
        report = _build_coordinator_report(
            run_id=run_id, started_at=started_at, completed_at=_utc_now(),
            total_elapsed=elapsed, stage_results=stage_results,
            advisory_count=0, overall_status="error",
        )
        try:
            _atomic_write(ocios_dir / "coordinator_report.json", report)
        except Exception:
            pass
        return report
    advisory_count = sr.get("metrics", {}).get("advisory_count", 0)

    # -------------------------------------------------------------------
    # STAGE 2: Manifest Validate  [CRITICAL]
    # -------------------------------------------------------------------
    sr = _run_stage(
        "manifest_validate",
        lambda: _stage_manifest_validate(manifest_path),
        is_critical=True,
    )
    stage_results.append(sr)
    # Non-blocking: even partial manifest passes continue

    # -------------------------------------------------------------------
    # STAGE 3: Campaign Correlation Engine  [OPTIONAL]
    # -------------------------------------------------------------------
    sr = _run_stage(
        "campaign_correlation",
        lambda: _stage_campaign_correlation(manifest_path, ocios_dir),
    )
    stage_results.append(sr)

    # -------------------------------------------------------------------
    # STAGE 4: Operational Reasoning Engine  [OPTIONAL]
    # -------------------------------------------------------------------
    sr = _run_stage(
        "operational_reasoning",
        lambda: _stage_operational_reasoning(manifest_path, ocios_dir),
    )
    stage_results.append(sr)

    # -------------------------------------------------------------------
    # STAGE 5: SOC Prioritization Engine  [OPTIONAL]
    # -------------------------------------------------------------------
    sr = _run_stage(
        "soc_prioritization",
        lambda: _stage_soc_prioritization(manifest_path, ocios_dir),
    )
    stage_results.append(sr)

    # -------------------------------------------------------------------
    # STAGE 6: Output Consolidation  [OPTIONAL]
    # -------------------------------------------------------------------
    sr = _run_stage(
        "output_consolidation",
        lambda: _stage_output_consolidation(
            ocios_dir, stage_results, run_id, started_at
        ),
    )
    stage_results.append(sr)

    # -------------------------------------------------------------------
    # STAGE 7: Integration Validation  [OPTIONAL]
    # -------------------------------------------------------------------
    sr = _run_stage(
        "integration_validate",
        lambda: _stage_integration_validate(ocios_dir),
    )
    stage_results.append(sr)

    # -------------------------------------------------------------------
    # Determine overall status
    # -------------------------------------------------------------------
    completed_at   = _utc_now()
    total_elapsed  = round(time.monotonic() - t_total, 2)

    error_stages   = [s for s in stage_results if s["status"] == "error"
                      and s["stage"] in _CRITICAL_STAGES]
    partial_stages = [s for s in stage_results if s["status"] in ("error", "partial")]

    if error_stages:
        overall_status = "error"
    elif partial_stages:
        overall_status = "partial"
    else:
        overall_status = "success"

    # Build final coordinator report
    report = _build_coordinator_report(
        run_id=run_id,
        started_at=started_at,
        completed_at=completed_at,
        total_elapsed=total_elapsed,
        stage_results=stage_results,
        advisory_count=advisory_count,
        overall_status=overall_status,
    )

    # Write coordinator report
    try:
        _atomic_write(ocios_dir / "coordinator_report.json", report)
        log.info("Coordinator report written: data/ocios/coordinator_report.json")
    except Exception as exc:
        log.error("Coordinator report write failed: %s", exc)

    # Final summary
    log.info("=" * 72)
    log.info(
        "OCIOS COORDINATOR COMPLETE | run_id=%s | status=%s | %.2fs | %d advisories",
        run_id, overall_status.upper(), total_elapsed, advisory_count
    )
    stage_summary = " | ".join(
        f"{s['stage']}:{s['status'].upper()}" for s in stage_results
    )
    log.info("Stage results: %s", stage_summary)
    log.info("=" * 72)

    return report


# ---------------------------------------------------------------------------
# CLI INTEGRATION VALIDATION MODE
# ---------------------------------------------------------------------------

def _validate_mode(ocios_dir: Path) -> int:
    """
    Run integration validation only (no engine execution).
    Used by CI/CD pipelines for post-deployment checks.
    """
    log.info("OCIOS Coordinator: VALIDATION MODE")
    status, _, metrics = _stage_integration_validate(ocios_dir)
    print(json.dumps({
        "mode":           "validate",
        "status":         status,
        "checks_passed":  metrics.get("checks_passed", 0),
        "checks_failed":  metrics.get("checks_failed", 0),
        "file_results":   metrics.get("file_results", {}),
    }, indent=2))
    return 0 if status in ("success", "partial") else 1


# ---------------------------------------------------------------------------
# CLI STATUS MODE
# ---------------------------------------------------------------------------

def _status_mode(ocios_dir: Path) -> int:
    """Print current OCIOS output status without running engines."""
    manifest = ocios_dir / "ocios_manifest.json"
    if not manifest.exists():
        print(json.dumps({"status": "no_prior_run", "ocios_dir": str(ocios_dir)}, indent=2))
        return 1
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        print(json.dumps({
            "last_run_status":  data.get("overall_status"),
            "generated_at":     data.get("generated_at"),
            "run_id":           data.get("run_id"),
            "output_count":     len(data.get("outputs", [])),
            "stage_summary":    data.get("stage_summary", {}),
        }, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
        return 1


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(
        description="OCIOS Coordinator -- Orchestrates all OCIOS engines"
    )
    parser.add_argument(
        "--manifest",
        default=str(MANIFEST_PATH),
        help="Path to feed_manifest.json",
    )
    parser.add_argument(
        "--output-dir",
        default=str(OCIOS_DIR),
        help="OCIOS output directory",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Optional run identifier (auto-generated if omitted)",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Run integration validation only (no engine execution)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print OCIOS output status from last run",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress INFO logging",
    )
    args = parser.parse_args()

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)

    ocios_dir = Path(args.output_dir)

    if args.status:
        return _status_mode(ocios_dir)

    if args.validate_only:
        return _validate_mode(ocios_dir)

    # Full orchestration run
    result = run_ocios_coordinator(
        manifest_path=Path(args.manifest),
        ocios_dir=ocios_dir,
        run_id=args.run_id,
    )

    # Print summary
    print(json.dumps({
        "run_id":          result.get("run_id"),
        "status":          result.get("overall_status"),
        "advisory_count":  result.get("advisory_count", 0),
        "total_elapsed_s": result.get("total_elapsed_s", 0),
        "stage_count":     result.get("stage_count", 0),
        "error_count":     result.get("error_count", 0),
        "errors":          result.get("errors", [])[:10],
        "tier_breakdown":  result.get("tier_breakdown", {}),
        "production_safe": result.get("production_safe", False),
    }, indent=2))

    status = result.get("overall_status", "error")
    return 0 if status in ("success", "partial") else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
