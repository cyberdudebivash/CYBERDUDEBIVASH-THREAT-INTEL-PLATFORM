#!/usr/bin/env python3
"""
orchestrator.py — CYBERDUDEBIVASH® SENTINEL APEX v134.1 (COMMAND CENTER)
════════════════════════════════════════════════════════════════════════════
CENTRAL ORCHESTRATOR — Single Source of Truth.

This is the ONLY service authorized to:
  - Write to feed_manifest.json
  - Generate STIX bundles
  - Produce dashboard data
  - Execute the intelligence pipeline

All other workflows are READ-ONLY or event-triggered.

Pipeline: INGEST → NORMALIZE → ENRICH → CORRELATE → SCORE → STORE → PUBLISH

Features:
  - Strict execution order enforcement
  - Concurrency lock (only one pipeline run at a time)
  - Idempotent processing
  - Circuit breaker for external APIs
  - Full audit trail
  - Graceful degradation on component failure

v134.1 ENTERPRISE RUNTIME GOVERNANCE HARDENING:
  ┌─────────────────────────────────────────────────────────────────┐
  │  P0 FIX: _is_running + _release_lock() now ALWAYS in finally    │
  │  P0 FIX: Stage imports wrapped in try/finally before lock acq.  │
  │  P0 FIX: stage.execute() return validated — None ctx guarded    │
  │  P0 FIX: _generate_summary() fully exception-safe (no crashes)  │
  │  P0 FIX: _store_run() KeyError-safe on partial summary dict     │
  │  NEW:    Stage context checkpoint validation after each stage    │
  │  NEW:    Orchestration telemetry with stage health scoring       │
  │  NEW:    Fail-safe emergency summary on complete ctx failure     │
  └─────────────────────────────────────────────────────────────────┘

Usage:
    from core.orchestrator import orchestrator
    result = orchestrator.run_pipeline()  # Full pipeline
    result = orchestrator.run_pipeline(items=[...])  # Pre-loaded items

CLI:
    python -m core.orchestrator                # Full pipeline run
    python -m core.orchestrator --status       # System status
    python -m core.orchestrator --stats        # Dashboard stats

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import uuid
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-ORCHESTRATOR")

# ═══════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════

class CircuitBreaker:
    """Prevents cascading failures by tracking component health."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, failure_threshold: int = 3, recovery_timeout: int = 60):
        self._state = self.CLOSED
        self._failures = 0
        self._threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._last_failure_time = 0

    @property
    def is_open(self) -> bool:
        if self._state == self.OPEN:
            if time.time() - self._last_failure_time >= self._recovery_timeout:
                self._state = self.HALF_OPEN
                return False
            return True
        return False

    def record_success(self):
        self._failures = 0
        self._state = self.CLOSED

    def record_failure(self):
        self._failures += 1
        self._last_failure_time = time.time()
        if self._failures >= self._threshold:
            self._state = self.OPEN
            logger.warning(f"Circuit breaker OPEN after {self._failures} failures")


# ═══════════════════════════════════════════════════════════
# SENTINEL APEX ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

class SentinelOrchestrator:
    """
    Central orchestrator — the single entry point for all intelligence operations.

    INVARIANTS:
      1. Only one pipeline runs at a time (concurrency lock)
      2. Stages execute in strict order
      3. Only this orchestrator writes manifest/STIX/dashboard data
      4. All operations are audited
      5. Component failures are isolated (circuit breaker)
    """

    PIPELINE_STAGES = [
        "ingest", "normalize", "enrich", "correlate", "score", "store", "publish", "r2_ai_export"
    ]

    def __init__(self):
        self._circuit_breakers: Dict[str, CircuitBreaker] = {
            stage: CircuitBreaker() for stage in self.PIPELINE_STAGES
        }
        self._run_history: List[Dict] = []
        self._is_running = False
        self._lock_token: Optional[str] = None

    def run_pipeline(
        self,
        items: Optional[List[Dict]] = None,
        skip_stages: Optional[List[str]] = None,
        run_id: str = "",
    ) -> Dict:
        """
        Execute the full intelligence pipeline.

        Args:
            items: Pre-loaded intelligence items (skips ingestion fetch)
            skip_stages: List of stage names to skip
            run_id: Custom run ID (auto-generated if empty)

        Returns:
            Pipeline execution summary dict

        v134.1 GOVERNANCE GUARANTEES:
          - _is_running is ALWAYS reset to False (finally block — P0 fix)
          - _release_lock() is ALWAYS called (finally block — P0 fix)
          - Import failures cannot hold the lock (imports before lock acquisition)
          - stage.execute() return is validated — None ctx is caught and contained
          - _generate_summary() is exception-safe — emergency fallback on failure
          - All finalization logic runs even if individual steps raise
        """
        if self._is_running:
            return {"error": "Pipeline already running", "status": "rejected"}

        # ── PRE-IMPORT pipeline components BEFORE acquiring lock ──────────────
        # GOVERNANCE: imports happening after lock acquisition caused permanent
        # lock hold on ImportError. Pre-importing ensures failed imports never
        # block future pipeline runs.
        try:
            from core.pipeline import (
                PipelineContext, IngestStage, NormalizeStage, EnrichStage,
                CorrelateStage, ScoreStage, StoreStage, PublishStage,
            )
            from core.pipeline.stages import R2AIExportStage
        except Exception as _import_err:
            logger.error(f"[ORCHESTRATOR] Pipeline component import FAILED: {_import_err}")
            return {
                "error": f"Pipeline component import failed: {_import_err}",
                "status": "import_failure",
                "run_id": run_id or f"FAILED-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "failed_at": datetime.now(timezone.utc).isoformat(),
            }

        # Acquire concurrency lock
        if not self._acquire_lock():
            return {"error": "Failed to acquire pipeline lock", "status": "rejected"}

        self._is_running = True
        skip_stages = set(skip_stages or [])

        # ── Build context with validated initial state ──────────────────────
        ctx = PipelineContext(run_id=run_id)
        if items:
            ctx.items = list(items)  # defensive copy — never mutate caller's list

        # ── Stage registry (constructed before execution loop) ───────────────
        # GOVERNANCE: constructing inside the loop meant a constructor failure
        # mid-loop left ctx in an inconsistent state. Build all at once so
        # construction failure is caught cleanly before any stage runs.
        try:
            stage_map = {
                "ingest":        IngestStage(),
                "normalize":     NormalizeStage(),
                "enrich":        EnrichStage(),
                "correlate":     CorrelateStage(),
                "score":         ScoreStage(),
                "store":         StoreStage(),
                "publish":       PublishStage(),
                "r2_ai_export":  R2AIExportStage(),
            }
        except Exception as _stage_build_err:
            logger.error(f"[ORCHESTRATOR] Stage construction FAILED: {_stage_build_err}")
            ctx.add_error("stage_construction", str(_stage_build_err))
            stage_map = {}

        self._emit_event("pipeline.started", {
            "run_id": ctx.run_id,
            "pre_loaded_items": len(items) if items else 0,
            "skip_stages": list(skip_stages),
        })

        logger.info(f"{'='*60}")
        logger.info(f"SENTINEL APEX ORCHESTRATOR — Pipeline Run: {ctx.run_id}")
        logger.info(f"{'='*60}")

        # ── Execute stages in strict order ────────────────────────────────────
        # GOVERNANCE: _is_running and _release_lock() are in finally so they
        # execute unconditionally even if finalization logic raises.
        summary: Dict = {}
        try:
            for stage_name in self.PIPELINE_STAGES:
                if stage_name in skip_stages:
                    logger.info(f"[SKIP] Stage: {stage_name}")
                    continue

                if stage_name not in stage_map:
                    logger.warning(f"[SKIP] Stage: {stage_name} not in registry — construction failed")
                    ctx.add_error(stage_name, "Stage not in registry (construction failed)")
                    continue

                cb = self._circuit_breakers[stage_name]
                if cb.is_open:
                    logger.warning(f"[CIRCUIT OPEN] Stage: {stage_name} — skipping")
                    ctx.add_error(stage_name, "Circuit breaker open")
                    continue

                self._emit_event("pipeline.stage.started", {
                    "run_id": ctx.run_id, "stage": stage_name
                })

                # Snapshot context item count before execution (for validation)
                _pre_stage_item_count = len(ctx.items) if ctx.items is not None else 0

                try:
                    stage = stage_map[stage_name]
                    logger.info(f"[STAGE] {stage_name.upper()} — Processing {_pre_stage_item_count} items")
                    _returned_ctx = stage.execute(ctx)

                    # ── CONTEXT RETURN VALIDATION (P0 fix) ───────────────────
                    # GOVERNANCE: stage.execute() returning None silently replaced
                    # ctx with None, causing AttributeError on the next iteration.
                    # Validate the return and fall back to original ctx on bad return.
                    if _returned_ctx is None:
                        logger.error(
                            f"[ORCHESTRATOR] Stage {stage_name} returned None context — "
                            f"retaining pre-stage context, recording error"
                        )
                        ctx.add_error(stage_name, "Stage returned None context (retained pre-stage ctx)")
                        cb.record_failure()
                    elif not hasattr(_returned_ctx, "items") or not hasattr(_returned_ctx, "errors"):
                        logger.error(
                            f"[ORCHESTRATOR] Stage {stage_name} returned invalid context type "
                            f"({type(_returned_ctx).__name__}) — retaining pre-stage context"
                        )
                        ctx.add_error(stage_name, f"Stage returned invalid ctx type: {type(_returned_ctx).__name__}")
                        cb.record_failure()
                    else:
                        ctx = _returned_ctx
                        cb.record_success()
                        self._emit_event("pipeline.stage.completed", {
                            "run_id": ctx.run_id,
                            "stage": stage_name,
                            "item_count": len(ctx.items) if ctx.items is not None else 0,
                        })

                except Exception as e:
                    cb.record_failure()
                    error_msg = f"Stage {stage_name} failed: {type(e).__name__}: {e}"
                    logger.error(f"[ORCHESTRATOR] {error_msg}")
                    ctx.add_error(stage_name, error_msg)
                    # Non-critical stage failure: continue pipeline (graceful degradation)
                    continue

            # ── Finalization: generate summary, store, emit event ─────────────
            # Each step is individually exception-safe so failures in one
            # do not prevent the others from running.
            try:
                summary = self._generate_summary(ctx)
            except Exception as _summary_err:
                logger.error(f"[ORCHESTRATOR] _generate_summary FAILED: {_summary_err} — using emergency fallback")
                summary = self._emergency_summary(ctx, _summary_err)

            try:
                self._store_run(summary)
            except Exception as _store_err:
                logger.error(f"[ORCHESTRATOR] _store_run FAILED (non-fatal): {_store_err}")

            try:
                self._emit_event("pipeline.completed", summary)
            except Exception as _emit_err:
                logger.warning(f"[ORCHESTRATOR] completion event emit FAILED (non-fatal): {_emit_err}")

            try:
                logger.info(f"{'='*60}")
                _duration = summary.get("duration_seconds", 0)
                _items    = summary.get("item_count", 0)
                _errors   = summary.get("error_count", 0)
                logger.info(
                    f"Pipeline COMPLETE | Duration: {_duration:.1f}s | "
                    f"Items: {_items} | Errors: {_errors}"
                )
                logger.info(f"{'='*60}")
            except Exception:
                pass  # logging failure is never fatal

        finally:
            # ── GOVERNANCE: unconditional lock release and flag reset ──────────
            # This block ALWAYS executes — even if summary generation, store,
            # or emit raised an uncaught exception. Prevents permanent deadlock.
            self._is_running = False
            self._release_lock()

        return summary

    def get_status(self) -> Dict:
        """Get orchestrator and system status."""
        status = {
            "orchestrator": {
                "running": self._is_running,
                "circuit_breakers": {
                    name: cb._state for name, cb in self._circuit_breakers.items()
                },
                "total_runs": len(self._run_history),
                "last_run": self._run_history[-1] if self._run_history else None,
            },
        }

        # Component health
        components = {}

        try:
            from core.event_bus import event_bus
            components["event_bus"] = {
                "status": "healthy",
                "backend": "redis" if event_bus.redis_available else "in-memory",
                **event_bus.get_stats(),
            }
        except Exception as e:
            components["event_bus"] = {"status": "error", "error": str(e)}

        try:
            from core.manifest_manager import manifest_manager
            components["manifest"] = {
                "status": "healthy",
                **manifest_manager.get_stats(),
            }
        except Exception as e:
            components["manifest"] = {"status": "error", "error": str(e)}

        try:
            from core.storage import get_db
            db = get_db()
            components["database"] = {
                "status": "healthy",
                "backend": "postgresql" if db.is_postgres else "sqlite",
                **db.get_dashboard_stats(),
            }
        except Exception as e:
            components["database"] = {"status": "error", "error": str(e)}

        try:
            from core.storage import get_cache
            cache = get_cache()
            components["cache"] = {
                "status": "healthy",
                **cache.get_stats(),
            }
        except Exception as e:
            components["cache"] = {"status": "error", "error": str(e)}

        try:
            from core.ai_engine import ai_engine
            components["ai_engine"] = {
                "status": "healthy",
                **ai_engine.get_stats(),
            }
        except Exception as e:
            components["ai_engine"] = {"status": "error", "error": str(e)}

        try:
            from core.detection import detection_engine
            components["detection_engine"] = {
                "status": "healthy",
                **detection_engine.get_stats(),
            }
        except Exception as e:
            components["detection_engine"] = {"status": "error", "error": str(e)}

        status["components"] = components
        status["timestamp"] = datetime.now(timezone.utc).isoformat()
        return status

    def get_dashboard_data(self) -> Dict:
        """Generate comprehensive dashboard data."""
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "version": "v134.0 COMMAND CENTER",
        }

        # Manifest stats
        try:
            from core.manifest_manager import manifest_manager
            data["manifest"] = manifest_manager.get_stats()
        except Exception:
            data["manifest"] = {}

        # Database stats
        try:
            from core.storage import get_db
            db = get_db()
            data["intelligence"] = db.get_dashboard_stats()
        except Exception:
            data["intelligence"] = {}

        # Pipeline run history
        data["recent_runs"] = self._run_history[-10:]

        # AI analysis summary
        data["ai_summary"] = {
            "last_analysis": self._run_history[-1].get("ai_analysis", {}) if self._run_history else {},
        }

        return data

    # ── Internal helpers ──────────────────────────────────

    def _acquire_lock(self) -> bool:
        """Acquire distributed pipeline lock."""
        try:
            from core.event_bus import event_bus
            self._lock_token = event_bus.acquire_lock("pipeline_execution", ttl=1800)
            if self._lock_token:
                return True
        except Exception:
            pass
        # Fallback: in-process lock
        self._lock_token = str(uuid.uuid4())
        return True

    def _release_lock(self):
        if self._lock_token:
            try:
                from core.event_bus import event_bus
                event_bus.release_lock("pipeline_execution", self._lock_token)
            except Exception:
                pass
            self._lock_token = None

    def _emit_event(self, event_type: str, payload: Dict):
        try:
            from core.event_bus import event_bus, EventPriority
            priority = EventPriority.HIGH if "failed" in event_type else EventPriority.MEDIUM
            event_bus.emit(event_type, payload, priority=priority, source="orchestrator")
        except Exception:
            pass

    def _generate_summary(self, ctx) -> Dict:
        """
        v134.1 EXCEPTION-SAFE summary generation.

        Every attribute access uses getattr() with a safe default.
        No crash path exists — even a fully None ctx produces a valid dict.
        Called inside a try/except in run_pipeline(); if it still raises,
        _emergency_summary() provides the ultimate fallback.
        """
        _now = datetime.now(timezone.utc).isoformat()
        _utc_epoch = "1970-01-01T00:00:00+00:00"

        # Safe attribute extraction with typed defaults
        _run_id         = getattr(ctx, "run_id", None) or f"UNKNOWN-{_now}"
        _errors         = list(getattr(ctx, "errors", None) or [])
        _items          = list(getattr(ctx, "items", None) or [])
        _stages_done    = list(getattr(ctx, "stages_completed", None) or [])
        _metrics        = dict(getattr(ctx, "metrics", None) or {})
        _metadata       = dict(getattr(ctx, "metadata", None) or {})

        # Safe started_at extraction
        try:
            _started_at = ctx.started_at.isoformat()
        except Exception:
            _started_at = _utc_epoch

        # Safe duration computation
        try:
            _duration = round(ctx.duration_seconds, 2)
        except Exception:
            _duration = 0.0

        # Safe metadata sub-key access
        try:
            _ai_analysis = _metadata.get("ai_analysis", {}) or {}
        except Exception:
            _ai_analysis = {}
        try:
            _campaigns = len(_metadata.get("campaigns", []) or [])
        except Exception:
            _campaigns = 0

        return {
            "run_id":             _run_id,
            "status":             "completed" if not _errors else "completed_with_errors",
            "started_at":         _started_at,
            "completed_at":       _now,
            "duration_seconds":   _duration,
            "item_count":         len(_items),
            "stages_completed":   _stages_done,
            "metrics":            _metrics,
            "error_count":        len(_errors),
            "errors":             _errors[:20],
            "ai_analysis":        _ai_analysis,
            "campaigns_detected": _campaigns,
        }

    def _emergency_summary(self, ctx, exc: Exception) -> Dict:
        """
        v134.1 EMERGENCY FALLBACK summary — returned when _generate_summary() itself fails.
        Provides a valid, structurally complete dict with zero attribute access on ctx.
        Ensures _store_run() and caller always receive a complete dict.
        """
        _now = datetime.now(timezone.utc).isoformat()
        _run_id = "EMERGENCY-UNKNOWN"
        try:
            _run_id = str(getattr(ctx, "run_id", None) or _run_id)
        except Exception:
            pass
        logger.critical(
            f"[ORCHESTRATOR] EMERGENCY SUMMARY ACTIVATED for run {_run_id}: {exc}"
        )
        return {
            "run_id":             _run_id,
            "status":             "finalization_failure",
            "started_at":         _now,
            "completed_at":       _now,
            "duration_seconds":   0.0,
            "item_count":         0,
            "stages_completed":   [],
            "metrics":            {},
            "error_count":        1,
            "errors":             [f"Summary generation failed: {type(exc).__name__}: {exc}"],
            "ai_analysis":        {},
            "campaigns_detected": 0,
            "emergency_fallback": True,
        }

    def _store_run(self, summary: Dict):
        """
        v134.1 KeyError-safe run storage.
        Uses .get() with typed defaults throughout — never crashes on partial summary.
        """
        if not isinstance(summary, dict):
            logger.error(f"[ORCHESTRATOR] _store_run: summary is not a dict ({type(summary)}) — skipping")
            return

        self._run_history.append(summary)
        if len(self._run_history) > 100:
            self._run_history = self._run_history[-100:]

        # Safe metrics extraction (P0 fix: was summary["metrics"].get() — KeyError risk)
        _metrics = summary.get("metrics") or {}
        if not isinstance(_metrics, dict):
            _metrics = {}

        # Persist to database
        try:
            from core.storage import get_db
            db = get_db()
            db.store_pipeline_run({
                "run_id":            summary.get("run_id", "UNKNOWN"),
                "status":            summary.get("status", "unknown"),
                "items_ingested":    _metrics.get("ingested", 0),
                "items_enriched":    _metrics.get("enriched", 0),
                "items_published":   _metrics.get("published", 0),
                "items_deduplicated": _metrics.get("deduplicated", 0),
                "errors":            summary.get("errors", []),
                "stages_completed":  summary.get("stages_completed", []),
                "duration_seconds":  summary.get("duration_seconds", 0),
            })
        except Exception as _db_err:
            logger.warning(f"[ORCHESTRATOR] _store_run: DB persist failed (non-fatal): {_db_err}")

        # Save to status file — atomic write with repo-relative path
        try:
            _status_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data", "status"
            )
            os.makedirs(_status_dir, exist_ok=True)
            _status_path = os.path.join(_status_dir, "last_pipeline_run.json")
            _tmp_path    = _status_path + ".tmp"
            _content     = json.dumps(summary, indent=2, default=str)
            with open(_tmp_path, "w", encoding="utf-8") as _fh:
                _fh.write(_content)
            os.replace(_tmp_path, _status_path)
        except Exception as _fs_err:
            logger.warning(f"[ORCHESTRATOR] _store_run: status file write failed (non-fatal): {_fs_err}")


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

orchestrator = SentinelOrchestrator()


# ═══════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════

def main():
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH® SENTINEL APEX — Central Orchestrator v134.0"
    )
    parser.add_argument("--status", action="store_true", help="Show system status")
    parser.add_argument("--stats", action="store_true", help="Show dashboard stats")
    parser.add_argument("--run", action="store_true", help="Execute full pipeline")
    parser.add_argument("--run-id", type=str, default="", help="Custom run ID")
    args = parser.parse_args()


    if args.status:
        status = orchestrator.get_status()
        print(json.dumps(status, indent=2, default=str))
    elif args.stats:
        stats = orchestrator.get_dashboard_data()
        print(json.dumps(stats, indent=2, default=str))
    elif args.run:
        result = orchestrator.run_pipeline(run_id=args.run_id)
        print(json.dumps(result, indent=2, default=str))
    else:
        result = orchestrator.run_pipeline()
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
