#!/usr/bin/env python3
"""
<<<<<<< HEAD
orchestrator.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0 (COMMAND CENTER)
=======
orchestrator.py — CYBERDUDEBIVASH® SENTINEL APEX v64.0 (COMMAND CENTER)
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
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
<<<<<<< HEAD
  - Circuit breaker for external APIs
  - Full audit trail
  - Graceful degradation on component failure
=======
  - Per-stage retry with exponential backoff
  - Circuit breaker for external APIs
  - Full audit trail with observability metrics
  - Graceful degradation on component failure
  - Dashboard sync signaling system
>>>>>>> claude/ai-threat-intelligence-system-eFwfT

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

<<<<<<< HEAD
=======
PLATFORM_VERSION = "v64.0"

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
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
<<<<<<< HEAD
=======
      6. Each stage retries up to MAX_STAGE_RETRIES on transient failure
      7. Dashboard sync signal updated after every successful run
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
    """

    PIPELINE_STAGES = [
        "ingest", "normalize", "enrich", "correlate", "score", "store", "publish"
    ]

<<<<<<< HEAD
=======
    MAX_STAGE_RETRIES = 2
    STAGE_RETRY_BACKOFF = [1.0, 3.0]  # seconds between retries

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
    def __init__(self):
        self._circuit_breakers: Dict[str, CircuitBreaker] = {
            stage: CircuitBreaker() for stage in self.PIPELINE_STAGES
        }
        self._run_history: List[Dict] = []
        self._is_running = False
        self._lock_token: Optional[str] = None
<<<<<<< HEAD
=======
        self._stage_timings: Dict[str, float] = {}
        self._last_sync_at: Optional[str] = None
        self._pipeline_state: str = "idle"  # idle | running | error
        self._total_items_processed: int = 0
        self._total_detections: int = 0
        self._error_count: int = 0
>>>>>>> claude/ai-threat-intelligence-system-eFwfT

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
        """
        if self._is_running:
            return {"error": "Pipeline already running", "status": "rejected"}

        # Acquire concurrency lock
        if not self._acquire_lock():
            return {"error": "Failed to acquire pipeline lock", "status": "rejected"}

        self._is_running = True
<<<<<<< HEAD
=======
        self._pipeline_state = "running"
        self._stage_timings = {}
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        skip_stages = set(skip_stages or [])

        # Import pipeline components
        from core.pipeline import (
            PipelineContext, IngestStage, NormalizeStage, EnrichStage,
            CorrelateStage, ScoreStage, StoreStage, PublishStage,
        )

        # Build context
        ctx = PipelineContext(run_id=run_id)
        if items:
            ctx.items = items

<<<<<<< HEAD
=======
        # Allow test manifest injection for test isolation
        if hasattr(self, '_test_manifest_manager'):
            ctx.metadata["_test_manifest_manager"] = self._test_manifest_manager

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        # Stage registry
        stage_map = {
            "ingest": IngestStage(),
            "normalize": NormalizeStage(),
            "enrich": EnrichStage(),
            "correlate": CorrelateStage(),
            "score": ScoreStage(),
            "store": StoreStage(),
            "publish": PublishStage(),
        }

        # Emit pipeline start event
        self._emit_event("pipeline.started", {
            "run_id": ctx.run_id,
            "pre_loaded_items": len(items) if items else 0,
            "skip_stages": list(skip_stages),
        })

        logger.info(f"{'='*60}")
<<<<<<< HEAD
        logger.info(f"SENTINEL APEX ORCHESTRATOR — Pipeline Run: {ctx.run_id}")
        logger.info(f"{'='*60}")

        # Execute stages in strict order
=======
        logger.info(f"SENTINEL APEX ORCHESTRATOR {PLATFORM_VERSION} — Pipeline Run: {ctx.run_id}")
        logger.info(f"{'='*60}")

        # Execute stages in strict order with retry
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        for stage_name in self.PIPELINE_STAGES:
            if stage_name in skip_stages:
                logger.info(f"[SKIP] Stage: {stage_name}")
                continue

            cb = self._circuit_breakers[stage_name]
            if cb.is_open:
                logger.warning(f"[CIRCUIT OPEN] Stage: {stage_name} — skipping")
                ctx.add_error(stage_name, "Circuit breaker open")
                continue

            self._emit_event("pipeline.stage.started", {
                "run_id": ctx.run_id, "stage": stage_name
            })

<<<<<<< HEAD
            try:
                stage = stage_map[stage_name]
                logger.info(f"[STAGE] {stage_name.upper()} — Processing {len(ctx.items)} items")
                ctx = stage.execute(ctx)
                cb.record_success()

                self._emit_event("pipeline.stage.completed", {
                    "run_id": ctx.run_id,
                    "stage": stage_name,
                    "item_count": len(ctx.items),
                })

            except Exception as e:
                cb.record_failure()
                error_msg = f"Stage {stage_name} failed: {e}"
                logger.error(error_msg)
                ctx.add_error(stage_name, str(e))

=======
            stage_start = time.time()
            executed = False

            # Retry loop for transient failures
            for attempt in range(1 + self.MAX_STAGE_RETRIES):
                try:
                    stage = stage_map[stage_name]
                    logger.info(
                        f"[STAGE] {stage_name.upper()} — Processing {len(ctx.items)} items"
                        + (f" (retry {attempt})" if attempt > 0 else "")
                    )
                    ctx = stage.execute(ctx)
                    cb.record_success()
                    executed = True

                    stage_duration = round(time.time() - stage_start, 3)
                    self._stage_timings[stage_name] = stage_duration

                    self._emit_event("pipeline.stage.completed", {
                        "run_id": ctx.run_id,
                        "stage": stage_name,
                        "item_count": len(ctx.items),
                        "duration_seconds": stage_duration,
                        "attempt": attempt + 1,
                    })
                    break  # Stage succeeded

                except Exception as e:
                    if attempt < self.MAX_STAGE_RETRIES:
                        backoff = self.STAGE_RETRY_BACKOFF[min(attempt, len(self.STAGE_RETRY_BACKOFF) - 1)]
                        logger.warning(
                            f"[RETRY] Stage {stage_name} attempt {attempt + 1} failed: {e} "
                            f"— retrying in {backoff}s"
                        )
                        time.sleep(backoff)
                    else:
                        cb.record_failure()
                        error_msg = f"Stage {stage_name} failed after {attempt + 1} attempts: {e}"
                        logger.error(error_msg)
                        ctx.add_error(stage_name, str(e))
                        self._error_count += 1

            if not executed:
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
                # Continue pipeline despite stage failure (graceful degradation)
                continue

        # Generate summary
        summary = self._generate_summary(ctx)

        # Store pipeline run
        self._store_run(summary)

<<<<<<< HEAD
=======
        # Update sync signal
        self._update_sync_signal(summary)

        # Update cumulative metrics
        self._total_items_processed += len(ctx.items)
        self._total_detections += ctx.metrics.get("detections", 0)

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        # Emit completion event
        self._emit_event("pipeline.completed", summary)

        # Release lock
        self._is_running = False
<<<<<<< HEAD
=======
        self._pipeline_state = "idle" if not ctx.errors else "error"
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        self._release_lock()

        logger.info(f"{'='*60}")
        logger.info(f"Pipeline COMPLETE | Duration: {ctx.duration_seconds:.1f}s | Items: {len(ctx.items)}")
        logger.info(f"{'='*60}")

        return summary

    def get_status(self) -> Dict:
<<<<<<< HEAD
        """Get orchestrator and system status."""
        status = {
            "orchestrator": {
                "running": self._is_running,
=======
        """Get orchestrator and system status with full observability."""
        status = {
            "orchestrator": {
                "running": self._is_running,
                "pipeline_state": self._pipeline_state,
                "version": PLATFORM_VERSION,
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
                "circuit_breakers": {
                    name: cb._state for name, cb in self._circuit_breakers.items()
                },
                "total_runs": len(self._run_history),
                "last_run": self._run_history[-1] if self._run_history else None,
<<<<<<< HEAD
=======
                "last_sync_at": self._last_sync_at,
                "total_items_processed": self._total_items_processed,
                "total_detections": self._total_detections,
                "error_count": self._error_count,
                "stage_timings": self._stage_timings,
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
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

<<<<<<< HEAD
    def get_dashboard_data(self) -> Dict:
        """Generate comprehensive dashboard data."""
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "version": "v47.0 COMMAND CENTER",
=======
    def get_sync_signal(self) -> Dict:
        """Get the current dashboard sync signal for frontend polling."""
        return {
            "last_sync_at": self._last_sync_at,
            "pipeline_state": self._pipeline_state,
            "is_running": self._is_running,
            "total_runs": len(self._run_history),
            "total_items_processed": self._total_items_processed,
            "total_detections": self._total_detections,
            "error_count": self._error_count,
            "stage_timings": self._stage_timings,
            "last_run_summary": self._run_history[-1] if self._run_history else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_dashboard_data(self) -> Dict:
        """Generate comprehensive dashboard data with sync signal."""
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "CYBERDUDEBIVASH SENTINEL APEX",
            "version": f"{PLATFORM_VERSION} COMMAND CENTER",
            "sync_signal": self.get_sync_signal(),
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
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
        return {
            "run_id": ctx.run_id,
            "status": "completed" if not ctx.errors else "completed_with_errors",
            "started_at": ctx.started_at.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(ctx.duration_seconds, 2),
            "item_count": len(ctx.items),
            "stages_completed": ctx.stages_completed,
            "metrics": ctx.metrics,
            "error_count": len(ctx.errors),
            "errors": ctx.errors[:20],
            "ai_analysis": ctx.metadata.get("ai_analysis", {}),
            "campaigns_detected": len(ctx.metadata.get("campaigns", [])),
<<<<<<< HEAD
        }

=======
            "stage_timings": dict(self._stage_timings),
            "version": PLATFORM_VERSION,
        }

    def _update_sync_signal(self, summary: Dict):
        """Update the dashboard sync signal after a pipeline run."""
        self._last_sync_at = datetime.now(timezone.utc).isoformat()
        try:
            sync_data = {
                "last_sync_at": self._last_sync_at,
                "last_run_id": summary.get("run_id", ""),
                "item_count": summary.get("item_count", 0),
                "status": summary.get("status", "unknown"),
                "duration_seconds": summary.get("duration_seconds", 0),
                "pipeline_state": "idle" if summary.get("error_count", 0) == 0 else "error",
                "total_items_processed": self._total_items_processed,
                "total_detections": self._total_detections,
                "stage_timings": summary.get("stage_timings", {}),
            }
            os.makedirs("data/status", exist_ok=True)
            with open("data/status/sync_signal.json", "w") as f:
                json.dump(sync_data, f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"Sync signal write failed (non-fatal): {e}")

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
    def _store_run(self, summary: Dict):
        self._run_history.append(summary)
        if len(self._run_history) > 100:
            self._run_history = self._run_history[-100:]

        # Persist to database
        try:
            from core.storage import get_db
            db = get_db()
            db.store_pipeline_run({
                "run_id": summary["run_id"],
                "status": summary["status"],
                "items_ingested": summary["metrics"].get("ingested", 0),
                "items_enriched": summary["metrics"].get("enriched", 0),
                "items_published": summary["metrics"].get("published", 0),
                "items_deduplicated": summary["metrics"].get("deduplicated", 0),
                "errors": summary.get("errors", []),
                "stages_completed": summary.get("stages_completed", []),
                "duration_seconds": summary.get("duration_seconds", 0),
            })
        except Exception:
            pass

        # Save to status file
        try:
            os.makedirs("data/status", exist_ok=True)
            with open("data/status/last_pipeline_run.json", "w") as f:
                json.dump(summary, f, indent=2, default=str)
        except Exception:
            pass


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
<<<<<<< HEAD
        description="CYBERDUDEBIVASH® SENTINEL APEX — Central Orchestrator v47.0"
=======
        description=f"CYBERDUDEBIVASH® SENTINEL APEX — Central Orchestrator {PLATFORM_VERSION}"
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
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
        # Default: run pipeline
        result = orchestrator.run_pipeline()
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
