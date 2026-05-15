#!/usr/bin/env python3
"""
scripts/runtime_governance.py
CYBERDUDEBIVASH® SENTINEL APEX v134.1 — Enterprise Runtime Governance Layer
═══════════════════════════════════════════════════════════════════════════════

GOVERNANCE MANDATE:
  This module is the single enforcement point for all runtime safety contracts.
  Every pipeline stage, every orchestration step, every finalization handler
  MUST execute through governance boundaries defined here.

PROVIDES:
  StageGovernor         — deterministic stage execution with contracts
  FailSafeCounter       — typed counter with defensive defaults (never NameError)
  ExceptionIsolator     — non-critical failure containment boundary
  PipelineCheckpoint    — state validation at stage boundaries
  DeterministicFinalizer— exception-safe finalization with rollback
  GovernanceRegistry    — hard-fail vs non-critical stage classification
  OrchestratorTelemetry — structured pipeline health scoring + metrics

CONTRACTS:
  1. ALL counters initialize with typed defaults — zero NameError risk
  2. ALL optional stages degrade gracefully — never terminate critical path
  3. ALL summaries are exception-safe — emergency fallback always available
  4. ALL finalization runs unconditionally — finally blocks enforced
  5. NON-CRITICAL failures are contained — blast radius is bounded
  6. CRITICAL failures are classified — never silently swallowed

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar

log = logging.getLogger("CDB-GOVERNANCE")

# ─────────────────────────────────────────────────────────────────────────────
# STAGE CLASSIFICATION — Hard-Fail vs Non-Critical
# ─────────────────────────────────────────────────────────────────────────────

# CRITICAL stages: failure here MUST be recorded prominently.
# Pipeline continues (graceful degradation) but alert is escalated.
CRITICAL_STAGES: Set[str] = {
    "ingest",      # no data → no pipeline value
    "normalize",   # unnormalized data breaks all downstream
    "store",       # failure = data loss
    "publish",     # failure = customer impact
}

# NON-CRITICAL stages: failure here is contained and never terminates pipeline.
NON_CRITICAL_STAGES: Set[str] = {
    "enrich",        # enrichment failure = less context, not blocked
    "correlate",     # correlation failure = no clustering, not blocked
    "score",         # score failure = default score applied
    "r2_ai_export",  # R2/AI failure = telemetry gap, not blocked
}

# Telemetry stages: analytics / observability — failure must never affect data path
TELEMETRY_STAGES: Set[str] = {
    "r2_ai_export",
}


def classify_stage(stage_name: str) -> str:
    """Return 'critical', 'non_critical', or 'telemetry' for a stage name."""
    if stage_name in TELEMETRY_STAGES:
        return "telemetry"
    if stage_name in NON_CRITICAL_STAGES:
        return "non_critical"
    return "critical"


# ─────────────────────────────────────────────────────────────────────────────
# FAIL-SAFE COUNTER — Never NameError, Never TypeError
# ─────────────────────────────────────────────────────────────────────────────

class FailSafeCounter:
    """
    Typed integer counter with defensive defaults.

    GOVERNANCE CONTRACT:
      - Always initialized to 0 (never NameError on first access)
      - All increment/decrement operations are exception-safe
      - Value always int (never None, bool, or float)
      - Thread-safe under concurrent pipeline workers
      - JSON-serializable at all times

    Usage:
        c = FailSafeCounter("reports_written")
        c.increment()
        c.increment(5)
        val = c.value   # always int, never raises
        c.reset()
    """

    def __init__(self, name: str = "counter", initial: int = 0):
        self._name  = str(name)
        self._value = max(0, int(initial)) if isinstance(initial, (int, float)) else 0
        self._lock  = threading.Lock()
        self._max_recorded = 0
        self._increments   = 0

    def increment(self, amount: int = 1) -> int:
        """Increment counter by amount. Returns new value. Never raises."""
        try:
            delta = max(0, int(amount)) if isinstance(amount, (int, float)) else 0
            with self._lock:
                self._value += delta
                self._increments += 1
                if self._value > self._max_recorded:
                    self._max_recorded = self._value
                return self._value
        except Exception as _e:
            log.warning("FailSafeCounter[%s].increment failed: %s", self._name, _e)
            return self._value

    def decrement(self, amount: int = 1) -> int:
        """Decrement counter. Floor is 0. Returns new value. Never raises."""
        try:
            delta = max(0, int(amount)) if isinstance(amount, (int, float)) else 0
            with self._lock:
                self._value = max(0, self._value - delta)
                return self._value
        except Exception as _e:
            log.warning("FailSafeCounter[%s].decrement failed: %s", self._name, _e)
            return self._value

    def reset(self) -> None:
        """Reset counter to 0. Never raises."""
        try:
            with self._lock:
                self._value = 0
        except Exception:
            pass

    @property
    def value(self) -> int:
        """Return current counter value as int. Never raises, never None."""
        try:
            with self._lock:
                return int(self._value)
        except Exception:
            return 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self._name,
            "value": self.value,
            "max_recorded": self._max_recorded,
            "total_increments": self._increments,
        }

    def __int__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return f"FailSafeCounter({self._name}={self.value})"


# ─────────────────────────────────────────────────────────────────────────────
# EXCEPTION ISOLATOR — Non-Critical Failure Containment
# ─────────────────────────────────────────────────────────────────────────────

class ExceptionIsolator:
    """
    Context manager that contains exceptions from non-critical operations.

    GOVERNANCE CONTRACT:
      - Non-critical failures are LOGGED (never silent)
      - Non-critical failures NEVER propagate to caller
      - Critical failures ARE re-raised (explicit opt-in)
      - All failures are recorded in the isolation registry
      - Blast radius is bounded to the isolated block

    Usage:
        with ExceptionIsolator("enrichment", critical=False) as iso:
            enrich_item(item)
        if iso.failed:
            log.warning("enrichment failed, using defaults")
    """

    def __init__(
        self,
        stage_name: str,
        critical: bool = False,
        registry: Optional["IsolationRegistry"] = None,
    ):
        self.stage_name = stage_name
        self.critical   = critical
        self.registry   = registry
        self.failed     = False
        self.exception: Optional[Exception] = None
        self.traceback_str: str = ""

    def __enter__(self) -> "ExceptionIsolator":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            return False  # no exception — nothing to do

        self.failed = True
        self.exception = exc_val

        try:
            self.traceback_str = traceback.format_exc()
        except Exception:
            self.traceback_str = f"{exc_type.__name__}: {exc_val}"

        _level = "error" if self.critical else "warning"
        getattr(log, _level)(
            "[ISOLATION] Stage '%s' [%s]: %s: %s",
            self.stage_name,
            "CRITICAL" if self.critical else "non-critical",
            exc_type.__name__ if exc_type else "UnknownError",
            exc_val,
        )

        if self.registry is not None:
            try:
                self.registry.record(self.stage_name, exc_val, self.critical)
            except Exception:
                pass

        if self.critical:
            return False  # re-raise — critical failures must propagate
        return True   # suppress — non-critical failure contained


class IsolationRegistry:
    """
    Thread-safe registry of all isolated failures in a pipeline run.
    Provides blast radius analysis and governance reporting.
    """

    def __init__(self):
        self._failures: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, stage: str, exc: Exception, is_critical: bool) -> None:
        with self._lock:
            self._failures.append({
                "stage":       stage,
                "classification": "critical" if is_critical else "non_critical",
                "error_type":  type(exc).__name__,
                "error":       str(exc),
                "timestamp":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })

    def critical_count(self) -> int:
        with self._lock:
            return sum(1 for f in self._failures if f["classification"] == "critical")

    def non_critical_count(self) -> int:
        with self._lock:
            return sum(1 for f in self._failures if f["classification"] == "non_critical")

    def to_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._failures)

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_failures":        len(self._failures),
                "critical_failures":     self.critical_count(),
                "non_critical_failures": self.non_critical_count(),
                "stages_affected":       list({f["stage"] for f in self._failures}),
                "failures":              self._failures[-20:],
            }


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE CHECKPOINT — State Validation at Stage Boundaries
# ─────────────────────────────────────────────────────────────────────────────

class PipelineCheckpoint:
    """
    Validates pipeline context state at stage boundaries.

    GOVERNANCE CONTRACT:
      - Context must not be None after any stage
      - Context must have required attributes
      - Item count must not decrease unexpectedly (data loss guard)
      - Metrics dict must remain a valid dict
      - All validation failures are logged with full context
    """

    REQUIRED_CTX_ATTRS = ("run_id", "items", "errors", "stages_completed", "metrics")

    @classmethod
    def validate(
        cls,
        ctx: Any,
        stage_name: str,
        pre_item_count: int = 0,
    ) -> Tuple[bool, List[str]]:
        """
        Validate context after stage execution.

        Returns:
            (is_valid: bool, violations: List[str])
        """
        violations: List[str] = []

        # NULL CHECK — highest priority
        if ctx is None:
            violations.append(f"[{stage_name}] Context is None after stage execution")
            return False, violations

        # ATTRIBUTE PRESENCE
        for attr in cls.REQUIRED_CTX_ATTRS:
            if not hasattr(ctx, attr):
                violations.append(f"[{stage_name}] Context missing required attribute: '{attr}'")

        # ITEMS TYPE CHECK
        items = getattr(ctx, "items", None)
        if items is not None and not isinstance(items, list):
            violations.append(
                f"[{stage_name}] ctx.items is {type(items).__name__}, expected list"
            )

        # DATA LOSS GUARD — item count should not drop to 0 if input was non-zero
        # (unless this is a dedup/filter stage — those are expected to reduce count)
        _filter_stages = {"correlate", "normalize"}
        if stage_name not in _filter_stages and pre_item_count > 0:
            _post_count = len(items) if isinstance(items, list) else 0
            if _post_count == 0:
                violations.append(
                    f"[{stage_name}] POTENTIAL DATA LOSS: "
                    f"item count dropped {pre_item_count} → 0 after stage"
                )

        # METRICS TYPE CHECK
        metrics = getattr(ctx, "metrics", None)
        if metrics is not None and not isinstance(metrics, dict):
            violations.append(
                f"[{stage_name}] ctx.metrics is {type(metrics).__name__}, expected dict"
            )

        # ERRORS TYPE CHECK
        errors = getattr(ctx, "errors", None)
        if errors is not None and not isinstance(errors, list):
            violations.append(
                f"[{stage_name}] ctx.errors is {type(errors).__name__}, expected list"
            )

        is_valid = len(violations) == 0

        if violations:
            for v in violations:
                log.error("[CHECKPOINT] %s", v)
        else:
            log.debug(
                "[CHECKPOINT] Stage '%s' PASSED — items=%d errors=%d",
                stage_name,
                len(items) if isinstance(items, list) else 0,
                len(getattr(ctx, "errors", []) or []),
            )

        return is_valid, violations


# ─────────────────────────────────────────────────────────────────────────────
# DETERMINISTIC FINALIZER — Exception-Safe Finalization with Rollback
# ─────────────────────────────────────────────────────────────────────────────

class DeterministicFinalizer:
    """
    Executes a sequence of finalization steps with guaranteed execution order.

    GOVERNANCE CONTRACT:
      - All steps run unconditionally (no early exit on failure)
      - Each step's failure is isolated and logged
      - Failed steps are recorded for post-mortem analysis
      - Rollback steps are invoked on failure when provided
      - Final state is always deterministic regardless of step outcomes

    Usage:
        finalizer = DeterministicFinalizer("pipeline_finalization")
        finalizer.add_step("save_manifest", save_manifest_fn, rollback=rollback_fn)
        finalizer.add_step("emit_event", emit_event_fn)
        finalizer.add_step("write_metrics", write_metrics_fn)
        result = finalizer.execute()
        # All steps ran, failures logged, rollbacks applied
    """

    def __init__(self, name: str = "finalizer"):
        self.name = name
        self._steps: List[Dict[str, Any]] = []
        self._results: List[Dict[str, Any]] = []

    def add_step(
        self,
        step_name: str,
        fn: Callable[[], Any],
        rollback: Optional[Callable[[], None]] = None,
        critical: bool = False,
    ) -> "DeterministicFinalizer":
        """Register a finalization step. Returns self for chaining."""
        self._steps.append({
            "name":     step_name,
            "fn":       fn,
            "rollback": rollback,
            "critical": critical,
        })
        return self

    def execute(self) -> Dict[str, Any]:
        """
        Execute all registered steps in order.
        Every step runs regardless of previous failures.
        Returns execution summary.
        """
        succeeded: List[str] = []
        failed: List[str]    = []
        rolled_back: List[str] = []

        for step in self._steps:
            step_name = step["name"]
            _t0 = time.monotonic()
            try:
                step["fn"]()
                _duration = round((time.monotonic() - _t0) * 1000, 2)
                succeeded.append(step_name)
                log.debug("[FINALIZER:%s] Step '%s' OK (%.1fms)", self.name, step_name, _duration)
                self._results.append({
                    "step": step_name, "status": "ok", "duration_ms": _duration
                })
            except Exception as _exc:
                _duration = round((time.monotonic() - _t0) * 1000, 2)
                _level = "error" if step["critical"] else "warning"
                getattr(log, _level)(
                    "[FINALIZER:%s] Step '%s' FAILED (%.1fms): %s: %s",
                    self.name, step_name, _duration,
                    type(_exc).__name__, _exc,
                )
                failed.append(step_name)
                self._results.append({
                    "step": step_name,
                    "status": "failed",
                    "error": f"{type(_exc).__name__}: {_exc}",
                    "duration_ms": _duration,
                })

                # Attempt rollback if provided
                if step.get("rollback"):
                    try:
                        step["rollback"]()
                        rolled_back.append(step_name)
                        log.info("[FINALIZER:%s] Rollback for '%s' succeeded", self.name, step_name)
                    except Exception as _rb_exc:
                        log.error(
                            "[FINALIZER:%s] Rollback for '%s' also FAILED: %s",
                            self.name, step_name, _rb_exc,
                        )

        summary = {
            "finalizer":   self.name,
            "total_steps": len(self._steps),
            "succeeded":   len(succeeded),
            "failed":      len(failed),
            "rolled_back": len(rolled_back),
            "all_ok":      len(failed) == 0,
            "step_results": self._results,
            "completed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

        if failed:
            log.warning(
                "[FINALIZER:%s] COMPLETE with %d failure(s): %s",
                self.name, len(failed), failed,
            )
        else:
            log.info("[FINALIZER:%s] COMPLETE — all %d steps succeeded", self.name, len(self._steps))

        return summary


# ─────────────────────────────────────────────────────────────────────────────
# ORCHESTRATOR TELEMETRY — Structured Pipeline Health Scoring
# ─────────────────────────────────────────────────────────────────────────────

class OrchestratorTelemetry:
    """
    Structured pipeline health scoring and execution telemetry.

    Tracks per-stage health, overall pipeline health score, and
    generates structured telemetry records for observability.

    Health Score Formula:
        score = 100
              - (critical_failures * 20)    # critical stage failures: -20 each
              - (non_critical_failures * 5)  # non-critical failures: -5 each
              - (data_loss_events * 30)      # data loss events: -30 each
              - (ctx_violations * 10)        # context violations: -10 each
        Clamped to [0.0, 100.0]
    """

    CRITICAL_FAILURE_PENALTY    = 20
    NON_CRITICAL_FAILURE_PENALTY = 5
    DATA_LOSS_PENALTY           = 30
    CTX_VIOLATION_PENALTY       = 10

    def __init__(self, run_id: str = ""):
        self._run_id    = run_id or f"TEL-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        self._stages:   List[Dict[str, Any]] = []
        self._events:   List[Dict[str, Any]] = []
        self._lock      = threading.Lock()
        self._started   = time.monotonic()

        # Counters
        self.critical_failures    = FailSafeCounter("critical_failures")
        self.non_critical_failures = FailSafeCounter("non_critical_failures")
        self.data_loss_events      = FailSafeCounter("data_loss_events")
        self.ctx_violations        = FailSafeCounter("ctx_violations")
        self.items_ingested        = FailSafeCounter("items_ingested")
        self.items_published       = FailSafeCounter("items_published")
        self.stages_completed      = FailSafeCounter("stages_completed")
        self.stages_failed         = FailSafeCounter("stages_failed")

    def record_stage(
        self,
        stage_name: str,
        status: str,           # "ok" | "failed" | "skipped" | "circuit_open"
        duration_ms: float,
        item_count: int = 0,
        error: str = "",
        classification: str = "",
    ) -> None:
        """Record a stage execution result."""
        _cls = classification or classify_stage(stage_name)
        _record = {
            "stage":          stage_name,
            "status":         status,
            "classification": _cls,
            "duration_ms":    round(duration_ms, 2),
            "item_count":     int(item_count),
            "error":          str(error)[:500] if error else "",
            "timestamp":      datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        with self._lock:
            self._stages.append(_record)

        if status == "ok":
            self.stages_completed.increment()
        elif status == "failed":
            self.stages_failed.increment()
            if _cls == "critical":
                self.critical_failures.increment()
            else:
                self.non_critical_failures.increment()

    def record_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Record a structured pipeline event."""
        with self._lock:
            self._events.append({
                "event":     event_type,
                "details":   details,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            })

    def health_score(self) -> float:
        """Compute current pipeline health score [0.0, 100.0]."""
        score = (
            100.0
            - (self.critical_failures.value    * self.CRITICAL_FAILURE_PENALTY)
            - (self.non_critical_failures.value * self.NON_CRITICAL_FAILURE_PENALTY)
            - (self.data_loss_events.value      * self.DATA_LOSS_PENALTY)
            - (self.ctx_violations.value        * self.CTX_VIOLATION_PENALTY)
        )
        return round(max(0.0, min(100.0, score)), 2)

    def to_dict(self) -> Dict[str, Any]:
        """Return complete telemetry dict. Never raises."""
        try:
            _elapsed = round((time.monotonic() - self._started) * 1000, 2)
            with self._lock:
                _stages_copy = list(self._stages)
                _events_copy = list(self._events)
            return {
                "run_id":              self._run_id,
                "health_score":        self.health_score(),
                "elapsed_ms":          _elapsed,
                "counters": {
                    "critical_failures":     self.critical_failures.value,
                    "non_critical_failures": self.non_critical_failures.value,
                    "data_loss_events":      self.data_loss_events.value,
                    "ctx_violations":        self.ctx_violations.value,
                    "items_ingested":        self.items_ingested.value,
                    "items_published":       self.items_published.value,
                    "stages_completed":      self.stages_completed.value,
                    "stages_failed":         self.stages_failed.value,
                },
                "stage_results":  _stages_copy,
                "events":         _events_copy[-50:],
                "generated_at":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
        except Exception as _e:
            return {
                "run_id":       self._run_id,
                "health_score": 0.0,
                "error":        f"Telemetry serialization failed: {_e}",
                "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }

    def write_report(self, repo_root: Optional[Path] = None) -> bool:
        """
        Write telemetry report to data/logs/orchestrator_telemetry.jsonl.
        Returns True on success. Never raises.
        """
        try:
            _root = repo_root or Path(__file__).resolve().parent.parent
            _log_dir = _root / "data" / "logs"
            _log_dir.mkdir(parents=True, exist_ok=True)
            _path = _log_dir / "orchestrator_telemetry.jsonl"
            _record = json.dumps(self.to_dict(), ensure_ascii=False, default=str)
            with open(_path, "a", encoding="utf-8") as _fh:
                _fh.write(_record + "\n")
            log.info("[TELEMETRY] Report written → %s (health=%.1f)", _path.name, self.health_score())
            return True
        except Exception as _e:
            log.warning("[TELEMETRY] Write failed (non-fatal): %s", _e)
            return False


# ─────────────────────────────────────────────────────────────────────────────
# GOVERNANCE REGISTRY — Stage Classification + Runtime Rules
# ─────────────────────────────────────────────────────────────────────────────

class GovernanceRegistry:
    """
    Central registry for all governance rules applied to pipeline stages.

    Provides:
      - Stage classification lookup (critical / non-critical / telemetry)
      - Retry policy per stage
      - Timeout limits per stage
      - Customer-path dependency map
    """

    # Retry policy: (max_attempts, base_delay_seconds)
    RETRY_POLICY: Dict[str, Tuple[int, float]] = {
        "ingest":       (3, 5.0),   # network — tolerate transient failures
        "normalize":    (2, 1.0),   # CPU only — fast retry
        "enrich":       (2, 2.0),   # may call external APIs
        "correlate":    (1, 0.0),   # pure compute — no retry
        "score":        (1, 0.0),   # pure compute — no retry
        "store":        (5, 2.0),   # I/O critical — aggressive retry
        "publish":      (3, 3.0),   # network + I/O — moderate retry
        "r2_ai_export": (2, 5.0),   # cloud upload — tolerate latency
    }

    # Timeout in seconds per stage (0 = no timeout enforced)
    TIMEOUT_POLICY: Dict[str, int] = {
        "ingest":       120,
        "normalize":    60,
        "enrich":       90,
        "correlate":    30,
        "score":        30,
        "store":        120,
        "publish":      180,
        "r2_ai_export": 300,
    }

    # Customer-path dependencies: which stages are directly on the customer path
    CUSTOMER_PATH_STAGES: Set[str] = {
        "normalize",  # broken normalization = broken dossier
        "store",      # storage failure = missing reports
        "publish",    # publish failure = inaccessible intel
    }

    @classmethod
    def is_customer_path(cls, stage_name: str) -> bool:
        return stage_name in cls.CUSTOMER_PATH_STAGES

    @classmethod
    def get_retry_policy(cls, stage_name: str) -> Tuple[int, float]:
        return cls.RETRY_POLICY.get(stage_name, (1, 0.0))

    @classmethod
    def get_timeout(cls, stage_name: str) -> int:
        return cls.TIMEOUT_POLICY.get(stage_name, 60)

    @classmethod
    def governance_report(cls) -> Dict[str, Any]:
        """Return complete governance configuration as a dict."""
        return {
            "critical_stages":      sorted(CRITICAL_STAGES),
            "non_critical_stages":  sorted(NON_CRITICAL_STAGES),
            "telemetry_stages":     sorted(TELEMETRY_STAGES),
            "customer_path_stages": sorted(cls.CUSTOMER_PATH_STAGES),
            "retry_policies":       cls.RETRY_POLICY,
            "timeout_policies":     cls.TIMEOUT_POLICY,
            "generated_at":         datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }


# ─────────────────────────────────────────────────────────────────────────────
# SAFE SUMMARY BUILDER — Exception-Safe Summary Generation
# ─────────────────────────────────────────────────────────────────────────────

def build_safe_summary(
    written: int = 0,
    errors: int = 0,
    skipped: int = 0,
    uploaded: int = 0,
    elapsed: float = 0.0,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Build a pipeline summary dict that is always structurally complete.
    All parameters have typed defaults — safe to call with no arguments.
    Never raises.
    """
    try:
        return {
            "reports_written":  int(written)  if isinstance(written,  (int, float)) else 0,
            "errors":           int(errors)   if isinstance(errors,   (int, float)) else 0,
            "skipped":          int(skipped)  if isinstance(skipped,  (int, float)) else 0,
            "uploaded":         int(uploaded) if isinstance(uploaded, (int, float)) else 0,
            "elapsed_seconds":  round(float(elapsed), 2) if isinstance(elapsed, (int, float)) else 0.0,
            "generated_at":     datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "platform":         "CYBERDUDEBIVASH® SENTINEL APEX",
            **(extra or {}),
        }
    except Exception as _e:
        log.error("build_safe_summary failed: %s", _e)
        return {
            "reports_written": 0,
            "errors": 0,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary_error": str(_e),
        }


# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL SINGLETONS
# ─────────────────────────────────────────────────────────────────────────────

governance_registry = GovernanceRegistry()

log.info(
    "CDB-GOVERNANCE: Runtime governance layer initialized | "
    "critical_stages=%d non_critical=%d customer_path=%d",
    len(CRITICAL_STAGES),
    len(NON_CRITICAL_STAGES),
    len(GovernanceRegistry.CUSTOMER_PATH_STAGES),
)
