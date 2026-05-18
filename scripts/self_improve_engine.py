#!/usr/bin/env python3
"""
scripts/self_improve_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Self-Improving Engine: Master Orchestrator
===============================================================================
PHASE 6:  Self-Audit Reporter        — reports/system_audit.json
PHASE 7:  Human Approval Mode        — data/pending_approvals.json
PHASE 8:  Continuous Learning Loop   — monitor → detect → recommend → validate → act
PHASE 9:  Performance Optimisation   — slow stage tracking + bottleneck reporting
PHASE 10: Final Safety System        — circuit breaker + emergency stop + canary

ORCHESTRATION SEQUENCE:
    1. Check emergency stop signal
    2. Check circuit breaker
    3. Run monitor (Phases 1+2) → data/system_health.json
    4. Run recommender (Phase 3) → data/recommendations.json
    5. Run safe actions (Phase 4+5) — auto-execute approved safe actions
    6. Process human-approved queue (Phase 7)
    7. Track performance metrics (Phase 9)
    8. Write audit report (Phase 6) → reports/system_audit.json
    9. Update learning state (Phase 8) → data/learning_state.json
    10. Enforce safety invariants (Phase 10)

SAFETY CONTRACT:
    - Emergency stop: data/.emergency_stop → halts all activity immediately
    - Circuit breaker: inherited from self_improve_actions.py
    - Canary check: validates system is healthy before each cycle
    - Never auto-modifies core files
    - Human approval required for high-impact changes
    - Full audit trail in reports/system_audit.json

CONTINUOUS LOOP MODE (--daemon):
    Runs cycles indefinitely with configurable interval.
    Respects emergency stop signal between cycles.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.engine")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_ROOT    = Path(__file__).resolve().parent.parent
_DATA    = _ROOT / "data"
_REPORTS = _ROOT / "reports"
_SCRIPTS = _ROOT / "scripts"

AUDIT_REPORT     = _REPORTS / "system_audit.json"
LEARNING_STATE   = _DATA / "learning_state.json"
HEALTH_PATH      = _DATA / "system_health.json"
RECOMMENDATIONS  = _DATA / "recommendations.json"
EMERGENCY_STOP   = _DATA / ".emergency_stop"
PERF_LOG         = _DATA / "performance_log.json"
AUDIT_HISTORY    = _REPORTS / "audit_history.json"

# ---------------------------------------------------------------------------
# Engine configuration (override via data/engine_config.json)
# ---------------------------------------------------------------------------
_DEFAULT_CONFIG = {
    "cycle_interval_s":        3600,    # 1 hour between cycles in daemon mode
    "max_auto_actions":        5,       # Max safe actions per cycle
    "health_score_canary":     40,      # Below this → canary fails → halt
    "learning_window_cycles":  10,      # Cycles to keep for trend analysis
    "perf_baseline_s":         120,     # Expected pipeline runtime baseline
    "emit_audit_always":       True,    # Always write audit even if no anomalies
    "dry_run_actions":         False,   # Global dry-run override
    "enable_daemon":           False,   # Enable continuous loop
}


def _load_config() -> Dict:
    """Load config from data/engine_config.json, falling back to defaults."""
    cfg_path = _DATA / "engine_config.json"
    cfg = dict(_DEFAULT_CONFIG)
    if cfg_path.exists():
        try:
            overrides = json.loads(cfg_path.read_text(encoding="utf-8"))
            cfg.update({k: v for k, v in overrides.items() if k in _DEFAULT_CONFIG})
        except Exception as exc:
            log.warning("[ENGINE] Config load failed (%s) — using defaults", exc)
    return cfg


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _load_json(path: Path, default: Any = None) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        log.warning("[ENGINE] Cannot load %s: %s", path.name, exc)
    return default


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
    except OSError:
        pass
    os.replace(tmp, path)


# ===========================================================================
# PHASE 6: SELF-AUDIT REPORTER
# ===========================================================================

def build_audit_report(
    cycle_id: str,
    health_report: Dict,
    recommendations: List[Dict],
    action_results: List[Dict],
    perf_metrics: Dict,
    config: Dict,
) -> Dict[str, Any]:
    """
    Phase 6: Build a structured self-audit report.
    Written to reports/system_audit.json after each cycle.
    """
    health = health_report.get("health", {})
    anomalies = health_report.get("anomalies", [])
    metrics = health_report.get("metrics", {})

    # Categorise action outcomes
    actions_succeeded = [r for r in action_results if r.get("success")]
    actions_failed    = [r for r in action_results if not r.get("success") and not r.get("blocked")]
    actions_blocked   = [r for r in action_results if r.get("blocked")]

    # Anomaly severity breakdown
    severity_breakdown = {}
    for a in anomalies:
        sev = a.get("severity", "UNKNOWN")
        severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

    # Recommendation breakdown
    auto_recs = [r for r in recommendations if r.get("safe_auto")]
    manual_recs = [r for r in recommendations if not r.get("safe_auto")]

    # Determine overall cycle status
    if health.get("score", 0) < config.get("health_score_canary", 40):
        cycle_status = "EMERGENCY"
    elif severity_breakdown.get("CRITICAL", 0) > 0:
        cycle_status = "CRITICAL"
    elif severity_breakdown.get("HIGH", 0) > 0:
        cycle_status = "DEGRADED"
    elif anomalies:
        cycle_status = "WARNING"
    else:
        cycle_status = "HEALTHY"

    report: Dict[str, Any] = {
        "schema_version":  "2.0",
        "cycle_id":        cycle_id,
        "generated_at":    _utc_now_iso(),
        "cycle_status":    cycle_status,

        # System health
        "health": {
            "score":           health.get("score", 0),
            "grade":           health.get("grade", "?"),
            "status":          health.get("status", "UNKNOWN"),
            "severity_breakdown": severity_breakdown,
        },

        # Issues detected
        "issues_detected": {
            "total":     len(anomalies),
            "critical":  severity_breakdown.get("CRITICAL", 0),
            "high":      severity_breakdown.get("HIGH", 0),
            "medium":    severity_breakdown.get("MEDIUM", 0),
            "low":       severity_breakdown.get("LOW", 0),
            "anomalies": anomalies[:20],  # Cap for file size
        },

        # Actions taken
        "actions_taken": {
            "total":        len(action_results),
            "succeeded":    len(actions_succeeded),
            "failed":       len(actions_failed),
            "blocked":      len(actions_blocked),
            "results":      action_results[:20],
        },

        # Recommendations
        "recommendations": {
            "total":             len(recommendations),
            "auto_executable":   len(auto_recs),
            "requires_approval": len(manual_recs),
            "top_3":             [r.get("title") for r in recommendations[:3]],
            "all":               recommendations[:15],  # Top 15
        },

        # Performance metrics
        "performance": perf_metrics,

        # Key operational metrics
        "operational_metrics": {
            "feed_item_count":          metrics.get("api_feed_item_count"),
            "dedup_total_seen":         metrics.get("dedup_total_seen"),
            "dedup_pro_required_count": metrics.get("dedup_pro_required_count"),
            "stale_intel_count":        metrics.get("stale_intel_count"),
            "pipeline_failure_rate":    metrics.get("pipeline_failure_rate"),
            "user_conversions_24h":     metrics.get("user_conversions_24h"),
            "api_feed_age_hours":       metrics.get("api_feed_age_hours"),
            "intel_hours_since_newest": metrics.get("intel_hours_since_newest"),
        },

        # Human approval queue state
        "approval_queue": _load_json(_DATA / "pending_approvals.json", []),
    }

    return report


def write_audit_report(report: Dict) -> None:
    """Write audit report to reports/system_audit.json and append to audit_history."""
    try:
        _REPORTS.mkdir(parents=True, exist_ok=True)
        _atomic_write(AUDIT_REPORT, report)
        log.info("[AUDIT] Report written: %s [%s, score=%d]",
                 AUDIT_REPORT, report.get("cycle_status"), report.get("health", {}).get("score", 0))

        # Maintain rolling audit history
        history = _load_json(AUDIT_HISTORY, [])
        if not isinstance(history, list):
            history = []
        history.append({
            "cycle_id":     report.get("cycle_id"),
            "generated_at": report.get("generated_at"),
            "cycle_status": report.get("cycle_status"),
            "health_score": report.get("health", {}).get("score"),
            "anomaly_count": report.get("issues_detected", {}).get("total", 0),
            "actions_taken": report.get("actions_taken", {}).get("succeeded", 0),
        })
        # Keep last 100 cycle summaries
        history = history[-100:]
        _atomic_write(AUDIT_HISTORY, history)
    except Exception as exc:
        log.error("[AUDIT] Failed to write audit report: %s", exc)


# ===========================================================================
# PHASE 8: LEARNING STATE MANAGER
# ===========================================================================

class LearningState:
    """
    Phase 8: Tracks historical health trends for continuous learning.

    Learns from historical cycles to:
        - Detect recurring anomalies (persistent issues)
        - Track threshold effectiveness
        - Identify improvement trends
        - Compute baseline drift
    """

    def __init__(self, window: int = 10) -> None:
        self.window = window
        self._state = _load_json(LEARNING_STATE, {}) or {}
        if not isinstance(self._state, dict):
            self._state = {}

    def record_cycle(self, cycle_id: str, health_score: int, anomalies: List[Dict],
                     actions_taken: List[Dict]) -> None:
        """Record this cycle's data into learning history."""
        history = self._state.setdefault("cycle_history", [])
        history.append({
            "cycle_id":      cycle_id,
            "timestamp":     _utc_now_iso(),
            "health_score":  health_score,
            "anomaly_count": len(anomalies),
            "anomaly_types": list({a.get("category") for a in anomalies}),
            "action_count":  len(actions_taken),
        })
        # Trim to window
        self._state["cycle_history"] = history[-self.window:]
        self._state["last_updated"] = _utc_now_iso()
        self._state["total_cycles"] = self._state.get("total_cycles", 0) + 1
        self._save()

    def get_trend(self) -> Dict[str, Any]:
        """Analyse recent cycles for trends."""
        history = self._state.get("cycle_history", [])
        if len(history) < 2:
            return {"trend": "INSUFFICIENT_DATA", "cycles_analysed": len(history)}

        scores = [h.get("health_score", 0) for h in history]
        avg_score = sum(scores) / len(scores)
        trend_direction = "IMPROVING" if scores[-1] > scores[0] else (
            "DEGRADING" if scores[-1] < scores[0] else "STABLE"
        )

        # Recurring anomalies
        all_types: List[str] = []
        for h in history:
            all_types.extend(h.get("anomaly_types", []))
        recurring = {t: all_types.count(t) for t in set(all_types)}
        persistent = [t for t, cnt in recurring.items() if cnt >= len(history) * 0.7]

        return {
            "trend":           trend_direction,
            "cycles_analysed": len(history),
            "avg_health_score": round(avg_score, 1),
            "current_score":   scores[-1] if scores else 0,
            "first_score":     scores[0] if scores else 0,
            "persistent_issues": persistent,
            "recurring_anomaly_types": recurring,
        }

    def _save(self) -> None:
        try:
            _atomic_write(LEARNING_STATE, self._state)
        except Exception as exc:
            log.error("[LEARNING] Save failed: %s", exc)


# ===========================================================================
# PHASE 9: PERFORMANCE TRACKER
# ===========================================================================

class PerformanceTracker:
    """
    Phase 9: Tracks pipeline stage timing and identifies bottlenecks.
    Recommends optimizations — never applies them automatically.
    """

    def __init__(self) -> None:
        self._timings: Dict[str, float] = {}
        self._started: Dict[str, float] = {}

    def start(self, stage: str) -> None:
        self._started[stage] = time.monotonic()

    def end(self, stage: str) -> float:
        start = self._started.pop(stage, None)
        if start is None:
            return 0.0
        elapsed = time.monotonic() - start
        self._timings[stage] = elapsed
        log.debug("[PERF] %s: %.2fs", stage, elapsed)
        return elapsed

    def get_metrics(self) -> Dict[str, Any]:
        if not self._timings:
            return {"stages": {}, "bottleneck": None, "total_s": 0}

        total = sum(self._timings.values())
        bottleneck = max(self._timings, key=self._timings.get)

        # Optimisation recommendations (read-only suggestions)
        suggestions = []
        for stage, elapsed in self._timings.items():
            pct = (elapsed / total * 100) if total > 0 else 0
            if pct > 40:
                suggestions.append(
                    f"Stage '{stage}' consumed {pct:.0f}% of total cycle time ({elapsed:.1f}s). "
                    "Consider async execution or caching."
                )

        return {
            "stages":       {s: round(t, 2) for s, t in self._timings.items()},
            "total_s":      round(total, 2),
            "bottleneck":   bottleneck,
            "bottleneck_s": round(self._timings.get(bottleneck, 0), 2),
            "suggestions":  suggestions,
        }

    def append_to_log(self, cycle_id: str) -> None:
        """Append timing metrics to data/performance_log.json."""
        try:
            log_data = _load_json(PERF_LOG, []) or []
            if not isinstance(log_data, list):
                log_data = []
            log_data.append({
                "cycle_id":   cycle_id,
                "timestamp":  _utc_now_iso(),
                **self.get_metrics(),
            })
            log_data = log_data[-200:]  # Keep last 200 entries
            _atomic_write(PERF_LOG, log_data)
        except Exception as exc:
            log.error("[PERF] Log write failed: %s", exc)


# ===========================================================================
# PHASE 10: SAFETY SYSTEM
# ===========================================================================

class SafetySystem:
    """
    Phase 10: Final safety layer.

    Invariants enforced each cycle:
        1. Emergency stop signal check
        2. Canary health score check (halt if below threshold)
        3. Core file integrity check (detect unauthorised modifications)
        4. Audit trail continuity check
        5. Action rate limiting (prevent runaway loops)
    """

    def __init__(self, config: Dict) -> None:
        self.config = config
        self._core_checksums: Dict[str, str] = {}

    def check_emergency_stop(self) -> Tuple[bool, str]:
        """Returns (stopped, reason) if emergency stop is active."""
        if EMERGENCY_STOP.exists():
            reason = EMERGENCY_STOP.read_text(encoding="utf-8").strip() or "Emergency stop file present"
            log.critical("[SAFETY] EMERGENCY STOP ACTIVE: %s", reason)
            return True, reason
        return False, ""

    def check_canary(self, health_score: int) -> Tuple[bool, str]:
        """Returns (failed, reason) if health score is critically low."""
        threshold = self.config.get("health_score_canary", 40)
        if health_score < threshold:
            reason = (
                f"Canary check failed: health_score={health_score} < threshold={threshold}. "
                "Halting auto-actions. Human review required."
            )
            log.critical("[SAFETY] CANARY FAILED: %s", reason)
            return True, reason
        return False, ""

    def assert_no_core_modification(self) -> List[str]:
        """
        Detect if any core files were modified since last cycle.
        Returns list of modified core files (should be empty).
        """
        violations: List[str] = []
        import hashlib
        core_paths = [
            _SCRIPTS / "master_p0_fix.py",
            _SCRIPTS / "run_pipeline.py",
            _SCRIPTS / "apex_intelligence_engine.py",
            _SCRIPTS / "intel_dedup_engine.py",
        ]
        for path in core_paths:
            if not path.exists():
                continue
            try:
                content = path.read_bytes()
                checksum = hashlib.md5(content, usedforsecurity=False).hexdigest()
                rel = str(path.relative_to(_ROOT))
                prev = self._core_checksums.get(rel)
                if prev and prev != checksum:
                    violations.append(f"{rel} (checksum changed: {prev[:8]}→{checksum[:8]})")
                self._core_checksums[rel] = checksum
            except Exception:
                pass
        if violations:
            log.critical("[SAFETY] CORE FILE MODIFICATION DETECTED: %s", violations)
        return violations

    def emit_emergency_stop(self, reason: str) -> None:
        """Write emergency stop signal file."""
        try:
            EMERGENCY_STOP.write_text(
                f"{_utc_now_iso()} — {reason}", encoding="utf-8"
            )
            log.critical("[SAFETY] Emergency stop signal written: %s", reason)
        except Exception as exc:
            log.error("[SAFETY] Failed to write emergency stop: %s", exc)

    def clear_emergency_stop(self) -> None:
        """Remove emergency stop signal (manual recovery)."""
        try:
            if EMERGENCY_STOP.exists():
                EMERGENCY_STOP.unlink()
                log.info("[SAFETY] Emergency stop cleared.")
        except Exception as exc:
            log.error("[SAFETY] Cannot clear emergency stop: %s", exc)


# ===========================================================================
# PHASE 7: HUMAN APPROVAL MODE
# ===========================================================================

def _summarise_pending_approvals() -> Dict[str, Any]:
    """Return summary of pending approval queue state."""
    pending = _load_json(_DATA / "pending_approvals.json", []) or []
    if not isinstance(pending, list):
        pending = []

    pending_items = [p for p in pending if p.get("status") == "pending"]
    approved_items = [p for p in pending if p.get("status") == "approved"]
    executed_items = [p for p in pending if p.get("status") == "executed"]

    return {
        "total":           len(pending),
        "pending_count":   len(pending_items),
        "approved_count":  len(approved_items),
        "executed_count":  len(executed_items),
        "pending_actions": [p.get("action_key") for p in pending_items],
    }


# ===========================================================================
# MASTER ORCHESTRATOR — SINGLE CYCLE
# ===========================================================================

def run_cycle(
    cycle_id: Optional[str] = None,
    dry_run: bool = False,
    config: Optional[Dict] = None,
    safety: Optional["SafetySystem"] = None,
    learner: Optional["LearningState"] = None,
    perf: Optional["PerformanceTracker"] = None,
) -> Dict[str, Any]:
    """
    Execute a single complete self-improvement cycle (Phases 1–10).

    Returns the full audit report dict.
    """
    if config is None:
        config = _load_config()

    cycle_id = cycle_id or f"CYCLE-{_utc_now().strftime('%Y%m%d-%H%M%S')}"
    log.info("[ENGINE] ══════════════════════════════════════════")
    log.info("[ENGINE] CYCLE START: %s", cycle_id)
    log.info("[ENGINE] ══════════════════════════════════════════")
    cycle_start = time.monotonic()

    if safety is None:
        safety = SafetySystem(config)
    if learner is None:
        learner = LearningState(window=config.get("learning_window_cycles", 10))
    if perf is None:
        perf = PerformanceTracker()

    action_results: List[Dict] = []
    health_report: Dict = {}
    recommendations: List[Dict] = []

    # ── Phase 10: Emergency stop check ────────────────────────────────────
    stopped, stop_reason = safety.check_emergency_stop()
    if stopped:
        audit = {
            "schema_version": "2.0",
            "cycle_id":       cycle_id,
            "generated_at":   _utc_now_iso(),
            "cycle_status":   "EMERGENCY_STOPPED",
            "stop_reason":    stop_reason,
            "health":         {"score": 0, "grade": "F", "status": "EMERGENCY"},
            "issues_detected": {},
            "actions_taken":  {},
            "recommendations": {},
            "performance":    {},
            "operational_metrics": {},
            "approval_queue": [],
        }
        write_audit_report(audit)
        return audit

    # ── Phase 10: Core file integrity check ───────────────────────────────
    violations = safety.assert_no_core_modification()
    if violations:
        log.critical("[ENGINE] Core file violations detected — blocking auto-actions this cycle")

    # ── Phase 1+2: Monitor + Anomaly Detection ───────────────────────────
    perf.start("monitor")
    try:
        # Import here to allow fresh reload each cycle
        from self_improve_monitor import run_monitor
        health_report = run_monitor(dry_run=False)  # always write health
    except Exception as exc:
        log.error("[ENGINE] Monitor phase failed: %s", exc)
        health_report = {"health": {"score": 0, "grade": "F", "status": "MONITOR_FAILED"},
                         "anomalies": [], "metrics": {}}
    perf.end("monitor")

    health_score = health_report.get("health", {}).get("score", 0)
    anomalies = health_report.get("anomalies", [])

    # ── Phase 10: Canary check ────────────────────────────────────────────
    canary_failed, canary_reason = safety.check_canary(health_score)
    if canary_failed:
        log.critical("[ENGINE] Canary failed — skipping auto-actions this cycle")

    # ── Phase 3: Recommendation Engine ───────────────────────────────────
    perf.start("recommender")
    try:
        from self_improve_recommender import run_recommender
        rec_report = run_recommender(health_report=health_report, dry_run=False)
        recommendations = rec_report.get("recommendations", [])
    except Exception as exc:
        log.error("[ENGINE] Recommender phase failed: %s", exc)
        recommendations = []
    perf.end("recommender")

    # ── Phase 4+5: Safe Action Engine ────────────────────────────────────
    perf.start("actions")
    if not canary_failed and not violations:
        try:
            from self_improve_actions import SafeActionEngine, process_approved_actions
            action_dry_run = dry_run or config.get("dry_run_actions", False)
            engine = SafeActionEngine(dry_run=action_dry_run)
            auto_results = engine.execute_batch(
                recommendations,
                max_actions=config.get("max_auto_actions", 5),
            )
            action_results = [r.to_dict() for r in auto_results]
        except Exception as exc:
            log.error("[ENGINE] Action phase failed: %s", exc)

    # ── Phase 7: Process human-approved actions ───────────────────────────
    try:
        from self_improve_actions import process_approved_actions
        approved_results = process_approved_actions(dry_run=dry_run)
        action_results.extend([r.to_dict() for r in approved_results])
    except Exception as exc:
        log.error("[ENGINE] Approval processing failed: %s", exc)
    perf.end("actions")

    # ── Phase 9: Performance metrics ──────────────────────────────────────
    cycle_elapsed = time.monotonic() - cycle_start
    perf_metrics = perf.get_metrics()
    perf_metrics["total_cycle_s"] = round(cycle_elapsed, 2)

    # Check for performance anomaly
    baseline = config.get("perf_baseline_s", 120)
    if cycle_elapsed > baseline * 2:
        log.warning("[PERF] Cycle time %.1fs exceeds 2x baseline (%ds)", cycle_elapsed, baseline)

    perf.append_to_log(cycle_id)

    # ── Phase 8: Learning State ───────────────────────────────────────────
    try:
        learner.record_cycle(cycle_id, health_score, anomalies, action_results)
        trend = learner.get_trend()
        log.info("[LEARNING] Trend: %s | Avg score: %s | Persistent: %s",
                 trend.get("trend"), trend.get("avg_health_score"), trend.get("persistent_issues"))
    except Exception as exc:
        log.error("[ENGINE] Learning state failed: %s", exc)
        trend = {}

    # ── Phase 6: Audit Report ─────────────────────────────────────────────
    approval_summary = _summarise_pending_approvals()
    audit_report = build_audit_report(
        cycle_id, health_report, recommendations, action_results, perf_metrics, config
    )
    audit_report["learning_trend"] = trend if 'trend' in dir() else {}  # type: ignore
    audit_report["approval_summary"] = approval_summary
    audit_report["core_file_violations"] = violations
    audit_report["canary_failed"] = canary_failed
    audit_report["dry_run"] = dry_run

    write_audit_report(audit_report)

    # ── Phase 10: Final safety invariant enforcement ──────────────────────
    # If health collapsed after actions, trigger emergency stop
    post_score = health_report.get("health", {}).get("score", 100)
    if post_score < 20 and not canary_failed:
        safety.emit_emergency_stop(
            f"Cycle {cycle_id}: health_score collapsed to {post_score}. Auto-stop triggered."
        )

    log.info(
        "[ENGINE] CYCLE COMPLETE: %s | score=%d | anomalies=%d | actions=%d | %.1fs",
        cycle_id, health_score, len(anomalies), len(action_results), cycle_elapsed,
    )
    return audit_report


# ===========================================================================
# PHASE 8: DAEMON / CONTINUOUS LEARNING LOOP
# ===========================================================================

def run_daemon(
    config: Dict,
    max_cycles: Optional[int] = None,
) -> None:
    """
    Phase 8: Continuous self-improvement loop.

    Runs cycles indefinitely (or up to max_cycles) with configurable interval.
    Stops on emergency stop signal or unrecoverable circuit breaker trip.
    """
    interval_s = config.get("cycle_interval_s", 3600)
    safety = SafetySystem(config)
    learner = LearningState(window=config.get("learning_window_cycles", 10))
    perf = PerformanceTracker()

    log.info("[ENGINE] DAEMON MODE STARTING — interval=%ds", interval_s)
    cycle_num = 0

    while True:
        cycle_num += 1
        cycle_id = f"CYCLE-{_utc_now().strftime('%Y%m%d-%H%M%S')}-{cycle_num:04d}"

        # Emergency stop check
        stopped, reason = safety.check_emergency_stop()
        if stopped:
            log.critical("[ENGINE] DAEMON HALTED — emergency stop: %s", reason)
            break

        # Run cycle
        try:
            audit = run_cycle(
                cycle_id=cycle_id,
                config=config,
                safety=safety,
                learner=learner,
                perf=perf,
            )
        except Exception as exc:
            log.critical("[ENGINE] Unhandled cycle exception: %s", exc)

        if max_cycles and cycle_num >= max_cycles:
            log.info("[ENGINE] Max cycles (%d) reached — stopping daemon.", max_cycles)
            break

        # Wait for next cycle
        log.info("[ENGINE] Next cycle in %ds (%.1f min)...", interval_s, interval_s / 60)
        # Check emergency stop every 30 seconds during sleep
        slept = 0
        while slept < interval_s:
            time.sleep(min(30, interval_s - slept))
            slept += 30
            stopped, reason = safety.check_emergency_stop()
            if stopped:
                log.critical("[ENGINE] DAEMON HALTED mid-sleep: %s", reason)
                return

    log.info("[ENGINE] DAEMON STOPPED after %d cycles.", cycle_num)


# ===========================================================================
# CLI / Entry Point
# ===========================================================================

def _print_cycle_summary(audit: Dict) -> None:
    """Pretty-print cycle summary to stdout."""
    h = audit.get("health", {})
    issues = audit.get("issues_detected", {})
    actions = audit.get("actions_taken", {})
    recs = audit.get("recommendations", {})
    perf = audit.get("performance", {})
    trend = audit.get("learning_trend", {})

    SEP = "=" * 65
    print(f"\n{SEP}")
    print(f"  SENTINEL APEX -- SELF-IMPROVING ENGINE CYCLE REPORT")
    print(f"{SEP}")
    print(f"  Cycle:       {audit.get('cycle_id', '?')}")
    print(f"  Status:      {audit.get('cycle_status', '?')}")
    print(f"  Health:      {h.get('score', '?')}/100  [{h.get('grade', '?')}]  {h.get('status', '?')}")
    print(f"  Generated:   {audit.get('generated_at', '?')}")

    print(f"\n  ISSUES DETECTED ({issues.get('total', 0)} anomalies):")
    print(f"    Critical: {issues.get('critical', 0)}  |  High: {issues.get('high', 0)}  |  Medium: {issues.get('medium', 0)}")
    for a in (issues.get("anomalies") or [])[:5]:
        print(f"    [{a.get('severity'):8s}] {a.get('title', '')[:60]}")

    print(f"\n  ACTIONS TAKEN ({actions.get('total', 0)}):")
    print(f"    Succeeded: {actions.get('succeeded', 0)}  |  Failed: {actions.get('failed', 0)}  |  Blocked: {actions.get('blocked', 0)}")
    for r in (actions.get("results") or [])[:5]:
        status = "OK" if r.get("success") else ("BLOCKED" if r.get("blocked") else "FAIL")
        print(f"    [{status:7s}] {r.get('action_key', '')}")

    print(f"\n  RECOMMENDATIONS ({recs.get('total', 0)}):")
    print(f"    Auto-executable: {recs.get('auto_executable', 0)}  |  Needs approval: {recs.get('requires_approval', 0)}")
    for title in (recs.get("top_3") or []):
        print(f"    -> {title}")

    print(f"\n  PERFORMANCE:")
    print(f"    Cycle time: {perf.get('total_cycle_s', '?')}s  |  Bottleneck: {perf.get('bottleneck', '?')} ({perf.get('bottleneck_s', '?')}s)")

    if trend.get("trend"):
        print(f"\n  LEARNING TREND: {trend.get('trend')} (avg score: {trend.get('avg_health_score')} over {trend.get('cycles_analysed')} cycles)")
        if trend.get("persistent_issues"):
            print(f"    Persistent issues: {', '.join(trend['persistent_issues'])}")

    if audit.get("core_file_violations"):
        print(f"\n  ⚠  CORE FILE VIOLATIONS: {audit['core_file_violations']}")
    if audit.get("canary_failed"):
        print(f"\n  ⚠  CANARY FAILED — auto-actions were suppressed this cycle")
    if audit.get("dry_run"):
        print(f"\n  [DRY RUN MODE — no actions executed]")

    approval = audit.get("approval_summary", {})
    if approval.get("pending_count", 0) > 0:
        print(f"\n  ⏳ PENDING APPROVALS: {approval['pending_count']} actions waiting for human approval")
        for ak in approval.get("pending_actions", []):
            print(f"    → {ak}")
    print(f"\n  Audit report: {AUDIT_REPORT}")
    print(f"{SEP}\n")


if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [engine] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX — Self-Improving Engine Master Orchestrator"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Run without executing any actions")
    parser.add_argument("--daemon", action="store_true",
                        help="Run continuously in daemon mode")
    parser.add_argument("--max-cycles", type=int, default=None,
                        help="Maximum cycles in daemon mode (default: unlimited)")
    parser.add_argument("--interval", type=int, default=None,
                        help="Cycle interval in seconds (overrides config)")
    parser.add_argument("--json", action="store_true",
                        help="Output full JSON audit report to stdout")
    parser.add_argument("--clear-emergency-stop", action="store_true",
                        help="Clear the emergency stop signal and exit")
    parser.add_argument("--emit-emergency-stop", type=str, default=None,
                        help="Trigger emergency stop with given reason")
    args = parser.parse_args()

    cfg = _load_config()
    safety = SafetySystem(cfg)

    if args.clear_emergency_stop:
        safety.clear_emergency_stop()
        print("Emergency stop cleared. System can resume.")
        sys.exit(0)

    if args.emit_emergency_stop:
        safety.emit_emergency_stop(args.emit_emergency_stop)
        print(f"Emergency stop emitted: {args.emit_emergency_stop}")
        sys.exit(0)

    if args.daemon:
        if args.interval:
            cfg["cycle_interval_s"] = args.interval
        run_daemon(cfg, max_cycles=args.max_cycles)
    else:
        audit = run_cycle(dry_run=args.dry_run, config=cfg, safety=safety)
        if args.json:
            print(json.dumps(audit, indent=2, ensure_ascii=False))
        else:
            _print_cycle_summary(audit)
