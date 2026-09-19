#!/usr/bin/env python3
"""
api/health.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Platform Health Endpoint v1.0
==================================================================
Exposes real-time platform health metrics for monitoring, alerting,
and enterprise SLA dashboards.

Endpoint: GET /api/health
Response:
  {
    "status":               "HEALTHY" | "DEGRADED" | "CRITICAL",
    "health_score":         0-100,
    "system_state":         "HEALTHY" | "DEGRADED" | "CRITICAL",
    "recovery_queue_size":  int,
    "write_queue_depth":    int,
    "pipeline_state":       { ... },
    "uptime_info":          { ... },
    "timestamp":            ISO-8601,
    "version":              "v134.0",
  }

Data sources (priority order):
  1. data/logs/system_health.json       -- written by stage_recovery_replay
  2. safe_io.py SystemHealthMonitor     -- in-process metrics (if importable)
  3. data/recovery/write_failures/*.json -- live blob count
  4. data/logs/write_failures.jsonl     -- audit log count
  5. Fallback: healthy defaults

NEVER raises. All errors return a safe UNKNOWN state response.

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("CDB-HEALTH")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR     = Path(__file__).resolve().parent.parent
DATA_DIR     = BASE_DIR / "data"
HEALTH_JSON  = DATA_DIR / "logs" / "system_health.json"
WF_LOG       = DATA_DIR / "logs" / "write_failures.jsonl"
RECOVERY_DIR = DATA_DIR / "recovery" / "write_failures"
METRICS_JSON = DATA_DIR / "logs" / "pipeline_metrics.json"
VERSION_FILE = BASE_DIR / "core" / "version.py"

# Bootstrap sys.path for safe_io import
for _p in (str(BASE_DIR / "scripts"), str(BASE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Data collectors
# ---------------------------------------------------------------------------

def _read_system_health_json() -> Optional[Dict]:
    """Read system_health.json written by stage_recovery_replay."""
    try:
        if HEALTH_JSON.exists() and HEALTH_JSON.stat().st_size > 0:
            return json.loads(HEALTH_JSON.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug("health.json read failed: %s", e)
    return None


def _get_recovery_blob_count() -> int:
    """Count live recovery blobs (unresolved write failures)."""
    try:
        if RECOVERY_DIR.exists():
            return len(list(RECOVERY_DIR.glob("*.json")))
    except Exception:
        pass
    return 0


def _get_wf_log_count() -> int:
    """Count audit entries in write_failures.jsonl."""
    try:
        if WF_LOG.exists() and WF_LOG.stat().st_size > 0:
            lines = [l for l in WF_LOG.read_text(encoding="utf-8").splitlines() if l.strip()]
            return len(lines)
    except Exception:
        pass
    return 0


def _get_safe_io_metrics() -> Optional[Dict]:
    """Read live WriteQueue + SystemHealthMonitor metrics from safe_io."""
    try:
        from safe_io import WriteQueue, SystemHealthMonitor
        snap = WriteQueue.metrics_snapshot()

        # Try to get SystemHealthMonitor state
        shm_state: Optional[Dict] = None
        try:
            shm = SystemHealthMonitor()
            shm_state = shm.get_state()
        except Exception:
            pass

        return {
            "write_queue_depth": snap.get("write_queue_depth", 0),
            "recovery_count":    snap.get("recovery_count", 0),
            "write_failures":    snap.get("write_failures", 0),
            "write_successes":   snap.get("write_successes", 0),
            "shm_state":         shm_state,
        }
    except Exception:
        return None


def _get_pipeline_metrics() -> Optional[Dict]:
    """Read last pipeline metrics report."""
    try:
        if METRICS_JSON.exists() and METRICS_JSON.stat().st_size > 0:
            raw = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
            return {
                "last_pipeline_at":    raw.get("timestamp", raw.get("started_at")),
                "ingested":            raw.get("ingested", 0),
                "failures":            raw.get("failures", 0),
                "iocs_extracted":      raw.get("iocs_extracted", 0),
                "pipeline_duration_s": raw.get("pipeline_duration_s", 0),
            }
    except Exception:
        pass
    return None


def _compute_health_score(
    recovery_blobs: int,
    wf_log_count: int,
    write_queue_depth: int,
    state: str,
    retry_count: int = 0,
) -> float:
    """
    Compute health score 0-100.

    Formula (v134):
        score = 100
              - (recovery_blobs    * 2.0)   # same weight as write failures
              - (retry_count       * 0.5)   # retries indicate write pressure
              - (write_queue_depth * 1.0)   # queue depth penalised 1:1
        Clamped to [0.0, 100.0].

    Note: state-based penalty removed — the formula components already drive
    the score down naturally when the system is DEGRADED/CRITICAL.
    100 = fully healthy. 0 = critical failure / maximum backlog.
    """
    score = (
        100.0
        - (recovery_blobs    * 2.0)
        - (retry_count       * 0.5)
        - (write_queue_depth * 1.0)
    )
    return max(0.0, min(100.0, round(score, 1)))


# ---------------------------------------------------------------------------
# Main health builder
# ---------------------------------------------------------------------------

def get_platform_health() -> Dict[str, Any]:
    """
    Build comprehensive platform health payload.
    NEVER raises. Falls back to safe defaults on any error.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    try:
        # -- Collect all data sources ------------------------------------------
        health_json    = _read_system_health_json()
        recovery_blobs = _get_recovery_blob_count()
        wf_log_count   = _get_wf_log_count()
        safe_io_metrics = _get_safe_io_metrics()
        pipeline_metrics = _get_pipeline_metrics()

        # -- Determine system state (priority: live blobs > health_json) -------
        if recovery_blobs > 100:
            state = "CRITICAL"
        elif recovery_blobs > 50:
            state = "DEGRADED"
        elif health_json:
            state = str(health_json.get("state", "HEALTHY")).upper()
            if state not in ("HEALTHY", "DEGRADED", "CRITICAL"):
                state = "HEALTHY"
        else:
            state = "HEALTHY"

        # -- Write queue depth from safe_io (or health_json fallback) ----------
        write_queue_depth = 0
        if safe_io_metrics:
            write_queue_depth = safe_io_metrics.get("write_queue_depth", 0)
        elif health_json:
            write_queue_depth = 0  # not tracked in health_json

        # -- Retry count from safe_io metrics (for health score) ---------------
        retry_count = 0
        if safe_io_metrics and safe_io_metrics.get("shm_state"):
            retry_count = int(safe_io_metrics["shm_state"].get("write_retry_count", 0))

        # -- Health score (v134 formula) ---------------------------------------
        health_score = _compute_health_score(
            recovery_blobs, wf_log_count, write_queue_depth, state, retry_count
        )

        # -- HTTP status (200 = healthy/degraded, 503 = critical) --------------
        http_status = 503 if state == "CRITICAL" else 200

        # -- Build response ----------------------------------------------------
        response: Dict[str, Any] = {
            "status":              state,
            "health_score":        health_score,
            "system_state":        state,
            "recovery_queue_size": recovery_blobs,
            "backlog_size":        recovery_blobs,      # v134: explicit alias
            "write_queue_depth":   write_queue_depth,
            "retry_count":         retry_count,         # v134: visible in metrics
            "write_failures_log":  wf_log_count,
            "timestamp":           now,
            "version":             "v134.0",
            "platform":            "CYBERDUDEBIVASH SENTINEL APEX",
        }

        # -- Safe IO live metrics (if available) --------------------------------
        if safe_io_metrics:
            response["live_metrics"] = {
                "write_successes": safe_io_metrics.get("write_successes", 0),
                "write_failures":  safe_io_metrics.get("write_failures", 0),
                "recovery_count":  safe_io_metrics.get("recovery_count", 0),
            }
            if safe_io_metrics.get("shm_state"):
                shm = safe_io_metrics["shm_state"]
                response["pipeline_state"] = {
                    "health_score":          shm.get("health_score", health_score),
                    "consecutive_degraded":  shm.get("consecutive_degraded_runs", 0),
                    "write_failure_count":   shm.get("write_failure_count", 0),
                    "write_retry_count":     shm.get("write_retry_count", 0),
                    "throttle_active":       shm.get("throttle_active", False),
                }

        # -- Pipeline metrics (if available) ------------------------------------
        if pipeline_metrics:
            response["last_pipeline"] = pipeline_metrics

        # -- Recovery info from health.json ------------------------------------
        if health_json:
            response["last_recovery"] = {
                "pre_replay_count":  health_json.get("pre_replay_count", recovery_blobs),
                "succeeded":         health_json.get("succeeded", 0),
                "failed_permanent":  health_json.get("failed_permanent", 0),
                "updated_at":        health_json.get("updated_at", now),
            }

        # -- Backlog thresholds (for monitoring dashboards) --------------------
        response["thresholds"] = {
            "degraded_at_blobs":  50,
            "critical_at_blobs":  100,
            "current_blobs":      recovery_blobs,
            "pct_to_critical":    round(recovery_blobs / 100 * 100, 1),
        }

        # -- Upgrade info (for public health endpoint) -------------------------
        response["api_info"] = {
            "feed_endpoint":   "/api/feed.json",
            "docs":            "https://intel.cyberdudebivash.com/api",
            "status_page":     "https://intel.cyberdudebivash.com/api/health",
            "enterprise_demo": "https://intel.cyberdudebivash.com/api/enterprise/demo",
        }

        return response, http_status

    except Exception as e:
        logger.error("get_platform_health raised (safe fallback): %s", e)
        return {
            "status":            "UNKNOWN",
            "health_score":      0,
            "system_state":      "UNKNOWN",
            "recovery_queue_size": -1,
            "write_queue_depth": -1,
            "error":             "health_check_error",
            "timestamp":         now,
            "version":           "v134.0",
        }, 200  # Return 200 with UNKNOWN rather than 500 — fail open


# ---------------------------------------------------------------------------
# Static JSON writer (called by pipeline to pre-bake health for static hosting)
# ---------------------------------------------------------------------------

def write_static_health_json(output_path: Optional[Path] = None) -> bool:
    """
    Write health payload to api/health.json for static GitHub Pages serving.
    Called at end of pipeline run by run_pipeline.py stage_write_health().
    """
    if output_path is None:
        output_path = BASE_DIR / "api" / "health.json"

    try:
        health, _ = get_platform_health()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = output_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(health, indent=2, default=str), encoding="utf-8")
        tmp.rename(output_path)
        logger.info("Static health.json written: %s (state=%s score=%.1f)",
                    output_path, health.get("status"), health.get("health_score", 0))
        return True
    except Exception as e:
        logger.error("write_static_health_json failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SENTINEL APEX Platform Health Check")
    parser.add_argument("--write", action="store_true",
                        help="Write health.json to api/health.json and exit")
    parser.add_argument("--output", default=None, help="Custom output path for --write")
    args = parser.parse_args()

    if args.write:
        ok = write_static_health_json(Path(args.output) if args.output else None)
        sys.exit(0 if ok else 1)

    health, status = get_platform_health()
    print(json.dumps(health, indent=2, default=str))
    sys.exit(0 if status == 200 else 1)
