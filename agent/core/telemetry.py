#!/usr/bin/env python3
"""
telemetry.py — CyberDudeBivash SENTINEL APEX v17.0
PRODUCTION OBSERVABILITY ENGINE

Tracks pipeline execution timing, performance, and intelligence throughput
for enterprise SLA monitoring. Non-breaking addition — purely additive.

Records:
  - Processing time per CVE / threat item
  - Feed latency per source
  - Risk engine compute time
  - Publishing duration
  - Error frequency per run
  - Total IOC count per run
"""

import time
import json
import os
import logging
from typing import Dict, Optional
from datetime import datetime, timezone

logger = logging.getLogger("CDB-TELEMETRY")

TELEMETRY_LOG_PATH = "data/telemetry_log.json"
MAX_TELEMETRY_ENTRIES = 500  # Rolling window


class SentinelTelemetry:
    """
    Lightweight telemetry engine for pipeline observability.
    All methods are additive — no changes to existing pipeline flow.
    Usage: wrap existing pipeline steps with start/stop timers.
    """

    def __init__(self):
        self._timers: Dict[str, float] = {}
        self._current_run: Dict = {}
        self._reset_run()

    def _reset_run(self):
        self._current_run = {
            "run_id": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "feed_latencies": {},       # {feed_url: seconds}
            "cve_process_times": [],    # List of floats (seconds per CVE)
            "risk_engine_times": [],    # List of floats
            "publish_times": [],        # List of floats
            "error_counts": {},         # {module: count}
            "ioc_counts": {},           # {ioc_type: total_count}
            "items_processed": 0,
            "items_published": 0,
            "items_deduplicated": 0,
            "feeds_fetched": 0,
            "feeds_failed": 0,
            "total_run_time": 0.0,
            "run_status": "running",
        }

    # ── Timer API ──────────────────────────────────────────

    def start_timer(self, label: str):
        """Start a named timer."""
        self._timers[label] = time.monotonic()

    def stop_timer(self, label: str) -> float:
        """Stop a named timer and return elapsed seconds."""
        if label not in self._timers:
            return 0.0
        elapsed = round(time.monotonic() - self._timers.pop(label), 4)
        return elapsed

    # ── Feed Tracking ──────────────────────────────────────

    def record_feed_fetch(self, feed_url: str, elapsed_sec: float, success: bool):
        """Record feed fetch latency and status."""
        short_url = feed_url[:60]
        self._current_run["feed_latencies"][short_url] = {
            "elapsed_sec": round(elapsed_sec, 3),
            "success": success,
        }
        if success:
            self._current_run["feeds_fetched"] += 1
        else:
            self._current_run["feeds_failed"] += 1

    # ── Processing Tracking ────────────────────────────────

    def record_cve_processing(self, elapsed_sec: float):
        """Record time to process a single CVE/threat item."""
        self._current_run["cve_process_times"].append(round(elapsed_sec, 4))
        self._current_run["items_processed"] += 1

    def record_risk_engine(self, elapsed_sec: float):
        """Record risk engine compute time."""
        self._current_run["risk_engine_times"].append(round(elapsed_sec, 4))

    def record_publish(self, elapsed_sec: float, success: bool):
        """Record Blogger publish time."""
        self._current_run["publish_times"].append(round(elapsed_sec, 4))
        if success:
            self._current_run["items_published"] += 1

    def record_dedup(self):
        """Record a deduplicated item."""
        self._current_run["items_deduplicated"] += 1

    def record_iocs(self, iocs: Dict):
        """Accumulate IOC counts from a single item."""
        for ioc_type, values in iocs.items():
            if values:
                self._current_run["ioc_counts"][ioc_type] = (
                    self._current_run["ioc_counts"].get(ioc_type, 0) + len(values)
                )

    def record_error(self, module: str):
        """Increment error count for a module."""
        self._current_run["error_counts"][module] = (
            self._current_run["error_counts"].get(module, 0) + 1
        )

    # ── Run Finalization ────────────────────────────────────

    def finalize_run(self, total_elapsed: float, status: str = "success"):
        """
        Finalize current run metrics, compute summaries, persist to log.
        Call this at the very end of sentinel_blogger.py main().
        """
        run = self._current_run
        run["total_run_time"] = round(total_elapsed, 2)
        run["completed_at"] = datetime.now(timezone.utc).isoformat()
        run["run_status"] = status

        # Compute averages
        if run["cve_process_times"]:
            run["avg_cve_process_sec"] = round(
                sum(run["cve_process_times"]) / len(run["cve_process_times"]), 4
            )
        if run["risk_engine_times"]:
            run["avg_risk_engine_sec"] = round(
                sum(run["risk_engine_times"]) / len(run["risk_engine_times"]), 4
            )
        if run["publish_times"]:
            run["avg_publish_sec"] = round(
                sum(run["publish_times"]) / len(run["publish_times"]), 4
            )

        # Total IOC count
        run["total_ioc_count"] = sum(run["ioc_counts"].values())

        self._persist_run(run)
        self._log_summary(run)
        self._reset_run()
        return run

    def _persist_run(self, run: Dict):
        """Append run data to rolling telemetry log."""
        try:
            os.makedirs("data", exist_ok=True)
            existing = []
            if os.path.exists(TELEMETRY_LOG_PATH):
                with open(TELEMETRY_LOG_PATH, "r") as f:
                    existing = json.load(f)
            existing.append(run)
            # Keep rolling window
            if len(existing) > MAX_TELEMETRY_ENTRIES:
                existing = existing[-MAX_TELEMETRY_ENTRIES:]
            with open(TELEMETRY_LOG_PATH, "w") as f:
                json.dump(existing, f, indent=2)
        except Exception as e:
            logger.warning(f"Telemetry persist failed: {e}")

    def _log_summary(self, run: Dict):
        """Log human-readable summary to stdout."""
        logger.info(
            f"📊 TELEMETRY SUMMARY | Run: {run['run_id']} | "
            f"Status: {run['run_status'].upper()} | "
            f"Total time: {run['total_run_time']}s | "
            f"Processed: {run['items_processed']} | "
            f"Published: {run['items_published']} | "
            f"Deduped: {run['items_deduplicated']} | "
            f"Feeds OK: {run['feeds_fetched']} | "
            f"Feeds Failed: {run['feeds_failed']} | "
            f"Total IOCs: {run.get('total_ioc_count', 0)} | "
            f"Errors: {sum(run['error_counts'].values())}"
        )

    def get_last_run_summary(self) -> Optional[Dict]:
        """Retrieve the last completed run summary from telemetry log."""
        try:
            if os.path.exists(TELEMETRY_LOG_PATH):
                with open(TELEMETRY_LOG_PATH, "r") as f:
                    runs = json.load(f)
                if runs:
                    return runs[-1]
        except Exception as e:
            logger.warning(f"Telemetry read failed: {e}")
        return None


# Singleton instance
telemetry = SentinelTelemetry()
