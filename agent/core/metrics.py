#!/usr/bin/env python3
"""
metrics.py — CyberDudeBivash SENTINEL APEX v17.0
PLATFORM METRICS ENGINE

Aggregates and exposes platform-wide performance metrics.
Reads from telemetry_log.json to compute rolling statistics
suitable for enterprise SLA dashboards and health monitoring.
"""

import json
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("CDB-METRICS")

TELEMETRY_LOG_PATH = "data/telemetry_log.json"


class PlatformMetrics:
    """
    Aggregated platform metrics from telemetry history.
    Provides rolling averages, error rates, throughput stats.
    """

    def compute_rolling_metrics(self, window_hours: int = 168) -> Dict:
        """
        Compute platform metrics over the last N hours (default: 7 days).
        Returns metrics dict suitable for dashboard display.
        """
        runs = self._load_runs()
        if not runs:
            return self._empty_metrics()

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        recent_runs = []
        for run in runs:
            try:
                completed = datetime.fromisoformat(
                    run.get("completed_at", run.get("started_at", ""))
                )
                if completed.tzinfo is None:
                    completed = completed.replace(tzinfo=timezone.utc)
                if completed >= cutoff:
                    recent_runs.append(run)
            except Exception:
                continue

        if not recent_runs:
            recent_runs = runs[-10:]  # Fall back to last 10 runs

        return self._aggregate(recent_runs, window_hours)

    def _aggregate(self, runs: List[Dict], window_hours: int) -> Dict:
        total_runs = len(runs)
        successful = sum(1 for r in runs if r.get("run_status") == "success")
        total_processed = sum(r.get("items_processed", 0) for r in runs)
        total_published = sum(r.get("items_published", 0) for r in runs)
        total_deduped = sum(r.get("items_deduplicated", 0) for r in runs)
        total_iocs = sum(r.get("total_ioc_count", 0) for r in runs)
        total_errors = sum(sum(r.get("error_counts", {}).values()) for r in runs)
        feeds_failed = sum(r.get("feeds_failed", 0) for r in runs)
        feeds_fetched = sum(r.get("feeds_fetched", 0) for r in runs)

        run_times = [r["total_run_time"] for r in runs if r.get("total_run_time")]
        avg_run_time = round(sum(run_times) / len(run_times), 2) if run_times else 0

        # IOC type breakdown aggregation
        ioc_breakdown: Dict[str, int] = {}
        for run in runs:
            for ioc_type, count in run.get("ioc_counts", {}).items():
                ioc_breakdown[ioc_type] = ioc_breakdown.get(ioc_type, 0) + count

        # Feed reliability
        total_feed_attempts = feeds_fetched + feeds_failed
        feed_reliability_pct = (
            round((feeds_fetched / total_feed_attempts) * 100, 1)
            if total_feed_attempts > 0 else 100.0
        )

        # v22.0: manifest-level enrichment stats
        kev_count = sum(r.get("kev_count", 0) for r in runs)
        epss_vals = [r["avg_epss"] for r in runs if r.get("avg_epss") is not None]
        avg_epss  = round(sum(epss_vals)/len(epss_vals), 4) if epss_vals else None
        sc_count  = sum(r.get("supply_chain_count", 0) for r in runs)

        return {
            "window_hours": window_hours,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "platform_version": "v22.0",
            "total_runs": total_runs,
            "successful_runs": successful,
            "failed_runs": total_runs - successful,
            "success_rate_pct": round((successful / total_runs) * 100, 1) if total_runs else 0,
            "total_threats_processed": total_processed,
            "total_threats_published": total_published,
            "total_deduplicated": total_deduped,
            "publish_rate_pct": round((total_published / total_processed) * 100, 1) if total_processed else 0,
            "total_iocs_extracted": total_iocs,
            "ioc_type_breakdown": ioc_breakdown,
            "avg_run_time_sec": avg_run_time,
            "total_errors": total_errors,
            "error_rate_per_run": round(total_errors / total_runs, 2) if total_runs else 0,
            "feed_reliability_pct": feed_reliability_pct,
            "feeds_fetched": feeds_fetched,
            "feeds_failed": feeds_failed,
            "kev_detections_total": kev_count,
            "avg_epss_score": avg_epss,
            "supply_chain_detections": sc_count,
        }

    def _load_runs(self) -> List[Dict]:
        try:
            if os.path.exists(TELEMETRY_LOG_PATH):
                with open(TELEMETRY_LOG_PATH, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Metrics load failed: {e}")
        return []

    def _empty_metrics(self) -> Dict:
        return {
            "window_hours": 168,
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "total_runs": 0,
            "message": "No telemetry data available yet.",
        }


# Singleton instance
platform_metrics = PlatformMetrics()
