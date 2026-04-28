#!/usr/bin/env python3
"""
scripts/self_improve_monitor.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Self-Improving Engine: Observability + Anomaly Detection
============================================================================================
PHASE 1: Observability Layer
    Collects: pipeline runtime, failure rates, duplicate intel count, stale intel detection,
              API response health, 404 detection, user activity (conversion signals)

PHASE 2: Anomaly Detection Engine
    Detects: repeated intel (duplicate fingerprint rate), no-new-intel condition,
             abnormal runtime, AI inconsistency (P4 for CRITICAL), feed corruption

OUTPUT: data/system_health.json

SAFETY CONTRACT:
    - READ ONLY: Never modifies core files
    - Never raises to caller; all errors are captured + logged
    - Atomic output write (tmp → fsync → os.replace)
    - Zero regression guaranteed

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.monitor")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
_DATA = _ROOT / "data"
_API  = _ROOT / "api"
_REPORTS = _ROOT / "reports"

HEALTH_OUTPUT  = _DATA / "system_health.json"
MANIFEST_PATH  = _DATA / "feed_manifest.json"
DEDUP_STATE    = _DATA / "processed_intel.json"
TELEMETRY_LOG  = _DATA / "telemetry_log.json"
AUDIT_LOG      = _DATA / "audit_log.json"
SYNC_MARKER    = _DATA / "sync_marker.json"

API_FEED       = _API / "feed.json"
API_LATEST     = _API / "latest.json"
API_STATUS     = _API / "status.json"
API_ENGINES    = _API / "engines.json"
API_STATS      = _API / "stats.json"

# ---------------------------------------------------------------------------
# Anomaly thresholds (tuneable)
# ---------------------------------------------------------------------------
THRESHOLDS = {
    "duplicate_rate_warn":    0.15,   # 15%+ duplicate rate → WARN
    "duplicate_rate_critical":0.40,   # 40%+ → CRITICAL
    "stale_intel_hours":      26,     # Item not updated in 26h → STALE
    "no_new_intel_cycles":    2,      # N cycles with 0 new items → ANOMALY
    "runtime_baseline_s":     120,    # Expected pipeline runtime (seconds)
    "runtime_warn_multiplier":2.0,    # >2x baseline → WARN
    "runtime_crit_multiplier":4.0,    # >4x baseline → CRITICAL
    "min_feed_items":         10,     # Feed below this count → WARN
    "ai_inconsistency_rate":  0.05,   # >5% CRITICAL items with P4 → ANOMALY
    "pro_required_rate":      0.01,   # >1% items with PRO_REQUIRED kill_chain → BUG
    "api_file_max_age_h":     3,      # API file not updated in 3h → WARN
}

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _load_json(path: Path, default: Any = None) -> Any:
    """Safe JSON loader. Returns default on any error."""
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        log.warning("[MONITOR] Failed to load %s: %s", path.name, exc)
        return default


def _atomic_write(path: Path, data: Dict) -> None:
    """Atomic JSON write: tmp → fsync → os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        with open(tmp, "rb") as fh:
            os.fsync(fh.fileno())
    except OSError:
        pass
    os.replace(tmp, path)


def _file_age_hours(path: Path) -> Optional[float]:
    """Return file age in hours, or None if missing."""
    try:
        mtime = path.stat().st_mtime
        return (time.time() - mtime) / 3600.0
    except OSError:
        return None


def _parse_iso(ts: str) -> Optional[datetime]:
    """Parse ISO-8601 string to tz-aware datetime."""
    if not ts:
        return None
    try:
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _item_list(data: Any) -> List[Dict]:
    """Normalise API/manifest JSON to a flat list."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("items", "data", "advisories", "results", "feed"):
            v = data.get(key)
            if isinstance(v, list):
                return v
    return []


# ===========================================================================
# PHASE 1: METRIC COLLECTORS
# ===========================================================================

class MetricCollector:
    """Collects all observability metrics from platform data sources."""

    def __init__(self) -> None:
        self.metrics: Dict[str, Any] = {}
        self._errors: List[str] = []

    # ── 1.1 Pipeline Runtime ───────────────────────────────────────────────

    def collect_pipeline_runtime(self) -> None:
        """Extract last pipeline runtime from telemetry/sync markers."""
        runtime_s = None
        last_run_iso = None
        run_count = 0

        # Try sync_marker first
        sm = _load_json(SYNC_MARKER, {})
        if sm:
            last_run_iso = sm.get("last_sync") or sm.get("timestamp") or sm.get("updated_at")
            run_count = sm.get("total_runs") or sm.get("run_count") or 0

        # Try telemetry log for runtime
        telem = _load_json(TELEMETRY_LOG, [])
        if isinstance(telem, list) and telem:
            last_entry = telem[-1] if isinstance(telem[-1], dict) else {}
            runtime_s = (
                last_entry.get("runtime_s") or
                last_entry.get("duration_s") or
                last_entry.get("elapsed_s")
            )
            if not last_run_iso:
                last_run_iso = last_entry.get("timestamp") or last_entry.get("run_at")
        elif isinstance(telem, dict):
            runtime_s = telem.get("last_runtime_s") or telem.get("runtime_s")
            if not last_run_iso:
                last_run_iso = telem.get("last_run") or telem.get("timestamp")

        # Derive from API file mtime if no telemetry
        if runtime_s is None:
            age_h = _file_age_hours(API_FEED)
            if age_h is not None:
                last_run_iso = last_run_iso or _utc_now_iso()

        self.metrics["pipeline_runtime_s"] = runtime_s
        self.metrics["pipeline_last_run_iso"] = last_run_iso
        self.metrics["pipeline_run_count"] = run_count
        self.metrics["api_feed_age_hours"] = _file_age_hours(API_FEED)
        self.metrics["api_latest_age_hours"] = _file_age_hours(API_LATEST)
        log.info("[MONITOR] Pipeline runtime: %ss, last_run=%s", runtime_s, last_run_iso)

    # ── 1.2 Failure Rates ─────────────────────────────────────────────────

    def collect_failure_rates(self) -> None:
        """Scan audit logs and health files for failure indicators."""
        total_runs = 0
        failed_runs = 0
        last_error = None
        error_types: Dict[str, int] = {}

        # Audit log
        audit = _load_json(AUDIT_LOG, [])
        if isinstance(audit, list):
            for entry in audit:
                if not isinstance(entry, dict):
                    continue
                total_runs += 1
                status = str(entry.get("status") or entry.get("result") or "").lower()
                if status in ("failed", "error", "failure", "critical"):
                    failed_runs += 1
                    err = entry.get("error") or entry.get("message") or "unknown"
                    last_error = str(err)[:200]
                    etype = entry.get("error_type") or entry.get("stage") or "generic"
                    error_types[str(etype)] = error_types.get(str(etype), 0) + 1

        # Health files
        for hfile in (_DATA / "health").iterdir() if (_DATA / "health").exists() else []:
            hdata = _load_json(hfile, {})
            if isinstance(hdata, dict):
                if hdata.get("status") in ("ERROR", "CRITICAL", "FAILED"):
                    failed_runs += 1
                    last_error = hdata.get("error") or last_error

        failure_rate = (failed_runs / total_runs) if total_runs > 0 else 0.0

        self.metrics["pipeline_total_runs"] = total_runs
        self.metrics["pipeline_failed_runs"] = failed_runs
        self.metrics["pipeline_failure_rate"] = round(failure_rate, 4)
        self.metrics["pipeline_last_error"] = last_error
        self.metrics["pipeline_error_types"] = error_types
        log.info("[MONITOR] Failure rate: %.1f%% (%d/%d)", failure_rate * 100, failed_runs, total_runs)

    # ── 1.3 Duplicate Intel Count ─────────────────────────────────────────

    def collect_dedup_metrics(self) -> None:
        """Analyse dedup state for duplicate fingerprint rate."""
        dedup = _load_json(DEDUP_STATE, {})
        fingerprints = dedup.get("fingerprints", {})
        total_seen = dedup.get("total_seen", len(fingerprints))
        last_updated = dedup.get("last_updated", "")

        # Compare against feed item count to derive dup rate
        feed_data = _load_json(API_FEED, [])
        feed_items = _item_list(feed_data)
        feed_count = len(feed_items)

        # Duplicate rate = items that exist in state but NOT in current feed
        # (approximation: items in feed / total seen)
        seen_in_feed = min(feed_count, total_seen)
        skip_rate = max(0.0, 1.0 - (seen_in_feed / total_seen)) if total_seen > 0 else 0.0

        # Count items still carrying PRO_REQUIRED (APEX AI bug indicator)
        pro_required_count = 0
        for item in feed_items:
            apex = item.get("apex_ai") or {}
            if isinstance(apex, dict) and apex.get("kill_chain") == "PRO_REQUIRED":
                pro_required_count += 1

        self.metrics["dedup_total_seen"] = total_seen
        self.metrics["dedup_last_updated"] = last_updated
        self.metrics["dedup_feed_count"] = feed_count
        self.metrics["dedup_skip_rate_approx"] = round(skip_rate, 4)
        self.metrics["dedup_pro_required_count"] = pro_required_count
        self.metrics["dedup_pro_required_rate"] = round(
            pro_required_count / feed_count if feed_count > 0 else 0.0, 4
        )
        log.info(
            "[MONITOR] Dedup: %d seen, ~%.1f%% skip rate, %d PRO_REQUIRED items",
            total_seen, skip_rate * 100, pro_required_count,
        )

    # ── 1.4 Stale Intel Detection ─────────────────────────────────────────

    def collect_stale_intel(self) -> None:
        """Detect intel items that haven't been updated past threshold."""
        threshold = THRESHOLDS["stale_intel_hours"]
        cutoff = _utc_now() - timedelta(hours=threshold)

        feed_data = _load_json(API_FEED, [])
        feed_items = _item_list(feed_data)

        stale_count = 0
        total_with_ts = 0
        newest_ts: Optional[datetime] = None
        oldest_ts: Optional[datetime] = None

        for item in feed_items:
            ts_str = (
                item.get("processed_at") or item.get("timestamp") or
                item.get("published_at") or item.get("published") or ""
            )
            dt = _parse_iso(ts_str)
            if dt:
                total_with_ts += 1
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                if dt < cutoff:
                    stale_count += 1
                if newest_ts is None or dt > newest_ts:
                    newest_ts = dt
                if oldest_ts is None or dt < oldest_ts:
                    oldest_ts = dt

        stale_rate = stale_count / total_with_ts if total_with_ts > 0 else 0.0

        # No-new-intel signal: if newest_ts is older than pipeline cycle threshold
        hours_since_newest = (
            (_utc_now() - newest_ts).total_seconds() / 3600.0
            if newest_ts else None
        )

        self.metrics["stale_intel_count"] = stale_count
        self.metrics["stale_intel_rate"] = round(stale_rate, 4)
        self.metrics["stale_intel_threshold_hours"] = threshold
        self.metrics["intel_newest_ts"] = newest_ts.isoformat() if newest_ts else None
        self.metrics["intel_oldest_ts"] = oldest_ts.isoformat() if oldest_ts else None
        self.metrics["intel_hours_since_newest"] = round(hours_since_newest, 2) if hours_since_newest is not None else None
        log.info(
            "[MONITOR] Stale intel: %d/%d items (>%dh old), newest=%.1fh ago",
            stale_count, total_with_ts, threshold,
            hours_since_newest if hours_since_newest is not None else -1,
        )

    # ── 1.5 API Response Health ───────────────────────────────────────────

    def collect_api_health(self) -> None:
        """Check all API data files for health indicators."""
        api_checks: Dict[str, Dict] = {}
        max_age_h = THRESHOLDS["api_file_max_age_h"]

        for label, path in [
            ("feed",    API_FEED),
            ("latest",  API_LATEST),
            ("status",  API_STATUS),
            ("engines", API_ENGINES),
            ("stats",   API_STATS),
        ]:
            age_h = _file_age_hours(path)
            exists = path.exists()
            data = _load_json(path, None)
            items = _item_list(data) if data is not None else []
            sz = path.stat().st_size if exists else 0

            api_checks[label] = {
                "exists": exists,
                "size_bytes": sz,
                "item_count": len(items),
                "age_hours": round(age_h, 2) if age_h is not None else None,
                "stale": age_h > max_age_h if age_h is not None else True,
                "empty": len(items) == 0 and exists,
            }

        # Check status.json for explicit error flags
        status_data = _load_json(API_STATUS, {})
        api_status_ok = isinstance(status_data, dict) and status_data.get("status") not in ("ERROR", "DOWN")

        self.metrics["api_checks"] = api_checks
        self.metrics["api_status_ok"] = api_status_ok
        self.metrics["api_feed_item_count"] = api_checks.get("feed", {}).get("item_count", 0)
        log.info("[MONITOR] API health: feed=%d items, latest=%d items",
                 api_checks.get("feed", {}).get("item_count", 0),
                 api_checks.get("latest", {}).get("item_count", 0))

    # ── 1.6 404 / Error Detection ─────────────────────────────────────────

    def collect_404_errors(self) -> None:
        """Detect 404s and broken URLs in feed items."""
        broken_urls: List[str] = []
        missing_urls: int = 0

        feed_data = _load_json(API_FEED, [])
        feed_items = _item_list(feed_data)

        for item in feed_items:
            url = item.get("source_url") or item.get("report_url") or item.get("link") or ""
            if not url:
                missing_urls += 1
            elif any(pat in url.lower() for pat in ["404", "not-found", "error", "missing"]):
                broken_urls.append(url[:120])

        # Scan telemetry log for 404 patterns
        telem = _load_json(TELEMETRY_LOG, [])
        telem_list = telem if isinstance(telem, list) else []
        telem_404s = sum(
            1 for e in telem_list
            if isinstance(e, dict) and (
                "404" in str(e.get("error", "")) or
                "not found" in str(e.get("message", "")).lower()
            )
        )

        self.metrics["broken_urls"] = broken_urls[:20]   # cap at 20 for report size
        self.metrics["broken_url_count"] = len(broken_urls)
        self.metrics["missing_url_count"] = missing_urls
        self.metrics["telemetry_404_count"] = telem_404s
        log.info("[MONITOR] 404 check: %d broken, %d missing URLs, %d telemetry 404s",
                 len(broken_urls), missing_urls, telem_404s)

    # ── 1.7 User Activity / Conversion Signals ───────────────────────────

    def collect_user_activity(self) -> None:
        """Read revenue/growth signals as conversion proxy."""
        rev_log = _load_json(_DATA / "revenue_log.json", [])
        rev_intel = _load_json(_DATA / "revenue_intelligence.json", {})

        total_events = len(rev_log) if isinstance(rev_log, list) else 0
        recent_conversions = 0
        recent_cutoff = _utc_now() - timedelta(hours=24)

        if isinstance(rev_log, list):
            for entry in rev_log:
                if not isinstance(entry, dict):
                    continue
                ts = _parse_iso(entry.get("timestamp") or entry.get("created_at") or "")
                if ts:
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if ts >= recent_cutoff:
                        recent_conversions += 1

        mrr = None
        if isinstance(rev_intel, dict):
            mrr = (
                rev_intel.get("mrr") or rev_intel.get("monthly_recurring_revenue") or
                rev_intel.get("revenue_mrr")
            )

        self.metrics["user_total_revenue_events"] = total_events
        self.metrics["user_conversions_24h"] = recent_conversions
        self.metrics["user_mrr"] = mrr
        log.info("[MONITOR] User activity: %d events, %d conversions/24h, MRR=%s",
                 total_events, recent_conversions, mrr)

    # ── Collector Orchestrator ────────────────────────────────────────────

    def collect_all(self) -> Dict[str, Any]:
        """Run all metric collectors. Returns full metrics dict."""
        collectors = [
            ("pipeline_runtime",  self.collect_pipeline_runtime),
            ("failure_rates",     self.collect_failure_rates),
            ("dedup_metrics",     self.collect_dedup_metrics),
            ("stale_intel",       self.collect_stale_intel),
            ("api_health",        self.collect_api_health),
            ("404_errors",        self.collect_404_errors),
            ("user_activity",     self.collect_user_activity),
        ]
        for name, fn in collectors:
            try:
                fn()
            except Exception as exc:
                err = f"[MONITOR] Collector '{name}' failed: {exc}"
                log.error(err)
                self._errors.append(err)

        self.metrics["collector_errors"] = self._errors
        self.metrics["collected_at"] = _utc_now_iso()
        return self.metrics


# ===========================================================================
# PHASE 2: ANOMALY DETECTION ENGINE
# ===========================================================================

class Anomaly:
    """Represents a single detected anomaly."""
    def __init__(
        self,
        anomaly_id: str,
        severity: str,          # CRITICAL | HIGH | MEDIUM | LOW
        category: str,          # DEDUP | STALE | RUNTIME | AI_INCONSISTENCY | FEED | API | SECURITY
        title: str,
        description: str,
        metric_key: str = "",
        metric_value: Any = None,
        threshold: Any = None,
        recommendation: str = "",
    ) -> None:
        self.anomaly_id = anomaly_id
        self.severity = severity
        self.category = category
        self.title = title
        self.description = description
        self.metric_key = metric_key
        self.metric_value = metric_value
        self.threshold = threshold
        self.recommendation = recommendation
        self.detected_at = _utc_now_iso()

    def to_dict(self) -> Dict:
        return {
            "anomaly_id":    self.anomaly_id,
            "severity":      self.severity,
            "category":      self.category,
            "title":         self.title,
            "description":   self.description,
            "metric_key":    self.metric_key,
            "metric_value":  self.metric_value,
            "threshold":     self.threshold,
            "recommendation":self.recommendation,
            "detected_at":   self.detected_at,
        }


class AnomalyDetector:
    """
    Phase 2: Detects anomalies from collected metrics.

    Detects:
        - Repeated intel (high duplicate fingerprint rate)
        - No-new-intel condition (>N cycles with no new data)
        - Abnormal pipeline runtime
        - AI inconsistency (CRITICAL items scoring P4, PRO_REQUIRED kill chains)
        - Feed corruption (missing fields, malformed data)
        - API staleness
        - Feed volume drops
    """

    def __init__(self, metrics: Dict[str, Any]) -> None:
        self.metrics = metrics
        self.anomalies: List[Anomaly] = []
        self._seq = 0

    def _next_id(self, prefix: str) -> str:
        self._seq += 1
        return f"ANO-{prefix}-{self._seq:03d}"

    def _add(self, anomaly: Anomaly) -> None:
        self.anomalies.append(anomaly)
        log.warning("[ANOMALY] %s [%s] %s", anomaly.severity, anomaly.category, anomaly.title)

    # ── 2.1 Duplicate Rate Anomaly ────────────────────────────────────────

    def detect_duplicate_rate(self) -> None:
        rate = self.metrics.get("dedup_skip_rate_approx", 0.0)
        crit = THRESHOLDS["duplicate_rate_critical"]
        warn = THRESHOLDS["duplicate_rate_warn"]

        if rate >= crit:
            self._add(Anomaly(
                self._next_id("DUP"),
                "CRITICAL", "DEDUP",
                "Critical duplicate intel rate detected",
                f"Duplicate rate is {rate*100:.1f}%, exceeding critical threshold of {crit*100:.0f}%. "
                "Dedup engine may be bypassed or fingerprint logic is broken.",
                "dedup_skip_rate_approx", rate, crit,
                "Audit dedup_state.py fingerprint logic. Re-run enforce_feed_uniqueness on manifest.",
            ))
        elif rate >= warn:
            self._add(Anomaly(
                self._next_id("DUP"),
                "HIGH", "DEDUP",
                "High duplicate intel rate detected",
                f"Duplicate rate is {rate*100:.1f}%, exceeding warning threshold of {warn*100:.0f}%.",
                "dedup_skip_rate_approx", rate, warn,
                "Review feed sources for overlapping content. Consider tightening title similarity threshold.",
            ))

    # ── 2.2 No-New-Intel Condition ────────────────────────────────────────

    def detect_no_new_intel(self) -> None:
        hours = self.metrics.get("intel_hours_since_newest")
        feed_count = self.metrics.get("api_feed_item_count", 0)
        threshold_h = THRESHOLDS["stale_intel_hours"]

        if feed_count == 0:
            self._add(Anomaly(
                self._next_id("NNI"),
                "CRITICAL", "FEED",
                "API feed is completely empty",
                "api/feed.json contains zero intel items. Ingestion pipeline has failed or feed was wiped.",
                "api_feed_item_count", 0, THRESHOLDS["min_feed_items"],
                "Check run_pipeline.py logs. Verify feed source connectivity. Restore from manifest backup.",
            ))
        elif hours is not None and hours > threshold_h:
            self._add(Anomaly(
                self._next_id("NNI"),
                "HIGH", "STALE",
                "No new intel ingested for extended period",
                f"Newest intel item is {hours:.1f}h old, exceeding {threshold_h}h threshold. "
                "Feed sources may be unreachable or pipeline is failing silently.",
                "intel_hours_since_newest", round(hours, 2), threshold_h,
                "Verify feed source URLs. Check GitHub Actions workflow status. Trigger manual pipeline run.",
            ))
        elif feed_count < THRESHOLDS["min_feed_items"]:
            self._add(Anomaly(
                self._next_id("NNI"),
                "MEDIUM", "FEED",
                "Feed item count critically low",
                f"Only {feed_count} items in API feed (minimum: {THRESHOLDS['min_feed_items']}). "
                "Possible partial ingestion failure.",
                "api_feed_item_count", feed_count, THRESHOLDS["min_feed_items"],
                "Investigate ingestion stage. Check for silent filter over-rejection.",
            ))

    # ── 2.3 Abnormal Runtime ──────────────────────────────────────────────

    def detect_abnormal_runtime(self) -> None:
        runtime = self.metrics.get("pipeline_runtime_s")
        if runtime is None:
            # Can't detect without telemetry — soft warn
            return

        baseline = THRESHOLDS["runtime_baseline_s"]
        crit_threshold = baseline * THRESHOLDS["runtime_crit_multiplier"]
        warn_threshold = baseline * THRESHOLDS["runtime_warn_multiplier"]

        if runtime >= crit_threshold:
            self._add(Anomaly(
                self._next_id("RUN"),
                "HIGH", "RUNTIME",
                "Pipeline runtime critically elevated",
                f"Pipeline took {runtime:.0f}s ({runtime/baseline:.1f}x baseline of {baseline}s). "
                "Possible infinite loop, external API timeout, or resource exhaustion.",
                "pipeline_runtime_s", runtime, crit_threshold,
                "Profile slow stages with pipeline_audit.py. Check external API rate limits. Consider async ingestion.",
            ))
        elif runtime >= warn_threshold:
            self._add(Anomaly(
                self._next_id("RUN"),
                "MEDIUM", "RUNTIME",
                "Pipeline runtime above normal baseline",
                f"Pipeline took {runtime:.0f}s ({runtime/baseline:.1f}x baseline of {baseline}s).",
                "pipeline_runtime_s", runtime, warn_threshold,
                "Monitor for consistent slow runs. Review bottleneck stages.",
            ))

    # ── 2.4 AI Inconsistency Detection ───────────────────────────────────

    def detect_ai_inconsistency(self) -> None:
        """Detect CRITICAL-severity items scored P4, and PRO_REQUIRED kill chains."""

        # Check PRO_REQUIRED residue
        pro_rate = self.metrics.get("dedup_pro_required_rate", 0.0)
        pro_count = self.metrics.get("dedup_pro_required_count", 0)
        threshold = THRESHOLDS["pro_required_rate"]

        if pro_rate > threshold:
            self._add(Anomaly(
                self._next_id("AI"),
                "CRITICAL", "AI_INCONSISTENCY",
                "PRO_REQUIRED kill_chain values detected in live feed",
                f"{pro_count} items ({pro_rate*100:.1f}%) still carry kill_chain='PRO_REQUIRED'. "
                "APEX AI engine P0 fix has not been applied to current feed. "
                "Users are seeing paywall artifacts in the free tier.",
                "dedup_pro_required_rate", pro_rate, threshold,
                "Trigger CI pipeline to run master_p0_fix.py against current API files. "
                "Verify ALWAYS-rebuild apex_ai logic is active.",
            ))
        elif pro_count > 0:
            self._add(Anomaly(
                self._next_id("AI"),
                "HIGH", "AI_INCONSISTENCY",
                "Residual PRO_REQUIRED entries detected",
                f"{pro_count} items still carry PRO_REQUIRED kill_chain. "
                "P0 fix applied but stale items remain in circulation.",
                "dedup_pro_required_count", pro_count, 0,
                "Run master_p0_fix.py fix_api_feed() to force-rebuild all apex_ai blocks.",
            ))

        # Scan latest.json for P4 + CRITICAL combination
        latest_data = _load_json(API_LATEST, [])
        latest_items = _item_list(latest_data)
        p4_critical = 0
        p4_masked_actor = 0

        for item in latest_items:
            apex = item.get("apex_ai") or {}
            if not isinstance(apex, dict):
                continue
            sev = str(item.get("severity") or apex.get("threat_level") or "").upper()
            pri = str(apex.get("soc_priority") or "").upper()
            actor = str(apex.get("actor_fingerprint") or "")

            if sev == "CRITICAL" and pri == "P4":
                p4_critical += 1
            if "****" in actor:
                p4_masked_actor += 1

        ai_incon_rate = p4_critical / len(latest_items) if latest_items else 0.0
        threshold_ai = THRESHOLDS["ai_inconsistency_rate"]

        if ai_incon_rate > threshold_ai:
            self._add(Anomaly(
                self._next_id("AI"),
                "CRITICAL", "AI_INCONSISTENCY",
                "CRITICAL intel items incorrectly scored P4",
                f"{p4_critical}/{len(latest_items)} CRITICAL-severity items have SOC priority P4. "
                "APEX AI scoring logic is broken — analysts will deprioritize critical threats.",
                "ai_p4_critical_rate", round(ai_incon_rate, 4), threshold_ai,
                "Verify risk_score thresholds in build_apex_ai(). Force unconditional apex_ai rebuild.",
            ))

        if p4_masked_actor > 0:
            self._add(Anomaly(
                self._next_id("AI"),
                "HIGH", "AI_INCONSISTENCY",
                "Masked actor fingerprints detected in live feed",
                f"{p4_masked_actor} items carry masked actor_fingerprint patterns (e.g. 'CDB-CVE-****'). "
                "APEX AI actor resolution is not applying P0 fix.",
                "masked_actor_count", p4_masked_actor, 0,
                "Re-run master_p0_fix.py. Verify _resolve_actor_fingerprint() returns UNATTRIBUTED for generic tags.",
            ))

    # ── 2.5 Feed Corruption Detection ────────────────────────────────────

    def detect_feed_corruption(self) -> None:
        """Detect malformed items, missing required fields, encoding issues."""
        feed_data = _load_json(API_FEED, None)
        if feed_data is None:
            self._add(Anomaly(
                self._next_id("COR"),
                "CRITICAL", "FEED",
                "API feed.json is missing or unreadable",
                "api/feed.json cannot be loaded. Feed is completely down.",
                "api_feed_exists", False, True,
                "Check disk permissions. Restore from data/feed_manifest.json backup.",
            ))
            return

        feed_items = _item_list(feed_data)
        required_fields = {"id", "title", "risk_score"}
        corrupt_count = 0
        missing_field_counts: Dict[str, int] = {}

        for item in feed_items:
            if not isinstance(item, dict):
                corrupt_count += 1
                continue
            for field in required_fields:
                if not item.get(field):
                    missing_field_counts[field] = missing_field_counts.get(field, 0) + 1

        total = len(feed_items) if feed_items else 1
        corruption_rate = corrupt_count / total

        if corrupt_count > 0:
            self._add(Anomaly(
                self._next_id("COR"),
                "HIGH", "FEED",
                "Corrupt (non-dict) items detected in feed",
                f"{corrupt_count} feed items are not valid JSON objects. "
                "Likely caused by serialisation error in pipeline.",
                "feed_corrupt_count", corrupt_count, 0,
                "Run validate_intel_schema.py. Audit JSON serialisation in run_pipeline.py.",
            ))

        for field, count in missing_field_counts.items():
            rate = count / total
            if rate > 0.05:  # >5% items missing this field
                self._add(Anomaly(
                    self._next_id("COR"),
                    "MEDIUM", "FEED",
                    f"Required field '{field}' missing in {rate*100:.0f}% of feed items",
                    f"{count}/{total} feed items are missing '{field}'. "
                    "Ingestion or enrichment stage may be stripping this field.",
                    f"missing_{field}_rate", round(rate, 4), 0.05,
                    f"Audit enrichment pipeline for '{field}' propagation. Check paywall_filter.py field stripping.",
                ))

    # ── 2.6 API Staleness ────────────────────────────────────────────────

    def detect_api_staleness(self) -> None:
        """Flag API files not updated within threshold."""
        api_checks = self.metrics.get("api_checks", {})
        max_age = THRESHOLDS["api_file_max_age_h"]

        critical_apis = ["feed", "latest"]
        for label in critical_apis:
            check = api_checks.get(label, {})
            age = check.get("age_hours")
            if not check.get("exists", False):
                self._add(Anomaly(
                    self._next_id("API"),
                    "CRITICAL", "API",
                    f"API file api/{label}.json does not exist",
                    f"Required API endpoint file is missing. Dashboard will show no data.",
                    f"api_{label}_exists", False, True,
                    f"Run pipeline to regenerate api/{label}.json.",
                ))
            elif age is not None and age > max_age * 2:
                self._add(Anomaly(
                    self._next_id("API"),
                    "HIGH", "API",
                    f"API api/{label}.json critically stale ({age:.1f}h old)",
                    f"File is {age:.1f}h old, exceeding {max_age*2}h critical threshold. "
                    "Scheduled pipeline may not be running.",
                    f"api_{label}_age_hours", round(age, 2), max_age * 2,
                    "Check GitHub Actions cron schedule. Verify sentinel-blogger.yml workflow.",
                ))
            elif age is not None and age > max_age:
                self._add(Anomaly(
                    self._next_id("API"),
                    "MEDIUM", "API",
                    f"API api/{label}.json stale ({age:.1f}h old)",
                    f"File is {age:.1f}h old, exceeding {max_age}h warning threshold.",
                    f"api_{label}_age_hours", round(age, 2), max_age,
                    "Monitor pipeline schedule. Consider reducing CI cadence.",
                ))

    # ── Detection Orchestrator ────────────────────────────────────────────

    def detect_all(self) -> List[Dict]:
        """Run all anomaly detectors. Returns list of anomaly dicts."""
        detectors = [
            self.detect_duplicate_rate,
            self.detect_no_new_intel,
            self.detect_abnormal_runtime,
            self.detect_ai_inconsistency,
            self.detect_feed_corruption,
            self.detect_api_staleness,
        ]
        for detector in detectors:
            try:
                detector()
            except Exception as exc:
                log.error("[ANOMALY] Detector %s failed: %s", detector.__name__, exc)

        # Sort by severity
        _SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.anomalies.sort(key=lambda a: _SEVERITY_ORDER.get(a.severity, 9))

        log.info(
            "[ANOMALY] Detection complete: %d anomalies (%d CRITICAL, %d HIGH, %d MEDIUM)",
            len(self.anomalies),
            sum(1 for a in self.anomalies if a.severity == "CRITICAL"),
            sum(1 for a in self.anomalies if a.severity == "HIGH"),
            sum(1 for a in self.anomalies if a.severity == "MEDIUM"),
        )
        return [a.to_dict() for a in self.anomalies]


# ===========================================================================
# Health Score Calculator
# ===========================================================================

def _calculate_health_score(metrics: Dict, anomalies: List[Dict]) -> Dict[str, Any]:
    """
    Calculates a 0-100 health score with letter grade.

    Deductions:
        CRITICAL anomaly: -20 pts (max -60)
        HIGH anomaly:     -10 pts (max -30)
        MEDIUM anomaly:    -5 pts (max -15)
        LOW anomaly:       -2 pts (max -6)
    """
    score = 100
    deductions: List[str] = []

    _DEDUCTIONS = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2}
    _MAX_DEDUCTIONS = {"CRITICAL": 60, "HIGH": 30, "MEDIUM": 15, "LOW": 6}
    _buckets: Dict[str, int] = {}

    for anomaly in anomalies:
        sev = anomaly.get("severity", "LOW")
        per_item = _DEDUCTIONS.get(sev, 0)
        _buckets[sev] = _buckets.get(sev, 0) + per_item
        cap = _MAX_DEDUCTIONS.get(sev, 0)
        # Apply deduction but respect cap
        if _buckets[sev] <= cap:
            score -= per_item
            deductions.append(f"-{per_item} [{sev}] {anomaly.get('title', '')[:60]}")

    score = max(0, score)

    # Grade mapping
    if score >= 90:   grade, status = "A", "HEALTHY"
    elif score >= 75: grade, status = "B", "GOOD"
    elif score >= 60: grade, status = "C", "DEGRADED"
    elif score >= 40: grade, status = "D", "CRITICAL"
    else:             grade, status = "F", "EMERGENCY"

    return {
        "score":      score,
        "grade":      grade,
        "status":     status,
        "deductions": deductions[:20],
    }


# ===========================================================================
# Main Monitor Entry Point
# ===========================================================================

def run_monitor(dry_run: bool = False) -> Dict[str, Any]:
    """
    Full Phase 1+2 execution:
        1. Collect all metrics
        2. Detect all anomalies
        3. Calculate health score
        4. Write data/system_health.json
    Returns the full health report dict.
    """
    log.info("[MONITOR] ====== SENTINEL APEX MONITOR CYCLE START ======")
    started = _utc_now_iso()

    # Phase 1: Collect
    collector = MetricCollector()
    metrics = collector.collect_all()

    # Phase 2: Detect
    detector = AnomalyDetector(metrics)
    anomalies = detector.detect_all()

    # Health score
    health = _calculate_health_score(metrics, anomalies)

    report: Dict[str, Any] = {
        "schema_version":  "2.0",
        "generated_at":    _utc_now_iso(),
        "monitor_started": started,
        "health":          health,
        "anomalies":       anomalies,
        "anomaly_count":   len(anomalies),
        "metrics":         metrics,
        "thresholds":      THRESHOLDS,
        "monitor_version": "1.0.0",
    }

    if not dry_run:
        try:
            _atomic_write(HEALTH_OUTPUT, report)
            log.info(
                "[MONITOR] Health report written: %s (score=%d/%s, anomalies=%d)",
                HEALTH_OUTPUT, health["score"], health["grade"], len(anomalies),
            )
        except Exception as exc:
            log.error("[MONITOR] Failed to write health report: %s", exc)

    log.info("[MONITOR] ====== MONITOR CYCLE COMPLETE: score=%d [%s] ======",
             health["score"], health["status"])
    return report


# ===========================================================================
# CLI
# ===========================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [monitor] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    parser = argparse.ArgumentParser(description="SENTINEL APEX — Self-Improving Monitor")
    parser.add_argument("--dry-run", action="store_true", help="Run without writing output")
    parser.add_argument("--json", action="store_true", help="Print full JSON report to stdout")
    parser.add_argument("--anomalies-only", action="store_true", help="Print anomalies summary only")
    args = parser.parse_args()

    report = run_monitor(dry_run=args.dry_run)

    if args.json:
        print(json.dumps(report, indent=2))
    elif args.anomalies_only:
        print(f"\n=== ANOMALY REPORT [{report['health']['status']} — Score: {report['health']['score']}/100] ===")
        for a in report["anomalies"]:
            print(f"  [{a['severity']:8s}] [{a['category']:18s}] {a['title']}")
            print(f"           Rec: {a['recommendation'][:100]}")
    else:
        h = report["health"]
        print(f"\n{'='*60}")
        print(f"  SENTINEL APEX — SYSTEM HEALTH REPORT")
        print(f"  Score: {h['score']}/100  Grade: {h['grade']}  Status: {h['status']}")
        print(f"  Anomalies: {report['anomaly_count']}")
        print(f"  Generated: {report['generated_at']}")
        print(f"{'='*60}")
        for a in report["anomalies"]:
            print(f"  [{a['severity']:8s}] {a['title']}")
        print(f"\nFeed: {report['metrics'].get('api_feed_item_count','?')} items | "
              f"Dedup: {report['metrics'].get('dedup_total_seen','?')} fingerprints | "
              f"PRO_REQUIRED: {report['metrics'].get('dedup_pro_required_count','?')} items")
        if not args.dry_run:
            print(f"\nReport written to: {HEALTH_OUTPUT}")
