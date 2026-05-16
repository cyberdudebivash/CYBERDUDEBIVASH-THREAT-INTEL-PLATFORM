#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX
scripts/observability_exporter.py — Prometheus-Compatible Metrics Exporter (v156.4.0)
=======================================================================================
Exports platform metrics in Prometheus text format for ingestion by Grafana Cloud
or any OpenMetrics-compatible backend.

METRICS EXPORTED:
  sentinel_pipeline_duration_seconds    — Total CI pipeline duration
  sentinel_report_count_total           — Total published intelligence reports
  sentinel_stix_bundles_total           — STIX bundles generated
  sentinel_r2_upload_count              — R2 objects uploaded
  sentinel_manifest_items_total         — Manifest item count
  sentinel_convergence_exit_code        — Deployment convergence result (0=success)
  sentinel_pipeline_version_info        — Pipeline version as label
  sentinel_disk_free_gb                 — Runner disk free (GB) at deployment time
  sentinel_intel_feed_items_total       — Active feed items count
  sentinel_vuln_count_by_severity       — Vulnerability count by severity

PUSH TARGETS:
  1. Grafana Cloud Prometheus push endpoint (if GRAFANA_PUSH_URL configured)
  2. data/observability/metrics-latest.txt — Prometheus text format file

Author: CYBERDUDEBIVASH SENTINEL APEX v156.4.0
"""
from __future__ import annotations
import json
import logging
import os
import pathlib
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(level=logging.INFO, format="[OBS-EXPORTER] %(message)s")
log = logging.getLogger("obs-exporter")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
OBS_DIR = REPO_ROOT / "data" / "observability"
METRICS_FILE = OBS_DIR / "metrics-latest.txt"
TELEMETRY_FILE = REPO_ROOT / "data" / "telemetry" / "ci_run_latest.json"
FEED_FILE = REPO_ROOT / "api" / "feed.json"
MANIFEST_FILE = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
AUDIT_FILE = REPO_ROOT / "data" / "security" / "dependency_audit.json"

GRAFANA_PUSH_URL = os.environ.get("GRAFANA_PUSH_URL", "")
GRAFANA_API_KEY = os.environ.get("GRAFANA_API_KEY", "")
PLATFORM_VERSION = os.environ.get("PIPELINE_VERSION", "unknown")
RUN_ID = os.environ.get("GITHUB_RUN_ID", "local")
RUN_NUMBER = os.environ.get("GITHUB_RUN_NUMBER", "0")
GITHUB_REF = os.environ.get("GITHUB_REF", "refs/heads/main")
BRANCH = GITHUB_REF.replace("refs/heads/", "")


def _load_json(path: pathlib.Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _collect_metrics() -> dict[str, Any]:
    """Collect all platform metrics from data files."""
    metrics = {}

    # From telemetry file
    telemetry = _load_json(TELEMETRY_FILE, {})
    metrics["pipeline_version"] = telemetry.get("pipeline_version", PLATFORM_VERSION)
    metrics["run_id"] = telemetry.get("run_id", RUN_ID)

    # From environment (set by GitHub Actions)
    metrics["report_count"] = int(os.environ.get("REPORT_COUNT", 0))
    metrics["stix_bundles"] = int(os.environ.get("STIX_NEW_BUNDLES", 0))
    metrics["r2_upload_count"] = int(os.environ.get("R2_UPLOAD_COUNT", 0))
    metrics["manifest_count"] = int(os.environ.get("MANIFEST_FINAL_COUNT", 0))
    metrics["convergence_exit_code"] = int(os.environ.get("CONVERGENCE_EXIT_CODE", -1))
    metrics["report_elapsed_min"] = int(os.environ.get("REPORT_ELAPSED", 0))

    # Pipeline duration from timestamps
    try:
        pipeline_start = os.environ.get("PIPELINE_START_TS", "")
        if pipeline_start:
            start = float(pipeline_start)
            metrics["pipeline_duration_seconds"] = time.time() - start
        else:
            metrics["pipeline_duration_seconds"] = 0
    except Exception:
        metrics["pipeline_duration_seconds"] = 0

    # Feed items
    feed = _load_json(FEED_FILE, [])
    if isinstance(feed, list):
        metrics["feed_items"] = len(feed)
    elif isinstance(feed, dict):
        metrics["feed_items"] = len(feed.get("items", feed.get("advisories", [])))
    else:
        metrics["feed_items"] = 0

    # Manifest items
    manifest = _load_json(MANIFEST_FILE, {})
    items = manifest.get("items", manifest.get("advisories", []))
    metrics["manifest_items"] = len(items) if isinstance(items, list) else 0

    # Dependency audit
    audit = _load_json(AUDIT_FILE, {})
    summary = audit.get("summary", {})
    metrics["vuln_critical"] = summary.get("critical", 0)
    metrics["vuln_high"] = summary.get("high", 0)
    metrics["vuln_medium"] = summary.get("medium", 0)
    metrics["vuln_low"] = summary.get("low", 0)

    return metrics


def _format_prometheus(metrics: dict[str, Any]) -> str:
    """Format metrics as Prometheus text exposition format."""
    ts_ms = int(time.time() * 1000)
    ver = metrics.get("pipeline_version", PLATFORM_VERSION).replace('"', '')
    branch = BRANCH.replace('"', '').replace("'", "")
    labels = f'pipeline_version="{ver}",branch="{branch}",run_id="{RUN_ID}"'

    lines = [
        f"# HELP sentinel_report_count_total Total published intelligence reports",
        f"# TYPE sentinel_report_count_total gauge",
        f"sentinel_report_count_total{{{labels}}} {metrics.get('report_count', 0)} {ts_ms}",
        "",
        f"# HELP sentinel_stix_bundles_total STIX bundles generated",
        f"# TYPE sentinel_stix_bundles_total gauge",
        f"sentinel_stix_bundles_total{{{labels}}} {metrics.get('stix_bundles', 0)} {ts_ms}",
        "",
        f"# HELP sentinel_r2_upload_count_total R2 objects uploaded",
        f"# TYPE sentinel_r2_upload_count_total gauge",
        f"sentinel_r2_upload_count_total{{{labels}}} {metrics.get('r2_upload_count', 0)} {ts_ms}",
        "",
        f"# HELP sentinel_manifest_items_total Manifest item count",
        f"# TYPE sentinel_manifest_items_total gauge",
        f"sentinel_manifest_items_total{{{labels}}} {metrics.get('manifest_items', 0)} {ts_ms}",
        "",
        f"# HELP sentinel_feed_items_total Active feed items",
        f"# TYPE sentinel_feed_items_total gauge",
        f"sentinel_feed_items_total{{{labels}}} {metrics.get('feed_items', 0)} {ts_ms}",
        "",
        f"# HELP sentinel_convergence_exit_code Deployment convergence result (0=success)",
        f"# TYPE sentinel_convergence_exit_code gauge",
        f"sentinel_convergence_exit_code{{{labels}}} {metrics.get('convergence_exit_code', -1)} {ts_ms}",
        "",
        f"# HELP sentinel_report_generation_minutes Report generation elapsed time (minutes)",
        f"# TYPE sentinel_report_generation_minutes gauge",
        f"sentinel_report_generation_minutes{{{labels}}} {metrics.get('report_elapsed_min', 0)} {ts_ms}",
        "",
        f"# HELP sentinel_vuln_count Dependency vulnerability count by severity",
        f"# TYPE sentinel_vuln_count gauge",
        f'sentinel_vuln_count{{severity="CRITICAL",{labels}}} {metrics.get("vuln_critical", 0)} {ts_ms}',
        f'sentinel_vuln_count{{severity="HIGH",{labels}}} {metrics.get("vuln_high", 0)} {ts_ms}',
        f'sentinel_vuln_count{{severity="MEDIUM",{labels}}} {metrics.get("vuln_medium", 0)} {ts_ms}',
        f'sentinel_vuln_count{{severity="LOW",{labels}}} {metrics.get("vuln_low", 0)} {ts_ms}',
        "",
        f"# HELP sentinel_pipeline_info Pipeline version information",
        f"# TYPE sentinel_pipeline_info gauge",
        f"sentinel_pipeline_info{{{labels}}} 1 {ts_ms}",
        "",
    ]
    return "\n".join(lines)


def push_to_grafana(metrics_text: str) -> bool:
    """Push metrics to Grafana Cloud Prometheus push endpoint."""
    if not GRAFANA_PUSH_URL or not GRAFANA_API_KEY:
        log.info("Grafana push not configured (GRAFANA_PUSH_URL/GRAFANA_API_KEY not set) — skipping remote push")
        return False

    try:
        data = metrics_text.encode("utf-8")
        req = urllib.request.Request(
            GRAFANA_PUSH_URL,
            data=data,
            headers={
                "Authorization": f"Bearer {GRAFANA_API_KEY}",
                "Content-Type": "text/plain; version=0.0.4",
                "User-Agent": f"SENTINEL-APEX/{PLATFORM_VERSION}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            log.info("Grafana push successful: HTTP %d", resp.status)
            return True
    except urllib.error.HTTPError as e:
        log.warning("Grafana push HTTP error: %d %s", e.code, e.reason)
    except urllib.error.URLError as e:
        log.warning("Grafana push connection error: %s", e.reason)
    except Exception as e:
        log.warning("Grafana push error: %s", e)
    return False


def main() -> None:
    OBS_DIR.mkdir(parents=True, exist_ok=True)
    log.info("Collecting platform metrics...")

    metrics = _collect_metrics()
    metrics_text = _format_prometheus(metrics)

    # Write local file
    METRICS_FILE.write_text(metrics_text, encoding="utf-8")
    log.info("Metrics written: %s", METRICS_FILE)

    # Also write timestamped archive
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive_path = OBS_DIR / f"metrics-{ts}.txt"
    archive_path.write_text(metrics_text, encoding="utf-8")

    # Push to Grafana Cloud (non-blocking)
    pushed = push_to_grafana(metrics_text)

    # Summary JSON for CI visibility
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics_file": str(METRICS_FILE),
        "grafana_push": pushed,
        "metrics": {k: v for k, v in metrics.items() if isinstance(v, (int, float, str))},
    }
    summary_path = OBS_DIR / "export-summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"[OBSERVABILITY] Metrics exported: {len(metrics)} data points")
    print(f"[OBSERVABILITY] Local file: {METRICS_FILE}")
    print(f"[OBSERVABILITY] Grafana push: {'SUCCESS' if pushed else 'SKIPPED (not configured)'}")
    log.info("Observability export complete.")


if __name__ == "__main__":
    main()
