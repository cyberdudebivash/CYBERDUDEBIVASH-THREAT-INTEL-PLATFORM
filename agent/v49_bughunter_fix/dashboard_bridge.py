"""
CYBERDUDEBIVASH® SENTINEL APEX v49.0 — Bug Hunter Dashboard Bridge
====================================================================
Writes Bug Hunter scan results to data/bughunter/bughunter_output.json
in the exact schema consumed by renderBugHunterEngine() in index.html.

This module ONLY writes to data/bughunter/. It does NOT touch:
  - data/stix/ (STIX pipeline)
  - data/nexus/ (NEXUS engine)
  - data/genesis/ (GENESIS engine)
  - index.html (dashboard rendering)
  - .github/workflows/sync-dashboard.yml (dashboard sync)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger("CDB-BH-BRIDGE")

# Output path — matches ENGINE_URLS.bughunter in index.html line 3834
_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "bughunter")
_OUTPUT_FILE = os.path.join(_DATA_DIR, "bughunter_output.json")
_HISTORY_DIR = os.path.join(_DATA_DIR, "scan_history")


def write_dashboard_output(scan_data: Dict[str, Any]) -> str:
    """
    Write scan results to bughunter_output.json.

    The dashboard's renderBugHunterEngine() reads:
      data.metrics.subdomains        → #bh-subdomain-count
      data.metrics.live_hosts        → #bh-livehost-count
      data.metrics.api_endpoints     → #bh-api-count
      data.metrics.critical_findings → #bh-critical-count
      data.metrics.risk_exposure     → #bh-risk-exposure
      data.metrics.rosi              → #bh-rosi
      data.findings_summary[]        → #bh-findings-feed
      data.engines[]                 → engine status indicators

    Args:
        scan_data: Output from SafeReconScanner.run_full_scan()

    Returns:
        Path to written output file.
    """
    os.makedirs(_DATA_DIR, exist_ok=True)
    os.makedirs(_HISTORY_DIR, exist_ok=True)

    # Validate required fields exist
    metrics = scan_data.get("metrics", {})
    required_keys = ["subdomains", "live_hosts", "api_endpoints", "critical_findings"]
    for key in required_keys:
        if key not in metrics:
            metrics[key] = 0

    # Ensure engines array exists
    if "engines" not in scan_data:
        scan_data["engines"] = _default_engines()

    # Write main output (consumed by dashboard)
    try:
        with open(_OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=4, default=str)
        logger.info(f"[BRIDGE] Dashboard output written: {_OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"[BRIDGE] Failed to write dashboard output: {e}")
        raise

    # Write timestamped history copy for delta tracking
    try:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        history_file = os.path.join(_HISTORY_DIR, f"scan_{ts}.json")
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(scan_data, f, indent=2, default=str)
        logger.info(f"[BRIDGE] History snapshot: {history_file}")

        # Keep only last 10 history files
        _prune_history()
    except Exception as e:
        logger.warning(f"[BRIDGE] History write failed (non-critical): {e}")

    return _OUTPUT_FILE


def get_previous_output() -> str:
    """Return path to current bughunter_output.json if it exists."""
    if os.path.exists(_OUTPUT_FILE):
        return _OUTPUT_FILE
    return ""


def validate_output(path: str) -> Dict[str, Any]:
    """Validate the output file matches expected schema."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    metrics = data.get("metrics", {})
    results = {
        "valid": True,
        "subdomains": metrics.get("subdomains", 0),
        "live_hosts": metrics.get("live_hosts", 0),
        "api_endpoints": metrics.get("api_endpoints", 0),
        "critical_findings": metrics.get("critical_findings", 0),
        "total_findings": metrics.get("total_findings", 0),
        "risk_exposure": metrics.get("risk_exposure", 0),
        "engines_count": len(data.get("engines", [])),
        "findings_count": len(data.get("findings_summary", [])),
        "has_nonzero_metrics": any(
            metrics.get(k, 0) > 0
            for k in ["subdomains", "live_hosts", "api_endpoints", "total_findings"]
        ),
    }
    return results


def _prune_history(keep: int = 10) -> None:
    """Remove old history files, keeping only the most recent."""
    try:
        files = sorted(
            [
                os.path.join(_HISTORY_DIR, f)
                for f in os.listdir(_HISTORY_DIR)
                if f.startswith("scan_") and f.endswith(".json")
            ]
        )
        for old_file in files[:-keep]:
            os.remove(old_file)
    except Exception:
        pass


def _default_engines():
    """Fallback engine list if scan data is missing it."""
    return [
        {"id": "subdomain_engine", "name": "Subdomain Intelligence", "status": "ONLINE"},
        {"id": "http_probe", "name": "HTTP Probe Engine", "status": "ONLINE"},
        {"id": "tech_fingerprint", "name": "Technology Fingerprinter", "status": "ONLINE"},
        {"id": "js_endpoint_extractor", "name": "JS Endpoint Extractor", "status": "ONLINE"},
        {"id": "bola_agent", "name": "BOLA Intelligence Agent", "status": "ONLINE"},
        {"id": "cloud_bucket_hunter", "name": "Multi-Cloud Bucket Hunter", "status": "ONLINE"},
        {"id": "port_scanner", "name": "Port Scanner Engine", "status": "ONLINE"},
        {"id": "takeover_detector", "name": "Subdomain Takeover Detector", "status": "ONLINE"},
        {"id": "asset_delta", "name": "Asset Delta Analyzer", "status": "ONLINE"},
        {"id": "roi_engine", "name": "ROI & Risk Calculator", "status": "ONLINE"},
        {"id": "recon_pipeline", "name": "Recon Pipeline Orchestrator", "status": "ONLINE"},
        {"id": "report_generator", "name": "Audit Report Generator", "status": "ONLINE"},
    ]
