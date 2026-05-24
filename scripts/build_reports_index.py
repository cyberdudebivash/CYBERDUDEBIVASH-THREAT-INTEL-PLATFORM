#!/usr/bin/env python3
"""
scripts/build_reports_index.py
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v161.2 -- Reports Index Builder
===============================================================================
P0 PERMANENT MANDATE: The platform dashboard and API MUST list/display ALL
intel reports generated during every workflow run. This script creates the
authoritative reports index endpoint that powers:
  - Dashboard "Intel Reports" panel (latest N reports with links)
  - API endpoint: https://intel.cyberdudebivash.com/api/reports/index.json

WHAT IT DOES:
  1. Scans reports/ directory for ALL intel--*.html files
  2. Cross-references api/feed.json to enrich each report with:
       title, severity, risk_score, cve, timestamp, threat_type,
       actor_tag, epss_score, kev_present, tlp
  3. Writes api/reports/index.json  — full machine-readable index
  4. Writes api/reports/latest.json — top 50 for dashboard quick-load
  5. Writes api/reports/stats.json  — total counts, by severity, by month

Output format (api/reports/index.json):
  {
    "schema_version": "1.0",
    "generated_at":   "2026-05-24T06:00:00Z",
    "platform":       "CYBERDUDEBIVASH SENTINEL APEX v161.2",
    "base_url":       "https://intel.cyberdudebivash.com",
    "total_reports":  44562,
    "reports_listed": 200,
    "reports": [
      {
        "id":          "intel--1779589091_...",
        "url":         "https://intel.cyberdudebivash.com/reports/2026/05/intel--....html",
        "path":        "/reports/2026/05/intel--....html",
        "title":       "CVE-2026-9347 ...",
        "severity":    "CRITICAL",
        "risk_score":  9.0,
        "cve":         ["CVE-2026-9347"],
        "timestamp":   "2026-05-24T02:18:11Z",
        "threat_type": "Remote Code Execution",
        "actor_tag":   "CDB-UNATTR-CVE",
        "epss_score":  0.12,
        "kev_present": true,
        "tlp":         "TLP:RED",
        "generated_at": "2026-05-24T06:00:00Z"
      },
      ...
    ]
  }

INSERTION POINT: sentinel-blogger.yml STAGE 3.1.8 (after STAGE 3.1.7)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO_ROOT    = Path(__file__).resolve().parent.parent
REPORTS_ROOT = REPO_ROOT / "reports"
API_FEED     = REPO_ROOT / "api" / "feed.json"
API_REPORTS  = REPO_ROOT / "api" / "reports"
BASE_URL     = os.environ.get("PLATFORM_BASE_URL", "https://intel.cyberdudebivash.com")

# How many reports to include in index.json (full index) vs latest.json (quick-load)
MAX_INDEX  = int(os.environ.get("REPORTS_INDEX_MAX",  "500"))
MAX_LATEST = int(os.environ.get("REPORTS_LATEST_MAX",  "50"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [build-reports-index] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("build_reports_index")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load_json_safe(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("Failed to load %s: %s", path, e)
        return None


def _atomic_write(path: Path, data: Any, indent: int = 2) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".build_tmp")
    try:
        tmp.write_text(
            json.dumps(data, indent=indent, ensure_ascii=False, default=str),
            encoding="utf-8"
        )
        os.replace(tmp, path)
        return True
    except Exception as e:
        log.error("Atomic write failed for %s: %s", path, e)
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        return False


def _path_to_public_url(path: Path) -> str:
    """Convert on-disk report path to absolute public URL."""
    try:
        rel = path.relative_to(REPORTS_ROOT)
        return f"{BASE_URL.rstrip('/')}/reports/{rel.as_posix()}"
    except ValueError:
        return ""


def _path_to_relative_url(path: Path) -> str:
    """Convert on-disk report path to root-relative URL."""
    try:
        rel = path.relative_to(REPORTS_ROOT)
        return f"/reports/{rel.as_posix()}"
    except ValueError:
        return ""


def _extract_id_from_path(path: Path) -> str:
    """Extract intel item id from filename (strip .html)."""
    return path.stem  # e.g. intel--ffec0a31e4fcdf6faf555895


def _fmt_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _fmt_ts(path: Path) -> str:
    """Get file modification time as ISO 8601 string."""
    try:
        mtime = path.stat().st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    t_start = time.monotonic()
    log.info("=" * 70)
    log.info("BUILD REPORTS INDEX  —  SENTINEL APEX v161.2 P0 Mandate")
    log.info("=" * 70)
    log.info("Reports root : %s", REPORTS_ROOT)
    log.info("Base URL     : %s", BASE_URL)
    log.info("Max index    : %d", MAX_INDEX)
    log.info("Max latest   : %d", MAX_LATEST)

    # ------------------------------------------------------------------
    # 1. Scan reports/ directory for all intel--*.html files
    # ------------------------------------------------------------------
    if not REPORTS_ROOT.exists():
        log.warning("reports/ directory not found — creating empty index")
        all_report_paths: List[Path] = []
    else:
        log.info("Scanning reports/ directory...")
        all_report_paths = sorted(
            [
                p for p in REPORTS_ROOT.rglob("intel--*.html")
                if p.is_file() and p.stat().st_size > 512
            ],
            key=lambda p: p.stat().st_mtime,
            reverse=True,  # newest first
        )
    log.info("Found %d intel report files on disk", len(all_report_paths))

    # ------------------------------------------------------------------
    # 2. Load api/feed.json for metadata enrichment
    # ------------------------------------------------------------------
    feed_map: Dict[str, dict] = {}
    if API_FEED.exists():
        feed_data = _load_json_safe(API_FEED)
        if isinstance(feed_data, list):
            for item in feed_data:
                if isinstance(item, dict) and item.get("id"):
                    feed_map[item["id"]] = item
            log.info("api/feed.json: %d items loaded for enrichment", len(feed_map))
    else:
        log.warning("api/feed.json not found — index will have minimal metadata")

    # ------------------------------------------------------------------
    # 3. Build report entries (newest-first, capped at MAX_INDEX)
    # ------------------------------------------------------------------
    now_str = _fmt_now()
    report_entries: List[dict] = []
    severity_counts: Dict[str, int] = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
    }
    month_counts: Dict[str, int] = {}

    for path in all_report_paths[:MAX_INDEX]:
        report_id  = _extract_id_from_path(path)
        public_url = _path_to_public_url(path)
        rel_url    = _path_to_relative_url(path)

        # Try to extract YYYY/MM from directory structure
        try:
            parts      = path.relative_to(REPORTS_ROOT).parts  # ('2026', '05', 'intel--xxx.html')
            year_month = f"{parts[0]}-{parts[1]}" if len(parts) >= 3 else ""
        except Exception:
            year_month = ""

        # Enrich from api/feed.json by id match
        feed_item = feed_map.get(report_id, {})

        severity   = str(feed_item.get("severity") or "").upper().strip()
        risk_score = feed_item.get("risk_score")

        # v161.3: Derive severity from risk/cvss score when absent or UNKNOWN
        # Ensures reports index shows accurate severity even when NVD enrichment
        # hasn't run yet or didn't return data for this CVE.
        if not severity or severity == "UNKNOWN":
            _rs = 0.0
            try:
                _rs = float(
                    feed_item.get("cvss_score") or
                    feed_item.get("risk_score") or 0
                )
            except (TypeError, ValueError):
                _rs = 0.0
            if _rs >= 9.0:   severity = "CRITICAL"
            elif _rs >= 7.0: severity = "HIGH"
            elif _rs >= 4.0: severity = "MEDIUM"
            elif _rs > 0.0:  severity = "LOW"
            else:            severity = "UNKNOWN"
        title      = str(feed_item.get("title") or report_id)
        cve_list   = feed_item.get("cve") or []
        if not isinstance(cve_list, list):
            cve_list = [str(cve_list)] if cve_list else []
        timestamp  = (
            feed_item.get("timestamp") or
            feed_item.get("processed_at") or
            _fmt_ts(path)
        )
        threat_type = str(feed_item.get("threat_type") or "")
        actor_tag   = str(feed_item.get("actor_tag") or "")
        epss_score  = feed_item.get("epss_score")
        kev_present = bool(feed_item.get("kev_present"))
        tlp         = str(feed_item.get("tlp") or "TLP:CLEAR")

        entry = {
            "id":           report_id,
            "url":          public_url,
            "path":         rel_url,
            "title":        title,
            "severity":     severity,
            "risk_score":   risk_score,
            "cve":          cve_list,
            "timestamp":    timestamp,
            "threat_type":  threat_type,
            "actor_tag":    actor_tag,
            "epss_score":   epss_score,
            "kev_present":  kev_present,
            "tlp":          tlp,
            "year_month":   year_month,
            "file_size":    path.stat().st_size,
            "generated_at": now_str,
        }
        report_entries.append(entry)

        # Stats accumulation
        sev_key = severity if severity in severity_counts else "UNKNOWN"
        severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1
        if year_month:
            month_counts[year_month] = month_counts.get(year_month, 0) + 1

    # ------------------------------------------------------------------
    # 4. Write api/reports/index.json (full index, newest-first)
    # ------------------------------------------------------------------
    index_payload = {
        "schema_version": "1.0",
        "generated_at":   now_str,
        "platform":       "CYBERDUDEBIVASH SENTINEL APEX v161.2",
        "base_url":       BASE_URL,
        "total_reports":  len(all_report_paths),   # all files on disk
        "reports_listed": len(report_entries),      # capped at MAX_INDEX
        "reports":        report_entries,
    }

    index_path = API_REPORTS / "index.json"
    if _atomic_write(index_path, index_payload):
        log.info("api/reports/index.json written: %d entries", len(report_entries))
    else:
        log.error("Failed to write api/reports/index.json")

    # ------------------------------------------------------------------
    # 5. Write api/reports/latest.json (top MAX_LATEST for dashboard)
    # ------------------------------------------------------------------
    latest_payload = {
        "schema_version": "1.0",
        "generated_at":   now_str,
        "platform":       "CYBERDUDEBIVASH SENTINEL APEX v161.2",
        "base_url":       BASE_URL,
        "total_reports":  len(all_report_paths),
        "reports_listed": min(len(report_entries), MAX_LATEST),
        "reports":        report_entries[:MAX_LATEST],
    }

    latest_path = API_REPORTS / "latest.json"
    if _atomic_write(latest_path, latest_payload):
        log.info("api/reports/latest.json written: %d entries", len(latest_payload["reports"]))
    else:
        log.error("Failed to write api/reports/latest.json")

    # ------------------------------------------------------------------
    # 6. Write api/reports/stats.json (totals, severity breakdown, monthly)
    # ------------------------------------------------------------------
    # Sort months descending
    sorted_months = dict(
        sorted(month_counts.items(), key=lambda x: x[0], reverse=True)
    )

    stats_payload = {
        "schema_version": "1.0",
        "generated_at":   now_str,
        "platform":       "CYBERDUDEBIVASH SENTINEL APEX v161.2",
        "total_reports":  len(all_report_paths),
        "by_severity":    severity_counts,
        "by_month":       sorted_months,
        "latest_report_ts": report_entries[0]["timestamp"] if report_entries else "",
        "oldest_report_ts": report_entries[-1]["timestamp"] if report_entries else "",
    }

    stats_path = API_REPORTS / "stats.json"
    if _atomic_write(stats_path, stats_payload):
        log.info("api/reports/stats.json written")
    else:
        log.error("Failed to write api/reports/stats.json")

    # ------------------------------------------------------------------
    # 7. Summary
    # ------------------------------------------------------------------
    elapsed = time.monotonic() - t_start
    log.info("=" * 70)
    log.info("BUILD COMPLETE in %.1fs", elapsed)
    log.info("  Total reports on disk : %d", len(all_report_paths))
    log.info("  Indexed               : %d", len(report_entries))
    log.info("  Severity breakdown    : %s", severity_counts)
    log.info("  Months covered        : %d", len(month_counts))
    log.info("  Outputs written to    : api/reports/")
    log.info("    index.json   → %d reports", len(report_entries))
    log.info("    latest.json  → %d reports", len(latest_payload["reports"]))
    log.info("    stats.json   → totals + breakdown")
    log.info("  Public URL: %s/api/reports/index.json", BASE_URL)
    log.info("=" * 70)

    return 0


if __name__ == "__main__":
    sys.exit(main())
