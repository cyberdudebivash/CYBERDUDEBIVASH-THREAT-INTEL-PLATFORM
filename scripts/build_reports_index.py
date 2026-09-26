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

import html as html_lib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)
from canonical_timestamp import parse_timestamp  # noqa: E402

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
REPO_ROOT    = Path(__file__).resolve().parent.parent
REPORTS_ROOT = REPO_ROOT / "reports"
API_FEED     = REPO_ROOT / "api" / "feed.json"
API_REPORTS  = REPO_ROOT / "api" / "reports"
BASE_URL     = os.environ.get("PLATFORM_BASE_URL", "https://intel.cyberdudebivash.com")

# How many reports to include in index.json (full index) vs latest.json (quick-load)
# The reports R2 actually holds: scripts/r2_report_publisher.py's own state
# (synced from R2 before this stage by r2_state_sync.py). An entry with an
# html_sha256 is a report that publisher PUT successfully.
PUBLISH_STATE = REPO_ROOT / "data" / "cache" / "r2_report_publish_state.json"
MAX_INDEX  = int(os.environ.get("REPORTS_INDEX_MAX",  "500"))
MAX_LATEST = int(os.environ.get("REPORTS_LATEST_MAX",  "50"))

# P0 R2 COST INCIDENT FIX (2026-09): the dashboard report index must reflect
# only the rolling hot-report window R2 actually retains -- see
# scripts/r2_report_publisher.py's module docstring for the full incident.
# Explicitly NOT filesystem mtime (forensic analysis found mtime unreliable
# here: this repo's reports/ tree has previously been bulk-seeded by single
# commits and reset on fresh checkouts -- see scripts/report_archive_manager.py's
# own REPORT_RETENTION_DAYS docstring for the same finding). Uses the
# platform's canonical-timestamp precedence (timestamp -> processed_at ->
# published_at, matching scripts/intelligence_quality_scorer.py::
# _compute_age_days) via scripts/canonical_timestamp.py.
REPORT_WINDOW_HOURS = float(os.environ.get("REPORT_WINDOW_HOURS", "24"))
EMPTY_WINDOW_MESSAGE = "No intelligence reports generated during the last 24 hours."

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


def _published_report_paths() -> List[Path]:
    """Report paths the publish state records as already in R2.

    2026-09-26: the index listed only reports/ files on this runner's disk,
    i.e. reports generated in THIS run (earlier ones live only in R2 since
    the R2-native publisher). Run 36232016684 generated none: index
    total_reports=0, STAGE 5.9.2 GATE-2 failed, and the live Reports catalog
    listed 7 of the 23 customer-ready reports. The publisher's state file is
    the inventory of what R2 holds; these paths are virtual (no local file).
    """
    state = _load_json_safe(PUBLISH_STATE)
    items = state.get("items") if isinstance(state, dict) else None
    if not isinstance(items, dict):
        return []
    paths: List[Path] = []
    for report_id, entry in items.items():
        if not isinstance(entry, dict) or not entry.get("html_sha256"):
            continue  # staged but never PUT
        key = str(entry.get("html_key") or "")
        if not (key.startswith("reports/") and key.endswith(".html")):
            continue
        path = REPORTS_ROOT / key[len("reports/"):]
        if path.stem == report_id:
            paths.append(path)
    return paths


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
# Artifact-embedded metadata fallback
#
# api/feed.json only ever holds the current run's rolling window (observed:
# ~40-55 items), while reports/ retains every report ever generated
# (observed: 11,398+). A report whose originating intel item has scrolled
# out of that window gets {} from feed_map, and title/severity/risk_score
# silently degrade to the id/"UNKNOWN"/null placeholders -- affecting the
# large majority of the catalogue (measured live: 96-99.8% of listed
# reports). generate_intel_reports.py embeds this same title/severity/risk
# permanently in each report's own <title> and description meta tags at
# generation time (public SEO/social-share metadata -- no paywalled
# content), so it survives independently of the feed window and is exactly
# as authoritative as the original feed item was. Used ONLY when the feed
# lookup has nothing; never overrides a real feed match.
# ---------------------------------------------------------------------------
_TITLE_TAG_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TITLE_SUFFIX_RE = re.compile(r"\s*[·—-]\s*(?:CyberDudeBivash\s+)?SENTINEL APEX.*$", re.IGNORECASE)
_OG_DESC_RE = re.compile(r"""og:description['"]\s+content=['"]([^'"]*)['"]""")
_META_DESC_RE = re.compile(r"""name=['"]description['"]\s+content=['"]([^'"]*)['"]""")
_SEV_RISK_RE = re.compile(r"Severity\s+(\w+).*?Risk\s+([\d.]+)/10", re.IGNORECASE)
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def _extract_artifact_metadata(path: Path) -> Dict[str, Any]:
    """Best-effort deterministic parse of title/severity/risk_score from a
    report's own embedded HTML head. Returns only keys it actually found --
    never fabricates a value."""
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:4000]
    except Exception:
        return {}

    result: Dict[str, Any] = {}

    m_title = _TITLE_TAG_RE.search(head)
    if m_title:
        title = html_lib.unescape(m_title.group(1)).strip()
        title = _TITLE_SUFFIX_RE.sub("", title).strip()
        if title:
            result["title"] = title

    m_meta = _OG_DESC_RE.search(head) or _META_DESC_RE.search(head)
    if m_meta:
        m_sr = _SEV_RISK_RE.search(html_lib.unescape(m_meta.group(1)))
        if m_sr:
            sev = m_sr.group(1).upper()
            if sev in _VALID_SEVERITIES:
                result["severity"] = sev
            try:
                result["risk_score"] = float(m_sr.group(2))
            except ValueError:
                pass

    return result


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
    # 1. Load api/feed.json (needed first now -- it's the source of the
    #    canonical timestamp the 24h window filter below requires)
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

    def _canonical_ts(report_id: str) -> Optional[datetime]:
        """Resolves a report's canonical intelligence timestamp via its
        api/feed.json entry -- timestamp -> processed_at -> published_at
        precedence (matches scripts/intelligence_quality_scorer.py::
        _compute_age_days). None (excluded from the hot index, never
        fabricated) if the id has no feed entry or no parseable timestamp --
        see REPORT_WINDOW_HOURS's module-level comment for why mtime is not
        used as a fallback here."""
        feed_item = feed_map.get(report_id)
        if not feed_item:
            return None
        raw = feed_item.get("timestamp") or feed_item.get("processed_at") or feed_item.get("published_at")
        if not raw:
            return None
        result = parse_timestamp(raw)
        return result.normalized if result.parse_status == "SUCCESS" else None

    # ------------------------------------------------------------------
    # 2. Scan reports/ directory, bounded to the rolling REPORT_WINDOW_HOURS
    #    window by each file's CANONICAL intelligence timestamp (never
    #    filesystem mtime -- see module-level comment). A file present on
    #    disk whose id has no feed_map match, or no parseable canonical
    #    timestamp, is excluded: this index cannot prove it belongs in the
    #    hot window, so it is not listed as current (fail safe).
    # ------------------------------------------------------------------
    if not REPORTS_ROOT.exists():
        log.warning("reports/ directory not found — indexing published reports only")
    log.info("Scanning reports/ directory (window = %sh)...", REPORT_WINDOW_HOURS)
    now = datetime.now(timezone.utc)
    _dated: List[tuple] = []
    _excluded_stale_or_unproven = 0
    _on_disk = [p for p in REPORTS_ROOT.rglob("intel--*.html")
                if p.is_file() and p.stat().st_size > 512] if REPORTS_ROOT.exists() else []
    _seen_ids = {_extract_id_from_path(p) for p in _on_disk}
    _published = [p for p in _published_report_paths()
                  if _extract_id_from_path(p) not in _seen_ids]
    if _published:
        log.info("Publish state: %d report(s) already in R2 not on this runner's disk", len(_published))
    for p in _on_disk + _published:
        ts = _canonical_ts(_extract_id_from_path(p))
        if ts is None:
            _excluded_stale_or_unproven += 1
            continue
        age_hours = (now - ts).total_seconds() / 3600.0
        if not (0 <= age_hours <= REPORT_WINDOW_HOURS):
            _excluded_stale_or_unproven += 1
            continue
        _dated.append((ts, p))
    _dated.sort(key=lambda t: t[0], reverse=True)  # newest first
    all_report_paths = [p for _ts, p in _dated]
    if _excluded_stale_or_unproven:
        log.info(
            "Excluded %d report file(s) on disk: outside the %sh window or no "
            "provable canonical timestamp (not listed as current -- fail safe).",
            _excluded_stale_or_unproven, REPORT_WINDOW_HOURS,
        )
    log.info("Found %d intel report file(s) within the %sh hot window", len(all_report_paths), REPORT_WINDOW_HOURS)

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
        title      = str(feed_item.get("title") or "")

        # Fallback for reports whose originating intel item has scrolled out
        # of api/feed.json's current window (see _extract_artifact_metadata
        # docstring): parse the report's own permanently-embedded metadata.
        # Only fills gaps left by the feed lookup above -- never overrides a
        # real feed value, never fabricates one that isn't found anywhere.
        if not title or severity == "UNKNOWN" or risk_score is None:
            _artifact_meta = _extract_artifact_metadata(path)
            if not title:
                title = _artifact_meta.get("title", "")
            if severity == "UNKNOWN" and "severity" in _artifact_meta:
                severity = _artifact_meta["severity"]
            if risk_score is None and "risk_score" in _artifact_meta:
                risk_score = _artifact_meta["risk_score"]

        if not title:
            title = report_id
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
            "file_size":    path.stat().st_size if path.exists() else None,
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
        "window_hours":   REPORT_WINDOW_HOURS,
        "total_reports":  len(all_report_paths),   # all files within the hot window
        "reports_listed": len(report_entries),      # capped at MAX_INDEX
        "reports":        report_entries,
    }
    if not report_entries:
        index_payload["empty_state_message"] = EMPTY_WINDOW_MESSAGE

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
        "window_hours":   REPORT_WINDOW_HOURS,
        "total_reports":  len(all_report_paths),
        "reports_listed": min(len(report_entries), MAX_LATEST),
        "reports":        report_entries[:MAX_LATEST],
    }
    if not report_entries:
        latest_payload["empty_state_message"] = EMPTY_WINDOW_MESSAGE

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
        "window_hours":   REPORT_WINDOW_HOURS,
        "total_reports":  len(all_report_paths),
        "by_severity":    severity_counts,
        "by_month":       sorted_months,
        "latest_report_ts": report_entries[0]["timestamp"] if report_entries else "",
        "oldest_report_ts": report_entries[-1]["timestamp"] if report_entries else "",
    }
    if not report_entries:
        stats_payload["empty_state_message"] = EMPTY_WINDOW_MESSAGE

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
