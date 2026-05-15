#!/usr/bin/env python3
"""
scripts/report_url_canary.py
CYBERDUDEBIVASH(R) SENTINEL APEX v154.0 -- Report URL Live Canary
====================================================================
Post-deploy HTTP probe: fetches a deterministic sample of report URLs
from the live GitHub Pages site (https://intel.cyberdudebivash.com)
and verifies they return HTTP 200.

Exits 0 = all sampled report URLs returned HTTP 200 (deployment healthy)
Exits 1 = one or more report URLs returned 404 / non-200 (P0 FAILURE)

Sampling strategy:
  - Read report_url values from api/feed.json (public feed, max 10 probes)
  - Probe each URL with a 15-second timeout
  - Pages CDN propagation: wait up to 60s before probing (configurable)
  - Hard fail if >0 sampled URLs return non-200

Usage (called by CI):
  python3 scripts/report_url_canary.py

Environment:
  PAGES_BASE_URL    -- override base URL (default: https://intel.cyberdudebivash.com)
  CANARY_WAIT_SECS  -- seconds to wait for Pages CDN propagation (default: 30)
  CANARY_MAX_PROBES -- max report URLs to probe (default: 10)
  CANARY_TIMEOUT    -- HTTP request timeout in seconds (default: 15)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from typing import List, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-REPORT-CANARY] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.report_url_canary")

REPO_ROOT      = Path(__file__).resolve().parent.parent
PAGES_BASE_URL = os.environ.get("PAGES_BASE_URL", "https://intel.cyberdudebivash.com").rstrip("/")
CANARY_WAIT    = int(os.environ.get("CANARY_WAIT_SECS", "30"))
MAX_PROBES     = int(os.environ.get("CANARY_MAX_PROBES", "10"))
HTTP_TIMEOUT   = int(os.environ.get("CANARY_TIMEOUT", "15"))

FEED_PATHS = [
    REPO_ROOT / "api" / "feed.json",
    REPO_ROOT / "feed.json",
]


def load_report_urls(max_count: int) -> List[str]:
    """Load up to max_count internal report_url values from feed files."""
    for feed_path in FEED_PATHS:
        if not feed_path.exists():
            continue
        try:
            raw = json.loads(feed_path.read_text(encoding="utf-8"))
            items = raw if isinstance(raw, list) else []
        except Exception as exc:
            log.warning("Could not parse %s: %s", feed_path.name, exc)
            continue
        urls = []
        for item in items:
            ru = (item.get("report_url") or item.get("internal_report_url") or "").strip()
            if ru and ru.startswith("/reports/") and not ru.startswith("http"):
                urls.append(ru)
            if len(urls) >= max_count:
                break
        if urls:
            log.info("Loaded %d report_url(s) from %s", len(urls), feed_path.name)
            return urls
    log.warning("No report URLs found in any feed file — canary has nothing to probe.")
    return []


def probe_url(report_path: str) -> Tuple[str, int, str]:
    """
    Probe a single report URL.
    Returns (full_url, http_status_code, error_message).
    """
    full_url = f"{PAGES_BASE_URL}{report_path}"
    try:
        req = urllib.request.Request(full_url, method="HEAD")
        req.add_header("User-Agent", "CDB-Sentinel-Canary/154.0")
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return full_url, resp.status, ""
    except urllib.error.HTTPError as exc:
        return full_url, exc.code, str(exc.reason)
    except Exception as exc:
        return full_url, 0, str(exc)


def main() -> int:
    log.info("=" * 70)
    log.info("SENTINEL APEX -- Report URL Live Canary v154.0")
    log.info("=" * 70)
    log.info("Pages base URL : %s", PAGES_BASE_URL)
    log.info("Max probes     : %d", MAX_PROBES)
    log.info("CDN wait       : %ds", CANARY_WAIT)
    log.info("HTTP timeout   : %ds", HTTP_TIMEOUT)

    report_urls = load_report_urls(MAX_PROBES)
    if not report_urls:
        log.info("No report URLs to probe — canary exits 0 (nothing to validate).")
        return 0

    if CANARY_WAIT > 0:
        log.info("Waiting %ds for GitHub Pages CDN propagation...", CANARY_WAIT)
        time.sleep(CANARY_WAIT)

    log.info("Probing %d report URL(s)...", len(report_urls))

    passed: List[str] = []
    failed: List[Tuple[str, int, str]] = []

    for report_path in report_urls:
        full_url, status, err = probe_url(report_path)
        if status in (200, 301, 302, 304):
            log.info("[PASS] HTTP %d -- %s", status, full_url)
            passed.append(full_url)
        else:
            log.error("[FAIL] HTTP %d -- %s  (%s)", status, full_url, err or "no detail")
            failed.append((full_url, status, err))

    log.info("")
    log.info("=" * 70)
    log.info("REPORT URL CANARY RESULT")
    log.info("=" * 70)
    log.info("  Probed : %d", len(report_urls))
    log.info("  Passed : %d", len(passed))
    log.info("  Failed : %d", len(failed))
    log.info("=" * 70)

    if failed:
        log.error("P0 DEPLOYMENT FAILURE: %d report URL(s) returned non-200:", len(failed))
        for url, code, err in failed:
            log.error("  HTTP %d: %s  (%s)", code, url, err or "no detail")
        log.error("")
        log.error("ROOT CAUSE CANDIDATES:")
        log.error("  1. GitHub Pages deployment artifact missing report HTML files")
        log.error("  2. git reset --hard origin/main wiped reports/ (check safe_git_commit.py)")
        log.error("  3. report_existence_validator.py gate bypassed or --warn-only")
        log.error("  4. CDN propagation delay (increase CANARY_WAIT_SECS if transient)")
        log.error("")
        log.error("ACTION REQUIRED: Do not merge. Investigate reports/ deployment artifact.")
        return 1

    log.info("ALL REPORT URL CANARIES GREEN -- customer-facing reports accessible.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
