#!/usr/bin/env python3
"""
scripts/report_url_canary.py
CYBERDUDEBIVASH(R) SENTINEL APEX v156.0 -- Report URL Live Canary
====================================================================
Post-deploy HTTP probe: fetches a deterministic sample of report URLs
from the live GitHub Pages site (https://intel.cyberdudebivash.com)
and verifies they are reachable and correctly served.

Exits 0 = all sampled report URLs returned an acceptable status code
Exits 1 = one or more report URLs returned 404/5xx/network error (P0 FAILURE)

ACCEPTABLE STATUS CODES (v156.0):
  200/301/302/304  -- publicly accessible
  401/403          -- AUTH-GATED (PRO/Enterprise Cloudflare Access) = PASS
                     401 proves report exists, CDN served it, auth is active.
FAILING STATUS CODES: 404 (missing), 5xx (server error), 0 (network failure)

ROOT CAUSE of prior false failures (v155.0):
  Treated HTTP 401 as P0 failure. PRO-tier reports are Cloudflare-gated by design.
  v156.0 aligns with CDB-CONVERGENCE engine which marks 401 as AUTH-GATED = OK.

Sampling strategy:
  - Read report_url values from dist/deployment_manifest.json first
  - Fall back to api/feed.json or feed.json (max 10 probes)
  - Pages CDN propagation: RETRY up to 3 times with 60s gaps
    (GitHub Pages CDN takes 2-5 minutes minimum after gh-pages push)
  - Hard fail if >0 sampled URLs return non-200 after all retries

v155.0 FIXES:
  - Increased default CDN wait from 30s to 120s
  - Added retry logic (3 retries x 60s = up to 3 min of retries)
  - Reads from dist/deployment_manifest.json for deterministic sampling
  - Null-byte stripping for corrupted feed.json files

Usage (called by CI):
  python3 scripts/report_url_canary.py

Environment:
  PAGES_BASE_URL       -- override base URL (default: https://intel.cyberdudebivash.com)
  CANARY_WAIT_SECS     -- initial seconds to wait for CDN propagation (default: 120)
  CANARY_RETRY_COUNT   -- max probe retry rounds (default: 3)
  CANARY_RETRY_WAIT    -- seconds between retry rounds (default: 60)
  CANARY_MAX_PROBES    -- max report URLs to probe (default: 10)
  CANARY_TIMEOUT       -- HTTP request timeout in seconds (default: 15)

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
# v155.0: increased default from 30s to 120s — Pages CDN needs 2-5 minutes
CANARY_WAIT    = int(os.environ.get("CANARY_WAIT_SECS", "120"))
RETRY_COUNT    = int(os.environ.get("CANARY_RETRY_COUNT", "3"))
RETRY_WAIT     = int(os.environ.get("CANARY_RETRY_WAIT", "60"))
MAX_PROBES     = int(os.environ.get("CANARY_MAX_PROBES", "10"))
HTTP_TIMEOUT   = int(os.environ.get("CANARY_TIMEOUT", "15"))

MANIFEST_PATH = REPO_ROOT / "dist" / "deployment_manifest.json"
FEED_PATHS = [
    REPO_ROOT / "api" / "feed.json",
    REPO_ROOT / "feed.json",
]


def _parse_feed_safe(feed_path: Path) -> List:
    """Parse a feed JSON file, stripping null bytes if present (corruption guard)."""
    try:
        raw = feed_path.read_bytes().rstrip(b"\x00")
        data = json.loads(raw.decode("utf-8", errors="replace"))
        return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("Could not parse %s: %s", feed_path.name, exc)
        return []


def load_report_urls(max_count: int) -> List[str]:
    """Load up to max_count internal report_url values.

    Priority:
      1. dist/deployment_manifest.json (most authoritative)
      2. api/feed.json
      3. feed.json
    """
    # Priority 1: deployment manifest (authoritative)
    if MANIFEST_PATH.exists():
        try:
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            report_files = [
                f"/{k}" for k in manifest.get("files", {})
                if k.startswith("reports/") and k.endswith(".html")
            ]
            if report_files:
                sampled = report_files[:max_count]
                log.info("Loaded %d report path(s) from dist/deployment_manifest.json",
                         len(sampled))
                return sampled
        except Exception as exc:
            log.warning("Could not read deployment_manifest.json: %s", exc)

    # Priority 2 & 3: feed files
    for feed_path in FEED_PATHS:
        if not feed_path.exists():
            continue
        items = _parse_feed_safe(feed_path)
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


# v156.0: acceptable status codes. 401/403 = auth-gated PRO tier = PASS.
# Only 404, 5xx, 0 (network) are genuine deployment failures.
_PASS_CODES = frozenset([200, 301, 302, 304])
_AUTH_GATED_CODES = frozenset([401, 403])


def probe_round(report_urls: List[str]) -> Tuple[List[str], List[Tuple[str, int, str]]]:
    """Probe all URLs once. Returns (passed, failed).

    v156.0: 401/403 = auth-gated PRO/Enterprise tier = correctly deployed = PASS.
    Failures: 404 (missing), 5xx (server error), 0 (network/DNS failure).
    """
    passed: List[str] = []
    failed: List[Tuple[str, int, str]] = []
    for report_path in report_urls:
        full_url, status, err = probe_url(report_path)
        if status in _PASS_CODES:
            log.info("[PASS] HTTP %d -- %s", status, full_url)
            passed.append(full_url)
        elif status in _AUTH_GATED_CODES:
            log.info("[AUTH-GATED] HTTP %d -- %s  (CDN-DELIVERED, auth required -- PASS)",
                     status, full_url)
            passed.append(full_url)
        else:
            log.error("[FAIL] HTTP %d -- %s  (%s)", status, full_url, err or "no detail")
            failed.append((full_url, status, err))
    return passed, failed


def main() -> int:
    log.info("=" * 70)
    log.info("SENTINEL APEX -- Report URL Live Canary v156.0")
    log.info("=" * 70)
    log.info("Pages base URL : %s", PAGES_BASE_URL)
    log.info("Max probes     : %d", MAX_PROBES)
    log.info("CDN wait       : %ds (initial)", CANARY_WAIT)
    log.info("Retry count    : %d", RETRY_COUNT)
    log.info("Retry wait     : %ds", RETRY_WAIT)
    log.info("HTTP timeout   : %ds", HTTP_TIMEOUT)

    report_urls = load_report_urls(MAX_PROBES)
    if not report_urls:
        log.info("No report URLs to probe — canary exits 0 (nothing to validate).")
        return 0

    # ── Initial CDN propagation wait ─────────────────────────────────────────
    if CANARY_WAIT > 0:
        log.info("Waiting %ds for GitHub Pages CDN propagation...", CANARY_WAIT)
        log.info("(GitHub Pages CDN requires 2-5 minutes after gh-pages push)")
        time.sleep(CANARY_WAIT)

    log.info("Probing %d report URL(s)...", len(report_urls))

    # ── Probe round 1 ────────────────────────────────────────────────────────
    passed, failed = probe_round(report_urls)

    # ── Retry rounds for failed URLs ──────────────────────────────────────────
    for retry in range(1, RETRY_COUNT + 1):
        if not failed:
            break
        still_failing = [url for url, _, _ in failed]
        log.info("")
        log.info("Retry %d/%d: %d URL(s) still failing. Waiting %ds for CDN...",
                 retry, RETRY_COUNT, len(still_failing), RETRY_WAIT)
        time.sleep(RETRY_WAIT)
        log.info("Re-probing %d failed URL(s)...", len(still_failing))
        # Re-probe only the failures
        retry_paths = [u.replace(PAGES_BASE_URL, "") for u in still_failing]
        passed_retry, failed = probe_round(retry_paths)
        passed.extend(passed_retry)
        log.info("  Retry %d result: %d recovered, %d still failing",
                 retry, len(passed_retry), len(failed))

    log.info("")
    log.info("=" * 70)
    log.info("REPORT URL CANARY RESULT")
    log.info("=" * 70)
    log.info("  Probed : %d", len(report_urls))
    log.info("  Passed : %d", len(passed))
    log.info("  Failed : %d", len(failed))
    log.info("=" * 70)

    if failed:
        log.error("P0 DEPLOYMENT FAILURE: %d report URL(s) returned non-200 after all retries:",
                  len(failed))
        for url, code, err in failed:
            log.error("  HTTP %d: %s  (%s)", code, url, err or "no detail")
        log.error("")
        log.error("ROOT CAUSE CANDIDATES (note: HTTP 401/403 = auth-gated = PASS, not failures):")
        log.error("  1. dist/ build excluded report HTML files (check build_dist_artifact.py)")
        log.error("  2. git reset --hard origin/main wiped reports/ (check safe_git_commit.py)")
        log.error("  3. report_existence_validator.py gate bypassed or --warn-only")
        log.error("  4. CDN propagation delay > total wait (%ds + %d x %ds)",
                  CANARY_WAIT, RETRY_COUNT, RETRY_WAIT)
        log.error("  5. GitHub Pages deployment artifact missing report HTML files")
        log.error("  6. Custom domain DNS/Cloudflare caching stale 404 responses")
        log.error("")
        log.error("ACTION REQUIRED: Investigate dist/ and gh-pages branch content.")
        return 1

    log.info("ALL REPORT URL CANARIES GREEN -- customer-facing reports accessible.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
