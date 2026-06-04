#!/usr/bin/env python3
"""
scripts/report_url_canary.py
CYBERDUDEBIVASH(R) SENTINEL APEX v174.0 -- Report URL Canary (Existence + Body)
====================================================================
Two-phase, fail-closed verification that customer-facing report_url values
actually resolve to a REAL report -- not a soft-404 stub, and not a stale
historical sample.

  --local  (PRE-DEPLOY, fail-closed, no network):
           For EVERY report_url in the CURRENT run's feed, verify the on-disk
           artifact exists, is readable, and carries a valid report body
           (size + <html> + no soft-404 marker). Exit 1 on ANY missing/invalid.
           This is the gate that BLOCKS publish-before-persist.

  --live / (default, POST-DEPLOY HTTP probe):
           GET each CURRENT-run report URL from the live site and validate the
           BODY (not just the status code), so a 200-with-"report_not_found"
           body FAILS. Retries for CDN propagation. 401/403 = auth-gated = PASS.

ROOT CAUSES FIXED (v174.0):
  1. v156 loader required `not ru.startswith("http")` -> silently DROPPED every
     fully-qualified https://intel.cyberdudebivash.com/reports/... URL, so the
     canary probed NOTHING from the current run (structurally blind).
  2. HEAD + status-only -> a soft-404 (HTTP 200 with report_not_found body)
     passed. Now GET + body validation.
  3. Sampled historical manifest first -> never the new current-run reports.
     Now the CURRENT feed is the authoritative source.
  4. No pre-deploy existence gate -> URLs were published before artifacts were
     persisted. --local now fails closed before publish.

Env: PAGES_BASE_URL CANARY_WAIT_SECS CANARY_RETRY_COUNT CANARY_RETRY_WAIT
     CANARY_MAX_PROBES CANARY_TIMEOUT
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-REPORT-CANARY] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.report_url_canary")

REPO_ROOT      = Path(__file__).resolve().parent.parent
REPORTS_DIR    = REPO_ROOT / "reports"
PAGES_BASE_URL = os.environ.get("PAGES_BASE_URL", "https://intel.cyberdudebivash.com").rstrip("/")
CANARY_WAIT    = int(os.environ.get("CANARY_WAIT_SECS", "120"))
RETRY_COUNT    = int(os.environ.get("CANARY_RETRY_COUNT", "3"))
RETRY_WAIT     = int(os.environ.get("CANARY_RETRY_WAIT", "60"))
MAX_PROBES     = int(os.environ.get("CANARY_MAX_PROBES", "10"))
HTTP_TIMEOUT   = int(os.environ.get("CANARY_TIMEOUT", "15"))

MANIFEST_PATH = REPO_ROOT / "dist" / "deployment_manifest.json"
FEED_PATHS = [REPO_ROOT / "api" / "feed.json", REPO_ROOT / "feed.json"]

# Body-validation calibration (real reports observed at ~100KB valid HTML).
MIN_REPORT_BYTES = 512
SOFT_404_MARKERS = (
    "report_not_found", "report not found", "page not found",
    "404 not found", "this report could not be found", "no report found",
)

_PASS_CODES = frozenset([200, 301, 302, 304])
_AUTH_GATED_CODES = frozenset([401, 403])


def _parse_feed_safe(feed_path: Path) -> List:
    try:
        raw = feed_path.read_bytes().rstrip(b"\x00").replace(b"\x00", b"")
        data = json.loads(raw.decode("utf-8", errors="replace"))
        return data if isinstance(data, list) else []
    except Exception as exc:
        log.warning("Could not parse %s: %s", feed_path.name, exc)
        return []


def _report_path(ru: Optional[str]) -> Optional[str]:
    """Normalize a report_url (full https URL OR relative) to '/reports/....html'."""
    ru = (ru or "").strip()
    if not ru:
        return None
    p = urlparse(ru).path if ru.lower().startswith("http") else ru
    if "/reports/" in p and p.lower().endswith(".html"):
        return p[p.index("/reports/"):]
    return None


def load_current_report_paths(max_count: int) -> List[str]:
    """Authoritative source = the CURRENT run's feed (reports being published now).

    Handles BOTH fully-qualified https URLs and relative paths (v174 fix).
    Falls back to dist/deployment_manifest.json only if no feed paths exist.
    """
    for feed_path in FEED_PATHS:
        if not feed_path.exists():
            continue
        items = _parse_feed_safe(feed_path)
        paths: List[str] = []
        seen = set()
        for item in items:
            for key in ("report_url", "internal_report_url"):
                rp = _report_path(item.get(key))
                if rp and rp not in seen:
                    seen.add(rp)
                    paths.append(rp)
        if paths:
            log.info("Loaded %d CURRENT-run report path(s) from %s", len(paths), feed_path.name)
            return paths[:max_count] if max_count and max_count > 0 else paths
    if MANIFEST_PATH.exists():
        try:
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            rep = [f"/{k}" for k in manifest.get("files", {})
                   if k.startswith("reports/") and k.endswith(".html")]
            if rep:
                log.warning("Feed empty -- falling back to %d manifest path(s)", len(rep))
                return rep[:max_count] if max_count and max_count > 0 else rep
        except Exception as exc:
            log.warning("Could not read deployment_manifest.json: %s", exc)
    log.warning("No report URLs found to probe.")
    return []


def validate_body(body: str) -> Tuple[bool, str]:
    """A real report = sufficient size + html shell + no soft-404 marker."""
    if body is None:
        return False, "no body"
    low = body.lower()
    if len(body) < MIN_REPORT_BYTES:
        return False, f"body too small ({len(body)}B < {MIN_REPORT_BYTES}B)"
    for mk in SOFT_404_MARKERS:
        if mk in low:
            return False, f"soft-404 marker present: {mk!r}"
    if "<html" not in low and "<!doctype" not in low:
        return False, "missing <html>/<!doctype> -- not a rendered report"
    return True, "ok"


def local_artifact_check(paths: List[str]) -> int:
    """PRE-DEPLOY fail-closed: every current report_url must resolve to a valid
    on-disk artifact. Exit 1 on ANY missing or invalid (report_not_found)."""
    log.info("LOCAL pre-deploy artifact gate: %d current report_url(s)", len(paths))
    if not paths:
        log.info("No report_url values in current feed -- nothing to publish, gate PASS (exit 0).")
        return 0
    missing: List[str] = []
    invalid: List[Tuple[str, str]] = []
    ok = 0
    for rp in paths:
        rel = rp.split("/reports/", 1)[1]
        disk = REPORTS_DIR / rel
        if not disk.exists():
            missing.append(rp)
            log.error("[MISSING] %s -> %s (artifact not persisted)", rp, disk)
            continue
        try:
            body = disk.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            invalid.append((rp, f"unreadable: {exc}"))
            log.error("[UNREADABLE] %s (%s)", rp, exc)
            continue
        valid, why = validate_body(body)
        if valid:
            ok += 1
            log.info("[OK] %s (%dB)", rp, len(body))
        else:
            invalid.append((rp, why))
            log.error("[INVALID] %s -- %s", rp, why)
    log.info("=" * 70)
    log.info("LOCAL GATE: %d ok / %d missing / %d invalid (of %d)",
             ok, len(missing), len(invalid), len(paths))
    log.info("=" * 70)
    if missing or invalid:
        log.error("P0 FAIL-CLOSED: %d report_url(s) would publish without a valid artifact.",
                  len(missing) + len(invalid))
        return 1
    log.info("ALL current report_url artifacts exist on disk and carry valid bodies.")
    return 0


def probe_url(report_path: str) -> Tuple[str, int, str, str]:
    """GET (not HEAD) so we can validate the BODY. Returns (url, status, body, err)."""
    full_url = f"{PAGES_BASE_URL}{report_path}"
    try:
        req = urllib.request.Request(full_url, method="GET")
        req.add_header("User-Agent", "CDB-Sentinel-Canary/174.0")
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            body = resp.read(131072).decode("utf-8", errors="replace")
            return full_url, resp.status, body, ""
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(8192).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return full_url, exc.code, body, str(exc.reason)
    except Exception as exc:
        return full_url, 0, "", str(exc)


def probe_round(report_paths: List[str]) -> Tuple[List[str], List[Tuple[str, int, str]]]:
    passed: List[str] = []
    failed: List[Tuple[str, int, str]] = []
    for rp in report_paths:
        full_url, status, body, err = probe_url(rp)
        if status in _PASS_CODES:
            valid, why = validate_body(body)
            if valid:
                log.info("[PASS] HTTP %d (valid body) -- %s", status, full_url)
                passed.append(full_url)
            else:
                log.error("[FAIL] HTTP %d but SOFT-404 body -- %s (%s)", status, full_url, why)
                failed.append((full_url, status, f"soft-404: {why}"))
        elif status in _AUTH_GATED_CODES:
            log.info("[AUTH-GATED] HTTP %d -- %s (CDN-delivered, auth required -- PASS)", status, full_url)
            passed.append(full_url)
        else:
            log.error("[FAIL] HTTP %d -- %s (%s)", status, full_url, err or "no detail")
            failed.append((full_url, status, err))
    return passed, failed


def run_live(report_paths: List[str]) -> int:
    if CANARY_WAIT > 0:
        log.info("Waiting %ds for GitHub Pages CDN propagation...", CANARY_WAIT)
        time.sleep(CANARY_WAIT)
    log.info("Probing %d CURRENT-run report URL(s) with body validation...", len(report_paths))
    passed, failed = probe_round(report_paths)
    for retry in range(1, RETRY_COUNT + 1):
        if not failed:
            break
        still = [u for u, _, _ in failed]
        log.info("Retry %d/%d: %d still failing. Waiting %ds...", retry, RETRY_COUNT, len(still), RETRY_WAIT)
        time.sleep(RETRY_WAIT)
        retry_paths = [u.replace(PAGES_BASE_URL, "") for u in still]
        passed_retry, failed = probe_round(retry_paths)
        passed.extend(passed_retry)
    log.info("=" * 70)
    log.info("LIVE CANARY: probed=%d passed=%d failed=%d", len(report_paths), len(passed), len(failed))
    log.info("=" * 70)
    if failed:
        log.error("P0 DEPLOYMENT FAILURE: %d report URL(s) non-200 or soft-404 after retries:", len(failed))
        for url, code, err in failed:
            log.error("  HTTP %s: %s (%s)", code, url, err or "no detail")
        return 1
    log.info("ALL current report URLs GREEN with valid bodies.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SENTINEL APEX Report URL Canary v174.0")
    ap.add_argument("--local", action="store_true",
                    help="Pre-deploy fail-closed on-disk existence+body gate (no network)")
    ap.add_argument("--live", action="store_true",
                    help="Post-deploy live HTTP probe with body validation")
    args = ap.parse_args()

    log.info("=" * 70)
    log.info("SENTINEL APEX -- Report URL Canary v174.0")
    log.info("Mode: %s | Pages base: %s", "LOCAL" if args.local else "LIVE", PAGES_BASE_URL)
    log.info("=" * 70)

    if args.local:
        return local_artifact_check(load_current_report_paths(0))   # ALL current paths

    report_paths = load_current_report_paths(MAX_PROBES)
    if not report_paths:
        log.info("No report URLs to probe -- canary exits 0 (nothing to validate).")
        return 0
    return run_live(report_paths)


if __name__ == "__main__":
    sys.exit(main())
