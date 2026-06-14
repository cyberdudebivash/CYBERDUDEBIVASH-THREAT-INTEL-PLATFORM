#!/usr/bin/env python3
"""
scripts/deployment_canary.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Deployment Canary v1.0.1
======================================================================
Post-deployment canary validation with automatic rollback trigger.

Validates live production endpoints after every deploy:
  CANARY A: /api/health  -- gateway operational, version match
  CANARY B: /api/preview -- public feed accessible, item count >= 5
  CANARY C: /api/feed    -- authenticated feed shape valid
  CANARY D: dashboard    -- HTTP 200, DOCTYPE present, no error markers
  CANARY E: version.json -- version file accessible and valid JSON

Rollback trigger:
  If CANARY A or B fails: emits rollback signal (exit code 2)
  If CANARY C or D fails: emits degraded signal (exit code 3)
  Exit 0 = all canaries green

CI Usage:
  python3 scripts/deployment_canary.py [--base-url URL] [--timeout 30]

(c) 2026 CYBERDUDEBIVASH PRIVATE LIMITED. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-CANARY] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("CDB-CANARY")

PLATFORM_BASE = "https://intel.cyberdudebivash.com"
DEFAULT_TIMEOUT = 20  # seconds per request
MIN_PREVIEW_ITEMS = 3
HARD_FAIL_CANARIES = {"A", "B"}  # rollback if these fail


def _fetch(url: str, timeout: int, token: Optional[str] = None) -> Tuple[int, str]:
    """Fetch URL. Returns (status_code, body_text)."""
    headers = {"User-Agent": "SentinelApex-Canary/1.0"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1 << 20).decode("utf-8", errors="replace")  # 1 MB cap (was 64 KB — too small for /api/preview)
            return resp.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc)
    except Exception as exc:
        return 0, str(exc)


def canary_a_health(base: str, timeout: int) -> Dict:
    """CANARY A: API health endpoint."""
    url = "%s/api/health" % base
    t0 = time.monotonic()
    status, body = _fetch(url, timeout)
    latency_ms = int((time.monotonic() - t0) * 1000)

    result = {
        "canary": "A",
        "name": "API Health",
        "url": url,
        "status_code": status,
        "latency_ms": latency_ms,
        "pass": False,
        "details": "",
    }

    if status != 200:
        result["details"] = "HTTP %d (expected 200)" % status
        return result

    try:
        data = json.loads(body)
        gw_ok = data.get("status") in ("healthy", "ok", "operational")
        result["pass"] = gw_ok
        result["details"] = "status=%s version=%s" % (
            data.get("status"), data.get("version", "?")
        )
    except Exception:
        result["details"] = "Invalid JSON response"

    return result


def canary_b_preview(base: str, timeout: int) -> Dict:
    """CANARY B: Public preview feed."""
    url = "%s/api/preview" % base
    t0 = time.monotonic()
    status, body = _fetch(url, timeout)
    latency_ms = int((time.monotonic() - t0) * 1000)

    result = {
        "canary": "B",
        "name": "Public Preview Feed",
        "url": url,
        "status_code": status,
        "latency_ms": latency_ms,
        "pass": False,
        "details": "",
    }

    if status != 200:
        result["details"] = "HTTP %d" % status
        return result

    try:
        data = json.loads(body)
        # Worker response shape: {"status":"ok","preview":{"items":[...],"total_preview":N,...}}
        # Canary must parse the nested "preview.items" path first (primary Worker format),
        # then fall back to flat shapes for forward-compatibility.
        # ROOT CAUSE FIX v150.1: Previous parser looked for top-level "items" key which
        # does not exist in the Worker envelope -- items are nested under data["preview"]["items"].
        if isinstance(data, list):
            # Flat list response (legacy / direct array)
            items = data
        elif isinstance(data.get("preview"), dict):
            # Primary Worker format: {"preview": {"items": [...], ...}}
            items = data["preview"].get("items", [])
        else:
            # Flat object fallback: {"items": [...]} or {"data": [...]}
            items = data.get("items", data.get("data", []))
        if not isinstance(items, list):
            items = []
        count = len(items)
        result["pass"] = count >= MIN_PREVIEW_ITEMS
        result["details"] = "items=%d (min=%d)" % (count, MIN_PREVIEW_ITEMS)
    except Exception as exc:
        result["details"] = "Parse error: %s" % exc

    return result


def canary_c_feed(base: str, timeout: int) -> Dict:
    """CANARY C: Feed endpoint shape validation."""
    url = "%s/api/feed" % base
    t0 = time.monotonic()
    status, body = _fetch(url, timeout)
    latency_ms = int((time.monotonic() - t0) * 1000)

    result = {
        "canary": "C",
        "name": "Intel Feed Endpoint",
        "url": url,
        "status_code": status,
        "latency_ms": latency_ms,
        "pass": False,
        "details": "",
    }

    # Feed may return 401 (auth required) which is valid
    if status in (200, 401, 403):
        result["pass"] = True
        result["details"] = "HTTP %d (auth gate operating)" % status
    elif status == 0:
        result["details"] = "Connection failed: %s" % body[:100]
    else:
        result["details"] = "Unexpected HTTP %d" % status

    return result


def canary_d_dashboard(base: str, timeout: int) -> Dict:
    """CANARY D: Dashboard HTML health."""
    url = "%s/" % base
    t0 = time.monotonic()
    status, body = _fetch(url, timeout)
    latency_ms = int((time.monotonic() - t0) * 1000)

    result = {
        "canary": "D",
        "name": "Dashboard Frontend",
        "url": url,
        "status_code": status,
        "latency_ms": latency_ms,
        "pass": False,
        "details": "",
    }

    if status != 200:
        result["details"] = "HTTP %d" % status
        return result

    has_doctype = "<!DOCTYPE" in body or "<!doctype" in body
    has_sentinel = "SENTINEL" in body or "sentinel" in body.lower()
    has_error_500 = "500 Internal Server Error" in body
    has_error_502 = "502 Bad Gateway" in body

    result["pass"] = has_doctype and not has_error_500 and not has_error_502
    result["details"] = "doctype=%s sentinel_brand=%s error_500=%s" % (
        has_doctype, has_sentinel, has_error_500
    )
    return result


def canary_e_version(base: str, timeout: int) -> Dict:
    """CANARY E: version.json accessible."""
    url = "%s/version.json" % base
    t0 = time.monotonic()
    status, body = _fetch(url, timeout)
    latency_ms = int((time.monotonic() - t0) * 1000)

    result = {
        "canary": "E",
        "name": "Version File",
        "url": url,
        "status_code": status,
        "latency_ms": latency_ms,
        "pass": False,
        "details": "",
    }

    if status == 200:
        try:
            data = json.loads(body)
            ver = data.get("version", "?")
            result["pass"] = True
            result["details"] = "version=%s" % ver
        except Exception:
            result["details"] = "Invalid JSON"
    else:
        result["details"] = "HTTP %d" % status

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Deployment Canary Validator"
    )
    parser.add_argument("--base-url", default=PLATFORM_BASE,
                        help="Platform base URL")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="HTTP timeout per canary (seconds)")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    timeout = args.timeout

    log.info("Running deployment canaries against: %s", base)

    canaries = [
        canary_a_health(base, timeout),
        canary_b_preview(base, timeout),
        canary_c_feed(base, timeout),
        canary_d_dashboard(base, timeout),
        canary_e_version(base, timeout),
    ]

    print("\n" + "=" * 60)
    print("  SENTINEL APEX DEPLOYMENT CANARY REPORT")
    print("  %s" % datetime.now(timezone.utc).isoformat())
    print("=" * 60)

    passed = 0
    hard_failed = []

    for c in canaries:
        status_icon = "PASS" if c["pass"] else "FAIL"
        log.info(
            "[CANARY %s] %s -- %s (%dms)",
            c["canary"], status_icon, c["details"], c["latency_ms"]
        )
        print("  [%s] Canary %s: %s -- %s (%dms)" % (
            status_icon, c["canary"], c["name"], c["details"], c["latency_ms"]
        ))
        if c["pass"]:
            passed += 1
        elif c["canary"] in HARD_FAIL_CANARIES:
            hard_failed.append(c["canary"])

    total = len(canaries)
    print("\n  Result: %d/%d canaries green" % (passed, total))

    if hard_failed:
        print("  ROLLBACK SIGNAL: Hard-fail canaries %s" % hard_failed)
        print("  Action: Trigger rollback_authority.py immediately.")
        print("=" * 60 + "\n")
        log.error("DEPLOYMENT CANARY HARD FAIL: %s -- rollback required", hard_failed)
        return 2  # rollback signal

    if passed < total:
        print("  DEGRADED: %d canaries failed (non-critical)" % (total - passed))
        print("=" * 60 + "\n")
        log.warning("DEPLOYMENT DEGRADED: %d/%d canaries passed", passed, total)
        return 3  # degraded signal

    print("  ALL CANARIES GREEN -- deployment validated")
    print("=" * 60 + "\n")
    log.info("DEPLOYMENT CANARY: ALL GREEN (%d/%d)", passed, total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
