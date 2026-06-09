#!/usr/bin/env python3
"""
post_deploy_smoke_test.py -- SENTINEL APEX Post-Deploy Smoke Tests v158.0
Runs AFTER deployment completes. Validates production URLs are serving correctly.
Called from sentinel-blogger.yml after the JamesIves deploy action.

Exit codes:
  0 = all smoke tests passed
  1 = one or more smoke tests failed (deployment may need rollback)

Usage: python scripts/post_deploy_smoke_test.py
Environment vars:
  PLATFORM_URL (default: https://intel.cyberdudebivash.com)
"""
import sys, os, time
from pathlib import Path
from datetime import datetime, timezone
from urllib import request, error

if hasattr(sys.stdout, 'reconfigure'):
    try: sys.stdout.reconfigure(encoding='utf-8')
    except Exception: pass

PLATFORM_URL = os.environ.get('PLATFORM_URL', 'https://intel.cyberdudebivash.com').rstrip('/')
TIMEOUT_SEC  = int(os.environ.get('SMOKE_TIMEOUT', '15'))
MAX_RETRIES  = int(os.environ.get('SMOKE_RETRIES', '3'))

failures = []
warnings = []

def fetch_url(url, timeout=TIMEOUT_SEC):
    """Fetch a URL with retries. Returns (status_code, content_length, elapsed_ms) or raises."""
    headers = {'User-Agent': 'SENTINEL-APEX-SMOKE-TEST/158.0'}
    req = request.Request(url, headers=headers)
    for attempt in range(MAX_RETRIES):
        try:
            t0 = time.time()
            with request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                elapsed = int((time.time() - t0) * 1000)
                return r.status, len(body), elapsed
        except error.HTTPError as e:
            if attempt == MAX_RETRIES - 1:
                return e.code, 0, 0
            time.sleep(2)
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(2)

def smoke(name, url, expect_status=200, min_size=500, must_contain=None, critical=True):
    try:
        status, size, elapsed = fetch_url(url)
        ok = (status == expect_status) and (size >= min_size)
        if ok and must_contain:
            # We'd need to re-fetch with content, skip content check in smoke test
            pass
        result = "[PASS]" if ok else "[FAIL]"
        detail = "HTTP " + str(status) + " | " + str(size) + " bytes | " + str(elapsed) + "ms"
        print("  " + result + " " + name)
        print("         " + url)
        print("         " + detail)
        if not ok:
            if critical:
                failures.append((name, "Expected HTTP " + str(expect_status) + " >= " + str(min_size) + "B, got HTTP " + str(status) + " " + str(size) + "B"))
            else:
                warnings.append((name, detail))
        return ok
    except Exception as e:
        print("  [FAIL] " + name + " -- EXCEPTION: " + str(e))
        if critical:
            failures.append((name, str(e)))
        else:
            warnings.append((name, str(e)))
        return False

print("=" * 62)
print("  SENTINEL APEX POST-DEPLOY SMOKE TESTS v158.0")
print("  Platform: " + PLATFORM_URL)
print("  " + datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
print("=" * 62)

# ── P0 CRITICAL ROUTES ───────────────────────────────────────────
print("\n[P0 CRITICAL ROUTES]")
smoke("Homepage",               PLATFORM_URL + "/",                    200, 100_000)
smoke("PAYMENT-GATEWAY.html",   PLATFORM_URL + "/PAYMENT-GATEWAY.html",200, 10_000)
smoke("404.html",               PLATFORM_URL + "/404.html",            200, 1_000)

# ── DASHBOARD ROUTES ─────────────────────────────────────────────
print("\n[DASHBOARD ROUTES]")
smoke("Enterprise Dashboard",   PLATFORM_URL + "/dashboard/enterprise_dashboard.html",   200, 10_000)
smoke("SOC V2 Dashboard",       PLATFORM_URL + "/dashboard/enterprise_dashboard_v2.html",200, 10_000)
smoke("Orchestration Hub",      PLATFORM_URL + "/dashboard/orchestration_hub.html",      200, 5_000)
smoke("Web3 Intel",             PLATFORM_URL + "/dashboard/web3_dashboard.html",         200, 5_000)
smoke("Analyst Dashboard",      PLATFORM_URL + "/dashboard/analyst_dashboard.html",      200, 5_000)

# ── API ENDPOINTS ─────────────────────────────────────────────────
print("\n[API ENDPOINTS]")
smoke("AI Brain Summary",        PLATFORM_URL + "/api/v1/intel/ai_summary.json", 200, 1_000)
smoke("Live Feed",              PLATFORM_URL + "/feed.json",               200, 10_000)
smoke("Latest Feed",            PLATFORM_URL + "/latest.json",             200, 10_000)
smoke("Feed Manifest",          PLATFORM_URL + "/feed_manifest.json",      200, 500)

# ── ASSETS ────────────────────────────────────────────────────────
print("\n[STATIC ASSETS]")
smoke("Service Worker",         PLATFORM_URL + "/service-worker.js",    200, 500)
smoke("Manifest JSON",          PLATFORM_URL + "/manifest.json",        200, 100)

# ── KNOWN 404 CHECK (regression guard) ───────────────────────────
print("\n[REGRESSION 404 GUARD]")
# These URLs used to 404 — verify they no longer do
smoke("No 404 on PAYMENT-GATEWAY",  PLATFORM_URL + "/PAYMENT-GATEWAY.html",  200, 10_000)
smoke("No 404 on Enterprise Dash",  PLATFORM_URL + "/dashboard/enterprise_dashboard.html", 200, 10_000)
smoke("No 404 on SOC V2",           PLATFORM_URL + "/dashboard/enterprise_dashboard_v2.html", 200, 10_000)

# ── SUMMARY ───────────────────────────────────────────────────────
print("")
print("=" * 62)
print("  SMOKE TEST RESULTS")
print("=" * 62)
if warnings:
    print("  Warnings (" + str(len(warnings)) + "):")
    for n, d in warnings: print("    [WARN] " + n + " -- " + d)

if failures:
    print("  FAILURES (" + str(len(failures)) + "):")
    for n, d in failures: print("    [FAIL] " + n + " -- " + d)
    print("")
    print("  POST-DEPLOY SMOKE TESTS: FAILED")
    print("  ACTION: Investigate failures. Consider rollback if P0 routes are down.")
    sys.exit(1)
else:
    print("  ALL SMOKE TESTS PASSED -- deployment verified")
    sys.exit(0)
