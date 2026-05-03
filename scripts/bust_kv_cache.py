#!/usr/bin/env python3
"""
scripts/bust_kv_cache.py
CYBERDUDEBIVASH® SENTINEL APEX v143.0.0 — Worker KV Cache Bust
================================================================
Busts all Cloudflare Worker KV cache keys so the edge serves fresh
intelligence immediately after a pipeline run. Runs with if: always()
in GitHub Actions — safe even when prior steps failed, because cache
invalidation cannot corrupt data.

Environment variable (set in GitHub Actions → Settings → Secrets):
  WORKER_ADMIN_SECRET  → the value set via: npx wrangler secret put WORKER_ADMIN_SECRET
                          in the Worker. If absent, KV expires via natural TTL (~60s).

To add the secret to GitHub Actions:
  1. Go to your repo → Settings → Secrets and variables → Actions
  2. Click "New repository secret"
  3. Name: WORKER_ADMIN_SECRET
  4. Value: <same value you set with wrangler secret put WORKER_ADMIN_SECRET>

To reference in your workflow YAML:
  env:
    WORKER_ADMIN_SECRET: ${{ secrets.WORKER_ADMIN_SECRET }}

Cache key prefixes and their purpose:
  idx:reports     — main feed index
  idx:preview     — dashboard preview cards
  ai:index        — AI enrichment index
  ai:analyze      — AI analysis cache
  ai:respond      — AI response cache
  ai:correlate    — AI correlation cache
  darkweb:scan:*  — Dark Web Monitor scan results (v143)
  darkweb:status:*— Dark Web Monitor scan status  (v143)
  reports:premium:*— Premium PDF report cache     (v143)
  reports:list:*  — Premium report listing cache  (v143)
  checkout:*      — Stripe checkout session cache (v143)

(c) 2026 CYBERDUDEBIVASH SENTINEL APEX. All Rights Reserved.
"""
from __future__ import annotations

import logging
import os
import sys
import time
import urllib.error
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [bust_kv_cache] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.bust_kv_cache")

BASE_URL = "https://intel.cyberdudebivash.com"

# ── v143.0.0: expanded key list includes all v143 GOD-MODE endpoints ──────────
CACHE_KEYS = [
    # Core feed / dashboard keys (v134+)
    "idx:reports",
    "idx:preview",
    "ai:index",
    "ai:analyze",
    "ai:respond",
    "ai:correlate",
    # Dark Web Monitor keys (v143)
    "darkweb:scan:*",
    "darkweb:status:*",
    # Premium PDF Report keys (v143)
    "reports:premium:*",
    "reports:list:*",
    # Stripe Checkout Session keys (v143)
    "checkout:*",
]

# Keys that are prefix-wildcards (bust via /api/admin/cache/bust-prefix endpoint)
WILDCARD_KEYS = {k for k in CACHE_KEYS if k.endswith(":*")}
EXACT_KEYS    = [k for k in CACHE_KEYS if not k.endswith(":*")]


def _make_request(url: str, secret: str, method: str = "POST") -> int:
    """Send an HTTP request. Returns status code or 0 on error."""
    try:
        req = urllib.request.Request(
            url, method=method,
            headers={"X-Admin-Secret": secret, "User-Agent": "SENTINEL-APEX-CACHE-BUST/143.0.0"},
        )
        with urllib.request.urlopen(req, timeout=12) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        log.debug("Request to %s failed: %s", url, e)
        return 0


def bust_exact_key(key: str, secret: str) -> int:
    """POST /api/admin/cache/bust?key={key} — invalidates a single cache key."""
    url = f"{BASE_URL}/api/admin/cache/bust?key={key}"
    status = _make_request(url, secret)
    return status


def bust_prefix_key(prefix: str, secret: str) -> int:
    """POST /api/admin/cache/bust-prefix?prefix={prefix} — invalidates all keys matching prefix."""
    clean_prefix = prefix.rstrip(":*")
    url = f"{BASE_URL}/api/admin/cache/bust-prefix?prefix={clean_prefix}"
    status = _make_request(url, secret)
    return status


def main() -> None:
    log.info("=" * 64)
    log.info("CYBERDUDEBIVASH SENTINEL APEX v143.0.0 — Worker KV Cache Bust")
    log.info("=" * 64)

    secret = os.environ.get("WORKER_ADMIN_SECRET", "").strip()

    if not secret:
        log.info("")
        log.info("⚠  WORKER_ADMIN_SECRET not set in environment.")
        log.info("   KV cache will expire via natural TTL (~60 seconds).")
        log.info("")
        log.info("   To enable instant cache invalidation, add this secret to GitHub Actions:")
        log.info("   → Repo → Settings → Secrets and variables → Actions → New repository secret")
        log.info("   → Name:  WORKER_ADMIN_SECRET")
        log.info("   → Value: <same value used with: npx wrangler secret put WORKER_ADMIN_SECRET>")
        log.info("")
        log.info("   Then reference it in your workflow YAML:")
        log.info("     env:")
        log.info("       WORKER_ADMIN_SECRET: ${{ secrets.WORKER_ADMIN_SECRET }}")
        log.info("")
        log.info("   Non-fatal: exiting with 0. Pipeline continues.")
        sys.exit(0)

    total     = len(EXACT_KEYS) + len(WILDCARD_KEYS)
    succeeded = 0
    failed    = 0
    skipped   = 0

    log.info("Busting %d cache targets (%d exact + %d prefix wildcards)…",
             total, len(EXACT_KEYS), len(WILDCARD_KEYS))
    log.info("")

    # ── Exact key busts
    for key in EXACT_KEYS:
        status = bust_exact_key(key, secret)
        if status == 200:
            log.info("  ✓  [200] Busted exact key: %s", key)
            succeeded += 1
        elif status == 404:
            log.info("  –  [404] Key not found (already cold): %s", key)
            skipped += 1
        elif status == 403:
            log.warning("  ✗  [403] Forbidden — WORKER_ADMIN_SECRET mismatch for key: %s", key)
            log.warning("       Verify the secret matches the Worker's WORKER_ADMIN_SECRET env var.")
            failed += 1
        elif status == 0:
            log.warning("  ✗  [ERR] Network error busting key: %s (non-fatal)", key)
            failed += 1
        else:
            log.info("  ~  [%d] Unexpected status for key: %s (non-fatal)", status, key)
            skipped += 1
        time.sleep(0.05)  # gentle rate-limiting — avoid Cloudflare 429

    # ── Prefix wildcard busts (v143 new endpoints)
    for key in sorted(WILDCARD_KEYS):
        status = bust_prefix_key(key, secret)
        if status == 200:
            log.info("  ✓  [200] Busted prefix: %s", key)
            succeeded += 1
        elif status == 404:
            log.info("  –  [404] Prefix endpoint not yet deployed (update Worker first): %s", key)
            skipped += 1
        elif status == 403:
            log.warning("  ✗  [403] Forbidden for prefix: %s", key)
            failed += 1
        elif status == 0:
            log.warning("  ~  [ERR] Network error for prefix: %s (non-fatal)", key)
            failed += 1
        else:
            log.info("  ~  [%d] Unexpected status for prefix: %s (non-fatal)", status, key)
            skipped += 1
        time.sleep(0.05)

    # ── Summary
    log.info("")
    log.info("Cache bust complete: %d succeeded, %d skipped, %d failed (non-fatal).",
             succeeded, skipped, failed)

    if failed > 0 and succeeded == 0:
        log.warning("")
        log.warning("All cache busts failed. Possible causes:")
        log.warning("  1. WORKER_ADMIN_SECRET value mismatch between GitHub secret and Worker env")
        log.warning("     Fix: npx wrangler secret put WORKER_ADMIN_SECRET  (re-enter value)")
        log.warning("  2. Worker not yet deployed (deploy first, then re-run pipeline)")
        log.warning("  3. Worker route not matching /api/admin/cache/bust")
        log.warning("")
        log.warning("Non-fatal: Worker KV TTL expiry will serve fresh data within ~60 seconds.")
    elif succeeded > 0:
        log.info("✓ Real-time cache invalidation active — dashboard will serve fresh intelligence immediately.")

    log.info("")
    sys.exit(0)  # Always exit 0 — cache bust must NEVER kill the pipeline


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        log.warning("bust_kv_cache.py unhandled error (non-fatal): %s\n%s",
                    e, traceback.format_exc())
        sys.exit(0)
