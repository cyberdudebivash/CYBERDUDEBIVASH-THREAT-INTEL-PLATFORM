#!/usr/bin/env python3
"""
scripts/bust_kv_cache.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.2.0 -- Worker KV Cache Bust
=================================================================
P0 FIX: Replaces the inline curl/bash block in sentinel-blogger.yml.
Zero inline shell in YAML.

Busts all Cloudflare Worker KV cache keys for the intel dashboard.
Runs with if: always() -- safe to execute even when prior steps failed,
because busting a cache cannot corrupt data.

Environment variables:
  WORKER_ADMIN_SECRET  -- optional; if absent, KV expires naturally (3 min TTL)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [bust_kv_cache] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.bust_kv_cache")

BASE_URL = "https://intel.cyberdudebivash.com"
CACHE_KEYS = [
    "idx:reports",
    "idx:preview",
    "ai:index",
    "ai:analyze",
    "ai:respond",
    "ai:correlate",
]


def bust_key(session, key: str, secret: str) -> int:
    """POST a cache bust request. Returns HTTP status code."""
    try:
        import urllib.request
        url = f"{BASE_URL}/api/admin/cache/bust?key={key}"
        req = urllib.request.Request(
            url,
            method="POST",
            headers={"X-Admin-Secret": secret},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except Exception as e:
        log.warning("Cache bust %s failed: %s", key, e)
        return 0


def main() -> None:
    log.info("=" * 60)
    log.info("SENTINEL APEX -- Worker KV Cache Bust")
    log.info("=" * 60)

    secret = os.environ.get("WORKER_ADMIN_SECRET", "").strip()
    if not secret:
        log.info("WORKER_ADMIN_SECRET not set -- KV will expire naturally (3 min TTL).")
        log.info("ACTION: Set WORKER_ADMIN_SECRET secret for instant cache invalidation.")
        sys.exit(0)

    log.info("Busting %d cache keys...", len(CACHE_KEYS))
    any_success = False
    for key in CACHE_KEYS:
        status = bust_key(None, key, secret)
        if status == 200:
            log.info("OK: Cache bust %s -> HTTP %d", key, status)
            any_success = True
        else:
            log.info("INFO: Cache bust %s -> HTTP %d (non-fatal)", key, status)

    if any_success:
        log.info("Worker KV cache busted successfully.")
    else:
        log.info("Cache bust HTTP non-200 (non-fatal -- TTL expiry will serve fresh data).")

    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        log.warning("bust_kv_cache.py error (non-fatal): %s\n%s", e, traceback.format_exc())
        sys.exit(0)  # Always exit 0 -- cache bust must never kill pipeline
