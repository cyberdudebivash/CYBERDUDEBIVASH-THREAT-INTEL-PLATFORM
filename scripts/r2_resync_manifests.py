#!/usr/bin/env python3
"""
scripts/r2_resync_manifests.py
CYBERDUDEBIVASH(R) SENTINEL APEX v160.0 -- R2 Post-Stage-3.93 Manifest Resync
==============================================================================
ROOT CAUSE FIX (v160.0):
  STAGE 3.5 (r2_upload.py) runs BEFORE STAGE 3.93 (Generate Immutable API
  Manifests). This means R2 receives PRE-generation manifests:
    - api/v1/intel/latest.json had 25 items at STAGE 3.5 time
    - api/v1/intel/top10.json had stale data
    - api/feed.json was not uploaded at all
  STAGE 3.93 then generates the FINAL versions of these files (71+ items),
  commits them to GitHub, but NEVER re-uploads them to R2.

  The Cloudflare Worker reads from R2 for all endpoints, so it kept serving
  the 25/54-item stale snapshots while GitHub Pages had 71 fresh items.

  THIS SCRIPT: Runs AFTER STAGE 3.93 (as STAGE 3.93.6) and re-syncs only
  the API manifest files that change during STAGE 3.93 generation.

Responsibility:
  Upload the post-3.93 final versions of:
    api/feed.json                → R2 api/feed.json         (full feed array)
    api/v1/intel/latest.json    → R2 api/v1/intel/latest.json
    api/v1/intel/top10.json     → R2 api/v1/intel/top10.json
    api/v1/intel/apex.json      → R2 api/v1/intel/apex.json
    api/v1/intel/manifest.json  → R2 api/v1/intel/manifest.json

Environment variables (same as r2_upload.py):
  CF_ACCOUNT_ID       -- Cloudflare account ID
  AWS_ACCESS_KEY_ID   -- R2 access key (same creds as STAGE 3.5)
  AWS_SECRET_ACCESS_KEY -- R2 secret key

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2_resync] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.r2_resync")

REPO_ROOT       = Path(__file__).resolve().parent.parent
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "160.0")
BUCKET_DATA     = "sentinel-apex-data"

# Files to re-upload after STAGE 3.93 generates the final manifests.
# Order: api/feed.json FIRST (most critical -- dashboard primary source).
RESYNC_FILES = [
    ("api/feed.json",                "api/feed.json",              "no-store, max-age=0"),
    ("api/v1/intel/latest.json",     "api/v1/intel/latest.json",   "public, max-age=300, stale-while-revalidate=60"),
    ("api/v1/intel/top10.json",      "api/v1/intel/top10.json",    "public, max-age=300, stale-while-revalidate=60"),
    ("api/v1/intel/apex.json",       "api/v1/intel/apex.json",     "no-cache, no-store, must-revalidate"),
    ("api/v1/intel/manifest.json",   "api/v1/intel/manifest.json", "public, max-age=300"),
    ("api/v1/intel/ai_summary.json", "api/v1/intel/ai_summary.json", "public, max-age=300"),
]


def get_credentials() -> tuple[str, str, str]:
    cf_account = os.environ.get("CF_ACCOUNT_ID", "").strip()
    access_key  = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key  = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if not cf_account or not access_key:
        log.error("FATAL: CF_ACCOUNT_ID or AWS_ACCESS_KEY_ID not set. Skipping resync.")
        sys.exit(1)
    return cf_account, access_key, secret_key


def s3_cp(src: str, dst_bucket: str, dst_key: str, endpoint: str,
          cache_control: str = "no-cache, no-store, must-revalidate") -> bool:
    cmd = [
        "aws", "s3", "cp", src, f"s3://{dst_bucket}/{dst_key}",
        "--endpoint-url", endpoint,
        "--content-type", "application/json",
        "--cache-control", cache_control,
        "--only-show-errors",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        log.info("OK: %s -> s3://%s/%s", src, dst_bucket, dst_key)
        return True
    log.warning(
        "WARN: Upload failed (%d): %s %s",
        result.returncode, result.stdout.strip()[:200], result.stderr.strip()[:200],
    )
    return False


def count_items(path: Path) -> int:
    """Return item count for a JSON file (array or dict with items/data/reports key)."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(d, list):
            return len(d)
        for k in ("items", "data", "reports", "advisories"):
            if isinstance(d.get(k), list):
                return len(d[k])
    except Exception:
        pass
    return 0


def main() -> None:
    log.info("=" * 64)
    log.info("SENTINEL APEX v%s -- R2 Post-STAGE-3.93 Manifest Resync", PIPELINE_VERSION)
    log.info("ROOT CAUSE FIX: upload final post-generation manifests to R2")
    log.info("=" * 64)

    os.chdir(REPO_ROOT)

    cf_account, _, _ = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"

    uploaded = 0
    skipped  = 0
    failed   = 0

    for src_rel, dst_key, cache_ctrl in RESYNC_FILES:
        src_path = REPO_ROOT / src_rel
        if not src_path.exists():
            log.warning("SKIP: %s not found -- STAGE 3.93 may not have generated it yet", src_rel)
            skipped += 1
            continue
        count = count_items(src_path)
        log.info("Uploading %s (%d items) -> R2 %s ...", src_rel, count, dst_key)
        ok = s3_cp(str(src_path), BUCKET_DATA, dst_key, endpoint, cache_ctrl)
        if ok:
            uploaded += 1
        else:
            failed += 1

    log.info("")
    log.info("R2 resync complete: %d uploaded, %d skipped, %d failed.", uploaded, skipped, failed)

    # Feed item count summary for CI visibility
    feed_path = REPO_ROOT / "api" / "feed.json"
    if feed_path.exists():
        total = count_items(feed_path)
        log.info("api/feed.json: %d items now live in R2 (dashboard will show fresh data).", total)

    if failed > 0:
        log.warning(
            "WARN: %d file(s) failed to upload to R2. "
            "Worker will fall back to KV/GitHub for those endpoints.",
            failed,
        )
        # Non-fatal: do not block the pipeline. KV TTL or next run will heal.
        sys.exit(0)

    log.info("All post-STAGE-3.93 manifests successfully synced to R2.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        log.warning(
            "r2_resync_manifests.py unhandled error (non-fatal): %s\n%s",
            e, traceback.format_exc(),
        )
        sys.exit(0)  # Always non-fatal -- pipeline must not die here
