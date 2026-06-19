#!/usr/bin/env python3
"""
scripts/r2_reports_integrity.py
CYBERDUDEBIVASH(R) SENTINEL APEX v1.0 -- R2 Reports Index Integrity Gate
=========================================================================
STAGE 3.5.1: Executed immediately after r2_upload.py (Stage 3.5).

PURPOSE:
  1. Verifies that current-run HTML reports were successfully uploaded to
     the sentinel-apex-reports R2 bucket.
  2. Purges stale entries from api/reports/index.json (entries that exist
     in the index but have no corresponding HTML in R2 sentinel-apex-reports).
  3. Re-uploads the cleaned api/reports/index.json to R2 sentinel-apex-data.

ROOT CAUSE FIX:
  r2_upload.py (Stage 3.5) treats HTML report upload as non-fatal -- it exits 0
  even when the upload to sentinel-apex-reports fails (credential issue, timeout,
  network error). The api/reports/index.json therefore accumulates ghost entries
  pointing to report URLs that do not exist in R2. Users who click these links
  receive a 404 JSON error from the Cloudflare Worker.

  This script detects and eliminates ghost entries, ensuring every entry in the
  published index points to an HTML file that actually exists in R2.

HARD FAIL condition:
  ALL current-run report URLs (derived from api/feed.json report_url fields) are
  missing from sentinel-apex-reports. This indicates the upload mechanism itself
  is broken (wrong credentials, missing bucket, permission denied). The pipeline
  must not publish a report index filled with 404 links.

NON-FATAL condition:
  Some historical index entries are missing from R2 (older runs with silent upload
  failures). These are purged and the pipeline continues cleanly.

EXIT CODES:
  0 -- OK (index is clean, or stale entries were purged and index re-uploaded)
  1 -- HARD FAIL (current-run reports ALL missing from R2 -- upload broken)

ENVIRONMENT (consumed):
  CF_ACCOUNT_ID            -- Cloudflare account ID
  CF_R2_REPORTS_KEY_ID     -- Dedicated R2 token for sentinel-apex-reports bucket
  CF_R2_REPORTS_SECRET_KEY -- Dedicated R2 secret for sentinel-apex-reports bucket
  AWS_ACCESS_KEY_ID        -- Job-level R2 key (sentinel-apex-data re-upload)
  AWS_SECRET_ACCESS_KEY    -- Job-level R2 secret (sentinel-apex-data re-upload)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2-integrity] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.r2_integrity")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO            = Path(__file__).resolve().parent.parent
INDEX_PATH      = REPO / "api" / "reports" / "index.json"
LATEST_PATH     = REPO / "api" / "reports" / "latest.json"
FEED_PATH       = REPO / "api" / "feed.json"
BUCKET_REPORTS  = "sentinel-apex-reports"
BUCKET_DATA     = "sentinel-apex-data"
MAX_WORKERS     = 20          # Parallel S3 head-object workers
MAX_CHECK       = 200         # Max index entries to verify (limits runtime)
CHECK_TIMEOUT   = 15          # Per-request timeout (seconds)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_github_env(key: str, value: str) -> None:
    gh_env = os.environ.get("GITHUB_ENV", "/dev/null")
    try:
        with open(gh_env, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")
    except Exception:
        pass


def _get_credentials() -> Tuple[str, str, str, str, str]:
    """
    Returns (cf_account, reports_key_id, reports_secret, data_key_id, data_secret).
    Falls back reports credentials to job-level if dedicated ones are absent.
    """
    cf_account  = os.environ.get("CF_ACCOUNT_ID", "").strip()
    reports_key = os.environ.get("CF_R2_REPORTS_KEY_ID", "").strip()
    reports_sec = os.environ.get("CF_R2_REPORTS_SECRET_KEY", "").strip()
    data_key    = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    data_sec    = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()

    if reports_key and reports_sec:
        log.info("Reports bucket check: using dedicated CF_R2_REPORTS_KEY_ID credentials")
    else:
        log.info("CF_R2_REPORTS_KEY_ID not set -- using job-level credentials for reports bucket check")
        reports_key = data_key
        reports_sec = data_sec

    return cf_account, reports_key, reports_sec, data_key, data_sec


def _path_to_r2_key(path_or_url: str) -> Optional[str]:
    """
    Convert a report path (/reports/2026/06/intel--xxx.html) or full URL to
    the R2 key used in sentinel-apex-reports (reports/2026/06/intel--xxx.html).
    """
    if not path_or_url:
        return None
    if path_or_url.startswith("http"):
        parsed = urlparse(path_or_url)
        path_or_url = parsed.path
    key = path_or_url.lstrip("/")
    return key if key.startswith("reports/") else None


def _r2_object_exists(
    key: str,
    bucket: str,
    endpoint: str,
    key_id: str,
    secret: str,
) -> bool:
    """Returns True if the object exists in R2 (authenticated S3 head-object)."""
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]     = key_id
    env["AWS_SECRET_ACCESS_KEY"] = secret

    result = subprocess.run(
        [
            "aws", "s3api", "head-object",
            "--bucket",       bucket,
            "--key",          key,
            "--endpoint-url", endpoint,
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=CHECK_TIMEOUT,
    )
    return result.returncode == 0


def _s3_cp(
    local_path: str,
    bucket: str,
    key: str,
    endpoint: str,
    key_id: str,
    secret: str,
) -> bool:
    """Upload a single file to R2. Returns True on success."""
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]     = key_id
    env["AWS_SECRET_ACCESS_KEY"] = secret

    result = subprocess.run(
        [
            "aws", "s3", "cp", local_path,
            f"s3://{bucket}/{key}",
            "--endpoint-url",  endpoint,
            "--content-type",  "application/json",
            "--cache-control", "no-cache, no-store, must-revalidate",
            "--only-show-errors",
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    if result.returncode == 0:
        log.info("OK: uploaded %s -> s3://%s/%s", local_path, bucket, key)
        return True
    log.warning("WARN: upload failed (%d): %s", result.returncode, result.stderr.strip()[:300])
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    log.info("=" * 70)
    log.info("R2 REPORTS INDEX INTEGRITY GATE v1.0  --  STAGE 3.5.1")
    log.info("=" * 70)

    # --- Credentials ---
    cf_account, reports_key, reports_sec, data_key, data_sec = _get_credentials()

    if not cf_account:
        log.warning("CF_ACCOUNT_ID not set -- skipping R2 integrity check (non-fatal)")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "SKIP_NO_ACCOUNT_ID")
        return 0

    if not reports_key or not reports_sec:
        log.warning("No R2 credentials available -- skipping integrity check (non-fatal)")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "SKIP_NO_CREDENTIALS")
        return 0

    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    log.info("R2 endpoint : %s", endpoint)
    log.info("Reports bucket : %s", BUCKET_REPORTS)

    # --- Load index ---
    if not INDEX_PATH.exists():
        log.warning("api/reports/index.json not found -- skipping (non-fatal)")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "SKIP_NO_INDEX")
        return 0

    try:
        index_data = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Failed to read api/reports/index.json: %s (non-fatal)", exc)
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "ERROR_READ_INDEX")
        return 0

    all_entries: List[dict] = index_data.get("reports", [])
    if not all_entries:
        log.info("Index has no entries -- nothing to verify")
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS", "OK_EMPTY_INDEX")
        return 0

    log.info("Index entries: %d total", len(all_entries))

    # --- Identify current-run report keys from api/feed.json ---
    current_run_keys: Set[str] = set()
    if FEED_PATH.exists():
        try:
            feed = json.loads(FEED_PATH.read_text(encoding="utf-8"))
            items = feed if isinstance(feed, list) else []
            for item in items:
                ru = item.get("report_url", "")
                if ru:
                    key = _path_to_r2_key(ru)
                    if key:
                        current_run_keys.add(key)
            log.info("Current-run report URLs: %d (from api/feed.json)", len(current_run_keys))
        except Exception as exc:
            log.warning("Could not read api/feed.json: %s (non-fatal)", exc)

    # --- Select entries to check (most recent MAX_CHECK + all current-run) ---
    entries_to_check = all_entries[:MAX_CHECK]
    skipped = len(all_entries) - len(entries_to_check)
    if skipped > 0:
        log.info("Checking %d entries (oldest %d skipped to respect runtime budget)",
                 len(entries_to_check), skipped)
    else:
        log.info("Checking all %d entries", len(entries_to_check))

    # Build the key list for the entries to check
    entry_key_map: Dict[str, dict] = {}   # r2_key -> entry
    for entry in entries_to_check:
        r2_key = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
        if r2_key:
            entry_key_map[r2_key] = entry

    # Also include any current-run keys not already in the checked set
    for ck in current_run_keys:
        if ck not in entry_key_map:
            # Find from all_entries by key
            for entry in all_entries:
                candidate_key = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
                if candidate_key == ck:
                    entry_key_map[ck] = entry
                    break

    all_keys_to_check = list(entry_key_map.keys())
    log.info("Dispatching %d parallel R2 head-object checks (workers=%d)...",
             len(all_keys_to_check), MAX_WORKERS)

    # --- Parallel R2 existence checks ---
    key_exists: Dict[str, bool] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_key = {
            pool.submit(
                _r2_object_exists, k, BUCKET_REPORTS, endpoint, reports_key, reports_sec
            ): k
            for k in all_keys_to_check
        }
        for future in as_completed(future_to_key):
            k = future_to_key[future]
            try:
                exists = future.result()
            except Exception as exc:
                log.warning("R2 check error for %s: %s -- treating as present (conservative)", k, exc)
                exists = True   # never purge on check error
            key_exists[k] = exists

    # --- Tally results ---
    missing_keys: Set[str] = {k for k, v in key_exists.items() if not v}
    present_keys: Set[str] = {k for k, v in key_exists.items() if v}

    log.info("R2 check results: %d present / %d missing (of %d checked)",
             len(present_keys), len(missing_keys), len(key_exists))

    # --- Assess current-run upload health ---
    current_missing = current_run_keys & missing_keys
    current_present = current_run_keys & present_keys
    log.info("Current-run reports: %d in R2 / %d missing from R2",
             len(current_present), len(current_missing))

    if current_missing:
        log.warning("Missing current-run reports from R2:")
        for mk in sorted(current_missing)[:10]:
            log.warning("  MISSING: %s", mk)

    # --- Purge stale entries from index ---
    clean_entries: List[dict] = []
    purged_count = 0

    for entry in all_entries:
        r2_key = _path_to_r2_key(entry.get("path", "") or entry.get("url", ""))
        if r2_key and key_exists.get(r2_key) is False:
            # Confirmed missing from R2 -- purge
            purged_count += 1
        else:
            clean_entries.append(entry)

    if purged_count > 0:
        log.info("Purged %d stale entries from api/reports/index.json "
                 "(had no HTML in R2 sentinel-apex-reports)", purged_count)
        log.info("Index: %d entries before -> %d entries after purge",
                 len(all_entries), len(clean_entries))

        # Write back cleaned index
        index_data["reports"]         = clean_entries
        index_data["reports_listed"]  = len(clean_entries)
        index_data["generated_at"]    = _utc_now()

        try:
            tmp = INDEX_PATH.with_suffix(".integrity_tmp")
            tmp.write_text(
                json.dumps(index_data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            os.replace(tmp, INDEX_PATH)
            log.info("OK: api/reports/index.json written with %d clean entries", len(clean_entries))
        except Exception as exc:
            log.error("Failed to write cleaned index: %s (non-fatal)", exc)

        # Also update api/reports/latest.json if it exists
        if LATEST_PATH.exists():
            try:
                latest_data = json.loads(LATEST_PATH.read_text(encoding="utf-8"))
                latest_reports = latest_data.get("reports", [])
                clean_latest = [
                    e for e in latest_reports
                    if _path_to_r2_key(e.get("path", "") or e.get("url", "")) not in missing_keys
                ]
                if len(clean_latest) < len(latest_reports):
                    latest_data["reports"]        = clean_latest
                    latest_data["reports_listed"] = len(clean_latest)
                    latest_data["generated_at"]   = _utc_now()
                    tmp2 = LATEST_PATH.with_suffix(".integrity_tmp")
                    tmp2.write_text(
                        json.dumps(latest_data, indent=2, ensure_ascii=False, default=str),
                        encoding="utf-8",
                    )
                    os.replace(tmp2, LATEST_PATH)
                    log.info("OK: api/reports/latest.json purged %d stale entries",
                             len(latest_reports) - len(clean_latest))
            except Exception as exc:
                log.warning("Could not update api/reports/latest.json: %s (non-fatal)", exc)

        # Re-upload cleaned index files to R2 sentinel-apex-data
        if data_key and data_sec:
            log.info("Re-uploading cleaned index files to R2 (sentinel-apex-data)...")
            for rel, local_p in [
                ("api/reports/index.json",  INDEX_PATH),
                ("api/reports/latest.json", LATEST_PATH),
            ]:
                if local_p.exists():
                    _s3_cp(str(local_p), BUCKET_DATA, rel, endpoint, data_key, data_sec)
        else:
            log.warning("WARN: No data bucket credentials -- cannot re-upload cleaned index to R2")
    else:
        log.info("Index is clean -- no stale entries detected in checked range (%d entries)",
                 len(entries_to_check))

    # --- Determine exit status ---
    # HARD FAIL only when ALL current-run reports are missing from R2.
    # This means the upload mechanism itself is broken (credentials, bucket, etc.).
    # A partial failure (some historical entries missing) is non-fatal after purge.
    if current_run_keys and len(current_present) == 0 and len(current_missing) > 0:
        log.error("=" * 70)
        log.error("HARD FAIL: STAGE 3.5 HTML upload to sentinel-apex-reports is BROKEN")
        log.error("ALL %d current-run reports are missing from R2.", len(current_missing))
        log.error("Root cause: CF_R2_REPORTS_KEY_ID / CF_R2_REPORTS_SECRET_KEY may be")
        log.error("  invalid, missing, or the sentinel-apex-reports bucket is unreachable.")
        log.error("ACTION REQUIRED: Verify secrets and bucket permissions.")
        log.error("=" * 70)
        _write_github_env("R2_REPORTS_INTEGRITY_STATUS",
                          f"HARD_FAIL_all_{len(current_missing)}_current_run_reports_missing")
        return 1

    # Partial current-run failure (some missing, some present) -- warn but continue
    if current_missing:
        log.warning("WARN: %d/%d current-run reports missing from R2 (partial upload failure)",
                    len(current_missing), len(current_run_keys))

    status = (
        f"OK_purged={purged_count}"
        f"_checked={len(key_exists)}"
        f"_clean={len(clean_entries)}"
    )
    _write_github_env("R2_REPORTS_INTEGRITY_STATUS", status)

    log.info("=" * 70)
    log.info("INTEGRITY GATE COMPLETE")
    log.info("  Entries checked  : %d", len(key_exists))
    log.info("  Present in R2    : %d", len(present_keys))
    log.info("  Missing (purged) : %d", purged_count)
    log.info("  Index remaining  : %d", len(clean_entries))
    log.info("  Status           : %s", status)
    log.info("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
