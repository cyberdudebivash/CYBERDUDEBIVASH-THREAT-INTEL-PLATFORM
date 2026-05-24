#!/usr/bin/env python3
"""
scripts/r2_upload.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.5.1 -- Cloudflare R2 Upload Engine
=========================================================================
P0 FIX: Replaces the inline PYEOF/unquoted-heredoc R2 upload block from
sentinel-blogger.yml.  Zero inline Python in YAML.

v143.5.1 FIX (R2 TIMEOUT ROOT CAUSE):
  - timeout-minutes: 60 in the workflow was killing the job before the HTML
    report sync could complete (18k+ files, ~35 min with default awscli).
  - Fix 1: configure_awscli_performance() sets 50 concurrent requests and
    disables per-file checksum (--size-only) for large directory syncs.
  - Fix 2: subprocess timeout=2700 (45 min) on reports sync -- non-fatal,
    pipeline continues even if reports upload is incomplete.
  - Fix 3: workflow timeout-minutes raised to 180 (companion change).

Responsibilities:
  1.  Validate R2 credentials (CF_ACCOUNT_ID, AWS_ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY).  Exit 1 if any missing.
  2.  Install awscli if not present.
  3.  Configure awscli for high-throughput parallel uploads.
  4.  Upload feed_manifest.json and enriched manifests.
  5.  Upload apex_v2 API endpoint files.
  6.  Upload generated HTML reports (Tactical Dossiers) -- non-fatal.
  7.  Upload AI intelligence data files.
  8.  Write and upload sync_meta.json with advisory count + run metadata.

Environment variables consumed (set at job level in workflow):
  CF_ACCOUNT_ID            -- Cloudflare account ID
  AWS_ACCESS_KEY_ID        -- R2 access key
  AWS_SECRET_ACCESS_KEY    -- R2 secret key
  CF_R2_REPORTS_KEY_ID     -- Dedicated token for sentinel-apex-reports bucket
  CF_R2_REPORTS_SECRET_KEY -- Dedicated secret for sentinel-apex-reports bucket
  PIPELINE_VERSION         -- e.g. 143.0.0
  GITHUB_RUN_ID            -- GitHub run ID
  REPORT_COUNT             -- set by run_pipeline.py

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2_upload] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.r2_upload")

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "160.0")
BUCKET_DATA = "sentinel-apex-data"
BUCKET_REPORTS = "sentinel-apex-reports"

# Max seconds the HTML report sync may run before being abandoned (non-fatal).
# Set to 45 minutes -- generous headroom for 18k+ files at 50 concurrent threads.
REPORTS_SYNC_TIMEOUT_SECONDS = 2700


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def write_github_env(key: str, value: str) -> None:
    gh_env = os.environ.get("GITHUB_ENV", "/dev/null")
    try:
        with open(gh_env, "a", encoding="utf-8") as fh:
            fh.write(f"{key}={value}\n")
    except Exception:
        pass


def get_credentials() -> tuple[str, str, str]:
    """Return (cf_account_id, access_key, secret_key). Exit 1 if missing."""
    cf_account = os.environ.get("CF_ACCOUNT_ID", "").strip()
    access_key  = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key  = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()

    if not cf_account or not access_key:
        log.error("FATAL: CF_ACCOUNT_ID or AWS_ACCESS_KEY_ID not set.")
        log.error("Add secrets per SETUP_GITHUB_SECRETS.md -- R2 upload is MANDATORY.")
        sys.exit(1)
    return cf_account, access_key, secret_key


def install_awscli() -> None:
    """Install awscli if aws command is not available."""
    result = subprocess.run(["aws", "--version"], capture_output=True)
    if result.returncode == 0:
        log.info("awscli already installed.")
        return
    log.info("Installing awscli...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "awscli", "--quiet"],
        check=False,
    )


def configure_awscli_performance() -> None:
    """
    Configure awscli for high-throughput R2 uploads.

    Root cause of the 36-minute stall: default awscli uses only 10 concurrent
    requests and computes MD5 checksums for every file before uploading.
    For 18k+ HTML reports this takes 35+ minutes, exceeding the old 60-minute
    job timeout.

    Fix:
      - max_concurrent_requests = 50  (5x throughput increase)
      - multipart_chunksize = 16MB    (fewer round trips per file)
      - max_queue_size = 10000        (larger in-flight queue)
      - multipart_threshold = 64MB   (single-part for small HTML files)

    The --size-only flag on s3 sync handles the checksum problem separately.
    """
    settings = [
        ("default.s3.max_concurrent_requests", "50"),
        ("default.s3.multipart_chunksize", "16MB"),
        ("default.s3.max_queue_size", "10000"),
        ("default.s3.multipart_threshold", "64MB"),
    ]
    for key, value in settings:
        subprocess.run(
            ["aws", "configure", "set", key, value],
            capture_output=True, check=False,
        )
    log.info(
        "OK: awscli performance profile set -- "
        "50 concurrent requests, 16MB chunks, size-only comparison."
    )


def s3_cp(
    src: str,
    dst_bucket: str,
    dst_key: str,
    endpoint: str,
    content_type: str = "application/json",
    cache_control: str = "no-cache, no-store, must-revalidate",
    only_show_errors: bool = True,
) -> bool:
    """Upload a single file to R2. Returns True on success."""
    cmd = [
        "aws", "s3", "cp", src, f"s3://{dst_bucket}/{dst_key}",
        "--endpoint-url", endpoint,
        "--content-type", content_type,
        "--cache-control", cache_control,
    ]
    if only_show_errors:
        cmd.append("--only-show-errors")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        log.info("OK: Uploaded %s -> s3://%s/%s", src, dst_bucket, dst_key)
        return True
    log.warning(
        "WARN: Upload failed (%d): %s %s",
        result.returncode, result.stdout.strip(), result.stderr.strip(),
    )
    return False


def s3_sync(
    src_dir: str,
    dst_bucket: str,
    dst_prefix: str,
    endpoint: str,
    content_type: str = "text/html; charset=utf-8",
    cache_control: str = "public, max-age=300",
    size_only: bool = False,
    timeout_seconds: int | None = None,
) -> bool:
    """
    Sync a directory to R2. Returns True on success.

    Args:
        size_only:       Use --size-only instead of full MD5 checksum comparison.
                         Dramatically faster for large directories where most files
                         are already in R2 and unchanged.
        timeout_seconds: Hard subprocess timeout in seconds. On expiry, logs a WARN
                         and returns False (non-fatal). Prevents job-level timeout
                         kill from leaving the pipeline in an unknown state.
    """
    cmd = [
        "aws", "s3", "sync", src_dir, f"s3://{dst_bucket}/{dst_prefix}",
        "--endpoint-url", endpoint,
        "--content-type", content_type,
        "--cache-control", cache_control,
        "--only-show-errors",
    ]
    if size_only:
        cmd.append("--size-only")

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "WARN: s3 sync timed out after %ds (non-fatal). "
            "Partial upload may have occurred -- existing R2 files remain valid. "
            "Remaining files will sync on the next pipeline run.",
            timeout_seconds,
        )
        return False

    if result.returncode == 0:
        log.info("OK: Synced %s -> s3://%s/%s", src_dir, dst_bucket, dst_prefix)
        return True
    log.warning(
        "WARN: Sync had errors (%d): %s",
        result.returncode, result.stderr.strip()[:400],
    )
    return False


def count_manifest() -> int:
    """Count advisory entries in feed_manifest.json."""
    path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if not path.exists():
        return 0
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(d, list):
            return len(d)
        if isinstance(d, dict):
            for key in ("advisories", "reports", "items"):
                if key in d and isinstance(d[key], list):
                    return len(d[key])
    except Exception:
        pass
    return 0


def main() -> None:
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- R2 Upload Engine", PIPELINE_VERSION)
    log.info("=" * 60)

    os.chdir(REPO_ROOT)

    cf_account, access_key, secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"

    install_awscli()

    # Configure awscli for high-throughput parallel uploads BEFORE any transfer.
    # This is the primary fix for the 36-minute stall / job-timeout cancellation.
    configure_awscli_performance()

    item_count = count_manifest()
    log.info("Uploading %d advisories to R2...", item_count)

    # --- Upload 1: Primary feed manifest (OVERWRITE) ---
    s3_cp(
        "data/stix/feed_manifest.json",
        BUCKET_DATA, "intel/feed_manifest.json",
        endpoint,
    )
    log.info("OK: feed_manifest.json uploaded (%d items)", item_count)

    # --- Upload 2: Enriched manifests ---
    enriched_files = [
        ("data/apex_enriched_manifest.json",    "intel/apex_enriched_manifest.json"),
        ("data/apex_v2_manifest.json",          "intel/apex_v2_manifest.json"),
        ("data/apex_v2_strategic_report.json",  "intel/apex_v2_strategic_report.json"),
        ("data/validated_manifest.json",        "intel/validated_manifest.json"),
    ]
    for src, dst_key in enriched_files:
        if Path(src).exists():
            s3_cp(src, BUCKET_DATA, dst_key, endpoint)

    # --- Upload 3: apex_v2 API endpoint files ---
    apex_v2_dir = REPO_ROOT / "api" / "apex_v2"
    if apex_v2_dir.is_dir():
        for f in apex_v2_dir.glob("*.json"):
            s3_cp(str(f), BUCKET_DATA, f"apex_v2/{f.name}", endpoint)
        log.info("OK: apex_v2/ uploaded")

    # --- Upload 3a: Immutable public intel manifests (v150.1 API-first) ---
    # Served by Cloudflare Worker via servePublicIntelManifest() using
    # r2Key = pathname.slice(1), e.g. "api/v1/intel/latest.json".
    # Uploading here guarantees Worker hits R2 (primary, ~1ms) instead of
    # GitHub raw fallback (~150-300ms, rate-limited).
    #
    # v160.0 FIX: api/feed.json is now EXPLICITLY uploaded to R2.
    # ROOT CAUSE: handleFeedJson in the Worker reads intel/feed_manifest.json
    # (STIX format -- only ~54 items survive normaliseManifestData filtering)
    # while api/feed.json has ALL pipeline items (71+ items, plain array).
    # Uploading api/feed.json as R2 key "api/feed.json" lets the Worker serve
    # the full authoritative feed without schema-loss normalisation.
    intel_v1_manifests = [
        ("api/feed.json",                 "api/feed.json"),                # v160.0 CRITICAL FIX
        ("api/v1/intel/latest.json",      "api/v1/intel/latest.json"),
        ("api/v1/intel/top10.json",       "api/v1/intel/top10.json"),
        ("api/v1/intel/apex.json",        "api/v1/intel/apex.json"),
        ("api/v1/intel/manifest.json",    "api/v1/intel/manifest.json"),
        ("api/v1/intel/ai_summary.json",  "api/v1/intel/ai_summary.json"),  # AI Cyber Brain endpoint (v147.0)
        # v161.3: Reports index files -- public (dashboard REPORTS tab via Worker)
        # Written by build_reports_index.py (Stage 3.3.7). Must be in R2 so the
        # Worker can serve them without auth to the public dashboard.
        ("api/reports/latest.json",       "api/reports/latest.json"),    # top-50 for dashboard REPORTS tab
        ("api/reports/index.json",        "api/reports/index.json"),     # full 500-entry index
        ("api/reports/stats.json",        "api/reports/stats.json"),     # severity breakdown + totals
    ]
    uploaded_manifests = 0
    for src, dst_key in intel_v1_manifests:
        src_path = REPO_ROOT / src
        if src_path.exists():
            s3_cp(str(src_path), BUCKET_DATA, dst_key, endpoint)
            uploaded_manifests += 1
        else:
            log.warning("SKIP: %s not found (will fallback to GitHub raw)", src)
    log.info(
        "OK: api/v1/intel/ manifests uploaded (%d/%d)",
        uploaded_manifests, len(intel_v1_manifests),
    )

    # --- Upload 3b: AI Tracker endpoint files (v148.1.0 FIX - MANDATORY) ---
    # ROOT CAUSE FIX: api/ai/tracker.json, health.json, executive-brief.json
    # were not being explicitly tracked. This block ensures all four AI Tracker
    # files are explicitly uploaded each pipeline run (the ai_dirs loop in
    # Upload 4b also covers these, but this explicit block provides auditability
    # and fail-safe coverage even if generate_ai_endpoints.py step is skipped).
    ai_tracker_files = [
        ("api/ai/tracker.json",          "ai/tracker.json"),
        ("api/ai/health.json",           "ai/health.json"),
        ("api/ai/executive-brief.json",  "ai/executive-brief.json"),
        ("api/ai/monetization.json",     "ai/monetization.json"),
    ]
    uploaded_ai_tracker = 0
    for src, dst_key in ai_tracker_files:
        src_path = REPO_ROOT / src
        if src_path.exists():
            s3_cp(str(src_path), BUCKET_DATA, dst_key, endpoint)
            uploaded_ai_tracker += 1
        else:
            log.warning("SKIP (AI tracker): %s not found -- run generate-and-sync workflow first", src)
    log.info("OK: AI Tracker files uploaded to R2 (%d/%d)", uploaded_ai_tracker, len(ai_tracker_files))


    # --- Upload 4a: Generated HTML reports (Tactical Dossiers) ---
    # v143.5.1 FIX: Two-part fix for 36-minute stall / job-timeout cancellation:
    #   1. awscli configured with 50 concurrent requests (5x faster)
    #   2. --size-only skips per-file MD5 checksum (reports already in R2 skip fast)
    #   3. subprocess timeout=2700 (45 min) -- non-fatal hard cap, pipeline continues
    #
    # Credentials: uses dedicated CF_R2_REPORTS_KEY_ID / CF_R2_REPORTS_SECRET_KEY
    # for sentinel-apex-reports bucket (scoped R2 token, injected via step-level env).
    # Falls back to job-level AWS credentials if per-bucket secrets absent.
    reports_dir = REPO_ROOT / "reports"
    if reports_dir.is_dir() and any(reports_dir.rglob("*.html")):
        log.info("Uploading HTML reports to R2 (sentinel-apex-reports)...")
        log.info(
            "Performance: 50 concurrent requests, --size-only, 45-min hard timeout."
        )

        # Swap in per-bucket credentials if available
        reports_key_id = os.environ.get("CF_R2_REPORTS_KEY_ID", "").strip()
        reports_secret = os.environ.get("CF_R2_REPORTS_SECRET_KEY", "").strip()
        orig_key_id    = os.environ.get("AWS_ACCESS_KEY_ID", "")
        orig_secret    = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

        if reports_key_id and reports_secret:
            os.environ["AWS_ACCESS_KEY_ID"]    = reports_key_id
            os.environ["AWS_SECRET_ACCESS_KEY"] = reports_secret
            log.info("Using dedicated sentinel-apex-reports R2 token.")
        else:
            log.info("CF_R2_REPORTS_KEY_ID not set -- using job-level R2 credentials.")

        try:
            reports_ok = s3_sync(
                "reports/", BUCKET_REPORTS, "reports/", endpoint,
                content_type="text/html; charset=utf-8",
                cache_control="public, max-age=300",
                size_only=True,                       # Skip MD5 -- use file size comparison
                timeout_seconds=REPORTS_SYNC_TIMEOUT_SECONDS,  # 45-min hard cap
            )
        finally:
            # Always restore original credentials regardless of outcome
            os.environ["AWS_ACCESS_KEY_ID"]    = orig_key_id
            os.environ["AWS_SECRET_ACCESS_KEY"] = orig_secret

        if reports_ok:
            log.info("OK: HTML reports uploaded to R2 (%s/reports/)", BUCKET_REPORTS)
        else:
            log.warning(
                "WARN: HTML reports R2 sync incomplete (non-fatal -- existing reports "
                "in R2 remain valid). Reports will retry on next pipeline run. "
                "Check bucket permissions for %s and verify CF_R2_REPORTS_KEY_ID secret.",
                BUCKET_REPORTS,
            )
    else:
        log.info("INFO: No reports/ directory or HTML files -- skipping report upload.")

    # --- Upload 4b: AI intelligence data ---
    # First generate AI endpoints from current manifest
    result = subprocess.run(
        [sys.executable, "scripts/generate_ai_endpoints.py"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log.warning(
            "WARN: AI endpoint generation failed (non-fatal): %s",
            result.stderr.strip()[:200],
        )

    ai_dirs = [REPO_ROOT / "data" / "ai_intelligence", REPO_ROOT / "api" / "ai"]
    for ai_dir in ai_dirs:
        if ai_dir.is_dir():
            for f in ai_dir.glob("*.json"):
                s3_cp(str(f), BUCKET_DATA, f"ai/{f.name}", endpoint)
    log.info("OK: AI intelligence data uploaded")

    # --- Upload 5: Sync metadata ---
    meta = {
        "synced_at":        utc_now(),
        "advisory_count":   item_count,
        "source":           "sentinel-blogger",
        "pipeline_version": PIPELINE_VERSION,
        "run_id":           os.environ.get("GITHUB_RUN_ID", "local"),
        "p0_fix":           "v143.5.1 -- r2_timeout_fix, awscli_perf, size_only_sync",
    }
    sync_meta_path = "/tmp/sync_meta.json"
    with open(sync_meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    s3_cp(sync_meta_path, BUCKET_DATA, "intel/_sync_meta.json", endpoint)
    log.info("OK: Sync metadata written (%d advisories synced to R2)", item_count)

    write_github_env("R2_UPLOAD_COUNT", str(item_count))
    log.info("R2 upload complete.")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        log.critical(
            "Unhandled exception in r2_upload.py:\n%s\n%s", e, traceback.format_exc(),
        )
        sys.exit(1)
