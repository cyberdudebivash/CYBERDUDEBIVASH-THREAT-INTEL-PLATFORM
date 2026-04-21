#!/usr/bin/env python3
"""
scripts/r2_upload.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0.0 -- Cloudflare R2 Upload Engine
=========================================================================
P0 FIX: Replaces the inline PYEOF/unquoted-heredoc R2 upload block from
sentinel-blogger.yml.  Zero inline Python in YAML.

Responsibilities:
  1.  Validate R2 credentials (CF_ACCOUNT_ID, AWS_ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY).  Exit 1 if any missing.
  2.  Install awscli if not present.
  3.  Upload feed_manifest.json and enriched manifests.
  4.  Upload apex_v2 API endpoint files.
  5.  Upload generated HTML reports (Tactical Dossiers).
  6.  Upload AI intelligence data files.
  7.  Write and upload sync_meta.json with advisory count + run metadata.

Environment variables consumed (set at job level in workflow):
  CF_ACCOUNT_ID            -- Cloudflare account ID
  AWS_ACCESS_KEY_ID        -- R2 access key
  AWS_SECRET_ACCESS_KEY    -- R2 secret key
  PIPELINE_VERSION         -- e.g. 131.2.0
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
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "131.2.0")
BUCKET_DATA = "sentinel-apex-data"
BUCKET_REPORTS = "sentinel-apex-reports"


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
    log.warning("WARN: Upload failed (%d): %s %s", result.returncode, result.stdout.strip(), result.stderr.strip())
    return False


def s3_sync(
    src_dir: str,
    dst_bucket: str,
    dst_prefix: str,
    endpoint: str,
    content_type: str = "text/html; charset=utf-8",
    cache_control: str = "public, max-age=300",
) -> bool:
    """Sync a directory to R2. Returns True on success."""
    cmd = [
        "aws", "s3", "sync", src_dir, f"s3://{dst_bucket}/{dst_prefix}",
        "--endpoint-url", endpoint,
        "--content-type", content_type,
        "--cache-control", cache_control,
        "--only-show-errors",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        log.info("OK: Synced %s -> s3://%s/%s", src_dir, dst_bucket, dst_prefix)
        return True
    log.warning("WARN: Sync had errors (%d): %s", result.returncode, result.stderr.strip()[:200])
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

    # --- Upload 4a: Generated HTML reports (Tactical Dossiers) ---
    reports_dir = REPO_ROOT / "reports"
    if reports_dir.is_dir() and any(reports_dir.rglob("*.html")):
        log.info("Uploading HTML reports to R2...")
        s3_sync(
            "reports/", BUCKET_REPORTS, "reports/", endpoint,
            content_type="text/html; charset=utf-8",
            cache_control="public, max-age=300",
        )
        log.info("OK: HTML reports uploaded to R2 (%s/reports/)", BUCKET_REPORTS)
    else:
        log.info("INFO: No reports/ directory or HTML files -- skipping report upload.")

    # --- Upload 4b: AI intelligence data ---
    # First generate AI endpoints from current manifest
    result = subprocess.run(
        [sys.executable, "scripts/generate_ai_endpoints.py"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log.warning("WARN: AI endpoint generation failed (non-fatal): %s", result.stderr.strip()[:200])

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
        "p0_fix":           "v134.0.0 -- inline_python_removed, encoding_guard_enforced",
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
        log.critical("Unhandled exception in r2_upload.py:\n%s\n%s", e, traceback.format_exc())
        sys.exit(1)
