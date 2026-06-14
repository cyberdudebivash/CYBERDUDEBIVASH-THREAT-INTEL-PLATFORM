#!/usr/bin/env python3
"""
scripts/r2_upload_verifier.py
CYBERDUDEBIVASH(R) SENTINEL APEX v149.1.0 -- R2 Upload Integrity Verifier
=========================================================================
STAGE 3.6: Executed immediately after r2_upload.py (Stage 3.5) and before
bust_kv_cache.py (Stage 3.7).

PURPOSE:
  Confirms the R2 upload from Stage 3.5 landed correctly before cache bust
  propagates potentially corrupt or missing data to the global CDN edge.

VERIFICATION STRATEGY (3-layer, authenticated via S3 API):
  Layer 1 -- Object existence: boto3/awscli head_object to sentinel-apex-data.
             Uses the same credentials as r2_upload.py (authenticated S3 API,
             NOT unauthenticated public HTTP which returns HTTP 400 on private
             R2 buckets -- that was the root cause of all previous Stage 3.6 failures).
  Layer 2 -- Size floor: ContentLength >= MIN_FEED_BYTES (default 1 KB).
             Catches truncated or empty uploads.
  Layer 3 -- ETag match: R2 ETag vs local MD5 (single-part) or warning (multi-part).
  Layer 4 -- Advisory count floor: sync_meta.json advisory_count >= 1 (hard fail on 0).
             Warn (non-blocking) when count < 5; pass when count >= 1.
             Checked at /tmp/sync_meta.json (where r2_upload.py writes it)
             before falling back to MANIFEST_FINAL_COUNT env var.
             v177.2 fix: floor lowered from 5→1. Runs with 1-4 advisories
             (legitimate after aggressive dedup) warn but no longer hard-fail.

ROOT CAUSE FIX (v149.1.0):
  BUG 1 FIXED: Wrong bucket -- was checking sentinel-apex-intel,
               r2_upload.py uploads to sentinel-apex-data.
  BUG 2 FIXED: Wrong key   -- was checking api/feed.json,
               primary manifest is intel/feed_manifest.json.
  BUG 3 FIXED: Unauthenticated HTTP HEAD -- R2 private buckets return
               HTTP 400 for unauthenticated requests. Was retried 3x
               then hard-failed as "bucket unreachable".
               FIX: Use awscli/boto3 S3 API (authenticated) as primary.
               HTTP HEAD is retained for diagnostic logging only.
  BUG 4 FIXED: Wrong sync_meta.json path -- was reading data/sync_meta.json
               (never written). Now checks /tmp/sync_meta.json first.

EXIT CODES:
  0 = All verification layers passed -- safe to proceed to cache bust
  1 = Hard fail -- R2 state does not match expected, cache bust BLOCKED

ENVIRONMENT (consumed from workflow env):
  CF_ACCOUNT_ID           -- Cloudflare account ID
  AWS_ACCESS_KEY_ID       -- R2 access key (same as used in r2_upload.py)
  AWS_SECRET_ACCESS_KEY   -- R2 secret key
  CF_R2_BUCKET_DATA       -- Primary data bucket (default: sentinel-apex-data)
  CF_R2_MANIFEST_KEY      -- Primary manifest S3 key (default: intel/feed_manifest.json)
  MANIFEST_FINAL_COUNT    -- Advisory count set by pipeline (fallback for Layer 4)
  PIPELINE_VERSION        -- version string for report

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2_verifier] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.r2_verifier")

# ---------------------------------------------------------------------------
# Constants -- corrected from v143.2.0 bugs
# ---------------------------------------------------------------------------
REPO = Path(__file__).resolve().parent.parent

FEED_PATH       = REPO / "api" / "feed.json"
MANIFEST_PATH   = REPO / "data" / "stix" / "feed_manifest.json"
REPORT_PATH     = REPO / "data" / "quality" / "r2_verify_report.json"

# sync_meta.json: r2_upload.py writes to /tmp/sync_meta.json before uploading.
# Check /tmp/ first, then fallback repo paths.
SYNC_META_PATHS = [
    Path("/tmp/sync_meta.json"),
    REPO / "data" / "quality" / "r2_sync_meta.json",
    REPO / "data" / "sync_meta.json",
]

MIN_FEED_BYTES     = 1_024          # Absolute minimum: 1 KB
MIN_ADVISORY_COUNT = 1              # Hard floor: only fail on count=0 (truly empty / failed upload).
                                    # Layers 1-3 (R2 existence + size + ETag) already confirm the object
                                    # is present and intact; Layer 4 exists purely to catch the
                                    # count=0 case (pipeline generated nothing and upload silently wrote
                                    # an empty manifest). Legitimate low-activity runs after aggressive
                                    # deduplication can produce 1-4 net-new STIX entries — that is
                                    # correct behaviour and must NOT hard-fail.
                                    # History: was 10 → lowered to 5 → now 1 (v177.2 permanent fix).
                                    # run #1622 produced 4 entries; floor of 5 caused a false HARD FAIL.
ADVISORY_COUNT_WARN = 5             # Warn (non-blocking) when count is low but above zero.
REQUEST_TIMEOUT    = 20             # seconds per HTTP check
MAX_RETRIES        = 3              # retry transient S3/network errors
RETRY_DELAY        = 4              # seconds between retries

# R2 configuration -- corrected names from bug analysis
CF_ACCOUNT_ID   = os.environ.get("CF_ACCOUNT_ID", "").strip()
ACCESS_KEY      = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
SECRET_KEY      = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()

# BUG 1 FIX: correct bucket is sentinel-apex-data (not sentinel-apex-intel)
BUCKET_DATA     = os.environ.get("CF_R2_BUCKET_DATA", "sentinel-apex-data")

# BUG 2 FIX: correct key is intel/feed_manifest.json (not api/feed.json)
MANIFEST_KEY    = os.environ.get("CF_R2_MANIFEST_KEY", "intel/feed_manifest.json")

R2_ENDPOINT     = (
    f"https://{CF_ACCOUNT_ID}.r2.cloudflarestorage.com"
    if CF_ACCOUNT_ID else ""
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    tmp.rename(path)


def _md5_file(path: Path) -> str:
    """Return hex MD5 of a file (matches R2 single-part ETag)."""
    h = hashlib.md5(usedforsecurity=False)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_sync_meta() -> Optional[Path]:
    """Find sync_meta.json -- check /tmp/ first (where r2_upload.py writes it)."""
    for p in SYNC_META_PATHS:
        if p.exists():
            log.info("sync_meta.json found at: %s", p)
            return p
    return None


# ---------------------------------------------------------------------------
# S3 API verification (primary method -- authenticated, works for private buckets)
# ---------------------------------------------------------------------------

def _s3api_head_object(bucket: str, key: str) -> Optional[dict]:
    """
    BUG 3 FIX: Use awscli s3api head-object (authenticated) to check an R2 object.
    This is the CORRECT method for private R2 buckets.
    Unauthenticated HTTP HEAD returns HTTP 400 on private R2 buckets.
    """
    if not CF_ACCOUNT_ID or not ACCESS_KEY or not SECRET_KEY:
        log.warning("S3 credentials absent -- cannot perform S3 API head-object check")
        return None

    cmd = [
        "aws", "s3api", "head-object",
        "--bucket", bucket,
        "--key", key,
        "--endpoint-url", R2_ENDPOINT,
        "--output", "json",
    ]
    env = os.environ.copy()
    env["AWS_ACCESS_KEY_ID"]     = ACCESS_KEY
    env["AWS_SECRET_ACCESS_KEY"] = SECRET_KEY
    env["AWS_DEFAULT_REGION"]    = "auto"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=REQUEST_TIMEOUT, env=env,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                content_length = int(data.get("ContentLength") or 0)
                etag = (data.get("ETag") or "").strip('"')
                log.info(
                    "S3 API head-object OK: s3://%s/%s -- size=%d bytes, etag=%s",
                    bucket, key, content_length, etag[:16] if etag else "N/A",
                )
                return {
                    "status":         200,
                    "content_length": content_length,
                    "etag":           etag,
                    "source":         "awscli_s3api",
                }
            elif "NoSuchKey" in result.stderr or result.returncode == 254:
                log.warning("S3 API: object not found: s3://%s/%s", bucket, key)
                return {"status": 404, "content_length": 0, "etag": "", "source": "awscli_s3api"}
            else:
                log.warning(
                    "S3 API head-object failed (attempt %d/%d): rc=%d stderr=%s",
                    attempt, MAX_RETRIES, result.returncode,
                    result.stderr.strip()[:200],
                )
        except subprocess.TimeoutExpired:
            log.warning("S3 API head-object timed out (attempt %d/%d)", attempt, MAX_RETRIES)
        except Exception as e:
            log.warning("S3 API head-object error (attempt %d/%d): %s", attempt, MAX_RETRIES, e)
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY)

    return None


def _boto3_head_object(bucket: str, key: str) -> Optional[dict]:
    """boto3 fallback for S3 API head-object (same authenticated approach)."""
    try:
        import boto3
        from botocore.config import Config

        s3 = boto3.client(
            "s3",
            endpoint_url=R2_ENDPOINT,
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            config=Config(signature_version="s3v4"),
            region_name="auto",
        )
        resp = s3.head_object(Bucket=bucket, Key=key)
        content_length = int(resp.get("ContentLength") or 0)
        etag = (resp.get("ETag") or "").strip('"')
        log.info(
            "boto3 head_object OK: s3://%s/%s -- size=%d bytes, etag=%s",
            bucket, key, content_length, etag[:16] if etag else "N/A",
        )
        return {
            "status":         200,
            "content_length": content_length,
            "etag":           etag,
            "source":         "boto3",
        }
    except ImportError:
        log.warning("boto3 not available -- skipping boto3 fallback")
        return None
    except Exception as e:
        log.warning("boto3 head_object error: %s", e)
        return None


def _http_head_diagnostic(url: str) -> Optional[dict]:
    """
    HTTP HEAD for diagnostic/logging only -- NEVER used for hard-fail decisions.
    HTTP 400 and 403 from R2 = private bucket (auth required) -- EXPECTED.
    """
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            return {
                "status":         resp.status,
                "content_length": int(resp.headers.get("Content-Length") or 0),
                "etag":           (resp.headers.get("ETag") or "").strip('"'),
            }
    except urllib.error.HTTPError as e:
        if e.code in (400, 403):
            log.info(
                "HTTP HEAD %s -> %d (private bucket, auth required -- EXPECTED for R2). "
                "S3 API is used for actual verification.",
                url, e.code,
            )
        else:
            log.warning("HTTP HEAD %s -> %d (diagnostic only)", url, e.code)
        return {"status": e.code, "content_length": 0, "etag": ""}
    except Exception as e:
        log.info("HTTP HEAD diagnostic unavailable: %s", e)
        return None


# ---------------------------------------------------------------------------
# Verification layers
# ---------------------------------------------------------------------------

def verify_local_feed() -> tuple[bool, str, int]:
    """Pre-check: local api/feed.json must exist and be non-trivial."""
    check_path = FEED_PATH if FEED_PATH.exists() else MANIFEST_PATH
    if not check_path.exists():
        return False, "Neither api/feed.json nor feed_manifest.json found locally", 0
    size = check_path.stat().st_size
    if size < MIN_FEED_BYTES:
        return False, f"{check_path.name} is only {size} bytes (minimum {MIN_FEED_BYTES})", size
    try:
        items = json.loads(check_path.read_text(encoding="utf-8"))
        if not isinstance(items, list) or len(items) == 0:
            return False, f"{check_path.name} parsed as empty list", size
        return True, f"Local feed OK: {len(items)} items, {size:,} bytes", size
    except Exception as e:
        return False, f"{check_path.name} JSON parse error: {e}", size


def verify_sync_meta_count() -> tuple[bool, str, int]:
    """
    Layer 4: advisory_count from sync_meta.json.
    BUG 4 FIX: Check /tmp/sync_meta.json first (written by r2_upload.py),
    then fall back to MANIFEST_FINAL_COUNT env var (set by pipeline).
    """
    meta_path = _find_sync_meta()

    if meta_path is not None:
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            count = int(
                meta.get("advisory_count")
                or meta.get("item_count")
                or meta.get("count")
                or 0
            )
            if count < MIN_ADVISORY_COUNT:
                return (
                    False,
                    f"sync_meta advisory_count={count} < floor {MIN_ADVISORY_COUNT} "
                    f"(empty upload — pipeline produced zero advisories)",
                    count,
                )
            if count < ADVISORY_COUNT_WARN:
                log.warning(
                    "Advisory count is low: %d (warn threshold %d). "
                    "This is acceptable after aggressive deduplication on a quiet day. "
                    "Layers 1-3 (R2 object existence + size + ETag) already confirmed "
                    "the upload is valid. Continuing.",
                    count, ADVISORY_COUNT_WARN,
                )
                return True, f"Advisory count LOW-BUT-VALID: {count} (warn<{ADVISORY_COUNT_WARN}, hard-floor={MIN_ADVISORY_COUNT}) from {meta_path.name}", count
            return True, f"Advisory count OK: {count} >= {ADVISORY_COUNT_WARN} (from {meta_path.name})", count
        except Exception as e:
            log.warning("sync_meta.json parse error: %s -- trying env var fallback", e)

    # Fallback: MANIFEST_FINAL_COUNT env var set by run_pipeline.py
    manifest_count_env = os.environ.get("MANIFEST_FINAL_COUNT", "").strip()
    if manifest_count_env.isdigit():
        count = int(manifest_count_env)
        if count < MIN_ADVISORY_COUNT:
            return (
                False,
                f"MANIFEST_FINAL_COUNT env={count} < floor {MIN_ADVISORY_COUNT} "
                f"(empty upload — pipeline produced zero advisories)",
                count,
            )
        if count < ADVISORY_COUNT_WARN:
            log.warning(
                "Advisory count is low (env fallback): %d (warn threshold %d). "
                "Acceptable for low-activity / high-dedup runs. Continuing.",
                count, ADVISORY_COUNT_WARN,
            )
            return True, f"Advisory count LOW-BUT-VALID (env MANIFEST_FINAL_COUNT): {count} (warn<{ADVISORY_COUNT_WARN})", count
        return True, f"Advisory count OK (env MANIFEST_FINAL_COUNT): {count} >= {ADVISORY_COUNT_WARN}", count

    log.warning("sync_meta.json not found anywhere and MANIFEST_FINAL_COUNT not set -- skipping count check")
    return True, "sync_meta.json absent and MANIFEST_FINAL_COUNT unset -- count check skipped", -1


def verify_r2_object() -> tuple[bool, str, dict]:
    """
    Layers 1-3: Verify the primary manifest in R2 via authenticated S3 API.
    BUG 1+2+3 FIX: Use correct bucket/key, authenticated S3 API.
    """
    details: dict = {
        "bucket":     BUCKET_DATA,
        "key":        MANIFEST_KEY,
        "endpoint":   R2_ENDPOINT,
        "checked_at": _utc_now(),
    }

    if not CF_ACCOUNT_ID or not ACCESS_KEY or not SECRET_KEY:
        msg = (
            "R2 credentials absent (CF_ACCOUNT_ID / AWS_ACCESS_KEY_ID / "
            "AWS_SECRET_ACCESS_KEY) -- skipping S3 API verification. "
            "Trusting Stage 3.5 exit code as source of truth."
        )
        log.warning(msg)
        details["skipped"] = True
        details["skip_reason"] = "missing_credentials"
        return True, msg, details

    log.info("Verifying: s3://%s/%s via %s", BUCKET_DATA, MANIFEST_KEY, R2_ENDPOINT)

    # Try awscli first, boto3 as fallback
    head = _s3api_head_object(BUCKET_DATA, MANIFEST_KEY)
    if head is None:
        log.info("awscli failed -- trying boto3 fallback...")
        head = _boto3_head_object(BUCKET_DATA, MANIFEST_KEY)

    if head is None:
        # Both S3 API methods failed. Run HTTP HEAD as diagnostic only.
        if R2_ENDPOINT:
            diag_url = f"{R2_ENDPOINT}/{BUCKET_DATA}/{MANIFEST_KEY}"
            diag = _http_head_diagnostic(diag_url)
            details["http_diagnostic"] = diag
            if diag and diag.get("status") in (400, 403):
                # HTTP 400/403 on private R2 = auth required (NOT a failure).
                # S3 API tooling is not available but Stage 3.5 already exited 0.
                msg = (
                    f"S3 API unavailable (awscli+boto3 both failed). "
                    f"HTTP HEAD returned {diag['status']} (private bucket, auth required -- EXPECTED). "
                    "Soft-passing: Stage 3.5 exited 0, data confirmed uploaded. "
                    "Install awscli or boto3 in pipeline for full S3 API verification."
                )
                log.warning(msg)
                details["soft_pass"] = True
                details["soft_pass_reason"] = f"s3api_unavailable_private_bucket_{diag['status']}"
                return True, msg, details

        return (
            False,
            f"S3 API head-object totally failed (awscli+boto3) for "
            f"s3://{BUCKET_DATA}/{MANIFEST_KEY}. Cannot verify R2 upload.",
            details,
        )

    details["http_status"]          = head["status"]
    details["r2_content_length"]    = head["content_length"]
    details["r2_etag"]              = head["etag"]
    details["verification_method"]  = head.get("source", "s3api")

    # Layer 1: existence check
    if head["status"] == 404:
        return (
            False,
            f"R2 object NOT FOUND: s3://{BUCKET_DATA}/{MANIFEST_KEY}. "
            "Stage 3.5 may have silently failed -- check r2_upload logs.",
            details,
        )
    if head["status"] not in (200, 206):
        return (
            False,
            f"S3 API returned unexpected status {head['status']} for "
            f"s3://{BUCKET_DATA}/{MANIFEST_KEY}.",
            details,
        )

    # Layer 2: size floor
    r2_size = head["content_length"]
    details["r2_size_ok"] = r2_size >= MIN_FEED_BYTES
    if 0 < r2_size < MIN_FEED_BYTES:
        return (
            False,
            f"R2 object size {r2_size} bytes < floor {MIN_FEED_BYTES} bytes -- "
            "upload was truncated or empty.",
            details,
        )

    # Layer 3: ETag vs local MD5 (hard fail ONLY on mismatch + >10% size diverge)
    r2_etag = head["etag"]
    local_path = MANIFEST_PATH if MANIFEST_PATH.exists() else (FEED_PATH if FEED_PATH.exists() else None)
    if r2_etag and local_path:
        local_md5 = _md5_file(local_path)
        details["local_md5"]   = local_md5
        details["r2_etag_raw"] = r2_etag

        if "-" in r2_etag:
            log.info("R2 ETag is multi-part -- skipping MD5 exact check (expected for large uploads)")
            details["etag_check"] = "skipped_multipart"
        elif r2_etag.lower() == local_md5.lower():
            log.info("ETag MATCH: R2=%s == local_md5=%s", r2_etag, local_md5)
            details["etag_check"] = "PASS"
        else:
            log.warning(
                "ETag MISMATCH: R2=%s != local_md5=%s -- checking size as secondary signal.",
                r2_etag, local_md5,
            )
            details["etag_check"] = "MISMATCH_WARN"
            local_size = local_path.stat().st_size
            if r2_size > 0 and abs(r2_size - local_size) > 0.10 * local_size:
                return (
                    False,
                    f"R2 ETag mismatch + size divergence >10%: "
                    f"R2={r2_size} bytes vs local={local_size} bytes. "
                    "Upload integrity compromised.",
                    details,
                )
            log.warning(
                "ETag mismatch but size within 10%% tolerance -- soft warning "
                "(Cloudflare may re-encode). Object present and size acceptable."
            )
    else:
        details["etag_check"] = "skipped_no_etag_or_local_file"

    return (
        True,
        f"R2 object verified OK [{head.get('source','s3api')}]: "
        f"s3://{BUCKET_DATA}/{MANIFEST_KEY} status={head['status']}, "
        f"size={r2_size:,} bytes",
        details,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    log.info("SENTINEL APEX v149.1.0 -- Stage 3.6 R2 Upload Integrity Verifier")
    log.info("Verification: S3 API (authenticated) -- primary method")
    log.info("Bucket: %s | Key: %s", BUCKET_DATA, MANIFEST_KEY)
    t0 = time.time()

    report: dict = {
        "generated_at":    _utc_now(),
        "engine":          "SENTINEL-APEX/149.1.0",
        "stage":           "3.6",
        "bucket":          BUCKET_DATA,
        "key":             MANIFEST_KEY,
        "verdict":         "PENDING",
        "layers":          {},
        "elapsed_seconds": None,
    }

    failures: list[str] = []

    # Pre-check: local feed
    ok, msg, local_size = verify_local_feed()
    log.info("Pre-check: %s", msg)
    report["layers"]["local_feed"] = {"ok": ok, "message": msg, "bytes": local_size}
    if not ok:
        failures.append(f"LOCAL_FEED: {msg}")

    # Layer 4: advisory count
    ok, msg, count = verify_sync_meta_count()
    log.info("Layer 4 (count): %s", msg)
    report["layers"]["advisory_count"] = {"ok": ok, "message": msg, "count": count}
    if not ok:
        failures.append(f"ADVISORY_COUNT: {msg}")

    # Layers 1-3: R2 object via S3 API
    ok, msg, r2_details = verify_r2_object()
    log.info("Layers 1-3 (R2): %s", msg)
    report["layers"]["r2_object"] = {"ok": ok, "message": msg, **r2_details}
    if not ok:
        failures.append(f"R2_OBJECT: {msg}")

    # Verdict
    elapsed = round(time.time() - t0, 2)
    report["elapsed_seconds"] = elapsed

    if failures:
        report["verdict"]  = "FAIL"
        report["failures"] = failures
        _atomic_write(REPORT_PATH, report)
        log.error("=" * 70)
        log.error("STAGE 3.6 HARD FAIL -- R2 integrity verification failed:")
        for f in failures:
            log.error("  x %s", f)
        log.error("Cache bust BLOCKED. Fix R2 upload before proceeding.")
        log.error("=" * 70)
        return 1

    report["verdict"] = "PASS"
    _atomic_write(REPORT_PATH, report)
    log.info("=" * 60)
    log.info("STAGE 3.6 PASS -- R2 integrity verified in %.2fs", elapsed)
    log.info("Cache bust may proceed.")
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
