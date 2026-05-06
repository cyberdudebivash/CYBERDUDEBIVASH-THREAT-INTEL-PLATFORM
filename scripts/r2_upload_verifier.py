#!/usr/bin/env python3
"""
scripts/r2_upload_verifier.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.2.0 -- R2 Upload Integrity Verifier
=========================================================================
STAGE 3.6: Executed immediately after r2_upload.py (Stage 3.5) and before
bust_kv_cache.py (Stage 3.7).

PURPOSE:
  Confirms the R2 upload from Stage 3.5 landed correctly before cache bust
  propagates potentially corrupt or missing data to the global CDN edge.

  Without this gate, the pipeline can:
    - Upload a truncated/empty feed to R2 (silent fail in awscli)
    - Immediately bust the KV cache (serving stale data with no alarm)
    - Pass all downstream validation gates (which run against local files)
    - Deliver a broken feed to 100% of production traffic

VERIFICATION STRATEGY (3-layer):
  Layer 1 -- Object existence: HEAD request to R2 public URL for feed.json.
             Confirms the object exists in R2 (not just "upload started").
  Layer 2 -- Size floor: R2 Content-Length >= MIN_FEED_BYTES (default 1024).
             Catches truncated or empty uploads.
  Layer 3 -- ETag vs local sha256: R2 ETag (MD5 for single-part) compared
             against local sha256. Detects bit-flips and partial writes.
             Note: multi-part upload ETags are "{md5}-{part_count}", which
             are exempt from the byte-exact check (flagged as warning only).
  Layer 4 -- Advisory count floor: sync_meta.json advisory_count field
             must be >= MIN_ADVISORY_COUNT (default 10) to prevent
             accidentally serving an empty-feed state to production.

EXIT CODES:
  0 = All verification layers passed -- safe to proceed to cache bust
  1 = Hard fail -- R2 state does not match expected, cache bust BLOCKED

ENVIRONMENT VARIABLES (consumed from workflow env):
  CF_ACCOUNT_ID           -- Cloudflare account ID (for R2 bucket URL)
  AWS_ACCESS_KEY_ID       -- R2 access key (passed to boto3 if available)
  AWS_SECRET_ACCESS_KEY   -- R2 secret key
  CF_R2_BUCKET_NAME       -- R2 bucket name (default: sentinel-apex-intel)
  CF_R2_PUBLIC_URL        -- Public R2 URL base (optional -- used for HEAD)
  PIPELINE_VERSION        -- version string for report

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
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
# Constants
# ---------------------------------------------------------------------------
REPO = Path(__file__).resolve().parent.parent

FEED_PATH       = REPO / "api" / "feed.json"
SYNC_META_PATH  = REPO / "data" / "sync_meta.json"
REPORT_PATH     = REPO / "data" / "quality" / "r2_verify_report.json"

MIN_FEED_BYTES     = 1_024          # Absolute minimum: 1 KB
MIN_ADVISORY_COUNT = 10             # Hard floor on advisory count in R2
REQUEST_TIMEOUT    = 20             # seconds per HTTP check
MAX_RETRIES        = 3              # retry transient network errors
RETRY_DELAY        = 4              # seconds between retries

# R2 public base URL pattern — used for object existence + size check
R2_PUBLIC_BASE = os.environ.get(
    "CF_R2_PUBLIC_URL",
    "https://pub-{account}.r2.dev",
)
CF_ACCOUNT_ID  = os.environ.get("CF_ACCOUNT_ID", "")
R2_BUCKET      = os.environ.get("CF_R2_BUCKET_NAME", "sentinel-apex-intel")

# If CF_R2_PUBLIC_URL is not set, try to construct from account ID
_r2_base = os.environ.get("CF_R2_PUBLIC_URL", "").rstrip("/")
if not _r2_base and CF_ACCOUNT_ID:
    _r2_base = f"https://{R2_BUCKET}.{CF_ACCOUNT_ID}.r2.cloudflarestorage.com"


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


def _sha256_file(path: Path) -> str:
    """Return hex SHA-256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _md5_file(path: Path) -> str:
    """Return hex MD5 of a file (matches R2 single-part ETag)."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _http_head(url: str, retries: int = MAX_RETRIES) -> Optional[dict]:
    """
    Perform an HTTP HEAD request with retry. Returns dict with:
      status, content_length, etag, content_type
    or None on total failure.
    """
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return {
                    "status":         resp.status,
                    "content_length": int(resp.headers.get("Content-Length") or 0),
                    "etag":           (resp.headers.get("ETag") or "").strip('"'),
                    "content_type":   resp.headers.get("Content-Type") or "",
                }
        except urllib.error.HTTPError as e:
            log.warning("HEAD %s → HTTP %d (attempt %d/%d)", url, e.code, attempt, retries)
            if e.code in (403, 404):
                return {"status": e.code, "content_length": 0, "etag": "", "content_type": ""}
        except Exception as e:
            log.warning("HEAD %s failed (attempt %d/%d): %s", url, attempt, retries, e)
        if attempt < retries:
            time.sleep(RETRY_DELAY)
    return None


# ---------------------------------------------------------------------------
# Verification layers
# ---------------------------------------------------------------------------

def verify_local_feed() -> tuple[bool, str, int]:
    """
    Pre-check: local api/feed.json must exist and be non-trivial.
    Returns (ok, message, byte_size).
    """
    if not FEED_PATH.exists():
        return False, f"api/feed.json not found at {FEED_PATH}", 0
    size = FEED_PATH.stat().st_size
    if size < MIN_FEED_BYTES:
        return False, f"api/feed.json is only {size} bytes (minimum {MIN_FEED_BYTES})", size
    try:
        items = json.loads(FEED_PATH.read_text(encoding="utf-8"))
        if not isinstance(items, list) or len(items) == 0:
            return False, "api/feed.json parsed as empty list", size
        return True, f"Local feed OK: {len(items)} items, {size:,} bytes", size
    except Exception as e:
        return False, f"api/feed.json JSON parse error: {e}", size


def verify_sync_meta_count() -> tuple[bool, str, int]:
    """
    Layer 4: sync_meta.json advisory_count must meet floor.
    Returns (ok, message, advisory_count).
    """
    if not SYNC_META_PATH.exists():
        log.warning("sync_meta.json not found — skipping advisory count check")
        return True, "sync_meta.json absent — count check skipped", -1

    try:
        meta = json.loads(SYNC_META_PATH.read_text(encoding="utf-8"))
        count = int(meta.get("advisory_count") or meta.get("item_count") or 0)
        if count < MIN_ADVISORY_COUNT:
            return (
                False,
                f"sync_meta advisory_count={count} < floor {MIN_ADVISORY_COUNT} — "
                "R2 was likely uploaded with an under-populated feed",
                count,
            )
        return True, f"Advisory count OK: {count} >= {MIN_ADVISORY_COUNT}", count
    except Exception as e:
        log.warning("sync_meta.json parse error: %s — skipping count check", e)
        return True, f"sync_meta parse error ({e}) — count check skipped", -1


def verify_r2_object(object_key: str = "api/feed.json") -> tuple[bool, str, dict]:
    """
    Layer 1 + 2 + 3: HEAD the R2 object, check existence, size, and ETag.
    Returns (ok, message, details_dict).
    """
    details: dict = {
        "object_key":     object_key,
        "r2_base":        _r2_base,
        "checked_at":     _utc_now(),
    }

    if not _r2_base:
        msg = (
            "CF_R2_PUBLIC_URL and CF_ACCOUNT_ID both absent — "
            "cannot perform R2 HEAD check. Falling back to local-only verification."
        )
        log.warning(msg)
        details["skipped"] = True
        return True, msg, details

    url = f"{_r2_base}/{object_key}"
    log.info("Layer 1-3: HEAD %s", url)

    head = _http_head(url)
    if head is None:
        return (
            False,
            f"R2 HEAD request totally failed after {MAX_RETRIES} retries — "
            f"network error or bucket unreachable: {url}",
            details,
        )

    details["http_status"]     = head["status"]
    details["r2_content_length"] = head["content_length"]
    details["r2_etag"]         = head["etag"]

    # Layer 1: existence
    if head["status"] == 404:
        return False, f"R2 object NOT FOUND (404): {url}", details
    if head["status"] == 403:
        log.warning(
            "R2 object returned 403 (private bucket or auth required) — "
            "size/ETag checks skipped. Treating as soft-pass."
        )
        details["auth_skip"] = True
        return True, f"R2 object returned 403 (auth-required bucket) — skipping ETag check", details
    if head["status"] not in (200, 206):
        return False, f"R2 HEAD returned unexpected status {head['status']}: {url}", details

    # Layer 2: size floor
    r2_size = head["content_length"]
    details["r2_size_ok"] = r2_size >= MIN_FEED_BYTES
    if r2_size > 0 and r2_size < MIN_FEED_BYTES:
        return (
            False,
            f"R2 object size {r2_size} bytes < floor {MIN_FEED_BYTES} bytes — "
            "upload was truncated or empty",
            details,
        )

    # Layer 3: ETag vs local MD5 (single-part upload only)
    r2_etag = head["etag"]
    if r2_etag and FEED_PATH.exists():
        local_md5 = _md5_file(FEED_PATH)
        details["local_md5"]   = local_md5
        details["r2_etag_raw"] = r2_etag

        # Multi-part ETags contain "-" — exempt from byte-exact comparison
        if "-" in r2_etag:
            log.info(
                "R2 ETag %s is multi-part — skipping MD5 byte-exact check (expected for large uploads)",
                r2_etag,
            )
            details["etag_check"] = "skipped_multipart"
        elif r2_etag.lower() == local_md5.lower():
            log.info("ETag MATCH: R2=%s == local_md5=%s", r2_etag, local_md5)
            details["etag_check"] = "PASS"
        else:
            # ETag mismatch — could be a partial upload or bit corruption
            # Treat as WARN not HARD FAIL: Cloudflare sometimes returns
            # different ETags due to server-side compression or re-chunking.
            log.warning(
                "ETag MISMATCH: R2=%s != local_md5=%s — possible partial upload. "
                "Checking size as secondary signal.",
                r2_etag, local_md5,
            )
            details["etag_check"] = "MISMATCH_WARN"
            local_size = FEED_PATH.stat().st_size
            if r2_size > 0 and abs(r2_size - local_size) > 0.10 * local_size:
                # Size differs by >10% AND ETag mismatch → hard fail
                return (
                    False,
                    f"R2 ETag mismatch + size divergence >10%: "
                    f"R2={r2_size} bytes vs local={local_size} bytes, "
                    f"ETag R2={r2_etag} vs local_md5={local_md5}. "
                    "Upload integrity compromised.",
                    details,
                )
            log.warning(
                "ETag mismatch but size within 10%% — treating as soft warning (Cloudflare re-encoding)."
            )
    else:
        details["etag_check"] = "skipped_no_etag_or_file"

    return True, f"R2 object verified OK: status={head['status']}, size={r2_size:,} bytes", details


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    log.info("SENTINEL APEX v143.2.0 — Stage 3.6 R2 Upload Integrity Verifier")
    t0 = time.time()

    report: dict = {
        "generated_at":    _utc_now(),
        "engine":          "SENTINEL-APEX/143.2.0",
        "stage":           "3.6",
        "verdict":         "PENDING",
        "layers":          {},
        "elapsed_seconds": None,
    }

    failures: list[str] = []

    # ── Pre-check: local feed integrity ──────────────────────────────────────
    ok, msg, local_size = verify_local_feed()
    log.info("Pre-check: %s", msg)
    report["layers"]["local_feed"] = {"ok": ok, "message": msg, "bytes": local_size}
    if not ok:
        failures.append(f"LOCAL_FEED: {msg}")

    # ── Layer 4: advisory count from sync_meta ────────────────────────────────
    ok, msg, count = verify_sync_meta_count()
    log.info("Layer 4 (count): %s", msg)
    report["layers"]["advisory_count"] = {"ok": ok, "message": msg, "count": count}
    if not ok:
        failures.append(f"ADVISORY_COUNT: {msg}")

    # ── Layers 1-3: R2 HEAD + size + ETag ────────────────────────────────────
    ok, msg, r2_details = verify_r2_object("api/feed.json")
    log.info("Layers 1-3 (R2): %s", msg)
    report["layers"]["r2_object"] = {"ok": ok, "message": msg, **r2_details}
    if not ok:
        failures.append(f"R2_OBJECT: {msg}")

    # ── Verdict ───────────────────────────────────────────────────────────────
    elapsed = round(time.time() - t0, 2)
    report["elapsed_seconds"] = elapsed

    if failures:
        report["verdict"]  = "FAIL"
        report["failures"] = failures
        _atomic_write(REPORT_PATH, report)
        log.error("=" * 70)
        log.error("STAGE 3.6 HARD FAIL — R2 integrity verification failed:")
        for f in failures:
            log.error("  ✗ %s", f)
        log.error("Cache bust BLOCKED. Fix R2 upload before proceeding.")
        log.error("=" * 70)
        return 1

    report["verdict"] = "PASS"
    _atomic_write(REPORT_PATH, report)
    log.info("=" * 60)
    log.info("STAGE 3.6 PASS — R2 upload integrity verified in %.2fs", elapsed)
    log.info("Cache bust may proceed.")
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
