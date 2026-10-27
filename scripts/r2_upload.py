#!/usr/bin/env python3
"""
scripts/r2_upload.py
CYBERDUDEBIVASH(R) SENTINEL APEX v200.0 -- Cloudflare R2 Upload Engine
=========================================================================
P0 FIX: Replaces the inline PYEOF/unquoted-heredoc R2 upload block from
sentinel-apex.yml.  Zero inline Python in YAML.

P0 R2 COST INCIDENT FIX (2026-09): this script no longer touches the
sentinel-apex-reports bucket at all. It used to run `aws s3 sync reports/
-> s3://sentinel-apex-reports/reports/` (whole-prefix LIST + full content
comparison, no bound) on every scheduled run -- confirmed root cause of a
3,004,147-Class-A-operation billing cycle (docs/P0_R2_COST_CONTAINMENT.md).
That sync, and its reports/pdf/ counterpart, have been removed entirely --
not flag-gated. scripts/r2_report_publisher.py is now the sole writer/
retirer for both keyspaces: deterministic keys, sha256-diffed against its
own state file (zero R2 LIST), bounded to a rolling 24h window, fail-closed
operation budget before any mutation. Run it as its own pipeline stage
immediately after this script.

Responsibilities (bounded to sentinel-apex-data only):
  1.  Validate R2 credentials (CF_ACCOUNT_ID, AWS_ACCESS_KEY_ID,
      AWS_SECRET_ACCESS_KEY).  Exit 1 if any missing.
  2.  Install awscli if not present.
  3.  Configure awscli for high-throughput parallel uploads.
  4.  Upload feed_manifest.json and enriched manifests.
  5.  Upload apex_v2 API endpoint files.
  6.  Upload AI intelligence data files.
  7.  Write and upload sync_meta.json with advisory count + run metadata.

Report/PDF publishing to sentinel-apex-reports and reports/pdf/ moved to
scripts/r2_report_publisher.py -- see that script's module docstring.

P0 DUPLICATE-WRITER RACE FIX (2026-09, PR #370 follow-up): main() no longer
uploads the 4 shared AI-tracker keys (ai/tracker.json, ai/health.json,
ai/executive-brief.json, ai/monetization.json) -- those are now written
exclusively by `python3 scripts/r2_upload.py --ai-tracker-only`
(main_ai_tracker_only()), called only from generate-and-sync.yml. See the
"P0 DUPLICATE-WRITER RACE FIX" comment above AI_TRACKER_FILES below for the
full race description this eliminates. main()'s own PUT plan is now also
built in full (build_upload_plan()) and checked against
scripts/r2_cost_guard.py's fail-closed budget BEFORE any upload -- closing
the r2_upload.py accounting gap documented in PR #370.

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

import hashlib
import json
import logging
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from r2_cost_guard import (  # noqa: E402
    R2Budgets,
    R2BudgetExceeded,
    R2OperationPlan,
    emit_summary,
    enforce_budget,
)
import public_freshness_contract as _freshness  # noqa: E402
import tlp_policy as _tlp_policy  # noqa: E402  (shared fail-closed publication authority)
import tlp_public_boundary as _tlp_boundary  # noqa: E402  (last-mile sanitizer for every JSON object)
from public_api_sanitizer import _remove_invalid_stix_alias  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [r2_upload] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.r2_upload")

REPO_ROOT = Path(__file__).resolve().parent.parent
PIPELINE_VERSION = os.environ.get("PIPELINE_VERSION", "201.0")
BUCKET_DATA = "sentinel-apex-data"
BUCKET_REPORTS = "sentinel-apex-reports"  # written/retired only by scripts/r2_report_publisher.py now

# ─────────────────────────────────────────────────────────────────────────
# P0 STALE-MANIFEST ROLLBACK GUARD
# ─────────────────────────────────────────────────────────────────────────
# Every pipeline push to main has been rejected by the branch ruleset
# (GH013) since ~2026-08-26, so the git-committed copies of the customer-
# facing manifests (api/v1/intel/{latest,latest_pro,top10,apex,manifest}
# .json, api/reports/*.json) are frozen at that date. Both writers of those
# keys -- this script's main() (STAGE 3.5, which runs BEFORE STAGE 3.93
# regenerates them) and scripts/r2_resync_manifests.py (STAGE 3.93.6 /
# STAGE 4.1) -- uploaded whatever file was on disk. Confirmed live on run
# 35867879014 (2026-09-23): the run failed at STAGE 3.3, STAGE 3.93 never
# ran, and STAGE 4.1 then uploaded the 08-26 git copy of latest.json
# (109 items) over the 273-item copy run 35818582480 had published at
# 05:26Z -- rolling every customer feed endpoint back four weeks until the
# next fully green run.
#
# Fix: a manifest that declares a top-level `generated_at` older than
# MAX_PUBLIC_MANIFEST_AGE_HOURS is never uploaded -- R2 keeps its current
# (newer) object instead. Files regenerated this run are minutes old and
# unaffected; files with no `generated_at` (e.g. api/feed.json, a bare
# list) keep their existing behaviour. The default (6h) is well above the
# sentinel-blogger job's own 130-minute timeout, so nothing this run wrote
# can age past it before being uploaded.
# Threshold + classification come from the ONE canonical contract
# (config/public_freshness_contract.json via scripts/public_freshness_contract.py),
# which /api/health and the public feed freshness release gate also use.
# Re-exported under the original names for backward compatibility.
DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS = _freshness.DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS
max_public_manifest_age_hours = _freshness.max_public_manifest_age_hours


def stale_manifest_reason(path: Path, now: datetime | None = None) -> str | None:
    """Returns a human-readable reason when `path` is a JSON object whose
    top-level `generated_at` is provably older than
    max_public_manifest_age_hours(), else None (upload allowed).

    Only a PROVABLY stale file is blocked (canonical state "stale").
    Unreadable JSON, a non-object document, or a missing/unparseable/
    future `generated_at` all return None so those files keep exactly their
    pre-existing upload behaviour."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    raw = data.get("generated_at")
    result = _freshness.classify_manifest_freshness(raw, now=now)
    if result["state"] != _freshness.STALE:
        return None
    age_h = result["age_seconds"] / 3600.0
    limit = result["max_age_seconds"] / 3600.0
    return (
        f"generated_at={raw} is {age_h:.1f}h old (limit {limit:g}h) -- "
        "not regenerated by this run; refusing to overwrite R2's newer copy"
    )

# ─────────────────────────────────────────────────────────────────────────
# P0 DUPLICATE-WRITER RACE FIX (PR #370 follow-up)
# ─────────────────────────────────────────────────────────────────────────
# These 4 keys used to be written by TWO independent, unlocked code paths:
#   1. This script's main() (invoked by sentinel-apex.yml, STAGE 3.5,
#      concurrency group "sentinel-data-writer") -- via its own former
#      "Upload 3b" block AND a second time via the ai_dirs glob below.
#   2. generate-and-sync.yml's inline `aws s3 cp` loop (STAGE 9.5,
#      concurrency group "sentinel-ai-writer").
# Different concurrency groups do NOT serialize each other in GitHub
# Actions -- a workflow_dispatch/push-triggered overlap, or a scheduled run
# overrunning into the next window, lets both issue PUTs for the identical
# 4 logical R2 keys with no shared lock and no shared accounting (path #2
# was raw inline bash, invisible to r2_cost_guard.py entirely).
#
# FIX (Option A -- one authoritative writer per shared key, Constitution
# Principle 3): generate-and-sync.yml's STAGE 9.5 now calls
# `python3 scripts/r2_upload.py --ai-tracker-only` (main_ai_tracker_only()
# below) instead of hand-rolling `aws s3 cp`. main() below no longer
# uploads these 4 keys at all (AI_TRACKER_FILENAMES exclusion in its
# ai_dirs loop) -- generate-and-sync.yml is now the sole caller of the sole
# code path that writes them, so two writers cannot race for the same key.
AI_TRACKER_FILES: list[tuple[str, str]] = [
    ("api/ai/tracker.json",          "ai/tracker.json"),
    ("api/ai/health.json",           "ai/health.json"),
    ("api/ai/executive-brief.json",  "ai/executive-brief.json"),
    ("api/ai/monetization.json",     "ai/monetization.json"),
]
AI_TRACKER_FILENAMES = frozenset(Path(src).name for src, _dst in AI_TRACKER_FILES)

# Extracted to module level (was a local literal inside upload_p40_artifacts())
# so main()'s upload-plan builder and upload_p40_artifacts() share exactly one
# definition (Constitution Principle 3 -- single source of truth) instead of
# two lists that could silently drift apart.
P40_SOURCE_FABRIC_FILES: list[tuple[str, str]] = [
    ("data/registry/source_registry.json",           "intel/source_registry.json"),
    ("data/quality/source_fabric_health.json",        "intel/source_fabric_health.json"),
    ("data/quality/p40_certification_report.json",    "intel/p40_certification_report.json"),
]

# P0 production-architecture-transformation mission (2026-09-08): STAGE
# 5.8.4b's "latest state" copy of the release-governance telemetry file --
# this is the Class B (generated artifact) half of that stage's persistence;
# the Class D (write-once, versioned audit trail) half is a separate call to
# scripts/audit_snapshot_store.py. Kept as a module-level list (not a bare
# literal inside the function) so it follows the same candidate-list
# convention as AI_TRACKER_FILES/P40_SOURCE_FABRIC_FILES above.
GOVERNANCE_TELEMETRY_FILES: list[tuple[str, str]] = [
    ("data/telemetry/global_release_governance.json", "data/telemetry/global_release_governance.json"),
]

# Customer Reports catalog (written only by scripts/build_reports_index.py).
# main() uploads these at STAGE 3.5; main_reports_index_only() re-uploads the
# same three keys after STAGE 5.4.0c publishes reports rendered late in the
# run -- see that function's docstring.
REPORTS_INDEX_FILES: list[tuple[str, str]] = [
    ("api/reports/latest.json",       "api/reports/latest.json"),
    ("api/reports/index.json",        "api/reports/index.json"),
    ("api/reports/stats.json",        "api/reports/stats.json"),
]

# Weekly Threat Brief API artifact. This key is consumed by intel-gateway's
# /api/v1/intel/* R2-backed static-manifest serving path. It is intentionally
# NOT part of build_upload_plan(): weekly-threat-brief.yml is the sole writer,
# preventing duplicate writers/races with sentinel-blogger.
WEEKLY_BRIEF_FILES: list[tuple[str, str]] = [
    ("api/v1/intel/weekly_brief.json", "api/v1/intel/weekly_brief.json"),
]


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


_TLP_VERIFIED_COPIES: set = set()  # str paths of upload-only copies produced by the tlp_safe_* helpers


def s3_cp(
    src: str,
    dst_bucket: str,
    dst_key: str,
    endpoint: str,
    content_type: str = "application/json",
    cache_control: str = "no-cache, no-store, must-revalidate",
    only_show_errors: bool = True,
    timeout_seconds: float | None = None,
) -> bool:
    """Upload a single file to R2. Returns True on success.

    This is the plain PUT primitive and is also used for INTERNAL cross-run state (scripts/r2_state_sync.py), whose
    JSON must round-trip byte-for-byte -- so it deliberately does NOT apply the public TLP boundary. Anything
    served anonymously must go through s3_cp_public() instead (P0 #721/#725).
    """
    cmd = [
        "aws", "s3", "cp", src, f"s3://{dst_bucket}/{dst_key}",
        "--endpoint-url", endpoint,
        "--content-type", content_type,
        "--cache-control", cache_control,
    ]
    if only_show_errors:
        cmd.append("--only-show-errors")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        # The bounded report publisher must not hang until the Actions stage
        # timeout while one R2 PUT stalls. Nonzero outcome leaves publish-state
        # unadvanced for safe retry; no additional R2 requests are issued.
        log.error("TIMEOUT: R2 upload exceeded %ss for s3://%s/%s",
                  timeout_seconds, dst_bucket, dst_key)
        return False
    if result.returncode == 0:
        log.info("OK: Uploaded %s -> s3://%s/%s", src, dst_bucket, dst_key)
        return True
    log.warning(
        "WARN: Upload failed (%d): %s %s",
        result.returncode, result.stdout.strip(), result.stderr.strip(),
    )
    return False


def s3_cp_public(
    src: str,
    dst_bucket: str,
    dst_key: str,
    endpoint: str,
    content_type: str = "application/json",
    cache_control: str = "no-cache, no-store, must-revalidate",
    only_show_errors: bool = True,
) -> bool:
    """s3_cp for objects that are served ANONYMOUSLY (P0 #721/#725): every JSON object passes the TLP boundary
    first unless the caller already produced a verified copy (tlp_safe_* helpers register it). An object that cannot
    be verified is NOT uploaded and the call reports failure (callers already treat that as fatal or skip it); the
    source file is never modified. Non-JSON keys are passed through unchanged."""
    extra = {}
    if content_type != "application/json":
        extra["content_type"] = content_type
    if cache_control != "no-cache, no-store, must-revalidate":
        extra["cache_control"] = cache_control
    if only_show_errors is not True:
        extra["only_show_errors"] = only_show_errors
    if dst_key.endswith(".json") and str(src) not in _TLP_VERIFIED_COPIES:
        with tempfile.TemporaryDirectory(prefix="cdb-p0-tlp-s3cp-") as _td:
            parents = _tlp_boundary.build_parent_index([
                REPO_ROOT / "api" / "feed.json", REPO_ROOT / "data" / "feed_manifest.json",
                REPO_ROOT / "data" / "stix" / "feed_manifest.json"])
            safe = tlp_safe_public_json_source(Path(src), Path(_td), dst_key, parents)
            if safe is None:
                return False
            return s3_cp(str(safe), dst_bucket, dst_key, endpoint, **extra)
    return s3_cp(src, dst_bucket, dst_key, endpoint, **extra)


def s3_get(
    dst_local: str,
    src_bucket: str,
    src_key: str,
    endpoint: str,
) -> str:
    """
    Download a single object from R2 to a local path.

    Returns one of three distinct outcomes -- callers that need bootstrap
    semantics (missing object is fine, transient errors are not) MUST branch
    on this three-way result rather than treating any failure alike:
      "OK"        -- downloaded successfully, dst_local now holds the object.
      "NOT_FOUND" -- the object genuinely does not exist yet in R2 (a brand
                     new key, e.g. before this migration's first successful
                     upload). Safe to fall back to a bootstrap source.
      "ERROR"     -- anything else (network, auth, R2 outage, malformed
                     response, or -- CodeRabbit review finding on this
                     migration, verified: AWS's actual NoSuchBucket message
                     is "The specified bucket does not exist", which the
                     naive "does not exist" substring check below used to
                     also match, misclassifying a wrong/misconfigured bucket
                     name as "object not created yet" -- checked first and
                     explicitly excluded). NOT safe to treat any of these as
                     "start fresh": doing so for a dedup/incremental-state
                     object could silently discard real history and
                     reintroduce duplicates, or mask a bucket misconfig
                     behind what looks like a normal first-run bootstrap.
    """
    cmd = [
        "aws", "s3", "cp", f"s3://{src_bucket}/{src_key}", dst_local,
        "--endpoint-url", endpoint,
        "--only-show-errors",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        log.info("OK: Downloaded s3://%s/%s -> %s", src_bucket, src_key, dst_local)
        return "OK"

    combined = f"{result.stdout}\n{result.stderr}".lower()
    if "nosuchbucket" in combined:
        log.error(
            "ERROR: Download failed for s3://%s/%s (%d): bucket does not "
            "exist or is misconfigured -- NOT the same as the object simply "
            "not being created yet. %s %s",
            src_bucket, src_key, result.returncode,
            result.stdout.strip(), result.stderr.strip(),
        )
        return "ERROR"
    if "404" in combined or "not found" in combined or "nosuchkey" in combined or "does not exist" in combined:
        log.info(
            "NOT_FOUND: s3://%s/%s does not exist yet (expected on first run "
            "after a state-object migration).", src_bucket, src_key,
        )
        return "NOT_FOUND"

    log.error(
        "ERROR: Download failed for s3://%s/%s (%d): %s %s",
        src_bucket, src_key, result.returncode,
        result.stdout.strip(), result.stderr.strip(),
    )
    return "ERROR"


def s3_delete(
    bucket: str,
    key: str,
    endpoint: str,
    timeout_seconds: float | None = None,
) -> bool:
    """Delete a single object from R2. Returns True on success (including
    the case where the object is already absent -- `aws s3 rm` on a
    nonexistent key exits 0, which is the correct outcome for a caller
    retiring an object it believes exists: idempotent, not an error).

    Cloudflare R2 does not bill DeleteObject as a Class A operation (see
    scripts/r2_cost_guard.py's module docstring) -- this helper exists for
    bounded, deterministic-key retirement (scripts/r2_report_publisher.py's
    24h rolling-window cleanup), not as a cost optimization in itself. Callers
    remain responsible for keeping the total delete count bounded and
    tracked through r2_cost_guard -- unbounded blast radius, not billing, is
    the risk this helper does not protect against on its own.
    """
    cmd = [
        "aws", "s3", "rm", f"s3://{bucket}/{key}",
        "--endpoint-url", endpoint,
        "--only-show-errors",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        log.error("TIMEOUT: R2 delete exceeded %ss for s3://%s/%s",
                  timeout_seconds, bucket, key)
        return False
    if result.returncode == 0:
        log.info("OK: Deleted s3://%s/%s", bucket, key)
        return True
    log.warning(
        "WARN: Delete failed (%d): %s %s",
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


def s3_sync_download(
    dst_dir: str,
    src_bucket: str,
    src_prefix: str,
    endpoint: str,
    timeout_seconds: int | None = None,
) -> bool:
    """
    Download counterpart to s3_sync(): pulls src_bucket/src_prefix down to
    dst_dir. Returns True on success (including the trivial case where the
    prefix has no objects yet -- `aws s3 sync` from an empty/nonexistent
    prefix is a legitimate no-op, not an error, unlike s3_get()'s single-
    object OK/NOT_FOUND/ERROR contract which a directory sync doesn't need:
    without --delete, sync only adds/updates -- it never removes files
    already present in dst_dir, so a git-checkout copy of dst_dir is safe to
    sync onto (bootstrap-safe by construction, no special-casing required).
    """
    cmd = [
        "aws", "s3", "sync", f"s3://{src_bucket}/{src_prefix}", dst_dir,
        "--endpoint-url", endpoint,
        "--only-show-errors",
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        log.warning(
            "WARN: s3 sync download timed out after %ds (non-fatal) -- "
            "existing local copy of %s is left untouched.",
            timeout_seconds, dst_dir,
        )
        return False

    if result.returncode == 0:
        log.info("OK: Synced s3://%s/%s -> %s", src_bucket, src_prefix, dst_dir)
        return True
    log.warning(
        "WARN: Sync download had errors (%d): %s",
        result.returncode, result.stderr.strip()[:400],
    )
    return False


def upload_p40_artifacts(endpoint: str) -> int:
    """
    Upload the 3 P40 Global Intelligence Source Fabric artifacts to R2.

    Extracted from main()'s inline "Upload 2b" block so it can also be
    invoked standalone (--p40-only) late in sentinel-apex.yml, after
    STAGE 5.9.5 regenerates these files. Without this, main()'s single
    upload pass at STAGE 3.5 runs BEFORE STAGE 5.9.5 in the same pipeline
    execution, so the freshly-regenerated certification/health reports were
    never uploaded until the *next* pipeline run — R2 was permanently one
    full pipeline cycle (~8h) behind what was actually on disk/in git.
    Returns the count of artifacts uploaded (0-3).
    """
    uploaded_p40 = 0
    for src, dst_key in P40_SOURCE_FABRIC_FILES:
        if Path(src).exists():
            s3_cp_public(src, BUCKET_DATA, dst_key, endpoint)
            uploaded_p40 += 1
        else:
            log.warning("SKIP: %s not found (P40 endpoint will 503 until it is generated)", src)
    log.info("OK: P40 source fabric artifacts uploaded (%d/%d)",
             uploaded_p40, len(P40_SOURCE_FABRIC_FILES))
    return uploaded_p40


def main_p40_only() -> None:
    """Late-pipeline sync of just the P40 artifacts (see upload_p40_artifacts).

    P0 FinOps accounting fix: this CLI mode used to issue up to 3 PUTs with
    no R2OperationPlan of its own -- invisible to the r2_cost_guard.py
    ledger. Now builds a plan from the same fixed candidate list, enforces
    budget BEFORE any mutation (fail-closed), and emits the standard
    R2_COST_GUARD telemetry block under its own label so it doesn't clobber
    main()'s "r2_upload" entry in the same pipeline run.
    """
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- R2 Upload Engine (P40-only late sync)", PIPELINE_VERSION)
    log.info("=" * 60)
    os.chdir(REPO_ROOT)
    cf_account, _access_key, _secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    install_awscli()

    planned = sum(1 for src, _dst in P40_SOURCE_FABRIC_FILES if (REPO_ROOT / src).exists())
    plan = R2OperationPlan(label="r2_upload_p40only", bucket=BUCKET_DATA)
    plan.record_put(planned)

    budgets = R2Budgets.from_env()
    try:
        enforce_budget(plan, budgets, is_report_plan=False)
    except R2BudgetExceeded as exc:
        log.critical(str(exc))
        emit_summary(plan, budgets, status="BLOCKED", is_report_plan=False, extra={"reason": str(exc)})
        sys.exit(1)

    upload_p40_artifacts(endpoint)
    emit_summary(plan, budgets, status="PASS", is_report_plan=False)
    log.info("P40-only R2 sync complete.")


def main_ai_tracker_only() -> None:
    """
    Sole authoritative writer for the 4 shared AI-tracker R2 keys -- see the
    "P0 DUPLICATE-WRITER RACE FIX" module-level comment above AI_TRACKER_FILES
    for the full race description and why this is now the only caller.

    Invoked exclusively by generate-and-sync.yml's STAGE 9.5 (replacing that
    step's former raw inline `aws s3 cp` loop, which issued R2 operations
    with zero r2_cost_guard.py accounting). main() below never uploads these
    keys, so this is the only place in the codebase that does.
    """
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- R2 Upload Engine (AI-tracker-only)", PIPELINE_VERSION)
    log.info("=" * 60)
    os.chdir(REPO_ROOT)
    cf_account, _access_key, _secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    install_awscli()

    candidates = [(src, dst) for src, dst in AI_TRACKER_FILES if (REPO_ROOT / src).exists()]
    for src, _dst in AI_TRACKER_FILES:
        if not (REPO_ROOT / src).exists():
            log.warning("SKIP (AI tracker): %s not found -- run generate-and-sync workflow first", src)

    plan = R2OperationPlan(label="r2_upload_ai_tracker", bucket=BUCKET_DATA)
    plan.record_put(len(candidates))

    budgets = R2Budgets.from_env()
    try:
        enforce_budget(plan, budgets, is_report_plan=False)
    except R2BudgetExceeded as exc:
        log.critical(str(exc))
        emit_summary(plan, budgets, status="BLOCKED", is_report_plan=False, extra={"reason": str(exc)})
        sys.exit(1)

    uploaded = 0
    for src, dst_key in candidates:
        if s3_cp_public(src, BUCKET_DATA, dst_key, endpoint):
            uploaded += 1
    log.info("OK: AI Tracker files uploaded to R2 (%d/%d)", uploaded, len(AI_TRACKER_FILES))

    emit_summary(plan, budgets, status="PASS", is_report_plan=False, extra={"uploaded": uploaded})
    log.info("AI-tracker-only R2 sync complete.")


def main_governance_telemetry_only() -> None:
    """
    Publishes the "latest state" copy of data/telemetry/global_release_
    governance.json to R2. Replaces STAGE 5.8.4b's former inline `git add`
    / `git commit` / `git push origin HEAD` block (P0 production-
    architecture-transformation mission, 2026-09-08: this file is Class B,
    a generated artifact, so it belongs in R2 publication -- not a
    scheduled runtime git commit to main). The historical, write-once audit
    trail for this same file is written separately, in the same stage, by
    scripts/audit_snapshot_store.py (Class D); this function only maintains
    the single mutable "latest" copy other consumers read.
    """
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- R2 Upload Engine (governance-telemetry-only)", PIPELINE_VERSION)
    log.info("=" * 60)
    os.chdir(REPO_ROOT)
    cf_account, _access_key, _secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    install_awscli()

    candidates = [(src, dst) for src, dst in GOVERNANCE_TELEMETRY_FILES if (REPO_ROOT / src).exists()]
    for src, _dst in GOVERNANCE_TELEMETRY_FILES:
        if not (REPO_ROOT / src).exists():
            log.warning("SKIP (governance telemetry): %s not found -- orchestrator may have skipped this run", src)

    plan = R2OperationPlan(label="r2_upload_governance_telemetry", bucket=BUCKET_DATA)
    plan.record_put(len(candidates))

    budgets = R2Budgets.from_env()
    try:
        enforce_budget(plan, budgets, is_report_plan=False)
    except R2BudgetExceeded as exc:
        log.critical(str(exc))
        emit_summary(plan, budgets, status="BLOCKED", is_report_plan=False, extra={"reason": str(exc)})
        sys.exit(1)

    uploaded = 0
    for src, dst_key in candidates:
        if s3_cp_public(src, BUCKET_DATA, dst_key, endpoint):
            uploaded += 1
    log.info("OK: Governance telemetry uploaded to R2 (%d/%d)", uploaded, len(GOVERNANCE_TELEMETRY_FILES))

    emit_summary(plan, budgets, status="PASS", is_report_plan=False, extra={"uploaded": uploaded})
    log.info("Governance-telemetry-only R2 sync complete.")


def main_weekly_brief_only() -> None:
    """
    Publish the customer-facing Weekly Threat Brief API artifact to the
    canonical INTEL_R2 data bucket.

    weekly-threat-brief.yml is the sole caller and therefore the sole writer
    for this key. The production gateway serves /api/v1/intel/* from R2, so
    a gh-pages deployment alone cannot satisfy the API contract.

    The operation is fail-closed:
      * the expected artifact must exist and be non-empty;
      * a provably stale manifest is rejected;
      * R2 cost budget is enforced before mutation;
      * the upload must complete successfully.
    """
    log.info("=" * 60)
    log.info(
        "SENTINEL APEX v%s -- R2 Upload Engine (weekly-brief-only)",
        PIPELINE_VERSION,
    )
    log.info("=" * 60)
    os.chdir(REPO_ROOT)

    cf_account, _access_key, _secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    install_awscli()

    candidates: list[tuple[str, str]] = []
    for src, dst_key in WEEKLY_BRIEF_FILES:
        path = REPO_ROOT / src
        if not path.is_file() or path.stat().st_size <= 0:
            log.critical("FATAL: weekly brief artifact missing or empty: %s", src)
            sys.exit(1)
        stale = stale_manifest_reason(path)
        if stale:
            log.critical("FATAL: refusing stale weekly brief publication: %s", stale)
            emit = f"::error::weekly brief publication blocked: {stale}"
            print(emit, flush=True)
            sys.exit(1)
        candidates.append((src, dst_key))

    plan = R2OperationPlan(label="r2_upload_weekly_brief", bucket=BUCKET_DATA)
    plan.record_put(len(candidates))

    budgets = R2Budgets.from_env()
    try:
        enforce_budget(plan, budgets, is_report_plan=False)
    except R2BudgetExceeded as exc:
        log.critical(str(exc))
        emit_summary(
            plan,
            budgets,
            status="BLOCKED",
            is_report_plan=False,
            extra={"reason": str(exc)},
        )
        sys.exit(1)

    uploaded = 0
    for src, dst_key in candidates:
        if s3_cp_public(src, BUCKET_DATA, dst_key, endpoint):
            uploaded += 1

    emit_summary(
        plan,
        budgets,
        status="PASS" if uploaded == len(candidates) else "FAIL",
        is_report_plan=False,
        extra={"uploaded": uploaded},
    )
    if uploaded != len(candidates):
        log.critical(
            "FATAL: weekly brief R2 publication incomplete (%d/%d)",
            uploaded,
            len(candidates),
        )
        sys.exit(1)

    log.info("Weekly Threat Brief API artifact published to R2.")


def main_reports_index_only() -> None:
    """
    Late re-upload of the customer Reports catalog (REPORTS_INDEX_FILES).

    2026-09-26: main() uploads api/reports/*.json at STAGE 3.5, built at
    STAGE 3.3.7 from the reports published so far. STAGE 5.4.0c then
    publishes the reports rendered later in the same run (production: 19 of
    21 in-window reports), so the live catalog listed 1 report next to 28
    advisories until the next run (~4h). sentinel-apex.yml STAGE 5.4.0d
    rebuilds the index (build_reports_index.py, still the only writer),
    verifies it against R2 (r2_reports_integrity.py) and calls this.

    Same budget accounting and stale-manifest guard as main().
    """
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- R2 Upload Engine (reports-index-only)", PIPELINE_VERSION)
    log.info("=" * 60)
    os.chdir(REPO_ROOT)
    # The late catalog refresh must not bypass the Stage 3.5 trio contract.
    # Reject BEFORE credentials, AWS CLI installation, or any R2 operation.
    if not report_catalog_chronology_precheck():
        log.critical("P0 report catalog chronology/registry precheck refused late R2 publication")
        sys.exit(1)
    cf_account, _access_key, _secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"
    install_awscli()

    candidates: list[tuple[str, str]] = []
    for src, dst_key in REPORTS_INDEX_FILES:
        if not (REPO_ROOT / src).exists():
            log.warning("SKIP (reports index): %s not found", src)
            continue
        stale = stale_manifest_reason(REPO_ROOT / src)
        if stale:
            log.warning("SKIP (stale): %s -- %s", src, stale)
            print(f"::warning::r2_upload: skipped stale {src} ({stale})", flush=True)
            continue
        candidates.append((src, dst_key))

    plan = R2OperationPlan(label="r2_upload_reports_index", bucket=BUCKET_DATA)
    plan.record_put(len(candidates))

    budgets = R2Budgets.from_env()
    try:
        enforce_budget(plan, budgets, is_report_plan=False)
    except R2BudgetExceeded as exc:
        log.critical(str(exc))
        emit_summary(plan, budgets, status="BLOCKED", is_report_plan=False, extra={"reason": str(exc)})
        sys.exit(1)

    uploaded = 0
    for src, dst_key in candidates:
        if s3_cp_public(src, BUCKET_DATA, dst_key, endpoint):
            uploaded += 1
    log.info("OK: Reports catalog uploaded to R2 (%d/%d)", uploaded, len(candidates))

    emit_summary(plan, budgets, status="PASS", is_report_plan=False, extra={"uploaded": uploaded})
    if uploaded < len(candidates):
        sys.exit(1)
    log.info("Reports-index-only R2 sync complete.")


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


def _generate_ai_endpoints() -> None:
    """Runs scripts/generate_ai_endpoints.py so its output files exist on
    disk before main() builds its upload plan below. Moved to run BEFORE
    any R2 mutation (it used to run in the middle of main(), interleaved
    with earlier uploads) purely so the plan-then-enforce-then-execute
    sequence in main() can see its output when counting candidates -- this
    subprocess call itself never touches R2, so re-ordering it earlier
    changes nothing about what gets generated or uploaded."""
    result = subprocess.run(
        [sys.executable, "scripts/generate_ai_endpoints.py"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        log.warning(
            "WARN: AI endpoint generation failed (non-fatal): %s",
            result.stderr.strip()[:200],
        )



def tlp_safe_public_feed_source(source: Path, scratch_dir: Path) -> Path:
    """Make an upload-only TLP-sanitized copy of api/feed.json.

    The checked-in/runtime source is left unchanged for forensic comparison.
    The R2 PUT must read only this validated copy. Missing policy, malformed
    source JSON or an unexpected shape fails BEFORE any PUT is planned.
    An empty authorized set is written as [] to replace stale public R2 feed
    bytes, instead of retaining a previous restricted payload. Historical
    Worker/CDN cache exposure still requires separately approved containment.
    """
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("cannot verify public feed JSON for TLP publication") from exc
    if not isinstance(raw, list):
        raise ValueError("public feed is not a JSON list; refusing R2 publication")
    publishable, quarantined = _tlp_policy.partition_publishable(raw)
    # R2 is another public-write boundary: never publish internal advisory
    # aliases as STIX object identifiers, even if an earlier stage was bypassed.
    # Keep the source inventory unmodified for provenance and operator review.
    safe_public = [dict(record) for record in publishable]
    for record in safe_public:
        _remove_invalid_stix_alias(record)
    # The top-level TLP policy is necessary but not sufficient: a CLEAR
    # advisory may contain an *unlabeled nested advisory*, which the Worker
    # refuses even when partition_publishable() accepts the parent. Apply
    # the same recursive record recognition as the Worker before R2 PUT.
    # Do not modify the original file or fabricate a missing TLP label.
    safe_public, nested_removed, withheld = _tlp_boundary.sanitize_document(safe_public)
    if withheld or not isinstance(safe_public, list):
        raise ValueError("public feed recursive TLP boundary unverified")
    if nested_removed:
        log.warning("TLP R2 feed nested boundary removed %d unverified record(s)", len(nested_removed))
    scratch_dir.mkdir(parents=True, exist_ok=True)
    safe_path = scratch_dir / "tlp-public-feed.json"
    safe_path.write_text(json.dumps(safe_public, ensure_ascii=False, separators=(",", ":")),
                         encoding="utf-8")
    log.warning("TLP R2 feed boundary: %d allowed, %d withheld; source unchanged",
                len(publishable), len(quarantined))
    _TLP_VERIFIED_COPIES.add(str(safe_path))
    return safe_path


def tlp_safe_public_json_source(source: Path, scratch_dir: Path, dst_key: str, parents=None):
    """Upload-only, boundary-sanitized copy of ANY JSON object bound for the public data bucket (P0 #721/#725).

    Restricted/missing/invalid-label records are removed; a document that declares its own restricted
    classification is replaced by a tombstone (so stale restricted bytes are overwritten, not retained).
    Unlabelled derived documents inherit the verified decision of their parent advisory (`parents`).
    The source is never modified. Returns the path to PUT, the original path if it does not exist (s3_cp reports
    that exactly as before), or None when the document cannot be verified -- the caller must then withhold it.
    """
    if not source.exists():
        return source
    scratch_dir.mkdir(parents=True, exist_ok=True)
    safe = scratch_dir / (hashlib.sha256(dst_key.encode("utf-8")).hexdigest()[:16] + ".json")
    try:
        res = _tlp_boundary.sanitize_json_file(source, safe, parents=parents)
    except _tlp_boundary.BoundaryError as exc:
        log.error("TLP boundary: %s -> %s cannot be verified; withheld from R2 (%s)", source.name, dst_key, exc)
        return None
    if res["removed"] or res["withheld"]:
        log.warning("TLP boundary: %s -> %s: %d record(s) removed%s; source unchanged", source.name, dst_key,
                    len(res["removed"]), ", document replaced by tombstone" if res["withheld"] else "")
    _TLP_VERIFIED_COPIES.add(str(safe))
    return safe


def report_catalog_chronology_precheck() -> bool:
    """Fail closed on chronology AND same-run registry consistency.

    The three report keys must be a coherent generation before any R2 PUT.
    This is an offline precheck, NOT customer-delivery certification.
    No Cloudflare/R2 calls, mutations, or report contents in diagnostics.
    """
    catalog = REPO_ROOT / "api/reports/index.json"
    try:
        if not catalog.is_file() or catalog.stat().st_size > 20_000_000:
            return False
        # Publish the three catalog keys together or not at all.
        for src, _dst in REPORTS_INDEX_FILES:
            path = REPO_ROOT / src
            if not path.is_file() or stale_manifest_reason(path):
                return False
        from report_chronology_integrity import audit_catalog
        from report_registry_contract import audit_registry
        payloads = {}
        for src, _dst in REPORTS_INDEX_FILES:
            path = REPO_ROOT / src
            if path.stat().st_size > 2_000_000:
                return False
            payloads[path.name] = json.loads(path.read_text(encoding="utf-8"))
        if audit_catalog(payloads["index.json"]).get("verdict") != "CHRONOLOGY_PRECHECK_ONLY":
            return False
        return audit_registry(
            payloads["index.json"], payloads["latest.json"], payloads["stats.json"]
        ).get("verdict") == "ARTIFACT_CONSISTENCY_ONLY"
    except (OSError, UnicodeError, ValueError, TypeError, ImportError, RecursionError):
        return False


def build_upload_plan() -> list[tuple[str, str]]:
    """
    Enumerates every (src, dst_key) pair main()'s normal run intends to PUT
    to BUCKET_DATA -- computed entirely from local Path.exists() checks,
    zero R2 calls. Building this full plan before issuing a single upload
    lets main() call r2_cost_guard.enforce_budget() BEFORE any mutation
    (fail-closed, Constitution Principle 6 / Level 2 Production Stability),
    closing the documented r2_upload.py accounting gap: this script used to
    issue ~20-30 PUTs/run with no R2OperationPlan of its own at all,
    invisible to the r2_cost_guard.py ledger that scripts/
    r2_report_publisher.py already populates every run.

    Deliberately excludes the 4 shared AI-tracker keys (ai/tracker.json,
    ai/health.json, ai/executive-brief.json, ai/monetization.json) -- see
    the "P0 DUPLICATE-WRITER RACE FIX" comment above AI_TRACKER_FILES for
    why those are now uploaded exclusively by generate-and-sync.yml via
    main_ai_tracker_only().
    """
    pairs: list[tuple[str, str]] = [("data/stix/feed_manifest.json", "intel/feed_manifest.json")]

    enriched_files = [
        ("data/apex_enriched_manifest.json",    "intel/apex_enriched_manifest.json"),
        ("data/apex_v2_manifest.json",          "intel/apex_v2_manifest.json"),
        ("data/apex_v2_strategic_report.json",  "intel/apex_v2_strategic_report.json"),
        ("data/validated_manifest.json",        "intel/validated_manifest.json"),
    ]
    pairs += [(s, d) for s, d in enriched_files if (REPO_ROOT / s).exists()]

    # P40 Global Intelligence Source Fabric artifacts (see P40_SOURCE_FABRIC_FILES).
    pairs += [(s, d) for s, d in P40_SOURCE_FABRIC_FILES if (REPO_ROOT / s).exists()]

    apex_v2_dir = REPO_ROOT / "api" / "apex_v2"
    if apex_v2_dir.is_dir():
        pairs += [(str(f), f"apex_v2/{f.name}") for f in sorted(apex_v2_dir.glob("*.json"))]

    # Immutable public intel manifests (v150.1 API-first). Served by the
    # Cloudflare Worker via servePublicIntelManifest() using
    # r2Key = pathname.slice(1), e.g. "api/v1/intel/latest.json".
    intel_v1_manifests = [
        ("api/feed.json",                 "api/feed.json"),
        ("api/v1/intel/latest.json",      "api/v1/intel/latest.json"),
        ("api/v1/intel/latest_pro.json",  "api/v1/intel/latest_pro.json"),
        ("api/v1/intel/top10.json",       "api/v1/intel/top10.json"),
        ("api/v1/intel/apex.json",        "api/v1/intel/apex.json"),
        ("api/v1/intel/manifest.json",    "api/v1/intel/manifest.json"),
        ("api/v1/intel/ai_summary.json",  "api/v1/intel/ai_summary.json"),
    ]
    if report_catalog_chronology_precheck():
        intel_v1_manifests.extend(REPORTS_INDEX_FILES)
    else:
        log.warning("P0 Stage 3.5: report catalog UTC chronology precheck blocked; all three catalog PUTs withheld")
    for src, dst_key in intel_v1_manifests:
        if (REPO_ROOT / src).exists():
            stale = stale_manifest_reason(REPO_ROOT / src)
            if stale:
                log.warning("SKIP (stale): %s -- %s", src, stale)
                print(f"::warning::r2_upload: skipped stale {src} ({stale})", flush=True)
                continue
            pairs.append((src, dst_key))
        else:
            log.warning("SKIP: %s not found (will fallback to GitHub raw)", src)

    # AI Index + Detection Rule Manifest.
    ai_index_files = [
        ("data/ai_intelligence/ai_index.json",                     "intelligence/ai_index.json"),
        ("data/intelligence/detection_rules/rule_manifest.json",   "intelligence/detection_rules_manifest.json"),
    ]
    for src, dst_key in ai_index_files:
        if (REPO_ROOT / src).exists():
            pairs.append((src, dst_key))
        else:
            log.warning("SKIP (AI index): %s not found", src)

    # AI intelligence data directories. AI_TRACKER_FILENAMES excluded --
    # those 4 keys are owned exclusively by main_ai_tracker_only(), called
    # only from generate-and-sync.yml (see module-level comment).
    ai_dirs = [REPO_ROOT / "data" / "ai_intelligence", REPO_ROOT / "api" / "ai"]
    for ai_dir in ai_dirs:
        if ai_dir.is_dir():
            for f in sorted(ai_dir.glob("*.json")):
                if f.name in AI_TRACKER_FILENAMES:
                    continue
                pairs.append((str(f), f"ai/{f.name}"))

    return pairs


def assert_worker_public_latest_preflight(path: Path) -> None:
    """Before ANY R2 PUT, require the sanitized latest.json to pass the real Worker.

    No network and no source contents in error messages. Original advisory
    inventory stays untouched, and 1MiB/TLP/depth/value-visit limits match
    the Worker and the final resynchronizer's acceptance gate.
    """
    diagnostic = Path(__file__).resolve().parent / "p0_r2_public_feed_diagnostic.mjs"
    try:
        result = subprocess.run(
            ["node", str(diagnostic), str(path)],
            capture_output=True, text=True, check=False, timeout=25,
        )
        decision = json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise ValueError("P0_PUBLIC_LATEST_WORKER_PREFLIGHT_UNAVAILABLE") from exc
    if (result.returncode != 0 or not isinstance(decision, dict)
            or decision.get("verdict") != "DELIVERABLE"
            or decision.get("worker_public_tlp_gate") != "PASS"
            or decision.get("freshness") != "FRESH"):
        # Do not report arbitrary stdout or exception text from source JSON.
        raise ValueError("P0_PUBLIC_LATEST_WORKER_REJECTED")


def main() -> None:
    log.info("=" * 60)
    log.info("SENTINEL APEX v%s -- R2 Upload Engine", PIPELINE_VERSION)
    log.info("=" * 60)

    os.chdir(REPO_ROOT)

    # Supplemental collectors run after the first feed prewrite check.
    # Finalize under the same rules before any R2 reads/writes are planned.
    from p0_r44_publication_boundary import finalize_public_feed
    finalize_public_feed(REPO_ROOT)

    cf_account, access_key, secret_key = get_credentials()
    endpoint = f"https://{cf_account}.r2.cloudflarestorage.com"

    install_awscli()

    # Configure awscli for high-throughput parallel uploads BEFORE any transfer.
    # This is the primary fix for the 36-minute stall / job-timeout cancellation.
    configure_awscli_performance()

    item_count = count_manifest()
    log.info("Uploading %d advisories to R2...", item_count)

    # Generate AI endpoints from the current manifest BEFORE building the
    # upload plan (see _generate_ai_endpoints() docstring) so the plan below
    # sees its output.
    _generate_ai_endpoints()

    # --- Build the full operation plan BEFORE issuing a single R2 call ---
    pairs = build_upload_plan()
    # P0 #725: the generic uploader must not PUT the raw, mixed-TLP api/feed.json
    # that contains restricted entries. Build the sanitized replacement BEFORE
    # any R2 mutation, using the same authority as the report publisher.
    tlp_scratch = tempfile.TemporaryDirectory(prefix="cdb-p0-tlp-r2-")
    try:
        # derived per-advisory documents (no label of their own) inherit the verified decision of their parent
        tlp_parents = _tlp_boundary.build_parent_index([
            REPO_ROOT / "api" / "feed.json", REPO_ROOT / "data" / "feed_manifest.json",
            REPO_ROOT / "data" / "stix" / "feed_manifest.json"])
        guarded_pairs = []
        for candidate_src, candidate_dst_key in pairs:
            if candidate_dst_key == "api/feed.json":
                safe = tlp_safe_public_feed_source(Path(candidate_src), Path(tlp_scratch.name))
                guarded_pairs.append((str(safe), candidate_dst_key))
            elif candidate_dst_key.endswith(".json"):
                # P0 #721: every other JSON object bound for the public bucket passes the same authority
                # (apex_v2/priority.json, intel/*_manifest.json, ai/*.json, ... -- measured: several carry
                # restricted-labelled records or a document-level TLP:AMBER classification).
                safe_json = tlp_safe_public_json_source(Path(candidate_src), Path(tlp_scratch.name), candidate_dst_key,
                                                      tlp_parents)
                if safe_json is None:
                    continue  # unverifiable -> withheld (no PUT planned, none budgeted)
                if candidate_dst_key == "api/v1/intel/latest.json":
                    # Stage 3.5 precedes the Stage 3.93 final resync; an
                    # invalid latest must NEVER become live even temporarily.
                    assert_worker_public_latest_preflight(Path(safe_json))
                guarded_pairs.append((str(safe_json), candidate_dst_key))
            else:
                guarded_pairs.append((candidate_src, candidate_dst_key))
        pairs = guarded_pairs
    except (OSError, ValueError, TypeError) as exc:
        tlp_scratch.cleanup()
        log.critical("P0 TLP public feed verification refused before R2 writes: %s", exc)
        sys.exit(1)

    plan = R2OperationPlan(label="r2_upload", bucket=BUCKET_DATA)
    plan.record_put(len(pairs) + 1)  # +1 for the sync-metadata write below

    budgets = R2Budgets.from_env()
    try:
        enforce_budget(plan, budgets, is_report_plan=False)
    except R2BudgetExceeded as exc:
        log.critical(str(exc))
        emit_summary(plan, budgets, status="BLOCKED", is_report_plan=False,
                     extra={"reason": str(exc)})
        sys.exit(1)

    # --- Execute the plan -- budget already cleared, safe to mutate ---
    uploaded = 0
    for src, dst_key in pairs:
        if s3_cp(src, BUCKET_DATA, dst_key, endpoint):
            uploaded += 1
    log.info("OK: %d/%d planned R2 data-bucket files uploaded", uploaded, len(pairs))

    # --- Upload 4a / 4a-PDF: REMOVED (P0 R2 COST INCIDENT, 2026-09) ---
    # ROOT CAUSE: this block used to run `aws s3 sync reports/ ->
    # s3://sentinel-apex-reports/reports/` (size_only=False, full content/
    # mtime comparison, no bound) plus a second `aws s3 sync` for
    # reports/pdf/ -- on EVERY scheduled pipeline run. Because
    # generate_intel_reports.py's default (non---only-missing) mode
    # regenerates a report for every item in the manifest -- not just new/
    # changed ones -- and every regenerated file embeds a fresh minute-
    # granularity timestamp into its SIGMA/YARA/KQL/SPL blocks, the entire
    # local reports/ tree looked "changed" to `aws s3 sync` on every single
    # run. `aws s3 sync` also unconditionally LISTs the entire destination
    # prefix to build its comparison map regardless of how much actually
    # changed. Against a ~193K-object bucket, this produced the 3,004,147
    # billable R2 Class A operations in one billing cycle documented in
    # docs/P0_R2_COST_CONTAINMENT.md.
    #
    # FIX: whole-corpus sync does not exist in this codebase anymore -- not
    # flag-gated, structurally removed. scripts/r2_report_publisher.py is
    # now the sole normal-operation writer/retirer for both the HTML
    # reports keyspace (sentinel-apex-reports) and reports/pdf/ (sentinel-
    # apex-data). It works from deterministic keys derived from the
    # CURRENT manifest, publishes only genuinely new/changed content (sha256
    # -diffed against its own local state file, never a bucket LIST), is
    # bounded to the rolling REPORT_WINDOW_HOURS (default 24h) window, and
    # enforces a fail-closed operation budget (scripts/r2_cost_guard.py)
    # before issuing a single R2 call. Invoked as its own pipeline stage
    # (see sentinel-apex.yml) immediately after this script, not from
    # inside main() -- keeping this script's own responsibility limited to
    # the bounded sentinel-apex-data manifest/endpoint uploads below, which
    # were never the cost driver.
    #
    # R2_REPORT_PUBLISHING_ENABLED=false (env var, read by
    # r2_report_publisher.py) remains the emergency kill switch if report
    # publishing itself ever needs to be paused without a code change.

    # --- Upload 5: Sync metadata ---
    meta = {
        "synced_at":        utc_now(),
        "advisory_count":   item_count,
        "source":           "sentinel-blogger",
        "pipeline_version": PIPELINE_VERSION,
        "run_id":           os.environ.get("GITHUB_RUN_ID", "local"),
        "p0_fix":           "v184.2 -- r2_timeout_fix, awscli_perf, full_content_sync",
    }
    # Stage 3.6 reads this exact private runner-local path. Avoid a
    # predictable world-writable /tmp file and cross-run stale collisions.
    sync_meta_dir = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()) / "sentinel-apex-r2"
    sync_meta_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(sync_meta_dir, 0o700)
    sync_meta_path = str(sync_meta_dir / "sync_meta.json")
    with open(sync_meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

    s3_cp(sync_meta_path, BUCKET_DATA, "intel/_sync_meta.json", endpoint)
    log.info("OK: Sync metadata written (%d advisories synced to R2)", item_count)

    write_github_env("R2_UPLOAD_COUNT", str(item_count))
    emit_summary(plan, budgets, status="PASS", is_report_plan=False,
                 extra={"advisory_count": item_count, "files_uploaded": uploaded})
    tlp_scratch.cleanup()
    log.info("R2 upload complete.")


if __name__ == "__main__":
    try:
        if "--p40-only" in sys.argv:
            main_p40_only()
        elif "--ai-tracker-only" in sys.argv:
            main_ai_tracker_only()
        elif "--governance-telemetry-only" in sys.argv:
            main_governance_telemetry_only()
        elif "--weekly-brief-only" in sys.argv:
            main_weekly_brief_only()
        elif "--reports-index-only" in sys.argv:
            main_reports_index_only()
        else:
            main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        log.critical(
            "Unhandled exception in r2_upload.py:\n%s\n%s", e, traceback.format_exc(),
        )
        sys.exit(1)
