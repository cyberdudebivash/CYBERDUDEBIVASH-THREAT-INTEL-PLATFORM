#!/usr/bin/env python3
"""
scripts/global_release_orchestrator.py
CYBERDUDEBIVASH(R) SENTINEL APEX — GLOBAL RELEASE ORCHESTRATION ENGINE v1.0

PURPOSE:
  Central governance gate that runs AFTER deployment and validates that every
  release surface (frontend, API, manifests, version artifacts, service worker,
  cache, telemetry) is convergently synchronized with the authoritative SSOT
  defined in config/platform_version.json.

GOVERNANCE DOMAINS:
  1. Release Identity Governance   — SSOT version consistent across all surfaces
  2. Release Manifest Validation   — all critical files present, non-empty, parseable
  3. Artifact Synchronization      — dist/ artifact integrity post-build
  4. Deployment Convergence        — version.json / service-worker match SSOT
  5. Rollback Governance           — previous deployment state assessable
  6. Concurrency Governance        — detect concurrent or orphaned deploy locks
  7. Cache Propagation Governance  — service-worker cache version aligned
  8. Synchronization Validation    — frontend / backend / API surface agreement

EXIT CODES:
  0 — all governance gates PASS (or non-blocking warnings only)
  1 — one or more HARD FAIL gates triggered → pipeline blocks deployment

Author : CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Repo root (script lives in scripts/)
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Governance result accumulator
# ---------------------------------------------------------------------------
RESULTS: List[Dict] = []
HARD_FAIL_COUNT = 0
WARN_COUNT = 0
PASS_COUNT = 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record(
    domain: str,
    check: str,
    status: str,          # "PASS" | "WARN" | "FAIL"
    detail: str = "",
    hard: bool = False,
) -> None:
    global HARD_FAIL_COUNT, WARN_COUNT, PASS_COUNT
    tag = "HARD_FAIL" if (status == "FAIL" and hard) else status
    RESULTS.append({
        "domain":  domain,
        "check":   check,
        "status":  tag,
        "detail":  detail,
        "ts":      _now_iso(),
    })
    if tag == "HARD_FAIL":
        HARD_FAIL_COUNT += 1
        print(f"  [HARD_FAIL] {domain} / {check}: {detail}")
    elif status == "FAIL":
        WARN_COUNT += 1
        print(f"  [WARN]      {domain} / {check}: {detail}")
    elif status == "WARN":
        WARN_COUNT += 1
        print(f"  [WARN]      {domain} / {check}: {detail}")
    else:
        PASS_COUNT += 1
        print(f"  [PASS]      {domain} / {check}: {detail}")


# ===========================================================================
# 1. LOAD SSOT
# ===========================================================================

def load_ssot() -> Dict:
    """Load config/platform_version.json — the authoritative SSOT."""
    ssot_path = BASE_DIR / "config" / "platform_version.json"
    if not ssot_path.exists():
        record("RELEASE_IDENTITY", "ssot_present",
               "FAIL", f"config/platform_version.json missing", hard=True)
        return {}
    try:
        data = json.loads(ssot_path.read_text(encoding="utf-8"))
        record("RELEASE_IDENTITY", "ssot_present", "PASS",
               f"config/platform_version.json loaded OK")
        return data
    except Exception as e:
        record("RELEASE_IDENTITY", "ssot_parseable",
               "FAIL", f"JSON parse error: {e}", hard=True)
        return {}


# ===========================================================================
# 2. RELEASE IDENTITY GOVERNANCE
# ===========================================================================

def check_release_identity(ssot: Dict) -> None:
    """Verify platform version is consistent across all surfaces."""
    print("\n[DOMAIN 1] RELEASE IDENTITY GOVERNANCE")

    if not ssot:
        record("RELEASE_IDENTITY", "ssot_loaded", "FAIL",
               "SSOT not loaded — skipping identity checks", hard=True)
        return

    platform_ver  = ssot.get("platform", {}).get("version", "")
    pipeline_ver  = ssot.get("ci", {}).get("pipeline_version", "")

    if not platform_ver:
        record("RELEASE_IDENTITY", "platform_version_defined",
               "FAIL", "platform.version missing in SSOT", hard=True)
    else:
        record("RELEASE_IDENTITY", "platform_version_defined",
               "PASS", f"platform.version = {platform_ver}")

    if not pipeline_ver:
        record("RELEASE_IDENTITY", "pipeline_version_defined",
               "FAIL", "ci.pipeline_version missing in SSOT", hard=True)
    else:
        record("RELEASE_IDENTITY", "pipeline_version_defined",
               "PASS", f"ci.pipeline_version = {pipeline_ver}")

    # version.json must match platform version
    vj_path = BASE_DIR / "version.json"
    if vj_path.exists():
        try:
            vj = json.loads(vj_path.read_text(encoding="utf-8"))
            vj_ver = vj.get("version", vj.get("platform_version", ""))
            if vj_ver == platform_ver:
                record("RELEASE_IDENTITY", "version_json_sync",
                       "PASS", f"version.json = {vj_ver} matches SSOT")
            else:
                record("RELEASE_IDENTITY", "version_json_sync",
                       "WARN", f"version.json = {vj_ver!r} vs SSOT = {platform_ver!r}")
        except Exception as e:
            record("RELEASE_IDENTITY", "version_json_parseable",
                   "WARN", f"version.json parse error: {e}")
    else:
        record("RELEASE_IDENTITY", "version_json_present",
               "WARN", "version.json not found")

    # config/version.json
    cvj_path = BASE_DIR / "config" / "version.json"
    if cvj_path.exists():
        try:
            cvj = json.loads(cvj_path.read_text(encoding="utf-8"))
            cvj_ver = cvj.get("version", cvj.get("platform_version", ""))
            if cvj_ver == platform_ver:
                record("RELEASE_IDENTITY", "config_version_json_sync",
                       "PASS", f"config/version.json = {cvj_ver}")
            else:
                record("RELEASE_IDENTITY", "config_version_json_sync",
                       "WARN", f"config/version.json = {cvj_ver!r} vs SSOT = {platform_ver!r}")
        except Exception as e:
            record("RELEASE_IDENTITY", "config_version_json_parseable",
                   "WARN", f"config/version.json parse error: {e}")
    else:
        record("RELEASE_IDENTITY", "config_version_json_present",
               "WARN", "config/version.json not found")


# ===========================================================================
# 3. RELEASE MANIFEST VALIDATION
# ===========================================================================

CRITICAL_FILES: List[Tuple[str, bool]] = [
    # (relative_path, hard_fail_if_missing)
    ("index.html",                                   True),
    ("api/feed.json",                                True),
    # api/latest.json: checked via check_latest_json() below — supports dual path
    # (api/latest.json OR api/v1/intel/latest.json) to prevent false HARD_FAIL
    ("version.json",                                 True),
    ("service-worker.js",                            True),
    ("config/platform_version.json",                 True),
    ("scripts/global_version_sync.py",               True),
    ("scripts/sentinel_observability_engine.py",     False),
    ("scripts/global_release_orchestrator.py",       False),
    ("api/billing.py",                               False),
    ("PAYMENT-GATEWAY.html",                         False),
    ("get-api-key.html",                             False),
    (".github/workflows/sentinel-blogger.yml",       True),
]

# Dual-path candidates for api/latest.json — checked in order, first hit wins
LATEST_JSON_CANDIDATES: List[str] = [
    "api/latest.json",
    "api/v1/intel/latest.json",
]


def resolve_latest_json() -> Optional[Path]:
    """Resolve api/latest.json with fallback to api/v1/intel/latest.json.

    Returns the resolved Path if found (non-empty), else None.
    This prevents false HARD_FAILs when the platform uses v1 intel endpoint
    as its latest feed instead of a root-level api/latest.json.
    """
    for candidate in LATEST_JSON_CANDIDATES:
        path = BASE_DIR / candidate
        if path.exists() and path.stat().st_size > 0:
            return path
    return None


def check_manifest(ssot: Dict) -> None:
    """Validate all critical files exist, are non-empty, and are parseable."""
    print("\n[DOMAIN 2] RELEASE MANIFEST VALIDATION")

    # Check api/latest.json with dual-path fallback (not in CRITICAL_FILES loop)
    latest_resolved = resolve_latest_json()
    if latest_resolved:
        size = latest_resolved.stat().st_size
        try:
            json.loads(latest_resolved.read_text(encoding="utf-8"))
            record("MANIFEST", "parseable:api/latest.json",
                   "PASS", f"{size:,} bytes — JSON valid (resolved: {latest_resolved.relative_to(BASE_DIR)})")
        except Exception as e:
            record("MANIFEST", "parseable:api/latest.json",
                   "FAIL", f"JSON parse error: {e}", hard=True)
    else:
        record("MANIFEST", "present:api/latest.json",
               "FAIL",
               f"api/latest.json and api/v1/intel/latest.json both missing or empty",
               hard=True)

    for rel_path, is_hard in CRITICAL_FILES:
        path = BASE_DIR / rel_path
        if not path.exists():
            record("MANIFEST", f"present:{rel_path}",
                   "FAIL", f"MISSING: {rel_path}", hard=is_hard)
            continue

        size = path.stat().st_size
        if size == 0:
            record("MANIFEST", f"non_empty:{rel_path}",
                   "FAIL", f"EMPTY FILE: {rel_path}", hard=is_hard)
            continue

        # JSON parseability check
        if rel_path.endswith(".json"):
            try:
                json.loads(path.read_text(encoding="utf-8"))
                record("MANIFEST", f"parseable:{rel_path}",
                       "PASS", f"{size:,} bytes — JSON valid")
            except Exception as e:
                record("MANIFEST", f"parseable:{rel_path}",
                       "FAIL", f"JSON parse error: {e}", hard=is_hard)
        else:
            record("MANIFEST", f"present:{rel_path}",
                   "PASS", f"{size:,} bytes")


# ===========================================================================
# 4. ARTIFACT SYNCHRONIZATION VALIDATION
# ===========================================================================

DIST_REQUIRED: List[str] = [
    "index.html",
    "service-worker.js",
    "version.json",
    "PAYMENT-GATEWAY.html",
]


def check_artifact_sync(ssot: Dict) -> None:
    """Verify dist/ artifact integrity if dist/ exists.

    Severity escalation:
      CI=true (GitHub Actions): HARD_FAIL when build artifacts missing post-build.
      Local / outside CI: WARN only (build stage not yet run).

    v160.1.1: STAGE 5.8.3b now creates dist/ before this runs in CI.
    If dist/ is still absent, this is a genuine build failure — HARD_FAIL is correct.
    """
    print("\n[DOMAIN 3] ARTIFACT SYNCHRONIZATION VALIDATION")

    in_ci = os.environ.get("CI", "").lower() in ("true", "1", "yes")
    dist_dir = BASE_DIR / "dist"

    if not dist_dir.exists():
        if in_ci:
            record("ARTIFACT_SYNC", "dist_present",
                   "FAIL",
                   "dist/ absent in CI — STAGE 5.8.3b builder failed or was skipped",
                   hard=True)
        else:
            record("ARTIFACT_SYNC", "dist_present",
                   "WARN", "dist/ not found — expected only after CI build stage")
        return

    record("ARTIFACT_SYNC", "dist_present", "PASS", f"dist/ exists")

    for rel in DIST_REQUIRED:
        p = dist_dir / rel
        if not p.exists():
            record("ARTIFACT_SYNC", f"dist_contains:{rel}",
                   "FAIL", f"dist/{rel} MISSING", hard=in_ci)
        else:
            record("ARTIFACT_SYNC", f"dist_contains:{rel}",
                   "PASS", f"dist/{rel} present ({p.stat().st_size:,} bytes)")
    # Version alignment: dist/version.json must match SSOT platform version
    platform_ver = ssot.get("platform", {}).get("version", "")
    dist_vj = dist_dir / "version.json"
    if dist_vj.exists() and platform_ver:
        try:
            dv = json.loads(dist_vj.read_text(encoding="utf-8"))
            dv_ver = dv.get("version", dv.get("platform_version", ""))
            if dv_ver == platform_ver:
                record("ARTIFACT_SYNC", "dist_version_sync",
                       "PASS", f"dist/version.json = {dv_ver}")
            else:
                record("ARTIFACT_SYNC", "dist_version_sync",
                       "WARN", f"dist/version.json = {dv_ver!r} vs SSOT = {platform_ver!r}")
        except Exception as e:
            record("ARTIFACT_SYNC", "dist_version_parseable",
                   "WARN", f"dist/version.json parse error: {e}")


# ===========================================================================
# 5. DEPLOYMENT CONVERGENCE GOVERNANCE
# ===========================================================================

def check_deployment_convergence(ssot: Dict) -> None:
    """Verify deployment confidence score from previous convergence run."""
    print("\n[DOMAIN 4] DEPLOYMENT CONVERGENCE GOVERNANCE")

    score_path = BASE_DIR / "deployment_confidence_score.json"
    if not score_path.exists():
        record("CONVERGENCE", "score_present",
               "WARN", "deployment_confidence_score.json not found — convergence not yet run")
        return

    try:
        score_data = json.loads(score_path.read_text(encoding="utf-8"))
    except Exception as e:
        record("CONVERGENCE", "score_parseable",
               "WARN", f"Parse error: {e}")
        return

    score     = score_data.get("confidence_score", score_data.get("score", 0))
    state     = score_data.get("state", score_data.get("deployment_state", "UNKNOWN"))
    generated = score_data.get("generated_at", score_data.get("timestamp", ""))

    record("CONVERGENCE", "score_value",
           "PASS" if score >= 80 else "WARN",
           f"confidence_score={score} state={state} generated={generated}")

    if score >= 90:
        record("CONVERGENCE", "deployment_stable", "PASS",
               f"Score {score} >= 90 — DEPLOYMENT_STABLE")
    elif score >= 70:
        record("CONVERGENCE", "deployment_stable", "WARN",
               f"Score {score} 70–89 — DEPLOYMENT_DEGRADED — investigate")
    else:
        record("CONVERGENCE", "deployment_stable", "FAIL",
               f"Score {score} < 70 — DEPLOYMENT_UNSTABLE — immediate action needed")


# ===========================================================================
# 6. ROLLBACK GOVERNANCE
# ===========================================================================

def check_rollback_governance(ssot: Dict) -> None:
    """Verify rollback artifacts and git history are healthy."""
    print("\n[DOMAIN 5] ROLLBACK GOVERNANCE")

    # Verify git HEAD is accessible
    git_dir = BASE_DIR / ".git"
    if git_dir.exists():
        record("ROLLBACK", "git_repo_present", "PASS", ".git directory present")
    else:
        record("ROLLBACK", "git_repo_present", "WARN",
               ".git not found — rollback may be impaired")
        return

    # Verify ORIG_HEAD or packed-refs exist (means we have history to roll back to)
    orig_head = BASE_DIR / ".git" / "ORIG_HEAD"
    packed_refs = BASE_DIR / ".git" / "packed-refs"
    if orig_head.exists() or packed_refs.exists():
        record("ROLLBACK", "rollback_history_present", "PASS",
               "Git history available for rollback")
    else:
        record("ROLLBACK", "rollback_history_present", "WARN",
               "ORIG_HEAD and packed-refs absent — limited rollback history")

    # Verify pipeline lock file is NOT stuck
    lock_path = BASE_DIR / ".pipeline_lock"
    if lock_path.exists():
        age_s = time.time() - lock_path.stat().st_mtime
        if age_s > 7200:  # 2 hours stale
            record("ROLLBACK", "pipeline_lock_stale", "WARN",
                   f"Stale .pipeline_lock (age={age_s/60:.0f}m) — may indicate orphaned deploy")
        else:
            record("ROLLBACK", "pipeline_lock_age", "PASS",
                   f"Active .pipeline_lock (age={age_s/60:.0f}m)")
    else:
        record("ROLLBACK", "pipeline_lock_absent", "PASS",
               "No active pipeline lock (clean state)")


# ===========================================================================
# 7. CONCURRENCY GOVERNANCE
# ===========================================================================

def check_concurrency_governance(ssot: Dict) -> None:
    """Verify no concurrent deployment artifacts or race conditions."""
    print("\n[DOMAIN 6] CONCURRENCY GOVERNANCE")

    # Confirm workflow concurrency group is set in SSOT context (check yml directly)
    yml_path = BASE_DIR / ".github" / "workflows" / "sentinel-blogger.yml"
    if yml_path.exists():
        content = yml_path.read_text(encoding="utf-8")
        if "sentinel-apex-production" in content and "cancel-in-progress: false" in content:
            record("CONCURRENCY", "workflow_serialized", "PASS",
                   "sentinel-apex-production concurrency group active, cancel-in-progress=false")
        elif "concurrency" in content:
            record("CONCURRENCY", "workflow_serialized", "WARN",
                   "concurrency block present but sentinel-apex-production group not confirmed")
        else:
            record("CONCURRENCY", "workflow_serialized", "FAIL",
                   "No concurrency governance in sentinel-blogger.yml", hard=False)
    else:
        record("CONCURRENCY", "workflow_present", "WARN",
               "sentinel-blogger.yml not found for concurrency audit")

    # Check for multiple .pipeline_lock files (should only ever be 0 or 1)
    lock_files = list(BASE_DIR.glob(".pipeline_lock*"))
    if len(lock_files) <= 1:
        record("CONCURRENCY", "single_lock_file", "PASS",
               f"Lock file count: {len(lock_files)} (safe)")
    else:
        record("CONCURRENCY", "single_lock_file", "WARN",
               f"Multiple lock files found ({len(lock_files)}) — possible concurrent deploys")


# ===========================================================================
# 8. CACHE PROPAGATION GOVERNANCE
# ===========================================================================

def check_cache_propagation(ssot: Dict) -> None:
    """Verify service-worker cache version and version.json are aligned."""
    print("\n[DOMAIN 7] CACHE PROPAGATION GOVERNANCE")

    platform_ver = ssot.get("platform", {}).get("version", "")
    pipeline_ver = ssot.get("ci", {}).get("pipeline_version", "")

    sw_path = BASE_DIR / "service-worker.js"
    if not sw_path.exists():
        record("CACHE", "sw_present", "WARN", "service-worker.js not found")
    else:
        content = sw_path.read_text(encoding="utf-8")

        # Look for cache version declaration
        ver_match = re.search(r"[Cc]ache[_\-]?[Vv]ersion\s*[=:]\s*['\"]?([^\s'\"]+)", content)
        const_match = re.search(r"const\s+\w*[Vv]ersion\w*\s*=\s*['\"]([^'\"]+)['\"]", content)
        cache_match = re.search(r"sentinel-apex-v([^\s'\"]+)", content)

        detected = (
            ver_match.group(1) if ver_match else
            const_match.group(1) if const_match else
            cache_match.group(1) if cache_match else
            None
        )

        if detected:
            record("CACHE", "sw_version_detected", "PASS",
                   f"service-worker.js cache version detected: {detected}")
        else:
            record("CACHE", "sw_version_detected", "WARN",
                   "Could not detect cache version in service-worker.js")

        if pipeline_ver and pipeline_ver in content:
            record("CACHE", "sw_pipeline_ver_present", "PASS",
                   f"Pipeline version {pipeline_ver} referenced in service-worker.js")
        else:
            record("CACHE", "sw_pipeline_ver_present", "WARN",
                   f"Pipeline version {pipeline_ver!r} not found in service-worker.js")

    # version.json cache version field
    vj_path = BASE_DIR / "version.json"
    if vj_path.exists():
        try:
            vj = json.loads(vj_path.read_text(encoding="utf-8"))
            if "cache_version" in vj or "version" in vj:
                record("CACHE", "version_json_cache_field", "PASS",
                       f"version.json has version/cache_version field")
            else:
                record("CACHE", "version_json_cache_field", "WARN",
                       "version.json has no version or cache_version field")
        except Exception as e:
            record("CACHE", "version_json_parseable", "WARN", f"Parse error: {e}")


# ===========================================================================
# 9. SYNCHRONIZATION VALIDATION
# ===========================================================================

def check_synchronization(ssot: Dict) -> None:
    """Validate frontend / API / manifest surfaces are mutually consistent."""
    print("\n[DOMAIN 8] SYNCHRONIZATION VALIDATION")

    platform_ver = ssot.get("platform", {}).get("version", "")
    if not platform_ver:
        record("SYNC", "ssot_platform_ver", "WARN",
               "Platform version unknown — skipping surface sync checks")
        return

    # api/version.json
    api_vj = BASE_DIR / "api" / "version.json"
    if api_vj.exists():
        try:
            av = json.loads(api_vj.read_text(encoding="utf-8"))
            av_ver = av.get("version", av.get("platform_version", ""))
            if av_ver == platform_ver:
                record("SYNC", "api_version_sync", "PASS",
                       f"api/version.json = {av_ver}")
            else:
                record("SYNC", "api_version_sync", "WARN",
                       f"api/version.json = {av_ver!r} vs SSOT = {platform_ver!r}")
        except Exception as e:
            record("SYNC", "api_version_parseable", "WARN", f"Parse error: {e}")
    else:
        record("SYNC", "api_version_present", "WARN",
               "api/version.json not found")

    # api/feed.json — check it has items
    feed_path = BASE_DIR / "api" / "feed.json"
    if feed_path.exists():
        try:
            feed = json.loads(feed_path.read_text(encoding="utf-8"))
            items = feed if isinstance(feed, list) else feed.get("items", feed.get("advisories", []))
            count = len(items)
            if count > 0:
                record("SYNC", "feed_non_empty", "PASS",
                       f"api/feed.json has {count} items")
            else:
                record("SYNC", "feed_non_empty", "WARN",
                       "api/feed.json has 0 items")
        except Exception as e:
            record("SYNC", "feed_parseable", "WARN", f"api/feed.json parse error: {e}")
    else:
        record("SYNC", "feed_present", "FAIL",
               "api/feed.json MISSING — critical API surface absent", hard=True)

    # api/latest.json — dual-path check (api/latest.json OR api/v1/intel/latest.json)
    latest_resolved = resolve_latest_json()
    if latest_resolved:
        try:
            latest = json.loads(latest_resolved.read_text(encoding="utf-8"))
            latest_items = latest if isinstance(latest, list) else latest.get("items", latest.get("advisories", []))
            lcount = len(latest_items)
            record("SYNC", "latest_non_empty",
                   "PASS" if lcount > 0 else "WARN",
                   f"api/latest.json has {lcount} items (source: {latest_resolved.relative_to(BASE_DIR)})")
        except Exception as e:
            record("SYNC", "latest_parseable", "WARN",
                   f"api/latest.json parse error ({latest_resolved.relative_to(BASE_DIR)}): {e}")
    else:
        record("SYNC", "latest_present", "FAIL",
               "api/latest.json MISSING — not found at api/latest.json or api/v1/intel/latest.json",
               hard=True)

    # Observability telemetry sync report (v166.2 — hard-fail on -1 sentinel)
    sync_report = BASE_DIR / "data" / "telemetry" / "sync_report.json"
    if sync_report.exists():
        try:
            sr = json.loads(sync_report.read_text(encoding="utf-8"))
            drift = sr.get("drift_count", sr.get("hard_fails", None))
            if drift is None:
                # drift_count key missing — schema mismatch; treat as uncomputed (WARN, not fail)
                record("SYNC", "telemetry_sync_report", "WARN",
                       "sync_report.json missing drift_count field — schema mismatch")
            elif drift == -1:
                # Sentinel error value: R2 sync compute failed silently — this is a HARD_FAIL
                record("SYNC", "telemetry_sync_report", "HARD_FAIL",
                       "sync_report.json drift_count=-1 (sentinel error) — R2 sync compute failed")
            elif drift == 0:
                record("SYNC", "telemetry_sync_report", "PASS",
                       f"sync_report.json drift_count=0 — fully synced")
            else:
                record("SYNC", "telemetry_sync_report", "WARN",
                       f"sync_report.json drift_count={drift} — drift detected")
        except Exception as e:
            record("SYNC", "telemetry_sync_report", "WARN", f"Parse error: {e}")
    else:
        record("SYNC", "telemetry_sync_report_present", "WARN",
               "data/telemetry/sync_report.json not found (observability engine not run)")


# ===========================================================================
# 10. GOVERNANCE GATE SUMMARY + REPORT
# ===========================================================================

def produce_governance_report(ssot: Dict) -> None:
    """Write machine-readable governance report to disk for downstream consumers."""
    # v160.0 FIX: compute governance_state first so overall_grade can derive from it.
    # STAGE 5.8.4b reads .overall_grade and .release_blocked via jq — both must exist.
    governance_state = (
        "RELEASE_BLOCKED"  if HARD_FAIL_COUNT > 0 else
        "RELEASE_DEGRADED" if WARN_COUNT > 3    else
        "RELEASE_CLEAN"
    )
    _grade_map = {
        "RELEASE_CLEAN":    "A",
        "RELEASE_DEGRADED": "B",
        "RELEASE_BLOCKED":  "F",
    }
    overall_grade = _grade_map.get(governance_state, "C")
    report = {
        "schema":           "sentinel-apex-release-orchestration-v1",
        "generated_at":     _now_iso(),
        "platform_ver":     ssot.get("platform", {}).get("version", "UNKNOWN"),
        "pipeline_ver":     ssot.get("ci", {}).get("pipeline_version", "UNKNOWN"),
        "pass_count":       PASS_COUNT,
        "warn_count":       WARN_COUNT,
        "hard_fail_count":  HARD_FAIL_COUNT,
        "governance_state": governance_state,
        "overall_grade":    overall_grade,
        "release_blocked":  HARD_FAIL_COUNT > 0,
        "results":          RESULTS,
    }

    out_dir = BASE_DIR / "data" / "telemetry"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "global_release_governance.json"
    out_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    print(f"\n  [REPORT] Governance report written to: {out_path.relative_to(BASE_DIR)}")
    return report


# ===========================================================================
# MAIN
# ===========================================================================

def main() -> int:
    print("=" * 72)
    print("CYBERDUDEBIVASH(R) SENTINEL APEX")
    print("GLOBAL RELEASE ORCHESTRATION ENGINE v1.0")
    print(f"Run timestamp: {_now_iso()}")
    print("=" * 72)

    ssot = load_ssot()

    check_release_identity(ssot)
    check_manifest(ssot)
    check_artifact_sync(ssot)
    check_deployment_convergence(ssot)
    check_rollback_governance(ssot)
    check_concurrency_governance(ssot)
    check_cache_propagation(ssot)
    check_synchronization(ssot)

    report = produce_governance_report(ssot)

    print("\n" + "=" * 72)
    print(f"GOVERNANCE GATE SUMMARY")
    print(f"  PASS      : {PASS_COUNT}")
    print(f"  WARN      : {WARN_COUNT}")
    print(f"  HARD_FAIL : {HARD_FAIL_COUNT}")
    print(f"  STATE     : {report['governance_state']}")
    print("=" * 72)

    if HARD_FAIL_COUNT > 0:
        print(f"\n[BLOCKED] {HARD_FAIL_COUNT} hard-fail governance gate(s) triggered.")
        print("          Deployment is BLOCKED until all HARD_FAIL checks pass.")
        return 1

    if WARN_COUNT > 3:
        print(f"\n[DEGRADED] {WARN_COUNT} warnings — release proceeds but investigate.")
    else:
        print("\n[CLEAN] All governance gates passed. Release is production-safe.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
