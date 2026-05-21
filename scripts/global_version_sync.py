#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX — Global Version Sync Engine
# scripts/global_version_sync.py
#
# PURPOSE:
#   Reads config/platform_version.json (SINGLE SOURCE OF TRUTH) and propagates
#   platform version to all registered sync_targets. Detects and reports drift
#   in index.html PLATFORM_VERSION. Writes telemetry sync report.
#
# GOVERNANCE:
#   - Platform version (152.x.x) — NEVER mix with CI pipeline version (158.x.x)
#   - PLATFORM_VERSION injected into frontend = platform.version ONLY
#   - Pipeline version (ci.pipeline_version) stays in workflow YAML ONLY
#
# USAGE:
#   python3 scripts/global_version_sync.py [--dry-run] [--check-only]
#
# EXIT CODES:
#   0 — Clean sync, no drift errors
#   1 — Hard drift detected or sync failure
#   2 — SSOT file missing or invalid
#
# =============================================================================

import argparse
import json
import os
import re
import sys
import hashlib
import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSOT_PATH = os.path.join(REPO_ROOT, "config", "platform_version.json")
TELEMETRY_DIR = os.path.join(REPO_ROOT, "data", "telemetry")
SYNC_REPORT_PATH = os.path.join(TELEMETRY_DIR, "sync_report.json")

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

def log_ok(msg):    print(f"{GREEN}[SYNC-OK ]{RESET} {msg}")
def log_warn(msg):  print(f"{YELLOW}[SYNC-WARN]{RESET} {msg}")
def log_fail(msg):  print(f"{RED}[SYNC-FAIL]{RESET} {msg}")
def log_info(msg):  print(f"{CYAN}[SYNC-INFO]{RESET} {msg}")
def log_dry(msg):   print(f"{BOLD}[DRY-RUN  ]{RESET} {msg}")


# =============================================================================
# LOAD SSOT
# =============================================================================

def load_ssot() -> dict:
    if not os.path.isfile(SSOT_PATH):
        log_fail(f"SSOT NOT FOUND: {SSOT_PATH}")
        log_fail("Run: git checkout config/platform_version.json")
        sys.exit(2)
    try:
        with open(SSOT_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data
    except json.JSONDecodeError as exc:
        log_fail(f"SSOT JSON INVALID: {exc}")
        sys.exit(2)


# =============================================================================
# SYNC TARGET: VERSION (plain text)
# =============================================================================

def sync_version_file(platform_ver: str, dry_run: bool) -> dict:
    target = os.path.join(REPO_ROOT, "VERSION")
    current = None
    if os.path.isfile(target):
        with open(target, "r", encoding="utf-8") as fh:
            current = fh.read().strip()
    drift = current != platform_ver
    result = {
        "target": "VERSION",
        "expected": platform_ver,
        "found": current,
        "drift": drift,
        "action": "skipped"
    }
    if drift:
        log_warn(f"VERSION drift: found='{current}' expected='{platform_ver}'")
        if not dry_run:
            with open(target, "w", encoding="utf-8") as fh:
                fh.write(platform_ver + "\n")
            log_ok(f"VERSION updated → {platform_ver}")
            result["action"] = "updated"
        else:
            log_dry(f"Would update VERSION: '{current}' → '{platform_ver}'")
            result["action"] = "would_update"
    else:
        log_ok(f"VERSION clean: {platform_ver}")
        result["action"] = "clean"
    return result


# =============================================================================
# SYNC TARGET: version.json (root)
# =============================================================================

def sync_root_version_json(ssot: dict, dry_run: bool) -> dict:
    target = os.path.join(REPO_ROOT, "version.json")
    platform = ssot.get("platform", {})
    ci = ssot.get("ci", {})
    endpoints = ssot.get("endpoints", {})

    expected = {
        "version": platform.get("version"),
        "label": platform.get("label"),
        "full": platform.get("full"),
        "codename": platform.get("codename"),
        "release_date": platform.get("release_date"),
        "release_type": platform.get("release_type"),
        "display": platform.get("display"),
        "pipeline_version": ci.get("pipeline_version"),
        "schema_version": platform.get("schema_version"),
        "copyright": platform.get("copyright"),
        "platform_url": endpoints.get("platform", "https://intel.cyberdudebivash.com"),
        "_generated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_generated_by": "global_version_sync.py"
    }

    current = None
    drift = False
    if os.path.isfile(target):
        try:
            with open(target, "r", encoding="utf-8") as fh:
                current = json.load(fh)
            # Check key fields for drift (ignore _generated timestamp)
            for key in ["version", "label", "full", "codename", "pipeline_version"]:
                if current.get(key) != expected.get(key):
                    drift = True
                    break
        except Exception:
            drift = True
    else:
        drift = True

    result = {
        "target": "version.json",
        "expected_version": expected["version"],
        "found_version": current.get("version") if current else None,
        "drift": drift,
        "action": "skipped"
    }

    if drift:
        log_warn(f"version.json (root) drift detected")
        if not dry_run:
            with open(target, "w", encoding="utf-8") as fh:
                json.dump(expected, fh, indent=2)
            log_ok(f"version.json (root) updated → {expected['version']}")
            result["action"] = "updated"
        else:
            log_dry(f"Would update version.json (root) → {expected['version']}")
            result["action"] = "would_update"
    else:
        log_ok(f"version.json (root) clean: {expected['version']}")
        result["action"] = "clean"
    return result


# =============================================================================
# SYNC TARGET: config/version.json
# =============================================================================

def sync_config_version_json(ssot: dict, dry_run: bool) -> dict:
    target = os.path.join(REPO_ROOT, "config", "version.json")
    platform = ssot.get("platform", {})
    ci = ssot.get("ci", {})

    expected = {
        "version": platform.get("version"),
        "label": platform.get("label"),
        "full": platform.get("full"),
        "codename": platform.get("codename"),
        "release_date": platform.get("release_date"),
        "release_type": platform.get("release_type"),
        "display": platform.get("display"),
        "pipeline_version": ci.get("pipeline_version"),
        "schema_version": platform.get("schema_version"),
        "copyright": platform.get("copyright"),
        "_note": "Synced from config/platform_version.json — DO NOT EDIT DIRECTLY",
        "_generated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_generated_by": "global_version_sync.py"
    }

    current = None
    drift = False
    if os.path.isfile(target):
        try:
            with open(target, "r", encoding="utf-8") as fh:
                current = json.load(fh)
            for key in ["version", "label", "full", "pipeline_version"]:
                if current.get(key) != expected.get(key):
                    drift = True
                    break
        except Exception:
            drift = True
    else:
        drift = True

    result = {
        "target": "config/version.json",
        "expected_version": expected["version"],
        "found_version": current.get("version") if current else None,
        "drift": drift,
        "action": "skipped"
    }

    if drift:
        log_warn(f"config/version.json drift detected")
        if not dry_run:
            with open(target, "w", encoding="utf-8") as fh:
                json.dump(expected, fh, indent=2)
            log_ok(f"config/version.json updated → {expected['version']}")
            result["action"] = "updated"
        else:
            log_dry(f"Would update config/version.json → {expected['version']}")
            result["action"] = "would_update"
    else:
        log_ok(f"config/version.json clean: {expected['version']}")
        result["action"] = "clean"
    return result


# =============================================================================
# SYNC TARGET: api/ai/health.json
# =============================================================================

def sync_api_health_json(ssot: dict, dry_run: bool) -> dict:
    target = os.path.join(REPO_ROOT, "api", "ai", "health.json")
    platform = ssot.get("platform", {})
    ci = ssot.get("ci", {})
    tiers = ssot.get("tiers", {})

    expected = {
        "status": "operational",
        "platform": platform.get("full"),
        "version": platform.get("version"),
        "label": platform.get("label"),
        "codename": platform.get("codename"),
        "release_date": platform.get("release_date"),
        "pipeline_version": ci.get("pipeline_version"),
        "tiers_available": list(tiers.keys()),
        "endpoints": {
            "platform": "https://intel.cyberdudebivash.com",
            "api": "https://intel.cyberdudebivash.com/api",
            "feed": "https://intel.cyberdudebivash.com/api/feed.json",
            "health": "https://intel.cyberdudebivash.com/api/health"
        },
        "_generated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "_generated_by": "global_version_sync.py"
    }

    current = None
    drift = False

    # Ensure directory exists
    os.makedirs(os.path.dirname(target), exist_ok=True)

    if os.path.isfile(target):
        try:
            with open(target, "r", encoding="utf-8") as fh:
                current = json.load(fh)
            for key in ["version", "platform", "pipeline_version"]:
                if current.get(key) != expected.get(key):
                    drift = True
                    break
        except Exception:
            drift = True
    else:
        drift = True

    result = {
        "target": "api/ai/health.json",
        "expected_version": expected["version"],
        "found_version": current.get("version") if current else None,
        "drift": drift,
        "action": "skipped"
    }

    if drift:
        log_warn(f"api/ai/health.json drift detected")
        if not dry_run:
            with open(target, "w", encoding="utf-8") as fh:
                json.dump(expected, fh, indent=2)
            log_ok(f"api/ai/health.json updated → {expected['version']}")
            result["action"] = "updated"
        else:
            log_dry(f"Would update api/ai/health.json → {expected['version']}")
            result["action"] = "would_update"
    else:
        log_ok(f"api/ai/health.json clean: {expected['version']}")
        result["action"] = "clean"
    return result


# =============================================================================
# DRIFT DETECTOR: index.html PLATFORM_VERSION
# =============================================================================

def check_index_html_drift(ssot: dict) -> dict:
    """
    Detect if index.html PLATFORM_VERSION constant contains the pipeline version
    instead of the platform version. REPORTS ONLY — does not auto-patch index.html
    because that file requires careful targeted surgery.
    """
    platform_ver = ssot["platform"]["version"]
    pipeline_ver = ssot["ci"]["pipeline_version"]

    index_path = os.path.join(REPO_ROOT, "index.html")
    result = {
        "target": "index.html (PLATFORM_VERSION drift check)",
        "expected": platform_ver,
        "found": None,
        "drift": False,
        "pipeline_version_injected": False,
        "action": "report_only"
    }

    if not os.path.isfile(index_path):
        log_warn("index.html not found — skipping drift check")
        result["found"] = "FILE_NOT_FOUND"
        return result

    with open(index_path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()

    # Primary check: const/let/var PLATFORM_VERSION = '...'
    m = re.search(r"(?:const|let|var)\s+PLATFORM_VERSION\s*=\s*['\"]([^'\"]+)['\"]", content)
    if m:
        found_ver = m.group(1)
        result["found"] = found_ver
        if found_ver != platform_ver:
            result["drift"] = True
            if found_ver == pipeline_ver:
                result["pipeline_version_injected"] = True
                log_fail(
                    f"index.html PLATFORM_VERSION DRIFT DETECTED: "
                    f"found='{found_ver}' (PIPELINE VERSION!) expected='{platform_ver}' (PLATFORM VERSION)"
                )
                log_fail("ACTION REQUIRED: Patch index.html — set PLATFORM_VERSION = '152.0.0'")
                log_fail("CAUSE: Pipeline version was incorrectly injected into PLATFORM_VERSION field.")
            else:
                log_warn(
                    f"index.html PLATFORM_VERSION mismatch: "
                    f"found='{found_ver}' expected='{platform_ver}'"
                )
        else:
            log_ok(f"index.html PLATFORM_VERSION clean: {found_ver}")
    else:
        result["drift"] = True
        result["found"] = "NOT_FOUND"
        log_warn("index.html: PLATFORM_VERSION declaration not found")

    # Secondary check: footer-version-copy span text
    m2 = re.search(r'id=["\']footer-version-copy["\'][^>]*>([^<]+)<', content)
    if m2:
        footer_text = m2.group(1).strip()
        result["footer_text_found"] = footer_text
        if platform_ver not in footer_text and pipeline_ver in footer_text:
            log_warn(f"index.html footer-version-copy also contains pipeline version: '{footer_text}'")
            result["footer_drift"] = True
        else:
            log_ok(f"index.html footer-version-copy: '{footer_text}'")

    return result


# =============================================================================
# SYNC TARGET: data/telemetry/sync_report.json
# =============================================================================

def write_sync_report(ssot: dict, sync_results: list, check_only: bool, dry_run: bool) -> None:
    os.makedirs(TELEMETRY_DIR, exist_ok=True)
    platform = ssot.get("platform", {})
    ci = ssot.get("ci", {})

    drift_count = sum(1 for r in sync_results if r.get("drift"))
    hard_fail = any(
        r.get("drift") and r.get("pipeline_version_injected")
        for r in sync_results
    )

    report = {
        "_schema": "sentinel-apex-sync-report-v1",
        "generated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generated_by": "global_version_sync.py",
        "platform_version": platform.get("version"),
        "pipeline_version": ci.get("pipeline_version"),
        "ssot": "config/platform_version.json",
        "mode": "dry_run" if dry_run else ("check_only" if check_only else "sync"),
        "drift_detected": drift_count > 0,
        "drift_count": drift_count,
        "hard_fail": hard_fail,
        "sync_results": sync_results,
        "overall_status": "CLEAN" if drift_count == 0 else ("HARD_FAIL" if hard_fail else "DRIFT_CORRECTED")
    }

    if not dry_run:
        with open(SYNC_REPORT_PATH, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        log_ok(f"Sync report written → {SYNC_REPORT_PATH}")
    else:
        log_dry(f"Would write sync report → {SYNC_REPORT_PATH}")


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Global Version Sync Engine — propagates platform_version.json to all targets"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing any files"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Check for drift and report; exit 1 if any drift found (for CI gate use)"
    )
    args = parser.parse_args()

    dry_run = args.dry_run
    check_only = args.check_only

    print()
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}  SENTINEL APEX — Global Version Sync Engine{RESET}")
    print(f"{BOLD}{CYAN}  SSOT: config/platform_version.json{RESET}")
    if dry_run:
        print(f"{BOLD}{YELLOW}  MODE: DRY-RUN (no files will be written){RESET}")
    elif check_only:
        print(f"{BOLD}{YELLOW}  MODE: CHECK-ONLY (drift detection, CI gate){RESET}")
    else:
        print(f"{BOLD}{GREEN}  MODE: SYNC (drift will be corrected){RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print()

    # Load SSOT
    ssot = load_ssot()
    platform_ver = ssot["platform"]["version"]
    pipeline_ver = ssot["ci"]["pipeline_version"]
    log_info(f"SSOT loaded: platform={platform_ver}  pipeline={pipeline_ver}")
    print()

    sync_results = []

    # --- Sync VERSION file ---
    log_info("Syncing: VERSION")
    r = sync_version_file(platform_ver, dry_run=(dry_run or check_only))
    sync_results.append(r)
    print()

    # --- Sync version.json (root) ---
    log_info("Syncing: version.json (root)")
    r = sync_root_version_json(ssot, dry_run=(dry_run or check_only))
    sync_results.append(r)
    print()

    # --- Sync config/version.json ---
    log_info("Syncing: config/version.json")
    r = sync_config_version_json(ssot, dry_run=(dry_run or check_only))
    sync_results.append(r)
    print()

    # --- Sync api/ai/health.json ---
    log_info("Syncing: api/ai/health.json")
    r = sync_api_health_json(ssot, dry_run=(dry_run or check_only))
    sync_results.append(r)
    print()

    # --- Drift check: index.html PLATFORM_VERSION ---
    log_info("Checking: index.html PLATFORM_VERSION drift")
    r = check_index_html_drift(ssot)
    sync_results.append(r)
    print()

    # --- Write sync report ---
    write_sync_report(ssot, sync_results, check_only=check_only, dry_run=dry_run)
    print()

    # --- Summary ---
    drift_count = sum(1 for r in sync_results if r.get("drift"))
    hard_fails = [r for r in sync_results if r.get("drift") and r.get("pipeline_version_injected")]
    updates = [r for r in sync_results if r.get("action") in ("updated", "would_update")]

    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}  SYNC SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print(f"  Targets checked : {len(sync_results)}")
    print(f"  Drift detected  : {drift_count}")
    print(f"  Hard fails      : {len(hard_fails)}")
    print(f"  Updates applied : {len(updates)}")
    print()

    if hard_fails:
        print(f"{RED}{BOLD}  STATUS: HARD_FAIL — Manual intervention required{RESET}")
        for r in hard_fails:
            print(f"    {RED}✗ {r['target']}{RESET}")
        print()
        print(f"{RED}  index.html must be patched:{RESET}")
        print(f"  Set: var PLATFORM_VERSION = '{platform_ver}'")
        print(f"  Set: footer-version-copy → 'SENTINEL APEX v{platform_ver}'")
        print()
        return 1
    elif drift_count > 0 and check_only:
        print(f"{YELLOW}{BOLD}  STATUS: DRIFT_DETECTED (check-only mode — no files written){RESET}")
        return 1
    elif drift_count > 0 and dry_run:
        print(f"{YELLOW}{BOLD}  STATUS: DRIFT_DETECTED (dry-run — no files written){RESET}")
        return 0
    elif drift_count > 0:
        print(f"{GREEN}{BOLD}  STATUS: DRIFT_CORRECTED — All targets synchronized{RESET}")
        return 0
    else:
        print(f"{GREEN}{BOLD}  STATUS: CLEAN — All targets at platform version {platform_ver}{RESET}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
":
    sys.exit(main())
":
    sys.exit(main())
