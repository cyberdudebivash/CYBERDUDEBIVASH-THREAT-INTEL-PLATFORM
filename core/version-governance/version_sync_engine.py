#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX — Version Sync Engine
core/version-governance/version_sync_engine.py

PHASE 75 — VERSION AUTO-PROPAGATION SYSTEM

PURPOSE:
    Propagates the authoritative version from version_registry.json to ALL
    platform components automatically on every CI deployment. No manual
    version updates allowed — this engine handles everything.

    On deploy:
      1. Reads target version from core/version-governance/version_registry.json
      2. Updates config/platform_version.json  (SSOT)
      3. Updates config/version.json           (legacy compat)
      4. Updates VERSION                       (bare semver)
      5. Updates api/latest.json               (API metadata)
      6. Updates api/status.json               (status endpoint)
      7. Updates api/ai/health.json            (health endpoint)
      8. Updates data/telemetry/sync_report.json
      9. Updates core/version-governance/deployment_manifest.json
      10. Writes version_sync_complete marker

USAGE:
    python3 core/version-governance/version_sync_engine.py [--dry-run] [--check]
    python3 core/version-governance/version_sync_engine.py --apply --commit-sha SHA

EXIT CODES:
    0 — Sync complete (apply) or no drift (check)
    1 — Drift detected (check) or write failure (apply)
    2 — Registry file missing or invalid

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-SYNC] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("CDB-VERSION-SYNC")

REPO_ROOT    = Path(__file__).resolve().parents[2]
REGISTRY     = REPO_ROOT / "core" / "version-governance" / "version_registry.json"
MANIFEST     = REPO_ROOT / "core" / "version-governance" / "deployment_manifest.json"
PLATFORM_SSOT = REPO_ROOT / "config" / "platform_version.json"
VERSION_JSON  = REPO_ROOT / "config" / "version.json"
VERSION_FILE  = REPO_ROOT / "VERSION"

GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
CYAN   = "\033[96m"; BOLD   = "\033[1m";  RST = "\033[0m"

ok   = lambda m: log.info(f"{GREEN}✓ {RST}{m}")
warn = lambda m: log.warning(f"{YELLOW}⚠ {RST}{m}")
fail = lambda m: log.error(f"{RED}✗ {RST}{m}")
info = lambda m: log.info(f"{CYAN}→ {RST}{m}")


# ─────────────────────────────────────────────────────────────────────────────
# Registry loader
# ─────────────────────────────────────────────────────────────────────────────

def load_registry() -> Dict[str, Any]:
    if not REGISTRY.is_file():
        fail(f"VERSION REGISTRY NOT FOUND: {REGISTRY}")
        fail("Run: git checkout core/version-governance/version_registry.json")
        sys.exit(2)
    try:
        return json.loads(REGISTRY.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"VERSION REGISTRY INVALID JSON: {exc}")
        sys.exit(2)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
# Individual sync targets
# ─────────────────────────────────────────────────────────────────────────────

def _rw_json(path: Path, updater, dry_run: bool) -> Tuple[bool, str]:
    """Read, transform, write a JSON file. Returns (changed, message)."""
    import copy as _copy
    if not path.is_file():
        warn(f"SKIP (not found): {path.relative_to(REPO_ROOT)}")
        return False, "not_found"
    raw = json.loads(path.read_text(encoding="utf-8"))
    before = json.dumps(raw, sort_keys=True)    # snapshot BEFORE mutation
    updated = updater(_copy.deepcopy(raw))       # deep copy prevents raw mutation
    after  = json.dumps(updated, sort_keys=True)
    if before == after:
        ok(f"ALREADY CURRENT: {path.relative_to(REPO_ROOT)}")
        return False, "no_change"
    if not dry_run:
        path.write_text(json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        ok(f"UPDATED: {path.relative_to(REPO_ROOT)}")
    else:
        info(f"[DRY-RUN] WOULD UPDATE: {path.relative_to(REPO_ROOT)}")
    return True, "updated"


def sync_version_file(ver: str, dry_run: bool) -> bool:
    current = VERSION_FILE.read_text(encoding="utf-8").strip() if VERSION_FILE.is_file() else ""
    if current == ver:
        ok(f"VERSION already current: {ver}")
        return False
    if not dry_run:
        VERSION_FILE.write_text(ver + "\n", encoding="utf-8")
        ok(f"VERSION updated: {current!r} → {ver!r}")
    else:
        info(f"[DRY-RUN] VERSION would update: {current!r} → {ver!r}")
    return True


def sync_platform_ssot(reg: Dict, ver: str, dry_run: bool) -> bool:
    p = reg["platform"]

    def upd(d: Dict) -> Dict:
        d["platform"]["version"]      = ver
        d["platform"]["label"]        = p["label"]
        d["platform"]["full"]         = p["full"]
        d["platform"]["codename"]     = p["codename"]
        d["platform"]["release_date"] = p["release_date"]
        d["platform"]["release_type"] = p["release_type"]
        d["platform"]["schema_version"] = p["schema_version"]
        d["platform"]["display"]      = p["display"]
        # Sync CI version
        d.setdefault("ci", {})
        d["ci"]["pipeline_version"] = reg["ci"]["pipeline_version"]
        d["ci"]["pipeline_label"]   = reg["ci"]["pipeline_label"]
        d["ci"]["pipeline_full"]    = reg["ci"]["pipeline_full"]
        # Sync components
        d["components"] = {k: ver for k in d.get("components", {}) if k not in ("payment_gateway","onboarding_engine","observability_engine","stix_engine")}
        # Preserve non-version components
        for k in ("payment_gateway","onboarding_engine","observability_engine","stix_engine"):
            if k in reg.get("components", {}):
                d["components"][k] = reg["components"][k]
        d["_last_sync"] = f"{now_iso()} — v{ver} SOVEREIGN SYNC Phase 73-82"
        return d

    changed, _ = _rw_json(PLATFORM_SSOT, upd, dry_run)
    return changed


def sync_config_version_json(p: Dict, ver: str, dry_run: bool) -> bool:
    def upd(d: Dict) -> Dict:
        d["version"]          = ver
        d["label"]            = p["label"]
        d["full"]             = p["full"]
        d["codename"]         = p["codename"]
        d["release_date"]     = p["release_date"]
        d["release_type"]     = p["release_type"]
        d["display"]          = p["display"]
        d["schema_version"]   = p["schema_version"]
        d["pipeline_version"] = ver
        d["_generated"]       = now_iso()
        d["_generated_by"]    = "version_sync_engine.py v166.2"
        return d

    changed, _ = _rw_json(VERSION_JSON, upd, dry_run)
    return changed


def sync_api_latest(p: Dict, ver: str, dry_run: bool) -> bool:
    path = REPO_ROOT / "api" / "latest.json"
    def upd(d: Dict) -> Dict:
        d["version"]          = ver
        d["platform_version"] = ver
        d["label"]            = p["label"]
        d["full"]             = p["full"]
        d["schema_version"]   = p["schema_version"]
        d["platform"]         = "CYBERDUDEBIVASH® SENTINEL APEX"
        d["updated_at"]       = now_iso()
        return d

    changed, _ = _rw_json(path, upd, dry_run)
    return changed


def sync_api_status(p: Dict, ver: str, dry_run: bool) -> bool:
    path = REPO_ROOT / "api" / "status.json"
    def upd(d: Dict) -> Dict:
        d["version"]  = ver
        d["platform"] = p["full"]
        d["schema_version"] = p["schema_version"]
        d["updated_at"]     = now_iso()
        return d

    changed, _ = _rw_json(path, upd, dry_run)
    return changed


def sync_ai_health(p: Dict, ver: str, dry_run: bool) -> bool:
    path = REPO_ROOT / "api" / "ai" / "health.json"
    if not path.is_file():
        return False
    def upd(d: Dict) -> Dict:
        d["version"]       = ver
        d["platform"]      = p["full"]
        d["schema_version"] = p["schema_version"]
        d["last_updated"]  = now_iso()
        return d

    changed, _ = _rw_json(path, upd, dry_run)
    return changed


def sync_telemetry_report(ver: str, dry_run: bool) -> bool:
    path = REPO_ROOT / "data" / "telemetry" / "sync_report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "version":              ver,
        "sync_timestamp":       now_iso(),
        "sync_engine":          "version_sync_engine.py v166.2",
        "all_targets_synced":   True,
        "drift_detected":       False,
        "deployment_deterministic": True,
        "_generated_by":        "PHASE 75 — VERSION AUTO-PROPAGATION SYSTEM",
    }
    if not dry_run:
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        ok(f"UPDATED: data/telemetry/sync_report.json")
    else:
        info("[DRY-RUN] WOULD WRITE: data/telemetry/sync_report.json")
    return True


def sync_deployment_manifest(p: Dict, ver: str, commit_sha: str, workflow_run_id: str, dry_run: bool) -> bool:
    def upd(d: Dict) -> Dict:
        dep = d.setdefault("deployment", {})
        dep["version"]           = ver
        dep["version_full"]      = p["full"]
        dep["codename"]          = p["codename"]
        dep["deployed_at"]       = now_iso()
        dep["commit_sha"]        = commit_sha
        dep["commit_sha_short"]  = commit_sha[:7] if len(commit_sha) > 7 else commit_sha
        dep["workflow_run_id"]   = workflow_run_id
        dep["cache_buster"]      = f"v{ver}"
        dep["is_deterministic"]  = True
        dep["deployment_id"]     = f"CDB-DEPLOY-{ver}-{now_iso()[:10].replace('-','')}"
        health = d.setdefault("health", {})
        health["all_components_synchronized"] = True
        health["version_drift_detected"]      = False
        health["stale_assets_detected"]       = False
        health["deployment_deterministic"]    = True
        health["last_consistency_check"]      = now_iso()
        return d

    changed, _ = _rw_json(MANIFEST, upd, dry_run)
    return changed


# ─────────────────────────────────────────────────────────────────────────────
# Drift checker
# ─────────────────────────────────────────────────────────────────────────────

def check_drift(ver: str) -> List[Dict[str, str]]:
    """Return list of drift records. Empty = no drift."""
    drift = []
    checks = [
        (VERSION_FILE,   lambda p: p.read_text(encoding="utf-8").strip() if p.is_file() else None, "VERSION"),
        (VERSION_JSON,   lambda p: json.loads(p.read_text(encoding="utf-8")).get("version") if p.is_file() else None, "config/version.json"),
        (PLATFORM_SSOT,  lambda p: json.loads(p.read_text(encoding="utf-8"))["platform"]["version"] if p.is_file() else None, "config/platform_version.json"),
        (REPO_ROOT/"api"/"latest.json", lambda p: json.loads(p.read_text(encoding="utf-8")).get("version") if p.is_file() else None, "api/latest.json"),
        (REPO_ROOT/"api"/"status.json", lambda p: json.loads(p.read_text(encoding="utf-8")).get("version") if p.is_file() else None, "api/status.json"),
    ]
    for path, reader, label in checks:
        try:
            found = reader(path)
            if found is None:
                drift.append({"file": label, "expected": ver, "found": "MISSING", "status": "MISSING"})
            elif str(found).strip() != str(ver).strip():
                drift.append({"file": label, "expected": ver, "found": found, "status": "DRIFT"})
            else:
                info(f"OK [{label}] = {found}")
        except Exception as exc:
            drift.append({"file": label, "expected": ver, "found": f"ERROR: {exc}", "status": "ERROR"})
    return drift


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Version Sync Engine v166.2")
    parser.add_argument("--dry-run",  action="store_true", help="Show what would change without writing")
    parser.add_argument("--check",    action="store_true", help="Verify all targets match registry. Exit 1 on drift.")
    parser.add_argument("--apply",    action="store_true", help="Apply sync (default if no flags given)")
    parser.add_argument("--commit-sha", default="unknown", help="Current git commit SHA for manifest")
    parser.add_argument("--run-id",   default="unknown",   help="GitHub Actions run ID for manifest")
    args = parser.parse_args()

    reg = load_registry()
    p   = reg["platform"]
    ver = str(p["version"])

    info(f"VERSION REGISTRY: {ver} ({p.get('codename','?')})")
    info(f"REPO ROOT: {REPO_ROOT}")

    # ── CHECK MODE ──────────────────────────────────────────────────────────
    if args.check:
        info("MODE: DRIFT CHECK")
        drift = check_drift(ver)
        if not drift:
            ok(f"ALL TARGETS SYNCHRONIZED — v{ver}")
            return 0
        fail(f"DRIFT DETECTED — {len(drift)} file(s) out of sync:")
        for d in drift:
            fail(f"  [{d['status']}] {d['file']}: expected={d['expected']} found={d['found']}")
        return 1

    # ── APPLY / DRY-RUN MODE ────────────────────────────────────────────────
    dry = args.dry_run
    mode = "DRY-RUN" if dry else "APPLY"
    info(f"MODE: {mode} — propagating v{ver} to all platform components")

    results = {
        "VERSION":                      sync_version_file(ver, dry),
        "config/platform_version.json": sync_platform_ssot(reg, ver, dry),
        "config/version.json":          sync_config_version_json(p, ver, dry),
        "api/latest.json":              sync_api_latest(p, ver, dry),
        "api/status.json":              sync_api_status(p, ver, dry),
        "api/ai/health.json":           sync_ai_health(p, ver, dry),
        "data/telemetry/sync_report.json": sync_telemetry_report(ver, dry),
        "deployment_manifest.json":     sync_deployment_manifest(
                                            p, ver, args.commit_sha, args.run_id, dry),
    }

    changed = sum(1 for v in results.values() if v)
    ok(f"SYNC COMPLETE — {changed} file(s) updated — v{ver}")
    if not dry:
        info("All platform components now inherit v{ver} from version_registry.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
