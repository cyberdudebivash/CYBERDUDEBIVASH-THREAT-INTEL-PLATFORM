#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Rollback Authority System
=========================================================================
Phase 1: Enterprise Rollback Governance

Provides:
  - Automatic deployment snapshots (pre-deploy state capture)
  - Frontend asset snapshots (checksum-verified)
  - Manifest rollback registry (versioned manifest history)
  - Deployment restore points (full repo-state reference)
  - Worker rollback recovery (previous Worker hash tracking)
  - Rollback validation engine (verify restore integrity)
  - Last-known-good recovery (fastest safe restore path)
  - Rollback audit history (complete governance ledger)

MANDATORY: Any failed deployment triggers auto-rollback to last-known-good.

Usage:
  python3 scripts/rollback_authority.py snapshot       -- capture pre-deploy snapshot
  python3 scripts/rollback_authority.py register       -- register current state as known-good
  python3 scripts/rollback_authority.py rollback        -- restore last-known-good
  python3 scripts/rollback_authority.py validate        -- verify rollback integrity
  python3 scripts/rollback_authority.py history         -- print audit history
  python3 scripts/rollback_authority.py status          -- print current rollback state
"""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Optional

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ROLLBACK_DIR = REPO_ROOT / "data" / "rollback"
ROLLBACK_DIR.mkdir(parents=True, exist_ok=True)

REGISTRY_PATH = ROLLBACK_DIR / "rollback_registry.json"
HISTORY_PATH  = ROLLBACK_DIR / "rollback_audit_history.json"
LKG_PATH      = ROLLBACK_DIR / "last_known_good.json"

# Frontend assets protected by rollback
PROTECTED_ASSETS = [
    "index.html",
    "dashboard.js",
    "renderer.js",
    "ai_runtime_engine.js",
    "api_adapter.js",
    "styles.css",
    "card_renderer.js",
]

# Manifests tracked by rollback
TRACKED_MANIFESTS = [
    "api/feed.json",
    "api/v1/intel/latest.json",
    "api/v1/intel/top10.json",
    "api/v1/intel/apex.json",
]

# Workflow configs tracked for governance
TRACKED_WORKFLOWS = [
    ".github/workflows/deploy-worker.yml",
    ".github/workflows/master-deployment-orchestrator.yml",
    ".github/workflows/post-deploy-validation.yml",
]

WORKER_BASE = "https://intel.cyberdudebivash.com"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: pathlib.Path) -> Optional[str]:
    """SHA-256 of a file. Returns None if file missing."""
    if not path.exists():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def get_git_head() -> dict:
    """Return current HEAD commit info."""
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
        msg = subprocess.check_output(
            ["git", "log", "-1", "--pretty=%s"], cwd=REPO_ROOT, text=True
        ).strip()
        author = subprocess.check_output(
            ["git", "log", "-1", "--pretty=%an"], cwd=REPO_ROOT, text=True
        ).strip()
        ts = subprocess.check_output(
            ["git", "log", "-1", "--pretty=%aI"], cwd=REPO_ROOT, text=True
        ).strip()
        return {"sha": sha, "message": msg, "author": author, "timestamp": ts}
    except Exception as e:
        return {"sha": "unknown", "message": str(e), "author": "unknown", "timestamp": now_iso()}


def probe_worker_version() -> dict:
    """Probe live Worker for version + health fingerprint."""
    import urllib.request, urllib.error
    try:
        req = urllib.request.Request(
            f"{WORKER_BASE}/api/health",
            headers={"User-Agent": "SENTINEL-APEX-ROLLBACK/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read(4096))
            return {
                "ok": True,
                "version": body.get("version", "unknown"),
                "status": body.get("status", "unknown"),
                "advisories": body.get("advisory_count", 0),
            }
    except Exception as e:
        return {"ok": False, "version": "unknown", "status": "error", "error": str(e)}


def snapshot_assets() -> dict:
    """Capture SHA-256 checksums for all protected frontend assets."""
    assets = {}
    for name in PROTECTED_ASSETS:
        path = REPO_ROOT / name
        assets[name] = {
            "path": str(path.relative_to(REPO_ROOT)),
            "exists": path.exists(),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size if path.exists() else 0,
        }
    return assets


def snapshot_manifests() -> dict:
    """Capture SHA-256 checksums for tracked manifests."""
    manifests = {}
    for rel in TRACKED_MANIFESTS:
        path = REPO_ROOT / rel
        manifests[rel] = {
            "exists": path.exists(),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size if path.exists() else 0,
        }
    return manifests


def snapshot_workflows() -> dict:
    """Capture workflow config checksums."""
    workflows = {}
    for rel in TRACKED_WORKFLOWS:
        path = REPO_ROOT / rel
        workflows[rel] = {
            "exists": path.exists(),
            "sha256": sha256_file(path),
        }
    return workflows


def load_registry() -> dict:
    """Load rollback registry (versioned snapshot history)."""
    if not REGISTRY_PATH.exists():
        return {"snapshots": [], "last_snapshot_id": None, "created_at": now_iso()}
    return json.loads(REGISTRY_PATH.read_text())


def save_registry(reg: dict) -> None:
    reg["updated_at"] = now_iso()
    REGISTRY_PATH.write_text(json.dumps(reg, indent=2))


def load_history() -> list:
    """Load rollback audit history."""
    if not HISTORY_PATH.exists():
        return []
    return json.loads(HISTORY_PATH.read_text()).get("events", [])


def append_history(event: dict) -> None:
    """Append a governance event to the audit history."""
    events = load_history()
    events.append({**event, "recorded_at": now_iso()})
    # Keep last 500 events
    events = events[-500:]
    HISTORY_PATH.write_text(json.dumps({"events": events, "updated_at": now_iso()}, indent=2))


def cmd_snapshot(args) -> int:
    """Capture a full pre-deploy snapshot and register it."""
    print(f"[ROLLBACK] Capturing deployment snapshot...")
    head = get_git_head()
    worker = probe_worker_version()
    assets = snapshot_assets()
    manifests = snapshot_manifests()
    workflows = snapshot_workflows()

    snapshot_id = f"snap-{int(time.time())}-{head['sha'][:8]}"
    snapshot = {
        "id": snapshot_id,
        "captured_at": now_iso(),
        "git": head,
        "worker": worker,
        "assets": assets,
        "manifests": manifests,
        "workflows": workflows,
        "type": getattr(args, "type", "pre-deploy"),
        "label": getattr(args, "label", ""),
    }

    reg = load_registry()
    reg["snapshots"].append(snapshot)
    reg["snapshots"] = reg["snapshots"][-50:]  # Keep last 50
    reg["last_snapshot_id"] = snapshot_id
    save_registry(reg)

    # Also write individual snapshot file
    snap_path = ROLLBACK_DIR / f"{snapshot_id}.json"
    snap_path.write_text(json.dumps(snapshot, indent=2))

    append_history({
        "event": "SNAPSHOT_CAPTURED",
        "snapshot_id": snapshot_id,
        "commit": head["sha"][:12],
        "worker_version": worker.get("version"),
        "type": snapshot.get("type"),
    })

    print(f"[ROLLBACK] Snapshot captured: {snapshot_id}")
    print(f"[ROLLBACK] Commit: {head['sha'][:12]} | Worker: {worker.get('version')}")
    print(f"[ROLLBACK] Assets: {len(assets)} | Manifests: {len(manifests)}")
    return 0


def cmd_register(args) -> int:
    """Register current state as the last-known-good (LKG) baseline."""
    print(f"[ROLLBACK] Registering last-known-good state...")
    head = get_git_head()
    worker = probe_worker_version()
    assets = snapshot_assets()
    manifests = snapshot_manifests()

    lkg = {
        "registered_at": now_iso(),
        "git": head,
        "worker": worker,
        "assets": assets,
        "manifests": manifests,
        "label": getattr(args, "label", "post-deploy-validated"),
    }
    LKG_PATH.write_text(json.dumps(lkg, indent=2))

    append_history({
        "event": "LKG_REGISTERED",
        "commit": head["sha"][:12],
        "worker_version": worker.get("version"),
        "label": lkg["label"],
    })

    print(f"[ROLLBACK] LKG registered at commit {head['sha'][:12]}")
    print(f"[ROLLBACK] Worker: {worker.get('version')} | Advisories: {worker.get('advisories')}")
    return 0


def cmd_rollback(args) -> int:
    """Restore to last-known-good state."""
    print(f"[ROLLBACK] INITIATING ROLLBACK TO LAST-KNOWN-GOOD...")

    if not LKG_PATH.exists():
        print(f"[ROLLBACK] FATAL: No last-known-good state registered. Cannot rollback.")
        return 2

    lkg = json.loads(LKG_PATH.read_text())
    lkg_commit = lkg["git"]["sha"]
    lkg_label  = lkg.get("label", "unknown")

    print(f"[ROLLBACK] Target LKG: commit={lkg_commit[:12]} | label={lkg_label}")
    print(f"[ROLLBACK] LKG registered at: {lkg['registered_at']}")

    reason = getattr(args, "reason", "deployment-failure")
    dry_run = getattr(args, "dry_run", False)

    append_history({
        "event": "ROLLBACK_INITIATED",
        "reason": reason,
        "target_commit": lkg_commit[:12],
        "lkg_label": lkg_label,
        "dry_run": dry_run,
    })

    if dry_run:
        print(f"[ROLLBACK] DRY RUN -- would revert to {lkg_commit[:12]}")
        print(f"[ROLLBACK] Run without --dry-run to execute rollback")
        return 0

    # Attempt git reset to LKG commit
    try:
        current = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
        print(f"[ROLLBACK] Current HEAD: {current[:12]}")
        print(f"[ROLLBACK] Rolling back to: {lkg_commit[:12]}")

        # Create a revert commit (safer than hard reset on shared main)
        result = subprocess.run(
            ["git", "revert", "--no-commit", f"{lkg_commit}..HEAD"],
            cwd=REPO_ROOT, capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"[ROLLBACK] Revert failed: {result.stderr}")
            print(f"[ROLLBACK] Attempting hard reset instead...")
            subprocess.run(
                ["git", "reset", "--hard", lkg_commit],
                cwd=REPO_ROOT, capture_output=True
            )

        append_history({
            "event": "ROLLBACK_COMPLETED",
            "reverted_from": current[:12],
            "restored_to": lkg_commit[:12],
            "reason": reason,
        })
        print(f"[ROLLBACK] ROLLBACK COMPLETE: Restored to {lkg_commit[:12]}")
        return 0
    except Exception as e:
        append_history({
            "event": "ROLLBACK_FAILED",
            "reason": reason,
            "error": str(e),
        })
        print(f"[ROLLBACK] ROLLBACK FAILED: {e}")
        return 1


def cmd_validate(args) -> int:
    """Validate current state against last-known-good."""
    print(f"[ROLLBACK] Validating integrity against last-known-good...")

    if not LKG_PATH.exists():
        print(f"[ROLLBACK] WARNING: No LKG registered -- cannot validate")
        return 0

    lkg = json.loads(LKG_PATH.read_text())
    current_assets = snapshot_assets()
    violations = []

    for name, lkg_info in lkg.get("assets", {}).items():
        cur = current_assets.get(name, {})
        if lkg_info.get("sha256") and cur.get("sha256"):
            if lkg_info["sha256"] != cur["sha256"]:
                violations.append({
                    "asset": name,
                    "type": "CHECKSUM_MISMATCH",
                    "lkg_sha": lkg_info["sha256"][:16],
                    "cur_sha": cur["sha256"][:16],
                })
        elif lkg_info.get("exists") and not cur.get("exists"):
            violations.append({"asset": name, "type": "ASSET_MISSING"})

    if violations:
        print(f"[ROLLBACK] INTEGRITY VIOLATIONS: {len(violations)}")
        for v in violations:
            print(f"  [{v['type']}] {v['asset']}")
        append_history({
            "event": "INTEGRITY_VIOLATIONS_DETECTED",
            "violations": violations,
            "violation_count": len(violations),
        })
        return 1
    else:
        print(f"[ROLLBACK] VALIDATION PASSED: Current state matches LKG")
        print(f"[ROLLBACK] LKG commit: {lkg['git']['sha'][:12]} | registered: {lkg['registered_at']}")
        return 0


def cmd_history(args) -> int:
    """Print rollback audit history."""
    events = load_history()
    print(f"\nROLLBACK AUDIT HISTORY ({len(events)} events)")
    print("=" * 60)
    for e in events[-20:]:
        ts = e.get("recorded_at", "?")[:19]
        ev = e.get("event", "?")
        detail = ""
        if "commit" in e:
            detail += f" commit={e['commit']}"
        if "reason" in e:
            detail += f" reason={e['reason']}"
        if "snapshot_id" in e:
            detail += f" snap={e['snapshot_id']}"
        print(f"  {ts}  {ev:<35}{detail}")
    print("=" * 60)
    return 0


def cmd_status(args) -> int:
    """Print current rollback system status."""
    reg = load_registry()
    print(f"\nROLLBACK AUTHORITY STATUS")
    print("=" * 60)
    snap_count = len(reg.get("snapshots", []))
    last_snap = reg.get("last_snapshot_id", "none")
    print(f"  Snapshots stored:    {snap_count}")
    print(f"  Last snapshot:       {last_snap}")
    if LKG_PATH.exists():
        lkg = json.loads(LKG_PATH.read_text())
        print(f"  LKG registered:      YES")
        print(f"  LKG commit:          {lkg['git']['sha'][:12]}")
        print(f"  LKG label:           {lkg.get('label','?')}")
        print(f"  LKG registered at:   {lkg['registered_at']}")
    else:
        print(f"  LKG registered:      NO -- run 'register' after a clean deploy")
    events = load_history()
    rollbacks = [e for e in events if e.get("event","").startswith("ROLLBACK")]
    print(f"  Rollback events:     {len(rollbacks)}")
    print("=" * 60)
    return 0


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Rollback Authority")
    sub = parser.add_subparsers(dest="cmd")

    p_snap = sub.add_parser("snapshot", help="Capture deployment snapshot")
    p_snap.add_argument("--type", default="pre-deploy")
    p_snap.add_argument("--label", default="")

    p_reg = sub.add_parser("register", help="Register current state as LKG")
    p_reg.add_argument("--label", default="post-deploy-validated")

    p_rb = sub.add_parser("rollback", help="Rollback to last-known-good")
    p_rb.add_argument("--reason", default="deployment-failure")
    p_rb.add_argument("--dry-run", action="store_true")

    sub.add_parser("validate", help="Validate integrity against LKG")
    sub.add_parser("history",  help="Print audit history")
    sub.add_parser("status",   help="Print rollback system status")

    args = parser.parse_args()

    dispatch = {
        "snapshot": cmd_snapshot,
        "register": cmd_register,
        "rollback": cmd_rollback,
        "validate": cmd_validate,
        "history":  cmd_history,
        "status":   cmd_status,
    }

    if args.cmd not in dispatch:
        parser.print_help()
        return 1

    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
