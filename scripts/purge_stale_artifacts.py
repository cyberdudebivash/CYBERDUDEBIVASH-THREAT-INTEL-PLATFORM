#!/usr/bin/env python3
"""
scripts/purge_stale_artifacts.py
CYBERDUDEBIVASH® SENTINEL APEX — Stale Artifact Purge Engine
=============================================================
Version: v158.5
Stage  : Pre-pipeline stale-state elimination

PURPOSE:
  Eliminates stale cached artifacts that cause the pipeline to skip
  regeneration stages and deploy degraded intelligence. This forces
  the next CI run to perform a FULL CLEAN REBUILD from live sources.

WHAT IS PURGED:
  - dist/ directory (stale GitHub Pages artifacts)
  - Stale API feed caches that prevent fresh generation
  - Empty or corrupted manifest files reset to clean state
  - Stale STIX feed_manifest.json reset (bootstrap will repopulate)

WHAT IS PRESERVED (NEVER DELETED):
  - data/feed_manifest.json   (advisory corpus — source of truth)
  - api/feed.json             (primary API feed)
  - data/stix/*.json          (STIX bundles — immutable intelligence)
  - All generated HTML reports in data/reports/

USAGE:
  python3 scripts/purge_stale_artifacts.py              # dry-run (report only)
  python3 scripts/purge_stale_artifacts.py --execute    # execute purge
  python3 scripts/purge_stale_artifacts.py --execute --force-full-sync  # also set FORCE_FULL_SYNC flag

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [purge-engine] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.purge")
REPO_ROOT = Path(__file__).resolve().parent.parent


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


PURGE_TARGETS = [
    # (path, action, description)
    ("dist",                        "rmtree",  "Stale GitHub Pages dist artifacts — force full rebuild"),
    ("data/cache",                  "rmtree",  "Stale intelligence cache — forces fresh fetch"),
    ("data/ai-telemetry/last-run.json", "delete", "Stale AI telemetry — prevents false-skip of AI stages"),
]

RESET_TO_EMPTY_LIST = [
    # These manifests are repopulated by CI bootstrap — safe to reset
    ("data/stix/feed_manifest.json", "Stale STIX manifest — bootstrap will repopulate from fresh bundles"),
]

# Files that MUST NEVER be deleted
PROTECTED_PATHS = {
    "api/feed.json",
    "data/feed_manifest.json",
    "feed_manifest.json",
    "data/stix",           # STIX bundles directory — immutable intelligence
    "data/reports",        # Generated HTML reports
    "scripts",
    "agent",
    ".github",
    "index.html",
}


def is_protected(path: Path) -> bool:
    rel = str(path.relative_to(REPO_ROOT))
    return any(rel == p or rel.startswith(p + "/") for p in PROTECTED_PATHS)


def purge(dry_run: bool = True) -> dict:
    log.info("=" * 70)
    log.info("SENTINEL APEX — Stale Artifact Purge Engine v158.5")
    log.info("Mode: %s", "DRY-RUN (no changes)" if dry_run else "EXECUTE")
    log.info("=" * 70)

    report = {
        "executed_at": _utc_now(),
        "dry_run": dry_run,
        "purged": [],
        "reset": [],
        "skipped": [],
        "protected": [],
        "errors": [],
    }

    # Process deletion targets
    for rel_path, action, description in PURGE_TARGETS:
        p = REPO_ROOT / rel_path
        if is_protected(p):
            msg = f"PROTECTED — skipped: {rel_path}"
            log.warning("  [SKIP] %s", msg)
            report["protected"].append(rel_path)
            continue
        if not p.exists():
            log.info("  [SKIP] Already absent: %s", rel_path)
            report["skipped"].append(rel_path)
            continue
        log.info("  [%s] %s — %s", "DRY" if dry_run else "PURGE", rel_path, description)
        if not dry_run:
            try:
                if action == "rmtree" and p.is_dir():
                    shutil.rmtree(p)
                elif action == "delete" and p.is_file():
                    p.unlink()
                report["purged"].append(rel_path)
                log.info("    → PURGED: %s", rel_path)
            except Exception as e:
                log.error("    → ERROR purging %s: %s", rel_path, e)
                report["errors"].append(f"{rel_path}: {e}")
        else:
            report["purged"].append(f"[would purge] {rel_path}")

    # Reset manifests to empty list (bootstrap will repopulate)
    for rel_path, description in RESET_TO_EMPTY_LIST:
        p = REPO_ROOT / rel_path
        log.info("  [%s] RESET %s — %s", "DRY" if dry_run else "RESET", rel_path, description)
        if not dry_run:
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("[]", encoding="utf-8")
                report["reset"].append(rel_path)
                log.info("    → RESET to []: %s", rel_path)
            except Exception as e:
                log.error("    → ERROR resetting %s: %s", rel_path, e)
                report["errors"].append(f"{rel_path}: {e}")
        else:
            report["reset"].append(f"[would reset] {rel_path}")

    log.info("=" * 70)
    log.info("PURGE SUMMARY: %d purged | %d reset | %d skipped | %d errors",
             len(report["purged"]), len(report["reset"]),
             len(report["skipped"]), len(report["errors"]))
    if dry_run:
        log.info("DRY-RUN complete. Re-run with --execute to apply.")
    else:
        log.info("PURGE COMPLETE. Next CI run will perform FULL CLEAN REBUILD.")

    # Write purge report
    rdir = REPO_ROOT / "data" / "quality"
    rdir.mkdir(parents=True, exist_ok=True)
    rpath = rdir / "purge_report.json"
    try:
        rpath.write_text(json.dumps(report, indent=2), encoding="utf-8")
        log.info("Purge report: %s", rpath)
    except Exception as e:
        log.warning("Could not write purge report: %s", e)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Stale Artifact Purge Engine")
    parser.add_argument("--execute", action="store_true",
                        help="Execute the purge (default: dry-run only)")
    parser.add_argument("--force-full-sync", action="store_true",
                        help="Write FORCE_FULL_SYNC=true to .github/force_full_sync.flag")
    args = parser.parse_args()

    report = purge(dry_run=not args.execute)

    if args.force_full_sync and args.execute:
        flag = REPO_ROOT / ".github" / "force_full_sync.flag"
        flag.write_text(
            f"FORCE_FULL_SYNC=true\ngenerated_at={_utc_now()}\n"
            "reason=purge_stale_artifacts.py --force-full-sync\n",
            encoding="utf-8",
        )
        log.info("FORCE_FULL_SYNC flag written: %s", flag)

    if report["errors"]:
        log.error("%d error(s) during purge — review before CI run", len(report["errors"]))
        sys.exit(1)


if __name__ == "__main__":
    main()
