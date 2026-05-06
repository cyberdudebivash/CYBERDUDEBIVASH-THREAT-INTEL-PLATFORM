#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Frontend Integrity System
=============================================================
Phase 3: Frontend Immutability Governance

Computes SHA-256 checksums for all protected frontend assets and
manages the immutable registry at config/frontend_checksums.json.

Modes:
  --generate  : Compute checksums from current files, write registry (CI: baseline commit only)
  --verify    : Compare current files against registry, fail if any mismatch
  --report    : Print full integrity status without failing

Protected assets (TIER 3 -- deployment authority write-only):
  index.html
  js/api_adapter.js
  js/card_renderer.js
  js/card_renderer_integration.js
  js/sla-monitor.js
  css/card_renderer_styles.css
"""

import argparse
import hashlib
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

PROTECTED_ASSETS = [
    "index.html",
    "js/api_adapter.js",
    "js/card_renderer.js",
    "js/card_renderer_integration.js",
    "js/sla-monitor.js",
    "css/card_renderer_styles.css",
]

REGISTRY_PATH = REPO_ROOT / "config" / "frontend_checksums.json"
SCHEMA_VERSION = "1.0"


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_stats(path: pathlib.Path) -> dict:
    stat = path.stat()
    return {
        "sha256": sha256_file(path),
        "size_bytes": stat.st_size,
        "last_modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    }


def generate_registry() -> dict:
    registry = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "frontend_integrity.py",
        "platform": "CYBERDUDEBIVASH(R) SENTINEL APEX",
        "description": "Immutable checksum registry for protected frontend assets. "
                       "Only TIER-3 deployment authority (sentinel-blogger / deploy-worker) "
                       "may update these files. Any other modification triggers CI hard-fail.",
        "protected_count": len(PROTECTED_ASSETS),
        "assets": {},
    }
    missing = []
    for rel in PROTECTED_ASSETS:
        path = REPO_ROOT / rel
        if path.exists():
            registry["assets"][rel] = file_stats(path)
        else:
            missing.append(rel)
            registry["assets"][rel] = {"sha256": "MISSING", "size_bytes": 0, "last_modified": None}

    if missing:
        print(f"WARNING: {len(missing)} protected file(s) not found: {missing}", file=sys.stderr)

    return registry


def load_registry() -> dict:
    if not REGISTRY_PATH.exists():
        print(f"FATAL: Registry not found at {REGISTRY_PATH}", file=sys.stderr)
        sys.exit(2)
    with open(REGISTRY_PATH, encoding="utf-8") as f:
        return json.load(f)


def verify(strict: bool = True) -> tuple[int, list[str], list[str]]:
    """
    Returns (exit_code, violations, warnings).
    exit_code=0 means all checksums match.
    """
    registry = load_registry()
    violations = []
    warnings = []
    ok_count = 0

    registered_assets = registry.get("assets", {})

    for rel, meta in registered_assets.items():
        path = REPO_ROOT / rel
        if not path.exists():
            violations.append(f"MISSING: {rel} (registered but not found on disk)")
            continue

        if meta.get("sha256") == "MISSING":
            warnings.append(f"SKIP: {rel} was MISSING when registry was generated")
            continue

        current_sha = sha256_file(path)
        registered_sha = meta.get("sha256", "")

        if current_sha != registered_sha:
            current_size = path.stat().st_size
            registered_size = meta.get("size_bytes", 0)
            violations.append(
                f"TAMPERED: {rel}\n"
                f"  registered: {registered_sha[:16]}... ({registered_size} bytes)\n"
                f"  current:    {current_sha[:16]}... ({current_size} bytes)"
            )
        else:
            ok_count += 1
            print(f"  OK: {rel} [{current_sha[:16]}...]")

    # Check for unregistered new files in protected locations
    for rel in PROTECTED_ASSETS:
        if rel not in registered_assets:
            path = REPO_ROOT / rel
            if path.exists():
                warnings.append(f"UNREGISTERED: {rel} exists but not in registry")

    exit_code = 0
    if violations:
        exit_code = 1

    return exit_code, violations, warnings


def print_report(violations: list[str], warnings: list[str], ok_count: int) -> None:
    print()
    print("=" * 60)
    print("SENTINEL APEX -- Frontend Integrity Report")
    print("=" * 60)
    total = len(PROTECTED_ASSETS)
    print(f"Protected assets : {total}")
    print(f"  OK             : {ok_count}")
    print(f"  Violations     : {len(violations)}")
    print(f"  Warnings       : {len(warnings)}")
    print()

    if violations:
        print("VIOLATIONS (DEPLOYMENT BLOCKED):")
        for v in violations:
            print(f"  [FAIL] {v}")
        print()

    if warnings:
        print("WARNINGS:")
        for w in warnings:
            print(f"  [WARN] {w}")
        print()

    if not violations:
        print("RESULT: PASS -- All registered assets are intact")
    else:
        print("RESULT: FAIL -- Frontend integrity compromised")
    print("=" * 60)


def cmd_generate(args):
    print("Generating frontend checksum registry...")
    registry = generate_registry()
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)
    print(f"Registry written: {REGISTRY_PATH}")
    print(f"  Assets registered: {len(registry['assets'])}")
    for rel, meta in registry["assets"].items():
        sha = meta.get("sha256", "MISSING")
        size = meta.get("size_bytes", 0)
        print(f"  {sha[:16]}... {size:>8} bytes  {rel}")
    print("OK: Registry generation complete")


def cmd_verify(args):
    print("Verifying frontend asset integrity...")
    exit_code, violations, warnings = verify(strict=True)
    ok_count = len(PROTECTED_ASSETS) - len(violations) - len(warnings)
    print_report(violations, warnings, ok_count)
    if exit_code != 0:
        print("FATAL: Frontend integrity check FAILED -- deployment blocked", file=sys.stderr)
    sys.exit(exit_code)


def cmd_report(args):
    print("Frontend integrity status report (non-blocking)...")
    exit_code, violations, warnings = verify(strict=False)
    ok_count = len(PROTECTED_ASSETS) - len(violations) - len(warnings)
    print_report(violations, warnings, ok_count)


def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Frontend Integrity System"
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("generate", help="Generate checksum registry from current files")
    sub.add_parser("verify", help="Verify current files against registry (fails on mismatch)")
    sub.add_parser("report", help="Print integrity report without failing")
    args = parser.parse_args()

    if args.command == "generate":
        cmd_generate(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "report":
        cmd_report(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
