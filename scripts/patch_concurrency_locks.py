#!/usr/bin/env python3
"""
SENTINEL APEX v71.0 — Concurrency Lock Patcher
================================================
Adds 'concurrency: sentinel-data-writer' to all workflows
that write to data/ and currently have NO concurrency lock.

Run from repo root:
    python3 scripts/patch_concurrency_locks.py

Safe to re-run — skips workflows that already have a concurrency block.
"""

import os
import re
import sys

WORKFLOWS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".github", "workflows")

LOCK_BLOCK = """
concurrency:
  group: sentinel-data-writer
  cancel-in-progress: false

"""

# These already have correct locks or are the master pipeline
SKIP_WORKFLOWS = {
    "sentinel-blogger.yml",     # Master pipeline — has its own lock
    "sync-dashboard.yml",       # Already patched in v71.0
    "status-monitor.yml",       # Already patched in v71.0
}


def needs_lock(content: str) -> bool:
    """Check if workflow has no concurrency block."""
    return "concurrency:" not in content


def add_lock(content: str) -> str:
    """Insert concurrency block after 'permissions:' or after 'on:' block."""
    # Try to insert after permissions block
    match = re.search(r"(permissions:\s*\n(?:\s+\w+:.*\n)*)", content)
    if match:
        insert_pos = match.end()
        return content[:insert_pos] + LOCK_BLOCK + content[insert_pos:]

    # Fallback: insert before 'jobs:'
    match = re.search(r"\njobs:", content)
    if match:
        return content[:match.start()] + "\n" + LOCK_BLOCK.strip() + "\n" + content[match.start():]

    return content


def main():
    if not os.path.isdir(WORKFLOWS_DIR):
        print(f"ERROR: {WORKFLOWS_DIR} not found. Run from repo root.")
        sys.exit(1)

    patched = 0
    skipped = 0

    for fname in sorted(os.listdir(WORKFLOWS_DIR)):
        if not fname.endswith(".yml"):
            continue
        if fname in SKIP_WORKFLOWS:
            print(f"  SKIP (protected): {fname}")
            skipped += 1
            continue

        fpath = os.path.join(WORKFLOWS_DIR, fname)
        with open(fpath, "r", encoding="utf-8") as f:
            content = f.read()

        if not needs_lock(content):
            print(f"  SKIP (has lock): {fname}")
            skipped += 1
            continue

        new_content = add_lock(content)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(new_content)

        print(f"  PATCHED: {fname}")
        patched += 1

    print(f"\nDone: {patched} patched, {skipped} skipped")


if __name__ == "__main__":
    main()
