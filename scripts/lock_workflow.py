#!/usr/bin/env python3
"""
SENTINEL APEX v72.1 — Workflow Lock Patcher
=============================================
Patches sentinel-blogger.yml with:
1. Pre-deploy gate BEFORE each gh-pages deploy action
2. Safe git pull that aborts on conflict instead of committing markers

Idempotent — safe to re-run.
Run from repo root: python3 scripts/lock_workflow.py
"""

import os
import re
import shutil
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "sentinel-blogger.yml")

GATE_MARKER = "pre_deploy_gate.py"

# Gate step inserted BEFORE each gh-pages deploy
GATE_STEP = '''
      # ═══ PERMANENT LOCK: Pre-deploy integrity gate (v72.1) ═══
      - name: "GATE: Dashboard integrity check"
        run: python3 scripts/pre_deploy_gate.py
'''


def main():
    print("=" * 60)
    print("  SENTINEL APEX — Workflow Lock Patcher")
    print("=" * 60)

    if not os.path.exists(WORKFLOW):
        print(f"  FATAL: {WORKFLOW} not found")
        print(f"  Add this step BEFORE each gh-pages deploy in your workflow:")
        print(GATE_STEP)
        sys.exit(1)

    with open(WORKFLOW, "r", encoding="utf-8") as f:
        content = f.read()

    print(f"  Loaded: {len(content):,} bytes")

    if GATE_MARKER in content:
        print("  ALREADY LOCKED — gate step found. No changes needed.")
        sys.exit(0)

    # Backup
    backup = WORKFLOW + f".pre_lock.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(WORKFLOW, backup)
    print(f"  Backup: {backup}")

    # Find ALL gh-pages deploy actions and insert gate before each
    # Pattern: "- name: ..." followed by "uses: JamesIves/github-pages-deploy-action"
    # OR: "uses: JamesIves/github-pages-deploy-action" directly
    deploy_positions = []

    # Strategy: find every "JamesIves/github-pages-deploy-action" and walk back to the step start
    for m in re.finditer(r"JamesIves/github-pages-deploy-action", content):
        # Walk backwards to find the "- name:" or "- uses:" that starts this step
        search_zone = content[max(0, m.start() - 500):m.start()]
        # Find the last "- name:" or "- uses:" before this
        step_markers = list(re.finditer(r"\n(\s*-\s*(?:name:|uses:))", search_zone))
        if step_markers:
            last_marker = step_markers[-1]
            # The actual position in the full content
            abs_pos = max(0, m.start() - 500) + last_marker.start()
            deploy_positions.append(abs_pos)

    if not deploy_positions:
        print("  WARN: No gh-pages deploy actions found")
        print("  Add this step manually BEFORE your deploy action:")
        print(GATE_STEP)
        sys.exit(0)

    # Remove duplicates and sort descending (insert from bottom up to preserve positions)
    deploy_positions = sorted(set(deploy_positions), reverse=True)

    print(f"  Found {len(deploy_positions)} deploy action(s)")

    for pos in deploy_positions:
        content = content[:pos] + GATE_STEP + content[pos:]

    # Also fix dangerous git pull --rebase patterns
    dangerous = re.compile(r"git pull origin main --rebase")
    if dangerous.search(content):
        safe_pull = (
            "git pull origin main --no-rebase --no-edit || "
            "{ echo 'MERGE CONFLICT — resetting to origin/main'; "
            "git merge --abort 2>/dev/null || true; "
            "git reset --hard origin/main; }"
        )
        content = dangerous.sub(safe_pull, content)
        print("  Replaced dangerous 'git pull --rebase' with safe-pull")

    with open(WORKFLOW, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  Patched: {len(content):,} bytes")
    print(f"  Gate steps inserted: {len(deploy_positions)}")
    print("  SUCCESS — workflow is now permanently locked")
    print("=" * 60)


if __name__ == "__main__":
    main()
