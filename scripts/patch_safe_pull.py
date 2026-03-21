#!/usr/bin/env python3
"""
SENTINEL APEX v72.1 — Workflow Safe-Pull Patcher
==================================================
Patches ALL workflow .yml files to:

1. Replace dangerous `git pull origin main --rebase` with safe-pull
   that ABORTS on conflict instead of committing markers
2. Add pre_deploy_gate.py check BEFORE any gh-pages deploy step

This is what PREVENTS the conflict marker bug from recurring.

Run from repo root:
    python3 scripts/patch_safe_pull.py
"""

import os
import re
import sys
import shutil
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS_DIR = os.path.join(REPO_ROOT, ".github", "workflows")

# The dangerous pattern: git pull with --rebase that can leave conflict markers
DANGEROUS_PULL_PATTERNS = [
    # Pattern: git pull origin main --rebase && git push origin main
    (
        re.compile(r'git pull origin main --rebase\s*&&\s*git push origin main'),
        'git pull origin main --no-rebase --no-edit || { echo "CONFLICT — resetting to origin"; git merge --abort 2>/dev/null || true; git reset --hard origin/main; } && git push origin main'
    ),
    # Pattern: git pull origin main --rebase
    (
        re.compile(r'git pull origin main --rebase(?!\s*&&)'),
        'git pull origin main --no-rebase --no-edit || { echo "CONFLICT — resetting to origin"; git merge --abort 2>/dev/null || true; git reset --hard origin/main; }'
    ),
    # Pattern: git pull --rebase (without specifying remote)
    (
        re.compile(r'git pull\s+--rebase(?!\s+origin)'),
        'git pull --no-rebase --no-edit || { echo "CONFLICT — resetting"; git merge --abort 2>/dev/null || true; git reset --hard origin/main; }'
    ),
]

# The gate step to insert before gh-pages deploy
GATE_STEP = """
      # ═══ v72.1 CONFLICT GUARD — blocks deploy if index.html is corrupted ═══
      - name: "GATE: Pre-deploy conflict check"
        run: python3 scripts/pre_deploy_gate.py
"""

GATE_MARKER = "pre_deploy_gate.py"


def patch_file(filepath):
    """Patch a single workflow file. Returns (modified, changes_made)."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content
    changes = []

    # 1. Replace dangerous git pull patterns
    for pattern, replacement in DANGEROUS_PULL_PATTERNS:
        if pattern.search(content):
            content = pattern.sub(replacement, content)
            changes.append(f"  Replaced dangerous git pull --rebase")

    # 2. Add gate before gh-pages deploy (if this workflow deploys)
    if 'gh-pages' in content and GATE_MARKER not in content:
        # Find the deploy step
        deploy_match = re.search(
            r'\n(\s*-\s*name:\s*["\']?.*(?:Deploy|deploy|gh-pages))',
            content
        )
        if not deploy_match:
            # Look for peaceiris action
            deploy_match = re.search(r'\n(\s*-\s*(?:name:.*\n\s*)?uses:\s*peaceiris)', content)

        if deploy_match:
            insert_pos = deploy_match.start()
            content = content[:insert_pos] + GATE_STEP + content[insert_pos:]
            changes.append(f"  Added pre-deploy conflict gate")

    modified = content != original
    return content, modified, changes


def main():
    print("=" * 60)
    print("  SENTINEL APEX v72.1 — Workflow Safe-Pull Patcher")
    print("=" * 60)

    if not os.path.isdir(WORKFLOWS_DIR):
        print(f"  WARN: {WORKFLOWS_DIR} not found")
        sys.exit(0)

    total_patched = 0

    for fname in sorted(os.listdir(WORKFLOWS_DIR)):
        if not fname.endswith('.yml') and not fname.endswith('.yaml'):
            continue

        filepath = os.path.join(WORKFLOWS_DIR, fname)
        new_content, modified, changes = patch_file(filepath)

        if modified:
            # Backup
            backup = filepath + f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.copy2(filepath, backup)

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)

            print(f"\n  PATCHED: {fname}")
            for c in changes:
                print(f"    {c}")
            total_patched += 1
        else:
            print(f"  OK: {fname} (no changes needed)")

    print(f"\n  Done: {total_patched} file(s) patched")
    print("=" * 60)


if __name__ == "__main__":
    main()
