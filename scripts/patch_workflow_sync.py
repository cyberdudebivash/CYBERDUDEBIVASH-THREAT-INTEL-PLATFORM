#!/usr/bin/env python3
"""
SENTINEL APEX v72.0 — Workflow Sync Marker Patcher
====================================================
Patches sentinel-blogger.yml to call scripts/update_sync_marker.sh
AFTER the main commit+push stage, ensuring sync_marker.json stays fresh.

Idempotent — detects if already patched.
Run: python3 scripts/patch_workflow_sync.py
"""

import os
import re
import sys
import shutil
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "sentinel-blogger.yml")

ALREADY_PATCHED_MARKERS = [
    "update_sync_marker.sh",
    "v72.0 Sync Marker",
    "Update sync_marker.json",
]

# The step to insert AFTER the commit+push stage
SYNC_STEP = """
      - name: "STAGE POST-COMMIT: Update sync_marker.json (v72.0)"
        if: success()
        continue-on-error: true
        run: |
          echo "=== v72.0: Updating sync_marker.json ==="
          chmod +x scripts/update_sync_marker.sh 2>/dev/null || true
          bash scripts/update_sync_marker.sh
          
          # Commit sync_marker update
          git add data/sync_marker.json data/status/status.json 2>/dev/null || true
          if ! git diff --staged --quiet; then
            git commit -m "v72.0: sync_marker update @ $(date -u +'%Y-%m-%d %H:%M UTC') [skip ci]"
            git pull origin main --rebase 2>/dev/null || true
            git push origin main || echo "sync_marker push deferred"
          fi
"""


def main():
    print("=" * 60)
    print("SENTINEL APEX v72.0 — Workflow Sync Marker Patcher")
    print("=" * 60)

    if not os.path.exists(WORKFLOW):
        print(f"[PATCH] WARN: {WORKFLOW} not found")
        print("[PATCH] You will need to manually add the sync_marker step to your workflow.")
        print("[PATCH] Add this step AFTER your main git commit+push stage:")
        print(SYNC_STEP)
        sys.exit(0)

    with open(WORKFLOW, "r", encoding="utf-8") as f:
        content = f.read()

    # Check if already patched
    for marker in ALREADY_PATCHED_MARKERS:
        if marker in content:
            print(f"[PATCH] ALREADY PATCHED — '{marker}' found in workflow.")
            sys.exit(0)

    # Backup
    backup = WORKFLOW + f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(WORKFLOW, backup)
    print(f"[PATCH] Backup: {backup}")

    # Find the gh-pages deploy step (or the last git push step)
    # Strategy: Insert before the gh-pages deploy, or after the last "git push" step
    
    # Look for deploy step or last push step
    insert_points = [
        # Before gh-pages deploy
        re.search(r"\n(\s*-\s*name:\s*['\"]?Deploy to GitHub Pages)", content),
        re.search(r"\n(\s*-\s*name:\s*['\"]?(?:STAGE\s*\d+|Stage\s*\d+).*[Dd]eploy)", content),
        # After last git push
    ]
    
    insert_pos = None
    for match in insert_points:
        if match:
            insert_pos = match.start()
            print(f"[PATCH] Inserting before: {match.group(1).strip()[:60]}")
            break
    
    if insert_pos is None:
        # Fallback: find the last "git push" and insert after that step block
        push_matches = list(re.finditer(r"git push\b", content))
        if push_matches:
            last_push = push_matches[-1]
            # Find the next step (starts with "      - name:") or end of job
            next_step = re.search(r"\n(\s*-\s*name:)", content[last_push.end():])
            if next_step:
                insert_pos = last_push.end() + next_step.start()
                print(f"[PATCH] Inserting after last git push, before next step")
            else:
                # Insert at end
                insert_pos = len(content)
                print(f"[PATCH] Inserting at end of workflow")
        else:
            print("[PATCH] ERROR: Cannot find suitable insertion point")
            print("[PATCH] Please manually add this step to sentinel-blogger.yml:")
            print(SYNC_STEP)
            sys.exit(1)
    
    # Insert the sync step
    new_content = content[:insert_pos] + SYNC_STEP + content[insert_pos:]
    
    with open(WORKFLOW, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"[PATCH] sentinel-blogger.yml patched successfully")
    print(f"[PATCH] sync_marker.json will now update on every pipeline run")
    print("=" * 60)


if __name__ == "__main__":
    main()
