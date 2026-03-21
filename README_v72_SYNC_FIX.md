# SENTINEL APEX v72.0 — PERMANENT DASHBOARD SYNC FIX

## Problem
The "Last Sync" metric card on the dashboard keeps showing stale times (e.g. "21h ago") 
even though the pipeline runs successfully and intel cards show fresh data ("1h ago").

## Root Cause (Dual Bug)

### Bug A — Frontend (index.html)
`fetchPipelineSyncTime()` fetches `data/sync_marker.json` and **blindly overwrites** 
the correct manifest-derived timestamp that `computeMetrics()` already set.

**Execution flow:**
1. `computeMetrics()` → sets "Last Sync" = "1h ago" (from EMBEDDED_INTEL) ✅
2. `fetchPipelineSyncTime()` → fetches stale `sync_marker.json` → overwrites to "21h ago" ❌

### Bug B — Backend (sentinel-blogger.yml)
The pipeline workflow **never updates** `data/sync_marker.json` after a successful run.
The file stays at whatever timestamp it was last manually set.

## Fix (3 Files)

| File | What It Does |
|------|-------------|
| `scripts/patch_sync_display.py` | Patches `index.html`: adds a freshest-wins guard — `fetchPipelineSyncTime()` only overrides if sync source is NEWER than manifest data |
| `scripts/update_sync_marker.sh` | Updates `sync_marker.json` with current UTC timestamp (called by workflow) |
| `scripts/patch_workflow_sync.py` | Patches `sentinel-blogger.yml`: adds a post-commit step that calls `update_sync_marker.sh` |

## Apply

### Option A — Automated (recommended)
```bash
# From repo root:
bash scripts/apply_v72_fix.sh
git add -A
git commit -m "v72.0: Permanent dashboard sync fix"
git push origin main
```

### Option B — Manual
```bash
# 1. Frontend fix
python3 scripts/patch_sync_display.py

# 2. Backend fix — add this step to sentinel-blogger.yml AFTER your main commit+push:
#    - name: "Update sync_marker.json (v72.0)"
#      if: success()
#      continue-on-error: true
#      run: |
#        bash scripts/update_sync_marker.sh
#        git add data/sync_marker.json data/status/status.json
#        git diff --staged --quiet || git commit -m "v72.0: sync_marker update [skip ci]"
#        git pull origin main --rebase && git push origin main || true

# 3. Immediately fix stale marker
bash scripts/update_sync_marker.sh
git add -A && git commit -m "v72.0 fix" && git push origin main
```

## Why v71 Didn't Fix This

The v71 ZIP addressed:
- ✅ Removed duplicate gh-pages deployers from `sync-dashboard.yml` and `status-monitor.yml`
- ✅ Added `concurrency: sentinel-data-writer` locks
- ✅ Improved data_bridge.py with CVE enrichment

But v71 **did not** address:
- ❌ The `fetchPipelineSyncTime()` blind overwrite in `index.html`
- ❌ The missing `sync_marker.json` update in the pipeline workflow

Both of those are required to fix the stale "Last Sync" display.

## Zero-Regression Guarantees

- All patches are idempotent (safe to re-run)
- `patch_sync_display.py` creates a backup of `index.html` before modifying
- The freshest-wins guard preserves correct behavior when `sync_marker.json` IS fresh
- `continue-on-error: true` on the workflow step prevents pipeline breakage
- No existing modules modified — all new files in `scripts/`
