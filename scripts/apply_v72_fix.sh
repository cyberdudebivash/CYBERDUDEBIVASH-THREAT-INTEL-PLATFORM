#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# SENTINEL APEX v72.0 — PERMANENT SYNC FIX — Master Apply Script
# ═══════════════════════════════════════════════════════════════════
#
# This script applies ALL fixes for the persistent "Last Sync" stale
# display bug. Run from the repo root:
#
#   bash scripts/apply_v72_fix.sh
#
# What it does:
#   1. Patches index.html → freshest-wins guard in fetchPipelineSyncTime()
#   2. Installs update_sync_marker.sh → keeps sync_marker.json fresh
#   3. Patches sentinel-blogger.yml → calls update_sync_marker.sh post-commit
#
# All patches are idempotent — safe to re-run.
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "═══════════════════════════════════════════════════════════"
echo " SENTINEL APEX v72.0 — PERMANENT SYNC FIX"
echo " Repo: ${REPO_ROOT}"
echo "═══════════════════════════════════════════════════════════"
echo ""

ERRORS=0

# ─── Step 1: Patch index.html (frontend fix) ───
echo ">>> STEP 1/3: Patching index.html (fetchPipelineSyncTime guard)"
if python3 "${SCRIPT_DIR}/patch_sync_display.py"; then
    echo "    ✓ index.html patch complete"
else
    echo "    ✗ index.html patch FAILED"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ─── Step 2: Ensure update_sync_marker.sh is executable ───
echo ">>> STEP 2/3: Installing update_sync_marker.sh"
if [ -f "${SCRIPT_DIR}/update_sync_marker.sh" ]; then
    chmod +x "${SCRIPT_DIR}/update_sync_marker.sh"
    echo "    ✓ update_sync_marker.sh installed and executable"
else
    echo "    ✗ update_sync_marker.sh not found in scripts/"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ─── Step 3: Patch sentinel-blogger.yml (backend fix) ───
echo ">>> STEP 3/3: Patching sentinel-blogger.yml (sync_marker post-commit)"
if python3 "${SCRIPT_DIR}/patch_workflow_sync.py"; then
    echo "    ✓ sentinel-blogger.yml patch complete"
else
    echo "    ✗ sentinel-blogger.yml patch FAILED (may need manual step)"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# ─── Step 4: Update sync_marker.json NOW ───
echo ">>> BONUS: Updating sync_marker.json with current timestamp"
NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")
mkdir -p "${REPO_ROOT}/data" "${REPO_ROOT}/data/status"

cat > "${REPO_ROOT}/data/sync_marker.json" << EOF
{
  "last_sync": "${NOW_ISO}",
  "updated_by": "v72-fix-apply",
  "pipeline_run": "manual"
}
EOF
echo "    ✓ sync_marker.json set to ${NOW_ISO}"
echo ""

# ─── Summary ───
echo "═══════════════════════════════════════════════════════════"
if [ ${ERRORS} -eq 0 ]; then
    echo " ALL FIXES APPLIED SUCCESSFULLY"
    echo ""
    echo " Next steps:"
    echo "   1. git add -A"
    echo "   2. git commit -m 'v72.0: Permanent dashboard sync fix'"
    echo "   3. git push origin main"
    echo ""
    echo " The 'Last Sync' metric will show fresh data after next"
    echo " sentinel-blogger run. sync_marker.json will stay current"
    echo " automatically from now on."
else
    echo " COMPLETED WITH ${ERRORS} ERROR(S)"
    echo " Review output above and fix manually if needed."
fi
echo "═══════════════════════════════════════════════════════════"

exit ${ERRORS}
