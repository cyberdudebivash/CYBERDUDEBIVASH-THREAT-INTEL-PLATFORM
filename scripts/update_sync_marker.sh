#!/usr/bin/env bash
# ============================================================
# SENTINEL APEX v64.2 — Sync Marker Updater
# ============================================================
# PURPOSE: Updates data/sync_marker.json on every pipeline run
#          so the dashboard's fetchPipelineSyncTime() has fresh data.
#
# ADD TO WORKFLOW: After STAGE 2 completes (feed ingestion done),
#                  add this step:
#
#   - name: "Update sync marker"
#     run: bash scripts/update_sync_marker.sh
#
# ============================================================
set -euo pipefail

REPO_ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
MARKER_FILE="${REPO_ROOT}/data/sync_marker.json"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)

mkdir -p "$(dirname "${MARKER_FILE}")"

cat > "${MARKER_FILE}" << EOF
{
  "last_sync": "${TIMESTAMP}",
  "sync_source": "github-actions-v64.2"
}
EOF

echo "[SYNC-MARKER] Updated: ${TIMESTAMP}"
