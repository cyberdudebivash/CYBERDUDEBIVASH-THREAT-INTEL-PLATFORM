#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# SENTINEL APEX v72.0 — Sync Marker Updater
# ═══════════════════════════════════════════════════════════
# Updates data/sync_marker.json with current timestamp after
# every successful pipeline run. This ensures the dashboard's
# fetchPipelineSyncTime() always has a fresh value to display.
#
# Called from sentinel-blogger.yml AFTER the main commit+push.
# ═══════════════════════════════════════════════════════════

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYNC_MARKER="${REPO_ROOT}/data/sync_marker.json"
STATUS_JSON="${REPO_ROOT}/data/status/status.json"

NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%S+00:00")

echo "=== v72.0 Sync Marker Update ==="
echo "  Timestamp: ${NOW_ISO}"

# ─── Update sync_marker.json ───
mkdir -p "$(dirname "${SYNC_MARKER}")"

# Read existing marker to preserve structure, or create new
if [ -f "${SYNC_MARKER}" ]; then
    python3 -c "
import json, sys
try:
    with open('${SYNC_MARKER}', 'r') as f:
        data = json.load(f)
except:
    data = {}
data['last_sync'] = '${NOW_ISO}'
data['updated_by'] = 'sentinel-blogger-v72'
data['pipeline_run'] = '${GITHUB_RUN_NUMBER:-unknown}'
with open('${SYNC_MARKER}', 'w') as f:
    json.dump(data, f, indent=2)
print(f'  sync_marker.json updated: {data[\"last_sync\"][:19]}')
" 2>/dev/null || {
    # Fallback: create fresh
    cat > "${SYNC_MARKER}" << MARKER_EOF
{
  "last_sync": "${NOW_ISO}",
  "updated_by": "sentinel-blogger-v72",
  "pipeline_run": "${GITHUB_RUN_NUMBER:-unknown}"
}
MARKER_EOF
    echo "  sync_marker.json created (fresh)"
}
else
    cat > "${SYNC_MARKER}" << MARKER_EOF
{
  "last_sync": "${NOW_ISO}",
  "updated_by": "sentinel-blogger-v72",
  "pipeline_run": "${GITHUB_RUN_NUMBER:-unknown}"
}
MARKER_EOF
    echo "  sync_marker.json created (new)"
fi

# ─── Update status.json generated_at ───
mkdir -p "$(dirname "${STATUS_JSON}")"
if [ -f "${STATUS_JSON}" ]; then
    python3 -c "
import json
try:
    with open('${STATUS_JSON}', 'r') as f:
        data = json.load(f)
except:
    data = {}
data['generated_at'] = '${NOW_ISO}'
data['status'] = 'OPERATIONAL'
with open('${STATUS_JSON}', 'w') as f:
    json.dump(data, f, indent=2)
print(f'  status.json updated: {data[\"generated_at\"][:19]}')
" 2>/dev/null || echo "  status.json update skipped (non-fatal)"
fi

echo "  SUCCESS"
echo "==================================="
