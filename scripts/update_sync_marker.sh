#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# SENTINEL APEX v72.0 — Sync Marker Updater
# ═══════════════════════════════════════════════════════════
# Updates data/sync_marker.json with current UTC timestamp
# after every successful pipeline run.
#
# Called by sentinel-blogger.yml post-commit step.
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
cat > "${SYNC_MARKER}" << MARKER_EOF
{
  "last_sync": "${NOW_ISO}",
  "updated_by": "sentinel-blogger-v72",
  "pipeline_run": "${GITHUB_RUN_NUMBER:-manual}"
}
MARKER_EOF
echo "  sync_marker.json: UPDATED"

# ─── Update status.json ───
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
print('  status.json: UPDATED')
" 2>/dev/null || echo "  status.json: SKIPPED (non-fatal)"
else
    cat > "${STATUS_JSON}" << STATUS_EOF
{
  "platform": "CYBERDUDEBIVASH SENTINEL APEX",
  "status": "OPERATIONAL",
  "generated_at": "${NOW_ISO}"
}
STATUS_EOF
    echo "  status.json: CREATED"
fi

echo "  SUCCESS"
echo "==================================="
