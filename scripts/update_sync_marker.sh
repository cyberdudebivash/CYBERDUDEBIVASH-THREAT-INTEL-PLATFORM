#!/bin/bash
# ================================================================
# SENTINEL APEX v70 — Sync Marker Update Script
# ================================================================
# Updates data/sync_marker.json with current pipeline sync time.
# FRESHEST-WINS GUARD: Only updates if new timestamp > existing.
# ================================================================

set -euo pipefail

SYNC_MARKER="data/sync_marker.json"
NOW_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
NOW_EPOCH=$(date -u +%s)

mkdir -p data

# Read existing marker
if [ -f "$SYNC_MARKER" ]; then
    EXISTING_TS=$(python3 -c "
import json, sys
try:
    d = json.load(open('$SYNC_MARKER'))
    print(d.get('last_sync', ''))
except:
    print('')
" 2>/dev/null || echo "")

    if [ -n "$EXISTING_TS" ]; then
        EXISTING_EPOCH=$(date -d "$EXISTING_TS" +%s 2>/dev/null || echo "0")
        if [ "$NOW_EPOCH" -le "$EXISTING_EPOCH" ]; then
            echo "[SYNC] Existing marker ($EXISTING_TS) is newer or equal — skipping update"
            exit 0
        fi
    fi
fi

# Write new marker
cat > "$SYNC_MARKER" << EOF
{
  "last_sync": "$NOW_ISO",
  "epoch": $NOW_EPOCH,
  "pipeline_version": "v70.0",
  "status": "complete"
}
EOF

echo "[SYNC] Marker updated: $NOW_ISO (epoch: $NOW_EPOCH)"
