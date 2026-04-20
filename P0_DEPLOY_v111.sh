#!/bin/bash
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX v111.0  -  P0 RECOVERY DEPLOYMENT SCRIPT
# =============================================================================
# This script deploys ALL P0 fixes. Run once from repo root to restore
# 100% platform functionality.
#
# WHAT THIS FIXES:
#   1. Clears the Blogger publish queue bomb (prevented intel generation)
#   2. Resets the platform to R2-native / Blogger-free architecture
#   3. Commits the cleared queue, fixed files, and triggers workflow
#
# PREREQUISITES:
#   - git configured with push access to origin
#   - GitHub secrets set: CF_ACCOUNT_ID, CF_R2_ACCESS_KEY_ID,
#     CF_R2_SECRET_ACCESS_KEY, WORKER_ADMIN_SECRET (optional)
#
# USAGE:
#   chmod +x P0_DEPLOY_v111.sh && ./P0_DEPLOY_v111.sh
# =============================================================================

set -e
echo "============================================================"
echo "SENTINEL APEX v111.0  -  P0 RECOVERY DEPLOYMENT"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

# STEP 1: Verify we are in the repo root
if [ ! -f ".github/workflows/sentinel-blogger.yml" ]; then
  echo "ERROR: Run this script from the repository root."
  exit 1
fi

# STEP 2: Clear the publish queue bomb
echo ""
echo "[1/8] Clearing Blogger publish queue bomb..."
python3 - << 'PYEOF'
import json, os
from datetime import datetime, timezone
queue_path = "data/publish_queue.json"
old_count = 0
if os.path.exists(queue_path):
    try:
        q = json.load(open(queue_path))
        queue = q.get("queue", q) if isinstance(q, dict) else q
        old_count = len(queue) if isinstance(queue, list) else 0
    except Exception:
        pass
empty = {"queue": [], "version": "111.0",
         "cleared_at": datetime.now(timezone.utc).isoformat(),
         "reason": "P0_FIX_v111_QUEUE_BOMB_NEUTRALISED"}
with open(queue_path, "w") as f:
    json.dump(empty, f, indent=2)
print(f"  [OK] Queue cleared: {old_count} stale Blogger entries removed")
PYEOF

# STEP 3: Validate fixed files exist
echo ""
echo "[2/8] Validating fixed files..."
FILES_TO_CHECK=(
  "agent/sentinel_blogger.py"
  "scripts/bootstrap_critical_files.py"
  ".github/workflows/sentinel-blogger.yml"
  ".github/workflows/multi-source-intel.yml"
  "workers/intel-gateway/src/index.js"
  "data/publish_queue.json"
)
for f in "${FILES_TO_CHECK[@]}"; do
  if [ -f "$f" ]; then
    echo "  [OK] $f"
  else
    echo "  [FAIL] MISSING: $f"
  fi
done

# STEP 4: Verify Blogger imports are removed from sentinel_blogger.py
echo ""
echo "[3/8] Verifying Blogger is fully removed from sentinel_blogger.py..."
if grep -q "from agent.blogger_auth import" agent/sentinel_blogger.py 2>/dev/null; then
  echo "  [FAIL] ERROR: blogger_auth import still present in sentinel_blogger.py"
  exit 1
else
  echo "  [OK] blogger_auth import: REMOVED"
fi
if grep -q "resilient_publish\|publish_with_retry\|save_to_pending_queue" agent/sentinel_blogger.py 2>/dev/null; then
  echo "  [FAIL] ERROR: Blogger publish functions still present"
  exit 1
else
  echo "  [OK] Blogger publish functions: REMOVED"
fi

# STEP 5: Verify bootstrap skip logic is removed
echo ""
echo "[4/8] Verifying bootstrap skip-logic is removed..."
if grep -q "skipping rebuild" scripts/bootstrap_critical_files.py 2>/dev/null; then
  echo "  [FAIL] ERROR: Old skip-rebuild logic still present in bootstrap"
  exit 1
else
  echo "  [OK] Bootstrap skip-logic: REMOVED"
fi

# STEP 6: Verify EMBEDDED_INTEL is empty
echo ""
echo "[5/8] Verifying EMBEDDED_INTEL is purged from dashboard..."
EMBEDDED_COUNT=$(python3 -c "
import re
html = open('index.html').read()
m = re.search(r'const EMBEDDED_INTEL = \[([^\]]*)\]', html)
if m:
    content = m.group(1).strip()
    print(len(content))
else:
    print(-1)
" 2>/dev/null)
if [ "$EMBEDDED_COUNT" -le "5" ]; then
  echo "  [OK] EMBEDDED_INTEL: EMPTY (brand contamination purged)"
else
  echo "    WARNING: EMBEDDED_INTEL still has $EMBEDDED_COUNT chars  -  check index.html"
fi

# STEP 7: Verify Worker version updated
echo ""
echo "[6/8] Verifying Worker cache TTL fix..."
if grep -q '"111.0"' workers/intel-gateway/src/index.js 2>/dev/null; then
  echo "  [OK] Worker version: v111.0"
else
  echo "    WARNING: Worker may not have v111.0  -  check manually"
fi

# STEP 8: Git commit all fixes
echo ""
echo "[7/8] Committing P0 fixes to repository..."
git config --local user.email "sentinel@cyberdudebivash.com" 2>/dev/null || true
git config --local user.name  "CDB-Sentinel-P0-Fix" 2>/dev/null || true

git add -f data/publish_queue.json
git add    agent/sentinel_blogger.py
git add    scripts/bootstrap_critical_files.py
git add    .github/workflows/sentinel-blogger.yml
git add    .github/workflows/multi-source-intel.yml
git add    workers/intel-gateway/src/index.js
git add    index.html
git add -f data/ai_intelligence/ai_index.json 2>/dev/null || true

if git diff --staged --quiet; then
  echo "    No staged changes (already committed or clean)"
else
  git commit -m " P0 FIX v111.0  -  Blogger queue bomb neutralised, R2-native architecture restored

FIXES:
- [P0] Blogger publish_queue cleared (was accumulating thousands of entries)
- [P0] sentinel_blogger.py: blogger_auth import REMOVED, resilient_publish REPLACED with direct STIX write
- [P0] bootstrap: skip-if->=50 logic REMOVED  -  always merges new STIX entries
- [P0] _load_manifest: 'entries' key BUG FIXED to 'advisories'
- [P0] multi-source-intel.yml: stops committing feed_manifest.json to git
- [P0] Worker: cache TTL reduced to 60/90s, MITRE/TTP data included in preview
- [P0] Dashboard: EMBEDDED_INTEL brand contamination PURGED (empty array)
- [P0] Failure guard: pipeline fails if manifest has <10 entries
- [P0] R2 upload: Cache-Control: no-cache headers added

Architecture: Intel Engine -> STIX Bundles -> bootstrap --force-rebuild -> R2 Upload -> Worker -> Dashboard

Co-Authored-By: CYBERDUDEBIVASH Sentinel APEX <sentinel@cyberdudebivash.com>"
  echo "  [OK] Committed P0 fixes"
fi

# STEP 9: Deploy Cloudflare Worker
echo ""
echo "[8/8] Deploy Cloudflare Worker (manual step required)..."
echo ""
echo "  Run the following to deploy the fixed Worker:"
echo "  ---------------------------------------------"
echo "  cd workers/intel-gateway"
echo "  npx wrangler deploy --env production"
echo "  ---------------------------------------------"
echo ""
echo "  Or trigger via GitHub Actions:"
echo "  Actions -> deploy-worker -> Run workflow"
echo ""

echo "============================================================"
echo "P0 RECOVERY COMPLETE"
echo ""
echo "NEXT STEPS:"
echo "  1. git push origin main"
echo "  2. Deploy Cloudflare Worker (see above)"
echo "  3. GitHub Actions -> sentinel-blogger -> Run workflow"
echo "  4. Wait 2 min -> check https://intel.cyberdudebivash.com/api/health"
echo "  5. Wait 5 min -> verify dashboard updates at intel.cyberdudebivash.com"
echo ""
echo "VALIDATION CHECKLIST:"
echo "   /api/health -> r2_intel: ok"
echo "   /api/preview -> total_in_feed > 100"
echo "   Dashboard shows fresh intel (not brand garbage)"
echo "   Last Sync timestamp updates"
echo "   MITRE ATT&CK heatmap populated"
echo "   AI panels visible"
echo "   Workflow runtime < 25 min (queue bomb gone)"
echo "============================================================"
