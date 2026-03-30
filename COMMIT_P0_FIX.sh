#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════════════
#  CYBERDUDEBIVASH SENTINEL APEX v78.0 — P0 FIX COMMIT SCRIPT
#  Run this from the repo root on your Windows machine (Git Bash or WSL):
#    bash COMMIT_P0_FIX.sh
# ════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "=== SENTINEL APEX v78.0 — P0 Dashboard Sync Fix Commit ==="
echo ""

# Verify we're in the repo root
if [ ! -f "index.html" ] || [ ! -f "service-worker.js" ]; then
    echo "ERROR: Run this script from the CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM repo root"
    exit 1
fi

# Run pre-deploy gate one final time
echo "Running pre-deploy integrity gate..."
python3 scripts/pre_deploy_gate.py
echo ""

# Stage exactly the 4 changed files
echo "Staging files..."
git add index.html
git add service-worker.js
git add .github/workflows/sentinel-blogger.yml
git add scripts/pre_deploy_gate.py

echo "Changed files:"
git diff --cached --stat
echo ""

# Commit
git commit -m "v78.0: Fix P0 dashboard sync — restore truncated index.html

ROOT CAUSE: index.html was truncated at line 6606, missing the closing
of the v65.0 expand toggle event listener, </script>, </body>, and </html>.
This caused ALL JavaScript to silently fail, leaving the dashboard stuck
at 'BOOTING...' with all metrics showing '—'.

FIXES (4 files):

1. index.html — Restored missing:
   - Complete v65.0 expand toggle (cdb-xtoggle) event handler
   - </script> closing tag
   - </body> closing tag
   - </html> closing tag
   - Removed controllerchange → window.location.reload() (SW reload loop)

2. service-worker.js (v77.1 → v78.0):
   - Removed self.skipWaiting() from install handler
   - Removed self.clients.claim() from activate handler
   - These two combined with the page's controllerchange listener
     caused a reload loop on every 6-hour pipeline deploy
   - Cache version bumped to sentinel-apex-v78

3. .github/workflows/sentinel-blogger.yml (Stage 1):
   - Fixed: was falling back to agent/enricher.py (a class, not a runner)
   - Now correctly calls sentinel_blogger.py → sentinel_engine.py → publisher.py
     in priority order

4. scripts/pre_deploy_gate.py (v75.1 → v78.0):
   - Added Check 9: index.html must end with </html> (truncation guard)
   - Added Check 10: balanced <script>/<script> open/close tags
   - Added Check 11: file size > 900KB minimum (regression guard)
   These three checks would have CAUGHT and BLOCKED this P0 before deploy."
echo ""
echo "Committed. Pushing to main..."
git push origin main

echo ""
echo "=== DONE — P0 Fix deployed to main ==="
echo "The GitHub Actions sentinel-blogger workflow will deploy to gh-pages."
echo "Dashboard will be live at: https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/"
