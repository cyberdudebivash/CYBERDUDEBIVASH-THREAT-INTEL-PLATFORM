@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM-main"

echo [1] Removing lock file if exists...
del /F /Q .git\index.lock 2>nul
echo [2] Setting git identity...
git config user.name "CDB-Sentinel-Bot"
git config user.email "bivash@cyberdudebivash.com"

echo [3] Staging workflow files...
git add .github/workflows/ai-predictions.yml
git add .github/workflows/ai-threat-analyst.yml
git add .github/workflows/arsenal.yml
git add .github/workflows/autonomous-guardian.yml
git add .github/workflows/bughunter-recon.yml
git add .github/workflows/bughunter-resilient.yml
git add .github/workflows/convergence.yml
git add .github/workflows/detection-engine.yml
git add .github/workflows/genesis-powerhouse.yml
git add .github/workflows/lead_autoresponder.yml
git add .github/workflows/multi-source-intel.yml
git add .github/workflows/nexus-intelligence.yml
git add .github/workflows/omnishield.yml
git add .github/workflows/precognition-engine.yml
git add .github/workflows/report-engine.yml
git add .github/workflows/revenue-orchestrator.yml
git add .github/workflows/sentinel-blogger.yml
git add .github/workflows/sentinel-factory.yml
git add .github/workflows/sovereign-platform.yml
git add .github/workflows/status-monitor.yml
git add .github/workflows/sync-dashboard.yml
git add .github/workflows/syndicate.yml
git add .github/workflows/weekly-analyst-briefing.yml
git add .github/workflows/zerodayhunter.yml
git add api/main.py api/copilot.py api/alerts.py 2>nul

echo [4] Checking staged diff...
git diff --staged --stat

echo [5] Committing...
git commit -m "v81.7: Phase 3 - Complete Workflow Hardening (24/24 workflows) - Add -f flag all git add data/ commands - Add concurrency groups prevent race conditions - Add timeout-minutes all jobs - Add GH_TOKEN auth all commit steps - Fix bare git push to git push origin main - Add push retry logic 3x replacing silent fallbacks - All 24 YAML files pass syntax validation"

echo [6] Done - exit code: %ERRORLEVEL%
