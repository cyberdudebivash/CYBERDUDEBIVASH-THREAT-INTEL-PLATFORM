@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

echo [1] Clearing lock files...
if exist ".git\index.lock"    del /f /q ".git\index.lock"    && echo Removed index.lock
if exist ".git\HEAD.lock"     del /f /q ".git\HEAD.lock"     && echo Removed HEAD.lock
if exist ".git\REBASE_HEAD"   del /f /q ".git\REBASE_HEAD"   && echo Removed REBASE_HEAD
if exist ".git\AUTO_MERGE"    del /f /q ".git\AUTO_MERGE"    && echo Removed AUTO_MERGE
if exist ".git\rebase-merge\" rd /s /q ".git\rebase-merge"   && echo Removed rebase-merge dir
echo Lock cleanup done.

echo.
echo [2] Git identity...
git config user.name "CYBERDUDEBIVASH"
git config user.email "bivashnayak.ai007@gmail.com"

echo.
echo [3] Resetting index to HEAD...
git reset HEAD

echo.
echo [4] Staging v152.0 files...
git add scripts/api_layer_v101.py
git add scripts/generate_intel_reports.py
git add agent/apex_intelligence_upgrade.py
git add index.html

echo.
echo [5] Staged:
git diff --cached --name-status

echo.
echo [6] Committing...
git commit -m "fix(v152.0): P0 production hardening -- HTML/JS leakage + pipeline sanitization

CYBERDUDEBIVASH SENTINEL APEX v152.0 | P0 Production Incident Fix

ROOT CAUSES FIXED:
- Raw HTML/JS source visible in live intelligence cards (P0-RENDER)
- Unescaped template literals in ticker + renderNexusIntelligence
- Python pipeline writing HTML markup into JSON text fields

FIXES (4-layer defence-in-depth):
1. index.html -- _cdbEsc() DOM-safe escape on all data-origin text
   _safeUrl() strips javascript:/data:/vbscript: injection vectors
2. scripts/api_layer_v101.py -- _sanitize_entry_text_fields wired
   after apex_ai_enrich() in build_feed_json() loop
3. scripts/generate_intel_reports.py -- _sanitize_intel_text_fields
   wired before schema enforcement and render in processing loop
4. agent/apex_intelligence_upgrade.py -- _strip_html() helper added

VERIFICATION: feed.json 144 unique items, py_compile PASS all files
CYBERDUDEBIVASH Pvt. Ltd. | Global CTO | Principal CTI Architect"

if %errorlevel% neq 0 (
    echo Commit check: %errorlevel%
    git status --short
)

echo.
echo [7] Pushing...
git push origin main
if %errorlevel% neq 0 (
    echo Retrying with fetch + force-with-lease...
    git fetch origin
    git push --force-with-lease origin main
)
if %errorlevel% neq 0 (
    echo Final fallback: force push...
    git push --force origin main
)

echo.
echo [8] Final log:
git log --oneline -5
echo.
pause
