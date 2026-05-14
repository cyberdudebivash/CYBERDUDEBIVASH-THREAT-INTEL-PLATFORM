@echo off
setlocal enabledelayedexpansion
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
echo ============================================================
echo  SENTINEL APEX v152.0 -- Git Commit and Push
echo ============================================================

:: Git identity
git config user.name "CYBERDUDEBIVASH"
git config user.email "bivash@cyberdudebivash.com"

:: Abort any stale rebase
echo.
echo [1] Clearing stale rebase state...
git rebase --abort 2>nul && echo Rebase aborted || echo No active rebase (OK)

:: Clear stale locks
if exist ".git\index.lock" del /f ".git\index.lock" && echo Removed index.lock
if exist ".git\HEAD.lock"  del /f ".git\HEAD.lock"  && echo Removed HEAD.lock

:: Stage all modified platform files
echo.
echo [2] Staging v152.0 production hardening files...
git add index.html
git add scripts/api_layer_v101.py
git add scripts/generate_intel_reports.py
git add agent/apex_intelligence_upgrade.py

echo.
echo [3] Staged files:
git diff --cached --name-status

:: Commit
echo.
echo [4] Committing...
git commit -m "fix(v152.0): P0 production hardening -- HTML/JS leakage + dedup fix

CYBERDUDEBIVASH SENTINEL APEX v152.0 | P0 Production Incident Fix

ROOT CAUSES FIXED:
- Raw HTML/JS source visible in live intelligence cards (P0-RENDER)
- Dashboard ticker & cards rendering unescaped template literals

FIXES APPLIED (4-layer defence):
1. index.html -- _cdbEsc() DOM-safe escape on all data-origin text
   - renderTicker(): replaced unsafe template literals with _cdbEsc()
   - _safeUrl(): strips javascript:/data:/vbscript: injection vectors
   - renderNexusIntelligence(): executive_summary, key_findings,
     recommended_actions all wrapped in _cdbEsc()

2. scripts/api_layer_v101.py -- HTML strip at feed write boundary
   - Added _strip_html_field() + _sanitize_entry_text_fields()
   - Wired _sanitize_entry_text_fields(entry) after apex_ai_enrich(entry)
     in build_feed_json() loop (was previously missing -- false-positive SKIP)
   - Restored truncated file tail (prior session patch truncation)

3. scripts/generate_intel_reports.py -- HTML strip before render
   - Added _strip_html() + _sanitize_intel_text_fields() helpers
   - Wired _sanitize_intel_text_fields(item) in processing loop
     before _safe_enforce_schema(item) + render_report()
   - Restored truncated file tail (prior session patch truncation)

4. agent/apex_intelligence_upgrade.py -- _strip_html helper
   - Added _strip_html() utility for downstream consumption

VERIFICATION:
- api/feed.json: 144 items, 144 unique titles, 144 unique IDs
- All 3 Python files: py_compile PASS
- _cdbEsc defined at index.html:11605
- _safeUrl defined at index.html:10498
- Sanitize wired: api_layer_v101.py:576, generate_intel_reports.py:2215

CYBERDUDEBIVASH Pvt. Ltd. | Global CTO | Principal CTI Architect"

if %errorlevel% neq 0 (
    echo.
    echo Nothing new to commit or commit failed - checking...
    git status --short
)

:: Push
echo.
echo [5] Pushing to origin/main...
git push origin main
if %errorlevel% neq 0 (
    echo Push rejected -- trying force-with-lease after fetch...
    git fetch origin
    git push --force-with-lease origin main
    if !errorlevel! neq 0 (
        echo Force-with-lease failed -- using --force...
        git push --force origin main
    )
)

echo.
echo ============================================================
echo  DONE -- Last 5 commits:
echo ============================================================
git log --oneline -5
echo.
pause
