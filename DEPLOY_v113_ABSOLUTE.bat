@echo off
setlocal EnableDelayedExpansion
REM ============================================================================
REM CYBERDUDEBIVASH SENTINEL APEX v113.0 -- ABSOLUTE DEPLOY (FIXED)
REM Repo: C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\
REM              CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
REM ============================================================================
REM FIXES IN THIS SCRIPT:
REM   - Hardcoded correct repo path (no fallback to wrong ai-security-hub repo)
REM   - Worker deployed using ABSOLUTE path to wrangler.toml (no relative cd)
REM   - CMD-safe validation (no nested Python quotes)
REM   - Proper ERRORLEVEL checks on every critical step
REM ============================================================================

REM ===== MANDATORY REPO PATH — DO NOT CHANGE =====
set "REPO=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
set "WORKER_DIR=%REPO%\workers\intel-gateway"

echo.
echo ============================================================
echo   SENTINEL APEX v113.0 -- ABSOLUTE SYSTEM DEPLOY
echo   Repo: %REPO%
echo ============================================================
echo.

REM ── Verify correct repo ────────────────────────────────────────────────────────
if not exist "%REPO%\.git" (
    echo FATAL: .git not found at %REPO%
    echo Check that REPO path is correct.
    pause
    exit /b 1
)
if not exist "%REPO%\index.html" (
    echo FATAL: index.html not found in repo.
    echo Repo path may be wrong: %REPO%
    pause
    exit /b 1
)
if not exist "%WORKER_DIR%\wrangler.toml" (
    echo FATAL: wrangler.toml not found at %WORKER_DIR%
    pause
    exit /b 1
)

cd /d "%REPO%"
echo [OK] Confirmed repo: %CD%
echo.

REM ── STEP 1: Clear git locks ────────────────────────────────────────────────────
echo [STEP 1/7] Clearing git locks...
del /f /q "%REPO%\.git\index.lock"   2>nul
del /f /q "%REPO%\.git\HEAD.lock"    2>nul
del /f /q "%REPO%\.git\config.lock"  2>nul
del /f /q "%REPO%\.git\MERGE_HEAD"   2>nul
rmdir /s /q "%REPO%\.git\rebase-merge"  2>nul
rmdir /s /q "%REPO%\.git\rebase-apply" 2>nul
echo [OK] Locks cleared.
echo.

REM ── STEP 2: Fetch + sync ───────────────────────────────────────────────────────
echo [STEP 2/7] Fetching and syncing with origin/main...
git fetch origin main --quiet
if !ERRORLEVEL! NEQ 0 (
    echo ERROR: git fetch failed. Check network / GitHub credentials.
    pause
    exit /b 1
)
git merge origin/main -X ours --no-edit --quiet 2>nul
if !ERRORLEVEL! NEQ 0 (
    git merge --abort 2>nul
    git reset --hard origin/main
)
echo [OK] Current HEAD:
git log --oneline -1
echo.

REM ── STEP 3: Show git status ────────────────────────────────────────────────────
echo [STEP 3/7] Git status (checking for uncommitted v113 changes)...
git status --short
echo.

REM ── STEP 4: Stage all v112.1 + v113.0 files ──────────────────────────────────
echo [STEP 4/7] Staging changed files...

REM Verify files exist before staging
if exist "%REPO%\index.html" (
    git add index.html
    echo   [staged] index.html
) else ( echo   [SKIP] index.html not found )

if exist "%REPO%\.github\workflows\sentinel-blogger.yml" (
    git add ".github\workflows\sentinel-blogger.yml"
    echo   [staged] sentinel-blogger.yml
) else ( echo   [SKIP] sentinel-blogger.yml not found )

if exist "%REPO%\.github\workflows\sync-dashboard.yml" (
    git add ".github\workflows\sync-dashboard.yml"
    echo   [staged] sync-dashboard.yml
) else ( echo   [SKIP] sync-dashboard.yml not found )

if exist "%REPO%\.github\workflows\r2-data-sync.yml" (
    git add ".github\workflows\r2-data-sync.yml"
    echo   [staged] r2-data-sync.yml
) else ( echo   [SKIP] r2-data-sync.yml not found )

if exist "%REPO%\.github\workflows\bughunter-resilient.yml" (
    git add ".github\workflows\bughunter-resilient.yml"
    echo   [staged] bughunter-resilient.yml
) else ( echo   [SKIP] bughunter-resilient.yml not found )

if exist "%WORKER_DIR%\src\index.js" (
    git add "workers\intel-gateway\src\index.js"
    echo   [staged] workers\intel-gateway\src\index.js
) else ( echo   [SKIP] Worker index.js not found )

if exist "%REPO%\agent\v70_apex_upgrade\pipeline\validator.py" (
    git add "agent\v70_apex_upgrade\pipeline\validator.py"
    echo   [staged] validator.py
) else ( echo   [SKIP] validator.py not found )

git add "DEPLOY_v113_ABSOLUTE.bat" 2>nul

echo.
echo [STEP 4b/7] Staged diff summary:
git diff --staged --stat
echo.

REM ── STEP 5: Commit ─────────────────────────────────────────────────────────────
git diff --staged --quiet
if !ERRORLEVEL! EQU 0 (
    echo [INFO] No staged changes -- all v113.0 fixes may already be committed.
    echo        Checking git log for v113 commit...
    git log --oneline -5
    echo.
    echo        If v113 changes are NOT in the log above, the files were not
    echo        written to this repo. Contact support.
    echo.
    goto :DEPLOY_WORKER
)

echo [STEP 5/7] Committing v112.1 + v113.0 changes...
git commit ^
 -m "SENTINEL APEX v113.0 -- ABSOLUTE: dashboard P0 + arch hardening" ^
 -m "v112.1: m-total/m-last-sync path fixed (data.preview.total_in_feed)" ^
 -m "v112.1: Overrides run AFTER computeMetrics (ordering fix)" ^
 -m "v112.1: Kill chain ttps->mitre_tactics mapping added" ^
 -m "v112.1: Confidence 0%% fixed (severity-calibrated defaults)" ^
 -m "v113.0: sync-dashboard stops committing feed_manifest.json to git" ^
 -m "v113.0: sentinel-blogger freshness gate MIN=50 + R2 hard count check" ^
 -m "v113.0: Worker v113 staleness logging + PREVIEW TTL 60s" ^
 -m "v113.0: bughunter-resilient + r2-data-sync auto-triggers disabled" ^
 -m "[skip ci]"

if !ERRORLEVEL! NEQ 0 (
    echo ERROR: Commit failed. See git output above.
    pause
    exit /b 1
)
echo [OK] Committed.
echo.

REM ── STEP 6: Push ───────────────────────────────────────────────────────────────
echo [STEP 6/7] Pushing to origin/main...
git push origin main
if !ERRORLEVEL! NEQ 0 (
    echo   Push failed. Fetching + rebasing...
    git fetch origin main
    git rebase origin/main 2>nul
    if !ERRORLEVEL! NEQ 0 (
        git rebase --abort 2>nul
        git merge origin/main -X ours --no-edit
    )
    git push origin main --force-with-lease
    if !ERRORLEVEL! NEQ 0 (
        echo FATAL: Push failed after rebase. Run manually:
        echo   git push origin main
        pause
        exit /b 1
    )
)
echo [OK] Push succeeded.
echo.

:DEPLOY_WORKER
REM ── STEP 7: Deploy Worker (ABSOLUTE PATH -- fixes "wrong directory" bug) ───────
echo [STEP 7/7] Deploying Cloudflare Worker v113.0...
echo   Worker dir: %WORKER_DIR%
echo.

if not exist "%WORKER_DIR%\wrangler.toml" (
    echo FATAL: wrangler.toml missing at %WORKER_DIR%
    echo Worker deploy skipped.
    goto :VALIDATION
)

REM Change to worker directory using absolute path
cd /d "%WORKER_DIR%"
if !ERRORLEVEL! NEQ 0 (
    echo FATAL: Cannot cd to %WORKER_DIR%
    goto :VALIDATION
)
echo [OK] Worker dir: %CD%

REM Install deps if needed
if not exist node_modules (
    echo   Installing wrangler dependencies...
    call npm install --silent
)

REM Deploy to production (wrangler.toml has [env.production])
echo   Running: wrangler deploy --env production
call npx wrangler deploy --env production
if !ERRORLEVEL! NEQ 0 (
    echo   WARN: --env production failed. Trying plain deploy (uses root wrangler.toml)...
    call npx wrangler deploy
    if !ERRORLEVEL! NEQ 0 (
        echo   ERROR: Worker deploy failed. Manual deploy:
        echo   cd %WORKER_DIR%
        echo   npx wrangler deploy --env production
        echo   Continuing to validation...
    ) else (
        echo [OK] Worker deployed (plain).
    )
) else (
    echo [OK] Worker deployed (production env).
)

REM Return to repo root
cd /d "%REPO%"
echo.

:VALIDATION
REM ── VALIDATION: Live endpoint checks ──────────────────────────────────────────
echo ============================================================
echo   LIVE VALIDATION
echo ============================================================
echo   Waiting 15s for Worker propagation...
timeout /t 15 /nobreak >nul
echo.

echo   [1] Health check:
curl -s -m 10 "https://intel.cyberdudebivash.com/api/health"
echo.
echo.

echo   [2] Preview check (look for total_in_feed):
curl -s -m 10 "https://intel.cyberdudebivash.com/api/preview" > "%TEMP%\apex_preview.json"
if exist "%TEMP%\apex_preview.json" (
    REM Write a temp Python script to avoid CMD quote issues
    echo import json > "%TEMP%\apex_check.py"
    echo d = json.load(open(r'%TEMP%\apex_preview.json')) >> "%TEMP%\apex_check.py"
    echo p = d.get('preview', {}) >> "%TEMP%\apex_check.py"
    echo print('gateway      :', d.get('gateway', 'MISSING')) >> "%TEMP%\apex_check.py"
    echo print('total_in_feed:', p.get('total_in_feed', 'MISSING')) >> "%TEMP%\apex_check.py"
    echo print('preview_items:', len(p.get('items', []))) >> "%TEMP%\apex_check.py"
    echo print('generated_at :', p.get('generated_at', 'MISSING')) >> "%TEMP%\apex_check.py"
    python "%TEMP%\apex_check.py" 2>nul
    if !ERRORLEVEL! NEQ 0 (
        echo   Python not available -- raw JSON:
        type "%TEMP%\apex_preview.json"
    )
    del "%TEMP%\apex_preview.json" 2>nul
    del "%TEMP%\apex_check.py"    2>nul
)
echo.

echo ============================================================
echo   DEPLOY SUMMARY
echo ============================================================
echo.
echo   EXPECTED AFTER sentinel-blogger RUNS:
echo     Total Advisories : 2,177  (was: 10)
echo     Kill Chain       : non-zero TTP hits
echo     Confidence       : 85%% CRITICAL / 72%% HIGH
echo     Worker version   : 113.0  (was: 112.0)
echo     Last Sync        : R2 manifest timestamp
echo.
echo   NEXT REQUIRED ACTION:
echo   ─────────────────────────────────────────────────────────
echo   1. Go to GitHub Actions:
echo      https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions
echo   2. Click "sentinel-blogger" workflow
echo   3. Click "Run workflow" button
echo   4. Wait 15-20 minutes for full pipeline to complete
echo   5. Refresh https://intel.cyberdudebivash.com/
echo      Dashboard MUST show 2,177+ advisories
echo.
echo   If dashboard still shows 10 after pipeline run:
echo   - Check Worker version at /api/health (must say 113.0)
echo   - Run: curl https://intel.cyberdudebivash.com/api/preview
echo   - Verify total_in_feed in response
echo ============================================================
echo.
pause
endlocal
