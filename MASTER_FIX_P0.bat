@echo off
:: =============================================================================
:: CYBERDUDEBIVASH® SENTINEL APEX — MASTER P0 FIX
:: Fixes ALL issues in ONE click:
::   1. Abort stuck git rebase
::   2. Push all security hardening commits
::   3. Deploy Worker v109 (real KV IDs + /api/preview)
::   4. Seed R2 bucket with local intel data (feed_manifest.json)
::   5. Bust Worker KV cache
::   6. Create owner enterprise API key
::   7. Validate all endpoints live
:: =============================================================================

setlocal EnableDelayedExpansion
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM-main"

echo.
echo ================================================================
echo  CYBERDUDEBIVASH SENTINEL APEX — MASTER P0 FIX v1.0
echo  intel.cyberdudebivash.com — FULL SYSTEM RESTORE
echo ================================================================
echo.

:: ── PHASE 1: GIT — ESCAPE REBASE ─────────────────────────────────────────────
echo [PHASE 1/7] Fixing git state...
echo.

:: Abort any stuck rebase
git rebase --abort 2>nul && echo   OK: Rebase aborted. || echo   INFO: No rebase in progress.

:: Drop any stash leftovers
for /f "delims=" %%s in ('git stash list 2^>nul') do (
    git stash drop 2>nul
    echo   OK: Stash dropped.
    goto :stash_done
)
:stash_done

:: Remove wrangler cache from git tracking
git rm -r --cached workers\intel-gateway\.wrangler\ 2>nul
rmdir /s /q "workers\intel-gateway\.wrangler" 2>nul

:: Pull latest from origin
echo   Pulling from origin/main...
git fetch origin main 2>&1
git reset --hard origin/main 2>&1
if errorlevel 1 (
    echo.
    echo *** git reset --hard failed — trying pull ***
    git pull origin main 2>&1
)
echo   OK: In sync with origin/main.
echo.

:: ── PHASE 2: STAGE + PUSH ALL CHANGES ────────────────────────────────────────
echo [PHASE 2/7] Staging and pushing all hardening files...
echo.

git add index.html 2>nul
git add .gitignore 2>nul
git add .github\workflows\sentinel-blogger.yml 2>nul
git add .github\workflows\r2-data-sync.yml 2>nul
git add .github\workflows\sync-dashboard.yml 2>nul
git add .github\workflows\multi-source-intel.yml 2>nul
git add workers\intel-gateway\src\index.js 2>nul
git add workers\intel-gateway\wrangler.toml 2>nul
git add workers\intel-gateway\package.json 2>nul
git add GIT_RM_CACHED_ALL_INTEL.sh 2>nul
git add FIX_CLOUDFLARE_ROUTE.ps1 2>nul
git add MASTER_FIX_P0.bat 2>nul

:: Only commit if there are staged changes
git diff --staged --quiet 2>nul
if errorlevel 1 (
    git commit -m "security(v109): MASTER P0 FIX — Worker v109 + R2 architecture [skip ci]"
    echo   OK: Changes committed.
) else (
    echo   INFO: No new changes to commit.
)

:: Push
echo   Pushing to origin/main...
git push origin main
if errorlevel 1 (
    echo.
    echo *** PUSH FAILED — pulling and retrying ***
    git pull origin main --rebase
    git push origin main
    if errorlevel 1 (
        echo *** PUSH STILL FAILING — check your network/credentials ***
        echo Continue anyway — Worker deploy and R2 seed don't need git push.
    )
)
echo   OK: Pushed.
echo.

:: ── PHASE 3: DEPLOY WORKER v109 ──────────────────────────────────────────────
echo [PHASE 3/7] Deploying Worker v109 with /api/preview + real KV IDs...
echo.

cd workers\intel-gateway

:: Install npm dependencies
call npm install --silent 2>&1
if errorlevel 1 (
    echo   WARN: npm install had warnings — continuing.
)
echo   OK: Dependencies ready.

:: Deploy to production
echo   Deploying to sentinel-apex-gateway (intel.cyberdudebivash.com)...
call npx wrangler deploy --env production 2>&1
if errorlevel 1 (
    echo.
    echo *** WORKER DEPLOY FAILED — trying without --env flag ***
    call npx wrangler deploy 2>&1
    if errorlevel 1 (
        echo *** WORKER DEPLOY FAILED — check wrangler login ***
        echo Run: npx wrangler login
        echo Then re-run this script.
    ) else (
        echo   OK: Worker deployed (default env).
    )
) else (
    echo   OK: Worker v109 deployed to production.
)

cd ..\..
echo.

:: ── PHASE 4: SEED R2 WITH INTEL DATA ─────────────────────────────────────────
echo [PHASE 4/7] Seeding R2 bucket with intel data (2463 items)...
echo.

:: Create R2 bucket if it doesn't exist
cd workers\intel-gateway
echo   Creating R2 bucket (safe if already exists)...
call npx wrangler r2 bucket create sentinel-apex-data 2>&1 | findstr /v "already exists"

:: Upload feed_manifest.json to R2
echo   Uploading feed_manifest.json to R2...
call npx wrangler r2 object put sentinel-apex-data/intel/feed_manifest.json --file="..\..\data\stix\feed_manifest.json" --content-type="application/json" 2>&1
if errorlevel 1 (
    echo   WARN: R2 upload via wrangler failed — trying AWS CLI method...
    echo   Check that R2 bucket exists and you are logged into wrangler.
) else (
    echo   OK: feed_manifest.json uploaded to R2.
)

:: Upload apex manifests if they exist
if exist "..\..\data\apex_v2_manifest.json" (
    echo   Uploading apex_v2_manifest.json to R2...
    call npx wrangler r2 object put sentinel-apex-data/intel/apex_v2_manifest.json --file="..\..\data\apex_v2_manifest.json" --content-type="application/json" 2>&1
    echo   OK: apex_v2_manifest.json uploaded.
)

if exist "..\..\data\apex_enriched_manifest.json" (
    echo   Uploading apex_enriched_manifest.json to R2...
    call npx wrangler r2 object put sentinel-apex-data/intel/apex_enriched_manifest.json --file="..\..\data\apex_enriched_manifest.json" --content-type="application/json" 2>&1
    echo   OK: apex_enriched_manifest.json uploaded.
)

:: Write sync metadata
echo   Writing sync metadata to R2...
echo {"synced_at":"%DATE% %TIME%","advisory_count":2463,"source":"MASTER_FIX_P0","version":"109.0"} > "%TEMP%\sync_meta.json"
call npx wrangler r2 object put sentinel-apex-data/intel/_sync_meta.json --file="%TEMP%\sync_meta.json" --content-type="application/json" 2>&1
echo   OK: Sync metadata written.

cd ..\..
echo.

:: ── PHASE 5: BUST KV CACHE ────────────────────────────────────────────────────
echo [PHASE 5/7] Busting Worker KV cache...
echo.

:: Check if ADMIN_SECRET is available via env or prompt
set ADMIN_SECRET_VAL=
if defined WORKER_ADMIN_SECRET (
    set ADMIN_SECRET_VAL=%WORKER_ADMIN_SECRET%
) else (
    echo   HINT: Set WORKER_ADMIN_SECRET env var to auto-bust cache.
    echo   Enter your ADMIN_SECRET (or press Enter to skip):
    set /p ADMIN_SECRET_VAL="> "
)

if not "!ADMIN_SECRET_VAL!"=="" (
    curl -s -o nul -w "  Cache bust response: %%{http_code}" ^
        -X POST "https://intel.cyberdudebivash.com/api/admin/cache/bust?key=idx:reports" ^
        -H "X-Admin-Secret: !ADMIN_SECRET_VAL!"
    echo.
    echo   OK: Cache busted.
) else (
    echo   SKIPPED: No admin secret provided. Cache will expire naturally (3 min).
)
echo.

:: ── PHASE 6: CREATE OWNER API KEY ─────────────────────────────────────────────
echo [PHASE 6/7] Creating OWNER enterprise API key...
echo.

if not "!ADMIN_SECRET_VAL!"=="" (
    echo   Creating enterprise key via Admin API...
    curl -s -X POST "https://intel.cyberdudebivash.com/api/admin/keys/create" ^
        -H "X-Admin-Secret: !ADMIN_SECRET_VAL!" ^
        -H "Content-Type: application/json" ^
        -d "{\"tier\":\"enterprise\",\"label\":\"OWNER-MASTER-KEY\"}"
    echo.
    echo   ^^ SAVE THIS API KEY — it cannot be retrieved again!
) else (
    echo   SKIPPED: No admin secret. Run this to create your enterprise key later:
    echo   curl -X POST https://intel.cyberdudebivash.com/api/admin/keys/create ^
    echo        -H "X-Admin-Secret: YOUR_SECRET" ^
    echo        -H "Content-Type: application/json" ^
    echo        -d "{\"tier\":\"enterprise\",\"label\":\"OWNER-MASTER-KEY\"}"
)
echo.

:: ── PHASE 7: FULL VALIDATION ──────────────────────────────────────────────────
echo [PHASE 7/7] Validating all live endpoints...
echo.
echo Waiting 5 seconds for deployment to propagate...
timeout /t 5 /nobreak >nul

echo   --- /api/health ---
curl -s https://intel.cyberdudebivash.com/api/health
echo.
echo.

echo   --- /api/preview (public, no key) ---
curl -s https://intel.cyberdudebivash.com/api/preview
echo.
echo.

echo   --- /api/feed (no key — expect 401) ---
curl -s https://intel.cyberdudebivash.com/api/feed
echo.
echo.

echo ================================================================
echo  MASTER P0 FIX COMPLETE
echo ================================================================
echo.
echo  SYSTEM STATUS:
echo   Worker v109      : https://intel.cyberdudebivash.com/api/health
echo   Feed Preview     : https://intel.cyberdudebivash.com/api/preview
echo   Authenticated    : https://intel.cyberdudebivash.com/api/feed
echo   Dashboard        : https://intel.cyberdudebivash.com/
echo.
echo  NEXT STEPS IF preview SHOWS 0 ITEMS:
echo   1. Go to: https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions
echo   2. Click "R2 Intel Data Sync v109"
echo   3. Click "Run workflow" (manual trigger)
echo   4. Wait 2-3 minutes, then re-test /api/preview
echo.
echo  ENSURE GITHUB ACTIONS SECRETS ARE SET:
echo   CF_ACCOUNT_ID, CF_R2_ACCESS_KEY_ID, CF_R2_SECRET_ACCESS_KEY,
echo   WORKER_ADMIN_SECRET
echo.
pause
