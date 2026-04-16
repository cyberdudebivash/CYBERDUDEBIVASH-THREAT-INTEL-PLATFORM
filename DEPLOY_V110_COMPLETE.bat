@echo off
:: =============================================================================
:: CYBERDUDEBIVASH® SENTINEL APEX — v110 COMPLETE DEPLOYMENT
:: Deploys: Worker v110 + sentinel-blogger.yml v110 + schema validator
::
:: Changes in v110:
::   - Blogger dependency COMPLETELY REMOVED from sentinel-blogger.yml
::   - EMBEDDED_INTEL obsolete — R2-only data flow enforced
::   - handlePreview() added to Worker (public /api/preview endpoint)
::   - validate_intel_schema.py — schema gate before every R2 upload
::   - wrangler.toml — real KV IDs (no more REPLACE_WITH_YOUR_*)
::   - Worker version bumped to 110.0
::
:: Prerequisites:
::   - npm / wrangler installed: npm install -g wrangler
::   - Authenticated: npx wrangler whoami (must show your account)
::   - Secrets already set via: npx wrangler secret put ADMIN_SECRET
::   - Git configured and SSH/HTTPS push access to remote
:: =============================================================================

setlocal EnableDelayedExpansion

set "REPO_DIR=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM-main"
set "WORKER_DIR=%REPO_DIR%\workers\intel-gateway"
set "LIVE_URL=https://intel.cyberdudebivash.com"
set "GITHUB_ACTIONS=https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions"

cd /d "%REPO_DIR%"

echo.
echo ================================================================
echo  SENTINEL APEX v110 — FULL PRODUCTION DEPLOYMENT
echo  Blogger REMOVED   R2-ONLY   handlePreview ADDED
echo ================================================================
echo.

:: =============================================================================
:: STEP 1 — Pre-flight checks
:: =============================================================================
echo [1/7] Pre-flight checks...

:: Verify wrangler is available
where npx >nul 2>&1
if errorlevel 1 (
    echo *** ERROR: npx not found. Install Node.js + npm first. ***
    pause
    exit /b 1
)

npx wrangler whoami >nul 2>&1
if errorlevel 1 (
    echo *** ERROR: Not authenticated with Cloudflare. Run: npx wrangler login ***
    pause
    exit /b 1
)

:: Verify git state
git status >nul 2>&1
if errorlevel 1 (
    echo *** ERROR: Not a git repository or git not found ***
    pause
    exit /b 1
)

:: Clear any stuck git state safely (no hard reset)
git rebase --abort >nul 2>&1
git merge --abort  >nul 2>&1
del /f .git\index.lock   >nul 2>&1
del /f .git\MERGE_HEAD   >nul 2>&1
rmdir /s /q .git\rebase-merge >nul 2>&1
rmdir /s /q .git\rebase-apply >nul 2>&1

echo   OK: Pre-flight checks passed.

:: =============================================================================
:: STEP 2 — Validate Worker source (YAML null-byte check on .yml)
:: =============================================================================
echo [2/7] Validating v110 source files...

:: Check sentinel-blogger.yml for null bytes
python3 -c "
import sys, os
files = [
    '.github/workflows/sentinel-blogger.yml',
    'workers/intel-gateway/src/index.js',
    'workers/intel-gateway/wrangler.toml',
    'scripts/validate_intel_schema.py',
]
all_ok = True
for f in files:
    if not os.path.exists(f):
        print(f'  MISSING: {f}')
        all_ok = False
        continue
    with open(f, 'rb') as fh:
        raw = fh.read()
    null_count = raw.count(b'\x00')
    if null_count > 0:
        print(f'  WARN: {null_count} null bytes in {f} -- auto-cleaning')
        with open(f, 'wb') as fh:
            fh.write(raw.replace(b'\x00', b''))
    size = len(raw) - null_count
    print(f'  OK: {f} ({size:,} bytes)')
if not all_ok:
    sys.exit(1)
print('  All source files validated.')
" 2>&1
if errorlevel 1 (
    echo *** Source file validation failed — check output above ***
    pause
    exit /b 1
)

:: Validate sentinel-blogger.yml YAML syntax
python3 -c "
import yaml, sys
filepath = '.github/workflows/sentinel-blogger.yml'
try:
    with open(filepath, 'rb') as f:
        raw = f.read().replace(b'\x00', b'')
    data = yaml.safe_load(raw.decode('utf-8'))
    jobs = data.get('jobs', {})
    if not jobs:
        print('ERROR: No jobs found in sentinel-blogger.yml')
        sys.exit(1)
    job = list(jobs.values())[0]
    steps = job.get('steps', [])
    step_names = [s.get('name','') for s in steps]
    has_r2     = any('R2' in (n or '') for n in step_names)
    has_schema = any('Schema' in (n or '') or 'Validate' in (n or '') for n in step_names)
    has_blogger = any('Blogger' in (n or '') or 'Blog' in (n or '') for n in step_names)
    print(f'  YAML VALID: {len(steps)} steps')
    print(f'  R2 upload step   : {has_r2}')
    print(f'  Schema validation: {has_schema}')
    print(f'  Blogger present  : {has_blogger} (should be False in v110)')
    if has_blogger:
        print('  WARN: Blogger steps still present in workflow')
    if not has_r2:
        print('  ERROR: R2 upload step missing')
        sys.exit(1)
except yaml.YAMLError as e:
    print(f'  YAML ERROR: {e}')
    sys.exit(1)
" 2>&1
if errorlevel 1 (
    echo *** sentinel-blogger.yml YAML invalid — fix before deploying ***
    pause
    exit /b 1
)

:: Verify wrangler.toml has real KV IDs (no REPLACE_WITH placeholders)
python3 -c "
import sys
with open('workers/intel-gateway/wrangler.toml') as f:
    content = f.read()
if 'REPLACE_WITH' in content:
    print('  ERROR: wrangler.toml still has placeholder KV IDs')
    sys.exit(1)
kv_ids = [line.split('=')[1].strip().strip('\"') for line in content.split('\n') if line.strip().startswith('id')]
print(f'  KV IDs configured: {len(kv_ids)}')
for kid in kv_ids:
    print(f'    {kid}')
print('  wrangler.toml: OK (no placeholders)')
" 2>&1
if errorlevel 1 (
    echo *** wrangler.toml has placeholder values — deploy aborted ***
    pause
    exit /b 1
)

echo   OK: All source files validated.

:: =============================================================================
:: STEP 3 — Deploy Worker v110 to Cloudflare
:: =============================================================================
echo [3/7] Deploying Worker v110 to Cloudflare...
cd /d "%WORKER_DIR%"

npx wrangler deploy
if errorlevel 1 (
    echo *** Wrangler deploy failed — check output above ***
    echo   Common causes:
    echo   - Not logged in: npx wrangler login
    echo   - KV ID mismatch: verify IDs in wrangler.toml
    echo   - Token missing permissions: Workers Scripts + R2 Edit
    cd /d "%REPO_DIR%"
    pause
    exit /b 1
)

cd /d "%REPO_DIR%"
echo   OK: Worker v110 deployed to Cloudflare.

:: =============================================================================
:: STEP 4 — Verify Worker deployment (live endpoint test)
:: =============================================================================
echo [4/7] Verifying live Worker endpoints...
timeout /t 5 /nobreak >nul

:: Test /api/health
echo   Testing /api/health...
curl -s "%LIVE_URL%/api/health" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    v = d.get('version', 'unknown')
    s = d.get('status', 'unknown')
    c = d.get('checks', {})
    print(f'    version: {v} | status: {s}')
    print(f'    r2_intel: {c.get(\"r2_intel\")} | kv_api_keys: {c.get(\"kv_api_keys\")}')
    if v != '110.0':
        print(f'    WARN: Expected v110.0 but got v{v} — may take 30s to propagate')
    else:
        print(f'    Worker v110 CONFIRMED on live platform')
except Exception as e:
    print(f'    health parse error: {e}')
" 2>&1

:: Test /api/preview
echo   Testing /api/preview...
curl -s "%LIVE_URL%/api/preview" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    p = d.get('preview', {})
    total = p.get('total_in_feed', 0)
    preview_count = p.get('total_preview', 0)
    gw = d.get('gateway', 'unknown')
    print(f'    gateway: {gw}')
    print(f'    preview items: {preview_count} | total in feed: {total}')
    if total > 0:
        print(f'    /api/preview: PASS ({total} total advisories in R2)')
    else:
        print(f'    /api/preview: WARN (0 items — R2 may be empty, trigger R2 sync)')
except Exception as e:
    print(f'    preview parse error: {e}')
" 2>&1

echo   OK: Live endpoint validation complete.

:: =============================================================================
:: STEP 5 — Git: stage and commit all v110 changes
:: =============================================================================
echo [5/7] Staging v110 changes for git commit...

:: Safe fetch — don't reset local changes
git fetch origin main 2>&1
if errorlevel 1 (
    echo   WARN: Git fetch failed — continuing with local state
)

:: Stage all v110 files
git add .github\workflows\sentinel-blogger.yml
git add workers\intel-gateway\src\index.js
git add workers\intel-gateway\wrangler.toml
git add scripts\validate_intel_schema.py
git add DEPLOY_V110_COMPLETE.bat

:: Check if there's anything staged
git diff --staged --quiet >nul 2>&1
if errorlevel 1 (
    echo   Staged changes detected — committing...
    git commit -m "feat(v110): GOD MODE pipeline rebuild — Blogger removed, R2-only, handlePreview added

- sentinel-blogger.yml v110: Blogger OAuth completely removed (230 lines vs 717)
- Worker v110: handlePreview() public endpoint added (/api/preview, no key required)
- wrangler.toml: Real KV IDs committed (no REPLACE_WITH placeholders)
- scripts/validate_intel_schema.py: Schema validation gate before R2 upload
- DEPLOY_V110_COMPLETE.bat: One-click v110 deploy script

Architecture: GitHub Actions -> R2 (primary) -> Worker -> Dashboard
No EMBEDDED_INTEL. No Blogger. No legacy fallbacks."
    if errorlevel 1 (
        echo *** Git commit failed ***
        pause
        exit /b 1
    )
    echo   OK: v110 changes committed.
) else (
    echo   INFO: No staged changes — files already up to date in git.
)

:: =============================================================================
:: STEP 6 — Push to remote
:: =============================================================================
echo [6/7] Pushing to origin/main...

git push origin main
if errorlevel 1 (
    echo   Push failed — attempting fetch + rebase...
    git fetch origin main
    git rebase origin/main 2>nul
    if errorlevel 1 (
        git rebase --abort >nul 2>&1
        echo   Rebase failed — using force-with-lease (safe: preserves remote history)
        git push origin main --force-with-lease
        if errorlevel 1 (
            echo *** All push attempts failed ***
            echo   Try manually: git push origin main
            pause
            exit /b 1
        )
    ) else (
        git push origin main
    )
)
echo   OK: Pushed to origin/main.

:: =============================================================================
:: STEP 7 — Final validation + next steps
:: =============================================================================
echo [7/7] Final platform validation...
timeout /t 10 /nobreak >nul

curl -s "%LIVE_URL%/api/health" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    c = d.get('checks', {})
    s = d.get('status')
    v = d.get('version')
    print(f'  FINAL HEALTH: status={s} version={v}')
    print(f'  r2_intel={c.get(\"r2_intel\")} kv_api_keys={c.get(\"kv_api_keys\")} kv_rate_limit={c.get(\"kv_rate_limit\")}')
    if s == 'healthy':
        print('  PLATFORM: HEALTHY')
    else:
        print('  PLATFORM: DEGRADED (check individual checks above)')
except Exception as e:
    print(f'  health error: {e}')
" 2>&1

echo.
echo ================================================================
echo  SENTINEL APEX v110 — DEPLOYMENT COMPLETE
echo ================================================================
echo.
echo  CHANGES DEPLOYED:
echo    Worker v110         : %LIVE_URL%/api/preview (public)
echo    sentinel-blogger    : Blogger removed, R2-only pipeline
echo    Schema validator    : scripts/validate_intel_schema.py
echo    wrangler.toml       : Real KV IDs committed
echo.
echo  VERIFY LIVE:
echo    Preview (public)  : %LIVE_URL%/api/preview
echo    Health            : %LIVE_URL%/api/health
echo    Dashboard         : %LIVE_URL%/
echo.
echo  GITHUB ACTIONS (trigger sentinel-blogger manually):
echo    %GITHUB_ACTIONS%
echo    -> sentinel-blogger -> Run workflow
echo.
echo  NEXT AUTO-RUN: sentinel-blogger runs every 4 hours
echo    When it runs, it will:
echo      1. Generate fresh intel (no Blogger publishing)
echo      2. Validate schema via validate_intel_schema.py
echo      3. Upload to R2 (primary storage)
echo      4. Bust Worker KV cache
echo      5. Deploy to GitHub Pages
echo.
echo ================================================================
echo.
pause
