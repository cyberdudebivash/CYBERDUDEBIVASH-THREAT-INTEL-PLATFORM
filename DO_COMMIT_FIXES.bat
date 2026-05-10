@echo off
SETLOCAL

SET REPO=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM

echo ============================================================
echo  SENTINEL APEX v145 -- Committing all production fixes
echo ============================================================

cd /d "%REPO%"

:: Remove stale git lock if it exists
IF EXIST "%REPO%\.git\index.lock" (
    echo Removing stale git lock file...
    del /f "%REPO%\.git\index.lock"
)

:: Configure git identity
git config user.name "SENTINEL-APEX-CI"
git config user.email "ci@cyberdudebivash.com"

:: Stage all fixed files
echo.
echo Staging fixed files...
git add scripts/generate_intel_reports.py
git add scripts/intel_quality_engine.py
git add scripts/patch_ai_brain_news.py
git add workers/intel-gateway/src/index.js
git add workers/intel-gateway/src/dark-web-monitor.js
git add workers/intel-gateway/src/alert-engine.js
git add .github/workflows/production-hardening-final.yml

:: Show what will be committed
echo.
echo === Files staged for commit ===
git diff --cached --stat
echo.

:: Commit
git commit -m "fix(v145): 6-issue permanent production hardening [skip ci]

- generate_intel_reports.py: CVSS/EPSS N/A bug fixed -- falsy 0.0 check
  replaced with explicit None check; scores now show numeric values
  (0.0+) and display 'Pending' only when genuinely absent from NVD

- intel_quality_engine.py: added --report argparse flag; sentinel-blogger
  workflow line 711 'python3 scripts/intel_quality_engine.py --report'
  no longer raises 'unrecognized arguments: --report'

- patch_ai_brain_news.py: full rewrite with regex-based marker detection
  (v145.0.0); version-agnostic -- strips any CDB-AI-BRAIN-INIT-vX block;
  eliminates '</body> not found' pipeline failure from v134/v150.1
  end-marker mismatch

- workers/intel-gateway/src/index.js: GATEWAY_VERSION bumped 143->145;
  feed_index health check now reads from SECURITY_HUB_KV (correct KV
  where cron writes idx:reports) instead of RATE_LIMIT_KV (was always
  empty); kv_rate_limit ping retried once before downgrading to 'warn';
  JSON feed KV fallback also corrected to SECURITY_HUB_KV

- workers/intel-gateway/src/{dark-web-monitor,alert-engine}.js:
  VERSION constants updated to 145.0.0

- .github/workflows/production-hardening-final.yml: git push retry loop
  (3 attempts with --rebase on conflict) replaces bare 'git push' that
  silently failed on concurrent workflow merge conflicts"

IF %ERRORLEVEL% NEQ 0 (
    echo.
    echo [INFO] Nothing new to commit -- all changes already committed.
    goto :push
)

:push
echo.
echo === Pushing to origin ===

:: Retry push up to 3 times with rebase
FOR /L %%i IN (1,1,3) DO (
    git push origin HEAD
    IF %ERRORLEVEL% EQU 0 (
        echo.
        echo ============================================================
        echo  SUCCESS: All fixes pushed to GitHub
        echo ============================================================
        goto :done
    )
    echo Push attempt %%i failed -- rebasing...
    git pull --rebase origin HEAD
)

echo.
echo ERROR: All push attempts failed. Check network and try again.
goto :done

:done
echo.
pause
ENDLOCAL
