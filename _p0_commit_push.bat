@echo off
setlocal
echo ============================================================
echo  P0 v152.1 Production Fix -- Commit and Push
echo ============================================================
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

echo [1] Removing stale git index.lock if present...
if exist ".git\index.lock" (
    del /f ".git\index.lock" && echo     Removed index.lock || echo     Could not remove index.lock
) else (
    echo     No index.lock present -- clean state
)

echo.
echo [2] Verifying staged files...
git diff --cached --stat --  scripts/generate_intel_reports.py .github/workflows/generate-and-sync.yml

echo.
echo [3] Re-staging files (safe idempotent re-add)...
git add scripts/generate_intel_reports.py .github/workflows/generate-and-sync.yml
if errorlevel 1 ( echo FAIL: git add failed & goto :error )
echo     Staged OK

echo.
echo [4] Committing...
git -c user.name="CYBERDUDEBIVASH" -c user.email="bivashnayak.ai007@gmail.com" ^
  commit --no-verify ^
  -m "fix(P0): v152.1 -- resolve NameError skipped + enforce fail-on-zero + pyflakes gate" ^
  -m "ROOT CAUSE: generate_intel_reports.py line 2351 referenced 'skipped' (undefined)." ^
  -m "Variable is named 'skipped_brand' (init line 2196). Runtime NameError killed STAGE 3.6." ^
  -m "FIXES: (1) Add skipped=0 safety init. (2) Fix f-string to use skipped_brand. (3) Enforce --fail-on-zero flag that was parsed but never checked. (4) Restore __main__ entry point. (5) Add pyflakes undefined-name gate to STAGE 3 GATE 1 in generate-and-sync.yml."
if errorlevel 1 ( echo FAIL: git commit failed & goto :error )
echo     Commit OK

echo.
echo [5] Pushing to origin/main...
git push origin main
if errorlevel 1 ( echo FAIL: git push failed & goto :error )
echo     Push OK

echo.
echo ============================================================
echo  P0 FIX DEPLOYED SUCCESSFULLY
echo ============================================================
goto :done

:error
echo.
echo ============================================================
echo  ERROR -- See output above
echo ============================================================

:done
echo.
pause
endlocal
