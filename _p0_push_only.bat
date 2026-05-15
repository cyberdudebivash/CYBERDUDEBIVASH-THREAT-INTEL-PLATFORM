@echo off
setlocal
echo ============================================================
echo  P0 v152.1 -- Push to origin/main
echo ============================================================
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

echo [1] Clearing ALL stale git locks...
if exist ".git\index.lock" ( del /f ".git\index.lock" && echo     Deleted index.lock )
if exist ".git\refs\heads\main.lock" ( del /f ".git\refs\heads\main.lock" && echo     Deleted main.lock )
if exist ".git\HEAD.lock" ( del /f ".git\HEAD.lock" && echo     Deleted HEAD.lock )
if exist ".git\COMMIT_EDITMSG.lock" ( del /f ".git\COMMIT_EDITMSG.lock" && echo     Deleted COMMIT_EDITMSG.lock )
echo     Lock cleanup done

echo.
echo [2] Local commit to push:
git log --oneline -1
echo.
echo [3] Pushing to origin/main (attempt 1)...
git push origin main
if errorlevel 1 (
    echo     Push attempt 1 failed -- retrying in 5s...
    timeout /t 5 /nobreak >nul
    echo     Push attempt 2...
    git push origin main
    if errorlevel 1 (
        echo     FAIL: Both push attempts failed
        goto :error
    )
)
echo.
echo [4] Verifying remote HEAD matches local...
for /f %%h in ('git rev-parse HEAD') do set LOCAL=%%h
echo     Local  HEAD: %LOCAL%
git ls-remote origin HEAD
echo.
echo ============================================================
echo  PUSH COMPLETE -- P0 FIX IS LIVE ON GITHUB
echo ============================================================
goto :done

:error
echo.
echo ============================================================
echo  PUSH FAILED -- See output above
echo ============================================================

:done
echo.
pause
endlocal
