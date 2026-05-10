@echo off
SETLOCAL
SET REPO=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM

echo ============================================================
echo  SENTINEL APEX v145 -- Pushing commit to GitHub
echo ============================================================

cd /d "%REPO%"

echo Current HEAD:
git log --oneline -3

echo.
echo Pushing to origin...

FOR /L %%i IN (1,1,3) DO (
    git push origin HEAD
    IF %ERRORLEVEL% EQU 0 (
        echo.
        echo ============================================================
        echo  SUCCESS: Pushed to GitHub
        echo ============================================================
        goto :done
    )
    echo Push attempt %%i failed -- rebasing...
    git pull --rebase origin HEAD
)

echo ERROR: All push attempts failed.

:done
echo.
pause
ENDLOCAL
