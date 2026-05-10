@echo off
SETLOCAL
SET REPO=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
SET LOG=%REPO%\push_result_v145.txt

cd /d "%REPO%"

echo REBASE-PUSH STARTED %DATE% %TIME% >> "%LOG%"

:: Remove stale lock
IF EXIST "%REPO%\.git\index.lock" (
    echo Removing stale lock... >> "%LOG%"
    del /f "%REPO%\.git\index.lock"
)

:: Fetch remote changes
echo. >> "%LOG%"
echo === git fetch === >> "%LOG%"
git fetch origin >> "%LOG%" 2>&1

:: Rebase local commit on top of remote
echo. >> "%LOG%"
echo === git rebase origin/main === >> "%LOG%"
git rebase origin/main >> "%LOG%" 2>&1
SET REBASE_EXIT=%ERRORLEVEL%
echo Rebase exit: %REBASE_EXIT% >> "%LOG%"

IF %REBASE_EXIT% NEQ 0 (
    echo Rebase failed -- aborting >> "%LOG%"
    git rebase --abort >> "%LOG%" 2>&1
    goto :done
)

:: Push
echo. >> "%LOG%"
echo === git push === >> "%LOG%"
git push origin HEAD >> "%LOG%" 2>&1
SET PUSH_EXIT=%ERRORLEVEL%
echo Push exit: %PUSH_EXIT% >> "%LOG%"

IF %PUSH_EXIT% EQU 0 (
    echo. >> "%LOG%"
    echo RESULT: SUCCESS >> "%LOG%"
) ELSE (
    echo. >> "%LOG%"
    echo RESULT: FAILED >> "%LOG%"
)

echo. >> "%LOG%"
echo === Final log (remote) === >> "%LOG%"
git log --oneline origin/main -5 >> "%LOG%" 2>&1

:done
echo REBASE-PUSH DONE %DATE% %TIME% >> "%LOG%"
echo. >> "%LOG%"
ENDLOCAL
