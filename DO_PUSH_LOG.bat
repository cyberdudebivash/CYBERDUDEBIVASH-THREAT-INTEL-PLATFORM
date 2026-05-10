@echo off
SETLOCAL
SET REPO=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
SET LOG=%REPO%\push_result_v145.txt

cd /d "%REPO%"

echo PUSH STARTED %DATE% %TIME% > "%LOG%"
echo. >> "%LOG%"

echo === Current HEAD === >> "%LOG%"
git log --oneline -3 >> "%LOG%" 2>&1

echo. >> "%LOG%"
echo === Pushing... === >> "%LOG%"

git push origin HEAD >> "%LOG%" 2>&1
SET PUSH_EXIT=%ERRORLEVEL%

echo. >> "%LOG%"
echo Push exit code: %PUSH_EXIT% >> "%LOG%"

IF %PUSH_EXIT% EQU 0 (
    echo RESULT: SUCCESS >> "%LOG%"
) ELSE (
    echo RESULT: FAILED -- trying rebase >> "%LOG%"
    git pull --rebase origin HEAD >> "%LOG%" 2>&1
    git push origin HEAD >> "%LOG%" 2>&1
    SET PUSH_EXIT2=%ERRORLEVEL%
    echo Second push exit: %PUSH_EXIT2% >> "%LOG%"
    IF %PUSH_EXIT2% EQU 0 (
        echo RESULT: SUCCESS (after rebase) >> "%LOG%"
    ) ELSE (
        echo RESULT: FAILED BOTH ATTEMPTS >> "%LOG%"
    )
)

echo. >> "%LOG%"
echo === Remote log after push === >> "%LOG%"
git log --oneline origin/main -5 >> "%LOG%" 2>&1

echo PUSH DONE %DATE% %TIME% >> "%LOG%"
ENDLOCAL
