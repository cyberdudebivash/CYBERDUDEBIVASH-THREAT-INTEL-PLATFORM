@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
set LOGFILE=v152_push_result.txt
echo. > %LOGFILE%
echo === v152 PUSH LOG === >> %LOGFILE%
echo %DATE% %TIME% >> %LOGFILE%

echo [1] Lock cleanup >> %LOGFILE%
if exist ".git\index.lock" (del /f /q ".git\index.lock" && echo Removed index.lock >> %LOGFILE%)
if exist ".git\HEAD.lock"  (del /f /q ".git\HEAD.lock"  && echo Removed HEAD.lock >> %LOGFILE%)

echo [2] HEAD before push >> %LOGFILE%
git log --oneline -3 >> %LOGFILE% 2>&1

echo [3] Pushing to origin/main >> %LOGFILE%
git push origin main >> %LOGFILE% 2>&1
set PUSH1=%errorlevel%
echo Push exit: %PUSH1% >> %LOGFILE%

if %PUSH1% neq 0 (
    echo Push rejected, trying force... >> %LOGFILE%
    git fetch origin >> %LOGFILE% 2>&1
    git push --force origin main >> %LOGFILE% 2>&1
    set PUSH2=%errorlevel%
    echo Force push exit: %PUSH2% >> %LOGFILE%
)

echo [4] Remote HEAD >> %LOGFILE%
git ls-remote origin HEAD >> %LOGFILE% 2>&1

echo [5] Done >> %LOGFILE%
echo %DATE% %TIME% >> %LOGFILE%
echo Push script completed. Check v152_push_result.txt for results.
