@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
echo [PULL REBASE]
git pull --rebase origin main
echo PULL EXIT: %ERRORLEVEL%
echo.
echo [PUSH]
git push origin main
echo PUSH EXIT: %ERRORLEVEL%
echo.
echo [FINAL LOG]
git log --oneline -5
echo.
echo DONE
pause
