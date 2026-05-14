@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
echo ============================================================
echo CYBERDUDEBIVASH SENTINEL APEX — Push null-byte fix v152
echo ============================================================
echo.
echo [1/3] Current git log (last 3 commits):
git log --oneline -3
echo.
echo [2/3] Checking remote status...
git remote -v
echo.
echo [3/3] Pushing to origin/main...
git push origin main
echo.
echo ============================================================
echo DONE. Exit code: %ERRORLEVEL%
echo ============================================================
pause
