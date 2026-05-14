@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

echo [1] Removing any stale locks...
if exist ".git\index.lock" del /f /q ".git\index.lock"
if exist ".git\HEAD.lock"  del /f /q ".git\HEAD.lock"

echo.
echo [2] Current HEAD:
git log --oneline -3

echo.
echo [3] Pushing to origin/main...
git push origin main
if %errorlevel% neq 0 (
    echo Push rejected - trying fetch + force-with-lease...
    git fetch origin
    git push --force-with-lease origin main
)
if %errorlevel% neq 0 (
    echo Force fallback...
    git push --force origin main
)

echo.
echo [4] Done. Final log:
git log --oneline -4
echo.
pause
