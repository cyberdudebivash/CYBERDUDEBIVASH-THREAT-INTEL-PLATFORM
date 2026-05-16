@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
echo [PUSH] Running git push origin main...
git push origin main
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Push completed successfully.
) else (
    echo [ERROR] Push failed with code %ERRORLEVEL%.
)
pause
