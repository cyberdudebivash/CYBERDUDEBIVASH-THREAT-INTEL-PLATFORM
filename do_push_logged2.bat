@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
set LOG=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\push_result_v2.txt
echo ============================================================ > %LOG%
echo PUSH LOG — %DATE% %TIME% >> %LOG%
echo ============================================================ >> %LOG%
echo. >> %LOG%
echo [LOCAL COMMITS NOT ON REMOTE] >> %LOG%
git log --oneline origin/main..HEAD >> %LOG% 2>&1
echo. >> %LOG%
echo [PUSHING origin main] >> %LOG%
git push origin main >> %LOG% 2>&1
echo EXIT CODE: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%
echo [POST-PUSH: REMOTE HEAD] >> %LOG%
git log --oneline -3 >> %LOG% 2>&1
echo ============================================================ >> %LOG%
echo DONE >> %LOG%
type %LOG%
pause
