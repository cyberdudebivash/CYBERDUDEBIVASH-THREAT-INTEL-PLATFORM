@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
set LOG=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\remote_verify.txt
echo ============================================================ > %LOG%
echo REMOTE VERIFY — %DATE% %TIME% >> %LOG%
echo ============================================================ >> %LOG%
echo. >> %LOG%

echo [FETCH latest from origin] >> %LOG%
git fetch origin >> %LOG% 2>&1
echo FETCH EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [REMOTE origin/main - last 8 commits] >> %LOG%
git log --oneline origin/main -8 >> %LOG% 2>&1
echo. >> %LOG%

echo [LOCAL HEAD position vs origin/main] >> %LOG%
echo Local ahead of remote: >> %LOG%
git log --oneline origin/main..HEAD >> %LOG% 2>&1
echo Local behind remote: >> %LOG%
git log --oneline HEAD..origin/main >> %LOG% 2>&1
echo. >> %LOG%

echo [NULL BYTE CHECK on origin/main version of generate_intel_reports.py] >> %LOG%
git show origin/main:scripts/generate_intel_reports.py > C:\Temp\remote_gir.py 2>&1
python3 -c "d=open('C:/Temp/remote_gir.py','rb').read();print(f'Remote file: {len(d)} bytes, {d.count(b\"\\x00\")} null bytes')" >> %LOG% 2>&1
echo. >> %LOG%

echo [PULL --rebase to sync local] >> %LOG%
git pull --rebase origin main >> %LOG% 2>&1
echo PULL EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [FINAL: local git log -5] >> %LOG%
git log --oneline -5 >> %LOG% 2>&1
echo ============================================================ >> %LOG%
echo DONE >> %LOG%

type %LOG%
pause
