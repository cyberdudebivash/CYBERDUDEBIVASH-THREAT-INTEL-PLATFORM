@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
IF EXIST ".git\index.lock" del /f ".git\index.lock"
echo Starting... > push_final.txt
git log --oneline -3 >> push_final.txt 2>&1
echo. >> push_final.txt
echo Fetching... >> push_final.txt
git fetch origin >> push_final.txt 2>&1
echo Fetch exit: %ERRORLEVEL% >> push_final.txt
echo. >> push_final.txt
echo Rebasing (autostash)... >> push_final.txt
git rebase --autostash origin/main >> push_final.txt 2>&1
echo Rebase exit: %ERRORLEVEL% >> push_final.txt
echo. >> push_final.txt
echo Pushing... >> push_final.txt
git push origin HEAD >> push_final.txt 2>&1
echo Push exit: %ERRORLEVEL% >> push_final.txt
echo. >> push_final.txt
echo Remote log: >> push_final.txt
git log --oneline origin/main -5 >> push_final.txt 2>&1
echo DONE >> push_final.txt
