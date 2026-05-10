@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
IF EXIST ".git\index.lock" del /f ".git\index.lock"
git fetch origin > push_v145_NEW.txt 2>&1
git rebase origin/main >> push_v145_NEW.txt 2>&1
git push origin HEAD >> push_v145_NEW.txt 2>&1
echo DONE >> push_v145_NEW.txt
git log --oneline -5 >> push_v145_NEW.txt 2>&1
