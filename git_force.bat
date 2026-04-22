@echo off
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
git merge --abort 2>nul
git push origin main --force
echo RESULT=%errorlevel%
