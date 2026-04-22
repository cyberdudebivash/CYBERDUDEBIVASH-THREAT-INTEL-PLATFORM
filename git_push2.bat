@echo off
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
git remote add origin https://github.com/cyberdudebivash/cyberdudebivash-blog.git
git remote -v
git push -u origin main
echo EXIT_CODE=%errorlevel% > "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\push_result.txt"
