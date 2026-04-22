@echo off
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
git pull origin main --allow-unrelated-histories
git push -u origin main
echo PUSH_DONE > "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\push_result.txt"
