@echo off
cd /d "C:\Users\Administrator\Desktop\cyberdudebivash-blog"
if exist ".git\index.lock" del /f ".git\index.lock"
git add index.html posts\cve-2026-33825-microsoft-defender-zero-day-bluehammer-redsun.html posts\cve-2026-35616-fortinet-forticlient-ems-zero-day.html posts\ai-llm-prompt-injection-enterprise-attack-surface-2026.html
git commit -m "feat: SENTINEL APEX — publish 3 enterprise threat intel reports + rebuild blog hub"
git push origin main
echo DONE > "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-SENTINEL-APEX\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\git_done.txt"
