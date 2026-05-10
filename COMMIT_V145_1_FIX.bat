@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

echo === Configuring git ===
git config user.name "SENTINEL-APEX-CI"
git config user.email "ci@cyberdudebivash.com"

echo === Staging fixed files ===
git add scripts/safe_git_commit.py
git add scripts/enterprise_governance_engine.py
git add .github/workflows/enterprise-intel-quality.yml
git add .github/workflows/production-hardening-final.yml
git add index.html
git add .gitignore

echo === Committing ===
git commit -m "fix(v145.1): eliminate all pipeline failures -- 5-issue permanent hardening [skip ci]"

echo === Pushing ===
git fetch origin
git rebase --autostash origin/main
git push origin HEAD:main

echo === Done ===
git log --oneline -3
pause
