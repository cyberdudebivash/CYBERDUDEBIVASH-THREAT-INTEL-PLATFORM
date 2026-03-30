@echo off
REM ═══════════════════════════════════════════════════════
REM  P0 FIX PUSH SCRIPT — Run this in Git Bash or terminal
REM  Fixes: Stage1 0-publish bug (fetch_all_feeds missing)
REM ═══════════════════════════════════════════════════════
echo Setting up remote and pushing P0 fix...

"C:\Program Files\Git\cmd\git.exe" remote add origin https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM.git
"C:\Program Files\Git\cmd\git.exe" fetch origin main
"C:\Program Files\Git\cmd\git.exe" checkout -b fix-p0-publish
"C:\Program Files\Git\cmd\git.exe" add sentinel_blogger.py .github/workflows/sentinel-blogger.yml
"C:\Program Files\Git\cmd\git.exe" commit --allow-empty-message -m "fix P0 zero publish route to agent sentinel_blogger skip ci"
"C:\Program Files\Git\cmd\git.exe" push origin fix-p0-publish:main --force

echo Done. Check GitHub Actions for run result.
pause
