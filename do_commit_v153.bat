@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
set LOG=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\commit_v153_result.txt

echo ============================================================ > %LOG%
echo COMMIT v153 LOG — %DATE% %TIME% >> %LOG%
echo ============================================================ >> %LOG%
echo. >> %LOG%

echo [1] Pull --rebase to sync remote >> %LOG%
git pull --rebase origin main >> %LOG% 2>&1
echo PULL EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [2] git status before staging >> %LOG%
git status --short >> %LOG% 2>&1
echo. >> %LOG%

echo [3] Stage the two fixed files >> %LOG%
git add index.html scripts/patch_ai_brain_news.py >> %LOG% 2>&1
echo ADD EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [4] Un-stage / remove temp bat files from tracking (if tracked) >> %LOG%
git rm --cached do_push_fix_v152.bat do_push_logged2.bat verify_remote_state.bat push_result_v2.txt remote_verify.txt 2>>%LOG%
git reset HEAD do_push_fix_v152.bat do_push_logged2.bat verify_remote_state.bat push_result_v2.txt remote_verify.txt 2>>%LOG%
echo. >> %LOG%

echo [5] Staged diff summary >> %LOG%
git diff --cached --stat >> %LOG% 2>&1
echo. >> %LOG%

echo [6] Commit >> %LOG%
git commit -m "fix(v153.0): P0 dashboard — remove orphaned raw-JS block + harden patcher" -m "index.html: removed 1114-line orphaned AI Brain JS block (lines 15210-16240) that had no <script> opener, causing raw JavaScript source code to render as visible plain text after the page footer." -m "scripts/patch_ai_brain_news.py: upgraded to v153.0.0 — added two-pass orphan detection (_ORPHAN_RE regex) that fingerprints and strips Micro-utilities blocks not enclosed in CDB-AI-BRAIN-INIT markers. Patcher is now fully idempotent against legacy marker-less residue. Prevents recurrence of the raw-JS-after-footer P0 bug." >> %LOG% 2>&1
echo COMMIT EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [7] Push >> %LOG%
git push origin main >> %LOG% 2>&1
echo PUSH EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [8] Final git log -5 >> %LOG%
git log --oneline -5 >> %LOG% 2>&1
echo. >> %LOG%

echo ============================================================ >> %LOG%
echo DONE >> %LOG%

type %LOG%
pause
