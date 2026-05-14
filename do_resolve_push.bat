@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
set LOG=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\resolve_push_result.txt

echo ============================================================ > %LOG%
echo RESOLVE + PUSH LOG -- %DATE% %TIME% >> %LOG%
echo ============================================================ >> %LOG%
echo. >> %LOG%

echo [1] Abort any in-progress rebase >> %LOG%
git rebase --abort >> %LOG% 2>&1
echo ABORT EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [2] Fetch latest remote state >> %LOG%
git fetch origin >> %LOG% 2>&1
echo FETCH EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [3] Reset HARD to origin/main (accept remote as truth for index.html) >> %LOG%
git reset --hard origin/main >> %LOG% 2>&1
echo RESET EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [4] Current HEAD after reset >> %LOG%
git log --oneline -3 >> %LOG% 2>&1
echo. >> %LOG%

echo [5] Run patch_ai_brain_news.py v153 to fix current index.html >> %LOG%
python3 scripts/patch_ai_brain_news.py >> %LOG% 2>&1
echo PATCHER EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [6] Run ci_preflight_check.py >> %LOG%
python3 scripts/ci_preflight_check.py >> %LOG% 2>&1
echo PREFLIGHT EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [7] Verify index.html is clean (line count + char count) >> %LOG%
python3 -c "html=open('index.html','r',encoding='utf-8').read(); lines=html.split('\n'); print('Lines:',len(lines)); print('Chars:',len(html))" >> %LOG% 2>&1
echo. >> %LOG%

echo [8] Stage patch_ai_brain_news.py and index.html >> %LOG%
git add scripts/patch_ai_brain_news.py index.html >> %LOG% 2>&1
echo ADD EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [9] Staged diff stat >> %LOG%
git diff --cached --stat >> %LOG% 2>&1
echo. >> %LOG%

echo [10] Commit >> %LOG%
git commit -m "fix(v153.0): P0 dashboard — remove orphaned raw-JS block + harden patcher" -m "index.html: removed orphaned AI Brain JS block (1114 lines, no script opener) that caused raw JavaScript to render as visible plain text after page footer." -m "scripts/patch_ai_brain_news.py: upgraded to v153.0.0 with two-pass orphan detection (_ORPHAN_RE) that permanently prevents recurrence of raw-JS-after-footer P0 bug. Patcher is now fully idempotent against legacy marker-less residue." >> %LOG% 2>&1
echo COMMIT EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [11] Push >> %LOG%
git push origin main >> %LOG% 2>&1
echo PUSH EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [12] Final git log -5 >> %LOG%
git log --oneline -5 >> %LOG% 2>&1
echo. >> %LOG%

echo ============================================================ >> %LOG%
echo DONE >> %LOG%

type %LOG%
pause
