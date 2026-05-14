@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
set LOG=C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM\final_commit_result.txt

echo ============================================================ > %LOG%
echo FINAL COMMIT v153 LOG -- %DATE% %TIME% >> %LOG%
echo ============================================================ >> %LOG%
echo. >> %LOG%

echo [1] Current HEAD >> %LOG%
git log --oneline -3 >> %LOG% 2>&1
echo. >> %LOG%

echo [2] Run patcher (python) >> %LOG%
python scripts\patch_ai_brain_news.py >> %LOG% 2>&1
echo PATCHER EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [3] Run ci_preflight_check (python) >> %LOG%
python scripts\ci_preflight_check.py >> %LOG% 2>&1
echo PREFLIGHT EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [4] Verify index.html structure >> %LOG%
python -c "import re; h=open('index.html','r',encoding='utf-8').read(); lines=h.split('\n'); print('Lines:',len(lines)); print('Chars:',len(h)); print('</body>:',h.count('</body>')); print('</html>:',h.count('</html>')); sb=list(re.finditer(r'<script[\s>].*?</script>',h,re.DOTALL|re.IGNORECASE)); iife=[m.start() for m in re.finditer(r'\}\)\(\);',h)]; out=[p for p in iife if not any(s.start()<=p<=s.end() for s in sb)]; print('Raw JS outside script:',len(out))" >> %LOG% 2>&1
echo. >> %LOG%

echo [5] git status >> %LOG%
git status --short >> %LOG% 2>&1
echo. >> %LOG%

echo [6] Stage index.html and patch_ai_brain_news.py >> %LOG%
git add index.html scripts\patch_ai_brain_news.py >> %LOG% 2>&1
echo ADD EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [7] Staged diff stat >> %LOG%
git diff --cached --stat >> %LOG% 2>&1
echo. >> %LOG%

echo [8] Commit >> %LOG%
git commit -m "fix(v153.0): P0 dashboard — repair truncated HTML + remove orphaned JS + harden patcher" -m "index.html: repaired remote file that was truncated mid-script (missing </body></html>). Removed 959 lines of orphaned AI Brain JS block that had no <script> opener, causing raw JavaScript source code to render as visible plain text after page footer. Re-injected AI Brain block properly wrapped with CDB-AI-BRAIN-INIT markers." -m "scripts/patch_ai_brain_news.py: upgraded to v153.0.0 with two-pass orphan detection (_ORPHAN_RE) that permanently prevents recurrence of raw-JS-after-footer P0 bug. Patcher is now fully idempotent against legacy marker-less residue." >> %LOG% 2>&1
echo COMMIT EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [9] Push >> %LOG%
git push origin main >> %LOG% 2>&1
echo PUSH EXIT: %ERRORLEVEL% >> %LOG%
echo. >> %LOG%

echo [10] Final git log -5 >> %LOG%
git log --oneline -5 >> %LOG% 2>&1
echo. >> %LOG%

echo ============================================================ >> %LOG%
echo DONE >> %LOG%

type %LOG%
pause
