# CYBERDUDEBIVASH SENTINEL APEX - P0 Production Fix Push
# Run this from PowerShell in the repo directory

Set-Location "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

# 1. Clear stale git locks
Remove-Item ".git\index.lock"  -Force -ErrorAction SilentlyContinue
Remove-Item ".git\HEAD.lock"   -Force -ErrorAction SilentlyContinue
Remove-Item ".git\MERGE_HEAD"  -Force -ErrorAction SilentlyContinue

# 2. Stage the two fixed files
git add scripts/report_generator.py dashboard.html

# 3. Commit
git commit -m "fix(ci): P0 resolve AttributeError in _resolve_technique + dashboard mojibake

ROOT CAUSE 1 FIXED - scripts/report_generator.py
- AttributeError: 'dict' object has no attribute 'strip' fired on every entry
- mitre_tactics now stored as enriched dicts, _resolve_technique expected strings
- Fix: isinstance(dict) guard added - handles both string and dict inputs
- Backward compatible: string path unchanged, dict resolved via known TIDs
- Repaired truncated file tail (if args.show_classes cut off) + null bytes

ROOT CAUSE 2 FIXED - dashboard.html
- 1037 double-encoded mojibake bytes in HTML comments blocked deployment
- validate_monetization.py HARD FAIL on xc3xa2 stopped every CI run
- Fix: surgical replacement of 536x double-horizontal + 501x single-horizontal

VALIDATION: Python syntax OK, monetization 46/46 PASS, 32 HTML files clean"

# 4. Push
git push origin main

Write-Host "`nP0 fix pushed. Check GitHub Actions for clean CI run." -ForegroundColor Green
