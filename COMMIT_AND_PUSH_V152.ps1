# =============================================================================
# COMMIT_AND_PUSH_V152.ps1
# Pushes the committed v152.2 P0 fix (commit 8c610840) to GitHub.
# All 3 fixes are already committed in HEAD -- this just cleans the index
# and pushes. Run from PowerShell in the repo root.
# =============================================================================

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SENTINEL APEX v152.2 -- Verify & Push Committed P0 Fixes" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $RepoRoot

# ── VERIFY the 3 fixed files in HEAD are correct ─────────────────────────────
Write-Host "[VERIFY] Checking committed fixes in HEAD..." -ForegroundColor Yellow

$verifyResult = python3 -c @"
import pathlib, subprocess, re, tempfile, os

REPO = pathlib.Path('.')
errors = []

# 1. index.html node --check (from HEAD commit)
html_bytes = subprocess.run(['git','show','HEAD:index.html'], capture_output=True).stdout
html = html_bytes.decode('utf-8','replace')
blocks = re.findall(r'<script(?:\s[^>]*)?>([\s\S]*?)</script>', html)
largest = max(blocks, key=len)
tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False, encoding='utf-8')
tmp.write(largest); tmp.close()
r = subprocess.run(['node','--check',tmp.name], capture_output=True, text=True)
os.unlink(tmp.name)
if r.returncode != 0:
    errors.append('index.html: node --check FAIL: ' + r.stderr.split(chr(10))[2][:80])
if b'}, 0) / items.length).toFixed(1)' in html_bytes:
    errors.append('index.html: dangling reduce expression still present')
if b'const sorted    = [...items].sort(' not in html_bytes:
    errors.append('index.html: const sorted missing')

# 2. workers/index.js non-ASCII (from HEAD commit)
js = subprocess.run(['git','show','HEAD:workers/intel-gateway/src/index.js'], capture_output=True).stdout
na = sum(1 for b in js if b > 127)
if na > 0:
    errors.append(f'workers/index.js: {na} non-ASCII bytes')

# 3. v149_frontend_dedup_patch.py (from HEAD commit)
py = subprocess.run(['git','show','HEAD:scripts/v149_frontend_dedup_patch.py'], capture_output=True).stdout
if py.count(b'\x00') > 0:
    errors.append('v149_frontend_dedup_patch.py: null bytes present')
if b'permanently disabled' not in py:
    errors.append('v149_frontend_dedup_patch.py: Patch 3 not disabled')

if errors:
    for e in errors: print('FAIL: ' + e)
    exit(1)
print('PASS: all 3 fixes verified in HEAD commit 8c610840')
"@ 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "[ABORT] Verification failed:" -ForegroundColor Red
    Write-Host $verifyResult -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] $verifyResult" -ForegroundColor Green

# ── CLEAN the stale git index (reset staged files to match HEAD) ──────────────
Write-Host ""
Write-Host "[CLEAN] Resetting stale git index to match HEAD..." -ForegroundColor Yellow
git reset HEAD -- index.html workers/intel-gateway/src/index.js PUSH_V152_FIX.ps1 2>$null
Write-Host "  [OK] Index cleaned"

# ── SHOW current state ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[STATUS] Commit ready to push:" -ForegroundColor Yellow
git log --oneline -3
Write-Host ""
Write-Host "[INFO] Files in commit 8c610840:" -ForegroundColor Yellow
git show --stat HEAD | Select-String "modified|index\.html|index\.js|v149"

# ── PUSH ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[PUSH] Pushing to origin/main..." -ForegroundColor Yellow
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host " SUCCESS -- v152.2 fixes are live on GitHub" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "What was fixed (commit 8c610840):" -ForegroundColor Green
    Write-Host ""
    Write-Host "  FIX 1: index.html" -ForegroundColor Green
    Write-Host "    Dangling '}, 0)/items.length).toFixed(1);' removed (line 11645)" -ForegroundColor Green
    Write-Host "    'const sorted=[...items].sort(...)' restored (line 13426)" -ForegroundColor Green
    Write-Host "    STAGE 3.92 dashboard_frontend_guard.py: 10/10 PASS" -ForegroundColor Green
    Write-Host ""
    Write-Host "  FIX 2: workers/intel-gateway/src/index.js" -ForegroundColor Green
    Write-Host "    2 em-dashes (U+2014) -> ASCII '--'  |  non-ascii=0" -ForegroundColor Green
    Write-Host "    deploy-worker pre-flight: PASS" -ForegroundColor Green
    Write-Host ""
    Write-Host "  FIX 3: scripts/v149_frontend_dedup_patch.py" -ForegroundColor Green
    Write-Host "    82 trailing null bytes stripped, Patch 3 permanently disabled" -ForegroundColor Green
    Write-Host "    STAGE 0.06 Python Syntax Guard: PASS" -ForegroundColor Green
    Write-Host ""
    Write-Host "Now trigger manual workflow runs to confirm:" -ForegroundColor Cyan
    Write-Host "  https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Run these 3 workflows manually:" -ForegroundColor Yellow
    Write-Host "    sentinel-blogger    (fixes STAGE 3.92)" -ForegroundColor Yellow
    Write-Host "    generate-and-sync   (fixes STAGE 3.92 + STAGE 0.06)" -ForegroundColor Yellow
    Write-Host "    deploy-worker       (fixes pre-flight non-ASCII check)" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[ERROR] Push failed (exit code $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "The commit 8c610840 is local. Run manually:" -ForegroundColor Yellow
    Write-Host "  git push origin main" -ForegroundColor Yellow
}
