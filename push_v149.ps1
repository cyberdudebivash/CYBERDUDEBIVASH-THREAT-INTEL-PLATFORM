# =============================================================================
# CYBERDUDEBIVASH SENTINEL APEX — v149.0 Git Push Script
# Phase 4-6 CTI Transformation + P0 Bug Fixes
# Run from: C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
# =============================================================================

$ErrorActionPreference = "Stop"
$RepoRoot = $PSScriptRoot

Write-Host "=== SENTINEL APEX v149.0 — Git Push Script ===" -ForegroundColor Cyan
Write-Host "Repo: $RepoRoot" -ForegroundColor Gray
Set-Location $RepoRoot

# ── Step 1: Clear stale lock files ───────────────────────────────────────────
Write-Host "`n[1/6] Clearing stale lock files..." -ForegroundColor Yellow
$locks = @(".git\index.lock", ".git\HEAD.lock", ".git\refs\heads\main.lock")
foreach ($lock in $locks) {
    $lockPath = Join-Path $RepoRoot $lock
    if (Test-Path $lockPath) {
        Remove-Item $lockPath -Force
        Write-Host "  Removed: $lock" -ForegroundColor Green
    }
}

# ── Step 2: Syntax validation ─────────────────────────────────────────────────
Write-Host "`n[2/6] Validating Python syntax..." -ForegroundColor Yellow
$files = @("agent\apex_intelligence_upgrade.py", "scripts\generate_intel_reports.py")
foreach ($f in $files) {
    $result = & python -c "import py_compile; py_compile.compile('$f', doraise=True); print('OK')" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  PASS: $f" -ForegroundColor Green
    } else {
        Write-Host "  FAIL: $f`n$result" -ForegroundColor Red
        exit 1
    }
}

# ── Step 3: Stage modified files ──────────────────────────────────────────────
Write-Host "`n[3/6] Staging modified files..." -ForegroundColor Yellow
& git add agent/apex_intelligence_upgrade.py
& git add scripts/generate_intel_reports.py
Write-Host "  Staged: agent/apex_intelligence_upgrade.py" -ForegroundColor Green
Write-Host "  Staged: scripts/generate_intel_reports.py" -ForegroundColor Green

# ── Step 4: Commit ────────────────────────────────────────────────────────────
Write-Host "`n[4/6] Committing..." -ForegroundColor Yellow
$commitMsg = @"
feat(apex): v149.0 — Phase 4-6 CTI transformation + P0 fixes

Phase 4 — Ransomware Kill Chain Engine:
  - RaaS vuln class detection added to _VULN_CLASS_MAP
  - _KILL_CHAIN_TEMPLATES['ransomware'] expanded to 8 operational phases
  - New 'raas_edge_device' template: 9-phase Fortinet/Cisco-specific kill chain
  - generate_kill_chain_html: routes to raas_edge_device on edge-device keywords
  - generate_enhanced_sigma: ransomware case with vssadmin/wbadmin/bcdedit detection

Phase 5 — Executive Financial Risk Model:
  - _render_financial_impact: vuln_class parameter + ransomware-specific block
  - Ransomware block: ransom demand range, recovery cost, double-extortion premium
  - Board decision framework: pay vs restore analysis with insurance sublimit risk
  - generate_intel_reports.py: inline vuln_class detection for S17 section

Phase 6 — Threat Actor Intelligence Depth:
  - _ACTOR_PROFILES: added The Gentlemen, LockBit, ALPHV, Cl0p with full profiles
  - _NAMED_ACTOR_SCAN: 15-pattern regex scan for named actor detection from content
  - resolve_actor_cluster: PASS 0 named-actor content scan (bypasses artifact labels)
  - generate_actor_intelligence_v2: APEX Analyst Assessment callout + ATT&CK badges
  - generate_ioc_intelligence_table: semantic IOC classification with SOC action guidance

P0 Fixes:
  - EPSS normalization: enrich_advisory + _safe_enforce_schema fix 9406% bug
  - EPSS division applied at both ingest (enrich_advisory) and schema boundary
  - All functions: never raises, production-safe exception handling throughout

MODULE 10 — IOC Semantic Classification Engine:
  - classify_ioc: SHA256/SHA1/MD5/IPv4/URL/domain/email/CVE classification
  - generate_ioc_intelligence_table: full operational IOC table with trust scoring
  - enrich_advisory: master enrichment entry point with IOC + EPSS + TTP pipeline

SENTINEL APEX v149.0 | CYBERDUDEBIVASH Pvt. Ltd.
"@

& git commit -m $commitMsg
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Commit failed — check output above" -ForegroundColor Red
    exit 1
}
Write-Host "  Commit created successfully" -ForegroundColor Green

# ── Step 5: Fetch + rebase onto remote ───────────────────────────────────────
Write-Host "`n[5/6] Fetching remote and rebasing..." -ForegroundColor Yellow
& git fetch origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Fetch failed — check network/credentials" -ForegroundColor Red
    exit 1
}
& git rebase origin/main
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Rebase conflict detected — resolve manually then run: git push origin main" -ForegroundColor Red
    exit 1
}

# ── Step 6: Push ──────────────────────────────────────────────────────────────
Write-Host "`n[6/6] Pushing to origin/main..." -ForegroundColor Yellow
& git push origin main
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Push failed. Try: git push --force-with-lease origin main" -ForegroundColor Red
    Write-Host "  (only if you are certain the remote has no newer work)" -ForegroundColor Gray
    exit 1
}

Write-Host "`n=== PUSH COMPLETE ===" -ForegroundColor Cyan
Write-Host "SENTINEL APEX v149.0 is live on GitHub." -ForegroundColor Green
& git log --oneline -3
