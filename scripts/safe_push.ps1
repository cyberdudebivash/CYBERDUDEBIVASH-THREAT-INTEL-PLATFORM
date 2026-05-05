# safe_push.ps1
# CYBERDUDEBIVASH(R) SENTINEL APEX v143.1.0 — CI-Race-Safe Git Push
# ==================================================================
# Permanently resolves the "cannot lock ref" / fetch-first rejection pattern
# caused by GitHub Actions pushing to main concurrently with local pushes.
#
# ROOT CAUSE: GitHub Actions CI runs on every push and writes back to main
# (Guardian reports, APEX Matrix updates, etc.). Between a local `git pull
# --rebase` and `git push`, CI can land 1-2 commits, causing the CAS-style
# ref lock to reject the local push.
#
# STRATEGY:
#   1. Optionally amend the last commit to include [skip ci] so our push
#      does NOT trigger a new CI run (breaking the feedback loop).
#   2. Fetch + rebase loop with up to MAX_RETRIES attempts.
#   3. Push immediately after each successful rebase (minimal window).
#   4. Exponential backoff between retries (1s, 2s, 4s, 8s, 16s).
#   5. Exit 0 on success, exit 1 on total failure.
#
# USAGE:
#   .\scripts\safe_push.ps1                  # push HEAD, auto-adds [skip ci]
#   .\scripts\safe_push.ps1 -NoSkipCI        # push without modifying commit msg
#   .\scripts\safe_push.ps1 -MaxRetries 10   # increase retry budget
#   .\scripts\safe_push.ps1 -Branch feature/x # push a non-main branch
#
# (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.

param(
    [switch]$NoSkipCI,
    [int]$MaxRetries = 7,
    [string]$Branch = "main",
    [string]$Remote = "origin"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$REPO = Split-Path -Parent $PSScriptRoot

function Write-Step([string]$msg) {
    $ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    Write-Host "[$ts] [safe_push] $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) {
    Write-Host "  OK  $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "  WARN  $msg" -ForegroundColor Yellow
}

function Write-Fail([string]$msg) {
    Write-Host "  FAIL  $msg" -ForegroundColor Red
}

Set-Location $REPO
Write-Step "SENTINEL APEX safe_push.ps1 — CI-Race-Safe Push to $Remote/$Branch"

# ── Pre-flight: confirm clean working tree ─────────────────────────────────────
$dirty = git status --porcelain
if ($dirty) {
    Write-Fail "Working tree is dirty. Commit or stash changes first:"
    Write-Host $dirty
    exit 1
}
Write-OK "Working tree clean"

# ── Step 1: Amend last commit to include [skip ci] ────────────────────────────
# This prevents GitHub Actions from triggering a new pipeline run on our push,
# which is the root cause of the CI race condition.
if (-not $NoSkipCI) {
    $lastMsg = git log -1 --format="%s"
    if ($lastMsg -notmatch '\[skip ci\]') {
        Write-Step "Amending commit to add [skip ci] (prevents CI feedback loop)"
        $newMsg = $lastMsg + " [skip ci]"
        git commit --amend --no-edit -m $newMsg | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Commit amended: `"$newMsg`""
        } else {
            Write-Warn "Could not amend commit — continuing without [skip ci]"
        }
    } else {
        Write-OK "Commit already has [skip ci] — no amendment needed"
    }
}

# ── Step 2: Retry loop — fetch + rebase + push ────────────────────────────────
$attempt = 0
$backoff = 1   # seconds

while ($attempt -lt $MaxRetries) {
    $attempt++
    Write-Step "Attempt $attempt/$MaxRetries — fetch $Remote/$Branch"

    # Fetch latest remote state
    $fetchOut = git fetch $Remote $Branch 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "Fetch failed (network?): $fetchOut"
        Start-Sleep -Seconds $backoff
        $backoff = [Math]::Min($backoff * 2, 30)
        continue
    }

    # Check if we need to rebase (local ahead only = no rebase needed)
    $remoteAhead = git log --oneline HEAD.."$Remote/$Branch" 2>$null
    $localAhead  = git log --oneline "$Remote/$Branch"..HEAD 2>$null

    Write-Step "Remote ahead: $(($remoteAhead | Measure-Object -Line).Lines) commit(s) | Local ahead: $(($localAhead | Measure-Object -Line).Lines) commit(s)"

    if ($remoteAhead) {
        Write-Step "Rebasing local commits on top of $Remote/$Branch..."
        $rebaseOut = git rebase "$Remote/$Branch" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Rebase conflict detected. Manual resolution required."
            Write-Host $rebaseOut
            git rebase --abort 2>$null
            exit 1
        }
        Write-OK "Rebase succeeded"
    } else {
        Write-OK "No rebase needed — already up to date with remote"
    }

    # Push immediately after rebase (minimal race window)
    Write-Step "Pushing to $Remote/$Branch..."
    $pushOut = git push $Remote $Branch 2>&1
    $pushExit = $LASTEXITCODE

    if ($pushExit -eq 0) {
        Write-OK "Push succeeded!"
        break
    }

    # Parse the rejection reason
    $pushStr = $pushOut -join " "
    if ($pushStr -match "cannot lock ref|fetch first|rejected") {
        Write-Warn "Push rejected (CI race — remote moved again). Retrying in ${backoff}s..."
        Start-Sleep -Seconds $backoff
        $backoff = [Math]::Min($backoff * 2, 30)
    } elseif ($pushStr -match "Everything up-to-date") {
        Write-OK "Already up-to-date — push not needed"
        $pushExit = 0
        break
    } else {
        Write-Fail "Unexpected push error: $pushStr"
        exit 1
    }
}

# ── Step 3: Final state verification ──────────────────────────────────────────
Write-Step "Verifying final state..."
git fetch $Remote $Branch --quiet 2>$null

$localSHA  = git rev-parse HEAD
$remoteSHA = git rev-parse "$Remote/$Branch"

if ($localSHA -eq $remoteSHA) {
    Write-OK "VERIFIED: Local HEAD == Remote HEAD ($($localSHA.Substring(0,12)))"
    Write-Step "git log (top 4):"
    git log --oneline -4 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
    Write-Host ""
    Write-Host "==> safe_push COMPLETE. Repo is clean, stable, and synced." -ForegroundColor Green
    exit 0
} else {
    $remaining = git log --oneline "$Remote/$Branch"..HEAD
    if (-not $remaining) {
        Write-Warn "Local behind remote (CI pushed after us) — but our commits are in remote."
        Write-Host "  Remote: $($remoteSHA.Substring(0,12))"
        Write-Host "  Local:  $($localSHA.Substring(0,12))"
        Write-Host "  Run: git pull origin main --rebase (no commits to push)"
        exit 0
    }
    Write-Fail "Push failed after $MaxRetries attempts. Local/remote still diverged."
    Write-Host "  Local:  $localSHA"
    Write-Host "  Remote: $remoteSHA"
    exit 1
}
