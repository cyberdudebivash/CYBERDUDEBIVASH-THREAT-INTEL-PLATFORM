#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL APEX — Autonomous Guardian Agent v1.0
================================================================
24/7 self-healing platform monitor. Runs as the LAST step of every
pipeline. Also runs hourly as a standalone watchdog.

Capabilities:
  1. Reads GitHub Actions API — every workflow run, every job, every step
  2. Parses logs line-by-line to detect failure signatures
  3. Classifies root cause from a library of known failure patterns
  4. Generates and commits the permanent fix autonomously
  5. Re-validates the fix locally before pushing
  6. Posts a structured report to data/health/guardian_report.json

Zero external dependencies beyond stdlib + requests (always installed).
Always exits 0 — never blocks the pipeline.
"""

import json
import os
import re
import sys
import time
import hashlib
import subprocess
import traceback
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error

# ── Configuration ─────────────────────────────────────────────────────────────
REPO        = os.environ.get("GITHUB_REPOSITORY", "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM")
GH_TOKEN    = os.environ.get("GITHUB_TOKEN", "")
REPO_ROOT   = Path(__file__).parent.parent.parent
HEALTH_DIR  = REPO_ROOT / "data" / "health"
REPORT_FILE = HEALTH_DIR / "guardian_report.json"
LOCK_FILE   = REPO_ROOT / "data" / "health" / "guardian.lock"
API_BASE    = "https://api.github.com"
MAX_LOG_BYTES = 500_000   # Read up to 500KB of log per job
LOOKBACK_HOURS = 6        # Check runs from last 6 hours

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def ts() -> str:
    return now_utc().isoformat()

# ── GitHub API ────────────────────────────────────────────────────────────────
def gh_get(path: str, raw: bool = False) -> Optional[dict]:
    """Make authenticated GitHub API request."""
    url = f"{API_BASE}{path}" if path.startswith("/") else path
    headers = {
        "Authorization": f"token {GH_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CDB-Guardian/1.0",
    }
    if raw:
        headers["Accept"] = "application/vnd.github.v3.raw"
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            if raw:
                return resp.read().decode("utf-8", errors="replace")
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        log(f"[GH-API] HTTP {e.code} for {path}: {e.reason}")
        return None
    except Exception as e:
        log(f"[GH-API] Error {path}: {e}")
        return None

def get_recent_workflow_runs(hours: int = LOOKBACK_HOURS) -> list:
    """Get all workflow runs from the last N hours."""
    since = (now_utc() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    runs = []
    page = 1
    while True:
        data = gh_get(f"/repos/{REPO}/actions/runs?per_page=50&page={page}&created=>={since}")
        if not data or not data.get("workflow_runs"):
            break
        runs.extend(data["workflow_runs"])
        if len(data["workflow_runs"]) < 50:
            break
        page += 1
    return runs

def get_job_logs(job_id: int) -> str:
    """Download logs for a specific job."""
    log_data = gh_get(f"/repos/{REPO}/actions/jobs/{job_id}/logs", raw=True)
    if not log_data:
        return ""
    # Limit size
    return log_data[:MAX_LOG_BYTES] if len(log_data) > MAX_LOG_BYTES else log_data

def get_run_jobs(run_id: int) -> list:
    """Get all jobs for a workflow run."""
    data = gh_get(f"/repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100")
    return data.get("jobs", []) if data else []

# ── Failure Detection ─────────────────────────────────────────────────────────
FAILURE_PATTERNS = [
    {
        "id": "git_pull_abort_unstaged",
        "name": "git pull aborted — unstaged files",
        "pattern": r"Your local changes to the following files would be overwritten by merge",
        "severity": "CRITICAL",
        "fix": "fix_git_pull_abort",
    },
    {
        "id": "git_push_rejected",
        "name": "git push rejected — behind remote",
        "pattern": r"Updates were rejected because the tip of your current branch is behind",
        "severity": "HIGH",
        "fix": "fix_git_push_rejected",
    },
    {
        "id": "conflict_markers",
        "name": "Git conflict markers in files",
        "pattern": r"FATAL: Conflict markers detected|<<<<<<< HEAD",
        "severity": "CRITICAL",
        "fix": "fix_conflict_markers",
    },
    {
        "id": "embedded_intel_duplicate",
        "name": "Duplicate EMBEDDED_INTEL declaration",
        "pattern": r"DUPLICATE EMBEDDED_INTEL|multiple EMBEDDED_INTEL",
        "severity": "CRITICAL",
        "fix": "fix_embedded_intel",
    },
    {
        "id": "pre_deploy_gate_fail",
        "name": "Pre-deploy integrity gate FAILED",
        "pattern": r"GATE FAILED|DEPLOY BLOCKED",
        "severity": "CRITICAL",
        "fix": "fix_embedded_intel",
    },
    {
        "id": "manifest_json_error",
        "name": "Manifest JSON parse error",
        "pattern": r"Manifest is not valid JSON|JSONDecodeError.*manifest",
        "severity": "HIGH",
        "fix": "fix_manifest_corruption",
    },
    {
        "id": "pip_install_fail",
        "name": "Python package install failure",
        "pattern": r"ERROR: Could not install packages|pip.*error",
        "severity": "MEDIUM",
        "fix": None,  # No auto-fix — needs manual requirements.txt update
    },
    {
        "id": "timeout",
        "name": "Workflow timed out",
        "pattern": r"The job running on runner.*has exceeded the maximum execution time",
        "severity": "HIGH",
        "fix": None,
    },
    {
        "id": "oom",
        "name": "Out of memory / disk full",
        "pattern": r"No space left on device|Killed.*memory",
        "severity": "HIGH",
        "fix": None,
    },
]

def analyze_log(log_text: str) -> list:
    """Scan log text for known failure signatures. Returns list of matches."""
    findings = []
    for pattern in FAILURE_PATTERNS:
        if re.search(pattern["pattern"], log_text, re.IGNORECASE):
            # Extract the exact matching lines for context
            lines = [l for l in log_text.split("\n") 
                     if re.search(pattern["pattern"], l, re.IGNORECASE)]
            findings.append({
                "pattern_id": pattern["id"],
                "name": pattern["name"],
                "severity": pattern["severity"],
                "fix_fn": pattern["fix"],
                "matched_lines": lines[:5],  # first 5 matching lines
            })
    return findings

# ── Self-Healing Fixes ────────────────────────────────────────────────────────
def run_cmd(cmd: list, cwd: str = None) -> tuple:
    """Run shell command, return (success, stdout, stderr)."""
    result = subprocess.run(
        cmd, capture_output=True, text=True,
        cwd=cwd or str(REPO_ROOT)
    )
    return result.returncode == 0, result.stdout, result.stderr

def git_configure():
    run_cmd(["git", "config", "--local", "user.email", "guardian@cyberdudebivash.com"])
    run_cmd(["git", "config", "--local", "user.name", "CDB-Guardian-Bot"])

def fix_git_pull_abort(context: dict) -> dict:
    """Fix: stage all subdirectory writes before pull. Verify STAGE 3 in sentinel-blogger."""
    log("[FIX] fix_git_pull_abort: verifying git add coverage in sentinel-blogger.yml")
    
    wf_path = REPO_ROOT / ".github/workflows/sentinel-blogger.yml"
    content = wf_path.read_text()
    
    # Check if fix is already applied
    if "git add data/ 2>/dev/null || true" in content:
        return {"applied": False, "reason": "Fix already present in sentinel-blogger.yml"}
    
    # Apply fix
    old = "git add data/*.json 2>/dev/null || true"
    new = "git add data/ 2>/dev/null || true          # ALL of data/ — recursive, future-proof"
    
    if old in content:
        content = content.replace(old, new)
        wf_path.write_text(content)
        return {"applied": True, "file": str(wf_path), "description": "Replaced narrow glob with git add data/"}
    
    return {"applied": False, "reason": "Could not locate git add pattern — manual inspection needed"}

def fix_git_push_rejected(context: dict) -> dict:
    """Fix: ensure all commit blocks use pull-before-push pattern."""
    log("[FIX] fix_git_push_rejected: checking push retry logic")
    fixed_files = []
    
    for wf_file in (REPO_ROOT / ".github/workflows").glob("*.yml"):
        content = wf_file.read_text()
        modified = False
        
        # Replace bare push with pull-then-push
        if re.search(r'git push origin main\s*\|\|\s*\{', content):
            continue  # already has retry
        
        # Find bare git push without retry
        if 'git push origin main\n' in content and 'no-rebase' not in content:
            old_push = '            git push origin main\n'
            new_push = (
                '            git pull origin main --no-rebase --no-edit -X ours || true\n'
                '            git push origin main || (\n'
                '              sleep 10 && git pull origin main --no-rebase --no-edit -X ours\n'
                '              git push origin main\n'
                '            )\n'
            )
            if old_push in content:
                content = content.replace(old_push, new_push)
                wf_file.write_text(content)
                fixed_files.append(wf_file.name)
                modified = True
    
    if fixed_files:
        return {"applied": True, "files": fixed_files, "description": "Added pull-before-push to bare git push commands"}
    return {"applied": False, "reason": "No bare git push patterns found needing fix"}

def fix_conflict_markers(context: dict) -> dict:
    """Fix: remove conflict markers from index.html and restore from manifest."""
    log("[FIX] fix_conflict_markers: checking index.html for conflict markers")
    index = REPO_ROOT / "index.html"
    if not index.exists():
        return {"applied": False, "reason": "index.html not found"}
    
    content = index.read_text(encoding="utf-8", errors="replace")
    if "<<<<<<<" not in content and "=======" not in content:
        return {"applied": False, "reason": "No conflict markers found in index.html"}
    
    # Try git checkout to restore
    ok, _, _ = run_cmd(["git", "checkout", "HEAD", "--", "index.html"])
    if not ok:
        # Try previous commit
        ok, _, _ = run_cmd(["git", "checkout", "HEAD~1", "--", "index.html"])
    
    if ok:
        # Re-patch EMBEDDED_INTEL
        updater = REPO_ROOT / "scripts/update_embedded_intel.py"
        if updater.exists():
            run_cmd(["python3", str(updater)])
        return {"applied": True, "description": "Restored index.html from git history and re-patched EMBEDDED_INTEL"}
    
    return {"applied": False, "reason": "Could not restore index.html from git history"}

def fix_embedded_intel(context: dict) -> dict:
    """Fix: re-run update_embedded_intel.py to repair dashboard."""
    log("[FIX] fix_embedded_intel: running update_embedded_intel.py")
    updater = REPO_ROOT / "scripts/update_embedded_intel.py"
    if not updater.exists():
        return {"applied": False, "reason": "update_embedded_intel.py not found"}
    
    ok, stdout, stderr = run_cmd(["python3", str(updater)])
    if ok and "[SUCCESS]" in stdout:
        return {"applied": True, "description": "update_embedded_intel.py ran successfully", "output": stdout[-500:]}
    
    return {"applied": False, "reason": f"update_embedded_intel.py failed: {stderr[-300:]}"}

def fix_manifest_corruption(context: dict) -> dict:
    """Fix: restore manifest from backup if corrupted."""
    log("[FIX] fix_manifest_corruption: checking manifest backups")
    manifest = REPO_ROOT / "data/stix/feed_manifest.json"
    backup_dir = REPO_ROOT / "data/.manifest_backups"
    
    if backup_dir.exists():
        backups = sorted(backup_dir.glob("manifest_*.json"), reverse=True)
        for backup in backups[:3]:
            try:
                data = json.loads(backup.read_text())
                if isinstance(data, list) and len(data) > 10:
                    import shutil
                    shutil.copy2(backup, manifest)
                    return {"applied": True, "description": f"Restored manifest from backup: {backup.name}"}
            except Exception:
                continue
    
    return {"applied": False, "reason": "No valid backup found"}

FIX_FUNCTIONS = {
    "fix_git_pull_abort": fix_git_pull_abort,
    "fix_git_push_rejected": fix_git_push_rejected,
    "fix_conflict_markers": fix_conflict_markers,
    "fix_embedded_intel": fix_embedded_intel,
    "fix_manifest_corruption": fix_manifest_corruption,
}

# ── Validation ────────────────────────────────────────────────────────────────
def validate_fix() -> dict:
    """Run all validation checks after applying a fix."""
    results = {}
    
    # 1. Pre-deploy gate
    gate = REPO_ROOT / "scripts/pre_deploy_gate.py"
    if gate.exists():
        ok, stdout, _ = run_cmd(["python3", str(gate)])
        results["pre_deploy_gate"] = "PASS" if ok and "DEPLOY AUTHORIZED" in stdout else "FAIL"
    
    # 2. YAML validity of all workflows
    import yaml
    wf_errors = []
    for f in (REPO_ROOT / ".github/workflows").glob("*.yml"):
        try:
            yaml.safe_load(f.read_text())
        except yaml.YAMLError as e:
            wf_errors.append(f"{f.name}: {e}")
    results["workflow_yaml"] = "PASS" if not wf_errors else f"FAIL: {wf_errors}"
    
    # 3. Manifest validity
    manifest = REPO_ROOT / "data/stix/feed_manifest.json"
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text())
            count = len(data) if isinstance(data, list) else 0
            results["manifest"] = f"PASS ({count} items)" if count > 10 else "FAIL (too few items)"
        except Exception as e:
            results["manifest"] = f"FAIL: {e}"
    
    # 4. No conflict markers in index.html
    index = REPO_ROOT / "index.html"
    if index.exists():
        content = index.read_text(encoding="utf-8", errors="replace")
        results["index_html"] = "PASS" if "<<<<<<<" not in content else "FAIL (conflict markers)"
    
    return results

# ── Git commit + push ─────────────────────────────────────────────────────────
def commit_and_push(message: str, paths: list) -> dict:
    """Stage, commit and push fix. Returns result dict."""
    git_configure()
    
    # Stage everything
    run_cmd(["git", "add", "data/"] + paths)
    run_cmd(["git", "add", ".github/workflows/"])
    
    # Check if there's anything to commit
    ok, stdout, _ = run_cmd(["git", "diff", "--staged", "--quiet"])
    if ok:  # returncode 0 = nothing staged
        return {"pushed": False, "reason": "Nothing to commit — fix was already present"}
    
    # Commit
    ok, stdout, stderr = run_cmd(["git", "commit", "-m", f"{message} [skip ci]"])
    if not ok:
        return {"pushed": False, "reason": f"Commit failed: {stderr}"}
    
    # Pull then push with retry
    run_cmd(["git", "checkout", "--", "."])  # clean unstaged
    for attempt in range(1, 4):
        run_cmd(["git", "pull", "origin", "main", "--no-rebase", "--no-edit", "-X", "ours"])
        ok, _, stderr = run_cmd(["git", "push", "origin", "main"])
        if ok:
            return {"pushed": True, "attempt": attempt, "message": message}
        log(f"[PUSH] Attempt {attempt} failed: {stderr[:100]}")
        time.sleep(15)
    
    return {"pushed": False, "reason": "Push failed after 3 attempts"}

# ── Main Guardian Cycle ───────────────────────────────────────────────────────
def log(msg: str):
    print(f"[GUARDIAN] {msg}", flush=True)

def run_guardian_cycle() -> dict:
    """Main cycle: scan → detect → fix → validate → commit → report."""
    start = time.monotonic()
    report = {
        "run_at": ts(),
        "repo": REPO,
        "lookback_hours": LOOKBACK_HOURS,
        "runs_scanned": 0,
        "jobs_scanned": 0,
        "failures_detected": [],
        "fixes_applied": [],
        "validations": {},
        "push_result": None,
        "overall_status": "HEALTHY",
        "duration_seconds": 0,
    }
    
    if not GH_TOKEN:
        log("GITHUB_TOKEN not set — skipping API scan (local mode)")
        report["overall_status"] = "SKIPPED_NO_TOKEN"
        return report
    
    # ── 1. Fetch recent workflow runs ──────────────────────────────────────────
    log(f"Fetching workflow runs from last {LOOKBACK_HOURS}h...")
    runs = get_recent_workflow_runs(LOOKBACK_HOURS)
    report["runs_scanned"] = len(runs)
    log(f"Found {len(runs)} runs")
    
    # ── 2. Identify failures ───────────────────────────────────────────────────
    failed_runs = [r for r in runs if r.get("conclusion") in ("failure", "timed_out", "cancelled")]
    log(f"Failed runs: {len(failed_runs)}")
    
    all_findings = []
    
    for run in failed_runs:
        run_id = run["id"]
        wf_name = run.get("name", "unknown")
        log(f"Scanning run #{run['run_number']} [{wf_name}] — {run['conclusion']}")
        
        jobs = get_run_jobs(run_id)
        report["jobs_scanned"] += len(jobs)
        
        for job in jobs:
            if job.get("conclusion") not in ("failure", "timed_out"):
                continue
            
            log(f"  Downloading logs for failed job: {job['name']}")
            log_text = get_job_logs(job["id"])
            if not log_text:
                continue
            
            findings = analyze_log(log_text)
            for finding in findings:
                finding["run_id"] = run_id
                finding["run_number"] = run["run_number"]
                finding["workflow"] = wf_name
                finding["job"] = job["name"]
                finding["run_url"] = run.get("html_url", "")
                all_findings.append(finding)
                log(f"  ⚠️  DETECTED: {finding['name']} [{finding['severity']}]")
    
    report["failures_detected"] = [
        {k: v for k, v in f.items() if k != "matched_lines"} 
        for f in all_findings
    ]
    
    if not all_findings:
        log("✅ No failures detected — platform is healthy")
        report["overall_status"] = "HEALTHY"
        report["duration_seconds"] = round(time.monotonic() - start, 2)
        return report
    
    report["overall_status"] = "FAILURES_DETECTED"
    
    # ── 3. Apply fixes ─────────────────────────────────────────────────────────
    applied_fix_ids = set()
    fix_results = []
    
    for finding in all_findings:
        fix_fn_name = finding.get("fix_fn")
        if not fix_fn_name or fix_fn_name in applied_fix_ids:
            continue
        
        fix_fn = FIX_FUNCTIONS.get(fix_fn_name)
        if not fix_fn:
            log(f"  No auto-fix available for: {finding['name']}")
            continue
        
        log(f"  Applying fix: {fix_fn_name} for [{finding['name']}]")
        try:
            result = fix_fn(finding)
            result["pattern_id"] = finding["pattern_id"]
            result["fix_fn"] = fix_fn_name
            fix_results.append(result)
            
            if result.get("applied"):
                applied_fix_ids.add(fix_fn_name)
                log(f"  ✅ Fix applied: {result.get('description', fix_fn_name)}")
            else:
                log(f"  ℹ️  Fix not applied: {result.get('reason', 'unknown')}")
        except Exception as e:
            log(f"  ❌ Fix crashed: {e}")
            fix_results.append({
                "fix_fn": fix_fn_name,
                "applied": False,
                "error": str(e),
                "traceback": traceback.format_exc()[-500:]
            })
    
    report["fixes_applied"] = fix_results
    
    # ── 4. Validate fixes ──────────────────────────────────────────────────────
    if any(f.get("applied") for f in fix_results):
        log("Running post-fix validation...")
        validation = validate_fix()
        report["validations"] = validation
        
        all_pass = all(v.startswith("PASS") for v in validation.values())
        log(f"Validation: {'ALL PASS ✅' if all_pass else 'SOME FAILURES ❌'}")
        for check, result in validation.items():
            log(f"  {check}: {result}")
        
        # ── 5. Commit and push fix ─────────────────────────────────────────────
        if all_pass:
            fix_names = ", ".join(set(f["fix_fn"] for f in fix_results if f.get("applied")))
            msg = f"🤖 Guardian auto-fix: {fix_names}"
            log(f"Committing fix: {msg}")
            
            push_result = commit_and_push(msg, [])
            report["push_result"] = push_result
            
            if push_result.get("pushed"):
                log(f"✅ Fix committed and pushed successfully (attempt {push_result.get('attempt')})")
                report["overall_status"] = "FIXED_AND_PUSHED"
            else:
                log(f"⚠️  Fix validated but push failed: {push_result.get('reason')}")
                report["overall_status"] = "FIXED_NOT_PUSHED"
        else:
            log("⚠️  Validation failed — not pushing fix to avoid making things worse")
            report["overall_status"] = "FIX_VALIDATION_FAILED"
    else:
        log("No fixes were applied")
        report["overall_status"] = "NO_AUTOFIX_AVAILABLE"
    
    report["duration_seconds"] = round(time.monotonic() - start, 2)
    return report

def write_report(report: dict):
    """Write guardian report and maintain rolling history."""
    HEALTH_DIR.mkdir(parents=True, exist_ok=True)
    
    # Load history
    history_file = HEALTH_DIR / "guardian_history.json"
    history = []
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text())
        except Exception:
            history = []
    
    # Add current run summary to history (keep last 100)
    summary = {
        "run_at": report["run_at"],
        "status": report["overall_status"],
        "failures": len(report["failures_detected"]),
        "fixes_applied": sum(1 for f in report.get("fixes_applied", []) if f.get("applied")),
        "pushed": report.get("push_result", {}).get("pushed", False) if report.get("push_result") else False,
        "duration_s": report["duration_seconds"],
    }
    history.insert(0, summary)
    history = history[:100]
    
    # Write files
    REPORT_FILE.write_text(json.dumps(report, indent=2))
    history_file.write_text(json.dumps(history, indent=2))

def main():
    log("=" * 60)
    log("SENTINEL APEX — Autonomous Guardian Agent v1.0")
    log(f"Repository: {REPO}")
    log(f"Timestamp:  {ts()}")
    log("=" * 60)
    
    # Prevent concurrent runs
    if LOCK_FILE.exists():
        lock_age = time.time() - LOCK_FILE.stat().st_mtime
        if lock_age < 300:  # 5 min lock
            log(f"Another Guardian instance running (lock age: {lock_age:.0f}s) — skipping")
            sys.exit(0)
    
    HEALTH_DIR.mkdir(parents=True, exist_ok=True)
    LOCK_FILE.write_text(ts())
    
    try:
        report = run_guardian_cycle()
        write_report(report)
        
        status = report["overall_status"]
        log(f"\n{'='*60}")
        log(f"GUARDIAN CYCLE COMPLETE — Status: {status}")
        log(f"Runs scanned: {report['runs_scanned']} | Jobs scanned: {report['jobs_scanned']}")
        log(f"Failures detected: {len(report['failures_detected'])}")
        log(f"Fixes applied: {sum(1 for f in report.get('fixes_applied',[]) if f.get('applied'))}")
        log(f"Duration: {report['duration_seconds']}s")
        log(f"{'='*60}")
    except Exception as e:
        log(f"GUARDIAN CRASHED: {e}")
        traceback.print_exc()
    finally:
        if LOCK_FILE.exists():
            LOCK_FILE.unlink()
    
    sys.exit(0)  # Always exit 0 — never block pipeline


if __name__ == "__main__":
    main()
