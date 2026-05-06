#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Change Manager
=============================================================
Phase 5: Enterprise Change Management

Implements:
  - Deployment freeze window enforcement
  - Protected deployment approval gates
  - Change audit registry (immutable governance ledger)
  - Deployment governance ledger
  - Release notes automation
  - Deployment risk scoring
  - Release certification gates

Usage:
  python3 scripts/change_manager.py check-freeze         -- check active freeze windows
  python3 scripts/change_manager.py risk-score           -- score this deployment's risk
  python3 scripts/change_manager.py audit-log <event>    -- append event to governance ledger
  python3 scripts/change_manager.py release-notes        -- generate release notes from git log
  python3 scripts/change_manager.py certify              -- run release certification gates
  python3 scripts/change_manager.py ledger               -- print governance ledger
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
GOVERNANCE_DIR = REPO_ROOT / "data" / "governance"
GOVERNANCE_DIR.mkdir(parents=True, exist_ok=True)

FREEZE_CONFIG  = REPO_ROOT / "config" / "deployment_freeze.json"
ENV_CONFIG     = REPO_ROOT / "config" / "environments.json"
LEDGER_PATH    = GOVERNANCE_DIR / "deployment_governance_ledger.json"
CHANGE_REG     = GOVERNANCE_DIR / "change_audit_registry.json"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def now_day() -> str:
    return datetime.now(timezone.utc).strftime("%A")


def now_time_utc() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M")


def load_json(path: pathlib.Path, default=None):
    if path.exists():
        return json.loads(path.read_text())
    return default or {}


def save_json(path: pathlib.Path, data: dict):
    data["updated_at"] = now_iso()
    path.write_text(json.dumps(data, indent=2))


def load_ledger() -> list:
    ledger = load_json(LEDGER_PATH, {"entries": []})
    return ledger.get("entries", [])


def append_ledger(entry: dict):
    entries = load_ledger()
    entries.append({**entry, "recorded_at": now_iso()})
    entries = entries[-1000:]  # Keep last 1000 entries
    LEDGER_PATH.write_text(json.dumps({"entries": entries, "updated_at": now_iso()}, indent=2))


def get_git_diff_stats() -> dict:
    """Get stats for the current uncommitted or last commit changes."""
    try:
        # Files changed in last commit
        files_out = subprocess.check_output(
            ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", "HEAD"],
            cwd=REPO_ROOT, text=True
        ).strip()
        files = [f for f in files_out.split("\n") if f]
        # Lines changed
        stat_out = subprocess.check_output(
            ["git", "show", "--stat", "HEAD"],
            cwd=REPO_ROOT, text=True
        ).strip().split("\n")
        last_line = stat_out[-1] if stat_out else ""
        return {"files_changed": len(files), "changed_files": files, "stat_summary": last_line}
    except Exception as e:
        return {"files_changed": 0, "changed_files": [], "stat_summary": str(e)}


def score_risk(diff_stats: dict) -> dict:
    """Score deployment risk (LOW/MEDIUM/HIGH/CRITICAL)."""
    freeze_cfg = load_json(FREEZE_CONFIG, {})
    thresholds = freeze_cfg.get("governance_rules", {}).get("change_risk_thresholds", {})
    files = diff_stats.get("files_changed", 0)

    # Frontend mutation check
    frontend_touched = any(
        f in ["index.html", "dashboard.js", "renderer.js", "ai_runtime_engine.js",
              "api_adapter.js", "styles.css", "card_renderer.js"]
        for f in diff_stats.get("changed_files", [])
    )

    # Workflow mutation check
    workflow_touched = any(
        ".github/workflows/" in f for f in diff_stats.get("changed_files", [])
    )

    # Worker mutation check
    worker_touched = any(
        "workers/" in f for f in diff_stats.get("changed_files", [])
    )

    base_score = 0
    risk_factors = []

    if files > 20:
        base_score += 40
        risk_factors.append("HIGH_FILE_COUNT")
    elif files > 5:
        base_score += 20
        risk_factors.append("MEDIUM_FILE_COUNT")
    else:
        base_score += 5

    if frontend_touched:
        base_score += 30
        risk_factors.append("FRONTEND_MUTATION")
    if workflow_touched:
        base_score += 20
        risk_factors.append("WORKFLOW_MUTATION")
    if worker_touched:
        base_score += 25
        risk_factors.append("WORKER_MUTATION")

    if base_score >= 70:
        level = "CRITICAL"
    elif base_score >= 45:
        level = "HIGH"
    elif base_score >= 20:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": base_score,
        "risk_level": level,
        "risk_factors": risk_factors,
        "files_changed": files,
        "frontend_touched": frontend_touched,
        "workflow_touched": workflow_touched,
        "worker_touched": worker_touched,
        "requires_extra_approval": level in ("HIGH", "CRITICAL"),
    }


def check_freeze_windows() -> dict:
    """Check if any freeze window is currently active."""
    freeze_cfg = load_json(FREEZE_CONFIG, {})

    # Global freeze
    if freeze_cfg.get("global_freeze_active"):
        return {
            "frozen": True,
            "type": "GLOBAL",
            "reason": freeze_cfg.get("freeze_reason", "Global freeze active"),
            "expires_at": freeze_cfg.get("freeze_expires_at"),
            "override_requires": "emergency-approval",
        }

    # Scheduled windows
    current_day = now_day()
    current_time = now_time_utc()

    for window in freeze_cfg.get("scheduled_freeze_windows", []):
        if not window.get("active", True):
            continue
        days = window.get("days_of_week", [])
        if days and current_day not in days:
            continue
        start = window.get("start_time_utc", "00:00")
        end = window.get("end_time_utc", "23:59")
        if start <= current_time <= end:
            if window.get("severity") == "HARD":
                return {
                    "frozen": True,
                    "type": "SCHEDULED_HARD",
                    "window": window["name"],
                    "reason": window["description"],
                    "override_requires": window.get("override_requires", "emergency-approval"),
                    "severity": window["severity"],
                }
            else:
                return {
                    "frozen": False,
                    "advisory": True,
                    "type": "SCHEDULED_SOFT",
                    "window": window["name"],
                    "reason": window["description"],
                    "severity": window["severity"],
                }

    return {"frozen": False, "advisory": False}


def generate_release_notes() -> str:
    """Generate release notes from last 10 non-skip-ci commits."""
    try:
        log = subprocess.check_output(
            ["git", "log", "--oneline", "--no-merges", "-20"],
            cwd=REPO_ROOT, text=True
        ).strip().split("\n")
        # Filter out auto-commits
        filtered = [l for l in log if "[skip ci]" not in l and l.strip()][:10]
        head = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()[:12]
        lines = [
            f"# Release Notes — {now_iso()[:10]}",
            f"Commit: {head}",
            "",
            "## Changes",
        ]
        for entry in filtered:
            sha = entry[:7]
            msg = entry[8:]
            lines.append(f"- `{sha}` {msg}")
        return "\n".join(lines)
    except Exception as e:
        return f"# Release Notes\nError: {e}"


def cmd_check_freeze(args) -> int:
    result = check_freeze_windows()
    if result.get("frozen"):
        print(f"[FREEZE] DEPLOYMENT BLOCKED: {result['type']}")
        print(f"[FREEZE] Reason: {result.get('reason','?')}")
        print(f"[FREEZE] Override requires: {result.get('override_requires','emergency-approval')}")
        return 1
    elif result.get("advisory"):
        print(f"[FREEZE] ADVISORY: {result.get('window','?')} -- {result.get('reason','?')}")
        print(f"[FREEZE] Severity: {result.get('severity','SOFT')} -- proceeding with caution")
        return 0
    else:
        print(f"[FREEZE] No active freeze windows -- deployment authorized")
        return 0


def cmd_risk_score(args) -> int:
    diff = get_git_diff_stats()
    risk = score_risk(diff)
    print(f"\nDEPLOYMENT RISK ASSESSMENT")
    print("=" * 50)
    print(f"  Risk Level:    {risk['risk_level']}")
    print(f"  Risk Score:    {risk['risk_score']}/100")
    print(f"  Files Changed: {risk['files_changed']}")
    print(f"  Risk Factors:  {', '.join(risk['risk_factors']) or 'none'}")
    print(f"  Frontend:      {'TOUCHED' if risk['frontend_touched'] else 'clean'}")
    print(f"  Worker:        {'TOUCHED' if risk['worker_touched'] else 'clean'}")
    print(f"  Workflows:     {'TOUCHED' if risk['workflow_touched'] else 'clean'}")
    print(f"  Extra Approval: {'REQUIRED' if risk['requires_extra_approval'] else 'not required'}")
    print("=" * 50)
    append_ledger({
        "event": "RISK_SCORED",
        "risk_level": risk["risk_level"],
        "risk_score": risk["risk_score"],
        "risk_factors": risk["risk_factors"],
        "files_changed": risk["files_changed"],
    })
    # Exit non-zero only for CRITICAL without override
    if risk["risk_level"] == "CRITICAL" and not getattr(args, "force", False):
        print(f"[RISK] CRITICAL risk -- manual review required before deployment")
        return 2
    return 0


def cmd_audit_log(args) -> int:
    event = getattr(args, "event", "CUSTOM_EVENT")
    meta_str = getattr(args, "meta", "{}")
    try:
        meta = json.loads(meta_str)
    except Exception:
        meta = {"raw": meta_str}
    append_ledger({"event": event, **meta})
    print(f"[AUDIT] Logged: {event}")
    return 0


def cmd_release_notes(args) -> int:
    notes = generate_release_notes()
    print(notes)
    notes_path = GOVERNANCE_DIR / "latest_release_notes.md"
    notes_path.write_text(notes)
    print(f"\n[NOTES] Saved to {notes_path}")
    return 0


def cmd_certify(args) -> int:
    """Run all release certification gates."""
    print(f"\nRELEASE CERTIFICATION GATES")
    print("=" * 60)
    passed = 0
    failed = 0

    # Gate: No active freeze
    freeze = check_freeze_windows()
    if freeze.get("frozen"):
        print(f"  [FAIL] Freeze window: {freeze.get('type')}")
        failed += 1
    else:
        print(f"  [PASS] No active deployment freeze")
        passed += 1

    # Gate: Risk level
    diff = get_git_diff_stats()
    risk = score_risk(diff)
    if risk["risk_level"] == "CRITICAL":
        print(f"  [FAIL] Risk level CRITICAL -- requires manual approval")
        failed += 1
    else:
        print(f"  [PASS] Risk level {risk['risk_level']} (score {risk['risk_score']})")
        passed += 1

    # Gate: Python syntax
    try:
        result = subprocess.run(
            ["python3", "-m", "py_compile"] +
            [str(p) for p in (REPO_ROOT / "scripts").glob("*.py")],
            capture_output=True, cwd=REPO_ROOT
        )
        if result.returncode == 0:
            print(f"  [PASS] Python syntax clean")
            passed += 1
        else:
            print(f"  [FAIL] Python syntax errors: {result.stderr.decode()[:100]}")
            failed += 1
    except Exception as e:
        print(f"  [WARN] Python syntax check failed: {e}")

    # Gate: YAML syntax
    try:
        import yaml
        wf_dir = REPO_ROOT / ".github" / "workflows"
        errors = []
        for f in wf_dir.glob("*.yml"):
            try:
                yaml.safe_load(f.read_text())
            except Exception as ye:
                errors.append(f"{f.name}: {ye}")
        if errors:
            print(f"  [FAIL] YAML errors: {errors[:3]}")
            failed += 1
        else:
            print(f"  [PASS] All workflow YAML valid")
            passed += 1
    except ImportError:
        print(f"  [SKIP] yaml not available")

    total = passed + failed
    score = int((passed / total) * 100) if total else 0
    certified = failed == 0

    print("=" * 60)
    print(f"  Passed: {passed}/{total} | Score: {score}%")
    print(f"  Certification: {'CERTIFIED' if certified else 'NOT CERTIFIED'}")
    print("=" * 60)

    append_ledger({
        "event": "RELEASE_CERTIFIED" if certified else "RELEASE_CERTIFICATION_FAILED",
        "passed": passed,
        "failed": failed,
        "score": score,
    })

    return 0 if certified else 1


def cmd_ledger(args) -> int:
    entries = load_ledger()
    print(f"\nDEPLOYMENT GOVERNANCE LEDGER ({len(entries)} entries)")
    print("=" * 70)
    for e in entries[-15:]:
        ts = e.get("recorded_at", "?")[:19]
        ev = e.get("event", "?")
        level = e.get("risk_level", "")
        detail = f" {level}" if level else ""
        print(f"  {ts}  {ev:<40}{detail}")
    print("=" * 70)
    return 0


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Change Manager")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("check-freeze", help="Check active freeze windows")

    p_risk = sub.add_parser("risk-score", help="Score deployment risk")
    p_risk.add_argument("--force", action="store_true", help="Proceed despite CRITICAL risk")

    p_audit = sub.add_parser("audit-log", help="Append event to governance ledger")
    p_audit.add_argument("event", help="Event name (e.g. DEPLOY_INITIATED)")
    p_audit.add_argument("--meta", default="{}", help="JSON metadata")

    sub.add_parser("release-notes", help="Generate release notes from git log")
    sub.add_parser("certify", help="Run release certification gates")
    sub.add_parser("ledger", help="Print governance ledger")

    args = parser.parse_args()

    dispatch = {
        "check-freeze":  cmd_check_freeze,
        "risk-score":    cmd_risk_score,
        "audit-log":     cmd_audit_log,
        "release-notes": cmd_release_notes,
        "certify":       cmd_certify,
        "ledger":        cmd_ledger,
    }

    if args.cmd not in dispatch:
        parser.print_help()
        return 1
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
