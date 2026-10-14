#!/usr/bin/env python3
"""Fail-closed, bounded SAST for changed production scripts on PR/push.

Schedule and unscoped manual runs scan all scripts. Never execute selected
scripts: only hand canonical file paths to the installed static analyzers.
No credentials, network writes or publication state are needed here.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SHA = re.compile(r"^[0-9a-fA-F]{40}$")
MAX_TARGETS = 2500


def run(*args: str, cwd: Path, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), cwd=cwd, check=True,
                          capture_output=capture, text=not capture)


def _safe_scripts(root: Path, raw: list[str]) -> list[str]:
    scripts = (root / "scripts").resolve()
    result = []
    for name in raw:
        candidate = (root / name).resolve()
        if not candidate.is_relative_to(scripts) or candidate == scripts:
            raise ValueError("SCRIPT_SAST_INVALID_PATH")
        if candidate.suffix != ".py" or not candidate.is_file():
            continue  # A deleted path or non-Python script cannot be scanned.
        result.append(candidate.relative_to(root).as_posix())
    return sorted(set(result))


def select_targets(root: Path, event: str, base: str, head: str) -> list[str]:
    root = root.resolve()
    if event in ("pull_request", "push") and base and base != "0" * 40:
        if not SHA.fullmatch(base) or not SHA.fullmatch(head):
            raise ValueError("SCRIPT_SAST_INVALID_COMMIT")
        # A base tree may be outside the shallow checkout. Fetch EXACT SHAs,
        # not a mutable branch; no GitHub PR content is executed.
        run("git", "fetch", "--quiet", "--no-tags", "--depth=1", "--filter=blob:none",
            "origin", base, head, cwd=root)
        diff = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames",
             "--diff-filter=ACM", "-z", base, head, "--", "scripts/"],
            cwd=root, capture_output=True, check=True,
        ).stdout
        names = [part.decode("utf-8") for part in diff.split(b"\0") if part]
        selected = _safe_scripts(root, names)
        if selected:
            return selected
        print("Production scripts have no remaining changed Python files: fallback to full scripts inventory")

    # No known diff (scheduled/manual scans and first pushes): scan every
    # production Python script instead of declaring the surface irrelevant.
    paths = [(p.resolve().relative_to(root)).as_posix()
             for p in (root / "scripts").rglob("*.py") if p.is_file()]
    return _safe_scripts(root, paths)


def build_scope(root: Path, destination: Path) -> int:
    event = os.environ.get("SAST_EVENT", "workflow_dispatch")
    head = os.environ.get("SAST_HEAD_SHA", "") if event == "pull_request" else os.environ.get("SAST_CURRENT_SHA", "")
    base = os.environ.get("SAST_BASE_SHA", "") if event == "pull_request" else os.environ.get("SAST_BEFORE_SHA", "")
    targets = select_targets(root, event, base, head)
    if not targets or len(targets) > MAX_TARGETS:
        raise ValueError("SCRIPT_SAST_SCOPE_UNAVAILABLE_OR_TOO_LARGE")
    destination.write_text(json.dumps({"event": event, "target_count": len(targets),
                                       "targets": targets}, indent=2), encoding="utf-8")
    print(f"Script SAST scope: {len(targets)} Python files (event={event})")
    return 0


def scan(root: Path, destination: Path) -> int:
    doc = json.loads(destination.read_text(encoding="utf-8"))
    names = doc.get("targets")
    if not isinstance(names, list) or not names or len(names) > MAX_TARGETS:
        raise ValueError("SCRIPT_SAST_INVALID_TARGET_MANIFEST")
    if not all(isinstance(s, str) for s in names):
        raise ValueError("SCRIPT_SAST_INVALID_TARGET_TYPE")
    targets = _safe_scripts(root, names)
    if targets != sorted(set(names)):
        raise ValueError("SCRIPT_SAST_TARGET_MISMATCH")

    # HIGH severity/HIGH confidence Bandit only; no broad B101 test-assert
    # noise, no suppressing scanner failures, no unsafe shell interpolation.
    bandit_file = root / ".scripts-sast-bandit.json"
    bandit = subprocess.run(
        ["bandit", "-f", "json", "-o", str(bandit_file), "-ll", "-ii",
         "-s", "B101,B601,B324", "--exit-zero", *targets], cwd=root,
        capture_output=True, text=True,
    )
    if bandit.returncode != 0 or not bandit_file.is_file():
        raise RuntimeError("SCRIPT_SAST_BANDIT_EXECUTION_FAILED")
    findings = json.loads(bandit_file.read_text(encoding="utf-8")).get("results")
    if not isinstance(findings, list):
        raise ValueError("SCRIPT_SAST_BANDIT_RESULT_INVALID")
    print(f"Bandit high/high findings: {len(findings)}", flush=True)
    # The previous gate only printed a count (3 at PR #814) and concealed
    # actionable rule/file/line. Do NOT dump code, secrets, or full messages.
    # Emit bounded, log-safe metadata for remediation while retaining BLOCK.
    for finding in findings[:50]:
        if not isinstance(finding, dict):
            raise ValueError("SCRIPT_SAST_BANDIT_FINDING_INVALID")
        file = str(finding.get("filename", ""))
        try:
            file = Path(file).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            file = "UNKNOWN_PATH"
        rule = str(finding.get("test_id", "UNKNOWN"))[:16]
        line = finding.get("line_number")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            line = "UNKNOWN"
        print(json.dumps({"scanner": "bandit", "rule": rule,
                          "file": file, "line": line}, sort_keys=True), flush=True)
    if findings:
        raise RuntimeError("SCRIPT_SAST_BANDIT_HIGH_FINDINGS")

    # Semgrep 1.x ERROR-only rules; scanning each exact target is bounded
    # by GitHub job timeout and the analyzer's own per-rule 45-second cap.
    # Missing output or any nonzero exit is a HARD failure, not clean.
    semgrep_file = root / ".scripts-sast-semgrep.json"
    status = subprocess.run(
        ["semgrep", "scan", "--config", "p/python", "--config", "p/secrets",
         "--severity", "ERROR", "--error", "--timeout", "45", "--jobs", "2",
         "--json", "--output", str(semgrep_file), *targets],
        cwd=root, capture_output=True, text=True,
    )
    if status.returncode != 0 or not semgrep_file.is_file():
        raise RuntimeError("SCRIPT_SAST_SEMGREP_FAILED_OR_FOUND_ISSUES")
    semgrep_findings = json.loads(semgrep_file.read_text(encoding="utf-8")).get("results")
    if not isinstance(semgrep_findings, list):
        raise ValueError("SCRIPT_SAST_SEMGREP_RESULT_INVALID")
    print(f"Semgrep ERROR findings: {len(semgrep_findings)}", flush=True)
    for finding in semgrep_findings[:50]:
        if not isinstance(finding, dict):
            raise ValueError("SCRIPT_SAST_SEMGREP_FINDING_INVALID")
        path = finding.get("path", "")
        try:
            path = Path(str(path)).resolve().relative_to(root).as_posix()
        except (ValueError, OSError):
            path = "UNKNOWN_PATH"
        print(json.dumps({"scanner": "semgrep",
                          "rule": str(finding.get("check_id", "UNKNOWN"))[:100],
                          "file": path,
                          "line": (finding.get("start") or {}).get("line")}, sort_keys=True), flush=True)
    if semgrep_findings:
        raise RuntimeError("SCRIPT_SAST_SEMGREP_FINDINGS")
    print("SCRIPT_SAST_PASS: validated both scanner reports and scanned all selected Python paths")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path)
    mode.add_argument("--scan-from", type=Path)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        if args.output is not None:
            return build_scope(root, args.output.resolve())
        return scan(root, args.scan_from.resolve())
    except (OSError, ValueError, subprocess.CalledProcessError,
            RuntimeError, json.JSONDecodeError) as exc:
        print(f"::error::Production scripts SAST fail-closed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
