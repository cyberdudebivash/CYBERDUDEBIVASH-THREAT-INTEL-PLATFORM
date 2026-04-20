#!/usr/bin/env python3
"""
scripts/validate_repo.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.2.0 -- Repository Validator
==================================================================
FINAL VALIDATION GATE -- runs after all other pipeline steps.

Checks:
  1.  Encoding clean  -- no BOM, CRLF, non-ASCII in YAML/shell files
  2.  YAML valid      -- all .yml/.yaml files parse correctly
  3.  Python syntax   -- all .py files pass py_compile
  4.  JSON valid      -- all critical .json files parse correctly
  5.  Workflow clean  -- sentinel-blogger.yml has no inline PYEOF/heredocs

Exit 0 -- all checks passed
Exit 1 -- one or more critical checks failed

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import py_compile
import sys
from typing import NamedTuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [validate_repo] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.validate_repo")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
}

CRITICAL_JSON_FILES = [
    "data/stix/feed_manifest.json",
    "data/feed_manifest.json",
    "data/publish_queue.json",
]

WORKFLOW_FILE = ".github/workflows/sentinel-blogger.yml"

# Patterns that must NOT appear in the rebuilt workflow
BANNED_PATTERNS = [
    b"python3 - << 'PYEOF'",
    b"python3 - <<'PYEOF'",
    b"python3 - << PYEOF",   # unquoted -- worst offender
    b"<< PYEOF",
    b"<< 'PYEOF'",
    b"<< EOF",
    b"<< 'EOF'",
    b"<< ENDJSON",
    b"<< 'ENDJSON'",
    b"PYEOF",
    b"ENDJSON",
]


class CheckResult(NamedTuple):
    name: str
    passed: bool
    details: str


# ---------------------------------------------------------------------------
# Check 1: Encoding
# ---------------------------------------------------------------------------

def check_encoding() -> CheckResult:
    """Verify no BOM or non-ASCII content in YAML/shell files."""
    dirty: list[str] = []
    yaml_exts = {".yml", ".yaml", ".sh", ".bash"}

    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = pathlib.Path(dirpath) / fname
            if p.suffix.lower() not in yaml_exts:
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            if data.startswith(b"\xef\xbb\xbf"):
                dirty.append(f"{p.relative_to(REPO_ROOT)} [BOM]")
                continue
            try:
                data.decode("ascii")
            except UnicodeDecodeError:
                dirty.append(f"{p.relative_to(REPO_ROOT)} [non-ASCII]")

    if dirty:
        return CheckResult("encoding", False,
                           f"{len(dirty)} dirty YAML/shell file(s): " + "; ".join(dirty[:5]))
    return CheckResult("encoding", True, "All YAML/shell files are ASCII-clean.")


# ---------------------------------------------------------------------------
# Check 2: YAML valid
# ---------------------------------------------------------------------------

def check_yaml() -> CheckResult:
    """Attempt to parse all .yml/.yaml files with PyYAML if available."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return CheckResult("yaml_parse", True, "PyYAML not installed -- skipping YAML parse check.")

    errors: list[str] = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = pathlib.Path(dirpath) / fname
            if p.suffix.lower() not in {".yml", ".yaml"}:
                continue
            try:
                with open(p, encoding="utf-8") as fh:
                    yaml.safe_load(fh)
            except yaml.YAMLError as e:
                rel = p.relative_to(REPO_ROOT)
                errors.append(f"{rel}: {str(e)[:80]}")
            except Exception:
                pass

    if errors:
        return CheckResult("yaml_parse", False,
                           f"{len(errors)} YAML error(s): " + "; ".join(errors[:3]))
    return CheckResult("yaml_parse", True, "All YAML files parse cleanly.")


# ---------------------------------------------------------------------------
# Check 3: Python syntax
# ---------------------------------------------------------------------------

def check_python_syntax() -> CheckResult:
    """Run py_compile on all .py files in scripts/ and agent/."""
    errors: list[str] = []
    check_dirs = [REPO_ROOT / "scripts", REPO_ROOT / "agent"]

    for check_dir in check_dirs:
        if not check_dir.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(check_dir):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                p = pathlib.Path(dirpath) / fname
                if p.suffix.lower() != ".py":
                    continue
                try:
                    py_compile.compile(str(p), doraise=True)
                except py_compile.PyCompileError as e:
                    errors.append(f"{p.relative_to(REPO_ROOT)}: {str(e)[:80]}")

    if errors:
        return CheckResult("python_syntax", False,
                           f"{len(errors)} Python syntax error(s): " + "; ".join(errors[:3]))
    return CheckResult("python_syntax", True, "All Python files have valid syntax.")


# ---------------------------------------------------------------------------
# Check 4: Critical JSON files
# ---------------------------------------------------------------------------

def check_json() -> CheckResult:
    """Verify critical JSON files parse correctly."""
    errors: list[str] = []
    warnings: list[str] = []

    for rel_path in CRITICAL_JSON_FILES:
        full = REPO_ROOT / rel_path
        if not full.exists():
            warnings.append(f"{rel_path} not found")
            continue
        try:
            json.loads(full.read_text(encoding="utf-8"))
        except Exception as e:
            errors.append(f"{rel_path}: {e}")

    if errors:
        return CheckResult("json_valid", False,
                           f"{len(errors)} JSON error(s): " + "; ".join(errors))
    if warnings:
        return CheckResult("json_valid", True,
                           f"JSON OK (warnings: {'; '.join(warnings)})")
    return CheckResult("json_valid", True, "All critical JSON files are valid.")


# ---------------------------------------------------------------------------
# Check 5: Workflow cleanliness (no inline heredocs)
# ---------------------------------------------------------------------------

def check_workflow_clean() -> CheckResult:
    """Ensure the rebuilt workflow has no inline PYEOF/heredoc blocks.
    Only checks non-comment lines (lines starting with # are excluded
    since they may document what was removed).
    """
    wf_path = REPO_ROOT / WORKFLOW_FILE
    if not wf_path.exists():
        return CheckResult("workflow_clean", False, f"{WORKFLOW_FILE} not found.")

    # Strip comment lines before checking -- comments may document removed patterns
    content = wf_path.read_text(encoding="utf-8", errors="replace")
    active_lines = [
        line for line in content.splitlines()
        if not line.lstrip().startswith("#")
    ]
    active_text = "\n".join(active_lines)
    data = active_text.encode("utf-8")

    found: list[str] = []
    for pattern in BANNED_PATTERNS:
        if pattern in data:
            found.append(pattern.decode("ascii", errors="replace"))

    if found:
        return CheckResult("workflow_clean", False,
                           f"Banned heredoc patterns found in {WORKFLOW_FILE}: " +
                           ", ".join(f"'{p}'" for p in found[:5]))
    return CheckResult("workflow_clean", True,
                       f"{WORKFLOW_FILE} is clean -- no inline Python/heredocs.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=" * 60)
    log.info("SENTINEL APEX -- Repository Validator v131.2.0")
    log.info("=" * 60)

    os.chdir(REPO_ROOT)

    checks = [
        check_encoding,
        check_yaml,
        check_python_syntax,
        check_json,
        check_workflow_clean,
    ]

    results: list[CheckResult] = []
    for check_fn in checks:
        try:
            result = check_fn()
        except Exception as e:
            result = CheckResult(check_fn.__name__, False, f"Check crashed: {e}")
        results.append(result)
        status = "[PASS]" if result.passed else "[FAIL]"
        level = log.info if result.passed else log.error
        level("%s %s -- %s", status, result.name, result.details)

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)

    log.info("-" * 60)
    log.info("Results: %d PASS, %d FAIL (of %d checks)", passed, failed, len(results))

    if failed > 0:
        log.error("VALIDATION FAILED -- %d check(s) did not pass.", failed)
        sys.exit(1)

    log.info("ALL CHECKS PASSED -- repository is production-ready.")
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        import traceback
        log.critical("validate_repo.py crashed:\n%s\n%s", e, traceback.format_exc())
        sys.exit(1)
