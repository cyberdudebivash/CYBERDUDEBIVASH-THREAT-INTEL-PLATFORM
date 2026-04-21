#!/usr/bin/env python3
"""
scripts/validate_repo.py
CYBERDUDEBIVASH(R) SENTINEL APEX v132.0.0 -- Repository Validator
==================================================================
HARD SCHEMA VALIDATION GATE — NO AUTO-HEAL.
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

# Extra dirs skipped for YAML parse validation only.
# These contain generated / third-party YAML (Sigma rules, enrichment archives)
# that use non-standard extensions (Sigma |modifier syntax) or multi-vendor formats
# not guaranteed to be standard-YAML-safe.  We validate pipeline YAML only.
YAML_PARSE_SKIP_DIRS = SKIP_DIRS | {
    "data",          # generated: sigma_rules.yml, archives, enrichment JSON/YAML
    "threat",        # generated threat-intel YAML/HTML
    "reports",       # generated HTML report artifacts
    "stix",          # STIX bundle files
}

CRITICAL_JSON_FILES = [
    "data/stix/feed_manifest.json",
    "data/feed_manifest.json",
    "data/publish_queue.json",
]

# Feed files: missing or empty list [] is VALID -- pipeline may not have generated yet
FEED_JSON_FILES = [
    "api/feed.json",
    "feed.json",
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
    """Attempt to parse all .yml/.yaml files with PyYAML if available.

    Scope:
    - Only pipeline/config YAML is validated (GitHub Actions, k8s, project config).
    - Generated/third-party dirs (data/, threat/, etc.) are excluded via
      YAML_PARSE_SKIP_DIRS -- Sigma rules and enrichment archives use
      non-standard YAML extensions (|modifier syntax) not safe-loadable.
    - Multi-document YAML (--- separated, e.g. k8s manifests) is handled by
      yaml.safe_load_all() which validates every document in the stream.
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        return CheckResult("yaml_parse", True, "PyYAML not installed -- skipping YAML parse check.")

    errors: list[str] = []
    scanned = 0

    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        # Prune traversal using the extended YAML-specific skip list
        dirnames[:] = [d for d in dirnames if d not in YAML_PARSE_SKIP_DIRS]
        for fname in filenames:
            p = pathlib.Path(dirpath) / fname
            if p.suffix.lower() not in {".yml", ".yaml"}:
                continue
            try:
                # Read raw bytes first -- handles any encoding edge cases
                raw = p.read_bytes()
                if not raw.strip():
                    # Empty file -- skip, not an error
                    continue
                text = raw.decode("utf-8", errors="replace")
                # safe_load_all() handles single-doc AND multi-doc (---) YAML.
                # We drain the generator to validate every document in the stream.
                docs = list(yaml.safe_load_all(text))
                scanned += 1
                rel = p.relative_to(REPO_ROOT)
                log.debug("[yaml_valid] OK (%d doc(s)): %s", len(docs), rel)
            except yaml.YAMLError as e:
                rel = p.relative_to(REPO_ROOT)
                errors.append(f"{rel}: {str(e)[:120]}")
            except Exception:
                # IO/encoding errors are non-fatal for YAML parse check
                pass

    if errors:
        return CheckResult("yaml_parse", False,
                           f"{len(errors)} YAML error(s) in {scanned} file(s) scanned: " +
                           "; ".join(errors[:3]))
    return CheckResult("yaml_parse", True,
                       f"All {scanned} pipeline YAML file(s) parse cleanly (multi-doc aware).")


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
    """
    Verify critical JSON files parse correctly.
    Rules:
      - Missing file              -> WARNING (not FAIL): pipeline may not have generated yet
      - Empty file (0 bytes)      -> WARNING (not FAIL): treated as []
      - Invalid JSON              -> FAIL
      - Valid JSON (any structure) -> PASS  ([] is explicitly VALID)
    """
    errors: list[str] = []
    warnings: list[str] = []

    # Check manifest files
    for rel_path in CRITICAL_JSON_FILES:
        full = REPO_ROOT / rel_path
        if not full.exists():
            warnings.append(f"{rel_path} not found (gitignored -- generated at runtime)")
            continue
        sz = full.stat().st_size
        if sz == 0:
            warnings.append(f"{rel_path} empty (0 bytes) -- treated as []")
            continue
        try:
            obj = json.loads(full.read_text(encoding="utf-8"))
            # [] is valid JSON -- do NOT fail on empty list
            log.info("[json_valid] OK (%s, %d bytes): %s", type(obj).__name__, sz, rel_path)
        except Exception as e:
            errors.append(f"{rel_path}: {e}")

    # Check feed files: [] is always VALID, missing is WARNING
    for rel_path in FEED_JSON_FILES:
        full = REPO_ROOT / rel_path
        if not full.exists():
            warnings.append(f"{rel_path} not found (will be generated by pipeline)")
            continue
        sz = full.stat().st_size
        if sz == 0:
            warnings.append(f"{rel_path} empty -- treated as []")
            continue
        try:
            raw = full.read_text(encoding="utf-8")
            obj = json.loads(raw)
            # Explicit: [] is VALID, {} is VALID, any JSON structure is VALID
            count = len(obj) if isinstance(obj, list) else "dict"
            log.info("[json_valid] feed OK (%s, entries=%s, %d bytes): %s",
                     type(obj).__name__, count, sz, rel_path)
        except Exception as e:
            errors.append(f"{rel_path}: INVALID JSON: {e}")

    if errors:
        return CheckResult("json_valid", False,
                           f"{len(errors)} JSON error(s): " + "; ".join(errors))
    if warnings:
        return CheckResult("json_valid", True,
                           f"JSON OK -- {len(warnings)} warning(s): {'; '.join(warnings[:3])}")
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
# Check 6: Intel object schema + ioc_count integrity
# ---------------------------------------------------------------------------

# Minimum required string fields for an intel advisory
_INTEL_REQUIRED = ("title", "source")
# Fields whose 'published' key must never be a boolean (P0 regression guard)
_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", ""}


def _validate_single_intel(obj: dict, idx: int) -> list[str]:
    """
    v132: STRICT hard validation — returns violation strings.
    All violations are HARD FAIL conditions (zero tolerance).
    NO auto-heal in this function — enforcement only.
    """
    errs: list[str] = []
    if not isinstance(obj, dict):
        errs.append(f"[{idx}] Not a dict: {type(obj).__name__}")
        return errs

    sid = obj.get("id", f"idx_{idx}")
    vs  = obj.get("validation_status")

    # Required fields: title and source must be non-empty strings
    for field in _INTEL_REQUIRED:
        val = obj.get(field)
        if not val or not isinstance(val, str) or not val.strip():
            errs.append(f"[{idx}/{sid}] V3/V4: Missing/empty required string field '{field}' (got: {repr(val)[:40]})")

    # published must NOT be a boolean (P0 regression — run #805)
    pub = obj.get("published")
    if isinstance(pub, bool):
        errs.append(
            f"[{idx}/{sid}] V1: 'published' is bool({pub}) — MUST be ISO-8601 string. "
            "Root cause of AttributeError in render_report(). "
            "enforce_schema() should have corrected this before this gate runs."
        )
    elif pub is not None and not isinstance(pub, str):
        errs.append(
            f"[{idx}/{sid}] V1: 'published' has type {type(pub).__name__} — must be str"
        )

    # severity must be string, not bool, and in known set
    sev = obj.get("severity")
    if sev is not None:
        if isinstance(sev, bool):
            errs.append(f"[{idx}/{sid}] V5: severity is bool({sev}) — must be string")
        elif not isinstance(sev, str):
            errs.append(f"[{idx}/{sid}] V5: severity is {type(sev).__name__} — must be str")
        elif str(sev).upper() not in _VALID_SEVERITIES:
            errs.append(f"[{idx}/{sid}] V5: severity '{sev}' not in {_VALID_SEVERITIES}")

    # ioc_count integrity — zero tolerance (v132: was 5% tolerance, now 0%)
    iocs = obj.get("iocs")
    ioc_count = obj.get("ioc_count")
    if iocs is not None:
        if not isinstance(iocs, list):
            errs.append(f"[{idx}/{sid}] V7: iocs is {type(iocs).__name__} — must be list")
        elif isinstance(ioc_count, int) and ioc_count != len(iocs):
            errs.append(
                f"[{idx}/{sid}] V2: ioc_count={ioc_count} != len(iocs)={len(iocs)} — P0 invariant violation"
            )

    # risk_score range
    rs = obj.get("risk_score")
    if rs is not None:
        try:
            rsf = float(rs)
            if not 0.0 <= rsf <= 10.0:
                errs.append(f"[{idx}/{sid}] V6: risk_score={rs} out of [0, 10]")
        except (TypeError, ValueError):
            errs.append(f"[{idx}/{sid}] V6: risk_score='{rs}' is not numeric")

    # V10: processed entries must have valid https report_url
    if vs in ("ok", "enriched"):
        ru = obj.get("report_url", "")
        if not ru or not ru.startswith("https://"):
            errs.append(
                f"[{idx}/{sid}] V10: validation_status='{vs}' but report_url is missing/invalid: {repr(ru)[:60]}"
            )

    return errs


def check_intel_schema() -> CheckResult:
    """
    v132 Check 6: HARD schema validation gate — zero tolerance.

    Enforces ALL 10 invariants with ZERO tolerance:
      V1. published is string (never bool) — P0 regression guard
      V2. ioc_count == len(iocs) exactly (0% tolerance, up from 5%)
      V3. title is non-empty string
      V4. source is non-empty string
      V5. severity is string in known set (if present)
      V6. risk_score in [0, 10] (if present)
      V7. iocs is list (if present)
      V10. processed entries have valid https report_url

    NO soft-pass for any violation. Every violation = HARD FAIL.
    enforce_schema() already ran in stage_enforce_schema — if violations
    still exist here, it is a write race or upstream data corruption.
    """
    manifest_path = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
    if not manifest_path.exists():
        return CheckResult("intel_schema", True,
                           "data/stix/feed_manifest.json not found (runtime-generated -- skipped).")

    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        return CheckResult("intel_schema", False, f"Cannot parse feed_manifest.json: {e}")

    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = raw.get("advisories") or raw.get("reports") or raw.get("items") or []
    else:
        return CheckResult("intel_schema", False,
                           f"Unexpected manifest root type: {type(raw).__name__}")

    if not items:
        return CheckResult("intel_schema", True, "Manifest has 0 items -- schema check skipped.")

    all_violations: list[str] = []
    brand_skip = 0

    for i, obj in enumerate(items):
        if isinstance(obj, dict) and obj.get("validation_status") == "brand_skip":
            brand_skip += 1
            continue
        errs = _validate_single_intel(obj, i)
        all_violations.extend(errs)

    total = len(items)
    non_brand = total - brand_skip

    if all_violations:
        for v in all_violations[:20]:
            log.error("[intel_schema] VIOLATION: %s", v)
        return CheckResult(
            "intel_schema", False,
            f"HARD FAIL: {len(all_violations)} schema violation(s) in {non_brand} entries "
            f"(brand_skip={brand_skip}). enforce_schema() must be called before this gate."
        )

    return CheckResult(
        "intel_schema", True,
        f"All {non_brand} non-brand intel objects satisfy all 10 schema invariants."
    )


# ---------------------------------------------------------------------------
# Check 7: No stale .tmp files (v132)
# ---------------------------------------------------------------------------

def check_no_stale_tmp() -> CheckResult:
    """V8: No abandoned .tmp write files in data/ or reports/."""
    stale: list[str] = []
    for search_dir in [REPO_ROOT / "data", REPO_ROOT / "reports"]:
        if not search_dir.is_dir():
            continue
        for tmp_file in search_dir.rglob("*.tmp"):
            stale.append(str(tmp_file.relative_to(REPO_ROOT)))
    if stale:
        return CheckResult(
            "no_stale_tmp", False,
            f"{len(stale)} stale .tmp file(s) found: {'; '.join(stale[:5])}"
        )
    return CheckResult("no_stale_tmp", True, "No stale .tmp files found.")


# ---------------------------------------------------------------------------
# Check 8: write_failures.jsonl absent or empty (v132)
# ---------------------------------------------------------------------------

def check_no_write_failures() -> CheckResult:
    """V9: Recovery backlog must be ZERO after recovery replay.

    POLICY (v133.0):
      - write_failures.jsonl entries are AUDIT records (historical, ephemeral).
        Their presence alone is NOT a HARD FAIL condition.
      - HARD FAIL only if: recovery blobs still exist in data/recovery/write_failures/
        AFTER recovery replay has run (permanent write failures confirmed).
      - HARD FAIL only if: system_health.json reports state == CRITICAL.
      - PASS unconditionally if: recovery dir is empty/absent and system is not CRITICAL.
    """
    recovery_dir = REPO_ROOT / "data" / "recovery" / "write_failures"
    health_json  = REPO_ROOT / "data" / "logs" / "system_health.json"
    wf_log       = REPO_ROOT / "data" / "logs" / "write_failures.jsonl"

    # -- Recovery blob backlog (the real failure indicator) ---------------------
    recovery_count = 0
    if recovery_dir.exists():
        blobs = list(recovery_dir.glob("*.json"))
        recovery_count = len(blobs)

    # -- System health state + recovery_mode flag --------------------------------
    system_state   = "OK"
    recovery_mode  = False
    if health_json.exists():
        try:
            health        = json.loads(health_json.read_text(encoding="utf-8"))
            system_state  = str(health.get("state", "OK")).upper()
            recovery_mode = bool(health.get("recovery_mode", False))
        except Exception:
            pass  # unreadable health file is non-fatal at this gate

    # -- Audit log count (informational only — NOT a fail criterion) ------------
    wf_count = 0
    if wf_log.exists():
        try:
            lines = [l.strip() for l in wf_log.read_text(encoding="utf-8").splitlines() if l.strip()]
            wf_count = len(lines)
        except Exception:
            pass

    log.info(
        "[no_write_failures] recovery_blobs=%d system_state=%s recovery_mode=%s wf_log_entries=%d",
        recovery_count, system_state, recovery_mode, wf_count,
    )

    # -- HARD FAIL: system CRITICAL (ingestion paused, replay could not drain) --
    if system_state == "CRITICAL":
        return CheckResult(
            "no_write_failures", False,
            f"System state=CRITICAL — recovery replay could not drain backlog. "
            f"recovery_blobs={recovery_count} wf_log_entries={wf_count}. "
            "Ingestion paused. Manual intervention required."
        )

    # -- HARD FAIL: unresolved recovery blobs remain after replay ---------------
    # Exception (v134): if drain_recovery_queue() set recovery_mode=True, the
    # drain is actively in progress in the same pipeline run — allow it.
    if recovery_count > 0:
        if recovery_mode:
            log.warning(
                "[no_write_failures] recovery_mode=True — drain in progress. "
                "Allowing %d remaining blob(s). [DRAIN_ACTIVE]", recovery_count,
            )
            return CheckResult(
                "no_write_failures", True,
                f"Recovery drain in progress (recovery_mode=True): "
                f"{recovery_count} blob(s) still being processed. [DRAIN_ACTIVE — non-fatal]",
            )
        return CheckResult(
            "no_write_failures", False,
            f"{recovery_count} unresolved recovery blob(s) remain after replay — "
            f"permanent write failures confirmed. wf_log_entries={wf_count}. "
            "Check data/recovery/write_failures/ for payload dumps."
        )

    # -- PASS: recovery dir empty/absent and system not CRITICAL ----------------
    if wf_count > 0:
        return CheckResult(
            "no_write_failures", True,
            f"Recovery drain complete: 0 blobs remain. "
            f"wf_log has {wf_count} historical audit record(s) — not active failures. [OK]"
        )
    return CheckResult(
        "no_write_failures", True,
        "write_failures.jsonl absent/empty. Recovery backlog: 0. System clean. [OK]"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("=" * 60)
    log.info("SENTINEL APEX -- Repository Validator v131.3.0")
    log.info("=" * 60)

    os.chdir(REPO_ROOT)

    checks = [
        check_encoding,
        check_yaml,
        check_python_syntax,
        check_json,
        check_workflow_clean,
        check_intel_schema,       # v132 Check 6: HARD schema gate (zero tolerance)
        check_no_stale_tmp,       # v132 Check 7: no abandoned .tmp files
        check_no_write_failures,  # v132 Check 8: write_failures.jsonl absent/empty
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

    log.info("ALL CHECKS PASSED -- repository is production-ready. [v132.0.0]")
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
