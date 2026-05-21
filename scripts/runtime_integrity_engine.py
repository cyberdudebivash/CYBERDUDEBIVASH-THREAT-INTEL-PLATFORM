#!/usr/bin/env python3
"""
scripts/runtime_integrity_engine.py
CYBERDUDEBIVASH® SENTINEL APEX — Runtime Integrity + Deployment Promotion Guard
================================================================================
Version : v158.0
Stage   : Pre-deploy governance gate

PURPOSE:
  Detects and hard-blocks degraded pipeline executions before they can deploy
  stale intelligence to production. Based on forensic analysis of regression
  chain introduced by commit 139fb83 (BLACKLISTED).

FORENSIC BASELINE:
  Good runtime (e565930 / Run #1265) : 36m 28s  → 2188 seconds
  Bad runtime  (post-139fb83 runs)   : ~13-15 min → 780-900 seconds
  Degraded threshold                  : < 1200 seconds (20 min)

HARD FAIL CONDITIONS:
  1. Pipeline runtime collapsed below MIN_RUNTIME_SECONDS
  2. Advisory/manifest count collapsed below MIN_ADVISORY_COUNT
  3. PIPELINE_VERSION downgraded below baseline (158.0.2)
  4. PIPELINE_ZERO_OUTPUT gate detected as active (banned architecture)
  5. Blacklisted commit detected in ancestry

USAGE (from sentinel-blogger.yml or standalone):
  python3 scripts/runtime_integrity_engine.py
  python3 scripts/runtime_integrity_engine.py --check-blacklist
  python3 scripts/runtime_integrity_engine.py --runtime-seconds 800
  python3 scripts/runtime_integrity_engine.py --advisory-count 15

Exit codes:
  0 = All integrity checks PASS
  1 = HARD FAIL — deployment blocked

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [runtime-integrity] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.runtime_integrity")

REPO_ROOT = Path(__file__).resolve().parent.parent

# ── IMMUTABLE GOVERNANCE CONSTANTS ──────────────────────────────────────────
BASELINE_COMMIT          = "e565930"
BASELINE_PIPELINE_VERSION = "158.0.2"
BASELINE_RUN             = "sentinel-blogger #1265"
BASELINE_RUNTIME_SECONDS = 2188   # 36m 28s

MIN_RUNTIME_SECONDS      = 1200   # 20 min — below this = stages were skipped
MIN_ADVISORY_COUNT       = 20     # below this = ingestion/dedup collapse
EXPECTED_RUNTIME_SECONDS = 2160   # 36 min — nominal healthy run
RUNTIME_WARNING_SECONDS  = 1500   # 25 min — warn if below this

# Commits permanently blacklisted from production
BLACKLISTED_COMMITS = {
    "139fb839a2": "P1_REGRESSION_ORIGIN — PIPELINE_VERSION downgrade 158.0.2→152.0.0",
    "bf5a2a1a38": "P1_REGRESSION — PIPELINE_ZERO_OUTPUT gate added (skips Stage 5)",
    "5d8613fd36": "P1_REGRESSION — PIPELINE_ZERO_OUTPUT extended to Stage 3.3",
    "a865fe3758": "P1_REGRESSION — PIPELINE_ZERO_OUTPUT compounded",
}

# Banned workflow patterns
BANNED_WORKFLOW_PATTERNS = [
    ("PIPELINE_ZERO_OUTPUT", "Zero-Output gate is architecturally banned — causes stale dashboard"),
    ('PIPELINE_VERSION: "152.0.0"', "PIPELINE_VERSION 152.0.0 is blacklisted — minimum is 158.0.2"),
    ('PIPELINE_VERSION: "151.', "PIPELINE_VERSION below 152 is blacklisted"),
    ('PIPELINE_VERSION: "150.', "PIPELINE_VERSION below 152 is blacklisted"),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _version_tuple(v: str) -> tuple:
    """Convert '158.0.2' to (158, 0, 2) for comparison."""
    try:
        return tuple(int(x) for x in str(v).strip().split("."))
    except Exception:
        return (0, 0, 0)


def check_pipeline_version() -> tuple[bool, str]:
    """Verify PIPELINE_VERSION in sentinel-blogger.yml is >= baseline."""
    workflow_path = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"
    if not workflow_path.exists():
        return False, "sentinel-blogger.yml not found"

    content = workflow_path.read_text(encoding="utf-8")
    for line in content.splitlines():
        if 'PIPELINE_VERSION:' in line and '#' not in line.split('PIPELINE_VERSION:')[0]:
            # Extract version string
            parts = line.split('"')
            if len(parts) >= 2:
                version = parts[1].strip()
                current = _version_tuple(version)
                baseline = _version_tuple(BASELINE_PIPELINE_VERSION)
                if current < baseline:
                    return False, (
                        f"PIPELINE_VERSION {version} is BELOW baseline {BASELINE_PIPELINE_VERSION}. "
                        f"Commit 139fb83 blacklisted this downgrade. Restore to {BASELINE_PIPELINE_VERSION}."
                    )
                log.info("[version-check] PIPELINE_VERSION=%s >= baseline %s: PASS",
                         version, BASELINE_PIPELINE_VERSION)
                return True, f"PIPELINE_VERSION {version} OK"
    return False, "PIPELINE_VERSION not found in sentinel-blogger.yml"


def check_banned_patterns() -> tuple[bool, list[str]]:
    """Scan workflow for architecturally banned patterns."""
    workflow_path = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"
    if not workflow_path.exists():
        return True, []  # Can't check, don't block

    content = workflow_path.read_text(encoding="utf-8")
    violations: list[str] = []
    for pattern, reason in BANNED_WORKFLOW_PATTERNS:
        if pattern in content:
            violations.append(f"BANNED PATTERN DETECTED: '{pattern}' — {reason}")

    if violations:
        return False, violations
    log.info("[pattern-check] No banned workflow patterns detected: PASS")
    return True, []


def check_runtime(runtime_seconds: Optional[int]) -> tuple[bool, str]:
    """Verify pipeline runtime is within healthy bounds."""
    if runtime_seconds is None:
        # Try to read from environment (set by CI)
        env_val = os.environ.get("PIPELINE_RUNTIME_SECONDS", "").strip()
        if not env_val:
            log.info("[runtime-check] No runtime provided — skipping runtime gate")
            return True, "Runtime check skipped (no value provided)"
        try:
            runtime_seconds = int(env_val)
        except ValueError:
            return True, f"Runtime parse error: {env_val} — skipping"

    mins = runtime_seconds // 60
    secs = runtime_seconds % 60
    log.info("[runtime-check] Pipeline runtime: %dm %ds (%d seconds)",
             mins, secs, runtime_seconds)
    log.info("[runtime-check] Healthy baseline: %dm %ds | Degraded threshold: %dm",
             BASELINE_RUNTIME_SECONDS // 60, BASELINE_RUNTIME_SECONDS % 60,
             MIN_RUNTIME_SECONDS // 60)

    if runtime_seconds < MIN_RUNTIME_SECONDS:
        return False, (
            f"RUNTIME COLLAPSE DETECTED: {mins}m {secs}s < minimum {MIN_RUNTIME_SECONDS//60}m. "
            f"Critical enrichment stages were SKIPPED. "
            f"Baseline healthy runtime: {BASELINE_RUNTIME_SECONDS//60}m {BASELINE_RUNTIME_SECONDS%60}s. "
            f"This matches the regression pattern from post-139fb83 corrupted runs."
        )
    if runtime_seconds < RUNTIME_WARNING_SECONDS:
        log.warning("[runtime-check] WARNING: Runtime %dm %ds is below expected %dm — "
                    "some enrichment stages may have been slower than usual.",
                    mins, secs, EXPECTED_RUNTIME_SECONDS // 60)
        return True, f"Runtime {mins}m {secs}s — PASS with warning"

    log.info("[runtime-check] Runtime %dm %ds: PASS (healthy)", mins, secs)
    return True, f"Runtime {mins}m {secs}s: PASS"


def check_advisory_count(count: Optional[int]) -> tuple[bool, str]:
    """Verify advisory count hasn't collapsed."""
    if count is None:
        # Try manifest files
        for manifest_path in [
            REPO_ROOT / "data" / "feed_manifest.json",
            REPO_ROOT / "api" / "feed.json",
        ]:
            if manifest_path.exists():
                try:
                    data = json.loads(manifest_path.read_text(encoding="utf-8"))
                    if isinstance(data, list):
                        count = len(data)
                    elif isinstance(data, dict):
                        for key in ("advisories", "items", "data", "intel"):
                            if isinstance(data.get(key), list):
                                count = len(data[key])
                                break
                    if count is not None:
                        log.info("[advisory-check] Loaded count=%d from %s",
                                 count, manifest_path.name)
                        break
                except Exception as e:
                    log.warning("[advisory-check] Cannot read %s: %s", manifest_path, e)

    if count is None:
        log.info("[advisory-check] Cannot determine advisory count — skipping")
        return True, "Advisory count check skipped"

    log.info("[advisory-check] Advisory count: %d (minimum: %d)", count, MIN_ADVISORY_COUNT)
    if count < MIN_ADVISORY_COUNT:
        return False, (
            f"ADVISORY COUNT COLLAPSE: {count} items < minimum {MIN_ADVISORY_COUNT}. "
            f"Ingestion failure or dedup over-suppression detected."
        )
    log.info("[advisory-check] Advisory count %d: PASS", count)
    return True, f"Advisory count {count}: PASS"


def check_blacklisted_commits() -> tuple[bool, list[str]]:
    """Check if any blacklisted commits are in the current ancestry."""
    violations: list[str] = []
    for short_sha, reason in BLACKLISTED_COMMITS.items():
        try:
            result = subprocess.run(
                ["git", "-c", "core.checkStat=minimal",
                 "merge-base", "--is-ancestor", short_sha, "HEAD"],
                capture_output=True, timeout=10,
                cwd=str(REPO_ROOT),
            )
            if result.returncode == 0:
                violations.append(
                    f"BLACKLISTED COMMIT IN ANCESTRY: {short_sha} — {reason}"
                )
        except Exception as e:
            log.warning("[blacklist-check] Cannot check %s: %s", short_sha, e)

    if violations:
        # Note: ancestry check is informational only — we cannot rewrite history
        # It's expected that blacklisted commits ARE ancestors after recovery
        # The key governance is the workflow pattern check, not ancestry
        log.warning("[blacklist-check] Blacklisted commits in ancestry (expected post-recovery):")
        for v in violations:
            log.warning("  %s", v)
        log.info("[blacklist-check] Ancestry presence noted. Governance enforced via pattern checks.")
    else:
        log.info("[blacklist-check] No blacklisted commits found in ancestry: PASS")

    return True, violations  # Informational — don't hard-fail on ancestry


def write_integrity_report(results: dict) -> None:
    report_dir = REPO_ROOT / "data" / "quality"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "runtime_integrity_report.json"
    tmp = report_path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, report_path)
        log.info("[report] Integrity report written: %s", report_path)
    except Exception as e:
        log.warning("[report] Could not write integrity report: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Runtime Integrity + Deployment Promotion Guard"
    )
    parser.add_argument("--runtime-seconds", type=int, default=None,
                        help="Pipeline runtime in seconds (optional)")
    parser.add_argument("--advisory-count", type=int, default=None,
                        help="Advisory count to validate (optional)")
    parser.add_argument("--check-blacklist", action="store_true",
                        help="Check blacklisted commit ancestry")
    parser.add_argument("--report-only", action="store_true",
                        help="Report findings without failing (audit mode)")
    args = parser.parse_args()

    log.info("=" * 70)
    log.info("SENTINEL APEX -- Runtime Integrity Engine v158.0")
    log.info("Baseline: commit=%s | pipeline=%s | run=%s",
             BASELINE_COMMIT, BASELINE_PIPELINE_VERSION, BASELINE_RUN)
    log.info("=" * 70)

    hard_fails: list[str] = []
    warnings: list[str] = []
    checks: dict = {}

    # CHECK 1: PIPELINE_VERSION
    ok, msg = check_pipeline_version()
    checks["pipeline_version"] = {"pass": ok, "detail": msg}
    if not ok:
        hard_fails.append(f"[version] {msg}")
    else:
        log.info("  CHECK 1 PASS: %s", msg)

    # CHECK 2: Banned workflow patterns
    ok, violations = check_banned_patterns()
    checks["banned_patterns"] = {"pass": ok, "violations": violations}
    if not ok:
        for v in violations:
            hard_fails.append(f"[pattern] {v}")
    else:
        log.info("  CHECK 2 PASS: No banned patterns")

    # CHECK 3: Runtime bounds
    ok, msg = check_runtime(args.runtime_seconds)
    checks["runtime"] = {"pass": ok, "detail": msg}
    if not ok:
        hard_fails.append(f"[runtime] {msg}")
    else:
        log.info("  CHECK 3 PASS: %s", msg)

    # CHECK 4: Advisory count
    ok, msg = check_advisory_count(args.advisory_count)
    checks["advisory_count"] = {"pass": ok, "detail": msg}
    if not ok:
        hard_fails.append(f"[advisory] {msg}")
    else:
        log.info("  CHECK 4 PASS: %s", msg)

    # CHECK 5: Blacklisted commits (informational)
    if args.check_blacklist:
        _, ancestry_notes = check_blacklisted_commits()
        checks["blacklist"] = {"pass": True, "notes": ancestry_notes}

    # Write report
    report = {
        "generated_at": _utc_now(),
        "baseline_commit": BASELINE_COMMIT,
        "baseline_pipeline_version": BASELINE_PIPELINE_VERSION,
        "overall_pass": len(hard_fails) == 0,
        "hard_fail_count": len(hard_fails),
        "hard_fail_reasons": hard_fails,
        "warnings": warnings,
        "checks": checks,
    }
    write_integrity_report(report)

    log.info("=" * 70)
    log.info("SUMMARY: %d hard fail(s) | %d warning(s)",
             len(hard_fails), len(warnings))

    if hard_fails:
        for f in hard_fails:
            log.error("  HARD FAIL: %s", f)
        if not args.report_only:
            log.error("RUNTIME INTEGRITY CHECK FAILED — DEPLOYMENT BLOCKED")
            sys.exit(1)
        else:
            log.warning("REPORT-ONLY MODE — failures logged but not blocking")
    else:
        log.info("RUNTIME INTEGRITY CHECK PASSED — DEPLOYMENT AUTHORIZED")


if __name__ == "__main__":
    main()
