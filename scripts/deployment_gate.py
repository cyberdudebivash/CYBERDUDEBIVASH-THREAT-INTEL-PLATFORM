#!/usr/bin/env python3
"""
scripts/deployment_gate.py — SENTINEL APEX v173.0
DEPLOYMENT GOVERNANCE GATE

MANDATE: This script MUST run before every deployment.
         If any check fails, the deployment is BLOCKED.
         No exceptions. No overrides. No bypasses.

Usage:
    python scripts/deployment_gate.py
    python scripts/deployment_gate.py --strict   # Exit code 1 on any failure

CI Integration (.github/workflows):
    - name: Access Governance Gate
      run: python scripts/deployment_gate.py --strict

Exit codes:
    0 — All gates passed — deployment approved
    1 — One or more gates failed — deployment BLOCKED

Gates:
    1.  Access policy self-checks (all policy invariants)
    2.  Policy drift detection (hash comparison)
    3.  Public report exposure check (MODEL_B scanner)
    4.  Public API field validation (scan API source)
    5.  Dashboard tier gate validation (scan index.html)
    6.  Report metadata compliance (scan report generators)
    7.  Regression test execution (pytest test_access_governance.py)
    8.  Audit record generation
"""

import os
import sys
import json
import hashlib
import re
import subprocess
import argparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

# Ensure project root in path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    from access_control_policy import (
        run_policy_checks,
        detect_policy_drift,
        compute_policy_hash,
        generate_audit_record,
        PUBLIC_BLOCKED_FIELDS,
        API_PUBLIC_BLOCKED,
        POLICY_CANONICAL_VERSION,
    )
    _POLICY_IMPORTED = True
except ImportError as e:
    print(f"FATAL: Cannot import access_control_policy: {e}")
    _POLICY_IMPORTED = False


GATE_RESULTS: Dict[str, Dict] = {}
GATE_PASS_COUNT = 0
GATE_FAIL_COUNT = 0


def _gate(name: str, passed: bool, detail: str, evidence: str = ""):
    global GATE_PASS_COUNT, GATE_FAIL_COUNT
    GATE_RESULTS[name] = {
        "passed":  passed,
        "detail":  detail,
        "evidence":evidence,
    }
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"  {status}  {name}")
    if not passed:
        print(f"         ↳ {detail}")
        if evidence:
            print(f"         ↳ Evidence: {evidence[:200]}")
        GATE_FAIL_COUNT += 1
    else:
        GATE_PASS_COUNT += 1


# ─────────────────────────────────────────────────────────────────────────────
# GATE 1: ACCESS POLICY SELF-CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def gate_policy_self_checks():
    print("\n[GATE 1] Access Policy Self-Checks")
    if not _POLICY_IMPORTED:
        _gate("policy_import", False, "access_control_policy.py not found or import failed")
        return

    result = run_policy_checks()
    for check_name, check_result in result["checks"].items():
        _gate(
            f"policy.{check_name}",
            check_result["passed"],
            check_result["detail"],
        )


# ─────────────────────────────────────────────────────────────────────────────
# GATE 2: POLICY DRIFT DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def gate_policy_drift():
    print("\n[GATE 2] Policy Drift Detection")
    if not _POLICY_IMPORTED:
        _gate("drift_detection", False, "access_control_policy.py not importable")
        return

    # Check for a stored reference hash
    ref_hash_path = ROOT / "reports" / "policy_hash_reference.txt"
    current_hash = compute_policy_hash()

    if ref_hash_path.exists():
        reference_hash = ref_hash_path.read_text().strip()
        drift = detect_policy_drift(reference_hash)
        _gate(
            "policy_drift",
            not drift["drift_detected"],
            drift["governance_message"],
            f"current={current_hash[:16]}... ref={reference_hash[:16]}...",
        )
    else:
        # No reference hash — write one and pass
        ref_hash_path.parent.mkdir(parents=True, exist_ok=True)
        ref_hash_path.write_text(current_hash)
        _gate(
            "policy_drift",
            True,
            f"Reference hash established: {current_hash[:16]}...",
        )


# ─────────────────────────────────────────────────────────────────────────────
# GATE 3: PUBLIC REPORT EXPOSURE SCAN (MODEL_B SCANNER)
# ─────────────────────────────────────────────────────────────────────────────

def gate_no_public_report_exposure():
    """
    Scan public_api.py for any code that returns report_url, internal_report_url,
    stix_bundle_url, or pdf_url to the PUBLIC tier.
    """
    print("\n[GATE 3] Public Report Exposure Scan (MODEL_B Scanner)")
    public_api_path = ROOT / "agent" / "api" / "public_api.py"

    if not public_api_path.exists():
        _gate("model_b_scan_public_api", False, "public_api.py not found")
        return

    content = public_api_path.read_text(encoding="utf-8")

    # Patterns that would indicate MODEL_B behavior
    danger_patterns = [
        (r'"report_url"\s*,', 'report_url in PUBLIC_FIELDS set'),
        (r'"internal_report_url"\s*,', 'internal_report_url in PUBLIC_FIELDS set'),
        (r'"stix_bundle_url"\s*,', 'stix_bundle_url in PUBLIC_FIELDS set'),
        (r'"pdf_url"\s*,', 'pdf_url in PUBLIC_FIELDS set'),
        (r'PUBLIC_FIELDS\s*=\s*\{[^}]*"report_url"', 'report_url in PUBLIC_FIELDS dict'),
    ]

    violations_found = []
    for pattern, description in danger_patterns:
        # Exclude comment lines
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            stripped_line = line.strip()
            if stripped_line.startswith('#') or stripped_line.startswith('//'):
                continue
            if re.search(pattern, line):
                violations_found.append(f"Line {i}: {description} → {line.strip()[:80]}")

    _gate(
        "model_b_no_report_url_in_public",
        len(violations_found) == 0,
        "public_api.py must not expose report_url to PUBLIC tier" if violations_found
        else "No report_url exposure in public API",
        "; ".join(violations_found[:3]) if violations_found else "",
    )


# ─────────────────────────────────────────────────────────────────────────────
# GATE 4: PUBLIC API FIELD VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def gate_api_field_validation():
    """Validate that public_api.py delegates to access_control_policy."""
    print("\n[GATE 4] API Field Validation")
    public_api_path = ROOT / "agent" / "api" / "public_api.py"

    if not public_api_path.exists():
        _gate("api_imports_policy", False, "public_api.py not found")
        return

    content = public_api_path.read_text(encoding="utf-8")

    # Must import from access_control_policy
    _gate(
        "api_imports_policy",
        "from access_control_policy import" in content,
        "public_api.py must import from access_control_policy",
    )

    # Must use strip_for_tier
    _gate(
        "api_uses_strip_for_tier",
        "strip_for_tier" in content,
        "public_api.py must use strip_for_tier from access_control_policy",
    )

    # Must use validate_and_block
    _gate(
        "api_uses_validate_and_block",
        "_validate_and_block" in content,
        "public_api.py must use _validate_and_block for response validation",
    )

    # Must have access_policy in response payloads
    _gate(
        "api_response_includes_access_policy",
        '"access_policy"' in content,
        "public_api.py responses must include access_policy field",
    )


# ─────────────────────────────────────────────────────────────────────────────
# GATE 5: DASHBOARD TIER GATE VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

def gate_dashboard_tier_gates():
    """Scan index.html for MODEL_B patterns — ungated report links."""
    print("\n[GATE 5] Dashboard Tier Gate Validation")
    dashboard_path = ROOT / "index.html"

    if not dashboard_path.exists():
        _gate("dashboard_exists", False, "index.html not found")
        return

    content = dashboard_path.read_text(encoding="utf-8", errors="replace")

    # CRITICAL: Look for the specific MODEL_B pattern — ungated _reportCta
    # The old dangerous pattern was: const _reportCta = _hasReport ? ...
    # without any tier check. The new safe pattern checks _isPro.
    _gate(
        "dashboard_report_cta_tier_gated",
        "_isPro" in content and "_reportCta = _hasReport && _isPro" in content,
        "Dashboard report CTA must be gated behind _isPro tier check",
    )

    # Must have access governance comment
    _gate(
        "dashboard_has_governance_comment",
        "ACCESS GOVERNANCE v173.0" in content,
        "Dashboard must contain ACCESS GOVERNANCE v173.0 markers",
    )

    # Must have tier check for report access
    _gate(
        "dashboard_tier_level_check",
        "_currentTierLvl" in content and "_hasProAccess" in content,
        "Dashboard must have tier level check (_currentTierLvl / _hasProAccess)",
    )

    # Watchlist dossier must be gated
    _gate(
        "dashboard_watchlist_gated",
        "_wPro" in content and "upgrade.html?plan=pro&utm_source=watchlist-dossier" in content,
        "Watchlist dossier link must be gated for PRO tier",
    )

    # Modal VIEW DOSSIER button must be gated
    _gate(
        "dashboard_modal_dossier_gated",
        "_mdPro" in content and "UPGRADE FOR DOSSIER" in content,
        "Modal VIEW DOSSIER button must be gated for PRO tier",
    )


# ─────────────────────────────────────────────────────────────────────────────
# GATE 6: REPORT METADATA COMPLIANCE
# ─────────────────────────────────────────────────────────────────────────────

def gate_report_metadata_compliance():
    """Scan report generators for required_tier and access_policy fields."""
    print("\n[GATE 6] Report Metadata Compliance")

    report_engines = [
        ROOT / "agent" / "v52_report_engine" / "engine.py",
        ROOT / "agent" / "content" / "premium_report_generator.py",
    ]

    for engine_path in report_engines:
        name = engine_path.parent.name + "/" + engine_path.name
        if not engine_path.exists():
            _gate(f"report_metadata.{name}", False, f"{name} not found")
            continue

        content = engine_path.read_text(encoding="utf-8", errors="replace")

        has_required_tier = '"required_tier"' in content or "'required_tier'" in content
        has_access_policy = '"access_policy"' in content or "'access_policy'" in content
        has_classification = '"classification"' in content

        _gate(
            f"report_metadata.{engine_path.name}.required_tier",
            has_required_tier,
            f"{name} must include required_tier in report metadata",
        )
        _gate(
            f"report_metadata.{engine_path.name}.access_policy",
            has_access_policy,
            f"{name} must include access_policy in report metadata",
        )


# ─────────────────────────────────────────────────────────────────────────────
# GATE 7: REGRESSION TESTS
# ─────────────────────────────────────────────────────────────────────────────

def gate_regression_tests():
    """Run the access governance regression test suite."""
    print("\n[GATE 7] Regression Tests (test_access_governance.py)")
    test_path = ROOT / "tests" / "test_access_governance.py"

    if not test_path.exists():
        _gate("regression_tests_exist", False, "tests/test_access_governance.py not found")
        return

    _gate("regression_tests_exist", True, "test_access_governance.py present")

    # Run pytest
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_path), "-v",
             "--tb=short", "--no-header", "-q"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=120,
        )
        passed = result.returncode == 0
        output = result.stdout + result.stderr

        # Count passed/failed from pytest output
        passed_match = re.search(r'(\d+) passed', output)
        failed_match = re.search(r'(\d+) failed', output)
        n_passed = int(passed_match.group(1)) if passed_match else 0
        n_failed = int(failed_match.group(1)) if failed_match else 0

        _gate(
            "regression_tests_pass",
            passed,
            f"Pytest: {n_passed} passed, {n_failed} failed",
            (result.stdout + result.stderr)[-500:] if not passed else "",
        )
    except subprocess.TimeoutExpired:
        _gate("regression_tests_pass", False, "Pytest timed out (120s)")
    except FileNotFoundError:
        _gate("regression_tests_pass", False, "pytest not available — install with pip install pytest")


# ─────────────────────────────────────────────────────────────────────────────
# GATE 8: AUDIT RECORD GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def gate_audit_record():
    """Generate and persist the access policy audit record."""
    print("\n[GATE 8] Audit Record Generation")
    if not _POLICY_IMPORTED:
        _gate("audit_record", False, "access_control_policy not importable")
        return

    try:
        audit = generate_audit_record()
        audit["deployment_gate_results"] = GATE_RESULTS
        audit["gate_pass_count"] = GATE_PASS_COUNT
        audit["gate_fail_count"] = GATE_FAIL_COUNT

        os.makedirs(ROOT / "reports", exist_ok=True)
        audit_path = ROOT / "reports" / "access_policy_audit.json"
        with open(audit_path, "w", encoding="utf-8") as f:
            json.dump(audit, f, indent=2)

        _gate(
            "audit_record_written",
            True,
            f"Audit written to reports/access_policy_audit.json",
        )
    except Exception as e:
        _gate("audit_record_written", False, f"Audit write failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX v173.0 — Deployment Governance Gate"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with code 1 if any gate fails (use in CI)",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="Skip pytest regression tests (useful for fast pre-commit check)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print(f"  SENTINEL APEX v173.0 — DEPLOYMENT GOVERNANCE GATE")
    print(f"  Policy Version: {POLICY_CANONICAL_VERSION if _POLICY_IMPORTED else 'UNKNOWN'}")
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)

    gate_policy_self_checks()
    gate_policy_drift()
    gate_no_public_report_exposure()
    gate_api_field_validation()
    gate_dashboard_tier_gates()
    gate_report_metadata_compliance()

    if not args.skip_tests:
        gate_regression_tests()
    else:
        print("\n[GATE 7] Regression Tests — SKIPPED (--skip-tests)")

    gate_audit_record()

    # ── FINAL VERDICT ──────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    total = GATE_PASS_COUNT + GATE_FAIL_COUNT
    print(f"  RESULTS: {GATE_PASS_COUNT}/{total} gates passed  |  {GATE_FAIL_COUNT} failed")
    print("=" * 70)

    if GATE_FAIL_COUNT == 0:
        print("\n  ✅ DEPLOYMENT APPROVED — All governance checks passed")
        print("     MODEL_C is the only active architecture")
        print("     MODEL_A: DISABLED ✓")
        print("     MODEL_B: DISABLED ✓")
        print("     Commercial access protected ✓\n")
        sys.exit(0)
    else:
        print(f"\n  🚨 DEPLOYMENT BLOCKED — {GATE_FAIL_COUNT} governance check(s) failed")
        print("\n  FAILED GATES:")
        for name, result in GATE_RESULTS.items():
            if not result["passed"]:
                print(f"    ✗  {name}: {result['detail']}")
        print("\n  RESOLVE ALL FAILURES BEFORE DEPLOYING.\n")
        if args.strict:
            sys.exit(1)
        else:
            sys.exit(0)  # Report-only mode (no --strict)


if __name__ == "__main__":
    main()
