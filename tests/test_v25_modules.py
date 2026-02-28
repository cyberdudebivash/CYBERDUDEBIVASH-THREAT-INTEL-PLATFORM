#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
Quick Validation Script
=======================

Run: python3 tests/test_v25_modules.py
"""

import sys
import json
from datetime import datetime

def test_credit_score():
    """Test Cyber-Risk Credit Score Engine"""
    print("\n[1] Testing Cyber-Risk Credit Score Engine...")
    
    from agent.scoring.cyber_risk_credit import calculate_credit_score, CreditTier
    
    # Test data
    vulns = [
        {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "epss_score": 0.85, "kev_listed": True},
        {"cve_id": "CVE-2024-5678", "cvss_score": 7.5, "epss_score": 0.45, "kev_listed": False},
        {"cve_id": "CVE-2024-9012", "cvss_score": 5.3, "epss_score": 0.12, "kev_listed": False},
    ]
    
    result = calculate_credit_score(
        entity_id="test-org",
        vulnerabilities=vulns,
        industry="technology",
    )
    
    assert "score" in result, "Missing score in result"
    assert 300 <= result["score"] <= 850, f"Score out of range: {result['score']}"
    assert "tier" in result, "Missing tier in result"
    
    print(f"    ✓ Credit Score: {result['score']} ({result['tier']})")
    print(f"    ✓ Industry Delta: {result['benchmarking']['industry_delta']}")
    return True


def test_cvss_v4():
    """Test CVSS v4.0 Calculator"""
    print("\n[2] Testing CVSS v4.0 Calculator...")
    
    from agent.scoring.cvss_v4 import parse_and_calculate
    
    # Test CVSS v4.0 vector
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    result = parse_and_calculate(vector)
    
    assert "scores" in result, "Missing scores in result"
    assert "overall" in result["scores"], "Missing overall score"
    assert 0 <= result["scores"]["overall"] <= 10, "Score out of range"
    
    print(f"    ✓ CVSS v4.0 Score: {result['scores']['overall']}")
    print(f"    ✓ Severity: {result['severity']}")
    
    # Test v3.1 auto-conversion
    v3_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    v3_result = parse_and_calculate(v3_vector)
    
    print(f"    ✓ v3.1 Auto-converted: {v3_result['scores']['overall']}")
    return True


def test_ctem():
    """Test CTEM Engine"""
    print("\n[3] Testing CTEM Engine...")
    
    from agent.ctem.ctem_engine import get_ctem_engine
    
    engine = get_ctem_engine()
    
    # Create scope
    scope = engine.create_scope(
        name="Test Scope",
        compliance_frameworks=["PCI_DSS", "SOC2"],
    )
    
    assert scope.scope_id, "Missing scope_id"
    print(f"    ✓ Scope Created: {scope.scope_id}")
    
    # Discover exposures
    vulns = [
        {
            "exposure_type": "vulnerability",
            "title": "Critical RCE",
            "cve_id": "CVE-2024-1234",
            "cvss_score": 9.8,
            "epss_score": 0.85,
            "kev_listed": True,
        },
        {
            "exposure_type": "vulnerability",
            "title": "SQL Injection",
            "cvss_score": 7.5,
            "epss_score": 0.45,
        },
    ]
    
    exposures = engine.bulk_discover(scope.scope_id, vulns)
    assert len(exposures) == 2, "Wrong exposure count"
    
    # Check prioritization
    p0_count = sum(1 for e in exposures if e.priority.value == "P0")
    print(f"    ✓ Exposures Created: {len(exposures)} (P0: {p0_count})")
    
    # Get metrics
    metrics = engine.calculate_metrics(scope.scope_id)
    print(f"    ✓ Total Exposures: {metrics.total_exposures}")
    
    return True


def test_digital_twin():
    """Test Digital Twin Simulator"""
    print("\n[4] Testing Digital Twin Simulator...")
    
    from agent.simulator.digital_twin import get_digital_twin
    
    simulator = get_digital_twin()
    
    # Build environment
    count = simulator.build_default_environment(
        endpoints=50,
        servers=10,
        web_apps=3,
        databases=2,
        domain_controllers=1,
    )
    
    print(f"    ✓ Environment Built: {count} assets")
    
    # Get attack surface
    surface = simulator.get_attack_surface_summary()
    print(f"    ✓ Total Connections: {surface['total_connections']}")
    
    # Run breach simulation
    scenario = simulator.simulate_breach(attack_vector="PHISHING")
    print(f"    ✓ Breach Simulation: {'SUCCESS' if scenario.successful else 'BLOCKED'}")
    print(f"    ✓ Detection: {'DETECTED' if scenario.detected else 'UNDETECTED'}")
    
    # Run Monte Carlo (quick)
    result = simulator.run_monte_carlo(iterations=10)
    print(f"    ✓ Monte Carlo Risk Score: {result.overall_risk_score:.1f}/10")
    
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("CYBERDUDEBIVASH® SENTINEL APEX v25.0")
    print("Module Validation Suite")
    print("=" * 60)
    
    tests = [
        ("Credit Score Engine", test_credit_score),
        ("CVSS v4.0 Calculator", test_cvss_v4),
        ("CTEM Engine", test_ctem),
        ("Digital Twin Simulator", test_digital_twin),
    ]
    
    results = []
    
    for name, test_func in tests:
        try:
            success = test_func()
            results.append((name, success, None))
        except Exception as e:
            print(f"\n    ✗ FAILED: {str(e)}")
            results.append((name, False, str(e)))
    
    # Summary
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    
    for name, success, error in results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status}: {name}")
        if error:
            print(f"         Error: {error}")
    
    print(f"\nResult: {passed}/{total} modules validated")
    print("=" * 60)
    
    return passed == total


if __name__ == "__main__":
    sys.path.insert(0, "/home/claude/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM")
    success = main()
    sys.exit(0 if success else 1)
