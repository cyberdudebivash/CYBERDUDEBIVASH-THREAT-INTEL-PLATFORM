#!/usr/bin/env python3
"""
SENTINEL APEX v26.0 Module Tests
=================================
Validates all v26 modules work correctly.

Run: python tests/test_v26_modules.py
"""

import sys
import os
from datetime import datetime, timezone, timedelta

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_v26_config():
    """Test v26 configuration module"""
    print("Testing v26 Config...")
    
    from agent.v26.config_v26 import V26Config, ThreatSeverity, config
    
    assert config.VERSION == "26.0.0", f"Expected 26.0.0, got {config.VERSION}"
    assert config.CODENAME == "Phoenix", f"Expected Phoenix, got {config.CODENAME}"
    assert config.SYNC_INTERVAL_HOURS == 4, "Sync interval should be 4 hours"
    
    # Test severity mapping
    assert config.get_severity(9.5) == ThreatSeverity.CRITICAL
    assert config.get_severity(7.5) == ThreatSeverity.HIGH
    assert config.get_severity(5.0) == ThreatSeverity.MEDIUM
    assert config.get_severity(2.0) == ThreatSeverity.LOW
    
    # Test feature flags
    assert config.is_feature_enabled("cyber_risk_credit") == True
    assert config.is_feature_enabled("temporal_decay") == True
    assert config.is_feature_enabled("ioc_correlation") == True
    
    # Test export
    export = config.to_dict()
    assert "version" in export
    assert "features" in export
    
    print("  ✓ Config module OK")
    return True


def test_temporal_decay():
    """Test temporal decay engine"""
    print("Testing Temporal Decay Engine...")
    
    from agent.v26.temporal_decay import (
        TemporalDecayEngine,
        TemporalDecayConfig,
        apply_temporal_decay,
    )
    
    engine = TemporalDecayEngine()
    
    # Test recent threat (should have high decay factor)
    recent = datetime.now(timezone.utc) - timedelta(hours=12)
    result = engine.apply_decay(9.0, recent)
    assert result["decay_factor"] >= 1.0, "Recent threats should have boost"
    assert result["is_recent"] == True
    
    # Test 30-day old threat (should be ~50% decayed)
    old_30d = datetime.now(timezone.utc) - timedelta(days=30)
    result = engine.apply_decay(10.0, old_30d)
    assert 0.4 <= result["decay_factor"] <= 0.6, f"30d should be ~50% decayed, got {result['decay_factor']}"
    
    # Test 90-day old threat (should be near minimum)
    old_90d = datetime.now(timezone.utc) - timedelta(days=90)
    result = engine.apply_decay(10.0, old_90d)
    assert result["decay_factor"] <= 0.4, "90d should be heavily decayed"
    assert result["is_stale"] == True
    
    # Test ranking
    threats = [
        {"id": 1, "risk_score": 8.0, "timestamp": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()},
        {"id": 2, "risk_score": 6.0, "timestamp": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()},
        {"id": 3, "risk_score": 9.0, "timestamp": (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()},
    ]
    ranked = engine.rank_by_decayed_score(threats)
    
    # Recent threat should be first (even with lower score)
    assert ranked[0]["id"] == 2, "Recent threat should rank first"
    
    print("  ✓ Temporal Decay Engine OK")
    return True


def test_ioc_correlation():
    """Test IOC correlation engine"""
    print("Testing IOC Correlation Engine...")
    
    from agent.v26.ioc_correlation import (
        IOCCorrelationEngine,
        IOCType,
    )
    
    engine = IOCCorrelationEngine(
        correlation_window_hours=168,  # 1 week
        min_confidence=0.1,  # Low threshold for testing
        min_shared_iocs=1,
    )
    
    # Test IOC extraction
    text = """
    The attacker used IP 192.168.1.100 and domain malware.evil.com.
    File hash: 5d41402abc4b2a76b9719d911017c592
    Contact: attacker@evil.com
    Vulnerability: CVE-2024-12345
    """
    
    iocs = engine.extract_iocs(text)
    assert IOCType.IP_ADDRESS in iocs, "Should extract IP"
    assert IOCType.DOMAIN in iocs, "Should extract domain"
    assert IOCType.MD5 in iocs, "Should extract MD5"
    assert IOCType.EMAIL in iocs, "Should extract email"
    assert IOCType.CVE in iocs, "Should extract CVE"
    
    # Test indexing
    engine.index_report("REPORT-001", iocs)
    
    iocs2 = engine.extract_iocs("Same IP 192.168.1.100 seen again with malware.evil.com and another.domain.net")
    engine.index_report("REPORT-002", iocs2)
    
    # Verify indexing works
    stats = engine.get_stats()
    assert stats["indexed_reports"] == 2, f"Should have 2 reports, got {stats['indexed_reports']}"
    assert stats["indexed_iocs"] > 0, "Should have IOCs indexed"
    
    # Test shared IOC detection (manual check)
    shared = engine._report_iocs["REPORT-001"] & engine._report_iocs["REPORT-002"]
    assert len(shared) >= 2, f"Should share at least 2 IOCs, found {len(shared)}: {shared}"
    
    print("  ✓ IOC Correlation Engine OK")
    return True


def test_v26_module_imports():
    """Test all v26 module imports work"""
    print("Testing v26 Module Imports...")
    
    from agent.v26 import (
        __version__,
        __codename__,
        config,
        get_config,
        get_temporal_decay_engine,
        get_ioc_correlation_engine,
    )
    
    assert __version__ == "26.0.0"
    assert __codename__ == "Phoenix"
    
    cfg = get_config()
    assert cfg.VERSION == "26.0.0"
    
    decay = get_temporal_decay_engine()
    assert decay is not None
    
    corr = get_ioc_correlation_engine()
    assert corr is not None
    
    print("  ✓ Module Imports OK")
    return True


def main():
    print("=" * 60)
    print("  SENTINEL APEX v26.0 Module Tests")
    print("=" * 60)
    print()
    
    tests = [
        ("Config", test_v26_config),
        ("Temporal Decay", test_temporal_decay),
        ("IOC Correlation", test_ioc_correlation),
        ("Module Imports", test_v26_module_imports),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_fn in tests:
        try:
            if test_fn():
                passed += 1
        except Exception as e:
            print(f"  ✗ {name} FAILED: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
