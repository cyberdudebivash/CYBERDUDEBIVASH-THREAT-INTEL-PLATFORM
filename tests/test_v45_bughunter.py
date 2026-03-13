"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Bug Hunter Test Suite
=============================================================
Comprehensive tests for all 12 Bug Hunter engines.
Zero-regression guarantee: all existing 188 tests must continue to pass.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import sys
import json
import asyncio
import tempfile
import shutil

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ══════════════════════════════════════════════════════════════
# 1. MODULE IMPORT TESTS
# ══════════════════════════════════════════════════════════════

def test_v45_init_imports():
    """v45 __init__.py loads correctly with version metadata."""
    from agent.v45_bughunter import V45_VERSION, V45_CODENAME, V45_ENGINES
    assert V45_VERSION == "45.0.0"
    assert V45_CODENAME == "BUG HUNTER"
    assert len(V45_ENGINES) == 12

def test_v45_models_import():
    from agent.v45_bughunter.models import BugHunterScan, BugHunterFinding
    assert BugHunterScan is not None
    assert BugHunterFinding is not None

def test_v45_all_engines_import():
    """All 12 engine modules import without error."""
    from agent.v45_bughunter import subdomain_engine
    from agent.v45_bughunter import http_probe
    from agent.v45_bughunter import tech_fingerprint
    from agent.v45_bughunter import js_endpoint_extractor
    from agent.v45_bughunter import bola_agent
    from agent.v45_bughunter import cloud_bucket_hunter
    from agent.v45_bughunter import port_scanner
    from agent.v45_bughunter import takeover_detector
    from agent.v45_bughunter import asset_delta
    from agent.v45_bughunter import roi_engine
    from agent.v45_bughunter import recon_pipeline
    from agent.v45_bughunter import report_generator
    assert True

def test_v45_bughunter_engine_import():
    from agent.v45_bughunter.bughunter_engine import BugHunterEngine
    assert BugHunterEngine is not None


# ══════════════════════════════════════════════════════════════
# 2. MODELS TESTS
# ══════════════════════════════════════════════════════════════

def test_scan_creation():
    from agent.v45_bughunter.models import BugHunterScan
    scan = BugHunterScan(domain="example.com")
    assert scan.domain == "example.com"
    assert scan.status == "INITIALIZED"
    assert scan.critical_count == 0
    assert scan.scan_id.startswith("BH-")

def test_scan_add_finding_critical():
    from agent.v45_bughunter.models import BugHunterScan
    scan = BugHunterScan(domain="test.com")
    scan.add_finding({"type": "BOLA", "severity": "CRITICAL", "url": "https://test.com/api"})
    assert scan.critical_count == 1
    assert len(scan.findings) == 1
    assert scan.findings[0]["scan_id"] == scan.scan_id

def test_scan_add_finding_non_critical():
    from agent.v45_bughunter.models import BugHunterScan
    scan = BugHunterScan(domain="test.com")
    scan.add_finding({"type": "OPEN_PORT", "severity": "MEDIUM"})
    assert scan.critical_count == 0
    assert len(scan.findings) == 1

def test_scan_add_asset():
    from agent.v45_bughunter.models import BugHunterScan
    scan = BugHunterScan(domain="test.com")
    scan.add_asset("api.test.com", ip="1.2.3.4", technologies=["nginx", "django"])
    assert len(scan.assets) == 1
    assert scan.assets[0]["hostname"] == "api.test.com"
    assert "nginx" in scan.assets[0]["technologies"]

def test_scan_finalize():
    from agent.v45_bughunter.models import BugHunterScan
    scan = BugHunterScan(domain="test.com")
    scan.finalize(status="COMPLETED", duration=42.5)
    assert scan.status == "COMPLETED"
    assert scan.duration_seconds == 42.5

def test_scan_to_dict():
    from agent.v45_bughunter.models import BugHunterScan
    scan = BugHunterScan(domain="test.com")
    scan.add_finding({"type": "BOLA", "severity": "CRITICAL"})
    scan.add_asset("api.test.com")
    d = scan.to_dict()
    assert d["domain"] == "test.com"
    assert d["finding_count"] == 1
    assert d["asset_count"] == 1

def test_scan_save_and_load():
    from agent.v45_bughunter.models import BugHunterScan
    scan = BugHunterScan(domain="savetest.com", scan_id="BH-SAVETEST")
    scan.add_finding({"type": "BOLA", "severity": "CRITICAL"})
    scan.finalize("COMPLETED", 10.0)
    path = scan.save()
    assert path is not None
    assert os.path.exists(path)
    with open(path) as f:
        data = json.load(f)
    assert data["domain"] == "savetest.com"
    assert data["status"] == "COMPLETED"
    # Cleanup
    os.remove(path)

def test_finding_creation():
    from agent.v45_bughunter.models import BugHunterFinding
    f = BugHunterFinding("BOLA", "https://api.test.com/v1/users/123", "CRITICAL")
    assert f.type == "BOLA"
    assert f.severity == "CRITICAL"
    assert f.risk_weight == 10

def test_finding_severity_weights():
    from agent.v45_bughunter.models import BugHunterFinding
    assert BugHunterFinding("X", "X", "CRITICAL").risk_weight == 10
    assert BugHunterFinding("X", "X", "HIGH").risk_weight == 7
    assert BugHunterFinding("X", "X", "MEDIUM").risk_weight == 4
    assert BugHunterFinding("X", "X", "LOW").risk_weight == 2
    assert BugHunterFinding("X", "X", "INFO").risk_weight == 1

def test_finding_to_dict():
    from agent.v45_bughunter.models import BugHunterFinding
    f = BugHunterFinding("CLOUD_LEAK", "s3://bucket", "CRITICAL", evidence="public listing")
    d = f.to_dict()
    assert d["type"] == "CLOUD_LEAK"
    assert d["severity"] == "CRITICAL"
    assert "risk_weight" in d

def test_finding_to_stix():
    from agent.v45_bughunter.models import BugHunterFinding
    f = BugHunterFinding("BOLA", "api.test.com", "CRITICAL")
    stix = f.to_stix_indicator()
    assert stix["type"] == "indicator"
    assert stix["spec_version"] == "2.1"
    assert "bug-hunter" in stix["labels"]
    assert stix["confidence"] == 100  # CRITICAL = 10 * 10


# ══════════════════════════════════════════════════════════════
# 3. SUBDOMAIN ENGINE TESTS
# ══════════════════════════════════════════════════════════════

def test_subdomain_engine_init():
    from agent.v45_bughunter.subdomain_engine import SubdomainEngine
    engine = SubdomainEngine("example.com", concurrency=50)
    assert engine.domain == "example.com"
    assert engine.concurrency == 50

def test_subdomain_engine_no_wordlist():
    from agent.v45_bughunter.subdomain_engine import SubdomainEngine
    engine = SubdomainEngine("test.com")
    assert engine.wordlist_path is None


# ══════════════════════════════════════════════════════════════
# 4. HTTP PROBE ENGINE TESTS
# ══════════════════════════════════════════════════════════════

def test_http_probe_init():
    from agent.v45_bughunter.http_probe import HTTPProbeEngine
    engine = HTTPProbeEngine(concurrency=50, timeout=5)
    assert engine.concurrency == 50
    assert engine.timeout == 5

def test_http_probe_title_extraction():
    from agent.v45_bughunter.http_probe import HTTPProbeEngine
    engine = HTTPProbeEngine()
    assert engine.extract_title("<html><title>Test Page</title></html>") == "Test Page"
    assert engine.extract_title("<html><body>No title</body></html>") == ""
    assert engine.extract_title("") == ""
    assert engine.extract_title("<TITLE>Upper</TITLE>") == "Upper"


# ══════════════════════════════════════════════════════════════
# 5. TECH FINGERPRINT TESTS
# ══════════════════════════════════════════════════════════════

def test_tech_fingerprint_init():
    from agent.v45_bughunter.tech_fingerprint import TechFingerprinter, SIGNATURES
    fp = TechFingerprinter()
    assert len(fp.signatures) == len(SIGNATURES)

def test_tech_fingerprint_detection():
    from agent.v45_bughunter.tech_fingerprint import TechFingerprinter
    fp = TechFingerprinter()
    results = fp.fingerprint(
        "<html>wp-content/themes/test</html>",
        {"Server": "nginx/1.21.0"}
    )
    tech_names = [r["technology"] for r in results]
    assert "nginx" in tech_names
    assert "wordpress" in tech_names

def test_tech_fingerprint_empty():
    from agent.v45_bughunter.tech_fingerprint import TechFingerprinter
    fp = TechFingerprinter()
    results = fp.fingerprint("", {})
    assert results == []

def test_tech_fingerprint_custom_sig():
    from agent.v45_bughunter.tech_fingerprint import TechFingerprinter
    custom = {"mytech": {"pattern": "CUSTOM_SIG_XYZ", "category": "custom"}}
    fp = TechFingerprinter(custom_signatures=custom)
    results = fp.fingerprint("contains CUSTOM_SIG_XYZ here", {})
    assert any(r["technology"] == "mytech" for r in results)

def test_tech_fingerprint_sync():
    from agent.v45_bughunter.tech_fingerprint import TechFingerprinter
    fp = TechFingerprinter()
    names = fp.fingerprint_sync("Powered by Django csrfmiddlewaretoken", {"Server": "Apache"})
    assert "django" in names
    assert "apache" in names


# ══════════════════════════════════════════════════════════════
# 6. JS ENDPOINT EXTRACTOR TESTS
# ══════════════════════════════════════════════════════════════

def test_js_extractor_init():
    from agent.v45_bughunter.js_endpoint_extractor import JSEndpointExtractor
    ext = JSEndpointExtractor(concurrency=10, timeout=5)
    assert ext.timeout == 5

def test_js_discover_files():
    from agent.v45_bughunter.js_endpoint_extractor import JSEndpointExtractor
    ext = JSEndpointExtractor()
    html = '<script src="/js/app.js"></script><script src="https://cdn.test.com/lib.js"></script>'
    files = ext.discover_js_files(html, "https://example.com")
    assert "https://example.com/js/app.js" in files
    assert "https://cdn.test.com/lib.js" in files

def test_js_extract_endpoints():
    from agent.v45_bughunter.js_endpoint_extractor import JSEndpointExtractor
    ext = JSEndpointExtractor()
    js = """var url = "/api/v1/users"; fetch("/api/v2/orders");"""
    eps = ext.extract_endpoints(js)
    assert "/api/v1/users" in eps
    assert "/api/v2/orders" in eps

def test_js_extract_tokens():
    from agent.v45_bughunter.js_endpoint_extractor import JSEndpointExtractor
    ext = JSEndpointExtractor()
    js = """var key = "AKIA1234567890ABCDEF"; var gkey = "AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";"""
    tokens = ext.extract_tokens(js)
    assert len(tokens) >= 1
    assert any(t["token_type"] == "AWS_ACCESS_KEY" for t in tokens)

def test_js_no_false_positives():
    from agent.v45_bughunter.js_endpoint_extractor import JSEndpointExtractor
    ext = JSEndpointExtractor()
    js = """var img = "/images/logo.png"; var font = "/fonts/arial.css";"""
    eps = ext.extract_endpoints(js)
    # Filter should remove images/fonts/css
    for ep in eps:
        assert ".png" not in ep.lower()
        assert ".css" not in ep.lower()


# ══════════════════════════════════════════════════════════════
# 7. BOLA AGENT TESTS
# ══════════════════════════════════════════════════════════════

def test_bola_agent_init():
    from agent.v45_bughunter.bola_agent import BOLAAgent
    agent = BOLAAgent(concurrency=10)
    assert len(agent.ID_PATTERNS) == 4

def test_bola_mutate_numeric():
    from agent.v45_bughunter.bola_agent import BOLAAgent
    agent = BOLAAgent()
    assert agent._mutate_id("123") == "124"
    assert agent._mutate_id("0") == "1"

def test_bola_mutate_uuid():
    from agent.v45_bughunter.bola_agent import BOLAAgent
    agent = BOLAAgent()
    assert agent._mutate_id("abc-def") is None  # Non-numeric → None

def test_bola_data_leak_json():
    from agent.v45_bughunter.bola_agent import BOLAAgent
    agent = BOLAAgent()
    assert agent._is_data_leaked('{"user_id": "124", "name": "test"}', "124") is True
    assert agent._is_data_leaked('{"user_id": "123", "name": "test"}', "124") is False

def test_bola_data_leak_plaintext():
    from agent.v45_bughunter.bola_agent import BOLAAgent
    agent = BOLAAgent()
    assert agent._is_data_leaked("User 124 found", "124") is True
    assert agent._is_data_leaked("No data here", "124") is False


# ══════════════════════════════════════════════════════════════
# 8. CLOUD BUCKET HUNTER TESTS
# ══════════════════════════════════════════════════════════════

def test_cloud_hunter_init():
    from agent.v45_bughunter.cloud_bucket_hunter import CloudBucketHunter
    hunter = CloudBucketHunter("example.com")
    assert hunter.target == "example"

def test_cloud_hunter_permutations():
    from agent.v45_bughunter.cloud_bucket_hunter import CloudBucketHunter
    hunter = CloudBucketHunter("testsite.io")
    perms = hunter._generate_permutations()
    assert "testsite" in perms
    assert "testsite-backup" in perms
    assert "data-testsite" in perms
    assert len(perms) > 50  # 17 keywords × 4 patterns + base


# ══════════════════════════════════════════════════════════════
# 9. PORT SCANNER TESTS
# ══════════════════════════════════════════════════════════════

def test_port_scanner_init():
    from agent.v45_bughunter.port_scanner import PortScanner, COMMON_PORTS
    scanner = PortScanner()
    assert len(scanner.ports) == len(COMMON_PORTS)

def test_port_scanner_custom_ports():
    from agent.v45_bughunter.port_scanner import PortScanner
    scanner = PortScanner(ports=[80, 443, 8080])
    assert scanner.ports == [80, 443, 8080]


# ══════════════════════════════════════════════════════════════
# 10. TAKEOVER DETECTOR TESTS
# ══════════════════════════════════════════════════════════════

def test_takeover_detector_init():
    from agent.v45_bughunter.takeover_detector import TakeoverDetector, TAKEOVER_FINGERPRINTS
    det = TakeoverDetector(concurrency=10)
    assert len(TAKEOVER_FINGERPRINTS) >= 14  # 14 providers


# ══════════════════════════════════════════════════════════════
# 11. ASSET DELTA TESTS
# ══════════════════════════════════════════════════════════════

def test_asset_delta_no_history():
    from agent.v45_bughunter.asset_delta import AssetDeltaAnalyzer
    analyzer = AssetDeltaAnalyzer()
    result = analyzer.analyze_drift("nonexistent-domain.xyz")
    assert result["status"] == "baseline_established"
    assert result["added"] == []


# ══════════════════════════════════════════════════════════════
# 12. ROI ENGINE TESTS
# ══════════════════════════════════════════════════════════════

def test_roi_empty():
    from agent.v45_bughunter.roi_engine import ROIEngine
    roi = ROIEngine()
    result = roi.calculate_exposure([])
    assert result["total_risk_exposure"] == 0
    assert result["finding_count"] == 0

def test_roi_single_bola_critical():
    from agent.v45_bughunter.roi_engine import ROIEngine
    roi = ROIEngine()
    result = roi.calculate_exposure([{"type": "BOLA", "severity": "CRITICAL"}])
    expected_sle = 250_000 * 2.5
    assert result["total_risk_exposure"] == expected_sle
    assert result["mitigated_value"] == expected_sle * 0.95

def test_roi_multiple_findings():
    from agent.v45_bughunter.roi_engine import ROIEngine
    roi = ROIEngine()
    findings = [
        {"type": "BOLA", "severity": "CRITICAL"},
        {"type": "CLOUD_LEAK", "severity": "HIGH"},
        {"type": "OPEN_PORT", "severity": "MEDIUM"},
    ]
    result = roi.calculate_exposure(findings)
    assert result["finding_count"] == 3
    assert result["total_risk_exposure"] > 0
    assert "BOLA" in result["exposure_by_type"]
    assert "CLOUD_LEAK" in result["exposure_by_type"]

def test_roi_rosi_calculation():
    from agent.v45_bughunter.roi_engine import ROIEngine
    roi = ROIEngine()
    result = roi.calculate_exposure([{"type": "BOLA", "severity": "CRITICAL"}])
    assert result["rosi_percentage"] > 0

def test_roi_executive_summary():
    from agent.v45_bughunter.roi_engine import ROIEngine
    roi = ROIEngine()
    summary = roi.format_executive_summary([{"type": "BOLA", "severity": "CRITICAL"}])
    assert "CyberDudeBivash" in summary
    assert "$" in summary


# ══════════════════════════════════════════════════════════════
# 13. REPORT GENERATOR TESTS
# ══════════════════════════════════════════════════════════════

def test_report_risk_score_empty():
    from agent.v45_bughunter.report_generator import ReportGenerator
    gen = ReportGenerator()
    assert gen.calculate_risk_score([]) == 0

def test_report_risk_score_critical():
    from agent.v45_bughunter.report_generator import ReportGenerator
    gen = ReportGenerator()
    score = gen.calculate_risk_score([{"type": "BOLA", "severity": "CRITICAL"}])
    assert score == 50  # 40 (BOLA) + 10 (CRITICAL)

def test_report_risk_score_capped():
    from agent.v45_bughunter.report_generator import ReportGenerator
    gen = ReportGenerator()
    findings = [{"type": "SECRET_LEAK", "severity": "CRITICAL"}] * 10
    score = gen.calculate_risk_score(findings)
    assert score == 100  # Capped

def test_report_text_generation():
    from agent.v45_bughunter.report_generator import ReportGenerator
    gen = ReportGenerator()
    scan_data = {
        "domain": "test.com",
        "findings": [{"type": "BOLA", "severity": "CRITICAL", "url": "https://test.com/api"}],
        "roi_metrics": {"total_risk_exposure": 625000, "mitigated_value": 593750, "rosi_percentage": 1187.5},
    }
    report = gen.generate_text_report(scan_data)
    assert "CYBERDUDEBIVASH" in report
    assert "test.com" in report
    assert "BOLA" in report

def test_report_save():
    from agent.v45_bughunter.report_generator import ReportGenerator
    gen = ReportGenerator(output_dir=tempfile.mkdtemp())
    scan_data = {
        "domain": "savetest.com",
        "findings": [],
        "roi_metrics": {},
    }
    path = gen.save_report(scan_data)
    assert path is not None
    assert os.path.exists(path)
    shutil.rmtree(os.path.dirname(path))


# ══════════════════════════════════════════════════════════════
# 14. BUG HUNTER ENGINE FACADE TESTS
# ══════════════════════════════════════════════════════════════

def test_engine_init():
    from agent.v45_bughunter.bughunter_engine import BugHunterEngine
    engine = BugHunterEngine(god_mode=True, concurrency=100)
    assert engine.god_mode is True
    assert engine.concurrency == 100

def test_engine_manifest():
    from agent.v45_bughunter.bughunter_engine import BugHunterEngine
    manifest = BugHunterEngine.get_engine_manifest()
    assert manifest["subsystem_id"] == "v45_bughunter"
    assert manifest["version"] == "45.0.0"
    assert manifest["codename"] == "BUG HUNTER"
    assert manifest["engine_count"] == 12
    assert len(manifest["engines"]) == 12

def test_engine_dashboard_no_data():
    from agent.v45_bughunter.bughunter_engine import BugHunterEngine
    engine = BugHunterEngine()
    data = engine.get_dashboard_data()
    assert data["status"] == "no_data"

def test_engine_stix_export_empty():
    from agent.v45_bughunter.bughunter_engine import BugHunterEngine
    engine = BugHunterEngine()
    indicators = engine.export_to_stix()
    assert indicators == []

def test_engine_roi_empty():
    from agent.v45_bughunter.bughunter_engine import BugHunterEngine
    engine = BugHunterEngine()
    roi = engine.calculate_roi()
    assert roi == {}


# ══════════════════════════════════════════════════════════════
# 15. VERSION INTEGRATION TESTS
# ══════════════════════════════════════════════════════════════

def test_version_updated():
    from core.version import VERSION, CODENAME
    assert VERSION == "45.0.0"
    assert CODENAME == "BUG HUNTER"

def test_version_history_includes_v45():
    from core.version import VERSION_HISTORY
    v45 = [v for v in VERSION_HISTORY if v["version"] == "45.0.0"]
    assert len(v45) == 1
    assert v45[0]["codename"] == "BUG HUNTER"

def test_version_compatibility():
    from core.version import check_version_compatibility
    assert check_version_compatibility("43.0.0") is True
    assert check_version_compatibility("45.0.0") is True
    assert check_version_compatibility("46.0.0") is False


# ══════════════════════════════════════════════════════════════
# TEST RUNNER
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    passed = 0
    failed = 0
    tests = [
        name for name, obj in list(globals().items())
        if name.startswith("test_") and callable(obj)
    ]

    print(f"\n{'='*65}")
    print(f"  SENTINEL APEX v45.0 BUG HUNTER — Test Suite")
    print(f"{'='*65}\n")

    for test_name in sorted(tests):
        try:
            globals()[test_name]()
            print(f"  \033[92m✅ {test_name}\033[0m")
            passed += 1
        except Exception as e:
            print(f"  \033[91m❌ {test_name}: {e}\033[0m")
            failed += 1

    print(f"\n{'='*65}")
    print(f"  \033[92mPassed: {passed}\033[0m")
    print(f"  \033[91mFailed: {failed}\033[0m")
    print(f"{'='*65}")

    if failed == 0:
        print(f"\033[92m\033[1m✅  ALL {passed} v45 TESTS PASSED\033[0m")
    else:
        print(f"\033[91m\033[1m❌  {failed} TESTS FAILED\033[0m")

    sys.exit(0 if failed == 0 else 1)
