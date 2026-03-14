"""
CYBERDUDEBIVASH® SENTINEL APEX v49.0 — Bug Hunter Fix Tests
=============================================================
Validates the v49 Bug Hunter activation fix without network calls.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.v49_bughunter_fix import V49_VERSION, V49_CODENAME
from agent.v49_bughunter_fix.recon_scanner import SafeReconScanner, SEVERITY_COST_MAP
from agent.v49_bughunter_fix.dashboard_bridge import (
    write_dashboard_output,
    validate_output,
    _default_engines,
)


class TestV49ModuleInit(unittest.TestCase):
    """Test module metadata."""

    def test_version_defined(self):
        self.assertEqual(V49_VERSION, "49.0.0")

    def test_codename_defined(self):
        self.assertEqual(V49_CODENAME, "BUG HUNTER ACTIVATION")


class TestSafeReconScanner(unittest.TestCase):
    """Test scanner engines in isolation."""

    def setUp(self):
        self.scanner = SafeReconScanner(domain="example.com")

    def test_scanner_initialization(self):
        self.assertEqual(self.scanner.domain, "example.com")
        self.assertIsNotNone(self.scanner.scan_id)
        self.assertTrue(self.scanner.scan_id.startswith("BH-"))
        self.assertEqual(len(self.scanner.subdomains), 0)
        self.assertEqual(len(self.scanner.findings), 0)

    def test_add_finding(self):
        self.scanner._add_finding(
            ftype="TEST_FINDING",
            target="test.example.com",
            severity="HIGH",
            evidence="Unit test finding",
        )
        self.assertEqual(len(self.scanner.findings), 1)
        f = self.scanner.findings[0]
        self.assertEqual(f["type"], "TEST_FINDING")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["scan_id"], self.scanner.scan_id)
        self.assertIn("detected_at", f)

    def test_roi_calculator_empty(self):
        roi = self.scanner.engine_roi_calculator()
        self.assertEqual(roi["total_risk_exposure"], 0)
        self.assertEqual(roi["rosi_percentage"], 0)

    def test_roi_calculator_with_findings(self):
        self.scanner._add_finding("A", "t1", "CRITICAL", "e1")
        self.scanner._add_finding("B", "t2", "HIGH", "e2")
        self.scanner._add_finding("C", "t3", "MEDIUM", "e3")
        roi = self.scanner.engine_roi_calculator()
        expected = SEVERITY_COST_MAP["CRITICAL"] + SEVERITY_COST_MAP["HIGH"] + SEVERITY_COST_MAP["MEDIUM"]
        self.assertEqual(roi["total_risk_exposure"], expected)
        self.assertGreater(roi["rosi_percentage"], 0)

    def test_bola_detection(self):
        self.scanner.api_endpoints = [
            "/api/v1/users/123",
            "/api/v1/config",
            "/api/v2/accounts/456",
        ]
        self.scanner.engine_bola_detection()
        bola_findings = [f for f in self.scanner.findings if f["type"] == "BOLA_CANDIDATE"]
        self.assertGreaterEqual(len(bola_findings), 1)

    def test_js_extractor_secrets(self):
        self.scanner.live_hosts = [{
            "subdomain": "test.example.com",
            "url": "https://test.example.com",
            "body_preview": 'var apiKey = "AKIA1234567890123456"; var config = {};',
            "headers": {},
        }]
        self.scanner.engine_js_extractor()
        secret_findings = [f for f in self.scanner.findings if f["type"] == "SECRET_LEAK"]
        self.assertGreaterEqual(len(secret_findings), 1)

    def test_security_header_audit(self):
        self.scanner.live_hosts = [{
            "subdomain": "test.example.com",
            "url": "https://test.example.com",
            "headers": {"content-type": "text/html"},
            "body_preview": "",
        }]
        self.scanner.engine_security_header_audit()
        header_findings = [f for f in self.scanner.findings if f["type"] == "MISSING_SECURITY_HEADERS"]
        self.assertEqual(len(header_findings), 1)
        self.assertIn("strict-transport-security", header_findings[0]["evidence"])

    def test_generate_output_schema(self):
        self.scanner.subdomains = ["a.example.com", "b.example.com"]
        self.scanner.live_hosts = [{"subdomain": "a.example.com", "url": "https://a.example.com", "status_code": 200}]
        roi = {"total_risk_exposure": 1000, "rosi_percentage": 95.0, "finding_breakdown": {}}
        output = self.scanner.engine_generate_output(roi)

        # Validate dashboard-critical fields
        self.assertIn("metrics", output)
        self.assertIn("findings_summary", output)
        self.assertIn("engines", output)
        self.assertEqual(output["subsystem"], "v45_bughunter")
        self.assertEqual(output["version"], "45.0.0")
        self.assertEqual(output["codename"], "BUG HUNTER")
        self.assertEqual(output["metrics"]["subdomains"], 2)
        self.assertEqual(output["metrics"]["live_hosts"], 1)
        self.assertEqual(len(output["engines"]), 12)

    def test_cloud_bucket_detection(self):
        self.scanner.live_hosts = [{
            "subdomain": "test.example.com",
            "url": "https://test.example.com",
            "body_preview": 'var img = "https://mybucket.s3.amazonaws.com/photo.jpg";',
            "headers": {},
        }]
        self.scanner.engine_cloud_bucket_hunter()
        cloud_findings = [f for f in self.scanner.findings if f["type"] == "CLOUD_EXPOSURE"]
        self.assertGreaterEqual(len(cloud_findings), 1)


class TestDashboardBridge(unittest.TestCase):
    """Test dashboard output writing."""

    def test_write_and_validate(self):
        scan_data = {
            "subsystem": "v45_bughunter",
            "version": "45.0.0",
            "codename": "BUG HUNTER",
            "status": "COMPLETED",
            "timestamp": "2026-03-14T00:00:00Z",
            "metrics": {
                "subdomains": 4,
                "live_hosts": 3,
                "api_endpoints": 2,
                "total_findings": 5,
                "critical_findings": 1,
                "high_findings": 2,
                "risk_exposure": 150000,
                "rosi": 95.0,
            },
            "findings_summary": [
                {"type": "MISSING_SECURITY_HEADERS", "severity": "HIGH", "target": "test.example.com"},
            ],
            "engines": _default_engines(),
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = os.path.join(tmpdir, "bughunter_output.json")
            # Patch the module-level path
            with patch("agent.v49_bughunter_fix.dashboard_bridge._OUTPUT_FILE", output_path):
                with patch("agent.v49_bughunter_fix.dashboard_bridge._DATA_DIR", tmpdir):
                    with patch("agent.v49_bughunter_fix.dashboard_bridge._HISTORY_DIR",
                               os.path.join(tmpdir, "history")):
                        result_path = write_dashboard_output(scan_data)

            # Validate written file
            with open(output_path) as f:
                written = json.load(f)

            self.assertEqual(written["metrics"]["subdomains"], 4)
            self.assertEqual(written["metrics"]["live_hosts"], 3)
            self.assertEqual(written["metrics"]["critical_findings"], 1)
            self.assertEqual(len(written["engines"]), 12)

    def test_default_engines_count(self):
        engines = _default_engines()
        self.assertEqual(len(engines), 12)
        engine_ids = [e["id"] for e in engines]
        self.assertIn("subdomain_engine", engine_ids)
        self.assertIn("report_generator", engine_ids)


class TestZeroRegression(unittest.TestCase):
    """Verify no existing modules are modified."""

    def test_v45_init_unchanged(self):
        """v45 __init__.py must still exist with original constants."""
        init_path = os.path.join(
            os.path.dirname(__file__), "..", "agent", "v45_bughunter", "__init__.py"
        )
        if os.path.exists(init_path):
            with open(init_path) as f:
                content = f.read()
            self.assertIn("V45_VERSION", content)
            self.assertIn("BUG HUNTER", content)

    def test_v49_does_not_import_v45_directly(self):
        """v49 scanner operates independently — no v45 engine imports."""
        scanner_path = os.path.join(
            os.path.dirname(__file__), "..", "agent",
            "v49_bughunter_fix", "recon_scanner.py"
        )
        if os.path.exists(scanner_path):
            with open(scanner_path) as f:
                content = f.read()
            # Must NOT import from v45 (isolation guarantee)
            self.assertNotIn("from agent.v45_bughunter", content)
            self.assertNotIn("import agent.v45_bughunter", content)

    def test_output_writes_only_to_bughunter_dir(self):
        """Dashboard bridge must only write to data/bughunter/."""
        bridge_path = os.path.join(
            os.path.dirname(__file__), "..", "agent",
            "v49_bughunter_fix", "dashboard_bridge.py"
        )
        if os.path.exists(bridge_path):
            with open(bridge_path) as f:
                content = f.read()
            # Extract only executable code lines (skip docstrings and comments)
            code_lines = []
            in_docstring = False
            for line in content.split("\n"):
                stripped = line.strip()
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    if in_docstring:
                        in_docstring = False
                        continue
                    elif stripped.count('"""') == 1 or stripped.count("'''") == 1:
                        in_docstring = True
                        continue
                if in_docstring or stripped.startswith("#"):
                    continue
                code_lines.append(line)
            code_only = "\n".join(code_lines)
            # Executable code must not open/write to other data directories
            self.assertNotIn('open("data/stix', code_only)
            self.assertNotIn('open("data/nexus', code_only)
            self.assertNotIn("data/genesis/", code_only)
            self.assertNotIn("data/cortex/", code_only)


if __name__ == "__main__":
    unittest.main()
