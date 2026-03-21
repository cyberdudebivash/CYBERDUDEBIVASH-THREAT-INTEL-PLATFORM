"""
SENTINEL APEX v70 — Comprehensive Test Suite
==============================================
Tests all phases:
1. Data models + serialization
2. Schema validation
3. Manifest management
4. Deduplication engine
5. Correlation engine
6. Threat scoring + confidence
7. AI classification (if sklearn available)
8. AI clustering
9. Blog report generation
10. Pipeline validator
11. Full orchestrator (end-to-end)
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.v70_apex_upgrade.core.models import (
    Advisory, IOC, IOCType, CVERecord, Severity, ThreatType,
    ConfidenceLevel, Manifest, advisory_from_legacy,
)
from agent.v70_apex_upgrade.core.schema_validator import (
    validate_advisory, validate_manifest, safe_write_manifest,
)
from agent.v70_apex_upgrade.core.manifest_manager import ManifestManager
from agent.v70_apex_upgrade.engines.dedup_engine import DedupEngine
from agent.v70_apex_upgrade.engines.correlation_engine import CorrelationEngine
from agent.v70_apex_upgrade.engines.threat_scoring import (
    ThreatScoringEngine, ConfidenceEngine, get_source_trust,
)
from agent.v70_apex_upgrade.blog.report_generator import (
    BlogReportGenerator, infer_kill_chain_phases,
)


class TestIOCModel(unittest.TestCase):
    """Test IOC type inference and dedup key generation."""

    def test_ipv4_inference(self):
        ioc = IOC(value="192.168.1.1")
        self.assertEqual(ioc.ioc_type, IOCType.IPV4)

    def test_domain_inference(self):
        ioc = IOC(value="malicious.example.com")
        self.assertEqual(ioc.ioc_type, IOCType.DOMAIN)

    def test_sha256_inference(self):
        ioc = IOC(value="a" * 64)
        self.assertEqual(ioc.ioc_type, IOCType.SHA256)

    def test_sha1_inference(self):
        ioc = IOC(value="a" * 40)
        self.assertEqual(ioc.ioc_type, IOCType.SHA1)

    def test_md5_inference(self):
        ioc = IOC(value="a" * 32)
        self.assertEqual(ioc.ioc_type, IOCType.MD5)

    def test_url_inference(self):
        ioc = IOC(value="https://malware.example.com/payload.exe")
        self.assertEqual(ioc.ioc_type, IOCType.URL)

    def test_cve_inference(self):
        ioc = IOC(value="CVE-2024-12345")
        self.assertEqual(ioc.ioc_type, IOCType.CVE)

    def test_email_inference(self):
        ioc = IOC(value="attacker@evil.com")
        self.assertEqual(ioc.ioc_type, IOCType.EMAIL)

    def test_dedup_key_consistency(self):
        ioc1 = IOC(value="192.168.1.1")
        ioc2 = IOC(value="192.168.1.1")
        self.assertEqual(ioc1.dedup_key, ioc2.dedup_key)

    def test_dedup_key_uniqueness(self):
        ioc1 = IOC(value="192.168.1.1")
        ioc2 = IOC(value="192.168.1.2")
        self.assertNotEqual(ioc1.dedup_key, ioc2.dedup_key)

    def test_serialization(self):
        ioc = IOC(value="10.0.0.1", source="test")
        d = ioc.to_dict()
        self.assertEqual(d["value"], "10.0.0.1")
        self.assertEqual(d["type"], "ipv4-addr")


class TestCVERecord(unittest.TestCase):
    def test_severity_from_cvss(self):
        cve = CVERecord(cve_id="CVE-2024-0001", cvss_score=9.8)
        self.assertEqual(cve.severity, Severity.CRITICAL)

    def test_composite_score(self):
        cve = CVERecord(
            cve_id="CVE-2024-0001",
            cvss_score=9.8,
            epss_score=0.95,
            kev_status=True,
            exploit_available=True,
        )
        score = cve.compute_composite_score()
        self.assertGreater(score, 80)
        self.assertLessEqual(score, 100)

    def test_dedup_key(self):
        cve = CVERecord(cve_id="CVE-2024-0001")
        self.assertEqual(cve.dedup_key, "CVE-2024-0001")


class TestAdvisory(unittest.TestCase):
    def test_creation(self):
        adv = Advisory(title="Test Advisory", cves=["CVE-2024-0001"])
        self.assertTrue(adv.advisory_id.startswith("advisory--"))
        self.assertEqual(adv.threat_type, ThreatType.GENERIC)

    def test_dedup_key(self):
        adv1 = Advisory(title="Test", source_url="http://a.com", cves=["CVE-2024-1"])
        adv2 = Advisory(title="Test", source_url="http://a.com", cves=["CVE-2024-1"])
        self.assertEqual(adv1.dedup_key, adv2.dedup_key)

    def test_legacy_conversion(self):
        legacy = {
            "title": "Critical RCE in Widget",
            "description": "A vulnerability was found.",
            "source": "CISA",
            "link": "https://cisa.gov/advisory/1",
            "published": "2024-01-01",
            "severity": "critical",
            "confidence": 75,
            "cves": ["CVE-2024-9999"],
            "iocs": ["192.168.1.1", "evil.com"],
        }
        adv = advisory_from_legacy(legacy)
        self.assertEqual(adv.title, "Critical RCE in Widget")
        self.assertEqual(adv.threat_type, ThreatType.VULNERABILITY)
        self.assertEqual(len(adv.iocs), 2)
        self.assertEqual(adv.severity, Severity.CRITICAL)

    def test_to_legacy_dict(self):
        adv = Advisory(
            title="Test",
            summary="Summary",
            cves=["CVE-2024-1"],
            severity=Severity.HIGH,
        )
        d = adv.to_legacy_dict()
        self.assertEqual(d["title"], "Test")
        self.assertIn("advisory_id", d)  # v70 enrichment
        self.assertIn("dedup_key", d)


class TestSchemaValidator(unittest.TestCase):
    def test_valid_manifest(self):
        data = {
            "version": "70.0",
            "schema_version": "2.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "advisories": [
                {"title": "Test Advisory 1"},
                {"title": "Test Advisory 2"},
            ],
        }
        is_valid, errors = validate_manifest(data)
        self.assertTrue(is_valid, f"Errors: {errors}")

    def test_missing_advisories(self):
        data = {"version": "1.0", "schema_version": "1.0", "generated_at": "2024-01-01T00:00:00Z"}
        is_valid, errors = validate_manifest(data)
        self.assertFalse(is_valid)

    def test_empty_title(self):
        errors = validate_advisory({"title": ""}, 0)
        self.assertTrue(len(errors) > 0)

    def test_invalid_severity(self):
        errors = validate_advisory({"title": "Test", "severity": "MEGA_BAD"}, 0)
        self.assertTrue(any("severity" in e for e in errors))

    def test_safe_write(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test_manifest.json")
            data = {
                "version": "1.0",
                "schema_version": "1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "advisories": [{"title": "Test"}],
            }
            ok, msg = safe_write_manifest(data, path)
            self.assertTrue(ok, msg)
            self.assertTrue(os.path.isfile(path))

    def test_safe_write_rejects_invalid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "test.json")
            ok, msg = safe_write_manifest({"bad": True}, path)
            self.assertFalse(ok)


class TestManifestManager(unittest.TestCase):
    def test_publish_and_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ManifestManager(tmpdir)
            manifest = Manifest()
            advisories = [
                Advisory(title="Adv 1", cves=["CVE-2024-1"]),
                Advisory(title="Adv 2"),
            ]
            ok, msg = mgr.publish(manifest, advisories)
            self.assertTrue(ok, msg)

            loaded = mgr.load_current_advisories()
            self.assertEqual(len(loaded), 2)

    def test_version_history(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mgr = ManifestManager(tmpdir)
            for i in range(3):
                manifest = Manifest()
                mgr.publish(manifest, [Advisory(title=f"Adv {i}")])
            history = mgr.get_version_history()
            self.assertEqual(len(history), 3)


class TestDedupEngine(unittest.TestCase):
    def test_exact_dedup(self):
        advs = [
            Advisory(title="Same Title", source_url="http://a.com", cves=["CVE-2024-1"]),
            Advisory(title="Same Title", source_url="http://a.com", cves=["CVE-2024-1"]),
        ]
        engine = DedupEngine()
        result = engine.deduplicate(advs)
        self.assertEqual(len(result), 1)

    def test_cve_overlap_dedup(self):
        advs = [
            Advisory(title="Advisory A", cves=["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]),
            Advisory(title="Advisory B", cves=["CVE-2024-1", "CVE-2024-2", "CVE-2024-4"]),
        ]
        engine = DedupEngine(cve_overlap_threshold=0.40)
        result = engine.deduplicate(advs)
        self.assertEqual(len(result), 1)

    def test_no_false_dedup(self):
        advs = [
            Advisory(title="Totally Different A", cves=["CVE-2024-1"]),
            Advisory(title="Completely Other B", cves=["CVE-2024-999"]),
        ]
        engine = DedupEngine()
        result = engine.deduplicate(advs)
        self.assertEqual(len(result), 2)

    def test_merge_preserves_data(self):
        advs = [
            Advisory(title="Same", source_url="http://a.com", cves=["CVE-2024-1"], confidence=90),
            Advisory(title="Same", source_url="http://a.com", cves=["CVE-2024-2"], confidence=50),
        ]
        engine = DedupEngine()
        result = engine.deduplicate(advs)
        self.assertEqual(len(result), 1)
        # Merged should have both CVEs
        self.assertIn("CVE-2024-1", result[0].cves)
        self.assertIn("CVE-2024-2", result[0].cves)
        # Higher confidence wins
        self.assertEqual(result[0].confidence, 90)


class TestCorrelationEngine(unittest.TestCase):
    def test_cve_correlation(self):
        advs = [
            Advisory(title="Adv A", advisory_id="a1", cves=["CVE-2024-1"]),
            Advisory(title="Adv B", advisory_id="a2", cves=["CVE-2024-1"]),
            Advisory(title="Adv C", advisory_id="a3", cves=["CVE-2024-999"]),
        ]
        engine = CorrelationEngine()
        result = engine.correlate(advs)
        # A and B should be correlated
        self.assertTrue(len(result[0].related_advisories) > 0 or len(result[1].related_advisories) > 0)

    def test_no_false_correlation(self):
        advs = [
            Advisory(title="Adv A", advisory_id="a1", cves=["CVE-2024-1"]),
            Advisory(title="Adv B", advisory_id="a2", cves=["CVE-2024-999"]),
        ]
        engine = CorrelationEngine()
        engine.correlate(advs)
        # Should have 0 links (no shared CVEs, actors, etc.)
        self.assertEqual(len(engine.links), 0)


class TestThreatScoring(unittest.TestCase):
    def test_scoring_range(self):
        engine = ThreatScoringEngine()
        adv = Advisory(title="Test", cves=["CVE-2024-1"], source_name="CISA")
        score = engine.score_advisory(adv)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

    def test_high_score_for_enriched(self):
        cve_lookup = {
            "CVE-2024-9999": CVERecord(
                cve_id="CVE-2024-9999",
                cvss_score=9.8,
                epss_score=0.95,
                kev_status=True,
                exploit_available=True,
            )
        }
        engine = ThreatScoringEngine(cve_lookup=cve_lookup)
        adv = Advisory(
            title="Critical RCE",
            cves=["CVE-2024-9999"],
            source_name="CISA",
            iocs=[IOC(value="10.0.0.1"), IOC(value="evil.com")],
            actors=["APT28"],
            published_date=datetime.now(timezone.utc).isoformat(),
        )
        score = engine.score_advisory(adv)
        self.assertGreater(score, 60)

    def test_source_trust(self):
        self.assertGreater(get_source_trust("CISA"), 0.9)
        self.assertGreater(get_source_trust("Mandiant"), 0.9)
        self.assertLess(get_source_trust("unknown_blog"), 0.6)


class TestConfidenceEngine(unittest.TestCase):
    def test_dynamic_confidence(self):
        engine = ConfidenceEngine()
        adv = Advisory(
            title="Test",
            summary="A detailed summary of the threat.",
            source_name="CISA",
            source_url="https://cisa.gov/1",
            cves=["CVE-2024-1"],
            iocs=[IOC(value="10.0.0.1")],
            published_date=datetime.now(timezone.utc).isoformat(),
        )
        conf = engine.compute_confidence(adv)
        self.assertGreater(conf, 30)  # Well-enriched advisory

    def test_low_confidence_for_sparse(self):
        engine = ConfidenceEngine()
        adv = Advisory(title="Vague")
        conf = engine.compute_confidence(adv)
        self.assertLess(conf, 40)


class TestBlogReportGenerator(unittest.TestCase):
    def test_report_generation(self):
        gen = BlogReportGenerator()
        adv = Advisory(
            title="Critical RCE in WidgetOS",
            summary="A critical vulnerability allows remote code execution.",
            cves=["CVE-2024-9999"],
            severity=Severity.CRITICAL,
            threat_score=92.5,
            confidence=85.0,
            confidence_level=ConfidenceLevel.CONFIRMED,
            source_name="CISA",
            source_url="https://cisa.gov/advisory/1",
            mitre_techniques=["T1190", "T1059"],
            actors=["APT28"],
            iocs=[IOC(value="10.0.0.1"), IOC(value="evil.com")],
            ai_classification="vulnerability",
        )
        report = gen.generate_report(adv)
        self.assertIn("title", report)
        self.assertIn("html", report)
        self.assertIn("labels", report)
        self.assertIn("CRITICAL", report["title"])
        self.assertIn("CVE-2024-9999", report["html"])
        self.assertIn("APT28", report["html"])

    def test_kill_chain_inference(self):
        phases = infer_kill_chain_phases(["T1190", "T1486"])
        self.assertTrue(len(phases) >= 2)


class TestAIClassifier(unittest.TestCase):
    def test_import(self):
        try:
            from agent.v70_apex_upgrade.ai.threat_classifier import ThreatClassifier
            classifier = ThreatClassifier()
            adv = Advisory(title="Critical RCE vulnerability CVE-2024-1234", cves=["CVE-2024-1234"])
            cat, conf = classifier.classify(adv)
            self.assertEqual(cat, "vulnerability")
            self.assertGreater(conf, 0.5)
        except ImportError:
            self.skipTest("sklearn not available")


class TestAIClusterer(unittest.TestCase):
    def test_clustering(self):
        try:
            from agent.v70_apex_upgrade.ai.threat_clusterer import ThreatClusterer
            advs = [
                Advisory(title="RCE in Apache", cves=["CVE-2024-1"], summary="Apache vuln"),
                Advisory(title="RCE in Apache Struts", cves=["CVE-2024-1"], summary="Apache Struts vuln"),
                Advisory(title="Ransomware Attack", summary="LockBit ransomware campaign"),
            ]
            clusterer = ThreatClusterer()
            result = clusterer.cluster(advs)
            self.assertEqual(len(result), 3)
            # At least some should be clustered
        except ImportError:
            self.skipTest("sklearn not available")


class TestEndToEnd(unittest.TestCase):
    """Full pipeline end-to-end test."""

    def test_full_pipeline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = os.path.join(tmpdir, "data")
            os.makedirs(data_dir)

            # Create initial manifest with test data
            test_advisories = [
                {
                    "title": "Critical RCE in Apache Log4j",
                    "description": "Remote code execution vulnerability in Log4j.",
                    "source": "CISA",
                    "link": "https://cisa.gov/advisory/log4j",
                    "published": datetime.now(timezone.utc).isoformat(),
                    "severity": "critical",
                    "confidence": 24,  # Old static confidence
                    "cves": ["CVE-2021-44228", "CVE-2021-45046"],
                    "iocs": ["192.168.1.100", "evil-log4j.com"],
                    "threat_score": 0,  # Not scored yet
                    "mitre_techniques": ["T1190", "T1059"],
                },
                {
                    "title": "Log4Shell Follow-Up Advisory",
                    "description": "Additional IOCs for Log4j exploitation.",
                    "source": "Mandiant",
                    "link": "https://mandiant.com/log4j",
                    "published": datetime.now(timezone.utc).isoformat(),
                    "severity": "high",
                    "confidence": 24,
                    "cves": ["CVE-2021-44228"],
                    "iocs": ["10.0.0.50"],
                },
                # Duplicate (should be deduped)
                {
                    "title": "Critical RCE in Apache Log4j",
                    "description": "Remote code execution vulnerability in Log4j.",
                    "source": "CISA",
                    "link": "https://cisa.gov/advisory/log4j",
                    "published": datetime.now(timezone.utc).isoformat(),
                    "severity": "critical",
                    "confidence": 24,
                    "cves": ["CVE-2021-44228"],
                    "iocs": [],
                },
                {
                    "title": "Ransomware Campaign Targets Healthcare",
                    "description": "LockBit 3.0 targeting hospitals.",
                    "source": "CrowdStrike",
                    "link": "https://crowdstrike.com/lockbit",
                    "published": datetime.now(timezone.utc).isoformat(),
                    "severity": "high",
                    "confidence": 24,
                    "cves": [],
                    "actors": ["LockBit"],
                    "iocs": ["ransomware-c2.evil.com"],
                    "mitre_techniques": ["T1486", "T1071"],
                },
            ]

            initial_manifest = {
                "version": "69.0",
                "schema_version": "1.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "advisories": test_advisories,
            }

            manifest_path = os.path.join(data_dir, "feed_manifest.json")
            with open(manifest_path, "w") as f:
                json.dump(initial_manifest, f, indent=2)

            # Create dummy dashboard
            dashboard_path = os.path.join(tmpdir, "index.html")
            with open(dashboard_path, "w") as f:
                f.write("<html><body>Dashboard</body></html>")

            # Run orchestrator
            from agent.v70_apex_upgrade.orchestrator import Orchestrator, OrchestratorConfig
            config = OrchestratorConfig(
                data_dir=data_dir,
                dashboard_file=dashboard_path,
                enable_ai=True,
                enable_dedup=True,
                enable_correlation=True,
            )
            orch = Orchestrator(config)
            result = orch.run()

            # Assertions
            self.assertTrue(result.success, f"Pipeline failed: {result.error}")
            self.assertGreater(result.total_advisories, 0)
            self.assertGreater(result.dedup_removed, 0, "Should have removed the duplicate")
            self.assertLess(result.total_advisories, len(test_advisories), "Dedup should reduce count")

            # Verify manifest was written and is valid
            self.assertTrue(os.path.isfile(manifest_path))
            with open(manifest_path, "r") as f:
                final_manifest = json.load(f)

            self.assertEqual(final_manifest["version"], "70.0")
            self.assertGreater(len(final_manifest["advisories"]), 0)

            # Verify no duplicates in output
            dedup_keys = [a.get("dedup_key", "") for a in final_manifest["advisories"]]
            self.assertEqual(len(dedup_keys), len(set(dedup_keys)), "Duplicates in final manifest!")

            # Verify enrichment (confidence should NOT be static 24%)
            for adv in final_manifest["advisories"]:
                conf = adv.get("confidence", 0)
                self.assertNotEqual(conf, 24, f"Advisory still has static 24% confidence: {adv['title']}")
                self.assertGreater(adv.get("threat_score", 0), 0, f"No threat score: {adv['title']}")

            # Verify version history exists
            versions_dir = os.path.join(data_dir, "manifest_versions")
            self.assertTrue(os.path.isdir(versions_dir))

            print(f"\n✓ End-to-end test passed: {result.total_advisories} advisories, "
                  f"{result.dedup_removed} deduped, {result.duration_seconds}s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
