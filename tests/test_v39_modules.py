#!/usr/bin/env python3
"""
test_v39_modules.py — CYBERDUDEBIVASH® SENTINEL APEX v39.0 Test Suite
=======================================================================
Comprehensive testing for all NEXUS Intelligence subsystems.
Zero regression: Tests only v39 modules, never modifies existing tests.

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import json
import os
import sys
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ═══════════════════════════════════════════════════════════════════════════════
# MOCK DATA
# ═══════════════════════════════════════════════════════════════════════════════

MOCK_ENTRIES = [
    {
        "title": "CVE-2026-1234 — Critical RCE in Apache Struts exploited by APT28",
        "risk_score": 9.5,
        "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        "stix_id": "indicator--test-001",
        "actor_tag": "APT28",
        "kev_present": True,
        "supply_chain": False,
        "epss_score": 85,
        "cvss_score": 9.8,
        "confidence_score": 90,
        "feed_source": "CISA",
        "blog_url": "https://cyberbivash.blogspot.com/test1",
        "mitre_tactics": ["T1190", "T1059", "T1071"],
        "ioc_counts": {"domain": 5, "ipv4": 12, "sha256": 3},
    },
    {
        "title": "Ransomware group LockBit targets financial sector via phishing",
        "risk_score": 8.2,
        "timestamp": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
        "stix_id": "indicator--test-002",
        "actor_tag": "LockBit",
        "kev_present": False,
        "supply_chain": False,
        "epss_score": 45,
        "cvss_score": 7.5,
        "confidence_score": 75,
        "feed_source": "BleepingComputer",
        "blog_url": "https://cyberbivash.blogspot.com/test2",
        "mitre_tactics": ["T1566", "T1486", "T1490", "T1021"],
        "ioc_counts": {"domain": 8, "ipv4": 6, "url": 2},
    },
    {
        "title": "Supply chain attack via compromised NPM package by Lazarus Group",
        "risk_score": 9.8,
        "timestamp": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
        "stix_id": "indicator--test-003",
        "actor_tag": "Lazarus",
        "kev_present": True,
        "supply_chain": True,
        "epss_score": 72,
        "cvss_score": 9.1,
        "confidence_score": 85,
        "feed_source": "TheHackersNews",
        "blog_url": "https://cyberbivash.blogspot.com/test3",
        "mitre_tactics": ["T1195", "T1059", "T1547", "T1041"],
        "ioc_counts": {"domain": 3, "sha256": 7},
    },
    {
        "title": "CVE-2026-5678 — Zero-day exploitation in Cisco IOS by APT28",
        "risk_score": 9.0,
        "timestamp": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
        "stix_id": "indicator--test-004",
        "actor_tag": "APT28",
        "kev_present": True,
        "supply_chain": False,
        "epss_score": 90,
        "cvss_score": 9.5,
        "confidence_score": 88,
        "feed_source": "CISA",
        "blog_url": "https://cyberbivash.blogspot.com/test4",
        "mitre_tactics": ["T1190", "T1068", "T1573"],
        "ioc_counts": {"ipv4": 20, "domain": 4},
    },
    {
        "title": "Cloud credential theft campaign targeting AWS environments",
        "risk_score": 7.5,
        "timestamp": (datetime.now(timezone.utc) - timedelta(days=4)).isoformat(),
        "stix_id": "indicator--test-005",
        "actor_tag": "UNC-CDB-99",
        "kev_present": False,
        "supply_chain": False,
        "epss_score": 30,
        "cvss_score": 6.5,
        "confidence_score": 60,
        "feed_source": "DarkReading",
        "blog_url": "https://cyberbivash.blogspot.com/test5",
        "mitre_tactics": ["T1078", "T1528", "T1567"],
        "ioc_counts": {"domain": 2, "ipv4": 1},
    },
    {
        "title": "Low severity information disclosure in WordPress plugin",
        "risk_score": 3.0,
        "timestamp": (datetime.now(timezone.utc) - timedelta(days=6)).isoformat(),
        "stix_id": "indicator--test-006",
        "actor_tag": "",
        "kev_present": False,
        "supply_chain": False,
        "epss_score": 5,
        "cvss_score": 3.1,
        "confidence_score": 40,
        "feed_source": "CVEFeed",
        "mitre_tactics": [],
        "ioc_counts": {},
    },
]


def _mock_entries():
    return MOCK_ENTRIES


# ═══════════════════════════════════════════════════════════════════════════════
# N1 — HUNTING ENGINE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestHuntingEngine:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_generate_hunts_produces_results(self, mock):
        from agent.v39_nexus.nexus_engine import HuntingEngine
        engine = HuntingEngine()
        hunts = engine.generate_hunts()
        assert isinstance(hunts, list)
        assert len(hunts) > 0

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_hunt_has_required_fields(self, mock):
        from agent.v39_nexus.nexus_engine import HuntingEngine
        engine = HuntingEngine()
        hunts = engine.generate_hunts()
        for hunt in hunts:
            assert "hunt_id" in hunt
            assert "hypothesis" in hunt
            assert "data_sources" in hunt
            assert "techniques" in hunt
            assert "priority" in hunt
            assert hunt["priority"] in ["CRITICAL", "HIGH", "MEDIUM"]

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_hunts_prioritized_correctly(self, mock):
        from agent.v39_nexus.nexus_engine import HuntingEngine
        engine = HuntingEngine()
        hunts = engine.generate_hunts()
        priorities = [h["priority"] for h in hunts]
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        for i in range(len(priorities) - 1):
            assert priority_order[priorities[i]] <= priority_order[priorities[i + 1]]

    @patch("agent.v39_nexus.nexus_engine._entries", return_value=[])
    def test_empty_entries_returns_empty(self, mock):
        from agent.v39_nexus.nexus_engine import HuntingEngine
        engine = HuntingEngine()
        hunts = engine.generate_hunts()
        assert hunts == []

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_supply_chain_template_selected(self, mock):
        from agent.v39_nexus.nexus_engine import HuntingEngine
        engine = HuntingEngine()
        hunts = engine.generate_hunts()
        sc_hunts = [h for h in hunts if "supply" in h["hypothesis"].lower()]
        assert len(sc_hunts) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# N2 — CORRELATION MATRIX TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCorrelationMatrix:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_correlate_campaigns(self, mock):
        from agent.v39_nexus.nexus_engine import CorrelationMatrix
        matrix = CorrelationMatrix()
        campaigns = matrix.correlate_campaigns()
        assert isinstance(campaigns, list)
        assert len(campaigns) > 0

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_campaign_has_required_fields(self, mock):
        from agent.v39_nexus.nexus_engine import CorrelationMatrix
        matrix = CorrelationMatrix()
        campaigns = matrix.correlate_campaigns()
        for c in campaigns:
            assert "campaign_id" in c
            assert "name" in c
            assert "actors" in c
            assert "severity" in c
            assert "confidence" in c

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_apt28_correlated_as_campaign(self, mock):
        from agent.v39_nexus.nexus_engine import CorrelationMatrix
        matrix = CorrelationMatrix()
        campaigns = matrix.correlate_campaigns()
        apt28_campaigns = [c for c in campaigns if "APT28" in c.get("actors", [])]
        assert len(apt28_campaigns) >= 1


# ═══════════════════════════════════════════════════════════════════════════════
# N3 — ATTACK CHAIN TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAttackChainReconstructor:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_reconstruct_chains(self, mock):
        from agent.v39_nexus.nexus_engine import AttackChainReconstructor
        recon = AttackChainReconstructor()
        chains = recon.reconstruct_chains()
        assert isinstance(chains, list)

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_chain_has_phases(self, mock):
        from agent.v39_nexus.nexus_engine import AttackChainReconstructor
        recon = AttackChainReconstructor()
        chains = recon.reconstruct_chains()
        for chain in chains:
            assert "phases" in chain
            assert "completeness_pct" in chain
            assert "assessment" in chain


# ═══════════════════════════════════════════════════════════════════════════════
# N4 — EXPOSURE FORECASTER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestExposureForecaster:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_compute_exposure(self, mock):
        from agent.v39_nexus.nexus_engine import ExposureForecaster
        forecaster = ExposureForecaster()
        exposure = forecaster.compute_exposure()
        assert "overall_score" in exposure
        assert 0 <= exposure["overall_score"] <= 10

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_exposure_has_components(self, mock):
        from agent.v39_nexus.nexus_engine import ExposureForecaster
        forecaster = ExposureForecaster()
        exposure = forecaster.compute_exposure()
        components = exposure.get("component_scores", {})
        assert "threat_velocity" in components
        assert "critical_density" in components
        assert "kev_exposure" in components

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_exposure_trend_valid(self, mock):
        from agent.v39_nexus.nexus_engine import ExposureForecaster
        forecaster = ExposureForecaster()
        exposure = forecaster.compute_exposure()
        assert exposure["trend"] in ["increasing", "stable", "decreasing"]


# ═══════════════════════════════════════════════════════════════════════════════
# N5 — DETECTION ENGINEER TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestDetectionEngineer:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_generate_detection_pack(self, mock):
        from agent.v39_nexus.nexus_engine import DetectionEngineer
        eng = DetectionEngineer()
        pack = eng.generate_detection_pack()
        assert "sigma_rules" in pack
        assert "yara_rules" in pack
        assert "snort_rules" in pack
        assert "stats" in pack

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_sigma_rules_generated(self, mock):
        from agent.v39_nexus.nexus_engine import DetectionEngineer
        eng = DetectionEngineer()
        pack = eng.generate_detection_pack()
        assert len(pack["sigma_rules"]) > 0

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_yara_rules_valid(self, mock):
        from agent.v39_nexus.nexus_engine import DetectionEngineer
        eng = DetectionEngineer()
        pack = eng.generate_detection_pack()
        for rule in pack["yara_rules"]:
            assert "rule_name" in rule
            assert "rule_text" in rule
            assert "rule CDB_" in rule["rule_text"]


# ═══════════════════════════════════════════════════════════════════════════════
# N6 — EXECUTIVE BRIEFING TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestExecBriefingGenerator:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_generate_briefing(self, mock):
        from agent.v39_nexus.nexus_engine import ExecBriefingGenerator
        gen = ExecBriefingGenerator()
        briefing = gen.generate_briefing()
        assert "executive_summary" in briefing
        assert "threat_landscape" in briefing
        assert "key_recommendations" in briefing
        assert "priority_actions" in briefing

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_briefing_classification(self, mock):
        from agent.v39_nexus.nexus_engine import ExecBriefingGenerator
        gen = ExecBriefingGenerator()
        briefing = gen.generate_briefing()
        assert briefing["classification"] == "TLP:AMBER"


# ═══════════════════════════════════════════════════════════════════════════════
# N7 — ADVERSARY EMULATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdversaryEmulationPlanner:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_generate_exercises(self, mock):
        from agent.v39_nexus.nexus_engine import AdversaryEmulationPlanner
        planner = AdversaryEmulationPlanner()
        exercises = planner.generate_exercises()
        assert isinstance(exercises, list)
        assert len(exercises) > 0

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_exercise_has_required_fields(self, mock):
        from agent.v39_nexus.nexus_engine import AdversaryEmulationPlanner
        planner = AdversaryEmulationPlanner()
        exercises = planner.generate_exercises()
        for ex in exercises:
            assert "exercise_id" in ex
            assert "adversary" in ex
            assert "techniques" in ex
            assert "success_criteria" in ex


# ═══════════════════════════════════════════════════════════════════════════════
# N8 — INTEL REQUIREMENTS TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntelRequirementsManager:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_analyze_coverage(self, mock):
        from agent.v39_nexus.nexus_engine import IntelRequirementsManager
        mgr = IntelRequirementsManager()
        result = mgr.analyze_coverage()
        assert "pirs" in result
        assert "coverage" in result
        assert "overall_coverage_pct" in result

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    def test_coverage_detects_ransomware_pir(self, mock):
        from agent.v39_nexus.nexus_engine import IntelRequirementsManager
        mgr = IntelRequirementsManager()
        result = mgr.analyze_coverage()
        pir_001 = result["coverage"].get("PIR-001", {})
        assert pir_001.get("matching_advisories", 0) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR INTEGRATION TEST
# ═══════════════════════════════════════════════════════════════════════════════

class TestNexusOrchestrator:

    @patch("agent.v39_nexus.nexus_engine._entries", side_effect=_mock_entries)
    @patch("agent.v39_nexus.nexus_engine._save_json", return_value=True)
    def test_full_cycle(self, mock_save, mock_entries):
        from agent.v39_nexus.nexus_engine import NexusOrchestrator
        orchestrator = NexusOrchestrator()
        results = orchestrator.execute_full_cycle()

        assert results["version"] == "39.0.0"
        assert results["codename"] == "NEXUS INTELLIGENCE"
        assert "threat_hunts" in results
        assert "campaigns" in results
        assert "attack_chains" in results
        assert "exposure" in results
        assert "detection_pack" in results
        assert "executive_briefing" in results
        assert "emulation_exercises" in results
        assert "intel_requirements" in results
        assert results["execution_time_ms"] > 0


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestUtilityFunctions:

    def test_generate_id_deterministic(self):
        from agent.v39_nexus.nexus_engine import _generate_id
        id1 = _generate_id("test", "seed123")
        id2 = _generate_id("test", "seed123")
        assert id1 == id2
        assert id1.startswith("test--")

    def test_severity_from_score(self):
        from agent.v39_nexus.nexus_engine import _severity_from_score
        assert _severity_from_score(9.5) == "CRITICAL"
        assert _severity_from_score(8.0) == "HIGH"
        assert _severity_from_score(5.0) == "MEDIUM"
        assert _severity_from_score(2.0) == "LOW"
        assert _severity_from_score(0.5) == "INFO"

    def test_extract_all_iocs(self):
        from agent.v39_nexus.nexus_engine import _extract_all_iocs
        text = "Found CVE-2026-1234 at 192.168.1.1 from evil.com with hash abc123def456abc123def456abc123de"
        iocs = _extract_all_iocs(text)
        assert "CVE-2026-1234" in iocs["cve"]
        assert "192.168.1.1" in iocs["ipv4"]


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
