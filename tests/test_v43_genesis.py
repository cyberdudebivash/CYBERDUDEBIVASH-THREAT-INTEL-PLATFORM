#!/usr/bin/env python3
"""test_v43_genesis.py — Test Suite for all 12 GENESIS engines. Zero regression."""
import json, os, sys, pytest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MOCK = [
    {"title": "CVE-2026-1234 Critical RCE by APT28", "risk_score": 9.5,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
     "stix_id": "indicator--001", "actor_tag": "APT28", "kev_present": True,
     "epss_score": 85, "cvss_score": 9.8, "confidence_score": 90, "feed_source": "CISA",
     "blog_url": "https://test.com/1", "mitre_tactics": ["T1190", "T1059", "T1071"],
     "ioc_counts": {"domain": 5, "ipv4": 12, "sha256": 1}, "supply_chain": False},
    {"title": "Ransomware LockBit targets financial sector", "risk_score": 8.2,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
     "stix_id": "indicator--002", "actor_tag": "LockBit", "kev_present": False,
     "epss_score": 45, "feed_source": "BleepingComputer", "mitre_tactics": ["T1566", "T1486"],
     "ioc_counts": {"domain": 8}, "blog_url": "https://test.com/2"},
    {"title": "CVE-2026-5678 Zero-day Cisco by APT28", "risk_score": 9.0,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
     "stix_id": "indicator--003", "actor_tag": "APT28", "kev_present": True,
     "epss_score": 90, "feed_source": "CISA", "mitre_tactics": ["T1190", "T1068"],
     "ioc_counts": {"ipv4": 20}, "blog_url": "https://test.com/3"},
    {"title": "Cloud credential theft AWS exposure", "risk_score": 7.5,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=4)).isoformat(),
     "stix_id": "indicator--004", "actor_tag": "UNC-CDB-99", "kev_present": False,
     "feed_source": "DarkReading", "mitre_tactics": ["T1078"], "ioc_counts": {}},
    {"title": "Low severity WordPress info disclosure", "risk_score": 2.0,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
     "stix_id": "indicator--005", "actor_tag": "", "kev_present": False,
     "feed_source": "CVEFeed", "mitre_tactics": [], "ioc_counts": {}},
]
def _m(): return MOCK

# G01
class TestSensorNetwork:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_telemetry(self, m):
        from agent.v43_genesis.genesis_engine import GlobalCyberSensorNetwork
        r = GlobalCyberSensorNetwork().generate_telemetry()
        assert r["sensor_count"] == 8
        assert r["total_events_24h"] > 0
        assert all(s["status"] == "ONLINE" for s in r["sensors"])

# G02
class TestHoneypotGrid:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_grid(self, m):
        from agent.v43_genesis.genesis_engine import HoneypotGrid
        r = HoneypotGrid().generate_grid_telemetry()
        assert r["honeypot_count"] == 8
        assert r["total_captures_24h"] > 0

# G03
class TestMalwareCloud:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_analysis(self, m):
        from agent.v43_genesis.genesis_engine import MalwareAnalysisCloud
        r = MalwareAnalysisCloud().analyze_landscape()
        assert "sandbox_config" in r
        assert "analysis_capabilities" in r
        assert len(r["analysis_capabilities"]) >= 5

# G04
class TestActorRegistry:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_registry(self, m):
        from agent.v43_genesis.genesis_engine import ThreatActorIntelRegistry
        r = ThreatActorIntelRegistry().build_registry()
        assert r["total_actors"] > 0
        assert r["known_actors"] >= 8
        apt28 = [a for a in r["actors"] if a["name"] == "APT28"]
        assert len(apt28) == 1
        assert apt28[0]["observed_advisories"] == 2

# G05
class TestCampaignCorrelation:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_correlate(self, m):
        from agent.v43_genesis.genesis_engine import CampaignCorrelationEngine
        r = CampaignCorrelationEngine().correlate()
        assert r["total_campaigns"] > 0
        apt28_campaigns = [c for c in r["campaigns"] if "APT28" in c.get("actor", "")]
        assert len(apt28_campaigns) >= 1

# G06
class TestIOCReputation:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_reputations(self, m):
        from agent.v43_genesis.genesis_engine import IOCReputationEngine
        r = IOCReputationEngine().compute_reputations()
        assert r["total_iocs_scored"] > 0
        assert r["malicious_count"] >= 0

# G07
class TestAutoDetection:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_pack(self, m):
        from agent.v43_genesis.genesis_engine import AutoDetectionGenerator
        r = AutoDetectionGenerator().generate_full_pack()
        assert r["stats"]["total_rules"] > 0
        assert r["stats"]["sigma"] > 0
        assert r["stats"]["suricata"] > 0

# G08
class TestTAXII:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_config(self, m):
        from agent.v43_genesis.genesis_engine import TAXIIServer
        r = TAXIIServer().generate_server_config()
        assert r["taxii_server"]["version"] == "2.1"
        assert len(r["collections"]) == 4
        assert "rest_api" in r

# G09
class TestDarkWeb:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_report(self, m):
        from agent.v43_genesis.genesis_engine import DarkWebIntelligence
        r = DarkWebIntelligence().generate_darkweb_report()
        assert r["source_count"] > 0
        assert len(r["monitoring_capabilities"]) >= 5

# G10
class TestAttackSurface:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_exposure(self, m):
        from agent.v43_genesis.genesis_engine import AttackSurfaceIntelligence
        r = AttackSurfaceIntelligence().analyze_exposure()
        assert "scan_capabilities" in r
        assert len(r["scan_capabilities"]) >= 5

# G11
class TestAttackMap:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_map(self, m):
        from agent.v43_genesis.genesis_engine import GlobalAttackMap
        r = GlobalAttackMap().generate_map_data()
        assert r["total_flows"] > 0
        assert len(r["hotspots"]) > 0

# G12
class TestAIHunter:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    def test_hunt(self, m):
        from agent.v43_genesis.genesis_engine import AIThreatHuntingEngine
        r = AIThreatHuntingEngine().execute_hunt()
        assert "threat_clusters" in r
        assert "predictions" in r or "emerging_predictions" in r

# ORCHESTRATOR
class TestOrchestrator:
    @patch("agent.v43_genesis.genesis_engine._entries", side_effect=_m)
    @patch("agent.v43_genesis.genesis_engine._save", return_value=True)
    def test_full_cycle(self, ms, me):
        from agent.v43_genesis.genesis_engine import GenesisOrchestrator
        r = GenesisOrchestrator().execute_full_cycle()
        assert r["version"] == "43.0.0"
        assert r["engines_ok"] == 12
        assert r["engines_total"] == 12
        assert r["execution_time_ms"] > 0

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
