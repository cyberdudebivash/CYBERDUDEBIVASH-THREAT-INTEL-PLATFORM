#!/usr/bin/env python3
"""
test_v40_v41_v42_modules.py — Test Suite for CORTEX, QUANTUM, SOVEREIGN
=========================================================================
Zero regression: Tests only v40-v42 modules, never modifies existing tests.
"""

import json, os, sys, pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

MOCK_ENTRIES = [
    {"title": "CVE-2026-1234 — Critical RCE in Apache Struts by APT28", "risk_score": 9.5,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
     "stix_id": "indicator--test-001", "actor_tag": "APT28", "kev_present": True,
     "supply_chain": False, "epss_score": 85, "cvss_score": 9.8, "confidence_score": 90,
     "feed_source": "CISA", "blog_url": "https://test.com/1",
     "mitre_tactics": ["T1190", "T1059", "T1071"], "ioc_counts": {"domain": 5, "ipv4": 12}},
    {"title": "Ransomware LockBit targets financial sector", "risk_score": 8.2,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
     "stix_id": "indicator--test-002", "actor_tag": "LockBit", "kev_present": False,
     "supply_chain": False, "epss_score": 45, "cvss_score": 7.5, "confidence_score": 75,
     "feed_source": "BleepingComputer", "blog_url": "https://test.com/2",
     "mitre_tactics": ["T1566", "T1486"], "ioc_counts": {"domain": 8}},
    {"title": "CVE-2026-5678 — Zero-day in Cisco by APT28", "risk_score": 9.0,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
     "stix_id": "indicator--test-003", "actor_tag": "APT28", "kev_present": True,
     "supply_chain": False, "epss_score": 90, "cvss_score": 9.5, "confidence_score": 88,
     "feed_source": "CISA", "blog_url": "https://test.com/3",
     "mitre_tactics": ["T1190", "T1068", "T1573"], "ioc_counts": {"ipv4": 20}},
    {"title": "Cloud credential theft targeting AWS", "risk_score": 7.5,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=4)).isoformat(),
     "stix_id": "indicator--test-004", "actor_tag": "UNC-CDB-99", "kev_present": False,
     "supply_chain": False, "epss_score": 30, "cvss_score": 6.5, "confidence_score": 60,
     "feed_source": "DarkReading", "mitre_tactics": ["T1078"], "ioc_counts": {}},
    {"title": "Low severity info disclosure", "risk_score": 2.0,
     "timestamp": (datetime.now(timezone.utc) - timedelta(days=5)).isoformat(),
     "stix_id": "indicator--test-005", "actor_tag": "", "kev_present": False,
     "supply_chain": False, "epss_score": 3, "cvss_score": 2.1, "confidence_score": 20,
     "feed_source": "CVEFeed", "mitre_tactics": [], "ioc_counts": {}},
]

def _mock_entries():
    return MOCK_ENTRIES


# ═══════════════════════════════════════════════════════════════════════════════
# v40 CORTEX TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestIntelFirehose:
    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_generate_stream(self, mock):
        from agent.v40_cortex.cortex_engine import IntelFirehose
        fh = IntelFirehose()
        stream = fh.generate_stream(since_hours=168)
        assert "metadata" in stream
        assert "events" in stream
        assert stream["metadata"]["total_events"] > 0

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_stream_channels(self, mock):
        from agent.v40_cortex.cortex_engine import IntelFirehose
        fh = IntelFirehose()
        stream = fh.generate_stream(since_hours=168)
        channels = stream["metadata"]["channels"]
        assert "threat-intel" in channels
        assert channels["threat-intel"] > 0

    def test_websocket_config(self):
        from agent.v40_cortex.cortex_engine import IntelFirehose
        fh = IntelFirehose()
        config = fh.get_websocket_config()
        assert "server" in config
        assert "channels" in config
        assert config["server"]["protocol"] == "wss"


class TestThreatKnowledgeGraph:
    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_build_graph(self, mock):
        from agent.v40_cortex.cortex_engine import ThreatKnowledgeGraph
        g = ThreatKnowledgeGraph()
        stats = g.build_graph()
        assert stats["total_nodes"] > 0
        assert stats["total_edges"] > 0

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_get_neighbors(self, mock):
        from agent.v40_cortex.cortex_engine import ThreatKnowledgeGraph
        g = ThreatKnowledgeGraph()
        g.build_graph()
        # Get neighbors of APT28
        result = g.get_neighbors("actor--apt28", max_depth=1)
        assert "neighbors" in result
        assert len(result["neighbors"]) > 0

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_export_graph(self, mock):
        from agent.v40_cortex.cortex_engine import ThreatKnowledgeGraph
        g = ThreatKnowledgeGraph()
        g.build_graph()
        export = g.export_graph()
        assert "nodes" in export
        assert "edges" in export
        assert len(export["nodes"]) > 0

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_entity_report(self, mock):
        from agent.v40_cortex.cortex_engine import ThreatKnowledgeGraph
        g = ThreatKnowledgeGraph()
        g.build_graph()
        report = g.get_entity_report("actor--apt28")
        assert "centrality_score" in report
        assert "connection_count" in report


class TestNaturalLanguageQuery:
    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_process_actor_query(self, mock):
        from agent.v40_cortex.cortex_engine import NaturalLanguageQueryEngine, ThreatKnowledgeGraph
        g = ThreatKnowledgeGraph()
        g.build_graph()
        nlq = NaturalLanguageQueryEngine()
        result = nlq.process_query("Show all APT28 activity", g)
        assert result["results"]["count"] > 0

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_severity_filter_query(self, mock):
        from agent.v40_cortex.cortex_engine import NaturalLanguageQueryEngine, ThreatKnowledgeGraph
        g = ThreatKnowledgeGraph()
        g.build_graph()
        nlq = NaturalLanguageQueryEngine()
        result = nlq.process_query("Find all critical threats", g)
        assert result["results"]["count"] > 0

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_count_query(self, mock):
        from agent.v40_cortex.cortex_engine import NaturalLanguageQueryEngine, ThreatKnowledgeGraph
        g = ThreatKnowledgeGraph()
        nlq = NaturalLanguageQueryEngine()
        result = nlq.process_query("How many advisories are tracked", g)
        assert result["results"]["count"] == len(MOCK_ENTRIES)


class TestRelationshipExplorer:
    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_attack_corridors(self, mock):
        from agent.v40_cortex.cortex_engine import ThreatKnowledgeGraph, RelationshipExplorer
        g = ThreatKnowledgeGraph()
        g.build_graph()
        exp = RelationshipExplorer(g)
        corridors = exp.find_attack_corridors()
        assert isinstance(corridors, list)

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_influence_scores(self, mock):
        from agent.v40_cortex.cortex_engine import ThreatKnowledgeGraph, RelationshipExplorer
        g = ThreatKnowledgeGraph()
        g.build_graph()
        exp = RelationshipExplorer(g)
        scores = exp.compute_influence_scores()
        assert isinstance(scores, list)
        assert len(scores) > 0
        assert "influence_score" in scores[0]

    @patch("agent.v40_cortex.cortex_engine._entries", side_effect=_mock_entries)
    def test_cluster_analysis(self, mock):
        from agent.v40_cortex.cortex_engine import ThreatKnowledgeGraph, RelationshipExplorer
        g = ThreatKnowledgeGraph()
        g.build_graph()
        exp = RelationshipExplorer(g)
        clusters = exp.get_cluster_analysis()
        assert "total_clusters" in clusters


# ═══════════════════════════════════════════════════════════════════════════════
# v41 QUANTUM TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAnomalyDetector:
    @patch("agent.v41_quantum.quantum_engine._entries")
    def test_detect_anomalies(self, mock):
        # Need 10+ entries for anomaly detection
        expanded = MOCK_ENTRIES * 3  # 15 entries
        mock.return_value = expanded
        from agent.v41_quantum.quantum_engine import AnomalyDetector
        d = AnomalyDetector()
        result = d.detect_anomalies()
        assert "anomaly_count" in result
        assert "overall_anomaly_score" in result
        assert "baseline_stats" in result

    @patch("agent.v41_quantum.quantum_engine._entries")
    def test_baselines_computed(self, mock):
        expanded = MOCK_ENTRIES * 3
        mock.return_value = expanded
        from agent.v41_quantum.quantum_engine import AnomalyDetector
        d = AnomalyDetector()
        result = d.detect_anomalies()
        stats = result["baseline_stats"]
        assert "risk_mean" in stats
        assert stats["total_entries"] == len(expanded)


class TestAdversarialFeedGuard:
    @patch("agent.v41_quantum.quantum_engine._entries", side_effect=_mock_entries)
    def test_analyze_feeds(self, mock):
        from agent.v41_quantum.quantum_engine import AdversarialFeedGuard
        g = AdversarialFeedGuard()
        result = g.analyze_feeds()
        assert "feed_scores" in result
        assert "overall_trust" in result
        assert result["feed_count"] > 0


class TestFalsePositiveReducer:
    @patch("agent.v41_quantum.quantum_engine._entries", side_effect=_mock_entries)
    def test_analyze(self, mock):
        from agent.v41_quantum.quantum_engine import FalsePositiveReducer
        r = FalsePositiveReducer()
        result = r.analyze()
        assert "entries_analyzed" in result
        assert result["entries_analyzed"] == len(MOCK_ENTRIES)
        assert "estimated_fp_rate_pct" in result


class TestDetectionABTester:
    @patch("agent.v41_quantum.quantum_engine._entries", side_effect=_mock_entries)
    def test_generate_experiments(self, mock):
        from agent.v41_quantum.quantum_engine import DetectionABTester
        t = DetectionABTester()
        result = t.generate_experiments()
        assert "experiments" in result
        assert result["total_experiments"] > 0
        assert "variant_a" in result["experiments"][0]
        assert "variant_b" in result["experiments"][0]


# ═══════════════════════════════════════════════════════════════════════════════
# v42 SOVEREIGN TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestTenantManager:
    def test_create_tenant(self):
        from agent.v42_sovereign.sovereign_engine import TenantManager
        with patch("agent.v42_sovereign.sovereign_engine._load", return_value=None), \
             patch("agent.v42_sovereign.sovereign_engine._save", return_value=True):
            tm = TenantManager()
            result = tm.create_tenant("Test Corp", "pro", "admin@test.com")
            assert "tenant_id" in result
            assert "api_key" in result
            assert result["tier"] == "pro"

    def test_check_access_allowed(self):
        from agent.v42_sovereign.sovereign_engine import TenantManager, Tenant
        with patch("agent.v42_sovereign.sovereign_engine._load", return_value=None), \
             patch("agent.v42_sovereign.sovereign_engine._save", return_value=True):
            tm = TenantManager()
            tm.create_tenant("Enterprise Corp", "enterprise", "admin@ent.com")
            tid = list(tm.tenants.keys())[0]
            result = tm.check_access(tid, "executive_briefings")
            assert result["allowed"] is True

    def test_check_access_denied(self):
        from agent.v42_sovereign.sovereign_engine import TenantManager
        with patch("agent.v42_sovereign.sovereign_engine._load", return_value=None), \
             patch("agent.v42_sovereign.sovereign_engine._save", return_value=True):
            tm = TenantManager()
            tm.create_tenant("Free Corp", "free", "admin@free.com")
            tid = list(tm.tenants.keys())[0]
            result = tm.check_access(tid, "executive_briefings")
            assert result["allowed"] is False


class TestBillingEngine:
    def test_compute_mrr(self):
        from agent.v42_sovereign.sovereign_engine import BillingEngine, Tenant
        be = BillingEngine()
        tenants = {
            "t1": Tenant(tenant_id="t1", org_name="Pro Corp", tier="pro"),
            "t2": Tenant(tenant_id="t2", org_name="Ent Corp", tier="enterprise"),
            "t3": Tenant(tenant_id="t3", org_name="Free Corp", tier="free"),
        }
        mrr = be.compute_mrr(tenants)
        assert mrr["total_mrr"] == 49 + 499  # pro + enterprise
        assert mrr["arr"] == (49 + 499) * 12

    def test_stripe_config(self):
        from agent.v42_sovereign.sovereign_engine import BillingEngine
        be = BillingEngine()
        config = be.get_stripe_config()
        assert "stripe_integration" in config
        assert "products" in config["stripe_integration"]


class TestComplianceAutomation:
    @patch("agent.v42_sovereign.sovereign_engine._entries", side_effect=_mock_entries)
    def test_soc2_report(self, mock):
        from agent.v42_sovereign.sovereign_engine import ComplianceAutomation
        ca = ComplianceAutomation()
        report = ca.generate_compliance_report("SOC2")
        assert report["compliance_score_pct"] > 0
        assert report["total_controls"] == 10
        assert report["framework"] == "SOC2"

    @patch("agent.v42_sovereign.sovereign_engine._entries", side_effect=_mock_entries)
    def test_nist_report(self, mock):
        from agent.v42_sovereign.sovereign_engine import ComplianceAutomation
        ca = ComplianceAutomation()
        report = ca.generate_compliance_report("NIST_CSF")
        assert report["compliance_score_pct"] > 0


class TestOnboardingPortal:
    def test_generate_flow(self):
        from agent.v42_sovereign.sovereign_engine import OnboardingPortal
        op = OnboardingPortal()
        flow = op.generate_onboarding_flow("Demo Corp", "enterprise")
        assert flow["total_steps"] == 8
        assert "quick_start_guide" in flow
        assert "integration_templates" in flow


class TestWhiteLabelEngine:
    def test_generate_config(self):
        from agent.v42_sovereign.sovereign_engine import WhiteLabelEngine
        wl = WhiteLabelEngine()
        config = wl.generate_whitelabel_config("TestMSSP", "intel.testmssp.com")
        assert config["mssp_name"] == "TestMSSP"
        assert config["branding"]["domain"] == "intel.testmssp.com"
        assert "dns_config" in config
        assert "sub_tenant_management" in config


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
