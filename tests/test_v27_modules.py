"""
SENTINEL APEX v27.0 — Test Suite
=================================
Comprehensive tests for all v27 modules.

Run: pytest tests/test_v27_modules.py -v
"""

import pytest
import asyncio
from datetime import datetime, timezone


class TestV27Config:
    """Tests for v27 configuration"""
    
    def test_config_loads(self):
        from agent.v27.config_v27 import V27Config, config
        
        assert config.VERSION == "27.0.0"
        assert config.CODENAME == "Phoenix Enterprise"
        assert config.STREAMING_ENABLED is True
        assert config.OBSERVABILITY_ENABLED is True
    
    def test_config_to_dict(self):
        from agent.v27.config_v27 import config
        
        cfg_dict = config.to_dict()
        assert "version" in cfg_dict
        assert "streaming" in cfg_dict
        assert "features" in cfg_dict


class TestStreamingPipeline:
    """Tests for streaming pipeline"""
    
    @pytest.fixture
    def pipeline(self):
        from agent.v27.streaming.pipeline import StreamingPipeline, InMemoryQueueBackend
        
        backend = InMemoryQueueBackend()
        return StreamingPipeline(backend=backend)
    
    @pytest.mark.asyncio
    async def test_ingest_event(self, pipeline):
        event_id = await pipeline.ingest(
            event_type="cve",
            payload={"cve_id": "CVE-2026-12345", "cvss_score": 9.8},
            source="test",
        )
        
        assert event_id is not None
        assert pipeline._stats["events_received"] == 1
    
    @pytest.mark.asyncio
    async def test_priority_detection(self, pipeline):
        # Critical threat
        await pipeline.ingest(
            event_type="cve",
            payload={"zero_day": True, "cvss_score": 10.0},
            source="test",
        )
        
        depths = await pipeline.get_queue_depths()
        assert depths["CRITICAL"] > 0
    
    @pytest.mark.asyncio
    async def test_handler_registration(self, pipeline):
        processed = []
        
        async def handler(event):
            processed.append(event)
            return True
        
        pipeline.register_handler("test", handler)
        
        assert "test" in pipeline._handlers


class TestMetricsExporter:
    """Tests for observability metrics"""
    
    def test_metrics_init(self):
        from agent.v27.observability.metrics import MetricsExporter
        
        metrics = MetricsExporter()
        assert metrics._initialized is True
    
    def test_inc_threats(self):
        from agent.v27.observability.metrics import get_metrics
        
        metrics = get_metrics()
        metrics.inc_threats(severity="critical", source="feed")
        # Should not raise


class TestRuleGeneration:
    """Tests for auto rule generation"""
    
    def test_sigma_generator(self):
        from agent.v27.auto_rules.sigma import SigmaRuleGenerator
        
        gen = SigmaRuleGenerator()
        
        threat_data = {
            "title": "Test Threat",
            "description": "Malicious activity from 192.168.1.100 and evil.com",
            "severity": "high",
            "mitre_techniques": ["T1566"],
        }
        
        rule = gen.generate(threat_data)
        
        assert rule is not None
        assert "logsource" in rule.content
        assert "detection" in rule.content
    
    def test_yara_generator(self):
        from agent.v27.auto_rules.yara import YaraRuleGenerator
        
        gen = YaraRuleGenerator()
        
        threat_data = {
            "title": "Malware Sample",
            "description": "Hash: 5d41402abc4b2a76b9719d911017c592 found in evil.exe",
            "severity": "critical",
        }
        
        rule = gen.generate(threat_data)
        
        assert rule is not None
        assert "rule " in rule.content
        assert "strings:" in rule.content
        assert "condition:" in rule.content
    
    def test_kql_generator(self):
        from agent.v27.auto_rules.siem_queries import KQLGenerator
        
        gen = KQLGenerator()
        
        threat_data = {
            "title": "Network IOC",
            "description": "C2 communication to 10.0.0.1 and malware.com",
            "severity": "high",
        }
        
        rule = gen.generate(threat_data)
        
        assert rule is not None
        assert "where" in rule.content or "project" in rule.content


class TestNLPSummarizer:
    """Tests for NLP threat summarization"""
    
    def test_summarize_threat(self):
        from agent.v27.nlp.summarizer import ThreatSummarizer
        
        summarizer = ThreatSummarizer()
        
        summary = summarizer.summarize(
            title="Critical RCE in Apache Log4j",
            content="A critical remote code execution vulnerability (CVE-2021-44228) "
                    "has been discovered in Apache Log4j. APT29 is actively exploiting "
                    "this vulnerability. Windows and Linux systems are affected. "
                    "Patches are available. Organizations should update immediately.",
            severity="critical",
            cvss_score=10.0,
        )
        
        assert summary.executive_summary
        assert len(summary.key_findings) > 0
        assert summary.confidence > 0.5
    
    def test_extract_actors(self):
        from agent.v27.nlp.summarizer import ThreatSummarizer
        
        summarizer = ThreatSummarizer()
        
        actors = summarizer._extract_threat_actors(
            "APT29 and Lazarus Group were observed using this technique"
        )
        
        assert "APT29" in actors or "Lazarus" in actors


class TestTAXIIServer:
    """Tests for TAXII 2.1 server"""
    
    def test_discovery(self):
        from agent.v27.taxii.server import TAXIIServer
        
        server = TAXIIServer()
        discovery = server.get_discovery()
        
        assert "title" in discovery
        assert "api_roots" in discovery
    
    def test_collections(self):
        from agent.v27.taxii.server import TAXIIServer, TAXIICollection
        
        server = TAXIIServer()
        
        # Default collection should exist
        collections = server.get_collections()
        assert len(collections["collections"]) >= 1
        
        # Add custom collection
        server.add_collection(TAXIICollection(
            id="test-collection",
            title="Test Collection",
            can_write=True,
        ))
        
        collections = server.get_collections()
        assert any(c["id"] == "test-collection" for c in collections["collections"])
    
    def test_add_objects(self):
        from agent.v27.taxii.server import TAXIIServer, TAXIICollection
        
        server = TAXIIServer()
        
        # Create writable collection
        server.add_collection(TAXIICollection(
            id="write-test",
            title="Write Test",
            can_write=True,
        ))
        
        # Add STIX object
        status = server.add_objects(
            "write-test",
            [{"type": "indicator", "id": "indicator--test-1"}]
        )
        
        assert status is not None
        assert status.success_count == 1


class TestRBAC:
    """Tests for RBAC engine"""
    
    def test_default_roles(self):
        from agent.v27.rbac.engine import RBACEngine
        
        rbac = RBACEngine()
        
        assert rbac.get_role("admin") is not None
        assert rbac.get_role("analyst") is not None
        assert rbac.get_role("viewer") is not None
    
    def test_user_access(self):
        from agent.v27.rbac.engine import RBACEngine, User
        
        rbac = RBACEngine()
        
        # Add user with viewer role
        user = User(
            user_id="test-user",
            email="test@example.com",
            roles=["viewer"],
        )
        rbac.add_user(user)
        
        # Check allowed access
        decision = rbac.check_access("test-user", "read", "threats")
        assert decision.allowed is True
        
        # Check denied access
        decision = rbac.check_access("test-user", "write", "threats")
        assert decision.allowed is False
    
    def test_admin_access(self):
        from agent.v27.rbac.engine import RBACEngine, User
        
        rbac = RBACEngine()
        
        # Add admin user
        admin = User(
            user_id="admin-user",
            email="admin@example.com",
            roles=["admin"],
        )
        rbac.add_user(admin)
        
        # Admin should have access to everything
        decision = rbac.check_access("admin-user", "delete", "users")
        assert decision.allowed is True
    
    def test_permission_parsing(self):
        from agent.v27.rbac.engine import Permission
        
        perm = Permission.from_string("read:threats")
        assert perm.action == "read"
        assert perm.resource == "threats"
        
        perm_all = Permission.from_string("*")
        assert perm_all.action == "*"
        assert perm_all.resource == "*"


class TestHealthCheck:
    """Tests for health checking"""
    
    @pytest.mark.asyncio
    async def test_health_checker(self):
        from agent.v27.observability.health import HealthChecker, HealthStatus
        
        checker = HealthChecker()
        
        # Register a test check
        async def test_check():
            from agent.v27.observability.health import ComponentHealth
            return ComponentHealth(
                name="test",
                status=HealthStatus.HEALTHY,
                message="OK",
            )
        
        checker.register("test", test_check)
        
        health = await checker.check_all()
        assert health.status in [HealthStatus.HEALTHY, HealthStatus.DEGRADED]
    
    @pytest.mark.asyncio
    async def test_liveness(self):
        from agent.v27.observability.health import HealthChecker
        
        checker = HealthChecker()
        alive = await checker.is_alive()
        assert alive is True


class TestIntegration:
    """Integration tests for v27 features"""
    
    @pytest.mark.asyncio
    async def test_full_pipeline_flow(self):
        """Test complete flow from ingestion to rule generation"""
        from agent.v27.streaming.pipeline import StreamingPipeline, InMemoryQueueBackend
        from agent.v27.auto_rules.generator import RuleGenerator
        from agent.v27.auto_rules.sigma import SigmaRuleGenerator
        from agent.v27.nlp.summarizer import ThreatSummarizer
        
        # Setup
        pipeline = StreamingPipeline(backend=InMemoryQueueBackend())
        rule_gen = RuleGenerator()
        rule_gen.register(SigmaRuleGenerator())
        summarizer = ThreatSummarizer()
        
        # Ingest threat
        event_id = await pipeline.ingest(
            event_type="cve",
            payload={
                "cve_id": "CVE-2026-99999",
                "cvss_score": 9.8,
                "title": "Critical RCE in Example Product",
                "description": "Remote code execution via malicious input to 192.168.1.1",
            },
            source="test",
        )
        
        assert event_id is not None
        
        # Generate rules
        threat_data = {
            "title": "Critical RCE",
            "description": "Attack from 192.168.1.1 targeting example.com",
            "severity": "critical",
        }
        
        rules = rule_gen.generate(threat_data)
        assert len(rules) > 0
        
        # Generate summary
        summary = summarizer.summarize(
            title=threat_data["title"],
            content=threat_data["description"],
            severity=threat_data["severity"],
        )
        
        assert summary.executive_summary


def run_tests():
    """Run all tests"""
    pytest.main([__file__, "-v", "--tb=short"])


if __name__ == "__main__":
    run_tests()
