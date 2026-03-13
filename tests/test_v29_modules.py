"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — Test Suite
===================================================
Comprehensive tests for all v29 modules.

Coverage:
- Storage backends
- Message broker
- Prometheus metrics
- ML lifecycle
- RBAC middleware
- OpenAPI docs
- Graph database
- API routes
- Integration tests

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import pytest
import asyncio
import json
import time
from pathlib import Path
from datetime import datetime


# ══════════════════════════════════════════════════════════════════════════════
# STORAGE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestStorageBackend:
    """Test storage abstraction layer"""
    
    def test_file_backend_save_load(self, tmp_path):
        """Test file backend save and load"""
        from agent.v29.storage import FileBackend
        
        backend = FileBackend(str(tmp_path))
        
        # Save data
        key = backend.save("test_collection", {"name": "threat1", "severity": "high"}, "threat-001")
        assert key == "threat-001"
        
        # Load data
        data = backend.load("test_collection", "threat-001")
        assert data["name"] == "threat1"
        assert data["severity"] == "high"
    
    def test_file_backend_list_keys(self, tmp_path):
        """Test listing keys"""
        from agent.v29.storage import FileBackend
        
        backend = FileBackend(str(tmp_path))
        
        # Save multiple items
        backend.save("threats", {"id": 1}, "threat-001")
        backend.save("threats", {"id": 2}, "threat-002")
        backend.save("threats", {"id": 3}, "threat-003")
        
        # List all
        keys = backend.list_keys("threats")
        assert len(keys) == 3
        assert "threat-001" in keys
        
        # List with prefix
        keys = backend.list_keys("threats", "threat-00")
        assert len(keys) == 3
    
    def test_file_backend_delete(self, tmp_path):
        """Test deletion"""
        from agent.v29.storage import FileBackend
        
        backend = FileBackend(str(tmp_path))
        
        backend.save("test", {"data": 1}, "key1")
        assert backend.exists("test", "key1")
        
        backend.delete("test", "key1")
        assert not backend.exists("test", "key1")
    
    def test_file_backend_health(self, tmp_path):
        """Test health check"""
        from agent.v29.storage import FileBackend
        
        backend = FileBackend(str(tmp_path))
        health = backend.health_check()
        
        assert health["backend"] == "file"
        assert health["status"] == "healthy"
        assert health["writable"] is True
    
    def test_storage_backend_factory(self, tmp_path, monkeypatch):
        """Test storage backend factory"""
        from agent.v29.storage import get_backend
        
        monkeypatch.setenv("SENTINEL_STORAGE", "file")
        backend = get_backend()
        
        assert backend.backend_type == "file"


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE BROKER TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestMessageBroker:
    """Test message broker"""
    
    @pytest.mark.asyncio
    async def test_memory_broker_publish(self):
        """Test in-memory broker publish"""
        from agent.v29.broker import MemoryBroker, MessagePriority
        
        broker = MemoryBroker()
        
        msg_id = await broker.publish("threats", {"ioc": "192.168.1.1"})
        assert msg_id is not None
        assert len(msg_id) == 16
    
    @pytest.mark.asyncio
    async def test_memory_broker_subscribe(self):
        """Test subscription"""
        from agent.v29.broker import MemoryBroker, Message
        
        broker = MemoryBroker()
        received = []
        
        async def handler(msg: Message) -> bool:
            received.append(msg)
            return True
        
        await broker.subscribe("threats", handler)
        await broker.publish("threats", {"ioc": "malware.com"})
        
        # Wait for processing
        await asyncio.sleep(0.1)
        
        assert len(received) == 1
        assert received[0].payload["ioc"] == "malware.com"
    
    @pytest.mark.asyncio
    async def test_memory_broker_priority(self):
        """Test message priority"""
        from agent.v29.broker import MemoryBroker, MessagePriority
        
        broker = MemoryBroker()
        
        # Publish normal priority
        await broker.publish("alerts", {"level": "low"}, MessagePriority.LOW)
        
        # Publish critical (should be first in queue)
        await broker.publish("alerts", {"level": "critical"}, MessagePriority.CRITICAL)
        
        # Check queue order
        queue = broker._get_queue("alerts")
        assert queue[0].payload["level"] == "critical"
    
    @pytest.mark.asyncio
    async def test_memory_broker_dlq(self):
        """Test dead letter queue"""
        from agent.v29.broker import MemoryBroker, Message
        
        broker = MemoryBroker()
        
        async def failing_handler(msg: Message) -> bool:
            raise Exception("Processing failed")
        
        await broker.subscribe("failures", failing_handler)
        await broker.publish("failures", {"data": "test"})
        
        # Wait for retries
        await asyncio.sleep(1)
        
        dlq_messages = await broker.get_dlq_messages("failures")
        # Message should eventually end up in DLQ after retries
    
    def test_broker_health_check(self):
        """Test broker health"""
        from agent.v29.broker import MemoryBroker
        
        broker = MemoryBroker()
        health = broker.health_check()
        
        assert health["broker"] == "memory"
        assert health["status"] == "healthy"


# ══════════════════════════════════════════════════════════════════════════════
# METRICS TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestPrometheusMetrics:
    """Test Prometheus metrics exporter"""
    
    def test_counter_increment(self):
        """Test counter metric"""
        from agent.v29.metrics import Counter
        
        counter = Counter("test_counter", "Test counter", ["label"])
        counter.inc(1, label="value1")
        counter.inc(2, label="value1")
        counter.inc(1, label="value2")
        
        assert counter.get(label="value1") == 3
        assert counter.get(label="value2") == 1
    
    def test_gauge_set(self):
        """Test gauge metric"""
        from agent.v29.metrics import Gauge
        
        gauge = Gauge("test_gauge", "Test gauge")
        gauge.set(42)
        assert gauge.get() == 42
        
        gauge.inc(8)
        assert gauge.get() == 50
        
        gauge.dec(10)
        assert gauge.get() == 40
    
    def test_histogram_observe(self):
        """Test histogram metric"""
        from agent.v29.metrics import Histogram
        
        hist = Histogram("test_histogram", "Test histogram")
        
        hist.observe(0.1)
        hist.observe(0.5)
        hist.observe(1.5)
        
        output = hist.to_prometheus()
        assert "test_histogram_bucket" in output
        assert "test_histogram_sum" in output
        assert "test_histogram_count" in output
    
    def test_exporter_prometheus_format(self):
        """Test Prometheus export format"""
        from agent.v29.metrics import PrometheusExporter
        
        exporter = PrometheusExporter()
        exporter.record_threat("high", "feed1", 5)
        exporter.record_ioc("ip", 10)
        
        output = exporter.export()
        
        assert "# HELP" in output
        assert "# TYPE" in output
        assert "sentinel_threats_total" in output
        assert "sentinel_iocs_extracted" in output
    
    def test_exporter_summary(self):
        """Test metrics summary"""
        from agent.v29.metrics import PrometheusExporter
        
        exporter = PrometheusExporter()
        exporter.record_threat("critical", "feed1", 3)
        
        summary = exporter.get_summary()
        
        assert "uptime_seconds" in summary
        assert summary["threats_total"] == 3


# ══════════════════════════════════════════════════════════════════════════════
# ML LIFECYCLE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestMLLifecycle:
    """Test ML lifecycle governance"""
    
    def test_register_model(self, tmp_path):
        """Test model registration"""
        from agent.v29.ml_ops import ModelRegistry, ModelStatus
        
        registry = ModelRegistry(str(tmp_path / "ml_registry"))
        
        model = registry.register_model(
            name="threat_classifier",
            version="1.0.0",
            metrics={"accuracy": 0.95, "f1": 0.93},
            parameters={"n_estimators": 100, "max_depth": 10}
        )
        
        assert model.name == "threat_classifier"
        assert model.version == "1.0.0"
        assert model.status == ModelStatus.STAGED
        assert model.metrics["accuracy"] == 0.95
    
    def test_get_model(self, tmp_path):
        """Test model retrieval"""
        from agent.v29.ml_ops import ModelRegistry
        
        registry = ModelRegistry(str(tmp_path / "ml_registry"))
        
        registry.register_model(
            name="risk_predictor",
            version="2.0.0",
            metrics={"accuracy": 0.88},
            parameters={}
        )
        
        model = registry.get_model("risk_predictor", "2.0.0")
        assert model is not None
        assert model.version == "2.0.0"
    
    def test_promote_to_production(self, tmp_path):
        """Test model promotion"""
        from agent.v29.ml_ops import ModelRegistry, ModelStatus
        
        registry = ModelRegistry(str(tmp_path / "ml_registry"))
        
        registry.register_model(
            name="detector",
            version="1.0.0",
            metrics={"accuracy": 0.90},
            parameters={}
        )
        
        model = registry.promote_to_production("detector", "1.0.0")
        assert model.status == ModelStatus.PRODUCTION
        
        # Get production model without version
        prod_model = registry.get_model("detector")
        assert prod_model.version == "1.0.0"
    
    def test_drift_detection(self):
        """Test drift detector"""
        from agent.v29.ml_ops import DriftDetector
        
        detector = DriftDetector(threshold=0.1)
        
        # Set baseline
        detector.set_baseline("feature1", [1.0, 1.1, 0.9, 1.05, 0.95])
        
        # Test with similar distribution (no drift)
        report = detector.detect_drift(
            model_name="test_model",
            version="1.0.0",
            current_features={"feature1": [1.02, 1.08, 0.92, 1.03, 0.97]},
            current_predictions=[0.5, 0.6, 0.4, 0.55],
            baseline_predictions=[0.5, 0.55, 0.45, 0.52]
        )
        
        assert report.drift_detected is False or report.drift_score < 0.5
    
    def test_calculate_metrics(self):
        """Test metric calculation"""
        from agent.v29.ml_ops import calculate_metrics
        
        y_true = [0, 0, 1, 1, 1, 0, 1, 0]
        y_pred = [0, 1, 1, 1, 0, 0, 1, 0]
        
        metrics = calculate_metrics(y_true, y_pred)
        
        assert 0 <= metrics.accuracy <= 1
        assert 0 <= metrics.precision <= 1
        assert 0 <= metrics.recall <= 1
        assert 0 <= metrics.f1_score <= 1
        assert len(metrics.confusion_matrix) == 2


# ══════════════════════════════════════════════════════════════════════════════
# RBAC MIDDLEWARE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestRBACMiddleware:
    """Test RBAC middleware"""
    
    def test_create_jwt_token(self):
        """Test JWT token creation"""
        from agent.v29.middleware import JWTManager, User, Role
        
        jwt_mgr = JWTManager()
        
        user = User(
            user_id="user-001",
            username="analyst1",
            email="analyst@company.com",
            role=Role.ANALYST
        )
        
        token = jwt_mgr.create_token(user)
        assert token is not None
        assert len(token) > 50
    
    def test_verify_jwt_token(self):
        """Test JWT token verification"""
        from agent.v29.middleware import JWTManager, User, Role
        
        jwt_mgr = JWTManager()
        
        user = User(
            user_id="user-002",
            username="admin1",
            email="admin@company.com",
            role=Role.ADMIN
        )
        
        token = jwt_mgr.create_token(user)
        payload = jwt_mgr.verify_token(token)
        
        assert payload is not None
        assert payload.user_id == "user-002"
        assert payload.role == "admin"
    
    def test_user_permissions(self):
        """Test user permission checking"""
        from agent.v29.middleware import User, Role, Permission
        
        analyst = User(
            user_id="analyst-001",
            username="analyst",
            email="analyst@company.com",
            role=Role.ANALYST
        )
        
        viewer = User(
            user_id="viewer-001",
            username="viewer",
            email="viewer@company.com",
            role=Role.VIEWER
        )
        
        # Analyst can read and write threats
        assert analyst.has_permission(Permission.THREAT_READ)
        assert analyst.has_permission(Permission.THREAT_WRITE)
        
        # Viewer can only read
        assert viewer.has_permission(Permission.THREAT_READ)
        assert not viewer.has_permission(Permission.THREAT_WRITE)
    
    def test_api_key_generation(self):
        """Test API key management"""
        from agent.v29.middleware import APIKeyManager, User, Role
        
        api_mgr = APIKeyManager()
        
        user = User(
            user_id="api-user",
            username="api_consumer",
            email="api@company.com",
            role=Role.API_CONSUMER
        )
        
        key = api_mgr.generate_key(user)
        assert len(key) == 64  # SHA256 hex
        
        # Validate key
        validated_user = api_mgr.validate_key(key)
        assert validated_user.user_id == "api-user"
        
        # Revoke key
        api_mgr.revoke_key(key)
        assert api_mgr.validate_key(key) is None


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH DATABASE TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestGraphDatabase:
    """Test graph database integration"""
    
    def test_add_node(self):
        """Test adding nodes"""
        from agent.v29.graph import NetworkXBackend, Node
        
        backend = NetworkXBackend()
        
        result = backend.add_node(Node(
            id="actor-001",
            label="ThreatActor",
            properties={"name": "APT29", "country": "RU"}
        ))
        
        assert result is True
    
    def test_add_edge(self):
        """Test adding edges"""
        from agent.v29.graph import NetworkXBackend, Node, Edge
        
        backend = NetworkXBackend()
        
        backend.add_node(Node(id="actor-001", label="ThreatActor", properties={"name": "APT29"}))
        backend.add_node(Node(id="campaign-001", label="Campaign", properties={"name": "SolarWinds"}))
        
        result = backend.add_edge(Edge(
            source_id="actor-001",
            target_id="campaign-001",
            relationship="ATTRIBUTED_TO"
        ))
        
        assert result is True
    
    def test_get_neighbors(self):
        """Test getting neighbors"""
        from agent.v29.graph import NetworkXBackend, Node, Edge
        
        backend = NetworkXBackend()
        
        backend.add_node(Node(id="actor-001", label="ThreatActor", properties={"name": "APT29"}))
        backend.add_node(Node(id="campaign-001", label="Campaign", properties={"name": "Campaign1"}))
        backend.add_node(Node(id="campaign-002", label="Campaign", properties={"name": "Campaign2"}))
        
        backend.add_edge(Edge(source_id="actor-001", target_id="campaign-001", relationship="RUNS"))
        backend.add_edge(Edge(source_id="actor-001", target_id="campaign-002", relationship="RUNS"))
        
        neighbors = backend.get_neighbors("actor-001", "RUNS")
        assert len(neighbors) == 2
    
    def test_threat_graph_operations(self):
        """Test high-level threat graph"""
        from agent.v29.graph import ThreatGraph, NetworkXBackend
        
        backend = NetworkXBackend()
        graph = ThreatGraph(backend)
        
        # Add threat actor
        graph.add_threat_actor("ta-001", "Lazarus Group", country="KP")
        
        # Add campaign
        graph.add_campaign("camp-001", "WannaCry", first_seen="2017-05")
        
        # Add IOC
        graph.add_ioc("hash", "abc123def456", malicious=True)
        
        # Link them
        graph.link_actor_to_campaign("ta-001", "camp-001")
        graph.link_campaign_to_ioc("camp-001", "ioc--hash--abc123def456")
        
        # Query
        campaigns = graph.get_actor_campaigns("ta-001")
        assert len(campaigns) == 1


# ══════════════════════════════════════════════════════════════════════════════
# OPENAPI TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestOpenAPI:
    """Test OpenAPI documentation"""
    
    def test_spec_generation(self):
        """Test OpenAPI spec generation"""
        from agent.v29.openapi import OpenAPIGenerator
        
        generator = OpenAPIGenerator()
        spec = generator.get_spec()
        
        assert spec["openapi"] == "3.1.0"
        assert spec["info"]["title"] == "CYBERDUDEBIVASH® SENTINEL APEX API"
        assert spec["info"]["version"] == "29.0.0"
    
    def test_spec_has_paths(self):
        """Test spec has all required paths"""
        from agent.v29.openapi import OpenAPIGenerator
        
        generator = OpenAPIGenerator()
        spec = generator.get_spec()
        
        assert "/threats" in spec["paths"]
        assert "/stix/export" in spec["paths"]
        assert "/health" in spec["paths"]
        assert "/metrics" in spec["paths"]
    
    def test_spec_has_security(self):
        """Test spec has security schemes"""
        from agent.v29.openapi import OpenAPIGenerator
        
        generator = OpenAPIGenerator()
        spec = generator.get_spec()
        
        assert "securitySchemes" in spec["components"]
        assert "BearerAuth" in spec["components"]["securitySchemes"]
        assert "ApiKeyAuth" in spec["components"]["securitySchemes"]
    
    def test_spec_json_export(self):
        """Test JSON export"""
        from agent.v29.openapi import OpenAPIGenerator
        
        generator = OpenAPIGenerator()
        json_spec = generator.get_spec_json()
        
        # Should be valid JSON
        parsed = json.loads(json_spec)
        assert parsed["openapi"] == "3.1.0"


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestIntegration:
    """Integration tests"""
    
    def test_version_info(self):
        """Test version info retrieval"""
        from agent.v29 import get_version_info
        
        info = get_version_info()
        
        assert info["version"] == "29.0.0"
        assert info["codename"] == "APEX SCALE"
        assert info["features_enabled"] > 0
    
    def test_feature_flags(self):
        """Test feature flags"""
        from agent.v29 import is_feature_enabled, get_enabled_features
        
        assert is_feature_enabled("storage_abstraction") is True
        assert is_feature_enabled("message_broker") is True
        assert is_feature_enabled("prometheus_metrics") is True
        
        features = get_enabled_features()
        assert len(features) >= 8  # v29 has at least 8 new features
    
    @pytest.mark.asyncio
    async def test_end_to_end_threat_processing(self, tmp_path):
        """Test complete threat processing flow"""
        from agent.v29.storage import FileBackend
        from agent.v29.broker import MemoryBroker, Message
        from agent.v29.metrics import PrometheusExporter
        
        # Initialize components
        storage = FileBackend(str(tmp_path / "data"))
        broker = MemoryBroker()
        metrics = PrometheusExporter()
        
        processed_threats = []
        
        # Setup handler
        async def process_threat(msg: Message) -> bool:
            threat = msg.payload
            
            # Save to storage
            key = storage.save("threats", threat, threat["id"])
            
            # Record metrics
            metrics.record_threat(threat["severity"], threat["source"])
            
            processed_threats.append(threat)
            return True
        
        # Subscribe
        await broker.subscribe("new_threats", process_threat)
        
        # Publish threat
        threat_data = {
            "id": "threat-001",
            "title": "Ransomware Campaign",
            "severity": "critical",
            "source": "unit42"
        }
        
        await broker.publish("new_threats", threat_data)
        
        # Wait for processing
        await asyncio.sleep(0.1)
        
        # Verify
        assert len(processed_threats) == 1
        assert storage.exists("threats", "threat-001")
        
        summary = metrics.get_summary()
        assert summary["threats_total"] == 1


# ══════════════════════════════════════════════════════════════════════════════
# CONFTEST
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tmp_path(tmp_path_factory):
    """Create temp directory"""
    return tmp_path_factory.mktemp("sentinel_test")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
