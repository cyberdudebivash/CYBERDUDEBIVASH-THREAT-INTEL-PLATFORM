"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — APEX SCALE
===================================================
Enterprise-scale enhancements addressing final gaps to reach 10/10.

v29.0 APEX SCALE Features:
--------------------------
1. Storage Abstraction Layer (DB + Object Storage support)
2. Real Message Broker (Redis/Kafka with DLQ)
3. Prometheus /metrics Endpoint
4. ML Lifecycle Governance (Model Registry + Drift Detection)
5. RBAC Middleware Enforcement
6. OpenAPI Auto-Documentation
7. Graph DB Integration (Neo4j)
8. Kubernetes Deployment Support

All modules are 100% backward compatible with v28.
Feature flags allow selective enablement.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

__version__ = "29.0.0"
__codename__ = "APEX SCALE"

from typing import Dict, Any, Optional
import os

# ══════════════════════════════════════════════════════════════════════════════
# FEATURE FLAGS
# ══════════════════════════════════════════════════════════════════════════════

V29_FEATURES = {
    # v29 new features
    "storage_abstraction": True,      # DB/Object storage support
    "message_broker": True,           # Redis/Kafka broker
    "prometheus_metrics": True,       # /metrics endpoint
    "ml_lifecycle": True,             # Model registry + drift
    "rbac_middleware": True,          # Middleware enforcement
    "openapi_docs": True,             # Auto API docs
    "graph_db": True,                 # Neo4j integration
    "kubernetes_ready": True,         # K8s deployment support
    
    # v28 features
    "security_hardening": True,
    "centralized_version": True,
    
    # v27 features (inherited)
    "streaming": True,
    "observability": True,
    "auto_rules": True,
    "nlp": True,
    "taxii": True,
    "rbac": True,
}

def is_feature_enabled(feature: str) -> bool:
    """Check if a feature is enabled"""
    return V29_FEATURES.get(feature, False)

def get_enabled_features() -> list:
    """Get list of enabled features"""
    return [f for f, enabled in V29_FEATURES.items() if enabled]


# ══════════════════════════════════════════════════════════════════════════════
# LAZY MODULE LOADERS
# ══════════════════════════════════════════════════════════════════════════════

_storage_backend = None
_message_broker = None
_metrics_exporter = None
_ml_registry = None
_rbac_middleware = None
_openapi_generator = None
_graph_client = None


def get_storage_backend():
    """Get storage abstraction layer"""
    global _storage_backend
    if _storage_backend is None and is_feature_enabled("storage_abstraction"):
        from .storage import StorageBackend
        _storage_backend = StorageBackend()
    return _storage_backend


def get_message_broker():
    """Get message broker instance"""
    global _message_broker
    if _message_broker is None and is_feature_enabled("message_broker"):
        from .broker import MessageBroker
        _message_broker = MessageBroker()
    return _message_broker


def get_metrics_exporter():
    """Get Prometheus metrics exporter"""
    global _metrics_exporter
    if _metrics_exporter is None and is_feature_enabled("prometheus_metrics"):
        from .metrics import PrometheusExporter
        _metrics_exporter = PrometheusExporter()
    return _metrics_exporter


def get_ml_registry():
    """Get ML model registry"""
    global _ml_registry
    if _ml_registry is None and is_feature_enabled("ml_lifecycle"):
        from .ml_ops import ModelRegistry
        _ml_registry = ModelRegistry()
    return _ml_registry


def get_rbac_middleware():
    """Get RBAC middleware"""
    global _rbac_middleware
    if _rbac_middleware is None and is_feature_enabled("rbac_middleware"):
        from .middleware import RBACMiddleware
        _rbac_middleware = RBACMiddleware()
    return _rbac_middleware


def get_graph_client():
    """Get graph database client"""
    global _graph_client
    if _graph_client is None and is_feature_enabled("graph_db"):
        from .graph import GraphClient
        _graph_client = GraphClient()
    return _graph_client


# ══════════════════════════════════════════════════════════════════════════════
# VERSION INFO
# ══════════════════════════════════════════════════════════════════════════════

def get_version_info() -> Dict[str, Any]:
    """Get complete v29 version info"""
    return {
        "version": __version__,
        "codename": __codename__,
        "features_enabled": len(get_enabled_features()),
        "features": get_enabled_features(),
        "storage_mode": os.getenv("SENTINEL_STORAGE", "file"),
        "broker_mode": os.getenv("SENTINEL_BROKER", "memory"),
    }


__all__ = [
    "__version__",
    "__codename__",
    "V29_FEATURES",
    "is_feature_enabled",
    "get_enabled_features",
    "get_storage_backend",
    "get_message_broker",
    "get_metrics_exporter",
    "get_ml_registry",
    "get_rbac_middleware",
    "get_graph_client",
    "get_version_info",
]
