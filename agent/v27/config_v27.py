"""
CYBERDUDEBIVASH® SENTINEL APEX v27.0 Configuration
====================================================
Enterprise-grade configuration with streaming, observability, and AI features.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import os


class DeploymentMode(Enum):
    """Deployment modes for v27"""
    STANDALONE = "standalone"      # Single instance
    DISTRIBUTED = "distributed"    # Multi-worker
    ENTERPRISE = "enterprise"      # Full HA cluster


class StreamingBackend(Enum):
    """Supported streaming backends"""
    REDIS = "redis"
    RABBITMQ = "rabbitmq"
    MEMORY = "memory"  # For testing


@dataclass
class V27Config:
    """
    SENTINEL APEX v27.0 Configuration
    
    Enterprise settings with streaming, observability, and AI capabilities.
    """
    
    # ══════════════════════════════════════════════════════════════════════════
    # PLATFORM METADATA
    # ══════════════════════════════════════════════════════════════════════════
    VERSION: str = "27.0.0"
    CODENAME: str = "Phoenix Enterprise"
    PLATFORM_NAME: str = "CYBERDUDEBIVASH® SENTINEL APEX"
    DEPLOYMENT_MODE: DeploymentMode = DeploymentMode.STANDALONE
    
    # ══════════════════════════════════════════════════════════════════════════
    # STREAMING PIPELINE CONFIGURATION
    # ══════════════════════════════════════════════════════════════════════════
    STREAMING_ENABLED: bool = True
    STREAMING_BACKEND: StreamingBackend = StreamingBackend.REDIS
    
    # Redis configuration
    REDIS_URL: str = field(default_factory=lambda: os.environ.get(
        "REDIS_URL", "redis://localhost:6379/0"
    ))
    REDIS_MAX_CONNECTIONS: int = 20
    
    # Queue configuration
    QUEUE_HIGH_PRIORITY: str = "sentinel:queue:high"
    QUEUE_NORMAL: str = "sentinel:queue:normal"
    QUEUE_LOW_PRIORITY: str = "sentinel:queue:low"
    QUEUE_MAX_SIZE: int = 10000
    
    # Worker configuration
    WORKER_CONCURRENCY: int = 4
    WORKER_PREFETCH: int = 2
    TASK_TIMEOUT_SECONDS: int = 300
    
    # ══════════════════════════════════════════════════════════════════════════
    # OBSERVABILITY CONFIGURATION
    # ══════════════════════════════════════════════════════════════════════════
    OBSERVABILITY_ENABLED: bool = True
    METRICS_PORT: int = 9090
    METRICS_PATH: str = "/metrics"
    
    # Metric prefixes
    METRICS_PREFIX: str = "cdb_sentinel"
    
    # Logging
    LOG_FORMAT: str = "json"  # json or text
    LOG_LEVEL: str = "INFO"
    LOG_CORRELATION_ENABLED: bool = True
    
    # Health checks
    HEALTH_CHECK_INTERVAL: int = 30
    HEALTH_CHECK_TIMEOUT: int = 10
    
    # ══════════════════════════════════════════════════════════════════════════
    # AUTO RULE GENERATION
    # ══════════════════════════════════════════════════════════════════════════
    AUTO_RULES_ENABLED: bool = True
    
    # Rule types
    RULE_TYPES: List[str] = field(default_factory=lambda: [
        "sigma", "yara", "kql", "spl", "eql"
    ])
    
    # Generation settings
    RULE_CONFIDENCE_THRESHOLD: float = 0.7
    RULE_MAX_CONDITIONS: int = 10
    RULE_INCLUDE_METADATA: bool = True
    
    # ══════════════════════════════════════════════════════════════════════════
    # NLP SUMMARIZATION
    # ══════════════════════════════════════════════════════════════════════════
    NLP_ENABLED: bool = True
    NLP_MODEL: str = "local"  # local, openai, anthropic
    NLP_MAX_SUMMARY_LENGTH: int = 500
    NLP_EXTRACT_ENTITIES: bool = True
    NLP_SENTIMENT_ANALYSIS: bool = True
    
    # ══════════════════════════════════════════════════════════════════════════
    # TAXII 2.1 SERVER
    # ══════════════════════════════════════════════════════════════════════════
    TAXII_ENABLED: bool = True
    TAXII_PORT: int = 443
    TAXII_DISCOVERY_PATH: str = "/taxii2/"
    TAXII_API_ROOT: str = "/api/v21/"
    
    # Collections
    TAXII_DEFAULT_COLLECTION: str = "cdb-threat-intel"
    TAXII_MAX_CONTENT_LENGTH: int = 10485760  # 10MB
    
    # Trust groups
    TAXII_TRUST_GROUPS: List[str] = field(default_factory=lambda: [
        "internal", "partners", "isac"
    ])
    
    # ══════════════════════════════════════════════════════════════════════════
    # ENHANCED RBAC
    # ══════════════════════════════════════════════════════════════════════════
    RBAC_ENABLED: bool = True
    
    # Default roles
    ROLES: Dict[str, List[str]] = field(default_factory=lambda: {
        "admin": ["*"],  # Full access
        "analyst": [
            "read:threats", "read:iocs", "read:reports",
            "write:watchlist", "export:stix", "export:csv"
        ],
        "viewer": ["read:threats", "read:reports"],
        "api_consumer": ["read:api", "export:json"],
        "enterprise": [
            "*:threats", "*:iocs", "*:reports", "*:rules",
            "admin:api_keys", "export:*"
        ],
    })
    
    # Session settings
    SESSION_TIMEOUT_MINUTES: int = 480  # 8 hours
    MAX_SESSIONS_PER_USER: int = 5
    
    # ══════════════════════════════════════════════════════════════════════════
    # INHERITED FROM v26
    # ══════════════════════════════════════════════════════════════════════════
    # Sync settings
    SYNC_INTERVAL_HOURS: int = 4
    SYNC_TIMEOUT_SECONDS: int = 300
    
    # Scoring thresholds
    CRITICAL_THRESHOLD: float = 9.0
    HIGH_THRESHOLD: float = 7.0
    MEDIUM_THRESHOLD: float = 4.0
    
    # API settings
    RATE_LIMIT_FREE: int = 100
    RATE_LIMIT_PRO: int = 1000
    RATE_LIMIT_ENTERPRISE: int = 10000
    
    def __post_init__(self):
        """Load environment overrides"""
        self._load_env_overrides()
    
    def _load_env_overrides(self):
        """Override config from environment variables"""
        env_mappings = {
            "SENTINEL_VERSION": "VERSION",
            "SENTINEL_REDIS_URL": "REDIS_URL",
            "SENTINEL_METRICS_PORT": ("METRICS_PORT", int),
            "SENTINEL_LOG_LEVEL": "LOG_LEVEL",
            "SENTINEL_WORKER_CONCURRENCY": ("WORKER_CONCURRENCY", int),
        }
        
        for env_key, mapping in env_mappings.items():
            value = os.environ.get(env_key)
            if value:
                if isinstance(mapping, tuple):
                    attr, type_fn = mapping
                    setattr(self, attr, type_fn(value))
                else:
                    setattr(self, mapping, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary"""
        return {
            "version": self.VERSION,
            "codename": self.CODENAME,
            "deployment_mode": self.DEPLOYMENT_MODE.value,
            "streaming": {
                "enabled": self.STREAMING_ENABLED,
                "backend": self.STREAMING_BACKEND.value,
                "worker_concurrency": self.WORKER_CONCURRENCY,
            },
            "observability": {
                "enabled": self.OBSERVABILITY_ENABLED,
                "metrics_port": self.METRICS_PORT,
                "log_format": self.LOG_FORMAT,
            },
            "features": {
                "auto_rules": self.AUTO_RULES_ENABLED,
                "nlp": self.NLP_ENABLED,
                "taxii": self.TAXII_ENABLED,
                "rbac": self.RBAC_ENABLED,
            },
        }


# Global config instance
config = V27Config()

__all__ = ["V27Config", "config", "DeploymentMode", "StreamingBackend"]
