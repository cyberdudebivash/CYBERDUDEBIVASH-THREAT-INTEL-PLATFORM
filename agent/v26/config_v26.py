"""
CYBERDUDEBIVASH® SENTINEL APEX v26.0 Configuration
====================================================
Production-grade configuration for v26.0 with enhanced features.

New in v26.0:
- Fixed GitHub Actions deployment (peaceiris → JamesIves)
- Fixed dashboard timestamp display bug
- Enhanced threat scoring with temporal decay
- Improved IOC correlation engine
- Better error recovery and resilience

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from datetime import datetime, timezone
import os


class ThreatSeverity(Enum):
    """Threat severity levels aligned with CVSS v4.0"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"


class DataSovereignty(Enum):
    """Data sovereignty regions"""
    INDIA = "IN"
    EUROPE = "EU"
    US = "US"
    APAC = "APAC"
    GLOBAL = "GLOBAL"


@dataclass
class V26Config:
    """
    SENTINEL APEX v26.0 Configuration
    
    Production settings with enhanced defaults.
    """
    
    # ══════════════════════════════════════════════════════════════════════════
    # PLATFORM METADATA
    # ══════════════════════════════════════════════════════════════════════════
    VERSION: str = "26.0.0"
    CODENAME: str = "Phoenix"
    PLATFORM_NAME: str = "CYBERDUDEBIVASH® SENTINEL APEX"
    FULL_NAME: str = "CYBERDUDEBIVASH® SENTINEL APEX v26.0 ULTRA"
    
    # ══════════════════════════════════════════════════════════════════════════
    # API & ENDPOINT CONFIGURATION
    # ══════════════════════════════════════════════════════════════════════════
    API_VERSION: str = "v26"
    API_BASE_URL: str = "https://intel.cyberdudebivash.com/api"
    DASHBOARD_URL: str = "https://intel.cyberdudebivash.com"
    STIX_FEED_URL: str = "https://intel.cyberdudebivash.com/data/stix/feed_manifest.json"
    STATUS_ENDPOINT: str = "/data/status/status.json"
    
    # ══════════════════════════════════════════════════════════════════════════
    # RATE LIMITING
    # ══════════════════════════════════════════════════════════════════════════
    RATE_LIMIT_FREE: int = 100       # Requests per hour (free tier)
    RATE_LIMIT_PRO: int = 1000       # Requests per hour (pro tier)
    RATE_LIMIT_ENTERPRISE: int = 10000  # Requests per hour (enterprise)
    RATE_LIMIT_WINDOW_SECONDS: int = 3600
    
    # ══════════════════════════════════════════════════════════════════════════
    # THREAT INTELLIGENCE SETTINGS
    # ══════════════════════════════════════════════════════════════════════════
    MAX_FEED_ENTRIES: int = 500
    STIX_VERSION: str = "2.1"
    DEFAULT_TLP: str = "TLP:AMBER"
    IOC_RETENTION_DAYS: int = 90
    CRITICAL_THRESHOLD: float = 9.0
    HIGH_THRESHOLD: float = 7.0
    MEDIUM_THRESHOLD: float = 4.0
    
    # ══════════════════════════════════════════════════════════════════════════
    # SYNC CONFIGURATION
    # ══════════════════════════════════════════════════════════════════════════
    SYNC_INTERVAL_HOURS: int = 4
    SYNC_TIMEOUT_SECONDS: int = 300
    SYNC_RETRY_ATTEMPTS: int = 5
    SYNC_RETRY_DELAY_SECONDS: int = 15
    
    # ══════════════════════════════════════════════════════════════════════════
    # v26.0 NEW: TEMPORAL DECAY SCORING
    # ══════════════════════════════════════════════════════════════════════════
    TEMPORAL_DECAY_ENABLED: bool = True
    DECAY_HALF_LIFE_DAYS: int = 30
    DECAY_MIN_SCORE_FACTOR: float = 0.3  # Minimum 30% of original score
    
    # ══════════════════════════════════════════════════════════════════════════
    # v26.0 NEW: IOC CORRELATION
    # ══════════════════════════════════════════════════════════════════════════
    CORRELATION_ENABLED: bool = True
    CORRELATION_WINDOW_HOURS: int = 72
    MIN_CORRELATION_CONFIDENCE: float = 0.7
    
    # ══════════════════════════════════════════════════════════════════════════
    # v26.0 NEW: RESILIENCE SETTINGS
    # ══════════════════════════════════════════════════════════════════════════
    CIRCUIT_BREAKER_ENABLED: bool = True
    CIRCUIT_BREAKER_THRESHOLD: int = 5
    CIRCUIT_BREAKER_TIMEOUT_SECONDS: int = 60
    GRACEFUL_DEGRADATION: bool = True
    
    # ══════════════════════════════════════════════════════════════════════════
    # DATA SOVEREIGNTY
    # ══════════════════════════════════════════════════════════════════════════
    DEFAULT_SOVEREIGNTY: DataSovereignty = DataSovereignty.INDIA
    ENFORCE_DATA_RESIDENCY: bool = True
    
    # ══════════════════════════════════════════════════════════════════════════
    # FEATURE FLAGS
    # ══════════════════════════════════════════════════════════════════════════
    FEATURES: Dict[str, bool] = field(default_factory=lambda: {
        "cyber_risk_credit": True,
        "cvss_v4": True,
        "ctem_engine": True,
        "digital_twin": True,
        "temporal_decay": True,
        "ioc_correlation": True,
        "ai_predictions": True,
        "epss_enrichment": True,
        "mitre_mapping": True,
        "premium_reports": True,
        "api_monetization": True,
        "circuit_breaker": True,
    })
    
    def __post_init__(self):
        """Initialize from environment variables if available"""
        self._load_env_overrides()
    
    def _load_env_overrides(self):
        """Load configuration overrides from environment"""
        env_mappings = {
            "SENTINEL_API_BASE_URL": "API_BASE_URL",
            "SENTINEL_RATE_LIMIT_FREE": ("RATE_LIMIT_FREE", int),
            "SENTINEL_RATE_LIMIT_PRO": ("RATE_LIMIT_PRO", int),
            "SENTINEL_MAX_FEED_ENTRIES": ("MAX_FEED_ENTRIES", int),
            "SENTINEL_SYNC_INTERVAL": ("SYNC_INTERVAL_HOURS", int),
        }
        
        for env_key, config_key in env_mappings.items():
            value = os.environ.get(env_key)
            if value:
                if isinstance(config_key, tuple):
                    attr_name, type_fn = config_key
                    setattr(self, attr_name, type_fn(value))
                else:
                    setattr(self, config_key, value)
    
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled"""
        return self.FEATURES.get(feature, False)
    
    def get_severity(self, score: float) -> ThreatSeverity:
        """Get threat severity from CVSS score"""
        if score >= self.CRITICAL_THRESHOLD:
            return ThreatSeverity.CRITICAL
        elif score >= self.HIGH_THRESHOLD:
            return ThreatSeverity.HIGH
        elif score >= self.MEDIUM_THRESHOLD:
            return ThreatSeverity.MEDIUM
        elif score > 0:
            return ThreatSeverity.LOW
        return ThreatSeverity.NONE
    
    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary"""
        return {
            "version": self.VERSION,
            "codename": self.CODENAME,
            "platform": self.PLATFORM_NAME,
            "api_version": self.API_VERSION,
            "features": self.FEATURES,
            "thresholds": {
                "critical": self.CRITICAL_THRESHOLD,
                "high": self.HIGH_THRESHOLD,
                "medium": self.MEDIUM_THRESHOLD,
            },
            "sync": {
                "interval_hours": self.SYNC_INTERVAL_HOURS,
                "timeout_seconds": self.SYNC_TIMEOUT_SECONDS,
                "retry_attempts": self.SYNC_RETRY_ATTEMPTS,
            },
            "temporal_decay": {
                "enabled": self.TEMPORAL_DECAY_ENABLED,
                "half_life_days": self.DECAY_HALF_LIFE_DAYS,
                "min_factor": self.DECAY_MIN_SCORE_FACTOR,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL CONFIG INSTANCE
# ══════════════════════════════════════════════════════════════════════════════
config = V26Config()

# Exports
__all__ = [
    "V26Config",
    "ThreatSeverity",
    "DataSovereignty",
    "config",
]
