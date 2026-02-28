"""
CYBERDUDEBIVASH® SENTINEL APEX v26.0 Module
=============================================
New features and fixes for v26.0 release.

v26.0 Release Notes:
-------------------
CRITICAL FIXES:
- Fixed GitHub Actions deployment failure (peaceiris → JamesIves action)
- Fixed dashboard "Last Sync: 3d ago" timestamp bug (line 2285)
- Fixed git context loss in gh-pages deployment

NEW FEATURES:
- Temporal Decay Engine for time-based threat scoring
- IOC Correlation Engine for threat clustering
- Enhanced resilience with circuit breaker pattern
- Improved error recovery and graceful degradation

IMPROVEMENTS:
- 4-hour sync interval (was 6 hours)
- Better pre-flight diagnostics
- Enhanced post-sync verification
- Comprehensive deployment logging

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

__version__ = "26.0.0"
__codename__ = "Phoenix"
__author__ = "CyberDudeBivash Pvt. Ltd."

# Lazy imports to avoid circular dependencies
def get_config():
    from .config_v26 import config
    return config

def get_temporal_decay_engine():
    from .temporal_decay import get_decay_engine
    return get_decay_engine()

def get_ioc_correlation_engine():
    from .ioc_correlation import get_correlation_engine
    return get_correlation_engine()

# Direct exports
from .config_v26 import V26Config, ThreatSeverity, DataSovereignty, config
from .temporal_decay import (
    TemporalDecayEngine,
    TemporalDecayConfig,
    apply_temporal_decay,
)
from .ioc_correlation import (
    IOCCorrelationEngine,
    IOCType,
    IOCMatch,
    CorrelationCluster,
)

__all__ = [
    # Version info
    "__version__",
    "__codename__",
    "__author__",
    
    # Config
    "V26Config",
    "ThreatSeverity",
    "DataSovereignty",
    "config",
    "get_config",
    
    # Temporal Decay
    "TemporalDecayEngine",
    "TemporalDecayConfig",
    "apply_temporal_decay",
    "get_temporal_decay_engine",
    
    # IOC Correlation
    "IOCCorrelationEngine",
    "IOCType",
    "IOCMatch",
    "CorrelationCluster",
    "get_ioc_correlation_engine",
]
