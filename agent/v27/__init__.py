"""
CYBERDUDEBIVASH® SENTINEL APEX v27.0 — ENTERPRISE UPGRADE
==========================================================
Codename: PHOENIX ENTERPRISE

v27.0 Release Notes:
-------------------
This release addresses enterprise-grade gaps identified in platform review
while preserving 100% backward compatibility with existing v26 modules.

NEW CAPABILITIES:
-----------------
1. STREAMING PIPELINE
   - Redis-backed async event queue
   - Celery workers for parallel processing
   - Real-time threat ingestion vs batch

2. OBSERVABILITY STACK
   - Prometheus metrics exporter
   - Structured logging with correlation IDs
   - Health check endpoints
   - Performance telemetry

3. AUTO RULE GENERATION (AI-Powered)
   - Sigma rule synthesis from threat reports
   - YARA rule generation from IOCs
   - KQL/SPL query generation
   - Detection-as-Code exports

4. NLP THREAT SUMMARIZATION
   - AI-powered executive summaries
   - Key findings extraction
   - Threat actor profiling
   - Technical impact analysis

5. TAXII 2.1 SERVER
   - Full TAXII 2.1 compliance
   - Collection management
   - Two-way sharing
   - Trust group support

6. ENHANCED RBAC
   - Role-based access control
   - Fine-grained permissions
   - Audit trail integration
   - SSO readiness

PRESERVED FROM v26:
------------------
- Temporal decay engine
- IOC correlation engine
- All existing scoring/enrichment

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

__version__ = "27.0.0"
__codename__ = "Phoenix Enterprise"
__author__ = "CyberDudeBivash Pvt. Ltd."
__release_date__ = "2026-03"

# Feature flags
FEATURES = {
    "streaming_pipeline": True,
    "observability": True,
    "auto_rules": True,
    "nlp_summarization": True,
    "taxii_server": True,
    "enhanced_rbac": True,
    # Inherited from v26
    "temporal_decay": True,
    "ioc_correlation": True,
    "cyber_risk_credit": True,
    "ctem_engine": True,
}

# Lazy imports
def get_streaming_pipeline():
    from .streaming.pipeline import get_pipeline
    return get_pipeline()

def get_metrics_exporter():
    from .observability.metrics import get_metrics
    return get_metrics()

def get_rule_generator():
    from .auto_rules.generator import get_rule_generator
    return get_rule_generator()

def get_nlp_engine():
    from .nlp.summarizer import get_summarizer
    return get_summarizer()

def get_taxii_server():
    from .taxii.server import get_taxii_server
    return get_taxii_server()

def get_rbac_engine():
    from .rbac.engine import get_rbac
    return get_rbac()

# Direct exports
from .config_v27 import V27Config, config

__all__ = [
    "__version__",
    "__codename__",
    "FEATURES",
    "V27Config",
    "config",
    "get_streaming_pipeline",
    "get_metrics_exporter",
    "get_rule_generator",
    "get_nlp_engine",
    "get_taxii_server",
    "get_rbac_engine",
]
