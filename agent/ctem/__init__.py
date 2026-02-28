"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
CTEM Package
============

Continuous Threat Exposure Management (Gartner Framework)

Phases:
1. SCOPING - Define attack surface
2. DISCOVERY - Identify exposures
3. PRIORITIZATION - Risk-based ranking
4. VALIDATION - Exploitability testing
5. MOBILIZATION - Remediation workflow

(c) 2026 CyberDudeBivash Pvt. Ltd.
"""

from typing import Dict, Any, List, Optional

# Lazy import
_ctem_engine = None


def get_ctem_engine():
    """Get CTEM Engine instance"""
    global _ctem_engine
    if _ctem_engine is None:
        from .ctem_engine import get_ctem_engine as _get
        _ctem_engine = _get()
    return _ctem_engine


def create_scope(name: str, **kwargs) -> Dict[str, Any]:
    """Create a new CTEM scope"""
    engine = get_ctem_engine()
    scope = engine.create_scope(name, **kwargs)
    return scope.to_dict()


def discover_exposures(
    scope_id: str,
    vulnerabilities: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Run CTEM discovery on vulnerabilities"""
    from .ctem_engine import run_ctem_discovery
    return run_ctem_discovery(scope_id, vulnerabilities)


def get_metrics(scope_id: Optional[str] = None) -> Dict[str, Any]:
    """Get CTEM metrics"""
    engine = get_ctem_engine()
    metrics = engine.calculate_metrics(scope_id)
    return metrics.to_dict()


def get_executive_summary(scope_id: Optional[str] = None) -> Dict[str, Any]:
    """Get executive summary report"""
    engine = get_ctem_engine()
    return engine.generate_executive_summary(scope_id)


# Module exports
CTEM_PHASES = [
    "SCOPING",
    "DISCOVERY", 
    "PRIORITIZATION",
    "VALIDATION",
    "MOBILIZATION",
]

PRIORITY_LEVELS = ["P0", "P1", "P2", "P3", "P4"]

SLA_HOURS = {
    "P0": 24,
    "P1": 72,
    "P2": 168,
    "P3": 720,
    "P4": 2160,
}


__all__ = [
    "get_ctem_engine",
    "create_scope",
    "discover_exposures",
    "get_metrics",
    "get_executive_summary",
    "CTEM_PHASES",
    "PRIORITY_LEVELS",
    "SLA_HOURS",
]
