"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
Scoring Package
===============

Advanced Scoring Engines:
- Cyber-Risk Credit Score (FICO-like 300-850)
- CVSS v4.0 Calculator

(c) 2026 CyberDudeBivash Pvt. Ltd.
"""

from typing import Dict, Any, Optional

# Lazy imports for performance
_credit_engine = None
_cvss_calculator = None


def get_credit_engine():
    """Get Cyber-Risk Credit Score Engine"""
    global _credit_engine
    if _credit_engine is None:
        from .cyber_risk_credit import get_credit_engine as _get
        _credit_engine = _get()
    return _credit_engine


def get_cvss_calculator():
    """Get CVSS v4.0 Calculator"""
    global _cvss_calculator
    if _cvss_calculator is None:
        from .cvss_v4 import get_cvss_calculator as _get
        _cvss_calculator = _get()
    return _cvss_calculator


def calculate_credit_score(
    entity_id: str,
    vulnerabilities: list,
    **kwargs
) -> Dict[str, Any]:
    """Calculate cyber-risk credit score"""
    from .cyber_risk_credit import calculate_credit_score as _calc
    return _calc(entity_id, vulnerabilities, **kwargs)


def calculate_cvss_v4(vector: str) -> Dict[str, Any]:
    """Calculate CVSS v4.0 from vector string"""
    from .cvss_v4 import parse_and_calculate
    return parse_and_calculate(vector)


# Module availability check
SCORING_MODULES = {
    "cyber_risk_credit": True,
    "cvss_v4": True,
}


def get_available_modules() -> Dict[str, bool]:
    """Check which scoring modules are available"""
    return SCORING_MODULES.copy()


__all__ = [
    "get_credit_engine",
    "get_cvss_calculator",
    "calculate_credit_score",
    "calculate_cvss_v4",
    "get_available_modules",
    "SCORING_MODULES",
]
