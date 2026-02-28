"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0 Configuration
===================================================
Enterprise-Grade Configuration Management

Version: v25.0
Codename: SENTINEL APEX ULTRA
Release: 2026-02-28

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from enum import Enum
import os

# =============================================================================
# VERSION METADATA
# =============================================================================

V25_VERSION = "25.0.0"
V25_CODENAME = "SENTINEL APEX ULTRA"
V25_RELEASE_DATE = "2026-02-28"
V25_API_VERSION = "v1"

# =============================================================================
# CYBER-RISK CREDIT SCORE CONFIGURATION
# =============================================================================

@dataclass
class CreditScoreConfig:
    """FICO-like Cyber-Risk Credit Score Configuration"""
    
    # Score Range (FICO-aligned)
    min_score: int = 300
    max_score: int = 850
    
    # Factor Weights (must sum to 1.0)
    weights: Dict[str, float] = field(default_factory=lambda: {
        "exposure_factor": 0.30,      # Current vulnerability exposure
        "velocity_factor": 0.20,      # Rate of vulnerability accumulation
        "impact_factor": 0.25,        # Potential business impact
        "resilience_factor": 0.15,    # Recovery/patch velocity
        "historical_factor": 0.10,    # Historical breach/incident data
    })
    
    # Temporal Decay Settings
    decay_half_life_days: int = 30
    decay_enabled: bool = True
    
    # Credit Tiers
    tiers: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "EXCELLENT": {"min": 750, "max": 850, "color": "#22c55e", "risk": "MINIMAL"},
        "GOOD": {"min": 670, "max": 749, "color": "#84cc16", "risk": "LOW"},
        "FAIR": {"min": 580, "max": 669, "color": "#eab308", "risk": "MODERATE"},
        "POOR": {"min": 450, "max": 579, "color": "#f97316", "risk": "HIGH"},
        "CRITICAL": {"min": 300, "max": 449, "color": "#ef4444", "risk": "CRITICAL"},
    })
    
    # Industry Benchmarks
    industry_benchmarks: Dict[str, int] = field(default_factory=lambda: {
        "technology": 680,
        "financial_services": 720,
        "healthcare": 650,
        "retail": 640,
        "manufacturing": 660,
        "government": 700,
        "education": 620,
        "energy": 690,
        "telecommunications": 675,
        "defense": 730,
    })
    
    # Asset Criticality Multipliers
    criticality_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "crown_jewel": 2.0,
        "critical": 1.5,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.8,
    })
    
    # Data Classification Impact
    data_classification_weights: Dict[str, float] = field(default_factory=lambda: {
        "top_secret": 2.5,
        "secret": 2.0,
        "confidential": 1.5,
        "internal": 1.0,
        "public": 0.5,
    })
    
    # Exposure Zone Multipliers
    exposure_zone_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "internet_facing": 1.8,
        "dmz": 1.4,
        "internal": 1.0,
        "restricted": 0.7,
        "air_gapped": 0.3,
    })


# =============================================================================
# CVSS v4.0 CONFIGURATION
# =============================================================================

@dataclass
class CVSSv4Config:
    """CVSS v4.0 Calculator Configuration"""
    
    # Severity Thresholds (FIRST specification)
    severity_thresholds: Dict[str, Dict[str, float]] = field(default_factory=lambda: {
        "NONE": {"min": 0.0, "max": 0.0},
        "LOW": {"min": 0.1, "max": 3.9},
        "MEDIUM": {"min": 4.0, "max": 6.9},
        "HIGH": {"min": 7.0, "max": 8.9},
        "CRITICAL": {"min": 9.0, "max": 10.0},
    })
    
    # Severity Colors
    severity_colors: Dict[str, str] = field(default_factory=lambda: {
        "NONE": "#6b7280",
        "LOW": "#22c55e",
        "MEDIUM": "#eab308",
        "HIGH": "#f97316",
        "CRITICAL": "#ef4444",
    })
    
    # Auto-conversion from v3.x
    auto_convert_v3: bool = True
    
    # Default Security Requirements (Environmental)
    default_security_requirements: Dict[str, str] = field(default_factory=lambda: {
        "confidentiality_requirement": "H",  # High
        "integrity_requirement": "H",
        "availability_requirement": "H",
    })
    
    # Exploit Maturity Weights
    exploit_maturity_weights: Dict[str, float] = field(default_factory=lambda: {
        "NOT_DEFINED": 1.0,
        "UNREPORTED": 0.91,
        "POC": 0.94,
        "ATTACKED": 1.0,
    })


# =============================================================================
# CTEM (CONTINUOUS THREAT EXPOSURE MANAGEMENT) CONFIGURATION
# =============================================================================

@dataclass
class CTEMConfig:
    """Gartner CTEM Framework Configuration"""
    
    # SLA Hours by Priority
    sla_hours: Dict[str, int] = field(default_factory=lambda: {
        "P0": 24,      # Critical - 24 hours
        "P1": 72,      # High - 3 days
        "P2": 168,     # Medium - 7 days
        "P3": 720,     # Low - 30 days
        "P4": 2160,    # Informational - 90 days
    })
    
    # Priority Calculation Thresholds
    priority_thresholds: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "P0": {"cvss_min": 9.0, "epss_min": 0.7, "kev": True, "label": "CRITICAL"},
        "P1": {"cvss_min": 7.0, "epss_min": 0.4, "kev": False, "label": "HIGH"},
        "P2": {"cvss_min": 4.0, "epss_min": 0.1, "kev": False, "label": "MEDIUM"},
        "P3": {"cvss_min": 0.1, "epss_min": 0.01, "kev": False, "label": "LOW"},
        "P4": {"cvss_min": 0.0, "epss_min": 0.0, "kev": False, "label": "INFO"},
    })
    
    # Compliance Scope Multipliers
    compliance_weights: Dict[str, float] = field(default_factory=lambda: {
        "PCI_DSS": 1.4,
        "HIPAA": 1.4,
        "SOX": 1.3,
        "GDPR": 1.2,
        "SOC2": 1.1,
        "ISO27001": 1.1,
        "NIST_CSF": 1.0,
        "CIS": 1.0,
        "NONE": 0.8,
    })
    
    # Escalation Thresholds (% of SLA consumed)
    escalation_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "warning": 0.5,      # 50% - Warning
        "escalation_1": 0.75, # 75% - First escalation
        "escalation_2": 1.0,  # 100% - Second escalation
        "critical": 1.5,      # 150% - Critical breach
    })
    
    # CTEM Phase Configuration
    phases: List[str] = field(default_factory=lambda: [
        "SCOPING",
        "DISCOVERY",
        "PRIORITIZATION",
        "VALIDATION",
        "MOBILIZATION",
    ])
    
    # Metrics Retention Days
    metrics_retention_days: int = 90
    
    # Auto-Discovery Settings
    auto_discovery_interval_hours: int = 4
    discovery_depth: str = "comprehensive"  # basic, standard, comprehensive


# =============================================================================
# DIGITAL TWIN BREACH SIMULATOR CONFIGURATION
# =============================================================================

@dataclass
class DigitalTwinConfig:
    """Digital Twin Breach Simulator Configuration"""
    
    # Default Organization Profile
    default_org_profile: Dict[str, int] = field(default_factory=lambda: {
        "endpoints": 100,
        "servers": 20,
        "web_apps": 5,
        "databases": 3,
        "domain_controllers": 2,
        "cloud_assets": 15,
        "network_devices": 10,
        "iot_devices": 25,
    })
    
    # Simulation Limits
    max_simulation_hours: int = 168  # 7 days
    max_attack_hops: int = 10
    max_monte_carlo_iterations: int = 500
    min_monte_carlo_iterations: int = 10
    
    # Network Zone Difficulty Multipliers
    zone_difficulty: Dict[str, float] = field(default_factory=lambda: {
        "internet": 0.1,
        "dmz": 0.4,
        "internal": 0.7,
        "restricted": 0.9,
        "air_gapped": 0.99,
    })
    
    # Security Control Effectiveness (Detection Probability)
    control_effectiveness: Dict[str, float] = field(default_factory=lambda: {
        "edr": 0.35,
        "mfa": 0.40,
        "pam": 0.35,
        "waf": 0.28,
        "ndr": 0.30,
        "siem": 0.25,
        "dlp": 0.20,
        "casb": 0.22,
        "ztna": 0.38,
        "deception": 0.45,
    })
    
    # MITRE ATT&CK Technique Success Rates (Base)
    technique_success_rates: Dict[str, float] = field(default_factory=lambda: {
        "T1190": 0.75,  # Exploit Public-Facing Application
        "T1566": 0.60,  # Phishing
        "T1078": 0.80,  # Valid Accounts
        "T1059": 0.85,  # Command and Scripting Interpreter
        "T1003": 0.65,  # OS Credential Dumping
        "T1021": 0.75,  # Remote Services
        "T1055": 0.70,  # Process Injection
        "T1036": 0.80,  # Masquerading
        "T1027": 0.75,  # Obfuscated Files or Information
        "T1486": 0.90,  # Data Encrypted for Impact (Ransomware)
        "T1048": 0.70,  # Exfiltration Over Alternative Protocol
        "T1071": 0.75,  # Application Layer Protocol
        "T1082": 0.95,  # System Information Discovery
        "T1083": 0.90,  # File and Directory Discovery
        "T1018": 0.85,  # Remote System Discovery
    })
    
    # Asset Value Multipliers
    asset_value_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "endpoint": 1.0,
        "server": 2.0,
        "domain_controller": 5.0,
        "database": 4.0,
        "web_app": 2.5,
        "cloud_asset": 2.0,
        "network_device": 1.5,
        "iot_device": 0.8,
        "crown_jewel": 10.0,
    })
    
    # Attack Vector Entry Points
    entry_points: List[str] = field(default_factory=lambda: [
        "phishing",
        "web_exploit",
        "supply_chain",
        "insider",
        "physical",
        "cloud_misconfiguration",
        "credential_stuffing",
        "zero_day",
    ])


# =============================================================================
# V25 FEATURE FLAGS
# =============================================================================

@dataclass
class V25Features:
    """v25 Feature Flags"""
    
    # Core Features
    cyber_risk_credit_score: bool = True
    cvss_v4_calculator: bool = True
    ctem_engine: bool = True
    digital_twin_simulator: bool = True
    
    # Premium Features
    monte_carlo_simulation: bool = True
    attack_path_analysis: bool = True
    executive_reporting: bool = True
    compliance_mapping: bool = True
    
    # Experimental Features (Disabled by Default)
    llm_threat_analysis: bool = False
    predictive_breach_modeling: bool = False
    autonomous_remediation: bool = False
    
    # Integration Features
    taxii_2_1_server: bool = True
    misp_bridge: bool = True
    siem_connectors: bool = True
    soar_playbooks: bool = True


# =============================================================================
# V25 API CONFIGURATION
# =============================================================================

@dataclass
class V25ApiConfig:
    """v25 API Configuration"""
    
    # Rate Limits (requests per minute)
    rate_limits: Dict[str, int] = field(default_factory=lambda: {
        "FREE": 30,
        "STANDARD": 100,
        "PREMIUM": 300,
        "PRO": 500,
        "ENTERPRISE": 1000,
    })
    
    # Endpoint Permissions by Tier
    endpoint_permissions: Dict[str, List[str]] = field(default_factory=lambda: {
        "FREE": [
            "credit_score_basic",
            "cvss_calculate",
            "ctem_view",
        ],
        "STANDARD": [
            "credit_score_basic",
            "credit_score_history",
            "cvss_calculate",
            "cvss_batch",
            "ctem_view",
            "ctem_discover",
        ],
        "PREMIUM": [
            "credit_score_full",
            "cvss_all",
            "ctem_full",
            "simulator_basic",
        ],
        "PRO": [
            "credit_score_full",
            "cvss_all",
            "ctem_full",
            "simulator_full",
            "monte_carlo",
        ],
        "ENTERPRISE": [
            "all",
        ],
    })
    
    # Response Caching TTL (seconds)
    cache_ttl: Dict[str, int] = field(default_factory=lambda: {
        "credit_score": 300,       # 5 minutes
        "cvss_calculation": 3600,  # 1 hour
        "ctem_metrics": 60,        # 1 minute
        "simulation": 1800,        # 30 minutes
    })
    
    # API Timeout Settings
    timeout_seconds: int = 30
    long_running_timeout: int = 300  # For Monte Carlo simulations


# =============================================================================
# GLOBAL CONFIGURATION INSTANCES
# =============================================================================

CREDIT_SCORE_CONFIG = CreditScoreConfig()
CVSS_V4_CONFIG = CVSSv4Config()
CTEM_CONFIG = CTEMConfig()
DIGITAL_TWIN_CONFIG = DigitalTwinConfig()
V25_FEATURES = V25Features()
V25_API_CONFIG = V25ApiConfig()


# =============================================================================
# ENVIRONMENT OVERRIDES
# =============================================================================

def load_env_overrides():
    """Load configuration overrides from environment variables"""
    
    # Feature Toggles
    if os.getenv("V25_DISABLE_LLM_ANALYSIS"):
        V25_FEATURES.llm_threat_analysis = False
    
    if os.getenv("V25_ENABLE_PREDICTIVE_BREACH"):
        V25_FEATURES.predictive_breach_modeling = True
    
    if os.getenv("V25_ENABLE_AUTONOMOUS_REMEDIATION"):
        V25_FEATURES.autonomous_remediation = True
    
    # API Overrides
    if os.getenv("V25_API_TIMEOUT"):
        V25_API_CONFIG.timeout_seconds = int(os.getenv("V25_API_TIMEOUT"))
    
    # Simulation Limits
    if os.getenv("V25_MAX_MONTE_CARLO"):
        DIGITAL_TWIN_CONFIG.max_monte_carlo_iterations = int(
            os.getenv("V25_MAX_MONTE_CARLO")
        )


# Load overrides on import
load_env_overrides()


# =============================================================================
# CONFIGURATION EXPORT
# =============================================================================

def get_v25_config_summary() -> Dict[str, Any]:
    """Get complete v25 configuration summary"""
    return {
        "version": V25_VERSION,
        "codename": V25_CODENAME,
        "release_date": V25_RELEASE_DATE,
        "api_version": V25_API_VERSION,
        "features": {
            "core": {
                "cyber_risk_credit_score": V25_FEATURES.cyber_risk_credit_score,
                "cvss_v4_calculator": V25_FEATURES.cvss_v4_calculator,
                "ctem_engine": V25_FEATURES.ctem_engine,
                "digital_twin_simulator": V25_FEATURES.digital_twin_simulator,
            },
            "premium": {
                "monte_carlo_simulation": V25_FEATURES.monte_carlo_simulation,
                "attack_path_analysis": V25_FEATURES.attack_path_analysis,
                "executive_reporting": V25_FEATURES.executive_reporting,
            },
            "experimental": {
                "llm_threat_analysis": V25_FEATURES.llm_threat_analysis,
                "predictive_breach_modeling": V25_FEATURES.predictive_breach_modeling,
            },
        },
        "modules": {
            "credit_score": {
                "score_range": f"{CREDIT_SCORE_CONFIG.min_score}-{CREDIT_SCORE_CONFIG.max_score}",
                "tiers": list(CREDIT_SCORE_CONFIG.tiers.keys()),
                "industries": len(CREDIT_SCORE_CONFIG.industry_benchmarks),
            },
            "ctem": {
                "phases": CTEM_CONFIG.phases,
                "sla_priorities": list(CTEM_CONFIG.sla_hours.keys()),
                "compliance_frameworks": list(CTEM_CONFIG.compliance_weights.keys()),
            },
            "simulator": {
                "max_iterations": DIGITAL_TWIN_CONFIG.max_monte_carlo_iterations,
                "techniques_mapped": len(DIGITAL_TWIN_CONFIG.technique_success_rates),
                "entry_points": len(DIGITAL_TWIN_CONFIG.entry_points),
            },
        },
    }


__all__ = [
    "V25_VERSION",
    "V25_CODENAME",
    "V25_RELEASE_DATE",
    "V25_API_VERSION",
    "CREDIT_SCORE_CONFIG",
    "CVSS_V4_CONFIG",
    "CTEM_CONFIG",
    "DIGITAL_TWIN_CONFIG",
    "V25_FEATURES",
    "V25_API_CONFIG",
    "CreditScoreConfig",
    "CVSSv4Config",
    "CTEMConfig",
    "DigitalTwinConfig",
    "V25Features",
    "V25ApiConfig",
    "get_v25_config_summary",
]
