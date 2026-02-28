"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
Simulator Package
=================

Digital Twin Breach Simulation Engine

Features:
- Attack path analysis
- Monte Carlo simulation
- MITRE ATT&CK technique modeling
- Time-to-compromise estimation
- Business impact assessment

(c) 2026 CyberDudeBivash Pvt. Ltd.
"""

from typing import Dict, Any, List, Optional

# Lazy import
_simulator = None


def get_simulator():
    """Get Digital Twin Simulator instance"""
    global _simulator
    if _simulator is None:
        from .digital_twin import get_digital_twin
        _simulator = get_digital_twin()
    return _simulator


def build_environment(
    endpoints: int = 100,
    servers: int = 20,
    web_apps: int = 5,
    databases: int = 3,
    domain_controllers: int = 2
) -> Dict[str, Any]:
    """Build default enterprise environment"""
    simulator = get_simulator()
    count = simulator.build_default_environment(
        endpoints=endpoints,
        servers=servers,
        web_apps=web_apps,
        databases=databases,
        domain_controllers=domain_controllers,
    )
    return {
        "assets_created": count,
        "summary": simulator.get_attack_surface_summary(),
    }


def run_breach_simulation(
    attack_vector: str = "PHISHING",
    entry_asset: Optional[str] = None
) -> Dict[str, Any]:
    """Run single breach simulation"""
    from .digital_twin import run_breach_simulation as _run
    return _run(attack_vector, entry_asset)


def run_monte_carlo(
    iterations: int = 100,
    attack_vectors: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Run Monte Carlo simulation"""
    from .digital_twin import run_full_simulation
    return run_full_simulation(iterations, attack_vectors)


def find_attack_paths(
    entry_point: str,
    target: str,
    max_paths: int = 5
) -> List[Dict[str, Any]]:
    """Find attack paths between assets"""
    simulator = get_simulator()
    paths = simulator.find_attack_paths(entry_point, target, max_paths)
    return [p.to_dict() for p in paths]


def get_attack_surface() -> Dict[str, Any]:
    """Get attack surface summary"""
    simulator = get_simulator()
    return simulator.get_attack_surface_summary()


# Available attack vectors
ATTACK_VECTORS = [
    "PHISHING",
    "WEB_EXPLOIT",
    "SUPPLY_CHAIN",
    "INSIDER",
    "PHYSICAL",
    "CLOUD_MISCONFIGURATION",
    "CREDENTIAL_STUFFING",
    "ZERO_DAY",
]

# Asset types
ASSET_TYPES = [
    "ENDPOINT",
    "SERVER",
    "DOMAIN_CONTROLLER",
    "DATABASE",
    "WEB_APP",
    "CLOUD_ASSET",
    "NETWORK_DEVICE",
    "IOT_DEVICE",
    "CROWN_JEWEL",
]


__all__ = [
    "get_simulator",
    "build_environment",
    "run_breach_simulation",
    "run_monte_carlo",
    "find_attack_paths",
    "get_attack_surface",
    "ATTACK_VECTORS",
    "ASSET_TYPES",
]
