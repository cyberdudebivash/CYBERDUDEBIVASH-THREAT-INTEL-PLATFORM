"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
Digital Twin Breach Simulator
=============================

Graph-based Attack Modeling and Breach Simulation Engine

Features:
- Attack path analysis
- Monte Carlo simulation
- MITRE ATT&CK technique modeling
- Time-to-compromise estimation
- Business impact assessment
- Security control effectiveness testing

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Tuple
from enum import Enum
from datetime import datetime
import random
import math
import uuid
import heapq
from collections import defaultdict

# =============================================================================
# ENUMS
# =============================================================================

class AssetType(Enum):
    """Asset Types in Digital Twin"""
    ENDPOINT = "ENDPOINT"
    SERVER = "SERVER"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    DATABASE = "DATABASE"
    WEB_APP = "WEB_APP"
    CLOUD_ASSET = "CLOUD_ASSET"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    IOT_DEVICE = "IOT_DEVICE"
    CROWN_JEWEL = "CROWN_JEWEL"


class NetworkZone(Enum):
    """Network Security Zones"""
    INTERNET = "INTERNET"
    DMZ = "DMZ"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class AttackVector(Enum):
    """Initial Attack Vectors"""
    PHISHING = "PHISHING"
    WEB_EXPLOIT = "WEB_EXPLOIT"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    INSIDER = "INSIDER"
    PHYSICAL = "PHYSICAL"
    CLOUD_MISCONFIGURATION = "CLOUD_MISCONFIGURATION"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING"
    ZERO_DAY = "ZERO_DAY"


class SimulationMode(Enum):
    """Simulation Modes"""
    SINGLE_PATH = "SINGLE_PATH"
    MULTI_PATH = "MULTI_PATH"
    MONTE_CARLO = "MONTE_CARLO"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class Asset:
    """Digital Twin Asset"""
    asset_id: str
    name: str
    asset_type: AssetType
    zone: NetworkZone
    
    # Risk factors
    vulnerability_score: float = 5.0  # 0-10
    value: float = 1.0  # Business value multiplier
    
    # Security controls
    has_edr: bool = True
    has_mfa: bool = False
    has_pam: bool = False
    patched: bool = True
    
    # Connectivity
    connected_to: List[str] = field(default_factory=list)
    
    # Crown jewel status
    is_crown_jewel: bool = False
    data_sensitivity: str = "internal"  # public, internal, confidential, secret
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "type": self.asset_type.value,
            "zone": self.zone.value,
            "vulnerability_score": self.vulnerability_score,
            "value": self.value,
            "controls": {
                "edr": self.has_edr,
                "mfa": self.has_mfa,
                "pam": self.has_pam,
                "patched": self.patched,
            },
            "connections": len(self.connected_to),
            "is_crown_jewel": self.is_crown_jewel,
            "data_sensitivity": self.data_sensitivity,
        }


@dataclass
class AttackTechnique:
    """MITRE ATT&CK Technique"""
    technique_id: str
    name: str
    tactic: str
    success_rate: float = 0.5
    detection_rate: float = 0.3
    time_hours: float = 1.0
    requires_privilege: str = "none"  # none, user, admin
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "success_rate": self.success_rate,
            "detection_rate": self.detection_rate,
            "time_hours": self.time_hours,
        }


@dataclass
class AttackStep:
    """Single Step in Attack Path"""
    step_number: int
    source_asset: str
    target_asset: str
    technique: AttackTechnique
    success_probability: float
    detection_probability: float
    time_hours: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_number,
            "source": self.source_asset,
            "target": self.target_asset,
            "technique": self.technique.to_dict(),
            "probabilities": {
                "success": round(self.success_probability, 3),
                "detection": round(self.detection_probability, 3),
            },
            "estimated_hours": round(self.time_hours, 1),
        }


@dataclass
class AttackPath:
    """Complete Attack Path"""
    path_id: str
    entry_point: str
    target: str
    steps: List[AttackStep] = field(default_factory=list)
    
    # Calculated metrics
    total_success_probability: float = 0.0
    total_detection_probability: float = 0.0
    total_time_hours: float = 0.0
    business_impact: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.path_id,
            "entry_point": self.entry_point,
            "target": self.target,
            "steps": [s.to_dict() for s in self.steps],
            "metrics": {
                "success_probability": round(self.total_success_probability, 3),
                "detection_probability": round(self.total_detection_probability, 3),
                "time_to_compromise_hours": round(self.total_time_hours, 1),
                "business_impact_score": round(self.business_impact, 2),
            },
            "hop_count": len(self.steps),
        }


@dataclass
class BreachScenario:
    """Breach Scenario Result"""
    scenario_id: str
    attack_vector: AttackVector
    entry_asset: str
    
    # Results
    successful: bool = False
    detected: bool = False
    crown_jewels_reached: List[str] = field(default_factory=list)
    assets_compromised: List[str] = field(default_factory=list)
    
    # Timing
    time_to_initial_access: float = 0.0
    time_to_crown_jewels: float = 0.0
    total_time_hours: float = 0.0
    
    # Impact
    data_exfiltrated: bool = False
    lateral_movement_hops: int = 0
    blast_radius: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "attack_vector": self.attack_vector.value,
            "entry_point": self.entry_asset,
            "outcome": {
                "successful": self.successful,
                "detected": self.detected,
                "detection_before_objective": self.detected and not self.crown_jewels_reached,
            },
            "impact": {
                "crown_jewels_reached": self.crown_jewels_reached,
                "assets_compromised": len(self.assets_compromised),
                "blast_radius": self.blast_radius,
                "data_exfiltrated": self.data_exfiltrated,
            },
            "timing": {
                "initial_access_hours": round(self.time_to_initial_access, 1),
                "time_to_objective_hours": round(self.time_to_crown_jewels, 1),
                "total_hours": round(self.total_time_hours, 1),
            },
            "lateral_movement_hops": self.lateral_movement_hops,
        }


@dataclass
class SimulationResult:
    """Monte Carlo Simulation Results"""
    simulation_id: str
    iterations: int
    
    # Success metrics
    breach_success_rate: float = 0.0
    detection_rate: float = 0.0
    crown_jewel_access_rate: float = 0.0
    
    # Timing distributions
    avg_time_to_compromise: float = 0.0
    min_time_to_compromise: float = 0.0
    max_time_to_compromise: float = 0.0
    p50_time: float = 0.0
    p95_time: float = 0.0
    
    # Impact distributions
    avg_blast_radius: float = 0.0
    max_blast_radius: int = 0
    
    # Risk assessment
    overall_risk_score: float = 0.0
    
    # Individual scenarios
    scenarios: List[BreachScenario] = field(default_factory=list)
    
    # Recommendations
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "iterations": self.iterations,
            "success_metrics": {
                "breach_success_rate": round(self.breach_success_rate * 100, 1),
                "detection_rate": round(self.detection_rate * 100, 1),
                "crown_jewel_access_rate": round(self.crown_jewel_access_rate * 100, 1),
            },
            "timing_distribution": {
                "average_hours": round(self.avg_time_to_compromise, 1),
                "minimum_hours": round(self.min_time_to_compromise, 1),
                "maximum_hours": round(self.max_time_to_compromise, 1),
                "p50_hours": round(self.p50_time, 1),
                "p95_hours": round(self.p95_time, 1),
            },
            "impact_metrics": {
                "average_blast_radius": round(self.avg_blast_radius, 1),
                "maximum_blast_radius": self.max_blast_radius,
            },
            "overall_risk_score": round(self.overall_risk_score, 1),
            "recommendations": self.recommendations,
        }


# =============================================================================
# MITRE ATT&CK TECHNIQUES LIBRARY
# =============================================================================

DEFAULT_TECHNIQUES = {
    "T1190": AttackTechnique("T1190", "Exploit Public-Facing Application", "initial-access", 0.75, 0.25, 0.5),
    "T1566": AttackTechnique("T1566", "Phishing", "initial-access", 0.60, 0.35, 2.0),
    "T1078": AttackTechnique("T1078", "Valid Accounts", "initial-access", 0.80, 0.15, 0.5),
    "T1059": AttackTechnique("T1059", "Command and Scripting Interpreter", "execution", 0.85, 0.40, 0.2),
    "T1003": AttackTechnique("T1003", "OS Credential Dumping", "credential-access", 0.65, 0.45, 0.5, "admin"),
    "T1021": AttackTechnique("T1021", "Remote Services", "lateral-movement", 0.75, 0.30, 0.3),
    "T1055": AttackTechnique("T1055", "Process Injection", "defense-evasion", 0.70, 0.35, 0.3),
    "T1036": AttackTechnique("T1036", "Masquerading", "defense-evasion", 0.80, 0.25, 0.2),
    "T1027": AttackTechnique("T1027", "Obfuscated Files or Information", "defense-evasion", 0.75, 0.20, 0.3),
    "T1486": AttackTechnique("T1486", "Data Encrypted for Impact", "impact", 0.90, 0.50, 0.5, "admin"),
    "T1048": AttackTechnique("T1048", "Exfiltration Over Alternative Protocol", "exfiltration", 0.70, 0.35, 1.0),
    "T1071": AttackTechnique("T1071", "Application Layer Protocol", "command-control", 0.75, 0.30, 0.2),
    "T1082": AttackTechnique("T1082", "System Information Discovery", "discovery", 0.95, 0.10, 0.1),
    "T1083": AttackTechnique("T1083", "File and Directory Discovery", "discovery", 0.90, 0.15, 0.2),
    "T1018": AttackTechnique("T1018", "Remote System Discovery", "discovery", 0.85, 0.20, 0.3),
    "T1087": AttackTechnique("T1087", "Account Discovery", "discovery", 0.88, 0.25, 0.2),
    "T1069": AttackTechnique("T1069", "Permission Groups Discovery", "discovery", 0.85, 0.20, 0.2),
}


# =============================================================================
# DIGITAL TWIN SIMULATOR
# =============================================================================

class DigitalTwinSimulator:
    """
    Digital Twin Breach Simulator
    
    Creates a virtual model of your infrastructure and simulates
    attack scenarios using graph-based pathfinding and Monte Carlo methods.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        
        # Assets (nodes)
        self._assets: Dict[str, Asset] = {}
        
        # Connections (edges)
        self._connections: Dict[str, Set[str]] = defaultdict(set)
        
        # Attack techniques
        self._techniques = dict(DEFAULT_TECHNIQUES)
        
        # Zone traversal difficulty
        self.zone_difficulty = self.config.get("zone_difficulty", {
            NetworkZone.INTERNET: 0.1,
            NetworkZone.DMZ: 0.4,
            NetworkZone.INTERNAL: 0.7,
            NetworkZone.RESTRICTED: 0.9,
        })
        
        # Control effectiveness
        self.control_effectiveness = self.config.get("control_effectiveness", {
            "edr": 0.35,
            "mfa": 0.40,
            "pam": 0.35,
            "waf": 0.28,
            "ndr": 0.30,
        })
        
        # Asset value multipliers
        self.asset_values = self.config.get("asset_values", {
            AssetType.ENDPOINT: 1.0,
            AssetType.SERVER: 2.0,
            AssetType.DOMAIN_CONTROLLER: 5.0,
            AssetType.DATABASE: 4.0,
            AssetType.WEB_APP: 2.5,
            AssetType.CLOUD_ASSET: 2.0,
            AssetType.NETWORK_DEVICE: 1.5,
            AssetType.IOT_DEVICE: 0.8,
            AssetType.CROWN_JEWEL: 10.0,
        })
    
    def _default_config(self) -> Dict[str, Any]:
        return {
            "max_simulation_hours": 168,
            "max_attack_hops": 10,
            "max_monte_carlo_iterations": 500,
        }
    
    # =========================================================================
    # DIGITAL TWIN CONSTRUCTION
    # =========================================================================
    
    def add_asset(
        self,
        asset_id: str,
        name: str,
        asset_type: str,
        zone: str,
        **kwargs
    ) -> Asset:
        """Add an asset to the digital twin"""
        try:
            asset_type_enum = AssetType[asset_type.upper()]
        except KeyError:
            asset_type_enum = AssetType.ENDPOINT
        
        try:
            zone_enum = NetworkZone[zone.upper()]
        except KeyError:
            zone_enum = NetworkZone.INTERNAL
        
        asset = Asset(
            asset_id=asset_id,
            name=name,
            asset_type=asset_type_enum,
            zone=zone_enum,
            vulnerability_score=kwargs.get("vulnerability_score", 5.0),
            value=self.asset_values.get(asset_type_enum, 1.0),
            has_edr=kwargs.get("has_edr", True),
            has_mfa=kwargs.get("has_mfa", False),
            has_pam=kwargs.get("has_pam", False),
            patched=kwargs.get("patched", True),
            is_crown_jewel=kwargs.get("is_crown_jewel", False),
            data_sensitivity=kwargs.get("data_sensitivity", "internal"),
        )
        
        if asset.is_crown_jewel:
            asset.value = self.asset_values[AssetType.CROWN_JEWEL]
        
        self._assets[asset_id] = asset
        return asset
    
    def add_connection(self, source_id: str, target_id: str, bidirectional: bool = True):
        """Add network connection between assets"""
        self._connections[source_id].add(target_id)
        
        if source_id in self._assets:
            self._assets[source_id].connected_to.append(target_id)
        
        if bidirectional:
            self._connections[target_id].add(source_id)
            if target_id in self._assets:
                self._assets[target_id].connected_to.append(source_id)
    
    def build_from_inventory(self, inventory: List[Dict[str, Any]]) -> int:
        """
        Build digital twin from asset inventory
        
        Args:
            inventory: List of asset dictionaries
            
        Returns:
            Number of assets created
        """
        count = 0
        
        for item in inventory:
            self.add_asset(
                asset_id=item.get("id", f"asset-{count}"),
                name=item.get("name", f"Asset {count}"),
                asset_type=item.get("type", "endpoint"),
                zone=item.get("zone", "internal"),
                **{k: v for k, v in item.items() if k not in ["id", "name", "type", "zone"]}
            )
            count += 1
        
        # Auto-generate connections based on zone
        self._auto_connect_assets()
        
        return count
    
    def _auto_connect_assets(self):
        """Auto-generate network connections based on zones"""
        assets_by_zone: Dict[NetworkZone, List[str]] = defaultdict(list)
        
        for asset_id, asset in self._assets.items():
            assets_by_zone[asset.zone].append(asset_id)
        
        # Connect DMZ to internal
        for dmz_asset in assets_by_zone[NetworkZone.DMZ]:
            for internal_asset in assets_by_zone[NetworkZone.INTERNAL][:5]:  # Limit connections
                self.add_connection(dmz_asset, internal_asset)
        
        # Connect internal assets
        internal = assets_by_zone[NetworkZone.INTERNAL]
        for i, asset_id in enumerate(internal):
            for j in range(i + 1, min(i + 4, len(internal))):
                self.add_connection(asset_id, internal[j])
        
        # Connect to restricted zone (limited)
        for restricted in assets_by_zone[NetworkZone.RESTRICTED]:
            if internal:
                self.add_connection(internal[0], restricted)
    
    def build_default_environment(
        self,
        endpoints: int = 100,
        servers: int = 20,
        web_apps: int = 5,
        databases: int = 3,
        domain_controllers: int = 2
    ) -> int:
        """Build a default enterprise environment"""
        count = 0
        
        # Internet-facing assets
        for i in range(web_apps):
            self.add_asset(
                f"webapp-{i}",
                f"Web Application {i}",
                "WEB_APP",
                "DMZ",
                vulnerability_score=6.0,
                has_edr=False,
            )
            count += 1
        
        # Domain Controllers (Crown Jewels)
        for i in range(domain_controllers):
            self.add_asset(
                f"dc-{i}",
                f"Domain Controller {i}",
                "DOMAIN_CONTROLLER",
                "RESTRICTED",
                vulnerability_score=3.0,
                has_edr=True,
                has_mfa=True,
                has_pam=True,
                is_crown_jewel=True,
            )
            count += 1
        
        # Databases (Crown Jewels)
        for i in range(databases):
            self.add_asset(
                f"db-{i}",
                f"Database Server {i}",
                "DATABASE",
                "RESTRICTED",
                vulnerability_score=4.0,
                has_edr=True,
                is_crown_jewel=True,
                data_sensitivity="confidential",
            )
            count += 1
        
        # Servers
        for i in range(servers):
            zone = "INTERNAL" if i < servers - 2 else "RESTRICTED"
            self.add_asset(
                f"server-{i}",
                f"Server {i}",
                "SERVER",
                zone,
                vulnerability_score=4.5,
                has_edr=True,
            )
            count += 1
        
        # Endpoints
        for i in range(endpoints):
            self.add_asset(
                f"endpoint-{i}",
                f"Endpoint {i}",
                "ENDPOINT",
                "INTERNAL",
                vulnerability_score=5.5,
                has_edr=random.random() > 0.2,  # 80% have EDR
                patched=random.random() > 0.15,  # 85% patched
            )
            count += 1
        
        # Auto-connect
        self._auto_connect_assets()
        
        return count
    
    # =========================================================================
    # ATTACK PATH ANALYSIS
    # =========================================================================
    
    def find_attack_paths(
        self,
        entry_point: str,
        target: str,
        max_paths: int = 5
    ) -> List[AttackPath]:
        """
        Find attack paths from entry point to target
        
        Uses modified Dijkstra's algorithm weighted by:
        - Success probability
        - Detection probability
        - Time to execute
        """
        if entry_point not in self._assets or target not in self._assets:
            return []
        
        paths = []
        
        # BFS/Dijkstra to find paths
        visited = set()
        queue = [(0, entry_point, [])]  # (cost, current, path)
        
        while queue and len(paths) < max_paths:
            cost, current, path = heapq.heappop(queue)
            
            if current == target:
                # Found a path
                attack_path = self._build_attack_path(entry_point, target, path)
                paths.append(attack_path)
                continue
            
            if current in visited:
                continue
            visited.add(current)
            
            # Explore neighbors
            for neighbor in self._connections.get(current, []):
                if neighbor not in visited:
                    # Calculate edge cost
                    edge_cost = self._calculate_edge_cost(current, neighbor)
                    new_path = path + [(current, neighbor)]
                    heapq.heappush(queue, (cost + edge_cost, neighbor, new_path))
        
        return paths
    
    def _calculate_edge_cost(self, source: str, target: str) -> float:
        """Calculate cost of traversing an edge"""
        target_asset = self._assets.get(target)
        if not target_asset:
            return float('inf')
        
        # Base cost from zone difficulty
        zone_cost = self.zone_difficulty.get(target_asset.zone, 0.5)
        
        # Vulnerability factor (lower = easier)
        vuln_factor = 1.0 - (target_asset.vulnerability_score / 10.0) * 0.3
        
        # Security controls increase cost
        control_factor = 1.0
        if target_asset.has_edr:
            control_factor += self.control_effectiveness["edr"]
        if target_asset.has_mfa:
            control_factor += self.control_effectiveness["mfa"]
        if target_asset.has_pam:
            control_factor += self.control_effectiveness["pam"]
        
        return zone_cost * vuln_factor * control_factor
    
    def _build_attack_path(
        self,
        entry_point: str,
        target: str,
        edges: List[Tuple[str, str]]
    ) -> AttackPath:
        """Build complete attack path with techniques"""
        path_id = f"path-{uuid.uuid4().hex[:8]}"
        
        attack_path = AttackPath(
            path_id=path_id,
            entry_point=entry_point,
            target=target,
        )
        
        total_success = 1.0
        total_detection = 0.0
        total_time = 0.0
        
        for i, (source, dest) in enumerate(edges):
            source_asset = self._assets.get(source)
            dest_asset = self._assets.get(dest)
            
            # Select appropriate technique
            technique = self._select_technique(source_asset, dest_asset)
            
            # Calculate success probability
            success_prob = self._calculate_success_probability(
                technique, dest_asset
            )
            
            # Calculate detection probability
            detect_prob = self._calculate_detection_probability(
                technique, dest_asset
            )
            
            # Time estimate
            time_hours = technique.time_hours * (1 + random.uniform(-0.3, 0.5))
            
            step = AttackStep(
                step_number=i + 1,
                source_asset=source,
                target_asset=dest,
                technique=technique,
                success_probability=success_prob,
                detection_probability=detect_prob,
                time_hours=time_hours,
            )
            
            attack_path.steps.append(step)
            
            # Accumulate metrics
            total_success *= success_prob
            total_detection = 1 - (1 - total_detection) * (1 - detect_prob)
            total_time += time_hours
        
        # Calculate business impact
        target_asset = self._assets.get(target)
        impact = target_asset.value if target_asset else 1.0
        if target_asset and target_asset.is_crown_jewel:
            impact *= 2.0
        
        attack_path.total_success_probability = total_success
        attack_path.total_detection_probability = total_detection
        attack_path.total_time_hours = total_time
        attack_path.business_impact = impact * total_success * (1 - total_detection)
        
        return attack_path
    
    def _select_technique(
        self,
        source: Optional[Asset],
        target: Optional[Asset]
    ) -> AttackTechnique:
        """Select appropriate MITRE technique for hop"""
        if not target:
            return self._techniques["T1021"]
        
        # Initial access
        if source is None or source.zone == NetworkZone.INTERNET:
            if target.asset_type == AssetType.WEB_APP:
                return self._techniques["T1190"]
            return self._techniques["T1566"]
        
        # Lateral movement
        if target.asset_type == AssetType.DOMAIN_CONTROLLER:
            return self._techniques["T1003"]  # Credential dumping
        
        if target.zone == NetworkZone.RESTRICTED:
            return self._techniques["T1078"]  # Valid accounts
        
        return self._techniques["T1021"]  # Remote services
    
    def _calculate_success_probability(
        self,
        technique: AttackTechnique,
        target: Optional[Asset]
    ) -> float:
        """Calculate success probability for technique on target"""
        base_prob = technique.success_rate
        
        if not target:
            return base_prob
        
        # Vulnerability increases success
        vuln_modifier = target.vulnerability_score / 10.0
        base_prob = base_prob * (0.7 + vuln_modifier * 0.3)
        
        # Patched systems harder to exploit
        if target.patched:
            base_prob *= 0.7
        
        # Zone difficulty
        zone_mod = 1.0 - self.zone_difficulty.get(target.zone, 0.5) * 0.3
        base_prob *= zone_mod
        
        return min(0.99, max(0.01, base_prob))
    
    def _calculate_detection_probability(
        self,
        technique: AttackTechnique,
        target: Optional[Asset]
    ) -> float:
        """Calculate detection probability"""
        base_prob = technique.detection_rate
        
        if not target:
            return base_prob
        
        # EDR increases detection
        if target.has_edr:
            base_prob = 1 - (1 - base_prob) * (1 - self.control_effectiveness["edr"])
        
        # PAM increases detection for privileged access
        if target.has_pam and technique.requires_privilege != "none":
            base_prob = 1 - (1 - base_prob) * (1 - self.control_effectiveness["pam"])
        
        return min(0.99, max(0.01, base_prob))
    
    # =========================================================================
    # BREACH SIMULATION
    # =========================================================================
    
    def simulate_breach(
        self,
        attack_vector: str = "PHISHING",
        entry_asset: Optional[str] = None
    ) -> BreachScenario:
        """
        Simulate a single breach scenario
        
        Args:
            attack_vector: Initial attack vector
            entry_asset: Specific entry point (or random)
            
        Returns:
            BreachScenario with results
        """
        try:
            vector = AttackVector[attack_vector.upper()]
        except KeyError:
            vector = AttackVector.PHISHING
        
        # Select entry point
        if not entry_asset:
            entry_asset = self._select_entry_point(vector)
        
        scenario = BreachScenario(
            scenario_id=f"breach-{uuid.uuid4().hex[:8]}",
            attack_vector=vector,
            entry_asset=entry_asset,
        )
        
        if not entry_asset or entry_asset not in self._assets:
            return scenario
        
        # Simulate initial access
        initial_success = self._simulate_initial_access(vector, entry_asset)
        scenario.time_to_initial_access = random.uniform(0.5, 4.0)
        
        if not initial_success:
            return scenario
        
        # Start lateral movement
        compromised = {entry_asset}
        current_positions = [entry_asset]
        crown_jewels = [aid for aid, a in self._assets.items() if a.is_crown_jewel]
        detected = False
        total_time = scenario.time_to_initial_access
        
        # BFS lateral movement
        for hop in range(self.config.get("max_attack_hops", 10)):
            if not current_positions:
                break
            
            next_positions = []
            
            for position in current_positions:
                neighbors = self._connections.get(position, [])
                
                for neighbor in neighbors:
                    if neighbor in compromised:
                        continue
                    
                    # Attempt to compromise
                    success_prob = self._calculate_lateral_success(position, neighbor)
                    detect_prob = self._calculate_lateral_detection(position, neighbor)
                    
                    if random.random() < success_prob:
                        compromised.add(neighbor)
                        next_positions.append(neighbor)
                        total_time += random.uniform(0.5, 2.0)
                        
                        # Check if crown jewel reached
                        if neighbor in crown_jewels:
                            scenario.crown_jewels_reached.append(neighbor)
                            if not scenario.time_to_crown_jewels:
                                scenario.time_to_crown_jewels = total_time
                    
                    # Detection check
                    if random.random() < detect_prob:
                        detected = True
                        break
                
                if detected:
                    break
            
            if detected:
                break
            
            current_positions = next_positions
        
        # Record results
        scenario.successful = len(compromised) > 1
        scenario.detected = detected
        scenario.assets_compromised = list(compromised)
        scenario.lateral_movement_hops = len(compromised) - 1
        scenario.blast_radius = len(compromised)
        scenario.total_time_hours = total_time
        scenario.data_exfiltrated = bool(scenario.crown_jewels_reached) and not detected
        
        return scenario
    
    def _select_entry_point(self, vector: AttackVector) -> Optional[str]:
        """Select entry point based on attack vector"""
        candidates = []
        
        if vector == AttackVector.WEB_EXPLOIT:
            candidates = [
                aid for aid, a in self._assets.items()
                if a.asset_type == AssetType.WEB_APP
            ]
        elif vector == AttackVector.PHISHING:
            candidates = [
                aid for aid, a in self._assets.items()
                if a.asset_type == AssetType.ENDPOINT
            ]
        elif vector == AttackVector.CLOUD_MISCONFIGURATION:
            candidates = [
                aid for aid, a in self._assets.items()
                if a.asset_type == AssetType.CLOUD_ASSET
            ]
        else:
            candidates = [
                aid for aid, a in self._assets.items()
                if a.zone in (NetworkZone.DMZ, NetworkZone.INTERNET)
            ]
        
        if not candidates:
            candidates = list(self._assets.keys())
        
        return random.choice(candidates) if candidates else None
    
    def _simulate_initial_access(
        self,
        vector: AttackVector,
        entry: str
    ) -> bool:
        """Simulate initial access success"""
        asset = self._assets.get(entry)
        if not asset:
            return False
        
        # Base success rate by vector
        base_rates = {
            AttackVector.PHISHING: 0.60,
            AttackVector.WEB_EXPLOIT: 0.70,
            AttackVector.CREDENTIAL_STUFFING: 0.50,
            AttackVector.SUPPLY_CHAIN: 0.80,
            AttackVector.INSIDER: 0.90,
            AttackVector.ZERO_DAY: 0.85,
        }
        
        base_prob = base_rates.get(vector, 0.50)
        
        # Modify by asset
        if asset.patched:
            base_prob *= 0.6
        if asset.has_mfa:
            base_prob *= 0.5
        
        return random.random() < base_prob
    
    def _calculate_lateral_success(self, source: str, target: str) -> float:
        """Calculate lateral movement success probability"""
        target_asset = self._assets.get(target)
        if not target_asset:
            return 0.0
        
        base_prob = 0.70
        
        # Zone traversal penalty
        source_asset = self._assets.get(source)
        if source_asset and target_asset.zone.value > source_asset.zone.value:
            base_prob *= 0.5
        
        # Control penalties
        if target_asset.has_pam:
            base_prob *= 0.4
        if target_asset.has_mfa:
            base_prob *= 0.6
        
        # Vulnerability boost
        base_prob *= (0.5 + target_asset.vulnerability_score / 20.0)
        
        return min(0.95, max(0.05, base_prob))
    
    def _calculate_lateral_detection(self, source: str, target: str) -> float:
        """Calculate detection probability during lateral movement"""
        target_asset = self._assets.get(target)
        if not target_asset:
            return 0.0
        
        base_prob = 0.15
        
        if target_asset.has_edr:
            base_prob += 0.25
        if target_asset.has_pam:
            base_prob += 0.20
        if target_asset.zone == NetworkZone.RESTRICTED:
            base_prob += 0.15
        
        return min(0.80, base_prob)
    
    # =========================================================================
    # MONTE CARLO SIMULATION
    # =========================================================================
    
    def run_monte_carlo(
        self,
        iterations: int = 100,
        attack_vectors: Optional[List[str]] = None
    ) -> SimulationResult:
        """
        Run Monte Carlo simulation
        
        Args:
            iterations: Number of simulation iterations
            attack_vectors: Attack vectors to simulate
            
        Returns:
            SimulationResult with aggregate statistics
        """
        iterations = min(
            iterations,
            self.config.get("max_monte_carlo_iterations", 500)
        )
        
        if not attack_vectors:
            attack_vectors = ["PHISHING", "WEB_EXPLOIT", "CREDENTIAL_STUFFING"]
        
        result = SimulationResult(
            simulation_id=f"sim-{uuid.uuid4().hex[:8]}",
            iterations=iterations,
        )
        
        # Run simulations
        scenarios = []
        for i in range(iterations):
            vector = random.choice(attack_vectors)
            scenario = self.simulate_breach(attack_vector=vector)
            scenarios.append(scenario)
        
        # Calculate statistics
        successful = [s for s in scenarios if s.successful]
        detected = [s for s in scenarios if s.detected]
        crown_jewel = [s for s in scenarios if s.crown_jewels_reached]
        
        result.breach_success_rate = len(successful) / iterations
        result.detection_rate = len(detected) / iterations
        result.crown_jewel_access_rate = len(crown_jewel) / iterations
        
        # Timing statistics
        times = [s.total_time_hours for s in successful if s.total_time_hours > 0]
        if times:
            times.sort()
            result.avg_time_to_compromise = sum(times) / len(times)
            result.min_time_to_compromise = min(times)
            result.max_time_to_compromise = max(times)
            result.p50_time = times[len(times) // 2]
            result.p95_time = times[int(len(times) * 0.95)]
        
        # Blast radius
        radii = [s.blast_radius for s in successful]
        if radii:
            result.avg_blast_radius = sum(radii) / len(radii)
            result.max_blast_radius = max(radii)
        
        # Overall risk score (0-10)
        result.overall_risk_score = (
            result.breach_success_rate * 4 +
            result.crown_jewel_access_rate * 4 +
            (1 - result.detection_rate) * 2
        )
        
        # Store sample scenarios
        result.scenarios = scenarios[:10]
        
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result, scenarios)
        
        return result
    
    def _generate_recommendations(
        self,
        result: SimulationResult,
        scenarios: List[BreachScenario]
    ) -> List[Dict[str, Any]]:
        """Generate security recommendations based on simulation"""
        recommendations = []
        
        # High breach success rate
        if result.breach_success_rate > 0.6:
            recommendations.append({
                "priority": "P0",
                "category": "Perimeter Security",
                "finding": f"High breach success rate ({result.breach_success_rate*100:.0f}%)",
                "recommendation": "Strengthen initial access controls, implement MFA universally",
                "estimated_reduction": "40-50%",
            })
        
        # Low detection rate
        if result.detection_rate < 0.3:
            recommendations.append({
                "priority": "P0",
                "category": "Detection & Response",
                "finding": f"Low detection rate ({result.detection_rate*100:.0f}%)",
                "recommendation": "Deploy EDR to all endpoints, enhance SIEM correlation rules",
                "estimated_reduction": "30-40%",
            })
        
        # Crown jewel access
        if result.crown_jewel_access_rate > 0.2:
            recommendations.append({
                "priority": "P0",
                "category": "Crown Jewel Protection",
                "finding": f"Crown jewels reached in {result.crown_jewel_access_rate*100:.0f}% of simulations",
                "recommendation": "Implement PAM, network segmentation, and enhanced monitoring for critical assets",
                "estimated_reduction": "50-60%",
            })
        
        # Fast compromise time
        if result.avg_time_to_compromise < 4:
            recommendations.append({
                "priority": "P1",
                "category": "Lateral Movement",
                "finding": f"Average time to compromise: {result.avg_time_to_compromise:.1f} hours",
                "recommendation": "Implement micro-segmentation and limit lateral movement paths",
                "estimated_reduction": "Increase TTC by 300%",
            })
        
        # Large blast radius
        if result.avg_blast_radius > 10:
            recommendations.append({
                "priority": "P1",
                "category": "Containment",
                "finding": f"Average blast radius: {result.avg_blast_radius:.0f} assets",
                "recommendation": "Improve network segmentation, implement automated containment",
                "estimated_reduction": "60-70%",
            })
        
        # Identify most compromised assets
        compromise_counts: Dict[str, int] = defaultdict(int)
        for scenario in scenarios:
            for asset_id in scenario.assets_compromised:
                compromise_counts[asset_id] += 1
        
        top_compromised = sorted(
            compromise_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        if top_compromised:
            recommendations.append({
                "priority": "P2",
                "category": "Asset Hardening",
                "finding": "Most frequently compromised assets identified",
                "assets": [
                    {"id": aid, "compromise_rate": f"{count/len(scenarios)*100:.0f}%"}
                    for aid, count in top_compromised
                ],
                "recommendation": "Prioritize hardening these specific assets",
            })
        
        return recommendations
    
    # =========================================================================
    # REPORTING
    # =========================================================================
    
    def get_attack_surface_summary(self) -> Dict[str, Any]:
        """Get summary of attack surface"""
        crown_jewels = [a for a in self._assets.values() if a.is_crown_jewel]
        internet_facing = [
            a for a in self._assets.values()
            if a.zone in (NetworkZone.INTERNET, NetworkZone.DMZ)
        ]
        
        # Calculate vulnerability distribution
        vuln_scores = [a.vulnerability_score for a in self._assets.values()]
        
        return {
            "total_assets": len(self._assets),
            "by_type": {
                at.value: sum(1 for a in self._assets.values() if a.asset_type == at)
                for at in AssetType
            },
            "by_zone": {
                z.value: sum(1 for a in self._assets.values() if a.zone == z)
                for z in NetworkZone
            },
            "crown_jewels": len(crown_jewels),
            "internet_facing": len(internet_facing),
            "total_connections": sum(len(c) for c in self._connections.values()) // 2,
            "vulnerability_stats": {
                "average": sum(vuln_scores) / len(vuln_scores) if vuln_scores else 0,
                "max": max(vuln_scores) if vuln_scores else 0,
                "min": min(vuln_scores) if vuln_scores else 0,
            },
            "controls_coverage": {
                "edr": sum(1 for a in self._assets.values() if a.has_edr) / len(self._assets) if self._assets else 0,
                "mfa": sum(1 for a in self._assets.values() if a.has_mfa) / len(self._assets) if self._assets else 0,
                "pam": sum(1 for a in self._assets.values() if a.has_pam) / len(self._assets) if self._assets else 0,
            },
        }


# =============================================================================
# FACTORY & EXPORTS
# =============================================================================

_simulator: Optional[DigitalTwinSimulator] = None


def get_digital_twin(config: Optional[Dict[str, Any]] = None) -> DigitalTwinSimulator:
    """Get or create digital twin simulator"""
    global _simulator
    if _simulator is None or config is not None:
        _simulator = DigitalTwinSimulator(config)
    return _simulator


def run_breach_simulation(
    attack_vector: str = "PHISHING",
    entry_asset: Optional[str] = None
) -> Dict[str, Any]:
    """Run single breach simulation"""
    simulator = get_digital_twin()
    
    if not simulator._assets:
        simulator.build_default_environment()
    
    scenario = simulator.simulate_breach(attack_vector, entry_asset)
    return scenario.to_dict()


def run_full_simulation(
    iterations: int = 100,
    attack_vectors: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Run full Monte Carlo simulation"""
    simulator = get_digital_twin()
    
    if not simulator._assets:
        simulator.build_default_environment()
    
    result = simulator.run_monte_carlo(iterations, attack_vectors)
    return result.to_dict()


# Singleton export
digital_twin = get_digital_twin()

__all__ = [
    "DigitalTwinSimulator",
    "Asset",
    "AssetType",
    "NetworkZone",
    "AttackVector",
    "AttackTechnique",
    "AttackPath",
    "AttackStep",
    "BreachScenario",
    "SimulationResult",
    "get_digital_twin",
    "run_breach_simulation",
    "run_full_simulation",
    "digital_twin",
]
