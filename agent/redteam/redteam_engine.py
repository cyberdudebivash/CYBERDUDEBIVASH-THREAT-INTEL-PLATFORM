"""
CYBERDUDEBIVASH® SENTINEL APEX
ATTACK PATH MAPPER + RED TEAM ENGINE — Full red team orchestration
Maps attack paths, identifies chokepoints, generates purple team exercises.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-REDTEAM")

NETWORK_ZONES = ["internet", "dmz", "web_tier", "app_tier", "data_tier", "admin_zone", "crown_jewels"]

ZONE_TRANSITIONS = {
    "internet":    ["dmz"],
    "dmz":         ["web_tier", "internet"],
    "web_tier":    ["app_tier", "dmz"],
    "app_tier":    ["data_tier", "web_tier", "admin_zone"],
    "data_tier":   ["admin_zone"],
    "admin_zone":  ["crown_jewels", "data_tier"],
    "crown_jewels": [],
}

CONTROL_GAPS = {
    "internet→dmz":         "WAF, IPS, Ingress filtering",
    "dmz→web_tier":         "Segmentation firewall, DMZ hardening",
    "web_tier→app_tier":    "Internal firewall, application authentication",
    "app_tier→data_tier":   "Database access controls, encryption at rest",
    "app_tier→admin_zone":  "PAM solution, privileged session monitoring",
    "admin_zone→crown_jewels": "MFA everywhere, zero trust verification",
}


class AttackPathMapper:
    """Maps realistic attack paths through network architecture."""

    def map_paths(self, entry_point: str = "internet") -> List[List[str]]:
        """BFS to enumerate all paths to crown jewels."""
        paths = []
        queue = [[entry_point]]
        while queue:
            path = queue.pop(0)
            current = path[-1]
            if current == "crown_jewels":
                paths.append(path)
                continue
            if len(path) > len(NETWORK_ZONES):
                continue
            for next_zone in ZONE_TRANSITIONS.get(current, []):
                if next_zone not in path:
                    queue.append(path + [next_zone])
        return paths

    def identify_chokepoints(self, paths: List[List[str]]) -> List[Dict]:
        """Identify network zones that appear in most attack paths."""
        from collections import Counter
        zone_count = Counter(zone for path in paths for zone in path[1:])
        total_paths = len(paths) or 1
        chokepoints = []
        for zone, count in sorted(zone_count.items(), key=lambda x: -x[1]):
            chokepoints.append({
                "zone": zone,
                "path_coverage": f"{round(count/total_paths*100)}%",
                "recommendation": f"Harden {zone}: deploy {CONTROL_GAPS.get(zone,'additional controls')}",
            })
        return chokepoints

    def generate_attack_map(self) -> Dict:
        paths = self.map_paths("internet")
        chokepoints = self.identify_chokepoints(paths)
        return {
            "total_paths_to_crown_jewels": len(paths),
            "shortest_path": min(paths, key=len) if paths else [],
            "longest_path": max(paths, key=len) if paths else [],
            "chokepoints": chokepoints[:5],
            "critical_transitions": [
                {"from": z, "to": t, "control_gap": CONTROL_GAPS.get(f"{z}→{t}", "Verify segmentation")}
                for z, transitions in ZONE_TRANSITIONS.items()
                for t in transitions
                if f"{z}→{t}" in CONTROL_GAPS
            ],
            "mapped_at": datetime.now(timezone.utc).isoformat(),
        }


class RedTeamEngine:
    """
    Autonomous red team engine.
    Combines attack simulation + path mapping into purple team exercises.
    """

    def __init__(self):
        from .attack_simulator import AttackSimulator
        self.simulator = AttackSimulator()
        self.path_mapper = AttackPathMapper()
        self.exercises_generated = 0

    def generate_exercise(self, advisory: Dict) -> Dict:
        """Generate a complete purple team exercise from threat intel."""
        simulation = self.simulator.simulate_from_advisory(advisory)
        attack_map = self.path_mapper.generate_attack_map()

        self.exercises_generated += 1
        logger.info(f"[REDTEAM] Exercise generated for: {advisory.get('title','')[:60]}")

        return {
            "exercise_id":    f"RT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "title":          f"Purple Team: {advisory.get('title','')[:60]}",
            "attack_simulation": simulation,
            "attack_map":     attack_map,
            "purple_team_objectives": [
                "Red: Execute attack chain steps against test environment",
                "Blue: Detect each attack step using monitoring stack",
                "Purple: Document detection gaps and coverage improvements",
                "Outcome: Update detection rules and playbooks",
            ],
            "success_criteria": [
                f"Detect {len(simulation.get('steps',[]))} of {len(simulation.get('steps',[]))} attack steps",
                "Mean time to detect (MTTD) < 15 minutes for P1 TTPs",
                "Alert triage accuracy > 90% for simulated attacks",
            ],
            "detection_gaps_to_close": simulation.get("detection_gaps", []),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_status(self) -> Dict:
        return {
            "engine": "RedTeamEngine v1.0",
            "exercises_generated": self.exercises_generated,
            "simulator_stats": self.simulator.get_stats(),
            "status": "OPERATIONAL",
        }
