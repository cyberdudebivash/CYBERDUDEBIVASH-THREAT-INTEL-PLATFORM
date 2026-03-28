"""
CYBERDUDEBIVASH® SENTINEL APEX
AGENT ORCHESTRATOR — Multi-agent collaborative pipeline
Runs ThreatHunter + MalwareAnalyst + VulnAnalyst in sequence on each advisory.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .threat_hunter import ThreatHunterAgent
from .malware_analyst import MalwareAnalystAgent
from .vuln_analyst import VulnerabilityAnalystAgent

logger = logging.getLogger("CDB-ORCHESTRATOR")


class AgentOrchestrator:
    """
    Multi-agent orchestration engine.
    Runs all specialist agents on threat data and assembles unified intelligence.
    """

    def __init__(self):
        self.threat_hunter  = ThreatHunterAgent()
        self.malware_analyst = MalwareAnalystAgent()
        self.vuln_analyst    = VulnerabilityAnalystAgent()
        self.runs = 0

    def run(self, advisory: Dict) -> Dict:
        """Run all agents on a single advisory and merge results."""
        logger.info(f"[ORCHESTRATOR] Processing: {advisory.get('title','')[:60]}")

        hunt_package   = self.threat_hunter.generate_hunt_package(advisory)
        malware_report = self.malware_analyst.analyze(advisory)
        patch_guidance = self.vuln_analyst.generate_patch_guidance(advisory)

        self.runs += 1
        result = {
            "orchestration_id":  f"ORCH-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "advisory_id":       advisory.get("stix_id", ""),
            "advisory_title":    advisory.get("title", "")[:80],
            "agents_run":        ["ThreatHunterAgent", "MalwareAnalystAgent", "VulnerabilityAnalystAgent"],
            "hunt_package":      hunt_package,
            "malware_report":    malware_report,
            "patch_guidance":    patch_guidance,
            "unified_risk_score": self._compute_unified_risk(malware_report, patch_guidance),
            "action_summary":    self._build_action_summary(hunt_package, malware_report, patch_guidance),
            "orchestrated_at":   datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"[ORCHESTRATOR] Complete: unified_risk={result['unified_risk_score']}")
        return result

    def run_batch(self, advisories: List[Dict]) -> Dict:
        """Orchestrate all agents over a batch of advisories."""
        results = [self.run(a) for a in advisories]
        return {
            "batch_size": len(advisories),
            "results": results,
            "high_priority_hunts": [r["hunt_package"] for r in results
                                    if r["hunt_package"].get("priority") in ("P1","P2")],
            "critical_patches": [r["patch_guidance"] for r in results
                                  if r["patch_guidance"].get("patch_priority",{}).get("urgency") == "CRITICAL"],
            "total_runs": self.runs,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_agent_status(self) -> Dict:
        return {
            "orchestrator": "AgentOrchestrator v1.0",
            "agents": {
                "ThreatHunterAgent":      self.threat_hunter.get_stats(),
                "MalwareAnalystAgent":    self.malware_analyst.get_stats(),
                "VulnerabilityAnalystAgent": self.vuln_analyst.get_stats(),
            },
            "total_orchestrations": self.runs,
            "status": "OPERATIONAL",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def _compute_unified_risk(self, malware_report: Dict, patch_guidance: Dict) -> float:
        exploit_score = patch_guidance.get("exploitability", {}).get("exploitability_score", 5.0)
        capability_count = malware_report.get("capability_profile", {}).get("capability_count", 0)
        cap_bonus = min(2.0, capability_count * 0.3)
        return round(min(10.0, exploit_score + cap_bonus), 2)

    def _build_action_summary(self, hunt: Dict, malware: Dict, patch: Dict) -> List[str]:
        actions = []
        if hunt.get("priority") in ("P1", "P2"):
            actions.append(f"HUNT: Execute {hunt.get('hunt_count',0)} threat hunt queries immediately")
        priority = patch.get("patch_priority", {}).get("priority", "")
        if priority in ("P1_IMMEDIATE", "P2_URGENT"):
            actions.append(f"PATCH: {patch.get('patch_priority',{}).get('label','Apply patches')}")
        family = malware.get("malware_classification", {}).get("primary_family", "UNKNOWN")
        if family != "UNKNOWN":
            actions.append(f"BLOCK: Deploy IOC blocks for identified {family} malware family")
        actions.append("MONITOR: Update SIEM dashboards with new hunt queries")
        return actions
