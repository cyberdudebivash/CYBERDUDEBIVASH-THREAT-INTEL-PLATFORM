"""
CYBERDUDEBIVASH® SENTINEL APEX
TIER-2 INVESTIGATION AGENT — Deep-dive threat analysis
Performs: timeline reconstruction, actor attribution, TTP mapping,
         lateral movement analysis, blast radius estimation.
"""
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-SOC-TIER2")

MITRE_TACTIC_MAP = {
    "T1566": "Phishing", "T1078": "Valid Accounts", "T1059": "Command Execution",
    "T1055": "Process Injection", "T1053": "Scheduled Task", "T1003": "Credential Dumping",
    "T1021": "Remote Services", "T1082": "System Info Discovery", "T1083": "File Discovery",
    "T1486": "Data Encrypted for Impact", "T1490": "Inhibit System Recovery",
    "T1071": "Application Layer Protocol", "T1041": "Exfiltration Over C2",
    "T1203": "Exploitation for Client Execution", "T1190": "Exploit Public-Facing App",
    "T1195": "Supply Chain Compromise", "T1199": "Trusted Relationship",
    "T1040": "Network Sniffing", "T1557": "Adversary-in-the-Middle",
}

KILL_CHAIN_STAGES = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "C2", "Actions on Objectives"
]

ACTOR_SIGNATURES = {
    "APT28": ["T1566", "T1078", "T1059"],
    "APT29": ["T1195", "T1199", "T1071"],
    "Lazarus": ["T1486", "T1490", "T1003"],
    "Sandworm": ["T1486", "T1055", "T1053"],
    "FIN7": ["T1566", "T1059", "T1041"],
    "REvil": ["T1486", "T1490", "T1078"],
    "LockBit": ["T1486", "T1490", "T1021"],
    "BlackCat": ["T1486", "T1082", "T1083"],
}


class Tier2InvestigationAgent:
    """
    Autonomous Tier-2 investigator.
    Deep threat analysis: TTP mapping, actor attribution, blast radius.
    """

    def __init__(self):
        self.investigation_cache: Dict[str, Dict] = {}

    # ── TTP Analysis ─────────────────────────────────────────────────────────

    def map_ttps(self, alert: Dict) -> Dict:
        """Map MITRE ATT&CK TTPs from alert data."""
        techniques = alert.get("mitre_techniques", [])
        if not techniques:
            # Extract from text
            text = f"{alert.get('title','')} {alert.get('summary','')}"
            techniques = re.findall(r"T\d{4}(?:\.\d{3})?", text)

        mapped = {}
        for t in techniques:
            t_id = str(t).upper()
            mapped[t_id] = MITRE_TACTIC_MAP.get(t_id, "Unknown Technique")

        kill_chain_coverage = self._map_kill_chain(list(mapped.keys()))
        return {
            "techniques": mapped,
            "technique_count": len(mapped),
            "kill_chain_coverage": kill_chain_coverage,
            "kill_chain_stages_hit": len([s for s in kill_chain_coverage.values() if s]),
        }

    def _map_kill_chain(self, techniques: List[str]) -> Dict:
        """Map techniques to kill chain stages."""
        mapping = {
            "Reconnaissance":           ["T1595", "T1592", "T1589"],
            "Weaponization":            ["T1587", "T1586"],
            "Delivery":                 ["T1566", "T1195", "T1199"],
            "Exploitation":             ["T1190", "T1203", "T1059"],
            "Installation":             ["T1055", "T1053", "T1543"],
            "C2":                       ["T1071", "T1095", "T1572"],
            "Actions on Objectives":    ["T1486", "T1490", "T1041", "T1003"],
        }
        coverage = {}
        for stage, stage_techniques in mapping.items():
            coverage[stage] = any(t in techniques for t in stage_techniques)
        return coverage

    # ── Actor Attribution ─────────────────────────────────────────────────────

    def attribute_actor(self, alert: Dict, ttp_data: Dict) -> Dict:
        """Attempt actor attribution based on TTPs and indicators."""
        techniques = list(ttp_data.get("techniques", {}).keys())
        title_lower = alert.get("title", "").lower()
        summary_lower = alert.get("summary", "").lower()
        actor_scores: Dict[str, float] = {}

        for actor, sig_techniques in ACTOR_SIGNATURES.items():
            overlap = len([t for t in sig_techniques if t in techniques])
            score = overlap / len(sig_techniques) if sig_techniques else 0.0
            # Boost if actor name mentioned directly
            if actor.lower() in title_lower or actor.lower() in summary_lower:
                score = min(1.0, score + 0.5)
            if score > 0:
                actor_scores[actor] = round(score, 2)

        if not actor_scores:
            return {"suspected_actor": "UNKNOWN", "confidence": 0.0, "candidates": []}

        top_actor = max(actor_scores, key=lambda k: actor_scores[k])
        confidence = actor_scores[top_actor]
        return {
            "suspected_actor": top_actor if confidence > 0.5 else "UNKNOWN",
            "confidence": confidence,
            "confidence_level": "HIGH" if confidence > 0.7 else "MEDIUM" if confidence > 0.4 else "LOW",
            "candidates": sorted(actor_scores.items(), key=lambda x: -x[1]),
        }

    # ── Blast Radius Estimation ───────────────────────────────────────────────

    def estimate_blast_radius(self, alert: Dict) -> Dict:
        """Estimate potential blast radius and business impact."""
        severity = alert.get("severity", "MEDIUM")
        cvss = float(alert.get("cvss", 5.0) or 5.0)
        ioc_count = len(alert.get("iocs", []))
        text = f"{alert.get('title','')} {alert.get('summary','')}".lower()

        # Impact categories
        impacts = []
        if any(k in text for k in ["ransomware", "encrypt", "lock"]):
            impacts.append({"category": "DATA_ENCRYPTION", "severity": "CRITICAL"})
        if any(k in text for k in ["exfiltrat", "data theft", "data breach"]):
            impacts.append({"category": "DATA_EXFILTRATION", "severity": "HIGH"})
        if any(k in text for k in ["credential", "password", "token", "key"]):
            impacts.append({"category": "CREDENTIAL_COMPROMISE", "severity": "HIGH"})
        if any(k in text for k in ["lateral", "movement", "pivot"]):
            impacts.append({"category": "LATERAL_MOVEMENT", "severity": "HIGH"})
        if any(k in text for k in ["supply chain", "dependency", "package"]):
            impacts.append({"category": "SUPPLY_CHAIN", "severity": "CRITICAL"})
        if any(k in text for k in ["denial", "ddos", "dos", "unavailable"]):
            impacts.append({"category": "SERVICE_DISRUPTION", "severity": "MEDIUM"})

        blast_score = min(10.0, cvss * 0.5 + len(impacts) * 0.8 + (ioc_count * 0.05))
        blast_level = "CATASTROPHIC" if blast_score >= 9 else "SEVERE" if blast_score >= 7 \
            else "SIGNIFICANT" if blast_score >= 5 else "MODERATE" if blast_score >= 3 else "LIMITED"

        return {
            "blast_score": round(blast_score, 1),
            "blast_level": blast_level,
            "impact_categories": impacts,
            "estimated_systems_at_risk": max(1, int(blast_score * 12)),
            "data_at_risk": blast_score >= 6,
            "critical_infra_risk": blast_score >= 8,
        }

    # ── Full Investigation ────────────────────────────────────────────────────

    def investigate(self, triage_result: Dict) -> Dict:
        """Run full Tier-2 investigation on a triaged alert."""
        enriched_alert = triage_result.get("enriched_alert", triage_result)
        alert_id = enriched_alert.get("stix_id", enriched_alert.get("id", "unknown"))

        logger.info(f"[T2-INVESTIGATION] Starting: {enriched_alert.get('title','')[:60]}")

        ttp_data = self.map_ttps(enriched_alert)
        attribution = self.attribute_actor(enriched_alert, ttp_data)
        blast_radius = self.estimate_blast_radius(enriched_alert)

        # Build investigation timeline
        timeline = [
            {"time": enriched_alert.get("tier1_processed_at", ""), "event": "Tier-1 triage completed"},
            {"time": datetime.now(timezone.utc).isoformat(), "event": "Tier-2 investigation started"},
        ]

        # Containment recommendations
        recommendations = self._generate_recommendations(enriched_alert, ttp_data, blast_radius)

        investigation = {
            "alert_id": alert_id,
            "tier": "T2",
            "status": "INVESTIGATED",
            "ttp_analysis": ttp_data,
            "actor_attribution": attribution,
            "blast_radius": blast_radius,
            "investigation_timeline": timeline,
            "containment_recommendations": recommendations,
            "escalate_to_tier3": blast_radius["blast_score"] >= 7.0 or attribution["confidence"] > 0.7,
            "investigated_at": datetime.now(timezone.utc).isoformat(),
            "confidence_level": attribution.get("confidence_level", "LOW"),
        }

        self.investigation_cache[alert_id] = investigation
        logger.info(f"[T2] Complete: actor={attribution['suspected_actor']} blast={blast_radius['blast_level']}")
        return investigation

    def _generate_recommendations(self, alert: Dict, ttp_data: Dict, blast: Dict) -> List[str]:
        recs = []
        if blast["blast_score"] >= 8:
            recs.append("IMMEDIATE: Isolate affected systems from network")
            recs.append("IMMEDIATE: Activate incident response team")
        if any(i["category"] == "CREDENTIAL_COMPROMISE" for i in blast["impact_categories"]):
            recs.append("URGENT: Force password reset for affected accounts")
            recs.append("URGENT: Revoke and rotate API keys and tokens")
        if any(i["category"] == "LATERAL_MOVEMENT" for i in blast["impact_categories"]):
            recs.append("HIGH: Audit all internal network connections from source host")
        if any(i["category"] == "DATA_EXFILTRATION" for i in blast["impact_categories"]):
            recs.append("HIGH: Enable DLP monitoring and block outbound transfers")
        if "T1486" in ttp_data.get("techniques", {}):
            recs.append("CRITICAL: Verify backup integrity immediately")
        recs.append("Deploy detection rules to SIEM for identified TTPs")
        recs.append("Update threat intelligence feeds with new IOCs")
        return recs
