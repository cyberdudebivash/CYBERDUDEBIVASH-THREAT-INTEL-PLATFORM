"""
CYBERDUDEBIVASH® SENTINEL APEX
INCIDENT REPORTER — Auto-generates structured incident reports
Produces: executive summary, technical analysis, timeline, recommendations.
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-SOC-REPORTER")

REPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "incidents")


class IncidentReporter:
    """Generates production-grade incident reports from SOC pipeline output."""

    def __init__(self):
        os.makedirs(REPORT_DIR, exist_ok=True)

    def generate_report(self, triage: Dict, investigation: Dict, response: Dict) -> Dict:
        """Assemble full incident report from all tier outputs."""
        alert = triage.get("enriched_alert", {})
        blast = investigation.get("blast_radius", {})
        attribution = investigation.get("actor_attribution", {})
        playbook = response.get("playbook", {})

        incident_id = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        report = {
            "incident_id": incident_id,
            "report_version": "1.0",
            "classification": "TLP:AMBER",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": self._build_executive_summary(alert, blast, attribution),
            "incident_details": {
                "title": alert.get("title", ""),
                "severity": alert.get("severity", ""),
                "priority": triage.get("priority", ""),
                "priority_score": triage.get("priority_score", 0),
                "cvss": alert.get("cvss", 0),
                "epss": alert.get("epss", 0),
                "kev_confirmed": alert.get("kev_confirmed", False),
                "stix_id": alert.get("stix_id", ""),
                "cves": alert.get("cves", []),
                "ioc_count": alert.get("ioc_count", 0),
                "ioc_types": alert.get("ioc_types", []),
            },
            "threat_analysis": {
                "actor_suspected": attribution.get("suspected_actor", "UNKNOWN"),
                "attribution_confidence": attribution.get("confidence", 0),
                "mitre_techniques": investigation.get("ttp_analysis", {}).get("techniques", {}),
                "kill_chain_coverage": investigation.get("ttp_analysis", {}).get("kill_chain_coverage", {}),
                "blast_radius": blast.get("blast_level", "UNKNOWN"),
                "blast_score": blast.get("blast_score", 0),
                "impact_categories": blast.get("impact_categories", []),
            },
            "response_actions": {
                "playbook_id": playbook.get("playbook_id", ""),
                "scenario": playbook.get("scenario", ""),
                "total_steps": len(playbook.get("steps", [])),
                "auto_executable": len(response.get("auto_executed_actions", [])),
                "priority_actions": playbook.get("priority_actions", []),
                "estimated_resolution": playbook.get("estimated_resolution_time", ""),
            },
            "recommendations": investigation.get("containment_recommendations", []),
            "timeline": self._build_timeline(triage, investigation, response),
            "sla_tracking": {
                "detected_at": triage.get("triaged_at", ""),
                "investigated_at": investigation.get("investigated_at", ""),
                "response_generated_at": response.get("responded_at", ""),
                "sla": triage.get("sla", ""),
                "sla_met": True,  # Would be calculated from actual timestamps
            },
        }

        # Persist report
        self._save_report(incident_id, report)
        logger.info(f"[REPORTER] Incident report generated: {incident_id}")
        return report

    def _build_executive_summary(self, alert: Dict, blast: Dict, attribution: Dict) -> str:
        actor = attribution.get("suspected_actor", "an unknown threat actor")
        confidence = attribution.get("confidence_level", "LOW")
        blast_level = blast.get("blast_level", "MODERATE")
        title = alert.get("title", "Unknown Threat")
        severity = alert.get("severity", "UNKNOWN")

        return (
            f"A {severity} severity security incident '{title}' has been detected and triaged. "
            f"Analysis indicates {blast_level} blast radius with {confidence}-confidence attribution to {actor}. "
            f"Immediate containment actions have been initiated per the automated response playbook. "
            f"CVSS Score: {alert.get('cvss','N/A')} | EPSS: {alert.get('epss','N/A')} | "
            f"IOCs Identified: {alert.get('ioc_count', 0)} | "
            f"KEV Status: {'Confirmed' if alert.get('kev_confirmed') else 'Not in KEV'}."
        )

    def _build_timeline(self, triage: Dict, investigation: Dict, response: Dict) -> List[Dict]:
        events = [
            {"time": triage.get("triaged_at",""), "tier": "T1", "event": "Alert triaged and prioritized"},
            {"time": investigation.get("investigated_at",""), "tier": "T2", "event": "Deep investigation completed"},
            {"time": response.get("responded_at",""), "tier": "T3", "event": "Response playbook generated"},
        ]
        return [e for e in events if e["time"]]

    def _save_report(self, incident_id: str, report: Dict) -> None:
        try:
            path = os.path.join(REPORT_DIR, f"{incident_id}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error(f"[REPORTER] Failed to save report: {e}")

    def load_recent_incidents(self, limit: int = 10) -> List[Dict]:
        """Load most recent incident reports."""
        reports = []
        try:
            files = sorted(
                [f for f in os.listdir(REPORT_DIR) if f.startswith("INC-") and f.endswith(".json")],
                reverse=True
            )[:limit]
            for fn in files:
                with open(os.path.join(REPORT_DIR, fn), encoding="utf-8") as f:
                    reports.append(json.load(f))
        except Exception as e:
            logger.error(f"[REPORTER] Error loading incidents: {e}")
        return reports
