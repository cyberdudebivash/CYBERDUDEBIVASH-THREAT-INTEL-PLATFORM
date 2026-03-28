"""
CYBERDUDEBIVASH® SENTINEL APEX
AUTONOMOUS SOC ENGINE — Orchestrates all three tiers
The master controller: ingests alerts → runs T1→T2→T3 pipeline → generates reports.
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .triage_engine import Tier1TriageAgent
from .investigation_engine import Tier2InvestigationAgent
from .response_engine import Tier3ResponseAgent
from .incident_reporter import IncidentReporter
from .alert_prioritizer import AlertPrioritizer

logger = logging.getLogger("CDB-SOC-ENGINE")


class AutonomousSOCEngine:
    """
    Master SOC orchestrator — runs full T1→T2→T3 pipeline autonomously.
    Integrated with CYBERDUDEBIVASH threat intel pipeline.
    """

    def __init__(self):
        self.tier1 = Tier1TriageAgent()
        self.tier2 = Tier2InvestigationAgent()
        self.tier3 = Tier3ResponseAgent()
        self.reporter = IncidentReporter()
        self.prioritizer = AlertPrioritizer()
        self.processed_count = 0
        self.incident_count = 0

    def process_alert(self, alert: Dict) -> Dict:
        """
        Full autonomous pipeline: T1 → T2 → T3 → Report.
        Returns complete SOC response package.
        """
        try:
            logger.info(f"[SOC-ENGINE] Processing: {alert.get('title','')[:60]}")

            # TIER 1: Triage
            triage = self.tier1.triage(alert)

            if triage.get("status") in ("FALSE_POSITIVE", "DUPLICATE"):
                return {"status": triage["status"], "alert_id": triage.get("alert_id"), "pipeline_stage": "T1"}

            # TIER 2: Investigation (only for P1/P2)
            investigation = None
            if triage.get("escalate"):
                investigation = self.tier2.investigate(triage)
            else:
                # Light investigation for P3/P4
                investigation = {
                    "alert_id": triage.get("enriched_alert", {}).get("stix_id", ""),
                    "tier": "T2-LIGHT",
                    "status": "LIGHT_ANALYSIS",
                    "ttp_analysis": {"techniques": {}, "technique_count": 0},
                    "actor_attribution": {"suspected_actor": "UNKNOWN", "confidence": 0.0},
                    "blast_radius": {"blast_score": triage.get("priority_score", 0) * 0.6,
                                     "blast_level": "LIMITED", "impact_categories": []},
                    "containment_recommendations": triage.get("enriched_alert", {}).get("summary", "")[:200],
                    "investigated_at": datetime.now(timezone.utc).isoformat(),
                }

            # TIER 3: Response (only for P1/P2 or high blast radius)
            response = None
            blast_score = investigation.get("blast_radius", {}).get("blast_score", 0)
            if triage.get("escalate") or blast_score >= 6.0:
                response = self.tier3.respond(investigation)
                self.incident_count += 1
            else:
                response = {
                    "alert_id": investigation.get("alert_id", ""),
                    "tier": "T3-SKIP",
                    "status": "MONITORING",
                    "playbook": {"steps": [], "scenario": "MONITOR", "priority_actions": []},
                    "soar_actions": [],
                    "auto_executed_actions": [],
                    "responded_at": datetime.now(timezone.utc).isoformat(),
                }

            # Generate incident report for P1/P2
            report = None
            if triage.get("escalate"):
                report = self.reporter.generate_report(triage, investigation, response)

            self.processed_count += 1
            logger.info(f"[SOC-ENGINE] Complete: P={triage['priority']} | "
                        f"Actor={investigation['actor_attribution']['suspected_actor']} | "
                        f"Blast={investigation['blast_radius']['blast_level']}")

            return {
                "status": "PROCESSED",
                "pipeline_complete": True,
                "triage": triage,
                "investigation": investigation,
                "response": response,
                "incident_report": report,
                "processing_summary": {
                    "priority": triage.get("priority"),
                    "priority_score": triage.get("priority_score"),
                    "suspected_actor": investigation.get("actor_attribution", {}).get("suspected_actor"),
                    "blast_level": investigation.get("blast_radius", {}).get("blast_level"),
                    "incident_id": report.get("incident_id") if report else None,
                    "auto_actions_triggered": len(response.get("auto_executed_actions", [])),
                },
            }

        except Exception as e:
            logger.error(f"[SOC-ENGINE] Pipeline error: {e}", exc_info=True)
            return {"status": "PIPELINE_ERROR", "error": str(e), "alert": alert.get("title","")}

    def process_batch(self, alerts: List[Dict]) -> Dict:
        """Process a batch of alerts through the full SOC pipeline."""
        logger.info(f"[SOC-ENGINE] Batch processing {len(alerts)} alerts")
        results = []
        p1_incidents = []

        for alert in alerts:
            result = self.process_alert(alert)
            results.append(result)
            if result.get("processing_summary", {}).get("priority") == "P1":
                p1_incidents.append(result)

        summary = {
            "total_processed": len(results),
            "p1_critical": len(p1_incidents),
            "incidents_generated": self.incident_count,
            "false_positives_filtered": self.tier1.stats.get("fp_filtered", 0),
            "duplicates_removed": self.tier1.stats.get("duplicates", 0),
            "escalated_to_t2": self.tier1.stats.get("escalated", 0),
            "results": results,
            "p1_incidents": p1_incidents,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"[SOC-ENGINE] Batch complete: {len(p1_incidents)} P1 incidents")
        return summary

    def get_engine_status(self) -> Dict:
        return {
            "engine": "CYBERDUDEBIVASH Autonomous SOC v1.0",
            "status": "OPERATIONAL",
            "processed_total": self.processed_count,
            "incidents_total": self.incident_count,
            "tier1_stats": self.tier1.get_stats(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
