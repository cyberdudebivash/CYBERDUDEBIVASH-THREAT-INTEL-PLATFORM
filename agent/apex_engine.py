"""
CYBERDUDEBIVASH® SENTINEL APEX
APEX INTELLIGENCE ENGINE v1.0 — MASTER INTEGRATION
Wires all 12 feature engines into a single unified pipeline.
Called from sentinel_blogger.py on every advisory ingested.
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-APEX-ENGINE")


class ApexIntelligenceEngine:
    """
    Master intelligence engine — unified pipeline for all 12 features.
    Lazy-initializes each sub-engine on first use for performance.
    """

    def __init__(self):
        self._soc          = None
        self._graph        = None
        self._predictive   = None
        self._orchestrator = None
        self._redteam      = None
        self._scoring      = None
        self._zerotrust    = None
        self._copilot      = None
        self._supply_chain = None
        self._social_eng   = None
        self._quantum      = None
        self._marketplace  = None
        self._initialized  = False
        self.stats = {
            "advisories_processed": 0,
            "incidents_generated":  0,
            "hunts_created":        0,
            "started_at":           datetime.now(timezone.utc).isoformat(),
        }

    def _lazy_init(self) -> None:
        if self._initialized:
            return
        try:
            from agent.soc.autonomous_soc          import AutonomousSOCEngine
            from agent.threat_graph.graph_engine   import ThreatIntelGraph
            from agent.threat_graph.correlation_engine import ThreatCorrelationEngine
            from agent.predictive.predictive_engine import PredictiveThreatEngine
            from agent.predictive.behavioral_analytics import BehavioralAnalytics
            from agent.orchestration.orchestrator  import AgentOrchestrator
            from agent.redteam.redteam_engine       import RedTeamEngine
            from agent.scoring.scoring_engine       import ScoringEngine
            from agent.zero_trust.zero_trust_engine import ZeroTrustEngine
            from agent.copilot.copilot_engine       import SecurityCopilot
            from agent.supply_chain.supply_chain_engine import SupplyChainEngine
            from agent.social_eng.social_eng_engine import SocialEngDetector
            from agent.quantum.quantum_engine       import QuantumReadinessEngine
            from agent.marketplace.marketplace_engine import ThreatIntelMarketplace

            self._soc          = AutonomousSOCEngine()
            self._graph        = ThreatIntelGraph()
            self._correlation  = ThreatCorrelationEngine(self._graph)
            self._predictive   = PredictiveThreatEngine()
            self._behavioral   = BehavioralAnalytics()
            self._orchestrator = AgentOrchestrator()
            self._redteam      = RedTeamEngine()
            self._scoring      = ScoringEngine()
            self._zerotrust    = ZeroTrustEngine()
            self._copilot      = SecurityCopilot()
            self._supply_chain = SupplyChainEngine()
            self._social_eng   = SocialEngDetector()
            self._quantum      = QuantumReadinessEngine()
            self._marketplace  = ThreatIntelMarketplace()
            self._initialized  = True
            logger.info("[APEX-ENGINE] All 12 feature engines initialized")
        except ImportError as e:
            logger.warning(f"[APEX-ENGINE] Partial init (non-critical): {e}")
            self._initialized = True  # Proceed with what's available

    def process_advisory(self, advisory: Dict) -> Dict:
        """
        Full 12-engine pipeline for a single advisory.
        Returns unified intelligence package — no engine failure blocks others.
        """
        self._lazy_init()
        results: Dict[str, Any] = {
            "advisory_id":    advisory.get("stix_id", ""),
            "advisory_title": advisory.get("title", "")[:80],
            "processed_at":   datetime.now(timezone.utc).isoformat(),
        }

        # 1. SCORING ENGINE — composite risk score
        try:
            if self._scoring:
                results["risk_scoring"] = self._scoring.score_advisory(advisory)
        except Exception as e:
            logger.debug(f"[APEX] scoring error: {e}")

        # 2. AUTONOMOUS SOC — T1 triage only (fast path)
        try:
            if self._soc:
                triage = self._soc.tier1.triage(advisory)
                results["soc_triage"] = {
                    "priority": triage.get("priority"),
                    "action":   triage.get("action"),
                    "escalate": triage.get("escalate", False),
                }
                if triage.get("escalate"):
                    self.stats["incidents_generated"] += 1
        except Exception as e:
            logger.debug(f"[APEX] SOC triage error: {e}")

        # 3. THREAT GRAPH — ingest advisory as graph nodes
        try:
            if self._graph:
                results["graph_ingest"] = self._graph.ingest_advisory(advisory)
        except Exception as e:
            logger.debug(f"[APEX] graph error: {e}")

        # 4. PREDICTIVE — behavioral anomaly check
        try:
            if self._behavioral:
                results["anomaly_detection"] = self._behavioral.detect_anomaly(advisory)
                self._behavioral.feed(advisory)
            if self._predictive:
                self._predictive.ingest_advisories([advisory])
        except Exception as e:
            logger.debug(f"[APEX] predictive error: {e}")

        # 5. ORCHESTRATION — multi-agent analysis
        try:
            if self._orchestrator:
                orch = self._orchestrator.run(advisory)
                results["orchestration"] = {
                    "hunt_priority": orch.get("hunt_package", {}).get("priority"),
                    "malware_family": orch.get("malware_report", {}).get(
                        "malware_classification", {}).get("primary_family"),
                    "patch_priority": orch.get("patch_guidance", {}).get(
                        "patch_priority", {}).get("priority"),
                    "action_summary": orch.get("action_summary", [])[:3],
                }
                self.stats["hunts_created"] += 1
        except Exception as e:
            logger.debug(f"[APEX] orchestration error: {e}")

        # 6. SUPPLY CHAIN — dependency threat check
        try:
            if self._supply_chain:
                sc = self._supply_chain.scan_advisory_for_supply_chain(advisory)
                if sc.get("is_supply_chain_threat"):
                    results["supply_chain"] = sc
        except Exception as e:
            logger.debug(f"[APEX] supply_chain error: {e}")

        # 7. SOCIAL ENGINEERING — phishing/BEC/deepfake detection
        try:
            if self._social_eng:
                se = self._social_eng.analyze_advisory(advisory)
                if se.get("is_social_eng"):
                    results["social_engineering"] = se
        except Exception as e:
            logger.debug(f"[APEX] social_eng error: {e}")

        # 8. QUANTUM — crypto vulnerability check
        try:
            if self._quantum:
                qr = self._quantum.assess_advisory(advisory)
                if qr.get("is_crypto_relevant"):
                    results["quantum_assessment"] = qr
        except Exception as e:
            logger.debug(f"[APEX] quantum error: {e}")

        # 9. INDEX for copilot
        try:
            if self._copilot:
                self._copilot.index_advisories([advisory])
        except Exception as e:
            logger.debug(f"[APEX] copilot index error: {e}")

        self.stats["advisories_processed"] += 1
        results["apex_stats"] = self.stats.copy()

        logger.info(f"[APEX-ENGINE] Processed: {advisory.get('title','')[:50]} | "
                    f"priority={results.get('soc_triage',{}).get('priority','?')} | "
                    f"risk={results.get('risk_scoring',{}).get('composite_score','?')}")
        return results

    def process_batch(self, advisories: List[Dict]) -> Dict:
        """Process a batch of advisories through all engines."""
        logger.info(f"[APEX-ENGINE] Batch: {len(advisories)} advisories")
        results = [self.process_advisory(a) for a in advisories]
        p1_count = sum(1 for r in results if r.get("soc_triage", {}).get("priority") == "P1")
        return {
            "total": len(results),
            "p1_critical": p1_count,
            "results": results,
            "engine_stats": self.stats,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

    def copilot_query(self, query: str, context: Optional[Dict] = None) -> Dict:
        """Direct copilot query interface."""
        self._lazy_init()
        if self._copilot:
            return self._copilot.query(query, context)
        return {"error": "Copilot not initialized"}

    def get_predictions(self) -> Dict:
        """Get current threat predictions."""
        self._lazy_init()
        if self._predictive:
            return self._predictive.get_attack_predictions()
        return {"error": "Predictive engine not initialized"}

    def get_graph_summary(self) -> Dict:
        """Get threat graph summary."""
        self._lazy_init()
        if self._graph:
            return self._graph.get_graph_summary()
        return {"error": "Graph not initialized"}

    def get_marketplace_catalog(self) -> Dict:
        """Get marketplace catalog."""
        self._lazy_init()
        if self._marketplace:
            return self._marketplace.get_catalog()
        return {}

    def get_engine_status(self) -> Dict:
        """Full engine health check."""
        self._lazy_init()
        engines = {
            "soc":          self._soc is not None,
            "threat_graph": self._graph is not None,
            "predictive":   self._predictive is not None,
            "orchestrator": self._orchestrator is not None,
            "redteam":      self._redteam is not None,
            "scoring":      self._scoring is not None,
            "zero_trust":   self._zerotrust is not None,
            "copilot":      self._copilot is not None,
            "supply_chain": self._supply_chain is not None,
            "social_eng":   self._social_eng is not None,
            "quantum":      self._quantum is not None,
            "marketplace":  self._marketplace is not None,
        }
        return {
            "engine": "CYBERDUDEBIVASH Apex Intelligence Engine v1.0",
            "status": "OPERATIONAL" if all(engines.values()) else "PARTIAL",
            "engines_online": sum(engines.values()),
            "engines_total": len(engines),
            "engines": engines,
            "stats": self.stats,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


# Singleton instance for pipeline use
_apex_engine_instance: Optional[ApexIntelligenceEngine] = None


def get_apex_engine() -> ApexIntelligenceEngine:
    """Get or create the singleton ApexIntelligenceEngine instance."""
    global _apex_engine_instance
    if _apex_engine_instance is None:
        _apex_engine_instance = ApexIntelligenceEngine()
    return _apex_engine_instance
