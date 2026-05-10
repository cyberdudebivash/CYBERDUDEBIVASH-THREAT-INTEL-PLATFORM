"""
CYBERDUDEBIVASH® SENTINEL APEX
APEX INTELLIGENCE ENGINE v1.0 — MASTER INTEGRATION
Wires all 12 feature engines + Phase 1-6 Enterprise Quality Engines.
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
    Master intelligence engine — unified pipeline for all 12 features
    plus Phase 1-6 Enterprise Intelligence Quality Engines.
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
        # Phase 1-6: Enterprise Intelligence Quality Engines
        self._ioc_depth_recovery = None
        self._graph_correlation  = None
        self._attck_context      = None
        self._explainable_conf   = None
        self._intel_memory_aging = None
        # Phase 1-10: Enterprise Observability + Trust Validation Engines
        self._graph_integrity    = None
        self._intel_repro        = None
        self._scoring_drift      = None
        self._enrich_obs         = None
        self._ioc_quality        = None
        self._attck_coverage     = None
        self._actor_clustering   = None
        self._fp_obs             = None
        self._obs_dashboard      = None
        self._saas_hardening     = None
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

        # Phase 1-6: Enterprise Intelligence Quality Engines (lazy, non-blocking)
        try:
            from agent.ioc_depth_recovery_engine     import IOCDepthRecoveryEngine
            from agent.graph_correlation_engine      import GraphCorrelationEngine
            from agent.attck_context_engine          import ATTCKContextEngine
            from agent.explainable_confidence_engine import ExplainableConfidenceEngine
            from agent.intel_memory_aging_engine     import IntelMemoryAgingEngine
            self._ioc_depth_recovery = IOCDepthRecoveryEngine()
            self._graph_correlation  = GraphCorrelationEngine()
            self._attck_context      = ATTCKContextEngine()
            self._explainable_conf   = ExplainableConfidenceEngine()
            self._intel_memory_aging = IntelMemoryAgingEngine()
            logger.info("[APEX-ENGINE] Phase 1-6 Enterprise Quality Engines initialized")
        except Exception as e:
            logger.warning(f"[APEX-ENGINE] Enterprise Quality Engines partial init: {e}")

        # Phase 1-10: Enterprise Observability + Trust Validation Engines (lazy, non-blocking)
        try:
            from agent.graph_integrity_validator          import GraphIntegrityValidator
            from agent.intelligence_reproducibility_engine import IntelligenceReproducibilityEngine
            from agent.scoring_drift_engine               import ScoringDriftEngine
            from agent.enrichment_observability_engine    import EnrichmentObservabilityEngine
            from agent.ioc_quality_metrics_engine         import IOCQualityMetricsEngine
            from agent.attck_coverage_analytics_engine    import ATTCKCoverageAnalyticsEngine
            from agent.actor_clustering_confidence_engine import ActorClusteringConfidenceEngine
            from agent.false_positive_observability_engine import FalsePositiveObservabilityEngine
            from agent.observability_dashboard_engine     import ObservabilityDashboardEngine
            from agent.saas_scale_hardening_engine        import SaaSScaleHardeningEngine
            self._graph_integrity  = GraphIntegrityValidator()
            self._intel_repro      = IntelligenceReproducibilityEngine()
            self._scoring_drift    = ScoringDriftEngine()
            self._enrich_obs       = EnrichmentObservabilityEngine()
            self._ioc_quality      = IOCQualityMetricsEngine()
            self._attck_coverage   = ATTCKCoverageAnalyticsEngine()
            self._actor_clustering = ActorClusteringConfidenceEngine()
            self._fp_obs           = FalsePositiveObservabilityEngine()
            self._obs_dashboard    = ObservabilityDashboardEngine()
            self._saas_hardening   = SaaSScaleHardeningEngine()
            logger.info("[APEX-ENGINE] Phase 1-10 Observability + Trust Validation Engines initialized")
        except Exception as e:
            logger.warning(f"[APEX-ENGINE] Observability Engines partial init: {e}")

    def process_advisory(self, advisory: Dict) -> Dict:
        """
        Full pipeline for a single advisory.
        Returns unified intelligence package — no engine failure blocks others.
        """
        self._lazy_init()
        results: Dict[str, Any] = {
            "status":         "PROCESSING",
            "advisory_id":    advisory.get("stix_id", ""),
            "advisory_title": advisory.get("title", "")[:80],
            "processed_at":   datetime.now(timezone.utc).isoformat(),
        }

        # 1. SCORING ENGINE
        try:
            if self._scoring:
                results["risk_scoring"] = self._scoring.score_advisory(advisory)
        except Exception as e:
            logger.debug(f"[APEX] scoring error: {e}")

        # 2. AUTONOMOUS SOC — T1 triage
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

        # 3. THREAT GRAPH — ingest advisory
        try:
            if self._graph:
                results["graph_ingest"] = self._graph.ingest_advisory(advisory)
        except Exception as e:
            logger.debug(f"[APEX] graph error: {e}")

        # 4. PREDICTIVE — behavioral anomaly
        try:
            if self._behavioral:
                results["anomaly_detection"] = self._behavioral.detect_anomaly(advisory)
                self._behavioral.feed(advisory)
            if self._predictive:
                self._predictive.ingest_advisories([advisory])
        except Exception as e:
            logger.debug(f"[APEX] predictive error: {e}")

        # 5. ORCHESTRATION
        try:
            if self._orchestrator:
                orch = self._orchestrator.run(advisory)
                results["orchestration"] = {
                    "hunt_priority":  orch.get("hunt_package", {}).get("priority"),
                    "malware_family": orch.get("malware_report", {}).get(
                        "malware_classification", {}).get("primary_family"),
                    "patch_priority": orch.get("patch_guidance", {}).get(
                        "patch_priority", {}).get("priority"),
                    "action_summary": orch.get("action_summary", [])[:3],
                }
                self.stats["hunts_created"] += 1
        except Exception as e:
            logger.debug(f"[APEX] orchestration error: {e}")

        # 6. SUPPLY CHAIN
        try:
            if self._supply_chain:
                sc = self._supply_chain.scan_advisory_for_supply_chain(advisory)
                if sc.get("is_supply_chain_threat"):
                    results["supply_chain"] = sc
        except Exception as e:
            logger.debug(f"[APEX] supply_chain error: {e}")

        # 7. SOCIAL ENGINEERING
        try:
            if self._social_eng:
                se = self._social_eng.analyze_advisory(advisory)
                if se.get("is_social_eng"):
                    results["social_engineering"] = se
        except Exception as e:
            logger.debug(f"[APEX] social_eng error: {e}")

        # 8. QUANTUM
        try:
            if self._quantum:
                qr = self._quantum.assess_advisory(advisory)
                if qr.get("is_crypto_relevant"):
                    results["quantum_assessment"] = qr
        except Exception as e:
            logger.debug(f"[APEX] quantum error: {e}")

        # 9. COPILOT INDEX
        try:
            if self._copilot:
                self._copilot.index_advisories([advisory])
        except Exception as e:
            logger.debug(f"[APEX] copilot index error: {e}")

        # ── ENTERPRISE INTELLIGENCE QUALITY ENGINES (Phase 1-6) ──────────────

        # Phase 1: IOC Depth Recovery
        try:
            if self._ioc_depth_recovery:
                ioc_result = self._ioc_depth_recovery.recover(advisory)
                results["ioc_depth_recovery"] = {
                    "recovery_strategy":  ioc_result.recovery_strategy,
                    "ioc_count":          ioc_result.ioc_count,
                    "intelligence_depth": ioc_result.intelligence_depth,
                    "traceability_score": ioc_result.traceability_score,
                }
                if not advisory.get("iocs") and ioc_result.iocs:
                    advisory["iocs"] = [
                        {"type": ioc.ioc_type, "value": ioc.value,
                         "confidence": ioc.confidence, "context": ioc.context}
                        for ioc in ioc_result.iocs
                    ]
        except Exception as e:
            logger.debug(f"[APEX] ioc_depth_recovery error: {e}")

        # Phase 3: ATT&CK Contextualization
        try:
            if self._attck_context:
                ctx = self._attck_context.contextualize(advisory)
                results["attck_context"] = {
                    "behavioral_maturity":  ctx.adversary_profile.behavioral_maturity,
                    "sophistication_score": ctx.adversary_profile.sophistication_score,
                    "kill_chain_coverage":  ctx.adversary_profile.kill_chain_coverage,
                    "estimated_dwell_days": ctx.adversary_profile.estimated_dwell_days,
                    "inferred_path":        ctx.inferred_path[:3],
                    "attck_confidence":     ctx.attck_confidence,
                    "enterprise_impacts":   [i["impact_type"] for i in ctx.enterprise_impacts[:3]],
                }
        except Exception as e:
            logger.debug(f"[APEX] attck_context error: {e}")

        # Phase 4: Explainable Confidence
        try:
            if self._explainable_conf:
                audit, lineage = self._explainable_conf.score(advisory)
                results["explainable_confidence"] = {
                    "final_confidence": audit.final_confidence,
                    "confidence_tier":  audit.confidence_tier,
                    "score_hash":       audit.score_hash,
                    "rationale":        audit.rationale,
                    "recommendation":   audit.recommendation,
                    "dimension_summary": audit.dimension_summary,
                }
        except Exception as e:
            logger.debug(f"[APEX] explainable_confidence error: {e}")

        self.stats["advisories_processed"] += 1
        results["status"] = "PROCESSED"
        results["apex_stats"] = self.stats.copy()

        logger.info(
            f"[APEX-ENGINE] Processed: {advisory.get('title','')[:50]} | "
            f"engines=phase1-6+legacy"
        )
        return results

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
        """Full engine health check including Phase 1-6 Enterprise Engines."""
        self._lazy_init()
        engines = {
            "soc":                    self._soc is not None,
            "threat_graph":           self._graph is not None,
            "predictive":             self._predictive is not None,
            "orchestrator":           self._orchestrator is not None,
            "redteam":                self._redteam is not None,
            "scoring":                self._scoring is not None,
            "zero_trust":             self._zerotrust is not None,
            "copilot":                self._copilot is not None,
            "supply_chain":           self._supply_chain is not None,
            "social_eng":             self._social_eng is not None,
            "quantum":                self._quantum is not None,
            "marketplace":            self._marketplace is not None,
            # Enterprise Quality Engines (Phase 1-6)
            "ioc_depth_recovery":     self._ioc_depth_recovery is not None,
            "graph_correlation":      self._graph_correlation is not None,
            "attck_context":          self._attck_context is not None,
            "explainable_confidence": self._explainable_conf is not None,
            "intel_memory_aging":     self._intel_memory_aging is not None,
            # Enterprise Observability Engines (Phase 1-10)
            "graph_integrity":        self._graph_integrity is not None,
            "intel_reproducibility":  self._intel_repro is not None,
            "scoring_drift":          self._scoring_drift is not None,
            "enrichment_obs":         self._enrich_obs is not None,
            "ioc_quality":            self._ioc_quality is not None,
            "attck_coverage":         self._attck_coverage is not None,
            "actor_clustering":       self._actor_clustering is not None,
            "fp_observability":       self._fp_obs is not None,
            "obs_dashboard":          self._obs_dashboard is not None,
            "saas_hardening":         self._saas_hardening is not None,
        }
        return {
            "engine": "CYBERDUDEBIVASH Apex Intelligence Engine v1.0 + Observability v1",
            "status": "OPERATIONAL" if all(engines.values()) else "PARTIAL",
            "engines_online": sum(engines.values()),
            "engines_total":  len(engines),
            "engines":        engines,
            "stats":          self.stats,
            "checked_at":     datetime.now(timezone.utc).isoformat(),
        }


# Singleton instance for pipeline use
_apex_engine_instance: Optional[ApexIntelligenceEngine] = None


def get_apex_engine() -> ApexIntelligenceEngine:
    """Get or create the singleton ApexIntelligenceEngine instance."""
    global _apex_engine_instance
    if _apex_engine_instance is None:
        _apex_engine_instance = ApexIntelligenceEngine()
    return _apex_engine_instance
