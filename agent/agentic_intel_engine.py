#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX                                            ║
║  AGENTIC AI + PREDICTIVE THREAT INTELLIGENCE ENGINE v1.0                  ║
║  Multi-Agent Orchestration · Supply Chain · Confidence Scoring            ║
╚══════════════════════════════════════════════════════════════════════════════╝
Zero-regression · Deterministic · Idempotent · Safe retry · Fallback on error
"""

import os
import sys
import json
import math
import hashlib
import logging
import statistics
import tempfile
from collections import defaultdict, Counter
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-AGENTIC-INTEL")
logging.basicConfig(level=logging.INFO, format="[AGENTIC-INTEL] %(asctime)s %(levelname)s %(message)s")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH   = os.path.join(BASE_DIR, "data", "enriched_manifest.json")
OUTPUT_DIR      = os.path.join(BASE_DIR, "data", "agentic_intel")
PREDICTIONS_OUT = os.path.join(OUTPUT_DIR, "predictions.json")
SUPPLY_CHAIN_OUT= os.path.join(OUTPUT_DIR, "supply_chain_risks.json")
AGENT_SIGNALS   = os.path.join(OUTPUT_DIR, "agent_signals.json")
ENGINE_META     = os.path.join(OUTPUT_DIR, "engine_meta.json")

# ── Confidence thresholds ──────────────────────────────────────────────────────
CONFIDENCE = {"HIGH": 0.80, "MEDIUM": 0.55, "LOW": 0.35, "NOISE": 0.0}

# ── Known supply-chain ecosystems ─────────────────────────────────────────────
SUPPLY_CHAIN_INDICATORS = {
    "npm":        ["npm", "node_modules", "package.json", "yarn"],
    "pypi":       ["pip", "pypi", "requirements.txt", "setup.py", "poetry"],
    "maven":      ["maven", "gradle", "pom.xml", "mvn", "springframework"],
    "docker":     ["docker", "container", "kubernetes", "k8s", "helm"],
    "github_actions": ["github actions", "workflow", ".yml", "ci/cd"],
    "cloud_sdk":  ["aws sdk", "azure sdk", "gcp sdk", "boto3", "google-cloud"],
    "openssl":    ["openssl", "tls", "ssl", "libssl", "openssl-devel"],
    "log4j":      ["log4j", "log4shell", "jndi", "jndilookup"],
    "xz":         ["xz-utils", "liblzma", "xz"],
    "polyfill":   ["polyfill.io", "polyfill", "cdn.polyfill"],
}

# ── Tech stack risk weights ───────────────────────────────────────────────────
TECH_RISK_WEIGHTS = {
    "log4j": 9.5, "xz": 9.2, "openssl": 8.0, "docker": 7.0,
    "npm": 6.5, "pypi": 6.0, "github_actions": 5.5, "cloud_sdk": 5.0,
    "maven": 5.0, "polyfill": 8.5,
}

# ── Threat actor TTP signatures ───────────────────────────────────────────────
ACTOR_TTP_PATTERNS = {
    "LockBit":      ["ransomware", "lockbit", "double extortion", "data leak", "T1486"],
    "APT29":        ["cozy bear", "apt29", "nobelium", "solorigate", "supply chain", "T1195"],
    "APT41":        ["apt41", "winnti", "double dragon", "espionage", "supply chain"],
    "Lazarus":      ["lazarus", "hidden cobra", "dprk", "north korea", "financial"],
    "Cl0p":         ["clop", "cl0p", "moveit", "progress software", "zero-day", "T1190"],
    "BlackCat":     ["alphv", "blackcat", "ransomware-as-a-service", "exfiltration"],
    "Volt Typhoon": ["volt typhoon", "living off land", "lolbas", "critical infrastructure"],
    "Salt Typhoon": ["salt typhoon", "telecom", "wiretap", "cisco", "ivanti"],
}


def _atomic_write(path: str, data: Any) -> None:
    """Atomic write: temp → rename, never corrupts on crash."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def _load_manifest() -> List[Dict]:
    """Load enriched manifest with graceful fallback."""
    for candidate in [MANIFEST_PATH,
                      os.path.join(BASE_DIR, "data", "advisory_manifest.json"),
                      os.path.join(BASE_DIR, "data", "stix", "manifest.json")]:
        if os.path.exists(candidate):
            try:
                with open(candidate, encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else data.get("advisories", [])
            except Exception as e:
                logger.warning(f"Failed to load {candidate}: {e}")
    return []


def _confidence_score(signals: List[float]) -> float:
    """Aggregate multiple confidence signals into a single score [0,1]."""
    if not signals:
        return 0.0
    return min(1.0, sum(signals) / len(signals) + (0.05 * math.log1p(len(signals))))


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 1: Supply Chain Analysis Agent
# ──────────────────────────────────────────────────────────────────────────────
class SupplyChainAgent:
    """
    Analyzes tech stack + dependencies mentioned in advisories.
    Predicts potential supply-chain threats before exploitation.
    """

    def __init__(self):
        self.detected_components: Dict[str, int] = defaultdict(int)
        self.risk_signals: List[Dict] = []

    def analyze(self, advisories: List[Dict]) -> Dict:
        results = []
        for adv in advisories:
            text = " ".join([
                adv.get("title", ""), adv.get("summary", ""),
                adv.get("description", ""), str(adv.get("tags", [])),
            ]).lower()

            for ecosystem, keywords in SUPPLY_CHAIN_INDICATORS.items():
                hits = [kw for kw in keywords if kw in text]
                if hits:
                    self.detected_components[ecosystem] += 1
                    risk = TECH_RISK_WEIGHTS.get(ecosystem, 5.0)
                    results.append({
                        "advisory_id": adv.get("id", ""),
                        "cve_id": adv.get("cve_id", ""),
                        "ecosystem": ecosystem,
                        "trigger_keywords": hits[:3],
                        "risk_score": risk,
                        "confidence": min(1.0, 0.5 + len(hits) * 0.15),
                    })

        top_ecosystems = sorted(
            [(k, v) for k, v in self.detected_components.items()],
            key=lambda x: -x[1]
        )[:10]

        return {
            "supply_chain_risks": results[:500],
            "top_vulnerable_ecosystems": [
                {"ecosystem": e, "advisory_count": c,
                 "risk_weight": TECH_RISK_WEIGHTS.get(e, 5.0)} for e, c in top_ecosystems
            ],
            "total_supply_chain_risks": len(results),
            "unique_ecosystems": len(self.detected_components),
        }


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 2: Threat Actor Attribution Agent
# ──────────────────────────────────────────────────────────────────────────────
class ThreatActorAgent:
    """
    Attributes advisories to known threat actors via TTP signature matching.
    """

    def __init__(self):
        self.actor_counts: Dict[str, int] = defaultdict(int)
        self.actor_cves: Dict[str, List[str]] = defaultdict(list)

    def analyze(self, advisories: List[Dict]) -> Dict:
        attributions = []
        for adv in advisories:
            text = " ".join([
                adv.get("title", ""), adv.get("summary", ""),
                adv.get("actors", ""), str(adv.get("mitre_techniques", [])),
            ]).lower()

            matched_actors = []
            for actor, patterns in ACTOR_TTP_PATTERNS.items():
                score = sum(1 for p in patterns if p.lower() in text)
                if score >= 1:
                    conf = min(1.0, 0.4 + score * 0.2)
                    matched_actors.append({"actor": actor, "match_count": score, "confidence": conf})
                    self.actor_counts[actor] += 1
                    cve = adv.get("cve_id", "")
                    if cve:
                        self.actor_cves[actor].append(cve)

            if matched_actors:
                attributions.append({
                    "advisory_id": adv.get("id", ""),
                    "cve_id": adv.get("cve_id", ""),
                    "attributed_actors": sorted(matched_actors, key=lambda x: -x["confidence"]),
                    "primary_actor": matched_actors[0]["actor"] if matched_actors else "UNKNOWN",
                })

        actor_profiles = {}
        for actor, count in self.actor_counts.items():
            actor_profiles[actor] = {
                "advisory_count": count,
                "associated_cves": list(set(self.actor_cves[actor]))[:20],
                "threat_level": "CRITICAL" if count >= 5 else "HIGH" if count >= 2 else "MEDIUM",
            }

        return {
            "attributions": attributions[:300],
            "actor_profiles": actor_profiles,
            "total_attributed": len(attributions),
            "actors_detected": len(self.actor_counts),
        }


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 3: Predictive Threat Forecaster
# ──────────────────────────────────────────────────────────────────────────────
class PredictiveForecaster:
    """
    Forecasts future threat trends using statistical analysis of historical data.
    Zero hallucination: only predicts from observed signal patterns.
    """

    def __init__(self):
        self.ttp_freq: Dict[str, int] = defaultdict(int)
        self.severity_counts: Dict[str, int] = defaultdict(int)
        self.kev_count = 0
        self.epss_values: List[float] = []
        self.weaponized_count = 0

    def ingest(self, advisories: List[Dict]) -> None:
        for adv in advisories:
            sev = adv.get("severity", "MEDIUM").upper()
            self.severity_counts[sev] += 1
            for ttp in adv.get("mitre_techniques", []):
                self.ttp_freq[ttp] += 1
            if adv.get("kev_confirmed") or adv.get("ei_kev_confirmed"):
                self.kev_count += 1
            epss = adv.get("epss") or adv.get("ei_epss") or 0
            try:
                self.epss_values.append(float(epss))
            except (TypeError, ValueError):
                pass
            status = adv.get("ei_exploit_status", "")
            if status in ("WEAPONIZED", "EXPLOITED_IN_WILD"):
                self.weaponized_count += 1

    def forecast(self) -> Dict:
        total = sum(self.severity_counts.values()) or 1
        critical_rate = (self.severity_counts.get("CRITICAL", 0) +
                         self.severity_counts.get("HIGH", 0)) / total

        epss_mean = statistics.mean(self.epss_values) if self.epss_values else 0.0
        epss_stdev = statistics.stdev(self.epss_values) if len(self.epss_values) > 1 else 0.0

        top_ttps = sorted(self.ttp_freq.items(), key=lambda x: -x[1])[:15]
        kev_rate = self.kev_count / total
        weaponized_rate = self.weaponized_count / total

        # Threat surge prediction: if critical rate > 40% or kev_rate > 20% → surge likely
        surge_confidence = _confidence_score([
            min(1.0, critical_rate * 2.0),
            min(1.0, kev_rate * 4.0),
            min(1.0, weaponized_rate * 3.0),
            min(1.0, epss_mean * 5.0),
        ])

        predictions = []

        if surge_confidence >= CONFIDENCE["HIGH"]:
            predictions.append({
                "prediction": "CRITICAL THREAT SURGE IMMINENT",
                "confidence": round(surge_confidence, 4),
                "evidence": f"KEV rate={kev_rate:.1%}, weaponized={weaponized_rate:.1%}, critical_rate={critical_rate:.1%}",
                "recommended_action": "Activate incident response, patch KEV items immediately",
                "horizon": "72 hours",
            })
        elif surge_confidence >= CONFIDENCE["MEDIUM"]:
            predictions.append({
                "prediction": "ELEVATED THREAT ENVIRONMENT",
                "confidence": round(surge_confidence, 4),
                "evidence": f"EPSS mean={epss_mean:.3f}, kev_count={self.kev_count}",
                "recommended_action": "Increase monitoring, review patch backlog",
                "horizon": "7 days",
            })

        # TTP-based predictions
        if self.ttp_freq.get("T1486", 0) >= 3 or self.ttp_freq.get("T1485", 0) >= 2:
            predictions.append({
                "prediction": "RANSOMWARE CAMPAIGN LIKELY",
                "confidence": min(1.0, 0.6 + self.ttp_freq.get("T1486", 0) * 0.05),
                "evidence": f"T1486 freq={self.ttp_freq.get('T1486', 0)}, T1485 freq={self.ttp_freq.get('T1485', 0)}",
                "recommended_action": "Verify backup integrity, enable EDR policies",
                "horizon": "30 days",
            })

        if self.ttp_freq.get("T1190", 0) >= 5 or self.ttp_freq.get("T1566", 0) >= 5:
            predictions.append({
                "prediction": "MASS EXPLOITATION WAVE PREDICTED",
                "confidence": min(1.0, 0.55 + (self.ttp_freq.get("T1190", 0) + self.ttp_freq.get("T1566", 0)) * 0.02),
                "evidence": f"T1190 (exploit)={self.ttp_freq.get('T1190', 0)}, T1566 (phish)={self.ttp_freq.get('T1566', 0)}",
                "recommended_action": "WAF rules, phishing simulation, patch public-facing apps",
                "horizon": "14 days",
            })

        if self.ttp_freq.get("T1195", 0) >= 2 or self.ttp_freq.get("T1199", 0) >= 2:
            predictions.append({
                "prediction": "SUPPLY CHAIN ATTACK VECTOR ACTIVE",
                "confidence": min(1.0, 0.65 + self.ttp_freq.get("T1195", 0) * 0.05),
                "evidence": f"T1195={self.ttp_freq.get('T1195', 0)}, T1199={self.ttp_freq.get('T1199', 0)}",
                "recommended_action": "Audit third-party dependencies, SBOM review",
                "horizon": "14 days",
            })

        return {
            "predictions": predictions,
            "threat_metrics": {
                "total_advisories": total,
                "critical_high_rate": round(critical_rate, 4),
                "kev_rate": round(kev_rate, 4),
                "weaponized_rate": round(weaponized_rate, 4),
                "epss_mean": round(epss_mean, 4),
                "epss_stdev": round(epss_stdev, 4),
                "top_ttps": [{"ttp": t, "frequency": c} for t, c in top_ttps],
                "surge_confidence": round(surge_confidence, 4),
            },
            "severity_distribution": dict(self.severity_counts),
        }


# ──────────────────────────────────────────────────────────────────────────────
# AGENT 4: Signal Verification Agent
# ──────────────────────────────────────────────────────────────────────────────
class SignalVerificationAgent:
    """
    Cross-validates threat signals from multiple advisory sources.
    Filters noise, boosts corroborated signals.
    """

    def __init__(self):
        self.cve_cross_refs: Dict[str, int] = defaultdict(int)
        self.ioc_occurrences: Dict[str, int] = defaultdict(int)

    def verify(self, advisories: List[Dict]) -> Dict:
        # Count how many times each CVE appears across advisories (corroboration)
        for adv in advisories:
            cve = adv.get("cve_id", "")
            if cve and cve.startswith("CVE-"):
                self.cve_cross_refs[cve] += 1
            for ioc in adv.get("iocs", []):
                self.ioc_occurrences[str(ioc)[:100]] += 1

        # High-corroboration = multiple independent sources confirm
        verified_cves = {k: v for k, v in self.cve_cross_refs.items() if v >= 2}
        verified_iocs = {k: v for k, v in self.ioc_occurrences.items() if v >= 2}

        return {
            "verified_cves": [{"cve": k, "source_count": v} for k, v in
                               sorted(verified_cves.items(), key=lambda x: -x[1])[:50]],
            "verified_iocs": [{"ioc": k, "occurrence_count": v} for k, v in
                               sorted(verified_iocs.items(), key=lambda x: -x[1])[:50]],
            "total_unique_cves": len(self.cve_cross_refs),
            "total_unique_iocs": len(self.ioc_occurrences),
            "high_corroboration_cves": len(verified_cves),
            "noise_filtered": len(self.cve_cross_refs) - len(verified_cves),
        }


# ──────────────────────────────────────────────────────────────────────────────
# MULTI-AGENT ORCHESTRATOR
# ──────────────────────────────────────────────────────────────────────────────
class AgenticIntelOrchestrator:
    """
    Orchestrates all agents, merges outputs, patches manifest, writes results.
    """

    def __init__(self):
        self.supply_chain_agent = SupplyChainAgent()
        self.actor_agent = ThreatActorAgent()
        self.forecaster = PredictiveForecaster()
        self.verifier = SignalVerificationAgent()

    def run(self) -> int:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        logger.info("=== AGENTIC INTEL ENGINE START ===")

        advisories = _load_manifest()
        if not advisories:
            logger.warning("No advisories found — writing empty outputs")
            self._write_empty()
            return 0

        logger.info(f"Loaded {len(advisories)} advisories for multi-agent analysis")

        # Run all 4 agents
        logger.info("[AGENT-1] Supply Chain Analysis...")
        sc_result = self.supply_chain_agent.analyze(advisories)

        logger.info("[AGENT-2] Threat Actor Attribution...")
        actor_result = self.actor_agent.analyze(advisories)

        logger.info("[AGENT-3] Predictive Forecasting...")
        self.forecaster.ingest(advisories)
        forecast_result = self.forecaster.forecast()

        logger.info("[AGENT-4] Signal Verification...")
        verify_result = self.verifier.verify(advisories)

        # Enrich manifest (non-destructive, prefixed fields)
        enriched = 0
        actor_map = {a["advisory_id"]: a for a in actor_result.get("attributions", [])}
        for adv in advisories:
            aid = adv.get("id", "")
            if aid in actor_map:
                adv["ai_actor_attribution"] = actor_map[aid].get("primary_actor", "")
                adv["ai_actor_confidence"] = actor_map[aid].get("attributed_actors", [{}])[0].get("confidence", 0)
                enriched += 1

        # Atomic write all outputs
        combined_signals = {
            "supply_chain": sc_result,
            "actor_attribution": actor_result,
            "forecast": forecast_result,
            "verification": verify_result,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(AGENT_SIGNALS, combined_signals)
        _atomic_write(SUPPLY_CHAIN_OUT, sc_result)
        _atomic_write(PREDICTIONS_OUT, {
            "predictions": forecast_result["predictions"],
            "threat_metrics": forecast_result["threat_metrics"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        })

        meta = {
            "engine": "AgenticIntelOrchestrator",
            "version": "1.0.0",
            "advisories_processed": len(advisories),
            "predictions_generated": len(forecast_result["predictions"]),
            "supply_chain_risks": sc_result["total_supply_chain_risks"],
            "actor_attributions": actor_result["total_attributed"],
            "actors_detected": actor_result["actors_detected"],
            "verified_cves": verify_result["high_corroboration_cves"],
            "manifest_enriched": enriched,
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(ENGINE_META, meta)

        logger.info(f"Predictions: {meta['predictions_generated']}")
        logger.info(f"Supply chain risks: {meta['supply_chain_risks']}")
        logger.info(f"Actors detected: {meta['actors_detected']}")
        logger.info(f"Verified CVEs: {meta['verified_cves']}")
        logger.info("=== AGENTIC INTEL ENGINE COMPLETE ===")
        return 0

    def _write_empty(self) -> None:
        empty_meta = {
            "engine": "AgenticIntelOrchestrator", "version": "1.0.0",
            "advisories_processed": 0, "predictions_generated": 0,
            "run_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        _atomic_write(ENGINE_META, empty_meta)
        _atomic_write(PREDICTIONS_OUT, {"predictions": [], "threat_metrics": {}})
        _atomic_write(AGENT_SIGNALS, {})


def main() -> int:
    try:
        orchestrator = AgenticIntelOrchestrator()
        return orchestrator.run()
    except Exception as e:
        logger.error(f"AgenticIntelEngine fatal: {e}", exc_info=True)
        try:
            _atomic_write(ENGINE_META, {
                "engine": "AgenticIntelOrchestrator", "version": "1.0.0",
                "error": str(e)[:500], "run_timestamp": datetime.now(timezone.utc).isoformat(),
            })
        except Exception:
            pass
        return 0  # Never fail pipeline


if __name__ == "__main__":
    sys.exit(main())
