#!/usr/bin/env python3
"""
zerodayhunter_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v35.0 (ZERO-DAY HUNTER)
==================================================================================
Core Zero-Day Hunter Engine — detects early-stage attacks before mass exploitation.

Subsystems:
  1. ZeroDaySignalDetector  — Identifies potential zero-day exploitation chains
  2. AttackWaveDetector     — Detects coordinated campaign waves
  3. ThreatReasoningAI      — Generates contextual intelligence explanations
  4. EarlyWarningSystem     — Threshold-based predictive alerts
  5. PlaybookGenerator      — Automated incident response playbooks
  6. GlobalThreatIndex      — Daily composite cyber risk index

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os, json, hashlib, logging, math
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from agent.v35_zerodayhunter.signals.signal_pipeline import (
    SignalPipeline, ThreatSignal, SignalCluster, Forecast, MANIFEST_PATH
)

logger = logging.getLogger("CDB-ZeroDayHunter")
OUTPUT_DIR = os.environ.get("ZDH_OUTPUT_DIR", "data/zerodayhunter")


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ZERO-DAY SIGNAL DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ZeroDayAlert:
    alert_id: str; entity: str; alert_type: str; severity: str; title: str
    description: str; confidence: float; chain_evidence: List[str]
    exploitation_status: str  # potential, probable, confirmed, active
    indicators: List[str]; recommended_actions: List[str]; timestamp: str
    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items() if k != "raw"}


class ZeroDaySignalDetector:
    """Detects potential zero-day exploitation from correlated signal chains."""

    # Zero-day indicator combinations (each is a detection rule)
    ZERODAY_RULES = [
        {
            "name": "Classic Zero-Day Chain",
            "required": ["cve_pub", "poc_release"],
            "boost": ["scan_spike", "kev_add"],
            "min_confidence": 0.6,
            "severity": "CRITICAL",
        },
        {
            "name": "KEV Rapid Addition",
            "required": ["kev_add"],
            "boost": ["poc_release", "scan_spike"],
            "min_confidence": 0.9,
            "severity": "CRITICAL",
        },
        {
            "name": "Exploit-Scan Convergence",
            "required": ["poc_release", "scan_spike"],
            "boost": ["severity_spike", "ioc_volume"],
            "min_confidence": 0.65,
            "severity": "HIGH",
        },
        {
            "name": "Unpatched Critical CVE",
            "required": ["cve_pub", "patch_gap"],
            "boost": ["severity_spike", "actor_activity"],
            "min_confidence": 0.5,
            "severity": "HIGH",
        },
        {
            "name": "Actor-Driven Campaign",
            "required": ["actor_activity"],
            "boost": ["scan_spike", "ioc_volume", "severity_spike"],
            "min_confidence": 0.55,
            "severity": "HIGH",
        },
    ]

    def detect(self, clusters: List[SignalCluster], forecasts: List[Forecast]) -> List[ZeroDayAlert]:
        alerts = []
        forecast_map = {f.entity: f for f in forecasts}

        for cluster in clusters:
            for rule in self.ZERODAY_RULES:
                if not all(st in cluster.chain for st in rule["required"]):
                    continue
                if cluster.confidence < rule["min_confidence"]:
                    continue

                boost_count = sum(1 for st in rule.get("boost", []) if st in cluster.chain)
                fc = forecast_map.get(cluster.entity)

                # Determine exploitation status
                if "kev_add" in cluster.chain:
                    status = "confirmed"
                elif fc and fc.prob >= 0.7:
                    status = "probable"
                elif boost_count >= 2:
                    status = "probable"
                else:
                    status = "potential"

                sev = rule["severity"]
                if boost_count >= 2 and sev != "CRITICAL":
                    sev = "CRITICAL"

                desc = (
                    f"Zero-day detection rule '{rule['name']}' triggered for {cluster.entity}. "
                    f"Chain evidence: {', '.join(cluster.chain)}. "
                    f"Exploitation status: {status.upper()}. "
                )
                if fc:
                    desc += f"Predicted exploitation probability: {fc.prob_pct}%. "
                    desc += f"Estimated window: {fc.window_label}."

                actions = [
                    f"IMMEDIATE: Assess exposure to {cluster.entity}",
                    "Deploy emergency detection rules (Sigma/YARA/Suricata)",
                ]
                if status in ("confirmed", "probable"):
                    actions.insert(0, f"CRITICAL: Patch or isolate systems affected by {cluster.entity}")
                    actions.append("Activate incident response team")
                    actions.append("Brief CISO on active exploitation risk")
                actions.append("Hunt for related IOCs across SIEM/EDR infrastructure")
                actions.append("Monitor for lateral movement post-exploitation")

                rule_name = rule["name"]
                alert_hash = hashlib.md5(f"{cluster.entity}:{rule_name}".encode()).hexdigest()[:12]
                alerts.append(ZeroDayAlert(
                    alert_id=f"zd-{alert_hash}",
                    entity=cluster.entity, alert_type=rule["name"], severity=sev,
                    title=f"Zero-Day Signal: {cluster.entity} — {rule['name']}",
                    description=desc, confidence=cluster.confidence,
                    chain_evidence=cluster.chain, exploitation_status=status,
                    indicators=[cluster.entity] + cluster.related[:5],
                    recommended_actions=actions, timestamp=datetime.now(timezone.utc).isoformat(),
                ))
                break  # One alert per cluster (highest-priority rule wins)

        alerts.sort(key=lambda a: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(a.severity, 3))
        logger.info(f"ZeroDayDetector: {len(alerts)} zero-day alerts")
        return alerts


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ATTACK WAVE DETECTOR
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackWave:
    wave_id: str; wave_type: str; title: str; description: str; severity: str
    entities: List[str]; signal_count: int; velocity: float; peak_prob: float
    sectors: List[str]; timestamp: str
    def to_dict(self) -> Dict: return self.__dict__


class AttackWaveDetector:
    def detect(self, forecasts: List[Forecast], clusters: List[SignalCluster]) -> List[AttackWave]:
        waves = []
        # Exploit burst
        high = [f for f in forecasts if f.prob >= 0.5]
        if len(high) >= 3:
            peak = max(f.prob for f in high)
            secs = list(set(s for f in high for s in f.sectors))
            waves.append(AttackWave(
                f"wave-burst-{hashlib.md5(str(len(high)).encode()).hexdigest()[:8]}",
                "exploit_burst", f"Exploit Burst: {len(high)} high-probability threats",
                f"{len(high)} vulnerabilities above 50% exploitation probability. Peak: {peak*100:.0f}%.",
                "CRITICAL" if peak >= 0.8 else "HIGH", [f.entity for f in high],
                sum(f.signal_count for f in high), len(high), peak, secs[:5],
                datetime.now(timezone.utc).isoformat()))

        # Sector siege
        sec_map: Dict[str, List[Forecast]] = defaultdict(list)
        for f in forecasts:
            for s in f.sectors: sec_map[s].append(f)
        for sec, fs in sec_map.items():
            if sec == "All Industries" or len(fs) < 4: continue
            peak = max(t.prob for t in fs)
            waves.append(AttackWave(
                f"wave-sector-{hashlib.md5(sec.encode()).hexdigest()[:8]}",
                "sector_siege", f"Sector Siege: {len(fs)} threats targeting {sec}",
                f"{len(fs)} threats converging on {sec}.", "HIGH",
                [t.entity for t in fs], sum(t.signal_count for t in fs), len(fs), peak,
                [sec], datetime.now(timezone.utc).isoformat()))

        # Velocity surge
        fast = [c for c in clusters if c.velocity > 1.5]
        if fast:
            pv = max(c.velocity for c in fast)
            waves.append(AttackWave(
                f"wave-velocity-{hashlib.md5(str(pv).encode()).hexdigest()[:8]}",
                "velocity_surge", f"Velocity Surge: {len(fast)} fast-moving clusters",
                f"Peak velocity: {pv:.1f} signals/hour.", "HIGH",
                [c.entity for c in fast], sum(len(c.signals) for c in fast), pv,
                max(c.confidence for c in fast), [], datetime.now(timezone.utc).isoformat()))

        waves.sort(key=lambda w: w.peak_prob, reverse=True)
        logger.info(f"WaveDetector: {len(waves)} waves")
        return waves


# ═══════════════════════════════════════════════════════════════════════════════
# 3. AI THREAT REASONING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatReasoningAI:
    """Generates contextual intelligence explanations from threat data."""

    REASONING_TEMPLATES = {
        "kev_add": "This vulnerability has been added to CISA's Known Exploited Vulnerabilities catalog, confirming active exploitation in the wild. Federal agencies are mandated to patch by the specified due date, and all organizations should treat this as a critical priority.",
        "poc_release": "A public proof-of-concept exploit has been published, significantly lowering the barrier to exploitation. Threat actors can now weaponize this vulnerability with minimal effort. The window between PoC release and mass exploitation is typically 24-72 hours.",
        "scan_spike": "Internet-wide scanning activity has been detected targeting this vulnerability or related infrastructure. This typically indicates threat actors are identifying vulnerable targets at scale, and exploitation attempts will follow shortly.",
        "patch_gap": "No vendor patch is currently available for this vulnerability, leaving a critical exploitation window open. Organizations should implement virtual patching, WAF rules, or network segmentation as interim mitigations.",
        "actor_activity": "Known threat actor involvement has been detected in campaigns related to this threat. This elevates the risk from opportunistic to targeted, with potential for more sophisticated exploitation and persistence techniques.",
        "severity_spike": "This threat has escalated to critical severity based on multi-signal analysis. The combination of technical severity, exploitation likelihood, and impact scope warrants immediate attention from security leadership.",
    }

    def reason(self, zd_alerts: List[ZeroDayAlert], forecasts: List[Forecast], clusters: List[SignalCluster]) -> List[Dict]:
        """Generate AI reasoning reports for top threats."""
        reports = []
        forecast_map = {f.entity: f for f in forecasts}
        cluster_map = {c.entity: c for c in clusters}

        # Combine zero-day alerts and top forecasts
        entities_done = set()
        ordered = [(a.entity, a.severity, a.confidence) for a in zd_alerts]
        ordered += [(f.entity, f.risk_level, f.confidence) for f in forecasts[:20]]

        for entity, severity, conf in ordered:
            if entity in entities_done: continue
            entities_done.add(entity)

            fc = forecast_map.get(entity)
            cl = cluster_map.get(entity)
            zd = next((a for a in zd_alerts if a.entity == entity), None)

            # Build contextual analysis
            analysis_parts = []
            if zd:
                analysis_parts.append(f"ZERO-DAY ALERT: {zd.title}")
                analysis_parts.append(f"Exploitation Status: {zd.exploitation_status.upper()}")
            if fc:
                analysis_parts.append(f"Exploitation Probability: {fc.prob_pct}%")
                analysis_parts.append(f"Estimated Window: {fc.window_label}")
                analysis_parts.append(f"Predicted Attack Vector: {fc.vector}")
                analysis_parts.append(f"Target Sectors: {', '.join(fc.sectors)}")

            # Stage-by-stage reasoning
            if cl:
                for stage in cl.chain:
                    template = self.REASONING_TEMPLATES.get(stage, "")
                    if template:
                        analysis_parts.append(f"[{stage.upper()}] {template}")

            # Composite assessment
            if fc and fc.prob >= 0.7:
                analysis_parts.append("ASSESSMENT: This threat shows strong early exploitation signals and poses an immediate risk. Organizations should prioritize defensive actions.")
            elif fc and fc.prob >= 0.4:
                analysis_parts.append("ASSESSMENT: Moderate exploitation signals detected. Proactive monitoring and preparation recommended.")
            else:
                analysis_parts.append("ASSESSMENT: Early-stage signals detected. Continue monitoring for escalation.")

            reports.append({
                "entity": entity,
                "severity": severity,
                "confidence": round(conf, 3),
                "ai_analysis": "\n\n".join(analysis_parts),
                "summary": analysis_parts[0] if analysis_parts else "No analysis available",
                "chain_stages": cl.chain if cl else [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

            if len(reports) >= 25:
                break

        logger.info(f"ThreatReasoning: {len(reports)} reports")
        return reports


# ═══════════════════════════════════════════════════════════════════════════════
# 4. EARLY WARNING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EarlyWarning:
    warning_id: str; level: str; title: str; entity: str; prob_pct: int
    window: str; sectors: List[str]; confidence: float; reasoning: List[str]
    actions: List[str]; timestamp: str
    def to_dict(self) -> Dict: return self.__dict__


class EarlyWarningSystem:
    def generate(self, forecasts: List[Forecast], zd_alerts: List[ZeroDayAlert]) -> List[EarlyWarning]:
        warnings = []
        # From forecasts
        for f in forecasts:
            if f.prob < 0.40: continue
            lvl = "CRITICAL_WARNING" if f.prob >= 0.8 else "HIGH_WARNING" if f.prob >= 0.6 else "ELEVATED_WARNING"
            acts = list(f.reasoning[-2:])
            if lvl == "CRITICAL_WARNING":
                acts = [f"IMMEDIATE: Patch/isolate {f.entity}", "Activate IR team", "Deploy emergency detection rules"] + acts
            elif lvl == "HIGH_WARNING":
                acts = [f"URGENT: Prioritize patching {f.entity}", "Deploy detection rules"] + acts
            else:
                acts = [f"Monitor {f.entity} for escalation"] + acts

            warnings.append(EarlyWarning(
                f"ew-{f.forecast_id[3:]}", lvl, f"Emerging Threat: {f.entity}",
                f.entity, f.prob_pct, f.window_label, f.sectors, f.confidence,
                f.reasoning, acts, datetime.now(timezone.utc).isoformat()))

        # From zero-day alerts (ensure no duplicates)
        warned = set(w.entity for w in warnings)
        for a in zd_alerts:
            if a.entity in warned: continue
            warnings.append(EarlyWarning(
                f"ew-zd-{a.alert_id[3:]}", "CRITICAL_WARNING" if a.severity == "CRITICAL" else "HIGH_WARNING",
                a.title, a.entity, 0, "See zero-day alert", [], a.confidence,
                a.chain_evidence, a.recommended_actions, datetime.now(timezone.utc).isoformat()))

        warnings.sort(key=lambda w: {"CRITICAL_WARNING": 0, "HIGH_WARNING": 1, "ELEVATED_WARNING": 2}.get(w.level, 3))
        logger.info(f"EarlyWarning: {len(warnings)} warnings")
        return warnings


# ═══════════════════════════════════════════════════════════════════════════════
# 5. PLAYBOOK GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class PlaybookGenerator:
    def generate(self, warnings: List[EarlyWarning], zd_alerts: List[ZeroDayAlert]) -> List[Dict]:
        playbooks = []
        for w in warnings:
            if w.level != "CRITICAL_WARNING": continue
            playbooks.append({
                "playbook_id": f"pb-{w.warning_id[3:]}",
                "title": f"IR Playbook: {w.entity}",
                "trigger": f"Critical warning for {w.entity} (probability: {w.prob_pct}%)",
                "severity": "CRITICAL",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "phases": [
                    {"phase": "1. PREPARATION", "actions": [
                        f"Identify all systems affected by {w.entity}",
                        "Verify IR team availability and backup integrity",
                        "Pre-stage containment tools"]},
                    {"phase": "2. DETECTION", "actions": [
                        "Deploy Sigma/YARA/Suricata rules from DetectionForge",
                        f"Hunt for {w.entity} exploitation indicators in SIEM",
                        "Check EDR for post-exploitation behaviors"]},
                    {"phase": "3. CONTAINMENT", "actions": [
                        "Isolate compromised systems",
                        "Block malicious IOCs at firewall",
                        "Implement network segmentation"]},
                    {"phase": "4. ERADICATION", "actions": [
                        f"Apply vendor patch for {w.entity}",
                        "Remove malicious artifacts",
                        "Reset compromised credentials"]},
                    {"phase": "5. RECOVERY", "actions": [
                        "Restore from clean backups",
                        "Validate system integrity",
                        "Resume normal operations with enhanced monitoring"]},
                ],
            })

        for a in zd_alerts:
            if a.severity != "CRITICAL": continue
            if any(p["title"].endswith(a.entity) for p in playbooks): continue
            playbooks.append({
                "playbook_id": f"pb-zd-{a.alert_id[3:]}",
                "title": f"IR Playbook: {a.entity}",
                "trigger": f"Zero-day alert: {a.alert_type} ({a.exploitation_status})",
                "severity": "CRITICAL", "created_at": datetime.now(timezone.utc).isoformat(),
                "phases": [
                    {"phase": "1. TRIAGE", "actions": a.recommended_actions[:3]},
                    {"phase": "2. CONTAIN", "actions": ["Isolate affected systems", "Block IOCs", "Deploy virtual patches"]},
                    {"phase": "3. HUNT", "actions": [f"Hunt for {a.entity} artifacts", "Check lateral movement", "Analyze C2 connections"]},
                    {"phase": "4. REMEDIATE", "actions": ["Patch when available", "Forensic analysis", "Reset credentials"]},
                ],
            })

        logger.info(f"PlaybookGen: {len(playbooks)} playbooks")
        return playbooks


# ═══════════════════════════════════════════════════════════════════════════════
# 6. GLOBAL THREAT INDEX
# ═══════════════════════════════════════════════════════════════════════════════

class GlobalThreatIndex:
    def calculate(self, forecasts: List[Forecast], zd_alerts: List[ZeroDayAlert], waves: List[AttackWave]) -> Dict:
        # Forecast-based scoring
        probs = [f.prob for f in forecasts] if forecasts else [0.5]
        avg_prob = sum(probs) / len(probs)
        critical_count = sum(1 for f in forecasts if f.risk_level == "IMMINENT")
        high_count = sum(1 for f in forecasts if f.risk_level == "HIGH")

        # Component scores
        prob_score = avg_prob * 4
        severity_score = min(2.0, critical_count * 0.3 + high_count * 0.1)
        zd_score = min(2.0, len(zd_alerts) * 0.4)
        wave_score = min(1.5, len(waves) * 0.3)
        volume_score = min(1.0, len(forecasts) / 50)

        composite = prob_score + severity_score + zd_score + wave_score + volume_score
        index = min(10.0, max(0.0, composite))

        level = "CRITICAL" if index >= 8.5 else "HIGH" if index >= 7 else "ELEVATED" if index >= 5 else "GUARDED" if index >= 3 else "LOW"

        return {
            "index": round(index, 1), "level": level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {"probability": round(prob_score, 2), "severity": round(severity_score, 2),
                           "zeroday": round(zd_score, 2), "waves": round(wave_score, 2), "volume": round(volume_score, 2)},
            "critical_threats": critical_count, "high_threats": high_count,
            "zeroday_alerts": len(zd_alerts), "attack_waves": len(waves),
            "brand": "CyberDudeBivash Global Threat Index",
            "platform": "SENTINEL APEX v35.0 — ZERO-DAY HUNTER",
        }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ZeroDayHunterEngine:
    """
    Master orchestrator — runs the complete Zero-Day Hunter pipeline.
    Pipeline: Signals → Correlation → Forecasting → Zero-Day Detection →
              Wave Detection → AI Reasoning → Early Warning → Playbooks → GTI
    """

    def __init__(self, output_dir: str = OUTPUT_DIR, enable_external: bool = True):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "playbooks"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "signals"), exist_ok=True)

        self.pipeline = SignalPipeline(enable_external=enable_external)
        self.zd_detector = ZeroDaySignalDetector()
        self.wave_detector = AttackWaveDetector()
        self.reasoning = ThreatReasoningAI()
        self.warning_sys = EarlyWarningSystem()
        self.playbook_gen = PlaybookGenerator()
        self.gti = GlobalThreatIndex()

    def run(self, window_hours: int = 72) -> Dict:
        logger.info("=" * 65)
        logger.info("SENTINEL APEX v35.0 — ZERO-DAY HUNTER ENGINE")
        logger.info("=" * 65)
        now = datetime.now(timezone.utc).isoformat()

        # Stage 1: Signal Pipeline
        logger.info("[1/7] Signal Collection + Correlation + Forecasting...")
        signals, clusters, forecasts = self.pipeline.run(window_hours)
        chains = [c for c in clusters if len(c.chain) >= 2]

        # Stage 2: Zero-Day Detection
        logger.info("[2/7] Zero-Day Signal Detection...")
        zd_alerts = self.zd_detector.detect(clusters, forecasts)

        # Stage 3: Attack Wave Detection
        logger.info("[3/7] Attack Wave Detection...")
        waves = self.wave_detector.detect(forecasts, clusters)

        # Stage 4: AI Threat Reasoning
        logger.info("[4/7] AI Threat Reasoning...")
        ai_reports = self.reasoning.reason(zd_alerts, forecasts, clusters)

        # Stage 5: Early Warning
        logger.info("[5/7] Early Warning Generation...")
        warnings = self.warning_sys.generate(forecasts, zd_alerts)

        # Stage 6: Playbook Generation
        logger.info("[6/7] Playbook Generation...")
        playbooks = self.playbook_gen.generate(warnings, zd_alerts)

        # Stage 7: Global Threat Index
        logger.info("[7/7] Global Threat Index...")
        threat_index = self.gti.calculate(forecasts, zd_alerts, waves)

        # Compile results
        result = {
            "status": "success", "version": "35.0.0", "codename": "ZERO-DAY HUNTER",
            "timestamp": now,
            "global_threat_index": threat_index,
            "pipeline_stats": {
                "signals_collected": len(signals), "clusters_formed": len(clusters),
                "attack_chains": len(chains), "forecasts": len(forecasts),
                "zeroday_alerts": len(zd_alerts), "attack_waves": len(waves),
                "ai_reports": len(ai_reports), "early_warnings": len(warnings),
                "playbooks": len(playbooks),
            },
            "signal_breakdown": dict(Counter(s.signal_type for s in signals)),
            "source_breakdown": dict(Counter(s.source for s in signals)),
            "zeroday_alerts": [a.to_dict() for a in zd_alerts[:15]],
            "top_forecasts": [f.to_dict() for f in forecasts[:10]],
            "attack_waves": [w.to_dict() for w in waves],
            "early_warnings": [w.to_dict() for w in warnings[:15]],
            "ai_reasoning_sample": ai_reports[:5],
        }

        # Save all outputs
        self._save(result, signals, clusters, forecasts, zd_alerts, waves, ai_reports, warnings, playbooks, threat_index)

        logger.info("=" * 65)
        logger.info(f"ZERO-DAY HUNTER COMPLETE — GTI: {threat_index['index']}/10 ({threat_index['level']})")
        logger.info(f"  {len(zd_alerts)} zero-day alerts | {len(waves)} waves | {len(warnings)} warnings")
        logger.info("=" * 65)
        return result

    def _save(self, result, signals, clusters, forecasts, zd_alerts, waves, ai_reports, warnings, playbooks, gti):
        d = self.output_dir
        for name, data in [
            ("zdh_report.json", result),
            ("signals/collected_signals.json", {"count": len(signals), "signals": [s.to_dict() for s in signals]}),
            ("correlated_clusters.json", [c.to_dict() for c in clusters]),
            ("threat_forecasts.json", [f.to_dict() for f in forecasts]),
            ("zeroday_alerts.json", [a.to_dict() for a in zd_alerts]),
            ("attack_waves.json", [w.to_dict() for w in waves]),
            ("ai_reasoning_reports.json", ai_reports),
            ("early_warnings.json", [w.to_dict() for w in warnings]),
            ("global_threat_index.json", gti),
        ]:
            with open(os.path.join(d, name), 'w') as f:
                json.dump(data, f, indent=2, default=str)

        for pb in playbooks:
            with open(os.path.join(d, "playbooks", f"{pb['playbook_id']}.json"), 'w') as f:
                json.dump(pb, f, indent=2, default=str)

        logger.info(f"All outputs saved to {d}/")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    logging.basicConfig(level=logging.INFO, format="[ZDH] %(asctime)s — %(levelname)s — %(message)s")
    try:
        import requests; ext = True
    except ImportError: ext = False
    engine = ZeroDayHunterEngine(enable_external=ext)
    result = engine.run(window_hours=168)
    print(json.dumps({
        "global_threat_index": result["global_threat_index"],
        "pipeline_stats": result["pipeline_stats"],
        "signal_breakdown": result["signal_breakdown"],
        "source_breakdown": result["source_breakdown"],
        "zeroday_alerts_count": len(result["zeroday_alerts"]),
        "top_zeroday": [{"entity": a["entity"], "type": a["alert_type"], "severity": a["severity"],
                         "status": a["exploitation_status"]} for a in result["zeroday_alerts"][:5]],
    }, indent=2))

if __name__ == "__main__":
    main()
