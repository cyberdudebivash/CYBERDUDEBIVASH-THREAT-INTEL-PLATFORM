#!/usr/bin/env python3
"""
ai_subsystems.py — CYBERDUDEBIVASH® SENTINEL APEX v36.0 (OMNISHIELD)
======================================================================
Six AI-powered defense subsystems operating on existing platform data.

S1 — AI Context Engine: Cross-source correlation + incident narrative generation
S2 — Behavioral Anomaly Detection: Statistical baseline + anomaly scoring
S3 — Agentic Security AI: Incident triage + defense recommendation generation
S4 — AI Security Posture: Pipeline integrity + prompt injection detection
S6 — AI Threat Countermeasures: AI-phishing/deepfake/malware pattern detection
S10 — Synthetic Threat Training: Attack scenario generation for detection tuning

Non-Breaking: Reads from manifest, fusion, ZDH data. Writes to data/omnishield/ai/.
Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os, re, json, math, hashlib, logging, statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("CDB-AI-Subsystems")

MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
FUSION_DIR = os.environ.get("FUSION_DIR", "data/fusion")
ZDH_DIR = os.environ.get("ZDH_DIR", "data/zerodayhunter")
AI_OUTPUT = os.environ.get("OMNISHIELD_AI_DIR", "data/omnishield/ai")

def _load_json(path: str) -> Any:
    try:
        with open(path) as f: return json.load(f)
    except Exception: return None

def _entries() -> List[Dict]:
    d = _load_json(MANIFEST_PATH)
    return d if isinstance(d, list) else (d.get("entries", []) if d else [])


# ═══════════════════════════════════════════════════════════════════════════════
# S1 — AI CONTEXT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class AIContextEngine:
    """Correlates intelligence across manifest, fusion, and ZDH to build incident narratives."""

    def run(self) -> Dict:
        entries = _entries()
        fusion_entities = _load_json(os.path.join(FUSION_DIR, "entity_store.json")) or {}
        zdh_alerts = _load_json(os.path.join(ZDH_DIR, "zeroday_alerts.json")) or []
        zdh_forecasts = _load_json(os.path.join(ZDH_DIR, "threat_forecasts.json")) or []

        # Build incident narratives from high-risk convergence
        narratives = []
        cve_re = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

        # Group threats by actor
        actor_events: Dict[str, List[Dict]] = defaultdict(list)
        for e in entries:
            actor = e.get("actor_tag", "")
            if actor and not actor.startswith("UNC-CDB"):
                actor_events[actor].append(e)

        for actor, events in actor_events.items():
            if len(events) < 2: continue
            cves = []
            for ev in events:
                cves.extend(cve_re.findall(ev.get("title", "")))
            cves = list(set(c.upper() for c in cves))

            tactics = list(set(t for ev in events for t in ev.get("mitre_tactics", [])))
            avg_risk = statistics.mean(ev.get("risk_score", 5) for ev in events)

            # Cross-reference with ZDH
            zdh_match = [a for a in zdh_alerts if a.get("entity", "").upper() in [c.upper() for c in cves]]

            narrative = {
                "narrative_id": f"nar-{hashlib.md5(actor.encode()).hexdigest()[:10]}",
                "actor": actor,
                "event_count": len(events),
                "cves_involved": cves[:10],
                "mitre_techniques": tactics[:10],
                "avg_risk_score": round(avg_risk, 1),
                "zeroday_correlation": len(zdh_match),
                "timeline": {
                    "first_seen": min(ev.get("timestamp", "") for ev in events),
                    "last_seen": max(ev.get("timestamp", "") for ev in events),
                },
                "narrative": self._build_narrative(actor, events, cves, tactics, zdh_match, avg_risk),
                "risk_assessment": "CRITICAL" if avg_risk >= 8 or zdh_match else "HIGH" if avg_risk >= 6 else "MEDIUM",
                "false_positive_score": max(0.1, 1.0 - (len(events) * 0.15 + len(cves) * 0.1)),
            }
            narratives.append(narrative)

        narratives.sort(key=lambda n: n["avg_risk_score"], reverse=True)

        result = {
            "subsystem": "S1_AI_Context_Engine",
            "narratives_generated": len(narratives),
            "actors_analyzed": len(actor_events),
            "fusion_entities_available": len(fusion_entities),
            "zdh_alerts_correlated": sum(n["zeroday_correlation"] for n in narratives),
            "narratives": narratives[:20],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S1 Context Engine: {len(narratives)} narratives")
        return result

    def _build_narrative(self, actor, events, cves, tactics, zdh_match, avg_risk) -> str:
        parts = [f"Threat actor {actor} has been observed in {len(events)} intelligence signals."]
        if cves:
            parts.append(f"Associated vulnerabilities: {', '.join(cves[:5])}.")
        if tactics:
            parts.append(f"MITRE ATT&CK techniques: {', '.join(tactics[:5])}.")
        if zdh_match:
            parts.append(f"CRITICAL: {len(zdh_match)} zero-day alert(s) correlate with this actor's activity.")
        parts.append(f"Average risk score: {avg_risk:.1f}/10.")
        if avg_risk >= 8:
            parts.append("Assessment: This actor poses an immediate threat requiring defensive action.")
        return " ".join(parts)


# ═══════════════════════════════════════════════════════════════════════════════
# S2 — BEHAVIORAL ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

class BehavioralAnomalyDetector:
    """Statistical baseline modeling + anomaly detection on platform telemetry."""

    def run(self) -> Dict:
        entries = _entries()
        if len(entries) < 5:
            return {"subsystem": "S2_Behavioral_Anomaly", "status": "insufficient_data"}

        # Build baselines
        risks = [e.get("risk_score", 5) for e in entries]
        ioc_totals = [sum(v for v in e.get("ioc_counts", {}).values() if isinstance(v, (int, float))) for e in entries]
        indicator_counts = [e.get("indicator_count", 0) for e in entries]

        risk_baseline = {"mean": statistics.mean(risks), "stdev": statistics.stdev(risks) if len(risks) > 1 else 1}
        ioc_baseline = {"mean": statistics.mean(ioc_totals), "stdev": statistics.stdev(ioc_totals) if len(ioc_totals) > 1 else 1}

        # Detect anomalies (z-score > 2)
        anomalies = []
        for i, e in enumerate(entries):
            risk_z = abs(e.get("risk_score", 5) - risk_baseline["mean"]) / max(0.1, risk_baseline["stdev"])
            ioc_total = sum(v for v in e.get("ioc_counts", {}).values() if isinstance(v, (int, float)))
            ioc_z = abs(ioc_total - ioc_baseline["mean"]) / max(0.1, ioc_baseline["stdev"])

            anomaly_score = max(risk_z, ioc_z)
            if anomaly_score > 2.0:
                anomalies.append({
                    "anomaly_id": f"anom-{hashlib.md5(e.get('stix_file', str(i)).encode()).hexdigest()[:10]}",
                    "title": e.get("title", "")[:80],
                    "anomaly_score": round(anomaly_score, 2),
                    "risk_zscore": round(risk_z, 2),
                    "ioc_zscore": round(ioc_z, 2),
                    "risk_score": e.get("risk_score", 0),
                    "ioc_total": ioc_total,
                    "detection_type": "risk_spike" if risk_z > ioc_z else "ioc_volume_spike",
                    "severity": "CRITICAL" if anomaly_score > 3 else "HIGH" if anomaly_score > 2.5 else "MEDIUM",
                    "timestamp": e.get("timestamp", ""),
                })

        # Trend analysis
        if len(risks) >= 10:
            recent = risks[-5:]
            older = risks[-10:-5]
            trend = statistics.mean(recent) - statistics.mean(older)
            trend_label = "ESCALATING" if trend > 1 else "DECLINING" if trend < -1 else "STABLE"
        else:
            trend, trend_label = 0, "INSUFFICIENT_DATA"

        anomalies.sort(key=lambda a: a["anomaly_score"], reverse=True)
        result = {
            "subsystem": "S2_Behavioral_Anomaly",
            "baselines": {"risk": risk_baseline, "ioc_volume": ioc_baseline},
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies[:15],
            "trend": {"direction": trend_label, "delta": round(trend, 2)},
            "entries_analyzed": len(entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S2 Behavioral: {len(anomalies)} anomalies, trend={trend_label}")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S3 — AGENTIC SECURITY AI
# ═══════════════════════════════════════════════════════════════════════════════

class AgenticSecurityAI:
    """Incident triage, defense recommendations, and detection rule generation."""

    TRIAGE_MATRIX = {
        (True, True, True): ("P1_CRITICAL", "Immediate IR activation — active zero-day with actor attribution"),
        (True, True, False): ("P1_CRITICAL", "Confirmed exploitation with actor — escalate to SOC Tier 3"),
        (True, False, True): ("P2_HIGH", "Zero-day signal without attribution — deploy detection rules"),
        (True, False, False): ("P2_HIGH", "Active exploitation detected — prioritize patching"),
        (False, True, True): ("P2_HIGH", "Actor activity with zero-day signal — increase hunting"),
        (False, True, False): ("P3_MEDIUM", "Actor activity observed — monitor and track"),
        (False, False, True): ("P3_MEDIUM", "Zero-day signal without exploitation — watch closely"),
        (False, False, False): ("P4_LOW", "Standard threat intelligence — routine processing"),
    }

    def run(self) -> Dict:
        entries = _entries()
        zdh_alerts = _load_json(os.path.join(ZDH_DIR, "zeroday_alerts.json")) or []
        zdh_entity_set = set(a.get("entity", "").upper() for a in zdh_alerts)

        triage_results = []
        recommendations = []

        for e in entries:
            title = e.get("title", "")
            risk = e.get("risk_score", 0)
            kev = e.get("kev_present", False)
            actor = e.get("actor_tag", "")
            has_actor = bool(actor and not actor.startswith("UNC-CDB"))
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', title, re.IGNORECASE)
            has_zd = any(c.upper() in zdh_entity_set for c in cves)

            # Triage
            key = (kev or risk >= 9, has_actor, has_zd)
            priority, rationale = self.TRIAGE_MATRIX.get(key, ("P4_LOW", "Standard processing"))

            triage = {
                "triage_id": f"tri-{hashlib.md5(e.get('stix_file', title).encode()).hexdigest()[:10]}",
                "title": title[:80], "priority": priority, "rationale": rationale,
                "risk_score": risk, "kev": kev, "actor": actor,
                "cves": [c.upper() for c in cves], "zeroday_match": has_zd,
            }
            triage_results.append(triage)

            # Generate defense recommendations for high-priority
            if priority in ("P1_CRITICAL", "P2_HIGH"):
                rec = {
                    "entity": title[:60],
                    "priority": priority,
                    "recommendations": [],
                    "mode": "RECOMMENDATION",  # Human approval required
                    "auto_approved": False,
                }
                if kev:
                    rec["recommendations"].append({"action": "PATCH", "detail": f"Apply vendor patch for {', '.join(cves[:3])}", "urgency": "IMMEDIATE"})
                if has_zd:
                    rec["recommendations"].append({"action": "HUNT", "detail": "Deploy detection rules and hunt for exploitation indicators", "urgency": "HIGH"})
                if has_actor:
                    rec["recommendations"].append({"action": "MONITOR", "detail": f"Increase monitoring for {actor} TTPs", "urgency": "HIGH"})
                rec["recommendations"].append({"action": "DETECT", "detail": "Deploy Sigma/YARA rules from DetectionForge", "urgency": "STANDARD"})
                recommendations.append(rec)

        triage_results.sort(key=lambda t: {"P1_CRITICAL": 0, "P2_HIGH": 1, "P3_MEDIUM": 2, "P4_LOW": 3}.get(t["priority"], 4))
        priority_dist = Counter(t["priority"] for t in triage_results)

        result = {
            "subsystem": "S3_Agentic_Security_AI",
            "mode": "RECOMMENDATION_ONLY",  # AI does NOT auto-execute — human approval required
            "triage_count": len(triage_results),
            "priority_distribution": dict(priority_dist),
            "triage_results": triage_results[:20],
            "defense_recommendations": recommendations[:15],
            "safety_note": "All recommendations require human analyst approval before execution",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S3 Agentic: {len(triage_results)} triaged, P1={priority_dist.get('P1_CRITICAL',0)}, P2={priority_dist.get('P2_HIGH',0)}")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S4 — AI SECURITY POSTURE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class AISecurityPosture:
    """Monitors AI pipeline integrity, detects prompt injection patterns, validates model outputs."""

    INJECTION_PATTERNS = [
        r"ignore\s+(?:previous|all|above)\s+instructions",
        r"you\s+are\s+now\s+(?:a|an)\s+(?:evil|malicious|hacker)",
        r"disregard\s+(?:your|the)\s+(?:rules|instructions|guidelines)",
        r"(?:system|admin)\s+(?:prompt|override|bypass)",
        r"jailbreak",
        r"do\s+anything\s+now",
        r"(?:act|pretend)\s+(?:as|like)\s+(?:you\s+have\s+)?no\s+(?:restrictions|limits)",
        r"reveal\s+(?:your|the)\s+(?:system|hidden)\s+prompt",
    ]

    def run(self) -> Dict:
        entries = _entries()
        # Check for injection-like patterns in intel titles (adversarial content detection)
        injection_flags = []
        for e in entries:
            title = e.get("title", "").lower()
            for pattern in self.INJECTION_PATTERNS:
                if re.search(pattern, title, re.IGNORECASE):
                    injection_flags.append({
                        "title": e.get("title", "")[:80],
                        "pattern_matched": pattern,
                        "stix_file": e.get("stix_file", ""),
                        "severity": "HIGH",
                    })
                    break

        # Data integrity checks
        integrity_checks = {
            "manifest_entries": len(entries),
            "manifest_readable": len(entries) > 0,
            "stix_dir_exists": os.path.isdir("data/stix"),
            "fusion_data_exists": os.path.isdir(FUSION_DIR),
            "zdh_data_exists": os.path.isdir(ZDH_DIR),
            "all_entries_have_risk_score": all(isinstance(e.get("risk_score"), (int, float)) for e in entries),
            "all_entries_have_timestamp": all(bool(e.get("timestamp")) for e in entries),
            "risk_scores_in_range": all(0 <= e.get("risk_score", 0) <= 10 for e in entries),
        }
        integrity_pass = all(integrity_checks.values())

        # Model drift check (compare recent vs historical risk distribution)
        drift_detected = False
        if len(entries) >= 10:
            recent_risks = [e.get("risk_score", 5) for e in entries[-5:]]
            older_risks = [e.get("risk_score", 5) for e in entries[:max(1, len(entries)-5)]]
            recent_mean = statistics.mean(recent_risks)
            older_mean = statistics.mean(older_risks)
            older_std = statistics.stdev(older_risks) if len(older_risks) > 1 else 1
            drift_score = abs(recent_mean - older_mean) / max(0.1, older_std)
            drift_detected = drift_score > 2.0

        result = {
            "subsystem": "S4_AI_Security_Posture",
            "integrity_checks": integrity_checks,
            "integrity_status": "PASS" if integrity_pass else "FAIL",
            "injection_attempts_detected": len(injection_flags),
            "injection_flags": injection_flags[:10],
            "model_drift": {"detected": drift_detected, "score": round(drift_score, 2) if len(entries) >= 10 else 0},
            "posture_score": 10 if integrity_pass and not injection_flags and not drift_detected else (7 if integrity_pass else 4),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S4 Posture: integrity={'PASS' if integrity_pass else 'FAIL'}, injections={len(injection_flags)}, drift={drift_detected}")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S6 — AI THREAT COUNTERMEASURES
# ═══════════════════════════════════════════════════════════════════════════════

class AIThreatCountermeasures:
    """Detects AI-powered cyber threats: AI phishing, deepfake, AI malware, social engineering."""

    AI_THREAT_INDICATORS = {
        "ai_phishing": ["ai-generated", "llm-generated", "chatgpt", "ai phishing", "ai-assisted phishing",
                        "automated phishing", "language model", "generative ai attack"],
        "deepfake": ["deepfake", "deep fake", "voice clone", "synthetic media", "ai-generated video",
                     "ai-generated audio", "face swap"],
        "ai_malware": ["ai malware", "ai-generated malware", "polymorphic ai", "machine learning evasion",
                       "ai-powered malware", "adversarial machine learning", "ai-assisted exploit"],
        "social_engineering": ["social engineering", "ai social engineering", "automated social",
                               "impersonation attack", "ai impersonation", "synthetic identity"],
    }

    def run(self) -> Dict:
        entries = _entries()
        zdh_reasoning = _load_json(os.path.join(ZDH_DIR, "ai_reasoning_reports.json")) or []

        detections = []
        category_counts = Counter()

        all_text = " ".join(e.get("title", "") for e in entries).lower()
        all_text += " " + " ".join(r.get("ai_analysis", "") for r in zdh_reasoning if isinstance(r, dict)).lower()

        for category, keywords in self.AI_THREAT_INDICATORS.items():
            matches = [kw for kw in keywords if kw in all_text]
            if matches:
                category_counts[category] = len(matches)
                detections.append({
                    "category": category,
                    "indicators_matched": matches,
                    "match_count": len(matches),
                    "severity": "HIGH" if len(matches) >= 2 else "MEDIUM",
                    "recommendation": self._get_recommendation(category),
                })

        result = {
            "subsystem": "S6_AI_Threat_Countermeasures",
            "ai_threats_detected": len(detections),
            "category_breakdown": dict(category_counts),
            "detections": detections,
            "entries_scanned": len(entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S6 Countermeasures: {len(detections)} AI threat categories detected")
        return result

    def _get_recommendation(self, category: str) -> str:
        recs = {
            "ai_phishing": "Deploy AI-aware email filtering. Train users on AI-generated phishing characteristics.",
            "deepfake": "Implement media verification protocols. Require multi-factor authentication for sensitive actions.",
            "ai_malware": "Update EDR with polymorphic detection capabilities. Enable behavioral analysis mode.",
            "social_engineering": "Strengthen identity verification procedures. Deploy voice/communication authentication.",
        }
        return recs.get(category, "Increase monitoring for AI-powered threats.")


# ═══════════════════════════════════════════════════════════════════════════════
# S10 — SYNTHETIC THREAT TRAINING
# ═══════════════════════════════════════════════════════════════════════════════

class SyntheticThreatTraining:
    """Generates synthetic attack scenarios for detection tuning and team training."""

    SCENARIO_TEMPLATES = [
        {"name": "Ransomware Double Extortion", "chain": ["T1566", "T1059", "T1486", "T1567"],
         "actors": ["LockBit", "BlackCat", "Cl0p"], "sectors": ["Healthcare", "Finance", "Manufacturing"]},
        {"name": "Supply Chain Compromise", "chain": ["T1195", "T1059", "T1078", "T1040"],
         "actors": ["APT-29", "Lazarus"], "sectors": ["Technology", "Government"]},
        {"name": "Zero-Day Exploitation", "chain": ["T1190", "T1068", "T1055", "T1003"],
         "actors": ["APT-41", "Volt Typhoon"], "sectors": ["Critical Infrastructure", "Telecom"]},
        {"name": "BEC via AI Phishing", "chain": ["T1566", "T1534", "T1114", "T1048"],
         "actors": ["FIN7", "Scattered Spider"], "sectors": ["Finance", "Retail"]},
        {"name": "Cloud Infrastructure Takeover", "chain": ["T1078", "T1098", "T1537", "T1530"],
         "actors": ["APT-29", "Scattered Spider"], "sectors": ["Technology", "SaaS"]},
    ]

    def run(self) -> Dict:
        entries = _entries()
        # Enrich templates with real platform data
        scenarios = []
        for tpl in self.SCENARIO_TEMPLATES:
            # Find matching real entries
            matching = [e for e in entries if any(t in e.get("mitre_tactics", []) for t in tpl["chain"])]
            real_risk = statistics.mean(e.get("risk_score", 5) for e in matching) if matching else 7.0

            scenario = {
                "scenario_id": f"syn-{hashlib.md5(tpl['name'].encode()).hexdigest()[:10]}",
                "name": tpl["name"],
                "attack_chain": tpl["chain"],
                "simulated_actors": tpl["actors"],
                "target_sectors": tpl["sectors"],
                "calibrated_risk": round(real_risk, 1),
                "real_data_matches": len(matching),
                "training_objectives": [
                    f"Detect {tpl['chain'][0]} initial access technique",
                    f"Correlate {tpl['name']} attack chain in SIEM",
                    f"Respond to {tpl['actors'][0]} TTPs within SLA",
                ],
                "detection_gaps": [f"Verify Sigma rule coverage for {t}" for t in tpl["chain"][:3]],
            }
            scenarios.append(scenario)

        result = {
            "subsystem": "S10_Synthetic_Training",
            "scenarios_generated": len(scenarios),
            "scenarios": scenarios,
            "training_data_entries": len(entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S10 Synthetic: {len(scenarios)} training scenarios")
        return result
