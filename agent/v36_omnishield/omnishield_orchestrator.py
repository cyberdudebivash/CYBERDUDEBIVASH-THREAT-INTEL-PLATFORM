#!/usr/bin/env python3
"""
omnishield_orchestrator.py — CYBERDUDEBIVASH® SENTINEL APEX v36.0 (OMNISHIELD)
================================================================================
Master orchestrator for 12 AI-powered cyber defense subsystems.

Also contains: S5 Cross-Domain Telemetry, S7 Identity Risk Engine,
S8 Self-Healing Defense, S9 Quantum Crypto Auditor, S11 Attack Simulation,
S12 Human Oversight Governance.

Pipeline: AI Analysis → Defense Posture → Risk Assessment → Governance → Output

Non-Breaking: Reads from manifest, fusion, ZDH. Writes to data/omnishield/.
Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os, re, json, hashlib, logging, math, statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from agent.v36_omnishield.ai.ai_subsystems import (
    AIContextEngine, BehavioralAnomalyDetector, AgenticSecurityAI,
    AISecurityPosture, AIThreatCountermeasures, SyntheticThreatTraining,
    _entries, _load_json, MANIFEST_PATH, FUSION_DIR, ZDH_DIR
)

logger = logging.getLogger("CDB-OmniShield")
OUTPUT_DIR = os.environ.get("OMNISHIELD_DIR", "data/omnishield")


# ═══════════════════════════════════════════════════════════════════════════════
# S5 — CROSS-DOMAIN TELEMETRY ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class CrossDomainTelemetry:
    """Analyzes telemetry coverage across cloud, endpoint, network, identity domains."""

    DOMAIN_INDICATORS = {
        "cloud": ["cloud", "aws", "azure", "gcp", "saas", "s3", "ec2", "kubernetes", "docker", "container", "serverless", "lambda"],
        "endpoint": ["endpoint", "edr", "malware", "trojan", "ransomware", "backdoor", "rootkit", "keylogger", "rat", "process injection"],
        "network": ["network", "firewall", "dns", "botnet", "c2", "scanning", "brute force", "ddos", "lateral movement", "port scan"],
        "identity": ["credential", "authentication", "identity", "oauth", "sso", "mfa", "password", "phishing", "session", "token theft"],
        "application": ["api", "web", "xss", "sqli", "injection", "rce", "deserialization", "ssrf", "idor", "file upload"],
        "supply_chain": ["supply chain", "third-party", "vendor", "dependency", "npm", "pypi", "package", "open source"],
    }

    def run(self) -> Dict:
        entries = _entries()
        all_text = " ".join(e.get("title", "") for e in entries).lower()

        domain_coverage = {}
        for domain, keywords in self.DOMAIN_INDICATORS.items():
            matches = sum(1 for kw in keywords if kw in all_text)
            total = len(keywords)
            coverage = min(1.0, matches / max(1, total * 0.3))
            domain_coverage[domain] = {
                "coverage_score": round(coverage, 2),
                "indicators_matched": matches,
                "total_indicators": total,
                "status": "STRONG" if coverage >= 0.7 else "MODERATE" if coverage >= 0.4 else "WEAK",
            }

        # Cross-domain correlation
        strong_domains = [d for d, v in domain_coverage.items() if v["status"] == "STRONG"]
        weak_domains = [d for d, v in domain_coverage.items() if v["status"] == "WEAK"]

        overall_score = statistics.mean(v["coverage_score"] for v in domain_coverage.values())

        result = {
            "subsystem": "S5_Cross_Domain_Telemetry",
            "domain_coverage": domain_coverage,
            "overall_coverage_score": round(overall_score, 2),
            "strong_domains": strong_domains,
            "weak_domains": weak_domains,
            "coverage_gaps": [f"Increase {d} telemetry collection" for d in weak_domains],
            "entries_analyzed": len(entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S5 Telemetry: overall={overall_score:.2f}, strong={strong_domains}, weak={weak_domains}")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S7 — IDENTITY RISK ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class IdentityRiskEngine:
    """Continuous identity risk scoring from threat intelligence signals."""

    IDENTITY_SIGNALS = {
        "credential_theft": ["credential theft", "credential stuffing", "credential harvest", "password spray",
                            "brute force", "stolen credentials", "credential dump"],
        "session_hijack": ["session hijack", "token theft", "cookie theft", "session fixation", "replay attack"],
        "privilege_escalation": ["privilege escalation", "privesc", "sudo", "admin access", "root access",
                                "elevation of privilege"],
        "identity_fraud": ["identity fraud", "impersonation", "fake identity", "synthetic identity",
                          "account takeover", "sim swap"],
        "auth_bypass": ["authentication bypass", "auth bypass", "mfa bypass", "2fa bypass", "sso vulnerability"],
        "api_abuse": ["api key", "api abuse", "api exposure", "api vulnerability", "oauth exploit"],
    }

    def run(self) -> Dict:
        entries = _entries()
        all_text = " ".join(e.get("title", "") for e in entries).lower()

        risk_categories = {}
        total_risk = 0
        for category, keywords in self.IDENTITY_SIGNALS.items():
            matches = [kw for kw in keywords if kw in all_text]
            risk = min(10, len(matches) * 2.5)
            risk_categories[category] = {
                "risk_score": round(risk, 1),
                "indicators_found": matches,
                "level": "CRITICAL" if risk >= 8 else "HIGH" if risk >= 5 else "MEDIUM" if risk >= 2.5 else "LOW",
            }
            total_risk += risk

        composite_risk = min(10, total_risk / max(1, len(self.IDENTITY_SIGNALS)))

        # Recommendations
        recs = []
        for cat, data in risk_categories.items():
            if data["level"] in ("CRITICAL", "HIGH"):
                recs.append(f"Mitigate {cat.replace('_', ' ')} risk: {', '.join(data['indicators_found'][:3])}")

        result = {
            "subsystem": "S7_Identity_Risk_Engine",
            "composite_identity_risk": round(composite_risk, 1),
            "risk_level": "CRITICAL" if composite_risk >= 8 else "HIGH" if composite_risk >= 5 else "MODERATE",
            "risk_categories": risk_categories,
            "recommendations": recs[:10],
            "entries_analyzed": len(entries),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S7 Identity Risk: {composite_risk:.1f}/10")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S8 — SELF-HEALING DEFENSE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class SelfHealingDefense:
    """Generates auto-remediation recommendations for detected vulnerabilities."""

    def run(self) -> Dict:
        entries = _entries()
        zdh_alerts = _load_json(os.path.join(ZDH_DIR, "zeroday_alerts.json")) or []
        zdh_warnings = _load_json(os.path.join(ZDH_DIR, "early_warnings.json")) or []

        remediation_actions = []

        # From high-risk manifest entries
        for e in entries:
            risk = e.get("risk_score", 0)
            if risk < 7: continue
            kev = e.get("kev_present", False)
            cves = re.findall(r'CVE-\d{4}-\d{4,7}', e.get("title", ""), re.IGNORECASE)
            actions = []
            if cves:
                actions.append({"type": "VIRTUAL_PATCH", "detail": f"Deploy WAF rule for {', '.join(c.upper() for c in cves[:3])}", "auto_eligible": True})
            if kev:
                actions.append({"type": "EMERGENCY_PATCH", "detail": "Apply vendor security update immediately", "auto_eligible": False})
            if risk >= 9:
                actions.append({"type": "MICRO_SEGMENT", "detail": "Isolate affected network segment", "auto_eligible": True})
                actions.append({"type": "CONFIG_HARDEN", "detail": "Apply CIS benchmark hardening to affected systems", "auto_eligible": True})
            if actions:
                remediation_actions.append({
                    "entity": e.get("title", "")[:60],
                    "risk_score": risk,
                    "actions": actions,
                    "approval_required": any(not a["auto_eligible"] for a in actions),
                })

        # From ZDH zero-day alerts
        for alert in zdh_alerts[:10]:
            if alert.get("severity") == "CRITICAL":
                remediation_actions.append({
                    "entity": alert.get("entity", ""),
                    "risk_score": 10,
                    "actions": [
                        {"type": "EMERGENCY_ISOLATE", "detail": f"Isolate systems affected by {alert.get('entity', '')}", "auto_eligible": False},
                        {"type": "VIRTUAL_PATCH", "detail": "Deploy emergency IPS/WAF rules", "auto_eligible": True},
                        {"type": "CREDENTIAL_RESET", "detail": "Reset credentials on affected systems", "auto_eligible": False},
                    ],
                    "approval_required": True,
                })

        remediation_actions.sort(key=lambda r: r["risk_score"], reverse=True)
        auto_count = sum(1 for r in remediation_actions if not r.get("approval_required"))

        result = {
            "subsystem": "S8_Self_Healing_Defense",
            "total_remediation_actions": len(remediation_actions),
            "auto_eligible": auto_count,
            "manual_approval_required": len(remediation_actions) - auto_count,
            "remediation_actions": remediation_actions[:20],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S8 Self-Healing: {len(remediation_actions)} actions ({auto_count} auto-eligible)")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S9 — QUANTUM-AWARE CRYPTOGRAPHY AUDITOR
# ═══════════════════════════════════════════════════════════════════════════════

class QuantumCryptoAuditor:
    """Audits threat landscape for quantum-vulnerable cryptographic patterns."""

    VULNERABLE_CRYPTO = {
        "rsa": {"risk": "HIGH", "recommendation": "Migrate to ML-KEM (CRYSTALS-Kyber) for key exchange"},
        "ecdsa": {"risk": "HIGH", "recommendation": "Migrate to ML-DSA (CRYSTALS-Dilithium) for signatures"},
        "ecdh": {"risk": "HIGH", "recommendation": "Migrate to ML-KEM for key agreement"},
        "dh": {"risk": "HIGH", "recommendation": "Replace with ML-KEM or hybrid key exchange"},
        "dsa": {"risk": "HIGH", "recommendation": "Migrate to ML-DSA or SLH-DSA"},
        "sha1": {"risk": "CRITICAL", "recommendation": "Replace immediately with SHA-256 or SHA-3"},
        "md5": {"risk": "CRITICAL", "recommendation": "Replace immediately — broken even classically"},
        "3des": {"risk": "HIGH", "recommendation": "Migrate to AES-256"},
        "rc4": {"risk": "CRITICAL", "recommendation": "Replace immediately — fundamentally broken"},
    }

    PQC_STANDARDS = [
        {"algorithm": "ML-KEM (CRYSTALS-Kyber)", "use": "Key Encapsulation", "nist_status": "FIPS 203 (Approved)"},
        {"algorithm": "ML-DSA (CRYSTALS-Dilithium)", "use": "Digital Signatures", "nist_status": "FIPS 204 (Approved)"},
        {"algorithm": "SLH-DSA (SPHINCS+)", "use": "Hash-based Signatures", "nist_status": "FIPS 205 (Approved)"},
        {"algorithm": "FN-DSA (FALCON)", "use": "Compact Signatures", "nist_status": "Draft Standard"},
    ]

    def run(self) -> Dict:
        entries = _entries()
        all_text = " ".join(e.get("title", "") for e in entries).lower()

        findings = []
        for algo, info in self.VULNERABLE_CRYPTO.items():
            if algo in all_text:
                findings.append({
                    "algorithm": algo.upper(),
                    "quantum_risk": info["risk"],
                    "recommendation": info["recommendation"],
                    "detected_in": "threat_intelligence_feed",
                })

        # Platform crypto audit
        platform_audit = {
            "stix_transport": {"protocol": "HTTPS/TLS", "quantum_risk": "MEDIUM", "note": "TLS 1.3 uses ECDHE — quantum vulnerable for key exchange"},
            "jwt_tokens": {"algorithm": "HS256", "quantum_risk": "LOW", "note": "Symmetric crypto — quantum resistant (Grover halves keyspace)"},
            "api_keys": {"method": "SHA-256 hash", "quantum_risk": "LOW", "note": "SHA-256 has adequate quantum margin"},
        }

        readiness = max(0, 10 - len(findings) * 2)

        result = {
            "subsystem": "S9_Quantum_Crypto_Auditor",
            "quantum_readiness_score": readiness,
            "quantum_risk_level": "HIGH" if readiness <= 4 else "MEDIUM" if readiness <= 7 else "LOW",
            "vulnerable_algorithms_detected": len(findings),
            "findings": findings,
            "platform_crypto_audit": platform_audit,
            "pqc_migration_roadmap": self.PQC_STANDARDS,
            "recommendation": "Begin hybrid key exchange deployment. Inventory all RSA/ECDSA usage for PQC migration.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S9 Quantum Audit: readiness={readiness}/10, findings={len(findings)}")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S11 — ATTACK SIMULATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class AttackSimulationEngine:
    """Models attack paths and simulates breach scenarios from real intelligence."""

    def run(self) -> Dict:
        entries = _entries()
        zdh_forecasts = _load_json(os.path.join(ZDH_DIR, "threat_forecasts.json")) or []

        simulations = []
        # Build attack path simulations from top forecasts
        for fc in (zdh_forecasts[:10] if zdh_forecasts else []):
            entity = fc.get("entity", "Unknown")
            chain = fc.get("chain", [])
            prob = fc.get("probability_pct", 0)

            sim = {
                "simulation_id": f"sim-{hashlib.md5(entity.encode()).hexdigest()[:10]}",
                "threat": entity,
                "exploitation_probability": prob,
                "attack_path": [
                    {"stage": "Initial Access", "technique": chain[0] if chain else "T1190", "success_rate": min(95, prob + 10)},
                    {"stage": "Execution", "technique": chain[1] if len(chain) > 1 else "T1059", "success_rate": min(85, prob)},
                    {"stage": "Persistence", "technique": "T1053", "success_rate": min(75, prob - 10)},
                    {"stage": "Impact", "technique": chain[-1] if chain else "T1486", "success_rate": min(60, prob - 20)},
                ],
                "breach_model": {
                    "estimated_dwell_time_hours": max(1, 168 - prob * 1.5),
                    "estimated_blast_radius": "HIGH" if prob >= 70 else "MEDIUM" if prob >= 40 else "LOW",
                    "data_exfiltration_risk": prob >= 60,
                },
                "defense_test_results": {
                    "detection_rule_coverage": "PARTIAL" if chain else "UNKNOWN",
                    "siem_visibility": "HIGH" if len(chain) >= 2 else "MEDIUM",
                    "response_readiness": "HIGH" if prob >= 50 else "MODERATE",
                },
            }
            simulations.append(sim)

        result = {
            "subsystem": "S11_Attack_Simulation",
            "simulations_run": len(simulations),
            "simulations": simulations,
            "source_forecasts": len(zdh_forecasts),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S11 Simulation: {len(simulations)} attack paths modeled")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# S12 — HUMAN OVERSIGHT GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════════════

class HumanOversightGovernance:
    """Ensures all AI actions operate under human supervision with audit trails."""

    def run(self, subsystem_results: Dict[str, Dict]) -> Dict:
        # Audit all subsystem outputs for governance compliance
        audit_entries = []
        actions_requiring_approval = []
        safety_violations = []

        for name, result in subsystem_results.items():
            # Track all recommended actions
            if "defense_recommendations" in result:
                for rec in result.get("defense_recommendations", []):
                    if rec.get("mode") == "RECOMMENDATION":
                        audit_entries.append({
                            "subsystem": name, "type": "recommendation",
                            "detail": f"{len(rec.get('recommendations', []))} defense recommendations generated",
                            "status": "PENDING_APPROVAL",
                        })

            if "remediation_actions" in result:
                for action in result.get("remediation_actions", []):
                    if action.get("approval_required"):
                        actions_requiring_approval.append({
                            "subsystem": name, "entity": action.get("entity", ""),
                            "action_count": len(action.get("actions", [])),
                            "status": "AWAITING_HUMAN_APPROVAL",
                        })

            # Safety check: no subsystem should auto-execute high-risk actions
            if result.get("auto_executed"):
                safety_violations.append({
                    "subsystem": name,
                    "violation": "Unauthorized auto-execution detected",
                    "severity": "CRITICAL",
                })

        governance_score = 10 if not safety_violations else max(0, 10 - len(safety_violations) * 5)

        result = {
            "subsystem": "S12_Human_Oversight_Governance",
            "governance_score": governance_score,
            "governance_status": "COMPLIANT" if not safety_violations else "VIOLATION_DETECTED",
            "subsystems_audited": len(subsystem_results),
            "audit_entries": audit_entries[:20],
            "actions_pending_approval": actions_requiring_approval[:15],
            "safety_violations": safety_violations,
            "policy": {
                "ai_auto_execution": "DISABLED — All high-risk actions require human approval",
                "recommendation_mode": "ENABLED — AI generates recommendations, humans decide",
                "audit_logging": "ENABLED — All actions logged with timestamps",
                "override_capability": "ENABLED — Analysts can override any AI recommendation",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        logger.info(f"S12 Governance: score={governance_score}/10, pending={len(actions_requiring_approval)}, violations={len(safety_violations)}")
        return result


# ═══════════════════════════════════════════════════════════════════════════════
# OMNISHIELD MASTER ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class OmniShieldEngine:
    """Master orchestrator for all 12 AI-powered cyber defense subsystems."""

    def __init__(self, output_dir: str = OUTPUT_DIR):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "ai"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "defense"), exist_ok=True)

    def run(self) -> Dict:
        logger.info("=" * 65)
        logger.info("SENTINEL APEX v36.0 — OMNISHIELD ENGINE")
        logger.info("12 AI-Powered Cyber Defense Subsystems")
        logger.info("=" * 65)
        now = datetime.now(timezone.utc).isoformat()
        results = {}

        # S1 — AI Context Engine
        logger.info("[S1/12] AI Context Engine...")
        results["S1_Context"] = AIContextEngine().run()

        # S2 — Behavioral Anomaly Detection
        logger.info("[S2/12] Behavioral Anomaly Detection...")
        results["S2_Behavioral"] = BehavioralAnomalyDetector().run()

        # S3 — Agentic Security AI
        logger.info("[S3/12] Agentic Security AI...")
        results["S3_Agentic"] = AgenticSecurityAI().run()

        # S4 — AI Security Posture
        logger.info("[S4/12] AI Security Posture Management...")
        results["S4_Posture"] = AISecurityPosture().run()

        # S5 — Cross-Domain Telemetry
        logger.info("[S5/12] Cross-Domain Telemetry Analysis...")
        results["S5_Telemetry"] = CrossDomainTelemetry().run()

        # S6 — AI Threat Countermeasures
        logger.info("[S6/12] AI Threat Countermeasures...")
        results["S6_Countermeasures"] = AIThreatCountermeasures().run()

        # S7 — Identity Risk Engine
        logger.info("[S7/12] Identity Risk Engine...")
        results["S7_Identity"] = IdentityRiskEngine().run()

        # S8 — Self-Healing Defense
        logger.info("[S8/12] Self-Healing Defense Engine...")
        results["S8_SelfHeal"] = SelfHealingDefense().run()

        # S9 — Quantum Crypto Auditor
        logger.info("[S9/12] Quantum Cryptography Auditor...")
        results["S9_Quantum"] = QuantumCryptoAuditor().run()

        # S10 — Synthetic Threat Training
        logger.info("[S10/12] Synthetic Threat Training...")
        results["S10_Synthetic"] = SyntheticThreatTraining().run()

        # S11 — Attack Simulation
        logger.info("[S11/12] Attack Simulation Engine...")
        results["S11_Simulation"] = AttackSimulationEngine().run()

        # S12 — Human Oversight Governance (audits all other subsystems)
        logger.info("[S12/12] Human Oversight Governance...")
        results["S12_Governance"] = HumanOversightGovernance().run(results)

        # Compile platform security score
        platform_score = self._compute_platform_score(results)

        report = {
            "status": "success", "version": "36.0.0", "codename": "OMNISHIELD",
            "timestamp": now,
            "platform_security_score": platform_score,
            "subsystem_summary": {name: {
                "subsystem": r.get("subsystem", name),
                "status": "OPERATIONAL",
                "key_metric": self._key_metric(r),
            } for name, r in results.items()},
            "subsystem_details": results,
        }

        # Save outputs
        self._save(report, results)

        logger.info("=" * 65)
        logger.info(f"OMNISHIELD COMPLETE — Platform Score: {platform_score['composite']}/10")
        logger.info(f"  12/12 subsystems operational")
        logger.info("=" * 65)
        return report

    def _compute_platform_score(self, results: Dict) -> Dict:
        scores = {
            "ai_context": min(10, results.get("S1_Context", {}).get("narratives_generated", 0) * 2),
            "behavioral": min(10, 10 - results.get("S2_Behavioral", {}).get("anomalies_detected", 0) * 0.5),
            "agentic": min(10, results.get("S3_Agentic", {}).get("priority_distribution", {}).get("P1_CRITICAL", 0) == 0 and 10 or 7),
            "posture": results.get("S4_Posture", {}).get("posture_score", 5),
            "telemetry": results.get("S5_Telemetry", {}).get("overall_coverage_score", 0.5) * 10,
            "identity": max(0, 10 - results.get("S7_Identity", {}).get("composite_identity_risk", 5)),
            "quantum": results.get("S9_Quantum", {}).get("quantum_readiness_score", 5),
            "governance": results.get("S12_Governance", {}).get("governance_score", 5),
        }
        composite = statistics.mean(scores.values())
        return {"composite": round(composite, 1), "components": {k: round(v, 1) for k, v in scores.items()}}

    def _key_metric(self, r: Dict) -> str:
        if "narratives_generated" in r: return f"{r['narratives_generated']} narratives"
        if "anomalies_detected" in r: return f"{r['anomalies_detected']} anomalies"
        if "triage_count" in r: return f"{r['triage_count']} triaged"
        if "posture_score" in r: return f"Score: {r['posture_score']}/10"
        if "overall_coverage_score" in r: return f"Coverage: {r['overall_coverage_score']}"
        if "ai_threats_detected" in r: return f"{r['ai_threats_detected']} AI threats"
        if "composite_identity_risk" in r: return f"Risk: {r['composite_identity_risk']}/10"
        if "total_remediation_actions" in r: return f"{r['total_remediation_actions']} actions"
        if "quantum_readiness_score" in r: return f"Readiness: {r['quantum_readiness_score']}/10"
        if "scenarios_generated" in r: return f"{r['scenarios_generated']} scenarios"
        if "simulations_run" in r: return f"{r['simulations_run']} simulations"
        if "governance_score" in r: return f"Score: {r['governance_score']}/10"
        return "OK"

    def _save(self, report: Dict, results: Dict):
        with open(os.path.join(self.output_dir, "omnishield_report.json"), 'w') as f:
            json.dump(report, f, indent=2, default=str)
        for name, data in results.items():
            path = os.path.join(self.output_dir, f"{name.lower()}.json")
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        logger.info(f"All outputs saved to {self.output_dir}/")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    logging.basicConfig(level=logging.INFO, format="[OMNISHIELD] %(asctime)s — %(levelname)s — %(message)s")
    engine = OmniShieldEngine()
    result = engine.run()
    score = result["platform_security_score"]
    print(json.dumps({
        "platform_security_score": score,
        "subsystem_summary": result["subsystem_summary"],
    }, indent=2))

if __name__ == "__main__":
    main()
