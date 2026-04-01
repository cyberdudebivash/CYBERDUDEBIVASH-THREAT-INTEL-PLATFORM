#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — AI SECURITY COPILOT v1.0                ║
║  Deterministic SOC intelligence engine — zero external LLM dependency     ║
║  Rule-based + template-driven threat analysis                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
Endpoint:  POST /api/v1/copilot/query
Features:
  • explain_threat  — SOC-style threat breakdown
  • what_to_do      — prioritized action plan
  • soc_report      — full structured SOC report
  • ioc_summary     — IOC intelligence digest
  • mitre_mapping   — ATT&CK technique context
  • risk_brief      — executive risk briefing
"""
from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-COPILOT")

BASE_DIR = Path(__file__).resolve().parent.parent

try:
    from fastapi import APIRouter, HTTPException, Header
    from pydantic import BaseModel as PM
    _FASTAPI_OK = True

    class CopilotRequest(PM):
        question:      str = ""      # Primary field
        query:         str = ""      # Alias for question (backwards compat)
        threat_id:     Optional[str] = None
        threat_data:   Optional[Dict] = None
        mode:          str = "explain_threat"   # explain_threat | what_to_do | soc_report | ioc_summary | mitre_mapping | risk_brief

except ImportError:
    _FASTAPI_OK = False
    class APIRouter:
        def post(self, *a, **kw): return lambda f: f

# ── MITRE ATT&CK knowledge base ───────────────────────────────────────────────
MITRE_CONTEXT: Dict[str, Dict] = {
    "T1190": {"name": "Exploit Public-Facing Application",  "tactic": "Initial Access",    "desc": "Attackers exploit vulnerabilities in internet-accessible applications to gain initial access.",        "mitigation": "Patch management, WAF deployment, input validation, network segmentation"},
    "T1133": {"name": "External Remote Services",           "tactic": "Initial Access",    "desc": "VPN, RDP, Citrix and similar remote services abused for unauthorized access.",                        "mitigation": "MFA on all remote access, VPN whitelisting, conditional access policies"},
    "T1566": {"name": "Phishing",                           "tactic": "Initial Access",    "desc": "Deceptive emails used to deliver malware or harvest credentials.",                                     "mitigation": "Email security gateway, DMARC/SPF/DKIM, security awareness training"},
    "T1078": {"name": "Valid Accounts",                     "tactic": "Initial Access",    "desc": "Stolen or compromised legitimate credentials used to gain access.",                                    "mitigation": "MFA enforcement, PAM solutions, credential monitoring, zero-trust"},
    "T1059": {"name": "Command and Scripting Interpreter",  "tactic": "Execution",         "desc": "Scripts (PowerShell, bash, Python) used to execute malicious commands.",                              "mitigation": "Script execution policies, application allowlisting, logging"},
    "T1486": {"name": "Data Encrypted for Impact",          "tactic": "Impact",            "desc": "Files encrypted by ransomware to deny access and extort victims.",                                    "mitigation": "Offline backups, EDR with behavioral detection, network segmentation"},
    "T1490": {"name": "Inhibit System Recovery",            "tactic": "Impact",            "desc": "Shadow copies and recovery mechanisms deleted to prevent restoration.",                               "mitigation": "Immutable backup solutions, privileged access management"},
    "T1562": {"name": "Impair Defenses",                    "tactic": "Defense Evasion",   "desc": "Security tools (AV, EDR, logs) disabled or tampered with.",                                          "mitigation": "Tamper-protection on security tools, centralized log management"},
    "T1055": {"name": "Process Injection",                  "tactic": "Defense Evasion",   "desc": "Malicious code injected into legitimate processes to evade detection.",                               "mitigation": "EDR with behavioral analytics, application control"},
    "T1003": {"name": "OS Credential Dumping",              "tactic": "Credential Access", "desc": "Credential material extracted from OS (LSASS, SAM, NTDS).",                                         "mitigation": "Credential Guard, LSA protection, privileged account monitoring"},
    "T1110": {"name": "Brute Force",                        "tactic": "Credential Access", "desc": "Password spraying, stuffing, or guessing attacks against authentication systems.",                    "mitigation": "Account lockout policies, MFA, adaptive authentication"},
    "T1046": {"name": "Network Service Discovery",          "tactic": "Discovery",         "desc": "Attacker maps network services and open ports for lateral movement planning.",                        "mitigation": "Network monitoring, IDS/IPS, micro-segmentation"},
    "T1021": {"name": "Remote Services",                    "tactic": "Lateral Movement",  "desc": "RDP, SSH, WMI used to move laterally through the environment.",                                       "mitigation": "Network segmentation, privileged access workstations, just-in-time access"},
    "T1041": {"name": "Exfiltration Over C2 Channel",       "tactic": "Exfiltration",      "desc": "Data stolen via the same command-and-control channel.",                                               "mitigation": "DLP, network monitoring, C2 detection rules in SIEM"},
    "T1530": {"name": "Data from Cloud Storage",            "tactic": "Collection",        "desc": "Sensitive data collected from misconfigured cloud storage (S3, Azure Blob).",                        "mitigation": "Cloud security posture management, storage ACL audits, data classification"},
    "T1195": {"name": "Supply Chain Compromise",            "tactic": "Initial Access",    "desc": "Software or hardware supply chain targeted to compromise downstream victims.",                        "mitigation": "Software composition analysis, vendor vetting, signed package verification"},
    "T1071": {"name": "Application Layer Protocol",         "tactic": "C2",               "desc": "HTTP/HTTPS/DNS used for command-and-control communications.",                                         "mitigation": "DNS monitoring, SSL inspection, network traffic analysis"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "desc": "Vulnerabilities exploited to gain elevated OS or application privileges.",                     "mitigation": "Vulnerability management, least-privilege, kernel protection"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution",         "desc": "WMI used for persistent execution and lateral movement.",                                            "mitigation": "WMI activity logging, WMIC access restrictions"},
    "T1539": {"name": "Steal Web Session Cookie",           "tactic": "Credential Access", "desc": "Session tokens stolen to bypass authentication.",                                                    "mitigation": "HTTPS-only cookies, SameSite attribute, token binding"},
}

# ── Threat type response templates ────────────────────────────────────────────
THREAT_PLAYBOOKS: Dict[str, Dict] = {
    "Ransomware": {
        "summary":        "Ransomware event requiring immediate containment and recovery response.",
        "primary_risk":   "Data encryption, business disruption, extortion, potential data leak",
        "urgency":        "CRITICAL — contain within 1 hour",
        "immediate":      ["Isolate affected systems from network immediately", "Do NOT pay ransom without legal/security consultation", "Preserve forensic evidence (memory dumps, logs)", "Activate incident response plan and notify stakeholders", "Check backup integrity before attempting recovery"],
        "short_term":     ["Identify patient zero and infection vector", "Scope the blast radius (affected systems/data)", "Restore from clean backups after environment validation", "Submit samples to AV vendors for detection updates", "File report with law enforcement (FBI IC3, CISA)"],
        "long_term":      ["Implement offline/immutable backup strategy", "Deploy EDR with ransomware-specific behavioral detection", "Segment network to limit lateral movement", "Security awareness training on phishing vectors", "Test incident response plan quarterly"],
        "detection":      "Monitor for: VSS deletion (vssadmin delete shadows), file rename storms, LSASS access, shadow copy deletion, SMB lateral movement",
    },
    "Vulnerability": {
        "summary":        "Exploitation of a software vulnerability requiring patch and compensating controls.",
        "primary_risk":   "Remote code execution, privilege escalation, unauthorized access",
        "urgency":        "HIGH — patch within vendor SLA, compensating controls immediately",
        "immediate":      ["Apply vendor patch — check NVD/vendor advisory for latest version", "If no patch available: implement WAF rules / virtual patching", "Block or restrict access to vulnerable service/endpoint", "Enable enhanced logging on affected systems", "Search SIEM for exploitation attempts in past 30 days"],
        "short_term":     ["Audit all systems running affected software versions", "Validate patch deployment with vulnerability scanner", "Review exploit-related IOCs for retroactive detection", "Test compensating controls in staging environment", "Update vulnerability management SLA based on CVSS/EPSS/KEV"],
        "long_term":      ["Implement continuous vulnerability management program", "Subscribe to vendor security advisories", "Integrate CVSS/EPSS/KEV data into patch prioritization", "Deploy EDR with exploit prevention capabilities", "Regular penetration testing on externally facing services"],
        "detection":      "Monitor for: exploitation signatures in WAF/IDS, anomalous process spawn from web services, unusual outbound connections post-exploit",
    },
    "Phishing": {
        "summary":        "Phishing campaign targeting credential theft or malware delivery.",
        "primary_risk":   "Credential compromise, initial access, BEC, wire fraud",
        "urgency":        "HIGH — contains immediately, credential reset required",
        "immediate":      ["Block malicious sender domains at email gateway", "Pull and delete phishing emails from all inboxes", "Force password reset for any users who interacted with email", "Invalidate active sessions for affected accounts", "Enable MFA immediately if not already active"],
        "short_term":     ["Hunt for additional phishing variants with similar indicators", "Check email gateway for similar campaigns in past 30 days", "Review OAuth app grants for suspicious authorizations", "Identify all users who opened the email or clicked links", "Report phishing infrastructure to hosting providers"],
        "long_term":      ["Deploy DMARC/DKIM/SPF with enforcement policies", "Implement AitM-resistant FIDO2 MFA", "User security awareness training with phishing simulations", "Email link rewriting and sandboxing", "Zero-trust email security with adaptive policies"],
        "detection":      "Monitor for: suspicious OAuth grants, impossible travel logins, forwarding rules on mailboxes, mass email from internal accounts",
    },
    "Malware": {
        "summary":        "Malware infection requiring endpoint investigation and remediation.",
        "primary_risk":   "Data theft, persistence, lateral movement, command-and-control",
        "urgency":        "HIGH — isolate affected endpoints immediately",
        "immediate":      ["Isolate infected endpoint(s) from the network", "Preserve forensic image and memory dump before remediation", "Identify C2 infrastructure and block at network level", "Search for lateral movement from infected system", "Change credentials of any accounts used on infected system"],
        "short_term":     ["Submit sample to AV vendors and threat intel feeds", "Hunt for malware IOCs across all endpoints", "Identify persistence mechanisms (registry, scheduled tasks, services)", "Review authentication logs for compromised account use", "Rebuild infected systems from known-good images"],
        "long_term":      ["Deploy next-gen EDR with behavioral detection", "Implement application allowlisting", "Network segmentation to limit C2 reach", "Email and web content filtering", "Threat intelligence integration for proactive IOC blocking"],
        "detection":      "Monitor for: unusual process spawning, LSASS access, scheduled task creation, suspicious registry modifications, outbound connections to new domains",
    },
    "Data Breach": {
        "summary":        "Data breach event requiring containment, investigation, and regulatory notification.",
        "primary_risk":   "Data loss, regulatory fines (GDPR/CCPA), reputational damage, litigation",
        "urgency":        "CRITICAL — legal notification requirements may apply (72h under GDPR)",
        "immediate":      ["Contain the breach vector — revoke access, patch vulnerability, or disable compromised service", "Identify what data was accessed/exfiltrated (scope, classification, volume)", "Engage legal counsel and data protection officer immediately", "Preserve all evidence and logs (chain of custody)", "Assess notification obligations (GDPR 72h, state breach laws)"],
        "short_term":     ["Notify affected individuals if personal data was involved", "Notify relevant regulators within required timeframes", "Engage forensics firm for thorough investigation", "Conduct root cause analysis to prevent recurrence", "Review and update data retention and access control policies"],
        "long_term":      ["Implement data loss prevention (DLP) controls", "Classify and tag sensitive data assets", "Zero-trust data access with need-to-know", "Regular access reviews and de-provisioning", "Incident response plan with legal/PR/regulatory coordination"],
        "detection":      "Monitor for: anomalous data access volumes, bulk download alerts, after-hours data access, access to sensitive data from unusual locations",
    },
    "APT": {
        "summary":        "Advanced Persistent Threat — sophisticated state-sponsored or organized criminal actor.",
        "primary_risk":   "Long-term compromise, intelligence gathering, sabotage, espionage",
        "urgency":        "CRITICAL — assume broad compromise, systematic investigation required",
        "immediate":      ["Engage specialized incident response firm with APT experience", "Do NOT alert attacker — maintain visibility while investigating", "Establish out-of-band communications (compromised systems may be monitored)", "Begin systematic threat hunting across the entire estate", "Identify crown jewel data and assess if targeted/accessed"],
        "short_term":     ["Map full scope of compromise (patient zero, pivot points, persistence)", "Identify all C2 channels and implant variants", "Collect and analyze all available forensic evidence", "Coordinate with government CERT/CISA if nation-state suspected", "Plan coordinated eviction once full scope is known"],
        "long_term":      ["Implement zero-trust architecture", "Deploy advanced threat detection (NDR, EDR, UEBA)", "Security architecture review with purple team exercises", "Threat intelligence program with APT group tracking", "Regular red team assessments"],
        "detection":      "Monitor for: living-off-the-land (LOTL) techniques, unusual admin tool usage, low-and-slow exfiltration, long-term persistent connections",
    },
    "Supply Chain": {
        "summary":        "Supply chain compromise — software or hardware vendor targeted to reach downstream victims.",
        "primary_risk":   "Trusted software/hardware as attack vector, broad organizational impact",
        "urgency":        "CRITICAL — assess whether you are an affected downstream target",
        "immediate":      ["Identify all instances of affected software/component in environment", "Isolate systems running compromised software version", "Check vendor advisory for indicators of compromise (IOCs)", "Hunt for IOCs across SIEM, EDR, and network logs", "Contact vendor for official guidance and updates"],
        "short_term":     ["Remove or update affected software per vendor guidance", "Audit all recent system changes on affected systems", "Review authentication from affected systems for anomalies", "Validate integrity of other software from same vendor", "Brief executive stakeholders on potential impact"],
        "long_term":      ["Implement software bill of materials (SBOM) tracking", "Software composition analysis in CI/CD pipeline", "Vendor security assessment program", "Signed binary verification and attestation", "Privileged access controls for software update mechanisms"],
        "detection":      "Monitor for: new processes spawning from trusted software, unexpected network connections from trusted applications, anomalous privilege use by service accounts",
    },
    "General": {
        "summary":        "Security advisory requiring assessment and appropriate response.",
        "primary_risk":   "Varies — assess based on affected assets and threat vector",
        "urgency":        "MEDIUM — assess and triage based on context",
        "immediate":      ["Review threat details and assess relevance to your environment", "Check if affected systems/software are present in inventory", "Search SIEM for related IOCs and indicators", "Notify relevant system owners for awareness", "Document initial assessment in your ticketing system"],
        "short_term":     ["Apply relevant patches or mitigations", "Update detection rules to include new IOCs", "Verify security controls are functioning correctly", "Brief security team on threat landscape update"],
        "long_term":      ["Review and update threat model", "Assess detection coverage gaps", "Security control effectiveness review"],
        "detection":      "Consult specific threat advisory for detection opportunities",
    },
}

# ── Severity context ──────────────────────────────────────────────────────────
SEV_CONTEXT = {
    "CRITICAL": "Immediate response required. Exploitation likely or confirmed. Potential for significant business impact.",
    "HIGH":     "Priority response within 24–72h. Exploitation feasible. Compensating controls should be deployed immediately.",
    "MEDIUM":   "Response within 7–30 days. Exploitation requires specific conditions. Monitor and plan remediation.",
    "LOW":      "Informational. Low exploitation probability. Address in routine maintenance cycles.",
    "INFO":     "No immediate action required. Track for situational awareness.",
}

# ── Core Copilot Engine ───────────────────────────────────────────────────────

class CopilotEngine:
    """Deterministic SOC intelligence engine. Zero external dependencies."""

    def __init__(self):
        self._manifest_cache: Optional[List[Dict]] = None
        self._cache_ts: float = 0

    def _load_manifest(self) -> List[Dict]:
        now = time.time()
        if self._manifest_cache is not None and now - self._cache_ts < 300:
            return self._manifest_cache
        paths = [
            BASE_DIR / "data" / "stix" / "feed_manifest.json",
            BASE_DIR / "data" / "enriched_manifest.json",
            BASE_DIR / "api" / "feed.json",
        ]
        for p in paths:
            try:
                if p.exists():
                    with open(p, encoding="utf-8") as f:
                        raw = json.load(f)
                    items = raw if isinstance(raw, list) else raw.get("data", raw.get("items", []))
                    if items:
                        self._manifest_cache = items
                        self._cache_ts       = now
                        return items
            except Exception:
                continue
        return []

    def _find_threat(self, threat_id: str) -> Optional[Dict]:
        for item in self._load_manifest():
            sid = item.get("stix_id", "") or ""
            if (threat_id.lower() in sid.lower() or
                threat_id.upper() in (item.get("title", "") + " ").upper() or
                threat_id.upper() in (str(item.get("mitre_tactics", ""))).upper()):
                return item
        return None

    def _soc_score_color(self, score: float) -> str:
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 5.0: return "MEDIUM"
        return "LOW"

    def _get_playbook(self, threat_type: str) -> Dict:
        # Normalize threat type
        for key in THREAT_PLAYBOOKS:
            if key.lower() in threat_type.lower():
                return THREAT_PLAYBOOKS[key]
        return THREAT_PLAYBOOKS["General"]

    def explain_threat(self, threat: Dict, question: str = "") -> Dict:
        """Generate SOC-style threat explanation."""
        sev    = (threat.get("severity") or "MEDIUM").upper()
        score  = float(threat.get("risk_score") or 0)
        ttype  = threat.get("threat_type") or "General"
        actor  = threat.get("actor_tag") or "UNATTRIBUTED"
        if actor in ("UNC-UNKNOWN", "UNC-CDB-99"):
            actor = "UNATTRIBUTED"
        cvss   = threat.get("cvss_score")
        epss   = threat.get("epss_score")
        kev    = threat.get("kev_present", False)
        mitre  = threat.get("mitre_tactics") or []
        sc     = threat.get("supply_chain", False)
        exploit= threat.get("exploit_probability") or "Unknown"
        pb     = self._get_playbook(ttype)

        # Build MITRE context
        mitre_details = []
        for t in mitre[:5]:
            ctx = MITRE_CONTEXT.get(t, {})
            if ctx:
                mitre_details.append({"technique": t, "name": ctx["name"], "tactic": ctx["tactic"], "description": ctx["desc"]})

        return {
            "mode":         "explain_threat",
            "title":        threat.get("title", "Unknown Threat"),
            "explanation": {
                "summary":         pb["summary"],
                "threat_category": ttype,
                "severity_context": SEV_CONTEXT.get(sev, "Review required."),
                "risk_assessment": {
                    "risk_score":    score,
                    "severity":      sev,
                    "risk_level":    self._soc_score_color(score),
                    "cvss":          cvss,
                    "epss_pct":      f"{float(epss)*100:.2f}%" if epss is not None else "N/A",
                    "kev_status":    "IN CISA KEV — exploitation confirmed" if kev else "Not in KEV",
                    "exploit_prob":  exploit,
                    "supply_chain":  "Yes — supply chain event" if sc else "No",
                    "actor":         actor,
                },
                "primary_risk":  pb["primary_risk"],
                "urgency":       pb["urgency"],
            },
            "mitre_context": mitre_details,
            "ioc_summary": {
                k: v for k, v in (threat.get("ioc_counts") or {}).items() if v and v > 0
            },
            "campaign": threat.get("campaign"),
            "openclaw":  threat.get("openclaw"),
        }

    def what_to_do(self, threat: Dict, question: str = "") -> Dict:
        """Generate prioritized action plan."""
        sev   = (threat.get("severity") or "MEDIUM").upper()
        score = float(threat.get("risk_score") or 0)
        ttype = threat.get("threat_type") or "General"
        kev   = threat.get("kev_present", False)
        pb    = self._get_playbook(ttype)

        # Adjust urgency for KEV
        urgency = pb["urgency"]
        if kev:
            urgency = "CRITICAL — CISA KEV confirmed exploitation, immediate action required"

        # Detection rules
        mitre = threat.get("mitre_tactics") or []
        detection_hints = []
        for t in mitre[:3]:
            ctx = MITRE_CONTEXT.get(t)
            if ctx:
                detection_hints.append(f"{t} ({ctx['name']}): {ctx['mitigation']}")

        return {
            "mode":        "what_to_do",
            "title":       threat.get("title", "Unknown Threat"),
            "action_plan": {
                "urgency":      urgency,
                "immediate_actions":   pb["immediate"],
                "short_term_actions":  pb["short_term"],
                "long_term_actions":   pb["long_term"],
                "detection_guidance":  pb["detection"],
                "mitre_mitigations":   detection_hints,
            },
            "soc_priority": {
                "ticket_priority": "P1" if score >= 9 else "P2" if score >= 7 else "P3" if score >= 5 else "P4",
                "sla_hours":       1 if score >= 9 else 4 if score >= 7 else 24 if score >= 5 else 72,
                "escalation_required": score >= 9 or kev,
            },
        }

    def soc_report(self, threat: Dict, question: str = "") -> Dict:
        """Generate full structured SOC report."""
        explain = self.explain_threat(threat, question)
        actions = self.what_to_do(threat, question)
        sev     = (threat.get("severity") or "MEDIUM").upper()
        score   = float(threat.get("risk_score") or 0)
        kev     = threat.get("kev_present", False)
        iocs    = threat.get("ioc_counts") or {}
        total_ioc = sum(v for v in iocs.values() if v)

        return {
            "mode":          "soc_report",
            "report_id":     f"CDB-SOC-{int(time.time())}",
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "classification": "TLP:AMBER" if score >= 7 else "TLP:GREEN",
            "title":         threat.get("title", "Unknown Threat"),
            "executive_summary": {
                "one_line":     f"{sev} severity {threat.get('threat_type','security event')} — risk score {score:.1f}/10{'  ⚠ CISA KEV confirmed exploitation' if kev else ''}",
                "business_impact": explain["explanation"]["primary_risk"],
                "urgency":         actions["action_plan"]["urgency"],
                "recommendation":  actions["action_plan"]["immediate_actions"][0] if actions["action_plan"]["immediate_actions"] else "Assess and triage",
            },
            "threat_intelligence": explain["explanation"],
            "ioc_intelligence": {
                "total_indicators": total_ioc,
                "breakdown":        iocs,
                "stix_bundle":      threat.get("stix_file"),
                "stix_id":          threat.get("stix_id"),
            },
            "response_plan":     actions["action_plan"],
            "soc_metadata":      actions["soc_priority"],
            "mitre_coverage":    explain["mitre_context"],
            "references": {
                "blog_url":    threat.get("blog_url"),
                "source_url":  threat.get("source_url"),
                "nvd_url":     threat.get("nvd_url"),
            },
        }

    def ioc_summary(self, threat: Dict, question: str = "") -> Dict:
        iocs  = threat.get("ioc_counts") or {}
        total = sum(v for v in iocs.values() if v)
        active = {k: v for k, v in iocs.items() if v and v > 0}
        tlp    = threat.get("tlp_label") or "TLP:CLEAR"
        return {
            "mode":     "ioc_summary",
            "title":    threat.get("title", "Unknown"),
            "total_indicators": total,
            "ioc_types": active,
            "tlp":       tlp,
            "stix_bundle": threat.get("stix_file"),
            "analyst_note": (
                f"This advisory contains {total} indicators of compromise across {len(active)} IOC types. "
                f"Classified {tlp}. "
                + ("Submit IOCs to your SIEM/SOAR for blocking and detection." if total > 0 else
                   "No IOCs extracted — check source for manual indicators.")
            ),
            "siem_action": "Block at firewall and add to SIEM watchlist" if total > 0 else "Monitor source for updated IOC data",
        }

    def mitre_mapping(self, threat: Dict, question: str = "") -> Dict:
        mitre = threat.get("mitre_tactics") or []
        mapped = []
        for t in mitre:
            ctx = MITRE_CONTEXT.get(t)
            if ctx:
                mapped.append({"technique_id": t, **ctx, "sigma_search": f"title: {ctx['name']}"})
            else:
                mapped.append({"technique_id": t, "name": "See MITRE ATT&CK", "tactic": "Unknown", "desc": "Lookup on attack.mitre.org", "mitigation": "See MITRE mitigation guidance"})
        return {
            "mode":      "mitre_mapping",
            "title":     threat.get("title", "Unknown"),
            "techniques": mapped,
            "tactic_coverage": list({m.get("tactic", "Unknown") for m in mapped if m.get("tactic")}),
            "sigma_query": " OR ".join(f'"{t}"' for t in mitre[:5]) if mitre else None,
            "detection_note": f"Detected {len(mitre)} ATT&CK techniques in this advisory. Create SIEM detection rules for each.",
        }

    def risk_brief(self, threat: Dict, question: str = "") -> Dict:
        score  = float(threat.get("risk_score") or 0)
        cvss   = threat.get("cvss_score")
        epss   = threat.get("epss_score")
        kev    = threat.get("kev_present", False)
        sc     = threat.get("supply_chain", False)
        level  = self._soc_score_color(score)
        pb     = self._get_playbook(threat.get("threat_type") or "General")

        fin_impact = {
            "CRITICAL": {"low_est": "$500K", "high_est": "$50M+",  "note": "Major breach or ransomware event potential"},
            "HIGH":     {"low_est": "$100K", "high_est": "$5M",    "note": "Significant incident with regulatory exposure"},
            "MEDIUM":   {"low_est": "$10K",  "high_est": "$500K",  "note": "Moderate incident, contained impact expected"},
            "LOW":      {"low_est": "$0",    "high_est": "$50K",   "note": "Low likelihood of significant financial impact"},
        }.get(level, {})

        return {
            "mode":         "risk_brief",
            "title":        threat.get("title", "Unknown"),
            "risk_summary": {
                "risk_score":      score,
                "risk_level":      level,
                "cvss":            cvss,
                "epss":            f"{float(epss)*100:.2f}%" if epss else "N/A",
                "kev":             kev,
                "supply_chain":    sc,
                "financial_impact_estimate": fin_impact,
                "remediation_urgency": pb["urgency"],
            },
            "board_summary": (
                f"A {level.lower()} severity cybersecurity advisory (risk score: {score:.1f}/10) affects your threat landscape. "
                f"{'CISA has confirmed active exploitation in the wild. ' if kev else ''}"
                f"{'This involves a supply chain event which may affect multiple vendors. ' if sc else ''}"
                f"Estimated financial exposure: {fin_impact.get('low_est','N/A')}–{fin_impact.get('high_est','N/A')}. "
                f"Recommended action: {pb['immediate'][0] if pb['immediate'] else 'Assess and triage.'}"
            ),
        }

    def query(self, question: str, mode: str, threat_id: Optional[str] = None, threat_data: Optional[Dict] = None) -> Dict:
        """Main query dispatcher."""
        t0 = time.time()

        # Resolve threat data
        threat = threat_data or {}
        if not threat and threat_id:
            threat = self._find_threat(threat_id) or {}
        if not threat:
            # Try to answer generically from question context
            threat = {
                "title":        f"Query: {question[:80]}",
                "severity":     "MEDIUM",
                "risk_score":   5.0,
                "threat_type":  "General",
                "mitre_tactics": [],
                "ioc_counts":   {},
            }

        # Dispatch mode
        MODES = {
            "explain_threat": self.explain_threat,
            "what_to_do":     self.what_to_do,
            "soc_report":     self.soc_report,
            "ioc_summary":    self.ioc_summary,
            "mitre_mapping":  self.mitre_mapping,
            "risk_brief":     self.risk_brief,
        }
        fn = MODES.get(mode, self.explain_threat)
        result = fn(threat, question)

        return {
            **result,
            "query":          question,
            "processed_in_ms": round((time.time() - t0) * 1000),
            "engine":          "CDB-Copilot v1.0 (deterministic)",
            "generated_at":    datetime.now(timezone.utc).isoformat(),
        }


# ── Singleton engine ──────────────────────────────────────────────────────────
_engine: Optional[CopilotEngine] = None

def get_engine() -> CopilotEngine:
    global _engine
    if _engine is None:
        _engine = CopilotEngine()
    return _engine

# ── FastAPI Router ────────────────────────────────────────────────────────────
if _FASTAPI_OK:
    copilot_router = APIRouter(prefix="/api/v1/copilot", tags=["AI Security Copilot"])

    @copilot_router.post("/query", summary="AI Security Copilot — SOC threat analysis")
    async def copilot_query(req: CopilotRequest):
        # Support both 'question' and 'query' field names
        effective_question = req.question or req.query or ""
        if not effective_question and not req.threat_id and not req.threat_data:
            raise HTTPException(400, {"error": "Provide question/query, threat_id, or threat_data"})

        valid_modes = {"explain_threat", "what_to_do", "soc_report", "ioc_summary", "mitre_mapping", "risk_brief"}
        mode = req.mode if req.mode in valid_modes else "explain_threat"

        try:
            engine = get_engine()
            result = engine.query(
                question   = effective_question,
                mode       = mode,
                threat_id  = req.threat_id,
                threat_data= req.threat_data,
            )
            return {"status": "ok", **result}
        except Exception as e:
            logger.error(f"Copilot error: {e}")
            raise HTTPException(500, {"error": "Copilot engine error — please retry", "detail": str(e)})

    @copilot_router.get("/modes", summary="List available copilot modes")
    async def list_modes():
        return {
            "status": "ok",
            "modes": [
                {"id": "explain_threat",  "label": "Explain Threat",        "desc": "SOC-style threat breakdown with context"},
                {"id": "what_to_do",      "label": "What Should I Do?",     "desc": "Prioritized action plan with SLA"},
                {"id": "soc_report",      "label": "Generate SOC Report",   "desc": "Full structured incident report"},
                {"id": "ioc_summary",     "label": "IOC Intelligence",      "desc": "IOC digest with SIEM guidance"},
                {"id": "mitre_mapping",   "label": "MITRE ATT&CK Mapping",  "desc": "Technique context and mitigations"},
                {"id": "risk_brief",      "label": "Executive Risk Brief",  "desc": "Board-level risk summary with $ impact"},
            ],
        }

    @copilot_router.get("/health", summary="Copilot engine health")
    async def copilot_health():
        engine = get_engine()
        items  = engine._load_manifest()
        return {
            "status":         "ok",
            "engine":         "CDB-Copilot v1.0",
            "manifest_loaded": len(items) > 0,
            "advisory_count":  len(items),
            "mitre_kb_size":   len(MITRE_CONTEXT),
            "playbooks":       len(THREAT_PLAYBOOKS),
        }
else:
    copilot_router = None
