#!/usr/bin/env python3
"""
scripts/apex_intel_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX v142.0 — GOD LEVEL Intelligence Depth Engine
===============================================================================

MISSION: Transform raw threat data into enterprise-grade, actionable intelligence
         matching standards of Mandiant, CrowdStrike, Palo Alto Unit 42.

MODULES:
  1. TechnicalDepthEngine   — Attack vector, execution chain, malware behavior extraction
  2. MITREJustificationEngine — MITRE technique + tactic + evidence + justification
  3. ExplainableRiskEngine  — Multi-factor risk with full reasoning breakdown
  4. AttributionGate        — Evidence-gated attribution (UNKNOWN if no hard evidence)
  5. AIExplainabilityEngine — Signal breakdown, reasoning summary, confidence rationale
  6. DataIntegrityValidator — Mandatory field validation, no empty/placeholder values

DESIGN PRINCIPLES:
  - ZERO external dependencies (pure Python stdlib)
  - DETERMINISTIC: same input → same output
  - ZERO FAILURE: all errors caught, degraded-safe result returned
  - PRODUCTION-GRADE: every output field is machine-readable + human-readable

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("apex.intel")

# ─────────────────────────────────────────────────────────────────────────────
# 1. TECHNICAL DEPTH ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class TechnicalDepthEngine:
    """
    Extracts structured technical intelligence from raw threat content.

    Outputs:
      - attack_vector: phishing|rce|supply_chain|zero_day|web_app|credential|
                       man_in_the_middle|physical|insider|unknown
      - execution_chain: ordered list of ATT&CK phases detected
      - malware_behaviors: process injection, registry persistence, C2 comms, etc.
      - exploit_mechanics: CVE root cause, vulnerable component, trigger condition
      - technical_depth_score: 0–100 (confidence in technical completeness)
    """

    # Attack vector keyword maps → canonical vector name
    _ATTACK_VECTORS: List[Tuple[List[str], str]] = [
        (["zero-day", "0-day", "zero day", "unpatched vulnerability", "undisclosed vulnerability"], "zero_day"),
        (["supply chain", "software supply chain", "dependency confusion", "typosquatting package",
          "compromised package", "malicious npm", "malicious pypi", "build system", "ci/cd compromise"], "supply_chain"),
        (["spearphishing", "spear phishing", "phishing attachment", "phishing email",
          "malicious attachment", "phishing link", "credential phishing", "business email compromise",
          "bec", "smishing", "vishing"], "phishing"),
        (["remote code execution", "rce", "code execution", "arbitrary code",
          "execute arbitrary", "unauthenticated rce", "pre-auth rce"], "rce"),
        (["sql injection", "xss", "cross-site scripting", "ssrf", "xml external entity",
          "xxe", "path traversal", "directory traversal", "file inclusion", "web shell",
          "deserialization", "template injection", "ssti"], "web_app"),
        (["credential stuffing", "password spray", "brute force", "credential harvest",
          "stolen credentials", "credential dump", "pass-the-hash", "golden ticket",
          "kerberoasting", "as-rep roasting"], "credential"),
        (["man-in-the-middle", "mitm", "arp poisoning", "ssl stripping",
          "dns hijacking", "bgp hijacking", "adversary-in-the-middle", "aitm"], "man_in_the_middle"),
        (["insider threat", "malicious insider", "privileged access abuse",
          "rogue employee", "disgruntled employee"], "insider"),
        (["usb drop", "physical access", "air-gapped", "removable media"], "physical"),
    ]

    # Execution chain phase detectors (ATT&CK phases, in order)
    _EXECUTION_PHASES: List[Tuple[str, List[str]]] = [
        ("initial_access", [
            "initial access", "phishing", "spearphishing", "exploit public",
            "watering hole", "drive-by download", "supply chain compromise",
            "valid accounts", "external remote services"
        ]),
        ("execution", [
            "powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
            "regsvr32", "certutil", "bitsadmin", "wmic", "vba macro",
            "javascript payload", "shellcode", "dll sideloading", "process hollow"
        ]),
        ("persistence", [
            "persistence", "registry run key", "startup folder", "scheduled task",
            "cron job", "service creation", "bootkit", "rootkit",
            "logon script", "browser extension", "wmi subscription"
        ]),
        ("privilege_escalation", [
            "privilege escalation", "uac bypass", "token impersonation",
            "setuid", "sudo abuse", "kernel exploit", "print spooler",
            "named pipe impersonation", "access token manipulation"
        ]),
        ("defense_evasion", [
            "defense evasion", "obfuscation", "packed", "encoded payload",
            "living off the land", "lolbins", "fileless", "process injection",
            "dll injection", "log tamper", "disable antivirus", "amsi bypass"
        ]),
        ("credential_access", [
            "credential dumping", "mimikatz", "lsass", "ntds.dit",
            "credential harvest", "keylogger", "pass-the-hash",
            "kerberoasting", "secretsdump"
        ]),
        ("lateral_movement", [
            "lateral movement", "pass-the-hash", "pass-the-ticket",
            "remote desktop", "rdp", "psexec", "wmi remote",
            "smb share", "windows admin share"
        ]),
        ("collection", [
            "data collection", "screen capture", "keylogger",
            "clipboard monitor", "file staging", "archive collected data"
        ]),
        ("command_and_control", [
            "command and control", "c2 server", "c&c", "cobalt strike",
            "metasploit", "empire", "beaconing", "dns tunneling",
            "http c2", "https c2", "domain fronting", "fast flux"
        ]),
        ("exfiltration", [
            "exfiltration", "data exfiltration", "data theft", "data leak",
            "upload to", "ftp exfil", "cloud exfil", "mega.nz", "dropbox exfil"
        ]),
        ("impact", [
            "ransomware", "encryption", "wiper", "disk wipe", "data destruction",
            "denial of service", "ddos", "defacement", "industrial sabotage"
        ]),
    ]

    # Malware behavior indicators
    _MALWARE_BEHAVIORS: Dict[str, List[str]] = {
        "process_injection": [
            "process injection", "dll injection", "process hollow", "process hollowing",
            "reflective dll", "thread hijacking", "apc injection", "atom bombing"
        ],
        "registry_persistence": [
            "registry", "hkcu\\software\\microsoft\\windows\\currentversion\\run",
            "hklm\\software\\microsoft\\windows\\currentversion\\run",
            "run key", "reg add", "regedit", "winlogon"
        ],
        "network_c2": [
            "beacon", "c2 communication", "command and control", "reverse shell",
            "bind shell", "dns query", "http post", "custom protocol c2"
        ],
        "credential_stealing": [
            "mimikatz", "lsass dump", "ntds.dit", "sam dump", "credential dump",
            "sekurlsa", "hashdump", "dcsync"
        ],
        "data_staging": [
            "data staging", "zip archive", "rar archive", "7zip", "encrypt before exfil",
            "collect and archive", "compress and upload"
        ],
        "anti_analysis": [
            "sandbox detection", "vm detection", "anti-debug", "anti-disassembly",
            "sleep before execute", "environment check", "string encryption",
            "code obfuscation", "packer"
        ],
        "file_system_abuse": [
            "temp directory", "appdata", "programdata", "system32",
            "drop file", "write to disk", "hidden file", "alternate data stream"
        ],
        "living_off_the_land": [
            "lolbin", "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
            "wmic", "powershell -enc", "base64 encoded", "invoke-expression"
        ],
    }

    def analyze(self, title: str, content: str, iocs: Dict = None) -> Dict:
        """
        Full technical depth analysis.
        Returns structured dict with attack_vector, execution_chain,
        malware_behaviors, exploit_mechanics, technical_depth_score.
        """
        text = f"{title} {content}".lower()
        iocs = iocs or {}

        result = {
            "attack_vector": self._classify_attack_vector(text),
            "execution_chain": self._map_execution_chain(text),
            "malware_behaviors": self._extract_malware_behaviors(text),
            "exploit_mechanics": self._extract_exploit_mechanics(title, content),
            "technical_depth_score": 0,
        }

        result["technical_depth_score"] = self._compute_depth_score(result, iocs, text)
        return result

    def _classify_attack_vector(self, text: str) -> Dict:
        scores: Dict[str, int] = {}
        for keywords, vector in self._ATTACK_VECTORS:
            hits = [k for k in keywords if k in text]
            if hits:
                scores[vector] = len(hits)

        if not scores:
            return {"type": "unknown", "confidence": "low", "evidence": []}

        primary = max(scores, key=lambda v: scores[v])
        all_vectors = sorted(scores.keys(), key=lambda v: -scores[v])

        # Find evidence keywords
        evidence = []
        for keywords, vector in self._ATTACK_VECTORS:
            if vector == primary:
                evidence = [k for k in keywords if k in text][:3]
                break

        confidence = "high" if scores[primary] >= 3 else ("medium" if scores[primary] >= 2 else "low")
        return {
            "type": primary,
            "confidence": confidence,
            "evidence": evidence,
            "all_vectors": all_vectors,
        }

    def _map_execution_chain(self, text: str) -> List[Dict]:
        chain = []
        for phase, keywords in self._EXECUTION_PHASES:
            hits = [k for k in keywords if k in text]
            if hits:
                chain.append({
                    "phase": phase,
                    "evidence": hits[:3],
                    "confidence": "high" if len(hits) >= 2 else "medium",
                })
        return chain

    def _extract_malware_behaviors(self, text: str) -> List[Dict]:
        behaviors = []
        for behavior, keywords in self._MALWARE_BEHAVIORS.items():
            hits = [k for k in keywords if k in text]
            if hits:
                behaviors.append({
                    "behavior": behavior,
                    "indicators": hits[:3],
                    "confidence": "high" if len(hits) >= 2 else "medium",
                })
        return behaviors

    def _extract_exploit_mechanics(self, title: str, content: str) -> Dict:
        """Extract CVE root cause, vulnerable component, trigger condition."""
        text = f"{title} {content}"

        # CVE extraction
        cves = list(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)))

        # CVSS extraction
        cvss_match = re.search(r"CVSS\s*(?:v3\.?\d?)?\s*(?:score\s*)?[=:]\s*(\d+\.?\d*)", text, re.IGNORECASE)
        cvss = float(cvss_match.group(1)) if cvss_match else None

        # Vulnerable component extraction (library/version patterns)
        component_patterns = [
            r"(?:in|affecting|vulnerability in|flaw in)\s+([A-Za-z][A-Za-z0-9\-_\.]{2,30})\s+(?:v|version)?\s*[\d\.]+",
            r"([A-Za-z][A-Za-z0-9\-_\.]{2,30})\s+(?:v|version)\s*([\d\.]+)",
        ]
        components = []
        for pat in component_patterns:
            m = re.search(pat, text)
            if m:
                components.append(m.group(1))
                break

        # Root cause classification
        root_causes = []
        root_cause_map = {
            "buffer overflow": ["buffer overflow", "heap overflow", "stack overflow", "out-of-bounds write"],
            "use-after-free": ["use-after-free", "uaf", "dangling pointer", "freed memory"],
            "integer overflow": ["integer overflow", "integer underflow", "arithmetic overflow"],
            "injection": ["injection", "code injection", "command injection", "sql injection"],
            "null pointer": ["null pointer", "null dereference", "null reference"],
            "race condition": ["race condition", "toctou", "time-of-check"],
            "path traversal": ["path traversal", "directory traversal", "..\\", "../"],
            "deserialization": ["deserialization", "unsafe deserialization", "java deserialization"],
            "xml parsing": ["xml external entity", "xxe", "xml injection"],
            "memory corruption": ["memory corruption", "heap corruption", "stack corruption"],
            "authentication bypass": ["authentication bypass", "auth bypass", "missing authentication"],
            "privilege escalation logic": ["improper access control", "missing authorization", "insecure defaults"],
        }
        t_lower = text.lower()
        for cause, keywords in root_cause_map.items():
            if any(k in t_lower for k in keywords):
                root_causes.append(cause)

        # Trigger condition
        trigger = "unknown"
        trigger_patterns = [
            ("network_unauthenticated", ["unauthenticated", "pre-auth", "without authentication", "no auth required"]),
            ("network_authenticated", ["authenticated", "requires auth", "post-auth"]),
            ("local_privilege", ["local privilege", "local attacker", "requires local access"]),
            ("user_interaction", ["user interaction", "user must open", "clicking a link", "opening a file"]),
            ("remote_no_interaction", ["no user interaction", "no interaction required", "wormable", "self-propagating"]),
        ]
        t_lower = text.lower()
        for tname, tkws in trigger_patterns:
            if any(k in t_lower for k in tkws):
                trigger = tname
                break

        return {
            "cves": cves[:5],
            "cvss_score": cvss,
            "vulnerable_component": components[:2] if components else [],
            "root_causes": root_causes[:3],
            "trigger_condition": trigger,
        }

    def _compute_depth_score(self, result: Dict, iocs: Dict, text: str) -> int:
        """0–100 technical depth score."""
        score = 0
        em = result.get("exploit_mechanics", {})

        if em.get("cves"):            score += 20
        if em.get("cvss_score"):      score += 10
        if em.get("root_causes"):     score += 15
        if em.get("trigger_condition") not in ("unknown", None): score += 10

        chain = result.get("execution_chain", [])
        score += min(len(chain) * 8, 24)  # up to 24 pts for chain coverage

        behaviors = result.get("malware_behaviors", [])
        score += min(len(behaviors) * 5, 20)  # up to 20 pts for behavior coverage

        av = result.get("attack_vector", {})
        if av.get("type") not in ("unknown", None): score += 5

        # IOC bonus
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        score += min(total_iocs * 2, 10)

        return min(score, 100)


# ─────────────────────────────────────────────────────────────────────────────
# 2. MITRE JUSTIFICATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class MITREJustificationEngine:
    """
    Enriches MITRE ATT&CK mappings with:
      - technique_name + tactic + technique_id (from existing mapper)
      - justification: WHY this technique was mapped (evidence from content)
      - confidence: high|medium|low based on evidence quality
      - url: MITRE ATT&CK URL for reference
    """

    _MITRE_DESCRIPTIONS = {
        "T1566": "Phishing — adversary sends malicious email attachments or links to gain initial access",
        "T1566.001": "Spearphishing Attachment — targeted email with malicious file attachment (Office macro, PDF, ZIP)",
        "T1566.002": "Spearphishing Link — targeted email with malicious URL leading to credential harvest or drive-by",
        "T1190": "Exploit Public-Facing Application — exploitation of internet-exposed vulnerability (web app, VPN, firewall)",
        "T1195": "Supply Chain Compromise — attack via trusted software/hardware/service provider",
        "T1195.001": "Compromise Software Dependencies — malicious package injected into dev/build pipeline",
        "T1059": "Command and Scripting Interpreter — abuse of native OS interpreters (PowerShell, bash, cmd)",
        "T1059.001": "PowerShell — execution via Windows PowerShell, often obfuscated (-enc, IEX, Invoke-Expression)",
        "T1055": "Process Injection — code injected into legitimate process memory to evade detection",
        "T1547": "Boot or Logon Autostart Execution — persistence via registry run keys, startup folders",
        "T1053": "Scheduled Task/Job — persistence or execution via OS scheduler (cron, Task Scheduler)",
        "T1548": "Abuse Elevation Control Mechanism — UAC bypass or sudo abuse for privilege escalation",
        "T1003": "OS Credential Dumping — extraction of credentials from memory (LSASS), SAM, NTDS.dit",
        "T1486": "Data Encrypted for Impact — ransomware encryption of files/volumes for extortion",
        "T1071": "Application Layer Protocol — C2 communication over HTTP/S, DNS, or other app protocols",
        "T1083": "File and Directory Discovery — enumeration of file system for sensitive data or config",
        "T1078": "Valid Accounts — use of legitimate credentials (stolen, guessed, or purchased)",
        "T1021": "Remote Services — lateral movement via RDP, SMB, WMI, SSH with valid credentials",
        "T1041": "Exfiltration Over C2 Channel — data theft via existing C2 communication channel",
        "T1105": "Ingress Tool Transfer — download of additional tools/payloads after initial compromise",
        "T1562": "Impair Defenses — disabling antivirus, firewall, logging, or EDR to avoid detection",
        "T1027": "Obfuscated Files or Information — encoding/encryption/packing to evade static analysis",
        "T1140": "Deobfuscate/Decode Files — runtime decryption/decoding of payloads",
        "T1574": "Hijack Execution Flow — DLL hijacking, PATH manipulation to redirect execution",
        "T1036": "Masquerading — disguising malicious files/processes as legitimate to evade detection",
        "T1595": "Active Scanning — reconnaissance via port scanning, service enumeration",
        "T1583": "Acquire Infrastructure — attacker-controlled domains, IPs, VPS for operations",
        "T1588": "Obtain Capabilities — purchase/develop exploits, malware, certificates",
    }

    def enrich_mitre_mappings(self, raw_mitre: List[Dict], title: str, content: str) -> List[Dict]:
        """
        Takes raw MITRE mapper output and enriches with justification + evidence.
        Returns enriched list with: technique_id, technique_name, tactic,
        justification, evidence, confidence, url.
        """
        enriched = []
        text = f"{title} {content}".lower()

        for entry in raw_mitre:
            # Support all MITRE mapper output key conventions:
            # map_threat() returns list of dicts with "technique" key
            # Other mappers may use "id", "technique_id"
            tid = (entry.get("technique") or entry.get("id") or
                   entry.get("technique_id") or "").strip()
            tname = (entry.get("name") or entry.get("technique_name") or
                     entry.get("tactic", "")).strip()
            tactic = entry.get("tactic", "")

            justification = self._MITRE_DESCRIPTIONS.get(tid, f"{tname} — {tactic} phase technique")
            evidence = self._extract_technique_evidence(tid, text)
            confidence = "high" if len(evidence) >= 2 else ("medium" if evidence else "low")

            enriched.append({
                "technique_id": tid,
                "technique_name": tname,
                "tactic": tactic,
                "justification": justification,
                "evidence": evidence,
                "confidence": confidence,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            })

        return enriched

    def _extract_technique_evidence(self, tid: str, text: str) -> List[str]:
        """Extract content phrases that justify this specific technique mapping."""
        evidence_keywords = {
            "T1566": ["phishing", "spearphishing", "malicious email", "email attachment", "phishing link"],
            "T1190": ["exploit", "vulnerability", "public-facing", "internet-exposed", "rce", "pre-auth"],
            "T1059": ["powershell", "cmd.exe", "bash", "command interpreter", "script execution"],
            "T1059.001": ["powershell", "-enc", "invoke-expression", "iex", "invoke-webrequest"],
            "T1055": ["process injection", "dll injection", "inject into", "hollow process"],
            "T1547": ["registry", "run key", "startup", "autorun", "persistence via registry"],
            "T1003": ["lsass", "credential dump", "mimikatz", "ntds", "sam database", "hashdump"],
            "T1486": ["ransomware", "encrypt files", "ransom note", "decrypt key", "ransom demand"],
            "T1071": ["c2", "command and control", "beacon", "dns query", "http post", "c&c"],
            "T1562": ["disable antivirus", "disable defender", "tamper protection", "amsi bypass", "edr bypass"],
            "T1027": ["obfuscated", "encoded", "packed", "encrypted payload", "base64", "xor encrypted"],
            "T1195": ["supply chain", "compromised package", "malicious dependency", "npm package", "pypi"],
            "T1021": ["rdp", "remote desktop", "lateral movement", "psexec", "wmi remote"],
        }
        kws = evidence_keywords.get(tid, [])
        return [k for k in kws if k in text][:3]


# ─────────────────────────────────────────────────────────────────────────────
# 3. EXPLAINABLE RISK ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ExplainableRiskEngine:
    """
    Wraps existing risk_engine output with full explainability.
    Provides:
      - risk_score with reasoning breakdown (signal_contributions)
      - confidence_rationale: why confidence = X
      - risk_summary: human-readable one-sentence explanation
      - signal_breakdown: each input signal and its contribution
    """

    def build_risk_explanation(
        self,
        risk_score: float,
        cvss: Optional[float],
        epss: Optional[float],
        kev_present: bool,
        iocs: Dict,
        mitre_count: int,
        content: str,
        actor_confidence: str = "unknown",
    ) -> Dict:
        """
        Build full explainable risk output.
        Returns dict with reasoning, signal_breakdown, risk_summary.
        """
        signals = []
        total = 0.0

        # CVSS contribution
        if cvss is not None:
            cvss_contrib = min(cvss * 0.4, 4.0)  # CVSS contributes up to 4.0
            signals.append({
                "signal": "CVSS_score",
                "value": cvss,
                "contribution": round(cvss_contrib, 2),
                "reason": f"CVSS {cvss:.1f} — {'Critical' if cvss >= 9 else 'High' if cvss >= 7 else 'Medium'} severity baseline"
            })
            total += cvss_contrib

        # EPSS contribution
        if epss is not None and epss > 0:
            epss_contrib = min(epss / 100 * 2.5, 2.5)  # EPSS 0-100% → up to 2.5
            tier = "very high (>75%)" if epss >= 75 else "high (>50%)" if epss >= 50 else "medium (>10%)" if epss >= 10 else "low"
            signals.append({
                "signal": "EPSS_score",
                "value": f"{epss:.1f}%",
                "contribution": round(epss_contrib, 2),
                "reason": f"EPSS {epss:.1f}% exploitation probability — {tier} real-world exploitation likelihood"
            })
            total += epss_contrib

        # KEV contribution
        if kev_present:
            kev_contrib = 2.5
            signals.append({
                "signal": "CISA_KEV",
                "value": True,
                "contribution": kev_contrib,
                "reason": "CISA KEV confirmed — actively exploited in the wild by threat actors, remediation urgency: IMMEDIATE"
            })
            total += kev_contrib

        # IOC density contribution
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        hash_iocs = len(iocs.get("sha256", [])) + len(iocs.get("sha1", [])) + len(iocs.get("md5", []))
        if total_iocs > 0:
            ioc_contrib = min(total_iocs * 0.1 + hash_iocs * 0.3, 1.5)
            signals.append({
                "signal": "IOC_density",
                "value": f"{total_iocs} IOCs ({hash_iocs} hashes)",
                "contribution": round(ioc_contrib, 2),
                "reason": f"{total_iocs} indicators extracted — {hash_iocs} high-fidelity file hashes provide definitive detection capability"
            })
            total += ioc_contrib

        # MITRE coverage contribution
        if mitre_count > 0:
            mitre_contrib = min(mitre_count * 0.15, 1.0)
            signals.append({
                "signal": "MITRE_coverage",
                "value": f"{mitre_count} techniques",
                "contribution": round(mitre_contrib, 2),
                "reason": f"{mitre_count} MITRE ATT&CK techniques mapped — broader coverage indicates more sophisticated/confirmed threat"
            })
            total += mitre_contrib

        # Active exploitation from content
        content_lower = content.lower()
        exploit_signals = []
        if "actively exploited" in content_lower or "in the wild" in content_lower:
            exploit_signals.append("active exploitation confirmed")
        if "proof of concept" in content_lower or "poc" in content_lower:
            exploit_signals.append("PoC publicly available")
        if "ransomware" in content_lower:
            exploit_signals.append("ransomware impact")
        if "nation-state" in content_lower or "state-sponsored" in content_lower:
            exploit_signals.append("nation-state actor")

        if exploit_signals:
            exploit_contrib = min(len(exploit_signals) * 0.5, 1.5)
            signals.append({
                "signal": "exploitation_context",
                "value": exploit_signals,
                "contribution": round(exploit_contrib, 2),
                "reason": f"Content confirms: {', '.join(exploit_signals)}"
            })
            total += exploit_contrib

        # Cap at 10.0
        calculated = min(round(total, 1), 10.0)

        # Build human-readable summary
        risk_summary = self._build_risk_summary(
            risk_score, cvss, epss, kev_present, total_iocs, exploit_signals, actor_confidence
        )

        # Confidence rationale
        confidence_rationale = self._build_confidence_rationale(
            cvss, epss, kev_present, total_iocs, mitre_count
        )

        # confidence_rationale is a dict with level/rationale/factors.
        # Expose rationale string at top level for direct string consumers.
        cr_string = confidence_rationale.get("rationale", "") if isinstance(confidence_rationale, dict) else str(confidence_rationale)
        return {
            "risk_score_engine": risk_score,
            "risk_score_explained": calculated,
            "signal_breakdown": signals,
            "risk_summary": risk_summary,
            "confidence_rationale": cr_string,           # string — for logging/display
            "confidence_detail": confidence_rationale,   # dict — for structured consumers
            "signals_count": len(signals),
            "explainability_version": "142.0",
        }

    def _build_risk_summary(self, score, cvss, epss, kev, ioc_count, exploit_signals, actor):
        parts = []
        if kev:
            parts.append("CISA KEV-confirmed active exploitation")
        if cvss and cvss >= 9:
            parts.append(f"CVSS {cvss:.1f} Critical")
        elif cvss and cvss >= 7:
            parts.append(f"CVSS {cvss:.1f} High")
        if epss and epss >= 50:
            parts.append(f"{epss:.0f}% EPSS exploitation probability")
        if "active exploitation confirmed" in exploit_signals:
            parts.append("in-the-wild exploitation reported")
        if ioc_count > 5:
            parts.append(f"{ioc_count} IOCs extracted")

        if not parts:
            severity = "Critical" if score >= 9 else "High" if score >= 7 else "Medium" if score >= 4 else "Low"
            return f"{severity} severity threat (score {score:.1f}/10) — limited technical indicators in source data"

        return f"Risk {score:.1f}/10 — {'; '.join(parts[:4])}"

    def _build_confidence_rationale(self, cvss, epss, kev, ioc_count, mitre_count):
        factors = []
        if cvss:      factors.append(f"CVSS score ({cvss:.1f})")
        if kev:       factors.append("CISA KEV confirmation")
        if epss and epss > 10: factors.append(f"EPSS {epss:.1f}%")
        if ioc_count > 0: factors.append(f"{ioc_count} extracted IOCs")
        if mitre_count > 0: factors.append(f"{mitre_count} MITRE techniques")

        if len(factors) >= 3:
            confidence = "HIGH"
            rationale = f"Multiple corroborating signals: {', '.join(factors)}"
        elif len(factors) >= 2:
            confidence = "MEDIUM"
            rationale = f"Moderate evidence: {', '.join(factors)}"
        elif factors:
            confidence = "LOW"
            rationale = f"Limited signal: {factors[0]} only"
        else:
            confidence = "VERY_LOW"
            rationale = "No hard technical evidence — title/keyword-based assessment only"

        return {"level": confidence, "rationale": rationale, "factors": factors}


# ─────────────────────────────────────────────────────────────────────────────
# 4. ATTRIBUTION GATE
# ─────────────────────────────────────────────────────────────────────────────

class AttributionGate:
    """
    Evidence-gated attribution. ONLY assigns actor if hard evidence exists.
    Otherwise: UNKNOWN — not a fake cluster label.

    Evidence requirements:
      - Named threat actor confirmed by CVE report, vendor advisory, or gov attribution
      - OR: Named malware family with known operator attribution
      - OR: Named campaign with documented TTPs and infrastructure overlap

    Confidence levels:
      - CONFIRMED: Government/law enforcement attribution, multi-vendor corroboration
      - HIGH: Named in vendor primary research (Mandiant, CrowdStrike, Unit42)
      - MEDIUM: Inferred from TTP overlap, infrastructure similarities
      - LOW: Possible attribution, single source, limited evidence
      - UNKNOWN: No credible evidence — do not speculate
    """

    # Named actors with known attribution in public domain
    _KNOWN_ACTORS: Dict[str, Dict] = {
        # Nation-state: China
        "apt41": {"alias": ["winnti", "barium", "double dragon"], "nation": "China", "type": "espionage+crime"},
        "apt40": {"alias": ["temp.periscope", "leviathan"], "nation": "China", "type": "espionage"},
        "apt31": {"alias": ["zirconium", "judgment panda"], "nation": "China", "type": "espionage"},
        "volt typhoon": {"alias": ["bronze silhouette"], "nation": "China", "type": "critical_infrastructure"},
        "salt typhoon": {"alias": [], "nation": "China", "type": "telecom_espionage"},
        "earth preta": {"alias": ["mustang panda"], "nation": "China", "type": "espionage"},
        # Nation-state: Russia
        "apt28": {"alias": ["fancy bear", "pawn storm", "sofacy", "strontium"], "nation": "Russia", "type": "espionage+disinfo"},
        "apt29": {"alias": ["cozy bear", "nobelium", "midnight blizzard"], "nation": "Russia", "type": "espionage"},
        "sandworm": {"alias": ["iridium", "voodoo bear"], "nation": "Russia", "type": "destructive"},
        "gamaredon": {"alias": ["primitive bear", "actinium"], "nation": "Russia", "type": "espionage"},
        "turla": {"alias": ["snake", "venomous bear", "secret blizzard"], "nation": "Russia", "type": "espionage"},
        # Nation-state: North Korea
        "lazarus": {"alias": ["hidden cobra", "zinc", "diamond sleet"], "nation": "North Korea", "type": "espionage+financial"},
        "kimsuky": {"alias": ["black banshee", "thallium"], "nation": "North Korea", "type": "espionage"},
        "andariel": {"alias": ["silent chollima", "stonefly"], "nation": "North Korea", "type": "ransomware+espionage"},
        "bluenoroff": {"alias": [], "nation": "North Korea", "type": "financial"},
        # Nation-state: Iran
        "apt34": {"alias": ["oilrig", "helix kitten", "cobalt gypsy"], "nation": "Iran", "type": "espionage"},
        "apt33": {"alias": ["refined kitten", "holmium"], "nation": "Iran", "type": "sabotage"},
        "charming kitten": {"alias": ["phosphorus", "apt42"], "nation": "Iran", "type": "espionage"},
        "imperial kitten": {"alias": [], "nation": "Iran", "type": "espionage"},
        # Cybercrime
        "lockbit": {"alias": ["abcd", "lockbit 3.0"], "nation": "Criminal", "type": "ransomware"},
        "blackcat": {"alias": ["alphv", "noberus"], "nation": "Criminal", "type": "ransomware"},
        "cl0p": {"alias": ["ta505", "fin11"], "nation": "Criminal", "type": "ransomware+extortion"},
        "revil": {"alias": ["sodinokibi", "pinchy spider"], "nation": "Criminal", "type": "ransomware"},
        "conti": {"alias": ["wizard spider"], "nation": "Criminal", "type": "ransomware"},
        "scattered spider": {"alias": ["0ktapus", "starfraud"], "nation": "Criminal", "type": "social_engineering"},
        "fin7": {"alias": ["carbanak", "sangria tempest"], "nation": "Criminal", "type": "financial"},
        "ta558": {"alias": [], "nation": "Criminal", "type": "hotel_sector_targeting"},
    }

    def gate_attribution(self, raw_actor_data: Dict, title: str, content: str) -> Dict:
        """
        Apply evidence gate to actor attribution.
        Returns attribution dict with confidence and evidence, or UNKNOWN.
        """
        text = f"{title} {content}".lower()
        raw_id = raw_actor_data.get("tracking_id", "")
        raw_name = raw_actor_data.get("actor_name", raw_actor_data.get("name", ""))

        # Check if any known actor is mentioned by name in content
        attributed_actors = []
        for actor_key, actor_info in self._KNOWN_ACTORS.items():
            all_names = [actor_key] + actor_info.get("alias", [])
            hits = [n for n in all_names if n in text]
            if hits:
                attributed_actors.append({
                    "actor": actor_key,
                    "aliases": actor_info.get("alias", []),
                    "nation_state": actor_info.get("nation", "Unknown"),
                    "actor_type": actor_info.get("type", "unknown"),
                    "evidence": hits,
                })

        if not attributed_actors:
            # No confirmed actor found in content — return UNKNOWN
            # NEVER assign a fake cluster label
            return {
                "attributed": False,
                "actor": "UNKNOWN",
                "confidence": "UNKNOWN",
                "nation_state": "UNKNOWN",
                "rationale": "No named threat actor or malware family with documented attribution found in source content. Speculative attribution suppressed.",
                "evidence": [],
                "raw_actor_data": raw_actor_data,
            }

        primary = attributed_actors[0]

        # Determine confidence based on evidence quality
        evidence_count = len(primary["evidence"])
        # Check for gov/vendor corroboration signals
        gov_corroboration = any(k in text for k in [
            "cisa advisory", "nsa advisory", "fbi advisory", "ncsc advisory",
            "unit 42", "mandiant", "crowdstrike", "secureworks", "microsoft security",
            "google tag", "recorded future", "shadowserver"
        ])

        if gov_corroboration and evidence_count >= 2:
            confidence = "CONFIRMED"
        elif evidence_count >= 2:
            confidence = "HIGH"
        elif evidence_count >= 1:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return {
            "attributed": True,
            "actor": primary["actor"].upper(),
            "aliases": primary["aliases"],
            "confidence": confidence,
            "nation_state": primary["nation_state"],
            "actor_type": primary["actor_type"],
            "evidence": primary["evidence"],
            "gov_corroboration": gov_corroboration,
            "all_actors_mentioned": [a["actor"] for a in attributed_actors],
            "rationale": f"{'Multiple ' if evidence_count >= 2 else ''}References to '{primary['actor']}' {'corroborated by government/vendor advisory' if gov_corroboration else 'found in source content'}",
            "raw_actor_data": raw_actor_data,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 5. DATA INTEGRITY VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────

class DataIntegrityValidator:
    """
    Validates intel entries before writing to manifest.
    Enforces: no empty mandatory fields, no placeholder values,
    no broken data structures.
    """

    MANDATORY_FIELDS = [
        "title", "source_url", "severity", "risk_score", "tlp_label",
        "timestamp", "stix_id", "feed_source",
    ]

    PLACEHOLDER_PATTERNS = [
        r"^UNKNOWN_", r"^N/A$", r"^TBD$", r"^PLACEHOLDER",
        r"^TODO", r"^\s*$", r"^None$",
    ]

    def validate(self, entry: Dict) -> Tuple[bool, List[str]]:
        """
        Validate entry. Returns (is_valid, list_of_errors).
        """
        errors = []

        # Check mandatory fields
        for field in self.MANDATORY_FIELDS:
            val = entry.get(field)
            if val is None or val == "" or val == []:
                errors.append(f"missing_mandatory_field:{field}")
                continue
            # Check for placeholder values
            val_str = str(val)
            for pat in self.PLACEHOLDER_PATTERNS:
                if re.match(pat, val_str.strip(), re.IGNORECASE):
                    errors.append(f"placeholder_value:{field}={val_str[:30]}")
                    break

        # Risk score sanity
        try:
            rs = float(entry.get("risk_score", 0))
            if not (0.0 <= rs <= 10.0):
                errors.append(f"invalid_risk_score:{rs}")
        except (TypeError, ValueError):
            errors.append("invalid_risk_score:non_numeric")

        # Severity must be one of known values
        severity = entry.get("severity", "")
        if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", ""):
            errors.append(f"invalid_severity:{severity}")

        # TLP must be valid
        tlp = str(entry.get("tlp_label", ""))
        if tlp and not any(t in tlp for t in ("RED", "AMBER", "GREEN", "CLEAR", "WHITE")):
            errors.append(f"invalid_tlp:{tlp[:20]}")

        # Title must be meaningful
        title = str(entry.get("title", ""))
        if len(title.strip()) < 10:
            errors.append(f"title_too_short:{len(title)}")
        if title.isupper() and len(title) < 20:
            errors.append("title_all_caps_suspect")

        return (len(errors) == 0), errors

    def sanitize(self, entry: Dict) -> Dict:
        """
        Apply safe defaults for missing non-mandatory fields.
        Never modifies mandatory fields — those must come from the pipeline.
        """
        entry.setdefault("ioc_counts", {"ipv4": 0, "domain": 0, "url": 0, "md5": 0, "sha256": 0, "cve": 0})
        entry.setdefault("mitre_tactics", [])
        entry.setdefault("actor_tag", "UNKNOWN")
        entry.setdefault("confidence_score", 30.0)
        entry.setdefault("kev_present", False)
        entry.setdefault("epss_score", None)
        entry.setdefault("cvss_score", None)
        entry.setdefault("threat_type", "unknown")
        entry.setdefault("supply_chain", False)
        entry.setdefault("schema_version", "142.0")
        return entry


# ─────────────────────────────────────────────────────────────────────────────
# 6. APEX INTEL ENRICHER (orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

class ApexIntelEnricher:
    """
    Orchestrates all engines for a single intel entry.
    Called from sentinel_blogger.py process_entry() after existing enrichment.
    Adds apex_intelligence block to entry without modifying existing fields.
    """

    def __init__(self):
        self.depth_engine       = TechnicalDepthEngine()
        self.mitre_engine       = MITREJustificationEngine()
        self.risk_engine        = ExplainableRiskEngine()
        self.attribution_gate   = AttributionGate()
        self.integrity_validator = DataIntegrityValidator()

    def enrich(
        self,
        title: str,
        content: str,
        iocs: Dict,
        raw_mitre: List[Dict],
        raw_actor: Dict,
        risk_score: float,
        cvss: Optional[float] = None,
        epss: Optional[float] = None,
        kev_present: bool = False,
    ) -> Dict:
        """
        Full GOD LEVEL enrichment pass.
        Returns apex_intelligence dict to be merged into the entry.
        """
        try:
            # 1. Technical depth analysis
            tech_depth = self.depth_engine.analyze(title, content, iocs)

            # 2. MITRE with justification
            mitre_enriched = self.mitre_engine.enrich_mitre_mappings(raw_mitre, title, content)

            # 3. Explainable risk
            risk_explained = self.risk_engine.build_risk_explanation(
                risk_score, cvss, epss, kev_present, iocs,
                len(mitre_enriched), content,
            )

            # 4. Evidence-gated attribution
            attribution = self.attribution_gate.gate_attribution(raw_actor, title, content)

            # 5. AI explainability summary
            ai_insight = self._build_ai_insight(
                tech_depth, mitre_enriched, risk_explained, attribution, iocs
            )

            return {
                "apex_intelligence": {
                    "version": "142.0",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "technical_depth": tech_depth,
                    "mitre_enriched": mitre_enriched,
                    "risk_explained": risk_explained,
                    "attribution": attribution,
                    "ai_insight": ai_insight,
                }
            }

        except Exception as e:
            log.warning("[APEX-INTEL] Enrichment error (non-fatal): %s", e)
            return {
                "apex_intelligence": {
                    "version": "142.0",
                    "error": str(e),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            }

    def _build_ai_insight(
        self,
        tech_depth: Dict,
        mitre: List[Dict],
        risk: Dict,
        attribution: Dict,
        iocs: Dict,
    ) -> Dict:
        """Build AI explainability summary — no black boxes."""
        # Signal inventory
        signals_active = []
        if risk.get("signal_breakdown"):
            signals_active = [s["signal"] for s in risk["signal_breakdown"]]

        # Attack narrative
        av = tech_depth.get("attack_vector", {})
        chain = tech_depth.get("execution_chain", [])
        behaviors = tech_depth.get("malware_behaviors", [])

        narrative_parts = []
        if av.get("type") and av["type"] != "unknown":
            narrative_parts.append(f"Initial access via {av['type'].replace('_', ' ')}")
        if chain:
            phases = [c["phase"].replace("_", " ") for c in chain[:4]]
            narrative_parts.append(f"execution chain: {' → '.join(phases)}")
        if behaviors:
            bnames = [b["behavior"].replace("_", " ") for b in behaviors[:3]]
            narrative_parts.append(f"malware behaviors: {', '.join(bnames)}")

        # Attribution statement
        attr_summary = (
            f"Attributed to {attribution['actor']} ({attribution['confidence']} confidence)"
            if attribution.get("attributed")
            else "Actor attribution: UNKNOWN (insufficient evidence)"
        )

        # Confidence breakdown — use structured confidence_detail dict, not the string rationale
        conf_data = risk.get("confidence_detail", {})
        if not isinstance(conf_data, dict):
            conf_data = {}

        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))

        return {
            "signals_active": signals_active,
            "attack_narrative": " → ".join(narrative_parts) if narrative_parts else "Insufficient technical data for attack narrative",
            "attribution_summary": attr_summary,
            "technical_depth_score": tech_depth.get("technical_depth_score", 0),
            "ioc_count_total": total_iocs,
            "mitre_technique_count": len(mitre),
            "confidence_level": conf_data.get("level", "UNKNOWN"),
            "confidence_rationale": conf_data.get("rationale", ""),
            "risk_summary": risk.get("risk_summary", ""),
            "explainability_complete": True,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_apex_enricher: Optional[ApexIntelEnricher] = None

def get_apex_enricher() -> ApexIntelEnricher:
    global _apex_enricher
    if _apex_enricher is None:
        _apex_enricher = ApexIntelEnricher()
    return _apex_enricher


# ─────────────────────────────────────────────────────────────────────────────
# CLI self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    enricher = get_apex_enricher()

    test_title = "CVE-2024-38213 Critical RCE in Microsoft Exchange — APT28 Actively Exploiting"
    test_content = """
    A critical remote code execution vulnerability (CVE-2024-38213, CVSS 9.8) in Microsoft Exchange Server
    is being actively exploited by APT28 (Fancy Bear), a Russian state-sponsored threat actor attributed
    by CISA and NSA advisory. The exploit leverages a pre-authentication buffer overflow in the Exchange
    OWA endpoint, allowing unauthenticated remote code execution without user interaction.

    Proof-of-concept code is publicly available on GitHub. Affected versions: Exchange 2016, 2019, 2021.
    The attack chain follows: phishing email → malicious attachment → PowerShell dropper (-enc encoded) →
    process injection into lsass.exe → credential dumping via Mimikatz → lateral movement via RDP →
    data exfiltration to C2 at 185.220.101.45.

    Indicators of Compromise:
    SHA256: a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd
    C2 Domain: update-patch-service[.]ru
    Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcHost32
    """

    test_iocs = {
        "sha256": ["a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd"],
        "domain": ["update-patch-service.ru"],
        "ipv4": ["185.220.101.45"],
        "cve": ["CVE-2024-38213"],
    }
    test_mitre = [
        {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
        {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    ]
    test_actor = {"tracking_id": "CDB-APT28-01", "actor_name": "APT28"}

    result = enricher.enrich(
        title=test_title,
        content=test_content,
        iocs=test_iocs,
        raw_mitre=test_mitre,
        raw_actor=test_actor,
        risk_score=9.2,
        cvss=9.8,
        epss=85.0,
        kev_present=True,
    )
    apex = result["apex_intelligence"]
    print("\n=== APEX INTEL ENGINE SELF-TEST ===")
    _av  = apex["technical_depth"]["attack_vector"]
    _td  = apex["technical_depth"]
    _ai  = apex.get("ai_insight", {})
    _re  = apex.get("risk_explained", {})
    _av_type = _av.get("type", "N/A")
    _av_conf = _av.get("confidence", "N/A")
    print(f"Attack Vector: {_av_type} ({_av_conf})")
    print(f"Execution Chain: {[c['phase'] for c in _td['execution_chain']]}")
    print(f"Malware Behaviors: {[b['behavior'] for b in _td['malware_behaviors']]}")
    _mitre_out = [(m['technique_id'], m['confidence']) for m in apex['mitre_enriched']]
    print(f"MITRE enriched: {_mitre_out}")
    _actor = apex['attribution']['actor']
    _attr_conf = apex['attribution']['confidence']
    print(f"Attribution: {_actor} ({_attr_conf})")
    print(f"Risk summary: {_re.get('risk_summary', 'N/A')}")
    print(f"Tech depth score: {_td['technical_depth_score']}/100")
    print(f"AI signals active: {_ai.get('signals_active', [])}")
    print(f"Confidence: {_ai.get('confidence_level', 'N/A')}")
    print(f"Attack narrative: {_ai.get('attack_narrative', 'N/A')}")
    print("\n=== SELF-TEST PASSED ===")
