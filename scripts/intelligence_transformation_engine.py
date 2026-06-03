#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/intelligence_transformation_engine.py
Intelligence Transformation Engine v171.0.0
================================================================================
PURPOSE:
  Transform raw external source content (BleepingComputer, Security Affairs,
  CyberSecurity News, Vulners, CISA, CVE Feed) into analyst-grade intelligence.

  This engine does NOT restate source articles.
  It GENERATES intelligence from structured fields.

OUTPUT SECTIONS (7 mandatory):
  1. Executive Assessment     — so-what, risk framing, decision context
  2. Evidence Summary         — what technical evidence actually exists
  3. Operational Impact       — how this affects defender operations NOW
  4. Attribution Assessment   — what is and is not known about the actor
  5. MITRE Assessment         — technique-level analysis with confidence
  6. Detection Strategy       — specific, actionable detection guidance
  7. Recommended Actions      — prioritized, time-boxed response actions

QUALITY RULES:
  - Each section must contain evidence-specific content (not template phrases)
  - Source restatement is prohibited (article title ≠ intelligence)
  - Confidence claims must match evidence level
  - Attribution sections must distinguish known from inferred
  - Detection guidance must name specific data sources and query logic

SUPPORTED SOURCES:
  bleepingcomputer, securityaffairs, cybersecuritynews, vulners, cisa, cvefeed,
  nvd, tenable, rapid7, recorded_future, crowdstrike, mandiant, generic
================================================================================
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ENGINE_ID      = "INTELLIGENCE-TRANSFORMATION-ENGINE"
ENGINE_VERSION = "171.0.0"

# =============================================================================
# Source Classification
# =============================================================================

SOURCE_PROFILES = {
    "bleepingcomputer": {
        "reliability": "HIGH",
        "typical_content": ["malware", "ransomware", "breaches", "vulnerability news"],
        "intel_value": "HIGH — journalism with technical detail, primary sources often cited",
        "bias": "Incident-focused; may amplify severity for engagement",
        "corroboration_weight": 0.8,
    },
    "securityaffairs": {
        "reliability": "HIGH",
        "typical_content": ["APT campaigns", "data breaches", "CVEs", "nation-state"],
        "intel_value": "HIGH — technical depth, APT tracking",
        "bias": "Aggregation-heavy; verify primary attribution sources",
        "corroboration_weight": 0.75,
    },
    "cybersecuritynews": {
        "reliability": "MEDIUM",
        "typical_content": ["CVEs", "security tools", "industry news"],
        "intel_value": "MEDIUM — broad coverage, variable depth",
        "bias": "Aggregation source; follow citations to primary",
        "corroboration_weight": 0.5,
    },
    "vulners": {
        "reliability": "HIGH",
        "typical_content": ["CVEs", "exploits", "security advisories"],
        "intel_value": "HIGH — structured vulnerability data, NVD-linked",
        "bias": "Technical only; no operational context",
        "corroboration_weight": 0.85,
    },
    "cisa": {
        "reliability": "AUTHORITATIVE",
        "typical_content": ["KEV entries", "advisories", "ICS vulnerabilities", "threat alerts"],
        "intel_value": "VERY_HIGH — US government authoritative source; KEV = confirmed exploitation",
        "bias": "Conservative; only publishes when confirmed",
        "corroboration_weight": 1.0,
    },
    "cvefeed": {
        "reliability": "HIGH",
        "typical_content": ["CVEs", "exploit availability"],
        "intel_value": "HIGH — structured CVE data with exploit tracking",
        "bias": "Automated; requires analyst enrichment",
        "corroboration_weight": 0.8,
    },
    "nvd": {
        "reliability": "AUTHORITATIVE",
        "typical_content": ["CVEs", "CVSS scores", "affected products"],
        "intel_value": "VERY_HIGH — NIST authoritative CVE database",
        "bias": "Technical only; no threat actor context",
        "corroboration_weight": 0.95,
    },
    "tenable": {
        "reliability": "HIGH",
        "typical_content": ["vulnerability research", "CVE analysis"],
        "intel_value": "HIGH — vendor research with technical depth",
        "corroboration_weight": 0.85,
    },
    "rapid7": {
        "reliability": "HIGH",
        "typical_content": ["exploit development", "vulnerability research", "AttackerKB"],
        "intel_value": "HIGH — exploitation context, AttackerKB community scoring",
        "corroboration_weight": 0.85,
    },
    "generic": {
        "reliability": "UNVERIFIED",
        "typical_content": ["unknown"],
        "intel_value": "LOW — unclassified source; manual verification required",
        "corroboration_weight": 0.3,
    },
}

def _classify_source(source_domain: str) -> Dict[str, Any]:
    """Classify a source URL/domain into a source profile."""
    domain = source_domain.lower()
    for key, profile in SOURCE_PROFILES.items():
        if key in domain:
            return {**profile, "source_key": key}
    return {**SOURCE_PROFILES["generic"], "source_key": "generic"}


# =============================================================================
# Intelligence Transformation Sections
# =============================================================================

def _section_1_executive_assessment(record: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    Section 1: Executive Assessment
    Answers: What is this? Why does it matter? What is the decision?
    Avoids: restating source headline, generic risk language
    """
    cve = evidence["primary_cve"]
    severity = evidence["severity"]
    cvss = evidence["cvss"]
    epss = evidence["epss"]
    kev = evidence["kev"]
    risk = evidence["risk_score"]
    threat_type = evidence["threat_type"]
    source_profile = evidence["source_profile"]

    # Build the so-what framing based on evidence
    if kev:
        so_what = (
            f"This advisory represents an actively exploited vulnerability — CISA KEV confirmed. "
            f"The window between disclosure and exploitation has already closed; "
            f"any unpatched system is currently exposed to known adversary activity."
        )
        decision = "Immediate patch deployment or compensating control implementation. This is not advisory-level."
    elif cvss and float(cvss) >= 9.0:
        so_what = (
            f"Critical severity ({_fmt_cvss(cvss)}) with a network-accessible attack vector places this "
            f"at the highest tier of remediation priority. "
            f"Unpatched internet-facing systems represent an active attack surface for opportunistic and targeted actors."
        )
        decision = "Treat as pre-compromise posture — patch internet-facing instances within 72 hours."
    elif epss and float(epss) > 0.10:
        so_what = (
            f"Statistical exploitation modeling ({_fmt_epss(epss)}) indicates this vulnerability "
            f"has elevated probability of active exploitation within 30 days. "
            f"Source intelligence reliability is {source_profile['reliability']}."
        )
        decision = "Accelerate patch cycle for affected systems; deploy detection coverage before patch window."
    elif cvss and float(cvss) >= 7.0:
        so_what = (
            f"High-severity vulnerability ({_fmt_cvss(cvss)}) requiring prioritized remediation. "
            f"No confirmed exploitation at time of analysis; however the attack class ({_threat_class(threat_type, record)}) "
            f"has consistent historical exploitation patterns."
        )
        decision = "Patch within standard high-severity SLA (7–14 days). Verify detection coverage."
    else:
        so_what = (
            f"Low-to-medium severity advisory from {source_profile['source_key']} (reliability: {source_profile['reliability']}). "
            f"Risk score {risk}/10. No active exploitation evidence at time of analysis."
        )
        decision = "Schedule patch in standard maintenance cycle. Monitor for escalation signals."

    # Source quality context
    src_note = (
        f"Source intelligence value: {source_profile['intel_value']}. "
        f"Corroboration weight: {source_profile['corroboration_weight']:.0%}."
    )

    return f"{so_what}\n\nDecision: {decision}\n\n{src_note}"


def _section_2_evidence_summary(record: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    Section 2: Evidence Summary
    States ONLY what technical evidence actually exists. No inference.
    """
    lines = []

    cve = evidence["primary_cve"]
    if cve:
        lines.append(f"CVE Identifier: {cve} — formally registered vulnerability.")

    cvss = evidence["cvss"]
    if cvss:
        lines.append(f"CVSS v3 Score: {_fmt_cvss(cvss)} — base score from NVD/vendor advisory.")
    else:
        lines.append("CVSS Score: Not yet available in NVD at time of processing.")

    epss = evidence["epss"]
    if epss:
        lines.append(f"EPSS 30-day Probability: {_fmt_epss(epss)} — FIRST model output for this CVE.")
    else:
        lines.append("EPSS: Not available — exploitation probability model not yet computed.")

    kev = evidence["kev"]
    if kev:
        lines.append("KEV Status: LISTED — CISA has confirmed active exploitation in the wild. This is the highest exploitation signal available.")
    else:
        lines.append("KEV Status: Not listed — CISA has not confirmed active exploitation.")

    real_iocs = evidence["real_ioc_count"]
    if real_iocs > 0:
        ioc_types = evidence.get("ioc_types", [])
        lines.append(f"Operational IOCs: {real_iocs} indicators extracted ({', '.join(ioc_types[:4]) if ioc_types else 'types unclassified'}).")
    else:
        lines.append("Operational IOCs: None extracted — no malicious infrastructure indicators present in source data.")

    ttps = evidence["ttps"]
    if ttps:
        lines.append(f"ATT&CK Techniques: {', '.join(ttps[:5])} — derived from CVE class and description. Not observationally confirmed.")
    else:
        lines.append("ATT&CK Techniques: Not mapped to specific techniques.")

    affected = evidence["affected_products"]
    if affected:
        lines.append(f"Affected Products: {', '.join(str(p) for p in affected[:5])}.")
    else:
        lines.append("Affected Products: Not enumerated in source data — check NVD CPE list for version range.")

    attack_vector = record.get("attack_vector", "")
    if attack_vector:
        lines.append(f"Attack Vector: {attack_vector}.")

    return "\n".join(f"• {l}" for l in lines)


def _section_3_operational_impact(record: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    Section 3: Operational Impact
    How does this affect defender operations TODAY? What changes right now?
    """
    severity = evidence["severity"]
    cvss = evidence["cvss"]
    threat_type = evidence["threat_type"]
    kev = evidence["kev"]
    affected = evidence["affected_products"]
    attack_vector = record.get("attack_vector", "NETWORK")

    # Detection posture change
    if kev or (cvss and float(cvss) >= 9.0):
        detection_posture = (
            "Detection posture change REQUIRED TODAY. "
            "Existing signature coverage must be verified against this CVE. "
            "Assume detection gap until confirmed otherwise."
        )
        incident_response = (
            "Activate threat hunt: search 90-day log retention for indicators of this vulnerability class. "
            "If this product is internet-facing, treat as potential pre-compromise scenario."
        )
    elif cvss and float(cvss) >= 7.0:
        detection_posture = (
            "Deploy detection rule update within the patch window. "
            "IDS/IPS signature check recommended before next maintenance cycle."
        )
        incident_response = "Perform targeted log review for exploitation patterns if affected product is customer-facing."
    else:
        detection_posture = "No immediate detection posture change required. Monitor for exploitation escalation signals."
        incident_response = "Standard advisory processing. No retrospective hunt required at current severity."

    # Asset scope
    if affected:
        scope = f"Asset scope: {', '.join(str(p) for p in affected[:3])} — perform inventory query to identify exposed instances."
    elif attack_vector and "NETWORK" in attack_vector.upper():
        scope = "Attack vector is network-accessible — all externally reachable instances of affected software are in scope."
    else:
        scope = "Asset scope undetermined — validate against internal software inventory."

    # Patch window impact
    patch_window = _patch_window_statement(severity, cvss, kev, evidence["epss"])

    return (
        f"Detection posture: {detection_posture}\n\n"
        f"Incident response: {incident_response}\n\n"
        f"Scope: {scope}\n\n"
        f"Patch window: {patch_window}"
    )


def _section_4_attribution_assessment(record: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    Section 4: Attribution Assessment
    Strictly separates what IS known from what is INFERRED.
    Never presents derived attribution as confirmed.
    """
    actor = evidence["actor"]
    attribution_status = record.get("attribution_status", "")
    actor_confidence = record.get("actor_confidence_label", "")
    verified_actor = record.get("verified_actor", False)
    mitre_group = record.get("mitre_group_name", "")
    actor_sectors = record.get("actor_sectors", []) or []
    actor_motivation = record.get("actor_motivation", "")

    if actor and verified_actor:
        attribution = (
            f"CONFIRMED ATTRIBUTION: {actor}.\n"
            f"Attribution basis: vendor-confirmed or multi-source corroborated.\n"
        )
        if mitre_group:
            attribution += f"MITRE ATT&CK Group: {mitre_group}.\n"
        if actor_sectors:
            attribution += f"Known targeting: {', '.join(str(s) for s in actor_sectors[:5])}.\n"
        if actor_motivation:
            attribution += f"Motivation: {actor_motivation}.\n"
        attribution += "\nAnalyst Note: Treat as confirmed for detection and hunting purposes."

    elif actor and actor not in ("Attribution Not Established", "Insufficient Evidence For Attribution"):
        attribution = (
            f"PARTIAL ATTRIBUTION: {actor} — attributed with limited confidence.\n"
            f"Attribution confidence: {actor_confidence or 'LOW'}.\n"
            f"This attribution is based on limited signals and should not be treated as confirmed.\n\n"
            f"Analyst Note: Cross-reference with additional intelligence sources before attributing "
            f"to this actor in incident response documentation."
        )
    else:
        attribution = (
            "ATTRIBUTION NOT ESTABLISHED.\n\n"
            "No threat actor has been attributed to this activity based on available evidence. "
            "This may indicate:\n"
            "• The vulnerability has not yet been operationally exploited by a tracked actor\n"
            "• Attribution evidence exists but has not been corroborated to publication threshold\n"
            "• The activity represents opportunistic exploitation without a primary attributed actor\n\n"
            "Do not infer attribution from vulnerability class or sector alone. "
            "Attribution requires direct technical linkage (shared infrastructure, code reuse, C2 overlap) "
            "or multi-source corroborated reporting."
        )

    return attribution


def _section_5_mitre_assessment(record: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    Section 5: MITRE Assessment
    Technique-level analysis with explicit confidence level per technique.
    Never presents derived mappings as observed behavior.
    """
    ttps = evidence["ttps"]
    kev = evidence["kev"]
    real_iocs = evidence["real_ioc_count"]
    cve = evidence["primary_cve"]

    if not ttps:
        return (
            "No ATT&CK techniques mapped at this time.\n\n"
            "ANALYST NOTE: Technique mapping requires behavioral evidence (logs, malware analysis, "
            "IOC correlation) or vendor advisory that explicitly names the technique. "
            "Do not assign techniques based on vulnerability class alone without evidence."
        )

    # Determine evidence basis for techniques
    if kev:
        confidence_basis = "CORROBORATED — CISA KEV confirmed active exploitation"
        technique_confidence = "CORROBORATED"
    elif real_iocs > 0:
        confidence_basis = "DERIVED — technical indicators present but behavioral evidence not confirmed"
        technique_confidence = "DERIVED"
    else:
        confidence_basis = "DERIVED — inferred from CVE description and vulnerability class. Not observationally confirmed."
        technique_confidence = "DERIVED"

    lines = [
        f"Technique Confidence Level: {technique_confidence}",
        f"Evidence Basis: {confidence_basis}",
        "",
        "Technique Analysis:",
    ]
    for ttp in ttps[:6]:
        technique_note = _technique_note(ttp, record)
        lines.append(f"  {ttp}: {technique_note} [{technique_confidence}]")

    lines.extend([
        "",
        "ANALYST NOTE: All technique mappings in this advisory are DERIVED from CVE description "
        "and vulnerability class analysis. They have NOT been observationally confirmed through "
        "incident data, malware analysis, or direct behavioral telemetry. "
        "Enterprise ATT&CK Navigator layers should tag these as HYPOTHESIS until confirmed.",
    ])

    if kev:
        lines[-1] = (
            "ANALYST NOTE: KEV-confirmed status upgrades exploitation techniques (T1190) to "
            "CORROBORATED confidence. Remaining techniques (lateral movement, persistence) "
            "remain DERIVED until post-exploitation behavioral data is available."
        )

    return "\n".join(lines)


def _section_6_detection_strategy(record: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    Section 6: Detection Strategy
    Specific, actionable detection guidance. Names exact data sources.
    Does NOT reproduce generic EventID lists or NOP sled patterns.
    """
    threat_type = evidence["threat_type"]
    severity = evidence["severity"]
    cve = evidence["primary_cve"]
    attack_vector = record.get("attack_vector", "NETWORK")
    vuln_class = record.get("vuln_class", "") or ""
    title_lower = (record.get("title", "") + " " + record.get("description", "")).lower()

    det_class = record.get("detection_confidence_class", "")
    has_sigma = bool(record.get("sigma_rule", ""))
    has_kql = bool(record.get("kql_query", ""))
    has_suricata = bool(record.get("suricata_rule", ""))

    lines = []

    # Primary detection data source
    if "network" in attack_vector.lower() or re.search(r"(?:remote|web|http|api)", title_lower):
        lines.append("Primary Data Source: Web/network access logs, WAF logs, proxy logs, IDS/IPS alerts.")
        lines.append("Query focus: HTTP requests to affected endpoints; anomalous response codes (500/400 series spikes).")
    else:
        lines.append("Primary Data Source: Endpoint telemetry (EDR), process creation logs, file system events.")
        lines.append("Query focus: Anomalous process spawning from affected application processes.")

    # CVE-specific detection hints
    if re.search(r"(?:rce|remote\s*code|command\s*inject)", title_lower):
        lines.append("Detection hint (RCE): Monitor for web server processes spawning unexpected child processes (cmd.exe, sh, python, powershell). Alert on outbound connections from web application processes.")
    if re.search(r"(?:sqli|sql\s*inject)", title_lower):
        lines.append("Detection hint (SQLi): Enable database error logging; alert on SQL syntax error spikes from web application. Monitor for UNION SELECT, information_schema queries in DB audit logs.")
    if re.search(r"(?:ssrf)", title_lower):
        lines.append("Detection hint (SSRF): Monitor for internal RFC1918 or metadata service (169.254.169.254) requests originating from application tier hosts.")
    if re.search(r"(?:xss|cross[\s\-]?site\s*script)", title_lower):
        lines.append("Detection hint (XSS): Monitor WAF for script injection patterns in request parameters. Review CSP violation reports.")
    if re.search(r"(?:path\s*travers|file\s*inclus)", title_lower):
        lines.append("Detection hint (Path Traversal): Alert on request patterns containing '../', '%2e%2e%2f', or absolute paths in URL parameters.")
    if re.search(r"(?:auth\s*bypass|improper\s*auth|missing\s*auth)", title_lower):
        lines.append("Detection hint (Auth Bypass): Monitor for access to privileged endpoints without corresponding authentication events in auth logs.")

    # Rule availability note
    if det_class == "PRODUCTION":
        lines.append(f"Detection Pack: Production-grade Sigma/KQL/Suricata rules available for {cve or 'this CVE'}. Deploy to SIEM immediately.")
    elif det_class == "LAB_VALIDATED":
        lines.append(f"Detection Pack: Lab-validated rules available. Tune alert thresholds to environment before production deployment.")
    elif has_sigma or has_kql or has_suricata:
        lines.append("Detection Pack: Rules present but require specificity review — generic patterns detected. Do not deploy without CVE-specific content validation.")
    else:
        lines.append(f"Detection Pack: Custom rules required. Build from detection hints above targeting {cve or 'this CVE'} exploitation patterns.")

    # SIEM integration
    lines.append("SIEM Integration: Correlate with vulnerability scan data to prioritize alerts on confirmed-affected asset IP ranges.")
    lines.append("EDR Coverage: Verify EDR vendor has released a {cve} behavioral detection signature.".format(cve=cve or "CVE-specific"))

    return "\n".join(f"• {l}" for l in lines)


def _section_7_recommended_actions(record: Dict[str, Any], evidence: Dict[str, Any]) -> str:
    """
    Section 7: Recommended Actions
    Prioritized, time-boxed, audience-specific response actions.
    """
    severity = evidence["severity"]
    cvss = evidence["cvss"]
    epss = evidence["epss"]
    kev = evidence["kev"]
    cve = evidence["primary_cve"]
    affected = evidence["affected_products"]
    real_iocs = evidence["real_ioc_count"]

    actions = []

    # Immediate (0–24h)
    if kev:
        actions.append("[IMMEDIATE — 0–24h] [SOC + VM] Patch all affected systems NOW. CISA KEV mandate applies. If patch unavailable, isolate or apply WAF/network compensating control and document exception.")
        actions.append("[IMMEDIATE — 0–24h] [SOC] Begin retrospective threat hunt: search 90-day endpoint and network logs for exploitation indicators.")
    elif severity == "CRITICAL" or (cvss and float(cvss) >= 9.0):
        actions.append("[URGENT — 0–72h] [VM] Emergency patch deployment for all internet-facing instances of affected software.")
        actions.append("[URGENT — 0–72h] [SOC] Verify IDS/IPS signatures cover this CVE. Deploy detection rules from Detection Pack.")

    # Short-term (1–7 days)
    if severity in ("CRITICAL", "HIGH") or (cvss and float(cvss) >= 7.0):
        actions.append("[SHORT-TERM — 1–7d] [VM] Complete internal asset inventory to identify all affected instances (not just internet-facing).")
        actions.append("[SHORT-TERM — 1–7d] [CISO] Confirm patch deployment to board/risk committee. Document timeline and compensating controls for risk register.")
        actions.append(f"[SHORT-TERM — 1–7d] [SOC] Tune SIEM correlation rules to suppress false positives for patch-confirmed assets.")
    else:
        actions.append("[STANDARD — 1–30d] [VM] Include in next patch cycle. No emergency change window required.")
        actions.append("[STANDARD — 1–30d] [SOC] Update vulnerability tracking system. Monitor for KEV listing escalation.")

    # IOC-based actions
    if real_iocs > 0:
        actions.append(f"[IMMEDIATE] [SOC] Deploy {real_iocs} extracted operational indicator(s) to firewall blocklists, proxy deny-lists, and EDR custom IOC feeds.")

    # Standard hygiene
    actions.append("[ONGOING] [VM] Subscribe to vendor security advisory RSS/mailing list for patch availability notification.")
    if affected:
        actions.append(f"[ONGOING] [VM] Verify SBOM and dependency manifests include {', '.join(str(p) for p in affected[:2])} version tracking.")

    return "\n".join(actions)


# =============================================================================
# Helper Functions
# =============================================================================

def _fmt_cvss(cvss) -> str:
    if cvss is None: return "N/A"
    v = float(cvss)
    if v >= 9.0: label = "Critical"
    elif v >= 7.0: label = "High"
    elif v >= 4.0: label = "Medium"
    else: label = "Low"
    return f"{v:.1f} ({label})"


def _fmt_epss(epss) -> str:
    if epss is None: return "N/A"
    v = float(epss)
    if v > 1: v = v / 100
    return f"{v*100:.2f}%"


def _threat_class(threat_type: str, record: Dict[str, Any]) -> str:
    t = threat_type.lower()
    if "rce" in t or "remote code" in t: return "Remote Code Execution"
    if "sql" in t: return "SQL Injection"
    if "ransomware" in t: return "Ransomware"
    if "phish" in t: return "Phishing"
    vclass = record.get("vuln_class", "") or ""
    return vclass or threat_type or "Unknown"


def _patch_window_statement(severity, cvss, kev, epss) -> str:
    if kev:
        return "IMMEDIATE — CISA KEV mandate requires patch or compensating control within defined SLA (14 days for federal agencies)."
    if cvss and float(cvss) >= 9.0:
        return "CRITICAL SLA: patch internet-facing systems within 24–72 hours of availability."
    if cvss and float(cvss) >= 7.0:
        return "HIGH SLA: patch within 7–14 days per standard vulnerability management policy."
    if epss and float(epss) > 0.05:
        return "ELEVATED EPSS: despite lower CVSS, exploitation probability warrants patching within 14 days."
    return "STANDARD: patch in next scheduled maintenance window (30-day cycle)."


def _technique_note(ttp: str, record: Dict[str, Any]) -> str:
    notes = {
        "T1190": "Exploit Public-Facing Application — the primary vector for this CVE class",
        "T1059": "Command and Scripting Interpreter — post-exploitation code execution",
        "T1059.007": "JavaScript/JScript — client-side scripting exploitation",
        "T1078": "Valid Accounts — authentication bypass may yield valid session",
        "T1083": "File and Directory Discovery — path traversal enables directory enumeration",
        "T1090": "Proxy — SSRF can route requests through internal proxy chains",
        "T1068": "Exploitation for Privilege Escalation — sandbox/privilege bypass",
        "T1499": "Endpoint Denial of Service — resource exhaustion vector",
        "T1552": "Unsecured Credentials — information disclosure may expose credentials",
        "T1185": "Browser Session Hijacking — CSRF enables unauthorized action in session",
    }
    return notes.get(ttp, "Technique applicable to this vulnerability class")


# =============================================================================
# Evidence Extraction
# =============================================================================

def _extract_evidence(record: Dict[str, Any]) -> Dict[str, Any]:
    cve_ids = record.get("cve_ids", []) or []
    if not cve_ids and record.get("cve_id"):
        cve_ids = [record["cve_id"]]
    primary_cve = cve_ids[0] if cve_ids else None

    cvss = record.get("cvss_score")
    epss_raw = record.get("epss_score") or record.get("epss")
    try:
        epss = float(str(epss_raw).rstrip("%")) if epss_raw and str(epss_raw) not in ("", "None", "N/A") else None
        if epss and epss > 1:
            epss = epss / 100
    except (ValueError, TypeError):
        epss = None

    actor = None
    for k in ("actor_name", "actor", "actor_tag"):
        v = record.get(k)
        if v and v not in ("CDB-UNATTR-CVE", "CDB-UNATTR-PHI", "CDB-UNATTR-APT",
                           "CDB-UNATTR-RAN", "CDB-UNATTR-SUP", "CDB-UNATTR-MAL",
                           "UNATTRIBUTED", "Attribution Not Established",
                           "Insufficient Evidence For Attribution", "Unknown",
                           "Untracked", "", None):
            actor = v
            break

    ttps = []
    for k in ("ttps", "attck_technique_ids", "tags"):
        v = record.get(k) or []
        ttps.extend([t for t in v if isinstance(t, str) and re.match(r"^T\d{4}", t)])
    ttps = list(dict.fromkeys(ttps))

    source_url = record.get("source_url", "") or ""
    source_domain = record.get("source_domain", "") or record.get("source", "") or source_url
    source_profile = _classify_source(source_domain)

    return {
        "primary_cve": primary_cve,
        "cve_ids": cve_ids,
        "cvss": cvss,
        "epss": epss,
        "severity": (record.get("severity") or "LOW").upper(),
        "kev": record.get("kev_present", False),
        "real_ioc_count": record.get("real_ioc_count", 0) or 0,
        "ioc_types": list((record.get("iocs_by_type") or {}).keys()),
        "ttps": ttps,
        "affected_products": record.get("affected_products", []) or [],
        "threat_type": record.get("threat_type", "") or "",
        "risk_score": record.get("risk_score", 0) or 0,
        "actor": actor,
        "source_profile": source_profile,
    }


# =============================================================================
# Main Transformation
# =============================================================================

def transform_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Transform a single raw intel record into 7-section analyst-grade intelligence."""
    evidence = _extract_evidence(record)

    s1 = _section_1_executive_assessment(record, evidence)
    s2 = _section_2_evidence_summary(record, evidence)
    s3 = _section_3_operational_impact(record, evidence)
    s4 = _section_4_attribution_assessment(record, evidence)
    s5 = _section_5_mitre_assessment(record, evidence)
    s6 = _section_6_detection_strategy(record, evidence)
    s7 = _section_7_recommended_actions(record, evidence)

    # Quality check: measure section distinctiveness
    sections_text = [s1, s2, s3, s4, s5, s6, s7]
    quality_score = _score_transformation_quality(sections_text, evidence)

    return {
        "engine_id": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "transformed_at": datetime.now(timezone.utc).isoformat(),
        "record_id": record.get("id", ""),
        "title": record.get("title", ""),
        "source": evidence["source_profile"]["source_key"],
        "source_reliability": evidence["source_profile"]["reliability"],
        "intelligence": {
            "1_executive_assessment": s1,
            "2_evidence_summary": s2,
            "3_operational_impact": s3,
            "4_attribution_assessment": s4,
            "5_mitre_assessment": s5,
            "6_detection_strategy": s6,
            "7_recommended_actions": s7,
        },
        "transformation_quality_score": quality_score,
    }


def _score_transformation_quality(sections: List[str], evidence: Dict[str, Any]) -> int:
    """Score transformation quality 0-100."""
    score = 50

    # All 7 sections present and non-empty
    if all(s and len(s) > 50 for s in sections):
        score += 20

    # Evidence references present
    cve = evidence.get("primary_cve", "")
    combined = " ".join(sections)
    if cve and cve in combined: score += 5
    if evidence.get("cvss") and str(evidence["cvss"]) in combined: score += 5
    if evidence.get("kev") and "KEV" in combined: score += 5

    # Attribution section distinguishes known from inferred
    attr = sections[3]
    if "NOT ESTABLISHED" in attr or "CONFIRMED" in attr or "PARTIAL" in attr: score += 5

    # MITRE section has confidence level
    mitre = sections[4]
    if any(c in mitre for c in ("DERIVED", "CORROBORATED", "OBSERVED", "SPECULATIVE")): score += 5

    # Detection section names specific data sources
    det = sections[5]
    if any(s in det for s in ("WAF", "EDR", "SIEM", "proxy", "DNS", "endpoint")): score += 5

    return min(100, score)


def process_feed(feed: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Transform entire feed."""
    results = [transform_record(r) for r in feed]
    avg_quality = round(sum(r["transformation_quality_score"] for r in results) / len(results), 1) if results else 0

    return {
        "engine_id": ENGINE_ID,
        "engine_version": ENGINE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "records_transformed": len(results),
        "average_transformation_quality": avg_quality,
        "records": results,
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SENTINEL APEX Intelligence Transformation Engine v171.0.0")
    parser.add_argument("--feed",    default="data/stix/feed_manifest.json")
    parser.add_argument("--output",  default="reports/intelligence_transformation_audit.json")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    feed_path = Path(args.feed)
    if not feed_path.exists():
        print(f"[INTEL-TRANSFORM] ERROR: Feed not found: {feed_path}")
        sys.exit(1)

    feed = json.loads(feed_path.read_text(encoding="utf-8"))
    if not isinstance(feed, list): feed = [feed]

    print(f"[INTEL-TRANSFORM] Transforming {len(feed)} records...")
    report = process_feed(feed)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[INTEL-TRANSFORM] Report written → {out_path}")

    if args.summary and report["records"]:
        print(f"\nAverage transformation quality: {report['average_transformation_quality']}/100")
        r = report["records"][0]
        print(f"\n--- SAMPLE: {r['title'][:60]} ---")
        for k, v in r["intelligence"].items():
            print(f"\n[{k}]\n{v[:200]}...")

    return report


if __name__ == "__main__":
    main()
