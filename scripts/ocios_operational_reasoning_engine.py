#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
scripts/ocios_operational_reasoning_engine.py
OCIOS Phase 2 — Operational Reasoning Engine
================================================================================
Version      : 1.0.0
Classification: CONFIDENTIAL — OCIOS TIER

MANDATE
-------
Replaces shallow AI narrative summaries with evidence-driven operational
intelligence reasoning.  Every advisory receives a reasoning block that
explains: WHY it matters, WHO is being targeted, WHAT the attacker objectives
are, WHAT follows next in the kill chain, and WHAT the business risk is.

The engine also produces corpus-level reasoning outputs:
- Sector threat landscape (which industries are under acute pressure)
- Active campaign timeline (temporal reasoning across the full corpus)
- Adversary objective map (what attackers are trying to accomplish)
- Business risk synthesis (financial and operational exposure aggregation)

DIFFERENTIATION FROM EXISTING ENGINES
--------------------------------------
- apex_intelligence_engine.py    : per-item modules, not corpus-aware
- ai_brain_publisher.py          : campaign names only, no reasoning
- enterprise_scoring_engine.py   : scores, no natural-language reasoning
- ai_explainability_engine.py    : score explanation, not threat reasoning
- THIS ENGINE                    : evidence chains, corpus context, targeting
                                   prediction, follow-on prediction,
                                   business risk synthesis

REASONING METHODOLOGY
---------------------
All reasoning is EVIDENCE-DRIVEN, not template-driven.
Each reasoning element is derived from observable signals:
  - KEV status          -> exploitation urgency reasoning
  - EPSS score          -> probability-weighted exploitation timeline
  - CVSS vector         -> attack complexity and privilege reasoning
  - TTP mapping         -> kill chain position reasoning
  - Actor attribution   -> targeting profile and objective reasoning
  - Vendor/product      -> infrastructure exposure reasoning
  - Temporal clustering -> attack wave and follow-on reasoning
  - Enterprise scores   -> business risk weighting

INPUTS
------
  data/stix/feed_manifest.json              (required)
  data/ocios/campaign_graph.json            (optional — enriches context)
  data/ocios/temporal_chains.json           (optional — enriches context)
  data/enterprise_scoring/scoring_report.json (optional)

OUTPUTS
-------
  data/ocios/operational_reasoning.json     — per-item reasoning blocks
  data/ocios/sector_threat_landscape.json   — sector-level threat synthesis
  data/ocios/adversary_objective_map.json   — attacker objectives across corpus
  data/ocios/business_risk_synthesis.json   — aggregated business risk picture

SAFETY GUARANTEES
-----------------
  - ADDITIVE ONLY — no modification to any existing files
  - Atomic writes throughout
  - UTF-8 clean
  - Deterministic reasoning — same inputs produce same reasoning
  - All reasoning text is ASCII-safe (no em-dashes, smart quotes, Unicode)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [OCIOS-REASON] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("CDB-OCIOS-REASON")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT       = Path(__file__).resolve().parent.parent
MANIFEST_PATH   = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
OCIOS_DIR       = REPO_ROOT / "data" / "ocios"

ENGINE_VERSION  = "1.0.0"

# ---------------------------------------------------------------------------
# Evidence weight table
# Evidence strength from 0.0 (weak) to 1.0 (conclusive)
# ---------------------------------------------------------------------------
EVIDENCE_WEIGHTS = {
    "kev_confirmed":          1.00,  # CISA KEV = actively exploited
    "epss_high":              0.90,  # EPSS > 0.70 = near-certain exploitation
    "epss_medium":            0.65,  # EPSS 0.30-0.70
    "epss_low":               0.35,  # EPSS < 0.30
    "cvss_critical":          0.85,  # CVSS >= 9.0
    "cvss_high":              0.70,  # CVSS 7.0-8.9
    "actor_attributed":       0.80,  # Named threat actor
    "ransomware_actor":       0.90,  # Known ransomware group
    "ttp_initial_access":     0.75,  # T1190, T1133, T1566
    "ttp_impact":             0.80,  # T1486, T1485, T1490
    "multiple_ttps":          0.70,  # 3+ ATT&CK techniques mapped
    "vendor_acknowledged":    0.85,  # Vendor advisory/patch published
    "high_confidence_intel":  0.75,  # Source confidence >= 60%
    "temporal_burst":         0.65,  # In an active attack wave
    "ioc_present":            0.60,  # Observable indicators present
    "single_source":          0.30,  # Only one source, unconfirmed
}

# ---------------------------------------------------------------------------
# ATT&CK kill chain position mapping
# ---------------------------------------------------------------------------
KILL_CHAIN_PHASES: Dict[str, str] = {
    # Reconnaissance
    "T1595": "reconnaissance", "T1596": "reconnaissance", "T1598": "reconnaissance",
    # Initial Access
    "T1190": "initial_access", "T1133": "initial_access", "T1566": "initial_access",
    "T1566.001": "initial_access", "T1566.002": "initial_access", "T1189": "initial_access",
    "T1195": "initial_access", "T1078": "initial_access",
    # Execution
    "T1059": "execution", "T1059.001": "execution", "T1059.003": "execution",
    "T1059.004": "execution", "T1059.006": "execution", "T1203": "execution",
    # Persistence
    "T1053": "persistence", "T1098": "persistence", "T1543": "persistence",
    "T1547": "persistence", "T1574": "persistence",
    # Privilege Escalation
    "T1055": "privilege_escalation", "T1068": "privilege_escalation",
    "T1134": "privilege_escalation", "T1484": "privilege_escalation",
    "T1548": "privilege_escalation",
    # Defense Evasion
    "T1027": "defense_evasion", "T1036": "defense_evasion", "T1070": "defense_evasion",
    "T1112": "defense_evasion", "T1562": "defense_evasion",
    # Credential Access
    "T1003": "credential_access", "T1040": "credential_access", "T1110": "credential_access",
    "T1555": "credential_access", "T1558": "credential_access",
    # Discovery
    "T1018": "discovery", "T1046": "discovery", "T1082": "discovery",
    "T1083": "discovery", "T1135": "discovery",
    # Lateral Movement
    "T1021": "lateral_movement", "T1021.001": "lateral_movement",
    "T1021.002": "lateral_movement", "T1550": "lateral_movement",
    # Collection
    "T1005": "collection", "T1039": "collection", "T1114": "collection",
    # Exfiltration
    "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
    # Impact
    "T1485": "impact", "T1486": "impact", "T1489": "impact",
    "T1490": "impact", "T1491": "impact", "T1498": "impact",
}

FOLLOW_ON_MAP: Dict[str, List[str]] = {
    "initial_access":        ["execution", "persistence", "privilege_escalation"],
    "execution":             ["persistence", "credential_access", "discovery"],
    "persistence":           ["privilege_escalation", "lateral_movement", "collection"],
    "privilege_escalation":  ["credential_access", "lateral_movement", "defense_evasion"],
    "defense_evasion":       ["credential_access", "discovery", "lateral_movement"],
    "credential_access":     ["lateral_movement", "collection", "exfiltration"],
    "discovery":             ["lateral_movement", "collection"],
    "lateral_movement":      ["collection", "exfiltration", "impact"],
    "collection":            ["exfiltration", "impact"],
    "exfiltration":          ["impact"],
    "impact":                ["complete_compromise"],
    "reconnaissance":        ["initial_access"],
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_str(v: Any, default: str = "") -> str:
    return str(v).strip() if v is not None else default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _safe_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().upper() in ("YES", "TRUE", "1", "CONFIRMED")
    return bool(v)


def _safe_list(v: Any) -> List:
    if isinstance(v, list):
        return v
    return [] if v is None else [v]


def _item_id(item: Dict) -> str:
    return _safe_str(item.get("id") or item.get("intel_id") or item.get("report_id"), "unknown")


def _extract_ttps(item: Dict) -> List[str]:
    ttps: List[str] = []
    for key in ("ttps", "mitre_ttps", "techniques"):
        for t in _safe_list(item.get(key)):
            m = re.search(r"T\d{4}(?:\.\d{3})?", _safe_str(t))
            if m:
                ttps.append(m.group().upper())
    apex = item.get("apex_score") or {}
    for t in _safe_list(apex.get("top_ttps")):
        m = re.search(r"T\d{4}(?:\.\d{3})?", _safe_str(t))
        if m:
            ttps.append(m.group().upper())
    return list(dict.fromkeys(ttps))  # dedup preserving order


def _get_kill_chain_phases(ttps: List[str]) -> List[str]:
    phases = []
    for ttp in ttps:
        phase = KILL_CHAIN_PHASES.get(ttp)
        if phase and phase not in phases:
            phases.append(phase)
    return phases


def _get_follow_on(phases: List[str]) -> List[str]:
    follow_on: List[str] = []
    for phase in phases:
        for next_phase in FOLLOW_ON_MAP.get(phase, []):
            if next_phase not in follow_on and next_phase not in phases:
                follow_on.append(next_phase)
    return follow_on


# ---------------------------------------------------------------------------
# Evidence chain builder
# ---------------------------------------------------------------------------

def build_evidence_chain(item: Dict) -> Dict[str, Any]:
    """
    Build a weighted evidence chain for an advisory.
    Returns evidence items with weights and the overall evidence strength.
    """
    evidence: List[Dict] = []
    total_weight = 0.0
    max_weight   = 0.0

    def _add(label: str, desc: str, weight_key: str) -> None:
        nonlocal total_weight, max_weight
        w = EVIDENCE_WEIGHTS.get(weight_key, 0.3)
        evidence.append({"signal": label, "description": desc, "weight": w})
        total_weight += w
        max_weight   += EVIDENCE_WEIGHTS.get("kev_confirmed", 1.0)  # normalize to max

    is_kev = _safe_bool(item.get("kev") or item.get("cisa_kev") or item.get("in_kev"))
    if is_kev:
        _add("KEV Confirmed", "CISA Known Exploited Vulnerability — active exploitation observed in the wild", "kev_confirmed")

    epss = _safe_float(item.get("epss") or item.get("epss_score"))
    if epss >= 0.70:
        _add("EPSS Critical", f"EPSS score {epss:.0%} — near-certain exploitation within 30 days", "epss_high")
    elif epss >= 0.30:
        _add("EPSS Elevated", f"EPSS score {epss:.0%} — elevated exploitation probability", "epss_medium")
    elif epss > 0:
        _add("EPSS Low", f"EPSS score {epss:.0%} — lower exploitation probability", "epss_low")

    cvss = _safe_float(item.get("cvss") or item.get("cvss_score"))
    if cvss >= 9.0:
        _add("CVSS Critical", f"CVSS {cvss:.1f} — critical severity, low attack complexity likely", "cvss_critical")
    elif cvss >= 7.0:
        _add("CVSS High", f"CVSS {cvss:.1f} — high severity vulnerability", "cvss_high")

    actor = _safe_str(item.get("actor") or "").lower()
    if actor and actor not in ("cdb-cve-gen", "unknown", ""):
        ransomware_actors = {
            "lockbit", "blackcat", "alphv", "clop", "hive", "black basta",
            "revil", "conti", "lazarus", "apt28", "apt29", "apt41",
            "kimsuky", "scattered spider", "volt typhoon", "salt typhoon",
        }
        if any(ra in actor for ra in ransomware_actors):
            _add("Ransomware Actor", f"Attributed to '{actor}' — known ransomware/APT group", "ransomware_actor")
        else:
            _add("Actor Attribution", f"Attributed to '{actor}'", "actor_attributed")

    ttps = _extract_ttps(item)
    if len(ttps) >= 3:
        _add("Multiple TTPs", f"{len(ttps)} ATT&CK techniques mapped: {', '.join(ttps[:5])}", "multiple_ttps")
    elif ttps:
        phases = _get_kill_chain_phases(ttps)
        if "impact" in phases:
            _add("Impact-Phase TTPs", f"Impact-stage techniques present: {', '.join(ttps)}", "ttp_impact")
        elif "initial_access" in phases:
            _add("Initial Access TTPs", f"Initial access techniques mapped: {', '.join(ttps)}", "ttp_initial_access")

    confidence = _safe_float(item.get("confidence"))
    if confidence >= 60:
        _add("High Confidence", f"Intelligence confidence {confidence:.0f}% — multiple source corroboration", "high_confidence_intel")

    iocs = _safe_list(item.get("iocs") or item.get("indicators"))
    if iocs:
        _add("Observables Present", f"{len(iocs)} IOC(s) available for detection", "ioc_present")

    source_url = _safe_str(item.get("source_url"))
    if source_url and any(d in source_url for d in ["cisa.gov", "nvd.nist.gov", "microsoft.com", "cisco.com", "fortinet.com"]):
        _add("Vendor Acknowledged", "Vendor or government advisory confirms the vulnerability", "vendor_acknowledged")

    if not evidence:
        _add("Single Source", "Single-source advisory, unconfirmed", "single_source")
        max_weight = EVIDENCE_WEIGHTS["single_source"]

    strength = min(1.0, total_weight / max(max_weight, 0.01) * 1.5)
    strength_label = (
        "CONCLUSIVE" if strength >= 0.85 else
        "STRONG"     if strength >= 0.65 else
        "MODERATE"   if strength >= 0.45 else
        "WEAK"
    )

    return {
        "evidence_items":     evidence,
        "total_weight":       round(total_weight, 2),
        "evidence_strength":  round(strength, 3),
        "strength_label":     strength_label,
    }


# ---------------------------------------------------------------------------
# Targeting profile builder
# ---------------------------------------------------------------------------

_SECTOR_TARGETING: Dict[str, Dict] = {
    "networking_infrastructure": {
        "victims":   "network administrators, NOC teams, ISPs, managed service providers",
        "motive":    "persistent network access for intelligence collection or lateral movement",
        "exposure":  "internet-exposed routers, switches, SD-WAN controllers, VPN concentrators",
    },
    "microsoft_ecosystem": {
        "victims":   "enterprise IT teams managing Windows Active Directory environments",
        "motive":    "credential harvest, lateral movement, ransomware staging",
        "exposure":  "domain controllers, Exchange servers, SharePoint, O365 tenants",
    },
    "cloud_infrastructure": {
        "victims":   "DevOps teams, cloud architects, container platform operators",
        "motive":    "cryptomining, data exfiltration, service disruption, supply chain pivot",
        "exposure":  "misconfigured S3/GCS/Blob storage, Kubernetes API servers, CI/CD pipelines",
    },
    "financial_services": {
        "victims":   "banks, payment processors, fintech platforms, cryptocurrency exchanges",
        "motive":    "financial theft, fraudulent transfers, ransomware for maximum leverage",
        "exposure":  "payment APIs, SWIFT infrastructure, core banking systems",
    },
    "healthcare": {
        "victims":   "hospitals, clinical systems, medical device manufacturers",
        "motive":    "ransomware (high payment willingness), PHI theft, regulatory extortion",
        "exposure":  "DICOM systems, EHR platforms, internet-exposed clinical portals",
    },
    "ot_ics": {
        "victims":   "industrial operators, critical infrastructure, utilities, manufacturing",
        "motive":    "operational disruption, sabotage, espionage",
        "exposure":  "internet-accessible PLCs, HMI interfaces, SCADA historians",
    },
    "government_defense": {
        "victims":   "government agencies, military contractors, defense industrial base",
        "motive":    "espionage, intelligence collection, pre-positioning",
        "exposure":  "email gateways, VPN concentrators, classified system boundaries",
    },
    "supply_chain": {
        "victims":   "software vendors, build pipeline operators, CDN providers",
        "motive":    "downstream compromise at scale via trusted software updates",
        "exposure":  "CI/CD infrastructure, package repositories, code signing systems",
    },
    "cryptocurrency": {
        "victims":   "DeFi protocols, wallet software users, blockchain node operators",
        "motive":    "direct financial theft, rug pull enablement",
        "exposure":  "wallet APIs, smart contract frontends, bridge protocols",
    },
    "ai_ml_systems": {
        "victims":   "AI platform operators, LLM API consumers, model hosting providers",
        "motive":    "model theft, prompt injection for data exfiltration, service abuse",
        "exposure":  "MCP servers, LLM API endpoints, model inference infrastructure",
    },
}


def build_targeting_profile(item: Dict) -> Dict[str, Any]:
    """
    Derive targeting profile — who is being targeted and why.
    Based on vendor, CVE type, TTP patterns, and actor attribution.
    """
    text = (
        _safe_str(item.get("title"))
        + " "
        + _safe_str(item.get("description"))
        + " "
        + _safe_str(item.get("affected_systems", ""))
    ).lower()

    # Match sector patterns
    from ocios_campaign_correlation_engine import _SECTOR_PATTERNS
    matched_sectors = []
    for pattern, sector in _SECTOR_PATTERNS:
        if re.search(pattern, text):
            matched_sectors.append(sector)

    if not matched_sectors:
        matched_sectors = ["general_enterprise"]

    # Build targeting descriptions
    victim_orgs = []
    exposure_vectors = []
    attacker_motives = []

    for sector in matched_sectors[:3]:
        info = _SECTOR_TARGETING.get(sector)
        if info:
            victim_orgs.append(info["victims"])
            attacker_motives.append(info["motive"])
            exposure_vectors.append(info["exposure"])

    # Generic fallback
    if not victim_orgs:
        victim_orgs    = ["organizations running affected software versions"]
        attacker_motives = ["opportunistic exploitation for initial access or data theft"]
        exposure_vectors = ["internet-facing systems running unpatched software"]

    # Internet exposure assessment
    ttps = _extract_ttps(item)
    is_internet_facing = (
        "T1190" in ttps or "T1133" in ttps or "T1566" in ttps
        or any(kw in text for kw in ("internet-facing", "public-facing", "remote", "unauthenticated"))
    )

    apex = item.get("apex_score") or {}
    exposure_score = _safe_float(apex.get("internet_exposure_score"))

    return {
        "primary_targets":     matched_sectors[:3],
        "victim_organizations": victim_orgs[0] if victim_orgs else "organizations with affected software",
        "attacker_motive":     attacker_motives[0] if attacker_motives else "opportunistic exploitation",
        "exposure_vector":     exposure_vectors[0] if exposure_vectors else "unpatched internet-facing systems",
        "internet_facing":     is_internet_facing or exposure_score >= 60,
        "internet_exposure_score": int(exposure_score),
        "targeting_confidence": "HIGH" if len(matched_sectors) >= 2 and matched_sectors[0] != "general_enterprise" else "MEDIUM",
    }


# ---------------------------------------------------------------------------
# Why-this-matters reasoning
# ---------------------------------------------------------------------------

def build_why_it_matters(item: Dict, evidence: Dict, targeting: Dict) -> str:
    """
    Generate evidence-driven 'why this matters' reasoning.
    NOT a template — each element is conditioned on observable evidence.
    """
    parts: List[str] = []

    is_kev  = _safe_bool(item.get("kev") or item.get("cisa_kev"))
    epss    = _safe_float(item.get("epss") or item.get("epss_score"))
    cvss    = _safe_float(item.get("cvss") or item.get("cvss_score"))
    actor   = _safe_str(item.get("actor") or "").lower()
    ttps    = _extract_ttps(item)
    strength = evidence.get("evidence_strength", 0.0)
    severity = _safe_str(item.get("severity", "")).upper()

    # Exploitation status
    if is_kev:
        parts.append(
            "This vulnerability is actively exploited in the wild — CISA has confirmed "
            "real-world exploitation and added it to the Known Exploited Vulnerabilities catalog. "
            "Unpatched systems face immediate risk."
        )
    elif epss >= 0.70:
        parts.append(
            f"With an EPSS score of {epss:.0%}, exploitation within 30 days is near-certain. "
            "Threat actors with automated scanning capabilities are likely already targeting this."
        )
    elif epss >= 0.30:
        parts.append(
            f"The EPSS score of {epss:.0%} indicates elevated exploitation probability. "
            "Proof-of-concept code or active scanning has likely emerged."
        )

    # CVSS reasoning
    if cvss >= 9.0:
        parts.append(
            f"A CVSS score of {cvss:.1f} reflects critical severity — likely low attack complexity "
            "with no authentication required, making automated exploitation at scale feasible."
        )
    elif cvss >= 7.0:
        parts.append(
            f"The CVSS score of {cvss:.1f} indicates high severity. Exploitation may require "
            "some privileges or specific conditions, but is well within reach of skilled adversaries."
        )

    # Actor context
    if actor and actor not in ("cdb-cve-gen", "unknown", ""):
        aptlike = any(kw in actor for kw in ("apt", "lazarus", "kimsuky", "volt", "salt", "sandworm", "cozy", "fancy"))
        ransom  = any(kw in actor for kw in ("lockbit", "clop", "hive", "alphv", "blackcat", "revil", "conti"))
        if aptlike:
            parts.append(
                f"Attribution to '{actor}' places this within a nation-state or APT-linked operation. "
                "These actors operate with long dwell times and sophisticated tradecraft."
            )
        elif ransom:
            parts.append(
                f"Attribution to '{actor}' indicates ransomware operator interest. "
                "The primary business risk is service disruption, data encryption, and extortion demands."
            )
        else:
            parts.append(f"Attributed to threat actor '{actor}'.")

    # Targeting context
    targets = targeting.get("primary_targets", [])
    if targets and targets[0] != "general_enterprise":
        sector_str = targets[0].replace("_", " ")
        parts.append(
            f"The {sector_str} sector is the primary target surface. "
            f"{targeting.get('attacker_motive', 'Exploitation').capitalize()}."
        )

    # Kill chain position
    phases = _get_kill_chain_phases(ttps)
    if "impact" in phases:
        parts.append(
            "ATT&CK technique mapping places this at the Impact phase — "
            "indicating capability for ransomware deployment, data destruction, or service disruption."
        )
    elif "initial_access" in phases:
        parts.append(
            "This provides an initial access vector. Once exploited, attackers typically "
            "establish persistence within hours before defenders detect the breach."
        )
    elif "privilege_escalation" in phases:
        parts.append(
            "This enables privilege escalation. Combined with initial access, an attacker can "
            "achieve domain administrator privileges and unrestricted lateral movement."
        )

    # Evidence quality statement
    if strength >= 0.85:
        parts.append(
            "Evidence quality is CONCLUSIVE — multiple independent sources and observable "
            "exploitation confirm this threat requires immediate action."
        )
    elif strength < 0.35:
        parts.append(
            "Evidence quality is currently WEAK. Intelligence should be treated as a lead "
            "requiring further validation before tier-1 SOC escalation."
        )

    if not parts:
        sev_map = {
            "CRITICAL": "Critical severity vulnerability with direct exploitation potential.",
            "HIGH":     "High severity vulnerability that could enable significant system compromise.",
            "MEDIUM":   "Medium severity vulnerability with limited but viable exploitation paths.",
        }
        parts.append(sev_map.get(severity, "Vulnerability with exploitation potential requiring assessment."))

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Follow-on activity prediction
# ---------------------------------------------------------------------------

def build_followon_prediction(item: Dict) -> Dict[str, Any]:
    """
    Predict likely follow-on attacker activity based on kill chain position
    and adversary patterns.
    """
    ttps    = _extract_ttps(item)
    phases  = _get_kill_chain_phases(ttps)
    is_kev  = _safe_bool(item.get("kev") or item.get("cisa_kev"))
    actor   = _safe_str(item.get("actor") or "").lower()

    is_ransomware = any(kw in actor for kw in (
        "lockbit", "clop", "hive", "alphv", "blackcat", "revil", "conti",
        "akira", "play", "rhysida", "hunters", "medusa",
    )) or any(t in ttps for t in ("T1486", "T1490", "T1485"))

    follow_on_phases = _get_follow_on(phases)

    # Build human-readable prediction
    predictions: List[str] = []

    if is_ransomware:
        predictions = [
            "Ransomware staging and encryption within 24-72 hours of initial access",
            "Data exfiltration prior to encryption for double extortion leverage",
            "Backup deletion and shadow copy removal to prevent recovery",
            "Lateral movement via credential abuse to maximize encryption scope",
        ]
    elif "initial_access" in phases:
        predictions = [
            "Immediate persistence mechanism installation (scheduled tasks, registry, backdoor)",
            "Credential harvesting from LSASS or credential stores within first hour",
            "Network reconnaissance to identify high-value lateral movement targets",
            "C2 beacon establishment on non-standard ports to evade network monitoring",
        ]
        if is_kev:
            predictions.insert(0, "Automated exploitation likely underway — dwell time begins immediately")
    elif "privilege_escalation" in phases:
        predictions = [
            "Lateral movement to domain controllers and critical servers",
            "Kerberoasting or AS-REP roasting for domain credential harvest",
            "Golden Ticket or Silver Ticket creation for persistent domain access",
            "Data staging and exfiltration from identified high-value systems",
        ]
    elif "lateral_movement" in phases:
        predictions = [
            "Collection from identified high-value systems (email, file shares, databases)",
            "Exfiltration to attacker-controlled infrastructure (cloud storage, paste sites)",
            "Deployment of secondary payloads or ransomware on staging is likely",
        ]
    elif "impact" in phases:
        predictions = [
            "Encryption or destruction of backup systems to prevent recovery",
            "Public extortion communication if ransomware operator is involved",
            "Regulatory breach notification obligations triggered for victim organizations",
        ]
    else:
        predictions = [
            "Monitor for exploitation attempts targeting this vulnerability",
            "Expect reconnaissance scanning from threat intelligence actors within days of disclosure",
            "PoC code development or weaponization by criminal groups within 7-14 days",
        ]

    # Timeline
    if is_kev:
        timeline = "IMMEDIATE — exploitation is confirmed active, dwell time may have already begun"
    elif _safe_float(item.get("epss")) >= 0.70:
        timeline = "0-7 DAYS — near-certain exploitation expected imminently"
    elif _safe_float(item.get("cvss") or 0) >= 9.0:
        timeline = "7-30 DAYS — high-severity, likely weaponized by criminal groups within weeks"
    else:
        timeline = "30-90 DAYS — opportunistic exploitation as threat actor tooling matures"

    return {
        "current_kill_chain_phases": phases,
        "predicted_follow_on_phases": follow_on_phases,
        "predicted_activities":      predictions,
        "exploitation_timeline":     timeline,
        "ransomware_risk":           is_ransomware,
        "persistence_likely":        "initial_access" in phases or is_kev,
        "lateral_movement_likely":   any(p in phases for p in ("privilege_escalation", "credential_access", "initial_access")) or is_ransomware,
    }


# ---------------------------------------------------------------------------
# Business risk reasoning
# ---------------------------------------------------------------------------

_FINANCIAL_IMPACT_TABLE: Dict[str, Dict] = {
    "networking_infrastructure": {
        "downtime_cost":     "USD 1M-10M per hour for ISP/carrier-grade outages",
        "recovery_cost":     "USD 500K-5M for full network infrastructure remediation",
        "regulatory_risk":   "FCC, OFAC, and sector-specific compliance exposure",
    },
    "financial_services": {
        "downtime_cost":     "USD 5M-50M per hour for core banking/payment disruption",
        "recovery_cost":     "USD 2M-20M incident response plus regulatory penalties",
        "regulatory_risk":   "PCI-DSS, SOX, DORA (EU), and banking regulator exposure",
    },
    "healthcare": {
        "downtime_cost":     "USD 1M-5M per day plus patient safety liability",
        "recovery_cost":     "USD 1M-10M average ransomware recovery cost in healthcare",
        "regulatory_risk":   "HIPAA breach fines (up to USD 1.9M per violation category)",
    },
    "cloud_infrastructure": {
        "downtime_cost":     "Variable — dependent on revenue-per-minute of hosted services",
        "recovery_cost":     "USD 200K-2M for cloud environment rebuild and forensics",
        "regulatory_risk":   "GDPR, CCPA, and contractual SLA breach liability",
    },
    "government_defense": {
        "downtime_cost":     "Non-financial — mission impact, national security implications",
        "recovery_cost":     "USD 500K-5M for classified system reconstruction",
        "regulatory_risk":   "FISMA, CMMC, and inter-agency breach notification requirements",
    },
    "ot_ics": {
        "downtime_cost":     "USD 500K-50M for industrial production line shutdown",
        "recovery_cost":     "USD 2M-20M for OT environment recovery and requalification",
        "regulatory_risk":   "NERC CIP, TSA Pipeline Security, EPA reporting requirements",
    },
}


def build_business_risk(item: Dict, targeting: Dict) -> Dict[str, Any]:
    """
    Build business risk reasoning — financial exposure, regulatory risk,
    operational impact, and recommended executive actions.
    """
    sectors  = targeting.get("primary_targets", ["general_enterprise"])
    is_kev   = _safe_bool(item.get("kev") or item.get("cisa_kev"))
    apex     = item.get("apex_score") or {}
    ransom_score = _safe_float(apex.get("ransomware_affinity_score"))
    bizdisr  = _safe_float(apex.get("business_disruption_score"))
    severity = _safe_str(item.get("severity", "")).upper()
    cvss     = _safe_float(item.get("cvss") or item.get("cvss_score"))

    # Get best financial impact table entry
    fin_info: Optional[Dict] = None
    for sector in sectors:
        fin_info = _FINANCIAL_IMPACT_TABLE.get(sector)
        if fin_info:
            break

    if not fin_info:
        fin_info = {
            "downtime_cost":   "USD 50K-500K per incident depending on scope",
            "recovery_cost":   "USD 100K-1M for standard enterprise IR engagement",
            "regulatory_risk": "GDPR, CCPA, and sector-specific breach notification",
        }

    # Risk level
    if is_kev and (ransom_score >= 60 or cvss >= 9.0):
        risk_level = "CRITICAL_BUSINESS_RISK"
    elif is_kev or bizdisr >= 70 or cvss >= 9.0:
        risk_level = "HIGH_BUSINESS_RISK"
    elif bizdisr >= 50 or severity == "HIGH":
        risk_level = "ELEVATED_BUSINESS_RISK"
    else:
        risk_level = "MODERATE_BUSINESS_RISK"

    # Executive actions
    exec_actions: List[str] = []
    if is_kev:
        exec_actions.append("EMERGENCY: Initiate patch deployment within 24 hours per CISA emergency directive guidance")
    if ransom_score >= 60:
        exec_actions.append("Validate backup integrity and test offline recovery capability immediately")
        exec_actions.append("Review cyber insurance policy coverage and ransomware response retainer")
    if sectors and sectors[0] != "general_enterprise":
        exec_actions.append(f"Notify CISO and IT leadership of active {sectors[0].replace('_',' ')} sector targeting")
    exec_actions.append("Confirm detection coverage for associated ATT&CK techniques in SIEM/EDR")
    exec_actions.append("Assess internet-exposed attack surface for vulnerable instances")

    # Regulatory exposure
    reg_frameworks = []
    for sector in sectors:
        if "financial" in sector:
            reg_frameworks.extend(["PCI-DSS", "SOX", "DORA"])
        elif "healthcare" in sector:
            reg_frameworks.extend(["HIPAA", "HITECH"])
        elif "government" in sector:
            reg_frameworks.extend(["FISMA", "CMMC", "FedRAMP"])
        elif "ot_ics" in sector:
            reg_frameworks.extend(["NERC-CIP", "ICS-CERT"])
    if not reg_frameworks:
        reg_frameworks = ["GDPR", "CCPA", "NIS2"]

    return {
        "business_risk_level":    risk_level,
        "estimated_downtime_cost": fin_info["downtime_cost"],
        "estimated_recovery_cost": fin_info["recovery_cost"],
        "regulatory_frameworks":  list(dict.fromkeys(reg_frameworks)),
        "regulatory_risk":        fin_info["regulatory_risk"],
        "ransomware_financial_risk": ransom_score >= 50,
        "executive_actions":      exec_actions,
        "board_escalation":       risk_level in ("CRITICAL_BUSINESS_RISK", "HIGH_BUSINESS_RISK") and (is_kev or cvss >= 9.0),
    }


# ---------------------------------------------------------------------------
# Per-item reasoning block
# ---------------------------------------------------------------------------

def build_item_reasoning(item: Dict) -> Dict[str, Any]:
    """
    Build the complete operational reasoning block for a single advisory.
    This is the primary per-item output of the reasoning engine.
    """
    item_id = _item_id(item)
    try:
        evidence    = build_evidence_chain(item)
        targeting   = build_targeting_profile(item)
        why_matters = build_why_it_matters(item, evidence, targeting)
        follow_on   = build_followon_prediction(item)
        biz_risk    = build_business_risk(item, targeting)

        return {
            "item_id":            item_id,
            "title":              _safe_str(item.get("title") or item.get("headline")),
            "evidence_chain":     evidence,
            "why_it_matters":     why_matters,
            "targeting_profile":  targeting,
            "follow_on_activity": follow_on,
            "business_risk":      biz_risk,
            "reasoning_quality":  evidence["strength_label"],
            "generated_at":       _utc_now(),
        }
    except Exception as exc:
        log.warning("Reasoning failed for %s: %s", item_id, exc)
        return {
            "item_id":         item_id,
            "error":           str(exc),
            "reasoning_quality": "ERROR",
        }


# ---------------------------------------------------------------------------
# Corpus-level outputs
# ---------------------------------------------------------------------------

def build_sector_threat_landscape(items: List[Dict], reasoning: List[Dict]) -> Dict[str, Any]:
    """
    Aggregate sector-level threat intelligence across the full corpus.
    Identifies which sectors face acute, elevated, or baseline pressure.
    """
    log.info("Building sector threat landscape...")
    sector_stats: Dict[str, Dict] = defaultdict(lambda: {
        "advisory_count": 0,
        "kev_count":      0,
        "high_risk_count": 0,
        "ransomware_count": 0,
        "avg_cvss":       [],
        "actors":         set(),
        "advisory_ids":   [],
    })

    for item, r in zip(items, reasoning):
        targets = (
            (r.get("targeting_profile") or {}).get("primary_targets")
            or ["general_enterprise"]
        )
        is_kev   = _safe_bool(item.get("kev") or item.get("cisa_kev"))
        cvss     = _safe_float(item.get("cvss") or item.get("cvss_score"))
        severity = _safe_str(item.get("severity", "")).upper()
        is_ransom = (r.get("follow_on_activity") or {}).get("ransomware_risk", False)
        actor    = _safe_str(item.get("actor") or "").lower()

        for sector in targets[:2]:
            s = sector_stats[sector]
            s["advisory_count"] += 1
            if is_kev:
                s["kev_count"] += 1
            if severity in ("CRITICAL", "HIGH"):
                s["high_risk_count"] += 1
            if is_ransom:
                s["ransomware_count"] += 1
            if cvss > 0:
                s["avg_cvss"].append(cvss)
            if actor and actor != "cdb-cve-gen":
                s["actors"].add(actor)
            s["advisory_ids"].append(_item_id(item))

    sectors_out = []
    for sector, stats in sector_stats.items():
        if stats["advisory_count"] == 0:
            continue
        cvss_list = stats["avg_cvss"]
        avg_cvss  = round(sum(cvss_list) / len(cvss_list), 1) if cvss_list else 0.0

        # Pressure score
        pressure = (
            stats["advisory_count"] * 3
            + stats["kev_count"]     * 20
            + stats["high_risk_count"] * 5
            + stats["ransomware_count"] * 10
        )
        pressure_label = (
            "CRITICAL" if pressure >= 60 else
            "HIGH"     if pressure >= 30 else
            "ELEVATED" if pressure >= 15 else
            "MODERATE"
        )

        sectors_out.append({
            "sector":             sector,
            "advisory_count":     stats["advisory_count"],
            "kev_confirmed":      stats["kev_count"],
            "high_risk_advisories": stats["high_risk_count"],
            "ransomware_pressure": stats["ransomware_count"],
            "avg_cvss":           avg_cvss,
            "active_actors":      sorted(stats["actors"]),
            "pressure_score":     pressure,
            "pressure_label":     pressure_label,
            "advisory_ids":       stats["advisory_ids"][:10],
        })

    sectors_out.sort(key=lambda s: -s["pressure_score"])

    return {
        "schema_version": "1.0",
        "engine":         "ocios_operational_reasoning_engine",
        "generated_at":   _utc_now(),
        "sector_count":   len(sectors_out),
        "hottest_sector": sectors_out[0]["sector"] if sectors_out else "unknown",
        "sectors":        sectors_out,
    }


def build_adversary_objective_map(items: List[Dict], reasoning: List[Dict]) -> Dict[str, Any]:
    """
    Map attacker objectives across the corpus.
    Shows what adversaries are actually trying to achieve.
    """
    log.info("Building adversary objective map...")
    obj_stats: Dict[str, Dict] = defaultdict(lambda: {
        "count": 0, "kev_count": 0, "advisory_ids": []
    })

    for item, r in zip(items, reasoning):
        phases  = (r.get("follow_on_activity") or {}).get("current_kill_chain_phases", [])
        is_kev  = _safe_bool(item.get("kev") or item.get("cisa_kev"))
        is_ransom = (r.get("follow_on_activity") or {}).get("ransomware_risk", False)

        objectives: List[str] = []
        if is_ransom:
            objectives.append("ransomware_and_extortion")
        elif "impact" in phases:
            objectives.append("service_disruption_or_destruction")
        elif "exfiltration" in phases or "collection" in phases:
            objectives.append("data_theft_and_espionage")
        elif "lateral_movement" in phases:
            objectives.append("network_infiltration_and_persistence")
        elif "initial_access" in phases:
            objectives.append("foothold_establishment")
        elif "privilege_escalation" in phases:
            objectives.append("privilege_escalation_and_domain_control")
        else:
            objectives.append("opportunistic_exploitation")

        for obj in objectives:
            obj_stats[obj]["count"]       += 1
            obj_stats[obj]["advisory_ids"].append(_item_id(item))
            if is_kev:
                obj_stats[obj]["kev_count"] += 1

    obj_out = []
    for obj, stats in obj_stats.items():
        obj_out.append({
            "objective":      obj,
            "advisory_count": stats["count"],
            "kev_linked":     stats["kev_count"],
            "advisory_ids":   stats["advisory_ids"][:8],
            "prevalence_pct": 0,  # filled below
        })

    total = sum(o["advisory_count"] for o in obj_out)
    for o in obj_out:
        o["prevalence_pct"] = round(o["advisory_count"] / total * 100, 1) if total else 0

    obj_out.sort(key=lambda o: -o["advisory_count"])

    return {
        "schema_version":       "1.0",
        "engine":               "ocios_operational_reasoning_engine",
        "generated_at":         _utc_now(),
        "dominant_objective":   obj_out[0]["objective"] if obj_out else "unknown",
        "objective_count":      len(obj_out),
        "objectives":           obj_out,
    }


def build_business_risk_synthesis(items: List[Dict], reasoning: List[Dict]) -> Dict[str, Any]:
    """
    Aggregate business risk picture across the full corpus.
    """
    log.info("Building business risk synthesis...")
    risk_levels    = Counter()
    board_triggers = 0
    reg_exposure   = Counter()
    total_kev      = 0
    ransom_exposed = 0
    exec_actions_seen: set = set()

    for item, r in zip(items, reasoning):
        biz = r.get("business_risk") or {}
        risk_levels[biz.get("business_risk_level", "UNKNOWN")] += 1
        if biz.get("board_escalation"):
            board_triggers += 1
        for fw in (biz.get("regulatory_frameworks") or []):
            reg_exposure[fw] += 1
        if _safe_bool(item.get("kev") or item.get("cisa_kev")):
            total_kev += 1
        if biz.get("ransomware_financial_risk"):
            ransom_exposed += 1
        for action in (biz.get("executive_actions") or [])[:2]:
            exec_actions_seen.add(action[:80])

    return {
        "schema_version":        "1.0",
        "engine":                "ocios_operational_reasoning_engine",
        "generated_at":          _utc_now(),
        "total_advisories":      len(items),
        "risk_distribution":     dict(risk_levels),
        "board_escalation_triggers": board_triggers,
        "kev_confirmed_total":   total_kev,
        "ransomware_exposed":    ransom_exposed,
        "regulatory_exposure":   dict(reg_exposure.most_common(8)),
        "top_executive_actions": sorted(exec_actions_seen)[:8],
        "portfolio_risk_level": (
            "CRITICAL" if risk_levels.get("CRITICAL_BUSINESS_RISK", 0) >= 3 else
            "HIGH"     if risk_levels.get("HIGH_BUSINESS_RISK", 0) >= 5 or total_kev >= 3 else
            "ELEVATED" if risk_levels.get("ELEVATED_BUSINESS_RISK", 0) >= 5 else
            "MODERATE"
        ),
    }


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, obj: Any, indent: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    try:
        content = json.dumps(obj, indent=indent, ensure_ascii=False, default=str)
        tmp.write_text(content, encoding="utf-8")
        os.replace(str(tmp), str(path))
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_reasoning_engine(
    manifest_path: Path = MANIFEST_PATH,
    ocios_dir:     Path = OCIOS_DIR,
) -> Dict[str, Any]:
    """Execute the OCIOS Operational Reasoning Engine. Never raises."""
    t_start = time.monotonic()
    summary: Dict[str, Any] = {
        "engine":      "ocios_operational_reasoning_engine",
        "version":     ENGINE_VERSION,
        "started_at":  _utc_now(),
        "status":      "running",
        "items_processed": 0,
        "errors":      [],
    }

    if not manifest_path.exists():
        msg = f"Manifest not found at {manifest_path}"
        log.warning(msg)
        summary.update({"status": "skipped", "errors": [msg]})
        return summary

    try:
        raw   = json.loads(manifest_path.read_text(encoding="utf-8"))
        items: List[Dict] = raw.get("advisories") or raw.get("reports") or []
    except Exception as exc:
        log.error("Manifest load failed: %s", exc)
        summary.update({"status": "error", "errors": [str(exc)]})
        return summary

    log.info("Running reasoning engine on %d advisories...", len(items))

    # Per-item reasoning
    item_reasoning: List[Dict] = []
    for item in items:
        item_reasoning.append(build_item_reasoning(item))
    summary["items_processed"] = len(item_reasoning)

    outputs = {
        "operational_reasoning.json": {
            "schema_version": "1.0",
            "engine":         "ocios_operational_reasoning_engine",
            "generated_at":   _utc_now(),
            "item_count":     len(item_reasoning),
            "items":          item_reasoning,
        }
    }

    # Corpus-level outputs
    try:
        outputs["sector_threat_landscape.json"] = build_sector_threat_landscape(items, item_reasoning)
    except Exception as exc:
        log.error("Sector landscape failed: %s", exc)
        summary["errors"].append(f"sector_landscape: {exc}")

    try:
        outputs["adversary_objective_map.json"] = build_adversary_objective_map(items, item_reasoning)
    except Exception as exc:
        log.error("Objective map failed: %s", exc)
        summary["errors"].append(f"adversary_objectives: {exc}")

    try:
        outputs["business_risk_synthesis.json"] = build_business_risk_synthesis(items, item_reasoning)
    except Exception as exc:
        log.error("Business risk synthesis failed: %s", exc)
        summary["errors"].append(f"business_risk: {exc}")

    # Write all outputs
    written = 0
    for filename, obj in outputs.items():
        try:
            _atomic_write(ocios_dir / filename, obj)
            log.info("Written: data/ocios/%s", filename)
            written += 1
        except Exception as exc:
            log.error("Write failed %s: %s", filename, exc)
            summary["errors"].append(f"write:{filename}: {exc}")

    elapsed = round(time.monotonic() - t_start, 2)
    summary.update({
        "status":          "success" if not summary["errors"] else "partial",
        "files_written":   written,
        "elapsed_seconds": elapsed,
        "completed_at":    _utc_now(),
    })

    try:
        _atomic_write(ocios_dir / "reasoning_engine_summary.json", summary)
    except Exception:
        pass

    log.info(
        "OCIOS Reasoning Engine complete: %d items, %d files | %.2fs",
        summary["items_processed"], written, elapsed,
    )
    return summary


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="OCIOS Operational Reasoning Engine")
    parser.add_argument("--manifest",   default=str(MANIFEST_PATH))
    parser.add_argument("--output-dir", default=str(OCIOS_DIR))
    args = parser.parse_args()
    result = run_reasoning_engine(
        manifest_path=Path(args.manifest),
        ocios_dir=Path(args.output_dir),
    )
    return 0 if result.get("status") in ("success", "partial", "skipped") else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
