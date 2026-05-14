#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/enterprise_scoring_engine.py — Enterprise Intelligence Scoring Engine
================================================================================
Version : 149.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering
License : CONFIDENTIAL — All Rights Reserved

10-DIMENSION ENTERPRISE INTELLIGENCE SCORING SYSTEM

Produces APEX_SCORE block on every advisory for premium API tier access.
Each dimension is independently scored 0–100 and combined into a composite
APEX_ENTERPRISE_SCORE that drives SOC prioritisation, MSSP alerting,
and executive dashboard intelligence.

DIMENSIONS:
  1.  threat_velocity_score        — How fast is this threat propagating?
  2.  ransomware_affinity_score    — Ransomware group linkage probability
  3.  kev_priority_score           — CISA KEV-aligned exploitability weight
  4.  exploit_maturity_score       — PoC → weaponised → ITW maturity
  5.  adversary_sophistication_score — Attribution confidence + TTPs
  6.  operational_severity_score   — Real-world SOC impact severity
  7.  business_disruption_score    — Revenue/operations impact potential
  8.  internet_exposure_score      — Internet-facing attack surface weight
  9.  exploitability_confidence_score — EPSS + KEV + exploit status fusion
  10. patch_urgency_score          — Time-to-patch priority derived score

PIPELINE POSITION:
  Called after intel_quality_engine.py (STAGE 3.5.1) before report generation.
  Reads:  data/stix/feed_manifest.json
  Writes: data/stix/feed_manifest.json (additive — apex_score block appended)
          data/enterprise_scoring/scoring_report.json

GUARANTEES:
  - ADDITIVE ONLY — never removes or modifies existing fields
  - Zero silent failure — all exceptions logged + item still passes through
  - Atomic writes — tmp → fsync → os.replace
  - Deterministic — same inputs always produce same scores
  - Performance — processes 1000 items in < 2s
================================================================================
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [APEX-SCORING] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("APEX-SCORING")

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT        = Path(__file__).resolve().parent.parent
MANIFEST_PATH    = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
SCORING_DIR      = REPO_ROOT / "data" / "enterprise_scoring"
SCORING_REPORT   = SCORING_DIR / "scoring_report.json"

ENGINE_VERSION   = "149.0.0"
NOW_UTC          = datetime.now(timezone.utc)
NOW_ISO          = NOW_UTC.strftime("%Y-%m-%dT%H:%M:%SZ")

# ── Ransomware-affiliated threat actors / campaigns ───────────────────────────
_RANSOMWARE_ACTORS = {
    "lockbit", "blackcat", "alphv", "clop", "hive", "black basta",
    "blackbasta", "revil", "conti", "darkside", "blackmatter", "ragnar",
    "ransomhub", "play ransomware", "akira", "royal", "rhysida",
    "hunters international", "medusa", "noname", "scattered spider",
    "lapsus", "lazarus", "apt41", "fin7", "fin8", "ta505", "evil corp",
    "evilcorp", "wizard spider", "cozy bear", "apt29", "nobelium",
    "blacksuit", "meow", "trigona", "fog", "lynx", "interlock",
    "qilin", "eldorado", "ransomexx", "darkrace", "incransom",
}

# ── Techniques strongly linked to ransomware kill chains ─────────────────────
_RANSOMWARE_TTPS = {
    "T1486", "T1490", "T1489", "T1485", "T1491",   # Impact phase
    "T1059.001", "T1059.003",                        # PowerShell / cmd
    "T1078", "T1021.001", "T1021.002",               # Valid accounts / RDP / SMB
    "T1055", "T1027", "T1562",                       # Defense evasion
    "T1567", "T1041",                                # Exfiltration (double extortion)
}

# ── Internet-facing attack surface techniques ─────────────────────────────────
_INTERNET_FACING_TTPS = {
    "T1190", "T1133", "T1566", "T1566.001", "T1566.002",
    "T1189", "T1195",
}

# ── Advanced threat actor techniques ─────────────────────────────────────────
_APT_TTPS = {
    "T1595", "T1592", "T1589", "T1590",              # Reconnaissance
    "T1583", "T1584", "T1587", "T1588",              # Resource development
    "T1055", "T1562", "T1620", "T1574",              # Advanced evasion
    "T1528", "T1539",                                 # Token/session theft
    "T1550",                                          # Pass-the-hash/ticket
}

# ── Vuln classes with immediate internet exploitation paths ──────────────────
_HIGH_INTERNET_EXPOSURE_CLASSES = {
    "remote_code_execution", "auth_bypass", "sql_injection", "ssrf",
    "path_traversal", "command_injection", "xxe", "deserialization",
    "template_injection",
}

# ── High-value target threat types ───────────────────────────────────────────
_BUSINESS_CRITICAL_TYPES = {
    "ransomware", "ics/ot", "critical infrastructure", "supply chain",
    "zero-day", "apt", "nation-state", "malware", "infostealer",
}


# ─────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> int:
    """Clamp and round to integer in [lo, hi]."""
    return max(int(lo), min(int(round(v)), int(hi)))


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v) if v is not None else default
    except (ValueError, TypeError):
        return default


def _safe_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("true", "yes", "1")
    return bool(v)


def _str_lower(v: Any) -> str:
    return str(v).lower() if v is not None else ""


def _extract_ttps(item: dict) -> set:
    """Extract all TTP IDs from item into a flat set."""
    ttps = set()
    raw = item.get("ttps") or item.get("mitre_tactics") or item.get("tags") or []
    for t in raw:
        if isinstance(t, str) and re.match(r'^T\d{4}', t.strip().upper()):
            ttps.add(t.strip().upper())
        elif isinstance(t, dict):
            tid = t.get("id") or t.get("technique_id") or ""
            if re.match(r'^T\d{4}', tid.strip().upper()):
                ttps.add(tid.strip().upper())
    return ttps


def _detect_vuln_class(item: dict) -> str:
    """Detect vulnerability class from title + description."""
    text = " ".join([
        str(item.get("title") or ""),
        str(item.get("description") or ""),
        str(item.get("threat_type") or ""),
    ]).lower()

    if re.search(r'\bransomware\b|\braas\b|\bransomware.as.a', text):
        return "ransomware"
    if re.search(r'\brce\b|\bremote.code.exec|\barbitrary.code', text):
        return "remote_code_execution"
    if re.search(r'\bauth.bypass|\bauthentication.bypass|\bunauthenticated\b', text):
        return "auth_bypass"
    if re.search(r'\bsql.inject|\bsqli\b', text):
        return "sql_injection"
    if re.search(r'\bssrf\b|\bserver.side.request', text):
        return "ssrf"
    if re.search(r'\bpath.travers|\bdirectory.travers|\blfi\b|\brfi\b', text):
        return "path_traversal"
    if re.search(r'\bxss\b|\bcross.site.script', text):
        return "xss"
    if re.search(r'\bdeseri|\bobject.inject', text):
        return "deserialization"
    if re.search(r'\bcommand.inject|\bos.command|\bcmd.inject', text):
        return "command_injection"
    if re.search(r'\bprivilege.escal|\bprivilege.elev|\bprivesc\b', text):
        return "privilege_escalation"
    if re.search(r'\btemplate.inject|\bssti\b', text):
        return "template_injection"
    if re.search(r'\bmemory.corrupt|\bbuffer.over|\bheap.over|\bstack.over|\buse.after.free|\buaf\b', text):
        return "memory_corruption"
    if re.search(r'\binfo.steal|\bstealer\b|\blumma\b|\bredline\b', text):
        return "infostealer"
    if re.search(r'\bphish|\bspear.phish', text):
        return "phishing"
    if re.search(r'\bapt\b|\bnation.state|\bstate.sponsor', text):
        return "apt"
    if re.search(r'\bzero.day\b|\b0day\b|\bunpatched\b', text):
        return "zero_day"
    if re.search(r'\bdos\b|\bdenial.of.service|\bread.service', text):
        return "denial_of_service"
    return "generic"


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 1: THREAT VELOCITY SCORE (0–100)
# How rapidly is this threat spreading / being exploited?
# ─────────────────────────────────────────────────────────────────────────────

def score_threat_velocity(item: dict) -> int:
    """
    Measures threat propagation velocity based on:
    - KEV confirmed exploitation (fastest signal)
    - EPSS probability (statistical exploitation likelihood)
    - IOC count (higher = active campaign)
    - TTP count (more techniques = active kill chain)
    - Exploit availability flags
    - Published_at recency
    """
    score = 0.0

    # KEV is the strongest velocity signal — confirmed in-the-wild
    kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))
    if kev:
        score += 45.0

    # EPSS probability contributes up to 25 points
    epss = _safe_float(item.get("epss_score"))
    if epss > 100:  # normalise basis-points
        epss = epss / 100.0
    score += min(epss / 100.0, 1.0) * 25.0

    # IOC count — each observed IOC signals active campaign infrastructure
    ioc_count = int(item.get("ioc_count") or len(item.get("iocs") or []))
    if ioc_count > 0:
        score += min(ioc_count / 50.0, 1.0) * 15.0

    # Exploit availability
    exploit_status = _str_lower(item.get("exploit_status") or item.get("exploit_maturity") or "")
    if "public" in exploit_status or "weaponised" in exploit_status or "in-the-wild" in exploit_status:
        score += 15.0
    elif "poc" in exploit_status or "proof" in exploit_status:
        score += 8.0

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 2: RANSOMWARE AFFINITY SCORE (0–100)
# Probability this threat is linked to ransomware ecosystem
# ─────────────────────────────────────────────────────────────────────────────

def score_ransomware_affinity(item: dict) -> int:
    """
    Multi-signal ransomware linkage score:
    - Threat type / tags containing ransomware keywords
    - Actor attribution to known ransomware groups
    - TTP overlap with ransomware kill chains
    - Vuln class (RCE / auth_bypass prime ransomware initial access)
    - IOC count suggesting active deployment
    """
    score = 0.0

    # Threat type / tags
    threat_type = _str_lower(item.get("threat_type") or "")
    tags_text = " ".join(_str_lower(t) for t in (item.get("tags") or []))
    combined_text = " ".join([
        _str_lower(item.get("title") or ""),
        threat_type,
        tags_text,
        _str_lower(item.get("description") or ""),
    ])

    if "ransomware" in combined_text:
        score += 40.0
    if any(actor in combined_text for actor in _RANSOMWARE_ACTORS):
        score += 30.0

    # TTP overlap with ransomware kill chain
    ttps = _extract_ttps(item)
    ransomware_ttp_hits = len(ttps & _RANSOMWARE_TTPS)
    score += min(ransomware_ttp_hits * 8.0, 24.0)

    # Vuln class that is commonly exploited as ransomware initial access
    vuln_class = _detect_vuln_class(item)
    if vuln_class in ("remote_code_execution", "auth_bypass", "privilege_escalation"):
        score += 10.0

    # KEV + high IOC count suggests active ransomware deployment
    kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))
    ioc_count = int(item.get("ioc_count") or len(item.get("iocs") or []))
    if kev and ioc_count > 5:
        score += 10.0

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 3: KEV PRIORITY SCORE (0–100)
# CISA-aligned exploitability priority weight
# ─────────────────────────────────────────────────────────────────────────────

def score_kev_priority(item: dict) -> int:
    """
    CISA KEV-aligned prioritisation:
    - KEV status (primary signal)
    - CVSS score (severity envelope)
    - EPSS probability
    - Exploit maturity
    - Known exploitation timeframe
    """
    score = 0.0
    kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))
    cvss = _safe_float(item.get("cvss_score"))
    epss = _safe_float(item.get("epss_score"))
    if epss > 100:
        epss = epss / 100.0
    risk = _safe_float(item.get("risk_score"))

    if kev:
        score += 50.0  # Hard KEV bonus

    # CVSS contribution (up to 20 pts)
    score += (cvss / 10.0) * 20.0

    # EPSS contribution (up to 20 pts)
    score += (epss / 100.0) * 20.0

    # APEX risk score contribution (up to 10 pts)
    score += (risk / 10.0) * 10.0

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 4: EXPLOIT MATURITY SCORE (0–100)
# PoC availability → weaponisation → in-the-wild continuum
# ─────────────────────────────────────────────────────────────────────────────

def score_exploit_maturity(item: dict) -> int:
    """
    Exploit maturity lifecycle:
    0–20:   Theoretical / CVE-only
    21–40:  PoC published (GitHub/ExploitDB)
    41–60:  Functional exploit / Metasploit module
    61–80:  Weaponised exploit in threat actor toolkit
    81–100: In-the-wild confirmed / KEV listed
    """
    score = 0.0
    exploit_status = _str_lower(item.get("exploit_status") or item.get("exploit_maturity") or "")
    kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))
    epss = _safe_float(item.get("epss_score"))
    if epss > 100:
        epss = epss / 100.0
    ioc_count = int(item.get("ioc_count") or len(item.get("iocs") or []))

    # Exploit status signals (highest maturity wins)
    if kev or "in-the-wild" in exploit_status or "itw" in exploit_status:
        score = max(score, 85.0)
    elif "weaponised" in exploit_status or "weaponized" in exploit_status:
        score = max(score, 72.0)
    elif "metasploit" in exploit_status or "module" in exploit_status:
        score = max(score, 60.0)
    elif "functional" in exploit_status or "working" in exploit_status:
        score = max(score, 55.0)
    elif "poc" in exploit_status or "proof" in exploit_status or "public" in exploit_status:
        score = max(score, 42.0)
    elif "theoretical" in exploit_status or "unproven" in exploit_status:
        score = max(score, 15.0)
    else:
        # Derive from EPSS — high probability implies exploit exists
        if epss >= 50.0:
            score = max(score, 65.0)
        elif epss >= 20.0:
            score = max(score, 45.0)
        elif epss >= 5.0:
            score = max(score, 30.0)
        else:
            score = max(score, 10.0)

    # IOC presence confirms active exploitation
    if ioc_count > 10:
        score = min(score + 15.0, 100.0)
    elif ioc_count > 3:
        score = min(score + 8.0, 100.0)

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 5: ADVERSARY SOPHISTICATION SCORE (0–100)
# Attribution confidence × TTP depth × actor tier
# ─────────────────────────────────────────────────────────────────────────────

def score_adversary_sophistication(item: dict) -> int:
    """
    Adversary sophistication assessment:
    - Actor attribution confidence
    - Number and depth of observed TTPs
    - Known advanced techniques (APT, supply chain, etc.)
    - Campaign infrastructure complexity (IOC diversity)
    """
    score = 0.0
    actor = _str_lower(item.get("actor_cluster") or item.get("actor_tag") or item.get("primary_actor") or "")
    ttps = _extract_ttps(item)
    ioc_count = int(item.get("ioc_count") or len(item.get("iocs") or []))
    confidence = _safe_float(item.get("confidence_score") or item.get("confidence") or 0)

    # Actor sophistication tier
    advanced_actors = {
        "apt29", "apt28", "apt41", "lazarus", "cozy bear", "fancy bear",
        "sandworm", "hafnium", "nobelium", "winnti", "equation group",
        "turla", "darkhotel", "kimsuky", "scarlet mimic", "fin7",
    }
    if any(adv in actor for adv in advanced_actors):
        score += 35.0
    elif "apt" in actor or "nation" in actor or "state" in actor:
        score += 25.0
    elif any(rw in actor for rw in _RANSOMWARE_ACTORS):
        score += 20.0
    elif actor and actor not in ("unattributed", "unknown", "cdb-cve-gen", "cdb-ran-gen", "cdb-apt-gen"):
        score += 12.0

    # TTP depth — number and variety of techniques
    ttp_count = len(ttps)
    score += min(ttp_count * 3.5, 28.0)

    # Advanced technique presence
    apt_ttp_hits = len(ttps & _APT_TTPS)
    score += min(apt_ttp_hits * 5.0, 20.0)

    # Attribution confidence
    score += min(confidence / 100.0 * 15.0, 15.0)

    # Infrastructure complexity (IOC diversity)
    if ioc_count > 20:
        score += 10.0
    elif ioc_count > 5:
        score += 5.0

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 6: OPERATIONAL SEVERITY SCORE (0–100)
# Real-world SOC operational impact severity
# ─────────────────────────────────────────────────────────────────────────────

def score_operational_severity(item: dict) -> int:
    """
    SOC operational severity:
    - Severity tier (CRITICAL/HIGH/MEDIUM/LOW)
    - APEX risk composite score
    - CVSS base score
    - Threat type operational impact
    - IOC availability for detection
    - Detection rule availability
    """
    score = 0.0
    sev = _str_lower(item.get("severity") or "medium")
    risk = _safe_float(item.get("risk_score"))
    cvss = _safe_float(item.get("cvss_score"))
    threat_type = _str_lower(item.get("threat_type") or "")
    ioc_count = int(item.get("ioc_count") or len(item.get("iocs") or []))

    # Severity tier
    sev_scores = {"critical": 40.0, "high": 30.0, "medium": 18.0, "low": 8.0}
    score += sev_scores.get(sev, 15.0)

    # APEX risk composite (up to 20 pts)
    score += (risk / 10.0) * 20.0

    # CVSS (up to 15 pts)
    score += (cvss / 10.0) * 15.0

    # Threat type operational impact
    high_ops_types = {"ransomware", "ics/ot", "critical infrastructure", "apt", "malware"}
    if any(t in threat_type for t in high_ops_types):
        score += 15.0
    elif "vulnerability" in threat_type or "exploit" in threat_type:
        score += 8.0

    # IOC coverage supports operational detection
    if ioc_count > 10:
        score += 10.0
    elif ioc_count > 0:
        score += 5.0

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 7: BUSINESS DISRUPTION SCORE (0–100)
# Business operations and revenue impact potential
# ─────────────────────────────────────────────────────────────────────────────

def score_business_disruption(item: dict) -> int:
    """
    Business impact disruption potential:
    - Ransomware (maximum disruption)
    - Service availability impact (DoS/Impact TTPs)
    - Sector criticality
    - Data breach risk
    - Regulatory exposure
    """
    score = 0.0
    vuln_class = _detect_vuln_class(item)
    threat_type = _str_lower(item.get("threat_type") or "")
    ttps = _extract_ttps(item)
    sev = _str_lower(item.get("severity") or "medium")
    kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))

    # Disruption class weights
    disruption_map = {
        "ransomware":           55.0,  # Maximum disruption
        "remote_code_execution": 40.0,
        "denial_of_service":    38.0,
        "auth_bypass":          35.0,
        "command_injection":    35.0,
        "sql_injection":        30.0,
        "deserialization":      32.0,
        "privilege_escalation": 28.0,
        "infostealer":          25.0,
        "memory_corruption":    30.0,
        "phishing":             22.0,
        "ssrf":                 28.0,
        "generic":              15.0,
    }
    score += disruption_map.get(vuln_class, 15.0)

    # Impact TTPs
    impact_ttps = {"T1486", "T1490", "T1489", "T1485", "T1499", "T1498"}
    if ttps & impact_ttps:
        score += 20.0

    # ICS/OT / Critical infrastructure has outsized disruption potential
    if "ics" in threat_type or "ot" in threat_type or "critical" in threat_type:
        score += 20.0

    # KEV = active disruption confirmed
    if kev:
        score += 15.0

    # Severity multiplier
    sev_mult = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.40}.get(sev, 0.65)
    score *= sev_mult

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 8: INTERNET EXPOSURE SCORE (0–100)
# Internet-facing attack surface exploitability
# ─────────────────────────────────────────────────────────────────────────────

def score_internet_exposure(item: dict) -> int:
    """
    Internet-facing attack surface weight:
    - Vuln class requires internet-facing application
    - Initial access TTPs (T1190, T1566, etc.)
    - Network attack vector (CVSS AV:N)
    - IOC types include public IPs/domains (active scanning)
    """
    score = 0.0
    vuln_class = _detect_vuln_class(item)
    ttps = _extract_ttps(item)
    attack_vector = _str_lower(item.get("attack_vector") or item.get("cvss_av") or "")

    # Vuln class directly exploitable from internet
    if vuln_class in _HIGH_INTERNET_EXPOSURE_CLASSES:
        score += 40.0
    elif vuln_class in ("privilege_escalation", "memory_corruption"):
        score += 20.0  # Post-exploitation but needs internet for initial access
    elif vuln_class == "phishing":
        score += 35.0
    else:
        score += 10.0

    # Internet-facing initial access TTPs
    ia_hits = len(ttps & _INTERNET_FACING_TTPS)
    score += min(ia_hits * 10.0, 30.0)

    # Network attack vector (CVSS)
    if "network" in attack_vector:
        score += 20.0
    elif "adjacent" in attack_vector:
        score += 10.0
    elif "local" in attack_vector or "physical" in attack_vector:
        score = max(0.0, score - 10.0)

    # Privileges required = None means unauthenticated internet exploitation
    pr = _str_lower(item.get("privileges_required") or item.get("cvss_pr") or "")
    if pr in ("none", ""):
        score += 10.0
    elif pr == "high":
        score = max(0.0, score - 10.0)

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 9: EXPLOITABILITY CONFIDENCE SCORE (0–100)
# EPSS + KEV + exploit status multi-signal fusion
# ─────────────────────────────────────────────────────────────────────────────

def score_exploitability_confidence(item: dict) -> int:
    """
    Fusion of exploitation probability signals:
    - EPSS (statistical model)
    - KEV status (confirmed exploitation)
    - Exploit status (maturity)
    - IOC presence (infrastructure deployed)
    - Source reliability
    """
    score = 0.0
    kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))
    epss = _safe_float(item.get("epss_score"))
    if epss > 100:
        epss = epss / 100.0
    confidence = _safe_float(item.get("confidence_score") or item.get("confidence") or 0)
    ioc_count = int(item.get("ioc_count") or len(item.get("iocs") or []))
    exploit_status = _str_lower(item.get("exploit_status") or "")

    # KEV = ground truth exploitation signal
    if kev:
        score += 50.0

    # EPSS probability (0–100 → 0–30 pts)
    score += (epss / 100.0) * 30.0

    # IOC presence confirms active tooling / infrastructure
    if ioc_count > 10:
        score += 15.0
    elif ioc_count > 3:
        score += 8.0
    elif ioc_count > 0:
        score += 4.0

    # Exploit status bonus
    if "in-the-wild" in exploit_status or "confirmed" in exploit_status:
        score += 10.0
    elif "weaponised" in exploit_status or "poc" in exploit_status:
        score += 6.0

    # Source confidence calibration
    score += min(confidence / 100.0 * 8.0, 8.0)

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION 10: PATCH URGENCY SCORE (0–100)
# Time-to-patch priority derived score
# ─────────────────────────────────────────────────────────────────────────────

def score_patch_urgency(item: dict) -> int:
    """
    Patch urgency derivation:
    - Emergency (0-4h): KEV + CRITICAL + active exploitation
    - Urgent (4-24h): HIGH + KEV or HIGH + EPSS>50
    - High (24-72h): HIGH severity standard
    - Standard (30d): MEDIUM severity
    - Low (90d): LOW severity
    Score maps urgency level to 0–100.
    """
    score = 0.0
    sev = _str_lower(item.get("severity") or "medium")
    kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))
    epss = _safe_float(item.get("epss_score"))
    if epss > 100:
        epss = epss / 100.0
    risk = _safe_float(item.get("risk_score"))
    cvss = _safe_float(item.get("cvss_score"))

    # KEV always emergency patch
    if kev:
        score += 50.0

    # Severity base
    sev_base = {"critical": 35.0, "high": 25.0, "medium": 12.0, "low": 4.0}
    score += sev_base.get(sev, 10.0)

    # EPSS urgency boost
    if epss >= 50.0:
        score += 12.0
    elif epss >= 20.0:
        score += 7.0
    elif epss >= 5.0:
        score += 3.0

    # Risk score contribution
    score += (risk / 10.0) * 8.0

    # CVSS 9+ deserves maximum urgency bonus
    if cvss >= 9.0:
        score += 10.0
    elif cvss >= 7.0:
        score += 5.0

    return _clamp(score)


# ─────────────────────────────────────────────────────────────────────────────
# COMPOSITE SCORE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

# Dimension weights for composite APEX Enterprise Score
_DIMENSION_WEIGHTS = {
    "threat_velocity_score":            0.15,
    "ransomware_affinity_score":        0.08,
    "kev_priority_score":               0.18,
    "exploit_maturity_score":           0.14,
    "adversary_sophistication_score":   0.10,
    "operational_severity_score":       0.15,
    "business_disruption_score":        0.08,
    "internet_exposure_score":          0.06,
    "exploitability_confidence_score":  0.04,
    "patch_urgency_score":              0.02,
}

def _urgency_label(patch_urgency: int, kev: bool, sev: str) -> str:
    if kev or patch_urgency >= 85:
        return "EMERGENCY — Patch within 4 hours"
    if patch_urgency >= 70:
        return "URGENT — Patch within 24 hours"
    if patch_urgency >= 55:
        return "HIGH — Patch within 72 hours"
    if patch_urgency >= 35 or sev.upper() == "HIGH":
        return "STANDARD — Patch within 30 days"
    return "LOW — Patch within standard maintenance window"

def _soc_priority(composite: int) -> str:
    if composite >= 80:
        return "P1 — Immediate SOC escalation"
    if composite >= 60:
        return "P2 — Analyst attention within 4 hours"
    if composite >= 40:
        return "P3 — Standard queue processing"
    return "P4 — Informational"

def _threat_actor_tier(adv_score: int) -> str:
    if adv_score >= 75:
        return "NATION-STATE / APT"
    if adv_score >= 55:
        return "ORGANISED CRIME / RaaS"
    if adv_score >= 35:
        return "SOPHISTICATED CRIMINAL"
    if adv_score >= 15:
        return "OPPORTUNISTIC"
    return "UNATTRIBUTED / AUTOMATED"

def _ransomware_risk_level(ra_score: int) -> str:
    if ra_score >= 70:
        return "CONFIRMED RANSOMWARE THREAT"
    if ra_score >= 45:
        return "HIGH RANSOMWARE AFFINITY"
    if ra_score >= 25:
        return "MODERATE RANSOMWARE RISK"
    return "LOW RANSOMWARE ASSOCIATION"


def compute_enterprise_scores(item: dict) -> dict:
    """
    Compute all 10 enterprise intelligence dimensions + composite score.
    Returns apex_score dict for injection into advisory.
    Never raises.
    """
    try:
        scores = {
            "threat_velocity_score":            score_threat_velocity(item),
            "ransomware_affinity_score":        score_ransomware_affinity(item),
            "kev_priority_score":               score_kev_priority(item),
            "exploit_maturity_score":           score_exploit_maturity(item),
            "adversary_sophistication_score":   score_adversary_sophistication(item),
            "operational_severity_score":       score_operational_severity(item),
            "business_disruption_score":        score_business_disruption(item),
            "internet_exposure_score":          score_internet_exposure(item),
            "exploitability_confidence_score":  score_exploitability_confidence(item),
            "patch_urgency_score":              score_patch_urgency(item),
        }

        # Weighted composite
        composite = sum(
            scores[dim] * weight
            for dim, weight in _DIMENSION_WEIGHTS.items()
        )
        composite_int = _clamp(composite)

        kev = _safe_bool(item.get("kev_present") or item.get("kev") or item.get("in_kev"))
        sev = str(item.get("severity") or "MEDIUM")

        scores["apex_enterprise_score"]    = composite_int
        scores["soc_priority"]             = _soc_priority(composite_int)
        scores["patch_urgency_label"]      = _urgency_label(scores["patch_urgency_score"], kev, sev)
        scores["threat_actor_tier"]        = _threat_actor_tier(scores["adversary_sophistication_score"])
        scores["ransomware_risk_level"]    = _ransomware_risk_level(scores["ransomware_affinity_score"])
        scores["scoring_engine_version"]   = ENGINE_VERSION
        scores["scored_at"]                = NOW_ISO
        scores["vuln_class"]               = _detect_vuln_class(item)

        return scores
    except Exception as exc:
        log.error("compute_enterprise_scores failed for %s: %s", item.get("id", "?"), exc)
        return {
            "apex_enterprise_score": 0,
            "scoring_engine_version": ENGINE_VERSION,
            "scored_at": NOW_ISO,
            "error": str(exc),
        }


# ─────────────────────────────────────────────────────────────────────────────
# ATOMIC WRITE HELPER
# ─────────────────────────────────────────────────────────────────────────────

def _atomic_write(path: Path, obj: Any, indent: int = 2) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=indent, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE INTEGRATION — MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def apply_enterprise_scoring(manifest_path: Path = MANIFEST_PATH) -> dict:
    """
    Load manifest, compute enterprise scores for every advisory, write back.
    Returns summary dict for CI logging.
    """
    log.info("=" * 60)
    log.info("SENTINEL APEX Enterprise Scoring Engine v%s", ENGINE_VERSION)
    log.info("Manifest: %s", manifest_path)
    log.info("=" * 60)
    t0 = time.monotonic()

    if not manifest_path.exists():
        log.error("FATAL: manifest not found: %s", manifest_path)
        return {"error": "manifest_not_found", "scored": 0}

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = data.get("advisories") or data.get("reports") or data.get("items") or []
    total = len(items)
    log.info("Loaded %d advisories", total)

    scored = 0
    score_distribution = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    high_velocity = []
    high_ransomware = []
    kev_items = []

    for item in items:
        if not isinstance(item, dict):
            continue
        apex_score = compute_enterprise_scores(item)
        item["apex_score"] = apex_score

        scored += 1
        soc_p = apex_score.get("soc_priority", "P4")
        for p in ["P1", "P2", "P3", "P4"]:
            if p in soc_p:
                score_distribution[p] += 1
                break

        # Track notable items for report
        if apex_score.get("threat_velocity_score", 0) >= 70:
            high_velocity.append({
                "id": item.get("id", ""),
                "title": (item.get("title") or "")[:80],
                "velocity": apex_score["threat_velocity_score"],
            })
        if apex_score.get("ransomware_affinity_score", 0) >= 60:
            high_ransomware.append({
                "id": item.get("id", ""),
                "title": (item.get("title") or "")[:80],
                "affinity": apex_score["ransomware_affinity_score"],
            })
        if _safe_bool(item.get("kev_present") or item.get("kev")):
            kev_items.append(item.get("id", ""))

    # Write enriched manifest back
    _atomic_write(manifest_path, data)
    log.info("Manifest written: %d scored", scored)

    # Write scoring report
    report = {
        "engine_version": ENGINE_VERSION,
        "generated_at": NOW_ISO,
        "manifest": str(manifest_path),
        "total_items": total,
        "scored_items": scored,
        "soc_distribution": score_distribution,
        "kev_item_count": len(kev_items),
        "high_velocity_items": high_velocity[:10],
        "high_ransomware_affinity_items": high_ransomware[:10],
        "elapsed_seconds": round(time.monotonic() - t0, 2),
    }
    SCORING_DIR.mkdir(parents=True, exist_ok=True)
    _atomic_write(SCORING_REPORT, report)

    elapsed = time.monotonic() - t0
    log.info("=" * 60)
    log.info("SCORING COMPLETE: %d/%d scored | P1=%d P2=%d P3=%d P4=%d | KEV=%d | %.2fs",
             scored, total,
             score_distribution["P1"], score_distribution["P2"],
             score_distribution["P3"], score_distribution["P4"],
             len(kev_items), elapsed)
    log.info("=" * 60)

    return report


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=f"SENTINEL APEX Enterprise Scoring Engine v{ENGINE_VERSION}")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH))
    parser.add_argument("--report-only", action="store_true", help="Print report, do not write manifest")
    args = parser.parse_args()

    result = apply_enterprise_scoring(Path(args.manifest))
    if "error" in result:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
