#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/apex_threat_actor_risk_signal.py — Threat Actor Intelligence Signal
================================================================================
Version : 162.0.0
Purpose : Provides threat-actor-aware risk signals for non-CVE threat intel
          advisories where CVSS/EPSS/KEV are absent.

PROBLEM SOLVED:
  The legacy risk engine weights CVSS(22%) + EPSS(22%) + KEV(18%) = 62%.
  Non-CVE threat actor campaigns have all three = 0, producing LOW scores
  even for ACTIVE nation-state / FIN group campaigns targeting enterprise.

SOLUTION — THREAT ACTOR INTELLIGENCE SIGNAL SET:
  1. actor_tier_signal       — nation-state / fin / cybercrime / hacktivist
  2. campaign_activity_signal — active / recent / historical
  3. malware_family_signal   — ransomware / wiper / rat / stealer / loader
  4. targeting_precision     — targeted / opportunistic / mass-campaign
  5. ttps_sophistication     — ATT&CK technique depth & persistence
  6. ioc_density_signal      — IOC count as proxy for evidence strength

Combined these replace CVSS+EPSS+KEV weight for non-CVE items ONLY.
================================================================================
"""
from __future__ import annotations

import re
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Tuple, List, Any

log = logging.getLogger("apex.threat_actor_signal")

ENGINE_VERSION = "162.0.0"

# ── Threat Actor Tier Classification ─────────────────────────────────────────
NATION_STATE_PATTERNS = re.compile(
    r"apt\s*\d+|cozy bear|fancy bear|lazarus|equation group|"
    r"sandworm|volt typhoon|salt typhoon|scattered spider|"
    r"charming kitten|muddywater|gamaredon|sidewinder|"
    r"nimbus manticore|ta\d+|unc\d+|g\d{4}|"
    r"nation.?state|state.?sponsored|state.?actor|"
    r"chinese|russian|iranian|north korean|dprk|prc\s+apt|"
    r"intelligence.?agency|military.?hacker|cyber.?espionage",
    re.I
)

FIN_GROUP_PATTERNS = re.compile(
    r"fin\d+|carbanak|cobalt group|silence group|"
    r"ta505|ta4563|ta4338|evil corp|indrik spider|"
    r"financial threat|bank.?heist|swift.?attack|"
    r"carding|bec\s+group|business email compromise",
    re.I
)

RANSOMWARE_GROUP_PATTERNS = re.compile(
    r"lockbit|blackcat|alphv|clop|akira|black basta|play ransomware|"
    r"royal ransomware|rhysida|medusa|hunters international|"
    r"8base|bianlian|darkside|revil|sodinokibi|conti|hive|"
    r"ransomware.?group|ransomware.?gang|ransomware.?affiliate",
    re.I
)

CYBERCRIME_PATTERNS = re.compile(
    r"cybercrime|crimeware|malware-as-a-service|maas|"
    r"initial access broker|iab|dropper.?service|"
    r"botnet|emotet|qakbot|icedid|dridex|trickbot|bumblebee",
    re.I
)

# ── Campaign Activity Signals ─────────────────────────────────────────────────
ACTIVE_CAMPAIGN_PATTERNS = re.compile(
    r"active\s+campaign|ongoing\s+campaign|actively\s+exploit|"
    r"in.the.wild|itw\s+exploit|zero.day\s+exploit|"
    r"under\s+active\s+attack|widespread\s+attack|mass\s+exploit|"
    r"actively\s+targeting|new\s+campaign|emerging\s+threat|"
    r"breaking\s+threat|critical\s+alert|immediate\s+threat",
    re.I
)

RECENT_CAMPAIGN_PATTERNS = re.compile(
    r"recent\s+campaign|new\s+variant|updated\s+malware|"
    r"new\s+attack|fresh\s+campaign|latest\s+attack|"
    r"newly\s+discovered|newly\s+observed",
    re.I
)

# ── Malware Family Severity ────────────────────────────────────────────────────
WIPER_PATTERNS = re.compile(
    r"wiper|destructive|data.?destruction|whispergate|hermeticwiper|"
    r"industroyer|crashoverride|notpetya",
    re.I
)

RAT_BACKDOOR_PATTERNS = re.compile(
    r"\brat\b|remote\s+access\s+trojan|backdoor|c2\s+implant|"
    r"command\s+and\s+control|c&c\s+server|cobalt strike|"
    r"metasploit|sliver\s+c2|havoc\s+c2|brute\s+ratel",
    re.I
)

STEALER_PATTERNS = re.compile(
    r"infostealer|credential\s+stealer|password\s+stealer|"
    r"redline|racoon|vidar|lumma|azorult|formbook",
    re.I
)

LOADER_DOWNLOADER_PATTERNS = re.compile(
    r"\bloader\b|downloader|dropper|stager|malware.?loader|"
    r"fake\s+installer|trojanized",
    re.I
)

# ── ATT&CK Sophistication Tiers ───────────────────────────────────────────────
HIGH_SOPHISTICATION_TACTICS = {
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0010",  # Exfiltration
    "TA0011",  # Command and Control
    "TA0040",  # Impact
}

PERSISTENCE_TECHNIQUES = re.compile(
    r"T1053|T1543|T1547|T1078|T1136|T1197|T1037|T1574|"
    r"scheduled.?task|startup|boot.*persistence|registry.*run",
    re.I
)

PRIVILEGE_ESCALATION_TECHNIQUES = re.compile(
    r"T1055|T1068|T1134|T1484|T1548|T1611|"
    r"privilege.*escalat|process.*inject|token.*imperson",
    re.I
)

LATERAL_MOVEMENT_TECHNIQUES = re.compile(
    r"T1021|T1550|T1563|T1570|"
    r"lateral.*movement|smb.*spread|wmi.*exec|pass.the.hash",
    re.I
)

# ── Vulnerability Type Severity Signals ──────────────────────────────────────
# For CVE-tagged items without CVSS, infer severity from vulnerability class
RCE_PATTERNS = re.compile(
    r"remote.?code.?execution|rce\b|arbitrary.?code|"
    r"code.?execution|command.?injection|os.?command.?injection",
    re.I
)
CRITICAL_VULN_PATTERNS = re.compile(
    r"heap.?buffer.?overflow|stack.?buffer.?overflow|"
    r"use.after.free|type.?confusion|zero.?day|0.?day|"
    r"unauthenticated.?rce|pre.?auth.?rce|wormable|"
    r"critical.*vulnerability|severity.?critical",
    re.I
)
HIGH_VULN_PATTERNS = re.compile(
    r"sql.?injection|sqli\b|xxe\b|ssrf\b|deserialization|"
    r"privilege.?escalation|auth.?bypass|authentication.?bypass|"
    r"path.?traversal|directory.?traversal|buffer.?overflow|"
    r"memory.?corruption|format.?string|integer.?overflow",
    re.I
)
RANSOMWARE_CAMPAIGN_PATTERNS = re.compile(
    r"CDB-UNATTR-RAN|CDB-RAN|ransomware.?campaign|"
    r"ransomware.?attack|encrypted.*files|ransom.?note|"
    r"extortion.?campaign|double.?extortion",
    re.I
)

def extract_vulnerability_severity_signal(item: Dict) -> Tuple[float, str]:
    """
    Returns (0.0-1.0, evidence) based on vulnerability class.
    Used when CVSS is absent but CVE type can be inferred from text.
    """
    all_text = _build_text(item)
    title = str(item.get("title") or "")
    actor_tag = str(item.get("actor_tag") or "")

    if CRITICAL_VULN_PATTERNS.search(all_text):
        return 0.95, "VulnClass=CRITICAL (heap overflow/UAF/0day/wormable detected)"
    if RCE_PATTERNS.search(all_text):
        return 0.88, "VulnClass=RCE (remote code execution vulnerability detected)"
    if RANSOMWARE_CAMPAIGN_PATTERNS.search(actor_tag + " " + all_text):
        return 0.85, f"VulnClass=RANSOMWARE_CAMPAIGN (actor_tag={actor_tag})"
    if HIGH_VULN_PATTERNS.search(all_text):
        return 0.75, "VulnClass=HIGH (SQLi/SSRF/auth-bypass/privesc detected)"
    if re.search(r"CDB-UNATTR-CVE", actor_tag, re.I):
        # Generic CVE with no type info — moderate baseline
        return 0.55, f"VulnClass=CVE_GENERIC (actor_tag={actor_tag}, type unknown)"

    return 0.25, "VulnClass=UNCLASSIFIED"


# ══════════════════════════════════════════════════════════════════════════════
# Signal Extraction Functions
# ══════════════════════════════════════════════════════════════════════════════

def extract_actor_tier_signal(item: Dict) -> Tuple[float, str]:
    """
    Returns (0.0-1.0, evidence_string).
    Nation-state = 0.95, FIN = 0.85, Ransomware Gang = 0.80,
    Cybercrime = 0.65, Unknown = 0.35
    """
    all_text = _build_text(item)

    if NATION_STATE_PATTERNS.search(all_text):
        return 0.95, "ActorTier=NATION_STATE (APT/state-sponsored indicators detected)"
    if FIN_GROUP_PATTERNS.search(all_text):
        return 0.85, "ActorTier=FIN_GROUP (financially motivated threat actor detected)"
    if RANSOMWARE_GROUP_PATTERNS.search(all_text):
        return 0.80, "ActorTier=RANSOMWARE_GANG (named ransomware operation detected)"
    if CYBERCRIME_PATTERNS.search(all_text):
        return 0.65, "ActorTier=CYBERCRIME (crimeware ecosystem indicators)"

    # Check actor_tag pattern (CDB-NAT = nation-state, CDB-FIN = financial etc.)
    actor_tag = str(item.get("actor_tag") or item.get("actor_cluster") or "")
    if re.search(r"CDB-NAT|APT|STATE", actor_tag, re.I):
        return 0.90, f"ActorTier=NATION_STATE (actor_tag={actor_tag})"
    if re.search(r"CDB-FIN", actor_tag, re.I):
        return 0.85, f"ActorTier=FIN_GROUP (actor_tag={actor_tag})"
    if re.search(r"CDB-RAN|RANSOM", actor_tag, re.I):
        return 0.80, f"ActorTier=RANSOMWARE (actor_tag={actor_tag})"
    if re.search(r"CDB-", actor_tag, re.I):
        return 0.60, f"ActorTier=TRACKED_ACTOR (actor_tag={actor_tag})"

    return 0.35, "ActorTier=UNKNOWN (no actor classification signals)"


def extract_campaign_activity_signal(item: Dict) -> Tuple[float, str]:
    """
    Returns (0.0-1.0, evidence_string).
    Active = 0.95, Recent = 0.70, Historical = 0.30
    """
    all_text = _build_text(item)

    if ACTIVE_CAMPAIGN_PATTERNS.search(all_text):
        return 0.95, "CampaignActivity=ACTIVE (active exploitation/campaign indicators)"
    if RECENT_CAMPAIGN_PATTERNS.search(all_text):
        return 0.70, "CampaignActivity=RECENT (new/updated campaign within reporting period)"

    # Check publication freshness
    published = item.get("published_at") or item.get("timestamp") or ""
    if published:
        try:
            from datetime import timedelta
            pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            age_days = (now - pub_dt).days
            if age_days <= 3:
                return 0.85, f"CampaignActivity=FRESH (published {age_days}d ago)"
            elif age_days <= 14:
                return 0.60, f"CampaignActivity=RECENT (published {age_days}d ago)"
        except Exception:
            pass

    return 0.30, "CampaignActivity=HISTORICAL (no active campaign signals)"


def extract_malware_family_signal(item: Dict) -> Tuple[float, str]:
    """
    Returns (0.0-1.0, evidence_string).
    Wiper = 1.0, RAT/Backdoor = 0.85, Ransomware payload = 0.80,
    Stealer = 0.70, Loader = 0.60, Generic malware = 0.50
    """
    all_text = _build_text(item)
    threat_type = str(item.get("threat_type") or "").upper()

    if WIPER_PATTERNS.search(all_text):
        return 1.0, "MalwareFamily=WIPER (destructive/wiper malware detected)"
    if RANSOMWARE_GROUP_PATTERNS.search(all_text) or "RANSOM" in threat_type:
        return 0.80, "MalwareFamily=RANSOMWARE (ransomware payload indicators)"
    if RAT_BACKDOOR_PATTERNS.search(all_text):
        return 0.85, "MalwareFamily=RAT_BACKDOOR (remote access / implant detected)"
    if STEALER_PATTERNS.search(all_text):
        return 0.70, "MalwareFamily=INFOSTEALER (credential/data theft malware)"
    if LOADER_DOWNLOADER_PATTERNS.search(all_text):
        return 0.60, "MalwareFamily=LOADER (malware loader/dropper detected)"
    if "MALWARE" in threat_type or "TROJAN" in threat_type:
        return 0.50, f"MalwareFamily=GENERIC_MALWARE (threat_type={threat_type})"

    return 0.25, "MalwareFamily=NOT_DETECTED (no malware family signals)"


def extract_ttps_sophistication_signal(item: Dict) -> Tuple[float, str]:
    """
    Returns (0.0-1.0, evidence_string).
    Based on ATT&CK tactic breadth and technique depth.
    """
    all_text = _build_text(item)

    # Count unique tactic phases present
    tactics = item.get("mitre_tactics") or item.get("ttps") or []
    tactic_ids = set()

    for t in tactics:
        if isinstance(t, dict):
            tid = t.get("tactic_id") or t.get("id") or ""
            tactic_ids.add(tid)

    # Also check text for tactic patterns
    tactic_count = len(tactic_ids)

    # Check for advanced technique patterns
    has_persistence = bool(PERSISTENCE_TECHNIQUES.search(all_text))
    has_privesc = bool(PRIVILEGE_ESCALATION_TECHNIQUES.search(all_text))
    has_lateral = bool(LATERAL_MOVEMENT_TECHNIQUES.search(all_text))

    sophistication_indicators = sum([has_persistence, has_privesc, has_lateral])

    if tactic_count >= 4 or sophistication_indicators >= 3:
        return 0.90, f"TTPsSophistication=HIGH ({tactic_count} tactics, {sophistication_indicators} adv techniques)"
    elif tactic_count >= 2 or sophistication_indicators >= 2:
        return 0.65, f"TTPsSophistication=MEDIUM ({tactic_count} tactics, {sophistication_indicators} adv techniques)"
    elif tactic_count >= 1 or sophistication_indicators >= 1:
        return 0.40, f"TTPsSophistication=LOW ({tactic_count} tactics mapped)"

    return 0.15, "TTPsSophistication=MINIMAL (no ATT&CK mapping detected)"


def extract_ioc_density_signal(item: Dict) -> Tuple[float, str]:
    """
    Returns (0.0-1.0, evidence_string).
    IOC density as proxy for evidence quality.
    """
    iocs = item.get("iocs") or []
    ioc_count = len(iocs) if isinstance(iocs, list) else 0

    # Also check ioc_counts dict
    ioc_counts = item.get("ioc_counts") or item.get("iocs_by_type") or {}
    if isinstance(ioc_counts, dict):
        ioc_count = max(ioc_count, sum(v for v in ioc_counts.values() if isinstance(v, int)))

    # Check indicator_count field
    ind_count = item.get("indicator_count") or item.get("ioc_count") or 0
    ioc_count = max(ioc_count, int(ind_count) if str(ind_count).isdigit() else 0)

    if ioc_count >= 20:
        return 0.95, f"IOCDensity=VERY_HIGH ({ioc_count} IOCs — strong evidence basis)"
    elif ioc_count >= 10:
        return 0.80, f"IOCDensity=HIGH ({ioc_count} IOCs)"
    elif ioc_count >= 5:
        return 0.65, f"IOCDensity=MEDIUM ({ioc_count} IOCs)"
    elif ioc_count >= 1:
        return 0.40, f"IOCDensity=LOW ({ioc_count} IOCs — limited evidence)"

    return 0.10, "IOCDensity=NONE (no operational IOCs attached)"


def extract_targeting_precision_signal(item: Dict) -> Tuple[float, str]:
    """
    Returns (0.0-1.0, evidence_string).
    Targeted = 0.85, Multi-sector = 0.65, Opportunistic = 0.45
    """
    all_text = _build_text(item)

    if re.search(r"targeted\s+attack|spearphish|highly\s+targeted|"
                 r"specific\s+sector|critical\s+infrastructure\s+target|"
                 r"supply\s+chain\s+attack|watering\s+hole", all_text, re.I):
        return 0.85, "TargetingPrecision=TARGETED (spearphishing/targeted attack indicators)"

    if re.search(r"multiple\s+sector|cross.?sector|global\s+campaign|"
                 r"widespread|multiple\s+industries", all_text, re.I):
        return 0.65, "TargetingPrecision=MULTI_SECTOR (broad targeting campaign)"

    return 0.45, "TargetingPrecision=OPPORTUNISTIC (no precision targeting signals)"


# ══════════════════════════════════════════════════════════════════════════════
# Primary Interface
# ══════════════════════════════════════════════════════════════════════════════

# Weights for threat-actor-based scoring (sum = 1.0)
TA_WEIGHTS = {
    "actor_tier":           0.22,   # Who is the actor?
    "campaign_activity":    0.22,   # How active is this right now?
    "vuln_severity":        0.22,   # Vulnerability class (RCE/0day/etc.)
    "malware_family":       0.16,   # What capability is deployed?
    "ttps_sophistication":  0.10,   # How sophisticated?
    "ioc_density":          0.05,   # How well evidenced?
    "targeting_precision":  0.03,   # How targeted?
}
assert abs(sum(TA_WEIGHTS.values()) - 1.0) < 1e-9


def compute_threat_actor_risk_score(item: Dict) -> Dict:
    """
    Compute threat-actor-intelligence-based risk score for items WITHOUT
    CVSS/EPSS/KEV signals (i.e., non-CVE threat intel advisories).

    Returns dict with:
      ta_risk_score: float (0.0–10.0)
      ta_risk_label: CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL
      ta_risk_evidence: detailed signal breakdown
    """
    actor_val,    actor_ev    = extract_actor_tier_signal(item)
    campaign_val, campaign_ev = extract_campaign_activity_signal(item)
    vuln_val,     vuln_ev     = extract_vulnerability_severity_signal(item)
    malware_val,  malware_ev  = extract_malware_family_signal(item)
    ttps_val,     ttps_ev     = extract_ttps_sophistication_signal(item)
    ioc_val,      ioc_ev      = extract_ioc_density_signal(item)
    target_val,   target_ev   = extract_targeting_precision_signal(item)

    raw_vals = {
        "actor_tier":          actor_val,
        "campaign_activity":   campaign_val,
        "vuln_severity":       vuln_val,
        "malware_family":      malware_val,
        "ttps_sophistication": ttps_val,
        "ioc_density":         ioc_val,
        "targeting_precision": target_val,
    }

    weighted_sum = sum(TA_WEIGHTS[sig] * raw_vals[sig] for sig in TA_WEIGHTS)
    ta_risk = round(min(10.0, max(0.0, weighted_sum * 10.0)), 2)

    # Severity label (TA-specific thresholds — lower ceiling than CVSS-backed scoring)
    # TA max ~8.5 for nation-state+wiper+active+targeted; CVSS max = 10.0+KEV
    # Thresholds calibrated so FIN-actor active campaigns = HIGH, nation-state = CRITICAL
    if ta_risk >= 7.5:
        label = "CRITICAL"
        urgency = "IMMEDIATE — nation-state/destructive actor with active campaign"
    elif ta_risk >= 5.5:
        label = "HIGH"
        urgency = "PRIORITY — active threat actor campaign; analyst review within 4 hours"
    elif ta_risk >= 3.5:
        label = "MEDIUM"
        urgency = "STANDARD — tracked actor activity; respond per playbook within 24 hours"
    elif ta_risk >= 2.0:
        label = "LOW"
        urgency = "MONITORED — lower-tier actor or historical campaign; 7-day review cycle"
    else:
        label = "INFORMATIONAL"
        urgency = "INFORMATIONAL — minimal indicators; situational awareness only"

    evidence_block = {}
    for sig, w in TA_WEIGHTS.items():
        evidence_block[sig] = {
            "raw_value":    raw_vals[sig],
            "weight":       w,
            "contribution": round(w * raw_vals[sig] * 10.0, 3),
            "evidence":     {
                "actor_tier":          actor_ev,
                "campaign_activity":   campaign_ev,
                "vuln_severity":       vuln_ev,
                "malware_family":      malware_ev,
                "ttps_sophistication": ttps_ev,
                "ioc_density":         ioc_ev,
                "targeting_precision": target_ev,
            }[sig],
        }

    return {
        "ta_risk_score":    ta_risk,
        "ta_risk_label":    label,
        "ta_risk_urgency":  urgency,
        "ta_risk_evidence": evidence_block,
        "ta_engine_version": ENGINE_VERSION,
    }


def should_use_ta_scoring(item: dict) -> bool:
    """Returns True if threat-actor scoring should be used for this item."""
    cvss  = item.get("cvss_score")
    epss  = item.get("epss_score")
    kev   = item.get("kev_present", False)
    cves  = item.get("cve_ids") or []
    has_cve_signal = (
        (cvss is not None and float(cvss or 0) > 0) or
        (epss is not None and float(epss or 0) > 0) or
        kev or
        (isinstance(cves, list) and len(cves) > 0)
    )
    return not has_cve_signal


def _build_text(item: dict) -> str:
    """Build composite text for pattern matching."""
    return " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "threat_type",
        "actor_tag", "actor_cluster", "malware_family",
        "campaign", "tags", "source",
    ))


if __name__ == "__main__":
    test_items = [
        {
            "title": "Nimbus Manticore Expanded Attacks With AI-Assisted Malware and Fake Zoom Installers",
            "threat_type": "Malware",
            "actor_tag": "CDB-FIN-09",
            "mitre_tactics": [{"id": "T1566", "tactic": "Initial Access"}],
            "cvss_score": None, "epss_score": None, "kev_present": False,
            "published_at": "2026-05-26T09:09:17Z",
        },
        {
            "title": "gimp: GIMP: Remote Code Execution via PSP file parsing",
            "threat_type": "Vulnerability",
            "actor_tag": "CDB-UNATTR-CVE",
            "cvss_score": None, "epss_score": None, "kev_present": False,
            "published_at": "2026-05-26T09:09:17Z",
        },
        {
            "title": "LockBit 4.0 ransomware campaign encrypts healthcare provider",
            "threat_type": "Ransomware",
            "actor_tag": "CDB-UNATTR-RAN",
            "cvss_score": None, "epss_score": None, "kev_present": False,
            "published_at": "2026-05-26T09:09:17Z",
        },
    ]
    for item in test_items:
        result = compute_threat_actor_risk_score(item)
        print(f"[{result['ta_risk_label']:12s}] {result['ta_risk_score']:5.2f} | {item['title'][:60]}")
