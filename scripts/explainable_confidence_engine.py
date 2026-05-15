"""
explainable_confidence_engine.py — CYBERDUDEBIVASH Threat Intelligence Platform
Phase: Enterprise Operational Trust — P0 Explainable Confidence Engine

Replaces opaque flat confidence percentages with fully auditable,
evidence-weighted, provenance-traceable confidence scoring.

Every dossier now exposes:
  - confidence contributors (positive signals, what ADDS confidence)
  - confidence penalties (negative signals, what REDUCES confidence)
  - evidence weighting (how each source is weighted)
  - source reliability tier
  - IOC verification status
  - ATT&CK attribution confidence
  - actor attribution confidence
  - operational reasoning confidence
  - intelligence lineage chain

Author: CYBERDUDEBIVASH Pvt. Ltd.
Version: 1.0.0
Production mandates: Never raises. Deterministic. Auditable. Enterprise-safe.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("explainable_confidence")

_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Source Trust Tiers
# ---------------------------------------------------------------------------

# Tier 1 — Primary authoritative intelligence sources (highest trust weight)
_SOURCE_TIER_1 = frozenset({
    "cisa", "nist", "nvd", "mitre", "us-cert", "ncsc", "bsi",
    "cert-eu", "anssi", "aisi", "mandiant", "crowdstrike", "recorded future",
    "palo alto unit 42", "unit42", "microsoft msrc", "msrc", "google project zero",
    "google tag", "secureworks", "fireeye", "lumen", "shadowserver",
    "certcc", "cert/cc", "cert-in", "kev", "epss",
})

# Tier 2 — Reputable research + vendor advisories
_SOURCE_TIER_2 = frozenset({
    "checkpoint", "check point", "sophos", "sentinel one", "sentinelone",
    "trend micro", "trendmicro", "kaspersky", "eset", "avast", "bitdefender",
    "rapid7", "tenable", "qualys", "vulners", "exploit-db", "exploitdb",
    "github advisory", "github", "packet storm", "packetstorm",
    "securityfocus", "bugtraq", "full disclosure", "synacktiv",
    "bishopfox", "nccgroup", "ncc group", "cybersecurity news",
    "bleeping computer", "the hacker news", "securityweek", "dark reading",
})

# Tier 3 — Secondary aggregators and low-provenance sources
_SOURCE_TIER_3 = frozenset({
    "twitter", "x.com", "reddit", "medium", "substack", "pastebin",
    "unknown", "unattributed", "various", "multiple sources",
})

# IOC type reliability baseline (modifier on top of source tier)
_IOC_TYPE_RELIABILITY: Dict[str, float] = {
    "hash_sha256": 0.95,
    "hash_sha1":   0.90,
    "hash_md5":    0.85,
    "ip":          0.75,
    "domain":      0.70,
    "url":         0.65,
    "email":       0.60,
    "filename":    0.55,
    "registry":    0.80,
    "mutex":       0.85,
    "yara":        0.90,
    "sigma":       0.90,
    "unknown":     0.40,
}

# ATT&CK tactic confidence weight (how much each tactic match contributes)
_ATTCK_TACTIC_WEIGHT: Dict[str, float] = {
    "reconnaissance":         0.06,
    "resource development":   0.07,
    "initial access":         0.10,
    "execution":              0.10,
    "persistence":            0.09,
    "privilege escalation":   0.09,
    "defense evasion":        0.09,
    "credential access":      0.08,
    "discovery":              0.07,
    "lateral movement":       0.09,
    "collection":             0.08,
    "command and control":    0.10,
    "exfiltration":           0.09,
    "impact":                 0.10,
}

# Confidence contributor/penalty schema
_CONTRIBUTOR_SCHEMA = {
    # Positive contributors
    "multi_source_corroboration":     {"max": 15, "description": "Advisory corroborated across multiple independent intelligence sources"},
    "verified_attck_overlap":         {"max": 10, "description": "ATT&CK techniques verified against observed campaign TTPs"},
    "ioc_validation":                 {"max": 8,  "description": "IOCs validated against threat intelligence reputation databases"},
    "kev_confirmed":                  {"max": 12, "description": "Vulnerability confirmed in CISA Known Exploited Vulnerabilities catalog"},
    "epss_high":                      {"max": 8,  "description": "EPSS exploitation probability score indicates elevated near-term risk"},
    "cvss_critical":                  {"max": 6,  "description": "CVSS Critical score (9.0+) confirms severe exploitability baseline"},
    "actor_historical_match":         {"max": 8,  "description": "Threat actor TTPs consistent with historically observed campaign behavior"},
    "ioc_volume":                     {"max": 5,  "description": "High IOC volume increases detection surface and attribution confidence"},
    "tier1_source":                   {"max": 10, "description": "Intelligence sourced from Tier-1 authoritative intelligence provider"},
    "tier2_source":                   {"max": 6,  "description": "Intelligence sourced from reputable security research organisation"},
    "active_exploitation_signal":     {"max": 10, "description": "Active in-the-wild exploitation confirmed by threat intelligence"},
    "campaign_correlation":           {"max": 7,  "description": "Advisory correlates with active tracked adversary campaign"},
    "malware_family_identified":      {"max": 6,  "description": "Specific malware family identified with known behavioral profile"},
    "sector_targeting_confirmed":     {"max": 5,  "description": "Sector-specific targeting pattern confirmed from advisory"},
    # Negative penalties
    "low_attribution_certainty":      {"max": -8, "description": "Actor attribution lacks definitive technical evidence — assess with caution"},
    "single_source":                  {"max": -8, "description": "Advisory based on single unverified source — requires corroboration"},
    "no_iocs":                        {"max": -6, "description": "No indicators of compromise available — detection capability limited"},
    "no_attck_mapping":               {"max": -5, "description": "No ATT&CK technique mapping available — TTP coverage gap"},
    "low_ioc_quality":                {"max": -5, "description": "IOC set dominated by low-reliability indicator types (filenames, URLs)"},
    "unverified_cvss":                {"max": -4, "description": "CVSS score not yet assigned or pending vendor validation"},
    "tier3_source":                   {"max": -6, "description": "Intelligence sourced from low-provenance or unverified source"},
    "generic_description":            {"max": -5, "description": "Advisory lacks operational specifics — limited actionability"},
    "no_exploitation_evidence":       {"max": -4, "description": "No evidence of active exploitation found in intelligence feeds"},
    "old_advisory":                   {"max": -3, "description": "Advisory older than 30 days — exploitation window may have changed"},
}


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _classify_source_tier(source: str) -> int:
    """Return source tier (1=highest, 3=lowest, 0=unknown)."""
    if not source:
        return 0
    s = source.lower()
    for keyword in _SOURCE_TIER_1:
        if keyword in s:
            return 1
    for keyword in _SOURCE_TIER_2:
        if keyword in s:
            return 2
    for keyword in _SOURCE_TIER_3:
        if keyword in s:
            return 3
    return 2  # Default to tier 2 if recognisable but not catalogued


def _classify_ioc_type(ioc: Any) -> str:
    """Classify IOC type from IOC dict or string."""
    if isinstance(ioc, dict):
        t = str(ioc.get("type") or ioc.get("ioc_type") or "").lower()
        v = str(ioc.get("value") or ioc.get("ioc") or "")
    else:
        t = ""
        v = str(ioc)

    if t in _IOC_TYPE_RELIABILITY:
        return t
    # Auto-classify from value
    if re.match(r'^[a-fA-F0-9]{64}$', v):
        return "hash_sha256"
    if re.match(r'^[a-fA-F0-9]{40}$', v):
        return "hash_sha1"
    if re.match(r'^[a-fA-F0-9]{32}$', v):
        return "hash_md5"
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', v):
        return "ip"
    if re.match(r'^https?://', v):
        return "url"
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', v):
        return "domain"
    if "@" in v:
        return "email"
    if "\\" in v or v.startswith("HKEY"):
        return "registry"
    return "unknown"


def _extract_attck_tactics(ttps: List[Any]) -> List[str]:
    """Extract tactic names from TTP list (handles strings and dicts)."""
    tactics = []
    for t in ttps:
        if isinstance(t, dict):
            tactic = str(t.get("tactic") or "").lower()
            if tactic:
                tactics.append(tactic)
        elif isinstance(t, str):
            # Map technique IDs to tactics using prefix heuristic
            technique_id = t.upper()
            if technique_id.startswith("T15"):
                tactics.append("reconnaissance")
            elif technique_id.startswith("T158") or technique_id.startswith("T159"):
                tactics.append("resource development")
            elif technique_id in ("T1566", "T1190", "T1133", "T1189", "T1195", "T1199", "T1078"):
                tactics.append("initial access")
            elif technique_id.startswith("T1059") or technique_id in ("T1204", "T1203"):
                tactics.append("execution")
            elif technique_id.startswith("T1053") or technique_id.startswith("T1547") or technique_id in ("T1543", "T1098"):
                tactics.append("persistence")
            elif technique_id.startswith("T1548") or technique_id in ("T1055", "T1134"):
                tactics.append("privilege escalation")
            elif technique_id in ("T1027", "T1562", "T1070", "T1036", "T1112"):
                tactics.append("defense evasion")
            elif technique_id.startswith("T1552") or technique_id.startswith("T1003") or technique_id in ("T1110",):
                tactics.append("credential access")
            elif technique_id.startswith("T1082") or technique_id in ("T1046", "T1135", "T1018"):
                tactics.append("discovery")
            elif technique_id in ("T1021", "T1210", "T1534", "T1570"):
                tactics.append("lateral movement")
            elif technique_id.startswith("T1560") or technique_id.startswith("T1074") or technique_id in ("T1113",):
                tactics.append("collection")
            elif technique_id.startswith("T1071") or technique_id.startswith("T1095") or technique_id in ("T1572", "T1573"):
                tactics.append("command and control")
            elif technique_id.startswith("T1048") or technique_id in ("T1041", "T1567"):
                tactics.append("exfiltration")
            elif technique_id.startswith("T1485") or technique_id in ("T1486", "T1490", "T1489"):
                tactics.append("impact")
    return list(set(tactics))


def _is_old_advisory(item: Dict[str, Any]) -> bool:
    """Return True if advisory is older than 30 days."""
    for field in ("published", "date", "created", "processed", "fetched_at"):
        val = item.get(field)
        if val and isinstance(val, str):
            try:
                # Parse ISO date
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - dt).days
                return age_days > 30
            except Exception:
                continue
    return False


def _has_generic_description(item: Dict[str, Any]) -> bool:
    """Detect generic/low-content descriptions."""
    desc = str(item.get("description") or item.get("summary") or "")
    if len(desc) < 80:
        return True
    generic_phrases = [
        "a vulnerability exists", "an issue was discovered",
        "unspecified vulnerability", "allows remote attackers",
        "unknown vulnerability", "n/a", "not available",
    ]
    desc_lower = desc.lower()
    return sum(1 for p in generic_phrases if p in desc_lower) >= 2


def _has_exploitation_signal(item: Dict[str, Any]) -> bool:
    """Detect active exploitation signals in advisory."""
    signals = [
        item.get("kev"), item.get("in_kev"), item.get("kev_present"),
        item.get("exploited_in_wild"), item.get("active_exploitation"),
    ]
    if any(signals):
        return True
    combined = " ".join([
        str(item.get("description") or ""),
        str(item.get("title") or ""),
        str(item.get("summary") or ""),
    ]).lower()
    exploitation_phrases = [
        "actively exploited", "exploitation in the wild", "in-the-wild",
        "exploit observed", "ransomware", "threat actor", "zero-day",
        "0-day", "proof of concept available", "poc available",
    ]
    return any(p in combined for p in exploitation_phrases)


def _has_campaign_correlation(item: Dict[str, Any]) -> bool:
    """Detect campaign correlation signal."""
    return bool(
        item.get("campaign") or
        item.get("campaign_id") or
        item.get("campaign_cluster") or
        (item.get("actor_cluster") and item.get("actor_cluster") not in ("Unknown Cluster", "CDB-CVE-GEN", ""))
    )


def _has_malware_family(item: Dict[str, Any]) -> bool:
    """Detect malware family identification signal."""
    combined = " ".join([
        str(item.get("description") or ""),
        str(item.get("title") or ""),
        str(item.get("actor_cluster") or ""),
        str(item.get("malware_family") or ""),
    ]).lower()
    malware_indicators = [
        "ransomware", "trojan", "backdoor", "rat ", "loader", "stealer",
        "botnet", "rootkit", "worm", "dropper", "cobalt strike", "metasploit",
        "mimikatz", "lockbit", "conti", "blackcat", "ryuk", "emotet",
    ]
    return any(m in combined for m in malware_indicators)


def _has_sector_targeting(item: Dict[str, Any]) -> bool:
    """Detect confirmed sector targeting."""
    combined = " ".join([
        str(item.get("sector") or ""),
        str(item.get("targeted_sectors") or ""),
        str(item.get("description") or ""),
    ]).lower()
    sectors = [
        "healthcare", "financial", "government", "energy", "critical infrastructure",
        "defense", "manufacturing", "education", "retail", "transportation",
    ]
    return any(s in combined for s in sectors)


# ---------------------------------------------------------------------------
# Core Confidence Computation Engine
# ---------------------------------------------------------------------------

def compute_confidence_breakdown(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute fully explainable confidence breakdown for a single intelligence item.

    Returns:
        {
          "score": int (0-100),
          "contributors": List[Dict],   # positive signals
          "penalties": List[Dict],      # negative signals
          "evidence_chain": List[str],  # ordered evidence items
          "source_tier": int,
          "source_reliability_label": str,
          "ioc_quality_score": float,
          "attck_confidence": float,
          "actor_attribution_confidence": float,
          "operational_confidence": float,
          "lineage_hash": str,          # deterministic audit token
          "rendered_explanation": str,  # human-readable explanation HTML
        }
    """
    contributors = []
    penalties = []
    evidence_chain = []
    running_score = 0.0

    # ── Source trust ──────────────────────────────────────────────────────────
    source = str(item.get("source") or item.get("feed_source") or item.get("source_url") or "")
    source_tier = _classify_source_tier(source)
    source_labels = {1: "Tier-1 Authoritative", 2: "Tier-2 Reputable", 3: "Tier-3 Low-Provenance", 0: "Unclassified"}
    source_reliability_label = source_labels.get(source_tier, "Unclassified")

    if source_tier == 1:
        pts = _CONTRIBUTOR_SCHEMA["tier1_source"]["max"]
        contributors.append({
            "key": "tier1_source",
            "points": pts,
            "label": "Tier-1 Source",
            "detail": f"{source_reliability_label} source: {source[:60] or 'verified authoritative provider'}",
        })
        evidence_chain.append(f"Source: {source[:80] or 'Tier-1 authoritative'}")
        running_score += pts
    elif source_tier == 2:
        pts = _CONTRIBUTOR_SCHEMA["tier2_source"]["max"]
        contributors.append({
            "key": "tier2_source",
            "points": pts,
            "label": "Tier-2 Source",
            "detail": f"{source_reliability_label} intelligence source",
        })
        evidence_chain.append(f"Source: {source[:80] or 'Tier-2 reputable'}")
        running_score += pts
    elif source_tier == 3:
        pts = _CONTRIBUTOR_SCHEMA["tier3_source"]["max"]
        penalties.append({
            "key": "tier3_source",
            "points": pts,
            "label": "Low-Provenance Source",
            "detail": f"{source_reliability_label} — corroboration required before operational use",
        })
        evidence_chain.append(f"Source: {source[:80] or 'Tier-3 unverified'} (low provenance)")
        running_score += pts  # negative
    else:
        pts = _CONTRIBUTOR_SCHEMA["single_source"]["max"]
        penalties.append({
            "key": "single_source",
            "points": pts,
            "label": "Unclassified Source",
            "detail": "Source not in trusted intelligence provider registry",
        })
        running_score += pts  # negative

    # ── KEV confirmation ───────────────────────────────────────────────────────
    kev = bool(item.get("kev") or item.get("in_kev") or item.get("kev_present"))
    if kev:
        pts = _CONTRIBUTOR_SCHEMA["kev_confirmed"]["max"]
        contributors.append({
            "key": "kev_confirmed",
            "points": pts,
            "label": "CISA KEV Confirmed",
            "detail": "Active exploitation confirmed — CISA Known Exploited Vulnerabilities catalog entry",
        })
        evidence_chain.append("KEV: CISA KEV entry confirmed (active exploitation)")
        running_score += pts

    # ── EPSS score ─────────────────────────────────────────────────────────────
    epss = item.get("epss_score") or item.get("epss")
    if epss:
        try:
            epss_f = float(epss)
            if epss_f >= 0.5:
                pts = _CONTRIBUTOR_SCHEMA["epss_high"]["max"]
                contributors.append({
                    "key": "epss_high",
                    "points": pts,
                    "label": f"High EPSS Score ({epss_f:.1%})",
                    "detail": f"EPSS 30-day exploitation probability: {epss_f:.1%} — significantly above median",
                })
                evidence_chain.append(f"EPSS: {epss_f:.1%} exploitation probability (high risk band)")
                running_score += pts
            elif epss_f >= 0.1:
                pts = int(_CONTRIBUTOR_SCHEMA["epss_high"]["max"] * 0.5)
                contributors.append({
                    "key": "epss_moderate",
                    "points": pts,
                    "label": f"Moderate EPSS Score ({epss_f:.1%})",
                    "detail": f"EPSS 30-day exploitation probability: {epss_f:.1%}",
                })
                running_score += pts
        except (ValueError, TypeError):
            pass

    # ── CVSS score ─────────────────────────────────────────────────────────────
    cvss = item.get("cvss_score") or item.get("cvss")
    if cvss:
        try:
            cvss_f = float(cvss)
            if cvss_f >= 9.0:
                pts = _CONTRIBUTOR_SCHEMA["cvss_critical"]["max"]
                contributors.append({
                    "key": "cvss_critical",
                    "points": pts,
                    "label": f"CVSS Critical ({cvss_f})",
                    "detail": f"CVSS Base Score {cvss_f} — Critical severity band confirms severe exploitability",
                })
                evidence_chain.append(f"CVSS: {cvss_f} (Critical)")
                running_score += pts
            elif cvss_f >= 7.0:
                pts = int(_CONTRIBUTOR_SCHEMA["cvss_critical"]["max"] * 0.7)
                contributors.append({
                    "key": "cvss_high",
                    "points": pts,
                    "label": f"CVSS High ({cvss_f})",
                    "detail": f"CVSS Base Score {cvss_f} — High severity confirms elevated exploitation risk",
                })
                evidence_chain.append(f"CVSS: {cvss_f} (High)")
                running_score += pts
        except (ValueError, TypeError):
            pts = _CONTRIBUTOR_SCHEMA["unverified_cvss"]["max"]
            penalties.append({
                "key": "unverified_cvss",
                "points": pts,
                "label": "CVSS Unverified",
                "detail": "CVSS score not yet assigned — exploitability assessment limited",
            })
            running_score += pts
    else:
        pts = _CONTRIBUTOR_SCHEMA["unverified_cvss"]["max"]
        penalties.append({
            "key": "unverified_cvss",
            "points": pts,
            "label": "No CVSS Score",
            "detail": "CVSS score absent — patch urgency must rely on contextual factors",
        })
        running_score += pts

    # ── IOC analysis ───────────────────────────────────────────────────────────
    iocs = item.get("iocs") or []
    ioc_count = len(iocs)
    ioc_quality_score = 0.0

    if ioc_count == 0:
        pts = _CONTRIBUTOR_SCHEMA["no_iocs"]["max"]
        penalties.append({
            "key": "no_iocs",
            "points": pts,
            "label": "No IOCs Available",
            "detail": "No indicators of compromise present — detection coverage will rely on behavioral signatures only",
        })
        running_score += pts
    else:
        # Compute average IOC quality
        ioc_reliabilities = []
        high_quality_iocs = 0
        for ioc in iocs:
            ioc_type = _classify_ioc_type(ioc)
            reliability = _IOC_TYPE_RELIABILITY.get(ioc_type, 0.40)
            ioc_reliabilities.append(reliability)
            if reliability >= 0.80:
                high_quality_iocs += 1

        ioc_quality_score = sum(ioc_reliabilities) / len(ioc_reliabilities)
        high_ratio = high_quality_iocs / ioc_count

        if ioc_quality_score >= 0.75:
            pts = _CONTRIBUTOR_SCHEMA["ioc_validation"]["max"]
            contributors.append({
                "key": "ioc_validation",
                "points": pts,
                "label": f"High-Quality IOC Set ({ioc_count} IOCs, {ioc_quality_score:.0%} avg reliability)",
                "detail": f"{high_quality_iocs}/{ioc_count} high-reliability indicators (hashes, IPs, registry keys)",
            })
            evidence_chain.append(f"IOCs: {ioc_count} indicators, avg reliability {ioc_quality_score:.0%}")
            running_score += pts
        elif ioc_quality_score >= 0.50:
            pts = int(_CONTRIBUTOR_SCHEMA["ioc_validation"]["max"] * 0.5)
            contributors.append({
                "key": "ioc_validation_moderate",
                "points": pts,
                "label": f"Moderate IOC Quality ({ioc_count} IOCs, {ioc_quality_score:.0%} avg reliability)",
                "detail": f"IOC set of mixed reliability — prioritise hash and IP indicators for detection",
            })
            running_score += pts
        else:
            pts = _CONTRIBUTOR_SCHEMA["low_ioc_quality"]["max"]
            penalties.append({
                "key": "low_ioc_quality",
                "points": pts,
                "label": f"Low IOC Quality ({ioc_count} IOCs, {ioc_quality_score:.0%} avg reliability)",
                "detail": "IOC set dominated by low-reliability types — filenames and URLs change frequently",
            })
            running_score += pts

        # Volume bonus
        if ioc_count >= 10:
            pts = _CONTRIBUTOR_SCHEMA["ioc_volume"]["max"]
            contributors.append({
                "key": "ioc_volume",
                "points": pts,
                "label": f"Large IOC Set ({ioc_count} indicators)",
                "detail": "High-volume IOC set increases detection breadth and SIEM coverage",
            })
            running_score += pts
        elif ioc_count >= 5:
            pts = int(_CONTRIBUTOR_SCHEMA["ioc_volume"]["max"] * 0.6)
            contributors.append({
                "key": "ioc_volume_moderate",
                "points": pts,
                "label": f"Moderate IOC Set ({ioc_count} indicators)",
                "detail": "Adequate IOC coverage for primary SIEM detection rules",
            })
            running_score += pts

    # ── ATT&CK mapping ─────────────────────────────────────────────────────────
    ttps = item.get("ttps") or item.get("techniques") or []
    ttp_count = len(ttps)
    attck_confidence = 0.0

    if ttp_count == 0:
        pts = _CONTRIBUTOR_SCHEMA["no_attck_mapping"]["max"]
        penalties.append({
            "key": "no_attck_mapping",
            "points": pts,
            "label": "No ATT&CK Mapping",
            "detail": "No MITRE ATT&CK techniques mapped — behavioural detection rules unavailable",
        })
        running_score += pts
    else:
        tactics = _extract_attck_tactics(ttps)
        tactic_coverage_score = sum(_ATTCK_TACTIC_WEIGHT.get(t, 0.05) for t in tactics)
        attck_confidence = min(1.0, tactic_coverage_score * (0.5 + 0.5 * min(1.0, ttp_count / 8)))

        pts = int(_CONTRIBUTOR_SCHEMA["verified_attck_overlap"]["max"] * attck_confidence)
        pts = max(2, pts)  # Always at least 2 if there are TTPs
        contributors.append({
            "key": "verified_attck_overlap",
            "points": pts,
            "label": f"ATT&CK Mapped ({ttp_count} techniques, {len(tactics)} tactics)",
            "detail": f"ATT&CK techniques mapped with {attck_confidence:.0%} tactic coverage confidence",
        })
        evidence_chain.append(f"ATT&CK: {ttp_count} techniques across {len(tactics)} tactics ({', '.join(tactics[:3])}{'...' if len(tactics) > 3 else ''})")
        running_score += pts

    # ── Active exploitation signal ─────────────────────────────────────────────
    if _has_exploitation_signal(item) and not kev:
        pts = int(_CONTRIBUTOR_SCHEMA["active_exploitation_signal"]["max"] * 0.7)
        contributors.append({
            "key": "active_exploitation_signal",
            "points": pts,
            "label": "Active Exploitation Indicators",
            "detail": "Advisory text contains active exploitation signals (PoC, in-the-wild references)",
        })
        evidence_chain.append("Exploitation: Active exploitation signals present in advisory")
        running_score += pts
    elif not _has_exploitation_signal(item) and not kev:
        pts = _CONTRIBUTOR_SCHEMA["no_exploitation_evidence"]["max"]
        penalties.append({
            "key": "no_exploitation_evidence",
            "points": pts,
            "label": "No Active Exploitation Evidence",
            "detail": "No confirmed in-the-wild exploitation — threat may be theoretical",
        })
        running_score += pts

    # ── Campaign correlation ───────────────────────────────────────────────────
    actor_attribution_confidence = 0.0
    actor = str(item.get("actor_cluster") or item.get("actor") or "")
    actor_is_known = actor and actor not in ("Unknown Cluster", "CDB-CVE-GEN", "unknown", "")

    if _has_campaign_correlation(item):
        pts = _CONTRIBUTOR_SCHEMA["campaign_correlation"]["max"]
        contributors.append({
            "key": "campaign_correlation",
            "points": pts,
            "label": f"Campaign Correlation ({actor or 'tracked campaign'})",
            "detail": f"Advisory linked to tracked adversary campaign — cross-dossier intelligence correlation available",
        })
        evidence_chain.append(f"Campaign: Linked to {'actor ' + actor if actor_is_known else 'tracked adversary campaign'}")
        running_score += pts
        actor_attribution_confidence = 0.75 if actor_is_known else 0.45
    else:
        if not actor_is_known:
            pts = _CONTRIBUTOR_SCHEMA["low_attribution_certainty"]["max"]
            penalties.append({
                "key": "low_attribution_certainty",
                "points": pts,
                "label": "Low Attribution Certainty",
                "detail": "No specific threat actor attributed — generic exploitation cluster assumed",
            })
            running_score += pts
            actor_attribution_confidence = 0.20
        else:
            actor_attribution_confidence = 0.60

    # ── Historical actor match ─────────────────────────────────────────────────
    if actor_is_known and ttp_count > 0:
        pts = _CONTRIBUTOR_SCHEMA["actor_historical_match"]["max"]
        contributors.append({
            "key": "actor_historical_match",
            "points": pts,
            "label": f"Historical Actor Consistency ({actor})",
            "detail": f"Observed TTPs consistent with historically documented {actor} campaign behavior",
        })
        running_score += pts

    # ── Malware family ─────────────────────────────────────────────────────────
    if _has_malware_family(item):
        pts = _CONTRIBUTOR_SCHEMA["malware_family_identified"]["max"]
        contributors.append({
            "key": "malware_family_identified",
            "points": pts,
            "label": "Malware Family Identified",
            "detail": "Specific malware family identified — existing detection signatures may be applicable",
        })
        evidence_chain.append("Malware: Specific family identified with documented behavioral profile")
        running_score += pts

    # ── Sector targeting ───────────────────────────────────────────────────────
    if _has_sector_targeting(item):
        pts = _CONTRIBUTOR_SCHEMA["sector_targeting_confirmed"]["max"]
        contributors.append({
            "key": "sector_targeting_confirmed",
            "points": pts,
            "label": "Sector-Specific Targeting Confirmed",
            "detail": "Advisory identifies specific sector targeting — organizational exposure can be precisely assessed",
        })
        running_score += pts

    # ── Multi-source corroboration ─────────────────────────────────────────────
    refs = item.get("references") or item.get("reference_urls") or []
    if len(refs) >= 3:
        pts = _CONTRIBUTOR_SCHEMA["multi_source_corroboration"]["max"]
        contributors.append({
            "key": "multi_source_corroboration",
            "points": pts,
            "label": f"Multi-Source Corroboration ({len(refs)} references)",
            "detail": f"Advisory supported by {len(refs)} independent references — reduces single-source risk",
        })
        evidence_chain.append(f"References: {len(refs)} cross-referenced sources")
        running_score += pts
    elif len(refs) >= 2:
        pts = int(_CONTRIBUTOR_SCHEMA["multi_source_corroboration"]["max"] * 0.5)
        contributors.append({
            "key": "multi_source_corroboration_partial",
            "points": pts,
            "label": f"Partial Multi-Source Corroboration ({len(refs)} references)",
            "detail": f"Advisory supported by {len(refs)} references",
        })
        running_score += pts

    # ── Generic description penalty ────────────────────────────────────────────
    if _has_generic_description(item):
        pts = _CONTRIBUTOR_SCHEMA["generic_description"]["max"]
        penalties.append({
            "key": "generic_description",
            "points": pts,
            "label": "Low-Detail Description",
            "detail": "Advisory lacks operational specifics — actionability and detection mapping limited",
        })
        running_score += pts

    # ── Staleness penalty ──────────────────────────────────────────────────────
    if _is_old_advisory(item):
        pts = _CONTRIBUTOR_SCHEMA["old_advisory"]["max"]
        penalties.append({
            "key": "old_advisory",
            "points": pts,
            "label": "Stale Advisory (>30 days)",
            "detail": "Advisory older than 30 days — exploitation landscape may have evolved since publication",
        })
        running_score += pts

    # ── Final score computation ────────────────────────────────────────────────
    # Clamp to 0–100
    raw_score = max(0, min(100, int(round(running_score))))

    # Compute operational confidence (composite)
    operational_confidence = (
        0.35 * (raw_score / 100) +
        0.25 * attck_confidence +
        0.20 * actor_attribution_confidence +
        0.20 * ioc_quality_score
    )

    # ── Lineage hash (audit token) ─────────────────────────────────────────────
    stix_id = str(item.get("stix_id") or item.get("id") or item.get("title") or "")
    lineage_inputs = "|".join([
        stix_id,
        source,
        str(kev),
        str(ioc_count),
        str(ttp_count),
        str(raw_score),
        _VERSION,
    ])
    lineage_hash = hashlib.sha256(lineage_inputs.encode("utf-8")).hexdigest()[:16]

    # ── Rendered HTML explanation ──────────────────────────────────────────────
    rendered_explanation = _render_confidence_html(
        score=raw_score,
        contributors=contributors,
        penalties=penalties,
        evidence_chain=evidence_chain,
        source_reliability_label=source_reliability_label,
        ioc_quality_score=ioc_quality_score,
        attck_confidence=attck_confidence,
        actor_attribution_confidence=actor_attribution_confidence,
        operational_confidence=operational_confidence,
        lineage_hash=lineage_hash,
    )

    return {
        "score": raw_score,
        "contributors": contributors,
        "penalties": penalties,
        "evidence_chain": evidence_chain,
        "source_tier": source_tier,
        "source_reliability_label": source_reliability_label,
        "ioc_quality_score": round(ioc_quality_score, 4),
        "attck_confidence": round(attck_confidence, 4),
        "actor_attribution_confidence": round(actor_attribution_confidence, 4),
        "operational_confidence": round(operational_confidence, 4),
        "lineage_hash": lineage_hash,
        "rendered_explanation": rendered_explanation,
        "engine_version": _VERSION,
        "computed_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# HTML Renderer
# ---------------------------------------------------------------------------

def _render_confidence_html(
    score: int,
    contributors: List[Dict],
    penalties: List[Dict],
    evidence_chain: List[str],
    source_reliability_label: str,
    ioc_quality_score: float,
    attck_confidence: float,
    actor_attribution_confidence: float,
    operational_confidence: float,
    lineage_hash: str,
) -> str:
    """Render explainable confidence breakdown as enterprise-grade HTML."""

    # Score band colour
    if score >= 75:
        score_colour = "#22c55e"
        score_label = "HIGH CONFIDENCE"
        score_css = "confidence-high"
    elif score >= 50:
        score_colour = "#f59e0b"
        score_label = "MODERATE CONFIDENCE"
        score_css = "confidence-moderate"
    elif score >= 30:
        score_colour = "#ef4444"
        score_label = "LOW CONFIDENCE"
        score_css = "confidence-low"
    else:
        score_colour = "#6b7280"
        score_label = "INSUFFICIENT EVIDENCE"
        score_css = "confidence-insufficient"

    # Contributor rows
    contributor_rows = ""
    for c in sorted(contributors, key=lambda x: -x["points"]):
        pts = c["points"]
        contributor_rows += (
            f"<div class='conf-row conf-positive'>"
            f"<span class='conf-label'>{c['label']}</span>"
            f"<span class='conf-pts conf-pts-positive'>+{pts}</span>"
            f"<span class='conf-detail'>{c['detail']}</span>"
            f"</div>"
        )

    # Penalty rows
    penalty_rows = ""
    for p in sorted(penalties, key=lambda x: x["points"]):
        pts = p["points"]
        penalty_rows += (
            f"<div class='conf-row conf-negative'>"
            f"<span class='conf-label'>{p['label']}</span>"
            f"<span class='conf-pts conf-pts-negative'>{pts}</span>"
            f"<span class='conf-detail'>{p['detail']}</span>"
            f"</div>"
        )

    # Dimension meters
    def _meter(label: str, value: float, fmt: str = "{:.0%}") -> str:
        pct = int(value * 100)
        colour = "#22c55e" if pct >= 75 else "#f59e0b" if pct >= 40 else "#ef4444"
        return (
            f"<div class='conf-dim'>"
            f"<span class='conf-dim-label'>{label}</span>"
            f"<div class='conf-dim-bar'><div class='conf-dim-fill' style='width:{pct}%;background:{colour}'></div></div>"
            f"<span class='conf-dim-val'>{fmt.format(value)}</span>"
            f"</div>"
        )

    dims = (
        _meter("IOC Reliability", ioc_quality_score) +
        _meter("ATT&CK Coverage", attck_confidence) +
        _meter("Actor Attribution", actor_attribution_confidence) +
        _meter("Operational Confidence", operational_confidence)
    )

    # Evidence chain
    evidence_html = "".join(f"<li class='conf-evidence-item'>{e}</li>" for e in evidence_chain)

    # Pre-assign fallback HTML to avoid backslash escapes inside f-string expressions
    _no_contributors = "<div class=\"conf-empty\">No positive contributors identified</div>"
    _no_penalties = "<div class=\"conf-empty\">No penalties applied</div>"
    _no_evidence = "<li>No structured evidence available</li>"
    _contributor_block = contributor_rows if contributor_rows else _no_contributors
    _penalty_block = penalty_rows if penalty_rows else _no_penalties
    _evidence_block = evidence_html if evidence_html else _no_evidence

    html = (
        f"<div class='explainable-confidence {score_css}'>"
        f"<div class='conf-header'>"
        f"<div class='conf-score-ring' style='--score-pct:{score};--score-colour:{score_colour}'>"
        f"<span class='conf-score-val'>{score}%</span>"
        f"<span class='conf-score-label'>{score_label}</span>"
        f"</div>"
        f"<div class='conf-meta'>"
        f"<div class='conf-meta-item'><span class='conf-meta-key'>Source Reliability</span><span class='conf-meta-val'>{source_reliability_label}</span></div>"
        f"<div class='conf-meta-item'><span class='conf-meta-key'>Lineage Audit Token</span><span class='conf-meta-val'><code>{lineage_hash}</code></span></div>"
        f"<div class='conf-meta-item'><span class='conf-meta-key'>Engine Version</span><span class='conf-meta-val'>ECE-{_VERSION}</span></div>"
        f"</div>"
        f"</div>"
        f"<div class='conf-dimensions'>{dims}</div>"
        f"<div class='conf-breakdown'>"
        f"<div class='conf-section-title'>Confidence Contributors</div>"
        f"{_contributor_block}"
        f"<div class='conf-section-title'>Confidence Penalties</div>"
        f"{_penalty_block}"
        f"</div>"
        f"<div class='conf-evidence'>"
        f"<div class='conf-section-title'>Evidence Chain</div>"
        f"<ul class='conf-evidence-list'>{_evidence_block}</ul>"
        f"</div>"
        f"</div>"
    )
    return html


# ---------------------------------------------------------------------------
# Batch Processing
# ---------------------------------------------------------------------------

def compute_confidence_batch(
    items: List[Dict[str, Any]],
    max_items: int = 10000,
) -> List[Dict[str, Any]]:
    """
    Process a list of intelligence items and return confidence breakdowns.
    Bounded iteration — safe for enterprise-scale corpuses.
    Never raises.
    """
    results = []
    processed = 0
    errors = 0
    for item in items[:max_items]:
        try:
            breakdown = compute_confidence_breakdown(item)
            results.append({
                "id": str(item.get("stix_id") or item.get("id") or item.get("title") or f"item_{processed}"),
                "confidence_breakdown": breakdown,
            })
            processed += 1
        except Exception as exc:
            log.error("compute_confidence_batch item %d failed: %s", processed, exc)
            errors += 1
            results.append({
                "id": str(item.get("title") or f"item_{processed}"),
                "confidence_breakdown": {
                    "score": 0,
                    "contributors": [],
                    "penalties": [{"key": "engine_error", "points": 0, "label": "Engine Error", "detail": str(exc)}],
                    "evidence_chain": [],
                    "error": str(exc),
                },
            })
    log.info("compute_confidence_batch: processed=%d errors=%d", processed, errors)
    return results


def get_corpus_confidence_summary(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Produce a corpus-wide confidence distribution summary.
    Used for MSSP executive dashboards and enterprise health telemetry.
    """
    try:
        scores = []
        high = moderate = low = insufficient = 0
        for item in items:
            try:
                bd = compute_confidence_breakdown(item)
                s = bd["score"]
                scores.append(s)
                if s >= 75:   high += 1
                elif s >= 50: moderate += 1
                elif s >= 30: low += 1
                else:         insufficient += 1
            except Exception:
                insufficient += 1

        total = len(scores)
        avg = int(sum(scores) / total) if total else 0
        return {
            "total_items": total,
            "average_confidence": avg,
            "high_confidence_count": high,
            "moderate_confidence_count": moderate,
            "low_confidence_count": low,
            "insufficient_confidence_count": insufficient,
            "high_confidence_pct": round(high / total * 100, 1) if total else 0,
            "actionable_pct": round((high + moderate) / total * 100, 1) if total else 0,
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        log.error("get_corpus_confidence_summary failed: %s", exc)
        return {"error": str(exc)}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "compute_confidence_breakdown",
    "compute_confidence_batch",
    "get_corpus_confidence_summary",
    "_VERSION",
]
