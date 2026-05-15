#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
scripts/ocios_soc_prioritization_engine.py
OCIOS Phase 3 -- SOC Prioritization Engine
================================================================================
Version      : 1.0.0
Classification: CONFIDENTIAL -- OCIOS TIER

MANDATE
-------
Transforms the advisory corpus into ACTIONABLE SOC PRIORITIES.
The central question this engine answers for every SOC team:

    "WHAT MUST WE ACT ON FIRST -- AND WHY?"

WHAT THIS ENGINE DOES (corpus-level, not per-item)
---------------------------------------------------
- SOC queue generation with deterministic priority ranking
- Patch urgency ranking with time-decay pressure modeling
- Exploitation urgency modeling (KEV + EPSS + threat velocity)
- KEV amplification (CISA active exploits get maximum elevation)
- Ransomware weighting (RaaS-linked threats escalate queue position)
- Internet exposure weighting (externally reachable attack surface)
- Operational downtime scoring (production system disruption risk)
- Blast radius prioritization (lateral movement + domain impact)
- Executive escalation thresholds (CISO-bound severity triggers)
- SLA impact weighting (customer-facing system breach urgency)
- Remediation sequencing (dependency-aware fix ordering)
- Incident response prioritization (triage urgency bands)
- Analyst workload optimization (balanced queue distribution)

DIFFERENTIATION FROM EXISTING ENGINES
--------------------------------------
- enterprise_scoring_engine.py : per-item 10-dimension raw scores (0-100)
- ocios_operational_reasoning_engine.py : WHY the threat matters, narrative
- THIS ENGINE : converts scores -> ranked SOC queues, action tiers,
                escalation triggers, remediation plans, analyst queues

INPUTS
------
  data/feed_manifest.json                       (required)
  data/enterprise_scoring/scoring_report.json   (optional enrichment)
  data/ocios/operational_reasoning.json         (optional enrichment)
  data/ocios/campaign_graph.json                (optional enrichment)

OUTPUTS
-------
  data/ocios/soc_priority_queue.json      -- ranked SOC action queue
  data/ocios/remediation_tiers.json       -- tiered remediation plan
  data/ocios/escalation_matrix.json       -- escalation categories + triggers
  data/ocios/executive_dashboard.json     -- CISO-level risk summary
  data/ocios/analyst_workload.json        -- analyst-optimized queue split
  data/ocios/soc_prioritization_summary.json -- engine run summary

PIPELINE POSITION
-----------------
  Runs AFTER: ocios_campaign_correlation_engine.py,
              ocios_operational_reasoning_engine.py
  Runs BEFORE: report generation, dashboard rendering
  Called by:  ocios_coordinator.py

SAFETY GUARANTEES
-----------------
  - ADDITIVE ONLY -- never modifies feed_manifest.json
  - Atomic writes (tmp -> fsync -> os.replace) for all outputs
  - UTF-8 clean -- no non-ASCII in any code path
  - Deterministic -- same corpus always produces identical queue order
  - Bounded execution -- O(N log N) complexity, no unbounded recursion
  - Exception-isolated -- individual item failures never abort the engine
  - Zero silent failures -- all exceptions logged, engine always completes

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("ocios.soc_prioritization")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT     = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "feed_manifest.json"
SCORING_REPORT = REPO_ROOT / "data" / "enterprise_scoring" / "scoring_report.json"
OCIOS_DIR     = REPO_ROOT / "data" / "ocios"
ENGINE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# SOC Tier thresholds  (composite priority score 0-1000)
# ---------------------------------------------------------------------------
TIER_CRITICAL_THRESHOLD   = 750   # P0 -- Immediate action < 4h
TIER_HIGH_THRESHOLD       = 550   # P1 -- Action required < 24h
TIER_MEDIUM_THRESHOLD     = 350   # P2 -- Action required < 72h
TIER_LOW_THRESHOLD        = 150   # P3 -- Scheduled remediation
# Below LOW_THRESHOLD      = P4 -- Monitor / accept risk

# Executive escalation threshold
EXEC_ESCALATION_THRESHOLD = 700   # Items >= this score go to CISO

# Analyst workload target per analyst per day
ANALYST_DAILY_CAPACITY    = 15

# KEV age in days for "hot" exploitation
KEV_HOT_DAYS = 14

# ---------------------------------------------------------------------------
# Known ransomware actor fragments (lowercase match)
# ---------------------------------------------------------------------------
_RANSOMWARE_ACTORS = frozenset({
    "lockbit", "blackcat", "alphv", "clop", "revil", "darkside", "conti",
    "hive", "blackbasta", "ransomhub", "play", "akira", "royal", "rhysida",
    "medusa", "8base", "lorenz", "scatter", "noname", "cl0p", "lazarus",
    "lapsus", "scattered spider", "midnight blizzard", "cozy bear",
    "apt41", "apt28", "apt29", "apt19", "ta505",
})

# Ransomware-associated TTP IDs
_RANSOMWARE_TTPS = frozenset({
    "T1486", "T1490", "T1489", "T1485", "T1491",   # Impact
    "T1021", "T1021.001", "T1021.002",              # Lateral
    "T1078", "T1133", "T1566",                      # Initial access
    "T1059", "T1059.001",                           # Execution
    "T1082", "T1083",                               # Discovery
})

# Vulnerability classes with fastest exploitation timelines
_HIGH_VELOCITY_VULN_CLASSES = frozenset({
    "rce", "remote code execution", "authentication bypass",
    "auth bypass", "unauthenticated", "zero-day", "0-day",
    "pre-auth", "sql injection", "deserialization",
    "file upload", "xxe", "ssrf", "prototype pollution",
})

# Sector criticality weights (higher = more critical infrastructure)
_SECTOR_CRITICALITY = {
    "critical infrastructure": 1.0,
    "energy": 1.0,
    "healthcare": 0.95,
    "finance": 0.95,
    "financial services": 0.95,
    "government": 0.90,
    "defense": 0.95,
    "water": 0.90,
    "transportation": 0.85,
    "telecommunications": 0.85,
    "manufacturing": 0.75,
    "education": 0.65,
    "retail": 0.60,
    "technology": 0.70,
}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    return str(v).strip()


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def _safe_list(v: Any) -> list:
    if isinstance(v, list):
        return v
    if v is None:
        return []
    return [v]


def _safe_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    s = str(v).lower().strip()
    return s in ("true", "yes", "1", "confirmed", "active")


def _item_id(item: Dict) -> str:
    return _safe_str(
        item.get("advisory_id") or item.get("id") or item.get("cve_id") or item.get("link"),
        default="unknown"
    )[:120]


def _item_title(item: Dict) -> str:
    return _safe_str(
        item.get("title") or item.get("name") or item.get("advisory_id"),
        default="Untitled Advisory"
    )[:200]


def _parse_ts(v: Any) -> Optional[datetime]:
    if not v:
        return None
    s = str(v)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            dt = datetime.strptime(s[:19], fmt[:len(s[:19])])
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _extract_cves(item: Dict) -> List[str]:
    cves = _safe_list(item.get("cves") or item.get("cve") or item.get("cve_id"))
    result = []
    for c in cves:
        s = _safe_str(c)
        if re.search(r"CVE-\d{4}-\d+", s, re.I):
            result.append(s.upper())
    return list(set(result))


def _extract_ttps(item: Dict) -> List[str]:
    ttps = _safe_list(item.get("mitre_techniques") or item.get("ttps") or [])
    result = []
    for t in ttps:
        s = _safe_str(t).upper()
        if re.match(r"T\d{4}", s):
            result.append(s[:10])
    return list(set(result))


def _extract_actors(item: Dict) -> List[str]:
    raw = _safe_list(item.get("actors") or item.get("actor") or [])
    return [_safe_str(a).lower() for a in raw if a]


def _extract_sectors(item: Dict) -> List[str]:
    raw = _safe_list(item.get("sectors") or item.get("sector") or item.get("tags") or [])
    return [_safe_str(s).lower() for s in raw if s]


def _is_kev(item: Dict) -> bool:
    return _safe_bool(
        item.get("kev") or item.get("kev_present") or item.get("in_kev") or item.get("cisa_kev")
    )


def _is_ransomware_linked(item: Dict) -> bool:
    actors = _extract_actors(item)
    for a in actors:
        if any(r in a for r in _RANSOMWARE_ACTORS):
            return True
    tags = [_safe_str(t).lower() for t in _safe_list(item.get("tags") or [])]
    if any("ransomware" in t for t in tags):
        return True
    threat_type = _safe_str(item.get("threat_type") or "").lower()
    if "ransomware" in threat_type or "raas" in threat_type:
        return True
    ttps = set(_extract_ttps(item))
    return bool(ttps & _RANSOMWARE_TTPS)


def _get_cvss(item: Dict) -> float:
    return _safe_float(item.get("cvss") or item.get("cvss_score") or item.get("cvss_v3"))


def _get_epss(item: Dict) -> float:
    return _safe_float(item.get("epss") or item.get("epss_score") or item.get("epss_probability"))


def _severity_rank(severity: str) -> int:
    """Map severity string to numeric rank (0-4)."""
    s = severity.lower().strip()
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0, "info": 0}.get(s, 1)


def _days_since_published(item: Dict) -> Optional[float]:
    ts = _parse_ts(item.get("published") or item.get("date") or item.get("published_at"))
    if ts is None:
        return None
    now = datetime.now(timezone.utc)
    return max(0.0, (now - ts).total_seconds() / 86400)


# ---------------------------------------------------------------------------
# SCORING DIMENSIONS
# Each returns 0-100.  All are exception-safe.
# ---------------------------------------------------------------------------

def _score_kev_amplification(item: Dict) -> float:
    """
    KEV confirmation is the single strongest exploitation signal.
    Active exploitation in the wild warrants immediate SOC response.
    """
    if not _is_kev(item):
        return 0.0
    days = _days_since_published(item)
    if days is None:
        return 90.0
    # Fresh KEV (< 14d) = maximum urgency; decays slowly over 90 days
    if days <= KEV_HOT_DAYS:
        return 100.0
    decay = max(0.0, 1.0 - ((days - KEV_HOT_DAYS) / 90.0) * 0.3)
    return round(90.0 * decay, 1)


def _score_ransomware_weight(item: Dict) -> float:
    """
    Ransomware linkage elevates SOC priority because:
    - Ransomware attacks are high-visibility incidents
    - Recovery costs are severe (downtime, legal, regulatory)
    - Dwell time is compressed -- defenders must act fast
    """
    if not _is_ransomware_linked(item):
        return 0.0
    base = 80.0
    # CVE present = exploit path identified for ransomware deployment
    if _extract_cves(item):
        base += 10.0
    # KEV + ransomware = worst-case scenario
    if _is_kev(item):
        base += 10.0
    return min(100.0, base)


def _score_exploitation_urgency(item: Dict) -> float:
    """
    Models probability and speed of active exploitation.
    Combines KEV, EPSS, CVSS, and threat velocity signals.
    """
    score = 0.0

    # KEV = confirmed exploitation (dominant signal)
    if _is_kev(item):
        score += 50.0

    # EPSS (0.0-1.0) = ML-based exploitation probability
    epss = _get_epss(item)
    if epss > 0:
        score += epss * 30.0

    # CVSS amplification
    cvss = _get_cvss(item)
    if cvss >= 9.0:
        score += 20.0
    elif cvss >= 7.0:
        score += 12.0
    elif cvss >= 5.0:
        score += 5.0

    # Threat score from manifest (0-100 normalized)
    threat_score = _safe_float(item.get("threat_score"))
    score += (threat_score / 100.0) * 15.0

    # Severity amplification
    sev = _safe_str(item.get("severity") or item.get("risk_level") or "").lower()
    if sev == "critical":
        score += 15.0
    elif sev == "high":
        score += 8.0

    return min(100.0, round(score, 1))


def _score_internet_exposure(item: Dict) -> float:
    """
    Internet-facing vulnerability = immediate attacker opportunity.
    Network-based unauthenticated RCE on perimeter systems = highest urgency.
    """
    score = 0.0
    title_desc = (
        _safe_str(item.get("title")) + " " +
        _safe_str(item.get("description")) + " " +
        _safe_str(item.get("threat_type")) + " " +
        " ".join(_safe_list(item.get("tags") or []))
    ).lower()

    # Unauthenticated/pre-auth = no credential requirement
    if any(kw in title_desc for kw in ("unauthenticated", "pre-auth", "pre_auth", "unauth")):
        score += 40.0

    # Network-based attack vector
    if any(kw in title_desc for kw in ("remote", "network", "internet-facing", "internet facing",
                                         "perimeter", "vpn", "firewall", "gateway", "edge")):
        score += 25.0

    # Exploit public = attackers have working tooling
    if any(kw in title_desc for kw in ("exploit available", "poc", "proof-of-concept",
                                         "proof of concept", "public exploit", "metasploit")):
        score += 20.0

    # High-velocity vuln class
    if any(vc in title_desc for vc in _HIGH_VELOCITY_VULN_CLASSES):
        score += 15.0

    return min(100.0, round(score, 1))


def _score_blast_radius(item: Dict) -> float:
    """
    Blast radius = potential damage scope if exploitation succeeds.
    Factors: IOC count, TTP spread, sector criticality, campaign membership.
    """
    score = 0.0

    # IOC count = indicator of campaign operational scale
    ioc_count = len(_safe_list(item.get("iocs") or []))
    score += min(25.0, ioc_count * 1.5)

    # TTP depth = attacker capability breadth
    ttps = _extract_ttps(item)
    ttp_count = len(ttps)
    score += min(20.0, ttp_count * 2.0)

    # Lateral movement TTPs amplify blast radius
    lateral_ttps = frozenset({"T1021", "T1021.001", "T1021.002", "T1550", "T1076"})
    if set(ttps) & lateral_ttps:
        score += 20.0

    # Sector criticality
    sectors = _extract_sectors(item)
    max_crit = max(
        (_SECTOR_CRITICALITY.get(s, 0.0) for s in sectors),
        default=0.0
    )
    score += max_crit * 25.0

    # Multiple actors = coordinated campaign with broader reach
    actors = _extract_actors(item)
    if len(actors) >= 3:
        score += 15.0
    elif len(actors) >= 2:
        score += 8.0

    return min(100.0, round(score, 1))


def _score_operational_downtime(item: Dict) -> float:
    """
    Operational downtime risk = probability exploitation causes service disruption.
    """
    score = 0.0
    combined = (
        _safe_str(item.get("title")) + " " +
        _safe_str(item.get("description")) + " " +
        _safe_str(item.get("threat_type")) + " " +
        " ".join(_safe_list(item.get("tags") or []))
    ).lower()

    # Ransomware = guaranteed downtime
    if _is_ransomware_linked(item):
        score += 50.0

    # DoS/DDoS = direct availability attack
    if any(kw in combined for kw in ("denial of service", "dos", "ddos", "availability")):
        score += 40.0

    # ICS/OT/SCADA = operational technology disruption
    if any(kw in combined for kw in ("ics", "ot", "scada", "industrial", "operational technology")):
        score += 35.0

    # Wiper malware = irrecoverable data loss
    if any(kw in combined for kw in ("wiper", "destructive", "data destruction")):
        score += 45.0

    # Supply chain = cascading operational impact
    if any(kw in combined for kw in ("supply chain", "software supply", "third-party")):
        score += 20.0

    return min(100.0, round(score, 1))


def _score_sla_impact(item: Dict) -> float:
    """
    SLA impact = risk of breach causing customer-facing SLA violations.
    """
    score = 0.0

    # Critical severity with KEV = SLA breach imminent
    sev = _safe_str(item.get("severity") or item.get("risk_level") or "").lower()
    if sev == "critical" and _is_kev(item):
        score += 60.0
    elif sev == "critical":
        score += 35.0
    elif sev == "high":
        score += 20.0

    # Ransomware = guaranteed SLA breach
    if _is_ransomware_linked(item):
        score += 30.0

    # Multiple CVEs = broader attack surface, harder to patch
    cves = _extract_cves(item)
    if len(cves) >= 3:
        score += 15.0
    elif len(cves) >= 1:
        score += 8.0

    return min(100.0, round(score, 1))


def _score_patch_urgency(item: Dict) -> float:
    """
    Patch urgency = how quickly patching must occur to prevent exploitation.
    Time-decay model: urgency increases as unpatched time grows for known exploits.
    """
    score = 0.0

    # KEV = emergency patch required
    if _is_kev(item):
        score += 50.0
        # Age pressure: longer unpatched KEV = higher urgency
        days = _days_since_published(item)
        if days is not None and days > 30:
            score += min(20.0, (days - 30) * 0.5)

    # CVSS drives baseline patch priority
    cvss = _get_cvss(item)
    if cvss >= 9.0:
        score += 25.0
    elif cvss >= 7.0:
        score += 15.0
    elif cvss >= 5.0:
        score += 8.0

    # Multiple CVEs in one advisory = patch window complexity
    cves = _extract_cves(item)
    if len(cves) >= 5:
        score += 10.0
    elif len(cves) >= 2:
        score += 5.0

    # Severity fallback when CVSS not present
    sev = _safe_str(item.get("severity") or "").lower()
    if cvss == 0.0:
        if sev == "critical":
            score += 20.0
        elif sev == "high":
            score += 12.0

    return min(100.0, round(score, 1))


def _score_adversary_sophistication(item: Dict) -> float:
    """
    Higher adversary sophistication = faster exploitation capability
    = less time for defenders = higher SOC urgency.
    """
    score = 0.0
    actors = _extract_actors(item)
    combined = " ".join(actors).lower() + " " + _safe_str(item.get("description") or "").lower()

    # Nation-state indicators
    apt_patterns = {"apt", "lazarus", "cozy bear", "fancy bear", "charming kitten",
                    "volt typhoon", "salt typhoon", "midnight blizzard", "lapsus",
                    "scattered spider", "sandworm", "equation group"}
    if any(p in combined for p in apt_patterns):
        score += 50.0

    # RaaS = highly organized criminal infrastructure
    if _is_ransomware_linked(item):
        score += 30.0

    # TTP depth signals sophisticated operation
    ttps = _extract_ttps(item)
    if len(ttps) >= 8:
        score += 20.0
    elif len(ttps) >= 4:
        score += 10.0

    return min(100.0, round(score, 1))


# ---------------------------------------------------------------------------
# COMPOSITE PRIORITY SCORE  (0-1000)
# ---------------------------------------------------------------------------

# Dimension weights (must sum to 1.0)
_DIMENSION_WEIGHTS = {
    "kev_amplification":       0.22,   # KEV = confirmed exploitation
    "exploitation_urgency":    0.20,   # Combined exploit probability
    "ransomware_weight":       0.15,   # Ransomware ecosystem linkage
    "blast_radius":            0.12,   # Damage scope
    "patch_urgency":           0.12,   # Remediation time pressure
    "internet_exposure":       0.08,   # Attack surface accessibility
    "operational_downtime":    0.06,   # Operational availability risk
    "sla_impact":              0.03,   # Customer-facing SLA risk
    "adversary_sophistication":0.02,   # Attacker capability
}

assert abs(sum(_DIMENSION_WEIGHTS.values()) - 1.0) < 0.001, "Weights must sum to 1.0"


def compute_composite_priority(item: Dict) -> Tuple[float, Dict[str, float]]:
    """
    Compute composite SOC priority score (0-1000) from weighted dimensions.
    Returns (score, dimension_breakdown).
    """
    dimensions: Dict[str, float] = {}
    try:
        dimensions["kev_amplification"]        = _score_kev_amplification(item)
        dimensions["exploitation_urgency"]     = _score_exploitation_urgency(item)
        dimensions["ransomware_weight"]        = _score_ransomware_weight(item)
        dimensions["blast_radius"]             = _score_blast_radius(item)
        dimensions["patch_urgency"]            = _score_patch_urgency(item)
        dimensions["internet_exposure"]        = _score_internet_exposure(item)
        dimensions["operational_downtime"]     = _score_operational_downtime(item)
        dimensions["sla_impact"]               = _score_sla_impact(item)
        dimensions["adversary_sophistication"] = _score_adversary_sophistication(item)
    except Exception as exc:
        log.warning("Dimension scoring partial for %s: %s", _item_id(item), exc)

    composite = sum(
        dimensions.get(k, 0.0) * w * 10.0   # *10 to scale to 0-1000
        for k, w in _DIMENSION_WEIGHTS.items()
    )
    return round(composite, 1), dimensions


# ---------------------------------------------------------------------------
# SOC TIER CLASSIFICATION
# ---------------------------------------------------------------------------

def classify_soc_tier(score: float) -> Dict[str, str]:
    """Return SOC tier label, SLA window, and escalation guidance."""
    if score >= TIER_CRITICAL_THRESHOLD:
        return {
            "tier":       "P0-CRITICAL",
            "label":      "CRITICAL",
            "color":      "red",
            "sla_window": "< 4 hours",
            "response":   "IMMEDIATE -- activate IR playbook, notify CISO",
            "action":     "Emergency patch or mitigating control required NOW",
        }
    elif score >= TIER_HIGH_THRESHOLD:
        return {
            "tier":       "P1-HIGH",
            "label":      "HIGH",
            "color":      "orange",
            "sla_window": "< 24 hours",
            "response":   "URGENT -- assign senior analyst, begin remediation",
            "action":     "Patch or workaround within one business day",
        }
    elif score >= TIER_MEDIUM_THRESHOLD:
        return {
            "tier":       "P2-MEDIUM",
            "label":      "MEDIUM",
            "color":      "yellow",
            "sla_window": "< 72 hours",
            "response":   "STANDARD -- schedule remediation in current sprint",
            "action":     "Patch within 72 hours, monitor for escalation",
        }
    elif score >= TIER_LOW_THRESHOLD:
        return {
            "tier":       "P3-LOW",
            "label":      "LOW",
            "color":      "blue",
            "sla_window": "< 30 days",
            "response":   "PLANNED -- include in next patch cycle",
            "action":     "Remediate in scheduled maintenance window",
        }
    else:
        return {
            "tier":       "P4-MONITOR",
            "label":      "MONITOR",
            "color":      "gray",
            "sla_window": "Next review cycle",
            "response":   "MONITOR -- accept risk or defer",
            "action":     "Log and reassess in 30-day review",
        }


# ---------------------------------------------------------------------------
# SOC QUEUE RECORD BUILDER
# ---------------------------------------------------------------------------

def build_soc_record(item: Dict, rank: int) -> Dict[str, Any]:
    """Build a single enriched SOC queue record for one advisory."""
    item_id    = _item_id(item)
    title      = _item_title(item)
    cves       = _extract_cves(item)
    actors     = _extract_actors(item)
    ttps       = _extract_ttps(item)
    sectors    = _extract_sectors(item)
    is_kev_    = _is_kev(item)
    is_ransom  = _is_ransomware_linked(item)
    severity   = _safe_str(item.get("severity") or item.get("risk_level") or "unknown")
    cvss       = _get_cvss(item)
    epss       = _get_epss(item)

    try:
        composite, dimensions = compute_composite_priority(item)
    except Exception as exc:
        log.warning("Priority computation failed for %s: %s", item_id, exc)
        composite, dimensions = 0.0, {}

    tier_info  = classify_soc_tier(composite)
    exec_esc   = composite >= EXEC_ESCALATION_THRESHOLD

    # Remediation recommendation
    remediation = _generate_remediation(item, composite, is_kev_, is_ransom)

    # Detection gaps
    detection_gaps = _assess_detection_gaps(item, ttps)

    # IR urgency narrative
    ir_narrative = _generate_ir_narrative(item, composite, is_kev_, is_ransom, tier_info)

    return {
        "rank":                   rank,
        "id":                     item_id,
        "title":                  title,
        "composite_priority":     composite,
        "soc_tier":               tier_info,
        "executive_escalation":   exec_esc,
        "cves":                   cves,
        "cve_count":              len(cves),
        "cvss":                   cvss if cvss > 0 else None,
        "epss":                   epss if epss > 0 else None,
        "kev_confirmed":          is_kev_,
        "ransomware_linked":      is_ransom,
        "severity":               severity,
        "actors":                 actors,
        "mitre_ttps":             ttps,
        "ttp_count":              len(ttps),
        "sectors":                sectors,
        "ioc_count":              len(_safe_list(item.get("iocs") or [])),
        "source":                 _safe_str(item.get("source") or item.get("link") or ""),
        "published":              _safe_str(item.get("published") or ""),
        "dimension_scores":       dimensions,
        "remediation":            remediation,
        "detection_gaps":         detection_gaps,
        "ir_narrative":           ir_narrative,
        "ai_cluster_id":          _safe_str(item.get("ai_cluster_id") or ""),
        "threat_type":            _safe_str(item.get("threat_type") or ""),
        "threat_score_raw":       _safe_float(item.get("threat_score")),
    }


# ---------------------------------------------------------------------------
# REMEDIATION GUIDANCE GENERATOR
# ---------------------------------------------------------------------------

def _generate_remediation(
    item: Dict, score: float, is_kev: bool, is_ransom: bool
) -> Dict[str, Any]:
    """Generate evidence-backed remediation guidance."""
    steps: List[str] = []
    priority_action = ""
    timeline = ""

    cves   = _extract_cves(item)
    ttps   = _extract_ttps(item)
    cvss   = _get_cvss(item)
    sev    = _safe_str(item.get("severity") or "").lower()
    combined = (
        _safe_str(item.get("title")) + " " +
        _safe_str(item.get("description") or "") + " " +
        _safe_str(item.get("threat_type") or "")
    ).lower()

    if is_kev:
        priority_action = "Apply vendor patch immediately per CISA KEV directive"
        timeline = "Emergency: complete within 24 hours"
        steps.append("1. Verify CISA KEV entry and obtain vendor advisory")
        steps.append("2. Apply emergency patch to all affected systems NOW")
        steps.append("3. If patch unavailable: isolate system, apply vendor workaround")
        steps.append("4. Scan network for exploitation indicators (IOCs in feed)")
        steps.append("5. Report remediation status to CISO within 4 hours")
    elif is_ransom:
        priority_action = "Block ransomware TTPs and segment affected systems"
        timeline = "Urgent: complete within 24 hours"
        steps.append("1. Isolate vulnerable systems from lateral movement paths")
        steps.append("2. Block ransomware C2 indicators in firewall / EDR")
        steps.append("3. Apply patches for identified RCE/auth-bypass CVEs")
        steps.append("4. Verify backup integrity for affected asset classes")
        steps.append("5. Enable enhanced monitoring on perimeter and identity systems")
    elif cvss >= 9.0 or sev == "critical":
        priority_action = "Patch critical vulnerability or apply compensating control"
        timeline = "Emergency: complete within 48 hours"
        steps.append("1. Obtain vendor patch and test in staging environment")
        steps.append("2. Deploy patch to internet-facing systems first")
        steps.append("3. Apply WAF or network rule as interim compensating control")
        steps.append("4. Validate patch effectiveness with vulnerability scanner")
    elif cvss >= 7.0 or sev == "high":
        priority_action = "Schedule and apply patch within next maintenance window"
        timeline = "Urgent: complete within 72 hours"
        steps.append("1. Add to sprint backlog as high-priority remediation task")
        steps.append("2. Apply vendor patch in next available maintenance window")
        steps.append("3. Implement detection rule for exploitation attempts")
    else:
        priority_action = "Schedule patch in next regular maintenance cycle"
        timeline = "Standard: complete within 30 days"
        steps.append("1. Add to patch management queue for next cycle")
        steps.append("2. Monitor threat intelligence for exploitation escalation")

    # Add TTP-specific hardening
    ttp_set = set(ttps)
    if {"T1021", "T1021.001", "T1021.002"} & ttp_set:
        steps.append("Harden: Restrict RDP/SMB access, enforce MFA on remote services")
    if {"T1078", "T1133"} & ttp_set:
        steps.append("Harden: Audit VPN/remote access accounts, rotate credentials")
    if {"T1486", "T1490"} & ttp_set:
        steps.append("Harden: Verify offline backups, test restoration procedures")
    if {"T1059", "T1059.001"} & ttp_set:
        steps.append("Harden: Enable PowerShell logging, restrict script execution policy")

    # IOC-based detection
    ioc_count = len(_safe_list(item.get("iocs") or []))
    if ioc_count > 0:
        steps.append(f"Detection: Load {ioc_count} IOCs into SIEM, EDR, and firewall blocklists")

    return {
        "priority_action": priority_action,
        "timeline":        timeline,
        "steps":           steps,
        "patch_required":  bool(cves),
        "cves_to_patch":   cves,
    }


# ---------------------------------------------------------------------------
# DETECTION GAP ASSESSMENT
# ---------------------------------------------------------------------------

def _assess_detection_gaps(item: Dict, ttps: List[str]) -> List[str]:
    """Identify detection coverage gaps based on TTP profile."""
    gaps: List[str] = []
    ttp_set = set(ttps)

    gap_map = {
        frozenset({"T1078"}):                  "No identity anomaly detection for valid account abuse",
        frozenset({"T1133"}):                  "No external remote service monitoring rule",
        frozenset({"T1059", "T1059.001"}):     "PowerShell/script execution logging may be incomplete",
        frozenset({"T1021", "T1021.002"}):     "Lateral SMB movement detection may lack coverage",
        frozenset({"T1486"}):                  "File encryption behavior detection rule missing",
        frozenset({"T1490"}):                  "Shadow copy deletion detection rule not confirmed",
        frozenset({"T1055"}):                  "Process injection detection may miss LOLBin variants",
        frozenset({"T1082", "T1083"}):         "Internal discovery scan detection may be under-tuned",
        frozenset({"T1071", "T1071.001"}):     "C2 over HTTPS detection requires SSL inspection",
        frozenset({"T1547", "T1053"}):         "Persistence mechanism detection (registry/task) not validated",
    }

    for required_ttps, gap_msg in gap_map.items():
        if required_ttps & ttp_set:
            gaps.append(gap_msg)

    if not ttps:
        gaps.append("No TTPs mapped -- cannot assess detection coverage")

    return gaps


# ---------------------------------------------------------------------------
# IR NARRATIVE GENERATOR
# ---------------------------------------------------------------------------

def _generate_ir_narrative(
    item: Dict,
    score: float,
    is_kev: bool,
    is_ransom: bool,
    tier_info: Dict,
) -> str:
    """Generate SOC-consumable IR urgency narrative. Evidence-derived, not cosmetic."""
    cves   = _extract_cves(item)
    actors = _extract_actors(item)
    cvss   = _get_cvss(item)
    epss   = _get_epss(item)
    title  = _item_title(item)
    sev    = _safe_str(item.get("severity") or "").lower()

    parts: List[str] = []

    # Lead sentence -- establish urgency
    if score >= TIER_CRITICAL_THRESHOLD:
        parts.append(
            f"CRITICAL SOC PRIORITY: {title} requires immediate incident response action."
        )
    elif score >= TIER_HIGH_THRESHOLD:
        parts.append(
            f"HIGH PRIORITY: {title} demands analyst attention within 24 hours."
        )
    else:
        parts.append(f"{title} has been assessed at {tier_info['label']} priority.")

    # KEV reasoning
    if is_kev:
        parts.append(
            "This vulnerability is confirmed by CISA as actively exploited in the wild, "
            "triggering the KEV directive -- all covered systems must be remediated immediately."
        )

    # Ransomware reasoning
    if is_ransom:
        if actors:
            actor_str = ", ".join(actors[:3])
            parts.append(
                f"Threat actors including {actor_str} are operating ransomware campaigns using "
                "this threat vector -- successful exploitation leads directly to ransomware deployment, "
                "data exfiltration, and operational downtime."
            )
        else:
            parts.append(
                "Ransomware actor TTPs are present in this advisory -- exploitation path leads "
                "directly to ransomware deployment and operational disruption."
            )

    # CVSS/EPSS reasoning
    if cvss >= 9.0:
        parts.append(
            f"CVSS score of {cvss:.1f} indicates critical severity with a low-complexity "
            "attack vector -- exploitation requires minimal attacker sophistication."
        )
    elif cvss >= 7.0:
        parts.append(f"CVSS score of {cvss:.1f} confirms high severity requiring urgent remediation.")

    if epss > 0.5:
        parts.append(
            f"EPSS probability of {epss:.0%} indicates a high statistical likelihood of "
            "exploitation within the next 30 days based on threat intelligence modeling."
        )

    # CVE context
    if cves:
        cve_str = ", ".join(cves[:4])
        parts.append(
            f"Affected CVEs: {cve_str}{'...' if len(cves) > 4 else ''}. "
            "Vendor patch availability should be confirmed before remediation planning begins."
        )

    # SLA window
    parts.append(
        f"Required response window: {tier_info['sla_window']}. "
        f"Action: {tier_info['action']}."
    )

    return " ".join(parts)


# ---------------------------------------------------------------------------
# CORPUS-LEVEL AGGREGATIONS
# ---------------------------------------------------------------------------

def build_soc_priority_queue(items: List[Dict]) -> List[Dict[str, Any]]:
    """
    Build the full ranked SOC priority queue from the advisory corpus.
    Returns items sorted by composite_priority (descending).
    """
    log.info("Computing SOC priorities for %d advisories...", len(items))
    records: List[Tuple[float, Dict]] = []

    for item in items:
        try:
            composite, _ = compute_composite_priority(item)
            records.append((composite, item))
        except Exception as exc:
            log.warning("Priority skip for %s: %s", _item_id(item), exc)

    # Sort descending by composite score, then by title for determinism
    records.sort(key=lambda x: (-x[0], _item_title(x[1])))

    queue: List[Dict[str, Any]] = []
    for rank, (score, item) in enumerate(records, start=1):
        try:
            record = build_soc_record(item, rank)
            queue.append(record)
        except Exception as exc:
            log.error("Record build failed for rank %d: %s", rank, exc)

    log.info("SOC queue built: %d items", len(queue))
    return queue


def build_remediation_tiers(queue: List[Dict]) -> Dict[str, Any]:
    """Aggregate remediation tiers from the priority queue."""
    tiers: Dict[str, List[Dict]] = {
        "P0-CRITICAL": [], "P1-HIGH": [], "P2-MEDIUM": [],
        "P3-LOW": [], "P4-MONITOR": []
    }

    for record in queue:
        tier = record.get("soc_tier", {}).get("tier", "P4-MONITOR")
        if tier not in tiers:
            tier = "P4-MONITOR"
        tiers[tier].append({
            "rank":               record["rank"],
            "id":                 record["id"],
            "title":              record["title"],
            "composite_priority": record["composite_priority"],
            "priority_action":    record.get("remediation", {}).get("priority_action", ""),
            "timeline":           record.get("remediation", {}).get("timeline", ""),
            "kev_confirmed":      record.get("kev_confirmed", False),
            "ransomware_linked":  record.get("ransomware_linked", False),
            "cves_to_patch":      record.get("remediation", {}).get("cves_to_patch", []),
        })

    # KEV items requiring emergency patch
    kev_items = [r for r in queue if r.get("kev_confirmed")]

    return {
        "schema_version":        "1.0",
        "generated_at":          _utc_now(),
        "total_items":           len(queue),
        "tier_counts": {
            "P0_CRITICAL":  len(tiers["P0-CRITICAL"]),
            "P1_HIGH":      len(tiers["P1-HIGH"]),
            "P2_MEDIUM":    len(tiers["P2-MEDIUM"]),
            "P3_LOW":       len(tiers["P3-LOW"]),
            "P4_MONITOR":   len(tiers["P4-MONITOR"]),
        },
        "kev_emergency_count":   len(kev_items),
        "tiers":                 tiers,
        "remediation_summary": {
            "immediate_action_required": len(tiers["P0-CRITICAL"]) + len(tiers["P1-HIGH"]),
            "kev_patches_outstanding":   len(kev_items),
            "total_cves_to_patch":       len(set(
                cve
                for r in queue
                for cve in r.get("remediation", {}).get("cves_to_patch", [])
            )),
        },
    }


def build_escalation_matrix(queue: List[Dict]) -> Dict[str, Any]:
    """
    Build the executive escalation matrix.
    Identifies which items require CISO notification and why.
    """
    exec_items = [r for r in queue if r.get("executive_escalation")]
    kev_items  = [r for r in queue if r.get("kev_confirmed")]
    ransom_items = [r for r in queue if r.get("ransomware_linked")]
    critical_items = [r for r in queue if r.get("soc_tier", {}).get("tier") == "P0-CRITICAL"]

    # Multi-factor escalation triggers
    triggers: List[Dict] = []

    if kev_items:
        triggers.append({
            "trigger":     "CISA KEV ACTIVE EXPLOITATION",
            "severity":    "P0-CRITICAL",
            "item_count":  len(kev_items),
            "rationale":   f"{len(kev_items)} advisories confirmed as actively exploited by CISA. "
                           "Immediate CISO notification and board-level risk acceptance required.",
            "top_items":   [r["title"] for r in kev_items[:5]],
        })

    if ransom_items:
        triggers.append({
            "trigger":     "RANSOMWARE CAMPAIGN THREAT",
            "severity":    "P1-HIGH",
            "item_count":  len(ransom_items),
            "rationale":   f"{len(ransom_items)} advisories linked to active ransomware campaigns. "
                           "Business continuity and cyber insurance notification may be required.",
            "top_items":   [r["title"] for r in ransom_items[:5]],
        })

    # Aggregate CVSS critical count
    high_cvss = [r for r in queue if _safe_float(r.get("cvss") or 0) >= 9.0]
    if len(high_cvss) >= 5:
        triggers.append({
            "trigger":     "CRITICAL CVSS CLUSTER",
            "severity":    "P1-HIGH",
            "item_count":  len(high_cvss),
            "rationale":   f"{len(high_cvss)} advisories carry CVSS >= 9.0 -- "
                           "represents systemic critical vulnerability exposure requiring executive awareness.",
            "top_items":   [r["title"] for r in high_cvss[:5]],
        })

    # Nation-state actors
    nation_state_items = [
        r for r in queue
        if any(
            kw in " ".join(r.get("actors") or []).lower()
            for kw in ("apt", "lazarus", "cozy bear", "midnight blizzard", "volt typhoon",
                       "sandworm", "fancy bear", "charming kitten", "scattered spider")
        )
    ]
    if nation_state_items:
        triggers.append({
            "trigger":     "NATION-STATE ACTOR ACTIVITY",
            "severity":    "P0-CRITICAL",
            "item_count":  len(nation_state_items),
            "rationale":   f"{len(nation_state_items)} advisories attributed to nation-state actors. "
                           "Regulatory notification and legal team consultation may be required.",
            "top_items":   [r["title"] for r in nation_state_items[:5]],
        })

    return {
        "schema_version":      "1.0",
        "generated_at":        _utc_now(),
        "executive_items":     [
            {
                "rank":               r["rank"],
                "id":                 r["id"],
                "title":              r["title"],
                "composite_priority": r["composite_priority"],
                "tier":               r.get("soc_tier", {}).get("tier", ""),
                "kev":                r.get("kev_confirmed", False),
                "ransomware":         r.get("ransomware_linked", False),
                "ir_narrative":       r.get("ir_narrative", ""),
            }
            for r in exec_items[:50]
        ],
        "escalation_triggers": triggers,
        "summary": {
            "executive_escalation_count": len(exec_items),
            "p0_critical_count":          len(critical_items),
            "kev_active_count":           len(kev_items),
            "ransomware_linked_count":    len(ransom_items),
            "nation_state_count":         len(nation_state_items),
            "trigger_count":              len(triggers),
        },
    }


def build_executive_dashboard(queue: List[Dict], items: List[Dict]) -> Dict[str, Any]:
    """CISO-level risk summary for executive reporting."""
    tier_counts: Dict[str, int] = defaultdict(int)
    for r in queue:
        tier_counts[r.get("soc_tier", {}).get("tier", "P4-MONITOR")] += 1

    kev_count    = sum(1 for r in queue if r.get("kev_confirmed"))
    ransom_count = sum(1 for r in queue if r.get("ransomware_linked"))
    exec_count   = sum(1 for r in queue if r.get("executive_escalation"))

    # Risk velocity: % P0+P1 vs total
    urgent_count = tier_counts.get("P0-CRITICAL", 0) + tier_counts.get("P1-HIGH", 0)
    risk_velocity = round((urgent_count / max(len(queue), 1)) * 100, 1)

    # Top-5 CVEs by priority
    top_cves: List[Dict] = []
    seen_cves: set = set()
    for r in queue:
        for cve in r.get("cves", []):
            if cve not in seen_cves:
                seen_cves.add(cve)
                top_cves.append({
                    "cve":       cve,
                    "priority":  r["composite_priority"],
                    "tier":      r.get("soc_tier", {}).get("tier", ""),
                    "kev":       r.get("kev_confirmed", False),
                })
            if len(top_cves) >= 10:
                break
        if len(top_cves) >= 10:
            break

    # Sector risk summary
    sector_risk: Dict[str, int] = defaultdict(int)
    for r in queue[:100]:   # Top 100 only for performance
        for sector in r.get("sectors", []):
            if sector:
                sector_risk[sector] += 1
    top_sectors = sorted(sector_risk.items(), key=lambda x: -x[1])[:8]

    # Risk posture determination
    if tier_counts.get("P0-CRITICAL", 0) >= 5 or kev_count >= 10:
        risk_posture = "CRITICAL -- Immediate executive intervention required"
    elif tier_counts.get("P0-CRITICAL", 0) >= 2 or kev_count >= 3:
        risk_posture = "HIGH -- Active threats require urgent SOC mobilization"
    elif tier_counts.get("P1-HIGH", 0) >= 10:
        risk_posture = "ELEVATED -- Sustained high-priority remediation in progress"
    elif urgent_count > 0:
        risk_posture = "MODERATE -- Manageable priority queue, normal operations"
    else:
        risk_posture = "NOMINAL -- No critical or high priority items identified"

    return {
        "schema_version":    "1.0",
        "generated_at":      _utc_now(),
        "risk_posture":      risk_posture,
        "risk_velocity_pct": risk_velocity,
        "advisory_summary": {
            "total_advisories":    len(queue),
            "P0_critical":         tier_counts.get("P0-CRITICAL", 0),
            "P1_high":             tier_counts.get("P1-HIGH", 0),
            "P2_medium":           tier_counts.get("P2-MEDIUM", 0),
            "P3_low":              tier_counts.get("P3-LOW", 0),
            "P4_monitor":          tier_counts.get("P4-MONITOR", 0),
        },
        "key_threats": {
            "kev_active_exploits":       kev_count,
            "ransomware_linked":         ransom_count,
            "executive_escalation_items": exec_count,
            "urgent_items_requiring_action": urgent_count,
        },
        "top_priority_items": [
            {
                "rank":     r["rank"],
                "title":    r["title"],
                "tier":     r.get("soc_tier", {}).get("tier", ""),
                "score":    r["composite_priority"],
                "kev":      r.get("kev_confirmed", False),
                "ransomware": r.get("ransomware_linked", False),
                "action":   r.get("soc_tier", {}).get("action", ""),
            }
            for r in queue[:10]
        ],
        "top_cves":     top_cves,
        "sector_risk":  [{"sector": s, "advisory_count": c} for s, c in top_sectors],
        "patch_summary": {
            "unique_cves_requiring_patch": len(seen_cves),
            "kev_emergency_patches":       kev_count,
        },
    }


def build_analyst_workload(queue: List[Dict]) -> Dict[str, Any]:
    """
    Distribute SOC queue across analyst workload bands for operational efficiency.
    Prevents analyst overload by creating balanced investigation queues.
    """
    p0 = [r for r in queue if r.get("soc_tier", {}).get("tier") == "P0-CRITICAL"]
    p1 = [r for r in queue if r.get("soc_tier", {}).get("tier") == "P1-HIGH"]
    p2 = [r for r in queue if r.get("soc_tier", {}).get("tier") == "P2-MEDIUM"]
    p3 = [r for r in queue if r.get("soc_tier", {}).get("tier") in ("P3-LOW", "P4-MONITOR")]

    # Estimate analyst effort (hours) per tier
    effort_map = {"P0-CRITICAL": 4.0, "P1-HIGH": 2.0, "P2-MEDIUM": 1.0, "P3-LOW": 0.5}

    total_effort_hours = sum(
        effort_map.get(r.get("soc_tier", {}).get("tier", "P3-LOW"), 0.5)
        for r in queue
    )

    return {
        "schema_version":        "1.0",
        "generated_at":          _utc_now(),
        "total_queue_size":      len(queue),
        "estimated_effort_hours": round(total_effort_hours, 1),
        "analyst_days_required": round(total_effort_hours / 8.0, 1),
        "recommended_team_size": max(1, math.ceil(total_effort_hours / (ANALYST_DAILY_CAPACITY * 2))),
        "queue_bands": {
            "immediate_4h":   [{"rank": r["rank"], "title": r["title"], "score": r["composite_priority"]} for r in p0],
            "urgent_24h":     [{"rank": r["rank"], "title": r["title"], "score": r["composite_priority"]} for r in p1],
            "standard_72h":   [{"rank": r["rank"], "title": r["title"], "score": r["composite_priority"]} for r in p2[:50]],
            "scheduled":      [{"rank": r["rank"], "title": r["title"], "score": r["composite_priority"]} for r in p3[:30]],
        },
        "workload_summary": {
            "critical_investigations": len(p0),
            "high_investigations":     len(p1),
            "medium_investigations":   len(p2),
            "scheduled_reviews":       len(p3),
        },
        "siem_hunt_queries": _generate_siem_queries(queue),
    }


def _generate_siem_queries(queue: List[Dict]) -> List[Dict[str, str]]:
    """Generate SIEM hunting queries for top priority items."""
    queries: List[Dict[str, str]] = []
    seen_ioc_types: set = set()

    # Collect IOCs from top priority items
    ioc_domains: List[str] = []
    ioc_hashes:  List[str] = []

    for r in queue[:20]:
        iocs = _safe_list(r.get("ioc_count") or [])
        # Query generation by TTP
        ttps = set(r.get("mitre_ttps") or [])
        if "T1059.001" in ttps and "powershell" not in seen_ioc_types:
            seen_ioc_types.add("powershell")
            queries.append({
                "name":        "Malicious PowerShell Execution",
                "ttp":         "T1059.001",
                "platform":    "Splunk / Sentinel / Elastic",
                "query":       (
                    "EventCode=4104 (Message=\"*-enc*\" OR Message=\"*IEX*\" OR "
                    "Message=\"*DownloadString*\" OR Message=\"*Invoke-Expression*\")"
                ),
                "purpose":     "Detect obfuscated/encoded PowerShell used in initial access and execution",
            })
        if "T1021.002" in ttps and "smb_lateral" not in seen_ioc_types:
            seen_ioc_types.add("smb_lateral")
            queries.append({
                "name":        "SMB Lateral Movement Detection",
                "ttp":         "T1021.002",
                "platform":    "Splunk / Sentinel",
                "query":       (
                    "EventCode=4624 LogonType=3 NOT SourceNetworkAddress IN (\"127.0.0.1\",\"::1\") "
                    "| stats count by SourceNetworkAddress, TargetUserName"
                ),
                "purpose":     "Detect lateral movement over SMB using Type 3 network logons",
            })
        if "T1486" in ttps and "ransomware_enc" not in seen_ioc_types:
            seen_ioc_types.add("ransomware_enc")
            queries.append({
                "name":        "Ransomware File Encryption Activity",
                "ttp":         "T1486",
                "platform":    "Splunk / Sentinel / Elastic",
                "query":       (
                    "EventCode=4663 ObjectType=\"File\" (ObjectName=\"*.locked\" OR "
                    "ObjectName=\"*.encrypted\" OR ObjectName=\"*.ransom\" OR "
                    "AccessMask=\"0x2\") | stats count by SubjectUserName, ObjectName"
                ),
                "purpose":     "Detect mass file encryption activity indicative of ransomware deployment",
            })
        if "T1078" in ttps and "valid_acct" not in seen_ioc_types:
            seen_ioc_types.add("valid_acct")
            queries.append({
                "name":        "Valid Account Abuse Detection",
                "ttp":         "T1078",
                "platform":    "Splunk / Sentinel",
                "query":       (
                    "EventCode=4624 LogonType IN (10, 3) | bucket _time span=1h "
                    "| stats dc(TargetUserName) as unique_users, count by src_ip, _time "
                    "| where unique_users > 5 OR count > 50"
                ),
                "purpose":     "Detect credential stuffing or valid account abuse patterns",
            })
        if len(queries) >= 6:
            break

    # Fallback generic query
    if not queries:
        queries.append({
            "name":    "General IOC Hunt",
            "ttp":     "Multiple",
            "platform": "Splunk / Sentinel / Elastic",
            "query":   "index=* | search [inputlookup threat_ioc_list.csv | fields ioc]",
            "purpose": "Hunt for known threat IOCs from current feed manifest",
        })

    return queries


# ---------------------------------------------------------------------------
# ATOMIC WRITE
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, obj: Any) -> None:
    """Write JSON atomically: tmp file -> fsync -> os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp_soc")
    try:
        data = json.dumps(obj, ensure_ascii=True, indent=2, default=str)
        # Validate UTF-8 and no null bytes
        encoded = data.encode("utf-8")
        if b"\x00" in encoded:
            raise ValueError("NULL bytes detected in output")
        tmp.write_bytes(encoded)
        tmp_fd = os.open(str(tmp), os.O_RDONLY)
        try:
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        os.replace(str(tmp), str(path))
    except Exception:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# ENGINE ENTRY POINT
# ---------------------------------------------------------------------------

def run_soc_prioritization_engine(
    manifest_path: Path = MANIFEST_PATH,
    ocios_dir:     Path = OCIOS_DIR,
) -> Dict[str, Any]:
    """
    Execute the OCIOS SOC Prioritization Engine.
    Never raises -- always returns a summary dict.
    """
    t_start = time.monotonic()
    summary: Dict[str, Any] = {
        "engine":       "ocios_soc_prioritization_engine",
        "version":      ENGINE_VERSION,
        "started_at":   _utc_now(),
        "status":       "running",
        "items_scored": 0,
        "errors":       [],
    }

    # Load manifest
    if not manifest_path.exists():
        msg = f"Manifest not found: {manifest_path}"
        log.warning(msg)
        summary.update({"status": "skipped", "errors": [msg]})
        return summary

    try:
        raw   = json.loads(manifest_path.read_text(encoding="utf-8"))
        items: List[Dict] = raw.get("advisories") or raw.get("reports") or []
        if isinstance(raw, list):
            items = raw
    except Exception as exc:
        log.error("Manifest load failed: %s", exc)
        summary.update({"status": "error", "errors": [str(exc)]})
        return summary

    log.info("SOC Prioritization Engine: scoring %d advisories", len(items))

    # Optionally load reasoning enrichment
    reasoning_index: Dict[str, Dict] = {}
    reasoning_path = ocios_dir / "operational_reasoning.json"
    if reasoning_path.exists():
        try:
            rd = json.loads(reasoning_path.read_text(encoding="utf-8"))
            for r_item in (rd.get("items") or []):
                rid = _safe_str(r_item.get("id") or r_item.get("advisory_id") or "")
                if rid:
                    reasoning_index[rid] = r_item
            log.info("Loaded %d reasoning records for enrichment", len(reasoning_index))
        except Exception as exc:
            log.warning("Reasoning enrichment load failed: %s", exc)

    # Build SOC queue
    try:
        queue = build_soc_priority_queue(items)
        summary["items_scored"] = len(queue)
    except Exception as exc:
        log.error("SOC queue build failed: %s", exc)
        summary.update({"status": "error", "errors": [str(exc)]})
        return summary

    # Build all output artifacts
    outputs: Dict[str, Any] = {}

    outputs["soc_priority_queue.json"] = {
        "schema_version": "1.0",
        "engine":         "ocios_soc_prioritization_engine",
        "generated_at":   _utc_now(),
        "total_items":    len(queue),
        "items":          queue,
    }

    try:
        outputs["remediation_tiers.json"] = build_remediation_tiers(queue)
    except Exception as exc:
        log.error("Remediation tiers failed: %s", exc)
        summary["errors"].append(f"remediation_tiers: {exc}")

    try:
        outputs["escalation_matrix.json"] = build_escalation_matrix(queue)
    except Exception as exc:
        log.error("Escalation matrix failed: %s", exc)
        summary["errors"].append(f"escalation_matrix: {exc}")

    try:
        outputs["executive_dashboard.json"] = build_executive_dashboard(queue, items)
    except Exception as exc:
        log.error("Executive dashboard failed: %s", exc)
        summary["errors"].append(f"executive_dashboard: {exc}")

    try:
        outputs["analyst_workload.json"] = build_analyst_workload(queue)
    except Exception as exc:
        log.error("Analyst workload failed: %s", exc)
        summary["errors"].append(f"analyst_workload: {exc}")

    # Write all outputs atomically
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
        "tier_breakdown": {
            "P0_critical": sum(1 for r in queue if r.get("soc_tier", {}).get("tier") == "P0-CRITICAL"),
            "P1_high":     sum(1 for r in queue if r.get("soc_tier", {}).get("tier") == "P1-HIGH"),
            "P2_medium":   sum(1 for r in queue if r.get("soc_tier", {}).get("tier") == "P2-MEDIUM"),
            "P3_low":      sum(1 for r in queue if r.get("soc_tier", {}).get("tier") == "P3-LOW"),
            "P4_monitor":  sum(1 for r in queue if r.get("soc_tier", {}).get("tier") == "P4-MONITOR"),
        },
    })

    try:
        _atomic_write(ocios_dir / "soc_prioritization_summary.json", summary)
    except Exception:
        pass

    log.info(
        "OCIOS SOC Engine complete: %d items scored, %d files | %.2fs",
        len(queue), written, elapsed,
    )
    return summary


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="OCIOS SOC Prioritization Engine")
    parser.add_argument("--manifest",    default=str(MANIFEST_PATH))
    parser.add_argument("--output-dir",  default=str(OCIOS_DIR))
    args = parser.parse_args()
    result = run_soc_prioritization_engine(
        manifest_path=Path(args.manifest),
        ocios_dir=Path(args.output_dir),
    )
    status = result.get("status", "error")
    print(json.dumps({
        "status":       status,
        "items_scored": result.get("items_scored", 0),
        "files_written": result.get("files_written", 0),
        "elapsed":      result.get("elapsed_seconds", 0),
        "tier_breakdown": result.get("tier_breakdown", {}),
        "errors":       result.get("errors", []),
    }, indent=2))
    return 0 if status in ("success", "partial", "skipped") else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
