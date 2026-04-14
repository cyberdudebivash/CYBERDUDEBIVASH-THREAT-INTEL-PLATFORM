#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL APEX v2.0 — Intelligence Evolution Engine
===================================================================
ADAPTIVE · PRIORITIZED · TIME-AWARE · SELF-IMPROVING

Pipeline position (Stage 2.7):
  sentinel_blogger → v70 → v74 → APEX v1 (Stage 2.6) → [THIS: Stage 2.7] → manifest → API → dashboard

Design mandate:
  Transform the platform from static intelligence generation into an adaptive,
  prioritized, time-aware, self-improving intelligence system. TOP 0.1% global standard.

Architecture:
  - ADDITIVE ONLY  — never modifies feed_manifest.json or apex_enriched_manifest.json
  - ZERO REGRESSION — each module is independently guarded; one failure ≠ pipeline failure
  - FEATURE-FLAG CONTROLLED — every module and gate is independently switchable
  - BACKWARD COMPATIBLE — all new outputs in new files; existing consumers unaffected

Module Registry (7 modules):
  Module 1: Threat Priority Scoring Engine     → threat_priority
  Module 2: Temporal Intelligence Engine       → threat_timeline
  Module 3: Feedback & Learning Engine         → feedback_signal
  Module 4: Intelligence Aggregation Engine    → platform_intelligence_summary (report-level)
  Module 5: API Evolution Layer                → api/apex_v2/*.json (4 endpoints)
  Module 6: Dashboard Prioritization Engine    → api/apex_v2/dashboard_intel.json
  Module 7: Validation Extension               → apex_v2_gate fields on each item

Outputs:
  data/apex_v2_manifest.json              — all items enriched with 3 per-item v2 blocks
  data/apex_v2_strategic_report.json      — platform-level strategic intelligence
  api/apex_v2/critical.json               — /api/v1/intel/critical
  api/apex_v2/trending.json               — /api/v1/intel/trending
  api/apex_v2/timeline.json               — /api/v1/intel/timeline
  api/apex_v2/priority.json               — /api/v1/intel/priority
  api/apex_v2/dashboard_intel.json        — dashboard progressive enhancement data
  data/health/apex_v2_audit.json          — execution audit log

Version: 2.0.0
Author: CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering
"""

import json
import re
import sys
import hashlib
import shutil
import logging
import math
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [APEX-V2] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("APEX-V2")

# ── Paths ─────────────────────────────────────────────────────────────────────
_THIS = Path(__file__).resolve()
REPO  = _THIS.parent.parent

# Input manifest preference chain (v2 prefers v1 output)
MANIFEST_CANDIDATES = [
    REPO / "data" / "apex_enriched_manifest.json",    # APEX v1 output (preferred)
    REPO / "data" / "validated_manifest.json",
    REPO / "data" / "stix" / "feed_manifest.json",
    REPO / "data" / "feed_manifest.json",
]

FEATURE_FLAGS_PATH         = REPO / "config" / "feature_flags.json"
APEX_V2_MANIFEST           = REPO / "data" / "apex_v2_manifest.json"
APEX_V2_STRATEGIC_REPORT   = REPO / "data" / "apex_v2_strategic_report.json"
APEX_V2_AUDIT              = REPO / "data" / "health" / "apex_v2_audit.json"
API_V2_DIR                 = REPO / "api" / "apex_v2"

ENGINE_VERSION = "2.0.0"
NOW_UTC        = datetime.now(timezone.utc)
NOW_ISO        = NOW_UTC.isoformat()

# ── Sector / industry keyword map ─────────────────────────────────────────────
_SECTOR_KEYWORDS: Dict[str, List[str]] = {
    "Finance":          ["bank", "financial", "fintech", "payment", "swift", "trading", "insurance", "credit"],
    "Healthcare":       ["hospital", "health", "medical", "patient", "clinical", "pharma", "hipaa", "ehr"],
    "Government":       ["government", "federal", "military", "defense", "dod", "agency", "treasury", "nato"],
    "Energy":           ["energy", "power", "oil", "gas", "utility", "grid", "nuclear", "pipeline"],
    "Technology":       ["software", "saas", "cloud", "tech", "it services", "msp", "developer", "cicd"],
    "Manufacturing":    ["manufacturing", "industrial", "scada", "ics", "ot ", "supply chain", "logistics"],
    "Retail":           ["retail", "ecommerce", "pos", "merchant", "customer data", "shopping"],
    "Telecommunications": ["telecom", "isp", "carrier", "network provider", "mobile", "5g"],
    "Education":        ["university", "school", "education", "academic", "student"],
    "Critical Infrastructure": ["critical infrastructure", "water", "transportation", "airport"],
}

# ── Actor sophistication classification ───────────────────────────────────────
_APT_KEYWORDS = [
    "apt", "nation-state", "state-sponsored", "silk typhoon", "volt typhoon",
    "salt typhoon", "lazarus", "cozy bear", "fancy bear", "apt28", "apt29",
    "apt41", "unc5221", "unc5337", "mandiant", "storm-0", "midnight blizzard",
    "nobelium", "sandworm", "turla", "equation group", "chinese apt",
    "north korean", "russian apt", "iranian apt",
]
_ECRIME_KEYWORDS = [
    "lockbit", "blackcat", "alphv", "cl0p", "clop", "play ransomware",
    "black basta", "revil", "conti", "ransomware group", "cybercrime",
    "fin7", "fin11", "ta505", "scattered spider", "storm-0506",
    "raas", "ransomware-as-a-service", "extortion",
]
_COMMODITY_KEYWORDS = [
    "script kiddie", "commodity malware", "botnet", "generic exploit",
    "mass scanning", "automated", "opportunistic",
]

# ── Internet-facing system patterns ──────────────────────────────────────────
_INTERNET_FACING = [
    "vpn", "firewall", "gateway", "remote access", "web application",
    "api gateway", "load balancer", "exchange", "outlook web", "sap portal",
    "citrix", "f5", "palo alto", "fortinet", "ivanti", "pulse", "cisco asa",
    "rdp", "remote desktop", "public-facing", "internet-exposed", "perimeter",
    "edge device", "owa", "webmail", "confluence", "jira", "gitlab",
    "jenkins", "teamcity", "nginx", "apache", "iis",
]
_CRITICAL_SYSTEM = [
    "active directory", "domain controller", "sap", "erp", "iam", "identity",
    "pam", "beyondtrust", "cyberark", "okta", "azure ad", "entra id",
    "vmware vcenter", "esxi", "hypervisor", "backup", "veeam",
    "database", "oracle", "mssql", "postgresql", "redis", "elasticsearch",
    "kubernetes", "docker", "container orchestration", "ci/cd",
    "security tool", "siem", "edr", "antivirus",
]


# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _atomic_write(path: Path, obj: Any, indent: int = 2) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = Path(str(path) + ".tmp")
    try:
        content = json.dumps(obj, ensure_ascii=False, indent=indent)
        tmp.write_text(content, encoding="utf-8")
        shutil.move(str(tmp), str(path))
        return path.stat().st_size
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def _load_flags() -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        # v2 master switch
        "ENABLE_APEX_V2_ENGINE":           True,
        # Per-module switches
        "APEX_V2_MODULE_PRIORITY":         True,
        "APEX_V2_MODULE_TEMPORAL":         True,
        "APEX_V2_MODULE_FEEDBACK":         True,
        "APEX_V2_MODULE_AGGREGATION":      True,
        "APEX_V2_MODULE_API":              True,
        "APEX_V2_MODULE_DASHBOARD":        True,
        "APEX_V2_MODULE_VALIDATION":       True,
        # Gate flags (all False by default — zero regression)
        "APEX_V2_REQUIRE_PRIORITY_GATE":   False,
        "APEX_V2_REQUIRE_TIMELINE_GATE":   False,
        "APEX_V2_REQUIRE_FEEDBACK_GATE":   False,
        # Tuning
        "APEX_V2_MAX_ITEMS":               2000,
        "APEX_V2_TOP_CRITICAL_COUNT":      10,
        "APEX_V2_TOP_TRENDING_COUNT":      15,
        "APEX_V2_TRENDING_WINDOW_DAYS":    30,
    }
    try:
        raw = json.loads(FEATURE_FLAGS_PATH.read_text(encoding="utf-8"))
        defaults.update(raw)
    except Exception as e:
        log.warning(f"Feature flags load failed ({e}) — using defaults")
    return defaults


def _load_manifest() -> Tuple[List[Dict], str]:
    """Load manifest from preference chain. Returns (items, source_name)."""
    for path in MANIFEST_CANDIDATES:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            items: List[Dict] = []
            if isinstance(raw, list):
                items = raw
            else:
                for key in ("advisories", "entries", "items", "data"):
                    v = raw.get(key)
                    if isinstance(v, list) and v:
                        items = v
                        break
            if items:
                v1_count = sum(1 for i in items if i.get("_apex_enriched"))
                log.info(f"Loaded {len(items)} items from {path.name} "
                         f"({v1_count} APEX v1 enriched)")
                return items, path.name
        except Exception as e:
            log.warning(f"Manifest parse error ({path.name}): {e}")
    return [], "none"


def _get_text(item: Dict) -> str:
    return " ".join(filter(None, [
        item.get("title", ""),
        item.get("description", ""),
        item.get("category", ""),
        item.get("detect", ""),
        item.get("analyze", ""),
        item.get("respond", ""),
    ])).lower()


def _get_cvss(item: Dict) -> float:
    for f in ("risk_score", "cvss", "cvss_score", "cvss3_score"):
        v = item.get(f)
        if v is not None:
            try:
                return float(v)
            except (ValueError, TypeError):
                pass
    return 0.0


def _is_kev(item: Dict) -> bool:
    return bool(item.get("kev") or item.get("kev_present") or item.get("cisa_kev"))


def _parse_date(item: Dict) -> Optional[datetime]:
    """Parse published date from any available field."""
    for field in ("date_published", "_isoDate", "published", "updated", "date", "created"):
        raw = item.get(field)
        if not raw or not isinstance(raw, str):
            continue
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(raw[:25].rstrip("Z"), fmt.rstrip("Z"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        # ISO format fallback
        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            pass
    return None


def _get_v1_field(item: Dict, block: str, field: str, default: Any = None) -> Any:
    """Safe accessor for APEX v1 enrichment blocks."""
    return item.get(block, {}).get(field, default)


def _item_id(item: Dict) -> str:
    return (item.get("stix_id") or item.get("id") or
            hashlib.md5((item.get("title") or "").encode()).hexdigest()[:12])


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1: THREAT PRIORITY SCORING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

# Weight table (totals 100)
_PRIORITY_WEIGHTS = {
    "kev":              30,   # KEV presence
    "cvss":             25,   # CVSS severity
    "exploit_maturity": 20,   # In-the-wild > PoC > theoretical
    "actor_sophist":    15,   # APT vs eCrime vs commodity
    "exposure":         10,   # Internet-facing + critical system
}


def _score_kev(item: Dict) -> Tuple[int, str]:
    if _is_kev(item):
        return 30, "CISA KEV confirmed (active exploitation)"
    # Check v1 evidence
    exploit_st = _get_v1_field(item, "evidence_validation", "exploit_status", "UNVERIFIED")
    if exploit_st == "ACTIVE_OBSERVED":
        return 22, "Active exploitation observed (not yet KEV-listed)"
    return 0, "No KEV or confirmed exploitation"


def _score_cvss(item: Dict) -> Tuple[int, str]:
    cvss = _get_cvss(item)
    if cvss >= 9.5:   return 25, f"CVSS {cvss:.1f} — maximum severity"
    if cvss >= 9.0:   return 23, f"CVSS {cvss:.1f} — critical"
    if cvss >= 8.0:   return 18, f"CVSS {cvss:.1f} — high-critical"
    if cvss >= 7.0:   return 14, f"CVSS {cvss:.1f} — high"
    if cvss >= 5.5:   return 9,  f"CVSS {cvss:.1f} — medium"
    if cvss >= 4.0:   return 5,  f"CVSS {cvss:.1f} — medium-low"
    if cvss > 0:      return 2,  f"CVSS {cvss:.1f} — low"
    return 0, "No CVSS score available"


def _score_exploit_maturity(item: Dict) -> Tuple[int, str]:
    text        = _get_text(item)
    exploit_st  = _get_v1_field(item, "evidence_validation", "exploit_status", "UNVERIFIED")
    kev         = _is_kev(item)

    if kev or exploit_st == "ACTIVE_CONFIRMED":
        if any(k in text for k in ("ransomware", "mass exploit", "widespread")):
            return 20, "Mass in-the-wild exploitation (ransomware/widespread)"
        return 18, "In-the-wild exploitation confirmed"

    if exploit_st == "ACTIVE_OBSERVED":
        return 15, "Active exploitation observed"

    if any(k in text for k in ("poc", "proof of concept", "exploit available",
                                "metasploit", "exploit-db", "published exploit")):
        return 10, "PoC or public exploit available"

    if any(k in text for k in ("trivial", "easy to exploit", "no auth",
                                "unauthenticated", "one-click")):
        return 8, "Low exploit complexity — trivially exploitable"

    if any(k in text for k in ("complex", "requires authentication",
                                "local access required")):
        return 4, "Complex or authenticated exploitation required"

    return 5, "Exploit maturity unknown — assess conservatively"


def _score_actor_sophistication(item: Dict) -> Tuple[int, str]:
    text = _get_text(item)

    # Pull from APEX v1 analyst insight if available
    vuln_class = _get_v1_field(item, "analyst_insight", "vulnerability_class", "").lower()

    if any(k in text for k in _APT_KEYWORDS):
        return 15, "Nation-state / APT threat actor confirmed"

    if any(k in text for k in _ECRIME_KEYWORDS):
        return 12, "Organized cybercrime / RaaS operator"

    if vuln_class in ("rce", "auth_bypass", "supply_chain"):
        return 10, f"High-value vulnerability class ({vuln_class.upper()}) — likely APT interest"

    if any(k in text for k in _COMMODITY_KEYWORDS):
        return 5, "Commodity threat actor"

    if _is_kev(item):
        return 10, "KEV exploitation implies organized threat actor activity"

    return 7, "Threat actor sophistication unassessed — moderate assumed"


def _score_exposure(item: Dict) -> Tuple[int, str]:
    text = _get_text(item)

    internet_facing = any(k in text for k in _INTERNET_FACING)
    critical_system = any(k in text for k in _CRITICAL_SYSTEM)

    if internet_facing and critical_system:
        return 10, "Internet-facing critical system — maximum exposure"
    if internet_facing:
        return 8,  "Internet-facing system — direct external exposure"
    if critical_system:
        return 6,  "Critical internal system — high lateral movement value"
    return 3, "Internal or unclassified exposure"


def module_threat_priority(item: Dict) -> Dict:
    """
    Module 1: Threat Priority Scoring Engine
    Composite 0-100 score with factor-level breakdown and reasoning.
    """
    kev_pts, kev_reason      = _score_kev(item)
    cvss_pts, cvss_reason    = _score_cvss(item)
    expl_pts, expl_reason    = _score_exploit_maturity(item)
    actor_pts, actor_reason  = _score_actor_sophistication(item)
    exp_pts, exp_reason      = _score_exposure(item)

    total = kev_pts + cvss_pts + expl_pts + actor_pts + exp_pts

    # Apply v1 confidence multiplier (bonus for high-reliability evidence)
    reliability = _get_v1_field(item, "evidence_validation", "reliability_score", "LOW")
    ev_conf     = _get_v1_field(item, "evidence_validation", "evidence_confidence", "UNVERIFIED")
    if reliability == "HIGH" and ev_conf == "CONFIRMED":
        total = min(100, total + 3)
    elif reliability == "LOW":
        total = max(0, total - 5)

    # Priority level classification
    if total >= 85:   level = "CRITICAL"
    elif total >= 65: level = "HIGH"
    elif total >= 40: level = "MEDIUM"
    else:             level = "LOW"

    # Build reasoning string (concise, CISO-readable)
    reasons = [r for r in [kev_reason, cvss_reason, expl_reason, actor_reason, exp_reason]
               if "No" not in r and "unknown" not in r.lower() and "unassessed" not in r.lower()]
    reasoning = "; ".join(reasons[:3]) or "Composite score below critical threshold"

    return {
        "score":   total,
        "level":   level,
        "reasoning": reasoning,
        "scoring_breakdown": {
            "kev_score":              kev_pts,
            "cvss_score":             cvss_pts,
            "exploit_maturity_score": expl_pts,
            "actor_sophistication_score": actor_pts,
            "exposure_score":         exp_pts,
            "evidence_bonus":         total - (kev_pts + cvss_pts + expl_pts + actor_pts + exp_pts),
        },
        "factor_reasoning": {
            "kev":              kev_reason,
            "cvss":             cvss_reason,
            "exploit_maturity": expl_reason,
            "actor":            actor_reason,
            "exposure":         exp_reason,
        },
        "priority_engine": "SENTINEL-APEX-V2-PRIORITY",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2: TEMPORAL INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _estimate_exploitation_start(
    discovered: datetime,
    kev: bool,
    exploit_status: str,
    cvss: float,
) -> Optional[datetime]:
    """
    Estimate when active exploitation likely began, based on available signals.
    Uses heuristic delay models from real-world exploitation timelines.
    """
    if kev or exploit_status in ("ACTIVE_CONFIRMED", "ACTIVE_OBSERVED"):
        # Real-world: KEV items are typically exploited within 7 days of disclosure
        delay_days = 3 if cvss >= 9.0 else 7
        return discovered + timedelta(days=delay_days)
    if cvss >= 9.0:
        # High-severity: attackers typically develop exploits within 14 days
        return discovered + timedelta(days=14)
    if cvss >= 7.0:
        return discovered + timedelta(days=30)
    return None


def _estimate_peak_activity(
    exploit_start: Optional[datetime],
    kev: bool,
    cvss: float,
) -> Optional[datetime]:
    """
    Estimate peak exploitation activity window.
    Based on observed patterns: KEV items peak 2-4 weeks post-disclosure.
    """
    if exploit_start is None:
        return None
    if kev and cvss >= 9.0:
        return exploit_start + timedelta(days=14)
    if kev:
        return exploit_start + timedelta(days=21)
    return exploit_start + timedelta(days=30)


def _compute_lifecycle_stage(
    discovered: Optional[datetime],
    kev: bool,
    exploit_status: str,
    priority_score: int,
) -> Tuple[str, str]:
    """
    Returns (lifecycle_stage, activity_status).
    Stages: EMERGING → ACTIVE → PEAK → DECLINING → HISTORICAL
    """
    if discovered is None:
        return "UNKNOWN", "UNKNOWN"

    age_days = (NOW_UTC - discovered).days

    # KEV + fresh = PEAK
    if kev and age_days <= 30:
        return "PEAK", "ACTIVE"

    # KEV + 30-90 days = ACTIVE
    if kev and age_days <= 90:
        return "ACTIVE", "ACTIVE"

    # KEV + old = DECLINING
    if kev and age_days <= 180:
        return "DECLINING", "DECLINING"

    # KEV + very old = HISTORICAL
    if kev and age_days > 180:
        return "HISTORICAL", "DECLINING"

    # Non-KEV but very fresh (< 7 days) = EMERGING
    if age_days <= 7:
        return "EMERGING", "ACTIVE"

    # Non-KEV, recent, high priority = ACTIVE
    if age_days <= 30 and priority_score >= 60:
        return "ACTIVE", "ACTIVE"

    # Non-KEV, 30-60 days = ACTIVE or DECLINING
    if age_days <= 60:
        if exploit_status in ("ACTIVE_CONFIRMED", "ACTIVE_OBSERVED"):
            return "ACTIVE", "ACTIVE"
        return "DECLINING", "DECLINING"

    # Old items
    if age_days <= 180:
        return "DECLINING", "DECLINING"

    return "HISTORICAL", "DECLINING"


def module_temporal_intelligence(item: Dict, priority_score: int = 0) -> Dict:
    """
    Module 2: Temporal Intelligence Engine
    Tracks threat evolution, lifecycle stage, and time-based urgency.
    """
    discovered    = _parse_date(item)
    kev           = _is_kev(item)
    exploit_status = _get_v1_field(item, "evidence_validation", "exploit_status", "UNVERIFIED")
    cvss          = _get_cvss(item)

    # Dates as ISO strings
    discovered_iso    = discovered.strftime("%Y-%m-%d") if discovered else None
    age_days          = (NOW_UTC - discovered).days if discovered else None

    exploit_start     = _estimate_exploitation_start(discovered, kev, exploit_status, cvss) if discovered else None
    peak_activity     = _estimate_peak_activity(exploit_start, kev, cvss)
    lifecycle, status = _compute_lifecycle_stage(discovered, kev, exploit_status, priority_score)

    # Patch window: time between disclosure and patch (estimated from KEV pattern)
    patch_window_days: Optional[int] = None
    if discovered and kev:
        # Industry average: KEV patch deployment takes 15-30 days
        patch_window_days = 15 if cvss >= 9.0 else 30

    # Urgency factor (0.0 – 1.0) — decays as threat ages
    if age_days is not None:
        if lifecycle in ("EMERGING", "PEAK") and status == "ACTIVE":
            urgency_factor = 1.0
        elif lifecycle == "ACTIVE":
            # Linear decay from 1.0 at disclosure to 0.6 at 90 days
            urgency_factor = round(max(0.6, 1.0 - (age_days / 300)), 2)
        elif lifecycle == "DECLINING":
            urgency_factor = round(max(0.2, 0.6 - (age_days / 365)), 2)
        else:
            urgency_factor = 0.1
    else:
        urgency_factor = 0.5  # Unknown date = moderate urgency

    # Days to estimated peak (negative = past peak)
    days_to_peak: Optional[int] = None
    if peak_activity:
        days_to_peak = (peak_activity - NOW_UTC).days

    return {
        "discovered":            discovered_iso,
        "exploitation_start":    exploit_start.strftime("%Y-%m-%d") if exploit_start else None,
        "peak_activity_estimate":peak_activity.strftime("%Y-%m-%d") if peak_activity else None,
        "days_since_disclosure": age_days,
        "days_to_peak":          days_to_peak,
        "status":                status,
        "lifecycle_stage":       lifecycle,
        "patch_window_days":     patch_window_days,
        "urgency_factor":        urgency_factor,
        "exploitation_velocity": (
            "RAPID"    if kev and cvss >= 9.0 else
            "FAST"     if kev else
            "MODERATE" if exploit_status in ("ACTIVE_CONFIRMED", "ACTIVE_OBSERVED") else
            "SLOW"
        ),
        "temporal_engine": "SENTINEL-APEX-V2-TEMPORAL",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3: FEEDBACK & LEARNING ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def module_feedback_learning(item: Dict, priority_score: int, lifecycle: str) -> Dict:
    """
    Module 3: Feedback & Learning Engine
    Generates heuristic feedback signals to enable self-improving intelligence.
    Uses APEX v1 evidence quality, detection confidence, and priority scoring
    as proxy signals in the absence of real-time feedback telemetry.
    """
    # ── Reliability Score (0–100) ─────────────────────────────────────────────
    # Derived from APEX v1 evidence quality + v2 priority score
    ev_reliability  = _get_v1_field(item, "evidence_validation", "reliability_score", "LOW")
    ev_raw_score    = _get_v1_field(item, "evidence_validation", "raw_confidence_score", 0)
    det_confidence  = _get_v1_field(item, "detection_confidence", "confidence", "LOW")
    det_composite   = _get_v1_field(item, "detection_confidence", "composite_score", 0)
    kev             = _is_kev(item)

    # Base reliability: evidence score + detection score blend
    base = (int(ev_raw_score) * 0.5 + int(det_composite) * 0.3 + priority_score * 0.2)
    reliability_score = int(min(100, base))

    # ── Usage Priority (HIGH / MEDIUM / LOW) ──────────────────────────────────
    # Proxy: KEV items + high priority = HIGH usage
    if kev or priority_score >= 85:
        usage_priority = "HIGH"
    elif priority_score >= 55:
        usage_priority = "MEDIUM"
    else:
        usage_priority = "LOW"

    # ── False Positive Likelihood ─────────────────────────────────────────────
    fp_risk = _get_v1_field(item, "detection_confidence", "false_positive_risk", "MEDIUM")
    fp_likelihood = {
        "LOW":    round(0.05 + (1 - priority_score / 100) * 0.1, 3),
        "MEDIUM": round(0.15 + (1 - priority_score / 100) * 0.15, 3),
        "HIGH":   round(0.30 + (1 - priority_score / 100) * 0.15, 3),
    }.get(fp_risk, 0.15)

    # ── Refinement Needed ─────────────────────────────────────────────────────
    refinement_needed = (
        ev_reliability == "LOW" or
        det_confidence == "LOW" or
        lifecycle in ("HISTORICAL",) or
        reliability_score < 40
    )

    # ── Intelligence Maturity ─────────────────────────────────────────────────
    if reliability_score >= 80 and kev:
        maturity = "MATURE"
    elif reliability_score >= 60:
        maturity = "VALIDATED"
    elif reliability_score >= 40:
        maturity = "DEVELOPING"
    else:
        maturity = "RAW"

    # ── Learning Signal ───────────────────────────────────────────────────────
    # Identifies what would improve confidence in future cycles
    signals = []
    if not kev and priority_score >= 70:
        signals.append("Monitor CISA KEV for exploitation confirmation")
    if ev_reliability == "LOW":
        signals.append("Seek additional source validation")
    if det_confidence == "LOW":
        signals.append("Deploy detection rule and collect telemetry feedback")
    if lifecycle == "DECLINING":
        signals.append("Reduce priority weight as threat activity declines")
    if lifecycle in ("EMERGING", "PEAK"):
        signals.append("Escalate — threat in high-activity phase")
    if not signals:
        signals.append("Intelligence stable — maintain current confidence level")

    # ── Confidence Trend ──────────────────────────────────────────────────────
    age_days = item.get("threat_timeline", {}).get("days_since_disclosure") or 0
    if isinstance(age_days, int) and lifecycle in ("DECLINING", "HISTORICAL"):
        trend = "DECREASING"
    elif lifecycle in ("EMERGING", "PEAK"):
        trend = "INCREASING"
    else:
        trend = "STABLE"

    return {
        "reliability_score":       reliability_score,
        "usage_priority":          usage_priority,
        "false_positive_likelihood": fp_likelihood,
        "refinement_needed":       refinement_needed,
        "intelligence_maturity":   maturity,
        "confidence_trend":        trend,
        "learning_signals":        signals,
        "feedback_engine":         "SENTINEL-APEX-V2-FEEDBACK",
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4: INTELLIGENCE AGGREGATION ENGINE  (report-level, not per-item)
# ══════════════════════════════════════════════════════════════════════════════

def _detect_sectors(text: str) -> List[str]:
    return [sector for sector, keywords in _SECTOR_KEYWORDS.items()
            if any(k in text for k in keywords)]


def module_intelligence_aggregation(enriched_items: List[Dict], flags: Dict) -> Dict:
    """
    Module 4: Intelligence Aggregation Engine
    Generates macro-level intelligence insights across the entire manifest.
    """
    top_n_critical  = int(flags.get("APEX_V2_TOP_CRITICAL_COUNT", 10))
    top_n_trending  = int(flags.get("APEX_V2_TOP_TRENDING_COUNT", 15))
    trending_window = int(flags.get("APEX_V2_TRENDING_WINDOW_DAYS", 30))

    # ── Classify items by priority level ─────────────────────────────────────
    critical_items = [i for i in enriched_items
                      if i.get("threat_priority", {}).get("level") == "CRITICAL"]
    high_items     = [i for i in enriched_items
                      if i.get("threat_priority", {}).get("level") == "HIGH"]

    # Sort by composite score: priority_score × urgency_factor
    def _composite(i: Dict) -> float:
        ps = i.get("threat_priority", {}).get("score", 0)
        uf = i.get("threat_timeline", {}).get("urgency_factor", 0.5)
        return ps * uf

    sorted_critical = sorted(critical_items, key=_composite, reverse=True)
    sorted_all      = sorted(enriched_items, key=_composite, reverse=True)

    # ── Top Critical Threats ──────────────────────────────────────────────────
    top_critical = []
    seen_titles: set = set()
    for item in sorted_critical:
        ttl = (item.get("title") or "")[:80]
        if ttl in seen_titles:
            continue
        seen_titles.add(ttl)
        top_critical.append({
            "title":           ttl,
            "priority_score":  item.get("threat_priority", {}).get("score", 0),
            "priority_level":  item.get("threat_priority", {}).get("level", "UNKNOWN"),
            "reasoning":       item.get("threat_priority", {}).get("reasoning", ""),
            "lifecycle_stage": item.get("threat_timeline", {}).get("lifecycle_stage", "UNKNOWN"),
            "urgency_factor":  item.get("threat_timeline", {}).get("urgency_factor", 0),
            "kev":             _is_kev(item),
            "cvss":            _get_cvss(item),
        })
        if len(top_critical) >= top_n_critical:
            break

    # ── Trending Threats (recent + high urgency) ──────────────────────────────
    trending_items = [
        i for i in enriched_items
        if (
            i.get("threat_timeline", {}).get("lifecycle_stage") in ("EMERGING", "PEAK", "ACTIVE")
            and i.get("threat_timeline", {}).get("days_since_disclosure") is not None
            and (i.get("threat_timeline", {}).get("days_since_disclosure") or 9999) <= trending_window
        )
    ]
    trending_sorted = sorted(trending_items, key=_composite, reverse=True)

    trending = []
    seen_t: set = set()
    for item in trending_sorted:
        ttl = (item.get("title") or "")[:80]
        if ttl in seen_t:
            continue
        seen_t.add(ttl)
        trending.append({
            "title":           ttl,
            "priority_score":  item.get("threat_priority", {}).get("score", 0),
            "lifecycle_stage": item.get("threat_timeline", {}).get("lifecycle_stage", "UNKNOWN"),
            "days_old":        item.get("threat_timeline", {}).get("days_since_disclosure"),
            "urgency_factor":  item.get("threat_timeline", {}).get("urgency_factor", 0),
            "exploitation_velocity": item.get("threat_timeline", {}).get("exploitation_velocity", "UNKNOWN"),
            "kev":             _is_kev(item),
        })
        if len(trending) >= top_n_trending:
            break

    # ── Declining Threats ─────────────────────────────────────────────────────
    declining_items = [
        i for i in enriched_items
        if i.get("threat_timeline", {}).get("lifecycle_stage") in ("DECLINING", "HISTORICAL")
    ]
    declining = [
        {
            "title":           (i.get("title") or "")[:80],
            "lifecycle_stage": i.get("threat_timeline", {}).get("lifecycle_stage"),
            "days_old":        i.get("threat_timeline", {}).get("days_since_disclosure"),
        }
        for i in sorted(declining_items,
                        key=lambda x: x.get("threat_timeline", {}).get("days_since_disclosure") or 0,
                        reverse=True)[:10]
    ]

    # ── Sector Impact Summary ─────────────────────────────────────────────────
    sector_hits: Dict[str, int] = {}
    critical_sector_hits: Dict[str, int] = {}
    for item in enriched_items:
        text = _get_text(item)
        for sector in _detect_sectors(text):
            sector_hits[sector] = sector_hits.get(sector, 0) + 1
            if item.get("threat_priority", {}).get("level") == "CRITICAL":
                critical_sector_hits[sector] = critical_sector_hits.get(sector, 0) + 1

    top_sectors = sorted(sector_hits.items(), key=lambda x: -x[1])[:5]
    top_critical_sectors = sorted(critical_sector_hits.items(), key=lambda x: -x[1])[:3]

    sector_narrative = _build_sector_narrative(top_sectors, top_critical_sectors)

    # ── Platform-Level Metrics ────────────────────────────────────────────────
    avg_priority = round(
        sum(i.get("threat_priority", {}).get("score", 0) for i in enriched_items) /
        max(len(enriched_items), 1), 1
    )
    kev_count    = sum(1 for i in enriched_items if _is_kev(i))
    active_count = sum(1 for i in enriched_items
                       if i.get("threat_timeline", {}).get("status") == "ACTIVE")
    peak_count   = sum(1 for i in enriched_items
                       if i.get("threat_timeline", {}).get("lifecycle_stage") == "PEAK")
    feedback_high= sum(1 for i in enriched_items
                       if i.get("feedback_signal", {}).get("usage_priority") == "HIGH")

    overall_risk = (
        "CRITICAL" if len(critical_items) >= 10 or (kev_count >= 5 and len(critical_items) >= 5) else
        "HIGH"     if len(critical_items) >= 3  or kev_count >= 3 else
        "ELEVATED" if len(high_items) >= 10     or kev_count >= 1 else
        "MODERATE"
    )

    return {
        "generated_at":       NOW_ISO,
        "overall_risk_posture": overall_risk,
        "platform_metrics": {
            "total_items":         len(enriched_items),
            "critical_count":      len(critical_items),
            "high_count":          len(high_items),
            "kev_active":          kev_count,
            "active_threats":      active_count,
            "peak_threats":        peak_count,
            "trending_threats":    len(trending),
            "declining_threats":   len(declining_items),
            "avg_priority_score":  avg_priority,
            "high_value_intel":    feedback_high,
        },
        "top_critical":       top_critical,
        "trending_threats":   trending,
        "declining_threats":  declining,
        "sector_impact": {
            "top_targeted_sectors":          [s[0] for s in top_sectors],
            "critical_threat_sectors":       [s[0] for s in top_critical_sectors],
            "sector_hit_counts":             dict(top_sectors),
            "sector_narrative":              sector_narrative,
        },
        "aggregation_engine": "SENTINEL-APEX-V2-AGGREGATION",
    }


def _build_sector_narrative(
    top_sectors: List[Tuple[str, int]],
    critical_sectors: List[Tuple[str, int]],
) -> str:
    if not top_sectors:
        return "Insufficient sector data for targeted impact assessment."

    primary = top_sectors[0][0] if top_sectors else "unclassified sectors"
    secondary = top_sectors[1][0] if len(top_sectors) > 1 else None

    crit_sectors = [s[0] for s in critical_sectors]

    if crit_sectors:
        crit_str = " and ".join(crit_sectors[:2])
        if secondary:
            return (f"{primary} and {secondary} face the highest threat volume. "
                    f"Critical-severity threats are disproportionately targeting "
                    f"{crit_str} sectors — CISO briefing and emergency patch prioritization required.")
        return (f"{primary} faces the highest threat volume. "
                f"Critical threats concentrated in {crit_str}.")
    if secondary:
        return (f"{primary} and {secondary} face the highest threat exposure this cycle. "
                f"No single sector bears critical-level concentration — broad defensive posture required.")
    return f"{primary} faces the highest threat exposure this cycle."


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5: API EVOLUTION LAYER
# ══════════════════════════════════════════════════════════════════════════════

def _item_to_api_record(item: Dict) -> Dict:
    """Serialize a single item into the standard v2 API record format."""
    tp   = item.get("threat_priority", {})
    tt   = item.get("threat_timeline", {})
    fs   = item.get("feedback_signal", {})
    ev   = item.get("evidence_validation", {})
    ex   = item.get("executive_summary", {})

    return {
        "id":              _item_id(item)[:16],
        "title":           (item.get("title") or "")[:120],
        "priority_score":  tp.get("score", 0),
        "priority_level":  tp.get("level", "UNKNOWN"),
        "reasoning":       tp.get("reasoning", ""),
        "kev":             _is_kev(item),
        "cvss":            _get_cvss(item),
        "lifecycle_stage": tt.get("lifecycle_stage", "UNKNOWN"),
        "activity_status": tt.get("status", "UNKNOWN"),
        "urgency_factor":  tt.get("urgency_factor", 0),
        "discovered":      tt.get("discovered"),
        "exploitation_start": tt.get("exploitation_start"),
        "reliability_score":  fs.get("reliability_score", 0),
        "usage_priority":     fs.get("usage_priority", "LOW"),
        "exploit_status":  ev.get("exploit_status", "UNVERIFIED"),
        "risk_level":      ex.get("risk_level", "MEDIUM") if ex else "MEDIUM",
        "decision":        (ex.get("decision_statement", "") or "")[:200] if ex else "",
        "date":            item.get("date_published") or item.get("_isoDate") or NOW_ISO,
    }


def module_api_evolution(enriched_items: List[Dict], agg_summary: Dict, flags: Dict) -> Dict:
    """
    Module 5: API Evolution Layer
    Generates 4 static JSON endpoints for /api/apex_v2/*.json
    Returns a dict of {filename: content} for atomic write.
    """
    top_n_critical = int(flags.get("APEX_V2_TOP_CRITICAL_COUNT", 10))
    top_n_trending = int(flags.get("APEX_V2_TOP_TRENDING_COUNT", 15))

    def _composite(i: Dict) -> float:
        ps = i.get("threat_priority", {}).get("score", 0)
        uf = i.get("threat_timeline", {}).get("urgency_factor", 0.5)
        return ps * uf

    # ── /api/apex_v2/critical.json ────────────────────────────────────────────
    critical_items = sorted(
        [i for i in enriched_items if i.get("threat_priority", {}).get("level") in ("CRITICAL", "HIGH")],
        key=_composite, reverse=True
    )
    seen: set = set()
    critical_records = []
    for item in critical_items:
        t = (item.get("title") or "")[:80]
        if t in seen: continue
        seen.add(t)
        critical_records.append(_item_to_api_record(item))
        if len(critical_records) >= top_n_critical:
            break

    critical_endpoint = {
        "endpoint":     "/api/v1/intel/critical",
        "version":      ENGINE_VERSION,
        "generated_at": NOW_ISO,
        "description":  "Top CRITICAL and HIGH priority threats — KEV-confirmed and highest composite scores",
        "total":        len(critical_records),
        "items":        critical_records,
        "meta": {
            "overall_risk_posture": agg_summary.get("overall_risk_posture", "UNKNOWN"),
            "kev_active": agg_summary.get("platform_metrics", {}).get("kev_active", 0),
            "critical_count": agg_summary.get("platform_metrics", {}).get("critical_count", 0),
        },
    }

    # ── /api/apex_v2/trending.json ────────────────────────────────────────────
    trending_window = int(flags.get("APEX_V2_TRENDING_WINDOW_DAYS", 30))
    trending_raw = sorted(
        [
            i for i in enriched_items
            if (
                i.get("threat_timeline", {}).get("lifecycle_stage") in ("EMERGING", "PEAK", "ACTIVE")
                and (i.get("threat_timeline", {}).get("days_since_disclosure") or 9999) <= trending_window
            )
        ],
        key=_composite, reverse=True
    )
    seen_t: set = set()
    trending_records = []
    for item in trending_raw:
        t = (item.get("title") or "")[:80]
        if t in seen_t: continue
        seen_t.add(t)
        rec = _item_to_api_record(item)
        rec["exploitation_velocity"] = item.get("threat_timeline", {}).get("exploitation_velocity", "UNKNOWN")
        trending_records.append(rec)
        if len(trending_records) >= top_n_trending:
            break

    trending_endpoint = {
        "endpoint":     "/api/v1/intel/trending",
        "version":      ENGINE_VERSION,
        "generated_at": NOW_ISO,
        "description":  f"Emerging and peak-activity threats in the last {trending_window} days",
        "window_days":  trending_window,
        "total":        len(trending_records),
        "items":        trending_records,
    }

    # ── /api/apex_v2/timeline.json ────────────────────────────────────────────
    timeline_records = []
    seen_tl: set = set()
    for item in sorted(enriched_items, key=_composite, reverse=True):
        tt = item.get("threat_timeline", {})
        if not tt.get("discovered"):
            continue
        t = (item.get("title") or "")[:80]
        if t in seen_tl: continue
        seen_tl.add(t)
        timeline_records.append({
            "title":              t,
            "discovered":         tt.get("discovered"),
            "exploitation_start": tt.get("exploitation_start"),
            "peak_activity":      tt.get("peak_activity_estimate"),
            "lifecycle_stage":    tt.get("lifecycle_stage", "UNKNOWN"),
            "status":             tt.get("status", "UNKNOWN"),
            "days_since_disclosure": tt.get("days_since_disclosure"),
            "urgency_factor":     tt.get("urgency_factor"),
            "priority_score":     item.get("threat_priority", {}).get("score", 0),
            "kev":                _is_kev(item),
        })
        if len(timeline_records) >= 100:
            break

    timeline_endpoint = {
        "endpoint":     "/api/v1/intel/timeline",
        "version":      ENGINE_VERSION,
        "generated_at": NOW_ISO,
        "description":  "Threat lifecycle timeline — discovered → exploitation → peak → decline",
        "total":        len(timeline_records),
        "items":        timeline_records,
        "lifecycle_distribution": {
            stage: sum(1 for i in enriched_items
                       if i.get("threat_timeline", {}).get("lifecycle_stage") == stage)
            for stage in ("EMERGING", "PEAK", "ACTIVE", "DECLINING", "HISTORICAL", "UNKNOWN")
        },
    }

    # ── /api/apex_v2/priority.json ────────────────────────────────────────────
    priority_records = []
    seen_p: set = set()
    for item in sorted(enriched_items, key=lambda x: x.get("threat_priority", {}).get("score", 0), reverse=True):
        t = (item.get("title") or "")[:80]
        if t in seen_p: continue
        seen_p.add(t)
        rec = _item_to_api_record(item)
        rec["scoring_breakdown"] = item.get("threat_priority", {}).get("scoring_breakdown", {})
        priority_records.append(rec)
        if len(priority_records) >= 200:
            break

    priority_endpoint = {
        "endpoint":     "/api/v1/intel/priority",
        "version":      ENGINE_VERSION,
        "generated_at": NOW_ISO,
        "description":  "All threats ranked by composite threat priority score (0-100)",
        "total":        len(priority_records),
        "items":        priority_records,
        "score_distribution": {
            "CRITICAL (85-100)": sum(1 for i in priority_records if i["priority_score"] >= 85),
            "HIGH (65-84)":      sum(1 for i in priority_records if 65 <= i["priority_score"] < 85),
            "MEDIUM (40-64)":    sum(1 for i in priority_records if 40 <= i["priority_score"] < 65),
            "LOW (0-39)":        sum(1 for i in priority_records if i["priority_score"] < 40),
        },
    }

    return {
        "critical.json": critical_endpoint,
        "trending.json": trending_endpoint,
        "timeline.json": timeline_endpoint,
        "priority.json": priority_endpoint,
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6: DASHBOARD PRIORITIZATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def module_dashboard_prioritization(
    enriched_items: List[Dict],
    agg_summary: Dict,
    flags: Dict,
) -> Dict:
    """
    Module 6: Dashboard Prioritization Engine
    Generates dashboard_intel.json — consumed by the frontend via progressive enhancement.
    Does NOT modify index.html directly — zero UI regression.
    Frontend reads this file asynchronously and injects priority badges, lifecycle indicators,
    and the Trending Threats section.
    """
    def _composite(i: Dict) -> float:
        ps = i.get("threat_priority", {}).get("score", 0)
        uf = i.get("threat_timeline", {}).get("urgency_factor", 0.5)
        return ps * uf

    # ── Top 3 threats for dashboard banner ───────────────────────────────────
    top3 = []
    seen: set = set()
    for item in sorted(enriched_items, key=_composite, reverse=True):
        ttl = (item.get("title") or "")[:80]
        if ttl in seen: continue
        seen.add(ttl)
        tp  = item.get("threat_priority", {})
        tt  = item.get("threat_timeline", {})
        top3.append({
            "title":         ttl,
            "priority_score":tp.get("score", 0),
            "priority_level":tp.get("level", "UNKNOWN"),
            "reasoning":     tp.get("reasoning", "")[:100],
            "lifecycle":     tt.get("lifecycle_stage", "UNKNOWN"),
            "kev":           _is_kev(item),
            "cvss":          _get_cvss(item),
            "badge": {
                "label": tp.get("level", "UNKNOWN"),
                "color": {
                    "CRITICAL": "#ef4444",
                    "HIGH":     "#f97316",
                    "MEDIUM":   "#fbbf24",
                    "LOW":      "#4ade80",
                }.get(tp.get("level", "UNKNOWN"), "#6b7280"),
            },
            "lifecycle_indicator": {
                "stage":  tt.get("lifecycle_stage", "UNKNOWN"),
                "status": tt.get("status", "UNKNOWN"),
                "icon":   {
                    "EMERGING": "🔺",
                    "PEAK":     "🔴",
                    "ACTIVE":   "🟠",
                    "DECLINING":"🟡",
                    "HISTORICAL":"⚪",
                    "UNKNOWN":  "⚫",
                }.get(tt.get("lifecycle_stage", "UNKNOWN"), "⚫"),
            },
        })
        if len(top3) >= 3:
            break

    # ── Trending Threats section data ─────────────────────────────────────────
    trending_window = int(flags.get("APEX_V2_TRENDING_WINDOW_DAYS", 30))
    trending_items  = sorted(
        [
            i for i in enriched_items
            if (
                i.get("threat_timeline", {}).get("lifecycle_stage") in ("EMERGING", "PEAK")
                and (i.get("threat_timeline", {}).get("days_since_disclosure") or 9999) <= trending_window
            )
        ],
        key=_composite, reverse=True
    )[:8]

    trending_section = []
    seen_t: set = set()
    for item in trending_items:
        ttl = (item.get("title") or "")[:80]
        if ttl in seen_t: continue
        seen_t.add(ttl)
        tp = item.get("threat_priority", {})
        tt = item.get("threat_timeline", {})
        trending_section.append({
            "title":    ttl,
            "score":    tp.get("score", 0),
            "level":    tp.get("level", "UNKNOWN"),
            "stage":    tt.get("lifecycle_stage", "UNKNOWN"),
            "days_old": tt.get("days_since_disclosure"),
            "velocity": tt.get("exploitation_velocity", "UNKNOWN"),
            "kev":      _is_kev(item),
        })

    # ── Priority badge distribution ───────────────────────────────────────────
    badge_counts = {
        "CRITICAL": sum(1 for i in enriched_items if i.get("threat_priority", {}).get("level") == "CRITICAL"),
        "HIGH":     sum(1 for i in enriched_items if i.get("threat_priority", {}).get("level") == "HIGH"),
        "MEDIUM":   sum(1 for i in enriched_items if i.get("threat_priority", {}).get("level") == "MEDIUM"),
        "LOW":      sum(1 for i in enriched_items if i.get("threat_priority", {}).get("level") == "LOW"),
    }

    # ── Lifecycle distribution ────────────────────────────────────────────────
    lifecycle_dist = {}
    for item in enriched_items:
        stage = item.get("threat_timeline", {}).get("lifecycle_stage", "UNKNOWN")
        lifecycle_dist[stage] = lifecycle_dist.get(stage, 0) + 1

    return {
        "endpoint":          "dashboard_intel",
        "version":           ENGINE_VERSION,
        "generated_at":      NOW_ISO,
        "overall_risk":      agg_summary.get("overall_risk_posture", "MODERATE"),
        "top_3_threats":     top3,
        "trending_section":  trending_section,
        "badge_counts":      badge_counts,
        "lifecycle_distribution": lifecycle_dist,
        "sector_impact":     agg_summary.get("sector_impact", {}).get("sector_narrative", ""),
        "alert_banner": {
            "show":    badge_counts.get("CRITICAL", 0) > 0,
            "message": (
                f"⚠️ {badge_counts['CRITICAL']} CRITICAL threat(s) require immediate action. "
                f"{agg_summary.get('platform_metrics', {}).get('kev_active', 0)} CISA KEV-confirmed."
            ) if badge_counts.get("CRITICAL", 0) > 0 else "",
            "severity": "CRITICAL" if badge_counts.get("CRITICAL", 0) > 0 else "NORMAL",
        },
        "data_freshness": {
            "generated_at": NOW_ISO,
            "engine":       "SENTINEL-APEX-V2-DASHBOARD",
            "items_analyzed": len(enriched_items),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 7: VALIDATION EXTENSION (per-item gate metadata)
# ══════════════════════════════════════════════════════════════════════════════

def module_validation_extension(item: Dict, flags: Dict) -> Dict:
    """
    Module 7: Validation Extension
    Attaches v2 gate check results to each item.
    All gate results are informational by default — only blocking when
    APEX_V2_REQUIRE_* flags are explicitly enabled.
    """
    tp = item.get("threat_priority", {})
    tt = item.get("threat_timeline", {})
    fs = item.get("feedback_signal", {})

    checks: Dict[str, Dict] = {}

    # Check 1: threat_priority presence and quality
    has_priority = bool(tp and tp.get("score") is not None)
    checks["priority"] = {
        "pass":   has_priority,
        "reason": "ok" if has_priority else "missing_threat_priority",
        "gate_active": flags.get("APEX_V2_REQUIRE_PRIORITY_GATE", False),
    }

    # Check 2: timeline structure
    has_timeline = bool(tt and tt.get("lifecycle_stage"))
    checks["timeline"] = {
        "pass":   has_timeline,
        "reason": "ok" if has_timeline else "missing_timeline_structure",
        "gate_active": flags.get("APEX_V2_REQUIRE_TIMELINE_GATE", False),
    }

    # Check 3: feedback signal
    has_feedback = bool(fs and fs.get("reliability_score") is not None)
    checks["feedback"] = {
        "pass":   has_feedback,
        "reason": "ok" if has_feedback else "missing_feedback_signal",
        "gate_active": flags.get("APEX_V2_REQUIRE_FEEDBACK_GATE", False),
    }

    # Overall gate status
    active_failures = [
        name for name, chk in checks.items()
        if chk["gate_active"] and not chk["pass"]
    ]
    overall_pass = len(active_failures) == 0

    return {
        "checks":         checks,
        "overall_pass":   overall_pass,
        "active_failures": active_failures,
        "v2_validation_engine": "SENTINEL-APEX-V2-VALIDATION",
    }


# ══════════════════════════════════════════════════════════════════════════════
# ITEM ENRICHMENT ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def enrich_item_v2(item: Dict, flags: Dict) -> Dict:
    """
    Apply all enabled per-item v2 modules (1, 2, 3, 7) to a single manifest item.
    Each module is independently guarded — one failure does not kill others.
    Returns original item with new v2 fields added (ADDITIVE ONLY).
    """
    enriched = dict(item)   # Shallow copy — NEVER mutate original

    priority_result  = {}
    timeline_result  = {}
    feedback_result  = {}
    priority_score   = 0
    lifecycle_stage  = "UNKNOWN"

    # Module 1: Threat Priority Scoring
    try:
        if flags.get("APEX_V2_MODULE_PRIORITY", True):
            priority_result = module_threat_priority(item)
            enriched["threat_priority"] = priority_result
            priority_score = priority_result.get("score", 0)
    except Exception as e:
        log.warning(f"[M1-PRIORITY] {_item_id(item)[:12]}: {e}")
        enriched["threat_priority"] = {"score": 0, "level": "UNKNOWN", "error": str(e)}

    # Module 2: Temporal Intelligence
    try:
        if flags.get("APEX_V2_MODULE_TEMPORAL", True):
            timeline_result = module_temporal_intelligence(item, priority_score)
            enriched["threat_timeline"] = timeline_result
            lifecycle_stage = timeline_result.get("lifecycle_stage", "UNKNOWN")
    except Exception as e:
        log.warning(f"[M2-TEMPORAL] {_item_id(item)[:12]}: {e}")
        enriched["threat_timeline"] = {"lifecycle_stage": "UNKNOWN", "error": str(e)}

    # Module 3: Feedback & Learning
    try:
        if flags.get("APEX_V2_MODULE_FEEDBACK", True):
            feedback_result = module_feedback_learning(item, priority_score, lifecycle_stage)
            enriched["feedback_signal"] = feedback_result
    except Exception as e:
        log.warning(f"[M3-FEEDBACK] {_item_id(item)[:12]}: {e}")
        enriched["feedback_signal"] = {"reliability_score": 0, "error": str(e)}

    # Module 7: Validation Extension (per-item gate)
    try:
        if flags.get("APEX_V2_MODULE_VALIDATION", True):
            enriched["apex_v2_gate"] = module_validation_extension(enriched, flags)
    except Exception as e:
        log.warning(f"[M7-VALIDATION] {_item_id(item)[:12]}: {e}")

    enriched["_apex_v2_enriched"]    = True
    enriched["_apex_v2_version"]     = ENGINE_VERSION
    enriched["_apex_v2_enriched_at"] = NOW_ISO

    return enriched


# ══════════════════════════════════════════════════════════════════════════════
# STRATEGIC REPORT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

def build_strategic_report(enriched_items: List[Dict], agg_summary: Dict) -> Dict:
    """Build the top-level APEX v2 Strategic Intelligence Report."""
    pm = agg_summary.get("platform_metrics", {})

    # ── Priority Distribution ─────────────────────────────────────────────────
    scores = [i.get("threat_priority", {}).get("score", 0) for i in enriched_items]
    avg_score = round(sum(scores) / max(len(scores), 1), 1)
    max_score = max(scores) if scores else 0

    # ── Feedback Quality ──────────────────────────────────────────────────────
    mature_count = sum(1 for i in enriched_items
                       if i.get("feedback_signal", {}).get("intelligence_maturity") == "MATURE")
    high_fb      = sum(1 for i in enriched_items
                       if i.get("feedback_signal", {}).get("usage_priority") == "HIGH")

    # ── Gate Compliance ───────────────────────────────────────────────────────
    gate_pass = sum(1 for i in enriched_items
                    if i.get("apex_v2_gate", {}).get("overall_pass", True))

    return {
        "report_title":    "SENTINEL APEX v2 STRATEGIC INTELLIGENCE REPORT",
        "subtitle":        "Adaptive · Prioritized · Time-Aware · Self-Improving",
        "platform":        "CYBERDUDEBIVASH SENTINEL APEX",
        "engine_version":  ENGINE_VERSION,
        "generated_at":    NOW_ISO,
        "classification":  "TLP:AMBER — For Authorized Security Personnel Only",
        "attribution":     "Analysis by CYBERDUDEBIVASH SENTINEL APEX v2 Intelligence Evolution Engine",
        "legal_notice":    "For cybersecurity defense and research purposes only.",

        "executive_brief": {
            "overall_risk_posture":    agg_summary.get("overall_risk_posture", "UNKNOWN"),
            "total_threats_analyzed":  pm.get("total_items", 0),
            "critical_threats":        pm.get("critical_count", 0),
            "kev_confirmed":           pm.get("kev_active", 0),
            "active_threats":          pm.get("active_threats", 0),
            "peak_threats":            pm.get("peak_threats", 0),
            "trending_threats":        pm.get("trending_threats", 0),
            "avg_priority_score":      avg_score,
            "max_priority_score":      max_score,
            "sector_narrative":        agg_summary.get("sector_impact", {}).get("sector_narrative", ""),
        },

        "threat_priority_summary": {
            "critical_count":  pm.get("critical_count", 0),
            "high_count":      pm.get("high_count", 0),
            "avg_score":       avg_score,
            "max_score":       max_score,
            "top_critical":    agg_summary.get("top_critical", [])[:5],
        },

        "temporal_summary": {
            "active_threats":   pm.get("active_threats", 0),
            "peak_threats":     pm.get("peak_threats", 0),
            "emerging_count":   sum(1 for i in enriched_items
                                    if i.get("threat_timeline", {}).get("lifecycle_stage") == "EMERGING"),
            "declining_count":  len(agg_summary.get("declining_threats", [])),
            "trending":         agg_summary.get("trending_threats", [])[:5],
        },

        "intelligence_quality": {
            "mature_intel_count":  mature_count,
            "high_value_count":    high_fb,
            "gate_pass_rate_pct":  round(gate_pass / max(len(enriched_items), 1) * 100, 1),
            "v2_enriched_count":   sum(1 for i in enriched_items if i.get("_apex_v2_enriched")),
        },

        "sector_impact": agg_summary.get("sector_impact", {}),

        "api_endpoints": {
            "/api/apex_v2/critical.json":       "Top CRITICAL & HIGH threats",
            "/api/apex_v2/trending.json":        "Emerging & peak-activity threats",
            "/api/apex_v2/timeline.json":        "Full lifecycle timeline data",
            "/api/apex_v2/priority.json":        "All threats ranked by priority score",
            "/api/apex_v2/dashboard_intel.json": "Dashboard progressive enhancement data",
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PIPELINE ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    flags = _load_flags()

    if not flags.get("ENABLE_APEX_V2_ENGINE", True):
        log.info("ENABLE_APEX_V2_ENGINE=false — engine disabled, skipping.")
        return 0

    log.info("=" * 65)
    log.info(f"SENTINEL APEX v2 EVOLUTION ENGINE {ENGINE_VERSION} — INIT")
    log.info(f"Timestamp : {NOW_ISO}")
    log.info("=" * 65)

    # ── Load manifest ─────────────────────────────────────────────────────────
    items, source = _load_manifest()
    if not items:
        log.warning("No manifest items — writing empty outputs and exiting cleanly.")
        _atomic_write(APEX_V2_STRATEGIC_REPORT, {"error": "no_items", "generated_at": NOW_ISO})
        _atomic_write(APEX_V2_AUDIT, {
            "status": "SKIPPED", "reason": "no_items",
            "generated_at": NOW_ISO, "engine": ENGINE_VERSION,
        })
        return 0

    max_items = int(flags.get("APEX_V2_MAX_ITEMS", 2000))
    if len(items) > max_items:
        log.info(f"Capping at {max_items} items (manifest has {len(items)})")
        items = items[:max_items]

    log.info(f"Processing {len(items)} items through APEX v2 modules...")

    # ── Per-item enrichment (Modules 1, 2, 3, 7) ─────────────────────────────
    enriched_items: List[Dict] = []
    gate_pass_count = 0
    gate_fail_count = 0

    for i, item in enumerate(items):
        try:
            enriched = enrich_item_v2(item, flags)
            if enriched.get("apex_v2_gate", {}).get("overall_pass", True):
                gate_pass_count += 1
            else:
                gate_fail_count += 1
            enriched_items.append(enriched)
        except Exception as e:
            log.error(f"Item {i} v2 enrichment failed: {e}")
            enriched_items.append(dict(item))  # Pass-through on total failure

    log.info(f"Per-item enrichment: {len(enriched_items)} items | "
             f"gate_pass={gate_pass_count} | gate_fail={gate_fail_count}")

    # ── Write enriched manifest ───────────────────────────────────────────────
    sz_manifest = _atomic_write(APEX_V2_MANIFEST, enriched_items)
    log.info(f"Written: apex_v2_manifest.json ({sz_manifest:,} bytes, {len(enriched_items)} items)")

    # ── Module 4: Intelligence Aggregation ───────────────────────────────────
    agg_summary: Dict = {}
    if flags.get("APEX_V2_MODULE_AGGREGATION", True):
        try:
            log.info("Running Module 4: Intelligence Aggregation...")
            agg_summary = module_intelligence_aggregation(enriched_items, flags)
        except Exception as e:
            log.error(f"[M4-AGGREGATION] failed: {e}")
            agg_summary = {"error": str(e), "overall_risk_posture": "UNKNOWN"}

    # ── Module 5: API Evolution Layer ─────────────────────────────────────────
    if flags.get("APEX_V2_MODULE_API", True):
        try:
            log.info("Running Module 5: API Evolution Layer...")
            API_V2_DIR.mkdir(parents=True, exist_ok=True)
            api_outputs = module_api_evolution(enriched_items, agg_summary, flags)
            for filename, content in api_outputs.items():
                sz = _atomic_write(API_V2_DIR / filename, content)
                log.info(f"  Written: api/apex_v2/{filename} ({sz:,} bytes, "
                         f"{content.get('total', '?')} items)")
        except Exception as e:
            log.error(f"[M5-API] failed: {e}")

    # ── Module 6: Dashboard Prioritization Engine ─────────────────────────────
    if flags.get("APEX_V2_MODULE_DASHBOARD", True):
        try:
            log.info("Running Module 6: Dashboard Prioritization Engine...")
            dashboard_data = module_dashboard_prioritization(enriched_items, agg_summary, flags)
            sz_dash = _atomic_write(API_V2_DIR / "dashboard_intel.json", dashboard_data)
            log.info(f"  Written: api/apex_v2/dashboard_intel.json ({sz_dash:,} bytes)")
        except Exception as e:
            log.error(f"[M6-DASHBOARD] failed: {e}")

    # ── Strategic Report ──────────────────────────────────────────────────────
    report = build_strategic_report(enriched_items, agg_summary)
    sz_report = _atomic_write(APEX_V2_STRATEGIC_REPORT, report)
    log.info(f"Written: apex_v2_strategic_report.json ({sz_report:,} bytes)")

    # ── Audit Log ─────────────────────────────────────────────────────────────
    pm = agg_summary.get("platform_metrics", {})
    audit = {
        "engine":           "APEX v2 Intelligence Evolution Engine",
        "version":          ENGINE_VERSION,
        "run_at":           NOW_ISO,
        "manifest_source":  source,
        "items_input":      len(items),
        "items_enriched":   len(enriched_items),
        "gate_pass":        gate_pass_count,
        "gate_fail":        gate_fail_count,
        "modules_run": {
            "priority_scoring":       flags.get("APEX_V2_MODULE_PRIORITY", True),
            "temporal_intelligence":  flags.get("APEX_V2_MODULE_TEMPORAL", True),
            "feedback_learning":      flags.get("APEX_V2_MODULE_FEEDBACK", True),
            "intelligence_aggregation":flags.get("APEX_V2_MODULE_AGGREGATION", True),
            "api_evolution":          flags.get("APEX_V2_MODULE_API", True),
            "dashboard_prioritization":flags.get("APEX_V2_MODULE_DASHBOARD", True),
            "validation_extension":   flags.get("APEX_V2_MODULE_VALIDATION", True),
        },
        "outputs": {
            "apex_v2_manifest":         str(APEX_V2_MANIFEST),
            "apex_v2_strategic_report": str(APEX_V2_STRATEGIC_REPORT),
            "api_v2_dir":               str(API_V2_DIR),
        },
        "intelligence_summary": {
            "overall_risk":    agg_summary.get("overall_risk_posture", "UNKNOWN"),
            "critical_count":  pm.get("critical_count", 0),
            "kev_active":      pm.get("kev_active", 0),
            "active_threats":  pm.get("active_threats", 0),
            "trending_count":  pm.get("trending_threats", 0),
        },
        "status": "SUCCESS",
    }
    sz_audit = _atomic_write(APEX_V2_AUDIT, audit)
    log.info(f"Written: apex_v2_audit.json ({sz_audit:,} bytes)")

    # ── Final summary ─────────────────────────────────────────────────────────
    log.info("─" * 65)
    log.info(
        f"✅ APEX v2 COMPLETE | Items: {len(enriched_items)} | "
        f"Critical: {pm.get('critical_count', 0)} | "
        f"KEV: {pm.get('kev_active', 0)} | "
        f"Trending: {pm.get('trending_threats', 0)} | "
        f"Risk: {agg_summary.get('overall_risk_posture', 'UNKNOWN')}"
    )
    log.info("─" * 65)
    return 0


if __name__ == "__main__":
    sys.exit(main())
