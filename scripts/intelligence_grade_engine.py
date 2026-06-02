#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
INTELLIGENCE GRADE ENGINE v1.0.0
===============================================================================
AUTHORITY: Principal Intelligence Integrity Governor
This engine supersedes all other grading, scoring, and publication logic.

FUNCTIONS:
  1. Intelligence Grading (A / B / C / D / F) — evidence-based only
  2. Deterministic Risk Scoring — CVSS + EPSS + KEV + actor + IOC quality
  3. ATT&CK Verification — strips corpus-mapped speculative techniques
  4. Output Contract Injection — adds all 10 mandatory fields to every item
  5. Publication Decision — ALLOW / ALLOW_WITH_WARNING / QUARANTINE / BLOCK
  6. Synthetic Actor/Campaign Enforcement — nulls banned identifiers

GRADE CRITERIA (10 Absolute Rules — Rule 7):
  A = Verified active exploitation + 2+ corroborating Tier 1/2 sources
  B = Strong corroboration (Tier 1 source + IOCs extracted + ATT&CK evidenced)
  C = Partially verified (KEV OR EPSS>10% OR vendor advisory, single source)
  D = Weak evidence (single news source, no IOCs, no KEV, no EPSS)
  F = Insufficient evidence (no CVSS, no EPSS, no KEV, no real IOCs, no actor)

PUBLICATION DECISIONS (Rule 9):
  ALLOW           — Grade A or B with all contract fields present
  ALLOW_WITH_WARNING — Grade C with noted deficiencies
  QUARANTINE      — Grade D — suppress from premium, allow in public free tier
  BLOCK           — Grade F, synthetic actor/campaign, output contract fail

RISK SCORE FORMULA (Rule 6 — deterministic, no random multipliers):
  base = cvss_normalized (0-10 → 0-4.0 weight)
  epss_boost = epss_pct * 0.03  (max +3.0)
  kev_boost = 2.5 if KEV else 0
  actor_boost = 0.5 if verified_actor else 0
  ioc_boost = min(1.0, real_ioc_count * 0.1)
  risk_score = min(10.0, base + epss_boost + kev_boost + actor_boost + ioc_boost)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [grade-engine] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-IGE")

ENGINE_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

TIER1_SOURCES = frozenset([
    "CISA", "NCSC", "NCSC Netherlands", "FBI", "NSA", "CERT", "US-CERT",
    "Mandiant", "CrowdStrike", "Microsoft", "Microsoft Security",
    "Microsoft MSRC", "Google Project Zero",
])

TIER2_SOURCES = frozenset([
    "Palo Alto Unit 42", "Recorded Future", "Sophos", "Kaspersky SecureList",
    "Check Point Research", "Trend Micro", "Rapid7", "NIST NVD",
    "GitHub Security Advisory", "abuse.ch", "Google Security Blog",
])

# ATT&CK justification strings that indicate corpus-mapping (not evidence)
CORPUS_MAPPING_MARKERS = [
    "Technique ID mapped from threat intelligence corpus",
    "mapped from threat intelligence corpus",
    "technique id mapped",
    "corpus",
]

# Synthetic actor tags — permanently banned
BANNED_ACTOR_TAGS = frozenset([
    "CDB-UNATTR-CVE", "CDB-UNATTR-APT", "CDB-UNATTR-RAN",
    "CDB-UNATTR-PHI", "CDB-UNATTR-MAL", "CDB-UNATTR-INT",
])

# Synthetic campaign IDs — permanently banned without direct source evidence
BANNED_CAMPAIGN_IDS = frozenset([
    "CDB-CONTI",  # Conti dissolved May 2022
    "UNCLASSIFIED",
])

# Source URLs / advisory pages that are NOT operational IOCs
PSEUDO_DOMAINS = frozenset([
    "cz.nic", "nvd.nist.gov", "cve.mitre.org", "vulners.com",
    "cvefeed.io", "github.com", "cisa.gov", "microsoft.com",
    "wordfence.com", "wpscan.com", "ncsc.nl", "ncsc.gov.uk",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "kaspersky.com", "securelist.com", "mandiant.com",
    "crowdstrike.com", "recordedfuture.com", "rapid7.com",
    "sophos.com", "trendmicro.com", "checkpoint.com",
    "msrc.microsoft.com", "bleepingcomputer.com", "krebsonsecurity.com",
    "profile.post", "cert.org", "us-cert.gov",
])

# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _safe_float(v, default=0.0) -> float:
    try:
        return float(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _safe_int(v, default=0) -> int:
    try:
        return int(v) if v is not None else default
    except (TypeError, ValueError):
        return default


def _sources(item: Dict) -> List[str]:
    out = []
    for k in ("source", "feed_source", "source_name"):
        s = str(item.get(k, "") or "")
        if s and s not in out:
            out.append(s)
    return out


def _real_ioc_count(item: Dict) -> int:
    """Count only genuine operational IOCs — strip CVE refs, source URLs, pseudo-domains."""
    iocs = item.get("iocs", []) or []
    count = 0
    for ioc in iocs:
        ioc_s = str(ioc).strip()
        # Skip CVE references
        if re.match(r"^CVE-\d{4}-\d+$", ioc_s, re.IGNORECASE):
            continue
        # Skip source/advisory URLs
        if ioc_s.startswith(("http://", "https://", "ftp://")):
            continue
        # Skip pseudo-domains
        lower = ioc_s.lower()
        if any(lower == d or lower.endswith("." + d) for d in PSEUDO_DOMAINS):
            continue
        # Skip very short strings (2-char TLDs extracted as domains)
        if len(ioc_s) < 5:
            continue
        count += 1
    return count


def _epss_pct(item: Dict) -> float:
    """Normalize EPSS to 0–100 range. Handles both 0.94 and 94.37 formats."""
    raw = _safe_float(item.get("epss_score"))
    if raw == 0:
        return 0.0
    # If stored as fraction (0.0–1.0)
    if raw <= 1.0:
        return raw * 100.0
    # If stored as percentage (1.0–100.0)
    if raw <= 100.0:
        return raw
    # Invalid — clamp
    return min(raw, 100.0)


def _has_kev(item: Dict) -> bool:
    return (
        item.get("kev") == "YES"
        or item.get("kev_present") is True
        or item.get("in_kev") is True
        or item.get("cisa_kev") is True
    )


def _attck_is_evidenced(technique: Any) -> bool:
    """Return True only if this ATT&CK technique has direct evidence, not corpus-mapping."""
    if isinstance(technique, str):
        return False  # Tag-only — no justification
    if not isinstance(technique, dict):
        return False
    justification = str(technique.get("justification", "") or "").lower()
    for marker in CORPUS_MAPPING_MARKERS:
        if marker.lower() in justification:
            return False  # Corpus-mapped — NOT evidence
    # Require some non-trivial justification
    return len(justification) > 50 and "source" in justification


def _corroboration_count(item: Dict) -> int:
    """Count distinct Tier 1+2 sources corroborating this item."""
    srcs = _sources(item)
    count = 0
    for s in srcs:
        if s in TIER1_SOURCES or s in TIER2_SOURCES:
            count += 1
    return count


def _actor_is_verified(item: Dict) -> bool:
    """True if actor_tag is a real verified actor, not a CDB-internal synthetic."""
    tag = str(item.get("actor_tag", "") or "")
    if not tag or tag in BANNED_ACTOR_TAGS:
        return False
    # CDB-APT-NN tags assigned without evidence
    if re.match(r"^CDB-(?:UNATTR|APT|IR)-\d+$", tag):
        return False  # Needs external verification evidence
    return True


# ══════════════════════════════════════════════════════════════════════════════
# GRADE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def assign_grade(item: Dict) -> Tuple[str, List[str]]:
    """
    Assign intelligence grade A–F.
    Returns (grade, evidence_notes).
    Rule 7: grade based purely on evidence — not on report length or source prestige alone.
    """
    notes = []
    cvss = _safe_float(item.get("cvss_score"))
    epss = _epss_pct(item)
    kev = _has_kev(item)
    real_iocs = _real_ioc_count(item)
    corroboration = _corroboration_count(item)
    srcs = _sources(item)
    cve_ids = item.get("cve_ids", []) or []
    techniques = item.get("mitre_tactics", item.get("ttps", [])) or []
    evidenced_techniques = [t for t in techniques if _attck_is_evidenced(t)]
    actor_verified = _actor_is_verified(item)

    # Grade F: Insufficient evidence
    if (
        cvss == 0 and epss == 0 and not kev
        and real_iocs == 0 and corroboration == 0
        and not evidenced_techniques
    ):
        notes.append("No CVSS, no EPSS, no KEV, no real IOCs, no evidenced ATT&CK, no Tier 1/2 corroboration")
        return "F", notes

    # Grade A: Verified exploitation + multi-source corroboration
    exploitation_confirmed = (
        kev
        or epss >= 50.0
        or item.get("exploit_maturity") in ("FUNCTIONAL", "HIGH", "WEAPONIZED")
        or item.get("observed_exploitation") is True
    )
    if exploitation_confirmed and corroboration >= 2 and (real_iocs >= 3 or cvss >= 7.0):
        notes.append(f"Verified exploitation (KEV={kev}, EPSS={epss:.1f}%), {corroboration} corroborating sources, {real_iocs} real IOCs")
        return "A", notes

    # Grade B: Strong corroboration (Tier 1 source + substantive enrichment)
    tier1_present = any(s in TIER1_SOURCES for s in srcs)
    tier2_present = any(s in TIER2_SOURCES for s in srcs)
    named_malware = bool(
        item.get("malware_family")
        or item.get("malware_name")
        or "malware" in str(item.get("title", "")).lower()
    )
    if (
        (tier1_present or (tier2_present and named_malware))
        and (real_iocs >= 1 or len(evidenced_techniques) >= 1 or kev or epss >= 10.0)
    ):
        notes.append(f"Tier 1/2 source present, real_iocs={real_iocs}, evidenced_techniques={len(evidenced_techniques)}")
        return "B", notes

    # Grade C: Partially verified
    if kev or epss >= 10.0 or (tier1_present or tier2_present) or cvss >= 7.0:
        reason = []
        if kev: reason.append("KEV confirmed")
        if epss >= 10.0: reason.append(f"EPSS {epss:.1f}%")
        if tier1_present: reason.append("Tier 1 source")
        if tier2_present: reason.append("Tier 2 source")
        if cvss >= 7.0: reason.append(f"CVSS {cvss}")
        notes.append(f"Partial verification: {', '.join(reason)}")
        return "C", notes

    # Grade D: Weak evidence
    if cvss > 0 or epss > 0 or real_iocs >= 1 or len(srcs) >= 1:
        notes.append(f"Weak evidence: CVSS={cvss}, EPSS={epss:.1f}%, real_iocs={real_iocs}, sources={srcs}")
        return "D", notes

    # Fallback F
    notes.append("INSUFFICIENT VERIFIED EVIDENCE")
    return "F", notes


# ══════════════════════════════════════════════════════════════════════════════
# DETERMINISTIC RISK SCORER
# ══════════════════════════════════════════════════════════════════════════════

def compute_risk_score(item: Dict) -> Tuple[float, Dict]:
    """
    Deterministic risk score. No random multipliers. No AI modifiers.
    Formula (Rule 6):
      base      = cvss_normalized to 0–4.0
      epss      = epss_pct * 0.03  (max 3.0)
      kev       = 2.5 if KEV confirmed
      actor     = 0.5 if verified non-synthetic actor
      ioc       = min(1.0, real_ioc_count * 0.2)
      total     = min(10.0, base + epss + kev + actor + ioc)
    """
    cvss = _safe_float(item.get("cvss_score"))
    epss = _epss_pct(item)
    kev = _has_kev(item)
    real_iocs = _real_ioc_count(item)
    actor_verified = _actor_is_verified(item)

    base = (cvss / 10.0) * 4.0
    epss_boost = epss * 0.03
    kev_boost = 2.5 if kev else 0.0
    actor_boost = 0.5 if actor_verified else 0.0
    ioc_boost = min(1.0, real_iocs * 0.2)

    total = min(10.0, base + epss_boost + kev_boost + actor_boost + ioc_boost)
    total = round(total, 4)

    reasoning = {
        "formula": "v1.0.0-deterministic",
        "inputs": {
            "cvss_score": cvss,
            "epss_pct": round(epss, 2),
            "kev_confirmed": kev,
            "verified_actor": actor_verified,
            "real_ioc_count": real_iocs,
        },
        "components": {
            "base_cvss": round(base, 4),
            "epss_boost": round(epss_boost, 4),
            "kev_boost": kev_boost,
            "actor_boost": actor_boost,
            "ioc_boost": round(ioc_boost, 4),
        },
        "computed_score": total,
        "notes": [],
    }

    if cvss == 0:
        reasoning["notes"].append("CVSS absent — base score is 0; add NVD enrichment for accurate scoring")
    if epss == 0 and item.get("cve_ids"):
        reasoning["notes"].append("EPSS absent for CVE item — enrich from FIRST.org API")
    if not kev and cvss >= 9.0:
        reasoning["notes"].append("Critical CVSS without KEV confirmation — monitor for escalation")

    return total, reasoning


# ══════════════════════════════════════════════════════════════════════════════
# ATT&CK VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def verify_attck(item: Dict) -> Tuple[str, List[Dict], str]:
    """
    Returns (attck_verification_status, verified_techniques, attck_notes).
    Strips all corpus-mapped speculative assignments.
    Rule 4: direct source evidence OR verified exploitation evidence OR vendor advisory mapping.
    """
    techniques = item.get("mitre_tactics", item.get("ttps", [])) or []
    verified = []
    stripped = []

    for t in techniques:
        if _attck_is_evidenced(t):
            verified.append(t)
        else:
            tid = t.get("id", "?") if isinstance(t, dict) else str(t)
            stripped.append(tid)

    if not techniques:
        return "NOT_MAPPED", [], "No ATT&CK techniques present"

    if stripped and not verified:
        return "NOT_VERIFIED", [], (
            f"All {len(stripped)} technique(s) stripped — corpus-mapped only: {stripped}. "
            "Requires direct source evidence or vendor advisory mapping."
        )

    if stripped and verified:
        return "PARTIAL", verified, (
            f"{len(verified)} verified, {len(stripped)} stripped (corpus-mapped): {stripped}"
        )

    return "VERIFIED", verified, f"{len(verified)} technique(s) with direct evidence"


# ══════════════════════════════════════════════════════════════════════════════
# SYNTHETIC ENFORCEMENT
# ══════════════════════════════════════════════════════════════════════════════

def enforce_attribution(item: Dict) -> Tuple[Dict, List[str]]:
    """
    Strip synthetic actors and campaigns. Return patched item + audit log.
    Rules 2 and 3.
    """
    patched = dict(item)
    log_entries = []

    # Actor enforcement
    # RC-1: check actor_tag AND actor field — feed stores CDB-UNATTR values in actor, not actor_tag
    actor_tag = str(patched.get("actor_tag") or patched.get("actor") or "")
    if actor_tag in BANNED_ACTOR_TAGS:
        patched["actor_tag"] = None
        patched["actor"] = None
        patched["actor_name"] = None
        patched["actor_display_name"] = None
        patched["actor_confidence"] = 0
        patched["verified_actor"] = False
        patched["attribution_status"] = "NONE"
        log_entries.append(f"RULE2: Synthetic actor '{actor_tag}' nulled — attribution_status=NONE")
    else:
        patched["verified_actor"] = _actor_is_verified(patched)
        patched.setdefault("attribution_status", "CLAIMED" if patched.get("actor_tag") else "NONE")

    # Campaign enforcement
    apex = patched.get("apex", {}) or {}
    campaign_id = str(apex.get("campaign_id", "") or "")
    campaign_name = str(patched.get("campaign_name", "") or "")

    if campaign_id in BANNED_CAMPAIGN_IDS or campaign_name in BANNED_CAMPAIGN_IDS:
        if isinstance(patched.get("apex"), dict):
            patched["apex"]["campaign_id"] = None
        patched["campaign_name"] = None
        patched["campaign_id"] = None
        patched["campaign_status"] = "UNVERIFIED"
        log_entries.append(
            f"RULE3: Synthetic campaign '{campaign_id or campaign_name}' nulled — "
            f"requires min 2 sources + reputable naming"
        )
    else:
        patched.setdefault("campaign_status", "UNVERIFIED" if not campaign_id else "CLAIMED")

    return patched, log_entries


# ══════════════════════════════════════════════════════════════════════════════
# IOC QUALITY SCORE
# ══════════════════════════════════════════════════════════════════════════════

def ioc_quality_score(item: Dict) -> Tuple[int, str]:
    """
    Score IOC quality 0–100. Rule 5.
    """
    stored_count = _safe_int(item.get("ioc_count"))
    real_count = _real_ioc_count(item)
    by_type = item.get("iocs_by_type", {}) or {}

    # Type diversity
    real_types = [t for t in by_type if t not in ("cve",) and by_type[t]]
    type_score = min(40, len(real_types) * 15)

    # Count score
    count_score = min(40, real_count * 8)

    # Penalty for inflation
    inflation = max(0, stored_count - real_count)
    inflation_penalty = min(30, inflation * 2)

    score = max(0, type_score + count_score - inflation_penalty)

    if stored_count == 0 and real_count == 0:
        quality_label = "NONE"
    elif score >= 70:
        quality_label = "HIGH"
    elif score >= 40:
        quality_label = "MEDIUM"
    elif score >= 10:
        quality_label = "LOW"
    else:
        quality_label = "NEGLIGIBLE"

    return score, quality_label


# ══════════════════════════════════════════════════════════════════════════════
# PUBLICATION DECISION
# ══════════════════════════════════════════════════════════════════════════════

def publication_decision(
    grade: str,
    item: Dict,
    attck_status: str,
    ioc_qs: int,
    synthetic_violations: List[str],
) -> Tuple[str, str]:
    """
    Returns (decision, analyst_verdict).
    Rule 9: ALLOW / ALLOW_WITH_WARNING / QUARANTINE / BLOCK
    Rule 10: Enterprise customers get truth, not volume.

    IMPORTANT DISTINCTION:
      - Synthetic actor NULLING is a remediation action, NOT a block reason.
        The item's evidence (KEV, CVSS, EPSS, source) stands independently.
      - BLOCK only when the grade itself is F (insufficient evidence regardless
        of actor), or when a synthetic CAMPAIGN was injected and the item is
        Grade D/F (campaign fabrication with no underlying evidence).
    """
    warnings = []
    remediation_notes = []

    # Log actor/campaign nulling as remediation, not as violation
    for v in synthetic_violations:
        if "RULE2" in v:
            remediation_notes.append(v.replace("RULE2: ", ""))
        elif "RULE3" in v:
            remediation_notes.append(v.replace("RULE3: ", ""))

    # Hard BLOCK conditions
    hard_block_reasons = []

    # Grade F = no defensible evidence regardless of source or enrichment
    if grade == "F":
        hard_block_reasons.append(
            "Grade F — INSUFFICIENT VERIFIED EVIDENCE. "
            "No CVSS, no EPSS, no KEV, no real IOCs, no Tier 1/2 corroboration."
        )

    # Vendor blog / news items with APT tags and no threat evidence
    if grade in ("F", "D") and any("RULE3" in v for v in synthetic_violations):
        hard_block_reasons.append(
            "Grade D/F with synthetic campaign injection — "
            "campaign nulled; item lacks underlying threat evidence."
        )

    if hard_block_reasons:
        remediation_str = (
            f" Remediations applied: {'; '.join(remediation_notes)}."
            if remediation_notes else ""
        )
        verdict = (
            f"FAIL — {'; '.join(hard_block_reasons)}.{remediation_str} "
            f"Suppress from all feeds until evidence threshold met."
        )
        return "BLOCK", verdict

    # QUARANTINE: Grade D — suppress from premium, allow in public free tier only
    if grade == "D":
        if attck_status == "NOT_VERIFIED":
            warnings.append("ATT&CK stripped (corpus-mapped, no direct evidence)")
        if ioc_qs < 10:
            warnings.append("No deployable operational IOCs")
        if remediation_notes:
            warnings.append(f"Remediations applied: {'; '.join(remediation_notes)}")
        verdict = (
            f"WARNING — Grade D: weak evidence. "
            f"Quarantined from premium/enterprise/MSSP feeds. "
            f"Free informational tier only. Issues: {'; '.join(warnings)}."
        )
        return "QUARANTINE", verdict

    # ALLOW_WITH_WARNING: Grade C — partial evidence, or Grade B/A with remediations applied
    if attck_status == "NOT_VERIFIED":
        warnings.append("ATT&CK techniques stripped (corpus-mapped only)")
    if ioc_qs < 10:
        warnings.append("IOC quality low — no deployable operational indicators")
    if remediation_notes:
        warnings.append(f"Remediations applied: {'; '.join(remediation_notes)}")
    if grade == "C":
        warnings.append("Grade C — partial verification; monitor for escalation")

    if warnings or grade == "C":
        verdict = (
            f"PASS WITH WARNINGS — Grade {grade}. "
            f"Issues: {'; '.join(warnings) if warnings else 'none'}. "
            f"Eligible for publication with deficiency disclosure to subscribers."
        )
        return "ALLOW_WITH_WARNING", verdict

    # ALLOW: Grade A or B, clean evidence, remediations applied
    notes = item.get("_grade_notes", ["verified"])
    verdict = (
        f"PASS — Grade {grade}. {notes[0] if notes else 'Evidence verified'}. "
        f"Cleared for all tiers including enterprise and MSSP."
    )
    return "ALLOW", verdict


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT CONTRACT INJECTOR
# ══════════════════════════════════════════════════════════════════════════════

def inject_output_contract(item: Dict) -> Dict:
    """
    Inject all 10 mandatory Output Contract fields into an item.
    This is the final step before publication.
    Rule 9 — every field must be present. Missing fields = HARD FAIL.
    """
    # Step 1: Enforce attribution (Rules 2+3)
    item, attr_log = enforce_attribution(item)

    # Step 2: Compute verified ATT&CK (Rule 4)
    attck_status, verified_techs, attck_notes = verify_attck(item)

    # Step 3: Compute real IOC quality (Rule 5)
    ioc_qs, ioc_quality_label = ioc_quality_score(item)
    real_ioc_cnt = _real_ioc_count(item)

    # Step 4: Deterministic risk score (Rule 6)
    risk, risk_reasoning = compute_risk_score(item)

    # Step 5: Grade assignment (Rule 7)
    grade, grade_notes = assign_grade(item)
    item["_grade_notes"] = grade_notes

    # Step 6: Evidence and corroboration counts (Rule 4)
    srcs = _sources(item)
    evidence_count = len(srcs) + (1 if _has_kev(item) else 0) + (1 if item.get("cvss_score") else 0) + (1 if _epss_pct(item) > 0 else 0)
    corroboration_count = _corroboration_count(item)

    # Step 7: Publication decision (Rule 9)
    pub_decision, analyst_verdict = publication_decision(
        grade, item, attck_status, ioc_qs, attr_log
    )

    # Step 8: Inject all contract fields
    item.update({
        # 10 mandatory Output Contract fields
        "publication_decision": pub_decision,
        "intelligence_grade": grade,
        "evidence_count": evidence_count,
        "corroboration_count": corroboration_count,
        "attribution_status": item.get("attribution_status", "NONE"),
        "campaign_status": item.get("campaign_status", "UNVERIFIED"),
        "ioc_quality_score": ioc_qs,
        "ioc_quality_label": ioc_quality_label,
        "real_ioc_count": real_ioc_cnt,
        "attck_verification": attck_status,
        "attck_notes": attck_notes,
        "risk_score_reasoning": risk_reasoning,
        "analyst_verdict": analyst_verdict,
        # Corrected derived fields
        "risk_score": risk,
        "mitre_tactics": verified_techs,
        "ttps": verified_techs,
        # Grade metadata
        "grade_notes": grade_notes,
        "grade_engine_version": ENGINE_VERSION,
        "graded_at": datetime.now(timezone.utc).isoformat(),
    })

    # Clean internal key
    item.pop("_grade_notes", None)

    # EPSS normalization — store as percentage (0–100)
    raw_epss = item.get("epss_score")
    if raw_epss is not None:
        item["epss_score"] = round(_epss_pct(item), 2)
        item["epss_normalized"] = True

    return item


# ══════════════════════════════════════════════════════════════════════════════
# FEED PROCESSOR
# ══════════════════════════════════════════════════════════════════════════════

def process_feed(items: List[Dict]) -> Tuple[List[Dict], Dict]:
    """
    Apply grade engine to all items. Returns (processed_items, summary).
    """
    processed = []
    grade_counts = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
    decision_counts = {"ALLOW": 0, "ALLOW_WITH_WARNING": 0, "QUARANTINE": 0, "BLOCK": 0}

    for item in items:
        p = inject_output_contract(dict(item))
        grade_counts[p["intelligence_grade"]] = grade_counts.get(p["intelligence_grade"], 0) + 1
        decision_counts[p["publication_decision"]] = decision_counts.get(p["publication_decision"], 0) + 1
        processed.append(p)

    summary = {
        "total_items": len(items),
        "grade_distribution": grade_counts,
        "publication_decisions": decision_counts,
        "premium_eligible": decision_counts["ALLOW"],
        "warning_eligible": decision_counts["ALLOW_WITH_WARNING"],
        "quarantined": decision_counts["QUARANTINE"],
        "blocked": decision_counts["BLOCK"],
        "block_pct": round(decision_counts["BLOCK"] / max(len(items), 1) * 100, 1),
        "engine_version": ENGINE_VERSION,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }

    return processed, summary


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def _load(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        log.error("File not found: %s", path)
        sys.exit(2)
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    return data.get("items", data.get("data", []))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"SENTINEL APEX Intelligence Grade Engine v{ENGINE_VERSION}"
    )
    parser.add_argument("feed", nargs="?",
                        default=str(REPO_ROOT / "api" / "feed.json"))
    parser.add_argument("--apply", action="store_true",
                        help="Write graded items back to feed file")
    parser.add_argument("--manifest", default=None,
                        help="Also apply to feed_manifest.json")
    parser.add_argument("--report", default=None,
                        help="Write grade summary JSON to path")
    parser.add_argument("--gate", action="store_true",
                        help="Exit 1 if block_pct > 30%%")
    args = parser.parse_args()

    items = _load(args.feed)
    log.info("[grade-engine] Processing %d items from %s", len(items), args.feed)

    processed, summary = process_feed(items)

    log.info(
        "[grade-engine] GRADES: A=%d B=%d C=%d D=%d F=%d | "
        "DECISIONS: ALLOW=%d WARNING=%d QUARANTINE=%d BLOCK=%d(%.1f%%)",
        summary["grade_distribution"].get("A", 0),
        summary["grade_distribution"].get("B", 0),
        summary["grade_distribution"].get("C", 0),
        summary["grade_distribution"].get("D", 0),
        summary["grade_distribution"].get("F", 0),
        summary["publication_decisions"].get("ALLOW", 0),
        summary["publication_decisions"].get("ALLOW_WITH_WARNING", 0),
        summary["publication_decisions"].get("QUARANTINE", 0),
        summary["publication_decisions"].get("BLOCK", 0),
        summary["block_pct"],
    )

    if args.apply:
        Path(args.feed).write_text(
            json.dumps(processed, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        log.info("[grade-engine] Graded feed written to %s", args.feed)

    if args.manifest:
        manifest_path = Path(args.manifest)
        if manifest_path.exists():
            with manifest_path.open("r", encoding="utf-8") as fh:
                mdata = json.load(fh)
            mitems = mdata if isinstance(mdata, list) else mdata.get("items", mdata.get("data", []))
            # Build lookup by id
            grade_map = {p["id"]: p for p in processed if "id" in p}
            updated = 0
            for mi in mitems:
                mid = mi.get("id", mi.get("stix_id", ""))
                if mid in grade_map:
                    gp = grade_map[mid]
                    for field in [
                        "publication_decision", "intelligence_grade", "evidence_count",
                        "corroboration_count", "attribution_status", "campaign_status",
                        "ioc_quality_score", "real_ioc_count", "attck_verification",
                        "risk_score_reasoning", "analyst_verdict", "risk_score",
                        "grade_notes", "graded_at",
                    ]:
                        if field in gp:
                            mi[field] = gp[field]
                    updated += 1
            out = mdata if isinstance(mdata, list) else {**mdata, "items": mitems}
            if not isinstance(mdata, list):
                out["items"] = mitems
            manifest_path.write_text(
                json.dumps(out if isinstance(out, dict) else mitems, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
            log.info("[grade-engine] Manifest updated: %d/%d items graded", updated, len(mitems))

    if args.report:
        Path(args.report).write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        log.info("[grade-engine] Summary report written to %s", args.report)

    if args.gate and summary["block_pct"] > 30.0:
        log.error(
            "[grade-engine] GATE FAIL: %.1f%% of items BLOCKED (>30%% threshold)",
            summary["block_pct"],
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
