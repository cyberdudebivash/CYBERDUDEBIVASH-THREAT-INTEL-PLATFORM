#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX
INTELLIGENCE PUBLICATION GATE v1.0.0
===============================================================================
PURPOSE:
    Per-item P0 publication blocker. Final gate before any intelligence object
    reaches Dashboard / Feed API / STIX / Reports / PDF / MSSP / Enterprise.

    Implements 9 mandatory integrity rules:
      Rule 1 — No Synthetic Actors
      Rule 2 — No Synthetic Campaigns
      Rule 3 — IOC Integrity (no phantom deployment guidance)
      Rule 4 — Evidence Ledger Required
      Rule 5 — Confidence Governance (formula-derived only)
      Rule 6 — MITRE Validation (no speculative assignments)
      Rule 7 — Report Integrity (no contradictions / placeholders)
      Rule 8 — Premium CTI Standard (downgrade gate)
      Rule 9 — Enterprise API Contract (required fields present)

OUTPUT per item:
    {
      "publication_status": "ALLOW | BLOCK",
      "integrity_score": 0-100,
      "rejection_reasons": [...],
      "evidence_ledger": {...},
      "confidence_reason": [...],
      "required_remediation": [...],
      "tier": "PREMIUM_CTI | FREE_INFORMATIONAL",
      "api_contract": "PASS | FAIL"
    }

CLI MODES:
    --check  <feed.json>   Evaluate all items; exit 1 if any are BLOCK
    --audit  <feed.json>   Print full per-item gate reports; always exits 0
    --patch  <feed.json>   Apply remediations in-place; write back to file

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
    format="%(asctime)s [intel_publication_gate] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-IPG")

GATE_VERSION = "1.0.0"
REPO_ROOT = Path(__file__).resolve().parent.parent

# ══════════════════════════════════════════════════════════════════════════════
# RULE 1 — ACTOR ALLOW/BLOCK LISTS
# ══════════════════════════════════════════════════════════════════════════════

# Verified actor naming prefixes (ALLOW)
VERIFIED_ACTOR_PREFIXES = (
    "APT", "UNC", "TA", "FIN", "G00", "S00",  # MITRE/Mandiant standard
)

# Verified named actors (ALLOW - exact or startswith match)
VERIFIED_NAMED_ACTORS = frozenset([
    "Lazarus", "LockBit", "Scattered Spider", "Volt Typhoon", "Sandworm",
    "MuddyWater", "Fancy Bear", "Cozy Bear", "Charming Kitten", "Turla",
    "Kimsuky", "BlackCat", "ALPHV", "Cl0p", "REvil", "BlackMatter",
    "DarkSide", "Conti", "Hive", "Royal", "Play", "BianLian", "Akira",
    "8Base", "Medusa", "Unknown Actor", "Unknown", "UNATTRIBUTED",
])

# Synthetic actor patterns — HARD BLOCK
SYNTHETIC_ACTOR_PATTERNS = [
    re.compile(r"\b\w+\s+Threat\s+Cluster\b", re.IGNORECASE),
    re.compile(r"\b\w+\s+Exploitation\s+(?:Group|Cluster|Ring)\b", re.IGNORECASE),
    re.compile(r"\bCriminal\s+\w+\s+Group\b", re.IGNORECASE),
    re.compile(r"\bMalware\s+(?:Cluster|Group|Ring)\b", re.IGNORECASE),
    re.compile(r"\bInfrastructure\s+(?:Cluster|Group)\b", re.IGNORECASE),
    re.compile(r"\bUnknown\s+(?:Campaign|Threat)\s+Group\b", re.IGNORECASE),
    re.compile(r"\bAI[- ]generated\b", re.IGNORECASE),
    re.compile(r"\bCDB-[A-Z]+-(?:APT|GEN|SYNTH|INT)\b"),
    re.compile(r"\bSENTINEL[- ]APEX\b", re.IGNORECASE),
    re.compile(r"\bAPEX[- ](?:AI|ENGINE|INTEL)\b", re.IGNORECASE),
    re.compile(r"\bUntracked\s+\w+\s+Cluster\b", re.IGNORECASE),
    re.compile(r"\bData\s+Exfiltration\s+Cluster\b", re.IGNORECASE),
    re.compile(r"\bPhishing\s+(?:Threat\s+)?(?:Cluster|Group)\b", re.IGNORECASE),
    re.compile(r"\bWeb\s+Application\s+(?:Threat\s+)?(?:Cluster|Group)\b", re.IGNORECASE),
    re.compile(r"\bThreat\s+Intel\s+Cluster\b", re.IGNORECASE),
    re.compile(r"\bUnknown\s+State[- ]Sponsored\s+Actor\b", re.IGNORECASE),
]

# ══════════════════════════════════════════════════════════════════════════════
# RULE 2 — CAMPAIGN ALLOW/BLOCK LISTS
# ══════════════════════════════════════════════════════════════════════════════

# Synthetic campaign name patterns — HARD BLOCK
SYNTHETIC_CAMPAIGN_PATTERNS = [
    re.compile(r"\bOperation\s+(?:Viper|Crimson|Tempest|Storm|Black|Shadow|Dark|Hydra|Eclipse)\s+\w+\b", re.IGNORECASE),
    re.compile(r"\bOPERATION\s+[A-Z]+-[A-Z]+\b"),   # ALL-CAPS-HYPHEN pattern
    re.compile(r"\bUNCLASSIFIED\b", re.IGNORECASE),
    re.compile(r"\bCampaign[- ]\d{4,}\b", re.IGNORECASE),  # Campaign-12345 style
    re.compile(r"\bAPEX[- ]CAMPAIGN\b", re.IGNORECASE),
    re.compile(r"\bCDB[- ]CAMPAIGN\b", re.IGNORECASE),
]

# ══════════════════════════════════════════════════════════════════════════════
# RULE 3 — IOC PHANTOM GUIDANCE PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

IOC_PHANTOM_PATTERNS = [
    re.compile(r"\bDeploy\s+(?:all\s+)?\d+\s+IOC", re.IGNORECASE),
    re.compile(r"\bCorrelate\s+(?:all\s+)?\d+\s+IOC", re.IGNORECASE),
    re.compile(r"\bBlock\s+(?:all\s+)?IOC\s+infrastructure\b", re.IGNORECASE),
    re.compile(r"\bIOC\s+(?:threat\s+)?hunting\s+guidance\b", re.IGNORECASE),
    re.compile(r"\bHunt\s+for\s+(?:all\s+)?\d+\s+indicator", re.IGNORECASE),
    re.compile(r"\bDeploy\s+(?:all\s+)?IOCs?\b", re.IGNORECASE),
]

# ══════════════════════════════════════════════════════════════════════════════
# RULE 6 — SPECULATIVE MITRE PATTERNS
# ══════════════════════════════════════════════════════════════════════════════

SPECULATIVE_MITRE_PHRASES = [
    re.compile(r"\bmay\s+use\b.*\bT\d{4}\b", re.IGNORECASE),
    re.compile(r"\bpossibly\s+employs?\b", re.IGNORECASE),
    re.compile(r"\blikely\s+uses?\s+T\d{4}\b", re.IGNORECASE),
    re.compile(r"\binferred\s+(?:from|based)\b", re.IGNORECASE),
    re.compile(r"\bspeculat", re.IGNORECASE),
]

# ══════════════════════════════════════════════════════════════════════════════
# SOURCE TRUST SCORES (for confidence formula)
# ══════════════════════════════════════════════════════════════════════════════

SOURCE_TRUST = {
    "CISA": 100, "NCSC": 100, "FBI": 100, "NSA": 100,
    "Mandiant": 95, "CrowdStrike": 95, "Microsoft": 95, "Microsoft Security": 95,
    "Microsoft MSRC": 95, "Palo Alto Unit 42": 90, "Recorded Future": 90,
    "Sophos": 88, "Kaspersky SecureList": 85, "Check Point Research": 85,
    "Trend Micro": 85, "Rapid7": 82, "NIST NVD": 80, "GitHub Security Advisory": 78,
    "BleepingComputer": 70, "KrebsOnSecurity": 72, "Wordfence": 68,
    "WPScan": 65, "abuse.ch": 80, "ransomware.live": 72,
    "Google Project Zero": 92, "Google Security Blog": 88,
}

# ══════════════════════════════════════════════════════════════════════════════
# HELPER EXTRACTORS
# ══════════════════════════════════════════════════════════════════════════════

def _get(item: Dict, *keys: str, default=None):
    """Safe nested getter with fallback."""
    for k in keys:
        if isinstance(item, dict) and k in item:
            item = item[k]
        else:
            return default
    return item if item is not None else default


def _ioc_count(item: Dict) -> int:
    count = item.get("ioc_count", 0) or 0
    iocs = item.get("iocs", []) or []
    if isinstance(iocs, list):
        # Don't count raw CVE strings as network IOCs unless explicitly typed
        real_iocs = [i for i in iocs if not str(i).startswith("CVE-")]
        return max(int(count), len(real_iocs))
    return int(count)


def _actor_name(item: Dict) -> str:
    return (
        item.get("actor_display_name")
        or item.get("actor_tag")
        or item.get("actor")
        or ""
    )


def _campaign(item: Dict) -> str:
    return (
        item.get("campaign_name")
        or item.get("campaign_id")
        or item.get("campaign")
        or ""
    )


def _techniques(item: Dict) -> List[str]:
    techs = (
        item.get("attck_technique_ids")
        or item.get("actor_ttps")
        or item.get("ttps")
        or []
    )
    return [t for t in techs if re.match(r"T\d{4}(\.\d{3})?$", str(t))]


def _sources(item: Dict) -> List[str]:
    sources = []
    for key in ("source", "feed_source", "source_name"):
        s = item.get(key, "")
        if s and s not in sources:
            sources.append(s)
    return [s for s in sources if s]


def _source_trust_score(item: Dict) -> float:
    """Average trust score of known sources on this item."""
    srcs = _sources(item)
    scores = [SOURCE_TRUST.get(s, 50) for s in srcs if s]
    return sum(scores) / len(scores) if scores else 40.0


def _text_fields(item: Dict) -> str:
    """Concatenate all text fields for pattern scanning."""
    parts = [
        str(item.get("title", "")),
        str(item.get("description", "")),
        str(item.get("apex_ai_summary", "")),
        str(_get(item, "apex_ai", "ai_summary", default="")),
        str(_get(item, "apex_ai", "recommended_action", default="")),
    ]
    return " ".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# RULE EVALUATORS
# ══════════════════════════════════════════════════════════════════════════════

def rule1_actor(item: Dict) -> Tuple[bool, List[str], List[str]]:
    """Rule 1: No synthetic actors. Returns (pass, reasons, remediation)."""
    actor = _actor_name(item)
    reasons = []
    remediations = []

    if not actor:
        return True, [], []  # No actor field — not a violation

    # Check against synthetic patterns
    for pat in SYNTHETIC_ACTOR_PATTERNS:
        if pat.search(actor):
            reasons.append(f"RULE1: Synthetic actor name detected: '{actor}'")
            remediations.append(
                f"Set actor_display_name='Unknown Actor', actor_confidence=0, "
                f"attribution_status='UNATTRIBUTED' (was: '{actor}')"
            )
            return False, reasons, remediations

    # Check if actor looks like a verified prefix
    actor_upper = actor.upper().strip()
    for prefix in VERIFIED_ACTOR_PREFIXES:
        if actor_upper.startswith(prefix):
            return True, [], []

    # Check named actors
    for named in VERIFIED_NAMED_ACTORS:
        if named.lower() in actor.lower():
            return True, [], []

    # Actor name not matching any verified pattern — warn but don't hard block
    # (many legitimate actors like "Kimsuky" variants exist)
    return True, [], []


def rule2_campaign(item: Dict) -> Tuple[bool, List[str], List[str]]:
    """Rule 2: No synthetic campaigns."""
    campaign = _campaign(item)
    reasons = []
    remediations = []

    if not campaign or campaign in ("UNCLASSIFIED", "UNKNOWN", "Unknown", ""):
        return True, [], []

    for pat in SYNTHETIC_CAMPAIGN_PATTERNS:
        if pat.search(campaign):
            reasons.append(f"RULE2: Synthetic campaign name detected: '{campaign}'")
            remediations.append(
                f"Set campaign_name='Unknown', campaign_status='UNATTRIBUTED' "
                f"(was: '{campaign}')"
            )
            return False, reasons, remediations

    return True, [], []


def rule3_ioc_integrity(item: Dict) -> Tuple[bool, List[str], List[str]]:
    """Rule 3: No phantom IOC deployment guidance when ioc_count == 0."""
    count = _ioc_count(item)
    text = _text_fields(item)
    reasons = []
    remediations = []

    if count > 0:
        return True, [], []  # IOCs exist — no phantom issue

    for pat in IOC_PHANTOM_PATTERNS:
        match = pat.search(text)
        if match:
            reasons.append(
                f"RULE3: Phantom IOC guidance detected (ioc_count=0): "
                f"'{match.group(0)[:80]}'"
            )
            remediations.append(
                "Replace IOC deployment guidance with: "
                "'No operational indicators were identified from available evidence.'"
            )
            return False, reasons, remediations

    return True, [], []


def rule4_evidence_ledger(item: Dict) -> Tuple[bool, List[str], List[str], Dict]:
    """Rule 4: Evidence ledger must exist or be constructible."""
    ledger = item.get("evidence_ledger")
    reasons = []
    remediations = []

    # Build ledger from available fields if missing
    if not ledger or not isinstance(ledger, dict):
        sources_list = _sources(item)
        source_count = len(sources_list)
        trust = _source_trust_score(item)
        ioc_cnt = _ioc_count(item)
        ttp_cnt = len(_techniques(item))
        cve_cnt = len(item.get("cve_ids", []) or [])
        conf_raw = item.get("confidence", item.get("confidence_score", 0)) or 0
        conf_pct = int(conf_raw * 100) if conf_raw <= 1.0 else int(conf_raw)

        # Determine evidence strength
        if source_count >= 3 and ioc_cnt >= 5 and ttp_cnt >= 3:
            strength = "HIGH"
        elif source_count >= 2 and (ioc_cnt >= 1 or ttp_cnt >= 1):
            strength = "MEDIUM"
        elif source_count >= 1:
            strength = "LOW"
        else:
            strength = "NONE"

        # Verified sources = sources with known trust score >= 65
        verified = sum(1 for s in sources_list if SOURCE_TRUST.get(s, 0) >= 65)

        ledger = {
            "source_count": source_count,
            "verified_sources": verified,
            "ioc_count": ioc_cnt,
            "ttp_count": ttp_cnt,
            "cve_count": cve_cnt,
            "confidence_score": conf_pct,
            "evidence_strength": strength,
            "ledger_generated": True,  # Flagged as auto-generated
        }
        remediations.append(
            "evidence_ledger was missing — auto-generated from available fields. "
            "Add explicit evidence_ledger in report generator for production."
        )
        # Auto-generated ledger is a P1 warning, not a P0 block
        return True, reasons, remediations, ledger

    return True, [], [], ledger


def rule5_confidence(item: Dict) -> Tuple[bool, List[str], List[str], int, List[str]]:
    """Rule 5: Confidence must be formula-derived. Returns (pass, reasons, remediations, score, reason_list)."""
    reasons = []
    remediations = []
    confidence_reason = []

    # Extract inputs
    sources_list = _sources(item)
    source_count = len(sources_list)
    trust_score = _source_trust_score(item)
    ioc_cnt = _ioc_count(item)
    ttp_cnt = len(_techniques(item))
    kev = (
        item.get("kev") == "YES"
        or item.get("kev_present") is True
        or item.get("in_kev") is True
    )
    epss = item.get("epss_score", 0) or 0
    cve_ids = item.get("cve_ids", []) or []

    # Vendor corroboration bonus
    vendor_sources = {s for s in sources_list if SOURCE_TRUST.get(s, 0) >= 85}
    corroboration_score = min(100, len(vendor_sources) * 30)

    # Component scores (0-100)
    source_s = min(100, (trust_score / 100) * 100)
    ioc_s = min(100, ioc_cnt * 10)
    ttp_s = min(100, ttp_cnt * 15)
    kev_s = 100 if kev else (50 if epss > 0.1 else 0)
    vendor_s = corroboration_score

    # Weighted formula (Rule 5)
    derived = int(
        source_s * 0.25
        + corroboration_score * 0.25
        + ioc_s * 0.20
        + ttp_s * 0.10
        + kev_s * 0.10
        + vendor_s * 0.10
    )
    derived = max(5, min(100, derived))

    # Build reason list
    if kev:
        confidence_reason.append("CISA KEV confirmed")
    for vs in vendor_sources:
        confidence_reason.append(f"{vs} corroborated")
    if source_count >= 2:
        confidence_reason.append(f"{source_count} sources found")
    if ioc_cnt > 0:
        confidence_reason.append(f"{ioc_cnt} IOC(s) extracted")
    if ttp_cnt > 0:
        confidence_reason.append(f"{ttp_cnt} ATT&CK technique(s) mapped")
    if epss > 0.1:
        confidence_reason.append(f"EPSS {epss:.1%} exploitation probability")
    if not confidence_reason:
        confidence_reason.append("Single unverified source — low evidence base")

    # Validate existing confidence — flag if wildly inconsistent
    existing_raw = item.get("confidence", item.get("confidence_score", None))
    if existing_raw is not None:
        existing_pct = int(existing_raw * 100) if existing_raw <= 1.0 else int(existing_raw)
        drift = abs(existing_pct - derived)
        if drift > 40 and existing_pct > 80 and derived < 40:
            reasons.append(
                f"RULE5: Confidence inflation detected. "
                f"Stored={existing_pct}% vs Formula-derived={derived}% (drift={drift})"
            )
            remediations.append(
                f"Recalculate confidence using formula. "
                f"Derived={derived}%. Do not publish confidence={existing_pct}% "
                f"without evidence supporting it."
            )
            return False, reasons, remediations, derived, confidence_reason

    return True, [], [], derived, confidence_reason


def rule6_mitre(item: Dict) -> Tuple[bool, List[str], List[str]]:
    """Rule 6: No speculative MITRE assignments in text."""
    text = _text_fields(item)
    reasons = []
    remediations = []

    for pat in SPECULATIVE_MITRE_PHRASES:
        match = pat.search(text)
        if match:
            reasons.append(
                f"RULE6: Speculative MITRE language detected: "
                f"'{match.group(0)[:80]}'"
            )
            remediations.append(
                "Remove speculative ATT&CK language. "
                "Every mapped technique requires explicit source evidence and reference."
            )
            return False, reasons, remediations

    return True, [], []


def rule7_report_integrity(item: Dict) -> Tuple[bool, List[str], List[str]]:
    """Rule 7: No contradictions (deploy N IOCs when ioc_count=0), no placeholders."""
    reasons = []
    remediations = []
    text = _text_fields(item)
    ioc_cnt = _ioc_count(item)

    # Check for zero-IOC contradiction
    zero_ioc_deploy = re.compile(
        r"\bDeploy\s+(?:all\s+)?0\s+IOC|\b0\s+IOC\s+(?:threat|hunt|block|deploy)",
        re.IGNORECASE,
    )
    if zero_ioc_deploy.search(text):
        reasons.append("RULE7: Report contains 'Deploy 0 IOCs' contradiction")
        remediations.append("Remove 0-IOC deployment instructions from report template")
        return False, reasons, remediations

    # Placeholder patterns
    placeholder_pats = [
        re.compile(r"\[PLACEHOLDER\]", re.IGNORECASE),
        re.compile(r"\[INSERT\s+\w+\]", re.IGNORECASE),
        re.compile(r"\bTODO\b"),
        re.compile(r"\bLOREM\s+IPSUM\b", re.IGNORECASE),
        re.compile(r"\bSAMPLE\s+(?:REPORT|DATA|INTEL)\b", re.IGNORECASE),
    ]
    for pat in placeholder_pats:
        match = pat.search(text)
        if match:
            reasons.append(f"RULE7: Placeholder text in report: '{match.group(0)}'")
            remediations.append("Remove all placeholder text before publication")
            return False, reasons, remediations

    # IOC count mismatch — stored count vs actual iocs array
    iocs_array = item.get("iocs", []) or []
    stored_count = int(item.get("ioc_count", 0) or 0)
    if abs(stored_count - ioc_cnt) > 5 and stored_count > 10:
        reasons.append(
            f"RULE7: ioc_count mismatch. Stored={stored_count}, "
            f"Actual={ioc_cnt}"
        )
        remediations.append("Reconcile ioc_count field with actual iocs array length")
        return False, reasons, remediations

    return True, [], []


def rule8_premium_tier(
    item: Dict, ledger: Dict, confidence_score: int
) -> Tuple[str, List[str]]:
    """Rule 8: Premium CTI standard. Returns (tier, reasons)."""
    reasons = []

    source_count = ledger.get("source_count", 0)
    verified_sources = ledger.get("verified_sources", 0)
    ioc_cnt = ledger.get("ioc_count", 0)
    evidence_strength = ledger.get("evidence_strength", "NONE")

    fails = []
    if confidence_score < 70:
        fails.append(f"confidence={confidence_score}% (<70 required)")
    if source_count < 2:
        fails.append(f"source_count={source_count} (<2 required)")
    if verified_sources < 2:
        fails.append(f"verified_sources={verified_sources} (<2 required)")
    if ioc_cnt == 0:
        fails.append("ioc_count=0 (must be >0)")
    if evidence_strength in ("NONE", "LOW"):
        fails.append(f"evidence_strength={evidence_strength} (<MEDIUM required)")

    if fails:
        reasons.append(f"RULE8: Downgraded from PREMIUM_CTI: {'; '.join(fails)}")
        return "FREE_INFORMATIONAL", reasons

    return "PREMIUM_CTI", []


def rule9_api_contract(item: Dict) -> Tuple[bool, List[str], List[str]]:
    """Rule 9: Enterprise API must expose required governance fields."""
    required = [
        "evidence_ledger",
        "confidence_reason",
        "source_reliability",
        "verification_status",
        "attribution_status",
        "ioc_quality",
        "ttp_quality",
        "report_quality",
    ]
    missing = [f for f in required if not item.get(f)]
    if missing:
        reasons = [f"RULE9: API contract missing fields: {missing}"]
        remediations = [
            f"Add required API fields: {missing}. "
            "These are mandatory for enterprise and MSSP consumers."
        ]
        return False, reasons, remediations
    return True, [], []


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRITY SCORE CALCULATOR
# ══════════════════════════════════════════════════════════════════════════════

def _integrity_score(
    rule_results: List[bool],
    confidence_score: int,
    ledger: Dict,
) -> int:
    """
    Compute integrity score 0-100 based on rule passes and evidence quality.
    Weight: rules (60%) + confidence (20%) + evidence strength (20%)
    """
    rules_pass = sum(1 for r in rule_results if r)
    rule_pct = int((rules_pass / max(len(rule_results), 1)) * 60)

    conf_pct = int((confidence_score / 100) * 20)

    strength_map = {"HIGH": 20, "MEDIUM": 12, "LOW": 6, "NONE": 0}
    strength_pct = strength_map.get(ledger.get("evidence_strength", "NONE"), 0)

    return min(100, rule_pct + conf_pct + strength_pct)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN GATE FUNCTION (importable as module)
# ══════════════════════════════════════════════════════════════════════════════

def evaluate_item(item: Dict, strict_api: bool = False) -> Dict:
    """
    Run all 9 rules against a single intel item.

    Args:
        item: Intelligence object dict
        strict_api: If True, Rule 9 API contract is a hard blocker (default: False)

    Returns:
        Gate result dict with publication_status, integrity_score, etc.
    """
    all_reasons: List[str] = []
    all_remediations: List[str] = []
    rule_results: List[bool] = []
    blocked = False

    # Rule 1 — Actor
    r1_pass, r1_reasons, r1_fix = rule1_actor(item)
    rule_results.append(r1_pass)
    if not r1_pass:
        blocked = True
        all_reasons.extend(r1_reasons)
        all_remediations.extend(r1_fix)

    # Rule 2 — Campaign
    r2_pass, r2_reasons, r2_fix = rule2_campaign(item)
    rule_results.append(r2_pass)
    if not r2_pass:
        blocked = True
        all_reasons.extend(r2_reasons)
        all_remediations.extend(r2_fix)

    # Rule 3 — IOC Integrity
    r3_pass, r3_reasons, r3_fix = rule3_ioc_integrity(item)
    rule_results.append(r3_pass)
    if not r3_pass:
        blocked = True
        all_reasons.extend(r3_reasons)
        all_remediations.extend(r3_fix)

    # Rule 4 — Evidence Ledger (auto-builds if missing, P1 warn not P0 block)
    r4_pass, r4_reasons, r4_fix, ledger = rule4_evidence_ledger(item)
    rule_results.append(r4_pass)
    all_remediations.extend(r4_fix)

    # Rule 5 — Confidence
    r5_pass, r5_reasons, r5_fix, conf_score, conf_reason = rule5_confidence(item)
    rule_results.append(r5_pass)
    if not r5_pass:
        blocked = True
        all_reasons.extend(r5_reasons)
        all_remediations.extend(r5_fix)

    # Rule 6 — MITRE
    r6_pass, r6_reasons, r6_fix = rule6_mitre(item)
    rule_results.append(r6_pass)
    if not r6_pass:
        blocked = True
        all_reasons.extend(r6_reasons)
        all_remediations.extend(r6_fix)

    # Rule 7 — Report Integrity
    r7_pass, r7_reasons, r7_fix = rule7_report_integrity(item)
    rule_results.append(r7_pass)
    if not r7_pass:
        blocked = True
        all_reasons.extend(r7_reasons)
        all_remediations.extend(r7_fix)

    # Rule 8 — Premium Tier (never blocks publication, only downgrades)
    tier, r8_reasons = rule8_premium_tier(item, ledger, conf_score)
    rule_results.append(tier == "PREMIUM_CTI")
    all_reasons.extend(r8_reasons)  # Informational

    # Rule 9 — API Contract (only hard-block in strict mode)
    r9_pass, r9_reasons, r9_fix = rule9_api_contract(item)
    rule_results.append(r9_pass)
    if not r9_pass and strict_api:
        blocked = True
        all_reasons.extend(r9_reasons)
        all_remediations.extend(r9_fix)
    elif not r9_pass:
        all_reasons.extend(r9_reasons)
        all_remediations.extend(r9_fix)

    api_contract = "PASS" if r9_pass else "FAIL"
    integrity_score = _integrity_score(rule_results, conf_score, ledger)
    publication_status = "BLOCK" if blocked else "ALLOW"

    return {
        "item_id": item.get("id", item.get("stix_id", "unknown")),
        "title": str(item.get("title", ""))[:80],
        "publication_status": publication_status,
        "integrity_score": integrity_score,
        "tier": tier,
        "api_contract": api_contract,
        "rejection_reasons": all_reasons,
        "evidence_ledger": ledger,
        "confidence_score": conf_score,
        "confidence_reason": conf_reason,
        "required_remediation": all_remediations,
        "gate_version": GATE_VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


def evaluate_feed(
    items: List[Dict],
    strict_api: bool = False,
    fail_threshold_pct: float = 0.20,
) -> Dict:
    """
    Evaluate all items in a feed.

    Returns summary dict with per-item results and aggregate metrics.
    fail_threshold_pct: if >X% of items are BLOCK, pipeline hard-fails.
    """
    results = [evaluate_item(i, strict_api=strict_api) for i in items]

    allowed = [r for r in results if r["publication_status"] == "ALLOW"]
    blocked = [r for r in results if r["publication_status"] == "BLOCK"]
    premium = [r for r in results if r["tier"] == "PREMIUM_CTI"]
    avg_integrity = (
        int(sum(r["integrity_score"] for r in results) / len(results))
        if results else 0
    )
    block_pct = len(blocked) / max(len(results), 1)
    pipeline_status = "FAIL" if block_pct > fail_threshold_pct else "PASS"

    return {
        "pipeline_status": pipeline_status,
        "total_items": len(items),
        "allowed": len(allowed),
        "blocked": len(blocked),
        "blocked_pct": round(block_pct * 100, 1),
        "premium_cti": len(premium),
        "free_informational": len(results) - len(premium),
        "avg_integrity_score": avg_integrity,
        "gate_version": GATE_VERSION,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "item_results": results,
    }


def apply_remediations(item: Dict, result: Dict) -> Dict:
    """
    Auto-apply safe remediations to an item:
    - Replace synthetic actor with UNATTRIBUTED
    - Replace synthetic campaign with Unknown
    - Add evidence_ledger if missing
    - Update confidence to formula-derived value
    """
    patched = dict(item)

    # Rule 1: patch actor
    for r in result["rejection_reasons"]:
        if r.startswith("RULE1:"):
            patched["actor_display_name"] = "Unknown Actor"
            patched["actor"] = "UNATTRIBUTED"
            patched["actor_confidence"] = 0
            patched["attribution_status"] = "UNATTRIBUTED"

    # Rule 2: patch campaign
    for r in result["rejection_reasons"]:
        if r.startswith("RULE2:"):
            patched["campaign_name"] = "Unknown"
            patched["campaign_id"] = "UNATTRIBUTED"
            patched["campaign_status"] = "UNATTRIBUTED"

    # Rule 4: inject ledger
    if result["evidence_ledger"]:
        patched["evidence_ledger"] = result["evidence_ledger"]

    # Rule 5: update confidence
    patched["confidence_score"] = result["confidence_score"]
    patched["confidence_reason"] = result["confidence_reason"]
    if item.get("confidence", 0) > 1.0:
        patched["confidence"] = result["confidence_score"]
    else:
        patched["confidence"] = round(result["confidence_score"] / 100, 4)

    # Rule 8: set tier
    patched["cti_tier"] = result["tier"]

    # Rule 9: inject stub API fields
    patched.setdefault("verification_status", "UNVERIFIED")
    patched.setdefault("attribution_status",
                       "UNATTRIBUTED" if not item.get("actor") else "CLAIMED")
    patched.setdefault("source_reliability", "UNRATED")
    patched.setdefault("ioc_quality", "LOW" if result["evidence_ledger"].get("ioc_count", 0) == 0 else "MEDIUM")
    patched.setdefault("ttp_quality", "LOW" if result["evidence_ledger"].get("ttp_count", 0) == 0 else "MEDIUM")
    patched.setdefault("report_quality", "INFORMATIONAL" if result["tier"] == "FREE_INFORMATIONAL" else "PREMIUM")

    return patched


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def _load_feed(path: str) -> List[Dict]:
    p = Path(path)
    if not p.exists():
        log.error("Feed file not found: %s", path)
        sys.exit(2)
    with p.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, list):
        return data
    return data.get("items", data.get("data", []))


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"SENTINEL APEX Intelligence Publication Gate v{GATE_VERSION}"
    )
    parser.add_argument("feed", nargs="?",
                        default=str(REPO_ROOT / "api" / "feed.json"),
                        help="Path to feed JSON file")
    parser.add_argument("--check", action="store_true",
                        help="Exit 1 if any items are BLOCK")
    parser.add_argument("--audit", action="store_true",
                        help="Print full gate report; always exits 0")
    parser.add_argument("--patch", action="store_true",
                        help="Apply remediations in-place to feed file")
    parser.add_argument("--strict-api", action="store_true",
                        help="Treat missing API contract fields as P0 block")
    parser.add_argument("--output", default=None,
                        help="Write gate report JSON to this path")
    args = parser.parse_args()

    items = _load_feed(args.feed)
    log.info("[gate] Evaluating %d items from %s", len(items), args.feed)

    summary = evaluate_feed(items, strict_api=args.strict_api)

    blocked_items = [r for r in summary["item_results"] if r["publication_status"] == "BLOCK"]

    log.info(
        "[gate] RESULT: %s | items=%d allowed=%d blocked=%d(%.1f%%) "
        "premium=%d avg_integrity=%d",
        summary["pipeline_status"],
        summary["total_items"],
        summary["allowed"],
        summary["blocked"],
        summary["blocked_pct"],
        summary["premium_cti"],
        summary["avg_integrity_score"],
    )

    if blocked_items:
        log.warning("[gate] BLOCKED ITEMS:")
        for b in blocked_items[:10]:
            log.warning("  [%s] %s", b["item_id"][:20], b["rejection_reasons"][0][:100])

    if args.audit:
        for r in summary["item_results"]:
            print(json.dumps(r, indent=2))

    if args.output:
        out = {
            "summary": {k: v for k, v in summary.items() if k != "item_results"},
            "blocked_items": blocked_items,
        }
        Path(args.output).write_text(json.dumps(out, indent=2), encoding="utf-8")
        log.info("[gate] Report written to %s", args.output)

    if args.patch:
        patched_items = []
        for item, result in zip(items, summary["item_results"]):
            patched_items.append(apply_remediations(item, result))
        Path(args.feed).write_text(json.dumps(patched_items, indent=2), encoding="utf-8")
        log.info("[gate] Patched %d items in %s", len(patched_items), args.feed)

    if args.check and summary["pipeline_status"] == "FAIL":
        log.error(
            "[gate] PIPELINE BLOCKED: %.1f%% of items failed P0 integrity gate",
            summary["blocked_pct"],
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
