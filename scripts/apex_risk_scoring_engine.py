#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/apex_risk_scoring_engine.py — Evidence-Weighted Risk Scoring Engine
================================================================================
Version : 152.0.0

PROBLEM SOLVED:
  The legacy pipeline produces STATIC BUCKET SCORES:
    CRITICAL = 10.0, HIGH = 7.5, MEDIUM = 5.5, LOW = 2.3
  These are hardcoded by severity label. They do NOT reflect actual risk.
  A CRITICAL label on a Vulners advisory with no CVSS, no EPSS, and no KEV
  entry has ZERO business justification for a 10.0 score.

SOLUTION — APEX EVIDENCE-WEIGHTED COMPOSITE SCORE:

  APEX_RISK_SCORE = Σ(signal × weight) × sector_multiplier

  Signal Weights:
    CVSS_BASE_NORMALIZED          0.22  (most widely understood baseline)
    EPSS_30D_PROBABILITY          0.22  (real-world exploit probability)
    KEV_STATUS                    0.18  (binary: CISA confirmed exploitation)
    EXPLOIT_MATURITY              0.14  (PoC→weaponised→ITW progression)
    RANSOMWARE_ASSOCIATION        0.10  (linked to active ransomware ecosystem)
    INTERNET_EXPOSURE_ESTIMATE    0.08  (attack vector + scope)
    OT_ICS_IMPACT                 0.04  (ICS/SCADA in affected product scope)
    ATTACK_CHAIN_POTENTIAL        0.02  (exploit chaining / privilege escalation)

  Sector Multiplier (1.0–1.5):
    Healthcare / ICS-Critical : 1.45
    Financial Services        : 1.30
    Energy / Utilities / OT   : 1.40
    Government                : 1.25
    Technology                : 1.20
    Default (cross-sector)    : 1.00

  Score is clamped to [0.0, 10.0].
  Every score includes a full evidence chain (score_evidence dict).

EXPLAINABILITY:
  Every scored item includes:
    apex_risk_evidence: {
      signal_name: { raw_value, normalised, contribution, evidence_source }
    }
    apex_risk_rationale: "Human-readable explanation of why the score is X"
    apex_risk_ceiling:   "What would push this score higher?"
================================================================================
"""
from __future__ import annotations

import json
import logging
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("apex.risk_scoring")

ENGINE_VERSION = "152.0.0"
ENGINE_ID      = "APEX-RSE"

# ── Signal weights (must sum to 1.0) ─────────────────────────────────────────
WEIGHTS = {
    "cvss_base":              0.22,
    "epss_30d":               0.22,
    "kev_status":             0.18,
    "exploit_maturity":       0.14,
    "ransomware_association": 0.10,
    "internet_exposure":      0.08,
    "ot_ics_impact":          0.04,
    "attack_chain_potential": 0.02,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "Weights must sum to 1.0"

# ── Sector criticality multipliers ────────────────────────────────────────────
SECTOR_MULTIPLIERS = {
    "healthcare":         1.45,
    "ics":                1.40,
    "ot":                 1.40,
    "scada":              1.40,
    "energy":             1.40,
    "utilities":          1.35,
    "financial":          1.30,
    "banking":            1.30,
    "government":         1.25,
    "defence":            1.35,
    "defense":            1.35,
    "telecom":            1.25,
    "technology":         1.20,
    "cloud":              1.20,
    "education":          1.10,
    "retail":             1.05,
    "default":            1.00,
}

# ── Exploit maturity progression ─────────────────────────────────────────────
# Maps various source strings to a 0.0–1.0 maturity value
EXPLOIT_MATURITY_MAP = {
    # No exploit
    "none":                   0.00,
    "no exploit":             0.00,
    "unproven":               0.00,
    "theoretical":            0.10,
    # PoC published
    "proof-of-concept":       0.50,
    "poc":                    0.50,
    "proof of concept":       0.50,
    "functional":             0.60,
    # Weaponised / in-the-wild
    "high":                   0.75,
    "weaponized":             0.80,
    "weaponised":             0.80,
    "exploited":              0.90,
    "in the wild":            0.90,
    "in-the-wild":            0.90,
    "itw":                    0.90,
    "active exploitation":    1.00,
    "actively exploited":     1.00,
    "confirmed":              1.00,
}

# ── Products/keywords indicating OT/ICS relevance ────────────────────────────
OT_ICS_KEYWORDS = re.compile(
    r"(scada|ics|ot\s+|industrial\s+control|plc|hmi|historian|"
    r"siemens\s+s7|modbus|dnp3|profinet|iec\s+61850|iec\s+62443|"
    r"yokogawa|schneider\s+electric|rockwell|allen-bradley|"
    r"honeyw|abb\s+|omron|mitsubishi\s+electric\s+melsec|"
    r"water\s+treatment|power\s+grid|substation|pipeline)",
    re.IGNORECASE,
)

# ── Ransomware association keywords ──────────────────────────────────────────
RANSOMWARE_KEYWORDS = re.compile(
    r"(ransomware|lockbit|blackcat|alphv|clop|cl0p|revil|ryuk|"
    r"conti|hive|blackbasta|play\s+ransomware|akira|medusa|"
    r"royal\s+ransomware|cuba\s+ransomware|bianlian|scattered\s+spider|"
    r"extortion|double\s+extortion|data\s+leak\s+site|"
    r"data\s+exfiltration.*ransom|ransom.*data\s+exfiltration)",
    re.IGNORECASE,
)

# ── Internet exposure inference ───────────────────────────────────────────────
NETWORK_ATTACK_VECTOR_PATTERNS = re.compile(
    r"(network|adjacent|remote\s+code|unauthenticated|internet.facing|"
    r"exposed\s+endpoint|public.facing|wan.facing|web\s+interface|"
    r"soap\s+endpoint|rest\s+api|http|https|vpn|rdp|smb|ftp|ssh\s+server)",
    re.IGNORECASE,
)

# ── Attack chain potential ────────────────────────────────────────────────────
CHAIN_KEYWORDS = re.compile(
    r"(privilege\s+escalation|lateral\s+movement|credential\s+harvest|"
    r"pass.the.hash|kerberoast|token\s+impersonation|"
    r"remote\s+code\s+execution|code\s+injection|"
    r"chaining|exploit\s+chain|0.click|zero.click|"
    r"pre-auth\s+rce|unauthenticated\s+rce)",
    re.IGNORECASE,
)


# ── Signal extractors ─────────────────────────────────────────────────────────

def _extract_cvss(item: Dict) -> Tuple[float, str]:
    """Returns (normalised 0-1, evidence_string)."""
    for key in ("cvss_score", "cvss", "cvss_base", "cvss3_score", "cvss_v3"):
        val = item.get(key)
        if val is not None and val not in ("N/A", "", "Pending", None):
            try:
                score = float(val)
                if 0.0 <= score <= 10.0:
                    return round(score / 10.0, 4), f"CVSS={score}"
            except (ValueError, TypeError):
                pass
    return 0.0, "CVSS=N/A (no score available; zero contribution)"


def _extract_epss(item: Dict) -> Tuple[float, str]:
    """Returns (normalised 0-1, evidence_string)."""
    for key in ("epss_score", "epss", "epss_30d", "epss_probability"):
        val = item.get(key)
        if val is not None and val not in ("N/A", "", "Pending", None):
            try:
                v = float(str(val).rstrip("%"))
                # If expressed as percentage (0-100), normalise
                if v > 1.0:
                    v = v / 100.0
                v = max(0.0, min(1.0, v))
                return round(v, 4), f"EPSS(30d)={v*100:.2f}%"
            except (ValueError, TypeError):
                pass
    return 0.0, "EPSS=N/A (no exploit probability data; zero contribution)"


def _extract_kev(item: Dict) -> Tuple[float, str]:
    """Returns (1.0 if KEV listed, 0.0 otherwise)."""
    kev = item.get("kev") or item.get("cisa_kev") or item.get("kev_listed") or ""
    if str(kev).strip().upper() in ("YES", "TRUE", "1", "LISTED"):
        return 1.0, "CISA KEV=LISTED (confirmed active exploitation)"
    return 0.0, "CISA KEV=NOT LISTED"


def _extract_exploit_maturity(item: Dict) -> Tuple[float, str]:
    """Returns (0.0-1.0, evidence)."""
    for key in ("exploit_maturity", "exploit_status", "exploit_stage",
                "exploitability", "vulnrichment_exploit_maturity"):
        val = str(item.get(key) or "").strip().lower()
        if val in EXPLOIT_MATURITY_MAP:
            return EXPLOIT_MATURITY_MAP[val], f"ExploitMaturity={val}"

    # Infer from title / description
    for field in ("title", "description", "summary", "executive_summary"):
        text = str(item.get(field) or "")
        if re.search(r"actively exploit|in.the.wild|itw", text, re.I):
            return 0.90, "ExploitMaturity=in-wild (inferred from text)"
        if re.search(r"weaponi[sz]ed|metasploit\s+module|exploit\s+framework", text, re.I):
            return 0.80, "ExploitMaturity=weaponised (inferred from text)"
        if re.search(r"proof.of.concept|poc\s+available|poc\s+published|github\.com.*exploit", text, re.I):
            return 0.55, "ExploitMaturity=PoC (inferred from text)"
    return 0.10, "ExploitMaturity=theoretical (no exploit evidence)"


def _extract_ransomware(item: Dict) -> Tuple[float, str]:
    """Returns (0.0-1.0, evidence)."""
    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "actor_cluster",
        "threat_type", "campaign", "malware_family",
    ))
    if RANSOMWARE_KEYWORDS.search(all_text):
        # Higher score if actor cluster is a known ransomware group
        actor = str(item.get("actor_cluster") or "")
        if re.search(r"lockbit|blackcat|alphv|clop|akira|blackbasta|play\s+ransom", actor, re.I):
            return 1.0, "RansomwareAssociation=DIRECT (named ransomware group)"
        return 0.75, "RansomwareAssociation=INDIRECT (ransomware keywords in text)"
    return 0.0, "RansomwareAssociation=NONE"


def _extract_internet_exposure(item: Dict) -> Tuple[float, str]:
    """Returns (0.0-1.0, evidence)."""
    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "attack_vector",
        "vulnerability_type", "affected_products",
    ))
    attack_vector = str(item.get("attack_vector") or "").upper()

    # Direct CVSS attack vector
    if attack_vector == "NETWORK" or "AV:N" in str(item.get("cvss_vector") or ""):
        return 0.90, "InternetExposure=HIGH (CVSS AV:Network)"
    if attack_vector in ("ADJACENT", "ADJACENT_NETWORK"):
        return 0.50, "InternetExposure=MEDIUM (CVSS AV:Adjacent)"
    if attack_vector == "LOCAL":
        return 0.20, "InternetExposure=LOW (CVSS AV:Local)"
    if attack_vector == "PHYSICAL":
        return 0.10, "InternetExposure=MINIMAL (CVSS AV:Physical)"

    # Infer from text
    if NETWORK_ATTACK_VECTOR_PATTERNS.search(all_text):
        return 0.75, "InternetExposure=HIGH (network attack vector inferred from text)"
    return 0.30, "InternetExposure=UNKNOWN (defaulting to 30% — validate manually)"


def _extract_ot_ics(item: Dict) -> Tuple[float, str]:
    """Returns (0.0-1.0, evidence)."""
    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "affected_products",
        "affected_systems", "threat_type",
    ))
    if OT_ICS_KEYWORDS.search(all_text):
        return 1.0, "OT_ICS=IN_SCOPE (OT/ICS product keywords detected)"
    return 0.0, "OT_ICS=NOT_IN_SCOPE"


def _extract_chain_potential(item: Dict) -> Tuple[float, str]:
    """Returns (0.0-1.0, evidence)."""
    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "description", "summary", "attack_chain",
    ))
    if CHAIN_KEYWORDS.search(all_text):
        # How many chaining indicators?
        matches = CHAIN_KEYWORDS.findall(all_text)
        distinct = len(set(m[0].lower() for m in matches)) if matches else 0
        score = min(1.0, 0.3 + distinct * 0.15)
        return round(score, 2), f"ChainPotential=HIGH ({distinct} chaining indicators)"
    return 0.0, "ChainPotential=NONE (no exploit chaining indicators)"


def _infer_sector_multiplier(item: Dict) -> Tuple[float, str]:
    """Infer sector from product/title/tags."""
    all_text = " ".join(str(item.get(k) or "") for k in (
        "title", "sector", "industry", "affected_products",
        "target_sector", "description",
    )).lower()

    for sector_key, mult in sorted(SECTOR_MULTIPLIERS.items(), key=lambda x: -x[1]):
        if sector_key == "default":
            continue
        if sector_key in all_text:
            return mult, f"SectorMultiplier={mult}x ({sector_key})"
    return 1.00, "SectorMultiplier=1.00 (cross-sector / sector unknown)"


# ── Main scoring function ─────────────────────────────────────────────────────

def compute_apex_risk(item: Dict) -> Dict:
    """
    Compute evidence-weighted APEX risk score for a single intel item.

    Returns the item with apex_risk, apex_risk_evidence, apex_risk_rationale
    fields added (never modifies existing fields).
    """
    signals = {}

    cvss_norm, cvss_ev        = _extract_cvss(item)
    epss_norm, epss_ev        = _extract_epss(item)
    kev_val,   kev_ev         = _extract_kev(item)
    mat_val,   mat_ev         = _extract_exploit_maturity(item)
    ran_val,   ran_ev         = _extract_ransomware(item)
    exp_val,   exp_ev         = _extract_internet_exposure(item)
    ot_val,    ot_ev          = _extract_ot_ics(item)
    chain_val, chain_ev       = _extract_chain_potential(item)
    sec_mult,  sec_ev         = _infer_sector_multiplier(item)

    raw_vals = {
        "cvss_base":              cvss_norm,
        "epss_30d":               epss_norm,
        "kev_status":             kev_val,
        "exploit_maturity":       mat_val,
        "ransomware_association": ran_val,
        "internet_exposure":      exp_val,
        "ot_ics_impact":          ot_val,
        "attack_chain_potential": chain_val,
    }
    evidences = {
        "cvss_base":              cvss_ev,
        "epss_30d":               epss_ev,
        "kev_status":             kev_ev,
        "exploit_maturity":       mat_ev,
        "ransomware_association": ran_ev,
        "internet_exposure":      exp_ev,
        "ot_ics_impact":          ot_ev,
        "attack_chain_potential": chain_ev,
    }

    # Weighted sum
    weighted_sum = sum(WEIGHTS[sig] * raw_vals[sig] for sig in WEIGHTS)

    # Apply sector multiplier, clamp to [0, 10]
    raw_score = weighted_sum * 10.0 * sec_mult
    apex_risk = round(min(10.0, max(0.0, raw_score)), 2)

    # Build evidence block
    evidence_block = {}
    for sig, w in WEIGHTS.items():
        contribution = round(WEIGHTS[sig] * raw_vals[sig] * 10.0, 3)
        evidence_block[sig] = {
            "raw_value":    raw_vals[sig],
            "weight":       w,
            "contribution": contribution,
            "evidence":     evidences[sig],
        }
    evidence_block["sector_multiplier"] = {
        "value":    sec_mult,
        "evidence": sec_ev,
    }

    # Determine severity label
    if apex_risk >= 9.0:
        label = "CRITICAL"
        urgency = "IMMEDIATE — exploit in wild or KEV listed; patch within 24 hours"
    elif apex_risk >= 7.0:
        label = "HIGH"
        urgency = "PRIORITY — weaponised exploit likely; patch within 72 hours"
    elif apex_risk >= 5.0:
        label = "MEDIUM"
        urgency = "STANDARD — PoC-level risk; patch within 14 days per SLA"
    elif apex_risk >= 3.0:
        label = "LOW"
        urgency = "MONITORED — limited exploitability; patch within 30 days"
    else:
        label = "INFORMATIONAL"
        urgency = "INFORMATIONAL — no exploit evidence; monitor and patch at next cycle"

    # Identify ceiling drivers
    ceiling_factors = []
    if kev_val == 0:
        ceiling_factors.append("KEV listing would add +1.80 pts")
    if mat_val < 0.8:
        ceiling_factors.append("Active exploitation evidence would add +{:.2f} pts".format(
            WEIGHTS["exploit_maturity"] * (1.0 - mat_val) * 10.0 * sec_mult))
    if epss_norm < 0.5:
        ceiling_factors.append("EPSS >50% would add +{:.2f} pts".format(
            WEIGHTS["epss_30d"] * (0.5 - epss_norm) * 10.0 * sec_mult))

    # Rationale
    active_signals = [sig for sig, v in raw_vals.items() if v > 0]
    null_signals   = [sig for sig, v in raw_vals.items() if v == 0]
    rationale_parts = [
        f"Score {apex_risk}/10 ({label}) computed from {len(active_signals)} active signal(s).",
    ]
    if cvss_norm > 0:
        rationale_parts.append(f"CVSS contributes {evidence_block['cvss_base']['contribution']:.2f} pts ({cvss_ev}).")
    if epss_norm > 0:
        rationale_parts.append(f"EPSS contributes {evidence_block['epss_30d']['contribution']:.2f} pts ({epss_ev}).")
    if kev_val > 0:
        rationale_parts.append("CISA KEV listing confirms active exploitation — maximum KEV contribution applied.")
    if mat_val > 0:
        rationale_parts.append(f"Exploit maturity: {mat_ev}.")
    if ran_val > 0:
        rationale_parts.append(f"Ransomware linkage detected: {ran_ev}.")
    if null_signals:
        rationale_parts.append(f"Zero contribution from: {', '.join(null_signals)} (no evidence available).")
    if ceiling_factors:
        rationale_parts.append("Score ceiling drivers: " + "; ".join(ceiling_factors))

    item_out = dict(item)
    item_out["apex_risk"]           = apex_risk
    item_out["apex_risk_label"]     = label
    item_out["apex_risk_urgency"]   = urgency
    item_out["apex_risk_evidence"]  = evidence_block
    item_out["apex_risk_rationale"] = " ".join(rationale_parts)
    item_out["apex_risk_engine"]    = ENGINE_ID
    item_out["apex_risk_version"]   = ENGINE_VERSION
    item_out["apex_risk_ts"]        = datetime.now(timezone.utc).isoformat()

    return item_out


def score_manifest(manifest_path: Path, out_path: Optional[Path] = None) -> List[Dict]:
    """Score all items in a feed manifest. Returns updated items list."""
    with manifest_path.open(encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("items", [])
    log.info("Scoring %d items", len(items))
    scored = [compute_apex_risk(item) for item in items]

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = out_path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(scored, f, indent=2, ensure_ascii=False)
        tmp.replace(out_path)
        log.info("Wrote scored manifest to %s", out_path)

    return scored


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    import argparse, sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [RSE] %(levelname)s %(message)s",
    )
    parser = argparse.ArgumentParser(description="APEX Risk Scoring Engine v" + ENGINE_VERSION)
    parser.add_argument("--manifest", default="data/stix/feed_manifest.json")
    parser.add_argument("--output",   default=None)
    args = parser.parse_args()

    manifest = Path(args.manifest)
    if not manifest.exists():
        log.error("Manifest not found: %s", manifest)
        return 1

    out = Path(args.output) if args.output else None
    scored = score_manifest(manifest, out)

    # Summary
    print(f"\n{'='*70}")
    print(f"  APEX RISK SCORING ENGINE v{ENGINE_VERSION}")
    print(f"{'='*70}")
    dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    for item in scored:
        dist[item.get("apex_risk_label", "INFORMATIONAL")] = dist.get(
            item.get("apex_risk_label", "INFORMATIONAL"), 0) + 1
    for label, count in dist.items():
        print(f"  {label:15s}: {count}")
    print(f"{'='*70}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
