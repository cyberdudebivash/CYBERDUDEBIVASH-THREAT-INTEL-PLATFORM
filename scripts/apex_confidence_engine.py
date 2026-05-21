#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/apex_confidence_engine.py — Deterministic Confidence Engine
================================================================================
Version : 152.0.0

PROBLEM SOLVED:
  Legacy pipeline assigns confidence values (21–56%) with no rationale.
  Values appear as hardcoded noise (e.g. "46%", "26%", "17%").
  Analysts cannot trust a confidence score they cannot audit.

SOLUTION — ADMIRALTY SCALE DETERMINISTIC CONFIDENCE:

  Based on NATO/UKUSA Intelligence Reliability and Credibility model:

  SOURCE RELIABILITY (A–F):
    A: Completely reliable     CISA KEV, MITRE, NVD, major vendor advisories
    B: Usually reliable        CrowdStrike, Mandiant, Recorded Future, Palo Alto
    C: Fairly reliable         ISACs, security researchers, WPScan, CIRCL
    D: Not usually reliable    Anonymous blog posts, unverified paste sites
    E: Unreliable              Dark web sources, unattributed claims
    F: Reliability cannot be judged  New sources, no track record

  INFORMATION CREDIBILITY (1–6):
    1: Confirmed by other independent sources
    2: Probably true (consistent with known intelligence)
    3: Possibly true (consistent but not confirmed)
    4: Doubtful (unusual or not confirmed by other sources)
    5: Improbable (contradicts other intelligence)
    6: Cannot be judged (entirely new or isolated)

  APEX CONFIDENCE = f(source_reliability, credibility, corroboration,
                       ioc_validity_rate, epss_coverage, kev_boost)

  CONFIDENCE RANGES:
    85–100: VERIFIED  — multiple corroborated sources, confirmed exploitation
    70–84:  HIGH      — reliable source, probably true, some corroboration
    50–69:  MEDIUM    — fairly reliable, possibly true, limited corroboration
    30–49:  LOW       — single source, unverified, use with caution
    0–29:   UNCERTAIN — minimal evidence, treat as unconfirmed

  Every confidence score includes:
    confidence_rationale: why this score was assigned
    confidence_admiralty: source reliability + credibility codes
    confidence_signals:   breakdown of each contributing factor
================================================================================
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("apex.confidence")

ENGINE_VERSION = "152.0.0"
ENGINE_ID      = "APEX-CE"

# ── Source Reliability Tiers (Admiralty A–F → 1.0–0.0) ───────────────────────
SOURCE_RELIABILITY: Dict[str, Tuple[float, str, str]] = {
    # domain_key: (score, admiralty_code, description)

    # A: Completely reliable (official government/authoritative bodies)
    "cisa.gov":                         (1.00, "A", "CISA — authoritative US government source"),
    "nvd.nist.gov":                     (0.98, "A", "NVD/NIST — authoritative CVE database"),
    "attack.mitre.org":                 (0.97, "A", "MITRE ATT&CK — authoritative framework"),
    "cert.org":                         (0.96, "A", "CERT/CC — authoritative coordination centre"),
    "us-cert.gov":                      (0.96, "A", "US-CERT — CISA operational arm"),
    "kb.cert.org":                      (0.96, "A", "CERT/CC Knowledge Base"),

    # B: Usually reliable (top-tier commercial threat intel vendors)
    "crowdstrike.com":                  (0.92, "B", "CrowdStrike — Tier-1 commercial CTI"),
    "unit42.paloaltonetworks.com":      (0.92, "B", "Unit42 — Tier-1 commercial CTI"),
    "mandiant.com":                     (0.92, "B", "Mandiant / Google TI — Tier-1 commercial CTI"),
    "recordedfuture.com":               (0.91, "B", "Recorded Future — Tier-1 commercial CTI"),
    "microsoft.com/security":           (0.91, "B", "MSTIC — Microsoft Threat Intelligence"),
    "msrc.microsoft.com":               (0.91, "B", "MSRC — Microsoft Security Response Centre"),
    "dragos.com":                       (0.93, "B", "Dragos — authoritative ICS/OT intelligence"),
    "claroty.com":                      (0.90, "B", "Claroty — OT/ICS security vendor"),
    "rapid7.com":                       (0.90, "B", "Rapid7 — commercial vulnerability research"),
    "tenable.com":                      (0.89, "B", "Tenable — commercial vulnerability research"),
    "qualys.com":                       (0.89, "B", "Qualys — commercial vulnerability research"),
    "sentinelone.com":                  (0.89, "B", "SentinelOne — commercial EDR/CTI"),
    "secureworks.com":                  (0.88, "B", "Secureworks — commercial CTI"),
    "proofpoint.com":                   (0.88, "B", "Proofpoint — email/phishing CTI"),
    "talos.cisco.com":                  (0.90, "B", "Cisco Talos — commercial CTI"),

    # C: Fairly reliable (reputable security research/ISACs)
    "securityaffairs.com":              (0.75, "C", "Security Affairs — established security journalism"),
    "thehackernews.com":                (0.72, "C", "The Hacker News — established security journalism"),
    "bleepingcomputer.com":             (0.73, "C", "BleepingComputer — established security journalism"),
    "darkfeed.io":                      (0.70, "C", "DarkFeed — aggregated dark web intel"),
    "vulners.com":                      (0.68, "C", "Vulners — aggregated vulnerability database"),
    "cvefeed.io":                       (0.68, "C", "CVE Feed — aggregated CVE data"),
    "wpscan.com":                       (0.70, "C", "WPScan — WordPress vulnerability DB"),
    "github.com/advisories":            (0.75, "C", "GitHub Security Advisories"),
    "exploit-db.com":                   (0.72, "C", "Exploit-DB — publicly submitted PoCs"),
    "packetstormsecurity.com":          (0.68, "C", "PacketStorm — aggregated security content"),

    # D: Not usually reliable (single-source, unverified blogs)
    "medium.com":                       (0.45, "D", "Medium — unverified blog posts"),
    "reddit.com":                       (0.30, "D", "Reddit — user-generated, unverified"),
    "pastebin.com":                     (0.25, "D", "Pastebin — anonymous paste site"),

    # E: Unreliable (dark web, anonymous)
    "onion":                            (0.15, "E", "Dark web (.onion) — unverified anonymous source"),
}

DEFAULT_SOURCE_RELIABILITY = (0.55, "C", "Unknown source — default reliability")

# ── Signal weights for confidence composition ─────────────────────────────────
CONF_WEIGHTS = {
    "source_reliability":    0.30,
    "ioc_validity_rate":     0.20,
    "corroboration_count":   0.15,
    "epss_coverage":         0.10,
    "kev_boost":             0.15,
    "technical_depth":       0.10,
}
assert abs(sum(CONF_WEIGHTS.values()) - 1.0) < 1e-9


def _match_source(source_url: str) -> Tuple[float, str, str]:
    """Look up source reliability from URL domain."""
    url_lower = source_url.lower()
    # Exact or substring match
    for domain, profile in sorted(SOURCE_RELIABILITY.items(), key=lambda x: -len(x[0])):
        if domain in url_lower:
            return profile
    if ".onion" in url_lower:
        return SOURCE_RELIABILITY["onion"]
    return DEFAULT_SOURCE_RELIABILITY


def _ioc_validity_rate(item: Dict) -> Tuple[float, str]:
    """
    What fraction of declared IOCs are genuine operational indicators?
    Pseudo-IOCs (CVE IDs, advisory URLs) count as invalid.
    """
    iocs = item.get("iocs") or item.get("indicators") or []
    if not iocs:
        return 0.0, "IOC validity: no IOCs declared"

    from scripts.anti_hallucination_engine import HallucinationEngine, REFERENCE_URL_PATTERNS, CVE_RE
    valid = 0
    invalid = 0
    for ioc in iocs:
        val = str(ioc.get("value") or ioc.get("indicator") or "").strip()
        if CVE_RE.match(val) or REFERENCE_URL_PATTERNS.search(val):
            invalid += 1
        else:
            valid += 1

    total = valid + invalid
    rate  = valid / total if total > 0 else 0.0
    return round(rate, 3), f"IOC validity: {valid}/{total} operational ({rate*100:.0f}%)"


def _corroboration_score(item: Dict) -> Tuple[float, str]:
    """Higher confidence if multiple sources reference same finding."""
    corroborations = item.get("corroboration_count") or item.get("source_count") or 1
    try:
        n = int(corroborations)
    except (ValueError, TypeError):
        n = 1
    # 1 source = 0.2, 2 = 0.5, 3 = 0.7, 5+ = 1.0
    score = min(1.0, 0.2 + (n - 1) * 0.2)
    return round(score, 3), f"Corroboration: {n} independent source(s)"


def _epss_coverage(item: Dict) -> Tuple[float, str]:
    """EPSS available → real probability model run → confidence boost."""
    epss = item.get("epss_score") or item.get("epss")
    if epss and epss not in ("N/A", "", "Pending", None):
        try:
            v = float(str(epss).rstrip("%"))
            if v > 1.0:
                v = v / 100.0
            return min(1.0, v + 0.3), f"EPSS coverage: {v*100:.2f}% (FIRST model available)"
        except (ValueError, TypeError):
            pass
    return 0.0, "EPSS coverage: not available (zero confidence contribution)"


def _kev_boost(item: Dict) -> Tuple[float, str]:
    """CISA KEV listing = CONFIRMED exploitation → maximum confidence boost."""
    kev = str(item.get("kev") or item.get("cisa_kev") or item.get("kev_listed") or "")
    if kev.strip().upper() in ("YES", "TRUE", "1", "LISTED"):
        return 1.0, "KEV boost: MAXIMUM — CISA confirmed active exploitation"
    return 0.0, "KEV boost: not applicable (not in CISA KEV)"


def _technical_depth(item: Dict) -> Tuple[float, str]:
    """Score depth of technical content: CVSS vectors, TTPs, affected versions."""
    score = 0.0
    reasons = []
    if item.get("cvss_score") and item.get("cvss_score") not in ("N/A", "", None):
        score += 0.25; reasons.append("CVSS score")
    if item.get("cvss_vector"):
        score += 0.15; reasons.append("CVSS vector")
    ttps = item.get("ttps") or item.get("attack_techniques") or []
    if ttps:
        score += min(0.30, len(ttps) * 0.10); reasons.append(f"{len(ttps)} ATT&CK techniques")
    if item.get("affected_versions") or item.get("affected_products"):
        score += 0.20; reasons.append("affected versions/products")
    if item.get("patch_url") or item.get("vendor_advisory"):
        score += 0.10; reasons.append("vendor advisory/patch URL")
    return round(min(1.0, score), 3), f"Technical depth: {', '.join(reasons) or 'minimal'}"


def compute_confidence(item: Dict) -> Dict:
    """
    Compute deterministic Admiralty-scale confidence for a single item.
    Returns item copy with confidence_* fields added.
    """
    source_url = str(item.get("source_url") or item.get("blog_url") or "")
    src_score, admiralty_code, src_description = _match_source(source_url)

    ioc_rate_val, ioc_rate_ev   = _ioc_validity_rate(item)
    corr_val,     corr_ev       = _corroboration_score(item)
    epss_val,     epss_ev       = _epss_coverage(item)
    kev_val,      kev_ev        = _kev_boost(item)
    depth_val,    depth_ev      = _technical_depth(item)

    signals = {
        "source_reliability":   (src_score,  src_description),
        "ioc_validity_rate":    (ioc_rate_val, ioc_rate_ev),
        "corroboration_count":  (corr_val,   corr_ev),
        "epss_coverage":        (epss_val,   epss_ev),
        "kev_boost":            (kev_val,    kev_ev),
        "technical_depth":      (depth_val,  depth_ev),
    }

    weighted_sum = sum(CONF_WEIGHTS[sig] * val for sig, (val, _) in signals.items())
    confidence_pct = round(min(100.0, max(0.0, weighted_sum * 100)), 1)

    # Confidence band
    if confidence_pct >= 85:
        band = "VERIFIED"
        band_desc = "Multiple corroborated sources, confirmed exploitation evidence"
    elif confidence_pct >= 70:
        band = "HIGH"
        band_desc = "Reliable source, probably true, partial corroboration"
    elif confidence_pct >= 50:
        band = "MEDIUM"
        band_desc = "Fairly reliable source, possibly true, limited corroboration"
    elif confidence_pct >= 30:
        band = "LOW"
        band_desc = "Single source, unverified — use with caution"
    else:
        band = "UNCERTAIN"
        band_desc = "Minimal evidence — treat as unconfirmed hypothesis"

    # Build signal breakdown for transparency
    signal_breakdown = {}
    for sig, (val, ev) in signals.items():
        contribution = round(CONF_WEIGHTS[sig] * val * 100, 2)
        signal_breakdown[sig] = {
            "raw_value":    round(val, 4),
            "weight":       CONF_WEIGHTS[sig],
            "contribution": contribution,
            "evidence":     ev,
        }

    # Rationale
    rationale_parts = [
        f"Confidence {confidence_pct}% ({band}): {band_desc}.",
        f"Source reliability: {admiralty_code} — {src_description}.",
    ]
    if ioc_rate_val < 0.5 and (item.get("iocs") or item.get("indicators")):
        rationale_parts.append(
            "Warning: IOC validity rate below 50% — pseudo-IOCs (CVE IDs, advisory URLs) "
            "are dragging confidence down. Run ioc_quality_hardener to filter."
        )
    if kev_val == 1.0:
        rationale_parts.append("CISA KEV confirmed exploitation provides maximum confidence boost.")
    if corr_val < 0.3:
        rationale_parts.append(
            "Low corroboration — single source. Confidence will increase when additional "
            "sources confirm this finding."
        )

    item_out = dict(item)
    item_out["confidence"]               = confidence_pct
    item_out["confidence_band"]          = band
    item_out["confidence_band_desc"]     = band_desc
    item_out["confidence_rationale"]     = " ".join(rationale_parts)
    item_out["confidence_admiralty"]     = f"{admiralty_code}/6"
    item_out["confidence_admiralty_src"] = src_description
    item_out["confidence_signals"]       = signal_breakdown
    item_out["confidence_engine"]        = ENGINE_ID
    item_out["confidence_version"]       = ENGINE_VERSION
    item_out["confidence_ts"]            = datetime.now(timezone.utc).isoformat()

    return item_out


def main() -> int:
    import argparse, sys
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [CE] %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="APEX Confidence Engine v" + ENGINE_VERSION)
    parser.add_argument("--manifest", default="data/stix/feed_manifest.json")
    parser.add_argument("--output",   default=None)
    args = parser.parse_args()

    path = Path(args.manifest)
    if not path.exists():
        log.error("Manifest not found: %s", path)
        return 1

    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get("items", [])
    scored = [compute_confidence(item) for item in items]
    log.info("Scored confidence for %d items", len(scored))

    out_path = Path(args.output) if args.output else path
    tmp = out_path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(scored, f, indent=2, ensure_ascii=False)
    tmp.replace(out_path)
    log.info("Written to %s", out_path)
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
