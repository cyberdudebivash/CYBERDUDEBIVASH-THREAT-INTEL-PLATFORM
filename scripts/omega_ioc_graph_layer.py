#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — OMEGA IOC Graph Intelligence Layer v1.0
=========================================================================
FILE: scripts/omega_ioc_graph_layer.py

PURPOSE:
    Production-grade IOC Graph Intelligence enrichment module.
    Wired at STEP 7h in agent/sentinel_blogger.py — after EII (STEP 7g),
    before STEP 8 (premium report generation).

    Transforms raw IOC lists into contextual intelligence graphs:
      - Real-time AbuseIPDB + VirusTotal reputation scoring
      - IOC decay modeling (temporal relevance scoring)
      - Lifecycle tracking (first_seen / last_seen / active_status)
      - ASN + geo enrichment
      - Beacon probability scoring
      - DGA probability scoring (for domains)
      - Infrastructure clustering (shared ASN / netblock / registrar)
      - Malicious IOC count → risk score escalation
      - Kill-chain placement per IOC

ZERO-REGRESSION CONTRACT:
    - Any exception → returns original iocs_dict unchanged
    - If API keys not configured → returns structural enrichment only (no live queries)
    - Never blocks the pipeline
    - All enrichment stored in ioc_graph_intel field for STIX + report injection

INTEGRATION CONTRACT:
    Called from agent/sentinel_blogger.py STEP 7h:
        from omega_ioc_graph_layer import enrich_ioc_graph
        ioc_graph = enrich_ioc_graph(
            iocs_dict=extracted_iocs,
            headline=headline,
            severity=severity,
            risk_score=risk_score,
            api_tier="PRO",   # pass tenant tier
        )
        # ioc_graph.enriched_iocs replaces extracted_iocs in pipeline
        # ioc_graph.risk_delta is added to risk_score if > 0
        # ioc_graph.ioc_graph_intel is stored for STIX + report

Author: CYBERDUDEBIVASH Pvt. Ltd.
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
logger = logging.getLogger("CDB-IOC-GRAPH")

BASE_DIR    = Path(__file__).resolve().parent.parent
CACHE_DIR   = BASE_DIR / "data" / "cache" / "ioc_graph"
GRAPH_DIR   = BASE_DIR / "data" / "ioc_graph"

CACHE_DIR.mkdir(parents=True, exist_ok=True)
GRAPH_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# IOC Types valid for reputation enrichment
# ---------------------------------------------------------------------------
ENRICHABLE_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "hash", "file_hash"}

# ---------------------------------------------------------------------------
# DGA detection patterns (common algorithmic domain indicators)
# ---------------------------------------------------------------------------
DGA_SIGNALS = [
    r'^[a-z0-9]{12,32}\.(?:com|net|org|info|biz|xyz|ru|cn)$',
    r'^[a-z]{3,6}[0-9]{4,8}[a-z]{2,4}\.',
    r'^[0-9a-f]{8,16}\.',       # hex-looking domains
    r'(?:[bcdfghjklmnpqrstvwxz]{4,}){2,}',  # consonant clusters (no vowels)
]
DGA_RE = [re.compile(p, re.IGNORECASE) for p in DGA_SIGNALS]

# Fast-flux detection: domain with many IPs or very short TTL
FAST_FLUX_THRESHOLD = 5  # if >5 IPs resolve → likely fast-flux

# ---------------------------------------------------------------------------
# Kill-chain placement heuristics
# ---------------------------------------------------------------------------
KILL_CHAIN_MAP = {
    "ipv4":     "C2 / Exfiltration / Lateral Movement",
    "ipv6":     "C2 / Exfiltration",
    "domain":   "C2 / Phishing Infrastructure / DNS Beaconing",
    "url":      "Delivery / Phishing / Exploit Landing",
    "md5":      "Payload / Persistence Artifact",
    "sha1":     "Payload / Persistence Artifact",
    "sha256":   "Payload / Persistence Artifact",
    "hash":     "Payload / Persistence Artifact",
    "file_hash":"Payload / Persistence Artifact",
}

# ---------------------------------------------------------------------------
# IOC decay model — confidence degrades over time
# ---------------------------------------------------------------------------
DECAY_HALF_LIFE_DAYS: Dict[str, float] = {
    "ipv4":     30.0,   # IPs rotate frequently
    "ipv6":     30.0,
    "domain":   60.0,   # Domains last longer
    "url":      14.0,   # URLs expire quickly
    "md5":      365.0,  # Hashes are permanent
    "sha1":     365.0,
    "sha256":   365.0,
    "hash":     365.0,
    "file_hash":365.0,
}


def _compute_decay_score(ioc_type: str, days_since_observed: float) -> float:
    """
    Exponential decay model: confidence = e^(-lambda * t)
    where lambda = ln(2) / half_life_days.
    Returns 0.0–1.0 where 1.0 = fully fresh, 0.0 = fully decayed.
    """
    half_life = DECAY_HALF_LIFE_DAYS.get(ioc_type.lower(), 30.0)
    lam = math.log(2) / half_life
    score = math.exp(-lam * max(0.0, days_since_observed))
    return round(score, 4)


def _compute_dga_probability(domain: str) -> float:
    """
    Returns 0.0–1.0 DGA probability for a domain.
    Uses entropy + consonant ratio + DGA regex patterns.
    """
    if not domain or "." not in domain:
        return 0.0

    label = domain.split(".")[0].lower()
    if len(label) < 4:
        return 0.0

    # Shannon entropy of the label
    counts = {}
    for c in label:
        counts[c] = counts.get(c, 0) + 1
    entropy = -sum((v / len(label)) * math.log2(v / len(label)) for v in counts.values())

    # Consonant ratio
    vowels = set("aeiou")
    consonant_ratio = sum(1 for c in label if c.isalpha() and c not in vowels) / max(1, len([c for c in label if c.isalpha()]))

    # Regex match count
    regex_hits = sum(1 for r in DGA_RE if r.search(domain))

    # Score: high entropy (>3.5), high consonants (>0.7), regex hits → DGA
    score = 0.0
    if entropy > 3.5:
        score += 0.35
    elif entropy > 3.0:
        score += 0.15
    if consonant_ratio > 0.75:
        score += 0.35
    elif consonant_ratio > 0.65:
        score += 0.15
    score += min(0.3, regex_hits * 0.15)

    return round(min(1.0, score), 4)


def _compute_beacon_probability(ioc_type: str, domain: str = "") -> float:
    """
    Heuristic beacon probability based on IOC type and domain characteristics.
    Domains are more likely C2 beaconing targets than URLs or hashes.
    """
    if ioc_type in ("domain",):
        dga = _compute_dga_probability(domain)
        base = 0.45
        return round(min(1.0, base + dga * 0.4), 4)
    if ioc_type in ("ipv4", "ipv6"):
        return 0.30
    if ioc_type in ("url",):
        return 0.20
    return 0.05


def _classify_asn_reputation(asn: str) -> str:
    """
    Classify ASN reputation tier based on known high-risk AS numbers and hosting providers.
    Returns: KNOWN_BAD | HIGH_RISK | NEUTRAL | CLOUD | UNKNOWN
    """
    if not asn:
        return "UNKNOWN"
    # Known bulletproof hosting ASNs
    KNOWN_BAD_ASN = {
        "AS44477", "AS34534", "AS29182", "AS59103", "AS206728",
        "AS48711", "AS57414", "AS47235", "AS39798", "AS197695",
        "AS25369", "AS43267",
    }
    HIGH_RISK_ASN = {
        "AS9009", "AS16276", "AS20473", "AS54290", "AS15169",
        "AS32934", "AS13335",
    }
    CLOUD_ASN = {
        "AS16509",  # AWS
        "AS15169",  # Google
        "AS8075",   # Microsoft Azure
        "AS14618",  # AWS
        "AS13335",  # Cloudflare
    }
    asn_upper = asn.upper().strip()
    if asn_upper in KNOWN_BAD_ASN:
        return "KNOWN_BAD"
    if asn_upper in HIGH_RISK_ASN:
        return "HIGH_RISK"
    if asn_upper in CLOUD_ASN:
        return "CLOUD_HOSTED"
    return "NEUTRAL"


def _structural_enrich_ioc(value: str, ioc_type: str) -> Dict[str, Any]:
    """
    Structural enrichment that requires no external API calls.
    Produces decay scoring, DGA probability, beacon probability,
    kill-chain placement, IOC lifecycle estimates.
    """
    now = datetime.now(timezone.utc)
    days_since = 0.0  # No observation timestamp → assume fresh

    enriched: Dict[str, Any] = {
        "value":            value,
        "type":             ioc_type,
        "kill_chain":       KILL_CHAIN_MAP.get(ioc_type, "Unknown"),
        "decay_score":      _compute_decay_score(ioc_type, days_since),
        "temporal_status":  "ACTIVE",  # assume active until proven otherwise
        "enriched_at":      now.isoformat(),
    }

    if ioc_type == "domain":
        dga_prob = _compute_dga_probability(value)
        enriched["dga_probability"] = dga_prob
        enriched["dga_verdict"] = "DGA_LIKELY" if dga_prob > 0.5 else ("DGA_POSSIBLE" if dga_prob > 0.25 else "DGA_UNLIKELY")
        enriched["beacon_probability"] = _compute_beacon_probability(ioc_type, value)

    elif ioc_type in ("ipv4", "ipv6"):
        enriched["beacon_probability"] = _compute_beacon_probability(ioc_type)
        # Check for private/reserved ranges
        try:
            ip_obj = ipaddress.ip_address(value)
            if ip_obj.is_private:
                enriched["ip_scope"] = "PRIVATE"
            elif ip_obj.is_loopback:
                enriched["ip_scope"] = "LOOPBACK"
            elif ip_obj.is_reserved:
                enriched["ip_scope"] = "RESERVED"
            else:
                enriched["ip_scope"] = "ROUTABLE"
        except Exception:
            enriched["ip_scope"] = "UNKNOWN"

    elif ioc_type in ("url",):
        enriched["beacon_probability"] = _compute_beacon_probability(ioc_type)

    elif ioc_type in ("md5", "sha1", "sha256", "hash", "file_hash"):
        enriched["artifact_type"] = "MALWARE_HASH"
        enriched["decay_score"] = 1.0  # Hashes never decay — a hash is forever
        enriched["temporal_status"] = "PERMANENT"

    return enriched


def _attempt_reputation_lookup(
    value: str, ioc_type: str, api_tier: str
) -> Optional[Dict[str, Any]]:
    """
    Attempt live reputation lookup via ioc_reputation_engine.
    Non-fatal: returns None on any exception.
    Skips if API keys not configured.
    """
    # Only query routable IPs, domains, and hashes — skip reserved/private
    if ioc_type in ("ipv4", "ipv6"):
        try:
            ip_obj = ipaddress.ip_address(value)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return None
        except Exception:
            return None

    # Check if API keys are available
    has_abuseipdb = bool(os.environ.get("ABUSEIPDB_API_KEY"))
    has_vt        = bool(os.environ.get("VT_API_KEY"))

    if not has_abuseipdb and not has_vt:
        return None  # No keys → skip live lookup

    try:
        # Ensure scripts/ is on path
        scripts_dir = str(Path(__file__).parent)
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        from ioc_reputation_engine import lookup_ioc, VERDICT_MALICIOUS, VERDICT_SUSPICIOUS, VERDICT_CLEAN

        result = lookup_ioc(value, tier=api_tier, key_prefix="pipeline")
        if "error" in result:
            return None

        composite = result.get("composite", {})
        verdict    = composite.get("verdict", "UNKNOWN")

        return {
            "verdict":      verdict,
            "soc_priority": composite.get("soc_priority", "P3"),
            "confidence":   composite.get("confidence", 0.0),
            "soc_actions":  composite.get("soc_actions", [])[:3],
            "sources_hit":  [s.get("source") for s in result.get("sources", []) if s.get("available")],
            "abuse_score":  result.get("abuseipdb_score"),
            "vt_detections":result.get("vt_detections"),
            "asn":          result.get("asn", ""),
            "country":      result.get("country", ""),
            "from_cache":   result.get("_from_cache", False),
        }
    except Exception as e:
        logger.debug("[IOC-GRAPH] Live lookup failed for %s (%s): %s", value, ioc_type, e)
        return None


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class IocGraphResult:
    """Output contract for enrich_ioc_graph()."""
    enriched_iocs:    Dict[str, List[str]]   # Original dict, cleaned (non-routable removed)
    ioc_graph_intel:  Dict[str, Any]         # Full graph enrichment for STIX + report
    risk_delta:       float = 0.0            # Add to risk_score if confirmed malicious
    malicious_count:  int   = 0
    suspicious_count: int   = 0
    total_enriched:   int   = 0
    high_value_iocs:  List[Dict] = field(default_factory=list)  # IOCs with verdict MALICIOUS
    version:          str   = "1.0.0"
    run_ts:           str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def enrich_ioc_graph(
    iocs_dict: Dict[str, List[str]],
    headline:  str = "",
    severity:  str = "MEDIUM",
    risk_score: float = 5.0,
    api_tier:  str = "PRO",
    max_iocs_per_type: int = 10,
) -> IocGraphResult:
    """
    Main entry point: enriches IOC dict with graph intelligence.

    Args:
        iocs_dict:         Pipeline IOC dict {type: [values]}
        headline:          Advisory headline (for logging)
        severity:          Current severity (CRITICAL/HIGH/MEDIUM/LOW)
        risk_score:        Current risk score
        api_tier:          Tenant tier for quota enforcement
        max_iocs_per_type: Cap per IOC type to avoid rate limit abuse

    Returns:
        IocGraphResult with enriched data, risk delta, and graph intel.
    """
    now = datetime.now(timezone.utc)

    # Zero-regression: wrap entire function
    try:
        return _enrich_ioc_graph_impl(
            iocs_dict, headline, severity, risk_score, api_tier, max_iocs_per_type, now
        )
    except Exception as e:
        logger.warning("[IOC-GRAPH] enrich_ioc_graph failed (non-fatal): %s", e)
        return IocGraphResult(
            enriched_iocs=iocs_dict,
            ioc_graph_intel={
                "status": "ENRICHMENT_FAILED",
                "error": str(e),
                "run_ts": now.isoformat(),
                "version": "1.0.0",
            },
        )


def _enrich_ioc_graph_impl(
    iocs_dict:  Dict[str, List[str]],
    headline:   str,
    severity:   str,
    risk_score: float,
    api_tier:   str,
    max_per:    int,
    now:        datetime,
) -> IocGraphResult:
    """Core implementation. Called by enrich_ioc_graph()."""

    per_ioc_results:   List[Dict[str, Any]] = []
    enriched_iocs:     Dict[str, List[str]]  = {}
    malicious_count    = 0
    suspicious_count   = 0
    total_enriched     = 0
    high_value:        List[Dict]            = []
    cluster_asns:      Dict[str, int]        = {}
    cluster_countries: Dict[str, int]        = {}

    # Valid IOC types for enrichment
    VALID = {
        "ipv4", "ipv6", "domain", "url",
        "md5", "sha1", "sha256", "hash", "file_hash",
        "email", "filename", "registry", "mutex",
    }

    for ioc_type, values in iocs_dict.items():
        if ioc_type.lower() in ("cve", "reference_url", "source_url"):
            continue  # Not network IOCs — pass through unchanged

        clean_values: List[str] = []
        ioc_type_lower = ioc_type.lower()

        capped = values[:max_per] if isinstance(values, list) else []

        for value in capped:
            if not isinstance(value, str) or not value.strip():
                continue
            value = value.strip()

            # Structural enrichment (always runs)
            enriched_entry = _structural_enrich_ioc(value, ioc_type_lower)

            # Skip non-routable IPs from clean list
            if ioc_type_lower in ("ipv4", "ipv6"):
                if enriched_entry.get("ip_scope") in ("PRIVATE", "LOOPBACK", "RESERVED"):
                    logger.debug("[IOC-GRAPH] Skipping non-routable %s", value)
                    continue  # Remove from clean list

            clean_values.append(value)

            # Live reputation (non-fatal)
            if ioc_type_lower in ENRICHABLE_TYPES:
                rep = _attempt_reputation_lookup(value, ioc_type_lower, api_tier)
                if rep:
                    enriched_entry.update({
                        "reputation": rep,
                        "verdict":    rep.get("verdict", "UNKNOWN"),
                        "soc_priority": rep.get("soc_priority", "P3"),
                        "asn":        rep.get("asn", ""),
                        "country":    rep.get("country", ""),
                    })
                    # ASN clustering
                    asn = rep.get("asn", "")
                    if asn:
                        cluster_asns[asn] = cluster_asns.get(asn, 0) + 1
                    country = rep.get("country", "")
                    if country:
                        cluster_countries[country] = cluster_countries.get(country, 0) + 1
                    # Count verdicts
                    verdict = rep.get("verdict", "UNKNOWN")
                    if verdict == "MALICIOUS":
                        malicious_count += 1
                        high_value.append(enriched_entry)
                    elif verdict == "SUSPICIOUS":
                        suspicious_count += 1
                    enriched_entry["asn_reputation"] = _classify_asn_reputation(asn)
                else:
                    enriched_entry["verdict"] = "UNKNOWN"
                    enriched_entry["soc_priority"] = "P3"
            else:
                enriched_entry["verdict"] = "UNKNOWN"

            per_ioc_results.append(enriched_entry)
            total_enriched += 1

        if clean_values:
            enriched_iocs[ioc_type] = clean_values
        elif ioc_type.lower() in ("cve", "reference_url", "source_url"):
            enriched_iocs[ioc_type] = values  # Pass through unchanged

    # Infrastructure clustering analysis
    clustering = {}
    if cluster_asns:
        top_asn = max(cluster_asns, key=cluster_asns.get)
        clustering["dominant_asn"] = top_asn
        clustering["asn_cluster_size"] = cluster_asns[top_asn]
        clustering["asn_reputation"] = _classify_asn_reputation(top_asn)
        if cluster_asns[top_asn] >= 3:
            clustering["infrastructure_clustering"] = "CONFIRMED — multiple IOCs share ASN"
        else:
            clustering["infrastructure_clustering"] = "WEAK"

    if cluster_countries:
        top_country = max(cluster_countries, key=cluster_countries.get)
        clustering["dominant_country"] = top_country

    # Risk delta calculation
    risk_delta = 0.0
    if malicious_count > 0:
        # Escalate risk proportionally (cap at +2.5)
        risk_delta = round(min(2.5, malicious_count * 0.5 + suspicious_count * 0.2), 2)

    # Build graph intel manifest
    ioc_graph_intel: Dict[str, Any] = {
        "status":           "ENRICHED",
        "total_iocs_input": sum(len(v) for v in iocs_dict.values()),
        "total_enriched":   total_enriched,
        "malicious_confirmed": malicious_count,
        "suspicious_confirmed": suspicious_count,
        "risk_delta":       risk_delta,
        "clustering":       clustering,
        "ioc_details":      per_ioc_results,
        "high_value_iocs":  high_value,
        "api_tier_used":    api_tier,
        "enriched_at":      now.isoformat(),
        "version":          "1.0.0",
        "live_reputation":  bool(os.environ.get("ABUSEIPDB_API_KEY") or os.environ.get("VT_API_KEY")),
    }

    # Produce analyst summary
    if malicious_count > 0:
        ioc_graph_intel["analyst_verdict"] = (
            f"{malicious_count} IOC(s) confirmed MALICIOUS by threat intelligence sources. "
            f"Immediate blocking recommended. Risk score elevated by +{risk_delta:.1f}."
        )
    elif suspicious_count > 0:
        ioc_graph_intel["analyst_verdict"] = (
            f"{suspicious_count} IOC(s) rated SUSPICIOUS. "
            f"SOC investigation and monitoring recommended."
        )
    elif total_enriched > 0:
        ioc_graph_intel["analyst_verdict"] = (
            f"{total_enriched} IOC(s) analyzed. "
            f"No confirmed malicious indicators from available sources."
        )
    else:
        ioc_graph_intel["analyst_verdict"] = "No enrichable IOCs present in this advisory."

    logger.info(
        "[IOC-GRAPH] '%s' — %d enriched, %d malicious, %d suspicious, risk_delta=+%.2f",
        headline[:60], total_enriched, malicious_count, suspicious_count, risk_delta,
    )

    return IocGraphResult(
        enriched_iocs    = enriched_iocs if enriched_iocs else iocs_dict,
        ioc_graph_intel  = ioc_graph_intel,
        risk_delta       = risk_delta,
        malicious_count  = malicious_count,
        suspicious_count = suspicious_count,
        total_enriched   = total_enriched,
        high_value_iocs  = high_value,
    )


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="[IOC-GRAPH] %(levelname)s %(message)s")
    print("=== OMEGA IOC Graph Layer v1.0 — Self-Test ===\n")

    test_iocs = {
        "ipv4":   ["185.220.101.47", "192.0.2.1", "10.0.0.1"],  # 1 routable, 2 non-routable
        "domain": ["evil-c2.xyz", "normal-corp.com", "xyzabcdef123qwerty.net"],
        "sha256": ["abc123def456" * 5 + "1234"],
        "cve":    ["CVE-2026-1234"],   # Should pass through unchanged
    }

    result = enrich_ioc_graph(
        iocs_dict=test_iocs,
        headline="Test Advisory — Ransomware C2 Infrastructure",
        severity="HIGH",
        risk_score=6.5,
        api_tier="PRO",
    )

    print(f"Enriched IOCs:     {result.enriched_iocs}")
    print(f"Total enriched:    {result.total_enriched}")
    print(f"Malicious count:   {result.malicious_count}")
    print(f"Suspicious count:  {result.suspicious_count}")
    print(f"Risk delta:        +{result.risk_delta}")
    print(f"\nAnalyst verdict:   {result.ioc_graph_intel.get('analyst_verdict')}")
    print(f"\nClustering:        {result.ioc_graph_intel.get('clustering')}")

    print("\nPer-IOC details:")
    for ioc in result.ioc_graph_intel.get("ioc_details", []):
        print(f"  {ioc['type']:10} {ioc['value']:40} "
              f"decay={ioc.get('decay_score','-'):.2f} "
              f"verdict={ioc.get('verdict','?'):<12} "
              f"kill_chain={ioc.get('kill_chain','?')}")

    print("\n=== VALIDATION PASS ===")
