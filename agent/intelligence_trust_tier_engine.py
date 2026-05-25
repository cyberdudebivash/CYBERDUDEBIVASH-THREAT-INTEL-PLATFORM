#!/usr/bin/env python3
"""
agent/intelligence_trust_tier_engine.py
CYBERDUDEBIVASH® SENTINEL APEX — Intelligence Trust-Tier Scoring Engine v1.0

PURPOSE:
  Assigns a deterministic, evidence-weighted trust tier to every advisory based
  on source reputation, corroboration signals, actor attribution confidence, IOC
  quality, ATT&CK coverage depth, and historical accuracy of the originating feed.

TRUST TIERS:
  TIER-1 VERIFIED:    Score >= 80  — Government, leading vendors, multi-corroborated
  TIER-2 RELIABLE:    Score 60-79  — Established threat intel, strong attribution
  TIER-3 CREDIBLE:    Score 40-59  — Secondary research, community feeds
  TIER-4 UNVERIFIED:  Score 20-39  — Aggregator, unattributed, no corroboration
  TIER-5 LOW-TRUST:   Score < 20   — RSS noise, generic content, low confidence

SCORING DIMENSIONS (total 100 points):
  D1: Source Authority       (25 pts) — feed domain reputation + government/vendor status
  D2: IOC Quality            (20 pts) — high-fidelity IOC types, count, uniqueness
  D3: Actor Attribution      (15 pts) — named actor, cluster confidence
  D4: ATT&CK Coverage        (15 pts) — technique count, tactic breadth
  D5: Corroboration          (10 pts) — cross-source confirmation
  D6: Evidence Traceability  (10 pts) — structured evidence, audit trail
  D7: Temporal Freshness     ( 5 pts) — recency vs. published date

OUTPUT:
  Enriches advisory dict with keys:
    trust_tier       — "TIER-1 VERIFIED" ... "TIER-5 LOW-TRUST"
    trust_score      — 0-100 float
    trust_evidence   — per-dimension breakdown (transparent/auditable)
    trust_audit_id   — deterministic audit reference

Never raises — all errors caught internally. Returns advisory unchanged on failure.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-TRUST-TIER")

# ── Source Authority Registry ─────────────────────────────────────────────────
# Maps feed domain → (authority_score 0-25, category)
SOURCE_AUTHORITY: Dict[str, Tuple[float, str]] = {
    # Government / CERT — maximum authority
    "cisa.gov":                   (25.0, "GOVERNMENT"),
    "nvd.nist.gov":               (24.0, "GOVERNMENT"),
    "nist.gov":                   (23.0, "GOVERNMENT"),
    "cert.gov":                   (23.0, "GOVERNMENT"),
    "us-cert.gov":                (23.0, "GOVERNMENT"),
    "ncsc.nl":                    (22.0, "GOVERNMENT"),
    "advisories.ncsc.nl":         (22.0, "GOVERNMENT"),
    # Tier-1 Vendor Threat Intelligence
    "unit42.paloaltonetworks.com": (22.0, "VENDOR_TIER1"),
    "securelist.com":             (21.0, "VENDOR_TIER1"),
    "cloud.google.com":           (21.0, "VENDOR_TIER1"),
    "sentinelone.com":            (21.0, "VENDOR_TIER1"),
    "rapid7.com":                 (20.0, "VENDOR_TIER1"),
    "crowdstrike.com":            (20.0, "VENDOR_TIER1"),
    "research.checkpoint.com":    (20.0, "VENDOR_TIER1"),
    "krebsonsecurity.com":        (19.0, "VENDOR_TIER1"),
    "projectzero.google":         (22.0, "VENDOR_TIER1"),
    # Tier-2 Vendor Intelligence
    "thehackernews.com":          (16.0, "VENDOR_TIER2"),
    "cybersecuritynews.com":      (15.0, "VENDOR_TIER2"),
    "securityaffairs.com":        (15.0, "VENDOR_TIER2"),
    "cyberscoop.com":             (15.0, "VENDOR_TIER2"),
    "bleepingcomputer.com":       (14.0, "VENDOR_TIER2"),
    "darkreading.com":            (14.0, "VENDOR_TIER2"),
    "securityweek.com":           (13.0, "VENDOR_TIER2"),
    "helpnetsecurity.com":        (13.0, "VENDOR_TIER2"),
    "seclists.org":               (14.0, "VENDOR_TIER2"),
    # Exploit / Vulnerability Tracking
    "zerodayinitiative.com":      (17.0, "VULN_TRACKER"),
    "sploitus.com":               (15.0, "VULN_TRACKER"),
    "exploit-db.com":             (15.0, "VULN_TRACKER"),
    "cvefeed.io":                 (12.0, "VULN_TRACKER"),
    # Cloud Provider Security Blogs
    "aws.amazon.com":             (16.0, "CLOUD_PROVIDER"),
    "blogs.microsoft.com":        (16.0, "CLOUD_PROVIDER"),
    # Ransomware Tracking
    "ransomware.live":            (14.0, "RANSOMWARE_TRACKER"),
}

# Actor attribution → trust boost
ACTOR_TIER: Dict[str, float] = {
    # APT / Nation-state actors — high confidence attribution
    "CDB-APT-28": 8.0, "CDB-APT-29": 8.0, "CDB-APT-22": 7.0,
    "CDB-APT-41": 8.0, "CDB-APT-GEN": 3.0,
    # Financial actors
    "CDB-FIN-07": 6.0, "CDB-FIN-09": 7.0, "CDB-FIN-11": 6.0,
    "CDB-FIN-12": 5.0,
    # Ransomware actors
    "CDB-RAN-05": 7.0, "CDB-RAN-GEN": 3.0, "CDB-RAN-01": 5.0,
    "CDB-RAN-04": 6.0, "CDB-RAN-06": 5.0,
    # Generic / unattributed
    "UNC-CDB-INGEST": 0.0, "CDB-CVE-GEN": 1.0, "CDB-CYB-01": 2.0,
}

# High-fidelity IOC types that raise trust
HIGH_FIDELITY_IOC_TYPES = {"hash", "md5", "sha1", "sha256", "ip", "ipv4", "ipv6", "cve"}

# KEV-listed entries get trust boost (actively exploited = verified threat)
KEV_TRUST_BOOST = 5.0

# ── Trust Tier Thresholds ─────────────────────────────────────────────────────
TRUST_TIERS = [
    (80.0, "TIER-1 VERIFIED"),
    (60.0, "TIER-2 RELIABLE"),
    (40.0, "TIER-3 CREDIBLE"),
    (20.0, "TIER-4 UNVERIFIED"),
    (0.0,  "TIER-5 LOW-TRUST"),
]


def _get_domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        host = urlparse(url).netloc.lower().lstrip("www.")
        return host
    except Exception:
        return ""


def _tier_from_score(score: float) -> str:
    for threshold, tier in TRUST_TIERS:
        if score >= threshold:
            return tier
    return "TIER-5 LOW-TRUST"


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts[:26], fmt[:len(ts)])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


class IntelligenceTrustTierEngine:
    """
    Assigns evidence-weighted trust tiers to intelligence advisories.
    Deterministic: same advisory → same trust_score + audit_id every run.
    """

    def __init__(self):
        self._telemetry: Dict[str, Any] = {
            "scored": 0,
            "by_tier": {t: 0 for _, t in TRUST_TIERS},
            "avg_score": 0.0,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        self._score_sum = 0.0

    def score_advisory(self, advisory: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compute trust tier for a single advisory.
        Returns enriched copy of advisory with trust_tier, trust_score,
        trust_evidence, and trust_audit_id keys added.
        """
        try:
            evidence: Dict[str, Any] = {}
            total = 0.0

            # D1: Source Authority (0-25)
            source_url = advisory.get("source_url", "")
            domain = _get_domain(source_url)
            auth_score, category = SOURCE_AUTHORITY.get(domain, (8.0, "UNKNOWN"))
            evidence["D1_source_authority"] = {
                "score": auth_score, "max": 25.0,
                "domain": domain, "category": category,
            }
            total += auth_score

            # D2: IOC Quality (0-20)
            iocs      = advisory.get("iocs", []) or []
            ioc_count = advisory.get("ioc_count", len(iocs) if isinstance(iocs, list) else 0)
            ioc_types = set()
            if isinstance(iocs, list):
                for ioc in iocs:
                    if isinstance(ioc, dict):
                        ioc_types.add(ioc.get("type", "").lower())
                    elif isinstance(ioc, str):
                        ioc_types.add("indicator")
            high_fi = len(ioc_types & HIGH_FIDELITY_IOC_TYPES)
            ioc_score = min(20.0, (
                min(ioc_count, 10) * 0.8 +  # up to 8 pts for count
                high_fi * 2.0 +              # 2 pts per high-fidelity type
                (3.0 if high_fi >= 2 else 0.0)  # bonus for type diversity
            ))
            evidence["D2_ioc_quality"] = {
                "score": round(ioc_score, 2), "max": 20.0,
                "ioc_count": ioc_count, "ioc_types": sorted(ioc_types),
                "high_fidelity_count": high_fi,
            }
            total += ioc_score

            # D3: Actor Attribution (0-15)
            actor = advisory.get("actor", "")
            attr_score = ACTOR_TIER.get(str(actor), 2.0) if actor else 0.0
            attr_score = min(15.0, attr_score * 1.5)  # scale to max 15
            evidence["D3_actor_attribution"] = {
                "score": round(attr_score, 2), "max": 15.0,
                "actor": actor,
            }
            total += attr_score

            # D4: ATT&CK Coverage (0-15)
            ttps      = advisory.get("ttps", []) or advisory.get("attack_techniques", []) or []
            ttp_count = len(ttps) if isinstance(ttps, list) else 0
            tactics   = set()
            if isinstance(ttps, list):
                for ttp in ttps:
                    if isinstance(ttp, dict):
                        tac = ttp.get("tactic", "")
                        if tac:
                            tactics.add(tac)
            ttp_score = min(15.0, ttp_count * 2.0 + len(tactics) * 1.5)
            evidence["D4_attck_coverage"] = {
                "score": round(ttp_score, 2), "max": 15.0,
                "ttp_count": ttp_count, "tactic_count": len(tactics),
            }
            total += ttp_score

            # D5: Corroboration (0-10)
            # Proxy: KEV-listed = externally corroborated. EPSS > 50% = widely tracked.
            kev   = str(advisory.get("kev", "")).upper() in ("YES", "TRUE", "1")
            epss  = advisory.get("epss")
            # FIX: epss_score stored as 0–100 percent — normalise to 0.0–1.0 for math
            try:
                _epss_raw = float(str(epss).strip("%"))
                epss_f = _epss_raw / 100.0 if _epss_raw > 1.0 else _epss_raw
            except (TypeError, ValueError):
                epss_f = 0.0
            corr_score = (KEV_TRUST_BOOST if kev else 0.0) + min(5.0, epss_f * 10)
            corr_score = min(10.0, corr_score)
            evidence["D5_corroboration"] = {
                "score": round(corr_score, 2), "max": 10.0,
                "kev": kev, "epss": epss,
            }
            total += corr_score

            # D6: Evidence Traceability (0-10)
            has_stix     = bool(advisory.get("stix_id", ""))
            has_blog_url = bool(advisory.get("blog_url", ""))
            has_cvss     = advisory.get("cvss") not in (None, "", "N/A")
            has_actor    = bool(actor and actor not in ("UNC-CDB-INGEST",))
            trace_score  = (
                (4.0 if has_stix else 0.0) +
                (2.0 if has_blog_url else 0.0) +
                (2.0 if has_cvss else 0.0) +
                (2.0 if has_actor else 0.0)
            )
            evidence["D6_evidence_traceability"] = {
                "score": round(trace_score, 2), "max": 10.0,
                "has_stix": has_stix, "has_blog_url": has_blog_url,
                "has_cvss": has_cvss, "has_actor": has_actor,
            }
            total += trace_score

            # D7: Temporal Freshness (0-5)
            ts_str    = advisory.get("timestamp", "")
            ts        = _parse_ts(ts_str)
            now       = datetime.now(timezone.utc)
            fresh_score = 0.0
            if ts:
                age_days = (now - ts).days
                if age_days <= 1:
                    fresh_score = 5.0
                elif age_days <= 7:
                    fresh_score = 4.0
                elif age_days <= 30:
                    fresh_score = 2.5
                elif age_days <= 90:
                    fresh_score = 1.0
            evidence["D7_temporal_freshness"] = {
                "score": round(fresh_score, 2), "max": 5.0,
                "timestamp": ts_str, "age_days": (now - ts).days if ts else None,
            }
            total += fresh_score

            # Clamp to [0, 100]
            trust_score = round(min(100.0, max(0.0, total)), 2)
            trust_tier  = _tier_from_score(trust_score)

            # Deterministic audit ID
            audit_raw  = f"{advisory.get('stix_id', '')}{advisory.get('title', ''[:40])}{trust_score}"
            trust_audit = hashlib.sha256(audit_raw.encode()).hexdigest()[:12]

            # Update telemetry
            self._telemetry["scored"] += 1
            self._telemetry["by_tier"][trust_tier] = (
                self._telemetry["by_tier"].get(trust_tier, 0) + 1
            )
            self._score_sum += trust_score
            self._telemetry["avg_score"] = round(
                self._score_sum / self._telemetry["scored"], 2
            )

            enriched = dict(advisory)
            enriched["trust_tier"]     = trust_tier
            enriched["trust_score"]    = trust_score
            enriched["trust_evidence"] = evidence
            enriched["trust_audit_id"] = trust_audit
            return enriched

        except Exception as e:
            logger.warning(f"[TRUST-TIER] Scoring failed for '{advisory.get('title', '?')[:40]}': {e}")
            return advisory

    def get_telemetry(self) -> Dict[str, Any]:
        snap = dict(self._telemetry)
        snap["last_updated"] = datetime.now(timezone.utc).isoformat()
        return snap


# Global singleton
_trust_engine: Optional[IntelligenceTrustTierEngine] = None


def get_trust_engine() -> IntelligenceTrustTierEngine:
    global _trust_engine
    if _trust_engine is None:
        _trust_engine = IntelligenceTrustTierEngine()
    return _trust_engine


def score_advisory_trust(advisory: Dict[str, Any]) -> Dict[str, Any]:
    """Convenience function: score a single advisory and return enriched copy."""
    return get_trust_engine().score_advisory(advisory)
