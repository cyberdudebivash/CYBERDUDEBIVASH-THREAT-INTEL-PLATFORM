"""
SENTINEL APEX v70 — Threat Scoring Engine
===========================================
Real composite threat scoring combining:
- CVSS base score (0-10)
- EPSS probability (0-1)
- KEV status (boolean → binary)
- Exploit availability (boolean → binary)
- Source trust rating (0-1)
- Temporal recency decay
- IOC density factor

Output: 0-100 composite threat score with severity classification.
"""

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..core.models import Advisory, CVERecord, Severity

logger = logging.getLogger("sentinel.threat_scoring")


# ---------------------------------------------------------------------------
# Source Trust Database
# ---------------------------------------------------------------------------

SOURCE_TRUST_SCORES: Dict[str, float] = {
    # Government / Official
    "cisa": 0.98,
    "us-cert": 0.98,
    "nist": 0.97,
    "nvd": 0.97,
    "cert-in": 0.95,
    "ncsc": 0.96,
    "enisa": 0.95,
    "jpcert": 0.94,
    "auscert": 0.93,

    # Tier 1 Vendors
    "microsoft": 0.95,
    "google": 0.94,
    "apple": 0.94,
    "cisco": 0.93,
    "oracle": 0.92,
    "vmware": 0.92,
    "adobe": 0.91,
    "redhat": 0.92,

    # Tier 1 Threat Intel
    "mandiant": 0.96,
    "crowdstrike": 0.95,
    "recorded future": 0.94,
    "palo alto": 0.93,
    "unit42": 0.93,
    "talos": 0.93,
    "kaspersky": 0.91,
    "eset": 0.90,
    "sophos": 0.89,
    "trendmicro": 0.89,
    "sentinelone": 0.90,

    # Research / Community
    "bleepingcomputer": 0.82,
    "theregister": 0.80,
    "hackernews": 0.78,
    "thehackernews": 0.80,
    "krebs": 0.88,
    "securityweek": 0.82,
    "darkreading": 0.81,
    "threatpost": 0.80,

    # RSS / Aggregated
    "rss": 0.60,
    "generic": 0.50,
}


def get_source_trust(source_name: str) -> float:
    """Lookup source trust score. Returns 0.50 for unknown sources."""
    if not source_name:
        return 0.50
    sn = source_name.lower().strip()
    for key, score in SOURCE_TRUST_SCORES.items():
        if key in sn:
            return score
    return 0.50


# ---------------------------------------------------------------------------
# Threat Scoring Engine
# ---------------------------------------------------------------------------

class ThreatScoringEngine:
    """
    Production threat scoring engine.
    Produces a 0-100 composite score for each advisory.
    """

    # Scoring weights (sum = 1.0)
    WEIGHTS = {
        "cvss": 0.25,
        "epss": 0.15,
        "kev": 0.15,
        "exploit": 0.12,
        "source_trust": 0.10,
        "ioc_density": 0.08,
        "recency": 0.08,
        "actor_presence": 0.07,
    }

    def __init__(self, cve_lookup: Optional[Dict[str, CVERecord]] = None):
        self.cve_lookup = cve_lookup or {}
        self._stats = {"scored": 0, "enriched_from_cve": 0}

    def score_advisory(self, advisory: Advisory) -> float:
        """
        Compute composite threat score for a single advisory.
        Returns score in range [0, 100].
        """
        signals: Dict[str, float] = {}

        # 1. CVSS — max across all linked CVEs
        max_cvss = 0.0
        max_epss = 0.0
        any_kev = False
        any_exploit = False

        for cve_id in advisory.cves:
            cve_rec = self.cve_lookup.get(cve_id.upper())
            if cve_rec:
                self._stats["enriched_from_cve"] += 1
                max_cvss = max(max_cvss, cve_rec.cvss_score)
                max_epss = max(max_epss, cve_rec.epss_score)
                any_kev = any_kev or cve_rec.kev_status
                any_exploit = any_exploit or cve_rec.exploit_available

        signals["cvss"] = min(max_cvss / 10.0, 1.0)

        # 2. EPSS
        signals["epss"] = min(max_epss, 1.0)

        # 3. KEV
        signals["kev"] = 1.0 if any_kev else 0.0

        # 4. Exploit availability
        signals["exploit"] = 1.0 if any_exploit else 0.0

        # 5. Source trust
        signals["source_trust"] = get_source_trust(advisory.source_name)

        # 6. IOC density — more IOCs = higher threat signal
        ioc_count = len(advisory.iocs)
        signals["ioc_density"] = min(ioc_count / 10.0, 1.0)  # Cap at 10 IOCs = 1.0

        # 7. Recency decay — newer = higher
        signals["recency"] = self._recency_score(advisory.published_date)

        # 8. Actor presence — named actor = higher confidence
        signals["actor_presence"] = min(len(advisory.actors), 2) / 2.0

        # Composite weighted score
        composite = sum(
            signals.get(dim, 0.0) * weight
            for dim, weight in self.WEIGHTS.items()
        )

        # Scale to 0-100 and apply minimum floor
        score = round(composite * 100, 2)

        # Floor: if we have CVEs or IOCs, minimum score is 15
        if advisory.cves or advisory.iocs:
            score = max(score, 15.0)

        # Cap at 100
        score = min(score, 100.0)

        self._stats["scored"] += 1
        return score

    def _recency_score(self, published_date: str) -> float:
        """Exponential decay: full score if < 24h, decays to ~0.1 at 30 days."""
        if not published_date:
            return 0.3  # Unknown date gets moderate recency
        try:
            dt = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            hours_old = max((now - dt).total_seconds() / 3600, 0)
            # Exponential decay: half-life = 72 hours
            return max(math.exp(-0.00963 * hours_old), 0.05)
        except (ValueError, TypeError):
            return 0.3

    def score_batch(self, advisories: List[Advisory]) -> List[Advisory]:
        """Score all advisories in batch. Updates each advisory in-place."""
        for adv in advisories:
            adv.threat_score = self.score_advisory(adv)
            # Derive severity from score
            if adv.threat_score >= 80:
                adv.severity = Severity.CRITICAL
                adv.risk_level = "CRITICAL"
            elif adv.threat_score >= 60:
                adv.severity = Severity.HIGH
                adv.risk_level = "HIGH"
            elif adv.threat_score >= 35:
                adv.severity = Severity.MEDIUM
                adv.risk_level = "MEDIUM"
            elif adv.threat_score >= 15:
                adv.severity = Severity.LOW
                adv.risk_level = "LOW"
            else:
                adv.severity = Severity.INFO
                adv.risk_level = "INFO"

        logger.info(
            f"Scoring complete: {self._stats['scored']} advisories scored, "
            f"{self._stats['enriched_from_cve']} CVE enrichments applied"
        )
        return advisories


# ---------------------------------------------------------------------------
# Confidence Engine
# ---------------------------------------------------------------------------

class ConfidenceEngine:
    """
    Dynamic confidence scoring engine.
    Replaces static 24% with multi-factor confidence calculation.

    Factors:
    - Source credibility (0-1)
    - CVE verification (0-1)
    - IOC corroboration (0-1)
    - Cross-reference density (0-1)
    - Temporal validation (0-1)
    - Data completeness (0-1)
    """

    WEIGHTS = {
        "source_credibility": 0.25,
        "cve_verification": 0.20,
        "ioc_corroboration": 0.15,
        "cross_reference": 0.15,
        "temporal_validity": 0.10,
        "data_completeness": 0.15,
    }

    def compute_confidence(self, advisory: Advisory) -> float:
        """Compute dynamic confidence score (0-100) for an advisory."""
        signals: Dict[str, float] = {}

        # 1. Source credibility
        signals["source_credibility"] = get_source_trust(advisory.source_name)

        # 2. CVE verification — verified CVEs boost confidence
        if advisory.cves:
            # More CVEs with proper format = higher confidence
            valid_cves = sum(
                1 for c in advisory.cves
                if c.upper().startswith("CVE-") and len(c.split("-")) == 3
            )
            signals["cve_verification"] = min(valid_cves / max(len(advisory.cves), 1), 1.0)
        else:
            signals["cve_verification"] = 0.2  # No CVEs = lower but not zero

        # 3. IOC corroboration — IOCs present with proper types
        if advisory.iocs:
            typed_iocs = sum(
                1 for ioc in advisory.iocs
                if hasattr(ioc, 'ioc_type') and ioc.ioc_type.value != "unknown"
            )
            signals["ioc_corroboration"] = min(typed_iocs / max(len(advisory.iocs), 1), 1.0)
        else:
            signals["ioc_corroboration"] = 0.1

        # 4. Cross-reference density
        related = len(advisory.related_advisories)
        corr_keys = len(advisory.correlation_keys)
        signals["cross_reference"] = min((related + corr_keys) / 10.0, 1.0)

        # 5. Temporal validity — recent data is more trustworthy
        try:
            if advisory.published_date:
                dt = datetime.fromisoformat(advisory.published_date.replace("Z", "+00:00"))
                days_old = (datetime.now(timezone.utc) - dt).days
                if days_old <= 1:
                    signals["temporal_validity"] = 1.0
                elif days_old <= 7:
                    signals["temporal_validity"] = 0.9
                elif days_old <= 30:
                    signals["temporal_validity"] = 0.7
                elif days_old <= 90:
                    signals["temporal_validity"] = 0.5
                else:
                    signals["temporal_validity"] = 0.3
            else:
                signals["temporal_validity"] = 0.3
        except (ValueError, TypeError):
            signals["temporal_validity"] = 0.3

        # 6. Data completeness — how much of the advisory is filled in
        completeness_fields = [
            advisory.title, advisory.summary, advisory.source_url,
            advisory.source_name, advisory.published_date,
        ]
        completeness_lists = [
            advisory.cves, advisory.iocs, advisory.mitre_techniques,
            advisory.tags,
        ]
        filled_basic = sum(1 for f in completeness_fields if f)
        filled_lists = sum(1 for l in completeness_lists if l)
        total_possible = len(completeness_fields) + len(completeness_lists)
        signals["data_completeness"] = (filled_basic + filled_lists) / total_possible

        # Weighted composite
        composite = sum(
            signals.get(dim, 0.0) * weight
            for dim, weight in self.WEIGHTS.items()
        )

        # Scale to 0-100
        confidence = round(composite * 100, 2)

        # Floor: always at least 5% for any ingested advisory
        confidence = max(confidence, 5.0)
        return min(confidence, 100.0)

    def score_batch(self, advisories: List[Advisory]) -> List[Advisory]:
        """Compute confidence for all advisories in batch."""
        for adv in advisories:
            adv.confidence = self.compute_confidence(adv)
            from ..core.models import ConfidenceLevel
            adv.confidence_level = ConfidenceLevel.from_score(adv.confidence)

        logger.info(f"Confidence scoring complete: {len(advisories)} advisories")
        return advisories
