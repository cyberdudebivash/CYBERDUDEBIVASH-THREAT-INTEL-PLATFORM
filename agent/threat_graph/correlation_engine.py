"""
CYBERDUDEBIVASH® SENTINEL APEX
THREAT CORRELATION ENGINE — Pattern matching across threat data
Identifies clusters, campaigns, actor TTPs, and attack patterns.
"""
import hashlib
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .graph_engine import ThreatIntelGraph

logger = logging.getLogger("CDB-THREAT-CORRELATION")

# Known APT TTP signatures for correlation
APT_TTP_SIGNATURES = {
    "APT28-Fancy Bear":   ["T1566", "T1078", "T1059", "T1071", "T1003"],
    "APT29-Cozy Bear":    ["T1195", "T1199", "T1071", "T1027", "T1055"],
    "Lazarus Group":      ["T1486", "T1490", "T1003", "T1059", "T1041"],
    "REvil-Ransomware":   ["T1486", "T1490", "T1078", "T1021", "T1082"],
    "LockBit":            ["T1486", "T1490", "T1021", "T1083", "T1059"],
    "BlackCat-ALPHV":     ["T1486", "T1082", "T1083", "T1059", "T1041"],
    "Sandworm":           ["T1486", "T1055", "T1053", "T1059", "T1078"],
    "Volt Typhoon":       ["T1021", "T1078", "T1082", "T1562", "T1036"],
    "Salt Typhoon":       ["T1078", "T1059", "T1021", "T1040", "T1557"],
}

# IOC pattern matchers
IOC_PATTERNS = {
    "ipv4": r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
    "domain": r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
    "hash_md5": r"^[a-fA-F0-9]{32}$",
    "hash_sha1": r"^[a-fA-F0-9]{40}$",
    "hash_sha256": r"^[a-fA-F0-9]{64}$",
    "url": r"^https?://",
    "email": r"^[^@]+@[^@]+\.[^@]+$",
    "cve": r"^CVE-\d{4}-\d{4,}$",
}


class ThreatCorrelationEngine:
    """
    Correlates threat data to identify patterns, campaigns, and actor clusters.
    """

    def __init__(self, graph: Optional[ThreatIntelGraph] = None):
        self.graph = graph or ThreatIntelGraph()
        self.correlation_cache: Dict[str, Any] = {}
        self.stats = {"correlations": 0, "clusters": 0, "attributions": 0}

    # ── Actor Attribution ─────────────────────────────────────────────────────

    def correlate_ttps_to_actor(self, observed_ttps: List[str]) -> List[Dict]:
        """Match observed TTPs to known APT signatures."""
        results = []
        for actor, signature in APT_TTP_SIGNATURES.items():
            overlap = len(set(observed_ttps) & set(signature))
            if overlap > 0:
                confidence = round(overlap / len(signature), 2)
                results.append({
                    "actor": actor,
                    "overlap": overlap,
                    "signature_size": len(signature),
                    "confidence": confidence,
                    "confidence_label": "HIGH" if confidence > 0.6 else "MEDIUM" if confidence > 0.3 else "LOW",
                    "matched_ttps": list(set(observed_ttps) & set(signature)),
                })
        return sorted(results, key=lambda x: x["confidence"], reverse=True)

    # ── IOC Clustering ────────────────────────────────────────────────────────

    def cluster_iocs_by_campaign(self, advisories: List[Dict]) -> Dict[str, List]:
        """
        Group IOCs by likely campaign based on temporal proximity
        and TTP similarity.
        """
        import re
        clusters: Dict[str, List] = defaultdict(list)

        for adv in advisories:
            # Determine cluster key from severity + TTPs
            ttps = sorted(adv.get("mitre_techniques", []))[:3]
            severity = adv.get("severity", "MEDIUM")
            cluster_key = f"{severity}-{'_'.join(ttps[:2]) if ttps else 'UNKNOWN'}"
            clusters[cluster_key].append({
                "title": adv.get("title", "")[:80],
                "stix_id": adv.get("stix_id", ""),
                "ioc_count": len(adv.get("iocs", [])),
                "risk_score": adv.get("risk_score", 0),
                "timestamp": adv.get("timestamp", ""),
            })

        self.stats["clusters"] += len(clusters)
        return dict(clusters)

    # ── Pattern Correlation ───────────────────────────────────────────────────

    def find_related_advisories(self, advisory: Dict, all_advisories: List[Dict],
                                 threshold: float = 0.3) -> List[Dict]:
        """Find advisories related to the given one by TTP/IOC overlap."""
        target_ttps = set(advisory.get("mitre_techniques", []))
        target_cves = set(advisory.get("cves", []))
        related = []

        for other in all_advisories:
            if other.get("stix_id") == advisory.get("stix_id"):
                continue

            other_ttps = set(other.get("mitre_techniques", []))
            other_cves = set(other.get("cves", []))

            ttp_overlap = len(target_ttps & other_ttps) / max(len(target_ttps | other_ttps), 1)
            cve_overlap = len(target_cves & other_cves) / max(len(target_cves | other_cves), 1)
            similarity = (ttp_overlap * 0.6) + (cve_overlap * 0.4)

            if similarity >= threshold:
                related.append({
                    "stix_id": other.get("stix_id"),
                    "title": other.get("title", "")[:80],
                    "similarity": round(similarity, 2),
                    "shared_ttps": list(target_ttps & other_ttps),
                    "shared_cves": list(target_cves & other_cves),
                })

        return sorted(related, key=lambda x: x["similarity"], reverse=True)[:10]

    def generate_correlation_report(self, advisories: List[Dict]) -> Dict:
        """Full correlation analysis of a set of advisories."""
        all_ttps: List[str] = []
        all_cves: List[str] = []
        all_iocs: int = 0
        severity_dist: Dict[str, int] = defaultdict(int)

        for adv in advisories:
            all_ttps.extend(adv.get("mitre_techniques", []))
            all_cves.extend(adv.get("cves", []))
            all_iocs += len(adv.get("iocs", []))
            severity_dist[adv.get("severity", "UNKNOWN")] += 1

        # TTP frequency analysis
        ttp_freq: Dict[str, int] = defaultdict(int)
        for t in all_ttps:
            ttp_freq[t] += 1
        top_ttps = sorted(ttp_freq.items(), key=lambda x: -x[1])[:10]

        # Actor attribution from TTP patterns
        actor_matches = self.correlate_ttps_to_actor(list(set(all_ttps)))[:5]

        # Campaign clusters
        clusters = self.cluster_iocs_by_campaign(advisories)

        self.stats["correlations"] += 1
        return {
            "total_advisories": len(advisories),
            "total_ttps": len(set(all_ttps)),
            "total_cves": len(set(all_cves)),
            "total_iocs": all_iocs,
            "severity_distribution": dict(severity_dist),
            "top_ttps": [{"ttp": t, "count": c} for t, c in top_ttps],
            "actor_attribution": actor_matches,
            "campaign_clusters": {k: len(v) for k, v in clusters.items()},
            "total_clusters": len(clusters),
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        }
