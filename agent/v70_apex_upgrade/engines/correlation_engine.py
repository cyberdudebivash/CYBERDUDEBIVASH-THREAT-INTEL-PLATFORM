"""
SENTINEL APEX v70 — Correlation Engine
========================================
Links advisories across multiple dimensions:
- Shared CVEs
- Common threat actors
- MITRE ATT&CK technique overlap
- Target sector / product overlap
- Temporal proximity

Produces a correlation graph that feeds dashboard indicators
and enables campaign-level intelligence.
"""

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.models import Advisory, Campaign

logger = logging.getLogger("sentinel.correlation_engine")


class CorrelationLink:
    """A scored link between two advisories."""
    __slots__ = ("source_id", "target_id", "link_type", "shared_values", "score")

    def __init__(
        self,
        source_id: str,
        target_id: str,
        link_type: str,
        shared_values: List[str],
        score: float,
    ):
        self.source_id = source_id
        self.target_id = target_id
        self.link_type = link_type
        self.shared_values = shared_values
        self.score = score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "link_type": self.link_type,
            "shared_values": self.shared_values,
            "score": self.score,
        }


class CorrelationEngine:
    """
    Multi-dimensional correlation engine.
    Produces a weighted correlation graph over the advisory set.
    """

    # Weights for each correlation dimension
    WEIGHTS = {
        "cve": 0.35,
        "actor": 0.25,
        "technique": 0.20,
        "target": 0.10,
        "temporal": 0.10,
    }

    TEMPORAL_WINDOW_HOURS = 72  # Advisories within 72h are temporally related

    def __init__(self):
        self._links: List[CorrelationLink] = []
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)
        self._campaigns: List[Campaign] = []

    @property
    def links(self) -> List[CorrelationLink]:
        return list(self._links)

    @property
    def campaigns(self) -> List[Campaign]:
        return list(self._campaigns)

    def correlate(self, advisories: List[Advisory]) -> List[Advisory]:
        """
        Run correlation across all advisories.
        Updates each advisory's related_advisories and correlation_keys.
        Returns the updated advisory list.
        """
        self._links = []
        self._adjacency = defaultdict(set)

        if len(advisories) < 2:
            return advisories

        # Build inverted indices for O(n) lookup
        cve_index: Dict[str, List[int]] = defaultdict(list)
        actor_index: Dict[str, List[int]] = defaultdict(list)
        technique_index: Dict[str, List[int]] = defaultdict(list)
        sector_index: Dict[str, List[int]] = defaultdict(list)
        product_index: Dict[str, List[int]] = defaultdict(list)

        for idx, adv in enumerate(advisories):
            for cve in adv.cves:
                cve_index[cve.upper()].append(idx)
            for actor in adv.actors:
                actor_index[actor.lower()].append(idx)
            for tech in adv.mitre_techniques:
                technique_index[tech.upper()].append(idx)
            for sector in adv.affected_sectors:
                sector_index[sector.lower()].append(idx)
            for prod in adv.affected_products:
                product_index[prod.lower()].append(idx)

        # Find correlations via each dimension
        pair_scores: Dict[Tuple[int, int], Dict[str, float]] = defaultdict(
            lambda: {"cve": 0.0, "actor": 0.0, "technique": 0.0, "target": 0.0, "temporal": 0.0}
        )
        pair_shared: Dict[Tuple[int, int], Dict[str, List[str]]] = defaultdict(
            lambda: {"cve": [], "actor": [], "technique": [], "target": []}
        )

        # CVE correlations
        for cve, indices in cve_index.items():
            if len(indices) > 1:
                for i in range(len(indices)):
                    for j in range(i + 1, len(indices)):
                        pair = (min(indices[i], indices[j]), max(indices[i], indices[j]))
                        pair_scores[pair]["cve"] += 1.0
                        pair_shared[pair]["cve"].append(cve)

        # Actor correlations
        for actor, indices in actor_index.items():
            if len(indices) > 1:
                for i in range(len(indices)):
                    for j in range(i + 1, len(indices)):
                        pair = (min(indices[i], indices[j]), max(indices[i], indices[j]))
                        pair_scores[pair]["actor"] += 1.0
                        pair_shared[pair]["actor"].append(actor)

        # Technique correlations
        for tech, indices in technique_index.items():
            if len(indices) > 1:
                for i in range(len(indices)):
                    for j in range(i + 1, len(indices)):
                        pair = (min(indices[i], indices[j]), max(indices[i], indices[j]))
                        pair_scores[pair]["technique"] += 1.0
                        pair_shared[pair]["technique"].append(tech)

        # Target correlations (sectors + products)
        for key, indices in {**sector_index, **product_index}.items():
            if len(indices) > 1:
                for i in range(len(indices)):
                    for j in range(i + 1, len(indices)):
                        pair = (min(indices[i], indices[j]), max(indices[i], indices[j]))
                        pair_scores[pair]["target"] += 0.5
                        pair_shared[pair]["target"].append(key)

        # Temporal proximity
        for pair, scores in pair_scores.items():
            adv_a = advisories[pair[0]]
            adv_b = advisories[pair[1]]
            try:
                dt_a = datetime.fromisoformat(
                    adv_a.published_date.replace("Z", "+00:00")
                ) if adv_a.published_date else None
                dt_b = datetime.fromisoformat(
                    adv_b.published_date.replace("Z", "+00:00")
                ) if adv_b.published_date else None
                if dt_a and dt_b:
                    delta_hours = abs((dt_a - dt_b).total_seconds()) / 3600
                    if delta_hours <= self.TEMPORAL_WINDOW_HOURS:
                        temporal_score = 1.0 - (delta_hours / self.TEMPORAL_WINDOW_HOURS)
                        scores["temporal"] = temporal_score
            except (ValueError, TypeError):
                pass

        # Compute weighted composite scores and build links
        for pair, dim_scores in pair_scores.items():
            # Normalize per-dimension (cap at 1.0)
            norm_scores = {}
            for dim, raw in dim_scores.items():
                # Use sqrt scaling so even 1 shared item = 0.577 (strong signal)
                norm_scores[dim] = min(raw ** 0.5 / 1.732, 1.0)

            composite = sum(
                norm_scores.get(dim, 0.0) * weight
                for dim, weight in self.WEIGHTS.items()
            )

            if composite >= 0.10:  # Minimum correlation threshold
                shared = pair_shared[pair]
                all_shared = []
                for dim_values in shared.values():
                    all_shared.extend(dim_values)

                # Determine dominant link type
                dominant = max(dim_scores, key=dim_scores.get)

                link = CorrelationLink(
                    source_id=advisories[pair[0]].advisory_id,
                    target_id=advisories[pair[1]].advisory_id,
                    link_type=dominant,
                    shared_values=list(set(all_shared)),
                    score=round(composite, 3),
                )
                self._links.append(link)
                self._adjacency[advisories[pair[0]].advisory_id].add(advisories[pair[1]].advisory_id)
                self._adjacency[advisories[pair[1]].advisory_id].add(advisories[pair[0]].advisory_id)

        # Update advisory relationships
        id_to_idx = {adv.advisory_id: idx for idx, adv in enumerate(advisories)}
        for adv_id, related_ids in self._adjacency.items():
            if adv_id in id_to_idx:
                idx = id_to_idx[adv_id]
                advisories[idx].related_advisories = list(related_ids)
                # Build correlation keys
                corr_keys = set()
                for link in self._links:
                    if link.source_id == adv_id or link.target_id == adv_id:
                        corr_keys.update(link.shared_values)
                advisories[idx].correlation_keys = list(corr_keys)

        # Detect campaigns (clusters with strong actor + CVE correlation)
        self._detect_campaigns(advisories)

        logger.info(
            f"Correlation complete: {len(self._links)} links found, "
            f"{len(self._campaigns)} potential campaigns detected"
        )
        return advisories

    def _detect_campaigns(self, advisories: List[Advisory]) -> None:
        """
        Detect potential campaigns from strongly correlated advisory clusters.
        A campaign = 3+ advisories sharing actor(s) or 3+ CVEs.
        """
        self._campaigns = []

        # Find connected components in the correlation graph
        visited: Set[str] = set()
        id_to_adv = {a.advisory_id: a for a in advisories}

        for adv_id in self._adjacency:
            if adv_id in visited:
                continue
            # BFS to find cluster
            cluster = set()
            queue = [adv_id]
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                cluster.add(current)
                for neighbor in self._adjacency.get(current, set()):
                    if neighbor not in visited:
                        queue.append(neighbor)

            if len(cluster) >= 3:
                # This cluster might be a campaign
                cluster_advs = [id_to_adv[aid] for aid in cluster if aid in id_to_adv]
                shared_actors = set()
                shared_cves = set()
                shared_techniques = set()
                for a in cluster_advs:
                    shared_actors.update(a.actors)
                    shared_cves.update(a.cves)
                    shared_techniques.update(a.mitre_techniques)

                if shared_actors or len(shared_cves) >= 3:
                    campaign = Campaign(
                        name=f"Campaign: {list(shared_actors)[0] if shared_actors else 'Unknown'} "
                             f"({len(shared_cves)} CVEs)",
                        threat_actors=list(shared_actors),
                        cves_exploited=list(shared_cves),
                        ttps=list(shared_techniques),
                        iocs=[],
                    )
                    for a in cluster_advs:
                        a.campaigns.append(campaign.campaign_id)
                    self._campaigns.append(campaign)

    def get_correlation_graph(self) -> Dict[str, Any]:
        """Export the correlation graph as JSON-serializable dict."""
        return {
            "total_links": len(self._links),
            "total_campaigns": len(self._campaigns),
            "links": [l.to_dict() for l in self._links],
            "campaigns": [c.to_dict() for c in self._campaigns],
        }
