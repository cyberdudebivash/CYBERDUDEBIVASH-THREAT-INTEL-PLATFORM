"""
CYBERDUDEBIVASH® SENTINEL APEX
GRAPH RISK SCORER — Node-level and graph-level risk quantification
PageRank-inspired threat propagation scoring.
"""
import logging
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-RISK-SCORER")

DAMPING_FACTOR = 0.85
MAX_ITERATIONS = 50
CONVERGENCE_THRESHOLD = 1e-6


class GraphRiskScorer:
    """
    Computes threat propagation scores across the graph.
    High-connectivity, high-severity nodes get higher aggregate scores.
    """

    def __init__(self, graph):
        self.graph = graph

    def compute_threat_rank(self) -> Dict[str, float]:
        """
        Modified PageRank for threat propagation scoring.
        Nodes with more connections to high-risk nodes score higher.
        """
        nodes = list(self.graph.nodes.keys())
        if not nodes:
            return {}

        n = len(nodes)
        rank = {node_id: 1.0 / n for node_id in nodes}

        for iteration in range(MAX_ITERATIONS):
            new_rank: Dict[str, float] = {}
            delta = 0.0

            for node_id in nodes:
                # Sum contributions from neighbors
                neighbor_contrib = 0.0
                for neighbor_id in self.graph.adjacency.get(node_id, []):
                    neighbor_degree = len(self.graph.adjacency.get(neighbor_id, [])) or 1
                    neighbor_node = self.graph.nodes.get(neighbor_id)
                    risk_weight = (neighbor_node.risk_score / 10.0) if neighbor_node else 0.5
                    neighbor_contrib += (rank[neighbor_id] / neighbor_degree) * risk_weight

                new_rank[node_id] = (1 - DAMPING_FACTOR) / n + DAMPING_FACTOR * neighbor_contrib

                # Also factor in the node's own base risk score
                base_node = self.graph.nodes.get(node_id)
                if base_node:
                    new_rank[node_id] = new_rank[node_id] * 0.7 + (base_node.risk_score / 10.0) * 0.3

                delta += abs(new_rank[node_id] - rank[node_id])

            rank = new_rank
            if delta < CONVERGENCE_THRESHOLD:
                logger.debug(f"[RISK-SCORER] Converged after {iteration+1} iterations")
                break

        # Normalize to 0-10 scale
        max_rank = max(rank.values()) if rank else 1.0
        return {nid: round((v / max_rank) * 10, 2) for nid, v in rank.items()}

    def get_critical_nodes(self, top_n: int = 20) -> List[Dict]:
        """Get top-N most critical nodes by threat rank."""
        threat_ranks = self.compute_threat_rank()
        scored_nodes = []

        for node_id, threat_score in sorted(threat_ranks.items(),
                                             key=lambda x: -x[1])[:top_n]:
            node = self.graph.nodes.get(node_id)
            if node:
                scored_nodes.append({
                    **node.to_dict(),
                    "threat_rank": threat_score,
                    "connection_count": len(self.graph.adjacency.get(node_id, [])),
                    "risk_category": self._categorize_risk(threat_score),
                })

        return scored_nodes

    def _categorize_risk(self, score: float) -> str:
        if score >= 8.5: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 5.0: return "MEDIUM"
        if score >= 3.0: return "LOW"
        return "INFORMATIONAL"

    def compute_aggregate_risk(self) -> Dict:
        """Compute overall platform risk score."""
        if not self.graph.nodes:
            return {"aggregate_score": 0.0, "risk_level": "UNKNOWN"}

        scores = [n.risk_score for n in self.graph.nodes.values()]
        avg = sum(scores) / len(scores)
        max_s = max(scores)
        high_risk_count = sum(1 for s in scores if s >= 7.0)

        # Weighted aggregate: 50% average, 30% max, 20% proportion of high-risk nodes
        proportion_high = high_risk_count / len(scores)
        aggregate = round((avg * 0.5) + (max_s * 0.3) + (proportion_high * 10 * 0.2), 2)
        aggregate = min(10.0, aggregate)

        return {
            "aggregate_score": aggregate,
            "risk_level": self._categorize_risk(aggregate),
            "avg_node_risk": round(avg, 2),
            "max_node_risk": max_s,
            "high_risk_nodes": high_risk_count,
            "total_nodes": len(scores),
            "calculated_at": datetime.now(timezone.utc).isoformat(),
        }
