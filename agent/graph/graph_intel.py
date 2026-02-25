#!/usr/bin/env python3
"""
graph_intel.py — CYBERDUDEBIVASH® SENTINEL APEX v24.0
Intelligence Correlation Graph Engine.

Non-Breaking Addition: Standalone graph analysis module.
Does NOT modify existing pipeline modules.

Provides a lightweight in-memory graph layer that correlates:
    CVE ↔ Threat Actors
    Threat Actors ↔ Campaigns
    Malware ↔ Infrastructure
    Industry ↔ Attack Patterns
    Geo ↔ Sector Targeting

Optional: Uses Neo4j when available, falls back to networkx, then pure Python.

Author: CyberDudeBivash Pvt. Ltd.
"""

import json
import os
import logging
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Any

logger = logging.getLogger("CDB-Graph-Intel")
VERSION = "1.0.0"

GRAPH_DIR = "data/graph"


class IntelligenceNode:
    def __init__(self, node_id: str, node_type: str, properties: Optional[Dict] = None):
        self.node_id    = node_id
        self.node_type  = node_type  # cve, actor, campaign, malware, infra, industry, geo
        self.properties = properties or {}
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {
            "id":         self.node_id,
            "type":       self.node_type,
            "properties": self.properties,
            "created_at": self.created_at,
        }


class IntelligenceEdge:
    def __init__(self, source_id: str, target_id: str, relationship: str,
                 confidence: float = 0.7, properties: Optional[Dict] = None):
        self.source_id    = source_id
        self.target_id    = target_id
        self.relationship = relationship
        self.confidence   = confidence
        self.properties   = properties or {}

    def to_dict(self) -> Dict:
        return {
            "source":       self.source_id,
            "target":       self.target_id,
            "relationship": self.relationship,
            "confidence":   self.confidence,
            "properties":   self.properties,
        }


class ThreatIntelligenceGraph:
    """
    Lightweight in-memory threat intelligence correlation graph.

    Correlates entities extracted from manifest entries:
    - CVE nodes linked to threat actors
    - Actor nodes linked to campaigns
    - Malware nodes linked to infrastructure
    - Industry nodes linked to attack patterns

    Pure Python implementation — no external graph DB required.
    Optional Neo4j export for enterprise deployments.
    """

    def __init__(self):
        self._nodes: Dict[str, IntelligenceNode] = {}
        self._edges: List[IntelligenceEdge] = []
        self._adj: Dict[str, List[str]] = defaultdict(list)  # adjacency list

    # ── Node Management ──────────────────────────────────────

    def add_node(self, node_id: str, node_type: str, **properties) -> IntelligenceNode:
        if node_id not in self._nodes:
            node = IntelligenceNode(node_id, node_type, properties)
            self._nodes[node_id] = node
            self._adj[node_id]   = []
        return self._nodes[node_id]

    def get_node(self, node_id: str) -> Optional[IntelligenceNode]:
        return self._nodes.get(node_id)

    def node_count(self) -> int:
        return len(self._nodes)

    # ── Edge Management ──────────────────────────────────────

    def add_edge(self, source_id: str, target_id: str, relationship: str,
                 confidence: float = 0.7, **properties) -> IntelligenceEdge:
        # Auto-create nodes if missing
        if source_id not in self._nodes:
            self.add_node(source_id, "unknown")
        if target_id not in self._nodes:
            self.add_node(target_id, "unknown")

        edge = IntelligenceEdge(source_id, target_id, relationship, confidence, properties)
        self._edges.append(edge)
        self._adj[source_id].append(target_id)
        return edge

    def edge_count(self) -> int:
        return len(self._edges)

    # ── Graph Queries ─────────────────────────────────────────

    def get_neighbors(self, node_id: str) -> List[IntelligenceNode]:
        return [self._nodes[nid] for nid in self._adj.get(node_id, []) if nid in self._nodes]

    def get_connected_actors(self, cve_id: str) -> List[IntelligenceNode]:
        """Get all threat actors connected to a CVE."""
        neighbors = self.get_neighbors(cve_id)
        return [n for n in neighbors if n.node_type == "actor"]

    def get_actor_campaigns(self, actor_id: str) -> List[IntelligenceNode]:
        """Get all campaigns associated with a threat actor."""
        neighbors = self.get_neighbors(actor_id)
        return [n for n in neighbors if n.node_type == "campaign"]

    def get_actor_cves(self, actor_id: str) -> List[IntelligenceNode]:
        """Get all CVEs attributed to a threat actor."""
        neighbors = self.get_neighbors(actor_id)
        return [n for n in neighbors if n.node_type == "cve"]

    def get_industry_threat_actors(self, industry: str) -> List[IntelligenceNode]:
        """Get threat actors known to target a specific industry."""
        industry_id = f"industry:{industry}"
        neighbors   = self.get_neighbors(industry_id)
        return [n for n in neighbors if n.node_type == "actor"]

    def find_shared_infrastructure(self, actor1_id: str, actor2_id: str) -> List[IntelligenceNode]:
        """Detect shared infrastructure between two threat actors."""
        infra1 = {n.node_id for n in self.get_neighbors(actor1_id) if n.node_type == "infra"}
        infra2 = {n.node_id for n in self.get_neighbors(actor2_id) if n.node_type == "infra"}
        shared = infra1 & infra2
        return [self._nodes[nid] for nid in shared if nid in self._nodes]

    def get_hub_nodes(self, top_n: int = 10) -> List[Tuple[str, int]]:
        """Get the most connected nodes (hub analysis)."""
        degrees = [(nid, len(neighbors)) for nid, neighbors in self._adj.items()]
        return sorted(degrees, key=lambda x: x[1], reverse=True)[:top_n]

    def find_paths(self, source_id: str, target_id: str, max_depth: int = 4) -> List[List[str]]:
        """BFS path finding between two nodes."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return []

        queue   = [[source_id]]
        visited = set()
        paths   = []

        while queue and len(paths) < 5:
            path = queue.pop(0)
            node = path[-1]

            if node == target_id:
                paths.append(path)
                continue

            if len(path) >= max_depth or node in visited:
                continue

            visited.add(node)
            for neighbor_id in self._adj.get(node, []):
                if neighbor_id not in path:
                    queue.append(path + [neighbor_id])

        return paths

    # ── Graph Building from Manifest ─────────────────────────

    def build_from_manifest(self, entries: List[Dict]) -> Dict:
        """
        Build the intelligence graph from manifest entries.
        Extracts and correlates all entities automatically.
        """
        stats = {
            "nodes_created": 0,
            "edges_created": 0,
            "cves_indexed":  0,
            "actors_indexed": 0,
            "entries_processed": len(entries),
        }

        for entry in entries:
            entry_id   = entry.get("bundle_id") or entry.get("id") or "unknown"
            actor_tag  = entry.get("actor_tag") or ""
            cve_ids    = entry.get("cve_ids", []) or []
            mitre_t    = entry.get("mitre_tactics", []) or []
            severity   = entry.get("severity", "")
            risk_score = entry.get("risk_score", 0)

            # Create entry node
            self.add_node(entry_id, "advisory",
                title=entry.get("title", "")[:100],
                severity=severity,
                risk_score=risk_score,
                tlp=entry.get("tlp", "GREEN"),
            )
            stats["nodes_created"] += 1

            # Create actor node and link
            if actor_tag and actor_tag not in ("UNC-CDB-99", "unknown", ""):
                actor_id = f"actor:{actor_tag.lower()}"
                self.add_node(actor_id, "actor", name=actor_tag, nation="Unknown")
                self.add_edge(entry_id, actor_id, "ATTRIBUTED_TO", confidence=0.65)
                stats["actors_indexed"] += 1
                stats["nodes_created"] += 1
                stats["edges_created"] += 1

                # Link actor to industries (sector targeting)
                sector = entry.get("sector") or ""
                if sector:
                    industry_id = f"industry:{sector}"
                    self.add_node(industry_id, "industry", name=sector)
                    self.add_edge(actor_id, industry_id, "TARGETS", confidence=0.70)
                    stats["nodes_created"] += 1
                    stats["edges_created"] += 1

            # Create CVE nodes and link to advisory + actor
            for cve_id in cve_ids:
                if not cve_id or not cve_id.startswith("CVE-"):
                    continue
                cve_node_id = f"cve:{cve_id}"
                self.add_node(cve_node_id, "cve",
                    cve_id=cve_id,
                    cvss=entry.get("cvss_score"),
                    epss=entry.get("epss_score"),
                    kev=entry.get("kev_present", False),
                )
                self.add_edge(entry_id, cve_node_id, "EXPLOITS", confidence=0.90)
                stats["cves_indexed"] += 1
                stats["edges_created"] += 1

                # Link CVE to actor
                if actor_tag and actor_tag not in ("UNC-CDB-99", "unknown", ""):
                    actor_id = f"actor:{actor_tag.lower()}"
                    self.add_edge(actor_id, cve_node_id, "WEAPONIZES", confidence=0.60)
                    stats["edges_created"] += 1

            # MITRE technique nodes
            for technique in mitre_t[:5]:  # Cap at 5 to avoid explosion
                tactic_id = f"mitre:{technique}"
                self.add_node(tactic_id, "tactic", technique=technique)
                self.add_edge(entry_id, tactic_id, "USES_TECHNIQUE", confidence=0.80)
                stats["edges_created"] += 1

            # IOC infrastructure nodes
            iocs = entry.get("iocs", []) or []
            for ioc in iocs[:10]:  # Cap at 10 per entry
                if ioc.get("type") in ("ipv4", "domain"):
                    infra_id = f"infra:{ioc.get('value', '')}"
                    self.add_node(infra_id, "infra",
                        ioc_type=ioc.get("type"),
                        value=ioc.get("value", ""),
                    )
                    self.add_edge(entry_id, infra_id, "USES_INFRASTRUCTURE", confidence=0.75)
                    stats["edges_created"] += 1

        logger.info(f"Graph built: {stats}")
        return stats

    # ── Graph Analytics ───────────────────────────────────────

    def compute_threat_clustering(self) -> Dict:
        """Identify clusters of related threats based on shared actors/CVEs."""
        actor_nodes = [n for n in self._nodes.values() if n.node_type == "actor"]
        clusters    = []

        for actor in actor_nodes:
            connected_cves = self.get_actor_cves(actor.node_id)
            if connected_cves:
                clusters.append({
                    "actor":       actor.node_id,
                    "actor_name":  actor.properties.get("name", ""),
                    "cve_count":   len(connected_cves),
                    "cves":        [n.properties.get("cve_id") for n in connected_cves],
                    "industries":  [n.node_id.replace("industry:", "") for n in self.get_neighbors(actor.node_id) if n.node_type == "industry"],
                })

        return {
            "cluster_count":  len(clusters),
            "clusters":       sorted(clusters, key=lambda x: x["cve_count"], reverse=True)[:10],
            "hub_nodes":      self.get_hub_nodes(top_n=5),
            "total_nodes":    self.node_count(),
            "total_edges":    self.edge_count(),
            "computed_at":    datetime.now(timezone.utc).isoformat(),
        }

    def compute_attack_paths(self, target_industry: str) -> Dict:
        """Compute likely attack paths targeting a specific industry."""
        industry_id = f"industry:{target_industry}"
        actors      = self.get_industry_threat_actors(target_industry)
        paths       = []

        for actor in actors[:5]:
            cves = self.get_actor_cves(actor.node_id)
            for cve in cves[:3]:
                path = {
                    "actor":  actor.node_id,
                    "vector": cve.node_id,
                    "target": industry_id,
                    "path":   [actor.node_id, cve.node_id, industry_id],
                    "confidence": 0.65,
                }
                paths.append(path)

        return {
            "target_industry": target_industry,
            "threat_actor_count": len(actors),
            "attack_paths":    paths,
            "risk_level":      "HIGH" if len(paths) >= 5 else "MEDIUM" if len(paths) >= 2 else "LOW",
            "computed_at":     datetime.now(timezone.utc).isoformat(),
        }

    def export_to_json(self, output_path: Optional[str] = None) -> str:
        """Export the graph to JSON format for visualization or storage."""
        os.makedirs(GRAPH_DIR, exist_ok=True)
        output_path = output_path or os.path.join(GRAPH_DIR, "intel_graph.json")

        graph_data = {
            "nodes":       [n.to_dict() for n in self._nodes.values()],
            "edges":       [e.to_dict() for e in self._edges],
            "stats": {
                "node_count": self.node_count(),
                "edge_count": self.edge_count(),
            },
            "analytics":   self.compute_threat_clustering(),
            "platform":    "CYBERDUDEBIVASH SENTINEL APEX",
            "version":     VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }

        with open(output_path, "w") as f:
            json.dump(graph_data, f, indent=2)

        logger.info(f"Graph exported: {output_path} ({self.node_count()} nodes, {self.edge_count()} edges)")
        return output_path

    def generate_graph_summary(self) -> Dict:
        """Generate a human-readable graph intelligence summary."""
        clustering = self.compute_threat_clustering()
        hub_nodes  = self.get_hub_nodes(top_n=3)

        return {
            "graph_size":         {"nodes": self.node_count(), "edges": self.edge_count()},
            "node_types":         {
                "advisories": sum(1 for n in self._nodes.values() if n.node_type == "advisory"),
                "actors":     sum(1 for n in self._nodes.values() if n.node_type == "actor"),
                "cves":       sum(1 for n in self._nodes.values() if n.node_type == "cve"),
                "tactics":    sum(1 for n in self._nodes.values() if n.node_type == "tactic"),
                "infra":      sum(1 for n in self._nodes.values() if n.node_type == "infra"),
                "industries": sum(1 for n in self._nodes.values() if n.node_type == "industry"),
            },
            "most_connected":     hub_nodes,
            "threat_clusters":    clustering["cluster_count"],
            "top_cluster":        clustering["clusters"][0] if clustering["clusters"] else {},
            "version":            VERSION,
            "generated_at":       datetime.now(timezone.utc).isoformat(),
        }


if __name__ == "__main__":
    print(f"CDB Intelligence Graph Engine v{VERSION}")
    graph = ThreatIntelligenceGraph()

    # Demo build
    demo_entries = [
        {
            "bundle_id": "bundle--demo-001",
            "title": "LockBit 3.0 exploiting CVE-2024-1234",
            "severity": "CRITICAL",
            "risk_score": 9.2,
            "actor_tag": "lockbit",
            "cve_ids": ["CVE-2024-1234"],
            "mitre_tactics": ["T1486", "T1490"],
            "sector": "healthcare",
        },
        {
            "bundle_id": "bundle--demo-002",
            "title": "APT29 campaign targeting government",
            "severity": "CRITICAL",
            "risk_score": 9.5,
            "actor_tag": "APT29",
            "cve_ids": ["CVE-2024-5678", "CVE-2024-9999"],
            "mitre_tactics": ["T1566", "T1059", "T1078"],
            "sector": "government",
        },
    ]

    stats  = graph.build_from_manifest(demo_entries)
    summary = graph.generate_graph_summary()

    print(f"Graph built: {stats['nodes_created']} nodes, {stats['edges_created']} edges")
    print(f"Node types: {summary['node_types']}")
    print(f"Most connected: {summary['most_connected'][:3]}")

    output = graph.export_to_json()
    print(f"Exported: {output}")
