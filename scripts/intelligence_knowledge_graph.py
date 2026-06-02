#!/usr/bin/env python3
"""
SENTINEL APEX v167.0 — INTELLIGENCE KNOWLEDGE GRAPH ENGINE
==========================================================
Phase 6 of Enterprise CTI Transformation.

Builds a graph connecting: Actor → Campaign → Malware → Infrastructure → IOC → Victim
Enables pivot analysis, relationship discovery, and investigation workflows.

Storage:
  data/graph/snapshot.json        — full graph snapshot
  data/graph/nodes.json           — all graph nodes
  data/graph/edges.json           — all graph edges
  data/graph/actors.json          — actor node index
  data/graph/pivot_index.json     — pre-computed pivot paths
"""

from __future__ import annotations
import json, logging, sys, hashlib
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict

log = logging.getLogger("KNOWLEDGE-GRAPH-ENGINE")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")

REPO_ROOT = Path(__file__).resolve().parents[1]
GRAPH_DIR = REPO_ROOT / "data" / "graph"
GRAPH_DIR.mkdir(parents=True, exist_ok=True)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def node_id(node_type: str, value: str) -> str:
    return f"{node_type}:{hashlib.md5((node_type + value).encode()).hexdigest()[:12]}"


class IntelligenceKnowledgeGraph:
    """Graph engine connecting all CTI intelligence objects."""

    NODE_TYPES = ["threat_actor", "campaign", "malware", "infrastructure",
                  "ioc", "victim", "industry", "technique", "advisory", "cve"]

    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self.adjacency: dict[str, list[str]] = defaultdict(list)

    def add_node(self, node_type: str, node_id_val: str, properties: dict) -> str:
        nid = node_id(node_type, node_id_val)
        self.nodes[nid] = {
            "node_id": nid,
            "node_type": node_type,
            "label": properties.get("name") or properties.get("value") or node_id_val,
            "properties": properties,
            "updated_at": utc_now(),
        }
        return nid

    def add_edge(self, from_id: str, to_id: str, relationship: str, confidence: int = 80, properties: dict = None) -> None:
        if from_id not in self.nodes or to_id not in self.nodes:
            return
        edge = {
            "from": from_id,
            "to": to_id,
            "relationship": relationship,
            "confidence": confidence,
            "properties": properties or {},
            "created_at": utc_now(),
        }
        self.edges.append(edge)
        self.adjacency[from_id].append(to_id)
        self.adjacency[to_id].append(from_id)

    def build_from_library(self) -> None:
        """Bootstrap graph from actor and campaign libraries."""
        from scripts.threat_actor_engine import ACTOR_LIBRARY
        from scripts.campaign_intelligence_engine import CAMPAIGN_LIBRARY

        # Add actor nodes
        for actor_id, profile in ACTOR_LIBRARY.items():
            nid = self.add_node("threat_actor", actor_id, {
                "name": profile["canonical_name"],
                "country": profile["country_attribution"],
                "motivation": profile["motivation"],
                "sophistication": profile["sophistication_level"],
                "confidence": profile["attribution_confidence"],
                "active": profile.get("active_status") == "ACTIVE",
            })

            # Add technique nodes and edges
            for ttp in profile.get("ttps", [])[:10]:
                ttp_nid = self.add_node("technique", ttp, {"name": ttp, "framework": "MITRE ATT&CK"})
                self.add_edge(nid, ttp_nid, "USES_TECHNIQUE", confidence=profile["attribution_confidence"])

            # Add malware nodes and edges
            for malware in profile.get("known_malware", [])[:5]:
                m_nid = self.add_node("malware", malware, {"name": malware})
                self.add_edge(nid, m_nid, "USES_MALWARE", confidence=profile["attribution_confidence"])

            # Add sector/industry nodes
            for sector in profile.get("target_sectors", [])[:5]:
                s_nid = self.add_node("industry", sector, {"name": sector})
                self.add_edge(nid, s_nid, "TARGETS_SECTOR", confidence=70)

        # Add campaign nodes and edges
        for cid, campaign in CAMPAIGN_LIBRARY.items():
            c_nid = self.add_node("campaign", cid, {
                "name": campaign["campaign_name"],
                "status": campaign["status"],
                "risk_score": campaign["risk_score"],
                "start_date": campaign["start_date"],
            })

            # Link campaign to actor
            actor_id = campaign.get("attributed_actor")
            if actor_id:
                a_nid = node_id("threat_actor", actor_id)
                self.add_edge(a_nid, c_nid, "OPERATES_CAMPAIGN",
                              confidence=campaign["confidence"])
                self.add_edge(c_nid, a_nid, "ATTRIBUTED_TO",
                              confidence=campaign["confidence"])

            # Campaign TTPs
            for ttp in campaign.get("ttps", [])[:8]:
                ttp_nid = node_id("technique", ttp)
                if ttp_nid in self.nodes:
                    self.add_edge(c_nid, ttp_nid, "USES_TECHNIQUE", confidence=campaign["confidence"])

            # Campaign malware
            for malware in campaign.get("malware_used", [])[:3]:
                m_nid = node_id("malware", malware)
                if m_nid in self.nodes:
                    self.add_edge(c_nid, m_nid, "DEPLOYS_MALWARE", confidence=campaign["confidence"])

        log.info("[KG] Built graph: %d nodes, %d edges", len(self.nodes), len(self.edges))

    def build_from_feed(self, feed_path: Path) -> None:
        """Extend graph with advisory-level intelligence."""
        try:
            raw = json.loads(feed_path.read_text(encoding="utf-8"))
        except Exception:
            return

        items = raw if isinstance(raw, list) else raw.get("advisories", raw.get("items", []))
        advisories_added = 0

        for item in items:
            adv_id = item.get("id") or item.get("stix_id") or "unknown"
            if not adv_id or adv_id == "unknown":
                continue

            # Advisory node
            a_nid = self.add_node("advisory", adv_id, {
                "title": item.get("title", ""),
                "severity": item.get("severity", "UNKNOWN"),
                "risk_score": item.get("risk_score", 0),
                "published_at": item.get("published_at", ""),
            })

            # Link to actor
            actor = (item.get("threat_actor") or {}).get("actor_id")
            if actor and actor not in ("CDB-UNATTR", "CDB-UNATTR-CVE", "UNKNOWN"):
                actor_nid = node_id("threat_actor", actor)
                if actor_nid in self.nodes:
                    conf = (item.get("threat_actor") or {}).get("confidence", 50)
                    self.add_edge(a_nid, actor_nid, "REFERENCES_ACTOR", confidence=conf)

            # Link to campaign
            campaign = (item.get("campaign_intelligence") or {}).get("primary_campaign")
            if campaign:
                c_nid = node_id("campaign", campaign)
                if c_nid in self.nodes:
                    self.add_edge(a_nid, c_nid, "BELONGS_TO_CAMPAIGN", confidence=70)

            # CVE nodes
            for cve in (item.get("cve_ids") or [])[:3]:
                cve_nid = self.add_node("cve", cve, {
                    "cve_id": cve,
                    "cvss": item.get("cvss_score"),
                    "epss": item.get("epss_score"),
                    "kev": item.get("kev_present", False),
                })
                self.add_edge(a_nid, cve_nid, "CONTAINS_CVE", confidence=95)

            # Technique nodes
            for ttp in (item.get("tags") or [])[:5]:
                if ttp.startswith("T"):
                    t_nid = node_id("technique", ttp)
                    if t_nid not in self.nodes:
                        t_nid = self.add_node("technique", ttp, {"name": ttp, "framework": "MITRE ATT&CK"})
                    self.add_edge(a_nid, t_nid, "USES_TECHNIQUE", confidence=75)

            advisories_added += 1

        log.info("[KG] Added %d advisories to graph. Total: %d nodes, %d edges",
                 advisories_added, len(self.nodes), len(self.edges))

    def get_neighbors(self, node_id_val: str, depth: int = 1) -> dict:
        """Return neighboring nodes up to given depth."""
        visited = {node_id_val}
        frontier = {node_id_val}
        result_nodes = {node_id_val: self.nodes.get(node_id_val)}
        result_edges = []

        for _ in range(depth):
            next_frontier = set()
            for nid in frontier:
                neighbors = self.adjacency.get(nid, [])
                for neighbor in neighbors:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_frontier.add(neighbor)
                        if neighbor in self.nodes:
                            result_nodes[neighbor] = self.nodes[neighbor]
                        # Add edges between visited nodes
                        for edge in self.edges:
                            if (edge["from"] == nid and edge["to"] == neighbor) or \
                               (edge["to"] == nid and edge["from"] == neighbor):
                                result_edges.append(edge)
            frontier = next_frontier

        return {
            "center": node_id_val,
            "depth": depth,
            "nodes": list(result_nodes.values()),
            "edges": result_edges,
        }

    def pivot(self, from_type: str, from_value: str, to_type: str) -> list[dict]:
        """Pivot from one node type to another."""
        start_nid = node_id(from_type, from_value)
        if start_nid not in self.nodes:
            return []

        # BFS to find all nodes of target type
        results = []
        visited = {start_nid}
        queue = [start_nid]

        while queue:
            current = queue.pop(0)
            for neighbor in self.adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append(neighbor)
                    node = self.nodes.get(neighbor)
                    if node and node["node_type"] == to_type:
                        results.append(node)

        return results

    def compute_stats(self) -> dict:
        type_counts: dict[str, int] = defaultdict(int)
        for node in self.nodes.values():
            type_counts[node["node_type"]] += 1

        rel_counts: dict[str, int] = defaultdict(int)
        for edge in self.edges:
            rel_counts[edge["relationship"]] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes_by_type": dict(type_counts),
            "top_relationships": dict(sorted(rel_counts.items(), key=lambda x: -x[1])[:10]),
        }

    def save(self) -> None:
        """Persist graph to data/graph/."""
        stats = self.compute_stats()
        snapshot = {
            "generated_at": utc_now(),
            "schema_version": "v2.0",
            "stats": stats,
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }
        (GRAPH_DIR / "snapshot.json").write_text(
            json.dumps(snapshot, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        # Separate indexes for fast API lookups
        for node_type in self.NODE_TYPES:
            type_nodes = [n for n in self.nodes.values() if n["node_type"] == node_type]
            if type_nodes:
                (GRAPH_DIR / f"{node_type}s.json").write_text(
                    json.dumps({"nodes": type_nodes, "generated_at": utc_now()}, indent=2), encoding="utf-8"
                )

        log.info("[KG] Graph saved: %d nodes, %d edges → data/graph/", len(self.nodes), len(self.edges))

    def generate_pivot_index(self) -> None:
        """Pre-compute common pivot paths for API performance."""
        pivots = {}
        # Actor → IOC paths
        for nid, node in self.nodes.items():
            if node["node_type"] == "threat_actor":
                actor_name = node["properties"].get("name", "")
                iocs = self.pivot("threat_actor", node["properties"].get("name", ""), "ioc")
                campaigns = self.pivot("threat_actor", actor_name, "campaign")
                malware = self.pivot("threat_actor", actor_name, "malware")
                pivots[nid] = {
                    "actor": actor_name,
                    "linked_campaigns": len(campaigns),
                    "linked_malware": len(malware),
                    "linked_iocs": len(iocs),
                }

        (GRAPH_DIR / "pivot_index.json").write_text(
            json.dumps({"generated_at": utc_now(), "pivots": pivots}, indent=2), encoding="utf-8"
        )


def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX v167.0 — INTELLIGENCE KNOWLEDGE GRAPH ENGINE")
    log.info("=" * 60)

    kg = IntelligenceKnowledgeGraph()

    # 1. Build from static libraries
    try:
        kg.build_from_library()
    except ImportError as e:
        log.warning("[KG] Library import failed (non-fatal): %s", e)

    # 2. Extend from live feed
    for fp in [REPO_ROOT / "data" / "feed_manifest.json", REPO_ROOT / "data" / "stix" / "feed_manifest.json"]:
        if fp.exists():
            kg.build_from_feed(fp)

    # 3. Save
    kg.save()
    kg.generate_pivot_index()

    stats = kg.compute_stats()
    log.info("[KG] COMPLETE — %d nodes, %d edges, %d node types",
             stats["total_nodes"], stats["total_edges"], len(stats["nodes_by_type"]))
    return 0

if __name__ == "__main__":
    sys.exit(main())
