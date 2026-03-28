"""
CYBERDUDEBIVASH® SENTINEL APEX
THREAT INTELLIGENCE GRAPH ENGINE v1.0
Real-time graph: actors → malware → CVEs → campaigns → TTPs
STIX 2.1 native, relationship-driven, risk-scored.
"""
import json
import logging
import os
import re
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-THREAT-GRAPH")

# Node types aligned with STIX 2.1
NODE_TYPES = {
    "threat-actor": "ACTOR",
    "malware": "MALWARE",
    "vulnerability": "CVE",
    "campaign": "CAMPAIGN",
    "attack-pattern": "TTP",
    "indicator": "IOC",
    "tool": "TOOL",
    "intrusion-set": "APT_GROUP",
    "course-of-action": "MITIGATION",
}

RELATIONSHIP_WEIGHTS = {
    "uses": 0.8,
    "targets": 0.9,
    "attributed-to": 1.0,
    "indicates": 0.7,
    "mitigates": 0.5,
    "related-to": 0.4,
    "exploits": 0.95,
    "delivers": 0.85,
    "drops": 0.8,
}


class ThreatGraphNode:
    __slots__ = ["id", "type", "name", "risk_score", "properties", "created_at"]

    def __init__(self, node_id: str, node_type: str, name: str,
                 risk_score: float = 5.0, properties: Optional[Dict] = None):
        self.id = node_id
        self.type = node_type
        self.name = name
        self.risk_score = risk_score
        self.properties = properties or {}
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {"id": self.id, "type": self.type, "name": self.name,
                "risk_score": self.risk_score, "properties": self.properties,
                "created_at": self.created_at}


class ThreatGraphEdge:
    __slots__ = ["source_id", "target_id", "relationship", "weight", "created_at"]

    def __init__(self, source_id: str, target_id: str, relationship: str, weight: float = 0.5):
        self.source_id = source_id
        self.target_id = target_id
        self.relationship = relationship
        self.weight = weight
        self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict:
        return {"source": self.source_id, "target": self.target_id,
                "relationship": self.relationship, "weight": self.weight,
                "created_at": self.created_at}


class ThreatIntelGraph:
    """
    In-memory threat intelligence graph.
    Nodes: actors, malware, CVEs, campaigns, TTPs, IOCs.
    Edges: relationships between entities.
    """

    def __init__(self):
        self.nodes: Dict[str, ThreatGraphNode] = {}
        self.edges: List[ThreatGraphEdge] = []
        self.adjacency: Dict[str, List[str]] = defaultdict(list)
        self.stats = {"nodes": 0, "edges": 0, "ingested": 0}

    def add_node(self, node: ThreatGraphNode) -> bool:
        if node.id in self.nodes:
            # Update existing
            existing = self.nodes[node.id]
            existing.risk_score = max(existing.risk_score, node.risk_score)
            existing.properties.update(node.properties)
            return False
        self.nodes[node.id] = node
        self.stats["nodes"] += 1
        return True

    def add_edge(self, edge: ThreatGraphEdge) -> None:
        self.edges.append(edge)
        self.adjacency[edge.source_id].append(edge.target_id)
        self.adjacency[edge.target_id].append(edge.source_id)
        self.stats["edges"] += 1

    def get_neighbors(self, node_id: str, max_hops: int = 2) -> Dict[str, Any]:
        """BFS traversal to find connected nodes up to max_hops."""
        if node_id not in self.nodes:
            return {"node_id": node_id, "found": False, "neighbors": []}

        visited = set()
        queue = [(node_id, 0)]
        result = []

        while queue:
            current_id, depth = queue.pop(0)
            if current_id in visited or depth > max_hops:
                continue
            visited.add(current_id)

            if current_id != node_id and current_id in self.nodes:
                result.append({**self.nodes[current_id].to_dict(), "depth": depth})

            if depth < max_hops:
                for neighbor_id in self.adjacency.get(current_id, []):
                    if neighbor_id not in visited:
                        queue.append((neighbor_id, depth + 1))

        return {
            "node_id": node_id,
            "node": self.nodes[node_id].to_dict() if node_id in self.nodes else None,
            "found": True,
            "neighbor_count": len(result),
            "neighbors": result,
        }

    def get_high_risk_nodes(self, threshold: float = 7.0) -> List[Dict]:
        """Return all nodes above risk threshold, sorted by score."""
        high_risk = [n.to_dict() for n in self.nodes.values() if n.risk_score >= threshold]
        return sorted(high_risk, key=lambda x: x["risk_score"], reverse=True)

    def find_attack_paths(self, actor_id: str, target_type: str = "CVE") -> List[List[str]]:
        """Find attack paths from actor to target node type."""
        paths = []
        target_nodes = [n.id for n in self.nodes.values() if n.type == target_type]

        for target_id in target_nodes[:5]:  # Limit to 5 paths
            path = self._bfs_path(actor_id, target_id)
            if path:
                paths.append(path)
        return paths

    def _bfs_path(self, start: str, end: str) -> Optional[List[str]]:
        queue = [[start]]
        visited = set()
        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node == end:
                return path
            if node in visited:
                continue
            visited.add(node)
            for neighbor in self.adjacency.get(node, []):
                if neighbor not in visited:
                    queue.append(path + [neighbor])
        return None

    def ingest_stix_bundle(self, bundle: Dict) -> Dict:
        """Ingest a STIX 2.1 bundle into the graph."""
        objects = bundle.get("objects", [])
        added_nodes = 0
        added_edges = 0

        for obj in objects:
            obj_type = obj.get("type", "")
            obj_id = obj.get("id", "")

            if obj_type == "relationship":
                source = obj.get("source_ref", "")
                target = obj.get("target_ref", "")
                rel_type = obj.get("relationship_type", "related-to")
                weight = RELATIONSHIP_WEIGHTS.get(rel_type, 0.4)
                self.add_edge(ThreatGraphEdge(source, target, rel_type, weight))
                added_edges += 1
            elif obj_type in NODE_TYPES:
                name = (obj.get("name") or obj.get("external_references", [{}])[0].get("external_id", obj_id))
                def _safe_risk(o):
                    for k in ("x_risk_score","cvss_score","risk_score","cvss"):
                        v = o.get(k)
                        if v is not None:
                            try: return float(v)
                            except: pass
                    try: return float(o.get("cvss_v3",{}).get("base_score",5.0) or 5.0)
                    except: return 5.0
                risk_score = _safe_risk(obj)
                node = ThreatGraphNode(
                    node_id=obj_id,
                    node_type=NODE_TYPES[obj_type],
                    name=str(name)[:120],
                    risk_score=risk_score,
                    properties={k: v for k, v in obj.items()
                                 if k not in ("id", "type", "name") and not isinstance(v, (dict, list))},
                )
                if self.add_node(node):
                    added_nodes += 1

        self.stats["ingested"] += 1
        return {"added_nodes": added_nodes, "added_edges": added_edges,
                "total_nodes": self.stats["nodes"], "total_edges": self.stats["edges"]}

    def ingest_advisory(self, advisory: Dict) -> Dict:
        """Convert a threat advisory into graph nodes and edges."""
        added = 0
        title = str(advisory.get("title", ""))[:80]
        risk  = float(advisory.get("risk_score") or advisory.get("cvss_score") or
                      advisory.get("cvss") or 5.0)
        stix_id = advisory.get("stix_id", "")

        # ── CVE nodes — check both 'cves' and extract from title/summary ──
        cves = advisory.get("cves") or advisory.get("cve_list") or []
        if not cves:
            import re
            text = f"{title} {str(advisory.get('summary',''))}"
            cves = list(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.I)))

        for cve in cves:
            cve_id = str(cve).upper()
            node = ThreatGraphNode(
                node_id=f"vulnerability--{cve_id}",
                node_type="CVE",
                name=cve_id,
                risk_score=risk,
                properties={"cvss": advisory.get("cvss_score") or advisory.get("cvss"),
                             "epss": advisory.get("epss_score") or advisory.get("epss"),
                             "kev": advisory.get("kev_present") or advisory.get("kev_confirmed", False)},
            )
            if self.add_node(node):
                added += 1

        # ── IOC nodes — support both list and count-dict format ──────────
        raw_iocs = advisory.get("iocs") or []
        ioc_counts = advisory.get("ioc_counts") or {}
        ioc_count = advisory.get("indicator_count", 0)
        # If no ioc list but count > 0, create a synthetic indicator node
        if not raw_iocs and ioc_count:
            ioc_id = f"indicator--{stix_id or title[:20]}-synthetic"
            node = ThreatGraphNode(
                node_id=ioc_id,
                node_type="IOC",
                name=f"IOCs({ioc_count}) from {title[:40]}",
                risk_score=risk,
                properties={"count": ioc_count, "types": list(ioc_counts.keys()) if ioc_counts else []},
            )
            if self.add_node(node):
                added += 1
        else:
            for ioc in raw_iocs[:20]:
                ioc_val = str(ioc.get("value", ioc) if isinstance(ioc, dict) else ioc)
                ioc_id = f"indicator--{hashlib.md5(ioc_val.encode()).hexdigest()}"
                node = ThreatGraphNode(
                    node_id=ioc_id,
                    node_type="IOC",
                    name=ioc_val[:80],
                    risk_score=risk,
                    properties={"type": ioc.get("type","unknown") if isinstance(ioc,dict) else "string"},
                )
                if self.add_node(node):
                    added += 1

        # ── TTP nodes — check both 'mitre_techniques' and 'mitre_tactics' ─
        ttps = (advisory.get("mitre_techniques") or
                advisory.get("mitre_tactics") or
                advisory.get("techniques") or [])
        for ttp in ttps[:10]:
            ttp_id = str(ttp).upper()
            node = ThreatGraphNode(
                node_id=f"attack-pattern--{ttp_id}",
                node_type="TTP",
                name=ttp_id,
                risk_score=7.0,
            )
            if self.add_node(node):
                added += 1

        # ── Actor node ─────────────────────────────────────────────────────
        actor = advisory.get("actor_tag") or advisory.get("actor") or ""
        if actor and actor not in ("UNKNOWN", "UNC-UNKNOWN", ""):
            node = ThreatGraphNode(
                node_id=f"threat-actor--{hashlib.md5(str(actor).encode()).hexdigest()[:16]}",
                node_type="ACTOR",
                name=str(actor)[:80],
                risk_score=min(10.0, risk + 1.5),
            )
            if self.add_node(node):
                added += 1

        # ── Advisory node always created ───────────────────────────────────
        adv_id = f"advisory--{stix_id or hashlib.md5(title.encode()).hexdigest()[:16]}"
        node = ThreatGraphNode(
            node_id=adv_id,
            node_type="ADVISORY",
            name=title,
            risk_score=risk,
            properties={"severity": advisory.get("severity",""), "timestamp": advisory.get("timestamp","")},
        )
        if self.add_node(node):
            added += 1

        return {"advisory_ingested": title, "nodes_added": added}

    def get_graph_summary(self) -> Dict:
        type_counts: Dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            type_counts[n.type] += 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_types": dict(type_counts),
            "high_risk_nodes": len(self.get_high_risk_nodes()),
            "bundles_ingested": self.stats["ingested"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
