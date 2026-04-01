#!/usr/bin/env python3
"""
threat_graph_engine.py — CYBERDUDEBIVASH SENTINEL APEX
THREAT GRAPH ENGINE v1.0 — Enterprise Knowledge Graph Layer

Competitive level: Recorded Future Graph, Mandiant Advantage,
CrowdStrike Threat Intelligence Graph, MISP Galaxy Correlation.

Node types:
  CVE       — vulnerability identifier (e.g. CVE-2024-1234)
  ACTOR     — threat actor / APT group
  CAMPAIGN  — named threat campaign
  IOC       — indicator of compromise (IP, domain, hash, URL)
  TECHNIQUE — MITRE ATT&CK TTP (e.g. T1059)
  FEED      — intelligence feed source

Edge types:
  EXPLOITS       CVE → ACTOR    "CVE exploited by actor"
  USES           CVE → TECHNIQUE "CVE uses technique"
  OPERATES       ACTOR → CAMPAIGN "actor operates campaign"
  TARGETS        ACTOR → CVE    "actor targets via CVE"
  INDICATES      IOC → CVE      "IOC indicates CVE activity"
  RELATED_TO     CVE → CVE      "CVEs share actor/campaign/technique"
  ATTRIBUTED_TO  CAMPAIGN → ACTOR
  EMPLOYS        CAMPAIGN → TECHNIQUE
  SOURCED_FROM   CVE → FEED

Design principles:
  - Pure stdlib — zero external dependencies
  - Deterministic node/edge IDs (MD5-hash stable)
  - Idempotent: merge on re-run (never duplicates)
  - Atomic JSON writes (temp → rename)
  - ZERO-FAILURE: unconditional exit(0)

Output files:
  data/threat_graph/graph_nodes.json         — all nodes
  data/threat_graph/graph_edges.json         — all edges
  data/threat_graph/adjacency_index.json     — fast lookup index
  data/threat_graph/correlation_clusters.json — connected components
  data/threat_graph/high_risk_paths.json     — top threat paths
  data/threat_graph/graph_meta.json          — run telemetry

Version: v1.0
Author: CYBERDUDEBIVASH SENTINEL APEX
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-THREAT-GRAPH] %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("CDB-THREAT-GRAPH")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR        = Path(__file__).resolve().parent.parent
DATA_DIR        = BASE_DIR / "data"
STIX_DIR        = DATA_DIR / "stix"
GRAPH_DIR       = DATA_DIR / "threat_graph"
MEMORY_DIR      = DATA_DIR / "threat_memory"
MANIFEST_PATH   = STIX_DIR / "feed_manifest.json"
AI_INDEX_PATH   = DATA_DIR / "ai_intelligence" / "ai_index.json"
CVE_MEMORY_PATH = MEMORY_DIR / "cve_memory.json"
ACTOR_MEM_PATH  = MEMORY_DIR / "actor_memory.json"
CAMP_MEM_PATH   = MEMORY_DIR / "campaign_memory.json"

# ---------------------------------------------------------------------------
# Node / Edge type constants
# ---------------------------------------------------------------------------
NT_CVE       = "CVE"
NT_ACTOR     = "ACTOR"
NT_CAMPAIGN  = "CAMPAIGN"
NT_IOC       = "IOC"
NT_TECHNIQUE = "TECHNIQUE"
NT_FEED      = "FEED"

ET_EXPLOITS      = "EXPLOITS"
ET_USES          = "USES"
ET_OPERATES      = "OPERATES"
ET_TARGETS       = "TARGETS"
ET_INDICATES     = "INDICATES"
ET_RELATED_TO    = "RELATED_TO"
ET_ATTRIBUTED_TO = "ATTRIBUTED_TO"
ET_EMPLOYS       = "EMPLOYS"
ET_SOURCED_FROM  = "SOURCED_FROM"

# ---------------------------------------------------------------------------
# Safe IO utilities
# ---------------------------------------------------------------------------

def _safe_write_json(path: Path, data: Any, indent: Optional[int] = 2) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False, default=str)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.warning(f"Write failed {path.name}: {e}")
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass
        return False


def _safe_load_json(path: Path, default: Any = None) -> Any:
    try:
        if path.exists() and path.stat().st_size > 0:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"Load failed {path.name}: {e}")
    return default if default is not None else {}


def _node_id(node_type: str, label: str) -> str:
    """Deterministic node ID: TYPE:HASH12"""
    h = hashlib.md5(f"{node_type}:{label}".encode()).hexdigest()[:12].upper()
    return f"{node_type}:{h}"


def _edge_id(src_id: str, edge_type: str, dst_id: str) -> str:
    """Deterministic edge ID."""
    h = hashlib.md5(f"{src_id}|{edge_type}|{dst_id}".encode()).hexdigest()[:12].upper()
    return f"E:{h}"


# ===========================================================================
# NODE REGISTRY
# ===========================================================================

class NodeRegistry:
    """
    Thread-safe (single-threaded) node registry with dedup.
    Merges properties on re-insert (idempotent).
    """

    def __init__(self, existing: Optional[Dict] = None):
        # node_id → node_dict
        self._nodes: Dict[str, Dict] = {}
        if existing:
            for nid, node in existing.items():
                self._nodes[nid] = node

    def upsert(
        self,
        node_type: str,
        label: str,
        properties: Optional[Dict] = None,
    ) -> str:
        nid = _node_id(node_type, label)
        if nid in self._nodes:
            # Merge new properties
            if properties:
                existing = self._nodes[nid]
                for k, v in properties.items():
                    if k not in existing or not existing[k]:
                        existing[k] = v
                # Increment observation count
                existing["observation_count"] = existing.get("observation_count", 1) + 1
                existing["last_seen"] = datetime.now(timezone.utc).isoformat()
        else:
            node = {
                "id": nid,
                "type": node_type,
                "label": label[:200],
                "observation_count": 1,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
            if properties:
                node.update(properties)
            self._nodes[nid] = node
        return nid

    def get(self, nid: str) -> Optional[Dict]:
        return self._nodes.get(nid)

    def all_nodes(self) -> List[Dict]:
        return list(self._nodes.values())

    def count(self) -> int:
        return len(self._nodes)

    def to_dict(self) -> Dict:
        return dict(self._nodes)


# ===========================================================================
# EDGE REGISTRY
# ===========================================================================

class EdgeRegistry:
    """
    Edge registry with dedup and weight tracking.
    Re-inserting same edge increments its weight.
    """

    def __init__(self, existing: Optional[Dict] = None):
        self._edges: Dict[str, Dict] = {}
        if existing:
            for eid, edge in existing.items():
                self._edges[eid] = edge

    def upsert(
        self,
        src_id: str,
        edge_type: str,
        dst_id: str,
        properties: Optional[Dict] = None,
    ) -> str:
        eid = _edge_id(src_id, edge_type, dst_id)
        if eid in self._edges:
            self._edges[eid]["weight"] = self._edges[eid].get("weight", 1) + 1
            self._edges[eid]["last_seen"] = datetime.now(timezone.utc).isoformat()
        else:
            edge = {
                "id": eid,
                "source": src_id,
                "type": edge_type,
                "target": dst_id,
                "weight": 1,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
            if properties:
                edge.update(properties)
            self._edges[eid] = edge
        return eid

    def all_edges(self) -> List[Dict]:
        return list(self._edges.values())

    def count(self) -> int:
        return len(self._edges)

    def to_dict(self) -> Dict:
        return dict(self._edges)


# ===========================================================================
# ADJACENCY INDEX
# ===========================================================================

class AdjacencyIndex:
    """Fast adjacency lookup: node_id → {outgoing: [...], incoming: [...]}"""

    def __init__(self):
        self._out: Dict[str, List[str]] = defaultdict(list)
        self._in: Dict[str, List[str]] = defaultdict(list)

    def add_edge(self, src_id: str, edge_id: str, dst_id: str) -> None:
        if edge_id not in self._out[src_id]:
            self._out[src_id].append(edge_id)
        if edge_id not in self._in[dst_id]:
            self._in[dst_id].append(edge_id)

    def neighbors_out(self, node_id: str) -> List[str]:
        return list(self._out.get(node_id, []))

    def neighbors_in(self, node_id: str) -> List[str]:
        return list(self._in.get(node_id, []))

    def to_dict(self) -> Dict:
        return {
            "outgoing": {k: v for k, v in self._out.items()},
            "incoming": {k: v for k, v in self._in.items()},
        }


# ===========================================================================
# GRAPH BUILDER — reads manifest and memory, builds nodes + edges
# ===========================================================================

class ThreatGraphBuilder:
    """
    Extracts entities from manifest advisories and memory databases,
    builds a typed knowledge graph.
    """

    # Known APT/actor patterns for node normalization
    KNOWN_ACTORS = {
        "APT28", "APT29", "APT41", "APT32", "APT34", "APT38",
        "Lazarus", "Sandworm", "Cozy Bear", "Fancy Bear", "Charming Kitten",
        "DarkSide", "BlackCat", "LockBit", "BlackMatter", "REvil", "Hive",
        "Volt Typhoon", "Salt Typhoon", "Scattered Spider", "UNC2452",
        "TA505", "FIN7", "Carbanak", "Turla", "Equation Group",
        "CDB-CYB-01", "CDB-CYB-02", "CDB-CYB-03",
    }

    # IOC type patterns
    IP_RE      = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    DOMAIN_RE  = r"^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$"
    MD5_RE     = r"^[a-fA-F0-9]{32}$"
    SHA1_RE    = r"^[a-fA-F0-9]{40}$"
    SHA256_RE  = r"^[a-fA-F0-9]{64}$"
    CVE_RE     = r"CVE-\d{4}-\d{4,7}"

    def __init__(self, nodes: NodeRegistry, edges: EdgeRegistry, adj: AdjacencyIndex):
        self.nodes = nodes
        self.edges = edges
        self.adj   = adj
        import re as _re
        self._re = _re

    def _add_edge(self, src: str, etype: str, dst: str, props: Optional[Dict] = None) -> str:
        eid = self.edges.upsert(src, etype, dst, props)
        self.adj.add_edge(src, eid, dst)
        return eid

    def _classify_ioc(self, ioc: str) -> str:
        import re as re_
        if re_.match(self.IP_RE, ioc):
            return "ip"
        if re_.match(self.SHA256_RE, ioc):
            return "sha256"
        if re_.match(self.SHA1_RE, ioc):
            return "sha1"
        if re_.match(self.MD5_RE, ioc):
            return "md5"
        if re_.match(self.DOMAIN_RE, ioc) and "." in ioc:
            return "domain"
        return "unknown"

    def _extract_cve_id(self, item: Dict) -> Optional[str]:
        """Extract CVE ID from manifest entry."""
        import re as re_
        # From nvd_url
        nvd = item.get("nvd_url", "")
        if nvd:
            m = re_.search(self.CVE_RE, nvd)
            if m:
                return m.group(0)
        # From stix_id or title
        title = item.get("title", "")
        m = re_.search(self.CVE_RE, title)
        if m:
            return m.group(0)
        # From advisory_id
        aid = item.get("advisory_id", "")
        m = re_.search(self.CVE_RE, str(aid))
        if m:
            return m.group(0)
        return None

    def process_advisory(self, item: Dict) -> int:
        """Process one advisory item. Returns number of nodes/edges added."""
        added = 0

        title      = item.get("title", "Unknown Advisory")[:120]
        actor_tag  = item.get("actor_tag", "UNC-UNKNOWN")
        tactics    = item.get("mitre_tactics", []) or []
        risk       = float(item.get("risk_score", 0) or 0)
        severity   = item.get("severity", "LOW")
        kev        = bool(item.get("kev_present", False))
        feed_src   = item.get("feed_source", "unknown")[:80]
        campaign_d = item.get("campaign", {}) or {}
        ioc_counts = item.get("ioc_counts", {}) or {}
        stix_id    = item.get("stix_id", "")
        epss       = float(item.get("epss_score") or 0)
        cvss       = float(item.get("cvss_score") or 0)

        # --- CVE node ---
        cve_id = self._extract_cve_id(item)
        if not cve_id:
            # Use stix_id as synthetic identifier
            cve_id = f"ADV-{hashlib.md5(title.encode()).hexdigest()[:8].upper()}"

        cve_nid = self.nodes.upsert(NT_CVE, cve_id, {
            "title": title,
            "risk_score": risk,
            "severity": severity,
            "kev_present": kev,
            "epss_score": epss,
            "cvss_score": cvss,
            "stix_id": stix_id,
            "exploit_probability": item.get("exploit_probability", "Unknown"),
        })
        added += 1

        # --- Actor node ---
        actor_label = actor_tag if actor_tag != "UNC-UNKNOWN" else "Unknown Actor"
        actor_nid = self.nodes.upsert(NT_ACTOR, actor_label, {
            "known": actor_tag in self.KNOWN_ACTORS,
            "attribution_confidence": item.get("confidence_score", 0),
        })
        added += 1

        # ACTOR TARGETS CVE
        self._add_edge(actor_nid, ET_TARGETS, cve_nid, {"risk": risk, "kev": kev})
        # CVE EXPLOITS (by) ACTOR — bidirectional semantic
        self._add_edge(cve_nid, ET_EXPLOITS, actor_nid, {"severity": severity})
        added += 2

        # --- Technique nodes ---
        for tac in tactics:
            tac_str = str(tac).strip()
            if not tac_str:
                continue
            tac_nid = self.nodes.upsert(NT_TECHNIQUE, tac_str, {
                "framework": "MITRE ATT&CK",
                "url": f"https://attack.mitre.org/techniques/{tac_str}/",
            })
            # CVE USES technique
            self._add_edge(cve_nid, ET_USES, tac_nid, {"advisory_title": title[:60]})
            # ACTOR EMPLOYS technique (via this CVE)
            self._add_edge(actor_nid, ET_EMPLOYS, tac_nid, {"via_cve": cve_id})
            added += 3

        # --- Campaign node ---
        campaign_name = ""
        if isinstance(campaign_d, dict):
            campaign_name = str(campaign_d.get("name", "")).strip()
        elif isinstance(campaign_d, str):
            campaign_name = campaign_d.strip()

        if campaign_name and campaign_name not in ("", "Unknown", "N/A"):
            camp_nid = self.nodes.upsert(NT_CAMPAIGN, campaign_name, {
                "risk": campaign_d.get("risk", risk) if isinstance(campaign_d, dict) else risk,
                "threat_count": campaign_d.get("threat_count", 1) if isinstance(campaign_d, dict) else 1,
            })
            # ACTOR OPERATES campaign
            self._add_edge(actor_nid, ET_OPERATES, camp_nid)
            # CAMPAIGN ATTRIBUTED TO actor
            self._add_edge(camp_nid, ET_ATTRIBUTED_TO, actor_nid)
            # CVE belongs to campaign
            self._add_edge(cve_nid, ET_RELATED_TO, camp_nid, {"relationship": "part_of_campaign"})
            for tac in tactics:
                tac_str = str(tac).strip()
                if tac_str:
                    tac_nid = _node_id(NT_TECHNIQUE, tac_str)
                    self._add_edge(camp_nid, ET_EMPLOYS, tac_nid)
            added += 3

        # --- IOC nodes (from ioc_counts keys as IOC types) ---
        if isinstance(ioc_counts, dict):
            for ioc_type, count_or_list in ioc_counts.items():
                if isinstance(count_or_list, list):
                    for ioc_val in count_or_list[:10]:  # cap at 10 per type
                        ioc_val = str(ioc_val).strip()
                        if len(ioc_val) > 3:
                            ioc_nid = self.nodes.upsert(NT_IOC, ioc_val, {
                                "ioc_type": ioc_type,
                                "classified": self._classify_ioc(ioc_val),
                            })
                            self._add_edge(ioc_nid, ET_INDICATES, cve_nid, {"ioc_type": ioc_type})
                            added += 2
                elif isinstance(count_or_list, (int, float)) and int(count_or_list) > 0:
                    # ioc_type label without specific value
                    ioc_label = f"{ioc_type}:from:{cve_id}"
                    ioc_nid = self.nodes.upsert(NT_IOC, ioc_label, {
                        "ioc_type": ioc_type,
                        "count": int(count_or_list),
                    })
                    self._add_edge(ioc_nid, ET_INDICATES, cve_nid, {"ioc_type": ioc_type})
                    added += 2

        # --- Feed node ---
        if feed_src:
            feed_nid = self.nodes.upsert(NT_FEED, feed_src, {"url": feed_src})
            self._add_edge(cve_nid, ET_SOURCED_FROM, feed_nid)
            added += 2

        return added

    def process_actor_memory(self, actor_mem: Dict) -> int:
        """Enrich graph from actor memory database."""
        added = 0
        for actor_label, actor_data in actor_mem.items():
            if not isinstance(actor_data, dict):
                continue
            actor_nid = self.nodes.upsert(NT_ACTOR, actor_label, {
                "activity_trend": actor_data.get("activity_trend", "STABLE"),
                "total_advisories": actor_data.get("total_advisories", 0),
                "known": actor_label in self.KNOWN_ACTORS,
            })
            added += 1
            # Link techniques from actor memory
            for tac in actor_data.get("techniques", []):
                tac_str = str(tac).strip()
                if tac_str:
                    tac_nid = self.nodes.upsert(NT_TECHNIQUE, tac_str, {
                        "framework": "MITRE ATT&CK",
                    })
                    self._add_edge(actor_nid, ET_EMPLOYS, tac_nid, {"source": "actor_memory"})
                    added += 2
        return added

    def process_campaign_memory(self, camp_mem: Dict) -> int:
        """Enrich graph from campaign memory."""
        added = 0
        for camp_name, camp_data in camp_mem.items():
            if not isinstance(camp_data, dict):
                continue
            camp_nid = self.nodes.upsert(NT_CAMPAIGN, camp_name, {
                "evolution_score": camp_data.get("evolution_score", 0),
                "status": camp_data.get("status", "unknown"),
                "total_advisories": camp_data.get("total_advisories", 0),
            })
            added += 1
            # Link actors
            for actor in camp_data.get("actors", []):
                actor_str = str(actor).strip()
                if actor_str:
                    actor_nid = self.nodes.upsert(NT_ACTOR, actor_str)
                    self._add_edge(actor_nid, ET_OPERATES, camp_nid, {"source": "campaign_memory"})
                    added += 2
        return added


# ===========================================================================
# CORRELATION ENGINE — connected components + path analysis
# ===========================================================================

class CorrelationEngine:
    """
    Finds connected components and high-risk threat paths in the graph.
    Uses BFS on adjacency index — pure Python, no external libs.
    """

    def __init__(self, nodes: NodeRegistry, edges: EdgeRegistry, adj: AdjacencyIndex):
        self.nodes = nodes
        self.edges = edges
        self.adj   = adj

    def find_connected_components(self) -> List[Dict]:
        """
        BFS-based connected components (undirected traversal).
        Returns list of clusters sorted by size desc.
        """
        all_node_ids = {n["id"] for n in self.nodes.all_nodes()}
        visited: Set[str] = set()
        clusters: List[List[str]] = []

        # Build undirected adjacency for BFS
        undirected: Dict[str, Set[str]] = defaultdict(set)
        for edge in self.edges.all_edges():
            src = edge["source"]
            dst = edge["target"]
            undirected[src].add(dst)
            undirected[dst].add(src)

        for start_nid in all_node_ids:
            if start_nid in visited:
                continue
            # BFS
            cluster: List[str] = []
            queue = deque([start_nid])
            visited.add(start_nid)
            while queue:
                nid = queue.popleft()
                cluster.append(nid)
                for neighbor in undirected.get(nid, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)
            clusters.append(cluster)

        # Sort largest first
        clusters.sort(key=len, reverse=True)

        result = []
        for i, cluster in enumerate(clusters[:50]):  # top 50 clusters
            node_types = defaultdict(int)
            max_risk = 0.0
            actors: List[str] = []
            cves: List[str] = []
            for nid in cluster:
                node = self.nodes.get(nid)
                if not node:
                    continue
                node_types[node["type"]] += 1
                risk = float(node.get("risk_score", 0) or 0)
                if risk > max_risk:
                    max_risk = risk
                if node["type"] == NT_ACTOR:
                    actors.append(node["label"])
                if node["type"] == NT_CVE:
                    cves.append(node["label"])

            result.append({
                "cluster_id": f"CLUSTER-{i+1:03d}",
                "size": len(cluster),
                "node_ids": cluster[:20],  # cap stored IDs at 20
                "node_type_counts": dict(node_types),
                "max_risk_score": round(max_risk, 2),
                "actors": actors[:5],
                "cves": cves[:5],
            })

        return result

    def find_high_risk_paths(self, top_n: int = 20) -> List[Dict]:
        """
        Find highest-risk CVE→Actor→Campaign chains.
        Returns paths sorted by combined risk score.
        """
        paths: List[Dict] = []

        # Get all CVE nodes sorted by risk
        cve_nodes = sorted(
            [n for n in self.nodes.all_nodes() if n["type"] == NT_CVE],
            key=lambda x: -float(x.get("risk_score", 0) or 0),
        )[:100]  # process top 100 CVEs only for performance

        edge_map: Dict[str, Dict] = {e["id"]: e for e in self.edges.all_edges()}

        for cve_node in cve_nodes:
            cve_id = cve_node["id"]
            cve_risk = float(cve_node.get("risk_score", 0) or 0)

            # Find actors linked to this CVE
            for eid in self.adj.neighbors_out(cve_id):
                edge = edge_map.get(eid)
                if not edge or edge["type"] not in (ET_EXPLOITS, ET_USES):
                    continue
                target_nid = edge["target"]
                target_node = self.nodes.get(target_nid)
                if not target_node:
                    continue

                path_risk = cve_risk + float(target_node.get("risk_score", 0) or 0)

                # Find campaigns linked to this actor (if target is ACTOR)
                campaign_names: List[str] = []
                if target_node["type"] == NT_ACTOR:
                    for eid2 in self.adj.neighbors_out(target_nid):
                        edge2 = edge_map.get(eid2)
                        if edge2 and edge2["type"] == ET_OPERATES:
                            camp_node = self.nodes.get(edge2["target"])
                            if camp_node and camp_node["type"] == NT_CAMPAIGN:
                                campaign_names.append(camp_node["label"])
                                path_risk += float(camp_node.get("risk", 0) or 0)

                paths.append({
                    "path": [
                        {"id": cve_id, "type": NT_CVE, "label": cve_node["label"]},
                        {"id": target_nid, "type": target_node["type"], "label": target_node["label"]},
                    ],
                    "campaigns": campaign_names[:3],
                    "combined_risk": round(path_risk, 2),
                    "cve_risk": cve_risk,
                    "kev": bool(cve_node.get("kev_present", False)),
                    "edge_type": edge["type"],
                })

        # Sort by combined risk
        paths.sort(key=lambda x: -x["combined_risk"])
        return paths[:top_n]


# ===========================================================================
# MAIN THREAT GRAPH ENGINE ORCHESTRATOR
# ===========================================================================

class ThreatGraphEngine:
    """
    Main orchestrator. Loads existing graph state, builds incremental updates,
    runs correlation engine, writes all outputs atomically.
    ZERO-FAILURE: unconditional exit(0).
    """

    def __init__(self):
        GRAPH_DIR.mkdir(parents=True, exist_ok=True)

    def _load_existing(self) -> Tuple[Dict, Dict]:
        """Load existing graph from disk for incremental merge."""
        nodes_file = GRAPH_DIR / "graph_nodes.json"
        edges_file = GRAPH_DIR / "graph_edges.json"
        existing_nodes = _safe_load_json(nodes_file, default={})
        existing_edges = _safe_load_json(edges_file, default={})
        return existing_nodes, existing_edges

    def run(self) -> Dict:
        start = time.time()
        logger.info("=" * 60)
        logger.info("THREAT GRAPH ENGINE v1.0 — Starting")
        logger.info("=" * 60)

        meta = {
            "engine": "threat_graph_engine_v1.0",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "running",
            "nodes_total": 0,
            "edges_total": 0,
            "clusters": 0,
            "high_risk_paths": 0,
            "advisories_processed": 0,
        }

        # Load existing graph state for incremental merge
        existing_nodes, existing_edges = self._load_existing()
        nodes  = NodeRegistry(existing_nodes)
        edges  = EdgeRegistry(existing_edges)
        adj    = AdjacencyIndex()

        # Rebuild adjacency from existing edges (for BFS correctness)
        for eid, edge in existing_edges.items():
            adj.add_edge(edge["source"], eid, edge["target"])

        builder = ThreatGraphBuilder(nodes, edges, adj)

        # --- Process manifest ---
        manifest_data = _safe_load_json(MANIFEST_PATH, default=[])
        items = manifest_data if isinstance(manifest_data, list) else manifest_data.get("items", [])
        logger.info(f"Processing {len(items)} manifest advisories")

        processed = 0
        for item in items:
            try:
                builder.process_advisory(item)
                processed += 1
            except Exception as e:
                logger.warning(f"Advisory processing error (non-fatal): {e}")
        logger.info(f"  Manifest processed: {processed} advisories")
        meta["advisories_processed"] = processed

        # --- Enrich from memory databases ---
        actor_mem  = _safe_load_json(ACTOR_MEM_PATH,  default={})
        camp_mem   = _safe_load_json(CAMP_MEM_PATH,   default={})

        try:
            n = builder.process_actor_memory(actor_mem)
            logger.info(f"  Actor memory enrichment: {n} entities added/merged")
        except Exception as e:
            logger.warning(f"Actor memory enrichment error (non-fatal): {e}")

        try:
            n = builder.process_campaign_memory(camp_mem)
            logger.info(f"  Campaign memory enrichment: {n} entities added/merged")
        except Exception as e:
            logger.warning(f"Campaign memory enrichment error (non-fatal): {e}")

        # --- Persist graph ---
        node_count = nodes.count()
        edge_count = edges.count()
        logger.info(f"  Graph state: {node_count} nodes, {edge_count} edges")

        _safe_write_json(GRAPH_DIR / "graph_nodes.json", nodes.to_dict(), indent=None)
        _safe_write_json(GRAPH_DIR / "graph_edges.json", edges.to_dict(), indent=None)
        _safe_write_json(GRAPH_DIR / "adjacency_index.json", adj.to_dict(), indent=None)

        # --- Correlation Engine ---
        logger.info("Running correlation engine...")
        corr = CorrelationEngine(nodes, edges, adj)

        try:
            clusters = corr.find_connected_components()
            _safe_write_json(GRAPH_DIR / "correlation_clusters.json", {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_clusters": len(clusters),
                "clusters": clusters,
            }, indent=2)
            logger.info(f"  Correlation clusters: {len(clusters)}")
            meta["clusters"] = len(clusters)
        except Exception as e:
            logger.warning(f"Cluster analysis error (non-fatal): {e}")

        try:
            paths = corr.find_high_risk_paths(top_n=25)
            _safe_write_json(GRAPH_DIR / "high_risk_paths.json", {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_paths": len(paths),
                "paths": paths,
            }, indent=2)
            logger.info(f"  High-risk paths: {len(paths)}")
            meta["high_risk_paths"] = len(paths)
        except Exception as e:
            logger.warning(f"Path analysis error (non-fatal): {e}")

        # --- Node type summary ---
        type_counts: Dict[str, int] = defaultdict(int)
        for node in nodes.all_nodes():
            type_counts[node["type"]] += 1

        elapsed = round(time.time() - start, 2)
        meta.update({
            "status": "success",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_s": elapsed,
            "nodes_total": node_count,
            "edges_total": edge_count,
            "node_type_counts": dict(type_counts),
        })
        _safe_write_json(GRAPH_DIR / "graph_meta.json", meta, indent=2)

        logger.info("=" * 60)
        logger.info(f"THREAT GRAPH ENGINE COMPLETE in {elapsed}s")
        logger.info(f"  Nodes: {node_count} | Edges: {edge_count} | "
                    f"Types: {dict(type_counts)}")
        logger.info("=" * 60)
        return meta


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> int:
    try:
        engine = ThreatGraphEngine()
        engine.run()
    except Exception as e:
        logger.error(f"Fatal threat graph error: {e}", exc_info=True)
    return 0  # ZERO-FAILURE — always exit 0


if __name__ == "__main__":
    sys.exit(main())
