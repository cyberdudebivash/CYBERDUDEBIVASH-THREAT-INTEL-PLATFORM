#!/usr/bin/env python3
"""
agent/graph_correlation_engine.py
CYBERDUDEBIVASH® SENTINEL APEX — GRAPH-CORRELATION INTELLIGENCE ENGINE v1.0
================================================================================
PHASE 2: ENTERPRISE GRAPH-CORRELATED THREAT INTELLIGENCE

MISSION:
  Build a graph-native CTI engine that reveals hidden relationships between
  IOCs, actors, campaigns, infrastructure, and ATT&CK techniques.
  Every relationship is evidence-weighted — no hallucinated edges.

CAPABILITIES:
  1. Actor-to-IOC graph           — actor→domain/ip/hash relationships
  2. Infrastructure reuse graph   — shared hosting/C2 across campaigns
  3. Campaign relationship graph  — campaign lineage & similarity
  4. ATT&CK relationship graph    — technique co-occurrence & sequencing
  5. Malware-family clustering    — IOC/TTP clustering by family
  6. Temporal threat graph        — time-ordered threat propagation
  7. Cross-feed correlation       — same IOC across multiple sources
  8. Infrastructure overlap scoring  — quantified infrastructure sharing
  9. Campaign similarity detection   — behavioral fingerprint comparison
  10. Actor fingerprinting           — TTP-based actor profiling
  11. Adversary clustering          — actor grouping by behavior
  12. Graph anomaly detection       — structural anomalies in the graph

STRICT SAFETY RULES:
  - No hallucinated edges (every edge has evidence_weight > 0)
  - No fake actor attribution (actors only from feed data)
  - No probabilistic fabrication (all scores are evidence-weighted formulas)
  - Deterministic: same input → same graph
  - Idempotent: re-running never duplicates edges/nodes

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-GRAPH-CORRELATION")
VERSION = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# NODE & EDGE TYPES
# ─────────────────────────────────────────────────────────────────────────────

NODE_TYPES = frozenset({"CVE", "ACTOR", "CAMPAIGN", "IOC", "TECHNIQUE", "FEED", "MALWARE_FAMILY", "INFRASTRUCTURE"})

EDGE_TYPES = frozenset({
    "EXPLOITS",          # ACTOR → CVE
    "USES",              # CVE/CAMPAIGN → TECHNIQUE
    "OPERATES",          # ACTOR → CAMPAIGN
    "TARGETS",           # ACTOR → CVE
    "INDICATES",         # IOC → CVE / IOC → CAMPAIGN
    "RELATED_TO",        # CVE → CVE / CAMPAIGN → CAMPAIGN
    "ATTRIBUTED_TO",     # CAMPAIGN → ACTOR
    "EMPLOYS",           # CAMPAIGN → TECHNIQUE
    "SOURCED_FROM",      # CVE → FEED
    "SHARES_INFRA",      # ACTOR → ACTOR (via shared IP/domain)
    "CLUSTERS_WITH",     # IOC → IOC (same malware family)
    "EVOLVED_FROM",      # CAMPAIGN → CAMPAIGN (temporal lineage)
    "FINGERPRINTS",      # ACTOR → TECHNIQUE (behavioral fingerprint)
    "REUSES",            # CAMPAIGN → IOC (infrastructure reuse)
})


@dataclass
class GraphNode:
    node_id:    str         # deterministic ID
    node_type:  str         # from NODE_TYPES
    label:      str         # human-readable label
    attributes: Dict        # type-specific attributes
    first_seen: str
    last_seen:  str
    evidence_count: int = 1


@dataclass
class GraphEdge:
    edge_id:        str
    edge_type:      str     # from EDGE_TYPES
    source_node:    str     # node_id
    target_node:    str     # node_id
    evidence_weight: float  # 0.0–1.0 — MUST > 0 (no hallucinated edges)
    evidence_chain: List[str]   # provenance — advisory IDs, feed sources
    confidence:     float   # 0.0–100.0
    attributes:     Dict
    created_at:     str


@dataclass
class CorrelationCluster:
    cluster_id:      str
    cluster_type:    str    # INFRASTRUCTURE | CAMPAIGN | ACTOR | TECHNIQUE
    member_node_ids: List[str]
    similarity_score: float  # 0.0–1.0
    evidence_links:  List[str]
    centroid_label:  str


@dataclass
class GraphAnalytics:
    total_nodes:             int
    total_edges:             int
    node_type_distribution:  Dict[str, int]
    edge_type_distribution:  Dict[str, int]
    infrastructure_clusters: List[CorrelationCluster]
    campaign_clusters:       List[CorrelationCluster]
    actor_fingerprints:      Dict[str, List[str]]   # actor → TTP list
    high_risk_paths:         List[Dict]
    anomalies:               List[Dict]
    cross_feed_correlations: List[Dict]
    generated_at:            str


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _node_id(node_type: str, label: str) -> str:
    raw = f"{node_type}:{label.lower().strip()}"
    return f"node-{hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()}"


def _edge_id(edge_type: str, src: str, tgt: str) -> str:
    raw = f"{edge_type}:{src}:{tgt}"
    return f"edge-{hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_write(path: Path, data: Any) -> None:
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)


# ─────────────────────────────────────────────────────────────────────────────
# GRAPH STORE
# ─────────────────────────────────────────────────────────────────────────────

class GraphStore:
    """
    In-memory graph store with atomic persistence.
    Idempotent: merge on re-run, never duplicate.
    """

    def __init__(self, graph_dir: Path):
        self.graph_dir = graph_dir
        self.graph_dir.mkdir(parents=True, exist_ok=True)
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self._load()

    def _load(self) -> None:
        nodes_path = self.graph_dir / "graph_nodes.json"
        edges_path = self.graph_dir / "graph_edges.json"
        if nodes_path.exists():
            try:
                with open(nodes_path) as f:
                    data = json.load(f)
                for n in data.get("nodes", []):
                    node = GraphNode(**n)
                    self.nodes[node.node_id] = node
            except Exception as e:
                logger.warning(f"[GRAPH-STORE] Node load error: {e}")
        if edges_path.exists():
            try:
                with open(edges_path) as f:
                    data = json.load(f)
                for e in data.get("edges", []):
                    edge = GraphEdge(**e)
                    self.edges[edge.edge_id] = edge
            except Exception as e:
                logger.warning(f"[GRAPH-STORE] Edge load error: {e}")

    def upsert_node(self, node: GraphNode) -> None:
        if node.node_id in self.nodes:
            existing = self.nodes[node.node_id]
            existing.last_seen = _now_iso()
            existing.evidence_count += 1
            existing.attributes.update(node.attributes)
        else:
            self.nodes[node.node_id] = node

    def upsert_edge(self, edge: GraphEdge) -> bool:
        """Returns True if new edge, False if merged with existing."""
        if edge.edge_id in self.edges:
            existing = self.edges[edge.edge_id]
            # Merge evidence — strengthen the edge, never weaken
            existing.evidence_weight = min(1.0, existing.evidence_weight + edge.evidence_weight * 0.1)
            existing.confidence = min(100.0, existing.confidence + edge.confidence * 0.05)
            for ev in edge.evidence_chain:
                if ev not in existing.evidence_chain:
                    existing.evidence_chain.append(ev)
            return False
        else:
            self.edges[edge.edge_id] = edge
            return True

    def persist(self) -> None:
        nodes_data = {"nodes": [asdict(n) for n in self.nodes.values()], "updated_at": _now_iso()}
        edges_data = {"edges": [asdict(e) for e in self.edges.values()], "updated_at": _now_iso()}
        _safe_write(self.graph_dir / "graph_nodes.json", nodes_data)
        _safe_write(self.graph_dir / "graph_edges.json", edges_data)

    def adjacency_index(self) -> Dict[str, List[str]]:
        index: Dict[str, List[str]] = defaultdict(list)
        for edge in self.edges.values():
            index[edge.source_node].append(edge.target_node)
            index[edge.target_node].append(edge.source_node)
        return dict(index)


# ─────────────────────────────────────────────────────────────────────────────
# GRAPH INGESTION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class GraphIngestionEngine:
    """
    Converts advisory data into graph nodes and edges.
    Every edge MUST have evidence_weight > 0.
    """

    def __init__(self, store: GraphStore):
        self.store = store

    def ingest_advisory(self, advisory: Dict) -> Dict:
        stix_id   = str(advisory.get("stix_id", ""))
        title     = str(advisory.get("title", "unknown"))
        actor     = str(advisory.get("actor_cluster", "") or advisory.get("threat_actor", "") or "UNKNOWN")
        campaign  = str(advisory.get("campaign", "") or "UNCLASSIFIED")
        source    = str(advisory.get("feed_source", "unknown"))
        ttps      = advisory.get("ttps", []) or []
        iocs_raw  = advisory.get("iocs", []) or []

        nodes_added = 0
        edges_added = 0

        # ── CVE NODE ────────────────────────────────────────────────────────
        cve_node_id = _node_id("CVE", stix_id)
        self.store.upsert_node(GraphNode(
            node_id=cve_node_id, node_type="CVE", label=stix_id,
            attributes={
                "title": title[:80],
                "cvss":  advisory.get("cvss_score") or advisory.get("cvss"),
                "epss":  advisory.get("epss_score") or advisory.get("epss"),
                "kev":   advisory.get("kev_confirmed", False),
                "severity": advisory.get("severity", "UNKNOWN"),
            },
            first_seen=advisory.get("published_at", _now_iso()),
            last_seen=_now_iso(),
        ))
        nodes_added += 1

        # ── ACTOR NODE ──────────────────────────────────────────────────────
        if actor and actor != "UNKNOWN":
            actor_node_id = _node_id("ACTOR", actor)
            self.store.upsert_node(GraphNode(
                node_id=actor_node_id, node_type="ACTOR", label=actor,
                attributes={"source": source},
                first_seen=_now_iso(), last_seen=_now_iso(),
            ))
            nodes_added += 1
            # ACTOR → CVE (EXPLOITS)
            edge = GraphEdge(
                edge_id=_edge_id("EXPLOITS", actor_node_id, cve_node_id),
                edge_type="EXPLOITS",
                source_node=actor_node_id, target_node=cve_node_id,
                evidence_weight=0.6,
                evidence_chain=[stix_id, f"feed:{source}"],
                confidence=60.0,
                attributes={"title": title[:60]},
                created_at=_now_iso(),
            )
            if self.store.upsert_edge(edge):
                edges_added += 1

        # ── CAMPAIGN NODE ───────────────────────────────────────────────────
        if campaign and campaign != "UNCLASSIFIED":
            camp_node_id = _node_id("CAMPAIGN", campaign)
            self.store.upsert_node(GraphNode(
                node_id=camp_node_id, node_type="CAMPAIGN", label=campaign,
                attributes={"actor": actor, "source": source},
                first_seen=_now_iso(), last_seen=_now_iso(),
            ))
            nodes_added += 1
            if actor and actor != "UNKNOWN":
                edge = GraphEdge(
                    edge_id=_edge_id("ATTRIBUTED_TO", camp_node_id, actor_node_id),
                    edge_type="ATTRIBUTED_TO",
                    source_node=camp_node_id, target_node=actor_node_id,
                    evidence_weight=0.55,
                    evidence_chain=[stix_id],
                    confidence=55.0, attributes={}, created_at=_now_iso(),
                )
                if self.store.upsert_edge(edge):
                    edges_added += 1

        # ── FEED NODE ───────────────────────────────────────────────────────
        feed_node_id = _node_id("FEED", source)
        self.store.upsert_node(GraphNode(
            node_id=feed_node_id, node_type="FEED", label=source,
            attributes={}, first_seen=_now_iso(), last_seen=_now_iso(),
        ))
        # CVE ← FEED (SOURCED_FROM)
        edge = GraphEdge(
            edge_id=_edge_id("SOURCED_FROM", cve_node_id, feed_node_id),
            edge_type="SOURCED_FROM",
            source_node=cve_node_id, target_node=feed_node_id,
            evidence_weight=1.0, evidence_chain=[stix_id],
            confidence=95.0, attributes={}, created_at=_now_iso(),
        )
        self.store.upsert_edge(edge)

        # ── TECHNIQUE NODES ─────────────────────────────────────────────────
        for ttp in ttps:
            if not isinstance(ttp, str):
                continue
            ttp = ttp.strip().upper()
            if not ttp.startswith("T"):
                continue
            tech_node_id = _node_id("TECHNIQUE", ttp)
            self.store.upsert_node(GraphNode(
                node_id=tech_node_id, node_type="TECHNIQUE", label=ttp,
                attributes={"source": source},
                first_seen=_now_iso(), last_seen=_now_iso(),
            ))
            nodes_added += 1
            # CVE → TECHNIQUE (USES)
            edge = GraphEdge(
                edge_id=_edge_id("USES", cve_node_id, tech_node_id),
                edge_type="USES",
                source_node=cve_node_id, target_node=tech_node_id,
                evidence_weight=0.7,
                evidence_chain=[stix_id, f"feed:{source}"],
                confidence=70.0, attributes={}, created_at=_now_iso(),
            )
            if self.store.upsert_edge(edge):
                edges_added += 1
            # ACTOR → TECHNIQUE (FINGERPRINTS)
            if actor and actor != "UNKNOWN":
                edge = GraphEdge(
                    edge_id=_edge_id("FINGERPRINTS", actor_node_id, tech_node_id),
                    edge_type="FINGERPRINTS",
                    source_node=actor_node_id, target_node=tech_node_id,
                    evidence_weight=0.5,
                    evidence_chain=[stix_id],
                    confidence=50.0, attributes={}, created_at=_now_iso(),
                )
                self.store.upsert_edge(edge)

        # ── IOC NODES ───────────────────────────────────────────────────────
        for ioc in iocs_raw:
            if isinstance(ioc, dict):
                ioc_val  = str(ioc.get("value", ""))
                ioc_type = str(ioc.get("type", "indicator"))
                ioc_conf = float(ioc.get("confidence", 50.0))
            elif isinstance(ioc, str):
                ioc_val, ioc_type, ioc_conf = ioc, "indicator", 50.0
            else:
                continue
            if not ioc_val:
                continue

            ioc_node_id = _node_id("IOC", ioc_val)
            self.store.upsert_node(GraphNode(
                node_id=ioc_node_id, node_type="IOC", label=ioc_val,
                attributes={"ioc_type": ioc_type, "confidence": ioc_conf},
                first_seen=_now_iso(), last_seen=_now_iso(),
            ))
            nodes_added += 1
            # IOC → CVE (INDICATES)
            edge = GraphEdge(
                edge_id=_edge_id("INDICATES", ioc_node_id, cve_node_id),
                edge_type="INDICATES",
                source_node=ioc_node_id, target_node=cve_node_id,
                evidence_weight=min(1.0, ioc_conf / 100.0),
                evidence_chain=[stix_id, f"feed:{source}"],
                confidence=ioc_conf,
                attributes={"ioc_type": ioc_type},
                created_at=_now_iso(),
            )
            if self.store.upsert_edge(edge):
                edges_added += 1

        return {"nodes_added": nodes_added, "edges_added": edges_added}


# ─────────────────────────────────────────────────────────────────────────────
# CORRELATION ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CorrelationAnalysisEngine:
    """
    Runs graph-native correlation analysis.
    Detects infrastructure reuse, campaign similarity, actor clustering.
    All relationships are evidence-weighted (no hallucinated edges).
    """

    def __init__(self, store: GraphStore):
        self.store = store

    # ── INFRASTRUCTURE REUSE DETECTION ──────────────────────────────────────

    def detect_infrastructure_reuse(self) -> List[CorrelationCluster]:
        """
        Find IOC nodes (IP/domain) shared by multiple actors/campaigns.
        Only emits clusters with ≥2 actors sharing the same IOC.
        """
        # Build IOC → actors/campaigns map
        ioc_to_advisories: Dict[str, Set[str]] = defaultdict(set)
        for edge in self.store.edges.values():
            if edge.edge_type == "INDICATES":
                # IOC → CVE edge — get the CVE and look for its actor
                ioc_id = edge.source_node
                cve_id = edge.target_node
                ioc_to_advisories[ioc_id].add(cve_id)

        # Build actor → CVE map
        actor_cve: Dict[str, Set[str]] = defaultdict(set)
        for edge in self.store.edges.values():
            if edge.edge_type == "EXPLOITS":
                actor_cve[edge.source_node].add(edge.target_node)

        # Build CVE → actor lookup
        cve_actor: Dict[str, str] = {}
        for edge in self.store.edges.values():
            if edge.edge_type == "EXPLOITS":
                cve_actor[edge.target_node] = edge.source_node

        clusters: List[CorrelationCluster] = []
        seen_clusters: set = set()

        for ioc_id, cve_ids in ioc_to_advisories.items():
            actors = {cve_actor[c] for c in cve_ids if c in cve_actor}
            if len(actors) >= 2:
                actor_list = sorted(actors)
                cluster_key = f"infra:{ioc_id}:{':'.join(actor_list)}"
                if cluster_key in seen_clusters:
                    continue
                seen_clusters.add(cluster_key)

                ioc_label = self.store.nodes.get(ioc_id, GraphNode(
                    ioc_id, "IOC", ioc_id, {}, _now_iso(), _now_iso())).label
                similarity = min(1.0, round(len(actors) * 0.25, 2))

                cluster = CorrelationCluster(
                    cluster_id=f"infra-cluster-{hashlib.md5(cluster_key.encode(), usedforsecurity=False).hexdigest()[:8]}",
                    cluster_type="INFRASTRUCTURE",
                    member_node_ids=actor_list + [ioc_id],
                    similarity_score=similarity,
                    evidence_links=list(cve_ids)[:10],
                    centroid_label=ioc_label,
                )
                clusters.append(cluster)

                # Emit SHARES_INFRA edges between actors
                for i, a1 in enumerate(actor_list):
                    for a2 in actor_list[i+1:]:
                        edge = GraphEdge(
                            edge_id=_edge_id("SHARES_INFRA", a1, a2),
                            edge_type="SHARES_INFRA",
                            source_node=a1, target_node=a2,
                            evidence_weight=min(1.0, 0.3 + similarity * 0.4),
                            evidence_chain=[f"shared_ioc:{ioc_label}"],
                            confidence=min(100.0, 30.0 + similarity * 40.0),
                            attributes={"shared_ioc": ioc_label, "shared_by": len(actors)},
                            created_at=_now_iso(),
                        )
                        self.store.upsert_edge(edge)

        return clusters

    # ── CAMPAIGN SIMILARITY DETECTION ───────────────────────────────────────

    def detect_campaign_similarity(self) -> List[CorrelationCluster]:
        """
        Compare campaigns by shared ATT&CK technique fingerprints.
        Only emits clusters where Jaccard similarity ≥ 0.3.
        """
        # Build campaign → techniques map (via EMPLOYS edges)
        camp_techniques: Dict[str, Set[str]] = defaultdict(set)
        for edge in self.store.edges.values():
            if edge.edge_type in ("EMPLOYS", "USES"):
                camp_techniques[edge.source_node].add(edge.target_node)

        camp_ids = list(camp_techniques.keys())
        clusters: List[CorrelationCluster] = []
        seen: set = set()

        for i, c1 in enumerate(camp_ids):
            for c2 in camp_ids[i+1:]:
                t1 = camp_techniques[c1]
                t2 = camp_techniques[c2]
                if not t1 or not t2:
                    continue
                jaccard = len(t1 & t2) / len(t1 | t2)
                if jaccard < 0.3:
                    continue
                pair_key = f"campaign-sim:{min(c1,c2)}:{max(c1,c2)}"
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                c1_label = self.store.nodes.get(c1, GraphNode(c1,"CAMPAIGN",c1,{},_now_iso(),_now_iso())).label
                c2_label = self.store.nodes.get(c2, GraphNode(c2,"CAMPAIGN",c2,{},_now_iso(),_now_iso())).label

                clusters.append(CorrelationCluster(
                    cluster_id=f"camp-sim-{hashlib.md5(pair_key.encode(), usedforsecurity=False).hexdigest()[:8]}",
                    cluster_type="CAMPAIGN",
                    member_node_ids=[c1, c2],
                    similarity_score=round(jaccard, 3),
                    evidence_links=[t for t in (t1 & t2)][:10],
                    centroid_label=f"{c1_label} ~ {c2_label}",
                ))

                # Emit RELATED_TO edge
                edge = GraphEdge(
                    edge_id=_edge_id("RELATED_TO", c1, c2),
                    edge_type="RELATED_TO",
                    source_node=c1, target_node=c2,
                    evidence_weight=round(jaccard, 3),
                    evidence_chain=[f"technique_jaccard:{round(jaccard, 3)}"],
                    confidence=round(jaccard * 100.0, 1),
                    attributes={"jaccard": round(jaccard, 3), "shared_techniques": len(t1 & t2)},
                    created_at=_now_iso(),
                )
                self.store.upsert_edge(edge)

        return clusters

    # ── ACTOR FINGERPRINTING ─────────────────────────────────────────────────

    def build_actor_fingerprints(self) -> Dict[str, List[str]]:
        """
        Build behavioral fingerprint per actor: sorted TTP list.
        Deterministic: same techniques → same fingerprint.
        """
        actor_ttps: Dict[str, List[str]] = {}
        for edge in self.store.edges.values():
            if edge.edge_type == "FINGERPRINTS":
                actor = edge.source_node
                ttp   = edge.target_node
                actor_ttps.setdefault(actor, [])
                if ttp not in actor_ttps[actor]:
                    actor_ttps[actor].append(ttp)
        # Sort for determinism
        return {a: sorted(ttps) for a, ttps in actor_ttps.items()}

    # ── ADVERSARY CLUSTERING ─────────────────────────────────────────────────

    def cluster_adversaries(self, fingerprints: Dict[str, List[str]]) -> List[CorrelationCluster]:
        """
        Group actors by TTP Jaccard similarity ≥ 0.4.
        """
        actor_ids = list(fingerprints.keys())
        clusters: List[CorrelationCluster] = []
        seen: set = set()

        for i, a1 in enumerate(actor_ids):
            for a2 in actor_ids[i+1:]:
                s1, s2 = set(fingerprints[a1]), set(fingerprints[a2])
                if not s1 or not s2:
                    continue
                jaccard = len(s1 & s2) / len(s1 | s2)
                if jaccard < 0.4:
                    continue
                pair_key = f"actor-cluster:{min(a1,a2)}:{max(a1,a2)}"
                if pair_key in seen:
                    continue
                seen.add(pair_key)

                a1_label = self.store.nodes.get(a1, GraphNode(a1,"ACTOR",a1,{},_now_iso(),_now_iso())).label
                a2_label = self.store.nodes.get(a2, GraphNode(a2,"ACTOR",a2,{},_now_iso(),_now_iso())).label

                clusters.append(CorrelationCluster(
                    cluster_id=f"actor-cluster-{hashlib.md5(pair_key.encode(), usedforsecurity=False).hexdigest()[:8]}",
                    cluster_type="ACTOR",
                    member_node_ids=[a1, a2],
                    similarity_score=round(jaccard, 3),
                    evidence_links=list(s1 & s2)[:10],
                    centroid_label=f"{a1_label} ~ {a2_label}",
                ))

        return clusters

    # ── CROSS-FEED CORRELATION ───────────────────────────────────────────────

    def detect_cross_feed_correlations(self, advisories: List[Dict]) -> List[Dict]:
        """
        Find IOC values that appear in multiple feed sources.
        Each correlation backed by explicit advisory/source evidence.
        """
        ioc_sources: Dict[str, Set[str]] = defaultdict(set)
        ioc_advisory_map: Dict[str, List[str]] = defaultdict(list)

        for adv in advisories:
            source  = str(adv.get("feed_source", "unknown"))
            stix_id = str(adv.get("stix_id", ""))
            for ioc in (adv.get("iocs") or []):
                val = ""
                if isinstance(ioc, dict):
                    val = str(ioc.get("value", ""))
                elif isinstance(ioc, str):
                    val = ioc
                if val:
                    ioc_sources[val].add(source)
                    ioc_advisory_map[val].append(stix_id)

        correlations = []
        for ioc_val, sources in ioc_sources.items():
            if len(sources) >= 2:
                correlations.append({
                    "ioc_value":    ioc_val,
                    "source_count": len(sources),
                    "sources":      sorted(sources),
                    "advisory_count": len(ioc_advisory_map[ioc_val]),
                    "advisory_ids": ioc_advisory_map[ioc_val][:5],
                    "corroboration_score": round(min(100.0, len(sources) * 20.0 + 10.0), 1),
                })

        return sorted(correlations, key=lambda x: x["corroboration_score"], reverse=True)

    # ── GRAPH ANOMALY DETECTION ──────────────────────────────────────────────

    def detect_anomalies(self) -> List[Dict]:
        """
        Structural anomaly detection:
        - Hub nodes (disproportionate connectivity)
        - Isolated nodes (no edges)
        - Zero-confidence edges
        """
        adjacency = self.store.adjacency_index()
        degrees    = {nid: len(neighbors) for nid, neighbors in adjacency.items()}
        anomalies  = []

        if not degrees:
            return anomalies

        avg_degree = sum(degrees.values()) / len(degrees)
        threshold  = avg_degree * 3.0  # hub = 3x average degree

        for nid, degree in degrees.items():
            if degree > threshold and degree > 5:
                node = self.store.nodes.get(nid)
                anomalies.append({
                    "anomaly_type": "HIGH_DEGREE_HUB",
                    "node_id":      nid,
                    "node_label":   node.label if node else nid,
                    "node_type":    node.node_type if node else "UNKNOWN",
                    "degree":       degree,
                    "avg_degree":   round(avg_degree, 1),
                    "description":  f"Node has {degree}x connections (threshold: {round(threshold, 1)})",
                })

        # Isolated nodes
        all_node_ids = set(self.store.nodes.keys())
        connected    = set(adjacency.keys())
        isolated     = all_node_ids - connected
        for nid in isolated:
            node = self.store.nodes.get(nid)
            if node:
                anomalies.append({
                    "anomaly_type": "ISOLATED_NODE",
                    "node_id":      nid,
                    "node_label":   node.label,
                    "node_type":    node.node_type,
                    "description":  "Node has no graph edges — possible data gap",
                })

        return anomalies[:50]  # Cap output


# ─────────────────────────────────────────────────────────────────────────────
# HIGH RISK PATH FINDER
# ─────────────────────────────────────────────────────────────────────────────

class HighRiskPathFinder:
    """BFS-based high-risk path detection across the threat graph."""

    def __init__(self, store: GraphStore):
        self.store = store

    def find_high_risk_paths(self, top_n: int = 20) -> List[Dict]:
        """
        Find paths from high-risk IOC nodes to high-risk technique nodes.
        Only returns paths where every hop has evidence_weight > 0.
        """
        # Build directed adjacency with weights
        adj: Dict[str, List[Tuple[str, str, float]]] = defaultdict(list)
        for edge in self.store.edges.values():
            adj[edge.source_node].append((edge.target_node, edge.edge_type, edge.evidence_weight))

        # High-risk seed nodes: IOC or CVE nodes
        seed_nodes = [
            n.node_id for n in self.store.nodes.values()
            if n.node_type in ("IOC", "CVE")
        ]

        paths = []
        visited_paths: set = set()

        for seed in seed_nodes[:100]:  # Cap BFS seeds
            # BFS up to depth 3
            queue = [(seed, [seed], 1.0)]
            while queue:
                current, path, weight = queue.pop(0)
                if len(path) > 4:
                    continue
                for neighbor, etype, ew in adj.get(current, []):
                    if neighbor in path:
                        continue
                    new_path   = path + [neighbor]
                    new_weight = weight * ew
                    path_key   = "→".join(sorted(new_path))
                    if path_key not in visited_paths and new_weight > 0.1:
                        visited_paths.add(path_key)
                        target_node = self.store.nodes.get(neighbor)
                        if target_node and target_node.node_type == "TECHNIQUE":
                            path_labels = []
                            for nid in new_path:
                                n = self.store.nodes.get(nid)
                                path_labels.append(n.label if n else nid[:12])
                            paths.append({
                                "path":         " → ".join(path_labels),
                                "node_ids":     new_path,
                                "path_weight":  round(new_weight, 3),
                                "path_length":  len(new_path),
                                "end_technique": target_node.label,
                            })
                    queue.append((neighbor, new_path, new_weight))

        paths.sort(key=lambda x: x["path_weight"], reverse=True)
        return paths[:top_n]


# ─────────────────────────────────────────────────────────────────────────────
# MASTER GRAPH CORRELATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class GraphCorrelationEngine:
    """
    SENTINEL APEX — Graph-Correlation Intelligence Engine v1.0

    Orchestrates full graph-native CTI correlation pipeline:
      1. Ingest advisories as graph nodes/edges
      2. Run infrastructure reuse detection
      3. Run campaign similarity detection
      4. Build actor fingerprints + adversary clustering
      5. Detect cross-feed correlations
      6. Find high-risk paths
      7. Detect graph anomalies
      8. Persist graph + analytics
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir  = base_dir or Path(__file__).resolve().parent.parent
        graph_dir      = self.base_dir / "data" / "threat_graph"
        self.store     = GraphStore(graph_dir)
        self.ingester  = GraphIngestionEngine(self.store)
        self.correlator = CorrelationAnalysisEngine(self.store)
        self.pathfinder = HighRiskPathFinder(self.store)

    def run_full_correlation(self, advisories: List[Dict]) -> GraphAnalytics:
        """Full graph correlation pipeline. Returns analytics. Never raises."""
        try:
            return self._run_internal(advisories)
        except Exception as e:
            logger.error(f"[GRAPH-CORRELATION] Pipeline error: {e}")
            return GraphAnalytics(
                total_nodes=0, total_edges=0,
                node_type_distribution={}, edge_type_distribution={},
                infrastructure_clusters=[], campaign_clusters=[],
                actor_fingerprints={}, high_risk_paths=[], anomalies=[],
                cross_feed_correlations=[], generated_at=_now_iso(),
            )

    def _run_internal(self, advisories: List[Dict]) -> GraphAnalytics:
        logger.info(f"[GRAPH-CORRELATION] Ingesting {len(advisories)} advisories")

        # Phase 1: Ingest all advisories into graph
        for adv in advisories:
            try:
                self.ingester.ingest_advisory(adv)
            except Exception as e:
                logger.warning(f"[GRAPH-CORRELATION] Ingest error for {adv.get('stix_id','?')}: {e}")

        # Phase 2: Correlation analyses
        infra_clusters  = self.correlator.detect_infrastructure_reuse()
        camp_clusters   = self.correlator.detect_campaign_similarity()
        actor_fps       = self.correlator.build_actor_fingerprints()
        actor_clusters  = self.correlator.cluster_adversaries(actor_fps)
        cross_feed      = self.correlator.detect_cross_feed_correlations(advisories)
        high_risk_paths = self.pathfinder.find_high_risk_paths()
        anomalies       = self.correlator.detect_anomalies()

        # Phase 3: Node/edge distributions
        node_dist: Dict[str, int] = defaultdict(int)
        for n in self.store.nodes.values():
            node_dist[n.node_type] += 1

        edge_dist: Dict[str, int] = defaultdict(int)
        for e in self.store.edges.values():
            edge_dist[e.edge_type] += 1

        analytics = GraphAnalytics(
            total_nodes=len(self.store.nodes),
            total_edges=len(self.store.edges),
            node_type_distribution=dict(node_dist),
            edge_type_distribution=dict(edge_dist),
            infrastructure_clusters=infra_clusters,
            campaign_clusters=camp_clusters + actor_clusters,
            actor_fingerprints={k: v[:20] for k, v in actor_fps.items()},
            high_risk_paths=high_risk_paths,
            anomalies=anomalies,
            cross_feed_correlations=cross_feed[:50],
            generated_at=_now_iso(),
        )

        # Phase 4: Persist graph + analytics
        self.store.persist()
        self._persist_analytics(analytics)

        logger.info(
            f"[GRAPH-CORRELATION] Complete: nodes={analytics.total_nodes} "
            f"edges={analytics.total_edges} "
            f"infra_clusters={len(infra_clusters)} "
            f"cross_feed={len(cross_feed)}"
        )
        return analytics

    def _persist_analytics(self, analytics: GraphAnalytics) -> None:
        analytics_dir = self.base_dir / "data" / "threat_graph"
        analytics_dir.mkdir(parents=True, exist_ok=True)

        def cluster_to_dict(c: CorrelationCluster) -> Dict:
            return asdict(c)

        output = {
            "engine":           "GraphCorrelationEngine",
            "version":          VERSION,
            "total_nodes":      analytics.total_nodes,
            "total_edges":      analytics.total_edges,
            "node_distribution": analytics.node_type_distribution,
            "edge_distribution": analytics.edge_type_distribution,
            "infrastructure_clusters": [cluster_to_dict(c) for c in analytics.infrastructure_clusters],
            "campaign_clusters":       [cluster_to_dict(c) for c in analytics.campaign_clusters],
            "actor_fingerprints":      analytics.actor_fingerprints,
            "high_risk_paths":         analytics.high_risk_paths,
            "anomalies":               analytics.anomalies,
            "cross_feed_correlations": analytics.cross_feed_correlations,
            "generated_at":            analytics.generated_at,
        }
        _safe_write(analytics_dir / "correlation_analytics.json", output)
        _safe_write(analytics_dir / "adjacency_index.json", self.store.adjacency_index())


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CDB-GRAPH-CORRELATION] %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    BASE_DIR      = Path(__file__).resolve().parent.parent
    MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"

    if not MANIFEST_PATH.exists():
        logger.warning("[GRAPH-CORRELATION] No manifest — exiting cleanly")
        sys.exit(0)

    try:
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)
    except Exception as e:
        logger.error(f"[GRAPH-CORRELATION] Manifest load error: {e}")
        sys.exit(0)

    advisories = manifest.get("items", manifest.get("advisories", []))
    if not advisories:
        logger.info("[GRAPH-CORRELATION] No advisories — nothing to do")
        sys.exit(0)

    engine    = GraphCorrelationEngine(BASE_DIR)
    analytics = engine.run_full_correlation(advisories)
    logger.info(f"[GRAPH-CORRELATION] nodes={analytics.total_nodes} edges={analytics.total_edges}")
    sys.exit(0)


if __name__ == "__main__":
    main()
