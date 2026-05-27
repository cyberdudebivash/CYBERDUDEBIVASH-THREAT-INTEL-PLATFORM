"""
CYBERDUDEBIVASH® SENTINEL APEX — Phase 52
Graph Operations Center Engine
Live attack-path exploration, infrastructure pivots, temporal campaign playback,
graph-native SOC workflows, adversary infrastructure timelines, malware lineage,
ATT&CK sequence reconstruction, graph anomaly analytics, graph confidence scoring.
Production-grade. Graph-native. Replay-backed. Analyst-usable.
"""

import json
import uuid
import statistics
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from collections import defaultdict, deque


# ─── Enumerations ─────────────────────────────────────────────────────────────

class NodeType(Enum):
    HOST            = "host"
    PROCESS         = "process"
    USER            = "user"
    FILE            = "file"
    NETWORK_CONN    = "network_connection"
    DOMAIN          = "domain"
    IP_ADDRESS      = "ip_address"
    REGISTRY_KEY    = "registry_key"
    TECHNIQUE       = "technique"
    ACTOR           = "actor"
    MALWARE         = "malware"
    C2_SERVER       = "c2_server"
    VULNERABILITY   = "vulnerability"
    CAMPAIGN        = "campaign"

class EdgeType(Enum):
    EXECUTED        = "executed"
    CONNECTED_TO    = "connected_to"
    WROTE           = "wrote"
    READ            = "read"
    SPAWNED         = "spawned"
    INJECTED_INTO   = "injected_into"
    RESOLVED_TO     = "resolved_to"
    ASSOCIATED_WITH = "associated_with"
    USED            = "used"
    ATTRIBUTED_TO   = "attributed_to"
    COMMUNICATES    = "communicates"
    MODIFIED        = "modified"
    PIVOTED_TO      = "pivoted_to"
    SHARES_INFRA    = "shares_infrastructure"
    TEMPORAL_NEXT   = "temporal_next"

class ConfidenceLevel(Enum):
    CONFIRMED   = "confirmed"     # 90–100%
    HIGH        = "high"          # 75–89%
    MEDIUM      = "medium"        # 50–74%
    LOW         = "low"           # 25–49%
    SPECULATIVE = "speculative"   # 0–24%

class AnomalyType(Enum):
    UNUSUAL_LATERAL_MOVEMENT    = "unusual_lateral_movement"
    BEACONING_PATTERN           = "beaconing_pattern"
    EXFILTRATION_PATH           = "exfiltration_path"
    PRIVILEGE_ESCALATION_CHAIN  = "privilege_escalation_chain"
    PERSISTENCE_CLUSTER         = "persistence_cluster"
    GRAPH_DENSITY_SPIKE         = "graph_density_spike"
    NEW_INFRASTRUCTURE_PIVOT    = "new_infrastructure_pivot"
    TEMPORAL_ANOMALY            = "temporal_anomaly"


# ─── Core Graph Primitives ────────────────────────────────────────────────────

@dataclass
class GraphNode:
    node_id:        str
    node_type:      NodeType
    label:          str
    properties:     dict                    = field(default_factory=dict)
    first_seen:     str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen:      str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence:     float                   = 1.0
    telemetry_refs: list[str]               = field(default_factory=list)
    attck_refs:     list[str]               = field(default_factory=list)
    risk_score:     float                   = 0.0

    @property
    def confidence_level(self) -> ConfidenceLevel:
        if   self.confidence >= 0.90: return ConfidenceLevel.CONFIRMED
        elif self.confidence >= 0.75: return ConfidenceLevel.HIGH
        elif self.confidence >= 0.50: return ConfidenceLevel.MEDIUM
        elif self.confidence >= 0.25: return ConfidenceLevel.LOW
        else:                          return ConfidenceLevel.SPECULATIVE


@dataclass
class GraphEdge:
    edge_id:        str
    src_id:         str
    dst_id:         str
    edge_type:      EdgeType
    timestamp:      str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence:     float                   = 1.0
    weight:         float                   = 1.0
    properties:     dict                    = field(default_factory=dict)
    telemetry_refs: list[str]               = field(default_factory=list)
    attck_refs:     list[str]               = field(default_factory=list)
    replay_validated: bool                  = False


@dataclass
class AttackPath:
    path_id:        str
    nodes:          list[str]               # ordered node_ids
    edges:          list[str]               # ordered edge_ids
    technique_ids:  list[str]
    origin_node:    str
    target_node:    str
    path_confidence:float                   = 0.0
    risk_score:     float                   = 0.0
    replay_validated: bool                  = False
    discovered_at:  str                     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    campaign_id:    Optional[str]           = None

    @property
    def path_length(self) -> int:
        return len(self.nodes)


@dataclass
class InfrastructurePivot:
    pivot_id:       str
    actor_id:       str
    src_infra:      str                     # IP / domain / ASN
    dst_infra:      str
    pivot_type:     str                     # "domain_reuse" / "ip_rotation" / "asn_pivot" / "hosting_pivot"
    timestamp:      str
    confidence:     float
    evidence_refs:  list[str]               = field(default_factory=list)
    techniques:     list[str]               = field(default_factory=list)
    campaign_id:    Optional[str]           = None


@dataclass
class CampaignTimeline:
    campaign_id:    str
    campaign_name:  str
    actor_id:       str
    events:         list[dict]              = field(default_factory=list)   # {timestamp, node_id, edge_id, description}
    start_time:     str                     = ""
    end_time:       str                     = ""
    duration_hours: float                   = 0.0
    techniques:     list[str]               = field(default_factory=list)
    confidence:     float                   = 0.0

    def add_event(self, timestamp: str, node_id: str, edge_id: str, description: str):
        self.events.append({
            "timestamp":    timestamp,
            "node_id":      node_id,
            "edge_id":      edge_id,
            "description":  description,
            "sequence":     len(self.events) + 1,
        })
        if not self.start_time or timestamp < self.start_time:
            self.start_time = timestamp
        if not self.end_time or timestamp > self.end_time:
            self.end_time = timestamp

    @property
    def event_count(self) -> int:
        return len(self.events)


@dataclass
class GraphAnomaly:
    anomaly_id:     str
    anomaly_type:   AnomalyType
    affected_nodes: list[str]
    severity:       float               # 0–10
    confidence:     float               # 0–1
    description:    str
    evidence:       list[str]           = field(default_factory=list)
    detected_at:    str                 = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    suppressed:     bool                = False

    @property
    def risk_priority(self) -> str:
        if self.severity >= 8:   return "CRITICAL"
        elif self.severity >= 6: return "HIGH"
        elif self.severity >= 4: return "MEDIUM"
        else:                    return "LOW"


@dataclass
class MalwareLineage:
    lineage_id:     str
    root_sample:    str
    family:         str
    variants:       list[dict]          = field(default_factory=list)   # {hash, timestamp, mutations}
    shared_code:    list[str]           = field(default_factory=list)   # shared function hashes
    campaign_refs:  list[str]           = field(default_factory=list)
    actor_refs:     list[str]           = field(default_factory=list)
    attck_coverage: list[str]           = field(default_factory=list)
    lineage_depth:  int                 = 0
    confidence:     float               = 0.0
    created_at:     str                 = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ─── Graph Operations Center Engine ───────────────────────────────────────────

class GraphOperationsEngine:
    """
    Phase 52 — Graph Operations Center Engine.
    Live attack-path exploration, infrastructure pivot tracking,
    temporal campaign playback, adversary graph analytics,
    malware lineage graphing, ATT&CK sequence reconstruction,
    graph anomaly detection, confidence scoring.
    """

    def __init__(self):
        self._nodes:        dict[str, GraphNode]        = {}
        self._edges:        dict[str, GraphEdge]        = {}
        self._adj:          dict[str, list[str]]        = defaultdict(list)  # src -> [edge_ids]
        self._rev_adj:      dict[str, list[str]]        = defaultdict(list)  # dst -> [edge_ids]
        self._attack_paths: dict[str, AttackPath]       = {}
        self._pivots:       list[InfrastructurePivot]   = []
        self._campaigns:    dict[str, CampaignTimeline] = {}
        self._anomalies:    list[GraphAnomaly]          = []
        self._lineages:     list[MalwareLineage]        = []
        self._initialized   = datetime.now(timezone.utc).isoformat()

    # ── Graph Primitive Operations ─────────────────────────────────────────

    def add_node(self, node: GraphNode) -> str:
        self._nodes[node.node_id] = node
        return node.node_id

    def add_edge(self, edge: GraphEdge) -> str:
        if edge.src_id not in self._nodes or edge.dst_id not in self._nodes:
            raise ValueError(f"Edge references unknown node(s): {edge.src_id} → {edge.dst_id}")
        self._edges[edge.edge_id] = edge
        self._adj[edge.src_id].append(edge.edge_id)
        self._rev_adj[edge.dst_id].append(edge.edge_id)
        return edge.edge_id

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str, direction: str = "out") -> list[GraphNode]:
        edge_ids = self._adj[node_id] if direction == "out" else self._rev_adj[node_id]
        neighbors = []
        for eid in edge_ids:
            e = self._edges[eid]
            neighbor_id = e.dst_id if direction == "out" else e.src_id
            n = self._nodes.get(neighbor_id)
            if n:
                neighbors.append(n)
        return neighbors

    # ── Attack Path Exploration ───────────────────────────────────────────

    def find_attack_paths(
        self,
        origin_id: str,
        target_id: str,
        max_depth: int = 8,
        min_confidence: float = 0.5,
    ) -> list[AttackPath]:
        """BFS-based attack path discovery between two nodes."""
        if origin_id not in self._nodes or target_id not in self._nodes:
            return []

        paths: list[AttackPath] = []
        # BFS: queue holds (current_node, path_nodes, path_edges, confidence_product)
        queue: deque = deque([(origin_id, [origin_id], [], 1.0)])
        visited_paths: set[tuple] = set()

        while queue and len(paths) < 20:
            cur_id, path_nodes, path_edges, conf_prod = queue.popleft()

            if len(path_nodes) > max_depth:
                continue

            if cur_id == target_id and len(path_nodes) > 1:
                path_key = tuple(path_nodes)
                if path_key not in visited_paths:
                    visited_paths.add(path_key)
                    # Collect ATT&CK refs from all nodes in path
                    all_techniques = []
                    risk_sum = 0.0
                    for nid in path_nodes:
                        n = self._nodes[nid]
                        all_techniques.extend(n.attck_refs)
                        risk_sum += n.risk_score

                    path = AttackPath(
                        path_id         = str(uuid.uuid4())[:8],
                        nodes           = path_nodes[:],
                        edges           = path_edges[:],
                        technique_ids   = list(set(all_techniques)),
                        origin_node     = origin_id,
                        target_node     = target_id,
                        path_confidence = round(conf_prod, 4),
                        risk_score      = round(risk_sum / len(path_nodes), 2),
                        replay_validated= all(
                            self._edges[eid].replay_validated for eid in path_edges if eid in self._edges
                        ),
                    )
                    self._attack_paths[path.path_id] = path
                    paths.append(path)
                continue

            for eid in self._adj.get(cur_id, []):
                edge = self._edges[eid]
                nxt  = edge.dst_id
                edge_conf = edge.confidence
                new_conf  = conf_prod * edge_conf

                if new_conf < min_confidence:
                    continue
                if nxt in path_nodes:  # avoid cycles
                    continue

                queue.append((nxt, path_nodes + [nxt], path_edges + [eid], new_conf))

        return sorted(paths, key=lambda p: (p.risk_score, p.path_confidence), reverse=True)

    def get_attack_path_summary(self, path_id: str) -> dict:
        path = self._attack_paths.get(path_id)
        if not path:
            return {"error": "path_not_found"}

        node_details = []
        for nid in path.nodes:
            n = self._nodes.get(nid)
            if n:
                node_details.append({
                    "node_id":   nid,
                    "label":     n.label,
                    "type":      n.node_type.value,
                    "risk":      n.risk_score,
                    "attck":     n.attck_refs,
                })

        return {
            "path_id":          path.path_id,
            "length":           path.path_length,
            "confidence":       path.path_confidence,
            "risk_score":       path.risk_score,
            "replay_validated": path.replay_validated,
            "techniques":       path.technique_ids,
            "nodes":            node_details,
        }

    # ── Infrastructure Pivots ─────────────────────────────────────────────

    def register_pivot(self, pivot: InfrastructurePivot) -> dict:
        self._pivots.append(pivot)
        return {
            "pivot_id":     pivot.pivot_id,
            "actor":        pivot.actor_id,
            "type":         pivot.pivot_type,
            "from":         pivot.src_infra,
            "to":           pivot.dst_infra,
            "confidence":   pivot.confidence,
        }

    def get_actor_pivot_timeline(self, actor_id: str) -> list[dict]:
        actor_pivots = sorted(
            [p for p in self._pivots if p.actor_id == actor_id],
            key=lambda p: p.timestamp,
        )
        return [
            {
                "pivot_id":     p.pivot_id,
                "type":         p.pivot_type,
                "from":         p.src_infra,
                "to":           p.dst_infra,
                "timestamp":    p.timestamp,
                "confidence":   p.confidence,
                "techniques":   p.techniques,
                "campaign":     p.campaign_id,
            }
            for p in actor_pivots
        ]

    def detect_shared_infrastructure(self, min_actors: int = 2) -> list[dict]:
        """Identify infrastructure nodes shared across multiple actors."""
        infra_actors: dict[str, set[str]] = defaultdict(set)
        for p in self._pivots:
            infra_actors[p.src_infra].add(p.actor_id)
            infra_actors[p.dst_infra].add(p.actor_id)

        shared = []
        for infra, actors in infra_actors.items():
            if len(actors) >= min_actors:
                shared.append({
                    "infrastructure":   infra,
                    "actor_count":      len(actors),
                    "actors":           list(actors),
                    "pivot_count":      sum(1 for p in self._pivots
                                           if p.src_infra == infra or p.dst_infra == infra),
                })
        return sorted(shared, key=lambda x: x["actor_count"], reverse=True)

    # ── Campaign Temporal Playback ─────────────────────────────────────────

    def register_campaign(self, campaign: CampaignTimeline) -> str:
        self._campaigns[campaign.campaign_id] = campaign
        return campaign.campaign_id

    def playback_campaign(self, campaign_id: str, speed: float = 1.0) -> list[dict]:
        """Return ordered events for timeline playback (speed=1.0 = realtime)."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return []

        playback = []
        for i, evt in enumerate(sorted(campaign.events, key=lambda e: e["timestamp"])):
            node = self._nodes.get(evt["node_id"])
            playback.append({
                "sequence":     i + 1,
                "timestamp":    evt["timestamp"],
                "node_id":      evt["node_id"],
                "node_label":   node.label if node else "unknown",
                "node_type":    node.node_type.value if node else "unknown",
                "description":  evt["description"],
                "edge_id":      evt.get("edge_id", ""),
                "playback_offset_s": i * speed,
            })
        return playback

    def get_campaign_summary(self, campaign_id: str) -> dict:
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"error": "not_found"}

        technique_freq: dict[str, int] = defaultdict(int)
        for evt in campaign.events:
            n = self._nodes.get(evt["node_id"])
            if n:
                for t in n.attck_refs:
                    technique_freq[t] += 1

        return {
            "campaign_id":      campaign.campaign_id,
            "name":             campaign.campaign_name,
            "actor":            campaign.actor_id,
            "event_count":      campaign.event_count,
            "start":            campaign.start_time,
            "end":              campaign.end_time,
            "techniques":       campaign.techniques,
            "confidence":       campaign.confidence,
            "top_techniques":   sorted(technique_freq.items(), key=lambda x: x[1], reverse=True)[:5],
        }

    # ── ATT&CK Sequence Reconstruction ────────────────────────────────────

    def reconstruct_attck_sequence(self, campaign_id: str) -> dict:
        """Reconstruct ATT&CK technique execution sequence for a campaign."""
        campaign = self._campaigns.get(campaign_id)
        if not campaign:
            return {"error": "not_found"}

        tactic_timeline: dict[str, list[str]] = defaultdict(list)
        for evt in sorted(campaign.events, key=lambda e: e["timestamp"]):
            n = self._nodes.get(evt["node_id"])
            if n:
                for t in n.attck_refs:
                    # Extract tactic from properties if available
                    tactic = n.properties.get("tactic", "unknown")
                    tactic_timeline[tactic].append(t)

        # Deduplicate preserving order
        dedup_timeline = {
            tactic: list(dict.fromkeys(techs))
            for tactic, techs in tactic_timeline.items()
        }

        return {
            "campaign_id":          campaign.campaign_id,
            "total_techniques":     len(set(t for techs in dedup_timeline.values() for t in techs)),
            "tactic_sequence":      dedup_timeline,
            "kill_chain_coverage":  list(dedup_timeline.keys()),
        }

    # ── Graph Anomaly Detection ───────────────────────────────────────────

    def detect_graph_anomalies(self) -> list[GraphAnomaly]:
        """Scan graph topology for anomalous patterns."""
        anomalies: list[GraphAnomaly] = []

        # 1. Lateral movement detection — nodes with high out-degree from process nodes
        for nid, node in self._nodes.items():
            if node.node_type == NodeType.PROCESS:
                out_edges = self._adj.get(nid, [])
                lateral_edges = [
                    eid for eid in out_edges
                    if self._edges[eid].edge_type == EdgeType.CONNECTED_TO
                ]
                if len(lateral_edges) >= 5:
                    anomalies.append(GraphAnomaly(
                        anomaly_id      = str(uuid.uuid4())[:8],
                        anomaly_type    = AnomalyType.UNUSUAL_LATERAL_MOVEMENT,
                        affected_nodes  = [nid] + [self._edges[eid].dst_id for eid in lateral_edges[:3]],
                        severity        = min(10, 5 + len(lateral_edges) * 0.5),
                        confidence      = 0.82,
                        description     = f"Process {node.label} made {len(lateral_edges)} lateral connections",
                        evidence        = lateral_edges[:5],
                    ))

        # 2. Beaconing — regular C2 connections from same node
        c2_connections: dict[str, list[str]] = defaultdict(list)
        for eid, edge in self._edges.items():
            if edge.edge_type == EdgeType.COMMUNICATES:
                dst = self._nodes.get(edge.dst_id)
                if dst and dst.node_type == NodeType.C2_SERVER:
                    c2_connections[edge.src_id].append(eid)

        for src_id, eids in c2_connections.items():
            if len(eids) >= 3:
                src = self._nodes.get(src_id)
                anomalies.append(GraphAnomaly(
                    anomaly_id      = str(uuid.uuid4())[:8],
                    anomaly_type    = AnomalyType.BEACONING_PATTERN,
                    affected_nodes  = [src_id],
                    severity        = 8.5,
                    confidence      = 0.88,
                    description     = f"{src.label if src else src_id} beaconing to C2 ({len(eids)} events)",
                    evidence        = eids,
                ))

        # 3. Privilege escalation chains
        escalation_chains = []
        for nid, node in self._nodes.items():
            if "T1068" in node.attck_refs or "T1055" in node.attck_refs:
                escalation_chains.append(nid)

        if len(escalation_chains) >= 2:
            anomalies.append(GraphAnomaly(
                anomaly_id      = str(uuid.uuid4())[:8],
                anomaly_type    = AnomalyType.PRIVILEGE_ESCALATION_CHAIN,
                affected_nodes  = escalation_chains[:5],
                severity        = 9.0,
                confidence      = 0.85,
                description     = f"Privilege escalation chain across {len(escalation_chains)} nodes",
                evidence        = escalation_chains,
            ))

        # 4. Graph density spike — unusually connected node
        for nid in self._nodes:
            out_count = len(self._adj.get(nid, []))
            in_count  = len(self._rev_adj.get(nid, []))
            if out_count + in_count > 20:
                anomalies.append(GraphAnomaly(
                    anomaly_id      = str(uuid.uuid4())[:8],
                    anomaly_type    = AnomalyType.GRAPH_DENSITY_SPIKE,
                    affected_nodes  = [nid],
                    severity        = min(10, 4 + (out_count + in_count) * 0.15),
                    confidence      = 0.75,
                    description     = f"Node {nid} has {out_count+in_count} connections (density spike)",
                    evidence        = [],
                ))

        self._anomalies.extend(anomalies)
        return sorted(anomalies, key=lambda a: a.severity, reverse=True)

    # ── Malware Lineage ────────────────────────────────────────────────────

    def register_malware_lineage(self, lineage: MalwareLineage) -> dict:
        self._lineages.append(lineage)
        return {
            "lineage_id":   lineage.lineage_id,
            "family":       lineage.family,
            "root_sample":  lineage.root_sample,
            "variant_count":len(lineage.variants),
            "confidence":   lineage.confidence,
        }

    def get_malware_lineage_graph(self, family: str) -> dict:
        lineages = [l for l in self._lineages if l.family == family]
        if not lineages:
            return {"error": "family_not_found"}

        all_actors    = set()
        all_campaigns = set()
        all_techniques = set()
        total_variants = 0

        for l in lineages:
            all_actors.update(l.actor_refs)
            all_campaigns.update(l.campaign_refs)
            all_techniques.update(l.attck_coverage)
            total_variants += len(l.variants)

        return {
            "family":               family,
            "total_samples":        len(lineages),
            "total_variants":       total_variants,
            "attributed_actors":    list(all_actors),
            "associated_campaigns": list(all_campaigns),
            "attck_techniques":     list(all_techniques),
            "lineage_depth":        max(l.lineage_depth for l in lineages),
            "avg_confidence":       round(statistics.mean(l.confidence for l in lineages), 2),
        }

    # ── Confidence Scoring ─────────────────────────────────────────────────

    def compute_graph_confidence(self) -> dict:
        if not self._nodes:
            return {"status": "empty_graph"}

        node_confs  = [n.confidence for n in self._nodes.values()]
        edge_confs  = [e.confidence for e in self._edges.values()]
        replay_rate = sum(1 for e in self._edges.values() if e.replay_validated) / max(len(self._edges), 1)
        attck_nodes = sum(1 for n in self._nodes.values() if len(n.attck_refs) > 0)

        avg_node_conf = statistics.mean(node_confs) if node_confs else 0
        avg_edge_conf = statistics.mean(edge_confs) if edge_confs else 0

        composite = round(
            avg_node_conf * 0.35 +
            avg_edge_conf * 0.30 +
            replay_rate   * 0.25 +
            (attck_nodes / max(len(self._nodes), 1)) * 0.10,
            4
        )

        return {
            "total_nodes":          len(self._nodes),
            "total_edges":          len(self._edges),
            "avg_node_confidence":  round(avg_node_conf, 4),
            "avg_edge_confidence":  round(avg_edge_conf, 4),
            "replay_validation_rate": round(replay_rate, 4),
            "attck_annotated_nodes":  attck_nodes,
            "composite_confidence":   composite,
            "confidence_level":       ConfidenceLevel.CONFIRMED.value if composite >= 0.9
                                      else ConfidenceLevel.HIGH.value if composite >= 0.75
                                      else ConfidenceLevel.MEDIUM.value,
        }

    # ── Graph Statistics ───────────────────────────────────────────────────

    def get_graph_stats(self) -> dict:
        node_type_counts = defaultdict(int)
        edge_type_counts = defaultdict(int)
        for n in self._nodes.values():
            node_type_counts[n.node_type.value] += 1
        for e in self._edges.values():
            edge_type_counts[e.edge_type.value] += 1

        avg_risk = statistics.mean(n.risk_score for n in self._nodes.values()) if self._nodes else 0
        high_risk_nodes = [
            {"id": n.node_id, "label": n.label, "risk": n.risk_score}
            for n in self._nodes.values() if n.risk_score >= 7.0
        ]

        return {
            "total_nodes":          len(self._nodes),
            "total_edges":          len(self._edges),
            "total_attack_paths":   len(self._attack_paths),
            "total_campaigns":      len(self._campaigns),
            "total_anomalies":      len(self._anomalies),
            "total_pivots":         len(self._pivots),
            "total_lineages":       len(self._lineages),
            "avg_node_risk":        round(avg_risk, 2),
            "high_risk_nodes":      sorted(high_risk_nodes, key=lambda x: x["risk"], reverse=True)[:10],
            "node_type_breakdown":  dict(node_type_counts),
            "edge_type_breakdown":  dict(edge_type_counts),
            "confidence":           self.compute_graph_confidence(),
        }

    def export_graph_report(self) -> dict:
        return {
            "meta": {
                "engine":       "GraphOperationsEngine",
                "phase":        52,
                "platform":     "SENTINEL APEX",
                "initialized":  self._initialized,
                "exported_at":  datetime.now(timezone.utc).isoformat(),
            },
            "graph_statistics":     self.get_graph_stats(),
            "anomaly_count":        len(self._anomalies),
            "critical_anomalies":   [a.anomaly_id for a in self._anomalies if a.severity >= 8],
            "campaign_ids":         list(self._campaigns.keys()),
            "actor_pivot_counts":   {
                actor: len([p for p in self._pivots if p.actor_id == actor])
                for actor in set(p.actor_id for p in self._pivots)
            },
        }


# ─── Demo Harness ─────────────────────────────────────────────────────────────

def _seed_demo_graph(engine: GraphOperationsEngine):
    """Seed a realistic attack graph for demonstration."""
    now = datetime.now(timezone.utc)

    # Nodes
    nodes = [
        GraphNode("n-host-001",     NodeType.HOST,         "WIN-WORKSTATION-07",   risk_score=6.5,
                  attck_refs=[], telemetry_refs=["ebpf-001"]),
        GraphNode("n-proc-001",     NodeType.PROCESS,      "powershell.exe",        risk_score=8.2,
                  attck_refs=["T1059.001"], properties={"tactic": "execution"}),
        GraphNode("n-proc-002",     NodeType.PROCESS,      "lsass.exe",             risk_score=9.1,
                  attck_refs=["T1003.001"], properties={"tactic": "credential_access"}),
        GraphNode("n-proc-003",     NodeType.PROCESS,      "cmd.exe",               risk_score=7.4,
                  attck_refs=["T1059.003"], properties={"tactic": "execution"}),
        GraphNode("n-net-001",      NodeType.NETWORK_CONN, "185.220.101.45:443",    risk_score=9.5,
                  attck_refs=["T1071.001"]),
        GraphNode("n-domain-001",   NodeType.DOMAIN,       "cdn-update.azurecdn.io",risk_score=8.8),
        GraphNode("n-c2-001",       NodeType.C2_SERVER,    "C2-APEX-001",           risk_score=10.0,
                  attck_refs=["T1071.001", "T1573"]),
        GraphNode("n-user-001",     NodeType.USER,         "CORP\\jsmith",          risk_score=7.0,
                  attck_refs=["T1078"]),
        GraphNode("n-host-002",     NodeType.HOST,         "WIN-SERVER-DC01",       risk_score=9.8,
                  attck_refs=[], properties={"role": "domain_controller"}),
        GraphNode("n-file-001",     NodeType.FILE,         "beacon.exe",            risk_score=9.9,
                  attck_refs=["T1105", "T1204"]),
    ]
    for n in nodes:
        engine.add_node(n)

    # Edges
    edges = [
        GraphEdge("e-001", "n-host-001", "n-proc-001", EdgeType.EXECUTED,       confidence=0.95, replay_validated=True,  attck_refs=["T1059.001"]),
        GraphEdge("e-002", "n-proc-001", "n-proc-002", EdgeType.INJECTED_INTO,  confidence=0.88, replay_validated=True,  attck_refs=["T1055"]),
        GraphEdge("e-003", "n-proc-001", "n-proc-003", EdgeType.SPAWNED,        confidence=0.92, replay_validated=True),
        GraphEdge("e-004", "n-proc-001", "n-net-001",  EdgeType.CONNECTED_TO,   confidence=0.90, replay_validated=True,  attck_refs=["T1071.001"]),
        GraphEdge("e-005", "n-net-001",  "n-domain-001",EdgeType.RESOLVED_TO,   confidence=0.85, replay_validated=False),
        GraphEdge("e-006", "n-domain-001","n-c2-001",  EdgeType.ASSOCIATED_WITH,confidence=0.80, replay_validated=False),
        GraphEdge("e-007", "n-user-001", "n-host-001", EdgeType.EXECUTED,       confidence=0.95, replay_validated=True),
        GraphEdge("e-008", "n-proc-001", "n-file-001", EdgeType.WROTE,          confidence=0.87, replay_validated=True,  attck_refs=["T1105"]),
        GraphEdge("e-009", "n-proc-001", "n-host-002", EdgeType.CONNECTED_TO,   confidence=0.78, replay_validated=False, attck_refs=["T1021.002"]),
        GraphEdge("e-010", "n-proc-001", "n-c2-001",   EdgeType.COMMUNICATES,   confidence=0.82, replay_validated=True,  attck_refs=["T1071.001"]),
        GraphEdge("e-011", "n-proc-003", "n-c2-001",   EdgeType.COMMUNICATES,   confidence=0.79, replay_validated=True),
        GraphEdge("e-012", "n-host-001", "n-c2-001",   EdgeType.COMMUNICATES,   confidence=0.77, replay_validated=True),
    ]
    for e in edges:
        engine.add_edge(e)

    # Campaign
    campaign = CampaignTimeline(
        campaign_id   = "cmp-apt29-2026",
        campaign_name = "APT29 NOCTURNAL SECTOR Q1 2026",
        actor_id      = "apt29",
        techniques    = ["T1059.001", "T1055", "T1003.001", "T1071.001", "T1078"],
        confidence    = 0.87,
    )
    ts = now - timedelta(hours=48)
    for i, (nid, desc) in enumerate([
        ("n-user-001",  "Initial access via valid credentials"),
        ("n-host-001",  "Workstation compromised"),
        ("n-proc-001",  "PowerShell execution — encoded command"),
        ("n-proc-002",  "LSASS memory dump attempt"),
        ("n-net-001",   "C2 beacon — encrypted channel"),
        ("n-host-002",  "Lateral movement to Domain Controller"),
    ]):
        campaign.add_event((ts + timedelta(hours=i*4)).isoformat(), nid, f"e-{str(i+1).zfill(3)}", desc)
    engine.register_campaign(campaign)

    # Infrastructure Pivots
    pivots = [
        InfrastructurePivot("piv-001", "apt29", "185.220.101.45", "195.144.122.87",
                            "ip_rotation", (now - timedelta(days=5)).isoformat(), 0.85,
                            campaign_id="cmp-apt29-2026"),
        InfrastructurePivot("piv-002", "apt29", "cdn-update.azurecdn.io", "api-telemetry.cloudfront-edge.io",
                            "domain_reuse", (now - timedelta(days=3)).isoformat(), 0.78,
                            campaign_id="cmp-apt29-2026"),
    ]
    for p in pivots:
        engine.register_pivot(p)

    # Malware Lineage
    lineage = MalwareLineage(
        lineage_id   = "lin-beacon-001",
        root_sample  = "sha256:4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b",
        family       = "CobaltStrike",
        variants     = [
            {"hash": "sha256:1a2b3c...", "timestamp": (now - timedelta(days=30)).isoformat(), "mutations": ["rc4_key_rotation"]},
            {"hash": "sha256:5e6f7a...", "timestamp": (now - timedelta(days=10)).isoformat(), "mutations": ["sleep_mask_v3"]},
        ],
        shared_code  = ["func_beacon_main", "func_dns_resolve", "func_rc4_decrypt"],
        campaign_refs = ["cmp-apt29-2026"],
        actor_refs   = ["apt29"],
        attck_coverage = ["T1071.001", "T1573", "T1055", "T1059.001"],
        lineage_depth = 3,
        confidence   = 0.88,
    )
    engine.register_malware_lineage(lineage)

    return engine


def run_demo() -> dict:
    engine = GraphOperationsEngine()
    _seed_demo_graph(engine)

    paths = engine.find_attack_paths("n-user-001", "n-c2-001", max_depth=6)
    anomalies = engine.detect_graph_anomalies()
    report = engine.export_graph_report()

    print(f"Nodes: {len(engine._nodes)} | Edges: {len(engine._edges)}")
    print(f"Attack paths found: {len(paths)}")
    print(f"Anomalies detected: {len(anomalies)}")
    print(json.dumps(report["graph_statistics"]["confidence"], indent=2))
    return report


if __name__ == "__main__":
    run_demo()
