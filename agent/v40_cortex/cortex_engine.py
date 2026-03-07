#!/usr/bin/env python3
"""
cortex_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v40.0 (CORTEX)
==================================================================
Real-Time Intelligence Streaming, Threat Knowledge Graph,
Natural Language Query Interface, and Relationship Explorer.

4 New Subsystems (features NOT in v22-v39):
  C1 — IntelFirehose: WebSocket-ready real-time threat event streaming
  C2 — ThreatKnowledgeGraph: In-memory entity-relationship graph w/ traversal
  C3 — NaturalLanguageQueryEngine: NLQ → structured intel queries
  C4 — RelationshipExplorer: Multi-hop entity relationship mapping & pathfinding

Non-Breaking: Reads from manifest/STIX/nexus data.
Writes to data/cortex/. Zero modification to any existing file.

Author: CyberDudeBivash Pvt. Ltd. — GOC
"""

import os
import re
import json
import hashlib
import logging
import time
import math
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger("CDB-Cortex")

MANIFEST_PATH = os.environ.get("MANIFEST_PATH", "data/stix/feed_manifest.json")
NEXUS_DIR = os.environ.get("NEXUS_DIR", "data/nexus")
CORTEX_DIR = os.environ.get("CORTEX_DIR", "data/cortex")

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def _load(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _save(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
        return True
    except OSError as e:
        logger.error(f"Save failed {path}: {e}")
        return False


def _entries():
    d = _load(MANIFEST_PATH)
    if isinstance(d, list):
        return d
    return d.get("entries", []) if isinstance(d, dict) else []


def _gen_id(prefix, seed):
    return f"{prefix}--{hashlib.sha256(seed.encode()).hexdigest()[:12]}"


# ═══════════════════════════════════════════════════════════════════════════════
# ENTITY TYPES & DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

class EntityType(Enum):
    ADVISORY = "advisory"
    CVE = "cve"
    ACTOR = "actor"
    TECHNIQUE = "technique"
    TACTIC = "tactic"
    MALWARE = "malware"
    SECTOR = "sector"
    COUNTRY = "country"
    CAMPAIGN = "campaign"
    IOC_CLUSTER = "ioc_cluster"


class RelationType(Enum):
    EXPLOITS = "exploits"
    USES_TECHNIQUE = "uses_technique"
    ATTRIBUTED_TO = "attributed_to"
    TARGETS_SECTOR = "targets_sector"
    TARGETS_COUNTRY = "targets_country"
    RELATED_TO = "related_to"
    PART_OF_CAMPAIGN = "part_of_campaign"
    INDICATES = "indicates"
    MITIGATES = "mitigates"
    CONTAINS_IOC = "contains_ioc"
    VARIANT_OF = "variant_of"


@dataclass
class GraphNode:
    node_id: str
    entity_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0
    first_seen: str = ""
    last_seen: str = ""


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relation: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StreamEvent:
    event_id: str
    event_type: str
    timestamp: str
    payload: Dict[str, Any]
    severity: str = "INFO"
    channel: str = "threat-intel"


# ═══════════════════════════════════════════════════════════════════════════════
# C1 — INTEL FIREHOSE (WebSocket-Ready Event Streaming)
# ═══════════════════════════════════════════════════════════════════════════════

class IntelFirehose:
    """
    Real-time intelligence event streaming engine.
    Generates WebSocket-ready event payloads from threat intelligence.
    Supports channel-based subscriptions and event filtering.
    """

    CHANNELS = [
        "threat-intel",       # All advisories
        "critical-alerts",    # Risk >= 9.0
        "kev-updates",        # CISA KEV entries
        "actor-tracking",     # Named threat actor activity
        "campaign-intel",     # Correlated campaign updates
        "detection-rules",    # New Sigma/YARA/Snort rules
        "exposure-updates",   # Exposure score changes
        "hunt-signals",       # New threat hunt hypotheses
    ]

    def __init__(self):
        self._event_buffer = deque(maxlen=10000)
        self._subscribers = defaultdict(list)
        self._sequence = 0

    def generate_stream(self, since_hours: int = 24) -> List[Dict]:
        """Generate stream events from recent intelligence."""
        entries = _entries()
        if not entries:
            return []

        events = []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)

        for entry in entries:
            ts = entry.get("timestamp", "")
            try:
                entry_time = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if entry_time < cutoff:
                    continue
            except (ValueError, TypeError):
                pass

            risk = entry.get("risk_score", 0) or 0
            title = entry.get("title", "")
            actor = entry.get("actor_tag", "")

            # Main threat-intel event
            self._sequence += 1
            event = StreamEvent(
                event_id=f"evt-{self._sequence:08d}",
                event_type="THREAT_ADVISORY",
                timestamp=ts or datetime.now(timezone.utc).isoformat(),
                severity="CRITICAL" if risk >= 9 else "HIGH" if risk >= 7 else "MEDIUM" if risk >= 4 else "LOW",
                channel="threat-intel",
                payload={
                    "title": title[:120],
                    "risk_score": risk,
                    "actor": actor,
                    "kev": entry.get("kev_present", False),
                    "stix_id": entry.get("stix_id", ""),
                    "cves": CVE_RE.findall(title),
                    "techniques": [
                        t if isinstance(t, str) else t.get("technique_id", t.get("id", ""))
                        for t in entry.get("mitre_tactics", [])
                    ][:5],
                    "ioc_summary": entry.get("ioc_counts", {}),
                    "feed_source": entry.get("feed_source", ""),
                    "blog_url": entry.get("blog_url", ""),
                },
            )
            events.append(asdict(event))

            # Critical alert channel
            if risk >= 9:
                self._sequence += 1
                crit_event = StreamEvent(
                    event_id=f"evt-{self._sequence:08d}",
                    event_type="CRITICAL_ALERT",
                    timestamp=ts or datetime.now(timezone.utc).isoformat(),
                    severity="CRITICAL",
                    channel="critical-alerts",
                    payload={
                        "alert": f"CRITICAL: {title[:80]}",
                        "risk_score": risk,
                        "action_required": "Immediate SOC triage",
                        "stix_id": entry.get("stix_id", ""),
                    },
                )
                events.append(asdict(crit_event))

            # KEV channel
            if entry.get("kev_present"):
                self._sequence += 1
                kev_event = StreamEvent(
                    event_id=f"evt-{self._sequence:08d}",
                    event_type="KEV_UPDATE",
                    timestamp=ts or datetime.now(timezone.utc).isoformat(),
                    severity="HIGH",
                    channel="kev-updates",
                    payload={
                        "advisory": title[:80],
                        "cves": CVE_RE.findall(title),
                        "action": "Patch within 72 hours per BOD 22-01",
                    },
                )
                events.append(asdict(kev_event))

            # Actor tracking
            if actor and actor != "UNC-CDB-99":
                self._sequence += 1
                actor_event = StreamEvent(
                    event_id=f"evt-{self._sequence:08d}",
                    event_type="ACTOR_ACTIVITY",
                    timestamp=ts or datetime.now(timezone.utc).isoformat(),
                    severity="HIGH" if risk >= 7 else "MEDIUM",
                    channel="actor-tracking",
                    payload={"actor": actor, "advisory": title[:80], "risk_score": risk},
                )
                events.append(asdict(actor_event))

        # Generate stream metadata
        stream_meta = {
            "stream_id": _gen_id("stream", datetime.now(timezone.utc).isoformat()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(events),
            "channels": {ch: sum(1 for e in events if e["channel"] == ch) for ch in self.CHANNELS},
            "severity_distribution": {
                sev: sum(1 for e in events if e["severity"] == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
        }

        return {"metadata": stream_meta, "events": events}

    def get_websocket_config(self) -> Dict:
        """Generate WebSocket server configuration."""
        return {
            "server": {
                "protocol": "wss",
                "host": "stream.cyberdudebivash.com",
                "port": 443,
                "path": "/v1/stream",
                "heartbeat_interval_ms": 30000,
                "reconnect_strategy": "exponential_backoff",
                "max_reconnect_attempts": 10,
            },
            "channels": self.CHANNELS,
            "auth": {
                "method": "bearer_token",
                "header": "Authorization",
                "format": "Bearer {api_key}",
                "tiers": {
                    "free": ["threat-intel"],
                    "pro": ["threat-intel", "critical-alerts", "kev-updates", "detection-rules"],
                    "enterprise": self.CHANNELS,
                },
            },
            "rate_limits": {
                "free": {"events_per_minute": 10, "channels": 1},
                "pro": {"events_per_minute": 100, "channels": 4},
                "enterprise": {"events_per_minute": 1000, "channels": 8},
            },
            "message_format": {
                "type": "json",
                "schema_version": "1.0",
                "compression": "gzip",
                "example": {
                    "event_id": "evt-00000001",
                    "event_type": "THREAT_ADVISORY",
                    "timestamp": "2026-03-07T00:00:00Z",
                    "severity": "CRITICAL",
                    "channel": "threat-intel",
                    "payload": {"title": "...", "risk_score": 9.5},
                },
            },
        }


# ═══════════════════════════════════════════════════════════════════════════════
# C2 — THREAT KNOWLEDGE GRAPH
# ═══════════════════════════════════════════════════════════════════════════════

class ThreatKnowledgeGraph:
    """
    In-memory entity-relationship knowledge graph.
    Builds a connected graph of advisories, CVEs, actors, techniques,
    sectors, and campaigns with weighted relationships.
    Supports traversal, pathfinding, and subgraph extraction.
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._adjacency: Dict[str, List[Tuple[str, str, float]]] = defaultdict(list)

    def build_graph(self) -> Dict:
        """Build complete knowledge graph from intelligence data."""
        entries = _entries()
        if not entries:
            return {"nodes": 0, "edges": 0, "entity_types": {}}

        self.nodes.clear()
        self.edges.clear()
        self._adjacency.clear()

        for entry in entries:
            title = entry.get("title", "")
            stix_id = entry.get("stix_id", _gen_id("advisory", title))
            actor = entry.get("actor_tag", "")
            risk = entry.get("risk_score", 0) or 0
            ts = entry.get("timestamp", "")
            cves = CVE_RE.findall(title)
            tactics = entry.get("mitre_tactics", [])

            # Advisory node
            self._add_node(stix_id, EntityType.ADVISORY.value, title[:80], {
                "risk_score": risk, "kev": entry.get("kev_present", False),
                "epss": entry.get("epss_score"), "feed": entry.get("feed_source", ""),
                "blog_url": entry.get("blog_url", ""),
            }, weight=risk, first_seen=ts, last_seen=ts)

            # CVE nodes + edges
            for cve in cves:
                cve_id = cve.upper()
                self._add_node(cve_id, EntityType.CVE.value, cve_id, {
                    "cvss": entry.get("cvss_score"), "epss": entry.get("epss_score"),
                    "kev": entry.get("kev_present", False),
                })
                self._add_edge(stix_id, cve_id, RelationType.EXPLOITS.value, risk * 0.8)

            # Actor node + edge
            if actor and actor != "UNC-CDB-99":
                actor_id = f"actor--{actor.lower().replace(' ', '-')}"
                self._add_node(actor_id, EntityType.ACTOR.value, actor, {
                    "type": "threat-actor",
                })
                self._add_edge(stix_id, actor_id, RelationType.ATTRIBUTED_TO.value, risk * 0.6)

                # Actor → CVE relationships
                for cve in cves:
                    self._add_edge(actor_id, cve.upper(), RelationType.EXPLOITS.value, risk * 0.5)

            # Technique nodes + edges
            for t in tactics:
                tid = t if isinstance(t, str) else t.get("technique_id", t.get("id", ""))
                if not tid:
                    continue
                tech_id = f"technique--{tid}"
                self._add_node(tech_id, EntityType.TECHNIQUE.value, tid, {
                    "mitre_id": tid,
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/",
                })
                self._add_edge(stix_id, tech_id, RelationType.USES_TECHNIQUE.value, 0.7)

                if actor and actor != "UNC-CDB-99":
                    self._add_edge(actor_id, tech_id, RelationType.USES_TECHNIQUE.value, 0.6)

            # Sector inference
            sectors = self._infer_sectors(title)
            for sector in sectors:
                sector_id = f"sector--{sector.lower().replace(' ', '-')}"
                self._add_node(sector_id, EntityType.SECTOR.value, sector)
                self._add_edge(stix_id, sector_id, RelationType.TARGETS_SECTOR.value, 0.5)
                if actor and actor != "UNC-CDB-99":
                    self._add_edge(actor_id, sector_id, RelationType.TARGETS_SECTOR.value, 0.4)

        # Compute graph statistics
        entity_counts = defaultdict(int)
        for n in self.nodes.values():
            entity_counts[n.entity_type] += 1

        relation_counts = defaultdict(int)
        for e in self.edges:
            relation_counts[e.relation] += 1

        stats = {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "entity_types": dict(entity_counts),
            "relation_types": dict(relation_counts),
            "density": round(len(self.edges) / max(len(self.nodes) * (len(self.nodes) - 1), 1), 6),
            "built_at": datetime.now(timezone.utc).isoformat(),
        }

        return stats

    def get_neighbors(self, node_id: str, max_depth: int = 1) -> Dict:
        """Get neighboring nodes up to max_depth hops."""
        if node_id not in self.nodes:
            return {"error": f"Node {node_id} not found"}

        visited = set()
        result = {"center": asdict(self.nodes[node_id]), "neighbors": [], "edges": []}
        queue = deque([(node_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if current in visited or depth > max_depth:
                continue
            visited.add(current)

            for target, relation, weight in self._adjacency.get(current, []):
                if target not in visited:
                    if target in self.nodes:
                        result["neighbors"].append({
                            **asdict(self.nodes[target]),
                            "depth": depth + 1,
                        })
                        result["edges"].append({
                            "source": current, "target": target,
                            "relation": relation, "weight": weight,
                        })
                    queue.append((target, depth + 1))

        return result

    def find_path(self, source_id: str, target_id: str, max_hops: int = 5) -> Optional[List[Dict]]:
        """Find shortest path between two entities using BFS."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None

        visited = {source_id}
        queue = deque([(source_id, [source_id])])

        while queue:
            current, path = queue.popleft()
            if current == target_id:
                return [
                    {"node": asdict(self.nodes[nid]) if nid in self.nodes else {"node_id": nid}}
                    for nid in path
                ]
            if len(path) > max_hops:
                continue

            for neighbor, relation, weight in self._adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def get_entity_report(self, entity_id: str) -> Dict:
        """Generate comprehensive report for a single entity."""
        if entity_id not in self.nodes:
            return {"error": f"Entity {entity_id} not found"}

        node = self.nodes[entity_id]
        neighbors = self.get_neighbors(entity_id, max_depth=2)

        # Group neighbors by type
        by_type = defaultdict(list)
        for n in neighbors.get("neighbors", []):
            by_type[n["entity_type"]].append(n)

        # Compute centrality (simplified degree centrality)
        degree = len(self._adjacency.get(entity_id, []))
        max_degree = max(len(v) for v in self._adjacency.values()) if self._adjacency else 1
        centrality = round(degree / max(max_degree, 1), 4)

        return {
            "entity": asdict(node),
            "centrality_score": centrality,
            "connection_count": degree,
            "related_entities": {k: len(v) for k, v in by_type.items()},
            "top_connections": [
                {"id": n["node_id"], "type": n["entity_type"], "label": n["label"]}
                for n in sorted(neighbors.get("neighbors", []),
                                key=lambda x: x.get("weight", 0), reverse=True)[:10]
            ],
        }

    def export_graph(self) -> Dict:
        """Export full graph in visualization-ready format."""
        return {
            "nodes": [
                {
                    "id": n.node_id, "type": n.entity_type,
                    "label": n.label, "weight": n.weight,
                    **n.properties,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id, "target": e.target_id,
                    "relation": e.relation, "weight": e.weight,
                }
                for e in self.edges
            ],
            "stats": {
                "nodes": len(self.nodes),
                "edges": len(self.edges),
            },
        }

    def _add_node(self, node_id, entity_type, label, properties=None,
                  weight=1.0, first_seen="", last_seen=""):
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                node_id=node_id, entity_type=entity_type, label=label,
                properties=properties or {}, weight=weight,
                first_seen=first_seen, last_seen=last_seen,
            )
        else:
            # Update weight (keep highest)
            existing = self.nodes[node_id]
            existing.weight = max(existing.weight, weight)
            if last_seen:
                existing.last_seen = max(existing.last_seen, last_seen) if existing.last_seen else last_seen

    def _add_edge(self, source, target, relation, weight=1.0):
        edge = GraphEdge(source_id=source, target_id=target, relation=relation, weight=weight)
        self.edges.append(edge)
        self._adjacency[source].append((target, relation, weight))
        self._adjacency[target].append((source, relation, weight))

    def _infer_sectors(self, title: str) -> List[str]:
        title_lower = title.lower()
        sectors = []
        sector_keywords = {
            "Financial Services": ["bank", "financial", "payment", "fintech"],
            "Healthcare": ["health", "hospital", "medical", "pharma"],
            "Government": ["government", "federal", "military", "defense"],
            "Technology": ["tech", "software", "saas", "cloud", "api"],
            "Energy": ["energy", "power", "grid", "oil", "utility"],
            "Education": ["university", "education", "school"],
            "Retail": ["retail", "e-commerce", "shopping"],
            "Telecom": ["telecom", "5g", "mobile", "carrier"],
        }
        for sector, kws in sector_keywords.items():
            if any(k in title_lower for k in kws):
                sectors.append(sector)
        return sectors if sectors else ["Cross-Sector"]


# ═══════════════════════════════════════════════════════════════════════════════
# C3 — NATURAL LANGUAGE QUERY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class NaturalLanguageQueryEngine:
    """
    Translates natural language questions into structured intelligence queries.
    Supports actor, CVE, technique, sector, and temporal queries.
    """

    QUERY_PATTERNS = [
        {
            "pattern": r"(?:show|find|list|get)\s+(?:all\s+)?(.+?)(?:\s+activity|\s+threats?|\s+advisories?)",
            "type": "entity_search",
        },
        {
            "pattern": r"(?:what|which)\s+(?:cves?|vulnerabilities?)\s+(?:are\s+)?(?:exploited|used)\s+by\s+(.+)",
            "type": "actor_cve_lookup",
        },
        {
            "pattern": r"(?:who|which\s+(?:actor|group))\s+(?:is\s+)?(?:targeting|attacking)\s+(.+)",
            "type": "sector_actor_lookup",
        },
        {
            "pattern": r"(?:show|find|list)\s+(?:all\s+)?(?:critical|high)\s+(?:threats?|risks?|advisories?)",
            "type": "severity_filter",
        },
        {
            "pattern": r"(?:what|show)\s+(?:is\s+)?(?:the\s+)?(?:risk|exposure|threat)\s+(?:score|level|index)",
            "type": "exposure_query",
        },
        {
            "pattern": r"(?:how\s+many|count)\s+(.+)",
            "type": "count_query",
        },
        {
            "pattern": r"(?:related|connected|linked)\s+(?:to\s+)?(.+)",
            "type": "relationship_query",
        },
    ]

    ACTOR_ALIASES = {
        "apt28": ["apt28", "fancy bear", "sofacy", "sednit", "pawn storm"],
        "apt29": ["apt29", "cozy bear", "dukes", "midnight blizzard"],
        "lazarus": ["lazarus", "hidden cobra", "zinc", "labyrinth chollima"],
        "lockbit": ["lockbit", "lock bit"],
        "cl0p": ["cl0p", "clop", "ta505"],
        "alphv": ["alphv", "blackcat", "noberus"],
        "scattered spider": ["scattered spider", "octo tempest", "unc3944"],
    }

    def process_query(self, query: str, graph: ThreatKnowledgeGraph) -> Dict:
        """Process a natural language query against the knowledge graph."""
        query_lower = query.lower().strip()

        # Detect query type
        query_type = self._classify_query(query_lower)

        # Extract entities from query
        entities = self._extract_query_entities(query_lower)

        # Execute query
        results = self._execute_query(query_type, entities, query_lower, graph)

        return {
            "query": query,
            "interpreted_as": query_type,
            "entities_detected": entities,
            "results": results,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _classify_query(self, query: str) -> str:
        for pattern_def in self.QUERY_PATTERNS:
            if re.search(pattern_def["pattern"], query, re.IGNORECASE):
                return pattern_def["type"]

        # Fallback classification
        if any(kw in query for kw in ["cve-", "vulnerability", "exploit"]):
            return "cve_search"
        if any(kw in query for kw in ["actor", "group", "apt", "threat group"]):
            return "actor_search"
        if any(kw in query for kw in ["technique", "t1", "mitre"]):
            return "technique_search"
        return "general_search"

    def _extract_query_entities(self, query: str) -> Dict:
        entities = {
            "actors": [],
            "cves": [],
            "techniques": [],
            "sectors": [],
            "severities": [],
            "time_range": None,
        }

        # CVEs
        entities["cves"] = [c.upper() for c in CVE_RE.findall(query)]

        # Actors
        for canonical, aliases in self.ACTOR_ALIASES.items():
            if any(a in query for a in aliases):
                entities["actors"].append(canonical)

        # Techniques
        tech_matches = re.findall(r't\d{4}(?:\.\d{3})?', query, re.IGNORECASE)
        entities["techniques"] = [t.upper() for t in tech_matches]

        # Sectors
        sector_keywords = {
            "financial": "Financial Services", "healthcare": "Healthcare",
            "government": "Government", "technology": "Technology",
            "energy": "Energy", "education": "Education",
        }
        for kw, sector in sector_keywords.items():
            if kw in query:
                entities["sectors"].append(sector)

        # Severities
        if "critical" in query:
            entities["severities"].append("CRITICAL")
        if "high" in query:
            entities["severities"].append("HIGH")

        # Time
        if "last" in query and "days" in query:
            match = re.search(r'last\s+(\d+)\s+days?', query)
            if match:
                entities["time_range"] = int(match.group(1))
        elif "today" in query:
            entities["time_range"] = 1
        elif "week" in query:
            entities["time_range"] = 7
        elif "month" in query:
            entities["time_range"] = 30

        return entities

    def _execute_query(self, query_type: str, entities: Dict, raw: str,
                       graph: ThreatKnowledgeGraph) -> Dict:
        entries = _entries()
        if not entries:
            return {"count": 0, "items": [], "message": "No intelligence data available"}

        results = []

        if query_type in ("actor_search", "actor_cve_lookup", "entity_search"):
            actor_filter = entities.get("actors", [])
            if actor_filter:
                for entry in entries:
                    actor_tag = (entry.get("actor_tag", "") or "").lower()
                    if any(a in actor_tag for a in actor_filter):
                        results.append(self._format_entry(entry))
            else:
                # General text search
                for entry in entries:
                    title_lower = (entry.get("title", "") or "").lower()
                    if any(word in title_lower for word in raw.split() if len(word) > 3):
                        results.append(self._format_entry(entry))

        elif query_type == "cve_search":
            cve_filter = entities.get("cves", [])
            for entry in entries:
                title = entry.get("title", "")
                if cve_filter:
                    if any(cve in title.upper() for cve in cve_filter):
                        results.append(self._format_entry(entry))
                elif "cve" in raw:
                    if CVE_RE.search(title):
                        results.append(self._format_entry(entry))

        elif query_type == "severity_filter":
            sevs = entities.get("severities", ["CRITICAL", "HIGH"])
            thresholds = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0}
            min_score = min(thresholds.get(s, 0) for s in sevs) if sevs else 7.0
            results = [self._format_entry(e) for e in entries if (e.get("risk_score", 0) or 0) >= min_score]

        elif query_type == "sector_actor_lookup":
            sectors = entities.get("sectors", [])
            if sectors:
                for entry in entries:
                    title_lower = entry.get("title", "").lower()
                    if any(s.lower() in title_lower for s in sectors):
                        results.append(self._format_entry(entry))

        elif query_type == "exposure_query":
            # Return exposure summary
            nexus_data = _load(os.path.join(NEXUS_DIR, "exposure_score.json"))
            if nexus_data:
                return {"exposure": nexus_data, "count": 1}

        elif query_type == "count_query":
            return {"count": len(entries), "message": f"Total advisories: {len(entries)}"}

        elif query_type == "relationship_query":
            # Use graph for relationship queries
            for actor in entities.get("actors", []):
                actor_id = f"actor--{actor}"
                if actor_id in graph.nodes:
                    report = graph.get_entity_report(actor_id)
                    return {"entity_report": report, "count": 1}

        else:
            # General search
            for entry in entries:
                title_lower = (entry.get("title", "") or "").lower()
                if any(word in title_lower for word in raw.split() if len(word) > 3):
                    results.append(self._format_entry(entry))

        # Apply time filter
        time_range = entities.get("time_range")
        if time_range and results:
            cutoff = datetime.now(timezone.utc) - timedelta(days=time_range)
            filtered = []
            for r in results:
                try:
                    ts = r.get("timestamp", "")
                    if ts:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if dt >= cutoff:
                            filtered.append(r)
                except (ValueError, TypeError):
                    filtered.append(r)
            results = filtered if filtered else results

        return {
            "count": len(results),
            "items": results[:50],
            "truncated": len(results) > 50,
        }

    def _format_entry(self, entry: Dict) -> Dict:
        return {
            "title": entry.get("title", "")[:100],
            "risk_score": entry.get("risk_score", 0),
            "actor": entry.get("actor_tag", ""),
            "kev": entry.get("kev_present", False),
            "timestamp": entry.get("timestamp", ""),
            "stix_id": entry.get("stix_id", ""),
            "cves": CVE_RE.findall(entry.get("title", "")),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# C4 — RELATIONSHIP EXPLORER
# ═══════════════════════════════════════════════════════════════════════════════

class RelationshipExplorer:
    """
    Multi-hop entity relationship mapping and visualization data generator.
    Identifies influence clusters, pivotal entities, and attack corridors.
    """

    def __init__(self, graph: ThreatKnowledgeGraph):
        self.graph = graph

    def find_attack_corridors(self) -> List[Dict]:
        """Identify high-risk attack corridors (actor → technique → sector chains)."""
        corridors = []

        actor_nodes = [n for n in self.graph.nodes.values() if n.entity_type == EntityType.ACTOR.value]

        for actor in actor_nodes:
            # Find techniques used by this actor
            techniques = []
            sectors = []
            for target, relation, weight in self.graph._adjacency.get(actor.node_id, []):
                if target.startswith("technique--"):
                    techniques.append(self.graph.nodes.get(target))
                elif target.startswith("sector--"):
                    sectors.append(self.graph.nodes.get(target))

            if techniques and sectors:
                max_weight = max(t.weight for t in techniques if t) if techniques else 0
                corridors.append({
                    "corridor_id": _gen_id("corridor", actor.node_id),
                    "actor": actor.label,
                    "techniques": [t.label for t in techniques if t][:10],
                    "targeted_sectors": [s.label for s in sectors if s],
                    "technique_count": len(techniques),
                    "risk_level": "CRITICAL" if max_weight >= 9 else "HIGH" if max_weight >= 7 else "MEDIUM",
                })

        return sorted(corridors, key=lambda c: len(c["techniques"]), reverse=True)

    def compute_influence_scores(self) -> List[Dict]:
        """Compute entity influence scores (simplified PageRank)."""
        scores = {}
        damping = 0.85
        iterations = 20
        n = len(self.graph.nodes)
        if n == 0:
            return []

        # Initialize
        for nid in self.graph.nodes:
            scores[nid] = 1.0 / n

        # Iterate
        for _ in range(iterations):
            new_scores = {}
            for nid in self.graph.nodes:
                incoming_score = 0
                for neighbor, relation, weight in self.graph._adjacency.get(nid, []):
                    out_degree = len(self.graph._adjacency.get(neighbor, []))
                    if out_degree > 0:
                        incoming_score += scores.get(neighbor, 0) / out_degree
                new_scores[nid] = (1 - damping) / n + damping * incoming_score
            scores = new_scores

        # Rank
        ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return [
            {
                "entity_id": nid,
                "label": self.graph.nodes[nid].label if nid in self.graph.nodes else nid,
                "entity_type": self.graph.nodes[nid].entity_type if nid in self.graph.nodes else "unknown",
                "influence_score": round(score * 1000, 4),
                "connections": len(self.graph._adjacency.get(nid, [])),
            }
            for nid, score in ranked[:50]
        ]

    def get_cluster_analysis(self) -> Dict:
        """Identify entity clusters using connected components."""
        visited = set()
        clusters = []

        for nid in self.graph.nodes:
            if nid in visited:
                continue
            cluster = []
            queue = deque([nid])
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                cluster.append(current)
                for neighbor, _, _ in self.graph._adjacency.get(current, []):
                    if neighbor not in visited:
                        queue.append(neighbor)
            if len(cluster) > 1:
                clusters.append(cluster)

        # Format clusters
        formatted = []
        for i, cluster in enumerate(sorted(clusters, key=len, reverse=True)[:20]):
            types = defaultdict(int)
            for nid in cluster:
                if nid in self.graph.nodes:
                    types[self.graph.nodes[nid].entity_type] += 1

            formatted.append({
                "cluster_id": i + 1,
                "size": len(cluster),
                "entity_types": dict(types),
                "sample_entities": [
                    self.graph.nodes[nid].label
                    for nid in cluster[:5]
                    if nid in self.graph.nodes
                ],
            })

        return {
            "total_clusters": len(clusters),
            "largest_cluster_size": max(len(c) for c in clusters) if clusters else 0,
            "isolated_nodes": sum(1 for nid in self.graph.nodes if nid not in visited or len(self.graph._adjacency.get(nid, [])) == 0),
            "clusters": formatted,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CORTEX ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

class CortexOrchestrator:
    """Master orchestrator for all CORTEX v40.0 subsystems."""

    def __init__(self):
        self.firehose = IntelFirehose()
        self.graph = ThreatKnowledgeGraph()
        self.nlq = NaturalLanguageQueryEngine()
        self.explorer = None  # Built after graph

    def execute_full_cycle(self) -> Dict:
        logger.info("[CORTEX] Starting full intelligence cycle...")
        start = time.time()

        results = {
            "version": "40.0.0",
            "codename": "CORTEX",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        # C1: Firehose
        try:
            stream = self.firehose.generate_stream(since_hours=168)
            results["stream"] = stream.get("metadata", {})
            _save(os.path.join(CORTEX_DIR, "stream_events.json"), stream)
            logger.info(f"[CORTEX-C1] Generated {results['stream'].get('total_events', 0)} stream events")
        except Exception as e:
            logger.error(f"[CORTEX-C1] Firehose failed: {e}")
            results["stream"] = {}

        # C1b: WebSocket config
        try:
            ws_config = self.firehose.get_websocket_config()
            _save(os.path.join(CORTEX_DIR, "websocket_config.json"), ws_config)
            results["websocket_config"] = True
        except Exception as e:
            logger.error(f"[CORTEX-C1b] WS config failed: {e}")

        # C2: Knowledge Graph
        try:
            graph_stats = self.graph.build_graph()
            results["knowledge_graph"] = graph_stats
            graph_export = self.graph.export_graph()
            _save(os.path.join(CORTEX_DIR, "knowledge_graph.json"), graph_export)
            _save(os.path.join(CORTEX_DIR, "graph_stats.json"), graph_stats)
            logger.info(f"[CORTEX-C2] Graph: {graph_stats.get('total_nodes', 0)} nodes, {graph_stats.get('total_edges', 0)} edges")
        except Exception as e:
            logger.error(f"[CORTEX-C2] Graph build failed: {e}")
            results["knowledge_graph"] = {}

        # C3: Sample NLQ queries
        try:
            sample_queries = [
                "Show all APT28 activity targeting financial sector",
                "Find critical threats in the last 7 days",
                "Which actors are targeting healthcare",
                "What is the current exposure score",
                "How many advisories are tracked",
            ]
            nlq_results = []
            for q in sample_queries:
                r = self.nlq.process_query(q, self.graph)
                nlq_results.append({"query": q, "result_count": r.get("results", {}).get("count", 0)})
            results["nlq_samples"] = nlq_results
            _save(os.path.join(CORTEX_DIR, "nlq_samples.json"), nlq_results)
            logger.info(f"[CORTEX-C3] NLQ: {len(nlq_results)} sample queries processed")
        except Exception as e:
            logger.error(f"[CORTEX-C3] NLQ failed: {e}")

        # C4: Relationship Explorer
        try:
            self.explorer = RelationshipExplorer(self.graph)
            corridors = self.explorer.find_attack_corridors()
            influence = self.explorer.compute_influence_scores()
            clusters = self.explorer.get_cluster_analysis()

            results["attack_corridors"] = len(corridors)
            results["top_influencers"] = len(influence)
            results["clusters"] = clusters.get("total_clusters", 0)

            _save(os.path.join(CORTEX_DIR, "attack_corridors.json"), corridors)
            _save(os.path.join(CORTEX_DIR, "influence_scores.json"), influence)
            _save(os.path.join(CORTEX_DIR, "cluster_analysis.json"), clusters)
            logger.info(f"[CORTEX-C4] Corridors: {len(corridors)}, Influencers: {len(influence)}, Clusters: {clusters.get('total_clusters', 0)}")
        except Exception as e:
            logger.error(f"[CORTEX-C4] Explorer failed: {e}")

        elapsed = round((time.time() - start) * 1000, 2)
        results["execution_time_ms"] = elapsed
        _save(os.path.join(CORTEX_DIR, "cortex_output.json"), results)
        logger.info(f"[CORTEX] Full cycle completed in {elapsed}ms")

        return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    print("=" * 70)
    print("CYBERDUDEBIVASH® SENTINEL APEX v40.0 — CORTEX")
    print("=" * 70)
    orchestrator = CortexOrchestrator()
    results = orchestrator.execute_full_cycle()
    print(f"\n✅ CORTEX Cycle Complete")
    print(f"   Stream Events:    {results.get('stream', {}).get('total_events', 0)}")
    print(f"   Graph Nodes:      {results.get('knowledge_graph', {}).get('total_nodes', 0)}")
    print(f"   Graph Edges:      {results.get('knowledge_graph', {}).get('total_edges', 0)}")
    print(f"   Attack Corridors: {results.get('attack_corridors', 0)}")
    print(f"   Clusters:         {results.get('clusters', 0)}")
    print(f"   Execution Time:   {results.get('execution_time_ms', 0)}ms")
