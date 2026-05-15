"""
persistent_campaign_graph_engine.py — CYBERDUDEBIVASH Threat Intelligence Platform
Phase: Enterprise Operational Trust — P0 Persistent Adversary Campaign Graphing

Transforms isolated per-advisory intelligence into persistent corpus-wide
adversary campaign intelligence with cross-dossier correlation, temporal
tracking, and infrastructure relationship mapping.

Capabilities:
  - Persistent Campaign Graph (cross-dossier node + edge correlation)
  - Adversary Infrastructure Correlation (IOC reuse across advisories)
  - Cross-Dossier Campaign Correlation (shared TTPs, sectors, actors)
  - Temporal Threat Evolution Tracking (campaign progression over time)
  - Infrastructure Reuse Detection (IP, domain, hash overlap)
  - ATT&CK Campaign Overlay (technique chain visualisation)
  - Actor Evolution Timelines (sophistication, capability growth)
  - Campaign Relationship Intelligence (parent/child campaigns)

Author: CYBERDUDEBIVASH Pvt. Ltd.
Version: 1.0.0
Production mandates: Never raises. Bounded iteration. Deterministic. Enterprise-safe.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger("persistent_campaign_graph")

_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Graph Node + Edge Schemas
# ---------------------------------------------------------------------------

# Node types in the campaign graph
NODE_ADVISORY    = "advisory"
NODE_ACTOR       = "actor"
NODE_CAMPAIGN    = "campaign"
NODE_IOC         = "ioc"
NODE_TTP         = "ttp"
NODE_SECTOR      = "sector"
NODE_CVE         = "cve"
NODE_MALWARE     = "malware"
NODE_GEO         = "geo"
NODE_INFRA       = "infrastructure"

# Edge types — directionality matters for intelligence reasoning
EDGE_ATTRIBUTED_TO  = "attributed_to"        # advisory → actor
EDGE_PART_OF        = "part_of"              # advisory → campaign
EDGE_USES_TTP       = "uses_ttp"             # advisory/actor/campaign → ttp
EDGE_CONTAINS_IOC   = "contains_ioc"         # advisory → ioc
EDGE_TARGETS_SECTOR = "targets_sector"       # campaign/actor → sector
EDGE_EXPLOITS_CVE   = "exploits_cve"         # advisory/campaign → cve
EDGE_REUSES_IOC     = "reuses_ioc"           # cross-advisory IOC overlap
EDGE_SHARES_TTP     = "shares_ttp"           # cross-advisory TTP overlap
EDGE_EVOLVES_FROM   = "evolves_from"         # campaign temporal succession
EDGE_CORRELATES_TO  = "correlates_to"        # generic correlation link
EDGE_USES_MALWARE   = "uses_malware"         # advisory/actor → malware


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum IOC overlap to assert an infrastructure reuse link
_IOC_REUSE_THRESHOLD = 1

# Minimum shared TTP count to assert a TTP correlation link
_TTP_CORRELATION_THRESHOLD = 2

# Maximum graph nodes before capping (performance safety)
_MAX_GRAPH_NODES = 50000

# Maximum advisories processed per corpus run
_MAX_CORPUS_SIZE = 20000

# Known malware families for detection
_MALWARE_FAMILIES: frozenset = frozenset({
    "lockbit", "blackcat", "alphv", "conti", "ryuk", "emotet", "cobalt strike",
    "mimikatz", "metasploit", "qakbot", "icedid", "dridex", "trickbot",
    "darkside", "blackmatter", "revil", "sodinokibi", "clop", "cuba",
    "ragnarlocker", "hive", "play", "royal", "akira", "blackbasta",
    "lazarus", "bluenoroff", "kimsuky", "apt28", "cozy bear", "fancy bear",
    "apt29", "apt41", "apt10", "turla", "sandworm", "volt typhoon",
    "scattered spider", "lapsus", "nighthawk", "brute ratel", "havoc",
    "sliver", "badnews", "plugx", "poison ivy", "remcos", "asyncrat",
})

# Geographic nexus patterns
_GEO_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\b(china|chinese|prc|beijing|guangdong)\b', re.I), "China"),
    (re.compile(r'\b(russia|russian|moscow|kremlin|gru|fsb|svr)\b', re.I), "Russia"),
    (re.compile(r'\b(north korea|dprk|pyongyang|lazarus)\b', re.I), "North Korea"),
    (re.compile(r'\b(iran|iranian|tehran|irgc)\b', re.I), "Iran"),
    (re.compile(r'\b(eastern europe|ex-soviet|ukraine|belarus)\b', re.I), "Eastern Europe"),
    (re.compile(r'\b(india|indian)\b', re.I), "India"),
    (re.compile(r'\b(pakistan|pakistani)\b', re.I), "Pakistan"),
]


# ---------------------------------------------------------------------------
# Internal Helpers
# ---------------------------------------------------------------------------

def _safe_str(v: Any, maxlen: int = 200) -> str:
    """Safe string extraction with length cap."""
    if v is None:
        return ""
    s = str(v)
    return s[:maxlen] if len(s) > maxlen else s


def _extract_cve_ids(item: Dict[str, Any]) -> List[str]:
    """Extract CVE IDs from advisory item."""
    combined = " ".join([
        _safe_str(item.get("title")),
        _safe_str(item.get("description")),
        _safe_str(item.get("cve_id")),
    ])
    return list({m.upper() for m in re.findall(r'CVE-\d{4}-\d+', combined)})


def _extract_malware_families(item: Dict[str, Any]) -> List[str]:
    """Extract known malware family names from advisory."""
    combined = " ".join([
        _safe_str(item.get("title")),
        _safe_str(item.get("description")),
        _safe_str(item.get("actor_cluster")),
        _safe_str(item.get("malware_family")),
    ]).lower()
    found = []
    for mw in _MALWARE_FAMILIES:
        if mw in combined:
            found.append(mw.title())
    return found


def _extract_geo_nexus(item: Dict[str, Any]) -> List[str]:
    """Extract geographic nexus from advisory text."""
    combined = " ".join([
        _safe_str(item.get("description")),
        _safe_str(item.get("actor_cluster")),
        _safe_str(item.get("geo_nexus")),
        _safe_str(item.get("campaign")),
    ])
    found = []
    for pattern, geo in _GEO_PATTERNS:
        if pattern.search(combined):
            found.append(geo)
    return list(set(found))


def _extract_sectors(item: Dict[str, Any]) -> List[str]:
    """Extract targeted sectors from advisory."""
    sectors = []
    raw_sectors = item.get("sectors") or item.get("targeted_sectors") or item.get("sector")
    if isinstance(raw_sectors, list):
        sectors.extend([_safe_str(s, 60) for s in raw_sectors if s])
    elif isinstance(raw_sectors, str) and raw_sectors:
        sectors.append(_safe_str(raw_sectors, 60))

    # Auto-detect from description
    combined = " ".join([
        _safe_str(item.get("description")),
        _safe_str(item.get("title")),
    ]).lower()

    sector_keywords = {
        "healthcare": ["hospital", "healthcare", "medical", "pharma", "clinic"],
        "finance": ["bank", "financial", "fintech", "insurance", "payment"],
        "energy": ["energy", "power grid", "utility", "oil", "gas", "pipeline"],
        "government": ["government", "federal", "ministry", "military", "defense"],
        "critical infrastructure": ["critical infrastructure", "water treatment", "nuclear"],
        "manufacturing": ["manufacturing", "industrial", "factory", "production"],
        "education": ["university", "school", "education", "academic"],
        "technology": ["software", "saas", "cloud provider", "tech company"],
        "retail": ["retail", "e-commerce", "consumer"],
        "transportation": ["logistics", "shipping", "aviation", "railway"],
    }
    for sector, keywords in sector_keywords.items():
        if any(kw in combined for kw in keywords):
            if sector not in [s.lower() for s in sectors]:
                sectors.append(sector.title())

    return list(set(sectors))[:10]  # Cap at 10 sectors


def _extract_ioc_values(item: Dict[str, Any]) -> Set[str]:
    """Extract normalised IOC values for graph hashing."""
    iocs = item.get("iocs") or []
    values = set()
    for ioc in iocs:
        if isinstance(ioc, dict):
            v = str(ioc.get("value") or ioc.get("ioc") or "").strip()
        else:
            v = str(ioc).strip()
        if v and len(v) >= 4:
            values.add(v.lower())
    return values


def _extract_ttp_ids(item: Dict[str, Any]) -> Set[str]:
    """Extract normalised ATT&CK technique IDs."""
    ttps = item.get("ttps") or item.get("techniques") or []
    ids = set()
    for t in ttps:
        if isinstance(t, dict):
            tid = str(t.get("technique_id") or t.get("id") or "").upper()
        else:
            tid = str(t).upper()
        if re.match(r'^T\d{4}(\.\d{3})?$', tid):
            ids.add(tid)
    return ids


def _normalise_actor(actor: str) -> str:
    """Normalise actor cluster name for graph node deduplication."""
    a = actor.strip()
    # Strip generic artifact prefixes
    artifact = {"unknown cluster", "cdb-cve-gen", "cdb-ran-gen", "cdb-apt-gen",
                "unclassified", "unknown", "n/a", "none", "automated cve exploitation cluster"}
    if a.lower() in artifact:
        return ""
    return a


def _node_id(node_type: str, value: str) -> str:
    """Generate deterministic node ID from type + value."""
    key = f"{node_type}::{value.lower().strip()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:20]


def _parse_date(item: Dict[str, Any]) -> Optional[datetime]:
    """Parse advisory date, return None if unparseable."""
    for field in ("published", "date", "created", "processed", "fetched_at"):
        val = item.get(field)
        if val and isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                continue
    return None


# ---------------------------------------------------------------------------
# Graph Construction Engine
# ---------------------------------------------------------------------------

class CampaignGraph:
    """
    Persistent in-memory adversary campaign knowledge graph.

    Nodes: advisories, actors, campaigns, IOCs, TTPs, sectors, CVEs, malware, geo
    Edges: attributed_to, part_of, uses_ttp, contains_ioc, targets_sector, etc.
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}    # node_id → node_data
        self.edges: List[Dict[str, Any]] = []          # edge list
        self._edge_set: Set[Tuple[str, str, str]] = set()  # dedup (src, rel, dst)
        self._ioc_index: Dict[str, List[str]] = defaultdict(list)   # ioc_val → [advisory_ids]
        self._ttp_index: Dict[str, List[str]] = defaultdict(list)   # ttp_id → [advisory_ids]
        self._actor_index: Dict[str, List[str]] = defaultdict(list) # actor → [advisory_ids]
        self._sector_index: Dict[str, List[str]] = defaultdict(list) # sector → [advisory_ids]
        self._cve_index: Dict[str, List[str]] = defaultdict(list)   # cve_id → [advisory_ids]
        self._malware_index: Dict[str, List[str]] = defaultdict(list) # malware → [advisory_ids]
        self._date_index: Dict[str, datetime] = {}    # advisory_id → datetime
        self._stats: Dict[str, int] = defaultdict(int)

    def _add_node(self, node_type: str, node_id: str, **attrs: Any) -> None:
        """Add or update a graph node."""
        if len(self.nodes) >= _MAX_GRAPH_NODES:
            return
        if node_id not in self.nodes:
            self.nodes[node_id] = {"type": node_type, "id": node_id, **attrs}
            self._stats[f"nodes_{node_type}"] += 1
        else:
            # Merge attributes
            existing = self.nodes[node_id]
            for k, v in attrs.items():
                if k not in existing or not existing[k]:
                    existing[k] = v

    def _add_edge(self, src_id: str, rel: str, dst_id: str, **attrs: Any) -> None:
        """Add a directed edge to the graph (deduplicated)."""
        key = (src_id, rel, dst_id)
        if key in self._edge_set:
            return
        self._edge_set.add(key)
        self.edges.append({
            "source": src_id,
            "relation": rel,
            "target": dst_id,
            **attrs,
        })
        self._stats["edges_total"] += 1

    def ingest_advisory(self, item: Dict[str, Any]) -> str:
        """
        Ingest a single advisory into the campaign graph.
        Returns the advisory node ID.
        Bounded, exception-isolated, never raises.
        """
        try:
            advisory_id = str(
                item.get("stix_id") or item.get("id") or
                item.get("title") or f"advisory_{self._stats['nodes_advisory']}"
            )
            adv_node_id = _node_id(NODE_ADVISORY, advisory_id)

            # Parse date
            dt = _parse_date(item)
            if dt:
                self._date_index[adv_node_id] = dt

            # ── Advisory node ──────────────────────────────────────────────────
            self._add_node(
                NODE_ADVISORY,
                adv_node_id,
                label=_safe_str(item.get("title"), 120),
                stix_id=advisory_id,
                severity=_safe_str(item.get("severity")),
                risk_score=item.get("risk_score"),
                kev=bool(item.get("kev") or item.get("in_kev") or item.get("kev_present")),
                date=dt.isoformat() if dt else None,
                source=_safe_str(item.get("source") or item.get("feed_source"), 80),
            )
            self._stats["nodes_advisory"] += 1

            # ── Actor node + edge ──────────────────────────────────────────────
            actor_raw = _safe_str(item.get("actor_cluster") or item.get("actor"), 100)
            actor = _normalise_actor(actor_raw)
            if actor:
                actor_node_id = _node_id(NODE_ACTOR, actor)
                self._add_node(NODE_ACTOR, actor_node_id, label=actor)
                self._add_edge(adv_node_id, EDGE_ATTRIBUTED_TO, actor_node_id,
                                weight=1.0, advisory_id=advisory_id)
                self._actor_index[actor].append(adv_node_id)

            # ── Campaign node + edge ───────────────────────────────────────────
            campaign_raw = _safe_str(item.get("campaign") or item.get("campaign_cluster"), 100)
            if campaign_raw and campaign_raw.upper() not in ("UNCLASSIFIED", "N/A", "NONE", ""):
                camp_node_id = _node_id(NODE_CAMPAIGN, campaign_raw)
                self._add_node(NODE_CAMPAIGN, camp_node_id, label=campaign_raw)
                self._add_edge(adv_node_id, EDGE_PART_OF, camp_node_id,
                                weight=1.0, advisory_id=advisory_id)

            # ── CVE nodes + edges ──────────────────────────────────────────────
            cve_ids = _extract_cve_ids(item)
            for cve_id in cve_ids[:20]:  # cap per advisory
                cve_node_id = _node_id(NODE_CVE, cve_id)
                self._add_node(NODE_CVE, cve_node_id, label=cve_id,
                                kev=bool(item.get("kev") or item.get("kev_present")))
                self._add_edge(adv_node_id, EDGE_EXPLOITS_CVE, cve_node_id,
                                advisory_id=advisory_id)
                self._cve_index[cve_id].append(adv_node_id)

            # ── TTP nodes + edges ──────────────────────────────────────────────
            ttp_ids = _extract_ttp_ids(item)
            for ttp_id in list(ttp_ids)[:30]:  # cap per advisory
                ttp_node_id = _node_id(NODE_TTP, ttp_id)
                self._add_node(NODE_TTP, ttp_node_id, label=ttp_id)
                self._add_edge(adv_node_id, EDGE_USES_TTP, ttp_node_id,
                                advisory_id=advisory_id)
                self._ttp_index[ttp_id].append(adv_node_id)
                # Actor → TTP if actor known
                if actor:
                    actor_node_id = _node_id(NODE_ACTOR, actor)
                    self._add_edge(actor_node_id, EDGE_USES_TTP, ttp_node_id, weight=0.8)

            # ── IOC nodes + edges ──────────────────────────────────────────────
            ioc_values = _extract_ioc_values(item)
            for ioc_val in list(ioc_values)[:50]:  # cap per advisory
                ioc_node_id = _node_id(NODE_IOC, ioc_val)
                self._add_node(NODE_IOC, ioc_node_id, label=ioc_val[:80])
                self._add_edge(adv_node_id, EDGE_CONTAINS_IOC, ioc_node_id,
                                advisory_id=advisory_id)
                self._ioc_index[ioc_val].append(adv_node_id)

            # ── Sector nodes + edges ───────────────────────────────────────────
            sectors = _extract_sectors(item)
            for sector in sectors:
                sec_node_id = _node_id(NODE_SECTOR, sector)
                self._add_node(NODE_SECTOR, sec_node_id, label=sector)
                self._add_edge(adv_node_id, EDGE_TARGETS_SECTOR, sec_node_id,
                                advisory_id=advisory_id)
                self._sector_index[sector].append(adv_node_id)
                if actor:
                    actor_node_id = _node_id(NODE_ACTOR, actor)
                    self._add_edge(actor_node_id, EDGE_TARGETS_SECTOR, sec_node_id, weight=0.7)

            # ── Malware nodes + edges ──────────────────────────────────────────
            malware_families = _extract_malware_families(item)
            for mw in malware_families[:5]:  # cap per advisory
                mw_node_id = _node_id(NODE_MALWARE, mw)
                self._add_node(NODE_MALWARE, mw_node_id, label=mw)
                self._add_edge(adv_node_id, EDGE_USES_MALWARE, mw_node_id,
                                advisory_id=advisory_id)
                self._malware_index[mw].append(adv_node_id)

            # ── Geographic nexus nodes ─────────────────────────────────────────
            geo_list = _extract_geo_nexus(item)
            for geo in geo_list[:3]:  # cap per advisory
                geo_node_id = _node_id(NODE_GEO, geo)
                self._add_node(NODE_GEO, geo_node_id, label=geo)
                if actor:
                    actor_node_id = _node_id(NODE_ACTOR, actor)
                    self._add_edge(actor_node_id, EDGE_CORRELATES_TO, geo_node_id, weight=0.6)

            return adv_node_id

        except Exception as exc:
            log.error("ingest_advisory failed for item: %s", exc)
            return ""

    def build_cross_advisory_edges(self) -> Dict[str, int]:
        """
        Build cross-advisory correlation edges:
        - IOC reuse (shared infrastructure)
        - TTP overlap (shared kill-chain techniques)
        Returns counts of each edge type added.
        """
        edge_counts: Dict[str, int] = defaultdict(int)

        # ── IOC reuse edges ────────────────────────────────────────────────────
        for ioc_val, adv_ids in self._ioc_index.items():
            if len(adv_ids) < 2:
                continue
            # Connect each pair of advisories sharing this IOC
            for i in range(len(adv_ids)):
                for j in range(i + 1, min(len(adv_ids), 20)):  # cap pairs
                    src, dst = adv_ids[i], adv_ids[j]
                    if src and dst and src != dst:
                        self._add_edge(src, EDGE_REUSES_IOC, dst,
                                       shared_ioc=ioc_val[:60], weight=0.9)
                        edge_counts["ioc_reuse"] += 1

        # ── TTP overlap edges ──────────────────────────────────────────────────
        # Group advisories by shared TTP and add correlation edges for pairs
        # with _TTP_CORRELATION_THRESHOLD or more shared techniques
        adv_ttp_sets: Dict[str, Set[str]] = defaultdict(set)
        for ttp_id, adv_ids in self._ttp_index.items():
            for adv_id in adv_ids:
                adv_ttp_sets[adv_id].add(ttp_id)

        adv_list = list(adv_ttp_sets.keys())
        for i in range(len(adv_list)):
            for j in range(i + 1, min(len(adv_list), 500)):  # cap comparison
                src, dst = adv_list[i], adv_list[j]
                shared = adv_ttp_sets[src] & adv_ttp_sets[dst]
                if len(shared) >= _TTP_CORRELATION_THRESHOLD:
                    self._add_edge(
                        src, EDGE_SHARES_TTP, dst,
                        shared_ttps=list(shared)[:10],
                        shared_count=len(shared),
                        weight=min(0.95, 0.5 + 0.05 * len(shared)),
                    )
                    edge_counts["ttp_overlap"] += 1

        log.info("Cross-advisory edges built: IOC_reuse=%d TTP_overlap=%d",
                 edge_counts["ioc_reuse"], edge_counts["ttp_overlap"])
        return dict(edge_counts)

    def get_stats(self) -> Dict[str, Any]:
        """Return graph statistics."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "advisory_nodes": self._stats.get("nodes_advisory", 0),
            "actor_nodes": len(self._actor_index),
            "unique_ttps": len(self._ttp_index),
            "unique_iocs": len(self._ioc_index),
            "unique_cves": len(self._cve_index),
            "unique_sectors": len(self._sector_index),
            "unique_malware": len(self._malware_index),
        }


# ---------------------------------------------------------------------------
# Intelligence Extraction from Graph
# ---------------------------------------------------------------------------

def extract_top_active_campaigns(
    graph: CampaignGraph,
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Extract top active campaigns by advisory count and infrastructure reuse.
    Returns ranked campaign intelligence suitable for executive dashboards.
    """
    try:
        # Count advisories per campaign node
        campaign_advisory_map: Dict[str, List[str]] = defaultdict(list)
        for edge in graph.edges:
            if edge["relation"] == EDGE_PART_OF:
                campaign_advisory_map[edge["target"]].append(edge["source"])

        # Count advisories per actor (as proxy for active campaigns)
        actor_advisory_map: Dict[str, List[str]] = defaultdict(list)
        for edge in graph.edges:
            if edge["relation"] == EDGE_ATTRIBUTED_TO:
                actor_advisory_map[edge["target"]].append(edge["source"])

        campaigns = []

        # Process explicit campaign nodes
        for camp_node_id, adv_node_ids in campaign_advisory_map.items():
            camp_node = graph.nodes.get(camp_node_id, {})
            if not camp_node:
                continue

            # Collect sectors this campaign targets
            camp_sectors = set()
            for adv_id in adv_node_ids:
                for edge in graph.edges:
                    if edge["source"] == adv_id and edge["relation"] == EDGE_TARGETS_SECTOR:
                        tgt = graph.nodes.get(edge["target"], {})
                        if tgt.get("label"):
                            camp_sectors.add(tgt["label"])

            # Collect TTPs
            camp_ttps: Set[str] = set()
            for adv_id in adv_node_ids:
                for ttp_id, ttp_advs in graph._ttp_index.items():
                    if adv_id in ttp_advs:
                        camp_ttps.add(ttp_id)

            # Collect CVEs
            camp_cves: Set[str] = set()
            for adv_id in adv_node_ids:
                for edge in graph.edges:
                    if edge["source"] == adv_id and edge["relation"] == EDGE_EXPLOITS_CVE:
                        cve_node = graph.nodes.get(edge["target"], {})
                        if cve_node.get("label"):
                            camp_cves.add(cve_node["label"])

            # Determine date range
            dates = [graph._date_index[adv_id] for adv_id in adv_node_ids
                     if adv_id in graph._date_index]
            first_seen = min(dates).isoformat() if dates else None
            last_seen  = max(dates).isoformat() if dates else None

            campaigns.append({
                "campaign_id": camp_node_id,
                "campaign_name": camp_node.get("label", "Unknown Campaign"),
                "advisory_count": len(adv_node_ids),
                "targeted_sectors": sorted(camp_sectors)[:8],
                "ttp_count": len(camp_ttps),
                "top_ttps": sorted(camp_ttps)[:10],
                "cves_exploited": sorted(camp_cves)[:10],
                "first_seen": first_seen,
                "last_seen": last_seen,
                "activity_score": len(adv_node_ids) * 2 + len(camp_ttps) * 0.5,
            })

        # Sort by activity score
        campaigns.sort(key=lambda x: -x["activity_score"])
        return campaigns[:top_n]

    except Exception as exc:
        log.error("extract_top_active_campaigns failed: %s", exc)
        return []


def extract_actor_evolution_timeline(
    graph: CampaignGraph,
    actor_name: Optional[str] = None,
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Extract actor evolution timelines showing capability and targeting changes.
    If actor_name specified, returns that actor's timeline.
    Otherwise returns top N most active actors.
    """
    try:
        # Build per-actor timelines
        actor_timelines: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for actor, adv_ids in graph._actor_index.items():
            if actor_name and actor.lower() != actor_name.lower():
                continue

            for adv_id in adv_ids:
                dt = graph._date_index.get(adv_id)
                adv_node = graph.nodes.get(adv_id, {})
                if not adv_node:
                    continue

                # Collect TTPs for this advisory
                ttps = [
                    graph.nodes[e["target"]]["label"]
                    for e in graph.edges
                    if e["source"] == adv_id and e["relation"] == EDGE_USES_TTP
                    and e["target"] in graph.nodes
                ]

                # Collect sectors
                sectors = [
                    graph.nodes[e["target"]]["label"]
                    for e in graph.edges
                    if e["source"] == adv_id and e["relation"] == EDGE_TARGETS_SECTOR
                    and e["target"] in graph.nodes
                ]

                actor_timelines[actor].append({
                    "advisory_id": adv_node.get("stix_id", adv_id),
                    "title": adv_node.get("label", ""),
                    "date": dt.isoformat() if dt else None,
                    "severity": adv_node.get("severity", ""),
                    "kev": adv_node.get("kev", False),
                    "ttps": ttps[:8],
                    "sectors": sectors[:5],
                })

        # Build actor summaries
        actor_summaries = []
        for actor, events in actor_timelines.items():
            events.sort(key=lambda e: e.get("date") or "")
            all_ttps = set(ttp for e in events for ttp in e["ttps"])
            all_sectors = set(s for e in events for s in e["sectors"])
            kev_events = sum(1 for e in events if e.get("kev"))
            dates = [e["date"] for e in events if e.get("date")]
            actor_summaries.append({
                "actor": actor,
                "total_advisories": len(events),
                "unique_ttps": len(all_ttps),
                "targeted_sectors": sorted(all_sectors)[:8],
                "kev_exploited_count": kev_events,
                "first_observed": min(dates) if dates else None,
                "last_observed": max(dates) if dates else None,
                "timeline": events[:50],  # cap timeline entries
                "activity_score": len(events) * 3 + len(all_ttps) * 0.5 + kev_events * 5,
            })

        actor_summaries.sort(key=lambda x: -x["activity_score"])
        return actor_summaries[:top_n]

    except Exception as exc:
        log.error("extract_actor_evolution_timeline failed: %s", exc)
        return []


def extract_infrastructure_reuse_clusters(
    graph: CampaignGraph,
    min_cluster_size: int = 2,
) -> List[Dict[str, Any]]:
    """
    Identify adversary infrastructure reuse clusters — IOCs shared across advisories.
    Returns clusters ranked by reuse breadth.
    """
    try:
        clusters = []

        for ioc_val, adv_ids in graph._ioc_index.items():
            if len(adv_ids) < min_cluster_size:
                continue

            # Get advisory metadata for each advisory in the cluster
            cluster_advisories = []
            for adv_id in adv_ids[:20]:  # cap
                adv_node = graph.nodes.get(adv_id, {})
                if adv_node:
                    cluster_advisories.append({
                        "id": adv_node.get("stix_id", adv_id),
                        "title": adv_node.get("label", "")[:80],
                        "date": adv_node.get("date"),
                        "severity": adv_node.get("severity"),
                    })

            # Get actors associated with this IOC cluster
            cluster_actors = set()
            for adv_id in adv_ids[:20]:
                for edge in graph.edges:
                    if edge["source"] == adv_id and edge["relation"] == EDGE_ATTRIBUTED_TO:
                        actor_node = graph.nodes.get(edge["target"], {})
                        if actor_node.get("label"):
                            cluster_actors.add(actor_node["label"])

            clusters.append({
                "shared_ioc": ioc_val[:80],
                "reuse_count": len(adv_ids),
                "advisories": cluster_advisories,
                "actors_involved": sorted(cluster_actors)[:5],
                "infrastructure_confidence": min(1.0, 0.5 + 0.1 * len(adv_ids)),
                "significance": (
                    "CRITICAL" if len(adv_ids) >= 5 else
                    "HIGH" if len(adv_ids) >= 3 else
                    "MODERATE"
                ),
            })

        clusters.sort(key=lambda x: -x["reuse_count"])
        return clusters

    except Exception as exc:
        log.error("extract_infrastructure_reuse_clusters failed: %s", exc)
        return []


def extract_attack_chain_intelligence(
    graph: CampaignGraph,
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    Extract attack chain intelligence — TTP combinations that appear together.
    Returns ranked ATT&CK tactic chains for SOC detection engineering.
    """
    try:
        # Build per-advisory TTP sets
        adv_ttp_map: Dict[str, List[str]] = defaultdict(list)
        for ttp_id, adv_ids in graph._ttp_index.items():
            for adv_id in adv_ids:
                adv_ttp_map[adv_id].append(ttp_id)

        # Count TTP co-occurrence pairs
        pair_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        for adv_id, ttps in adv_ttp_map.items():
            ttp_list = sorted(ttps)
            for i in range(len(ttp_list)):
                for j in range(i + 1, min(len(ttp_list), 15)):
                    pair = (ttp_list[i], ttp_list[j])
                    pair_counts[pair] += 1

        # Rank by co-occurrence
        top_pairs = sorted(pair_counts.items(), key=lambda x: -x[1])[:top_n * 3]

        chains = []
        seen_anchors: Set[str] = set()
        for (t1, t2), count in top_pairs:
            if t1 in seen_anchors or len(chains) >= top_n:
                continue
            seen_anchors.add(t1)

            # Find additional TTPs commonly associated with this pair
            related_ttps: Dict[str, int] = defaultdict(int)
            for adv_id, ttps in adv_ttp_map.items():
                if t1 in ttps and t2 in ttps:
                    for t in ttps:
                        if t not in (t1, t2):
                            related_ttps[t] += 1

            extended_chain = [t1, t2] + sorted(related_ttps, key=lambda k: -related_ttps[k])[:4]

            # Count how many advisories use this chain
            advisory_count = sum(
                1 for adv_id, ttps in adv_ttp_map.items()
                if t1 in ttps and t2 in ttps
            )

            chains.append({
                "primary_pair": [t1, t2],
                "extended_chain": extended_chain[:8],
                "co_occurrence_count": count,
                "advisory_count": advisory_count,
                "significance": (
                    "CRITICAL" if count >= 10 else
                    "HIGH" if count >= 5 else
                    "MODERATE"
                ),
                "detection_priority": "P0" if count >= 10 else "P1" if count >= 5 else "P2",
            })

        return chains

    except Exception as exc:
        log.error("extract_attack_chain_intelligence failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Campaign Graph Report Generator
# ---------------------------------------------------------------------------

def generate_campaign_graph_report(graph: CampaignGraph) -> Dict[str, Any]:
    """
    Generate the full persistent campaign graph intelligence report.
    Produces all intelligence surfaces required for OCIOS command center.
    """
    try:
        # Build cross-advisory edges before extraction
        edge_counts = graph.build_cross_advisory_edges()

        stats = graph.get_stats()

        # Top active campaigns
        top_campaigns = extract_top_active_campaigns(graph, top_n=15)

        # Actor evolution timelines (top 10 actors)
        actor_timelines = extract_actor_evolution_timeline(graph, top_n=10)

        # Infrastructure reuse clusters
        infra_clusters = extract_infrastructure_reuse_clusters(graph, min_cluster_size=2)

        # Attack chain intelligence
        attack_chains = extract_attack_chain_intelligence(graph, top_n=15)

        # Sector targeting heatmap
        sector_heatmap = {
            sector: len(adv_ids)
            for sector, adv_ids in sorted(
                graph._sector_index.items(),
                key=lambda x: -len(x[1])
            )[:20]
        }

        # Most active actors by advisory count
        top_actors = sorted(
            graph._actor_index.items(),
            key=lambda x: -len(x[1])
        )[:15]
        top_actors_summary = [
            {"actor": actor, "advisory_count": len(adv_ids)}
            for actor, adv_ids in top_actors
        ]

        # Most common CVEs across corpus
        top_cves = sorted(
            graph._cve_index.items(),
            key=lambda x: -len(x[1])
        )[:20]
        top_cves_summary = [
            {"cve_id": cve_id, "advisory_count": len(adv_ids)}
            for cve_id, adv_ids in top_cves
        ]

        # Most deployed malware
        top_malware = sorted(
            graph._malware_index.items(),
            key=lambda x: -len(x[1])
        )[:10]
        top_malware_summary = [
            {"malware": mw, "advisory_count": len(adv_ids)}
            for mw, adv_ids in top_malware
        ]

        # IOC reuse summary
        reuse_summary = {
            "total_shared_iocs": sum(1 for v in graph._ioc_index.values() if len(v) >= 2),
            "high_reuse_iocs": sum(1 for v in graph._ioc_index.values() if len(v) >= 3),
            "critical_reuse_iocs": sum(1 for v in graph._ioc_index.values() if len(v) >= 5),
        }

        report = {
            "engine": "persistent_campaign_graph_engine",
            "version": _VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "graph_stats": stats,
            "cross_advisory_edges": edge_counts,
            "top_active_campaigns": top_campaigns,
            "actor_evolution_timelines": actor_timelines,
            "infrastructure_reuse_clusters": infra_clusters[:50],  # cap output
            "attack_chain_intelligence": attack_chains,
            "sector_targeting_heatmap": sector_heatmap,
            "top_actors": top_actors_summary,
            "top_cves": top_cves_summary,
            "top_malware": top_malware_summary,
            "ioc_reuse_summary": reuse_summary,
        }

        log.info(
            "Campaign graph report generated: %d nodes %d edges %d campaigns %d actors",
            stats["total_nodes"], stats["total_edges"],
            len(top_campaigns), len(actor_timelines)
        )
        return report

    except Exception as exc:
        log.error("generate_campaign_graph_report failed: %s", exc)
        return {
            "engine": "persistent_campaign_graph_engine",
            "version": _VERSION,
            "error": str(exc),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# HTML Report Renderer (for OCIOS dashboard surfaces)
# ---------------------------------------------------------------------------

def render_campaign_graph_html_summary(report: Dict[str, Any]) -> str:
    """
    Render a compact HTML executive summary of campaign graph intelligence.
    Suitable for embedding in OCIOS command center dashboard.
    """
    try:
        stats = report.get("graph_stats", {})
        top_campaigns = report.get("top_active_campaigns", [])
        top_actors = report.get("top_actors", [])
        sector_heatmap = report.get("sector_targeting_heatmap", {})
        infra_clusters = report.get("infrastructure_reuse_clusters", [])
        attack_chains = report.get("attack_chain_intelligence", [])

        # Stats bar
        stats_html = (
            f"<div class='pcge-stats-bar'>"
            f"<div class='pcge-stat'><span class='pcge-stat-val'>{stats.get('advisory_nodes', 0)}</span>"
            f"<span class='pcge-stat-label'>Advisories Indexed</span></div>"
            f"<div class='pcge-stat'><span class='pcge-stat-val'>{stats.get('actor_nodes', 0)}</span>"
            f"<span class='pcge-stat-label'>Threat Actors Tracked</span></div>"
            f"<div class='pcge-stat'><span class='pcge-stat-val'>{stats.get('unique_ttps', 0)}</span>"
            f"<span class='pcge-stat-label'>Unique ATT&CK TTPs</span></div>"
            f"<div class='pcge-stat'><span class='pcge-stat-val'>{stats.get('unique_iocs', 0)}</span>"
            f"<span class='pcge-stat-label'>Unique IOCs Indexed</span></div>"
            f"<div class='pcge-stat'><span class='pcge-stat-val'>{stats.get('total_edges', 0)}</span>"
            f"<span class='pcge-stat-label'>Intelligence Relationships</span></div>"
            f"</div>"
        )

        # Top campaigns
        camp_rows = ""
        for c in top_campaigns[:5]:
            camp_rows += (
                f"<tr><td class='pcge-td'>{c['campaign_name']}</td>"
                f"<td class='pcge-td'>{c['advisory_count']}</td>"
                f"<td class='pcge-td'>{c['ttp_count']}</td>"
                f"<td class='pcge-td'>{', '.join(c['targeted_sectors'][:3])}</td>"
                f"<td class='pcge-td pcge-last-seen'>{(c.get('last_seen') or '')[:10]}</td></tr>"
            )
        campaigns_html = (
            f"<div class='pcge-section'>"
            f"<div class='pcge-section-title'>Top Active Campaigns</div>"
            f"<table class='pcge-table'><thead><tr>"
            f"<th>Campaign</th><th>Advisories</th><th>TTPs</th><th>Sectors</th><th>Last Active</th>"
            f"</tr></thead><tbody>{camp_rows}</tbody></table>"
            f"</div>"
        ) if camp_rows else ""

        # Top actors
        actor_rows = "".join(
            f"<div class='pcge-actor-row'>"
            f"<span class='pcge-actor-name'>{a['actor']}</span>"
            f"<span class='pcge-actor-count'>{a['advisory_count']} advisories</span>"
            f"</div>"
            for a in top_actors[:8]
        )

        # Infrastructure reuse
        critical_clusters = [c for c in infra_clusters if c.get("significance") == "CRITICAL"]
        infra_html = ""
        if critical_clusters:
            infra_html = (
                f"<div class='pcge-section pcge-critical'>"
                f"<div class='pcge-section-title'>Critical Infrastructure Reuse ({len(critical_clusters)} clusters)</div>"
                f"<p>IOCs shared across 5+ advisories indicate persistent adversary infrastructure — "
                f"high-confidence attribution and pivot opportunity for threat hunting.</p>"
                f"</div>"
            )

        # Attack chains
        chain_rows = ""
        for ch in attack_chains[:5]:
            chain_str = " → ".join(ch["extended_chain"][:6])
            chain_rows += (
                f"<div class='pcge-chain-row'>"
                f"<span class='pcge-chain-badge pcge-{ch['detection_priority'].lower()}'>{ch['detection_priority']}</span>"
                f"<span class='pcge-chain'>{chain_str}</span>"
                f"<span class='pcge-chain-count'>{ch['advisory_count']} advisories</span>"
                f"</div>"
            )

        # Sector heatmap
        sector_html = "".join(
            f"<div class='pcge-sector-row'>"
            f"<span class='pcge-sector-name'>{sector}</span>"
            f"<div class='pcge-sector-bar' style='width:{min(100, count * 5)}%'></div>"
            f"<span class='pcge-sector-count'>{count}</span>"
            f"</div>"
            for sector, count in list(sector_heatmap.items())[:8]
        )

        generated_at = report.get("generated_at", "")[:19].replace("T", " ")

        html = (
            f"<div class='persistent-campaign-graph'>"
            f"<div class='pcge-header'>"
            f"<h3>OCIOS Persistent Campaign Intelligence Graph</h3>"
            f"<span class='pcge-ts'>Generated: {generated_at} UTC | Engine v{_VERSION}</span>"
            f"</div>"
            f"{stats_html}"
            f"{campaigns_html}"
            f"<div class='pcge-columns'>"
            f"<div class='pcge-col'>"
            f"<div class='pcge-section-title'>Top Threat Actors</div>{actor_rows}"
            f"</div>"
            f"<div class='pcge-col'>"
            f"<div class='pcge-section-title'>Sector Targeting Heatmap</div>{sector_html}"
            f"</div>"
            f"</div>"
            f"{infra_html}"
            f"<div class='pcge-section'>"
            f"<div class='pcge-section-title'>ATT&CK Chain Intelligence</div>"
            f"{chain_rows}"
            f"</div>"
            f"</div>"
        )
        return html

    except Exception as exc:
        log.error("render_campaign_graph_html_summary failed: %s", exc)
        return f"<div class='pcge-error'>Campaign graph rendering unavailable: {exc}</div>"


# ---------------------------------------------------------------------------
# Corpus Processing Entry Point
# ---------------------------------------------------------------------------

def build_graph_from_corpus(
    items: List[Dict[str, Any]],
    max_items: int = _MAX_CORPUS_SIZE,
) -> CampaignGraph:
    """
    Build a persistent campaign graph from a corpus of advisory items.
    Bounded, deterministic, exception-isolated. Never raises.
    Returns a fully populated CampaignGraph.
    """
    graph = CampaignGraph()
    processed = 0
    errors = 0

    for item in items[:max_items]:
        try:
            graph.ingest_advisory(item)
            processed += 1
        except Exception as exc:
            log.error("build_graph_from_corpus: item %d failed: %s", processed, exc)
            errors += 1

    log.info(
        "build_graph_from_corpus: processed=%d errors=%d nodes=%d edges=%d",
        processed, errors, len(graph.nodes), len(graph.edges)
    )
    return graph


def run_corpus_campaign_intelligence(
    items: List[Dict[str, Any]],
    output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Complete pipeline: ingest corpus → build graph → extract intelligence → report.
    Safe entry point for integration with OCIOS coordinator.
    Never raises.
    """
    try:
        graph = build_graph_from_corpus(items)
        report = generate_campaign_graph_report(graph)

        if output_path:
            try:
                import os
                os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False, default=str)
                log.info("Campaign graph report written: %s", output_path)
            except Exception as write_exc:
                log.error("Failed to write campaign graph report: %s", write_exc)

        return report

    except Exception as exc:
        log.error("run_corpus_campaign_intelligence failed: %s", exc)
        return {
            "engine": "persistent_campaign_graph_engine",
            "version": _VERSION,
            "error": str(exc),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "CampaignGraph",
    "build_graph_from_corpus",
    "generate_campaign_graph_report",
    "render_campaign_graph_html_summary",
    "run_corpus_campaign_intelligence",
    "extract_top_active_campaigns",
    "extract_actor_evolution_timeline",
    "extract_infrastructure_reuse_clusters",
    "extract_attack_chain_intelligence",
    "_VERSION",
]
