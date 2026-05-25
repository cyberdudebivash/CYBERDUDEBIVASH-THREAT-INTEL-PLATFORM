#!/usr/bin/env python3
"""
threat_graph_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v164.0
===============================================================
THREAT GRAPH ENGINE — AI-Native Cyber Intelligence OS Layer

Transforms the advisory corpus into a queryable threat intelligence graph:
  Nodes: advisories, IOCs (CVE/domain/IP/hash/URL), actors, TTPs, campaigns
  Edges: CONTAINS_IOC, MAPS_TTP, ATTRIBUTES_ACTOR, USES_TTP, RELATED_TO, PART_OF

Output:
  api/graph/nodes.json  — node catalogue with metadata
  api/graph/edges.json  — directed edge list
  api/graph/stats.json  — graph statistics
  api/graph/pivot/      — pre-computed pivot indexes (actor→advisories, ttp→advisories, etc.)

This is the PROPRIETARY MOAT — no competitor has a queryable threat graph
served directly from advisory corpus at this scale and depth.

Monetization:
  Free:       node count summary only
  Pro:        full node list, no edge traversal
  Enterprise: full graph + pivot queries + actor correlation
  MSSP:       tenant-namespaced graph subsets

Stage 3.4.10 in sentinel-blogger.yml (after apex_v2, before R2 upload)
continue-on-error: true — non-blocking
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [THREAT-GRAPH] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("threat-graph-engine")

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
MANIFEST_PATH  = Path("data/feed_manifest.json")
FEED_PATH      = Path("api/feed.json")
GRAPH_DIR      = Path("api/graph")
PIVOT_DIR      = GRAPH_DIR / "pivot"

# ─────────────────────────────────────────────────────────────────────────────
# Node type constants
# ─────────────────────────────────────────────────────────────────────────────
NT_ADVISORY  = "advisory"
NT_CVE       = "cve"
NT_DOMAIN    = "domain"
NT_IP        = "ip"
NT_HASH      = "hash"
NT_URL_IOC   = "url_ioc"
NT_ACTOR     = "actor"
NT_TTP       = "ttp"
NT_CAMPAIGN  = "campaign"

# ─────────────────────────────────────────────────────────────────────────────
# Edge type constants
# ─────────────────────────────────────────────────────────────────────────────
ET_CONTAINS_IOC    = "CONTAINS_IOC"
ET_MAPS_TTP        = "MAPS_TTP"
ET_ATTRIBUTES      = "ATTRIBUTES_ACTOR"
ET_USES_TTP        = "USES_TTP"
ET_RELATED_TO      = "RELATED_TO"
ET_PART_OF         = "PART_OF"

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _node_id(node_type: str, value: str) -> str:
    """Stable deterministic node ID."""
    raw = f"{node_type}:{value.lower().strip()}"
    return hashlib.md5(raw.encode()).hexdigest()[:16]


def _edge_id(src: str, dst: str, rel: str) -> str:
    return hashlib.md5(f"{src}-{rel}-{dst}".encode()).hexdigest()[:16]


def _norm_cve(cve: str) -> str:
    return cve.strip().upper()


def _is_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _is_domain(s: str) -> bool:
    if "." not in s or s.startswith("http") or "/" in s:
        return False
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$", s))


def _classify_ioc(value: str) -> Optional[str]:
    """Return node_type for an IOC string, or None if unclassifiable."""
    v = value.strip()
    if re.match(r"^CVE-\d{4}-\d+$", v, re.IGNORECASE):
        return NT_CVE
    if re.match(r"^[a-fA-F0-9]{32,64}$", v):
        return NT_HASH
    if v.startswith("http://") or v.startswith("https://"):
        return NT_URL_IOC
    if _is_ip(v):
        return NT_IP
    if _is_domain(v):
        return NT_DOMAIN
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Graph Builder
# ─────────────────────────────────────────────────────────────────────────────

class ThreatGraphBuilder:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self._actor_ttp_cache: Dict[str, Set[str]] = defaultdict(set)

    # ── Node management ──────────────────────────────────────────────────────

    def _upsert_node(self, node_type: str, value: str, **meta) -> str:
        nid = _node_id(node_type, value)
        if nid not in self.nodes:
            self.nodes[nid] = {
                "id":         nid,
                "type":       node_type,
                "value":      value,
                "label":      value[:80],
                "degree":     0,
                **meta,
            }
        else:
            # Merge metadata
            for k, v in meta.items():
                if k not in self.nodes[nid] or not self.nodes[nid][k]:
                    self.nodes[nid][k] = v
        return nid

    def _upsert_edge(self, src: str, dst: str, rel: str, **meta) -> str:
        eid = _edge_id(src, dst, rel)
        if eid not in self.edges:
            self.edges[eid] = {
                "id":       eid,
                "source":   src,
                "target":   dst,
                "relation": rel,
                "weight":   1,
                **meta,
            }
            # Increment degree on both nodes
            if src in self.nodes:
                self.nodes[src]["degree"] += 1
            if dst in self.nodes:
                self.nodes[dst]["degree"] += 1
        else:
            self.edges[eid]["weight"] += 1
        return eid

    # ── Advisory ingestion ───────────────────────────────────────────────────

    def ingest_advisory(self, item: Dict[str, Any]) -> None:
        # ── Dual-schema support ───────────────────────────────────────────────
        # Enriched schema (api/feed.json):  id, actor_tag, iocs_by_type, ttps, risk_score
        # Raw manifest schema:              advisory_id, actors[], cves[], mitre_techniques[]
        adv_id   = item.get("id") or item.get("advisory_id") or item.get("stix_id") or ""
        title    = item.get("title", "")
        risk     = float(item.get("risk_score") or item.get("threat_score") or 0.0)
        severity = item.get("severity", "LOW")
        tlp      = item.get("tlp", "TLP:GREEN")
        ts       = item.get("processed_at") or item.get("timestamp") or item.get("published") or ""
        # actor_tag (enriched) or first item of actors[] (raw)
        actor    = item.get("actor_tag") or (
            (item.get("actors") or [""])[0] if item.get("actors") else ""
        )
        report   = item.get("report_url", "")
        kev      = item.get("kev_present", False)
        cvss     = item.get("cvss_score")
        epss     = item.get("epss_score")

        if not adv_id:
            return

        # Advisory node
        adv_nid = self._upsert_node(
            NT_ADVISORY, adv_id,
            title=title[:120],
            risk_score=risk,
            severity=severity,
            tlp=tlp,
            timestamp=ts,
            report_url=report,
            kev_present=kev,
            cvss_score=cvss,
            epss_score=epss,
        )

        # ── IOC nodes + edges ──────────────────────────────────────────────
        # Primary: iocs_by_type dict (structured)
        iocs_by_type = item.get("iocs_by_type") or {}
        processed_iocs: Set[str] = set()

        for ioc_type, values in iocs_by_type.items():
            if not isinstance(values, list):
                continue
            for v in values:
                v = str(v).strip()
                if not v or v in processed_iocs:
                    continue
                processed_iocs.add(v)
                nt = None
                if ioc_type == "cve":
                    nt = NT_CVE
                elif ioc_type in ("domain",):
                    nt = NT_DOMAIN
                elif ioc_type in ("ipv4", "ip"):
                    nt = NT_IP
                elif ioc_type in ("sha256", "sha1", "md5"):
                    nt = NT_HASH
                elif ioc_type == "url":
                    nt = NT_URL_IOC
                else:
                    nt = _classify_ioc(v)

                if nt:
                    ioc_nid = self._upsert_node(nt, v, ioc_type=ioc_type)
                    self._upsert_edge(adv_nid, ioc_nid, ET_CONTAINS_IOC)

        # Fallback: flat iocs list
        flat_iocs = item.get("iocs") or []
        for v in flat_iocs:
            v = str(v).strip()
            if v in processed_iocs:
                continue
            processed_iocs.add(v)
            nt = _classify_ioc(v)
            if nt:
                ioc_nid = self._upsert_node(nt, v)
                self._upsert_edge(adv_nid, ioc_nid, ET_CONTAINS_IOC)

        # ── CVE nodes from raw manifest cves[] list ─────────────────────────
        for cve_id in (item.get("cves") or []):
            cve_id = str(cve_id).strip()
            if re.match(r"^CVE-\d{4}-\d+$", cve_id, re.IGNORECASE):
                cve_nid = self._upsert_node(NT_CVE, cve_id.upper())
                self._upsert_edge(adv_nid, cve_nid, ET_CONTAINS_IOC)

        # ── TTP nodes + edges ──────────────────────────────────────────────
        # Enriched schema: ttps (list of objects) / mitre_tactics
        # Raw schema:      mitre_techniques (list of strings like "T1059")
        raw_ttps = (
            item.get("ttps") or
            item.get("mitre_tactics") or
            [{"id": t} for t in (item.get("mitre_techniques") or [])]
        )
        ttps = raw_ttps
        actor_nid = None

        for ttp in ttps:
            if isinstance(ttp, dict):
                tid   = ttp.get("id", "")
                tname = ttp.get("name", tid)
                tact  = ttp.get("tactic", "")
            elif isinstance(ttp, str):
                tid = ttp; tname = ttp; tact = ""
            else:
                continue
            if not tid:
                continue
            ttp_nid = self._upsert_node(NT_TTP, tid, name=tname, tactic=tact)
            self._upsert_edge(adv_nid, ttp_nid, ET_MAPS_TTP)
            if actor:
                self._actor_ttp_cache[actor].add(tid)

        # Tags (T-prefixed MITRE IDs from tags list)
        for tag in (item.get("tags") or []):
            if isinstance(tag, str) and re.match(r"^T\d{4}", tag):
                ttp_nid = self._upsert_node(NT_TTP, tag)
                self._upsert_edge(adv_nid, ttp_nid, ET_MAPS_TTP)
                if actor:
                    self._actor_ttp_cache[actor].add(tag)

        # ── Actor nodes + edges ────────────────────────────────────────────
        # Collect all actor values: actor_tag (enriched) + actors[] (raw manifest)
        all_actors: List[str] = []
        if actor:
            all_actors.append(actor)
        for a in (item.get("actors") or []):
            a = str(a).strip()
            if a and a not in all_actors:
                all_actors.append(a)

        for actor_val in all_actors:
            if not actor_val:
                continue
            unattr = actor_val in ("CDB-UNATTR-RAN", "CDB-UNATTR-CVE", "CDB-UNATTR-SUP",
                                   "CDB-UNATTR-APT", "CDB-UNATTR", "UNC-UNKNOWN")
            actor_nid = self._upsert_node(NT_ACTOR, actor_val,
                                           tracking_id=actor_val, unattributed=unattr)
            self._upsert_edge(adv_nid, actor_nid, ET_ATTRIBUTES)
            if actor_val not in self._actor_ttp_cache:
                self._actor_ttp_cache[actor_val]  # initialize

    # ── Post-processing ───────────────────────────────────────────────────────

    def _build_actor_ttp_edges(self) -> None:
        """After all advisories ingested, add actor→TTP edges from cache."""
        for actor_val, ttp_ids in self._actor_ttp_cache.items():
            actor_nid = _node_id(NT_ACTOR, actor_val)
            if actor_nid not in self.nodes:
                continue
            for tid in ttp_ids:
                ttp_nid = _node_id(NT_TTP, tid)
                if ttp_nid in self.nodes:
                    self._upsert_edge(actor_nid, ttp_nid, ET_USES_TTP)

    def _build_ioc_correlation_edges(self) -> None:
        """
        IOC cross-correlation: CVEs that appear in multiple advisories
        get RELATED_TO edges between those advisories (shared attack surface).
        """
        ioc_to_advisories: Dict[str, List[str]] = defaultdict(list)
        for eid, edge in self.edges.items():
            if edge["relation"] == ET_CONTAINS_IOC:
                src = edge["source"]  # advisory node
                dst = edge["target"]  # ioc node
                if self.nodes.get(src, {}).get("type") == NT_ADVISORY:
                    ioc_to_advisories[dst].append(src)

        related_added = 0
        for ioc_nid, adv_nids in ioc_to_advisories.items():
            if len(adv_nids) < 2:
                continue
            # Create RELATED_TO edges between advisory pairs sharing this IOC
            for i, a1 in enumerate(adv_nids):
                for a2 in adv_nids[i+1:]:
                    ioc_val = self.nodes.get(ioc_nid, {}).get("value", "")
                    self._upsert_edge(a1, a2, ET_RELATED_TO, via_ioc=ioc_val)
                    related_added += 1

        if related_added:
            log.info("IOC correlation: %d RELATED_TO edges added", related_added)

    # ── Statistics ────────────────────────────────────────────────────────────

    def _compute_stats(self) -> Dict[str, Any]:
        node_type_counts: Dict[str, int] = defaultdict(int)
        edge_type_counts: Dict[str, int] = defaultdict(int)

        for node in self.nodes.values():
            node_type_counts[node["type"]] += 1
        for edge in self.edges.values():
            edge_type_counts[edge["relation"]] += 1

        # Top degree nodes (most connected = highest threat relevance)
        top_nodes = sorted(
            self.nodes.values(),
            key=lambda n: n.get("degree", 0),
            reverse=True,
        )[:20]

        return {
            "total_nodes":       len(self.nodes),
            "total_edges":       len(self.edges),
            "node_types":        dict(node_type_counts),
            "edge_types":        dict(edge_type_counts),
            "top_connected":     [
                {"id": n["id"], "type": n["type"], "value": n["value"][:60], "degree": n["degree"]}
                for n in top_nodes
            ],
            "graph_version":     "164.0",
            "generated_at":      __import__("datetime").datetime.utcnow().isoformat() + "Z",
        }

    # ── Pivot indexes ─────────────────────────────────────────────────────────

    def _build_pivot_indexes(self) -> Dict[str, Any]:
        """Pre-compute pivot tables for fast API lookups."""
        actor_to_ttps:       Dict[str, List[str]] = defaultdict(list)
        actor_to_advisories: Dict[str, List[str]] = defaultdict(list)
        ttp_to_advisories:   Dict[str, List[str]] = defaultdict(list)
        cve_to_advisories:   Dict[str, List[str]] = defaultdict(list)

        for eid, edge in self.edges.items():
            src_node = self.nodes.get(edge["source"], {})
            dst_node = self.nodes.get(edge["target"], {})
            rel      = edge["relation"]

            if rel == ET_ATTRIBUTES:
                # advisory → actor
                actor_to_advisories[dst_node.get("value","")].append(src_node.get("value",""))
            elif rel == ET_MAPS_TTP:
                # advisory → ttp
                ttp_to_advisories[dst_node.get("value","")].append(src_node.get("value",""))
            elif rel == ET_CONTAINS_IOC and dst_node.get("type") == NT_CVE:
                # advisory → CVE
                cve_to_advisories[dst_node.get("value","")].append(src_node.get("value",""))
            elif rel == ET_USES_TTP:
                # actor → ttp
                actor_to_ttps[src_node.get("value","")].append(dst_node.get("value",""))

        return {
            "actor_advisories":  {k: list(set(v)) for k, v in actor_to_advisories.items()},
            "ttp_advisories":    {k: list(set(v)) for k, v in ttp_to_advisories.items()},
            "cve_advisories":    {k: list(set(v)) for k, v in cve_to_advisories.items()},
            "actor_ttps":        {k: list(set(v)) for k, v in actor_to_ttps.items()},
        }

    # ── Build ─────────────────────────────────────────────────────────────────

    def build(self, advisories: List[Dict[str, Any]]) -> None:
        log.info("Ingesting %d advisories into threat graph...", len(advisories))
        for item in advisories:
            try:
                self.ingest_advisory(item)
            except Exception as e:
                log.warning("Skipping advisory %s: %s", item.get("id", "?"), e)

        log.info("Post-processing: actor→TTP edges...")
        self._build_actor_ttp_edges()

        log.info("Post-processing: IOC correlation edges...")
        self._build_ioc_correlation_edges()

        log.info(
            "Graph built: %d nodes, %d edges",
            len(self.nodes), len(self.edges),
        )

    # ── Serialize ─────────────────────────────────────────────────────────────

    def write(self) -> None:
        GRAPH_DIR.mkdir(parents=True, exist_ok=True)
        PIVOT_DIR.mkdir(parents=True, exist_ok=True)

        nodes_list = sorted(self.nodes.values(), key=lambda n: n.get("degree", 0), reverse=True)
        edges_list = sorted(self.edges.values(), key=lambda e: e.get("weight", 1), reverse=True)
        stats      = self._compute_stats()
        pivots     = self._build_pivot_indexes()

        # nodes.json
        (GRAPH_DIR / "nodes.json").write_text(
            json.dumps({"nodes": nodes_list, "count": len(nodes_list), **stats}, indent=2),
            encoding="utf-8",
        )
        log.info("✓ Wrote api/graph/nodes.json (%d nodes)", len(nodes_list))

        # edges.json
        (GRAPH_DIR / "edges.json").write_text(
            json.dumps({"edges": edges_list, "count": len(edges_list)}, indent=2),
            encoding="utf-8",
        )
        log.info("✓ Wrote api/graph/edges.json (%d edges)", len(edges_list))

        # stats.json (public summary — served free tier)
        (GRAPH_DIR / "stats.json").write_text(
            json.dumps(stats, indent=2),
            encoding="utf-8",
        )
        log.info("✓ Wrote api/graph/stats.json")

        # Pivot indexes
        for pivot_name, pivot_data in pivots.items():
            (PIVOT_DIR / f"{pivot_name}.json").write_text(
                json.dumps(pivot_data, indent=2),
                encoding="utf-8",
            )
        log.info("✓ Wrote %d pivot indexes to api/graph/pivot/", len(pivots))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _load_advisories() -> List[Dict[str, Any]]:
    """Load advisory corpus — prefer full manifest, fall back to api/feed.json."""
    advisories: List[Dict[str, Any]] = []

    if MANIFEST_PATH.exists():
        try:
            manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            raw = manifest.get("advisories") or []
            if isinstance(raw, list):
                advisories = raw
            elif isinstance(raw, dict):
                advisories = list(raw.values())
            log.info("Loaded %d advisories from feed_manifest.json", len(advisories))
        except Exception as e:
            log.warning("Could not load manifest: %s — falling back to feed.json", e)

    if not advisories and FEED_PATH.exists():
        try:
            advisories = json.loads(FEED_PATH.read_text(encoding="utf-8"))
            log.info("Loaded %d advisories from api/feed.json (fallback)", len(advisories))
        except Exception as e:
            log.error("Could not load feed: %s", e)

    return advisories


def main() -> int:
    log.info("=== THREAT GRAPH ENGINE START (v164.0) ===")

    advisories = _load_advisories()
    if not advisories:
        log.warning("No advisories found — graph will be empty skeleton.")
        # Write empty graph so API routes don't 404
        GRAPH_DIR.mkdir(parents=True, exist_ok=True)
        (GRAPH_DIR / "nodes.json").write_text('{"nodes":[],"count":0}', encoding="utf-8")
        (GRAPH_DIR / "edges.json").write_text('{"edges":[],"count":0}', encoding="utf-8")
        (GRAPH_DIR / "stats.json").write_text('{"total_nodes":0,"total_edges":0}', encoding="utf-8")
        return 0

    builder = ThreatGraphBuilder()
    builder.build(advisories)
    builder.write()

    stats = builder._compute_stats()
    log.info(
        "=== THREAT GRAPH ENGINE COMPLETE: %d nodes | %d edges | %d node types ===",
        stats["total_nodes"], stats["total_edges"], len(stats["node_types"]),
    )
    log.info("Node breakdown: %s", stats["node_types"])
    log.info("Edge breakdown: %s", stats["edge_types"])

    if stats["top_connected"]:
        log.info(
            "Highest-degree node: %s (%s, degree=%d)",
            stats["top_connected"][0]["value"],
            stats["top_connected"][0]["type"],
            stats["top_connected"][0]["degree"],
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
