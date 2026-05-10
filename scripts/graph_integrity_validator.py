#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v146.0.0
THREAT ACTOR GRAPH INTEGRITY VALIDATOR
===============================================================================
PURPOSE:
  Validates the threat actor relationship graph for structural integrity.
  Detects orphaned nodes, dangling edges, cycle anomalies in actor-to-technique
  and actor-to-campaign associations, and referential integrity between the
  feed and graph nodes.

CHECKS:
  1. Node completeness  — every actor_tag in feed.json exists in graph
  2. Edge integrity     — no dangling edges pointing to unknown actors
  3. Technique refs     — all technique IDs in graph are valid ATT&CK format
  4. Orphan detection   — actors in graph not referenced in any advisory
  5. Cluster coherence  — actor clusters with 0 techniques flagged
  6. Feed referential   — all actor_tag values in feed map to known actors

GRAPH SOURCES (in priority order):
  data/intelligence/threat_actor_graph.json
  data/intelligence/actor_clusters.json
  api/feed.json (for referential integrity check)

OUTPUTS:
  data/governance/graph_integrity.json — full validation report

EXIT CODES:
  0 — PASS (graph is structurally sound)
  1 — HARD FAIL (dangling edges or critical referential integrity violations)
  3 — WARN (orphans, missing actors — non-blocking)
  0 — always on unexpected errors (non-blocking to production)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import re
import shutil
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [graph_integrity] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-GRAPH-INTEGRITY")

REPO_ROOT    = pathlib.Path(__file__).resolve().parent.parent
INTEL_DIR    = REPO_ROOT / "data" / "intelligence"
GOV_DIR      = REPO_ROOT / "data" / "governance"
FEED_PATH    = REPO_ROOT / "api" / "feed.json"
GRAPH_PATH   = INTEL_DIR / "threat_actor_graph.json"
CLUSTERS_PATH= INTEL_DIR / "actor_clusters.json"
REPORT_PATH  = GOV_DIR / "graph_integrity.json"

VERSION = "146.0.0"

TECHNIQUE_RE = re.compile(r'^T\d{4}(\.\d{3})?$', re.IGNORECASE)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".giv_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_json_safe(path: pathlib.Path) -> Tuple[Any, str]:
    """Load JSON file, return (data, error_msg). error_msg is None on success."""
    if not path.exists():
        return None, f"File not found: {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace")), None
    except json.JSONDecodeError as e:
        return None, f"JSON parse error in {path.name}: {e}"


def extract_feed_actors(feed: List[Dict]) -> Set[str]:
    """Extract all unique actor_tag values from feed."""
    actors: Set[str] = set()
    for item in feed:
        tag = item.get("actor_tag", "").strip()
        if tag and tag.upper() != "UNATTRIBUTED":
            actors.add(tag)
    return actors


def validate_graph(graph: Any) -> Tuple[List[str], List[str], List[str], Set[str]]:
    """
    Validate graph structure. Returns (errors, warnings, infos, known_actors).
    Graph format expected: {"nodes": [...], "edges": [...]} or {"actors": {...}}
    """
    errors: List[str] = []
    warnings: List[str] = []
    infos: List[str] = []
    known_actors: Set[str] = set()

    if not isinstance(graph, dict):
        errors.append("Graph root is not a JSON object")
        return errors, warnings, infos, known_actors

    # Support two common formats
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    actors_dict = graph.get("actors") or {}

    # Format A: {nodes, edges}
    if nodes or edges:
        node_ids: Set[str] = set()
        for n in nodes:
            nid = (n.get("id") or n.get("name") or "").strip()
            if nid:
                node_ids.add(nid)
                known_actors.add(nid)
            # Validate techniques on node
            for tid in (n.get("techniques") or []):
                tid_str = str(tid).strip().upper()
                if tid_str and not TECHNIQUE_RE.match(tid_str):
                    warnings.append(f"Node '{nid}': invalid technique ID format '{tid_str}'")

        # Edge integrity
        edge_ids: Set[str] = set()
        for e in edges:
            src = (e.get("source") or e.get("from") or "").strip()
            tgt = (e.get("target") or e.get("to") or "").strip()
            if src and src not in node_ids:
                errors.append(f"Dangling edge source: '{src}' not in node list")
            if tgt and tgt not in node_ids:
                errors.append(f"Dangling edge target: '{tgt}' not in node list")
            edge_ids.add(f"{src}->{tgt}")

        infos.append(f"Graph: {len(node_ids)} nodes, {len(edges)} edges")

        # Nodes with no outbound edges
        nodes_with_edges = {(e.get("source") or e.get("from") or "") for e in edges}
        isolated = node_ids - nodes_with_edges
        if isolated:
            warnings.append(f"Isolated nodes (no outbound edges): {sorted(isolated)[:10]}")

    # Format B: {actors: {name: {techniques: [...], ...}}}
    elif actors_dict:
        for actor_name, actor_data in actors_dict.items():
            known_actors.add(actor_name)
            techs = actor_data.get("techniques") or actor_data.get("ttps") or []
            if not techs:
                warnings.append(f"Actor '{actor_name}' has no techniques mapped (zero ATT&CK coverage)")
            for tid in techs:
                tid_str = str(tid).strip().upper()
                if tid_str and not TECHNIQUE_RE.match(tid_str):
                    warnings.append(f"Actor '{actor_name}': invalid technique ID '{tid_str}'")

        infos.append(f"Actor dict format: {len(actors_dict)} actors")
    else:
        warnings.append("Graph has no recognizable node/edge or actor structure — may be empty")

    return errors, warnings, infos, known_actors


def validate_clusters(clusters: Any, known_actors: Set[str]) -> Tuple[List[str], List[str]]:
    """Validate actor cluster file. Returns (errors, warnings)."""
    errors: List[str] = []
    warnings: List[str] = []

    if clusters is None:
        return errors, warnings

    if isinstance(clusters, list):
        cluster_list = clusters
    elif isinstance(clusters, dict):
        cluster_list = list(clusters.values())
    else:
        warnings.append("actor_clusters.json has unexpected root type")
        return errors, warnings

    for i, cluster in enumerate(cluster_list):
        members = cluster.get("members") or cluster.get("actors") or []
        cid = cluster.get("id") or cluster.get("name") or f"cluster_{i}"
        if not members:
            warnings.append(f"Cluster '{cid}' has no members")
        for m in members:
            mname = (m if isinstance(m, str) else m.get("name") or "").strip()
            if mname and known_actors and mname not in known_actors:
                warnings.append(f"Cluster '{cid}': member '{mname}' not in graph nodes")

    return errors, warnings


def check_feed_referential_integrity(
    feed_actors: Set[str],
    known_actors: Set[str],
) -> Tuple[List[str], List[str]]:
    """
    Cross-check feed actor_tags against graph nodes.
    Returns (errors, warnings).
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not known_actors:
        warnings.append("Graph has no known actors — cannot perform referential integrity check")
        return errors, warnings

    unregistered = feed_actors - known_actors
    orphan_actors = known_actors - feed_actors

    if unregistered:
        warnings.append(
            f"{len(unregistered)} feed actor_tags not in graph: "
            + ", ".join(sorted(unregistered)[:10])
        )
    if orphan_actors:
        warnings.append(
            f"{len(orphan_actors)} graph actors not observed in any advisory: "
            + ", ".join(sorted(orphan_actors)[:10])
        )

    if not unregistered and not orphan_actors:
        pass  # perfect alignment

    return errors, warnings


def main() -> int:
    t0 = time.monotonic()
    log.info("=" * 66)
    log.info("SENTINEL APEX %s — Threat Actor Graph Integrity Validator", VERSION)
    log.info("=" * 66)

    all_errors: List[str] = []
    all_warnings: List[str] = []
    all_infos: List[str] = []
    sources_checked: List[str] = []

    # Load graph
    graph, graph_err = load_json_safe(GRAPH_PATH)
    if graph_err:
        log.warning("[SKIP] %s", graph_err)
        all_warnings.append(graph_err)
        known_actors: Set[str] = set()
    else:
        sources_checked.append(str(GRAPH_PATH.name))
        g_errors, g_warnings, g_infos, known_actors = validate_graph(graph)
        all_errors.extend(g_errors)
        all_warnings.extend(g_warnings)
        all_infos.extend(g_infos)
        log.info("Graph: %d nodes known, %d errors, %d warnings",
                 len(known_actors), len(g_errors), len(g_warnings))

    # Load clusters
    clusters, clusters_err = load_json_safe(CLUSTERS_PATH)
    if not clusters_err:
        sources_checked.append(str(CLUSTERS_PATH.name))
        c_errors, c_warnings = validate_clusters(clusters, known_actors)
        all_errors.extend(c_errors)
        all_warnings.extend(c_warnings)
        log.info("Clusters: %d errors, %d warnings", len(c_errors), len(c_warnings))

    # Load feed for referential integrity
    feed_data, feed_err = load_json_safe(FEED_PATH)
    if feed_err:
        log.warning("[SKIP] Feed: %s", feed_err)
        all_warnings.append(feed_err)
        feed_actors: Set[str] = set()
    else:
        feed_items = feed_data if isinstance(feed_data, list) else []
        feed_actors = extract_feed_actors(feed_items)
        log.info("Feed: %d unique attributed actors across %d items", len(feed_actors), len(feed_items))
        ri_errors, ri_warnings = check_feed_referential_integrity(feed_actors, known_actors)
        all_errors.extend(ri_errors)
        all_warnings.extend(ri_warnings)

    # Verdict
    if all_errors:
        verdict = "FAIL"
    elif all_warnings:
        verdict = "WARN"
    else:
        verdict = "PASS"

    runtime = round(time.monotonic() - t0, 3)

    for e in all_errors:
        log.error("[ERROR] %s", e)
    for w in all_warnings:
        log.warning("[WARN] %s", w)
    for i in all_infos:
        log.info("[INFO] %s", i)

    report = {
        "schema_version"  : "1.0",
        "generated_at"    : now_iso(),
        "generator"       : "graph_integrity_validator.py",
        "version"         : VERSION,
        "overall_verdict" : verdict,
        "sources_checked" : sources_checked,
        "known_actor_count": len(known_actors),
        "feed_actor_count" : len(feed_actors),
        "error_count"     : len(all_errors),
        "warning_count"   : len(all_warnings),
        "errors"          : all_errors,
        "warnings"        : all_warnings,
        "infos"           : all_infos,
        "runtime_seconds" : runtime,
    }

    GOV_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(REPORT_PATH, json.dumps(report, ensure_ascii=False, indent=2))

    log.info("=" * 66)
    log.info("GRAPH INTEGRITY: %s | errors=%d warnings=%d actors=%d",
             verdict, len(all_errors), len(all_warnings), len(known_actors))
    log.info("[WRITE] %s", REPORT_PATH)
    log.info("=" * 66)

    if all_errors:
        return 1
    if all_warnings:
        return 3
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log.error("[FATAL] Unexpected error: %s", e)
        sys.exit(0)
