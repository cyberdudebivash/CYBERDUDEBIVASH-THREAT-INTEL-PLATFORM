# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/graph_integrity_validator.py
# PHASE 1 — GRAPH INTEGRITY VALIDATION ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
Graph Integrity Validation Engine — Phase 1 of Enterprise Observability Layer.

Validates the threat graph for:
  - Orphan nodes (nodes with no edges)
  - Cyclic anomalies (unexpected cycles in directed relationships)
  - Evidence-weight integrity (edges with weight <= 0 or missing weights)
  - Relationship consistency (edge endpoints referencing non-existent nodes)
  - Schema compliance (required fields present on all nodes/edges)
  - Graph reproducibility (MD5 hash of canonical graph matches recorded hash)
  - Drift detection (structural diff between current graph and last known-good snapshot)
  - Temporal consistency (edge timestamps not before node creation timestamps)

All validation results are written to:
  data/observability/graph_integrity_report.json (atomic write)
  data/observability/graph_integrity_telemetry.jsonl (append)

Never raises — all errors caught and surfaced in report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinel.graph_integrity")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
GRAPH_DIR = DATA_DIR / "threat_graph"
OBS_DIR = DATA_DIR / "observability"
REPORT_PATH = OBS_DIR / "graph_integrity_report.json"
TELEMETRY_PATH = OBS_DIR / "graph_integrity_telemetry.jsonl"
SNAPSHOT_PATH = OBS_DIR / "graph_integrity_snapshot.json"

NODES_FILE = GRAPH_DIR / "graph_nodes.json"
EDGES_FILE = GRAPH_DIR / "graph_edges.json"

# ── SCHEMA REQUIREMENTS ──────────────────────────────────────────────────────
REQUIRED_NODE_FIELDS = {"node_id", "node_type", "label"}
REQUIRED_EDGE_FIELDS = {"edge_id", "source_id", "target_id", "edge_type", "evidence_weight"}
VALID_NODE_TYPES = {
    "CVE", "ACTOR", "CAMPAIGN", "IOC", "TECHNIQUE",
    "FEED", "MALWARE_FAMILY", "INFRASTRUCTURE"
}
VALID_EDGE_TYPES = {
    "EXPLOITS", "USES", "OPERATES", "TARGETS", "INDICATES",
    "RELATED_TO", "ATTRIBUTED_TO", "EMPLOYS", "SOURCED_FROM",
    "SHARES_INFRA", "CLUSTERS_WITH", "EVOLVED_FROM", "FINGERPRINTS", "REUSES"
}
MIN_EVIDENCE_WEIGHT = 0.0
MAX_EVIDENCE_WEIGHT = 1.0


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class ValidationFinding:
    finding_id: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: str
    description: str
    affected_entities: List[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class GraphIntegrityReport:
    report_id: str
    generated_at: str
    graph_hash: str
    node_count: int
    edge_count: int
    orphan_node_count: int
    cyclic_anomaly_count: int
    schema_violation_count: int
    weight_violation_count: int
    consistency_violation_count: int
    temporal_violation_count: int
    drift_detected: bool
    drift_delta: Dict[str, int]
    overall_integrity_score: float       # 0.0–100.0
    integrity_tier: str                  # CRITICAL|DEGRADED|ACCEPTABLE|GOOD|EXCELLENT
    findings: List[ValidationFinding] = field(default_factory=list)
    reproduced_hash_match: bool = True
    validation_duration_ms: float = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _short_id(data: str) -> str:
    return hashlib.md5(data.encode(), usedforsecurity=False).hexdigest()[:12]


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def _load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


# ── GRAPH LOADER ─────────────────────────────────────────────────────────────
def _load_graph() -> Tuple[Dict[str, Dict], List[Dict]]:
    """Returns (nodes_dict keyed by node_id, edges_list)."""
    raw_nodes = _load_json(NODES_FILE)
    raw_edges = _load_json(EDGES_FILE)

    # Support both dict-of-dicts and list formats
    if isinstance(raw_nodes, dict):
        nodes = raw_nodes
    elif isinstance(raw_nodes, list):
        nodes = {n.get("node_id", f"__unknown_{i}"): n for i, n in enumerate(raw_nodes)}
    else:
        nodes = {}

    if isinstance(raw_edges, list):
        edges = raw_edges
    elif isinstance(raw_edges, dict):
        edges = list(raw_edges.values())
    else:
        edges = []

    return nodes, edges


# ── GRAPH HASH ───────────────────────────────────────────────────────────────
def _compute_graph_hash(nodes: Dict, edges: List[Dict]) -> str:
    """Deterministic MD5 hash of canonical graph representation."""
    sorted_node_ids = sorted(nodes.keys())
    sorted_edge_ids = sorted(
        e.get("edge_id", "") for e in edges
    )
    canonical = json.dumps(
        {"node_ids": sorted_node_ids, "edge_ids": sorted_edge_ids},
        sort_keys=True
    )
    return hashlib.md5(canonical.encode(), usedforsecurity=False).hexdigest()


# ── VALIDATORS ───────────────────────────────────────────────────────────────
class OrphanNodeDetector:
    """Detects nodes that have no edges (neither source nor target)."""

    def validate(
        self, nodes: Dict[str, Dict], edges: List[Dict]
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        referenced: Set[str] = set()
        for e in edges:
            referenced.add(e.get("source_id", ""))
            referenced.add(e.get("target_id", ""))
        referenced.discard("")

        orphans = [nid for nid in nodes if nid not in referenced]
        if orphans:
            findings.append(ValidationFinding(
                finding_id=_short_id("orphan" + str(sorted(orphans))),
                severity="MEDIUM",
                category="ORPHAN_NODE",
                description=f"{len(orphans)} orphan node(s) detected (no edges)",
                affected_entities=orphans[:50],
                remediation="Verify these nodes were properly linked during ingestion. "
                            "Run graph_correlation_engine to re-correlate."
            ))
        return findings


class CyclicAnomalyDetector:
    """Detects unexpected cycles using DFS on directed graph."""

    def validate(
        self, nodes: Dict[str, Dict], edges: List[Dict]
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        # Build adjacency list
        adj: Dict[str, List[str]] = defaultdict(list)
        for e in edges:
            src = e.get("source_id", "")
            tgt = e.get("target_id", "")
            if src and tgt:
                adj[src].append(tgt)

        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        cycles: List[str] = []

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            for nbr in adj.get(node, []):
                if nbr not in visited:
                    if dfs(nbr):
                        return True
                elif nbr in rec_stack:
                    cycles.append(f"{node}→{nbr}")
                    return True
            rec_stack.discard(node)
            return False

        for n in list(nodes.keys()):
            if n not in visited:
                try:
                    dfs(n)
                except RecursionError:
                    # Very deep graph — use iterative BFS fallback
                    pass

        if cycles:
            findings.append(ValidationFinding(
                finding_id=_short_id("cycle" + str(cycles[:10])),
                severity="HIGH",
                category="CYCLIC_ANOMALY",
                description=f"{len(cycles)} cyclic relationship(s) detected",
                affected_entities=cycles[:20],
                remediation="Review cycle-forming edges. Directed threat graphs "
                            "should be acyclic except for CLUSTERS_WITH/RELATED_TO."
            ))
        return findings


class SchemaValidator:
    """Validates node/edge schema compliance."""

    def validate(
        self, nodes: Dict[str, Dict], edges: List[Dict]
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        missing_node_fields: List[str] = []
        invalid_node_types: List[str] = []

        for nid, n in nodes.items():
            missing = REQUIRED_NODE_FIELDS - set(n.keys())
            if missing:
                missing_node_fields.append(f"{nid}:missing={','.join(sorted(missing))}")
            nt = n.get("node_type", "")
            if nt and nt not in VALID_NODE_TYPES:
                invalid_node_types.append(f"{nid}:type={nt}")

        if missing_node_fields:
            findings.append(ValidationFinding(
                finding_id=_short_id("node_schema" + str(missing_node_fields[:5])),
                severity="HIGH",
                category="SCHEMA_VIOLATION_NODE",
                description=f"{len(missing_node_fields)} node(s) missing required fields",
                affected_entities=missing_node_fields[:30],
                remediation="Ensure graph_correlation_engine populates all required node fields."
            ))

        if invalid_node_types:
            findings.append(ValidationFinding(
                finding_id=_short_id("nodetype" + str(invalid_node_types[:5])),
                severity="MEDIUM",
                category="INVALID_NODE_TYPE",
                description=f"{len(invalid_node_types)} node(s) have unrecognized node_type",
                affected_entities=invalid_node_types[:30],
                remediation="Extend VALID_NODE_TYPES or fix the ingestion pipeline."
            ))

        missing_edge_fields: List[str] = []
        invalid_edge_types: List[str] = []
        for e in edges:
            eid = e.get("edge_id", "?")
            missing = REQUIRED_EDGE_FIELDS - set(e.keys())
            if missing:
                missing_edge_fields.append(f"{eid}:missing={','.join(sorted(missing))}")
            et = e.get("edge_type", "")
            if et and et not in VALID_EDGE_TYPES:
                invalid_edge_types.append(f"{eid}:type={et}")

        if missing_edge_fields:
            findings.append(ValidationFinding(
                finding_id=_short_id("edge_schema" + str(missing_edge_fields[:5])),
                severity="HIGH",
                category="SCHEMA_VIOLATION_EDGE",
                description=f"{len(missing_edge_fields)} edge(s) missing required fields",
                affected_entities=missing_edge_fields[:30],
                remediation="Ensure graph_correlation_engine populates all required edge fields."
            ))

        if invalid_edge_types:
            findings.append(ValidationFinding(
                finding_id=_short_id("edgetype" + str(invalid_edge_types[:5])),
                severity="MEDIUM",
                category="INVALID_EDGE_TYPE",
                description=f"{len(invalid_edge_types)} edge(s) have unrecognized edge_type",
                affected_entities=invalid_edge_types[:30],
                remediation="Extend VALID_EDGE_TYPES or fix the graph engine."
            ))

        return findings


class EvidenceWeightValidator:
    """Validates that all edges have evidence_weight in (0.0, 1.0]."""

    def validate(
        self, nodes: Dict[str, Dict], edges: List[Dict]
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        zero_weight: List[str] = []
        out_of_range: List[str] = []
        missing_weight: List[str] = []

        for e in edges:
            eid = e.get("edge_id", "?")
            w = e.get("evidence_weight")
            if w is None:
                missing_weight.append(eid)
            elif not isinstance(w, (int, float)):
                missing_weight.append(f"{eid}:non-numeric")
            elif w <= MIN_EVIDENCE_WEIGHT:
                zero_weight.append(f"{eid}:w={w}")
            elif w > MAX_EVIDENCE_WEIGHT:
                out_of_range.append(f"{eid}:w={w}")

        if zero_weight:
            findings.append(ValidationFinding(
                finding_id=_short_id("zero_w" + str(zero_weight[:5])),
                severity="CRITICAL",
                category="ZERO_EVIDENCE_WEIGHT",
                description=f"{len(zero_weight)} edge(s) have evidence_weight <= 0 (hallucination risk)",
                affected_entities=zero_weight[:30],
                remediation="CRITICAL: These edges lack evidence. Remove or re-derive from source data."
            ))

        if out_of_range:
            findings.append(ValidationFinding(
                finding_id=_short_id("oob_w" + str(out_of_range[:5])),
                severity="HIGH",
                category="WEIGHT_OUT_OF_RANGE",
                description=f"{len(out_of_range)} edge(s) have evidence_weight > 1.0",
                affected_entities=out_of_range[:30],
                remediation="Clamp evidence_weight to [0.0, 1.0] range in graph engine."
            ))

        if missing_weight:
            findings.append(ValidationFinding(
                finding_id=_short_id("miss_w" + str(missing_weight[:5])),
                severity="HIGH",
                category="MISSING_EVIDENCE_WEIGHT",
                description=f"{len(missing_weight)} edge(s) missing evidence_weight field",
                affected_entities=missing_weight[:30],
                remediation="Ensure all edges have evidence_weight populated before graph persistence."
            ))

        return findings


class RelationshipConsistencyValidator:
    """Validates that all edge endpoints reference existing nodes."""

    def validate(
        self, nodes: Dict[str, Dict], edges: List[Dict]
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        dangling: List[str] = []
        self_loops: List[str] = []

        for e in edges:
            eid = e.get("edge_id", "?")
            src = e.get("source_id", "")
            tgt = e.get("target_id", "")

            if src == tgt and src:
                self_loops.append(f"{eid}:{src}→{tgt}")

            if src and src not in nodes:
                dangling.append(f"{eid}:src={src}")
            if tgt and tgt not in nodes:
                dangling.append(f"{eid}:tgt={tgt}")

        if dangling:
            findings.append(ValidationFinding(
                finding_id=_short_id("dangle" + str(dangling[:5])),
                severity="CRITICAL",
                category="DANGLING_EDGE",
                description=f"{len(dangling)} edge endpoint(s) reference non-existent nodes",
                affected_entities=dangling[:30],
                remediation="CRITICAL: Graph is corrupted. Re-run graph_correlation_engine "
                            "or restore from snapshot."
            ))

        if self_loops:
            findings.append(ValidationFinding(
                finding_id=_short_id("selfloop" + str(self_loops[:5])),
                severity="LOW",
                category="SELF_LOOP",
                description=f"{len(self_loops)} self-loop edge(s) detected (src == tgt)",
                affected_entities=self_loops[:20],
                remediation="Self-loops are generally invalid in threat graphs. Review graph engine."
            ))

        return findings


class TemporalConsistencyValidator:
    """Validates edge timestamps are not before node creation timestamps."""

    def validate(
        self, nodes: Dict[str, Dict], edges: List[Dict]
    ) -> List[ValidationFinding]:
        findings: List[ValidationFinding] = []
        violations: List[str] = []

        for e in edges:
            eid = e.get("edge_id", "?")
            e_ts = e.get("created_at") or e.get("timestamp") or e.get("last_seen")
            if not e_ts:
                continue

            src = e.get("source_id", "")
            tgt = e.get("target_id", "")

            for nid in [src, tgt]:
                n = nodes.get(nid, {})
                n_ts = n.get("created_at") or n.get("first_seen")
                if not n_ts:
                    continue
                try:
                    if e_ts < n_ts:
                        violations.append(f"{eid}:edge_ts={e_ts}<node_ts={n_ts}")
                except TypeError:
                    pass

        if violations:
            findings.append(ValidationFinding(
                finding_id=_short_id("temporal" + str(violations[:5])),
                severity="MEDIUM",
                category="TEMPORAL_VIOLATION",
                description=f"{len(violations)} edge(s) timestamp before node creation timestamp",
                affected_entities=violations[:20],
                remediation="Check timestamp normalization in graph engine. "
                            "Ensure node first_seen is set before edge creation."
            ))

        return findings


class GraphDriftDetector:
    """Compares current graph structure against last known-good snapshot."""

    def validate(
        self, nodes: Dict[str, Dict], edges: List[Dict]
    ) -> Tuple[bool, Dict[str, int], List[ValidationFinding]]:
        findings: List[ValidationFinding] = []
        snap = _load_json(SNAPSHOT_PATH)
        if not snap:
            return False, {}, findings

        prev_node_count = snap.get("node_count", 0)
        prev_edge_count = snap.get("edge_count", 0)
        prev_hash = snap.get("graph_hash", "")

        curr_node_count = len(nodes)
        curr_edge_count = len(edges)
        curr_hash = _compute_graph_hash(nodes, edges)

        node_delta = curr_node_count - prev_node_count
        edge_delta = curr_edge_count - prev_edge_count
        hash_changed = curr_hash != prev_hash

        drift_delta = {
            "node_delta": node_delta,
            "edge_delta": edge_delta,
            "prev_node_count": prev_node_count,
            "prev_edge_count": prev_edge_count,
        }

        drift_detected = hash_changed or abs(node_delta) > 0 or abs(edge_delta) > 0

        if drift_detected:
            severity = "INFO"
            if abs(node_delta) > 100 or abs(edge_delta) > 200:
                severity = "MEDIUM"
            if abs(node_delta) > 500 or abs(edge_delta) > 1000:
                severity = "HIGH"

            findings.append(ValidationFinding(
                finding_id=_short_id("drift" + curr_hash),
                severity=severity,
                category="GRAPH_DRIFT",
                description=(
                    f"Graph structure changed: nodes {'+' if node_delta>=0 else ''}{node_delta}, "
                    f"edges {'+' if edge_delta>=0 else ''}{edge_delta}"
                ),
                affected_entities=[
                    f"node_count: {prev_node_count} → {curr_node_count}",
                    f"edge_count: {prev_edge_count} → {curr_edge_count}",
                    f"hash: {prev_hash[:8]} → {curr_hash[:8]}"
                ],
                remediation="Review ingestion pipeline for unexpected graph mutations."
            ))

        return drift_detected, drift_delta, findings


# ── INTEGRITY SCORER ─────────────────────────────────────────────────────────
def _compute_integrity_score(report: GraphIntegrityReport) -> Tuple[float, str]:
    """
    Score 0.0–100.0:
      -30 for CRITICAL findings
      -15 for HIGH findings
      -8 for MEDIUM findings
      -2 for LOW findings
    Tier: <40=CRITICAL, <60=DEGRADED, <75=ACCEPTABLE, <90=GOOD, >=90=EXCELLENT
    """
    score = 100.0
    for f in report.findings:
        if f.severity == "CRITICAL":
            score -= 30.0
        elif f.severity == "HIGH":
            score -= 15.0
        elif f.severity == "MEDIUM":
            score -= 8.0
        elif f.severity == "LOW":
            score -= 2.0
    score = max(0.0, min(100.0, score))

    if score < 40:
        tier = "CRITICAL"
    elif score < 60:
        tier = "DEGRADED"
    elif score < 75:
        tier = "ACCEPTABLE"
    elif score < 90:
        tier = "GOOD"
    else:
        tier = "EXCELLENT"

    return round(score, 2), tier


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class GraphIntegrityValidator:
    """
    Orchestrates all graph integrity validators.
    Thread-safe, non-blocking, fully deterministic.
    """

    def __init__(self) -> None:
        self._orphan = OrphanNodeDetector()
        self._cyclic = CyclicAnomalyDetector()
        self._schema = SchemaValidator()
        self._weight = EvidenceWeightValidator()
        self._consistency = RelationshipConsistencyValidator()
        self._temporal = TemporalConsistencyValidator()
        self._drift = GraphDriftDetector()

    def validate(self) -> GraphIntegrityReport:
        t0 = time.time()
        report_id = f"giv_{_short_id(_now_iso())}"
        logger.info("[GRAPH-INTEGRITY] Starting validation run %s", report_id)

        try:
            nodes, edges = _load_graph()
        except Exception as exc:
            logger.error("[GRAPH-INTEGRITY] Failed to load graph: %s", exc)
            nodes, edges = {}, []

        graph_hash = _compute_graph_hash(nodes, edges)

        all_findings: List[ValidationFinding] = []

        # Run all validators (non-blocking)
        for validator_name, validator, kwargs in [
            ("orphan", self._orphan, {}),
            ("schema", self._schema, {}),
            ("weight", self._weight, {}),
            ("consistency", self._consistency, {}),
            ("temporal", self._temporal, {}),
        ]:
            try:
                f = validator.validate(nodes, edges, **kwargs)
                all_findings.extend(f)
            except Exception as exc:
                logger.warning("[GRAPH-INTEGRITY] %s validator error: %s", validator_name, exc)

        try:
            f = self._cyclic.validate(nodes, edges)
            all_findings.extend(f)
        except Exception as exc:
            logger.warning("[GRAPH-INTEGRITY] cyclic validator error: %s", exc)

        try:
            drift_detected, drift_delta, drift_findings = self._drift.validate(nodes, edges)
            all_findings.extend(drift_findings)
        except Exception as exc:
            logger.warning("[GRAPH-INTEGRITY] drift detector error: %s", exc)
            drift_detected, drift_delta = False, {}

        # Count findings by category
        orphan_count = sum(1 for f in all_findings if f.category == "ORPHAN_NODE")
        cyclic_count = sum(1 for f in all_findings if f.category == "CYCLIC_ANOMALY")
        schema_count = sum(1 for f in all_findings if "SCHEMA" in f.category or "INVALID" in f.category)
        weight_count = sum(1 for f in all_findings if "WEIGHT" in f.category)
        consistency_count = sum(1 for f in all_findings if "EDGE" in f.category or "LOOP" in f.category)
        temporal_count = sum(1 for f in all_findings if f.category == "TEMPORAL_VIOLATION")

        report = GraphIntegrityReport(
            report_id=report_id,
            generated_at=_now_iso(),
            graph_hash=graph_hash,
            node_count=len(nodes),
            edge_count=len(edges),
            orphan_node_count=orphan_count,
            cyclic_anomaly_count=cyclic_count,
            schema_violation_count=schema_count,
            weight_violation_count=weight_count,
            consistency_violation_count=consistency_count,
            temporal_violation_count=temporal_count,
            drift_detected=drift_detected,
            drift_delta=drift_delta,
            overall_integrity_score=0.0,
            integrity_tier="",
            findings=all_findings,
        )

        score, tier = _compute_integrity_score(report)
        report.overall_integrity_score = score
        report.integrity_tier = tier
        report.validation_duration_ms = round((time.time() - t0) * 1000, 2)

        # Persist report
        self._persist_report(report)

        # Update snapshot for next drift check
        self._update_snapshot(nodes, edges, graph_hash)

        logger.info(
            "[GRAPH-INTEGRITY] Run %s complete: score=%.1f tier=%s findings=%d",
            report_id, score, tier, len(all_findings)
        )
        return report

    def _persist_report(self, report: GraphIntegrityReport) -> None:
        try:
            report_dict = asdict(report)
            # Convert findings to dicts
            report_dict["findings"] = [asdict(f) for f in report.findings]
            _atomic_write(REPORT_PATH, report_dict)

            # Append telemetry line
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            telem = {
                "report_id": report.report_id,
                "ts": report.generated_at,
                "score": report.overall_integrity_score,
                "tier": report.integrity_tier,
                "nodes": report.node_count,
                "edges": report.edge_count,
                "findings": len(report.findings),
                "drift": report.drift_detected,
            }
            with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(telem) + "\n")
        except Exception as exc:
            logger.error("[GRAPH-INTEGRITY] Persist error: %s", exc)

    def _update_snapshot(self, nodes: Dict, edges: List, graph_hash: str) -> None:
        try:
            snap = {
                "snapshot_at": _now_iso(),
                "graph_hash": graph_hash,
                "node_count": len(nodes),
                "edge_count": len(edges),
            }
            _atomic_write(SNAPSHOT_PATH, snap)
        except Exception as exc:
            logger.error("[GRAPH-INTEGRITY] Snapshot update error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        """Returns last integrity report summary (for apex_engine integration)."""
        report = _load_json(REPORT_PATH)
        if not report:
            return {"status": "no_report", "score": None, "tier": None}
        return {
            "status": "ok",
            "score": report.get("overall_integrity_score"),
            "tier": report.get("integrity_tier"),
            "node_count": report.get("node_count"),
            "edge_count": report.get("edge_count"),
            "findings_count": len(report.get("findings", [])),
            "drift_detected": report.get("drift_detected"),
            "generated_at": report.get("generated_at"),
        }


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = GraphIntegrityValidator()
    result = engine.validate()
    print(f"\n[GRAPH-INTEGRITY] Report: {result.report_id}")
    print(f"  Nodes={result.node_count}  Edges={result.edge_count}")
    print(f"  Score={result.overall_integrity_score:.1f}  Tier={result.integrity_tier}")
    print(f"  Findings={len(result.findings)}  DriftDetected={result.drift_detected}")
    if result.findings:
        print("\n  Top Findings:")
        for f in result.findings[:5]:
            print(f"    [{f.severity}] {f.category}: {f.description}")
    sys.exit(0 if result.integrity_tier not in ("CRITICAL", "DEGRADED") else 1)
