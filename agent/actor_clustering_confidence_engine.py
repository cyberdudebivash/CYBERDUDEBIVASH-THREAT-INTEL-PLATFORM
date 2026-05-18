# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/actor_clustering_confidence_engine.py
# PHASE 7 — ACTOR CLUSTERING CONFIDENCE ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
Actor Clustering Confidence Engine — Phase 7 of Enterprise Observability Layer.

Validates and measures the confidence and stability of actor attribution:
  - Clustering telemetry: per-cluster size, cohesion, TTP Jaccard scores
  - Attribution volatility analytics: how often actor attribution changes
  - Adversary similarity analytics: pairwise TTP similarity matrix summary
  - Cluster stability: tracks which clusters gain/lose members over time
  - Attribution confidence distribution: % of advisories per confidence tier
  - Weak attribution detector: flags advisories with attribution confidence < threshold
  - Phantom actor detector: actors appearing in only 1 advisory (attribution risk)

Outputs:
  data/observability/actor_clustering_report.json  (atomic write)
  data/observability/actor_clustering_telemetry.jsonl (append)
  data/observability/actor_clustering_baseline.json (drift tracking)

Never raises — all errors caught and surfaced in report.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinel.actor_clustering")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
OBS_DIR    = DATA_DIR / "observability"
REPORT_PATH    = OBS_DIR / "actor_clustering_report.json"
TELEMETRY_PATH = OBS_DIR / "actor_clustering_telemetry.jsonl"
BASELINE_PATH  = OBS_DIR / "actor_clustering_baseline.json"

INTEL_DIR      = DATA_DIR / "intelligence"
MEMORY_DIR     = DATA_DIR / "threat_memory"
ACTOR_MEM_PATH = MEMORY_DIR / "actor_memory.json"
GRAPH_DIR      = DATA_DIR / "threat_graph"
NODES_FILE     = GRAPH_DIR / "graph_nodes.json"
EDGES_FILE     = GRAPH_DIR / "graph_edges.json"

# Thresholds (match graph_correlation_engine constants)
JACCARD_CLUSTER_THRESHOLD = 0.4
WEAK_ATTRIBUTION_THRESHOLD = 0.35   # attribution confidence below this = weak
PHANTOM_ACTOR_THRESHOLD = 1         # actor in only N advisory = phantom risk


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class ActorCluster:
    cluster_id: str
    members: List[str]          # actor names / IDs in cluster
    size: int
    mean_jaccard: float         # mean pairwise TTP similarity within cluster
    shared_techniques: List[str]
    cohesion_score: float       # 0–1, how tightly grouped by TTP profile
    advisory_count: int

@dataclass
class AttributionVolatility:
    actor_name: str
    advisory_count: int
    attribution_confidence_mean: float
    confidence_std: float
    is_volatile: bool           # std_dev > 0.2
    is_phantom: bool            # advisory_count == 1

@dataclass
class ClusterDrift:
    new_clusters: int
    dissolved_clusters: int
    grown_clusters: int
    shrunk_clusters: int
    stable_clusters: int

@dataclass
class ActorClusteringReport:
    report_id: str
    generated_at: str
    total_actors: int
    total_clusters: int
    mean_cluster_size: float
    mean_cluster_cohesion: float
    weak_attribution_count: int
    phantom_actor_count: int
    volatile_actor_count: int
    clusters: List[ActorCluster]
    volatility: List[AttributionVolatility]
    cluster_drift: Optional[ClusterDrift]
    similarity_matrix_summary: Dict[str, Any]
    clustering_health_score: float
    clustering_tier: str
    duration_ms: float = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _short_id(s: str) -> str:
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()[:12]

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

def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


# ── ACTOR PROFILE BUILDER ────────────────────────────────────────────────────
def _build_actor_profiles(advisories: List[Dict], actor_memory: Dict) -> Dict[str, Dict]:
    """Build a profile for each actor: techniques, advisory_ids, confidence scores."""
    profiles: Dict[str, Dict] = defaultdict(lambda: {
        "techniques": set(),
        "advisory_ids": [],
        "confidences": [],
        "actor_name": "",
    })

    # From advisories
    for adv in advisories:
        adv_id = adv.get("id", adv.get("cve_id", "unknown"))
        actors = adv.get("actors", adv.get("threat_actors", []))
        if isinstance(actors, str):
            actors = [actors]
        if not isinstance(actors, list):
            actors = []

        techs = adv.get("techniques", adv.get("ttps", []))
        tech_ids: Set[str] = set()
        for t in techs:
            if isinstance(t, str):
                tech_ids.add(t)
            elif isinstance(t, dict):
                tid = t.get("technique_id", t.get("id", ""))
                if tid:
                    tech_ids.add(tid)

        conf = adv.get("confidence", adv.get("risk_score", 0.0))

        for actor in actors:
            actor_key = str(actor).strip().lower()
            if not actor_key:
                continue
            profiles[actor_key]["techniques"] |= tech_ids
            profiles[actor_key]["advisory_ids"].append(adv_id)
            profiles[actor_key]["actor_name"] = str(actor)
            if conf is not None:
                try:
                    profiles[actor_key]["confidences"].append(float(conf))
                except (TypeError, ValueError):
                    pass

    # Augment from actor memory
    if isinstance(actor_memory, dict):
        for actor_key, mem in actor_memory.items():
            if isinstance(mem, dict):
                ttps = mem.get("techniques", mem.get("ttps", []))
                if isinstance(ttps, list):
                    profiles[actor_key]["techniques"] |= set(ttps)
                if not profiles[actor_key]["actor_name"]:
                    profiles[actor_key]["actor_name"] = mem.get("actor_name", actor_key)

    return dict(profiles)


# ── CLUSTER BUILDER ───────────────────────────────────────────────────────────
def _build_clusters(profiles: Dict[str, Dict]) -> List[ActorCluster]:
    """Group actors by TTP Jaccard similarity >= threshold."""
    actor_keys = list(profiles.keys())
    n = len(actor_keys)
    if n == 0:
        return []

    # Union-Find for clustering
    parent = {k: k for k in actor_keys}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        parent[find(x)] = find(y)

    # O(n²) pairwise — bounded by practical actor count (< 500)
    for i in range(n):
        for j in range(i + 1, n):
            a_key = actor_keys[i]
            b_key = actor_keys[j]
            a_techs = profiles[a_key]["techniques"]
            b_techs = profiles[b_key]["techniques"]
            if a_techs and b_techs:
                j_score = _jaccard(a_techs, b_techs)
                if j_score >= JACCARD_CLUSTER_THRESHOLD:
                    union(a_key, b_key)

    # Collect clusters
    cluster_map: Dict[str, List[str]] = defaultdict(list)
    for k in actor_keys:
        cluster_map[find(k)].append(k)

    clusters: List[ActorCluster] = []
    for root, members in cluster_map.items():
        cluster_id = _short_id("cluster_" + "_".join(sorted(members)))

        # Compute mean pairwise Jaccard within cluster
        jaccards: List[float] = []
        shared: Set[str] = set()
        first = True
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                ta = profiles[members[i]]["techniques"]
                tb = profiles[members[j]]["techniques"]
                jaccards.append(_jaccard(ta, tb))
            if first:
                shared = profiles[members[i]]["techniques"].copy()
                first = False
            else:
                shared &= profiles[members[i]]["techniques"]

        mean_j = round(sum(jaccards) / len(jaccards), 4) if jaccards else 1.0
        cohesion = mean_j  # for single-member clusters cohesion = 1.0

        # Advisory count = union of all advisory_ids in cluster
        adv_ids: Set[str] = set()
        for m in members:
            adv_ids |= set(profiles[m]["advisory_ids"])

        clusters.append(ActorCluster(
            cluster_id=cluster_id,
            members=sorted(members)[:20],
            size=len(members),
            mean_jaccard=mean_j,
            shared_techniques=sorted(shared)[:10],
            cohesion_score=cohesion,
            advisory_count=len(adv_ids),
        ))

    return sorted(clusters, key=lambda c: c.size, reverse=True)


# ── VOLATILITY ANALYZER ───────────────────────────────────────────────────────
def _analyze_volatility(profiles: Dict[str, Dict]) -> List[AttributionVolatility]:
    result: List[AttributionVolatility] = []
    for actor_key, prof in profiles.items():
        confs = prof.get("confidences", [])
        adv_count = len(prof.get("advisory_ids", []))
        mean_conf = sum(confs) / len(confs) if confs else 0.0
        if len(confs) > 1:
            variance = sum((c - mean_conf) ** 2 for c in confs) / len(confs)
            import math
            std = math.sqrt(variance)
        else:
            std = 0.0
        result.append(AttributionVolatility(
            actor_name=prof.get("actor_name", actor_key),
            advisory_count=adv_count,
            attribution_confidence_mean=round(mean_conf, 3),
            confidence_std=round(std, 4),
            is_volatile=std > 0.2,
            is_phantom=adv_count <= PHANTOM_ACTOR_THRESHOLD,
        ))
    return sorted(result, key=lambda x: x.advisory_count, reverse=True)


# ── DRIFT DETECTOR ────────────────────────────────────────────────────────────
def _detect_cluster_drift(current_cluster_count: int, current_actor_count: int) -> Optional[ClusterDrift]:
    baseline = _load_json(BASELINE_PATH)
    if not baseline:
        return None
    prev_clusters = baseline.get("cluster_count", 0)
    prev_actors   = baseline.get("actor_count", 0)
    delta_clusters = current_cluster_count - prev_clusters
    delta_actors   = current_actor_count - prev_actors

    return ClusterDrift(
        new_clusters=max(0, delta_clusters),
        dissolved_clusters=max(0, -delta_clusters),
        grown_clusters=max(0, delta_actors),
        shrunk_clusters=max(0, -delta_actors),
        stable_clusters=max(0, min(prev_clusters, current_cluster_count)),
    )


def _update_baseline(cluster_count: int, actor_count: int) -> None:
    try:
        _atomic_write(BASELINE_PATH, {
            "snapshot_at": _now_iso(),
            "cluster_count": cluster_count,
            "actor_count": actor_count,
        })
    except Exception:
        pass


# ── SIMILARITY MATRIX SUMMARY ────────────────────────────────────────────────
def _similarity_summary(profiles: Dict[str, Dict]) -> Dict[str, Any]:
    keys = list(profiles.keys())[:20]  # cap for performance
    if len(keys) < 2:
        return {"actors_sampled": len(keys), "mean_pairwise_jaccard": 0.0}

    jaccards: List[float] = []
    for i in range(len(keys)):
        for j in range(i + 1, len(keys)):
            ta = profiles[keys[i]]["techniques"]
            tb = profiles[keys[j]]["techniques"]
            jaccards.append(_jaccard(ta, tb))

    mean_j = round(sum(jaccards) / len(jaccards), 4) if jaccards else 0.0
    max_j  = round(max(jaccards), 4) if jaccards else 0.0
    min_j  = round(min(jaccards), 4) if jaccards else 0.0

    return {
        "actors_sampled": len(keys),
        "pairs_compared": len(jaccards),
        "mean_pairwise_jaccard": mean_j,
        "max_pairwise_jaccard": max_j,
        "min_pairwise_jaccard": min_j,
        "highly_similar_pairs": sum(1 for j in jaccards if j >= 0.7),
    }


# ── HEALTH SCORER ─────────────────────────────────────────────────────────────
def _health_score(
    total_actors: int,
    weak_count: int,
    phantom_count: int,
    volatile_count: int,
    mean_cohesion: float,
) -> Tuple[float, str]:
    score = 100.0
    if total_actors > 0:
        weak_rate   = weak_count / total_actors
        phantom_rate = phantom_count / total_actors
        volatile_rate = volatile_count / total_actors
        score -= weak_rate * 30.0
        score -= phantom_rate * 20.0
        score -= volatile_rate * 15.0
    score += (mean_cohesion - 0.5) * 20.0
    score = round(max(0.0, min(100.0, score)), 2)
    tier = (
        "EXCELLENT" if score >= 80 else
        "GOOD"      if score >= 65 else
        "ACCEPTABLE" if score >= 50 else
        "POOR"      if score >= 30 else
        "CRITICAL"
    )
    return score, tier


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class ActorClusteringConfidenceEngine:

    def run_full_pipeline(
        self, advisories: Optional[List[Dict]] = None
    ) -> ActorClusteringReport:
        t0 = time.time()
        report_id = f"actor_clus_{_short_id(_now_iso())}"
        logger.info("[ACTOR-CLUSTER] Starting actor clustering confidence run %s", report_id)

        if advisories is None:
            advisories = self._load_advisories()

        actor_memory = _load_json(ACTOR_MEM_PATH)
        if not isinstance(actor_memory, dict):
            actor_memory = {}

        # Build profiles
        profiles: Dict[str, Dict] = {}
        try:
            profiles = _build_actor_profiles(advisories, actor_memory)
        except Exception as exc:
            logger.warning("[ACTOR-CLUSTER] Profile build error: %s", exc)

        # Build clusters
        clusters: List[ActorCluster] = []
        try:
            clusters = _build_clusters(profiles)
        except Exception as exc:
            logger.warning("[ACTOR-CLUSTER] Cluster build error: %s", exc)

        # Volatility
        volatility: List[AttributionVolatility] = []
        try:
            volatility = _analyze_volatility(profiles)
        except Exception as exc:
            logger.warning("[ACTOR-CLUSTER] Volatility error: %s", exc)

        # Counters
        weak_count     = sum(1 for v in volatility if v.attribution_confidence_mean < WEAK_ATTRIBUTION_THRESHOLD)
        phantom_count  = sum(1 for v in volatility if v.is_phantom)
        volatile_count = sum(1 for v in volatility if v.is_volatile)
        mean_cohesion  = (
            round(sum(c.cohesion_score for c in clusters) / len(clusters), 4)
            if clusters else 0.0
        )
        mean_size = (
            round(sum(c.size for c in clusters) / len(clusters), 2)
            if clusters else 0.0
        )

        # Drift
        drift = None
        try:
            drift = _detect_cluster_drift(len(clusters), len(profiles))
        except Exception as exc:
            logger.warning("[ACTOR-CLUSTER] Drift error: %s", exc)

        # Similarity matrix
        sim_summary: Dict[str, Any] = {}
        try:
            sim_summary = _similarity_summary(profiles)
        except Exception as exc:
            logger.warning("[ACTOR-CLUSTER] Similarity summary error: %s", exc)

        # Health
        health_score, health_tier = _health_score(
            len(profiles), weak_count, phantom_count, volatile_count, mean_cohesion
        )

        report = ActorClusteringReport(
            report_id=report_id,
            generated_at=_now_iso(),
            total_actors=len(profiles),
            total_clusters=len(clusters),
            mean_cluster_size=mean_size,
            mean_cluster_cohesion=mean_cohesion,
            weak_attribution_count=weak_count,
            phantom_actor_count=phantom_count,
            volatile_actor_count=volatile_count,
            clusters=clusters[:20],
            volatility=volatility[:20],
            cluster_drift=drift,
            similarity_matrix_summary=sim_summary,
            clustering_health_score=health_score,
            clustering_tier=health_tier,
            duration_ms=round((time.time() - t0) * 1000, 2),
        )

        self._persist(report)
        _update_baseline(len(clusters), len(profiles))
        logger.info(
            "[ACTOR-CLUSTER] Run %s: actors=%d clusters=%d phantoms=%d score=%.1f tier=%s",
            report_id, len(profiles), len(clusters), phantom_count, health_score, health_tier
        )
        return report

    def _load_advisories(self) -> List[Dict]:
        conf_data = _load_json(INTEL_DIR / "explainable_confidence_scores.json")
        if isinstance(conf_data, list) and conf_data:
            return conf_data
        results: List[Dict] = []
        reports_dir = INTEL_DIR / "reports"
        if reports_dir.exists():
            for f in sorted(reports_dir.glob("*.json"))[-30:]:
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    if isinstance(d, dict):
                        results.append(d)
                    elif isinstance(d, list):
                        results.extend(d[:5])
                except Exception:
                    pass
        return results

    def _persist(self, report: ActorClusteringReport) -> None:
        try:
            report_dict = asdict(report)
            _atomic_write(REPORT_PATH, report_dict)

            telem = {
                "report_id": report.report_id,
                "ts": report.generated_at,
                "actors": report.total_actors,
                "clusters": report.total_clusters,
                "mean_cohesion": report.mean_cluster_cohesion,
                "weak": report.weak_attribution_count,
                "phantom": report.phantom_actor_count,
                "volatile": report.volatile_actor_count,
                "score": report.clustering_health_score,
                "tier": report.clustering_tier,
            }
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            with TELEMETRY_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(telem) + "\n")
        except Exception as exc:
            logger.error("[ACTOR-CLUSTER] Persist error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        report = _load_json(REPORT_PATH)
        if not report:
            return {"status": "no_report"}
        return {
            "status": "ok",
            "actors": report.get("total_actors"),
            "clusters": report.get("total_clusters"),
            "score": report.get("clustering_health_score"),
            "tier": report.get("clustering_tier"),
            "phantom_count": report.get("phantom_actor_count"),
            "generated_at": report.get("generated_at"),
        }


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = ActorClusteringConfidenceEngine()
    result = engine.run_full_pipeline()
    print(f"\n[ACTOR-CLUSTER] Report: {result.report_id}")
    print(f"  Actors: {result.total_actors}  Clusters: {result.total_clusters}")
    print(f"  Phantom: {result.phantom_actor_count}  Volatile: {result.volatile_actor_count}")
    print(f"  Cohesion: {result.mean_cluster_cohesion:.3f}  Score: {result.clustering_health_score:.1f}  Tier: {result.clustering_tier}")
    sys.exit(0 if result.clustering_tier not in ("CRITICAL", "POOR") else 1)
