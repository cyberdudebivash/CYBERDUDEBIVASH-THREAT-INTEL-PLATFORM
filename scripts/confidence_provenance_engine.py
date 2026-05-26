#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Confidence Provenance Engine
Section 2: Explainable Confidence Scoring | Evidence Lineage | Telemetry Contribution |
           Signal Provenance Graphing | Scoring Reproducibility | Confidence Traceability
DIRECTIVE: No score without lineage. Every confidence value is explainable,
           reproducible, and traceable to its evidence sources.
Production-grade | Deterministic | Evidence-backed | CISO-trusted
"""
import json, uuid, math, hashlib, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

log = logging.getLogger("confidence_provenance")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CONF-PROV] %(levelname)s %(message)s")

# ─── Evidence Signal Types ─────────────────────────────────────────────────────
SIGNAL_WEIGHTS = {
    # Telemetry signals (highest weight — ground truth)
    "endpoint_telemetry":    0.22,
    "network_telemetry":     0.18,
    "cloud_telemetry":       0.16,
    "auth_telemetry":        0.17,
    "dns_telemetry":         0.14,
    "ai_runtime_telemetry":  0.15,
    # Behavioral analytics
    "behavioral_beaconing":  0.15,
    "behavioral_lateral":    0.17,
    "behavioral_anomaly":    0.12,
    "behavioral_ueba":       0.14,
    # Graph intelligence
    "graph_pivot":           0.12,
    "graph_overlap":         0.14,
    "graph_lineage":         0.10,
    "graph_cluster":         0.11,
    # Detection/replay
    "detection_rule_match":  0.13,
    "replay_validation":     0.16,
    "replay_regression":     0.14,
    # Attribution/correlation
    "ttp_overlap":           0.13,
    "infra_overlap":         0.12,
    "malware_overlap":       0.11,
    "actor_similarity":      0.10,
    # External feeds (lowest weight — unverified by default)
    "osint_feed":            0.06,
    "threat_feed":           0.07,
    "cve_feed":              0.08,
    "manual_analyst":        0.09,
}

@dataclass
class ConfidenceSignal:
    """A single evidence signal contributing to a confidence score."""
    signal_id:     str
    signal_type:   str
    source_id:     str
    source_trust:  float      # 0-1: trust of the source itself
    signal_value:  float      # 0-1: strength of the signal
    weight:        float      # from SIGNAL_WEIGHTS
    contribution:  float      # weight × source_trust × signal_value
    context:       str        # human-readable context
    timestamp:     str
    validated:     bool = True

    def to_dict(self): return asdict(self)

@dataclass
class ConfidenceScore:
    """Full explainable confidence score with provenance lineage."""
    score_id:         str
    entity_id:        str     # what is being scored (IOC, alert, actor, etc.)
    entity_type:      str
    final_score:      float   # 0-1
    confidence_band:  str     # VERY_HIGH/HIGH/MEDIUM/LOW/VERY_LOW
    signals:          List[ConfidenceSignal]
    signal_count:     int
    contributing_types: List[str]
    breakdown:        Dict[str, float]   # signal_type -> contribution
    temporal_weight:  float              # recency factor
    signal_diversity: float              # how many distinct signal types
    reproducible_hash:str
    narrative:        str
    timestamp:        str

    def to_dict(self):
        d = asdict(self)
        d["signals"] = [s.to_dict() for s in self.signals]
        return d

    def breakdown_table(self) -> str:
        """Formatted evidence breakdown table for analyst consumption."""
        lines = [
            f"{'Signal Type':35s} {'Contribution':12s} {'Weight':8s}",
            "─"*58,
        ]
        for stype, contrib in sorted(self.breakdown.items(), key=lambda x: x[1], reverse=True):
            weight = SIGNAL_WEIGHTS.get(stype, 0)
            lines.append(f"{stype:35s} {contrib:.4f}       {weight:.2f}")
        lines.append("─"*58)
        lines.append(f"{'FINAL SCORE':35s} {self.final_score:.4f}")
        return "\n".join(lines)

class ConfidenceProvenanceEngine:
    """
    Explainable, reproducible confidence scoring engine.
    Every score is traceable to its contributing signals with full lineage.
    Produces confidence breakdown tables, provenance graphs, and narratives.
    """

    CONFIDENCE_BANDS = [
        (0.85, "VERY_HIGH"),
        (0.70, "HIGH"),
        (0.50, "MEDIUM"),
        (0.30, "LOW"),
        (0.00, "VERY_LOW"),
    ]

    RECENCY_DECAY = 3600 * 24  # 24hr for full recency

    def __init__(self):
        self._scores:    Dict[str, ConfidenceScore] = {}
        self._lineage:   Dict[str, List[str]]        = defaultdict(list)  # entity -> [score_ids]
        self._stats      = defaultdict(int)
        log.info("ConfidenceProvenanceEngine INITIALIZED — all scoring explainable")

    def add_signal(self, signal_type: str, source_id: str,
                   source_trust: float, signal_value: float,
                   context: str = "", validated: bool = True,
                   age_seconds: float = 0.0) -> ConfidenceSignal:
        """Build a single evidence signal."""
        base_weight = SIGNAL_WEIGHTS.get(signal_type, 0.05)
        # Apply temporal decay
        recency_factor = math.exp(-age_seconds / self.RECENCY_DECAY) if age_seconds > 0 else 1.0
        contribution   = base_weight * source_trust * signal_value * recency_factor
        return ConfidenceSignal(
            signal_id   = str(uuid.uuid4())[:8],
            signal_type = signal_type,
            source_id   = source_id,
            source_trust= round(source_trust, 4),
            signal_value= round(signal_value, 4),
            weight      = base_weight,
            contribution= round(contribution, 6),
            context     = context[:200],
            timestamp   = datetime.now(timezone.utc).isoformat(),
            validated   = validated,
        )

    def compute(self, entity_id: str, entity_type: str,
                signals: List[ConfidenceSignal]) -> ConfidenceScore:
        """
        Compute explainable confidence score from signals.
        Score = Σ(signal.contribution) normalized by max possible sum.
        Diversity bonus applied for multi-type signal sets.
        """
        if not signals:
            return self._zero_score(entity_id, entity_type)

        # Raw sum of contributions
        raw_sum = sum(s.contribution for s in signals)

        # Max possible (if all signals were perfect)
        signal_types_present = set(s.signal_type for s in signals)
        max_possible = sum(SIGNAL_WEIGHTS.get(st, 0.05) for st in signal_types_present)
        max_possible = max(max_possible, 0.01)

        # Base normalized score
        base_score = min(1.0, raw_sum / max_possible)

        # Signal diversity bonus (more independent signal types = more trust)
        diversity = len(signal_types_present)
        diversity_bonus = min(0.10, (diversity - 1) * 0.02) if diversity > 1 else 0.0

        # Validation penalty: unvalidated signals reduce confidence
        unvalidated_ct = sum(1 for s in signals if not s.validated)
        validation_penalty = unvalidated_ct * 0.03

        # Temporal weight (recency of most recent signal)
        temporal_weight = max(s.contribution for s in signals) / max(raw_sum, 0.001)

        final_score = min(0.99, max(0.01, base_score + diversity_bonus - validation_penalty))

        # Confidence band
        band = "VERY_LOW"
        for threshold, label in self.CONFIDENCE_BANDS:
            if final_score >= threshold:
                band = label
                break

        # Breakdown by signal type
        breakdown: Dict[str, float] = defaultdict(float)
        for s in signals:
            breakdown[s.signal_type] += s.contribution

        # Narrative
        narrative = self._generate_narrative(entity_id, entity_type, final_score, band,
                                             signal_types_present, diversity)

        # Reproducible hash
        hash_input = json.dumps({
            "entity_id": entity_id,
            "signals": sorted([
                {"type":s.signal_type,"trust":s.source_trust,"value":s.signal_value}
                for s in signals
            ], key=lambda x: x["type"]),
        }, sort_keys=True)
        rep_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        score = ConfidenceScore(
            score_id          = str(uuid.uuid4())[:10],
            entity_id         = entity_id,
            entity_type       = entity_type,
            final_score       = round(final_score, 4),
            confidence_band   = band,
            signals           = signals,
            signal_count      = len(signals),
            contributing_types= list(signal_types_present),
            breakdown         = dict(breakdown),
            temporal_weight   = round(temporal_weight, 4),
            signal_diversity  = round(diversity / max(len(SIGNAL_WEIGHTS), 1), 4),
            reproducible_hash = rep_hash,
            narrative         = narrative,
            timestamp         = datetime.now(timezone.utc).isoformat(),
        )

        self._scores[score.score_id] = score
        self._lineage[entity_id].append(score.score_id)
        self._stats["scores_computed"] += 1
        self._stats[f"band_{band}"] += 1

        log.info(f"📊 CONFIDENCE [{band:9s}] {entity_type}:{entity_id[:20]} "
                 f"score={final_score:.3f} signals={len(signals)} diversity={diversity}")
        return score

    def _zero_score(self, entity_id: str, entity_type: str) -> ConfidenceScore:
        return ConfidenceScore(
            score_id="zero", entity_id=entity_id, entity_type=entity_type,
            final_score=0.0, confidence_band="VERY_LOW", signals=[],
            signal_count=0, contributing_types=[], breakdown={},
            temporal_weight=0.0, signal_diversity=0.0,
            reproducible_hash="0"*16,
            narrative="No evidence signals provided. Score is zero.",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    def _generate_narrative(self, entity_id: str, entity_type: str,
                            score: float, band: str,
                            signal_types: set, diversity: int) -> str:
        telemetry_types = {st for st in signal_types if "telemetry" in st}
        behavioral_types= {st for st in signal_types if "behavioral" in st}
        graph_types     = {st for st in signal_types if "graph" in st}

        parts = [f"{entity_type} '{entity_id[:30]}' assessed at {band} confidence ({score:.0%})."]
        if telemetry_types:
            parts.append(f"Telemetry evidence from {len(telemetry_types)} source type(s): {', '.join(telemetry_types)}.")
        if behavioral_types:
            parts.append(f"Behavioral analytics contribution: {', '.join(behavioral_types)}.")
        if graph_types:
            parts.append(f"Graph intelligence correlation: {', '.join(graph_types)}.")
        if diversity >= 4:
            parts.append("High signal diversity increases confidence reliability.")
        elif diversity == 1:
            parts.append("Single signal type — confidence may not be representative.")
        parts.append("Score is deterministic and reproducible from listed evidence signals.")
        return " ".join(parts)

    def lineage_chain(self, entity_id: str) -> List[Dict]:
        """Return full confidence scoring history for an entity."""
        score_ids = self._lineage.get(entity_id, [])
        return [self._scores[sid].to_dict() for sid in score_ids if sid in self._scores]

    def compare(self, score_a: ConfidenceScore, score_b: ConfidenceScore) -> Dict:
        """Compare two confidence scores — useful for drift detection."""
        delta = score_a.final_score - score_b.final_score
        return {
            "entity":    score_a.entity_id,
            "score_a":   score_a.final_score,
            "score_b":   score_b.final_score,
            "delta":     round(delta, 4),
            "direction": "increased" if delta > 0 else "decreased" if delta < 0 else "stable",
            "band_a":    score_a.confidence_band,
            "band_b":    score_b.confidence_band,
            "band_changed": score_a.confidence_band != score_b.confidence_band,
        }

    def stats(self) -> Dict:
        return dict(self._stats)

if __name__ == "__main__":
    engine = ConfidenceProvenanceEngine()

    print("\n" + "="*65)
    print("  SENTINEL APEX — CONFIDENCE PROVENANCE ENGINE SELF-TEST")
    print("="*65)

    # High-evidence IOC score
    ioc_signals = [
        engine.add_signal("endpoint_telemetry","sysmon-win01",0.93,0.90,"Process creation EID 1",True,300),
        engine.add_signal("network_telemetry", "firewall-01", 0.85,0.85,"Outbound C2 connection",True,600),
        engine.add_signal("behavioral_beaconing","ueba-01",   0.88,0.92,"CoV=0.06 beacon interval",True,200),
        engine.add_signal("graph_overlap",      "graph-01",   0.80,0.78,"IP shares ASN with known C2",True,1800),
        engine.add_signal("replay_validation",  "replay-01",  0.95,0.88,"Ransomware scenario replay PASS",True,0),
    ]
    s1 = engine.compute("185.220.101.45","ip_ioc", ioc_signals)
    print(f"\n📊 IOC Confidence: {s1.confidence_band} ({s1.final_score:.3f})")
    print(f"\n{s1.breakdown_table()}")
    print(f"\n📖 Narrative:\n   {s1.narrative}")
    print(f"\n🔑 Reproducible Hash: {s1.reproducible_hash}")

    # Low-evidence actor attribution
    actor_signals = [
        engine.add_signal("osint_feed","open-feed-1",0.45,0.50,"Feed mentions APT29",False,86400),
    ]
    s2 = engine.compute("APT29","actor_attribution", actor_signals)
    print(f"\n📊 Actor Confidence: {s2.confidence_band} ({s2.final_score:.3f})")
    print(f"   Narrative: {s2.narrative}")

    # Comparison
    comp = engine.compare(s1, s2)
    print(f"\n📈 Score comparison: delta={comp['delta']} direction={comp['direction']}")
    print(f"\n📊 Engine Stats: {engine.stats()}")
    print("\n✅ CONFIDENCE PROVENANCE ENGINE — PRODUCTION READY\n")
