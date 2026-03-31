#!/usr/bin/env python3
"""
ai_learning_engine.py — CyberDudeBivash SENTINEL APEX v1.0
AI LEARNING ENGINE — Self-Improving, Memory-Driven Intelligence System

This engine reads from the Threat Memory Engine's persistent databases and
applies learned patterns to IMPROVE the accuracy and relevance of every
AI assessment produced by the sentinel_ai_engine.py.

The system gets SMARTER EVERY RUN by:

  1. SELF-IMPROVING SCORING
     - Adjusts risk score weights based on historical memory trends
     - Boosts confidence for actors/techniques confirmed across multiple runs
     - Applies recurrence multipliers to CVEs seen repeatedly with escalation
     - Reduces noise weight for low-impact signals that never escalate

  2. PATTERN LEARNING
     - Detects CVE recurrence patterns (same CVE re-observed over time)
     - Identifies recurring attack technique clusters (technique co-occurrence)
     - Tracks actor activity surges (week-over-week comparison)
     - Detects campaign growth trajectories from timeline data

  3. ADAPTIVE THREAT PRIORITIZATION
     - Escalates priority for CVEs with ESCALATING risk_trend in memory
     - Escalates for campaigns with growing evolution_score
     - Escalates for actors with INCREASING activity_trend
     - De-prioritizes low-risk recurring signals with no escalation evidence

  4. PREDICTIVE SIGNAL BOOSTING
     - Boosts exploit probability for CVEs with historical exploitation confirmed
     - Applies actor-weight multipliers based on historical activity frequency
     - Increases TTE urgency for techniques in active high-frequency actor TTPs

  5. LEARNING MODEL STATE
     - Persists learned weights in data/ai_learning/learning_model.json
     - Tracks weight evolution across runs in weight_history.json
     - Produces human-readable learning_report.json (explainable AI)

Design Principles:
  - ZERO external ML dependencies (no sklearn, torch, tensorflow)
  - DETERMINISTIC: same inputs → same outputs
  - EXPLAINABLE: every adjustment includes a human-readable reason
  - PRODUCTION-SAFE: all exceptions caught, pipeline never blocked
  - IDEMPOTENT: re-running on same data produces same adjustments
  - ADDITIVE: enriches existing data, never removes or overwrites raw fields

Storage: data/ai_learning/
  ├── learning_model.json      — current learned weight state
  ├── weight_history.json      — weight evolution across runs
  ├── learning_report.json     — human-readable this-run analysis
  └── adjusted_scores.json     — per-advisory adjustment log

Author: CyberDudeBivash Pvt. Ltd.
Version: v1.0
"""

import json
import logging
import math
import os
import re
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("CDB-AI-LEARN")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR     = Path(__file__).resolve().parent.parent
DATA_DIR     = BASE_DIR / "data"
MEMORY_DIR   = DATA_DIR / "threat_memory"
AI_DIR       = DATA_DIR / "ai_intelligence"
LEARNING_DIR = DATA_DIR / "ai_learning"
STIX_DIR     = DATA_DIR / "stix"

MANIFEST_PATH        = STIX_DIR / "feed_manifest.json"
AI_INDEX_PATH        = AI_DIR / "ai_index.json"
CVE_MEMORY_PATH      = MEMORY_DIR / "cve_memory.json"
ACTOR_MEMORY_PATH    = MEMORY_DIR / "actor_memory.json"
CAMPAIGN_MEMORY_PATH = MEMORY_DIR / "campaign_memory.json"
MEMORY_META_PATH     = MEMORY_DIR / "memory_meta.json"

LEARNING_MODEL_PATH  = LEARNING_DIR / "learning_model.json"
WEIGHT_HISTORY_PATH  = LEARNING_DIR / "weight_history.json"
LEARNING_REPORT_PATH = LEARNING_DIR / "learning_report.json"
ADJUSTED_SCORES_PATH = LEARNING_DIR / "adjusted_scores.json"

LEARNING_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Learning Model Default Weights
# These are the baseline signal weights — modified by learning across runs
# ---------------------------------------------------------------------------
DEFAULT_WEIGHTS = {
    # Risk score adjustment multipliers (applied on top of base AI score)
    "cve_recurrence_boost":      0.30,   # per additional occurrence (capped)
    "escalating_trend_boost":    0.50,   # CVE with ESCALATING risk_trend
    "kev_historical_boost":      0.40,   # CVE known to be KEV across runs
    "actor_known_boost":         0.25,   # advisory matches a tracked actor
    "actor_increasing_boost":    0.35,   # actor with INCREASING activity
    "campaign_active_boost":     0.20,   # advisory part of active campaign
    "campaign_escalating_boost": 0.45,   # advisory part of ESCALATING campaign
    "technique_cluster_boost":   0.15,   # technique seen in high-freq cluster
    "low_impact_noise_penalty":  0.20,   # repeated low-risk signal reduction

    # Confidence multipliers
    "recurrence_confidence_boost":  0.08,  # per occurrence (capped at 0.30)
    "actor_confidence_boost":       0.10,  # confirmed actor match
    "campaign_confidence_boost":    0.06,  # part of tracked campaign

    # Exploit probability boosters
    "exploit_historical_boost":     15.0,  # CVE previously confirmed exploited
    "actor_technique_match_boost":  8.0,   # technique in actor's known TTP set
    "campaign_active_exploit_boost":12.0,  # campaign has active exploitation

    # Priority thresholds (AI risk score thresholds after adjustment)
    "p1_threshold":  8.5,
    "p2_threshold":  6.5,
    "p3_threshold":  4.5,

    # Learning rate — how fast weights adapt (0.0 = no learning, 1.0 = instant)
    "learning_rate":        0.12,
    "weight_decay":         0.02,   # decay toward defaults each run
    "max_boost_per_entry":  2.50,   # cap on total boost per advisory
}

# ---------------------------------------------------------------------------
# Safe I/O
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _now_ts() -> float:
    return time.time()

def _safe_load(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[LEARN] Load error {path.name}: {e}")
        return default

def _safe_write(path: Path, data: Any) -> bool:
    try:
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        tmp.rename(path)
        return True
    except Exception as e:
        logger.error(f"[LEARN] Write failed {path.name}: {e}")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            return True
        except Exception:
            return False

def _extract_cves(text: str) -> List[str]:
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)))

def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# PATTERN ANALYZER — derives learning signals from memory databases
# ---------------------------------------------------------------------------

class PatternAnalyzer:
    """
    Analyzes the threat memory databases and extracts statistical patterns
    that feed into score adjustment decisions.
    """

    def __init__(self,
                 cve_db:      Dict[str, Dict],
                 actor_db:    Dict[str, Dict],
                 campaign_db: Dict[str, Dict]):
        self.cve_db      = cve_db
        self.actor_db    = actor_db
        self.campaign_db = campaign_db

    # ── CVE Patterns ────────────────────────────────────────────────────────

    def get_recurring_cves(self, min_occurrences: int = 3) -> Dict[str, Dict]:
        """CVEs seen at least min_occurrences times — high recurrence = real threat."""
        return {
            cve_id: rec
            for cve_id, rec in self.cve_db.items()
            if rec.get("occurrences", 0) >= min_occurrences
        }

    def get_escalating_cves(self) -> Dict[str, Dict]:
        """CVEs whose risk_trend is ESCALATING."""
        return {
            cve_id: rec
            for cve_id, rec in self.cve_db.items()
            if rec.get("risk_trend") == "ESCALATING"
        }

    def get_kev_confirmed_cves(self) -> Set[str]:
        """CVEs confirmed as CISA KEV in any prior run."""
        return {
            cve_id
            for cve_id, rec in self.cve_db.items()
            if rec.get("kev_ever")
        }

    def get_exploit_confirmed_cves(self) -> Set[str]:
        """CVEs with confirmed active exploitation in memory."""
        return {
            cve_id
            for cve_id, rec in self.cve_db.items()
            if rec.get("active_exploitation_confirmed")
        }

    def get_low_impact_cves(self, max_risk: float = 4.0,
                             min_occurrences: int = 2) -> Set[str]:
        """
        CVEs that have appeared multiple times but NEVER escalated above
        a low-risk threshold — strong signal for noise reduction.
        """
        return {
            cve_id
            for cve_id, rec in self.cve_db.items()
            if (rec.get("occurrences", 0) >= min_occurrences
                and rec.get("max_risk_score", 0) <= max_risk
                and rec.get("risk_trend") != "ESCALATING"
                and not rec.get("kev_ever")
                and not rec.get("active_exploitation_confirmed"))
        }

    # ── Technique Patterns ──────────────────────────────────────────────────

    def get_high_frequency_techniques(self, top_n: int = 15) -> Dict[str, int]:
        """
        Aggregate technique frequencies across all actor memory records.
        Returns {technique_id: total_count} for top N.
        """
        freq: Counter = Counter()
        for actor_rec in self.actor_db.values():
            for tech, count in (actor_rec.get("techniques_used") or {}).items():
                freq[tech] += count
        return dict(freq.most_common(top_n))

    def get_technique_actor_map(self) -> Dict[str, List[str]]:
        """Map each technique to actors known to use it."""
        tech_map: Dict[str, List[str]] = defaultdict(list)
        for actor_name, actor_rec in self.actor_db.items():
            for tech in (actor_rec.get("techniques_used") or {}).keys():
                if actor_name not in tech_map[tech]:
                    tech_map[tech].append(actor_name)
        return dict(tech_map)

    def get_technique_cooccurrence_clusters(self) -> Dict[str, Set[str]]:
        """
        Detect technique clusters — groups of techniques that co-occur
        frequently across advisories. Useful for pattern fingerprinting.
        Returns {anchor_technique: set_of_co_occurring_techniques}.
        """
        clusters: Dict[str, Set[str]] = defaultdict(set)
        for cve_rec in self.cve_db.values():
            techs = cve_rec.get("mitre_techniques", [])
            if len(techs) >= 2:
                for i, t1 in enumerate(techs):
                    for t2 in techs[i+1:]:
                        clusters[t1].add(t2)
                        clusters[t2].add(t1)
        return dict(clusters)

    # ── Actor Patterns ──────────────────────────────────────────────────────

    def get_active_actors(self) -> Dict[str, Dict]:
        """Actors seen in the last 30 days."""
        active = {}
        cutoff = datetime.now(timezone.utc) - timedelta(days=30)
        for name, rec in self.actor_db.items():
            last_seen = rec.get("last_seen", "")
            try:
                dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                if dt >= cutoff:
                    active[name] = rec
            except Exception:
                pass
        return active

    def get_increasing_actors(self) -> Dict[str, Dict]:
        """Actors with INCREASING activity trend — elevated threat state."""
        return {
            name: rec
            for name, rec in self.actor_db.items()
            if rec.get("activity_trend") == "INCREASING"
        }

    def get_actor_technique_sets(self) -> Dict[str, Set[str]]:
        """Per-actor set of known techniques for fast lookup."""
        return {
            name: set(rec.get("techniques_used", {}).keys())
            for name, rec in self.actor_db.items()
        }

    def get_high_confidence_actors(self, min_advisories: int = 3) -> Set[str]:
        """Actors observed in enough advisories to trust attribution."""
        return {
            name
            for name, rec in self.actor_db.items()
            if rec.get("total_advisories", 0) >= min_advisories
        }

    # ── Campaign Patterns ───────────────────────────────────────────────────

    def get_escalating_campaigns(self) -> Dict[str, Dict]:
        """Campaigns with ESCALATING status or high evolution score."""
        return {
            cid: rec
            for cid, rec in self.campaign_db.items()
            if (rec.get("campaign_status") == "ESCALATING"
                or rec.get("evolution_score", 0) >= 6.0)
        }

    def get_active_campaign_ids(self) -> Set[str]:
        """All campaigns that are not DORMANT or CONTAINED."""
        return {
            cid
            for cid, rec in self.campaign_db.items()
            if rec.get("campaign_status") in ("ACTIVE", "ESCALATING")
        }

    def get_campaign_actor_map(self) -> Dict[str, List[str]]:
        """Map campaign_id → list of actors involved."""
        return {
            cid: rec.get("actors_involved", [])
            for cid, rec in self.campaign_db.items()
        }

    # ── Composite Summary ───────────────────────────────────────────────────

    def summarize(self) -> Dict:
        return {
            "recurring_cves":          len(self.get_recurring_cves()),
            "escalating_cves":         len(self.get_escalating_cves()),
            "kev_confirmed_cves":      len(self.get_kev_confirmed_cves()),
            "exploit_confirmed_cves":  len(self.get_exploit_confirmed_cves()),
            "low_impact_cves":         len(self.get_low_impact_cves()),
            "high_freq_techniques":    len(self.get_high_frequency_techniques()),
            "active_actors":           len(self.get_active_actors()),
            "increasing_actors":       len(self.get_increasing_actors()),
            "escalating_campaigns":    len(self.get_escalating_campaigns()),
            "active_campaigns":        len(self.get_active_campaign_ids()),
        }


# ---------------------------------------------------------------------------
# WEIGHT LEARNER — adapts scoring weights from historical patterns
# ---------------------------------------------------------------------------

class WeightLearner:
    """
    Maintains and evolves the learning model's weight state across runs.

    Learning Algorithm:
    - Each run, patterns are observed (CVE escalations, actor surges, etc.)
    - If a pattern is MORE prevalent than the previous run → boost that weight
    - If a pattern is LESS prevalent → decay that weight toward default
    - Learning rate controls how fast adaptation occurs
    - Weights are bounded to prevent runaway amplification

    This is DETERMINISTIC statistical adaptation — no randomness, fully
    explainable, and produces the same output for the same input history.
    """

    # Absolute min/max bounds per weight to prevent runaway
    WEIGHT_BOUNDS = {
        "cve_recurrence_boost":      (0.10, 0.80),
        "escalating_trend_boost":    (0.20, 1.20),
        "kev_historical_boost":      (0.20, 1.00),
        "actor_known_boost":         (0.10, 0.60),
        "actor_increasing_boost":    (0.15, 0.80),
        "campaign_active_boost":     (0.05, 0.50),
        "campaign_escalating_boost": (0.20, 1.00),
        "technique_cluster_boost":   (0.05, 0.40),
        "low_impact_noise_penalty":  (0.05, 0.50),
        "recurrence_confidence_boost": (0.03, 0.20),
        "actor_confidence_boost":      (0.05, 0.25),
        "campaign_confidence_boost":   (0.03, 0.15),
        "exploit_historical_boost":    (5.0,  30.0),
        "actor_technique_match_boost": (3.0,  20.0),
        "campaign_active_exploit_boost": (5.0, 25.0),
    }

    def __init__(self):
        saved = _safe_load(LEARNING_MODEL_PATH, {})
        self.weights = dict(DEFAULT_WEIGHTS)
        # Overlay saved learned weights (only numeric, non-threshold keys)
        for key, val in saved.get("weights", {}).items():
            if key in self.weights and key not in ("p1_threshold", "p2_threshold",
                                                    "p3_threshold", "learning_rate",
                                                    "weight_decay", "max_boost_per_entry"):
                self.weights[key] = val
        self.run_count = saved.get("run_count", 0)
        self.prev_pattern_summary = saved.get("prev_pattern_summary", {})

    def adapt(self, current_patterns: Dict) -> Dict[str, str]:
        """
        Compare current patterns to previous run and adapt weights.
        Returns dict of {weight_name: explanation} for each adjustment.
        """
        adjustments: Dict[str, str] = {}
        lr = self.weights["learning_rate"]
        decay = self.weights["weight_decay"]
        prev = self.prev_pattern_summary

        # ── CVE recurrence boost ─────────────────────────────────────────
        curr_recurring = current_patterns.get("recurring_cves", 0)
        prev_recurring = prev.get("recurring_cves", 0)
        if curr_recurring > prev_recurring:
            delta = lr * 0.5
            self.weights["cve_recurrence_boost"] = _clamp(
                self.weights["cve_recurrence_boost"] + delta,
                *self.WEIGHT_BOUNDS["cve_recurrence_boost"]
            )
            adjustments["cve_recurrence_boost"] = (
                f"INCREASED +{delta:.3f}: recurring CVE count rose "
                f"{prev_recurring}→{curr_recurring}"
            )
        elif curr_recurring < prev_recurring and prev_recurring > 0:
            self.weights["cve_recurrence_boost"] = _clamp(
                self.weights["cve_recurrence_boost"] - decay,
                *self.WEIGHT_BOUNDS["cve_recurrence_boost"]
            )

        # ── Escalating trend boost ───────────────────────────────────────
        curr_escalating = current_patterns.get("escalating_cves", 0)
        prev_escalating = prev.get("escalating_cves", 0)
        if curr_escalating > prev_escalating:
            delta = lr * 0.8
            self.weights["escalating_trend_boost"] = _clamp(
                self.weights["escalating_trend_boost"] + delta,
                *self.WEIGHT_BOUNDS["escalating_trend_boost"]
            )
            adjustments["escalating_trend_boost"] = (
                f"INCREASED +{delta:.3f}: escalating CVE count rose "
                f"{prev_escalating}→{curr_escalating}"
            )

        # ── KEV historical boost ─────────────────────────────────────────
        curr_kev = current_patterns.get("kev_confirmed_cves", 0)
        prev_kev = prev.get("kev_confirmed_cves", 0)
        if curr_kev > prev_kev:
            delta = lr * 0.6
            self.weights["kev_historical_boost"] = _clamp(
                self.weights["kev_historical_boost"] + delta,
                *self.WEIGHT_BOUNDS["kev_historical_boost"]
            )
            adjustments["kev_historical_boost"] = (
                f"INCREASED +{delta:.3f}: new KEV confirmations "
                f"{prev_kev}→{curr_kev}"
            )

        # ── Actor known boost ────────────────────────────────────────────
        curr_active_actors = current_patterns.get("active_actors", 0)
        prev_active_actors = prev.get("active_actors", 0)
        if curr_active_actors > prev_active_actors:
            delta = lr * 0.4
            self.weights["actor_known_boost"] = _clamp(
                self.weights["actor_known_boost"] + delta,
                *self.WEIGHT_BOUNDS["actor_known_boost"]
            )
            adjustments["actor_known_boost"] = (
                f"INCREASED +{delta:.3f}: active actor count rose "
                f"{prev_active_actors}→{curr_active_actors}"
            )
        elif curr_active_actors < prev_active_actors:
            self.weights["actor_known_boost"] = _clamp(
                self.weights["actor_known_boost"] - decay,
                *self.WEIGHT_BOUNDS["actor_known_boost"]
            )

        # ── Actor increasing boost ───────────────────────────────────────
        curr_inc_actors = current_patterns.get("increasing_actors", 0)
        prev_inc_actors = prev.get("increasing_actors", 0)
        if curr_inc_actors > prev_inc_actors:
            delta = lr * 0.7
            self.weights["actor_increasing_boost"] = _clamp(
                self.weights["actor_increasing_boost"] + delta,
                *self.WEIGHT_BOUNDS["actor_increasing_boost"]
            )
            adjustments["actor_increasing_boost"] = (
                f"INCREASED +{delta:.3f}: surge in actors with increasing activity "
                f"{prev_inc_actors}→{curr_inc_actors}"
            )

        # ── Campaign escalating boost ────────────────────────────────────
        curr_esc_camps = current_patterns.get("escalating_campaigns", 0)
        prev_esc_camps = prev.get("escalating_campaigns", 0)
        if curr_esc_camps > prev_esc_camps:
            delta = lr * 0.9
            self.weights["campaign_escalating_boost"] = _clamp(
                self.weights["campaign_escalating_boost"] + delta,
                *self.WEIGHT_BOUNDS["campaign_escalating_boost"]
            )
            adjustments["campaign_escalating_boost"] = (
                f"INCREASED +{delta:.3f}: escalating campaigns rose "
                f"{prev_esc_camps}→{curr_esc_camps}"
            )

        # ── Low-impact noise penalty ─────────────────────────────────────
        curr_noise = current_patterns.get("low_impact_cves", 0)
        prev_noise = prev.get("low_impact_cves", 0)
        if curr_noise > prev_noise + 5:
            delta = lr * 0.3
            self.weights["low_impact_noise_penalty"] = _clamp(
                self.weights["low_impact_noise_penalty"] + delta,
                *self.WEIGHT_BOUNDS["low_impact_noise_penalty"]
            )
            adjustments["low_impact_noise_penalty"] = (
                f"INCREASED +{delta:.3f}: low-impact noise grew "
                f"{prev_noise}→{curr_noise}"
            )

        # ── Exploit historical boost ─────────────────────────────────────
        curr_exploit = current_patterns.get("exploit_confirmed_cves", 0)
        prev_exploit = prev.get("exploit_confirmed_cves", 0)
        if curr_exploit > prev_exploit:
            delta = lr * 5.0
            self.weights["exploit_historical_boost"] = _clamp(
                self.weights["exploit_historical_boost"] + delta,
                *self.WEIGHT_BOUNDS["exploit_historical_boost"]
            )
            adjustments["exploit_historical_boost"] = (
                f"INCREASED +{delta:.3f}: new exploitation confirmations "
                f"{prev_exploit}→{curr_exploit}"
            )

        return adjustments

    def save(self, pattern_summary: Dict) -> bool:
        self.run_count += 1
        model_state = {
            "engine_version": "v1.0",
            "run_count": self.run_count,
            "last_updated": _now_iso(),
            "weights": {k: v for k, v in self.weights.items()
                        if k not in ("p1_threshold", "p2_threshold", "p3_threshold",
                                     "learning_rate", "weight_decay", "max_boost_per_entry")},
            "prev_pattern_summary": pattern_summary,
        }
        ok = _safe_write(LEARNING_MODEL_PATH, model_state)

        # Append to weight history
        history = _safe_load(WEIGHT_HISTORY_PATH, [])
        history.append({
            "run": self.run_count,
            "timestamp": _now_iso(),
            "weights_snapshot": dict(self.weights),
            "pattern_summary": pattern_summary,
        })
        history = history[-100:]  # keep last 100 runs
        _safe_write(WEIGHT_HISTORY_PATH, history)

        return ok


# ---------------------------------------------------------------------------
# SCORE ADJUSTER — applies learned weights to current advisory assessments
# ---------------------------------------------------------------------------

class ScoreAdjuster:
    """
    For each advisory in the manifest + ai_index, computes learning-based
    adjustments to risk score, confidence, exploit probability, and priority.

    Every adjustment is logged with a human-readable explanation.
    """

    def __init__(self, weights: Dict,
                 patterns: "PatternAnalyzer",
                 high_freq_techniques: Dict[str, int]):
        self.w  = weights
        self.p  = patterns
        self.high_freq_techs = high_freq_techniques

        # Pre-compute lookup sets for O(1) checks
        self.recurring_cves      = set(patterns.get_recurring_cves().keys())
        self.escalating_cves     = set(patterns.get_escalating_cves().keys())
        self.kev_cves            = patterns.get_kev_confirmed_cves()
        self.exploit_cves        = patterns.get_exploit_confirmed_cves()
        self.low_impact_cves     = patterns.get_low_impact_cves()
        self.increasing_actors   = set(patterns.get_increasing_actors().keys())
        self.active_actors       = set(patterns.get_active_actors().keys())
        self.high_conf_actors    = patterns.get_high_confidence_actors()
        self.active_campaigns    = patterns.get_active_campaign_ids()
        self.escalating_campaigns = set(patterns.get_escalating_campaigns().keys())
        self.actor_tech_sets     = patterns.get_actor_technique_sets()
        self.tech_cluster_map    = patterns.get_technique_cooccurrence_clusters()

    def adjust(self, entry: Dict, ai_record: Optional[Dict]) -> Dict:
        """
        Compute all learning-based adjustments for one advisory.

        Returns an AdjustmentRecord dict containing:
          - risk_delta: float       (positive = boost, negative = penalty)
          - confidence_delta: float
          - exploit_prob_delta: float
          - adjusted_risk: float    (clamped 0–10)
          - adjusted_confidence: float (clamped 0–1)
          - adjusted_exploit_prob: float (clamped 0–100)
          - new_priority: str
          - reasons: List[str]      (human-readable explanations)
          - learning_signals: List[str]
        """
        reasons: List[str] = []
        learning_signals: List[str] = []

        base_risk    = float(
            (ai_record or {}).get("ai_risk_score") or entry.get("risk_score") or 0
        )
        base_conf    = float((ai_record or {}).get("ai_confidence") or 0.50)
        base_exploit = float(
            (ai_record or {}).get("exploit_probability_pct") or
            entry.get("exploit_probability_pct") or 0
        )

        risk_delta    = 0.0
        conf_delta    = 0.0
        exploit_delta = 0.0

        # ── Extract advisory CVE IDs ─────────────────────────────────────
        text = " ".join([
            entry.get("title", "") or "",
            entry.get("advisory_id", "") or "",
            entry.get("cve_id", "") or "",
        ])
        cves = set(c.upper() for c in _extract_cves(text))
        if not cves and entry.get("cve_id"):
            cves.add(entry["cve_id"].upper())

        # ── Extract advisory techniques ──────────────────────────────────
        raw_techs = (entry.get("mitre_techniques") or
                     entry.get("mitre_tactics") or [])
        if ai_record:
            raw_techs = raw_techs or (ai_record.get("kill_chain_phases") or [])
        techniques = set(
            t.split(".")[0].upper()
            for t in raw_techs
            if isinstance(t, str)
        )

        # ── Extract actor / campaign ─────────────────────────────────────
        primary_actor = (
            (ai_record or {}).get("primary_actor") or
            entry.get("actor_tag") or
            entry.get("threat_actor") or ""
        )
        campaign_id = (
            (ai_record or {}).get("campaign_id") or
            entry.get("campaign_id") or ""
        )

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 1 — CVE RECURRENCE BOOST
        # ════════════════════════════════════════════════════════════════
        matching_recurring = cves & self.recurring_cves
        if matching_recurring:
            # Get max occurrence count for bonus scaling
            max_occ = max(
                self.p.cve_db.get(cid, {}).get("occurrences", 3)
                for cid in matching_recurring
            )
            # Diminishing returns: log scale capped at 4×
            occ_factor = min(math.log2(max(max_occ, 2)), 4.0)
            delta = self.w["cve_recurrence_boost"] * occ_factor
            risk_delta += delta
            conf_delta += self.w["recurrence_confidence_boost"] * min(occ_factor, 3.0)
            cve_str = ", ".join(sorted(matching_recurring)[:3])
            reasons.append(
                f"CVE recurrence boost +{delta:.2f}: {cve_str} seen {max_occ}x "
                f"in memory (recurrence factor {occ_factor:.1f})"
            )
            learning_signals.append("cve_recurrence")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 2 — ESCALATING RISK TREND
        # ════════════════════════════════════════════════════════════════
        matching_escalating = cves & self.escalating_cves
        if matching_escalating:
            delta = self.w["escalating_trend_boost"]
            risk_delta  += delta
            conf_delta  += 0.05
            cve_str = ", ".join(sorted(matching_escalating)[:3])
            reasons.append(
                f"Escalating risk trend +{delta:.2f}: {cve_str} shows "
                f"rising risk trajectory across runs"
            )
            learning_signals.append("escalating_trend")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 3 — KEV HISTORICAL CONFIRMATION
        # ════════════════════════════════════════════════════════════════
        matching_kev = cves & self.kev_cves
        if matching_kev:
            delta = self.w["kev_historical_boost"]
            risk_delta    += delta
            conf_delta    += self.w["recurrence_confidence_boost"]
            exploit_delta += 20.0  # KEV = near-certain exploitation by others
            cve_str = ", ".join(sorted(matching_kev)[:3])
            reasons.append(
                f"KEV memory confirmation +{delta:.2f}: {cve_str} confirmed "
                f"in CISA KEV across historical runs"
            )
            learning_signals.append("kev_historical")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 4 — HISTORICAL EXPLOITATION CONFIRMED
        # ════════════════════════════════════════════════════════════════
        matching_exploit = cves & self.exploit_cves
        if matching_exploit:
            delta = self.w["exploit_historical_boost"]
            exploit_delta += delta
            risk_delta    += 0.30
            conf_delta    += 0.08
            cve_str = ", ".join(sorted(matching_exploit)[:3])
            reasons.append(
                f"Historical exploitation confirmed +{delta:.1f}pt exploit prob: "
                f"{cve_str} has confirmed active exploitation in memory"
            )
            learning_signals.append("exploit_confirmed")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 5 — LOW IMPACT NOISE REDUCTION
        # ════════════════════════════════════════════════════════════════
        matching_noise = cves & self.low_impact_cves
        if matching_noise and not matching_escalating and not matching_kev:
            penalty = self.w["low_impact_noise_penalty"]
            risk_delta -= penalty
            reasons.append(
                f"Low-impact noise penalty -{penalty:.2f}: "
                f"{', '.join(sorted(matching_noise)[:2])} repeated without escalation"
            )
            learning_signals.append("noise_reduction")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 6 — KNOWN ACTIVE ACTOR
        # ════════════════════════════════════════════════════════════════
        if primary_actor and primary_actor in self.active_actors:
            delta = self.w["actor_known_boost"]
            risk_delta += delta
            conf_delta += self.w["actor_confidence_boost"]
            reasons.append(
                f"Known active actor boost +{delta:.2f}: '{primary_actor}' "
                f"observed in last 30 days"
            )
            learning_signals.append("active_actor")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 7 — ACTOR WITH INCREASING ACTIVITY
        # ════════════════════════════════════════════════════════════════
        if primary_actor and primary_actor in self.increasing_actors:
            delta = self.w["actor_increasing_boost"]
            risk_delta    += delta
            conf_delta    += 0.05
            exploit_delta += self.w["actor_technique_match_boost"]
            reasons.append(
                f"Surge actor boost +{delta:.2f}: '{primary_actor}' shows "
                f"INCREASING activity trend in memory"
            )
            learning_signals.append("increasing_actor")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 8 — ACTOR TECHNIQUE MATCH (KNOWN TTP PATTERN)
        # ════════════════════════════════════════════════════════════════
        if primary_actor and primary_actor in self.actor_tech_sets:
            known_ttps  = self.actor_tech_sets[primary_actor]
            matched_ttps = techniques & known_ttps
            if matched_ttps:
                # More matches = stronger signal
                match_ratio = len(matched_ttps) / max(len(known_ttps), 1)
                delta = self.w["actor_technique_match_boost"] * min(match_ratio * 3, 1.0)
                exploit_delta += delta
                conf_delta    += 0.04 * len(matched_ttps)
                reasons.append(
                    f"Actor TTP match +{delta:.1f}pt exploit: "
                    f"'{primary_actor}' techniques {sorted(matched_ttps)[:4]} "
                    f"match known TTP profile"
                )
                learning_signals.append("actor_ttp_match")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 9 — CAMPAIGN ACTIVE
        # ════════════════════════════════════════════════════════════════
        if campaign_id and campaign_id in self.active_campaigns:
            delta = self.w["campaign_active_boost"]
            risk_delta += delta
            conf_delta += self.w["campaign_confidence_boost"]
            reasons.append(
                f"Active campaign boost +{delta:.2f}: part of tracked "
                f"campaign {campaign_id} (ACTIVE status)"
            )
            learning_signals.append("active_campaign")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 10 — CAMPAIGN ESCALATING
        # ════════════════════════════════════════════════════════════════
        if campaign_id and campaign_id in self.escalating_campaigns:
            delta = self.w["campaign_escalating_boost"]
            risk_delta    += delta
            exploit_delta += self.w["campaign_active_exploit_boost"]
            conf_delta    += self.w["campaign_confidence_boost"] * 2
            reasons.append(
                f"Escalating campaign boost +{delta:.2f}: {campaign_id} "
                f"has ESCALATING status and high evolution score"
            )
            learning_signals.append("escalating_campaign")

        # ════════════════════════════════════════════════════════════════
        # SIGNAL 11 — HIGH FREQUENCY TECHNIQUE CLUSTER
        # ════════════════════════════════════════════════════════════════
        matching_hf_techs = techniques & set(self.high_freq_techs.keys())
        if matching_hf_techs:
            # Boost scales with total frequency of matched techniques
            total_freq = sum(self.high_freq_techs.get(t, 0) for t in matching_hf_techs)
            delta = self.w["technique_cluster_boost"] * min(total_freq / 20.0, 2.0)
            risk_delta += delta
            reasons.append(
                f"High-freq technique boost +{delta:.2f}: "
                f"{sorted(matching_hf_techs)[:4]} are high-frequency across memory "
                f"(total freq {total_freq})"
            )
            learning_signals.append("technique_cluster")

        # ════════════════════════════════════════════════════════════════
        # APPLY ADJUSTMENTS — with cap on total boost per entry
        # ════════════════════════════════════════════════════════════════
        max_boost = self.w["max_boost_per_entry"]

        # Cap risk boost
        risk_delta = _clamp(risk_delta, -2.0, max_boost)
        conf_delta = _clamp(conf_delta, -0.15, 0.30)
        exploit_delta = _clamp(exploit_delta, 0.0, 40.0)

        adjusted_risk    = _clamp(base_risk + risk_delta, 0.0, 10.0)
        adjusted_conf    = _clamp(base_conf + conf_delta, 0.0, 1.0)
        adjusted_exploit = _clamp(base_exploit + exploit_delta, 0.0, 100.0)

        # ── Re-derive priority from adjusted risk ────────────────────────
        # Also consider AI record priority if no learning boosts applied
        old_priority = (ai_record or {}).get("priority", "P3")
        if adjusted_risk >= self.w["p1_threshold"] or "IMMINENT" in learning_signals:
            new_priority = "P1"
        elif adjusted_risk >= self.w["p2_threshold"]:
            new_priority = "P2"
        elif adjusted_risk >= self.w["p3_threshold"]:
            new_priority = "P3"
        else:
            new_priority = "P4"

        # Priority can only increase, never decrease from AI assessment
        priority_order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
        if priority_order.get(new_priority, 4) > priority_order.get(old_priority, 4):
            new_priority = old_priority  # Keep higher (lower number = higher priority)

        return {
            "advisory_id":          entry.get("advisory_id", entry.get("id", "")),
            "title":                entry.get("title", "")[:80],
            "base_risk":            round(base_risk, 3),
            "base_confidence":      round(base_conf, 3),
            "base_exploit_prob":    round(base_exploit, 1),
            "risk_delta":           round(risk_delta, 3),
            "confidence_delta":     round(conf_delta, 3),
            "exploit_prob_delta":   round(exploit_delta, 1),
            "adjusted_risk":        round(adjusted_risk, 3),
            "adjusted_confidence":  round(adjusted_conf, 3),
            "adjusted_exploit_prob": round(adjusted_exploit, 1),
            "old_priority":         old_priority,
            "new_priority":         new_priority,
            "reasons":              reasons,
            "learning_signals":     learning_signals,
            "signals_count":        len(learning_signals),
        }


# ---------------------------------------------------------------------------
# AI LEARNING ENGINE — main orchestrator
# ---------------------------------------------------------------------------

class AILearningEngine:
    """
    Main orchestrator. Reads memory → learns patterns → adjusts scores →
    writes adjusted AI index → saves learning state.
    """

    def __init__(self):
        self._start_ts  = _now_ts()
        self._start_iso = _now_iso()

    def _load_manifest(self) -> List[Dict]:
        data = _safe_load(MANIFEST_PATH, [])
        entries = data if isinstance(data, list) else data.get("entries", data.get("items", []))
        return entries if isinstance(entries, list) else []

    def _load_ai_index(self) -> Dict[str, Dict]:
        records = _safe_load(AI_INDEX_PATH, [])
        if not isinstance(records, list):
            return {}
        return {r.get("advisory_id", ""): r for r in records if r.get("advisory_id")}

    def _load_memory(self) -> Tuple[Dict, Dict, Dict]:
        cve_db      = _safe_load(CVE_MEMORY_PATH, {})
        actor_db    = _safe_load(ACTOR_MEMORY_PATH, {})
        campaign_db = _safe_load(CAMPAIGN_MEMORY_PATH, {})
        return cve_db, actor_db, campaign_db

    def _patch_manifest_entry(self, entry: Dict, adj: Dict) -> Dict:
        """
        Non-destructively patch a manifest entry with learning-adjusted fields.
        Prefixed with 'learned_' to avoid overwriting raw AI engine outputs.
        """
        entry["learned_risk_score"]    = adj["adjusted_risk"]
        entry["learned_confidence"]    = adj["adjusted_confidence"]
        entry["learned_exploit_prob"]  = adj["adjusted_exploit_prob"]
        entry["learned_priority"]      = adj["new_priority"]
        entry["learning_signals"]      = adj["learning_signals"]
        entry["learning_adjusted"]     = len(adj["learning_signals"]) > 0
        entry["learning_boost_total"]  = round(adj["risk_delta"], 3)
        return entry

    def _patch_ai_index_entry(self, ai_rec: Dict, adj: Dict) -> Dict:
        """Patch ai_index record with learning-adjusted scores."""
        ai_rec["learned_risk_score"]   = adj["adjusted_risk"]
        ai_rec["learned_confidence"]   = adj["adjusted_confidence"]
        ai_rec["learned_exploit_prob"] = adj["adjusted_exploit_prob"]
        ai_rec["learned_priority"]     = adj["new_priority"]
        ai_rec["learning_signals"]     = adj["learning_signals"]
        ai_rec["learning_adjusted"]    = len(adj["learning_signals"]) > 0
        return ai_rec

    def run(self) -> Dict:
        print("\n══════════════════════════════════════════════════════")
        print("  AI LEARNING ENGINE v1.0 — SENTINEL APEX")
        print("══════════════════════════════════════════════════════")
        print(f"  Started: {self._start_iso}")

        # ── 1. Load all data sources ─────────────────────────────────────
        entries   = self._load_manifest()
        ai_index  = self._load_ai_index()
        cve_db, actor_db, campaign_db = self._load_memory()

        print(f"  Manifest  : {len(entries)} entries")
        print(f"  AI Index  : {len(ai_index)} records")
        print(f"  CVE Memory: {len(cve_db)} CVEs")
        print(f"  Actors    : {len(actor_db)} actors")
        print(f"  Campaigns : {len(campaign_db)} campaigns")

        if not entries:
            print("  ⚠ No manifest entries — learning engine skipped")
            return self._build_result("no_manifest", {}, {}, [], [], 0)

        # ── 2. Analyze patterns from memory ─────────────────────────────
        print("\n  ── Pattern Analysis ──")
        analyzer = PatternAnalyzer(cve_db, actor_db, campaign_db)
        pattern_summary = analyzer.summarize()
        high_freq_techs = analyzer.get_high_frequency_techniques(top_n=20)

        for k, v in pattern_summary.items():
            print(f"    {k:<35} {v}")

        # ── 3. Learn / adapt weights ─────────────────────────────────────
        print("\n  ── Weight Learning ──")
        learner = WeightLearner()
        weight_adjustments = learner.adapt(pattern_summary)

        if weight_adjustments:
            for key, reason in weight_adjustments.items():
                print(f"    ⚡ {key}: {reason}")
        else:
            print("    ● Weights stable — no significant pattern shifts detected")

        # ── 4. Apply adjusted scores to every advisory ───────────────────
        print("\n  ── Score Adjustment Pass ──")
        adjuster = ScoreAdjuster(learner.weights, analyzer, high_freq_techs)

        adjustment_log: List[Dict] = []
        adjusted_entries = 0
        priority_escalated = 0
        total_risk_boost = 0.0

        updated_manifest = []
        updated_ai_index: List[Dict] = []

        for entry in entries:
            try:
                aid = entry.get("advisory_id", entry.get("id", ""))
                ai_rec = ai_index.get(aid)
                adj = adjuster.adjust(entry, ai_rec)

                # Patch manifest
                patched = self._patch_manifest_entry(dict(entry), adj)
                updated_manifest.append(patched)

                # Patch AI index
                if ai_rec:
                    patched_ai = self._patch_ai_index_entry(dict(ai_rec), adj)
                    updated_ai_index.append(patched_ai)

                # Track metrics
                if adj["risk_delta"] != 0 or adj["confidence_delta"] != 0:
                    adjusted_entries += 1
                    total_risk_boost += adj["risk_delta"]
                if adj["new_priority"] < adj["old_priority"]:  # P1 < P2 (escalated)
                    priority_escalated += 1

                # Only log entries that were actually adjusted
                if adj["learning_signals"]:
                    adjustment_log.append(adj)

            except Exception as e:
                logger.warning(f"[LEARN] Adjustment error for entry: {e}")
                updated_manifest.append(entry)
                if ai_rec:
                    updated_ai_index.append(ai_rec)
                continue

        print(f"    ✓ {len(entries)} advisories processed")
        print(f"    ✓ {adjusted_entries} entries adjusted by learning")
        print(f"    ✓ {priority_escalated} priorities escalated")
        print(f"    ✓ Avg risk boost: {total_risk_boost/max(len(entries),1):.3f}")

        # ── 5. Save adjusted outputs ─────────────────────────────────────
        print("\n  ── Saving Outputs ──")

        # Save adjusted manifest
        manifest_data = _safe_load(MANIFEST_PATH, [])
        if isinstance(manifest_data, list):
            save_ok_manifest = _safe_write(MANIFEST_PATH, updated_manifest)
        else:
            manifest_data["entries" if "entries" in manifest_data else "items"] = updated_manifest
            save_ok_manifest = _safe_write(MANIFEST_PATH, manifest_data)

        # Save adjusted AI index
        save_ok_ai = _safe_write(AI_INDEX_PATH, updated_ai_index)

        # Save adjustment log
        save_ok_adj = _safe_write(ADJUSTED_SCORES_PATH, {
            "generated_at": _now_iso(),
            "total_adjusted": adjusted_entries,
            "priority_escalated": priority_escalated,
            "avg_risk_boost": round(total_risk_boost / max(len(entries), 1), 4),
            "adjustments": adjustment_log[:200],  # cap at 200 for storage
        })

        print(f"    ✓ Manifest saved: {save_ok_manifest}")
        print(f"    ✓ AI index saved: {save_ok_ai}")
        print(f"    ✓ Adjustment log: {save_ok_adj}")

        # ── 6. Save learning model state ─────────────────────────────────
        learner.save(pattern_summary)
        print(f"    ✓ Learning model saved (run #{learner.run_count})")

        # ── 7. Generate learning report ──────────────────────────────────
        result = self._build_result(
            "success", pattern_summary, weight_adjustments,
            adjustment_log, list(high_freq_techs.keys()[:10]),
            adjusted_entries
        )
        result.update({
            "priority_escalated":  priority_escalated,
            "total_risk_boost":    round(total_risk_boost, 3),
            "avg_risk_boost":      round(total_risk_boost / max(len(entries), 1), 4),
            "weight_run":          learner.run_count,
            "current_weights":     {
                k: round(v, 4) if isinstance(v, float) else v
                for k, v in learner.weights.items()
            },
            "pattern_summary":     pattern_summary,
        })
        _safe_write(LEARNING_REPORT_PATH, result)

        print(f"\n  ✓ Learning Engine complete")
        print(f"    Adjusted: {adjusted_entries} | Escalated: {priority_escalated} | "
              f"Avg boost: +{result['avg_risk_boost']:.3f}")
        print("══════════════════════════════════════════════════════\n")

        return result

    def _build_result(self, status: str, patterns: Dict,
                      weight_adjustments: Dict, adj_log: List,
                      top_techniques: List, adjusted_count: int) -> Dict:
        return {
            "engine":              "AILearningEngine",
            "version":             "v1.0",
            "status":              status,
            "started_at":          self._start_iso,
            "finished_at":         _now_iso(),
            "duration_s":          round(_now_ts() - self._start_ts, 2),
            "entries_adjusted":    adjusted_count,
            "weight_adaptations":  len(weight_adjustments),
            "weight_adjustments":  weight_adjustments,
            "top_techniques":      top_techniques,
        }


# ---------------------------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    """CLI entry point — called by workflow Stage 6e."""
    try:
        engine = AILearningEngine()
        result = engine.run()
        status = result.get("status", "unknown")
        if status == "success":
            print(f"[LEARN] ✓ AI Learning Engine completed successfully")
            sys.exit(0)
        else:
            print(f"[LEARN] ⚠ Status: {status} — pipeline continues")
            sys.exit(0)
    except Exception as e:
        logger.error(f"[LEARN] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        # Always exit 0 — zero failure architecture
        sys.exit(0)


if __name__ == "__main__":
    main()
