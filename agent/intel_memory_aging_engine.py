#!/usr/bin/env python3
"""
agent/intel_memory_aging_engine.py
CYBERDUDEBIVASH® SENTINEL APEX — INTELLIGENCE MEMORY & AGING ENGINE v1.0
================================================================================
PHASE 5: INTELLIGENCE MEMORY & AGING

MISSION:
  Transform SENTINEL APEX from a stateless per-run system into a temporal
  intelligence platform that accumulates, ages, and evolves threat memory
  across every pipeline execution.

CAPABILITIES:
  1. Temporal IOC memory          — track every IOC across all runs
  2. Intelligence lifecycle engine — manage IOC lifecycle states
  3. Recurring campaign tracking  — detect campaign reappearances
  4. Infrastructure persistence   — track persistent C2/hosting infra
  5. Stale IOC retirement         — automatically retire aged-out IOCs
  6. Temporal decay scoring       — confidence degrades over time
  7. Recurring actor detection    — detect actor campaign recurrence
  8. Campaign evolution tracking  — track technique/TTPs shifts over time
  9. Historical threat similarity — score new threats against memory

IOC LIFECYCLE STATES:
  ACTIVE      — observed within decay window (< 30 days)
  PERSISTENT  — active for > 30 days (high persistence risk)
  AGING       — 30–90 days since last observation
  STALE       — 90–180 days — retired from active blocking lists
  RETIRED     — > 180 days — archived, minimal operational relevance

DESIGN PRINCIPLES:
  - Idempotent: re-running on same data never duplicates memory entries
  - Atomic writes: temp→rename pattern — never corrupt on crash
  - Backward compatible: new fields default gracefully
  - Zero failure: all exceptions caught, pipeline never blocked
  - Deterministic: same input sequence → same memory state

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("CDB-INTEL-MEMORY-AGING")
VERSION = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

IOC_LIFECYCLE_DAYS: Dict[str, int] = {
    "ACTIVE":     30,
    "PERSISTENT": 30,   # if still active after 30d → PERSISTENT
    "AGING":      90,
    "STALE":      180,
    "RETIRED":    999,  # effectively permanent archive
}

# Decay curve: days since last seen → confidence multiplier
IOC_DECAY_CURVE: List[Tuple[int, float]] = [
    (0,   1.000),
    (7,   0.920),
    (14,  0.820),
    (30,  0.650),
    (45,  0.500),
    (60,  0.380),
    (90,  0.250),
    (120, 0.150),
    (180, 0.080),
    (365, 0.030),
]

# Minimum memory age thresholds
MIN_OCCURRENCES_FOR_PERSISTENT = 3   # Seen 3+ times → mark as persistent
MIN_OCCURRENCES_FOR_RECURRING  = 2   # Seen 2+ times across runs → recurring actor

# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_paths(base_dir: Optional[Path] = None) -> Dict[str, Path]:
    base = base_dir or Path(__file__).resolve().parent.parent
    mem_dir = base / "data" / "threat_memory"
    mem_dir.mkdir(parents=True, exist_ok=True)
    return {
        "base":         base,
        "memory_dir":   mem_dir,
        "ioc_memory":   mem_dir / "ioc_memory.json",
        "actor_memory": mem_dir / "actor_memory.json",
        "campaign_mem": mem_dir / "campaign_memory.json",
        "infra_memory": mem_dir / "infrastructure_memory.json",
        "aging_report": mem_dir / "aging_report.json",
        "memory_meta":  mem_dir / "memory_meta.json",
    }


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(iso: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except Exception:
        return None


def _days_since(iso: str) -> int:
    dt = _parse_dt(iso)
    if not dt:
        return 999
    return max(0, (_now_dt() - dt).days)


def _decay_multiplier(days: int) -> float:
    for i, (threshold, mult) in enumerate(IOC_DECAY_CURVE):
        if days <= threshold:
            return mult
        if i + 1 < len(IOC_DECAY_CURVE):
            next_thresh, next_mult = IOC_DECAY_CURVE[i + 1]
            if days <= next_thresh:
                frac = (days - threshold) / (next_thresh - threshold)
                return mult + frac * (next_mult - mult)
    return 0.030


def _lifecycle_state(days_since_last_seen: int, occurrence_count: int) -> str:
    if days_since_last_seen <= IOC_LIFECYCLE_DAYS["ACTIVE"]:
        return "PERSISTENT" if occurrence_count >= MIN_OCCURRENCES_FOR_PERSISTENT else "ACTIVE"
    if days_since_last_seen <= IOC_LIFECYCLE_DAYS["AGING"]:
        return "AGING"
    if days_since_last_seen <= IOC_LIFECYCLE_DAYS["STALE"]:
        return "STALE"
    return "RETIRED"


def _safe_write(path: Path, data: Any) -> None:
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=str)
    tmp.replace(path)


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"[MEMORY] Load error {path.name}: {e}")
        return default


# ─────────────────────────────────────────────────────────────────────────────
# IOC MEMORY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class IOCMemoryEngine:
    """
    Persistent IOC temporal memory.
    Tracks every IOC across all pipeline runs with full lifecycle management.
    """

    def __init__(self, paths: Dict[str, Path]):
        self.paths   = paths
        self.memory: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        data = _load_json(self.paths["ioc_memory"], {})
        self.memory = data.get("ioc_entries", {}) if isinstance(data, dict) else {}

    def update(self, ioc_value: str, ioc_type: str, advisory_id: str,
               confidence: float, source: str) -> Dict:
        """Upsert IOC into memory. Idempotent — merge, never duplicate."""
        key = f"{ioc_type}:{ioc_value.lower().strip()}"

        if key in self.memory:
            entry = self.memory[key]
            # Update recurrence fields
            entry["last_seen"]          = _now_iso()
            entry["occurrence_count"]   = entry.get("occurrence_count", 1) + 1
            entry["max_confidence"]     = max(entry.get("max_confidence", 0.0), confidence)
            entry["current_confidence"] = confidence
            # Append advisory if not seen
            if advisory_id not in entry.get("advisory_ids", []):
                advisories = entry.get("advisory_ids", [])
                advisories.append(advisory_id)
                entry["advisory_ids"] = advisories[-50:]  # cap at 50
            if source not in entry.get("sources", []):
                entry["sources"] = entry.get("sources", []) + [source]
        else:
            entry = {
                "ioc_key":          key,
                "ioc_value":        ioc_value,
                "ioc_type":         ioc_type,
                "first_seen":       _now_iso(),
                "last_seen":        _now_iso(),
                "occurrence_count": 1,
                "max_confidence":   confidence,
                "current_confidence": confidence,
                "advisory_ids":     [advisory_id],
                "sources":          [source],
                "lifecycle_state":  "ACTIVE",
                "decayed_confidence": confidence,
                "persistence_score": 0.0,
            }
        self.memory[key] = entry
        return entry

    def apply_aging(self) -> Dict[str, int]:
        """Apply temporal decay to all IOCs. Returns aging report summary."""
        state_counts: Dict[str, int] = defaultdict(int)
        retired_count = 0
        for key, entry in self.memory.items():
            days = _days_since(entry.get("last_seen", _now_iso()))
            mult  = _decay_multiplier(days)
            count = entry.get("occurrence_count", 1)
            state = _lifecycle_state(days, count)

            entry["lifecycle_state"]   = state
            entry["days_since_seen"]   = days
            entry["decay_multiplier"]  = round(mult, 4)
            entry["decayed_confidence"] = round(
                entry.get("max_confidence", 0.0) * mult, 2
            )
            # Persistence score: frequency × longevity
            entry["persistence_score"] = round(
                min(100.0, count * 10.0 * (1.0 - days / 365.0)), 2
            )
            state_counts[state] += 1
            if state == "RETIRED":
                retired_count += 1

        return {
            "ACTIVE":     state_counts.get("ACTIVE", 0),
            "PERSISTENT": state_counts.get("PERSISTENT", 0),
            "AGING":      state_counts.get("AGING", 0),
            "STALE":      state_counts.get("STALE", 0),
            "RETIRED":    state_counts.get("RETIRED", 0),
            "total":      len(self.memory),
            "retired_this_run": retired_count,
        }

    def get_active_iocs(self) -> List[Dict]:
        return [
            e for e in self.memory.values()
            if e.get("lifecycle_state") in ("ACTIVE", "PERSISTENT")
        ]

    def get_high_persistence_iocs(self, min_score: float = 30.0) -> List[Dict]:
        return sorted(
            [e for e in self.memory.values() if e.get("persistence_score", 0) >= min_score],
            key=lambda x: x.get("persistence_score", 0), reverse=True
        )[:100]

    def persist(self) -> None:
        _safe_write(self.paths["ioc_memory"], {
            "version":     VERSION,
            "total_iocs":  len(self.memory),
            "ioc_entries": self.memory,
            "updated_at":  _now_iso(),
        })


# ─────────────────────────────────────────────────────────────────────────────
# ACTOR MEMORY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ActorMemoryEngine:
    """
    Track threat actor activity patterns across pipeline runs.
    Detects recurring actor campaigns and TTP evolution.
    """

    def __init__(self, paths: Dict[str, Path]):
        self.paths  = paths
        self.memory: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        data = _load_json(self.paths["actor_memory"], {})
        self.memory = data.get("actor_entries", {}) if isinstance(data, dict) else {}

    def update(self, actor_id: str, advisory: Dict) -> None:
        """Update actor memory from advisory data."""
        if not actor_id or actor_id in ("UNKNOWN", "UNCLASSIFIED"):
            return

        ttps     = [str(t).upper() for t in (advisory.get("ttps") or []) if t]
        campaign = str(advisory.get("campaign", "") or "UNCLASSIFIED")
        source   = str(advisory.get("feed_source", "unknown"))
        stix_id  = str(advisory.get("stix_id", ""))

        if actor_id in self.memory:
            entry = self.memory[actor_id]
            entry["last_seen"]          = _now_iso()
            entry["advisory_count"]     = entry.get("advisory_count", 1) + 1
            entry["campaign_count"]     = entry.get("campaign_count", 0)

            # TTP evolution tracking
            old_ttps = set(entry.get("observed_ttps", []))
            new_ttps = set(ttps) - old_ttps
            if new_ttps:
                entry["new_ttps_this_run"] = list(new_ttps)
                entry["observed_ttps"]     = list(old_ttps | set(ttps))[:100]
                entry["ttp_evolution_events"] = entry.get("ttp_evolution_events", 0) + 1
            else:
                entry["new_ttps_this_run"] = []

            # Campaign tracking
            camps = entry.get("campaigns", [])
            if campaign not in camps:
                camps.append(campaign)
                entry["campaigns"]     = camps[-20:]
                entry["campaign_count"] = len(camps)

            # Source diversity
            sources = entry.get("sources", [])
            if source not in sources:
                entry["sources"] = sources + [source]

            # Advisory history
            adv_hist = entry.get("advisory_ids", [])
            if stix_id not in adv_hist:
                entry["advisory_ids"] = (adv_hist + [stix_id])[-50:]

        else:
            self.memory[actor_id] = {
                "actor_id":           actor_id,
                "first_seen":         _now_iso(),
                "last_seen":          _now_iso(),
                "advisory_count":     1,
                "campaign_count":     1 if campaign != "UNCLASSIFIED" else 0,
                "observed_ttps":      ttps[:100],
                "campaigns":          [campaign] if campaign != "UNCLASSIFIED" else [],
                "sources":            [source],
                "advisory_ids":       [stix_id],
                "ttp_evolution_events": 0,
                "new_ttps_this_run":  [],
                "is_recurring":       False,
            }

        # Mark as recurring
        entry = self.memory[actor_id]
        entry["is_recurring"] = entry.get("advisory_count", 1) >= MIN_OCCURRENCES_FOR_RECURRING

    def get_recurring_actors(self) -> List[Dict]:
        return [e for e in self.memory.values() if e.get("is_recurring", False)]

    def persist(self) -> None:
        _safe_write(self.paths["actor_memory"], {
            "version":       VERSION,
            "total_actors":  len(self.memory),
            "actor_entries": self.memory,
            "updated_at":    _now_iso(),
        })


# ─────────────────────────────────────────────────────────────────────────────
# CAMPAIGN MEMORY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CampaignMemoryEngine:
    """
    Track campaign evolution across pipeline runs.
    Detects recurring campaigns, technique inheritance, and threat escalation.
    """

    def __init__(self, paths: Dict[str, Path]):
        self.paths  = paths
        self.memory: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        data = _load_json(self.paths["campaign_mem"], {})
        self.memory = data.get("campaign_entries", {}) if isinstance(data, dict) else {}

    def update(self, campaign_id: str, advisory: Dict) -> None:
        if not campaign_id or campaign_id in ("UNCLASSIFIED", "UNKNOWN"):
            return

        ttps     = [str(t).upper() for t in (advisory.get("ttps") or []) if t]
        actor    = str(advisory.get("actor_cluster", "") or "UNKNOWN")
        stix_id  = str(advisory.get("stix_id", ""))
        risk     = float(advisory.get("risk_score") or advisory.get("composite_score") or 5.0)

        if campaign_id in self.memory:
            entry = self.memory[campaign_id]
            entry["last_seen"]     = _now_iso()
            entry["advisory_count"] = entry.get("advisory_count", 1) + 1
            entry["max_risk_score"] = max(entry.get("max_risk_score", 0.0), risk)

            # TTP accumulation
            old_ttps = set(entry.get("ttps", []))
            all_ttps = old_ttps | set(ttps)
            entry["ttps"] = list(all_ttps)[:100]
            entry["ttp_count"] = len(all_ttps)

            # IOC count accumulation
            ioc_count = len(advisory.get("iocs") or [])
            entry["total_ioc_count"] = entry.get("total_ioc_count", 0) + ioc_count

            # Evolution score: grows with TTP diversity over time
            entry["evolution_score"] = round(
                min(100.0, (entry["advisory_count"] * 5.0) + (entry["ttp_count"] * 2.0)), 1
            )

            adv_hist = entry.get("advisory_ids", [])
            if stix_id not in adv_hist:
                entry["advisory_ids"] = (adv_hist + [stix_id])[-50:]
        else:
            self.memory[campaign_id] = {
                "campaign_id":    campaign_id,
                "first_seen":     _now_iso(),
                "last_seen":      _now_iso(),
                "advisory_count": 1,
                "ttps":           ttps[:100],
                "ttp_count":      len(ttps),
                "actor":          actor,
                "max_risk_score": risk,
                "total_ioc_count": len(advisory.get("iocs") or []),
                "advisory_ids":   [stix_id],
                "evolution_score": 0.0,
                "is_recurring":   False,
            }

        entry = self.memory[campaign_id]
        entry["is_recurring"] = entry.get("advisory_count", 1) >= MIN_OCCURRENCES_FOR_RECURRING

    def get_recurring_campaigns(self) -> List[Dict]:
        return sorted(
            [e for e in self.memory.values() if e.get("is_recurring", False)],
            key=lambda x: x.get("evolution_score", 0), reverse=True
        )

    def persist(self) -> None:
        _safe_write(self.paths["campaign_mem"], {
            "version":         VERSION,
            "total_campaigns": len(self.memory),
            "campaign_entries": self.memory,
            "updated_at":      _now_iso(),
        })


# ─────────────────────────────────────────────────────────────────────────────
# INFRASTRUCTURE PERSISTENCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class InfrastructurePersistenceEngine:
    """
    Track persistent C2/hosting infrastructure across time.
    Detects long-lived malicious infrastructure (the most operationally dangerous).
    """

    def __init__(self, paths: Dict[str, Path]):
        self.paths  = paths
        self.memory: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        data = _load_json(self.paths["infra_memory"], {})
        self.memory = data.get("infra_entries", {}) if isinstance(data, dict) else {}

    def update_from_iocs(self, advisory: Dict) -> None:
        stix_id = str(advisory.get("stix_id", ""))
        actor   = str(advisory.get("actor_cluster", "") or "UNKNOWN")
        iocs    = advisory.get("iocs") or []

        for ioc in iocs:
            if isinstance(ioc, dict):
                ioc_type = str(ioc.get("type", "indicator"))
                ioc_val  = str(ioc.get("value", ""))
                conf     = float(ioc.get("confidence", 50.0))
            elif isinstance(ioc, str):
                ioc_type, ioc_val, conf = "indicator", ioc, 50.0
            else:
                continue

            if ioc_type not in ("ip", "domain", "url"):
                continue
            if not ioc_val:
                continue

            key = f"{ioc_type}:{ioc_val.lower()}"
            if key in self.memory:
                entry = self.memory[key]
                entry["last_seen"]      = _now_iso()
                entry["sighting_count"] = entry.get("sighting_count", 1) + 1
                if actor not in entry.get("associated_actors", []):
                    entry["associated_actors"] = entry.get("associated_actors", []) + [actor]
                if stix_id not in entry.get("advisory_ids", []):
                    entry["advisory_ids"] = (entry.get("advisory_ids", []) + [stix_id])[-50:]
                # Persistence tier upgrade
                days = _days_since(entry["first_seen"])
                entry["infrastructure_age_days"] = days
                entry["persistence_tier"] = (
                    "LONG_LIVED" if days > 90 else
                    "MEDIUM_LIVED" if days > 30 else "SHORT_LIVED"
                )
                entry["multi_actor"] = len(entry.get("associated_actors", [])) > 1
            else:
                self.memory[key] = {
                    "infra_key":             key,
                    "ioc_type":              ioc_type,
                    "ioc_value":             ioc_val,
                    "first_seen":            _now_iso(),
                    "last_seen":             _now_iso(),
                    "sighting_count":        1,
                    "associated_actors":     [actor],
                    "advisory_ids":          [stix_id],
                    "infrastructure_age_days": 0,
                    "persistence_tier":      "SHORT_LIVED",
                    "multi_actor":           False,
                    "confidence":            conf,
                }

    def get_persistent_infra(self, min_sightings: int = 2) -> List[Dict]:
        return sorted(
            [e for e in self.memory.values() if e.get("sighting_count", 0) >= min_sightings],
            key=lambda x: x.get("sighting_count", 0), reverse=True
        )[:100]

    def get_multi_actor_infra(self) -> List[Dict]:
        return [e for e in self.memory.values() if e.get("multi_actor", False)]

    def persist(self) -> None:
        _safe_write(self.paths["infra_memory"], {
            "version":      VERSION,
            "total_infra":  len(self.memory),
            "infra_entries": self.memory,
            "updated_at":   _now_iso(),
        })


# ─────────────────────────────────────────────────────────────────────────────
# HISTORICAL SIMILARITY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class HistoricalSimilarityEngine:
    """
    Score new advisories against historical high-risk memory.
    Uses TTP Jaccard similarity (deterministic, reproducible).
    """

    def score_similarity(
        self,
        advisory: Dict,
        actor_memory: Dict[str, Dict],
        campaign_memory: Dict[str, Dict],
    ) -> Dict:
        actor = str(advisory.get("actor_cluster", "") or "UNKNOWN")
        camp  = str(advisory.get("campaign", "") or "UNCLASSIFIED")
        ttps  = set(str(t).upper() for t in (advisory.get("ttps") or []) if t)

        actor_sim  = 0.0
        camp_sim   = 0.0
        actor_hist = []
        camp_hist  = []

        # Actor TTP similarity
        if actor in actor_memory:
            hist_ttps = set(actor_memory[actor].get("observed_ttps", []))
            if ttps and hist_ttps:
                actor_sim = round(len(ttps & hist_ttps) / len(ttps | hist_ttps), 3)
            actor_hist = list(ttps & hist_ttps)[:5]

        # Campaign TTP similarity
        if camp in campaign_memory:
            hist_ttps = set(campaign_memory[camp].get("ttps", []))
            if ttps and hist_ttps:
                camp_sim = round(len(ttps & hist_ttps) / len(ttps | hist_ttps), 3)
            camp_hist = list(ttps & hist_ttps)[:5]

        combined_sim = round((actor_sim * 0.6 + camp_sim * 0.4), 3)

        return {
            "advisory_id":         advisory.get("stix_id", ""),
            "actor_similarity":    actor_sim,
            "campaign_similarity": camp_sim,
            "combined_similarity": combined_sim,
            "shared_actor_ttps":   actor_hist,
            "shared_campaign_ttps": camp_hist,
            "is_recurring_actor":  actor in actor_memory and actor_memory[actor].get("is_recurring", False),
            "is_recurring_campaign": camp in campaign_memory and campaign_memory[camp].get("is_recurring", False),
            "similarity_tier": (
                "HIGH" if combined_sim >= 0.6 else
                "MEDIUM" if combined_sim >= 0.3 else "LOW"
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# MASTER INTELLIGENCE MEMORY & AGING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class IntelMemoryAgingEngine:
    """
    SENTINEL APEX — Intelligence Memory & Aging Engine v1.0

    Orchestrates full temporal intelligence lifecycle:
      1. Update IOC memory from current batch
      2. Update actor memory
      3. Update campaign memory
      4. Update infrastructure persistence memory
      5. Apply temporal aging/decay to all IOCs
      6. Compute historical similarity for new advisories
      7. Retire stale IOCs
      8. Persist all memory stores
      9. Generate aging report
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self.paths     = _resolve_paths(base_dir)
        self.ioc_mem   = IOCMemoryEngine(self.paths)
        self.actor_mem = ActorMemoryEngine(self.paths)
        self.camp_mem  = CampaignMemoryEngine(self.paths)
        self.infra_mem = InfrastructurePersistenceEngine(self.paths)
        self.hist_sim  = HistoricalSimilarityEngine()

    def run_full_pipeline(self, advisories: List[Dict]) -> Dict:
        """
        Run complete memory & aging pipeline.
        Returns comprehensive aging report.
        Never raises — all errors caught.
        """
        try:
            return self._run_internal(advisories)
        except Exception as e:
            logger.error(f"[INTEL-MEMORY-AGING] Pipeline error: {e}")
            return {"error": str(e), "status": "FAILED", "generated_at": _now_iso()}

    def _run_internal(self, advisories: List[Dict]) -> Dict:
        logger.info(f"[INTEL-MEMORY-AGING] Processing {len(advisories)} advisories")
        similarity_results = []

        for adv in advisories:
            try:
                stix_id = str(adv.get("stix_id", ""))
                actor   = str(adv.get("actor_cluster", "") or adv.get("threat_actor", "") or "UNKNOWN")
                camp    = str(adv.get("campaign", "") or "UNCLASSIFIED")
                source  = str(adv.get("feed_source", "unknown"))

                # 1. IOC memory update
                for ioc in (adv.get("iocs") or []):
                    if isinstance(ioc, dict):
                        val  = str(ioc.get("value", ""))
                        typ  = str(ioc.get("type", "indicator"))
                        conf = float(ioc.get("confidence", 50.0))
                    elif isinstance(ioc, str):
                        val, typ, conf = ioc, "indicator", 50.0
                    else:
                        continue
                    if val:
                        self.ioc_mem.update(val, typ, stix_id, conf, source)

                # 2. Actor memory
                self.actor_mem.update(actor, adv)

                # 3. Campaign memory
                self.camp_mem.update(camp, adv)

                # 4. Infrastructure persistence
                self.infra_mem.update_from_iocs(adv)

                # 5. Historical similarity
                sim = self.hist_sim.score_similarity(
                    adv,
                    self.actor_mem.memory,
                    self.camp_mem.memory,
                )
                similarity_results.append(sim)

            except Exception as e:
                logger.warning(f"[INTEL-MEMORY-AGING] Advisory {adv.get('stix_id','?')}: {e}")

        # 6. Apply IOC aging
        aging_summary = self.ioc_mem.apply_aging()

        # 7. Persist all memory stores
        self.ioc_mem.persist()
        self.actor_mem.persist()
        self.camp_mem.persist()
        self.infra_mem.persist()

        # 8. Build analytics
        recurring_actors   = self.actor_mem.get_recurring_actors()
        recurring_campaigns = self.camp_mem.get_recurring_campaigns()
        persistent_infra   = self.infra_mem.get_persistent_infra()
        multi_actor_infra  = self.infra_mem.get_multi_actor_infra()
        high_persist_iocs  = self.ioc_mem.get_high_persistence_iocs()
        active_iocs        = self.ioc_mem.get_active_iocs()

        report = {
            "engine":          "IntelMemoryAgingEngine",
            "version":         VERSION,
            "run_stats": {
                "advisories_processed": len(advisories),
                "iocs_updated":         len(self.ioc_mem.memory),
                "actors_tracked":       len(self.actor_mem.memory),
                "campaigns_tracked":    len(self.camp_mem.memory),
                "infra_tracked":        len(self.infra_mem.memory),
            },
            "ioc_lifecycle": aging_summary,
            "active_ioc_count": len(active_iocs),
            "high_persistence_iocs": [
                {"key": e["ioc_key"], "score": e.get("persistence_score", 0),
                 "state": e.get("lifecycle_state", ""), "sightings": e.get("occurrence_count", 0)}
                for e in high_persist_iocs[:20]
            ],
            "recurring_actors": [
                {"actor": e["actor_id"], "advisories": e.get("advisory_count", 0),
                 "ttp_count": len(e.get("observed_ttps", [])),
                 "evolution_events": e.get("ttp_evolution_events", 0)}
                for e in recurring_actors[:20]
            ],
            "recurring_campaigns": [
                {"campaign": e["campaign_id"], "advisories": e.get("advisory_count", 0),
                 "evolution_score": e.get("evolution_score", 0),
                 "max_risk": e.get("max_risk_score", 0)}
                for e in recurring_campaigns[:20]
            ],
            "persistent_infrastructure": [
                {"ioc": e["ioc_value"], "type": e["ioc_type"],
                 "sightings": e.get("sighting_count", 0),
                 "tier": e.get("persistence_tier", ""),
                 "multi_actor": e.get("multi_actor", False)}
                for e in persistent_infra[:20]
            ],
            "multi_actor_infrastructure_count": len(multi_actor_infra),
            "similarity_summary": {
                "HIGH":   sum(1 for s in similarity_results if s.get("similarity_tier") == "HIGH"),
                "MEDIUM": sum(1 for s in similarity_results if s.get("similarity_tier") == "MEDIUM"),
                "LOW":    sum(1 for s in similarity_results if s.get("similarity_tier") == "LOW"),
            },
            "generated_at": _now_iso(),
        }

        _safe_write(self.paths["aging_report"], report)

        # Meta
        meta_data = _load_json(self.paths["memory_meta"], {})
        runs = meta_data.get("run_count", 0) + 1
        _safe_write(self.paths["memory_meta"], {
            "version":      VERSION,
            "run_count":    runs,
            "last_run":     _now_iso(),
            "total_iocs":   len(self.ioc_mem.memory),
            "total_actors": len(self.actor_mem.memory),
            "total_campaigns": len(self.camp_mem.memory),
            "total_infra":  len(self.infra_mem.memory),
        })

        logger.info(
            f"[INTEL-MEMORY-AGING] Complete: "
            f"IOCs={len(self.ioc_mem.memory)} "
            f"actors={len(self.actor_mem.memory)} "
            f"campaigns={len(self.camp_mem.memory)} "
            f"ACTIVE={aging_summary.get('ACTIVE',0)} "
            f"RETIRED={aging_summary.get('RETIRED',0)}"
        )
        return report


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CDB-INTEL-MEMORY-AGING] %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    BASE_DIR      = Path(__file__).resolve().parent.parent
    MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"

    if not MANIFEST_PATH.exists():
        logger.warning("[INTEL-MEMORY-AGING] No manifest — exiting cleanly")
        sys.exit(0)

    try:
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)
    except Exception as e:
        logger.error(f"[INTEL-MEMORY-AGING] Manifest load error: {e}")
        sys.exit(0)

    advisories = manifest.get("items", manifest.get("advisories", []))
    if not advisories:
        logger.info("[INTEL-MEMORY-AGING] No advisories — nothing to do")
        sys.exit(0)

    engine = IntelMemoryAgingEngine(BASE_DIR)
    report = engine.run_full_pipeline(advisories)
    logger.info(
        f"[INTEL-MEMORY-AGING] Report: "
        f"active_iocs={report.get('active_ioc_count',0)} "
        f"recurring_actors={len(report.get('recurring_actors',[]))} "
        f"recurring_campaigns={len(report.get('recurring_campaigns',[]))}"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
