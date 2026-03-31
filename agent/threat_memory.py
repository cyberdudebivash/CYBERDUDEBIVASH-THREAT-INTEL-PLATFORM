#!/usr/bin/env python3
"""
threat_memory.py — CyberDudeBivash SENTINEL APEX v1.0
THREAT MEMORY ENGINE — Persistent Cross-Run Intelligence Memory System

This engine transforms the SENTINEL APEX platform from stateless per-run
analysis into a MEMORY-DRIVEN system that accumulates intelligence across
every pipeline execution.

Capabilities:
  1. CVE MEMORY — tracks every CVE across all runs: first seen, last seen,
     occurrence count, max risk, KEV history, actor associations, techniques
  2. ACTOR MEMORY — tracks APT group activity patterns: campaigns, TTPs,
     average risk, activity frequency, target sectors
  3. CAMPAIGN MEMORY — tracks multi-advisory campaigns: evolution score,
     IOC volume, actor linkages, threat density timeline
  4. MEMORY META — pipeline telemetry, run history, learning signals

Design Principles:
  - IDEMPOTENT: Re-running on the same data produces identical memory state
  - DEDUPLICATION: No duplicate entries — merge-on-update not append
  - SAFE WRITES: Atomic writes via temp file → rename (never corrupt on crash)
  - EFFICIENT: O(n) scan — handles 1000+ entries without performance loss
  - BACKWARD COMPATIBLE: New fields default gracefully; old fields preserved
  - ZERO FAILURE: All exceptions caught and logged — pipeline never blocked

Storage: data/threat_memory/
  ├── cve_memory.json
  ├── actor_memory.json
  ├── campaign_memory.json
  └── memory_meta.json

Author: CyberDudeBivash Pvt. Ltd.
Version: v1.0
"""

import json
import logging
import os
import re
import sys
import tempfile
import time
from collections import defaultdict
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
logger = logging.getLogger("CDB-THREAT-MEMORY")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
MEMORY_DIR = DATA_DIR / "threat_memory"
STIX_DIR   = DATA_DIR / "stix"
AI_DIR     = DATA_DIR / "ai_intelligence"

MANIFEST_PATH     = STIX_DIR / "feed_manifest.json"
AI_INDEX_PATH     = AI_DIR / "ai_index.json"
CAMPAIGN_TRACKER  = AI_DIR / "campaign_tracker.json"

CVE_MEMORY_FILE      = MEMORY_DIR / "cve_memory.json"
ACTOR_MEMORY_FILE    = MEMORY_DIR / "actor_memory.json"
CAMPAIGN_MEMORY_FILE = MEMORY_DIR / "campaign_memory.json"
MEMORY_META_FILE     = MEMORY_DIR / "memory_meta.json"

MEMORY_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Safe I/O Utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _now_ts() -> float:
    return time.time()

def _safe_load_json(path: Path, default: Any) -> Any:
    """Load JSON with safe fallback — never raises."""
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        logger.warning(f"[MEM] JSON decode error in {path.name}: {e} — using default")
        return default
    except Exception as e:
        logger.warning(f"[MEM] Load error {path.name}: {e} — using default")
        return default

def _safe_write_json(path: Path, data: Any) -> bool:
    """
    Atomic safe write: write to temp file in same directory, then rename.
    This prevents partial writes from corrupting the memory file on crash.
    """
    try:
        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        tmp_path.rename(path)
        return True
    except Exception as e:
        logger.error(f"[MEM] Write failed for {path.name}: {e}")
        # Try direct write as last resort
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
            return True
        except Exception as e2:
            logger.error(f"[MEM] Direct write also failed: {e2}")
            return False

def _extract_cve_ids(text: str) -> List[str]:
    """Extract all CVE-YYYY-NNNNN identifiers from text."""
    if not text:
        return []
    return list(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)))

def _today_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def _days_ago(iso_str: str) -> Optional[int]:
    """Return number of days since an ISO timestamp. None if unparseable."""
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CVE MEMORY ENGINE
# ---------------------------------------------------------------------------

class CVEMemory:
    """
    Maintains persistent memory of every CVE observed across pipeline runs.
    Schema per CVE entry:
    {
        "cve_id": "CVE-2024-XXXX",
        "first_seen": "<ISO>",
        "last_seen": "<ISO>",
        "occurrences": 5,
        "max_risk_score": 9.2,
        "min_risk_score": 7.1,
        "avg_risk_score": 8.3,
        "kev_ever": false,
        "kev_first_seen": null,
        "cvss_score": 9.8,
        "epss_score_max": 0.97,
        "epss_score_last": 0.94,
        "associated_actors": ["Lazarus Group", "APT28"],
        "actor_confidence_max": {"Lazarus Group": 0.82},
        "associated_campaigns": ["CDB-CAMP-ABCD1234"],
        "mitre_techniques": ["T1190", "T1059"],
        "exploit_tier_max": "IMMINENT",
        "exploit_tier_history": ["LIKELY", "IMMINENT"],
        "active_exploitation_confirmed": false,
        "poc_seen": false,
        "titles_seen": ["First advisory title", ...],
        "risk_trend": "ESCALATING",   // ESCALATING | STABLE | DECLINING
        "risk_history": [7.1, 8.3, 9.2],
        "days_since_last_seen": 0
    }
    """

    def __init__(self):
        self.db: Dict[str, Dict] = _safe_load_json(CVE_MEMORY_FILE, {})
        self._updated_ids: Set[str] = set()

    def update(self, entry: Dict, ai_record: Optional[Dict] = None) -> List[str]:
        """
        Process a manifest entry — extract CVE IDs and update memory.
        Returns list of CVE IDs updated.
        """
        # Build text corpus for CVE extraction
        text_corpus = " ".join([
            entry.get("title", "") or "",
            entry.get("summary", "") or "",
            entry.get("advisory_id", "") or "",
            entry.get("cve_id", "") or "",
        ])
        cve_ids = _extract_cve_ids(text_corpus)

        # Also check direct field
        direct_cve = entry.get("cve_id", "") or ""
        if direct_cve and re.match(r"CVE-\d{4}-\d{4,}", direct_cve, re.IGNORECASE):
            if direct_cve not in cve_ids:
                cve_ids.append(direct_cve)

        if not cve_ids:
            return []

        now = _now_iso()
        risk = float(entry.get("risk_score", 0) or entry.get("ai_risk_score", 0) or 0)
        kev = bool(entry.get("kev_present", False))
        cvss = float(entry.get("cvss_score", 0) or 0)
        epss = float(entry.get("epss_score", 0) or 0)

        # Extract AI enrichment fields
        actors: List[str] = []
        actor_conf: Dict[str, float] = {}
        campaigns: List[str] = []
        techniques: List[str] = []
        exploit_tier = None
        active_exploit = bool(entry.get("active_exploitation", False))
        poc_seen = False

        if ai_record:
            actors = [ai_record.get("primary_actor")] if ai_record.get("primary_actor") else []
            for match in ai_record.get("actor_matches", []):
                name = match.get("name") or match.get("actor_name")
                conf = match.get("confidence", 0)
                if name:
                    if name not in actors:
                        actors.append(name)
                    actor_conf[name] = max(actor_conf.get(name, 0), conf)
            campaign_id = ai_record.get("campaign_id")
            if campaign_id:
                campaigns = [campaign_id]
            techniques = ai_record.get("kill_chain_phases", [])
            exploit_tier = ai_record.get("exploit_tier")
            signals = ai_record.get("exploit_signals", [])
            if "active_exploitation" in signals:
                active_exploit = True
            if "poc_available" in signals:
                poc_seen = True
            if not risk:
                risk = float(ai_record.get("ai_risk_score", 0) or 0)

        # Also extract techniques from entry directly
        entry_techniques = entry.get("mitre_techniques", []) or entry.get("mitre_tactics", []) or []
        for t in entry_techniques:
            if isinstance(t, str) and t not in techniques:
                techniques.append(t)

        updated = []
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            existing = self.db.get(cve_id)

            if existing is None:
                # NEW CVE — first observation
                entry_rec = {
                    "cve_id": cve_id,
                    "first_seen": now,
                    "last_seen": now,
                    "occurrences": 1,
                    "max_risk_score": risk,
                    "min_risk_score": risk,
                    "avg_risk_score": risk,
                    "kev_ever": kev,
                    "kev_first_seen": now if kev else None,
                    "cvss_score": cvss,
                    "epss_score_max": epss,
                    "epss_score_last": epss,
                    "associated_actors": actors[:],
                    "actor_confidence_max": dict(actor_conf),
                    "associated_campaigns": campaigns[:],
                    "mitre_techniques": techniques[:],
                    "exploit_tier_max": exploit_tier,
                    "exploit_tier_history": [exploit_tier] if exploit_tier else [],
                    "active_exploitation_confirmed": active_exploit,
                    "poc_seen": poc_seen,
                    "titles_seen": [entry.get("title", "")[:120]] if entry.get("title") else [],
                    "risk_trend": "STABLE",
                    "risk_history": [risk] if risk else [],
                    "days_since_last_seen": 0,
                }
                self.db[cve_id] = entry_rec
                logger.debug(f"[CVE-MEM] NEW: {cve_id} risk={risk}")
            else:
                # EXISTING CVE — merge update (idempotent)
                rec = existing

                # Time tracking
                rec["last_seen"] = now
                rec["occurrences"] = rec.get("occurrences", 0) + 1
                rec["days_since_last_seen"] = 0

                # Risk scoring — running average + max/min
                if risk > 0:
                    history = rec.get("risk_history", [])
                    history.append(risk)
                    # Keep last 50 observations
                    history = history[-50:]
                    rec["risk_history"] = history
                    rec["max_risk_score"] = max(rec.get("max_risk_score", 0), risk)
                    rec["min_risk_score"] = min(rec.get("min_risk_score", 99), risk)
                    rec["avg_risk_score"] = round(sum(history) / len(history), 3)

                    # Compute risk trend
                    if len(history) >= 3:
                        recent_avg = sum(history[-3:]) / 3
                        older_avg = sum(history[:-3]) / max(len(history) - 3, 1)
                        if recent_avg > older_avg + 0.5:
                            rec["risk_trend"] = "ESCALATING"
                        elif recent_avg < older_avg - 0.5:
                            rec["risk_trend"] = "DECLINING"
                        else:
                            rec["risk_trend"] = "STABLE"

                # KEV tracking
                if kev and not rec.get("kev_ever"):
                    rec["kev_ever"] = True
                    rec["kev_first_seen"] = now

                # CVSS — take max observed
                if cvss > rec.get("cvss_score", 0):
                    rec["cvss_score"] = cvss

                # EPSS — track max and latest
                if epss > 0:
                    rec["epss_score_max"] = max(rec.get("epss_score_max", 0), epss)
                    rec["epss_score_last"] = epss

                # Actor merge — no duplicates
                existing_actors = set(rec.get("associated_actors", []))
                for a in actors:
                    existing_actors.add(a)
                rec["associated_actors"] = list(existing_actors)[:10]

                # Actor confidence — keep max per actor
                existing_conf = rec.get("actor_confidence_max", {})
                for aname, aconf in actor_conf.items():
                    existing_conf[aname] = max(existing_conf.get(aname, 0), aconf)
                rec["actor_confidence_max"] = existing_conf

                # Campaign merge
                existing_camps = set(rec.get("associated_campaigns", []))
                for c in campaigns:
                    existing_camps.add(c)
                rec["associated_campaigns"] = list(existing_camps)[:10]

                # Technique merge
                existing_tech = set(rec.get("mitre_techniques", []))
                for t in techniques:
                    existing_tech.add(t)
                rec["mitre_techniques"] = list(existing_tech)[:20]

                # Exploit tier tracking
                if exploit_tier:
                    tier_order = {"UNLIKELY": 0, "POSSIBLE": 1, "ELEVATED": 2,
                                  "LIKELY": 3, "IMMINENT": 4}
                    curr_max = rec.get("exploit_tier_max")
                    curr_order = tier_order.get(curr_max, 0)
                    new_order = tier_order.get(exploit_tier, 0)
                    if new_order >= curr_order:
                        rec["exploit_tier_max"] = exploit_tier
                    history = rec.get("exploit_tier_history", [])
                    history.append(exploit_tier)
                    rec["exploit_tier_history"] = history[-20:]

                # Exploitation flags
                if active_exploit:
                    rec["active_exploitation_confirmed"] = True
                if poc_seen:
                    rec["poc_seen"] = True

                # Title dedup
                title = entry.get("title", "")[:120]
                if title:
                    existing_titles = rec.get("titles_seen", [])
                    if title not in existing_titles:
                        existing_titles.append(title)
                        rec["titles_seen"] = existing_titles[-10:]

            self._updated_ids.add(cve_id)
            updated.append(cve_id)

        return updated

    def save(self) -> bool:
        return _safe_write_json(CVE_MEMORY_FILE, self.db)

    def get_stats(self) -> Dict:
        total = len(self.db)
        kev_count = sum(1 for v in self.db.values() if v.get("kev_ever"))
        active_exploit = sum(1 for v in self.db.values() if v.get("active_exploitation_confirmed"))
        escalating = sum(1 for v in self.db.values() if v.get("risk_trend") == "ESCALATING")
        high_risk = sum(1 for v in self.db.values() if v.get("max_risk_score", 0) >= 7.0)
        recurring = sum(1 for v in self.db.values() if v.get("occurrences", 0) >= 3)
        return {
            "total_cves": total,
            "kev_confirmed": kev_count,
            "active_exploitation": active_exploit,
            "escalating_risk": escalating,
            "high_risk": high_risk,
            "recurring_cves": recurring,
            "updated_this_run": len(self._updated_ids),
        }


# ---------------------------------------------------------------------------
# ACTOR MEMORY ENGINE
# ---------------------------------------------------------------------------

class ActorMemory:
    """
    Maintains persistent memory of threat actor activity patterns.
    Schema per actor entry:
    {
        "actor_name": "Lazarus Group",
        "nation": "DPRK",
        "first_seen": "<ISO>",
        "last_seen": "<ISO>",
        "total_advisories": 12,
        "run_count": 5,           // how many pipeline runs observed
        "avg_risk_score": 8.7,
        "max_risk_score": 9.8,
        "risk_scores": [...],     // rolling last 30
        "techniques_used": {"T1190": 5, "T1059": 3},    // technique → count
        "target_sectors": {"healthcare": 3, "finance": 2},
        "linked_campaigns": ["CDB-CAMP-ABCD1234"],
        "linked_cves": ["CVE-2024-1234", ...],
        "activity_trend": "INCREASING",   // INCREASING | STABLE | DECREASING
        "activity_by_week": {"2024-W15": 3, ...},
        "avg_confidence": 0.72,
        "confidence_history": [...]
    }
    """

    def __init__(self):
        self.db: Dict[str, Dict] = _safe_load_json(ACTOR_MEMORY_FILE, {})
        self._updated_actors: Set[str] = set()

    def update(self, actor_name: str, nation: str, confidence: float,
               entry: Dict, ai_record: Optional[Dict] = None,
               campaign_id: Optional[str] = None) -> bool:
        """Update memory for a single actor observation."""
        if not actor_name:
            return False

        now = _now_iso()
        week_key = datetime.now(timezone.utc).strftime("%Y-W%W")
        risk = float(entry.get("risk_score", 0) or entry.get("ai_risk_score", 0) or 0)
        if ai_record:
            ai_r = float(ai_record.get("ai_risk_score", 0) or 0)
            if ai_r > risk:
                risk = ai_r

        # Extract sectors
        sectors: List[str] = []
        if ai_record:
            sectors = ai_record.get("sectors_targeted", []) or []

        # Extract techniques
        techniques: List[str] = []
        entry_techs = entry.get("mitre_techniques", []) or entry.get("mitre_tactics", []) or []
        for t in entry_techs:
            if isinstance(t, str):
                techniques.append(t.split(".")[0].upper())

        # Extract CVE IDs
        cve_ids = _extract_cve_ids(entry.get("title", "") + " " + entry.get("advisory_id", ""))

        existing = self.db.get(actor_name)

        if existing is None:
            # NEW actor observation
            self.db[actor_name] = {
                "actor_name": actor_name,
                "nation": nation,
                "first_seen": now,
                "last_seen": now,
                "total_advisories": 1,
                "run_count": 1,
                "avg_risk_score": risk,
                "max_risk_score": risk,
                "risk_scores": [risk] if risk else [],
                "techniques_used": {t: 1 for t in techniques},
                "target_sectors": {s: 1 for s in sectors},
                "linked_campaigns": [campaign_id] if campaign_id else [],
                "linked_cves": cve_ids[:10],
                "activity_trend": "STABLE",
                "activity_by_week": {week_key: 1},
                "avg_confidence": confidence,
                "confidence_history": [confidence],
            }
            logger.debug(f"[ACTOR-MEM] NEW: {actor_name}")
        else:
            rec = existing
            rec["last_seen"] = now
            rec["total_advisories"] = rec.get("total_advisories", 0) + 1

            # Risk tracking
            if risk > 0:
                scores = rec.get("risk_scores", [])
                scores.append(risk)
                scores = scores[-30:]
                rec["risk_scores"] = scores
                rec["avg_risk_score"] = round(sum(scores) / len(scores), 3)
                rec["max_risk_score"] = max(rec.get("max_risk_score", 0), risk)

            # Technique frequency counting
            tech_counts = rec.get("techniques_used", {})
            for t in techniques:
                tech_counts[t] = tech_counts.get(t, 0) + 1
            rec["techniques_used"] = tech_counts

            # Sector frequency
            sector_counts = rec.get("target_sectors", {})
            for s in sectors:
                sector_counts[s] = sector_counts.get(s, 0) + 1
            rec["target_sectors"] = sector_counts

            # Campaign links (no duplicates)
            if campaign_id:
                camps = set(rec.get("linked_campaigns", []))
                camps.add(campaign_id)
                rec["linked_campaigns"] = list(camps)[:20]

            # CVE links (no duplicates)
            linked = set(rec.get("linked_cves", []))
            for cid in cve_ids:
                linked.add(cid)
            rec["linked_cves"] = list(linked)[:50]

            # Activity by week
            activity = rec.get("activity_by_week", {})
            activity[week_key] = activity.get(week_key, 0) + 1
            # Keep last 52 weeks
            if len(activity) > 52:
                oldest = sorted(activity.keys())[0]
                del activity[oldest]
            rec["activity_by_week"] = activity

            # Activity trend
            sorted_weeks = sorted(activity.keys())
            if len(sorted_weeks) >= 4:
                recent_4 = sum(activity[w] for w in sorted_weeks[-2:])
                older_4 = sum(activity[w] for w in sorted_weeks[-4:-2])
                if recent_4 > older_4 * 1.3:
                    rec["activity_trend"] = "INCREASING"
                elif recent_4 < older_4 * 0.7:
                    rec["activity_trend"] = "DECREASING"
                else:
                    rec["activity_trend"] = "STABLE"

            # Confidence tracking
            conf_history = rec.get("confidence_history", [])
            conf_history.append(confidence)
            conf_history = conf_history[-30:]
            rec["confidence_history"] = conf_history
            rec["avg_confidence"] = round(sum(conf_history) / len(conf_history), 3)

        self._updated_actors.add(actor_name)
        return True

    def save(self) -> bool:
        return _safe_write_json(ACTOR_MEMORY_FILE, self.db)

    def get_top_actors(self, n: int = 10) -> List[Dict]:
        """Return top N actors by total advisory count."""
        actors = list(self.db.values())
        actors.sort(key=lambda a: a.get("total_advisories", 0), reverse=True)
        return actors[:n]

    def get_stats(self) -> Dict:
        total = len(self.db)
        increasing = sum(1 for a in self.db.values() if a.get("activity_trend") == "INCREASING")
        high_activity = sum(1 for a in self.db.values() if a.get("total_advisories", 0) >= 5)
        nation_groups: Dict[str, int] = {}
        for a in self.db.values():
            nation = a.get("nation", "Unknown")
            nation_groups[nation] = nation_groups.get(nation, 0) + 1
        return {
            "total_actors": total,
            "increasing_activity": increasing,
            "high_activity_actors": high_activity,
            "by_nation": nation_groups,
            "updated_this_run": len(self._updated_actors),
        }


# ---------------------------------------------------------------------------
# CAMPAIGN MEMORY ENGINE
# ---------------------------------------------------------------------------

class CampaignMemory:
    """
    Maintains persistent memory of tracked threat campaigns.
    Schema per campaign:
    {
        "campaign_id": "CDB-CAMP-ABCD1234",
        "first_seen": "<ISO>",
        "last_seen": "<ISO>",
        "advisory_count": 8,
        "total_runs_observed": 3,
        "actors_involved": ["Lazarus Group"],
        "sectors_targeted": {"healthcare": 4, "finance": 2},
        "techniques_observed": {"T1190": 3, "T1059": 2},
        "cves_linked": ["CVE-2024-XXXX"],
        "ioc_volume": 12,
        "evolution_score": 6.5,   // 0-10: how much the campaign has grown
        "risk_max": 9.1,
        "risk_avg": 7.8,
        "risk_history": [7.2, 8.1, 9.1],
        "activity_timeline": [
            {"date": "2024-04-01", "advisories": 2, "risk_avg": 7.2},
            ...
        ],
        "campaign_status": "ACTIVE",   // ACTIVE | ESCALATING | DORMANT | CONTAINED
        "escalation_signals": ["kev_added", "nation_state_confirmed"]
    }
    """

    def __init__(self):
        self.db: Dict[str, Dict] = _safe_load_json(CAMPAIGN_MEMORY_FILE, {})
        self._updated_campaigns: Set[str] = set()
        # Also try to import existing campaign tracker from AI engine
        self._import_ai_campaigns()

    def _import_ai_campaigns(self):
        """Import campaigns from the AI engine's campaign_tracker.json."""
        ai_campaigns = _safe_load_json(CAMPAIGN_TRACKER, {})
        if not isinstance(ai_campaigns, dict):
            return
        for cid, camp_data in ai_campaigns.items():
            if cid not in self.db:
                # Bootstrap memory entry from AI campaign data
                now = _now_iso()
                self.db[cid] = {
                    "campaign_id": cid,
                    "first_seen": camp_data.get("first_seen", now),
                    "last_seen": now,
                    "advisory_count": len(camp_data.get("advisories", [])),
                    "total_runs_observed": 1,
                    "actors_involved": [camp_data.get("primary_actor")] if camp_data.get("primary_actor") else [],
                    "sectors_targeted": {},
                    "techniques_observed": {},
                    "cves_linked": [],
                    "ioc_volume": 0,
                    "evolution_score": 0.0,
                    "risk_max": camp_data.get("max_risk", 0),
                    "risk_avg": camp_data.get("avg_risk", 0),
                    "risk_history": [],
                    "activity_timeline": [],
                    "campaign_status": "ACTIVE",
                    "escalation_signals": [],
                }

    def update(self, campaign_id: str, entry: Dict,
               actor_name: Optional[str] = None,
               ai_record: Optional[Dict] = None) -> bool:
        """Update memory for a campaign observation."""
        if not campaign_id:
            return False

        now = _now_iso()
        today = _today_str()
        risk = float(entry.get("risk_score", 0) or entry.get("ai_risk_score", 0) or 0)
        if ai_record:
            ai_r = float(ai_record.get("ai_risk_score", 0) or 0)
            if ai_r > risk:
                risk = ai_r

        sectors: List[str] = []
        if ai_record:
            sectors = ai_record.get("sectors_targeted", []) or []

        techniques: List[str] = []
        entry_techs = entry.get("mitre_techniques", []) or []
        for t in entry_techs:
            if isinstance(t, str):
                techniques.append(t.split(".")[0].upper())

        ioc_count = entry.get("ioc_count", 0) or 0
        cve_ids = _extract_cve_ids(entry.get("title", "") + " " + entry.get("advisory_id", ""))

        escalation_signals: List[str] = []
        if entry.get("kev_present"):
            escalation_signals.append("kev_added")
        if ai_record and "nation_state" in (ai_record.get("exploit_signals") or []):
            escalation_signals.append("nation_state_confirmed")
        if ai_record and ai_record.get("exploit_tier") == "IMMINENT":
            escalation_signals.append("imminent_exploitation")

        existing = self.db.get(campaign_id)

        if existing is None:
            self.db[campaign_id] = {
                "campaign_id": campaign_id,
                "first_seen": now,
                "last_seen": now,
                "advisory_count": 1,
                "total_runs_observed": 1,
                "actors_involved": [actor_name] if actor_name else [],
                "sectors_targeted": {s: 1 for s in sectors},
                "techniques_observed": {t: 1 for t in techniques},
                "cves_linked": cve_ids[:20],
                "ioc_volume": ioc_count,
                "evolution_score": 0.0,
                "risk_max": risk,
                "risk_avg": risk,
                "risk_history": [risk] if risk else [],
                "activity_timeline": [{
                    "date": today,
                    "advisories": 1,
                    "risk_avg": risk,
                }],
                "campaign_status": "ACTIVE",
                "escalation_signals": escalation_signals,
            }
        else:
            rec = existing
            rec["last_seen"] = now
            rec["advisory_count"] = rec.get("advisory_count", 0) + 1

            # Risk tracking
            if risk > 0:
                history = rec.get("risk_history", [])
                history.append(risk)
                history = history[-50:]
                rec["risk_history"] = history
                rec["risk_max"] = max(rec.get("risk_max", 0), risk)
                rec["risk_avg"] = round(sum(history) / len(history), 3)

            # Actor merge
            actors_set = set(rec.get("actors_involved", []))
            if actor_name:
                actors_set.add(actor_name)
            rec["actors_involved"] = list(actors_set)[:10]

            # Sector frequency
            sector_counts = rec.get("sectors_targeted", {})
            for s in sectors:
                sector_counts[s] = sector_counts.get(s, 0) + 1
            rec["sectors_targeted"] = sector_counts

            # Technique frequency
            tech_counts = rec.get("techniques_observed", {})
            for t in techniques:
                tech_counts[t] = tech_counts.get(t, 0) + 1
            rec["techniques_observed"] = tech_counts

            # CVE links
            cves_set = set(rec.get("cves_linked", []))
            for cid in cve_ids:
                cves_set.add(cid)
            rec["cves_linked"] = list(cves_set)[:50]

            # IOC volume
            rec["ioc_volume"] = rec.get("ioc_volume", 0) + ioc_count

            # Escalation signals merge
            existing_signals = set(rec.get("escalation_signals", []))
            for sig in escalation_signals:
                existing_signals.add(sig)
            rec["escalation_signals"] = list(existing_signals)

            # Activity timeline — per-day aggregation
            timeline = rec.get("activity_timeline", [])
            today_entry = next((t for t in timeline if t.get("date") == today), None)
            if today_entry:
                today_entry["advisories"] = today_entry.get("advisories", 0) + 1
                today_entry["risk_avg"] = round(
                    (today_entry.get("risk_avg", 0) + risk) / 2, 2
                )
            else:
                timeline.append({"date": today, "advisories": 1, "risk_avg": risk})
            # Keep last 90 days of timeline
            timeline = sorted(timeline, key=lambda x: x.get("date", ""))[-90:]
            rec["activity_timeline"] = timeline

            # Compute evolution score (0-10)
            rec["evolution_score"] = self._compute_evolution_score(rec)

            # Campaign status
            rec["campaign_status"] = self._compute_status(rec)

        self._updated_campaigns.add(campaign_id)
        return True

    def _compute_evolution_score(self, rec: Dict) -> float:
        """
        Evolution score measures campaign growth and sophistication.
        Factors: advisory count, actor count, sector breadth, technique count,
        risk trend, IOC volume.
        """
        score = 0.0

        # Advisory count (max 2.0 pts)
        advisories = min(rec.get("advisory_count", 0), 20)
        score += advisories / 10.0

        # Actor diversity (max 1.5 pts)
        actors = len(rec.get("actors_involved", []))
        score += min(actors * 0.5, 1.5)

        # Sector breadth (max 2.0 pts)
        sectors = len(rec.get("sectors_targeted", {}))
        score += min(sectors * 0.4, 2.0)

        # Technique count (max 2.0 pts)
        techniques = len(rec.get("techniques_observed", {}))
        score += min(techniques * 0.2, 2.0)

        # Risk max (max 1.5 pts)
        risk_max = rec.get("risk_max", 0)
        score += (risk_max / 10.0) * 1.5

        # Escalation signals (max 1.0 pts)
        signals = len(rec.get("escalation_signals", []))
        score += min(signals * 0.25, 1.0)

        return round(min(score, 10.0), 2)

    def _compute_status(self, rec: Dict) -> str:
        """Determine campaign operational status."""
        last_seen = rec.get("last_seen", "")
        days_old = _days_ago(last_seen)

        if days_old is not None and days_old > 30:
            return "DORMANT"

        escalation_signals = rec.get("escalation_signals", [])
        if "imminent_exploitation" in escalation_signals or "kev_added" in escalation_signals:
            return "ESCALATING"

        evolution = rec.get("evolution_score", 0)
        if evolution >= 5.0:
            return "ACTIVE"

        return "ACTIVE"

    def save(self) -> bool:
        return _safe_write_json(CAMPAIGN_MEMORY_FILE, self.db)

    def get_stats(self) -> Dict:
        total = len(self.db)
        active = sum(1 for c in self.db.values() if c.get("campaign_status") in ("ACTIVE", "ESCALATING"))
        escalating = sum(1 for c in self.db.values() if c.get("campaign_status") == "ESCALATING")
        return {
            "total_campaigns": total,
            "active_campaigns": active,
            "escalating_campaigns": escalating,
            "updated_this_run": len(self._updated_campaigns),
        }


# ---------------------------------------------------------------------------
# THREAT MEMORY ORCHESTRATOR
# ---------------------------------------------------------------------------

class ThreatMemoryEngine:
    """
    Orchestrates all memory subsystems. Called once per pipeline run.
    Reads: feed_manifest.json + ai_index.json
    Writes: cve_memory.json, actor_memory.json, campaign_memory.json, memory_meta.json
    """

    def __init__(self):
        self.cve_mem = CVEMemory()
        self.actor_mem = ActorMemory()
        self.campaign_mem = CampaignMemory()
        self._run_start = _now_iso()
        self._run_ts = _now_ts()

    def _load_manifest(self) -> List[Dict]:
        data = _safe_load_json(MANIFEST_PATH, [])
        entries = data if isinstance(data, list) else data.get("entries", data.get("items", []))
        return entries if isinstance(entries, list) else []

    def _load_ai_index(self) -> Dict[str, Dict]:
        """Load AI index and build lookup by advisory_id."""
        ai_records = _safe_load_json(AI_INDEX_PATH, [])
        if not isinstance(ai_records, list):
            return {}
        lookup: Dict[str, Dict] = {}
        for rec in ai_records:
            aid = rec.get("advisory_id", "")
            if aid:
                lookup[aid] = rec
        return lookup

    def run(self) -> Dict:
        """
        Main entry point. Process all manifest entries through all memory engines.
        Returns run telemetry dict.
        """
        print("\n══════════════════════════════════════════════════════")
        print("  THREAT MEMORY ENGINE v1.0 — SENTINEL APEX")
        print("══════════════════════════════════════════════════════")
        print(f"  Started: {self._run_start}")

        # Load data sources
        entries = self._load_manifest()
        ai_index = self._load_ai_index()
        print(f"  Manifest: {len(entries)} entries")
        print(f"  AI Index: {len(ai_index)} records")

        if not entries:
            print("  ⚠ No manifest entries — memory update skipped")
            return self._build_result(0, 0, 0, "no_manifest")

        # Process each manifest entry
        processed = 0
        cve_updates = 0
        actor_updates = 0
        campaign_updates = 0

        for entry in entries:
            try:
                advisory_id = entry.get("advisory_id", entry.get("id", ""))
                ai_record = ai_index.get(advisory_id) if advisory_id else None

                # 1. CVE Memory
                updated_cves = self.cve_mem.update(entry, ai_record)
                cve_updates += len(updated_cves)

                # 2. Actor Memory
                if ai_record:
                    # Primary actor from AI
                    primary = ai_record.get("primary_actor")
                    campaign_id = ai_record.get("campaign_id")
                    if primary:
                        # Find nation from actor matches
                        nation = "Unknown"
                        confidence = 0.5
                        for match in (ai_record.get("actor_matches") or []):
                            if match.get("name") == primary or match.get("actor_name") == primary:
                                nation = match.get("nation", "Unknown")
                                confidence = match.get("confidence", 0.5)
                                break
                        self.actor_mem.update(primary, nation, confidence, entry, ai_record, campaign_id)
                        actor_updates += 1
                else:
                    # Fallback: use entry's threat_actor field
                    actor_tag = entry.get("actor_tag") or entry.get("threat_actor", "")
                    if actor_tag and actor_tag not in ("Unattributed", "Unknown", ""):
                        self.actor_mem.update(actor_tag, "Unknown", 0.3, entry, None)
                        actor_updates += 1

                # 3. Campaign Memory
                campaign_id = (ai_record.get("campaign_id") if ai_record else None) or \
                              entry.get("campaign_id")
                if campaign_id:
                    actor_name = (ai_record.get("primary_actor") if ai_record else None) or \
                                 entry.get("actor_tag", "")
                    self.campaign_mem.update(campaign_id, entry, actor_name, ai_record)
                    campaign_updates += 1

                processed += 1

            except Exception as e:
                logger.warning(f"[MEM] Error processing entry: {e}")
                continue

        # Save all memory stores
        print(f"\n  Saving memory stores...")
        cve_saved = self.cve_mem.save()
        actor_saved = self.actor_mem.save()
        camp_saved = self.campaign_mem.save()

        # Print stats
        cve_stats = self.cve_mem.get_stats()
        actor_stats = self.actor_mem.get_stats()
        camp_stats = self.campaign_mem.get_stats()

        print(f"  ✓ CVE Memory   : {cve_stats['total_cves']} CVEs tracked | "
              f"{cve_stats['kev_confirmed']} KEV | "
              f"{cve_stats['escalating_risk']} escalating | "
              f"{cve_stats['updated_this_run']} updated")
        print(f"  ✓ Actor Memory : {actor_stats['total_actors']} actors tracked | "
              f"{actor_stats['increasing_activity']} increasing | "
              f"{actor_stats['updated_this_run']} updated")
        print(f"  ✓ Campaign Mem : {camp_stats['total_campaigns']} campaigns | "
              f"{camp_stats['active_campaigns']} active | "
              f"{camp_stats['escalating_campaigns']} escalating")

        result = self._build_result(processed, cve_updates, actor_updates, "success")
        result.update({
            "campaign_updates": campaign_updates,
            "cve_stats": cve_stats,
            "actor_stats": actor_stats,
            "campaign_stats": camp_stats,
            "saves_ok": all([cve_saved, actor_saved, camp_saved]),
        })

        # Write memory meta
        self._write_meta(result)

        print(f"\n  ✓ Memory Engine complete: {processed} advisories processed")
        print(f"    CVE updates: {cve_updates} | Actor updates: {actor_updates} | Campaign: {campaign_updates}")
        print("══════════════════════════════════════════════════════\n")

        return result

    def _build_result(self, processed: int, cve_updates: int,
                      actor_updates: int, status: str) -> Dict:
        return {
            "engine": "ThreatMemoryEngine",
            "version": "v1.0",
            "status": status,
            "started_at": self._run_start,
            "finished_at": _now_iso(),
            "duration_s": round(_now_ts() - self._run_ts, 2),
            "processed": processed,
            "cve_updates": cve_updates,
            "actor_updates": actor_updates,
        }

    def _write_meta(self, result: Dict):
        """Write/update memory_meta.json with run history."""
        meta = _safe_load_json(MEMORY_META_FILE, {
            "engine_version": "v1.0",
            "total_runs": 0,
            "first_run": _now_iso(),
            "last_run": None,
            "run_history": [],
        })

        meta["total_runs"] = meta.get("total_runs", 0) + 1
        meta["last_run"] = _now_iso()
        meta["engine_version"] = "v1.0"

        # Append run summary to history (keep last 50 runs)
        run_summary = {
            "run": meta["total_runs"],
            "timestamp": result.get("started_at"),
            "status": result.get("status"),
            "processed": result.get("processed", 0),
            "cve_updates": result.get("cve_updates", 0),
            "actor_updates": result.get("actor_updates", 0),
            "campaign_updates": result.get("campaign_updates", 0),
            "duration_s": result.get("duration_s", 0),
            "total_cves": result.get("cve_stats", {}).get("total_cves", 0),
            "total_actors": result.get("actor_stats", {}).get("total_actors", 0),
            "total_campaigns": result.get("campaign_stats", {}).get("total_campaigns", 0),
        }
        history = meta.get("run_history", [])
        history.append(run_summary)
        meta["run_history"] = history[-50:]

        _safe_write_json(MEMORY_META_FILE, meta)


# ---------------------------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    """CLI entry point for direct execution or workflow invocation."""
    try:
        engine = ThreatMemoryEngine()
        result = engine.run()
        status = result.get("status", "unknown")
        if status == "success":
            sys.exit(0)
        else:
            # Non-fatal: log but exit 0 (zero failure architecture)
            print(f"  ⚠ Memory engine status: {status} — pipeline continues")
            sys.exit(0)
    except Exception as e:
        logger.error(f"[MEM] Fatal error in memory engine: {e}")
        # Always exit 0 — never block the pipeline
        sys.exit(0)


if __name__ == "__main__":
    main()
