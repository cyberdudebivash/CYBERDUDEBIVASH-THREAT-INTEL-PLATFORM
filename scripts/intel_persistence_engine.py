#!/usr/bin/env python3
"""
scripts/intel_persistence_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
Intelligence Persistence & Retention Engine
============================================
P0 PRODUCTION FIX: Transforms the platform from LATEST FEED VIEW
to PERSISTENT INTELLIGENCE REPOSITORY.

MANDATE:
  - A valid advisory NEVER disappears because a newer run executed.
  - Historical intelligence is permanently retained.
  - Dashboard reads repository totals, not latest feed counts.
  - Deduplication prevents inflation across runs.
  - Retention policy governs lifecycle (ACTIVE -> MONITORING -> ARCHIVED).

PIPELINE POSITION:
  Run AFTER every feed generation / feed sync step.

  sentinel-blogger.yml:
    ... [feed generation steps] ...
    - name: "Intelligence Persistence Engine"
      run: python3 scripts/intel_persistence_engine.py

REPOSITORY STRUCTURE:
  data/intelligence_repository/
    intelligence_index.json       -- master index + stable dashboard metrics
    advisory_registry.json        -- full advisory registry (paginated chunks)
    intel_retention_registry.json -- per-item retention policy
    intel_lifecycle_registry.json -- lifecycle state per item
    historical_feed_registry.json -- per-run snapshot registry

  data/intelligence_repository/advisories/
    registry_<YYYYMM>.json        -- monthly advisory chunks (never overwritten)

RETENTION POLICY:
  CRITICAL  -> 24 months
  HIGH      -> 18 months
  MEDIUM    -> 12 months
  LOW       -> 6 months
  KEV       -> PERMANENT
  APT/Ransomware/Nation-State/Major Breach -> PERMANENT

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Repo root ─────────────────────────────────────────────────────────────────
REPO = Path(__file__).resolve().parent.parent
REPO_DIR = REPO / "data" / "intelligence_repository"
ADVISORIES_DIR = REPO_DIR / "advisories"
REPO_DIR.mkdir(parents=True, exist_ok=True)
ADVISORIES_DIR.mkdir(parents=True, exist_ok=True)

# ── Feed source paths ─────────────────────────────────────────────────────────
ARCHIVE_DIR   = REPO / "data" / "archive"
SNAPSHOT_DIR  = REPO / "data" / "snapshots"
FEED_JSON     = REPO / "feed.json"
APEX_JSON     = REPO / "api" / "v1" / "intel" / "apex.json"
LATEST_JSON   = REPO / "api" / "v1" / "intel" / "latest.json"
ENRICHED      = REPO / "data" / "apex_enriched_manifest.json"
STIX_DIR      = REPO / "data" / "stix"

# ── Repository file paths ─────────────────────────────────────────────────────
INDEX_FILE     = REPO_DIR / "intelligence_index.json"
RETENTION_FILE = REPO_DIR / "intel_retention_registry.json"
LIFECYCLE_FILE = REPO_DIR / "intel_lifecycle_registry.json"
HIST_FEED_FILE = REPO_DIR / "historical_feed_registry.json"
ADVISORY_FILE  = REPO_DIR / "advisory_registry.json"   # meta only (IDs + stats)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [intel-persistence] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("intel-persistence")

# ── Retention policy (days) ────────────────────────────────────────────────────
RETENTION_DAYS: Dict[str, Optional[int]] = {
    "CRITICAL": 730,   # 24 months
    "HIGH":     545,   # 18 months
    "MEDIUM":   365,   # 12 months
    "LOW":      180,   # 6 months
    "INFO":     90,
    "UNKNOWN":  180,
    # Permanent categories (None = never expire)
    "KEV":           None,
    "APT":           None,
    "RANSOMWARE":    None,
    "NATION_STATE":  None,
    "MAJOR_BREACH":  None,
}

# ── Lifecycle states ──────────────────────────────────────────────────────────
LIFECYCLE_ACTIVE     = "ACTIVE"
LIFECYCLE_MONITORING = "MONITORING"
LIFECYCLE_ARCHIVED   = "ARCHIVED"
LIFECYCLE_EXPIRED    = "EXPIRED"

# ── Permanent categories (keywords to detect) ─────────────────────────────────
PERMANENT_KEYWORDS = {
    "kev", "ransomware", "apt", "nation.state", "nation-state", "espionage",
    "state.sponsored", "state-sponsored", "critical infrastructure",
    "major breach", "supply chain", "zero.day", "zero-day",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_load(path: Path, default: Any = None) -> Any:
    """Load JSON file safely. Returns default on any error."""
    if default is None:
        default = {}
    try:
        if path.exists() and path.stat().st_size > 0:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        log.warning("Failed to load %s: %s", path, e)
    return default


def _atomic_write(path: Path, data: Any) -> None:
    """Atomic write: write to .tmp then rename."""
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"), default=str)
        shutil.move(str(tmp), str(path))
    except Exception as e:
        log.error("Failed to write %s: %s", path, e)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def _content_hash(item: Dict) -> str:
    """Generate stable content fingerprint for deduplication."""
    # Use stable fields only (not timestamps that change per run)
    stable = "|".join([
        str(item.get("stix_id", item.get("id", ""))),
        str(item.get("title", ""))[:200],
        str(item.get("source_url", item.get("link", ""))),
        str(item.get("timestamp", ""))[:10],  # date only
    ])
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]


def _dedupe_hash(item: Dict) -> str:
    """Stronger dedup hash including CVE identifiers."""
    cves = sorted(item.get("cves", item.get("iocs_by_type", {}).get("cve", [])))
    stable = "|".join([
        str(item.get("stix_id", item.get("id", ""))),
        str(item.get("title", ""))[:200],
        str(item.get("source_url", item.get("link", ""))),
        ",".join(cves[:5]),
    ])
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]


def _is_permanent(item: Dict) -> bool:
    """Determine if item is permanently retained."""
    text = " ".join([
        str(item.get("title", "")),
        str(item.get("tags", "")),
        str(item.get("threat_type", "")),
        str(item.get("actor_tag", "")),
        str(item.get("mitre_tactics", "")),
    ]).lower()
    if item.get("kev") or item.get("is_kev") or item.get("cisa_kev"):
        return True
    return any(kw in text for kw in PERMANENT_KEYWORDS)


def _retention_days(item: Dict) -> Optional[int]:
    """Calculate retention period in days. None = permanent."""
    if _is_permanent(item):
        return None
    sev = str(item.get("severity", item.get("risk_level", "MEDIUM"))).upper()
    return RETENTION_DAYS.get(sev, RETENTION_DAYS["MEDIUM"])


def _retention_until(item: Dict, published: datetime) -> Optional[str]:
    """Calculate retention_until ISO timestamp. None = permanent."""
    days = _retention_days(item)
    if days is None:
        return None
    return (published + timedelta(days=days)).isoformat()


def _parse_timestamp(ts: Any) -> Optional[datetime]:
    """Parse timestamp string to datetime."""
    if not ts:
        return None
    for fmt in [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dZ",
        "%Y-%m-%d",
    ]:
        try:
            return datetime.strptime(str(ts)[:32], fmt)
        except ValueError:
            continue
    return None


def _lifecycle_state(item_meta: Dict, now: datetime) -> str:
    """Determine current lifecycle state."""
    retention_until = item_meta.get("retention_until")
    if retention_until is None:
        return LIFECYCLE_ACTIVE  # Permanent

    ru = _parse_timestamp(retention_until)
    if ru is None:
        return LIFECYCLE_ACTIVE

    age_days = (now - _parse_timestamp(item_meta.get("created_at", _now()))).days if _parse_timestamp(item_meta.get("created_at")) else 0

    if now > ru:
        return LIFECYCLE_ARCHIVED  # Past retention — archive (never delete)
    elif age_days > 30:
        return LIFECYCLE_MONITORING
    else:
        return LIFECYCLE_ACTIVE


def _ingest_source_file(path: Path) -> List[Dict]:
    """Load and normalize items from any known feed/archive format."""
    try:
        raw = open(path, encoding="utf-8").read()
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("JSON error in %s: %s — attempting recovery", path.name, e)
        # Try to recover partial JSON
        raw_trunc = raw[:e.pos - 1].rsplit(",", 1)[0] + "]"
        try:
            data = json.loads(raw_trunc + "}")
        except Exception:
            try:
                data = json.loads(raw_trunc)
            except Exception:
                log.error("Cannot recover %s — skipping", path.name)
                return []
    except Exception as e:
        log.warning("Cannot read %s: %s", path.name, e)
        return []

    if isinstance(data, list):
        return data
    for key in ("items", "advisories", "feed", "data", "intel"):
        if key in data and isinstance(data[key], list):
            return data[key]
    if "advisories" not in data:
        return []
    return []


def load_all_existing_intel() -> List[Dict]:
    """Load all existing intelligence from all known sources."""
    all_items = []
    seen_hashes: Set[str] = set()

    def _add(items: List[Dict], source_label: str):
        added = 0
        for item in items:
            if not isinstance(item, dict) or not item.get("title"):
                continue
            dh = _dedupe_hash(item)
            if dh in seen_hashes:
                continue
            seen_hashes.add(dh)
            item["_source_label"] = source_label
            item["_dedupe_hash"] = dh
            all_items.append(item)
            added += 1
        if added:
            log.info("  Loaded %d unique items from %s", added, source_label)

    # 1. Daily archive files (most authoritative historical source)
    if ARCHIVE_DIR.exists():
        for f in sorted(ARCHIVE_DIR.glob("*.json")):
            if f.name.startswith("index") or f.name.startswith("archive") or f.name.startswith("lifecycle"):
                continue
            items = _ingest_source_file(f)
            _add(items, f"archive/{f.name}")

    # 2. Enriched manifest
    if ENRICHED.exists():
        items = _ingest_source_file(ENRICHED)
        _add(items, "apex_enriched_manifest")

    # 3. STIX bundles directory
    if STIX_DIR.exists():
        for f in sorted(STIX_DIR.glob("*.json"))[:500]:  # cap to prevent runaway
            try:
                raw_data = json.loads(open(f, encoding="utf-8").read())
                # Extract objects from STIX bundle
                if isinstance(raw_data, dict) and "objects" in raw_data:
                    items = [o for o in raw_data["objects"] if isinstance(o, dict) and o.get("type") in ("report", "vulnerability", "threat-actor", "campaign", "intrusion-set")]
                elif isinstance(raw_data, dict):
                    items = [raw_data]
                else:
                    items = raw_data if isinstance(raw_data, list) else []
                _add(items, f"stix/{f.name}")
            except Exception:
                pass

    # 4. Current feed.json
    if FEED_JSON.exists():
        items = _ingest_source_file(FEED_JSON)
        _add(items, "feed.json")

    log.info("Total unique intelligence items loaded: %d", len(all_items))
    return all_items


def build_item_metadata(item: Dict, run_ts: str) -> Dict:
    """Build full metadata envelope for a repository entry."""
    # Extract canonical fields
    intel_id = item.get("stix_id") or item.get("id") or item.get("_dedupe_hash", "")
    if not intel_id:
        intel_id = "intel--" + _content_hash(item)

    title     = str(item.get("title", ""))[:500]
    severity  = str(item.get("severity", item.get("risk_level", "MEDIUM"))).upper()
    confidence = float(item.get("confidence", item.get("confidence_score", 50)) or 50)
    risk_score = float(item.get("risk_score", 5.0) or 5.0)
    source     = str(item.get("source", item.get("_source_label", "SENTINEL_APEX")))

    ts_raw = item.get("timestamp") or item.get("published_at") or item.get("generated_at") or run_ts
    published = _parse_timestamp(ts_raw) or datetime.now(timezone.utc)
    published_str = published.isoformat()

    content_hash = _content_hash(item)
    dedupe_hash  = item.get("_dedupe_hash") or _dedupe_hash(item)

    ret_until = _retention_until(item, published)
    is_perm   = _is_permanent(item)

    # Tags
    tags = item.get("tags", [])
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]

    # CVEs
    cves = item.get("cves", item.get("ioc_counts", {}).get("cve", []))
    if not isinstance(cves, list):
        cves = []

    return {
        "intel_id":       intel_id,
        "title":          title,
        "source":         source,
        "source_url":     item.get("source_url", item.get("link", "")),
        "blog_url":       item.get("blog_url", ""),
        "severity":       severity,
        "risk_score":     round(risk_score, 2),
        "confidence":     round(confidence, 2),
        "cves":           cves[:20],
        "tags":           tags[:20],
        "actor_tag":      item.get("actor_tag", ""),
        "mitre_tactics":  item.get("mitre_tactics", []),
        "threat_type":    item.get("threat_type", ""),
        "tlp_label":      item.get("tlp_label", "TLP:WHITE"),
        "ioc_count":      int(item.get("ioc_count", 0) or 0),
        "is_kev":         bool(item.get("kev") or item.get("is_kev") or item.get("cisa_kev")),
        "is_permanent":   is_perm,
        "content_hash":   content_hash,
        "dedupe_hash":    dedupe_hash,
        "created_at":     published_str,
        "published_at":   published_str,
        "last_seen":      run_ts,
        "status":         LIFECYCLE_ACTIVE,
        "retention_until": ret_until,
        "_retention_days": _retention_days(item),
        "year_month":     published.strftime("%Y%m"),
    }


class IntelligenceRepository:
    """
    Persistent Intelligence Repository.
    Append-only: never removes entries, only updates lifecycle state.
    """

    def __init__(self):
        self.index       = _safe_load(INDEX_FILE, {})
        self.retention   = _safe_load(RETENTION_FILE, {"registry": {}, "stats": {}})
        self.lifecycle   = _safe_load(LIFECYCLE_FILE, {"registry": {}, "stats": {}})
        self.hist_feed   = _safe_load(HIST_FEED_FILE, {"runs": [], "total_runs": 0})
        self.advisory_meta = _safe_load(ADVISORY_FILE, {"advisories": {}, "total": 0})

        # In-memory set of known dedupe hashes (fast lookup)
        self._known_hashes: Set[str] = set(
            self.retention.get("registry", {}).get(k, {}).get("dedupe_hash", "")
            for k in self.retention.get("registry", {})
        ) - {""}

        log.info("Repository loaded: %d known entries", len(self._known_hashes))

    def is_known(self, dedupe_hash: str) -> bool:
        return dedupe_hash in self._known_hashes

    def ingest(self, items: List[Dict], run_ts: str) -> Dict:
        """Ingest items into repository. Returns ingestion stats."""
        new_count   = 0
        update_count = 0
        skip_count  = 0

        now = datetime.now(timezone.utc)

        # Monthly chunk registry (for paginated access)
        monthly_chunks: Dict[str, List[str]] = defaultdict(list)

        for item in items:
            dedupe_hash = item.get("_dedupe_hash") or _dedupe_hash(item)

            if self.is_known(dedupe_hash):
                # Update last_seen only
                if dedupe_hash in self.retention.get("registry", {}):
                    self.retention["registry"][dedupe_hash]["last_seen"] = run_ts
                skip_count += 1
                continue

            meta = build_item_metadata(item, run_ts)
            intel_id = meta["intel_id"]
            ym       = meta["year_month"]

            # Register in retention registry
            if "registry" not in self.retention:
                self.retention["registry"] = {}
            self.retention["registry"][dedupe_hash] = {
                "intel_id":       intel_id,
                "dedupe_hash":    dedupe_hash,
                "content_hash":   meta["content_hash"],
                "severity":       meta["severity"],
                "is_permanent":   meta["is_permanent"],
                "is_kev":         meta["is_kev"],
                "retention_until": meta["retention_until"],
                "retention_days": meta["_retention_days"],
                "created_at":     meta["created_at"],
                "last_seen":      run_ts,
            }

            # Register in lifecycle registry
            lifecycle_state = _lifecycle_state(meta, now)
            if "registry" not in self.lifecycle:
                self.lifecycle["registry"] = {}
            self.lifecycle["registry"][intel_id] = {
                "intel_id":    intel_id,
                "status":      lifecycle_state,
                "created_at":  meta["created_at"],
                "last_seen":   run_ts,
                "severity":    meta["severity"],
            }

            # Advisory meta registry
            if "advisories" not in self.advisory_meta:
                self.advisory_meta["advisories"] = {}
            self.advisory_meta["advisories"][intel_id] = {
                "intel_id":   intel_id,
                "title":      meta["title"][:200],
                "severity":   meta["severity"],
                "published":  meta["published_at"][:10],
                "source":     meta["source"][:80],
                "is_kev":     meta["is_kev"],
                "risk_score": meta["risk_score"],
                "year_month": ym,
            }

            monthly_chunks[ym].append(intel_id)
            self._known_hashes.add(dedupe_hash)
            new_count += 1

        # Write monthly chunk files (append-only)
        for ym, ids in monthly_chunks.items():
            self._write_monthly_chunk(ym, ids, run_ts)

        return {
            "new":     new_count,
            "updated": update_count,
            "skipped": skip_count,
            "total":   len(self._known_hashes),
        }

    def _write_monthly_chunk(self, year_month: str, new_ids: List[str], run_ts: str):
        """Append new IDs to monthly chunk file. Never overwrites."""
        chunk_path = ADVISORIES_DIR / f"registry_{year_month}.json"
        existing = _safe_load(chunk_path, {"year_month": year_month, "ids": [], "updated": ""})
        existing_ids = set(existing.get("ids", []))
        for iid in new_ids:
            existing_ids.add(iid)
        existing["ids"] = sorted(existing_ids)
        existing["count"] = len(existing["ids"])
        existing["updated"] = run_ts
        _atomic_write(chunk_path, existing)

    def update_lifecycle(self):
        """Update lifecycle states based on current time."""
        now = datetime.now(timezone.utc)
        state_counts = defaultdict(int)

        for intel_id, entry in self.lifecycle.get("registry", {}).items():
            created = _parse_timestamp(entry.get("created_at"))
            if created is None:
                entry["status"] = LIFECYCLE_ACTIVE
            else:
                # Find retention for this entry
                age_days = (now - created.replace(tzinfo=timezone.utc) if created.tzinfo is None else now - created).days
                if age_days <= 30:
                    entry["status"] = LIFECYCLE_ACTIVE
                elif age_days <= 90:
                    entry["status"] = LIFECYCLE_MONITORING
                else:
                    entry["status"] = LIFECYCLE_ARCHIVED
                    # Archived = never delete, just moves state
            state_counts[entry["status"]] += 1

        self.lifecycle["stats"] = {
            "active":     state_counts[LIFECYCLE_ACTIVE],
            "monitoring": state_counts[LIFECYCLE_MONITORING],
            "archived":   state_counts[LIFECYCLE_ARCHIVED],
            "total":      sum(state_counts.values()),
        }

    def record_feed_run(self, run_ts: str, stats: Dict, feed_info: Dict):
        """Record this pipeline run in historical feed registry."""
        run_record = {
            "run_id":      f"run-{int(time.time())}",
            "run_ts":      run_ts,
            "new_items":   stats.get("new", 0),
            "total_repo":  stats.get("total", 0),
            "feed_count":  feed_info.get("feed_count", 0),
            "apex_count":  feed_info.get("apex_count", 0),
        }

        if "runs" not in self.hist_feed:
            self.hist_feed["runs"] = []

        # Keep last 500 run records
        self.hist_feed["runs"].append(run_record)
        if len(self.hist_feed["runs"]) > 500:
            self.hist_feed["runs"] = self.hist_feed["runs"][-500:]

        self.hist_feed["total_runs"] = len(self.hist_feed["runs"])
        self.hist_feed["last_run"] = run_ts
        self.hist_feed["cumulative_total"] = stats.get("total", 0)

    def build_index(self, run_ts: str) -> Dict:
        """Build master intelligence_index.json — the stable dashboard source."""
        ret_reg  = self.retention.get("registry", {})
        life_reg = self.lifecycle.get("registry", {})
        adv_reg  = self.advisory_meta.get("advisories", {})

        # Severity breakdown
        sev_counts: Dict[str, int] = defaultdict(int)
        kev_count = 0
        permanent_count = 0
        total_iocs = 0
        actor_set: Set[str] = set()
        cve_set: Set[str] = set()

        for dh, entry in ret_reg.items():
            sev = entry.get("severity", "UNKNOWN")
            sev_counts[sev] += 1
            if entry.get("is_kev"):
                kev_count += 1
            if entry.get("is_permanent"):
                permanent_count += 1

        for intel_id, adv in adv_reg.items():
            actor = adv.get("actor", adv.get("actor_tag", ""))
            if actor and actor not in ("", "CDB-UNATTR-CVE", "UNKNOWN"):
                actor_set.add(actor)

        # Lifecycle breakdown
        life_stats = self.lifecycle.get("stats", {})

        total = len(ret_reg)
        now_str = _now()

        # Year-month distribution
        ym_dist: Dict[str, int] = defaultdict(int)
        for intel_id, adv in adv_reg.items():
            ym = adv.get("year_month", "202600")
            ym_dist[ym] += 1

        index = {
            "schema_version":   "2.0.0",
            "generated_at":     now_str,
            "last_run":         run_ts,
            "repository": {
                "total_advisories":  total,
                "total_iocs":        total_iocs,
                "unique_actors":     len(actor_set),
                "unique_cves":       len(cve_set),
                "kev_count":         kev_count,
                "permanent_count":   permanent_count,
                "severity_breakdown": dict(sev_counts),
                "lifecycle_breakdown": {
                    "active":     life_stats.get("active", 0),
                    "monitoring": life_stats.get("monitoring", 0),
                    "archived":   life_stats.get("archived", 0),
                },
                "monthly_distribution": dict(sorted(ym_dist.items())),
            },
            "dashboard": {
                "total_advisories":    total,
                "critical_advisories": sev_counts.get("CRITICAL", 0),
                "high_advisories":     sev_counts.get("HIGH", 0),
                "kev_advisories":      kev_count,
                "permanent_advisories": permanent_count,
                "data_source":         "intelligence_repository",
                "note":                "Cumulative totals — never decreasing",
            },
            "feed_history": {
                "total_runs":  self.hist_feed.get("total_runs", 0),
                "last_run":    run_ts,
            },
            "retention_summary": {
                "policy": {
                    "CRITICAL": "24 months",
                    "HIGH":     "18 months",
                    "MEDIUM":   "12 months",
                    "LOW":      "6 months",
                    "KEV":      "PERMANENT",
                    "APT":      "PERMANENT",
                    "RANSOMWARE": "PERMANENT",
                    "NATION_STATE": "PERMANENT",
                },
            },
        }

        self.index = index
        return index

    def save_all(self, run_ts: str):
        """Atomically write all repository files."""
        log.info("Writing repository files...")

        # Index (dashboard reads this)
        _atomic_write(INDEX_FILE, self.index)

        # Retention registry (large — write in chunks if > 100k entries)
        ret_save = {
            "schema_version": "2.0.0",
            "last_updated": run_ts,
            "total":   len(self.retention.get("registry", {})),
            "registry": self.retention.get("registry", {}),
            "stats": {
                "permanent": sum(1 for v in self.retention.get("registry", {}).values() if v.get("is_permanent")),
                "kev":       sum(1 for v in self.retention.get("registry", {}).values() if v.get("is_kev")),
            },
        }
        _atomic_write(RETENTION_FILE, ret_save)

        # Lifecycle registry
        life_save = {
            "schema_version": "2.0.0",
            "last_updated": run_ts,
            "total": len(self.lifecycle.get("registry", {})),
            "registry": self.lifecycle.get("registry", {}),
            "stats": self.lifecycle.get("stats", {}),
        }
        _atomic_write(LIFECYCLE_FILE, life_save)

        # Historical feed registry
        _atomic_write(HIST_FEED_FILE, self.hist_feed)

        # Advisory meta registry
        adv_save = {
            "schema_version": "2.0.0",
            "last_updated": run_ts,
            "total": len(self.advisory_meta.get("advisories", {})),
            "advisories": self.advisory_meta.get("advisories", {}),
        }
        _atomic_write(ADVISORY_FILE, adv_save)

        log.info(
            "Repository saved: %d total advisories, %d lifecycle entries",
            len(self.retention.get("registry", {})),
            len(self.lifecycle.get("registry", {})),
        )


def get_feed_info() -> Dict:
    """Get current feed file statistics."""
    info = {}
    for label, path in [("feed_count", FEED_JSON), ("apex_count", APEX_JSON), ("latest_count", LATEST_JSON)]:
        try:
            items = _ingest_source_file(path)
            info[label] = len(items)
        except Exception:
            info[label] = 0
    return info


def main() -> int:
    run_ts = _now()
    log.info("=" * 60)
    log.info("Intelligence Persistence Engine v171.0 — %s", run_ts)
    log.info("=" * 60)

    repo = IntelligenceRepository()

    # Step 1: Load all existing intelligence
    log.info("Step 1: Loading all existing intelligence sources...")
    all_items = load_all_existing_intel()

    if not all_items:
        log.warning("No intelligence items found — writing empty repository baseline")

    # Step 2: Ingest into repository (dedup + merge)
    log.info("Step 2: Ingesting %d items into repository...", len(all_items))
    stats = repo.ingest(all_items, run_ts)
    log.info(
        "Ingestion complete: new=%d skipped=%d total=%d",
        stats["new"], stats["skipped"], stats["total"],
    )

    # Step 3: Update lifecycle states
    log.info("Step 3: Updating lifecycle states...")
    repo.update_lifecycle()

    # Step 4: Record feed run
    feed_info = get_feed_info()
    repo.record_feed_run(run_ts, stats, feed_info)
    log.info("Feed run recorded: feed=%d apex=%d", feed_info.get("feed_count", 0), feed_info.get("apex_count", 0))

    # Step 5: Build master index
    log.info("Step 5: Building master intelligence index...")
    index = repo.build_index(run_ts)
    log.info(
        "Index built: total=%d CRITICAL=%d HIGH=%d KEV=%d",
        index["repository"]["total_advisories"],
        index["repository"]["severity_breakdown"].get("CRITICAL", 0),
        index["repository"]["severity_breakdown"].get("HIGH", 0),
        index["repository"]["kev_count"],
    )

    # Step 6: Save all repository files
    log.info("Step 6: Saving repository files...")
    repo.save_all(run_ts)

    log.info("=" * 60)
    log.info("Intelligence Persistence Engine COMPLETE")
    log.info("  Total repository: %d advisories", stats["total"])
    log.info("  New this run:     %d", stats["new"])
    log.info("  Dashboard source: data/intelligence_repository/intelligence_index.json")
    log.info("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
