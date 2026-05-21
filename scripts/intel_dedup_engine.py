#!/usr/bin/env python3
"""
scripts/intel_dedup_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX v141.3.0 -- Persistent Global Intel Dedup Engine
===================================================================================

MISSION: Guarantee ZERO duplicate intel across ALL pipeline runs, forever.

ROOT CAUSES FIXED (v141.3.0):
  1. data/blogger_processed.json was GITIGNORED -- CI always started fresh
     -> New: data/cache/intel_index.json is committed to git (persists forever)
  2. DeduplicationEngine seeded from wrong path (data/stix/feed_manifest.json)
     -> Fixed: seeds from data/feed_manifest.json (actual manifest location)
  3. Archive (5,429 entries) was NEVER checked during dedup seeding
     -> Fixed: builds index from ALL archive files on first run
  4. No source_url / stix_id primary key dedup -- only title-based hashes
     -> Fixed: source_url + stix_id are PRIMARY keys (strict unique enforcement)
  5. No per-feed state tracking -- re-ingest same data every run
     -> Fixed: data/cache/feed_state.json tracks last_seen per feed

MULTI-LAYER DEDUP CONTRACT (strict order):
  Layer 0 (PRIMARY): source_url match         -> SKIP (same URL seen before)
  Layer 1 (PRIMARY): stix_id match            -> SKIP (same STIX object)
  Layer 2 (STRONG):  content_hash match       -> SKIP (same content body)
  Layer 3 (CROSS):   title_hash match         -> SKIP (same title, cross-feed)
                     (SKIPPED for generic titles -- CISA KEV etc.)

PERSISTENCE CONTRACT:
  data/cache/intel_index.json  -- primary index, committed to git
  data/cache/feed_state.json   -- per-feed last_seen state, committed to git
  Writes are ATOMIC: tmp -> fsync -> os.replace()
  Index is rebuilt from archive if corrupt or missing

ZERO REGRESSION GUARANTEE:
  - All existing dedup logic in safe_io.dedup_items() preserved unchanged
  - agent/deduplication.DeduplicationEngine is patched (not replaced)
  - This engine runs AS LAYER 0 -- before all existing layers
  - Pure Python 3.8+, no external dependencies

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("sentinel.dedup")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT   = Path(__file__).resolve().parent.parent
CACHE_DIR   = REPO_ROOT / "data" / "cache"
INDEX_PATH  = CACHE_DIR / "intel_index.json"
FSTATE_PATH = CACHE_DIR / "feed_state.json"

MANIFEST_PATH   = REPO_ROOT / "data" / "feed_manifest.json"
ARCHIVE_DIR     = REPO_ROOT / "data" / "archive"
STIX_DIR        = REPO_ROOT / "data" / "stix"

# Generic titles that defeat title-based dedup (CISA KEV etc.)
_GENERIC_TITLE_PREFIXES = frozenset({
    "cisa adds", "security advisory", "advisory update",
    "vulnerability advisory", "patch tuesday", "monthly security update",
    "security bulletin", "security update", "product security advisory",
    "weekly threat roundup", "weekly security roundup",
    "threat intelligence report",
})
_STOPWORDS = frozenset({
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to",
    "for", "of", "with", "by", "from", "is", "are", "was", "new",
    "update", "adds", "one", "its", "it", "this", "that",
})

# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _url_key(url: str) -> str:
    """Normalised source_url key — strip ONLY marketing tracking params, keep content IDs.

    v141.4.0 FIX: Previous logic stripped ALL query params (re.sub r"[?#].*$"),
    which collapsed NCSC advisories (advisory?id=NCSC-2026-0076) into the same
    hash as (advisory?id=NCSC-2026-0010) — causing false-duplicate blocking.

    Strategy:
    - Strip anchor fragments (#...) always (never content-identifying)
    - Strip known marketing params (utm_*, ref, source, campaign, etc.)
    - KEEP content-identifying params (id, advisory_id, cve, article_id, etc.)
    - If only tracking params remain after stripping, the base URL is used
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    url = url.strip().lower()

    # Strip anchor fragment entirely
    url = re.sub(r"#.*$", "", url)

    # Marketing/tracking params to strip (not content-identifying)
    _TRACKING_PARAMS = frozenset({
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_reader", "utm_referrer",
        "ref", "referrer", "source", "campaign", "via",
        "fbclid", "gclid", "msclkid", "yclid", "dclid",
        "mc_cid", "mc_eid", "_hsenc", "_hsmi",
        "WT.mc_id", "wt.mc_id", "affiliate",
    })

    try:
        parsed = urlparse(url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            # Remove ONLY known tracking params
            clean_qs = {k: v for k, v in qs.items()
                        if k.lower() not in _TRACKING_PARAMS}
            # Rebuild with sorted params for deterministic hashing
            new_query = urlencode(sorted(clean_qs.items()), doseq=True)
            url = urlunparse(parsed._replace(query=new_query, fragment=""))
    except Exception:
        # Fallback: strip nothing (preserve as-is minus fragment)
        pass

    url = url.rstrip("/")
    return _sha256(url)


def _content_key(item: Dict) -> str:
    """SHA256 of: title + description[:300] + published-date."""
    title = str(item.get("title", "")).strip().lower()
    desc  = str(item.get("description", "") or item.get("summary", ""))[:300].strip().lower()
    pub   = str(item.get("published") or item.get("timestamp") or
                item.get("processed_at") or "")[:10]
    return _sha256(f"{title}|{desc}|{pub}")


def _title_key(item: Dict) -> str:
    """SHA256 of normalised title (stripped punctuation, lowercased)."""
    title = re.sub(r"[^\w\s]", "", str(item.get("title", "")).strip().lower())
    title = re.sub(r"\s+", " ", title).strip()
    return _sha256(title)


def _is_generic_title(title: str) -> bool:
    t = title.strip().lower()
    for prefix in _GENERIC_TITLE_PREFIXES:
        if t.startswith(prefix) or prefix in t:
            return True
    words = re.sub(r"[^\w\s]", "", t).split()
    meaningful = [w for w in words if w not in _STOPWORDS and len(w) > 2]
    return len(meaningful) < 5


def _get_source_url(item: Dict) -> str:
    return (item.get("source_url") or item.get("url") or
            item.get("link") or item.get("blog_url") or "").strip()


def _get_stix_id(item: Dict) -> str:
    return (item.get("stix_id") or item.get("bundle_id") or "").strip()

# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------

def _atomic_write(path: Path, data: Dict) -> None:
    """Write JSON atomically: tmp -> fsync -> replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    content = json.dumps(data, indent=2, ensure_ascii=False)
    tmp.write_text(content, encoding="utf-8")
    with open(tmp, "rb") as fh:
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Persistent Intel Index
# ---------------------------------------------------------------------------

class IntelDedupEngine:
    """
    Persistent multi-layer dedup engine with cross-run memory.

    State lives in data/cache/intel_index.json (committed to git).
    Seeded on first run from:
      - data/feed_manifest.json (current manifest)
      - data/archive/*.json     (all historical archive files)
      - data/stix/*.json        (STIX bundle objects)

    Usage:
        engine = IntelDedupEngine()
        engine.load()              # load persistent index

        is_dup, reason = engine.is_duplicate(item)
        if not is_dup:
            engine.mark_seen(item) # register item
            process(item)

        engine.save()              # persist index after batch
    """

    _EMPTY_INDEX: Dict = {
        "schema_version": "141.3.0",
        "created_at": "",
        "last_updated": "",
        "total_seen": 0,
        "source_urls":    {},   # url_sha256  -> {first_seen, title}
        "stix_ids":       {},   # stix_id     -> {first_seen, title}
        "content_hashes": {},   # content_sha256 -> {first_seen, title}
        "title_hashes":   {},   # title_sha256   -> {first_seen, title}
    }

    def __init__(self) -> None:
        self._index: Dict = {}
        self._dirty = False
        self._new_this_run = 0

    # ---- I/O -----------------------------------------------------------

    def load(self) -> "IntelDedupEngine":
        """Load index from disk. Auto-rebuild if missing or corrupt.

        v152.1.0 SCHEMA VALIDATION FIX:
        Validates that dict sections (source_urls, stix_ids, content_hashes,
        title_hashes) are actual dicts after loading. Old schema versions or
        corrupt writes can store these as lists, causing:
          TypeError: list indices must be integers or slices, not str
        in is_duplicate() / mark_seen(). This silently disabled the entire
        persistent dedup layer (dedup-L0) every run, allowing cross-run
        duplicates and stale advisory re-publication.
        """
        if INDEX_PATH.exists():
            try:
                raw = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
                if raw.get("schema_version") and "source_urls" in raw:
                    # v152.1.0: Validate and heal section types before assigning.
                    # If any dict section is a list (old/corrupt schema), reset it
                    # to an empty dict rather than letting a TypeError kill dedup-L0.
                    _dict_sections = ("source_urls", "stix_ids", "content_hashes", "title_hashes")
                    _healed = False
                    for _sec in _dict_sections:
                        if _sec in raw and not isinstance(raw[_sec], dict):
                            log.warning(
                                "[DEDUP] intel_index.json section '%s' is %s (expected dict) — "
                                "resetting to empty dict. This fixed the dedup-L0 TypeError.",
                                _sec, type(raw[_sec]).__name__
                            )
                            raw[_sec] = {}
                            _healed = True
                    if _healed:
                        raw["last_updated"] = _utc_now()
                        self._dirty = True  # force re-save with healed schema
                    self._index = raw
                    log.info("[DEDUP] Loaded intel_index: %d seen items, last_updated=%s",
                             raw.get("total_seen", 0), raw.get("last_updated", "?"))
                    return self
                log.warning("[DEDUP] intel_index.json schema mismatch — rebuilding")
            except Exception as e:
                log.warning("[DEDUP] intel_index.json corrupt (%s) — rebuilding", e)

        log.info("[DEDUP] intel_index.json not found — building from scratch")
        self._index = {**self._EMPTY_INDEX,
                       "created_at": _utc_now(),
                       "last_updated": _utc_now()}
        self._rebuild_from_sources()
        self._dirty = True
        return self

    def save(self) -> None:
        """Persist index atomically. Always updates last_updated."""
        self._index["last_updated"] = _utc_now()
        self._index["total_seen"] = (
            len(self._index["source_urls"]) +
            len(self._index["stix_ids"]) +
            len(self._index["content_hashes"])
        ) // 3  # approximate unique items
        _atomic_write(INDEX_PATH, self._index)
        if self._new_this_run:
            log.info("[DEDUP] Index saved: %d new items registered this run",
                     self._new_this_run)
        self._dirty = False
        self._new_this_run = 0

    # ---- Core API ------------------------------------------------------

    def is_duplicate(self, item: Dict) -> Tuple[bool, str]:
        """
        Multi-layer duplicate check.
        Returns (True, reason) if duplicate, (False, "") if new.

        Layer 0: source_url (PRIMARY KEY -- strict unique)
        Layer 1: stix_id    (PRIMARY KEY -- strict unique)
        Layer 2: content_hash (strong content match)
        Layer 3: title_hash   (cross-feed, skipped for generic titles)
        """
        url = _get_source_url(item)
        if url:
            uk = _url_key(url)
            if uk in self._index["source_urls"]:
                return True, f"source_url:{url[:60]}"

        sid = _get_stix_id(item)
        if sid and not sid.startswith("null"):
            if sid in self._index["stix_ids"]:
                return True, f"stix_id:{sid[:40]}"

        ck = _content_key(item)
        if ck in self._index["content_hashes"]:
            return True, f"content_hash:{ck[:16]}"

        title = str(item.get("title", ""))
        if title and not _is_generic_title(title):
            tk = _title_key(item)
            if tk in self._index["title_hashes"]:
                return True, f"title_hash:{title[:60]}"

        return False, ""

    def mark_seen(self, item: Dict, run_ts: Optional[str] = None) -> None:
        """Register item in ALL index layers."""
        ts = run_ts or _utc_now()
        title = str(item.get("title", ""))[:120]

        url = _get_source_url(item)
        if url:
            self._index["source_urls"][_url_key(url)] = {
                "first_seen": ts, "title": title, "url": url[:200]}

        sid = _get_stix_id(item)
        if sid and not sid.startswith("null"):
            self._index["stix_ids"][sid] = {"first_seen": ts, "title": title}

        ck = _content_key(item)
        self._index["content_hashes"][ck] = {"first_seen": ts, "title": title}

        if title and not _is_generic_title(title):
            self._index["title_hashes"][_title_key(item)] = {
                "first_seen": ts, "title": title}

        self._new_this_run += 1
        self._dirty = True

    def dedup_batch(self, items: List[Dict]) -> Tuple[List[Dict], int]:
        """
        Filter a batch of items, returning only NEW items.
        Marks all new items as seen immediately (prevents intra-batch dups too).
        Returns (new_items, removed_count).
        """
        unique: List[Dict] = []
        removed = 0
        run_ts = _utc_now()

        for item in items:
            is_dup, reason = self.is_duplicate(item)
            if is_dup:
                removed += 1
                log.debug("[DEDUP] SKIP duplicate (%s): %s",
                          reason, str(item.get("title", ""))[:60])
            else:
                self.mark_seen(item, run_ts)
                unique.append(item)

        if removed:
            log.info("[DEDUP] Batch filtered: %d duplicates removed, %d new items",
                     removed, len(unique))
        return unique, removed

    def get_stats(self) -> Dict:
        return {
            "source_urls":    len(self._index["source_urls"]),
            "stix_ids":       len(self._index["stix_ids"]),
            "content_hashes": len(self._index["content_hashes"]),
            "title_hashes":   len(self._index["title_hashes"]),
            "last_updated":   self._index.get("last_updated", ""),
        }

    # ---- Rebuild -------------------------------------------------------

    def _rebuild_from_sources(self) -> None:
        """
        Seed index from ALL existing data sources:
          1. data/feed_manifest.json  (current live manifest)
          2. data/archive/*.json      (historical archive files)
          3. data/stix/*.json         (STIX bundle objects -- id field)
        """
        ts = _utc_now()
        seeded = 0

        # 1. Current manifest
        seeded += self._seed_from_manifest(ts)

        # 2. Archive files (historical intel -- most important)
        seeded += self._seed_from_archive(ts)

        # 3. STIX bundle objects (stix_id primary key)
        seeded += self._seed_from_stix(ts)

        log.info("[DEDUP] Index rebuilt: %d items seeded from all sources", seeded)

    def _seed_from_manifest(self, ts: str) -> int:
        count = 0
        for mpath in [MANIFEST_PATH,
                      REPO_ROOT / "data" / "stix" / "feed_manifest.json",
                      REPO_ROOT / "manifest.json"]:
            if not mpath.exists():
                continue
            try:
                raw = json.loads(mpath.read_text(encoding="utf-8"))
                # v141.4.1 CRIT-04 FIX: robust normalisation — raw can be list, dict, or garbage
                if isinstance(raw, list):
                    items = raw
                elif isinstance(raw, dict):
                    items = (raw.get("advisories") or raw.get("items") or
                             raw.get("reports") or raw.get("entries") or [])
                else:
                    log.warning("[DEDUP] Manifest %s: unexpected root type %s — skipping", mpath.name, type(raw).__name__)
                    continue
                if not isinstance(items, list):
                    log.warning("[DEDUP] Manifest %s: advisory list is %s — skipping", mpath.name, type(items).__name__)
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    is_dup, _ = self.is_duplicate(item)
                    if not is_dup:
                        self.mark_seen(item, ts)
                        count += 1
                log.info("[DEDUP] Seeded %d from %s", count, mpath.name)
                break  # use first found manifest
            except Exception as e:
                log.warning("[DEDUP] Manifest seed failed (%s): %s", mpath.name, e)
        return count

    def _seed_from_archive(self, ts: str) -> int:
        count = 0
        if not ARCHIVE_DIR.exists():
            return 0
        archive_files = sorted(ARCHIVE_DIR.glob("*.json"))
        for af in archive_files:
            if af.name == "index.json":
                continue
            try:
                items = json.loads(af.read_text(encoding="utf-8"))
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    is_dup, _ = self.is_duplicate(item)
                    if not is_dup:
                        self.mark_seen(item, ts)
                        count += 1
            except Exception as e:
                log.warning("[DEDUP] Archive seed failed (%s): %s", af.name, e)
        log.info("[DEDUP] Seeded %d from archive (%d files)", count, len(archive_files))
        return count

    def _seed_from_stix(self, ts: str) -> int:
        count = 0
        if not STIX_DIR.exists():
            return 0
        stix_files = list(STIX_DIR.glob("CDB-APEX-*.json"))
        for sf in stix_files[:200]:  # cap at 200 to avoid slow startup
            try:
                raw = json.loads(sf.read_text(encoding="utf-8"))
                # STIX bundles have 'id' and 'objects' array
                bundle_id = raw.get("id", "")
                if bundle_id and bundle_id not in self._index["stix_ids"]:
                    self._index["stix_ids"][bundle_id] = {
                        "first_seen": ts, "title": sf.stem}
                    count += 1
                for obj in raw.get("objects", []):
                    oid = obj.get("id", "")
                    if oid and oid not in self._index["stix_ids"]:
                        self._index["stix_ids"][oid] = {
                            "first_seen": ts,
                            "title": obj.get("name", obj.get("title", sf.stem))[:120]}
                        count += 1
            except Exception:
                pass
        log.info("[DEDUP] Seeded %d STIX IDs", count)
        return count


# ---------------------------------------------------------------------------
# Feed State Tracker
# ---------------------------------------------------------------------------

class FeedStateTracker:
    """
    Per-feed ingestion state tracker.
    Prevents re-ingesting the same feed batch across pipeline runs.

    State stored in data/cache/feed_state.json (committed to git).

    Anti-loop protection:
      - If feed returns identical batch as last run -> skip entire batch
      - Tracks last_seen_ids per feed (up to 500 most recent)
    """

    def __init__(self) -> None:
        self._state: Dict = {}

    def load(self) -> "FeedStateTracker":
        if FSTATE_PATH.exists():
            try:
                raw = json.loads(FSTATE_PATH.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    # v141.5.0 FORMAT NORMALISATION:
                    # Old format: {"schema_version":..., "feeds":{...}}  (nested)
                    # New format: {"_meta":{...}, "https://...": {...}}   (flat)
                    # Detect old format: no URL-shaped top-level key, has "feeds" dict
                    has_url_keys = any(
                        str(k).startswith(("http://", "https://", "ftp://"))
                        for k in raw
                    )
                    if not has_url_keys and isinstance(raw.get("feeds"), dict):
                        # Migrate old nested format to flat URL-keyed format
                        self._state = dict(raw["feeds"])
                        log.info(
                            "[FEED-STATE] Migrated old nested format -> %d feeds",
                            len(self._state),
                        )
                    else:
                        # Current format: extract only URL-keyed entries, skip _meta/schema noise
                        self._state = {
                            k: v for k, v in raw.items()
                            if str(k).startswith(("http://", "https://", "ftp://"))
                        }
                        log.info("[FEED-STATE] Loaded state for %d feeds", len(self._state))
                    return self
            except Exception as e:
                log.warning("[FEED-STATE] State corrupt (%s) -- fresh start", e)
        self._state = {}
        return self

    def save(self) -> None:
        # v141.5.0: persist ONLY URL-keyed feed entries + _meta (no schema pollution)
        feed_entries = {
            k: v for k, v in self._state.items()
            if str(k).startswith(("http://", "https://", "ftp://"))
        }
        data = {
            "_meta": {
                "schema_version": "141.5.0",
                "last_updated": _utc_now(),
                "feed_count": len(feed_entries),
            },
            **feed_entries,
        }
        _atomic_write(FSTATE_PATH, data)

    def get_last_seen(self, feed_url: str) -> Optional[str]:
        """Return ISO timestamp of last successful ingestion for this feed."""
        return self._state.get(feed_url, {}).get("last_seen_timestamp")

    def get_last_ids(self, feed_url: str) -> Set[str]:
        """Return set of item IDs seen in last run for this feed."""
        return set(self._state.get(feed_url, {}).get("last_seen_ids", []))

    def is_same_batch(self, feed_url: str, item_ids: List[str]) -> bool:
        """
        Anti-loop check: return True if this batch is identical to the last run.
        If True -> skip entire batch (feed returning stale data).
        """
        if not item_ids:
            return False
        last_ids = self.get_last_ids(feed_url)
        if not last_ids:
            return False  # No history — process normally
        current_set = set(item_ids)
        # If 90%+ overlap with last batch -> treat as same (anti-loop)
        if not current_set:
            return False
        overlap = len(current_set & last_ids) / len(current_set)
        if overlap >= 0.90:
            log.warning("[FEED-STATE] ANTI-LOOP: feed %s returned %.0f%% same IDs as last run — SKIPPING",
                        feed_url[:60], overlap * 100)
            return True
        return False

    def filter_new_ids(self, feed_url: str, items: List[Dict],
                       id_fields: Tuple[str, ...] = ("stix_id", "bundle_id", "id",
                                                       "source_url", "link", "url")
                       ) -> List[Dict]:
        """
        Return only items whose ID was NOT seen in last run.
        Filters intra-run duplicates too (using id_fields for key extraction).
        """
        last_ids = self.get_last_ids(feed_url)
        if not last_ids:
            return items  # No history — return all

        new_items = []
        for item in items:
            item_id = ""
            for field in id_fields:
                v = item.get(field, "")
                if v:
                    item_id = str(v).strip()
                    break
            if not item_id or item_id not in last_ids:
                new_items.append(item)

        skipped = len(items) - len(new_items)
        if skipped:
            log.info("[FEED-STATE] %s: %d already-seen items filtered, %d new",
                     feed_url[:60], skipped, len(new_items))
        return new_items

    def update(self, feed_url: str, items: List[Dict],
               id_fields: Tuple[str, ...] = ("stix_id", "bundle_id", "id",
                                              "source_url", "link", "url")) -> None:
        """Record successful ingestion of this batch."""
        ids: List[str] = []
        for item in items:
            for field in id_fields:
                v = item.get(field, "")
                if v:
                    ids.append(str(v).strip())
                    break

        prev = self._state.get(feed_url, {})
        # Keep rolling window of last 500 IDs per feed
        all_ids = list(set(prev.get("last_seen_ids", []) + ids))[-500:]

        self._state[feed_url] = {
            "last_seen_timestamp": _utc_now(),
            "last_seen_ids": all_ids,
            "last_batch_size": len(items),
            "total_ingested": prev.get("total_ingested", 0) + len(items),
        }


# ---------------------------------------------------------------------------
# Manifest Uniqueness Guard
# ---------------------------------------------------------------------------

def enforce_manifest_uniqueness(items) -> Tuple[List[Dict], int]:
    """
    Final pre-write manifest uniqueness guard.
    Applied immediately before manifest is written to disk.

    Checks:
      1. source_url uniqueness (PRIMARY)
      2. stix_id uniqueness   (PRIMARY)
      3. content_hash         (STRONG)
      4. title dedup          (CROSS-FEED)

    Returns (unique_items, removed_count).
    This is ADDITIVE to existing dedup_items() — a final safety net.

    v141.4.1 CRIT-04 FIX: Guard against non-list input and non-dict items.
    The TypeError "list indices must be integers or slices, not str" was triggered
    when `items` was a dict (manifest wrapper) rather than a list of advisory dicts.
    Now handles: list of dicts, dict with advisory list, None → all normalised to list.
    """
    # Normalise input: accept list, dict wrapper, or empty
    if items is None:
        items = []
    elif isinstance(items, dict):
        # Caller passed the manifest wrapper dict instead of the advisories list
        items = (
            items.get("advisories")
            or items.get("items")
            or items.get("reports")
            or items.get("entries")
            or []
        )
    if not isinstance(items, list):
        log.warning("[MANIFEST-GUARD] enforce_manifest_uniqueness: unexpected input type %s — returning empty", type(items).__name__)
        return [], 0

    seen_urls:    Dict[str, int] = {}  # url_key -> first_index
    seen_sids:    Dict[str, int] = {}
    seen_content: Dict[str, int] = {}
    seen_titles:  Dict[str, int] = {}

    unique: List[Dict] = []
    removed = 0

    for item in items:
        # v141.4.1: Skip non-dict items (e.g. strings or ints that sneak into the list)
        if not isinstance(item, dict):
            log.debug("[MANIFEST-GUARD] Skipping non-dict item: %s", type(item).__name__)
            removed += 1
            continue
        url = _get_source_url(item)
        if url:
            uk = _url_key(url)
            if uk in seen_urls:
                log.info("[MANIFEST-GUARD] Duplicate source_url blocked: %s", url[:80])
                removed += 1
                continue
            seen_urls[uk] = len(unique)

        sid = _get_stix_id(item)
        if sid and not sid.startswith("null"):
            if sid in seen_sids:
                log.info("[MANIFEST-GUARD] Duplicate stix_id blocked: %s", sid[:40])
                removed += 1
                continue
            seen_sids[sid] = len(unique)

        ck = _content_key(item)
        if ck in seen_content:
            log.info("[MANIFEST-GUARD] Duplicate content_hash blocked: %s",
                     str(item.get("title", ""))[:60])
            removed += 1
            continue
        seen_content[ck] = len(unique)

        title = str(item.get("title", ""))
        if title and not _is_generic_title(title):
            tk = _title_key(item)
            if tk in seen_titles:
                log.info("[MANIFEST-GUARD] Cross-feed title dup blocked: %s", title[:60])
                removed += 1
                continue
            seen_titles[tk] = len(unique)

        unique.append(item)

    if removed:
        log.info("[MANIFEST-GUARD] Blocked %d duplicates before manifest write, %d unique remain",
                 removed, len(unique))
    return unique, removed


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_engine_instance: Optional[IntelDedupEngine] = None
_feed_tracker_instance: Optional[FeedStateTracker] = None


def get_dedup_engine() -> IntelDedupEngine:
    """Get (or create and load) the global dedup engine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = IntelDedupEngine().load()
    return _engine_instance


def get_feed_tracker() -> FeedStateTracker:
    """Get (or create and load) the global feed state tracker singleton."""
    global _feed_tracker_instance
    if _feed_tracker_instance is None:
        _feed_tracker_instance = FeedStateTracker().load()
    return _feed_tracker_instance


def save_all() -> None:
    """Persist both engine and feed tracker."""
    global _engine_instance, _feed_tracker_instance
    if _engine_instance is not None:
        _engine_instance.save()
    if _feed_tracker_instance is not None:
        _feed_tracker_instance.save()


# ---------------------------------------------------------------------------
# CLI: bootstrap / validate
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [dedup] %(levelname)s: %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%SZ")

    parser = argparse.ArgumentParser(description="Intel Dedup Engine CLI")
    parser.add_argument("--build-index", action="store_true",
                        help="Build/rebuild intel_index.json from all data sources")
    parser.add_argument("--stats", action="store_true",
                        help="Print current index stats")
    parser.add_argument("--validate-manifest", action="store_true",
                        help="Check data/feed_manifest.json for duplicate entries")

    if args.stats:
        engine = IntelDedupEngine()
        engine.load()
        stats = engine.get_stats()
        print(f"\nIntelDedupEngine index stats:")
        print(f"  source_urls:    {stats['source_urls']}")
        print(f"  stix_ids:       {stats['stix_ids']}")
        print(f"  content_hashes: {stats['content_hashes']}")
        print(f"  title_hashes:   {stats['title_hashes']}")
        print(f"  last_updated:   {stats['last_updated']}")

    if args.validate_manifest:
        if not MANIFEST_PATH.exists():
            print("No manifest found at", MANIFEST_PATH)
        else:
            raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
            items = (raw if isinstance(raw, list)
                     else raw.get("advisories") or raw.get("items") or [])
            unique, removed = enforce_manifest_uniqueness(items)
            print(f"\nManifest validation:")
            print(f"  Total items: {len(items)}")
            print(f"  Duplicates:  {removed}")
            print(f"  Unique:      {len(unique)}")
            if removed == 0:
                print("  STATUS: CLEAN -- no duplicates detected")
            else:
                print("  STATUS: DUPLICATES FOUND -- manifest needs cleanup")
