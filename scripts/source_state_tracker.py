#!/usr/bin/env python3
"""
scripts/source_state_tracker.py
CYBERDUDEBIVASH® SENTINEL APEX — Source State Tracker v1.0
============================================================
PHASE 1 FIX: Per-source ingestion state tracking with published_at comparison.

MANDATE:
  - Track last_seen_guid + last_seen_published_at per source feed entry
  - Ingestion rule: IF published_at <= last_seen_published_at → SKIP (not new intel)
  - Atomic persistence to data/source_state.json (committed to git)
  - Zero regression: purely additive layer, never blocks existing dedup

DATA SCHEMA (data/source_state.json):
  {
    "https://article-source-url.com": {
      "source_url":             "https://article-source-url.com",
      "last_seen_guid":         "https://article-url-or-id",
      "last_seen_published_at": "2026-04-29T18:00:00Z",
      "last_updated":           "2026-04-29T18:05:00Z",
      "skip_count":             42
    },
    ...
  }

INGESTION RULE (strict):
  IF entry.published_at <= state[source_url].last_seen_published_at  → SKIP
  IF entry.guid IN state[source_url].seen_guids                      → SKIP
  ELSE                                                               → PROCESS as NEW

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger("sentinel.source_state")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT        = Path(__file__).resolve().parent.parent
DATA_DIR         = REPO_ROOT / "data"
SOURCE_STATE_PATH = DATA_DIR / "source_state.json"

_SCHEMA_VERSION  = "1.0"
_MAX_GUIDS_PER_SOURCE = 200   # rolling window of seen GUIDs per source


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(ts: str) -> Optional[datetime]:
    """Parse ISO-8601 string to offset-aware datetime. Returns None on failure."""
    if not ts or not isinstance(ts, str):
        return None
    ts = ts.strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(ts[:len(fmt) + 6], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _atomic_write(path: Path, data: Dict) -> None:
    """Write JSON atomically: tmp → fsync → os.replace()."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    content = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True)
    tmp.write_text(content, encoding="utf-8")
    with open(tmp, "rb") as fh:
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# SourceStateTracker
# ---------------------------------------------------------------------------

class SourceStateTracker:
    """
    Persistent per-source state tracker.

    Implements Phase 1 ingestion rule:
      IF published_at <= last_seen_published_at → SKIP (stale intel)
      IF guid already seen                      → SKIP (exact duplicate)
      ELSE                                      → PROCESS as NEW

    Thread-safety: NOT thread-safe — single-process pipeline use only.

    Usage:
        tracker = SourceStateTracker().load()
        for entry in feed_entries:
            skip, reason = tracker.should_skip(entry)
            if skip:
                logger.info(f"[STATE-SKIP] {reason}: {entry['title'][:50]}")
                continue
            # process entry ...
            tracker.mark_processed(entry)
        tracker.save()
    """

    def __init__(self) -> None:
        self._state: Dict[str, Dict] = {}   # source_url → state dict
        self._dirty: bool = False
        self._new_this_run: int = 0
        self._skipped_this_run: int = 0

    # ---- I/O ---------------------------------------------------------------

    def load(self) -> "SourceStateTracker":
        """Load state from disk. Gracefully handles missing/corrupt file."""
        if SOURCE_STATE_PATH.exists():
            try:
                raw = json.loads(SOURCE_STATE_PATH.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    # Strip meta key, keep only URL-keyed entries
                    self._state = {
                        k: v for k, v in raw.items()
                        if str(k).startswith(("http://", "https://", "ftp://"))
                        and isinstance(v, dict)
                    }
                    log.info(
                        "[SOURCE-STATE] Loaded %d source state entries from %s",
                        len(self._state), SOURCE_STATE_PATH.name
                    )
                    return self
            except Exception as e:
                log.warning("[SOURCE-STATE] State file corrupt (%s) — fresh start", e)
        log.info("[SOURCE-STATE] No state file found — starting fresh (first run or clean slate)")
        self._state = {}
        return self

    def save(self) -> None:
        """Persist state atomically."""
        if not self._dirty:
            return
        payload = {
            "_meta": {
                "schema_version": _SCHEMA_VERSION,
                "last_updated":   _utc_now(),
                "source_count":   len(self._state),
                "new_this_run":   self._new_this_run,
                "skipped_this_run": self._skipped_this_run,
            },
            **self._state,
        }
        _atomic_write(SOURCE_STATE_PATH, payload)
        log.info(
            "[SOURCE-STATE] Saved: %d sources | %d new processed | %d skipped",
            len(self._state), self._new_this_run, self._skipped_this_run
        )
        self._dirty = False

    # ---- Core API ----------------------------------------------------------

    def should_skip(self, entry: Dict) -> Tuple[bool, str]:
        """
        Phase 1 ingestion rule check.
        Returns (True, reason) if entry should be SKIPPED.
        Returns (False, "") if entry is NEW and should be PROCESSED.

        Rules (applied in order):
          1. GUID match            → SKIP (exact duplicate URL/ID seen before)
          2. published_at ≤ state  → SKIP (not newer than last seen for this source)
        """
        source_url = _extract_source_url(entry)
        guid       = _extract_guid(entry)
        pub_at_str = _extract_published_at(entry)

        if not source_url:
            return False, ""   # No source URL → cannot check → pass through

        state = self._state.get(source_url, {})

        # Rule 1: GUID match
        if guid:
            seen_guids: Set[str] = set(state.get("seen_guids", []))
            if guid in seen_guids:
                self._skipped_this_run += 1
                return True, f"guid_seen:{guid[:80]}"

        # Rule 2: published_at comparison
        if pub_at_str and state.get("last_seen_published_at"):
            entry_dt = _parse_iso(pub_at_str)
            last_dt  = _parse_iso(state["last_seen_published_at"])
            if entry_dt and last_dt:
                if entry_dt <= last_dt:
                    self._skipped_this_run += 1
                    return True, (
                        f"published_at:{pub_at_str[:20]}"
                        f"<=last_seen:{state['last_seen_published_at'][:20]}"
                    )

        return False, ""

    def mark_processed(self, entry: Dict) -> None:
        """
        Record that this entry was processed.
        Updates last_seen_guid + last_seen_published_at for its source.
        """
        source_url = _extract_source_url(entry)
        guid       = _extract_guid(entry)
        pub_at_str = _extract_published_at(entry)

        if not source_url:
            return

        prev = self._state.get(source_url, {
            "source_url":             source_url,
            "last_seen_guid":         "",
            "last_seen_published_at": "",
            "seen_guids":             [],
            "last_updated":           "",
            "skip_count":             0,
            "process_count":          0,
        })

        # Update last_seen_published_at only if entry is actually newer
        if pub_at_str:
            prev_pub = _parse_iso(prev.get("last_seen_published_at", ""))
            this_pub = _parse_iso(pub_at_str)
            if this_pub and (prev_pub is None or this_pub > prev_pub):
                prev["last_seen_published_at"] = pub_at_str

        # Update GUID tracking
        if guid:
            prev["last_seen_guid"] = guid
            seen: List[str] = prev.get("seen_guids", [])
            if guid not in seen:
                seen.append(guid)
            # Rolling window
            prev["seen_guids"] = seen[-_MAX_GUIDS_PER_SOURCE:]

        prev["last_updated"]   = _utc_now()
        prev["process_count"]  = prev.get("process_count", 0) + 1
        self._state[source_url] = prev
        self._new_this_run += 1
        self._dirty = True

    def get_stats(self) -> Dict:
        """Return runtime statistics for this tracker instance."""
        return {
            "sources_tracked":  len(self._state),
            "new_this_run":     self._new_this_run,
            "skipped_this_run": self._skipped_this_run,
        }

    def update_skip_count(self, source_url: str) -> None:
        """Increment skip counter for a source (call when should_skip returns True)."""
        if source_url in self._state:
            self._state[source_url]["skip_count"] = (
                self._state[source_url].get("skip_count", 0) + 1
            )
            self._dirty = True


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _extract_source_url(entry: Dict) -> str:
    """Extract the canonical source URL (article link, not feed URL)."""
    for field in ("source_url", "link", "url", "blog_url"):
        v = entry.get(field, "")
        if v and isinstance(v, str) and v.startswith("http"):
            return v.strip()
    return ""


def _extract_guid(entry: Dict) -> str:
    """Extract unique identifier for this entry."""
    for field in ("id", "guid", "link", "source_url", "url"):
        v = entry.get(field, "")
        if v and isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _extract_published_at(entry: Dict) -> str:
    """Extract publication timestamp from entry dict."""
    for field in ("published_at", "published", "pubDate", "date"):
        v = entry.get(field, "")
        if v and isinstance(v, str) and not isinstance(v, bool):
            v = v.strip()
            if v and v[0].isdigit():
                return v
    # Try published_parsed struct_time (feedparser format)
    pp = entry.get("published_parsed")
    if pp:
        try:
            from datetime import datetime as _dt
            return _dt(*pp[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
    return ""


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: Optional[SourceStateTracker] = None


def get_source_state_tracker() -> SourceStateTracker:
    """Get (or create and load) the global SourceStateTracker singleton."""
    global _instance
    if _instance is None:
        _instance = SourceStateTracker().load()
    return _instance


def reset_singleton() -> None:
    """Reset singleton (for testing)."""
    global _instance
    _instance = None


# ---------------------------------------------------------------------------
# CLI: inspect / validate
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [source_state] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    parser = argparse.ArgumentParser(description="Source State Tracker CLI")
    parser.add_argument("--stats", action="store_true", help="Print current state stats")
    parser.add_argument("--dump", action="store_true", help="Dump all tracked sources")
    args = parser.parse_args()

    tracker = SourceStateTracker().load()

    if args.stats:
        stats = tracker.get_stats()
        print(f"\nSource State Stats:")
        print(f"  sources_tracked:  {stats['sources_tracked']}")
        print(f"  new_this_run:     {stats['new_this_run']}")
        print(f"  skipped_this_run: {stats['skipped_this_run']}")
        print(f"  state_file:       {SOURCE_STATE_PATH}")
        print(f"  exists:           {SOURCE_STATE_PATH.exists()}")

    if args.dump:
        for url, state in tracker._state.items():
            print(f"\n  Source: {url[:80]}")
            print(f"    last_seen_guid:         {state.get('last_seen_guid','')[:60]}")
            print(f"    last_seen_published_at: {state.get('last_seen_published_at','')}")
            print(f"    process_count:          {state.get('process_count', 0)}")
            print(f"    skip_count:             {state.get('skip_count', 0)}")
