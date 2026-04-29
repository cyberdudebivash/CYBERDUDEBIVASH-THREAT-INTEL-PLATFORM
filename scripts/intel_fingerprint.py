#!/usr/bin/env python3
"""
scripts/intel_fingerprint.py
CYBERDUDEBIVASH® SENTINEL APEX — Intel Fingerprint Store v1.0
=============================================================
PHASE 2 FIX: SHA256 content fingerprint deduplication layer.

MANDATE:
  - Generate: fingerprint = SHA256(source_url + title + published_at)
  - Store in:  data/processed_fingerprints.json
  - RULE:      IF fingerprint EXISTS → SKIP (already processed)
               ELSE                 → PROCESS as NEW
  - Atomic persistence (committed to git)
  - Rolling window: cap at MAX_FINGERPRINTS to prevent unbounded growth

FINGERPRINT FORMULA:
  input  = (source_url.strip().lower() + "||" +
            title.strip().lower()      + "||" +
            published_at.strip())
  digest = hashlib.sha256(input.encode("utf-8")).hexdigest()

DATA SCHEMA (data/processed_fingerprints.json):
  {
    "_meta": {
      "schema_version": "1.0",
      "last_updated":   "2026-04-29T18:05:00Z",
      "total_stored":   1234
    },
    "fingerprints": [
      "e3b0c44298fc1c...",
      ...
    ]
  }

LAYERED DEDUP STACK (Sentinel APEX):
  Layer 0: source_state.json  (published_at timestamp per source feed)
  Layer 1: intel_index.json   (stix_id dedup via IntelDedupEngine)
  Layer 2: processed_fingerprints.json  ← THIS MODULE (content hash)
  Layer 3: title_hash in IntelDedupEngine

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

log = logging.getLogger("sentinel.intel_fingerprint")

# ---------------------------------------------------------------------------
# Paths & Constants
# ---------------------------------------------------------------------------
REPO_ROOT                 = Path(__file__).resolve().parent.parent
DATA_DIR                  = REPO_ROOT / "data"
FINGERPRINT_PATH          = DATA_DIR / "processed_fingerprints.json"

_SCHEMA_VERSION           = "1.0"
_MAX_FINGERPRINTS         = 50_000   # rolling cap — ~10MB file max
_FINGERPRINT_FIELD_SEP    = "||"     # deterministic separator (not in URLs/titles)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, data: Dict) -> None:
    """Write JSON atomically: tmp → fsync → os.replace()."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    content = json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False)
    tmp.write_text(content, encoding="utf-8")
    with open(tmp, "rb") as fh:
        os.fsync(fh.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Fingerprint computation
# ---------------------------------------------------------------------------

def compute_fingerprint(source_url: str, title: str, published_at: str) -> str:
    """
    Compute deterministic SHA256 fingerprint for a threat intel entry.

    Formula:
        input  = lower(source_url) + "||" + lower(title) + "||" + published_at
        digest = sha256(input.encode("utf-8")).hexdigest()

    All fields are stripped before concatenation.
    Empty fields contribute empty string (never raises).
    """
    parts = (
        (source_url or "").strip().lower(),
        (title or "").strip().lower(),
        (published_at or "").strip(),
    )
    raw = _FINGERPRINT_FIELD_SEP.join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fingerprint_from_entry(entry: Dict) -> str:
    """Extract fields from an entry dict and compute its fingerprint."""
    source_url  = _extract_source_url(entry)
    title       = _extract_title(entry)
    published_at = _extract_published_at(entry)
    return compute_fingerprint(source_url, title, published_at)


# ---------------------------------------------------------------------------
# IntelFingerprintStore
# ---------------------------------------------------------------------------

class IntelFingerprintStore:
    """
    Persistent SHA256 fingerprint store for threat intel deduplication.

    Phase 2 dedup rule:
      IF fingerprint(source_url + title + published_at) in store → SKIP
      ELSE                                                        → PROCESS + mark

    Usage:
        store = IntelFingerprintStore().load()
        for entry in entries:
            fp = fingerprint_from_entry(entry)
            if store.is_duplicate(fp):
                continue
            # process entry ...
            store.mark_seen(fp)
        store.save()
    """

    def __init__(self) -> None:
        self._fps: Set[str] = set()
        self._ordered: List[str] = []   # insertion-order for rolling window trim
        self._dirty: bool = False
        self._new_this_run: int = 0
        self._skipped_this_run: int = 0

    # ---- I/O ---------------------------------------------------------------

    def load(self) -> "IntelFingerprintStore":
        """Load fingerprints from disk. Gracefully handles missing/corrupt file."""
        if FINGERPRINT_PATH.exists():
            try:
                raw = json.loads(FINGERPRINT_PATH.read_text(encoding="utf-8"))
                fps_list = raw.get("fingerprints", [])
                if isinstance(fps_list, list):
                    # Validate: keep only 64-char hex strings
                    valid = [
                        fp for fp in fps_list
                        if isinstance(fp, str) and len(fp) == 64
                    ]
                    self._ordered = valid
                    self._fps     = set(valid)
                    log.info(
                        "[FINGERPRINT] Loaded %d fingerprints from %s",
                        len(self._fps), FINGERPRINT_PATH.name
                    )
                    return self
            except Exception as e:
                log.warning("[FINGERPRINT] Store corrupt (%s) — fresh start", e)
        log.info("[FINGERPRINT] No fingerprint store found — starting fresh")
        self._fps     = set()
        self._ordered = []
        return self

    def save(self) -> None:
        """Persist fingerprints atomically. No-op if not dirty."""
        if not self._dirty:
            return
        # Enforce rolling window before persist
        if len(self._ordered) > _MAX_FINGERPRINTS:
            trim = len(self._ordered) - _MAX_FINGERPRINTS
            removed = self._ordered[:trim]
            self._ordered = self._ordered[trim:]
            self._fps -= set(removed)
            log.debug("[FINGERPRINT] Trimmed %d old fingerprints (rolling window)", trim)

        payload = {
            "_meta": {
                "schema_version":  _SCHEMA_VERSION,
                "last_updated":    _utc_now(),
                "total_stored":    len(self._ordered),
                "new_this_run":    self._new_this_run,
                "skipped_this_run": self._skipped_this_run,
            },
            "fingerprints": self._ordered,
        }
        _atomic_write(FINGERPRINT_PATH, payload)
        log.info(
            "[FINGERPRINT] Saved: %d total | %d new | %d skipped",
            len(self._ordered), self._new_this_run, self._skipped_this_run
        )
        self._dirty = False

    # ---- Core API ----------------------------------------------------------

    def is_duplicate(self, fingerprint: str) -> bool:
        """Return True if this fingerprint was already processed."""
        return fingerprint in self._fps

    def mark_seen(self, fingerprint: str) -> None:
        """Record a fingerprint as processed."""
        if fingerprint and fingerprint not in self._fps:
            self._fps.add(fingerprint)
            self._ordered.append(fingerprint)
            self._new_this_run += 1
            self._dirty = True

    def record_skip(self) -> None:
        """Increment skip counter (call when is_duplicate returns True)."""
        self._skipped_this_run += 1

    def dedup_batch(
        self,
        entries: List[Dict],
        *,
        mark_all: bool = False,
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Split a list of entry dicts into (new_entries, skipped_entries).

        Args:
            entries:   List of entry dicts (each must have source_url/title/published_at)
            mark_all:  If True, mark all new entries as seen immediately.
                       If False, caller is responsible for calling mark_seen().

        Returns:
            (new_entries, skipped_entries)
        """
        new_entries: List[Dict] = []
        skipped: List[Dict] = []

        for entry in entries:
            fp = fingerprint_from_entry(entry)
            if self.is_duplicate(fp):
                self.record_skip()
                skipped.append(entry)
            else:
                new_entries.append(entry)
                if mark_all:
                    self.mark_seen(fp)

        return new_entries, skipped

    def check_entry(self, entry: Dict) -> Tuple[bool, str]:
        """
        High-level entry check: returns (is_dup, fingerprint).
        Mirrors SourceStateTracker.should_skip() interface for pipeline consistency.
        """
        fp = fingerprint_from_entry(entry)
        if self.is_duplicate(fp):
            self._skipped_this_run += 1
            return True, fp
        return False, fp

    def get_stats(self) -> Dict:
        """Return runtime statistics."""
        return {
            "total_fingerprints": len(self._fps),
            "new_this_run":       self._new_this_run,
            "skipped_this_run":   self._skipped_this_run,
        }

    def __len__(self) -> int:
        return len(self._fps)


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _extract_source_url(entry: Dict) -> str:
    for field in ("source_url", "link", "url", "blog_url"):
        v = entry.get(field, "")
        if v and isinstance(v, str) and v.startswith("http"):
            return v.strip()
    return ""


def _extract_title(entry: Dict) -> str:
    for field in ("title", "headline", "name"):
        v = entry.get(field, "")
        if v and isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _extract_published_at(entry: Dict) -> str:
    for field in ("published_at", "published", "pubDate", "date"):
        v = entry.get(field, "")
        if v and isinstance(v, str) and not isinstance(v, bool):
            v = v.strip()
            if v and v[0].isdigit():
                return v
    # feedparser published_parsed (struct_time)
    pp = entry.get("published_parsed")
    if pp:
        try:
            return datetime(*pp[:6], tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass
    return ""


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_instance: Optional[IntelFingerprintStore] = None


def get_fingerprint_store() -> IntelFingerprintStore:
    """Get (or create and load) the global IntelFingerprintStore singleton."""
    global _instance
    if _instance is None:
        _instance = IntelFingerprintStore().load()
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
        format="%(asctime)s [fingerprint] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    parser = argparse.ArgumentParser(description="Intel Fingerprint Store CLI")
    parser.add_argument("--stats",  action="store_true", help="Print store stats")
    parser.add_argument("--check",  metavar="URL",       help="Check if URL fingerprint exists")
    parser.add_argument("--title",  default="",          help="Title for --check")
    parser.add_argument("--pubdate",default="",          help="Published-at for --check")
    args = parser.parse_args()

    store = IntelFingerprintStore().load()

    if args.stats:
        stats = store.get_stats()
        print(f"\nFingerprint Store Stats:")
        print(f"  total_fingerprints: {stats['total_fingerprints']}")
        print(f"  new_this_run:       {stats['new_this_run']}")
        print(f"  skipped_this_run:   {stats['skipped_this_run']}")
        print(f"  store_path:         {FINGERPRINT_PATH}")
        print(f"  exists:             {FINGERPRINT_PATH.exists()}")

    if args.check:
        fp = compute_fingerprint(args.check, args.title, args.pubdate)
        is_dup = store.is_duplicate(fp)
        print(f"\n  URL:         {args.check[:80]}")
        print(f"  Title:       {args.title[:60]}")
        print(f"  Published:   {args.pubdate}")
        print(f"  Fingerprint: {fp}")
        print(f"  Duplicate:   {'YES — SKIP' if is_dup else 'NO — PROCESS'}")
