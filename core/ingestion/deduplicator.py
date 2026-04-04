"""
core/ingestion/deduplicator.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
Content-addressed deduplication engine for the ingestion pipeline.

Design:
  - Two-level dedup: content-hash (exact) + semantic-key (logical same entity)
  - In-memory ring buffer with configurable TTL (default 24 h)
  - Persistent bloom-filter-style JSONL backing for crash-recovery
  - Thread-safe: uses threading.Lock for concurrent source processing
  - Emits dedup metrics: total_seen, total_accepted, total_rejected, hit_rate
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .sources.base import RawIntelItem

logger = logging.getLogger("sentinel.ingestion.deduplicator")

_PERSIST_PATH = "/tmp/sentinel_dedup_cache.jsonl"
_MAX_CACHE_ENTRIES = 500_000    # memory safety ceiling
_DEFAULT_TTL_S = 86_400         # 24 hours


@dataclass
class DedupStats:
    total_seen:     int = 0
    total_accepted: int = 0
    total_rejected: int = 0
    cache_size:     int = 0

    @property
    def hit_rate(self) -> float:
        if not self.total_seen:
            return 0.0
        return round(self.total_rejected / self.total_seen, 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_seen":     self.total_seen,
            "total_accepted": self.total_accepted,
            "total_rejected": self.total_rejected,
            "cache_size":     self.cache_size,
            "hit_rate":       self.hit_rate,
        }


class Deduplicator:
    """
    Two-level deduplication:
      Level 1 — content_hash (SHA-256 of raw_data): exact duplicate
      Level 2 — semantic_key (source_id + raw_id): same logical entity updated
                  If semantic key matches but content_hash differs → accept (updated entity)
    """

    def __init__(
        self,
        ttl_s: int = _DEFAULT_TTL_S,
        persist_path: str = _PERSIST_PATH,
        max_entries: int = _MAX_CACHE_ENTRIES,
    ) -> None:
        self._ttl_s        = ttl_s
        self._persist_path = persist_path
        self._max_entries  = max_entries
        self._lock         = threading.Lock()

        # content_hash → expiry_ts
        self._hash_cache: OrderedDict[str, float] = OrderedDict()
        # semantic_key → (content_hash, expiry_ts)
        self._semantic_cache: Dict[str, Tuple[str, float]] = {}

        self._stats = DedupStats()
        self._load_persisted()

    # ── Public API ────────────────────────────────────────────────────────────

    def is_duplicate(self, item: RawIntelItem) -> bool:
        """
        Returns True if the item is a duplicate (should be skipped).
        Registers the item if it is NOT a duplicate.
        """
        with self._lock:
            self._stats.total_seen += 1
            self._evict_expired()

            content_hash  = item.content_hash
            semantic_key  = self._make_semantic_key(item)
            now           = time.time()
            expiry        = now + self._ttl_s

            # Level 1: exact content hash match
            if content_hash in self._hash_cache:
                self._stats.total_rejected += 1
                return True

            # Level 2: same entity, different content (update) → accept but refresh
            existing = self._semantic_cache.get(semantic_key)
            if existing:
                existing_hash, _ = existing
                # If content changed: remove old hash and accept new version
                if existing_hash in self._hash_cache:
                    del self._hash_cache[existing_hash]

            # Register
            self._hash_cache[content_hash] = expiry
            self._semantic_cache[semantic_key] = (content_hash, expiry)
            self._stats.total_accepted += 1
            self._stats.cache_size = len(self._hash_cache)

            # Safety: trim to max_entries (LRU eviction via OrderedDict)
            while len(self._hash_cache) > self._max_entries:
                oldest_hash, _ = self._hash_cache.popitem(last=False)
                # Remove corresponding semantic entry
                for sk, (h, _) in list(self._semantic_cache.items()):
                    if h == oldest_hash:
                        del self._semantic_cache[sk]
                        break

            return False

    def filter_batch(self, items: List[RawIntelItem]) -> Tuple[List[RawIntelItem], int]:
        """
        Filter a batch of items.
        Returns (accepted_items, rejected_count).
        """
        accepted: List[RawIntelItem] = []
        rejected = 0
        for item in items:
            if self.is_duplicate(item):
                rejected += 1
            else:
                accepted.append(item)
        return accepted, rejected

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return self._stats.to_dict()

    def reset(self) -> None:
        with self._lock:
            self._hash_cache.clear()
            self._semantic_cache.clear()
            self._stats = DedupStats()
        logger.info("deduplicator_reset")

    def persist(self) -> None:
        """Write current hash cache to disk for crash-recovery."""
        try:
            tmp = self._persist_path + ".tmp"
            with open(tmp, "w") as f:
                with self._lock:
                    now = time.time()
                    for h, expiry in self._hash_cache.items():
                        if expiry > now:
                            f.write(json.dumps({"h": h, "exp": expiry}) + "\n")
            os.replace(tmp, self._persist_path)
            logger.debug("deduplicator_persisted entries=%d", len(self._hash_cache))
        except Exception as exc:
            logger.warning("deduplicator_persist_failed err=%s", exc)

    # ── Internals ─────────────────────────────────────────────────────────────

    def _evict_expired(self) -> None:
        """Remove expired entries. Called under lock."""
        now  = time.time()
        expired_hashes: List[str] = [
            h for h, exp in self._hash_cache.items() if exp <= now
        ]
        for h in expired_hashes:
            del self._hash_cache[h]

        expired_keys: List[str] = [
            sk for sk, (_, exp) in self._semantic_cache.items() if exp <= now
        ]
        for sk in expired_keys:
            del self._semantic_cache[sk]

        if expired_hashes:
            self._stats.cache_size = len(self._hash_cache)
            logger.debug("dedup_evict expired=%d", len(expired_hashes))

    def _load_persisted(self) -> None:
        if not os.path.exists(self._persist_path):
            return
        loaded = 0
        skipped = 0
        now = time.time()
        try:
            with open(self._persist_path, "r") as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        h, exp = entry["h"], entry["exp"]
                        if exp > now:
                            self._hash_cache[h] = exp
                            loaded += 1
                        else:
                            skipped += 1
                    except Exception:
                        skipped += 1
            self._stats.cache_size = len(self._hash_cache)
            logger.info("dedup_loaded loaded=%d skipped=%d", loaded, skipped)
        except Exception as exc:
            logger.warning("dedup_load_failed err=%s", exc)

    @staticmethod
    def _make_semantic_key(item: RawIntelItem) -> str:
        """Logical identity key: source + raw_id."""
        raw = f"{item.source_id}:{item.raw_id}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]
