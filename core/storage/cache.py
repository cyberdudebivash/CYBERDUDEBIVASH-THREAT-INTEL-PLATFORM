#!/usr/bin/env python3
"""
cache.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0 (COMMAND CENTER)
═══════════════════════════════════════════════════════════════════
Redis Cache Engine with in-memory LRU fallback.

Provides:
  - Distributed caching via Redis (Upstash)
  - Thread-safe in-memory LRU cache fallback
  - TTL-based expiration
  - Namespace isolation
  - Cache statistics and health monitoring
  - IOC lookup cache for high-speed matching

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import time
import logging
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-CACHE")

DEFAULT_TTL = 300  # 5 minutes
MAX_MEMORY_ENTRIES = 10000


class LRUCache:
    """Thread-safe LRU cache with TTL support."""

    def __init__(self, max_size: int = MAX_MEMORY_ENTRIES):
        self._cache: OrderedDict = OrderedDict()
        self._expiry: Dict[str, float] = {}
        self._max_size = max_size
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if self._expiry.get(key, float("inf")) < time.time():
                    del self._cache[key]
                    del self._expiry[key]
                    self._misses += 1
                    return None
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            self._misses += 1
            return None

    def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL):
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            self._expiry[key] = time.time() + ttl
            while len(self._cache) > self._max_size:
                oldest_key, _ = self._cache.popitem(last=False)
                self._expiry.pop(oldest_key, None)

    def delete(self, key: str):
        with self._lock:
            self._cache.pop(key, None)
            self._expiry.pop(key, None)

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._expiry.clear()

    def exists(self, key: str) -> bool:
        with self._lock:
            if key not in self._cache:
                return False
            if self._expiry.get(key, float("inf")) < time.time():
                del self._cache[key]
                del self._expiry[key]
                return False
            return True

    @property
    def stats(self) -> Dict:
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "max_size": self._max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total * 100, 1) if total > 0 else 0,
        }


class CacheEngine:
    """
    Unified cache engine: Redis (production) + LRU (fallback).
    Maintains IOC lookup cache and intelligence result cache.
    """

    def __init__(self):
        self._redis = None
        self._redis_available = False
        self._lru = LRUCache()
        self._connect_redis()

    def _connect_redis(self):
        redis_url = os.environ.get("UPSTASH_REDIS_URL", "")
        redis_token = os.environ.get("UPSTASH_REDIS_TOKEN", "")
        if not redis_url:
            logger.info("Cache engine: in-memory LRU mode")
            return

        try:
            import redis as redis_lib
            if redis_token:
                self._redis = redis_lib.from_url(
                    redis_url, password=redis_token,
                    decode_responses=True, socket_timeout=3,
                )
            else:
                self._redis = redis_lib.from_url(
                    redis_url, decode_responses=True, socket_timeout=3,
                )
            self._redis.ping()
            self._redis_available = True
            logger.info("Cache engine: Redis connected")
        except Exception as e:
            logger.warning(f"Redis cache unavailable, using LRU: {e}")
            self._redis_available = False

    def get(self, key: str, namespace: str = "cdb") -> Optional[Any]:
        full_key = f"{namespace}:{key}"

        if self._redis_available:
            try:
                val = self._redis.get(full_key)
                if val is not None:
                    return json.loads(val)
            except Exception:
                pass

        return self._lru.get(full_key)

    def set(self, key: str, value: Any, ttl: int = DEFAULT_TTL, namespace: str = "cdb"):
        full_key = f"{namespace}:{key}"

        if self._redis_available:
            try:
                self._redis.setex(full_key, ttl, json.dumps(value, default=str))
            except Exception:
                pass

        self._lru.set(full_key, value, ttl)

    def delete(self, key: str, namespace: str = "cdb"):
        full_key = f"{namespace}:{key}"
        if self._redis_available:
            try:
                self._redis.delete(full_key)
            except Exception:
                pass
        self._lru.delete(full_key)

    def exists(self, key: str, namespace: str = "cdb") -> bool:
        full_key = f"{namespace}:{key}"
        if self._redis_available:
            try:
                return bool(self._redis.exists(full_key))
            except Exception:
                pass
        return self._lru.exists(full_key)

    # ── IOC Cache (high-speed matching) ───────────────────

    def cache_ioc_set(self, ioc_type: str, values: List[str], ttl: int = 3600):
        """Cache a set of IOCs for fast lookup."""
        key = f"ioc_set:{ioc_type}"
        if self._redis_available:
            try:
                pipe = self._redis.pipeline()
                pipe.delete(f"cdb:{key}")
                if values:
                    pipe.sadd(f"cdb:{key}", *values)
                    pipe.expire(f"cdb:{key}", ttl)
                pipe.execute()
                return
            except Exception:
                pass
        self._lru.set(key, set(values), ttl)

    def check_ioc(self, ioc_type: str, value: str) -> bool:
        """Check if an IOC value exists in the cached set."""
        key = f"ioc_set:{ioc_type}"
        if self._redis_available:
            try:
                return bool(self._redis.sismember(f"cdb:{key}", value))
            except Exception:
                pass
        cached = self._lru.get(key)
        return value in cached if isinstance(cached, set) else False

    # ── Intelligence Cache ────────────────────────────────

    def cache_intel_result(self, query_hash: str, results: List[Dict], ttl: int = 120):
        self.set(f"intel_query:{query_hash}", results, ttl)

    def get_cached_intel(self, query_hash: str) -> Optional[List[Dict]]:
        return self.get(f"intel_query:{query_hash}")

    # ── Stats ─────────────────────────────────────────────

    def get_stats(self) -> Dict:
        stats = {
            "backend": "redis" if self._redis_available else "lru",
            "lru_stats": self._lru.stats,
        }
        if self._redis_available:
            try:
                info = self._redis.info("memory")
                stats["redis_memory"] = info.get("used_memory_human", "N/A")
            except Exception:
                pass
        return stats


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

_cache_instance: Optional[CacheEngine] = None


def get_cache() -> CacheEngine:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = CacheEngine()
    return _cache_instance
