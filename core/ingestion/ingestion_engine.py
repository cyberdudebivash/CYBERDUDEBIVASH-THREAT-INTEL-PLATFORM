"""
core/ingestion/ingestion_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
Main ingestion orchestrator for all threat intelligence sources.

Architecture:
  ┌──────────────┐     ┌──────────────────┐     ┌─────────────────┐
  │  Source Pool │────▶│  Ingestion Queue │────▶│  Worker Pool    │
  │  NVD / KEV  │     │ (Redis Streams / │     │  Dedup → Norm  │
  │  MB / AIDB  │     │  In-memory Q)    │     │  → Storage      │
  └──────────────┘     └──────────────────┘     └─────────────────┘

Components:
  - IngestionQueue: Redis Streams primary, in-memory deque fallback
  - SourceScheduler: Priority-based fetch schedule per source (cron-like)
  - WorkerPool: Thread-based consumer of the queue
  - IngestionEngine: Top-level orchestrator with health + metrics APIs
  - FastAPI router: /api/v1/ingestion/* — status, trigger, metrics, queue

Security:
  - Source errors are isolated: one failing source doesn't cascade
  - Queue backpressure: drops items when queue reaches max_depth
  - Rate limiting enforced per-source at BaseSource layer
"""
from __future__ import annotations

import json
import logging
import os
import queue
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from .sources.base import FetchResult, FetchStatus, RawIntelItem, SourceType
from .sources.nvd_source import NVDSource
from .sources.kev_source import KEVSource
from .sources.malwarebazaar_source import MalwareBazaarSource
from .sources.abuseipdb_source import AbuseIPDBSource
from .deduplicator import Deduplicator
from .normalizer import Normalizer, IntelItem

logger = logging.getLogger("sentinel.ingestion.engine")

_QUEUE_MAX_DEPTH    = 50_000
_WORKER_THREADS     = 4
_HEARTBEAT_INTERVAL = 60    # seconds


# ─────────────────────────────────────────────
# Schedule Configuration
# ─────────────────────────────────────────────

@dataclass
class SourceSchedule:
    """Defines how often a source is polled."""
    source_id:     str
    interval_s:    int          # polling interval in seconds
    priority:      int = 5      # lower = higher priority (1 is highest)
    enabled:       bool = True
    last_run_ts:   float = 0.0
    next_run_ts:   float = 0.0
    consecutive_failures: int = 0
    max_failures:  int = 5      # disable source after N consecutive failures

    def is_due(self) -> bool:
        return self.enabled and time.time() >= self.next_run_ts

    def mark_success(self) -> None:
        self.consecutive_failures = 0
        self.last_run_ts  = time.time()
        self.next_run_ts  = self.last_run_ts + self.interval_s

    def mark_failure(self) -> None:
        self.consecutive_failures += 1
        self.last_run_ts = time.time()
        # Exponential backoff on consecutive failures (cap at 1 hour)
        backoff = min(self.interval_s * (2 ** self.consecutive_failures), 3600)
        self.next_run_ts = self.last_run_ts + backoff
        if self.consecutive_failures >= self.max_failures:
            self.enabled = False
            logger.error("source_disabled source_id=%s consecutive_failures=%d",
                         self.source_id, self.consecutive_failures)


# ─────────────────────────────────────────────
# In-Memory Queue (Redis Streams fallback)
# ─────────────────────────────────────────────

class IngestionQueue:
    """
    Thread-safe ingestion queue.
    Primary: Redis Streams (if redis available).
    Fallback: in-process Python queue.Queue with backpressure.
    """

    def __init__(self, max_depth: int = _QUEUE_MAX_DEPTH) -> None:
        self._max_depth = max_depth
        self._redis     = self._try_connect_redis()
        self._q: queue.Queue = queue.Queue(maxsize=max_depth)
        self._enqueued  = 0
        self._dequeued  = 0
        self._dropped   = 0

    def enqueue(self, item: RawIntelItem) -> bool:
        """Enqueue a raw item. Returns True if enqueued, False if dropped."""
        if self._redis:
            return self._redis_enqueue(item)
        return self._mem_enqueue(item)

    def dequeue(self, timeout_s: float = 2.0) -> Optional[RawIntelItem]:
        """Blocking dequeue with timeout. Returns None on timeout."""
        if self._redis:
            return self._redis_dequeue(timeout_s)
        return self._mem_dequeue(timeout_s)

    def depth(self) -> int:
        if self._redis:
            try:
                return self._redis.xlen("sentinel:ingestion:queue")
            except Exception:
                pass
        return self._q.qsize()

    def stats(self) -> Dict[str, Any]:
        return {
            "backend":   "redis" if self._redis else "memory",
            "depth":     self.depth(),
            "enqueued":  self._enqueued,
            "dequeued":  self._dequeued,
            "dropped":   self._dropped,
            "max_depth": self._max_depth,
        }

    # ── Memory backend ────────────────────────────────────────────────────────

    def _mem_enqueue(self, item: RawIntelItem) -> bool:
        try:
            self._q.put_nowait(item)
            self._enqueued += 1
            return True
        except queue.Full:
            self._dropped += 1
            logger.warning("queue_full dropped source=%s raw_id=%s",
                           item.source_id, item.raw_id)
            return False

    def _mem_dequeue(self, timeout_s: float) -> Optional[RawIntelItem]:
        try:
            item = self._q.get(timeout=timeout_s)
            self._dequeued += 1
            return item
        except queue.Empty:
            return None

    # ── Redis Streams backend ─────────────────────────────────────────────────

    def _redis_enqueue(self, item: RawIntelItem) -> bool:
        try:
            payload = json.dumps({
                "source_id":   item.source_id,
                "source_type": item.source_type.value,
                "raw_id":      item.raw_id,
                "content_hash": item.content_hash,
                "raw_data":    item.raw_data,
                "fetched_at":  item.fetched_at,
                "metadata":    item.metadata,
            })
            depth = self._redis.xlen("sentinel:ingestion:queue")
            if depth >= self._max_depth:
                self._dropped += 1
                return False
            self._redis.xadd(
                "sentinel:ingestion:queue",
                {"payload": payload},
                maxlen=self._max_depth,
                approximate=True,
            )
            self._enqueued += 1
            return True
        except Exception as exc:
            logger.warning("redis_enqueue_failed err=%s; fallback", exc)
            self._redis = None
            return self._mem_enqueue(item)

    def _redis_dequeue(self, timeout_s: float) -> Optional[RawIntelItem]:
        try:
            ms = int(timeout_s * 1000)
            entries = self._redis.xread(
                {"sentinel:ingestion:queue": "0-0"}, count=1, block=ms
            )
            if not entries:
                return None
            _, messages = entries[0]
            stream_id, data = messages[0]
            self._redis.xdel("sentinel:ingestion:queue", stream_id)
            payload = json.loads(data[b"payload"] if b"payload" in data else data["payload"])
            self._dequeued += 1
            return RawIntelItem(
                source_id=payload["source_id"],
                source_type=SourceType(payload["source_type"]),
                raw_id=payload["raw_id"],
                raw_data=payload["raw_data"],
                metadata=payload.get("metadata", {}),
                fetched_at=payload.get("fetched_at", time.time()),
            )
        except Exception as exc:
            logger.warning("redis_dequeue_failed err=%s; fallback", exc)
            self._redis = None
            return self._mem_dequeue(timeout_s)

    @staticmethod
    def _try_connect_redis():
        try:
            import redis as redis_lib
            host = os.environ.get("REDIS_HOST", "localhost")
            port = int(os.environ.get("REDIS_PORT", 6379))
            db   = int(os.environ.get("REDIS_INGESTION_DB", 1))
            r = redis_lib.Redis(host=host, port=port, db=db, socket_timeout=2)
            r.ping()
            logger.info("ingestion_queue redis_connected host=%s port=%d", host, port)
            return r
        except Exception as exc:
            logger.info("ingestion_queue redis_unavailable: %s; using in-memory queue", exc)
            return None


# ─────────────────────────────────────────────
# Ingestion Pipeline Metrics
# ─────────────────────────────────────────────

@dataclass
class IngestionMetrics:
    total_fetched:      int = 0
    total_enqueued:     int = 0
    total_deduplicated: int = 0
    total_normalized:   int = 0
    total_stored:       int = 0
    total_errors:       int = 0
    source_metrics:     Dict[str, Dict[str, Any]] = field(default_factory=lambda: defaultdict(dict))
    start_time:         float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time
        return {
            "total_fetched":      self.total_fetched,
            "total_enqueued":     self.total_enqueued,
            "total_deduplicated": self.total_deduplicated,
            "total_normalized":   self.total_normalized,
            "total_stored":       self.total_stored,
            "total_errors":       self.total_errors,
            "throughput_per_min": round(self.total_normalized / (uptime / 60), 2) if uptime > 0 else 0,
            "uptime_s":           round(uptime, 1),
            "source_metrics":     dict(self.source_metrics),
        }


# ─────────────────────────────────────────────
# Main Ingestion Engine
# ─────────────────────────────────────────────

class IngestionEngine:
    """
    Central orchestrator for the threat intelligence ingestion pipeline.

    Usage:
        engine = IngestionEngine(config={...})
        engine.start()
        # ... running in background threads ...
        engine.stop()
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config     = config or {}
        self._lock       = threading.Lock()
        self._running    = False
        self._threads: List[threading.Thread] = []

        # Core components
        self._queue      = IngestionQueue(
            max_depth=self._config.get("queue_max_depth", _QUEUE_MAX_DEPTH)
        )
        self._deduplicator = Deduplicator(
            ttl_s=self._config.get("dedup_ttl_s", 86400),
        )
        self._normalizer = Normalizer()
        self._metrics    = IngestionMetrics()

        # Downstream storage callback — injected by orchestrator
        self._on_intel_item: Optional[Callable[[IntelItem], None]] = None

        # Build source pool
        self._sources: Dict[str, Any] = {}
        self._schedules: Dict[str, SourceSchedule] = {}
        self._init_sources()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True

        logger.info("ingestion_engine starting workers=%d", _WORKER_THREADS)

        # Scheduler thread
        sched_thread = threading.Thread(
            target=self._scheduler_loop, name="ingestion-scheduler", daemon=True
        )
        sched_thread.start()
        self._threads.append(sched_thread)

        # Worker threads (consumer pool)
        for i in range(_WORKER_THREADS):
            t = threading.Thread(
                target=self._worker_loop, name=f"ingestion-worker-{i}", daemon=True
            )
            t.start()
            self._threads.append(t)

        # Heartbeat / persist thread
        hb_thread = threading.Thread(
            target=self._heartbeat_loop, name="ingestion-heartbeat", daemon=True
        )
        hb_thread.start()
        self._threads.append(hb_thread)

        logger.info("ingestion_engine started")

    def stop(self) -> None:
        logger.info("ingestion_engine stopping")
        with self._lock:
            self._running = False
        self._deduplicator.persist()

    def set_intel_callback(self, callback: Callable[[IntelItem], None]) -> None:
        """Register callback for processed IntelItems (downstream storage/enrichment)."""
        self._on_intel_item = callback

    # ── Manual triggers ───────────────────────────────────────────────────────

    def trigger_source(self, source_id: str, **kwargs) -> Dict[str, Any]:
        """Manually trigger a source fetch. Returns fetch summary."""
        source = self._sources.get(source_id)
        if not source:
            return {"error": f"Unknown source: {source_id}"}

        logger.info("manual_trigger source=%s", source_id)
        t0 = time.time()
        try:
            result: FetchResult = source.fetch(**kwargs)
            enqueued = self._handle_fetch_result(result)
            return {
                "source_id": source_id,
                "status":    result.status.value,
                "fetched":   result.items_count,
                "enqueued":  enqueued,
                "duration_s": round(time.time() - t0, 3),
            }
        except Exception as exc:
            logger.error("manual_trigger_failed source=%s err=%s", source_id, exc)
            return {"source_id": source_id, "error": str(exc)}

    def trigger_all(self) -> Dict[str, Any]:
        """Trigger all enabled sources immediately."""
        results = {}
        for source_id in self._sources:
            results[source_id] = self.trigger_source(source_id)
        return results

    # ── Status and metrics ────────────────────────────────────────────────────

    def status(self) -> Dict[str, Any]:
        return {
            "running":    self._running,
            "sources":    {sid: s.health() for sid, s in self._sources.items()},
            "schedules":  {
                sid: {
                    "enabled":    sch.enabled,
                    "interval_s": sch.interval_s,
                    "last_run":   sch.last_run_ts,
                    "next_run":   sch.next_run_ts,
                    "failures":   sch.consecutive_failures,
                }
                for sid, sch in self._schedules.items()
            },
            "queue":      self._queue.stats(),
            "dedup":      self._deduplicator.stats(),
            "metrics":    self._metrics.to_dict(),
        }

    # ── Background loops ──────────────────────────────────────────────────────

    def _scheduler_loop(self) -> None:
        """Checks schedules and dispatches fetch tasks to worker threads."""
        while self._running:
            try:
                # Sort by priority then due time
                due_sources = sorted(
                    [
                        (sid, sch) for sid, sch in self._schedules.items()
                        if sch.is_due()
                    ],
                    key=lambda x: (x[1].priority, x[1].next_run_ts),
                )
                for source_id, schedule in due_sources:
                    threading.Thread(
                        target=self._fetch_and_enqueue,
                        args=(source_id,),
                        daemon=True,
                    ).start()
                    schedule.next_run_ts = time.time() + schedule.interval_s  # optimistic advance

            except Exception as exc:
                logger.error("scheduler_error err=%s", exc, exc_info=True)

            time.sleep(10)

    def _worker_loop(self) -> None:
        """Consumes items from queue → dedup → normalize → store."""
        while self._running:
            try:
                item = self._queue.dequeue(timeout_s=2.0)
                if item is None:
                    continue
                self._process_item(item)
            except Exception as exc:
                logger.error("worker_error err=%s", exc, exc_info=True)
                self._metrics.total_errors += 1

    def _heartbeat_loop(self) -> None:
        """Periodic health logging and cache persistence."""
        while self._running:
            time.sleep(_HEARTBEAT_INTERVAL)
            try:
                self._deduplicator.persist()
                m = self._metrics.to_dict()
                logger.info(
                    "ingestion_heartbeat fetched=%d normalized=%d stored=%d "
                    "queue_depth=%d dedup_hit_rate=%.3f throughput=%.1f/min",
                    m["total_fetched"], m["total_normalized"], m["total_stored"],
                    self._queue.depth(),
                    self._deduplicator.stats()["hit_rate"],
                    m["throughput_per_min"],
                )
            except Exception as exc:
                logger.warning("heartbeat_error err=%s", exc)

    # ── Fetch and processing ──────────────────────────────────────────────────

    def _fetch_and_enqueue(self, source_id: str) -> None:
        source   = self._sources.get(source_id)
        schedule = self._schedules.get(source_id)
        if not source or not schedule:
            return

        try:
            result = source.fetch()
            if result.status in (FetchStatus.NETWORK_ERROR, FetchStatus.TIMEOUT,
                                  FetchStatus.AUTH_FAILURE):
                schedule.mark_failure()
                self._metrics.total_errors += 1
                self._metrics.source_metrics[source_id]["last_error"] = result.error
            else:
                schedule.mark_success()
                enqueued = self._handle_fetch_result(result)
                self._metrics.source_metrics[source_id] = {
                    "last_fetch": time.time(),
                    "status":     result.status.value,
                    "fetched":    result.items_count,
                    "enqueued":   enqueued,
                    "duration_s": result.duration_s,
                }

        except Exception as exc:
            schedule.mark_failure()
            self._metrics.total_errors += 1
            logger.error("fetch_task_error source=%s err=%s", source_id, exc, exc_info=True)

    def _handle_fetch_result(self, result: FetchResult) -> int:
        """Enqueue all items from a fetch result. Returns count enqueued."""
        enqueued = 0
        for item in result.items:
            self._metrics.total_fetched += 1
            if self._queue.enqueue(item):
                self._metrics.total_enqueued += 1
                enqueued += 1
        return enqueued

    def _process_item(self, item: RawIntelItem) -> None:
        """Dedup → normalize → store pipeline for a single item."""
        # Level 1: deduplication
        if self._deduplicator.is_duplicate(item):
            self._metrics.total_deduplicated += 1
            return

        # Level 2: normalization
        normalized = self._normalizer.normalize(item)
        if not normalized:
            self._metrics.total_errors += 1
            return

        self._metrics.total_normalized += 1

        # Level 3: downstream delivery
        if self._on_intel_item:
            try:
                self._on_intel_item(normalized)
                self._metrics.total_stored += 1
            except Exception as exc:
                logger.error("store_callback_error intel_id=%s err=%s",
                             normalized.intel_id, exc)
                self._metrics.total_errors += 1

    # ── Source initialization ─────────────────────────────────────────────────

    def _init_sources(self) -> None:
        source_cfg = self._config.get("sources", {})

        # NVD
        nvd_cfg = source_cfg.get("nvd", {})
        if nvd_cfg.get("enabled", True):
            self._sources["nvd_cve"] = NVDSource(nvd_cfg)
            self._schedules["nvd_cve"] = SourceSchedule(
                source_id="nvd_cve",
                interval_s=nvd_cfg.get("interval_s", 3600),    # hourly
                priority=2,
            )

        # CISA KEV
        kev_cfg = source_cfg.get("kev", {})
        if kev_cfg.get("enabled", True):
            self._sources["cisa_kev"] = KEVSource(kev_cfg)
            self._schedules["cisa_kev"] = SourceSchedule(
                source_id="cisa_kev",
                interval_s=kev_cfg.get("interval_s", 1800),    # 30 min
                priority=1,   # highest priority — CISA mandates
            )

        # MalwareBazaar
        mb_cfg = source_cfg.get("malwarebazaar", {})
        if mb_cfg.get("enabled", True):
            self._sources["malwarebazaar"] = MalwareBazaarSource(mb_cfg)
            self._schedules["malwarebazaar"] = SourceSchedule(
                source_id="malwarebazaar",
                interval_s=mb_cfg.get("interval_s", 900),      # 15 min
                priority=3,
            )

        # AbuseIPDB
        ai_cfg = source_cfg.get("abuseipdb", {})
        if ai_cfg.get("enabled", True):
            self._sources["abuseipdb"] = AbuseIPDBSource(ai_cfg)
            self._schedules["abuseipdb"] = SourceSchedule(
                source_id="abuseipdb",
                interval_s=ai_cfg.get("interval_s", 3600),     # hourly
                priority=4,
            )

        logger.info("ingestion_sources_registered count=%d sources=%s",
                    len(self._sources), list(self._sources.keys()))


# ─────────────────────────────────────────────
# Module Singleton + FastAPI Router
# ─────────────────────────────────────────────

# Singleton engine (lazy init)
_engine_instance: Optional[IngestionEngine] = None
_engine_lock = threading.Lock()


def get_engine(config: Optional[Dict[str, Any]] = None) -> IngestionEngine:
    """Get or create the singleton IngestionEngine."""
    global _engine_instance
    with _engine_lock:
        if _engine_instance is None:
            _engine_instance = IngestionEngine(config)
        return _engine_instance


# ── FastAPI Router ─────────────────────────────────────────────────────────

try:
    from fastapi import APIRouter, HTTPException, Depends, Header
    from pydantic import BaseModel

    ingestion_router = APIRouter(prefix="/api/v1/ingestion", tags=["Ingestion"])

    class TriggerRequest(BaseModel):
        source_id: str = "all"
        kwargs: Dict[str, Any] = {}

    def _get_engine() -> IngestionEngine:
        return get_engine()

    @ingestion_router.get("/status")
    async def ingestion_status(engine: IngestionEngine = Depends(_get_engine)):
        """Full pipeline status: sources, queue, dedup, metrics."""
        return engine.status()

    @ingestion_router.get("/metrics")
    async def ingestion_metrics(engine: IngestionEngine = Depends(_get_engine)):
        """Ingestion pipeline metrics only."""
        return engine._metrics.to_dict()

    @ingestion_router.post("/trigger")
    async def trigger_ingestion(
        body: TriggerRequest,
        engine: IngestionEngine = Depends(_get_engine),
    ):
        """Manually trigger a source fetch or all sources."""
        if body.source_id == "all":
            return engine.trigger_all()
        return engine.trigger_source(body.source_id, **body.kwargs)

    @ingestion_router.get("/sources")
    async def list_sources(engine: IngestionEngine = Depends(_get_engine)):
        """List all registered sources with health status."""
        return {
            sid: {**s.health(), "schedule": {
                "enabled":    engine._schedules[sid].enabled,
                "interval_s": engine._schedules[sid].interval_s,
                "next_run_ts": engine._schedules[sid].next_run_ts,
            }}
            for sid, s in engine._sources.items()
            if sid in engine._schedules
        }

    @ingestion_router.get("/queue")
    async def queue_stats(engine: IngestionEngine = Depends(_get_engine)):
        """Queue depth and throughput stats."""
        return engine._queue.stats()

    @ingestion_router.post("/sources/{source_id}/enable")
    async def enable_source(source_id: str, engine: IngestionEngine = Depends(_get_engine)):
        if source_id not in engine._schedules:
            raise HTTPException(404, f"Source '{source_id}' not found")
        engine._schedules[source_id].enabled = True
        engine._schedules[source_id].consecutive_failures = 0
        return {"status": "ok", "source_id": source_id, "enabled": True}

    @ingestion_router.post("/sources/{source_id}/disable")
    async def disable_source(source_id: str, engine: IngestionEngine = Depends(_get_engine)):
        if source_id not in engine._schedules:
            raise HTTPException(404, f"Source '{source_id}' not found")
        engine._schedules[source_id].enabled = False
        return {"status": "ok", "source_id": source_id, "enabled": False}

except ImportError:
    # FastAPI not installed — ingestion_router is None; API still starts without it
    ingestion_router = None  # type: ignore[assignment]
    logger.warning("ingestion_router_unavailable reason='fastapi not installed'")
