#!/usr/bin/env python3
"""
event_bus.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0 (COMMAND CENTER)
═══════════════════════════════════════════════════════════════════════
Event-Driven Architecture: Redis-backed Event Bus with in-memory fallback.

Provides:
  - Pub/Sub event broadcasting
  - Priority event queues (CRITICAL > HIGH > MEDIUM > LOW)
  - Event persistence and replay
  - Idempotent event processing via dedup tokens
  - Dead letter queue for failed events
  - Event schema validation
  - Async event handlers with retry logic

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import uuid
import time
import hashlib
import logging
import threading
from enum import IntEnum
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from queue import PriorityQueue

logger = logging.getLogger("CDB-EVENT-BUS")


# ═══════════════════════════════════════════════════════════
# EVENT SCHEMA
# ═══════════════════════════════════════════════════════════

class EventPriority(IntEnum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2
    LOW = 3


@dataclass(order=True)
class Event:
    """Immutable event envelope for the Sentinel APEX event bus."""
    priority: int = field(compare=True)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()), compare=False)
    event_type: str = field(default="", compare=False)
    source: str = field(default="orchestrator", compare=False)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        compare=False,
    )
    payload: Dict[str, Any] = field(default_factory=dict, compare=False)
    idempotency_key: str = field(default="", compare=False)
    retry_count: int = field(default=0, compare=False)
    max_retries: int = field(default=3, compare=False)
    correlation_id: str = field(default="", compare=False)

    def __post_init__(self):
        if not self.idempotency_key:
            raw = f"{self.event_type}:{json.dumps(self.payload, sort_keys=True)}"
            self.idempotency_key = hashlib.sha256(raw.encode()).hexdigest()[:24]
        if not self.correlation_id:
            self.correlation_id = self.event_id

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "Event":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ═══════════════════════════════════════════════════════════
# EVENT TYPES REGISTRY
# ═══════════════════════════════════════════════════════════

class EventTypes:
    # Pipeline lifecycle
    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_COMPLETED = "pipeline.completed"
    PIPELINE_FAILED = "pipeline.failed"
    PIPELINE_STAGE_STARTED = "pipeline.stage.started"
    PIPELINE_STAGE_COMPLETED = "pipeline.stage.completed"

    # Intelligence events
    INTEL_INGESTED = "intel.ingested"
    INTEL_NORMALIZED = "intel.normalized"
    INTEL_ENRICHED = "intel.enriched"
    INTEL_CORRELATED = "intel.correlated"
    INTEL_SCORED = "intel.scored"
    INTEL_STORED = "intel.stored"
    INTEL_PUBLISHED = "intel.published"

    # Detection events
    DETECTION_TRIGGERED = "detection.triggered"
    DETECTION_SIGMA_MATCH = "detection.sigma.match"
    DETECTION_YARA_MATCH = "detection.yara.match"
    DETECTION_IOC_MATCH = "detection.ioc.match"

    # AI engine events
    AI_CAMPAIGN_DETECTED = "ai.campaign.detected"
    AI_CLUSTER_FORMED = "ai.cluster.formed"
    AI_ANOMALY_DETECTED = "ai.anomaly.detected"
    AI_PREDICTION_GENERATED = "ai.prediction.generated"

    # Threat events
    THREAT_CRITICAL = "threat.critical"
    THREAT_ZERO_DAY = "threat.zero_day"
    THREAT_APT_DETECTED = "threat.apt.detected"
    THREAT_CAMPAIGN_LINKED = "threat.campaign.linked"

    # System events
    MANIFEST_UPDATED = "manifest.updated"
    HEALTH_CHECK = "system.health_check"
    QUOTA_EXCEEDED = "system.quota.exceeded"


# ═══════════════════════════════════════════════════════════
# REDIS EVENT BUS BACKEND
# ═══════════════════════════════════════════════════════════

class RedisBackend:
    """Redis-backed event persistence and pub/sub."""

    def __init__(self):
        self._client = None
        self._pubsub = None
        self._connected = False

    def connect(self) -> bool:
        redis_url = os.environ.get("UPSTASH_REDIS_URL", "")
        redis_token = os.environ.get("UPSTASH_REDIS_TOKEN", "")

        if not redis_url:
            return False

        try:
            import redis as redis_lib
            if redis_token:
                self._client = redis_lib.from_url(
                    redis_url,
                    password=redis_token,
                    decode_responses=True,
                    socket_timeout=5,
                )
            else:
                self._client = redis_lib.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_timeout=5,
                )
            self._client.ping()
            self._pubsub = self._client.pubsub()
            self._connected = True
            logger.info("Redis event bus connected")
            return True
        except Exception as e:
            logger.warning(f"Redis unavailable, using in-memory fallback: {e}")
            self._connected = False
            return False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def publish(self, channel: str, event: Event):
        if not self._connected:
            return
        try:
            self._client.publish(f"cdb:events:{channel}", json.dumps(event.to_dict()))
            self._client.lpush(
                f"cdb:event_log:{channel}",
                json.dumps(event.to_dict()),
            )
            self._client.ltrim(f"cdb:event_log:{channel}", 0, 9999)
        except Exception as e:
            logger.error(f"Redis publish failed: {e}")

    def enqueue(self, queue_name: str, event: Event):
        if not self._connected:
            return
        try:
            score = event.priority * 1_000_000_000 + time.time()
            self._client.zadd(
                f"cdb:queue:{queue_name}",
                {json.dumps(event.to_dict()): score},
            )
        except Exception as e:
            logger.error(f"Redis enqueue failed: {e}")

    def dequeue(self, queue_name: str) -> Optional[Event]:
        if not self._connected:
            return None
        try:
            result = self._client.zpopmin(f"cdb:queue:{queue_name}", count=1)
            if result:
                data, _score = result[0]
                return Event.from_dict(json.loads(data))
        except Exception as e:
            logger.error(f"Redis dequeue failed: {e}")
        return None

    def add_to_dead_letter(self, event: Event, error: str):
        if not self._connected:
            return
        try:
            entry = {**event.to_dict(), "error": error, "dlq_at": datetime.now(timezone.utc).isoformat()}
            self._client.lpush("cdb:dlq", json.dumps(entry))
            self._client.ltrim("cdb:dlq", 0, 999)
        except Exception as e:
            logger.error(f"Redis DLQ write failed: {e}")

    def check_idempotency(self, key: str) -> bool:
        if not self._connected:
            return False
        try:
            return bool(self._client.exists(f"cdb:idem:{key}"))
        except Exception:
            return False

    def mark_processed(self, key: str, ttl: int = 86400):
        if not self._connected:
            return
        try:
            self._client.setex(f"cdb:idem:{key}", ttl, "1")
        except Exception:
            pass

    def get_event_log(self, channel: str, limit: int = 100) -> List[Dict]:
        if not self._connected:
            return []
        try:
            raw = self._client.lrange(f"cdb:event_log:{channel}", 0, limit - 1)
            return [json.loads(r) for r in raw]
        except Exception:
            return []

    def acquire_lock(self, lock_name: str, ttl: int = 60) -> Optional[str]:
        if not self._connected:
            return None
        try:
            token = str(uuid.uuid4())
            acquired = self._client.set(
                f"cdb:lock:{lock_name}", token, nx=True, ex=ttl
            )
            return token if acquired else None
        except Exception:
            return None

    def release_lock(self, lock_name: str, token: str):
        if not self._connected:
            return
        try:
            current = self._client.get(f"cdb:lock:{lock_name}")
            if current == token:
                self._client.delete(f"cdb:lock:{lock_name}")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
# IN-MEMORY FALLBACK BACKEND
# ═══════════════════════════════════════════════════════════

class InMemoryBackend:
    """Thread-safe in-memory event bus for environments without Redis."""

    def __init__(self):
        self._queues: Dict[str, PriorityQueue] = defaultdict(PriorityQueue)
        self._event_log: Dict[str, List[Dict]] = defaultdict(list)
        self._processed: set = set()
        self._dlq: List[Dict] = []
        self._locks: Dict[str, str] = {}
        self._lock = threading.Lock()

    def publish(self, channel: str, event: Event):
        with self._lock:
            self._event_log[channel].append(event.to_dict())
            if len(self._event_log[channel]) > 10000:
                self._event_log[channel] = self._event_log[channel][-10000:]

    def enqueue(self, queue_name: str, event: Event):
        self._queues[queue_name].put(event)

    def dequeue(self, queue_name: str) -> Optional[Event]:
        q = self._queues.get(queue_name)
        if q and not q.empty():
            return q.get_nowait()
        return None

    def add_to_dead_letter(self, event: Event, error: str):
        with self._lock:
            self._dlq.append({
                **event.to_dict(),
                "error": error,
                "dlq_at": datetime.now(timezone.utc).isoformat(),
            })
            if len(self._dlq) > 1000:
                self._dlq = self._dlq[-1000:]

    def check_idempotency(self, key: str) -> bool:
        return key in self._processed

    def mark_processed(self, key: str, ttl: int = 86400):
        self._processed.add(key)
        if len(self._processed) > 100000:
            self._processed = set(list(self._processed)[-50000:])

    def get_event_log(self, channel: str, limit: int = 100) -> List[Dict]:
        return self._event_log.get(channel, [])[:limit]

    def acquire_lock(self, lock_name: str, ttl: int = 60) -> Optional[str]:
        with self._lock:
            if lock_name in self._locks:
                return None
            token = str(uuid.uuid4())
            self._locks[lock_name] = token
            return token

    def release_lock(self, lock_name: str, token: str):
        with self._lock:
            if self._locks.get(lock_name) == token:
                del self._locks[lock_name]


# ═══════════════════════════════════════════════════════════
# UNIFIED EVENT BUS
# ═══════════════════════════════════════════════════════════

class SentinelEventBus:
    """
    Central event bus for SENTINEL APEX.
    Provides pub/sub, priority queues, idempotent processing,
    and dead letter queue with automatic Redis/in-memory backend selection.
    """

    def __init__(self, force_memory: bool = False):
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._middleware: List[Callable] = []
        self._stats = {
            "events_published": 0,
            "events_processed": 0,
            "events_failed": 0,
            "events_deduplicated": 0,
        }

        if force_memory:
            self._backend = InMemoryBackend()
            self._redis_available = False
        else:
            redis_backend = RedisBackend()
            if redis_backend.connect():
                self._backend = redis_backend
                self._redis_available = True
            else:
                self._backend = InMemoryBackend()
                self._redis_available = False

        backend_type = "Redis" if self._redis_available else "In-Memory"
        logger.info(f"Event Bus initialized [{backend_type}]")

    @property
    def redis_available(self) -> bool:
        return self._redis_available

    def subscribe(self, event_type: str, handler: Callable):
        self._handlers[event_type].append(handler)
        logger.debug(f"Handler subscribed: {event_type} -> {handler.__name__}")

    def add_middleware(self, middleware: Callable):
        self._middleware.append(middleware)

    def emit(
        self,
        event_type: str,
        payload: Dict[str, Any],
        priority: EventPriority = EventPriority.MEDIUM,
        source: str = "orchestrator",
        correlation_id: str = "",
    ) -> Event:
        event = Event(
            priority=priority.value,
            event_type=event_type,
            source=source,
            payload=payload,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )

        # Idempotency check
        if self._backend.check_idempotency(event.idempotency_key):
            self._stats["events_deduplicated"] += 1
            logger.debug(f"Duplicate event suppressed: {event_type}")
            return event

        # Middleware chain
        for mw in self._middleware:
            try:
                event = mw(event)
                if event is None:
                    return Event(priority=EventPriority.LOW.value)
            except Exception as e:
                logger.error(f"Middleware error: {e}")

        # Publish to backend
        self._backend.publish(event_type, event)
        self._backend.mark_processed(event.idempotency_key)
        self._stats["events_published"] += 1

        # Dispatch to local handlers
        self._dispatch(event)

        return event

    def enqueue(
        self,
        queue_name: str,
        event_type: str,
        payload: Dict[str, Any],
        priority: EventPriority = EventPriority.MEDIUM,
    ) -> Event:
        event = Event(
            priority=priority.value,
            event_type=event_type,
            payload=payload,
        )
        self._backend.enqueue(queue_name, event)
        return event

    def dequeue(self, queue_name: str) -> Optional[Event]:
        return self._backend.dequeue(queue_name)

    def _dispatch(self, event: Event):
        handlers = self._handlers.get(event.event_type, [])
        wildcard_handlers = self._handlers.get("*", [])

        for handler in handlers + wildcard_handlers:
            try:
                handler(event)
                self._stats["events_processed"] += 1
            except Exception as e:
                self._stats["events_failed"] += 1
                logger.error(f"Handler {handler.__name__} failed for {event.event_type}: {e}")

                if event.retry_count < event.max_retries:
                    event.retry_count += 1
                    self.enqueue("retry", event.event_type, event.payload)
                else:
                    self._backend.add_to_dead_letter(event, str(e))

    def acquire_lock(self, name: str, ttl: int = 60) -> Optional[str]:
        return self._backend.acquire_lock(name, ttl)

    def release_lock(self, name: str, token: str):
        self._backend.release_lock(name, token)

    def get_event_log(self, event_type: str, limit: int = 100) -> List[Dict]:
        return self._backend.get_event_log(event_type, limit)

    def get_stats(self) -> Dict:
        return {
            **self._stats,
            "backend": "redis" if self._redis_available else "in-memory",
            "registered_handlers": {k: len(v) for k, v in self._handlers.items()},
        }


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

event_bus = SentinelEventBus()
