"""
CYBERDUDEBIVASH® SENTINEL APEX v27.0 — Streaming Pipeline
===========================================================
Real-time threat ingestion pipeline replacing batch processing.

Features:
- Redis-backed async event queue
- Priority-based processing (critical > high > normal)
- Backpressure handling
- Automatic failover to batch mode
- Delta feed support

Architecture:
    [Feed Sources] → [Ingest Workers] → [Redis Queue] → [Process Workers] → [Storage]
                                              ↓
                                    [Priority Routing]
                                              ↓
                            [Critical] [High] [Normal] [Low]

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable, Awaitable
from enum import Enum
import hashlib
import uuid

logger = logging.getLogger("CDB-Streaming")


class Priority(Enum):
    """Event priority levels"""
    CRITICAL = 0   # Zero-day, active exploitation
    HIGH = 1       # KEV, nation-state
    NORMAL = 2     # Standard CVEs
    LOW = 3        # Informational
    BATCH = 4      # Deferred processing


@dataclass
class StreamEvent:
    """Streaming event wrapper"""
    event_id: str
    event_type: str
    priority: Priority
    payload: Dict[str, Any]
    source: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    retry_count: int = 0
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "priority": self.priority.value,
            "payload": self.payload,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "retry_count": self.retry_count,
            "correlation_id": self.correlation_id,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "StreamEvent":
        return cls(
            event_id=data["event_id"],
            event_type=data["event_type"],
            priority=Priority(data["priority"]),
            payload=data["payload"],
            source=data["source"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            retry_count=data.get("retry_count", 0),
            correlation_id=data.get("correlation_id"),
        )
    
    def serialize(self) -> str:
        return json.dumps(self.to_dict())
    
    @classmethod
    def deserialize(cls, data: str) -> "StreamEvent":
        return cls.from_dict(json.loads(data))


class QueueBackend(ABC):
    """Abstract queue backend interface"""
    
    @abstractmethod
    async def push(self, queue: str, event: StreamEvent) -> bool:
        pass
    
    @abstractmethod
    async def pop(self, queue: str, timeout: int = 0) -> Optional[StreamEvent]:
        pass
    
    @abstractmethod
    async def length(self, queue: str) -> int:
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        pass


class RedisQueueBackend(QueueBackend):
    """Redis-backed queue implementation"""
    
    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        self.redis_url = redis_url
        self._client = None
        self._connected = False
    
    async def _ensure_connection(self):
        """Lazy connection to Redis"""
        if self._client is None:
            try:
                import redis.asyncio as redis
                self._client = redis.from_url(
                    self.redis_url,
                    decode_responses=True,
                    max_connections=20
                )
                self._connected = True
                logger.info(f"Connected to Redis: {self.redis_url}")
            except ImportError:
                logger.warning("redis-py not installed, using in-memory fallback")
                self._client = InMemoryQueueBackend()
            except Exception as e:
                logger.error(f"Redis connection failed: {e}")
                self._client = InMemoryQueueBackend()
    
    async def push(self, queue: str, event: StreamEvent) -> bool:
        await self._ensure_connection()
        try:
            if isinstance(self._client, InMemoryQueueBackend):
                return await self._client.push(queue, event)
            await self._client.lpush(queue, event.serialize())
            return True
        except Exception as e:
            logger.error(f"Queue push failed: {e}")
            return False
    
    async def pop(self, queue: str, timeout: int = 0) -> Optional[StreamEvent]:
        await self._ensure_connection()
        try:
            if isinstance(self._client, InMemoryQueueBackend):
                return await self._client.pop(queue, timeout)
            
            if timeout > 0:
                result = await self._client.brpop(queue, timeout)
            else:
                result = await self._client.rpop(queue)
            
            if result:
                data = result[1] if isinstance(result, tuple) else result
                return StreamEvent.deserialize(data)
            return None
        except Exception as e:
            logger.error(f"Queue pop failed: {e}")
            return None
    
    async def length(self, queue: str) -> int:
        await self._ensure_connection()
        try:
            if isinstance(self._client, InMemoryQueueBackend):
                return await self._client.length(queue)
            return await self._client.llen(queue)
        except Exception:
            return 0
    
    async def health_check(self) -> bool:
        await self._ensure_connection()
        try:
            if isinstance(self._client, InMemoryQueueBackend):
                return True
            await self._client.ping()
            return True
        except Exception:
            return False


class InMemoryQueueBackend(QueueBackend):
    """In-memory queue for testing and fallback"""
    
    def __init__(self):
        self._queues: Dict[str, List[StreamEvent]] = {}
        self._lock = asyncio.Lock()
    
    async def push(self, queue: str, event: StreamEvent) -> bool:
        async with self._lock:
            if queue not in self._queues:
                self._queues[queue] = []
            self._queues[queue].insert(0, event)
            return True
    
    async def pop(self, queue: str, timeout: int = 0) -> Optional[StreamEvent]:
        async with self._lock:
            if queue in self._queues and self._queues[queue]:
                return self._queues[queue].pop()
            return None
    
    async def length(self, queue: str) -> int:
        return len(self._queues.get(queue, []))
    
    async def health_check(self) -> bool:
        return True


class StreamingPipeline:
    """
    Real-time streaming pipeline for threat intelligence.
    
    Features:
    - Priority-based routing
    - Backpressure handling
    - Automatic retry with exponential backoff
    - Delta feed support
    - Graceful degradation to batch mode
    """
    
    QUEUE_NAMES = {
        Priority.CRITICAL: "sentinel:queue:critical",
        Priority.HIGH: "sentinel:queue:high",
        Priority.NORMAL: "sentinel:queue:normal",
        Priority.LOW: "sentinel:queue:low",
        Priority.BATCH: "sentinel:queue:batch",
    }
    
    def __init__(
        self,
        backend: Optional[QueueBackend] = None,
        max_queue_size: int = 10000,
        max_retries: int = 3,
    ):
        self.backend = backend or InMemoryQueueBackend()
        self.max_queue_size = max_queue_size
        self.max_retries = max_retries
        self._handlers: Dict[str, Callable] = {}
        self._running = False
        self._stats = {
            "events_received": 0,
            "events_processed": 0,
            "events_failed": 0,
            "backpressure_events": 0,
        }
    
    async def start(self):
        """Start the pipeline"""
        self._running = True
        logger.info("Streaming pipeline started")
    
    async def stop(self):
        """Stop the pipeline gracefully"""
        self._running = False
        logger.info("Streaming pipeline stopped")
    
    def register_handler(
        self,
        event_type: str,
        handler: Callable[[StreamEvent], Awaitable[bool]]
    ):
        """Register an event handler"""
        self._handlers[event_type] = handler
        logger.info(f"Registered handler for: {event_type}")
    
    async def ingest(
        self,
        event_type: str,
        payload: Dict[str, Any],
        source: str,
        priority: Optional[Priority] = None,
        correlation_id: Optional[str] = None,
    ) -> str:
        """
        Ingest an event into the pipeline.
        
        Returns:
            Event ID for tracking
        """
        # Auto-detect priority if not specified
        if priority is None:
            priority = self._detect_priority(payload)
        
        # Create event
        event = StreamEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            priority=priority,
            payload=payload,
            source=source,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )
        
        # Check backpressure
        queue_name = self.QUEUE_NAMES[priority]
        queue_len = await self.backend.length(queue_name)
        
        if queue_len >= self.max_queue_size:
            self._stats["backpressure_events"] += 1
            # Downgrade to batch queue
            queue_name = self.QUEUE_NAMES[Priority.BATCH]
            event.priority = Priority.BATCH
            logger.warning(f"Backpressure: downgraded event {event.event_id} to batch")
        
        # Push to queue
        success = await self.backend.push(queue_name, event)
        if success:
            self._stats["events_received"] += 1
            logger.debug(f"Ingested event: {event.event_id} [{priority.name}]")
        
        return event.event_id
    
    async def process_one(self, priority: Priority, timeout: int = 5) -> bool:
        """
        Process one event from the specified priority queue.
        
        Returns:
            True if an event was processed
        """
        queue_name = self.QUEUE_NAMES[priority]
        event = await self.backend.pop(queue_name, timeout)
        
        if not event:
            return False
        
        handler = self._handlers.get(event.event_type)
        if not handler:
            logger.warning(f"No handler for event type: {event.event_type}")
            return False
        
        try:
            success = await handler(event)
            if success:
                self._stats["events_processed"] += 1
                return True
            else:
                return await self._handle_failure(event)
        except Exception as e:
            logger.error(f"Handler error for {event.event_id}: {e}")
            return await self._handle_failure(event)
    
    async def _handle_failure(self, event: StreamEvent) -> bool:
        """Handle failed event with retry logic"""
        event.retry_count += 1
        
        if event.retry_count >= self.max_retries:
            self._stats["events_failed"] += 1
            logger.error(f"Event {event.event_id} failed after {self.max_retries} retries")
            # TODO: Send to dead letter queue
            return False
        
        # Exponential backoff - push back with lower priority
        next_priority = Priority(min(event.priority.value + 1, Priority.BATCH.value))
        queue_name = self.QUEUE_NAMES[next_priority]
        
        await asyncio.sleep(2 ** event.retry_count)  # Backoff
        await self.backend.push(queue_name, event)
        
        return False
    
    def _detect_priority(self, payload: Dict) -> Priority:
        """Auto-detect event priority from payload"""
        # Check for critical indicators
        if payload.get("zero_day") or payload.get("active_exploitation"):
            return Priority.CRITICAL
        
        if payload.get("kev") or payload.get("nation_state"):
            return Priority.HIGH
        
        cvss = payload.get("cvss_score", 0)
        if cvss >= 9.0:
            return Priority.CRITICAL
        elif cvss >= 7.0:
            return Priority.HIGH
        elif cvss >= 4.0:
            return Priority.NORMAL
        
        return Priority.LOW
    
    async def run_worker(self, priorities: Optional[List[Priority]] = None):
        """
        Run a worker loop processing events.
        
        Processes queues in priority order (critical first).
        """
        if priorities is None:
            priorities = [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]
        
        logger.info(f"Worker started for priorities: {[p.name for p in priorities]}")
        
        while self._running:
            processed = False
            
            for priority in priorities:
                if await self.process_one(priority, timeout=1):
                    processed = True
                    break  # Process next critical first
            
            if not processed:
                await asyncio.sleep(0.1)  # Small delay when idle
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics"""
        return {
            **self._stats,
            "running": self._running,
            "handlers": list(self._handlers.keys()),
        }
    
    async def get_queue_depths(self) -> Dict[str, int]:
        """Get current queue depths"""
        depths = {}
        for priority, queue_name in self.QUEUE_NAMES.items():
            depths[priority.name] = await self.backend.length(queue_name)
        return depths


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
_pipeline: Optional[StreamingPipeline] = None


def get_pipeline(redis_url: Optional[str] = None) -> StreamingPipeline:
    """Get or create the global streaming pipeline"""
    global _pipeline
    if _pipeline is None:
        if redis_url:
            backend = RedisQueueBackend(redis_url)
        else:
            backend = InMemoryQueueBackend()
        _pipeline = StreamingPipeline(backend=backend)
    return _pipeline


# ══════════════════════════════════════════════════════════════════════════════
# EXPORTS
# ══════════════════════════════════════════════════════════════════════════════
__all__ = [
    "StreamingPipeline",
    "StreamEvent",
    "Priority",
    "QueueBackend",
    "RedisQueueBackend",
    "InMemoryQueueBackend",
    "get_pipeline",
]
