"""
SENTINEL APEX v27.0 — Queue Management
=======================================
Priority queue and dead letter queue management.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from enum import Enum

from .pipeline import StreamEvent, Priority

logger = logging.getLogger("CDB-Queues")


@dataclass
class QueueStats:
    """Statistics for a single queue"""
    name: str
    depth: int
    processed: int
    failed: int
    avg_latency_ms: float
    last_activity: Optional[datetime] = None


class PriorityQueue:
    """
    Priority-aware queue with backpressure handling.
    """
    
    def __init__(
        self,
        name: str,
        priority: Priority,
        max_size: int = 10000,
    ):
        self.name = name
        self.priority = priority
        self.max_size = max_size
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_size)
        self._processed = 0
        self._failed = 0
        self._latencies: List[float] = []
        self._last_activity: Optional[datetime] = None
    
    async def put(self, event: StreamEvent, timeout: float = 5.0) -> bool:
        """Add event to queue with timeout"""
        try:
            await asyncio.wait_for(
                self._queue.put(event),
                timeout=timeout
            )
            self._last_activity = datetime.now(timezone.utc)
            return True
        except asyncio.TimeoutError:
            logger.warning(f"Queue {self.name} full, event dropped")
            return False
    
    async def get(self, timeout: float = 5.0) -> Optional[StreamEvent]:
        """Get event from queue with timeout"""
        try:
            event = await asyncio.wait_for(
                self._queue.get(),
                timeout=timeout
            )
            self._last_activity = datetime.now(timezone.utc)
            return event
        except asyncio.TimeoutError:
            return None
    
    def mark_processed(self, latency_ms: float = 0):
        """Mark an event as successfully processed"""
        self._processed += 1
        if latency_ms > 0:
            self._latencies.append(latency_ms)
            # Keep only last 100 latencies
            if len(self._latencies) > 100:
                self._latencies = self._latencies[-100:]
    
    def mark_failed(self):
        """Mark an event as failed"""
        self._failed += 1
    
    @property
    def depth(self) -> int:
        return self._queue.qsize()
    
    @property
    def is_full(self) -> bool:
        return self._queue.full()
    
    @property
    def is_empty(self) -> bool:
        return self._queue.empty()
    
    def get_stats(self) -> QueueStats:
        avg_latency = sum(self._latencies) / len(self._latencies) if self._latencies else 0
        return QueueStats(
            name=self.name,
            depth=self.depth,
            processed=self._processed,
            failed=self._failed,
            avg_latency_ms=round(avg_latency, 2),
            last_activity=self._last_activity,
        )


class DeadLetterQueue:
    """
    Dead letter queue for failed events.
    """
    
    def __init__(self, name: str = "dlq", max_size: int = 1000):
        self.name = name
        self.max_size = max_size
        self._events: List[Dict[str, Any]] = []
    
    def add(self, event: StreamEvent, error: str):
        """Add failed event to DLQ"""
        dlq_entry = {
            "event": event.to_dict(),
            "error": error,
            "failed_at": datetime.now(timezone.utc).isoformat(),
        }
        
        self._events.append(dlq_entry)
        
        # Trim if over max size
        if len(self._events) > self.max_size:
            self._events = self._events[-self.max_size:]
        
        logger.warning(f"Event {event.event_id} sent to DLQ: {error}")
    
    def get_all(self) -> List[Dict]:
        """Get all DLQ entries"""
        return self._events.copy()
    
    def clear(self):
        """Clear the DLQ"""
        count = len(self._events)
        self._events.clear()
        logger.info(f"DLQ cleared: {count} events removed")
    
    def reprocess(self, event_id: str) -> Optional[StreamEvent]:
        """Remove and return an event for reprocessing"""
        for i, entry in enumerate(self._events):
            if entry["event"]["event_id"] == event_id:
                removed = self._events.pop(i)
                return StreamEvent.from_dict(removed["event"])
        return None
    
    @property
    def depth(self) -> int:
        return len(self._events)


class QueueManager:
    """
    Manages multiple priority queues.
    """
    
    def __init__(self, max_queue_size: int = 10000):
        self.max_queue_size = max_queue_size
        self._queues: Dict[Priority, PriorityQueue] = {}
        self._dlq = DeadLetterQueue()
        
        # Initialize priority queues
        for priority in Priority:
            self._queues[priority] = PriorityQueue(
                name=f"queue:{priority.name.lower()}",
                priority=priority,
                max_size=max_queue_size,
            )
    
    def get_queue(self, priority: Priority) -> PriorityQueue:
        """Get queue for priority level"""
        return self._queues[priority]
    
    @property
    def dlq(self) -> DeadLetterQueue:
        """Get dead letter queue"""
        return self._dlq
    
    async def route_event(self, event: StreamEvent) -> bool:
        """Route event to appropriate queue"""
        queue = self._queues.get(event.priority)
        if not queue:
            logger.error(f"No queue for priority: {event.priority}")
            return False
        
        # Check for backpressure
        if queue.is_full:
            # Try to downgrade priority
            for fallback_priority in [Priority.LOW, Priority.BATCH]:
                fallback_queue = self._queues.get(fallback_priority)
                if fallback_queue and not fallback_queue.is_full:
                    event.priority = fallback_priority
                    return await fallback_queue.put(event)
            
            # All queues full - send to DLQ
            self._dlq.add(event, "All queues full")
            return False
        
        return await queue.put(event)
    
    async def get_next(self) -> Optional[StreamEvent]:
        """Get next event, prioritizing critical"""
        for priority in [Priority.CRITICAL, Priority.HIGH, Priority.NORMAL, Priority.LOW]:
            queue = self._queues[priority]
            if not queue.is_empty:
                return await queue.get(timeout=0.1)
        return None
    
    def get_all_stats(self) -> Dict[str, Any]:
        """Get statistics for all queues"""
        return {
            "queues": {
                p.name: q.get_stats().__dict__
                for p, q in self._queues.items()
            },
            "dlq": {
                "depth": self._dlq.depth,
            },
            "total_depth": sum(q.depth for q in self._queues.values()),
        }


__all__ = [
    "PriorityQueue",
    "DeadLetterQueue",
    "QueueManager",
    "QueueStats",
]
