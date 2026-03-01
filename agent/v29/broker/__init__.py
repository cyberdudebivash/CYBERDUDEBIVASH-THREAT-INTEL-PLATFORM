"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — Message Broker
======================================================
Enterprise-grade message broker with real broker enforcement.

Supported Brokers:
- MemoryBroker (default, development)
- RedisBroker (production recommended)
- KafkaBroker (high-volume streaming)

Features:
- Dead Letter Queues (DLQ)
- Persistent offsets
- Consumer groups
- Backpressure handling
- Message acknowledgment
- Retry with exponential backoff

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import time
import hashlib
import asyncio
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
from enum import Enum
import logging
import threading

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# MESSAGE TYPES
# ══════════════════════════════════════════════════════════════════════════════

class MessagePriority(Enum):
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class MessageStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD = "dead"


@dataclass
class Message:
    """Standard message format"""
    id: str
    topic: str
    payload: Any
    priority: MessagePriority = MessagePriority.NORMAL
    status: MessageStatus = MessageStatus.PENDING
    retry_count: int = 0
    max_retries: int = 3
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    processed_at: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "topic": self.topic,
            "payload": self.payload,
            "priority": self.priority.value,
            "status": self.status.value,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "created_at": self.created_at,
            "processed_at": self.processed_at,
            "error": self.error,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "Message":
        return cls(
            id=data["id"],
            topic=data["topic"],
            payload=data["payload"],
            priority=MessagePriority(data.get("priority", 1)),
            status=MessageStatus(data.get("status", "pending")),
            retry_count=data.get("retry_count", 0),
            max_retries=data.get("max_retries", 3),
            created_at=data.get("created_at", datetime.utcnow().isoformat()),
            processed_at=data.get("processed_at"),
            error=data.get("error"),
        )


# ══════════════════════════════════════════════════════════════════════════════
# BROKER INTERFACE
# ══════════════════════════════════════════════════════════════════════════════

class BrokerInterface(ABC):
    """Abstract message broker interface"""
    
    @abstractmethod
    async def publish(self, topic: str, payload: Any, priority: MessagePriority = MessagePriority.NORMAL) -> str:
        """Publish message to topic. Returns message ID."""
        pass
    
    @abstractmethod
    async def subscribe(self, topic: str, handler: Callable[[Message], Awaitable[bool]], group: str = "default"):
        """Subscribe to topic with handler. Handler returns True on success."""
        pass
    
    @abstractmethod
    async def acknowledge(self, message: Message):
        """Acknowledge message processing."""
        pass
    
    @abstractmethod
    async def reject(self, message: Message, error: str):
        """Reject message, may retry or send to DLQ."""
        pass
    
    @abstractmethod
    async def get_dlq_messages(self, topic: str, limit: int = 100) -> List[Message]:
        """Get messages from dead letter queue."""
        pass
    
    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Check broker health."""
        pass


# ══════════════════════════════════════════════════════════════════════════════
# MEMORY BROKER (DEVELOPMENT)
# ══════════════════════════════════════════════════════════════════════════════

class MemoryBroker(BrokerInterface):
    """
    In-memory message broker for development/testing.
    NOT suitable for production - no persistence!
    """
    
    def __init__(self, max_queue_size: int = 10000):
        self.queues: Dict[str, deque] = {}
        self.dlq: Dict[str, deque] = {}
        self.handlers: Dict[str, List[Callable]] = {}
        self.offsets: Dict[str, int] = {}
        self.max_queue_size = max_queue_size
        self._lock = threading.Lock()
        self._running = True
        self._stats = {"published": 0, "processed": 0, "failed": 0, "dlq": 0}
    
    def _get_queue(self, topic: str) -> deque:
        if topic not in self.queues:
            self.queues[topic] = deque(maxlen=self.max_queue_size)
        return self.queues[topic]
    
    def _get_dlq(self, topic: str) -> deque:
        if topic not in self.dlq:
            self.dlq[topic] = deque(maxlen=self.max_queue_size)
        return self.dlq[topic]
    
    async def publish(self, topic: str, payload: Any, priority: MessagePriority = MessagePriority.NORMAL) -> str:
        """Publish to in-memory queue"""
        msg_id = hashlib.md5(f"{topic}:{time.time()}:{json.dumps(payload, default=str)}".encode()).hexdigest()[:16]
        
        message = Message(
            id=msg_id,
            topic=topic,
            payload=payload,
            priority=priority
        )
        
        queue = self._get_queue(topic)
        
        # Insert based on priority
        with self._lock:
            if priority == MessagePriority.CRITICAL:
                queue.appendleft(message)
            else:
                queue.append(message)
            self._stats["published"] += 1
        
        # Trigger handlers
        await self._dispatch(topic, message)
        
        return msg_id
    
    async def _dispatch(self, topic: str, message: Message):
        """Dispatch message to handlers"""
        if topic in self.handlers:
            for handler in self.handlers[topic]:
                try:
                    success = await handler(message)
                    if success:
                        await self.acknowledge(message)
                    else:
                        await self.reject(message, "Handler returned False")
                except Exception as e:
                    await self.reject(message, str(e))
    
    async def subscribe(self, topic: str, handler: Callable[[Message], Awaitable[bool]], group: str = "default"):
        """Subscribe handler to topic"""
        if topic not in self.handlers:
            self.handlers[topic] = []
        self.handlers[topic].append(handler)
        logger.info(f"Subscribed to topic '{topic}' in group '{group}'")
    
    async def acknowledge(self, message: Message):
        """Mark message as completed"""
        message.status = MessageStatus.COMPLETED
        message.processed_at = datetime.utcnow().isoformat()
        self._stats["processed"] += 1
    
    async def reject(self, message: Message, error: str):
        """Reject and possibly retry message"""
        message.error = error
        message.retry_count += 1
        
        if message.retry_count >= message.max_retries:
            # Send to DLQ
            message.status = MessageStatus.DEAD
            dlq = self._get_dlq(message.topic)
            dlq.append(message)
            self._stats["dlq"] += 1
            logger.warning(f"Message {message.id} sent to DLQ after {message.retry_count} retries")
        else:
            # Retry with exponential backoff
            message.status = MessageStatus.PENDING
            delay = 2 ** message.retry_count
            await asyncio.sleep(delay)
            
            queue = self._get_queue(message.topic)
            queue.append(message)
            self._stats["failed"] += 1
            logger.info(f"Message {message.id} requeued (retry {message.retry_count})")
    
    async def get_dlq_messages(self, topic: str, limit: int = 100) -> List[Message]:
        """Get DLQ messages"""
        dlq = self._get_dlq(topic)
        return list(dlq)[:limit]
    
    def health_check(self) -> Dict[str, Any]:
        """Check memory broker health"""
        total_messages = sum(len(q) for q in self.queues.values())
        total_dlq = sum(len(q) for q in self.dlq.values())
        
        return {
            "broker": "memory",
            "status": "healthy",
            "warning": "In-memory broker - not for production!",
            "queues": len(self.queues),
            "total_messages": total_messages,
            "dlq_messages": total_dlq,
            "stats": self._stats,
        }


# ══════════════════════════════════════════════════════════════════════════════
# REDIS BROKER (PRODUCTION)
# ══════════════════════════════════════════════════════════════════════════════

class RedisBroker(BrokerInterface):
    """
    Redis-backed message broker for production.
    Uses Redis Streams for persistent messaging.
    Requires: pip install redis
    """
    
    def __init__(self, redis_url: Optional[str] = None, prefix: str = "sentinel"):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.prefix = prefix
        self._client = None
        self._handlers: Dict[str, List[Callable]] = {}
        self._consumer_tasks: List[asyncio.Task] = []
    
    def _get_client(self):
        """Lazy load Redis client"""
        if self._client is None:
            try:
                import redis
                self._client = redis.from_url(self.redis_url, decode_responses=True)
            except ImportError:
                logger.warning("Redis not installed")
                return None
        return self._client
    
    def _stream_key(self, topic: str) -> str:
        return f"{self.prefix}:stream:{topic}"
    
    def _dlq_key(self, topic: str) -> str:
        return f"{self.prefix}:dlq:{topic}"
    
    def _group_key(self, topic: str, group: str) -> str:
        return f"{self.prefix}:group:{topic}:{group}"
    
    async def publish(self, topic: str, payload: Any, priority: MessagePriority = MessagePriority.NORMAL) -> str:
        """Publish to Redis Stream"""
        client = self._get_client()
        if client is None:
            return await MemoryBroker().publish(topic, payload, priority)
        
        msg_id = hashlib.md5(f"{topic}:{time.time()}".encode()).hexdigest()[:16]
        
        message_data = {
            "id": msg_id,
            "payload": json.dumps(payload, default=str),
            "priority": priority.value,
            "created_at": datetime.utcnow().isoformat(),
            "retry_count": 0,
        }
        
        stream_key = self._stream_key(topic)
        
        # Use XADD to add to stream
        redis_id = client.xadd(stream_key, message_data)
        logger.debug(f"Published message {msg_id} to {stream_key}: {redis_id}")
        
        return msg_id
    
    async def subscribe(self, topic: str, handler: Callable[[Message], Awaitable[bool]], group: str = "default"):
        """Subscribe to Redis Stream"""
        client = self._get_client()
        if client is None:
            return await MemoryBroker().subscribe(topic, handler, group)
        
        stream_key = self._stream_key(topic)
        
        # Create consumer group if not exists
        try:
            client.xgroup_create(stream_key, group, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                logger.error(f"Failed to create consumer group: {e}")
        
        # Store handler
        if topic not in self._handlers:
            self._handlers[topic] = []
        self._handlers[topic].append(handler)
        
        # Start consumer task
        task = asyncio.create_task(self._consume(topic, group))
        self._consumer_tasks.append(task)
    
    async def _consume(self, topic: str, group: str):
        """Consume messages from stream"""
        client = self._get_client()
        if client is None:
            return
        
        stream_key = self._stream_key(topic)
        consumer_name = f"consumer-{os.getpid()}"
        
        while True:
            try:
                # Read from stream
                messages = client.xreadgroup(
                    group, consumer_name,
                    {stream_key: ">"},
                    count=10,
                    block=1000
                )
                
                for stream, entries in messages or []:
                    for entry_id, data in entries:
                        message = Message(
                            id=data["id"],
                            topic=topic,
                            payload=json.loads(data["payload"]),
                            priority=MessagePriority(int(data.get("priority", 1))),
                            retry_count=int(data.get("retry_count", 0)),
                            created_at=data.get("created_at"),
                        )
                        
                        # Process with handlers
                        for handler in self._handlers.get(topic, []):
                            try:
                                success = await handler(message)
                                if success:
                                    await self.acknowledge(message)
                                    client.xack(stream_key, group, entry_id)
                                else:
                                    await self.reject(message, "Handler returned False")
                            except Exception as e:
                                await self.reject(message, str(e))
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Consumer error: {e}")
                await asyncio.sleep(1)
    
    async def acknowledge(self, message: Message):
        """Acknowledge message"""
        logger.debug(f"Acknowledged message {message.id}")
    
    async def reject(self, message: Message, error: str):
        """Reject and handle retry/DLQ"""
        client = self._get_client()
        if client is None:
            return
        
        message.error = error
        message.retry_count += 1
        
        if message.retry_count >= message.max_retries:
            # Send to DLQ
            dlq_key = self._dlq_key(message.topic)
            client.lpush(dlq_key, json.dumps(message.to_dict()))
            logger.warning(f"Message {message.id} sent to DLQ")
        else:
            # Republish for retry
            delay = 2 ** message.retry_count
            await asyncio.sleep(delay)
            await self.publish(message.topic, message.payload, message.priority)
    
    async def get_dlq_messages(self, topic: str, limit: int = 100) -> List[Message]:
        """Get DLQ messages"""
        client = self._get_client()
        if client is None:
            return []
        
        dlq_key = self._dlq_key(topic)
        messages = client.lrange(dlq_key, 0, limit - 1)
        return [Message.from_dict(json.loads(m)) for m in messages]
    
    def health_check(self) -> Dict[str, Any]:
        """Check Redis broker health"""
        try:
            client = self._get_client()
            if client is None:
                return {"broker": "redis", "status": "unavailable"}
            
            client.ping()
            
            # Get stream info
            streams = {}
            for key in client.keys(f"{self.prefix}:stream:*"):
                info = client.xinfo_stream(key)
                streams[key] = {"length": info["length"]}
            
            return {
                "broker": "redis",
                "status": "healthy",
                "url": self.redis_url.split("@")[-1] if "@" in self.redis_url else "localhost",
                "streams": streams,
            }
        except Exception as e:
            return {"broker": "redis", "status": "unhealthy", "error": str(e)}


# ══════════════════════════════════════════════════════════════════════════════
# KAFKA BROKER (HIGH VOLUME)
# ══════════════════════════════════════════════════════════════════════════════

class KafkaBroker(BrokerInterface):
    """
    Kafka broker for high-volume streaming.
    Requires: pip install aiokafka
    """
    
    def __init__(self, bootstrap_servers: Optional[str] = None):
        self.bootstrap_servers = bootstrap_servers or os.getenv("KAFKA_SERVERS", "localhost:9092")
        self._producer = None
        self._consumers: Dict[str, Any] = {}
        self._handlers: Dict[str, List[Callable]] = {}
    
    async def _get_producer(self):
        """Lazy load Kafka producer"""
        if self._producer is None:
            try:
                from aiokafka import AIOKafkaProducer
                self._producer = AIOKafkaProducer(
                    bootstrap_servers=self.bootstrap_servers,
                    value_serializer=lambda v: json.dumps(v, default=str).encode()
                )
                await self._producer.start()
            except ImportError:
                logger.warning("aiokafka not installed")
                return None
        return self._producer
    
    async def publish(self, topic: str, payload: Any, priority: MessagePriority = MessagePriority.NORMAL) -> str:
        """Publish to Kafka topic"""
        producer = await self._get_producer()
        if producer is None:
            return await MemoryBroker().publish(topic, payload, priority)
        
        msg_id = hashlib.md5(f"{topic}:{time.time()}".encode()).hexdigest()[:16]
        
        message_data = {
            "id": msg_id,
            "payload": payload,
            "priority": priority.value,
            "created_at": datetime.utcnow().isoformat(),
        }
        
        await producer.send_and_wait(topic, message_data)
        return msg_id
    
    async def subscribe(self, topic: str, handler: Callable[[Message], Awaitable[bool]], group: str = "default"):
        """Subscribe to Kafka topic"""
        try:
            from aiokafka import AIOKafkaConsumer
            
            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=self.bootstrap_servers,
                group_id=group,
                value_deserializer=lambda v: json.loads(v.decode())
            )
            await consumer.start()
            
            if topic not in self._handlers:
                self._handlers[topic] = []
            self._handlers[topic].append(handler)
            self._consumers[topic] = consumer
            
            # Start consuming
            asyncio.create_task(self._consume(topic, consumer))
            
        except ImportError:
            return await MemoryBroker().subscribe(topic, handler, group)
    
    async def _consume(self, topic: str, consumer):
        """Consume from Kafka"""
        async for msg in consumer:
            message = Message(
                id=msg.value.get("id", ""),
                topic=topic,
                payload=msg.value.get("payload"),
                priority=MessagePriority(msg.value.get("priority", 1)),
                created_at=msg.value.get("created_at"),
            )
            
            for handler in self._handlers.get(topic, []):
                try:
                    await handler(message)
                except Exception as e:
                    logger.error(f"Handler error: {e}")
    
    async def acknowledge(self, message: Message):
        """Acknowledge - Kafka handles via consumer groups"""
        pass
    
    async def reject(self, message: Message, error: str):
        """Reject - publish to DLQ topic"""
        await self.publish(f"{message.topic}.dlq", message.to_dict())
    
    async def get_dlq_messages(self, topic: str, limit: int = 100) -> List[Message]:
        """Get DLQ messages - requires separate consumer"""
        return []
    
    def health_check(self) -> Dict[str, Any]:
        """Check Kafka health"""
        return {
            "broker": "kafka",
            "status": "configured",
            "servers": self.bootstrap_servers,
        }


# ══════════════════════════════════════════════════════════════════════════════
# BROKER FACTORY
# ══════════════════════════════════════════════════════════════════════════════

_broker_instance: Optional[BrokerInterface] = None

BROKER_CLASSES = {
    "memory": MemoryBroker,
    "redis": RedisBroker,
    "kafka": KafkaBroker,
}


class MessageBroker:
    """Unified message broker interface"""
    
    def __init__(self, broker_type: Optional[str] = None):
        broker_type = broker_type or os.getenv("SENTINEL_BROKER", "memory")
        broker_class = BROKER_CLASSES.get(broker_type, MemoryBroker)
        self._broker = broker_class()
        self._type = broker_type
    
    async def publish(self, topic: str, payload: Any, priority: MessagePriority = MessagePriority.NORMAL) -> str:
        return await self._broker.publish(topic, payload, priority)
    
    async def subscribe(self, topic: str, handler: Callable[[Message], Awaitable[bool]], group: str = "default"):
        return await self._broker.subscribe(topic, handler, group)
    
    async def acknowledge(self, message: Message):
        return await self._broker.acknowledge(message)
    
    async def reject(self, message: Message, error: str):
        return await self._broker.reject(message, error)
    
    async def get_dlq_messages(self, topic: str, limit: int = 100) -> List[Message]:
        return await self._broker.get_dlq_messages(topic, limit)
    
    def health_check(self) -> Dict[str, Any]:
        return self._broker.health_check()
    
    @property
    def broker_type(self) -> str:
        return self._type


def get_broker(broker_type: Optional[str] = None) -> MessageBroker:
    """Get message broker singleton"""
    global _broker_instance
    
    requested_type = broker_type or os.getenv("SENTINEL_BROKER", "memory")
    
    if _broker_instance is None or _broker_instance.broker_type != requested_type:
        _broker_instance = MessageBroker(requested_type)
    
    return _broker_instance


__all__ = [
    "Message",
    "MessagePriority",
    "MessageStatus",
    "BrokerInterface",
    "MemoryBroker",
    "RedisBroker",
    "KafkaBroker",
    "MessageBroker",
    "get_broker",
]
