"""
SENTINEL APEX v27.0 — Health Checks
====================================
Application health monitoring and readiness probes.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable, Awaitable
from enum import Enum

logger = logging.getLogger("CDB-Health")


class HealthStatus(Enum):
    """Health check status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    """Health status for a single component"""
    name: str
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemHealth:
    """Overall system health"""
    status: HealthStatus
    components: Dict[str, ComponentHealth]
    timestamp: datetime
    version: str = "27.0.0"
    uptime_seconds: float = 0


class HealthChecker:
    """
    Health check manager for SENTINEL APEX.
    
    Monitors:
    - Database connectivity
    - Redis/queue health
    - External API availability
    - Feed sources
    - Worker status
    """
    
    def __init__(self):
        self._checks: Dict[str, Callable[[], Awaitable[ComponentHealth]]] = {}
        self._start_time = datetime.now(timezone.utc)
        self._last_results: Dict[str, ComponentHealth] = {}
    
    def register(
        self,
        name: str,
        check: Callable[[], Awaitable[ComponentHealth]]
    ):
        """Register a health check function"""
        self._checks[name] = check
        logger.info(f"Registered health check: {name}")
    
    async def check_component(self, name: str) -> ComponentHealth:
        """Run health check for a specific component"""
        check_fn = self._checks.get(name)
        if not check_fn:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message="Check not found"
            )
        
        try:
            start = datetime.now(timezone.utc)
            result = await asyncio.wait_for(check_fn(), timeout=10)
            result.latency_ms = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            self._last_results[name] = result
            return result
        except asyncio.TimeoutError:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message="Health check timed out"
            )
        except Exception as e:
            return ComponentHealth(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=str(e)
            )
    
    async def check_all(self) -> SystemHealth:
        """Run all health checks"""
        components = {}
        
        for name in self._checks:
            components[name] = await self.check_component(name)
        
        # Determine overall status
        statuses = [c.status for c in components.values()]
        
        if all(s == HealthStatus.HEALTHY for s in statuses):
            overall = HealthStatus.HEALTHY
        elif any(s == HealthStatus.UNHEALTHY for s in statuses):
            overall = HealthStatus.UNHEALTHY
        else:
            overall = HealthStatus.DEGRADED
        
        uptime = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        
        return SystemHealth(
            status=overall,
            components=components,
            timestamp=datetime.now(timezone.utc),
            uptime_seconds=uptime,
        )
    
    async def is_ready(self) -> bool:
        """Readiness probe - all critical components healthy"""
        health = await self.check_all()
        return health.status != HealthStatus.UNHEALTHY
    
    async def is_alive(self) -> bool:
        """Liveness probe - basic application health"""
        return True  # If this code runs, we're alive
    
    def get_last_results(self) -> Dict[str, ComponentHealth]:
        """Get cached results from last check"""
        return self._last_results.copy()


# ══════════════════════════════════════════════════════════════════════════════
# BUILT-IN HEALTH CHECKS
# ══════════════════════════════════════════════════════════════════════════════

async def check_redis() -> ComponentHealth:
    """Check Redis connectivity"""
    try:
        import redis.asyncio as redis
        client = redis.from_url("redis://localhost:6379/0")
        await client.ping()
        await client.close()
        return ComponentHealth(
            name="redis",
            status=HealthStatus.HEALTHY,
            message="Connected"
        )
    except ImportError:
        return ComponentHealth(
            name="redis",
            status=HealthStatus.DEGRADED,
            message="redis-py not installed, using in-memory"
        )
    except Exception as e:
        return ComponentHealth(
            name="redis",
            status=HealthStatus.UNHEALTHY,
            message=str(e)
        )


async def check_feeds() -> ComponentHealth:
    """Check feed source availability"""
    import os
    
    manifest_path = "data/stix/feed_manifest.json"
    if os.path.exists(manifest_path):
        # Check freshness
        mtime = datetime.fromtimestamp(
            os.path.getmtime(manifest_path),
            tz=timezone.utc
        )
        age = datetime.now(timezone.utc) - mtime
        
        if age < timedelta(hours=6):
            return ComponentHealth(
                name="feeds",
                status=HealthStatus.HEALTHY,
                message=f"Manifest updated {age.seconds // 60}m ago"
            )
        elif age < timedelta(hours=24):
            return ComponentHealth(
                name="feeds",
                status=HealthStatus.DEGRADED,
                message=f"Manifest stale: {age.seconds // 3600}h old"
            )
        else:
            return ComponentHealth(
                name="feeds",
                status=HealthStatus.UNHEALTHY,
                message=f"Manifest very stale: {age.days}d old"
            )
    else:
        return ComponentHealth(
            name="feeds",
            status=HealthStatus.UNHEALTHY,
            message="Manifest not found"
        )


async def check_api() -> ComponentHealth:
    """Check API server health"""
    return ComponentHealth(
        name="api",
        status=HealthStatus.HEALTHY,
        message="Running"
    )


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════
_health_checker: Optional[HealthChecker] = None


def get_health_checker() -> HealthChecker:
    """Get or create the global health checker"""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
        
        # Register built-in checks
        _health_checker.register("redis", check_redis)
        _health_checker.register("feeds", check_feeds)
        _health_checker.register("api", check_api)
    
    return _health_checker


__all__ = [
    "HealthChecker",
    "HealthStatus",
    "ComponentHealth",
    "SystemHealth",
    "get_health_checker",
]
