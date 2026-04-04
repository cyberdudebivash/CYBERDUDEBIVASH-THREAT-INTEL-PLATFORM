"""
core/stability/auto_recovery.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
Automated recovery system for pipeline and service failures.

Recovery strategies:
  - Circuit breaker pattern per component (open/half-open/closed)
  - Automatic service restart with backoff (source schedulers, queues)
  - Graceful degradation: disable failed sources, keep healthy ones running
  - Health-check driven recovery: probe → recover → re-enable
  - Audit trail: all recovery actions logged to JSONL

Architecture:
  AutoRecoveryManager
    ├── CircuitBreaker (per component)
    ├── ServiceWatchdog (monitors + restarts threads)
    └── DegradationController (feature flags under failure)
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("sentinel.stability.auto_recovery")

_AUDIT_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", "/tmp/sentinel_data")) / "recovery"
_AUDIT_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────
# Circuit Breaker
# ─────────────────────────────────────────────

class CircuitState(str, Enum):
    CLOSED     = "closed"       # normal — requests flow through
    OPEN       = "open"         # tripped — requests rejected immediately
    HALF_OPEN  = "half_open"    # probing — one request allowed through


@dataclass
class CircuitBreaker:
    """
    Per-component circuit breaker.
    Trips after failure_threshold consecutive failures.
    Auto-resets after recovery_timeout_s seconds in OPEN state.
    """
    name:               str
    failure_threshold:  int   = 5
    recovery_timeout_s: int   = 60
    half_open_max_calls: int  = 1

    _state:             CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count:     int          = field(default=0, init=False)
    _last_failure_ts:   float        = field(default=0.0, init=False)
    _half_open_calls:   int          = field(default=0, init=False)
    _lock:              threading.Lock = field(default_factory=threading.Lock, init=False)

    def call(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute func through the circuit breaker.
        Raises CircuitOpenError if circuit is OPEN.
        """
        with self._lock:
            state = self._current_state()

            if state == CircuitState.OPEN:
                raise CircuitOpenError(
                    f"Circuit '{self.name}' is OPEN — "
                    f"recovery in {self._time_to_recovery():.0f}s"
                )

            if state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    raise CircuitOpenError(
                        f"Circuit '{self.name}' is HALF-OPEN, probe limit reached"
                    )
                self._half_open_calls += 1

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as exc:
            self._on_failure()
            raise

    def _current_state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.time() - self._last_failure_ts >= self.recovery_timeout_s:
                self._state          = CircuitState.HALF_OPEN
                self._half_open_calls = 0
                logger.info("circuit_half_open name=%s", self.name)
        return self._state

    def _on_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                logger.info("circuit_closed name=%s (recovered)", self.name)
            self._state         = CircuitState.CLOSED
            self._failure_count = 0

    def _on_failure(self) -> None:
        with self._lock:
            self._failure_count  += 1
            self._last_failure_ts = time.time()
            if self._failure_count >= self.failure_threshold:
                if self._state != CircuitState.OPEN:
                    self._state = CircuitState.OPEN
                    logger.error(
                        "circuit_tripped name=%s failures=%d",
                        self.name, self._failure_count
                    )
                    self._audit("circuit_tripped", {
                        "failures": self._failure_count,
                        "state":    "open",
                    })

    def _time_to_recovery(self) -> float:
        return max(0, self.recovery_timeout_s - (time.time() - self._last_failure_ts))

    def reset(self) -> None:
        with self._lock:
            self._state         = CircuitState.CLOSED
            self._failure_count = 0
            logger.info("circuit_reset name=%s", self.name)

    def status(self) -> Dict[str, Any]:
        return {
            "name":             self.name,
            "state":            self._current_state().value,
            "failure_count":    self._failure_count,
            "time_to_recovery": self._time_to_recovery(),
        }

    def _audit(self, event: str, details: Dict[str, Any]) -> None:
        try:
            entry = {"ts": time.time(), "component": self.name,
                     "event": event, **details}
            with open(_AUDIT_DIR / "circuit_breakers.jsonl", "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass


class CircuitOpenError(Exception):
    """Raised when a call is rejected because the circuit breaker is OPEN."""


# ─────────────────────────────────────────────
# Service Watchdog
# ─────────────────────────────────────────────

@dataclass
class WatchedService:
    name:           str
    start_fn:       Callable         # Function to start/restart the service
    health_fn:      Callable[[], bool]  # Returns True if healthy
    restart_delay_s: int = 5
    max_restarts:   int  = 10
    restart_count:  int  = field(default=0, init=False)
    last_restart_ts: float = field(default=0.0, init=False)
    healthy:        bool   = field(default=True, init=False)


class ServiceWatchdog:
    """
    Monitors registered services and automatically restarts failed ones.
    Uses exponential backoff between restart attempts.
    """

    def __init__(self, poll_interval_s: int = 30) -> None:
        self._services: Dict[str, WatchedService] = {}
        self._poll_interval = poll_interval_s
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def register(self, service: WatchedService) -> None:
        self._services[service.name] = service
        logger.info("watchdog_registered service=%s", service.name)

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(
            target=self._watch_loop, name="watchdog", daemon=True
        )
        self._thread.start()
        logger.info("watchdog_started services=%d", len(self._services))

    def stop(self) -> None:
        self._running = False

    def status(self) -> Dict[str, Any]:
        return {
            svc.name: {
                "healthy":       svc.healthy,
                "restart_count": svc.restart_count,
                "last_restart":  svc.last_restart_ts,
            }
            for svc in self._services.values()
        }

    def _watch_loop(self) -> None:
        while self._running:
            for name, svc in list(self._services.items()):
                try:
                    is_healthy = svc.health_fn()
                    if not is_healthy and svc.healthy:
                        svc.healthy = False
                        logger.error("watchdog_unhealthy service=%s", name)
                        self._try_restart(svc)
                    elif is_healthy and not svc.healthy:
                        svc.healthy = True
                        logger.info("watchdog_recovered service=%s", name)
                except Exception as exc:
                    logger.warning("watchdog_probe_error service=%s err=%s", name, exc)
            time.sleep(self._poll_interval)

    def _try_restart(self, svc: WatchedService) -> None:
        if svc.restart_count >= svc.max_restarts:
            logger.error("watchdog_restart_limit service=%s max=%d",
                         svc.name, svc.max_restarts)
            return

        delay = min(svc.restart_delay_s * (2 ** svc.restart_count), 300)
        logger.info("watchdog_restarting service=%s attempt=%d delay_s=%d",
                    svc.name, svc.restart_count + 1, delay)
        time.sleep(delay)

        try:
            svc.start_fn()
            svc.restart_count  += 1
            svc.last_restart_ts = time.time()
            logger.info("watchdog_restart_ok service=%s", svc.name)
            self._audit_restart(svc)
        except Exception as exc:
            svc.restart_count += 1
            logger.error("watchdog_restart_failed service=%s err=%s", svc.name, exc)

    @staticmethod
    def _audit_restart(svc: WatchedService) -> None:
        try:
            entry = {
                "ts":         time.time(),
                "service":    svc.name,
                "event":      "restart",
                "attempt":    svc.restart_count,
            }
            with open(_AUDIT_DIR / "watchdog.jsonl", "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass


# ─────────────────────────────────────────────
# Degradation Controller
# ─────────────────────────────────────────────

class DegradationController:
    """
    Feature-flag style degradation controller.
    When a component fails, its dependent features are automatically disabled.
    Enables graceful degradation instead of total outage.

    Example:
        controller.register_dependency("stix_export", "redis")
        controller.register_dependency("search",      "redis")
        controller.mark_failed("redis")
        # Now stix_export and search are degraded
        assert not controller.is_available("stix_export")
    """

    def __init__(self) -> None:
        self._features:     Dict[str, bool]          = {}
        self._dependencies: Dict[str, List[str]]     = {}
        self._failed_components: set                 = set()
        self._lock = threading.Lock()

    def register_feature(self, feature: str, enabled: bool = True) -> None:
        with self._lock:
            self._features[feature] = enabled

    def register_dependency(self, feature: str, component: str) -> None:
        """Register that feature requires component to be healthy."""
        with self._lock:
            if feature not in self._dependencies:
                self._dependencies[feature] = []
            self._dependencies[feature].append(component)

    def mark_failed(self, component: str) -> None:
        """Mark a component as failed — disables all dependent features."""
        with self._lock:
            self._failed_components.add(component)
            affected = [
                f for f, deps in self._dependencies.items()
                if component in deps
            ]
            for f in affected:
                self._features[f] = False
            logger.warning(
                "degradation_triggered component=%s affected_features=%s",
                component, affected
            )

    def mark_recovered(self, component: str) -> None:
        """Mark a component as recovered — re-enables features if all deps healthy."""
        with self._lock:
            self._failed_components.discard(component)
            for feature, deps in self._dependencies.items():
                if not any(d in self._failed_components for d in deps):
                    self._features[feature] = True
                    logger.info("degradation_recovered feature=%s component=%s",
                                feature, component)

    def is_available(self, feature: str) -> bool:
        with self._lock:
            return self._features.get(feature, True)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "failed_components":  list(self._failed_components),
                "feature_status":     dict(self._features),
                "degraded_features":  [f for f, ok in self._features.items() if not ok],
            }


# ─────────────────────────────────────────────
# AutoRecoveryManager — top-level facade
# ─────────────────────────────────────────────

class AutoRecoveryManager:
    """
    Unified auto-recovery manager.
    Combines circuit breakers, watchdog, and degradation control.
    """

    def __init__(self) -> None:
        self._breakers:     Dict[str, CircuitBreaker] = {}
        self._watchdog      = ServiceWatchdog(poll_interval_s=30)
        self._degradation   = DegradationController()
        self._lock          = threading.Lock()

    def start(self) -> None:
        self._watchdog.start()
        self._init_default_dependencies()
        logger.info("auto_recovery_manager started")

    def stop(self) -> None:
        self._watchdog.stop()

    def get_breaker(self, component: str,
                    failure_threshold: int = 5,
                    recovery_timeout_s: int = 60) -> CircuitBreaker:
        """Get or create a circuit breaker for a component."""
        with self._lock:
            if component not in self._breakers:
                self._breakers[component] = CircuitBreaker(
                    name=component,
                    failure_threshold=failure_threshold,
                    recovery_timeout_s=recovery_timeout_s,
                )
            return self._breakers[component]

    def register_service(self, service: WatchedService) -> None:
        self._watchdog.register(service)

    def feature_available(self, feature: str) -> bool:
        return self._degradation.is_available(feature)

    def mark_component_failed(self, component: str) -> None:
        self._degradation.mark_failed(component)
        breaker = self._breakers.get(component)
        if breaker:
            breaker._on_failure()

    def mark_component_recovered(self, component: str) -> None:
        self._degradation.mark_recovered(component)
        breaker = self._breakers.get(component)
        if breaker:
            breaker.reset()

    def status(self) -> Dict[str, Any]:
        return {
            "circuit_breakers": {
                name: cb.status()
                for name, cb in self._breakers.items()
            },
            "watchdog":     self._watchdog.status(),
            "degradation":  self._degradation.status(),
        }

    def _init_default_dependencies(self) -> None:
        """Register standard Sentinel APEX feature-to-component dependencies."""
        deps = [
            ("stix_export",        "redis"),
            ("search",             "redis"),
            ("ingestion_pipeline", "redis"),
            ("usage_metering",     "redis"),
            ("nvd_feed",           "nvd_api"),
            ("kev_feed",           "cisa_kev"),
            ("malware_feed",       "malwarebazaar"),
            ("ip_threat_feed",     "abuseipdb"),
        ]
        for feature, component in deps:
            self._degradation.register_feature(feature, enabled=True)
            self._degradation.register_dependency(feature, component)


# ── Module singleton ────────────────────────────────────────────────────────
_recovery_manager: Optional[AutoRecoveryManager] = None
_recovery_lock    = threading.Lock()


def get_recovery_manager() -> AutoRecoveryManager:
    global _recovery_manager
    with _recovery_lock:
        if _recovery_manager is None:
            _recovery_manager = AutoRecoveryManager()
            _recovery_manager.start()
        return _recovery_manager
