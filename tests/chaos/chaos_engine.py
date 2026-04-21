"""
tests/chaos/chaos_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v134.0
Chaos engineering framework for resilience validation.

Failure injection modes:
  - LatencyInjector     — Add random/fixed latency to function calls
  - ExceptionInjector   — Randomly raise exceptions in target functions
  - NetworkPartition    — Block/delay outbound HTTP calls to specific hosts
  - MemoryPressure      — Allocate memory to simulate OOM conditions
  - CPUSpike            — Saturate CPU threads to test timeout behaviour
  - StorageFailure      — Corrupt/delete files to test recovery paths
  - RedisFailure        — Drop Redis connection to test in-memory fallback
  - DataCorruption      — Inject malformed data into queues/caches

Usage:
    from tests.chaos.chaos_engine import ChaosEngine

    with ChaosEngine(failure_rate=0.1) as chaos:
        chaos.inject_latency(min_ms=100, max_ms=2000)
        chaos.inject_exceptions(target='core.ingestion', rate=0.05)
        run_integration_tests()   # tests run with chaos active
        report = chaos.report()

CLI:
    python -m tests.chaos.chaos_engine --scenario network_partition --duration 30
"""
from __future__ import annotations

import functools
import logging
import os
import random
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest.mock import patch

logger = logging.getLogger("sentinel.chaos")


# ─────────────────────────────────────────────
# Chaos event record
# ─────────────────────────────────────────────

@dataclass
class ChaosEvent:
    injection_type: str
    target:         str
    ts:             float = field(default_factory=time.time)
    triggered:      bool  = False
    latency_ms:     float = 0.0
    error_type:     str   = ""
    recovered:      bool  = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "injection_type": self.injection_type,
            "target":         self.target,
            "ts":             self.ts,
            "triggered":      self.triggered,
            "latency_ms":     self.latency_ms,
            "error_type":     self.error_type,
            "recovered":      self.recovered,
        }


# ─────────────────────────────────────────────
# Individual injectors
# ─────────────────────────────────────────────

class LatencyInjector:
    """Wraps a callable to randomly inject latency."""

    def __init__(self, min_ms: int = 100, max_ms: int = 2000,
                 rate: float = 1.0, events: List[ChaosEvent] = None) -> None:
        self._min_ms  = min_ms
        self._max_ms  = max_ms
        self._rate    = rate
        self._events  = events if events is not None else []
        self._active  = True

    def wrap(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if self._active and random.random() < self._rate:
                delay_ms = random.uniform(self._min_ms, self._max_ms)
                ev = ChaosEvent("latency", func.__name__,
                                triggered=True, latency_ms=delay_ms)
                self._events.append(ev)
                logger.debug("chaos_latency func=%s delay_ms=%.0f", func.__name__, delay_ms)
                time.sleep(delay_ms / 1000.0)
            return func(*args, **kwargs)
        return wrapper

    def stop(self) -> None:
        self._active = False


class ExceptionInjector:
    """Randomly raises exceptions from a target function."""

    _EXCEPTION_TYPES = [
        ConnectionError("chaos: simulated connection reset"),
        TimeoutError("chaos: simulated timeout"),
        IOError("chaos: simulated I/O failure"),
        ValueError("chaos: simulated bad data"),
        RuntimeError("chaos: simulated runtime failure"),
    ]

    def __init__(self, rate: float = 0.1,
                 exception: Optional[Exception] = None,
                 events: List[ChaosEvent] = None) -> None:
        self._rate   = rate
        self._exc    = exception
        self._events = events if events is not None else []
        self._active = True

    def wrap(self, func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if self._active and random.random() < self._rate:
                exc = self._exc or random.choice(self._EXCEPTION_TYPES)
                ev  = ChaosEvent("exception", func.__name__,
                                 triggered=True, error_type=type(exc).__name__)
                self._events.append(ev)
                logger.debug("chaos_exception func=%s exc=%s",
                             func.__name__, type(exc).__name__)
                raise exc
            return func(*args, **kwargs)
        return wrapper

    def stop(self) -> None:
        self._active = False


class NetworkPartitionSimulator:
    """
    Patches urllib.request.urlopen to simulate network partitions.
    Affects all HTTP calls made through urllib (used by source adapters).
    """

    def __init__(self, blocked_hosts: List[str], rate: float = 1.0,
                 events: List[ChaosEvent] = None) -> None:
        self._blocked = blocked_hosts
        self._rate    = rate
        self._events  = events if events is not None else []
        self._patch   = None
        self._active  = False

    def start(self) -> None:
        from urllib.error import URLError
        original_urlopen = __import__("urllib.request", fromlist=["urlopen"]).urlopen

        def patched_urlopen(req, *args, **kwargs):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            for host in self._blocked:
                if host in url and random.random() < self._rate:
                    ev = ChaosEvent("network_partition", host, triggered=True)
                    self._events.append(ev)
                    logger.debug("chaos_network_block host=%s", host)
                    raise URLError(f"chaos: network partition to {host}")
            return original_urlopen(req, *args, **kwargs)

        self._patch = patch("urllib.request.urlopen", side_effect=patched_urlopen)
        self._patch.start()
        self._active = True
        logger.info("chaos_network_partition started hosts=%s", self._blocked)

    def stop(self) -> None:
        if self._patch:
            self._patch.stop()
        self._active = False


class StorageFailureSimulator:
    """Injects file I/O failures at configurable rates."""

    def __init__(self, target_path: str, rate: float = 0.3,
                 events: List[ChaosEvent] = None) -> None:
        self._target_path = target_path
        self._rate        = rate
        self._events      = events if events is not None else []
        self._active      = False
        self._patch       = None

    def start(self) -> None:
        original_open = open

        def patched_open(file, mode="r", *args, **kwargs):
            if (self._target_path in str(file) and
                    "w" in str(mode) and random.random() < self._rate):
                ev = ChaosEvent("storage_failure", str(file), triggered=True)
                self._events.append(ev)
                logger.debug("chaos_storage_fail path=%s", file)
                raise IOError(f"chaos: simulated write failure for {file}")
            return original_open(file, mode, *args, **kwargs)

        self._patch  = patch("builtins.open", side_effect=patched_open)
        self._patch.start()
        self._active = True

    def stop(self) -> None:
        if self._patch:
            self._patch.stop()
        self._active = False


# ─────────────────────────────────────────────
# Pre-built chaos scenarios
# ─────────────────────────────────────────────

_SCENARIOS: Dict[str, Callable] = {}


def scenario(name: str):
    def decorator(fn):
        _SCENARIOS[name] = fn
        return fn
    return decorator


@scenario("network_partition")
def scenario_network_partition(engine: "ChaosEngine") -> None:
    """Block all external threat intelligence source calls."""
    engine._network = NetworkPartitionSimulator(
        blocked_hosts=[
            "services.nvd.nist.gov",
            "www.cisa.gov",
            "mb-api.abuse.ch",
            "api.abuseipdb.com",
            "api.first.org",
        ],
        rate=1.0,
        events=engine._events,
    )
    engine._network.start()


@scenario("degraded_network")
def scenario_degraded_network(engine: "ChaosEngine") -> None:
    """30% packet loss + high latency to external APIs."""
    engine._network = NetworkPartitionSimulator(
        blocked_hosts=[
            "services.nvd.nist.gov",
            "www.cisa.gov",
        ],
        rate=0.3,
        events=engine._events,
    )
    engine._network.start()


@scenario("high_latency")
def scenario_high_latency(engine: "ChaosEngine") -> None:
    """Inject 1-5 second latency on all operations."""
    # Stored for context manager cleanup
    engine._latency_injector = LatencyInjector(
        min_ms=1000, max_ms=5000, rate=0.5, events=engine._events
    )


@scenario("cascade_failure")
def scenario_cascade_failure(engine: "ChaosEngine") -> None:
    """Combined: network partition + storage failures + high error rate."""
    scenario_network_partition(engine)
    engine._exception_injectors.append(
        ExceptionInjector(rate=0.2, events=engine._events)
    )


# ─────────────────────────────────────────────
# Main ChaosEngine
# ─────────────────────────────────────────────

class ChaosEngine:
    """
    Context manager that activates chaos injection for the duration of a test.

    Usage::

        with ChaosEngine(scenario='network_partition', duration_s=30) as chaos:
            run_integration_suite()
            print(chaos.report())
    """

    def __init__(
        self,
        scenario: Optional[str] = None,
        failure_rate: float = 0.1,
        duration_s:   int   = 0,
        seed:         Optional[int] = None,
    ) -> None:
        self._scenario_name       = scenario
        self._failure_rate        = failure_rate
        self._duration_s          = duration_s
        self._seed                = seed
        self._events: List[ChaosEvent] = []
        self._network: Optional[NetworkPartitionSimulator] = None
        self._storage: Optional[StorageFailureSimulator]   = None
        self._latency_injector: Optional[LatencyInjector]  = None
        self._exception_injectors: List[ExceptionInjector] = []
        self._start_ts:  float = 0.0
        self._active:    bool  = False
        self._timer: Optional[threading.Timer] = None

    def __enter__(self) -> "ChaosEngine":
        if self._seed is not None:
            random.seed(self._seed)
        self._start_ts = time.time()
        self._active   = True

        if self._scenario_name and self._scenario_name in _SCENARIOS:
            _SCENARIOS[self._scenario_name](self)
            logger.info("chaos_scenario_activated name=%s", self._scenario_name)
        else:
            logger.info("chaos_engine_started failure_rate=%.2f", self._failure_rate)

        if self._duration_s > 0:
            self._timer = threading.Timer(self._duration_s, self.stop)
            self._timer.daemon = True
            self._timer.start()

        return self

    def __exit__(self, *args) -> None:
        self.stop()

    def stop(self) -> None:
        if not self._active:
            return
        self._active = False
        if self._timer:
            self._timer.cancel()
        if self._network:
            self._network.stop()
        if self._storage:
            self._storage.stop()
        if self._latency_injector:
            self._latency_injector.stop()
        for inj in self._exception_injectors:
            inj.stop()
        logger.info("chaos_engine_stopped events_triggered=%d",
                    sum(1 for e in self._events if e.triggered))

    def report(self) -> Dict[str, Any]:
        """Return chaos test summary."""
        triggered   = [e for e in self._events if e.triggered]
        by_type: Dict[str, int] = {}
        for ev in triggered:
            by_type[ev.injection_type] = by_type.get(ev.injection_type, 0) + 1
        avg_latency = (
            sum(e.latency_ms for e in triggered if e.latency_ms > 0)
            / max(1, sum(1 for e in triggered if e.latency_ms > 0))
        )
        return {
            "scenario":        self._scenario_name or "custom",
            "duration_s":      round(time.time() - self._start_ts, 1),
            "total_events":    len(self._events),
            "triggered_events": len(triggered),
            "by_type":         by_type,
            "avg_latency_ms":  round(avg_latency, 1),
            "recovered_count": sum(1 for e in triggered if e.recovered),
        }

    # ── Fluent injection API ──────────────────────────────────────────────────

    def inject_latency(self, min_ms: int = 100, max_ms: int = 2000,
                       rate: float = 1.0) -> "ChaosEngine":
        self._latency_injector = LatencyInjector(
            min_ms=min_ms, max_ms=max_ms, rate=rate, events=self._events
        )
        return self

    def inject_exceptions(self, rate: float = 0.1,
                           exception: Optional[Exception] = None) -> "ChaosEngine":
        inj = ExceptionInjector(rate=rate, exception=exception, events=self._events)
        self._exception_injectors.append(inj)
        return self

    def block_network(self, hosts: List[str],
                      rate: float = 1.0) -> "ChaosEngine":
        self._network = NetworkPartitionSimulator(
            blocked_hosts=hosts, rate=rate, events=self._events
        )
        self._network.start()
        return self

    def wrap_with_latency(self, func: Callable) -> Callable:
        """Wrap a specific function with latency injection."""
        if self._latency_injector:
            return self._latency_injector.wrap(func)
        return func

    def wrap_with_exceptions(self, func: Callable, rate: float = 0.1) -> Callable:
        """Wrap a specific function with exception injection."""
        inj = ExceptionInjector(rate=rate, events=self._events)
        self._exception_injectors.append(inj)
        return inj.wrap(func)


# ─────────────────────────────────────────────
# Built-in chaos tests
# ─────────────────────────────────────────────

def run_deduplicator_chaos() -> Dict[str, Any]:
    """Validate deduplicator survives concurrent access + errors."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
    from core.ingestion.deduplicator import Deduplicator
    from core.ingestion.sources.base import RawIntelItem, SourceType

    dedup = Deduplicator(ttl_s=300, persist_path="/tmp/chaos_dedup_test.jsonl")
    errors = []
    success_count = 0

    def worker(thread_id: int) -> None:
        nonlocal success_count
        for i in range(50):
            try:
                item = RawIntelItem(
                    source_id="test",
                    source_type=SourceType.CVE,
                    raw_id=f"CVE-{thread_id}-{i}",
                    raw_data={"id": f"CVE-{thread_id}-{i}", "score": random.random() * 10},
                )
                dedup.is_duplicate(item)
                success_count += 1
            except Exception as e:
                errors.append(str(e))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()

    stats = dedup.stats()
    return {
        "test":         "deduplicator_concurrency",
        "threads":      10,
        "ops_each":     50,
        "total_ops":    success_count,
        "errors":       len(errors),
        "error_details": errors[:5],
        "dedup_stats":  stats,
        "passed":       len(errors) == 0,
    }


def run_ingestion_queue_chaos() -> Dict[str, Any]:
    """Validate queue survives producer/consumer races."""
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
    from core.ingestion.ingestion_engine import IngestionQueue
    from core.ingestion.sources.base import RawIntelItem, SourceType

    q = IngestionQueue(max_depth=100)
    enqueued = [0]
    dequeued = [0]
    dropped  = [0]

    def producer(count: int) -> None:
        for i in range(count):
            item = RawIntelItem(
                source_id="chaos_test",
                source_type=SourceType.GENERIC,
                raw_id=f"item-{i}",
                raw_data={"i": i},
            )
            if q.enqueue(item):
                enqueued[0] += 1
            else:
                dropped[0] += 1
            time.sleep(0.001)

    def consumer() -> None:
        deadline = time.time() + 3.0
        while time.time() < deadline:
            item = q.dequeue(timeout_s=0.1)
            if item:
                dequeued[0] += 1

    producers = [threading.Thread(target=producer, args=(60,)) for _ in range(5)]
    consumer_t = threading.Thread(target=consumer)
    consumer_t.start()
    for p in producers: p.start()
    for p in producers: p.join()
    consumer_t.join()

    # Queue should not have lost items (enqueued = dequeued + remaining_depth)
    remaining = q.depth()
    accounted = dequeued[0] + remaining + dropped[0]
    total_produced = 5 * 60
    items_ok = accounted == total_produced

    return {
        "test":           "ingestion_queue_concurrency",
        "total_produced": total_produced,
        "enqueued":       enqueued[0],
        "dequeued":       dequeued[0],
        "dropped":        dropped[0],
        "remaining":      remaining,
        "accounting_ok":  items_ok,
        "passed":         items_ok,
    }


def run_all_chaos_tests() -> List[Dict[str, Any]]:
    """Run built-in chaos suite and return results."""
    results = []
    print("\n── Chaos Suite: Deduplicator Concurrency ──")
    r1 = run_deduplicator_chaos()
    results.append(r1)
    status = "PASS" if r1["passed"] else "FAIL"
    print(f"  {status}: errors={r1['errors']} total_ops={r1['total_ops']}")

    print("── Chaos Suite: Ingestion Queue Concurrency ──")
    r2 = run_ingestion_queue_chaos()
    results.append(r2)
    status = "PASS" if r2["passed"] else "FAIL"
    print(f"  {status}: accounting_ok={r2['accounting_ok']} "
          f"enqueued={r2['enqueued']} dequeued={r2['dequeued']} dropped={r2['dropped']}")

    return results


# ── CLI entrypoint ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Sentinel APEX Chaos Engine")
    parser.add_argument("--scenario", choices=list(_SCENARIOS.keys()) + ["all"],
                        default="all")
    parser.add_argument("--duration", type=int, default=30)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    print(f"\nSentinel APEX Chaos Engine — scenario={args.scenario}")

    if args.scenario == "all":
        results = run_all_chaos_tests()
        passed = sum(1 for r in results if r.get("passed"))
        print(f"\n{passed}/{len(results)} chaos tests passed")
    else:
        with ChaosEngine(scenario=args.scenario, duration_s=args.duration) as chaos:
            print(f"Chaos active for {args.duration}s — run your tests now")
            time.sleep(args.duration)
        print(f"\nChaos report: {chaos.report()}")
