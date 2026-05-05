#!/usr/bin/env python3
"""
scripts/crash_guard.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.1.0 — Crash-Guard: Phase 2 Multi-Feed Fusion
====================================================================================
Production crash-isolation wrapper for all Phase 2 (multi-feed fusion) operations.

GUARANTEES:
  - Single-source failure NEVER halts the master pipeline
  - IOC enforcer type errors are caught and logged (not propagated)
  - dedup-L0 persistent fallback is handled gracefully
  - Per-source timeout isolation (default 300s per source)
  - Structured failure ledger written to data/audit/crash_guard_ledger.json
  - All failures are non-fatal; at least 1 source must succeed for pipeline OK

USAGE (in run_pipeline.py Phase 2):
    from scripts.crash_guard import CrashGuard, CrashGuardError

    guard = CrashGuard(phase="phase2_fusion", timeout_per_source=300)

    @guard.protect(source="the_hacker_news")
    def ingest_thn():
        return thn_ingestor.run()

    @guard.protect(source="ioc_enforcer")
    def run_ioc_enforcer():
        return ioc_enforcer.process(manifest)

    results = guard.collect_results()  # always returns, never raises

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import functools
import json
import logging
import os
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [crash_guard] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.crash_guard")

REPO = Path(__file__).resolve().parent.parent
LEDGER_PATH = REPO / "data" / "audit" / "crash_guard_ledger.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    tmp.rename(path)


class CrashGuardError(RuntimeError):
    """Raised only when ALL sources fail and pipeline cannot continue."""


class SourceResult:
    __slots__ = ("source", "status", "result", "error", "elapsed", "timestamp")

    def __init__(
        self,
        source: str,
        status: str,
        result: Any = None,
        error: Optional[str] = None,
        elapsed: float = 0.0,
    ):
        self.source    = source
        self.status    = status   # "OK" | "FAIL" | "TIMEOUT" | "SKIP"
        self.result    = result
        self.error     = error
        self.elapsed   = elapsed
        self.timestamp = _utc_now()

    def to_dict(self) -> dict:
        return {
            "source":    self.source,
            "status":    self.status,
            "error":     self.error,
            "elapsed_s": round(self.elapsed, 3),
            "timestamp": self.timestamp,
            "has_result": self.result is not None,
        }


class CrashGuard:
    """
    Phase 2 multi-feed fusion crash isolator.

    Wraps individual source ingestion / enrichment callables so that:
      - Exceptions are caught and logged (non-fatal)
      - Timeouts are enforced per-source via daemon threads
      - A structured ledger is written after all sources complete

    Parameters
    ----------
    phase : str
        Pipeline phase label for logging/ledger
    timeout_per_source : int
        Max seconds to wait for a single source (default 300)
    min_success_required : int
        Minimum number of sources that must succeed (default 1)
    """

    def __init__(
        self,
        phase: str = "phase2_fusion",
        timeout_per_source: int = 300,
        min_success_required: int = 1,
    ):
        self.phase = phase
        self.timeout = timeout_per_source
        self.min_success = min_success_required
        self._results: list[SourceResult] = []
        self._lock = threading.Lock()
        log.info(
            "[CrashGuard] Initialized | phase=%s timeout=%ds min_ok=%d",
            phase, timeout_per_source, min_success_required,
        )

    # ── Core isolation wrapper ────────────────────────────────────────────────

    def run_isolated(
        self,
        source: str,
        fn: Callable[[], Any],
        *args: Any,
        **kwargs: Any,
    ) -> SourceResult:
        """
        Execute fn(*args, **kwargs) in a daemon thread with timeout isolation.
        Never raises. Returns a SourceResult with status OK/FAIL/TIMEOUT.
        """
        container: dict[str, Any] = {"result": None, "error": None, "done": False}

        def _worker():
            try:
                container["result"] = fn(*args, **kwargs)
                container["done"] = True
            except TypeError as e:
                # Common: 'str' object has no attribute 'get' in IOC enforcer
                container["error"] = f"TypeError [{source}]: {e}"
                container["done"] = True
            except AttributeError as e:
                container["error"] = f"AttributeError [{source}]: {e}"
                container["done"] = True
            except Exception as e:
                tb = traceback.format_exc(limit=6)
                container["error"] = f"{type(e).__name__}: {e}\n{tb}"
                container["done"] = True

        t_start = time.monotonic()
        thread = threading.Thread(target=_worker, daemon=True, name=f"cg-{source}")
        thread.start()
        thread.join(timeout=self.timeout)
        elapsed = time.monotonic() - t_start

        if not container["done"]:
            status = "TIMEOUT"
            error  = f"Source '{source}' timed out after {self.timeout}s"
            log.warning("[CrashGuard] TIMEOUT (%ds): %s", self.timeout, source)
        elif container["error"]:
            status = "FAIL"
            error  = container["error"]
            log.error("[CrashGuard] FAIL: %s | %s", source, error[:200])
        else:
            status = "OK"
            error  = None
            log.info("[CrashGuard] OK: %s (%.2fs)", source, elapsed)

        sr = SourceResult(source, status, container["result"], error, elapsed)
        with self._lock:
            self._results.append(sr)
        return sr

    def protect(self, source: str, timeout: Optional[int] = None) -> Callable:
        """
        Decorator form of run_isolated.

        Usage:
            @guard.protect(source="ioc_enforcer")
            def run_ioc():
                ...
        """
        _timeout = timeout or self.timeout

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                return self.run_isolated(source, fn, *args, **kwargs)
            return wrapper
        return decorator

    @contextmanager
    def guarded(self, source: str):
        """
        Context manager form for inline usage:

            with guard.guarded("dedup_l0") as ctx:
                dedup_engine.run_persistent()
        """
        t_start = time.monotonic()
        try:
            yield
            elapsed = time.monotonic() - t_start
            sr = SourceResult(source, "OK", elapsed=elapsed)
            with self._lock:
                self._results.append(sr)
            log.info("[CrashGuard] OK: %s (%.2fs)", source, elapsed)
        except (TypeError, AttributeError) as e:
            elapsed = time.monotonic() - t_start
            error = f"{type(e).__name__}: {e}"
            log.error("[CrashGuard] FAIL [%s]: %s", source, error)
            sr = SourceResult(source, "FAIL", error=error, elapsed=elapsed)
            with self._lock:
                self._results.append(sr)
        except Exception as e:
            elapsed = time.monotonic() - t_start
            tb = traceback.format_exc(limit=6)
            error = f"{type(e).__name__}: {e}\n{tb}"
            log.error("[CrashGuard] FAIL [%s]: %s", source, error[:300])
            sr = SourceResult(source, "FAIL", error=error, elapsed=elapsed)
            with self._lock:
                self._results.append(sr)

    # ── IOC Enforcer specific fix ─────────────────────────────────────────────

    @staticmethod
    def safe_ioc_get(ioc_entry: Any, key: str, default: Any = None) -> Any:
        """
        Type-safe getter for IOC entries.
        Fixes the recurring 'str' object has no attribute 'get' crash.
        """
        if isinstance(ioc_entry, dict):
            return ioc_entry.get(key, default)
        if isinstance(ioc_entry, str):
            # Legacy format: IOC stored as raw string value
            if key in ("value", "indicator"):
                return ioc_entry
            return default
        return default

    @staticmethod
    def safe_ioc_list(ioc_data: Any) -> list[dict]:
        """
        Normalize IOC data from any legacy format to list[dict].
        Handles: None, str, list[str], list[dict], dict.
        """
        if ioc_data is None:
            return []
        if isinstance(ioc_data, dict):
            return [ioc_data]
        if isinstance(ioc_data, str):
            return [{"value": ioc_data, "type": "unknown"}]
        if isinstance(ioc_data, list):
            normalized = []
            for item in ioc_data:
                if isinstance(item, dict):
                    normalized.append(item)
                elif isinstance(item, str):
                    normalized.append({"value": item, "type": "unknown"})
            return normalized
        return []

    # ── dedup-L0 safe wrapper ─────────────────────────────────────────────────

    @staticmethod
    def safe_dedup_l0_lookup(dedup_state: Any, key: str) -> bool:
        """
        Safe lookup into dedup-L0 persistent state.
        Fixes 'list indices must be integers or slices, not str'.
        """
        if isinstance(dedup_state, dict):
            return key in dedup_state
        if isinstance(dedup_state, list):
            # Legacy list format: convert on the fly
            return key in {item if isinstance(item, str) else str(item) for item in dedup_state}
        return False

    @staticmethod
    def safe_dedup_l0_register(dedup_state: Any, key: str) -> dict:
        """
        Safe registration into dedup-L0 state. Returns normalized dict.
        Fixes list-type dedup state causing index errors.
        """
        if isinstance(dedup_state, dict):
            dedup_state[key] = True
            return dedup_state
        if isinstance(dedup_state, list):
            # Migrate list → dict
            log.warning("[CrashGuard] Migrating dedup-L0 state from list to dict (%d entries)", len(dedup_state))
            new_state = {item: True for item in dedup_state if isinstance(item, str)}
            new_state[key] = True
            return new_state
        return {key: True}

    # ── Results & health check ────────────────────────────────────────────────

    def collect_results(self) -> list[SourceResult]:
        return list(self._results)

    def is_healthy(self) -> bool:
        ok_count = sum(1 for r in self._results if r.status == "OK")
        return ok_count >= self.min_success

    def assert_minimum_success(self) -> None:
        """Raises CrashGuardError only if ALL sources failed."""
        if not self.is_healthy():
            fail_summary = [f"{r.source}={r.status}" for r in self._results]
            raise CrashGuardError(
                f"[CrashGuard] ALL sources failed — pipeline cannot continue. "
                f"Results: {fail_summary}"
            )

    def write_ledger(self) -> None:
        """Write structured failure/success ledger for CI audit."""
        ok  = [r for r in self._results if r.status == "OK"]
        fail = [r for r in self._results if r.status != "OK"]
        payload = {
            "generated_at":   _utc_now(),
            "phase":          self.phase,
            "total_sources":  len(self._results),
            "ok_count":       len(ok),
            "fail_count":     len(fail),
            "pipeline_healthy": self.is_healthy(),
            "sources": [r.to_dict() for r in self._results],
        }
        _atomic_write(LEDGER_PATH, payload)
        log.info(
            "[CrashGuard] Ledger written: %d OK / %d FAIL → %s",
            len(ok), len(fail), LEDGER_PATH,
        )


# ── Module-level convenience guard instance (Phase 2 default) ────────────────

_DEFAULT_GUARD: Optional[CrashGuard] = None


def get_phase2_guard(timeout: int = 300) -> CrashGuard:
    """Return (or create) the module-level Phase 2 guard."""
    global _DEFAULT_GUARD
    if _DEFAULT_GUARD is None:
        _DEFAULT_GUARD = CrashGuard(phase="phase2_fusion", timeout_per_source=timeout)
    return _DEFAULT_GUARD


def reset_phase2_guard() -> None:
    """Reset guard between pipeline runs (used in testing)."""
    global _DEFAULT_GUARD
    _DEFAULT_GUARD = None


# ── Standalone CLI test ───────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info("CrashGuard self-test")
    guard = CrashGuard(phase="selftest", timeout_per_source=5)

    @guard.protect(source="ok_source")
    def good_fn():
        time.sleep(0.1)
        return {"status": "ok", "items": 42}

    @guard.protect(source="fail_source")
    def bad_fn():
        raise ValueError("Simulated source failure")

    @guard.protect(source="type_error_source")
    def type_fn():
        bad_obj = "raw_string"
        bad_obj.get("value")  # triggers 'str has no attribute get'

    @guard.protect(source="timeout_source", timeout=2)
    def slow_fn():
        time.sleep(10)   # exceeds timeout

    good_fn()
    bad_fn()
    type_fn()

    guard.write_ledger()
    print(f"\nHealthy: {guard.is_healthy()}")
    for r in guard.collect_results():
        print(f"  {r.source}: {r.status} (elapsed={r.elapsed:.3f}s)")
