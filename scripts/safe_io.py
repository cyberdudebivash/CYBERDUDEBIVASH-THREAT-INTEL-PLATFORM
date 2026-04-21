#!/usr/bin/env python3
"""
scripts/safe_io.py
CYBERDUDEBIVASH(R) SENTINEL APEX v132.3.0 -- Production SafeIO Foundation
==========================================================================
Centralised, production-grade I/O primitives for the entire pipeline.

Provides:
  AtomicWriter         -- write-temp-then-rename, post-write verify, never partial
  FileLock             -- cross-platform exclusive file lock (fcntl/msvcrt/softlock)
  SafeJSONIO           -- load/dump wrappers that never raise, with auto-heal
  SchemaValidator      -- strict schema gate for intel objects + ioc_count integrity
  DedupEngine          -- SHA-256 dedup on (title, source, published) normalised key
  PipelineMetrics      -- ingestion / failure / IOC rate collector + JSON reporter
  SystemHealthMonitor  -- autonomic health state machine: HEALTHY/DEGRADED/CRITICAL
                          auto-throttle, health score, persistent state, API export

Usage:
  from scripts.safe_io import (
      atomic_json_write, safe_json_load, safe_json_dump,
      validate_intel_object, dedup_items, PipelineMetrics, acquire_lock,
      enforce_schema, enforce_schema_list,
      WriteQueue, retry_write, WriteHardFail, WRITE_SOFT_FAIL, _store_write_failure,
      MAX_CONCURRENT_WRITES, WRITE_DELAY_MS, BACKPRESSURE_THRESHOLD,
      SystemHealthMonitor,
      SYSTEM_STATE_HEALTHY, SYSTEM_STATE_DEGRADED, SYSTEM_STATE_CRITICAL,
      DEGRADED_QUEUE_THRESHOLD, DEGRADED_RECOVERY_THRESHOLD,
      CRITICAL_RECOVERY_THRESHOLD, CRITICAL_DEGRADED_RUNS,
      THROTTLE_MAX_CONCURRENT_WRITES, THROTTLE_WRITE_DELAY_MS,
  )

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import random
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

log = logging.getLogger("sentinel.safe_io")

# ---------------------------------------------------------------------------
# Platform-aware file lock
# ---------------------------------------------------------------------------

class FileLock:
    """
    Cross-platform exclusive file lock.
    - POSIX  (GitHub Actions / Linux CI): uses fcntl.flock — kernel-enforced.
    - Windows (local dev): uses msvcrt.locking — process-level.
    - Fallback: soft-lock via .lock sentinel file (last resort).
    """

    def __init__(self, path: Path, timeout: float = 120.0, poll: float = 0.1):
        self._path = Path(str(path) + ".lock")
        self._timeout = timeout
        self._poll = poll
        self._fh = None
        self._soft = False

    def acquire(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self._timeout

        if sys.platform != "win32":
            # POSIX: fcntl.flock -- blocking with timeout via non-blocking poll
            import fcntl
            self._fh = open(self._path, "w", encoding="utf-8")
            while time.monotonic() < deadline:
                try:
                    fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return
                except BlockingIOError:
                    # Jitter before retry: prevents lock thundering-herd under batch load
                    time.sleep(self._poll + random.uniform(0.1, 0.5))
            self._fh.close()
            raise TimeoutError(f"FileLock timeout after {self._timeout}s on {self._path}")
        else:
            # Windows: soft lock via sentinel file
            while time.monotonic() < deadline:
                try:
                    fd = os.open(str(self._path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                    os.write(fd, str(os.getpid()).encode())
                    os.close(fd)
                    self._soft = True
                    return
                except FileExistsError:
                    # Jitter before retry
                    time.sleep(self._poll + random.uniform(0.1, 0.5))
            raise TimeoutError(f"FileLock timeout after {self._timeout}s on {self._path}")

    def release(self) -> None:
        if sys.platform != "win32" and self._fh:
            import fcntl
            try:
                fcntl.flock(self._fh, fcntl.LOCK_UN)
            except Exception:
                pass
            finally:
                self._fh.close()
                self._fh = None
        if self._soft and self._path.exists():
            try:
                self._path.unlink()
            except Exception:
                pass

    def __enter__(self) -> "FileLock":
        self.acquire()
        return self

    def __exit__(self, *_: Any) -> None:
        self.release()


@contextlib.contextmanager
def acquire_lock(path: Path, timeout: float = 120.0) -> Iterator[FileLock]:
    """Context manager wrapper for FileLock."""
    lock = FileLock(path, timeout=timeout)
    lock.acquire()
    try:
        yield lock
    finally:
        lock.release()


# ---------------------------------------------------------------------------
# Atomic Writer
# ---------------------------------------------------------------------------

def atomic_json_write(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
    ensure_ascii: bool = False,
    verify: bool = True,
    locked: bool = True,
) -> int:
    """
    Write JSON to `path` atomically:
      1. Serialise to string (raises TypeError on bad data).
      2. Write to <path>.tmp (isolated, never partial).
      3. Verify the .tmp is parseable (catches silent corruption).
      4. os.replace() -- atomic on POSIX, best-effort on Windows.
      5. Return bytes written.

    If `locked=True` uses FileLock to prevent concurrent writers.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        content = json.dumps(data, ensure_ascii=ensure_ascii, indent=indent, default=str)
    except (TypeError, ValueError) as e:
        raise ValueError(f"atomic_json_write: serialisation failed for {path.name}: {e}") from e

    tmp = path.with_suffix(path.suffix + ".tmp")

    def _do_write() -> int:
        tmp.write_text(content, encoding="utf-8")
        # SAFETY: verify tmp exists on disk before attempting replace
        if not tmp.exists():
            raise OSError(f"atomic_json_write: tmp file vanished before replace: {tmp}")
        if verify:
            parsed = json.loads(tmp.read_text(encoding="utf-8"))
            # Light sanity: same top-level type
            if type(parsed) is not type(data):
                raise ValueError(
                    f"Post-write type mismatch: expected {type(data).__name__}, "
                    f"got {type(parsed).__name__}"
                )
        # Atomic rename — fallback to direct write if os.replace fails (NFS/Windows edge)
        try:
            os.replace(str(tmp), str(path))
        except OSError as _replace_err:
            log.warning(
                "atomic_json_write: os.replace failed (%s) — falling back to direct write",
                _replace_err,
            )
            # Direct write fallback: still atomic enough for recovery scenarios
            path.write_text(content, encoding="utf-8")
            try:
                tmp.unlink(missing_ok=True)
            except Exception:
                pass
        sz = path.stat().st_size
        log.debug("atomic_json_write: %s | %d bytes", path.name, sz)
        return sz

    try:
        if locked:
            with acquire_lock(path):
                return _do_write()
        else:
            return _do_write()
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        raise


# ---------------------------------------------------------------------------
# Write Recovery Paths
# ---------------------------------------------------------------------------

_WRITE_FAILURE_DIR: Optional[Path] = None
_WRITE_FAILURE_LOG: Optional[Path] = None


def _resolve_recovery_paths(repo_root: Optional[Path] = None) -> None:
    """
    Resolve write-failure recovery directories relative to repo root.
    Called once at module import or first use.
    """
    global _WRITE_FAILURE_DIR, _WRITE_FAILURE_LOG
    if _WRITE_FAILURE_DIR is not None:
        return
    root = repo_root or Path(__file__).resolve().parent.parent
    _WRITE_FAILURE_DIR = root / "data" / "recovery" / "write_failures"
    _WRITE_FAILURE_LOG = root / "data" / "logs" / "write_failures.jsonl"


def _store_write_failure(
    path: Path,
    exc: Exception,
    payload: Any = None,
    *,
    repo_root: Optional[Path] = None,
) -> None:
    """
    Persist a failed write payload so no data is lost on permanent write failure.
    - Saves payload JSON to data/recovery/write_failures/<timestamp>_<stem>.json
    - Appends a JSONL record to data/logs/write_failures.jsonl
    Never raises — this is a best-effort safety net.
    """
    _resolve_recovery_paths(repo_root)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    stem = Path(str(path)).stem[:60].replace("/", "_").replace("\\", "_")
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "target_path": str(path),
        "error": str(exc),
        "error_type": type(exc).__name__,
    }
    # Save payload blob — embed recovery metadata for ReplayEngine
    if _WRITE_FAILURE_DIR is not None:
        try:
            _WRITE_FAILURE_DIR.mkdir(parents=True, exist_ok=True)
            blob_path = _WRITE_FAILURE_DIR / f"{ts}_{stem}.json"
            # Build blob: recovery metadata keys + flattened payload (for ReplayEngine)
            blob: Dict[str, Any] = {
                "_recovery_target": str(path),     # target path for replay
                "_recovery_error": str(exc),
                "_recovery_timestamp": record["timestamp"],
                "_recovery_attempt": 0,             # incremented by ReplayEngine on each retry
            }
            if isinstance(payload, dict):
                # Merge payload into blob (metadata keys take precedence)
                blob = {**payload, **blob}
            elif payload is not None:
                blob["_payload_data"] = payload     # non-dict payload stored under _payload_data
            blob_path.write_text(
                json.dumps(blob, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            record["recovery_blob"] = str(blob_path)
            log.warning("_store_write_failure: payload saved -> %s", blob_path.name)
        except Exception as save_err:
            log.error("_store_write_failure: could not save payload blob: %s", save_err)
    # Append JSONL log
    if _WRITE_FAILURE_LOG is not None:
        try:
            _WRITE_FAILURE_LOG.parent.mkdir(parents=True, exist_ok=True)
            with open(_WRITE_FAILURE_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except Exception as log_err:
            log.error("_store_write_failure: JSONL append failed: %s", log_err)


# ---------------------------------------------------------------------------
# v132.2 Write Pressure Hardening — Global Semaphore + Constants
# ---------------------------------------------------------------------------

# WRITE THROTTLING: Maximum concurrent writes allowed at any time.
# Prevents file-descriptor exhaustion and lock thundering-herd under batch load.
MAX_CONCURRENT_WRITES: int = 3

# Mandatory inter-write delay (milliseconds). Prevents burst write saturation.
WRITE_DELAY_MS: int = 50

# WriteQueue backpressure threshold — warn if queue depth exceeds this.
BACKPRESSURE_THRESHOLD: int = 50

# GLOBAL WRITE SEMAPHORE — wraps ALL write operations.
# Enforces at most MAX_CONCURRENT_WRITES simultaneous writers across the pipeline.
_WRITE_SEMAPHORE = threading.Semaphore(MAX_CONCURRENT_WRITES)

# ---------------------------------------------------------------------------
# v132.3 Autonomic Layer — System State Constants + Thresholds
# ---------------------------------------------------------------------------

# System health states (ordered: HEALTHY < DEGRADED < CRITICAL)
SYSTEM_STATE_HEALTHY  = "HEALTHY"
SYSTEM_STATE_DEGRADED = "DEGRADED"
SYSTEM_STATE_CRITICAL = "CRITICAL"

# Backpressure thresholds that trigger DEGRADED state
DEGRADED_QUEUE_THRESHOLD: int = BACKPRESSURE_THRESHOLD  # 50 — queue_depth triggers DEGRADED
DEGRADED_RECOVERY_THRESHOLD: int = 20                   # recovery_count triggers DEGRADED

# Escalation thresholds that trigger CRITICAL state
CRITICAL_RECOVERY_THRESHOLD: int = 100  # recovery_count triggers CRITICAL
CRITICAL_DEGRADED_RUNS: int = 3         # consecutive DEGRADED runs before CRITICAL

# Throttle values applied automatically when system enters DEGRADED state
THROTTLE_MAX_CONCURRENT_WRITES: int = 1    # reduce from 3 → 1
THROTTLE_WRITE_DELAY_MS: int = 200         # increase from 50ms → 200ms

# Health score formula weights (v134):
#   health = 100 - (write_failures*2) - (retries*0.5) - (queue_depth*1) - (recovery_count*2)
HEALTH_SCORE_WRITE_FAILURE_PENALTY: float = 2.0
HEALTH_SCORE_RETRY_PENALTY: float = 0.5
HEALTH_SCORE_QUEUE_DEPTH_PENALTY: float = 1.0
HEALTH_SCORE_RECOVERY_PENALTY: float = 2.0   # v134: recovery_count penalised same as write failures

# ---------------------------------------------------------------------------
# v132.3 Dynamic Throttle Globals — mutated at runtime by SystemHealthMonitor
# ---------------------------------------------------------------------------

# NOTE: These are runtime-mutable. _apply_throttle() / _restore_throttle() modify
# them and replace _WRITE_SEMAPHORE to enforce new concurrency limits immediately.
_current_max_concurrent_writes: int = MAX_CONCURRENT_WRITES
_current_write_delay_ms: int = WRITE_DELAY_MS
_throttle_active: bool = False
_SEMAPHORE_LOCK: threading.Lock = threading.Lock()


def _apply_throttle() -> bool:
    """
    Apply write throttle: MAX_CONCURRENT_WRITES → 1, WRITE_DELAY_MS → 200ms.
    Replaces global _WRITE_SEMAPHORE with a new Semaphore(1).
    Thread-safe. Returns True if throttle was newly applied (False if already active).
    """
    global _WRITE_SEMAPHORE, _current_max_concurrent_writes, _current_write_delay_ms, _throttle_active
    with _SEMAPHORE_LOCK:
        if _throttle_active:
            return False
        _current_max_concurrent_writes = THROTTLE_MAX_CONCURRENT_WRITES
        _current_write_delay_ms = THROTTLE_WRITE_DELAY_MS
        _WRITE_SEMAPHORE = threading.Semaphore(THROTTLE_MAX_CONCURRENT_WRITES)
        _throttle_active = True
    log.critical(
        "_apply_throttle: DEGRADED MODE — concurrent writes capped at %d, delay=%dms",
        THROTTLE_MAX_CONCURRENT_WRITES, THROTTLE_WRITE_DELAY_MS,
    )
    return True


def _restore_throttle() -> bool:
    """
    Restore normal write throughput: MAX_CONCURRENT_WRITES=3, WRITE_DELAY_MS=50ms.
    Thread-safe. Returns True if throttle was restored (False if already normal).
    """
    global _WRITE_SEMAPHORE, _current_max_concurrent_writes, _current_write_delay_ms, _throttle_active
    with _SEMAPHORE_LOCK:
        if not _throttle_active:
            return False
        _current_max_concurrent_writes = MAX_CONCURRENT_WRITES
        _current_write_delay_ms = WRITE_DELAY_MS
        _WRITE_SEMAPHORE = threading.Semaphore(MAX_CONCURRENT_WRITES)
        _throttle_active = False
    log.info("_restore_throttle: NORMAL MODE restored — concurrent writes=%d, delay=%dms",
             MAX_CONCURRENT_WRITES, WRITE_DELAY_MS)
    return True

# Soft-fail sentinel — returned by retry_write() on permanent failure (raise_on_exhaustion=False).
# Distinguishes "callable returned None (success)" from "all retries exhausted (soft-fail)".
# Callers check:  if result is WRITE_SOFT_FAIL:  ...
class _WriteSoftFailType:
    """Singleton sentinel indicating retry_write() permanent failure (soft-fail path)."""
    _instance: "Optional[_WriteSoftFailType]" = None
    def __new__(cls) -> "_WriteSoftFailType":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    def __repr__(self) -> str:
        return "WRITE_SOFT_FAIL"
    def __bool__(self) -> bool:
        return False  # falsy so `if result:` patterns treat failure as falsy

WRITE_SOFT_FAIL = _WriteSoftFailType()  # the singleton sentinel


# ---------------------------------------------------------------------------
# Retry Write — Exponential Backoff + Jitter + Soft-Fail (MANDATORY)
# ---------------------------------------------------------------------------

class WriteHardFail(RuntimeError):
    """
    Retained for test-suite compatibility.
    retry_write() no longer raises this — permanent failures soft-fail to recovery.
    """


def retry_write(
    fn: Callable[[], Any],
    *,
    attempts: int = 10,
    base_delay: float = 0.1,
    path: Optional[Path] = None,
    payload: Any = None,
    raise_on_exhaustion: bool = False,
) -> Any:
    """
    v132.2 WRITE PRESSURE HARDENING — Retry with full exponential backoff + jitter.

    Changes vs v132.1:
      - attempts: 5 → 10 (10 total attempts before permanent failure)
      - backoff: linear → full exponential (base_delay * 2^attempt)
      - jitter: added (random.uniform(0, base_delay * 0.5)) to prevent thundering-herd
      - soft-fail: permanent failures STORE TO RECOVERY, do NOT raise by default
        (pipeline continues — nothing is lost)

    Args:
        fn:                 Zero-argument callable that performs the write.
        attempts:           Total attempts (default 10).
        base_delay:         Base delay seconds; actual = base_delay * 2^attempt + jitter.
        path:               Target file path (for fail-safe buffer and logging).
        payload:            Data payload (stored in recovery buffer on perm failure).
        raise_on_exhaustion: If True, raise WriteHardFail after exhaustion (for tests).
                            Default False — soft-fail, pipeline continues.

    Returns:
        Write result on success, None on permanent failure (soft-fail).
    """
    last_exc: Exception = RuntimeError("retry_write: no attempts made")
    for attempt in range(attempts):
        try:
            result = fn()
            if attempt > 0:
                log.info(
                    "retry_write: SUCCESS on attempt %d/%d for %s",
                    attempt + 1, attempts,
                    Path(str(path)).name if path else "?",
                )
            return result
        except Exception as exc:
            last_exc = exc
            # Full exponential backoff with jitter — prevents synchronized retries
            exp_delay = base_delay * (2 ** attempt)
            jitter = random.uniform(0, base_delay * 0.5)
            delay = min(exp_delay + jitter, 2.0)  # cap at 2s per attempt
            log.warning(
                "retry_write: attempt %d/%d failed for %s: %s (retry in %.2fs)",
                attempt + 1, attempts,
                Path(str(path)).name if path else "?",
                exc, delay,
            )
            if attempt < attempts - 1:
                time.sleep(delay)

    # ── ALL ATTEMPTS EXHAUSTED ──────────────────────────────────────────────
    # SOFT FAIL: store payload for recovery, log error, return None.
    # Pipeline CONTINUES — no data lost, no crash.
    log.error(
        "retry_write: PERMANENT FAILURE after %d attempts for %s: %s — "
        "payload stored to recovery buffer, pipeline continues",
        attempts, path, last_exc,
    )
    _store_write_failure(path or Path("unknown"), last_exc, payload)

    if raise_on_exhaustion:
        raise WriteHardFail(
            f"retry_write: all {attempts} attempts failed for {path}: {last_exc}"
        ) from last_exc

    # Return WRITE_SOFT_FAIL sentinel — distinguishes from callable returning None (success).
    # Callers: `if result is WRITE_SOFT_FAIL: handle_recovery()`
    return WRITE_SOFT_FAIL


# ---------------------------------------------------------------------------
# WriteQueue — Centralized Single-Writer Enforcement
# ---------------------------------------------------------------------------

class WriteQueue:
    """
    v132.2 WRITE PRESSURE HARDENED Centralized Write Queue for SENTINEL APEX.

    ALL writes to data/stix/*, data/intel/*, data/api/*, feed_manifest.json
    MUST go through this queue.  Writes are enqueued as callables and flushed
    ONLY at controlled stage boundaries via flush().

    v132.2 Additions:
      - Global write semaphore (MAX_CONCURRENT_WRITES=3) prevents write saturation
      - WRITE_DELAY_MS=50 inter-write sleep prevents burst write pressure
      - Backpressure warning when queue depth > BACKPRESSURE_THRESHOLD
      - Post-flush barrier: checks stale .tmp files + queue emptiness
      - Barrier failure → retry flush once (self-healing)
      - write_queue_depth exposed in metrics_snapshot()
      - recovery_count tracks soft-failed items stored to recovery buffer

    Thread-safety: all mutable state protected by threading.Lock.
    """

    _queue: List[Callable[[], Any]] = []
    _lock: threading.Lock = threading.Lock()

    # Metrics
    _write_latency_ms: List[float] = []
    _write_failures: int = 0
    _retry_count: int = 0
    _recovery_count: int = 0    # items soft-failed to recovery buffer

    @classmethod
    def enqueue(cls, write_fn: Callable[[], Any]) -> None:
        """
        Append a write callable to the queue.
        Logs backpressure warning if queue depth exceeds BACKPRESSURE_THRESHOLD.
        """
        with cls._lock:
            cls._queue.append(write_fn)
            depth = len(cls._queue)

        if depth > BACKPRESSURE_THRESHOLD:
            log.warning(
                "WriteQueue.enqueue: BACKPRESSURE — queue depth %d > threshold %d. "
                "Ingestion will pause at next flush().",
                depth, BACKPRESSURE_THRESHOLD,
            )

    @classmethod
    def _execute_one(
        cls,
        fn: Callable[[], Any],
        i: int,
        total: int,
        attempts: int,
        base_delay: float,
    ) -> bool:
        """
        Execute a single write callable under the global semaphore.
        Returns True on success, False on soft-fail (stored to recovery).
        """
        t0 = time.monotonic()
        with _WRITE_SEMAPHORE:
            result = retry_write(
                fn,
                attempts=attempts,
                base_delay=base_delay,
                raise_on_exhaustion=False,  # soft-fail — never crash pipeline
            )
        latency_ms = (time.monotonic() - t0) * 1000
        with cls._lock:
            cls._write_latency_ms.append(latency_ms)

        if result is WRITE_SOFT_FAIL:
            # retry_write returned WRITE_SOFT_FAIL sentinel → permanent failure,
            # recovery payload already stored by retry_write()
            with cls._lock:
                cls._write_failures += 1
                cls._recovery_count += 1
            log.warning(
                "WriteQueue._execute_one: item %d/%d → SOFT FAIL (stored to recovery, pipeline continues)",
                i + 1, total,
            )
            return False
        else:
            log.debug("WriteQueue._execute_one: item %d/%d OK (%.1fms)", i + 1, total, latency_ms)
            return True

    @classmethod
    def flush(
        cls,
        *,
        attempts: int = 10,
        base_delay: float = 0.1,
    ) -> Dict[str, Any]:
        """
        v132.2 HARDENED FLUSH — Execute all queued write callables with:
          - Global semaphore throttling (MAX_CONCURRENT_WRITES=3)
          - WRITE_DELAY_MS inter-write sleep (50ms between writes)
          - Soft-fail: permanent failures go to recovery, never crash pipeline
          - Post-flush barrier: assert queue empty + no stale .tmp files
          - Self-healing: if barrier fails, retry flush once

        Returns metrics dict: {queued, succeeded, failed, recovery_count, total_latency_ms}.
        """
        with cls._lock:
            queue_snapshot = list(cls._queue)
            cls._queue.clear()

        if not queue_snapshot:
            log.debug("WriteQueue.flush: queue empty — nothing to flush")
            return {"queued": 0, "succeeded": 0, "failed": 0, "recovery_count": 0, "total_latency_ms": 0.0}

        total = len(queue_snapshot)
        succeeded = 0
        failed = 0
        t_flush_start = time.monotonic()

        log.info(
            "WriteQueue.flush: starting — %d items | semaphore=%d | delay=%dms | max_attempts=%d%s",
            total, _current_max_concurrent_writes, _current_write_delay_ms, attempts,
            " [THROTTLED]" if _throttle_active else "",
        )

        for i, fn in enumerate(queue_snapshot):
            ok = cls._execute_one(fn, i, total, attempts, base_delay)
            if ok:
                succeeded += 1
            else:
                failed += 1

            # ── INTER-WRITE THROTTLE ──────────────────────────────────────
            # Mandatory delay between writes to prevent burst saturation.
            # Uses _current_write_delay_ms which is dynamically increased when DEGRADED.
            # Skip delay after the last item.
            if i < total - 1:
                time.sleep(_current_write_delay_ms / 1000.0)

        total_latency_ms = (time.monotonic() - t_flush_start) * 1000

        # ── POST-FLUSH BARRIER ────────────────────────────────────────────
        # Assert: queue is empty, no stale .tmp files left behind.
        # If stale .tmp files found → attempt cleanup + warn (non-fatal).
        barrier_ok = cls._post_flush_barrier()
        if not barrier_ok:
            log.warning(
                "WriteQueue.flush: post-flush barrier failed — "
                "attempting second flush pass for any re-queued items"
            )
            # Retry flush: drain any items that got re-enqueued due to barrier issues
            with cls._lock:
                retry_queue = list(cls._queue)
                cls._queue.clear()
            for i, fn in enumerate(retry_queue):
                ok = cls._execute_one(fn, i, len(retry_queue), attempts, base_delay)
                if ok:
                    succeeded += 1
                else:
                    failed += 1

        log.info(
            "WriteQueue.flush: COMPLETE — queued=%d succeeded=%d failed=%d "
            "recovery=%d latency=%.1fms",
            total, succeeded, failed, failed, round(total_latency_ms, 2),
        )
        if failed > 0:
            log.warning(
                "WriteQueue.flush: %d item(s) stored to recovery buffer — "
                "data preserved at data/recovery/write_failures/ — pipeline continues",
                failed,
            )

        return {
            "queued": total,
            "succeeded": succeeded,
            "failed": failed,
            "recovery_count": failed,
            "total_latency_ms": round(total_latency_ms, 2),
        }

    @classmethod
    def _post_flush_barrier(cls) -> bool:
        """
        Post-flush barrier check:
          1. Assert internal queue is empty (no re-enqueue race condition)
          2. Scan for stale .tmp files in data/ and reports/ (cleanup if found)

        Returns True if clean, False if issues found (caller should retry flush).
        """
        issues = []

        # Check queue is drained
        with cls._lock:
            remaining = len(cls._queue)
        if remaining > 0:
            issues.append(f"queue has {remaining} un-flushed items after flush()")
            log.warning("WriteQueue._post_flush_barrier: %d items still in queue after flush", remaining)

        # Scan for stale .tmp write artifacts
        try:
            _resolve_recovery_paths()
            if _WRITE_FAILURE_LOG is not None:
                repo_root = _WRITE_FAILURE_LOG.parent.parent.parent
                stale_tmp = []
                for scan_dir in (repo_root / "data", repo_root / "reports"):
                    if scan_dir.exists():
                        stale_tmp.extend(scan_dir.rglob("*.tmp"))
                if stale_tmp:
                    issues.append(f"{len(stale_tmp)} stale .tmp file(s) found")
                    log.warning("WriteQueue._post_flush_barrier: %d stale .tmp file(s) — attempting cleanup", len(stale_tmp))
                    for tmp_file in stale_tmp:
                        try:
                            tmp_file.unlink(missing_ok=True)
                            log.debug("WriteQueue._post_flush_barrier: removed stale %s", tmp_file.name)
                        except Exception as e:
                            log.warning("WriteQueue._post_flush_barrier: could not remove %s: %s", tmp_file.name, e)
        except Exception as e:
            log.debug("WriteQueue._post_flush_barrier: barrier scan error (non-fatal): %s", e)

        if issues:
            log.warning("WriteQueue._post_flush_barrier: %d issue(s): %s", len(issues), "; ".join(issues))
            return False

        log.debug("WriteQueue._post_flush_barrier: CLEAN — queue empty, no stale .tmp files")
        return True

    @classmethod
    def metrics_snapshot(cls) -> Dict[str, Any]:
        """Return current write queue metrics including live queue depth."""
        with cls._lock:
            latencies = list(cls._write_latency_ms)
            failures = cls._write_failures
            recovery = cls._recovery_count
            queue_depth = len(cls._queue)
        avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        p99_lat = (
            round(sorted(latencies)[int(len(latencies) * 0.99)], 2)
            if len(latencies) >= 100
            else (max(latencies) if latencies else 0.0)
        )
        return {
            "write_count": len(latencies),
            "write_failures": failures,
            "recovery_count": recovery,
            "write_queue_depth": queue_depth,
            "write_latency_avg_ms": avg_lat,
            "write_latency_p99_ms": p99_lat,
        }

    @classmethod
    def reset(cls) -> None:
        """Reset queue and metrics — for testing only."""
        with cls._lock:
            cls._queue.clear()
            cls._write_latency_ms.clear()
            cls._write_failures = 0
            cls._retry_count = 0
            cls._recovery_count = 0


# ---------------------------------------------------------------------------
# Safe JSON I/O (never raises in production)
# ---------------------------------------------------------------------------

def safe_json_load(
    path: Path,
    default: Any = None,
    *,
    auto_heal: bool = True,
    heal_value: Any = None,
) -> Any:
    """
    Load JSON from path. Never raises.
    - Missing / empty file  -> return default
    - Invalid JSON          -> if auto_heal: overwrite with heal_value; return default
    - Valid JSON            -> return parsed object
    """
    path = Path(path)
    if not path.exists():
        log.debug("safe_json_load: %s not found — returning default", path.name)
        return default
    sz = path.stat().st_size
    if sz == 0:
        log.debug("safe_json_load: %s empty — returning default", path.name)
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        log.warning("safe_json_load: %s corrupt (%s)", path.name, e)
        if auto_heal:
            _fallback = heal_value if heal_value is not None else default
            try:
                path.write_text(
                    json.dumps(_fallback if _fallback is not None else []),
                    encoding="utf-8",
                )
                log.warning("safe_json_load: auto-healed %s -> %r", path.name, _fallback)
            except Exception as he:
                log.error("safe_json_load: auto-heal write failed: %s", he)
        return default
    except Exception as e:
        log.error("safe_json_load: unexpected error reading %s: %s", path.name, e)
        return default


def safe_json_dump(path: Path, data: Any, *, indent: int = 2, locked: bool = True) -> bool:
    """
    Write JSON atomically. Returns True on success, False on failure. Never raises.
    """
    try:
        atomic_json_write(path, data, indent=indent, locked=locked)
        return True
    except Exception as e:
        log.error("safe_json_dump: failed writing %s: %s", path, e)
        return False


# ---------------------------------------------------------------------------
# Intel Object Schema Validator
# ---------------------------------------------------------------------------

# Minimum required fields for a valid intel advisory object
INTEL_REQUIRED_FIELDS: Dict[str, type] = {
    "title":       str,
    "source":      str,
}

# Fields that, if present, must be specific types
INTEL_TYPE_CONSTRAINTS: Dict[str, type] = {
    "risk_score":  (int, float),
    "iocs":        list,
    "ioc_count":   (int, type(None)),
    "severity":    str,
    "timestamp":   str,
    "published":   str,   # must be a string (ISO-8601), NOT a boolean
    "cve_ids":     list,
}

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", ""}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}$", re.I)

# IOC pattern matchers
_IOC_PATTERNS = [
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),                    # IPv4
    re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"),# IPv6
    re.compile(r"\b[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}\b"),               # domain
    re.compile(r"\b[0-9a-fA-F]{32,64}\b"),                          # hash (MD5/SHA)
    re.compile(r"https?://[^\s\"'<>]+"),                             # URL
]


class ValidationError(Exception):
    """Raised by SchemaValidator when an intel object fails validation."""


class SchemaValidator:
    """
    Strict schema validator for intel advisory objects.
    Enforces:
      - Required fields present and correct type
      - ioc_count == len(iocs) when both present
      - published is a string (never a boolean -- P0 regression fix)
      - severity is a known value
      - risk_score in [0, 10]
    """

    def __init__(self, strict: bool = True):
        self.strict = strict
        self._errors: List[str] = []

    def validate(self, obj: Dict, idx: int = 0) -> List[str]:
        """Validate a single intel object. Returns list of error strings."""
        errors: List[str] = []

        if not isinstance(obj, dict):
            errors.append(f"[{idx}] Not a dict: {type(obj).__name__}")
            return errors

        # Required fields
        for field, expected_type in INTEL_REQUIRED_FIELDS.items():
            val = obj.get(field)
            if val is None or val == "":
                errors.append(f"[{idx}] Missing required field '{field}'")
            elif not isinstance(val, expected_type):
                errors.append(
                    f"[{idx}] '{field}' must be {expected_type.__name__}, "
                    f"got {type(val).__name__}"
                )

        # Type constraints
        for field, expected in INTEL_TYPE_CONSTRAINTS.items():
            val = obj.get(field)
            if val is None:
                continue
            expected_types = expected if isinstance(expected, tuple) else (expected,)
            if not isinstance(val, expected_types):
                errors.append(
                    f"[{idx}] '{field}' wrong type: expected "
                    f"{'/'.join(t.__name__ for t in expected_types)}, "
                    f"got {type(val).__name__}"
                )

        # ioc_count integrity
        iocs = obj.get("iocs")
        ioc_count = obj.get("ioc_count")
        if isinstance(iocs, list) and ioc_count is not None:
            if isinstance(ioc_count, int) and ioc_count != len(iocs):
                errors.append(
                    f"[{idx}] ioc_count mismatch: declared {ioc_count}, "
                    f"actual len(iocs)={len(iocs)}"
                )

        # published must NOT be a boolean
        pub = obj.get("published")
        if isinstance(pub, bool):
            errors.append(
                f"[{idx}] 'published' is boolean ({pub}) — must be ISO-8601 string. "
                "This was the root cause of run #793 AttributeError."
            )

        # severity
        sev = obj.get("severity", "")
        if sev and sev not in VALID_SEVERITIES:
            errors.append(f"[{idx}] Invalid severity '{sev}'")

        # risk_score range
        rs = obj.get("risk_score")
        if rs is not None:
            try:
                rsf = float(rs)
                if not (0.0 <= rsf <= 10.0):
                    errors.append(f"[{idx}] risk_score {rs} out of range [0,10]")
            except (TypeError, ValueError):
                errors.append(f"[{idx}] risk_score '{rs}' not numeric")

        return errors

    def validate_manifest(
        self, items: List[Dict]
    ) -> Tuple[List[Dict], List[str]]:
        """
        Validate a list of intel objects.
        Returns (valid_items, all_errors).
        """
        valid: List[Dict] = []
        all_errors: List[str] = []
        for i, obj in enumerate(items):
            errs = self.validate(obj, i)
            if errs:
                all_errors.extend(errs)
                if not self.strict:
                    # In lenient mode: fix what we can and keep the item
                    obj = _auto_fix_intel_object(obj)
                    valid.append(obj)
            else:
                valid.append(obj)
        return valid, all_errors


def _auto_fix_intel_object(obj: Dict) -> Dict:
    """
    Best-effort auto-fix for common intel object issues.
    Called in lenient mode after validation fails.
    """
    obj = dict(obj)  # shallow copy

    # Fix boolean published -> convert to ISO string
    if isinstance(obj.get("published"), bool):
        obj["published"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Fix ioc_count mismatch
    iocs = obj.get("iocs")
    if isinstance(iocs, list):
        obj["ioc_count"] = len(iocs)

    # Ensure title and source are strings
    for field in ("title", "source"):
        if not isinstance(obj.get(field), str):
            obj[field] = str(obj.get(field, ""))

    # Clamp risk_score
    rs = obj.get("risk_score")
    if rs is not None:
        try:
            rsf = max(0.0, min(10.0, float(rs)))
            obj["risk_score"] = round(rsf, 2)
        except (TypeError, ValueError):
            obj["risk_score"] = 5.0

    return obj


def validate_intel_object(obj: Dict, idx: int = 0, strict: bool = True) -> List[str]:
    """Convenience wrapper: validate a single intel object, return error list."""
    return SchemaValidator(strict=strict).validate(obj, idx)


# ---------------------------------------------------------------------------
# Global Schema Enforcement (Write Boundary — MANDATORY before every write)
# ---------------------------------------------------------------------------

# All string fields that must NEVER be boolean or non-string types
_STRING_FIELDS: Tuple[str, ...] = (
    "title", "source", "description", "summary", "severity",
    "published", "timestamp", "processed_at", "stix_id",
    "threat_type", "actor_tag", "primary_actor", "campaign_id",
    "tlp", "feed_source", "nvd_url", "source_url",
)

# Fields that must be list type
_LIST_FIELDS: Tuple[str, ...] = (
    "iocs", "cve_ids", "tags", "ttps", "mitre_tactics",
    "affected_products", "kill_chain_phases",
)

# Required fields (must be present and non-empty string)
_REQUIRED_FIELDS: Tuple[str, ...] = ("title", "source")


def enforce_schema(entry: Dict) -> Dict:
    """
    GLOBAL SCHEMA ENFORCEMENT — called at EVERY write boundary.

    Guarantees:
      1. published: bool → ISO-8601 string (P0 regression fix — run #805)
      2. ioc_count == len(iocs) always (hard invariant)
      3. All string fields are str type (never bool/int/None)
      4. All list fields are list type (never None)
      5. risk_score clamped to [0, 10]
      6. severity normalised to uppercase known value
      7. required fields (title, source) always non-empty string

    Returns a shallow copy — original is never mutated.
    Safe to call on every entry unconditionally.
    """
    entry = dict(entry)  # shallow copy — never mutate originals

    # 1. Fix boolean/non-string fields → coerce to string
    _utc_now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for field in _STRING_FIELDS:
        val = entry.get(field)
        if isinstance(val, bool):
            # Boolean fields: published=True/False is the documented P0 regression
            if field == "published":
                entry[field] = _utc_now  # replace with current ISO timestamp
                log.warning("enforce_schema: 'published' was bool(%s) — replaced with ISO timestamp", val)
            else:
                # Other bool fields: stringify to avoid AttributeError on .upper()/.lower() etc.
                entry[field] = str(val)
                log.warning("enforce_schema: '%s' was bool(%s) — coerced to str", field, val)
        elif val is None:
            # published must always be a valid ISO string — supply UTC now if absent/None
            if field == "published":
                entry[field] = _utc_now
            # All other optional string fields: leave absent rather than inject empty strings
        elif not isinstance(val, str):
            entry[field] = str(val)

    # 2. Normalise severity to uppercase known set
    sev = entry.get("severity")
    if sev is not None:
        sev_str = str(sev).upper().strip()
        if sev_str not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "INFO", ""):
            sev_str = "UNKNOWN"
        entry["severity"] = sev_str

    # 3. Ensure list fields are actually lists
    for field in _LIST_FIELDS:
        val = entry.get(field)
        if val is None:
            entry[field] = []
        elif not isinstance(val, list):
            # Wrap scalars in list, discard non-iterable garbage
            try:
                entry[field] = list(val)
            except TypeError:
                entry[field] = []

    # 4. ioc_count == len(iocs) — hard invariant
    iocs = entry.get("iocs", [])
    if not isinstance(iocs, list):
        iocs = []
        entry["iocs"] = iocs
    ioc_count = len(iocs)
    if entry.get("ioc_count") != ioc_count:
        log.debug(
            "enforce_schema: ioc_count mismatch corrected (%s → %d)",
            entry.get("ioc_count"), ioc_count,
        )
    entry["ioc_count"] = ioc_count

    # 5. Clamp risk_score to [0, 10]
    rs = entry.get("risk_score")
    if rs is not None:
        try:
            entry["risk_score"] = round(max(0.0, min(10.0, float(rs))), 2)
        except (TypeError, ValueError):
            entry["risk_score"] = 5.0

    # 6. Required fields — ensure non-empty string
    for field in _REQUIRED_FIELDS:
        val = entry.get(field)
        if not val or not str(val).strip():
            entry[field] = f"UNKNOWN_{field.upper()}"

    return entry


def enforce_schema_list(items: List[Dict]) -> List[Dict]:
    """Apply enforce_schema() to every item in a list. Returns new list."""
    return [enforce_schema(item) for item in items]


# ---------------------------------------------------------------------------
# IOC Quality Engine
# ---------------------------------------------------------------------------

# Patterns that are NOT valid IOCs (false positives to reject)
_IOC_BLOCKLIST_RE = re.compile(
    r"^("
    r"127\.0\.0\.\d+|"          # loopback
    r"0\.0\.0\.0|"              # null route
    r"192\.168\.\d+\.\d+|"      # RFC1918
    r"10\.\d+\.\d+\.\d+|"       # RFC1918
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|"  # RFC1918
    r"localhost|"
    r"example\.com|example\.org|"
    r"test\.com|"
    r"\d{1,3}$"                  # single number fragments
    r")$",
    re.I
)


def extract_iocs(text: str) -> List[str]:
    """
    Extract IOCs from free text using regex patterns.
    Filters out loopback/RFC1918/known-false-positive patterns.
    Returns deduplicated list.

    v131.3: Delegates to agent.ioc_engine when available for full IOC coverage.
    Falls back to legacy regex extraction if engine import fails.
    """
    if not text:
        return []
    # Prefer the production IOC engine (comprehensive extraction + FP filtering)
    try:
        from agent.ioc_engine import extract_iocs as _engine_extract
        result = _engine_extract(text)
        return result.flat_iocs
    except ImportError:
        pass
    except Exception as _e:
        log.warning("IOC engine fallback to legacy regex: %s", _e)
    # Legacy fallback
    found: set[str] = set()
    for pat in _IOC_PATTERNS:
        for match in pat.finditer(text):
            candidate = match.group(0).strip(".,;\"'")
            if candidate and not _IOC_BLOCKLIST_RE.match(candidate):
                found.add(candidate)
    return sorted(found)


def enrich_ioc_count(obj: Dict) -> Dict:
    """
    Enforce ioc_count == len(iocs) with full IOC engine integration.

    v131.3 UPGRADE:
      - Uses agent.ioc_engine.enforce_ioc_integrity() for comprehensive enforcement.
      - Fixes P0: ioc_count > 0 but iocs = [] (re-extracts from text fields).
      - Fixes: ioc_confidence always 0 (recomputes from IOC count + type distribution).
      - Fixes: ioc_threat_level always NONE (maps from confidence).
      - All mutations on a shallow copy — original never modified.
    """
    obj = dict(obj)
    # Prefer the production IOC engine for full enforcement
    try:
        from agent.ioc_engine import enforce_ioc_integrity as _enforce
        return _enforce(obj)
    except ImportError:
        pass
    except Exception as _e:
        log.warning("IOC engine enforce failed, using legacy fix: %s", _e)

    # Legacy fallback — basic ioc_count == len(iocs) fix
    iocs = obj.get("iocs")
    ioc_count = obj.get("ioc_count", 0)

    if not isinstance(iocs, list):
        # Try to extract from text fields
        text = " ".join([
            str(obj.get("title", "")),
            str(obj.get("description", "")),
            str(obj.get("summary", "")),
        ])
        iocs = extract_iocs(text)
        if iocs:
            obj["iocs"] = iocs
            log.debug("enrich_ioc_count: extracted %d IOCs from text", len(iocs))
    elif ioc_count > 0 and len(iocs) == 0:
        # P0 integrity violation: ioc_count > 0 but iocs empty
        text = " ".join([
            str(obj.get("title", "")),
            str(obj.get("description", "")),
            str(obj.get("summary", "")),
        ])
        iocs = extract_iocs(text)
        if iocs:
            obj["iocs"] = iocs
            log.warning(
                "enrich_ioc_count: P0 fix — ioc_count=%d but iocs=[]; extracted %d from text",
                ioc_count, len(iocs)
            )

    # Remove empty strings
    iocs = [i for i in (iocs or []) if i and str(i).strip()]
    obj["iocs"] = iocs
    obj["ioc_count"] = len(iocs)

    # Fix ioc_confidence if it's 0 but we have iocs
    if iocs and float(obj.get("ioc_confidence", 0.0)) == 0.0:
        obj["ioc_confidence"] = round(min(len(iocs) * 5.0, 100.0), 2)

    # Fix ioc_threat_level if NONE but confidence > 0
    if float(obj.get("ioc_confidence", 0.0)) > 0 and obj.get("ioc_threat_level") == "NONE":
        conf = float(obj.get("ioc_confidence", 0.0))
        if conf >= 60:
            obj["ioc_threat_level"] = "HIGH"
        elif conf >= 35:
            obj["ioc_threat_level"] = "MEDIUM"
        else:
            obj["ioc_threat_level"] = "LOW"

    return obj


# ---------------------------------------------------------------------------
# Dedup Engine
# ---------------------------------------------------------------------------

def _dedup_key_primary(obj: Dict) -> str:
    """
    Primary dedup key: SHA-256 of normalised (title + source + published-date).
    Catches exact republish from same feed.
    """
    title  = re.sub(r"\s+", " ", str(obj.get("title", "")).strip().lower())
    source = str(obj.get("source", "") or obj.get("feed_source", "")).strip().lower()
    pub    = str(obj.get("published") or obj.get("timestamp") or
                 obj.get("processed_at") or "").strip()[:10]  # date only
    raw = f"{title}|{source}|{pub}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _dedup_key_title_only(obj: Dict) -> str:
    """
    Secondary dedup key: SHA-256 of normalised title only.
    Catches cross-feed duplicates (same story, different source URL).
    Only applied for non-generic titles (>= 5 meaningful words).
    """
    title = re.sub(r"[^\w\s]", "", str(obj.get("title", "")).strip().lower())
    title = re.sub(r"\s+", " ", title).strip()
    return hashlib.sha256(title.encode("utf-8")).hexdigest()


_GENERIC_TITLE_PREFIXES = frozenset({
    "cisa adds", "security advisory", "advisory update", "vulnerability advisory",
    "patch tuesday", "monthly security update", "security bulletin",
    "security update", "product security advisory", "weekly threat roundup",
    "weekly security roundup", "threat intelligence report",
})


def _is_generic_title(title: str) -> bool:
    """Return True if title is a known generic vendor template that reuses the same wording."""
    t = title.strip().lower()
    for prefix in _GENERIC_TITLE_PREFIXES:
        if t.startswith(prefix) or prefix in t:
            return True
    # Too few meaningful words
    _stopwords = frozenset({"the", "a", "an", "and", "or", "but", "in", "on", "at", "to",
                            "for", "of", "with", "by", "from", "is", "are", "was", "new",
                            "update", "adds", "one", "its", "it", "this", "that"})
    words = re.sub(r"[^\w\s]", "", t).split()
    meaningful = [w for w in words if w not in _stopwords and len(w) > 2]
    return len(meaningful) < 5


def dedup_items(items: List[Dict]) -> Tuple[List[Dict], int]:
    """
    v131.3 GLOBAL DEDUP ENGINE — three-layer deduplication.

    Layer 1: SHA-256(title + source + published-date)  — exact republish
    Layer 2: SHA-256(normalized-title-only)            — cross-feed duplicate
             (skipped for generic titles per KNOWN_GENERIC_TITLE_PATTERNS)
    Layer 3: SHA-256(bundle_id)                        — STIX bundle ID dedup
             (handles cases where title changed but same intel was re-emitted)

    Preserves FIRST occurrence. Returns (deduped_list, removed_count).
    """
    seen_primary:    set[str] = set()
    seen_title_only: set[str] = set()
    seen_bundle_ids: set[str] = set()
    result:  List[Dict] = []
    removed: int = 0

    for obj in items:
        title = str(obj.get("title", ""))

        # Layer 1: primary key
        k1 = _dedup_key_primary(obj)
        if k1 in seen_primary:
            removed += 1
            log.debug("dedup-L1: duplicate removed — %s", title[:60])
            continue

        # Layer 2: title-only (cross-feed) — skip for generic titles
        if not _is_generic_title(title):
            k2 = _dedup_key_title_only(obj)
            if k2 in seen_title_only:
                removed += 1
                log.info("dedup-L2 (cross-feed): duplicate removed — %s", title[:60])
                continue

        # Layer 3: bundle_id dedup (prevents STIX re-emit)
        bid = str(obj.get("bundle_id") or obj.get("stix_id") or "")
        if bid and bid.startswith("bundle--") and bid in seen_bundle_ids:
            removed += 1
            log.info("dedup-L3 (bundle_id): duplicate removed — %s", title[:60])
            continue

        # Passed all layers — mark as seen
        seen_primary.add(k1)
        if not _is_generic_title(title):
            seen_title_only.add(_dedup_key_title_only(obj))
        if bid:
            seen_bundle_ids.add(bid)
        result.append(obj)

    if removed:
        log.info("GlobalDedupEngine: removed %d duplicate(s) across 3 layers, %d unique remain",
                 removed, len(result))
    return result, removed


# ---------------------------------------------------------------------------
# Pipeline Metrics
# ---------------------------------------------------------------------------

class PipelineMetrics:
    """
    Lightweight in-process metrics collector for the SENTINEL APEX pipeline.
    Tracks: ingestion count, failure count, IOC count, stage timings.
    Writes a JSON report at the end of the pipeline run.
    """

    def __init__(self) -> None:
        self._start = time.monotonic()
        self._ingested = 0
        self._failed = 0
        self._ioc_count = 0
        self._duplicates = 0
        self._stage_timings: Dict[str, float] = {}
        self._stage_statuses: Dict[str, str] = {}
        self._errors: List[str] = []
        # v132 write observability
        self._write_latencies_ms: List[float] = []
        self._write_failures: int = 0
        self._retry_count: int = 0
        self._render_failures: int = 0
        self._schema_violations: int = 0
        self._recovery_count: int = 0   # v132.2: soft-fail items stored to recovery

    def record_ingestion(self, count: int) -> None:
        self._ingested += count

    def record_failure(self, stage: str, reason: str) -> None:
        self._failed += 1
        self._errors.append(f"{stage}: {reason}")

    def record_iocs(self, count: int) -> None:
        self._ioc_count += count

    def record_duplicates(self, count: int) -> None:
        self._duplicates += count

    def record_stage(self, stage: str, duration_s: float, status: str = "ok") -> None:
        self._stage_timings[stage] = round(duration_s, 3)
        self._stage_statuses[stage] = status

    # v132 write observability
    def record_write(self, latency_ms: float) -> None:
        self._write_latencies_ms.append(latency_ms)

    def record_write_failure(self, stage: str, reason: str) -> None:
        self._write_failures += 1
        self._errors.append(f"write_failure [{stage}]: {reason}")

    def record_write_retry(self, count: int = 1) -> None:
        self._retry_count += count

    def record_render_failure(self, stage: str = "", reason: str = "") -> None:
        self._render_failures += 1
        if reason:
            self._errors.append(f"render_failure [{stage}]: {reason}")

    def record_schema_violation(self, field: str = "", reason: str = "") -> None:
        self._schema_violations += 1
        if reason:
            self._errors.append(f"schema_violation [{field}]: {reason}")

    def record_recovery(self, stage: str = "", reason: str = "") -> None:
        """v132.2: Track items soft-failed to recovery buffer."""
        self._recovery_count += 1
        if reason:
            self._errors.append(f"recovery [{stage}]: {reason}")

    def ingestion_rate(self) -> float:
        total = self._ingested + self._failed
        return round(self._ingested / total, 4) if total else 0.0

    def pipeline_failure_rate(self) -> float:
        total = len(self._stage_statuses)
        if not total:
            return 0.0
        failed = sum(1 for s in self._stage_statuses.values() if s != "ok")
        return round(failed / total, 4)

    def ioc_extraction_rate(self) -> float:
        return round(self._ioc_count / self._ingested, 2) if self._ingested else 0.0

    def _write_latency_stats(self) -> Dict:
        lats = self._write_latencies_ms
        if not lats:
            return {"count": 0, "avg_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
        sorted_lats = sorted(lats)
        p99_idx = max(0, int(len(sorted_lats) * 0.99) - 1)
        return {
            "count": len(lats),
            "avg_ms": round(sum(lats) / len(lats), 2),
            "p99_ms": round(sorted_lats[p99_idx], 2),
            "max_ms": round(max(lats), 2),
        }

    def to_dict(self) -> Dict:
        elapsed = round(time.monotonic() - self._start, 2)
        # Merge WriteQueue metrics for full observability
        wq_metrics = WriteQueue.metrics_snapshot()
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "pipeline_duration_s": elapsed,
            "ingested_items": self._ingested,
            "failed_items": self._failed,
            "ingestion_success_rate": self.ingestion_rate(),
            "pipeline_failure_rate": self.pipeline_failure_rate(),
            "total_iocs_extracted": self._ioc_count,
            "ioc_extraction_rate_per_item": self.ioc_extraction_rate(),
            "duplicates_removed": self._duplicates,
            "stage_timings_s": self._stage_timings,
            "stage_statuses": self._stage_statuses,
            "errors": self._errors,
            # v132 write + render observability
            "write_latency": self._write_latency_stats(),
            "write_failures": self._write_failures + wq_metrics.get("write_failures", 0),
            "write_retry_count": self._retry_count,
            "render_failures": self._render_failures,
            "schema_violations": self._schema_violations,
            # v132.2 write pressure metrics
            "recovery_count": self._recovery_count + wq_metrics.get("recovery_count", 0),
            "write_queue_depth": wq_metrics.get("write_queue_depth", 0),
            "write_queue_metrics": wq_metrics,
        }

    def write_report(self, path: Path) -> None:
        """Write metrics JSON report atomically."""
        try:
            atomic_json_write(path, self.to_dict(), locked=False)
            log.info("PipelineMetrics: report written -> %s", path.name)
        except Exception as e:
            log.warning("PipelineMetrics: failed to write report: %s", e)

    def log_summary(self) -> None:
        d = self.to_dict()
        log.info("=" * 60)
        log.info("PIPELINE METRICS SUMMARY")
        log.info("  Duration         : %.2fs", d["pipeline_duration_s"])
        log.info("  Ingested items   : %d", d["ingested_items"])
        log.info("  Failed items     : %d", d["failed_items"])
        log.info("  Ingestion rate   : %.1f%%", d["ingestion_success_rate"] * 100)
        log.info("  Pipeline fail %%  : %.1f%%", d["pipeline_failure_rate"] * 100)
        log.info("  Total IOCs       : %d", d["total_iocs_extracted"])
        log.info("  IOC/item rate    : %.2f", d["ioc_extraction_rate_per_item"])
        log.info("  Duplicates removed: %d", d["duplicates_removed"])
        if d["errors"]:
            log.warning("  Errors           : %d", len(d["errors"]))
            for e in d["errors"][:5]:
                log.warning("    - %s", e)
        log.info("=" * 60)


# ---------------------------------------------------------------------------
# v132.3 Autonomic Stability Layer — SystemHealthMonitor
# ---------------------------------------------------------------------------

class SystemCriticalError(RuntimeError):
    """
    Raised when the pipeline enters CRITICAL state and all recovery attempts
    are exhausted. Signals that the pipeline MUST halt immediately.
    """


class SystemHealthMonitor:
    """
    v132.3 AUTONOMIC STABILITY LAYER — Health State Machine.

    States (ordered): HEALTHY → DEGRADED → CRITICAL

    Transition rules (evaluated on every tick()):
      DEGRADED  if: write_queue_depth > DEGRADED_QUEUE_THRESHOLD  (50)
                    OR recovery_count  > DEGRADED_RECOVERY_THRESHOLD (20)
      CRITICAL  if: recovery_count > CRITICAL_RECOVERY_THRESHOLD (100)
                    OR consecutive_degraded_runs >= CRITICAL_DEGRADED_RUNS (3)

    Auto-throttle (applied when transitioning to DEGRADED):
      MAX_CONCURRENT_WRITES → THROTTLE_MAX_CONCURRENT_WRITES (1)
      WRITE_DELAY_MS        → THROTTLE_WRITE_DELAY_MS        (200ms)
      ingestion             → paused

    Restore (applied when returning to HEALTHY):
      MAX_CONCURRENT_WRITES → MAX_CONCURRENT_WRITES (3)
      WRITE_DELAY_MS        → WRITE_DELAY_MS        (50ms)

    Hard guard:
      DEGRADED for CRITICAL_DEGRADED_RUNS consecutive runs
      → raise SystemCriticalError (pipeline INTENTIONAL FAIL)

    Health score:
      health_score = 100
                   - (write_failures * HEALTH_SCORE_WRITE_FAILURE_PENALTY)   [2.0]
                   - (retry_count    * HEALTH_SCORE_RETRY_PENALTY)            [0.5]
                   - (queue_depth    * HEALTH_SCORE_QUEUE_DEPTH_PENALTY)      [1.0]
      Clamped to [0.0, 100.0].

    Persistence: data/logs/system_health.json  (atomic write)
    Thread-safety: all state mutations are lock-protected.

    Usage:
        from scripts.safe_io import health_monitor
        health_monitor.tick()           # evaluate state, apply throttle
        health_monitor.get_state()      # returns dict for /api/health
        health_monitor.assert_healthy() # raises SystemCriticalError if CRITICAL
    """

    def __init__(self, repo_root: Optional[Path] = None) -> None:
        self._lock = threading.Lock()
        self._root = repo_root or Path(__file__).resolve().parent.parent
        self._health_path = self._root / "data" / "logs" / "system_health.json"

        # Runtime state
        self._state: str = SYSTEM_STATE_HEALTHY
        self._consecutive_degraded_runs: int = 0
        self._ingestion_paused: bool = False
        self._last_tick_ts: str = ""

        # Cumulative counters (reset per pipeline run via reset_counters())
        self._run_write_failures: int = 0
        self._run_retry_count: int = 0
        self._run_recovery_count: int = 0

        # Historical event log (capped at 100 entries)
        self._events: List[Dict[str, Any]] = []

        log.info("SystemHealthMonitor: initialised (state=%s)", SYSTEM_STATE_HEALTHY)

    # ── Public interface ──────────────────────────────────────────────────────

    def tick(self) -> str:
        """
        Evaluate current system state from live WriteQueue metrics.
        Applies/restores throttle as required.
        Persists state to data/logs/system_health.json.
        Returns new state string: HEALTHY | DEGRADED | CRITICAL.
        Raises SystemCriticalError if CRITICAL and pipeline must halt.
        """
        with self._lock:
            snap = WriteQueue.metrics_snapshot()
            queue_depth    = snap.get("write_queue_depth", 0)
            recovery_count = snap.get("recovery_count", 0)
            write_failures = snap.get("write_failures", 0)
            retry_count    = self._run_retry_count

            # ── State transition logic ─────────────────────────────────────
            new_state = self._evaluate_state(queue_depth, recovery_count)

            if new_state == SYSTEM_STATE_CRITICAL:
                # CRITICAL: block ingestion, enforce slow mode, allow only recovery replay
                self._ingestion_paused = True
                if not self._is_throttle_active():
                    _apply_throttle()
                self._record_event("STATE_TRANSITION", {
                    "from": self._state,
                    "to": SYSTEM_STATE_CRITICAL,
                    "queue_depth": queue_depth,
                    "recovery_count": recovery_count,
                })
                self._state = SYSTEM_STATE_CRITICAL
                log.critical(
                    "SystemHealthMonitor: CRITICAL — ingestion BLOCKED, "
                    "recovery replay only | queue=%d recovery=%d degraded_runs=%d",
                    queue_depth, recovery_count, self._consecutive_degraded_runs,
                )
                self._persist()
                raise SystemCriticalError(
                    f"SENTINEL APEX entered CRITICAL state: "
                    f"recovery_count={recovery_count} "
                    f"degraded_runs={self._consecutive_degraded_runs}. "
                    f"Pipeline intentionally halted. "
                    f"Run scripts/recovery_replay.py to drain recovery backlog."
                )

            elif new_state == SYSTEM_STATE_DEGRADED:
                self._consecutive_degraded_runs += 1
                self._ingestion_paused = True

                if not self._is_throttle_active():
                    _apply_throttle()
                    self._record_event("THROTTLE_APPLIED", {
                        "queue_depth": queue_depth,
                        "recovery_count": recovery_count,
                        "consecutive_degraded_runs": self._consecutive_degraded_runs,
                    })

                # Hard guard: 3 consecutive DEGRADED runs → FAIL
                if self._consecutive_degraded_runs >= CRITICAL_DEGRADED_RUNS:
                    self._state = SYSTEM_STATE_CRITICAL
                    self._persist()
                    raise SystemCriticalError(
                        f"SENTINEL APEX DEGRADED for "
                        f"{self._consecutive_degraded_runs} consecutive runs "
                        f"(threshold={CRITICAL_DEGRADED_RUNS}). "
                        f"Pipeline intentionally halted — run recovery_replay.py."
                    )

                if self._state != SYSTEM_STATE_DEGRADED:
                    self._record_event("STATE_TRANSITION", {
                        "from": self._state, "to": SYSTEM_STATE_DEGRADED,
                        "queue_depth": queue_depth, "recovery_count": recovery_count,
                    })
                self._state = SYSTEM_STATE_DEGRADED
                log.warning(
                    "SystemHealthMonitor: DEGRADED (run %d/%d) — "
                    "throttle active, ingestion paused | queue=%d recovery=%d",
                    self._consecutive_degraded_runs, CRITICAL_DEGRADED_RUNS,
                    queue_depth, recovery_count,
                )

            else:
                # HEALTHY — restore throttle if it was active
                if self._is_throttle_active():
                    _restore_throttle()
                    self._record_event("THROTTLE_RESTORED", {
                        "queue_depth": queue_depth,
                        "recovery_count": recovery_count,
                    })
                if self._state != SYSTEM_STATE_HEALTHY:
                    self._record_event("STATE_TRANSITION", {
                        "from": self._state, "to": SYSTEM_STATE_HEALTHY,
                        "queue_depth": queue_depth,
                    })
                self._consecutive_degraded_runs = 0
                self._ingestion_paused = False
                self._state = SYSTEM_STATE_HEALTHY
                log.info(
                    "SystemHealthMonitor: HEALTHY | queue=%d recovery=%d",
                    queue_depth, recovery_count,
                )

            self._last_tick_ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self._persist()
            return self._state

    def health_score(self) -> float:
        """
        Compute health score from live WriteQueue metrics.
        Formula: 100 - (failures*2) - (retries*0.5) - queue_depth
        Clamped to [0.0, 100.0].
        """
        snap   = WriteQueue.metrics_snapshot()
        wf     = snap.get("write_failures", 0)
        qd     = snap.get("write_queue_depth", 0)
        rc     = snap.get("recovery_count", 0)
        retry  = self._run_retry_count
        score  = (
            100.0
            - (wf    * HEALTH_SCORE_WRITE_FAILURE_PENALTY)   # 2.0 per failure
            - (retry * HEALTH_SCORE_RETRY_PENALTY)            # 0.5 per retry
            - (qd    * HEALTH_SCORE_QUEUE_DEPTH_PENALTY)      # 1.0 per queued item
            - (rc    * HEALTH_SCORE_RECOVERY_PENALTY)         # 2.0 per recovery blob (v134)
        )
        return round(max(0.0, min(100.0, score)), 2)

    def get_state(self) -> Dict[str, Any]:
        """
        Return complete health state dict for GET /api/health.
        Thread-safe. Never raises.
        """
        try:
            snap = WriteQueue.metrics_snapshot()
            with self._lock:
                return {
                    "platform": "CYBERDUDEBIVASH® SENTINEL APEX",
                    "version": "v132.3.0",
                    "state": self._state,
                    "health_score": self.health_score(),
                    "ingestion_paused": self._ingestion_paused,
                    "consecutive_degraded_runs": self._consecutive_degraded_runs,
                    "throttle_active": self._is_throttle_active(),
                    "current_max_concurrent_writes": _current_max_concurrent_writes,
                    "current_write_delay_ms": _current_write_delay_ms,
                    "write_queue_depth": snap.get("write_queue_depth", 0),
                    "write_failures": snap.get("write_failures", 0),
                    "recovery_count": snap.get("recovery_count", 0),
                    "write_count": snap.get("write_count", 0),
                    "write_latency_avg_ms": snap.get("write_latency_avg_ms", 0.0),
                    "thresholds": {
                        "degraded_queue_threshold": DEGRADED_QUEUE_THRESHOLD,
                        "degraded_recovery_threshold": DEGRADED_RECOVERY_THRESHOLD,
                        "critical_recovery_threshold": CRITICAL_RECOVERY_THRESHOLD,
                        "critical_degraded_runs": CRITICAL_DEGRADED_RUNS,
                    },
                    "last_tick": self._last_tick_ts,
                    "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "recent_events": list(self._events[-10:]),
                }
        except Exception as e:
            return {
                "state": SYSTEM_STATE_HEALTHY,
                "health_score": 100.0,
                "error": str(e),
                "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }

    def assert_healthy(self) -> None:
        """
        Assert system is not CRITICAL. Raises SystemCriticalError if CRITICAL.
        Call at pipeline ingestion gate to block new work when degraded.
        """
        with self._lock:
            if self._state == SYSTEM_STATE_CRITICAL:
                raise SystemCriticalError(
                    f"Pipeline blocked: system is CRITICAL "
                    f"(consecutive_degraded_runs={self._consecutive_degraded_runs}). "
                    f"Run scripts/recovery_replay.py to clear recovery backlog."
                )
            if self._ingestion_paused and self._state == SYSTEM_STATE_DEGRADED:
                log.warning(
                    "SystemHealthMonitor.assert_healthy: DEGRADED — "
                    "ingestion paused; new work will be throttled."
                )

    def reset_run_counters(self) -> None:
        """Reset per-pipeline-run counters. Call at start of each pipeline run."""
        with self._lock:
            self._run_write_failures = 0
            self._run_retry_count = 0
            self._run_recovery_count = 0

    def record_retry(self, count: int = 1) -> None:
        """Record write retries from the pipeline."""
        with self._lock:
            self._run_retry_count += count

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _evaluate_state(self, queue_depth: int, recovery_count: int) -> str:
        """Pure state evaluation — no side effects."""
        if (recovery_count > CRITICAL_RECOVERY_THRESHOLD
                or self._consecutive_degraded_runs >= CRITICAL_DEGRADED_RUNS):
            return SYSTEM_STATE_CRITICAL
        if (queue_depth > DEGRADED_QUEUE_THRESHOLD
                or recovery_count > DEGRADED_RECOVERY_THRESHOLD):
            return SYSTEM_STATE_DEGRADED
        return SYSTEM_STATE_HEALTHY

    @staticmethod
    def _is_throttle_active() -> bool:
        return _throttle_active

    def _record_event(self, event_type: str, details: Dict[str, Any]) -> None:
        """Append a structured event to the rolling event log (max 100 entries)."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event_type,
            **details,
        }
        self._events.append(entry)
        if len(self._events) > 100:
            self._events = self._events[-100:]

    def _persist(self) -> None:
        """
        Atomically persist health state to data/logs/system_health.json.
        Never raises — persistence failure is non-fatal.
        """
        try:
            state_doc = self.get_state()
            self._health_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._health_path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(state_doc, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            try:
                os.replace(str(tmp), str(self._health_path))
            except OSError:
                self._health_path.write_text(
                    json.dumps(state_doc, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8",
                )
                try:
                    tmp.unlink(missing_ok=True)
                except Exception:
                    pass
            log.debug("SystemHealthMonitor: persisted state=%s score=%.1f",
                      self._state, state_doc.get("health_score", 0))
        except Exception as persist_err:
            log.warning("SystemHealthMonitor: persist failed (non-fatal): %s", persist_err)


# ---------------------------------------------------------------------------
# Module-level SystemHealthMonitor singleton
# ---------------------------------------------------------------------------
# Import-safe: zero I/O at instantiation. Thread-safe singleton.
# Usage:
#   from scripts.safe_io import health_monitor
#   health_monitor.tick()
#   state = health_monitor.get_state()
health_monitor = SystemHealthMonitor()
