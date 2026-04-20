#!/usr/bin/env python3
"""
scripts/safe_io.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.3.0 -- Production SafeIO Foundation
==========================================================================
Centralised, production-grade I/O primitives for the entire pipeline.

Provides:
  AtomicWriter    -- write-temp-then-rename, post-write verify, never partial
  FileLock        -- cross-platform exclusive file lock (fcntl/msvcrt/softlock)
  SafeJSONIO      -- load/dump wrappers that never raise, with auto-heal
  SchemaValidator -- strict schema gate for intel objects + ioc_count integrity
  DedupEngine     -- SHA-256 dedup on (title, source, published) normalised key
  PipelineMetrics -- ingestion / failure / IOC rate collector + JSON reporter

Usage:
  from scripts.safe_io import (
      atomic_json_write, safe_json_load, safe_json_dump,
      validate_intel_object, dedup_items, PipelineMetrics, acquire_lock,
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
    # Save payload blob
    if payload is not None and _WRITE_FAILURE_DIR is not None:
        try:
            _WRITE_FAILURE_DIR.mkdir(parents=True, exist_ok=True)
            blob_path = _WRITE_FAILURE_DIR / f"{ts}_{stem}.json"
            blob_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False, default=str),
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
# Retry Write — Exponential Backoff Wrapper (MANDATORY for all write paths)
# ---------------------------------------------------------------------------

class WriteHardFail(RuntimeError):
    """Raised by retry_write() after all attempts exhausted."""


def retry_write(
    fn: Callable[[], Any],
    *,
    attempts: int = 5,
    base_delay: float = 0.5,
    path: Optional[Path] = None,
    payload: Any = None,
) -> Any:
    """
    Wrap any write callable with retry + exponential backoff.
    On permanent failure: stores to fail-safe buffer, raises WriteHardFail.

    Args:
        fn:         Zero-argument callable that performs the write.
        attempts:   Total attempts (default 5).
        base_delay: Base sleep seconds; sleep = base_delay * (attempt + 1).
        path:       Target file path (for fail-safe buffer and logging).
        payload:    Data payload (stored in recovery buffer on permanent failure).
    """
    last_exc: Exception = RuntimeError("retry_write: no attempts made")
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            delay = base_delay * (attempt + 1)
            log.warning(
                "retry_write: attempt %d/%d failed for %s: %s (retry in %.1fs)",
                attempt + 1, attempts,
                Path(str(path)).name if path else "?",
                exc, delay,
            )
            time.sleep(delay)
    # All attempts exhausted — engage fail-safe buffer
    log.error(
        "retry_write: PERMANENT FAILURE after %d attempts for %s: %s",
        attempts, path, last_exc,
    )
    if path is not None:
        _store_write_failure(path, last_exc, payload)
    raise WriteHardFail(
        f"retry_write: all {attempts} attempts failed for {path}: {last_exc}"
    ) from last_exc


# ---------------------------------------------------------------------------
# WriteQueue — Centralized Single-Writer Enforcement
# ---------------------------------------------------------------------------

class WriteQueue:
    """
    Centralized write queue for SENTINEL APEX pipeline.

    ALL writes to data/stix/*, data/intel/*, data/api/*, feed_manifest.json
    MUST go through this queue.  Writes are enqueued as callables and flushed
    ONLY at controlled stage boundaries via flush().

    This prevents concurrent-write races during Stage 3.6 batch processing.

    Usage:
        WriteQueue.enqueue(lambda: atomic_json_write(path, data))
        ...
        WriteQueue.flush()   # called once at stage boundary

    Thread-safety: the queue list and metrics are protected by a threading.Lock.
    """

    _queue: List[Callable[[], Any]] = []
    _lock: threading.Lock = threading.Lock()

    # Metrics (also exposed to PipelineMetrics.write_report)
    _write_latency_ms: List[float] = []
    _write_failures: int = 0
    _retry_count: int = 0

    @classmethod
    def enqueue(cls, write_fn: Callable[[], Any]) -> None:
        """Append a write callable to the queue."""
        with cls._lock:
            cls._queue.append(write_fn)

    @classmethod
    def flush(
        cls,
        *,
        attempts: int = 5,
        base_delay: float = 0.5,
    ) -> Dict[str, Any]:
        """
        Execute all queued write callables sequentially (never parallel).
        Each write is wrapped in retry_write with exponential backoff.
        Failed writes are stored in the fail-safe buffer.

        Returns metrics dict: {queued, succeeded, failed, total_latency_ms}.
        """
        with cls._lock:
            queue_snapshot = list(cls._queue)
            cls._queue.clear()

        succeeded = 0
        failed = 0
        t_flush_start = time.monotonic()

        for i, fn in enumerate(queue_snapshot):
            t0 = time.monotonic()
            try:
                # retry_write wraps the callable with backoff
                retry_write(fn, attempts=attempts, base_delay=base_delay)
                latency_ms = (time.monotonic() - t0) * 1000
                with cls._lock:
                    cls._write_latency_ms.append(latency_ms)
                succeeded += 1
                log.debug("WriteQueue.flush: item %d/%d OK (%.1fms)", i + 1, len(queue_snapshot), latency_ms)
            except WriteHardFail as exc:
                latency_ms = (time.monotonic() - t0) * 1000
                with cls._lock:
                    cls._write_failures += 1
                    cls._write_latency_ms.append(latency_ms)
                failed += 1
                log.error("WriteQueue.flush: item %d/%d HARD FAIL: %s", i + 1, len(queue_snapshot), exc)
            except Exception as exc:
                with cls._lock:
                    cls._write_failures += 1
                failed += 1
                log.error("WriteQueue.flush: item %d/%d unexpected error: %s", i + 1, len(queue_snapshot), exc)

        total_latency_ms = (time.monotonic() - t_flush_start) * 1000
        log.info(
            "WriteQueue.flush: queued=%d succeeded=%d failed=%d total_latency=%.1fms",
            len(queue_snapshot), succeeded, failed, total_latency_ms,
        )
        return {
            "queued": len(queue_snapshot),
            "succeeded": succeeded,
            "failed": failed,
            "total_latency_ms": round(total_latency_ms, 2),
        }

    @classmethod
    def metrics_snapshot(cls) -> Dict[str, Any]:
        """Return current write queue metrics (non-destructive)."""
        with cls._lock:
            latencies = list(cls._write_latency_ms)
            failures = cls._write_failures
        avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        p99_lat = round(sorted(latencies)[int(len(latencies) * 0.99)], 2) if len(latencies) >= 100 else (max(latencies) if latencies else 0.0)
        return {
            "write_count": len(latencies),
            "write_failures": failures,
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
            # v132 write observability
            "write_latency": self._write_latency_stats(),
            "write_failures": self._write_failures + wq_metrics.get("write_failures", 0),
            "write_retry_count": self._retry_count,
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
