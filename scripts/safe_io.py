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
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

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

    def __init__(self, path: Path, timeout: float = 30.0, poll: float = 0.1):
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
                    time.sleep(self._poll)
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
                    time.sleep(self._poll)
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
def acquire_lock(path: Path, timeout: float = 30.0) -> Iterator[FileLock]:
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
        if verify:
            parsed = json.loads(tmp.read_text(encoding="utf-8"))
            # Light sanity: same top-level type
            if type(parsed) is not type(data):
                raise ValueError(
                    f"Post-write type mismatch: expected {type(data).__name__}, "
                    f"got {type(parsed).__name__}"
                )
        os.replace(str(tmp), str(path))
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
    """
    if not text:
        return []
    found: set[str] = set()
    for pat in _IOC_PATTERNS:
        for match in pat.finditer(text):
            candidate = match.group(0).strip(".,;\"'")
            if candidate and not _IOC_BLOCKLIST_RE.match(candidate):
                found.add(candidate)
    return sorted(found)


def enrich_ioc_count(obj: Dict) -> Dict:
    """
    Ensure ioc_count == len(iocs). If iocs is missing but title/description
    have IOC-like content, extract them. Mutates a copy and returns it.
    """
    obj = dict(obj)
    iocs = obj.get("iocs")
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
    # Remove empty strings
    iocs = [i for i in (iocs or []) if i and str(i).strip()]
    obj["iocs"] = iocs
    obj["ioc_count"] = len(iocs)
    return obj


# ---------------------------------------------------------------------------
# Dedup Engine
# ---------------------------------------------------------------------------

def _dedup_key(obj: Dict) -> str:
    """Compute SHA-256 dedup key from normalised (title, source, published)."""
    title = str(obj.get("title", "")).strip().lower()
    source = str(obj.get("source", "")).strip().lower()
    # Use published OR timestamp, whichever is present
    pub = str(obj.get("published") or obj.get("timestamp") or "").strip()[:10]  # date only
    raw = f"{title}|{source}|{pub}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def dedup_items(items: List[Dict]) -> Tuple[List[Dict], int]:
    """
    Deduplicate intel items using hash(title + source + published-date).
    Preserves the FIRST occurrence (chronological order maintained).
    Returns (deduped_list, removed_count).
    """
    seen: set[str] = set()
    result: List[Dict] = []
    removed = 0
    for obj in items:
        key = _dedup_key(obj)
        if key in seen:
            removed += 1
            log.debug("dedup: duplicate removed — %s", str(obj.get("title", ""))[:60])
        else:
            seen.add(key)
            result.append(obj)
    if removed:
        log.info("DedupEngine: removed %d duplicate(s), %d unique remain", removed, len(result))
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

    def to_dict(self) -> Dict:
        elapsed = round(time.monotonic() - self._start, 2)
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
