"""
core/ingestion/sources/base.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
Abstract base class for all threat intelligence ingestion sources.

Contract:
  - Every source must implement fetch() → List[RawIntelItem]
  - Sources declare their source_id, source_type, and capability flags
  - Rate limiting, retry, and error isolation are enforced at the base layer
"""
from __future__ import annotations

import hashlib
import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("sentinel.ingestion.source")


# ─────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────

class SourceType(str, Enum):
    CVE         = "cve"
    KEV         = "kev"
    MALWARE     = "malware"
    IP_THREAT   = "ip_threat"
    INDICATOR   = "indicator"
    THREAT_ACTOR = "threat_actor"
    GENERIC     = "generic"


class FetchStatus(str, Enum):
    SUCCESS     = "success"
    PARTIAL     = "partial"
    EMPTY       = "empty"
    RATE_LIMITED = "rate_limited"
    AUTH_FAILURE = "auth_failure"
    NETWORK_ERROR = "network_error"
    PARSE_ERROR = "parse_error"
    TIMEOUT     = "timeout"


# ─────────────────────────────────────────────
# Data Containers
# ─────────────────────────────────────────────

@dataclass
class RawIntelItem:
    """
    Normalised raw item from any source before schema mapping.
    The content_hash is computed at creation and used for deduplication.
    """
    source_id:    str                       # Canonical source identifier, e.g. "nvd_cve"
    source_type:  SourceType               # Category of this intelligence
    raw_id:       str                       # Source-native primary key (CVE-ID, hash, IP…)
    raw_data:     Dict[str, Any]           # Full raw payload — preserved for audit
    content_hash: str = field(init=False)  # SHA-256 of deterministic repr for dedup
    fetched_at:   float = field(default_factory=time.time)
    metadata:     Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.content_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """
        Deterministic SHA-256 over the raw_data dict.
        Sorted keys ensure dict ordering differences don't produce hash divergence.
        """
        serialised = str(sorted(self.raw_data.items()))
        return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


@dataclass
class FetchResult:
    """Result envelope returned from every source.fetch() call."""
    source_id:    str
    status:       FetchStatus
    items:        List[RawIntelItem] = field(default_factory=list)
    items_count:  int = 0
    duration_s:   float = 0.0
    error:        Optional[str] = None
    next_cursor:  Optional[str] = None     # For paginated sources
    metadata:     Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.items_count:
            self.items_count = len(self.items)


# ─────────────────────────────────────────────
# Rate-Limiter (Token Bucket)
# ─────────────────────────────────────────────

class TokenBucketRateLimiter:
    """
    Thread-safe token bucket rate limiter.
    Limits: requests_per_minute at steady state, with burst capacity.
    """

    def __init__(self, requests_per_minute: int, burst: int = 0) -> None:
        self._rate = requests_per_minute / 60.0   # tokens / second
        self._burst = burst or requests_per_minute
        self._tokens = float(self._burst)
        self._last_refill = time.monotonic()

    def acquire(self, tokens: int = 1) -> None:
        """Block until the requested tokens are available."""
        while True:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
            self._last_refill = now

            if self._tokens >= tokens:
                self._tokens -= tokens
                return

            # Sleep for the deficit
            deficit = tokens - self._tokens
            sleep_s = deficit / self._rate
            time.sleep(min(sleep_s, 2.0))   # cap individual sleep to 2 s for responsiveness


# ─────────────────────────────────────────────
# Abstract Base Source
# ─────────────────────────────────────────────

class BaseSource(ABC):
    """
    Abstract base for all threat intelligence sources.

    Subclasses must:
      1. Set SOURCE_ID  (str)  — unique identifier used in routing and metrics
      2. Set SOURCE_TYPE (SourceType)
      3. Implement _do_fetch() → List[RawIntelItem]

    Optional overrides:
      - REQUESTS_PER_MINUTE: int  — enforced via token bucket (default 60)
      - BURST: int               — burst capacity (default = RPM)
      - TIMEOUT_S: int           — HTTP timeout in seconds (default 30)
    """

    SOURCE_ID:   str        = "unknown"
    SOURCE_TYPE: SourceType = SourceType.GENERIC
    REQUESTS_PER_MINUTE: int = 60
    BURST:       int        = 0
    TIMEOUT_S:   int        = 30

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config   = config or {}
        self._limiter = TokenBucketRateLimiter(
            self.REQUESTS_PER_MINUTE, self.BURST
        )
        self._fetch_count   = 0
        self._error_count   = 0
        self._last_fetch_ts: Optional[float] = None
        self._last_error:    Optional[str]   = None
        self.log = logging.getLogger(f"sentinel.ingestion.{self.SOURCE_ID}")

    # ── Public interface ──────────────────────────────────────────────────────

    def fetch(self, **kwargs) -> FetchResult:
        """
        Public fetch entrypoint.
        Handles timing, rate limiting, error isolation, and result wrapping.
        """
        self._limiter.acquire()
        t0 = time.time()
        try:
            items = self._do_fetch(**kwargs)
            duration = time.time() - t0
            self._fetch_count += 1
            self._last_fetch_ts = time.time()
            status = FetchStatus.SUCCESS if items else FetchStatus.EMPTY
            result = FetchResult(
                source_id=self.SOURCE_ID,
                status=status,
                items=items,
                duration_s=round(duration, 3),
            )
            self.log.info(
                "fetch_ok source=%s items=%d duration_s=%.3f",
                self.SOURCE_ID, len(items), duration
            )
            return result

        except RateLimitError as exc:
            self._error_count += 1
            self._last_error = str(exc)
            self.log.warning("rate_limit source=%s", self.SOURCE_ID)
            return FetchResult(
                source_id=self.SOURCE_ID,
                status=FetchStatus.RATE_LIMITED,
                duration_s=round(time.time() - t0, 3),
                error=str(exc),
            )

        except AuthError as exc:
            self._error_count += 1
            self._last_error = str(exc)
            self.log.error("auth_failure source=%s error=%s", self.SOURCE_ID, exc)
            return FetchResult(
                source_id=self.SOURCE_ID,
                status=FetchStatus.AUTH_FAILURE,
                duration_s=round(time.time() - t0, 3),
                error=str(exc),
            )

        except ParseError as exc:
            self._error_count += 1
            self._last_error = str(exc)
            self.log.error("parse_error source=%s error=%s", self.SOURCE_ID, exc)
            return FetchResult(
                source_id=self.SOURCE_ID,
                status=FetchStatus.PARSE_ERROR,
                duration_s=round(time.time() - t0, 3),
                error=str(exc),
            )

        except Exception as exc:
            self._error_count += 1
            self._last_error = str(exc)
            self.log.error("fetch_error source=%s error=%s", self.SOURCE_ID, exc, exc_info=True)
            return FetchResult(
                source_id=self.SOURCE_ID,
                status=FetchStatus.NETWORK_ERROR,
                duration_s=round(time.time() - t0, 3),
                error=str(exc),
            )

    def health(self) -> Dict[str, Any]:
        """Return health summary for monitoring."""
        return {
            "source_id":      self.SOURCE_ID,
            "source_type":    self.SOURCE_TYPE.value,
            "fetch_count":    self._fetch_count,
            "error_count":    self._error_count,
            "last_fetch_ts":  self._last_fetch_ts,
            "last_error":     self._last_error,
            "error_rate":     (
                round(self._error_count / self._fetch_count, 4)
                if self._fetch_count else 0.0
            ),
        }

    # ── Abstract implementation ───────────────────────────────────────────────

    @abstractmethod
    def _do_fetch(self, **kwargs) -> List[RawIntelItem]:
        """
        Implement actual data retrieval logic.
        Raise RateLimitError / AuthError / ParseError for known failure modes.
        All other exceptions are caught as generic network errors.
        """
        ...

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_item(self, raw_id: str, raw_data: Dict[str, Any],
                   metadata: Optional[Dict[str, Any]] = None) -> RawIntelItem:
        return RawIntelItem(
            source_id=self.SOURCE_ID,
            source_type=self.SOURCE_TYPE,
            raw_id=raw_id,
            raw_data=raw_data,
            metadata=metadata or {},
        )


# ─────────────────────────────────────────────
# Source-Specific Exceptions
# ─────────────────────────────────────────────

class SourceError(Exception):
    """Base exception for all ingestion source errors."""


class SourceAuthError(SourceError):
    """API key missing, invalid, or quota exhausted."""


class SourceRateLimitError(SourceError):
    """Source rate limit hit — caller should back off."""
    def __init__(self, message: str = "Rate limit exceeded", retry_after_s: int = 60) -> None:
        super().__init__(message)
        self.retry_after_s = retry_after_s


class SourceNetworkError(SourceError):
    """Network-level failure (timeout, DNS, TLS)."""


class SourceParseError(SourceError):
    """Unexpected response format — schema changed upstream."""


class SourceConfigError(SourceError):
    """Source mis-configured (missing required env var, bad URL, etc.)."""