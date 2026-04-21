#!/usr/bin/env python3
"""
core/stability/pipeline_guardian.py — CYBERDUDEBIVASH® SENTINEL APEX v134.0
=============================================================================
PIPELINE STABILITY & SYNCHRONIZATION ENGINE

Responsibilities:
  1. Feed freshness validation    — detect stale ingestion data
  2. API data consistency checks  — confirm /api/v1/intel reflects latest manifest
  3. Module health tracking       — which routers loaded, which failed
  4. Dynamic APEX mode evaluation — replaces static CDB_APEX_ENABLED env flag
  5. Sync event logging           — structured JSON desync events
  6. FastAPI health_router        — /api/v1/health/* + /apex/v1/status endpoints

Design constraints:
  - Zero directory creation at import time (safe for all environments)
  - No blocking I/O at module load  (all I/O deferred to function calls)
  - Graceful degradation if FastAPI not installed
  - Thread-safe singleton

Author: CYBERDUDEBIVASH® SENTINEL APEX
Version: v134.0
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger("CDB-GUARDIAN")

# ── Paths (resolved at import; no I/O performed here) ─────────────────────────
_BASE   = Path(__file__).resolve().parent.parent.parent
_DATA   = _BASE / "data"
_FEED   = _BASE / "api" / "feed.json"
_LATEST = _BASE / "api" / "latest.json"
_MFST   = _DATA / "stix" / "feed_manifest.json"
_HEALTH = _DATA / "health"

# ── Thresholds (override via env) ─────────────────────────────────────────────
FEED_MAX_AGE_H  = float(os.getenv("CDB_FEED_MAX_AGE_H",  "12"))  # hours → stale
FEED_WARN_AGE_H = float(os.getenv("CDB_FEED_WARN_AGE_H", "4"))   # hours → warn
STALE_THRESHOLD = FEED_MAX_AGE_H  * 3600                          # seconds
WARN_THRESHOLD  = FEED_WARN_AGE_H * 3600


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FeedFreshness:
    """Feed file inspection result — pure data, no I/O."""
    path:          str  = ""
    exists:        bool = False
    size_bytes:    int  = 0
    mtime_ts:      float = 0.0
    age_seconds:   float = 0.0
    item_count:    int  = 0
    status:        str  = "unknown"   # fresh | warn | stale | missing | error
    last_modified: str  = ""

    @property
    def age_hours(self) -> float:
        return round(self.age_seconds / 3600, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path":          self.path,
            "exists":        self.exists,
            "size_bytes":    self.size_bytes,
            "age_hours":     self.age_hours,
            "item_count":    self.item_count,
            "status":        self.status,
            "last_modified": self.last_modified,
        }


@dataclass
class ApexState:
    """
    Dynamic APEX mode evaluation result.
    APEX = fully_operational only when ALL gate conditions pass.
    """
    enabled:       bool              = False
    mode:          str               = "degraded"   # fully_operational | degraded | offline
    gates_passed:  List[str]         = field(default_factory=list)
    gates_failed:  List[str]         = field(default_factory=list)
    evaluated_at:  str               = ""
    router_status: Dict[str, bool]   = field(default_factory=dict)
    feed_age_hours: float            = 0.0
    advisory_count: int              = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "apex_enabled":   self.enabled,
            "mode":           self.mode,
            "gates_passed":   self.gates_passed,
            "gates_failed":   self.gates_failed,
            "evaluated_at":   self.evaluated_at,
            "router_status":  self.router_status,
            "feed_age_hours": self.feed_age_hours,
            "advisory_count": self.advisory_count,
        }


@dataclass
class SyncState:
    """Full platform synchronisation check result."""
    status:          str               = "unknown"  # live | warn | stale | degraded
    apex:            Optional[ApexState] = None
    feed:            Optional[FeedFreshness] = None
    manifest:        Optional[FeedFreshness] = None
    module_errors:   List[str]         = field(default_factory=list)
    desync_events:   List[str]         = field(default_factory=list)
    checked_at:      str               = ""
    platform_uptime: float             = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sync_status":       self.status,
            "checked_at":        self.checked_at,
            "platform_uptime_s": round(self.platform_uptime, 1),
            "apex":              self.apex.to_dict() if self.apex else {},
            "feed":              self.feed.to_dict() if self.feed else {},
            "manifest":          self.manifest.to_dict() if self.manifest else {},
            "module_errors":     self.module_errors,
            "desync_events":     self.desync_events,
        }


# ─────────────────────────────────────────────────────────────────────────────
# FEED FRESHNESS CHECKER
# ─────────────────────────────────────────────────────────────────────────────

class FreshnessChecker:
    """
    Inspects feed/manifest files for staleness.
    All I/O happens inside check() — zero I/O at class definition.
    """

    @staticmethod
    def check(path: Path) -> FeedFreshness:
        result = FeedFreshness(path=str(path))
        try:
            if not path.exists():
                result.status = "missing"
                return result

            stat              = path.stat()
            result.exists     = True
            result.size_bytes = stat.st_size
            result.mtime_ts   = stat.st_mtime
            now               = time.time()
            result.age_seconds = now - stat.st_mtime
            result.last_modified = datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat()

            # Item count (JSON only)
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    result.item_count = len(data)
                elif isinstance(data, dict):
                    items = data.get("data") or data.get("items") or data.get("advisories") or []
                    result.item_count = len(items) if isinstance(items, list) else 0
            except Exception:
                result.item_count = 0

            # Freshness classification
            if result.age_seconds < WARN_THRESHOLD:
                result.status = "fresh"
            elif result.age_seconds < STALE_THRESHOLD:
                result.status = "warn"
            else:
                result.status = "stale"

        except Exception as exc:
            result.status = f"error:{exc}"

        return result


# ─────────────────────────────────────────────────────────────────────────────
# APEX MODE EVALUATOR
# ─────────────────────────────────────────────────────────────────────────────

class ApexEvaluator:
    """
    Evaluates dynamic APEX mode from live system state.
    Replaces the static CDB_APEX_ENABLED environment variable.

    Gate set — ALL must pass for "fully_operational":
      feed_exists  : api/feed.json exists with items
      feed_fresh   : feed modified within FEED_MAX_AGE_H hours
      manifest_ok  : stix/feed_manifest.json exists with items
      routers_ok   : all critical routers loaded (ingestion, monetize, onboarding)
    """

    CRITICAL_ROUTERS: frozenset = frozenset({"ingestion", "monetize", "onboarding"})

    def evaluate(
        self,
        feed:          FeedFreshness,
        manifest:      FeedFreshness,
        router_status: Dict[str, bool],
    ) -> ApexState:
        now    = datetime.now(timezone.utc).isoformat()
        passed: List[str] = []
        failed: List[str] = []

        # Gate 1: feed exists + populated
        if feed.exists and feed.item_count > 0:
            passed.append("feed_exists")
        else:
            failed.append(f"feed_exists (items={feed.item_count}, exists={feed.exists})")

        # Gate 2: feed freshness
        if feed.status in ("fresh", "warn"):
            passed.append(f"feed_fresh (age={feed.age_hours}h)")
        else:
            failed.append(f"feed_fresh (age={feed.age_hours}h, status={feed.status})")

        # Gate 3: manifest populated
        if manifest.exists and manifest.item_count > 0:
            passed.append("manifest_ok")
        else:
            failed.append(f"manifest_ok (items={manifest.item_count}, exists={manifest.exists})")

        # Gate 4: critical routers
        loaded  = {k for k, v in router_status.items() if v}
        missing = self.CRITICAL_ROUTERS - loaded
        if not missing:
            passed.append("routers_ok")
        else:
            failed.append(f"routers_ok (missing={sorted(missing)})")

        enabled = (len(failed) == 0)
        if enabled:
            mode = "fully_operational"
        elif len(passed) >= (len(passed) + len(failed)) // 2:
            mode = "degraded"
        else:
            mode = "offline"

        return ApexState(
            enabled=enabled,
            mode=mode,
            gates_passed=passed,
            gates_failed=failed,
            evaluated_at=now,
            router_status=dict(router_status),
            feed_age_hours=feed.age_hours,
            advisory_count=feed.item_count,
        )


# ─────────────────────────────────────────────────────────────────────────────
# SYNC EVENT LOGGER
# ─────────────────────────────────────────────────────────────────────────────

class SyncEventLogger:
    """
    Emits structured desync events to logger.
    Persists latest state to data/health/latest.json for external monitoring.
    Never raises — all persistence errors are silently swallowed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def emit(self, event_type: str, details: Dict[str, Any]) -> None:
        record = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "event":   event_type,
            "host":    _get_hostname(),
            **details,
        }
        level = logging.WARNING if "desync" in event_type else logging.INFO
        _log.log(level, "sync_event type=%s %s", event_type, json.dumps(details, default=str))
        self._persist(record)

    def _persist(self, record: Dict) -> None:
        try:
            _HEALTH.mkdir(parents=True, exist_ok=True)
            path = _HEALTH / "latest.json"
            tmp  = path.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(record, f, indent=2, default=str)
            tmp.rename(path)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE GUARDIAN — Central Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class PipelineGuardian:
    """
    Singleton orchestrator for pipeline health and synchronisation.

    Import and use the module-level `pipeline_guardian` singleton:
        from core.stability.pipeline_guardian import pipeline_guardian
        apex  = pipeline_guardian.evaluate_apex(router_status)
        state = pipeline_guardian.health_check(router_status)

    Import-safe: zero I/O at instantiation.
    Thread-safe: all state mutation is lock-protected.
    """

    def __init__(self) -> None:
        self._start     = time.monotonic()
        self._checker   = FreshnessChecker()
        self._evaluator = ApexEvaluator()
        self._evlog     = SyncEventLogger()
        self._last:     Optional[SyncState] = None
        self._lock      = threading.Lock()

    # ── Public interface ──────────────────────────────────────────────────────

    def evaluate_apex(
        self,
        router_status: Optional[Dict[str, bool]] = None,
    ) -> ApexState:
        """
        Dynamic APEX mode from live system state.
        Called by api/main.py to replace the static _APEX_ENABLED flag.
        """
        feed     = self._checker.check(_FEED)
        manifest = self._checker.check(_MFST)
        return self._evaluator.evaluate(feed, manifest, router_status or {})

    def health_check(
        self,
        router_status: Optional[Dict[str, bool]] = None,
    ) -> SyncState:
        """
        Full synchronisation health check.
        Returns SyncState with feed freshness, APEX evaluation, and desync events.
        """
        with self._lock:
            return self._run(router_status or {})

    def emit_ingestion_complete(self, count: int, source: str = "workflow") -> None:
        """Call after each ingestion run to log completion and trigger cache bust."""
        self._evlog.emit("ingestion_complete", {"count": count, "source": source})

    def emit_desync(self, source: str, detail: str) -> None:
        self._evlog.emit("desync", {"source": source, "detail": detail})

    def last_state(self) -> Optional[Dict[str, Any]]:
        return self._last.to_dict() if self._last else None

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(self, router_status: Dict[str, bool]) -> SyncState:
        now      = datetime.now(timezone.utc).isoformat()
        uptime   = time.monotonic() - self._start
        feed     = self._checker.check(_FEED)
        manifest = self._checker.check(_MFST)
        apex     = self._evaluator.evaluate(feed, manifest, router_status)
        desync   = self._detect_desync(feed, manifest, router_status)
        mod_errs = [k for k, v in router_status.items() if not v]

        if not desync and apex.mode == "fully_operational":
            status = "live"
        elif len(desync) == 0 or feed.status in ("fresh", "warn"):
            status = "warn"
        else:
            status = "degraded"

        state = SyncState(
            status=status,
            apex=apex,
            feed=feed,
            manifest=manifest,
            module_errors=mod_errs,
            desync_events=desync,
            checked_at=now,
            platform_uptime=uptime,
        )
        self._last = state
        for ev in desync:
            self._evlog.emit("desync", {"detail": ev})
        return state

    @staticmethod
    def _detect_desync(
        feed:          FeedFreshness,
        manifest:      FeedFreshness,
        router_status: Dict[str, bool],
    ) -> List[str]:
        events: List[str] = []

        # Feed vs manifest item divergence (>50%)
        if feed.item_count > 0 and manifest.item_count > 0:
            delta = abs(feed.item_count - manifest.item_count)
            if delta / max(feed.item_count, manifest.item_count) > 0.5:
                events.append(
                    f"feed_manifest_divergence feed={feed.item_count} "
                    f"manifest={manifest.item_count} delta={delta}"
                )

        # Feed newer than manifest by >5 min (ingestion ran but manifest stale)
        if (feed.mtime_ts > 0 and manifest.mtime_ts > 0
                and feed.mtime_ts > manifest.mtime_ts + 300):
            diff_min = round((feed.mtime_ts - manifest.mtime_ts) / 60, 1)
            events.append(
                f"feed_ahead_of_manifest by {diff_min}min"
            )

        # Stale feed
        if feed.status == "stale":
            events.append(
                f"feed_stale age={feed.age_hours}h threshold={FEED_MAX_AGE_H}h"
            )

        # Critical router failures
        crit_failed = sorted(
            k for k, v in router_status.items()
            if not v and k in ApexEvaluator.CRITICAL_ROUTERS
        )
        if crit_failed:
            events.append(f"critical_routers_failed {crit_failed}")

        return events


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL SINGLETON
# ─────────────────────────────────────────────────────────────────────────────
# Zero I/O at instantiation — safe at import time in all environments.
pipeline_guardian = PipelineGuardian()


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI HEALTH ROUTER
# ─────────────────────────────────────────────────────────────────────────────

try:
    from fastapi import APIRouter as _APIRouter
    from fastapi.responses import JSONResponse as _JSONResponse

    health_router = _APIRouter(tags=["Health & Sync"])

    # ── /api/v1/health/full ────────────────────────────────────────────────────
    @health_router.get(
        "/api/v1/health/full",
        summary="Full pipeline synchronisation health check",
    )
    async def full_health_check() -> _JSONResponse:
        """Returns feed freshness, APEX mode, desync events. Used by frontend heartbeat."""
        try:
            import api.main as _m
            rs = getattr(_m, "_router_status", {})
        except Exception:
            rs = {}
        state = pipeline_guardian.health_check(rs)
        code  = 200 if state.status in ("live", "warn") else 503
        return _JSONResponse(status_code=code, content=state.to_dict())

    # ── /apex/v1/status ────────────────────────────────────────────────────────
    @health_router.get(
        "/apex/v1/status",
        summary="APEX mode evaluation and full system state",
    )
    async def apex_status() -> _JSONResponse:
        """
        Authoritative APEX mode endpoint — dynamic evaluation, not a static flag.
        APEX = fully_operational only when ALL gates pass.
        """
        try:
            import api.main as _m
            rs = getattr(_m, "_router_status", {})
        except Exception:
            rs = {}
        state = pipeline_guardian.health_check(rs)
        a     = state.apex or ApexState()
        payload = {
            "platform":          "CYBERDUDEBIVASH® Sentinel APEX",
            "version":           "v134.0",
            "apex_mode":         a.mode,
            "apex_enabled":      a.enabled,
            "sync_status":       state.status,
            "gates_passed":      a.gates_passed,
            "gates_failed":      a.gates_failed,
            "feed":              state.feed.to_dict() if state.feed else {},
            "manifest":          state.manifest.to_dict() if state.manifest else {},
            "router_status":     a.router_status,
            "module_errors":     state.module_errors,
            "desync_events":     state.desync_events,
            "platform_uptime_s": round(state.platform_uptime, 1),
            "evaluated_at":      state.checked_at,
        }
        code = 200 if a.mode != "offline" else 503
        return _JSONResponse(status_code=code, content=payload)

    # ── /api/v1/health/feed ────────────────────────────────────────────────────
    @health_router.get(
        "/api/v1/health/feed",
        summary="Feed and manifest freshness",
    )
    async def feed_freshness_check() -> _JSONResponse:
        feed     = FreshnessChecker.check(_FEED)
        manifest = FreshnessChecker.check(_MFST)
        return _JSONResponse({
            "feed":       feed.to_dict(),
            "manifest":   manifest.to_dict(),
            "status":     "ok" if feed.status in ("fresh", "warn") else "stale",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        })

    _HEALTH_ROUTER_OK = True
    _log.debug("pipeline_guardian: health_router mounted (3 routes)")

except ImportError:
    _HEALTH_ROUTER_OK = False
    health_router = None
    _log.warning("pipeline_guardian: FastAPI unavailable — health_router=None")
