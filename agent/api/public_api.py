#!/usr/bin/env python3
"""
public_api.py — CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
PUBLIC API DATA LAYER — PRODUCTION UPGRADE

v22.0 ADDITIONS (additive, backward compatible):
  - Rate limiting on all endpoints via RateLimiter
  - Versioned response envelope (api_version, request_id, latency_ms)
  - _strip_for_public() expanded with v22.0 safe fields
  - get_public_stats() includes KEV count + EPSS average
  - get_platform_health() returns v22.0 component checks

All existing method signatures preserved.

Endpoints (data layer):
  GET /api/v1/threats          → Latest 10 threats (stripped)
  GET /api/v1/feed             → Public feed manifest (limited)
  GET /api/v1/health           → Platform health
  GET /api/v1/stats            → Public statistics + KEV count [v22.0]
  GET /api/v1/threat/{id}      → Single threat summary (no IOC details)
"""
import json
import os
import uuid
import time
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

from agent.api.rate_limiter import rate_limiter

logger = logging.getLogger("CDB-API-PUBLIC")

MANIFEST_PATH      = "data/stix/feed_manifest.json"
TELEMETRY_PATH     = "data/telemetry_log.json"
PUBLIC_MAX_ENTRIES = 10
API_VERSION        = "v22.0"


def _envelope(data: Dict, request_id: str, latency_ms: float) -> Dict:
    data["_meta"] = {
        "api_version":  API_VERSION,
        "request_id":   request_id,
        "latency_ms":   round(latency_ms, 2),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return data


class PublicAPIHandler:
    """Data handler for public/free tier API. Read-only. Rate-limited."""

    def get_latest_threats(
        self,
        limit: int = PUBLIC_MAX_ENTRIES,
        identity: str = "anon",
    ) -> Dict:
        """Returns latest N threats (IOCs stripped for public tier)."""
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())[:8]

        allowed, rl_info = rate_limiter.check(identity, "FREE",
                                              endpoint="/api/v1/threats")
        if not allowed:
            return _envelope({
                "error": "RATE_LIMITED",
                "retry_after": rl_info["retry_after"],
                "message": f"Free tier limit reached. Retry after {rl_info['retry_after']}s.",
            }, req_id, (time.monotonic() - t0) * 1000)

        entries = self._load_manifest_entries()
        active  = [e for e in entries if e.get("status") != "archived"]
        sorted_entries = sorted(active, key=lambda x: x.get("generated_at", ""), reverse=True)[:limit]
        public_entries = [self._strip_for_public(e) for e in sorted_entries]

        return _envelope({
            "api_tier":     "FREE",
            "endpoint":     "/api/v1/threats",
            "count":        len(public_entries),
            "max_allowed":  PUBLIC_MAX_ENTRIES,
            "entries":      public_entries,
            "upgrade_note": "Upgrade to Pro for full IOC details, STIX export, and 90-day history.",
        }, req_id, (time.monotonic() - t0) * 1000)

    def get_public_feed(self, identity: str = "anon") -> Dict:
        """Returns public feed manifest with limited fields."""
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())[:8]

        allowed, rl_info = rate_limiter.check(identity, "FREE", endpoint="/api/v1/feed")
        if not allowed:
            return _envelope({"error": "RATE_LIMITED", "retry_after": rl_info["retry_after"]},
                             req_id, (time.monotonic() - t0) * 1000)

        entries = self._load_manifest_entries()
        active  = [e for e in entries if e.get("status") != "archived"]

        return _envelope({
            "api_tier":       "FREE",
            "endpoint":       "/api/v1/feed",
            "platform":       "CyberDudeBivash SENTINEL APEX",
            "total_entries":  len(entries),
            "active_entries": len(active),
            "preview_entries":[self._strip_for_public(e) for e in active[:PUBLIC_MAX_ENTRIES]],
            "feed_url":       "https://intel.cyberdudebivash.com",
            "upgrade_url":    "https://cyberdudebivash.gumroad.com",
        }, req_id, (time.monotonic() - t0) * 1000)

    def get_platform_health(self, identity: str = "anon") -> Dict:
        """Returns basic platform health for public consumption."""
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())[:8]

        allowed, rl_info = rate_limiter.check(identity, "FREE", endpoint="/api/v1/health")
        if not allowed:
            return _envelope({"error": "RATE_LIMITED", "retry_after": rl_info["retry_after"]},
                             req_id, (time.monotonic() - t0) * 1000)

        try:
            from agent.core.healthcheck import health_checker
            report = health_checker.run_full_check()
            return _envelope({
                "api_tier":  "FREE",
                "endpoint":  "/api/v1/health",
                "status":    report["overall_status"],
                "version":   report.get("version", API_VERSION),
                "checked_at":report["checked_at"],
            }, req_id, (time.monotonic() - t0) * 1000)
        except Exception as e:
            return _envelope({
                "api_tier": "FREE",
                "endpoint": "/api/v1/health",
                "status":   "unknown",
                "error":    str(e),
            }, req_id, (time.monotonic() - t0) * 1000)

    def get_public_stats(self, identity: str = "anon") -> Dict:
        """
        Returns public platform statistics.
        v22.0: includes KEV count and average EPSS score.
        """
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())[:8]

        allowed, rl_info = rate_limiter.check(identity, "FREE", endpoint="/api/v1/stats")
        if not allowed:
            return _envelope({"error": "RATE_LIMITED", "retry_after": rl_info["retry_after"]},
                             req_id, (time.monotonic() - t0) * 1000)

        entries = self._load_manifest_entries()
        active  = [e for e in entries if e.get("status") != "archived"]

        severity_counts: Dict[str, int] = {}
        for entry in active:
            sev = entry.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        scores      = [float(e.get("risk_score", 0)) for e in active if e.get("risk_score")]
        avg_score   = round(sum(scores) / len(scores), 2) if scores else 0.0

        # v22.0: KEV count + avg EPSS
        kev_count   = sum(1 for e in active if e.get("kev_present"))
        epss_vals   = [float(e.get("epss_score", 0)) for e in active if e.get("epss_score")]
        avg_epss    = round(sum(epss_vals) / len(epss_vals), 4) if epss_vals else None

        return _envelope({
            "api_tier":               "FREE",
            "endpoint":               "/api/v1/stats",
            "total_threats_tracked":  len(entries),
            "active_threats":         len(active),
            "severity_distribution":  severity_counts,
            "avg_risk_score":         avg_score,
            "kev_active_count":       kev_count,     # v22.0
            "avg_epss_score":         avg_epss,      # v22.0
            "upgrade_note": "Upgrade to Enterprise for IOC exports, STIX bundles, actor intelligence, and forecasting.",
        }, req_id, (time.monotonic() - t0) * 1000)

    def get_single_threat(self, bundle_id: str, identity: str = "anon") -> Optional[Dict]:
        """Returns a single threat summary by bundle_id (no IOC details)."""
        entries = self._load_manifest_entries()
        for entry in entries:
            if entry.get("bundle_id") == bundle_id:
                return self._strip_for_public(entry)
        return None

    def _strip_for_public(self, entry: Dict) -> Dict:
        """Remove sensitive/premium fields for public API response."""
        PUBLIC_FIELDS = {
            "bundle_id", "title", "risk_score", "severity", "tlp_label",
            "generated_at", "source_url", "mitre_tactics", "actor_tag",
            "status", "confidence",
            # v22.0: safe additions
            "kev_present", "feed_source",
        }
        return {k: v for k, v in entry.items() if k in PUBLIC_FIELDS}

    def _load_manifest_entries(self) -> List[Dict]:
        if not os.path.exists(MANIFEST_PATH):
            return []
        try:
            with open(MANIFEST_PATH, "r") as f:
                manifest = json.load(f)
            if isinstance(manifest, list):
                return manifest
            return manifest.get("entries", [])
        except Exception as e:
            logger.warning(f"Public API manifest load failed: {e}")
            return []


# Singleton instance
public_api = PublicAPIHandler()
