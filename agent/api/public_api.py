#!/usr/bin/env python3
"""
public_api.py — CyberDudeBivash SENTINEL APEX v17.0
PUBLIC API DATA LAYER

Provides read-only access to threat intelligence data for public/free tier users.
Serves: limited feed manifest, recent threats (last 10), public risk scores.

Designed for FastAPI integration:
  from agent.api.public_api import PublicAPIHandler, api_handler

Rate limits and full web serving are handled by FastAPI middleware.
This module is the data layer only — pure data access, no HTTP.

Endpoints (data layer):
  GET /api/v1/threats           → Latest 10 threat entries
  GET /api/v1/feed              → Public feed manifest (limited)
  GET /api/v1/health            → Platform health status
  GET /api/v1/stats             → Public platform statistics
  GET /api/v1/threat/{id}       → Single threat summary (no IOC details)
"""

import json
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger("CDB-API-PUBLIC")

MANIFEST_PATH = "data/stix/feed_manifest.json"
TELEMETRY_PATH = "data/telemetry_log.json"

# Public tier limits
PUBLIC_MAX_ENTRIES = 10
PUBLIC_MAX_IOC_REVEAL = False  # No IOC details for free tier


class PublicAPIHandler:
    """
    Data handler for public/free tier API endpoints.
    Read-only. No IOC details. Limited to recent N entries.
    """

    def get_latest_threats(self, limit: int = PUBLIC_MAX_ENTRIES) -> Dict:
        """
        Returns latest N threat entries (stripped of IOC details for public tier).
        """
        entries = self._load_manifest_entries()
        # Filter to non-archived, sort by date
        active = [e for e in entries if e.get("status") != "archived"]
        # Sort by generated_at descending
        sorted_entries = sorted(
            active,
            key=lambda x: x.get("generated_at", ""),
            reverse=True
        )[:limit]

        # Strip sensitive fields for public tier
        public_entries = [self._strip_for_public(e) for e in sorted_entries]

        return {
            "api_tier": "FREE",
            "endpoint": "/api/v1/threats",
            "count": len(public_entries),
            "max_allowed": PUBLIC_MAX_ENTRIES,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": public_entries,
            "upgrade_note": "Upgrade to Pro for full IOC details, STIX export, and 90-day history.",
        }

    def get_public_feed(self) -> Dict:
        """Returns public feed manifest with limited fields."""
        entries = self._load_manifest_entries()
        active = [e for e in entries if e.get("status") != "archived"]

        return {
            "api_tier": "FREE",
            "endpoint": "/api/v1/feed",
            "platform": "CyberDudeBivash SENTINEL APEX",
            "version": "v17.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(entries),
            "active_entries": len(active),
            "preview_entries": [self._strip_for_public(e) for e in active[:PUBLIC_MAX_ENTRIES]],
            "feed_url": "https://intel.cyberdudebivash.com",
        }

    def get_platform_health(self) -> Dict:
        """Returns basic platform health for public consumption."""
        try:
            from agent.core.healthcheck import health_checker
            report = health_checker.run_full_check()
            return {
                "api_tier": "FREE",
                "endpoint": "/api/v1/health",
                "status": report["overall_status"],
                "version": report["version"],
                "checked_at": report["checked_at"],
            }
        except Exception as e:
            return {
                "api_tier": "FREE",
                "endpoint": "/api/v1/health",
                "status": "unknown",
                "error": str(e),
            }

    def get_public_stats(self) -> Dict:
        """Returns public platform statistics."""
        entries = self._load_manifest_entries()
        active = [e for e in entries if e.get("status") != "archived"]

        # Severity distribution
        severity_counts: Dict[str, int] = {}
        for entry in active:
            sev = entry.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Average risk score
        scores = [float(e.get("risk_score", 0)) for e in active if e.get("risk_score")]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0

        return {
            "api_tier": "FREE",
            "endpoint": "/api/v1/stats",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_threats_tracked": len(entries),
            "active_threats": len(active),
            "severity_distribution": severity_counts,
            "avg_risk_score": avg_score,
            "upgrade_note": "Upgrade to Enterprise for IOC exports, STIX bundles, actor intelligence, and forecasting.",
        }

    def get_single_threat(self, bundle_id: str) -> Optional[Dict]:
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
        }
        return {k: v for k, v in entry.items() if k in PUBLIC_FIELDS}

    def _load_manifest_entries(self) -> List[Dict]:
        if not os.path.exists(MANIFEST_PATH):
            return []
        try:
            with open(MANIFEST_PATH, "r") as f:
                manifest = json.load(f)
            return manifest.get("entries", [])
        except Exception as e:
            logger.warning(f"Public API manifest load failed: {e}")
            return []


# Singleton instance
public_api = PublicAPIHandler()
