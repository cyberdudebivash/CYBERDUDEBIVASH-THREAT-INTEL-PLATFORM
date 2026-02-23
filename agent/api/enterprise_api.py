#!/usr/bin/env python3
"""
enterprise_api.py — CyberDudeBivash SENTINEL APEX v17.0
ENTERPRISE API DATA LAYER

Full-access enterprise API handler. Provides:
  - Complete threat entries with IOC details
  - STIX bundle access
  - Actor intelligence
  - Predictive risk forecasts
  - Campaign tracker data
  - Platform telemetry / metrics
  - Archive access

Designed for FastAPI integration with API key authentication middleware.
This module is the data layer only — pure data access, no HTTP.

Endpoints (data layer):
  GET /api/v1/enterprise/threats           → Full threat entries with IOCs
  GET /api/v1/enterprise/stix/{bundle_id}  → Full STIX bundle
  GET /api/v1/enterprise/actors            → Actor intelligence summary
  GET /api/v1/enterprise/campaigns         → Active campaign data
  GET /api/v1/enterprise/forecast/{id}     → Exploit forecast for threat
  GET /api/v1/enterprise/metrics           → Platform metrics
  GET /api/v1/enterprise/archive           → Archived threat list
  POST /api/v1/enterprise/search          → Full-text threat search
"""

import json
import os
import logging
from typing import Dict, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger("CDB-API-ENTERPRISE")

MANIFEST_PATH = "data/stix/feed_manifest.json"
STIX_DIR = "data/stix"
ARCHIVE_DIR = "data/archive"


class EnterpriseAPIHandler:
    """
    Full-access data handler for Enterprise API tier.
    Returns complete intelligence data including IOCs, STIX, actors, forecasts.
    """

    def get_all_threats(self, limit: int = 100, include_archived: bool = False) -> Dict:
        """Returns full threat entries including IOC details."""
        entries = self._load_manifest_entries()
        if not include_archived:
            entries = [e for e in entries if e.get("status") != "archived"]
        sorted_entries = sorted(
            entries,
            key=lambda x: x.get("generated_at", ""),
            reverse=True
        )[:limit]

        return {
            "api_tier": "ENTERPRISE",
            "endpoint": "/api/v1/enterprise/threats",
            "count": len(sorted_entries),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries": sorted_entries,
        }

    def get_stix_bundle(self, bundle_id: str) -> Optional[Dict]:
        """Returns full STIX bundle JSON by bundle_id reference."""
        # Try to find file matching bundle_id
        try:
            for filename in os.listdir(STIX_DIR):
                if not filename.endswith(".json") or filename == "feed_manifest.json":
                    continue
                filepath = os.path.join(STIX_DIR, filename)
                with open(filepath, "r") as f:
                    bundle = json.load(f)
                if bundle.get("id") == bundle_id:
                    return {
                        "api_tier": "ENTERPRISE",
                        "endpoint": f"/api/v1/enterprise/stix/{bundle_id}",
                        "bundle": bundle,
                        "retrieved_at": datetime.now(timezone.utc).isoformat(),
                    }
        except Exception as e:
            logger.warning(f"STIX bundle lookup failed for {bundle_id}: {e}")
        return None

    def get_actor_intelligence(self) -> Dict:
        """Returns full actor intelligence summary from registry."""
        try:
            from agent.threat_actor.actor_registry import actor_registry
            profiles = actor_registry.ACTOR_PROFILES
            return {
                "api_tier": "ENTERPRISE",
                "endpoint": "/api/v1/enterprise/actors",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "actor_count": len(profiles),
                "actors": profiles,
            }
        except Exception as e:
            logger.warning(f"Actor intel fetch failed: {e}")
            return {"error": str(e)}

    def get_campaign_data(self, days: int = 30) -> Dict:
        """Returns active campaign tracker data."""
        try:
            from agent.threat_actor.campaign_tracker import campaign_tracker
            active = campaign_tracker.get_active_campaigns(days=days)
            summary = campaign_tracker.get_campaign_summary()
            return {
                "api_tier": "ENTERPRISE",
                "endpoint": "/api/v1/enterprise/campaigns",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "window_days": days,
                "summary": summary,
                "active_campaigns": active,
            }
        except Exception as e:
            logger.warning(f"Campaign data fetch failed: {e}")
            return {"error": str(e)}

    def get_exploit_forecast(self, bundle_id: str) -> Optional[Dict]:
        """Returns exploit forecast for a specific threat bundle."""
        try:
            from agent.predictive.exploit_forecaster import exploit_forecaster
            entries = self._load_manifest_entries()
            for entry in entries:
                if entry.get("bundle_id") == bundle_id:
                    forecast = exploit_forecaster.forecast(
                        cvss_score=entry.get("cvss_score"),
                        epss_score=entry.get("epss_score"),
                        kev_present=entry.get("kev_present", False),
                        headline=entry.get("title", ""),
                        content="",
                        actor_tag=entry.get("actor_tag", ""),
                        mitre_match_count=len(entry.get("mitre_tactics", [])),
                    )
                    return {
                        "api_tier": "ENTERPRISE",
                        "endpoint": f"/api/v1/enterprise/forecast/{bundle_id}",
                        "bundle_id": bundle_id,
                        "threat_title": entry.get("title"),
                        "forecast": forecast,
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                    }
        except Exception as e:
            logger.warning(f"Forecast fetch failed for {bundle_id}: {e}")
        return None

    def get_platform_metrics(self) -> Dict:
        """Returns full platform metrics from telemetry."""
        try:
            from agent.core.metrics import platform_metrics
            return {
                "api_tier": "ENTERPRISE",
                "endpoint": "/api/v1/enterprise/metrics",
                "metrics": platform_metrics.compute_rolling_metrics(),
            }
        except Exception as e:
            return {"error": str(e)}

    def search_threats(self, query: str, limit: int = 50) -> Dict:
        """Full-text search across all threat entries."""
        entries = self._load_manifest_entries()
        query_lower = query.lower()
        results = []

        for entry in entries:
            title = entry.get("title", "").lower()
            actor = entry.get("actor_tag", "").lower()
            tactics = " ".join(entry.get("mitre_tactics", [])).lower()
            severity = entry.get("severity", "").lower()

            if (
                query_lower in title or
                query_lower in actor or
                query_lower in tactics or
                query_lower in severity
            ):
                results.append(entry)

        return {
            "api_tier": "ENTERPRISE",
            "endpoint": "/api/v1/enterprise/search",
            "query": query,
            "results_count": len(results[:limit]),
            "results": results[:limit],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_archive_list(self) -> Dict:
        """Lists all archived intelligence entries."""
        archive_log = "data/archive/archive_log.json"
        entries = []
        if os.path.exists(archive_log):
            try:
                with open(archive_log, "r") as f:
                    logs = json.load(f)
                for log in logs:
                    entries.extend(log.get("archived_files", []))
            except Exception as e:
                logger.warning(f"Archive list read failed: {e}")
        return {
            "api_tier": "ENTERPRISE",
            "endpoint": "/api/v1/enterprise/archive",
            "archive_count": len(entries),
            "archived_files": entries,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _load_manifest_entries(self) -> List[Dict]:
        if not os.path.exists(MANIFEST_PATH):
            return []
        try:
            with open(MANIFEST_PATH, "r") as f:
                manifest = json.load(f)
            return manifest.get("entries", [])
        except Exception as e:
            logger.warning(f"Enterprise API manifest load failed: {e}")
            return []


# Singleton instance
enterprise_api = EnterpriseAPIHandler()
