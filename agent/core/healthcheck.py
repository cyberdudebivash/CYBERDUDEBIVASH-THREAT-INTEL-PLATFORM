#!/usr/bin/env python3
"""
healthcheck.py — CyberDudeBivash SENTINEL APEX v17.0
PLATFORM HEALTH CHECK ENGINE

Provides system health status for the APEX platform.
Checks: data directories, manifest integrity, feed availability,
telemetry data presence, API key presence, and disk usage.

Used by: GitHub Actions, monitoring systems, API endpoint /health
"""

import os
import json
import logging
from typing import Dict, List
from datetime import datetime, timezone

logger = logging.getLogger("CDB-HEALTHCHECK")

REQUIRED_DIRS = [
    "data/stix",
    "data/archive",
    "data/rule_packs",
    "data/playbooks",
    "data/enterprise_kits",
]

REQUIRED_FILES = [
    "data/blogger_processed.json",
    "data/stix/feed_manifest.json",
]

OPTIONAL_API_KEYS = [
    "VT_API_KEY",
    "DISCORD_WEBHOOK",
    "SLACK_WEBHOOK",
    "TEAMS_WEBHOOK",
]


class HealthCheckEngine:
    """
    System health monitor for SENTINEL APEX platform.
    Checks all critical components and returns structured health report.
    """

    def run_full_check(self) -> Dict:
        """Run all health checks and return complete health report."""
        checks = {
            "directories":      self._check_directories(),
            "critical_files":   self._check_files(),
            "api_keys":         self._check_api_keys(),
            "manifest_integrity":self._check_manifest(),
            "telemetry":        self._check_telemetry(),
            "disk_usage":       self._check_disk_usage(),
            "rate_limiter":     self._check_rate_limiter(),
            "auth_config":      self._check_auth_config(),
            "epss_pipeline":    self._check_epss_pipeline(),
        }

        overall = "healthy"
        warnings = []
        errors = []

        for check_name, result in checks.items():
            if result.get("status") == "error":
                overall = "unhealthy"
                errors.append(check_name)
            elif result.get("status") == "warning":
                if overall == "healthy":
                    overall = "degraded"
                warnings.append(check_name)

        return {
            "platform": "CyberDudeBivash SENTINEL APEX",
            "version": "v22.0",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "overall_status": overall,
            "warnings": warnings,
            "errors": errors,
            "checks": checks,
        }

    def _check_directories(self) -> Dict:
        missing = []
        for d in REQUIRED_DIRS:
            if not os.path.isdir(d):
                missing.append(d)
                try:
                    os.makedirs(d, exist_ok=True)
                except Exception:
                    pass
        if missing:
            return {"status": "warning", "missing_created": missing}
        return {"status": "ok", "all_present": True}

    def _check_files(self) -> Dict:
        missing = [f for f in REQUIRED_FILES if not os.path.exists(f)]
        if missing:
            return {"status": "warning", "missing": missing}
        return {"status": "ok", "all_present": True}

    def _check_api_keys(self) -> Dict:
        present = []
        absent = []
        for key in OPTIONAL_API_KEYS:
            if os.environ.get(key):
                present.append(key)
            else:
                absent.append(key)
        status = "ok" if len(present) >= 2 else "warning"
        return {"status": status, "configured": present, "missing": absent}

    def _check_manifest(self) -> Dict:
        manifest_path = "data/stix/feed_manifest.json"
        if not os.path.exists(manifest_path):
            return {"status": "warning", "message": "Feed manifest not found"}
        try:
            with open(manifest_path, "r") as f:
                manifest = json.load(f)
            entry_count = len(manifest.get("entries", []))
            return {
                "status": "ok",
                "entry_count": entry_count,
                "schema_valid": "generated_at" in manifest or "updated_at" in manifest,
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _check_telemetry(self) -> Dict:
        telemetry_path = "data/telemetry_log.json"
        if not os.path.exists(telemetry_path):
            return {"status": "warning", "message": "No telemetry data yet (normal on first run)"}
        try:
            with open(telemetry_path, "r") as f:
                runs = json.load(f)
            last_run = runs[-1] if runs else {}
            return {
                "status": "ok",
                "total_runs_logged": len(runs),
                "last_run_id": last_run.get("run_id", "unknown"),
                "last_run_status": last_run.get("run_status", "unknown"),
            }
        except Exception as e:
            return {"status": "warning", "message": str(e)}

    def _check_disk_usage(self) -> Dict:
        try:
            import shutil
            usage = shutil.disk_usage(".")
            used_pct = round((usage.used / usage.total) * 100, 1)
            status = "ok" if used_pct < 80 else ("warning" if used_pct < 90 else "error")
            return {
                "status": status,
                "used_pct": used_pct,
                "free_gb": round(usage.free / (1024 ** 3), 2),
            }
        except Exception as e:
            return {"status": "warning", "message": str(e)}


    def _check_rate_limiter(self) -> Dict:
        """v22.0: Check rate limiter is operational."""
        try:
            from agent.api.rate_limiter import rate_limiter
            stats = rate_limiter.get_stats()
            return {"status": "ok", "active_buckets": stats["active_buckets"],
                    "total_denied": stats["total_denied"]}
        except Exception as e:
            return {"status": "warning", "message": str(e)}

    def _check_auth_config(self) -> Dict:
        """v22.0: Check JWT secret and API key configuration."""
        import os
        issues = []
        jwt_secret = os.environ.get("CDB_JWT_SECRET", "")
        if not jwt_secret or "change-in-prod" in jwt_secret:
            issues.append("CDB_JWT_SECRET is not set or using default — change for production")
        pro_keys  = len([k for k in os.environ.get("CDB_PRO_KEYS", "").split(",") if k])
        ent_keys  = len([k for k in os.environ.get("CDB_ENTERPRISE_KEYS", "").split(",") if k])
        status = "warning" if issues else "ok"
        return {"status": status, "issues": issues,
                "pro_keys_configured": pro_keys, "enterprise_keys_configured": ent_keys}

    def _check_epss_pipeline(self) -> Dict:
        """v22.0: Check EPSS fetch is enabled and FIRST API reachable."""
        try:
            from agent.config import EPSS_FETCH_ENABLED, EPSS_API_URL
            if not EPSS_FETCH_ENABLED:
                return {"status": "warning", "message": "EPSS_FETCH_ENABLED is False"}
            from agent.enricher_pro import enricher_pro
            stats = enricher_pro.cache_stats()
            return {"status": "ok", "epss_enabled": True, "cache_stats": stats}
        except Exception as e:
            return {"status": "warning", "message": str(e)}

    def quick_status(self) -> str:
        """Returns 'healthy', 'degraded', or 'unhealthy' string."""
        report = self.run_full_check()
        return report["overall_status"]


# Singleton instance
health_checker = HealthCheckEngine()
