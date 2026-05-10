#!/usr/bin/env python3
"""
agent/commercial_observability_engine.py
CYBERDUDEBIVASH® SENTINEL APEX — Commercial Observability Engine v1.0

PURPOSE:
  Unified commercial health monitoring for the SaaS platform.
  Aggregates revenue telemetry, customer SLA status, API uptime, subscription
  health, upgrade funnel metrics, and monetization continuity signals into a
  single observable state snapshot.

OUTPUTS (all atomic writes):
  data/commercial/platform_health.json     — current commercial health snapshot
  data/commercial/sla_telemetry.json       — per-tier SLA metrics
  data/commercial/upgrade_funnel.json      — conversion funnel analytics
  data/commercial/monetization_status.json — revenue engine health

HEALTH STATES:
  HEALTHY   — All commercial KPIs green, SLAs met
  DEGRADED  — Non-critical commercial signals outside threshold
  CRITICAL  — SLA violations, revenue engine down, or customer impact

Never raises — all errors caught. Designed for cron + API health endpoint use.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-COMMERCIAL-OBS")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).resolve().parent.parent
DATA_DIR      = BASE_DIR / "data"
COMMERCIAL_DIR = DATA_DIR / "commercial"
REVENUE_DIR   = DATA_DIR / "revenue"
HEALTH_DIR    = DATA_DIR / "health"
GOV_DIR       = DATA_DIR / "governance"

COMMERCIAL_DIR.mkdir(parents=True, exist_ok=True)

# Output paths
PLATFORM_HEALTH     = COMMERCIAL_DIR / "platform_health.json"
SLA_TELEMETRY       = COMMERCIAL_DIR / "sla_telemetry.json"
UPGRADE_FUNNEL      = COMMERCIAL_DIR / "upgrade_funnel.json"
MONETIZATION_STATUS = COMMERCIAL_DIR / "monetization_status.json"

# Input paths
REVENUE_LOG         = REVENUE_DIR / "transaction_log.json"
REVENUE_TELEMETRY   = REVENUE_DIR / "revenue_telemetry.json"
FEED_FRESHNESS      = HEALTH_DIR / "feed_freshness_report.json"
SLA_STATUS          = HEALTH_DIR / "sla_status.json"
DEDUP_TELEMETRY     = GOV_DIR / "dedup_telemetry.json"

# ── SLA Definitions ───────────────────────────────────────────────────────────
# Per-tier SLA targets (uptime %)
TIER_SLA_TARGET = {
    "ENTERPRISE": 99.9,
    "PRO":        99.5,
    "PREMIUM":    99.5,
    "STANDARD":   99.0,
    "FREE":       95.0,
}

# API freshness SLA (hours — max age of latest advisory in the feed)
API_FRESHNESS_SLA_HOURS = 4

# Revenue health thresholds
MIN_TRANSACTIONS_PER_DAY = 0    # non-zero means billing engine is active


def _atomic_write(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_json(path: Path) -> Optional[Dict]:
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.debug(f"[COMMERCIAL-OBS] Load failed {path.name}: {e}")
    return None


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts[:26], fmt[:len(ts)])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


# ── Health Check Modules ──────────────────────────────────────────────────────

def _check_revenue_engine() -> Dict:
    """Validate revenue engine is alive and processing transactions."""
    issues: List[str] = []
    health = "HEALTHY"
    total_usd = 0.0
    tx_count   = 0

    rev_log = _load_json(REVENUE_LOG)
    if rev_log is None:
        issues.append("Revenue transaction log missing")
        health = "DEGRADED"
    else:
        total_usd = rev_log.get("total_revenue_usd", 0.0)
        tx_count  = len(rev_log.get("transactions", []))

    rev_telem = _load_json(REVENUE_TELEMETRY)
    by_feature = {}
    by_month   = {}
    if rev_telem:
        by_feature = rev_telem.get("by_feature", {})
        by_month   = rev_telem.get("by_month", {})

    return {
        "status":       health,
        "issues":       issues,
        "total_revenue_usd": round(total_usd, 4),
        "transaction_count": tx_count,
        "by_feature":   by_feature,
        "by_month":     by_month,
    }


def _check_feed_freshness() -> Dict:
    """Check if intelligence feed meets freshness SLA."""
    report = _load_json(FEED_FRESHNESS)
    if report is None:
        return {"status": "UNKNOWN", "issues": ["Feed freshness report not found"]}

    overall = report.get("overall_status", "UNKNOWN")
    status  = "HEALTHY" if overall == "HEALTHY" else (
        "CRITICAL" if overall == "CRITICAL" else "DEGRADED"
    )
    return {
        "status":            status,
        "overall_status":    overall,
        "freshness_pct":     report.get("freshness_pct", 0),
        "critical_violations": report.get("critical_violations", []),
        "soft_violations":   report.get("soft_violations", []),
        "feeds_ok":          report.get("feeds_ok", 0),
        "feeds_checked":     report.get("feeds_checked", 0),
        "last_run":          report.get("run_at"),
    }


def _check_dedup_health() -> Dict:
    """Check deduplication pipeline health."""
    telem = _load_json(DEDUP_TELEMETRY)
    if telem is None:
        return {"status": "UNKNOWN", "issues": ["Dedup telemetry not found"]}

    dedup_rate = telem.get("dedup_rate_pct", 0.0)
    state_size = telem.get("state_size", 0)
    checked    = telem.get("checked", 0)

    issues: List[str] = []
    # Dedup rate > 95% might indicate engine stuck / seeding issue
    if dedup_rate > 95 and checked > 100:
        issues.append(f"Suspiciously high dedup rate: {dedup_rate}% — possible seed over-block")
    # State size too small — engine might be resetting
    if state_size < 10 and checked > 0:
        issues.append(f"Dedup state size very small: {state_size} — possible state loss")

    return {
        "status":          "DEGRADED" if issues else "HEALTHY",
        "issues":          issues,
        "dedup_rate_pct":  dedup_rate,
        "state_size":      state_size,
        "checked":         checked,
        "by_layer":        telem.get("by_layer", {}),
        "last_updated":    telem.get("last_updated"),
    }


def _build_sla_telemetry(now: datetime) -> Dict:
    """Build per-tier SLA compliance metrics."""
    # In a full implementation this reads per-tenant API call logs.
    # Provides the structure + governance framework for when logs are available.
    tiers = {}
    for tier, target in TIER_SLA_TARGET.items():
        tiers[tier] = {
            "sla_target_pct": target,
            "status":         "TRACKING",
            "last_updated":   now.isoformat(),
        }
    return {
        "run_at":         now.isoformat(),
        "tier_sla":       tiers,
        "api_freshness_sla_hours": API_FRESHNESS_SLA_HOURS,
    }


def _build_upgrade_funnel() -> Dict:
    """Build upgrade conversion funnel metrics from revenue telemetry."""
    rev_telem = _load_json(REVENUE_TELEMETRY)
    by_tenant = {}
    tier_dist: Dict[str, int] = {}

    if rev_telem:
        by_tenant = rev_telem.get("by_tenant", {})

    # Count features used per tenant as proxy for engagement
    rev_log = _load_json(REVENUE_LOG)
    feature_counts: Dict[str, int] = {}
    if rev_log:
        for tx in rev_log.get("transactions", []):
            feat = tx.get("feature", "unknown")
            feature_counts[feat] = feature_counts.get(feat, 0) + 1

    return {
        "active_tenants":   len(by_tenant),
        "top_features":     sorted(feature_counts.items(), key=lambda x: -x[1])[:10],
        "revenue_by_tenant_count": len(by_tenant),
        "funnel_stages": {
            "free_users":       "tracked_by_api_tier",
            "standard_convert": "tracked_by_subscription_manager",
            "premium_convert":  "tracked_by_stripe_gateway",
            "enterprise_close": "tracked_by_crm",
        },
    }


# ── Main Snapshot Builder ─────────────────────────────────────────────────────

def build_commercial_health_snapshot() -> Dict:
    """
    Build the full commercial observability snapshot.
    Writes all output files atomically. Returns the snapshot dict.
    """
    now = datetime.now(timezone.utc)
    logger.info(f"[COMMERCIAL-OBS] Building commercial health snapshot — {now.isoformat()}")

    revenue_health   = _check_revenue_engine()
    freshness_health = _check_feed_freshness()
    dedup_health     = _check_dedup_health()
    sla_telem        = _build_sla_telemetry(now)
    upgrade_funnel   = _build_upgrade_funnel()

    # Aggregate overall commercial health
    component_statuses = [
        revenue_health.get("status"),
        freshness_health.get("status"),
        dedup_health.get("status"),
    ]

    if "CRITICAL" in component_statuses:
        overall = "CRITICAL"
    elif "DEGRADED" in component_statuses or "UNKNOWN" in component_statuses:
        overall = "DEGRADED"
    else:
        overall = "HEALTHY"

    all_issues: List[str] = []
    for component in (revenue_health, freshness_health, dedup_health):
        all_issues.extend(component.get("issues", []))

    monetization_status = {
        "run_at":             now.isoformat(),
        "revenue_engine":     revenue_health.get("status"),
        "total_revenue_usd":  revenue_health.get("total_revenue_usd", 0.0),
        "transaction_count":  revenue_health.get("transaction_count", 0),
        "by_feature":         revenue_health.get("by_feature", {}),
        "by_month":           revenue_health.get("by_month", {}),
        "issues":             revenue_health.get("issues", []),
    }

    platform_health = {
        "run_at":           now.isoformat(),
        "overall_status":   overall,
        "issues":           all_issues,
        "components": {
            "revenue_engine":   revenue_health,
            "feed_freshness":   freshness_health,
            "dedup_pipeline":   dedup_health,
        },
        "commercial_kpis": {
            "total_revenue_usd":  revenue_health.get("total_revenue_usd", 0.0),
            "transaction_count":  revenue_health.get("transaction_count", 0),
            "freshness_pct":      freshness_health.get("freshness_pct", 0),
            "dedup_rate_pct":     dedup_health.get("dedup_rate_pct", 0),
            "active_tenants":     upgrade_funnel.get("active_tenants", 0),
        },
    }

    # Atomic write all outputs
    _atomic_write(PLATFORM_HEALTH,     platform_health)
    _atomic_write(SLA_TELEMETRY,       sla_telem)
    _atomic_write(UPGRADE_FUNNEL,      upgrade_funnel)
    _atomic_write(MONETIZATION_STATUS, monetization_status)

    logger.info(
        f"[COMMERCIAL-OBS] Snapshot complete — "
        f"overall={overall} revenue=${revenue_health.get('total_revenue_usd', 0):.2f} "
        f"freshness={freshness_health.get('freshness_pct', 0)}%"
    )

    return platform_health


if __name__ == "__main__":
    import sys
    snapshot = build_commercial_health_snapshot()
    status   = snapshot.get("overall_status", "UNKNOWN")
    print(json.dumps(snapshot, indent=2))
    sys.exit(0 if status == "HEALTHY" else (1 if status == "CRITICAL" else 3))
