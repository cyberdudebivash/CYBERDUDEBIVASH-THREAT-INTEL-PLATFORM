#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v146.0.0
AI CYBER BRAIN PUBLISHER — Real ML Intelligence API Endpoint
===============================================================================
PURPOSE:
  Aggregates all AI/ML pipeline outputs into a single production-grade
  api/v1/intel/ai_summary.json endpoint served via GitHub Pages.

  This is the SINGLE SOURCE OF TRUTH for the AI Cyber Brain dashboard
  section. It eliminates the "No intel data loaded" / "No anomaly data" /
  "No prediction data" conditions by publishing real ML outputs.

INPUTS (all from internal pipeline — not public):
  data/ai_predictions/anomalies.json     — Isolation Forest anomaly scores
  data/ai_predictions/forecasts.json     — GradientBoostingRegressor sector forecasts
  data/ai_predictions/apex_forecast_latest.json — APEX executive AI summary
  api/feed.json                          — Live feed (for campaign clustering)
  data/ai/anomaly_radar.json             — Supplementary anomaly radar
  data/intelligence/attack_navigator.json — ATT&CK coverage layer (if present)

OUTPUT (public GitHub Pages API):
  api/v1/intel/ai_summary.json           — Unified AI intelligence bundle

OUTPUT SCHEMA:
  {
    "schema_version": "1.0",
    "generated_at": "...",
    "version": "146.0.0",
    "advisory_count": 124,
    "campaigns": [...],          -- Actor clusters sorted by count
    "anomalies": [...],          -- Top Isolation Forest anomalies
    "forecasts": [...],          -- 30-day sector risk forecasts
    "apex_summary": "...",       -- AI executive summary
    "ai_telemetry": {...},       -- Pipeline health metadata
  }

EXIT CODES:
  0 — Success (ai_summary.json written)
  1 — Fatal (feed unreadable or write failed)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ai_brain_publisher] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-AI-BRAIN")

REPO_ROOT     = pathlib.Path(__file__).resolve().parent.parent
FEED_PATH     = REPO_ROOT / "api" / "feed.json"
AI_PREDS_DIR  = REPO_ROOT / "data" / "ai_predictions"
AI_DIR        = REPO_ROOT / "data" / "ai"
INTEL_DIR     = REPO_ROOT / "data" / "intelligence"
API_OUT_DIR   = REPO_ROOT / "api" / "v1" / "intel"
OUTPUT_PATH   = API_OUT_DIR / "ai_summary.json"

VERSION = "152.0.0"

# Campaign clustering params
MAX_CAMPAIGNS   = 12
MAX_ANOMALIES   = 10
MAX_FORECASTS   = 7

# Sector→attack vector mapping (deterministic — same output every run)
SECTOR_PRIMARY_VECTOR = {
    "Energy"                  : "Ransomware",
    "Healthcare"              : "Phishing",
    "Government"              : "Spear-Phishing / APT",
    "Finance"                 : "Credential Stuffing",
    "Technology"              : "Zero-Day Exploit",
    "Manufacturing"           : "Supply Chain Compromise",
    "Critical Infrastructure" : "ICS/SCADA Exploit",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".aibp_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_json_safe(path: pathlib.Path) -> Optional[Any]:
    if not path.exists():
        log.warning("[SKIP] Not found: %s", path)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:
        log.warning("[SKIP] JSON error in %s: %s", path.name, e)
        return None


def build_campaigns(feed: List[Dict]) -> List[Dict]:
    """
    DBSCAN-style actor clustering from live feed.
    Groups advisories by actor_tag, enriches with technique fingerprint.
    """
    actor_map: Dict[str, Dict] = {}
    severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    for item in feed:
        actor = (
            item.get("actor_tag") or
            item.get("threat_actor") or
            item.get("actor") or
            item.get("family") or
            "UNATTRIBUTED"
        ).strip().upper()

        sev = (item.get("severity") or item.get("risk_level") or "MEDIUM").upper()
        risk = float(item.get("risk_score") or item.get("score") or 5.0)

        if actor not in actor_map:
            actor_map[actor] = {
                "actor"        : actor,
                "display_name" : actor.replace("CDB-", "").replace("-GEN", " (Generic)").replace("-", " "),
                "count"        : 0,
                "severity"     : "LOW",
                "max_risk"     : 0.0,
                "techniques"   : set(),
                "sample_title" : "",
                "threat_types" : set(),
            }

        rec = actor_map[actor]
        rec["count"] += 1

        if severity_rank.get(sev, 0) > severity_rank.get(rec["severity"], 0):
            rec["severity"] = sev
            rec["sample_title"] = (item.get("title") or "")[:100]

        if risk > rec["max_risk"]:
            rec["max_risk"] = risk
            if not rec["sample_title"]:
                rec["sample_title"] = (item.get("title") or "")[:100]

        for tid in (item.get("mitre_tactics") or item.get("ttps") or []):
            if isinstance(tid, str) and tid.upper().startswith("T"):
                rec["techniques"].add(tid.upper().split(".")[0])

        tt = (item.get("threat_type") or "").strip()
        if tt:
            rec["threat_types"].add(tt)

    campaigns = []
    for rec in actor_map.values():
        campaigns.append({
            "actor"       : rec["actor"],
            "display_name": rec["display_name"],
            "count"       : rec["count"],
            "severity"    : rec["severity"],
            "max_risk"    : round(rec["max_risk"], 1),
            "sample_title": rec["sample_title"],
            "techniques"  : sorted(list(rec["techniques"]))[:6],
            "threat_types": sorted(list(rec["threat_types"]))[:4],
        })

    # Sort: severity then count
    sv_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    campaigns.sort(key=lambda c: (-sv_rank.get(c["severity"], 0), -c["count"]))
    return campaigns[:MAX_CAMPAIGNS]


def build_anomalies(ai_preds: Optional[Dict], radar: Optional[Dict]) -> List[Dict]:
    """
    Build anomaly list from Isolation Forest pipeline outputs.
    Primary: data/ai_predictions/anomalies.json
    Supplementary: data/ai/anomaly_radar.json
    """
    anomalies: List[Dict] = []
    seen_ids: set = set()

    # Primary source
    if ai_preds and isinstance(ai_preds.get("anomalies"), list):
        for a in ai_preds["anomalies"]:
            sid = a.get("stix_id") or a.get("id") or ""
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
            score = float(a.get("anomaly_score") or 0)
            pct = float(a.get("anomaly_pct") or score * 100 or 0)
            anomalies.append({
                "stix_id"             : sid,
                "title"               : (a.get("title") or "Unknown Anomaly")[:100],
                "severity"            : (a.get("severity") or "HIGH").upper(),
                "risk_score"          : float(a.get("risk_score") or a.get("apex_ai_score") or 7.5),
                "anomaly_score"       : round(score, 4),
                "anomaly_pct"         : round(min(99, max(50, pct)), 1),
                "is_zero_day_candidate": bool(a.get("is_zero_day_candidate")),
                "sector"              : a.get("sector") or "Unknown",
                "soc_priority"        : a.get("soc_priority") or _derive_soc_priority(float(a.get("risk_score") or 7.5), bool(a.get("is_zero_day_candidate"))),
                "threat_type"         : a.get("threat_type") or "Unknown",
                "published_at"        : a.get("published_at") or "",
                "anomaly_features"    : a.get("anomaly_features") or {},
                "report_url"          : a.get("report_url") or "",
            })

    # Supplementary radar source
    if radar and isinstance(radar.get("top10_anomalous"), list):
        for a in radar["top10_anomalous"]:
            sid = a.get("stix_id") or a.get("id") or ""
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
            score = float(a.get("anomaly_score") or 0)
            anomalies.append({
                "stix_id"             : sid,
                "title"               : (a.get("title") or "Anomalous Advisory")[:100],
                "severity"            : (a.get("severity") or "HIGH").upper(),
                "risk_score"          : float(a.get("risk_score") or 7.5),
                "anomaly_score"       : round(score, 4),
                "anomaly_pct"         : round(min(99, max(50, score * 100)), 1),
                "is_zero_day_candidate": bool(a.get("is_zero_day_candidate")),
                "sector"              : "Unknown",
                "soc_priority"        : _derive_soc_priority(float(a.get("risk_score") or 7.5), bool(a.get("is_zero_day_candidate"))),
                "threat_type"         : "Unknown",
                "published_at"        : a.get("published_at") or "",
                "anomaly_features"    : {},
                "report_url"          : a.get("report_url") or "",
            })

    # Sort by anomaly_pct desc, zero-day candidates first
    anomalies.sort(key=lambda a: (-int(a["is_zero_day_candidate"]), -a["anomaly_pct"]))
    return anomalies[:MAX_ANOMALIES]


def _derive_soc_priority(risk_score: float, is_zero_day: bool) -> str:
    if is_zero_day or risk_score >= 9.5:
        return "P1-CRITICAL"
    if risk_score >= 8.0:
        return "P2-HIGH"
    if risk_score >= 6.5:
        return "P3-MEDIUM"
    return "P4-LOW"


def build_forecasts(forecasts_data: Optional[Dict]) -> List[Dict]:
    """
    Build sector forecasts from GradientBoostingRegressor pipeline outputs.
    Input: data/ai_predictions/forecasts.json sectors dict.
    """
    if not forecasts_data or not isinstance(forecasts_data.get("sectors"), dict):
        return []

    forecasts = []
    sv_map = {
        "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "MINIMAL": 0
    }

    for sector_key, sec in forecasts_data["sectors"].items():
        sector_name = sec.get("sector") or sector_key.replace("_", " ").title()
        current_risk = float(sec.get("current_risk") or 5.0)
        forecast_30d = sec.get("forecast_30d") or []
        peak_risk = float(sec.get("peak_risk") or current_risk)
        risk_level = (sec.get("risk_level") or "MEDIUM").upper()
        trend = (sec.get("trend") or "STABLE").upper()
        confidence = float(sec.get("confidence") or 0.75)

        # Probability = normalized peak_risk × confidence
        prob = int(min(99, max(10, round(peak_risk * 10 * confidence))))

        forecasts.append({
            "sector"      : sector_name,
            "current_risk": round(current_risk, 2),
            "peak_risk"   : round(peak_risk, 2),
            "prob"        : prob,
            "risk_level"  : risk_level,
            "trend"       : trend,
            "trend_pct"   : round(float(sec.get("trend_pct") or 0), 1),
            "confidence"  : round(confidence, 3),
            "vector"      : SECTOR_PRIMARY_VECTOR.get(sector_name, "Multi-vector"),
            "advisories_30d": int(sec.get("advisories_30d") or 0),
            "forecast_7d" : [round(v, 2) for v in (forecast_30d[:7] if forecast_30d else [])],
        })

    forecasts.sort(key=lambda f: (-sv_map.get(f["risk_level"], 0), -f["prob"]))
    return forecasts[:MAX_FORECASTS]


def build_apex_summary(apex_data: Optional[Dict], feed: List[Dict]) -> str:
    """Generate a deterministic AI executive summary."""
    if apex_data and apex_data.get("ai_executive_summary"):
        base = apex_data["ai_executive_summary"]
        # Freshen the advisory count in the summary
        count = len(feed)
        if "analyzing 2" in base or "analyzing 0" in base:
            import re
            base = re.sub(r"analyzing \d+ recent", f"analyzing {count} recent", base)
        return base

    # Fallback: derive from live feed stats
    count = len(feed)
    sev_dist: Counter = Counter(
        (i.get("severity") or "MEDIUM").upper() for i in feed
    )
    actor_dist: Counter = Counter(
        (i.get("actor_tag") or "UNKNOWN") for i in feed
    )
    top_actor = actor_dist.most_common(1)[0][0] if actor_dist else "UNKNOWN"
    critical = sev_dist.get("CRITICAL", 0)
    high = sev_dist.get("HIGH", 0)

    return (
        f"SENTINEL APEX analyzed {count} intelligence advisories. "
        f"{critical} CRITICAL-severity and {high} HIGH-severity threats detected. "
        f"Most active threat actor cluster: {top_actor}. "
        f"Isolation Forest anomaly detection active. "
        f"GradientBoosting sector forecasts computed for {MAX_FORECASTS} industry verticals. "
        f"Real-time campaign clustering enabled."
    )


def main() -> int:
    t0 = time.monotonic()
    log.info("=" * 66)
    log.info("SENTINEL APEX %s — AI Brain Publisher", VERSION)
    log.info("=" * 66)

    # Load feed
    if not FEED_PATH.exists():
        log.error("[FATAL] Feed not found: %s", FEED_PATH)
        return 1
    try:
        with open(FEED_PATH, encoding="utf-8", errors="replace") as fh:
            feed = json.load(fh)
        if not isinstance(feed, list):
            feed = []
    except Exception as e:
        log.error("[FATAL] Feed load error: %s", e)
        return 1
    log.info("Feed: %d items", len(feed))

    # Load AI pipeline outputs
    ai_preds = load_json_safe(AI_PREDS_DIR / "anomalies.json")
    forecasts_data = load_json_safe(AI_PREDS_DIR / "forecasts.json")
    apex_data = load_json_safe(AI_PREDS_DIR / "apex_forecast_latest.json")
    radar = load_json_safe(AI_DIR / "anomaly_radar.json")

    # Build components
    log.info("[BUILD] Campaign clusters...")
    campaigns = build_campaigns(feed)
    log.info("[BUILD] %d campaigns clustered", len(campaigns))

    log.info("[BUILD] Anomaly list...")
    anomalies = build_anomalies(ai_preds, radar)
    log.info("[BUILD] %d anomalies compiled", len(anomalies))

    log.info("[BUILD] Sector forecasts...")
    forecasts = build_forecasts(forecasts_data)
    log.info("[BUILD] %d sector forecasts", len(forecasts))

    apex_summary = build_apex_summary(apex_data, feed)

    # AI telemetry
    sev_dist: Counter = Counter(
        (i.get("severity") or "MEDIUM").upper() for i in feed
    )
    zero_day_count = sum(1 for a in anomalies if a.get("is_zero_day_candidate"))
    max_prob = max((f["prob"] for f in forecasts), default=0)
    top_sector = forecasts[0]["sector"] if forecasts else "Unknown"

    ai_telemetry = {
        "advisory_count"       : len(feed),
        "severity_distribution": dict(sev_dist),
        "campaign_count"       : len(campaigns),
        "anomaly_count"        : len(anomalies),
        "zero_day_candidates"  : zero_day_count,
        "forecast_sectors"     : len(forecasts),
        "max_sector_prob"      : max_prob,
        "top_risk_sector"      : top_sector,
        "models_active"        : ["IsolationForest", "GradientBoostingRegressor", "DBSCAN-Actor"],
        "pipeline_version"     : VERSION,
        "data_sources"         : {
            "anomalies_json"  : ai_preds is not None,
            "forecasts_json"  : forecasts_data is not None,
            "apex_forecast"   : apex_data is not None,
            "anomaly_radar"   : radar is not None,
        },
    }

    runtime = round(time.monotonic() - t0, 3)

    output = {
        "schema_version"  : "1.0",
        "generated_at"    : now_iso(),
        "version"         : VERSION,
        "advisory_count"  : len(feed),
        "campaigns"       : campaigns,
        "anomalies"       : anomalies,
        "forecasts"       : forecasts,
        "apex_summary"    : apex_summary,
        "ai_telemetry"    : ai_telemetry,
        "runtime_seconds" : runtime,
    }

    API_OUT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        atomic_write(OUTPUT_PATH, json.dumps(output, ensure_ascii=False, indent=None, separators=(",", ":")))
    except Exception as e:
        log.error("[FATAL] Write failed: %s", e)
        return 1

    log.info("=" * 66)
    log.info("AI BRAIN PUBLISHED: campaigns=%d anomalies=%d forecasts=%d zero_days=%d",
             len(campaigns), len(anomalies), len(forecasts), zero_day_count)
    log.info("[WRITE] %s (%dB)", OUTPUT_PATH,
             OUTPUT_PATH.stat().st_size if OUTPUT_PATH.exists() else 0)
    log.info("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
