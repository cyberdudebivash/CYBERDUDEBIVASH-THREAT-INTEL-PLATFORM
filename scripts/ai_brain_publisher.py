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

# v201.0 (AI plane forensic audit, 2026-09-09) -- input freshness enforcement.
# This publisher previously checked only `is not None` on each upstream AI
# artifact, so a producer that had not run in four months was indistinguishable
# from a healthy one and its output was republished under a freshly-stamped
# `generated_at`. scripts/ai_freshness_guard.py is the SSOT that decides
# artifact age; see its header for the full incident record.
#
# Imported defensively: if the guard module is ever unavailable, the publisher
# degrades to "cannot verify freshness" and marks the bundle degraded rather
# than crashing the pipeline or silently reverting to the old blind behaviour.
try:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from ai_freshness_guard import (  # noqa: E402
        assess as _assess_freshness,
        summarize as _summarize_freshness,
    )
    FRESHNESS_GUARD_AVAILABLE = True
    _FRESHNESS_IMPORT_ERROR = ""
except Exception as _fg_err:  # noqa: BLE001
    FRESHNESS_GUARD_AVAILABLE = False
    _FRESHNESS_IMPORT_ERROR = str(_fg_err)

REPO_ROOT     = pathlib.Path(__file__).resolve().parent.parent
FEED_PATH     = REPO_ROOT / "api" / "feed.json"
AI_PREDS_DIR  = REPO_ROOT / "data" / "ai_predictions"
AI_DIR        = REPO_ROOT / "data" / "ai"
INTEL_DIR     = REPO_ROOT / "data" / "intelligence"
API_OUT_DIR   = REPO_ROOT / "api" / "v1" / "intel"
OUTPUT_PATH   = API_OUT_DIR / "ai_summary.json"

VERSION = "201.0"

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


# v158.5 — CDB-UNATTR-* display name map (matches actor_matrix.py rename)
_UNATTR_DISPLAY = {
    "CDB-UNATTR-RAN": "Unattributed Ransomware Cluster",
    "CDB-UNATTR-PHI": "Unattributed Phishing Cluster",
    "CDB-UNATTR-RAT": "Unattributed RAT / Remote-Access Cluster",
    "CDB-UNATTR-APT": "Unattributed APT / Nation-State Cluster",
    "CDB-UNATTR-SUP": "Unattributed Supply-Chain Cluster",
    "CDB-UNATTR-CVE": "Unattributed CVE / Exploit Cluster",
    "CDB-UNATTR-MAL": "Unattributed Malware Cluster",
    "CDB-UNATTR-BOT": "Unattributed Botnet / DDoS Cluster",
    "CDB-UNATTR-CRY": "Unattributed Cryptojacking Cluster",
    "CDB-UNATTR-MOB": "Unattributed Mobile Threat Cluster",
}


def _actor_display_name(actor: str) -> str:
    """Return a human-readable display name for an actor tag.

    Handles CDB-UNATTR-* (v158.5 canonical labels), legacy CDB-*-GEN labels
    (backward compat), known threat groups, and raw actor strings.
    """
    # Exact match in canonical unattr map
    if actor in _UNATTR_DISPLAY:
        return _UNATTR_DISPLAY[actor]

    # Legacy CDB-*-GEN labels (pre-v158.5 backward compat — should not appear after rename)
    if actor.startswith("CDB-") and actor.endswith("-GEN"):
        category = actor[4:-4].title()
        return f"Unattributed {category} Cluster"

    # Generic CDB- prefix cleanup
    if actor.startswith("CDB-"):
        cleaned = actor[4:].replace("-", " ").title()
        return cleaned

    # UNATTRIBUTED / unknown
    if actor in ("UNATTRIBUTED", "UNKNOWN", "N/A"):
        return "Unattributed Threat Actor"

    # Pass-through: real named threat groups, APT designations, etc.
    return actor.replace("-", " ").replace("_", " ").title()


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
        # v201.1: was `or 5.0`. max_risk is a MAXIMUM, so imputing a mid-scale
        # 5.0 for an unscored advisory would publish "max_risk 5.0" for a
        # campaign whose advisories carry no risk score at all. An unscored
        # item contributes no risk evidence and is skipped below.
        risk = _opt_float(item.get("risk_score"), item.get("score"))

        if actor not in actor_map:
            actor_map[actor] = {
                "actor"        : actor,
                "display_name" : _actor_display_name(actor),
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

        if risk is not None and risk > rec["max_risk"]:
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


def build_anomalies(
    ai_preds: Optional[Dict],
    radar: Optional[Dict],
    preds_publishable: bool = True,
    radar_publishable: bool = True,
) -> List[Dict]:
    """
    Build anomaly list from the anomaly-detection pipeline outputs.
    Primary: data/ai_predictions/anomalies.json
    Supplementary: data/ai/anomaly_radar.json

    v201.0: each source is admitted only when its freshness verdict says it
    is publishable as current intelligence. An EXPIRED source is dropped
    entirely rather than republished -- a "ZERO-DAY CANDIDATE" derived from a
    four-month-old scoring run is not a zero-day candidate, and presenting it
    as one on a customer-facing endpoint is a correctness defect, not a
    cosmetic one. Callers that do not pass the flags keep the previous
    behaviour, so this is backward compatible for any other consumer.
    """
    anomalies: List[Dict] = []
    seen_ids: set = set()

    if not preds_publishable and ai_preds:
        log.warning("[FRESHNESS] anomalies.json excluded -- source not publishable as current")
        ai_preds = None
    if not radar_publishable and radar:
        log.warning("[FRESHNESS] anomaly_radar.json excluded -- source not publishable as current")
        radar = None

    # Primary source
    if ai_preds and isinstance(ai_preds.get("anomalies"), list):
        for a in ai_preds["anomalies"]:
            sid = a.get("stix_id") or a.get("id") or ""
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
            score = float(a.get("anomaly_score") or 0)
            pct = float(a.get("anomaly_pct") or score * 100 or 0)
            # v201.1: risk_score used to fall back to a literal 7.5 -- a
            # "HIGH-ish" number invented whenever the upstream record carried
            # no score, and then fed to _derive_soc_priority() so an entirely
            # made-up value drove the published SOC priority. An anomaly
            # without a risk score is published without one; consumers can
            # distinguish null from a real assessment, but not from a 7.5.
            risk_val = _opt_float(a.get("risk_score"), a.get("apex_ai_score"))
            anomalies.append({
                "stix_id"             : sid,
                "title"               : (a.get("title") or "Unknown Anomaly")[:100],
                "severity"            : (a.get("severity") or "UNKNOWN").upper(),
                "risk_score"          : risk_val,
                "anomaly_score"       : round(score, 4),
                "anomaly_pct"         : round(min(99, max(50, pct)), 1),
                "is_zero_day_candidate": bool(a.get("is_zero_day_candidate")),
                "sector"              : a.get("sector") or "Unknown",
                "soc_priority"        : a.get("soc_priority") or _derive_soc_priority(risk_val, bool(a.get("is_zero_day_candidate"))),
                "threat_type"         : a.get("threat_type") or "Unknown",
                "published_at"        : a.get("published_at") or "",
                "anomaly_features"    : a.get("anomaly_features") or {},
                "report_url"          : a.get("report_url") or "",
            })

    # Supplementary radar source
    #
    # v201.0 PRODUCER/CONSUMER CONTRACT FIX. scripts/anomaly_radar_engine.py
    # writes two arrays. `top10_anomalous` is the compact ranking and marks a
    # candidate with the key `is_candidate`; `zero_day_candidates` is the rich
    # record carrying severity, threat_type, kev_present and published_at for
    # exactly those candidates. This branch read only `top10_anomalous` and
    # looked for `is_zero_day_candidate` -- a key that array has never
    # contained -- so on the live 2026-09-09 data every radar-sourced anomaly
    # published as:
    #   severity "HIGH"            (actual: CRITICAL, KEV-confirmed)
    #   is_zero_day_candidate false (actual: true, 10 of 10)
    #   soc_priority "P2-HIGH"     (actual: P1-CRITICAL)
    # and the zero-day-first sort below plus the zero_day_candidates telemetry
    # counter were both permanently inert. The platform's flagship zero-day
    # radar signal never reached the published bundle.
    #
    # Fixed by indexing the rich array once and merging it in, and by accepting
    # either spelling of the candidate flag. Both reads are defensive: a radar
    # payload missing either array still produces exactly what it produced
    # before for the fields it does carry.
    if radar and isinstance(radar.get("top10_anomalous"), list):
        rich_by_id: Dict[str, Dict] = {}
        for c in (radar.get("zero_day_candidates") or []):
            if isinstance(c, dict):
                cid = c.get("stix_id") or c.get("id") or ""
                if cid:
                    rich_by_id[cid] = c

        for a in radar["top10_anomalous"]:
            sid = a.get("stix_id") or a.get("id") or ""
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
            rich = rich_by_id.get(sid, {})
            score = float(a.get("anomaly_score") or rich.get("anomaly_score") or 0)
            # v201.1: was `or 7.5`. See _opt_float — an unscored anomaly is
            # published unscored rather than assigned an invented HIGH-band value.
            risk = _opt_float(a.get("risk_score"), rich.get("risk_score"))
            # `is_candidate` is the radar engine's spelling; presence in the
            # zero_day_candidates array is itself authoritative evidence.
            is_zd = bool(
                a.get("is_zero_day_candidate")
                or a.get("is_candidate")
                or rich.get("is_zero_day_candidate")
                or bool(rich)
            )
            anomalies.append({
                "stix_id"             : sid,
                "title"               : (a.get("title") or rich.get("title") or "Anomalous Advisory")[:100],
                # v201.1: was `or "HIGH"` -- an unlabelled anomaly was published
                # as HIGH severity on no evidence. Matches the primary branch.
                "severity"            : (a.get("severity") or rich.get("severity") or "UNKNOWN").upper(),
                "risk_score"          : risk,
                "anomaly_score"       : round(score, 4),
                "anomaly_pct"         : round(min(99, max(50, score * 100)), 1),
                "is_zero_day_candidate": is_zd,
                "sector"              : "Unknown",
                "soc_priority"        : _derive_soc_priority(risk, is_zd),
                "threat_type"         : a.get("threat_type") or rich.get("threat_type") or "Unknown",
                "published_at"        : a.get("published_at") or rich.get("published_at") or "",
                "anomaly_features"    : {},
                "report_url"          : a.get("report_url") or rich.get("report_url") or "",
            })

    # Sort by anomaly_pct desc, zero-day candidates first
    anomalies.sort(key=lambda a: (-int(a["is_zero_day_candidate"]), -a["anomaly_pct"]))
    return anomalies[:MAX_ANOMALIES]


def _opt_float(*candidates: Any) -> Optional[float]:
    """First candidate parseable as a float, else None.

    v201.1: replaces the `float(x or <literal>)` idiom used throughout this
    module. `or` treats a genuine 0.0 as absent, and the literal fallback
    fabricated a plausible score whenever a field was missing. Returning None
    keeps "not assessed" distinguishable from "assessed as N" downstream.
    """
    for c in candidates:
        if c is None:
            continue
        try:
            return float(c)
        except (TypeError, ValueError):
            continue
    return None


def _derive_soc_priority(risk_score: Optional[float], is_zero_day: bool) -> str:
    """Map a risk score to a SOC priority band.

    v201.1: accepts None. A zero-day candidate is P1 on that evidence alone.
    Otherwise, with no risk score there is no basis for a band, and inventing
    one (previously P4-LOW via a fabricated default) would understate an
    unassessed item. "P?-UNSCORED" is explicit and sorts as unknown.
    """
    if is_zero_day:
        return "P1-CRITICAL"
    if risk_score is None:
        return "P?-UNSCORED"
    if risk_score >= 9.5:
        return "P1-CRITICAL"
    if risk_score >= 8.0:
        return "P2-HIGH"
    if risk_score >= 6.5:
        return "P3-MEDIUM"
    return "P4-LOW"


def build_forecasts(
    forecasts_data: Optional[Dict],
    publishable: bool = True,
) -> List[Dict]:
    """
    Build sector forecasts from the forecasting pipeline outputs.
    Input: data/ai_predictions/forecasts.json sectors dict.

    v201.0: a 30-day sector forecast whose source run is older than the
    forecast horizon itself describes a window that has already fully elapsed.
    Such a source is dropped rather than presented as a forward-looking
    prediction.
    """
    if not publishable and forecasts_data:
        log.warning("[FRESHNESS] forecasts.json excluded -- forecast window already elapsed")
        return []
    if not forecasts_data or not isinstance(forecasts_data.get("sectors"), dict):
        return []

    forecasts = []
    sv_map = {
        "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "MINIMAL": 0
    }

    declined_sectors: List[str] = []

    for sector_key, sec in forecasts_data["sectors"].items():
        if not isinstance(sec, dict):
            continue
        sector_name = sec.get("sector") or sector_key.replace("_", " ").title()

        # ------------------------------------------------------------------
        # v201.1 ANTI-FABRICATION GATE.
        #
        # This loop used to coerce every field with `or <default>`. Handed a
        # sector record that carries no forecast -- which is exactly what
        # ai_predictions_engine.py now emits for a sector it declined to
        # forecast -- those defaults manufactured a complete, plausible,
        # entirely invented forecast card:
        #
        #     current_risk 5.0 | peak_risk 5.0 | risk_level MEDIUM
        #     trend STABLE     | confidence 0.75 | prob 37
        #
        # rendered on the dashboard as a real sector prediction. A missing
        # value is not a 5.0. Skip any sector that is not an actual forecast.
        #
        # Backward compatible: forecast files written before `status` existed
        # have no such key, so presence of the required numeric fields is the
        # fallback test -- an older file with real forecasts still publishes,
        # while a record lacking the substance is skipped either way.
        # ------------------------------------------------------------------
        status = str(sec.get("status") or "").upper()
        if status and status != "FORECAST":
            declined_sectors.append(f"{sector_name}({status})")
            continue

        forecast_30d = sec.get("forecast_30d") or []
        if sec.get("current_risk") is None or sec.get("confidence") is None or not forecast_30d:
            declined_sectors.append(f"{sector_name}(INCOMPLETE)")
            continue

        try:
            current_risk = float(sec["current_risk"])
            confidence = float(sec["confidence"])
            peak_risk = float(sec.get("peak_risk") if sec.get("peak_risk") is not None else current_risk)
        except (TypeError, ValueError):
            declined_sectors.append(f"{sector_name}(UNPARSEABLE)")
            continue

        # risk_level / trend are labels the producer derives from the series it
        # actually computed; absent a series there is nothing to label, and the
        # guards above have already skipped that case.
        risk_level = (sec.get("risk_level") or "MEDIUM").upper()
        trend = (sec.get("trend") or "STABLE").upper()

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

    if declined_sectors:
        log.warning("[EVIDENCE] %d sector(s) carry no publishable forecast, skipped: %s",
                    len(declined_sectors), ", ".join(sorted(declined_sectors)))

    forecasts.sort(key=lambda f: (-sv_map.get(f["risk_level"], 0), -f["prob"]))
    return forecasts[:MAX_FORECASTS]


def build_apex_summary(
    apex_data: Optional[Dict],
    feed: List[Dict],
    apex_publishable: bool = True,
    active_engines: Optional[List[str]] = None,
) -> str:
    """Generate enterprise-grade AI executive summary (v158.5 — SOC/MSSP quality).

    Produces a structured, actionable threat summary consumable by:
    - SOC Tier 1/2/3 analysts (triage context)
    - MSSP threat briefings (client-facing intelligence)
    - Executive risk dashboards (board-level decision support)
    """
    import re as _re

    # Reuse the upstream executive summary only while its source run is still
    # publishable as current intelligence.
    #
    # v201.0 CORRECTNESS FIX: this branch used to rewrite the advisory-count
    # numerals inside a stored summary to today's feed count before returning
    # it. Applied to a stale artifact (apex_forecast_latest.json was found 158
    # days old during the 2026-09-09 audit) that rewrite made months-old
    # prose report today's numbers -- the text asserted a present-tense
    # assessment that no engine had actually made. The count refresh is kept
    # for a still-current summary, where it is a harmless consistency touch-up,
    # and the whole branch is skipped once the source is no longer publishable
    # so the derived live-feed summary below is used instead.
    if apex_publishable and apex_data and apex_data.get("ai_executive_summary"):
        base = apex_data["ai_executive_summary"]
        count = len(feed)
        base = _re.sub(r"analyzing \d+ recent", f"analyzing {count} recent", base)
        # Update advisory count numerals in the text
        base = _re.sub(r"\b\d+ intelligence advisories?\b", f"{count} intelligence advisories", base)
        return base
    if apex_data and apex_data.get("ai_executive_summary"):
        log.warning("[FRESHNESS] apex_forecast_latest.json summary excluded -- "
                    "deriving summary from the live feed instead")

    # --- Enterprise-grade derived summary from live feed stats ---
    count = len(feed)
    if count == 0:
        return "SENTINEL APEX: No advisories in current feed window. Pipeline active — awaiting next ingestion cycle."

    sev_dist: Counter = Counter(
        (i.get("severity") or "MEDIUM").upper() for i in feed
    )
    actor_dist: Counter = Counter(
        (i.get("actor_tag") or "UNKNOWN") for i in feed
    )
    sector_dist: Counter = Counter(
        (i.get("sector") or "").strip() for i in feed if i.get("sector")
    )
    kev_count = sum(1 for i in feed if i.get("kev_enriched") or i.get("in_cisa_kev"))
    ioc_count = sum(len(i.get("iocs") or []) for i in feed)
    critical = sev_dist.get("CRITICAL", 0)
    high = sev_dist.get("HIGH", 0)
    medium = sev_dist.get("MEDIUM", 0)

    # Top actor (exclude generic/unattributed for executive summary)
    named_actors = [
        (a, c) for a, c in actor_dist.most_common(5)
        if not a.startswith("CDB-UNATTR") and a not in ("UNATTRIBUTED", "UNKNOWN", "N/A", "")
    ]
    top_actor_str = named_actors[0][0] if named_actors else "no attributed threat group"
    top_actor_count = named_actors[0][1] if named_actors else 0

    top_sector = sector_dist.most_common(1)[0][0] if sector_dist else "cross-sector"

    # Threat posture assessment
    if critical >= 5 or kev_count >= 3:
        posture = "ELEVATED — immediate SOC triage recommended"
    elif critical >= 2 or high >= 10:
        posture = "HIGH — accelerated investigation warranted"
    elif high >= 5:
        posture = "MODERATE-HIGH — prioritized review advised"
    else:
        posture = "MODERATE — routine monitoring continues"

    parts = [
        f"SENTINEL APEX v{VERSION} — Executive Intelligence Summary.",
        f"Current threat window: {count} verified advisories ingested and enriched.",
        f"Severity profile: {critical} CRITICAL | {high} HIGH | {medium} MEDIUM.",
    ]
    if kev_count > 0:
        parts.append(f"CISA KEV confirmed: {kev_count} advisories map to actively exploited vulnerabilities — immediate patching priority.")
    if ioc_count > 0:
        parts.append(f"IOC corpus: {ioc_count} extracted indicators ready for SIEM/EDR ingestion.")
    if top_actor_count > 0:
        parts.append(f"Most active threat cluster: {top_actor_str} ({top_actor_count} advisories).")
    if top_sector:
        parts.append(f"Highest-impact target sector: {top_sector}.")
    # v201.0 TRUTHFULNESS FIX: this sentence used to be a hardcoded string
    # asserting "Isolation Forest anomaly detection, GradientBoosting 30-day
    # sector forecasts, DBSCAN actor clustering" on every single run. The
    # 2026-09-09 audit found no such estimators anywhere in the repository and
    # the artifacts they supposedly produced last changed on 2026-05-04, so
    # the claim was published unconditionally while the engines behind it were
    # not running at all. The engine list is now derived from which analytic
    # outputs this bundle actually contains.
    if active_engines:
        parts.append(f"Analytic engines contributing to this assessment: {', '.join(active_engines)}.")
    else:
        parts.append(
            "Predictive analytic engines are not contributing to this assessment — "
            "summary derived from live feed telemetry only."
        )
    parts.append(f"Threat posture: {posture}.")

    return " ".join(parts)


# -----------------------------------------------------------------------------
# v201.0 — Input freshness + evidence-derived engine attribution
# -----------------------------------------------------------------------------

#: The upstream artifacts this publisher consumes, and the engine each one
#: represents. `label` is the key used in the published `data_freshness` block.
_FRESHNESS_INPUTS = (
    ("anomalies",     AI_PREDS_DIR / "anomalies.json"),
    ("forecasts",     AI_PREDS_DIR / "forecasts.json"),
    ("apex_forecast", AI_PREDS_DIR / "apex_forecast_latest.json"),
    ("anomaly_radar", AI_DIR / "anomaly_radar.json"),
)


def _assess_inputs() -> Tuple[Dict[str, Any], Dict[str, bool]]:
    """Assess every upstream AI artifact's freshness.

    Returns:
        (freshness_block, publishable) where `freshness_block` is the JSON-safe
        observability payload embedded in ai_telemetry, and `publishable` maps
        each input label to whether it may be republished as current intel.

    If the freshness guard module is unavailable, every input is reported
    unverifiable and treated as NOT publishable. That is deliberate: the
    failure mode this whole change exists to remove is publishing unverified
    content as current, so an unavailable verifier must never re-enable it.
    """
    if not FRESHNESS_GUARD_AVAILABLE:
        log.error("[FRESHNESS] guard module unavailable (%s) — "
                  "treating all AI inputs as unverifiable", _FRESHNESS_IMPORT_ERROR)
        return (
            {
                "overall_state": "UNVERIFIABLE",
                "degraded": True,
                "guard_available": False,
                "error": _FRESHNESS_IMPORT_ERROR,
                "fresh_count": 0,
                "total_count": len(_FRESHNESS_INPUTS),
                "artifacts": {},
            },
            {label: False for label, _ in _FRESHNESS_INPUTS},
        )

    verdicts = [_assess_freshness(path, label=label) for label, path in _FRESHNESS_INPUTS]
    block = _summarize_freshness(verdicts)
    block["guard_available"] = True

    for v in verdicts:
        level = log.info if v.is_fresh else log.warning
        level("[FRESHNESS] %-14s %-10s %s", v.label, v.state, v.reason)

    if block["degraded"]:
        log.warning("[FRESHNESS] AI plane DEGRADED — overall=%s fresh=%d/%d expired=%s",
                    block["overall_state"], block["fresh_count"],
                    block["total_count"], block.get("expired") or [])

    return block, {v.label: v.is_publishable for v in verdicts}


def _derive_active_engines(
    campaigns: List[Dict],
    anomalies: List[Dict],
    forecasts: List[Dict],
) -> List[str]:
    """Name only the analytic engines that actually contributed to this bundle.

    An engine is listed when the output it produces is present and non-empty.
    Campaign clustering is computed in-process from the live feed by
    build_campaigns(), so it is evidenced by its own result rather than by an
    upstream artifact's freshness.
    """
    engines: List[str] = []
    if campaigns:
        engines.append("Actor-Campaign Clustering")
    if anomalies:
        engines.append("Anomaly Detection")
    if forecasts:
        engines.append("Sector Risk Forecasting")
    return engines


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

    # ------------------------------------------------------------------
    # v201.0 -- Assess upstream freshness BEFORE building anything from it.
    # ------------------------------------------------------------------
    freshness_block, publishable = _assess_inputs()

    # Build components
    log.info("[BUILD] Campaign clusters...")
    campaigns = build_campaigns(feed)
    log.info("[BUILD] %d campaigns clustered", len(campaigns))

    log.info("[BUILD] Anomaly list...")
    anomalies = build_anomalies(
        ai_preds, radar,
        preds_publishable=publishable["anomalies"],
        radar_publishable=publishable["anomaly_radar"],
    )
    log.info("[BUILD] %d anomalies compiled", len(anomalies))

    log.info("[BUILD] Sector forecasts...")
    forecasts = build_forecasts(forecasts_data, publishable=publishable["forecasts"])
    log.info("[BUILD] %d sector forecasts", len(forecasts))

    # Engine attribution is derived from what this bundle actually contains,
    # never asserted unconditionally.
    active_engines = _derive_active_engines(campaigns, anomalies, forecasts)

    apex_summary = build_apex_summary(
        apex_data, feed,
        apex_publishable=publishable["apex_forecast"],
        active_engines=active_engines,
    )

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
        # v201.0: was a hardcoded ["IsolationForest", "GradientBoostingRegressor",
        # "DBSCAN-Actor"] literal published on every run regardless of whether any
        # of those produced anything. Now derived from the bundle's actual content.
        "models_active"        : active_engines,
        "pipeline_version"     : VERSION,
        # PRESERVED UNCHANGED for backward compatibility: existing consumers read
        # these four booleans. They answer "was the file present and parseable",
        # which is what they have always answered. `data_freshness` below is the
        # additive block that answers the question these never could -- how old
        # the artifact is, and whether it is publishable as current intelligence.
        "data_sources"         : {
            "anomalies_json"  : ai_preds is not None,
            "forecasts_json"  : forecasts_data is not None,
            "apex_forecast"   : apex_data is not None,
            "anomaly_radar"   : radar is not None,
        },
        "data_freshness"       : freshness_block,
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
        # v201.0 additive top-level integrity fields. `generated_at` above is
        # this bundle's publish time and always has been; it says nothing about
        # how old the intelligence inside it is. These two say exactly that, at
        # the top level, so a dashboard can render an honest degraded state
        # without having to reach into ai_telemetry.
        "degraded"        : bool(freshness_block.get("degraded", True)),
        "freshness_state" : freshness_block.get("overall_state", "UNVERIFIABLE"),
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
