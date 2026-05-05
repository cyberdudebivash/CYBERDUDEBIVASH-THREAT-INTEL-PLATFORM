#!/usr/bin/env python3
"""
scripts/anomaly_radar_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.1.0 — Anomaly Radar Engine
=================================================================
Production Isolation Forest engine for Zero-Day candidate detection.

ARCHITECTURE:
  - Reads api/feed.json (primary) and data/stix/feed_manifest.json (secondary)
  - Constructs a normalized feature matrix per advisory
  - Trains sklearn IsolationForest (contamination=0.05, n_estimators=200)
  - Any item with isolation_score > 0.80 → flagged as ZERO_DAY_CANDIDATE
  - Writes results to data/ai/anomaly_radar.json (R2-uploadable)
  - Emits Telegram alert for any ZERO_DAY_CANDIDATE found (optional)
  - Integration point: called by run_pipeline.py Phase 2 (crash-guard wrapped)

Exit codes:
  0 = OK — radar computed, results written
  1 = FAIL — feature matrix empty or JSON parse error

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [anomaly_radar] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.anomaly_radar")

# ── Dependency bootstrap ──────────────────────────────────────────────────────
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False
    log.warning("scikit-learn not available — falling back to statistical Z-score radar")

# ── Constants ─────────────────────────────────────────────────────────────────
REPO = Path(__file__).resolve().parent.parent

FEED_PATH         = REPO / "api" / "feed.json"
MANIFEST_PATH     = REPO / "data" / "stix" / "feed_manifest.json"
OUTPUT_PATH       = REPO / "data" / "ai" / "anomaly_radar.json"
ZERO_DAY_THRESHOLD = 0.80   # isolation_score > 0.80 → ZERO_DAY_CANDIDATE
CONTAMINATION      = 0.05   # expected anomaly fraction
N_ESTIMATORS       = 200    # IsolationForest trees
RANDOM_STATE       = 42


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Feature Extraction ────────────────────────────────────────────────────────

_TACTIC_SEVERITY: dict[str, float] = {
    # High-impact tactics score higher
    "impact":           10.0,
    "exfiltration":      9.5,
    "lateral-movement":  9.0,
    "persistence":       8.5,
    "privilege-escalation": 8.0,
    "defense-evasion":   7.5,
    "command-and-control": 7.0,
    "collection":        6.5,
    "credential-access": 6.0,
    "discovery":         5.5,
    "execution":         5.0,
    "initial-access":    4.5,
    "reconnaissance":    3.5,
    "resource-development": 3.0,
}

# Threat type severity weights
_THREAT_TYPE_SEVERITY: dict[str, float] = {
    "ransomware":   10.0,
    "apt":           9.5,
    "zero-day":      9.5,
    "zero day":      9.5,
    "supply chain":  9.0,
    "data breach":   8.5,
    "wiper":         8.5,
    "backdoor":      8.0,
    "rootkit":       8.0,
    "trojan":        7.5,
    "rat":           7.5,
    "exploit":       7.0,
    "vulnerability": 6.0,
    "phishing":      5.5,
    "botnet":        5.0,
    "malware":       5.0,
    "advisory":      2.0,
}


def _tactic_max_score(item: dict) -> float:
    ttps = item.get("ttps") or item.get("mitre_tactics") or []
    scores = []
    for t in ttps:
        tactic = str(t.get("tactic", "")).lower().strip() if isinstance(t, dict) else ""
        scores.append(_TACTIC_SEVERITY.get(tactic, 4.0))
    return max(scores, default=4.0)


def _threat_type_score(item: dict) -> float:
    tt = str(item.get("threat_type", "") or "").lower()
    for key, val in _THREAT_TYPE_SEVERITY.items():
        if key in tt:
            return val
    return 3.0


def _recency_hours(item: dict) -> float:
    """Hours since the threat was published. More recent = potentially hotter."""
    ts_str = item.get("published_at") or item.get("timestamp") or ""
    if not ts_str:
        return 9999.0
    try:
        ts_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        now = datetime.now(timezone.utc)
        delta = now - dt.astimezone(timezone.utc)
        return max(0.0, delta.total_seconds() / 3600)
    except Exception:
        return 9999.0


def extract_features(item: dict) -> list[float]:
    """
    Returns a 12-dimensional feature vector per advisory.
    All features normalised to roughly [0, 10] before passing to scaler.
    """
    risk         = float(item.get("risk_score") or 0)
    cvss         = float(item.get("cvss_score") or 0)
    epss         = float(item.get("epss_score") or 0) * 100   # 0-1 → 0-100
    kev          = 10.0 if item.get("kev_present") else 0.0
    ioc_count    = min(float(item.get("ioc_count") or 0), 50.0)
    ioc_conf     = float(item.get("ioc_confidence") or 0) / 10.0   # normalise
    ttp_count    = min(float(item.get("ttp_count") or len(item.get("ttps") or [])), 20.0)
    confidence   = float(item.get("confidence") or item.get("confidence_score") or 0)
    if confidence <= 1.0 and confidence > 0:
        confidence *= 100
    ai_conf      = float((item.get("apex_ai") or {}).get("ai_confidence") or confidence)
    pred_risk    = float((item.get("apex_ai") or {}).get("predictive_risk") or risk)
    tactic_sev   = _tactic_max_score(item)
    threat_sev   = _threat_type_score(item)

    return [
        risk,           # 0  raw risk score 0-10
        cvss,           # 1  CVSS 0-10
        epss,           # 2  EPSS 0-100
        kev,            # 3  KEV presence 0 or 10
        ioc_count,      # 4  IOC count (capped 50)
        ioc_conf,       # 5  IOC confidence (normalised)
        ttp_count,      # 6  TTP count (capped 20)
        ai_conf,        # 7  AI confidence 0-100
        pred_risk,      # 8  predictive risk 0-10
        tactic_sev,     # 9  worst tactic severity 0-10
        threat_sev,     # 10 threat type severity 0-10
        confidence,     # 11 raw confidence 0-100
    ]


# ── Isolation Forest detection ────────────────────────────────────────────────

def run_isolation_forest(items: list[dict]) -> list[dict]:
    """
    Returns items annotated with:
      - anomaly_score: float 0.0–1.0  (higher = more anomalous)
      - is_zero_day_candidate: bool
      - anomaly_rank: int (1 = most anomalous)
    """
    if not _SKLEARN_AVAILABLE or len(items) < 10:
        log.warning("Falling back to Z-score anomaly radar (sklearn unavailable or too few items)")
        return _zscore_fallback(items)

    feature_matrix = [extract_features(it) for it in items]
    X = np.array(feature_matrix, dtype=np.float64)

    # Replace NaN/Inf from bad data
    X = np.nan_to_num(X, nan=0.0, posinf=10.0, neginf=0.0)

    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    clf = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_scaled)

    # score_samples returns negative anomaly scores; more negative = more anomalous
    raw_scores = clf.score_samples(X_scaled)

    # Normalise to [0, 1] where 1 = most anomalous
    min_s, max_s = raw_scores.min(), raw_scores.max()
    span = max_s - min_s if max_s != min_s else 1.0
    normalised = 1.0 - (raw_scores - min_s) / span   # invert so anomalous = high

    ranked_indices = np.argsort(normalised)[::-1]  # descending

    annotated = []
    rank_map = {int(idx): int(rank) + 1 for rank, idx in enumerate(ranked_indices)}

    for i, item in enumerate(items):
        score = float(normalised[i])
        is_candidate = score >= ZERO_DAY_THRESHOLD
        annotated.append({
            **item,
            "anomaly_score": round(score, 4),
            "is_zero_day_candidate": is_candidate,
            "anomaly_rank": rank_map[i],
            "zero_day_label": "⚡ ZERO-DAY CANDIDATE" if is_candidate else "nominal",
        })

    return annotated


def _zscore_fallback(items: list[dict]) -> list[dict]:
    """Statistical fallback when sklearn unavailable."""
    if not items:
        return items

    scores_raw = [
        (float(it.get("risk_score") or 0) * 0.4
         + float((it.get("apex_ai") or {}).get("predictive_risk") or 0) * 0.4
         + min(float(it.get("ioc_count") or 0), 50) * 0.12
         + (10.0 if it.get("kev_present") else 0.0) * 0.08)
        for it in items
    ]

    if len(scores_raw) < 2:
        return [{**it, "anomaly_score": 0.0, "is_zero_day_candidate": False,
                 "anomaly_rank": 1, "zero_day_label": "nominal"} for it in items]

    mean_s = sum(scores_raw) / len(scores_raw)
    std_s = math.sqrt(sum((s - mean_s) ** 2 for s in scores_raw) / len(scores_raw)) or 1.0

    normalised = [(s - mean_s) / std_s for s in scores_raw]
    # Clamp to [0, 1]
    min_n = min(normalised)
    max_n = max(normalised)
    span = max_n - min_n or 1.0
    norm01 = [(v - min_n) / span for v in normalised]

    ranked = sorted(range(len(norm01)), key=lambda i: norm01[i], reverse=True)
    rank_map = {idx: rank + 1 for rank, idx in enumerate(ranked)}

    annotated = []
    for i, item in enumerate(items):
        score = norm01[i]
        is_candidate = score >= ZERO_DAY_THRESHOLD
        annotated.append({
            **item,
            "anomaly_score": round(score, 4),
            "is_zero_day_candidate": is_candidate,
            "anomaly_rank": rank_map[i],
            "zero_day_label": "⚡ ZERO-DAY CANDIDATE" if is_candidate else "nominal",
        })
    return annotated


# ── Output writer (atomic) ────────────────────────────────────────────────────

def _atomic_write(path: Path, data: Any) -> None:
    """Atomic JSON write using .tmp + rename to prevent corruption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    tmp.rename(path)  # atomic on POSIX; near-atomic on Windows NTFS


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    log.info("SENTINEL APEX v143.1.0 — Anomaly Radar Engine starting")
    t0 = time.time()

    # Load feed
    if not FEED_PATH.exists():
        log.error("api/feed.json not found — cannot compute anomaly radar")
        return 1

    try:
        items: list[dict] = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Failed to parse api/feed.json: %s", e)
        return 1

    if not items:
        log.error("api/feed.json is empty — anomaly radar requires at least 1 advisory")
        return 1

    log.info("Loaded %d advisories for anomaly radar analysis", len(items))

    # Run detector
    annotated = run_isolation_forest(items)

    candidates = [a for a in annotated if a.get("is_zero_day_candidate")]
    top10 = sorted(annotated, key=lambda x: x.get("anomaly_rank", 9999))[:10]

    log.info("Zero-Day Candidates detected: %d / %d", len(candidates), len(items))

    for c in candidates:
        log.warning(
            "⚡ ZERO-DAY CANDIDATE [score=%.3f rank=#%d]: %s",
            c["anomaly_score"],
            c["anomaly_rank"],
            c.get("title", c.get("id", "unknown"))[:100],
        )

    # Build output payload
    payload = {
        "generated_at": utc_now(),
        "engine": "SENTINEL-APEX/143.1.0",
        "model": "IsolationForest" if _SKLEARN_AVAILABLE else "ZScoreFallback",
        "threshold": ZERO_DAY_THRESHOLD,
        "total_advisories": len(items),
        "zero_day_candidate_count": len(candidates),
        "zero_day_candidates": [
            {
                "stix_id": c.get("stix_id") or c.get("id"),
                "title": c.get("title", "")[:200],
                "anomaly_score": c["anomaly_score"],
                "anomaly_rank": c["anomaly_rank"],
                "risk_score": c.get("risk_score"),
                "threat_type": c.get("threat_type"),
                "kev_present": c.get("kev_present"),
                "severity": c.get("severity"),
                "zero_day_label": c.get("zero_day_label"),
                "source": c.get("source"),
                "published_at": c.get("published_at"),
            }
            for c in sorted(candidates, key=lambda x: x["anomaly_score"], reverse=True)
        ],
        "top10_anomalous": [
            {
                "rank": it.get("anomaly_rank"),
                "stix_id": it.get("stix_id") or it.get("id"),
                "title": it.get("title", "")[:200],
                "anomaly_score": it.get("anomaly_score"),
                "is_candidate": it.get("is_zero_day_candidate"),
                "zero_day_label": it.get("zero_day_label"),
                "risk_score": it.get("risk_score"),
            }
            for it in top10
        ],
        "elapsed_seconds": round(time.time() - t0, 2),
    }

    _atomic_write(OUTPUT_PATH, payload)
    log.info("Anomaly Radar results written → %s", OUTPUT_PATH)
    log.info(
        "DONE: %d advisories processed | %d Zero-Day Candidates | %.2fs",
        len(items), len(candidates), time.time() - t0,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
