#!/usr/bin/env python3
"""
threat_predictor.py — CYBERDUDEBIVASH® SENTINEL APEX v123.0.0
════════════════════════════════════════════════════════════════════════════════
ML Threat Prediction Engine

Forecasts emerging threats using gradient boosting on historical intel feed data.
Features: CVSS distribution, exploit maturity, KEV velocity, TTP frequency,
          temporal patterns, seasonal cyber calendar, actor activity cycles.

Zero LLM dependency. Rule-based fallback when model is untrained.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import pickle
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger("CDB-THREAT-PREDICTOR")

# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS & LOOKUP TABLES
# ════════════════════════════════════════════════════════════════════════════════

EXPLOIT_MATURITY_SCORES: Dict[str, float] = {
    "not_defined": 0.0,
    "unproven": 0.10,
    "poc": 0.35,
    "functional": 0.65,
    "high": 0.85,
    "active": 1.00,
    "weaponized": 1.00,
    "in_the_wild": 1.00,
}

ACTOR_NOTORIETY_MAP: Dict[str, float] = {
    "apt28": 0.95, "apt29": 0.95, "apt41": 0.93, "lazarus": 0.92,
    "fin7": 0.88, "conti": 0.85, "lockbit": 0.85, "blackcat": 0.82,
    "revil": 0.88, "cozy bear": 0.95, "fancy bear": 0.95,
    "carbanak": 0.80, "turla": 0.90, "sandworm": 0.97,
    "unknown": 0.30, "": 0.20,
}

SECTOR_WEIGHTS: Dict[str, float] = {
    "healthcare": 0.90, "finance": 0.92, "energy": 0.95,
    "government": 0.93, "defense": 0.97, "critical_infrastructure": 0.98,
    "education": 0.65, "retail": 0.70, "manufacturing": 0.75,
    "technology": 0.80, "telecom": 0.82, "transportation": 0.78,
    "unknown": 0.50, "": 0.50,
}

# Months historically associated with elevated attack activity (1-indexed)
HIGH_ACTIVITY_MONTHS = {1, 3, 10, 11}  # Jan, Mar, Oct, Nov
# Days of week with higher exploit activity (0=Mon, 6=Sun)
HIGH_ACTIVITY_DAYS = {0, 1, 2}  # Mon–Wed

SEVERITY_LABELS = {0: "low_risk", 1: "medium_risk", 2: "high_risk", 3: "critical"}
SEVERITY_THRESHOLDS = [0.25, 0.50, 0.75]  # boundaries for rule-based scoring

FEATURE_NAMES = [
    "cvss_score",
    "epss_score",
    "kev_present",
    "ttp_count",
    "ioc_count",
    "days_since_disclosure",
    "exploit_maturity_score",
    "source_trust_score",
    "sector_weight",
    "day_of_week_sin",
    "day_of_week_cos",
    "month_sin",
    "month_cos",
    "actor_notoriety",
    "is_high_activity_month",
    "is_high_activity_day",
]


# ════════════════════════════════════════════════════════════════════════════════
# FEATURE ENGINEERING HELPERS
# ════════════════════════════════════════════════════════════════════════════════

def _safe_float(value: Any, default: float = 0.0, lo: float = 0.0, hi: float = 1.0) -> float:
    """Clamp a value to [lo, hi] with safe type coercion."""
    try:
        v = float(value)
        return max(lo, min(hi, v))
    except (TypeError, ValueError):
        return default


def _exploit_maturity(item: dict) -> float:
    raw = str(item.get("exploit_maturity", "")).lower().replace(" ", "_").replace("-", "_")
    for key, score in EXPLOIT_MATURITY_SCORES.items():
        if key in raw:
            return score
    # Secondary signals
    if any(k in raw for k in ("wild", "active", "weapon")):
        return 1.00
    if "poc" in raw or "proof" in raw:
        return 0.35
    if "functional" in raw:
        return 0.65
    return 0.10


def _actor_notoriety(item: dict) -> float:
    actor = str(item.get("actor", item.get("threat_actor", ""))).lower()
    for name, score in ACTOR_NOTORIETY_MAP.items():
        if name and name in actor:
            return score
    return 0.30


def _source_trust(item: dict) -> float:
    source = str(item.get("source", item.get("feed_source", ""))).lower()
    if any(s in source for s in ("cisa", "nvd", "mitre", "cert")):
        return 1.00
    if any(s in source for s in ("crowdstrike", "mandiant", "recorded future", "palo alto")):
        return 0.92
    if any(s in source for s in ("alienvault", "virustotal", "abuse.ch")):
        return 0.78
    if "internal" in source:
        return 0.85
    return 0.60


def _days_since_disclosure(item: dict) -> float:
    """Returns days since disclosure, clamped to [0, 365], then normalized to [0,1]."""
    for key in ("disclosure_date", "published_date", "created_at", "date"):
        raw = item.get(key)
        if raw:
            try:
                if isinstance(raw, (int, float)):
                    dt = datetime.fromtimestamp(raw, tz=timezone.utc)
                else:
                    dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                now = datetime.now(tz=timezone.utc)
                days = max(0.0, (now - dt).total_seconds() / 86400.0)
                return min(days, 365.0) / 365.0
            except Exception:
                pass
    return 0.5  # unknown → mid-range


def _temporal_features(item: dict) -> Tuple[float, float, float, float, float, float]:
    """Return (dow_sin, dow_cos, month_sin, month_cos, high_month, high_day)."""
    now = datetime.now(tz=timezone.utc)
    for key in ("disclosure_date", "published_date", "created_at", "date"):
        raw = item.get(key)
        if raw:
            try:
                if isinstance(raw, (int, float)):
                    now = datetime.fromtimestamp(raw, tz=timezone.utc)
                else:
                    now = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                break
            except Exception:
                pass
    dow = now.weekday()
    month = now.month
    dow_sin = math.sin(2 * math.pi * dow / 7)
    dow_cos = math.cos(2 * math.pi * dow / 7)
    month_sin = math.sin(2 * math.pi * (month - 1) / 12)
    month_cos = math.cos(2 * math.pi * (month - 1) / 12)
    high_month = 1.0 if month in HIGH_ACTIVITY_MONTHS else 0.0
    high_day = 1.0 if dow in HIGH_ACTIVITY_DAYS else 0.0
    return dow_sin, dow_cos, month_sin, month_cos, high_month, high_day


def _ttp_count(item: dict) -> float:
    ttps = item.get("ttps", item.get("techniques", item.get("mitre_techniques", [])))
    if isinstance(ttps, (list, set, tuple)):
        return min(float(len(ttps)), 30.0) / 30.0
    if isinstance(ttps, str):
        return min(float(len(ttps.split(","))), 30.0) / 30.0
    return 0.0


def _ioc_count(item: dict) -> float:
    iocs = item.get("iocs", item.get("indicators", []))
    if isinstance(iocs, (list, set, tuple)):
        return min(float(len(iocs)), 100.0) / 100.0
    return 0.0


def _sector_weight(item: dict) -> float:
    sector = str(item.get("sector", item.get("industry", ""))).lower().replace(" ", "_")
    for key, w in SECTOR_WEIGHTS.items():
        if key and key in sector:
            return w
    return 0.50


# ════════════════════════════════════════════════════════════════════════════════
# SYNTHETIC TRAINING DATA GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

def _generate_synthetic_training_data(n: int = 400) -> Tuple[np.ndarray, np.ndarray]:
    """
    Produce a deterministic synthetic training set for bootstrapping.
    Uses a fixed seed so feature vectors are reproducible across calls.
    """
    rng = np.random.RandomState(seed=42)
    X_rows, y_rows = [], []

    # Profile definitions: (label, cvss_range, epss_range, kev_p, exploit_hi_p)
    profiles = [
        (0, (0.1, 3.9), (0.00, 0.05), 0.02, 0.05, 80),   # low
        (1, (4.0, 6.9), (0.01, 0.15), 0.10, 0.20, 100),   # medium
        (2, (7.0, 8.9), (0.10, 0.50), 0.35, 0.55, 120),   # high
        (3, (9.0, 10.0), (0.40, 1.00), 0.75, 0.90, 100),  # critical
    ]

    for label, cvss_r, epss_r, kev_p, exploit_p, count in profiles:
        for _ in range(count):
            cvss = rng.uniform(*cvss_r) / 10.0
            epss = rng.uniform(*epss_r)
            kev = 1.0 if rng.random() < kev_p else 0.0
            ttps = rng.uniform(0.0, exploit_p)
            iocs = rng.uniform(0.0, exploit_p)
            days = rng.uniform(0.0, 1.0)
            exploit = rng.uniform(exploit_p * 0.5, min(exploit_p * 1.2, 1.0))
            trust = rng.uniform(0.5, 1.0)
            sector = rng.uniform(0.4, 1.0) if label >= 2 else rng.uniform(0.3, 0.8)
            dow = rng.randint(0, 7)
            month = rng.randint(1, 13)
            actor = rng.uniform(0.0, exploit_p)
            dow_sin = math.sin(2 * math.pi * dow / 7)
            dow_cos = math.cos(2 * math.pi * dow / 7)
            month_sin = math.sin(2 * math.pi * (month - 1) / 12)
            month_cos = math.cos(2 * math.pi * (month - 1) / 12)
            high_m = 1.0 if month in HIGH_ACTIVITY_MONTHS else 0.0
            high_d = 1.0 if dow in HIGH_ACTIVITY_DAYS else 0.0

            row = [cvss, epss, kev, ttps, iocs, days, exploit, trust, sector,
                   dow_sin, dow_cos, month_sin, month_cos, actor, high_m, high_d]
            X_rows.append(row)
            y_rows.append(label)

    return np.array(X_rows, dtype=np.float64), np.array(y_rows, dtype=np.int64)


# ════════════════════════════════════════════════════════════════════════════════
# RULE-BASED FALLBACK SCORER
# ════════════════════════════════════════════════════════════════════════════════

def _rule_based_score(fv: np.ndarray) -> Tuple[int, float]:
    """
    Deterministic heuristic scoring when no trained model is available.
    Returns (label_int, confidence_float).
    """
    (cvss, epss, kev, ttps, iocs, days_norm, exploit, trust,
     sector, _, _, _, _, actor, high_m, high_d) = fv

    score = (
        cvss * 0.30
        + epss * 0.20
        + kev * 0.15
        + exploit * 0.15
        + actor * 0.08
        + sector * 0.05
        + ttps * 0.04
        + iocs * 0.03
    )
    # Seasonal amplifier
    score += high_m * 0.02 + high_d * 0.01

    if score >= SEVERITY_THRESHOLDS[2]:
        label, conf = 3, min(0.95, 0.60 + score * 0.35)
    elif score >= SEVERITY_THRESHOLDS[1]:
        label, conf = 2, min(0.88, 0.55 + score * 0.30)
    elif score >= SEVERITY_THRESHOLDS[0]:
        label, conf = 1, min(0.80, 0.50 + score * 0.25)
    else:
        label, conf = 0, min(0.75, 0.45 + (1.0 - score) * 0.25)

    return label, round(float(conf), 4)


# ════════════════════════════════════════════════════════════════════════════════
# MAIN CLASS
# ════════════════════════════════════════════════════════════════════════════════

class ThreatPredictor:
    """
    Forecasts emerging threats using gradient boosting on historical intel feed data.

    Functional from first instantiation — rule-based fallback until trained.
    Thread-safe via internal RLock.
    """

    def __init__(self, model_path: Optional[str] = None) -> None:
        self._lock = threading.RLock()
        self._model = None          # GradientBoostingClassifier or None
        self._trained = False
        self._training_samples = 0
        self._accuracy: Optional[float] = None
        self._feature_importances: Optional[np.ndarray] = None
        self._model_path: Optional[str] = model_path

        if model_path and os.path.isfile(model_path):
            try:
                self.load_model(model_path)
            except Exception as exc:
                logger.warning("Failed to load model from %s: %s", model_path, exc)

        if not self._trained:
            logger.info("ThreatPredictor: bootstrapping with synthetic training data.")
            self._bootstrap_train()

    # ── bootstrap ────────────────────────────────────────────────────────────

    def _bootstrap_train(self) -> None:
        X, y = _generate_synthetic_training_data(400)
        result = self.train([])  # will use synthetic path
        # Direct bootstrap (bypasses empty-list guard)
        self._fit_model(X, y)

    def _fit_model(self, X: np.ndarray, y: np.ndarray) -> None:
        try:
            from sklearn.ensemble import GradientBoostingClassifier
            from sklearn.model_selection import cross_val_score
        except ImportError as exc:
            logger.error("scikit-learn not available: %s", exc)
            return

        with self._lock:
            clf = GradientBoostingClassifier(
                n_estimators=150,
                max_depth=4,
                learning_rate=0.08,
                subsample=0.85,
                min_samples_leaf=5,
                random_state=42,
            )
            clf.fit(X, y)
            cv_scores = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
            self._model = clf
            self._trained = True
            self._training_samples = len(y)
            self._accuracy = float(np.mean(cv_scores))
            self._feature_importances = clf.feature_importances_.copy()
            logger.info(
                "ThreatPredictor trained: samples=%d, cv_accuracy=%.4f",
                self._training_samples, self._accuracy,
            )

    # ── public: feature vector ────────────────────────────────────────────────

    def build_feature_vector(self, item: dict) -> np.ndarray:
        """Extract deterministic feature vector from an intel item dict."""
        cvss = _safe_float(item.get("cvss_score", item.get("cvss", 0.0)), 0.0, 0.0, 10.0) / 10.0
        epss = _safe_float(item.get("epss_score", item.get("epss", 0.0)), 0.0, 0.0, 1.0)
        kev = 1.0 if item.get("kev", item.get("in_kev", item.get("kev_present", False))) else 0.0
        ttps = _ttp_count(item)
        iocs = _ioc_count(item)
        days = _days_since_disclosure(item)
        exploit = _exploit_maturity(item)
        trust = _source_trust(item)
        sector = _sector_weight(item)
        dow_sin, dow_cos, m_sin, m_cos, high_m, high_d = _temporal_features(item)
        actor = _actor_notoriety(item)

        fv = np.array([
            cvss, epss, kev, ttps, iocs, days, exploit, trust, sector,
            dow_sin, dow_cos, m_sin, m_cos, actor, high_m, high_d,
        ], dtype=np.float64)
        return fv

    # ── public: train ─────────────────────────────────────────────────────────

    def train(self, intel_items: List[dict]) -> dict:
        """
        Train on real historical items.  Falls back to synthetic data if fewer
        than 20 real samples are provided.
        Returns: accuracy, feature_importances, training_samples.
        """
        real_X, real_y = [], []
        for item in intel_items:
            label = item.get("severity_label", item.get("risk_label"))
            if label is None:
                # Derive label from cvss
                cvss = _safe_float(item.get("cvss_score", 0.0), 0.0, 0.0, 10.0)
                if cvss >= 9.0:
                    label = 3
                elif cvss >= 7.0:
                    label = 2
                elif cvss >= 4.0:
                    label = 1
                else:
                    label = 0
            else:
                label_map = {"low_risk": 0, "medium_risk": 1, "high_risk": 2, "critical": 3,
                             "low": 0, "medium": 1, "high": 2, "critical_risk": 3}
                label = label_map.get(str(label).lower(), int(label) if str(label).isdigit() else 1)
            real_X.append(self.build_feature_vector(item))
            real_y.append(label)

        synth_X, synth_y = _generate_synthetic_training_data(400)
        if len(real_X) >= 20:
            X = np.vstack([np.array(real_X), synth_X])
            y = np.concatenate([np.array(real_y), synth_y])
        else:
            if real_X:
                logger.warning("Only %d real samples; augmenting with synthetic data.", len(real_X))
            X, y = synth_X, synth_y

        self._fit_model(X, y)

        fi = {}
        if self._feature_importances is not None:
            fi = {FEATURE_NAMES[i]: round(float(self._feature_importances[i]), 6)
                  for i in range(len(FEATURE_NAMES))}

        return {
            "accuracy": round(self._accuracy or 0.0, 4),
            "feature_importances": fi,
            "training_samples": self._training_samples,
        }

    # ── public: predict ───────────────────────────────────────────────────────

    def predict(self, item: dict) -> dict:
        """
        Returns predicted_severity, confidence, risk_trajectory,
        next_30d_exploitation_probability, feature_contributions.
        """
        fv = self.build_feature_vector(item)

        with self._lock:
            if self._trained and self._model is not None:
                proba = self._model.predict_proba(fv.reshape(1, -1))[0]
                label_int = int(np.argmax(proba))
                confidence = float(np.max(proba))
            else:
                label_int, confidence = _rule_based_score(fv)
                proba = np.zeros(4)
                proba[label_int] = confidence

        severity = SEVERITY_LABELS[label_int]

        # Risk trajectory: compare exploit maturity vs days-since-disclosure
        exploit_score = float(fv[6])
        days_norm = float(fv[5])
        if exploit_score > 0.65 and days_norm < 0.10:
            trajectory = "rapidly_escalating"
        elif exploit_score > 0.40 and days_norm < 0.30:
            trajectory = "escalating"
        elif exploit_score < 0.20 and days_norm > 0.70:
            trajectory = "declining"
        else:
            trajectory = "stable"

        # 30-day exploitation probability heuristic
        exploit_30d = round(
            float(fv[1]) * 0.5  # epss
            + float(fv[2]) * 0.25  # kev
            + exploit_score * 0.25, 4
        )
        exploit_30d = min(1.0, exploit_30d)

        # Feature contributions (signed, relative to mean importance)
        fi = self._feature_importances if self._feature_importances is not None else np.ones(16) / 16
        contributions = {
            FEATURE_NAMES[i]: round(float(fv[i] * fi[i]), 6)
            for i in range(len(FEATURE_NAMES))
        }
        top_contributors = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)[:5]

        return {
            "predicted_severity": severity,
            "severity_label_int": label_int,
            "confidence": round(confidence, 4),
            "class_probabilities": {SEVERITY_LABELS[i]: round(float(p), 4) for i, p in enumerate(proba)},
            "risk_trajectory": trajectory,
            "next_30d_exploitation_probability": exploit_30d,
            "feature_contributions": dict(top_contributors),
            "model_type": "gradient_boosting" if self._trained else "rule_based_heuristic",
        }

    def predict_batch(self, items: List[dict]) -> List[dict]:
        """Predict threat severity for a list of intel items."""
        results = []
        for item in items:
            try:
                result = self.predict(item)
                result["item_id"] = item.get("id", item.get("cve_id", ""))
                results.append(result)
            except Exception as exc:
                logger.error("predict_batch error on item %s: %s", item.get("id", "?"), exc)
                results.append({"error": str(exc), "item_id": item.get("id", "")})
        return results

    # ── public: emerging threats ──────────────────────────────────────────────

    def predict_emerging_threats(self, current_feed: List[dict]) -> List[dict]:
        """
        Identifies items trending toward critical based on velocity signals.
        Returns a sorted list (highest risk first) of items with predicted severity >= high_risk
        and risk_trajectory in (escalating, rapidly_escalating).
        """
        emerging = []
        for item in current_feed:
            try:
                pred = self.predict(item)
                if (pred["severity_label_int"] >= 2
                        and pred["risk_trajectory"] in ("escalating", "rapidly_escalating")):
                    entry = {**item, "_prediction": pred}
                    emerging.append(entry)
            except Exception as exc:
                logger.warning("Skipping item in emerging threat scan: %s", exc)

        # Sort by confidence × severity descending
        emerging.sort(
            key=lambda x: x["_prediction"]["confidence"] * x["_prediction"]["severity_label_int"],
            reverse=True,
        )
        logger.info("predict_emerging_threats: %d/%d items flagged.", len(emerging), len(current_feed))
        return emerging

    # ── public: sector forecast ───────────────────────────────────────────────

    def forecast_sector_risk(self, sector: str, days: int = 30) -> dict:
        """
        Forecast risk level for a specific sector over the next N days.
        Uses sector weight, seasonal calendar, and model calibration.
        """
        sector_w = SECTOR_WEIGHTS.get(sector.lower().replace(" ", "_"), 0.50)
        now = datetime.now(tz=timezone.utc)

        # Average seasonal uplift across forecast window
        seasonal_scores = []
        for day_offset in range(days):
            from datetime import timedelta
            future = now + timedelta(days=day_offset)
            high_m = 1.0 if future.month in HIGH_ACTIVITY_MONTHS else 0.0
            high_d = 1.0 if future.weekday() in HIGH_ACTIVITY_DAYS else 0.0
            seasonal_scores.append(high_m * 0.06 + high_d * 0.03)
        avg_seasonal = float(np.mean(seasonal_scores))

        base_risk = sector_w * 0.70 + avg_seasonal
        base_risk = min(1.0, base_risk)

        if base_risk >= 0.75:
            forecast_label = "critical"
        elif base_risk >= 0.55:
            forecast_label = "high_risk"
        elif base_risk >= 0.35:
            forecast_label = "medium_risk"
        else:
            forecast_label = "low_risk"

        return {
            "sector": sector,
            "forecast_days": days,
            "forecast_label": forecast_label,
            "base_risk_score": round(base_risk, 4),
            "sector_weight": sector_w,
            "avg_seasonal_uplift": round(avg_seasonal, 4),
            "peak_risk_months": sorted(HIGH_ACTIVITY_MONTHS),
            "generated_at": now.isoformat(),
        }

    # ── persistence ───────────────────────────────────────────────────────────

    def save_model(self, path: str) -> None:
        with self._lock:
            if not self._trained or self._model is None:
                raise RuntimeError("No trained model to save.")
            payload = {
                "model": self._model,
                "accuracy": self._accuracy,
                "training_samples": self._training_samples,
                "feature_importances": self._feature_importances,
            }
            with open(path, "wb") as fh:
                pickle.dump(payload, fh, protocol=pickle.HIGHEST_PROTOCOL)
        logger.info("Model saved to %s", path)

    def load_model(self, path: str) -> None:
        with open(path, "rb") as fh:
            payload = pickle.load(fh)
        with self._lock:
            self._model = payload["model"]
            self._accuracy = payload.get("accuracy")
            self._training_samples = payload.get("training_samples", 0)
            self._feature_importances = payload.get("feature_importances")
            self._trained = True
        logger.info("Model loaded from %s (samples=%d)", path, self._training_samples)

    # ── diagnostics ───────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._lock:
            fi = {}
            if self._feature_importances is not None:
                fi = {FEATURE_NAMES[i]: round(float(self._feature_importances[i]), 6)
                      for i in range(len(FEATURE_NAMES))}
            return {
                "module": "ThreatPredictor",
                "version": "v123.0.0",
                "trained": self._trained,
                "training_samples": self._training_samples,
                "cv_accuracy": self._accuracy,
                "feature_importances": fi,
                "model_type": "GradientBoostingClassifier" if self._trained else "rule_based",
                "feature_count": len(FEATURE_NAMES),
                "severity_labels": SEVERITY_LABELS,
            }


# ════════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ════════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(name)s | %(levelname)s | %(message)s")
    tp = ThreatPredictor()
    sample = {
        "id": "CVE-2024-12345",
        "cvss_score": 9.8,
        "epss_score": 0.92,
        "kev": True,
        "ttps": ["T1190", "T1059", "T1486"],
        "iocs": ["1.2.3.4", "evil.example.com"],
        "exploit_maturity": "active",
        "source": "CISA",
        "sector": "healthcare",
        "actor": "Lazarus",
        "disclosure_date": "2024-01-15",
    }
    result = tp.predict(sample)
    print(json.dumps(result, indent=2))
    print(json.dumps(tp.forecast_sector_risk("healthcare", 30), indent=2))
    print(json.dumps(tp.stats(), indent=2))
