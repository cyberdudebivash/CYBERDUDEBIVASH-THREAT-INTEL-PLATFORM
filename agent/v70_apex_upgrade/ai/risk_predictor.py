"""
SENTINEL APEX v70 — AI Risk Predictor
=======================================
Predicts risk level using a feature-engineered sklearn model.
Uses GradientBoosting for structured data risk prediction.
Features: CVSS, EPSS, IOC count, actor count, technique count,
          source trust, recency, exploit status, KEV status.
"""

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..core.models import Advisory

logger = logging.getLogger("sentinel.ai.risk_predictor")

_ML_AVAILABLE = False
try:
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    _ML_AVAILABLE = True
except ImportError:
    logger.warning("sklearn not available — using rule-based risk prediction")


# Training data: feature vectors + risk labels
# Features: [cvss_norm, epss, ioc_count_norm, actor_count_norm,
#            tech_count_norm, source_trust, recency, has_exploit, is_kev]
TRAINING_FEATURES = [
    # CRITICAL
    [1.0, 0.9, 0.8, 0.5, 0.7, 0.9, 1.0, 1, 1],
    [0.95, 0.8, 0.6, 0.3, 0.5, 0.95, 0.9, 1, 1],
    [0.9, 0.7, 1.0, 0.6, 0.8, 0.85, 1.0, 1, 0],
    [1.0, 0.95, 0.4, 0.0, 0.3, 0.9, 0.8, 1, 1],
    [0.85, 0.6, 0.9, 0.8, 0.9, 0.8, 0.95, 1, 1],
    # HIGH
    [0.8, 0.5, 0.5, 0.3, 0.4, 0.8, 0.8, 1, 0],
    [0.7, 0.6, 0.3, 0.2, 0.3, 0.9, 0.7, 0, 1],
    [0.75, 0.4, 0.7, 0.4, 0.6, 0.7, 0.9, 1, 0],
    [0.7, 0.3, 0.4, 0.1, 0.5, 0.85, 0.6, 0, 1],
    [0.65, 0.5, 0.6, 0.3, 0.4, 0.75, 0.85, 1, 0],
    # MEDIUM
    [0.5, 0.3, 0.3, 0.1, 0.2, 0.7, 0.5, 0, 0],
    [0.4, 0.2, 0.4, 0.0, 0.3, 0.6, 0.6, 0, 0],
    [0.55, 0.15, 0.2, 0.2, 0.1, 0.8, 0.4, 0, 0],
    [0.45, 0.1, 0.5, 0.1, 0.4, 0.5, 0.7, 1, 0],
    [0.5, 0.25, 0.1, 0.0, 0.2, 0.65, 0.3, 0, 0],
    # LOW
    [0.2, 0.05, 0.1, 0.0, 0.1, 0.5, 0.3, 0, 0],
    [0.1, 0.02, 0.0, 0.0, 0.0, 0.6, 0.2, 0, 0],
    [0.3, 0.08, 0.2, 0.0, 0.1, 0.4, 0.4, 0, 0],
    [0.15, 0.01, 0.1, 0.0, 0.0, 0.5, 0.1, 0, 0],
    [0.25, 0.03, 0.0, 0.0, 0.05, 0.3, 0.5, 0, 0],
]

TRAINING_LABELS = (
    ["CRITICAL"] * 5 + ["HIGH"] * 5 + ["MEDIUM"] * 5 + ["LOW"] * 5
)


class RiskPredictor:
    """
    ML-powered risk level predictor.
    Uses GradientBoosting with handcrafted features.
    """

    def __init__(self):
        self._model = None
        self._scaler = None
        self._is_trained = False

        if _ML_AVAILABLE:
            self._build_model()

    def _build_model(self) -> None:
        """Train the risk predictor on built-in data."""
        if not _ML_AVAILABLE:
            return

        try:
            X = np.array(TRAINING_FEATURES)
            y = np.array(TRAINING_LABELS)

            self._scaler = StandardScaler()
            X_scaled = self._scaler.fit_transform(X)

            self._model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.1,
                random_state=42,
            )
            self._model.fit(X_scaled, y)
            self._is_trained = True
            logger.info("Risk predictor trained on built-in dataset")
        except Exception as e:
            logger.error(f"Risk predictor training failed: {e}")

    def _extract_features(self, advisory: Advisory) -> List[float]:
        """Extract normalized feature vector from an advisory."""
        from ..engines.threat_scoring import get_source_trust

        # CVSS normalized (0-1)
        cvss_norm = 0.0
        # We don't have direct CVSS here, approximate from threat_score
        cvss_norm = min(advisory.threat_score / 100.0, 1.0)

        # EPSS — approximate from confidence if not available
        epss = advisory.confidence / 100.0 * 0.5  # Rough proxy

        # IOC count normalized
        ioc_count = len(advisory.iocs)
        ioc_norm = min(ioc_count / 10.0, 1.0)

        # Actor count
        actor_norm = min(len(advisory.actors) / 3.0, 1.0)

        # Technique count
        tech_norm = min(len(advisory.mitre_techniques) / 5.0, 1.0)

        # Source trust
        source_trust = get_source_trust(advisory.source_name)

        # Recency (0-1, newer = higher)
        recency = 0.5
        if advisory.published_date:
            try:
                dt = datetime.fromisoformat(advisory.published_date.replace("Z", "+00:00"))
                hours_old = max((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 0)
                recency = max(math.exp(-0.00963 * hours_old), 0.05)
            except (ValueError, TypeError):
                pass

        # Exploit availability (binary)
        has_exploit = 1 if any(
            kw in (advisory.title + " " + advisory.summary).lower()
            for kw in ["exploit", "poc", "proof of concept", "in the wild", "actively exploited"]
        ) else 0

        # KEV (binary) — check tags/title
        is_kev = 1 if any(
            kw in (advisory.title + " " + " ".join(advisory.tags)).lower()
            for kw in ["kev", "known exploited", "cisa kev"]
        ) else 0

        return [cvss_norm, epss, ioc_norm, actor_norm, tech_norm,
                source_trust, recency, has_exploit, is_kev]

    def predict(self, advisory: Advisory) -> Tuple[str, float]:
        """
        Predict risk level for an advisory.
        Returns (risk_level, confidence).
        """
        features = self._extract_features(advisory)

        if self._is_trained and self._model is not None and self._scaler is not None:
            try:
                X = np.array([features])
                X_scaled = self._scaler.transform(X)
                probs = self._model.predict_proba(X_scaled)[0]
                classes = self._model.classes_
                max_idx = int(np.argmax(probs))
                return classes[max_idx], float(probs[max_idx])
            except Exception as e:
                logger.debug(f"ML risk prediction failed: {e}")

        # Rule-based fallback
        return self._rule_predict(features)

    def _rule_predict(self, features: List[float]) -> Tuple[str, float]:
        """Rule-based risk prediction fallback."""
        score = sum(features[:7]) / 7.0  # Average of continuous features
        exploit_boost = features[7] * 0.15
        kev_boost = features[8] * 0.15
        total = score + exploit_boost + kev_boost

        if total >= 0.75:
            return "CRITICAL", 0.85
        elif total >= 0.55:
            return "HIGH", 0.75
        elif total >= 0.35:
            return "MEDIUM", 0.70
        else:
            return "LOW", 0.65

    def predict_batch(self, advisories: List[Advisory]) -> List[Advisory]:
        """Predict risk for all advisories in batch."""
        for adv in advisories:
            risk_level, conf = self.predict(adv)
            adv.risk_level = risk_level

        logger.info(f"Risk prediction complete: {len(advisories)} advisories")
        return advisories
