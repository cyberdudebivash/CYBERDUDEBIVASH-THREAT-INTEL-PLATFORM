"""
core/ai — CYBERDUDEBIVASH® SENTINEL APEX v134.0.0
═══════════════════════════════════════════════════════════════════════════════
AI CYBER BRAIN — Full Module Registry

Exports all AI intelligence modules:
  - AICyberBrain       : Deterministic threat reasoning + kill chain simulation
  - AnomalyDetector    : Isolation Forest + statistical outlier detection
  - CampaignClusterer  : DBSCAN clustering — groups threats into campaigns
  - ThreatPredictor    : Gradient Boosting — forecasts emerging threats

Singletons (lazy-initialised, thread-safe):
  cyber_brain, anomaly_detector, campaign_clusterer, threat_predictor

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from .cyber_brain import AICyberBrain, cyber_brain
from .anomaly_detector import AnomalyDetector
from .campaign_clusterer import CampaignClusterer
from .threat_predictor import ThreatPredictor

import threading
import logging

logger = logging.getLogger("CDB-AI-INIT")

_lock = threading.Lock()
_anomaly_detector: AnomalyDetector | None = None
_campaign_clusterer: CampaignClusterer | None = None
_threat_predictor: ThreatPredictor | None = None


def get_anomaly_detector() -> AnomalyDetector:
    """Return the module-level AnomalyDetector singleton (created on first call)."""
    global _anomaly_detector
    if _anomaly_detector is None:
        with _lock:
            if _anomaly_detector is None:
                _anomaly_detector = AnomalyDetector()
                logger.info("AnomalyDetector singleton initialised.")
    return _anomaly_detector


def get_campaign_clusterer() -> CampaignClusterer:
    """Return the module-level CampaignClusterer singleton."""
    global _campaign_clusterer
    if _campaign_clusterer is None:
        with _lock:
            if _campaign_clusterer is None:
                _campaign_clusterer = CampaignClusterer()
                logger.info("CampaignClusterer singleton initialised.")
    return _campaign_clusterer


def get_threat_predictor() -> ThreatPredictor:
    """Return the module-level ThreatPredictor singleton (bootstrapped on init)."""
    global _threat_predictor
    if _threat_predictor is None:
        with _lock:
            if _threat_predictor is None:
                _threat_predictor = ThreatPredictor()
                logger.info("ThreatPredictor singleton initialised.")
    return _threat_predictor


# Convenience accessors (module-level aliases)
anomaly_detector: AnomalyDetector = None   # type: ignore[assignment]
campaign_clusterer: CampaignClusterer = None  # type: ignore[assignment]
threat_predictor: ThreatPredictor = None  # type: ignore[assignment]


def _lazy_init():
    """Called by pipeline on first use — initialises all singletons."""
    global anomaly_detector, campaign_clusterer, threat_predictor
    anomaly_detector    = get_anomaly_detector()
    campaign_clusterer  = get_campaign_clusterer()
    threat_predictor    = get_threat_predictor()


__all__ = [
    "AICyberBrain", "cyber_brain",
    "AnomalyDetector", "get_anomaly_detector",
    "CampaignClusterer", "get_campaign_clusterer",
    "ThreatPredictor", "get_threat_predictor",
    "anomaly_detector", "campaign_clusterer", "threat_predictor",
    "_lazy_init",
]
