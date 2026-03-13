"""
SENTINEL APEX v46.0 — ULTRA INTEL Module Registry
© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

ENGINE_REGISTRY = {
    "actor_attribution":      "agent.v46_ultraintel.actor_attribution",
    "sector_tagger":          "agent.v46_ultraintel.sector_tagger",
    "exploit_status":         "agent.v46_ultraintel.exploit_status_classifier",
    "cwe_classifier":         "agent.v46_ultraintel.cwe_classifier",
    "extended_metrics":       "agent.v46_ultraintel.extended_metrics_builder",
    "intel_quality_scorer":   "agent.v46_ultraintel.intel_quality_scorer",
    "manifest_enricher":      "agent.v46_ultraintel.manifest_enricher",
}

VERSION = "46.0.0"
CODENAME = "ULTRA INTEL"
ENGINE_COUNT = len(ENGINE_REGISTRY)
