#!/usr/bin/env python3
"""
vanguard_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v46.0 VANGUARD
Pipeline Enhancement Orchestrator

Provides a single integration point for all v46 VANGUARD modules.
Called from sentinel_blogger.py process_entry() AFTER existing extraction
and BEFORE report generation, as a post-processing enhancement pass.

ARCHITECTURE:
  - Takes existing pipeline outputs (iocs, risk_score, etc.)
  - Applies IOC validation, KEV enrichment, confidence recalculation
  - Returns enhanced data dict — caller merges into existing flow
  - Fully non-breaking: if any sub-module fails, returns original data

Usage:
    from agent.v46_vanguard.vanguard_engine import vanguard_engine
    enhanced = vanguard_engine.enhance(
        iocs=extracted_iocs,
        cve_ids=cve_ids,
        mitre_data=mitre_data,
        actor_data=actor_data,
        ...
    )
    # enhanced["iocs"] → cleaned IOCs
    # enhanced["kev_present"] → True/False from live KEV lookup
    # enhanced["confidence"] → recalculated confidence score
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-VANGUARD")

# Lazy imports with graceful degradation
_ioc_validator = None
_kev_enricher = None
_confidence_engine = None

try:
    from agent.v46_vanguard.ioc_validator import ioc_validator as _ioc_validator
except ImportError:
    pass

try:
    from agent.v46_vanguard.kev_enricher import kev_enricher as _kev_enricher
except ImportError:
    pass

try:
    from agent.v46_vanguard.confidence_engine import confidence_engine as _confidence_engine
except ImportError:
    pass


class VanguardEngine:
    """
    v46.0 Pipeline Enhancement Orchestrator.
    """

    def enhance(
        self,
        iocs: Dict[str, List[str]],
        source_text: str = "",
        cve_ids: Optional[List[str]] = None,
        mitre_data: Optional[List[Dict]] = None,
        actor_data: Optional[Dict] = None,
        impact_metrics: Optional[Dict] = None,
        fetched_article: Optional[Dict] = None,
        source_content: str = "",
        epss_score: Optional[float] = None,
        cvss_score: Optional[float] = None,
        kev_present: bool = False,
    ) -> Dict:
        """
        Apply all v46 enhancements.
        Returns dict with enhanced values. Original values used as fallback.
        """
        result = {
            "iocs": iocs,
            "kev_present": kev_present,
            "kev_metadata": {},
            "confidence": None,  # None = use existing calculation
            "confidence_label": None,
            "confidence_dimensions": {},
            "fp_removed_count": 0,
            "enhancements_applied": [],
        }

        # ── 1. IOC Validation ──
        if _ioc_validator:
            try:
                cleaned_iocs = _ioc_validator.validate(iocs, source_text=source_text)
                # Count FPs removed
                orig_total = sum(len(v) for v in iocs.values())
                clean_total = sum(len(v) for v in cleaned_iocs.values())
                fp_removed = orig_total - clean_total

                result["iocs"] = cleaned_iocs
                result["fp_removed_count"] = fp_removed
                result["enhancements_applied"].append("ioc_validation")

                if fp_removed > 0:
                    logger.info(f"VANGUARD IOC Validator: removed {fp_removed} false positives")
            except Exception as e:
                logger.warning(f"VANGUARD IOC validation failed (non-critical): {e}")

        # ── 2. KEV Enrichment ──
        if _kev_enricher and cve_ids:
            try:
                for cve_id in cve_ids[:5]:  # Limit to first 5 CVEs
                    is_kev, kev_meta = _kev_enricher.lookup(cve_id)
                    if is_kev:
                        result["kev_present"] = True
                        result["kev_metadata"] = kev_meta
                        result["enhancements_applied"].append("kev_enrichment")
                        logger.info(f"VANGUARD KEV: {cve_id} CONFIRMED in CISA KEV catalog")
                        break  # One KEV hit is sufficient to flag
            except Exception as e:
                logger.warning(f"VANGUARD KEV enrichment failed (non-critical): {e}")

        # ── 3. Confidence Recalculation ──
        if _confidence_engine:
            try:
                conf_result = _confidence_engine.score(
                    iocs=result["iocs"],  # Use validated IOCs
                    mitre_data=mitre_data,
                    actor_data=actor_data,
                    impact_metrics=impact_metrics,
                    fetched_article=fetched_article,
                    source_content=source_content,
                    epss_score=epss_score,
                    cvss_score=cvss_score,
                    kev_present=result["kev_present"],
                )
                result["confidence"] = conf_result.score
                result["confidence_label"] = conf_result.label
                result["confidence_dimensions"] = conf_result.dimensions
                result["enhancements_applied"].append("confidence_v46")
            except Exception as e:
                logger.warning(f"VANGUARD confidence engine failed (non-critical): {e}")

        if result["enhancements_applied"]:
            logger.info(
                f"VANGUARD v46.0 enhancements applied: "
                f"{', '.join(result['enhancements_applied'])}"
            )

        return result


# ── Singleton ──
vanguard_engine = VanguardEngine()
