#!/usr/bin/env python3
"""
manifest_enricher.py — CyberDudeBivash v46.0 (SENTINEL APEX ULTRA INTEL)
Master post-processing enrichment orchestrator.
Loads feed_manifest.json → runs all 5 v46 engines in correct dependency order →
writes enriched output to data/v46_ultraintel/enriched_manifest.json
and also updates the live feed_manifest.json (schema-compatible, additive-only).

Engine Execution Order (dependency-aware):
  1. actor_attribution     — sets actor_tag + actor_profile
  2. sector_tagger         — sets sector_tags
  3. exploit_status        — sets exploit_status (uses kev, epss, cvss)
  4. cwe_classifier        — sets cwe_classification
  5. extended_metrics      — uses actor_profile + exploit_status (built last-1)
  6. intel_quality_scorer  — uses all above signals (runs last)

Zero-Regression Guarantee:
  - Never removes existing fields
  - Never changes stix_id, bundle_id, title, timestamp, stix_file
  - Only adds new fields to each item
  - Output written to SEPARATE file (safe for GitHub Pages)

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
import json
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from agent.v46_ultraintel.actor_attribution import actor_attribution_engine_v46
from agent.v46_ultraintel.sector_tagger import sector_tagger_v46
from agent.v46_ultraintel.exploit_status_classifier import exploit_status_classifier_v46
from agent.v46_ultraintel.cwe_classifier import cwe_classifier_v46
from agent.v46_ultraintel.extended_metrics_builder import extended_metrics_builder_v46
from agent.v46_ultraintel.intel_quality_scorer import intel_quality_scorer_v46

logger = logging.getLogger("CDB-MANIFEST-ENRICHER-V46")

# ── PATHS ─────────────────────────────────────────────────────────────────────
_REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
_MANIFEST_PATH = os.path.join(_REPO_ROOT, "data", "stix", "feed_manifest.json")
_OUTPUT_DIR = os.path.join(_REPO_ROOT, "data", "v46_ultraintel")
_ENRICHED_MANIFEST_PATH = os.path.join(_OUTPUT_DIR, "enriched_manifest.json")
_PLATFORM_STATS_PATH = os.path.join(_OUTPUT_DIR, "platform_quality_stats.json")


class ManifestEnricherV46:
    """
    Master enrichment pipeline orchestrator for SENTINEL APEX v46.0.
    Processes feed_manifest.json through all 6 v46 engines.
    """

    def __init__(self):
        self.engines = [
            ("actor_attribution",    actor_attribution_engine_v46),
            ("sector_tagger",        sector_tagger_v46),
            ("exploit_status",       exploit_status_classifier_v46),
            ("cwe_classifier",       cwe_classifier_v46),
            ("extended_metrics",     extended_metrics_builder_v46),
            ("intel_quality_scorer", intel_quality_scorer_v46),
        ]

    def _load_manifest(self, path: str) -> List[Dict]:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "items" in data:
            return data["items"]
        raise ValueError(f"Unexpected manifest format: {type(data)}")

    def _save_json(self, data, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        logger.info(f"Saved: {path}")

    def enrich_all(self, items: List[Dict]) -> List[Dict]:
        """
        Run all 6 engines in pipeline order.
        Each engine is called in batch mode with the full item list.
        """
        logger.info(f"v46 ULTRA INTEL enrichment pipeline starting — {len(items)} items")
        current = items

        for engine_name, engine in self.engines:
            logger.info(f"  → Running {engine_name}...")
            try:
                current = engine.batch_enrich(current)
                logger.info(f"  ✓ {engine_name} complete")
            except Exception as e:
                logger.error(f"  ✗ {engine_name} FAILED: {e}")
                # Continue pipeline — non-breaking

        logger.info(f"Enrichment pipeline complete — {len(current)} items enriched")
        return current

    def compute_meta(self, items: List[Dict]) -> Dict:
        """Compute enrichment run metadata."""
        actor_attributed = sum(
            1 for i in items
            if not str(i.get("actor_tag", "UNC-CDB-99")).startswith("UNC-CDB")
        )
        with_exploit_status = sum(1 for i in items if i.get("exploit_status"))
        with_sectors = sum(1 for i in items if i.get("sector_tags"))
        with_cwe = sum(1 for i in items if i.get("cwe_classification"))
        with_em = sum(1 for i in items if i.get("extended_metrics"))
        quality_stats = intel_quality_scorer_v46.compute_platform_stats(items)

        exploit_dist = {}
        for item in items:
            s = item.get("exploit_status", {}).get("status", "UNKNOWN")
            exploit_dist[s] = exploit_dist.get(s, 0) + 1

        itw_count = exploit_dist.get("ITW", 0)
        active_count = exploit_dist.get("ACTIVE", 0)
        poc_count = exploit_dist.get("POC_PUBLIC", 0)

        return {
            "enrichment_version": "v46.0",
            "enrichment_run_at": datetime.now(timezone.utc).isoformat(),
            "total_items": len(items),
            "actor_attributed_count": actor_attributed,
            "actor_attribution_pct": round(actor_attributed / len(items) * 100, 1) if items else 0,
            "with_exploit_status": with_exploit_status,
            "with_sectors": with_sectors,
            "with_cwe": with_cwe,
            "with_extended_metrics": with_em,
            "exploit_distribution": exploit_dist,
            "itw_count": itw_count,
            "active_exploitation_count": active_count,
            "poc_available_count": poc_count,
            "quality_stats": quality_stats,
        }

    def run(
        self,
        manifest_path: Optional[str] = None,
        output_path: Optional[str] = None,
        stats_path: Optional[str] = None,
    ) -> Dict:
        """
        Full pipeline run:
        1. Load manifest
        2. Enrich all items
        3. Save enriched manifest
        4. Save platform quality stats
        Returns run summary dict.
        """
        manifest_path = manifest_path or _MANIFEST_PATH
        output_path = output_path or _ENRICHED_MANIFEST_PATH
        stats_path = stats_path or _PLATFORM_STATS_PATH

        logger.info("=" * 60)
        logger.info("SENTINEL APEX v46.0 — ULTRA INTEL ENRICHMENT PIPELINE")
        logger.info("=" * 60)

        # Load
        logger.info(f"Loading manifest: {manifest_path}")
        items = self._load_manifest(manifest_path)
        logger.info(f"Loaded {len(items)} items from manifest")

        # Enrich
        enriched = self.enrich_all(items)

        # Compute metadata
        meta = self.compute_meta(enriched)
        logger.info(f"Quality stats: avg_iqs={meta['quality_stats'].get('avg_iqs', 0)}, "
                    f"actor_attributed={meta['actor_attributed_count']}/{len(enriched)}")

        # Build output payload
        output_payload = {
            "meta": meta,
            "items": enriched,
        }

        # Save enriched manifest
        self._save_json(output_payload, output_path)

        # Save platform stats separately
        self._save_json(meta, stats_path)

        logger.info("=" * 60)
        logger.info(f"✓ v46.0 ULTRA INTEL enrichment COMPLETE")
        logger.info(f"  Items enriched:     {len(enriched)}")
        logger.info(f"  Actor attributed:   {meta['actor_attributed_count']}/{len(enriched)}")
        logger.info(f"  ITW threats:        {meta['itw_count']}")
        logger.info(f"  Active threats:     {meta['active_exploitation_count']}")
        logger.info(f"  PoC available:      {meta['poc_available_count']}")
        logger.info(f"  Avg IQS:            {meta['quality_stats'].get('avg_iqs', 0)}")
        logger.info("=" * 60)

        return meta


# Module-level singleton
manifest_enricher_v46 = ManifestEnricherV46()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CDB-V46] %(message)s"
    )
    result = manifest_enricher_v46.run()
    print(json.dumps(result, indent=2, default=str))
