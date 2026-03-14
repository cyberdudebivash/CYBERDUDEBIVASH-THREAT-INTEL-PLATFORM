#!/usr/bin/env python3
"""
pipeline_hardener.py — CYBERDUDEBIVASH® SENTINEL APEX v48.0
Post-pipeline orchestrator that runs after sentinel_blogger.py completes.

FIXES:
  - BUG-02: Sorts manifest DESCENDING (newest first) for correct dashboard display
  - BUG-03: Triggers EPSS batch enrichment
  - BUG-04: Triggers KEV enrichment via v46 VANGUARD kev_enricher
  - BUG-06: Integrates v47 integrity checks

ARCHITECTURE:
  - Runs as a standalone post-pipeline step in GitHub Actions
  - Can also be called from sentinel_blogger.py main() as final step
  - Fully non-breaking: all operations are additive/corrective
  - Graceful degradation on any failure

Usage:
    python agent/v48_pipeline_hardening/pipeline_hardener.py

Or from GitHub Actions (add after sentinel_blogger stage):
    python -m agent.v48_pipeline_hardening.pipeline_hardener
"""

import json
import os
import re
import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-PIPELINE-HARDENER")

MANIFEST_PATH = "data/stix/feed_manifest.json"


def fix_manifest_sort_order(manifest_path: str = MANIFEST_PATH) -> bool:
    """
    BUG-02 FIX: Sort manifest DESCENDING by timestamp (newest first).
    
    The manifest was stored in ascending order (oldest first) because
    new entries are appended at the end. Dashboard reads entries
    sequentially, expecting newest first. The .reverse() in index.html
    partially fixes this, but the raw JSON API consumers, pre-flight
    diagnostics, and EMBEDDED_INTEL patching all assume [0] = newest.
    
    This fix sorts the manifest in-place after every pipeline run.
    """
    if not os.path.exists(manifest_path):
        return False

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except Exception:
        return False

    if not isinstance(manifest, list) or len(manifest) < 2:
        return False

    # Sort descending by timestamp (newest first)
    manifest.sort(
        key=lambda e: e.get("timestamp", "1970-01-01T00:00:00"),
        reverse=True
    )

    try:
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=4)
        logger.info(f"Manifest sorted: newest={manifest[0].get('timestamp','?')[:19]}")
        return True
    except Exception as e:
        logger.warning(f"Manifest sort write failed: {e}")
        return False


def enrich_kev_batch(manifest_path: str = MANIFEST_PATH) -> int:
    """
    BUG-04 FIX: Apply KEV enrichment to all CVE entries.
    Uses v46 VANGUARD kev_enricher if available.
    """
    try:
        from agent.v46_vanguard.kev_enricher import kev_enricher
    except ImportError:
        logger.debug("KEV enricher not available")
        return 0

    if not os.path.exists(manifest_path):
        return 0

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except Exception:
        return 0

    if not isinstance(manifest, list):
        return 0

    updated = 0
    for entry in manifest:
        # Skip entries already marked as KEV
        if entry.get("kev_present"):
            continue

        # Extract CVE from title
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", entry.get("title", ""), re.IGNORECASE)
        if not cve_match:
            continue

        cve_id = cve_match.group().upper()
        try:
            is_kev, kev_meta = kev_enricher.lookup(cve_id)
            if is_kev:
                entry["kev_present"] = True
                updated += 1
                logger.info(f"  KEV confirmed: {cve_id}")
        except Exception:
            continue

    if updated > 0:
        try:
            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=4)
        except Exception:
            pass

    return updated


def validate_manifest_integrity(manifest_path: str = MANIFEST_PATH) -> List[Dict]:
    """Check manifest for data inconsistencies."""
    findings = []

    if not os.path.exists(manifest_path):
        return findings

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except Exception:
        return findings

    if not isinstance(manifest, list):
        return findings

    seen_titles = {}
    for i, entry in enumerate(manifest):
        title = entry.get("title", "").strip().lower()
        risk = entry.get("risk_score", 0)
        sev = entry.get("severity", "")

        # Check for duplicates
        if title in seen_titles:
            findings.append({
                "type": "duplicate_title",
                "index": i,
                "title": entry.get("title", "")[:80],
                "duplicate_of": seen_titles[title],
            })
        seen_titles[title] = i

        # Check severity alignment
        expected = "CRITICAL" if risk >= 9 else "HIGH" if risk >= 7 else "MEDIUM" if risk >= 4 else "LOW"
        if sev and sev != expected:
            sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            try:
                if abs(sev_order.index(sev) - sev_order.index(expected)) > 1:
                    findings.append({
                        "type": "severity_mismatch",
                        "index": i,
                        "title": entry.get("title", "")[:80],
                        "risk_score": risk,
                        "severity": sev,
                        "expected": expected,
                    })
            except ValueError:
                pass

    return findings


def run_post_pipeline():
    """Main orchestrator — runs all v48 hardening passes."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CDB-v48] %(message)s"
    )

    logger.info("=" * 60)
    logger.info("PIPELINE HARDENER v48.0 — Post-Pipeline Orchestrator")
    logger.info("=" * 60)

    results = {
        "sort_fixed": False,
        "epss_enriched": 0,
        "kev_enriched": 0,
        "integrity_findings": 0,
        "run_at": datetime.now(timezone.utc).isoformat(),
    }

    # 1. Fix manifest sort order
    try:
        results["sort_fixed"] = fix_manifest_sort_order()
        logger.info(f"  Manifest sort: {'FIXED' if results['sort_fixed'] else 'SKIPPED'}")
    except Exception as e:
        logger.warning(f"  Manifest sort failed: {e}")

    # 2. EPSS batch enrichment
    try:
        from agent.v48_pipeline_hardening.epss_batch_enricher import EPSSBatchEnricher
        enricher = EPSSBatchEnricher()
        results["epss_enriched"] = enricher.enrich_manifest()
        logger.info(f"  EPSS/CVSS enriched: {results['epss_enriched']} fields")
    except ImportError:
        # Fallback: try v47 enricher
        try:
            from agent.v47_integrity.integrity_guard import EPSSBatchEnricher
            enricher = EPSSBatchEnricher()
            results["epss_enriched"] = enricher.enrich_manifest()
            logger.info(f"  EPSS/CVSS (v47 fallback): {results['epss_enriched']} fields")
        except Exception as e:
            logger.warning(f"  EPSS enrichment unavailable: {e}")
    except Exception as e:
        logger.warning(f"  EPSS enrichment failed: {e}")

    # 3. KEV batch enrichment
    try:
        results["kev_enriched"] = enrich_kev_batch()
        logger.info(f"  KEV enriched: {results['kev_enriched']} entries")
    except Exception as e:
        logger.warning(f"  KEV enrichment failed: {e}")

    # 4. Manifest integrity validation
    try:
        findings = validate_manifest_integrity()
        results["integrity_findings"] = len(findings)
        if findings:
            logger.warning(f"  Integrity: {len(findings)} issues found")
            for f in findings[:5]:
                logger.warning(f"    [{f['type']}] {f.get('title', '')[:60]}")
        else:
            logger.info("  Integrity: PASS")
    except Exception as e:
        logger.warning(f"  Integrity check failed: {e}")

    # 5. Re-sort after enrichment (enrichment may have modified entries)
    try:
        fix_manifest_sort_order()
    except Exception:
        pass

    # Write results
    try:
        out_path = "data/enrichment/v48_hardening_results.json"
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
    except Exception:
        pass

    logger.info("=" * 60)
    logger.info(f"PIPELINE HARDENER v48.0 — Complete | "
                f"EPSS:{results['epss_enriched']} KEV:{results['kev_enriched']} "
                f"Issues:{results['integrity_findings']}")
    logger.info("=" * 60)

    return results


if __name__ == "__main__":
    run_post_pipeline()
