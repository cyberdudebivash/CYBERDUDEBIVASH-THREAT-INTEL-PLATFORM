#!/usr/bin/env python3
"""
sentinel_blogger.py — CYBERDUDEBIVASH® SENTINEL APEX v77.2
Path: sentinel_blogger.py (ROOT — thin launcher)

PURPOSE:
    Entry point called by GitHub Actions workflow (sentinel-blogger.yml).
    Delegates ALL work to agent/sentinel_blogger.py — the real v21.0
    production pipeline.

    DO NOT add feed-fetching or publishing logic here.
    All production logic lives in agent/sentinel_blogger.py.

HISTORY:
    v69.1  Original — called fetch_all_feeds() from multi_source_intel.py
    v77.0  BUG: fetch_all_feeds does NOT exist in multi_source_intel.py
               → ImportError silently caught → 0 articles published every run
    v77.1  FIX: Delegate directly to agent/sentinel_blogger.main()
    v77.2  Updated to match v77.2 platform release:
               - Workflow: GOOGLE_OAUTH_DISABLE_FILE_CACHE, NVD_API_KEY,
                 Node.js 24 actions, PYTHONWARNINGS fix, reset --soft push
               - agent/sentinel_blogger.py: IOC telemetry fix (record_iocs)
               - agent/content/quality_gate.py: threshold 6.0→4.5,
                 vendor award instant-fail, bug bounty positive signal
               - agent/config.py: dead feeds replaced with active feeds
"""

import os
import sys
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-LAUNCHER] %(message)s"
)
logger = logging.getLogger("CDB-LAUNCHER")


def main():
    """
    Thin launcher — delegates to agent/sentinel_blogger.py.

    agent/sentinel_blogger.py is the authoritative v21.0 production engine:
      - Phase 1: Primary CDB RSS feed (1 entry)
      - Phase 2: Multi-source RSS fusion (15+ feeds)
      - Triple-layer deduplication (exact + URL + fuzzy similarity)
      - Full source article fetching (enrich thin RSS summaries)
      - 16-section premium report generation (2500+ words)
      - EPSS + CVSS + KEV enrichment (NVD + CISA + FIRST)
      - VANGUARD IOC validation + false-positive removal
      - STIX 2.1 bundle creation + manifest update
      - Resilient Blogger publish (rate-limit retry + pending queue)
      - Revenue CTA injection on every published post
      - IOC telemetry accumulation (v77.2 fix)
    """
    logger.info("=" * 70)
    logger.info("SENTINEL APEX v77.2 — LAUNCHER ACTIVATED")
    logger.info("Delegating to agent/sentinel_blogger.py (production pipeline)")
    logger.info("=" * 70)

    # Ensure agent/ is importable when running from repo root
    repo_root = os.path.dirname(os.path.abspath(__file__))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    try:
        from agent.sentinel_blogger import main as agent_main
        agent_main()
    except ImportError as e:
        logger.error(f"Failed to import agent/sentinel_blogger.py: {e}")
        logger.error("Ensure PYTHONPATH includes the repo root directory.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Pipeline error in agent/sentinel_blogger.py: {e}")
        raise


if __name__ == "__main__":
    main()
