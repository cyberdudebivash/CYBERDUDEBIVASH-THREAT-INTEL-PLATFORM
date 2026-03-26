#!/usr/bin/env python3
"""
sentinel_blogger.py — CYBERDUDEBIVASH® SENTINEL APEX v77.1
Path: sentinel_blogger.py (ROOT — thin launcher)

PURPOSE: This file is the entry point called by the GitHub Actions workflow.
         It delegates ALL work to agent/sentinel_blogger.py (the real v21.0
         production pipeline with 15 feeds, premium report generation, STIX,
         deduplication, KEV/EPSS enrichment, etc.)

HISTORY OF FIXES:
  v69.1  Original root file — called fetch_all_feeds() from multi_source_intel.py
  v77.0  BUG: fetch_all_feeds does NOT exist in multi_source_intel.py
         → ImportError silently caught → 0 articles published every run
  v77.1  FIX: Delegate directly to agent/sentinel_blogger.main()
         This is the correct production pipeline.

DO NOT add feed-fetching or publishing logic here.
All production logic lives in agent/sentinel_blogger.py.
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
    v77.1 FIX: Delegate to the real production pipeline.
    agent/sentinel_blogger.py is the authoritative v21.0 engine:
      - Phase 1: Primary CDB RSS feed
      - Phase 2: 15 multi-source RSS feeds (THN, Krebs, CISA, Project Zero, etc.)
      - Triple-layer deduplication
      - Full source article fetching
      - 16-section premium report generation (2500+ words)
      - EPSS + CVSS + KEV enrichment
      - STIX 2.1 bundle creation
      - Manifest update
      - Blogger publish with rate-limit protection
    """
    logger.info("=" * 70)
    logger.info("SENTINEL APEX v77.1 — LAUNCHER ACTIVATED")
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
        logger.error(f"Pipeline error: {e}")
        raise


if __name__ == "__main__":
    main()
