"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Asset Delta Analyzer
=============================================================
Tracks attack surface drift by comparing scan results over time.
Identifies newly exposed assets, removed assets, and tech stack changes.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import glob
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-BH-DELTA")

_SCANS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "bughunter", "scans")


class AssetDeltaAnalyzer:
    """Compares sequential scans for a domain to detect attack surface changes."""

    def load_scan_history(self, domain: str, limit: int = 2) -> List[Dict]:
        """Load the most recent N scan files for a domain."""
        pattern = os.path.join(_SCANS_DIR, f"*_{domain.replace('.', '_')}.json")
        files = sorted(glob.glob(pattern), reverse=True)[:limit]

        scans = []
        for f in files:
            try:
                with open(f, "r") as fp:
                    scans.append(json.load(fp))
            except Exception as e:
                logger.error(f"[DELTA] Failed to load {f}: {e}")
        return scans

    def analyze_drift(self, domain: str) -> Dict:
        """
        Compare latest scan against previous baseline.
        Returns: added, removed, and modified assets.
        """
        history = self.load_scan_history(domain, limit=2)

        if len(history) < 2:
            return {
                "domain": domain,
                "status": "baseline_established",
                "added": [], "removed": [], "modified": [],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        current = history[0]
        previous = history[1]

        current_hosts = {a["hostname"]: a for a in current.get("assets", [])}
        previous_hosts = {a["hostname"]: a for a in previous.get("assets", [])}

        current_set = set(current_hosts.keys())
        previous_set = set(previous_hosts.keys())

        # New assets (high-priority for bug hunters)
        added = [current_hosts[h] for h in (current_set - previous_set)]

        # Removed assets
        removed = [previous_hosts[h] for h in (previous_set - current_set)]

        # Modified assets (tech stack changes)
        modified = []
        for h in (current_set & previous_set):
            curr_tech = set(current_hosts[h].get("technologies", []))
            prev_tech = set(previous_hosts[h].get("technologies", []))
            if curr_tech != prev_tech:
                modified.append({
                    "hostname": h,
                    "old_tech": sorted(prev_tech),
                    "new_tech": sorted(curr_tech),
                })

        logger.info(
            f"[DELTA] {domain}: +{len(added)} | -{len(removed)} | Δ{len(modified)}"
        )

        return {
            "domain": domain,
            "status": "delta_computed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_current": current.get("scan_id"),
            "scan_previous": previous.get("scan_id"),
            "added": added,
            "removed": removed,
            "modified": modified,
            "summary": {
                "new_assets": len(added),
                "removed_assets": len(removed),
                "tech_changes": len(modified),
            },
        }
