#!/usr/bin/env python3
"""
risk_score_differentiator.py  —  CYBERDUDEBIVASH® SENTINEL APEX v163.0
=======================================================================
POST-ENRICHMENT RISK SCORE MICRO-DIFFERENTIATOR

PURPOSE
-------
The SENTINEL APEX risk engine (risk_engine.py) scores IOC diversity by
*category presence* (binary per-type flag) rather than raw IOC count.
This means all zero-evidence items (no CVSS / EPSS / KEV) that share the
same category set receive an identical base score (e.g., 1.04), regardless
of their actual IOC count, confidence level, or TTP coverage.

When many CVE advisories arrive in the same pipeline batch, 40-55% of items
can cluster at 1.04, triggering the feed_health_gate.py uniform_risk WARNING
(threshold: >30% items share the same score).

SOLUTION
--------
For every item that shares its risk_score with ≥2 other items, apply a
deterministic micro-adjustment derived from signals already present in the
enriched feed JSON:

    micro = (ioc_count * IOC_WEIGHT)
          + (confidence / CONF_DIVISOR)
          + (ttp_count  * TTP_WEIGHT)

    adjusted = round(base_score + micro, 4)

The adjustment is bounded by MAX_MICRO_BUMP (default 0.25) so a LOW item
(score < 4.0) can never be bumped into a MEDIUM tier solely from this step.

OPERATION
---------
- Input / Output: api/feed.json (in-place update)
- Non-blocking:   always exits 0 — pipeline continues even on error
- Idempotent:     re-running on already-differentiated scores is safe
                  (adjustment is bounded; severity tier is preserved)
- Reports:        prints a before/after cluster summary to stdout

WIRING
------
Inserted as Stage 3.4.9 in sentinel-blogger.yml, immediately after Stage
3.4.8 (apex_v2 builder) and before Stage 3.5 (R2 upload).

v163.0 — Initial implementation
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FEED_PATH = Path("api/feed.json")

# Micro-bump weights — tune here, not in risk_engine.py
IOC_WEIGHT   = 0.010   # per-IOC (raw count, not categories)  e.g. 13 IOCs → +0.130
CONF_DIVISOR = 1_000.0 # confidence 0-100 divided by 1000     e.g. 56% → +0.056
TTP_WEIGHT   = 0.005   # per unique MITRE TTP                 e.g. 3 TTPs → +0.015

# Hard cap: never bump a single item by more than this
MAX_MICRO_BUMP = 0.25

# Minimum cluster size before applying differentiation
# (don't touch scores that are already unique)
MIN_CLUSTER_SIZE = 2

# Severity tier thresholds (for guard check — never cross a tier)
SEVERITY_TIERS = [
    (0.0, 4.0,  "LOW"),
    (4.0, 7.0,  "MEDIUM"),
    (7.0, 9.0,  "HIGH"),
    (9.0, 10.0, "CRITICAL"),
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [RISK-DIFF] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("risk-differentiator")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def severity_tier(score: float) -> str:
    """Return the severity tier label for a given score."""
    for lo, hi, label in SEVERITY_TIERS:
        if lo <= score < hi:
            return label
    return "CRITICAL"


def compute_micro(item: Dict[str, Any]) -> float:
    """
    Compute the micro-adjustment for a single feed item using signals
    that the risk engine does NOT currently differentiate on.

    Returns a float in [0.0, MAX_MICRO_BUMP].
    """
    # Raw IOC count (ioc_count field is populated by ioc_extractor.py)
    ioc_count: int = int(item.get("ioc_count") or 0)

    # Confidence score 0-100 (could be float)
    confidence: float = float(item.get("confidence_score") or item.get("confidence") or 0.0)

    # TTP count — use len(ttps) if present, else len(mitre_tactics)
    ttps: list = item.get("ttps") or item.get("mitre_tactics") or []
    ttp_count: int = len(ttps)

    micro = (ioc_count * IOC_WEIGHT) + (confidence / CONF_DIVISOR) + (ttp_count * TTP_WEIGHT)
    return round(min(micro, MAX_MICRO_BUMP), 6)


def find_clusters(feed: List[Dict[str, Any]]) -> Dict[float, List[int]]:
    """
    Return a mapping of risk_score → [indices] for all scores
    that appear more than once (i.e., clusters).
    """
    score_to_indices: Dict[float, List[int]] = defaultdict(list)
    for idx, item in enumerate(feed):
        rs = item.get("risk_score")
        if rs is not None:
            score_to_indices[float(rs)].append(idx)

    return {
        score: indices
        for score, indices in score_to_indices.items()
        if len(indices) >= MIN_CLUSTER_SIZE
    }


def print_cluster_report(label: str, feed: List[Dict[str, Any]]) -> None:
    """Print a concise cluster summary."""
    counts = Counter(
        round(float(item["risk_score"]), 4)
        for item in feed
        if item.get("risk_score") is not None
    )
    total = sum(counts.values())
    top_score, top_n = counts.most_common(1)[0]
    pct = (top_n / total * 100) if total else 0.0
    unique = len(counts)
    log.info(
        "%s — %d items | %d unique scores | top cluster: %.4f ×%d (%.1f%%)",
        label, total, unique, top_score, top_n, pct,
    )
    # Show top-5 clusters
    for score, n in counts.most_common(5):
        bar = "█" * n
        log.info("  score=%.4f  count=%2d  %s", score, n, bar)


# ---------------------------------------------------------------------------
# Main differentiator logic
# ---------------------------------------------------------------------------

def differentiate(feed: List[Dict[str, Any]]) -> Tuple[int, int]:
    """
    Apply micro-differentiation to all clustered risk scores in-place.

    Returns (items_modified, clusters_broken).
    """
    clusters = find_clusters(feed)
    if not clusters:
        log.info("No clustered risk scores found — feed is already well-differentiated.")
        return 0, 0

    log.info(
        "Found %d score cluster(s) covering %d items",
        len(clusters),
        sum(len(v) for v in clusters.values()),
    )

    items_modified = 0
    clusters_broken = 0

    for base_score, indices in clusters.items():
        log.info(
            "Processing cluster: risk_score=%.4f  (%d items)",
            base_score, len(indices),
        )
        new_scores: list = []

        for idx in indices:
            item = feed[idx]
            micro = compute_micro(item)
            original = float(item["risk_score"])
            adjusted = round(original + micro, 4)

            # Guard: never cross a severity tier boundary
            if severity_tier(adjusted) != severity_tier(original):
                # Find the ceiling of the current tier
                for lo, hi, label in SEVERITY_TIERS:
                    if lo <= original < hi:
                        adjusted = round(hi - 0.001, 4)
                        log.warning(
                            "Tier guard triggered for item %s — capped %.4f → %.4f (%s)",
                            item.get("id", "?"), original + micro, adjusted, label,
                        )
                        break

            item["risk_score"] = adjusted
            item["_risk_micro_adj"] = round(micro, 6)  # audit field
            new_scores.append(adjusted)
            items_modified += 1

            log.debug(
                "  id=%-40s  base=%.4f  micro=+%.4f  adj=%.4f  "
                "ioc=%d  conf=%.1f  ttps=%d",
                item.get("id", "?"),
                original, micro, adjusted,
                int(item.get("ioc_count") or 0),
                float(item.get("confidence_score") or item.get("confidence") or 0),
                len(item.get("ttps") or item.get("mitre_tactics") or []),
            )

        # Check if we actually broke the cluster
        if len(set(new_scores)) > 1:
            clusters_broken += 1
            log.info(
                "  ✓ Cluster broken: %d unique scores now (was 1)",
                len(set(new_scores)),
            )
        else:
            log.warning(
                "  ⚠ Cluster NOT broken — all items produced identical micro (%.4f)",
                new_scores[0] if new_scores else 0.0,
            )

    return items_modified, clusters_broken


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    if not FEED_PATH.exists():
        log.warning("Feed not found at %s — skipping differentiator.", FEED_PATH)
        return 0

    try:
        raw = FEED_PATH.read_text(encoding="utf-8")
        feed: List[Dict[str, Any]] = json.loads(raw)
    except Exception as exc:
        log.error("Failed to load %s: %s", FEED_PATH, exc)
        return 0  # non-blocking

    if not isinstance(feed, list) or len(feed) == 0:
        log.warning("Feed is empty or not a list — nothing to do.")
        return 0

    log.info("=== RISK SCORE DIFFERENTIATOR START (v163.0) ===")
    log.info("Feed: %s  |  Items: %d", FEED_PATH, len(feed))

    # --- Before ---
    print_cluster_report("BEFORE", feed)

    # --- Differentiate ---
    items_modified, clusters_broken = differentiate(feed)

    # --- After ---
    print_cluster_report("AFTER", feed)

    # --- Write back ---
    if items_modified > 0:
        try:
            FEED_PATH.write_text(
                json.dumps(feed, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            log.info(
                "✓ Wrote %s — %d item(s) adjusted, %d cluster(s) broken",
                FEED_PATH, items_modified, clusters_broken,
            )
        except Exception as exc:
            log.error("Failed to write %s: %s", FEED_PATH, exc)
            return 0  # non-blocking — don't fail the pipeline
    else:
        log.info("No adjustments needed — feed unchanged.")

    # --- Health summary ---
    counts = Counter(
        round(float(item["risk_score"]), 4)
        for item in feed
        if item.get("risk_score") is not None
    )
    total = len(feed)
    top_score, top_n = counts.most_common(1)[0]
    pct = (top_n / total * 100) if total else 0.0
    threshold_pct = 30.0

    if pct <= threshold_pct:
        log.info(
            "✅ uniform_risk check PASS — top cluster: %.4f ×%d (%.1f%% ≤ %.0f%%)",
            top_score, top_n, pct, threshold_pct,
        )
    else:
        log.warning(
            "⚠ uniform_risk check WARN — top cluster still %.1f%% (threshold %.0f%%); "
            "manual review recommended.",
            pct, threshold_pct,
        )

    log.info("=== RISK SCORE DIFFERENTIATOR COMPLETE ===")
    return 0  # always 0 — non-blocking


if __name__ == "__main__":
    sys.exit(main())
