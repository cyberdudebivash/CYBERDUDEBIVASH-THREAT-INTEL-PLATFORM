#!/usr/bin/env python3
"""P0 paid/public catalog: align the producer with the existing R2 TLP boundary.

The source producer's tlp_policy.partition_publishable() checks record-level
labels, while the final R2/Pages boundary recursively screens nested records
and reconciles conflicting labels across the authoritative sources. A paid
PRO manifest that the latter must modify is *not* a publishable paid artifact.

This module makes only pure in-memory decisions and bounded local source reads.
Every item that would require ANY last-mile redaction is withheld in full,
never partially stripped and passed as an approved customer report.
No trust policy, entitlement, scoring threshold, or storage binding changes.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from tlp_public_boundary import build_parent_index, sanitize_document
from tlp_policy import load_policy


def select_last_mile_verified(items: list[dict], root: Path) -> tuple[list[dict], dict[str, int]]:
    """Select only records that stay EXACTLY unchanged at the final boundary.

    Returns (selected, aggregate_reason_counts), never report IDs, IOC data,
    hidden TLP content or full source material. Raw source is never mutated.
    """
    if not isinstance(items, list) or any(not isinstance(v, dict) for v in items):
        raise ValueError("P0_MANIFEST_TLP_UNVERIFIABLE_INPUT")
    root = Path(root)
    policy = load_policy()
    parents = build_parent_index((
        root / "api/feed.json",
        root / "data/feed_manifest.json",
        root / "data/stix/feed_manifest.json",
    ), policy)
    allowed: list[dict] = []
    rejected: Counter = Counter()
    for item in items:
        # This is the exact function used by last-mile R2/Pages writers.
        # Parent-index decisions can only be more restrictive than own labels.
        out, removals, withheld = sanitize_document(item, policy, parents)
        if withheld is not None:
            rejected["DENIED_RECORD"] += 1
        elif removals or out != item:
            rejected["WOULD_REQUIRE_LAST_MILE_REDACTION"] += 1
        else:
            allowed.append(item)
    return allowed, dict(rejected)
