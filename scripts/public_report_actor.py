#!/usr/bin/env python3
"""
Public dossier actor-label policy shared by the HTML renderer and the public
reports index builder.

The S1 public report intentionally hides actor identity and any unverified
category tags. This is a presentation policy, NOT independent attribution
corroboration. Never put the underlying raw actor_tag in the public index.
"""
from __future__ import annotations

from typing import Any, Mapping

from attribution_evidence_engine import BANNED_SYNTHETIC_NAMES, BANNED_SYNTHETIC_PREFIXES

PUBLIC_UNATTRIBUTED = "UNATTRIBUTED"
PUBLIC_ATTRIBUTION_GATED = "ATTRIBUTED — ENTERPRISE ACCESS REQUIRED"


def is_real_attribution(raw_tag: Any) -> bool:
    """Preserves renderer's pre-existing non-placeholder/paywall signal only.

    A true result is NOT evidence that an actual actor was independently
    attributed. It only requests the same public redaction as HTML S1.
    """
    if not isinstance(raw_tag, str) or not raw_tag.strip():
        return False
    normalized = " ".join(raw_tag.strip().casefold().split())
    if normalized in {
        "unattributed", "unknown", "unclassified", "none",
        "null", "n/a", "generic", "unc-unknown",
    }:
        return False
    if raw_tag.strip().upper().startswith(("CDB-UNATTR", *BANNED_SYNTHETIC_PREFIXES)):
        return False
    if any(name in normalized for name in BANNED_SYNTHETIC_NAMES):
        return False
    if normalized.startswith("apex-cluster-unattributed"):
        return False
    return True


def public_actor_label(item: Mapping[str, Any] | None) -> str:
    """Compute exactly the public S1 actor display without exporting raw data."""
    if not isinstance(item, dict):
        return PUBLIC_UNATTRIBUTED
    actor = item.get("actor_cluster") or item.get("actor_tag") or item.get("primary_actor")
    return PUBLIC_ATTRIBUTION_GATED if is_real_attribution(actor) else PUBLIC_UNATTRIBUTED
