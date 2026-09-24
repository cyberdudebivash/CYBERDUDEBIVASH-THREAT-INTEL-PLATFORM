#!/usr/bin/env python3
"""
scripts/public_freshness_contract.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- canonical customer-visible freshness contract.

ONE definition of "is the customer-facing intelligence fresh?", shared by:
  * scripts/r2_upload.py / scripts/r2_resync_manifests.py -- stale-manifest
    upload guard (PR #485): never overwrite R2 with a provably stale copy;
  * scripts/public_feed_freshness_gate.py -- external post-deploy release
    gate against the live public feed and /api/health;
  * workers/intel-gateway/src/freshness-contract.js -- /api/health (JS
    mirror; cannot import Python or, on this repo's bundler toolchain, JSON).

The threshold values live in config/public_freshness_contract.json and the
expected classification of each edge case in
config/public_freshness_contract_vectors.json. tests/test_public_freshness_
contract.py runs every vector through this module AND through the JS module,
and asserts the constants match, so the implementations cannot drift.

Environment overrides keep PR #485's existing operator knobs working:
MAX_PUBLIC_MANIFEST_AGE_HOURS (default from the contract file).
"""
from __future__ import annotations

import json
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = REPO_ROOT / "config" / "public_freshness_contract.json"

_CONTRACT = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS: float = float(_CONTRACT["max_public_manifest_age_hours"])
MAX_FUTURE_SKEW_HOURS: float = float(_CONTRACT["max_future_skew_hours"])
GENERATED_AT_RE = re.compile(_CONTRACT["generated_at_pattern"])

FRESH = "fresh"
STALE = "stale"
FUTURE = "future_timestamp"
MISSING = "missing_timestamp"
INVALID = "invalid_timestamp"


def max_public_manifest_age_hours() -> float:
    """Contract default, overridable by MAX_PUBLIC_MANIFEST_AGE_HOURS (the
    same env knob PR #485 introduced). Invalid or non-positive values fall
    back to the contract default."""
    raw = os.environ.get("MAX_PUBLIC_MANIFEST_AGE_HOURS", "").strip()
    if not raw:
        return DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS
    return value if value > 0 else DEFAULT_MAX_PUBLIC_MANIFEST_AGE_HOURS


def parse_generated_at(raw: Any) -> Optional[datetime]:
    """Strict ISO-8601 with explicit offset (the only form
    generate_api_manifests.py emits). Anything else is None -- the JS mirror
    applies the identical pattern, so both sides reject the same inputs."""
    if not isinstance(raw, str) or not GENERATED_AT_RE.match(raw):
        return None
    text = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
    # datetime.fromisoformat accepts at most 6 fractional digits.
    m = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(.*)$", text)
    if m and m.group(2) and len(m.group(2)) > 7:
        text = m.group(1) + m.group(2)[:7] + m.group(3)
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc)


def classify_manifest_freshness(raw: Any, now: Optional[datetime] = None,
                                max_age_hours: Optional[float] = None) -> dict:
    """Returns {"state", "age_seconds", "max_age_seconds"}.

    age_seconds is floor(real age), clamped to 0 inside the future-skew
    allowance, and None when no trustworthy age exists. Boundary: an age of
    exactly max_age is FRESH (inclusive, matching PR #485's `<=`); the
    comparison uses the exact elapsed time, not the floored integer."""
    limit_h = max_public_manifest_age_hours() if max_age_hours is None else float(max_age_hours)
    max_age_seconds = int(round(limit_h * 3600))
    if raw is None or (isinstance(raw, str) and raw.strip() == ""):
        return {"state": MISSING, "age_seconds": None, "max_age_seconds": max_age_seconds}
    dt = parse_generated_at(raw)
    if dt is None:
        return {"state": INVALID, "age_seconds": None, "max_age_seconds": max_age_seconds}
    now = now or datetime.now(timezone.utc)
    age = (now - dt).total_seconds()
    if age < -(MAX_FUTURE_SKEW_HOURS * 3600):
        return {"state": FUTURE, "age_seconds": None, "max_age_seconds": max_age_seconds}
    age_seconds = max(0, math.floor(age))
    state = FRESH if age <= limit_h * 3600 else STALE
    return {"state": state, "age_seconds": age_seconds, "max_age_seconds": max_age_seconds}
