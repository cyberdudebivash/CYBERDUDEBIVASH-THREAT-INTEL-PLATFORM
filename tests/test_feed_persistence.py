"""
tests/test_feed_persistence.py - SENTINEL APEX v149.1.0 Persistence Regression Tests
"""
from __future__ import annotations
import json
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List
from unittest.mock import patch

import pytest

# Use /tmp stub directly (bypass FUSE mount)
TMP_REPO = Path("/tmp/testrepo_persist")
sys.path.insert(0, str(TMP_REPO))

for key in list(sys.modules.keys()):
    if "v149_intelligence_hardening" in key:
        del sys.modules[key]

from scripts.v149_intelligence_hardening import (
    _item_age_days,
    apply_confidence_gate,
    write_archive_items,
    RETENTION_WINDOW_DAYS,
    ARCHIVE_BASE,
)


def _iso(days_ago: float = 0.0) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _item(title="Test", days_ago=0.0, confidence=0.0, stix_id="", include_date=True):
    item: Dict = {"title": title, "confidence_score": confidence}
    if stix_id:
        item["stix_id"] = stix_id
    if include_date:
        item["published"] = _iso(days_ago)
    return item


def _gate_enabled(items, threshold=30):
    fake_flags = {"APEX_REQUIRE_CONFIDENCE_GATE": True, "APEX_CONFIDENCE_GATE_MIN": threshold}
    with patch("scripts.v149_intelligence_hardening.REPO", new=TMP_REPO):
        cfg = TMP_REPO / "config"
        cfg.mkdir(parents=True, exist_ok=True)
        ff = cfg / "feature_flags.json"
        ff.write_text(json.dumps(fake_flags))
        stats: Dict = {}
        result = apply_confidence_gate(items, stats)
        ff.unlink(missing_ok=True)
    return result


# T-PERSIST-01
def test_fresh_items_never_removed():
    items = [
        _item("Fresh-A", days_ago=0.0, confidence=0.0),
        _item("Fresh-B", days_ago=7.0, confidence=0.0),
        _item("Fresh-C", days_ago=14.0, confidence=5.0),
        _item("Fresh-D", days_ago=14.9, confidence=0.0),
    ]
    prod, arch, quar = _gate_enabled(items)
    assert len(prod) == 4, f"All 4 fresh items must be in production; got {len(prod)}"
    assert len(arch) == 0
    assert len(quar) == 0


# T-PERSIST-02
def test_confidence_zero_today_retained():
    items = [_item("ZeroConf-Today", days_ago=0.0, confidence=0.0)]
    prod, arch, _ = _gate_enabled(items)
    assert len(prod) == 1
    assert len(arch) == 0


# T-PERSIST-03
def test_old_low_confidence_goes_to_archive():
    items = [
        _item("Old-A", days_ago=20.0, confidence=0.0, stix_id="stix--old-1"),
        _item("Old-B", days_ago=30.0, confidence=10.0, stix_id="stix--old-2"),
    ]
    prod, arch, quar = _gate_enabled(items)
    assert len(prod) == 0, f"Old low-conf must not be in production; got {len(prod)}"
    assert len(arch) == 2, f"Both old items must be archived; got {len(arch)}"
    assert len(quar) == 0
    for item in arch:
        assert "_archived_reason" in item
        assert "_archived_at" in item


# T-PERSIST-04
def test_old_high_confidence_stays_in_production():
    items = [
        _item("Old-Pass-A", days_ago=20.0, confidence=85.0),
        _item("Old-Pass-B", days_ago=16.0, confidence=31.0),
    ]
    prod, arch, _ = _gate_enabled(items)
    assert len(prod) == 2
    assert len(arch) == 0


# T-PERSIST-05
def test_unknown_age_items_are_protected():
    items = [
        _item("No-Date", confidence=0.0, include_date=False),
        {"title": "No Fields"},
    ]
    prod, arch, _ = _gate_enabled(items)
    assert len(prod) == 2, f"Unknown-age items must be protected; got {len(prod)}"
    assert len(arch) == 0


# T-PERSIST-06
def test_feed_count_never_below_protected_set():
    fresh = [_item(f"F{i}", days_ago=float(i), confidence=0.0) for i in range(10)]
    old_pass = [_item(f"OP{i}", days_ago=20.0+i, confidence=90.0) for i in range(5)]
    old_fail = [_item(f"OF{i}", days_ago=20.0+i, confidence=0.0) for i in range(5)]
    prod, arch, _ = _gate_enabled(fresh + old_pass + old_fail)
    assert len(prod) >= 15, f"Expected >=15 in production; got {len(prod)}"
    assert len(arch) == 5, f"Expected 5 archived; got {len(arch)}"


# T-PERSIST-07
def test_archive_items_written_to_correct_path():
    with tempfile.TemporaryDirectory() as tmpdir:
        ab = Path(tmpdir) / "archive"
        items = [
            {"stix_id": "s1", "title": "May Item", "published": "2026-05-01T10:00:00Z"},
            {"stix_id": "s2", "title": "Apr Item", "published": "2026-04-15T10:00:00Z"},
        ]
        with patch("scripts.v149_intelligence_hardening.ARCHIVE_BASE", new=ab):
            write_archive_items(items)
        assert (ab / "2026-05" / "archived_intel.json").exists()
        assert (ab / "2026-04" / "archived_intel.json").exists()
        may = json.loads((ab / "2026-05" / "archived_intel.json").read_text())
        assert len(may) == 1 and may[0]["stix_id"] == "s1"


# T-PERSIST-08
def test_archive_is_append_only():
    with tempfile.TemporaryDirectory() as tmpdir:
        ab = Path(tmpdir) / "archive"
        first = [
            {"stix_id": "f1", "title": "First", "published": "2026-05-10T10:00:00Z"},
            {"stix_id": "f2", "title": "Second", "published": "2026-05-10T12:00:00Z"},
        ]
        second = [
            {"stix_id": "f1", "title": "First", "published": "2026-05-10T10:00:00Z"},  # dup
            {"stix_id": "f3", "title": "Third", "published": "2026-05-10T14:00:00Z"},  # new
        ]
        with patch("scripts.v149_intelligence_hardening.ARCHIVE_BASE", new=ab):
            write_archive_items(first)
            write_archive_items(second)
        items = json.loads((ab / "2026-05" / "archived_intel.json").read_text())
        assert len(items) == 3, f"Expected 3 unique items; got {len(items)}"
        ids = {i["stix_id"] for i in items}
        assert ids == {"f1", "f2", "f3"}


# T-PERSIST-09
def test_item_age_days_no_date_returns_zero():
    assert _item_age_days({}) == 0.0
    assert _item_age_days({"title": "No Date"}) == 0.0
    assert _item_age_days({"published": ""}) == 0.0
    assert _item_age_days({"published": None}) == 0.0


# T-PERSIST-10
def test_item_age_days_parses_iso_variants():
    ts_z = _iso(7.0)
    ts_plus = ts_z.replace("Z", "+00:00")
    assert 6.9 <= _item_age_days({"published": ts_z}) <= 7.1
    assert 6.9 <= _item_age_days({"published": ts_plus}) <= 7.1


def test_item_age_days_fallback_fields():
    ts = _iso(5.0)
    assert 4.9 <= _item_age_days({"timestamp": ts}) <= 5.1
    assert 4.9 <= _item_age_days({"created_at": ts}) <= 5.1


# T-PERSIST-11
def test_mixed_feed_correct_split():
    items = [
        _item("Fresh-A", days_ago=0.0,  confidence=0.0),
        _item("Fresh-B", days_ago=5.0,  confidence=0.0),
        _item("Fresh-C", days_ago=10.0, confidence=25.0),
        _item("Fresh-D", days_ago=14.9, confidence=0.0),
        _item("OldPass-A", days_ago=20.0, confidence=50.0),
        _item("OldPass-B", days_ago=30.0, confidence=99.0),
        _item("OldFail-A", days_ago=16.0, confidence=0.0),
        _item("OldFail-B", days_ago=25.0, confidence=5.0),
        _item("OldFail-C", days_ago=60.0, confidence=0.0),
    ]
    prod, arch, quar = _gate_enabled(items)
    assert len(prod) == 6, f"Expected 4 fresh + 2 old-pass = 6; got {len(prod)}"
    assert len(arch) == 3, f"Expected 3 archived; got {len(arch)}"
    assert len(quar) == 0


# T-PERSIST-12
def test_gate_disabled_passes_all():
    items = [
        _item("Old-A", days_ago=60.0, confidence=0.0),
        _item("Old-B", days_ago=90.0, confidence=0.0),
        _item("Fresh", days_ago=1.0,  confidence=0.0),
    ]
    fake_flags = {"APEX_REQUIRE_CONFIDENCE_GATE": False, "APEX_CONFIDENCE_GATE_MIN": 30}
    with patch("scripts.v149_intelligence_hardening.REPO", new=TMP_REPO):
        cfg = TMP_REPO / "config"
        cfg.mkdir(parents=True, exist_ok=True)
        ff = cfg / "feature_flags.json"
        ff.write_text(json.dumps(fake_flags))
        prod, arch, quar = apply_confidence_gate(items, {})
        ff.unlink(missing_ok=True)
    assert len(prod) == 3
    assert len(arch) == 0


# T-PERSIST-BOUNDARY
def test_boundary_exactly_15_days():
    # Use 14.9d (clearly inside window) vs 15.1d (clearly outside)
    # Avoids sub-second timing race at exact 15.0d boundary
    inside  = _item("At-14.9d",  days_ago=14.9, confidence=0.0)
    outside = _item("At-15.1d",  days_ago=15.1, confidence=0.0)
    prod_in,  arch_in,  _ = _gate_enabled([inside])
    prod_out, arch_out, _ = _gate_enabled([outside])
    assert len(prod_in) == 1,  "Item at 14.9d is protected (age < 15)"
    assert len(arch_in) == 0
    assert len(prod_out) == 0, "Item at 15.1d with conf=0 is archived"
    assert len(arch_out) == 1
