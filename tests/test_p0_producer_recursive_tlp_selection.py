"""P0: no FREE/PRO report can diverge from the final recursive R2 TLP gate.

This is a pure offline test of the actual production TLP policy on synthetic
records. No R2, HTTP, customer data, credentials or external dependencies.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from strict_public_manifest_selection import select_last_mile_verified  # noqa: E402
from tlp_public_boundary import build_parent_index, sanitize_document  # noqa: E402
from tlp_policy import partition_publishable  # noqa: E402


def item(suffix: str, **extra):
    return {
        "id": "intel--" + suffix * 24,
        "title": "Synthetic vendor advisory",
        "tlp": "TLP:CLEAR",
        "source": "Vendor",
        "source_url": "https://vendor.example.com/intel",
        "severity": "HIGH",
        **extra,
    }


def setup_sources(root, source, manifest=None):
    (root / "api").mkdir(parents=True)
    (root / "data/stix").mkdir(parents=True)
    (root / "api/feed.json").write_text(json.dumps(source), encoding="utf8")
    (root / "data/stix/feed_manifest.json").write_text(
        json.dumps(manifest if manifest is not None else source), encoding="utf8")


def test_unmodified_clear_source_kept_and_no_source_file_mutated(tmp_path):
    clear = item("a")
    setup_sources(tmp_path, [clear])
    before = (tmp_path / "api/feed.json").read_bytes()
    kept, reasons = select_last_mile_verified([clear], tmp_path)
    assert kept == [clear]
    assert reasons == {}
    assert (tmp_path / "api/feed.json").read_bytes() == before


def test_nested_red_evidence_denied_as_one_whole_advisory_instead_of_redacting_paid_bytes(tmp_path):
    clear = item("a")
    mixed = item("b", analysis={"tlp": "TLP:RED", "secret": "DO_NOT_PUBLISH"})
    setup_sources(tmp_path, [clear, mixed])
    assert len(partition_publishable([clear, mixed])[0]) == 2, (
        "reproduce genuine discrepancy: record-level policy misses nested restricted object")
    parents = build_parent_index([tmp_path / "api/feed.json"])
    sanitized, removed, withheld = sanitize_document(mixed, parents=parents)
    assert withheld is None and removed and sanitized != mixed, (
        "last-mile gate must reject the nested source bytes")
    original = copy.deepcopy([clear, mixed])
    kept, reasons = select_last_mile_verified([clear, mixed], tmp_path)
    assert kept == [clear]
    assert reasons == {"WOULD_REQUIRE_LAST_MILE_REDACTION": 1}
    assert [clear, mixed] == original, "never mutate original evidence to force approval"
    assert "DO_NOT_PUBLISH" not in json.dumps(kept)


def test_restricted_cross_source_parent_wins_over_clear_report_record(tmp_path):
    candidate = item("b")
    archival = dict(candidate, tlp="TLP:RED")
    setup_sources(tmp_path, [candidate], [archival])
    kept, reasons = select_last_mile_verified([candidate], tmp_path)
    assert kept == []
    assert reasons == {"DENIED_RECORD": 1}


def test_legacy_missing_and_conflicting_labels_fail_closed(tmp_path):
    records = [
        item("a"), item("b", tlp="TLP:RED"),
        item("c", tlp=None), item("d", classification="TLP:CLEAR; TLP:RED"),
    ]
    setup_sources(tmp_path, records)
    kept, reasons = select_last_mile_verified(records, tmp_path)
    assert kept == [records[0]]
    assert sum(reasons.values()) == 3
    assert all(x["id"] not in json.dumps(reasons) for x in records)


def test_nested_unclassified_advisory_is_not_laundered_into_free_or_pro(tmp_path):
    clear = item("a")
    bad = item("b", nested=[{"id": "intel--" + "f"*24, "title": "Unclassified report"}])
    setup_sources(tmp_path, [clear, bad])
    allowed, reasons = select_last_mile_verified([clear, bad], tmp_path)
    assert allowed == [clear]
    assert reasons == {"WOULD_REQUIRE_LAST_MILE_REDACTION": 1}


def test_malformed_input_is_not_treated_as_a_clean_feed(tmp_path):
    for malformed in (None, "not a list", [{"id": "x"}, None]):
        with pytest.raises(ValueError, match="P0_MANIFEST_TLP_UNVERIFIABLE_INPUT"):
            select_last_mile_verified(malformed, tmp_path)


def test_final_paired_manifest_generator_has_single_last_mile_verification_step():
    source = (ROOT / "scripts/generate_api_manifests.py").read_text(encoding="utf8")
    last_mile = source.index("select_last_mile_verified(deduped_feed, _Path.cwd())")
    sorted_feed = source.index("sorted_feed = sorted(deduped_feed")
    free_projection = source.index("_sanitize_feed(sorted_feed)")
    paid_projection = source.index("_sanitize_feed_pro(sorted_feed)")
    assert last_mile < sorted_feed < free_projection < paid_projection
    assert source.count("select_last_mile_verified(deduped_feed, _Path.cwd())") == 1
    assert "atomic_write(FEED_PATH, _safe_json)" in source
    assert "atomic_write('feed.json', _safe_json)" in source
    assert "if not _stable:" in source
