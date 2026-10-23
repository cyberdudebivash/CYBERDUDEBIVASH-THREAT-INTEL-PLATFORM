"""P0 regression contracts for NVD manifest identity and checkpoint durability.

These tests intentionally expose existing gaps until the corresponding
production fixes are implemented and certified.
"""
from unittest.mock import patch

import scripts.true_intel_ingestor as ingestor


class FakeDedup:
    def is_duplicate(self, item):
        return False

    def mark_seen(self, item):
        return "seen"


def _cve_item(cve_id, title="Shared advisory title"):
    return {
        "id": f"intel--{cve_id}",
        "stix_id": f"vulnerability--{cve_id}",
        "source": "NVD",
        "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "cve_id": cve_id,
        "cve_ids": [cve_id],
        "title": title,
        "published_at": "2026-10-21T12:00:00Z",
    }


def test_distinct_cves_with_same_title_are_not_collapsed():
    items = [_cve_item("CVE-2026-10001"), _cve_item("CVE-2026-10002")]
    saved = []
    with patch.object(ingestor, "_load_manifest", return_value=[]), patch.object(
        ingestor, "_save_manifest", side_effect=lambda entries: saved.extend(entries)
    ):
        added, skipped = ingestor._merge_into_manifest(items, FakeDedup())
    assert (added, skipped) == (2, 0)
    assert {item["cve_id"] for item in saved} == {
        "CVE-2026-10001", "CVE-2026-10002"
    }


def test_same_cve_with_updated_title_does_not_duplicate_manifest():
    original = _cve_item("CVE-2026-10001", "Original advisory")
    revised = _cve_item("CVE-2026-10001", "Updated advisory")
    revised["id"] = "intel--revised"
    revised["stix_id"] = "vulnerability--revised"
    saved = []
    with patch.object(ingestor, "_load_manifest", return_value=[original]), patch.object(
        ingestor, "_save_manifest", side_effect=lambda entries: saved.extend(entries)
    ):
        ingestor._merge_into_manifest([revised], FakeDedup())
    assert len([item for item in saved if item.get("cve_id") == "CVE-2026-10001"]) == 1
