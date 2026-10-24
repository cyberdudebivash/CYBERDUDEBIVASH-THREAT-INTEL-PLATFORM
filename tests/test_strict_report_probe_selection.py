"""Offline regression tests for chronology and manifest-aware report selection."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from strict_report_probe_selection import ReportSelectionBlocked, select_report_probes


BASE = "https://intel.cyberdudebivash.com"


def report(digest: str, timestamp: str):
    slug = "intel--" + digest * 24
    path = "/reports/2025/10/" + slug + ".html"
    return {"id": slug, "path": path, "url": BASE + path, "timestamp": timestamp}


def test_latest_is_utc_ordered_not_hash_ordered():
    early = report("f", "2025-10-01T00:00:00Z")
    late = report("a", "2025-10-02T00:00:00+00:00")
    # A hash sort would incorrectly designate the f... report latest.
    urls = [early["url"], late["url"]]
    latest, historical = select_report_probes(
        {"reports": [early, late]}, manifest_files={url[len(BASE) + 1:]: {} for url in urls},
        latest_limit=1, historical_limit=1,
    )
    assert latest == [late["url"]]
    assert historical == [early["url"]]


def test_selected_report_absent_from_nonempty_manifest_blocks():
    early = report("f", "2025-10-01T00:00:00Z")
    late = report("a", "2025-10-02T00:00:00Z")
    with pytest.raises(ReportSelectionBlocked, match="missing from Pages manifest"):
        select_report_probes(
            {"reports": [early, late]},
            manifest_files={early["path"].lstrip("/"): {}},
            latest_limit=1, historical_limit=1,
        )


def test_naive_timestamp_blocks_instead_of_guessing_timezone():
    bad = report("a", "2025-10-02T00:00:00")
    with pytest.raises(ReportSelectionBlocked, match=r"(?i)^canonical chronology rejected:"):
        select_report_probes({"reports": [bad]}, manifest_files={})


def test_duplicate_report_paths_block():
    item = report("a", "2025-10-02T00:00:00Z")
    with pytest.raises(ReportSelectionBlocked, match="duplicate"):
        select_report_probes({"reports": [item, item]}, manifest_files={})


def test_r2_first_empty_pages_manifest_is_precheck_only():
    item = report("a", "2025-10-02T00:00:00Z")
    latest, historical = select_report_probes({"reports": [item]}, manifest_files={})
    assert latest == [item["url"]]
    assert historical == []
