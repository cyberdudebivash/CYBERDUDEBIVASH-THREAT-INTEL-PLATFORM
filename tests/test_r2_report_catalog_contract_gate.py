"""Offline R2 report-trio admission controls: no network, credentials, or R2 PUTs."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import r2_upload


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    monkeypatch.setattr(r2_upload, "REPO_ROOT", tmp_path)
    # This suite tests the registry contract; stale-age policy is covered
    # independently by test_p0_publish_window_race_and_stale_manifest_guard.
    monkeypatch.setattr(r2_upload, "stale_manifest_reason", lambda _path: None)
    folder = tmp_path / "api" / "reports"
    folder.mkdir(parents=True)
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    path = "/reports/2026/10/intel--aaaaaaaaaaaaaaaa.html"
    row = {"id": "intel--aaaaaaaaaaaaaaaa", "path": path,
           "url": "https://intel.cyberdudebivash.com" + path,
           "timestamp": timestamp, "severity": "HIGH"}
    common = {"schema_version": "1.0", "generated_at": timestamp, "total_reports": 1}
    trio = {
        "index.json": {**common, "reports_listed": 1, "reports": [row]},
        "latest.json": {**common, "reports_listed": 1, "reports": [row]},
        "stats.json": {**common, "by_severity": {
            "CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}},
    }

    def write():
        for name, value in trio.items():
            (folder / name).write_text(json.dumps(value), encoding="utf-8")

    write()
    return folder, trio, write


def test_coherent_trio_admitted_as_precheck_only(catalog):
    assert r2_upload.report_catalog_chronology_precheck() is True


def test_legacy_stats_schema_is_withheld(catalog):
    folder, trio, write = catalog
    trio["stats.json"]["schema_version"] = "1.1.0"
    write()
    assert r2_upload.report_catalog_chronology_precheck() is False


def test_severity_bucket_swap_is_withheld(catalog):
    _, trio, write = catalog
    trio["stats.json"]["by_severity"]["HIGH"] = 0
    trio["stats.json"]["by_severity"]["MEDIUM"] = 1
    write()
    assert r2_upload.report_catalog_chronology_precheck() is False


def test_generation_timestamp_mismatch_is_withheld(catalog):
    _, trio, write = catalog
    trio["stats.json"]["generated_at"] = "2026-10-01T00:00:00Z"
    write()
    assert r2_upload.report_catalog_chronology_precheck() is False


def test_latest_report_divergence_is_withheld(catalog):
    _, trio, write = catalog
    trio["latest.json"]["reports"][0] = {
        **trio["latest.json"]["reports"][0], "id": "intel--bbbbbbbbbbbbbbbb"}
    write()
    assert r2_upload.report_catalog_chronology_precheck() is False


def test_missing_trio_member_is_withheld(catalog):
    folder, _, _ = catalog
    (folder / "stats.json").unlink()
    assert r2_upload.report_catalog_chronology_precheck() is False


def test_late_upload_denied_before_credentials_or_r2(catalog, monkeypatch):
    folder, trio, write = catalog
    trio["stats.json"]["schema_version"] = "1.1.0"
    write()
    monkeypatch.chdir(folder.parents[1])
    def forbidden_credentials():
        pytest.fail("Cloudflare credentials accessed before report-trio validation")
    monkeypatch.setattr(r2_upload, "get_credentials", forbidden_credentials)
    with pytest.raises(SystemExit) as exc:
        r2_upload.main_reports_index_only()
    assert exc.value.code == 1


def test_stage35_does_not_plan_partial_report_trio(catalog):
    folder, trio, write = catalog
    trio["stats.json"]["by_severity"]["MEDIUM"] = 9
    write()
    keys = {key for _src, key in r2_upload.build_upload_plan()}
    report_keys = {key for _src, key in r2_upload.REPORTS_INDEX_FILES}
    assert keys.isdisjoint(report_keys)
