"""Strict UTC integration tests: no production calls, billing or mutations."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import deployment_convergence_validator as dcv


BASE = "https://intel.cyberdudebivash.com"


def record(char, timestamp):
    rid = "intel--" + char * 24
    path = "/reports/2025/10/" + rid + ".html"
    return {"id": rid, "path": path, "url": BASE + path, "timestamp": timestamp}


def test_strict_mode_uses_utc_not_hash(monkeypatch, tmp_path):
    earlier = record("f", "2025-10-01T00:00:00Z")
    later = record("a", "2025-10-02T00:00:00Z")
    catalog = tmp_path / "index.json"
    catalog.write_text(json.dumps({"reports": [earlier, later]}), encoding="utf-8")
    monkeypatch.setenv("CONVERGENCE_STRICT_CHRONOLOGY", "1")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", catalog)
    monkeypatch.setattr(dcv, "MAX_REPORT_PROBES", 1)
    monkeypatch.setattr(dcv, "HIST_PROBE_COUNT", 1)
    latest, historical = dcv._extract_report_urls([], {"files": {}})
    assert latest == [later["url"]]
    assert historical == [earlier["url"]]


def test_strict_mode_missing_catalog_hard_blocks(monkeypatch, tmp_path):
    monkeypatch.setenv("CONVERGENCE_STRICT_CHRONOLOGY", "1")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", tmp_path / "missing.json")
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([], {"files": {}})


def test_strict_mode_bad_timestamp_never_falls_back(monkeypatch, tmp_path):
    bad = record("a", "2025-10-02T00:00:00")
    catalog = tmp_path / "index.json"
    catalog.write_text(json.dumps({"reports": [bad]}), encoding="utf-8")
    monkeypatch.setenv("CONVERGENCE_STRICT_CHRONOLOGY", "1")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", catalog)
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([{"report_url": bad["url"]}], {"files": {}})


def test_strict_mode_manifest_mismatch_hard_blocks(monkeypatch, tmp_path):
    item = record("a", "2025-10-02T00:00:00Z")
    catalog = tmp_path / "index.json"
    catalog.write_text(json.dumps({"reports": [item]}), encoding="utf-8")
    monkeypatch.setenv("CONVERGENCE_STRICT_CHRONOLOGY", "1")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", catalog)
    manifest = {"files": {"reports/2025/10/intel--" + "b" * 24 + ".html": {}}}
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([], manifest)


def test_explicit_legacy_override_cannot_bypass_missing_catalog(monkeypatch, tmp_path):
    monkeypatch.setenv("CONVERGENCE_STRICT_CHRONOLOGY", "0")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", tmp_path / "missing.json")
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([], {"files": {}})


def test_unset_mode_cannot_fall_back_to_untrusted_feed(monkeypatch, tmp_path):
    monkeypatch.delenv("CONVERGENCE_STRICT_CHRONOLOGY", raising=False)
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", tmp_path / "missing.json")
    forged = record("a", "2025-10-02T00:00:00Z")
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([{"report_url": forged["url"]}], {"files": {}})


def test_legacy_override_with_valid_catalog_still_uses_utc(monkeypatch, tmp_path):
    """Setting the old bypass flag must not silently restore filename sorting."""
    earlier = record("f", "2025-10-01T00:00:00Z")
    later = record("a", "2025-10-02T00:00:00Z")
    catalog = tmp_path / "index.json"
    catalog.write_text(json.dumps({"reports": [earlier, later]}), encoding="utf-8")
    monkeypatch.setenv("CONVERGENCE_STRICT_CHRONOLOGY", "0")
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", catalog)
    monkeypatch.setattr(dcv, "MAX_REPORT_PROBES", 1)
    monkeypatch.setattr(dcv, "HIST_PROBE_COUNT", 1)
    latest, historical = dcv._extract_report_urls(
        [{"report_url": earlier["url"]}], {"files": {}}
    )
    assert latest == [later["url"]]
    assert historical == [earlier["url"]]


def test_customer_ready_catalog_with_all_reports_withheld_blocks(monkeypatch, tmp_path):
    """A populated candidate count must never substitute for deliverable reports."""
    catalog = tmp_path / "index.json"
    catalog.write_text(
        json.dumps({
            "schema_version": "2.0.0",
            "feed_type": "customer_ready_catalog",
            "total_candidates": 28,
            "customer_ready_count": 0,
            "withheld_count": 28,
            "total_reports": 28,
            "reports_listed": 0,
            "reports": [],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(dcv, "REPORTS_CATALOG_PATH", catalog)
    with pytest.raises(RuntimeError, match="blocked"):
        dcv._extract_report_urls([], {"files": {}})
