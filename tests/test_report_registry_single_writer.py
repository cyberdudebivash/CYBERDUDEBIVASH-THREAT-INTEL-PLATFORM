"""
tests/test_report_registry_single_writer.py — CyberDudeBivash SENTINEL APEX

Regression tests for the F-02 fix (report-index dual-writer conflict).

Background: scripts/build_reports_index.py (sentinel-blogger.yml STAGE 3.3.7)
is the sole authoritative writer of api/reports/index.json,
api/reports/latest.json, and api/reports/stats.json -- it scans the real
reports/ directory on disk and produces report_url values that resolve to
actual HTML files. scripts/generate_dashboard_feeds.py (run from a separate,
independently-scheduled workflow, dashboard-feeds-sync.yml) used to ALSO
write api/reports/index.json and api/reports/stats.json, derived from a
severity-filtered subset of feed items with fabricated /api/reports/{id}.json
URLs that never resolved to a real report file. Two writers racing on the
same R2 keys with incompatible schemas produced a flapping, internally
inconsistent report registry: live production was observed serving
index.json with total_reports=329 and latest.json with total_reports=0 from
what should have been the same authoritative source.

This file also covers two related bugs found in scripts/r2_reports_integrity.py
(STAGE 3.5.1, which purges index/latest entries whose HTML is confirmed
missing from R2): total_reports was left stale after a purge (drifting from
the true count), and latest.json was only ever checked when index.json's own
purge_count was nonzero -- so a staleness unique to latest.json could survive
indefinitely.
"""
import json
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))

import generate_dashboard_feeds  # noqa: E402
import r2_reports_integrity as integrity  # noqa: E402


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


class TestGenerateDashboardFeedsDoesNotWriteReportRegistry:
    """generate_dashboard_feeds.py must never write api/reports/index.json or
    api/reports/stats.json -- that is build_reports_index.py's exclusive
    responsibility. Regression guard for the F-02 dual-writer conflict."""

    def test_does_not_create_reports_index_or_stats(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _write_json(tmp_path / "api" / "feed.json", [
            {
                "id": "intel--test1", "title": "Test Advisory", "severity": "CRITICAL",
                "risk_score": 9.0, "published_at": "2026-08-10T00:00:00Z",
                "cve_ids": ["CVE-2026-0001"],
            },
        ])

        generate_dashboard_feeds.main()

        assert not (tmp_path / "api" / "reports" / "index.json").exists(), (
            "generate_dashboard_feeds.py must not write api/reports/index.json "
            "-- build_reports_index.py is the sole authoritative writer (F-02)"
        )
        assert not (tmp_path / "api" / "reports" / "stats.json").exists(), (
            "generate_dashboard_feeds.py must not write api/reports/stats.json "
            "-- build_reports_index.py is the sole authoritative writer (F-02)"
        )
        # Positive control: the script still does its actual job.
        assert (tmp_path / "api" / "v1" / "intel" / "stats.json").exists()
        assert (tmp_path / "api" / "v1" / "intel" / "campaigns.json").exists()
        # Same single-writer rule for api/v1/intel/apex.json (P0 Phase 3C):
        # generate_api_manifests.py is its sole producer. This assertion used
        # to require the competing SUMMARY write that caused the schema drift.
        assert not (tmp_path / "api" / "v1" / "intel" / "apex.json").exists()


class TestR2ReportsIntegrityPurgeConsistency:
    """scripts/r2_reports_integrity.py must keep total_reports consistent
    after a purge, and must check/purge latest.json regardless of whether
    index.json itself had anything to purge."""

    def _common_env(self, monkeypatch):
        monkeypatch.setenv("CF_ACCOUNT_ID", "test-account")
        monkeypatch.setenv("CF_R2_REPORTS_KEY_ID", "test-key")
        monkeypatch.setenv("CF_R2_REPORTS_SECRET_KEY", "test-secret")
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
        monkeypatch.setattr(integrity, "_s3_cp", lambda *a, **k: True)

    def _patch_paths(self, tmp_path, monkeypatch):
        monkeypatch.setattr(integrity, "INDEX_PATH", tmp_path / "api" / "reports" / "index.json")
        monkeypatch.setattr(integrity, "LATEST_PATH", tmp_path / "api" / "reports" / "latest.json")
        monkeypatch.setattr(integrity, "FEED_PATH", tmp_path / "api" / "feed.json")

    def test_total_reports_decrements_by_purged_count(self, tmp_path, monkeypatch):
        self._patch_paths(tmp_path, monkeypatch)
        self._common_env(monkeypatch)

        _write_json(integrity.INDEX_PATH, {
            "schema_version": "1.0", "total_reports": 3, "reports_listed": 3,
            "reports": [
                {"id": "intel--a", "path": "/reports/2026/08/intel--a.html"},
                {"id": "intel--b", "path": "/reports/2026/08/intel--b.html"},
                {"id": "intel--c", "path": "/reports/2026/08/intel--c.html"},
            ],
        })
        _write_json(integrity.LATEST_PATH, {
            "schema_version": "1.0", "total_reports": 3, "reports_listed": 2,
            "reports": [
                {"id": "intel--a", "path": "/reports/2026/08/intel--a.html"},
                {"id": "intel--b", "path": "/reports/2026/08/intel--b.html"},
            ],
        })
        _write_json(integrity.FEED_PATH, [])

        # intel--b is missing from R2 (e.g. its upload silently failed).
        monkeypatch.setattr(
            integrity, "_r2_object_exists",
            lambda key, *a, **k: "intel--b" not in key,
        )

        rc = integrity.main()
        assert rc == 0

        new_index = json.loads(integrity.INDEX_PATH.read_text())
        assert new_index["reports_listed"] == 2
        assert new_index["total_reports"] == 2, (
            "total_reports must be reduced by the purged count, not left stale (F-02 fix)"
        )
        assert {r["id"] for r in new_index["reports"]} == {"intel--a", "intel--c"}

        new_latest = json.loads(integrity.LATEST_PATH.read_text())
        assert new_latest["reports_listed"] == 1
        assert new_latest["total_reports"] == 2, (
            "latest.json's total_reports must also be reduced by its own purged count"
        )
        assert {r["id"] for r in new_latest["reports"]} == {"intel--a"}

    def test_latest_purged_even_when_index_has_zero_purges(self, tmp_path, monkeypatch):
        """The exact bug this guards against: index.json has nothing to purge
        (all its entries verified present), but latest.json has independently
        drifted and lists an entry that is not even present in index.json's
        own list. Before the fix, latest.json's own entries were never added
        to the checked key set, and the purge block was gated on index.json's
        purge_count -- so this stale entry would survive forever."""
        self._patch_paths(tmp_path, monkeypatch)
        self._common_env(monkeypatch)

        _write_json(integrity.INDEX_PATH, {
            "schema_version": "1.0", "total_reports": 1, "reports_listed": 1,
            "reports": [{"id": "intel--a", "path": "/reports/2026/08/intel--a.html"}],
        })
        _write_json(integrity.LATEST_PATH, {
            "schema_version": "1.0", "total_reports": 1, "reports_listed": 1,
            "reports": [{"id": "intel--z", "path": "/reports/2026/08/intel--z.html"}],
        })
        _write_json(integrity.FEED_PATH, [])

        # Only intel--z is missing from R2; intel--a is fine.
        monkeypatch.setattr(
            integrity, "_r2_object_exists",
            lambda key, *a, **k: "intel--z" not in key,
        )

        rc = integrity.main()
        assert rc == 0

        new_index = json.loads(integrity.INDEX_PATH.read_text())
        assert new_index["reports_listed"] == 1  # unchanged -- intel--a is present

        new_latest = json.loads(integrity.LATEST_PATH.read_text())
        assert new_latest["reports_listed"] == 0, (
            "intel--z must be purged from latest.json even though index.json "
            "had zero purges of its own (F-02 decoupling fix)"
        )
        assert new_latest["total_reports"] == 0
