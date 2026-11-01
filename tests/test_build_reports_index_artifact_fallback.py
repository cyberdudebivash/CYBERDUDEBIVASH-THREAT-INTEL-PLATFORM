"""
tests/test_build_reports_index_artifact_fallback.py

Regression test for a P1 customer-facing trust defect found during live
production certification: the public REPORTS catalogue
(api/reports/index.json, api/reports/latest.json) showed the raw internal
report ID as the title, "UNKNOWN" severity, and a null risk score for the
overwhelming majority of listed reports (measured live: 96.5% of
latest.json, 99.8% of the full index.json).

Root cause: scripts/build_reports_index.py enriches each report entry by
looking up its id in api/feed.json -- but api/feed.json only ever holds the
current pipeline run's rolling window (measured live: ~39-53 items), while
reports/ retains every report ever generated (measured live: 11,398+
files). A report whose originating intel item has scrolled out of that
window gets {} back from the lookup, and title/severity/risk_score fall
through to placeholders -- for the vast majority of the historical
catalogue, forever, regardless of how many times the pipeline re-runs.

Fix: when the feed lookup has nothing, fall back to parsing the report
HTML's own permanently-embedded <title> and og:description/description meta
tags (written by generate_intel_reports.py at generation time from the same
canonical intel item, and publicly visible in every report's SEO/social-share
metadata already -- not paywalled content). Deterministic regex parse, never
fuzzy-matched, never fabricated: a value is used only if actually found in
the artifact; genuinely unavailable data stays honestly UNKNOWN/null.

These tests build real fixture files (a temp reports/ tree + api/feed.json)
and run the actual production script via subprocess, so they exercise the
real code path, not a reimplementation.
"""
import json
import os
import shutil
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT_REAL = Path(__file__).resolve().parent.parent
REAL_SCRIPT = REPO_ROOT_REAL / "scripts" / "build_reports_index.py"
REAL_CANONICAL_TS = REPO_ROOT_REAL / "scripts" / "canonical_timestamp.py"


def _recent_ts(hours_ago: float = 1) -> str:
    """P0 R2 cost fix: scripts/build_reports_index.py now requires a
    provable canonical timestamp (via the item's api/feed.json entry) to
    include a report in the hot-window index at all -- see that script's
    module docstring. Every fixture feed entry in this file needs one."""
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _report_html(title, severity=None, risk_score=None, engine_comment=True, description_style="og"):
    """Builds a realistic report HTML fixture matching
    generate_intel_reports.py's real output shape."""
    parts = ["<!doctype html>"]
    if engine_comment:
        parts.append("<!-- CDB-REPORT-ENGINE: generate_intel_reports.py vv184.0 -->")
    parts.append("<html lang='en'><head>")
    if severity is not None and risk_score is not None:
        desc = f"{title} - Severity {severity} - Tactical Dossier. Risk {risk_score}/10. Generated 2026-08-07 UTC."
        og_desc = f"Severity {severity} · Risk {risk_score}/10 · CYBERDUDEBIVASH SENTINEL APEX"
        if description_style == "og":
            parts.append(f"<meta property='og:description' content='{og_desc}'>")
        else:
            parts.append(f"<meta name='description' content='{desc}'>")
    parts.append(f"<title>{title} · SENTINEL APEX Tactical Dossier</title>")
    parts.append("</head><body>report body content -- PRO ONLY full text</body></html>")
    html = "\n".join(parts)
    # build_reports_index.py's scanner requires files > 512 bytes (filters
    # out empty/truncated report artifacts) -- pad realistic fixtures past
    # that so they aren't silently excluded from the scan.
    if len(html.encode("utf-8")) <= 512:
        html += "\n<!-- " + ("padding " * 80) + "-->"
    return html


class TestBuildReportsIndexArtifactFallback(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="bri_test_"))
        (self.tmp / "scripts").mkdir()
        shutil.copy(REAL_SCRIPT, self.tmp / "scripts" / "build_reports_index.py")
        # P0 R2 cost fix: build_reports_index.py now imports its sibling
        # scripts/canonical_timestamp.py for canonical-timestamp-based
        # windowing -- this isolated fixture copy needs it too, same as
        # it already needed only build_reports_index.py itself before.
        shutil.copy(REAL_CANONICAL_TS, self.tmp / "scripts" / "canonical_timestamp.py")
        (self.tmp / "reports" / "2026" / "08").mkdir(parents=True)
        (self.tmp / "api" / "reports").mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_report(self, report_id, html):
        path = self.tmp / "reports" / "2026" / "08" / f"{report_id}.html"
        path.write_text(html, encoding="utf-8")
        return path

    def _write_feed(self, items):
        # Fixtures are authored before their feed timestamps. Place each
        # artifact in the same canonical UTC month as its feed evidence so
        # fallback tests do not inadvertently exercise chronology rejection.
        for item in items:
            raw = item.get("timestamp")
            if not raw:
                continue
            ts = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            for path in (self.tmp / "reports").rglob(item["id"] + ".html"):
                target = self.tmp / "reports" / ts.strftime("%Y") / ts.strftime("%m") / path.name
                target.parent.mkdir(parents=True, exist_ok=True)
                if path != target:
                    path.replace(target)
        (self.tmp / "api" / "feed.json").write_text(json.dumps(items), encoding="utf-8")

    def _run(self):
        env = dict(os.environ)
        env["PLATFORM_BASE_URL"] = "https://intel.example.test"
        proc = subprocess.run(
            [sys.executable, str(self.tmp / "scripts" / "build_reports_index.py")],
            cwd=self.tmp, env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, f"script must exit 0\nstdout={proc.stdout}\nstderr={proc.stderr}")
        return json.loads((self.tmp / "api" / "reports" / "index.json").read_text())

    def _entry(self, index_payload, report_id):
        for r in index_payload["reports"]:
            if r["id"] == report_id:
                return r
        self.fail(f"{report_id} not found in index")

    # 1. Canonical feed mapping still wins when present (single source of truth preserved).
    def test_feed_match_is_used_when_present(self):
        self._write_report("intel--aaa1111111111111", _report_html("Ignored Artifact Title", "LOW", 1.0))
        self._write_feed([{"id": "intel--aaa1111111111111", "title": "Real Feed Title",
                            "severity": "CRITICAL", "risk_score": 9.5, "timestamp": _recent_ts()}])
        idx = self._run()
        entry = self._entry(idx, "intel--aaa1111111111111")
        self.assertEqual(entry["title"], "Real Feed Title")
        self.assertEqual(entry["severity"], "CRITICAL")
        self.assertEqual(entry["risk_score"], 9.5)

    # 2/3/4. Title/severity/risk enrichment from the artifact when the feed
    # entry exists (proving the item is within the hot window -- P0 R2 cost
    # fix requirement) but carries none of those fields itself yet (e.g. an
    # enrichment stage hasn't populated them). Before that fix this
    # scenario was "id absent from feed entirely"; a feed entry with truly
    # NO id at all can no longer be included in the index by design (its
    # age can't be proven -- see build_reports_index.py's module docstring),
    # so the meaningful, still-current version of this scenario is "present
    # in feed, but under-enriched", not "absent from feed".
    def test_artifact_fallback_when_feed_entry_lacks_enrichment_fields(self):
        self._write_report("intel--bbb2222222222222",
                            _report_html("CVE-2099-00001 Something Bad Happened", "HIGH", 7.6))
        self._write_feed([{"id": "intel--bbb2222222222222", "timestamp": _recent_ts()}])
        idx = self._run()
        entry = self._entry(idx, "intel--bbb2222222222222")
        self.assertEqual(entry["title"], "CVE-2099-00001 Something Bad Happened")
        self.assertEqual(entry["severity"], "HIGH")
        self.assertEqual(entry["risk_score"], 7.6)

    def test_artifact_fallback_works_with_plain_description_meta(self):
        self._write_report("intel--ccc3333333333333",
                            _report_html("Plain Meta Report", "MEDIUM", 5.2, description_style="plain"))
        self._write_feed([{"id": "intel--ccc3333333333333", "timestamp": _recent_ts()}])
        idx = self._run()
        entry = self._entry(idx, "intel--ccc3333333333333")
        self.assertEqual(entry["severity"], "MEDIUM")
        self.assertEqual(entry["risk_score"], 5.2)

    # 5/8. Missing canonical record + genuinely unknown severity/risk -> honest state, no fabrication.
    def test_missing_severity_stays_honestly_unknown_not_fabricated(self):
        html = ("<!doctype html><html><head>"
                "<title>Old Format Report — CyberDudeBivash SENTINEL APEX</title>"
                "</head><body></body></html>"
                "\n<!-- " + ("padding " * 80) + "-->")
        self._write_report("intel--ddd4444444444444", html)
        self._write_feed([{"id": "intel--ddd4444444444444", "timestamp": _recent_ts()}])
        idx = self._run()
        entry = self._entry(idx, "intel--ddd4444444444444")
        self.assertEqual(entry["title"], "Old Format Report")
        self.assertEqual(entry["severity"], "UNKNOWN")
        self.assertIsNone(entry["risk_score"])

    # 6. Malformed/unreadable report file must not crash the whole run.
    def test_malformed_report_file_does_not_crash_run(self):
        bad_path = self.tmp / "reports" / "2026" / "08" / "intel--eee5555555555555.html"
        bad_path.write_bytes(b"\xff\xfe\x00not really html \x00\x01")
        self._write_report("intel--fff6666666666666", _report_html("Fine Report", "LOW", 1.5))
        # Both ids get a feed entry (P0 R2 cost fix: unprovable age is
        # excluded entirely now) -- the malformed file's entry deliberately
        # carries no title/severity/risk so the artifact-metadata-extraction
        # fallback path (the code this test actually exercises) still runs
        # against its malformed bytes and must not crash.
        self._write_feed([
            {"id": "intel--eee5555555555555", "timestamp": _recent_ts()},
            {"id": "intel--fff6666666666666", "timestamp": _recent_ts()},
        ])
        idx = self._run()  # must not raise / exit non-zero
        ids = [r["id"] for r in idx["reports"]]
        self.assertIn("intel--fff6666666666666", ids)

    # 9. Zero risk score must be preserved, not treated as "missing".
    def test_zero_risk_score_from_feed_is_preserved_not_treated_as_missing(self):
        self._write_report("intel--000aaaaaaaaaaaaa", _report_html("Zero Risk Report", "LOW", 0.0))
        self._write_feed([{"id": "intel--000aaaaaaaaaaaaa", "title": "Zero Risk Feed Title",
                            "severity": "LOW", "risk_score": 0.0, "timestamp": _recent_ts()}])
        idx = self._run()
        entry = self._entry(idx, "intel--000aaaaaaaaaaaaa")
        self.assertEqual(entry["risk_score"], 0.0)

    # 11/12. Only public catalogue metadata is exposed -- no paywalled fields introduced.
    def test_entry_schema_contains_no_restricted_content_fields(self):
        self._write_report("intel--111bbbbbbbbbbbbb", _report_html("Schema Check Report", "HIGH", 8.0))
        self._write_feed([{"id": "intel--111bbbbbbbbbbbbb", "timestamp": _recent_ts()}])
        idx = self._run()
        entry = self._entry(idx, "intel--111bbbbbbbbbbbbb")
        restricted_fields = {"body", "full_text", "iocs", "ioc_list", "attribution",
                              "stix_bundle", "api_key", "internal_notes"}
        self.assertFalse(restricted_fields & set(entry.keys()),
                          f"registry entry must never carry restricted/paid-only fields: {entry.keys()}")

    # 14/15. latest.json is a strict prefix subset of index.json (consistency).
    def test_latest_json_is_prefix_of_index_json(self):
        feed_items = []
        for i in range(3):
            item_id = f"intel--2{i:02d}cccccccccccc"
            self._write_report(item_id, _report_html(f"Report {i}", "LOW", 1.0 + i))
            feed_items.append({"id": item_id, "timestamp": _recent_ts(hours_ago=i + 1)})
        self._write_feed(feed_items)
        self._run()
        index_payload = json.loads((self.tmp / "api" / "reports" / "index.json").read_text())
        latest_payload = json.loads((self.tmp / "api" / "reports" / "latest.json").read_text())
        index_ids = [r["id"] for r in index_payload["reports"]]
        latest_ids = [r["id"] for r in latest_payload["reports"]]
        self.assertEqual(index_ids[: len(latest_ids)], latest_ids)

    # 16. total_reports reflects actual file count on disk.
    def test_total_reports_matches_files_on_disk(self):
        feed_items = []
        for i in range(4):
            item_id = f"intel--3{i:02d}dddddddddddd"
            self._write_report(item_id, _report_html(f"Report {i}", "LOW", 1.0))
            feed_items.append({"id": item_id, "timestamp": _recent_ts(hours_ago=i + 1)})
        self._write_feed(feed_items)
        idx = self._run()
        self.assertEqual(idx["total_reports"], 4)
        self.assertEqual(idx["reports_listed"], 4)

    # 18. Deterministic newest-first ordering by CANONICAL TIMESTAMP (P0 R2
    # cost fix -- was file mtime; forensic analysis found mtime unreliable
    # in this repo, see build_reports_index.py's module docstring, so
    # ordering no longer depends on write order/sleep timing at all here).
    def test_ordering_is_newest_first_by_canonical_timestamp(self):
        self._write_report("intel--400eeeeeeeeeeeee", _report_html("Oldest", "LOW", 1.0))
        self._write_report("intel--401eeeeeeeeeeeee", _report_html("Newest", "LOW", 1.0))
        self._write_feed([
            {"id": "intel--400eeeeeeeeeeeee", "timestamp": _recent_ts(hours_ago=5)},
            {"id": "intel--401eeeeeeeeeeeee", "timestamp": _recent_ts(hours_ago=1)},
        ])
        idx = self._run()
        ids = [r["id"] for r in idx["reports"]]
        self.assertEqual(ids[0], "intel--401eeeeeeeeeeeee")
        self.assertEqual(ids[1], "intel--400eeeeeeeeeeeee")

    # 19. Idempotent regeneration -- running twice on unchanged inputs gives the same metadata.
    def test_idempotent_regeneration(self):
        self._write_report("intel--500ffffffffffff0", _report_html("Idempotent Report", "MEDIUM", 4.4))
        self._write_feed([{"id": "intel--500ffffffffffff0", "timestamp": _recent_ts()}])
        idx1 = self._run()
        idx2 = self._run()
        e1 = self._entry(idx1, "intel--500ffffffffffff0")
        e2 = self._entry(idx2, "intel--500ffffffffffff0")
        self.assertEqual(e1["title"], e2["title"])
        self.assertEqual(e1["severity"], e2["severity"])
        self.assertEqual(e1["risk_score"], e2["risk_score"])


class TestSingleWriterOwnership(unittest.TestCase):
    """13. Proves build_reports_index.py remains the sole content-generating
    writer of api/reports/index.json and api/reports/latest.json. Fails if
    a new script starts writing full report entries into these files
    (r2_reports_integrity.py is allowed -- it only purges/re-uploads the
    existing writer's output, verified separately by asserting it never
    sets a 'title' key on an entry)."""

    def test_no_new_content_writer_introduced(self):
        scripts_dir = REPO_ROOT_REAL / "scripts"
        write_markers = ("_atomic_write(", ".write_text(", "json.dump(")
        registry_paths = ("api/reports/index.json", "api/reports/latest.json",
                           'API_REPORTS / "index.json"', "API_REPORTS / 'index.json'",
                           'API_REPORTS / "latest.json"', "API_REPORTS / 'latest.json'")
        offenders = []
        for path in scripts_dir.glob("*.py"):
            if path.name in ("build_reports_index.py",):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            # Only flag a script that WRITES to the registry paths (a real
            # second writer), not one that merely mentions the path string
            # (e.g. a docstring explaining a past fix, or a read-only gate
            # check) -- and only if that write is near a "title" assignment,
            # i.e. it's constructing report entries, not passthrough-purging
            # the existing writer's output (r2_reports_integrity.py does the
            # latter and must stay allowed).
            write_lines = [
                i for i, line in enumerate(lines)
                if any(rp in line for rp in registry_paths)
                and any(wm in "\n".join(lines[max(0, i - 3): i + 1]) for wm in write_markers)
            ]
            for wl in write_lines:
                window = "\n".join(lines[max(0, wl - 15): wl + 15])
                if '"title"' in window or "'title'" in window:
                    offenders.append(path.name)
                    break
        self.assertEqual(
            offenders, [],
            f"found a second script that WRITES to the reports registry "
            f"paths AND constructs report entry metadata (title field) near "
            f"that write -- this would recreate the F-02 dual-writer class "
            f"of bug: {offenders}"
        )


if __name__ == "__main__":
    unittest.main()
