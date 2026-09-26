"""
The reports index lists every report R2 holds, not only this run's files.

Run 36232016684 (2026-09-26): no new reports were generated, so reports/ on
the runner held none; api/reports/index.json had total_reports=0 and STAGE
5.9.2 GATE-2 failed. The live catalog listed 7 of the 23 customer-ready
reports. scripts/r2_report_publisher.py's state file is the inventory of
what R2 holds (html_sha256 = PUT succeeded).
"""
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import build_reports_index as bri  # noqa: E402


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class PublishedStateIndexTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self._orig = (bri.REPORTS_ROOT, bri.API_FEED, bri.API_REPORTS, bri.PUBLISH_STATE)
        bri.REPORTS_ROOT = root / "reports"
        bri.API_FEED = root / "api" / "feed.json"
        bri.API_REPORTS = root / "api" / "reports"
        bri.PUBLISH_STATE = root / "data" / "cache" / "r2_report_publish_state.json"
        bri.API_FEED.parent.mkdir(parents=True)
        bri.PUBLISH_STATE.parent.mkdir(parents=True)
        self.now = datetime.now(timezone.utc)

    def tearDown(self):
        bri.REPORTS_ROOT, bri.API_FEED, bri.API_REPORTS, bri.PUBLISH_STATE = self._orig
        self._tmp.cleanup()

    def _feed(self, ids_hours):
        bri.API_FEED.write_text(json.dumps([
            {"id": i, "title": f"t {i}", "severity": "HIGH", "timestamp": _iso(self.now - timedelta(hours=h))}
            for i, h in ids_hours]))

    def _state(self, entries):
        bri.PUBLISH_STATE.write_text(json.dumps({"schema_version": "1.0", "items": entries}))

    def _entry(self, rid, sha=True):
        e = {"html_key": f"reports/2026/09/{rid}.html", "canonical_ts": _iso(self.now)}
        if sha:
            e["html_sha256"] = "ab" * 32
        return e

    def _disk(self, rid):
        d = bri.REPORTS_ROOT / "2026" / "09"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{rid}.html").write_text("<html>" + "x" * 600 + "</html>")

    def _index(self):
        self.assertEqual(bri.main(), 0)
        return json.loads((bri.API_REPORTS / "index.json").read_text())

    def test_run_with_no_new_reports_still_lists_what_r2_holds(self):
        ids = [f"intel--pub{i:04d}" for i in range(23)]
        self._feed([(i, 2) for i in ids])
        self._state({i: self._entry(i) for i in ids})
        idx = self._index()  # reports/ does not even exist on the runner
        self.assertEqual(idx["total_reports"], 23)
        self.assertEqual({r["id"] for r in idx["reports"]}, set(ids))
        r = idx["reports"][0]
        self.assertTrue(r["url"].startswith("https://") and r["url"].endswith(f"{r['id']}.html"))
        self.assertIsNone(r["file_size"])
        stats = json.loads((bri.API_REPORTS / "stats.json").read_text())
        self.assertEqual(stats["total_reports"], 23)

    def test_disk_and_published_are_merged_without_duplicates(self):
        self._feed([("intel--new0001", 1), ("intel--old0001", 3)])
        self._disk("intel--new0001")
        self._state({"intel--new0001": self._entry("intel--new0001"),
                     "intel--old0001": self._entry("intel--old0001")})
        idx = self._index()
        self.assertEqual([r["id"] for r in idx["reports"]], ["intel--new0001", "intel--old0001"])
        self.assertIsNotNone(idx["reports"][0]["file_size"])

    def test_unpublished_out_of_window_and_unknown_ids_are_excluded(self):
        self._feed([("intel--staged01", 1), ("intel--aged0001", 30)])
        self._state({
            "intel--staged01": self._entry("intel--staged01", sha=False),  # never PUT
            "intel--aged0001": self._entry("intel--aged0001"),             # outside 24h
            "intel--gone0001": self._entry("intel--gone0001"),             # not in feed
            "intel--badkey01": {"html_key": "../../etc/passwd", "html_sha256": "x"},
        })
        idx = self._index()
        self.assertEqual(idx["total_reports"], 0)
        self.assertIn("empty_state_message", idx)

    def test_missing_or_corrupt_state_is_ignored(self):
        self._feed([("intel--disk0001", 1)])
        self._disk("intel--disk0001")
        self.assertEqual(self._index()["total_reports"], 1)
        bri.PUBLISH_STATE.write_text("{not json")
        self.assertEqual(self._index()["total_reports"], 1)


if __name__ == "__main__":
    unittest.main()
