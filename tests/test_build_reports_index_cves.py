"""Reports catalog entries carry the CVE IDs of their feed item.

Live 2026-09-27: all 12 entries in /api/reports/latest.json had "cve": []
while their feed items carried CVEs -- build_reports_index.py read
feed_item["cve"], a key the feed never writes (it uses cve_id / cve_ids /
cves). The homepage REPORTS grid therefore never showed a CVE, including on
a KEV-flagged report.
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


class ItemCvesTest(unittest.TestCase):
    def test_reads_every_structured_field(self):
        self.assertEqual(bri._item_cves({"cve_id": "CVE-2026-35273"}), ["CVE-2026-35273"])
        self.assertEqual(bri._item_cves({"cve_ids": ["CVE-2026-1", "CVE-2026-10001"]}), ["CVE-2026-10001"])
        self.assertEqual(bri._item_cves({"cves": ["cve-2024-3094"]}), ["CVE-2024-3094"])
        self.assertEqual(bri._item_cves({"cve": "CVE-2021-44228"}), ["CVE-2021-44228"])  # legacy key

    def test_dedupes_in_first_seen_order_and_drops_junk(self):
        item = {"cve": ["CVE-2025-0001"], "cves": ["CVE-2025-0002", "cve-2025-0001"],
                "cve_ids": ["CVE-2025-0002", None, "", "N/A", 7], "cve_id": "CVE-2025-0003"}
        self.assertEqual(bri._item_cves(item), ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"])

    def test_no_cve_fields(self):
        self.assertEqual(bri._item_cves({}), [])
        self.assertEqual(bri._item_cves({"cve_id": None, "cves": None}), [])


class CatalogCarriesCvesTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self._orig = (bri.REPORTS_ROOT, bri.API_FEED, bri.API_REPORTS, bri.PUBLISH_STATE)
        bri.REPORTS_ROOT = root / "reports"
        bri.API_FEED = root / "api" / "feed.json"
        bri.API_REPORTS = root / "api" / "reports"
        bri.PUBLISH_STATE = root / "data" / "cache" / "r2_report_publish_state.json"
        bri.API_FEED.parent.mkdir(parents=True)
        recent = datetime.now(timezone.utc) - timedelta(hours=1)
        d = bri.REPORTS_ROOT / recent.strftime("%Y") / recent.strftime("%m")
        d.mkdir(parents=True)
        ts = recent.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Shape of a live feed item: cve_id + cve_ids, no "cve" key.
        items = [
            {"id": "intel--kev00001", "title": "CISA adds WordPress flaw to KEV", "severity": "CRITICAL",
             "timestamp": ts, "cve_id": "CVE-2026-35273", "cve_ids": ["CVE-2026-35273"], "kev_present": True},
            {"id": "intel--nocve001", "title": "Phishing campaign", "severity": "HIGH", "timestamp": ts},
        ]
        bri.API_FEED.write_text(json.dumps(items))
        for i in items:
            (d / f"{i['id']}.html").write_text("<html>" + "x" * 600 + "</html>")

    def tearDown(self):
        bri.REPORTS_ROOT, bri.API_FEED, bri.API_REPORTS, bri.PUBLISH_STATE = self._orig
        self._tmp.cleanup()

    def test_index_and_latest_list_the_items_cves(self):
        self.assertEqual(bri.main(), 0)
        for name in ("index.json", "latest.json"):
            data = json.loads((bri.API_REPORTS / name).read_text())
            by_id = {r["id"]: r for r in data["reports"]}
            self.assertEqual(by_id["intel--kev00001"]["cve"], ["CVE-2026-35273"], name)
            self.assertTrue(by_id["intel--kev00001"]["kev_present"], name)
            self.assertEqual(by_id["intel--nocve001"]["cve"], [], name)


if __name__ == "__main__":
    unittest.main()
