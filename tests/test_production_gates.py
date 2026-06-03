#!/usr/bin/env python3
"""
tests/test_production_gates.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Production Gate Regression Tests (Phase 12)
8 hard gates that must pass before any production deployment.
"""
import json
import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def _load_items(path):
    path = Path(path)
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            for k in ("items","advisories","data"):
                if k in raw and isinstance(raw[k],list):
                    return raw[k]
        return raw if isinstance(raw, list) else []
    except Exception:
        return []

def _parse_ts(ts_str):
    if not ts_str:
        return None
    try:
        normalized = str(ts_str).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


class ProductionGateTests(unittest.TestCase):
    """Production gate regression tests. ALL must pass before push."""

    @classmethod
    def setUpClass(cls):
        cls.api_items = _load_items(REPO_ROOT / "api" / "feed.json")
        cls.root_items = _load_items(REPO_ROOT / "feed.json")
        cls.latest_raw = None
        latest_path = REPO_ROOT / "api" / "latest.json"
        if latest_path.exists():
            try:
                cls.latest_raw = json.loads(latest_path.read_text(encoding="utf-8"))
            except Exception:
                cls.latest_raw = None
        cls.now_utc = datetime.now(timezone.utc)

    def test_no_future_timestamps(self):
        """GATE 1: No item in api/feed.json has published_at > now."""
        future_items = []
        for item in self.api_items:
            pub = item.get("published_at") or item.get("published") or item.get("timestamp")
            if pub:
                dt = _parse_ts(str(pub))
                if dt and dt > self.now_utc:
                    future_items.append({"id": item.get("id","?"), "published_at": pub})
        self.assertEqual(
            len(future_items), 0,
            f"Found {len(future_items)} future-dated items: {future_items[:3]}"
        )

    def test_kev_never_low(self):
        """GATE 2: No item with kev=YES/True has severity=LOW."""
        kev_low = []
        for item in self.api_items:
            kev = item.get("kev") or item.get("kev_present") or item.get("in_kev")
            is_kev = kev and str(kev).upper() in ("TRUE","YES","1")
            sev = (item.get("severity") or "").upper()
            if is_kev and sev == "LOW":
                kev_low.append({"id": item.get("id","?"), "kev": kev, "severity": sev})
        self.assertEqual(
            len(kev_low), 0,
            f"Found {len(kev_low)} KEV items with LOW severity: {kev_low[:3]}"
        )

    def test_required_fields(self):
        """GATE 3: All items in api/feed.json have id, title, severity, published_at."""
        required = ["id","title","severity","published_at"]
        missing_items = []
        for item in self.api_items:
            for f in required:
                if not item.get(f):
                    missing_items.append({"id": item.get("id","?"), "missing": f})
                    break
        self.assertEqual(
            len(missing_items), 0,
            f"Found {len(missing_items)} items missing required fields: {missing_items[:5]}"
        )

    def test_no_duplicate_ids(self):
        """GATE 4: All item IDs in api/feed.json are unique."""
        ids = [item.get("id","") for item in self.api_items if item.get("id")]
        unique_ids = set(ids)
        self.assertEqual(
            len(ids), len(unique_ids),
            f"Found {len(ids)-len(unique_ids)} duplicate IDs in api/feed.json"
        )

    def test_severity_distribution(self):
        """GATE 5: LOW severity < 60% of total (catches 97% LOW regression)."""
        if not self.api_items:
            self.skipTest("api/feed.json has no items")
        sev_counts = {}
        for item in self.api_items:
            s = (item.get("severity") or "UNKNOWN").upper()
            sev_counts[s] = sev_counts.get(s,0)+1
        total = len(self.api_items)
        low_pct = 100 * sev_counts.get("LOW",0) / total
        self.assertLess(
            low_pct, 60.0,
            f"LOW severity {low_pct:.1f}% >= 60% threshold. Distribution: {sev_counts}"
        )

    def test_source_attribution(self):
        """GATE 6: All items in api/feed.json have a source field."""
        missing_source = [item.get("id","?") for item in self.api_items if not item.get("source")]
        self.assertEqual(
            len(missing_source), 0,
            f"Found {len(missing_source)} items without source field: {missing_source[:5]}"
        )

    def test_report_url_latest(self):
        """GATE 7: api/latest.json items have report_url populated."""
        if self.latest_raw is None:
            self.skipTest("api/latest.json not found")
        if isinstance(self.latest_raw, dict):
            items = self.latest_raw.get("data", self.latest_raw.get("items", []))
        else:
            items = self.latest_raw if isinstance(self.latest_raw, list) else []
        if not items:
            self.skipTest("api/latest.json has no items")
        missing_ru = [i.get("id","?") for i in items if not i.get("report_url")]
        self.assertEqual(
            len(missing_ru), 0,
            f"Found {len(missing_ru)}/{len(items)} latest items missing report_url: {missing_ru[:5]}"
        )

    def test_feed_json_valid(self):
        """GATE 8: Feed files parse as valid JSON with items > 0."""
        files_to_check = [
            REPO_ROOT/"api"/"feed.json",
            REPO_ROOT/"feed.json",
            REPO_ROOT/"data"/"feed.json",
        ]
        failures = []
        for fp in files_to_check:
            if not fp.exists():
                failures.append(f"{fp.name}: file not found")
                continue
            try:
                raw = json.loads(fp.read_text(encoding="utf-8"))
                items = _load_items(fp)
                if len(items) == 0:
                    failures.append(f"{fp.name}: 0 items parsed")
            except Exception as e:
                failures.append(f"{fp.name}: JSON parse error: {e}")
        self.assertEqual(
            len(failures), 0,
            f"Feed file failures: {failures}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
