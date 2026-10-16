#!/usr/bin/env python3
"""
tests/test_field_preserving_merge_canonical_key.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Report Continuity: Canonical Manifest Key Guard

P0.2 INCIDENT (2026-08-22): scripts/field_preserving_merge.py's _load_manifest()
searched a dict-shaped manifest for one of ("data", "items", "entries", "intel")
-- but never "advisories", the canonical envelope key used by every other
manifest reader/writer in the pipeline (validate_reports.py, report_generator.py,
manifest_reconciler.py, report_existence_validator.py, sync_report_urls.py).

Production evidence (run 32570451251, job 97025064853): STAGE 3.1.5 logged
"[merge] Loaded existing manifest: 0 items from feed_manifest.json (fmt=dict)"
against a manifest that actually held 1115 items under "advisories". Because
_load_manifest() couldn't find a recognised key, run_merge() treated the
manifest as empty, merged only the ~500-item incoming api/feed.json batch, and
_atomic_write() -- independently re-deriving a key via the same broken list --
fell through to injecting a brand-new "data" key. The real "advisories" list
was left completely untouched (frozen, stale) while every downstream script
that reads "advisories" first (which is nearly everything) kept operating on
whatever content was there before this step ever ran -- exactly the kind of
inconsistent, unverified carry-forward that produces dangling report_url
entries over time.

This exact symptom class ("field_preserving_merge.py writes under 'data' by
default") is independently documented as a prior incident and defensively
worked around in ioc_quality_hardener.py, validate_reports.py,
report_generator.py, enterprise_scoring_engine.py, and
api_dashboard_contract_validator.py -- but the writer itself was never fixed.

FIX: _load_manifest() now checks "advisories" first (matching the canonical
order used everywhere else) and returns the matched key; _atomic_write() now
requires that exact key instead of independently re-deriving one. Read and
write are now guaranteed to target the same key within a single invocation.

These tests lock in that contract directly against the module's public
functions (run_merge, merge_preserving_fields, sync_apex_ai_from_feed) and via
subprocess against the exact CLI invocations sentinel-apex.yml's STAGE
3.1.5 and STAGE 3.1.6 now use, so this cannot silently regress.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("CDB_JWT_SECRET", "pytest-dummy-secret-not-for-production")

import scripts.field_preserving_merge as fpm  # noqa: E402

SCRIPT = REPO_ROOT / "scripts" / "field_preserving_merge.py"


class TestCanonicalKeyRecognition(unittest.TestCase):
    """_load_manifest() must recognise "advisories" -- not silently read a
    populated dict manifest as empty."""

    def test_advisories_keyed_manifest_is_not_read_as_empty(self):
        with tempfile.TemporaryDirectory() as td:
            manifest_path = Path(td) / "feed_manifest.json"
            items = [{"stix_id": f"intel--x{i:03d}", "title": f"Item {i}"} for i in range(10)]
            manifest_path.write_text(json.dumps({"advisories": items}), encoding="utf-8")

            existing, fmt, raw_data, matched_key = fpm._load_manifest(manifest_path)
            self.assertEqual(len(existing), 10, "advisories-keyed manifest must not read as empty")
            self.assertEqual(fmt, "dict")
            self.assertEqual(matched_key, "advisories")

    def test_advisories_checked_before_legacy_keys(self):
        """If a manifest somehow carries both a real "advisories" list and a
        legacy "data" key (e.g. mid-migration), "advisories" must win --
        it's what every other script in the pipeline reads."""
        with tempfile.TemporaryDirectory() as td:
            manifest_path = Path(td) / "feed_manifest.json"
            real_items = [{"stix_id": "intel--real"}]
            stale_items = [{"stix_id": "intel--stale-orphan"}]
            manifest_path.write_text(
                json.dumps({"advisories": real_items, "data": stale_items}), encoding="utf-8"
            )
            existing, fmt, raw_data, matched_key = fpm._load_manifest(manifest_path)
            self.assertEqual(matched_key, "advisories")
            self.assertEqual([it["stix_id"] for it in existing], ["intel--real"])


class TestWriteBackTargetsSameKeyAsRead(unittest.TestCase):
    """_atomic_write() must never orphan updates into a different key than
    the one items were read from -- that mismatch is the entire bug class."""

    def test_advisories_manifest_round_trips_through_advisories(self):
        with tempfile.TemporaryDirectory() as td:
            manifest_path = Path(td) / "feed_manifest.json"
            items = [{"stix_id": f"intel--x{i:03d}", "title": f"Item {i}"} for i in range(5)]
            manifest_path.write_text(json.dumps({"advisories": items}), encoding="utf-8")

            fpm.run_merge(manifest_path, incoming_path=None, cap=0)

            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIn("advisories", data)
            self.assertEqual(len(data["advisories"]), 5)
            self.assertNotIn("data", data,
                              "write-back must never create a new 'data' key alongside 'advisories'")

    def test_legacy_data_keyed_manifest_round_trips_through_data(self):
        """A manifest genuinely shaped with a legacy "data" key (no
        "advisories" present at all) must still round-trip through "data" --
        this fix adds "advisories" priority, it does not remove support for
        the other historically-recognised shapes."""
        with tempfile.TemporaryDirectory() as td:
            manifest_path = Path(td) / "feed_manifest.json"
            items = [{"stix_id": f"intel--x{i:03d}"} for i in range(3)]
            manifest_path.write_text(json.dumps({"data": items}), encoding="utf-8")

            fpm.run_merge(manifest_path, incoming_path=None, cap=0)

            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIn("data", data)
            self.assertEqual(len(data["data"]), 3)
            self.assertNotIn("advisories", data)


class TestProductionIncidentReproduction(unittest.TestCase):
    """Exact reproduction of the production sequence from run 32570451251:
    STAGE 3.1.5 (--sync-apex --incoming api/feed.json) immediately followed
    by STAGE 3.1.6 (--incoming api/feed.json --cap 5000), starting from a
    real ~1100-item "advisories" manifest with a smaller overlapping
    api/feed.json batch. Before the fix, this sequence silently collapsed
    "advisories" -- err, orphaned a "data" key -- while report_url values
    already-validated against real files sat frozen and increasingly
    disconnected from what every other pipeline stage was producing."""

    def test_sync_apex_then_merge_preserves_full_manifest_under_advisories(self):
        existing_items = [
            {
                "stix_id": f"intel--existing-{i:04d}", "id": f"intel--existing-{i:04d}",
                "title": f"Existing advisory {i}",
                "report_url": f"/reports/2026/08/intel--existing-{i:04d}.html",
                "apex_ai": {"ai_summary": "pre-existing enrichment"},
                "risk_score": 5.0, "timestamp": "2026-08-20T00:00:00Z",
            }
            for i in range(1115)
        ]
        incoming_items = [
            {
                "stix_id": f"intel--existing-{i:04d}", "id": f"intel--existing-{i:04d}",
                "title": f"Existing advisory {i}", "report_url": "",
                "risk_score": 5.0, "timestamp": "2026-08-20T00:00:00Z",
            }
            for i in range(615, 1115)
        ] + [
            {
                "stix_id": f"intel--new-{i:04d}", "id": f"intel--new-{i:04d}",
                "title": f"Brand new advisory {i}", "report_url": "",
                "risk_score": 6.0, "timestamp": "2026-08-22T00:00:00Z",
            }
            for i in range(15)
        ]

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            manifest_path = td / "feed_manifest.json"
            feed_path = td / "feed.json"
            manifest_path.write_text(json.dumps({"advisories": existing_items}), encoding="utf-8")
            feed_path.write_text(json.dumps(incoming_items), encoding="utf-8")

            # STAGE 3.1.5 equivalent
            fpm.run_merge(manifest_path, feed_path, cap=5000)
            fpm.sync_apex_ai_from_feed(manifest_path, feed_path)

            after_315 = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertNotIn("data", after_315,
                              "STAGE 3.1.5 must not orphan an updated key into 'data'")
            self.assertGreaterEqual(len(after_315["advisories"]), 1115,
                                     "STAGE 3.1.5 must never shrink the manifest below what already existed")

            # STAGE 3.1.6 equivalent
            fpm.run_merge(manifest_path, feed_path, cap=5000)

            final = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertNotIn("data", final)
            self.assertEqual(len(final["advisories"]), 1130,
                              "expected 1115 existing + 15 genuinely new items")

            by_id = {it["stix_id"]: it for it in final["advisories"]}
            preserved = by_id["intel--existing-0000"]
            self.assertEqual(
                preserved["report_url"], "/reports/2026/08/intel--existing-0000.html",
                "an already-materialized report_url must survive the sync+merge sequence unchanged",
            )
            self.assertEqual(
                preserved["apex_ai"]["ai_summary"], "pre-existing enrichment",
                "protected-field preservation must still work once 'advisories' is read correctly",
            )

    def test_cli_invocation_matches_stage_3_1_5_and_3_1_6_exactly(self):
        """Subprocess-level proof against the exact CLI flags sentinel-apex.yml
        now uses for STAGE 3.1.5 and STAGE 3.1.6, not a re-implementation of
        their logic."""
        existing_items = [
            {"stix_id": f"intel--e{i:03d}", "title": f"E{i}",
             "report_url": f"/reports/2026/08/intel--e{i:03d}.html",
             "timestamp": "2026-08-20T00:00:00Z"}
            for i in range(120)
        ]
        incoming_items = [
            {"stix_id": f"intel--e{i:03d}", "title": f"E{i}", "report_url": "",
             "timestamp": "2026-08-20T00:00:00Z"}
            for i in range(100, 120)
        ] + [
            {"stix_id": f"intel--n{i:03d}", "title": f"N{i}", "report_url": "",
             "timestamp": "2026-08-22T00:00:00Z"}
            for i in range(5)
        ]

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            manifest_path = td / "feed_manifest.json"
            feed_path = td / "feed.json"
            manifest_path.write_text(json.dumps({"advisories": existing_items}), encoding="utf-8")
            feed_path.write_text(json.dumps(incoming_items), encoding="utf-8")

            r1 = subprocess.run(
                [sys.executable, str(SCRIPT), "--sync-apex",
                 "--manifest", str(manifest_path), "--incoming", str(feed_path),
                 "--feed", str(feed_path), "--cap", "5000"],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(r1.returncode, 0, r1.stderr)

            r2 = subprocess.run(
                [sys.executable, str(SCRIPT),
                 "--manifest", str(manifest_path), "--incoming", str(feed_path),
                 "--cap", "5000"],
                cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(r2.returncode, 0, r2.stderr)

            final = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertNotIn("data", final, "CLI invocation must not orphan a 'data' key")
            self.assertEqual(len(final["advisories"]), 125, "120 existing + 5 new")


if __name__ == "__main__":
    unittest.main()
