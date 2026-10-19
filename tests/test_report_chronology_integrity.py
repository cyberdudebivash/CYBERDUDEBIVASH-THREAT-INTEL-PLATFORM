"""Offline negative controls for strict release report chronology selection."""
import unittest
from datetime import datetime, timezone

from scripts.report_chronology_integrity import audit_catalog, BASE


def report(hashtext, time, month="10", **extra):
    path = f"/reports/2026/{month}/intel--{hashtext}.html"
    return {"id": f"intel--{hashtext}", "path": path,
            "url": BASE + path, "timestamp": time, **extra}


def catalog(rows, generated_at="2026-10-19T10:00:00Z"):
    return {"generated_at": generated_at, "reports": rows}


class ChronologyTests(unittest.TestCase):
    def test_hash_order_does_not_overrule_publication_time(self):
        old = report("ffffffffffffffff", "2026-10-18T09:00:00Z")
        new = report("0000000000000000", "2026-10-19T09:00:00Z")
        r = audit_catalog(catalog([new, old]), latest_limit=1, history_limit=1)
        self.assertEqual(r["verdict"], "CHRONOLOGY_PRECHECK_ONLY")
        self.assertEqual(r["latest"], [new["url"]])
        self.assertEqual(r["historical"], [old["url"]])
        self.assertFalse(r["delivery_certified"])

    def test_latest_newest_first_and_historical_disjoint(self):
        rows = [report(f"{i:016x}", f"2026-10-19T{(i+1):02d}:00:00Z")
                for i in range(6)]
        result = audit_catalog(catalog(list(reversed(rows))),
                               latest_limit=4, history_limit=5,
                               at=datetime(2026, 10, 19, 10, tzinfo=timezone.utc))
        self.assertEqual(result["verdict"], "CHRONOLOGY_PRECHECK_ONLY")
        self.assertEqual(result["latest"], [r["url"] for r in reversed(rows[-4:])])
        self.assertEqual(result["historical"], [r["url"] for r in rows[:2]])
        self.assertFalse(set(result["latest"]) & set(result["historical"]))

    def test_future_report_fails_closed(self):
        future = report("aaaaaaaaaaaaaaaa", "2026-10-20T08:00:00Z")
        result = audit_catalog(catalog([future]),
                               at=datetime(2026, 10, 19, 10, tzinfo=timezone.utc))
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertEqual(result["latest"], [])
        self.assertTrue(any("future" in x for x in result["defects"]))

    def test_naive_audit_clock_fails_even_without_freshness(self):
        with self.assertRaises(ValueError):
            audit_catalog(catalog([report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00Z")]),
                          at=datetime(2026, 10, 19, 10))

    def test_timestamp_tie_breaks_by_canonical_path(self):
        a = report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00Z")
        b = report("bbbbbbbbbbbbbbbb", "2026-10-19T08:00:00+00:00")
        r = audit_catalog(catalog([b, a]), latest_limit=1)
        self.assertEqual(r["latest"], [b["url"]])

    def test_naive_timestamp_fails_closed_without_probes(self):
        r = audit_catalog(catalog([report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00")]))
        self.assertEqual(r["verdict"], "BLOCKED")
        self.assertEqual(r["latest"], [])
        self.assertIn("explicit-UTC", r["defects"][0])

    def test_duplicate_and_malformed_do_not_enter_samples(self):
        a = report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00Z")
        r = audit_catalog(catalog([a, a]))
        self.assertEqual(r["verdict"], "BLOCKED")
        self.assertEqual(r["latest"], [])
        evil = dict(a, path="/reports/2026/10/../../secret.html")
        self.assertEqual(audit_catalog(catalog([evil]))["verdict"], "BLOCKED")

    def test_forged_host_and_id_fail_closed(self):
        a = report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00Z")
        self.assertEqual(audit_catalog(catalog([dict(a, url="https://evil.invalid/x")]))["verdict"], "BLOCKED")
        self.assertEqual(audit_catalog(catalog([dict(a, id="intel--other")]))["verdict"], "BLOCKED")

    def test_path_month_mismatch_is_not_silently_relabelled(self):
        r = audit_catalog(catalog([report("aaaaaaaaaaaaaaaa", "2026-09-19T08:00:00Z")]))
        self.assertEqual(r["verdict"], "BLOCKED")

    def test_missing_generated_at_blocks_bounded_live_freshness(self):
        r = audit_catalog({"reports": [report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00Z")]},
                          at=datetime(2026, 10, 19, 10, tzinfo=timezone.utc),
                          maximum_age_hours=24)
        self.assertEqual(r["verdict"], "BLOCKED")

    def test_stale_catalog_does_not_claim_live_freshness(self):
        r = audit_catalog(catalog([report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00Z")],
                                  generated_at="2026-10-17T08:00:00Z"),
                          at=datetime(2026, 10, 19, 10, tzinfo=timezone.utc),
                          maximum_age_hours=24)
        self.assertEqual(r["verdict"], "BLOCKED")

    def test_no_report_can_be_declared_delivered_by_chronology_alone(self):
        r = audit_catalog(catalog([report("aaaaaaaaaaaaaaaa", "2026-10-19T08:00:00Z")]))
        self.assertEqual(r["verdict"], "CHRONOLOGY_PRECHECK_ONLY")
        self.assertFalse(r["delivery_certified"])
        self.assertTrue(r["remaining_gates"])

    def test_empty_or_invalid_schema_fails_closed(self):
        for x in ({}, [], {"reports": []}, {"reports": "not-list"}):
            self.assertEqual(audit_catalog(x)["verdict"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
