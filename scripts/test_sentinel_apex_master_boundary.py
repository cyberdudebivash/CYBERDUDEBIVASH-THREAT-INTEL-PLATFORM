import unittest
from datetime import datetime, timezone
from pathlib import Path

from sentinel_apex_master_boundary import activation_status, freshness_from_feed, publication_decision, stage_page

ENV = {
    "SENTINEL_APEX_AI_INTEL": "1",
    "SENTINEL_APEX_AI_INTEL_BASE_URL": "https://ai-intel.example",
}
NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
FEED = {"generated_at": "2026-10-10T12:00:00Z", "generation": "public-feed-2026-10-10T12:00:00Z"}
PAGE = {
    "schema": "sentinel-apex.intel.v1",
    "tlp": "CLEAR",
    "next_cursor": 4,
    "records": [{
        "id": "CVE-2026-1",
        "primary_source_id": "cisa-kev",
        "canonical_source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "source_published_at": "2026-10-08T00:00:00.000Z",
        "cvss_score": 9.8,
        "kev_status": True,
        "evidence": [
            {"source_id": "cisa-kev", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "claim": "listed"},
            {"source_id": "unattributed", "url": "https://example.invalid/n", "claim": "unknown"},
        ],
    }],
}


class BoundaryTest(unittest.TestCase):
    def test_flag_off_does_not_stage(self):
        result = stage_page({}, {"cursor": 2, "records": {}}, PAGE, feed=FEED, now=NOW)
        self.assertEqual(result["status"], "NOT_CONFIGURED")
        self.assertEqual(result["state"]["cursor"], 2)
        self.assertFalse(result["public_feed_write"])
        self.assertEqual(result["release"], "NOT_AUTHORIZED")

    def test_contract_keeps_provenance_and_still_does_not_publish(self):
        result = stage_page(ENV, {"cursor": 0, "records": {}}, PAGE, feed=FEED, now=NOW)
        self.assertEqual(result["status"], "CONTRACT_VERIFIED")
        self.assertEqual(result["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")
        self.assertEqual(result["freshness_observation"], "fresh")
        self.assertIsNone(result["freshness_bound_to"])
        self.assertEqual(result["release"], "NOT_AUTHORIZED")
        self.assertFalse(result["customer_visible"])
        row = result["state"]["records"]["CVE-2026-1"]
        self.assertEqual(row["primary_source_id"], "cisa-kev")
        self.assertEqual(row["cvss_score"], 9.8)
        self.assertEqual(row["source_published_at"], "2026-10-08T00:00:00.000Z")
        self.assertEqual(row["corroborating_source_ids"], ["cisa-kev"])
        self.assertEqual(row["evidence"][1]["source_id"], "unresolved")
        self.assertFalse((Path(__file__).resolve().parents[1] / "api" / "feed.json").exists())

    def test_a_caller_supplied_fresh_label_cannot_authorize_release(self):
        labeled = stage_page(ENV, {"cursor": 0, "records": {}}, PAGE, feed="FRESH", now=NOW)
        self.assertEqual(labeled["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")
        self.assertEqual(labeled["release"], "NOT_AUTHORIZED")
        self.assertEqual(freshness_from_feed("FRESH")["state"], "unbound")
        self.assertEqual(publication_decision(None, {"state": "fresh"}), "BLOCKED_BY_FRESHNESS_GATE")
        forged = publication_decision(None, {"state": "fresh", "bound_to": FEED["generated_at"], "generation": FEED["generation"]}, {"manifest": "forged"})
        self.assertEqual(forged, "BLOCKED_BY_FRESHNESS_GATE")
        forged_page = stage_page(ENV, {"cursor": 0, "records": {}}, PAGE, feed=FEED, now=NOW)
        self.assertEqual(forged_page["freshness_observation"], "fresh")
        self.assertEqual(forged_page["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")
        self.assertEqual(forged_page["release"], "NOT_AUTHORIZED")
        different = stage_page(ENV, {"cursor": 0, "records": {}}, {**PAGE, "records": []}, feed=FEED, now=NOW)
        self.assertEqual(different["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")
        replay = stage_page(ENV, {"cursor": 4, "records": {}}, {**PAGE, "next_cursor": 4}, feed=FEED, now=NOW)
        self.assertEqual(replay["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")
        self.assertEqual(replay["release"], "NOT_AUTHORIZED")
        stale = stage_page(ENV, {"cursor": 0, "records": {}}, PAGE, feed={"generated_at": "2020-01-01T00:00:00Z", "generation": "old"}, now=NOW)
        self.assertEqual(stale["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")
        restricted = stage_page(ENV, {"cursor": 5, "records": {}}, {**PAGE, "tlp": "AMBER"}, feed=FEED, now=NOW)
        self.assertEqual(restricted["status"], "FAILED")
        self.assertEqual(restricted["state"]["cursor"], 5)
        self.assertEqual(activation_status({"SENTINEL_APEX_AI_INTEL": "1", "SENTINEL_APEX_AI_INTEL_BASE_URL": "http://insecure"})["status"], "FAILED")
        cached = freshness_from_feed({"state": "fresh", "bound_to": FEED["generated_at"]}, now=NOW)
        self.assertEqual(cached["state"], "unbound")
        mismatched = freshness_from_feed({**FEED, "state": "fresh", "generated_at": "2020-01-01T00:00:00Z", "generation": "public-feed-2020-01-01T00:00:00Z"}, now=NOW)
        self.assertEqual(mismatched["state"], "unbound")
        other = freshness_from_feed({"generated_at": FEED["generated_at"], "generation": "other-product"}, now=NOW)
        self.assertEqual(other["state"], "unbound")
        future = stage_page(ENV, {"cursor": 1, "records": {}}, PAGE, feed={"generated_at": "2027-01-01T00:00:00Z", "generation": "public-feed-2027-01-01T00:00:00Z"}, now=NOW)
        self.assertEqual(future["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")
        self.assertEqual(future["release"], "NOT_AUTHORIZED")
        missing = stage_page(ENV, {"cursor": 1, "records": {}}, PAGE, feed={"generation": "public-feed-"}, now=NOW)
        self.assertEqual(missing["freshness_decision"], "BLOCKED_BY_FRESHNESS_GATE")


if __name__ == "__main__":
    unittest.main()
