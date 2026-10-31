import unittest
from datetime import datetime, timezone
from agent.global_incidents import build_feed, IncidentValidationError

NOW = "2026-10-31T12:00:00Z"
URL = "https://example.org/advisory"
def sample():
    return {"id":"event-1","title":"Verified example incident","category":"breach",
        "first_seen_utc":NOW,"updated_utc":NOW,"status":"confirmed",
        "severity":"critical","confidence":"high",
        "sources":[{"url":URL,"publisher":"Example CERT","published_at_utc":NOW,"retrieved_at_utc":NOW}],
        "claims":[{"text":"An incident occurred","source_urls":[URL],"verification_state":"confirmed"}]}

class GlobalIncidentTests(unittest.TestCase):
    def test_valid_feed(self):
        result = build_feed([sample()], generated_at=NOW)
        self.assertEqual(result["schema"], "cdb.global-incidents.v1")
        self.assertEqual(len(result["sha256"]), 64)
    def test_deterministic_digest(self):
        self.assertEqual(build_feed([sample()], NOW), build_feed([sample()], NOW))
    def test_unverified_confirmed_rejected(self):
        item = sample()
        item["claims"][0]["verification_state"] = "reported"
        with self.assertRaises(IncidentValidationError): build_feed([item], NOW)
    def test_unattributed_claim_rejected(self):
        item = sample()
        item["claims"][0]["source_urls"] = ["https://unknown.example/a"]
        with self.assertRaises(IncidentValidationError): build_feed([item], NOW)
    def test_insecure_source_rejected(self):
        item = sample()
        item["sources"][0]["url"] = "http://example.org/advisory"
        with self.assertRaises(IncidentValidationError): build_feed([item], NOW)
    def test_duplicate_incident_rejected(self):
        with self.assertRaises(IncidentValidationError): build_feed([sample(), sample()], NOW)
    def test_naive_timestamp_rejected(self):
        item = sample()
        item["updated_utc"] = "2026-10-31T12:00:00"
        with self.assertRaises(IncidentValidationError): build_feed([item], NOW)
    def test_mixed_timezone_ordering(self):
        early = sample()
        early["id"] = "early"
        early["first_seen_utc"] = "2026-10-31T10:00:00Z"
        early["updated_utc"] = "2026-10-31T13:00:00+02:00"
        late = sample()
        late["id"] = "late"
        late["updated_utc"] = "2026-10-31T12:00:00Z"
        self.assertEqual([i["id"] for i in build_feed([early, late], NOW)["incidents"]], ["late", "early"])
    def test_bad_status_rejected(self):
        item = sample()
        item["status"] = "definitely-hacked"
        with self.assertRaises(IncidentValidationError): build_feed([item], NOW)

if __name__ == "__main__":
    unittest.main()
