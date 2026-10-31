import json
import tempfile
import unittest
from pathlib import Path
from agent.global_incidents_publish import publish
from agent.global_incidents import IncidentValidationError

STAMP = "2026-10-31T12:00:00Z"
URL = "https://example.org/advisory"

def incident():
    return {
        "id":"test-event", "title":"Test incident", "category":"breach",
        "first_seen_utc":STAMP, "updated_utc":STAMP,
        "status":"confirmed", "severity":"high", "confidence":"high",
        "sources":[{"url":URL,"publisher":"Test CERT",
                    "published_at_utc":STAMP,"retrieved_at_utc":STAMP}],
        "claims":[{"text":"Test claim","source_urls":[URL],
                   "verification_state":"confirmed"}]
    }

class PublisherTests(unittest.TestCase):
    def test_atomic_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/"reviewed.json"
            output=root/"feed.json"
            source.write_text(json.dumps([incident()]),encoding="utf-8")
            result=publish(str(source),str(output))
            data=json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(result["count"],1)
            self.assertEqual(data["schema"],"cdb.global-incidents.v1")
            self.assertEqual(result["sha256"],data["sha256"])
    def test_invalid_does_not_replace_last_known_good(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/"reviewed.json"
            output=root/"feed.json"
            output.write_text('{"existing":true}',encoding="utf-8")
            bad=incident()
            bad["claims"][0]["source_urls"]=["https://not-in-sources.example"]
            source.write_text(json.dumps([bad]),encoding="utf-8")
            with self.assertRaises(IncidentValidationError):
                publish(str(source),str(output))
            self.assertEqual(output.read_text(encoding="utf-8"),'{"existing":true}')
    def test_missing_parent_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/"reviewed.json"
            source.write_text("[]",encoding="utf-8")
            with self.assertRaises(IncidentValidationError):
                publish(str(source),str(root/"missing"/"feed.json"))

if __name__ == "__main__":
    unittest.main()
