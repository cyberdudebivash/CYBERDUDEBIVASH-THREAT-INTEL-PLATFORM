import tempfile
import unittest
from pathlib import Path
from agent.global_incidents_store import IncidentStore, RevisionConflict

T = "2026-10-31T12:00:00Z"
URL = "https://example.org/notice"
def event():
    return {"id":"event-1","title":"Reviewed event","category":"breach",
      "status":"confirmed","severity":"high","confidence":"high",
      "first_seen_utc":T,"updated_utc":T,
      "sources":[{"url":URL,"publisher":"CERT","published_at_utc":T,"retrieved_at_utc":T}],
      "claims":[{"text":"Reviewed claim","source_urls":[URL],"verification_state":"confirmed"}]}

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=IncidentStore(str(Path(self.tmp.name)/"events.db"))
    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()
    def test_revision_history(self):
        item=event()
        self.assertEqual(self.store.upsert(item),1)
        self.assertEqual(self.store.upsert(item,expected_revision=1),1)
        item["status"]="resolved"
        self.assertEqual(self.store.upsert(item,expected_revision=1),2)
        self.assertEqual(len(self.store.history(item["id"])),2)
        self.assertEqual(self.store.history(item["id"])[1]["event"]["status"],"confirmed")
    def test_conflict_fails_closed(self):
        item=event()
        self.store.upsert(item)
        item["status"]="resolved"
        with self.assertRaises(RevisionConflict):
            self.store.upsert(item,expected_revision=0)
        self.assertEqual(len(self.store.history(item["id"])),1)
    def test_invalid_evidence_does_not_write(self):
        item=event()
        item["claims"][0]["source_urls"]=["https://other.example/notice"]
        with self.assertRaises(ValueError):
            self.store.upsert(item)
        self.assertEqual(self.store.list_current(),[])

if __name__=="__main__":
    unittest.main()
