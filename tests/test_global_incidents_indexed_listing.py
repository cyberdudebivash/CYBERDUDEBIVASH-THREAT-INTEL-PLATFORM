import tempfile
import unittest
from pathlib import Path
from agent.global_incidents_store import IncidentStore

STAMP = "2026-10-31T12:00:00Z"
URL = "https://example.org/report"

def record(identifier, updated):
    return {
        "id": identifier, "title": "Example report", "category": "breach",
        "status": "confirmed", "severity": "medium", "confidence": "high",
        "first_seen_utc": "2026-10-31T10:00:00Z", "updated_utc": updated,
        "sources": [{"url": URL, "publisher": "Example",
                     "published_at_utc": STAMP, "retrieved_at_utc": STAMP}],
        "claims": [{"text": "Example", "source_urls": [URL],
                    "verification_state": "confirmed"}]
    }

class IndexedListingTests(unittest.TestCase):
    def test_bounded_order(self):
        with tempfile.TemporaryDirectory() as directory:
            store = IncidentStore(str(Path(directory) / "events.sqlite"))
            try:
                for i in range(30):
                    store.upsert(record(f"event-{i:02d}", STAMP))
                store.upsert(record("earlier", "2026-10-31T13:00:00+02:00"))
                latest = store.list_current(3)
                self.assertEqual(len(latest), 3)
                self.assertEqual([x["id"] for x in latest],
                                 ["event-29", "event-28", "event-27"])
                plan = store.db.execute(
                    "EXPLAIN QUERY PLAN SELECT payload FROM incidents "
                    "ORDER BY julianday(updated_utc) DESC, id DESC LIMIT 3"
                ).fetchall()
                self.assertTrue(any("idx_incidents_updated_instant" in row[3]
                                    for row in plan), plan)
            finally:
                store.close()

if __name__ == "__main__":
    unittest.main()
