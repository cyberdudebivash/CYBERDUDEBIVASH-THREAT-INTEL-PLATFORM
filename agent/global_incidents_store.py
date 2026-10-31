"""Fail-closed, single-writer GCII revision store (stdlib SQLite).

Store only reviewed events. Existing incident revisions are immutable.
No network, automatic attribution, or production side effects.
"""
from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from agent.global_incidents import validate_incident, IncidentValidationError

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS incidents (
 id TEXT PRIMARY KEY,
 revision INTEGER NOT NULL CHECK(revision >= 1),
 status TEXT NOT NULL,
 updated_utc TEXT NOT NULL,
 payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS revisions (
 id TEXT NOT NULL,
 revision INTEGER NOT NULL,
 saved_at_utc TEXT NOT NULL,
 payload TEXT NOT NULL,
 PRIMARY KEY (id, revision),
 FOREIGN KEY (id) REFERENCES incidents(id)
);
"""
class RevisionConflict(IncidentValidationError):
    pass

class IncidentStore:
    def __init__(self, path):
        self.path = Path(path)
        if not self.path.parent.is_dir():
            raise IncidentValidationError("database directory missing")
        self.db = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    def close(self):
        self.db.close()

    def upsert(self, event, expected_revision=None):
        validate_incident(event)
        data = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        identifier = event["id"]
        now = datetime.now(timezone.utc).isoformat()
        try:
            self.db.execute("BEGIN IMMEDIATE")
            current = self.db.execute("SELECT revision, payload, updated_utc FROM incidents WHERE id=?", (identifier,)).fetchone()
            if current:
                revision, previous, previous_updated = current
                if expected_revision != revision:
                    raise RevisionConflict("revision mismatch")
                if event["updated_utc"] < previous_updated:
                    raise RevisionConflict("stale incident update")
                if previous == data:
                    self.db.execute("COMMIT")
                    return revision
                next_revision = revision + 1
                self.db.execute("UPDATE incidents SET revision=?,status=?,updated_utc=?,payload=? WHERE id=?",
                                (next_revision,event["status"],event["updated_utc"],data,identifier))
            else:
                if expected_revision not in (None, 0):
                    raise RevisionConflict("new incident revision mismatch")
                next_revision = 1
                self.db.execute("INSERT INTO incidents(id,revision,status,updated_utc,payload) VALUES(?,?,?,?,?)",
                                (identifier,next_revision,event["status"],event["updated_utc"],data))
            self.db.execute("INSERT INTO revisions(id,revision,saved_at_utc,payload) VALUES(?,?,?,?)",
                            (identifier,next_revision,now,data))
            self.db.execute("COMMIT")
            return next_revision
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def list_current(self, limit=500):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 500:
            raise IncidentValidationError("invalid limit")
        rows = self.db.execute("SELECT payload FROM incidents ORDER BY updated_utc DESC,id LIMIT ?", (limit,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def history(self, identifier, limit=100):
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise IncidentValidationError("invalid limit")
        rows = self.db.execute("SELECT revision,saved_at_utc,payload FROM revisions WHERE id=? ORDER BY revision DESC LIMIT ?",
                               (identifier,limit)).fetchall()
        return [{"revision":row[0],"saved_at_utc":row[1],"event":json.loads(row[2])} for row in rows]
