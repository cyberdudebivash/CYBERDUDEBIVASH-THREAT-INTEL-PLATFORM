-- GCII v1 additive migration. Apply only to a dedicated D1 database after review.
-- Existing production tables are not modified.
CREATE TABLE IF NOT EXISTS gcii_incidents (
  id TEXT PRIMARY KEY NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  status TEXT NOT NULL CHECK (status IN ('investigating','confirmed','disputed','resolved')),
  updated_utc TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json))
);
CREATE TABLE IF NOT EXISTS gcii_revisions (
  incident_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision >= 1),
  saved_at_utc TEXT NOT NULL,
  payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
  PRIMARY KEY (incident_id, revision),
  FOREIGN KEY (incident_id) REFERENCES gcii_incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_gcii_incidents_updated ON gcii_incidents(julianday(updated_utc) DESC, id DESC);
