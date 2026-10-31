/**
 * GCII D1 repository for Cloudflare Workers.
 * Caller must validate the incident against the shared GCII v1 contract.
 * A single D1 batch commits current state and immutable revision together.
 * No automatic publication or network access.
 */
export class GCIIRevisionConflict extends Error {
  constructor() { super('incident revision conflict'); this.name = 'GCIIRevisionConflict'; }
}
export async function saveIncident(db, event, expectedRevision = 0) {
  if (!db || !event || typeof event.id !== 'string' || !event.id ||
      !Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new TypeError('invalid save request');
  }
  const id = event.id;
  const current = await db.prepare('SELECT revision, payload_json, updated_utc FROM gcii_incidents WHERE id = ?')
    .bind(id).first();
  const payload = JSON.stringify(event);
  if (current && current.revision !== expectedRevision) throw new GCIIRevisionConflict();
  if (!current && expectedRevision !== 0) throw new GCIIRevisionConflict();
  if (current && event.updated_utc < current.updated_utc) throw new GCIIRevisionConflict();
  if (current && JSON.stringify(JSON.parse(current.payload_json)) === payload) return current.revision;
  const revision = expectedRevision + 1;
  const savedAt = new Date().toISOString();
  const statements = [];
  if (current) {
    statements.push(db.prepare('UPDATE gcii_incidents SET revision=?, status=?, updated_utc=?, payload_json=? WHERE id=? AND revision=?')
      .bind(revision, event.status, event.updated_utc, payload, id, expectedRevision));
  } else {
    statements.push(db.prepare('INSERT INTO gcii_incidents (id,revision,status,updated_utc,payload_json) VALUES (?,?,?,?,?)')
      .bind(id, revision, event.status, event.updated_utc, payload));
  }
  statements.push(db.prepare('INSERT INTO gcii_revisions (incident_id,revision,saved_at_utc,payload_json) VALUES (?,?,?,?)')
    .bind(id, revision, savedAt, payload));
  // D1 batch alone does not provide an application-level compare-and-swap guarantee.\n  // Keep writes disabled until a transactional, verified CAS path is implemented.\n  throw new GCIIRevisionConflict();
}
export async function listIncidents(db, limit = 100) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new RangeError('invalid limit');
  const result = await db.prepare('SELECT payload_json FROM gcii_incidents ORDER BY updated_utc DESC,id LIMIT ?')
    .bind(limit).all();
  return (result.results || []).map(row => JSON.parse(row.payload_json));
}
