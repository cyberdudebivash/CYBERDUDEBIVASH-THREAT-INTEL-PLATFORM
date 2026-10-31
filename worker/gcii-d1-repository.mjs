/** GCII Cloudflare D1 read adapter. Mutations remain disabled until verified CAS. */
export class GCIIRevisionConflict extends Error {
  constructor() { super('incident mutation disabled pending verified atomic CAS'); this.name = 'GCIIRevisionConflict'; }
}
export async function saveIncident(_db, _event, _expectedRevision = 0) {
  throw new GCIIRevisionConflict();
}
export async function listIncidents(db, limit = 100) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new RangeError('invalid limit');
  if (!db || typeof db.prepare !== 'function') throw new TypeError('invalid D1 binding');
  const result = await db.prepare('SELECT payload_json FROM gcii_incidents ORDER BY julianday(updated_utc) DESC,id DESC LIMIT ?')
    .bind(limit).all();
  if (!result || !Array.isArray(result.results) || result.results.length > limit) {
    throw new TypeError('invalid D1 query result');
  }
  return result.results.map(row => {
    if (!row || typeof row.payload_json !== 'string' || row.payload_json.length > 65536) {
      throw new TypeError('invalid incident row');
    }
    const incident = JSON.parse(row.payload_json);
    if (!incident || typeof incident !== 'object' || Array.isArray(incident) ||
        typeof incident.id !== 'string' || !incident.id ||
        !Array.isArray(incident.sources) || !Array.isArray(incident.claims)) {
      throw new TypeError('invalid incident payload');
    }
    return incident;
  });
}
