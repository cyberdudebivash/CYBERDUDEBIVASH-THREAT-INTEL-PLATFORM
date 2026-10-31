import { test } from 'node:test';
import assert from 'node:assert/strict';
import { saveIncident, listIncidents, GCIIRevisionConflict } from '../worker/gcii-d1-repository.mjs';

test('D1 mutation fails closed even when current row exists', async () => {
  let writes = 0;
  const db = {
    prepare(sql) {
      return {
        bind() {
          return {
            async first() { return {revision: 1, payload_json: '{"id":"incident-1"}', updated_utc: '2026-10-31T00:00:00Z'}; },
            async all() { return {results: []}; }
          };
        }
      };
    },
    async batch() { writes += 1; }
  };
  await assert.rejects(saveIncident(db, {id:'incident-1', status:'resolved', updated_utc:'2026-10-31T01:00:00Z'}, 1), GCIIRevisionConflict);
  assert.equal(writes, 0);
});
test('D1 list enforces bounded queries', async () => {
  await assert.rejects(listIncidents({}, 501), RangeError);
  await assert.rejects(listIncidents({}, 0), RangeError);
});
