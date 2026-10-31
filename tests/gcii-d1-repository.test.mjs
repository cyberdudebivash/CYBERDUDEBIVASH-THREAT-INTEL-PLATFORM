import { test } from 'node:test';
import assert from 'node:assert/strict';
import { saveIncident, listIncidents, GCIIRevisionConflict } from '../worker/gcii-d1-repository.mjs';

test('all D1 mutation requests fail closed without touching DB', async () => {
  let touched = false;
  const db = { prepare() { touched = true; throw Error('unexpected DB access'); } };
  await assert.rejects(saveIncident(db, {id:'i'}, 0), GCIIRevisionConflict);
  await assert.rejects(saveIncident(db, {id:'i'}, 1), GCIIRevisionConflict);
  assert.equal(touched, false);
});
test('D1 list enforces bounded queries', async () => {
  await assert.rejects(listIncidents({}, 501), RangeError);
  await assert.rejects(listIncidents({}, 0), RangeError);
});
test('D1 list rejects malformed row payloads', async () => {
  const db = {prepare() {return {bind() {return {async all() {return {results:[{payload_json:'[]'}]};}};}};}};
  await assert.rejects(listIncidents(db), TypeError);
});
test('D1 list returns valid stored incidents', async () => {
  const incident = {id:'a', sources:[], claims:[]};
  const db = {prepare() {return {bind() {return {async all() {return {results:[{payload_json:JSON.stringify(incident)}]};}};}};}};
  assert.deepEqual(await listIncidents(db), [incident]);
});
