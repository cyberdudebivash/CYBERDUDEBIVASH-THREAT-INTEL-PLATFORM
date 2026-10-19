import assert from 'node:assert/strict';
import { test } from 'node:test';
import { validateWorkerWeeklyCandidate } from '../scripts/check_weekly_worker_contract.mjs';
const NOW = Date.parse('2026-10-19T12:00:00Z');
const doc = () => ({
  _schema:'sentinel-apex-weekly-brief-v1',
  week:'Week 42 2026',period:'12 Oct 2026 — 18 Oct 2026',
  generated_at:'2026-10-19T09:00:00Z',
  stats:{total_advisories:1,critical_count:0,kev_additions:0},
  top_threats:[{id:'intel--test',title:'Verified source-linked advisory',
    tlp:'TLP:CLEAR',source_url:'https://example.org/advisory'}],
});
const encode = d => Buffer.from(JSON.stringify(d),'utf8');

test('current public Week42 candidate accepted by exact Worker predicates',()=>{
  assert.equal(validateWorkerWeeklyCandidate(encode(doc()),NOW).week,'Week 42 2026');
});
test('unclassified advisory is blocked before R2 publication',()=>{
  const d=doc(); delete d.top_threats[0].tlp;
  assert.throws(()=>validateWorkerWeeklyCandidate(encode(d),NOW),/TLP_DENIED/);
});
test('restricted advisory is blocked before R2 publication',()=>{
  const d=doc(); d.top_threats[0].tlp='TLP:AMBER';
  assert.throws(()=>validateWorkerWeeklyCandidate(encode(d),NOW),/TLP_DENIED/);
});
test('wrong weekly date, old generation, or malformed JSON fail closed',()=>{
  const d=doc();d.week='Week 43 2026';
  assert.throws(()=>validateWorkerWeeklyCandidate(encode(d),NOW),/STALE_OR_INVALID/);
  d.week='Week 42 2026';d.generated_at='2026-08-25T00:00:00Z';
  assert.throws(()=>validateWorkerWeeklyCandidate(encode(d),NOW),/STALE_OR_INVALID/);
  assert.throws(()=>validateWorkerWeeklyCandidate(Buffer.from('{'),NOW),/INVALID_JSON/);
});
test('oversize object is blocked independently of source classifications',()=>{
  const d=doc();d.description='x'.repeat(1024*1024);
  assert.throws(()=>validateWorkerWeeklyCandidate(encode(d),NOW),/BODY_SIZE/);
});
