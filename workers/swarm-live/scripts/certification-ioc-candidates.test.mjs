import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildCandidatesFromIocCsv,
  normalizeCandidateType,
  parseCsv,
} from './certification-ioc-candidates.mjs';

test('parseCsv handles quoted commas and escaped quotes', () => {
  const rows = parseCsv(
    'ioc_type,ioc_value,source_title\n' +
    'domain,evil.example,"Example, Campaign"\n' +
    'url,"https://bad.example/a?x=1","Quoted ""Title"""\n'
  );
  assert.deepEqual(rows[1], ['domain', 'evil.example', 'Example, Campaign']);
  assert.deepEqual(rows[2], ['url', 'https://bad.example/a?x=1', 'Quoted "Title"']);
});

test('candidate type normalization preserves real threat observable semantics', () => {
  assert.equal(normalizeCandidateType('ip', '8.8.8.8'), 'ipv4');
  assert.equal(normalizeCandidateType('sha256', 'a'.repeat(64)), 'hash');
  assert.equal(normalizeCandidateType('', 'evil.example'), 'domain');
  assert.equal(normalizeCandidateType('', 'https://evil.example/path'), 'url');
});

test('IOC export candidate builder deduplicates and prioritizes structurally rich evidence', () => {
  const csv = [
    'ioc_type,ioc_value,confidence,source_report_id,source_title,cve_id,actor_tag,severity,risk_score,processed_at,kev,epss',
    'domain,weak.example,0.7,report-1,Weak,,,LOW,2.0,2026-09-20,false,0.01',
    'ipv4,203.0.113.44,0.9,report-rich,Rich,CVE-2026-12345,APT42,CRITICAL,9.8,2026-09-20,true,0.91',
    'ip,203.0.113.44,0.8,report-dup,Duplicate,CVE-2026-12345,APT42,HIGH,8.1,2026-09-20,true,0.80',
  ].join('\n');

  const candidates = buildCandidatesFromIocCsv(csv, 10);
  assert.equal(candidates.length, 2);
  assert.equal(candidates[0].value, '203.0.113.44');
  assert.equal(candidates[0].type, 'ipv4');
  assert.equal(candidates[0].report_id, 'report-rich');
  assert.equal(candidates[0].cve_id, 'CVE-2026-12345');
  assert.equal(candidates[0].actor_tag, 'APT42');
  assert.ok(candidates[0].structural_score > candidates[1].structural_score);
});

test('candidate builder fails closed on malformed/non-IOC CSV shapes', () => {
  assert.deepEqual(buildCandidatesFromIocCsv('', 10), []);
  assert.deepEqual(buildCandidatesFromIocCsv('foo,bar\na,b\n', 10), []);
});
