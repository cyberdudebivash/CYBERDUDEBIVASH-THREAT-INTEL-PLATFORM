import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { assessOperatorCutover, CRITICAL_CALLERS } from '../../scripts/operator-cutover-preflight.mjs';

const root = fileURLToPath(new URL('../../../../', import.meta.url));
const script = fileURLToPath(new URL('../../scripts/operator-cutover-preflight.mjs', import.meta.url));
const read = path => readFileSync(resolve(root, path), 'utf8');

test('source inventory pins all known critical secret-only revenue caller surfaces', () => {
  assert.equal(CRITICAL_CALLERS.length, 11);
  assert.equal(new Set(CRITICAL_CALLERS.map(x => x.id)).size, 11);
  assert.equal(new Set(CRITICAL_CALLERS.map(x => x.path)).size, 11);
  assert.ok(CRITICAL_CALLERS.some(x => x.id === 'quota_alert_gateway'));
  assert.ok(CRITICAL_CALLERS.some(x => x.id === 'release_readiness_report'));
  assert.ok(CRITICAL_CALLERS.some(x => x.id === 'billing_canary_admin'));
  for (const client of CRITICAL_CALLERS) {
    const source = read(client.path);
    assert.ok(source.includes(client.endpoint), client.id + ': expected route missing');
    assert.ok(source.includes(client.marker), client.id + ': admin credential path missing');
  }
});

test('off source inspection records incompatibilities without claiming Cloudflare activation state', () => {
  const result = assessOperatorCutover('off', read);
  assert.equal(result.ok, true);
  assert.equal(result.state, 'OFF_SOURCE_PREFLIGHT_ONLY');
  assert.equal(result.evaluated, CRITICAL_CALLERS.length);
  assert.ok(result.findings.every(f => f.disposition === 'JWT_MIGRATION_NOT_ATTESTED'));
  assert.match(result.note, /NOT remotely verified/);
  assert.equal(Object.hasOwn(result, 'activated'), false);
});

test('required operator JWT mode is BLOCKED until every legacy caller has genuine migration evidence', () => {
  const result = assessOperatorCutover('required', read);
  assert.equal(result.ok, false);
  assert.equal(result.state, 'CUTOVER_BLOCKED');
  assert.ok(result.findings.some(f => f.id === 'quota_alert_gateway'));
  assert.ok(result.findings.some(f => f.id === 'release_readiness_report'));
  assert.ok(result.findings.some(f => f.id === 'billing_admin_browser'));
});

test('missing evidence or changed source fails even with off target mode', () => {
  const missing = assessOperatorCutover('off', path => {
    if (path === 'workers/intel-gateway/src/index.js') throw new Error('file unavailable');
    return read(path);
  });
  assert.equal(missing.ok, false);
  assert.equal(missing.state, 'INVENTORY_DRIFT');
  assert.equal(missing.findings[0].disposition, 'SOURCE_DRIFT_REVIEW_REQUIRED');
  const invented = assessOperatorCutover('off', () => 'Cf-Access-Jwt-Assertion');
  assert.equal(invented.ok, false, 'a JWT header string alone never proves client migration');
});

test('only explicit valid mode is accepted; missing mode cannot silently become off', () => {
  for (const mode of [undefined, null, '', 'on', 'TRUE', 'false', 'required ', 'audit']) {
    const result = assessOperatorCutover(mode, read);
    assert.equal(result.ok, false);
    assert.equal(result.state, 'INVALID_MODE');
  }
  assert.equal(assessOperatorCutover('off', null).ok, false);
  assert.equal(assessOperatorCutover('off', read, []).ok, false);
});

test('CLI exposes no secrets, accepts off, rejects required and missing argument', () => {
  for (const [args, status] of [[['off'], 0], [['required'], 1], [[], 1]]) {
    const run = spawnSync(process.execPath, [script, ...args], {
      encoding: 'utf8', env: { PATH: process.env.PATH }
    });
    assert.equal(run.status, status, run.stderr);
    assert.ok(!run.stdout.includes('REVENUE_ADMIN_SECRET'), 'never echo credential variable values');
    const parsed = JSON.parse(run.stdout);
    assert.equal(parsed.ok, status === 0);
    if (parsed.findings) assert.equal(parsed.findings.every(f => !('secret' in f)), true);
  }
});
