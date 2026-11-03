import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { stampProductionSha } from '../../scripts/stamp-release-sha.mjs';
import { healthMatches } from '../../scripts/verify-public-health.mjs';
import { handleRevenueEngineHealth } from '../index.js';

const SHA = 'f'.repeat(40);
const OTHER = 'e'.repeat(40);
const script = fileURLToPath(new URL('../../scripts/stamp-release-sha.mjs', import.meta.url));
const TOML = readFileSync(new URL('../../wrangler.toml', import.meta.url), 'utf8');
const HEALTH = new Request('https://revenue.example.test/api/health');

test('ephemeral named-production SHA insertion is minimal and preserves all route and bindings', () => {
  const stamped = stampProductionSha(TOML, SHA);
  assert.equal(stamped.replace(`ENGINE_RELEASE_SHA = "${SHA}"\n`, ''), TOML);
  assert.match(stamped, new RegExp('\\[env\\.production\\.vars\\]\\nENGINE_RELEASE_SHA = "' + SHA + '"'));
  assert.ok(stamped.includes('ENGINE_VERSION = "183.0"'));
  assert.ok(stamped.includes('[[env.production.d1_databases]]'));
  assert.ok(stamped.includes('[[env.production.kv_namespaces]]'));
  assert.ok(stamped.includes('src/production-entry.js'));
});

test('stamping rejects invalid, repeated or ambiguous release identity before modifying config', () => {
  for (const sha of ['', 'x'.repeat(40), 'A'.repeat(40), SHA.slice(1), SHA + 'f', 42, null]) {
    assert.throws(() => stampProductionSha(TOML, sha));
  }
  const stamped = stampProductionSha(TOML, SHA);
  assert.throws(() => stampProductionSha(stamped, OTHER));
  assert.throws(() => stampProductionSha(stamped, SHA));
  assert.throws(() => stampProductionSha(TOML.replace('[env.production.vars]', '[vars.other]'), SHA));
  assert.throws(() => stampProductionSha(TOML.replace('[env.production.vars]', '[env.production.vars]\n[env.production.vars]'), SHA));
  assert.throws(() => stampProductionSha(TOML.replace('[env.production.vars]\nENGINE_VERSION = "183.0"', '[env.production.vars]'), SHA));
});

test('stamping CLI writes only on valid approval; invalid SHA leaves checked-out TOML intact', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdb-release-sha-'));
  const file = join(dir, 'wrangler.toml');
  try {
    writeFileSync(file, TOML, { mode: 0o600 });
    const bad = spawnSync(process.execPath, [script, 'invalid', file], { encoding: 'utf8' });
    assert.notEqual(bad.status, 0);
    assert.equal(readFileSync(file, 'utf8'), TOML);
    const good = spawnSync(process.execPath, [script, SHA, file], { encoding: 'utf8' });
    assert.equal(good.status, 0, good.stderr);
    assert.equal(readFileSync(file, 'utf8'), stampProductionSha(TOML, SHA));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('public health source SHA claim detects stale route, malformed binding and approved SHA', async () => {
  const env = { ENGINE_RELEASE_SHA: SHA };
  const response = await handleRevenueEngineHealth(HEALTH, env, 'attest_test');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(healthMatches(body, '183.0', SHA), true);
  assert.equal(healthMatches(body, '183.0', OTHER), false);
  assert.equal(healthMatches({ ...body, release_sha: null }, '183.0', SHA), false);
  assert.equal(healthMatches({ ...body, release_sha: SHA.toUpperCase() }, '183.0', SHA), false);
  assert.equal(healthMatches({ ...body, version: '182.0' }, '183.0', SHA), false);
  assert.equal(healthMatches(body, '183.0', 'not-a-sha'), false);
  const missing = await (await handleRevenueEngineHealth(HEALTH, {}, 'attest_test')).json();
  assert.equal(missing.release_sha, null);
  assert.equal(healthMatches(missing, '183.0', SHA), false);
});
