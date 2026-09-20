import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = readFileSync('scripts/pre-demo-certify.mjs', 'utf8');
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));

test('pre-demo certification hard-blocks SWARM mission dispatch', () => {
  assert.ok(source.includes("const HARD_BLOCKED_PATHS = new Set(["));
  assert.ok(source.includes("'/api/swarm/run'"));
  assert.ok(source.includes('mission-safety violation'));
  assert.ok(source.includes('missionDispatchCount === 0'));
});

test('pre-demo certification allows only the two explicit backend POST canaries', () => {
  assert.ok(source.includes("'/api/intel/correlate'"));
  assert.ok(source.includes("'/api/v1/swarm-synthesis'"));
  assert.ok(source.includes("method !== 'GET' && !SAFE_POST_PATHS.has(url.pathname)"));
});

test('pre-demo certification proves mission history is unchanged before GO', () => {
  assert.ok(source.includes('snapshotMissionIds()'));
  assert.ok(source.includes('mission history changed during pre-demo certification'));
  assert.ok(source.includes('/api/swarm/run calls=0'));
});

test('package scripts expose mission-safe public and full pre-demo gates', () => {
  assert.equal(pkg.scripts['pre-demo:certify'], 'node scripts/pre-demo-certify.mjs');
  assert.equal(pkg.scripts['pre-demo:public'], 'node scripts/pre-demo-certify.mjs --public-only');
  assert.ok(pkg.scripts.test.includes('scripts/pre-demo-certify.contract.test.mjs'));
  assert.ok(pkg.scripts.check.includes('node --check scripts/pre-demo-certify.mjs'));
});
