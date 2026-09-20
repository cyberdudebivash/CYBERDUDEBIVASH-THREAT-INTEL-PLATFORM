import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = readFileSync('scripts/post-demo-certify.mjs', 'utf8');

test('post-demo certification is read-only and hard-blocks SWARM dispatch', () => {
  assert.ok(source.includes("const HARD_BLOCKED_PATHS = new Set(['/api/swarm/run'])"));
  assert.ok(source.includes("if (method !== 'GET')"));
  assert.ok(source.includes('missionDispatchCount === 0'));
  assert.equal(/fetch\([^\n]*\/api\/swarm\/run/.test(source), false);
});

test('post-demo certification requires durable quality provenance history and exports', () => {
  for (const marker of [
    'owned durable mission read-back',
    'FULL_FABRIC_COMPLETE',
    'cdb.swarm.evidence-graph.v1',
    'mission history contains filmed mission',
    'Markdown evidence export',
    'JSON evidence export',
    'STIX 2.1 evidence export',
  ]) {
    assert.ok(source.includes(marker), marker);
  }
});
