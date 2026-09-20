import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const source = readFileSync('scripts/release-validate.mjs', 'utf8');

test('authenticated release validation discovers real candidates from the paid IOC export before canonical readiness', () => {
  assert.ok(source.includes('async function discoverFullFabricCandidate'));
  assert.ok(source.includes('/api/export/csv?limit='));
  assert.ok(source.includes("accept: 'text/csv'"));
  assert.ok(source.includes('buildCandidatesFromIocCsv'));
  assert.ok(source.includes('/api/swarm/readiness'));
  assert.ok(source.includes("mission_quality === 'FULL_FABRIC'"));
  assert.ok(source.includes('ready_agents) === 8'));
  assert.ok(source.includes('synthesis_readiness?.ready === true'));
  assert.ok(source.includes('demo_recommended === true'));
  assert.equal(source.includes("candidate feed is empty"), false);
});

test('strict production E2E mode requires full-fabric completion and LLM synthesis', () => {
  assert.ok(source.includes('SENTINEL_SWARM_REQUIRE_FULL_FABRIC'));
  assert.ok(source.includes("terminal.mission_quality === 'FULL_FABRIC_COMPLETE'"));
  assert.ok(source.includes('terminal.result?.llm_enhanced === true'));
});

test('live validator emits only non-secret mission identity as its result artifact', () => {
  assert.ok(source.includes('SENTINEL_SWARM_RESULT_PATH'));
  assert.ok(source.includes('mission_id: terminal.mission_id'));
  assert.ok(source.includes('execution_id: terminal.execution_id'));
  assert.ok(source.includes('correlation_id: terminal.correlation_id'));
  assert.ok(source.includes('mission_quality: terminal.mission_quality'));
  assert.equal(source.includes('apiKey:'), false);
  assert.equal(source.includes('SENTINEL_API_KEY: process.env'), false);
});
