import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizeMissionDiagnostic } from './mission-diagnostic.mjs';

test('records authentic terminal agent states without altering quality', () => {
  const got = summarizeMissionDiagnostic([
    { agent_id: 'ioc-hunter', event_type: 'agent.started', state: 'RUNNING' },
    { agent_id: 'ioc-hunter', event_type: 'agent.completed', state: 'COMPLETED' },
    { agent_id: 'risk-synthesizer', event_type: 'agent.degraded', state: 'DEGRADED' },
    { agent_id: 'siem-defender', event_type: 'agent.unavailable', state: 'UNAVAILABLE' },
  ], { mission_quality: 'COMPLETED_WITH_WARNINGS', result: { llm_enhanced: false, ai_mode: 'deterministic_fallback' } });
  assert.equal(got.mission_quality, 'COMPLETED_WITH_WARNINGS');
  assert.equal(got.agents['ioc-hunter'], 'COMPLETED');
  assert.equal(got.agents['risk-synthesizer'], 'DEGRADED');
  assert.equal(got.agents['siem-defender'], 'UNAVAILABLE');
  assert.equal(got.agents['attack-mapper'], 'NO_TERMINAL_EVENT');
  assert.equal(got.llm_enhanced, false);
});

test('never discloses credential, IOC, IP, backend error, or result body', () => {
  const secret = 'secret-cdb-enterprise-api-key';
  const ioc = 'sensitive-example.invalid';
  const data = summarizeMissionDiagnostic([
    { agent_id: 'ioc-hunter', event_type: 'agent.completed', state: 'COMPLETED',
      result: { api_key: secret, ioc_value: ioc, tokens: 1200 } },
    { agent_id: 'unknown-injected-agent', event_type: 'agent.failed', state: 'FAILED',
      detail: { error: secret } },
  ], { mission_quality: 'COMPLETED_WITH_WARNINGS', result: {
    llm_enhanced: false, message: secret, ioc_value: ioc, ai_mode: 'deterministic_fallback',
  } });
  assert.doesNotMatch(JSON.stringify(data), new RegExp(secret));
  assert.doesNotMatch(JSON.stringify(data), /sensitive-example\.invalid/);
  assert.equal(Object.hasOwn(data.agents, 'unknown-injected-agent'), false);
  assert.equal(Object.keys(data.agents).length, 8);
});

test('malformed events cannot spoof successful terminal agent states', () => {
  const data = summarizeMissionDiagnostic([
    { agent_id: 'ioc-hunter', event_type: 'agent.started', state: 'COMPLETED' },
    { agent_id: 'cve-intelligence', event_type: 'agent.completed', state: 'BOGUS' },
  ], null);
  assert.equal(data.agents['ioc-hunter'], 'NO_TERMINAL_EVENT');
  assert.equal(data.agents['cve-intelligence'], 'UNKNOWN');
  assert.equal(data.mission_quality, 'MISSING');
});
