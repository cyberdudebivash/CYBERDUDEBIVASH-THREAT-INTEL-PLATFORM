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
  assert.equal(data.mission_quality, 'UNKNOWN');
});

test('failed specialists emit only bounded HTTP code and allowlisted error code', () => {
  const data = summarizeMissionDiagnostic([
    { agent_id:'ir-playbook', event_type:'agent.failed', state:'FAILED',
      detail:{ error:'report_not_found', message:'REDACT_CANARY_SOURCE' },
      attempted_candidates:[{ candidate:'REDACT_CANARY_MATCH', http_status:404 }] },
    { agent_id:'exposure-analyst', event_type:'agent.failed', state:'FAILED',
      detail:{ error:'exposure_analysis_failed' },
      attempted_candidates:[{ candidate:'REDACT_CANARY_ITEM', http_status:500 }] },
  ], { mission_quality:'COMPLETED_WITH_WARNINGS', result:{llm_enhanced:true} });
  assert.deepEqual(data.failures['ir-playbook'], {
    state:'FAILED', http_status:404, error_code:'report_not_found'
  });
  assert.deepEqual(data.failures['exposure-analyst'], {
    state:'FAILED', http_status:500, error_code:'exposure_analysis_failed'
  });
  assert.doesNotMatch(JSON.stringify(data), /REDACT_CANARY/);
});

test('unrecognized failure causes, status strings and injected payloads are not reflected', () => {
  const data = summarizeMissionDiagnostic([
    { agent_id:'ir-playbook', event_type:'agent.failed', state:'FAILED',
      detail:{error:'REDACT_CANARY_UNRECOGNIZED'},
      attempted_candidates:[{candidate:'REDACT_CANARY', http_status:'404'}] },
  ], { mission_quality:'REDACT_CANARY_INVALID', result:{llm_enhanced:false} });
  assert.deepEqual(data.failures['ir-playbook'], {
    state:'FAILED', http_status:null, error_code:null
  });
  assert.equal(data.mission_quality, 'UNKNOWN');
  assert.doesNotMatch(JSON.stringify(data), /REDACT_CANARY/);
});

test('successful retry clears prior failure and does not invent failure evidence', () => {
  const data = summarizeMissionDiagnostic([
    { agent_id:'ir-playbook', event_type:'agent.failed', state:'FAILED',
      attempted_candidates:[{http_status:404}] },
    { agent_id:'ir-playbook', event_type:'agent.completed', state:'COMPLETED' },
  ], {mission_quality:'FULL_FABRIC_COMPLETE', result:{llm_enhanced:true}});
  assert.equal(data.agents['ir-playbook'], 'COMPLETED');
  assert.deepEqual(data.failures, {});
  assert.equal(data.mission_quality, 'FULL_FABRIC_COMPLETE');
});
