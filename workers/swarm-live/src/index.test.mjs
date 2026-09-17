import test from 'node:test';
import assert from 'node:assert/strict';
import { __test, buildSentinelSpecialistResults } from './index.js';
import {
  buildMissionReport,
  missionSummary,
  sanitizeForCustomer,
  validateMissionInput,
} from './enterprise.js';

test('specialist catalog is complete and unique', () => {
  assert.equal(__test.AGENTS.length, 8);
  assert.equal(new Set(__test.AGENTS.map((a) => a.id)).size, 8);
  assert.ok(__test.AGENTS.some((a) => a.id === 'risk-synthesizer'));
});

test('specialist results are derived from canonical CTI only', () => {
  const result = buildSentinelSpecialistResults({
    ioc: '8.8.8.8',
    verdict: 'malicious',
    recommendation: 'block',
    matches: [
      { report_id: 'r1', cve_id: 'CVE-2026-0001', actor_tag: 'APT-X', severity: 'critical', risk_score: 9.8, ttps: [{ technique_id: 'T1059' }] },
      { report_id: 'r2', cve_id: 'CVE-2026-0001', actor_tag: 'APT-X', severity: 'high', risk_score: 8.1, ttps: ['T1105'] },
    ],
  });
  assert.equal(result['ioc-hunter'].verdict, 'malicious');
  assert.deepEqual(result['cve-intelligence'].cves, ['CVE-2026-0001']);
  assert.deepEqual(result['threat-hunter'].actors, ['APT-X']);
  assert.deepEqual(result['attack-mapper'].techniques, ['T1059', 'T1105']);
  assert.equal(result['risk-synthesizer'].max_risk_score, 9.8);
});

test('mission input validation is fail closed', () => {
  assert.equal(validateMissionInput(null), 'invalid_request');
  assert.equal(validateMissionInput({}), 'ioc_value_required');
  assert.equal(validateMissionInput({ ioc_value: 'x'.repeat(257) }), 'ioc_value_too_long');
  assert.equal(validateMissionInput({ ioc_value: '8.8.8.8', ioc_type: 7 }), 'invalid_ioc_type');
  assert.equal(validateMissionInput({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }), null);
});

test('customer sanitizer redacts credential-shaped fields recursively', () => {
  const safe = sanitizeForCustomer({
    verdict: 'malicious',
    api_key: 'secret-value',
    nested: { authorization: 'Bearer x', token: 'x', useful: 'ok' },
  });
  assert.equal(safe.verdict, 'malicious');
  assert.equal(safe.api_key, '[REDACTED]');
  assert.equal(safe.nested.authorization, '[REDACTED]');
  assert.equal(safe.nested.token, '[REDACTED]');
  assert.equal(safe.nested.useful, 'ok');
});

test('mission summary uses real event state and results', () => {
  const events = [
    { mission_id: 'm1', correlation_id: 'c1', execution_id: 'e1', sequence: 1, timestamp: '2026-09-17T00:00:00Z', state: 'QUEUED', event_type: 'mission.accepted' },
    { mission_id: 'm1', correlation_id: 'c1', execution_id: 'e1', sequence: 2, timestamp: '2026-09-17T00:00:01Z', state: 'RUNNING', event_type: 'agent.started', agent_id: 'ioc-hunter', agent_name: 'IOC Hunter', capability: 'ioc.correlation' },
    { mission_id: 'm1', correlation_id: 'c1', execution_id: 'e1', sequence: 3, timestamp: '2026-09-17T00:00:02Z', state: 'COMPLETED', event_type: 'agent.completed', agent_id: 'ioc-hunter', agent_name: 'IOC Hunter', capability: 'ioc.correlation', result: { verdict: 'clean' } },
    { mission_id: 'm1', correlation_id: 'c1', execution_id: 'e1', sequence: 4, timestamp: '2026-09-17T00:00:03Z', state: 'COMPLETED', event_type: 'mission.completed', mesh_certified: true, mesh_execution_id: 'mesh-1', result: { verdict: 'clean' } },
  ];
  const summary = missionSummary(events);
  assert.equal(summary.mission_id, 'm1');
  assert.equal(summary.mesh_certified, true);
  assert.equal(summary.agents[0].state, 'COMPLETED');
  assert.deepEqual(summary.agents[0].result, { verdict: 'clean' });
});

test('mission report excludes secrets and carries release evidence', () => {
  const report = buildMissionReport({ mission_id: 'm1', api_key: 'should-not-leak', mesh_certified: true });
  assert.equal(report.report_schema, 'cdb.swarm.report.v1');
  assert.equal(report.api_key, '[REDACTED]');
  assert.equal(report.mesh_certified, true);
});

test('auth helper does not invent authentication', () => {
  const none = __test.authHeaders(new Request('https://example.test/'));
  assert.equal(__test.hasAuth(none), false);
  const req = new Request('https://example.test/', { headers: { 'x-api-key': 'abc' } });
  const headers = __test.authHeaders(req);
  assert.equal(__test.hasAuth(headers), true);
  assert.equal(headers.get('x-api-key'), 'abc');
});

test('safe request id accepts bounded safe IDs and replaces unsafe IDs', () => {
  const safe = __test.safeRequestId(new Request('https://example.test/', { headers: { 'x-request-id': 'cdb-test-123' } }));
  assert.equal(safe, 'cdb-test-123');
  const unsafe = __test.safeRequestId(new Request('https://example.test/', { headers: { 'x-request-id': '../../bad id' } }));
  assert.match(unsafe, /^sentinel-swarm-/);
});
