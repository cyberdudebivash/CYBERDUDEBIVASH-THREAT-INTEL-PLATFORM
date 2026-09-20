import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  AGENT_STATES,
  MISSION_QUALITY,
  buildDependencyCandidates,
  buildMissionReadiness,
  classifyMissionCompletion,
  normalizeAgentState,
} from '../mission-readiness.js';
import { adaptSpecialistResponse } from '../specialist-contract.js';

const richCorrelation = {
  status: 'ok',
  verdict: 'malicious',
  match_count: 2,
  ioc: { value: 'evil.example', type: 'domain' },
  matches: [
    {
      report_id: 'intel--one',
      cve_id: 'CVE-2026-10001',
      actor_tag: 'APT-X',
      risk_score: 9,
      ttps: [{ technique_id: 'T1059' }, { technique_id: 'T1078' }],
    },
    {
      report_id: 'intel--two',
      cve_id: 'CVE-2026-10002',
      actor_tag: 'APT-Y',
      risk_score: 8,
      ttps: ['T1566'],
    },
  ],
};

test('dependency planner preserves ordered unique evidence candidates', () => {
  const plan = buildDependencyCandidates(richCorrelation);
  assert.deepEqual(plan['cve-intelligence'], ['CVE-2026-10001', 'CVE-2026-10002']);
  assert.deepEqual(plan['threat-hunter'], ['APT-X', 'APT-Y']);
  assert.deepEqual(plan['attack-mapper'], ['T1059', 'T1078', 'T1566']);
  assert.deepEqual(plan['siem-defender'], ['intel--one', 'intel--two']);
});

test('absent quota telemetry is unknown and never interpreted as exhausted', () => {
  const readiness = buildMissionReadiness(richCorrelation, {
    entitlementEligible: true,
    llmReady: true,
  });
  assert.equal(readiness.status, 'ready');
  assert.equal(readiness.quota_remaining, null);
  assert.equal(readiness.mission_quality, MISSION_QUALITY.FULL_FABRIC);
});

test('explicit zero quota blocks readiness', () => {
  const readiness = buildMissionReadiness(richCorrelation, {
    entitlementEligible: true,
    quotaRemaining: 0,
    llmReady: true,
  });
  assert.equal(readiness.status, 'blocked');
  assert.equal(readiness.mission_quality, MISSION_QUALITY.BLOCKED);
  assert.equal(readiness.quota_remaining, 0);
});

test('rich correlation + ready LLM projects FULL_FABRIC 8/8', () => {
  const readiness = buildMissionReadiness(richCorrelation, {
    entitlementEligible: true,
    quotaRemaining: 49999,
    llmReady: true,
    llmProviders: ['deepseek'],
  });
  assert.equal(readiness.status, 'ready');
  assert.equal(readiness.mission_quality, MISSION_QUALITY.FULL_FABRIC);
  assert.equal(readiness.ready_agents, 8);
  assert.equal(readiness.specialist_ready, 6);
  assert.equal(readiness.llm_ready, true);
});

test('no-match correlation is truthful NO_MATCH with six NOT_APPLICABLE agents', () => {
  const readiness = buildMissionReadiness({
    status: 'ok',
    verdict: 'clean',
    match_count: 0,
    ioc: { value: '8.8.8.8', type: 'ipv4' },
    matches: [],
  }, { llmReady: false, entitlementEligible: true, quotaRemaining: 10 });

  assert.equal(readiness.mission_quality, MISSION_QUALITY.NO_MATCH);
  assert.equal(readiness.specialist_ready, 0);
  for (const id of [
    'cve-intelligence','threat-hunter','attack-mapper',
    'siem-defender','ir-playbook','exposure-analyst'
  ]) {
    assert.equal(readiness.agents[id].state, AGENT_STATES.NOT_APPLICABLE);
  }
  assert.equal(readiness.agents['risk-synthesizer'].state, AGENT_STATES.DEGRADED);
});

test('focused mission profile projects PROFILE_READY and marks excluded agents explicitly', () => {
  const expected = [
    'ioc-hunter',
    'attack-mapper',
    'siem-defender',
    'risk-synthesizer',
  ];
  const readiness = buildMissionReadiness(richCorrelation, {
    entitlementEligible: true,
    quotaRemaining: 100,
    llmReady: true,
    expectedAgentIds: expected,
  });

  assert.equal(readiness.mission_quality, MISSION_QUALITY.PROFILE_READY);
  assert.equal(readiness.total_agents, 4);
  assert.equal(readiness.ready_agents, 4);
  assert.equal(readiness.fleet_agents, 8);
  assert.equal(readiness.agents['cve-intelligence'].state, AGENT_STATES.NOT_APPLICABLE);
  assert.equal(readiness.agents['cve-intelligence'].reason, 'mission_profile_excluded');
});

test('legacy SKIPPED evidence normalizes to NOT_APPLICABLE', () => {
  assert.equal(normalizeAgentState('SKIPPED'), AGENT_STATES.NOT_APPLICABLE);
});

test('mission quality differentiates full, partial, no-match and AI-degraded completion', () => {
  const completed = Object.fromEntries([
    'ioc-hunter','cve-intelligence','threat-hunter','attack-mapper',
    'siem-defender','ir-playbook','exposure-analyst','risk-synthesizer'
  ].map((id) => [id, { state: 'COMPLETED' }]));

  assert.equal(
    classifyMissionCompletion(completed, { match_count: 2, llm_enhanced: true }),
    MISSION_QUALITY.FULL_FABRIC_COMPLETE
  );
  assert.equal(
    classifyMissionCompletion(completed, { match_count: 2, llm_enhanced: false }),
    MISSION_QUALITY.AI_DEGRADED_COMPLETE
  );

  const degradedSynth = {
    ...completed,
    'risk-synthesizer': { state: 'DEGRADED' },
  };
  assert.equal(
    classifyMissionCompletion(degradedSynth, { match_count: 2, llm_enhanced: false }),
    MISSION_QUALITY.AI_DEGRADED_COMPLETE
  );

  const partial = { ...completed, 'cve-intelligence': { state: 'NOT_APPLICABLE' } };
  assert.equal(
    classifyMissionCompletion(partial, { match_count: 1, llm_enhanced: true }),
    MISSION_QUALITY.PARTIAL_FABRIC_COMPLETE
  );

  assert.equal(
    classifyMissionCompletion(completed, { match_count: 0, llm_enhanced: false }),
    MISSION_QUALITY.NO_MATCH_COMPLETE
  );
});

test('specialist adapters normalize heterogeneous gateway response envelopes', () => {
  const cve = adaptSpecialistResponse('cve-intelligence', {
    status: 'ok', data: { cves: [{ cve_id: 'CVE-2026-1' }] }
  });
  assert.equal(cve.success, true);
  assert.equal(cve.substantive, true);
  assert.equal(cve.count, 1);
  assert.equal(cve.data.cves[0].cve_id, 'CVE-2026-1');

  const detection = adaptSpecialistResponse('siem-defender', {
    schema_version: '1.0.0',
    data: [{ artifact_type: 'sigma' }],
    pagination: { total: 1 },
  });
  assert.equal(detection.success, true);
  assert.equal(detection.schema, 'detection-registry-v1');
  assert.equal(detection.substantive, true);

  const emptyDetection = adaptSpecialistResponse('siem-defender', {
    schema_version: '1.0.0',
    data: [],
    pagination: { total: 0 },
  });
  assert.equal(emptyDetection.success, true);
  assert.equal(emptyDetection.substantive, false);
});
