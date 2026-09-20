import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  MISSION_PROFILES,
  listMissionProfiles,
  normalizeMissionProfile,
  profileIncludesAgent,
  resolveMissionProfile,
} from '../mission-profiles.js';

test('AUTO and FULL_CTI_FABRIC preserve the eight-agent default', () => {
  assert.equal(MISSION_PROFILES.AUTO.agents.length, 8);
  assert.equal(MISSION_PROFILES.FULL_CTI_FABRIC.agents.length, 8);
});

test('focused profiles always retain IOC Hunter and Risk Synthesizer', () => {
  for (const profile of listMissionProfiles()) {
    assert.ok(profile.agents.includes('ioc-hunter'), profile.id);
    assert.ok(profile.agents.includes('risk-synthesizer'), profile.id);
  }
});

test('profile normalization is strict and rejects unknown values', () => {
  assert.equal(normalizeMissionProfile('cve-response'), 'CVE_RESPONSE');
  assert.equal(normalizeMissionProfile('incident response'), 'INCIDENT_RESPONSE');
  assert.equal(normalizeMissionProfile('made-up-profile'), null);
});

test('profile membership is explicit', () => {
  const profile = resolveMissionProfile('SOC_DETECTION_ENGINEERING');
  assert.equal(profileIncludesAgent(profile, 'siem-defender'), true);
  assert.equal(profileIncludesAgent(profile, 'cve-intelligence'), false);
});
