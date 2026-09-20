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

test('pre-demo certification allows only the three explicit non-mission POST canaries', () => {
  assert.ok(source.includes("'/api/swarm/readiness'"));
  assert.ok(source.includes("'/api/intel/correlate'"));
  assert.ok(source.includes("'/api/v1/swarm-synthesis'"));
  assert.ok(source.includes("method !== 'GET' && !SAFE_POST_PATHS.has(url.pathname)"));
});

test('pre-demo GO report identity comes from the selected candidate correlation', () => {
  assert.ok(source.includes("const correlationPlan = buildDependencyCandidates(correlation)"));
  assert.ok(source.includes("demoCandidate.reportId = correlatedReportIds[0]"));
  assert.ok(source.includes("DEMO REPORT"));
  assert.ok(source.includes("candidate.reportId || 'UNRESOLVED'"));
});

test('pre-demo certification proves mission history is unchanged before GO', () => {
  assert.ok(source.includes('snapshotMissionIds()'));
  assert.ok(source.includes('mission history changed during pre-demo certification'));
  assert.ok(source.includes('/api/swarm/run calls=0'));
});

test('public-only certification can never emit the final live-mission authorization', () => {
  assert.ok(source.includes("if (publicOnly)"));
  assert.ok(source.includes('PUBLIC-ONLY PASS — public production surfaces are certified.'));
  assert.ok(source.includes('the live SWARM mission is NOT authorized'));
  const publicBlockStart = source.indexOf('if (publicOnly)');
  const fullGo = source.indexOf('PRE-MISSION GO — 100% OF THE PRE-MISSION ACCEPTANCE MATRIX PASSED.', publicBlockStart);
  const publicReturn = source.indexOf('return;', publicBlockStart);
  assert.ok(publicReturn > publicBlockStart && publicReturn < fullGo);
});

test('public certification distinguishes malformed mission ids from valid-shaped unauthenticated ids', () => {
  assert.ok(source.includes('/api/swarm/mission/bad%20mission%20id'));
  assert.ok(source.includes("invalid.body?.error === 'invalid_mission_id'"));
  assert.ok(source.includes('/api/swarm/mission/sentinel-mission-probe'));
  assert.ok(source.includes("unauthenticatedValidId.body?.error === 'authentication_required'"));
  assert.equal(source.includes('/api/swarm/mission/not-a-valid-mission-id'), false);
});

test('full pre-demo certification requires explicit physical mobile sign-off', () => {
  assert.ok(source.includes('PREDEMO_MOBILE_VISUAL_SIGNOFF'));
  assert.ok(source.includes('physical mobile sign-off missing'));
  assert.ok(source.includes('no horizontal page overflow/cutoff'));
  assert.ok(source.includes('all 8 agent cards reachable'));
});

test('package scripts expose mission-safe public and full pre-demo gates', () => {
  assert.equal(pkg.scripts['pre-demo:certify'], 'node scripts/pre-demo-certify.mjs');
  assert.equal(pkg.scripts['pre-demo:public'], 'node scripts/pre-demo-certify.mjs --public-only');
  assert.equal(pkg.scripts['post-demo:certify'], 'node scripts/post-demo-certify.mjs');
  assert.ok(pkg.scripts.test.includes('scripts/pre-demo-certify.contract.test.mjs'));
  assert.ok(pkg.scripts.test.includes('scripts/post-demo-certify.contract.test.mjs'));
  assert.ok(pkg.scripts.check.includes('node --check scripts/pre-demo-certify.mjs'));
});
