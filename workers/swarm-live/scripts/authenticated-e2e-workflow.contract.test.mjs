import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const workflow = readFileSync('../../.github/workflows/swarm-v4470-authenticated-e2e-cert.yml', 'utf8');

test('authenticated production E2E gate requires full-fabric discovery and completion', () => {
  assert.ok(workflow.includes("SENTINEL_SWARM_DISCOVER_FULL_FABRIC: 'true'"));
  assert.ok(workflow.includes("SENTINEL_SWARM_REQUIRE_FULL_FABRIC: 'true'"));
  assert.ok(workflow.includes("POSTDEMO_REQUIRE_FULL_FABRIC: 'true'"));
  assert.ok(workflow.includes('npm run release:validate:live'));
  assert.ok(workflow.includes('npm run post-demo:certify'));
  assert.ok(workflow.includes("result.mission_quality !== 'FULL_FABRIC_COMPLETE'"));
});

test('temporary production credential is masked and never printed by the workflow', () => {
  assert.ok(workflow.includes("'::add-mask::' + state.raw_key"));
  assert.ok(workflow.includes("'SENTINEL_API_KEY=' + state.raw_key"));
  assert.ok(workflow.includes('Raw credential was not printed.'));
  assert.equal(workflow.includes('echo "$SENTINEL_API_KEY"'), false);
  assert.equal(workflow.includes('echo "${SENTINEL_API_KEY}"'), false);
});

test('credential cleanup is unconditional after key-creation step and uses fail-closed revoke operator', () => {
  assert.ok(workflow.includes("if: always() && steps.demo_key.outcome != 'skipped'"));
  assert.ok(workflow.includes('node scripts/demo-key-operator.mjs revoke'));
  assert.ok(workflow.includes('Credential lifecycle: created -> certified -> revoked'));
});

test('workflow executes regression and Wrangler dry-run before creating production credential state', () => {
  const gate = workflow.indexOf('Static + regression gate before touching production credential state');
  const create = workflow.indexOf('Create short-lived production demo credential');
  assert.ok(gate >= 0 && create > gate);
  const preCreate = workflow.slice(gate, create);
  assert.ok(preCreate.includes('npm run check'));
  assert.ok(preCreate.includes('npm test'));
  assert.ok(preCreate.includes('npm run deploy:dry'));
  assert.ok(preCreate.includes('npm run release:validate'));
});
