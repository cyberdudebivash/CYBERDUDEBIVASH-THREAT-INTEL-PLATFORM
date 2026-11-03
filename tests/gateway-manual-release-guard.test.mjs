import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const workflow = readFileSync(new URL('../.github/workflows/deploy-worker.yml', import.meta.url), 'utf8');
const trigger = workflow.slice(workflow.indexOf('\non:\n'), workflow.indexOf('\npermissions:'));
const concurrency = workflow.slice(workflow.indexOf('\nconcurrency:'), workflow.indexOf('\njobs:'));
const guard = workflow.indexOf('Confirm approved SHA is still main HEAD immediately before production write');
const deploy = workflow.indexOf('Deploy Worker to Cloudflare (production only)');
const post = workflow.indexOf('Post-deploy smoke test (version + exact commit assertion)');
const deploymentBlock = workflow.slice(deploy, post);

test('P0 gateway release can only be dispatched manually with an explicit SHA input', () => {
  assert.match(trigger, /on:\s*\n\s*workflow_dispatch:\s*\n\s*inputs:\s*\n\s*approved_commit_sha:/);
  assert.match(trigger, /approved_commit_sha:[\s\S]*required:\s*true/);
  assert.doesNotMatch(trigger, /^\s+push:/m, 'code merges must NOT silently deploy gateway');
  assert.doesNotMatch(trigger, /^\s+schedule:/m);
  assert.doesNotMatch(trigger, /^\s+workflow_run:/m);
  assert.match(workflow, /github\.event_name == 'workflow_dispatch'/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /inputs\.approved_commit_sha == github\.sha/);
});

test('running production upload cannot be canceled before exact-source health verification', () => {
  assert.match(concurrency, /group:\s*worker-deploy/);
  assert.match(concurrency, /cancel-in-progress:\s*false/);
  assert.doesNotMatch(concurrency, /cancel-in-progress:\s*true/);
});

test('guard verifies exact current main and approved checkout immediately before production write', () => {
  assert.ok(guard > 0 && deploy > guard && post > deploy);
  const prewrite = workflow.slice(guard, deploy);
  assert.match(prewrite, /set -euo pipefail/);
  assert.match(prewrite, /GITHUB_SHA/);
  assert.match(prewrite, /APPROVED_RELEASE_SHA/);
  assert.match(prewrite, /git rev-parse HEAD/);
  assert.match(prewrite, /git ls-remote --exit-code origin refs\/heads\/main/);
  assert.match(prewrite, /CURRENT_MAIN/);
  assert.match(prewrite, /exit 1/, 'unverified main must stop the release');
  assert.doesNotMatch(prewrite, /\|\| true/, 'main lookup must fail closed');
  assert.match(workflow, /APPROVED_RELEASE_SHA: \$\{\{\s*inputs\.approved_commit_sha\s*\}\}/);
});

test('live upload uses only the named production environment and never falls back to default', () => {
  assert.match(deploymentBlock, /wrangler deploy --env production/);
  assert.equal((deploymentBlock.match(/wrangler deploy --env production/g) || []).length, 1);
  assert.doesNotMatch(deploymentBlock, /wrangler deploy\s*>/, 'no bare default-env deployment');
  assert.doesNotMatch(deploymentBlock, /wrangler deploy\s*$/, 'no default env deployment');
  assert.doesNotMatch(deploymentBlock, /Deploy successful \(default env\)/);
  assert.match(deploymentBlock, /FATAL: named production deploy failed/);
});

test('routes-permission exception remains subordinate to exact public deployment SHA validation', () => {
  assert.match(deploymentBlock, /PROVISIONAL ROUTE-ONLY RESULT/);
  const smoke = workflow.slice(post);
  assert.match(smoke, /https:\/\/intel\.cyberdudebivash\.com\/api\/health\/live/);
  assert.match(smoke, /deploy_commit_sha/);
  assert.match(smoke, /GITHUB_SHA/);
  assert.match(smoke, /FATAL: public route did not converge to GITHUB_SHA/);
  assert.match(smoke, /exit 1/);
});

test('no deployment-relevant step allows push to main as implicit authorization', () => {
  const jobSection = workflow.slice(workflow.indexOf('\njobs:'), workflow.indexOf('    steps:'));
  assert.doesNotMatch(jobSection, /github\.event_name == 'push'/);
  assert.doesNotMatch(jobSection, /\|\|\s*\(github\.event_name/);
});
