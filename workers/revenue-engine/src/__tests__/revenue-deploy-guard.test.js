import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { healthMatches } from '../../scripts/verify-public-health.mjs';

const script = fileURLToPath(new URL('../../scripts/verify-public-health.mjs', import.meta.url));
const workflow = readFileSync(
  new URL('../../../../.github/workflows/deploy-revenue-engine.yml', import.meta.url), 'utf8'
);
const APPROVED_SHA = 'a'.repeat(40);
const good = { status: 'ok', engine: 'SENTINEL-REVENUE-ENGINE', version: '183.0', release_sha: APPROVED_SHA };

test('release health predicate strictly matches expected service, version and liveness', () => {
  assert.equal(healthMatches(good, '183.0', APPROVED_SHA), true);
  for (const payload of [
    null, [], '', 42, {},
    { ...good, status: 'degraded' },
    { ...good, engine: 'SENTINEL-INTEL-GATEWAY' },
    { ...good, version: '182.0' },
    { ...good, version: 183 },
    { ...good, status: true },
  ]) assert.equal(healthMatches(payload, '183.0', APPROVED_SHA), false);
  assert.equal(healthMatches(good, '183.0+untrusted', APPROVED_SHA), false);
  assert.equal(healthMatches(good, '', APPROVED_SHA), false);
});

test('release health CLI fails closed for non-JSON, wrong version and oversized replies', () => {
  const dir = mkdtempSync(join(tmpdir(), 'cdb-revenue-health-'));
  try {
    const file = join(dir, 'health.json');
    for (const [body, expectedStatus] of [
      [JSON.stringify(good), 0],
      [JSON.stringify({ ...good, version: '182.0' }), 1],
      [JSON.stringify({ ...good, status: 'error' }), 1],
      [JSON.stringify({ ...good, release_sha: 'b'.repeat(40) }), 1],
      [JSON.stringify({ ...good, release_sha: undefined }), 1],
      ['not JSON', 1],
      [JSON.stringify({ ...good, padding: 'x'.repeat(10000) }), 1],
    ]) {
      writeFileSync(file, body, { mode: 0o600 });
      const result = spawnSync(process.execPath, [script, file, '183.0', APPROVED_SHA], { encoding: 'utf8' });
      assert.equal(result.status, expectedStatus, result.stderr);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('production deployment workflow prohibits unnamed fallback and requires explicit SHA', () => {
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /inputs\.approved_commit_sha == github\.sha/);
  const deploy = workflow.slice(
    workflow.indexOf('      - name: "Deploy Worker to approved production environment'),
    workflow.indexOf('      - name: "Post-deploy public health acceptance gate')
  );
  assert.ok(deploy.length > 300, 'production deploy step must be present');
  assert.match(deploy, /wrangler deploy --env production/);
  assert.doesNotMatch(deploy, /wrangler deploy\s*>/);
  assert.doesNotMatch(deploy, /wrangler deploy --env (?:staging|development)/);
  assert.doesNotMatch(deploy, /handle_routes_gap\s*&&\s*exit 0/);
  assert.match(deploy, /exit 1/, 'a failed production deploy must fail closed');
  const health = workflow.slice(
    workflow.indexOf('      - name: "Post-deploy public health acceptance gate'),
    workflow.indexOf('      # S13/S22: commercial go-live verdict')
  );
  assert.ok(health.length > 300, 'required health step must be present');
  assert.doesNotMatch(health, /continue-on-error:\s*true/);
  assert.match(health, /node scripts\/verify-public-health\.mjs/);
  assert.match(health, /"\\$HEALTH_FILE" "\\$EXPECTED_VERSION" "\\$GITHUB_SHA"/);
  assert.match(health, /exit 1/, 'failure to verify live service must block release');
});

test('release executable, mandatory dry-run and bundler are pinned to identical versions', () => {
  const authority = readFileSync(
    new URL('../../../../.github/workflows/revenue-manual-payment-authority-gate.yml', import.meta.url), 'utf8'
  );
  assert.match(workflow, /npm install -g wrangler@3\.114\.17(?:\s|$)/m);
  assert.match(authority, /npx --yes wrangler@3\.114\.17 deploy --env production --dry-run/);
  assert.match(authority, /npx --yes wrangler@4\.127\.0 deploy --env production --dry-run/);
  assert.doesNotMatch(workflow, /npm install -g wrangler@3\s/);
  assert.doesNotMatch(workflow, /npm install -g wrangler@4/);
  assert.match(workflow, /npm install -g esbuild@0\.25\.9(?:\s|$)/m);
  assert.match(authority, /npx --yes esbuild@0\.25\.9 src\/production-entry\.js/);
  const runStep = workflow.slice(
    workflow.indexOf('      - name: "Install pinned production Wrangler'),
    workflow.indexOf('      - name: "Deploy Worker to approved production environment')
  );
  assert.match(runStep, /wrangler --version/);
  assert.doesNotMatch(runStep, /wrangler@latest|wrangler@3\s/);
});

test('approved exact checkout SHA is stamped and dry-run before named production deploy', () => {
  const stamp = workflow.indexOf('      - name: "Stamp and dry-run exact approved production source SHA"');
  const deploy = workflow.indexOf('      - name: "Deploy Worker to approved production environment');
  assert.ok(stamp > 0 && deploy > stamp);
  const preDeploy = workflow.slice(stamp, deploy);
  assert.match(preDeploy, /stamp-release-sha\\.mjs/);
  assert.match(preDeploy, /git rev-parse HEAD/);
  assert.match(preDeploy, /ENGINE_RELEASE_SHA/);
  assert.match(preDeploy, /wrangler deploy --env production --dry-run/);
});
