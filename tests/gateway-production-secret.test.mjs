import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { hasRequiredGatewayJwtSecret } from '../scripts/verify-gateway-production-secret.mjs';

const script = fileURLToPath(new URL('../scripts/verify-gateway-production-secret.mjs', import.meta.url));
const present = JSON.stringify([
  { name: 'CDB_JWT_SECRET', type: 'secret_text' },
  { name: 'SYNTHETIC_OTHER', type: 'secret_text' },
]);
const missing = JSON.stringify([{ name: 'SYNTHETIC_OTHER', type: 'secret_text' }]);

test('exact named production JWT secret metadata is the only success case', () => {
  assert.equal(hasRequiredGatewayJwtSecret(present), true);
  assert.equal(hasRequiredGatewayJwtSecret(JSON.stringify([{ name: 'CDB_JWT_SECRET' }])), true);
  for (const raw of [missing, '[]', '{}', '{"name":"CDB_JWT_SECRET"}',
    '[{"name":"CDB_JWT_SECRET_backup"}]',
    '[{"name":"cdb_jwt_secret"}]', 'not-json', '', null, undefined, 'x'.repeat(65537)]) {
    assert.equal(hasRequiredGatewayJwtSecret(raw), false);
  }
});

test('malformed and false-positive secret listings fail closed', () => {
  assert.equal(hasRequiredGatewayJwtSecret('[null,42,"CDB_JWT_SECRET",{"name":"other"}]'), false);
  assert.equal(hasRequiredGatewayJwtSecret(JSON.stringify(Array.from(
    {length: 513}, () => ({name: 'CDB_JWT_SECRET'})
  ))), false);
});

test('CLI reports status only and NEVER reflects any input secret metadata', () => {
  for (const [payload, exit] of [[present, 0], [missing, 1], ['permission denied', 1]]) {
    const run = spawnSync(process.execPath, [script], {
      input: payload, encoding: 'utf8',
    });
    assert.equal(run.status, exit, run.stderr);
    const output = run.stdout + run.stderr;
    assert.equal(output.includes('SYNTHETIC_OTHER'), false);
    assert.equal(output.includes('"name"'), false);
    assert.equal(output.includes('"type"'), false);
    assert.equal(output.includes('permission denied'), false);
  }
});

test('named-production secret preflight is hard-fail and has no default-env fallback', async () => {
  const { readFileSync } = await import('node:fs');
  const flow = readFileSync(new URL('../.github/workflows/deploy-worker.yml', import.meta.url), 'utf8');
  const start = flow.indexOf('GATE — Verify named-production CDB_JWT_SECRET presence (HARD FAIL)');
  const end = flow.indexOf('Confirm approved SHA is still main HEAD immediately before production write', start);
  assert.ok(start > 0 && end > start);
  const gate = flow.slice(start, end);
  assert.match(gate, /set -euo pipefail/);
  assert.match(gate, /npx wrangler secret list --env production/);
  assert.match(gate, /verify-gateway-production-secret\.mjs/);
  assert.match(gate, /exit 1/);
  assert.doesNotMatch(gate, /npx wrangler secret list\s+2>/);
  assert.doesNotMatch(gate, /echo "\$SECRET_LIST"/);
  assert.doesNotMatch(gate, /Proceeding with deploy/);
});
