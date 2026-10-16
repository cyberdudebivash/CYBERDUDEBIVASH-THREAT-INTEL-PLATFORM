import test from 'node:test';
import assert from 'node:assert/strict';
import { awaitGatewayDeployment } from './await-gateway-deploy.mjs';

const SHA = 'a'.repeat(40);
const OLD = 'b'.repeat(40);
const ready = sha => ({
  status: 200,
  async json() { return { status: 'alive', service: 'sentinel-apex', deploy_commit_sha: sha }; },
});
const noop = () => {};

test('exact live commit passes immediately with one GET and no credential headers', async () => {
  const calls = [];
  const result = await awaitGatewayDeployment({
    expectedSha: SHA,
    fetchImpl: async (url, options) => { calls.push({ url, options }); return ready(SHA); },
    sleep: async () => assert.fail('unnecessary poll'),
    maxAttempts: 3,
  });
  assert.deepEqual(result, { sha: SHA, attempt: 1 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://intel.cyberdudebivash.com/api/health/live');
  assert.equal(calls[0].options.method, 'GET');
  assert.equal(calls[0].options.cache, 'no-store');
  assert.equal(calls[0].options.headers['x-api-key'], undefined);
  assert.equal(calls[0].options.headers.Authorization, undefined);
});

test('older deployment must converge to exact SHA before succeeding', async () => {
  let n = 0;
  let sleeps = 0;
  const got = await awaitGatewayDeployment({
    expectedSha: SHA,
    fetchImpl: async () => ready(++n < 3 ? OLD : SHA),
    sleep: async () => { sleeps++; },
    maxAttempts: 4,
    intervalMs: 1,
  });
  assert.equal(got.attempt, 3);
  assert.equal(n, 3);
  assert.equal(sleeps, 2);
});

test('permanent stale deployment fails closed rather than issuing a credential', async () => {
  const evidence = [];
  let n = 0;
  await assert.rejects(awaitGatewayDeployment({
    expectedSha: SHA, fetchImpl: async () => { n++; return ready(OLD); },
    sleep: async () => {},
    maxAttempts: 2, intervalMs: 1, log: x => evidence.push(x),
  }), /GATEWAY_DEPLOY_NOT_CONVERGED.*deployment_sha_not_converged/);
  assert.equal(n, 2);
  assert.equal(evidence.filter(x => x.startsWith('GATEWAY_EXACT_SHA_CONFIRMED')).length, 0);
});

test('missing, unauthorized, malformed or failed endpoint cannot pass', async () => {
  const failures = [
    async () => ({ status: 503 }),
    async () => ({ status: 401 }),
    async () => ({ status: 200, async json() { return { status: 'ok', deploy_commit_sha: SHA }; } }),
    async () => ({ status: 200, async json() { throw Error('malformed JSON'); } }),
    async () => { throw Error('connection refused'); },
  ];
  for (const fetchImpl of failures) {
    await assert.rejects(awaitGatewayDeployment({
      expectedSha: SHA, fetchImpl, sleep: async () => {},
      maxAttempts: 1, log: noop,
    }), /GATEWAY_DEPLOY_NOT_CONVERGED/);
  }
});

test('invalid expected SHA and unbounded retries fail before any HTTP fetch', async () => {
  let calls = 0;
  const fetchImpl = async () => { calls++; return ready(SHA); };
  await assert.rejects(awaitGatewayDeployment({ expectedSha: 'main', fetchImpl }), /GATEWAY_DEPLOY_SHA_INVALID/);
  await assert.rejects(awaitGatewayDeployment({ expectedSha: SHA, fetchImpl, maxAttempts: 1000 }), /GATEWAY_DEPLOY_ATTEMPTS_INVALID/);
  assert.equal(calls, 0);
});

test('a valid SHA on non-200 HTTP cannot bypass the liveness contract', async () => {
  await assert.rejects(awaitGatewayDeployment({
    expectedSha: SHA,
    fetchImpl: async () => ({ ...ready(SHA), status: 500 }),
    maxAttempts: 1,
  }), /GATEWAY_DEPLOY_NOT_CONVERGED/);
});
