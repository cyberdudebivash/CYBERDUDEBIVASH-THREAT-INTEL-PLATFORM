import { describe, test, before } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { authorizeRevenueOperator } from '../revenue-operator-identity.js';
import revenueWorker from '../index.js';

const cryptoApi = globalThis.crypto ?? webcrypto;
const NOW = 1800000000;
const issuer = 'https://security-team.cloudflareaccess.com';
const audience = 'revenue-access-audience-1234';
let privateKey;
let publicJwk;

const encode = value => Buffer.from(
  typeof value === 'string' ? value : JSON.stringify(value)
).toString('base64url');
async function signedJwt(overrides = {}, headerOverrides = {}) {
  const header = { alg: 'RS256', typ: 'JWT', kid: 'operator-key-1', ...headerOverrides };
  const payload = {
    iss: issuer, aud: [audience], type: 'app', sub: 'operator-001',
    email: 'operator@example.com', iat: NOW - 60, exp: NOW + 3600,
    ...overrides,
  };
  const input = encode(header) + '.' + encode(payload);
  const signature = await cryptoApi.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' }, privateKey,
    new TextEncoder().encode(input)
  );
  return input + '.' + Buffer.from(signature).toString('base64url');
}
const request = token => new Request('https://revenue.example.test/api/revenue/dashboard', {
  headers: token ? { 'Cf-Access-Jwt-Assertion': token, 'X-Admin-Secret': 'synthetic-operator-key' }
    : { 'X-Admin-Secret': 'synthetic-operator-key' },
});
function config(overrides = {}) {
  return {
    REVENUE_OPERATOR_ACCESS_MODE: 'required',
    REVENUE_OPERATOR_ACCESS_ISSUER: issuer,
    REVENUE_OPERATOR_ACCESS_AUDIENCE: audience,
    REVENUE_OPERATOR_ACCESS_EMAILS: 'operator@example.com',
    REVENUE_OPERATOR_ACCESS_JWKS: JSON.stringify({ keys: [publicJwk] }),
    ...overrides,
  };
}

describe('Revenue operator identity gate (offline; zero external calls)', () => {
  before(async () => {
    const pair = await cryptoApi.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['sign', 'verify']
    );
    privateKey = pair.privateKey;
    publicJwk = { ...await cryptoApi.subtle.exportKey('jwk', pair.publicKey),
      kid: 'operator-key-1', alg: 'RS256', use: 'sig' };
  });

  test('legacy default/off configuration stays unchanged pending authorized activation', async () => {
    assert.equal(await authorizeRevenueOperator(request(), {}, NOW), true);
    assert.equal(await authorizeRevenueOperator(request(), {
      REVENUE_OPERATOR_ACCESS_MODE: 'off',
    }, NOW), true);
  });

  test('requires a real signed, allowlisted, time-bound operator JWT', async () => {
    assert.equal(await authorizeRevenueOperator(request(await signedJwt()), config(), NOW), true);
    assert.equal(await authorizeRevenueOperator(request(), config(), NOW), false);
  });

  test('machine tokens require an independently allowlisted Access service identifier', async () => {
    const token = await signedJwt({
      sub: '', email: undefined, common_name: 'automation-client.access',
    });
    assert.equal(await authorizeRevenueOperator(request(token), config(), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(token), config({
      REVENUE_OPERATOR_ACCESS_SERVICE_IDS: 'automation-client.access',
    }), NOW), true);
    assert.equal(await authorizeRevenueOperator(request(token), config({
      REVENUE_OPERATOR_ACCESS_SERVICE_IDS: 'other-client.access',
    }), NOW), false);
  });

  test('rejects unauthorized issuer, audience, email and missing identity', async () => {
    for (const claims of [
      { iss: 'https://evil.example.test' },
      { aud: ['wrong-audience'] },
      { type: 'org' },
      { email: 'unauthorized@example.com' },
      { sub: '' },
      { exp: NOW - 1 },
      { nbf: NOW + 120 },
      { iat: NOW + 120 },
      { iat: NOW - 90000 },
      { exp: NOW + 90000 },
    ]) {
      assert.equal(await authorizeRevenueOperator(request(await signedJwt(claims)), config(), NOW),
        false, JSON.stringify(claims));
    }
  });

  test('rejects tampering, algorithm substitution, unknown kid and invalid JWKS', async () => {
    const valid = await signedJwt();
    const parts = valid.split('.');
    const tampered = parts[0] + '.' + encode({
      iss: issuer, aud: [audience], type: 'app', sub: 'operator-001',
      email: 'attacker@example.com', iat: NOW - 60, exp: NOW + 3600,
    }) + '.' + parts[2];
    assert.equal(await authorizeRevenueOperator(request(tampered), config(), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(await signedJwt({}, { alg: 'none' })), config(), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(await signedJwt({}, { kid: 'different' })), config(), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(valid), config({ REVENUE_OPERATOR_ACCESS_JWKS: '{"keys":[]}' }), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(valid), config({ REVENUE_OPERATOR_ACCESS_JWKS: '{bad' }), NOW), false);
  });

  test('rejects stolen admin-secret requests before pre-gated billing handlers execute', async () => {
    const response = await revenueWorker.fetch(new Request(
      'https://revenue.example.test/api/v2/billing/refunds/approve',
      { method: 'POST', headers: { 'X-Admin-Secret': 'synthetic-operator-key' } }
    ), config({ REVENUE_ADMIN_SECRET: 'synthetic-operator-key' }), {});
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: 'operator_identity_required' });
  });

  test('fails closed for wrong configuration, wrong operator allowlist, invalid tokens and missing keys', async () => {
    const valid = await signedJwt();
    assert.equal(await authorizeRevenueOperator(request(valid), config({
      REVENUE_OPERATOR_ACCESS_MODE: 'requierd',
    }), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(valid), config({
      REVENUE_OPERATOR_ACCESS_EMAILS: 'someone-else@example.com',
    }), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(valid), config({
      REVENUE_OPERATOR_ACCESS_ISSUER: 'http://security-team.cloudflareaccess.com',
    }), NOW), false);
    assert.equal(await authorizeRevenueOperator(request(valid), config({
      REVENUE_OPERATOR_ACCESS_JWKS: undefined,
    }), NOW), false);
    assert.equal(await authorizeRevenueOperator(request('untrusted.payload.bad'), config(), NOW), false);
  });

  test('public customer health remains reachable in required mode without operator header', async () => {
    const response = await revenueWorker.fetch(new Request(
      'https://revenue.example.test/api/health',
      { method: 'GET' }
    ), config({ REVENUE_ADMIN_SECRET: 'synthetic-operator-key' }), {});
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.engine, 'SENTINEL-REVENUE-ENGINE');
  });

  test('operator header on public health still requires verified identity in required mode', async () => {
    const response = await revenueWorker.fetch(new Request(
      'https://revenue.example.test/api/health',
      { method: 'GET', headers: { 'X-Admin-Secret': 'synthetic-operator-key' } }
    ), config({ REVENUE_ADMIN_SECRET: 'synthetic-operator-key' }), {});
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: 'operator_identity_required' });
  });

  test('malformed required-mode configuration fails closed before privileged dispatch', async () => {
    const response = await revenueWorker.fetch(new Request(
      'https://revenue.example.test/api/crm/leads',
      { method: 'GET', headers: { 'X-Admin-Secret': 'synthetic-operator-key' } }
    ), config({
      REVENUE_ADMIN_SECRET: 'synthetic-operator-key',
      REVENUE_OPERATOR_ACCESS_JWKS: '{bad'
    }), {});
    assert.equal(response.status, 403);
    assert.deepEqual(await response.json(), { error: 'operator_identity_required' });
  });

});
