/**
 * Synthetic cross-Worker contract test. No HTTP, Cloudflare account, real
 * service token, real JWT, email provider, or production KV.
 *
 * The Access proxy below is a strict TEST DOUBLE that simulates a configured
 * Service Auth policy and a signed application JWT. It never claims that the
 * user's actual Cloudflare tenant/policy/token is configured or working.
 */
import assert from 'node:assert/strict';
import { before, test } from 'node:test';
import { webcrypto } from 'node:crypto';
import revenueWorker from '../../../revenue-engine/src/index.js';
import { revenueQuotaAlertHeaders } from '../revenue-quota-access-client.js';
import { dispatchQuotaAlertOnce } from '../quota-alert-delivery.js';

const cryptoApi = globalThis.crypto ?? webcrypto;
const URL = 'https://revenue.intel.cyberdudebivash.com/api/automation/trigger';
const KEY = 'alert_sent:80pct:synthetic-key:2026-11-03';
const ADMIN = 'synthetic_admin_key_not_real';
const CLIENT_ID = 'abcdef0123456789abcdef0123456789.access';
const CLIENT_SECRET = 'cfast_0123456789abcdef0123456789abcdef0123456789';
const ISSUER = 'https://synthetic-team.cloudflareaccess.com';
const AUDIENCE = 'synthetic-revenue-audience-1234';
// Full Worker fetch uses the actual clock; keep the synthetic JWT freshly valid.
const NOW = Math.floor(Date.now() / 1000);

let signingKey;
let publicJwk;
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');

before(async () => {
  const pair = await cryptoApi.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
  signingKey = pair.privateKey;
  publicJwk = {
    ...(await cryptoApi.subtle.exportKey('jwk', pair.publicKey)),
    kid: 'synthetic-quota-service-key', use: 'sig', alg: 'RS256'
  };
});

async function signedToken(overrides = {}) {
  const header = { alg: 'RS256', typ: 'JWT', kid: 'synthetic-quota-service-key' };
  const body = {
    iss: ISSUER, aud: [AUDIENCE], type: 'app', sub: '',
    common_name: CLIENT_ID, iat: NOW - 60, exp: NOW + 1800,
    ...overrides,
  };
  const unsigned = encode(header) + '.' + encode(body);
  const signature = await cryptoApi.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' }, signingKey,
    new TextEncoder().encode(unsigned)
  );
  return unsigned + '.' + Buffer.from(signature).toString('base64url');
}

function harness(overrides = {}) {
  const record = new Map();
  const quota = new Map();
  const env = {
    REVENUE_ADMIN_SECRET: ADMIN,
    REVENUE_OPERATOR_ACCESS_MODE: 'required',
    REVENUE_OPERATOR_ACCESS_ISSUER: ISSUER,
    REVENUE_OPERATOR_ACCESS_AUDIENCE: AUDIENCE,
    REVENUE_OPERATOR_ACCESS_JWKS: JSON.stringify({ keys: [publicJwk] }),
    REVENUE_OPERATOR_ACCESS_EMAILS: 'operator@example.test',
    REVENUE_OPERATOR_ACCESS_SERVICE_IDS: CLIENT_ID,
    EMAIL_QUEUE_KV: {
      async put(key, value, options) {
        assert.match(key, /^email:/);
        assert.equal(options.expirationTtl, 30 * 86400);
        record.set(key, JSON.parse(value));
      },
    },
    ...overrides,
  };
  const kv = {
    async get(key) { return quota.get(key) ?? null; },
    async put(key, value, options) {
      assert.ok(options.expirationTtl === 3600 || options.expirationTtl === 90000);
      quota.set(key, value);
    },
  };
  return { env, record, quota, kv };
}

// This is NOT a Cloudflare Access implementation. It models only the boundary:
// an approved service credential pair is accepted, and Access forwards a
// cryptographically signed application JWT to the protected origin.
async function accessDouble(headers, env, overrides = {}, tokenOverride = null) {
  if (!headers || headers.get('CF-Access-Client-Id') !== CLIENT_ID ||
      headers.get('CF-Access-Client-Secret') !== CLIENT_SECRET) {
    return Response.json({ error: 'synthetic_access_denied' }, { status: 403 });
  }
  const originHeaders = new Headers(headers);
  originHeaders.delete('CF-Access-Client-Id');
  originHeaders.delete('CF-Access-Client-Secret');
  originHeaders.set('Cf-Access-Jwt-Assertion',
    tokenOverride ?? await signedToken(overrides));
  return revenueWorker.fetch(new Request(URL, {
    method: 'POST',
    headers: originHeaders,
    body: JSON.stringify({
      trigger: 'usage_80pct',
      email: 'synthetic-customer@example.test',
      context: 'daily_quota:PRO',
    }),
  }), env, {});
}

function credentialHeaders(overrides = {}) {
  return revenueQuotaAlertHeaders({
    REVENUE_ADMIN_SECRET: ADMIN,
    REVENUE_CF_ACCESS_CLIENT_ID: CLIENT_ID,
    REVENUE_CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET,
    ...overrides,
  });
}

test('valid service client and signed Access JWT queue exactly one email and then mark daily quota alert', async () => {
  const h = harness();
  const headers = credentialHeaders();
  assert.ok(headers);
  assert.equal(headers.has('Cf-Access-Jwt-Assertion'), false,
    'gateway must not fabricate an origin JWT');
  const result = await dispatchQuotaAlertOnce({
    kv: h.kv, key: KEY, deliver: () => accessDouble(headers, h.env),
  });
  assert.equal(result.outcome, 'queued');
  assert.equal(h.quota.get(KEY), 'sent');
  assert.equal(h.record.size, 1);
  const email = [...h.record.values()][0];
  assert.equal(email.status, 'queued');
  assert.equal(email.to, 'synthetic-customer@example.test');
  assert.equal(email.template, 'usage_approaching_limit');
  assert.equal((await dispatchQuotaAlertOnce({
    kv: h.kv, key: KEY, deliver: () => { throw Error('must not re-send'); }
  })).outcome, 'suppressed');
});

test('wrong/partial service credentials are rejected before origin JWT and cannot mark alert sent', async () => {
  for (const values of [
    { REVENUE_CF_ACCESS_CLIENT_ID: CLIENT_ID, REVENUE_CF_ACCESS_CLIENT_SECRET: 'x'.repeat(32) },
    { REVENUE_CF_ACCESS_CLIENT_ID: 'wrong-client.access', REVENUE_CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET },
  ]) {
    const h = harness();
    const headers = credentialHeaders(values);
    assert.ok(headers);
    const result = await dispatchQuotaAlertOnce({
      kv: h.kv, key: KEY, deliver: () => accessDouble(headers, h.env)
    });
    assert.equal(result.outcome, 'retry_after_reservation');
    assert.equal(h.quota.get(KEY), 'pending');
    assert.equal(h.record.size, 0);
  }
  for (const values of [
    { REVENUE_CF_ACCESS_CLIENT_ID: CLIENT_ID, REVENUE_CF_ACCESS_CLIENT_SECRET: '' },
    { REVENUE_CF_ACCESS_CLIENT_ID: undefined, REVENUE_CF_ACCESS_CLIENT_SECRET: CLIENT_SECRET },
  ]) {
    const h = harness();
    assert.equal(credentialHeaders(values), null);
    assert.equal(h.quota.size, 0);
    assert.equal(h.record.size, 0);
  }
});

test('wrong Access JWT audience or service identity is rejected by REAL Revenue Worker gate', async () => {
  for (const claim of [
    { aud: ['wrong-audience'] },
    { common_name: 'other-client.access' },
    { iss: 'https://wrong-team.cloudflareaccess.com' },
    { exp: NOW - 1 },
  ]) {
    const h = harness();
    const headers = credentialHeaders();
    const response = await accessDouble(headers, h.env, claim);
    assert.equal(response.status, 403, JSON.stringify(claim));
    assert.equal((await response.json()).error, 'operator_identity_required');
    assert.equal(h.record.size, 0, JSON.stringify(claim));
  }
});

test('legacy admin-only request is accepted only while source operator gate is explicitly off', async () => {
  const h = harness({ REVENUE_OPERATOR_ACCESS_MODE: 'off' });
  const legacyHeaders = revenueQuotaAlertHeaders({ REVENUE_ADMIN_SECRET: ADMIN });
  assert.ok(legacyHeaders);
  const res = await revenueWorker.fetch(new Request(URL, {
    method: 'POST', headers: legacyHeaders,
    body: JSON.stringify({ trigger: 'usage_80pct', email: 'synthetic-customer@example.test' }),
  }), h.env, {});
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, 'triggered');
  assert.equal(h.record.size, 1);
  const required = harness();
  const denied = await revenueWorker.fetch(new Request(URL, {
    method: 'POST', headers: legacyHeaders,
    body: JSON.stringify({ trigger: 'usage_80pct', email: 'synthetic-customer@example.test' }),
  }), required.env, {});
  assert.equal(denied.status, 403);
  assert.equal(required.record.size, 0);
});

test('valid service/JWT with bad admin secret cannot bypass the second factor', async () => {
  const h = harness();
  const headers = credentialHeaders({ REVENUE_ADMIN_SECRET: 'wrong_admin_secret' });
  const response = await accessDouble(headers, h.env);
  assert.equal(response.status, 401);
  assert.equal(h.record.size, 0);
});

test('missing queue binding cannot produce successful quota acknowledgment with valid Access JWT', async () => {
  const h = harness({ EMAIL_QUEUE_KV: undefined });
  const result = await dispatchQuotaAlertOnce({
    kv: h.kv, key: KEY, deliver: () => accessDouble(credentialHeaders(), h.env),
  });
  assert.equal(result.outcome, 'retry_after_reservation');
  assert.equal(h.quota.get(KEY), 'pending');
  assert.equal(h.record.size, 0);
});
