import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import worker from '../index.js';
import {
  portalV2Enabled, portalV2Configured, legacyPortalAllowed,
  issuePortalTokenV2, verifyPortalTokenV2,
} from '../portal-token-v2.js';

const EMAIL = 'customer@example.com';
const OTHER = 'other@example.com';
const KEY = 'TEST_ONLY_portal_hmac_secret_32_bytes_or_longer';
const ADMIN = 'TEST_ONLY_admin_separate_secret';
const v2 = () => ({
  REVENUE_PORTAL_V2_ENABLED: 'true',
  REVENUE_PORTAL_HMAC_KEY: KEY,
  REVENUE_ADMIN_SECRET: ADMIN,
});

function fakeEnv(add = {}) {
  const entries = new Map([
    [`customer:${EMAIL}`, { id: 'cust_test', email: EMAIL, tier: 'PRO', status: 'active' }],
    [`apikeys:${EMAIL}`, [{ id: 'k_1', key: 'CDB-PRO-TEST_ONLY_SECRET_KEY', tier: 'PRO', status: 'active' }]],
    [`sub:email:${EMAIL}`, { current_period_end: '2030-01-01T00:00:00Z' }],
  ]);
  const reads = [];
  const env = {
    ...v2(), ...add,
    REVENUE_CRM_KV: {
      async get(key) { reads.push(key); return entries.get(key) || null; },
    },
  };
  return { env, reads };
}

const PORTAL_URL = 'https://revenue.intel.cyberdudebivash.com/api/customer/portal';
const ctx = { waitUntil() {} };
function post(email, bearer, path = PORTAL_URL, extra = {}) {
  return new Request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
    body: JSON.stringify({ email, ...extra }),
  });
}
function legacyToken() {
  return createHmac('sha256', ADMIN).update('portal:' + EMAIL).digest('hex');
}

test('v2 requires explicit opt-in, dedicated 32-byte key and distinct admin secret', async () => {
  const env = v2();
  assert.equal(portalV2Enabled(env), true);
  assert.equal(portalV2Configured(env), true);
  assert.equal(portalV2Configured({ ...env, REVENUE_PORTAL_HMAC_KEY: ADMIN }), false);
  assert.equal(portalV2Configured({ ...env, REVENUE_ADMIN_SECRET: KEY }), false);
  assert.equal(portalV2Configured({ ...env, REVENUE_PORTAL_HMAC_KEY: 'short' }), false);
  assert.equal(await issuePortalTokenV2({ ...env, REVENUE_PORTAL_V2_ENABLED: 'false' }, EMAIL), null);
  assert.equal(await issuePortalTokenV2({ ...env, REVENUE_ADMIN_SECRET: KEY }, EMAIL), null);
});

test('signed 24-hour bearer is subject-bound, expires, cannot use another key or forged claims', async () => {
  const now = Date.parse('2026-11-02T12:00:00Z');
  const env = v2();
  const token = await issuePortalTokenV2(env, EMAIL, now);
  assert.match(token, /^v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assert.equal(await verifyPortalTokenV2(env, EMAIL, token, now), true);
  assert.equal(await verifyPortalTokenV2(env, EMAIL, token, now + 86_400_000), false);
  assert.equal(await verifyPortalTokenV2(env, OTHER, token, now), false);
  assert.equal(await verifyPortalTokenV2({ ...env, REVENUE_PORTAL_HMAC_KEY: KEY+'x' }, EMAIL, token, now), false);
  assert.equal(await verifyPortalTokenV2(env, EMAIL, token.slice(0,-1)+'!', now), false);
  assert.equal(await verifyPortalTokenV2(env, EMAIL, token+'.x', now), false);
  const another = await issuePortalTokenV2(env, EMAIL, now);
  assert.notEqual(another, token, 'nonce ensures distinct bearer for separately issued links');
});

test('legacy defaults unchanged before cutover; after activation only explicit bounded grace permits old links', () => {
  const now = Date.parse('2026-11-02T12:00:00Z');
  assert.equal(legacyPortalAllowed({}, now), true);
  assert.equal(legacyPortalAllowed(v2(), now), false);
  const env = { ...v2(), REVENUE_PORTAL_LEGACY_ACCEPT_UNTIL: '2026-11-08T12:00:00Z' };
  assert.equal(legacyPortalAllowed(env, now), true);
  assert.equal(legacyPortalAllowed(env, Date.parse(env.REVENUE_PORTAL_LEGACY_ACCEPT_UNTIL)), false);
  assert.equal(legacyPortalAllowed({ ...env, REVENUE_PORTAL_LEGACY_ACCEPT_UNTIL: '2027-03-02T12:00:00Z' }, now), false);
});

test('full route: authenticated POST returns own masked keys; not admin secret', async () => {
  const {env,reads} = fakeEnv();
  const token = await issuePortalTokenV2(env, EMAIL);
  const result = await worker.fetch(post(EMAIL, token), env, ctx);
  assert.equal(result.status, 200);
  const body = await result.json();
  assert.equal(body.customer.email, EMAIL);
  assert.equal(body.api_keys.length, 1);
  assert.equal(body.api_keys[0].key, undefined);
  assert.equal(JSON.stringify(body).includes('CDB-PRO-TEST_ONLY_SECRET_KEY'), false);
  assert.deepEqual(reads, [`customer:${EMAIL}`,`apikeys:${EMAIL}`,`sub:email:${EMAIL}`]);
  assert.match(result.headers.get('cache-control'), /no-store/);
});

test('full route: missing/wrong/other customer token denies without KV reads', async () => {
  for (const [envExtra, email, getToken, expected] of [
    [{}, EMAIL, false, 401],
    [{}, OTHER, true, 401],
    [{REVENUE_PORTAL_HMAC_KEY:'short'}, EMAIL, true, 503],
  ]) {
    const {env,reads} = fakeEnv(envExtra);
    const token = getToken ? await issuePortalTokenV2(v2(), EMAIL) : null;
    const result = await worker.fetch(post(email, token), env, ctx);
    assert.equal(result.status, expected);
    assert.deepEqual(reads, []);
  }
  const {env, reads} = fakeEnv();
  const token = await issuePortalTokenV2(env, EMAIL);
  assert.equal((await worker.fetch(post(EMAIL, token, PORTAL_URL+'?token='+encodeURIComponent(token)), env, ctx)).status, 401);
  assert.equal((await worker.fetch(new Request(PORTAL_URL, {
    method:'POST', headers:{ 'content-type':'application/json', 'X-Admin-Secret':ADMIN },
    body:JSON.stringify({email:EMAIL}),
  }),env,ctx)).status,401);
  assert.deepEqual(reads, []);
});

test('streaming oversized or malformed JSON is rejected before any customer KV reads', async () => {
  const { env, reads } = fakeEnv();
  const data = new TextEncoder().encode(JSON.stringify({ email: EMAIL, notes: 'A'.repeat(4000) }));
  const stream = new ReadableStream({ start(controller) { controller.enqueue(data); controller.close(); } });
  const oversized = await worker.fetch(new Request(PORTAL_URL, {
    method: 'POST', duplex: 'half',
    headers: { 'content-type': 'application/json' },
    body: stream,
  }), env, ctx);
  assert.equal(oversized.status, 413);

  const malformed = await worker.fetch(new Request(PORTAL_URL, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: '{invalid',
  }), env, ctx);
  assert.equal(malformed.status, 400);
  assert.deepEqual(reads, []);
});

test('malformed customer identity types fail with 400 and perform zero KV reads', async () => {
  const { env, reads } = fakeEnv();
  const signed = await issuePortalTokenV2(env, EMAIL);
  for (const value of [null, 5, true, {}, ['customer@example.com']]) {
    const request = new Request(PORTAL_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${signed}`,
      },
      body: JSON.stringify({ email: value }),
    });
    const response = await worker.fetch(request, env, ctx);
    assert.equal(response.status, 400, `unexpected status for email type ${typeof value}`);
    const body = await response.json();
    assert.equal(body.error, 'invalid_email');
    assert.deepEqual(reads, [], 'malformed identity must not touch customer KV');
  }
});

test('backend exceptions never disclose internal errors, credentials or customer data', async () => {
  const { env } = fakeEnv();
  const sentinel = 'TEST_ONLY_PRIVATE_PROVIDER_CREDENTIAL_AND_CUSTOMER_DATA';
  env.REVENUE_CRM_KV.get = async () => {
    throw new Error(sentinel);
  };
  const token = await issuePortalTokenV2(env, EMAIL);
  const result = await worker.fetch(post(EMAIL, token), env, ctx);
  assert.equal(result.status, 500);
  const body = await result.json();
  assert.equal(body.error, 'internal_error');
  assert.equal(body.message, 'An internal error occurred.');
  assert.ok(typeof body.rid === 'string' && body.rid.length > 0);
  assert.equal(JSON.stringify(body).includes(sentinel), false);
  assert.equal(JSON.stringify(body).includes(EMAIL), false);
});

test('full route: legacy GET remains available until reviewed migration, then fails closed', async () => {
  const old = legacyToken();
  const initial = fakeEnv({REVENUE_PORTAL_V2_ENABLED: undefined, REVENUE_PORTAL_HMAC_KEY: undefined});
  assert.equal((await worker.fetch(new Request(PORTAL_URL+'?email='+EMAIL+'&token='+old),initial.env,ctx)).status,200);
  const migrated = fakeEnv();
  assert.equal((await worker.fetch(new Request(PORTAL_URL+'?email='+EMAIL+'&token='+old),migrated.env,ctx)).status,401);
  const future = new Date(Math.floor((Date.now()+3600_000)/1000)*1000).toISOString().replace('.000Z','Z');
  const grace = fakeEnv({REVENUE_PORTAL_LEGACY_ACCEPT_UNTIL:future});
  assert.equal((await worker.fetch(new Request(PORTAL_URL+'?email='+EMAIL+'&token='+old),grace.env,ctx)).status,200);
  assert.equal((await worker.fetch(new Request(PORTAL_URL+'?email='+EMAIL+'&token=bad'),grace.env,ctx)).status,401);
  assert.equal((await worker.fetch(new Request(PORTAL_URL+'?email='+EMAIL+'&token=v2.invalid.invalid'),grace.env,ctx)).status,401);
});

test('customer HTML uses fragment-only v2 link and bearer POST while preserving #redeem', () => {
  const frontend = readFileSync(new URL('../../../../customer/api-keys.html',import.meta.url),'utf8');
  const backend = readFileSync(new URL('../index.js',import.meta.url),'utf8');
  assert.match(frontend, /#portal=/);
  assert.match(frontend, /portalTokenV2 = true/);
  assert.match(frontend, /method: 'POST', cache: 'no-store'/);
  assert.match(frontend, /history\.replaceState/);
  assert.match(frontend, /#redeem=/);
  assert.match(backend, /portalV2Enabled\(env\)/);
  assert.match(backend, /verifyPortalTokenV2\(env, cleanEmail/);
  assert.match(backend, /#portal=\$\{encodeURIComponent\(portalToken\)\}/);
});
