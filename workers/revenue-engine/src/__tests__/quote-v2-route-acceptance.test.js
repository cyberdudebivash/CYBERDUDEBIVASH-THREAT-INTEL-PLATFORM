// End-to-end, in-memory D1 regression for the opt-in enterprise quote signer.
// All requests run against the production Revenue Engine router; no Cloudflare
// deployment, payment-provider calls, real customer records, or secrets.
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { test } from 'node:test';

import worker from '../index.js';
import { createD1 } from './helpers/d1-sqlite.js';

const ROOT = 'https://revenue.example.test';
const ADMIN = 'TEST_ONLY_admin_key_for_local_regression';
const QUOTE_KEY = 'TEST_ONLY_independent_quote_signer_more_than_32_bytes';
const PORTAL_KEY = 'TEST_ONLY_portal_key_separate_from_quote_key_32';
const ctx = { waitUntil() {} };
const quoteData = {
  email: 'finance@example.test',
  company_name: 'Example Security Pvt Ltd',
  billing_address: '123 Example Road, Bengaluru 560001',
  billing_state: '29',
  tier: 'ENTERPRISE',
};
const baseEnv = () => ({
  CRM_DB: createD1(),
  REVENUE_ADMIN_SECRET: ADMIN,
  REVENUE_PORTAL_HMAC_KEY: PORTAL_KEY,
});
function request(path, method = 'GET', payload = null, headers = {}) {
  return new Request(ROOT + path, {
    method,
    headers: { ...(payload !== null ? { 'content-type': 'application/json' } : {}), ...headers },
    ...(payload !== null ? { body: JSON.stringify(payload) } : {}),
  });
}
async function route(env, path, method = 'GET', body = null, headers = {}) {
  return worker.fetch(request(path, method, body, headers), env, ctx);
}
async function createQuote(env) {
  const response = await route(env, '/api/v2/billing/quotes', 'POST', quoteData,
    { 'X-Admin-Secret': ADMIN });
  assert.equal(response.status, 201, 'authenticated quote creation must succeed');
  const created = await response.json();
  assert.match(created.acceptance.id, /^qt_[0-9a-f]{20}$/);
  assert.match(created.acceptance.token, /^[0-9a-f]{64}$/);
  return created.acceptance;
}
function legacyToken(id) {
  return createHmac('sha256', ADMIN).update('quote:' + id).digest('hex');
}
function viewPath(quote, token = quote.token) {
  return '/api/v2/billing/quotes/view?id=' + quote.id + '&token=' + token;
}
async function accept(env, quote, token = quote.token) {
  return route(env, '/api/v2/billing/quotes/accept', 'POST', {
    id: quote.id, token, po_number: 'PO-SYNTHETIC-26', po_date: '2026-11-03',
  });
}
const asUtcSeconds = (ms) =>
  new Date(Math.floor(ms / 1000) * 1000).toISOString().replace('.000Z', 'Z');

test('v2: real router creates, views and accepts a quote with independent signature', async () => {
  const env = {
    ...baseEnv(),
    REVENUE_QUOTE_V2_ENABLED: 'true',
    REVENUE_QUOTE_HMAC_KEY: QUOTE_KEY,
  };
  const quote = await createQuote(env);
  assert.notEqual(quote.token, legacyToken(quote.id), 'quote signer must not reuse admin authority');
  const view = await route(env, viewPath(quote));
  assert.equal(view.status, 200);
  const data = await view.json();
  assert.equal(data.quote.email, quoteData.email);
  assert.equal(data.quote.status, 'sent');
  const denied = await route(env, viewPath(quote, legacyToken(quote.id)));
  assert.equal(denied.status, 404, 'legacy admin-secret capability is invalid after cutover');
  assert.equal((await accept(env, quote, legacyToken(quote.id))).status, 404);
  const accepted = await accept(env, quote);
  assert.equal(accepted.status, 200);
  assert.equal((await accepted.json()).quote.status, 'accepted');
  const repeated = await accept(env, quote);
  assert.equal(repeated.status, 200, 'same-PO accept retries remain idempotent');
  assert.equal((await repeated.json()).duplicate, true);
});

test('existing quote survives authorized bounded grace; new signer works after grace disabled', async () => {
  const env = baseEnv();
  const old = await createQuote(env);
  assert.equal(old.token, legacyToken(old.id));
  const now = Date.now();
  Object.assign(env, {
    REVENUE_QUOTE_V2_ENABLED: 'true',
    REVENUE_QUOTE_HMAC_KEY: QUOTE_KEY,
    REVENUE_QUOTE_LEGACY_CUTOVER_AT: asUtcSeconds(now - 60_000),
    REVENUE_QUOTE_LEGACY_ACCEPT_UNTIL: asUtcSeconds(now + 3_600_000),
  });
  assert.equal((await route(env, viewPath(old))).status, 200,
    'previously issued customer quote must remain usable during approved grace');
  const fresh = await createQuote(env);
  assert.equal((await route(env, viewPath(fresh))).status, 200);
  assert.equal((await accept(env, old)).status, 200, 'legacy quote accepts during bounded grace');
  delete env.REVENUE_QUOTE_LEGACY_ACCEPT_UNTIL;
  assert.equal((await route(env, viewPath(old))).status, 404,
    'legacy bearer is immediately denied when grace ends');
  assert.equal((await route(env, viewPath(fresh))).status, 200,
    'independent-key quote must remain valid after legacy grace ends');
});

test('invalid quote bearer and missing v2 signer fail before D1 access', async () => {
  let accessed = false;
  const database = { prepare() { accessed = true; throw new Error('D1 must not be touched'); } };
  const env = {
    ...baseEnv(), CRM_DB: database,
    REVENUE_QUOTE_V2_ENABLED: 'true',
    REVENUE_QUOTE_HMAC_KEY: QUOTE_KEY,
  };
  const bogus = { id: 'qt_' + 'f'.repeat(20), token: 'a'.repeat(64) };
  assert.equal((await route(env, viewPath(bogus))).status, 404);
  assert.equal((await accept(env, bogus)).status, 404);
  assert.equal(accessed, false, 'invalid customer tokens cannot cause D1 access');
  env.REVENUE_QUOTE_HMAC_KEY = ADMIN;
  const denied = await route(env, '/api/v2/billing/quotes', 'POST', quoteData,
    { 'X-Admin-Secret': ADMIN });
  assert.equal(denied.status, 503, 'shared signing key denies quote creation');
  assert.equal(accessed, false, 'misconfigured quote signer never persists a quote');
});
