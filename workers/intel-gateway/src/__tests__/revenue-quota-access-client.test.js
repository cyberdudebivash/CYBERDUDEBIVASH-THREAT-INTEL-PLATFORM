import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { revenueQuotaAlertHeaders } from '../revenue-quota-access-client.js';

const admin = 'synthetic_admin_credential';
const id = '123456789abcdef123456789abcdef.access';
const service = 'cfast_1234567890abcdefghijABCDEFGHIJ12345678abcdef12';

test('legacy gateway authentication is unchanged when no service token is provisioned', () => {
  const h = revenueQuotaAlertHeaders({ REVENUE_ADMIN_SECRET: admin });
  assert.ok(h instanceof Headers);
  assert.equal(h.get('X-Admin-Secret'), admin);
  assert.equal(h.get('Content-Type'), 'application/json');
  assert.equal(h.has('CF-Access-Client-Id'), false);
  assert.equal(h.has('CF-Access-Client-Secret'), false);
});

test('both approved service credentials are passed only on the Revenue request', () => {
  const h = revenueQuotaAlertHeaders({
    REVENUE_ADMIN_SECRET: admin,
    REVENUE_CF_ACCESS_CLIENT_ID: id,
    REVENUE_CF_ACCESS_CLIENT_SECRET: service,
  });
  assert.ok(h instanceof Headers);
  assert.equal(h.get('X-Admin-Secret'), admin);
  assert.equal(h.get('CF-Access-Client-Id'), id);
  assert.equal(h.get('CF-Access-Client-Secret'), service);
  assert.equal(h.has('Cf-Access-Jwt-Assertion'), false,
    'caller cannot forge a signed Access assertion; Access must issue it');
});

test('invalid and half-configured service tokens fail closed, never silently use the legacy header', () => {
  const invalid = [
    { REVENUE_CF_ACCESS_CLIENT_ID: id },
    { REVENUE_CF_ACCESS_CLIENT_SECRET: service },
    { REVENUE_CF_ACCESS_CLIENT_ID: id, REVENUE_CF_ACCESS_CLIENT_SECRET: '' },
    { REVENUE_CF_ACCESS_CLIENT_ID: 'abc', REVENUE_CF_ACCESS_CLIENT_SECRET: service },
    { REVENUE_CF_ACCESS_CLIENT_ID: 'id with spaces.access', REVENUE_CF_ACCESS_CLIENT_SECRET: service },
    { REVENUE_CF_ACCESS_CLIENT_ID: id, REVENUE_CF_ACCESS_CLIENT_SECRET: 'short' },
    { REVENUE_CF_ACCESS_CLIENT_ID: id, REVENUE_CF_ACCESS_CLIENT_SECRET: service + '\r\nInjected: 1' },
    { REVENUE_CF_ACCESS_CLIENT_ID: id + '\r', REVENUE_CF_ACCESS_CLIENT_SECRET: service },
    { REVENUE_CF_ACCESS_CLIENT_ID: id, REVENUE_CF_ACCESS_CLIENT_SECRET: 123 },
    { REVENUE_CF_ACCESS_CLIENT_ID: 2, REVENUE_CF_ACCESS_CLIENT_SECRET: service },
  ];
  for (const values of invalid) {
    assert.equal(revenueQuotaAlertHeaders({ REVENUE_ADMIN_SECRET: admin, ...values }), null);
  }
});

test('missing, empty, or invalid admin secret never authorizes an outbound request', () => {
  for (const bad of [undefined, null, '', 2, {}, 'bad\r\nheader']) {
    assert.equal(revenueQuotaAlertHeaders({ REVENUE_ADMIN_SECRET: bad }), null);
  }
});

test('intended source sends Access machine identity only via existing Revenue quota alert', () => {
  const src = readFileSync(new URL('../index.js', import.meta.url), 'utf8');
  assert.match(src, /import \{ revenueQuotaAlertHeaders \} from '\.\/revenue-quota-access-client\.js'/);
  const start = src.indexOf('async function maybeDispatchQuotaAlert(');
  const end = src.indexOf('// P0 2026-09-03 -- first-party web read plane', start);
  assert.ok(start > 0 && end > start);
  const fn = src.slice(start, end);
  assert.ok(fn.includes('const headers = revenueQuotaAlertHeaders(env);'));
  assert.ok(fn.indexOf('if (!headers) return;') < fn.indexOf('await env.RATE_LIMIT_KV.get(dedupeKey)'));
  assert.ok(fn.indexOf('await env.RATE_LIMIT_KV.get(dedupeKey)') <
    fn.indexOf('await env.API_KEYS_KV?.get(auth.key, "json")'));
  assert.match(fn, /fetch\("https:\/\/revenue\.intel\.cyberdudebivash\.com\/api\/automation\/trigger"/);
  assert.match(fn, /headers,/);
  assert.match(fn, /redirect:\s*"manual"/,
    'Workers must NOT follow redirects with X-Admin-Secret and Access credentials');
  assert.doesNotMatch(fn, /redirect:\s*"follow"/);
  assert.doesNotMatch(fn, /Cf-Access-Jwt-Assertion/);
});
