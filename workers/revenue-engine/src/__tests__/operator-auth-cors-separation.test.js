import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import worker from '../index.js';

// ---------------------------------------------------------------------------
// #973 acceptance: executable evidence for the operator boundary of the Revenue Engine.
//
// A responsible-disclosure report observed that an unauthenticated request to an operator path
// returned 401 and that the CORS preflight advertised Access-Control-Allow-Methods. Neither shows a
// bypass. This suite pins the facts so the classification does not rest on reading code:
//
//   1. Authentication is decided per request, before routing: a missing, empty, wrong, truncated or
//      unconfigured credential is 401 with no data, and no route is enumerable (an unknown path is
//      401, not 404). A deployment with no REVENUE_ADMIN_SECRET never matches an empty or
//      "undefined" header.
//   2. CORS is not authorization. The preflight is answered for any origin and lists the methods the
//      API supports; only an allow-listed origin is echoed in Access-Control-Allow-Origin. A request
//      from either kind of origin without a valid credential is still 401.
//   3. In REVENUE_OPERATOR_ACCESS_MODE=required the legacy shared secret alone is refused (403)
//      without a verified Access identity.
//   4. The public customer health route stays reachable with no credential.
//
// Offline: no network, no real secret, synthetic values only. This file does not change behaviour.
// ---------------------------------------------------------------------------

const SECRET = 'synthetic-operator-secret-0123456789';
const ALLOWED_ORIGIN = 'https://intel.cyberdudebivash.com';
const UNTRUSTED_ORIGIN = 'https://attacker.example';
const BASE = 'https://revenue.intel.cyberdudebivash.com';
const PROTECTED = '/api/revenue/dashboard';

async function call({ method = 'GET', path = PROTECTED, headers = {}, env = { REVENUE_ADMIN_SECRET: SECRET } } = {}) {
  const res = await worker.fetch(new Request(BASE + path, { method, headers }), env, {});
  const text = await res.text();
  return { res, text, acao: res.headers.get('Access-Control-Allow-Origin') };
}
const leaksData = (text) => /dashboard|mrr|customer|invoice|subscription/i.test(text);

describe('#973 — legacy operator credential (access mode off)', () => {
  for (const [label, headers] of [
    ['no credential', {}],
    ['a wrong credential', { 'X-Admin-Secret': 'not-the-secret' }],
    ['an empty credential', { 'X-Admin-Secret': '' }],
    ['a truncated copy of the real credential', { 'X-Admin-Secret': SECRET.slice(0, 12) }],
    ['the real credential with one character appended', { 'X-Admin-Secret': SECRET + 'x' }],
  ]) {
    test(`${label} → 401, no data`, async () => {
      const { res, text } = await call({ headers });
      assert.equal(res.status, 401);
      assert.equal(JSON.parse(text).error, 'unauthorized');
      assert.equal(leaksData(text.replace('X-Admin-Secret required.', '')), false);
    });
  }

  test('a deployment with no REVENUE_ADMIN_SECRET never matches an empty, "undefined" or arbitrary header', async () => {
    for (const value of ['', 'undefined', 'null', 'x']) {
      const { res } = await call({ headers: { 'X-Admin-Secret': value }, env: {} });
      assert.equal(res.status, 401, `header value ${JSON.stringify(value)}`);
    }
  });

  test('the correct credential is accepted (positive control: the gate is not simply closed)', async () => {
    const { res, text } = await call({ headers: { 'X-Admin-Secret': SECRET } });
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(text).status, 'ok');
  });

  test('authentication precedes routing: every method on an unknown path is 401, never 404 (no route enumeration)', async () => {
    for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
      const { res } = await call({ method, path: '/api/definitely/not/a/route' });
      assert.equal(res.status, 401, method);
    }
  });

  test('mutating methods without a credential are 401 on CRM paths', async () => {
    for (const [method, path] of [['POST', '/api/crm/leads'], ['PUT', '/api/crm/leads/1'], ['DELETE', '/api/crm/leads/1']]) {
      const { res } = await call({ method, path });
      assert.equal(res.status, 401, `${method} ${path}`);
    }
  });
});

describe('#973 — CORS is not authorization', () => {
  test('preflight from an allow-listed origin: 204, origin echoed (never *), no body, no data', async () => {
    const { res, text, acao } = await call({ method: 'OPTIONS', headers: { Origin: ALLOWED_ORIGIN, 'Access-Control-Request-Method': 'DELETE' } });
    assert.equal(res.status, 204);
    assert.equal(acao, ALLOWED_ORIGIN);
    assert.equal(text, '');
  });

  test('preflight from an untrusted origin: no Access-Control-Allow-Origin, so a browser blocks the cross-origin request', async () => {
    const { res, text, acao } = await call({ method: 'OPTIONS', headers: { Origin: UNTRUSTED_ORIGIN, 'Access-Control-Request-Method': 'DELETE' } });
    assert.equal(res.status, 204);
    assert.equal(acao, null);
    assert.equal(text, '');
  });

  test('the preflight advertises supported methods; that list grants nothing (the same request with no credential is 401)', async () => {
    const pre = await call({ method: 'OPTIONS', headers: { Origin: ALLOWED_ORIGIN } });
    const advertised = String(pre.res.headers.get('Access-Control-Allow-Methods') || '');
    assert.match(advertised, /DELETE/);
    for (const method of advertised.split(',').map(m => m.trim()).filter(m => m && m !== 'OPTIONS')) {
      const { res } = await call({ method, path: '/api/crm/leads/1', headers: { Origin: ALLOWED_ORIGIN } });
      assert.equal(res.status, 401, `advertised method ${method} without a credential`);
    }
  });

  test('an allow-listed origin without a valid credential is still 401 with no data (the origin is echoed so its own page can read the 401)', async () => {
    for (const headers of [{ Origin: ALLOWED_ORIGIN }, { Origin: ALLOWED_ORIGIN, 'X-Admin-Secret': 'wrong' }]) {
      const { res, text, acao } = await call({ headers });
      assert.equal(res.status, 401);
      assert.equal(acao, ALLOWED_ORIGIN);
      assert.equal(leaksData(text.replace('X-Admin-Secret required.', '')), false);
    }
  });

  test('an untrusted origin without a valid credential is 401 and receives no CORS grant', async () => {
    for (const [method, path] of [['GET', PROTECTED], ['POST', '/api/crm/leads'], ['DELETE', '/api/crm/leads/1']]) {
      const { res, acao } = await call({ method, path, headers: { Origin: UNTRUSTED_ORIGIN } });
      assert.equal(res.status, 401, `${method} ${path}`);
      assert.equal(acao, null);
    }
  });

  test('a null/absent Origin never falls back to a wildcard', async () => {
    const { acao } = await call({ headers: { Origin: 'null' } });
    assert.notEqual(acao, '*');
    assert.equal(acao, null);
  });
});

describe('#973 — required Access mode (offline; the JWT path itself is covered by revenue-operator-identity.test.js)', () => {
  const required = { REVENUE_ADMIN_SECRET: SECRET, REVENUE_OPERATOR_ACCESS_MODE: 'required' };

  test('the legacy shared secret alone is refused with 403 operator_identity_required and no data', async () => {
    const { res, text } = await call({ headers: { 'X-Admin-Secret': SECRET }, env: required });
    assert.equal(res.status, 403);
    assert.equal(JSON.parse(text).error, 'operator_identity_required');
    assert.equal(leaksData(text), false);
  });

  test('no credential at all stays 401', async () => {
    const { res } = await call({ env: required });
    assert.equal(res.status, 401);
  });
});

describe('#973 — the public customer route is not blocked by the operator boundary', () => {
  test('GET /api/health without any credential is 200 and exposes only status, engine, version and time', async () => {
    for (const env of [{ REVENUE_ADMIN_SECRET: SECRET }, { REVENUE_ADMIN_SECRET: SECRET, REVENUE_OPERATOR_ACCESS_MODE: 'required' }]) {
      const { res, text } = await call({ path: '/api/health', env });
      assert.equal(res.status, 200);
      const body = JSON.parse(text);
      assert.equal(body.status, 'ok');
      assert.equal(body.checks, undefined);
      assert.equal(JSON.stringify(body).includes(SECRET), false);
    }
  });
});
