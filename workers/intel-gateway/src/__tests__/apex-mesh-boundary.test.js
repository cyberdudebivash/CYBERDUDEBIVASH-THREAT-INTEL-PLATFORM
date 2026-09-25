import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import {
  beginApexMeshBoundary,
  completeApexMeshBoundary,
  __test,
} from '../apex-mesh-boundary.js';

const VALID_KEY = 'sentinel-production-key-material-1234567890';

function request(requestId = 'sentinel-req-1', body = { ioc_value: '8.8.8.8', ioc_type: 'ipv4' }) {
  return new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': VALID_KEY,
      'X-Request-ID': requestId,
    },
    body: JSON.stringify(body),
  });
}

function envFor(record = { tier: 'PRO', customer_id: 'cust-1', subscription_status: 'active' }, mutate = null) {
  const calls = [];
  let executionId = null;
  return {
    calls,
    env: {
      APEX_MESH_SERVICE_KEY: 'm'.repeat(64),
      API_KEYS_KV: {
        async get(key, type) {
          assert.equal(key, VALID_KEY);
          assert.equal(type, 'json');
          return record;
        },
      },
      SECURITY_HUB_KV: { async get() { return null; } },
      APEX_MESH: {
        async fetch(req) {
          const path = new URL(req.url).pathname;
          const body = JSON.parse(await req.text());
          calls.push({ path, body, authorization: req.headers.get('authorization') });
          if (path === '/v1/mesh/admit') {
            executionId = 'e'.repeat(64);
            const payload = {
              version: 'cdb.mesh.v1',
              execution_id: executionId,
              tenant_id: body.tenant_id,
              mission_id: body.mission_id,
              correlation_id: body.correlation_id,
              capability: body.capability,
              state: 'admitted',
            };
            return Response.json(mutate?.('admit', payload) ?? payload);
          }
          if (path === '/v1/mesh/complete') {
            const payload = {
              version: 'cdb.mesh.v1',
              execution_id: executionId,
              mission_id: body.mission_id,
              state: body.outcome,
            };
            return Response.json(mutate?.('complete', payload) ?? payload);
          }
          return Response.json({ error: 'unexpected' }, { status: 404 });
        },
      },
    },
  };
}

test('only POST /api/intel/correlate is mesh-bound', () => {
  assert.equal(__test.routePolicy(request()).capability, 'intel.enrich');
  assert.equal(__test.routePolicy(new Request('https://intel.cyberdudebivash.com/api/intel/correlate')), null);
  assert.equal(__test.routePolicy(new Request('https://intel.cyberdudebivash.com/api/search', { method: 'POST' })), null);
});

test('server API-key record is the commercial source of truth', async () => {
  const principal = await __test.resolveMeshPrincipal(request('commercial', {
    ioc_value: '8.8.8.8',
    tier: 'MSSP',
    customer_id: 'attacker',
  }), envFor({ tier: 'ENTERPRISE', customer_id: 'cust-real', subscription_status: 'active' }).env);
  assert.deepEqual(principal, { sub: 'cust-real', tier: 'ENTERPRISE', source: 'api_key' });
});

function jwtFor(payload, secret) {
  const enc = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = enc({ alg: 'HS256', typ: 'JWT' });
  const body = enc(payload);
  const sig = createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

test('billing refund deny marker invalidates an already-issued mesh JWT immediately', async () => {
  const secret = 'j'.repeat(64);
  const token = jwtFor({ sub: 'cust-refunded', tier: 'PRO', exp: Math.floor(Date.now() / 1000) + 3600 }, secret);
  const req = new Request('https://intel.cyberdudebivash.com/api/intel/correlate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, 'X-Request-ID': 'jwt-refund-deny' },
    body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
  });
  const env = {
    CDB_JWT_SECRET: secret,
    SECURITY_HUB_KV: { async get() { return null; } },
    API_KEYS_KV: { async get(key) { return key === 'jwt_deny:cust-refunded' ? '{"reason":"refunded"}' : null; } },
  };
  await assert.rejects(() => __test.resolveMeshPrincipal(req, env), (err) => err?.code === 'mesh_subscription_denied' && err?.status === 403);
});

test('FREE credentials are rejected before a mesh reservation', async () => {
  const fixture = envFor({ tier: 'FREE', customer_id: 'free-1', subscription_status: 'active' });
  const result = await beginApexMeshBoundary(request('free-denied'), fixture.env);
  assert.equal(result.blockedResponse.status, 403);
  assert.equal((await result.blockedResponse.json()).error, 'mesh_paid_tier_required');
  assert.equal(fixture.calls.length, 0);
});

test('cancelled and expired credentials are rejected before mesh admission', async () => {
  for (const status of ['cancelled', 'expired']) {
    const fixture = envFor({ tier: 'PRO', customer_id: 'cust-1', subscription_status: status });
    const result = await beginApexMeshBoundary(request(`deny-${status}`), fixture.env);
    assert.equal(result.blockedResponse.status, 403);
    assert.match((await result.blockedResponse.json()).error, /subscription_/);
    assert.equal(fixture.calls.length, 0);
  }
});

test('same logical request ID produces the same tenant and mission identity', async () => {
  const firstFixture = envFor();
  const secondFixture = envFor();
  const first = await beginApexMeshBoundary(request('retry-key'), firstFixture.env);
  const second = await beginApexMeshBoundary(request('retry-key'), secondFixture.env);
  assert.equal(first.session.missionId, second.session.missionId);
  assert.equal(first.session.tenantId, second.session.tenantId);
  assert.equal(firstFixture.calls[0].body.correlation_id, 'retry-key');
  assert.equal(firstFixture.calls[0].body.local_plan, 'PRO');
  assert.match(firstFixture.calls[0].body.input_sha256, /^[0-9a-f]{64}$/);
});

test('different idempotency keys cannot alias to one mission', async () => {
  const tenant = 'sentinel-' + 'a'.repeat(48);
  const one = await __test.missionIdFor(tenant, 'request-one', request(), 'intel.enrich');
  const two = await __test.missionIdFor(tenant, 'request-two', request(), 'intel.enrich');
  assert.notEqual(one, two);
});

test('malformed correlation input is rejected before auth/metering', async () => {
  const fixture = envFor();
  const result = await beginApexMeshBoundary(request('bad-input', { ioc_type: 'ipv4' }), fixture.env);
  assert.equal(result.blockedResponse.status, 400);
  assert.equal((await result.blockedResponse.json()).error, 'ioc_value_required');
  assert.equal(fixture.calls.length, 0);
});

test('admission metadata mismatch fails closed', async () => {
  const fixture = envFor(undefined, (kind, payload) => kind === 'admit' ? { ...payload, tenant_id: 'sentinel-wrong' } : payload);
  const result = await beginApexMeshBoundary(request('bad-admit'), fixture.env);
  assert.equal(result.blockedResponse.status, 503);
});

test('actual gateway response is hashed and certified server-side', async () => {
  const fixture = envFor();
  const begin = await beginApexMeshBoundary(request('certify-1'), fixture.env);
  const original = Response.json({ status: 'ok', verdict: 'malicious', match_count: 2 }, { status: 200 });
  const certified = await completeApexMeshBoundary(begin.session, original, fixture.env);

  assert.equal(certified.status, 200);
  assert.equal(certified.headers.get('X-CDB-Mesh-Certified'), 'true');
  assert.equal(certified.headers.get('X-CDB-Mesh-Execution'), 'e'.repeat(64));
  assert.equal(fixture.calls[1].path, '/v1/mesh/complete');
  assert.equal(fixture.calls[1].body.outcome, 'succeeded');
  assert.match(fixture.calls[1].body.output_sha256, /^[0-9a-f]{64}$/);
});

test('completion must bind to the admitted execution', async () => {
  const fixture = envFor(undefined, (kind, payload) => kind === 'complete' ? { ...payload, execution_id: 'f'.repeat(64) } : payload);
  const begin = await beginApexMeshBoundary(request('certify-2'), fixture.env);
  const result = await completeApexMeshBoundary(begin.session, Response.json({ status: 'ok' }), fixture.env);
  assert.equal(result.status, 503);
  assert.equal((await result.json()).error, 'agent_mesh_unavailable');
});

test('service token identifies only sentinel-apex with mesh.invoke scope', async () => {
  const token = await __test.issueServiceToken({ APEX_MESH_SERVICE_KEY: 's'.repeat(64) }, 'sentinel-' + '1'.repeat(48), 1000);
  const [encoded] = token.split('.');
  const raw = new TextDecoder().decode(Uint8Array.from(encoded.match(/../g).map(v => Number.parseInt(v, 16))));
  const payload = JSON.parse(raw);
  assert.equal(payload.iss, 'cdb-apex-mesh');
  assert.equal(payload.sub, 'sentinel-apex');
  assert.deepEqual(payload.scopes, ['mesh.invoke']);
  assert.equal(payload.exp - payload.iat, 300);
});
