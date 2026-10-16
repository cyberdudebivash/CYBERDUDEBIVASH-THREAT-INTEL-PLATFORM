import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildScopeSet, handleCorrelate } from '../api-extensions.js';

const PAID = 'api/v1/intel/latest_pro.json';
const PUBLIC = 'api/v1/intel/latest.json';
const ENDPOINT = 'https://intel.cyberdudebivash.com/api/intel/correlate';

const advisory = {
  id: 'intel--evidence',
  title: 'Synthetic P0 regression advisory - never publish as live intelligence',
  severity: 'CRITICAL',
  risk_score: 9,
  processed_at: '2026-10-16T08:00:00Z',
  cve_id: 'CVE-2026-10001',
  actor_tag: 'SYNTHETIC-ACTOR',
  ttps: [{ technique_id: 'T1059' }],
  iocs: [
    { type: 'domain', value: 'evidence.invalid' },
    { type: 'ipv4', value: '192.0.2.20' },
    null,
    { type: 'domain', value: null },
  ],
};

function fixtureEnv(files = {}) {
  const reads = [];
  return {
    reads,
    env: {
      INTEL_R2: {
        async get(key) {
          reads.push(key);
          return Object.hasOwn(files, key) ? { async json() { return files[key]; } } : null;
        },
      },
      SECURITY_HUB_KV: { async get() { throw Error('public cached report index must not be consulted'); } },
    },
  };
}
function identity(tier = 'PRO', scopes = buildScopeSet(tier, null)) {
  return { tier, scopes };
}
async function query(ctx, value, auth = identity(), type = 'domain') {
  return handleCorrelate(new Request(ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ioc_value: value, ioc_type: type }),
  }), ctx.env, auth, 'p0-correlation-test');
}

test('PRO / ENTERPRISE / MSSP correlate paid indicator and preserve real eight-agent dependencies', async () => {
  for (const tier of ['PRO', 'ENTERPRISE', 'MSSP']) {
    const ctx = fixtureEnv({
      [PUBLIC]: { items: [{ ...advisory, iocs: undefined, ioc_count: 2 }] },
      [PAID]: { tier: 'PRO', items: [advisory] },
    });
    const response = await query(ctx, 'evidence.invalid', identity(tier));
    assert.equal(response.status, 200, tier);
    const body = await response.json();
    assert.equal(body.match_count, 1, tier);
    assert.equal(body.verdict, 'malicious', tier);
    assert.deepEqual(body.matches[0].ttps, [{ technique_id: 'T1059' }]);
    assert.equal(body.matches[0].actor_tag, 'SYNTHETIC-ACTOR');
    assert.equal(body.matches[0].cve_id, 'CVE-2026-10001');
    assert.equal(body.matches[0].report_id, 'intel--evidence');
    assert.deepEqual(ctx.reads, [PAID]);
  }
});

test('FREE and limited-scope PRO receive 403 before the private R2 read', async () => {
  for (const caller of [identity('FREE'), identity('PRO', ['export:csv'])]) {
    const ctx = fixtureEnv({ [PAID]: { items: [advisory] } });
    const response = await query(ctx, 'evidence.invalid', caller);
    assert.equal(response.status, 403);
    assert.deepEqual(ctx.reads, []);
    assert.doesNotMatch(await response.text(), /evidence\\.invalid/);
  }
});

test('missing paid artifact fails closed even if public listing has IOC metadata', async () => {
  const ctx = fixtureEnv({ [PUBLIC]: { items: [{ ...advisory, ioc_count: 2 }] } });
  const response = await query(ctx, 'evidence.invalid');
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error, 'correlation_feed_unavailable');
  assert.deepEqual(ctx.reads, [PAID]);
});

test('malformed, header-only or IOC-free paid source returns 503 rather than a false clean verdict', async () => {
  const malformed = [
    null,
    { items: [] },
    { items: [{ ...advisory, iocs: undefined }] },
    { items: [{ ...advisory, iocs: [null, { type: 'domain', value: '' }] }] },
    { items: [{ ...advisory, iocs: [{ type: null, value: 'evidence.invalid' }] }] },
  ];
  for (const body of malformed) {
    const ctx = fixtureEnv({ [PAID]: body });
    const response = await query(ctx, 'evidence.invalid');
    assert.equal(response.status, 503);
    assert.equal((await response.json()).error, 'correlation_feed_unavailable');
    assert.deepEqual(ctx.reads, [PAID]);
  }
});

test('a genuine absence in a valid paid inventory is a bounded no-match, not a lookup of public data', async () => {
  const ctx = fixtureEnv({
    [PAID]: { items: [advisory] },
    [PUBLIC]: { items: [{ ...advisory, iocs: [{ type: 'domain', value: 'unlisted.invalid' }] }] },
  });
  const response = await query(ctx, 'unlisted.invalid');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.match_count, 0);
  assert.deepEqual(body.matches, []);
  assert.deepEqual(ctx.reads, [PAID]);
});

test('malformed individual indicators never crash or create a false match', async () => {
  const ctx = fixtureEnv({ [PAID]: { items: [{ ...advisory, iocs: [
    null, 'garbage', { value: 'evidence.invalid' }, { type: 'domain', value: null },
    { type: 'domain', value: 'evidence.invalid' },
  ], ttps: 'badly shaped technique string' }] } });
  const response = await query(ctx, 'evidence.invalid');
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.match_count, 1);
  assert.deepEqual(body.matches[0].ttps, []);
});

test('R2 failures return a generic 500 without exposing private infrastructure details', async () => {
  const ctx = fixtureEnv();
  ctx.env.INTEL_R2.get = async key => {
    ctx.reads.push(key);
    return { async json() { throw Error('PRIVATE_R2_DIAGNOSTIC_SECRET'); } };
  };
  const response = await query(ctx, 'evidence.invalid');
  assert.equal(response.status, 500);
  const body = await response.text();
  assert.match(body, /correlate_failed/);
  assert.doesNotMatch(body, /PRIVATE_R2_DIAGNOSTIC_SECRET/);
  assert.deepEqual(ctx.reads, [PAID]);
});
