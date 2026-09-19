import test from 'node:test';
import assert from 'node:assert/strict';
import { buildSwarmPreflightDecision, mapSwarmAuthError, readSwarmQuotaSnapshot } from '../swarm-preflight.js';

test('maps canonical auth failures to customer-safe SWARM reasons', () => {
  assert.deepEqual(mapSwarmAuthError('key_expired'), { reason: 'KEY_EXPIRED', status: 403 });
  assert.deepEqual(mapSwarmAuthError('subscription_suspended'), { reason: 'SUBSCRIPTION_SUSPENDED', status: 403 });
  assert.deepEqual(mapSwarmAuthError('subscription_cancelled'), { reason: 'SUBSCRIPTION_CANCELLED', status: 403 });
  assert.deepEqual(mapSwarmAuthError('auth_service_unavailable'), { reason: 'VERIFY_UNAVAILABLE', status: 503 });
});

test('denies missing, invalid and under-tier credentials', () => {
  assert.equal(buildSwarmPreflightDecision({ credentialPresented: false, auth: {}, quota: {} }).body.reason, 'AUTH_REQUIRED');
  assert.equal(buildSwarmPreflightDecision({ credentialPresented: true, auth: { error: 'invalid_key' }, quota: {} }).body.reason, 'KEY_INVALID');
  assert.equal(buildSwarmPreflightDecision({ credentialPresented: true, auth: { key: 'x', tier: 'FREE' }, quota: { available: true } }).body.reason, 'TIER_NOT_ENTITLED');
});

test('allows PRO/ENTERPRISE/MSSP only when quota is available', () => {
  for (const tier of ['PRO', 'ENTERPRISE', 'MSSP']) {
    const result = buildSwarmPreflightDecision({
      credentialPresented: true,
      auth: { key: 'customer-key', tier, kv: true },
      record: { subscription_status: 'active', expires_at: '2099-01-01T00:00:00.000Z' },
      quota: {
        available: true,
        per_minute: { limit: 120, used: 1, remaining: 119, exhausted: false },
        per_day: { limit: 5000, used: 1, remaining: 4999, exhausted: false, reset_utc: '2099-01-02T00:00:00.000Z' },
      },
    });
    assert.equal(result.http_status, 200);
    assert.equal(result.body.allowed, true);
    assert.equal(result.body.swarm_entitled, true);
    assert.equal(result.body.tier, tier);
    assert.equal(result.body.subscription_status, 'active');
  }
});

test('fails closed when quota authority is unavailable or exhausted', () => {
  const auth = { key: 'customer-key', tier: 'PRO' };
  const unavailable = buildSwarmPreflightDecision({ credentialPresented: true, auth, quota: { available: false } });
  assert.equal(unavailable.http_status, 503);
  assert.equal(unavailable.body.reason, 'VERIFY_UNAVAILABLE');

  const exhausted = buildSwarmPreflightDecision({
    credentialPresented: true,
    auth,
    quota: {
      available: true,
      per_minute: { limit: 120, used: 120, remaining: 0, exhausted: true },
      per_day: { limit: 5000, used: 12, remaining: 4988, exhausted: false },
    },
  });
  assert.equal(exhausted.http_status, 429);
  assert.equal(exhausted.body.reason, 'QUOTA_EXHAUSTED');
});

test('readSwarmQuotaSnapshot is read-only and uses canonical keyspaces', async () => {
  const seen = [];
  const env = {
    RATE_LIMIT_KV: {
      async get(key) {
        seen.push(key);
        if (key.startsWith('rl:')) return '7';
        if (key.startsWith('quota:daily:')) return '42';
        return null;
      },
    },
  };
  const now = new Date('2026-09-20T12:34:56.000Z');
  const quota = await readSwarmQuotaSnapshot(env, {
    identifier: 'customer-key',
    ip: '203.0.113.10',
    tier: 'PRO',
    rateLimits: { FREE: 30, PRO: 120, ENTERPRISE: 600, MSSP: 1200 },
    now,
  });
  assert.equal(quota.available, true);
  assert.equal(quota.per_minute.used, 7);
  assert.equal(quota.per_minute.remaining, 113);
  assert.equal(quota.per_day.used, 42);
  assert.equal(quota.per_day.remaining, 4958);
  assert.equal(seen.some((k) => k.startsWith('rl:203.0.113.10:')), true);
  assert.equal(seen.some((k) => k === 'quota:daily:customer-key:2026-09-20'), true);
});
