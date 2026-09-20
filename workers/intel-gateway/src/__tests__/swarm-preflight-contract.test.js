import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const indexSource = readFileSync('src/index.js', 'utf8');
const meshSource = readFileSync('src/apex-mesh-boundary.js', 'utf8');

test('canonical SWARM preflight is routed before commercial quota mutation', () => {
  const route = indexSource.indexOf('path === "/api/v1/swarm/preflight"');
  const commercialGate = indexSource.indexOf('const firstPartyRead = isFirstPartyRead');
  const dailyMutation = indexSource.indexOf('const dq = await checkDailyQuota');
  assert.ok(route > 0, 'preflight route must exist');
  assert.ok(commercialGate > route, 'preflight must return before commercial plane selection');
  assert.ok(dailyMutation > route, 'preflight must not spend daily quota');
});

test('preflight has an isolated non-billable anti-abuse limiter', () => {
  assert.ok(indexSource.includes('const SWARM_PREFLIGHT_RATE_LIMIT_PER_MINUTE = 60'));
  assert.ok(indexSource.includes('rl:swarm-preflight:'));
  const route = indexSource.indexOf('path === "/api/v1/swarm/preflight"');
  const limiter = indexSource.indexOf('checkSwarmPreflightRateLimit(env, ip)', route);
  const handler = indexSource.indexOf('handleSwarmPreflight(env, auth)', route);
  assert.ok(limiter > route && limiter < handler, 'dedicated preflight limiter must run before entitlement response');
  assert.ok(indexSource.includes('reason: "preflight_rate_limited"'));
  assert.ok(indexSource.includes('"X-Preflight-RateLimit-Remaining"'));
});

test('preflight uses a read-only quota snapshot and never reflects credential material', () => {
  const start = indexSource.indexOf('async function handleSwarmPreflight');
  const end = indexSource.indexOf('\n}\n', start) + 3;
  const fn = indexSource.slice(start, end);

  assert.ok(fn.includes('readSwarmQuotaSnapshot(env, auth.key, auth.tier)'), 'preflight may use the credential internally to read its own quota partition');
  assert.ok(fn.includes('evaluateSwarmPreflight'));
  assert.ok(fn.includes('"Cache-Control": "no-store"'));
  assert.ok(!fn.includes('checkDailyQuota('), 'preflight must not call the mutating quota gate');

  // Credential material is legitimately consumed internally by
  // readSwarmQuotaSnapshot(); the leak boundary is the response body, not the
  // whole function. Scope the assertion to the object serialized by jsonResp()
  // so this test rejects a real response leak without false-positive failures
  // on safe internal authorization/quota lookups.
  const bodyStart = fn.indexOf('  const body = {');
  const statusStart = fn.indexOf('  const status =', bodyStart);
  assert.ok(bodyStart > 0 && statusStart > bodyStart, 'preflight response body boundary must remain explicit');
  const responseBody = fn.slice(bodyStart, statusStart);

  assert.ok(!responseBody.includes('auth.key'), 'preflight response must not serialize the raw credential');
  assert.ok(!responseBody.includes('auth.sub'), 'preflight response must not serialize customer identity');
});

test('mesh admission and preflight share one paid-tier/capability policy', () => {
  assert.ok(meshSource.includes("from './swarm-access.js'"));
  assert.ok(meshSource.includes('tierAllowsSwarm(tier)'));
  assert.ok(meshSource.includes('capability: SWARM_MESH_CAPABILITY'));
  assert.ok(!meshSource.includes("new Set(['PRO', 'ENTERPRISE', 'MSSP'])"));
});

test('resolved auth carries only safe lifecycle metadata needed by preflight', () => {
  assert.ok(indexSource.includes('credential_type: "api_key"'));
  assert.ok(indexSource.includes('subscription_status: record.subscription_status || "active"'));
  assert.ok(indexSource.includes('expires_at: record.expires_at || null'));
  assert.ok(indexSource.includes('credential_type: "bearer"'));
});
