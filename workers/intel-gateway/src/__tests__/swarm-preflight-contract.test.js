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

test('preflight uses a read-only quota snapshot and never reflects credential material', () => {
  const start = indexSource.indexOf('async function handleSwarmPreflight');
  const end = indexSource.indexOf('\n}\n', start) + 3;
  const fn = indexSource.slice(start, end);
  assert.ok(fn.includes('readSwarmQuotaSnapshot'));
  assert.ok(fn.includes('evaluateSwarmPreflight'));
  assert.ok(fn.includes('"Cache-Control": "no-store"'));
  assert.ok(!fn.includes('checkDailyQuota('), 'preflight must not call the mutating quota gate');
  assert.ok(!fn.includes('auth.key,'), 'preflight response must not serialize the raw credential');
  assert.ok(!fn.includes('auth.sub'), 'preflight response must not serialize customer identity');
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
