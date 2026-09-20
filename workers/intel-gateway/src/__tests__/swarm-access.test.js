import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  SWARM_CUSTOMER_TIERS,
  SWARM_MESH_CAPABILITY,
  SWARM_REQUIRED_SCOPE,
  evaluateSwarmPreflight,
  normalizeSwarmTier,
  tierAllowsSwarm,
} from '../swarm-access.js';

test('SWARM paid-tier contract is exactly PRO / ENTERPRISE / MSSP', () => {
  assert.deepEqual(SWARM_CUSTOMER_TIERS, ['PRO', 'ENTERPRISE', 'MSSP']);
  assert.equal(SWARM_MESH_CAPABILITY, 'intel.enrich');
  assert.equal(SWARM_REQUIRED_SCOPE, 'read:intel');
  for (const tier of ['PRO', 'ENTERPRISE', 'MSSP', 'pro', ' enterprise ']) {
    assert.equal(tierAllowsSwarm(tier), true, tier);
  }
  for (const tier of ['', 'FREE', 'TRIAL', 'ADMIN', null, undefined]) {
    assert.equal(tierAllowsSwarm(tier), false, String(tier));
  }
  assert.equal(normalizeSwarmTier(' pro '), 'PRO');
});

test('preflight requires both paid tier and canonical read:intel scope', () => {
  const ok = evaluateSwarmPreflight({ tier: 'ENTERPRISE', scopes: ['read:intel'] });
  assert.deepEqual(ok, {
    eligible: true,
    reason: null,
    tier: 'ENTERPRISE',
    tier_allowed: true,
    scope_allowed: true,
    required_scope: 'read:intel',
    capability: 'intel.enrich',
  });

  const free = evaluateSwarmPreflight({ tier: 'FREE', scopes: ['read:intel:preview'] });
  assert.equal(free.eligible, false);
  assert.equal(free.reason, 'swarm_paid_tier_required');

  const missingScope = evaluateSwarmPreflight({ tier: 'PRO', scopes: [] });
  assert.equal(missingScope.eligible, false);
  assert.equal(missingScope.reason, 'swarm_scope_required');
});

test('quota exhaustion is an explicit launch denial, not a fake entitlement failure', () => {
  const result = evaluateSwarmPreflight({
    tier: 'MSSP',
    scopes: ['read:intel'],
    quotaExhausted: true,
  });
  assert.equal(result.eligible, false);
  assert.equal(result.tier_allowed, true);
  assert.equal(result.scope_allowed, true);
  assert.equal(result.reason, 'daily_quota_exhausted');
});
