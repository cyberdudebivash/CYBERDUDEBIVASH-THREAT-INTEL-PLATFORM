// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- SUPER AGENT SWARM access contract
//
// Dependency-free, side-effect-free shared policy for the SWARM customer tier
// and capability boundary. The production mesh boundary and the read-only
// entitlement preflight both import this module so they cannot drift into
// different paid-tier decisions.
// =============================================================================

export const SWARM_REQUIRED_SCOPE = 'read:intel';
export const SWARM_MESH_CAPABILITY = 'intel.enrich';
export const SWARM_CUSTOMER_TIERS = Object.freeze(['PRO', 'ENTERPRISE', 'MSSP']);

const SWARM_CUSTOMER_TIER_SET = new Set(SWARM_CUSTOMER_TIERS);

export function normalizeSwarmTier(value) {
  return String(value || '').trim().toUpperCase();
}

export function tierAllowsSwarm(value) {
  return SWARM_CUSTOMER_TIER_SET.has(normalizeSwarmTier(value));
}

/**
 * Pure preflight decision. Credential validity / subscription lifecycle are
 * resolved by the gateway before this function is called. This function only
 * combines the already-authoritative tier, scope and non-mutating quota
 * snapshot into the launch eligibility exposed to the SWARM console.
 */
export function evaluateSwarmPreflight({ tier, scopes = [], quotaExhausted = false } = {}) {
  const normalizedTier = normalizeSwarmTier(tier);
  const tier_allowed = tierAllowsSwarm(normalizedTier);
  const scope_allowed = Array.isArray(scopes) && scopes.includes(SWARM_REQUIRED_SCOPE);
  const eligible = tier_allowed && scope_allowed && !quotaExhausted;

  let reason = null;
  if (!tier_allowed) reason = 'swarm_paid_tier_required';
  else if (!scope_allowed) reason = 'swarm_scope_required';
  else if (quotaExhausted) reason = 'daily_quota_exhausted';

  return Object.freeze({
    eligible,
    reason,
    tier: normalizedTier || 'FREE',
    tier_allowed,
    scope_allowed,
    required_scope: SWARM_REQUIRED_SCOPE,
    capability: SWARM_MESH_CAPABILITY,
  });
}
