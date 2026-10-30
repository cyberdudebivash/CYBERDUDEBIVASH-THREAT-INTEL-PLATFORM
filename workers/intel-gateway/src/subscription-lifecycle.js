// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Subscription Lifecycle (pure module)
//
// v185.6 (Mission v185.0 Phase 3): extracted from index.js into its own
// dependency-free file specifically so it is unit-testable in CI. Before
// this extraction, workers/intel-gateway/src/__tests__/subscription-
// lifecycle.test.js imported evaluateKeyRecordAccess() from ../index.js,
// which transitively imports pricing.js, which imports pricing-data.json
// without a `with {type:'json'}` attribute -- fine for wrangler/esbuild's
// bundler, but Node's native `node --test` ESM loader rejects it outright
// (ERR_IMPORT_ATTRIBUTE_MISSING), so the test could never actually run.
// Rather than touch pricing.js's import statement (real risk: esbuild's
// bundling behavior for that file is exactly what PR #185.x's Enterprise/
// PRO pricing-conflict fixes depend on being stable), this file has ZERO
// imports of its own -- no KV, no network, no other Worker module -- so it
// can be imported directly by both index.js (production) and the test file
// (CI) without ever touching the pricing.js/pricing-data.json chain.
//
// index.js re-exports these three names unchanged so every existing
// production call site (resolveAuth, handleLogin,
// applySubscriptionStatusChange, the key-rotation endpoint) keeps working
// with no changes beyond the import line -- this is a pure move, not a
// behavior change. Principle 3 (single source of truth) still holds:
// evaluateKeyRecordAccess() has exactly one implementation, here.
// =============================================================================

// SIX canonical states -- deliberately no "trialing": this platform has no
// real trial product (PR #251 confirmed "Start N-Day Trial" charges the
// full price immediately, no distinct trial period exists in the backend).
//
// `subscription_status` is a NEW, OPTIONAL field on API_KEYS_KV records.
// Every key provisioned before v185.5 has no such field -- per
// SUBSCRIPTION_STATUS_DENY_STATES / evaluateKeyRecordAccess() below, an
// absent field is treated identically to "active", so no existing valid
// customer key's behavior changes. This is additive, not a migration:
// nothing is backfilled, nothing is required to change on old records.
//
// PAST_DUE is deliberately NOT a deny state here: the mission's own
// required-deny list is expired/cancelled-after-end/refunded/suspended/
// revoked/downgraded -- past_due is the conventional SaaS "payment failed,
// grace period before hard cutoff" state, and denying on it immediately
// would cut off a customer over a single failed charge with no recovery
// window. Access stays allowed while past_due; only the terminal states
// below deny.
export const SUBSCRIPTION_STATUS_DENY_STATES = new Set(["cancelled", "refunded", "suspended", "expired"]);
export const SUBSCRIPTION_STATUS_VALID_STATES = new Set(["active", "past_due", "cancelled", "expired", "refunded", "suspended"]);

/**
 * Pure decision function, no KV/network access. resolveAuth() and
 * handleLogin() (index.js) are the only production callers -- this is not
 * a second decision path.
 * @param {{expires_at?: string|null, subscription_status?: string}} record
 * @returns {{allowed: boolean, error: string|null}}
 */
export function evaluateKeyRecordAccess(record) {
  if (record.expires_at && new Date(record.expires_at) < new Date()) {
    return { allowed: false, error: "key_expired" };
  }
  if (record.subscription_status) {
    if (!SUBSCRIPTION_STATUS_VALID_STATES.has(record.subscription_status)) {
      return { allowed: false, error: "subscription_status_invalid" };
    }
    if (SUBSCRIPTION_STATUS_DENY_STATES.has(record.subscription_status)) {
      return { allowed: false, error: `subscription_${record.subscription_status}` };
    }
  }
  return { allowed: true, error: null };
}


/**
 * Resolve a customer entitlement from an explicit canonical tier only.
 * Missing/malformed tier records must NEVER inherit PRO. Own properties are
 * required: JavaScript prototype names (e.g. "constructor") are not plans.
 * Keeping this pure allows both Worker and CI to use the same decision.
 *
 * null signals that the caller must reject the credential / SSO configuration.
 */
export function resolveCanonicalTier(tier, tiers) {
  if (typeof tier !== "string" || !tiers || typeof tiers !== "object" ||
      !Object.prototype.hasOwnProperty.call(tiers, tier)) return null;
  const value = tiers[tier];
  return typeof value === "string" && value === tier ? value : null;
}
