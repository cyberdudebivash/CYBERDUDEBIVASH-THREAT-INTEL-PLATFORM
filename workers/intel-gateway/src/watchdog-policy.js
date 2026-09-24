/**
 * CYBER WATCHDOG POLICY -- the one Watchdog entitlement and operations authority.
 *
 * What lives here: per-plan Watchdog FEATURES (watch/webhook quotas, which
 * plans get background evaluation, MSSP sub-tenants), the scheduler bounds,
 * the webhook delivery/retry policy, the signed-webhook contract version,
 * and the browser session scopes.
 *
 * What does NOT live here: prices. Plan prices come only from the gateway's
 * runtime pricing provider (pricing.js -> pricing-data.js), the same values
 * Razorpay charges and /api/pricing serves. A price literal in this file is
 * a defect; __tests__/watchdog-policy.test.js fails on one.
 *
 * Plain ES module, no JSON import: the gateway's two toolchains (wrangler's
 * esbuild 0.17.19 and Node 22 ESM) cannot share a JSON import. See
 * pricing-data.js for that history.
 */

export const WATCHDOG_POLICY_VERSION = "watchdog-policy-3";

// Plan ids match subscription tiers (FREE/PRO/ENTERPRISE/MSSP).
export const WATCHDOG_FEATURES = Object.freeze({
  FREE: Object.freeze({
    watches: 0, brief_items: 8, poller: false, events: false,
    webhooks: 0, background_evaluation: false, tenants: false,
  }),
  PRO: Object.freeze({
    watches: 25, brief_items: 50, poller: true, events: true,
    webhooks: 0, background_evaluation: true, tenants: false,
  }),
  ENTERPRISE: Object.freeze({
    watches: 200, brief_items: 200, poller: true, events: true,
    webhooks: 3, background_evaluation: true, tenants: false,
  }),
  MSSP: Object.freeze({
    watches: 200, brief_items: 200, poller: true, events: true,
    webhooks: 5, background_evaluation: true, tenants: true,
  }),
});

// Subscription states that remove every paid Watchdog feature.
export const DENIED_SUBSCRIPTION_STATES = Object.freeze([
  "cancelled", "refunded", "suspended", "expired", "revoked",
]);

// Autonomous evaluation. The Worker's existing 15-minute cron drives one
// scheduler cycle; no Queue, no new paid product.
export const SCHEDULER_POLICY = Object.freeze({
  // Ledgers evaluated per cron tick. Bounds CPU and DO requests per tick.
  max_subjects_per_run: 25,
  // Events one watch may create from one evaluation.
  max_events_per_watch_per_eval: 20,
  // Consecutive evaluation failures before a subject is parked until its
  // owner next changes a watch. Stops a broken ledger retrying forever.
  max_consecutive_failures: 5,
  // A planned subject not reported back within this window may be planned again.
  lease_seconds: 600,
  // Bounded run history kept for operators.
  run_history: 24,
});

// Webhook delivery. One policy for every delivery path.
export const DELIVERY_POLICY = Object.freeze({
  max_attempts: 4,
  // Delay before attempt n (index n-1). Attempt 1 is immediate.
  backoff_seconds: Object.freeze([0, 60, 300, 1800]),
  // Retry-After (429/503) is honored up to this bound.
  retry_after_max_seconds: 3600,
  timeout_ms: 5000,
  // Never retried. 410 also disables the destination.
  non_retryable_statuses: Object.freeze([400, 401, 403, 404, 405, 410, 413, 422]),
  retry_after_statuses: Object.freeze([429, 503]),
  // A 3xx is recorded as a failure. Redirects are never followed.
  redirect: "manual",
  // Destination auto-disable rules (state -> "failed").
  auto_disable_on_status: Object.freeze([410]),
  auto_disable_on_forbidden_address: true,
  auto_disable_after_consecutive_failed_events: 5,
  // Bounds per ledger.
  max_deliveries_per_run: 20,
  max_pending_deliveries: 500,
  lease_seconds: 60,
  // Challenge a new destination must answer before it receives intelligence.
  verification_ttl_seconds: 3600,
});

export const WEBHOOK_CONTRACT = Object.freeze({
  version: "2026-09-24",
  signature_scheme: "v1",
  // Receivers should reject a timestamp further than this from their clock.
  timestamp_tolerance_seconds: 300,
  headers: Object.freeze({
    event_id: "X-CDB-Watchdog-Event-ID",
    delivery_id: "X-CDB-Watchdog-Delivery-ID",
    timestamp: "X-CDB-Watchdog-Timestamp",
    signature: "X-CDB-Watchdog-Signature",
    version: "X-CDB-Watchdog-Version",
    attempt: "X-CDB-Watchdog-Attempt",
  }),
});

// Browser session. The long-lived API key is exchanged once for a short,
// audience- and scope-restricted token.
export const SESSION_POLICY = Object.freeze({
  audience: "cdb-watchdog",
  ttl_seconds: 900,
  // A session may be refreshed with itself, never beyond this since the key
  // exchange. Tier and MSSP tenant membership are re-read from the key only at
  // exchange, so this bounds how long a membership change can lag. Subscription
  // denial (jwt_deny) is immediate regardless.
  max_lifetime_seconds: 4 * 3600,
});

export const WATCHDOG_SCOPES = Object.freeze({
  READ: "watchdog:read",
  WATCHES_WRITE: "watchdog:watches:write",
  EVENTS_READ: "watchdog:events:read",
  EVENTS_ACK: "watchdog:events:ack",
  DESTINATIONS_WRITE: "watchdog:destinations:write",
});

export function featuresFor(tier) {
  return WATCHDOG_FEATURES[tier] || WATCHDOG_FEATURES.FREE;
}

export function scopesForTier(tier) {
  const f = featuresFor(tier);
  if (!f.events) return [];
  const scopes = [WATCHDOG_SCOPES.READ, WATCHDOG_SCOPES.WATCHES_WRITE, WATCHDOG_SCOPES.EVENTS_READ, WATCHDOG_SCOPES.EVENTS_ACK];
  if (f.webhooks > 0) scopes.push(WATCHDOG_SCOPES.DESTINATIONS_WRITE);
  return scopes;
}

/**
 * Emergency kill switch for every outbound Watchdog webhook request
 * (deliveries and verification challenges). Fail-closed: only the exact
 * string "true" enables delivery; absent, empty, "1", "TRUE" or anything else
 * disables it. wrangler.toml sets it to "true" explicitly for production. To
 * stop delivery without a code change: set the var to "false" and deploy, or
 * change it in the Cloudflare dashboard. Pending deliveries are kept, not
 * dropped, and resume on the next alarm after delivery is re-enabled.
 */
export const WEBHOOK_DELIVERY_FLAG = "WATCHDOG_WEBHOOK_DELIVERY_ENABLED";

export function webhookDeliveryEnabled(env) {
  return !!env && env[WEBHOOK_DELIVERY_FLAG] === "true";
}

// Watch Definition v2 and Exposure Profile v1 input bounds. Structure limits,
// not commercial quotas: plan watch counts stay in WATCHDOG_FEATURES.
export const DEFINITION_LIMITS = Object.freeze({
  name_max: 80,
  values_per_list: 8,
  total_values: 40,
  term_max: 48,
  package_max: 120,
});

export const PROFILE_LIMITS = Object.freeze({
  values_per_list: 25,
  total_values: 100,
  term_max: 64,
  package_max: 120,
});

// Preview bounds: one feed read (the same R2 GET as /brief), no write.
export const PREVIEW_POLICY = Object.freeze({
  max_items_scanned: 500,
  sample_size: 10,
  // A rule matching at least this share of the current feed gets a
  // deterministic "broad rule" warning. Nothing is blocked.
  broad_match_ratio: 0.5,
});
