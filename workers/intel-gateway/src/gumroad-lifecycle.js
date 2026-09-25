// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Gumroad Lifecycle (pure module)
//
// Extracted from handleWebhookGumroad() (index.js) for the same reason
// subscription-lifecycle.js was extracted (see that file's header comment):
// zero imports of its own, so it can be unit-tested under plain
// `node --test` without pulling in index.js's full import chain (which
// transitively fails Node's native ESM loader via pricing.js's
// pricing-data.json import). Pure decision logic only -- no KV, no
// network. handleWebhookGumroad() is the only production caller.
//
// inferGumroadTier() is a straight move of the tier-inference logic that
// already lived inline in handleWebhookGumroad() (Principle 3: single
// source of truth, not a second implementation).
//
// isGumroadCancellationEvent() covers a gap the existing webhook never
// handled: Gumroad's "Subscription updated" ping (posted to the same
// webhook URL as the "sale" ping) carries `cancelled: "true"` when the
// buyer cancels auto-renewal, or `ended: "true"` once the subscription
// period actually ends -- neither field was read before, so a Gumroad
// subscription cancellation never revoked platform access.
// =============================================================================

// DEPRECATED 2026-09-25 (S16): no longer decides what a sale grants.
// handleWebhookGumroad() now takes tier and cycle from the product catalog
// (gumroad-products.js); a product outside it is ignored or held, never
// guessed from its name. Kept exported (index.js re-exports it) for existing
// importers; remove in the next major P-layer.
export function inferGumroadTier(productName, variants) {
  const pnl = `${productName || ""}${variants || ""}`.toLowerCase();
  // Bug fix: the original inline check also matched the bare substring
  // "ent", which false-positives on every product name here -- all of them
  // are branded "CYBERDUDEBIVASH SENTINEL APEX ..." and "Sentinel" itself
  // contains "ent". That silently misclassified every PRO sale as
  // ENTERPRISE. "enterprise" (the full word) is unambiguous and sufficient.
  if (pnl.includes("mssp") || pnl.includes("white-label")) return "MSSP";
  if (pnl.includes("enterprise")) return "ENTERPRISE";
  return "PRO";
}

/**
 * Gumroad sends `recurrence` on subscription products: "monthly",
 * "quarterly", "biannually", "yearly", or "every_two_years" -- all 5
 * preserved here (issue #287) and given a real cycleDays bucket in
 * provisionApiKey (index.js), rather than collapsing anything other than
 * monthly/yearly to "monthly", which silently expired a quarterly/biannual/
 * every-two-years subscriber's key after only 30 days once
 * SUBSCRIPTION_EXPIRY_ENABLED is turned on. No currently configured Gumroad
 * product uses those recurrences (GUMROAD_URLS in upgrade.html only lists
 * monthly/annual variants) or Razorpay plan (RAZORPAY_PLAN_ID_* is
 * monthly/annual only) -- this is forward-compatible, not fixing a live
 * incident -- but it's now correct if one is ever added, rather than merely
 * documented as a known gap.
 * @param {string} recurrence
 * @param {string} productName
 * @param {string} variants
 * @returns {"monthly"|"quarterly"|"biannual"|"annual"|"every_two_years"}
 */
// DEPRECATED 2026-09-25 (S16) for sale decisions, like inferGumroadTier():
// the catalog entry carries the cycle. Kept exported for existing importers.
export function inferGumroadBillingCycle(recurrence, productName, variants) {
  const r = String(recurrence || "").toLowerCase();
  if (r === "yearly" || r === "annually" || r === "annual") return "annual";
  if (r === "quarterly") return "quarterly";
  if (r === "biannually" || r === "biannual") return "biannual";
  if (r === "every_two_years" || r === "every-two-years") return "every_two_years";
  const pnl = `${productName || ""}${variants || ""}`.toLowerCase();
  return pnl.includes("annual") ? "annual" : "monthly";
}

/**
 * @param {Record<string, string>} formData raw Gumroad Ping form fields
 * @returns {boolean} true when this ping represents a subscription
 *   cancellation or end-of-term event, not a new sale
 */
export function isGumroadCancellationEvent(formData) {
  if (!formData) return false;
  const cancelled = String(formData.cancelled || "").toLowerCase();
  const ended = String(formData.ended || "").toLowerCase();
  return cancelled === "true" || ended === "true";
}

/**
 * `cancelled: "true"` alone means the buyer turned off auto-renewal -- the
 * current paid period is not affected, so access must continue until it
 * actually ends. Only `ended: "true"` (Gumroad's ping once the subscription
 * has actually terminated) means access should be revoked now. Without this
 * distinction, a customer who cancels on day 1 of a 30-day period would
 * lose access to 29 days they already paid for.
 * @param {Record<string, string>} formData raw Gumroad Ping form fields
 * @returns {boolean} true only once access should actually be revoked
 */
export function isGumroadAccessRevokingEvent(formData) {
  if (!formData) return false;
  return String(formData.ended || "").toLowerCase() === "true";
}

// ---------------------------------------------------------------------------
// Gumroad memberships (recurring), 2026-09-25 -- owner commercial policy:
// recurring services are sold as recurring subscriptions, never as one-time
// "30-day grants". Gumroad posts a "sale" ping for EVERY membership charge
// (a new sale_id each time, the same subscription_id, is_recurring_charge
// "true"), and pings again with refunded / disputed when money goes back.
// ---------------------------------------------------------------------------

/** Days of access per billing cycle. Single table for every provider (provisionApiKey). */
export const BILLING_CYCLE_DAYS = Object.freeze({ monthly: 30, quarterly: 90, biannual: 180, annual: 365, every_two_years: 730 });

const _true = (v) => String(v || "").toLowerCase() === "true";

/**
 * What a Gumroad ping asks the platform to do.
 *   "refund"       money returned for this sale: revoke
 *   "dispute"      chargeback opened (and not won): revoke
 *   "cancellation" membership cancelled / ended (see isGumroadAccessRevokingEvent)
 *   "renewal"      a membership's recurring charge: extend the existing key
 *   "sale"         a first purchase: provision a key
 * Money-back signals are checked first: a refund ping repeats the sale's
 * other fields, including is_recurring_charge.
 */
export function classifyGumroadPing(formData) {
  if (!formData) return "sale";
  if (_true(formData.refunded)) return "refund";
  if (_true(formData.disputed) && !_true(formData.dispute_won)) return "dispute";
  if (isGumroadCancellationEvent(formData)) return "cancellation";
  if (_true(formData.is_recurring_charge)) return "renewal";
  return "sale";
}

/**
 * New expiry after a paid renewal: one cycle added to whichever is later,
 * the current expiry (charged early: no paid time lost) or the charge time
 * (charged after a lapse: the new period starts now, not in the past).
 */
export function renewedExpiry(existingExpiresAt, saleTimestamp, billingCycle, nowMs = Date.now()) {
  const days = BILLING_CYCLE_DAYS[billingCycle] || BILLING_CYCLE_DAYS.monthly;
  const existing = Date.parse(existingExpiresAt || "");
  const charged = Date.parse(saleTimestamp || "");
  const start = Math.max(Number.isFinite(existing) ? existing : 0, Number.isFinite(charged) ? charged : nowMs);
  return new Date(start + days * 86400000).toISOString();
}

/**
 * A renewal charge restores access for keys that lapsed or were cancelled
 * (a restarted membership), never for keys an operator or a refund denied:
 * those need an explicit admin reactivation.
 */
export function renewalMayReactivate(subscriptionStatus) {
  return !["refunded", "suspended"].includes(String(subscriptionStatus || ""));
}
