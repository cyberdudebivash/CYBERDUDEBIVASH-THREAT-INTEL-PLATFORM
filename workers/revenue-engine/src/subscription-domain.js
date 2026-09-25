// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Subscription Domain (Phase 2)
// Subscription aggregate + evidence-based lifecycle state machine.
//
// Scope (locked): subscription domain only. Storage stays REVENUE_CRM_KV, the
// namespace already used by provisionCustomer(), patchInternalSub(), and
// handleSubExpireCheck() -- confirmed in the Phase 0 audit
// (docs/BILLING_ENTITLEMENT_ARCHITECTURE_AUDIT.md) as the live system, not the
// D1 `subscriptions` table. This module adds an aggregate + transition
// validation on top of that existing storage; it does not introduce a new
// storage layer.
//
// Explicitly out of scope for this pass: entitlement logic, pricing,
// authorization, customer/trial/usage/payment repositories, partner
// provisioning. See PHASE 2 lock in the implementation contract.
// =============================================================================

// SUB_STATUS is declared once, in index.js, and re-used here rather than
// redeclared -- same import pattern subscription-engine.js already uses for
// the same constant (see its own header comment).
import { SUB_STATUS } from "./index.js";

// -----------------------------------------------------------------------
// Evidence-based lifecycle graph.
//
// Built by tracing every place a SUB_STATUS value is actually *assigned* in
// production code today (subscription-engine.js's webhook switch, index.js's
// provisionCustomer() and handleSubExpireCheck()), not by design intent.
//
// Two of the eight declared SUB_STATUS values are never assigned anywhere in
// the current codebase -- confirmed by an exhaustive grep for
// `SUB_STATUS.EXPIRING` and `SUB_STATUS.RENEWED` across both revenue-engine
// source files, zero matches for either:
//   - EXPIRING: "expiring soon" is a *computed* condition (days_remaining <=
//     14 AND status === ACTIVE), never a stored status.
//   - RENEWED: a renewal (subscription.charged) sets status back to ACTIVE,
//     not a distinct RENEWED value.
// Per the Phase 2 lock ("only include states supported by the current
// production platform... do not invent future states that have no
// implementation today"), neither appears below. If a future phase actually
// starts assigning them, add the real transitions then, from real evidence.
//
// Built lazily (function, not a top-level const) rather than eagerly at
// module-evaluation time. index.js <-> subscription-engine.js <->
// subscription-domain.js form an import cycle (the first two already existed
// before this file); computing this object's keys off SUB_STATUS.* at this
// module's own top level would run before index.js has necessarily finished
// defining SUB_STATUS, throwing "Cannot access 'SUB_STATUS' before
// initialization" at Worker startup. Reproduced and confirmed with a
// standalone 3-module repro before writing it this way -- deferring
// construction into a function called only from inside Subscription's
// methods (i.e. only once a request or the cron actually runs, long after
// the whole module graph has finished initializing) avoids it entirely.
// -----------------------------------------------------------------------
let _transitions = null;
function getTransitions() {
  if (_transitions) return _transitions;
  _transitions = Object.freeze({
    [SUB_STATUS.TRIAL]:     Object.freeze([SUB_STATUS.ACTIVE, SUB_STATUS.CANCELLED, SUB_STATUS.EXPIRED]),
    // ACTIVE -> ACTIVE: subscription.charged (renewal) re-confirms ACTIVE with
    // new period dates -- a self-transition, not a no-op, so it's listed.
    [SUB_STATUS.ACTIVE]:    Object.freeze([SUB_STATUS.ACTIVE, SUB_STATUS.PAST_DUE, SUB_STATUS.SUSPENDED, SUB_STATUS.CANCELLED, SUB_STATUS.EXPIRED]),
    [SUB_STATUS.PAST_DUE]:  Object.freeze([SUB_STATUS.ACTIVE, SUB_STATUS.SUSPENDED, SUB_STATUS.CANCELLED]),
    // SUSPENDED -> ACTIVE: owner decision 2026-09-25 -- a halted Razorpay
    // subscription whose retried charge is later captured reactivates
    // automatically (recoverHaltedSubscription(), subscription-engine.js,
    // only on a signed webhook carrying a captured payment).
    [SUB_STATUS.SUSPENDED]: Object.freeze([SUB_STATUS.ACTIVE, SUB_STATUS.CANCELLED]),
    [SUB_STATUS.CANCELLED]: Object.freeze([]),
    [SUB_STATUS.EXPIRED]:   Object.freeze([]),
  });
  return _transitions;
}

// Exported read-only accessor -- used by tests/tooling that want to inspect
// or render the transition graph without reaching into a private module
// variable.
export function getSubscriptionTransitions() {
  return getTransitions();
}

export class SubscriptionTransitionError extends Error {
  constructor(fromStatus, toStatus) {
    super(`Invalid subscription transition: ${fromStatus} -> ${toStatus}`);
    this.name = "SubscriptionTransitionError";
    this.fromStatus = fromStatus;
    this.toStatus = toStatus;
  }
}

/**
 * Subscription aggregate. Wraps the exact plain-object record shape already
 * written by provisionCustomer() / patchInternalSub() (id, customer_id,
 * email, tier, billing_cycle, status, created_at, current_period_start,
 * current_period_end, trial_ends_at, payment_id, renewal_reminder_sent,
 * renewal_count, auto_renew, mssp_parent_id) -- does not change that shape,
 * only centralizes the logic that reads and validates it.
 */
export class Subscription {
  constructor(record) {
    if (!record) throw new Error("Subscription requires a record");
    this.record = record;
  }

  get id()               { return this.record.id; }
  get email()            { return this.record.email; }
  get tier()             { return this.record.tier; }
  get status()           { return this.record.status; }
  get billingCycle()     { return this.record.billing_cycle; }
  get currentPeriodEnd() { return this.record.current_period_end; }
  get autoRenew()        { return this.record.auto_renew !== false; }
  get renewalCount()     { return this.record.renewal_count || 0; }

  isActive()   { return this.status === SUB_STATUS.ACTIVE; }
  isTrial()    { return this.status === SUB_STATUS.TRIAL; }
  isTerminal() { return (getTransitions()[this.status] || []).length === 0; }

  daysUntilExpiry(now = new Date()) {
    if (!this.currentPeriodEnd) return Infinity;
    return Math.ceil((new Date(this.currentPeriodEnd) - now) / 86400000);
  }

  isPastPeriodEnd(now = new Date()) {
    return this.daysUntilExpiry(now) <= 0;
  }

  canTransitionTo(newStatus) {
    return (getTransitions()[this.status] || []).includes(newStatus);
  }

  /**
   * Validates the transition and returns the patch to apply (does not write
   * anything -- callers pass this to patchInternalSub() / a repository
   * save()). Throws SubscriptionTransitionError on an invalid transition
   * rather than silently applying it, so a caller can log + skip instead of
   * corrupting state.
   */
  withTransition(newStatus, extraPatch = {}) {
    if (!this.canTransitionTo(newStatus)) {
      throw new SubscriptionTransitionError(this.status, newStatus);
    }
    return { ...extraPatch, status: newStatus };
  }
}
