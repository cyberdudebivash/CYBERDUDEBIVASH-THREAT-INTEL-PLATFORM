import assert from "node:assert/strict";
import { test } from "node:test";
import {
  Subscription, SubscriptionTransitionError, getSubscriptionTransitions,
} from "../subscription-domain.js";

// ---------------------------------------------------------------------------
// Phase 2 (Razorpay Subscriptions): unit coverage for the subscription
// aggregate + lifecycle transition graph that subscription-engine.js's
// tryTransition() enforces on every webhook-driven state change. Pure logic,
// no KV/network -- same scope/style as intel-gateway's subscription-
// lifecycle.test.js, for the revenue-engine side of the same "what can a
// customer's subscription state legally become" question.
// ---------------------------------------------------------------------------

test("getSubscriptionTransitions: only the six SUB_STATUS values actually assigned in production code appear as keys", () => {
  const t = getSubscriptionTransitions();
  assert.deepEqual(
    Object.keys(t).sort(),
    ["active", "cancelled", "expired", "past_due", "suspended", "trial"].sort(),
    "EXPIRING and RENEWED are documented as never-assigned and must stay absent unless a real code path starts assigning them"
  );
});

test("getSubscriptionTransitions: lazy singleton, frozen at every level", () => {
  const a = getSubscriptionTransitions();
  const b = getSubscriptionTransitions();
  assert.equal(a, b);
  assert.ok(Object.isFrozen(a));
  assert.ok(Object.isFrozen(a.active));
});

test("Subscription: constructor throws without a record", () => {
  assert.throws(() => new Subscription(null), /requires a record/);
  assert.throws(() => new Subscription(undefined), /requires a record/);
});

test("Subscription: getters read straight through to the underlying record", () => {
  const sub = new Subscription({
    id: "sub_1", email: "a@b.com", tier: "PRO", status: "active",
    billing_cycle: "monthly", current_period_end: "2026-09-30T00:00:00Z",
    renewal_count: 3,
  });
  assert.equal(sub.id, "sub_1");
  assert.equal(sub.email, "a@b.com");
  assert.equal(sub.tier, "PRO");
  assert.equal(sub.status, "active");
  assert.equal(sub.billingCycle, "monthly");
  assert.equal(sub.currentPeriodEnd, "2026-09-30T00:00:00Z");
  assert.equal(sub.renewalCount, 3);
});

test("Subscription: renewalCount defaults to 0 when absent", () => {
  assert.equal(new Subscription({ status: "trial" }).renewalCount, 0);
});

test("Subscription: autoRenew defaults true unless explicitly false", () => {
  assert.equal(new Subscription({ status: "active" }).autoRenew, true);
  assert.equal(new Subscription({ status: "active", auto_renew: false }).autoRenew, false);
  assert.equal(new Subscription({ status: "active", auto_renew: true }).autoRenew, true);
});

test("Subscription: isActive/isTrial reflect status", () => {
  assert.equal(new Subscription({ status: "active" }).isActive(), true);
  assert.equal(new Subscription({ status: "trial" }).isActive(), false);
  assert.equal(new Subscription({ status: "trial" }).isTrial(), true);
  assert.equal(new Subscription({ status: "active" }).isTrial(), false);
});

test("Subscription: isTerminal is true only for cancelled/expired", () => {
  assert.equal(new Subscription({ status: "cancelled" }).isTerminal(), true);
  assert.equal(new Subscription({ status: "expired" }).isTerminal(), true);
  assert.equal(new Subscription({ status: "active" }).isTerminal(), false);
  assert.equal(new Subscription({ status: "suspended" }).isTerminal(), false, "suspended can still reach cancelled");
  assert.equal(new Subscription({ status: "trial" }).isTerminal(), false);
});

test("Subscription: daysUntilExpiry is Infinity with no current_period_end", () => {
  assert.equal(new Subscription({ status: "trial" }).daysUntilExpiry(), Infinity);
});

test("Subscription: daysUntilExpiry counts whole days from a fixed 'now'", () => {
  const now = new Date("2026-09-01T00:00:00Z");
  const sub = new Subscription({ status: "active", current_period_end: "2026-09-05T00:00:00Z" });
  assert.equal(sub.daysUntilExpiry(now), 4);
});

test("Subscription: isPastPeriodEnd true once current_period_end has passed", () => {
  const now = new Date("2026-09-10T00:00:00Z");
  const sub = new Subscription({ status: "active", current_period_end: "2026-09-05T00:00:00Z" });
  assert.equal(sub.isPastPeriodEnd(now), true);
});

test("Subscription: isPastPeriodEnd false with no current_period_end", () => {
  assert.equal(new Subscription({ status: "trial" }).isPastPeriodEnd(), false);
});

// Mirrors the exact graph declared in subscription-domain.js's getTransitions().
// A change here forces a conscious, evidence-based update to that graph (or
// vice versa) rather than a silent drift -- the same discipline the module's
// own header comment demands of itself.
const EXPECTED_TRANSITIONS = {
  trial:     ["active", "cancelled", "expired"],
  active:    ["active", "past_due", "suspended", "cancelled", "expired"],
  past_due:  ["active", "suspended", "cancelled"],
  suspended: ["active", "cancelled"],
  cancelled: [],
  expired:   [],
};
const ALL_STATUSES = Object.keys(EXPECTED_TRANSITIONS);

for (const [from, allowed] of Object.entries(EXPECTED_TRANSITIONS)) {
  test(`Subscription.canTransitionTo: from '${from}' allows exactly [${allowed.join(", ") || "nothing"}]`, () => {
    const sub = new Subscription({ status: from });
    for (const to of ALL_STATUSES) {
      assert.equal(sub.canTransitionTo(to), allowed.includes(to), `${from} -> ${to}`);
    }
  });
}

test("Subscription.withTransition: valid transition returns a patch carrying the new status", () => {
  const sub = new Subscription({ status: "trial" });
  const patch = sub.withTransition("active", { payment_id: "pay_123" });
  assert.deepEqual(patch, { payment_id: "pay_123", status: "active" });
});

test("Subscription.withTransition: invalid transition throws SubscriptionTransitionError instead of silently applying", () => {
  const sub = new Subscription({ status: "cancelled" });
  assert.throws(
    () => sub.withTransition("active"),
    (err) => {
      assert.ok(err instanceof SubscriptionTransitionError);
      assert.equal(err.name, "SubscriptionTransitionError");
      assert.equal(err.fromStatus, "cancelled");
      assert.equal(err.toStatus, "active");
      return true;
    }
  );
});
