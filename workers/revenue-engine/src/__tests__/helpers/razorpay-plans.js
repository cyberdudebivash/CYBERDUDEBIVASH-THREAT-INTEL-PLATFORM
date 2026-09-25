// Test-only Razorpay Plan fixtures (S19). A fake Razorpay answers
// GET /v1/plans/{id} with the Plan a correctly configured account would hold:
// the canonical INR amount for the tier/cycle the fixture id names: it must
// contain "mssp", "enterprise"/"_ent_" or neither (PRO), and "annual" for a
// yearly Plan.
import { canonicalPlanPaise } from "../../subscription-engine.js";

export function tierCycleFromPlanId(id) {
  const s = String(id).toLowerCase();
  const tier = /mssp/.test(s) ? "MSSP" : /enterprise|_ent_/.test(s) ? "ENTERPRISE" : "PRO";
  const cycle = /annual/.test(s) ? "annual" : "monthly";
  return { tier, cycle };
}

export function canonicalPlan(id, overrides = {}) {
  const { tier, cycle } = tierCycleFromPlanId(id);
  return {
    id, entity: "plan", period: cycle === "annual" ? "yearly" : "monthly", interval: 1,
    item: { amount: canonicalPlanPaise(tier, cycle), currency: "INR", name: `${tier} ${cycle}` },
    ...overrides,
  };
}

/** Response for a GET /v1/plans/{id} URL, or null when the URL is not one. */
export function planResponse(url) {
  const m = String(url).match(/\/v1\/plans\/([^/?]+)$/);
  return m ? Response.json(canonicalPlan(decodeURIComponent(m[1]))) : null;
}
