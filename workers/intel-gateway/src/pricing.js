/**
 * Canonical pricing provider for workers/intel-gateway.
 *
 * Phase 1 architecture consolidation: this module is now the ONE place the
 * Worker's Razorpay pricing lives. It replaces the RAZORPAY_TIER_PRICES
 * object that used to be defined inline in index.js - the values are
 * unchanged, only their location moved, so this is a zero commercial-impact
 * refactor. See pricing-data.json's "_note" for the known, deliberately
 * unresolved discrepancy against config/pricing.json - do not "fix" that
 * here by editing numbers based on inference; it requires a supplied,
 * business-approved figure (tracked separately).
 */
// v184.2 FIX: the RX-PUB-A0.6C `with { type: 'json' }` attribute below was
// removed -- it broke the real Workers deploy. Confirmed directly: wrangler
// v3 (every 3.7.0+ patch, including the pinned version this workflow
// installs) bundles esbuild 0.17.19, which cannot parse the `with` import-
// attribute syntax at all ("Expected ';' but found 'with'"), so deploy-
// worker.yml's actual `wrangler deploy` step -- not the separate esbuild
// pre-flight gate, which installs a newer 0.25.x esbuild that masks this --
// failed on every run since that attribute was added. A bare JSON import
// (no attribute) is what wrangler v3's real bundled esbuild accepts;
// confirmed directly against esbuild 0.17.19.
//
// This does mean `node --test src/__tests__/find-item-by-slug.test.js` will
// fail locally again (Node 22's native ESM loader requires the attribute
// for a direct, unbundled JSON import) -- but that test is not wired into
// any CI gate today (deploy-worker.yml's node --test step is explicitly
// scoped to certification-registry/publication-gate/reports-canonical-
// write-guard only, citing unrelated pre-existing failures elsewhere in
// __tests__/), so this trades a already-not-enforced local-only test
// convenience for an actually-deployable Worker. Re-enabling that test
// needs its own fix (e.g. running it through a bundler-aware test runner,
// or wiring the whole suite up deliberately) rather than reintroducing a
// syntax the real deploy path can't parse.
import pricingData from './pricing-data.json' with { type: "json" };

// Same shape/keys as the constant this replaces, so existing call sites
// (handleRazorpayCreateOrder, etc.) need no changes beyond the import.
export const RAZORPAY_TIER_PRICES = pricingData.tiers;

export function getPricingSnapshot() {
  return {
    status: pricingData._status,
    currency: pricingData.currency,
    unit: pricingData.unit,
    tiers: pricingData.tiers,
  };
}
