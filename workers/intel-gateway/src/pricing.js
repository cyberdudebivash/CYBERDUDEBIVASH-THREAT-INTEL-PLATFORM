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
import pricingData from './pricing-data.json';

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
