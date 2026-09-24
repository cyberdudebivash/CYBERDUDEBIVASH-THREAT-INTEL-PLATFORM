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
// BUNDLER-AGNOSTIC PRICING IMPORT (supersedes the v184.2 / "Node 24 import
// attributes" flip-flop, which broke the deploy each time it was reversed).
//
// This used to import ./pricing-data.json directly, and no form of that
// import worked on both toolchains at once:
//
//   with { type: "json" }   Node 22+ ESM: OK   |  esbuild 0.17.19: parse error
//   bare (no attribute)     esbuild 0.17.19: OK |  Node 22+ ESM: ERR_IMPORT_
//                                                  ATTRIBUTE_MISSING
//
// esbuild 0.17.19 is the version bundled in wrangler 3.114.17, which
// deploy-worker.yml pins and which runs the real `wrangler deploy`. Every
// gateway deploy from 2026-09-20 07:48 onward failed on that single line;
// the workflow's separate esbuild pre-flight installs a newer 0.25.x that
// parses `with` fine, so it masked the break rather than catching it.
//
// ./pricing-data.js is a plain ES module, so it needs no import attribute
// and BOTH toolchains load it unconditionally. pricing-data.json is
// unchanged and remains what scripts/verify_commercial_contract.py
// validates against config/commercial-contract.json;
// __tests__/pricing-data-parity.test.js fails if the .js mirror and the
// .json ever diverge, so the two cannot drift apart silently.
//
// Values are IDENTICAL -- this changes how the data is loaded, never what
// Razorpay charges.
import {
  PRICING_TIERS as pricingTiers,
  PRICING_CURRENCY,
  PRICING_UNIT,
  PRICING_STATUS,
} from './pricing-data.js';

// Same shape/keys as the constant this replaces, so existing call sites
// (handleRazorpayCreateOrder, etc.) need no changes beyond the import.
export const RAZORPAY_TIER_PRICES = pricingTiers;

// /api/pricing response. Built only from the pricing-data.js mirror: the
// previous body read an undefined `pricingData` left over from the removed
// JSON import, so every /api/pricing request threw a ReferenceError (500).
export function getPricingSnapshot() {
  return {
    status: PRICING_STATUS,
    currency: PRICING_CURRENCY,
    unit: PRICING_UNIT,
    tiers: pricingTiers,
  };
}
