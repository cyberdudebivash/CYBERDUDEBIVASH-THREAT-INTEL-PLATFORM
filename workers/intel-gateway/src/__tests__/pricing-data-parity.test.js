/**
 * pricing-data.js must mirror pricing-data.json EXACTLY.
 *
 * pricing.js loads ./pricing-data.js (a plain ES module) because no form of a
 * direct JSON import parses on both wrangler 3.114.17's bundled esbuild
 * 0.17.19 and Node 22+ native ESM -- see pricing-data.js's header for the
 * full history and why every gateway deploy from 2026-09-20 07:48 failed.
 *
 * pricing-data.json remains the on-disk data that
 * scripts/verify_commercial_contract.py validates against
 * config/commercial-contract.json. That makes the .js file a MIRROR, and a
 * mirror that can drift is worse than no mirror: these are the paise amounts
 * Razorpay actually charges, so a divergence would mean billing customers an
 * amount no gate had approved.
 *
 * This test is the thing that makes the duplication safe. It compares the
 * two representations structurally -- every tier, every field, exact numeric
 * equality -- and fails on any difference, including a tier added to one file
 * and not the other.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PRICING_TIERS, PRICING_CURRENCY, PRICING_UNIT } from "../pricing-data.js";
import { RAZORPAY_TIER_PRICES } from "../pricing.js";

const SRC_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
const json = JSON.parse(readFileSync(join(SRC_DIR, "pricing-data.json"), "utf-8"));

test("pricing-data.js tiers are structurally identical to pricing-data.json", () => {
  assert.deepEqual(
    PRICING_TIERS,
    json.tiers,
    "pricing-data.js has drifted from pricing-data.json -- these are live " +
      "Razorpay charges; reconcile before shipping"
  );
});

test("currency and unit match", () => {
  assert.equal(PRICING_CURRENCY, json.currency);
  assert.equal(PRICING_UNIT, json.unit);
});

test("no tier exists in one representation but not the other", () => {
  assert.deepEqual(Object.keys(PRICING_TIERS).sort(), Object.keys(json.tiers).sort());
});

test("every tier's monthly/annual are integers in paise, not rupees or floats", () => {
  for (const [name, tier] of Object.entries(PRICING_TIERS)) {
    assert.ok(Number.isInteger(tier.monthly), `${name}.monthly must be an integer`);
    assert.ok(Number.isInteger(tier.annual), `${name}.annual must be an integer`);
    assert.ok(tier.monthly > 0, `${name}.monthly must be positive`);
    assert.ok(tier.annual > 0, `${name}.annual must be positive`);
  }
});

test("pricing.js re-exports exactly the mirrored tiers", () => {
  // Guards the indirection introduced with pricing-data.js: RAZORPAY_TIER_PRICES
  // is what handleRazorpayCreateOrder charges from, so it must still be the
  // same object the contract gate validates.
  assert.deepEqual(RAZORPAY_TIER_PRICES, json.tiers);
});

test("known production paise values are unchanged by the module refactor", () => {
  // Pinned literals: if a future edit changes what Razorpay charges, that is a
  // billing decision and must fail here rather than pass silently.
  assert.equal(RAZORPAY_TIER_PRICES.PRO.monthly, 410000);
  assert.equal(RAZORPAY_TIER_PRICES.PRO.annual, 4100000);
  assert.equal(RAZORPAY_TIER_PRICES.ENTERPRISE.monthly, 4160000);
  assert.equal(RAZORPAY_TIER_PRICES.ENTERPRISE.annual, 41600000);
  assert.equal(RAZORPAY_TIER_PRICES.MSSP.monthly, 8330000);
  assert.equal(RAZORPAY_TIER_PRICES.MSSP.annual, 83300000);
});
