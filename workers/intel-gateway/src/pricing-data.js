/**
 * Canonical pricing VALUES for workers/intel-gateway, as a plain ES module.
 *
 * WHY THIS FILE EXISTS (and is not a JSON import)
 * ----------------------------------------------
 * pricing.js used to import ./pricing-data.json directly. That import had no
 * form that worked on both of this repo's toolchains, and the two "fixes"
 * kept undoing each other:
 *
 *   import ... with { type: "json" }   Node 22+ native ESM: OK
 *                                       esbuild 0.17.19:     FAILS to parse
 *                                       ("Expected ';' but found 'with'")
 *
 *   import ... (bare, no attribute)     esbuild 0.17.19:     OK
 *                                       Node 22+ native ESM: FAILS
 *                                       (ERR_IMPORT_ATTRIBUTE_MISSING)
 *
 * esbuild 0.17.19 is not incidental: it is the version bundled inside
 * wrangler 3.114.17, which deploy-worker.yml pins and which performs the
 * REAL `wrangler deploy`. (The workflow's separate esbuild pre-flight gate
 * installs a newer 0.25.x that parses `with` fine, which is why that gate
 * stayed green while production deploys failed -- it masked the break.)
 *
 * History: the attribute was added, removed in v184.2 to unbreak deploys,
 * then re-added in "fix(gateway): support Node 24 JSON import attributes"
 * to unbreak Node -- which broke the deploy again. Every gateway deploy
 * from 2026-09-20 07:48 onward failed on this one line.
 *
 * A plain .js module ends the oscillation: it needs no import attribute, so
 * BOTH toolchains load it unconditionally. No bundler feature is required.
 *
 * SOURCE OF TRUTH
 * ---------------
 * config/commercial-contract.json is canonical (see pricing-data.json's
 * "_authority"). pricing-data.json remains the on-disk data that
 * scripts/verify_commercial_contract.py validates against that contract --
 * it is unchanged and still authoritative for tooling. This module mirrors
 * its `tiers` exactly, and __tests__/pricing-data-parity.test.js fails if
 * the two ever diverge by even one paise, so the mirror cannot silently
 * drift. Edit pricing-data.json, then mirror the change here; the parity
 * test will tell you if you forget.
 *
 * VALUES ARE UNCHANGED by the introduction of this file -- these are the
 * exact paise amounts Razorpay charges today, copied verbatim.
 */

export const PRICING_CURRENCY = "INR";
export const PRICING_UNIT = "paise";

export const PRICING_TIERS = {
  PRO:          { monthly: 410000,   annual: 4100000,   label: "Sentinel APEX PRO" },
  ENTERPRISE:   { monthly: 4160000,  annual: 41600000,  label: "Sentinel APEX ENTERPRISE" },
  MSSP:         { monthly: 8330000,  annual: 83300000,  label: "Sentinel APEX MSSP" },
};

export default { currency: PRICING_CURRENCY, unit: PRICING_UNIT, tiers: PRICING_TIERS };
