/**
 * One commercial price authority, one Watchdog feature authority.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { RAZORPAY_TIER_PRICES, getPricingSnapshot } from "../pricing.js";
import { DENIED_SUBSCRIPTION_STATES, WATCHDOG_FEATURES, featuresFor, scopesForTier } from "../watchdog-policy.js";
import { effectiveTier, planPrice, quotaForTier, routeWatchdog, watchdogOffer } from "../cyber-watchdog.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, "..");
const CONTRACT = JSON.parse(fs.readFileSync(path.resolve(SRC, "../../../config/commercial-contract.json"), "utf8"));

test("Watchdog price == Razorpay charge == /api/pricing == canonical contract", () => {
  const snap = getPricingSnapshot();
  const offer = watchdogOffer();
  for (const [id, key] of [["PRO", "pro"], ["ENTERPRISE", "enterprise"], ["MSSP", "mssp"]]) {
    const plan = offer.plans.find((p) => p.id === id);
    assert.equal(plan.price_inr_monthly * 100, RAZORPAY_TIER_PRICES[id].monthly, id + " Razorpay paise");
    assert.equal(plan.price_inr_monthly * 100, snap.tiers[id].monthly, id + " /api/pricing");
    assert.equal(plan.price_usd_monthly, snap.tiers[id].usd_monthly, id + " /api/pricing usd");
    assert.equal(plan.price_inr_monthly, CONTRACT.tiers[key].inr_monthly, id + " contract inr");
    assert.equal(plan.price_usd_monthly, CONTRACT.tiers[key].usd_monthly, id + " contract usd");
  }
  assert.equal(offer.plans.find((p) => p.id === "FREE").price_usd_monthly, CONTRACT.tiers.free.usd_monthly);
});

test("mutating the one price source moves Watchdog with it (no second copy)", () => {
  const saved = { ...RAZORPAY_TIER_PRICES.PRO };
  try {
    RAZORPAY_TIER_PRICES.PRO.monthly = 123400;
    RAZORPAY_TIER_PRICES.PRO.usd_monthly = 15;
    const pro = watchdogOffer().plans.find((p) => p.id === "PRO");
    assert.equal(pro.price_inr_monthly, 1234);
    assert.equal(pro.price_usd_monthly, 15);
    assert.equal(pro.price_label, "$15/mo | INR 1,234/mo");
    assert.equal(quotaForTier("PRO").price_inr_monthly, 1234);
    // A missing paid row renders "Contract", never an invented number.
    delete RAZORPAY_TIER_PRICES.PRO.monthly;
    assert.equal(planPrice("PRO").inr_monthly, null);
    assert.equal(watchdogOffer().plans.find((p) => p.id === "PRO").price_label, "Contract");
  } finally {
    Object.assign(RAZORPAY_TIER_PRICES.PRO, saved);
  }
  assert.equal(watchdogOffer().plans.find((p) => p.id === "PRO").price_inr_monthly, CONTRACT.tiers.pro.inr_monthly);
});

test("no price literal in the Watchdog modules", () => {
  for (const f of ["cyber-watchdog.js", "watchdog-policy.js", "watchdog-scheduler.js", "watchdog-webhook.js"]) {
    const src = fs.readFileSync(path.join(SRC, f), "utf8");
    assert.doesNotMatch(src, /(usd|inr)_(monthly|annual)\s*:\s*[1-9]/, f);
    assert.doesNotMatch(src, /\$\s?(49|499|999)\b|INR\s?(4,?100|41,?600|83,?300)\b/, f);
  }
});

test("feature policy: FREE / PRO / ENTERPRISE / MSSP", () => {
  assert.deepEqual(Object.keys(WATCHDOG_FEATURES).sort(), ["ENTERPRISE", "FREE", "MSSP", "PRO"]);
  assert.equal(featuresFor("FREE").events, false);
  assert.equal(featuresFor("FREE").background_evaluation, false);
  assert.equal(featuresFor("PRO").background_evaluation, true);
  assert.equal(featuresFor("PRO").webhooks, 0);
  assert.ok(featuresFor("ENTERPRISE").webhooks > 0);
  assert.equal(featuresFor("ENTERPRISE").tenants, false);
  assert.equal(featuresFor("MSSP").tenants, true);
  assert.equal(featuresFor("NOT_A_TIER"), WATCHDOG_FEATURES.FREE);
  assert.equal(scopesForTier("FREE").length, 0);
  assert.equal(scopesForTier("PRO").includes("watchdog:destinations:write"), false);
  assert.equal(scopesForTier("MSSP").includes("watchdog:destinations:write"), true);
  for (const k of Object.values(WATCHDOG_FEATURES)) {
    for (const field of Object.keys(k)) assert.doesNotMatch(field, /price|usd|inr/);
  }
});

test("commercial states: expired, cancelled, refunded, suspended, revoked all lose paid Watchdog", async () => {
  assert.deepEqual([...DENIED_SUBSCRIPTION_STATES].sort(), ["cancelled", "expired", "refunded", "revoked", "suspended"]);
  for (const status of DENIED_SUBSCRIPTION_STATES) {
    for (const tier of ["PRO", "ENTERPRISE", "MSSP"]) {
      assert.equal(effectiveTier({ tier, subscription_status: status }), "FREE", tier + "/" + status);
      const res = await routeWatchdog({ path: "/api/watchdog/watches", method: "POST", auth: { tier, sub: "c", subscription_status: status }, body: { name: "x", keywords: ["y"] }, ledger: { mutate: async () => { throw new Error("must not be reached"); } } });
      assert.equal(res.status, 403);
    }
  }
  for (const err of ["key_expired", "subscription_cancelled", "subscription_revoked"]) {
    assert.equal(effectiveTier({ tier: "ENTERPRISE", error: err }), "FREE");
  }
  assert.equal(effectiveTier({ tier: "PRO", subscription_status: "active" }), "PRO");
});
