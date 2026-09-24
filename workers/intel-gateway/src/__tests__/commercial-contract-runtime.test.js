/**
 * P0 commercial-contract convergence (2026-09-24) -- runtime behaviour.
 *
 * config/commercial-contract.json is the one commercial authority. These
 * tests pin what real callers receive from the production router:
 *
 *   1. GET /api/pricing answers 200 with the Razorpay paise table. It was
 *      HTTP 500 in production: getPricingSnapshot() read an undefined
 *      `pricingData` binding left over from the removed JSON import.
 *   2. POST /api/leads/trial answers 410 Gone and writes NOTHING -- the
 *      contract's trial_policy is "No free trial" for every tier, but this
 *      route minted a live 7-day PRO API key from an email alone.
 *   3. Upgrade copy returned to FREE/PRO API callers quotes the contracted
 *      quotas (FREE 50/day, PRO 5,000/day, ENTERPRISE 50,000/day), never
 *      "unlimited", and never offers MSSP-only white-label to Enterprise.
 *
 * scripts/verify_commercial_contract.py (C62+/C63+) gates the same values
 * statically; these tests prove the running code behaves accordingly.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import worker from "../index.js";
import {
  REVENUE_CONFIG,
  TRIAL_DISCONTINUED_BODY,
  buildUpgradeTrigger,
  handleLeadCapture,
} from "../revenue-enforcement.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const CONTRACT = JSON.parse(
  readFileSync(join(HERE, "..", "..", "..", "..", "config", "commercial-contract.json"), "utf-8"),
);
const PRICING_DATA = JSON.parse(readFileSync(join(HERE, "..", "pricing-data.json"), "utf-8"));

function fakeKV() {
  const m = new Map();
  return {
    store: m,
    get: async (k, o) => {
      const v = m.get(k);
      if (v === undefined) return null;
      return o === "json" || (o && o.type === "json") ? JSON.parse(v) : v;
    },
    put: async (k, v) => { m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    list: async () => ({ keys: [], list_complete: true }),
  };
}

function harness() {
  const edge = new Map();
  globalThis.caches = {
    default: {
      match: async (req) => edge.get(req.url),
      put: async (req, res) => { edge.set(req.url, res); },
    },
  };
  const env = {
    INTEL_R2: { get: async () => null },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(),
    ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const call = async (p, init = {}) => {
    const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com${p}`, init), env, ctx);
    await Promise.allSettled(waits);
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { body = text; }
    return { res, body };
  };
  return { call, env };
}

// --- 1. /api/pricing ---------------------------------------------------------

test("GET /api/pricing answers 200 with the canonical paise table (was 500 in production)", async () => {
  const { call } = harness();
  const { res, body } = await call("/api/pricing");
  assert.equal(res.status, 200, `expected 200, got ${res.status}: ${JSON.stringify(body)}`);
  assert.equal(body.currency, "INR");
  assert.equal(body.unit, "paise");
  assert.deepEqual(body.tiers, PRICING_DATA.tiers);
  for (const tier of ["pro", "enterprise", "mssp"]) {
    const row = body.tiers[tier.toUpperCase()];
    assert.equal(row.monthly, CONTRACT.tiers[tier].inr_monthly * 100, `${tier} monthly paise`);
    assert.equal(row.annual, CONTRACT.tiers[tier].inr_annual * 100, `${tier} annual paise`);
  }
});

// --- 2. no free trial --------------------------------------------------------

test("contract states no free trial for every tier (precondition for the 410 below)", () => {
  for (const [id, tier] of Object.entries(CONTRACT.tiers)) {
    assert.match(tier.trial_policy, /^No free trial\./, `${id}.trial_policy`);
  }
});

test("POST /api/leads/trial answers 410 Gone and issues no API key", async () => {
  const { call, env } = harness();
  const { res, body } = await call("/api/leads/trial", {
    method: "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
    body: JSON.stringify({ email: "buyer@example.com" }),
  });
  assert.equal(res.status, 410);
  assert.equal(body.error, "trial_discontinued");
  assert.equal(body.upgrade_url, TRIAL_DISCONTINUED_BODY.upgrade_url);
  // Nothing may be provisioned: no key record, no trial record, no nudge.
  assert.equal(env.API_KEYS_KV.store.size, 0, "no API key may be written");
  for (const k of env.SECURITY_HUB_KV.store.keys()) {
    assert.ok(!/^(trial|nudge):/.test(k), `unexpected trial state written: ${k}`);
  }
  assert.ok(!("trial" in body) && !JSON.stringify(body).includes("cdb_trial_"));
});

test("lead capture no longer advertises a trial offer (shape kept, available:false)", async () => {
  const req = new Request("https://intel.cyberdudebivash.com/api/leads/capture", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "lead@example.com" }),
  });
  const res = await handleLeadCapture(req, {}, "rid-test");
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.trial_offer.available, false);
  assert.doesNotMatch(body.trial_offer.message, /\d+-day|no credit card/i);
});

// --- 3. contracted quotas in upgrade copy -----------------------------------

test("REVENUE_CONFIG.LIMITS equals contract requests_per_minute / requests_per_day", () => {
  for (const [id, tier] of Object.entries(CONTRACT.tiers)) {
    const row = REVENUE_CONFIG.LIMITS[id.toUpperCase()];
    assert.equal(row.rpm, tier.requests_per_minute, `${id}.rpm`);
    assert.equal(row.api_calls_day, tier.requests_per_day, `${id}.api_calls_day`);
  }
});

test("FREE usage-limit copy quotes the contracted 50/day and PRO 5,000/day", () => {
  const t = buildUpgradeTrigger("usage_limit", "FREE");
  assert.match(t.message, /all 50 free API calls/);
  assert.match(t.message, /5,000 calls\/day/);
  assert.doesNotMatch(t.message, /\b100\b/);
});

test("Enterprise upgrade features are contracted: capped quota, no unlimited, no white-label", () => {
  const t = buildUpgradeTrigger("usage_limit", "PRO");
  assert.equal(t.target_tier, "enterprise");
  const features = t.features.join(" | ");
  assert.match(features, /50,000 API calls\/day/);
  assert.match(features, /600 req\/min/);
  assert.doesNotMatch(features, /unlimited/i);
  assert.doesNotMatch(features, /white-label/i);
  assert.doesNotMatch(t.message, /unlimited/i);
  assert.equal(CONTRACT.tiers.enterprise.white_label, false, "precondition: white-label is not an Enterprise entitlement");
});

test("negative control: the quota assertions above would catch the pre-fix values", () => {
  // Pre-fix table (main @ 63daaf182). Proves the equality check is not vacuous.
  const PRE_FIX = { FREE: 100, PRO: 5000, ENTERPRISE: -1, MSSP: -1 };
  const drifted = Object.entries(PRE_FIX)
    .filter(([k, v]) => v !== CONTRACT.tiers[k.toLowerCase()].requests_per_day)
    .map(([k]) => k);
  assert.deepEqual(drifted, ["FREE", "ENTERPRISE", "MSSP"]);
});
