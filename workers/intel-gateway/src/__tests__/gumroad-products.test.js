/**
 * S16 Gumroad config authority, S19 price fail-closed, S18 legacy
 * reconciliation -- against the real gateway router.
 *
 *   - only catalog products grant access; tier and cycle come from the
 *     catalog, never from the product name
 *   - a sale below the canonical price, not in USD, or with no readable price
 *     is held for an operator, never provisioned
 *   - an unrelated product on the same Gumroad account is ignored silently
 *   - the catalog, the contract and upgrade.html agree
 *   - legacy keys (before the sale -> key maps) are reconciled, after which a
 *     refund of such a sale revokes automatically
 * Every identifier here is a TEST-ONLY fixture.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import worker from "../index.js";
import {
  GUMROAD_PRODUCTS, GUMROAD_CANONICAL_USD_CENTS, GUMROAD_STORE_BASE,
  gumroadPermalinkFrom, resolveGumroadProduct, checkGumroadSalePrice,
} from "../gumroad-products.js";

const SECRET = "gumroad_TEST_ONLY_secret";
const ADMIN = "admin_TEST_ONLY";
const ROOT = new URL("../../../../", import.meta.url);

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
    list: async ({ prefix = "", limit = 1000, cursor } = {}) => {
      const names = [...m.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0;
      const page = names.slice(start, start + limit);
      const done = start + limit >= names.length;
      return { keys: page.map((name) => ({ name })), list_complete: done, cursor: done ? undefined : String(start + limit) };
    },
  };
}

let ipN = 0;
function harness(extraEnv = {}) {
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  const env = {
    INTEL_R2: { get: async () => null },
    RATE_LIMIT_KV: fakeKV(), API_KEYS_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    CDB_JWT_SECRET: "jwt_TEST_ONLY", ADMIN_SECRET: ADMIN, GUMROAD_WEBHOOK_SECRET: SECRET, SUBSCRIPTION_EXPIRY_ENABLED: "true",
    TG_BOT_TOKEN: "tg_TEST_ONLY", TG_CHAT_ID: "chat_TEST_ONLY",
    ...extraEnv,
  };
  const ip = `203.0.113.${++ipN}`;
  const alerts = [];
  const send = async (req) => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (u, init) => { alerts.push(String(init?.body || "")); return new Response("{}", { status: 200 }); };
    const waits = [];
    try {
      const res = await worker.fetch(req, env, { waitUntil: (p) => waits.push(p) });
      await Promise.allSettled(waits);
      return { status: res.status, body: await res.json().catch(() => ({})) };
    } finally { globalThis.fetch = realFetch; }
  };
  const ping = (fields) => send(new Request(`https://intel.cyberdudebivash.com/api/webhooks/gumroad?secret=${SECRET}`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "cf-connecting-ip": ip },
    body: new URLSearchParams(fields).toString(),
  }));
  const admin = (method, path, body) => send(new Request(`https://intel.cyberdudebivash.com${path}`, {
    method, headers: { "X-Admin-Key": ADMIN, "content-type": "application/json", "cf-connecting-ip": ip },
    ...(body ? { body: JSON.stringify(body) } : {}),
  }));
  const keysFor = (email) => [...env.API_KEYS_KV.store.entries()]
    .filter(([k]) => k.startsWith("cdb_")).map(([k, v]) => ({ key: k, rec: JSON.parse(v) })).filter((x) => x.rec.customer_id === email);
  return { env, ping, admin, keysFor, alerts };
}

const SALE = (over = {}) => ({
  sale_id: "sale_TEST_ONLY_1", email: "buyer@example.com", product_name: "CYBERDUDEBIVASH SENTINEL APEX PRO",
  permalink: "pxyfcb", price: "4900", currency: "usd", sale_timestamp: "2026-09-25T00:00:00Z", ...over,
});

// --- authority: catalog <-> contract <-> upgrade.html -------------------------

test("catalog prices equal config/commercial-contract.json", () => {
  const contract = JSON.parse(readFileSync(new URL("config/commercial-contract.json", ROOT), "utf8"));
  for (const [tier, id] of [["PRO", "pro"], ["ENTERPRISE", "enterprise"], ["MSSP", "mssp"]]) {
    assert.equal(GUMROAD_CANONICAL_USD_CENTS[tier].monthly, contract.tiers[id].usd_monthly * 100, `${tier} monthly`);
    assert.equal(GUMROAD_CANONICAL_USD_CENTS[tier].annual, contract.tiers[id].usd_annual * 100, `${tier} annual`);
  }
});

test("upgrade.html sells exactly the catalog's Gumroad products (grants and memberships)", () => {
  const page = readFileSync(new URL("upgrade.html", ROOT), "utf8");
  const block = (name) => {
    const m = page.match(new RegExp(`var ${name} = \\{([\\s\\S]*?)\\n\\};`));
    assert.ok(m, `${name} located`);
    return m[1];
  };
  const pageUrls = (src) => {
    const out = [];
    for (const [, tier, body] of src.matchAll(/(\w+):\s*\{([^}]*)\}/g)) {
      for (const [, cycle, url] of body.matchAll(/(monthly|annual):\s*'([^']+)'/g)) {
        if (url.startsWith(GUMROAD_STORE_BASE)) out.push(`${tier.toUpperCase()}/${cycle}/${url.slice(GUMROAD_STORE_BASE.length)}`);
      }
    }
    return out.sort();
  };
  const grants = GUMROAD_PRODUCTS.filter((p) => p.kind === "grant").map((p) => `${p.tier}/${p.cycle}/${p.permalink}`).sort();
  const memberships = GUMROAD_PRODUCTS.filter((p) => p.kind === "membership").map((p) => `${p.tier}/${p.cycle}/${p.permalink}`).sort();
  assert.deepEqual(pageUrls(block("GUMROAD_URLS")), grants, "GUMROAD_URLS == catalog grants");
  assert.deepEqual(pageUrls(block("GUMROAD_MEMBERSHIP_URLS")), memberships, "GUMROAD_MEMBERSHIP_URLS == catalog memberships");
});

test("permalink parsing: slug or full URL, never garbage", () => {
  assert.equal(gumroadPermalinkFrom({ permalink: "pxyfcb" }), "pxyfcb");
  assert.equal(gumroadPermalinkFrom({ product_permalink: "https://cyberdudebivash.gumroad.com/l/XTNZU/?ref=x" }), "xtnzu");
  assert.equal(gumroadPermalinkFrom({ permalink: "<script>" }), "");
  assert.equal(gumroadPermalinkFrom({}), "");
  assert.equal(resolveGumroadProduct({ permalink: "unknown1" }), null);
  assert.equal(resolveGumroadProduct({ product_permalink: "https://cyberdudebivash.gumroad.com/l/cdedlo" }).tier, "ENTERPRISE");
});

test("price rules: at least the canonical USD price, else a named reason", () => {
  const pro = GUMROAD_PRODUCTS[0];
  assert.equal(checkGumroadSalePrice(pro, { price: "4900" }).ok, true, "currency defaults to USD");
  assert.equal(checkGumroadSalePrice(pro, { price: "5500", currency: "USD" }).ok, true, "tax or tip on top is fine");
  assert.equal(checkGumroadSalePrice(pro, { price: "4899", currency: "usd" }).reason, "price_below_catalog");
  assert.equal(checkGumroadSalePrice(pro, { price: "4900", currency: "eur" }).reason, "currency_not_usd");
  assert.equal(checkGumroadSalePrice(pro, { price: "" }).reason, "price_unreadable");
  assert.equal(checkGumroadSalePrice(pro, { price: "49.00" }).reason, "price_unreadable");
});

// --- webhook ------------------------------------------------------------------

test("a catalog sale at the canonical price provisions the catalog's tier, whatever the product name says", async () => {
  const h = harness();
  const r = await h.ping(SALE({ product_name: "SENTINEL APEX ENTERPRISE MSSP (renamed)" }));
  assert.equal(r.body.status, "provisioned");
  assert.equal(r.body.tier, "PRO", "tier from the catalog (pxyfcb = PRO), not the name");
  const [k] = h.keysFor("buyer@example.com");
  assert.equal(k.rec.tier, "PRO");
  assert.equal(k.rec.billing_cycle, "monthly");
  const annual = await harness().ping(SALE({ permalink: "vxoczs", price: "499000" }));
  assert.equal(annual.body.tier, "ENTERPRISE");
});

test("content products (packs, reports, daily brief, IOC download) never mint an API key, even named SENTINEL APEX", async () => {
  for (const [permalink, product_name, price] of [
    ["sentinel-apex-daily-brief", "SENTINEL APEX Daily Brief", "900"],
    ["ioc-feed-annual", "Annual IOC Feed \u2014 Structured JSON + STIX 2.1", "29900"],
    ["detection-pack-pro", "PRO Detection Pack \u2014 Full rule library", "34900"],
  ]) {
    const h = harness();
    const r = await h.ping(SALE({ permalink, product_name, price }));
    assert.equal(r.body.status, "ignored_not_a_platform_product", permalink);
    assert.equal(h.keysFor("buyer@example.com").length, 0, `${permalink}: no key`);
    assert.equal(h.alerts.length, 0, `${permalink}: no alert`);
    assert.equal(h.env.SECURITY_HUB_KV.store.has("gumroad_held:sale_TEST_ONLY_1"), false, `${permalink}: no hold`);
  }
});

test("an unrelated product on the Gumroad account is ignored: no key, no alert, no hold", async () => {
  const h = harness();
  const r = await h.ping(SALE({ permalink: "ebook01", product_name: "Enterprise SOC checklist (e-book)", price: "500" }));
  assert.equal(r.status, 200);
  assert.equal(r.body.status, "ignored_not_a_platform_product");
  assert.equal(h.keysFor("buyer@example.com").length, 0);
  assert.equal(h.env.SECURITY_HUB_KV.store.has("gumroad_held:sale_TEST_ONLY_1"), false);
});

for (const [name, over, reason] of [
  ["a plan-like product missing from the catalog", { permalink: "newplan", product_name: "SENTINEL APEX PRO Membership" }, "unknown_product"],
  ["a discounted sale", { price: "2450" }, "price_below_catalog"],
  ["a sale in another currency", { currency: "inr", price: "410000" }, "currency_not_usd"],
  ["a sale with no readable price", { price: "" }, "price_unreadable"],
]) {
  test(`held for review, never provisioned: ${name}`, async () => {
    const h = harness();
    const r = await h.ping(SALE(over));
    assert.equal(r.status, 200, "acknowledged so Gumroad does not retry forever");
    assert.equal(r.body.status, "held_for_review");
    assert.equal(r.body.reason, reason);
    assert.equal(h.keysFor("buyer@example.com").length, 0, "no key");
    const held = JSON.parse(h.env.SECURITY_HUB_KV.store.get("gumroad_held:sale_TEST_ONLY_1"));
    assert.equal(held.reason, reason);
    assert.ok(h.alerts.some((a) => a.includes("SALE HELD")), "operator alerted");
    const again = await h.ping(SALE(over));
    assert.equal(again.body.duplicate, true, "a redelivery answers from the hold");
    assert.equal(h.alerts.filter((a) => a.includes("SALE HELD")).length, 1, "alerted once");
    const list = await h.admin("GET", "/api/admin/gumroad/holds");
    assert.equal(list.body.count, 1);
    assert.equal(list.body.holds[0].sale_id, "sale_TEST_ONLY_1");
  });
}

test("a discounted membership renewal is held too, and does not extend the key", async () => {
  const h = harness();
  await h.ping(SALE({ subscription_id: "gsub_TEST_ONLY" }));
  const [k] = h.keysFor("buyer@example.com");
  const before = k.rec.expires_at;
  const r = await h.ping(SALE({ sale_id: "sale_TEST_ONLY_2", subscription_id: "gsub_TEST_ONLY", is_recurring_charge: "true", price: "100" }));
  assert.equal(r.body.status, "held_for_review");
  assert.equal(JSON.parse(h.env.API_KEYS_KV.store.get(k.key)).expires_at, before);
});

test("release: a price hold provisions with the catalog tier; an unknown product needs tier and cycle; once only", async () => {
  const h = harness();
  await h.ping(SALE({ price: "2450" }));
  const rel = await h.admin("POST", "/api/admin/gumroad/release", { sale_id: "sale_TEST_ONLY_1" });
  assert.equal(rel.status, 200);
  assert.equal(rel.body.status, "provisioned");
  assert.equal(h.keysFor("buyer@example.com")[0].rec.tier, "PRO");
  assert.equal((await h.admin("POST", "/api/admin/gumroad/release", { sale_id: "sale_TEST_ONLY_1" })).status, 404, "released once");
  assert.equal((await h.ping(SALE({ price: "2450" }))).body.status, "already_provisioned", "a redelivery never provisions twice");

  const u = harness();
  await u.ping(SALE({ permalink: "newplan", product_name: "SENTINEL APEX Enterprise yearly" }));
  assert.equal((await u.admin("POST", "/api/admin/gumroad/release", { sale_id: "sale_TEST_ONLY_1" })).status, 400);
  assert.equal((await u.admin("POST", "/api/admin/gumroad/release", { sale_id: "sale_TEST_ONLY_1", tier: "ENTERPRISE", billing_cycle: "annual" })).body.tier, "ENTERPRISE");
});

test("release is admin only; a refunded held sale can no longer be released", async () => {
  const h = harness();
  await h.ping(SALE({ price: "100" }));
  const anon = await worker.fetch(new Request("https://intel.cyberdudebivash.com/api/admin/gumroad/release", {
    method: "POST", headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.200" }, body: JSON.stringify({ sale_id: "sale_TEST_ONLY_1" }),
  }), h.env, { waitUntil() {} });
  assert.equal(anon.status, 403);
  const refund = await h.ping(SALE({ price: "100", refunded: "true" }));
  assert.equal(refund.body.status, "held_sale_refunded");
  assert.equal((await h.admin("POST", "/api/admin/gumroad/release", { sale_id: "sale_TEST_ONLY_1" })).status, 404);
  assert.equal(h.keysFor("buyer@example.com").length, 0);
});

test("seller binding: once GUMROAD_SELLER_ID is set, another seller's ping is refused before any effect", async () => {
  const h = harness({ GUMROAD_SELLER_ID: "seller_TEST_ONLY_A" });
  for (const seller of ["seller_TEST_ONLY_B", undefined]) {
    const r = await h.ping(SALE(seller ? { seller_id: seller } : {}));
    assert.equal(r.status, 403);
  }
  assert.equal(h.keysFor("buyer@example.com").length, 0);
  assert.equal((await h.ping(SALE({ seller_id: "seller_TEST_ONLY_A" }))).body.status, "provisioned");
});

// --- S18 legacy reconciliation --------------------------------------------------

test("reconcile: dry run reports, apply backfills; conflicts and unmappable keys are reported, never overwritten", async () => {
  const h = harness();
  const put = (key, rec) => h.env.API_KEYS_KV.store.set(key, JSON.stringify({ key, tier: "PRO", customer_id: `${key}@example.com`, ...rec }));
  put("cdb_pro_legacyA", { source: "gumroad_webhook", payment_metadata: { sale_id: "legacy_sale_A", subscription_id: "legacy_sub_A" } });
  put("cdb_pro_legacyB", { source: "gumroad_webhook", payment_metadata: { sale_id: "legacy_sale_B" } });
  put("cdb_pro_mappedC", { source: "gumroad_webhook", payment_metadata: { sale_id: "sale_C" } });
  put("cdb_pro_conflictD", { source: "gumroad_webhook", payment_metadata: { sale_id: "sale_D" } });
  put("cdb_pro_nosaleE", { source: "gumroad_webhook", payment_metadata: {} });
  put("cdb_pro_razorpayF", { source: "razorpay_webhook", payment_metadata: { payment_id: "pay_F" } });
  h.env.SECURITY_HUB_KV.store.set("gumroad_sale_key_map:sale_C", "cdb_pro_mappedC");
  h.env.SECURITY_HUB_KV.store.set("gumroad_sale_key_map:sale_D", "cdb_pro_someoneElse");

  const dry = await h.admin("POST", "/api/admin/gumroad/reconcile", {});
  assert.equal(dry.status, 200);
  assert.deepEqual({ apply: dry.body.apply, scanned: dry.body.scanned, gumroad: dry.body.gumroad_keys, mapped: dry.body.mapped, backfilled: dry.body.backfilled },
    { apply: false, scanned: 6, gumroad: 5, mapped: 1, backfilled: 2 });
  assert.equal(dry.body.conflicts.length, 1);
  assert.equal(dry.body.unmappable.length, 1);
  assert.equal(h.env.SECURITY_HUB_KV.store.has("gumroad_sale_key_map:legacy_sale_A"), false, "dry run writes nothing");
  assert.equal(JSON.stringify(dry.body).includes("cdb_pro_legacyA"), false, "key prefixes only, never full keys");

  const applied = await h.admin("POST", "/api/admin/gumroad/reconcile", { apply: true });
  assert.equal(applied.body.backfilled, 2);
  assert.equal(h.env.SECURITY_HUB_KV.store.get("gumroad_sale_key_map:legacy_sale_A"), "cdb_pro_legacyA");
  assert.equal(h.env.SECURITY_HUB_KV.store.get("gumroad_sub_key_map:legacy_sub_A"), "cdb_pro_legacyA");
  assert.equal(h.env.SECURITY_HUB_KV.store.get("gumroad_sale_key_map:sale_D"), "cdb_pro_someoneElse", "conflict left untouched");

  // The point of S18: a refund of a legacy sale now revokes automatically.
  const refund = await h.ping({ sale_id: "legacy_sale_B", email: "x@example.com", refunded: "true" });
  assert.equal(refund.body.status, "refunded");
  assert.equal(JSON.parse(h.env.API_KEYS_KV.store.get("cdb_pro_legacyB")).subscription_status, "refunded");
  const again = await h.admin("POST", "/api/admin/gumroad/reconcile", {});
  assert.equal(again.body.backfilled, 0, "idempotent");
});

test("reconcile pages through the key store with a cursor", async () => {
  const h = harness();
  for (let i = 0; i < 250; i++) {
    const key = `cdb_pro_${String(i).padStart(4, "0")}`;
    h.env.API_KEYS_KV.store.set(key, JSON.stringify({ key, source: "gumroad_webhook", payment_metadata: { sale_id: `s${i}` } }));
  }
  const p1 = await h.admin("POST", "/api/admin/gumroad/reconcile", { apply: true });
  assert.equal(p1.body.scanned, 200);
  assert.equal(p1.body.list_complete, false);
  const p2 = await h.admin("POST", "/api/admin/gumroad/reconcile", { apply: true, cursor: p1.body.cursor });
  assert.equal(p2.body.scanned, 50);
  assert.equal(p2.body.list_complete, true);
  assert.equal(p2.body.cursor, null);
});
