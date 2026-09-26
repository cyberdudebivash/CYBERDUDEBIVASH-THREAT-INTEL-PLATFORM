// SENTINEL APEX AI THREAT FEED (SKU cdb-aish-feed) -- module and router.
// Owner spec: stale -> 503; FREE never sees details, timeline or actions;
// ingest without an https source_url -> 400; prices only from the runtime
// pricing provider; the seed catalog mirrors config/ai-threat-feed-catalog.json
// and the entitlements mirror config/commercial-contract.json.
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import worker from "../index.js";
import {
  routeAiFeed, mergeFeed, redact, validateHubItem, feedItemToAi, offerBody, effectiveCatalog, sourceKey,
  AI_FEED_FEATURES, AI_FEED_SEED_CATALOG, AI_FEED_CATALOG_KEY, normalizeTier,
} from "../ai-threat-feed.js";
import { planPrice } from "../cyber-watchdog.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..", "..");
const NOW = Date.parse("2026-09-26T06:00:00Z");
const iso = (ms) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

const AI_ADV = {
  id: "intel--ai1", title: "LiteLLM proxy SSRF lets attackers reach internal model endpoints",
  description: "An SSRF in the LiteLLM proxy.", severity: "HIGH", source: "GitHub Security Advisories",
  source_url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", published_at: "2026-09-26T02:00:00Z",
  processed_at: "2026-09-26T03:00:00Z", cve_ids: ["CVE-2026-11111"], tlp: "TLP:CLEAR",
};
const NON_AI = { id: "intel--x", title: "Router firmware overflow", source_url: "https://example.com/a", severity: "LOW" };
const feedAt = (ageSec, items = [AI_ADV, NON_AI]) => ({ generated_at: iso(NOW - ageSec * 1000), count: items.length, items });
const FRESH = feedAt(600);
const STALE = feedAt(9 * 3600);
const ANCIENT = feedAt(49 * 3600);

const HUB = {
  id: "CDB-AISH-FEED-2026-0926-01", title: "MCP server exposes shell tool without auth",
  summary: "Default config binds the shell tool publicly.", status: "NEW_PUBLIC", tlp: "CLEAR", severity: "CRITICAL",
  source_url: "https://example.org/mcp-advisory", source_name: "Example Research", first_seen: "2026-09-26T01:00:00Z",
  hub_ruling: "Disable the shell tool.", timeline: [{ at: "2026-09-25", event: "disclosed" }],
  triggers: ["mcp shell"], actions: ["rotate tokens"], exploitation: "NOT_CONFIRMED",
};
const AMBER = { ...HUB, id: "CDB-AISH-FEED-2026-0926-02", tlp: "AMBER", title: "Private advisory for paying members" };

function store(initial = null) {
  let v = initial;
  let writes = 0;
  return {
    read: async () => v,
    write: async (o) => { writes++; v = JSON.parse(JSON.stringify(o)); },
    get value() { return v; },
    get writes() { return writes; },
  };
}
const call = (path, over = {}) => {
  const s = over.store || store();
  return routeAiFeed({ path, method: "GET", auth: { tier: "FREE" }, feed: FRESH, nowMs: NOW,
    readCatalog: s.read, writeCatalog: s.write, ...over });
};

// ── owner spec ────────────────────────────────────────────────────────────
test("stale feed -> 503 on live, health and item; never served as live", async () => {
  const live = await call("/api/ai-feed/live", { feed: STALE, auth: { tier: "ENTERPRISE" } });
  assert.equal(live.status, 503);
  assert.equal(live.body.error, "intelligence_degraded");
  assert.deepEqual(live.body.items, []);
  assert.equal(live.body.last_authoritative.live, false);
  assert.match(live.body.last_authoritative.label, /NOT LIVE/);
  assert.equal((await call("/api/ai-feed/health", { feed: STALE })).status, 503);
  assert.equal((await call("/api/ai-feed/item/intel--ai1", { feed: STALE, auth: { tier: "PRO" } })).status, 503);
  const old = await call("/api/ai-feed/live", { feed: ANCIENT });
  assert.equal(old.status, 503);
  assert.equal(old.body.last_authoritative, null, "nothing presented as current beyond 48h");
  for (const f of [null, {}, { generated_at: "not a date", items: [] }]) {
    assert.equal((await call("/api/ai-feed/live", { feed: f })).status, 503);
  }
});

test("FREE sees locked cards only: no summary, source URL, ruling, timeline or actions", async () => {
  const s = store({ items: [HUB] });
  const r = await call("/api/ai-feed/live", { store: s });
  assert.equal(r.status, 200);
  assert.equal(r.body.tier, "FREE");
  assert.equal(r.body.locked, true);
  assert.ok(r.body.items.length > 0 && r.body.items.length <= 5);
  for (const it of r.body.items) {
    assert.equal(it.locked, true);
    for (const k of ["summary", "source_url", "hub_ruling", "timeline", "triggers", "actions", "cves", "exploitation"]) {
      assert.equal(k in it, false, `FREE card leaks ${k}`);
    }
    assert.match(it.checkout, /plan=pro/);
  }
  assert.equal(r.body.upgrade.plan, "PRO");
  const item = await call("/api/ai-feed/item/" + HUB.id, { store: s });
  assert.equal(item.status, 403);
  assert.equal(item.body.error, "tier_required");
});

test("ingest without an https source_url -> 400 and nothing is written", async () => {
  for (const bad of [undefined, "", "http://example.org/x", "javascript:alert(1)", "ftp://x"]) {
    const s = store();
    const r = await call("/api/ai-feed/ingest", { method: "POST", isOperator: true, store: s,
      body: { items: [{ ...HUB, source_url: bad }] } });
    assert.equal(r.status, 400, String(bad));
    assert.equal(r.body.error, "invalid_items");
    assert.equal(r.body.rejected[0].error, "source_url_required");
    assert.equal(s.writes, 0);
  }
});

// ── tiers ─────────────────────────────────────────────────────────────────
test("PRO: details and source, timeline and actions locked; ENTERPRISE/MSSP: everything", async () => {
  const s = store({ items: [HUB] });
  const pro = (await call("/api/ai-feed/live", { store: s, auth: { tier: "PRO" } })).body.items.find((i) => i.id === HUB.id);
  assert.equal(pro.source_url, HUB.source_url);
  assert.equal(pro.hub_ruling, HUB.hub_ruling);
  assert.equal(pro.timeline_locked, true);
  assert.equal("timeline" in pro || "actions" in pro || "triggers" in pro, false);
  for (const tier of ["ENTERPRISE", "MSSP"]) {
    const e = (await call("/api/ai-feed/live", { store: s, auth: { tier } })).body.items.find((i) => i.id === HUB.id);
    assert.deepEqual(e.actions, HUB.actions);
    assert.deepEqual(e.timeline, HUB.timeline);
  }
  const one = await call("/api/ai-feed/item/" + HUB.id, { store: s, auth: { tier: "PRO" } });
  assert.equal(one.status, 200);
  assert.equal(one.body.item.id, HUB.id);
  assert.equal((await call("/api/ai-feed/item/CDB-AISH-FEED-2099-0101-01", { store: s, auth: { tier: "PRO" } })).status, 404);
});

test("item caps per plan: FREE 5, PRO 25, ENTERPRISE/MSSP 100", async () => {
  // 120 distinct Hub objects: distinct ids and distinct source articles.
  const unique = Array.from({ length: 120 }, (_, i) => ({
    ...HUB,
    id: `CDB-AISH-FEED-2026-${String(1000 + Math.floor(i / 100)).slice(-4)}-${String(i % 100).padStart(2, "0")}`,
    source_url: `https://example.org/advisory/${i}`,
  }));
  const s = store({ items: unique });
  for (const [tier, cap] of [["FREE", 5], ["PRO", 25], ["ENTERPRISE", 100], ["MSSP", 100]]) {
    const r = await call("/api/ai-feed/live", { store: s, auth: { tier } });
    assert.equal(r.body.items.length, cap, tier);
  }
});

test("TLP:AMBER Hub objects are hidden from FREE, visible to paid tiers", async () => {
  const s = store({ items: [AMBER] });
  const free = await call("/api/ai-feed/live", { store: s });
  assert.equal(free.body.items.some((i) => i.id === AMBER.id), false);
  const pro = await call("/api/ai-feed/live", { store: s, auth: { tier: "PRO" } });
  assert.equal(pro.body.items.some((i) => i.id === AMBER.id), true);
});

test("cancelled, refunded or expired paid keys collapse to FREE", async () => {
  const s = store({ items: [HUB] });
  for (const auth of [{ tier: "ENTERPRISE", subscription_status: "cancelled" }, { tier: "PRO", subscription_status: "refunded" },
    { tier: "PRO", error: "key_expired" }, { tier: "MSSP", error: "subscription_status_denied" }]) {
    const r = await call("/api/ai-feed/live", { store: s, auth });
    assert.equal(r.body.tier, "FREE");
    assert.equal(r.body.items.every((i) => i.locked === true), true);
  }
  assert.equal(normalizeTier({ tier: "PRO", subscription_status: "cancelled" }), "FREE");
});

// ── sources and truth ─────────────────────────────────────────────────────
test("feed items: only AI advisories that cite an https source; nothing invented", () => {
  const ai = feedItemToAi(AI_ADV);
  assert.equal(ai.origin, "sentinel_feed");
  assert.equal(ai.hub_ruling, null);
  assert.deepEqual(ai.actions, []);
  assert.deepEqual(ai.timeline.map((t) => t.at), [AI_ADV.published_at, AI_ADV.processed_at]);
  assert.equal(feedItemToAi(NON_AI), null);
  assert.equal(feedItemToAi({ ...AI_ADV, source_url: "" }), null);
  assert.equal(feedItemToAi({ ...AI_ADV, source_url: "http://insecure.example/x" }), null);
  assert.equal(feedItemToAi({ ...AI_ADV, title: "Mcpanel update", description: "" }), null, "word-bounded vocabulary");
  const merged = mergeFeed([HUB, { ...HUB, source_url: "http://x" , id: "CDB-AISH-FEED-2026-0926-09" }], [AI_ADV, NON_AI]);
  assert.deepEqual(merged.map((i) => i.id), [AI_ADV.id, HUB.id], "invalid hub item dropped, newest first");
});

test("one item per source article: production duplicate collapses, Hub wins", () => {
  // Production 2026-09-26: the same article, twice, different source names and severities.
  const a = { ...AI_ADV, id: "intel--7dbf", title: "OpenAI's AI Agents Tried Hacking 4 Websites Without Being Prompted",
    source: "CyberSecurityNews", severity: "MEDIUM", source_url: "https://cybersecuritynews.com/openais-ai-agents-tried-hacking-4-websites/" };
  const b = { ...a, id: "intel--bad5", source: "CyberSecurity News", severity: "LOW", source_url: "https://CyberSecurityNews.com/openais-ai-agents-tried-hacking-4-websites?utm_source=rss" };
  const merged = mergeFeed([], [a, b]);
  assert.deepEqual(merged.map((i) => i.id), ["intel--7dbf"]);
  const hub = { ...HUB, source_url: "https://cybersecuritynews.com/openais-ai-agents-tried-hacking-4-websites/" };
  assert.deepEqual(mergeFeed([hub], [a, b]).map((i) => i.id), [HUB.id]);
  assert.equal(sourceKey("https://Example.org/a/"), sourceKey("https://example.org/a?utm_source=rss&fbclid=1#f"));
  assert.notEqual(sourceKey("https://example.org/a"), sourceKey("https://example.org/b"));
  // Query-selected pages stay distinct (production: two CVEs on cvename.cgi).
  assert.notEqual(sourceKey("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-1"), sourceKey("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-2"));
  assert.equal(sourceKey("https://x.org/p?b=2&a=1&utm_medium=rss"), sourceKey("https://x.org/p?a=1&b=2"));
  const c1 = { ...AI_ADV, id: "intel--c1", title: "LLM gateway flaw one", source_url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-1" };
  const c2 = { ...c1, id: "intel--c2", title: "LLM gateway flaw two", source_url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-2" };
  assert.equal(mergeFeed([], [c1, c2]).length, 2);
});

test("hub validation rejects every field a buyer relies on", () => {
  const cases = {
    invalid_id: { id: "CDB-X-1" }, title_required: { title: "short" }, source_name_required: { source_name: "" },
    invalid_status: { status: "LIVE" }, invalid_tlp: { tlp: "RED" }, invalid_severity: { severity: "SEVERE" },
    invalid_first_seen: { first_seen: "yesterday" }, invalid_exploitation: { exploitation: "MAYBE" },
    invalid_timeline: { timeline: [{ at: "soon", event: "x" }] },
  };
  for (const [err, patch] of Object.entries(cases)) assert.equal(validateHubItem({ ...HUB, ...patch }).error, err);
  const v = validateHubItem({ ...HUB, title: "<img src=x onerror=alert(1)> MCP server exposes shell" });
  assert.equal(/[<>]/.test(v.item.title), false, "markup stripped");
});

test("ingest: operator only, all-or-nothing, upsert and retract", async () => {
  const s = store();
  assert.equal((await call("/api/ai-feed/ingest", { method: "POST", store: s, body: { items: [HUB] } })).status, 403);
  assert.equal((await call("/api/ai-feed/ingest", { method: "GET", isOperator: true, store: s })).status, 405);
  const mixed = await call("/api/ai-feed/ingest", { method: "POST", isOperator: true, store: s, body: { items: [HUB, { ...AMBER, severity: "?" }] } });
  assert.equal(mixed.status, 400);
  assert.equal(s.writes, 0);
  const ok = await call("/api/ai-feed/ingest", { method: "POST", isOperator: true, store: s, body: { items: [HUB, AMBER] } });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.accepted, 2);
  const seedId = AI_FEED_SEED_CATALOG[0].id;
  const r = await call("/api/ai-feed/ingest", { method: "POST", isOperator: true, store: s, body: { retract: [AMBER.id, seedId] } });
  assert.equal(r.status, 200);
  const ids = effectiveCatalog(s.value).map((i) => i.id);
  assert.deepEqual(ids, [HUB.id], "retract removes stored and seed items");
  const noStore = await routeAiFeed({ path: "/api/ai-feed/ingest", method: "POST", isOperator: true, body: { items: [HUB] }, nowMs: NOW });
  assert.equal(noStore.status, 503);
});

test("an unreadable catalog store serves the seed on reads (never an error)", async () => {
  const r = await routeAiFeed({ path: "/api/ai-feed/live", method: "GET", auth: { tier: "PRO" }, feed: FRESH, nowMs: NOW,
    readCatalog: async () => { throw new Error("kv down"); } });
  assert.equal(r.status, 200);
  assert.ok(r.body.items.some((i) => i.id === AI_FEED_SEED_CATALOG[0].id));
});

// ── commercial contract ───────────────────────────────────────────────────
test("no price literal in the module; offer prices are the runtime pricing provider's", () => {
  const src = readFileSync(join(HERE, "..", "ai-threat-feed.js"), "utf-8").replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "");
  assert.equal(/\$\s?\d/.test(src), false, "dollar amount literal");
  for (const tier of ["PRO", "ENTERPRISE", "MSSP"]) {
    const p = planPrice(tier);
    assert.equal(new RegExp(`\\b${p.usd_monthly}\\b`).test(src), false, `${tier} price ${p.usd_monthly} hard-coded`);
  }
  const offer = offerBody();
  for (const plan of offer.plans) {
    const p = planPrice(plan.id);
    assert.equal(plan.price_usd_monthly, p.usd_monthly);
    assert.equal(plan.price_inr_monthly, p.inr_monthly);
  }
  assert.equal(offer.second_invoice, false);
});

test("entitlements equal config/commercial-contract.json features.ai_threat_feed", () => {
  const c = JSON.parse(readFileSync(join(ROOT, "config", "commercial-contract.json"), "utf-8")).features.ai_threat_feed;
  assert.equal(c.sku, "cdb-aish-feed");
  for (const [tier, e] of Object.entries(c.entitlements)) {
    const f = AI_FEED_FEATURES[tier.toUpperCase()];
    assert.deepEqual({ items: f.items, details: f.details, timeline_and_actions: f.timeline, item_view: f.item_view, tlp_amber: f.amber }, e, tier);
  }
  assert.deepEqual(Object.keys(c.entitlements).map((t) => t.toUpperCase()).sort(), Object.keys(AI_FEED_FEATURES).sort());
});

test("seed catalog equals config/ai-threat-feed-catalog.json and validates", () => {
  const cfg = JSON.parse(readFileSync(join(ROOT, "config", "ai-threat-feed-catalog.json"), "utf-8"));
  assert.deepEqual(JSON.parse(JSON.stringify(AI_FEED_SEED_CATALOG)), cfg.items);
  for (const it of AI_FEED_SEED_CATALOG) {
    const v = validateHubItem(it);
    assert.equal(v.ok, true, it.id);
    assert.equal(new URL(it.source_url).protocol, "https:");
  }
});

// ── router (index.js) ─────────────────────────────────────────────────────
function fakeKV(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    get: async (k, o) => { const v = m.get(k); if (v === undefined) return null; return o === "json" || (o && o.type === "json") ? JSON.parse(v) : v; },
    put: async (k, v) => { m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    list: async () => ({ keys: [], list_complete: true }),
    _m: m,
  };
}
const PRO_KEY = "cdb_pro_test_aifeed0123456789abcdef01234567";
function gateway(feedAgeSec) {
  const feed = JSON.stringify({ generated_at: iso(Date.now() - feedAgeSec * 1000), count: 1, items: [AI_ADV] });
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  const env = {
    INTEL_R2: { get: async (k) => (k === "api/v1/intel/latest.json" ? { text: async () => feed, json: async () => JSON.parse(feed) } : null) },
    RATE_LIMIT_KV: fakeKV(), SECURITY_HUB_KV: fakeKV(), ANALYTICS_KV: fakeKV(), REVENUE_CRM_KV: fakeKV(),
    API_KEYS_KV: fakeKV({ [PRO_KEY]: JSON.stringify({ tier: "PRO", customer_id: "cust_ai_1", status: "active" }) }),
    CDB_JWT_SECRET: "jwt-test", ADMIN_SECRET: "admin-test",
  };
  const waits = [];
  const ctx = { waitUntil: (p) => waits.push(p) };
  const req = async (path, { method = "GET", headers = {}, body } = {}) => {
    const h = { "cf-connecting-ip": "198.51.100.23", ...headers };
    if (body !== undefined) h["Content-Type"] = "application/json";
    const res = await worker.fetch(new Request(`https://intel.cyberdudebivash.com${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), env, ctx);
    await Promise.allSettled(waits);
    return { status: res.status, body: await res.json(), headers: res.headers };
  };
  return { env, req };
}

test("router: public offer and health, anonymous live is the FREE projection", async () => {
  const { req } = gateway(600);
  const offer = await req("/api/ai-feed/offer");
  assert.equal(offer.status, 200);
  assert.equal(offer.body.sku, "cdb-aish-feed");
  assert.equal((await req("/api/ai-feed/health")).status, 200);
  const live = await req("/api/ai-feed/live");
  assert.equal(live.status, 200);
  assert.equal(live.body.tier, "FREE");
  assert.equal(live.headers.get("Cache-Control"), "no-store");
  assert.equal(live.body.items.every((i) => i.locked && !("source_url" in i)), true);
  const pro = await req("/api/ai-feed/live", { headers: { "X-API-Key": PRO_KEY } });
  assert.equal(pro.body.tier, "PRO");
  assert.equal(pro.body.items.find((i) => i.id === AI_ADV.id).source_url, AI_ADV.source_url);
});

test("router: stale R2 feed -> 503", async () => {
  const { req } = gateway(9 * 3600);
  assert.equal((await req("/api/ai-feed/live")).status, 503);
  assert.equal((await req("/api/ai-feed/health")).status, 503);
});

test("router: ingest needs X-Admin-Key, rejects a missing source_url with 400, persists to SECURITY_HUB_KV", async () => {
  const { env, req } = gateway(600);
  const noKey = await req("/api/ai-feed/ingest", { method: "POST", body: { items: [HUB] } });
  assert.equal(noKey.status, 403);
  const wrongKey = await req("/api/ai-feed/ingest", { method: "POST", headers: { "X-Admin-Key": "nope" }, body: { items: [HUB] } });
  assert.equal(wrongKey.status, 403);
  const bad = await req("/api/ai-feed/ingest", { method: "POST", headers: { "X-Admin-Key": "admin-test" }, body: { items: [{ ...HUB, source_url: undefined }] } });
  assert.equal(bad.status, 400);
  assert.equal(env.SECURITY_HUB_KV._m.has(AI_FEED_CATALOG_KEY), false);
  const ok = await req("/api/ai-feed/ingest", { method: "POST", headers: { "X-Admin-Key": "admin-test" }, body: { items: [HUB] } });
  assert.equal(ok.status, 200);
  assert.equal(JSON.parse(env.SECURITY_HUB_KV._m.get(AI_FEED_CATALOG_KEY)).items[0].id, HUB.id);
  const pro = await req("/api/ai-feed/item/" + HUB.id, { headers: { "X-API-Key": PRO_KEY } });
  assert.equal(pro.status, 200);
  assert.equal(pro.body.item.source_url, HUB.source_url);
});

test("router: listed in the 404 endpoint inventory", async () => {
  const { req } = gateway(600);
  const r = await req("/api/no-such-route");
  assert.equal(r.status, 404);
  assert.ok(r.body.available_endpoints.includes("/api/ai-feed/live"));
});

// A Cyber Watchdog browser session (aud cdb-watchdog) reads the AI feed it is
// sold with (GET live / item), and nothing else: not ingest, not other APIs.
async function watchdogSession(secret, tier = "PRO") {
  const b64u = (s) => Buffer.from(s).toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const now = Math.floor(Date.now() / 1000);
  const data = `${b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${b64u(JSON.stringify({
    sub: "cust_ai_1", tier, aud: "cdb-watchdog", scope: "watchdog:read", iat: now, exp: now + 600, auth_time: now, jti: "j-ai-1",
  }))}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data)));
  return `${data}.${b64u(Buffer.from(sig))}`;
}

test("router: Watchdog session token reads AI feed live/item; refused on ingest and elsewhere", async () => {
  const { req } = gateway(600);
  const token = await watchdogSession("jwt-test", "PRO");
  const auth = { Authorization: `Bearer ${token}` };
  const live = await req("/api/ai-feed/live", { headers: auth });
  assert.equal(live.status, 200, JSON.stringify(live.body).slice(0, 300));
  assert.equal(live.body.tier, "PRO");
  const item = await req("/api/ai-feed/item/" + AI_ADV.id, { headers: auth });
  assert.equal(item.status, 200);
  const ingest = await req("/api/ai-feed/ingest", { method: "POST", headers: { ...auth, "X-Admin-Key": "wrong" }, body: { items: [HUB] } });
  assert.equal(ingest.status === 401 || ingest.status === 403, true, `ingest ${ingest.status}`);
  const other = await req("/api/feed.json", { headers: auth });
  assert.equal(other.body.error === "token_audience_mismatch" || other.status === 401, true, JSON.stringify(other.body).slice(0, 200));
});
