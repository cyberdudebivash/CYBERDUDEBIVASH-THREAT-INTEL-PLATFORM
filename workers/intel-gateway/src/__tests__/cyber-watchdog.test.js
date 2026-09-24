import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { evaluatePublicIntelligence } from "../freshness-contract.js";
import { pollDecision, retryDelayMs } from "../../../../deploy/cyber-watchdog/poll-lib.mjs";
import {
  CLASSIFIER_VERSION,
  COMMERCIAL_MIRROR,
  MemoryLedger,
  planPrice,
  runDueDeliveries,
  analyticsFromEvents,
  applyLedgerMutation,
  buildWatchdogBrief,
  buildWebhookPayload,
  candidateEvent,
  classifyItem,
  deployManifest,
  effectiveTier,
  emptyLedgerState,
  matchWatch,
  normalizeDestination,
  routeWatchdog,
  watchdogOffer,
  watchdogPublication,
} from "../cyber-watchdog.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../../..");
const CONTRACT = JSON.parse(fs.readFileSync(path.join(REPO, "config/commercial-contract.json"), "utf8"));
const NOW_MS = Date.parse("2026-09-24T06:00:00Z");
const NOW = "2026-09-24T06:00:00Z";

const FEED_ITEMS = [
  {
    id: "adv-1",
    title: "CVE-2026-1000 exploited ransomware campaign",
    summary: "KEV-listed vulnerability with ransomware use.",
    severity: "CRITICAL",
    source: "CISA KEV",
    published: "2026-09-20T00:00:00Z",
    processed_at: "2026-09-20T00:00:00Z",
    cve_ids: ["CVE-2026-1000"],
    kev_present: true,
    epss_score: 0.9,
    cvss_score: 9.8,
    affected_products: ["Microsoft Windows"],
    tlp: "TLP:CLEAR",
    ioc: "should-not-leak-to-free",
  },
  {
    id: "adv-2",
    title: "Azure Kubernetes supply-chain advisory",
    summary: "Vendor cloud control-plane note.",
    severity: "HIGH",
    source: "Vendor",
    published: "2026-09-21T00:00:00Z",
    processed_at: "2026-09-21T00:00:00Z",
  },
  {
    id: "adv-3",
    title: "Sigma detection for suspicious PowerShell",
    summary: "SOC triage playbook stub.",
    severity: "MEDIUM",
    source: "Detection pack",
    published: "2026-09-22T00:00:00Z",
    processed_at: "2026-09-22T00:00:00Z",
  },
  {
    id: "adv-4",
    title: "Quarterly planning note",
    severity: "INFO",
    source: "Internal",
    published: "2026-09-22T00:00:00Z",
  },
];

function liveFeed(items = FEED_ITEMS, generatedAt = "2026-09-24T05:00:00Z") {
  return { generated_at: generatedAt, count: items.length, items };
}

function auth(tier, sub = "cust-1", extra = {}) {
  return { tier, sub, subscription_status: "active", ...extra };
}

// v3 destination registration needs a DNS safety check and a signing secret.
const SECRET = "whsec_" + "a".repeat(64);
const PUBLIC_DNS = { resolveDestination: async () => ({ ok: true, addresses: ["93.184.216.34"] }), secret: SECRET };

test("offer prices come from the runtime provider and equal config/commercial-contract.json", () => {
  for (const [id, key] of [["PRO", "pro"], ["ENTERPRISE", "enterprise"], ["MSSP", "mssp"], ["FREE", "free"]]) {
    assert.equal(planPrice(id).usd_monthly, CONTRACT.tiers[key].usd_monthly);
    assert.equal(planPrice(id).inr_monthly, CONTRACT.tiers[key].inr_monthly);
    // Deprecated view stays readable for old importers.
    assert.equal(COMMERCIAL_MIRROR.tiers[id].usd_monthly, CONTRACT.tiers[key].usd_monthly);
    assert.equal(COMMERCIAL_MIRROR.tiers[id].inr_monthly, CONTRACT.tiers[key].inr_monthly);
  }
  assert.equal(COMMERCIAL_MIRROR.gstin, CONTRACT.gstin);
  assert.equal(COMMERCIAL_MIRROR.seller_legal, CONTRACT.seller_legal);
  const offer = watchdogOffer();
  const pro = offer.plans.find((p) => p.id === "PRO");
  const ent = offer.plans.find((p) => p.id === "ENTERPRISE");
  assert.equal(pro.price_usd_monthly, 49);
  assert.equal(pro.price_inr_monthly, 4100);
  assert.equal(pro.price_label, "$49/mo | INR 4,100/mo");
  assert.equal(ent.price_inr_monthly, 41600);
  assert.equal(ent.price_label, "$499/mo | INR 41,600/mo");
  assert.equal(offer.plans.find((p) => p.id === "MSSP").price_usd_monthly, 999);
  assert.equal(offer.checkout.primary, "razorpay");
  assert.equal(offer.checkout.second_invoice, false);
  const blob = JSON.stringify(offer);
  assert.doesNotMatch(blob, /entire internet is watched|watches the entire world|100% coverage/i);
  assert.match(blob, /Does not watch the entire internet/);
  assert.match(offer.aligned_not_certified, /not certified/);
});

test("negative control: book-rate 4067 is not the canonical Pro price", () => {
  const pro = watchdogOffer().plans.find((p) => p.id === "PRO");
  assert.notEqual(pro.price_inr_monthly, 4067);
  assert.equal(pro.price_inr_monthly, CONTRACT.tiers.pro.inr_monthly);
});

test("classifier is versioned and leaves unmatched items unclassified", () => {
  const cyber = classifyItem(FEED_ITEMS[0]);
  assert.equal(cyber.classification_version, CLASSIFIER_VERSION);
  assert.ok(cyber.lenses.includes("cybersecurity"));
  assert.ok(cyber.reasons.some((r) => r.includes("CVE")));
  assert.ok(classifyItem(FEED_ITEMS[1]).lenses.includes("technology"));
  assert.ok(classifyItem(FEED_ITEMS[2]).lenses.includes("security_operations"));
  assert.deepEqual(classifyItem(FEED_ITEMS[3]).lenses, []);
});

test("freshness uses the canonical evaluator and refuses a stale brief", () => {
  const fresh = watchdogPublication(liveFeed(), NOW_MS);
  assert.equal(fresh.freshness_status, "FRESH");
  assert.equal(fresh.feed_item_count, evaluatePublicIntelligence(liveFeed(), NOW_MS).intelligence.advisory_count);
  const stale = buildWatchdogBrief(liveFeed(FEED_ITEMS, "2026-08-26T09:55:27Z"), { tier: "FREE", nowMs: NOW_MS });
  assert.equal(stale.status, 503);
  assert.equal(stale.body.freshness_status, "STALE");
  assert.equal(stale.body.items.length, 0);
  assert.match(stale.body.message, /INTELLIGENCE DEGRADED/);
  const empty = buildWatchdogBrief({ generated_at: "2026-09-24T05:00:00Z", count: 0, items: [] }, { tier: "FREE", nowMs: NOW_MS });
  assert.equal(empty.status, 503);
  assert.equal(empty.body.freshness_status, "EMPTY");
  const missing = buildWatchdogBrief(null, { tier: "PRO", nowMs: NOW_MS });
  assert.equal(missing.body.freshness_status, "UNAVAILABLE");
});

test("negative control: stale feed must not look live", () => {
  const stale = buildWatchdogBrief(liveFeed(FEED_ITEMS, "2026-08-01T00:00:00Z"), { tier: "PRO", nowMs: NOW_MS });
  assert.notEqual(stale.status, 200);
  assert.notEqual(stale.body.freshness_status, "FRESH");
});

test("free brief redacts and count matches canonical advisory_count", () => {
  const free = buildWatchdogBrief(liveFeed(), { tier: "FREE", nowMs: NOW_MS, limit: 8 });
  assert.equal(free.status, 200);
  assert.equal(free.body.feed_items_seen, 4);
  assert.equal(free.body.items[0].cve_ids.length, 0);
  assert.equal(free.body.items[0].summary, null);
  assert.doesNotMatch(JSON.stringify(free.body), /should-not-leak/);
  assert.equal(free.body.situation.unclassified, 1);
});

test("structured AND watch matches only the critical Microsoft KEV item", () => {
  const watch = {
    id: "w_ms",
    name: "Critical Microsoft Exploitation",
    logic: "AND",
    enabled: true,
    criteria: { vendors: ["microsoft"], min_severity: "HIGH", kev: true },
  };
  assert.equal(matchWatch(watch, FEED_ITEMS[0]).matched, true);
  assert.equal(matchWatch(watch, FEED_ITEMS[1]).matched, false);
  const event = candidateEvent(watch, FEED_ITEMS[0], "2026-09-24T05:00:00Z", NOW);
  assert.ok(event.dedupe_key.includes("adv-1"));
  assert.equal(candidateEvent(watch, FEED_ITEMS[0], "2026-09-24T05:00:00Z", NOW).dedupe_key, event.dedupe_key);
});

test("negative control: snapshot overwrite loses a concurrent create", () => {
  const snap = emptyLedgerState();
  const a = applyLedgerMutation(snap, { type: "create_watch", subject: "c1", tier: "PRO", id: "aaa", now: NOW, watch: { name: "A", keywords: ["ransomware"] } });
  const b = applyLedgerMutation(snap, { type: "create_watch", subject: "c1", tier: "PRO", id: "bbb", now: NOW, watch: { name: "B", keywords: ["azure"] } });
  assert.equal(a.state.watches.length, 1);
  assert.equal(b.state.watches.length, 1);
  assert.equal(b.state.watches.some((w) => w.name === "A"), false);
});

test("serialized ledger keeps both concurrent creates and rejects the other tenant", async () => {
  const ledger = new MemoryLedger();
  await Promise.all([
    ledger.mutate({ type: "create_watch", subject: "c1", tier: "PRO", id: "aaa", now: NOW, watch: { name: "A", keywords: ["ransomware"] } }),
    ledger.mutate({ type: "create_watch", subject: "c1", tier: "PRO", id: "bbb", now: NOW, watch: { name: "B", keywords: ["azure"] } }),
  ]);
  const got = await ledger.mutate({ type: "get", subject: "c1" });
  assert.equal(got.result.watches.length, 2);
  const foreign = await ledger.mutate({ type: "get", subject: "c2" });
  assert.equal(foreign.error, "tenant_mismatch");
  assert.equal(foreign.status, 403);
});

test("entitlement: free, pro, enterprise, expired, refunded", async () => {
  assert.equal(effectiveTier({ tier: "ENTERPRISE", subscription_status: "expired" }), "FREE");
  assert.equal(effectiveTier({ tier: "ENTERPRISE", subscription_status: "refunded" }), "FREE");
  assert.equal(effectiveTier({ tier: "PRO", error: "subscription_cancelled" }), "FREE");
  const ledger = new MemoryLedger();
  const base = { ledger, feed: liveFeed(), nowMs: NOW_MS, now: NOW, id: "abc123", ...PUBLIC_DNS };
  const free = await routeWatchdog({ ...base, path: "/api/watchdog/watches", method: "POST", auth: auth("FREE", null), body: { name: "KEV", keywords: ["ransomware"] } });
  assert.equal(free.status, 403);
  const created = await routeWatchdog({ ...base, path: "/api/watchdog/watches", method: "POST", auth: auth("PRO"), body: { name: "Ransomware", keywords: ["ransomware"], lenses: ["cybersecurity"] } });
  assert.equal(created.status, 201);
  const proHook = await routeWatchdog({ ...base, path: "/api/watchdog/destinations", method: "POST", auth: auth("PRO"), body: { url: "https://hooks.example/watchdog" } });
  assert.equal(proHook.status, 403);
  const entHook = await routeWatchdog({ ...base, path: "/api/watchdog/destinations", method: "POST", auth: auth("ENTERPRISE"), body: { url: "https://hooks.example/watchdog" } });
  assert.equal(entHook.status, 201);
  const expired = await routeWatchdog({ ...base, path: "/api/watchdog/watches", method: "GET", auth: auth("ENTERPRISE", "cust-1", { subscription_status: "expired" }) });
  assert.equal(expired.status, 403);
  const proDeploy = await routeWatchdog({ ...base, path: "/api/watchdog/deploy", method: "GET", auth: auth("PRO") });
  assert.equal(proDeploy.status, 200);
  assert.equal(proDeploy.body.webhooks.endpoint, null);
  const entDeploy = deployManifest("ENTERPRISE");
  assert.equal(entDeploy.webhooks.endpoint, "POST /api/watchdog/destinations");
  assert.equal(entHook.body.destination.state, "pending");
  assert.equal(entHook.body.signing_secret, SECRET);
  assert.equal(JSON.stringify(entHook.body.destination).includes("whsec_"), false);
  const deniedHost = normalizeDestination({ url: "http://127.0.0.1/hook" });
  assert.equal(deniedHost.error, "invalid_destination");
  const meta = normalizeDestination({ url: "https://169.254.169.254/latest" });
  assert.equal(meta.error, "invalid_destination");
});

test("match events dedupe and do not record from a stale feed", async () => {
  const ledger = new MemoryLedger();
  const calls = { mutate: 0 };
  const counting = { mutate(op) { calls.mutate += 1; return ledger.mutate(op); } };
  const req = {
    ledger: counting,
    feed: liveFeed(),
    nowMs: NOW_MS,
    now: NOW,
    id: "abc123",
    path: "/api/watchdog/watches",
    method: "POST",
    auth: auth("PRO"),
    body: { name: "Ransomware", logic: "OR", criteria: { keywords: ["ransomware"] } },
  };
  assert.equal((await routeWatchdog(req)).status, 201);
  const before = calls.mutate;
  const brief = await routeWatchdog({ ...req, path: "/api/watchdog/brief", method: "GET", searchParams: new URLSearchParams() });
  assert.equal(brief.status, 200);
  assert.equal(calls.mutate, before);
  const first = await routeWatchdog({ ...req, path: "/api/watchdog/events", method: "GET", searchParams: new URLSearchParams("limit=10") });
  assert.equal(first.status, 200);
  assert.equal(first.body.events.length, 1);
  assert.equal(first.body.analytics.matches_24h >= 0, true);
  const second = await routeWatchdog({ ...req, path: "/api/watchdog/events", method: "GET", searchParams: new URLSearchParams("limit=10") });
  assert.equal(second.body.analytics.history, "stored-match-events");
  assert.equal(second.body.total, 1);
  const acked = await routeWatchdog({ ...req, path: "/api/watchdog/events/ack", method: "POST", body: { ids: [first.body.events[0].id] } });
  assert.equal(acked.body.acknowledged, 1);
  const stale = await routeWatchdog({ ...req, feed: liveFeed(FEED_ITEMS, "2026-08-01T00:00:00Z"), path: "/api/watchdog/matches", method: "GET", searchParams: new URLSearchParams() });
  assert.equal(stale.status, 503);
  assert.equal(stale.body.events_recorded, false);
});

test("enterprise webhook: nothing is delivered before verification, then one signed delivery", async () => {
  const { attemptDelivery, verifySignature } = await import("../watchdog-webhook.js");
  const ledger = new MemoryLedger();
  const posted = [];
  const dns = async (url) => ({ ok: true, json: async () => ({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }), status: 200, url });
  const fetchImpl = async (url, init) => {
    if (String(url).startsWith("https://cloudflare-dns.com/")) return dns(url);
    posted.push({ url, init });
    return { ok: true, status: 204, headers: new Headers() };
  };
  const base = { ledger, feed: liveFeed(), nowMs: NOW_MS, now: NOW, id: "zzz999", auth: auth("ENTERPRISE"), ...PUBLIC_DNS };
  await routeWatchdog({ ...base, path: "/api/watchdog/watches", method: "POST", body: { name: "Ransomware", keywords: ["ransomware"] } });
  const dest = await routeWatchdog({ ...base, path: "/api/watchdog/destinations", method: "POST", body: { url: "https://siem.example/hook" } });
  assert.equal(dest.status, 201);
  const first = await routeWatchdog({ ...base, path: "/api/watchdog/events", method: "GET", searchParams: new URLSearchParams() });
  assert.equal(first.status, 200);
  assert.equal(first.body.events[0].delivery_status, "no_destinations", "a pending destination gets nothing queued");
  const idle = await runDueDeliveries({ ledger, subject: "cust-1", now: NOW, attempt: attemptDelivery, fetchImpl });
  assert.equal(idle.attempted, 0);
  assert.equal(posted.length, 0);

  const verified = await routeWatchdog({
    ...base, path: "/api/watchdog/destinations/verify", method: "POST", nonce: "ab".repeat(16),
    searchParams: new URLSearchParams("id=" + dest.body.destination.id),
    verifyDestination: async () => ({ ok: true }),
  });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.destination.state, "active");

  // A new matching item after verification is queued and delivered, signed.
  const feed2 = liveFeed([...FEED_ITEMS, { id: "adv-9", title: "New ransomware wave", severity: "HIGH", source: "CERT", processed_at: "2026-09-24T05:30:00Z" }], "2026-09-24T05:40:00Z");
  const second = await routeWatchdog({ ...base, feed: feed2, path: "/api/watchdog/events", method: "GET", searchParams: new URLSearchParams() });
  const fresh = second.body.events.find((e) => e.matched_item_id === "adv-9");
  assert.equal(fresh.delivery_status, "pending");
  const run = await runDueDeliveries({ ledger, subject: "cust-1", now: NOW, attempt: attemptDelivery, fetchImpl });
  assert.equal(run.attempted, 1);
  assert.equal(posted.length, 1);
  const sent = posted[0];
  assert.equal(sent.url, "https://siem.example/hook");
  assert.equal(sent.init.redirect, "manual");
  const h = sent.init.headers;
  assert.equal(h["X-CDB-Watchdog-Event-ID"], fresh.id);
  const ok = await verifySignature({ secret: SECRET, timestamp: h["X-CDB-Watchdog-Timestamp"], signature: h["X-CDB-Watchdog-Signature"], rawBody: sent.init.body, nowMs: NOW_MS });
  assert.equal(ok.ok, true);
  const body = JSON.parse(sent.init.body);
  assert.equal(body.product.includes("CYBER WATCHDOG"), true);
  assert.equal("remediation" in body, false);
  assert.doesNotMatch(sent.init.body, /should-not-leak/);
  const after = await routeWatchdog({ ...base, feed: feed2, path: "/api/watchdog/events", method: "GET", searchParams: new URLSearchParams("evaluate=0") });
  const done = after.body.events.find((e) => e.matched_item_id === "adv-9");
  assert.equal(done.delivery_status, "delivered");
  assert.equal(done.deliveries[0].status, "delivered");
  assert.equal(after.body.analytics.delivery_success_rate, 1);
  const payload = buildWebhookPayload(done);
  assert.ok(payload.matched_item_id);
});

test("cross-customer ledger isolation", async () => {
  const a = new MemoryLedger();
  const b = new MemoryLedger();
  const feed = liveFeed();
  await routeWatchdog({ ledger: a, feed, nowMs: NOW_MS, now: NOW, id: "a1", path: "/api/watchdog/watches", method: "POST", auth: auth("PRO", "cust-a"), body: { name: "A", keywords: ["ransomware"] } });
  const other = await routeWatchdog({ ledger: b, feed, nowMs: NOW_MS, now: NOW, id: "b1", path: "/api/watchdog/watches", method: "GET", auth: auth("PRO", "cust-b"), searchParams: new URLSearchParams() });
  assert.equal(other.body.watches.length, 0);
  const del = await routeWatchdog({ ledger: a, feed, nowMs: NOW_MS, now: NOW, path: "/api/watchdog/watches", method: "DELETE", auth: auth("PRO", "cust-b"), searchParams: new URLSearchParams("id=w_a1") });
  assert.equal(del.status, 403);
  assert.equal(del.body.error, "tenant_mismatch");
  assert.equal("state" in del.body, false);
  assert.doesNotMatch(JSON.stringify(del.body), /ransomware|Owned|"name":"A"/);
});

test("dashboard binds Total Advisories to total_advisories, not the report catalog", () => {
  const html = fs.readFileSync(path.join(REPO, "index.html"), "utf8");
  assert.match(html, /set\('m-total',\s*intel\.total_advisories\)/);
  assert.doesNotMatch(html, /set\('m-total',\s*intel\.total_reports\)/);
});

test("negative control: page escape is not an identity map", () => {
  const html = fs.readFileSync(path.join(REPO, "cyber-watchdog.html"), "utf8");
  assert.match(html, /charCodeAt\(0\)/);
  assert.doesNotMatch(html, /sessionStorage is not used|localStorage\.setItem\('apex_watchdog_key'/);
  assert.match(html, /sessionStorage/);
  assert.doesNotMatch(html, /localStorage\.(get|set)Item/);
  // v3: the long-lived key is never stored, only exchanged for a session.
  assert.doesNotMatch(html, /sessionStorage\.setItem\('apex_watchdog_key'/);
  assert.match(html, /\/api\/watchdog\/session/);
  assert.match(html, /input\.value = ''/);
});

test("analytics does not invent history", () => {
  const empty = analyticsFromEvents([], NOW_MS);
  assert.equal(empty.matches_24h, 0);
  assert.equal(empty.history, "no_history_yet");
  assert.equal(empty.delivery_success_rate, null);
  assert.deepEqual(empty.top_watches, []);
  assert.deepEqual(empty.top_sources, []);
});

test("poller refuses to replace a good file with stale, unauthorized, or malformed input", () => {
  assert.equal(pollDecision(200, JSON.stringify({ freshness_status: "FRESH", feed_item_count: 4 })).replace, true);
  assert.equal(pollDecision(503, JSON.stringify({ freshness_status: "STALE" })).exitCode, 4);
  assert.equal(pollDecision(503, JSON.stringify({ freshness_status: "STALE" })).replace, false);
  assert.equal(pollDecision(401, "no").exitCode, 3);
  assert.equal(pollDecision(403, "no").exitCode, 3);
  assert.equal(pollDecision(200, "not-json").exitCode, 5);
  assert.equal(pollDecision(429, "{}").action, "retry");
  assert.equal(retryDelayMs(0, "2"), 2000);
});

test("negative control: private and mapped webhook hosts are rejected, and a body cannot choose the customer", async () => {
  for (const url of [
    "https://[::1]/hook",
    "https://[::ffff:169.254.169.254]/latest",
    "https://[fd00::1]/hook",
    "https://[fe80::1]/hook",
    "https://2130706433/hook",
    "https://10.1.2.3/hook",
    "http://hooks.example/hook",
    "https://user:pass@hooks.example/hook",
  ]) {
    assert.equal(normalizeDestination({ url }).error, "invalid_destination", url);
  }
  assert.equal(normalizeDestination({ url: "https://hooks.example/watchdog" }).url, "https://hooks.example/watchdog");
  assert.equal(normalizeDestination({ url: "https://[2001:4860:4860::8888]/dns" }).error, undefined);

  const ledger = new MemoryLedger();
  const created = await routeWatchdog({
    ledger, feed: liveFeed(), nowMs: NOW_MS, now: NOW, id: "owner1",
    path: "/api/watchdog/watches", method: "POST", auth: auth("PRO", "cust-1"),
    body: { name: "Owned", keywords: ["ransomware"], customer_id: "cust-victim", subject: "cust-victim" },
  });
  assert.equal(created.status, 201);
  const victim = await routeWatchdog({
    ledger, feed: liveFeed(), nowMs: NOW_MS, now: NOW,
    path: "/api/watchdog/watches", method: "GET", auth: auth("PRO", "cust-victim"),
    searchParams: new URLSearchParams(),
  });
  assert.equal(victim.status, 403);
  assert.equal("state" in victim.body, false);
  assert.doesNotMatch(JSON.stringify(victim.body), /Owned/);
  const owner = await routeWatchdog({
    ledger, feed: liveFeed(), nowMs: NOW_MS, now: NOW,
    path: "/api/watchdog/watches", method: "GET", auth: auth("PRO", "cust-1"),
    searchParams: new URLSearchParams(),
  });
  assert.equal(owner.body.watches.length, 1);
  const disabled = await routeWatchdog({
    ledger, feed: liveFeed(), nowMs: NOW_MS, now: NOW,
    path: "/api/watchdog/watches", method: "PATCH", auth: auth("PRO", "cust-1"),
    searchParams: new URLSearchParams("id=" + created.body.watch.id),
    body: { enabled: false },
  });
  assert.equal(disabled.status, 200);
  assert.equal(disabled.body.watch.enabled, false);
  assert.deepEqual(disabled.body.watch.criteria.keywords, ["ransomware"]);
  assert.equal(effectiveTier({ tier: "MSSP", subscription_status: "suspended" }), "FREE");
  assert.equal(effectiveTier({ tier: "ENTERPRISE", error: "subscription_revoked" }), "FREE");
  const mssp = await routeWatchdog({
    ledger: new MemoryLedger(), feed: liveFeed(), nowMs: NOW_MS, now: NOW, id: "mssp1", ...PUBLIC_DNS,
    path: "/api/watchdog/destinations", method: "POST", auth: auth("MSSP", "mssp-a"),
    body: { url: "https://hooks.example/mssp" },
  });
  assert.equal(mssp.status, 201);
});

test("negative control: a 200 without FRESH must not be written", () => {
  const decision = pollDecision(200, JSON.stringify({ items: [{ title: "invented" }] }));
  assert.equal(decision.replace, false);
  assert.equal(decision.exitCode, 4);
});
