/**
 * CYBER WATCHDOG v3 -- end-to-end through the real gateway router, the real
 * WatchdogLedger / WatchdogScheduler Durable Object classes (in-memory
 * storage), the real 15-minute cron handler and ledger alarms, and a fake
 * network for DNS-over-HTTPS and webhook receivers. Fixture evidence only;
 * this is NOT production certification.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  ENT_KEY, EXPIRED_KEY, FEED_ITEMS, MSSP_A_ONLY_KEY, MSSP_KEY, MSSP_LEGACY_KEY, PRO2_KEY, PRO_KEY,
  craftJwt, feedObject, harness,
} from "./watchdog-harness.js";
import { verifySignature } from "../watchdog-webhook.js";

async function session(h, key, tenant) {
  const q = tenant ? "?tenant=" + encodeURIComponent(tenant) : "";
  const res = await h.call("POST", "/api/watchdog/session" + q, { key });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.token;
}

// ---------------------------------------------------------------------------
// PRO lifecycle (Phase 14 acceptance, fixture form)
// ---------------------------------------------------------------------------

test("PRO: create, read, evaluate once, no duplicate, ack persists, edit, disable stops events, delete cleans up", async () => {
  const h = harness();
  const t = await session(h, PRO_KEY);
  const created = await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "KEV CVE", cves: ["CVE-2026-1000"] } });
  assert.equal(created.status, 201);
  const id = created.body.watch.id;
  const read = await h.call("GET", "/api/watchdog/watches", { bearer: t });
  assert.equal(read.body.watches.length, 1);

  const first = await h.call("GET", "/api/watchdog/events", { bearer: t });
  assert.equal(first.status, 200);
  assert.equal(first.body.inserted, 1);
  assert.equal(first.body.total, 1);
  assert.equal(first.body.events[0].matched_item_id, "intel--kev-1");
  const second = await h.call("GET", "/api/watchdog/events", { bearer: t });
  assert.equal(second.body.inserted, 0, "same feed must not create a duplicate");
  assert.equal(second.body.total, 1);

  const ack = await h.call("POST", "/api/watchdog/events/ack", { bearer: t, body: { ids: [first.body.events[0].id] } });
  assert.equal(ack.body.acknowledged, 1);
  const after = await h.call("GET", "/api/watchdog/events?evaluate=0", { bearer: t });
  assert.equal(after.body.events[0].acknowledged, true);

  const edited = await h.call("PATCH", "/api/watchdog/watches?id=" + id, { bearer: t, body: { name: "KEV CVE edited" } });
  assert.equal(edited.body.watch.name, "KEV CVE edited");
  const disabled = await h.call("PATCH", "/api/watchdog/watches?id=" + id, { bearer: t, body: { enabled: false } });
  assert.equal(disabled.body.watch.enabled, false);
  assert.equal(h.schedulerState().subjects.cust_pro_1, undefined, "all watches disabled -> unscheduled");

  // New authoritative generation with an escalated revision: a disabled watch stays silent.
  h.state.feed = feedObject([{ ...FEED_ITEMS[0], severity: "HIGH", title: "CVE-2026-1000 revised" }], 60);
  await h.cron();
  const quiet = await h.call("GET", "/api/watchdog/events", { bearer: t });
  assert.equal(quiet.body.inserted, 0);
  assert.equal(quiet.body.total, 1);

  const del = await h.call("DELETE", "/api/watchdog/watches?id=" + id, { bearer: t });
  assert.equal(del.status, 200);
  const empty = await h.call("GET", "/api/watchdog/watches", { bearer: t });
  assert.equal(empty.body.watches.length, 0);

  const hook = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url: "https://siem.example.com/hook" } });
  assert.equal(hook.status, 403, "PRO is denied Enterprise webhook destinations");
  const hookKey = await h.call("POST", "/api/watchdog/destinations", { key: PRO_KEY, body: { url: "https://siem.example.com/hook" } });
  assert.equal(hookKey.status, 403);
});

// ---------------------------------------------------------------------------
// Autonomous evaluation (Phase 3) + FinOps (Phase 17)
// ---------------------------------------------------------------------------

test("autonomous: the cron creates the event with no browser, poller or events read", async () => {
  const h = harness();
  const t = await session(h, PRO_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "Ransomware", keywords: ["ransomware"] } });
  assert.equal(h.ledgerState("cust_pro_1").events.length, 0, "watch creation alone evaluates nothing");
  h.state.r2Gets = 0;
  await h.cron();
  assert.equal(h.state.r2Gets, 1, "one R2 GET per tick");
  assert.equal(h.state.r2Lists, 0);
  const stored = h.ledgerState("cust_pro_1").events;
  assert.equal(stored.length, 1);
  assert.equal(stored[0].origin, "scheduler");
  const run = h.schedulerState().last_run;
  assert.equal(run.status, "ok");
  assert.equal(run.inserted, 1);
  assert.equal(h.schedulerState().last_successful_generation, h.state.feed.generated_at);
});

test("autonomous: stale / empty / missing feed creates zero events and touches no ledger", async () => {
  for (const bad of [feedObject(FEED_ITEMS, 7 * 24 * 3600), feedObject([], 60), null]) {
    const h = harness();
    const t = await session(h, PRO_KEY);
    await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "Any", keywords: ["cve"] } });
    h.state.feed = bad;
    const before = h.env.WATCHDOG_LEDGER.requests;
    await h.cron();
    assert.equal(h.env.WATCHDOG_LEDGER.requests, before, "no ledger request on a non-FRESH feed");
    assert.equal(h.ledgerState("cust_pro_1").events.length, 0);
    assert.equal(h.schedulerState().last_run.status, "feed_not_fresh");
  }
});

test("autonomous: same generation is not re-evaluated; re-processing is not a new event; escalation is", async () => {
  const h = harness();
  const t = await session(h, PRO_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "KEV", cves: ["CVE-2026-1000"] } });
  await h.cron();
  assert.equal(h.ledgerState("cust_pro_1").events.length, 1);
  const before = h.env.WATCHDOG_LEDGER.requests;
  await h.cron();
  assert.equal(h.env.WATCHDOG_LEDGER.requests, before, "unchanged generation: no ledger request");
  // New generation, same advisory re-processed (processed_at changed only).
  h.state.feed = feedObject([{ ...FEED_ITEMS[0], processed_at: "2026-09-24T08:00:00Z" }, ...FEED_ITEMS.slice(1)], 30);
  await h.cron();
  assert.equal(h.ledgerState("cust_pro_1").events.length, 1, "re-processing is not a new revision");
  assert.equal(h.schedulerState().last_run.deduped, 1);
  // New generation, material change (severity escalation) -> new event.
  h.state.feed = feedObject([{ ...FEED_ITEMS[0], severity: "HIGH" }, ...FEED_ITEMS.slice(1)], 10);
  await h.cron();
  assert.equal(h.ledgerState("cust_pro_1").events.length, 2);
});

test("finops: zero paid watches -> one scheduler read per tick, zero R2 reads, zero writes", async () => {
  const h = harness();
  h.state.r2Gets = 0;
  await h.cron();
  await h.cron();
  assert.equal(h.state.r2Gets, 0);
  assert.equal(h.state.r2Lists, 0);
  assert.equal(h.env.WATCHDOG_SCHEDULER.requests, 2);
  const inst = h.env.WATCHDOG_SCHEDULER.instance("watchdog-scheduler-v1");
  assert.equal(inst.storage.writes, 0);
  assert.equal(h.env.WATCHDOG_LEDGER.requests, 0);
});

test("finops: anonymous brief/offer/health never touch the scheduler or a ledger", async () => {
  const h = harness();
  for (const p of ["/api/watchdog/brief", "/api/watchdog/offer", "/api/watchdog/health", "/api/watchdog/deploy"]) {
    await h.call("GET", p);
  }
  const mut = await h.call("POST", "/api/watchdog/watches", { body: { name: "x", keywords: ["y"] } });
  assert.equal(mut.status, 403);
  assert.equal(h.env.WATCHDOG_SCHEDULER.requests, 0);
  assert.equal(h.env.WATCHDOG_LEDGER.requests, 0);
});

test("autonomous: revoked subscription (jwt_deny) leaves the registry and gets no events", async () => {
  const h = harness();
  const t = await session(h, ENT_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "KEV", cves: ["CVE-2026-1000"] } });
  await h.env.SECURITY_HUB_KV.put("jwt_deny:cust_ent_1", "1");
  await h.cron();
  assert.equal(h.schedulerState().subjects.cust_ent_1, undefined);
  assert.equal(h.ledgerState("cust_ent_1").events.length, 0);
  const denied = await h.call("GET", "/api/watchdog/watches", { bearer: t });
  assert.equal(denied.status, 401, "the session itself is refused after revocation");
});

// ---------------------------------------------------------------------------
// Browser authentication (Phase 10)
// ---------------------------------------------------------------------------

test("browser auth: expired, wrong audience, missing scope, revoked, CSRF, cross-customer", async () => {
  const h = harness();
  const now = Math.floor(Date.now() / 1000);
  const base = { sub: "cust_pro_1", tier: "PRO", iss: "SENTINEL-APEX", aud: "cdb-watchdog", auth_time: now, jti: "j1" };

  const expired = await craftJwt({ ...base, scope: "watchdog:read", iat: now - 2000, exp: now - 1000 });
  assert.equal((await h.call("GET", "/api/watchdog/watches", { bearer: expired })).status, 401);

  const wrongAud = await craftJwt({ ...base, aud: "some-other-app", scope: "watchdog:read", iat: now, exp: now + 600 });
  assert.equal((await h.call("GET", "/api/watchdog/watches", { bearer: wrongAud })).status, 401);

  const readOnly = await craftJwt({ ...base, scope: "watchdog:read", iat: now, exp: now + 600 });
  const noScope = await h.call("POST", "/api/watchdog/watches", { bearer: readOnly, body: { name: "x", keywords: ["y"] } });
  assert.equal(noScope.status, 403);
  assert.equal(noScope.body.error, "insufficient_scope");

  const t = await session(h, PRO_KEY);
  assert.equal((await h.call("GET", "/api/v1/intel/apex.json", { bearer: t })).status, 401, "watchdog token is not a general bearer");
  assert.equal((await h.call("GET", "/api/feed.json", { bearer: t })).status, 401);
  const revoke = await h.call("DELETE", "/api/watchdog/session", { bearer: t });
  assert.equal(revoke.body.revoked, true);
  assert.equal((await h.call("GET", "/api/watchdog/watches", { bearer: t })).status, 401, "revoked session");

  // CSRF: a cross-site form can carry cookies but never an Authorization
  // header; with no ambient credential the mutation has no identity.
  const csrf = await h.call("POST", "/api/watchdog/watches", { headers: { Cookie: "session=whatever", Origin: "https://evil.example" }, body: { name: "x", keywords: ["y"] } });
  assert.equal(csrf.status, 403);

  const a = await session(h, PRO_KEY);
  const b = await session(h, PRO2_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: a, body: { name: "Mine", keywords: ["ransomware"] } });
  const other = await h.call("GET", "/api/watchdog/watches", { bearer: b });
  assert.equal(other.body.watches.length, 0, "cross-customer session sees nothing");
  const bodySpoof = await h.call("POST", "/api/watchdog/watches", { bearer: b, body: { name: "Spoof", keywords: ["x"], subject: "cust_pro_1", customer_id: "cust_pro_1" } });
  assert.equal(bodySpoof.status, 201);
  const mine = await h.call("GET", "/api/watchdog/watches", { bearer: a });
  assert.deepEqual(mine.body.watches.map((w) => w.name), ["Mine"]);

  const exp = await h.call("POST", "/api/watchdog/session", { key: EXPIRED_KEY });
  assert.ok(exp.status === 401 || exp.status === 403, "expired subscription cannot open a session");
});

test("browser auth: a refreshed session never widens scope or outlives max lifetime", async () => {
  const h = harness();
  const now = Math.floor(Date.now() / 1000);
  const narrow = await craftJwt({ sub: "cust_ent_1", tier: "ENTERPRISE", aud: "cdb-watchdog", scope: "watchdog:read watchdog:events:read", iat: now, exp: now + 600, auth_time: now, jti: "j2", iss: "SENTINEL-APEX" });
  const refreshed = await h.call("POST", "/api/watchdog/session", { bearer: narrow });
  assert.equal(refreshed.status, 200);
  assert.deepEqual(refreshed.body.scopes.sort(), ["watchdog:events:read", "watchdog:read"]);
  const old = await craftJwt({ sub: "cust_ent_1", tier: "ENTERPRISE", aud: "cdb-watchdog", scope: "watchdog:read", iat: now, exp: now + 600, auth_time: now - 9 * 3600, jti: "j3", iss: "SENTINEL-APEX" });
  const tooOld = await h.call("POST", "/api/watchdog/session", { bearer: old });
  assert.equal(tooOld.status, 403);
  const fresh = await session(h, ENT_KEY);
  const payload = JSON.parse(Buffer.from(fresh.split(".")[1], "base64url").toString());
  assert.equal(payload.aud, "cdb-watchdog");
  assert.ok(payload.exp - payload.iat <= 900);
  assert.ok(payload.scope.includes("watchdog:destinations:write"));
  const proPayload = JSON.parse(Buffer.from((await session(h, PRO_KEY)).split(".")[1], "base64url").toString());
  assert.equal(proPayload.scope.includes("watchdog:destinations:write"), false);
});

// ---------------------------------------------------------------------------
// Enterprise verified + signed delivery, SSRF / DNS rebinding (Phases 4-8, 15)
// ---------------------------------------------------------------------------

function enterpriseNet(h, url = "https://hooks.customer.example/wd") {
  h.net.dns.set("hooks.customer.example", [{ type: 1, data: "93.184.216.34" }, { type: 28, data: "2606:2800:220:1:248:1893:25c8:1946" }]);
  const received = [];
  let mode = { status: 204 };
  h.net.receivers.set(url, async (init) => {
    const body = JSON.parse(init.body);
    received.push({ headers: init.headers, raw: init.body, body });
    if (body.type === "watchdog.verification") return { status: 200, body: { challenge: body.challenge } };
    return typeof mode === "function" ? mode() : mode;
  });
  return { received, setMode: (m) => { mode = m; }, url };
}

test("enterprise: register -> pending -> verify -> signed delivery -> no duplicate -> failure recorded -> remove", async () => {
  const h = harness();
  const sink = enterpriseNet(h);
  const t = await session(h, ENT_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "Ransomware", keywords: ["ransomware"] } });

  const reg = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url: sink.url } });
  assert.equal(reg.status, 201);
  assert.equal(reg.body.destination.state, "pending");
  assert.match(reg.body.signing_secret, /^whsec_[0-9a-f]{64}$/);
  const secret = reg.body.signing_secret;
  const listed = await h.call("GET", "/api/watchdog/destinations", { bearer: t });
  assert.equal(listed.text.includes(secret), false, "secret is never returned again");
  assert.equal(JSON.stringify(h.ledgerState("cust_ent_1").destinations).includes(secret), true, "secret persisted server-side");

  // Before verification: the cron matches but queues nothing.
  await h.cron();
  await h.runAlarms();
  assert.equal(sink.received.length, 0);
  assert.equal(h.ledgerState("cust_ent_1").events[0].delivery_status, "no_destinations");

  const ver = await h.call("POST", "/api/watchdog/destinations/verify?id=" + reg.body.destination.id, { bearer: t, body: {} });
  assert.equal(ver.status, 200, JSON.stringify(ver.body));
  assert.equal(ver.body.destination.state, "active");
  assert.equal(sink.received.length, 1);
  const challenge = sink.received[0];
  assert.equal((await verifySignature({ secret, timestamp: challenge.headers["X-CDB-Watchdog-Timestamp"], signature: challenge.headers["X-CDB-Watchdog-Signature"], rawBody: challenge.raw })).ok, true);

  // New real-looking advisory in a new generation -> event -> signed delivery.
  h.state.feed = feedObject([...FEED_ITEMS, { id: "intel--rw-9", title: "New ransomware affiliate wave", severity: "HIGH", source: "CERT", processed_at: "2026-09-24T09:00:00Z" }], 30);
  await h.cron();
  const ledgerKey = "wd:cust_ent_1";
  assert.ok(h.env.WATCHDOG_LEDGER.instance(ledgerKey).storage.alarm != null, "delivery alarm armed");
  await h.runAlarms();
  const deliveries = sink.received.filter((r) => r.body.type === "watchdog.match");
  assert.equal(deliveries.length, 1);
  const d = deliveries[0];
  assert.equal(d.body.matched_item_id, "intel--rw-9");
  assert.equal(d.headers["X-CDB-Watchdog-Event-ID"], d.body.event_id);
  assert.equal(d.headers["X-CDB-Watchdog-Delivery-ID"], d.body.event_id + ":" + reg.body.destination.id);
  assert.equal(d.headers["X-CDB-Watchdog-Version"], "2026-09-24");
  assert.equal((await verifySignature({ secret, timestamp: d.headers["X-CDB-Watchdog-Timestamp"], signature: d.headers["X-CDB-Watchdog-Signature"], rawBody: d.raw })).ok, true);
  const tampered = await verifySignature({ secret, timestamp: d.headers["X-CDB-Watchdog-Timestamp"], signature: d.headers["X-CDB-Watchdog-Signature"], rawBody: d.raw.replace("HIGH", "LOW") });
  assert.equal(tampered.ok, false);

  const events = await h.call("GET", "/api/watchdog/events?evaluate=0", { bearer: t });
  const ev = events.body.events.find((e) => e.matched_item_id === "intel--rw-9");
  assert.equal(ev.delivery_status, "delivered");
  assert.equal(ev.deliveries[0].status, "delivered");

  // Same feed again: no duplicate event, no second delivery.
  await h.cron();
  await h.call("GET", "/api/watchdog/events", { bearer: t });
  await h.runAlarms();
  assert.equal(sink.received.filter((r) => r.body.type === "watchdog.match").length, 1);

  // Forced safe failure: receiver answers 503 Retry-After: 120 -> retry scheduled per policy.
  sink.setMode({ status: 503, headers: { "Retry-After": "120" } });
  h.state.feed = feedObject([...h.state.feed.items, { id: "intel--rw-10", title: "Second ransomware wave", severity: "HIGH", source: "CERT" }], 20);
  const t0 = Date.now();
  await h.cron();
  await h.runAlarms();
  const failing = (await h.call("GET", "/api/watchdog/events?evaluate=0", { bearer: t })).body.events.find((e) => e.matched_item_id === "intel--rw-10");
  assert.equal(failing.delivery_status, "pending");
  assert.equal(failing.deliveries[0].attempts, 1);
  assert.equal(failing.deliveries[0].last_http_status, 503);
  assert.ok(Date.parse(failing.deliveries[0].next_attempt_at) - t0 >= 119000, "Retry-After honored");
  const dests = await h.call("GET", "/api/watchdog/destinations", { bearer: t });
  assert.equal(dests.body.recent_deliveries[0].outcome, "retry_scheduled");

  // Remove destination: the pending delivery ends visibly; remove watch.
  const rm = await h.call("DELETE", "/api/watchdog/destinations?id=" + reg.body.destination.id, { bearer: t });
  assert.equal(rm.status, 200);
  const ended = (await h.call("GET", "/api/watchdog/events?evaluate=0", { bearer: t })).body.events.find((e) => e.matched_item_id === "intel--rw-10");
  assert.equal(ended.deliveries[0].status, "failed");
  assert.equal(ended.deliveries[0].last_error, "destination_removed");
});

test("ssrf: DNS rebinding after verification blocks delivery and fails the destination", async () => {
  const h = harness();
  const sink = enterpriseNet(h);
  const t = await session(h, ENT_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "Ransomware", keywords: ["ransomware"] } });
  const reg = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url: sink.url } });
  await h.call("POST", "/api/watchdog/destinations/verify?id=" + reg.body.destination.id, { bearer: t, body: {} });
  const verifiedPosts = sink.received.length;
  h.net.dns.set("hooks.customer.example", [{ type: 1, data: "169.254.169.254" }]);
  await h.cron();
  await h.runAlarms();
  assert.equal(sink.received.length, verifiedPosts, "no request reached the rebound destination");
  const ev = h.ledgerState("cust_ent_1").events[0];
  assert.equal(ev.deliveries[0].status, "failed");
  assert.equal(ev.deliveries[0].last_error, "forbidden_address");
  const dest = (await h.call("GET", "/api/watchdog/destinations", { bearer: t })).body.destinations[0];
  assert.equal(dest.state, "failed");
  assert.equal(dest.disabled_reason, "forbidden_address");
});

test("ssrf: registration refuses private, mixed, CNAME-to-internal and unresolvable hosts", async () => {
  const h = harness();
  const t = await session(h, ENT_KEY);
  h.net.dns.set("private.example.com", [{ type: 1, data: "10.0.0.5" }]);
  h.net.dns.set("mixed.example.com", [{ type: 1, data: "93.184.216.34" }, { type: 1, data: "127.0.0.1" }]);
  h.net.dns.set("alias.example.com", [{ type: 5, data: "metadata.google.internal." }, { type: 1, data: "93.184.216.34" }]);
  h.net.dns.set("v6ula.example.com", [{ type: 28, data: "fd12:3456::1" }]);
  for (const host of ["private.example.com", "mixed.example.com", "alias.example.com", "v6ula.example.com", "nxdomain.example.com"]) {
    const res = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url: "https://" + host + "/hook" } });
    assert.equal(res.status, 400, host);
    assert.equal(res.body.error, "invalid_destination", host);
  }
  for (const url of ["http://hooks.example.com/x", "https://127.0.0.1/x", "https://2130706433/x", "https://[::ffff:10.0.0.1]/x", "https://u:p@hooks.example.com/x", "https://hooks.example.com:8443/x", "not a url"]) {
    const res = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url } });
    assert.equal(res.status, 400, url);
  }
  assert.equal(h.ledgerState("cust_ent_1"), null, "nothing was stored");
});

test("verification: wrong echo and redirects never activate a destination", async () => {
  const h = harness();
  h.net.dns.set("bad.example.com", [{ type: 1, data: "93.184.216.34" }]);
  h.net.receivers.set("https://bad.example.com/hook", async () => ({ status: 200, body: { challenge: "nope" } }));
  h.net.dns.set("redir.example.com", [{ type: 1, data: "93.184.216.34" }]);
  h.net.receivers.set("https://redir.example.com/hook", async () => ({ status: 302, headers: { Location: "http://169.254.169.254/" } }));
  const t = await session(h, ENT_KEY);
  for (const url of ["https://bad.example.com/hook", "https://redir.example.com/hook"]) {
    const reg = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url } });
    assert.equal(reg.status, 201);
    const ver = await h.call("POST", "/api/watchdog/destinations/verify?id=" + reg.body.destination.id, { bearer: t, body: {} });
    assert.equal(ver.status, 422);
    assert.equal(ver.body.destination.state, "pending");
  }
  assert.equal(h.net.posts.some((p) => p.url.includes("169.254")), false, "redirect target never requested");
  const ops = await h.call("GET", "/api/watchdog/ops", { admin: "admin-test-secret" });
  assert.equal(ops.body.verification_failures_24h, 2);
});

// ---------------------------------------------------------------------------
// MSSP sub-tenant isolation (Phase 9 / 16, fixture form)
// ---------------------------------------------------------------------------

test("mssp: tenants A and B are isolated for reads, writes, ack, destinations and analytics", async () => {
  const h = harness();
  h.net.dns.set("a.example.com", [{ type: 1, data: "93.184.216.34" }]);
  const tA = await session(h, MSSP_KEY, "CANARY-A");
  const tB = await session(h, MSSP_KEY, "CANARY-B");
  const wA = await h.call("POST", "/api/watchdog/watches?tenant=CANARY-A", { bearer: tA, body: { name: "A-only", keywords: ["ransomware"] } });
  assert.equal(wA.status, 201);
  const eA = await h.call("GET", "/api/watchdog/events?tenant=CANARY-A", { bearer: tA });
  assert.equal(eA.body.total, 1);
  assert.equal(eA.body.tenant, "CANARY-A");
  const dA = await h.call("POST", "/api/watchdog/destinations?tenant=CANARY-A", { bearer: tA, body: { url: "https://a.example.com/hook" } });
  assert.equal(dA.status, 201);

  // B sees none of A.
  const bWatches = await h.call("GET", "/api/watchdog/watches?tenant=CANARY-B", { bearer: tB });
  assert.equal(bWatches.body.watches.length, 0);
  const bEvents = await h.call("GET", "/api/watchdog/events?tenant=CANARY-B&evaluate=0", { bearer: tB });
  assert.equal(bEvents.body.total, 0);
  assert.equal(bEvents.body.analytics.history, "no_history_yet");
  const bDest = await h.call("GET", "/api/watchdog/destinations?tenant=CANARY-B", { bearer: tB });
  assert.equal(bDest.body.destinations.length, 0);

  // A session bound to A cannot address B, for any operation.
  const cross = [
    ["GET", "/api/watchdog/watches?tenant=CANARY-B"],
    ["POST", "/api/watchdog/watches?tenant=CANARY-B", { name: "x", keywords: ["y"] }],
    ["PATCH", "/api/watchdog/watches?tenant=CANARY-B&id=" + wA.body.watch.id, { enabled: false }],
    ["DELETE", "/api/watchdog/watches?tenant=CANARY-B&id=" + wA.body.watch.id],
    ["POST", "/api/watchdog/events/ack?tenant=CANARY-B", { ids: [eA.body.events[0].id] }],
    ["GET", "/api/watchdog/events?tenant=CANARY-B"],
    ["GET", "/api/watchdog/destinations?tenant=CANARY-B"],
    ["POST", "/api/watchdog/destinations?tenant=CANARY-B", { url: "https://a.example.com/hook" }],
  ];
  for (const [m, p, body] of cross) {
    const res = await h.call(m, p, { bearer: tA, body });
    assert.equal(res.status, 403, m + " " + p);
    assert.equal(res.body.error, "forbidden");
  }
  // A key authorized only for A gets the same generic 403 for B, and for a tenant that does not exist.
  for (const tenant of ["CANARY-B", "NO-SUCH-TENANT"]) {
    const res = await h.call("GET", "/api/watchdog/watches?tenant=" + tenant, { key: MSSP_A_ONLY_KEY });
    assert.equal(res.status, 403);
    assert.deepEqual(res.body, { error: "forbidden", message: "Not authorized for this Watchdog resource." });
  }
  // A still intact after every attempt.
  const aAfter = await h.call("GET", "/api/watchdog/watches?tenant=CANARY-A", { bearer: tA });
  assert.equal(aAfter.body.watches[0].enabled, true);
  const aEv = await h.call("GET", "/api/watchdog/events?tenant=CANARY-A&evaluate=0", { bearer: tA });
  assert.equal(aEv.body.events[0].acknowledged, false);
  // No explicit membership list -> no tenant access. PRO -> no tenant access.
  assert.equal((await h.call("GET", "/api/watchdog/watches?tenant=CANARY-A", { key: MSSP_LEGACY_KEY })).status, 403);
  assert.equal((await h.call("GET", "/api/watchdog/watches?tenant=CANARY-A", { key: PRO_KEY })).status, 403);
  // Tenant in the body is ignored: the write lands in the account ledger, not A.
  await h.call("POST", "/api/watchdog/watches", { key: MSSP_KEY, body: { name: "body-tenant", keywords: ["x"], tenant: "CANARY-A" } });
  const aNames = (await h.call("GET", "/api/watchdog/watches?tenant=CANARY-A", { bearer: tA })).body.watches.map((w) => w.name);
  assert.deepEqual(aNames, ["A-only"]);
});

// ---------------------------------------------------------------------------
// Feed staleness contract (Phase 11) + operator observability (Phase 13)
// ---------------------------------------------------------------------------

test("feed.json: stale is never represented as fresh, and a stale body is not edge-cached", async () => {
  const h = harness({ feed: feedObject(FEED_ITEMS, 7 * 24 * 3600) });
  const stale = await h.call("GET", "/api/feed.json");
  assert.equal(stale.status, 200, "HTTP 200 kept for existing clients");
  assert.equal(stale.body.freshness_status, "STALE");
  assert.equal(stale.body.publication_state, "stale");
  assert.ok(stale.body.age_seconds > 6 * 3600);
  assert.equal(stale.headers.get("x-sentinel-freshness"), "STALE");
  assert.equal(stale.headers.get("x-sentinel-edge-ttl"), null, "internal TTL header stripped");
  h.state.feed = feedObject(FEED_ITEMS, 60);
  const again = await h.call("GET", "/api/feed.json");
  assert.equal(again.body.freshness_status, "FRESH", "stale body was not served from the edge cache");
  assert.equal(again.headers.get("x-sentinel-freshness"), "FRESH");
  const missingTs = harness({ feed: { count: 3, items: FEED_ITEMS } });
  const m = await missingTs.call("GET", "/api/feed.json");
  assert.equal(m.body.freshness_status, "INVALID");
  assert.equal(m.body.publication_state, "missing_timestamp");
});

test("feed.json: a paid body is never stored in the shared edge cache", async () => {
  const h = harness();
  const paid = await h.call("GET", "/api/feed.json", { key: PRO_KEY });
  assert.equal(paid.status, 200);
  assert.match(paid.headers.get("cache-control"), /private/);
  const anon = await h.call("GET", "/api/feed.json");
  assert.equal(anon.status, 200);
  assert.match(anon.headers.get("cache-control"), /public/);
});

test("ops: operator-only aggregates, nothing identifying", async () => {
  const h = harness();
  const sink = enterpriseNet(h);
  const t = await session(h, ENT_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "Ransomware", keywords: ["ransomware"] } });
  const reg = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url: sink.url } });
  await h.call("POST", "/api/watchdog/destinations/verify?id=" + reg.body.destination.id, { bearer: t, body: {} });
  await h.cron();
  await h.runAlarms();
  assert.equal((await h.call("GET", "/api/watchdog/ops")).status, 404);
  assert.equal((await h.call("GET", "/api/watchdog/ops", { key: ENT_KEY })).status, 404);
  const ops = await h.call("GET", "/api/watchdog/ops", { admin: "admin-test-secret" });
  assert.equal(ops.status, 200);
  for (const k of ["active_watch_subjects", "enabled_watches", "last_scheduler_run", "last_successful_feed_generation", "events_generated_24h", "events_deduped_24h", "delivery_attempts_24h", "delivery_successes_24h", "delivery_failures_24h", "active_destinations", "verification_failures_24h", "scheduler_failures_24h"]) {
    assert.ok(k in ops.body, k);
  }
  assert.equal(ops.body.active_watch_subjects, 1);
  assert.equal(ops.body.events_generated_24h, 1);
  assert.equal(ops.body.delivery_successes_24h, 1);
  assert.equal(ops.body.active_destinations, 1);
  assert.doesNotMatch(ops.text, /cust_ent_1|hooks\.customer\.example|whsec_|wd:/);
  const pub = await h.call("GET", "/api/watchdog/health");
  assert.doesNotMatch(pub.text, /cust_|whsec_|hooks\./);
});
