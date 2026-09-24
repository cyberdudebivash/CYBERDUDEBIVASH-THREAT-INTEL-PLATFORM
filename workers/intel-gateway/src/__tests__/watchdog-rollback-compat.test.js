/**
 * ROLLBACK SAFETY: v3 signed destinations must be inert under the previous
 * implementation, and v2 destinations must be inert under v3.
 *
 * The previous implementation is exercised for real: the vendored v2 router
 * and v2 WatchdogLedger (fixtures/watchdog-v2, byte-identical to main @
 * 6ac0385 apart from one import path, checked below) run over Durable Object
 * storage written by the real v3 WatchdogLedger. v2 delivers unsigned to the
 * `url` of every element of ledger.destinations, so the proof is behavioral:
 * which URLs v2 actually tries to POST to.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { WatchdogLedger } from "../watchdog-ledger.js";
import { activeDestinations, destinationState, fromPersisted, publicDestination } from "../cyber-watchdog.js";
import { webhookDeliveryEnabled } from "../watchdog-policy.js";
import { WatchdogLedger as V2Ledger } from "./fixtures/watchdog-v2/watchdog-ledger.js";
import { routeWatchdog as v2Route } from "./fixtures/watchdog-v2/cyber-watchdog.js";
import { ENT_KEY, MemStorage, feedObject, FEED_ITEMS, harness } from "./watchdog-harness.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SECRET = (c) => "whsec_" + c.repeat(64);
const URLS = {
  legacy: "https://legacy-v2.example.com/hook",
  pending: "https://pending-v3.example.com/hook",
  verified: "https://verified-v3.example.com/hook",
  disabled: "https://disabled-v3.example.com/hook",
};
const NOW = new Date().toISOString();

async function call(obj, op) {
  const res = await obj.fetch(new Request("https://watchdog.ledger/mutate", { method: "POST", body: JSON.stringify({ op }) }));
  return res.json();
}

/**
 * One Durable Object storage holding all four fixture destinations, each
 * written by the implementation that really creates it: the legacy row by v2,
 * the three signed rows by v3.
 */
async function mixedStorage() {
  const storage = new MemStorage();
  const v2 = new V2Ledger({ storage }, {});
  const base = { subject: "cust_ent_1", tier: "ENTERPRISE", now: NOW };
  assert.equal((await call(v2, { ...base, type: "create_watch", id: "w1", watch: { name: "Ransomware", keywords: ["ransomware"] } })).error, undefined);
  const legacy = await call(v2, { ...base, type: "set_destination", id: "legacy", destination: { url: URLS.legacy } });
  assert.equal(legacy.error, undefined);

  const v3 = new WatchdogLedger({ storage }, {});
  const make = async (id, url, c) => {
    const out = await call(v3, { ...base, type: "create_destination", id, destination: { url }, secret: SECRET(c) });
    assert.equal(out.error, undefined, JSON.stringify(out));
    return out.result.destination.id;
  };
  const ids = {
    legacy: "d_legacy",
    pending: await make("pending", URLS.pending, "a"),
    verified: await make("verified", URLS.verified, "b"),
    disabled: await make("disabled", URLS.disabled, "c"),
  };
  await call(v3, { ...base, type: "verification_result", id: ids.verified, ok: true });
  await call(v3, { ...base, type: "verification_result", id: ids.disabled, ok: true });
  await call(v3, { ...base, type: "set_destination_state", id: ids.disabled, state: "disabled" });
  return { storage, ids };
}

/** Runs the REAL v2 event path once over `storage`; returns every URL v2 fetched. */
async function v2Deliveries(storage, items) {
  const v2 = new V2Ledger({ storage }, {});
  const fetched = [];
  const out = await v2Route({
    path: "/api/watchdog/events",
    method: "GET",
    auth: { tier: "ENTERPRISE", sub: "cust_ent_1", subscription_status: "active" },
    feed: feedObject(items, 60),
    ledger: { mutate: (op) => call(v2, op) },
    searchParams: new URLSearchParams(),
    id: "x",
    now: new Date().toISOString(),
    nowMs: Date.now(),
    fetchImpl: async (url, init) => { fetched.push({ url, init }); return { ok: true, status: 204 }; },
  });
  assert.equal(out.status, 200, JSON.stringify(out.body));
  return fetched.map((f) => f.url);
}

test("fixture is the exact previous implementation (main @ 6ac0385)", () => {
  const sha = (s) => createHash("sha256").update(s).digest("hex");
  const cw = readFileSync(path.join(HERE, "fixtures/watchdog-v2/cyber-watchdog.js"), "utf8")
    .replace('import { evaluatePublicIntelligence } from "../../../freshness-contract.js"; // path-only edit; see README', 'import { evaluatePublicIntelligence } from "./freshness-contract.js";');
  assert.equal(sha(cw), "58b9ea6e7ea9d34ef18a331e0e34e38266e0182d6d108d73dfa58cc23580fb70");
  const led = readFileSync(path.join(HERE, "fixtures/watchdog-v2/watchdog-ledger.js"), "utf8");
  assert.equal(sha(led), "56dabb71b7bfb49f3d1c61ee7bf0b591fd6699274ac9e90ed59e7e9134ada0ec");
});

test("A. current v3 selection: only the verified signed destination is deliverable", async () => {
  const { storage, ids } = await mixedStorage();
  const state = fromPersisted(storage.data.get("ledger"), storage.data.get("watchdog_v3_signed_destinations"));
  const byId = Object.fromEntries(state.destinations.map((d) => [d.id, d]));
  assert.equal(Object.keys(byId).length, 4);
  assert.equal(destinationState(byId[ids.legacy]), "disabled", "v2 legacy active -> v3 inactive");
  assert.equal(publicDestination(byId[ids.legacy]).disabled_reason, "reregister_required_unsigned_v2_destination");
  assert.equal(destinationState(byId[ids.pending]), "pending");
  assert.equal(destinationState(byId[ids.verified]), "active");
  assert.equal(destinationState(byId[ids.disabled]), "disabled");
  assert.deepEqual(activeDestinations(state.destinations).map((d) => d.id), [ids.verified]);
});

test("B. previous v2 selection: legacy is still deliverable, NO v3 destination is (behavioral, real v2 code)", async () => {
  const { storage } = await mixedStorage();
  // v2's own view of the destination list.
  const v2 = new V2Ledger({ storage }, {});
  const listed = await call(v2, { type: "get", subject: "cust_ent_1" });
  assert.deepEqual(listed.result.destinations.map((d) => d.url), [URLS.legacy]);
  // v2's real event path, with a new matching item so it attempts delivery.
  const urls = await v2Deliveries(storage, [...FEED_ITEMS, { id: "intel--new-1", title: "New ransomware wave", severity: "HIGH" }]);
  assert.ok(urls.length >= 1, "v2 does run its delivery loop in this scenario");
  assert.ok(urls.every((u) => u === URLS.legacy), "v2 tried to POST to: " + JSON.stringify(urls));
  for (const k of ["pending", "verified", "disabled"]) assert.equal(urls.includes(URLS[k]), false, k + " reached by v2");
});

test("B'. a ledger holding only v3 destinations: v2 makes zero outbound requests", async () => {
  const storage = new MemStorage();
  const v3 = new WatchdogLedger({ storage }, {});
  const base = { subject: "cust_ent_1", tier: "ENTERPRISE", now: NOW };
  await call(v3, { ...base, type: "create_watch", id: "w1", watch: { name: "Ransomware", keywords: ["ransomware"] } });
  const d = await call(v3, { ...base, type: "create_destination", id: "only", destination: { url: URLS.verified }, secret: SECRET("d") });
  await call(v3, { ...base, type: "verification_result", id: d.result.destination.id, ok: true });
  const urls = await v2Deliveries(storage, FEED_ITEMS);
  assert.deepEqual(urls, []);
});

test("rollback is not destructive: v2 writes keep v3 signed destinations for roll-forward", async () => {
  const { storage, ids } = await mixedStorage();
  await v2Deliveries(storage, [...FEED_ITEMS, { id: "intel--new-2", title: "Another ransomware wave", severity: "HIGH" }]);
  const v2 = new V2Ledger({ storage }, {});
  await call(v2, { subject: "cust_ent_1", tier: "ENTERPRISE", now: NOW, type: "create_watch", id: "w2", watch: { name: "Azure", keywords: ["azure"] } });
  const state = fromPersisted(storage.data.get("ledger"), storage.data.get("watchdog_v3_signed_destinations"));
  const verified = state.destinations.find((d) => d.id === ids.verified);
  assert.equal(destinationState(verified), "active");
  assert.equal(verified.secret, SECRET("b"));
  assert.equal(state.watches.length, 2);
});

test("kill switch: fail-closed flag semantics", () => {
  assert.equal(webhookDeliveryEnabled({ WATCHDOG_WEBHOOK_DELIVERY_ENABLED: "true" }), true);
  for (const v of [undefined, "", "TRUE", "1", "yes", "false", true]) {
    assert.equal(webhookDeliveryEnabled({ WATCHDOG_WEBHOOK_DELIVERY_ENABLED: v }), false, String(v));
  }
  assert.equal(webhookDeliveryEnabled({}), false);
  assert.equal(webhookDeliveryEnabled(undefined), false);
  const toml = readFileSync(path.resolve(HERE, "../../wrangler.toml"), "utf8");
  assert.equal((toml.match(/^WATCHDOG_WEBHOOK_DELIVERY_ENABLED = "true"$/gm) || []).length, 2, "explicit in [vars] and [env.production.vars]");
});

test("kill switch: flag absent -> no verification challenge, no delivery; re-enabled -> pending delivery resumes", async () => {
  const h = harness({ deliveryFlag: null });
  h.net.dns.set("hooks.customer.example", [{ type: 1, data: "93.184.216.34" }]);
  const received = [];
  h.net.receivers.set("https://hooks.customer.example/wd", async (init) => {
    const body = JSON.parse(init.body);
    received.push(body);
    return body.type === "watchdog.verification" ? { status: 200, body: { challenge: body.challenge } } : { status: 204 };
  });
  const s = await h.call("POST", "/api/watchdog/session", { key: ENT_KEY });
  const t = s.body.token;
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "Ransomware", keywords: ["ransomware"] } });
  const reg = await h.call("POST", "/api/watchdog/destinations", { bearer: t, body: { url: "https://hooks.customer.example/wd" } });
  const blocked = await h.call("POST", "/api/watchdog/destinations/verify?id=" + reg.body.destination.id, { bearer: t, body: {} });
  assert.equal(blocked.status, 503);
  assert.equal(blocked.body.error, "webhook_delivery_disabled");
  assert.equal(received.length, 0);
  const ops = await h.call("GET", "/api/watchdog/ops", { admin: "admin-test-secret" });
  assert.equal(ops.body.webhook_delivery_enabled, false);

  // Verify while enabled, then switch off: a new event queues but nothing is sent.
  h.env.WATCHDOG_WEBHOOK_DELIVERY_ENABLED = "true";
  assert.equal((await h.call("POST", "/api/watchdog/destinations/verify?id=" + reg.body.destination.id, { bearer: t, body: {} })).status, 200);
  h.env.WATCHDOG_WEBHOOK_DELIVERY_ENABLED = "false";
  h.state.feed = feedObject([...FEED_ITEMS, { id: "intel--kill-1", title: "Kill switch ransomware", severity: "HIGH" }], 30);
  await h.cron();
  await h.runAlarms();
  assert.equal(received.filter((b) => b.type === "watchdog.match").length, 0);
  const ev = h.ledgerState("cust_ent_1").events.find((e) => e.matched_item_id === "intel--kill-1");
  assert.equal(ev.deliveries[0].status, "pending", "kept, not dropped");
  assert.equal(ev.deliveries[0].attempts, 0);

  h.env.WATCHDOG_WEBHOOK_DELIVERY_ENABLED = "true";
  await h.env.WATCHDOG_LEDGER.instance("wd:cust_ent_1").obj.alarm();
  assert.equal(received.filter((b) => b.type === "watchdog.match" && b.matched_item_id === "intel--kill-1").length, 1);
});

test("migration: a destination persisted by the first deployed v3 build (6977abf) is adopted and moved out of the v2-readable key", async () => {
  // Exact row shape 6977abf's create_destination + verification_result write
  // into "ledger": whsec_ secret, no delivery_protocol.
  const storage = new MemStorage();
  const v2 = new V2Ledger({ storage }, {});
  const base = { subject: "cust_ent_1", tier: "ENTERPRISE", now: NOW };
  await call(v2, { ...base, type: "create_watch", id: "w1", watch: { name: "Ransomware", keywords: ["ransomware"] } });
  await call(v2, { ...base, type: "set_destination", id: "legacy", destination: { url: URLS.legacy } });
  const ledger = storage.data.get("ledger");
  ledger.destinations.push({
    id: "d_early", url: URLS.verified, state: "active", secret: SECRET("e"), created_at: NOW,
    verified_at: NOW, last_delivery_at: null, failure_count: 0, disabled_reason: null, last_verification_error: null,
  });
  storage.data.set("ledger", ledger);

  const v3 = new WatchdogLedger({ storage }, {});
  const got = await call(v3, { ...base, type: "get" });
  assert.equal(got.result.destinations.find((d) => d.id === "d_early").state, "active", "still deliverable under v3");
  assert.equal(got.result.destinations.find((d) => d.id === "d_legacy").state, "disabled");

  // Any v3 write re-persists: the early row leaves "ledger".
  await call(v3, { ...base, type: "create_watch", id: "w2", watch: { name: "Azure", keywords: ["azure"] } });
  assert.deepEqual(storage.data.get("ledger").destinations.map((d) => d.id), ["d_legacy"]);
  const moved = storage.data.get("watchdog_v3_signed_destinations").find((d) => d.id === "d_early");
  assert.equal(moved.delivery_protocol, "signed-v3");
  assert.equal(moved.secret, SECRET("e"));

  const urls = await v2Deliveries(storage, [...FEED_ITEMS, { id: "intel--mig-1", title: "Migration ransomware wave", severity: "HIGH" }]);
  assert.ok(urls.every((u) => u === URLS.legacy), JSON.stringify(urls));
  assert.equal(urls.includes(URLS.verified), false);
});
