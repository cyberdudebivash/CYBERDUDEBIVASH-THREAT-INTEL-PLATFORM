/**
 * ROLLBACK MATRIX -- persisted states A..H x implementations:
 *   1. corrected v3 (this branch)                       -- real WatchdogLedger + alarm
 *   2. raw historical v2 (main @ 6ac0385, vendored)     -- evidence of the unsafe path
 *   3. SAFE ROLLBACK TARGET (deploy/cyber-watchdog/safe-rollback/overlay)
 *
 * Outbound requests are observed at the fetch boundary. DNS-over-HTTPS
 * lookups are answered and not counted; every other request is a webhook
 * POST. Fixture evidence only.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { copyFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { WatchdogLedger as V3Ledger } from "../watchdog-ledger.js";
import { WatchdogLedger as V2Ledger } from "./fixtures/watchdog-v2/watchdog-ledger.js";
import { routeWatchdog as v2Route } from "./fixtures/watchdog-v2/cyber-watchdog.js";
import { MemStorage, FEED_ITEMS, feedObject } from "./watchdog-harness.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OVERLAY = path.resolve(HERE, "../../../../deploy/cyber-watchdog/safe-rollback/overlay/workers/intel-gateway/src");

// The safe overlay imports ./freshness-contract.js; stage it next to a copy.
async function loadSafe() {
  const dir = mkdtempSync(path.join(tmpdir(), "wd-safe-"));
  for (const f of ["cyber-watchdog.js", "watchdog-ledger.js", "production-entry.js"]) copyFileSync(path.join(OVERLAY, f), path.join(dir, f));
  copyFileSync(path.resolve(HERE, "../freshness-contract.js"), path.join(dir, "freshness-contract.js"));
  mkdirSync(path.join(dir, "node_modules"), { recursive: true });
  const cw = await import(pathToFileURL(path.join(dir, "cyber-watchdog.js")).href);
  const led = await import(pathToFileURL(path.join(dir, "watchdog-ledger.js")).href);
  return { route: cw.routeWatchdog, Ledger: led.WatchdogLedger, version: cw.WATCHDOG_VERSION, deliverWebhook: cw.deliverWebhook };
}

const NOW = new Date().toISOString();
const SUB = "cust_ent_1";
const SECRET = "whsec_" + "f".repeat(64);
const url = (k) => "https://" + k.toLowerCase() + "-dest.example.com/hook";
const NEW_ITEM = { id: "intel--matrix-new", title: "Matrix ransomware wave", severity: "HIGH", source: "CERT" };

async function call(obj, op) {
  const res = await obj.fetch(new Request("https://watchdog.ledger/mutate", { method: "POST", body: JSON.stringify({ op }) }));
  return res.json();
}

function earlyV3Row(id, u) {
  // Exact shape 6977abf (#496, deployed) persisted inside "ledger".
  return { id, url: u, state: "active", secret: SECRET, created_at: NOW, verified_at: NOW, last_delivery_at: null, failure_count: 0, disabled_reason: null, last_verification_error: null };
}

/** Builds one persisted state in fresh storage. Returns { storage, urls: {unsafeUnderV2, ...} }. */
async function build(kind) {
  const storage = new MemStorage();
  const base = { subject: SUB, tier: "ENTERPRISE", now: NOW };
  const v2 = new V2Ledger({ storage }, {});
  await call(v2, { ...base, type: "create_watch", id: "w1", watch: { name: "Ransomware", keywords: ["ransomware"], enabled: kind !== "G" } });
  const v3 = new V3Ledger({ storage }, {});
  const pushEarly = (row, extraEvent) => {
    const l = storage.data.get("ledger");
    l.destinations.push(row);
    if (extraEvent) l.events.unshift(extraEvent);
    storage.data.set("ledger", l);
  };
  if (kind === "A") await call(v2, { ...base, type: "set_destination", id: "a", destination: { url: url("A") } });
  if (kind === "B" || kind === "H" || kind === "G") pushEarly(earlyV3Row("d_" + kind.toLowerCase(), url(kind)));
  if (kind === "F") {
    pushEarly(earlyV3Row("d_f", url("F")), {
      id: "e_pending_f", watch_id: "w_w1", watch_name: "Ransomware", matched_item_id: "intel--old", revision: "r1", origin: "scheduler",
      matched_at: NOW, title: "Old ransomware item", dedupe_key: "w_w1|intel--old|r1", acknowledged: false, delivery_status: "pending",
      deliveries: [{ destination_id: "d_f", delivery_id: "e_pending_f:d_f", status: "pending", attempts: 0, next_attempt_at: "2020-01-01T00:00:00.000Z", last_error: null }],
    });
  }
  if (kind === "C" || kind === "D" || kind === "E") {
    const d = await call(v3, { ...base, type: "create_destination", id: kind.toLowerCase(), destination: { url: url(kind) }, secret: SECRET });
    const id = d.result.destination.id;
    if (kind !== "D") await call(v3, { ...base, type: "verification_result", id, ok: true });
    if (kind === "E") await call(v3, { ...base, type: "set_destination_state", id, state: "disabled" });
  }
  if (kind === "H") {
    // Hotfix deployed, but this ledger is never accessed by v3 again: the
    // row stays in the v2-readable key. No migration can reach it, which is
    // why the safe rollback target (not migration) protects a rollback.
    assert.ok(storage.data.get("ledger").destinations.some((x) => x.id === "d_h"), "H: row still in the v2-readable key");
  }
  return storage;
}

function network() {
  const posts = [];
  const fetchImpl = async (input, init = {}) => {
    const u = typeof input === "string" ? input : input.url;
    if (u.startsWith("https://cloudflare-dns.com/dns-query")) {
      const type = new URL(u).searchParams.get("type");
      return new Response(JSON.stringify({ Status: 0, Answer: type === "A" ? [{ type: 1, data: "93.184.216.34" }] : [] }), { status: 200 });
    }
    posts.push({ url: u, signed: !!(init.headers && init.headers["X-CDB-Watchdog-Signature"]) });
    return new Response(null, { status: 204 });
  };
  return { posts, fetchImpl };
}

const feed = () => feedObject([...FEED_ITEMS, NEW_ITEM], 60);

async function runV3(storage, flag) {
  const net = network();
  const saved = globalThis.fetch;
  globalThis.fetch = net.fetchImpl;
  try {
    const env = flag === undefined ? {} : { WATCHDOG_WEBHOOK_DELIVERY_ENABLED: flag };
    const v3 = new V3Ledger({ storage }, env);
    const { projectFeedItems } = await import("../cyber-watchdog.js");
    await call(v3, { type: "scheduled_evaluate", subject: SUB, tier: "ENTERPRISE", now: new Date().toISOString(), items: projectFeedItems(feed()), publication: { freshness_status: "FRESH", feed_generated_at: feed().generated_at } });
    await v3.alarm();
  } finally {
    globalThis.fetch = saved;
  }
  return net.posts;
}

async function runV2Like(route, Ledger, storage) {
  const net = network();
  const led = new Ledger({ storage }, {});
  const out = await route({
    path: "/api/watchdog/events", method: "GET", auth: { tier: "ENTERPRISE", sub: SUB, subscription_status: "active" },
    feed: feed(), ledger: { mutate: (op) => call(led, op) }, searchParams: new URLSearchParams(), id: "x",
    now: new Date().toISOString(), nowMs: Date.now(), fetchImpl: net.fetchImpl,
  });
  assert.equal(out.status, 200);
  if (typeof led.alarm === "function") await led.alarm();
  return net.posts;
}

const KINDS = ["A", "B", "C", "D", "E", "F", "G", "H"];

test("1. corrected v3: legacy inert; early-v3 adopted and delivered SIGNED; only verified rows deliver; kill switch fail-closed", async () => {
  const expected = { A: [], B: ["B"], C: ["C"], D: [], E: [], F: ["F"], G: [], H: ["H"] };
  for (const k of KINDS) {
    const posts = await runV3(await build(k), "true");
    const hosts = [...new Set(posts.map((p) => p.url))];
    assert.deepEqual(hosts, expected[k].map(url), k);
    assert.ok(posts.every((p) => p.signed), k + ": every v3 request is signed");
    const off = await runV3(await build(k), undefined);
    assert.deepEqual(off, [], k + ": flag absent -> zero requests");
  }
});

test("1b. corrected v3 moves early-v3 rows out of the v2-readable key on its first access, including a pure read", async () => {
  for (const k of ["B", "F", "G", "H"]) {
    const storage = await build(k);
    await runV3(storage, "true");
    assert.equal(storage.data.get("ledger").destinations.some((d) => d.secret), false, k);
  }
  const storage = await build("G");
  await call(new V3Ledger({ storage }, {}), { type: "get", subject: SUB });
  assert.equal(storage.data.get("ledger").destinations.some((d) => d.secret), false, "read-only access migrates");
  assert.equal(storage.data.get("watchdog_v3_signed_destinations")[0].delivery_protocol, "signed-v3");
});

test("2. raw historical v2 (evidence, NOT a supported rollback target): unsigned POSTs to early-v3 rows", async () => {
  const unsafe = [];
  for (const k of KINDS) {
    const posts = await runV2Like(v2Route, V2Ledger, await build(k));
    assert.ok(posts.every((p) => !p.signed), k + ": v2 never signs");
    if (posts.length) unsafe.push(k);
  }
  // A is v2's own destination. B, F and H are early-v3 destinations that raw
  // v2 would send unsigned intelligence to: the reason raw 6ac0385 is not a
  // supported rollback target after v3.
  assert.deepEqual(unsafe, ["A", "B", "F", "H"]);
});

test("3. SAFE ROLLBACK TARGET: zero outbound Watchdog requests for every persisted state", async () => {
  const safe = await loadSafe();
  assert.equal(safe.version, "2.0.0-safe-rollback");
  for (const k of KINDS) {
    const storage = await build(k);
    const posts = await runV2Like(safe.route, safe.Ledger, storage);
    assert.deepEqual(posts, [], k);
    for (const method of ["GET", "POST", "DELETE"]) {
      const r = await safe.route({ path: "/api/watchdog/destinations", method, auth: { tier: "ENTERPRISE", sub: SUB, subscription_status: "active" }, body: { url: url("X") }, ledger: { mutate: () => { throw new Error("ledger must not be touched"); } } });
      assert.equal(r.status, 503, k + " " + method);
      assert.doesNotMatch(JSON.stringify(r.body), /whsec_/);
    }
  }
  let called = 0;
  const r = await safe.deliverWebhook(url("Z"), {}, async () => { called += 1; return { ok: true, status: 204 }; });
  assert.equal(called, 0);
  assert.equal(r.status, "suppressed_safe_rollback");
});

test("3b. SAFE ROLLBACK TARGET keeps normal Watchdog reads and watch management working", async () => {
  const safe = await loadSafe();
  const storage = await build("C");
  const led = new safe.Ledger({ storage }, {});
  const ctx = { auth: { tier: "ENTERPRISE", sub: SUB, subscription_status: "active" }, feed: feed(), ledger: { mutate: (op) => call(led, op) }, searchParams: new URLSearchParams(), id: "n1", now: NOW, nowMs: Date.now() };
  assert.equal((await safe.route({ ...ctx, path: "/api/watchdog/health", method: "GET" })).status, 200);
  assert.equal((await safe.route({ ...ctx, path: "/api/watchdog/brief", method: "GET" })).status, 200);
  const w = await safe.route({ ...ctx, path: "/api/watchdog/watches", method: "POST", body: { name: "Azure", keywords: ["azure"] } });
  assert.equal(w.status, 201);
  const ev = await safe.route({ ...ctx, path: "/api/watchdog/events", method: "GET" });
  assert.equal(ev.status, 200);
  assert.ok(ev.body.total >= 1);
  // The v3-only key is untouched by the safe target, ready for roll-forward.
  assert.equal(storage.data.get("watchdog_v3_signed_destinations").length, 1);
});
