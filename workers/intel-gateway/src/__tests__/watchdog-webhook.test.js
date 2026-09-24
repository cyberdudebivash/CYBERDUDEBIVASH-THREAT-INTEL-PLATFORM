/**
 * Cyber Watchdog webhook security, signing and delivery policy matrix.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import {
  attemptDelivery,
  classifyAddress,
  classifyHttpOutcome,
  resolveAndValidate,
  retryDelaySeconds,
  runVerificationChallenge,
  signPayload,
  signedHeaders,
  validateDestinationUrl,
  verifySignature,
} from "../watchdog-webhook.js";
import { DELIVERY_POLICY } from "../watchdog-policy.js";
import { MemoryLedger, applyLedgerMutation, emptyLedgerState, runDueDeliveries } from "../cyber-watchdog.js";

const SECRET = "whsec_" + "b".repeat(64);
const NOW_MS = Date.parse("2026-09-24T06:00:00Z");

function doh(map) {
  let calls = 0;
  const fn = async (url) => {
    calls += 1;
    const u = new URL(url);
    const rec = map[u.searchParams.get("name")];
    if (rec === "throw") throw new Error("down");
    if (!rec) return { ok: true, status: 200, json: async () => ({ Status: 3 }) };
    const want = u.searchParams.get("type") === "A" ? 1 : 28;
    return { ok: true, status: 200, json: async () => ({ Status: 0, Answer: rec.filter((a) => a.type === 5 || a.type === want) }) };
  };
  fn.calls = () => calls;
  return fn;
}

// ---------------------------------------------------------------------------
// Static URL + address classification
// ---------------------------------------------------------------------------

test("url: literal forbidden addresses and unsafe forms are refused", () => {
  const refused = [
    "https://10.1.2.3/h", "https://172.16.0.1/h", "https://192.168.1.1/h",          // RFC1918
    "https://127.0.0.1/h", "https://2130706433/h", "https://0x7f.1/h", "https://017700000001/h", // loopback, decimal/hex/octal
    "https://169.254.169.254/latest", "https://[::ffff:169.254.169.254]/x",         // metadata, mapped
    "https://[::1]/h", "https://[fe80::1]/h", "https://[fd00::1]/h", "https://[ff02::1]/h", // v6 loopback/link-local/ULA/multicast
    "https://0.0.0.0/h", "https://[::]/h", "https://100.64.1.1/h", "https://224.0.0.1/h", "https://240.0.0.1/h",
    "https://192.0.2.10/h", "https://[2001:db8::1]/h", "https://[64:ff9b::a00:1]/h", "https://[2002:a00:1::1]/h",
    "http://hooks.example.com/h",                                                   // http scheme
    "https://user:pass@hooks.example.com/h",                                        // userinfo
    "https://hooks.example.com:8443/h",                                             // non-443 port
    "https://localhost/h", "https://metadata.google.internal/h", "https://printer.local/h", "https://intranet/h",
    "::::", "", "https://", "javascript:alert(1)",                                  // malformed
  ];
  for (const url of refused) assert.ok(validateDestinationUrl(url).error, url);
  assert.equal(validateDestinationUrl("https://hooks.example.com/h?x=1").url, "https://hooks.example.com/h?x=1");
  assert.equal(validateDestinationUrl("https://[2606:4700:4700::1111]/h").error, undefined);
});

test("address classes", () => {
  const cases = {
    "8.8.8.8": true, "93.184.216.34": true, "10.0.0.1": false, "127.0.0.53": false, "169.254.1.1": false,
    "100.100.100.100": false, "198.18.0.1": false, "255.255.255.255": false,
    "2606:4700::1": true, "::ffff:8.8.8.8": false, "::ffff:10.0.0.1": false, "fc00::1": false,
    "fe80::abcd": false, "ff00::1": false, "::": false, "::1": false, "2001:db8::5": false, "3fff::1": false,
  };
  for (const [addr, ok] of Object.entries(cases)) assert.equal(classifyAddress(addr).allowed, ok, addr);
});

// ---------------------------------------------------------------------------
// DNS resolution
// ---------------------------------------------------------------------------

test("dns: public ok; private, mixed, CNAME-to-internal, v6 ULA and mapped refused; NXDOMAIN / resolver down retryable", async () => {
  const net = doh({
    "ok.example.com": [{ type: 1, data: "93.184.216.34" }, { type: 28, data: "2606:4700::6810:84e5" }],
    "priv.example.com": [{ type: 1, data: "192.168.0.10" }],
    "mixed.example.com": [{ type: 1, data: "93.184.216.34" }, { type: 28, data: "::1" }],
    "cname.example.com": [{ type: 5, data: "db.corp." }, { type: 1, data: "93.184.216.34" }],
    "cnameip.example.com": [{ type: 5, data: "10.0.0.1" }, { type: 1, data: "93.184.216.34" }],
    "ula.example.com": [{ type: 28, data: "fd00::1" }],
    "mapped.example.com": [{ type: 28, data: "::ffff:127.0.0.1" }],
    "down.example.com": "throw",
    "empty.example.com": [],
  });
  assert.equal((await resolveAndValidate("ok.example.com", net)).ok, true);
  for (const [host, err] of [["priv.example.com", "forbidden_address"], ["mixed.example.com", "forbidden_address"], ["cname.example.com", "forbidden_cname"], ["cnameip.example.com", "forbidden_cname"], ["ula.example.com", "forbidden_address"], ["mapped.example.com", "forbidden_address"]]) {
    const r = await resolveAndValidate(host, net);
    assert.equal(r.ok, false, host);
    assert.equal(r.error, err, host);
    assert.equal(r.retryable, false, host);
  }
  for (const [host, err] of [["nx.example.com", "dns_nxdomain"], ["down.example.com", "dns_unavailable"], ["empty.example.com", "dns_no_address"]]) {
    const r = await resolveAndValidate(host, net);
    assert.equal(r.error, err, host);
    assert.equal(r.retryable, true, host);
  }
});

test("dns: result changing public -> private between registration and delivery is caught at delivery", async () => {
  const answers = { "flip.example.com": [{ type: 1, data: "93.184.216.34" }] };
  const net = doh(answers);
  assert.equal((await resolveAndValidate("flip.example.com", net)).ok, true);
  answers["flip.example.com"] = [{ type: 1, data: "127.0.0.1" }];
  let posted = 0;
  const out = await attemptDelivery({
    destination: { id: "d1", url: "https://flip.example.com/h", secret: SECRET },
    eventId: "e1", deliveryId: "e1:d1", attempt: 1, rawBody: "{}",
    fetchImpl: async () => { posted += 1; return { status: 204, headers: new Headers() }; }, dnsFetch: net, nowMs: NOW_MS,
  });
  assert.equal(posted, 0);
  assert.equal(out.outcome, "failed");
  assert.equal(out.disable, "forbidden_address");
});

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

test("signature: correct / modified body / modified timestamp / expired / wrong secret", async () => {
  const body = JSON.stringify({ event_id: "e_1", title: "x" });
  const h = await signedHeaders({ secret: SECRET, eventId: "e_1", deliveryId: "e_1:d_1", attempt: 1, rawBody: body, nowMs: NOW_MS });
  const ts = h["X-CDB-Watchdog-Timestamp"];
  const sig = h["X-CDB-Watchdog-Signature"];
  assert.match(sig, /^v1=[0-9a-f]{64}$/);
  // Canonical construction, computed independently.
  const { createHmac } = await import("node:crypto");
  assert.equal(sig, "v1=" + createHmac("sha256", SECRET).update(ts + "." + body).digest("hex"));
  assert.equal((await verifySignature({ secret: SECRET, timestamp: ts, signature: sig, rawBody: body, nowMs: NOW_MS })).ok, true);
  assert.equal((await verifySignature({ secret: SECRET, timestamp: ts, signature: sig, rawBody: body + " ", nowMs: NOW_MS })).reason, "signature_mismatch");
  assert.equal((await verifySignature({ secret: SECRET, timestamp: String(Number(ts) + 1), signature: sig, rawBody: body, nowMs: NOW_MS })).reason, "signature_mismatch");
  assert.equal((await verifySignature({ secret: SECRET, timestamp: ts, signature: sig, rawBody: body, nowMs: NOW_MS + 301000 })).reason, "timestamp_outside_tolerance");
  assert.equal((await verifySignature({ secret: "whsec_" + "c".repeat(64), timestamp: ts, signature: sig, rawBody: body, nowMs: NOW_MS })).reason, "signature_mismatch");
  assert.equal(await signPayload(SECRET, ts, body), sig.slice(3));
});

test("signature: a retry sends the same event id and byte-identical body", async () => {
  const state = seededLedger();
  const sent = [];
  const fetchImpl = async (url, init) => { sent.push(init); return { status: 500, headers: new Headers() }; };
  const dns = doh({ "hooks.example.com": [{ type: 1, data: "93.184.216.34" }] });
  const ledger = memory(state);
  await runDueDeliveries({ ledger, subject: "s1", now: "2026-09-24T06:00:00Z", attempt: attemptDelivery, fetchImpl, dnsFetch: dns });
  await runDueDeliveries({ ledger, subject: "s1", now: "2026-09-24T06:05:00Z", attempt: attemptDelivery, fetchImpl, dnsFetch: dns });
  assert.equal(sent.length, 2);
  assert.equal(sent[0].headers["X-CDB-Watchdog-Event-ID"], sent[1].headers["X-CDB-Watchdog-Event-ID"]);
  assert.equal(sent[0].headers["X-CDB-Watchdog-Delivery-ID"], sent[1].headers["X-CDB-Watchdog-Delivery-ID"]);
  assert.equal(sent[0].body, sent[1].body);
  assert.equal(sent[0].headers["X-CDB-Watchdog-Attempt"], "1");
  assert.equal(sent[1].headers["X-CDB-Watchdog-Attempt"], "2");
});

// ---------------------------------------------------------------------------
// Delivery outcomes and the retry / dead-letter policy
// ---------------------------------------------------------------------------

test("http outcome matrix", () => {
  const expect = {
    200: "delivered", 202: "delivered", 204: "delivered",
    301: "failed", 302: "failed", 400: "failed", 401: "failed", 403: "failed", 404: "failed", 410: "failed",
    429: "retry", 500: "retry", 502: "retry", 503: "retry",
  };
  for (const [code, outcome] of Object.entries(expect)) assert.equal(classifyHttpOutcome(Number(code), null, NOW_MS).outcome, outcome, code);
  assert.equal(classifyHttpOutcome(410, null).disable, "gone");
  assert.equal(classifyHttpOutcome(302, null).error, "redirect_not_followed");
  assert.equal(classifyHttpOutcome(null, null).outcome, "retry", "timeout / network");
  assert.equal(classifyHttpOutcome(429, "30", NOW_MS).retry_after_seconds, 30);
  assert.equal(classifyHttpOutcome(503, new Date(NOW_MS + 90000).toUTCString(), NOW_MS).retry_after_seconds, 90);
  assert.equal(retryDelaySeconds(2, null), 60);
  assert.equal(retryDelaySeconds(3, null), 300);
  assert.equal(retryDelaySeconds(4, null), 1800);
  assert.equal(retryDelaySeconds(2, 120), 120, "Retry-After longer than backoff wins");
  assert.equal(retryDelaySeconds(2, 10), 60, "never shorter than the policy backoff");
  assert.equal(retryDelaySeconds(2, 999999), DELIVERY_POLICY.retry_after_max_seconds, "bounded");
});

test("delivery: timeout and DNS failure are retried; a hung receiver is aborted", async () => {
  const dns = doh({ "slow.example.com": [{ type: 1, data: "93.184.216.34" }], "gone.example.com": "throw" });
  const aborting = (url, init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted"))));
  const base = { eventId: "e", deliveryId: "e:d", attempt: 1, rawBody: "{}", nowMs: NOW_MS, dnsFetch: dns };
  const t0 = Date.now();
  const slow = await attemptDelivery({ ...base, destination: { id: "d", url: "https://slow.example.com/h", secret: SECRET }, fetchImpl: aborting });
  assert.equal(slow.outcome, "retry");
  assert.ok(Date.now() - t0 < DELIVERY_POLICY.timeout_ms + 1500);
  const dnsFail = await attemptDelivery({ ...base, destination: { id: "d", url: "https://gone.example.com/h", secret: SECRET }, fetchImpl: async () => ({ status: 204 }) });
  assert.equal(dnsFail.outcome, "retry");
  assert.equal(dnsFail.error, "dns_unavailable");
});

function seededLedger(destinations = [{ id: "d_1", url: "https://hooks.example.com/h" }]) {
  let st = emptyLedgerState();
  const apply = (op) => {
    const out = applyLedgerMutation(st, { subject: "s1", tier: "ENTERPRISE", now: "2026-09-24T05:59:00Z", ...op });
    assert.equal(out.error, undefined, JSON.stringify(out));
    if (!out.readOnly) st = out.state;
    return out;
  };
  for (const d of destinations) {
    apply({ type: "create_destination", id: d.id.slice(2), destination: { url: d.url }, secret: SECRET });
    apply({ type: "verification_result", id: d.id, ok: true });
  }
  apply({ type: "create_watch", id: "w1", watch: { name: "W", keywords: ["ransomware"] } });
  apply({ type: "append_events", events: [{ id: "e_1", dedupe_key: "w_w1|i1|r1", revision: "r1", watch_id: "w_w1", watch_name: "W", matched_item_id: "i1", title: "ransomware", matched_at: "2026-09-24T05:59:00Z" }], now: "2026-09-24T06:00:00Z" });
  return st;
}

function memory(state) {
  const l = new MemoryLedger();
  l.state = state;
  return l;
}

test("dead-letter: bounded attempts on the policy schedule, then failed and visible", async () => {
  const ledger = memory(seededLedger());
  const dns = doh({ "hooks.example.com": [{ type: 1, data: "93.184.216.34" }] });
  let n = 0;
  const fetchImpl = async () => { n += 1; return { status: 500, headers: new Headers() }; };
  let now = Date.parse("2026-09-24T06:00:00Z");
  for (let i = 0; i < 10; i += 1) {
    const run = await runDueDeliveries({ ledger, subject: "s1", now: new Date(now).toISOString(), attempt: attemptDelivery, fetchImpl, dnsFetch: dns });
    if (!run.next_delivery_due_at) break;
    now = Date.parse(run.next_delivery_due_at);
  }
  assert.equal(n, DELIVERY_POLICY.max_attempts, "exactly max_attempts, no endless retry");
  const e = ledger.state.events[0];
  assert.equal(e.deliveries[0].status, "failed");
  assert.equal(e.delivery_status, "failed");
  assert.equal(e.deliveries[0].attempts, 4);
  assert.equal(ledger.state.destinations[0].failure_count, 1);
  assert.equal(ledger.state.deliveries[0].outcome, "failed");
  // Schedule actually used: +0, +60s, +300s, +1800s.
  const times = ledger.state.deliveries.map((d) => Date.parse(d.at)).reverse();
  assert.deepEqual(times.slice(1).map((t, i) => (t - times[i]) / 1000), [60, 300, 1800]);
});

test("dead-letter: 401/403/404/410 are never retried; 410 disables the destination", async () => {
  for (const code of [400, 401, 403, 404, 410]) {
    const ledger = memory(seededLedger());
    const dns = doh({ "hooks.example.com": [{ type: 1, data: "93.184.216.34" }] });
    let n = 0;
    const run = await runDueDeliveries({ ledger, subject: "s1", now: "2026-09-24T06:00:00Z", attempt: attemptDelivery, fetchImpl: async () => { n += 1; return { status: code, headers: new Headers() }; }, dnsFetch: dns });
    assert.equal(n, 1, String(code));
    assert.equal(run.next_delivery_due_at, null, String(code));
    assert.equal(ledger.state.events[0].deliveries[0].status, "failed");
    assert.equal(ledger.state.destinations[0].state, code === 410 ? "failed" : "active", String(code));
  }
});

test("dead-letter: a destination failing 5 consecutive events is auto-disabled; success resets the count", async () => {
  let st = seededLedger();
  const dns = doh({ "hooks.example.com": [{ type: 1, data: "93.184.216.34" }] });
  const ledger = memory(st);
  for (let i = 2; i <= 6; i += 1) {
    await ledger.mutate({ type: "append_events", subject: "s1", tier: "ENTERPRISE", now: "2026-09-24T06:00:00Z", events: [{ id: "e_" + i, dedupe_key: "w_w1|i" + i + "|r", revision: "r", watch_id: "w_w1", matched_item_id: "i" + i, title: "t" }] });
  }
  await runDueDeliveries({ ledger, subject: "s1", now: "2026-09-24T06:00:00Z", attempt: attemptDelivery, fetchImpl: async () => ({ status: 404, headers: new Headers() }), dnsFetch: dns });
  assert.equal(ledger.state.destinations[0].failure_count, 6);
  assert.equal(ledger.state.destinations[0].state, "failed");
  assert.equal(ledger.state.destinations[0].disabled_reason, "consecutive_failures");

  const reset = memory(seededLedger());
  await runDueDeliveries({ ledger: reset, subject: "s1", now: "2026-09-24T06:00:00Z", attempt: attemptDelivery, fetchImpl: async () => ({ status: 404, headers: new Headers() }), dnsFetch: dns });
  assert.equal(reset.state.destinations[0].failure_count, 1);
  await reset.mutate({ type: "append_events", subject: "s1", tier: "ENTERPRISE", now: "2026-09-24T06:01:00Z", events: [{ id: "e_ok", dedupe_key: "w_w1|ok|r", revision: "r", watch_id: "w_w1", matched_item_id: "ok", title: "t" }] });
  await runDueDeliveries({ ledger: reset, subject: "s1", now: "2026-09-24T06:01:00Z", attempt: attemptDelivery, fetchImpl: async () => ({ status: 200, headers: new Headers() }), dnsFetch: dns });
  assert.equal(reset.state.destinations[0].failure_count, 0);
  assert.equal(reset.state.destinations[0].state, "active");
});

test("idempotency: per-destination delivery ids and independent results (partial)", async () => {
  const ledger = memory(seededLedger([{ id: "d_a", url: "https://a.example.com/h" }, { id: "d_b", url: "https://b.example.com/h" }]));
  const dns = doh({ "a.example.com": [{ type: 1, data: "93.184.216.34" }], "b.example.com": [{ type: 1, data: "93.184.216.35" }] });
  const fetchImpl = async (url) => ({ status: url.includes("a.example") ? 204 : 403, headers: new Headers() });
  await runDueDeliveries({ ledger, subject: "s1", now: "2026-09-24T06:00:00Z", attempt: attemptDelivery, fetchImpl, dnsFetch: dns });
  const e = ledger.state.events[0];
  assert.deepEqual(e.deliveries.map((d) => [d.delivery_id, d.status]), [["e_1:d_a", "delivered"], ["e_1:d_b", "failed"]]);
  assert.equal(e.delivery_status, "partial");
});

test("bounded: one run attempts at most max_deliveries_per_run; overlapping runs never double-send", async () => {
  const ledger = memory(seededLedger());
  for (let i = 2; i <= 40; i += 1) {
    await ledger.mutate({ type: "append_events", subject: "s1", tier: "ENTERPRISE", now: "2026-09-24T06:00:00Z", events: [{ id: "e_" + i, dedupe_key: "w_w1|i" + i + "|r", revision: "r", watch_id: "w_w1", matched_item_id: "i" + i, title: "t" }] });
  }
  const dns = doh({ "hooks.example.com": [{ type: 1, data: "93.184.216.34" }] });
  const seen = [];
  const fetchImpl = async (url, init) => { seen.push(init.headers["X-CDB-Watchdog-Delivery-ID"]); return { status: 204, headers: new Headers() }; };
  const now = "2026-09-24T06:00:00Z";
  const [r1, r2] = await Promise.all([
    runDueDeliveries({ ledger, subject: "s1", now, attempt: attemptDelivery, fetchImpl, dnsFetch: dns }),
    runDueDeliveries({ ledger, subject: "s1", now, attempt: attemptDelivery, fetchImpl, dnsFetch: dns }),
  ]);
  assert.ok(r1.attempted <= DELIVERY_POLICY.max_deliveries_per_run);
  assert.ok(r2.attempted <= DELIVERY_POLICY.max_deliveries_per_run);
  assert.equal(new Set(seen).size, seen.length, "no delivery id sent twice");
});

test("verification challenge: echo required, redirects refused, private resolution refused", async () => {
  const dns = doh({ "ok.example.com": [{ type: 1, data: "93.184.216.34" }], "priv.example.com": [{ type: 1, data: "10.0.0.9" }] });
  const dest = (host) => ({ id: "d_1", url: "https://" + host + "/h", secret: SECRET });
  const echo = async (url, init) => ({ status: 200, json: async () => ({ challenge: JSON.parse(init.body).challenge }) });
  assert.equal((await runVerificationChallenge({ destination: dest("ok.example.com"), nonce: "ab".repeat(16), fetchImpl: echo, dnsFetch: dns })).ok, true);
  const wrong = async () => ({ status: 200, json: async () => ({ challenge: "cd".repeat(16) }) });
  assert.equal((await runVerificationChallenge({ destination: dest("ok.example.com"), nonce: "ab".repeat(16), fetchImpl: wrong, dnsFetch: dns })).error, "challenge_mismatch");
  const redirect = async () => ({ status: 307, json: async () => ({}) });
  assert.equal((await runVerificationChallenge({ destination: dest("ok.example.com"), nonce: "ab".repeat(16), fetchImpl: redirect, dnsFetch: dns })).error, "redirect_not_followed");
  let posted = 0;
  const count = async () => { posted += 1; return { status: 200, json: async () => ({}) }; };
  assert.equal((await runVerificationChallenge({ destination: dest("priv.example.com"), nonce: "ab".repeat(16), fetchImpl: count, dnsFetch: dns })).error, "forbidden_address");
  assert.equal(posted, 0);
});
