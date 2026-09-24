/**
 * CYBER WATCHDOG COMMAND CENTER (PR A backend) -- evidence-cited priority on
 * every event, analyst triage workflow, server-side inbox filters and the
 * event detail route. Drives the real gateway router and the real
 * WatchdogLedger / WatchdogScheduler Durable Object classes via the harness.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { FEED_ITEMS, PRO2_KEY, PRO_KEY, craftJwt, feedObject, harness } from "./watchdog-harness.js";
import { compactPriority, computeEventPriority, eventPriority } from "../watchdog-priority.js";
import {
  EVENT_RETENTION, STATUS_HISTORY_RETENTION, TRIAGE_STATUSES, analyticsFromEvents, applyLedgerMutation,
  candidateEvent, emptyLedgerState, eventStatus, filterEvents, parseInboxQuery, projectItem,
} from "../cyber-watchdog.js";

async function session(h, key) {
  const res = await h.call("POST", "/api/watchdog/session", { key });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.token;
}

async function proWithEvents(h, key = PRO_KEY) {
  const t = await session(h, key);
  const created = await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "All lenses", lenses: ["cybersecurity", "technology", "security_operations"] } });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const first = await h.call("GET", "/api/watchdog/events", { bearer: t });
  assert.equal(first.status, 200);
  return { t, events: first.body.events };
}

const sp = (q) => new URLSearchParams(q);

// ---------------------------------------------------------------------------
// Priority engine
// ---------------------------------------------------------------------------

test("priority: KEV + critical impact is CRITICAL and every point cites its field", () => {
  const p = computeEventPriority({ severity: "CRITICAL", cvss_score: 9.8, epss_score: 0.91, kev_present: true, title: "Actively exploited RCE" });
  assert.equal(p.band, "CRITICAL");
  assert.ok(p.score >= 70 && p.score <= 100);
  for (const f of p.factors) {
    if (f.known) assert.ok(f.evidence && f.evidence.length, "known factor " + f.id + " must cite evidence");
    else assert.equal(f.evidence, null);
    assert.ok(f.points <= f.max);
  }
  assert.equal(p.factors.find((f) => f.id === "cvss").evidence, "cvss_score=9.8");
});

test("priority: missing evidence is never scored 0 -- null score, INSUFFICIENT_EVIDENCE", () => {
  const none = computeEventPriority({ title: "Vendor blog post" });
  assert.equal(none.score, null);
  assert.equal(none.band, "INSUFFICIENT_EVIDENCE");
  assert.ok(none.factors.every((f) => !f.known && f.points === 0));
  // Activity words alone do not establish the threat.
  const activityOnly = computeEventPriority({ title: "Ransomware group named", actor_tag: "APT-X" });
  assert.equal(activityOnly.band, "INSUFFICIENT_EVIDENCE");
  assert.equal(activityOnly.score, null);
  // Out-of-range numbers are unknown, not clamped.
  const bad = computeEventPriority({ cvss_score: 11, epss_score: 2, severity: "BOGUS" });
  assert.equal(bad.band, "INSUFFICIENT_EVIDENCE");
  assert.equal(computeEventPriority(null).band, "INSUFFICIENT_EVIDENCE");
});

test("priority: floors -- CVSS >= 9 alone is at least HIGH, KEV alone is at least HIGH, cited", () => {
  const cvss10 = computeEventPriority({ cvss_score: 10 });
  assert.equal(cvss10.score, 25);
  assert.equal(cvss10.band, "HIGH");
  assert.deepEqual(cvss10.floors_applied, ["cvss_ge_9"]);
  const kev = computeEventPriority({ kev_present: true });
  assert.equal(kev.band, "HIGH");
  assert.deepEqual(kev.floors_applied, ["kev_listed"]);
  const low = computeEventPriority({ severity: "LOW", cvss_score: 2.1 });
  assert.equal(low.band, "LOW");
  assert.deepEqual(low.floors_applied, []);
  const sevOnly = computeEventPriority({ severity: "HIGH" });
  assert.equal(sevOnly.band, "MEDIUM", "feed HIGH severity is never shown as LOW priority");
  assert.deepEqual(sevOnly.floors_applied, ["severity_high"]);
  assert.equal(computeEventPriority({ severity: "CRITICAL" }).band, "HIGH");
  const notKev = computeEventPriority({ kev_present: false, severity: "MEDIUM" });
  assert.equal(notKev.factors.find((f) => f.id === "kev").known, true);
  assert.equal(notKev.factors.find((f) => f.id === "kev").points, 0);
});

test("priority: compact stored form expands to the identical public shape; legacy events report INSUFFICIENT_EVIDENCE", () => {
  const p = computeEventPriority({ severity: "HIGH", cvss_score: 8.1, actor_tag: "FIN7" });
  assert.deepEqual(eventPriority({ priority: compactPriority(p) }), p);
  const legacy = eventPriority({ id: "e_old" });
  assert.equal(legacy.band, "INSUFFICIENT_EVIDENCE");
  assert.equal(legacy.legacy, true);
  assert.equal(eventStatus({ acknowledged: true }), "ACKNOWLEDGED");
  assert.equal(eventStatus({}), "NEW");
});

test("retention bound: a full ledger of prioritized, triaged events stays compact", () => {
  let state = emptyLedgerState();
  const watch = { id: "w_1", name: "w", logic: "OR", enabled: true, criteria: { keywords: ["cve"] } };
  const events = [];
  for (let i = 0; i < EVENT_RETENTION; i += 1) {
    events.push(candidateEvent(watch, projectItem({ id: "intel--" + i, title: "CVE-2026-" + (1000 + i) + " exploited in the wild ransomware", severity: "CRITICAL", cvss_score: 9.8, epss_score: 0.9, kev_present: true, actor_tag: "APT-X" }), "2026-09-24T00:00:00Z", "2026-09-24T00:00:00Z"));
  }
  let out = applyLedgerMutation(state, { subject: "s", tier: "PRO", type: "append_events", events, now: "2026-09-24T00:00:00Z" });
  state = out.state;
  for (let n = 0; n < STATUS_HISTORY_RETENTION + 5; n += 1) {
    out = applyLedgerMutation(state, { subject: "s", tier: "PRO", type: "set_status", ids: state.events.slice(0, 50).map((e) => e.id), status: n % 2 ? "INVESTIGATING" : "RESOLVED", note: "x".repeat(280), now: "2026-09-24T00:00:00Z" });
    state = out.state;
  }
  assert.equal(state.events[0].status_history.length, STATUS_HISTORY_RETENTION);
  const bytes = JSON.stringify(state).length;
  assert.ok(bytes < 1_500_000, "ledger record must stay well under the 2 MB Durable Object value limit, got " + bytes);
});

// ---------------------------------------------------------------------------
// Triage workflow through the real router + ledger DO
// ---------------------------------------------------------------------------

test("triage: NEW -> INVESTIGATING -> RESOLVED -> reopen, history bounded, legacy acknowledged kept in sync", async () => {
  const h = harness();
  const { t, events } = await proWithEvents(h);
  assert.equal(events.length, 3);
  for (const e of events) {
    assert.equal(e.status, "NEW");
    assert.equal(e.acknowledged, false);
    assert.ok(e.priority && e.priority.version === "watchdog-priority-1");
    assert.ok(Array.isArray(e.priority.factors) && e.priority.factors.length === 5, "public event carries the expanded priority");
  }
  const kev = events.find((e) => e.matched_item_id === "intel--kev-1");
  assert.equal(kev.priority.band, "CRITICAL", "KEV + CRITICAL severity fixture");

  const inv = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { ids: [kev.id], status: "investigating", note: "Checking Windows fleet <b>now</b>" } });
  assert.equal(inv.status, 200, JSON.stringify(inv.body));
  assert.deepEqual(inv.body.updated, [kev.id]);
  const res = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { id: kev.id, status: "RESOLVED" } });
  assert.deepEqual(res.body.updated, [kev.id]);
  const same = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { ids: [kev.id], status: "RESOLVED" } });
  assert.deepEqual(same.body.unchanged, [kev.id]);
  const reopen = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { ids: [kev.id], status: "NEW" } });
  assert.deepEqual(reopen.body.updated, [kev.id]);

  const detail = await h.call("GET", "/api/watchdog/events/item?id=" + kev.id, { bearer: t });
  assert.equal(detail.status, 200);
  const ev = detail.body.event;
  assert.equal(ev.status, "NEW");
  assert.equal(ev.acknowledged, false, "reopened to NEW -> legacy acknowledged false");
  assert.deepEqual(ev.status_history.map((x) => x.to), ["NEW", "RESOLVED", "INVESTIGATING"]);
  assert.equal(ev.status_history[2].note, "Checking Windows fleet bnow/b", "note is sanitized");
  assert.equal(ev.status_history[0].by, "cust_pro_1");

  // Legacy ack endpoint still works and moves NEW -> ACKNOWLEDGED.
  const ack = await h.call("POST", "/api/watchdog/events/ack", { bearer: t, body: { ids: [kev.id] } });
  assert.equal(ack.body.acknowledged, 1);
  const after = await h.call("GET", "/api/watchdog/events/item?id=" + kev.id, { bearer: t });
  assert.equal(after.body.event.status, "ACKNOWLEDGED");
  assert.equal(after.body.event.acknowledged, true);

  // No auto-resolution: a new feed generation leaves triage state alone.
  h.state.feed = feedObject(FEED_ITEMS, 30);
  await h.cron();
  await h.call("GET", "/api/watchdog/events", { bearer: t });
  const still = await h.call("GET", "/api/watchdog/events/item?id=" + kev.id, { bearer: t });
  assert.equal(still.body.event.status, "ACKNOWLEDGED");
});

test("triage: invalid input is refused with nothing written", async () => {
  const h = harness();
  const { t, events } = await proWithEvents(h);
  const writes = h.ledgerStorage("cust_pro_1").writes;
  const bad = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { ids: [events[0].id], status: "CLOSED" } });
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error, "invalid_status");
  const none = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { status: "RESOLVED" } });
  assert.equal(none.body.error, "ids_required");
  const many = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { status: "RESOLVED", ids: Array.from({ length: 51 }, (_, i) => "e_" + i) } });
  assert.equal(many.body.error, "too_many_ids");
  const ghost = await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { status: "RESOLVED", ids: ["e_doesnotexist"] } });
  assert.equal(ghost.status, 200);
  assert.deepEqual(ghost.body.not_found, ["e_doesnotexist"]);
  const get = await h.call("GET", "/api/watchdog/events/status", { bearer: t });
  assert.equal(get.status, 405);
  assert.equal(h.ledgerStorage("cust_pro_1").writes, writes, "refusals and no-op updates do not write");
});

test("triage: isolation -- another customer cannot see or change this customer's events", async () => {
  const h = harness();
  const { events } = await proWithEvents(h);
  const t2 = await session(h, PRO2_KEY);
  const other = await h.call("POST", "/api/watchdog/events/status", { bearer: t2, body: { ids: [events[0].id], status: "IGNORED" } });
  assert.equal(other.status, 200);
  assert.deepEqual(other.body.updated, []);
  assert.deepEqual(other.body.not_found, [events[0].id]);
  const peek = await h.call("GET", "/api/watchdog/events/item?id=" + events[0].id, { bearer: t2 });
  assert.equal(peek.status, 404);
  assert.equal(h.ledgerState("cust_pro_1").events.find((e) => e.id === events[0].id).status, "NEW");
});

test("entitlement and scopes: FREE refused; a read-only session cannot change status", async () => {
  const h = harness();
  const anon = await h.call("POST", "/api/watchdog/events/status", { body: { ids: ["e_x"], status: "RESOLVED" } });
  assert.ok(anon.status === 401 || anon.status === 403, "unauthenticated triage is refused");
  const now = Math.floor(Date.now() / 1000);
  const readOnly = await craftJwt({ sub: "cust_pro_1", tier: "PRO", iss: "SENTINEL-APEX", aud: "cdb-watchdog", auth_time: now, jti: "j2", scope: "watchdog:read watchdog:events:read", iat: now, exp: now + 600 });
  const denied = await h.call("POST", "/api/watchdog/events/status", { bearer: readOnly, body: { ids: ["e_x"], status: "RESOLVED" } });
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error, "insufficient_scope");
  assert.equal(denied.body.required_scope, "watchdog:events:ack");
  const item = await h.call("GET", "/api/watchdog/events/item?id=e_x", { bearer: readOnly });
  assert.equal(item.status, 404, "events:read is enough for the detail route");
});

// ---------------------------------------------------------------------------
// Inbox filters
// ---------------------------------------------------------------------------

test("inbox: no parameters keeps the previous list and order exactly", async () => {
  const h = harness();
  const { t, events } = await proWithEvents(h);
  const plain = await h.call("GET", "/api/watchdog/events?evaluate=0", { bearer: t });
  assert.deepEqual(plain.body.events.map((e) => e.id), events.map((e) => e.id));
  assert.equal(plain.body.matched_total, plain.body.total);
  assert.equal(plain.body.filters, null);
  assert.ok(plain.body.analytics.by_status && plain.body.analytics.by_priority);
  assert.equal(plain.body.analytics.open, 3);
});

test("inbox: status, priority, severity, open, q, sort=priority filter server-side", async () => {
  const h = harness();
  const { t, events } = await proWithEvents(h);
  const kev = events.find((e) => e.matched_item_id === "intel--kev-1");
  const soc = events.find((e) => e.matched_item_id === "intel--soc-3");
  await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { ids: [soc.id], status: "RESOLVED" } });

  const crit = await h.call("GET", "/api/watchdog/events?evaluate=0&priority=CRITICAL", { bearer: t });
  assert.deepEqual(crit.body.events.map((e) => e.id), [kev.id]);
  assert.equal(crit.body.total, 3);
  assert.equal(crit.body.matched_total, 1);
  assert.deepEqual(crit.body.filters.priority, ["CRITICAL"]);

  const open = await h.call("GET", "/api/watchdog/events?evaluate=0&open=1", { bearer: t });
  assert.equal(open.body.matched_total, 2);
  assert.ok(!open.body.events.some((e) => e.id === soc.id));

  const resolved = await h.call("GET", "/api/watchdog/events?evaluate=0&status=resolved", { bearer: t });
  assert.deepEqual(resolved.body.events.map((e) => e.id), [soc.id]);

  const sev = await h.call("GET", "/api/watchdog/events?evaluate=0&severity=HIGH,MEDIUM", { bearer: t });
  assert.equal(sev.body.matched_total, 2);

  const q = await h.call("GET", "/api/watchdog/events?evaluate=0&q=cve-2026-1000", { bearer: t });
  assert.deepEqual(q.body.events.map((e) => e.id), [kev.id]);

  const sorted = await h.call("GET", "/api/watchdog/events?evaluate=0&sort=priority", { bearer: t });
  const ranks = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INSUFFICIENT_EVIDENCE: 0 };
  const bands = sorted.body.events.map((e) => ranks[e.priority.band]);
  assert.deepEqual(bands, bands.slice().sort((a, b) => b - a));
  assert.equal(sorted.body.events[0].id, kev.id);
});

test("inbox: invalid filters are 400 and evaluate nothing", async () => {
  const h = harness();
  const { t } = await proWithEvents(h);
  const before = h.ledgerStorage("cust_pro_1").writes;
  for (const q of ["status=DONE", "priority=URGENT", "sort=random", "since=yesterday", "severity=SEVERE"]) {
    const r = await h.call("GET", "/api/watchdog/events?" + q, { bearer: t });
    assert.equal(r.status, 400, q);
    assert.equal(r.body.error, "invalid_filter");
  }
  assert.equal(h.ledgerStorage("cust_pro_1").writes, before);
});

test("inbox helpers: since and watch_id filters; priority sort is stable", () => {
  const mk = (id, band, score, at, watch) => ({ id, watch_id: watch, matched_at: at, priority: { band, score, f: [] } });
  const list = [mk("a", "HIGH", 50, "2026-09-24T03:00:00Z", "w1"), mk("b", "HIGH", 50, "2026-09-24T02:00:00Z", "w2"), mk("c", "CRITICAL", 80, "2026-09-24T01:00:00Z", "w1")];
  const { query } = parseInboxQuery(sp("sort=priority"));
  assert.deepEqual(filterEvents(list, query).map((e) => e.id), ["c", "a", "b"]);
  assert.deepEqual(filterEvents(list, parseInboxQuery(sp("since=2026-09-24T02:00:00Z")).query).map((e) => e.id), ["a", "b"]);
  assert.deepEqual(filterEvents(list, parseInboxQuery(sp("watch_id=w1&sort=oldest")).query).map((e) => e.id), ["c", "a"]);
  const a = analyticsFromEvents(list, Date.parse("2026-09-24T04:00:00Z"));
  assert.equal(a.by_priority.HIGH, 2);
  assert.equal(a.open_critical, 1);
  assert.equal(TRIAGE_STATUSES.length, 5);
});

// ---------------------------------------------------------------------------
// Detail route and scheduler path
// ---------------------------------------------------------------------------

test("detail: current advisory only from a FRESH feed; revised and removed items are labelled", async () => {
  const h = harness();
  const { t, events } = await proWithEvents(h);
  const kev = events.find((e) => e.matched_item_id === "intel--kev-1");
  const cur = await h.call("GET", "/api/watchdog/events/item?id=" + kev.id, { bearer: t });
  assert.equal(cur.body.feed_item_status, "current");
  assert.equal(cur.body.feed_item.id, "intel--kev-1");
  assert.equal(cur.body.watch.name, "All lenses");

  h.state.feed = feedObject([{ ...FEED_ITEMS[0], severity: "HIGH" }], 60);
  assert.equal((await h.call("GET", "/api/watchdog/events/item?id=" + kev.id, { bearer: t })).body.feed_item_status, "revised_since_match");

  h.state.feed = feedObject([FEED_ITEMS[1]], 60);
  const gone = await h.call("GET", "/api/watchdog/events/item?id=" + kev.id, { bearer: t });
  assert.equal(gone.body.feed_item_status, "not_on_current_feed");
  assert.equal(gone.body.feed_item, null);

  h.state.feed = feedObject(FEED_ITEMS, 10 * 86400);
  const stale = await h.call("GET", "/api/watchdog/events/item?id=" + kev.id, { bearer: t });
  assert.equal(stale.status, 200, "the stored event stays readable when the feed is degraded");
  assert.equal(stale.body.feed_item_status, "feed_not_fresh");
  assert.equal(stale.body.feed_item, null);

  assert.equal((await h.call("GET", "/api/watchdog/events/item", { bearer: t })).body.error, "id_required");
});

test("scheduler: events created by the autonomous cron carry the same priority as the request path", async () => {
  const h = harness();
  const t = await session(h, PRO_KEY);
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { name: "KEV", cves: ["CVE-2026-1000"] } });
  await h.cron();
  const stored = h.ledgerState("cust_pro_1").events;
  assert.equal(stored.length, 1);
  assert.equal(stored[0].origin, "scheduler");
  assert.equal(stored[0].status, "NEW");
  assert.deepEqual(eventPriority(stored[0]), computeEventPriority(projectItem(FEED_ITEMS[0])));
});
