/**
 * CYBER WATCHDOG production canary -- step machine.
 *
 * Transport-agnostic: `http(method, path, { key, bearer, body })` returns
 * { status, body }. canary.mjs binds it to https://intel.cyberdudebivash.com;
 * the unit test binds it to the in-process gateway harness.
 *
 * Rules this code enforces:
 *   - The API key is used for exactly one request (the session exchange) and
 *     never appears in evidence, logs or errors.
 *   - Watch criteria are chosen from a REAL item on the current authoritative
 *     feed; nothing is invented. If no item yields an unambiguous criterion the
 *     canary stops with NO_UNAMBIGUOUS_FEED_ITEM instead of weakening the check.
 *   - Every assertion failure stops the run (FAIL) after best-effort cleanup.
 */
import { matchWatch } from "../../workers/intel-gateway/src/cyber-watchdog.js";
import { verifySignature } from "../../workers/intel-gateway/src/watchdog-webhook.js";

export class CanaryFailure extends Error {
  constructor(step, message) { super(step + ": " + message); this.step = step; }
}

function check(step, cond, message) {
  if (!cond) throw new CanaryFailure(step, message);
}

/**
 * Picks a watch criterion that matches exactly one item of the given feed,
 * using the production matcher. Prefers a CVE id, then a distinctive title token.
 */
export function pickUnambiguousCriterion(items, exclude = new Set()) {
  const list = (items || []).filter((i) => i && typeof i.id === "string" && !exclude.has(i.id));
  const count = (criteria) => list.filter((i) => matchWatch({ id: "w_probe", enabled: true, logic: "OR", criteria }, i).matched).length;
  for (const item of list) {
    const cves = Array.isArray(item.cve_ids) ? item.cve_ids : [];
    for (const cve of cves) {
      if (typeof cve === "string" && /^CVE-\d{4}-\d{4,}$/i.test(cve) && count({ cves: [cve.toUpperCase()] }) === 1) {
        return { item_id: item.id, criteria: { cves: [cve.toUpperCase()] } };
      }
    }
  }
  for (const item of list) {
    const tokens = String(item.title || "").toLowerCase().split(/[^a-z0-9-]+/).filter((t) => t.length >= 7);
    for (const t of tokens) {
      if (count({ keywords: [t] }) === 1) return { item_id: item.id, criteria: { keywords: [t] } };
    }
  }
  return null;
}

async function session(http, key, tenant) {
  const q = tenant ? "?tenant=" + encodeURIComponent(tenant) : "";
  const res = await http("POST", "/api/watchdog/session" + q, { key });
  check("authenticate", res.status === 200 && res.body && res.body.token, "session exchange returned " + res.status);
  return { token: res.body.token, tier: res.body.tier, scopes: res.body.scopes || [] };
}

function eventsFor(body, watchId) {
  return (body && Array.isArray(body.events) ? body.events : []).filter((e) => e.watch_id === watchId);
}

/**
 * PRO acceptance (Phase 14). Returns evidence; throws CanaryFailure.
 */
export async function runProCanary({ http, key, runId, log = () => {}, feedItems }) {
  const ev = { mode: "PRO", run_id: runId, steps: [] };
  const step = (name, detail) => { ev.steps.push({ step: name, ok: true, ...detail }); log(name, detail); };
  const s = await session(http, key);
  step("authenticate", { tier: s.tier, scopes: s.scopes.length });
  const auth = { bearer: s.token };

  const pick = pickUnambiguousCriterion(feedItems);
  check("select_real_item", pick, "NO_UNAMBIGUOUS_FEED_ITEM");
  step("select_real_item", { matched_item_id: pick.item_id, criteria: pick.criteria });

  let watchId = null;
  try {
    const created = await http("POST", "/api/watchdog/watches", { ...auth, body: { name: "CANARY-" + runId, logic: "OR", criteria: pick.criteria } });
    check("create_watch", created.status === 201, "status " + created.status);
    watchId = created.body.watch.id;
    step("create_watch", { watch_id: watchId });

    const read = await http("GET", "/api/watchdog/watches", auth);
    check("read_watch", read.status === 200 && read.body.watches.some((w) => w.id === watchId), "watch not listed");
    step("read_watch", {});

    const first = await http("GET", "/api/watchdog/events?limit=50", auth);
    check("evaluate", first.status === 200, "status " + first.status + " freshness " + (first.body && first.body.freshness_status));
    const mine = eventsFor(first.body, watchId);
    check("exactly_one_event", mine.length === 1 && mine[0].matched_item_id === pick.item_id, "events for watch: " + mine.length);
    ev.event_id = mine[0].id;
    ev.feed_generation = first.body.feed_generated_at;
    ev.matched_item_id = mine[0].matched_item_id;
    step("exactly_one_event", { event_id: ev.event_id, feed_generation: ev.feed_generation, freshness_status: first.body.freshness_status });

    const second = await http("GET", "/api/watchdog/events?limit=50", auth);
    const again = eventsFor(second.body, watchId);
    check("no_duplicate", again.length === 1 && again[0].id === ev.event_id, "events after re-evaluation: " + again.length);
    ev.dedupe = { second_evaluation_events_for_watch: again.length, same_event_id: again[0].id === ev.event_id };
    step("no_duplicate", ev.dedupe);
    step("event_visible", {});

    const ack = await http("POST", "/api/watchdog/events/ack", { ...auth, body: { ids: [ev.event_id] } });
    check("ack", ack.status === 200 && ack.body.acknowledged === 1, "acknowledged " + (ack.body && ack.body.acknowledged));
    const persisted = await http("GET", "/api/watchdog/events?evaluate=0&limit=50", auth);
    const acked = eventsFor(persisted.body, watchId)[0];
    check("ack_persists", acked && acked.acknowledged === true, "not persisted");
    ev.ack = { acknowledged: true, acknowledged_at: acked.acknowledged_at };
    step("ack_persists", ev.ack);

    const edit = await http("PATCH", "/api/watchdog/watches?id=" + watchId, { ...auth, body: { name: "CANARY-" + runId + "-edited" } });
    check("edit_watch", edit.status === 200 && edit.body.watch.name.endsWith("-edited"), "status " + edit.status);
    step("edit_watch", {});
    const dis = await http("PATCH", "/api/watchdog/watches?id=" + watchId, { ...auth, body: { enabled: false } });
    check("disable_watch", dis.status === 200 && dis.body.watch.enabled === false, "status " + dis.status);
    step("disable_watch", {});
    const quiet = await http("GET", "/api/watchdog/events?limit=50", auth);
    check("disabled_stops_events", eventsFor(quiet.body, watchId).length === 1, "disabled watch generated events");
    step("disabled_stops_events", {});

    const hook = await http("POST", "/api/watchdog/destinations", { ...auth, body: { url: "https://example.com/never-called" } });
    if (s.tier === "PRO") {
      check("pro_denied_webhooks", hook.status === 403, "PRO destination status " + hook.status);
      step("pro_denied_webhooks", {});
    }
  } finally {
    if (watchId) {
      const del = await http("DELETE", "/api/watchdog/watches?id=" + watchId, auth);
      const after = await http("GET", "/api/watchdog/watches", auth);
      const gone = del.status === 200 && after.status === 200 && !after.body.watches.some((w) => w.id === watchId);
      ev.cleanup = { watch_deleted: gone };
      if (gone) step("cleanup", {});
    }
    await http("DELETE", "/api/watchdog/session", auth).catch(() => {});
  }
  check("cleanup", ev.cleanup && ev.cleanup.watch_deleted, "watch not removed");
  ev.result = "PASS";
  return ev;
}

/**
 * Autonomous proof: create a watch and wait for an event created by the
 * scheduler (origin "scheduler") while observing read-only (evaluate=0).
 */
export async function runAutonomousCanary({ http, key, runId, feedItems, sleep, maxWaitMs = 20 * 60000, pollMs = 60000, log = () => {} }) {
  const s = await session(http, key);
  const auth = { bearer: s.token };
  const pick = pickUnambiguousCriterion(feedItems);
  check("select_real_item", pick, "NO_UNAMBIGUOUS_FEED_ITEM");
  const created = await http("POST", "/api/watchdog/watches", { ...auth, body: { name: "CANARY-AUTO-" + runId, criteria: pick.criteria } });
  check("create_watch", created.status === 201, "status " + created.status);
  const watchId = created.body.watch.id;
  let auth2 = auth;
  const ev = { mode: "AUTONOMOUS", run_id: runId, watch_id: watchId, matched_item_id: pick.item_id };
  try {
    let waited = 0;
    for (;;) {
      const r = await http("GET", "/api/watchdog/events?evaluate=0&limit=50", auth2);
      if (r.status === 401) {
        const s2 = await session(http, key);
        auth2 = { bearer: s2.token };
        continue;
      }
      const mine = eventsFor(r.body, watchId);
      if (mine.length) {
        check("scheduler_origin", mine[0].origin === "scheduler", "first event origin " + mine[0].origin);
        ev.event_id = mine[0].id;
        ev.matched_at = mine[0].matched_at;
        ev.waited_ms = waited;
        ev.result = "PASS";
        log("autonomous_event", { event_id: ev.event_id, waited_ms: waited });
        return ev;
      }
      check("wait", waited < maxWaitMs, "no scheduler event within " + maxWaitMs + "ms");
      await sleep(pollMs);
      waited += pollMs;
    }
  } finally {
    await http("DELETE", "/api/watchdog/watches?id=" + watchId, auth2).catch(() => {});
  }
}

/**
 * ENTERPRISE acceptance (Phase 15). `sink` is an owner-controlled receiver:
 *   { url, records(): Promise<[{headers, raw}]>, setMode(status, retryAfter) }
 */
export async function runEnterpriseCanary({ http, key, runId, feedItems, sink, sleep, log = () => {} }) {
  const ev = { mode: "ENTERPRISE", run_id: runId, steps: [] };
  const step = (name, detail) => { ev.steps.push({ step: name, ok: true, ...detail }); log(name, detail); };
  const s = await session(http, key);
  check("authenticate", s.scopes.includes("watchdog:destinations:write"), "session lacks destinations scope");
  step("authenticate", { tier: s.tier });
  const auth = { bearer: s.token };
  const pick = pickUnambiguousCriterion(feedItems);
  check("select_real_item", pick, "NO_UNAMBIGUOUS_FEED_ITEM");
  let watchId = null;
  let watch2 = null;
  let destId = null;
  const hdr = (r, name) => r.headers[name] ?? r.headers[name.toLowerCase()];
  const waitFor = async (pred, what, maxMs = 180000) => {
    for (let waited = 0; waited <= maxMs; waited += 5000) {
      const recs = await sink.records();
      const hit = recs.filter(pred);
      if (hit.length) return hit;
      await sleep(5000);
    }
    throw new CanaryFailure(what, "not observed within " + maxMs + "ms");
  };
  try {
    await sink.setMode(204);
    const created = await http("POST", "/api/watchdog/watches", { ...auth, body: { name: "CANARY-ENT-" + runId, criteria: pick.criteria } });
    check("create_watch", created.status === 201, "status " + created.status);
    watchId = created.body.watch.id;
    step("create_watch", { watch_id: watchId });

    const reg = await http("POST", "/api/watchdog/destinations", { ...auth, body: { url: sink.url } });
    check("register_destination", reg.status === 201 && reg.body.destination.state === "pending" && /^whsec_/.test(reg.body.signing_secret || ""), "status " + reg.status);
    destId = reg.body.destination.id;
    const secret = reg.body.signing_secret;
    step("register_destination", { destination_id: destId, state: "pending" });

    const ver = await http("POST", "/api/watchdog/destinations/verify?id=" + destId, { ...auth, body: {} });
    check("verify_destination", ver.status === 200 && ver.body.destination.state === "active", "status " + ver.status + " " + (ver.body && ver.body.error));
    step("verify_destination", {});

    const first = await http("GET", "/api/watchdog/events?limit=50", auth);
    const mine = eventsFor(first.body, watchId);
    check("durable_event", mine.length === 1 && mine[0].matched_item_id === pick.item_id, "events " + mine.length);
    ev.event_id = mine[0].id;
    ev.matched_item_id = pick.item_id;
    ev.feed_generation = first.body.feed_generated_at;
    step("durable_event", { event_id: ev.event_id });

    const got = await waitFor((r) => hdr(r, "X-CDB-Watchdog-Event-ID") === ev.event_id, "signed_delivery");
    const d = got[0];
    const sig = await verifySignature({ secret, timestamp: hdr(d, "X-CDB-Watchdog-Timestamp"), signature: hdr(d, "X-CDB-Watchdog-Signature"), rawBody: d.raw });
    check("signature_verified", sig.ok, "signature " + sig.reason);
    step("signature_verified", { delivery_id: hdr(d, "X-CDB-Watchdog-Delivery-ID") });

    const rec = await http("GET", "/api/watchdog/events?evaluate=0&limit=50", auth);
    const recorded = eventsFor(rec.body, watchId)[0];
    check("delivery_recorded", recorded && recorded.deliveries.some((x) => x.destination_id === destId && x.status === "delivered"), "not recorded");
    step("delivery_recorded", {});

    const again = await http("GET", "/api/watchdog/events?limit=50", auth);
    check("no_duplicate", eventsFor(again.body, watchId).length === 1, "duplicate event");
    step("no_duplicate", {});

    // Forced safe failure: the owner sink answers 503 for the next event.
    const second = pickUnambiguousCriterion(feedItems, new Set([pick.item_id]));
    check("select_second_item", second, "NO_UNAMBIGUOUS_FEED_ITEM");
    await sink.setMode(503, 120);
    const c2 = await http("POST", "/api/watchdog/watches", { ...auth, body: { name: "CANARY-ENT-FAIL-" + runId, criteria: second.criteria } });
    check("create_failure_watch", c2.status === 201, "status " + c2.status);
    watch2 = c2.body.watch.id;
    const e2 = eventsFor((await http("GET", "/api/watchdog/events?limit=50", auth)).body, watch2)[0];
    check("failure_event", !!e2, "no event for failure watch");
    await waitFor((r) => hdr(r, "X-CDB-Watchdog-Event-ID") === e2.id, "failed_attempt_observed");
    let state = null;
    for (let i = 0; i < 12; i += 1) {
      const r = await http("GET", "/api/watchdog/events?evaluate=0&limit=50", auth);
      state = eventsFor(r.body, watch2)[0];
      if (state && state.deliveries[0] && state.deliveries[0].attempts >= 1) break;
      await sleep(5000);
    }
    const dl = state && state.deliveries[0];
    check("failure_recorded", dl && dl.attempts >= 1 && dl.last_http_status === 503 && dl.status === "pending" && dl.next_attempt_at, "delivery " + JSON.stringify(dl));
    step("failure_recorded", { attempts: dl.attempts, next_attempt_at: dl.next_attempt_at, retry_policy: "Retry-After honored" });
    await sink.setMode(204);
  } finally {
    if (destId) await http("DELETE", "/api/watchdog/destinations?id=" + destId, auth).catch(() => {});
    for (const id of [watchId, watch2].filter(Boolean)) await http("DELETE", "/api/watchdog/watches?id=" + id, auth).catch(() => {});
    const w = await http("GET", "/api/watchdog/watches", auth).catch(() => null);
    const dd = await http("GET", "/api/watchdog/destinations", auth).catch(() => null);
    ev.cleanup = {
      watches_removed: !!w && !w.body.watches.some((x) => x.id === watchId || x.id === watch2),
      destination_removed: !!dd && !dd.body.destinations.some((x) => x.id === destId),
    };
  }
  check("cleanup", ev.cleanup.watches_removed && ev.cleanup.destination_removed, "cleanup incomplete");
  step("cleanup", ev.cleanup);
  ev.result = "PASS";
  return ev;
}

/** MSSP isolation (Phase 16) across two operator-created tenants. */
export async function runMsspCanary({ http, key, runId, feedItems, tenants = ["CANARY-A", "CANARY-B"], log = () => {} }) {
  const [A, B] = tenants;
  const ev = { mode: "MSSP", run_id: runId, tenants: [A, B], checks: [] };
  const sa = await session(http, key, A);
  const sb = await session(http, key, B);
  const a = { bearer: sa.token };
  const b = { bearer: sb.token };
  const pick = pickUnambiguousCriterion(feedItems);
  check("select_real_item", pick, "NO_UNAMBIGUOUS_FEED_ITEM");
  let wa = null;
  let wb = null;
  const q = (t) => "tenant=" + encodeURIComponent(t);
  try {
    const ca = await http("POST", "/api/watchdog/watches?" + q(A), { ...a, body: { name: "CANARY-" + runId + "-A", criteria: pick.criteria } });
    const cb = await http("POST", "/api/watchdog/watches?" + q(B), { ...b, body: { name: "CANARY-" + runId + "-B", criteria: pick.criteria } });
    check("create_independent", ca.status === 201 && cb.status === 201, ca.status + "/" + cb.status);
    wa = ca.body.watch.id;
    wb = cb.body.watch.id;
    const ea = eventsFor((await http("GET", "/api/watchdog/events?" + q(A), a)).body, wa);
    const eb = eventsFor((await http("GET", "/api/watchdog/events?" + q(B), b)).body, wb);
    check("independent_events", ea.length === 1 && eb.length === 1, ea.length + "/" + eb.length);
    const listA = (await http("GET", "/api/watchdog/watches?" + q(A), a)).body.watches.map((w) => w.id);
    const listB = (await http("GET", "/api/watchdog/watches?" + q(B), b)).body.watches.map((w) => w.id);
    check("reads_isolated", !listA.includes(wb) && !listB.includes(wa), "cross-visible watches");
    const probes = [
      ["GET", "/api/watchdog/watches?" + q(B)],
      ["POST", "/api/watchdog/watches?" + q(B), { name: "x", keywords: ["x"] }],
      ["DELETE", "/api/watchdog/watches?" + q(B) + "&id=" + wb],
      ["POST", "/api/watchdog/events/ack?" + q(B), { ids: [eb[0].id] }],
      ["GET", "/api/watchdog/events?" + q(B)],
      ["GET", "/api/watchdog/destinations?" + q(B)],
    ];
    for (const [m, p, body] of probes) {
      const r = await http(m, p, { ...a, body });
      check("cross_tenant_" + m, r.status === 403, m + " " + p + " -> " + r.status);
      ev.checks.push({ probe: m + " " + p.split("?")[0], status: r.status });
    }
    const bAfter = eventsFor((await http("GET", "/api/watchdog/events?evaluate=0&" + q(B), b)).body, wb)[0];
    check("b_untouched", bAfter && bAfter.acknowledged === false, "B event changed by A");
    ev.result = "PASS";
    log("mssp_isolation", { probes: ev.checks.length });
    return ev;
  } finally {
    if (wa) await http("DELETE", "/api/watchdog/watches?" + q(A) + "&id=" + wa, a).catch(() => {});
    if (wb) await http("DELETE", "/api/watchdog/watches?" + q(B) + "&id=" + wb, b).catch(() => {});
  }
}

/**
 * MSSP self-service canary (tenant_auth_version 2). The MSSP key must be a
 * freshly issued MSSP key (managed_tenants: [] -- no operator edit). The
 * canary creates its two tenants through the customer endpoint, runs the
 * isolation canary across them, then revokes B and proves B's feed, Watchdog
 * access and already-issued scoped session all end while A keeps working.
 * Tenant A is left active for the caller's rotation check; the caller
 * revokes it. Tenant ids are generated by the server and never returned in
 * the evidence.
 */
export async function runMsspSelfServiceCanary({ http, key, runId, feedItems, log = () => {} }) {
  const ev = { mode: "MSSP_SELF_SERVICE", run_id: runId, checks: [] };
  const step = (name, ok, detail) => { check(name, ok, detail); ev.checks.push({ step: name, ok: true }); };
  const auth = { key };
  const before = await http("GET", "/api/mssp/tenants", auth);
  step("list_initially_empty", before.status === 200 && before.body.active_count === 0, "status " + before.status + " active " + (before.body && before.body.active_count));
  const mk = async (label) => http("POST", "/api/mssp/tenants", { ...auth, body: { name: "CANARY-" + label + "-" + runId } });
  const ca = await mk("A");
  const cb = await mk("B");
  step("create_via_customer_endpoint", ca.status === 201 && cb.status === 201, ca.status + "/" + cb.status);
  const A = ca.body.tenant.tenant_id;
  const B = cb.body.tenant.tenant_id;
  step("server_generated_ids", /^tn_[0-9a-f]{20}$/.test(A) && /^tn_[0-9a-f]{20}$/.test(B) && A !== B, "unexpected tenant id shape");
  const listed = (await http("GET", "/api/mssp/tenants", auth)).body.tenants.filter((t) => t.status === "active").map((t) => t.tenant_id);
  step("both_listed", listed.includes(A) && listed.includes(B) && listed.length === 2, "listed " + listed.length);
  step("tenant_a_get", (await http("GET", "/api/mssp/tenants/" + A, auth)).status === 200, "get A");
  step("tenant_a_feed", (await http("GET", "/api/mssp/tenants/" + A + "/feed", auth)).status === 200, "feed A");

  const iso = await runMsspCanary({ http, key, runId, feedItems, tenants: [A, B], log });
  ev.isolation = { result: iso.result, cross_tenant_probes: iso.checks.map((c) => ({ probe: c.probe, status: c.status })) };

  const q = (t) => "tenant=" + encodeURIComponent(t);
  const sb = await session(http, key, B);
  step("b_session_before_revoke", (await http("GET", "/api/watchdog/watches?" + q(B), { bearer: sb.token })).status === 200, "B session");
  const rv = await http("DELETE", "/api/mssp/tenants/" + B, auth);
  step("revoke_b", rv.status === 200 && rv.body.tenant.status === "revoked", "revoke " + rv.status);
  step("b_feed_denied", (await http("GET", "/api/mssp/tenants/" + B + "/feed", auth)).status === 403, "B feed after revoke");
  step("b_watchdog_denied", (await http("GET", "/api/watchdog/watches?" + q(B), auth)).status === 403, "B watchdog after revoke");
  step("b_old_session_denied", (await http("GET", "/api/watchdog/watches", { bearer: sb.token })).status === 403, "B old session after revoke");
  step("b_new_session_denied", (await http("POST", "/api/watchdog/session?" + q(B), auth)).status === 403, "B new session after revoke");
  step("a_still_operational", (await http("GET", "/api/mssp/tenants/" + A + "/feed", auth)).status === 200
    && (await http("GET", "/api/watchdog/watches?" + q(A), auth)).status === 200, "A after B revoke");
  ev.result = "PASS";
  log("mssp_self_service", { checks: ev.checks.length });
  return ev;
}
