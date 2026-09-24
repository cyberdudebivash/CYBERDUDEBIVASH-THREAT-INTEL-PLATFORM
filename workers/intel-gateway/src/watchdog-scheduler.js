/**
 * CYBER WATCHDOG AUTONOMOUS EVALUATION
 *
 * Architecture (chosen on operation counts, see docs/CYBER_WATCHDOG_P3.md):
 *
 *   Worker cron (existing 15-minute trigger, no new product)
 *     -> WatchdogScheduler DO "peek"           1 request, 1 read
 *        (zero active subjects: stop here -- no R2 read, no write)
 *     -> R2 GET feed/latest.json                1 Class B read, 0 LIST
 *     -> freshness gate (canonical contract)    not FRESH: 0 events
 *     -> WatchdogScheduler DO "plan"            bounded batch + leases
 *     -> WatchdogLedger DO "scheduled_evaluate" 1 request per planned subject
 *        (the ledger re-checks freshness, dedupes, stores, arms its own
 *         delivery alarm only when a verified destination has work)
 *     -> WatchdogScheduler DO "report"          records outcome
 *
 * One coordinator reads the feed once per tick and fans out to at most
 * SCHEDULER_POLICY.max_subjects_per_run ledgers. The alternative -- a
 * per-customer DO alarm -- costs one R2 read per customer per cycle and
 * keeps idle customers' alarms firing; the coordinator costs one R2 read per
 * tick for everyone and nothing at all while no paid watch is enabled.
 *
 * The registry only learns about a subject from an authenticated paid
 * mutation (create/update/delete watch, destination verification). An
 * anonymous request never reaches it. A subject with zero enabled watches is
 * removed, which stops its evaluation.
 */

import { SCHEDULER_POLICY, featuresFor } from "./watchdog-policy.js";
import { projectFeedItems, watchdogPublication } from "./cyber-watchdog.js";

const HOUR_MS = 3600000;
export const PRODUCT_METRIC_KEYS = Object.freeze([
  "product_signins", "product_previews", "product_watches_created_v2", "product_profiles_saved",
  "product_profiles_deleted", "product_evidence_views", "product_status_changes",
]);
const METRIC_KEYS = [
  "events_generated", "events_deduped", "delivery_attempts", "delivery_successes",
  "delivery_failures", "verification_failures", "scheduler_failures",
  // Product activation telemetry: hourly aggregate counts only. Never a
  // subject, tenant, key, profile value, watch value, note or secret.
  ...PRODUCT_METRIC_KEYS,
];

export function emptySchedulerState() {
  return {
    subjects: {},
    last_run: null,
    last_successful_generation: null,
    runs: [],
    buckets: [],
  };
}

function bump(state, nowMs, delta) {
  const hour = Math.floor(nowMs / HOUR_MS);
  const buckets = (state.buckets || []).filter((b) => b.hour > hour - 24).map((b) => ({ ...b }));
  let b = buckets.find((x) => x.hour === hour);
  if (!b) { b = { hour }; buckets.push(b); }
  for (const k of METRIC_KEYS) if (delta[k]) b[k] = (b[k] || 0) + delta[k];
  state.buckets = buckets.sort((x, y) => x.hour - y.hour).slice(-24);
}

function activeKeys(state, nowMs) {
  return Object.entries(state.subjects || {})
    .filter(([, s]) => !s.parked && (!s.expires_at || !(Date.parse(s.expires_at) < nowMs)))
    .map(([k]) => k);
}

function clone(state) {
  const s = state && typeof state === "object" ? state : emptySchedulerState();
  return {
    subjects: Object.fromEntries(Object.entries(s.subjects || {}).map(([k, v]) => [k, { ...v }])),
    last_run: s.last_run ? { ...s.last_run } : null,
    last_successful_generation: s.last_successful_generation || null,
    runs: (s.runs || []).slice(),
    buckets: (s.buckets || []).map((b) => ({ ...b })),
  };
}

function recordRun(next, run) {
  next.last_run = run;
  next.runs = [run].concat(next.runs).slice(0, SCHEDULER_POLICY.run_history);
}

/** Pure scheduler state machine. The DO and MemoryScheduler only store. */
export function applySchedulerMutation(state, op) {
  const base = state && typeof state === "object" ? state : emptySchedulerState();
  const nowMs = Date.parse(op?.now || "") || Date.now();
  const now = new Date(nowMs).toISOString();

  if (op?.type === "peek") {
    return { readOnly: true, state: base, result: { active: activeKeys(base, nowMs).length } };
  }
  if (op?.type === "metrics") {
    return { readOnly: true, state: base, result: summarize(base, nowMs) };
  }

  const next = clone(base);

  if (op?.type === "register") {
    const key = typeof op.ledger_key === "string" ? op.ledger_key.slice(0, 200) : "";
    if (!key) return { error: "ledger_key_required", state: base };
    const tier = String(op.tier || "FREE");
    const enabled = Number(op.enabled_watches) || 0;
    if (enabled <= 0 || !featuresFor(tier).background_evaluation) {
      if (!next.subjects[key]) return { readOnly: true, state: base, result: { scheduled: false } };
      delete next.subjects[key];
      return { state: next, result: { scheduled: false } };
    }
    const prev = next.subjects[key] || {};
    next.subjects[key] = {
      subject: String(op.subject || prev.subject || "").slice(0, 128),
      tenant: op.tenant || null,
      tier,
      enabled_watches: enabled,
      active_destinations: prev.active_destinations || 0,
      expires_at: op.expires_at || null,
      registered_at: prev.registered_at || now,
      updated_at: now,
      evaluated_generation: prev.evaluated_generation || null,
      evaluated_at: prev.evaluated_at || null,
      dirty: true,
      failures: 0,
      parked: null,
      lease_until: null,
    };
    return { state: next, result: { scheduled: true } };
  }

  if (op?.type === "plan") {
    if (!op.fresh) {
      recordRun(next, { at: now, status: "feed_not_fresh", freshness_status: op.freshness_status || "UNKNOWN", generation: op.generation || null, planned: 0 });
      return { state: next, result: { planned: [] } };
    }
    const generation = op.generation || null;
    const candidates = activeKeys(next, nowMs)
      .map((k) => [k, next.subjects[k]])
      .filter(([, s]) => (s.dirty || s.evaluated_generation !== generation) && !(s.lease_until && Date.parse(s.lease_until) > nowMs))
      .sort((a, b) => (Date.parse(a[1].evaluated_at || 0) || 0) - (Date.parse(b[1].evaluated_at || 0) || 0))
      .slice(0, SCHEDULER_POLICY.max_subjects_per_run);
    const lease = new Date(nowMs + SCHEDULER_POLICY.lease_seconds * 1000).toISOString();
    for (const [k] of candidates) next.subjects[k].lease_until = lease;
    // Expired entitlements leave the registry at plan time.
    for (const [k, s] of Object.entries(next.subjects)) {
      if (s.expires_at && Date.parse(s.expires_at) < nowMs) delete next.subjects[k];
    }
    if (!candidates.length) {
      // Nothing to do: keep storage unchanged apart from expiries.
      const expired = Object.keys(base.subjects || {}).length !== Object.keys(next.subjects).length;
      if (!expired) return { readOnly: true, state: base, result: { planned: [] } };
      return { state: next, result: { planned: [] } };
    }
    return {
      state: next,
      result: { planned: candidates.map(([k, s]) => ({ ledger_key: k, subject: s.subject, tenant: s.tenant || null, tier: s.tier })) },
    };
  }

  if (op?.type === "report") {
    const generation = op.generation || null;
    let inserted = 0;
    let deduped = 0;
    let failures = 0;
    let evaluated = 0;
    for (const r of op.results || []) {
      const s = next.subjects[r.ledger_key];
      if (!s) continue;
      s.lease_until = null;
      if (r.denied) { delete next.subjects[r.ledger_key]; continue; }
      // Entitlement could not be read. Do not evaluate, do not delete, and
      // do not park: the next tick retries. A blip must not look like revocation.
      if (r.unverified) continue;
      if (!r.ok) {
        failures += 1;
        s.failures = (s.failures || 0) + 1;
        s.last_error = String(r.error || "evaluation_failed").slice(0, 60);
        if (s.failures >= SCHEDULER_POLICY.max_consecutive_failures) s.parked = "evaluation_failures";
        continue;
      }
      evaluated += 1;
      inserted += Number(r.inserted) || 0;
      deduped += Number(r.deduped) || 0;
      s.failures = 0;
      s.last_error = null;
      s.dirty = false;
      s.evaluated_generation = generation;
      s.evaluated_at = now;
      if (r.active_destinations != null) s.active_destinations = Number(r.active_destinations) || 0;
      if (r.enabled_watches != null) {
        s.enabled_watches = Number(r.enabled_watches) || 0;
        if (s.enabled_watches <= 0) delete next.subjects[r.ledger_key];
      }
    }
    const remaining = activeKeys(next, nowMs).filter((k) => next.subjects[k].evaluated_generation !== generation || next.subjects[k].dirty);
    const unverified = (op.results || []).filter((r) => r.unverified).length;
    if (!remaining.length && generation && !unverified) next.last_successful_generation = generation;
    bump(next, nowMs, { events_generated: inserted, events_deduped: deduped, scheduler_failures: failures + (op.cycle_error ? 1 : 0) });
    recordRun(next, {
      at: now,
      status: op.cycle_error ? "cycle_error" : failures ? "partial" : unverified ? "entitlement_unverified" : "ok",
      generation,
      planned: (op.results || []).length,
      evaluated,
      inserted,
      deduped,
      failures,
      backlog: remaining.length,
    });
    return { state: next, result: { recorded: true, backlog: remaining.length } };
  }

  if (op?.type === "record_metrics") {
    const delta = {};
    for (const k of METRIC_KEYS) delta[k] = Math.max(0, Math.min(10000, Number(op.delta?.[k]) || 0));
    if (!Object.values(delta).some(Boolean)) return { readOnly: true, state: base, result: { recorded: false } };
    bump(next, nowMs, delta);
    return { state: next, result: { recorded: true } };
  }

  return { error: "unsupported_op", state: base };
}

/**
 * Operator view. Aggregates only: no subject, tenant, URL, secret or DO id.
 */
export function summarize(state, nowMs = Date.now()) {
  const hour = Math.floor(nowMs / HOUR_MS);
  const window = (state.buckets || []).filter((b) => b.hour > hour - 24);
  const sum = (k) => window.reduce((n, b) => n + (b[k] || 0), 0);
  const active = activeKeys(state, nowMs).map((k) => state.subjects[k]);
  return {
    active_watch_subjects: active.length,
    enabled_watches: active.reduce((n, s) => n + (s.enabled_watches || 0), 0),
    parked_subjects: Object.values(state.subjects || {}).filter((s) => s.parked).length,
    active_destinations: active.reduce((n, s) => n + (s.active_destinations || 0), 0),
    last_scheduler_run: state.last_run || null,
    last_successful_feed_generation: state.last_successful_generation || null,
    events_generated_24h: sum("events_generated"),
    events_deduped_24h: sum("events_deduped"),
    delivery_attempts_24h: sum("delivery_attempts"),
    delivery_successes_24h: sum("delivery_successes"),
    delivery_failures_24h: sum("delivery_failures"),
    verification_failures_24h: sum("verification_failures"),
    scheduler_failures_24h: sum("scheduler_failures"),
    product_24h: Object.fromEntries(PRODUCT_METRIC_KEYS.map((k) => [k.replace(/^product_/, ""), sum(k)])),
    recent_runs: (state.runs || []).slice(0, 8),
    policy: {
      max_subjects_per_run: SCHEDULER_POLICY.max_subjects_per_run,
      max_events_per_watch_per_eval: SCHEDULER_POLICY.max_events_per_watch_per_eval,
      max_consecutive_failures: SCHEDULER_POLICY.max_consecutive_failures,
    },
  };
}

export class MemoryScheduler {
  constructor() {
    this.state = emptySchedulerState();
    this.chain = Promise.resolve();
    this.writes = 0;
  }
  mutate(op) {
    const run = this.chain.then(() => {
      const out = applySchedulerMutation(this.state, op);
      if (!out.error && !out.readOnly) { this.state = out.state; this.writes += 1; }
      return out;
    });
    this.chain = run.then(() => {}, () => {});
    return run;
  }
}

/**
 * One autonomous evaluation cycle. Every dependency is injected so the same
 * code runs under the Worker cron and under node --test.
 *
 *   scheduler.mutate(op)       WatchdogScheduler (or MemoryScheduler)
 *   loadFeed()                 authoritative feed object or null (one R2 GET)
 *   ledgerFor(key).mutate(op)  WatchdogLedger for that subject
 *   checkEntitlement(entry)    { denied } drops the subject; { unverified }
 *                              skips this cycle only (store outage)
 *
 * Returns a summary including the operation counts of this cycle.
 */
export async function runWatchdogCycle({ scheduler, loadFeed, ledgerFor, checkEntitlement, nowMs = Date.now() }) {
  const ops = { scheduler_requests: 0, r2_get: 0, r2_list: 0, ledger_requests: 0, entitlement_reads: 0 };
  const now = new Date(nowMs).toISOString();
  const peek = await scheduler.mutate({ type: "peek", now });
  ops.scheduler_requests += 1;
  if (!peek?.result?.active) return { status: "idle", ops };

  let feed = null;
  try { feed = await loadFeed(); } catch { feed = null; }
  ops.r2_get += 1;
  const pub = watchdogPublication(feed, nowMs);
  const plan = await scheduler.mutate({
    type: "plan", now, generation: pub.feed_generated_at, fresh: pub.serve_live, freshness_status: pub.freshness_status,
  });
  ops.scheduler_requests += 1;
  if (!pub.serve_live) return { status: "feed_not_fresh", freshness_status: pub.freshness_status, ops };
  const planned = plan?.result?.planned || [];
  if (!planned.length) return { status: "nothing_due", generation: pub.feed_generated_at, ops };

  const items = projectFeedItems(feed);
  const publication = { freshness_status: pub.freshness_status, feed_generated_at: pub.feed_generated_at };
  const results = [];
  for (const entry of planned) {
    try {
      if (checkEntitlement) {
        ops.entitlement_reads += 1;
        const ent = await checkEntitlement(entry);
        if (ent && ent.unverified) { results.push({ ledger_key: entry.ledger_key, unverified: true }); continue; }
        if (ent && ent.denied) { results.push({ ledger_key: entry.ledger_key, denied: true }); continue; }
      }
      ops.ledger_requests += 1;
      const out = await ledgerFor(entry.ledger_key).mutate({
        type: "scheduled_evaluate", subject: entry.ledger_key, tier: entry.tier, now, items, publication,
      });
      if (out?.error) {
        // tier_required: the stored tier no longer grants events.
        if (out.error === "tier_required") results.push({ ledger_key: entry.ledger_key, denied: true });
        else results.push({ ledger_key: entry.ledger_key, ok: false, error: out.error });
        continue;
      }
      results.push({
        ledger_key: entry.ledger_key,
        ok: true,
        inserted: out.result?.inserted_count || 0,
        deduped: out.result?.deduped || 0,
        enabled_watches: out.result?.enabled_watches,
        active_destinations: out.result?.active_destinations,
      });
    } catch (err) {
      results.push({ ledger_key: entry.ledger_key, ok: false, error: "exception" });
    }
  }
  await scheduler.mutate({ type: "report", now, generation: pub.feed_generated_at, results });
  ops.scheduler_requests += 1;
  return {
    status: "evaluated",
    generation: pub.feed_generated_at,
    evaluated: results.filter((r) => r.ok).length,
    inserted: results.reduce((n, r) => n + (r.inserted || 0), 0),
    failures: results.filter((r) => r.ok === false).length,
    denied: results.filter((r) => r.denied).length,
    skipped_unverified: results.filter((r) => r.unverified).length,
    ops,
  };
}

/** SQLite-backed Durable Object: one global instance, storage only. */
export class WatchdogScheduler {
  constructor(state, _env) {
    this.state = state;
  }

  async fetch(request) {
    let body;
    try { body = await request.json(); } catch { body = null; }
    const op = body && body.op;
    if (!op || typeof op !== "object") {
      return new Response(JSON.stringify({ error: "invalid_request" }), { status: 400, headers: { "Content-Type": "application/json" } });
    }
    const current = (await this.state.storage.get("scheduler")) || emptySchedulerState();
    const out = applySchedulerMutation(current, op);
    if (!out.readOnly && !out.error) await this.state.storage.put("scheduler", out.state);
    const { state: _omit, ...rest } = out;
    return new Response(JSON.stringify(rest), { status: out.error ? 400 : 200, headers: { "Content-Type": "application/json" } });
  }
}
