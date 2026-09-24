/**
 * Cyber Watchdog scheduler: registry semantics, bounded batches, bounded
 * failures, and the freshness gate inside the store.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { MemoryScheduler, applySchedulerMutation, emptySchedulerState, runWatchdogCycle, summarize } from "../watchdog-scheduler.js";
import { MemoryLedger, applyLedgerMutation, emptyLedgerState } from "../cyber-watchdog.js";
import { SCHEDULER_POLICY } from "../watchdog-policy.js";

const NOW_MS = Date.parse("2026-09-24T06:00:00Z");
const feed = (gen = "2026-09-24T05:50:00Z") => ({
  generated_at: gen, count: 2,
  items: [
    { id: "i-1", title: "CVE-2026-1000 ransomware", severity: "CRITICAL", cve_ids: ["CVE-2026-1000"] },
    { id: "i-2", title: "Azure advisory", severity: "HIGH" },
  ],
});

async function populated(n) {
  const scheduler = new MemoryScheduler();
  const ledgers = new Map();
  for (let i = 0; i < n; i += 1) {
    const key = "cust-" + i;
    const l = new MemoryLedger();
    await l.mutate({ type: "create_watch", subject: key, tier: "PRO", id: "w" + i, now: "2026-09-24T05:00:00Z", watch: { name: "W", keywords: ["ransomware"] } });
    ledgers.set(key, l);
    await scheduler.mutate({ type: "register", ledger_key: key, subject: key, tier: "PRO", enabled_watches: 1, now: "2026-09-24T05:00:00Z" });
  }
  return { scheduler, ledgers };
}

test("registry: enabled watch schedules; zero enabled, FREE tier, or no background entitlement unschedules", () => {
  let st = emptySchedulerState();
  const reg = (op) => { const o = applySchedulerMutation(st, { now: "2026-09-24T06:00:00Z", ...op }); if (!o.readOnly) st = o.state; return o; };
  assert.equal(reg({ type: "register", ledger_key: "a", subject: "a", tier: "PRO", enabled_watches: 2 }).result.scheduled, true);
  assert.equal(Object.keys(st.subjects).length, 1);
  assert.equal(reg({ type: "register", ledger_key: "a", subject: "a", tier: "PRO", enabled_watches: 0 }).result.scheduled, false);
  assert.equal(Object.keys(st.subjects).length, 0);
  assert.equal(reg({ type: "register", ledger_key: "f", subject: "f", tier: "FREE", enabled_watches: 3 }).result.scheduled, false);
  assert.equal(Object.keys(st.subjects).length, 0);
  reg({ type: "register", ledger_key: "x", subject: "x", tier: "ENTERPRISE", enabled_watches: 1, expires_at: "2026-09-24T05:00:00Z" });
  assert.equal(applySchedulerMutation(st, { type: "peek", now: "2026-09-24T06:00:00Z" }).result.active, 0, "expired entitlement is not active");
});

test("bounded batch: 60 subjects are evaluated 25 per tick, all within 3 ticks, then nothing due", async () => {
  const { scheduler, ledgers } = await populated(60);
  const counts = [];
  let ledgerCalls = 0;
  const ledgerFor = (k) => ({ mutate: (op) => { ledgerCalls += 1; return ledgers.get(k).mutate(op); } });
  for (let tick = 0; tick < 4; tick += 1) {
    const before = ledgerCalls;
    const out = await runWatchdogCycle({ scheduler, loadFeed: async () => feed(), ledgerFor, nowMs: NOW_MS + tick * 900000 });
    counts.push(ledgerCalls - before);
    assert.equal(out.ops.r2_list, 0);
    assert.ok(out.ops.r2_get <= 1);
  }
  assert.deepEqual(counts, [25, 25, 10, 0]);
  assert.equal(scheduler.state.last_successful_generation, "2026-09-24T05:50:00Z");
  for (const l of ledgers.values()) assert.equal(l.state.events.length, 1);
  assert.equal(SCHEDULER_POLICY.max_subjects_per_run, 25);
});

test("bounded failures: a throwing ledger is parked after max_consecutive_failures and never loses events", async () => {
  const { scheduler, ledgers } = await populated(1);
  const good = ledgers.get("cust-0");
  await runWatchdogCycle({ scheduler, loadFeed: async () => feed(), ledgerFor: () => good, nowMs: NOW_MS });
  assert.equal(good.state.events.length, 1);
  let calls = 0;
  const broken = { mutate: async () => { calls += 1; throw new Error("boom"); } };
  for (let i = 1; i <= 8; i += 1) {
    // A new generation every tick, so the subject is due each time.
    const gen = new Date(NOW_MS + i * 900000 - 60000).toISOString();
    await runWatchdogCycle({ scheduler, loadFeed: async () => feed(gen), ledgerFor: () => broken, nowMs: NOW_MS + i * 900000 });
  }
  assert.equal(calls, SCHEDULER_POLICY.max_consecutive_failures, "bounded retries, then parked");
  assert.equal(scheduler.state.subjects["cust-0"].parked, "evaluation_failures");
  assert.equal(good.state.events.length, 1, "scheduler failure never deletes prior events");
  const m = summarize(scheduler.state, NOW_MS + 8 * 900000);
  assert.equal(m.parked_subjects, 1);
  assert.ok(m.scheduler_failures_24h >= SCHEDULER_POLICY.max_consecutive_failures);
  // The owner changing a watch re-registers and un-parks.
  await scheduler.mutate({ type: "register", ledger_key: "cust-0", subject: "cust-0", tier: "PRO", enabled_watches: 1, now: new Date(NOW_MS + 9 * 900000).toISOString() });
  assert.equal(scheduler.state.subjects["cust-0"].parked, null);
});

test("freshness is re-checked inside the store: scheduled_evaluate with a non-FRESH publication creates nothing", () => {
  let st = emptyLedgerState();
  st = applyLedgerMutation(st, { type: "create_watch", subject: "s", tier: "PRO", id: "w", now: "2026-09-24T05:00:00Z", watch: { name: "W", keywords: ["ransomware"] } }).state;
  for (const status of ["STALE", "EMPTY", "INVALID", "UNAVAILABLE", undefined]) {
    const out = applyLedgerMutation(st, { type: "scheduled_evaluate", subject: "s", tier: "PRO", now: "2026-09-24T06:00:00Z", items: feed().items, publication: { freshness_status: status } });
    assert.equal(out.result.inserted_count, 0, String(status));
    assert.equal(out.readOnly, true);
  }
  const ok = applyLedgerMutation(st, { type: "scheduled_evaluate", subject: "s", tier: "PRO", now: "2026-09-24T06:00:00Z", items: feed().items, publication: { freshness_status: "FRESH", feed_generated_at: "2026-09-24T05:50:00Z" } });
  assert.equal(ok.result.inserted_count, 1);
  assert.equal(ok.result.inserted[0].origin, "scheduler");
});

test("an expired or FREE-downgraded subject is dropped, not evaluated", async () => {
  const { scheduler, ledgers } = await populated(1);
  const l = ledgers.get("cust-0");
  const out = await runWatchdogCycle({
    scheduler, loadFeed: async () => feed(), nowMs: NOW_MS,
    ledgerFor: () => ({ mutate: (op) => l.mutate({ ...op, tier: "FREE" }) }),
  });
  assert.equal(out.denied, 1);
  assert.equal(scheduler.state.subjects["cust-0"], undefined);
  assert.equal(l.state.events.length, 0);
});

test("an unreadable entitlement skips this cycle and keeps the subject", async () => {
  const { scheduler, ledgers } = await populated(1);
  const l = ledgers.get("cust-0");
  let ledgerCalls = 0;
  const out = await runWatchdogCycle({
    scheduler, loadFeed: async () => feed(), nowMs: NOW_MS,
    ledgerFor: () => ({ mutate: async () => { ledgerCalls += 1; throw new Error("should not evaluate"); } }),
    checkEntitlement: async () => ({ unverified: true }),
  });
  assert.equal(out.skipped_unverified, 1);
  assert.equal(out.evaluated, 0);
  assert.equal(ledgerCalls, 0);
  assert.equal(scheduler.state.subjects["cust-0"].parked, null);
  assert.equal(scheduler.state.subjects["cust-0"].failures || 0, 0);
  assert.equal(scheduler.state.runs[0].status, "entitlement_unverified");
  assert.equal(l.state.events.length, 0);
  const next = await runWatchdogCycle({
    scheduler, loadFeed: async () => feed(), nowMs: NOW_MS + 900000,
    ledgerFor: () => l,
    checkEntitlement: async () => ({ denied: false }),
  });
  assert.equal(next.evaluated, 1);
  assert.equal(l.state.events.length, 1, "the following healthy tick still records the match");
});

test("operator summary exposes no subject, tenant or url", async () => {
  const { scheduler, ledgers } = await populated(3);
  await runWatchdogCycle({ scheduler, loadFeed: async () => feed(), ledgerFor: (k) => ledgers.get(k), nowMs: NOW_MS });
  const m = summarize(scheduler.state, NOW_MS);
  assert.equal(m.active_watch_subjects, 3);
  assert.equal(m.events_generated_24h, 3);
  assert.doesNotMatch(JSON.stringify(m), /cust-\d/);
});
