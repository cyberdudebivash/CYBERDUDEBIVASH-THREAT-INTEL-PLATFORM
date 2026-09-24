/**
 * WatchdogLedger -- SQLite Durable Object already available on this account.
 * One object per authenticated customer subject (or subject + MSSP tenant).
 * Requests to one id are serialized by the runtime, so two watch creates
 * cannot overwrite each other. Decision logic lives in applyLedgerMutation();
 * this class stores, and runs webhook delivery on its own alarm.
 *
 * Alarm discipline (no unbounded loop): an alarm is armed only when a
 * mutation leaves a pending delivery to a verified destination. Each alarm
 * run attempts at most DELIVERY_POLICY.max_deliveries_per_run deliveries and
 * re-arms only if pending work remains. Every delivery ends after
 * DELIVERY_POLICY.max_attempts attempts, so the alarm chain always ends.
 */
import {
  LEDGER_STORAGE_KEY,
  SIGNED_DESTINATIONS_STORAGE_KEY,
  applyLedgerMutation,
  fromPersisted,
  ledgerNeedsMigration,
  runDueDeliveries,
  toPersisted,
} from "./cyber-watchdog.js";
import { attemptDelivery } from "./watchdog-webhook.js";
import { webhookDeliveryEnabled } from "./watchdog-policy.js";

export class WatchdogLedger {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async mutate(op) {
    // Two storage keys (see toPersisted() in cyber-watchdog.js): "ledger" is
    // the only key the previous implementation reads, and it never holds a
    // signed v3 destination, so a code rollback cannot deliver to one.
    const rawLedger = await this.state.storage.get(LEDGER_STORAGE_KEY);
    const current = fromPersisted(rawLedger, await this.state.storage.get(SIGNED_DESTINATIONS_STORAGE_KEY));
    // Read-migrate: a signed row still in "ledger" (early v3, 6977abf) is moved
    // out on ANY access, reads included, not only on the next write.
    const migrate = ledgerNeedsMigration(rawLedger);
    const out = applyLedgerMutation(current, op);
    if (migrate && (out.readOnly || out.error)) {
      const persisted = toPersisted(current);
      await this.state.storage.put(SIGNED_DESTINATIONS_STORAGE_KEY, persisted.signed);
      await this.state.storage.put(LEDGER_STORAGE_KEY, persisted.ledger);
    }
    if (!out.readOnly && !out.error) {
      const persisted = toPersisted(out.state);
      await this.state.storage.put(SIGNED_DESTINATIONS_STORAGE_KEY, persisted.signed);
      await this.state.storage.put(LEDGER_STORAGE_KEY, persisted.ledger);
    }
    if (!out.error && op && op.subject && op.type !== "get") {
      // Remember whose ledger this is for the alarm (no secrets).
      const meta = await this.state.storage.get("meta");
      if (!meta || meta.subject !== op.subject) await this.state.storage.put("meta", { subject: op.subject });
    }
    if (out.next_delivery_due_at) await this.arm(out.next_delivery_due_at);
    return out;
  }

  async arm(dueIso) {
    const due = Math.max(Date.parse(dueIso) || Date.now(), Date.now() + 1000);
    const existing = await this.state.storage.getAlarm();
    if (existing == null || existing > due) await this.state.storage.setAlarm(due);
  }

  async fetch(request) {
    let body;
    try { body = await request.json(); } catch { body = null; }
    const op = body && body.op;
    if (!op || typeof op !== "object") {
      return new Response(JSON.stringify({ error: "invalid_request", status: 400 }), {
        status: 400, headers: { "Content-Type": "application/json" },
      });
    }
    const out = await this.mutate(op);
    // Full state (which holds destination signing secrets) never leaves the
    // object. Callers receive the op result only.
    const { state: _omit, ...rest } = out;
    const status = out.error ? (out.status || 400) : 200;
    return new Response(JSON.stringify(rest), {
      status, headers: { "Content-Type": "application/json" },
    });
  }

  async alarm() {
    // Kill switch: no outbound request, pending deliveries kept. The next
    // mutation that queues work re-arms the alarm.
    if (!webhookDeliveryEnabled(this.env)) return;
    const meta = await this.state.storage.get("meta");
    if (!meta || !meta.subject) return;
    const run = await runDueDeliveries({
      ledger: { mutate: (op) => this.mutate(op) },
      subject: meta.subject,
      now: new Date().toISOString(),
      attempt: attemptDelivery,
      fetchImpl: fetch,
    });
    if (run.next_delivery_due_at) await this.arm(run.next_delivery_due_at);
    const m = run.metrics;
    const ns = this.env && this.env.WATCHDOG_SCHEDULER;
    if (m && ns && typeof ns.idFromName === "function" && (m.delivery_attempts || m.delivery_failures || m.delivery_successes)) {
      try {
        const stub = ns.get(ns.idFromName("watchdog-scheduler-v1"));
        await stub.fetch("https://watchdog.scheduler/op", { method: "POST", body: JSON.stringify({ op: { type: "record_metrics", now: new Date().toISOString(), delta: m } }) });
      } catch (_) { /* metrics are best effort; delivery state is already stored */ }
    }
  }
}
