/**
 * WatchdogLedger -- SQLite Durable Object already available on this account.
 * One object per authenticated customer subject. Requests to one id are
 * serialized by the runtime, so two watch creates cannot overwrite each other.
 * Decision logic lives in applyLedgerMutation(); this class only stores.
 */
import { applyLedgerMutation, emptyLedgerState } from "./cyber-watchdog.js";

export class WatchdogLedger {
  constructor(state, _env) {
    this.state = state;
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
    const current = (await this.state.storage.get("ledger")) || emptyLedgerState();
    const out = applyLedgerMutation(current, op);
    if (!out.readOnly && !out.error) await this.state.storage.put("ledger", out.state);
    const status = out.error ? (out.status || 400) : 200;
    return new Response(JSON.stringify(out), {
      status, headers: { "Content-Type": "application/json" },
    });
  }
}
