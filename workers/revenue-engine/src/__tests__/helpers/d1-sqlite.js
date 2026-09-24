// Test-only Cloudflare D1 stand-in backed by node:sqlite (real SQLite, so
// UNIQUE constraints, ON CONFLICT and transactional batch rollback behave as
// in D1). Implements the D1 surface the revenue engine uses:
// prepare().bind().run()/first()/all(), and batch() as one transaction.
// Every call yields to the event loop first, like a real network binding,
// so concurrent callers genuinely interleave between statements.
import { DatabaseSync } from "node:sqlite";

const tick = () => new Promise((r) => setImmediate(r));

export function createD1() {
  const sqlite = new DatabaseSync(":memory:");
  let inBatch = false;
  const stats = { batches: 0, rolledBack: 0 };

  function statement(sql, params = []) {
    const exec = () => {
      const st = sqlite.prepare(sql);
      return st;
    };
    return {
      sql, params,
      bind: (...p) => statement(sql, p),
      async run() {
        await tick();
        const r = exec().run(...params);
        return { success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } };
      },
      async first(col) {
        await tick();
        const row = exec().get(...params);
        if (row === undefined) return null;
        return col ? row[col] : { ...row };
      },
      async all() {
        await tick();
        return { success: true, results: exec().all(...params).map((r) => ({ ...r })) };
      },
      _runSync() {
        const r = exec().run(...params);
        return { success: true, meta: { changes: Number(r.changes) } };
      },
    };
  }

  return {
    stats,
    sqlite,
    prepare: (sql) => statement(sql),
    async batch(stmts) {
      await tick();
      if (inBatch) throw new Error("nested batch");
      inBatch = true;
      stats.batches += 1;
      sqlite.exec("BEGIN IMMEDIATE");
      try {
        const out = stmts.map((s) => s._runSync());
        sqlite.exec("COMMIT");
        return out;
      } catch (err) {
        sqlite.exec("ROLLBACK");
        stats.rolledBack += 1;
        throw err;
      } finally {
        inBatch = false;
      }
    },
  };
}
