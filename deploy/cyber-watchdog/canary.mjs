#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG -- live production canary.
 *
 *   node deploy/cyber-watchdog/canary.mjs pro|autonomous|enterprise|mssp
 *
 * Credentials come ONLY from the environment (never argv, never URLs):
 *   CDB_WATCHDOG_CANARY_PRO_KEY     sanctioned PRO canary key
 *   CDB_WATCHDOG_CANARY_ENT_KEY     sanctioned ENTERPRISE canary key
 *   CDB_WATCHDOG_CANARY_MSSP_KEY    sanctioned MSSP key whose managed_tenants
 *                                   include CANARY-A and CANARY-B
 *   CDB_WATCHDOG_SINK_URL           owner-controlled HTTPS receiver (sink.mjs)
 *   CDB_WATCHDOG_SINK_INSPECT_URL   that receiver's /__inspect endpoint
 *   CDB_WATCHDOG_SINK_TOKEN         bearer token for /__inspect
 *   CDB_WATCHDOG_BASE               default https://intel.cyberdudebivash.com
 *
 * Missing credentials are reported, never worked around:
 *   exit 10 OPERATOR_CREDENTIAL_REQUIRED
 *   exit 11 OPERATOR_WEBHOOK_SINK_REQUIRED
 *   exit 12 OPERATOR_MSSP_FIXTURE_REQUIRED
 *   exit 1  FAIL (a step failed; see JSON evidence)
 *   exit 0  PASS
 *
 * Output is JSON evidence on stdout. Keys, tokens and signing secrets are
 * never printed. An internal canary key is not revenue.
 */
import { runAutonomousCanary, runEnterpriseCanary, runMsspCanary, runProCanary } from "./canary-lib.mjs";

const mode = process.argv[2] || "pro";
const base = (process.env.CDB_WATCHDOG_BASE || "https://intel.cyberdudebivash.com").replace(/\/$/, "");
const runId = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function out(obj, code) {
  process.stdout.write(JSON.stringify({ product: "CYBER WATCHDOG canary", base, mode, at: new Date().toISOString(), ...obj }, null, 2) + "\n");
  process.exit(code);
}

async function http(method, path, { key, bearer, body } = {}) {
  const headers = { Accept: "application/json", "User-Agent": "CDB-WATCHDOG-CANARY/1" };
  if (key) headers["X-API-Key"] = key;
  if (bearer) headers.Authorization = "Bearer " + bearer;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(20000) });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, body: json };
}

async function feedItems(key) {
  // One authoritative read. Refuses to pick criteria from a non-FRESH feed.
  const res = await http("GET", "/api/feed.json", { key });
  if (res.status !== 200 || !res.body || res.body.freshness_status !== "FRESH") {
    out({ result: "NO_GO_FEED_NOT_FRESH", status: res.status, freshness_status: res.body && res.body.freshness_status }, 1);
  }
  return { items: res.body.items, generated_at: res.body.generated_at };
}

function httpSink() {
  const url = process.env.CDB_WATCHDOG_SINK_URL;
  const inspect = process.env.CDB_WATCHDOG_SINK_INSPECT_URL;
  const token = process.env.CDB_WATCHDOG_SINK_TOKEN;
  if (!url || !inspect || !token) return null;
  const h = { Authorization: "Bearer " + token, "Content-Type": "application/json" };
  return {
    url,
    records: async () => (await (await fetch(inspect, { headers: h })).json()).records || [],
    setMode: async (status, retryAfter) => { await fetch(inspect + "/mode", { method: "POST", headers: h, body: JSON.stringify({ status, retry_after: retryAfter || null }) }); },
  };
}

const log = (step, detail) => process.stderr.write(JSON.stringify({ step, ...(detail || {}) }) + "\n");

try {
  if (mode === "pro" || mode === "autonomous") {
    const key = process.env.CDB_WATCHDOG_CANARY_PRO_KEY;
    if (!key) out({ result: "OPERATOR_CREDENTIAL_REQUIRED", needs: "CDB_WATCHDOG_CANARY_PRO_KEY (sanctioned PRO canary key)" }, 10);
    const feed = await feedItems(key);
    const evidence = mode === "pro"
      ? await runProCanary({ http, key, runId, feedItems: feed.items, log })
      : await runAutonomousCanary({ http, key, runId, feedItems: feed.items, sleep, log });
    out({ result: evidence.result, feed_generated_at: feed.generated_at, evidence }, evidence.result === "PASS" ? 0 : 1);
  }
  if (mode === "enterprise") {
    const key = process.env.CDB_WATCHDOG_CANARY_ENT_KEY;
    if (!key) out({ result: "OPERATOR_CREDENTIAL_REQUIRED", needs: "CDB_WATCHDOG_CANARY_ENT_KEY (sanctioned ENTERPRISE canary key)" }, 10);
    const sink = httpSink();
    if (!sink) out({ result: "OPERATOR_WEBHOOK_SINK_REQUIRED", needs: "An owner-controlled HTTPS receiver running deploy/cyber-watchdog/sink.mjs: CDB_WATCHDOG_SINK_URL, CDB_WATCHDOG_SINK_INSPECT_URL, CDB_WATCHDOG_SINK_TOKEN. Third-party capture services are not acceptable." }, 11);
    const feed = await feedItems(key);
    const evidence = await runEnterpriseCanary({ http, key, runId, feedItems: feed.items, sink, sleep, log });
    out({ result: evidence.result, feed_generated_at: feed.generated_at, evidence }, evidence.result === "PASS" ? 0 : 1);
  }
  if (mode === "mssp") {
    const key = process.env.CDB_WATCHDOG_CANARY_MSSP_KEY;
    if (!key) out({ result: "OPERATOR_MSSP_FIXTURE_REQUIRED", needs: "CDB_WATCHDOG_CANARY_MSSP_KEY: an MSSP key whose managed_tenants include CANARY-A and CANARY-B (set via the admin key API)" }, 12);
    const feed = await feedItems(key);
    const evidence = await runMsspCanary({ http, key, runId, feedItems: feed.items, log });
    out({ result: evidence.result, feed_generated_at: feed.generated_at, evidence }, evidence.result === "PASS" ? 0 : 1);
  }
  out({ result: "USAGE", usage: "canary.mjs pro|autonomous|enterprise|mssp" }, 2);
} catch (err) {
  out({ result: "FAIL", step: err && err.step, error: String(err && err.message || err).slice(0, 300) }, 1);
}
