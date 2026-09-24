/**
 * The production canary tool, proven against the in-process gateway harness
 * (fixtures, not production). Also proves it reports operator blockers
 * instead of passing when credentials or the webhook sink are absent.
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { ENT_KEY, FEED_ITEMS, MSSP_KEY, PRO_KEY, harness } from "./watchdog-harness.js";
import {
  pickUnambiguousCriterion, runAutonomousCanary, runEnterpriseCanary, runMsspCanary, runMsspSelfServiceCanary, runProCanary,
} from "../../../../deploy/cyber-watchdog/canary-lib.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CANARY = path.resolve(HERE, "../../../../deploy/cyber-watchdog/canary.mjs");

function bind(h) {
  return (method, p, { key, bearer, body } = {}) => h.call(method, p, { key, bearer, body });
}

test("criterion picker uses the production matcher and refuses ambiguity", () => {
  const pick = pickUnambiguousCriterion(FEED_ITEMS);
  assert.deepEqual(pick, { item_id: "intel--kev-1", criteria: { cves: ["CVE-2026-1000"] } });
  const twins = [{ id: "a", title: "same words here", cve_ids: ["CVE-2026-1"] }, { id: "b", title: "same words here", cve_ids: ["CVE-2026-1"] }];
  assert.equal(pickUnambiguousCriterion(twins), null);
});

test("PRO canary passes end to end and never leaks the key", async () => {
  const h = harness();
  const logs = [];
  const ev = await runProCanary({ http: bind(h), key: PRO_KEY, runId: "t1", feedItems: FEED_ITEMS, log: (s, d) => logs.push(JSON.stringify({ s, d })) });
  assert.equal(ev.result, "PASS");
  assert.equal(ev.matched_item_id, "intel--kev-1");
  assert.ok(ev.event_id);
  assert.equal(ev.dedupe.second_evaluation_events_for_watch, 1);
  assert.equal(ev.ack.acknowledged, true);
  assert.equal(ev.cleanup.watch_deleted, true);
  assert.ok(ev.steps.some((s) => s.step === "pro_denied_webhooks"));
  assert.doesNotMatch(JSON.stringify(ev) + logs.join(""), new RegExp(PRO_KEY));
});

test("autonomous canary observes a scheduler-created event without evaluating", async () => {
  const h = harness();
  const ev = await runAutonomousCanary({ http: bind(h), key: PRO_KEY, runId: "t2", feedItems: FEED_ITEMS, sleep: async () => { await h.cron(); }, pollMs: 1, maxWaitMs: 10 });
  assert.equal(ev.result, "PASS");
  assert.ok(ev.event_id);
});

test("ENTERPRISE canary passes against an owner-controlled sink", async () => {
  const h = harness();
  h.net.dns.set("sink.owner.example", [{ type: 1, data: "93.184.216.34" }]);
  const url = "https://sink.owner.example/wd";
  const recs = [];
  let mode = { status: 204 };
  h.net.receivers.set(url, async (init) => {
    const body = JSON.parse(init.body);
    recs.unshift({ headers: init.headers, raw: init.body });
    if (body.type === "watchdog.verification") return { status: 200, body: { challenge: body.challenge } };
    return mode;
  });
  const sink = {
    url,
    records: async () => { await h.runAlarms(); return recs; },
    setMode: async (status, ra) => { mode = { status, headers: ra ? { "Retry-After": String(ra) } : {} }; },
  };
  const ev = await runEnterpriseCanary({ http: bind(h), key: ENT_KEY, runId: "t3", feedItems: FEED_ITEMS, sink, sleep: async () => {} });
  assert.equal(ev.result, "PASS");
  for (const s of ["verify_destination", "durable_event", "signature_verified", "delivery_recorded", "no_duplicate", "failure_recorded", "cleanup"]) {
    assert.ok(ev.steps.some((x) => x.step === s), s);
  }
});

test("MSSP canary proves tenant isolation", async () => {
  const h = harness();
  const ev = await runMsspCanary({ http: bind(h), key: MSSP_KEY, runId: "t4", feedItems: FEED_ITEMS });
  assert.equal(ev.result, "PASS");
  assert.ok(ev.checks.every((c) => c.status === 403));
});

test("canary CLI reports operator blockers instead of passing", () => {
  const env = { PATH: process.env.PATH, CDB_WATCHDOG_BASE: "http://127.0.0.1:9" };
  const run = (mode, extra = {}) => spawnSync(process.execPath, [CANARY, mode], { env: { ...env, ...extra }, encoding: "utf8" });
  const pro = run("pro");
  assert.equal(pro.status, 10);
  assert.match(pro.stdout, /OPERATOR_CREDENTIAL_REQUIRED/);
  const ent = run("enterprise", { CDB_WATCHDOG_CANARY_ENT_KEY: "cdb_ent_placeholder_not_real_0000000000" });
  assert.equal(ent.status, 11);
  assert.match(ent.stdout, /OPERATOR_WEBHOOK_SINK_REQUIRED/);
  assert.doesNotMatch(ent.stdout + ent.stderr, /cdb_ent_placeholder/);
  const mssp = run("mssp");
  assert.equal(mssp.status, 12);
  assert.match(mssp.stdout, /OPERATOR_MSSP_FIXTURE_REQUIRED/);
});

const V2_MSSP = "cdb_mssp_canary_v2_0123456789abcdef01234567";

function v2Harness() {
  const h = harness();
  h.env.API_KEYS_KV.map.set(V2_MSSP, JSON.stringify({ tier: "MSSP", customer_id: "cust_canary_v2", status: "active", managed_tenants: [], tenant_auth_version: 2 }));
  return h;
}

test("MSSP self-service canary: customer-created tenants, isolation, immediate revocation, no ids leaked", async () => {
  const h = v2Harness();
  const logs = [];
  const ev = await runMsspSelfServiceCanary({ http: bind(h), key: V2_MSSP, runId: "t5", feedItems: FEED_ITEMS, log: (s, d) => logs.push(JSON.stringify({ s, d })) });
  assert.equal(ev.result, "PASS");
  assert.equal(ev.isolation.result, "PASS");
  assert.ok(ev.isolation.cross_tenant_probes.length >= 6);
  for (const s of ["list_initially_empty", "server_generated_ids", "revoke_b", "b_feed_denied", "b_watchdog_denied", "b_old_session_denied", "b_new_session_denied", "a_still_operational"]) {
    assert.ok(ev.checks.some((c) => c.step === s), s);
  }
  const out = JSON.stringify(ev) + logs.join("");
  assert.doesNotMatch(out, /tn_[0-9a-f]{20}/, "tenant ids never in evidence");
  assert.doesNotMatch(out, new RegExp(V2_MSSP));
  // Tenant A is left active for the caller's rotation check.
  const list = await h.call("GET", "/api/mssp/tenants", { key: V2_MSSP });
  assert.equal(list.body.active_count, 1);
});

test("MSSP self-service canary fails when a revocation does not take effect", async () => {
  const h = v2Harness();
  // A gateway that ignored revocation would keep answering 200 for B.
  const http = bind(h);
  let revoked = false;
  const lying = async (m, p, o) => {
    if (m === "DELETE" && p.startsWith("/api/mssp/tenants/")) { revoked = true; return { status: 200, body: { tenant: { status: "revoked" } } }; }
    return http(m, p, o);
  };
  await assert.rejects(runMsspSelfServiceCanary({ http: lying, key: V2_MSSP, runId: "t6", feedItems: FEED_ITEMS }));
  assert.equal(revoked, true);
});
