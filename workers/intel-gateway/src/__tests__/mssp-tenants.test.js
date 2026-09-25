/**
 * MSSP tenant self-service (tenant_auth_version 2), end to end through the
 * REAL gateway router and the REAL WatchdogLedger / WatchdogScheduler
 * classes (watchdog-harness.js). Payment providers are local stubs: no real
 * payment, no network.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { harness, craftJwt, MSSP_KEY, MSSP_LEGACY_KEY, PRO_KEY, ENT_KEY } from "./watchdog-harness.js";
import {
  TENANT_POLICY, applyTenantMutation, emptyMembership, isTenantId, newTenantId, requestSelectsTenant, validateTenantName,
} from "../mssp-tenants.js";

const V2_A = "cdb_mssp_v2a_0123456789abcdef0123456789abcdef";
const V2_B = "cdb_mssp_v2b_0123456789abcdef0123456789abcdef";
const V2_A_SECOND = "cdb_mssp_v2a2_123456789abcdef0123456789abcdef";

function h(opts) {
  const hx = harness(opts);
  const put = (key, rec) => hx.env.API_KEYS_KV.map.set(key, JSON.stringify({ status: "active", ...rec }));
  put(V2_A, { tier: "MSSP", customer_id: "cust_v2_a", managed_tenants: [], tenant_auth_version: 2 });
  put(V2_B, { tier: "MSSP", customer_id: "cust_v2_b", managed_tenants: [], tenant_auth_version: 2 });
  return { ...hx, put };
}

async function createTenant(hx, key, name) {
  const r = await hx.call("POST", "/api/mssp/tenants", { key, body: { name } });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  return r.body.tenant.tenant_id;
}

function keysFor(hx, customer) {
  return [...hx.env.API_KEYS_KV.map.entries()].filter(([, v]) => JSON.parse(v).customer_id === customer);
}

// ---------------------------------------------------------------- pure logic

test("pure: server ids, name validation, duplicate and limit rules", () => {
  const id = newTenantId((n) => new Uint8Array(n).fill(171));
  assert.equal(id, "tn_" + "ab".repeat(10));
  assert.ok(isTenantId(id));
  for (const bad of ["../etc", "tn_ABABABABABABABABABAB", "tn_abab", "tn_" + "a".repeat(21), "tn_abababababababababa ", "", null, "CANARY-A"]) {
    assert.equal(isTenantId(bad), false, String(bad));
  }
  for (const bad of ["", "   ", "a\u0000b", "a\nb", "x".repeat(81), "../../x", "a/b", "a\\b", "<script>", "tab\tname"]) {
    assert.ok(validateTenantName(bad).error, JSON.stringify(bad));
  }
  assert.equal(validateTenantName("  Acme   Corp  ").name, "Acme Corp");
  // Non-ASCII written as escapes: deploy-worker.yml rewrites non-ASCII in
  // Worker JS (sanitize_encoding.py) before running this suite.
  assert.equal(validateTenantName("M\u00fcller & S\u00f6hne (EU)").name, "M\u00fcller & S\u00f6hne (EU)");

  let st = null;
  const op = (o) => ({ owner: "o1", now: "2026-09-24T00:00:00Z", ...o });
  let out = applyTenantMutation(st, op({ type: "create", id: "tn_" + "1".repeat(20), name: "Acme" }));
  st = out.state;
  assert.equal(applyTenantMutation(st, op({ type: "create", id: "tn_" + "2".repeat(20), name: "ACME" })).error, "tenant_name_exists");
  // Full-width letters normalize (NFKC) to the same name.
  assert.equal(applyTenantMutation(st, op({ type: "create", id: "tn_" + "2".repeat(20), name: "\uff21\uff23\uff2d\uff25" })).error, "tenant_name_exists");
  assert.equal(applyTenantMutation(st, op({ type: "create", id: "tn_" + "1".repeat(20), name: "Other" })).error, "tenant_id_conflict");
  assert.equal(applyTenantMutation(st, { ...op({ type: "list" }), owner: "o2" }).error, "not_found", "another owner sees nothing");
  // Revoked names can be reused; ids never are.
  st = applyTenantMutation(st, op({ type: "revoke", id: "tn_" + "1".repeat(20) })).state;
  assert.ok(applyTenantMutation(st, op({ type: "create", id: "tn_" + "3".repeat(20), name: "Acme" })).state);

  let full = emptyMembership("o1");
  for (let i = 0; i < TENANT_POLICY.max_active_tenants; i += 1) {
    full = applyTenantMutation(full, op({ type: "create", id: "tn_" + i.toString(16).padStart(20, "0"), name: "T" + i })).state;
  }
  const over = applyTenantMutation(full, op({ type: "create", id: "tn_" + "f".repeat(20), name: "One too many" }));
  assert.equal(over.error, "tenant_limit_reached");
  assert.equal(over.limit, 100);
});

test("source is ASCII-only, as the deploy pipeline requires", async () => {
  // deploy-worker.yml runs scripts/sanitize_encoding.py --fix, which rewrites
  // every non-ASCII character under workers/intel-gateway/src to "?" before
  // the unit suite runs. A literal "\u00fc" here once passed the PR gate and
  // then failed the pre-deploy suite. Escapes survive; literals do not.
  const { readFileSync } = await import("node:fs");
  for (const rel of ["../mssp-tenants.js", "./mssp-tenants.test.js"]) {
    const src = readFileSync(new URL(rel, import.meta.url), "utf8");
    const bad = [...src].findIndex((c) => c.charCodeAt(0) > 127);
    assert.equal(bad, -1, rel + " has a non-ASCII character at offset " + bad);
  }
});

test("pure: only tenant-selecting requests pay for a membership read", () => {
  const hdr = (v) => ({ get: (k) => (k === "X-CDB-Watchdog-Tenant" ? v : null) });
  const qs = (v) => new URLSearchParams(v ? { tenant: v } : {});
  assert.equal(requestSelectsTenant("/api/mssp/tenants/x/feed", hdr(null), qs(), {}), true);
  assert.equal(requestSelectsTenant("/api/watchdog/watches", hdr("t"), qs(), {}), true);
  assert.equal(requestSelectsTenant("/api/watchdog/watches", hdr(null), qs("t"), {}), true);
  assert.equal(requestSelectsTenant("/api/watchdog/watches", hdr(null), qs(), { tenant: "t" }), true);
  assert.equal(requestSelectsTenant("/api/watchdog/watches", hdr(null), qs(), {}), false);
  assert.equal(requestSelectsTenant("/api/mssp/tenants", hdr("t"), qs(), {}), false);
  assert.equal(requestSelectsTenant("/api/feed", hdr("t"), qs("t"), {}), false);
});

// ---------------------------------------------------------- self-service API

test("self-service: create, list, get, feed, revoke -- owner from the key, no ADMIN_SECRET", async () => {
  const hx = h();
  const id = await createTenant(hx, V2_A, "Acme Corp");
  assert.ok(isTenantId(id));

  const list = await hx.call("GET", "/api/mssp/tenants", { key: V2_A });
  assert.equal(list.status, 200);
  assert.deepEqual(list.body.tenants.map((t) => [t.tenant_id, t.name, t.status]), [[id, "Acme Corp", "active"]]);
  assert.match(list.body.data_semantics, /shared/);
  assert.equal(list.headers.get("Cache-Control"), "no-store");

  const feed = await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key: V2_A });
  assert.equal(feed.status, 200);
  assert.equal(feed.body._tenant_authorization, "enforced");
  assert.match(feed.body._mssp_note, /not private per-tenant data/);

  // Membership lives in its own DO instance, never in a "wd:" ledger.
  assert.ok(hx.env.WATCHDOG_LEDGER.instance("mssp:cust_v2_a"));
  // The key record is not rewritten by tenant changes.
  assert.deepEqual(JSON.parse(hx.env.API_KEYS_KV.map.get(V2_A)).managed_tenants, []);

  const del = await hx.call("DELETE", `/api/mssp/tenants/${id}`, { key: V2_A });
  assert.equal(del.status, 200);
  assert.equal(del.body.tenant.status, "revoked");
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key: V2_A })).status, 403, "revocation is immediate");
  assert.equal((await hx.call("DELETE", `/api/mssp/tenants/${id}`, { key: V2_A })).status, 200, "idempotent");
  // A second key of the same customer shares the same tenants.
  hx.put(V2_A_SECOND, { tier: "MSSP", customer_id: "cust_v2_a", managed_tenants: [], tenant_auth_version: 2 });
  const id2 = await createTenant(hx, V2_A, "Globex");
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id2}/feed`, { key: V2_A_SECOND })).status, 200);
});

test("isolation: tenant A is invisible and unusable for customer B", async () => {
  const hx = h();
  const a = await createTenant(hx, V2_A, "Acme");
  const b = await createTenant(hx, V2_B, "Acme"); // same name, different owner: fine
  assert.notEqual(a, b);
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${a}/feed`, { key: V2_B })).status, 403);
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${b}/feed`, { key: V2_A })).status, 403);
  const probe = await hx.call("GET", `/api/mssp/tenants/${a}`, { key: V2_B });
  const never = await hx.call("GET", `/api/mssp/tenants/tn_${"0".repeat(20)}`, { key: V2_B });
  assert.equal(probe.status, 404);
  assert.deepEqual(probe.body, never.body, "an existing foreign tenant is indistinguishable from none");
  assert.equal((await hx.call("DELETE", `/api/mssp/tenants/${a}`, { key: V2_B })).status, 404);
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${a}/feed`, { key: V2_A })).status, 200, "B's delete attempt changed nothing");
  const listB = await hx.call("GET", "/api/mssp/tenants", { key: V2_B });
  assert.deepEqual(listB.body.tenants.map((t) => t.tenant_id), [b]);
});

test("ownership and ids never come from the request", async () => {
  const hx = h();
  for (const field of ["mssp_email", "customer_id", "owner_id", "owner", "email", "sub", "tenant_id", "id"]) {
    const r = await hx.call("POST", "/api/mssp/tenants", { key: V2_A, body: { name: "X", [field]: "cust_v2_b" } });
    assert.equal(r.status, 400, field);
    assert.equal(r.body.field, field);
  }
  assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: V2_A, body: { name: "X", tier: "ENTERPRISE" } })).status, 400);
  assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: V2_A, body: ["x"] })).status, 400);
  for (const name of ["", "a\u0001b", "x".repeat(81), "../x", "<b>"]) {
    assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: V2_A, body: { name } })).status, 400, JSON.stringify(name));
  }
  assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: V2_A, body: { name: "Dup" } })).status, 201);
  assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: V2_A, body: { name: "dUP" } })).status, 409);
  // Path ids: traversal, encoded traversal, case, spaces, control, overlong, reserved.
  for (const raw of ["..", "%2e%2e", "TN_" + "a".repeat(20), "tn_%20" + "a".repeat(17), "tn_%00" + "a".repeat(17), "tn_" + "a".repeat(200), "admin", "CANARY-A"]) {
    const r = await hx.call("DELETE", "/api/mssp/tenants/" + raw, { key: V2_A });
    assert.equal(r.status, 404, raw);
  }
  const list = await hx.call("GET", "/api/mssp/tenants", { key: V2_A });
  assert.deepEqual(list.body.tenants.map((t) => t.name), ["Dup"], "no rejected request created anything");
});

test("who may manage tenants: MSSP v2 keys only; legacy and operator lists unchanged", async () => {
  const hx = h();
  assert.equal((await hx.call("GET", "/api/mssp/tenants")).status, 401);
  assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: PRO_KEY, body: { name: "X" } })).status, 403);
  assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: ENT_KEY, body: { name: "X" } })).status, 403);
  const legacy = await hx.call("POST", "/api/mssp/tenants", { key: MSSP_LEGACY_KEY, body: { name: "X" } });
  assert.equal(legacy.status, 409);
  assert.equal(legacy.body.error, "tenant_self_service_unavailable_for_key");
  assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: MSSP_KEY, body: { name: "X" } })).status, 409);
  // Their existing access is exactly as before.
  const lf = await hx.call("GET", "/api/mssp/tenants/anything/feed", { key: MSSP_LEGACY_KEY });
  assert.equal(lf.status, 200);
  assert.equal(lf.body._tenant_authorization, "unrestricted_legacy_key");
  assert.equal((await hx.call("GET", "/api/mssp/tenants/CANARY-A/feed", { key: MSSP_KEY })).status, 200);
  assert.equal((await hx.call("GET", "/api/mssp/tenants/OTHER/feed", { key: MSSP_KEY })).status, 403);
  // A v2 key with no tenants is fail-closed, not unrestricted.
  assert.equal((await hx.call("GET", "/api/mssp/tenants/anything/feed", { key: V2_A })).status, 403);
  // A Watchdog browser session cannot manage tenants.
  const s = await hx.call("POST", "/api/watchdog/session", { key: V2_A });
  assert.equal(s.status, 200);
  const viaSession = await hx.call("POST", "/api/mssp/tenants", { bearer: s.body.token, body: { name: "X" } });
  assert.ok([401, 403].includes(viaSession.status), String(viaSession.status));
  // A forged claim of version 2 without a valid signature is rejected.
  const forged = await craftJwt({ sub: "cust_v2_b", tier: "MSSP", aud: "cdb-watchdog", scope: "watchdog:read", tenant_auth_version: 2, exp: Math.floor(Date.now() / 1000) + 600 }, "wrong-secret");
  assert.equal((await hx.call("GET", "/api/watchdog/watches", { bearer: forged })).status >= 400, true);
});

test("membership store unavailable: tenant access fails closed, nothing is created", async () => {
  const hx = h();
  const id = await createTenant(hx, V2_A, "Acme");
  const ns = hx.env.WATCHDOG_LEDGER;
  const realGet = ns.get;
  ns.get = (idObj) => (String(idObj.name).startsWith("mssp:") ? { fetch: async () => { throw new Error("DO down"); } } : realGet(idObj));
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key: V2_A })).status, 403);
  assert.equal((await hx.call("GET", "/api/watchdog/watches", { key: V2_A, headers: { "X-CDB-Watchdog-Tenant": id } })).status, 403);
  const c = await hx.call("POST", "/api/mssp/tenants", { key: V2_A, body: { name: "Later" } });
  assert.equal(c.status, 503);
  ns.get = realGet;
  const list = await hx.call("GET", "/api/mssp/tenants", { key: V2_A });
  assert.deepEqual(list.body.tenants.map((t) => t.name), ["Acme"]);
});

// ------------------------------------------------------------------ Watchdog

test("Watchdog recognizes self-service tenants automatically; revoke ends access, sessions included", async () => {
  const hx = h();
  const id = await createTenant(hx, V2_A, "Acme");
  const other = await createTenant(hx, V2_B, "Other");
  const hdr = { "X-CDB-Watchdog-Tenant": id };
  const w = await hx.call("POST", "/api/watchdog/watches", { key: V2_A, headers: hdr, body: { name: "Ransomware", keywords: ["ransomware"] } });
  assert.equal(w.status, 201, JSON.stringify(w.body));
  assert.ok(hx.ledgerState("cust_v2_a|t:" + id), "tenant ledger is subject + tenant");
  assert.equal((await hx.call("GET", "/api/watchdog/watches", { key: V2_A, headers: { "X-CDB-Watchdog-Tenant": other } })).status, 403);
  assert.equal((await hx.call("GET", "/api/watchdog/watches", { key: V2_B, headers: hdr })).status, 403);

  const sess = await hx.call("POST", "/api/watchdog/session", { key: V2_A, headers: hdr });
  assert.equal(sess.status, 200);
  assert.equal(sess.body.tenant, id);
  assert.equal((await hx.call("GET", "/api/watchdog/watches", { bearer: sess.body.token })).status, 200);

  // Background evaluation is registered for the tenant ledger.
  const key = "cust_v2_a|t:" + id;
  assert.ok(hx.schedulerState().subjects[key]);

  assert.equal((await hx.call("DELETE", `/api/mssp/tenants/${id}`, { key: V2_A })).status, 200);
  assert.equal((await hx.call("GET", "/api/watchdog/watches", { key: V2_A, headers: hdr })).status, 403);
  assert.equal((await hx.call("GET", "/api/watchdog/watches", { bearer: sess.body.token })).status, 403, "existing session loses the tenant at once");
  assert.equal((await hx.call("POST", "/api/watchdog/session", { key: V2_A, headers: hdr })).status, 403);

  // The next cron run drops the revoked tenant instead of evaluating it.
  const before = hx.ledgerState(key).events.length;
  await hx.cron();
  assert.equal(hx.schedulerState().subjects[key], undefined, "revoked tenant deregistered");
  assert.equal(hx.ledgerState(key).events.length, before, "no evaluation for a revoked tenant");
});

test("scheduler: an unreachable membership store skips the tenant (unverified), never deregisters it", async () => {
  const hx = h();
  const id = await createTenant(hx, V2_A, "Acme");
  await hx.call("POST", "/api/watchdog/watches", { key: V2_A, headers: { "X-CDB-Watchdog-Tenant": id }, body: { name: "Ransomware", keywords: ["ransomware"] } });
  const ns = hx.env.WATCHDOG_LEDGER;
  const realGet = ns.get;
  ns.get = (idObj) => (String(idObj.name).startsWith("mssp:") ? { fetch: async () => { throw new Error("DO down"); } } : realGet(idObj));
  await hx.cron();
  ns.get = realGet;
  const key = "cust_v2_a|t:" + id;
  const s = hx.schedulerState().subjects[key];
  assert.ok(s, "still registered");
  assert.equal(s.parked, null, "an outage is not a revocation or a failure streak");
  assert.equal(hx.ledgerState(key).events.length, 0, "not evaluated while membership is unknown");
  await hx.cron();
  assert.ok(hx.ledgerState(key).events.length > 0, "evaluated once membership answers again");
});

// ---------------------------------------------------------------- lifecycle

test("lifecycle: rotation preserves, suspension denies, reactivation preserves", async () => {
  const hx = h();
  const admin = hx.env.ADMIN_SECRET;
  const id = await createTenant(hx, V2_A, "Acme");

  const rot = await hx.call("POST", `/api/admin/keys/${V2_A}/rotate`, { admin });
  assert.equal(rot.status, 201);
  const newKey = rot.body.new_key;
  const rec = JSON.parse(hx.env.API_KEYS_KV.map.get(newKey));
  assert.equal(rec.tenant_auth_version, 2);
  assert.deepEqual(rec.managed_tenants, []);
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key: V2_A })).status, 401, "old key gone");
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key: newKey })).status, 200, "tenants survive rotation");

  for (const status of ["suspended", "cancelled", "refunded"]) {
    assert.equal((await hx.call("PATCH", `/api/admin/keys/${newKey}/status`, { admin, body: { subscription_status: status } })).status, 200);
    const denied = await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key: newKey });
    assert.ok(denied.status === 401 || denied.status === 403, status + " -> " + denied.status);
    assert.equal((await hx.call("POST", "/api/mssp/tenants", { key: newKey, body: { name: "During " + status } })).status, 401);
    assert.equal((await hx.call("PATCH", `/api/admin/keys/${newKey}/status`, { admin, body: { subscription_status: "active" } })).status, 200);
    assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key: newKey })).status, 200, "reactivation preserves tenants");
  }

  // Rotation keeps legacy keys legacy and operator lists as they are.
  const legacyRot = await hx.call("POST", `/api/admin/keys/${MSSP_LEGACY_KEY}/rotate`, { admin });
  const legacyRec = JSON.parse(hx.env.API_KEYS_KV.map.get(legacyRot.body.new_key));
  assert.equal("managed_tenants" in legacyRec, false);
  assert.equal("tenant_auth_version" in legacyRec, false);
  const opRot = await hx.call("POST", `/api/admin/keys/${MSSP_KEY}/rotate`, { admin });
  const opRec = JSON.parse(hx.env.API_KEYS_KV.map.get(opRot.body.new_key));
  assert.deepEqual(opRec.managed_tenants, ["CANARY-A", "CANARY-B"]);
  assert.equal("tenant_auth_version" in opRec, false);
  // A corrupted list stays fail-closed through rotation (was: silently unrestricted).
  hx.put("cdb_mssp_corrupt_0123456789abcdef0123456789", { tier: "MSSP", customer_id: "cust_c", managed_tenants: "oops" });
  const cRot = await hx.call("POST", "/api/admin/keys/cdb_mssp_corrupt_0123456789abcdef0123456789/rotate", { admin });
  assert.deepEqual(JSON.parse(hx.env.API_KEYS_KV.map.get(cRot.body.new_key)).managed_tenants, []);
});

test("admin key creation: MSSP starts self-service with zero tenants; explicit list or null unchanged", async () => {
  const hx = h();
  const admin = hx.env.ADMIN_SECRET;
  const mk = async (body) => {
    const r = await hx.call("POST", "/api/admin/keys", { admin, body });
    assert.equal(r.status, 201, JSON.stringify(r.body));
    return JSON.parse(hx.env.API_KEYS_KV.map.get(r.body.key));
  };
  const v2 = await mk({ customer_id: "cust_new", tier: "MSSP" });
  assert.deepEqual(v2.managed_tenants, []);
  assert.equal(v2.tenant_auth_version, 2);
  const op = await mk({ customer_id: "cust_op", tier: "MSSP", managed_tenants: ["X"] });
  assert.deepEqual(op.managed_tenants, ["X"]);
  assert.equal("tenant_auth_version" in op, false);
  const legacy = await mk({ customer_id: "cust_leg", tier: "MSSP", managed_tenants: null });
  assert.equal("managed_tenants" in legacy, false);
  const ent = await mk({ customer_id: "cust_ent", tier: "ENTERPRISE" });
  assert.equal("managed_tenants" in ent, false);
  assert.equal("tenant_auth_version" in ent, false);
  assert.equal((await hx.call("POST", "/api/admin/keys", { admin, body: { customer_id: "x", tier: "MSSP", managed_tenants: "all" } })).status, 400);
});

// ------------------------------------------------------ paid activation stubs

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function selfServiceWorks(hx, customer) {
  const [[key, raw]] = keysFor(hx, customer);
  const rec = JSON.parse(raw);
  assert.equal(rec.tier, "MSSP");
  assert.deepEqual(rec.managed_tenants, [], "paid MSSP key is never unrestricted");
  assert.equal(rec.tenant_auth_version, 2);
  assert.equal((await hx.call("GET", "/api/mssp/tenants/anything/feed", { key })).status, 403);
  const id = await createTenant(hx, key, "First customer");
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key })).status, 200);
  assert.equal((await hx.call("POST", "/api/watchdog/watches", { key, headers: { "X-CDB-Watchdog-Tenant": id }, body: { name: "KEV", keywords: ["kev"] } })).status, 201);
  return key;
}

test("paid activation: Razorpay verify (stubbed provider) -> MSSP self-service works without an operator", async () => {
  const hx = h();
  hx.env.RAZORPAY_KEY_ID = "rzp_test_stub";
  hx.env.RAZORPAY_KEY_SECRET = "rzp-stub-secret";
  hx.net.receivers.set("https://api.razorpay.com/v1/payments/pay_stub_1", async () => ({
    status: 200, body: { id: "pay_stub_1", order_id: "order_stub_1", status: "captured", notes: { tier: "MSSP" } },
  }));
  hx.env.RESEND_API_KEY = "re_stub";
  const mails = [];
  hx.net.receivers.set("https://api.resend.com/emails", async (init) => { mails.push(JSON.parse(init.body)); return { status: 200, body: { id: "m1" } }; });
  const sig = await hmacHex("rzp-stub-secret", "order_stub_1|pay_stub_1");
  // A client-supplied tier is ignored; the tier comes from the payment record.
  const r = await hx.call("POST", "/api/payment/razorpay/verify", { body: { razorpay_order_id: "order_stub_1", razorpay_payment_id: "pay_stub_1", razorpay_signature: sig, email: "mssp-buyer@example.com", tier: "PRO" } });
  assert.equal(r.status, 201, JSON.stringify(r.body));
  // Onboarding: the activation email tells the MSSP buyer how to add a tenant.
  assert.equal(mails.length, 1);
  assert.match(mails[0].html, /POST[^<]*\/api\/mssp\/tenants/);
  await selfServiceWorks(hx, "mssp-buyer@example.com");
});

test("paid activation: Razorpay webhook, then refund denies and keeps tenants for reactivation", async () => {
  const hx = h();
  hx.env.RAZORPAY_WEBHOOK_SECRET = "rzp-wh-stub";
  const send = async (payload) => {
    const raw = JSON.stringify(payload);
    const res = await (await import("../index.js")).default.fetch(new Request("https://intel.cyberdudebivash.com/api/webhooks/razorpay", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Razorpay-Signature": await hmacHex("rzp-wh-stub", raw), "cf-connecting-ip": "203.0.113.9" }, body: raw,
    }), hx.env, hx.ctx);
    return res.status;
  };
  assert.equal(await send({ event: "payment.captured", payload: { payment: { entity: { id: "pay_wh_1", amount: 83300, notes: { tier: "MSSP", email: "wh-buyer@example.com" } } } } }), 200);
  const key = await selfServiceWorks(hx, "wh-buyer@example.com");
  const [{ tenant_id: id }] = (await hx.call("GET", "/api/mssp/tenants", { key })).body.tenants;
  assert.equal(await send({ event: "refund.processed", payload: { refund: { entity: { id: "rfnd_1", payment_id: "pay_wh_1" } } } }), 200);
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key })).status, 401);
  assert.equal(JSON.parse(hx.env.API_KEYS_KV.map.get(key)).subscription_status, "refunded");
  assert.equal((await hx.call("PATCH", `/api/admin/keys/${key}/status`, { admin: hx.env.ADMIN_SECRET, body: { subscription_status: "active" } })).status, 200);
  assert.equal((await hx.call("GET", `/api/mssp/tenants/${id}/feed`, { key })).status, 200);
});

test("paid activation: Gumroad webhook parity with Razorpay", async () => {
  const hx = h();
  hx.env.GUMROAD_WEBHOOK_SECRET = "gum-stub-secret";
  const form = new URLSearchParams({ sale_id: "sale_stub_1", email: "gum-buyer@example.com", product_name: "SENTINEL APEX MSSP Partner", price: "99900", recurrence: "monthly" });
  const res = await (await import("../index.js")).default.fetch(new Request("https://intel.cyberdudebivash.com/api/webhooks/gumroad?secret=gum-stub-secret", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "cf-connecting-ip": "203.0.113.10" }, body: form.toString(),
  }), hx.env, hx.ctx);
  assert.equal(res.status, 200);
  // S16: MSSP has no Gumroad catalog product, so the sale is held, never
  // provisioned from the product name ...
  assert.equal((await res.json()).status, "held_for_review");
  const buyerKeys = () => [...hx.env.API_KEYS_KV.map.values()].filter((v) => { try { return JSON.parse(v).customer_id === "gum-buyer@example.com"; } catch { return false; } });
  assert.equal(buyerKeys().length, 0, "no key for the held sale");
  // ... until an operator releases it as MSSP: then self-service works as for Razorpay.
  const rel = await hx.call("POST", "/api/admin/gumroad/release", { admin: hx.env.ADMIN_SECRET, body: { sale_id: "sale_stub_1", tier: "MSSP", billing_cycle: "monthly" } });
  assert.equal(rel.status, 200);
  assert.equal(rel.body.status, "provisioned");
  await selfServiceWorks(hx, "gum-buyer@example.com");
});

// ------------------------------------------------------------- docs parity

test("docs: published MSSP tenant API matches the live routes", async () => {
  const { readFileSync } = await import("node:fs");
  const root = new URL("../../../../", import.meta.url);
  const partner = readFileSync(new URL("MSSP_PARTNER_PROGRAM.md", root), "utf8");
  const page = readFileSync(new URL("mssp.html", root), "utf8");
  const ident = readFileSync(new URL("docs/MSSP_TENANT_IDENTITY_V185.md", root), "utf8");
  for (const doc of [partner, page]) {
    assert.match(doc, /-X POST https:\/\/intel\.cyberdudebivash\.com\/api\/mssp\/tenants/);
    assert.match(doc, /X-API-Key/);
    assert.doesNotMatch(doc, /\/api\/mssp\/tenants\/\{tenant_id\}\/usage \\/, "no documented route that does not exist");
    assert.doesNotMatch(doc, /"client_id"|"tier": "pro"|API key issued/, "no request fields the API rejects");
  }
  assert.match(partner, /DELETE https:\/\/intel\.cyberdudebivash\.com\/api\/mssp\/tenants\/\{tenant_id\}/);
  assert.match(partner, /X-CDB-Watchdog-Tenant/);
  assert.match(partner, /no private per-tenant intelligence store/);
  assert.match(ident, /OWNER_DECISION_REQUIRED_MSSP_TENANT_QUOTA/);
  // Every route the docs name is served (and a documented body is accepted).
  const hx = h();
  const id = await createTenant(hx, V2_A, "Customer A");
  for (const [m, p] of [["GET", "/api/mssp/tenants"], ["GET", `/api/mssp/tenants/${id}`], ["GET", `/api/mssp/tenants/${id}/feed?severity=HIGH&industry=finance`], ["DELETE", `/api/mssp/tenants/${id}`]]) {
    assert.equal((await hx.call(m, p, { key: V2_A })).status, 200, m + " " + p);
  }
});
