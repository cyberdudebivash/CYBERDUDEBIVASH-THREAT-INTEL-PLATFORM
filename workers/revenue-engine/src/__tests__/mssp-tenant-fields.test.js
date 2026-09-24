import assert from "node:assert/strict";
import { test } from "node:test";
import worker from "../index.js";
import { gatewayTenantFields } from "../index.js";

// intel-gateway mssp-tenants.js: new MSSP keys start self-service with zero
// tenants; rotation carries the previous mode exactly.
test("gatewayTenantFields: new MSSP keys are never unrestricted", () => {
  assert.deepEqual(gatewayTenantFields("MSSP", null), { managed_tenants: [], tenant_auth_version: 2 });
  assert.deepEqual(gatewayTenantFields("PRO", null), {});
  assert.deepEqual(gatewayTenantFields("ENTERPRISE", null), {});
});

test("gatewayTenantFields: rotation carries legacy, operator list, self-service and fail-closed", () => {
  assert.deepEqual(gatewayTenantFields("MSSP", { tier: "MSSP", customer_id: "c" }), {});
  assert.deepEqual(gatewayTenantFields("MSSP", { tier: "MSSP", managed_tenants: ["A"] }), { managed_tenants: ["A"] });
  assert.deepEqual(gatewayTenantFields("MSSP", { tier: "MSSP", managed_tenants: "oops" }), { managed_tenants: [] });
  assert.deepEqual(gatewayTenantFields("MSSP", { tier: "MSSP", customer_id: "a@x", managed_tenants: [], tenant_auth_version: 2 }),
    { managed_tenants: [], tenant_auth_version: 2, customer_id: "a@x" });
  // An upgrade to MSSP starts self-service rather than inheriting legacy.
  assert.deepEqual(gatewayTenantFields("MSSP", { tier: "PRO", customer_id: "c" }), { managed_tenants: [], tenant_auth_version: 2 });
});

function kv(initial = {}) {
  const m = new Map(Object.entries(initial));
  return {
    m,
    async get(k, t) { const v = m.get(k); if (v === undefined) return null; return t === "json" ? JSON.parse(v) : v; },
    async put(k, v) { m.set(k, String(v)); },
    async delete(k) { m.delete(k); },
    async list() { return { keys: [], list_complete: true }; },
  };
}

test("admin rotation through the Worker keeps a self-service MSSP key's tenants", async () => {
  const email = "mssp@example.com";
  const crm = kv({
    [`customer:${email}`]: JSON.stringify({ id: "cust_rev_1", email, tier: "MSSP", current_period_end: "2099-01-01T00:00:00Z" }),
    [`apikeys:${email}`]: JSON.stringify([{ key: "CDB-MSSP-OLD", tier: "MSSP", status: "active" }]),
  });
  const keys = kv({ "CDB-MSSP-OLD": JSON.stringify({ key: "CDB-MSSP-OLD", tier: "MSSP", customer_id: email, managed_tenants: [], tenant_auth_version: 2 }) });
  const env = { REVENUE_CRM_KV: crm, API_KEYS_KV: keys, EMAIL_QUEUE_KV: kv(), REVENUE_ADMIN_SECRET: "rev-admin-test" };
  const res = await worker.fetch(new Request("https://revenue.intel.cyberdudebivash.com/api/apikeys/rotate", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Admin-Secret": "rev-admin-test" }, body: JSON.stringify({ email }),
  }), env, { waitUntil() {} });
  assert.equal(res.status, 200);
  assert.equal(keys.m.has("CDB-MSSP-OLD"), false);
  const [[, raw]] = [...keys.m.entries()];
  const rec = JSON.parse(raw);
  assert.equal(rec.tenant_auth_version, 2);
  assert.deepEqual(rec.managed_tenants, []);
  assert.equal(rec.customer_id, email, "tenant owner unchanged, so tenants survive");
});
