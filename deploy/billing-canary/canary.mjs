#!/usr/bin/env node
/**
 * CYBERDUDEBIVASH SENTINEL APEX -- billing canary (S28).
 *
 *   node deploy/billing-canary/canary.mjs public|admin|live|test-checkout
 *
 *   public         no credentials, never mutates anything
 *   admin          + readiness/health summary (read-only); BLOCKED is reported
 *   live           as admin, but a BLOCKED verdict FAILS (production go-live gate)
 *   test-checkout  admin + one unpaid Razorpay TEST subscription; refused
 *                  (exit 13) unless readiness proves a test-mode key
 *
 * Environment only (never argv, never URLs):
 *   CDB_BILLING_CANARY_BASE          default https://intel.cyberdudebivash.com
 *   CDB_BILLING_CANARY_REVENUE_BASE  default https://revenue.intel.cyberdudebivash.com
 *   CDB_BILLING_CANARY_ADMIN_SECRET  revenue engine REVENUE_ADMIN_SECRET (admin/live/test-checkout)
 *   CDB_BILLING_CANARY_EMAIL         test-checkout buyer (default billing-canary+<run>@example.com)
 *
 * Exit: 0 PASS, 1 FAIL, 10 OPERATOR_CREDENTIAL_REQUIRED, 13 LIVE_MODE_REFUSED.
 * Output: JSON evidence on stdout; no secret, key or full id is printed.
 */
import { EXIT, runPublicChecks, runAdminChecks, runTestCheckout, readinessProvesTestMode } from "./canary-lib.mjs";

const mode = process.argv[2] || "public";
const base = (process.env.CDB_BILLING_CANARY_BASE || "https://intel.cyberdudebivash.com").replace(/\/$/, "");
const revenueBase = (process.env.CDB_BILLING_CANARY_REVENUE_BASE || "https://revenue.intel.cyberdudebivash.com").replace(/\/$/, "");
const secret = process.env.CDB_BILLING_CANARY_ADMIN_SECRET || "";
const runId = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);

function client(root) {
  return async (method, path, { headers = {}, body, raw } = {}) => {
    const h = { Accept: "application/json", "User-Agent": "CDB-BILLING-CANARY/1", ...headers };
    if (body !== undefined && !raw && !h["Content-Type"]) h["Content-Type"] = "application/json";
    const res = await fetch(root + path, {
      method, headers: h, redirect: "manual", signal: AbortSignal.timeout(20000),
      body: body === undefined ? undefined : (raw ? body : JSON.stringify(body)),
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = null; }
    return { status: res.status, body: json, text };
  };
}

function out(result, steps, code, extra = {}) {
  process.stdout.write(JSON.stringify({ product: "SENTINEL APEX billing canary", base, revenue_base: revenueBase, mode, run: runId,
    at: new Date().toISOString(), result, ...extra, steps }, null, 2) + "\n");
  process.exit(code);
}

const http = { intel: client(base), revenue: client(revenueBase) };
if (!["public", "admin", "live", "test-checkout"].includes(mode)) out("USAGE", [], EXIT.FAIL, { usage: "public|admin|live|test-checkout" });

const steps = await runPublicChecks(http);
if (mode !== "public") {
  if (!secret) out("OPERATOR_CREDENTIAL_REQUIRED", steps, EXIT.OPERATOR_CREDENTIAL_REQUIRED, { missing: "CDB_BILLING_CANARY_ADMIN_SECRET" });
  const admin = await runAdminChecks(http, secret, { requireReady: mode === "live" });
  steps.push(...admin.steps);
  if (mode === "test-checkout") {
    if (!readinessProvesTestMode(admin.readiness)) out("LIVE_MODE_REFUSED", steps, EXIT.LIVE_MODE_REFUSED,
      { reason: "readiness does not prove a Razorpay test-mode key; the canary never creates a subscription on live keys" });
    const email = process.env.CDB_BILLING_CANARY_EMAIL || `billing-canary+${runId}@example.com`;
    steps.push(...await runTestCheckout(http, { email }));
  }
}
const failed = steps.filter((s) => !s.ok).map((s) => s.step);
out(failed.length ? "FAIL" : "PASS", steps, failed.length ? EXIT.FAIL : EXIT.PASS, { failed });
