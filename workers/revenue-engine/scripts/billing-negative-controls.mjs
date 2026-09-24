#!/usr/bin/env node
/**
 * Commercial policy v1 (2026-09-24) -- billing negative controls (mutation proof).
 *
 * Copies the billing code and its tests to a temp directory, requires the
 * unmutated copy to PASS, then applies ONE deliberate defect per control (a
 * refund amount read from the request, a missing admin check, a skipped
 * serial guard, a one-time fallback, ...) and requires the suites to FAIL.
 * A control the tests do not catch exits 1. The working tree is never
 * modified.
 *
 *   node workers/revenue-engine/scripts/billing-negative-controls.mjs
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const COPY = [
  "revenue-crm/schema.sql",
  "config",
  "workers/revenue-engine/src",
  "workers/intel-gateway/package.json",
  "workers/intel-gateway/src",
];
const SUITES = [
  ["workers/revenue-engine", ["--test", "src/__tests__/billing-policy.test.js", "src/__tests__/subscription-engine.test.js"]],
  ["workers/intel-gateway", ["--test", "src/__tests__/razorpay-create-order-taxid.test.js",
    "src/__tests__/razorpay-webhook-subscription-guard.test.js", "src/__tests__/manual-notify-retirement.test.js"]],
];

const BR = "workers/revenue-engine/src/billing-routes.js";
const BL = "workers/revenue-engine/src/billing-ledger.js";
const GS = "workers/revenue-engine/src/gst.js";
const SE = "workers/revenue-engine/src/subscription-engine.js";
const GW = "workers/intel-gateway/src/index.js";

// [name, file, find, replace] -- `find` must occur exactly once.
const CONTROLS = [
  ["refund amount taken from the request body", BR,
    "amount: payment.amount_paise, speed: \"normal\", receipt: id,",
    "amount: Number(body.amount) || payment.amount_paise, speed: \"normal\", receipt: id,"],
  ["refund approval without the admin check", BR,
    "export async function handleRefundApprove(request, env, ctx, rid) {\n  if (!(await isAdmin(request, env))) return json({ error: \"unauthorized\" }, 401);",
    "export async function handleRefundApprove(request, env, ctx, rid) {"],
  ["approval not compare-and-set (double refund race)", BL,
    "`UPDATE refund_requests SET ${sets.join(\", \")} WHERE id = ? AND status IN (${fromList.map(() => \"?\").join(\",\")})`\n  ).bind(...vals, id, ...fromList).run();",
    "`UPDATE refund_requests SET ${sets.join(\", \")} WHERE id = ?`\n  ).bind(...vals, id).run();"],
  ["retry refunds again instead of adopting the existing refund", BR,
    "if ((p.amount_refunded || 0) > 0) {", "if (false) {"],
  ["refund window not enforced", BR,
    "if (!(age >= 0 && age <= REFUND_WINDOW_MS)) {", "if (false) {"],
  ["any payment (not the first) eligible", BL,
    "ORDER BY captured_at ASC, payment_id ASC LIMIT 1", "ORDER BY captured_at DESC, payment_id DESC LIMIT 1"],
  ["disputed payment refundable at approval", BR,
    "if (payment.disputed) return fail(\"payment_disputed\"", "if (false) return fail(\"payment_disputed\""],
  ["Razorpay amount not cross-checked", BR,
    "if (p.amount !== payment.amount_paise) return fail(", "if (false) return fail("],
  ["refund webhook does not revoke the entitlement", BR,
    "if (payment.provider_sub_id) await revokeEntitlementForSubscription(payment.provider_sub_id, \"refunded\");", ""],
  ["invoice serial consumed for an already-invoiced payment", BL,
    "WHERE fy = ? AND last_seq < ? AND ${notYet}`)\n        .bind(fy, INVOICE_SERIAL_MAX, paymentId),",
    "WHERE fy = ? AND last_seq < ?`)\n        .bind(fy, INVOICE_SERIAL_MAX),"],
  ["invoice issued without GST configuration", BL,
    "  if (!cfg.ok) return \"gst_config_incomplete:\" + cfg.missing.join(\",\");\n", ""],
  ["export invoiced as a domestic supply", BL,
    "  if (pos.export) return \"recipient_outside_india_export_requires_review\";\n", ""],
  ["IGST applied to an intra-state supply", GS,
    "  if (intraState) {\n    const cgst", "  if (false) {\n    const cgst"],
  ["recipient GSTIN ignored for place of supply", GS,
    "  if (buyerGstin && isValidGstin(buyerGstin)) {", "  if (false) {"],
  ["invoice number allowed past 16 characters", GS,
    "  if (n.length > INVOICE_NUMBER_MAX_LENGTH) throw", "  if (false) throw"],
  ["foreign customer reads another customer's invoice", BR,
    "if (!inv || (!viewer.admin && inv.email !== viewer.email))", "if (!inv)"],
  ["subscription GSTIN not validated", SE,
    "  if (!taxId.ok) return json({ error: taxId.reason, field: \"gstin\" }, 400);\n  const billingState", "  const billingState"],
  ["cancellation refunds / ends access immediately", BR,
    "{ cancel_at_cycle_end: 1 }", "{ cancel_at_cycle_end: 0 }"],
  ["gateway sells a recurring plan as a one-time order", GW,
    "  if (RECURRING_TIERS.has(tierUp)) {", "  if (false) {"],
  ["gateway provisions subscription charges (double key)", GW,
    "    if (payEntity.invoice_id || payload.payload?.subscription?.entity) {", "    if (false) {"],
  ["manual payment proof accepted again", GW,
    "async function handleManualNotify(request, env, ctx, method) {\n  return jsonResp(MANUAL_PAYMENT_RETIRED_BODY",
    "async function handleManualNotify(request, env, ctx, method) {\n  return _legacyHandleManualNotify(request, env, ctx, method);\n  return jsonResp(MANUAL_PAYMENT_RETIRED_BODY"],
];

function stage() {
  const dir = mkdtempSync(path.join(tmpdir(), "billing-nc-"));
  for (const rel of COPY) {
    const dest = path.join(dir, rel);
    mkdirSync(path.dirname(dest), { recursive: true });
    cpSync(path.join(REPO, rel), dest, { recursive: true });
  }
  return dir;
}

function suitesPass(dir) {
  for (const [cwd, args] of SUITES) {
    const r = spawnSync(process.execPath, args, { cwd: path.join(dir, cwd), encoding: "utf8" });
    if (r.status !== 0) return false;
  }
  return true;
}

let failures = 0;
const base = stage();
try {
  if (!suitesPass(base)) {
    console.error("BASELINE FAILED: the unmutated copy does not pass; controls would be meaningless.");
    process.exit(1);
  }
  console.log("baseline: unmutated billing suites PASS");
} finally {
  rmSync(base, { recursive: true, force: true });
}

for (const [name, file, find, replace] of CONTROLS) {
  const dir = stage();
  try {
    const target = path.join(dir, file);
    const src = readFileSync(target, "utf8");
    const count = src.split(find).length - 1;
    if (count !== 1) {
      console.error(`[BROKEN CONTROL] ${name}: anchor found ${count} times in ${file}`);
      failures++;
      continue;
    }
    writeFileSync(target, src.replace(find, replace));
    if (suitesPass(dir)) {
      console.error(`[NOT CAUGHT] ${name}`);
      failures++;
    } else {
      console.log(`[caught] ${name}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log(`\n${CONTROLS.length - failures}/${CONTROLS.length} billing negative controls caught`);
process.exit(failures ? 1 : 0);
