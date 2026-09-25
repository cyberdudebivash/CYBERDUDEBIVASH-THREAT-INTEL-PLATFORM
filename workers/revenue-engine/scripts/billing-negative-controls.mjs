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
  ["workers/revenue-engine", ["--test", "src/__tests__/billing-policy.test.js", "src/__tests__/subscription-engine.test.js",
    "src/__tests__/billing-credit-notes.test.js", "src/__tests__/billing-export-po.test.js",
    "src/__tests__/billing-go-live.test.js", "src/__tests__/billing-center.test.js",
    "src/__tests__/cross-worker-revocation.test.js", "src/__tests__/commercial-readiness.test.js"]],
  ["workers/intel-gateway", ["--test", "src/__tests__/razorpay-create-order-taxid.test.js",
    "src/__tests__/razorpay-webhook-subscription-guard.test.js", "src/__tests__/manual-notify-retirement.test.js",
    "src/__tests__/gumroad-membership.test.js", "src/__tests__/gumroad-lifecycle.test.js"]],
];

const BR = "workers/revenue-engine/src/billing-routes.js";
const BL = "workers/revenue-engine/src/billing-ledger.js";
const GS = "workers/revenue-engine/src/gst.js";
const SE = "workers/revenue-engine/src/subscription-engine.js";
const GW = "workers/intel-gateway/src/index.js";
const GL = "workers/intel-gateway/src/gumroad-lifecycle.js";
const EP = "workers/revenue-engine/src/enterprise-po.js";

// [name, file, find, replace] -- `find` must occur exactly once.
const CONTROLS = [
  // Commercial readiness S13/S22/S23.
  ["missing webhook secret does not block go-live", "workers/revenue-engine/src/commercial-readiness.js",
    "  checks.push(check(\"razorpay_webhook_secret\", !!env.RAZORPAY_WEBHOOK_SECRET, true,", "  checks.push(check(\"razorpay_webhook_secret\", !!env.RAZORPAY_WEBHOOK_SECRET, false,"],
  ["test-mode Razorpay key passes as live", "workers/revenue-engine/src/commercial-readiness.js",
    "    const live = keyId.startsWith(\"rzp_live_\");", "    const live = true;"],
  ["a missing Plan ID is not reported", "workers/revenue-engine/src/commercial-readiness.js",
    "    for (const [cycle, envKey] of Object.entries(cycles)) if (!env[envKey]) missingPlans.push(", "    for (const [cycle, envKey] of Object.entries(cycles)) if (false) missingPlans.push("],
  ["readiness echoes a secret value", "workers/revenue-engine/src/commercial-readiness.js",
    "hasKeys ? \"Razorpay API key pair configured.\"", "hasKeys ? \"Razorpay API key pair configured: \" + keyId"],
  ["overdue refund decisions not flagged", "workers/revenue-engine/src/commercial-readiness.js",
    "  refund_decision_ms: 2 * DAY,", "  refund_decision_ms: 30 * DAY,"],
  ["readiness served without the admin check", "workers/revenue-engine/src/commercial-readiness.js",
    "  if (!(await isAdmin(request, env))) return json({ error: \"unauthorized\" }, 401);\n  return json(await buildCommercialReadiness(env));",
    "  return json(await buildCommercialReadiness(env));"],
  // Halt recovery (owner decision 2026-09-25).
  ["halted subscription recovers without a captured payment", SE,
    "  if (!link?.internal_sub_id || !payEntity || payEntity.status !== \"captured\") {", "  if (!link?.internal_sub_id) {"],
  ["recovery revives a refunded key", SE,
    "  if (!rec || rec.subscription_status === \"refunded\" || rec.subscription_status === \"cancelled\") return false;", "  if (!rec) return false;"],
  ["recovery leaves the jwt_deny marker (new login refused)", SE,
    "  if (customerId) await env.API_KEYS_KV.delete(`jwt_deny:${customerId}`);\n  return true;", "  return true;"],
  ["halted subscription cannot recover (no SUSPENDED -> ACTIVE)", "workers/revenue-engine/src/subscription-domain.js",
    "[SUB_STATUS.SUSPENDED]: Object.freeze([SUB_STATUS.ACTIVE, SUB_STATUS.CANCELLED]),", "[SUB_STATUS.SUSPENDED]: Object.freeze([SUB_STATUS.CANCELLED]),"],
  ["activation after a halt provisions a second key", SE,
    "      if (link?.status === \"halted\" && link.internal_sub_id) {", "      if (false) {"],
  ["activation after a refund provisions again (clears jwt_deny)", SE,
    "      if (link && [\"refunded\", \"cancelled\", \"completed\"].includes(link.status)) {", "      if (false) {"],
  // S10 cross-worker revocation (revenue engine writes, gateway enforces).
  ["halt leaves pre-issued JWTs valid (no jwt_deny)", SE,
    "        await denyGatewayAccess(env, link, \"suspended\", new Date().toISOString(), { provider_sub_id: providerId });",
    "        await patchApiKeyEntitlement(env, link.api_key, { expires_at: new Date().toISOString() });"],
  ["cycle-end cancellation leaves pre-issued JWTs valid (no jwt_deny)", SE,
    "        await denyGatewayAccess(env, link, \"cancelled\", new Date().toISOString(), { provider_sub_id: providerId });",
    "        await patchApiKeyEntitlement(env, link.api_key, { expires_at: new Date().toISOString() });"],
  ["revenue engine writes a status the gateway does not deny", SE,
    "    await patchApiKeyEntitlement(env, link.api_key, { subscription_status: keep, expires_at: at });",
    "    await patchApiKeyEntitlement(env, link.api_key, { subscription_status: keep === \"refunded\" ? keep : \"past_due\", expires_at: new Date(Date.parse(at) + 60000).toISOString() });"],
  ["a later cancel relabels a refunded key", SE,
    "keyRecord && keyRecord.subscription_status === \"refunded\" ? \"refunded\" : status", "status"],
  ["gateway ignores the revenue engine's jwt_deny", GW,
    "      if (billingDenied) return { tier: TIERS.FREE, key: null, sub: null, error: \"subscription_status_denied\" };", ""],
  ["gateway no longer denies suspended keys", "workers/intel-gateway/src/subscription-lifecycle.js",
    "new Set([\"cancelled\", \"refunded\", \"suspended\", \"expired\"])", "new Set([\"cancelled\", \"refunded\", \"expired\"])"],
  // Billing Center S6-S12.
  ["account view reads another customer's email from the query string", BR,
    "  const database = db(env);\n  await ensureBillingSchema(database);",
    "  const q = sanitizeEmail(new URL(request.url).searchParams.get(\"email\")); if (q) who.email = q;\n  const database = db(env);\n  await ensureBillingSchema(database);"],
  ["superseded key reads the billing account", BR,
    "if (who.key_status === \"superseded\" || who.key_status === \"revoked\") {", "if (false) {"],
  ["account view leaks the provider link (and its api_key)", BR,
    "  const subscription = subscriptionView(link, internal, subId);", "  const subscription = link ? { ...link, ...subscriptionView(link, internal, subId) } : subscriptionView(link, internal, subId);"],
  ["refund offered again after a request exists", BR,
    "    eligible: elig.ok && !req,", "    eligible: elig.ok,"],
  ["repeated cancel calls Razorpay again", BR,
    "  if (link && link.cancel_scheduled_at) {", "  if (false) {"],
  ["scheduled cancellation not persisted", BR,
    "    if (link) await putProviderLink(env, subId, { ...link, cancel_at_cycle_end: true, cancel_scheduled_at: at });", ""],
  ["cancelling an ended subscription calls Razorpay", BR,
    "  if (link && ENDED_LINK_STATUSES.includes(link.status)) {", "  if (false) {"],
  // P0 go-live S5/S15.
  ["retried checkout creates a second subscription (no pending reuse)", SE,
    "if (pendingLink && pendingLink.status === \"created\") {", "if (false) {"],
  ["a paid subscription handed out again as the pending checkout", SE,
    "if (pendingLink && pendingLink.status === \"created\") {", "if (pendingLink) {"],
  ["same-tier live subscriber billed a second time", SE,
    "if (existing && existing.tier === tier && LIVE_SUB_STATUSES.includes(existing.status) &&", "if (false &&"],
  ["account binding skipped when the payload omits account_id", SE,
    "if (env.RAZORPAY_ACCOUNT_ID && payload.account_id !== env.RAZORPAY_ACCOUNT_ID) {",
    "if (env.RAZORPAY_ACCOUNT_ID && payload.account_id && payload.account_id !== env.RAZORPAY_ACCOUNT_ID) {"],
  ["unknown signed events claimed as processed", SE,
    "  if (!RAZORPAY_BILLING_EVENTS.includes(event)) {\n    await trackEvent(env, \"subscription_webhook_event_ignored\", { event: event || null, rid });",
    "  if (!RAZORPAY_BILLING_EVENTS.includes(event)) {\n    await markProcessed(env, request.headers.get(\"X-Razorpay-Event-Id\") || \"x\", {});\n    await trackEvent(env, \"subscription_webhook_event_ignored\", { event: event || null, rid });"],
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
    "WHERE fy = ? AND last_seq < ? AND ${notYet}`)\n        .bind(fy, INVOICE_SERIAL_MAX, key),",
    "WHERE fy = ? AND last_seq < ?`)\n        .bind(fy, INVOICE_SERIAL_MAX),"],
  ["invoice issued without GST configuration", BL,
    "  if (!cfg.ok) return \"gst_config_incomplete:\" + cfg.missing.join(\",\");\n", ""],
  ["export invoiced as a domestic supply", BL,
    "  if (pos.export) return exportHoldReason(row, cfg.config);\n", ""],
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

  // GST credit notes (2026-09-25)
  ["credit note issued for an unprocessed refund", BL,
    "if (refund.status !== \"processed\") return { status: \"held\", reason: \"refund_not_processed\" };",
    "if (false) return { status: \"held\", reason: \"refund_not_processed\" };"],
  ["credit notes may exceed the invoice (transactional guard off)", BL,
    "const fits = `(SELECT COALESCE(SUM(total_paise), 0) FROM credit_notes WHERE payment_id = ?) + ? <= ?`;",
    "const fits = `(? IS NOT NULL AND ? IS NOT NULL AND ? IS NOT NULL)`;"],
  ["credit note ignores the invoice's supply type", BL,
    "  const intra = inv.supply_type === \"intra_state\";\n  const zeroRated",
    "  const intra = true;\n  const zeroRated"],
  ["redelivered refund un-credits the invoice", BL,
    "WHERE payment_id = ? AND status = 'issued'`).bind(paymentId).run();", "WHERE payment_id = ?`).bind(paymentId).run();"],
  ["held invoice's refund never gets its credit note", BL,
    "  await issuePendingCreditNotesForPayment(db, env, paymentId);\n", ""],
  ["foreign customer reads another customer's credit note", BR,
    "if (!cn || (!viewer.admin && cn.email !== viewer.email))", "if (!cn)"],
  ["credit note issuance without the admin check", BR,
    "export async function handleCreditNoteIssue(request, env, ctx, rid) {\n  if (!(await isAdmin(request, env))) return json({ error: \"unauthorized\" }, 401);",
    "export async function handleCreditNoteIssue(request, env, ctx, rid) {"],
  ["credit notes share the invoice series", GS,
    "    if (prefix && cnPrefix === prefix) missing.push", "    if (false) missing.push"],

  // Gumroad memberships (2026-09-25)
  ["membership renewal mints a second key", GW,
    "  if (subscription_id && (pingKind === \"renewal\" ||", "  if (false && subscription_id && (pingKind === \"renewal\" ||"],
  ["Gumroad refund ping swallowed as already provisioned", GW,
    "  if (pingKind === \"refund\" || pingKind === \"dispute\") {", "  if (false) {"],
  ["a charge reactivates a refunded key", GL,
    "  return ![\"refunded\", \"suspended\"].includes(String(subscriptionStatus || \"\"));", "  return true;"],
  ["an early renewal loses already-paid time", GL,
    "Math.max(Number.isFinite(existing) ? existing : 0,", "Math.max(0,"],
  ["a won dispute revokes access", GL,
    "if (_true(formData.disputed) && !_true(formData.dispute_won)) return \"dispute\";", "if (_true(formData.disputed)) return \"dispute\";"],

  // Export of services under LUT (2026-09-25)
  ["export invoiced without a LUT for the year", BL,
    "  if (!lutFor(c, fy)) return \"export_lut_not_configured_for_\" + fy;\n", ""],
  ["export zero-rated without foreign-exchange evidence", BL,
    "  if (!row.payment_international && ![", "  if (false && ![" ],
  ["export invoiced as a taxable domestic supply", BL,
    "    return buildExportInvoiceDocument(row, c);\n", ""],
  ["export credit note charges GST", BL,
    "  const zeroRated = inv.supply_type === \"export_under_lut\";", "  const zeroRated = false;"],
  ["column migrations skipped", BL,
    "  for (const sql of BILLING_MIGRATIONS) {", "  for (const sql of []) {"],

  // Enterprise quote -> PO -> invoice -> bank transfer -> entitlement (2026-09-25)
  ["PO price drifts from the canonical contract", EP,
    "ENTERPRISE: 416000,", "ENTERPRISE: 415000,"],
  ["custom quote price without a recorded reason", EP,
    "    if (reason.length < 10) return json(", "    if (false) return json("],
  ["quote accepted without its token", EP,
    "  if (!/^qt_[0-9a-f]{20}$/.test(id) || !(await tokenValid(env, id, b.token))) return json({ error: \"not_found\" }, 404);",
    "  if (!/^qt_[0-9a-f]{20}$/.test(id)) return json({ error: \"not_found\" }, 404);"],
  ["expired quote accepted", EP,
    "  if (q.status === \"sent\" && Date.parse(q.valid_until) < Date.now()) {", "  if (false) {"],
  ["invoice issued before the PO", EP,
    "  if (q.status !== \"accepted\") {\n    if (q.invoice_number)", "  if (false) {\n    if (q.invoice_number)"],
  ["reconciled with a short payment", EP,
    "  if (received + tds !== total) {", "  if (false) {"],
  ["one bank transfer settles two invoices", BL,
    "    bank_reference      TEXT UNIQUE,", "    bank_reference      TEXT,"],
  ["entitlement provisioned twice", EP,
    "  const won = await transitionQuote(database, id, \"paid\", \"provisioning\");",
    "  const won = 1; await transitionQuote(database, id, \"paid\", \"provisioning\");"],
  ["reconciliation without the admin check", EP,
    "export async function handleQuoteReconcile(request, env, ctx, rid) {\n  if (!(await isAdmin(request, env))) return json({ error: \"unauthorized\" }, 401);",
    "export async function handleQuoteReconcile(request, env, ctx, rid) {"],
  ["TDS accepted on an export", EP,
    "    if (isExport(q)) return json({ error: \"TDS does not apply", "    if (false) return json({ error: \"TDS does not apply"],
  ["export reconciled without a FIRC", EP,
    "  if (isExport(q) && firc.length < 4) {", "  if (false) {"],
  ["invoiced quote cancelled (invoice orphaned)", EP,
    "[\"sent\", \"accepted\"], \"cancelled\"", "[\"sent\", \"accepted\", \"invoiced\"], \"cancelled\""],
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
