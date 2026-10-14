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
  "upgrade.html",
  "billing.html",
  "admin.html",
  "deploy/billing-canary",
  "config",
  "workers/revenue-engine/src",
  "workers/intel-gateway/package.json",
  "workers/intel-gateway/src",
  // mssp-tenants.test.js checks the published MSSP docs against the live routes.
  "MSSP_PARTNER_PROGRAM.md",
  "mssp.html",
  "docs/MSSP_TENANT_IDENTITY_V185.md",
];
const SUITES = [
  // S28 billing canary, certified against both Workers in-process.
  ["deploy/billing-canary", ["--test", "canary.test.mjs"]],
  ["workers/revenue-engine", ["--test", "src/__tests__/billing-policy.test.js", "src/__tests__/subscription-engine.test.js",
    "src/__tests__/billing-credit-notes.test.js", "src/__tests__/billing-export-po.test.js",
    "src/__tests__/billing-go-live.test.js", "src/__tests__/billing-center.test.js",
    "src/__tests__/cross-worker-revocation.test.js", "src/__tests__/commercial-readiness.test.js",
    "src/__tests__/pricing-fail-closed.test.js",
    // P0 2026-10-02: payment-to-entitlement hardening.
    "src/__tests__/subscription-webhook-hardening.test.js", "src/__tests__/renewal-and-key-email.test.js",
    // F22 2026-10-02: keys are never emailed; one-time redemption.
    "src/__tests__/activation-link.test.js"]],
  ["workers/intel-gateway", ["--test", "src/__tests__/razorpay-create-order-taxid.test.js",
    "src/__tests__/razorpay-webhook-subscription-guard.test.js", "src/__tests__/manual-notify-retirement.test.js",
    "src/__tests__/gumroad-membership.test.js", "src/__tests__/gumroad-lifecycle.test.js",
    "src/__tests__/gumroad-products.test.js",
    // P0 2026-10-02: legacy Order authority and Gumroad recovery, plus the
    // webhook-authenticity, sale-lock and MSSP activation suites, which no
    // control exercised before.
    "src/__tests__/legacy-order-authority.test.js", "src/__tests__/gumroad-provisioning-recovery.test.js",
    "src/__tests__/payment-webhook-metering.test.js", "src/__tests__/gumroad-provisioning-lock.test.js",
    "src/__tests__/mssp-tenants.test.js",
    // F22 2026-10-02: one-time key redemption and key-free activation email.
    "src/__tests__/key-redemption.test.js"]],
];

const BR = "workers/revenue-engine/src/billing-routes.js";
const BL = "workers/revenue-engine/src/billing-ledger.js";
const GS = "workers/revenue-engine/src/gst.js";
const SE = "workers/revenue-engine/src/subscription-engine.js";
const GW = "workers/intel-gateway/src/index.js";
const GL = "workers/intel-gateway/src/gumroad-lifecycle.js";
const EP = "workers/revenue-engine/src/enterprise-po.js";
const RI = "workers/revenue-engine/src/index.js";
const LA = "workers/intel-gateway/src/legacy-order-authority.js";
const KR = "workers/intel-gateway/src/key-redemption.js";

// [name, file, find, replace] -- `find` must occur exactly once.
const CONTROLS = [
  // S28 billing canary safety.
  ["canary would create a test checkout on live keys", "deploy/billing-canary/canary-lib.mjs",
    "  return !!(c && c.ok === false && /test mode/.test(String(c.detail || \"\")));", "  return !!c;"],
  ["canary counts a missing webhook secret (500) as a refusal", "deploy/billing-canary/canary-lib.mjs",
    "  step(steps, \"razorpay_webhook_refuses_bad_signature\", unsigned.status === 401,",
    "  step(steps, \"razorpay_webhook_refuses_bad_signature\", unsigned.status === 401 || unsigned.status === 500,"],
  ["canary live gate passes a BLOCKED verdict", "deploy/billing-canary/canary-lib.mjs",
    "    step(steps, \"readiness_verdict\", !requireReady || readiness.verdict === \"READY\",", "    step(steps, \"readiness_verdict\", true,"],
  ["canary accepts a checkout the Plan check refused", "deploy/billing-canary/canary-lib.mjs",
    "  const created = a.status === 200 && a.body && /^sub_/.test(a.body.subscription_id || \"\");", "  const created = a.status < 600 && a.body && a.body.subscription_id !== null;"],
  // S16/S18/S19 Gumroad (gateway).
  ["Gumroad tier inferred from the product name again", GW,
    "    tier = product.tier;", "    tier = inferGumroadTier(product_name, variants);"],
  ["Gumroad sale price not checked", GW,
    "    if (!priceCheck.ok) return await holdGumroadSale(env, ctx, formData, priceCheck.reason, priceCheck);", ""],
  ["plan-like product outside the catalog provisioned by name", GW,
    "      return await holdGumroadSale(env, ctx, formData, \"unknown_product\", null);",
    "      return await processGumroadSale(env, ctx, formData, pingKind, { tier: inferGumroadTier(product_name, variants), billingCycle: \"monthly\" });"],
  ["content products mint API keys again", GW,
    "      if (GUMROAD_CONTENT_PRODUCTS.includes(gumroadPermalinkFrom(formData)) || !looksLikePlatformProduct(product_name)) {",
    "      if (!looksLikePlatformProduct(product_name)) {"],
  ["a discount below the catalog price accepted", "workers/intel-gateway/src/gumroad-products.js",
    "  if (paid < expected) return", "  if (paid < expected / 2) return"],
  ["non-USD Gumroad sale accepted", "workers/intel-gateway/src/gumroad-products.js",
    "  if (currency !== \"usd\") return", "  if (false) return"],
  ["held-sale redelivery re-holds and re-alerts", GW,
    "    if (priorHold) return jsonResp({ status: \"held_for_review\", reason: priorHold.reason, sale_id, duplicate: true });", ""],
  ["refund of a held sale leaves it releasable", GW,
    "    await env.SECURITY_HUB_KV.delete(`gumroad_held:${saleId}`);\n    auditLog(ctx, env, { action: `gumroad_held_sale_${kind}`, sale_id: saleId });",
    "    auditLog(ctx, env, { action: `gumroad_held_sale_${kind}`, sale_id: saleId });"],
  ["Gumroad seller binding skipped", GW,
    "  if (env.GUMROAD_SELLER_ID && formData.seller_id !== env.GUMROAD_SELLER_ID) {", "  if (false) {"],
  ["reconcile writes during a dry run", GW,
    "        if (apply) await env.SECURITY_HUB_KV.put(mapKey, k.name, { expirationTtl: GUMROAD_KEY_MAP_TTL });",
    "        await env.SECURITY_HUB_KV.put(mapKey, k.name, { expirationTtl: GUMROAD_KEY_MAP_TTL });"],
  ["reconcile overwrites a conflicting map", GW,
    "        if (existing) { conflict = true; out.conflicts.push(", "        if (false) { conflict = true; out.conflicts.push("],
  // S19 pricing fail-closed (Razorpay Plans).
  ["checkout created without verifying the Plan price", SE,
    "  const planCheck = await verifyPlanPrice(env, tier, cycle, planId);", "  const planCheck = { ok: true };"],
  ["Plan amount not compared", SE,
    "  if (plan.item.amount !== expected) return", "  if (false) return"],
  ["Plan period not compared", SE,
    "  if (!periodOk) return { ok: false, reason: \"period_mismatch\", expected_paise: expected };", ""],
  ["unreadable Plan treated as verified (fail open)", SE,
    "  if (!plan || !plan.item) return { ok: false, reason: \"plan_unreadable\" };", "  if (!plan || !plan.item) return { ok: true, expected_paise: expected };"],
  ["readiness ignores Plan prices", "workers/revenue-engine/src/commercial-readiness.js",
    "    checks.push(check(\"razorpay_plan_prices\", bad.length === 0, true,", "    checks.push(check(\"razorpay_plan_prices\", true, true,"],
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
    "        await denyGatewayAccess(env, link, \"cancelled\", at, { provider_sub_id: providerId });",
    "        await patchApiKeyEntitlement(env, link.api_key, { expires_at: at });"],
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
  // Checkout P0 (2026-10-01).
  ["a paid checkout's retry opens a second payment", SE,
    "if (pendingLink && PAID_CHECKOUT_LINK_STATUSES.includes(pendingLink.status)) {", "if (false) {"],
  ["malformed Gumroad sale ping provisions a key", GW,
    "  if (!sale_id || !email) return jsonResp({ error: \"Invalid Gumroad payload: sale_id and email required\" }, 400);",
    "  if (false) return jsonResp({ error: \"Invalid Gumroad payload: sale_id and email required\" }, 400);"],
  ["Razorpay error body returned to the browser", SE,
    "message: \"Checkout could not be started. No payment was taken.\" }, 502);",
    "message: \"Checkout could not be started. No payment was taken.\", detail: errText }, 502);"],
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
  // P0 2026-10-02: payment-to-entitlement closure.
  ["legacy webhook provisions any captured payment (no Order authority)", GW,
    "      { ...payEntity, notes: { ...orderNotes, ...(payEntity.notes || {}) } }, RAZORPAY_TIER_PRICES);\n    if (!authority.ok) {",
    "      { ...payEntity, notes: { ...orderNotes, ...(payEntity.notes || {}) } }, RAZORPAY_TIER_PRICES);\n    if (false) {"],
  ["legacy verify trusts the browser's billing cycle", GW,
    "    order_id: razorpay_order_id, payment_id: razorpay_payment_id,\n  }, authority.billing);",
    "    order_id: razorpay_order_id, payment_id: razorpay_payment_id,\n  }, body.billing === \"annual\" ? \"annual\" : \"monthly\");"],
  ["legacy Order amount not checked", LA,
    "  if (!Number.isInteger(p.amount) || p.amount !== price[billing]) return { ok: false, reason: \"amount_mismatch\" };",
    "  if (false) return { ok: false, reason: \"amount_mismatch\" };"],
  ["legacy payment not created by the platform accepted", LA,
    "  if (notes.platform !== LEGACY_ORDER_PLATFORM) return { ok: false, reason: \"not_created_by_this_platform\" };",
    "  if (false) return { ok: false, reason: \"not_created_by_this_platform\" };"],
  ["activation without a link ignores the Plan (notes set the tier)", SE,
    "        if (!planTier || (notes.tier && String(notes.tier).toUpperCase() !== planTier.tier)) {",
    "        if (planTier && notes.tier && String(notes.tier).toUpperCase() !== planTier.tier) {"],
  ["activation ignores a Plan mismatch with the server link", SE,
    "        if (link.plan_id && subPlanId && link.plan_id !== subPlanId) {", "        if (false) {"],
  ["event claim kept when the link read fails (read outside the try)", SE,
    "  let link = null, email = \"\", tier = \"\", cycle = \"monthly\";\n  try {\n  link  = providerId ? await getProviderLink(env, providerId) : null;",
    "  let link = providerId ? await getProviderLink(env, providerId) : null, email = \"\", tier = \"\", cycle = \"monthly\";\n  try {"],
  ["activation retry mints a second key", SE,
    "      let result = provisionedKey ? await env.REVENUE_CRM_KV.get(provisionedKey, \"json\") : null;", "      let result = null;"],
  ["activation key ignores Razorpay's paid period", SE,
    "      await patchApiKeyEntitlement(env, result.api_key, { expires_at: keyAccessUntil(env, activePeriodEnd) || activePeriodEnd });", ""],
  ["renewal grace removed (key lapses at period end)", SE,
    "  return new Date(t + renewalGraceHours(env) * 3600e3).toISOString();", "  return new Date(t).toISOString();"],
  ["Razorpay subscription webhook signature not verified", SE,
    "  const valid = await verifyRazorpayHmac(rawBody, sig, secret);", "  const valid = true;"],
  ["daily check expires Razorpay subscriptions at period end", RI,
    "    const providerManaged = rec.billing_provider === \"razorpay\" || !!rec.provider_sub_id;", "    const providerManaged = false;"],
  // Re-anchored 2026-10-02 (F22): the flag now also gates the one-time link.
  ["key email sent with the owner flag off", RI,
    "  const keyEmailOn = env.KEY_EMAIL_DELIVERY_ENABLED === \"true\";\n  const activation = keyEmailOn", "  const keyEmailOn = true;\n  const activation = keyEmailOn"],
  ["failed or skipped email recorded as sent", RI,
    "      msg.status = outcome === \"sent\" ? \"sent\" : outcome === \"no_provider\" ? \"skipped_no_provider\" : \"failed\";",
    "      msg.status = \"sent\";"],
  ["Gumroad claim never released after a failure", GW,
    "        method: \"POST\", body: JSON.stringify({ action: \"claim_release\", saleId: sale_id }),",
    "        method: \"POST\", body: JSON.stringify({ saleId: sale_id }),"],
  ["Gumroad retry mints a second key", GW,
    "  const apiKey = (await env.SECURITY_HUB_KV.get(`gumroad_sale_key_map:${sale_id}`))\n    || await provisionApiKey(env, ctx, tier, email, \"gumroad_webhook\", {",
    "  const apiKey = await provisionApiKey(env, ctx, tier, email, \"gumroad_webhook\", {"],
  ["Gumroad webhook secret not checked", GW,
    "  if (!urlToken || !timingSafeEqual(urlToken, env.GUMROAD_WEBHOOK_SECRET)) {", "  if (false) {"],
  ["legacy Razorpay webhook signature not verified", GW,
    "  if (!valid) {\n    auditLog(ctx, env, { action: \"webhook_sig_fail\", source: \"razorpay\" });",
    "  if (false) {\n    auditLog(ctx, env, { action: \"webhook_sig_fail\", source: \"razorpay\" });"],
  ["refund.created does not revoke (access lasts until refund.processed)", BR,
    "    if (payment.provider_sub_id) await revokeEntitlementForSubscription(payment.provider_sub_id, \"refunded\");",
    "    if (payment.provider_sub_id && processed) await revokeEntitlementForSubscription(payment.provider_sub_id, \"refunded\");"],
  ["refund.failed revokes the paid access", BR,
    "    if (event === \"refund.failed\") {\n      const req",
    "    if (event === \"refund.failed\") {\n      if (payment.provider_sub_id) await revokeEntitlementForSubscription(payment.provider_sub_id, \"refunded\");\n      const req"],
  ["a replayed renewal extends access again (expiry relative, not Razorpay's period)", SE,
    "      await patchApiKeyEntitlement(env, link.api_key, { expires_at: keyAccessUntil(env, periodEnd) || periodEnd });\n      await putProviderLink(env, providerId, { ...link, status: \"active\", current_period_end: periodEnd",
    "      await patchApiKeyEntitlement(env, link.api_key, { expires_at: new Date(Math.max(Date.now(), Date.parse(JSON.parse(await env.API_KEYS_KV.get(link.api_key) || \"{}\").expires_at || 0)) + 30 * 86400000).toISOString() });\n      await putProviderLink(env, providerId, { ...link, status: \"active\", current_period_end: periodEnd"],
  ["redemption replay allowed (one-time claim ignored)", KR,
    "  if (claim !== \"claimed\") return { status: 410, outcome: \"replay\", ref };",
    "  if (false) return { status: 410, outcome: \"replay\", ref };"],
  ["redemption expiry not checked", KR,
    "  if (!(Date.parse(rec.expires_at) > nowMs)) return { status: 410, outcome: \"expired\", ref };",
    "  if (false) return { status: 410, outcome: \"expired\", ref };"],
  ["redemption reveals a revoked key (access not checked)", KR,
    "  const access = await deps.keyAccess(rec.key);",
    "  const access = { ok: true, record: null };"],
  ["redemption without the claim lock allowed (fail open)", GW,
    "  if (!env.GUMROAD_PROVISIONING_LOCK) return \"unavailable\";\n  try {\n    const name = `redeem:${hash}`;",
    "  if (!env.GUMROAD_PROVISIONING_LOCK) return \"claimed\";\n  try {\n    const name = `redeem:${hash}`;"],
  ["redemption token accepted from the query string", GW,
    "    token = raw ? JSON.parse(raw)?.token : null;",
    "    token = (raw ? JSON.parse(raw)?.token : null) || new URL(request.url).searchParams.get(\"token\");"],
  ["activation email carries the raw key", GW,
    "      <a href=\"${redemption.url}\" style=\"color:#34d399;font-weight:700;\">Reveal my API key (one time) &rarr;</a>",
    "      <code>${apiKey}</code> <a href=\"${redemption.url}\" style=\"color:#34d399;font-weight:700;\">Reveal my API key (one time) &rarr;</a>"],
  ["welcome template renders a key", RI,
    "<h2>Welcome to SENTINEL APEX ${v.tier}</h2><p>For your security",
    "<h2>Welcome to SENTINEL APEX ${v.tier}</h2><code>${v.api_key}</code><p>For your security"],
  ["queued variables shipped to the email provider", RI,
    "        personalizations: [{ to: [{ email: msg.to }] }],",
    "        personalizations: [{ to: [{ email: msg.to }], dynamic_template_data: msg.vars }],"],
  ["activation notice queues the raw key", RI,
    "    email, tier, req_day:tierCfg.req_day, req_min:tierCfg.req_min,\n    activation_url:",
    "    email, tier, api_key:key, req_day:tierCfg.req_day, req_min:tierCfg.req_min,\n    activation_url:"],
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
