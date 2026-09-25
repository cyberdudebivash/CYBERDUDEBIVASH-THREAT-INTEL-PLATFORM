// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Revenue Engine: commercial readiness
//
// S13/S22/S23. One read-only answer to "can this deployment take money
// correctly right now, and what is waiting on an operator?":
//
//   buildCommercialReadiness(env, nowMs)
//     checks   configuration the checkout, webhook, invoicing and gateway
//              entitlement depend on. Presence / validity only: never a
//              secret value, never a Plan ID, never GST config contents.
//     verdict  READY | BLOCKED (any failing check with blocking: true)
//     queue    operator work from the billing ledger (refunds to decide or
//              stuck, invoice holds, credit notes to issue, disputes,
//              enterprise quotes waiting on invoice / payment / provisioning)
//
// Served at GET /api/v2/billing/admin/readiness (X-Admin-Secret) and
// summarised in the admin /api/health response. Composes existing sources
// (PLAN_ID_ENV_KEYS, parseGstInvoiceConfig, lutFor, financialYear, the
// ledger list helpers); it re-implements none of them.
// =============================================================================

import { json, isAdmin } from "./index.js";
import { PLAN_ID_ENV_KEYS } from "./subscription-engine.js";
import { parseGstInvoiceConfig, lutFor, financialYear } from "./gst.js";
import { ensureBillingSchema, listRefundRequests, listInvoiceHolds, listPendingCreditNotes } from "./billing-ledger.js";

const HOUR = 3600e3;
const DAY = 24 * HOUR;
// Thresholds for "needs attention", not policy: a pending refund request is
// overdue after 2 days; an approved request whose Razorpay refund never
// started after 1 hour; a refund Razorpay has not confirmed after 7 days.
export const QUEUE_THRESHOLDS = Object.freeze({
  refund_decision_ms: 2 * DAY,
  refund_approved_stuck_ms: HOUR,
  refund_initiated_stuck_ms: 7 * DAY,
  quote_provisioning_stuck_ms: HOUR,
});

function check(id, ok, blocking, detail, fix) {
  return ok ? { id, ok: true, blocking, detail } : { id, ok: false, blocking, detail, fix };
}

/** Configuration checks, pure over env except the two binding pings. */
async function configurationChecks(env, nowMs) {
  const checks = [];
  const keyId = typeof env.RAZORPAY_KEY_ID === "string" ? env.RAZORPAY_KEY_ID : "";
  const hasKeys = !!(keyId && env.RAZORPAY_KEY_SECRET);
  checks.push(check("razorpay_api_keys", hasKeys, true,
    hasKeys ? "Razorpay API key pair configured." : "Razorpay API key pair missing: checkout and refunds cannot call Razorpay.",
    "wrangler secret put RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET (revenue engine)"));
  if (hasKeys) {
    const live = keyId.startsWith("rzp_live_");
    checks.push(check("razorpay_live_mode", live, true,
      live ? "Live-mode key." : `Key is not a live-mode key (${keyId.startsWith("rzp_test_") ? "test mode" : "unrecognised prefix"}): no real payment can be taken.`,
      "Use the Razorpay live key pair for production"));
  }
  checks.push(check("razorpay_webhook_secret", !!env.RAZORPAY_WEBHOOK_SECRET, true,
    env.RAZORPAY_WEBHOOK_SECRET ? "Webhook secret configured." : "Webhook secret missing: every Razorpay webhook is refused, so no payment activates a subscription.",
    "wrangler secret put RAZORPAY_WEBHOOK_SECRET (same value as the Razorpay Dashboard webhook)"));
  checks.push(check("razorpay_account_binding", !!env.RAZORPAY_ACCOUNT_ID, false,
    env.RAZORPAY_ACCOUNT_ID ? "Webhooks are bound to one Razorpay account." : "Webhooks are not bound to an account (recommended hardening).",
    "wrangler secret put RAZORPAY_ACCOUNT_ID (acc_... from the Razorpay Dashboard)"));

  const missingPlans = [];
  for (const [tier, cycles] of Object.entries(PLAN_ID_ENV_KEYS)) {
    for (const [cycle, envKey] of Object.entries(cycles)) if (!env[envKey]) missingPlans.push({ sku: `${tier.toLowerCase()}_${cycle}`, env: envKey });
  }
  checks.push(check("razorpay_plan_ids", missingPlans.length === 0, true,
    missingPlans.length === 0 ? "All 6 Plan IDs configured."
      : `${missingPlans.length} of 6 plans cannot be bought online: ${missingPlans.map((m) => m.sku).join(", ")}.`,
    missingPlans.map((m) => `wrangler secret put ${m.env}`).join("; ")));

  checks.push(check("api_keys_kv", !!env.API_KEYS_KV, true,
    env.API_KEYS_KV ? "Gateway entitlement store bound." : "API_KEYS_KV not bound: paid keys would never work at the gateway, and revocations would not reach it.",
    "Bind API_KEYS_KV (the gateway's namespace) in wrangler.toml"));
  const kvOk = env.REVENUE_CRM_KV ? await env.REVENUE_CRM_KV.get("health:ping").then(() => true).catch(() => false) : false;
  checks.push(check("revenue_crm_kv", kvOk, true,
    kvOk ? "Subscription store reachable." : "REVENUE_CRM_KV unbound or unreachable: subscriptions cannot be recorded.",
    "Bind REVENUE_CRM_KV in wrangler.toml"));
  let dbOk = false;
  if (env.CRM_DB) { try { await ensureBillingSchema(env.CRM_DB); dbOk = true; } catch (_) { dbOk = false; } }
  checks.push(check("billing_ledger", dbOk, true,
    dbOk ? "Billing ledger (D1) reachable, schema current." : "Billing ledger (CRM_DB) unbound or unreachable: payments, invoices and refunds cannot be recorded.",
    "Bind CRM_DB (sentinel-crm) in wrangler.toml"));

  const gst = env.GST_INVOICE_CONFIG ? parseGstInvoiceConfig(env.GST_INVOICE_CONFIG) : { ok: false, missing: ["GST_INVOICE_CONFIG"] };
  checks.push(check("gst_invoice_config", gst.ok, false,
    gst.ok ? "GST invoicing configured (CA-confirmed)." : `GST invoices are held, not issued. Missing or invalid: ${gst.missing.join(", ")}.`,
    "wrangler secret put GST_INVOICE_CONFIG (see docs/COMMERCIAL_POLICY_V1.md)"));
  if (gst.ok) {
    const fy = financialYear(nowMs);
    const hasLut = !!lutFor(gst.config, fy);
    checks.push(check("export_lut_current_fy", hasLut, false,
      hasLut ? `LUT on file for FY ${fy}.` : `No LUT for FY ${fy}: export invoices are held.`,
      `Add {"arn": "...", "financial_year": "${fy}"} to luts in GST_INVOICE_CONFIG`));
    const nextFy = financialYear(nowMs + 30 * DAY);
    if (nextFy !== fy) {
      const hasNext = !!lutFor(gst.config, nextFy);
      checks.push(check("export_lut_next_fy", hasNext, false,
        hasNext ? `LUT on file for FY ${nextFy}.` : `FY ${nextFy} starts within 30 days and has no LUT.`,
        `File the LUT for FY ${nextFy} and add it to luts before 1 April`));
    }
  }
  checks.push(check("operator_alerts", !!env.SLACK_WEBHOOK_URL, false,
    env.SLACK_WEBHOOK_URL ? "Refund requests alert the operator." : "No alert channel: refund requests are only visible in this queue.",
    "wrangler secret put SLACK_WEBHOOK_URL"));
  return checks;
}

function ageMs(iso, nowMs) {
  const t = Date.parse(iso || "");
  return Number.isFinite(t) ? nowMs - t : 0;
}

function bucket(rows, nowMs, field, overMs) {
  const oldest = rows.reduce((m, r) => Math.max(m, ageMs(r[field], nowMs)), 0);
  return {
    count: rows.length,
    oldest_age_hours: rows.length ? Math.floor(oldest / HOUR) : null,
    overdue: overMs === undefined ? rows.length : rows.filter((r) => ageMs(r[field], nowMs) > overMs).length,
  };
}

/** Operator work waiting in the billing ledger. Counts and ages only, no customer data. */
export async function buildOperationsQueue(db, nowMs) {
  await ensureBillingSchema(db);
  const [pending, approved, initiated, holds, cns, disputed, quotes] = await Promise.all([
    listRefundRequests(db, "pending_review"),
    listRefundRequests(db, "approved"),
    listRefundRequests(db, "refund_initiated"),
    listInvoiceHolds(db),
    listPendingCreditNotes(db),
    db.prepare(`SELECT COUNT(*) AS n FROM billing_payments WHERE disputed = 1 AND refund_status = 'none'`).first(),
    db.prepare(`SELECT status, COUNT(*) AS n, MIN(updated_at) AS oldest FROM enterprise_quotes
                 WHERE status IN ('accepted', 'invoiced', 'provisioning') GROUP BY status`).all(),
  ]);
  const holdReasons = {};
  for (const h of holds) holdReasons[h.invoice_hold_reason || "unspecified"] = (holdReasons[h.invoice_hold_reason || "unspecified"] || 0) + 1;
  const q = Object.fromEntries((quotes.results || []).map((r) => [r.status, r]));
  const quoteBucket = (s, overMs) => {
    const r = q[s];
    if (!r) return { count: 0, oldest_age_hours: null, overdue: 0 };
    const age = ageMs(r.oldest, nowMs);
    return { count: r.n, oldest_age_hours: Math.floor(age / HOUR), overdue: overMs === undefined ? r.n : (age > overMs ? r.n : 0) };
  };
  const T = QUEUE_THRESHOLDS;
  const items = {
    refund_requests_to_decide: { ...bucket(pending, nowMs, "requested_at", T.refund_decision_ms), action: "POST /api/v2/billing/refunds/approve or /reject" },
    refunds_approved_not_started: { ...bucket(approved, nowMs, "decided_at", T.refund_approved_stuck_ms), action: "Retry POST /api/v2/billing/refunds/approve (adopts an existing Razorpay refund)" },
    refunds_awaiting_razorpay: { ...bucket(initiated, nowMs, "updated_at", T.refund_initiated_stuck_ms), action: "Check the refund in the Razorpay Dashboard" },
    invoice_holds: { ...bucket(holds, nowMs, "captured_at"), by_reason: holdReasons, action: "POST /api/v2/billing/invoices/issue" },
    credit_notes_to_issue: { ...bucket(cns, nowMs, "processed_at"), action: "POST /api/v2/billing/credit-notes/issue" },
    disputes_open: { count: disputed?.n || 0, oldest_age_hours: null, overdue: disputed?.n || 0, action: "Respond in the Razorpay Dashboard (disputes)" },
    quotes_to_invoice: { ...quoteBucket("accepted"), action: "POST /api/v2/billing/quotes/invoice" },
    quotes_awaiting_payment: { ...quoteBucket("invoiced", Infinity), action: "POST /api/v2/billing/quotes/reconcile when the transfer arrives" },
    quotes_provisioning_stuck: { ...quoteBucket("provisioning", T.quote_provisioning_stuck_ms), action: "POST /api/v2/billing/quotes/provision" },
  };
  // "Attention" counts what an operator must act on now. Quotes awaiting
  // the buyer's bank transfer are listed but are not operator work.
  const attention = Object.entries(items)
    .filter(([k]) => k !== "quotes_awaiting_payment" && k !== "refunds_awaiting_razorpay")
    .reduce((n, [, v]) => n + v.count, 0) + items.refunds_awaiting_razorpay.overdue;
  return { attention, items };
}

/**
 * @returns {Promise<{verdict: "READY"|"BLOCKED", blockers: string[], warnings: string[],
 *   checks: object[], queue: object|null, generated_at: string}>}
 */
export async function buildCommercialReadiness(env, nowMs = Date.now()) {
  const checks = await configurationChecks(env, nowMs);
  const blockers = checks.filter((c) => !c.ok && c.blocking).map((c) => c.id);
  const warnings = checks.filter((c) => !c.ok && !c.blocking).map((c) => c.id);
  let queue = null;
  if (checks.find((c) => c.id === "billing_ledger")?.ok) {
    try { queue = await buildOperationsQueue(env.CRM_DB, nowMs); } catch (_) { queue = null; }
  }
  return {
    verdict: blockers.length ? "BLOCKED" : "READY",
    blockers, warnings, checks, queue,
    generated_at: new Date(nowMs).toISOString(),
  };
}

// GET /api/v2/billing/admin/readiness  (X-Admin-Secret)
export async function handleCommercialReadiness(request, env) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);
  return json(await buildCommercialReadiness(env));
}
