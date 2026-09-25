// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Revenue Engine v134.0.0
// CRM · Lead Management · Outbound · Enterprise Sales · Automation · Retention
// Routes: /api/crm/*, /api/deals/*, /api/outreach/*, /api/automation/*
// Deployed at: https://revenue.intel.cyberdudebivash.com
// =============================================================================

// Phase 2 (foundational pass): Razorpay Subscriptions -- subscription
// creation, webhook lifecycle, entitlement sync. See subscription-engine.js
// for scope notes (refunds/upgrades/downgrades/checkout-cutover deferred).
import { handleBillingSubscriptionCreate, handleBillingSubscriptionStatus, handleBillingWebhook, patchApiKeyEntitlement, patchInternalSub, tryTransition, PLAN_ID_ENV_KEYS } from "./subscription-engine.js";
import { handleRefundRequest, handleRefundList, handleRefundApprove, handleRefundReject, handleInvoiceList, handleInvoiceView, handleInvoiceHolds, handleInvoiceIssue, handleSubscriptionCancel, handleCreditNoteList, handleCreditNoteView, handleCreditNotesPending, handleCreditNoteIssue, handleBillingAccount } from "./billing-routes.js";
import { handleQuoteCreate, handleQuoteList, handleQuoteView, handleQuoteAccept, handleQuoteCancel, handleQuoteInvoice, handleQuoteReconcile, handleQuoteProvision } from "./enterprise-po.js";

const ENGINE = {
  VERSION:  "183.0",
  NAME:     "SENTINEL-REVENUE-ENGINE",
  // Confirmed unused elsewhere in this file (no `.PLANS`/`PLANS.`/`PLANS[` reference
  // outside this definition) -- kept, not deleted, per CLAUDE.md's deprecation-over-
  // deletion policy, but corrected to canon so it can't mislead a future reader.
  PLANS: {
    pro:        { name: "Pro",        inr: 4100,  usd: 49,  annual_inr: 41000,  annual_usd: 490  },
    enterprise: { name: "Enterprise", inr: 41600, usd: 499, annual_inr: 416000, annual_usd: 4990 },
    mssp:       { name: "MSSP",       inr: 83300,  usd: 999,  annual_inr: 833000,  annual_usd: 9990 },
  },
  TARGET_MRR_INR: 1000000,  // Rs.10L/month
  PIPELINE_STAGES: ["new","contacted","demo_scheduled","demo_done","trial","negotiation","closed_won","closed_lost"],
  DEAL_VALUES_INR: {
    pro_monthly:        4100,
    pro_annual:         41000,
    enterprise_monthly: 41600,
    enterprise_annual:  416000,
    enterprise_custom:  0,  // negotiated
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// ROUTER
// ─────────────────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const rid      = genId("rev");
    const url      = new URL(request.url);
    const path     = url.pathname;
    const method   = request.method;
    const requestOrigin = request.headers.get("Origin");
    const allowedOrigin = isAllowedRevenueOrigin(requestOrigin) ? requestOrigin : null;

    if (method === "OPTIONS") return cors204(allowedOrigin);

    const response = await routeRevenueRequest(request, env, ctx, rid, url, path, method);
    return withCorsOrigin(response, allowedOrigin);
  },

  // ── Cron handler — email send + follow-ups + trial nudges + sub expiry ────
  async scheduled(event, env, ctx) {
    const h = new Date().getUTCHours();
    if (h === 9)  await runDailyOutreach(env);
    if (h === 9)  await handleSubExpireCheck({}, env, "cron"); // daily expiry check
    if (h === 14) await runFollowUps(env);
    if (h === 18 && new Date().getUTCDay() === 1) await runWeeklyDigest(env);
  },
};

// Extracted from fetch() above (behavior unchanged) so the CORS-origin decision in fetch() can
// be applied exactly once, centrally, to whatever this returns -- rather than threading it
// through every dispatch line/handler below. See withCorsOrigin()'s comment.
async function routeRevenueRequest(request, env, ctx, rid, url, path, method) {
    try {
      // ── Public lead/trial endpoints ────────────────────────────────────────
      if (path === "/api/leads/capture" && method === "POST")
        return await handleLeadCapture(request, env, rid);
      // DEPRECATED 2026-09-24: free trial discontinued (commercial-contract.json
      // "No free trial"). Route kept, answers 410 Gone with the replacement;
      // handleTrialRequest() is unrouted, not deleted. Already-issued trial
      // keys and their nudge emails run out on their own expiry.
      if (path === "/api/leads/trial"   && method === "POST")
        return json(TRIAL_DISCONTINUED_BODY, 410);
      if (path === "/api/demo/request"  && method === "POST")
        return await handleDemoRequest(request, env, rid);
      if (path === "/api/demo/live"     && method === "GET")
        return await handleLiveDemoEndpoint(request, env, rid);

      // ── Public: Razorpay Subscriptions (Phase 2 foundational pass) ─────────
      // Dispatched here, before the isAdmin() gate below -- these must be
      // reachable by real customers and by Razorpay's webhook caller, neither
      // of which send X-Admin-Secret. (Contrast with the existing
      // dispatchCommercialRoutes() routes further below, which are only
      // reached *after* this gate and are therefore unreachable by non-admin
      // callers today despite being coded as "public" within that function --
      // a separate, pre-existing gap this pass does not change; see
      // Production Readiness Report.)
      if (path === "/api/v2/billing/subscriptions/create" && method === "POST")
        return await handleBillingSubscriptionCreate(request, env, ctx, rid);
      if (path === "/api/v2/billing/webhooks/razorpay" && method === "POST")
        return await handleBillingWebhook(request, env, ctx, rid);
      if (path === "/api/v2/billing/subscriptions/status" && method === "GET")
        return await handleBillingSubscriptionStatus(request, env, ctx, rid);

      // ── Refunds (merchant-approved) + GST invoices (billing-routes.js) ─────
      // Each handler authenticates itself: customer routes take the
      // subscription's X-API-Key, decision routes take X-Admin-Secret.
      // ── Enterprise quote -> PO -> invoice -> bank transfer (enterprise-po.js) ─
      if (path === "/api/v2/billing/quotes" && method === "POST")
        return await handleQuoteCreate(request, env, ctx, rid);
      if (path === "/api/v2/billing/quotes" && method === "GET")
        return await handleQuoteList(request, env);
      if (path === "/api/v2/billing/quotes/view" && method === "GET")
        return await handleQuoteView(request, env);
      if (path === "/api/v2/billing/quotes/accept" && method === "POST")
        return await handleQuoteAccept(request, env, ctx, rid);
      if (path === "/api/v2/billing/quotes/cancel" && method === "POST")
        return await handleQuoteCancel(request, env, ctx, rid);
      if (path === "/api/v2/billing/quotes/invoice" && method === "POST")
        return await handleQuoteInvoice(request, env, ctx, rid);
      if (path === "/api/v2/billing/quotes/reconcile" && method === "POST")
        return await handleQuoteReconcile(request, env, ctx, rid);
      if (path === "/api/v2/billing/quotes/provision" && method === "POST")
        return await handleQuoteProvision(request, env, ctx, rid);
      if (path === "/api/v2/billing/subscriptions/cancel" && method === "POST")
        return await handleSubscriptionCancel(request, env, ctx, rid);
      if (path === "/api/v2/billing/refunds/request" && method === "POST")
        return await handleRefundRequest(request, env, ctx, rid);
      if (path === "/api/v2/billing/refunds" && method === "GET")
        return await handleRefundList(request, env);
      if (path === "/api/v2/billing/refunds/approve" && method === "POST")
        return await handleRefundApprove(request, env, ctx, rid);
      if (path === "/api/v2/billing/refunds/reject" && method === "POST")
        return await handleRefundReject(request, env, ctx, rid);
      if (path === "/api/v2/billing/invoices" && method === "GET")
        return await handleInvoiceList(request, env);
      if (path === "/api/v2/billing/invoices/view" && method === "GET")
        return await handleInvoiceView(request, env);
      if (path === "/api/v2/billing/invoices/holds" && method === "GET")
        return await handleInvoiceHolds(request, env);
      if (path === "/api/v2/billing/invoices/issue" && method === "POST")
        return await handleInvoiceIssue(request, env, ctx, rid);
      if (path === "/api/v2/billing/credit-notes" && method === "GET")
        return await handleCreditNoteList(request, env);
      if (path === "/api/v2/billing/credit-notes/view" && method === "GET")
        return await handleCreditNoteView(request, env);
      if (path === "/api/v2/billing/credit-notes/pending" && method === "GET")
        return await handleCreditNotesPending(request, env);
      if (path === "/api/v2/billing/credit-notes/issue" && method === "POST")
        return await handleCreditNoteIssue(request, env, ctx, rid);
      // Billing Center (billing.html): the caller's own account, by X-API-Key.
      if (path === "/api/v2/billing/account" && method === "GET")
        return await handleBillingAccount(request, env);

      // ── Public: customer-facing commercial routes ──────────────────────────
      // Moved here from dispatchCommercialRoutes() (further below), which is
      // only ever reached *after* the isAdmin() gate immediately below this
      // block -- meaning these four routes, despite being coded there as
      // "public" (before that function's own internal isAdmin() check), were
      // never actually reachable by a real customer or by intel-gateway's
      // apikeys/validate caller, both of which send no X-Admin-Secret. Fixed
      // by dispatching them here, matching the same pattern already used for
      // the leads/trial/demo routes above and the billing routes just above.
      // The handler functions themselves are unchanged -- only reached
      // correctly now. The now-dead duplicate checks inside
      // dispatchCommercialRoutes() have been removed (see that function).
      if (path === "/api/apikeys/request-free" && method === "POST")
        return await handleFreeKeyRequest(request, env, rid);
      if (path === "/api/apikeys/validate" && method === "GET")
        return await handleApiKeyValidate(request, env, rid);
      if (path === "/api/apikeys/self-rotate" && method === "POST")
        return await handleApiKeySelfRotate(request, env, rid);
      if (path === "/api/payments/submit" && method === "POST")
        return await handlePaymentSubmit(request, env, rid);
      if (path === "/api/customer/portal" && method === "GET")
        return await handleCustomerPortal(request, env, rid);

      // ── Public: observability endpoint ─────────────────────────────────────
      // New (this pass) -- this Worker previously had no health endpoint at
      // all, unlike intel-gateway's /api/health. Added both as the minimum
      // observability requirement for a component now getting its own CI
      // deploy workflow, and to give that workflow's post-deploy smoke test
      // something real to check.
      if ((path === "/api/health" || path === "/api/health/") && method === "GET")
        return await handleRevenueEngineHealth(request, env, rid);

      // ── Admin-secured CRM endpoints ────────────────────────────────────────
      if (!await isAdmin(request, env)) {
        return json({ error: "unauthorized", message: "X-Admin-Secret required." }, 401);
      }

      // CRM — Leads
      if (path === "/api/crm/leads"              && method === "GET")  return await crmListLeads(request, env, rid);
      if (path === "/api/crm/leads"              && method === "POST") return await crmCreateLead(request, env, rid);
      if (path.startsWith("/api/crm/leads/")     && method === "GET")  return await crmGetLead(request, env, rid, path.slice(16));
      if (path.startsWith("/api/crm/leads/")     && method === "PUT")  return await crmUpdateLead(request, env, rid, path.slice(16));

      // CRM — Deals
      if (path === "/api/deals"                  && method === "GET")  return await dealsList(request, env, rid);
      if (path === "/api/deals"                  && method === "POST") return await dealCreate(request, env, rid);
      if (path.startsWith("/api/deals/")         && method === "GET")  return await dealGet(request, env, rid, path.slice(12));
      if (path.startsWith("/api/deals/")         && method === "PUT")  return await dealUpdate(request, env, rid, path.slice(12));

      // Outreach
      if (path === "/api/outreach/send"          && method === "POST") return await outreachSend(request, env, rid);
      if (path === "/api/outreach/sequence"      && method === "POST") return await outreachCreateSequence(request, env, rid);
      if (path === "/api/outreach/log"           && method === "GET")  return await outreachLog(request, env, rid);

      // Revenue dashboard
      if (path === "/api/revenue/dashboard"      && method === "GET")  return await revenueDashboard(request, env, rid);
      if (path === "/api/revenue/mrr"            && method === "GET")  return await revenueMRR(request, env, rid);
      if (path === "/api/revenue/scale-model"    && method === "GET")  return await revenueScaleModel(request, env, rid);

      // Enterprise onboarding
      if (path === "/api/enterprise/onboard"     && method === "POST") return await enterpriseOnboard(request, env, rid);
      if (path === "/api/enterprise/contract"    && method === "POST") return await enterpriseContractTrigger(request, env, rid);

      // Automation
      if (path === "/api/automation/trigger"     && method === "POST") return await automationTrigger(request, env, rid);
      if (path === "/api/automation/sequences"   && method === "GET")  return await listSequences(request, env, rid);

      // ── Phase 2: Commercial Operations routes ──────────────────────────────
      const commercialResult = await dispatchCommercialRoutes(path, method, request, env, rid);
      if (commercialResult) return commercialResult;

      return json({ error: "not_found", path }, 404);
    } catch (e) {
      return json({ error: "internal_error", message: e.message, rid }, 500);
    }
}

// =============================================================================
// PHASE 2 — LEAD CAPTURE + TRIAL
// =============================================================================

async function handleLeadCapture(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const email   = sanitizeEmail(body.email);
  const company = (body.company || "").slice(0, 128);
  const role    = (body.role    || "").slice(0, 64);
  const context = (body.context || "generic").slice(0, 64);
  const source  = (body.source  || "web").slice(0, 64);

  if (!email) return json({ error: "invalid_email" }, 400);

  const ts      = new Date().toISOString();
  const leadId  = "lead_" + await sha256prefix(email, 12);

  const lead = {
    id: leadId, email, company, role, context, source,
    status: "new", score: scoreLeadInitial(company, role),
    captured_at: ts, last_activity: ts,
    country: request.headers.get("cf-ipcountry") || "unknown",
    ip_hash: await sha256prefix(request.headers.get("cf-connecting-ip") || "x", 8),
    sequence_step: 0,
    tags: inferTags(company, role, context),
    notes: "",
  };

  // Write to D1 CRM database
  try {
    await env.CRM_DB?.prepare(
      `INSERT OR IGNORE INTO leads
       (id, email, company, role, context, source, status, score, captured_at, last_activity, country, tags)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      lead.id, lead.email, lead.company, lead.role, lead.context, lead.source,
      lead.status, lead.score, lead.captured_at, lead.last_activity,
      lead.country, JSON.stringify(lead.tags)
    ).run();

    // Queue welcome email
    await queueEmail(env, {
      to: email, template: "lead_welcome",
      vars: { company, role, context },
      send_at: new Date(Date.now() + 300000).toISOString(), // 5min delay
    });

    // Notify sales Slack on high-score lead
    if (lead.score >= 70) {
      await slackNotify(env, `🔥 HIGH-VALUE LEAD | ${email} | ${company} | ${role} | score: ${lead.score}`);
    }

    await trackEvent(env, "lead_captured", { lead_id: leadId, score: lead.score, source });
  } catch (e) {
    // KV fallback if D1 unavailable
    await env.REVENUE_CRM_KV?.put(`lead:${leadId}`, JSON.stringify(lead), { expirationTtl: 86400 * 90 });
  }

  return json({
    status:    "captured",
    lead_id:   leadId,
    score:     lead.score,
    upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html?plan=pro",
    // DEPRECATED 2026-09-24 (remove after the next major release): kept for
    // response-shape compatibility only. /trial never existed (404) and the
    // contract offers no free trial, so it now points at the pricing page.
    trial_url: "https://intel.cyberdudebivash.com/pricing.html",
    message:   "Thanks, you're on the list. Check your email.",
    request_id: rid,
  });
}

// Mirrors TRIAL_DISCONTINUED_BODY in intel-gateway/src/revenue-enforcement.js
// (separate Worker bundle, so it cannot import it).
const TRIAL_DISCONTINUED_BODY = Object.freeze({
  error:       "trial_discontinued",
  message:     "Sentinel APEX does not offer a free trial. The Free tier is available without payment, and paid plans activate immediately after checkout.",
  free_tier:   "https://intel.cyberdudebivash.com/pricing.html",
  pricing_url: "https://intel.cyberdudebivash.com/pricing.html",
  upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html?plan=pro",
  deprecated:  "2026-09-24",
});

// DEPRECATED 2026-09-24: unrouted (see /api/leads/trial above).
async function handleTrialRequest(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const email   = sanitizeEmail(body.email);
  const name    = (body.name    || "").slice(0, 128);
  const company = (body.company || "").slice(0, 128);
  if (!email) return json({ error: "invalid_email" }, 400);

  // Anti-automation: this endpoint mints a live 7-day PRO-tier key from just
  // an email with no auth, so it's directly scriptable with disposable
  // addresses. Fixed-window per-IP cap (hashed, not stored raw) — cheap and
  // proportionate; a full sliding-window limiter belongs in intel-gateway's
  // shared RATE_LIMIT_KV, not duplicated per-Worker for a Medium-severity gap.
  const ipHash = await sha256prefix(request.headers.get("cf-connecting-ip") || "unknown", 16);
  const rlKey  = `trial_rl:${ipHash}:${new Date().toISOString().slice(0, 13)}`; // hour bucket
  const rlCount = parseInt((await env.REVENUE_CRM_KV?.get(rlKey)) || "0", 10);
  if (rlCount >= 3) {
    return json({ error: "rate_limited", message: "Too many trial requests from this network. Try again later." }, 429);
  }
  await env.REVENUE_CRM_KV?.put(rlKey, String(rlCount + 1), { expirationTtl: 3600 });

  const trialId  = "trial_" + await sha256prefix(email, 10);
  const existing = await env.REVENUE_CRM_KV?.get(`trial:${trialId}`);

  if (existing) {
    const t = JSON.parse(existing);
    if (t.activated && !t.converted) {
      return json({
        error:       "trial_exists",
        expires_at:  t.expires_at,
        api_key:     "[shown at activation only]",
        upgrade_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro",
        message:     "Trial already active. Upgrade to Pro to continue.",
      }, 409);
    }
  }

  const raw       = crypto.getRandomValues(new Uint8Array(20));
  const apiKey    = "cdb_pro_trial_" + [...raw].map(b=>b.toString(16).padStart(2,"0")).join("");
  const expiresAt = new Date(Date.now() + 7 * 86400000).toISOString();

  const trialRecord = {
    id: trialId, email, name, company,
    api_key:    apiKey,
    activated:  true,
    activated_at: new Date().toISOString(),
    expires_at: expiresAt,
    converted:  false,
    nudge_sent_3d: false,
    nudge_sent_1d: false,
    nudge_sent_0d: false,
  };

  await env.REVENUE_CRM_KV?.put(`trial:${trialId}`, JSON.stringify(trialRecord), { expirationTtl: 8 * 86400 });

  // Register API key in the gateway's live auth store (API_KEYS_KV), matching
  // provisionCustomer()'s exact write shape — same binding, full raw key as
  // the lookup key, uppercase TIERS value ("PRO", not "premium") — since
  // that's what intel-gateway's resolveAuth() actually reads
  // (env.API_KEYS_KV.get(raw) then TIERS[record.tier] || TIERS.PRO). The
  // previous pending_apikey:{last12} write went to REVENUE_CRM_KV under a
  // key shape nothing ever read, so every trial silently never worked.
  if (env.API_KEYS_KV) {
    await env.API_KEYS_KV.put(apiKey, JSON.stringify({
      key: apiKey, tier: "PRO", customer_id: trialId, email,
      source: "trial", created_at: new Date().toISOString(), expires_at: expiresAt,
      payment_metadata: { trial: true },
    }));
  }

  await queueEmail(env, {
    to: email, template: "trial_welcome",
    vars: { name, company, api_key: apiKey, expires_at: expiresAt },
    send_at: new Date().toISOString(),
  });

  // Update lead score in CRM
  try {
    await env.CRM_DB?.prepare(
      `UPDATE leads SET status='trial', score=score+30, last_activity=? WHERE email=?`
    ).bind(new Date().toISOString(), email).run();
  } catch {}

  await slackNotify(env, `🚀 TRIAL ACTIVATED | ${email} | ${company} | expires: ${expiresAt.slice(0,10)}`);
  await trackEvent(env, "trial_activated", { email_hash: trialId, company });

  return json({
    status:      "trial_activated",
    api_key:     apiKey,
    tier:        "pro",
    expires_at:  expiresAt,
    docs:        "https://intel.cyberdudebivash.com/docs",
    upgrade_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro",
    features: [
      "500 req/min API access",
      "Full IOC arrays on every threat",
      "Full AI analysis (kill chain, actor fingerprint)",
      "5,000 API calls/day",
      "Threat alerts with attribution",
    ],
    request_id:  rid,
  });
}

// =============================================================================
// PHASE 3 — OUTBOUND ENGINE
// =============================================================================

async function outreachSend(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const { to, template, vars: tplVars, delay_minutes } = body;
  if (!to || !template) return json({ error: "missing_fields" }, 400);

  const sendAt = delay_minutes
    ? new Date(Date.now() + delay_minutes * 60000).toISOString()
    : new Date().toISOString();

  const msgId = await queueEmail(env, { to, template, vars: tplVars || {}, send_at: sendAt });

  // Log outreach attempt in D1
  try {
    await env.CRM_DB?.prepare(
      `INSERT INTO outreach_log (id, lead_email, template, scheduled_at, status)
       VALUES (?, ?, ?, ?, 'queued')`
    ).bind(msgId, to, template, sendAt).run();
  } catch {}

  return json({ status: "queued", message_id: msgId, send_at: sendAt, request_id: rid });
}

async function outreachCreateSequence(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const { lead_email, sequence_name } = body;
  if (!lead_email || !sequence_name) return json({ error: "missing_fields" }, 400);

  const sequences = EMAIL_SEQUENCES[sequence_name];
  if (!sequences) return json({ error: "unknown_sequence", available: Object.keys(EMAIL_SEQUENCES) }, 400);

  const now = Date.now();
  const queued = [];
  for (const step of sequences) {
    const sendAt = new Date(now + step.delay_hours * 3600000).toISOString();
    const msgId  = await queueEmail(env, {
      to: lead_email, template: step.template,
      vars: { ...step.vars, ...body.vars },
      send_at: sendAt,
    });
    queued.push({ step: step.name, template: step.template, send_at: sendAt, message_id: msgId });
  }

  return json({ status: "sequence_created", sequence_name, steps_queued: queued.length, steps: queued, request_id: rid });
}

async function outreachLog(request, env, rid) {
  try {
    const result = await env.CRM_DB?.prepare(
      `SELECT * FROM outreach_log ORDER BY scheduled_at DESC LIMIT 100`
    ).all();
    return json({ logs: result?.results || [], request_id: rid });
  } catch {
    return json({ logs: [], error: "db_unavailable", request_id: rid });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL SEQUENCES — Cold outbound + nurture + trial conversion
// ─────────────────────────────────────────────────────────────────────────────
const EMAIL_SEQUENCES = {
  // Cold outbound for enterprise prospects
  "enterprise_cold": [
    { name: "initial_touch",   delay_hours: 0,   template: "cold_enterprise_v1",   vars: {} },
    { name: "follow_up_1",     delay_hours: 72,  template: "cold_enterprise_fu1",  vars: {} },
    { name: "value_add",       delay_hours: 144, template: "cold_enterprise_value", vars: {} },
    { name: "follow_up_2",     delay_hours: 240, template: "cold_enterprise_fu2",  vars: {} },
    { name: "breakup",         delay_hours: 336, template: "cold_enterprise_break", vars: {} },
  ],
  // Trial user conversion sequence
  "trial_conversion": [
    { name: "trial_day1",      delay_hours: 0,   template: "trial_welcome",        vars: {} },
    { name: "trial_day3_nudge",delay_hours: 72,  template: "trial_nudge_d3",       vars: {} },
    { name: "trial_day6_urgency",delay_hours:144,template: "trial_expiry_d1",      vars: {} },
    { name: "trial_day7_final",delay_hours: 168, template: "trial_expired",        vars: {} },
  ],
  // Pro user → Enterprise upsell
  "pro_upsell": [
    { name: "upsell_intro",    delay_hours: 0,   template: "pro_enterprise_upsell",vars: {} },
    { name: "upsell_followup", delay_hours: 96,  template: "pro_enterprise_fu",    vars: {} },
  ],
  // Lead welcome + nurture
  "lead_nurture": [
    { name: "welcome",         delay_hours: 0,   template: "lead_welcome",         vars: {} },
    { name: "value_email",     delay_hours: 48,  template: "lead_value_d2",        vars: {} },
    { name: "trial_offer",     delay_hours: 120, template: "lead_trial_offer",     vars: {} },
  ],
};

// =============================================================================
// PHASE 4 — ENTERPRISE SALES SYSTEM
// =============================================================================

async function handleDemoRequest(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const { email, name, company, team_size, use_case } = body;
  if (!email || !company) return json({ error: "missing_fields" }, 400);

  const demoId = "demo_" + crypto.randomUUID().replace(/-/g, "");
  const demo = {
    id: demoId, email, name, company, team_size,
    use_case, requested_at: new Date().toISOString(), status: "pending",
    demo_link: `https://intel.cyberdudebivash.com/demo/live?token=${demoId}`,
  };

  await env.REVENUE_CRM_KV?.put(`demo:${demoId}`, JSON.stringify(demo), { expirationTtl: 86400 * 30 });

  // Auto-create deal in pipeline
  await createDealInternal(env, {
    lead_email:     email,
    company,
    deal_name:      `${company} — Enterprise Demo`,
    stage:          "demo_scheduled",
    value_inr:      ENGINE.DEAL_VALUES_INR.enterprise_monthly,
    plan:           "enterprise",
    close_probability: 0.30,
    notes:          `Use case: ${use_case || "not specified"}. Team: ${team_size || "unknown"}`,
    source:         "demo_request",
  });

  await slackNotify(env, `📅 DEMO REQUEST | ${company} (${email}) | use case: ${use_case} | team: ${team_size}\n🔗 Demo link: ${demo.demo_link}`);

  // Queue enterprise sequence
  await outreachQueueDirect(env, email, "enterprise_cold", { company, name, demo_link: demo.demo_link });

  return json({
    status:      "demo_scheduled",
    demo_id:     demoId,
    demo_link:   demo.demo_link,
    message:     "Enterprise demo request received. Our team will confirm within 24 hours.",
    request_id:  rid,
  });
}

async function handleLiveDemoEndpoint(request, env, rid) {
  // Returns live threat feed snapshot for demo — no auth required (token-gated)
  const token = new URL(request.url).searchParams.get("token");
  if (!token?.startsWith("demo_")) {
    return json({ error: "invalid_demo_token" }, 401);
  }

  const demo = await env.REVENUE_CRM_KV?.get(`demo:${token}`, { type: "json" });
  if (!demo) return json({ error: "demo_not_found" }, 404);

  // Fetch from main platform
  let threatData = [];
  try {
    const r = await fetch("https://intel.cyberdudebivash.com/api/preview");
    const d = await r.json();
    threatData = (d.data?.reports || []).slice(0, 5);
  } catch { threatData = DEMO_FALLBACK_THREATS; }

  return json({
    status:       "demo_active",
    demo_for:     demo.company,
    platform:     "CYBERDUDEBIVASH® SENTINEL APEX",
    version:      "183.0",
    demo_features: ["Real-time threat intelligence", "AI-powered IOC extraction", "STIX 2.1 export", "SIEM integration", "Actor attribution"],
    sample_threats: threatData,
    // P0 2026-09-24: derived from TIERS/commercial-contract.json. Previously
    // claimed unlimited_api (forbidden claim; ENTERPRISE is capped),
    // white_label:true (MSSP-only in the contract) and a "Dedicated security
    // engineer" (contract: email and chat support, 4h response).
    enterprise_benefits: {
      requests_per_day:   TIERS.ENTERPRISE.req_day,
      requests_per_minute: TIERS.ENTERPRISE.req_min,
      siem_push:          true,
      stix_bundles:       true,
      uptime_sla:         "99.9%",
      support:            "Email and chat support, 4h response",
      custom_feeds:       true,
      white_label:        false,
      onprem_option:      "Contact sales",
    },
    upgrade_url:   "https://intel.cyberdudebivash.com/upgrade?plan=enterprise",
    contact_sales: "enterprise@cyberdudebivash.com",
    request_id:    rid,
  });
}

// ─── Deal Management ──────────────────────────────────────────────────────────

async function dealCreate(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const deal = await createDealInternal(env, body);
  return json({ status: "created", deal, request_id: rid });
}

async function createDealInternal(env, data) {
  const dealId = "deal_" + await sha256prefix(data.lead_email + Date.now(), 10);
  const deal = {
    id:                 dealId,
    lead_email:         data.lead_email || "",
    company:            data.company    || "",
    deal_name:          data.deal_name  || "",
    stage:              data.stage      || "new",
    plan:               data.plan       || "enterprise",
    value_inr:          data.value_inr  || ENGINE.DEAL_VALUES_INR.enterprise_monthly,
    close_probability:  data.close_probability || 0.10,
    expected_close:     data.expected_close || new Date(Date.now() + 30 * 86400000).toISOString().slice(0,10),
    source:             data.source     || "inbound",
    notes:              data.notes      || "",
    created_at:         new Date().toISOString(),
    updated_at:         new Date().toISOString(),
    owner:              "sales@cyberdudebivash.com",
    weighted_value_inr: Math.floor((data.value_inr || ENGINE.DEAL_VALUES_INR.enterprise_monthly) * (data.close_probability || 0.10)),
  };

  try {
    await env.CRM_DB?.prepare(
      `INSERT INTO deals
       (id, lead_email, company, deal_name, stage, plan, value_inr, close_probability,
        expected_close, source, notes, created_at, updated_at, weighted_value_inr)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      deal.id, deal.lead_email, deal.company, deal.deal_name, deal.stage,
      deal.plan, deal.value_inr, deal.close_probability, deal.expected_close,
      deal.source, deal.notes, deal.created_at, deal.updated_at, deal.weighted_value_inr
    ).run();
  } catch {
    await env.REVENUE_CRM_KV?.put(`deal:${dealId}`, JSON.stringify(deal), { expirationTtl: 86400 * 180 });
  }

  return deal;
}

async function dealUpdate(request, env, rid, dealId) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const updates = [];
  const values  = [];

  if (body.stage)             { updates.push("stage=?");             values.push(body.stage); }
  if (body.close_probability) { updates.push("close_probability=?"); values.push(body.close_probability); }
  if (body.value_inr)         { updates.push("value_inr=?");         values.push(body.value_inr); }
  if (body.notes)             { updates.push("notes=?");             values.push(body.notes); }
  if (body.expected_close)    { updates.push("expected_close=?");    values.push(body.expected_close); }
  updates.push("updated_at=?"); values.push(new Date().toISOString());
  values.push(dealId);

  try {
    await env.CRM_DB?.prepare(
      `UPDATE deals SET ${updates.join(", ")} WHERE id=?`
    ).bind(...values).run();

    // If deal closed, fire contract trigger + billing activation
    if (body.stage === "closed_won") {
      await enterpriseClosingSequence(env, dealId, body);
    }
  } catch (e) {
    return json({ error: "update_failed", message: e.message }, 500);
  }

  return json({ status: "updated", deal_id: dealId, request_id: rid });
}

async function dealsList(request, env, rid) {
  try {
    const result = await env.CRM_DB?.prepare(
      `SELECT * FROM deals ORDER BY created_at DESC LIMIT 100`
    ).all();
    const deals  = result?.results || [];
    const totalWeighted = deals.reduce((s, d) => s + (d.weighted_value_inr || 0), 0);
    return json({ deals, total_pipeline_inr: totalWeighted, count: deals.length, request_id: rid });
  } catch {
    return json({ deals: [], error: "db_unavailable", request_id: rid });
  }
}

async function dealGet(request, env, rid, dealId) {
  try {
    const result = await env.CRM_DB?.prepare(
      `SELECT d.*, l.email, l.company, l.role FROM deals d
       LEFT JOIN leads l ON d.lead_email = l.email
       WHERE d.id = ?`
    ).bind(dealId).first();
    if (!result) return json({ error: "not_found" }, 404);
    return json({ deal: result, request_id: rid });
  } catch {
    return json({ error: "db_unavailable" }, 500);
  }
}

// ─── Enterprise Closing Sequence ──────────────────────────────────────────────
async function enterpriseClosingSequence(env, dealId, data) {
  // 1. Send contract trigger email
  if (data.lead_email) {
    await queueEmail(env, {
      to: data.lead_email, template: "enterprise_contract",
      vars: { deal_id: dealId, company: data.company, plan: data.plan },
      send_at: new Date().toISOString(),
    });
  }

  // 2. Notify sales team
  await slackNotify(env, `🏆 DEAL CLOSED WON | ${data.company} | ${data.plan} | ₹${data.value_inr || ENGINE.DEAL_VALUES_INR.enterprise_monthly}/mo | deal: ${dealId}`);

  // 3. Queue onboarding sequence
  if (data.lead_email) {
    await outreachQueueDirect(env, data.lead_email, "enterprise_cold", { company: data.company });
  }

  // 4. Update MRR counter
  await trackEvent(env, "deal_closed_won", { deal_id: dealId, value_inr: data.value_inr || ENGINE.DEAL_VALUES_INR.enterprise_monthly });
}

// Enterprise onboard — POST /api/enterprise/onboard
async function enterpriseOnboard(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const { email, name, company, deal_id } = body;
  if (!email || !company) return json({ error: "missing_fields" }, 400);

  const onboardSteps = [
    { step: 1, action: "api_key_creation",   description: "Enterprise API key issued", status: "pending" },
    { step: 2, action: "siem_setup",          description: "SIEM webhook URL configured", status: "pending" },
    { step: 3, action: "ip_allowlist",        description: "IP allowlist configured", status: "pending" },
    { step: 4, action: "slack_integration",   description: "Slack threat channel connected", status: "pending" },
    { step: 5, action: "kickoff_call",        description: "Kickoff call scheduled", status: "pending" },
    { step: 6, action: "sla_agreement",       description: "SLA document signed", status: "pending" },
  ];

  await queueEmail(env, {
    to: email, template: "enterprise_onboard",
    vars: { name, company, onboard_steps: JSON.stringify(onboardSteps), deal_id },
    send_at: new Date().toISOString(),
  });

  await slackNotify(env, `🎉 ENTERPRISE ONBOARDING STARTED | ${company} (${email}) | deal: ${deal_id}`);

  return json({
    status:        "onboarding_initiated",
    company,
    onboard_steps: onboardSteps,
    support_email: "enterprise@cyberdudebivash.com",
    sla:           "99.9% uptime, 4-hour response SLA",
    dedicated_slack: "Will be created within 24 hours",
    request_id:    rid,
  });
}

async function enterpriseContractTrigger(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const { email, company, plan, deal_id, value_inr } = body;
  if (!email) return json({ error: "missing_fields" }, 400);

  // Generate contract reference
  const contractRef = `CDB-ENT-${new Date().getFullYear()}-${await sha256prefix(email, 6).then(h=>h.toUpperCase())}`;

  await queueEmail(env, {
    to: email, template: "enterprise_contract",
    vars: { company, plan, deal_id, contract_ref: contractRef, value_inr: value_inr || ENGINE.DEAL_VALUES_INR.enterprise_monthly },
    send_at: new Date().toISOString(),
  });

  return json({
    status:       "contract_triggered",
    contract_ref: contractRef,
    message:      "Contract document sent to " + email,
    next_steps:   ["Review contract", "Sign via DocuSign", "Billing activation"],
    request_id:   rid,
  });
}

// =============================================================================
// PHASE 5 — REVENUE AUTOMATION ENGINE
// =============================================================================

// Real defect found and fixed while wiring intel-gateway's daily-quota alert
// into this endpoint: /api/automation/trigger had NO authentication -- any
// external caller could POST an arbitrary `email` and fire any of the seven
// trigger cases below, using this platform's own SendGrid sending
// reputation/domain to relay email to any address, for free, with no rate
// limit. The only file that ever called it, revenue-crm/frontend-injection.js
// ("Inject this as a <script> block in index.html"), is never actually
// included in any real page (confirmed: zero matches for it across every
// .html file in this repo) -- so there was no live legitimate caller whose
// behavior this breaks. Gated the same way every other admin-only route in
// this file already is (isAdmin(), X-Admin-Secret / REVENUE_ADMIN_SECRET) --
// intel-gateway's new caller sends that header; nothing else has ever needed
// unauthenticated access to this route.
async function automationTrigger(request, env, rid) {
  if (!(await isAdmin(request, env))) return json({ error: "unauthorized" }, 401);

  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const { trigger, email, context } = body;
  if (!trigger) return json({ error: "missing_trigger" }, 400);

  switch (trigger) {
    case "usage_80pct":
      await queueEmail(env, {
        to: email, template: "usage_approaching_limit",
        vars: { context, upgrade_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro" },
        send_at: new Date().toISOString(),
      });
      break;
    case "usage_100pct":
      await queueEmail(env, {
        to: email, template: "usage_limit_hit",
        vars: { upgrade_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro" },
        send_at: new Date().toISOString(),
      });
      break;
    case "trial_d3":
      await queueEmail(env, {
        to: email, template: "trial_nudge_d3",
        vars: { context, upgrade_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro" },
        send_at: new Date().toISOString(),
      });
      break;
    case "trial_d6":
      await queueEmail(env, {
        to: email, template: "trial_expiry_d1",
        vars: { upgrade_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro" },
        send_at: new Date().toISOString(),
      });
      break;
    case "trial_expired":
      await queueEmail(env, {
        to: email, template: "trial_expired",
        vars: { upgrade_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro" },
        send_at: new Date().toISOString(),
      });
      break;
    case "ioc_blocked":
      await queueEmail(env, {
        to: email, template: "ioc_upgrade_prompt",
        vars: { context },
        send_at: new Date(Date.now() + 1800000).toISOString(), // 30min
      });
      break;
    case "pro_to_enterprise":
      await queueEmail(env, {
        to: email, template: "pro_enterprise_upsell",
        vars: { context },
        send_at: new Date().toISOString(),
      });
      break;
    default:
      return json({ error: "unknown_trigger", trigger }, 400);
  }

  await trackEvent(env, `automation:${trigger}`, { email: await sha256prefix(email, 8), context });
  return json({ status: "triggered", trigger, request_id: rid });
}

// ── Cron: Daily outreach send ──────────────────────────────────────────────────
async function runDailyOutreach(env) {
  const now = new Date().toISOString();
  try {
    const queue = await env.EMAIL_QUEUE_KV?.list({ prefix: "email:" });
    const toSend = [];
    for (const key of (queue?.keys || [])) {
      const msg = await env.EMAIL_QUEUE_KV?.get(key.name, { type: "json" });
      if (msg && msg.send_at <= now && msg.status === "queued") {
        toSend.push({ key: key.name, msg });
      }
    }
    for (const { key, msg } of toSend.slice(0, 50)) {
      await sendEmailViaProvider(env, msg);
      msg.status = "sent";
      msg.sent_at = now;
      await env.EMAIL_QUEUE_KV?.put(key, JSON.stringify(msg), { expirationTtl: 86400 * 7 });
    }
  } catch {}
}

// ── Cron: Trial nudges + follow-ups ───────────────────────────────────────────
async function runFollowUps(env) {
  try {
    const trials = await env.REVENUE_CRM_KV?.list({ prefix: "trial:" });
    const now    = Date.now();
    for (const key of (trials?.keys || [])) {
      const trial = await env.REVENUE_CRM_KV?.get(key.name, { type: "json" });
      if (!trial || trial.converted) continue;
      const expiresAt = new Date(trial.expires_at).getTime();
      const daysLeft  = (expiresAt - now) / 86400000;

      if (daysLeft <= 1 && !trial.nudge_sent_1d) {
        await queueEmail(env, { to: trial.email, template: "trial_expiry_d1", vars: { name: trial.name }, send_at: new Date().toISOString() });
        trial.nudge_sent_1d = true;
        await env.REVENUE_CRM_KV?.put(key.name, JSON.stringify(trial), { expirationTtl: 86400 * 8 });
      } else if (daysLeft <= 4 && !trial.nudge_sent_3d) {
        await queueEmail(env, { to: trial.email, template: "trial_nudge_d3", vars: { name: trial.name }, send_at: new Date().toISOString() });
        trial.nudge_sent_3d = true;
        await env.REVENUE_CRM_KV?.put(key.name, JSON.stringify(trial), { expirationTtl: 86400 * 8 });
      } else if (daysLeft <= 0 && !trial.nudge_sent_0d) {
        await queueEmail(env, { to: trial.email, template: "trial_expired", vars: { name: trial.name }, send_at: new Date().toISOString() });
        trial.nudge_sent_0d = true;
        await env.REVENUE_CRM_KV?.put(key.name, JSON.stringify(trial), { expirationTtl: 86400 * 8 });
      }
    }
  } catch {}
}

// ── Cron: Weekly threat digest to Pro/Enterprise subscribers ─────────────────
async function runWeeklyDigest(env) {
  try {
    const subs = await env.REVENUE_CRM_KV?.list({ prefix: "subscriber:" });
    let threats = [];
    try {
      const r = await fetch("https://intel.cyberdudebivash.com/api/preview");
      const d = await r.json();
      threats = (d.data?.reports || []).slice(0, 10);
    } catch {}
    for (const key of (subs?.keys || []).slice(0, 500)) {
      const sub = await env.REVENUE_CRM_KV?.get(key.name, { type: "json" });
      if (!sub?.email) continue;
      await queueEmail(env, {
        to: sub.email, template: "weekly_digest",
        vars: { threats: JSON.stringify(threats), week: getWeekLabel() },
        send_at: new Date().toISOString(),
      });
    }
  } catch {}
}

// =============================================================================
// PHASE 6 — ₹10L SCALE MODEL
// =============================================================================

async function revenueScaleModel(request, env, rid) {
  const TARGET_INR = ENGINE.TARGET_MRR_INR; // ₹10,00,000

  // ── Funnel Math ───────────────────────────────────────────────────────────
  const model = {
    target_mrr_inr:  TARGET_INR,
    target_mrr_usd:  Math.floor(TARGET_INR / 83),

    // Revenue mix: Enterprise drives 70%, Pro 30%
    revenue_mix: {
      enterprise: { pct: 0.70, target_inr: 700000, target_usd: 8434 },
      pro:        { pct: 0.30, target_inr: 300000, target_usd: 3614 },
    },

    // Deal counts needed
    deals_required: {
      enterprise_monthly: { deals: Math.ceil(700000 / ENGINE.DEAL_VALUES_INR.enterprise_monthly), value_inr: ENGINE.DEAL_VALUES_INR.enterprise_monthly },
      pro_monthly:        { deals: Math.ceil(300000 / ENGINE.DEAL_VALUES_INR.pro_monthly),        value_inr: ENGINE.DEAL_VALUES_INR.pro_monthly        },
    },

    // Funnel assumptions (industry benchmarks for PLG SaaS)
    funnel: {
      cold_outreach_to_reply:      0.08,  // 8%
      reply_to_demo:               0.40,  // 40%
      demo_to_trial:               0.60,  // 60%
      trial_to_paid:               0.18,  // 18%
      inbound_lead_to_trial:       0.15,  // 15%
      inbound_trial_to_paid:       0.22,  // 22%
    },

    // Outreach volume required for 47 enterprise deals
    outreach_volume: {
      enterprise_deals_needed:     Math.ceil(700000 / ENGINE.DEAL_VALUES_INR.enterprise_monthly),
      // Back-calc from funnel
      demos_needed:                Math.ceil(Math.ceil(700000/ENGINE.DEAL_VALUES_INR.enterprise_monthly) / 0.18 / 0.60),
      replies_needed:              Math.ceil(Math.ceil(700000/ENGINE.DEAL_VALUES_INR.enterprise_monthly) / 0.18 / 0.60 / 0.40),
      cold_emails_per_month:       Math.ceil(Math.ceil(700000/ENGINE.DEAL_VALUES_INR.enterprise_monthly) / 0.18 / 0.60 / 0.40 / 0.08),
      cold_emails_per_day:         Math.ceil(Math.ceil(700000/ENGINE.DEAL_VALUES_INR.enterprise_monthly) / 0.18 / 0.60 / 0.40 / 0.08 / 22),
    },

    // Pro tier — driven by PLG (product-led growth)
    pro_plg: {
      pro_subs_needed:             Math.ceil(300000 / ENGINE.DEAL_VALUES_INR.pro_monthly),
      trials_needed_per_month:     Math.ceil(Math.ceil(300000/ENGINE.DEAL_VALUES_INR.pro_monthly) / 0.22),
      leads_needed_per_month:      Math.ceil(Math.ceil(300000/ENGINE.DEAL_VALUES_INR.pro_monthly) / 0.22 / 0.15),
      website_visitors_needed:     Math.ceil(Math.ceil(300000/ENGINE.DEAL_VALUES_INR.pro_monthly) / 0.22 / 0.15 / 0.04),
    },

    // Current CRM wiring
    crm_connected: true,
    outbound_connected: true,
    trial_system_connected: true,
    automation_connected: true,
  };

  // Annotate
  model.narrative = {
    enterprise: `Need ${model.deals_required.enterprise_monthly.deals} enterprise deals @ ₹${ENGINE.DEAL_VALUES_INR.enterprise_monthly}/mo each. Requires ${model.outreach_volume.cold_emails_per_day} cold emails/day, targeting CISOs, VPs of Security, SOC leads.`,
    pro:        `Need ${model.deals_required.pro_monthly.deals} Pro subscribers @ ₹${ENGINE.DEAL_VALUES_INR.pro_monthly}/mo. Driven by trial system — ${model.pro_plg.leads_needed_per_month} leads/month needed.`,
    combined:   `Total monthly outreach: ${model.outreach_volume.cold_emails_per_month} cold emails + ${model.pro_plg.leads_needed_per_month} inbound leads via PLG.`,
  };

  return json({ status: "ok", scale_model: model, request_id: rid });
}

async function revenueMRR(request, env, rid) {
  try {
    const result = await env.CRM_DB?.prepare(
      `SELECT stage, plan, SUM(value_inr) as total, COUNT(*) as count
       FROM deals WHERE stage='closed_won' GROUP BY stage, plan`
    ).all();
    const rows = result?.results || [];
    const mrr  = rows.reduce((s, r) => s + (r.total || 0), 0);
    const pipeline = await env.CRM_DB?.prepare(
      `SELECT SUM(weighted_value_inr) as weighted FROM deals WHERE stage NOT IN ('closed_won','closed_lost')`
    ).first();

    return json({
      mrr_inr:          mrr,
      mrr_usd:          Math.floor(mrr / 83),
      target_inr:       ENGINE.TARGET_MRR_INR,
      target_pct:       Math.floor((mrr / ENGINE.TARGET_MRR_INR) * 100),
      pipeline_inr:     pipeline?.weighted || 0,
      by_plan:          rows,
      request_id:       rid,
    });
  } catch {
    return json({ mrr_inr: 0, target_inr: ENGINE.TARGET_MRR_INR, error: "db_unavailable", request_id: rid });
  }
}

async function revenueDashboard(request, env, rid) {
  const [mrr, deals, leads, events] = await Promise.all([
    revenueMRR(request, env, rid).then(r => r.json?.() || {}),
    dealsList(request, env, rid).then(r => r.json?.() || {}),
    crmListLeads(request, env, rid).then(r => r.json?.() || {}),
    env.REVENUE_CRM_KV?.get(`revenue:events:${new Date().toISOString().slice(0,10)}`, { type: "json" }) || {},
  ]);

  return json({
    status:     "ok",
    dashboard: { mrr, pipeline: deals, leads, events },
    request_id: rid,
  });
}

// =============================================================================
// CRM — LEAD MANAGEMENT
// =============================================================================

async function crmListLeads(request, env, rid) {
  const url    = new URL(request.url);
  const status = url.searchParams.get("status");
  const limit  = parseInt(url.searchParams.get("limit") || "50");

  try {
    const sql = status
      ? `SELECT * FROM leads WHERE status=? ORDER BY score DESC, captured_at DESC LIMIT ?`
      : `SELECT * FROM leads ORDER BY score DESC, captured_at DESC LIMIT ?`;
    const result = await env.CRM_DB?.prepare(sql).bind(...(status ? [status, limit] : [limit])).all();
    return json({ leads: result?.results || [], request_id: rid });
  } catch {
    return json({ leads: [], error: "db_unavailable", request_id: rid });
  }
}

async function crmCreateLead(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const email = sanitizeEmail(body.email);
  if (!email) return json({ error: "invalid_email" }, 400);

  const leadId = "lead_" + await sha256prefix(email, 12);
  const ts     = new Date().toISOString();

  try {
    await env.CRM_DB?.prepare(
      `INSERT OR REPLACE INTO leads
       (id, email, company, role, context, source, status, score, captured_at, last_activity, country, tags, notes, linkedin)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      leadId, email, body.company||"", body.role||"", body.context||"", body.source||"manual",
      body.status||"new", body.score || scoreLeadInitial(body.company, body.role),
      ts, ts, body.country||"", JSON.stringify(body.tags||[]), body.notes||"", body.linkedin||""
    ).run();
  } catch (e) {
    return json({ error: "db_error", message: e.message }, 500);
  }

  return json({ status: "created", lead_id: leadId, request_id: rid });
}

async function crmGetLead(request, env, rid, leadId) {
  try {
    const lead = await env.CRM_DB?.prepare(`SELECT * FROM leads WHERE id=?`).bind(leadId).first();
    if (!lead) return json({ error: "not_found" }, 404);
    const deals = await env.CRM_DB?.prepare(`SELECT * FROM deals WHERE lead_email=?`).bind(lead.email).all();
    const log   = await env.CRM_DB?.prepare(`SELECT * FROM outreach_log WHERE lead_email=? ORDER BY scheduled_at DESC LIMIT 20`).bind(lead.email).all();
    return json({ lead, deals: deals?.results || [], outreach: log?.results || [], request_id: rid });
  } catch {
    return json({ error: "db_unavailable" }, 500);
  }
}

async function crmUpdateLead(request, env, rid, leadId) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const fields = ["company","role","status","score","notes","linkedin","tags"];
  const updates = []; const vals = [];
  for (const f of fields) {
    if (body[f] !== undefined) {
      updates.push(`${f}=?`);
      vals.push(f === "tags" ? JSON.stringify(body[f]) : body[f]);
    }
  }
  if (!updates.length) return json({ error: "no_fields" }, 400);
  updates.push("last_activity=?"); vals.push(new Date().toISOString());
  vals.push(leadId);

  try {
    await env.CRM_DB?.prepare(`UPDATE leads SET ${updates.join(",")} WHERE id=?`).bind(...vals).run();
    return json({ status: "updated", lead_id: leadId, request_id: rid });
  } catch (e) {
    return json({ error: "update_failed", message: e.message }, 500);
  }
}

async function listSequences(request, env, rid) {
  return json({ sequences: Object.keys(EMAIL_SEQUENCES).map(name => ({
    name, steps: EMAIL_SEQUENCES[name].length,
    templates: EMAIL_SEQUENCES[name].map(s => s.template),
  })), request_id: rid });
}

// =============================================================================
// EMAIL ENGINE
// =============================================================================

async function queueEmail(env, { to, template, vars, send_at }) {
  const msgId = "email_" + await sha256prefix(to + template + Date.now(), 10);
  const msg   = { id: msgId, to, template, vars: vars||{}, send_at, status: "queued", created_at: new Date().toISOString() };
  await env.EMAIL_QUEUE_KV?.put(`email:${msgId}`, JSON.stringify(msg), { expirationTtl: 86400 * 30 });
  return msgId;
}

async function outreachQueueDirect(env, email, sequenceName, vars) {
  const seq = EMAIL_SEQUENCES[sequenceName];
  if (!seq) return;
  for (const step of seq) {
    await queueEmail(env, {
      to: email, template: step.template,
      vars: { ...step.vars, ...vars },
      send_at: new Date(Date.now() + step.delay_hours * 3600000).toISOString(),
    });
  }
}

async function sendEmailViaProvider(env, msg) {
  if (!env?.SENDGRID_API_KEY) return; // Skip if no key
  const tpl = getCommercialEmailTemplate(msg.template, msg.vars);

  await fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.SENDGRID_API_KEY}`,
      "Content-Type":  "application/json",
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: msg.to }], dynamic_template_data: msg.vars }],
      from:    { email: "intel@cyberdudebivash.com", name: "CYBERDUDEBIVASH Sentinel APEX" },
      subject: tpl.subject,
      content: [{ type: "text/html", value: tpl.html }],
    }),
  }).catch(() => {});
}

// ─────────────────────────────────────────────────────────────────────────────
// EMAIL TEMPLATES — Production cold outreach + nurture + automation
// ─────────────────────────────────────────────────────────────────────────────
function getEmailTemplate(name, vars) {
  const T = vars || {};
  const templates = {
    "cold_enterprise_v1": {
      subject: `${T.company || "Your team"} — AI threat intelligence that pays for itself`,
      html: `<p>Hi there,</p>
<p>I noticed ${T.company || "your organization"} operates in a space where real-time threat intelligence is mission-critical.</p>
<p>We built <strong>CYBERDUDEBIVASH® SENTINEL APEX</strong> — an AI-powered threat intelligence platform used by security teams to:</p>
<ul>
<li>Detect active threats with CVE/APT/IOC feeds in real-time</li>
<li>Export STIX 2.1 bundles directly to your SIEM (Splunk, Sentinel, QRadar)</li>
<li>Cut MTTD by 60% using AI-driven actor attribution</li>
</ul>
<p>Would you be open to a 15-minute demo? I'll show you live threat data from the past 24 hours relevant to your sector.</p>
<p><a href="${T.demo_link || 'https://intel.cyberdudebivash.com/demo'}">Book a live demo →</a></p>
<p>— Bivash<br>CyberDudeBivash Pvt. Ltd.<br>enterprise@cyberdudebivash.com</p>`,
    },
    "cold_enterprise_fu1": {
      subject: `Re: Threat intelligence for ${T.company || "your team"}`,
      html: `<p>Just following up on my previous message.</p>
<p>Every item in the live feed at <a href="https://intel.cyberdudebivash.com/api/feed.json">intel.cyberdudebivash.com/api/feed.json</a> links to its public source, so you can check exactly what we are tracking right now.</p>
<p>Our Enterprise tier delivers these alerts to your SIEM within minutes of confirmation.</p>
<p>15 minutes this week? <a href="https://intel.cyberdudebivash.com/demo">Book here →</a></p>
<p>— Bivash</p>`,
    },
    "cold_enterprise_value": {
      subject: `How ${T.company || "security teams"} use SENTINEL APEX to detect threats faster`,
      html: `<p>Quick value share —</p>
<p>SENTINEL APEX processes live threat intelligence around the clock. Here's what Pro/Enterprise users get that free users don't:</p>
<ul>
<li>✅ Full IOC arrays (IPs, domains, hashes) on every threat</li>
<li>✅ STIX 2.1 bundle export to Splunk/QRadar/Sentinel</li>
<li>✅ Actor fingerprinting with kill chain mapping</li>
<li>✅ Real-time alert webhooks</li>
</ul>
<p>Enterprise is ₹${ENGINE.DEAL_VALUES_INR.enterprise_monthly.toLocaleString('en-IN')}/month.</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise">Start Enterprise →</a></p>`,
    },
    "cold_enterprise_fu2": {
      subject: `Last check-in — threat intel for ${T.company || "your team"}`,
      html: `<p>I'll keep this brief.</p>
<p>If protecting your infrastructure against the latest APT campaigns and zero-days is a priority, I'd love to show you SENTINEL APEX in 15 minutes.</p>
<p>If the timing isn't right, just reply and I'll reach out in a month.</p>
<p><a href="https://intel.cyberdudebivash.com/demo">One last chance to book →</a></p>`,
    },
    "cold_enterprise_break": {
      subject: `Closing the loop`,
      html: `<p>I'm going to stop reaching out — clearly the timing isn't right.</p>
<p>If threat intelligence ever becomes a priority, you can reach us at <a href="https://intel.cyberdudebivash.com">intel.cyberdudebivash.com</a>.</p>
<p>Stay secure.</p>
<p>— Bivash</p>`,
    },
    "lead_welcome": {
      subject: "Your Sentinel APEX access is ready",
      html: `<p>Welcome to <strong>CYBERDUDEBIVASH® SENTINEL APEX</strong>.</p>
<p>You now have access to our real-time threat intelligence platform.</p>
<p><strong>What you can do right now (free tier):</strong></p>
<ul><li>Browse the latest 20 threat reports</li><li>See AI-generated risk scores</li><li>Preview IOC counts</li></ul>
<p><strong>Upgrade to Pro</strong> (₹${ENGINE.DEAL_VALUES_INR.pro_monthly.toLocaleString('en-IN')}/month) to unlock full IOC arrays, AI kill chain analysis, and ${TIERS.PRO.req_day.toLocaleString('en-US')} API calls/day.</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro">Start Pro →</a></p>`,
    },
    "lead_value_d2": {
      subject: "What Pro adds to the live Sentinel APEX feed",
      html: `<p>The public feed at <a href="https://intel.cyberdudebivash.com">intel.cyberdudebivash.com</a> is updated by the publishing pipeline; every item links to its source.</p>
<p>On the free tier, you can see the threat titles. On Pro, you get:</p>
<ul><li>Full IOC arrays to block immediately</li><li>Actor attribution</li><li>STIX export for your SIEM</li></ul>
<p><a href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro">Unlock full intel with Pro — ₹${ENGINE.DEAL_VALUES_INR.pro_monthly.toLocaleString('en-IN')}/mo →</a></p>`,
    },
    "lead_trial_offer": {
      // Template key kept for the lead_nurture sequence; the copy no longer
      // offers a trial (commercial-contract.json: "No free trial").
      subject: "Sentinel APEX Pro — full IOC access for your SOC",
      html: `<p>Pro gives your team full IOC arrays, AI analysis and STIX export, with ${TIERS.PRO.req_day.toLocaleString('en-US')} API calls/day.</p>
<p>₹${ENGINE.DEAL_VALUES_INR.pro_monthly.toLocaleString('en-IN')}/month, cancel any time; access runs to the end of the paid period.</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro">Start Pro →</a></p>`,
    },
    "trial_welcome": {
      subject: "Your 7-day Pro trial is active — API key inside",
      html: `<p>Hi ${T.name || "there"},</p>
<p>Your <strong>7-day Pro trial</strong> is live.</p>
<p><strong>Your API key:</strong><br><code style="background:#f5f5f5;padding:8px;display:block">${T.api_key || "[see dashboard]"}</code></p>
<p>Expires: ${T.expires_at || "7 days from now"}</p>
<p><strong>Quick start:</strong></p>
<pre>curl -H "X-Api-Key: ${T.api_key || "YOUR_KEY"}" https://intel.cyberdudebivash.com/api/feed</pre>
<p><a href="https://intel.cyberdudebivash.com/docs">Full API docs →</a></p>
<p>To keep full access after your trial: <a href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro">Upgrade to Pro (₹${ENGINE.DEAL_VALUES_INR.pro_monthly.toLocaleString('en-IN')}/mo) →</a></p>`,
    },
    "trial_nudge_d3": {
      subject: "4 days left on your Pro trial — here's what you've unlocked",
      html: `<p>Hi ${T.name || "there"},</p>
<p>You're halfway through your Pro trial. Here's a quick reminder of what you now have access to:</p>
<ul><li>✅ Full IOC arrays on every threat</li><li>✅ AI kill chain analysis</li><li>✅ Actor fingerprinting</li><li>✅ ${TIERS.PRO.req_day.toLocaleString('en-US')} API calls/day</li></ul>
<p>Keep this access with Pro at ₹${ENGINE.DEAL_VALUES_INR.pro_monthly.toLocaleString('en-IN')}/month.</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade?plan=pro">Upgrade Now →</a></p>`,
    },
    "trial_expiry_d1": {
      subject: "⚠️ Your Pro trial expires tomorrow",
      html: `<p>Hi ${T.name || "there"},</p>
<p>Your 7-day Pro trial expires <strong>tomorrow</strong>.</p>
<p>After expiry, your API key will revert to free tier — IOC arrays and AI analysis will be locked.</p>
<p><strong>Upgrade now to maintain full access:</strong></p>
<p><a href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro" style="background:#00d4aa;color:#000;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block">Upgrade to Pro — ₹${ENGINE.DEAL_VALUES_INR.pro_monthly.toLocaleString('en-IN')}/mo →</a></p>`,
    },
    "trial_expired": {
      subject: "Your Pro trial has ended — upgrade to restore access",
      html: `<p>Hi ${T.name || "there"},</p>
<p>Your 7-day Pro trial has ended. Your API key is now on the free tier.</p>
<p>To restore full IOC access, AI analysis, and ${TIERS.PRO.req_day.toLocaleString('en-US')} API calls/day:</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade.html?plan=pro">Upgrade to Pro — ₹${ENGINE.DEAL_VALUES_INR.pro_monthly.toLocaleString('en-IN')}/mo →</a></p>
<p>Need enterprise access for your team? <a href="mailto:enterprise@cyberdudebivash.com">Contact us</a>.</p>`,
    },
    "usage_approaching_limit": {
      subject: "80% of your daily API limit used",
      html: `<p>You've used <strong>80% of your daily API calls</strong>.</p>
<p>Upgrade to Pro for ${TIERS.PRO.req_day.toLocaleString('en-US')} calls/day (vs ${TIERS.FREE.req_day} on the free tier).</p>
<p><a href="${T.upgrade_url || 'https://intel.cyberdudebivash.com/upgrade'}">Upgrade Now →</a></p>`,
    },
    "usage_limit_hit": {
      subject: "Daily API limit reached — upgrade to continue",
      html: `<p>You've hit your daily API limit.</p>
<p>Your access will reset tomorrow. To continue today — upgrade to Pro for ${TIERS.PRO.req_day.toLocaleString('en-US')} calls/day.</p>
<p><a href="${T.upgrade_url}">Upgrade Now →</a></p>`,
    },
    "pro_enterprise_upsell": {
      subject: "Ready to scale beyond Pro? Enterprise is waiting.",
      html: `<p>You're getting serious value from your Pro subscription.</p>
<p>When you're ready to scale, Enterprise unlocks:</p>
<ul><li>${TIERS.ENTERPRISE.req_day.toLocaleString('en-US')} API calls/day</li><li>Full STIX 2.1 bundle export</li><li>SIEM push (Splunk, Sentinel, QRadar)</li><li>99.9% uptime SLA</li><li>Email and chat support, 4h response</li></ul>
<p><a href="https://intel.cyberdudebivash.com/upgrade?plan=enterprise">Upgrade to Enterprise — ₹${ENGINE.DEAL_VALUES_INR.enterprise_monthly.toLocaleString('en-IN')}/mo →</a></p>`,
    },
    "enterprise_contract": {
      subject: `Enterprise agreement ready — ${T.company}`,
      html: `<p>Hi,</p>
<p>Thank you for choosing <strong>CYBERDUDEBIVASH® SENTINEL APEX Enterprise</strong>.</p>
<p><strong>Contract ref:</strong> ${T.contract_ref || "CDB-ENT-2026-XXXX"}<br>
<strong>Plan:</strong> Enterprise<br>
<strong>Value:</strong> ₹${T.value_inr || ENGINE.DEAL_VALUES_INR.enterprise_monthly}/month</p>
<p>Next steps:</p>
<ol><li>Review and sign the contract (DocuSign link coming separately)</li><li>Billing activation within 24 hours of signature</li><li>Enterprise API key + SIEM setup call with our team</li></ol>
<p>Questions? Reply to this email or reach us at enterprise@cyberdudebivash.com</p>`,
    },
    "enterprise_onboard": {
      subject: `Enterprise onboarding started — ${T.company}`,
      html: `<p>Welcome to SENTINEL APEX Enterprise, ${T.name || ""}!</p>
<p>Your onboarding checklist:</p>
<ol>
<li>✅ Enterprise API key — issued within 1 hour</li>
<li>⏳ SIEM webhook configuration</li>
<li>⏳ IP allowlist setup</li>
<li>⏳ Slack threat channel integration</li>
<li>⏳ Kickoff call with our security team</li>
<li>⏳ SLA agreement</li>
</ol>
<p>Your dedicated support: <a href="mailto:enterprise@cyberdudebivash.com">enterprise@cyberdudebivash.com</a></p>`,
    },
    "weekly_digest": {
      subject: `Your Weekly Threat Digest — ${T.week || getWeekLabel()}`,
      html: `<p><strong>CYBERDUDEBIVASH® SENTINEL APEX</strong> — Weekly Threat Digest</p>
<p>Top threats detected this week:</p>
<pre>${T.threats || "Threat data loading..."}</pre>
<p><a href="https://intel.cyberdudebivash.com">View full platform →</a></p>`,
    },
  };
  return templates[name] || { subject: "SENTINEL APEX Update", html: "<p>Update from CYBERDUDEBIVASH SENTINEL APEX.</p>" };
}

// =============================================================================
// HELPERS
// =============================================================================

function scoreLeadInitial(company, role) {
  let score = 30; // base
  if (!company) return score;
  const co = company.toLowerCase();
  const ro = (role || "").toLowerCase();
  // Company signals
  if (co.includes("bank") || co.includes("finance") || co.includes("fintech")) score += 25;
  if (co.includes("healthcare") || co.includes("hospital"))                     score += 20;
  if (co.includes("government") || co.includes("ministry"))                     score += 30;
  if (co.includes("telecom") || co.includes("telco"))                           score += 20;
  if (co.includes("enterprise") || co.includes("corp"))                         score += 15;
  if (co.match(/\.(com|in|io|co)$/))                                            score += 5;
  // Role signals
  if (ro.includes("ciso") || ro.includes("cto") || ro.includes("ceo"))         score += 30;
  if (ro.includes("security") || ro.includes("soc") || ro.includes("cyber"))   score += 20;
  if (ro.includes("head") || ro.includes("director") || ro.includes("vp"))     score += 15;
  if (ro.includes("analyst") || ro.includes("engineer"))                        score += 10;
  return Math.min(100, score);
}

function inferTags(company, role, context) {
  const tags = [];
  if ((role||"").toLowerCase().includes("ciso")) tags.push("c-suite");
  if ((company||"").toLowerCase().includes("bank")) tags.push("finance");
  if (context === "ioc_access") tags.push("technical");
  if (context === "stix_request") tags.push("siem-user");
  if (context === "demo_request") tags.push("high-intent");
  return tags;
}

// Constant-time string comparison — prevents timing side-channel attacks on
// the admin shared secret. Always walks the full length of the longer input.
function timingSafeEqual(a, b) {
  const bufA = new TextEncoder().encode(String(a ?? ""));
  const bufB = new TextEncoder().encode(String(b ?? ""));
  const len  = Math.max(bufA.length, bufB.length);
  let diff   = bufA.length ^ bufB.length;
  for (let i = 0; i < len; i++) {
    diff |= (bufA[i] ?? 0) ^ (bufB[i] ?? 0);
  }
  return diff === 0;
}

async function isAdmin(request, env) {
  const secret = request.headers.get("X-Admin-Secret");
  return Boolean(secret && env?.REVENUE_ADMIN_SECRET && timingSafeEqual(secret, env.REVENUE_ADMIN_SECRET));
}

// Customer portal token: HMAC-SHA256(REVENUE_ADMIN_SECRET, "portal:"+email),
// hex-encoded. Reuses the Worker's existing admin secret as the HMAC key
// (a one-way derivation - never exposes the secret itself) rather than
// requiring a new dedicated secret to be provisioned before this fix takes
// effect. Domain-separated with a "portal:" prefix so it can't be replayed
// against any other HMAC use of the same secret.
async function computePortalToken(env, email) {
  if (!env?.REVENUE_ADMIN_SECRET) return null;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(env.REVENUE_ADMIN_SECRET),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("portal:" + email.toLowerCase()));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * GET /api/health -- public observability endpoint. Mirrors the shape/intent
 * of intel-gateway's /api/health (binding pings + config presence), scaled
 * down to what this Worker actually has.
 *
 * @param {Request} request - unused; accepted for the standard route-handler
 *   signature used throughout this file.
 * @param {object} env - Worker bindings/secrets whose presence is reported.
 * @param {string} rid - request id, echoed back in the response for log
 *   correlation.
 * @returns {Promise<Response>} binding health + boolean config-presence
 *   flags only -- never secret values, including the per-tier/cycle
 *   `razorpay_plan_ids_configured` booleans.
 */
export async function handleRevenueEngineHealth(request, env, rid) {
  // Same fix, same reasoning as intel-gateway's /api/health (see that file): a security report
  // showed this endpoint handing an anonymous caller the engine name/version, every KV/D1
  // binding's presence, and which Razorpay integrations are configured -- a free
  // infrastructure map, gated behind nothing. Reuses the existing isAdmin() (X-Admin-Secret,
  // timingSafeEqual) rather than a new mechanism: an authenticated admin gets the identical,
  // unchanged full response; anonymous callers get {status, engine, version, generated_at}.
  if (!(await isAdmin(request, env))) {
    return json({ status: "ok", engine: ENGINE.NAME, version: ENGINE.VERSION, generated_at: new Date().toISOString() });
  }

  const kvOk  = env.REVENUE_CRM_KV ? await env.REVENUE_CRM_KV.get("health:ping").then(() => "ok").catch(() => "error") : "not_bound";
  const d1Ok  = env.CRM_DB ? await env.CRM_DB.prepare("SELECT 1").first().then(() => "ok").catch(() => "error") : "not_bound";

  // Per-tier/cycle Plan ID presence -- booleans only, never the values
  // themselves. Built off PLAN_ID_ENV_KEYS (the same map
  // handleBillingSubscriptionCreate's 503 check reads) so this can never
  // silently drift from what actually gates checkout: a tier/cycle showing
  // false here is exactly the one that falls back to the one-time-order
  // flow in upgrade.html today.
  const planIdsConfigured = {};
  for (const [tier, cycles] of Object.entries(PLAN_ID_ENV_KEYS)) {
    for (const [cycle, envKey] of Object.entries(cycles)) {
      planIdsConfigured[`${tier.toLowerCase()}_${cycle}`] = !!env[envKey];
    }
  }

  return json({
    status: "ok",
    engine: ENGINE.NAME,
    version: ENGINE.VERSION,
    checks: {
      revenue_crm_kv: kvOk,
      email_queue_kv: env.EMAIL_QUEUE_KV ? "bound" : "not_bound",
      api_keys_kv: env.API_KEYS_KV ? "bound" : "not_bound",
      crm_db: d1Ok,
      razorpay_orders_configured: !!(env.RAZORPAY_KEY_ID && env.RAZORPAY_KEY_SECRET),
      razorpay_subscriptions_configured: !!env.RAZORPAY_WEBHOOK_SECRET,
      razorpay_plan_ids_configured: planIdsConfigured,
    },
    generated_at: new Date().toISOString(),
    rid,
  });
}

async function slackNotify(env, message) {
  if (!env?.SLACK_WEBHOOK_URL) return;
  await fetch(env.SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: message }),
  }).catch(() => {});
}

async function trackEvent(env, event, meta = {}) {
  if (!env?.REVENUE_CRM_KV) return;
  try {
    const day = new Date().toISOString().slice(0, 10);
    const key = `events:${day}:${event}`;
    const cnt = parseInt(await env.REVENUE_CRM_KV.get(key) || "0") + 1;
    await env.REVENUE_CRM_KV.put(key, String(cnt), { expirationTtl: 86400 * 30 });
    try {
      await env.CRM_DB?.prepare(
        `INSERT INTO events (id, event, meta, created_at) VALUES (?,?,?,?)`
      ).bind(
        await sha256prefix(event + Date.now(), 8),
        event, JSON.stringify(meta), new Date().toISOString()
      ).run();
    } catch {}
  } catch {}
}

async function sha256prefix(text, len = 12) {
  const data = new TextEncoder().encode(String(text));
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,"0")).join("").slice(0, len);
}

// Was `^[^\s@]+@[^\s@]+\.[^\s@]+$` -- "anything but whitespace/@" permits every HTML-special
// character (`<>"'`), which is exactly what let a stored-XSS payload into an email field that
// payment-status-dashboard.html later rendered unescaped (see that file's fix for the matching
// output-encoding half of this issue -- input validation on a structured field like email is a
// real defense, but it's never a substitute for escaping at render time on the free-text fields
// like payment_notes that legitimately need to allow punctuation). Bounded length matches the
// column this feeds (email TEXT, no declared limit elsewhere, so cap here) and RFC 5321's 254.
function sanitizeEmail(email) {
  const e = (email || "").trim().toLowerCase();
  if (e.length > 254) return null;
  return /^[a-z0-9][a-z0-9._%+-]*@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(e)
    ? e : null;
}

function genId(prefix) {
  const b = crypto.getRandomValues(new Uint8Array(6));
  return (prefix||"id") + "_" + [...b].map(x=>x.toString(16).padStart(2,"0")).join("");
}

function getWeekLabel() {
  const d = new Date();
  return `Week of ${d.toISOString().slice(0,10)}`;
}

// A security report flagged this Worker returning Access-Control-Allow-Origin: * on every
// response, including its admin-secret-gated CRM/deals/revenue/payment-approval routes -- with
// wildcard CORS, any origin's browser-side JS can read those responses whenever an admin secret
// is in play, and it lets an unauthenticated caller script freely against the API from any
// origin with none of the (admittedly weak, since it's just a header value) friction a same-
// origin-only policy would add. This is a server-to-server-style admin API; the only browser
// callers that legitimately need it are this repo's own admin/customer dashboard HTML pages,
// all of which are deployed to and served from intel.cyberdudebivash.com (confirmed by grepping
// this repo for every root-level *.html file referencing this Worker's URL: payment-status-
// dashboard.html, revenue-dashboard.html, customer/api-keys.html, trial-center.html, lead-
// pipeline.html, subscription-management.html, payment-submission.html, mssp-tenant-
// dashboard.html, enterprise-onboarding.html, customer-success.html, demo-intelligence-
// center.html). Extend this set if a legitimate new browser-based consumer is added elsewhere.
const REVENUE_ALLOWED_ORIGINS = new Set([
  "https://intel.cyberdudebivash.com",
]);

function isAllowedRevenueOrigin(origin) {
  return typeof origin === "string" && REVENUE_ALLOWED_ORIGINS.has(origin);
}

// Applies the single, correct Access-Control-Allow-Origin decision to every response this
// Worker returns, regardless of which handler built it -- see the fetch() entry point below,
// which is this Worker's only inbound edge, so this is the one place this needs to happen
// rather than threading `request`/origin through json()'s ~150 existing call sites.
function withCorsOrigin(response, allowedOrigin) {
  const headers = new Headers(response.headers);
  if (allowedOrigin) headers.set("Access-Control-Allow-Origin", allowedOrigin);
  else headers.delete("Access-Control-Allow-Origin");
  headers.append("Vary", "Origin");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function cors204(allowedOrigin) {
  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Secret, Authorization",
    "Vary": "Origin",
  };
  if (allowedOrigin) headers["Access-Control-Allow-Origin"] = allowedOrigin;
  return new Response(null, { status: 204, headers });
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type":   "application/json",
      "Cache-Control":  "no-cache, no-store",
    },
  });
}

const DEMO_FALLBACK_THREATS = [
  { title: "Critical RCE in Apache Struts — CVE-2026-0542", severity: "critical", risk_score: 9.8, ioc_count: 12 },
  { title: "APT41 Campaign Targeting Financial Sector via Spear Phishing", severity: "high", risk_score: 8.5, ioc_count: 34 },
  { title: "Ransomware Group LockBit 4.0 — New Variant Detected", severity: "critical", risk_score: 9.5, ioc_count: 67 },
];

// =============================================================================
// SENTINEL APEX REVENUE ENGINE — PHASE 2: COMMERCIAL OPERATIONS
// Payment Processing · API Key Management · Customer Provisioning
// Subscription Lifecycle · MSSP Tenant Management · Customer Success
// Added: 2026-06-05 | Version: v175.0.0
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// TIER CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────
// v185.2 FIX (Fortune-500 audit, Phase 9): PRO here previously said
// price_usd:99/price_inr:8250 -- the actual Razorpay charge
// (workers/intel-gateway/src/pricing-data.json, the live checkout source of
// truth) is $49/mo (INR 4,100). This TIERS object drives real key issuance
// and customer welcome emails (queueEmail() below), so the wrong price was
// reaching customers directly, not just documentation. req_day/req_min
// corrected to match the real enforced values (revenue-enforcement.js
// LIMITS.PRO / index.js RATE_LIMITS.PRO in the intel-gateway Worker).
// req_min must match workers/intel-gateway/src/index.js's RATE_LIMITS (the
// only actually-enforced values) -- this table only drives portal display
// and this dormant Subscriptions-API path, so a mismatch here never changed
// real enforcement, only what a customer's own portal told them it was.
// price_usd must match pricing.html, the canonical price list. Both ENTERPRISE
// fields were found drifted (req_min 500 vs real 600; price_usd 999 vs real
// 499) during a 2026-08-31 monetization audit.
//
// P0 commercial-contract convergence (2026-09-24): req_day was FREE 25 and
// MSSP 200000 -- config/commercial-contract.json says requests_per_day FREE 50
// and MSSP 50,000, which is also what intel-gateway's DAILY_QUOTAS enforces on
// the real API (so no customer could ever use more than 50,000/day; the 200000
// here only mis-stated the cap on the portal and in /api/apikeys/validate).
// scripts/verify_commercial_contract.py now gates req_day/req_min on drift.
const TIERS = {
  FREE:       { label:"Free",       req_day:50,     req_min:30,   price_usd:0,    price_inr:0,       trial_days:0,  features:["basic_feed","metadata","stix_ids"] },
  PRO:        { label:"Pro",        req_day:5000,   req_min:120,  price_usd:49,   price_inr:4100,    trial_days:7,  features:["full_ioc","sigma","yara","kql","spl","stix_bundle","actor","kill_chain","playbook","misp_json","csv_export"] },
  ENTERPRISE: { label:"Enterprise", req_day:50000,  req_min:600,  price_usd:499,  price_inr:41600,   trial_days:14, features:["siem_webhook","soar_export","navigator","hunt_queries","actor_tracking","campaign_intel","prediction_api","sector_feed","executive_brief","fair_model","reg_compliance","10_seats"] },
  MSSP:       { label:"MSSP",       req_day:50000,  req_min:1200, price_usd:999,  price_inr:83300,   trial_days:14, features:["multi_tenant","white_label","partner_api","bulk_stix","tenant_keys","oem_resale","40pct_revshare","25_seats"] },
};

const PAYMENT_METHODS = ["upi","qr","paypal","neft","crypto_usdt_bep20","crypto_usdt_erc20","amazon_pay","bank_wire"];
const PAYMENT_STATUS  = { PENDING:"pending", VERIFIED:"verified", APPROVED:"approved", REJECTED:"rejected", REFUNDED:"refunded" };
const SUB_STATUS      = { TRIAL:"trial", ACTIVE:"active", EXPIRING:"expiring", EXPIRED:"expired", SUSPENDED:"suspended", CANCELLED:"cancelled", RENEWED:"renewed", PAST_DUE:"past_due" };

// ─────────────────────────────────────────────────────────────────────────────
// ROUTER EXTENSION — inject into main fetch() by pattern
// These routes are appended after existing route table
// ─────────────────────────────────────────────────────────────────────────────

// Called from main fetch() — we expose a secondary dispatcher
async function dispatchCommercialRoutes(path, method, request, env, rid) {
  // Public routes (free-key request, apikeys/validate, payments/submit,
  // customer/portal) used to be checked here, but this function is only ever
  // called from the main fetch() *after* its isAdmin() gate -- making them
  // unreachable by any non-admin caller despite being coded as "public".
  // Moved to the main fetch(), before that gate, where they are now actually
  // reachable. See the "Public: customer-facing commercial routes" block
  // there. Nothing below this comment changes -- all admin-secured.

  // ── Admin-secured routes below ────────────────────────────────────────────
  if (!await isAdmin(request, env))
    return json({ error:"unauthorized", message:"X-Admin-Secret required." }, 401);

  // Payments
  if (path === "/api/payments"                  && method === "GET")  return await handlePaymentList(request, env, rid);
  if (path.startsWith("/api/payments/approve/") && method === "POST") return await handlePaymentApprove(request, env, rid, path.slice(22));
  if (path.startsWith("/api/payments/reject/")  && method === "POST") return await handlePaymentReject(request, env, rid, path.slice(21));
  if (path.startsWith("/api/payments/")         && method === "GET")  return await handlePaymentGet(request, env, rid, path.slice(14));

  // API Keys
  if (path === "/api/apikeys"                   && method === "GET")  return await handleApiKeyListAll(request, env, rid);
  if (path === "/api/apikeys/generate"          && method === "POST") return await handleApiKeyGenerate(request, env, rid);
  if (path === "/api/apikeys/rotate"            && method === "POST") return await handleApiKeyRotate(request, env, rid);
  if (path === "/api/apikeys/revoke"            && method === "POST") return await handleApiKeyRevoke(request, env, rid);

  // Customer provisioning
  if (path === "/api/customers"                 && method === "GET")  return await handleCustomerList(request, env, rid);
  if (path === "/api/customers/provision"       && method === "POST") return await handleCustomerProvision(request, env, rid);
  if (path.startsWith("/api/customers/")        && method === "GET")  return await handleCustomerGet(request, env, rid, path.slice(16));
  if (path.startsWith("/api/customers/")        && method === "PUT")  return await handleCustomerUpdate(request, env, rid, path.slice(16));

  // Subscriptions
  if (path === "/api/subscriptions"             && method === "GET")  return await handleSubList(request, env, rid);
  if (path === "/api/subscriptions/expire-check"&& method === "POST") return await handleSubExpireCheck(request, env, rid);
  if (path.startsWith("/api/subscriptions/")    && method === "GET")  return await handleSubGet(request, env, rid, path.slice(19));
  if (path.startsWith("/api/subscriptions/")    && method === "PUT")  return await handleSubUpdate(request, env, rid, path.slice(19));

  // MSSP tenants
  if (path === "/api/mssp/tenants"              && method === "GET")  return await handleMSSPTenantList(request, env, rid);
  if (path === "/api/mssp/tenants"              && method === "POST") return await handleMSSPTenantCreate(request, env, rid);
  if (path.startsWith("/api/mssp/tenants/")     && method === "GET")  return await handleMSSPTenantGet(request, env, rid, path.slice(19));
  if (path.startsWith("/api/mssp/tenants/")     && method === "PUT")  return await handleMSSPTenantUpdate(request, env, rid, path.slice(19));
  if (path.startsWith("/api/mssp/tenants/")     && method === "DELETE") return await handleMSSPTenantRevoke(request, env, rid, path.slice(19));

  // Customer success
  if (path === "/api/success/scores"            && method === "GET")  return await handleSuccessScores(request, env, rid);
  if (path === "/api/success/at-risk"           && method === "GET")  return await handleAtRisk(request, env, rid);

  // Revenue analytics
  if (path === "/api/revenue/commercial"        && method === "GET")  return await handleCommercialDashboard(request, env, rid);

  return null; // not handled — fall through to main router's 404
}

// =============================================================================
// FREE API KEY REQUEST
// =============================================================================
async function handleFreeKeyRequest(request, env, rid) {
  const body = await request.json().catch(() => ({}));
  const email = sanitizeEmail(body.email);
  if (!email) return json({ error:"invalid_email" }, 400);

  // Check for existing key. Resend via email only (the address already on
  // file) rather than returning the live key in the response — this endpoint
  // has no auth, so anyone who knows/guesses an email could otherwise pull
  // out that customer's real, active key.
  const existing = await env.REVENUE_CRM_KV.get(`customer:${email}`, "json");
  if (existing) {
    const keys = await env.REVENUE_CRM_KV.get(`apikeys:${email}`, "json") || [];
    const activeKey = keys.find(k => k.tier === "FREE" && k.status === "active");
    if (activeKey) {
      // Backfill: this key may have been issued before the entitlement-sync
      // fix above existed, in which case it was never written to
      // API_KEYS_KV and would still 401 on every gateway call even after
      // being resent. Upsert unconditionally (cheap, idempotent) rather
      // than trying to detect whether it's already synced.
      if (env.API_KEYS_KV) {
        await env.API_KEYS_KV.put(activeKey.key, JSON.stringify({
          key: activeKey.key, tier: "FREE", customer_id: existing.id, email,
          source: "free_signup",
          created_at: activeKey.created_at, expires_at: activeKey.expires_at,
          payment_metadata: {},
        }));
      }
      await queueEmail(env, { to:email, template:"free_key_welcome", vars:{ api_key:activeKey.key, tier:"FREE", req_day:TIERS.FREE.req_day, upgrade_url:"https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html" } });
      return json({ success:true, already_exists:true, key:"[sent to your email]", tier:"FREE", message:"Your existing free API key has been resent to your email." });
    }
  }

  const key = generateApiKey("FREE");
  const keyId = genId("key");
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 365 * 86400000).toISOString(); // 1 year

  // req_day/req_min here are the customer-facing figures shown at signup and
  // stored for display (admin listings, /api/apikeys/validate) -- not an
  // independent enforcement path. The one that actually gates every gateway
  // call is intel-gateway's RATE_LIMITS.FREE (30/min) and FREE_TIER_ITEM_CAP
  // (25 items/response); kept in sync with those here so this endpoint
  // doesn't quote a customer a limit intel-gateway doesn't actually apply.
  const keyRecord = { id:keyId, key, tier:"FREE", status:"active", email, created_at:now, expires_at:expiresAt, req_day:TIERS.FREE.req_day, req_min:TIERS.FREE.req_min, rotation_count:0 };
  const custRecord = { id:genId("cust"), email, tier:"FREE", status:"active", created_at:now, plan_started_at:now, source:"free_signup" };

  await env.REVENUE_CRM_KV.put(`customer:${email}`, JSON.stringify(custRecord));
  await env.REVENUE_CRM_KV.put(`apikeys:${email}`, JSON.stringify([keyRecord]));
  await env.REVENUE_CRM_KV.put(`apikey:${key}`, JSON.stringify(keyRecord));
  await env.REVENUE_CRM_KV.put(`apikey_id:${keyId}`, JSON.stringify(keyRecord));

  // Entitlement sync — mirror the key into API_KEYS_KV, the namespace
  // intel-gateway's live auth path (resolveAuth()) actually reads on every
  // request. Without this, every FREE-tier self-service signup issued a key
  // intel-gateway could never recognize (confirmed live: 401 invalid_key on
  // every gateway call) — REVENUE_CRM_KV and API_KEYS_KV are different
  // namespaces intel-gateway never cross-reads. Same pattern already used by
  // provisionCustomer()'s entitlement sync below for paid tiers; this path
  // was missed when that fix was made. Guarded so this is a no-op wherever
  // the binding isn't configured.
  if (env.API_KEYS_KV) {
    await env.API_KEYS_KV.put(key, JSON.stringify({
      key, tier: "FREE", customer_id: custRecord.id, email,
      source: "free_signup",
      created_at: now, expires_at: expiresAt,
      payment_metadata: {},
    }));
  }

  await queueEmail(env, { to:email, template:"free_key_welcome", vars:{ api_key:key, tier:"FREE", req_day:TIERS.FREE.req_day, upgrade_url:"https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html" } });
  await trackEvent(env, "free_key_issued", { email, keyId });

  return json({ success:true, key, tier:"FREE", req_day:TIERS.FREE.req_day, req_min:TIERS.FREE.req_min, expires_at:expiresAt, upgrade_url:"/PAYMENT-GATEWAY.html", message:"API key issued. Check your email for onboarding details." });
}

// =============================================================================
// API KEY VALIDATION (used by intel-gateway on every request)
// =============================================================================
async function handleApiKeyValidate(request, env, rid) {
  const url = new URL(request.url);
  const key = url.searchParams.get("key") || request.headers.get("X-API-Key") || request.headers.get("Authorization")?.replace("Bearer ","");
  if (!key) return json({ valid:false, error:"no_key" }, 401);

  const rec = await env.REVENUE_CRM_KV.get(`apikey:${key}`, "json");
  if (!rec) return json({ valid:false, error:"invalid_key" }, 401);
  if (rec.status !== "active") return json({ valid:false, error:`key_${rec.status}`, tier:rec.tier }, 403);
  if (rec.expires_at && new Date(rec.expires_at) < new Date()) {
    await env.REVENUE_CRM_KV.put(`apikey:${key}`, JSON.stringify({...rec, status:"expired"}));
    return json({ valid:false, error:"key_expired", tier:rec.tier, renew_url:"/PAYMENT-GATEWAY.html" }, 403);
  }

  // Usage tracking
  const day = new Date().toISOString().slice(0,10);
  const usageKey = `usage:${key}:${day}`;
  const usage = parseInt(await env.REVENUE_CRM_KV.get(usageKey) || "0") + 1;
  await env.REVENUE_CRM_KV.put(usageKey, String(usage), { expirationTtl: 86400 * 2 });

  const tier = TIERS[rec.tier] || TIERS.FREE;
  if (usage > tier.req_day) return json({ valid:false, error:"rate_limit_day", tier:rec.tier, usage_today:usage, limit_day:tier.req_day, upgrade_url:"/PAYMENT-GATEWAY.html?from=rate_limit" }, 429);

  return json({ valid:true, tier:rec.tier, email:rec.email, customer_id:rec.customer_id, req_day:tier.req_day, req_min:tier.req_min, usage_today:usage, expires_at:rec.expires_at, features:tier.features });
}

// =============================================================================
// PAYMENT SUBMISSION (customer uploads evidence)
// =============================================================================
// Public by design (dispatched before the isAdmin() gate in the router above, alongside the
// other genuinely-public customer routes) -- a real customer paying by UPI/bank transfer/crypto
// has no admin secret and needs to submit proof before any account exists. What was missing was
// everything downstream of "public": no per-IP rate limit, a screenshot_url stored with no
// scheme check, and payment_notes/email flowing into payment-status-dashboard.html unescaped
// (fixed in that file). This pass adds the input-side controls; see sanitizeEmail() above and
// this dashboard's escapeHtml()/escapeJsAttr()/safeHref() for the corresponding output-side fix
// -- both are required, per "encode untrusted data at output" (input validation alone can't be
// the whole XSS control for a free-text field like payment_notes).
const PAYMENT_SUBMIT_MAX_PER_HOUR_PER_IP = 5;
const PAYMENT_NOTES_MAX_LENGTH = 2000;
const TRANSACTION_ID_MAX_LENGTH = 128;
const SCREENSHOT_URL_MAX_LENGTH = 2048;

// Same http(s)-only scheme check the dashboard applies again at render time (safeHref) --
// rejecting javascript:/data: here means a malicious screenshot_url never even reaches storage,
// while the dashboard's own check stays as defense in depth for any record written before this
// fix shipped.
function sanitizeScreenshotUrl(url) {
  if (!url) return null;
  const trimmed = String(url).trim();
  if (!trimmed || trimmed.length > SCREENSHOT_URL_MAX_LENGTH) return null;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

async function handlePaymentSubmit(request, env, rid) {
  // Fixed-window per-IP cap (hashed, not stored raw) -- same pattern as handleTrialRequest's
  // existing anti-automation limiter just above, reused rather than re-implemented.
  const ipHash = await sha256prefix(request.headers.get("cf-connecting-ip") || "unknown", 16);
  const rlKey = `payment_submit_rl:${ipHash}:${new Date().toISOString().slice(0, 13)}`; // hour bucket
  const rlCount = parseInt((await env.REVENUE_CRM_KV?.get(rlKey)) || "0", 10);
  if (rlCount >= PAYMENT_SUBMIT_MAX_PER_HOUR_PER_IP) {
    return json({ error:"rate_limited", message:"Too many payment submissions from this network. Try again later." }, 429);
  }
  await env.REVENUE_CRM_KV?.put(rlKey, String(rlCount + 1), { expirationTtl: 3600 });

  const body = await request.json().catch(() => ({}));
  const { email, plan, payment_method, transaction_id, amount_paid, currency, payment_notes, screenshot_url, billing_cycle } = body;

  const cleanEmail = sanitizeEmail(email);
  if (!cleanEmail) return json({ error:"invalid_email" }, 400);
  if (!plan || !TIERS[plan.toUpperCase()]) return json({ error:"invalid_plan", valid_plans:Object.keys(TIERS) }, 400);
  if (!payment_method || !PAYMENT_METHODS.includes(payment_method)) return json({ error:"invalid_payment_method", valid_methods:PAYMENT_METHODS }, 400);
  const cleanScreenshotUrl = sanitizeScreenshotUrl(screenshot_url);
  if (screenshot_url && !cleanScreenshotUrl) return json({ error:"invalid_screenshot_url", message:"screenshot_url must be an http(s) URL." }, 400);
  if (!transaction_id && !cleanScreenshotUrl) return json({ error:"evidence_required", message:"Provide transaction_id or screenshot_url" }, 400);
  const cleanTransactionId = transaction_id ? String(transaction_id).trim().slice(0, TRANSACTION_ID_MAX_LENGTH) : null;
  const cleanNotes = payment_notes ? String(payment_notes).trim().slice(0, PAYMENT_NOTES_MAX_LENGTH) : null;

  const paymentId = genId("pay");
  const now = new Date().toISOString();
  const tier = plan.toUpperCase();

  // Idempotency: the same customer resubmitting the same transaction_id (double-click, retry
  // after a network blip) lands as a duplicate pending record today with no way to tell it apart
  // from a fresh submission. Reject an exact (email, transaction_id) repeat among recent
  // submissions rather than queuing another one -- cheap, and needs no new client-sent key.
  if (cleanTransactionId) {
    const recentIdx = await env.REVENUE_CRM_KV.get("payments:index", "json") || [];
    const duplicate = recentIdx.find(p => p.email === cleanEmail && p.transaction_id === cleanTransactionId);
    if (duplicate) {
      return json({ error:"duplicate_submission", message:"This transaction was already submitted.", payment_id:duplicate.id, status:duplicate.status }, 409);
    }
  }

  const record = {
    id: paymentId, email: cleanEmail, plan: tier, billing_cycle: billing_cycle || "monthly",
    payment_method, transaction_id: cleanTransactionId, amount_paid: amount_paid || null,
    currency: currency || (payment_method === "upi" || payment_method === "neft" ? "INR" : "USD"),
    screenshot_url: cleanScreenshotUrl, payment_notes: cleanNotes,
    status: PAYMENT_STATUS.PENDING, submitted_at: now, verified_at: null, approved_at: null,
    approved_by: null, rejection_reason: null, rid
  };

  await env.REVENUE_CRM_KV.put(`payment:${paymentId}`, JSON.stringify(record));

  // Append to payment index
  const idx = await env.REVENUE_CRM_KV.get("payments:index", "json") || [];
  idx.unshift({ id:paymentId, email:cleanEmail, plan:tier, method:payment_method, transaction_id:cleanTransactionId, status:PAYMENT_STATUS.PENDING, submitted_at:now });
  await env.REVENUE_CRM_KV.put("payments:index", JSON.stringify(idx.slice(0, 500)));

  // Notify admin via Slack
  await slackNotify(env, `💳 *NEW PAYMENT SUBMISSION* — ${cleanEmail}\nPlan: ${tier} | Method: ${payment_method} | TxID: ${cleanTransactionId||"(screenshot)"}\nApprove: https://intel.cyberdudebivash.com/payment-status-dashboard.html`);

  // Confirm email to customer
  await queueEmail(env, { to:cleanEmail, template:"payment_received", vars:{ payment_id:paymentId, plan:tier, method:payment_method, expected_hours:"4" } });
  await trackEvent(env, "payment_submitted", { paymentId, email:cleanEmail, plan:tier, method:payment_method });

  return json({ success:true, payment_id:paymentId, status:"pending", message:"Payment submission received. Verification usually completes within 4 business hours. Reference: "+paymentId });
}

// =============================================================================
// PAYMENT LIST + GET (admin)
// =============================================================================
async function handlePaymentList(request, env, rid) {
  const url = new URL(request.url);
  const statusFilter = url.searchParams.get("status");
  const idx = await env.REVENUE_CRM_KV.get("payments:index", "json") || [];
  const filtered = statusFilter ? idx.filter(p => p.status === statusFilter) : idx;
  return json({ count:filtered.length, payments:filtered.slice(0,200) });
}

async function handlePaymentGet(request, env, rid, paymentId) {
  const rec = await env.REVENUE_CRM_KV.get(`payment:${paymentId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  return json(rec);
}

// =============================================================================
// PAYMENT APPROVE → triggers full customer provisioning
// =============================================================================
async function handlePaymentApprove(request, env, rid, paymentId) {
  const body = await request.json().catch(() => ({}));
  const rec = await env.REVENUE_CRM_KV.get(`payment:${paymentId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  if (rec.status === PAYMENT_STATUS.APPROVED) return json({ error:"already_approved", payment_id:paymentId }, 400);

  const now = new Date().toISOString();
  rec.status    = PAYMENT_STATUS.APPROVED;
  rec.approved_at = now;
  rec.approved_by = body.approved_by || "admin";
  await env.REVENUE_CRM_KV.put(`payment:${paymentId}`, JSON.stringify(rec));

  // Update index
  const idx = await env.REVENUE_CRM_KV.get("payments:index", "json") || [];
  const i = idx.findIndex(p => p.id === paymentId);
  if (i >= 0) { idx[i].status = PAYMENT_STATUS.APPROVED; await env.REVENUE_CRM_KV.put("payments:index", JSON.stringify(idx)); }

  // Audit log
  await appendAuditLog(env, { action:"payment_approved", payment_id:paymentId, email:rec.email, plan:rec.plan, approved_by:rec.approved_by, ts:now });

  // PROVISION CUSTOMER
  const result = await provisionCustomer(env, { email:rec.email, tier:rec.plan, billing_cycle:rec.billing_cycle, payment_id:paymentId, payment_method:rec.payment_method, amount_paid:rec.amount_paid, currency:rec.currency });

  await slackNotify(env, `✅ *PAYMENT APPROVED & PROVISIONED* — ${rec.email}\nPlan: ${rec.plan} | API Key: ${result.api_key.substring(0,20)}...\nCustomer ID: ${result.customer_id}`);
  await trackEvent(env, "payment_approved", { paymentId, email:rec.email, plan:rec.plan });

  return json({ success:true, payment_id:paymentId, provisioning:result, message:"Customer provisioned and API key delivered." });
}

async function handlePaymentReject(request, env, rid, paymentId) {
  const body = await request.json().catch(() => ({}));
  const rec = await env.REVENUE_CRM_KV.get(`payment:${paymentId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  const now = new Date().toISOString();
  rec.status = PAYMENT_STATUS.REJECTED;
  rec.rejection_reason = body.reason || "Payment could not be verified.";
  rec.rejected_at = now;
  await env.REVENUE_CRM_KV.put(`payment:${paymentId}`, JSON.stringify(rec));
  const idx = await env.REVENUE_CRM_KV.get("payments:index", "json") || [];
  const i = idx.findIndex(p => p.id === paymentId);
  if (i >= 0) { idx[i].status = PAYMENT_STATUS.REJECTED; await env.REVENUE_CRM_KV.put("payments:index", JSON.stringify(idx)); }
  await queueEmail(env, { to:rec.email, template:"payment_rejected", vars:{ reason:rec.rejection_reason, retry_url:"https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html" } });
  await trackEvent(env, "payment_rejected", { paymentId, email:rec.email });
  return json({ success:true, payment_id:paymentId, status:"rejected" });
}

// =============================================================================
// CORE: provisionCustomer — creates record + sub + API key + sends welcome
// =============================================================================
async function provisionCustomer(env, { email, tier, billing_cycle, payment_id, payment_method, amount_paid, currency, trial=false, mssp_parent_id=null }) {
  const now = new Date().toISOString();
  const customerId = genId("cust");
  const subId = genId("sub");
  const tierCfg = TIERS[tier] || TIERS.PRO;

  // Calculate subscription dates
  const trialDays = trial ? (tierCfg.trial_days || 7) : 0;
  const billDays  = billing_cycle === "annual" ? 365 : 30;
  const activeDays = trialDays + billDays;
  const trialEndsAt   = trial ? new Date(Date.now() + trialDays * 86400000).toISOString() : null;
  const currentPeriodEnd = new Date(Date.now() + activeDays * 86400000).toISOString();

  // SEC-2026-07-18: this performs ~10 sequential cross-namespace KV writes
  // with no rollback available (Cloudflare KV has no multi-key transactions),
  // and previously had no error handling at all — a mid-sequence failure
  // vanished silently, which can leave a customer billed but without a
  // working key. True atomicity isn't achievable here, so the correct,
  // minimal fix is to make failures observable and propagated instead of
  // swallowed: track which stage failed, log it, count it via the existing
  // trackEvent() mechanism, then re-throw unchanged so callers (payment
  // approval, webhooks) see the same rejection as before and can alert/retry
  // rather than treating a partial failure as success.
  let stage = "customer_record";
  try {

  // 1. Create/update customer record
  const existing = await env.REVENUE_CRM_KV.get(`customer:${email}`, "json");
  const custRecord = {
    id: existing?.id || customerId,
    email, tier, status:"active", billing_cycle: billing_cycle || "monthly",
    plan_started_at: now, current_period_end: currentPeriodEnd,
    payment_method: payment_method || null, amount_paid: amount_paid || null, currency: currency || null,
    payment_id, mssp_parent_id, trial_ends_at: trialEndsAt,
    onboarding_completed: false, first_api_call_at: null, first_report_access_at: null,
    api_calls_total: 0, created_at: existing?.created_at || now, updated_at: now,
    source: trial ? "trial" : "payment"
  };
  await env.REVENUE_CRM_KV.put(`customer:${email}`, JSON.stringify(custRecord));

  // Append to customer index
  const custIdx = await env.REVENUE_CRM_KV.get("customers:index", "json") || [];
  const ci = custIdx.findIndex(c => c.email === email);
  const custSummary = { id:custRecord.id, email, tier, status:"active", created_at:now };
  if (ci >= 0) custIdx[ci] = custSummary; else custIdx.unshift(custSummary);
  await env.REVENUE_CRM_KV.put("customers:index", JSON.stringify(custIdx.slice(0,1000)));

  // 2. Generate API key
  const key = generateApiKey(tier);
  const keyId = genId("key");
  const keyRecord = {
    id:keyId, key, tier, status:"active", email, customer_id:custRecord.id,
    created_at:now, expires_at:currentPeriodEnd, req_day:tierCfg.req_day, req_min:tierCfg.req_min,
    features:tierCfg.features, rotation_count:0, mssp_parent_id, billing_cycle
  };
  await env.REVENUE_CRM_KV.put(`apikey:${key}`, JSON.stringify(keyRecord));
  await env.REVENUE_CRM_KV.put(`apikey_id:${keyId}`, JSON.stringify(keyRecord));

  // Revoke previous keys for this email
  const prevKeys = await env.REVENUE_CRM_KV.get(`apikeys:${email}`, "json") || [];
  for (const pk of prevKeys) {
    if (pk.status === "active" && pk.key !== key) {
      await env.REVENUE_CRM_KV.put(`apikey:${pk.key}`, JSON.stringify({...pk, status:"superseded", superseded_at:now}));
    }
  }
  await env.REVENUE_CRM_KV.put(`apikeys:${email}`, JSON.stringify([keyRecord]));

  stage = "entitlement_sync";
  // 2b. Entitlement sync — mirror the key into API_KEYS_KV, the namespace
  // intel-gateway's live auth path (resolveAuth()) actually reads on every
  // request. Without this, every customer provisioned here (manual payment
  // approval, trial activation, MSSP tenants, and now Razorpay Subscriptions)
  // received a key intel-gateway could never recognize — REVENUE_CRM_KV and
  // API_KEYS_KV are different namespaces intel-gateway never cross-reads.
  // Guarded so this is a no-op wherever the binding isn't configured.
  // Unprefixed key (the literal API key string), matching exactly how
  // intel-gateway's own provisionApiKey()/admin key issuance write this
  // namespace — required for resolveAuth()'s env.API_KEYS_KV.get(raw) lookup
  // to find it. real expires_at (currentPeriodEnd), not the null intel-gateway's
  // own one-time-order path issues today (a separate, pre-existing, and
  // out-of-scope-for-this-pass gap — see Production Readiness Report).
  if (env.API_KEYS_KV) {
    await env.API_KEYS_KV.put(key, JSON.stringify({
      key, tier, customer_id: custRecord.id, email,
      source: trial ? "trial" : "revenue_engine",
      created_at: now, expires_at: currentPeriodEnd,
      payment_metadata: { payment_id: payment_id || null, billing_cycle },
      ...gatewayTenantFields(tier, null),
    }));
  }

  stage = "subscription_record";
  // 3. Create subscription record
  const subRecord = {
    id:subId, customer_id:custRecord.id, email, tier, billing_cycle,
    status: trial ? SUB_STATUS.TRIAL : SUB_STATUS.ACTIVE,
    created_at:now, current_period_start:now, current_period_end:currentPeriodEnd,
    trial_ends_at:trialEndsAt, payment_id, renewal_reminder_sent:false, renewal_count:0,
    auto_renew:true, mssp_parent_id
  };
  await env.REVENUE_CRM_KV.put(`sub:${subId}`, JSON.stringify(subRecord));
  await env.REVENUE_CRM_KV.put(`sub:email:${email}`, JSON.stringify(subRecord));

  // Append to subscription index
  const subIdx = await env.REVENUE_CRM_KV.get("subscriptions:index", "json") || [];
  subIdx.unshift({ id:subId, email, tier, status:subRecord.status, current_period_end:currentPeriodEnd, created_at:now });
  await env.REVENUE_CRM_KV.put("subscriptions:index", JSON.stringify(subIdx.slice(0,1000)));

  stage = "welcome_email";
  // 4. Send welcome email with API key
  const portalToken = await computePortalToken(env, email);
  const welcomeVars = {
    email, tier, api_key:key, req_day:tierCfg.req_day, req_min:tierCfg.req_min,
    period_end:currentPeriodEnd, features:tierCfg.features.join(", "),
    dashboard_url:"https://intel.cyberdudebivash.com", api_docs_url:"https://intel.cyberdudebivash.com/api-docs.html",
    customer_id:custRecord.id, sub_id:subId,
    portal_url: portalToken
      ? `https://intel.cyberdudebivash.com/customer/api-keys.html?email=${encodeURIComponent(email)}&token=${portalToken}`
      : "https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html",
  };
  await queueEmail(env, { to:email, template:"welcome_provisioned", vars:welcomeVars });

  stage = "mrr_update";
  // 5. Update revenue MRR counter
  await updateMRR(env, tier, billing_cycle, "add");

  return { customer_id:custRecord.id, sub_id:subId, api_key:key, key_id:keyId, tier, period_end:currentPeriodEnd, features:tierCfg.features };
  } catch (err) {
    console.error(`[provisionCustomer] FAILED at stage=${stage} email=${email} tier=${tier} trial=${trial}: ${err?.message || err}`);
    await trackEvent(env, "provision_customer_failed", { stage, tier, trial }).catch(() => {});
    throw err;
  }
}

// =============================================================================
// API KEY MANAGEMENT (admin)
// =============================================================================
async function handleApiKeyGenerate(request, env, rid) {
  const body = await request.json().catch(() => ({}));
  const { email, tier, billing_cycle, payment_id, mssp_parent_id, trial } = body;
  const cleanEmail = sanitizeEmail(email);
  if (!cleanEmail) return json({ error:"invalid_email" }, 400);
  if (!tier || !TIERS[tier]) return json({ error:"invalid_tier" }, 400);
  const result = await provisionCustomer(env, { email:cleanEmail, tier, billing_cycle:billing_cycle||"monthly", payment_id:payment_id||null, mssp_parent_id:mssp_parent_id||null, trial:!!trial });
  return json({ success:true, ...result });
}

async function handleApiKeyListAll(request, env, rid) {
  const url  = new URL(request.url);
  const tier = url.searchParams.get("tier");
  const idx  = await env.REVENUE_CRM_KV.get("customers:index", "json") || [];
  const results = [];
  for (const c of idx.slice(0,100)) {
    const keys = await env.REVENUE_CRM_KV.get(`apikeys:${c.email}`, "json") || [];
    for (const k of keys) {
      if (!tier || k.tier === tier) results.push({ email:c.email, tier:k.tier, key_prefix:k.key.substring(0,20)+"...", status:k.status, expires_at:k.expires_at, req_day:k.req_day });
    }
  }
  return json({ count:results.length, keys:results });
}

async function handleApiKeyRotate(request, env, rid) {
  const body = await request.json().catch(() => ({}));
  const { email } = body;
  const cleanEmail = sanitizeEmail(email);
  if (!cleanEmail) return json({ error:"invalid_email" }, 400);
  const cust = await env.REVENUE_CRM_KV.get(`customer:${cleanEmail}`, "json");
  if (!cust) return json({ error:"customer_not_found" }, 404);

  const now = new Date().toISOString();
  const oldKeys = await env.REVENUE_CRM_KV.get(`apikeys:${cleanEmail}`, "json") || [];
  const newKey = generateApiKey(cust.tier);
  const newKeyId = genId("key");
  const tierCfg = TIERS[cust.tier] || TIERS.PRO;

  // Revoke all old keys
  for (const ok of oldKeys) {
    await env.REVENUE_CRM_KV.put(`apikey:${ok.key}`, JSON.stringify({...ok, status:"rotated", rotated_at:now}));
  }

  const newRecord = {
    id:newKeyId, key:newKey, tier:cust.tier, status:"active", email:cleanEmail,
    customer_id:cust.id, created_at:now, expires_at:cust.current_period_end,
    req_day:tierCfg.req_day, req_min:tierCfg.req_min, features:tierCfg.features,
    rotation_count:(oldKeys[0]?.rotation_count||0)+1
  };
  await env.REVENUE_CRM_KV.put(`apikey:${newKey}`, JSON.stringify(newRecord));
  await env.REVENUE_CRM_KV.put(`apikeys:${cleanEmail}`, JSON.stringify([newRecord]));

  // Entitlement sync -- mirrors provisionCustomer()'s existing API_KEYS_KV
  // write (see its comment above): REVENUE_CRM_KV is not what intel-gateway's
  // resolveAuth() reads on each request, so a rotation that only updated
  // REVENUE_CRM_KV left the old key fully live against the production
  // gateway and the new key unable to authenticate at all. Guarded the same
  // way provisionCustomer() is, so this stays a no-op wherever the binding
  // isn't configured.
  if (env.API_KEYS_KV) {
    // Read the gateway record before deleting it, so the MSSP tenant mode
    // is carried rather than silently reset to unrestricted.
    let previous = null;
    for (const ok of oldKeys) {
      if (previous) break;
      try { previous = await env.API_KEYS_KV.get(ok.key, "json"); } catch (_) { previous = null; }
    }
    for (const ok of oldKeys) {
      await env.API_KEYS_KV.delete(ok.key);
    }
    await env.API_KEYS_KV.put(newKey, JSON.stringify({
      key: newKey, tier: cust.tier, customer_id: cust.id, email: cleanEmail,
      source: "revenue_engine_rotation",
      created_at: now, expires_at: cust.current_period_end,
      ...gatewayTenantFields(cust.tier, previous),
    }));
  }

  await appendAuditLog(env, { action:"key_rotated", email:cleanEmail, new_key_prefix:newKey.substring(0,16), ts:now });
  await queueEmail(env, { to:cleanEmail, template:"key_rotated", vars:{ new_key:newKey, tier:cust.tier } });

  return json({ success:true, new_key:newKey, old_key_prefix:oldKeys[0]?.key?.substring(0,16)||"—", tier:cust.tier, expires_at:cust.current_period_end });
}

async function handleApiKeyRevoke(request, env, rid) {
  const body = await request.json().catch(() => ({}));
  const { email, reason } = body;
  const cleanEmail = sanitizeEmail(email);
  if (!cleanEmail) return json({ error:"invalid_email" }, 400);
  const keys = await env.REVENUE_CRM_KV.get(`apikeys:${cleanEmail}`, "json") || [];
  const now = new Date().toISOString();
  for (const k of keys) {
    await env.REVENUE_CRM_KV.put(`apikey:${k.key}`, JSON.stringify({...k, status:"revoked", revoked_at:now, revocation_reason:reason||"admin_action"}));
  }
  await env.REVENUE_CRM_KV.put(`apikeys:${cleanEmail}`, JSON.stringify(keys.map(k => ({...k, status:"revoked"}))));
  const cust = await env.REVENUE_CRM_KV.get(`customer:${cleanEmail}`, "json");
  if (cust) await env.REVENUE_CRM_KV.put(`customer:${cleanEmail}`, JSON.stringify({...cust, status:"suspended", suspended_at:now}));

  // Entitlement sync -- see the matching comment in handleApiKeyRotate above:
  // without this, a "revoked" key kept authenticating against the live
  // gateway (API_KEYS_KV) until it naturally expired, regardless of what
  // REVENUE_CRM_KV said. Guarded the same way provisionCustomer() is.
  if (env.API_KEYS_KV) {
    for (const k of keys) {
      await env.API_KEYS_KV.delete(k.key);
    }
  }

  await appendAuditLog(env, { action:"key_revoked", email:cleanEmail, reason:reason||"admin_action", ts:now });
  return json({ success:true, keys_revoked:keys.length, email:cleanEmail });
}

// =============================================================================
// SELF-SERVICE KEY ROTATION
// handleApiKeyRotate above is admin-only (isAdmin() gate at dispatch) and
// identifies the target customer by an email supplied in the request body --
// fine for a support desk, unsafe to expose to a browser/script directly,
// since nothing there proves the caller owns that email. This route proves
// ownership the only way a public API allows: the caller must present their
// own currently-active key. It then calls handleApiKeyRotate completely
// unchanged (Reuse Before Build, priority 1: call the existing function
// unchanged) with the verified email, so entitlement sync (API_KEYS_KV),
// audit logging, and the "key_rotated" notification email all stay identical
// to the admin path with zero duplicated logic.
//
// Deliberately rotation-only, not revocation: handleApiKeyRevoke also sets
// the customer record to "suspended" (an account-level action appropriate
// for admin/fraud handling), which isn't what a customer wants when they
// just need to kill a leaked key -- rotation already does that immediately
// (the old key is deleted from API_KEYS_KV / marked "rotated" the moment the
// new one is issued), without the account-suspension side effect.
// =============================================================================
async function handleApiKeySelfRotate(request, env, rid) {
  const key = request.headers.get("X-API-Key") || (request.headers.get("Authorization") || "").replace("Bearer ", "");
  if (!key) return json({ error: "X-API-Key header (your current active key) is required" }, 401);
  const rec = await env.REVENUE_CRM_KV.get(`apikey:${key}`, "json");
  if (!rec || rec.status !== "active") return json({ error: "invalid_or_inactive_key" }, 401);

  const proxied = new Request(request.url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: rec.email }),
  });
  return await handleApiKeyRotate(proxied, env, rid);
}

// =============================================================================
// CUSTOMER MANAGEMENT (admin)
// =============================================================================
async function handleCustomerList(request, env, rid) {
  const url = new URL(request.url);
  const tier = url.searchParams.get("tier");
  const idx  = await env.REVENUE_CRM_KV.get("customers:index", "json") || [];
  const filtered = tier ? idx.filter(c => c.tier === tier) : idx;
  return json({ count:filtered.length, customers:filtered.slice(0,200) });
}

async function handleCustomerGet(request, env, rid, email) {
  const cleanEmail = sanitizeEmail(decodeURIComponent(email));
  if (!cleanEmail) return json({ error:"invalid_email" }, 400);
  const cust = await env.REVENUE_CRM_KV.get(`customer:${cleanEmail}`, "json");
  if (!cust) return json({ error:"not_found" }, 404);
  const keys = await env.REVENUE_CRM_KV.get(`apikeys:${cleanEmail}`, "json") || [];
  const sub  = await env.REVENUE_CRM_KV.get(`sub:email:${cleanEmail}`, "json");
  return json({ customer:cust, subscription:sub, api_keys:keys.map(k => ({...k, key:k.key.substring(0,20)+"..."})) });
}

async function handleCustomerUpdate(request, env, rid, email) {
  const cleanEmail = sanitizeEmail(decodeURIComponent(email));
  const body = await request.json().catch(() => ({}));
  const cust = await env.REVENUE_CRM_KV.get(`customer:${cleanEmail}`, "json");
  if (!cust) return json({ error:"not_found" }, 404);
  const updated = { ...cust, ...body, email:cleanEmail, updated_at:new Date().toISOString() };
  await env.REVENUE_CRM_KV.put(`customer:${cleanEmail}`, JSON.stringify(updated));
  return json({ success:true, customer:updated });
}

async function handleCustomerProvision(request, env, rid) {
  const body = await request.json().catch(() => ({}));
  const { email, tier, billing_cycle, payment_id, mssp_parent_id, trial } = body;
  const cleanEmail = sanitizeEmail(email);
  if (!cleanEmail || !tier || !TIERS[tier]) return json({ error:"invalid_params" }, 400);
  const result = await provisionCustomer(env, { email:cleanEmail, tier, billing_cycle:billing_cycle||"monthly", payment_id, mssp_parent_id, trial:!!trial });
  return json({ success:true, ...result });
}

async function handleCustomerPortal(request, env, rid) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token"); // token = HMAC of email (for simple auth)
  const email = url.searchParams.get("email");
  const cleanEmail = sanitizeEmail(email);
  if (!cleanEmail) return json({ error:"invalid_email" }, 400);
  const expectedToken = await computePortalToken(env, cleanEmail);
  if (!expectedToken) return json({ error:"portal_not_configured" }, 500);
  if (!token || !timingSafeEqual(token, expectedToken)) {
    return json({ error:"unauthorized", message:"Invalid or missing portal token. Use the link from your welcome email." }, 401);
  }
  const cust = await env.REVENUE_CRM_KV.get(`customer:${cleanEmail}`, "json");
  if (!cust) return json({ error:"not_found", message:"No account found. Check your email or subscribe at /PAYMENT-GATEWAY.html" }, 404);
  const keys = await env.REVENUE_CRM_KV.get(`apikeys:${cleanEmail}`, "json") || [];
  const sub  = await env.REVENUE_CRM_KV.get(`sub:email:${cleanEmail}`, "json");
  const tierCfg = TIERS[cust.tier] || TIERS.FREE;
  // Mask key for security
  const maskedKeys = keys.map(k => ({ id:k.id, key_masked:k.key.substring(0,10)+"••••••••••••••••"+k.key.slice(-4), tier:k.tier, status:k.status, expires_at:k.expires_at, req_day:k.req_day, req_min:k.req_min }));
  return json({ customer:{ ...cust }, subscription:sub, api_keys:maskedKeys, tier_config:{ features:tierCfg.features, req_day:tierCfg.req_day, req_min:tierCfg.req_min }, upgrade_url:"/PAYMENT-GATEWAY.html" });
}

// =============================================================================
// SUBSCRIPTION LIFECYCLE
// =============================================================================
async function handleSubList(request, env, rid) {
  const url    = new URL(request.url);
  const status = url.searchParams.get("status");
  const idx    = await env.REVENUE_CRM_KV.get("subscriptions:index", "json") || [];
  const now    = new Date();
  const enriched = idx.map(s => {
    const daysLeft = Math.ceil((new Date(s.current_period_end) - now) / 86400000);
    return { ...s, days_remaining:daysLeft, expiring_soon: daysLeft <= 7 && daysLeft > 0, overdue: daysLeft < 0 };
  });
  const filtered = status ? enriched.filter(s => s.status === status) : enriched;
  const expiringSoon = enriched.filter(s => s.days_remaining > 0 && s.days_remaining <= 14 && s.status === SUB_STATUS.ACTIVE);
  return json({ count:filtered.length, expiring_soon_count:expiringSoon.length, subscriptions:filtered.slice(0,200) });
}

async function handleSubGet(request, env, rid, subId) {
  const rec = await env.REVENUE_CRM_KV.get(`sub:${subId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  const now = new Date();
  const daysLeft = Math.ceil((new Date(rec.current_period_end) - now) / 86400000);
  return json({ ...rec, days_remaining:daysLeft });
}

async function handleSubUpdate(request, env, rid, subId) {
  const body = await request.json().catch(() => ({}));
  const rec  = await env.REVENUE_CRM_KV.get(`sub:${subId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  const updated = { ...rec, ...body, id:subId, updated_at:new Date().toISOString() };
  await env.REVENUE_CRM_KV.put(`sub:${subId}`, JSON.stringify(updated));
  await env.REVENUE_CRM_KV.put(`sub:email:${rec.email}`, JSON.stringify(updated));
  return json({ success:true, subscription:updated });
}

async function handleSubExpireCheck(request, env, rid) {
  // Called by cron: check all subscriptions, mark expiring/expired, send reminders
  const idx = await env.REVENUE_CRM_KV.get("subscriptions:index", "json") || [];
  const now = new Date();
  let reminded=0, expired=0, suspended=0;
  for (const s of idx) {
    if (s.status === SUB_STATUS.CANCELLED || s.status === SUB_STATUS.EXPIRED) continue;
    const rec = await env.REVENUE_CRM_KV.get(`sub:${s.id}`, "json");
    if (!rec) continue;
    const daysLeft = Math.ceil((new Date(rec.current_period_end) - now) / 86400000);
    if (daysLeft === 7 && !rec.renewal_reminder_sent) {
      await queueEmail(env, { to:rec.email, template:"renewal_reminder_7d", vars:{ tier:rec.tier, days:7, renew_url:"https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?renew="+rec.id } });
      // Phase 2: patchInternalSub (subscription-engine.js) keeps sub:{id},
      // sub:email:{email}, and subscriptions:index consistent -- the direct
      // REVENUE_CRM_KV.put this replaces only ever updated sub:{id}, leaving
      // sub:email:{email}-based reads (and the index) permanently stale.
      await patchInternalSub(env, s.id, { renewal_reminder_sent:true, reminder_sent_at:now.toISOString() });
      reminded++;
    }
    if (daysLeft === 3) {
      await queueEmail(env, { to:rec.email, template:"renewal_reminder_3d", vars:{ tier:rec.tier, days:3, renew_url:"https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?renew="+rec.id } });
      reminded++;
    }
    if (daysLeft <= 0 && rec.status === SUB_STATUS.ACTIVE) {
      // Phase 2: tryTransition (subscription-engine.js) validates ACTIVE ->
      // EXPIRED against the evidence-based transition graph before applying
      // it, and patchInternalSub keeps sub:{id}/sub:email:{email}/
      // subscriptions:index consistent -- replacing the direct REVENUE_CRM_KV
      // writes this loop used to do inline (which never touched the index,
      // so it silently went stale after every expiry).
      await tryTransition(env, s.id, SUB_STATUS.EXPIRED, { expired_at: now.toISOString() }, rid);
      // Suspend API key. The REVENUE_CRM_KV write above is this Worker's own
      // bookkeeping copy -- kept as-is. It does NOT reach intel-gateway's
      // resolveAuth(), which reads API_KEYS_KV and checks `expires_at`, not a
      // `status` field, so it never actually enforced anything. Added the
      // missing patchApiKeyEntitlement() call (already correct, already used
      // by the Subscriptions webhook path) to close that gap.
      const keys = await env.REVENUE_CRM_KV.get(`apikeys:${rec.email}`, "json") || [];
      for (const k of keys) {
        await env.REVENUE_CRM_KV.put(`apikey:${k.key}`, JSON.stringify({...k, status:"expired"}));
        try { await patchApiKeyEntitlement(env, k.key, { expires_at: now.toISOString() }); } catch {}
      }
      await queueEmail(env, { to:rec.email, template:"subscription_expired", vars:{ tier:rec.tier, renew_url:"https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html?renew="+rec.id } });
      await updateMRR(env, rec.tier, rec.billing_cycle, "remove");
      expired++;
    }
  }
  return json({ processed:idx.length, reminded, expired, suspended });
}

// =============================================================================
// MSSP TENANT MANAGEMENT
// =============================================================================
async function handleMSSPTenantList(request, env, rid) {
  const url = new URL(request.url);
  const msspEmail = url.searchParams.get("mssp_email");
  const idx = await env.REVENUE_CRM_KV.get("mssp:tenants:index", "json") || [];
  const filtered = msspEmail ? idx.filter(t => t.mssp_email === msspEmail) : idx;
  return json({ count:filtered.length, tenants:filtered.slice(0,500) });
}

async function handleMSSPTenantCreate(request, env, rid) {
  const body = await request.json().catch(() => ({}));
  const { mssp_email, tenant_name, tenant_email, tenant_tier, sector, quota_req_day, white_label_slug } = body;
  const cleanMSSP = sanitizeEmail(mssp_email);
  const cleanTenant = sanitizeEmail(tenant_email);
  if (!cleanMSSP || !cleanTenant || !tenant_name) return json({ error:"invalid_params" }, 400);

  // Verify MSSP is valid customer
  const mssp = await env.REVENUE_CRM_KV.get(`customer:${cleanMSSP}`, "json");
  if (!mssp || mssp.tier !== "MSSP") return json({ error:"mssp_account_not_found_or_not_mssp_tier" }, 403);

  const tenantId = genId("ten");
  const now = new Date().toISOString();
  const tenantTier = tenant_tier || "ENTERPRISE";
  const tierCfg = TIERS[tenantTier] || TIERS.ENTERPRISE;

  // Provision tenant's API key under MSSP namespace
  const key = generateApiKey(tenantTier, `MSSP-${white_label_slug || cleanMSSP.split("@")[0].substring(0,8).toUpperCase()}`);
  const keyId = genId("key");
  const tenantKeyRecord = {
    id:keyId, key, tier:tenantTier, status:"active", email:cleanTenant,
    mssp_parent_id:mssp.id, mssp_email:cleanMSSP, created_at:now,
    expires_at:mssp.current_period_end,
    req_day:quota_req_day || Math.floor(tierCfg.req_day * 0.3),
    req_min:Math.floor(tierCfg.req_min * 0.3),
    features:tierCfg.features, rotation_count:0
  };
  await env.REVENUE_CRM_KV.put(`apikey:${key}`, JSON.stringify(tenantKeyRecord));
  await env.REVENUE_CRM_KV.put(`apikeys:${cleanTenant}`, JSON.stringify([tenantKeyRecord]));

  const tenantRecord = {
    id:tenantId, mssp_email:cleanMSSP, mssp_id:mssp.id, tenant_name, tenant_email:cleanTenant,
    tenant_tier:tenantTier, sector:sector||"general", status:"active", api_key_id:keyId,
    api_key_preview:key.substring(0,20)+"...", quota_req_day:tenantKeyRecord.req_day,
    white_label_slug:white_label_slug||null, created_at:now, activated_at:now,
    api_calls_total:0, last_call_at:null
  };
  await env.REVENUE_CRM_KV.put(`mssp:tenant:${tenantId}`, JSON.stringify(tenantRecord));

  // MSSP tenant index
  const idx = await env.REVENUE_CRM_KV.get("mssp:tenants:index", "json") || [];
  idx.unshift({ id:tenantId, mssp_email:cleanMSSP, tenant_name, tenant_email:cleanTenant, status:"active", created_at:now });
  await env.REVENUE_CRM_KV.put("mssp:tenants:index", JSON.stringify(idx.slice(0,1000)));

  // Welcome tenant
  await queueEmail(env, { to:cleanTenant, template:"mssp_tenant_welcome", vars:{ tenant_name, api_key:key, tier:tenantTier, req_day:tenantKeyRecord.req_day, mssp_name:cleanMSSP } });
  await slackNotify(env, `🏢 *NEW MSSP TENANT* — ${tenant_name} (${cleanTenant})\nMSSP: ${cleanMSSP} | Tier: ${tenantTier} | Quota: ${tenantKeyRecord.req_day} req/day`);

  return json({ success:true, tenant_id:tenantId, api_key:key, tenant:tenantRecord });
}

async function handleMSSPTenantGet(request, env, rid, tenantId) {
  const rec = await env.REVENUE_CRM_KV.get(`mssp:tenant:${tenantId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  return json(rec);
}

async function handleMSSPTenantUpdate(request, env, rid, tenantId) {
  const body = await request.json().catch(() => ({}));
  const rec  = await env.REVENUE_CRM_KV.get(`mssp:tenant:${tenantId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  const updated = { ...rec, ...body, id:tenantId, updated_at:new Date().toISOString() };
  await env.REVENUE_CRM_KV.put(`mssp:tenant:${tenantId}`, JSON.stringify(updated));
  // Update quota on API key if changed
  if (body.quota_req_day && rec.api_key_id) {
    const keys = await env.REVENUE_CRM_KV.get(`apikeys:${rec.tenant_email}`, "json") || [];
    for (const k of keys) {
      await env.REVENUE_CRM_KV.put(`apikey:${k.key}`, JSON.stringify({...k, req_day:body.quota_req_day}));
    }
    await env.REVENUE_CRM_KV.put(`apikeys:${rec.tenant_email}`, JSON.stringify(keys.map(k => ({...k, req_day:body.quota_req_day}))));
  }
  return json({ success:true, tenant:updated });
}

async function handleMSSPTenantRevoke(request, env, rid, tenantId) {
  const rec = await env.REVENUE_CRM_KV.get(`mssp:tenant:${tenantId}`, "json");
  if (!rec) return json({ error:"not_found" }, 404);
  const now = new Date().toISOString();
  const updated = { ...rec, status:"revoked", revoked_at:now };
  await env.REVENUE_CRM_KV.put(`mssp:tenant:${tenantId}`, JSON.stringify(updated));
  const keys = await env.REVENUE_CRM_KV.get(`apikeys:${rec.tenant_email}`, "json") || [];
  for (const k of keys) await env.REVENUE_CRM_KV.put(`apikey:${k.key}`, JSON.stringify({...k, status:"revoked"}));
  return json({ success:true, tenant_id:tenantId, status:"revoked" });
}

// =============================================================================
// CUSTOMER SUCCESS TRACKING
// =============================================================================
async function handleSuccessScores(request, env, rid) {
  const custIdx = await env.REVENUE_CRM_KV.get("customers:index", "json") || [];
  const scored = [];
  for (const c of custIdx.slice(0,50)) {
    const cust = await env.REVENUE_CRM_KV.get(`customer:${c.email}`, "json");
    if (!cust) continue;
    const sub  = await env.REVENUE_CRM_KV.get(`sub:email:${c.email}`, "json");
    const daysSinceCreate = Math.ceil((Date.now() - new Date(cust.created_at).getTime()) / 86400000);
    const daysRemaining = sub ? Math.ceil((new Date(sub.current_period_end) - Date.now()) / 86400000) : 0;
    let score = 0;
    if (cust.onboarding_completed) score += 20;
    if (cust.first_api_call_at) score += 30;
    if (cust.first_report_access_at) score += 20;
    if (cust.api_calls_total > 100) score += 15;
    if (cust.api_calls_total > 1000) score += 15;
    const health = score >= 80 ? "healthy" : score >= 50 ? "at_risk" : "critical";
    const renewal_ready = daysRemaining > 0 && daysRemaining <= 30 && health === "healthy";
    const expansion_ready = cust.api_calls_total > 500 && cust.tier !== "ENTERPRISE";
    scored.push({ email:c.email, tier:c.tier, health_score:score, health, days_remaining:daysRemaining, renewal_ready, expansion_ready, api_calls:cust.api_calls_total, onboarded:cust.onboarding_completed, first_api_call:cust.first_api_call_at });
  }
  scored.sort((a,b) => a.health_score - b.health_score);
  return json({ total:scored.length, healthy:scored.filter(s=>s.health==="healthy").length, at_risk:scored.filter(s=>s.health==="at_risk").length, critical:scored.filter(s=>s.health==="critical").length, customers:scored });
}

async function handleAtRisk(request, env, rid) {
  const custIdx = await env.REVENUE_CRM_KV.get("customers:index", "json") || [];
  const at_risk = [];
  for (const c of custIdx.slice(0,100)) {
    const sub = await env.REVENUE_CRM_KV.get(`sub:email:${c.email}`, "json");
    if (!sub) continue;
    const daysLeft = Math.ceil((new Date(sub.current_period_end) - Date.now()) / 86400000);
    if (daysLeft <= 14 && daysLeft > 0 && sub.status === SUB_STATUS.ACTIVE) {
      at_risk.push({ email:c.email, tier:c.tier, days_remaining:daysLeft, sub_id:sub.id, renew_url:`/PAYMENT-GATEWAY.html?renew=${sub.id}&email=${c.email}` });
    }
  }
  return json({ count:at_risk.length, at_risk });
}

// =============================================================================
// COMMERCIAL ANALYTICS DASHBOARD
// =============================================================================
async function handleCommercialDashboard(request, env, rid) {
  const custIdx = await env.REVENUE_CRM_KV.get("customers:index", "json") || [];
  const subIdx  = await env.REVENUE_CRM_KV.get("subscriptions:index", "json") || [];
  const payIdx  = await env.REVENUE_CRM_KV.get("payments:index", "json") || [];

  const now = new Date();
  const tierCounts = { FREE:0, PRO:0, ENTERPRISE:0, MSSP:0 };
  for (const c of custIdx) { if (tierCounts[c.tier] !== undefined) tierCounts[c.tier]++; }

  // FIX (P0, 2026-09-10): this table still carried the pre-2026-08-31 wrong
  // prices (PRO $99, ENTERPRISE $999 -- ~2x the real $49/$499) after the
  // 2026-08-31 monetization audit reconciled the TIERS constant above
  // (line ~1550, canonical vs. config/subscription_tiers.json) but missed
  // this second, independent duplicate -- so the Commercial Analytics
  // Dashboard's mrr_usd/arr_usd have been silently ~2x-inflated for every
  // PRO/ENTERPRISE customer since. Reusing TIERS directly (single source of
  // truth) instead of a second hardcoded copy so this can't drift again.
  const tierPrices = { FREE:0, PRO:TIERS.PRO.price_usd, ENTERPRISE:TIERS.ENTERPRISE.price_usd, MSSP:TIERS.MSSP.price_usd };
  const mrr = (tierCounts.PRO * tierPrices.PRO) + (tierCounts.ENTERPRISE * tierPrices.ENTERPRISE) + (tierCounts.MSSP * tierPrices.MSSP);
  const arr = mrr * 12;

  const activeCount   = subIdx.filter(s => s.status === SUB_STATUS.ACTIVE).length;
  const trialCount    = subIdx.filter(s => s.status === SUB_STATUS.TRIAL).length;
  const expiredCount  = subIdx.filter(s => s.status === SUB_STATUS.EXPIRED).length;
  const expiringSoon  = subIdx.filter(s => { const d=Math.ceil((new Date(s.current_period_end)-now)/86400000); return d>0&&d<=14&&s.status===SUB_STATUS.ACTIVE; }).length;
  const pendingPayments = payIdx.filter(p => p.status === PAYMENT_STATUS.PENDING).length;
  const approvedPayments = payIdx.filter(p => p.status === PAYMENT_STATUS.APPROVED).length;

  const tenantIdx = await env.REVENUE_CRM_KV.get("mssp:tenants:index", "json") || [];
  const msspRevenue = tierCounts.MSSP * tierPrices.MSSP + tenantIdx.filter(t=>t.status==="active").length * 149;

  return json({ generated_at:now.toISOString(), revenue:{ mrr_usd:mrr, arr_usd:arr, mrr_inr:mrr*83, arr_inr:arr*83 }, customers:{ total:custIdx.length, by_tier:tierCounts }, subscriptions:{ active:activeCount, trial:trialCount, expiring_soon:expiringSoon, expired:expiredCount }, payments:{ pending:pendingPayments, approved:approvedPayments, total:payIdx.length }, mssp:{ partners:tierCounts.MSSP, tenants:tenantIdx.filter(t=>t.status==="active").length, revenue_usd:msspRevenue } });
}

// =============================================================================
// HELPERS
// =============================================================================
// MSSP tenant authorization fields for an intel-gateway API_KEYS_KV record
// (intel-gateway mssp-tenants.js). A new MSSP key starts self-service with
// zero tenants (tenant_auth_version 2), never unrestricted. A rotation
// carries the previous record's mode exactly: an explicit list stays that
// list (malformed stays fail-closed []), a legacy record (no field) stays
// legacy, and a self-service key keeps its owner (customer_id), which is
// where its tenants live -- so rotation never drops or widens tenants.
function gatewayTenantFields(tier, previous) {
  // Carried only for the same tier: an upgrade to MSSP starts self-service.
  if (previous && typeof previous === "object" && previous.tier === tier) {
    if (previous.managed_tenants === undefined) return {};
    const out = { managed_tenants: Array.isArray(previous.managed_tenants) ? previous.managed_tenants : [] };
    if (previous.tenant_auth_version === 2) {
      out.tenant_auth_version = 2;
      if (previous.customer_id) out.customer_id = previous.customer_id;
    }
    return out;
  }
  return tier === "MSSP" ? { managed_tenants: [], tenant_auth_version: 2 } : {};
}

function generateApiKey(tier, prefix) {
  const tPrefix = prefix || { FREE:"CDB-FREE", PRO:"CDB-PRO", ENTERPRISE:"CDB-ENT", MSSP:"CDB-MSSP" }[tier] || "CDB-PRO";
  const buf = crypto.getRandomValues(new Uint8Array(12));
  const hex = [...buf].map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();
  const checksum = (buf.reduce((a,b)=>a^b,0)).toString(16).padStart(4,"0").toUpperCase();
  return `${tPrefix}-${hex}-${checksum}`;
}

async function updateMRR(env, tier, billing_cycle, action) {
  // FIX (P0, 2026-09-10): same stale duplicate as handleCommercialDashboard's
  // tierPrices above (PRO $99/ENTERPRISE $999 vs. real $49/$499) -- this one
  // is worse, since it mutates the persisted revenue:mrr_usd KV ledger on
  // every subscription add/remove (call sites: line ~2017, ~2307), so the
  // error compounded with every subscription event rather than just
  // mis-displaying at read time. Reusing the canonical TIERS constant.
  const price = { FREE:0, PRO:TIERS.PRO.price_usd, ENTERPRISE:TIERS.ENTERPRISE.price_usd, MSSP:TIERS.MSSP.price_usd }[tier] || 0;
  const monthly = billing_cycle === "annual" ? price : price;
  const key = "revenue:mrr_usd";
  const curr = parseFloat(await env.REVENUE_CRM_KV.get(key) || "0");
  const updated = action === "add" ? curr + monthly : Math.max(0, curr - monthly);
  await env.REVENUE_CRM_KV.put(key, String(updated));
}

async function appendAuditLog(env, entry) {
  const day = new Date().toISOString().slice(0,10);
  const key = `audit:${day}`;
  const log = await env.REVENUE_CRM_KV.get(key, "json") || [];
  log.push({ ...entry, logged_at: new Date().toISOString() });
  await env.REVENUE_CRM_KV.put(key, JSON.stringify(log.slice(-200)), { expirationTtl: 86400 * 90 });
}

// Email template definitions (extend existing getEmailTemplate)
const COMMERCIAL_EMAIL_TEMPLATES = {
  free_key_welcome: (v) => ({ subject:`Your SENTINEL APEX Free API Key`, html:`<h2>Your Free API Key</h2><p>Key: <code>${v.api_key}</code></p><p>Rate limit: ${v.req_day} requests/day</p><p><a href="${v.upgrade_url}">Upgrade to PRO</a> for full IOC access, Sigma/YARA rules, and more.</p>` }),
  payment_received: (v) => ({ subject:`Payment Received — Reference: ${v.payment_id}`, html:`<h2>Payment Under Review</h2><p>We've received your payment for <strong>${v.plan}</strong> via ${v.method}. Verification typically takes within ${v.expected_hours} business hours.</p><p>Reference: <strong>${v.payment_id}</strong></p>` }),
  payment_rejected: (v) => ({ subject:`Payment Could Not Be Verified`, html:`<h2>Payment Verification Issue</h2><p>Unfortunately we couldn't verify your payment: ${v.reason}</p><p><a href="${v.retry_url}">Try again</a> or contact us at support@cyberdudebivash.in</p>` }),
  welcome_provisioned: (v) => ({ subject:`🔑 Your SENTINEL APEX ${v.tier} API Key is Ready`, html:`<h2>Welcome to SENTINEL APEX ${v.tier}</h2><p>Your API key: <code>${v.api_key}</code></p><p>Rate limit: ${v.req_day} requests/day, ${v.req_min} req/min</p><p>Valid until: ${v.period_end}</p><p>Features: ${v.features}</p><p><a href="${v.api_docs_url}">API Documentation</a> | <a href="${v.dashboard_url}">Platform Dashboard</a></p><p>Customer ID: ${v.customer_id}</p>` }),
  key_rotated: (v) => ({ subject:`API Key Rotated — SENTINEL APEX ${v.tier}`, html:`<h2>Your API key has been rotated</h2><p>New key: <code>${v.new_key}</code></p><p>Your old key has been deactivated. Update your integrations now.</p>` }),
  renewal_reminder_7d: (v) => ({ subject:`⚠️ Your ${v.tier} subscription expires in ${v.days} days`, html:`<h2>Subscription Expiring Soon</h2><p>Your SENTINEL APEX ${v.tier} plan expires in ${v.days} days. <a href="${v.renew_url}">Renew now</a> to keep your API key active.</p>` }),
  renewal_reminder_3d: (v) => ({ subject:`🚨 Final Reminder: ${v.tier} expires in ${v.days} days`, html:`<h2>Last Chance — Renew Today</h2><p>Your API key will stop working in ${v.days} days. <a href="${v.renew_url}">Renew immediately</a>.</p>` }),
  subscription_expired: (v) => ({ subject:`Subscription Expired — API Key Deactivated`, html:`<h2>Your SENTINEL APEX ${v.tier} has expired</h2><p>Your API key has been deactivated. <a href="${v.renew_url}">Renew now</a> to restore access.</p>` }),
  mssp_tenant_welcome: (v) => ({ subject:`Welcome to ${v.mssp_name} Threat Intelligence (Powered by SENTINEL APEX)`, html:`<h2>Welcome, ${v.tenant_name}</h2><p>Your threat intelligence API key: <code>${v.api_key}</code></p><p>Rate limit: ${v.req_day} requests/day</p>` }),
};

// Commercial template lookup, falling back to the cold-outreach template set
// (getEmailTemplate, declared above). Previously this re-declared
// getEmailTemplate itself (same name, same top-level scope) — harmless under
// permissive script parsing but a hard "Identifier has already been declared"
// SyntaxError the moment this file is parsed as an ECMAScript module (which it
// already is, per the `export default` below), and would have infinitely
// recursed even if it had parsed, since the hoisted duplicate declaration
// meant _origGetEmailTemplate captured a reference to itself, not to the
// original template function. Renamed and fixed; queueEmail() (its one
// caller) updated accordingly.
function getCommercialEmailTemplate(name, vars) {
  if (COMMERCIAL_EMAIL_TEMPLATES[name]) {
    const t = COMMERCIAL_EMAIL_TEMPLATES[name](vars);
    return { subject:t.subject, html:t.html, text:t.html.replace(/<[^>]+>/g,"") };
  }
  return getEmailTemplate(name, vars);
}

// =============================================================================
// END PHASE 2 COMMERCIAL OPERATIONS
// =============================================================================

// =============================================================================
// NAMED EXPORTS — for subscription-engine.js (Razorpay Subscriptions, Phase 2
// foundational subsystem). Purely additive: the existing `export default`
// entry point above is unchanged, and nothing previously imported named
// exports from this file (it had none), so this introduces zero backward-
// compatibility risk. Exposes the canonical implementations so
// subscription-engine.js calls them rather than re-implementing customer
// provisioning, tier config, or subscription status logic in parallel.
// =============================================================================
export {
  json, sanitizeEmail, genId, TIERS, SUB_STATUS,
  provisionCustomer, trackEvent, isAdmin, automationTrigger, slackNotify, timingSafeEqual,
  handlePaymentSubmit, sanitizeScreenshotUrl, gatewayTenantFields,
};
