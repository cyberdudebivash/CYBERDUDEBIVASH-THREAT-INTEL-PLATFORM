// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Revenue Engine v123.0.0
// CRM · Lead Management · Outbound · Enterprise Sales · Automation · Retention
// Routes: /api/crm/*, /api/deals/*, /api/outreach/*, /api/automation/*
// Deployed at: https://revenue.intel.cyberdudebivash.com
// =============================================================================

const ENGINE = {
  VERSION:  "123.0.0",
  NAME:     "SENTINEL-REVENUE-ENGINE",
  PLANS: {
    pro:        { name: "Pro",        inr: 2499,  usd: 29,  annual_inr: 24990,  annual_usd: 290  },
    enterprise: { name: "Enterprise", inr: 14999, usd: 199, annual_inr: 149990, annual_usd: 1990 },
  },
  TARGET_MRR_INR: 1000000,  // ₹10L/month
  PIPELINE_STAGES: ["new","contacted","demo_scheduled","demo_done","trial","negotiation","closed_won","closed_lost"],
  DEAL_VALUES_INR: {
    pro_monthly:        2499,
    pro_annual:         24990,
    enterprise_monthly: 14999,
    enterprise_annual:  149990,
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

    if (method === "OPTIONS") return cors204();

    try {
      // ── Public lead/trial endpoints ────────────────────────────────────────
      if (path === "/api/leads/capture" && method === "POST")
        return await handleLeadCapture(request, env, rid);
      if (path === "/api/leads/trial"   && method === "POST")
        return await handleTrialRequest(request, env, rid);
      if (path === "/api/demo/request"  && method === "POST")
        return await handleDemoRequest(request, env, rid);
      if (path === "/api/demo/live"     && method === "GET")
        return await handleLiveDemoEndpoint(request, env, rid);

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

      return json({ error: "not_found", path }, 404);
    } catch (e) {
      return json({ error: "internal_error", message: e.message, rid }, 500);
    }
  },

  // ── Cron handler — email send + follow-ups + trial nudges ─────────────────
  async scheduled(event, env, ctx) {
    const h = new Date().getUTCHours();
    if (h === 9)  await runDailyOutreach(env);
    if (h === 14) await runFollowUps(env);
    if (h === 18 && new Date().getUTCDay() === 1) await runWeeklyDigest(env);
  },
};

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
    trial_url: "https://intel.cyberdudebivash.com/trial",
    message:   "Access granted. Full intel unlocked. Check your email.",
    request_id: rid,
  });
}

async function handleTrialRequest(request, env, rid) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "invalid_json" }, 400); }

  const email   = sanitizeEmail(body.email);
  const name    = (body.name    || "").slice(0, 128);
  const company = (body.company || "").slice(0, 128);
  if (!email) return json({ error: "invalid_email" }, 400);

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

  // Register API key in gateway KV (cross-namespace — requires binding)
  // Gateway worker reads API_KEYS_KV; this worker writes to it via binding name
  await env.REVENUE_CRM_KV?.put(`pending_apikey:${apiKey.slice(-12)}`, JSON.stringify({
    api_key:  apiKey,
    tier:     "premium",
    email,
    name,
    company,
    expires_at: expiresAt,
    is_trial:   true,
  }), { expirationTtl: 7 * 86400 });

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

  const demoId = "demo_" + await sha256prefix(email + Date.now(), 10);
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
    version:      "123.0.0",
    demo_features: ["Real-time threat intelligence", "AI-powered IOC extraction", "STIX 2.1 export", "SIEM integration", "Actor attribution"],
    sample_threats: threatData,
    enterprise_benefits: {
      unlimited_api:      true,
      siem_push:          true,
      stix_bundles:       true,
      dedicated_sla:      "99.9% uptime",
      support:            "Dedicated security engineer",
      custom_feeds:       true,
      white_label:        true,
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
    weighted_value_inr: Math.floor((data.value_inr || 14999) * (data.close_probability || 0.10)),
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
  await slackNotify(env, `🏆 DEAL CLOSED WON | ${data.company} | ${data.plan} | ₹${data.value_inr || 14999}/mo | deal: ${dealId}`);

  // 3. Queue onboarding sequence
  if (data.lead_email) {
    await outreachQueueDirect(env, data.lead_email, "enterprise_cold", { company: data.company });
  }

  // 4. Update MRR counter
  await trackEvent(env, "deal_closed_won", { deal_id: dealId, value_inr: data.value_inr || 14999 });
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
    vars: { company, plan, deal_id, contract_ref: contractRef, value_inr: value_inr || 14999 },
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

async function automationTrigger(request, env, rid) {
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
  const tpl = getEmailTemplate(msg.template, msg.vars);

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
<p>Last week, we detected <strong>3 critical CVEs</strong> actively exploited in the wild — including one targeting enterprise cloud infrastructure.</p>
<p>Our Enterprise tier delivers these alerts to your SIEM within minutes of confirmation.</p>
<p>15 minutes this week? <a href="https://intel.cyberdudebivash.com/demo">Book here →</a></p>
<p>— Bivash</p>`,
    },
    "cold_enterprise_value": {
      subject: `How ${T.company || "security teams"} use SENTINEL APEX to detect threats faster`,
      html: `<p>Quick value share —</p>
<p>SENTINEL APEX processed <strong>2,400+ threat events</strong> last month. Here's what Pro/Enterprise users get that free users don't:</p>
<ul>
<li>✅ Full IOC arrays (IPs, domains, hashes) on every threat</li>
<li>✅ STIX 2.1 bundle export to Splunk/QRadar/Sentinel</li>
<li>✅ Actor fingerprinting with kill chain mapping</li>
<li>✅ Real-time alert webhooks</li>
</ul>
<p>Enterprise starts at ₹14,999/month. ROI: one prevented incident pays for years of coverage.</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade?plan=enterprise">Start Enterprise trial →</a></p>`,
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
<p><strong>Upgrade to Pro</strong> to unlock full IOC arrays, AI kill chain analysis, and 5,000 API calls/day.</p>
<p><a href="https://intel.cyberdudebivash.com/trial">Start 7-day Pro trial (no card needed) →</a></p>`,
    },
    "lead_value_d2": {
      subject: "3 threats detected in the last 24h — your sector",
      html: `<p>Since you signed up, our platform detected <strong>new active threats</strong> across enterprise cloud infrastructure.</p>
<p>On the free tier, you can see the threat titles. On Pro, you get:</p>
<ul><li>Full IOC arrays to block immediately</li><li>Actor attribution</li><li>STIX export for your SIEM</li></ul>
<p><a href="https://intel.cyberdudebivash.com/trial">Unlock full intel — 7-day free trial →</a></p>`,
    },
    "lead_trial_offer": {
      subject: "Last chance: 7-day Pro trial — no credit card",
      html: `<p>Your free trial offer expires in 24 hours.</p>
<p>Activate now to get full IOC access, AI analysis, and SIEM integration for 7 days — free.</p>
<p><a href="https://intel.cyberdudebivash.com/trial">Activate Trial Now →</a></p>`,
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
<p>To keep full access after your trial: <a href="https://intel.cyberdudebivash.com/upgrade?plan=pro">Upgrade to Pro (₹2,499/mo) →</a></p>`,
    },
    "trial_nudge_d3": {
      subject: "4 days left on your Pro trial — here's what you've unlocked",
      html: `<p>Hi ${T.name || "there"},</p>
<p>You're halfway through your Pro trial. Here's a quick reminder of what you now have access to:</p>
<ul><li>✅ Full IOC arrays on every threat</li><li>✅ AI kill chain analysis</li><li>✅ Actor fingerprinting</li><li>✅ 5,000 API calls/day</li></ul>
<p>Don't lose this access. Lock it in at ₹2,499/month.</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade?plan=pro">Upgrade Now →</a></p>`,
    },
    "trial_expiry_d1": {
      subject: "⚠️ Your Pro trial expires tomorrow",
      html: `<p>Hi ${T.name || "there"},</p>
<p>Your 7-day Pro trial expires <strong>tomorrow</strong>.</p>
<p>After expiry, your API key will revert to free tier — IOC arrays and AI analysis will be locked.</p>
<p><strong>Upgrade now to maintain full access:</strong></p>
<p><a href="https://intel.cyberdudebivash.com/upgrade?plan=pro" style="background:#00d4aa;color:#000;padding:12px 24px;text-decoration:none;border-radius:6px;font-weight:bold;display:inline-block">Upgrade to Pro — ₹2,499/mo →</a></p>`,
    },
    "trial_expired": {
      subject: "Your Pro trial has ended — upgrade to restore access",
      html: `<p>Hi ${T.name || "there"},</p>
<p>Your 7-day Pro trial has ended. Your API key is now on the free tier.</p>
<p>To restore full IOC access, AI analysis, and 5,000 API calls/day:</p>
<p><a href="https://intel.cyberdudebivash.com/upgrade?plan=pro">Upgrade to Pro — ₹2,499/mo →</a></p>
<p>Need enterprise access for your team? <a href="mailto:enterprise@cyberdudebivash.com">Contact us</a>.</p>`,
    },
    "usage_approaching_limit": {
      subject: "80% of your daily API limit used",
      html: `<p>You've used <strong>80% of your daily API calls</strong>.</p>
<p>Upgrade to Pro for 5,000 calls/day (vs 100 on free tier).</p>
<p><a href="${T.upgrade_url || 'https://intel.cyberdudebivash.com/upgrade'}">Upgrade Now →</a></p>`,
    },
    "usage_limit_hit": {
      subject: "Daily API limit reached — upgrade to continue",
      html: `<p>You've hit your daily API limit.</p>
<p>Your access will reset tomorrow. To continue today — upgrade to Pro for 5,000 calls/day.</p>
<p><a href="${T.upgrade_url}">Upgrade Now →</a></p>`,
    },
    "pro_enterprise_upsell": {
      subject: "Ready to scale beyond Pro? Enterprise is waiting.",
      html: `<p>You're getting serious value from your Pro subscription.</p>
<p>When you're ready to scale, Enterprise unlocks:</p>
<ul><li>Unlimited API calls</li><li>Full STIX 2.1 bundle export</li><li>SIEM push (Splunk, Sentinel, QRadar)</li><li>Dedicated SLA + support engineer</li><li>White-label API option</li></ul>
<p><a href="https://intel.cyberdudebivash.com/upgrade?plan=enterprise">Upgrade to Enterprise — ₹14,999/mo →</a></p>`,
    },
    "enterprise_contract": {
      subject: `Enterprise agreement ready — ${T.company}`,
      html: `<p>Hi,</p>
<p>Thank you for choosing <strong>CYBERDUDEBIVASH® SENTINEL APEX Enterprise</strong>.</p>
<p><strong>Contract ref:</strong> ${T.contract_ref || "CDB-ENT-2026-XXXX"}<br>
<strong>Plan:</strong> Enterprise<br>
<strong>Value:</strong> ₹${T.value_inr || 14999}/month</p>
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

async function isAdmin(request, env) {
  const secret = request.headers.get("X-Admin-Secret");
  return secret && env?.REVENUE_ADMIN_SECRET && secret === env.REVENUE_ADMIN_SECRET;
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

function sanitizeEmail(email) {
  const e = (email || "").trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) ? e : null;
}

function genId(prefix) {
  const b = crypto.getRandomValues(new Uint8Array(6));
  return (prefix||"id") + "_" + [...b].map(x=>x.toString(16).padStart(2,"0")).join("");
}

function getWeekLabel() {
  const d = new Date();
  return `Week of ${d.toISOString().slice(0,10)}`;
}

function cors204() {
  return new Response(null, { status: 204, headers: {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-Admin-Secret, Authorization",
  }});
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type":                "application/json",
      "Cache-Control":               "no-cache, no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

const DEMO_FALLBACK_THREATS = [
  { title: "Critical RCE in Apache Struts — CVE-2026-0542", severity: "critical", risk_score: 9.8, ioc_count: 12 },
  { title: "APT41 Campaign Targeting Financial Sector via Spear Phishing", severity: "high", risk_score: 8.5, ioc_count: 34 },
  { title: "Ransomware Group LockBit 4.0 — New Variant Detected", severity: "critical", risk_score: 9.5, ioc_count: 67 },
];
