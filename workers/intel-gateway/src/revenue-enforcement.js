// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Revenue Enforcement Engine v123.0.0
// Phase 1: Tier gates · Usage billing · Upgrade triggers · Lead capture
// Phase 2: Trial issuance · Email capture · Conversion hooks
// Import this file into index.js and wire into the request pipeline.
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// TIER CONFIGURATION — Hard enforcement matrix
// FREE       : preview only, truncated AI, blocked IOC/STIX, 20 items/req
// PRO        : full feed, full AI, full IOC, partial STIX, 500/req, 500/min
// ENTERPRISE : everything + raw STIX bundle, SIEM webhooks, dedicated SLA
// ─────────────────────────────────────────────────────────────────────────────
export const REVENUE_CONFIG = {
  VERSION: "123.0.0",
  TIERS: {
    FREE:       "free",
    PRO:        "premium",      // internal name kept as "premium" for compat
    ENTERPRISE: "enterprise",
  },
  LIMITS: {
    free:       { items: 20,   rpm: 60,   api_calls_day: 100,  stix: false, ioc: false,  ai_full: false },
    premium:    { items: 500,  rpm: 500,  api_calls_day: 5000, stix: "meta", ioc: true,  ai_full: true  },
    enterprise: { items: 2000, rpm: 2000, api_calls_day: -1,   stix: true,  ioc: true,  ai_full: true  },
  },
  PRICING: {
    free:       { monthly_inr: 0,       monthly_usd: 0     },
    premium:    { monthly_inr: 2499,    monthly_usd: 29    },
    enterprise: { monthly_inr: 14999,   monthly_usd: 199   },
  },
  UPGRADE_URLS: {
    free_to_pro:       "https://intel.cyberdudebivash.com/upgrade?plan=pro",
    pro_to_enterprise: "https://intel.cyberdudebivash.com/upgrade?plan=enterprise",
    trial:             "https://intel.cyberdudebivash.com/trial",
  },
  TRIAL: {
    duration_days:  7,
    tier:           "premium",
    auto_key:       true,
  },
  USAGE_KV_TTL: 86400,          // 24h rolling usage window
  LEAD_KV_TTL:  86400 * 90,     // 90-day lead retention in KV
};

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1A — Hard Tier Gate Middleware
// Call this BEFORE returning any gated response.
// Returns { allowed: bool, reason: string, upgrade: object|null }
// ─────────────────────────────────────────────────────────────────────────────
export function enforceTierGate(resource, tier) {
  const t    = (tier || "free").toLowerCase();
  const cfg  = REVENUE_CONFIG.LIMITS[t] || REVENUE_CONFIG.LIMITS.free;
  const isFree = t === "free";
  const isPro  = t === "premium";
  const isEnt  = t === "enterprise";

  switch (resource) {

    // IOC array access — Free: BLOCKED
    case "ioc_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "ioc_locked",
        message: "Full IOC arrays require Pro or Enterprise. Upgrade to detect, hunt, and contain.",
        upgrade: buildUpgradeTrigger("ioc", t),
      };
      return { allowed: true };

    // STIX bundle — Free: BLOCKED, Pro: metadata only, Enterprise: full
    case "stix_bundle":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "stix_enterprise_only",
        message: "STIX 2.1 full bundles are Enterprise-only. Includes all objects, relationships, and actor TTPs.",
        upgrade: buildUpgradeTrigger("stix", t),
      };
      if (isPro) return {
        allowed: false,
        resource,
        reason:  "stix_metadata_only",
        message: "Full STIX bundle export requires Enterprise. You have metadata access.",
        upgrade: buildUpgradeTrigger("stix_full", t),
      };
      return { allowed: true };

    // Full AI analysis — Free: TRUNCATED
    case "ai_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "ai_truncated",
        message: "Full AI analysis (kill chain mapping, actor fingerprint, TTP scoring) requires Pro.",
        upgrade: buildUpgradeTrigger("ai", t),
      };
      return { allowed: true };

    // Full report (deep intel) — Free: TRUNCATED to 300 chars summary
    case "report_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "report_truncated",
        message: "Full report text and attribution require Pro tier.",
        upgrade: buildUpgradeTrigger("report", t),
      };
      return { allowed: true };

    // SIEM webhooks — Enterprise only
    case "siem":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "SIEM webhook push (Splunk, Sentinel, QRadar) is Enterprise-exclusive.",
        upgrade: buildUpgradeTrigger("siem", t),
      };
      return { allowed: true };

    // Advanced alerts — Pro+
    case "alerts":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Threat alerts with actor attribution require Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("alerts", t),
      };
      return { allowed: true };

    // API key creation limit
    case "api_keys":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "api_key_limited",
        message: "Additional API keys require Pro. Free tier: 1 key maximum.",
        upgrade: buildUpgradeTrigger("api", t),
      };
      return { allowed: true };

    // ── v123.0.0: AI Intelligence gates ──────────────────────────────────────

    // IOC Confidence Detail — Free: summary only, Pro+: full extraction meta
    case "ioc_confidence_detail":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Full IOC extraction metadata (per-type confidence, enrichment priority, layer breakdown) requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ioc_confidence_detail", t),
      };
      return { allowed: true };

    // Full STIX Export with all IOC indicator objects — Enterprise only
    case "stix_export_full":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "Full STIX 2.1 export with all indicator, malware, threat-actor, and relationship objects is Enterprise-exclusive.",
        upgrade: buildUpgradeTrigger("stix_export_full", t),
      };
      return { allowed: true };

    // AI Threat Prediction — Free: BLOCKED, Pro+: ALLOWED (ENTERPRISE gets stored predictions)
    case "ai_predict":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "AI threat prediction (CVSS+EPSS+KEV+TTP scoring) requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ai_predict", t),
      };
      return { allowed: true };

    // Campaign Clustering — Free: BLOCKED, Pro+: ALLOWED (Enterprise gets full member details)
    case "ai_campaigns":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "DBSCAN campaign intelligence requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ai_campaigns", t),
      };
      return { allowed: true };

    // Anomaly Detection — Free: BLOCKED, Pro+: ALLOWED (Enterprise gets zero-day indicators)
    case "ai_anomalies":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Isolation Forest anomaly detection + zero-day candidate flagging requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ai_anomalies", t),
      };
      return { allowed: true };

    // Intelligence Graph — Free: BLOCKED, Pro: summary only, Enterprise: full graph
    case "intel_graph":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "IOC intelligence graph access requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("intel_graph", t),
      };
      return { allowed: true };

    // Intelligence Graph — full node list (Enterprise only)
    case "intel_graph_full":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "Full IOC graph (all nodes + attribution edges) is Enterprise-exclusive.",
        upgrade: buildUpgradeTrigger("intel_graph_full", t),
      };
      return { allowed: true };

    // Intelligence Relations (BFS traversal) — Free: BLOCKED, Pro: depth≤1 + 5 results, Enterprise: full
    case "intel_relations":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "IOC relationship traversal + actor attribution requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("intel_relations", t),
      };
      return { allowed: true };

    default:
      return { allowed: true };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1B — Usage Billing Tracker (KV-backed)
// Tracks per-key daily API calls. Enforces hard cap for free tier.
// KV key format: usage:<key_id>:<YYYY-MM-DD>
// ─────────────────────────────────────────────────────────────────────────────
export async function trackUsageAndEnforce(env, keyId, tier) {
  if (!env?.SECURITY_HUB_KV || !keyId) return { allowed: true, count: 0 };

  const t      = (tier || "free").toLowerCase();
  const limit  = REVENUE_CONFIG.LIMITS[t]?.api_calls_day ?? 100;
  if (limit === -1) return { allowed: true, unlimited: true }; // enterprise

  const day    = new Date().toISOString().slice(0, 10);
  const kvKey  = `usage:${keyId}:${day}`;

  try {
    const current = parseInt(await env.SECURITY_HUB_KV.get(kvKey) || "0");
    const next    = current + 1;

    // Always write updated count
    await env.SECURITY_HUB_KV.put(kvKey, String(next), { expirationTtl: REVENUE_CONFIG.USAGE_KV_TTL });

    if (next > limit) {
      return {
        allowed:  false,
        reason:   "usage_limit_hit",
        used:     next,
        limit,
        upgrade:  buildUpgradeTrigger("usage_limit", t),
        message:  `Daily API limit reached (${limit} calls). ${t === "free" ? "Upgrade to Pro for 5,000 calls/day." : "Upgrade to Enterprise for unlimited."}`,
        reset_at: `${day}T23:59:59Z`,
      };
    }

    return {
      allowed:    true,
      used:       next,
      limit,
      remaining:  limit - next,
      pct_used:   Math.floor((next / limit) * 100),
      // Emit upsell nudge at 80% usage
      upsell_nudge: next >= Math.floor(limit * 0.8) ? buildUpgradeTrigger("approaching_limit", t) : null,
    };
  } catch {
    return { allowed: true, count: 0, error: "usage_tracking_unavailable" };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1C — Revenue Trigger Builder
// Generates consistent upgrade trigger objects for API responses
// ─────────────────────────────────────────────────────────────────────────────
export function buildUpgradeTrigger(context, currentTier) {
  const t = (currentTier || "free").toLowerCase();
  const targetTier = t === "free" ? "pro" : "enterprise";
  const url = t === "free"
    ? REVENUE_CONFIG.UPGRADE_URLS.free_to_pro
    : REVENUE_CONFIG.UPGRADE_URLS.pro_to_enterprise;

  const contextMessages = {
    ioc:              { title: "Unlock Full IOC Arrays",         body: "See every IP, domain, hash and URL extracted from this threat. Used by SOC teams globally." },
    stix:             { title: "Access STIX 2.1 Bundles",        body: "Import threat objects directly into your SIEM, SOAR, or threat platform." },
    stix_full:        { title: "Upgrade to Enterprise",          body: "Full STIX bundle export with all objects and relationships." },
    ai:               { title: "Unlock Full AI Analysis",        body: "Kill chain mapping, actor fingerprinting, TTP scoring — real-time." },
    report:           { title: "Access Full Intel Reports",      body: "Deep attribution, technical analysis, and defensive recommendations." },
    siem:             { title: "Enterprise SIEM Push",           body: "Auto-push threats to Splunk, Sentinel, or QRadar in real-time." },
    alerts:           { title: "Real-Time Threat Alerts",        body: "Get notified instantly when critical threats emerge. Actor TTPs included." },
    api:              { title: "More API Keys",                  body: "Create multiple API keys for your team and CI/CD pipelines." },
    usage_limit:      { title: "Daily Limit Reached",            body: t === "free" ? "You've used all 100 free API calls today. Upgrade to Pro for 5,000/day." : "Upgrade to Enterprise for unlimited calls." },
    approaching_limit:{ title: "80% of Daily Limit Used",        body: "You're close to your daily API limit. Upgrade now to avoid disruption." },
  };

  const ctx = contextMessages[context] || { title: "Upgrade Your Plan", body: "Get more access, faster responses, and deeper intelligence." };

  const prices = {
    pro:        { inr: "₹2,499/mo", usd: "$29/mo" },
    enterprise: { inr: "₹14,999/mo", usd: "$199/mo" },
  };

  return {
    trigger_context:  context,
    current_tier:     t,
    target_tier:      targetTier,
    title:            ctx.title,
    message:          ctx.body,
    price:            prices[targetTier] || prices.pro,
    upgrade_url:      url,
    trial_url:        REVENUE_CONFIG.UPGRADE_URLS.trial,
    cta_primary:      targetTier === "pro" ? `Upgrade to Pro — ${prices.pro.usd}` : `Upgrade to Enterprise — ${prices.enterprise.usd}`,
    cta_trial:        "Start 7-Day Free Trial",
    features:         getUpgradeFeatures(targetTier),
    revenue_event:    `upgrade_trigger:${context}:${t}→${targetTier}`,
  };
}

function getUpgradeFeatures(targetTier) {
  if (targetTier === "enterprise") {
    return ["Unlimited API calls", "Full STIX 2.1 bundles", "SIEM push integrations", "Dedicated SLA", "White-label API", "Priority support"];
  }
  return ["500 req/min", "5,000 API calls/day", "Full IOC arrays", "Full AI analysis", "Threat alerts", "Priority email support"];
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2A — Lead Capture Backend
// POST /api/leads/capture — stores email + context before gated content
// POST /api/leads/trial   — issues 7-day PRO trial + API key
// ─────────────────────────────────────────────────────────────────────────────
export async function handleLeadCapture(request, env, rid) {
  if (request.method !== "POST") {
    return revenueJson({ error: "method_not_allowed" }, 405);
  }

  let body;
  try { body = await request.json(); } catch {
    return revenueJson({ error: "invalid_json" }, 400);
  }

  const email   = (body.email || "").trim().toLowerCase();
  const context = (body.context || "generic").slice(0, 64);
  const company = (body.company || "").slice(0, 128);
  const role    = (body.role || "").slice(0, 64);
  const source  = (body.source || "website").slice(0, 64);

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return revenueJson({ error: "invalid_email", message: "Valid email required." }, 400);
  }

  const ts   = new Date().toISOString();
  const lead = {
    email,
    company,
    role,
    source,
    context,
    status:       "new",
    captured_at:  ts,
    ip:           request.headers.get("cf-connecting-ip") || "unknown",
    country:      request.headers.get("cf-ipcountry")     || "unknown",
    rid,
  };

  try {
    // Store in KV: lead:<email_hash>
    if (env?.SECURITY_HUB_KV) {
      const hash = await sha256hex(email);
      const kvKey = `lead:${hash}`;
      const existing = await env.SECURITY_HUB_KV.get(kvKey, { type: "json" });
      if (!existing) {
        // New lead — store + trigger welcome sequence flag
        lead.sequence_step = 0;
        lead.next_touch_at = new Date(Date.now() + 3600000).toISOString(); // 1h
        await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(lead), { expirationTtl: REVENUE_CONFIG.LEAD_KV_TTL });

        // Also push to leads list for outbound engine
        const listKey = `leads:list:${ts.slice(0,10)}`;
        const dayList = await env.SECURITY_HUB_KV.get(listKey, { type: "json" }) || [];
        dayList.push({ email, hash, company, role, source, context, captured_at: ts });
        await env.SECURITY_HUB_KV.put(listKey, JSON.stringify(dayList), { expirationTtl: REVENUE_CONFIG.LEAD_KV_TTL });

        // Track revenue event
        await trackRevenueEvent(env, "lead_captured", { email: hash, context, source });
      } else {
        // Returning lead — update last seen
        existing.last_seen = ts;
        existing.visit_count = (existing.visit_count || 1) + 1;
        await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(existing), { expirationTtl: REVENUE_CONFIG.LEAD_KV_TTL });
      }
    }

    return revenueJson({
      status:      "captured",
      message:     "Access granted. Check your email for full report delivery.",
      trial_offer: {
        available: true,
        message:   "Start your 7-day Pro trial — no credit card required.",
        url:       REVENUE_CONFIG.UPGRADE_URLS.trial,
      },
      request_id:  rid,
    });
  } catch (e) {
    return revenueJson({ error: "capture_failed", message: e.message }, 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2B — Trial Issuance Engine
// POST /api/leads/trial — issues 7-day PRO trial + API key instantly
// ─────────────────────────────────────────────────────────────────────────────
export async function handleTrialIssuance(request, env, rid) {
  if (request.method !== "POST") {
    return revenueJson({ error: "method_not_allowed" }, 405);
  }

  let body;
  try { body = await request.json(); } catch {
    return revenueJson({ error: "invalid_json" }, 400);
  }

  const email = (body.email || "").trim().toLowerCase();
  const name  = (body.name  || email.split("@")[0]).slice(0, 128);

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return revenueJson({ error: "invalid_email" }, 400);
  }

  if (!env?.API_KEYS_KV || !env?.SECURITY_HUB_KV) {
    return revenueJson({ error: "service_unavailable", message: "Trial system initializing." }, 503);
  }

  try {
    const emailHash  = await sha256hex(email);
    const trialKey   = `trial:${emailHash}`;
    const existing   = await env.SECURITY_HUB_KV.get(trialKey, { type: "json" });

    // One trial per email — enforce
    if (existing?.activated) {
      return revenueJson({
        error:    "trial_already_used",
        message:  "Trial already activated for this email. Upgrade to Pro to continue.",
        upgrade:  REVENUE_CONFIG.UPGRADE_URLS.free_to_pro,
      }, 409);
    }

    // Generate trial API key
    const raw          = crypto.getRandomValues(new Uint8Array(24));
    const apiKey       = "cdb_trial_" + Array.from(raw).map(b => b.toString(16).padStart(2,"0")).join("").slice(0,32);
    const keyHash      = await sha256hex(apiKey);
    const keyId        = "trial_" + emailHash.slice(0, 12);
    const now          = new Date();
    const expiresAt    = new Date(now.getTime() + REVENUE_CONFIG.TRIAL.duration_days * 86400000).toISOString();
    const expTtl       = REVENUE_CONFIG.TRIAL.duration_days * 86400;

    // Store API key with PRO tier + expiry
    const keyRecord = {
      key_id:      keyId,
      key_hash:    keyHash,
      tier:        REVENUE_CONFIG.TRIAL.tier,
      email,
      name,
      created_at:  now.toISOString(),
      expires_at:  expiresAt,
      is_trial:    true,
      status:      "active",
      rate_limit:  REVENUE_CONFIG.LIMITS.premium.rpm,
      daily_limit: REVENUE_CONFIG.LIMITS.premium.api_calls_day,
    };
    await env.API_KEYS_KV.put(`key:${keyHash}`, JSON.stringify(keyRecord), { expirationTtl: expTtl + 3600 });

    // Record trial activation
    const trialRecord = {
      email,
      name,
      email_hash:  emailHash,
      api_key_id:  keyId,
      activated_at: now.toISOString(),
      expires_at:  expiresAt,
      activated:   true,
      converted:   false,
    };
    await env.SECURITY_HUB_KV.put(trialKey, JSON.stringify(trialRecord), { expirationTtl: REVENUE_CONFIG.LEAD_KV_TTL });

    // Track revenue event
    await trackRevenueEvent(env, "trial_activated", { email_hash: emailHash });

    // Schedule trial expiry nudge (store flag for automation engine to pick up)
    const nudgeKey = `nudge:trial_expiry:${emailHash}`;
    await env.SECURITY_HUB_KV.put(nudgeKey, JSON.stringify({
      email, name,
      expires_at: expiresAt,
      nudge_at_3d: new Date(now.getTime() + 3 * 86400000).toISOString(),
      nudge_at_1d: new Date(now.getTime() + 6 * 86400000).toISOString(),
      sent_3d: false, sent_1d: false, sent_expiry: false,
    }), { expirationTtl: expTtl + 86400 });

    return revenueJson({
      status:     "trial_activated",
      message:    `7-day Pro trial active. Your API key is below — save it securely.`,
      trial: {
        api_key:    apiKey,
        key_id:     keyId,
        tier:       "pro",
        expires_at: expiresAt,
        features:   getUpgradeFeatures("pro"),
        docs:       "https://intel.cyberdudebivash.com/docs",
      },
      convert_url: REVENUE_CONFIG.UPGRADE_URLS.free_to_pro,
      request_id:  rid,
    });
  } catch (e) {
    return revenueJson({ error: "trial_failed", message: e.message }, 500);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1D — Augmented applyTierGate (drop-in replacement for existing fn)
// Harder enforcement: blocks more fields, injects stronger upgrade triggers
// ─────────────────────────────────────────────────────────────────────────────
export function applyTierGateV2(item, tier, usageState) {
  const t      = (tier || "free").toLowerCase();
  const isFree = t === "free";
  const isPro  = t === "premium";
  const isEnt  = t === "enterprise";

  const gated = { ...item };

  // ── IOC enforcement ────────────────────────────────────────────────────────
  if (isFree && Array.isArray(item.iocs) && item.iocs.length > 0) {
    const gate = enforceTierGate("ioc_full", t);
    gated.iocs       = [];
    gated.ioc_count  = item.iocs.length;
    gated.ioc_paywall = { ...gate, count: item.iocs.length };
  }

  // ── STIX enforcement ───────────────────────────────────────────────────────
  if (!isEnt) {
    const gate = enforceTierGate("stix_bundle", t);
    gated.stix_bundle = null;
    if (item.stix_bundle || item.stix_id) {
      gated.stix_paywall = {
        ...gate,
        bundle_id:    item.bundle_id || item.stix_id,
        object_count: item.stix_object_count || 0,
      };
    }
  }

  // ── AI analysis enforcement ────────────────────────────────────────────────
  gated.apex_ai = computeApexAIGated(item, t);

  // ── Report text truncation for free tier ──────────────────────────────────
  if (isFree) {
    const desc = item.description || item.summary || "";
    if (desc.length > 280) {
      gated.description = desc.slice(0, 280) + "... [Full analysis available on Pro]";
      gated.report_paywall = enforceTierGate("report_full", t);
    }
  }

  // ── Threat urgency CTA injection ───────────────────────────────────────────
  if (isFree) {
    const sev       = (item.severity || item.risk_level || "").toUpperCase();
    const riskScore = typeof item.risk_score === "number" ? item.risk_score
                    : typeof item.cvss_score  === "number" ? item.cvss_score : 0;
    if (sev === "CRITICAL" || sev === "HIGH" || riskScore >= 7.0) {
      gated.threat_urgency = {
        active:       true,
        severity:     sev,
        message:      `⚠️ ${sev} ACTIVE THREAT — Full IOC array, actor attribution, and kill chain locked.`,
        upgrade:      buildUpgradeTrigger("ioc", t),
        cta_modal:    "upgrade_modal",
        cta_plan:     "pro",
      };
    }
  }

  // ── Usage-based upsell injection ───────────────────────────────────────────
  if (usageState?.upsell_nudge) {
    gated.usage_alert = usageState.upsell_nudge;
  }

  return gated;
}

// Minimal computeApexAIGated — mirrors existing but enforces AI gate
function computeApexAIGated(item, tier) {
  const isFree = !tier || tier === "free";
  const base = {
    predictive_risk: typeof item.risk_score === "number" ? Math.min(10, item.risk_score) : 0,
    ai_confidence:   typeof item.confidence === "number" ? Math.min(100, item.confidence * 100) : 50,
  };
  if (isFree) {
    return {
      ...base,
      ai_summary:     (item.apex?.ai_summary || item.description || "").slice(0, 120) + " [Full AI analysis requires Pro]",
      actor_fingerprint: null,
      kill_chain:     null,
      ttp_density:    null,
      locked:         true,
      upgrade:        buildUpgradeTrigger("ai", tier),
    };
  }
  return {
    ...base,
    ai_summary:       item.apex?.ai_summary || item.description || "",
    actor_fingerprint: item.apex?.actor_fingerprint || null,
    kill_chain:       item.apex?.kill_chain        || null,
    ttp_density:      item.apex?.ttp_density       || 0,
    locked:           false,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2C — Usage Limit Hit Handler
// Returns 402 Payment Required with upgrade trigger when daily cap hit
// ─────────────────────────────────────────────────────────────────────────────
export function buildUsageLimitResponse(usageState, rid) {
  return new Response(JSON.stringify({
    error:      "usage_limit_reached",
    message:    usageState.message,
    used:       usageState.used,
    limit:      usageState.limit,
    reset_at:   usageState.reset_at,
    upgrade:    usageState.upgrade,
    request_id: rid,
  }, null, 2), {
    status: 402,
    headers: {
      "Content-Type":                "application/json",
      "X-RateLimit-Limit":           String(usageState.limit),
      "X-RateLimit-Remaining":       "0",
      "X-RateLimit-Reset":           usageState.reset_at,
      "Cache-Control":               "no-cache, no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Revenue Event Tracker — persists to SECURITY_HUB_KV for revenue analytics
// ─────────────────────────────────────────────────────────────────────────────
export async function trackRevenueEvent(env, event, meta = {}) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const day = new Date().toISOString().slice(0, 10);
    const key = `revenue:events:${day}`;
    const rec = await env.SECURITY_HUB_KV.get(key, { type: "json" }) || { events: [], total: 0 };
    rec.total++;
    if (rec.events.length < 200) {
      rec.events.push({ ts: new Date().toISOString(), event, ...meta });
    }
    await env.SECURITY_HUB_KV.put(key, JSON.stringify(rec), { expirationTtl: 86400 * 30 });

    // Per-event counter
    const cntKey = `revenue:count:${event}:${day}`;
    const cnt    = parseInt(await env.SECURITY_HUB_KV.get(cntKey) || "0") + 1;
    await env.SECURITY_HUB_KV.put(cntKey, String(cnt), { expirationTtl: 86400 * 30 });
  } catch { /* non-critical */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// Revenue Analytics Endpoint — GET /api/revenue/analytics (admin only)
// ─────────────────────────────────────────────────────────────────────────────
export async function handleRevenueAnalytics(request, env, rid) {
  const adminSecret = request.headers.get("X-Admin-Secret");
  if (!env?.ADMIN_SECRET || adminSecret !== env.ADMIN_SECRET) {
    return revenueJson({ error: "unauthorized" }, 401);
  }

  const day  = new URL(request.url).searchParams.get("date") || new Date().toISOString().slice(0, 10);
  const keys = ["lead_captured","trial_activated","upgrade_trigger","usage_limit_hit","ioc_access_attempt","stix_access_attempt"];

  const counts = {};
  for (const k of keys) {
    const cnt = await env.SECURITY_HUB_KV?.get(`revenue:count:${k}:${day}`) || "0";
    counts[k] = parseInt(cnt);
  }

  const events = await env.SECURITY_HUB_KV?.get(`revenue:events:${day}`, { type: "json" }) || { events: [], total: 0 };

  // Estimate daily MRR from conversion signals
  const trialConvRate  = 0.18; // 18% trial-to-paid
  const leadConvRate   = 0.07; // 7% lead-to-trial
  const estimatedMRR = (
    (counts.trial_activated * trialConvRate * REVENUE_CONFIG.PRICING.premium.monthly_usd) +
    (counts.lead_captured   * leadConvRate  * trialConvRate * REVENUE_CONFIG.PRICING.premium.monthly_usd)
  ).toFixed(2);

  return revenueJson({
    status:     "ok",
    date:       day,
    counts,
    estimated_daily_mrr_usd: parseFloat(estimatedMRR),
    estimated_monthly_mrr_usd: parseFloat(estimatedMRR) * 30,
    top_events: events.events.slice(-20),
    request_id: rid,
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
async function sha256hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function revenueJson(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type":                "application/json",
      "Cache-Control":               "no-cache, no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
