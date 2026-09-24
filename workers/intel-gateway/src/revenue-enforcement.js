// =============================================================================
// CYBERDUDEBIVASH SENTINEL APEX  Revenue Enforcement Engine v134.0.0
// Phase 1: Tier gates  Usage billing  Upgrade triggers  Lead capture
// Phase 2: Trial issuance  Email capture  Conversion hooks
// Import this file into index.js and wire into the request pipeline.
// =============================================================================

// Constant-time string comparison for shared-secret checks (admin key) --
// same implementation as index.js's timingSafeEqual; duplicated locally
// (rather than imported) because index.js imports from this module, so an
// index.js -> this file -> index.js import would be circular.
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

// 
// TIER CONFIGURATION  Hard enforcement matrix
// FREE       : preview only, truncated AI, blocked IOC/STIX, 20 items/req
// PRO        : full feed, full AI, full IOC, partial STIX, 500/req, 500/min
// ENTERPRISE : everything + raw STIX bundle, SIEM webhooks, dedicated SLA
// 
export const REVENUE_CONFIG = {
  VERSION: "201.0",  // v201.0  synced with platform version
  // Phase 3: tier identifiers now match index.js's live TIERS constant
  // exactly (TIERS = { FREE:"FREE", PRO:"PRO", ENTERPRISE:"ENTERPRISE",
  // MSSP:"MSSP" }) instead of a separate lowercase/"premium" vocabulary.
  // That mismatch is why enforceTierGate() was never callable with a real
  // auth.tier value -- (tier||"free").toLowerCase() on the real string "PRO"
  // produced "pro", which matched neither "premium" (this file's old PRO
  // key) nor anything else, so every real PRO/ENTERPRISE/MSSP caller was
  // silently treated as free. The only two call sites that existed
  // (index.js's campaigns_paywall/anomalies_paywall) sidestepped this by
  // hardcoding the literal "free" tier -- correct for what they do (they
  // build the free-tier-masked view unconditionally), not a workaround for
  // this bug, but it meant the bug never surfaced.
  TIERS: {
    FREE:       "FREE",
    PRO:        "PRO",
    ENTERPRISE: "ENTERPRISE",
    MSSP:       "MSSP",
  },
  // v185.2 FIX (Fortune-500 audit, Phase 9): rpm values here previously said
  // 60/500/2000/-1 (FREE/PRO/ENTERPRISE/MSSP) and leaked into customer-facing
  // text (getUpgradeFeatures(), the rate_limit field at buildUpgradeTrigger())
  // even though these values were never consumed by the actual rate limiter
  // (`cfg` is assigned here but never referenced below -- confirmed unused).
  // The real, enforced sliding-window limiter is RATE_LIMITS in index.js
  // (FREE:30, PRO:120, ENTERPRISE:600, MSSP:1200 req/min) -- corrected to
  // match so this file stops emitting a promise the platform doesn't keep.
  // MSSP was also wrongly marked unlimited (-1); it is rate-limited too, just
  // at a higher ceiling than Enterprise.
  //
  // P0 commercial-contract convergence (2026-09-24): api_calls_day said
  // FREE 100 and ENTERPRISE/MSSP -1 ("unlimited"), contradicting
  // config/commercial-contract.json (requests_per_day FREE 50,
  // ENTERPRISE 50,000, MSSP 50,000) and the limiter that really enforces
  // it (DAILY_QUOTAS, daily-quota.js). The contract forbids publishing any
  // tier as unlimited. These values reach customers through
  // buildUpgradeTrigger()/getUpgradeFeatures() copy, so they now equal the
  // contract; scripts/verify_commercial_contract.py fails the build on drift.
  LIMITS: {
    FREE:       { items: 20,   rpm: 30,   api_calls_day: 50,    stix: false, ioc: false,  ai_full: false },
    PRO:        { items: 500,  rpm: 120,  api_calls_day: 5000,  stix: "meta", ioc: true,  ai_full: true  },
    ENTERPRISE: { items: 2000, rpm: 600,  api_calls_day: 50000, stix: true,  ioc: true,  ai_full: true  },
    // MSSP evidenced as >= ENTERPRISE everywhere else in this codebase
    // (every ad-hoc `auth.tier === TIERS.ENTERPRISE || auth.tier === TIERS.MSSP`
    // check in index.js treats them identically) -- unlimited items/day here
    // for the same reason, not a new policy invented for this pass. rpm is
    // NOT unlimited -- matches RATE_LIMITS.MSSP in index.js.
    MSSP:       { items: -1,   rpm: 1200, api_calls_day: 50000, stix: true,  ioc: true,  ai_full: true  },
  },
  // v185.2 FIX (Fortune-500 audit, Phase 9): premium.monthly_usd was 29 --
  // the actual Razorpay charge (pricing-data.json, the live checkout source
  // of truth) is $49/mo (INR 4,100, 410000 paise). This object's price
  // leaked into buildUpgradeTrigger()'s live paywall response
  // (upgrade.price/cta_primary) as $29, a number no customer is ever
  // actually charged.
  //
  // v185.3 FIX (Fortune-500 audit, Phase 2 of the commercial-cutover
  // mission): enterprise.monthly_usd was 199 -- traced the REAL checkout
  // authority per the mission's own required method (frontend plan id ->
  // handleRazorpayCreateOrder -> RAZORPAY_TIER_PRICES ->
  // pricing-data.json.tiers.ENTERPRISE.monthly -> the actual Razorpay
  // order amount): 4160000 paise = INR 41,600/mo, which is $499/mo, not
  // $199. upgrade.html and pricing.html already advertise $499/INR 41,600
  // consistently and match pricing-data.json exactly -- this object was
  // the only remaining source still disagreeing with the real charge.
  PRICING: {
    free:       { monthly_inr: 0,       monthly_usd: 0     },
    premium:    { monthly_inr: 4100,    monthly_usd: 49    },
    enterprise: { monthly_inr: 41600,   monthly_usd: 499   },
  },
  UPGRADE_URLS: {
    free_to_pro:       "https://intel.cyberdudebivash.com/upgrade.html?plan=pro",
    pro_to_enterprise: "https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise",
    trial:             "https://intel.cyberdudebivash.com/upgrade.html?plan=pro",
    mssp:              "https://intel.cyberdudebivash.com/upgrade.html?plan=mssp",
    get_key:           "https://intel.cyberdudebivash.com/upgrade.html",
    pricing:           "https://intel.cyberdudebivash.com/pricing.html",
  },
  TRIAL: {
    duration_days:  7,
    tier:           "PRO", // was "premium" -- same vocabulary fix as LIMITS/TIERS above.
                            // Only consumed by handleTrialIssuance(), confirmed dead code
                            // (not imported/called anywhere in index.js) -- fixed for
                            // consistency in case it's ever wired up, not because it's
                            // reachable today. See Phase 3 doc for the separate,
                            // unrelated key-storage bug in that same function.
    auto_key:       true,
  },
  USAGE_KV_TTL: 86400,          // 24h rolling usage window
  LEAD_KV_TTL:  86400 * 90,     // 90-day lead retention in KV
};

// 
// PHASE 1A  Hard Tier Gate Middleware
// Call this BEFORE returning any gated response.
// Returns { allowed: bool, reason: string, upgrade: object|null }
// 
export function enforceTierGate(resource, tier) {
  const t    = (tier || "FREE").toUpperCase();
  const cfg  = REVENUE_CONFIG.LIMITS[t] || REVENUE_CONFIG.LIMITS.FREE;
  const isFree = t === "FREE";
  const isPro  = t === "PRO";
  // MSSP inherits ENTERPRISE-level access throughout this file -- evidenced,
  // not invented (see LIMITS.MSSP comment above).
  const isEnt  = t === "ENTERPRISE" || t === "MSSP";

  switch (resource) {

    // IOC array access  Free: BLOCKED
    case "ioc_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "ioc_locked",
        message: "Full IOC arrays require Pro or Enterprise. Upgrade to detect, hunt, and contain.",
        upgrade: buildUpgradeTrigger("ioc", t),
      };
      return { allowed: true };

    // STIX bundle  Free: BLOCKED, Pro: metadata only, Enterprise: full
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

    // Full AI analysis  Free: TRUNCATED
    case "ai_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "ai_truncated",
        message: "Full AI analysis (kill chain mapping, actor fingerprint, TTP scoring) requires Pro.",
        upgrade: buildUpgradeTrigger("ai", t),
      };
      return { allowed: true };

    // Full report (deep intel)  Free: TRUNCATED to 300 chars summary
    case "report_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "report_truncated",
        message: "Full report text and attribution require Pro tier.",
        upgrade: buildUpgradeTrigger("report", t),
      };
      return { allowed: true };

    // SLA compliance report / incident log / certificate  Enterprise+MSSP
    // (v185.4 entitlement inventory: mirrors sla-monitor.js's own
    // auth.tier==="ENTERPRISE"||"MSSP" ad-hoc gate exactly -- this case
    // exists so index.js's new shadow-mode resolveEntitlement() calls at
    // /api/sla/report, /api/sla/incidents, /api/sla/certificate compare
    // against real logic instead of this switch's fail-open default.)
    case "sla_report":
    case "sla_incidents":
    case "sla_certificate":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "SLA compliance reports, incident logs, and certificates require Enterprise or MSSP tier.",
        upgrade: buildUpgradeTrigger("sla", t),
      };
      return { allowed: true };

    // SIEM webhooks  Enterprise only
    case "siem":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "SIEM webhook push (Splunk, Sentinel, QRadar) is Enterprise-exclusive.",
        upgrade: buildUpgradeTrigger("siem", t),
      };
      return { allowed: true };

    // Advanced alerts  Pro+
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

    //  v134.0.0: AI Intelligence gates 

    // IOC Confidence Detail  Free: summary only, Pro+: full extraction meta
    case "ioc_confidence_detail":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Full IOC extraction metadata (per-type confidence, enrichment priority, layer breakdown) requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ioc_confidence_detail", t),
      };
      return { allowed: true };

    // Full STIX Export with all IOC indicator objects  Enterprise only
    case "stix_export_full":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "Full STIX 2.1 export with all indicator, malware, threat-actor, and relationship objects is Enterprise-exclusive.",
        upgrade: buildUpgradeTrigger("stix_export_full", t),
      };
      return { allowed: true };

    // AI Threat Prediction  Free: BLOCKED, Pro+: ALLOWED (ENTERPRISE gets stored predictions)
    case "ai_predict":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "AI threat prediction (CVSS+EPSS+KEV+TTP scoring) requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ai_predict", t),
      };
      return { allowed: true };

    // Campaign Clustering  Free: BLOCKED, Pro+: ALLOWED (Enterprise gets full member details)
    case "ai_campaigns":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "DBSCAN campaign intelligence requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ai_campaigns", t),
      };
      return { allowed: true };

    // Anomaly Detection  Free: BLOCKED, Pro+: ALLOWED (Enterprise gets zero-day indicators)
    case "ai_anomalies":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Isolation Forest anomaly detection + zero-day candidate flagging requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("ai_anomalies", t),
      };
      return { allowed: true };

    // Intelligence Graph  Free: BLOCKED, Pro: summary only, Enterprise: full graph
    case "intel_graph":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "IOC intelligence graph access requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("intel_graph", t),
      };
      return { allowed: true };

    // Intelligence Graph  full node list (Enterprise only)
    case "intel_graph_full":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "Full IOC graph (all nodes + attribution edges) is Enterprise-exclusive.",
        upgrade: buildUpgradeTrigger("intel_graph_full", t),
      };
      return { allowed: true };

    // Intelligence Relations (BFS traversal)  Free: BLOCKED, Pro: depth1 + 5 results, Enterprise: full
    case "intel_relations":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "IOC relationship traversal + actor attribution requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("intel_relations", t),
      };
      return { allowed: true };

    // Detection rules (Sigma / KQL / Suricata) - Free: BLOCKED, Pro+: ALLOWED
    case "detection_rules":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Sigma rules, KQL queries, and Suricata signatures require Pro or Enterprise. Deploy detections directly to your SIEM.",
        upgrade: buildUpgradeTrigger("detection_rules", t),
      };
      return { allowed: true };

    // Threat actor attribution (identity, aliases, TTPs, sectors, motivation) - Free: BLOCKED, Pro+: ALLOWED
    case "actor_attribution":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Full threat actor attribution (identity, aliases, TTPs, sectors, motivation) requires Pro or Enterprise.",
        upgrade: buildUpgradeTrigger("actor_attribution", t),
      };
      return { allowed: true };

    //  Phase 3: resource cases for modules that gated tier access inline in
    //  index.js with no shared policy (each message/threshold below matches
    //  exactly what that inline check already enforces -- not a new rule).

    // TAXII 2.1 data endpoints  -  Free: BLOCKED, Pro+: ALLOWED
    case "taxii_access":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "TAXII data endpoints require PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("taxii", t),
      };
      return { allowed: true };

    // TAXII CISA KEV collection  -  Enterprise/MSSP only
    case "taxii_kev":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "KEV collection (CISA Known Exploited Vulnerabilities, confirmed) requires ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("taxii_kev", t),
      };
      return { allowed: true };

    // MISP JSON export  -  Enterprise/MSSP only (v185.9 Wave A Phase 3: no
    // canonical resource previously existed for /api/misp/export, which was
    // gated only by enterprise-endpoints.js's own legacy requireEnterprise()
    // inline check -- this case mirrors that exact rule, matching the
    // taxii_kev/siem enterprise_only cases above.)
    case "misp_export":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "MISP JSON export requires ENTERPRISE or MSSP tier.",
        upgrade: buildUpgradeTrigger("misp_export", t),
      };
      return { allowed: true };

    // Brand Protection (typosquatting/homograph scanning)  -  Free: BLOCKED, Pro+: ALLOWED
    case "brand_protection":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Brand Protection requires PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("brand", t),
      };
      return { allowed: true };

    // Vendor Risk Assessment (FAIR model)  -  Free: BLOCKED, Pro+: ALLOWED
    case "vendor_risk":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Vendor Risk Assessment requires PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("vendor_risk", t),
      };
      return { allowed: true };

    // Bulk vendor risk assessment (up to 50 vendors/request)  -  Enterprise/MSSP only
    case "vendor_risk_bulk":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "Bulk vendor assessment requires ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("vendor_risk_bulk", t),
      };
      return { allowed: true };

    // Geopolitical Risk Intelligence (country/sanctions/landscape)  -  Free: BLOCKED, Pro+: ALLOWED
    case "geopolitical_risk":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Geopolitical Risk Intelligence requires PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("geopolitical", t),
      };
      return { allowed: true };

    // Natural Language Query on the live intel feed  -  Free: BLOCKED, Pro+: ALLOWED
    case "nlq":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Natural Language Query requires PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("nlq", t),
      };
      return { allowed: true };

    // Incident Response CRUD (NIST SP 800-61r3 lifecycle)  -  Free: BLOCKED, Pro+: ALLOWED
    case "incident_response":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Incident Response requires PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("incident_response", t),
      };
      return { allowed: true };

    // Incident deletion  -  Enterprise/MSSP only
    case "incident_delete":
      if (!isEnt) return {
        allowed: false,
        resource,
        reason:  "enterprise_only",
        message: "ENTERPRISE tier required to delete incidents.",
        upgrade: buildUpgradeTrigger("incident_delete", t),
      };
      return { allowed: true };

    // /api/v1/intel/latest.json full manifest (report_url, pdf_url)  -  Free: sanitized, Pro+: full
    case "intel_manifest_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Full manifest (report_url, pdf_url, premium fields) requires PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("intel_manifest", t),
      };
      return { allowed: true };

    // CVE detail lookup  -  Free: truncated summary, Pro+: full detail
    case "cve_detail_full":
      if (isFree) return {
        allowed: false,
        resource,
        reason:  "pro_required",
        message: "Full CVE detail requires PRO or ENTERPRISE tier.",
        upgrade: buildUpgradeTrigger("cve_detail", t),
      };
      return { allowed: true };

    default:
      return { allowed: true };
  }
}

// 
// PHASE 1B  Usage Billing Tracker (KV-backed)
// Tracks per-key daily API calls. Enforces hard cap for free tier.
// KV key format: usage:<key_id>:<YYYY-MM-DD>
// 
export async function trackUsageAndEnforce(env, keyId, tier) {
  if (!env?.SECURITY_HUB_KV || !keyId) return { allowed: true, count: 0 };

  const t      = (tier || "FREE").toUpperCase();
  const limit  = REVENUE_CONFIG.LIMITS[t]?.api_calls_day ?? REVENUE_CONFIG.LIMITS.FREE.api_calls_day;

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
        message:  `Daily API limit reached (${limit} calls). ${dailyUpgradeHint(t)}`,
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

// 
// PHASE 1C  Revenue Trigger Builder
// Generates consistent upgrade trigger objects for API responses
// 
export function buildUpgradeTrigger(context, currentTier) {
  const t = (currentTier || "FREE").toUpperCase();
  const targetTier = t === "FREE" ? "pro" : "enterprise";
  const url = t === "FREE"
    ? REVENUE_CONFIG.UPGRADE_URLS.free_to_pro
    : REVENUE_CONFIG.UPGRADE_URLS.pro_to_enterprise;

  const contextMessages = {
    ioc:              { title: "Unlock Full IOC Arrays",         body: "See every IP, domain, hash and URL extracted from this threat. Used by SOC teams globally." },
    stix:             { title: "Access STIX 2.1 Bundles",        body: "Import threat objects directly into your SIEM, SOAR, or threat platform." },
    stix_full:        { title: "Upgrade to Enterprise",          body: "Full STIX bundle export with all objects and relationships." },
    ai:               { title: "Unlock Full AI Analysis",        body: "Kill chain mapping, actor fingerprinting, TTP scoring  real-time." },
    report:           { title: "Access Full Intel Reports",      body: "Deep attribution, technical analysis, and defensive recommendations." },
    siem:             { title: "Enterprise SIEM Push",           body: "Auto-push threats to Splunk, Sentinel, or QRadar in real-time." },
    alerts:           { title: "Real-Time Threat Alerts",        body: "Get notified instantly when critical threats emerge. Actor TTPs included." },
    api:              { title: "More API Keys",                  body: "Create multiple API keys for your team and CI/CD pipelines." },
    usage_limit:      { title: "Daily Limit Reached",            body: t === "FREE" ? `You've used all ${fmtCalls(REVENUE_CONFIG.LIMITS.FREE.api_calls_day)} free API calls today. ${dailyUpgradeHint(t)}` : dailyUpgradeHint(t) },
    approaching_limit:{ title: "80% of Daily Limit Used",        body: "You're close to your daily API limit. Upgrade now to avoid disruption." },
    detection_rules:  { title: "Unlock Sigma / KQL / Suricata",  body: "Deploy production-ready detection rules directly to Splunk, Sentinel, and your NIDS." },
    actor_attribution:{ title: "Unlock Threat Actor Attribution", body: "See who's behind the threat: aliases, TTPs, sectors, and motivation." },
  };

  const ctx = contextMessages[context] || { title: "Upgrade Your Plan", body: "Get more access, faster responses, and deeper intelligence." };

  // v185.2/v185.3 FIX (Fortune-500 audit): pro was "$29/mo", enterprise was
  // "$199/mo" -- both corrected to match the real Razorpay checkout amount
  // (pricing-data.json, traced via handleRazorpayCreateOrder). See the
  // matching comment on REVENUE_CONFIG.PRICING above for the full trace.
  const prices = {
    pro:        { inr: "4,100/mo", usd: "$49/mo" },
    enterprise: { inr: "41,600/mo", usd: "$499/mo" },
  };

  // trial_url/cta_trial deliberately removed (real defect, fixed here): this
  // repo's one true checkout contract (established across pricing.html,
  // upgrade.html, index.html, get-api-key.html -- see PR #251/#281) is that
  // there is no trial -- PRO/Enterprise/MSSP are billed the full listed
  // price immediately at checkout. This function's output reaches real
  // customers via enforceTierGate()'s `upgrade` field, spread into
  // masked.campaigns_paywall/anomalies_paywall by maskForFreeTier() (index.js)
  // for every FREE-tier request to /api/v1/intel/ai_summary.json -- so the
  // "Start 7-Day Free Trial" claim this function returned was live and
  // customer-facing, not dead code, despite buildUpgradeTrigger() itself
  // having no direct call site in index.js.
  return {
    trigger_context:  context,
    current_tier:     t,
    target_tier:      targetTier,
    title:            ctx.title,
    message:          ctx.body,
    price:            prices[targetTier] || prices.pro,
    upgrade_url:      url,
    cta_primary:      targetTier === "pro" ? `Upgrade to Pro  ${prices.pro.usd}` : `Upgrade to Enterprise  ${prices.enterprise.usd}`,
    features:         getUpgradeFeatures(targetTier),
    revenue_event:    `upgrade_trigger:${context}:${t}${targetTier}`,
  };
}

// Quota copy is derived from LIMITS (contract-gated) so upgrade messages can
// never quote a figure the limiter does not enforce.
function fmtCalls(n) {
  return Number(n).toLocaleString("en-US");
}

// Next paid tier's contracted daily quota for a customer who hit theirs.
// Never "unlimited": every tier is capped (commercial-contract.json).
function dailyUpgradeHint(tier) {
  const L = REVENUE_CONFIG.LIMITS;
  if (tier === "FREE") return `Upgrade to Pro for ${fmtCalls(L.PRO.api_calls_day)} calls/day.`;
  if (tier === "PRO")  return `Upgrade to Enterprise for ${fmtCalls(L.ENTERPRISE.api_calls_day)} calls/day.`;
  return "Your plan's daily quota resets at 00:00 UTC. Contact sales for higher volume.";
}

function getUpgradeFeatures(targetTier) {
  const L = REVENUE_CONFIG.LIMITS;
  if (targetTier === "enterprise") {
    // P0 2026-09-24: previously claimed unlimited API calls (a _forbidden_claims entry in
    // commercial-contract.json) and "White-label API" (white_label is MSSP-only
    // in the contract; ENTERPRISE white_label=false).
    return [`${L.ENTERPRISE.rpm} req/min`, `${fmtCalls(L.ENTERPRISE.api_calls_day)} API calls/day`, "Full STIX 2.1 bundles", "SIEM push integrations", "99.9% uptime SLA", "Email and chat support, 4h response"];
  }
  // v185.2 FIX (Fortune-500 audit, Phase 9): was "500 req/min" -- the actual
  // enforced PRO rate limit (RATE_LIMITS.PRO, index.js) is 120 req/min.
  return [`${L.PRO.rpm} req/min`, `${fmtCalls(L.PRO.api_calls_day)} API calls/day`, "Full IOC arrays", "Full AI analysis", "Threat alerts", "Email support, 48h response"];
}

// 
// PHASE 2A  Lead Capture Backend
// POST /api/leads/capture  stores email + context before gated content
// POST /api/leads/trial    issues 7-day PRO trial + API key
// 
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
        // New lead  store + trigger welcome sequence flag
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
        // Returning lead  update last seen
        existing.last_seen = ts;
        existing.visit_count = (existing.visit_count || 1) + 1;
        await env.SECURITY_HUB_KV.put(kvKey, JSON.stringify(existing), { expirationTtl: REVENUE_CONFIG.LEAD_KV_TTL });
      }
    }

    return revenueJson({
      status:      "captured",
      message:     "Access granted. Check your email for full report delivery.",
      // Shape kept for compatibility; commercial-contract.json offers no free
      // trial, so this now always reports available:false (P0 2026-09-24).
      trial_offer: {
        available: false,
        message:   "No free trial. The Free tier is available without payment; Pro starts immediately after checkout.",
        url:       REVENUE_CONFIG.UPGRADE_URLS.pricing,
      },
      request_id:  rid,
    });
  } catch (e) {
    return revenueJson({ error: "capture_failed", message: e.message }, 500);
  }
}

// 
// PHASE 2B  Trial Issuance Engine
// POST /api/leads/trial  issues 7-day PRO trial + API key instantly
//
// DEPRECATED 2026-09-24: no longer routed. commercial-contract.json states
// "No free trial" for every tier; POST /api/leads/trial now answers 410 with
// TRIAL_DISCONTINUED_BODY. Replacement: the Free tier (no payment) or a paid
// plan via /upgrade.html. Kept exported for one release so any out-of-tree
// importer keeps building; remove at the next major P-layer release.
// 
export const TRIAL_DISCONTINUED_BODY = Object.freeze({
  error:       "trial_discontinued",
  message:     "Sentinel APEX does not offer a free trial. The Free tier is available without payment, and paid plans activate immediately after checkout.",
  free_tier:   "https://intel.cyberdudebivash.com/pricing.html",
  pricing_url: "https://intel.cyberdudebivash.com/pricing.html",
  upgrade_url: "https://intel.cyberdudebivash.com/upgrade.html?plan=pro",
  deprecated:  "2026-09-24",
});

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

    // One trial per email  enforce
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
      rate_limit:  REVENUE_CONFIG.LIMITS.PRO.rpm,
      daily_limit: REVENUE_CONFIG.LIMITS.PRO.api_calls_day,
    };
    // FIX (P0, 2026-09-10, CodeRabbit review on PR #407): stored under
    // `key:${keyHash}` -- every real reader of API_KEYS_KV disagrees.
    // resolveAuth() (index.js) does env.API_KEYS_KV.get(raw, "json") with
    // the RAW key and no prefix, matching every other writer in this
    // codebase (index.js:2911,3775,3853 -- confirmed via repo-wide grep,
    // none use a hash or a "key:" prefix). A trial key issued via this
    // function could never actually authenticate on any subsequent
    // request -- this bug was only ever exercised for the first time when
    // this function was wired into intel-gateway's live router in this
    // same PR, so it was latent, not a regression of previously-working
    // behavior. `keyHash` itself is kept (still stored as the record's own
    // `key_hash` metadata field above) -- only the KV key this record is
    // addressed by changes.
    await env.API_KEYS_KV.put(apiKey, JSON.stringify(keyRecord), { expirationTtl: expTtl + 3600 });

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
      message:    `7-day Pro trial active. Your API key is below  save it securely.`,
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

// 
// PHASE 1D  Augmented applyTierGate (drop-in replacement for existing fn)
// Harder enforcement: blocks more fields, injects stronger upgrade triggers
// 
export function applyTierGateV2(item, tier, usageState) {
  const t      = (tier || "FREE").toUpperCase();
  const isFree = t === "FREE";
  const isPro  = t === "PRO";
  const isEnt  = t === "ENTERPRISE" || t === "MSSP";

  const gated = { ...item };

  //  IOC enforcement 
  if (isFree && Array.isArray(item.iocs) && item.iocs.length > 0) {
    const gate = enforceTierGate("ioc_full", t);
    gated.iocs       = [];
    gated.ioc_count  = item.iocs.length;
    gated.ioc_paywall = { ...gate, count: item.iocs.length };
  }

  //  STIX enforcement 
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

  // Detection rule enforcement (Sigma / KQL / Suricata) - v142.0
  if (isFree && (item.sigma_rule || item.kql_query || item.suricata_rule)) {
    const gate = enforceTierGate("detection_rules", t);
    gated.sigma_rule        = null;
    gated.kql_query         = null;
    gated.suricata_rule     = null;
    gated.detection_paywall = gate;
  }

  // Threat actor attribution enforcement - v142.0
  // actor_tag values like "CDB-UNATTR-*" / "UNC-UNKNOWN" mean "no attribution
  // available" and are not sensitive; only mask when real attribution exists.
  if (isFree) {
    const rawTag    = item.actor_tag;
    const noAttrTag = !rawTag || /^CDB-UNATTR/.test(String(rawTag)) || rawTag === "UNC-UNKNOWN";
    const hasAttribution = !noAttrTag
      || (item.actor_display_name && item.actor_display_name !== "Unknown Threat Actor")
      || (Array.isArray(item.actor_aliases) && item.actor_aliases.length > 0);
    if (hasAttribution) {
      const gate = enforceTierGate("actor_attribution", t);
      gated.actor_display_name = null;
      gated.actor_aliases      = null;
      gated.actor_sectors      = null;
      gated.actor_ttps         = null;
      gated.actor_malware      = null;
      gated.actor_mitre_id     = null;
      gated.actor_country      = null;
      gated.actor_motivation   = null;
      gated.actor_threat_level = null;
      gated.mitre_group_name    = null;
      gated.mitre_group_aliases = null;
      gated.actor_tag           = noAttrTag ? rawTag : null;
      gated.actor_paywall       = gate;
    }
  }

  //  AI analysis enforcement 
  gated.apex_ai = computeApexAIGated(item, t);
  // The raw `apex` object and `apex_ai_summary` text (populated by the
  // enrichment pipeline) carry full AI analysis and can embed attribution
  // inline in prose (e.g. "Actor attribution: <name>") - null/replace them
  // for FREE tier rather than relying on field-level masking of free text.
  if (isFree) {
    const aiGate = enforceTierGate("ai_full", t);
    gated.apex = { locked: true, upgrade: aiGate.upgrade || buildUpgradeTrigger("ai", t) };
    gated.apex_ai_summary = "Full AI threat analysis (kill chain mapping, actor fingerprint, TTP scoring) requires Pro or Enterprise.";
  }

  //  Report text truncation for free tier 
  if (isFree) {
    const desc = item.description || item.summary || "";
    if (desc.length > 280) {
      gated.description = desc.slice(0, 280) + "... [Full analysis available on Pro]";
      gated.report_paywall = enforceTierGate("report_full", t);
    }
  }

  //  Threat urgency CTA injection 
  if (isFree) {
    const sev       = (item.severity || item.risk_level || "").toUpperCase();
    const riskScore = typeof item.risk_score === "number" ? item.risk_score
                    : typeof item.cvss_score  === "number" ? item.cvss_score : 0;
    if (sev === "CRITICAL" || sev === "HIGH" || riskScore >= 7.0) {
      gated.threat_urgency = {
        active:       true,
        severity:     sev,
        message:      ` ${sev} ACTIVE THREAT  Full IOC array, actor attribution, and kill chain locked.`,
        upgrade:      buildUpgradeTrigger("ioc", t),
        cta_modal:    "upgrade_modal",
        cta_plan:     "pro",
      };
    }
  }

  //  Usage-based upsell injection 
  if (usageState?.upsell_nudge) {
    gated.usage_alert = usageState.upsell_nudge;
  }

  return gated;
}

// P0 fix (dashboard truth contract, 2026-08-11): ttp_density is a
// deterministic function of the `ttps`/`mitre_tactics` array -- and that
// array is already unlocked/customer-visible at every tier (only `iocs`,
// `stix_bundle`, detection rules, and actor attribution are tier-gated
// above). Nulling ttp_density for FREE tier hid a number derivable from
// data the same response already exposes, and for PAID tiers it read
// `item.apex.ttp_density` -- a field enrich_feed_apex.py never writes
// (the real value lives at `item.apex_ai.ttp_density`, itself stripped by
// public_api_sanitizer.py before any manifest is written) -- so it was
// silently 0 for every tier, not just FREE. Recomputed here from the same
// always-visible source and the same formula scripts/enrich_feed_apex.py's
// compute_ttp_density() already uses (len(ttps) * 1.5, capped at 10) --
// reused, not reinvented, and identical for every tier since there is no
// additional information being protected.
function _ttpDensityFromVisibleTtps(item) {
  // Mirrors compute_ttp_density()'s own `item.get("ttps") or
  // item.get("mitre_tactics") or []` -- an empty `ttps` array is treated
  // the same as an absent one and falls through to `mitre_tactics`.
  const ttps = (Array.isArray(item.ttps) && item.ttps.length > 0) ? item.ttps
             : (Array.isArray(item.mitre_tactics) && item.mitre_tactics.length > 0) ? item.mitre_tactics
             : [];
  return Math.round(Math.min(10, ttps.length * 1.5) * 10) / 10;
}

// Minimal computeApexAIGated  mirrors existing but enforces AI gate
function computeApexAIGated(item, tier) {
  const isFree = !tier || String(tier).toUpperCase() === "FREE";
  const base = {
    predictive_risk: typeof item.risk_score === "number" ? Math.min(10, item.risk_score) : 0,
    // 50 is the canonical unknown-confidence default (0-100 scale) -- see
    // CONFIDENCE_FRAMEWORK_DISCOVERY.md Part A7. Already correct here; kept
    // as-is, tagged for discoverability alongside the other sites that used
    // to disagree with it.
    ai_confidence:   typeof item.confidence === "number" ? Math.min(100, item.confidence * 100) : 50,
    ttp_density:     _ttpDensityFromVisibleTtps(item),
  };
  if (isFree) {
    return {
      ...base,
      ai_summary:     (item.apex?.ai_summary || item.description || "").slice(0, 120) + " [Full AI analysis requires Pro]",
      actor_fingerprint: null,
      kill_chain:     null,
      locked:         true,
      upgrade:        buildUpgradeTrigger("ai", tier),
    };
  }
  return {
    ...base,
    ai_summary:       item.apex?.ai_summary || item.description || "",
    actor_fingerprint: item.apex?.actor_fingerprint || null,
    kill_chain:       item.apex?.kill_chain        || null,
    locked:           false,
  };
}

// 
// PHASE 2C  Usage Limit Hit Handler
// Returns 402 Payment Required with upgrade trigger when daily cap hit
// 
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
      // Access-Control-Allow-Origin intentionally not set here -- SENTINEL
      // APEX PUBLIC-REPO ZERO-TRUST PHASE 3: this is a customer-specific
      // 402 rate-limit/upgrade response, never genuinely public -- index.js's
      // withBaselineHeaders() applies the real, origin-aware decision via
      // cors-policy.js to every response including this one; see that
      // file's header comment.
    },
  });
}

// 
// Revenue Event Tracker  persists to SECURITY_HUB_KV for revenue analytics
// 
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

// 
// Revenue Analytics Endpoint  GET /api/revenue/analytics (admin only)
// 
export async function handleRevenueAnalytics(request, env, rid) {
  const adminSecret = request.headers.get("X-Admin-Secret");
  if (!env?.ADMIN_SECRET || !timingSafeEqual(adminSecret || "", env.ADMIN_SECRET)) {
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

// 
// Helpers
// 
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
      // Access-Control-Allow-Origin intentionally not set here -- SENTINEL
      // APEX PUBLIC-REPO ZERO-TRUST PHASE 3: this is a shared revenue-
      // enforcement helper (upgrade prompts, entitlement state), never
      // genuinely public -- index.js's withBaselineHeaders() applies the
      // real, origin-aware decision via cors-policy.js to every response
      // including this one; see that file's header comment.
    },
  });
}
