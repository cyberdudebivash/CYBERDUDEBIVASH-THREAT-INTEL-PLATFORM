// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Credit System v134.0.0
// Phase 2: Token/Credit model -- balance management, tier enforcement, billing
// Phase 3: Billing engine -- 402 on exhaustion, blocking gate, billing_status
// Phase 9: Security -- no negative credits, no bypass, all paths gated
//
// Storage: SECURITY_HUB_KV (existing binding -- no new infra required)
// KV keys:
//   credits:bal:<userId>:<periodKey>    -- balance record (JSON)
//   credits:exhaust:<userId>:<date>     -- exhaustion event count (for analytics)
// =============================================================================

// 
// CREDIT LIMITS -- authoritative allocation per tier
// FREE:       100  credits / day   (resets at midnight UTC)
// PRO:       10000 credits / month (resets on 1st of month UTC)
// ENTERPRISE:     (unlimited -- credits not tracked, always allowed)
// 
export const CREDIT_CONFIG = {
  FREE:       { limit: 100,   period: "day",   tier_key: "free"       },
  PRO:        { limit: 10000, period: "month",  tier_key: "premium"    },
  ENTERPRISE: { limit: -1,    period: "none",   tier_key: "enterprise" },

  // Upgrade URLs for billing prompts
  UPGRADE: {
    free_to_pro:       "https://intel.cyberdudebivash.com/upgrade?plan=pro",
    pro_to_enterprise: "https://intel.cyberdudebivash.com/upgrade?plan=enterprise",
    trial:             "https://intel.cyberdudebivash.com/trial",
  },

  // KV TTLs
  TTL_DAY:    86400 + 3600,    // 25h (covers timezone drift)
  TTL_MONTH:  86400 * 32,      // 32 days
};

// 
// _tierConfig -- get credit config for a given tier string
// 
function _tierConfig(tier) {
  const t = (tier || "free").toLowerCase();
  if (t === "enterprise") return CREDIT_CONFIG.ENTERPRISE;
  if (t === "premium")    return CREDIT_CONFIG.PRO;
  return CREDIT_CONFIG.FREE;
}

// 
// _periodKey -- current period string for credit window
// FREE -> "2026-04-20" (daily)    PRO -> "2026-04" (monthly)
// 
function _periodKey(cfg) {
  const iso = new Date().toISOString();
  return cfg.period === "month" ? iso.slice(0, 7) : iso.slice(0, 10);
}

// 
// _kvKey -- returns the KV balance key for a user in the current period
// 
function _kvKey(userId, periodKey) {
  return `credits:bal:${String(userId).slice(0, 64)}:${periodKey}`;
}

// 
// getCredits -- read current credit balance for a user
// Auto-initializes if no record exists for the current period.
// Returns: { balance, initial, tier, period, period_key, is_new }
// Enterprise: returns { balance: Infinity, unlimited: true }
// 
export async function getCredits(env, userId, tier) {
  const cfg = _tierConfig(tier);

  // Enterprise -- unlimited, skip KV entirely
  if (cfg.limit === -1) {
    return { balance: Infinity, initial: Infinity, tier, unlimited: true, period: "none", period_key: "none" };
  }

  if (!env?.SECURITY_HUB_KV || !userId) {
    // KV unavailable -- fail open (never block on infra failure)
    return { balance: cfg.limit, initial: cfg.limit, tier, unlimited: false, period: cfg.period, period_key: _periodKey(cfg), error: "kv_unavailable" };
  }

  const periodKey = _periodKey(cfg);
  const key       = _kvKey(userId, periodKey);

  try {
    const stored = await env.SECURITY_HUB_KV.get(key, { type: "json" });

    if (stored && stored.period_key === periodKey) {
      // Valid record for this period
      return {
        balance:    Math.max(0, stored.balance ?? cfg.limit),
        initial:    stored.initial ?? cfg.limit,
        tier,
        unlimited:  false,
        period:     cfg.period,
        period_key: periodKey,
        is_new:     false,
      };
    }

    // No record / stale period -> initialize fresh credits
    const rec = {
      balance:    cfg.limit,
      initial:    cfg.limit,
      tier,
      period_key: periodKey,
      period:     cfg.period,
      created_at: new Date().toISOString(),
    };
    const ttl = cfg.period === "month" ? CREDIT_CONFIG.TTL_MONTH : CREDIT_CONFIG.TTL_DAY;
    await env.SECURITY_HUB_KV.put(key, JSON.stringify(rec), { expirationTtl: ttl });

    return { ...rec, unlimited: false, is_new: true };
  } catch {
    // KV error -- fail open (never block legitimate requests due to infra failure)
    return { balance: cfg.limit, initial: cfg.limit, tier, unlimited: false, period: cfg.period, period_key: periodKey, error: "kv_error" };
  }
}

// 
// deductCredits -- deduct `amount` credits from user balance
// SECURITY: balance NEVER goes below 0 (non-negative guard enforced here)
// Returns: { ok: bool, balance_before, balance_after, deducted, exhausted }
// 
export async function deductCredits(env, userId, amount, tier) {
  const cfg = _tierConfig(tier);

  // Enterprise -- unlimited, nothing to deduct
  if (cfg.limit === -1) return { ok: true, unlimited: true, deducted: 0, balance_after: Infinity };

  // Zero-cost call (auth endpoints, health, etc.) -- skip KV write
  if (!amount || amount <= 0) return { ok: true, deducted: 0, balance_after: null, zero_cost: true };

  if (!env?.SECURITY_HUB_KV || !userId) {
    return { ok: true, deducted: amount, balance_after: null, error: "kv_unavailable" };
  }

  const periodKey = _periodKey(cfg);
  const key       = _kvKey(userId, periodKey);
  const ttl       = cfg.period === "month" ? CREDIT_CONFIG.TTL_MONTH : CREDIT_CONFIG.TTL_DAY;

  try {
    const stored = await env.SECURITY_HUB_KV.get(key, { type: "json" });
    const before  = stored?.period_key === periodKey
      ? Math.max(0, stored.balance ?? cfg.limit)
      : cfg.limit;  // Auto-init if stale period

    // SECURITY: enforce non-negative, cap deduction at available balance
    const actualDeduct = Math.min(amount, before);
    const after        = before - actualDeduct;

    const rec = {
      balance:    after,
      initial:    stored?.initial ?? cfg.limit,
      tier,
      period_key: periodKey,
      period:     cfg.period,
      created_at: stored?.created_at ?? new Date().toISOString(),
      last_deduct: new Date().toISOString(),
    };
    await env.SECURITY_HUB_KV.put(key, JSON.stringify(rec), { expirationTtl: ttl });

    // Track exhaustion event for analytics
    if (after === 0 && before > 0) {
      const date    = new Date().toISOString().slice(0, 10);
      const exhKey  = `credits:exhaust:${String(userId).slice(0, 64)}:${date}`;
      const exhPrev = parseInt(await env.SECURITY_HUB_KV.get(exhKey) || "0");
      await env.SECURITY_HUB_KV.put(exhKey, String(exhPrev + 1), { expirationTtl: CREDIT_CONFIG.TTL_DAY }).catch(() => {});
    }

    return {
      ok:             true,
      balance_before: before,
      balance_after:  after,
      deducted:       actualDeduct,
      exhausted:      after === 0,
    };
  } catch {
    return { ok: true, deducted: amount, balance_after: null, error: "kv_error" };
  }
}

// 
// checkCredits -- FULL GATE -- check balance, deduct if sufficient, return gate result
// This is the single entry point for all credit enforcement.
// Returns: { allowed: bool, status: object, 402Response?: Response }
// 
export async function checkCredits(env, userId, tier, cost, requestId) {
  const cfg = _tierConfig(tier);

  // Enterprise -- always allowed, no deduction
  if (cfg.limit === -1) {
    return {
      allowed: true,
      unlimited: true,
      status: buildBillingStatus(Infinity, 0, -1, tier, cost),
    };
  }

  // Zero-cost endpoint -- skip balance check entirely
  if (!cost || cost <= 0) {
    const bal = await getCredits(env, userId, tier);
    return {
      allowed: true,
      zero_cost: true,
      status: buildBillingStatus(bal.balance, (bal.initial - bal.balance), bal.initial, tier, 0),
    };
  }

  // Get current balance
  const bal = await getCredits(env, userId, tier);

  // GATE: check if sufficient credits exist
  if (bal.balance < cost) {
    const used   = bal.initial - bal.balance;
    const status = buildBillingStatus(bal.balance, used, bal.initial, tier, cost);

    // Build 402 Payment Required response
    const body402 = {
      error:       "credits_exhausted",
      message:     `Credit balance exhausted. ${tier === "free" ? "Upgrade to Pro for 10,000 monthly credits." : "Upgrade to Enterprise for unlimited access."}`,
      credits_remaining: 0,
      credits_used:      used,
      credit_limit:      bal.initial,
      period:            bal.period,
      reset_period:      bal.period_key,
      cost_of_request:   cost,
      tier,
      upgrade_url:       tier === "free" ? CREDIT_CONFIG.UPGRADE.free_to_pro : CREDIT_CONFIG.UPGRADE.pro_to_enterprise,
      trial_url:         CREDIT_CONFIG.UPGRADE.trial,
      billing_status:    status,
      request_id:        requestId,
    };

    const resp402 = new Response(JSON.stringify(body402, null, 2), {
      status: 402,
      headers: {
        "Content-Type":              "application/json",
        "X-Credits-Remaining":       "0",
        "X-Credits-Limit":           String(bal.initial),
        "X-Credits-Period":          bal.period,
        "X-Usage-Today":             String(used),
        "X-Plan":                    tier,
        "X-Upgrade-Url":             body402.upgrade_url,
        "Cache-Control":             "no-cache, no-store",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Expose-Headers": "X-Credits-Remaining,X-Credits-Limit,X-Credits-Period,X-Usage-Today,X-Plan,X-Upgrade-Url",
      },
    });

    return { allowed: false, status, response402: resp402 };
  }

  // Sufficient credits -- deduct
  const deduction = await deductCredits(env, userId, cost, tier);
  const newBalance = deduction.balance_after ?? (bal.balance - cost);
  const used       = bal.initial - newBalance;

  return {
    allowed:   true,
    deducted:  deduction.deducted,
    status:    buildBillingStatus(Math.max(0, newBalance), used, bal.initial, tier, cost),
  };
}

// 
// buildBillingStatus -- builds the billing_status object for API responses
// Attached to all authenticated API responses as a field + headers
// 
export function buildBillingStatus(balance, used, limit, tier, costThisCall) {
  const isUnlimited = limit === -1 || balance === Infinity;
  const pctUsed     = (!isUnlimited && limit > 0) ? Math.min(100, Math.floor((used / limit) * 100)) : 0;

  return {
    credits_remaining: isUnlimited ? null : Math.max(0, balance),
    credits_used:      isUnlimited ? null : Math.max(0, used),
    credit_limit:      isUnlimited ? null : limit,
    cost_this_call:    costThisCall ?? 0,
    pct_used:          isUnlimited ? 0   : pctUsed,
    plan:              tier,
    unlimited:         isUnlimited,
    upsell: (!isUnlimited && pctUsed >= 70) ? {
      active:  true,
      message: tier === "free"
        ? `${100 - pctUsed}% credits remaining today. Upgrade to Pro for 10,000/month.`
        : `${100 - pctUsed}% credits remaining. Enterprise offers unlimited access.`,
      upgrade_url: tier === "free" ? CREDIT_CONFIG.UPGRADE.free_to_pro : CREDIT_CONFIG.UPGRADE.pro_to_enterprise,
    } : null,
  };
}

// 
// buildCreditHeaders -- builds response headers for credit state
// 
export function buildCreditHeaders(billingStatus, usedToday) {
  const remaining = billingStatus?.credits_remaining;
  const limit     = billingStatus?.credit_limit;
  const plan      = billingStatus?.plan || "free";

  return {
    "X-Credits-Remaining": remaining !== null && remaining !== undefined ? String(remaining) : "unlimited",
    "X-Credits-Limit":     limit     !== null && limit     !== undefined ? String(limit)     : "unlimited",
    "X-Usage-Today":       String(usedToday ?? billingStatus?.credits_used ?? 0),
    "X-Plan":              plan,
    "Access-Control-Expose-Headers": "X-Credits-Remaining,X-Credits-Limit,X-Credits-Period,X-Usage-Today,X-Plan,X-RateLimit-Limit,X-RateLimit-Remaining,X-Tier",
  };
}

// 
// getCreditExhaustionStats -- how many users hit their credit limit today
// Used by /api/revenue dashboard
// 
export async function getCreditExhaustionStats(env, date) {
  if (!env?.SECURITY_HUB_KV) return { exhaustions_today: 0 };
  const d = date || new Date().toISOString().slice(0, 10);
  try {
    // List all exhaustion events for today
    const list = await env.SECURITY_HUB_KV.list({ prefix: `credits:exhaust:` });
    let total  = 0;
    for (const key of (list?.keys || [])) {
      if (key.name.endsWith(`:${d}`)) {
        const cnt = parseInt(await env.SECURITY_HUB_KV.get(key.name) || "0");
        total += cnt;
      }
    }
    return { exhaustions_today: total };
  } catch { return { exhaustions_today: 0 }; }
}
