// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — Usage Meter Engine v134.0.0
// Phase 1: Per-endpoint API usage tracking · Cost calculation · Peak detection
// Storage: ANALYTICS_KV  (existing binding — no new infra required)
// KV keys:
//   meter:total:<userId>:<date>                — total calls per user per day
//   meter:ep:<endpoint_slug>:<date>            — global endpoint hit counts
//   meter:user_ep:<userId>:<endpoint_slug>:<date> — per-user per-endpoint
//   meter:cost:<userId>:<date>                 — credits consumed per user per day
//   meter:peak:<userId>:<date>                 — {hour, count} peak usage record
//   meter:patterns:<userId>                    — rolling usage patterns (30d)
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// CREDIT COST TABLE — credits deducted per API call by endpoint + tier
// Free tier pays 1:1 (credit/call) on most endpoints; Pro/Enterprise discounted
// Gated endpoints (ai/stix/export) cost more — reflects real compute cost
// ─────────────────────────────────────────────────────────────────────────────
const COST_TABLE = {
  // Public (no credit deduction — authenticated endpoints only)
  "preview":               { free: 0, premium: 0, enterprise: 0 },
  "health":                { free: 0, premium: 0, enterprise: 0 },
  "version":               { free: 0, premium: 0, enterprise: 0 },

  // Core intel feed — base cost
  "feed":                  { free: 2, premium: 1, enterprise: 1 },
  "feed_item":             { free: 3, premium: 1, enterprise: 1 },

  // Search + structured queries
  "search":                { free: 3, premium: 2, enterprise: 1 },
  "actors":                { free: 3, premium: 2, enterprise: 1 },
  "cves":                  { free: 3, premium: 2, enterprise: 1 },
  "analytics":             { free: 2, premium: 1, enterprise: 1 },

  // AI Intelligence — higher compute cost
  "predict":               { free: 10, premium: 5, enterprise: 2 },
  "campaigns":             { free: 10, premium: 5, enterprise: 2 },
  "anomalies":             { free: 10, premium: 5, enterprise: 2 },

  // Intelligence graph + correlation
  "intel_graph":           { free: 8,  premium: 4, enterprise: 2 },
  "intel_relations":       { free: 8,  premium: 4, enterprise: 2 },
  "intel_correlate":       { free: 8,  premium: 4, enterprise: 2 },

  // STIX / Export — bandwidth-heavy
  "stix_export":           { free: 15, premium: 8, enterprise: 3 },
  "export_misp":           { free: 15, premium: 8, enterprise: 3 },
  "export_csv":            { free: 10, premium: 5, enterprise: 2 },

  // Alerts + webhooks
  "alerts":                { free: 5,  premium: 3, enterprise: 1 },
  "webhooks_siem":         { free: 20, premium: 10, enterprise: 2 },

  // Account/billing — no cost
  "auth":                  { free: 0, premium: 0, enterprise: 0 },
  "keys":                  { free: 0, premium: 0, enterprise: 0 },
  "billing":               { free: 0, premium: 0, enterprise: 0 },
  "account_usage":         { free: 0, premium: 0, enterprise: 0 },

  // Default fallback
  "default":               { free: 1, premium: 1, enterprise: 1 },
};

// Endpoint path → slug mapping (prefix-based for efficiency)
const ENDPOINT_SLUG_MAP = [
  { prefix: "/api/preview",            slug: "preview"         },
  { prefix: "/api/health",             slug: "health"          },
  { prefix: "/api/version",            slug: "version"         },
  { prefix: "/api/feed/",              slug: "feed_item"       },
  { prefix: "/api/feed",               slug: "feed"            },
  { prefix: "/api/search",             slug: "search"          },
  { prefix: "/api/actors",             slug: "actors"          },
  { prefix: "/api/cves",               slug: "cves"            },
  { prefix: "/api/analytics",          slug: "analytics"       },
  { prefix: "/api/predict",            slug: "predict"         },
  { prefix: "/api/campaigns",          slug: "campaigns"       },
  { prefix: "/api/anomalies",          slug: "anomalies"       },
  { prefix: "/api/intelligence/graph", slug: "intel_graph"     },
  { prefix: "/api/intelligence/",      slug: "intel_relations" },
  { prefix: "/api/intel/correlate",    slug: "intel_correlate" },
  { prefix: "/api/stix/",              slug: "stix_export"     },
  { prefix: "/api/export/misp",        slug: "export_misp"     },
  { prefix: "/api/export/csv",         slug: "export_csv"      },
  { prefix: "/api/alerts",             slug: "alerts"          },
  { prefix: "/api/webhooks/siem",      slug: "webhooks_siem"   },
  { prefix: "/api/auth",               slug: "auth"            },
  { prefix: "/api/keys",               slug: "keys"            },
  { prefix: "/api/billing",            slug: "billing"         },
  { prefix: "/api/account",            slug: "account_usage"   },
  { prefix: "/auth/",                  slug: "auth"            },
];

// ─────────────────────────────────────────────────────────────────────────────
// slugifyEndpoint — converts a request pathname to a cost-table slug
// ─────────────────────────────────────────────────────────────────────────────
export function slugifyEndpoint(pathname) {
  for (const { prefix, slug } of ENDPOINT_SLUG_MAP) {
    if (pathname.startsWith(prefix)) return slug;
  }
  return "default";
}

// ─────────────────────────────────────────────────────────────────────────────
// calculateCostPerCall — returns credit cost for a given endpoint + tier
// ─────────────────────────────────────────────────────────────────────────────
export function calculateCostPerCall(endpointSlug, tier) {
  const t     = (tier || "free").toLowerCase();
  const costs = COST_TABLE[endpointSlug] || COST_TABLE.default;
  // Tier key mapping: "premium" → "premium", "enterprise" → "enterprise", else "free"
  const tierKey = t === "enterprise" ? "enterprise" : t === "premium" ? "premium" : "free";
  return costs[tierKey] ?? 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// trackApiUsage — records a metered API call in ANALYTICS_KV
// Call AFTER auth succeeds and AFTER credit deduction to ensure billing-accurate logs
// Fully async — fire-and-forget inside waitUntil (never blocks response)
// ─────────────────────────────────────────────────────────────────────────────
export async function trackApiUsage(env, userId, endpointSlug, tier, creditsCost) {
  if (!env?.ANALYTICS_KV || !userId) return;

  const kv      = env.ANALYTICS_KV;
  const date    = new Date().toISOString().slice(0, 10);   // "YYYY-MM-DD"
  const hour    = new Date().getUTCHours();
  const TTL     = 86400 * 90;  // 90-day retention
  const cost    = typeof creditsCost === "number" ? creditsCost : 0;

  // Atomic-ish increment helper (KV best-effort — eventual consistency acceptable for analytics)
  const inc = async (key, amount = 1) => {
    try {
      const prev = parseInt(await kv.get(key) || "0");
      await kv.put(key, String(prev + amount), { expirationTtl: TTL });
    } catch { /* non-critical */ }
  };

  const slug = endpointSlug || "default";
  const uid  = String(userId).slice(0, 64);

  await Promise.allSettled([
    // Per-user daily total
    inc(`meter:total:${uid}:${date}`),
    // Per-endpoint global daily count
    inc(`meter:ep:${slug}:${date}`),
    // Per-user per-endpoint daily count
    inc(`meter:user_ep:${uid}:${slug}:${date}`),
    // Per-user credit cost accumulator
    inc(`meter:cost:${uid}:${date}`, cost),
    // Per-user per-hour call count (for peak detection)
    inc(`meter:peak_h:${uid}:${date}:${hour}`),
    // Global tier distribution
    inc(`meter:tier:${tier || "free"}:${date}`),
  ]);

  // Update rolling usage pattern (peak hour tracking — async, non-blocking)
  _updatePeakPattern(kv, uid, date, hour, TTL).catch(() => {});
}

async function _updatePeakPattern(kv, uid, date, hour, TTL) {
  const peakKey = `meter:peak:${uid}:${date}`;
  try {
    const existing = await kv.get(peakKey, { type: "json" }) || { hour: hour, count: 0, hours: {} };
    const hours    = existing.hours || {};
    hours[hour]    = (hours[hour] || 0) + 1;
    // Track which hour had the most calls
    const peakHr  = Object.entries(hours).sort(([,a],[,b]) => b - a)[0];
    await kv.put(peakKey, JSON.stringify({
      peak_hour:  parseInt(peakHr?.[0] ?? hour),
      peak_count: peakHr?.[1] ?? 1,
      hours,
      date,
    }), { expirationTtl: TTL });
  } catch { /* non-critical */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// getUsageSummary — returns full per-user usage breakdown for a given date
// Used by: /api/account/usage, /api/revenue, billing_status headers
// ─────────────────────────────────────────────────────────────────────────────
export async function getUsageSummary(env, userId, date) {
  if (!env?.ANALYTICS_KV || !userId) return null;

  const kv   = env.ANALYTICS_KV;
  const d    = date || new Date().toISOString().slice(0, 10);
  const uid  = String(userId).slice(0, 64);

  try {
    const [totalRaw, costRaw, peakData] = await Promise.all([
      kv.get(`meter:total:${uid}:${d}`),
      kv.get(`meter:cost:${uid}:${d}`),
      kv.get(`meter:peak:${uid}:${d}`, { type: "json" }),
    ]);

    // Endpoint breakdown — fetch known slugs for this user+date
    const KNOWN_SLUGS = ["feed","feed_item","search","actors","cves","predict","campaigns","anomalies","intel_graph","intel_correlate","stix_export","export_misp","export_csv","alerts","analytics"];
    const epEntries   = await Promise.all(
      KNOWN_SLUGS.map(async sl => {
        const v = parseInt(await kv.get(`meter:user_ep:${uid}:${sl}:${d}`) || "0");
        return [sl, v];
      })
    );
    const endpoint_usage = Object.fromEntries(epEntries.filter(([,v]) => v > 0));

    return {
      date,
      user_id:          uid,
      requests_count:   parseInt(totalRaw || "0"),
      credits_consumed: parseInt(costRaw  || "0"),
      peak_hour:        peakData?.peak_hour  ?? null,
      peak_count:       peakData?.peak_count ?? 0,
      endpoint_usage,
      timestamp:        new Date().toISOString(),
    };
  } catch { return null; }
}

// ─────────────────────────────────────────────────────────────────────────────
// getEndpointStats — global endpoint analytics (admin/revenue dashboard)
// Returns top endpoints by call volume for a given date
// ─────────────────────────────────────────────────────────────────────────────
export async function getEndpointStats(env, date) {
  if (!env?.ANALYTICS_KV) return [];

  const kv = env.ANALYTICS_KV;
  const d  = date || new Date().toISOString().slice(0, 10);

  const KNOWN_SLUGS = [
    "feed","feed_item","search","actors","cves","predict","campaigns","anomalies",
    "intel_graph","intel_relations","intel_correlate","stix_export","export_misp",
    "export_csv","alerts","webhooks_siem","analytics","default",
  ];

  try {
    const results = await Promise.all(
      KNOWN_SLUGS.map(async sl => {
        const count = parseInt(await kv.get(`meter:ep:${sl}:${d}`) || "0");
        const cost  = COST_TABLE[sl] || COST_TABLE.default;
        return { endpoint: sl, calls: count, avg_cost_free: cost.free, avg_cost_pro: cost.premium };
      })
    );
    return results.filter(r => r.calls > 0).sort((a, b) => b.calls - a.calls);
  } catch { return []; }
}

// ─────────────────────────────────────────────────────────────────────────────
// getTierDistribution — how many calls came from each tier today
// Used by /api/revenue dashboard
// ─────────────────────────────────────────────────────────────────────────────
export async function getTierDistribution(env, date) {
  if (!env?.ANALYTICS_KV) return {};

  const kv = env.ANALYTICS_KV;
  const d  = date || new Date().toISOString().slice(0, 10);

  try {
    const [free, premium, enterprise] = await Promise.all([
      kv.get(`meter:tier:free:${d}`),
      kv.get(`meter:tier:premium:${d}`),
      kv.get(`meter:tier:enterprise:${d}`),
    ]);
    return {
      free:       parseInt(free       || "0"),
      premium:    parseInt(premium    || "0"),
      enterprise: parseInt(enterprise || "0"),
    };
  } catch { return {}; }
}

// ─────────────────────────────────────────────────────────────────────────────
// analyzeUsagePatterns — Phase 6 auto-optimization
// Returns adaptive signals: upgrade suggestions, high-value endpoint flags
// ─────────────────────────────────────────────────────────────────────────────
export async function analyzeUsagePatterns(env, userId, tier, creditBalance, creditLimit) {
  const signals = [];

  // Signal 1: Approaching daily/monthly credit limit (>= 70% used)
  const pctUsed = creditLimit > 0 ? (creditLimit - creditBalance) / creditLimit : 0;

  if (pctUsed >= 0.90 && tier === "free") {
    signals.push({
      type:      "upgrade_critical",
      message:   "90% of daily free credits used. Upgrade to Pro for 10,000 monthly credits.",
      urgency:   "high",
      cta_url:   "https://intel.cyberdudebivash.com/upgrade?plan=pro&ref=usage_90pct",
    });
  } else if (pctUsed >= 0.70 && tier === "free") {
    signals.push({
      type:      "upgrade_nudge",
      message:   "70% of daily free credits used. Pro tier gives 100× more access.",
      urgency:   "medium",
      cta_url:   "https://intel.cyberdudebivash.com/upgrade?plan=pro&ref=usage_70pct",
    });
  } else if (pctUsed >= 0.70 && tier === "premium") {
    signals.push({
      type:      "upgrade_enterprise",
      message:   "70% of monthly Pro credits used. Enterprise offers unlimited access.",
      urgency:   "low",
      cta_url:   "https://intel.cyberdudebivash.com/upgrade?plan=enterprise&ref=usage_70pct",
    });
  }

  // Signal 2: High-value endpoint usage (AI/export) on free tier → upgrade signal
  if (tier === "free") {
    try {
      const kv   = env?.ANALYTICS_KV;
      const date = new Date().toISOString().slice(0, 10);
      const uid  = String(userId).slice(0, 64);
      const aiCalls = parseInt(await kv?.get(`meter:user_ep:${uid}:predict:${date}`) || "0")
                    + parseInt(await kv?.get(`meter:user_ep:${uid}:campaigns:${date}`) || "0")
                    + parseInt(await kv?.get(`meter:user_ep:${uid}:anomalies:${date}`) || "0");
      if (aiCalls >= 3) {
        signals.push({
          type:    "high_value_usage",
          message: "You've been using AI intelligence endpoints. Pro unlocks unlimited AI threat analysis.",
          urgency: "medium",
          cta_url: "https://intel.cyberdudebivash.com/upgrade?plan=pro&ref=ai_usage",
        });
      }
    } catch { /* non-critical */ }
  }

  return signals;
}
