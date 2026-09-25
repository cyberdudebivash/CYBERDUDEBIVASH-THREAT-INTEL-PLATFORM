/**
 * SENTINEL APEX AI THREAT FEED v1.0.0
 * Prices from commercial-contract via pricingSnapshot. No dollar literals.
 * No internet crawl. Hub catalog requires https source_url. STALE => 503.
 */
export const AI_FEED_NAME = "SENTINEL APEX AI THREAT FEED";
export const AI_FEED_VERSION = "1.0.0";
export const AI_FEED_SKU = "cdb-aish-feed";

const AI_VOCAB = Object.freeze([
  "mcp", "llm", "litellm", "agentic", "prompt injection", "coding agent",
  "claude code", "codex", "copilot", "gemini cli", "foundry", "openai agent",
  "model context protocol", "plugin4shell", "eval egress", "ai gateway",
]);
const LIMITS = Object.freeze({ FREE: 5, PRO: 25, ENTERPRISE: 100, MSSP: 100 });

export function normalizeTier(auth) {
  const raw = String((auth && auth.tier) || "FREE").toUpperCase();
  const status = String((auth && auth.subscription_status) || "active").toLowerCase();
  if (["cancelled", "canceled", "refunded", "suspended", "expired"].includes(status)) return "FREE";
  if (raw === "MSSP" || raw === "ENTERPRISE" || raw === "PRO") return raw;
  return "FREE";
}

export function isAiAdvisory(item) {
  const blob = [item && item.title, item && item.summary, item && item.product, Array.isArray(item && item.tags) ? item.tags.join(" ") : ""].join(" ").toLowerCase();
  return AI_VOCAB.some((k) => blob.includes(k));
}

export function validateHubItem(raw) {
  if (!raw || typeof raw !== "object") return { ok: false, error: "invalid_item" };
  if (!/^CDB-AISH-FEED-\d{4}-\d{4}-\d{2}$/.test(String(raw.id || ""))) return { ok: false, error: "invalid_id" };
  if (typeof raw.source_url !== "string" || !raw.source_url.startsWith("https://")) return { ok: false, error: "source_url_required" };
  if (!["NEW_PUBLIC", "STILL_OPEN"].includes(raw.status)) return { ok: false, error: "invalid_status" };
  if (!["CLEAR", "AMBER"].includes(raw.tlp || "CLEAR")) return { ok: false, error: "invalid_tlp" };
  return { ok: true, item: raw };
}

export function redact(item, tier) {
  const base = {
    id: item.id, title: item.title, severity: item.severity || "HIGH",
    status: item.status || "STILL_OPEN", tlp: item.tlp || "CLEAR", class: item.class || "AI-SEC",
    first_seen: item.first_seen || item.published || null,
    source_name: item.source_name || item.source || null,
    product: AI_FEED_NAME, sku: AI_FEED_SKU,
  };
  if (tier === "FREE") return { ...base, locked: true, upgrade: "/pricing", checkout: "/api/payments/razorpay/order" };
  const paid = { ...base, summary: item.summary || null, source_url: item.source_url || null, cves: Array.isArray(item.cves) ? item.cves : [], hub_ruling: item.hub_ruling || null, exploitation: item.exploitation || "UNKNOWN", locked: false };
  if (tier === "PRO") return paid;
  return { ...paid, timeline: Array.isArray(item.timeline) ? item.timeline : [], triggers: Array.isArray(item.triggers) ? item.triggers : [], actions: Array.isArray(item.actions) ? item.actions : [] };
}

export function mergeFeed(hubItems, advisories) {
  const out = []; const seen = new Set();
  for (const raw of hubItems || []) { const v = validateHubItem(raw); if (!v.ok) continue; seen.add(v.item.id); out.push(v.item); }
  for (const adv of advisories || []) {
    if (!isAiAdvisory(adv)) continue;
    const id = String(adv.id || adv.cve || "");
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push({ id, title: adv.title, summary: adv.summary || adv.description || "", severity: adv.severity || "MEDIUM", status: "STILL_OPEN", tlp: "CLEAR", class: "AI-SEC", first_seen: adv.published || adv.processed_at || null, source_name: adv.source || "sentinel-apex-catalog", source_url: adv.url || adv.reference || "https://intel.cyberdudebivash.com/", cves: adv.cve ? [adv.cve] : (adv.cves || []), hub_ruling: "Filtered from the live Sentinel catalog by AI vocabulary. Not a Hub-origin event.", exploitation: "UNKNOWN", origin: "sentinel_catalog" });
  }
  out.sort((a, b) => String(b.first_seen || "").localeCompare(String(a.first_seen || "")));
  return out;
}

export function offerBody(pricingSnapshot) {
  const tiers = (pricingSnapshot && pricingSnapshot.tiers) || {};
  return { product: AI_FEED_NAME, version: AI_FEED_VERSION, sku: AI_FEED_SKU, seller: "CYBERDUDEBIVASH(R)", statement: "AI-only live feed. Same freshness contract as Cyber Watchdog. Upgrade unlocks timeline, actions, and higher item caps.", checkout: "/pricing", endpoints: { offer: "GET /api/ai-feed/offer", health: "GET /api/ai-feed/health", live: "GET /api/ai-feed/live", item: "GET /api/ai-feed/item/:id" }, entitlements: { FREE: { items: LIMITS.FREE, timeline: false, actions: false }, PRO: { items: LIMITS.PRO, timeline: false, actions: false, ruling: true, usd_monthly: tiers.pro && tiers.pro.usd_monthly }, ENTERPRISE: { items: LIMITS.ENTERPRISE, timeline: true, actions: true, usd_monthly: tiers.enterprise && tiers.enterprise.usd_monthly }, MSSP: { items: LIMITS.MSSP, timeline: true, actions: true, usd_monthly: tiers.mssp && tiers.mssp.usd_monthly } } };
}

export async function routeAiFeed(req) {
  const path = req.path || "";
  if (!path.startsWith("/api/ai-feed")) return null;
  const method = String(req.method || "GET").toUpperCase();
  const tier = normalizeTier(req.auth);
  if (path === "/api/ai-feed/offer") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    return { status: 200, body: offerBody(req.pricingSnapshot) };
  }
  if (path === "/api/ai-feed/health") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    return { status: 200, body: { product: AI_FEED_NAME, version: AI_FEED_VERSION, freshness_status: req.freshness_status || "UNKNOWN", catalog_count: Array.isArray(req.hubCatalog) ? req.hubCatalog.length : 0 } };
  }
  const freshness = req.freshness_status || "UNAVAILABLE";
  if (path === "/api/ai-feed/live" || path.startsWith("/api/ai-feed/item/")) {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    if (freshness !== "FRESH") return { status: 503, body: { error: "intelligence_degraded", freshness_status: freshness, events_recorded: false } };
    const merged = mergeFeed(req.hubCatalog || [], req.advisories || []);
    if (path === "/api/ai-feed/live") {
      const cap = LIMITS[tier] || LIMITS.FREE;
      const items = merged.slice(0, cap).map((it) => redact(it, tier));
      return { status: 200, body: { product: AI_FEED_NAME, version: AI_FEED_VERSION, freshness_status: "FRESH", tier, locked: tier === "FREE", checkout: tier === "FREE" ? "/pricing" : null, count: items.length, total_available: merged.length, items, stamp: "CYBERDUDEBIVASH(R) SENTINEL APEX" } };
    }
    const id = decodeURIComponent(path.slice("/api/ai-feed/item/".length));
    if (tier === "FREE") return { status: 403, body: { error: "tier_required", upgrade: "/pricing" } };
    const found = merged.find((it) => it.id === id);
    if (!found) return { status: 404, body: { error: "not_found" } };
    return { status: 200, body: redact(found, tier) };
  }
  if (path === "/api/ai-feed/ingest") {
    if (method !== "POST") return { status: 405, body: { error: "method_not_allowed" } };
    if (!req.isOperator) return { status: 403, body: { error: "operator_required" } };
    const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
    const accepted = []; const rejected = [];
    for (const raw of items) { const v = validateHubItem(raw); if (v.ok) accepted.push(v.item); else rejected.push({ id: raw && raw.id, error: v.error }); }
    if (typeof req.persistCatalog === "function") await req.persistCatalog(accepted);
    return { status: 200, body: { accepted: accepted.length, rejected } };
  }
  return { status: 404, body: { error: "not_found" } };
}
