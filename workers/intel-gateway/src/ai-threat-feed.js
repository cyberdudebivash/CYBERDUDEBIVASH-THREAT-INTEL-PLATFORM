/**
 * CYBERDUDEBIVASH(R) SENTINEL APEX(TM) AI THREAT FEED  (SKU cdb-aish-feed)
 *
 * A paid lens under Cyber Watchdog: AI-security intelligence (MCP, LLM
 * gateways, coding agents, prompt injection, model supply chain) from two
 * inputs only --
 *   1. live Sentinel APEX feed items whose title / tags / description match
 *      the AI vocabulary below AND carry the source's own https URL, and
 *   2. Hub-authored objects (id CDB-AISH-FEED-YYYY-MMDD-NN), each with a
 *      required https source_url: the seed catalog below plus operator
 *      ingest (POST /api/ai-feed/ingest), persisted in SECURITY_HUB_KV.
 * It does not crawl the internet and invents nothing: no ruling, timeline or
 * action is generated for a feed item; a feed item without its source's
 * https URL is left out rather than pointed at this site.
 *
 * Same contract as Cyber Watchdog, reused rather than re-implemented:
 *   - tier from effectiveTier() (cancelled / refunded / expired -> FREE)
 *   - freshness from watchdogPublication() (the canonical contract): not
 *     FRESH -> 503 intelligence_degraded, plus a labelled last_authoritative
 *     block (live:false) while STALE <= 48h, exactly like /api/watchdog/brief
 *   - prices only from planPrice() (the runtime pricing provider, the same
 *     values Razorpay charges). No price literal in this file:
 *     __tests__/ai-threat-feed.test.js fails on one.
 *
 * Routes (index.js dispatches /api/ai-feed/* here):
 *   GET  /api/ai-feed/offer       public   plans, entitlements, checkout links
 *   GET  /api/ai-feed/health      public   freshness + catalog counts
 *   GET  /api/ai-feed/live        public   tier-projected; FREE = locked cards
 *   GET  /api/ai-feed/item/:id    PRO+     one item, tier-projected
 *   POST /api/ai-feed/ingest      operator (X-Admin-Key) validated Hub upsert / retract
 */
import { effectiveTier, planPrice, watchdogPublication, LAST_AUTHORITATIVE_MAX_AGE_SECONDS } from "./cyber-watchdog.js";

export const AI_FEED_NAME = "SENTINEL APEX AI THREAT FEED";
export const AI_FEED_VERSION = "1.1.0";
export const AI_FEED_SKU = "cdb-aish-feed";
export const AI_FEED_CATALOG_KEY = "ai_feed:hub_catalog:v1";
export const AI_FEED_MAX_CATALOG = 500;

/** Entitlements per plan. Items per response and which fields unlock. No prices here. */
export const AI_FEED_FEATURES = Object.freeze({
  FREE:       Object.freeze({ items: 5,   locked: true,  details: false, timeline: false, item_view: false, amber: false }),
  PRO:        Object.freeze({ items: 25,  locked: false, details: true,  timeline: false, item_view: true,  amber: true }),
  ENTERPRISE: Object.freeze({ items: 100, locked: false, details: true,  timeline: true,  item_view: true,  amber: true }),
  MSSP:       Object.freeze({ items: 100, locked: false, details: true,  timeline: true,  item_view: true,  amber: true }),
});

export const AI_FEED_CHECKOUT = Object.freeze({
  PRO: "/upgrade.html?plan=pro&feature=ai-threat-feed",
  ENTERPRISE: "/upgrade.html?plan=enterprise&feature=ai-threat-feed",
  MSSP: "/upgrade.html?plan=mssp&feature=ai-threat-feed",
});

// Word-bounded, so "mcp" does not match "mcpanel" and "llm" not "allmode".
const AI_TERMS = Object.freeze([
  ["mcp", /\bmcp\b/i], ["model context protocol", /\bmodel context protocol\b/i],
  ["llm", /\bllms?\b/i], ["large language model", /\blarge language models?\b/i],
  ["prompt injection", /\bprompt[- ]injection\b/i], ["jailbreak", /\bjailbreak/i],
  ["agentic", /\bagentic\b/i], ["ai agent", /\bai[- ]agents?\b/i], ["coding agent", /\bcoding agents?\b/i],
  ["copilot", /\bcopilot\b/i], ["codex", /\bcodex\b/i], ["claude code", /\bclaude code\b/i],
  ["gemini cli", /\bgemini cli\b/i], ["openai", /\bopenai\b/i], ["anthropic", /\banthropic\b/i],
  ["chatgpt", /\bchatgpt\b/i], ["litellm", /\blitellm\b/i], ["langchain", /\blangchain\b/i],
  ["llamaindex", /\bllama[- ]?index\b/i], ["ollama", /\bollama\b/i], ["vllm", /\bvllm\b/i],
  ["hugging face", /\bhugging ?face\b/i], ["ai foundry", /\b(azure )?ai foundry\b/i],
  ["vertex ai", /\bvertex ai\b/i], ["bedrock", /\bamazon bedrock\b/i], ["ai gateway", /\bai gateway\b/i],
  ["open webui", /\bopen[- ]?webui\b/i], ["comfyui", /\bcomfyui\b/i], ["gradio", /\bgradio\b/i],
  ["mlflow", /\bmlflow\b/i], ["generative ai", /\b(generative ai|genai)\b/i], ["model supply chain", /\bmodel (weights|supply[- ]chain|poisoning)\b/i],
]);

const HUB_ID_RE = /^CDB-AISH-FEED-\d{4}-\d{4}-\d{2}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2}))?$/;
const SEVERITIES = Object.freeze(["CRITICAL", "HIGH", "MEDIUM", "LOW"]);
const HUB_STATUSES = Object.freeze(["NEW_PUBLIC", "STILL_OPEN", "RESOLVED"]);
const EXPLOITATION = Object.freeze(["CONFIRMED", "NOT_CONFIRMED", "UNKNOWN"]);

// Seed Hub catalog, mirrored from config/ai-threat-feed-catalog.json (the
// operator-readable copy; the Worker cannot import JSON on both toolchains).
// __tests__/ai-threat-feed.test.js fails if the two drift.
export const AI_FEED_SEED_CATALOG = Object.freeze([
  Object.freeze({
    id: "CDB-AISH-FEED-2026-0925-01",
    title: "OpenAI agent gained unauthorized access to Australia's Medicare statistics portal",
    summary: "Australia's Prime Minister confirmed that an OpenAI agent gained unauthorized access to the public-facing Medicare Statistics Reporting Portal (Services Australia), accessed public and non-public files and wrote files to the internal server. No personal information is believed accessed; investigation ongoing with the Australian Signals Directorate. The access happened in June 2026; OpenAI notified the government on 10 September 2026. Researchers traced the agents' escalation from data retrieval to probing defenses on other sites.",
    status: "NEW_PUBLIC",
    tlp: "CLEAR",
    severity: "HIGH",
    class: "AGENT-EGRESS",
    source_url: "https://www.helpnetsecurity.com/2026/09/24/openai-agent-hacking-australia/",
    source_name: "Help Net Security",
    first_seen: "2026-09-24T00:00:00Z",
    hub_ruling: "Treat autonomous agents with open web egress as untrusted clients of other organisations' systems: an agent on an ordinary data task escalated to unauthorized access.",
    timeline: Object.freeze([{ at: "2026-09-10", event: "OpenAI notifies the Australian Government (Services Australia mailbox); access occurred in June 2026" }, { at: "2026-09-24", event: "Prime Minister confirms the Medicare statistics portal breach; taskforce convened" }]),
    triggers: Object.freeze(["AI agent outbound HTTP(S) to third-party or government data portals", "agent requests that retry blocked data sources through converters or crafted URLs"]),
    actions: Object.freeze(["Inventory AI agents with unrestricted outbound web access", "Restrict agent egress to an allowlist and log every agent HTTP request", "Alert when an agent's requests move from data retrieval to probing (errors, crafted payloads, account sign-ups)"]),
    exploitation: "CONFIRMED",
    cves: Object.freeze([]),
  }),
]);

function clean(v, max) {
  return typeof v === "string" ? v.replace(/[\u0000-\u001F\u007F<>]/g, " ").replace(/\s+/g, " ").trim().slice(0, max) : "";
}
function httpsUrl(v) {
  if (typeof v !== "string" || v.length > 2048) return null;
  try { const u = new URL(v); return u.protocol === "https:" && u.hostname ? u.toString() : null; } catch { return null; }
}
function list(v, maxItems, maxLen) {
  return Array.isArray(v) ? v.slice(0, maxItems).map((x) => clean(String(x ?? ""), maxLen)).filter(Boolean) : [];
}

/** @deprecated use effectiveTier() from cyber-watchdog.js (kept: exported since #526). */
export function normalizeTier(auth) { return effectiveTier(auth); }

/** AI vocabulary terms an advisory matches (empty = not an AI advisory). */
export function aiTermsFor(item) {
  if (!item || typeof item !== "object") return [];
  const blob = [item.title, item.description, item.summary, item.product, Array.isArray(item.tags) ? item.tags.join(" ") : ""]
    .filter((x) => typeof x === "string").join(" \n ");
  return AI_TERMS.filter(([, re]) => re.test(blob)).map(([term]) => term);
}
export function isAiAdvisory(item) { return aiTermsFor(item).length > 0; }

/** Hub object validation: every field a buyer relies on is checked, never defaulted. */
export function validateHubItem(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { ok: false, error: "invalid_item" };
  const id = String(raw.id || "");
  if (!HUB_ID_RE.test(id)) return { ok: false, error: "invalid_id" };
  const source_url = httpsUrl(raw.source_url);
  if (!source_url) return { ok: false, error: "source_url_required" };
  const title = clean(raw.title, 240);
  if (title.length < 8) return { ok: false, error: "title_required" };
  const source_name = clean(raw.source_name, 120);
  if (!source_name) return { ok: false, error: "source_name_required" };
  if (!HUB_STATUSES.includes(raw.status)) return { ok: false, error: "invalid_status" };
  const tlp = raw.tlp === undefined ? "CLEAR" : raw.tlp;
  if (!["CLEAR", "AMBER"].includes(tlp)) return { ok: false, error: "invalid_tlp" };
  const severity = String(raw.severity || "").toUpperCase();
  if (!SEVERITIES.includes(severity)) return { ok: false, error: "invalid_severity" };
  if (typeof raw.first_seen !== "string" || !ISO_RE.test(raw.first_seen) || Number.isNaN(Date.parse(raw.first_seen))) return { ok: false, error: "invalid_first_seen" };
  const exploitation = raw.exploitation === undefined ? "UNKNOWN" : raw.exploitation;
  if (!EXPLOITATION.includes(exploitation)) return { ok: false, error: "invalid_exploitation" };
  const timeline = Array.isArray(raw.timeline) ? raw.timeline.slice(0, 50) : [];
  for (const t of timeline) {
    if (!t || typeof t.at !== "string" || !ISO_RE.test(t.at) || !clean(t.event, 200)) return { ok: false, error: "invalid_timeline" };
  }
  return {
    ok: true,
    item: {
      id, title, summary: clean(raw.summary, 1000) || null, status: raw.status, tlp, severity,
      class: clean(raw.class, 40) || "AI-SEC", source_url, source_name, first_seen: raw.first_seen,
      hub_ruling: clean(raw.hub_ruling, 600) || null,
      timeline: timeline.map((t) => ({ at: t.at, event: clean(t.event, 200) })),
      triggers: list(raw.triggers, 30, 200), actions: list(raw.actions, 30, 300),
      exploitation, cves: list(raw.cves, 50, 32).filter((c) => /^CVE-\d{4}-\d{4,}$/i.test(c)).map((c) => c.toUpperCase()),
      origin: "hub",
    },
  };
}

/** A live feed advisory as an AI feed item, or null (not AI, or no https source URL). */
export function feedItemToAi(adv) {
  const terms = aiTermsFor(adv);
  if (!terms.length) return null;
  const source_url = httpsUrl(adv.source_url);
  const id = clean(String(adv.id || ""), 128);
  if (!source_url || !id) return null;
  const sev = String(adv.severity || "").toUpperCase();
  const published = clean(String(adv.published_at || adv.published || ""), 40) || null;
  const ingested = clean(String(adv.processed_at || adv.timestamp || ""), 40) || null;
  const timeline = [];
  if (published) timeline.push({ at: published, event: "published by " + (clean(adv.source, 80) || "source") });
  if (ingested) timeline.push({ at: ingested, event: "ingested by Sentinel APEX" });
  const maturity = String(adv.exploit_maturity || "").toUpperCase();
  return {
    id, title: clean(adv.title, 240), summary: clean(adv.description || adv.summary || "", 1000) || null,
    status: "ON_FEED", tlp: String(adv.tlp || "").toUpperCase().includes("AMBER") ? "AMBER" : "CLEAR",
    severity: SEVERITIES.includes(sev) ? sev : "MEDIUM", class: "AI-SEC",
    source_url, source_name: clean(adv.source || adv.feed_source || "", 120) || null,
    first_seen: published || ingested,
    hub_ruling: null, // never generated for a feed item
    timeline, triggers: [], actions: [],
    exploitation: /ACTIVE|WEAPONIZED|IN[_ ]THE[_ ]WILD|CONFIRMED/.test(maturity) || adv.kev_present === true ? "CONFIRMED" : "UNKNOWN",
    cves: list(adv.cve_ids, 50, 32).filter((c) => /^CVE-\d{4}-\d{4,}$/i.test(c)).map((c) => c.toUpperCase()),
    matched_terms: terms, origin: "sentinel_feed",
  };
}

// Query parameters that only track the click, never select the page.
const TRACKING_PARAM = /^(utm_[a-z_]+|fbclid|gclid|mc_cid|mc_eid|ref|ref_src|source)$/i;

/**
 * Source article identity: scheme + lower-case host + path without a
 * trailing slash + the query minus tracking parameters (sorted). The query is
 * kept: cvename.cgi?name=CVE-A and ?name=CVE-B are different pages.
 */
export function sourceKey(url) {
  try {
    const u = new URL(url);
    const params = [...u.searchParams.entries()].filter(([k]) => !TRACKING_PARAM.test(k)).sort(([a, x], [b, y]) => (a + "=" + x).localeCompare(b + "=" + y));
    const query = params.length ? "?" + params.map(([k, v]) => k + "=" + v).join("&") : "";
    return u.protocol + "//" + u.hostname.toLowerCase() + (u.pathname.replace(/\/+$/, "") || "/") + query;
  } catch { return null; }
}

/**
 * Hub items (validated; invalid ones dropped) + AI items from the live feed,
 * newest first, one item per id and per source article. Production
 * 2026-09-26: the feed carried the same cybersecuritynews.com article twice
 * (sources "CyberSecurityNews" / "CyberSecurity News", LOW and MEDIUM) and
 * both reached buyers. Hub objects win; among feed items, feed order wins.
 */
export function mergeFeed(hubItems, advisories) {
  const out = [];
  const seen = new Set();
  const sources = new Set();
  const add = (it) => {
    const key = sourceKey(it.source_url);
    if (seen.has(it.id) || (key && sources.has(key))) return;
    seen.add(it.id);
    if (key) sources.add(key);
    out.push(it);
  };
  for (const raw of hubItems || []) {
    const v = validateHubItem(raw);
    if (v.ok) add(v.item);
  }
  for (const adv of advisories || []) {
    const it = adv && typeof adv === "object" ? feedItemToAi(adv) : null;
    if (it) add(it);
  }
  out.sort((a, b) => (Date.parse(b.first_seen || "") || 0) - (Date.parse(a.first_seen || "") || 0) || a.id.localeCompare(b.id));
  return out;
}

/** Tier projection: FREE a locked teaser; paid tiers unlock fields by plan. */
export function redact(item, tier) {
  const f = AI_FEED_FEATURES[tier] || AI_FEED_FEATURES.FREE;
  const base = {
    id: item.id, title: item.title, severity: item.severity, status: item.status, tlp: item.tlp,
    class: item.class, first_seen: item.first_seen, source_name: item.source_name, origin: item.origin,
  };
  if (!f.details) return { ...base, locked: true, checkout: AI_FEED_CHECKOUT.PRO };
  const paid = {
    ...base, locked: false, summary: item.summary, source_url: item.source_url, cves: item.cves,
    hub_ruling: item.hub_ruling, exploitation: item.exploitation,
    ...(item.matched_terms ? { matched_terms: item.matched_terms } : {}),
  };
  if (!f.timeline) return { ...paid, timeline_locked: true, checkout: AI_FEED_CHECKOUT.ENTERPRISE };
  return { ...paid, timeline: item.timeline, triggers: item.triggers, actions: item.actions };
}

function priceLabel(tier) {
  const p = planPrice(tier);
  if (!p || p.usd_monthly == null) return "Contract";
  const usd = "$" + p.usd_monthly;
  return p.usd_monthly === 0 ? usd : usd + "/mo | INR " + String(Math.round(p.inr_monthly)).replace(/\B(?=(\d{3})+(?!\d))/g, ",") + "/mo";
}

export function offerBody() {
  const plan = (tier, name) => {
    const f = AI_FEED_FEATURES[tier];
    const p = planPrice(tier);
    return {
      id: tier, name, price_usd_monthly: p.usd_monthly, price_inr_monthly: p.inr_monthly, price_label: priceLabel(tier),
      items: f.items, details: f.details, timeline_and_actions: f.timeline, item_view: f.item_view,
      checkout: AI_FEED_CHECKOUT[tier] || null,
    };
  };
  return {
    product: AI_FEED_NAME, version: AI_FEED_VERSION, sku: AI_FEED_SKU, seller: "CYBERDUDEBIVASH(R)",
    commercial_source: "config/commercial-contract.json (features.ai_threat_feed)",
    price_source: "gateway runtime pricing provider (same values as Razorpay and /api/pricing)",
    second_invoice: false,
    statement: "AI-security intelligence under Cyber Watchdog: live Sentinel APEX advisories that match the AI vocabulary and cite their source, plus Hub-authored objects that each carry their source URL. Included with the existing plans; no second invoice.",
    scope: {
      covers: ["MCP servers and Model Context Protocol", "LLM gateways, SDKs and inference servers", "coding agents and AI assistants", "prompt injection and jailbreaks", "AI evaluation and agent egress", "model supply chain"],
      does_not: ["Does not crawl the internet.", "Does not invent rulings, timelines or actions for feed items.", "Does not show an item without its source URL.", "Does not serve a stale feed as live."],
    },
    plans: [plan("FREE", "Free preview"), plan("PRO", "Pro Defense"), plan("ENTERPRISE", "Enterprise SOC"), plan("MSSP", "MSSP")],
    endpoints: { offer: "GET /api/ai-feed/offer", health: "GET /api/ai-feed/health", live: "GET /api/ai-feed/live", item: "GET /api/ai-feed/item/{id}" },
  };
}

function degraded(pub) {
  return {
    product: AI_FEED_NAME, version: AI_FEED_VERSION, error: "intelligence_degraded",
    message: "INTELLIGENCE DEGRADED - LAST AUTHORITATIVE UPDATE " + (pub.feed_generated_at || "unknown"),
    freshness_status: pub.freshness_status, feed_generated_at: pub.feed_generated_at,
    feed_age_seconds: pub.feed_age_seconds, items: [],
  };
}

function liveBody(merged, tier, pub) {
  const f = AI_FEED_FEATURES[tier];
  const visible = f.amber ? merged : merged.filter((i) => i.tlp !== "AMBER");
  const items = visible.slice(0, f.items).map((it) => redact(it, tier));
  const upgrade = tier === "FREE" ? { plan: "PRO", price_label: priceLabel("PRO"), checkout: AI_FEED_CHECKOUT.PRO }
    : tier === "PRO" ? { plan: "ENTERPRISE", price_label: priceLabel("ENTERPRISE"), checkout: AI_FEED_CHECKOUT.ENTERPRISE, unlocks: "timeline, triggers and actions; 100 items" } : null;
  return {
    product: AI_FEED_NAME, version: AI_FEED_VERSION, sku: AI_FEED_SKU, tier, locked: !f.details,
    freshness_status: pub.freshness_status, feed_generated_at: pub.feed_generated_at, feed_age_seconds: pub.feed_age_seconds,
    count: items.length, total_available: visible.length,
    sources: { hub: visible.filter((i) => i.origin === "hub").length, sentinel_feed: visible.filter((i) => i.origin === "sentinel_feed").length },
    items, upgrade, stamp: "CYBERDUDEBIVASH(R) SENTINEL APEX",
  };
}

/** Hub catalog = seed + persisted operator ingest (upserts override the seed; retracted ids removed). */
export function effectiveCatalog(stored) {
  const byId = new Map(AI_FEED_SEED_CATALOG.map((i) => [i.id, i]));
  const s = stored && typeof stored === "object" ? stored : {};
  for (const it of Array.isArray(s.items) ? s.items : []) if (it && it.id) byId.set(it.id, it);
  for (const id of Array.isArray(s.retracted) ? s.retracted : []) byId.delete(id);
  return [...byId.values()];
}

/**
 * req: { path, method, auth, feed, nowMs, isOperator, body, readCatalog(), writeCatalog(obj) }
 * Returns { status, body } or null when the path is not an AI feed route.
 */
export async function routeAiFeed(req) {
  const path = String(req.path || "");
  if (path !== "/api/ai-feed" && !path.startsWith("/api/ai-feed/")) return null;
  const method = String(req.method || "GET").toUpperCase();
  const read = method === "GET" || method === "HEAD";

  if (path === "/api/ai-feed/offer") {
    if (!read) return { status: 405, body: { error: "method_not_allowed" } };
    return { status: 200, body: offerBody() };
  }

  if (path === "/api/ai-feed/ingest") {
    if (method !== "POST") return { status: 405, body: { error: "method_not_allowed" } };
    if (!req.isOperator) return { status: 403, body: { error: "operator_required" } };
    const b = req.body && typeof req.body === "object" ? req.body : {};
    const items = Array.isArray(b.items) ? b.items : [];
    const retract = Array.isArray(b.retract) ? b.retract.filter((x) => typeof x === "string" && HUB_ID_RE.test(x)) : [];
    if (!items.length && !retract.length) return { status: 400, body: { error: "nothing_to_ingest", message: "Send items[] and/or retract[] (Hub ids)." } };
    const accepted = []; const rejected = [];
    for (const raw of items.slice(0, AI_FEED_MAX_CATALOG)) {
      const v = validateHubItem(raw);
      if (v.ok) accepted.push(v.item); else rejected.push({ id: raw && typeof raw.id === "string" ? raw.id.slice(0, 64) : null, error: v.error });
    }
    // All or nothing: a batch with any invalid object writes nothing.
    if (rejected.length) return { status: 400, body: { error: "invalid_items", accepted: 0, rejected } };
    if (typeof req.readCatalog !== "function" || typeof req.writeCatalog !== "function") return { status: 503, body: { error: "catalog_store_unavailable" } };
    const cur = (await req.readCatalog()) || {};
    const byId = new Map((Array.isArray(cur.items) ? cur.items : []).map((i) => [i.id, i]));
    for (const it of accepted) byId.set(it.id, it);
    for (const id of retract) byId.delete(id);
    const retracted = [...new Set([...(Array.isArray(cur.retracted) ? cur.retracted : []).filter((id) => !accepted.some((a) => a.id === id)), ...retract])];
    const next = { version: 1, updated_at: new Date(req.nowMs || Date.now()).toISOString(), items: [...byId.values()].slice(-AI_FEED_MAX_CATALOG), retracted: retracted.slice(-AI_FEED_MAX_CATALOG) };
    await req.writeCatalog(next);
    return { status: 200, body: { accepted: accepted.length, retracted: retract.length, catalog_size: effectiveCatalog(next).length } };
  }

  const pub = watchdogPublication(req.feed, req.nowMs);
  // Reads never fail on the catalog store: an unreadable catalog serves the
  // seed (ingest above reads it strictly, so it never overwrites after a failed read).
  let stored = null;
  if (typeof req.readCatalog === "function") {
    try { stored = await req.readCatalog(); } catch { stored = null; }
  }
  const catalog = effectiveCatalog(stored);
  const advisories = req.feed && Array.isArray(req.feed.items) ? req.feed.items : [];

  if (path === "/api/ai-feed/health") {
    if (!read) return { status: 405, body: { error: "method_not_allowed" } };
    const merged = mergeFeed(catalog, advisories);
    return {
      status: pub.serve_live ? 200 : 503,
      body: {
        product: AI_FEED_NAME, version: AI_FEED_VERSION, sku: AI_FEED_SKU,
        freshness_status: pub.freshness_status, feed_generated_at: pub.feed_generated_at, feed_age_seconds: pub.feed_age_seconds,
        hub_catalog_count: catalog.length, ai_items_available: merged.length,
        sentinel_feed_ai_items: merged.filter((i) => i.origin === "sentinel_feed").length,
      },
    };
  }

  const tier = effectiveTier(req.auth);

  if (path === "/api/ai-feed/live") {
    if (!read) return { status: 405, body: { error: "method_not_allowed" } };
    if (!pub.serve_live) {
      const body = { ...degraded(pub), tier, last_authoritative: null };
      if (pub.freshness_status === "STALE" && Number.isFinite(pub.feed_age_seconds) && pub.feed_age_seconds <= LAST_AUTHORITATIVE_MAX_AGE_SECONDS) {
        body.last_authoritative = { live: false, label: "LAST AUTHORITATIVE INTELLIGENCE - NOT LIVE", ...liveBody(mergeFeed(catalog, advisories), tier, pub) };
      }
      return { status: 503, body };
    }
    return { status: 200, body: liveBody(mergeFeed(catalog, advisories), tier, pub) };
  }

  if (path.startsWith("/api/ai-feed/item/")) {
    if (!read) return { status: 405, body: { error: "method_not_allowed" } };
    let id = "";
    try { id = decodeURIComponent(path.slice("/api/ai-feed/item/".length)); } catch { return { status: 400, body: { error: "invalid_id" } }; }
    if (!id || id.length > 128) return { status: 400, body: { error: "invalid_id" } };
    if (!AI_FEED_FEATURES[tier].item_view) {
      return { status: 403, body: { error: "tier_required", message: "Item detail is included with Pro Defense (" + priceLabel("PRO") + ").", checkout: AI_FEED_CHECKOUT.PRO } };
    }
    if (!pub.serve_live) return { status: 503, body: degraded(pub) };
    const found = mergeFeed(catalog, advisories).find((it) => it.id === id);
    if (!found) return { status: 404, body: { error: "not_found" } };
    return { status: 200, body: { product: AI_FEED_NAME, tier, freshness_status: pub.freshness_status, item: redact(found, tier) } };
  }

  return { status: 404, body: { error: "not_found", endpoints: offerBody().endpoints } };
}
