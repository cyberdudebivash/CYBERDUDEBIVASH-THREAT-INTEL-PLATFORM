/**
 * CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG v3
 *
 * Classifies and watches items already on the authoritative Sentinel APEX
 * feed. Does not crawl the internet, does not invent advisories, and does
 * not serve a stale feed as a live brief.
 *
 * Prices: the gateway runtime pricing provider (pricing.js), the same values
 * Razorpay charges and /api/pricing serves. No Watchdog price copy.
 * Features, scheduler, delivery and session policy: watchdog-policy.js.
 * Freshness: evaluatePublicIntelligence() via freshness-contract.js.
 *
 * Customer mutations go through WatchdogLedger (one Durable Object per
 * authenticated subject, or per subject + MSSP tenant). Anonymous
 * brief/offer/health do not write. Evaluation also runs from the Worker cron
 * through WatchdogScheduler, so no browser is needed to generate events.
 */

import { evaluatePublicIntelligence, freshnessStatusFor } from "./freshness-contract.js";
import { RAZORPAY_TIER_PRICES } from "./pricing.js";
import {
  DELIVERY_POLICY,
  DENIED_SUBSCRIPTION_STATES,
  SCHEDULER_POLICY,
  SESSION_POLICY,
  WATCHDOG_FEATURES,
  WATCHDOG_SCOPES,
  WEBHOOK_CONTRACT,
  featuresFor,
  scopesForTier,
} from "./watchdog-policy.js";
import { retryDelaySeconds, validateDestinationUrl } from "./watchdog-webhook.js";

export const WATCHDOG_NAME = "CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG";
export const WATCHDOG_VERSION = "3.0.0";
export const CLASSIFIER_VERSION = "watchdog-lens-v2";
export const EVENT_RETENTION = 200;
export const DELIVERY_RETENTION = 50;
export const MAX_WEBHOOK_TIMEOUT_MS = DELIVERY_POLICY.timeout_ms;

// Seller identity (not a price). The unit test pins it to the contract.
export const SELLER = Object.freeze({
  gstin: "21ARKPN8270G1ZP",
  seller_legal: "BIVASHA KUMAR NAYAK",
  seller_trade_name: "CYBERDUDEBIVASH(R)",
});

/**
 * Monthly list price for a plan, read at call time from the runtime pricing
 * provider. FREE is $0 by definition. A paid tier missing from the provider
 * returns null (rendered "Contract"), never an invented number.
 */
export function planPrice(tierId) {
  if (tierId === "FREE") return { usd_monthly: 0, inr_monthly: 0 };
  const row = RAZORPAY_TIER_PRICES[tierId];
  if (!row || !Number.isInteger(row.monthly)) return { usd_monthly: null, inr_monthly: null };
  return {
    usd_monthly: Number.isFinite(row.usd_monthly) ? row.usd_monthly : null,
    inr_monthly: row.monthly / 100,
  };
}

/**
 * DEPRECATED (v3): kept only so existing importers keep working. Values are
 * read from the runtime pricing provider on access -- this is a view, not a
 * second price table. Use planPrice() and SELLER. Removal: next Watchdog major.
 */
export const COMMERCIAL_MIRROR = Object.freeze({
  gstin: SELLER.gstin,
  seller_legal: SELLER.seller_legal,
  seller_trade_name: SELLER.seller_trade_name,
  tiers: Object.freeze({
    get FREE() { return planPrice("FREE"); },
    get PRO() { return planPrice("PRO"); },
    get ENTERPRISE() { return planPrice("ENTERPRISE"); },
    get MSSP() { return planPrice("MSSP"); },
  }),
});

const DENY_STATUS = new Set(DENIED_SUBSCRIPTION_STATES);
const SEVERITY_RANK = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
const CRITERION_KEYS = new Set([
  "keywords", "cves", "vendors", "products", "actors", "malware_families",
  "sources", "min_severity", "kev", "min_epss", "min_cvss", "techniques",
  "sectors", "countries", "ioc_types", "lenses",
]);

const LENS_RULES = [
  ["cybersecurity", /\b(cve-\d{4}-\d+|ransomware|malware|exploit|kev|vulnerabilit|phish|apt\b|intrusion|backdoor|zero-?day|ioc\b)/i],
  ["technology", /\b(cloud|kubernetes|k8s|microsoft|windows|apple|google|aws|azure|gcp|firmware|vendor|supply[- ]chain|openssl|chrome|linux)\b/i],
  ["security_operations", /\b(sigma|yara|detection|siem|soar|playbook|incident|soc\b|triage|suricata|kql|splunk)\b/i],
];

export function emptyLedgerState() {
  return { revision: 0, subject: null, watches: [], events: [], destinations: [], deliveries: [], metrics: {} };
}

function clean(value, max) {
  if (typeof value !== "string") return "";
  return value.replace(/[\u0000-\u001F\u007F<>]/g, "").trim().slice(0, max);
}

function groupInr(n) {
  const s = String(Math.round(Number(n) || 0));
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function priceLabel(tierId) {
  const row = planPrice(tierId);
  if (!row || row.usd_monthly == null) return "Contract";
  if (row.usd_monthly === 0) return "$0";
  return "$" + row.usd_monthly + "/mo | INR " + groupInr(row.inr_monthly) + "/mo";
}

export function effectiveTier(auth) {
  const status = String(auth?.subscription_status || "").toLowerCase();
  const err = String(auth?.error || "");
  if (DENY_STATUS.has(status) || err === "key_expired" || err.startsWith("subscription_")) return "FREE";
  const tier = String(auth?.tier || "FREE").toUpperCase();
  return WATCHDOG_FEATURES[tier] ? tier : "FREE";
}

export function quotaForTier(tier) {
  const features = featuresFor(tier);
  const price = planPrice(WATCHDOG_FEATURES[tier] ? tier : "FREE");
  return {
    ...features,
    paid: features.events,
    price_usd_monthly: price.usd_monthly,
    price_inr_monthly: price.inr_monthly,
  };
}

export function watchdogOffer() {
  const seller = {
    legal_name: SELLER.seller_legal,
    trade_name: SELLER.seller_trade_name,
    gstin: SELLER.gstin,
  };
  const plan = (id, name, checkout, note) => {
    const q = quotaForTier(id);
    const price = planPrice(id);
    return {
      id,
      name,
      price_usd_monthly: price.usd_monthly,
      price_inr_monthly: price.inr_monthly,
      price_label: priceLabel(id),
      watches: q.watches,
      brief_items: q.brief_items,
      poller: q.poller,
      webhooks: q.webhooks,
      background_evaluation: q.background_evaluation,
      tenants: q.tenants,
      checkout,
      note,
    };
  };
  return {
    product: WATCHDOG_NAME,
    version: WATCHDOG_VERSION,
    classifier: CLASSIFIER_VERSION,
    seller,
    commercial_source: "config/commercial-contract.json",
    price_source: "gateway runtime pricing provider (same values as Razorpay and /api/pricing)",
    checkout: {
      primary: "razorpay",
      alternative: "gumroad",
      second_invoice: false,
    },
    scope: {
      watches: [
        "Vulnerabilities, KEV, ransomware, malware, and intrusion reporting already on the Sentinel APEX feed.",
        "Vendor, cloud, software, and supply-chain items already on the Sentinel APEX feed.",
        "Detection, incident-response, and SOC-relevant items already on the Sentinel APEX feed.",
      ],
      does_not: [
        "Does not watch the entire internet.",
        "Does not watch private customer networks.",
        "Does not query dark-web marketplaces. That monitor is separately unavailable.",
        "Does not invent advisories when the feed is empty or stale.",
        "Does not guarantee zero-day detection.",
      ],
    },
    plans: [
      plan("FREE", "Public preview", null, "Titles only. No watches."),
      plan("PRO", "Pro Defense", "/upgrade.html?plan=pro&feature=cyber-watchdog", "Existing Pro charge. Included. No second invoice. Hosted watches, background evaluation and the brief poller."),
      plan("ENTERPRISE", "Enterprise SOC", "/upgrade.html?plan=enterprise&feature=cyber-watchdog", "Existing Enterprise charge. Includes verified, signed HTTPS webhook delivery."),
      plan("MSSP", "MSSP", "/upgrade.html?plan=mssp&feature=cyber-watchdog", "Canonical MSSP list price. Includes signed webhook delivery and sub-tenant isolation for managed tenants. Not a second invoice."),
    ],
    endpoints: {
      offer: "GET /api/watchdog/offer",
      brief: "GET /api/watchdog/brief",
      health: "GET /api/watchdog/health",
      watches: "GET|POST /api/watchdog/watches",
      watch_update: "PATCH /api/watchdog/watches?id=",
      watch_delete: "DELETE /api/watchdog/watches?id=",
      matches: "GET /api/watchdog/matches",
      events: "GET /api/watchdog/events",
      ack: "POST /api/watchdog/events/ack",
      destinations: "GET|POST|PATCH|DELETE /api/watchdog/destinations",
      destination_verify: "POST /api/watchdog/destinations/verify?id=",
      session: "POST|DELETE /api/watchdog/session",
      deploy: "GET /api/watchdog/deploy",
    },
    background_evaluation: "Paid watches are evaluated by the hosted scheduler after authoritative feed updates. No browser or poller is required.",
    webhook_contract: {
      version: WEBHOOK_CONTRACT.version,
      signature: "HMAC-SHA256(secret, timestamp + \".\" + raw_body), hex, header X-CDB-Watchdog-Signature: v1=<hex>",
      destination_verification: "required before any delivery",
    },
    dashboard: "/cyber-watchdog.html",
    aligned_not_certified: "ISO 27001 / SOC 2: aligned, not certified.",
  };
}

function itemText(item) {
  const bits = [
    item.title, item.name, item.summary, item.description, item.ai_summary,
    item.severity, item.source, item.source_name, item.actor_tag, item.actor_display_name,
    item.threat_type, item.actor_malware, item.kev_product, item.kev_name,
  ];
  if (Array.isArray(item.tags)) bits.push(item.tags.join(" "));
  if (Array.isArray(item.cve_ids)) bits.push(item.cve_ids.join(" "));
  if (Array.isArray(item.affected_products)) bits.push(item.affected_products.join(" "));
  if (typeof item.affected_products === "string") bits.push(item.affected_products);
  return bits.filter(Boolean).join(" ");
}

function cveIds(item) {
  const found = new Set();
  for (const m of itemText(item).matchAll(/CVE-\d{4}-\d{4,}/gi)) found.add(m[0].toUpperCase());
  if (Array.isArray(item.cve_ids)) {
    for (const c of item.cve_ids) {
      if (typeof c === "string" && /^CVE-\d{4}-\d{4,}$/i.test(c)) found.add(c.toUpperCase());
    }
  }
  return [...found].slice(0, 12);
}

export function classifyItem(item) {
  const reasons = [];
  const lenses = new Set();
  const text = itemText(item || {});
  const cves = cveIds(item || {});
  if (cves.length) {
    lenses.add("cybersecurity");
    reasons.push("CVE identifier present");
  }
  if (item?.kev_present === true || item?.kev_confirmed === true || item?.kev === true) {
    lenses.add("cybersecurity");
    reasons.push("CISA KEV present");
  }
  if (item?.actor_tag || item?.actor_display_name) {
    lenses.add("cybersecurity");
    reasons.push("actor=" + clean(String(item.actor_tag || item.actor_display_name), 60));
  }
  const products = []
    .concat(item?.affected_products || [])
    .concat(item?.kev_product || [])
    .filter((v) => typeof v === "string");
  if (products.length) reasons.push("product=" + clean(products[0], 60));
  for (const [id, re] of LENS_RULES) {
    if (re.test(text)) {
      lenses.add(id);
      reasons.push("text:" + id);
    }
  }
  return {
    lenses: [...lenses],
    classification_version: CLASSIFIER_VERSION,
    reasons: reasons.slice(0, 8),
  };
}

export function watchdogPublication(feed, nowMs = Date.now()) {
  const evaluation = evaluatePublicIntelligence(feed, nowMs);
  const intel = evaluation.intelligence;
  const freshness_status = freshnessStatusFor(evaluation, feed);
  return {
    freshness_status,
    feed_generated_at: intel.generated_at,
    feed_age_seconds: intel.age_seconds,
    freshness_threshold_seconds: intel.max_age_seconds,
    feed_item_count: intel.advisory_count,
    serve_live: freshness_status === "FRESH",
    reason: evaluation.reason,
  };
}

function validItems(feed) {
  if (!feed || !Array.isArray(feed.items)) return [];
  return feed.items.filter((i) => i && typeof i === "object" && typeof i.id === "string" && i.id.trim() !== "");
}

function severityBucket(item) {
  const raw = clean(String(item?.severity || ""), 24).toUpperCase();
  if (SEVERITY_RANK[raw]) return raw === "INFO" ? "INFO" : raw;
  return "UNKNOWN";
}

export function buildSituation(items) {
  const by_lens = { cybersecurity: 0, technology: 0, security_operations: 0 };
  const by_severity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
  let classified = 0;
  let unclassified = 0;
  const sources = new Map();
  for (const item of items) {
    const found = classifyItem(item);
    if (found.lenses.length) {
      classified += 1;
      for (const id of found.lenses) by_lens[id] += 1;
    } else unclassified += 1;
    const sev = severityBucket(item);
    by_severity[sev] = (by_severity[sev] || 0) + 1;
    const src = clean(String(item.source || item.source_name || ""), 80);
    if (src) sources.set(src, (sources.get(src) || 0) + 1);
  }
  const top_sources = [...sources.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 5)
    .map(([source, count]) => ({ source, count }));
  const seen = items.length;
  return {
    coverage: "sentinel-apex-feed",
    not_coverage: "entire-internet",
    feed_items_seen: seen,
    classified,
    unclassified,
    unclassified_rate: seen ? Number((unclassified / seen).toFixed(4)) : 0,
    by_lens,
    by_severity,
    top_sources,
    note: "Counts classify items already on the Sentinel APEX feed. An item may sit in more than one lens. Nothing was invented.",
  };
}

function publicItem(item, paid) {
  const found = classifyItem(item);
  const summary = clean(String(item.summary || item.description || item.ai_summary || ""), paid ? 500 : 0);
  return {
    id: clean(String(item.id), 128) || null,
    title: clean(String(item.title || item.name || "Untitled advisory"), paid ? 240 : 120),
    summary: summary || null,
    severity: clean(String(item.severity || ""), 24) || null,
    source: clean(String(item.source || item.source_name || ""), 80) || null,
    observed_at: clean(String(item.published || item.timestamp || item.processed_at || ""), 40) || null,
    cve_ids: paid ? cveIds(item) : [],
    tlp: clean(String(item.tlp || ""), 20) || null,
    lenses: found.lenses,
    classification_version: found.classification_version,
    reasons: paid ? found.reasons : found.reasons.slice(0, 2),
    provenance: "sentinel-apex-feed",
  };
}

function degradedBody(pub) {
  const when = pub.feed_generated_at || "unknown";
  return {
    product: WATCHDOG_NAME,
    version: WATCHDOG_VERSION,
    error: "intelligence_degraded",
    message: "INTELLIGENCE DEGRADED - LAST AUTHORITATIVE UPDATE " + when,
    freshness_status: pub.freshness_status,
    feed_generated_at: pub.feed_generated_at,
    feed_age_seconds: pub.feed_age_seconds,
    freshness_threshold_seconds: pub.freshness_threshold_seconds,
    feed_item_count: pub.feed_item_count,
    items: [],
    events_recorded: false,
  };
}

export function buildWatchdogBrief(feed, opts = {}) {
  const pub = watchdogPublication(feed, opts.nowMs);
  const tier = effectiveTier({ tier: opts.tier, subscription_status: opts.subscription_status, error: opts.error });
  const quota = quotaForTier(tier);
  if (!pub.serve_live) {
    return { status: 503, body: { ...degradedBody(pub), tier } };
  }
  const lens = opts.lens && ["cybersecurity", "technology", "security_operations"].includes(opts.lens) ? opts.lens : null;
  const q = clean(String(opts.q || ""), 80).toLowerCase();
  const cap = Math.min(quota.brief_items, Math.max(1, Number(opts.limit) || quota.brief_items));
  const source = validItems(feed);
  const rows = [];
  let matched = 0;
  for (const item of source) {
    const found = classifyItem(item);
    if (lens && !found.lenses.includes(lens)) continue;
    if (q && !itemText(item).toLowerCase().includes(q)) continue;
    matched += 1;
    if (rows.length < cap) rows.push(publicItem(item, quota.paid));
  }
  return {
    status: 200,
    body: {
      product: WATCHDOG_NAME,
      version: WATCHDOG_VERSION,
      tier,
      lens: lens || "all",
      count: rows.length,
      feed_items_seen: pub.feed_item_count,
      freshness_status: pub.freshness_status,
      feed_generated_at: pub.feed_generated_at,
      feed_age_seconds: pub.feed_age_seconds,
      freshness_threshold_seconds: pub.freshness_threshold_seconds,
      feed_item_count: pub.feed_item_count,
      truncated: matched > rows.length,
      items: rows,
      situation: buildSituation(source),
      empty: rows.length === 0,
      empty_reason: rows.length === 0 ? "No feed items matched this lens or query." : null,
      generated_at: opts.now || new Date(opts.nowMs || Date.now()).toISOString(),
    },
  };
}

function asList(value, maxItems, maxLen, map) {
  if (!Array.isArray(value)) return [];
  const out = [];
  for (const raw of value.slice(0, maxItems)) {
    const mapped = map(raw);
    if (mapped) out.push(mapped);
  }
  return out;
}

function normalizeCriteria(input) {
  const src = input?.criteria && typeof input.criteria === "object" ? input.criteria : {};
  const legacy = {
    keywords: input?.keywords,
    cves: input?.cves,
    lenses: input?.lenses,
  };
  const merged = { ...legacy, ...src };
  for (const key of Object.keys(merged)) {
    if (merged[key] == null) continue;
    if (!CRITERION_KEYS.has(key)) return { error: "unsupported_criterion", message: "Unsupported watch criterion: " + key };
  }
  const criteria = {};
  criteria.keywords = asList(merged.keywords, 8, 48, (k) => clean(String(k), 48).toLowerCase());
  criteria.cves = asList(merged.cves, 8, 20, (c) => {
    const v = clean(String(c), 20).toUpperCase();
    return /^CVE-\d{4}-\d{4,}$/.test(v) ? v : "";
  });
  if (Array.isArray(merged.cves) && merged.cves.length && criteria.cves.length !== merged.cves.filter(Boolean).length) {
    return { error: "invalid_cve", message: "CVE ids must look like CVE-2026-1000." };
  }
  criteria.vendors = asList(merged.vendors, 8, 48, (v) => clean(String(v), 48).toLowerCase());
  criteria.products = asList(merged.products, 8, 48, (v) => clean(String(v), 48).toLowerCase());
  criteria.actors = asList(merged.actors, 8, 48, (v) => clean(String(v), 48).toLowerCase());
  criteria.malware_families = asList(merged.malware_families, 8, 48, (v) => clean(String(v), 48).toLowerCase());
  criteria.sources = asList(merged.sources, 8, 80, (v) => clean(String(v), 80).toLowerCase());
  criteria.techniques = asList(merged.techniques, 8, 16, (v) => {
    const t = clean(String(v), 16).toUpperCase();
    return /^T\d{4}(\.\d{3})?$/.test(t) ? t : "";
  });
  criteria.sectors = asList(merged.sectors, 8, 48, (v) => clean(String(v), 48).toLowerCase());
  criteria.countries = asList(merged.countries, 8, 32, (v) => clean(String(v), 32).toUpperCase());
  criteria.ioc_types = asList(merged.ioc_types, 8, 24, (v) => clean(String(v), 24).toLowerCase());
  criteria.lenses = asList(merged.lenses, 3, 24, (v) => {
    const l = String(v);
    return ["cybersecurity", "technology", "security_operations"].includes(l) ? l : "";
  });
  if (merged.min_severity != null && merged.min_severity !== "") {
    const sev = clean(String(merged.min_severity), 16).toUpperCase();
    if (!SEVERITY_RANK[sev]) return { error: "invalid_severity", message: "min_severity must be INFO, LOW, MEDIUM, HIGH, or CRITICAL." };
    criteria.min_severity = sev;
  }
  if (merged.kev != null) criteria.kev = merged.kev === true;
  if (merged.min_epss != null && merged.min_epss !== "") {
    const n = Number(merged.min_epss);
    if (!Number.isFinite(n) || n < 0 || n > 1) return { error: "invalid_epss", message: "min_epss must be between 0 and 1." };
    criteria.min_epss = n;
  }
  if (merged.min_cvss != null && merged.min_cvss !== "") {
    const n = Number(merged.min_cvss);
    if (!Number.isFinite(n) || n < 0 || n > 10) return { error: "invalid_cvss", message: "min_cvss must be between 0 and 10." };
    criteria.min_cvss = n;
  }
  const active = Object.entries(criteria).filter(([, v]) => (Array.isArray(v) ? v.length : v != null && v !== false));
  if (!active.length) return { error: "invalid_watch", message: "Provide at least one keyword, CVE, or structured criterion." };
  const logic = String(input?.logic || "OR").toUpperCase();
  if (logic !== "AND" && logic !== "OR") return { error: "invalid_logic", message: "logic must be AND or OR." };
  return { criteria, logic };
}

export function matchWatch(watch, item) {
  if (watch.enabled === false) return { matched: false, reasons: [] };
  const criteria = watch.criteria || {};
  const text = itemText(item).toLowerCase();
  const cves = cveIds(item);
  const products = [].concat(item.affected_products || [], item.kev_product || []).filter((v) => typeof v === "string");
  const actors = [item.actor_tag, item.actor_display_name, item.mitre_group_name].filter(Boolean);
  const sectors = [].concat(item.actor_sectors || []).filter((v) => typeof v === "string");
  const techniques = [].concat(item.attck_technique_ids || []).map((v) => String(v).toUpperCase());
  const iocTypes = Array.isArray(item.iocs) ? item.iocs.map((i) => i && i.type).filter(Boolean) : [];
  const found = classifyItem(item);
  const checks = [];
  const add = (label, ok) => { if (label) checks.push({ label, ok }); };
  if (criteria.keywords?.length) add("keyword", criteria.keywords.some((k) => k && text.includes(k)));
  if (criteria.cves?.length) add("cve", criteria.cves.some((c) => cves.includes(c)));
  if (criteria.vendors?.length) add("vendor", criteria.vendors.some((v) => text.includes(v) || products.some((p) => p.toLowerCase().includes(v))));
  if (criteria.products?.length) add("product", criteria.products.some((v) => text.includes(v) || products.some((p) => p.toLowerCase().includes(v))));
  if (criteria.actors?.length) add("actor", criteria.actors.some((v) => actors.some((a) => String(a).toLowerCase().includes(v))));
  if (criteria.malware_families?.length) add("malware", criteria.malware_families.some((v) => text.includes(v)));
  if (criteria.sources?.length) add("source", criteria.sources.some((v) => String(item.source || "").toLowerCase().includes(v)));
  if (criteria.min_severity) {
    const rank = SEVERITY_RANK[severityBucket(item)] || 0;
    add("severity", rank >= SEVERITY_RANK[criteria.min_severity]);
  }
  if (criteria.kev === true) add("kev", item.kev_present === true || item.kev_confirmed === true || item.kev === true);
  if (criteria.min_epss != null) add("epss", Number(item.epss_score) >= criteria.min_epss);
  if (criteria.min_cvss != null) add("cvss", Number(item.cvss_score) >= criteria.min_cvss);
  if (criteria.techniques?.length) add("technique", criteria.techniques.some((t) => techniques.includes(t)));
  if (criteria.sectors?.length) add("sector", criteria.sectors.some((s) => sectors.some((v) => v.toLowerCase().includes(s))));
  if (criteria.countries?.length) add("country", criteria.countries.some((c) => String(item.actor_country || "").toUpperCase().includes(c)));
  if (criteria.ioc_types?.length) add("ioc_type", criteria.ioc_types.some((t) => iocTypes.map((x) => String(x).toLowerCase()).includes(t)));
  if (criteria.lenses?.length) add("lens", criteria.lenses.some((l) => found.lenses.includes(l)));
  if (!checks.length) return { matched: false, reasons: [] };
  const logic = watch.logic === "AND" ? "AND" : "OR";
  const matched = logic === "AND" ? checks.every((c) => c.ok) : checks.some((c) => c.ok);
  return {
    matched,
    reasons: checks.filter((c) => c.ok).map((c) => c.label),
    lenses: found.lenses,
  };
}

// ---------------------------------------------------------------------------
// Event identity and dedupe
// ---------------------------------------------------------------------------

// 64-bit FNV-1a as 16 hex chars. Deterministic, dependency-free, sync.
function fnv64(text) {
  let h1 = 0x811c9dc5;
  let h2 = 0xcbf29ce4;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c ^ (h1 >>> 7), 0x01000193) >>> 0;
  }
  return h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0");
}

/**
 * Material revision of an item: what a customer would call "the advisory
 * changed" (title, severity, CVEs, KEV). Pipeline timestamps such as
 * processed_at are deliberately excluded, so re-enrichment of an unchanged
 * advisory in a new feed generation never produces a second event, while a
 * severity escalation or a new KEV listing does.
 */
export function materialRevision(item) {
  const sev = severityBucket(item || {});
  const kev = item?.kev_present === true || item?.kev_confirmed === true || item?.kev === true;
  const title = clean(String(item?.title || item?.name || ""), 240).toLowerCase();
  return "r" + fnv64([title, sev, cveIds(item || {}).sort().join(","), kev ? "kev" : ""].join("|"));
}

// Fields the matcher, classifier and event builder read. The scheduler ships
// only these to ledgers; the request path matches on the same projection so
// both paths decide identically.
const PROJECTED_FIELDS = [
  "id", "title", "name", "summary", "description", "ai_summary", "severity", "source", "source_name",
  "actor_tag", "actor_display_name", "threat_type", "actor_malware", "kev_product", "kev_name", "tags",
  "cve_ids", "affected_products", "kev_present", "kev_confirmed", "kev", "mitre_group_name", "actor_sectors",
  "attck_technique_ids", "epss_score", "cvss_score", "actor_country", "processed_at", "published", "tlp",
  "source_url", "blog_url",
];

export function projectItem(item) {
  const out = {};
  for (const k of PROJECTED_FIELDS) if (item[k] !== undefined) out[k] = item[k];
  if (Array.isArray(item.iocs)) out.iocs = item.iocs.map((i) => ({ type: i && i.type })).filter((i) => i.type);
  return out;
}

export function projectFeedItems(feed) {
  return validItems(feed).map(projectItem);
}

export function candidateEvent(watch, item, feedGeneratedAt, nowIso, origin = "request") {
  const hit = matchWatch(watch, item);
  if (!hit.matched) return null;
  const itemId = clean(String(item.id), 128);
  const revision = materialRevision(item);
  const dedupe = watch.id + "|" + itemId + "|" + revision;
  return {
    id: "e_" + fnv64(dedupe),
    watch_id: watch.id,
    watch_name: watch.name,
    matched_item_id: itemId,
    revision,
    origin,
    matched_at: nowIso,
    severity: clean(String(item.severity || ""), 24) || null,
    source: clean(String(item.source || ""), 80) || null,
    title: clean(String(item.title || ""), 240),
    lens: hit.lenses,
    reason: hit.reasons,
    cve_ids: cveIds(item),
    tlp: clean(String(item.tlp || ""), 20) || null,
    feed_generated_at: feedGeneratedAt || null,
    reference: clean(String(item.source_url || item.blog_url || ""), 300) || "https://intel.cyberdudebivash.com/cyber-watchdog.html",
    dedupe_key: dedupe,
    acknowledged: false,
    delivery_status: "no_destinations",
    deliveries: [],
  };
}

/** Candidate events for every enabled watch, bounded per watch. */
export function evaluateWatches(watches, items, feedGeneratedAt, nowIso, origin) {
  const out = [];
  for (const watch of (watches || []).filter((w) => w.enabled !== false)) {
    let n = 0;
    for (const item of items) {
      const event = candidateEvent(watch, item, feedGeneratedAt, nowIso, origin);
      if (event) { out.push(event); n += 1; }
      if (n >= SCHEDULER_POLICY.max_events_per_watch_per_eval) break;
    }
  }
  return out;
}

// v2 events carry a processed_at-based dedupe key and no `revision`. They
// suppress any new event for the same watch + item, so the upgrade cannot
// replay an old match as new.
function isDuplicate(index, event) {
  const k = event.watch_id + "|" + event.matched_item_id;
  const seen = index.get(k);
  if (!seen) return false;
  return seen.has("*legacy*") || seen.has(event.revision) || seen.has(event.dedupe_key);
}

function buildDedupeIndex(events) {
  const index = new Map();
  for (const e of events) {
    const k = e.watch_id + "|" + e.matched_item_id;
    if (!index.has(k)) index.set(k, new Set());
    const set = index.get(k);
    set.add(e.revision || "*legacy*");
    if (e.dedupe_key) set.add(e.dedupe_key);
  }
  return index;
}

// ---------------------------------------------------------------------------
// Ledger state machine (pure). WatchdogLedger and MemoryLedger only store.
// ---------------------------------------------------------------------------

function publicWatch(w) {
  return {
    id: w.id, name: w.name, logic: w.logic, enabled: w.enabled !== false,
    criteria: w.criteria, created_at: w.created_at, updated_at: w.updated_at,
  };
}

// ---------------------------------------------------------------------------
// Rollback safety (persisted representation)
//
// The previous implementation (v2, main @ 6ac0385) POSTs, unsigned, to the
// `url` of EVERY element of `destinations` inside the Durable Object storage
// key "ledger" -- it reads no state or protocol field. A marker alone would
// therefore not protect a v3 destination from a code rollback. v3 persists
// its signed destinations under a separate storage key that v2 never reads
// or writes, so after a rollback they are invisible (inert) to v2, and they
// survive any v2 write for a later roll-forward. The "ledger" key keeps only
// legacy v2 rows, which v3 in turn treats as disabled (no signing secret).
// Proven against the vendored v2 code by watchdog-rollback-compat.test.js.
// ---------------------------------------------------------------------------
export const LEDGER_STORAGE_KEY = "ledger";
export const SIGNED_DESTINATIONS_STORAGE_KEY = "watchdog_v3_signed_destinations";
export const DELIVERY_PROTOCOL = "signed-v3";

function isSignedV3(d) {
  return !!d && d.delivery_protocol === DELIVERY_PROTOCOL && typeof d.secret === "string" && d.secret.startsWith("whsec_");
}

/** Splits in-memory ledger state into the two persisted records. */
export function toPersisted(state) {
  const all = Array.isArray(state?.destinations) ? state.destinations : [];
  return {
    ledger: { ...state, destinations: all.filter((d) => !isSignedV3(d)) },
    signed: all.filter(isSignedV3),
  };
}

/** True when "ledger" still holds a signed v3 row (e.g. written by 6977abf). */
export function ledgerNeedsMigration(ledger) {
  return !!ledger && Array.isArray(ledger.destinations)
    && ledger.destinations.some((d) => d && typeof d.secret === "string" && d.secret.startsWith("whsec_"));
}

/**
 * Joins the two persisted records back into ledger state.
 *
 * Migration: the first v3 build deployed to production (6977abf, #496) kept
 * signed destinations inside "ledger" with a whsec_ secret but no
 * delivery_protocol. Such a row is a v3 destination, not a v2 one: it is
 * adopted as signed-v3 here, and the next write (toPersisted) moves it out of
 * "ledger" into the v3-only key. v2 never writes a secret, so a real v2 row
 * cannot match this rule.
 */
export function fromPersisted(ledger, signed) {
  const base = ledger && typeof ledger === "object" ? ledger : emptyLedgerState();
  const rows = (Array.isArray(base.destinations) ? base.destinations : []).map((d) => (
    d && !d.delivery_protocol && typeof d.secret === "string" && d.secret.startsWith("whsec_")
      ? { ...d, delivery_protocol: DELIVERY_PROTOCOL }
      : d
  ));
  const v3 = (Array.isArray(signed) ? signed.filter(isSignedV3) : []);
  const seen = new Set(v3.map((d) => d.id));
  const adopted = rows.filter((d) => isSignedV3(d) && !seen.has(d.id));
  const legacy = rows.filter((d) => !isSignedV3(d) && !seen.has(d.id));
  return { ...base, destinations: legacy.concat(v3, adopted) };
}

// Only a signed-v3 destination can ever deliver. A v2 destination has no
// signing secret or protocol, so it is inert until registered again.
export function destinationState(d) {
  if (!isSignedV3(d)) return "disabled";
  return d.state || "pending";
}

// Never includes the signing secret or the verification nonce.
export function publicDestination(d) {
  let hostname = null;
  try { hostname = new URL(d.url).hostname; } catch { hostname = null; }
  return {
    id: d.id,
    hostname,
    url: d.url,
    state: destinationState(d),
    created_at: d.created_at || null,
    verified_at: d.verified_at || null,
    last_delivery_at: d.last_delivery_at || null,
    failure_count: d.failure_count || 0,
    disabled_reason: isSignedV3(d) ? d.disabled_reason || null : "reregister_required_unsigned_v2_destination",
    last_verification_error: d.last_verification_error || null,
  };
}

function publicEvent(e) {
  return {
    ...e,
    deliveries: (e.deliveries || []).map((d) => ({
      destination_id: d.destination_id,
      delivery_id: d.delivery_id,
      status: d.status,
      attempts: d.attempts || 0,
      next_attempt_at: d.status === "pending" ? d.next_attempt_at || null : null,
      last_attempt_at: d.last_attempt_at || null,
      last_http_status: d.last_http_status ?? null,
      last_error: d.last_error || null,
      delivered_at: d.delivered_at || null,
    })),
  };
}

function aggregateDeliveryStatus(deliveries) {
  if (!deliveries || !deliveries.length) return "no_destinations";
  const s = new Set(deliveries.map((d) => d.status));
  if (s.has("pending")) return "pending";
  if (s.size === 1) return [...s][0];
  return "partial";
}

function enabledCount(watches) {
  return (watches || []).filter((w) => w.enabled !== false).length;
}

export function activeDestinations(destinations) {
  return (destinations || []).filter((d) => destinationState(d) === "active");
}

function pendingCount(events) {
  let n = 0;
  for (const e of events) for (const d of e.deliveries || []) if (d.status === "pending") n += 1;
  return n;
}

function msIso(ms) { return new Date(ms).toISOString(); }

export function nextDeliveryDue(state) {
  let min = null;
  const active = new Set(activeDestinations(state.destinations).map((d) => d.id));
  for (const e of state.events || []) {
    for (const d of e.deliveries || []) {
      if (d.status !== "pending" || !active.has(d.destination_id)) continue;
      const due = Date.parse(d.next_attempt_at || 0) || 0;
      const lease = d.lease_until ? Date.parse(d.lease_until) || 0 : 0;
      const t = Math.max(due, lease);
      if (min === null || t < min) min = t;
    }
  }
  return min === null ? null : msIso(min);
}

function appendCandidates(next, candidates, quota, now) {
  const index = buildDedupeIndex(next.events);
  const inserted = [];
  let deduped = 0;
  const active = quota.webhooks ? activeDestinations(next.destinations) : [];
  let pending = pendingCount(next.events);
  const nowMs = Date.parse(now) || Date.now();
  for (const raw of candidates || []) {
    if (!raw?.dedupe_key || !raw.watch_id || !raw.matched_item_id) continue;
    const event = { ...raw, revision: raw.revision || null };
    if (isDuplicate(index, event)) { deduped += 1; continue; }
    const k = event.watch_id + "|" + event.matched_item_id;
    if (!index.has(k)) index.set(k, new Set());
    index.get(k).add(event.revision || event.dedupe_key).add(event.dedupe_key);
    event.deliveries = active.map((d) => {
      const queueFull = pending >= DELIVERY_POLICY.max_pending_deliveries;
      if (!queueFull) pending += 1;
      return {
        destination_id: d.id,
        delivery_id: event.id + ":" + d.id,
        status: queueFull ? "failed" : "pending",
        attempts: 0,
        next_attempt_at: msIso(nowMs),
        last_error: queueFull ? "queue_full" : null,
      };
    });
    event.delivery_status = aggregateDeliveryStatus(event.deliveries);
    inserted.push(event);
  }
  next.events = inserted.concat(next.events).slice(0, EVENT_RETENTION);
  next.metrics = bumpMetrics(next.metrics, { events_generated: inserted.length, events_deduped: deduped });
  return { inserted, deduped };
}

function bumpMetrics(m, delta) {
  const out = { ...(m || {}) };
  for (const [k, v] of Object.entries(delta)) if (v) out[k] = (out[k] || 0) + v;
  return out;
}

function cloneState(base, subject) {
  return {
    revision: (base.revision || 0) + 1,
    subject,
    watches: Array.isArray(base.watches) ? base.watches.map((w) => ({ ...w })) : [],
    events: Array.isArray(base.events) ? base.events.map((e) => ({ ...e, deliveries: (e.deliveries || []).map((d) => ({ ...d })) })) : [],
    destinations: Array.isArray(base.destinations) ? base.destinations.map((d) => ({ ...d })) : [],
    deliveries: Array.isArray(base.deliveries) ? base.deliveries.slice() : [],
    metrics: { ...(base.metrics || {}) },
  };
}

export function applyLedgerMutation(state, op) {
  const base = state && typeof state === "object" ? state : emptyLedgerState();
  const subject = clean(String(op?.subject || ""), 200);
  if (!subject) return { error: "subject_required", status: 400, state: base };
  if (base.subject && base.subject !== subject) return { error: "tenant_mismatch", status: 403, state: base };
  if (op.type === "get") {
    return { readOnly: true, state: base, result: viewState(base) };
  }
  if (op.type === "get_destination_internal") {
    const d = (base.destinations || []).find((x) => x.id === clean(String(op.id || ""), 40));
    if (!d) return { error: "not_found", status: 404, state: base };
    return { readOnly: true, state: base, result: { destination: { ...d } } };
  }
  const next = cloneState(base, subject);
  const quota = quotaForTier(op.tier || "FREE");
  const now = op.now || new Date().toISOString();
  const nowMs = Date.parse(now) || Date.now();
  if (op.type === "create_watch") {
    if (!quota.events) return { error: "tier_required", status: 403, state: base, message: "Watches are included with Pro Defense." };
    if (next.watches.length >= quota.watches) return { error: "watch_limit", status: 403, state: base, message: "Watch limit for this plan is reached.", limit: quota.watches };
    const norm = normalizeCriteria(op.watch);
    if (norm.error) return { ...norm, status: 400, state: base };
    const name = clean(String(op.watch?.name || ""), 80);
    if (!name) return { error: "invalid_watch", status: 400, state: base, message: "Name is required." };
    const watch = {
      id: "w_" + clean(String(op.id || ""), 24).replace(/[^a-z0-9]/gi, "").slice(0, 24),
      name, logic: norm.logic, criteria: norm.criteria, enabled: op.watch?.enabled !== false,
      created_at: now, updated_at: now,
    };
    if (!watch.id || watch.id === "w_") return { error: "invalid_watch", status: 400, state: base };
    next.watches.push(watch);
    return { state: next, result: { watch: publicWatch(watch), count: next.watches.length, limit: quota.watches }, enabled_watches: enabledCount(next.watches) };
  }
  if (op.type === "update_watch") {
    if (!quota.events) return { error: "tier_required", status: 403, state: base };
    const id = clean(String(op.id || ""), 40);
    const idx = next.watches.findIndex((w) => w.id === id);
    if (idx < 0) return { error: "not_found", status: 404, state: base };
    const prev = next.watches[idx];
    const patch = op.watch && typeof op.watch === "object" ? op.watch : {};
    const mergedCriteria = { ...(prev.criteria || {}), ...(patch.criteria && typeof patch.criteria === "object" ? patch.criteria : {}) };
    for (const key of ["keywords", "cves", "vendors", "products", "actors", "malware_families", "sources", "techniques", "sectors", "countries", "ioc_types", "lenses"]) {
      if (Array.isArray(patch[key])) mergedCriteria[key] = patch[key];
    }
    if (patch.min_severity != null) mergedCriteria.min_severity = patch.min_severity;
    if (patch.kev != null) mergedCriteria.kev = patch.kev;
    if (patch.min_epss != null) mergedCriteria.min_epss = patch.min_epss;
    if (patch.min_cvss != null) mergedCriteria.min_cvss = patch.min_cvss;
    const norm = normalizeCriteria({ logic: patch.logic || prev.logic, criteria: mergedCriteria });
    if (norm.error) return { ...norm, status: 400, state: base };
    const name = clean(String(patch.name || prev.name), 80);
    next.watches[idx] = {
      ...prev, name, logic: norm.logic, criteria: norm.criteria,
      enabled: patch.enabled == null ? prev.enabled !== false : patch.enabled === true,
      updated_at: now,
    };
    return { state: next, result: { watch: publicWatch(next.watches[idx]) }, enabled_watches: enabledCount(next.watches) };
  }
  if (op.type === "delete_watch") {
    const id = clean(String(op.id || ""), 40);
    const kept = next.watches.filter((w) => w.id !== id);
    if (kept.length === next.watches.length) return { error: "not_found", status: 404, state: base };
    next.watches = kept;
    return { state: next, result: { deleted: id, count: kept.length }, enabled_watches: enabledCount(next.watches) };
  }
  if (op.type === "append_events" || op.type === "scheduled_evaluate") {
    if (!quota.events) return { error: "tier_required", status: 403, state: base };
    let candidates = op.events || [];
    if (op.type === "scheduled_evaluate") {
      // Freshness is re-checked here, inside the store: a caller that skipped
      // the gate still cannot create events from a non-FRESH feed.
      if (op.publication?.freshness_status !== "FRESH" || !Array.isArray(op.items)) {
        return { readOnly: true, state: base, result: { inserted: [], inserted_count: 0, deduped: 0, skipped: "feed_not_fresh", enabled_watches: enabledCount(base.watches) } };
      }
      candidates = evaluateWatches(next.watches, op.items, op.publication.feed_generated_at, now, "scheduler");
    }
    const { inserted, deduped } = appendCandidates(next, candidates, quota, now);
    const result = {
      inserted, inserted_count: inserted.length, deduped,
      enabled_watches: enabledCount(next.watches),
      active_destinations: activeDestinations(next.destinations).length,
    };
    if (!inserted.length) {
      // Nothing new: do not rewrite storage for a pure dedupe pass.
      return { readOnly: true, state: base, result };
    }
    return { state: next, result, next_delivery_due_at: nextDeliveryDue(next) };
  }
  if (op.type === "ack") {
    const ids = new Set(asList(op.ids, 50, 96, (v) => clean(String(v), 96)));
    let n = 0;
    next.events = next.events.map((e) => {
      if (!ids.has(e.id) || e.acknowledged) return e;
      n += 1;
      return { ...e, acknowledged: true, acknowledged_at: now };
    });
    return { state: next, result: { acknowledged: n } };
  }
  if (op.type === "set_destination" || op.type === "create_destination") {
    if (!quota.webhooks) return { error: "tier_required", status: 403, state: base, message: "HTTPS webhook delivery is included with Enterprise SOC or MSSP." };
    const dest = normalizeDestination(op.destination);
    if (dest.error) return { ...dest, status: 400, state: base };
    const live = next.destinations.filter((d) => destinationState(d) !== "disabled");
    if (live.length >= quota.webhooks) return { error: "webhook_limit", status: 403, state: base, limit: quota.webhooks };
    const secret = typeof op.secret === "string" && /^whsec_[0-9a-f]{64}$/.test(op.secret) ? op.secret : null;
    if (!secret) return { error: "secret_required", status: 500, state: base };
    const row = {
      id: "d_" + clean(String(op.id || ""), 40).replace(/[^a-z0-9-]/gi, "").slice(0, 36),
      url: dest.url,
      state: "pending",
      delivery_protocol: DELIVERY_PROTOCOL,
      secret,
      created_at: now,
      verified_at: null,
      last_delivery_at: null,
      failure_count: 0,
    };
    next.destinations.push(row);
    return { state: next, result: { destination: publicDestination(row), count: next.destinations.length } };
  }
  if (op.type === "verification_result") {
    const id = clean(String(op.id || ""), 40);
    const idx = next.destinations.findIndex((d) => d.id === id);
    if (idx < 0) return { error: "not_found", status: 404, state: base };
    const d = next.destinations[idx];
    if (!isSignedV3(d)) return { error: "reregister_required", status: 409, state: base };
    if (op.ok) {
      next.destinations[idx] = { ...d, state: "active", verified_at: now, failure_count: 0, disabled_reason: null, last_verification_error: null };
    } else {
      next.destinations[idx] = { ...d, state: d.state === "active" ? "active" : "pending", last_verification_error: clean(String(op.error || "verification_failed"), 60) };
      next.metrics = bumpMetrics(next.metrics, { verification_failures: 1 });
    }
    return { state: next, result: { destination: publicDestination(next.destinations[idx]), verified: !!op.ok }, enabled_watches: enabledCount(next.watches) };
  }
  if (op.type === "set_destination_state") {
    const id = clean(String(op.id || ""), 40);
    const idx = next.destinations.findIndex((d) => d.id === id);
    if (idx < 0) return { error: "not_found", status: 404, state: base };
    const want = op.state === "disabled" ? "disabled" : null;
    if (!want) return { error: "invalid_state", status: 400, state: base };
    next.destinations[idx] = { ...next.destinations[idx], state: want, disabled_reason: "customer" };
    return { state: next, result: { destination: publicDestination(next.destinations[idx]) } };
  }
  if (op.type === "delete_destination") {
    const id = clean(String(op.id || ""), 40);
    const kept = next.destinations.filter((d) => d.id !== id);
    if (kept.length === next.destinations.length) return { error: "not_found", status: 404, state: base };
    next.destinations = kept;
    // Pending deliveries to a removed destination end here, visibly.
    for (const e of next.events) {
      let touched = false;
      for (const d of e.deliveries || []) {
        if (d.destination_id === id && d.status === "pending") { d.status = "failed"; d.last_error = "destination_removed"; touched = true; }
      }
      if (touched) e.delivery_status = aggregateDeliveryStatus(e.deliveries);
    }
    return { state: next, result: { deleted: id, count: kept.length } };
  }
  if (op.type === "delivery_plan") {
    // Leases due deliveries so an overlapping alarm cannot send them twice.
    const limit = Math.min(DELIVERY_POLICY.max_deliveries_per_run, Math.max(1, Number(op.limit) || DELIVERY_POLICY.max_deliveries_per_run));
    const byId = new Map(next.destinations.map((d) => [d.id, d]));
    const planned = [];
    let changed = false;
    for (const e of next.events) {
      for (const d of e.deliveries || []) {
        if (d.status !== "pending") continue;
        const dest = byId.get(d.destination_id);
        if (!dest || destinationState(dest) !== "active") {
          d.status = "failed"; d.last_error = dest ? "destination_" + destinationState(dest) : "destination_removed";
          e.delivery_status = aggregateDeliveryStatus(e.deliveries);
          changed = true;
          continue;
        }
        if (Date.parse(d.next_attempt_at || 0) > nowMs) continue;
        if (d.lease_until && Date.parse(d.lease_until) > nowMs) continue;
        if (planned.length >= limit) continue;
        d.lease_until = msIso(nowMs + DELIVERY_POLICY.lease_seconds * 1000);
        changed = true;
        planned.push({
          event_id: e.id,
          delivery_id: d.delivery_id,
          attempt: (d.attempts || 0) + 1,
          destination: { id: dest.id, url: dest.url, secret: dest.secret },
          raw_body: JSON.stringify(buildWebhookPayload(e, d.delivery_id)),
        });
      }
    }
    if (!changed) return { readOnly: true, state: base, result: { planned: [], next_delivery_due_at: nextDeliveryDue(base) } };
    return { state: next, result: { planned, next_delivery_due_at: nextDeliveryDue(next) }, next_delivery_due_at: nextDeliveryDue(next) };
  }
  if (op.type === "delivery_results") {
    const byDelivery = new Map();
    for (const r of op.results || []) if (r && r.delivery_id) byDelivery.set(r.delivery_id, r);
    const destIdx = new Map(next.destinations.map((d, i) => [d.id, i]));
    const delta = { delivery_attempts: 0, delivery_successes: 0, delivery_failures: 0 };
    for (const e of next.events) {
      let touched = false;
      for (const d of e.deliveries || []) {
        const r = byDelivery.get(d.delivery_id);
        if (!r || d.status !== "pending") continue;
        touched = true;
        d.attempts = (d.attempts || 0) + 1;
        d.last_attempt_at = now;
        d.last_http_status = r.http_status ?? null;
        d.last_error = r.error || null;
        d.lease_until = null;
        delta.delivery_attempts += 1;
        const di = destIdx.get(d.destination_id);
        const dest = di == null ? null : next.destinations[di];
        let final = null;
        if (r.outcome === "delivered") {
          d.status = "delivered"; d.delivered_at = now;
          delta.delivery_successes += 1;
          if (dest) next.destinations[di] = { ...dest, last_delivery_at: now, failure_count: 0 };
        } else if (r.outcome === "retry" && d.attempts < DELIVERY_POLICY.max_attempts) {
          d.next_attempt_at = msIso(nowMs + retryDelaySeconds(d.attempts + 1, r.retry_after_seconds) * 1000);
        } else {
          d.status = "failed"; final = true;
          delta.delivery_failures += 1;
        }
        if (dest && (final || r.disable)) {
          const cur = next.destinations[di];
          const failures = final ? (cur.failure_count || 0) + 1 : cur.failure_count || 0;
          let stateNext = cur.state;
          let reason = cur.disabled_reason || null;
          if (r.disable) { stateNext = "failed"; reason = r.disable; }
          else if (failures >= DELIVERY_POLICY.auto_disable_after_consecutive_failed_events) { stateNext = "failed"; reason = "consecutive_failures"; }
          next.destinations[di] = { ...cur, failure_count: failures, state: stateNext, disabled_reason: reason };
        }
        next.deliveries = [{
          event_id: e.id, destination_id: d.destination_id, delivery_id: d.delivery_id, attempt: d.attempts,
          outcome: d.status === "pending" ? "retry_scheduled" : d.status, http_status: d.last_http_status, error: d.last_error, at: now,
        }].concat(next.deliveries).slice(0, DELIVERY_RETENTION);
      }
      if (touched) e.delivery_status = aggregateDeliveryStatus(e.deliveries);
    }
    next.metrics = bumpMetrics(next.metrics, delta);
    return { state: next, result: { recorded: delta.delivery_attempts, metrics: delta, next_delivery_due_at: nextDeliveryDue(next) }, next_delivery_due_at: nextDeliveryDue(next) };
  }
  if (op.type === "record_delivery") {
    // DEPRECATED v2 op (single status per event). Kept so an in-flight v2
    // caller cannot corrupt state; v3 uses delivery_plan/delivery_results.
    next.deliveries = [{ ...op.delivery, at: now }].concat(next.deliveries).slice(0, DELIVERY_RETENTION);
    return { state: next, result: { recorded: true } };
  }
  return { error: "unsupported_op", status: 400, state: base };
}

function viewState(state) {
  return {
    revision: state.revision || 0,
    watches: (state.watches || []).map(publicWatch),
    events: (state.events || []).map(publicEvent),
    destinations: (state.destinations || []).map(publicDestination),
    deliveries: state.deliveries || [],
    metrics: { ...(state.metrics || {}) },
  };
}

/**
 * Static URL checks (scheme, port, credentials, literal addresses, local
 * names). DNS resolution safety is enforced separately, at registration,
 * verification and every delivery -- see watchdog-webhook.js.
 */
export function normalizeDestination(input) {
  const out = validateDestinationUrl(input?.url);
  if (out.error) return out;
  return { url: out.url, hostname: out.hostname };
}

export function analyticsFromEvents(events, nowMs = Date.now()) {
  const list = Array.isArray(events) ? events : [];
  const day = 86400000;
  const inWindow = (e, ms) => {
    const t = Date.parse(e.matched_at || "");
    return Number.isFinite(t) && nowMs - t <= ms;
  };
  const dayEvents = list.filter((e) => inWindow(e, day));
  const weekEvents = list.filter((e) => inWindow(e, 7 * day));
  // Destination-specific results; a v2 event without `deliveries` falls back
  // to its single delivery_status.
  const finals = [];
  for (const e of list) {
    if (Array.isArray(e.deliveries) && e.deliveries.length) {
      for (const d of e.deliveries) if (d.status === "delivered" || d.status === "failed") finals.push(d.status);
    } else if (e.delivery_status === "delivered" || e.delivery_status === "failed") {
      finals.push(e.delivery_status);
    }
  }
  const pending = list.reduce((n, e) => n + (e.deliveries || []).filter((d) => d.status === "pending").length, 0);
  const success = finals.filter((s) => s === "delivered").length;
  const failed = finals.filter((s) => s === "failed").length;
  const byWatch = new Map();
  const bySource = new Map();
  for (const event of list) {
    const watch = event.watch_name || event.watch_id;
    if (watch) byWatch.set(watch, (byWatch.get(watch) || 0) + 1);
    if (event.source) bySource.set(event.source, (bySource.get(event.source) || 0) + 1);
  }
  const ranked = (map) => [...map.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0]))).slice(0, 5);
  return {
    matches_24h: dayEvents.length,
    matches_7d: weekEvents.length,
    critical_matches_24h: dayEvents.filter((e) => String(e.severity).toUpperCase() === "CRITICAL").length,
    high_matches_24h: dayEvents.filter((e) => String(e.severity).toUpperCase() === "HIGH").length,
    unread: list.filter((e) => !e.acknowledged).length,
    delivery_success_rate: finals.length ? Number((success / finals.length).toFixed(4)) : null,
    delivery_failure_rate: finals.length ? Number((failed / finals.length).toFixed(4)) : null,
    delivery_failures: failed,
    deliveries_pending: pending,
    top_watches: ranked(byWatch).map(([name, count]) => ({ name, count })),
    top_sources: ranked(bySource).map(([source, count]) => ({ source, count })),
    history: list.length ? "stored-match-events" : "no_history_yet",
  };
}

export class MemoryLedger {
  constructor() {
    this.state = emptyLedgerState();
    this.chain = Promise.resolve();
  }
  mutate(op) {
    const run = this.chain.then(() => {
      const out = applyLedgerMutation(this.state, op);
      if (!out.error && !out.readOnly) this.state = out.state;
      return out;
    });
    this.chain = run.then(() => {}, () => {});
    return run;
  }
}

/**
 * Executes due webhook deliveries for one ledger: plan (leases) -> attempt
 * (re-resolve, sign, POST) -> record. Used by the WatchdogLedger alarm and
 * by tests. Bounded by DELIVERY_POLICY.max_deliveries_per_run.
 * `attempt` is watchdog-webhook.js attemptDelivery (injected, no cycle).
 */
export async function runDueDeliveries({ ledger, subject, tier, now, attempt, fetchImpl, dnsFetch }) {
  const plan = await ledger.mutate({ type: "delivery_plan", subject, tier, now });
  if (plan.error) return { error: plan.error, attempted: 0, next_delivery_due_at: null };
  const planned = plan.result?.planned || [];
  if (!planned.length) return { attempted: 0, next_delivery_due_at: plan.result?.next_delivery_due_at || null, metrics: null };
  const results = [];
  for (const p of planned) {
    const r = await attempt({
      destination: p.destination, eventId: p.event_id, deliveryId: p.delivery_id, attempt: p.attempt,
      rawBody: p.raw_body, fetchImpl, dnsFetch, nowMs: Date.parse(now) || Date.now(),
    });
    results.push({ delivery_id: p.delivery_id, ...r });
  }
  const rec = await ledger.mutate({ type: "delivery_results", subject, tier, now, results });
  return {
    attempted: results.length,
    results,
    metrics: rec.result?.metrics || null,
    next_delivery_due_at: rec.result?.next_delivery_due_at || null,
  };
}

// ---------------------------------------------------------------------------
// Request routing
// ---------------------------------------------------------------------------

const SCOPE_BY_ROUTE = [
  // [path, methods, scope]
  ["/api/watchdog/watches", ["GET", "HEAD"], WATCHDOG_SCOPES.READ],
  ["/api/watchdog/watches", ["POST", "PATCH", "DELETE"], WATCHDOG_SCOPES.WATCHES_WRITE],
  ["/api/watchdog/events", ["GET", "HEAD"], WATCHDOG_SCOPES.EVENTS_READ],
  ["/api/watchdog/matches", ["GET", "HEAD"], WATCHDOG_SCOPES.EVENTS_READ],
  ["/api/watchdog/events/ack", ["POST"], WATCHDOG_SCOPES.EVENTS_ACK],
  ["/api/watchdog/destinations", ["GET", "HEAD"], WATCHDOG_SCOPES.READ],
  ["/api/watchdog/destinations", ["POST", "PATCH", "DELETE"], WATCHDOG_SCOPES.DESTINATIONS_WRITE],
  ["/api/watchdog/destinations/verify", ["POST"], WATCHDOG_SCOPES.DESTINATIONS_WRITE],
  ["/api/watchdog/deploy", ["GET", "HEAD"], WATCHDOG_SCOPES.READ],
  ["/api/watchdog/brief", ["GET", "HEAD"], WATCHDOG_SCOPES.READ],
];

export function requiredScope(path, method) {
  for (const [p, methods, scope] of SCOPE_BY_ROUTE) if (p === path && methods.includes(method)) return scope;
  return null;
}

/** A Watchdog session token may only do what its scopes name. */
export function scopeDenied(auth, path, method) {
  if (!auth || auth.aud !== SESSION_POLICY.audience) return null;
  const need = requiredScope(path, method);
  if (!need) return null;
  const have = Array.isArray(auth.scopes) ? auth.scopes : [];
  return have.includes(need) ? null : { status: 403, body: { error: "insufficient_scope", required_scope: need } };
}

const TENANT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const FORBIDDEN = { status: 403, body: { error: "forbidden", message: "Not authorized for this Watchdog resource." } };

/**
 * MSSP sub-tenant selection. Tenant identity comes from the authenticated
 * credential's managed_tenants list (the platform's existing MSSP tenant
 * authority, set by the key administrator), never from the request body.
 * A key with no explicit managed_tenants list gets no sub-tenant access:
 * isolation requires an explicit membership list. Every refusal is the same
 * generic 403, so a caller cannot probe which tenants exist.
 */
export function resolveTenant(req) {
  const fromHeader = req.headers && typeof req.headers.get === "function" ? req.headers.get("X-CDB-Watchdog-Tenant") : null;
  const fromQuery = req.searchParams?.get?.("tenant") || null;
  const requested = fromHeader || fromQuery || null;
  const bound = req.auth?.tenant || null;
  if (!requested && !bound) return { tenant: null };
  const tenant = requested || bound;
  if (bound && requested && bound !== requested) return { error: FORBIDDEN };
  if (typeof tenant !== "string" || !TENANT_RE.test(tenant)) return { error: FORBIDDEN };
  const tier = effectiveTier(req.auth);
  if (!featuresFor(tier).tenants) return { error: FORBIDDEN };
  const managed = Array.isArray(req.auth?.managed_tenants) ? req.auth.managed_tenants : null;
  if (!managed || !managed.includes(tenant)) return { error: FORBIDDEN };
  return { tenant };
}

export function ledgerKeyFor(sub, tenant) {
  return tenant ? sub + "|t:" + tenant : sub;
}

function paidGuard(auth) {
  const tier = effectiveTier(auth);
  const quota = quotaForTier(tier);
  if (!quota.events || !auth?.sub) {
    return { error: { status: 403, body: { error: "tier_required", message: "This Watchdog capability is included with Pro Defense (" + priceLabel("PRO") + ").", checkout: "/upgrade.html?plan=pro&feature=cyber-watchdog" } } };
  }
  return { tier, quota };
}

async function ledger(req, op) {
  const key = req.ledgerKey || req.auth.sub;
  const store = typeof req.ledgerFor === "function" ? req.ledgerFor(key) : req.ledger;
  if (!store || typeof store.mutate !== "function") {
    return { error: "watch_store_unavailable", status: 503, message: "Watch store is temporarily unavailable. Nothing was saved." };
  }
  return store.mutate({ ...op, subject: key, tier: effectiveTier(req.auth), now: req.now });
}

function publicFailure(out) {
  const body = { error: out?.error || "watch_store_unavailable" };
  // Ownership mismatch reveals nothing about the other ledger.
  if (out?.error === "tenant_mismatch") return { status: 403, body };
  if (out?.message) body.message = out.message;
  if (out?.limit != null) body.limit = out.limit;
  return { status: out?.status || 503, body };
}

/**
 * Claims for a Watchdog browser session: customer-bound (sub), audience- and
 * scope-restricted, short-lived, and never outliving max_lifetime_seconds
 * from the original credential exchange. A session token can refresh
 * itself but can never widen its scopes or tenant.
 */
export function buildSessionClaims(auth, nowSec, jti, tenant) {
  const tier = effectiveTier(auth);
  const tierScopes = scopesForTier(tier);
  const isSession = auth?.aud === SESSION_POLICY.audience;
  const scopes = isSession ? tierScopes.filter((s) => (auth.scopes || []).includes(s)) : tierScopes;
  const authTime = isSession && Number.isInteger(auth.auth_time) ? auth.auth_time : nowSec;
  const hardStop = authTime + SESSION_POLICY.max_lifetime_seconds;
  const exp = Math.min(nowSec + SESSION_POLICY.ttl_seconds, hardStop);
  if (!scopes.length || exp <= nowSec) return null;
  const claims = {
    sub: auth.sub, tier, aud: SESSION_POLICY.audience, scope: scopes.join(" "),
    iat: nowSec, exp, auth_time: authTime, jti, iss: "SENTINEL-APEX",
  };
  if (tenant) claims.tenant = tenant;
  if (Array.isArray(auth.managed_tenants)) claims.managed_tenants = auth.managed_tenants.slice(0, 100);
  // Entitlement expiry of the underlying key (not the token's own exp), so
  // the scheduler never confuses a 15-minute session with the subscription.
  const ent = entitlementExpiry(auth);
  if (ent) {
    if (Date.parse(ent) <= nowSec * 1000) return null;
    claims.ent_exp = ent;
    claims.exp = Math.min(claims.exp, Math.floor(Date.parse(ent) / 1000));
  }
  return claims;
}

export function buildWebhookPayload(event, deliveryId) {
  const payload = {
    type: "watchdog.match",
    contract_version: WEBHOOK_CONTRACT.version,
    event_id: event.id,
    product: WATCHDOG_NAME,
    watch_id: event.watch_id,
    watch_name: event.watch_name,
    matched_item_id: event.matched_item_id,
    revision: event.revision || null,
    matched_at: event.matched_at || null,
    title: event.title,
    severity: event.severity,
    source: event.source,
    reason: event.reason,
    cve_ids: event.cve_ids || [],
    lenses: event.lens || [],
    feed_generated_at: event.feed_generated_at,
    reference: event.reference,
    tlp: event.tlp,
  };
  if (deliveryId) payload.delivery_id = deliveryId;
  return payload;
}

/**
 * DEPRECATED (v3): unsigned single-attempt POST with no DNS validation.
 * Not called by any v3 path; retained for importers. Use
 * watchdog-webhook.js attemptDelivery() via runDueDeliveries().
 * Removal: next Watchdog major.
 */
export async function deliverWebhook(url, payload, fetchImpl = fetch, timeoutMs = MAX_WEBHOOK_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      redirect: "manual",
      headers: { "Content-Type": "application/json", "User-Agent": "CYBERDUDEBIVASH-SENTINEL-APEX-CYBER-WATCHDOG/3.0" },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    return { status: res.ok ? "delivered" : "failed", http_status: res.status };
  } catch {
    return { status: "failed", http_status: null };
  } finally {
    clearTimeout(timer);
  }
}

async function evaluateMatches(req, record) {
  const pub = watchdogPublication(req.feed, req.nowMs);
  if (!pub.serve_live) return { degraded: degradedBody(pub), inserted: [] };
  const candidates = evaluateWatches(record.watches || [], projectFeedItems(req.feed), pub.feed_generated_at, req.now, "request");
  const appended = candidates.length
    ? await ledger(req, { type: "append_events", events: candidates })
    : { result: { inserted: [], deduped: 0 } };
  return { pub, inserted: appended.result?.inserted || [], deduped: appended.result?.deduped || 0, error: appended.error ? appended : null };
}

export function deployManifest(tier) {
  const quota = quotaForTier(tier);
  if (!quota.poller) {
    return {
      error: "tier_required",
      message: "The Watchdog poller is a Pro Defense client of the hosted brief. It is not a separate product.",
      checkout: "/upgrade.html?plan=pro&feature=cyber-watchdog",
    };
  }
  return {
    product: WATCHDOG_NAME,
    mode: "customer-environment",
    seller: SELLER.seller_trade_name,
    entitlement: "PRO+ reads GET /api/watchdog/brief. The poller is not an Enterprise boundary.",
    runtime: "Node.js 18+",
    poll: {
      endpoint: "https://intel.cyberdudebivash.com/api/watchdog/brief",
      auth_header: "X-API-Key",
      interval_seconds: 900,
      package: "deploy/cyber-watchdog/poll.mjs",
    },
    background_evaluation: quota.background_evaluation
      ? "Watches are evaluated by the hosted scheduler after each authoritative feed update. No browser or poller is required."
      : null,
    webhooks: quota.webhooks
      ? {
        endpoint: "POST /api/watchdog/destinations",
        verify: "POST /api/watchdog/destinations/verify?id=",
        limit: quota.webhooks,
        contract_version: WEBHOOK_CONTRACT.version,
        signature: "X-CDB-Watchdog-Signature: v1=hex(HMAC-SHA256(secret, timestamp + \".\" + raw_body))",
        reference_receiver: "deploy/cyber-watchdog/sink.mjs",
      }
      : { endpoint: null, message: "HTTPS delivery is included with Enterprise SOC or MSSP." },
    does_not: [
      "The poller does not scan the internet from the customer host.",
      "It pulls the entitled Sentinel APEX brief and writes it locally only when the brief is FRESH.",
    ],
    included_with: tier,
  };
}

/**
 * When the paid entitlement behind this credential ends. An API key carries
 * its record's expires_at; a Watchdog session carries ent_exp from the key it
 * was exchanged for. Any other JWT's expires_at is the token lifetime, not
 * the entitlement, so it is not used.
 */
export function entitlementExpiry(auth) {
  if (!auth) return null;
  if (auth.aud === SESSION_POLICY.audience) return auth.entitlement_expires_at || null;
  if (auth.jwt) return null;
  return auth.expires_at || null;
}

function registerHook(req, out) {
  if (!req.scheduler || typeof req.scheduler.register !== "function" || out?.enabled_watches == null) return;
  const tier = effectiveTier(req.auth);
  return req.scheduler.register({
    ledger_key: req.ledgerKey,
    subject: req.auth.sub,
    tenant: req.tenant || null,
    tier,
    enabled_watches: featuresFor(tier).background_evaluation ? out.enabled_watches : 0,
    expires_at: entitlementExpiry(req.auth),
  });
}

function metricsHook(req, delta) {
  if (!req.scheduler || typeof req.scheduler.recordMetrics !== "function") return;
  if (!Object.values(delta).some(Boolean)) return;
  return req.scheduler.recordMetrics(delta);
}

export async function routeWatchdog(req) {
  const path = req.path || "";
  if (!path.startsWith("/api/watchdog")) return null;
  const method = String(req.method || "GET").toUpperCase();
  const tier = effectiveTier(req.auth);
  const now = req.now || new Date().toISOString();
  req.now = now;

  if (path === "/api/watchdog/offer") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    return { status: 200, body: watchdogOffer() };
  }

  if (path === "/api/watchdog/health") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    const pub = watchdogPublication(req.feed, req.nowMs);
    return {
      status: pub.serve_live ? 200 : 503,
      body: {
        product: WATCHDOG_NAME,
        module_version: WATCHDOG_VERSION,
        freshness_status: pub.freshness_status,
        feed_generated_at: pub.feed_generated_at,
        feed_age_seconds: pub.feed_age_seconds,
        freshness_threshold_seconds: pub.freshness_threshold_seconds,
        feed_item_count: pub.feed_item_count,
        watch_store: (req.ledger || req.ledgerFor) ? "ok" : "unavailable",
        autonomous_evaluation: req.scheduler ? "configured" : "unavailable",
      },
    };
  }

  if (path === "/api/watchdog/session") {
    if (method === "DELETE") {
      if (req.auth?.aud !== SESSION_POLICY.audience || typeof req.revokeSession !== "function") return { status: 400, body: { error: "no_watchdog_session" } };
      await req.revokeSession(req.auth);
      return { status: 200, body: { revoked: true } };
    }
    if (method !== "POST") return { status: 405, body: { error: "method_not_allowed" } };
    const guard = paidGuard(req.auth);
    if (guard.error) return guard.error;
    const t = resolveTenant(req);
    if (t.error) return t.error;
    if (typeof req.issueSession !== "function") return { status: 503, body: { error: "session_unavailable" } };
    const claims = buildSessionClaims(req.auth, Math.floor((req.nowMs || Date.now()) / 1000), req.id, t.tenant);
    if (!claims) return { status: 403, body: { error: "session_expired", message: "Sign in again with your API key." } };
    const token = await req.issueSession(claims);
    if (!token) return { status: 503, body: { error: "session_unavailable" } };
    return {
      status: 200,
      body: {
        token, token_type: "Bearer", audience: claims.aud, scopes: claims.scope.split(" "),
        tier: claims.tier, tenant: claims.tenant || null,
        expires_at: new Date(claims.exp * 1000).toISOString(),
        refresh_before: new Date(claims.exp * 1000).toISOString(),
        max_session_until: new Date((claims.auth_time + SESSION_POLICY.max_lifetime_seconds) * 1000).toISOString(),
        usage: "Authorization: Bearer <token> on /api/watchdog/* only.",
      },
    };
  }

  const denied = scopeDenied(req.auth, path, method);
  if (denied) return denied;

  if (path === "/api/watchdog/brief") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    const lens = req.searchParams?.get?.("lens") || null;
    const q = req.searchParams?.get?.("q") || "";
    const limit = req.searchParams?.get?.("limit");
    return buildWatchdogBrief(req.feed, { tier, lens, q, limit, now, nowMs: req.nowMs, subscription_status: req.auth?.subscription_status, error: req.auth?.error });
  }

  if (path === "/api/watchdog/deploy") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    const body = deployManifest(tier);
    return { status: body.error ? 403 : 200, body };
  }

  if (path === "/api/watchdog/ops") {
    // Operator-only. Unknown to everyone else.
    if (!req.isOperator || !req.scheduler || typeof req.scheduler.metrics !== "function") return { status: 404, body: { error: "not_found", path } };
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    return { status: 200, body: await req.scheduler.metrics(req.nowMs) };
  }

  const known = ["/api/watchdog/watches", "/api/watchdog/matches", "/api/watchdog/events", "/api/watchdog/events/ack", "/api/watchdog/destinations", "/api/watchdog/destinations/verify"];
  if (!known.includes(path)) return { status: 404, body: { error: "not_found", path } };

  const guard = paidGuard(req.auth);
  if (guard.error) return guard.error;
  const t = resolveTenant(req);
  if (t.error) return t.error;
  req.tenant = t.tenant;
  req.ledgerKey = ledgerKeyFor(req.auth.sub, t.tenant);

  if (path === "/api/watchdog/destinations" || path === "/api/watchdog/destinations/verify") {
    const quota = quotaForTier(tier);
    if (!quota.webhooks) {
      return { status: 403, body: { error: "tier_required", message: "HTTPS webhook delivery is included with Enterprise SOC (" + priceLabel("ENTERPRISE") + ") or MSSP. Pro Defense includes the hosted watch, background evaluation and the brief poller.", checkout: "/upgrade.html?plan=enterprise&feature=cyber-watchdog" } };
    }
    if (path === "/api/watchdog/destinations/verify") {
      if (method !== "POST") return { status: 405, body: { error: "method_not_allowed" } };
      const id = req.searchParams?.get?.("id") || req.body?.id;
      const got = await ledger(req, { type: "get_destination_internal", id });
      if (got.error) return publicFailure(got);
      const dest = got.result.destination;
      if (dest.state === "disabled") return { status: 409, body: { error: "destination_disabled" } };
      if (req.webhookDeliveryEnabled !== true) return { status: 503, body: { error: "webhook_delivery_disabled", message: "Webhook delivery is switched off by the operator. Nothing was sent." } };
      if (typeof req.verifyDestination !== "function") return { status: 503, body: { error: "verification_unavailable" } };
      const nonce = req.nonce || "";
      const outcome = await req.verifyDestination({ destination: dest, nonce });
      const rec = await ledger(req, { type: "verification_result", id: dest.id, ok: outcome.ok, error: outcome.error });
      if (rec.error) return publicFailure(rec);
      if (!outcome.ok) await metricsHook(req, { verification_failures: 1 });
      await registerHook(req, { enabled_watches: rec.enabled_watches });
      return { status: outcome.ok ? 200 : 422, body: { ...rec.result, error: outcome.ok ? undefined : outcome.error } };
    }
    if (method === "GET" || method === "HEAD") {
      const got = await ledger(req, { type: "get" });
      if (got.error) return publicFailure(got);
      return { status: 200, body: { destinations: got.result.destinations, limit: quota.webhooks, recent_deliveries: got.result.deliveries.slice(0, 20), contract_version: WEBHOOK_CONTRACT.version } };
    }
    if (method === "POST") {
      const checked = normalizeDestination(req.body);
      if (checked.error) return { status: 400, body: { error: checked.error, message: checked.message } };
      if (typeof req.resolveDestination === "function") {
        const resolved = await req.resolveDestination(checked.hostname);
        if (!resolved.ok) return { status: 400, body: { error: "invalid_destination", message: "Webhook host did not resolve to an allowed public address.", reason: resolved.error } };
      } else {
        return { status: 503, body: { error: "destination_resolution_unavailable", message: "Destination safety check is unavailable. Nothing was saved." } };
      }
      const secret = req.secret;
      const out = await ledger(req, { type: "create_destination", destination: req.body, id: req.id, secret });
      if (out.error) return publicFailure(out);
      return {
        status: 201,
        body: {
          ...out.result,
          signing_secret: secret,
          signing_secret_notice: "Shown once. Store it now. It is never returned again.",
          next_step: "POST /api/watchdog/destinations/verify?id=" + out.result.destination.id,
        },
      };
    }
    if (method === "PATCH") {
      const out = await ledger(req, { type: "set_destination_state", id: req.searchParams?.get?.("id") || req.body?.id, state: req.body?.state });
      if (out.error) return publicFailure(out);
      return { status: 200, body: out.result };
    }
    if (method === "DELETE") {
      const out = await ledger(req, { type: "delete_destination", id: req.searchParams?.get?.("id") || req.body?.id });
      if (out.error) return publicFailure(out);
      return { status: 200, body: out.result };
    }
    return { status: 405, body: { error: "method_not_allowed" } };
  }

  if (path === "/api/watchdog/watches" && (method === "GET" || method === "HEAD")) {
    const got = await ledger(req, { type: "get" });
    if (got.error) return publicFailure(got);
    return { status: 200, body: { watches: got.result.watches, limit: guard.quota.watches, tier, tenant: req.tenant || null } };
  }
  if (path === "/api/watchdog/watches" && method === "POST") {
    const out = await ledger(req, { type: "create_watch", watch: req.body, id: req.id });
    if (out.error) return publicFailure(out);
    await registerHook(req, out);
    return { status: 201, body: out.result };
  }
  if (path === "/api/watchdog/watches" && method === "PATCH") {
    const out = await ledger(req, { type: "update_watch", id: req.searchParams?.get?.("id") || req.body?.id, watch: req.body });
    if (out.error) return publicFailure(out);
    await registerHook(req, out);
    return { status: 200, body: out.result };
  }
  if (path === "/api/watchdog/watches" && method === "DELETE") {
    const out = await ledger(req, { type: "delete_watch", id: req.searchParams?.get?.("id") || req.body?.id });
    if (out.error) return publicFailure(out);
    await registerHook(req, out);
    return { status: 200, body: out.result };
  }
  if (path === "/api/watchdog/events/ack") {
    if (method !== "POST") return { status: 405, body: { error: "method_not_allowed" } };
    const out = await ledger(req, { type: "ack", ids: req.body?.ids || [] });
    if (out.error) return publicFailure(out);
    return { status: 200, body: out.result };
  }
  if (path === "/api/watchdog/matches" || path === "/api/watchdog/events") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    const got = await ledger(req, { type: "get" });
    if (got.error) return publicFailure(got);
    // evaluate=0 lists stored events without evaluating: used to observe what
    // the autonomous scheduler produced on its own.
    const readOnly = req.searchParams?.get?.("evaluate") === "0";
    let evaluated;
    if (readOnly) {
      const pub = watchdogPublication(req.feed, req.nowMs);
      evaluated = { pub, inserted: [], deduped: 0 };
    } else {
      evaluated = await evaluateMatches(req, got.result);
      if (evaluated.degraded) return { status: 503, body: evaluated.degraded };
      await metricsHook(req, { events_generated: evaluated.inserted.length, events_deduped: evaluated.deduped });
    }
    const finalState = evaluated.inserted.length ? await ledger(req, { type: "get" }) : got;
    const events = finalState.result?.events || [];
    const limit = Math.min(50, Math.max(1, Number(req.searchParams?.get?.("limit")) || 20));
    const offset = Math.min(Math.max(0, Number(req.searchParams?.get?.("offset")) || 0), 500);
    const page = events.slice(offset, offset + limit);
    const analytics = analyticsFromEvents(events, req.nowMs);
    const pub = evaluated.pub;
    if (path === "/api/watchdog/matches") {
      const byWatch = {};
      for (const watch of got.result.watches) byWatch[watch.id] = { watch_id: watch.id, name: watch.name, hit_count: 0, hits: [] };
      for (const event of events) {
        if (!byWatch[event.watch_id]) continue;
        byWatch[event.watch_id].hit_count += 1;
        if (byWatch[event.watch_id].hits.length < 20) byWatch[event.watch_id].hits.push(event);
      }
      return { status: 200, body: { product: WATCHDOG_NAME, tier, tenant: req.tenant || null, matches: Object.values(byWatch), inserted: evaluated.inserted.length, analytics, freshness_status: pub.freshness_status, feed_generated_at: pub.feed_generated_at, feed_item_count: pub.feed_item_count } };
    }
    return {
      status: 200,
      body: {
        product: WATCHDOG_NAME,
        tier,
        tenant: req.tenant || null,
        evaluated: !readOnly,
        inserted: evaluated.inserted.length,
        events: page,
        total: events.length,
        limit,
        offset,
        analytics,
        watches_active: got.result.watches.filter((w) => w.enabled !== false).length,
        freshness_status: pub.freshness_status,
        feed_generated_at: pub.feed_generated_at,
        feed_age_seconds: pub.feed_age_seconds,
        freshness_threshold_seconds: pub.freshness_threshold_seconds,
        feed_item_count: pub.feed_item_count,
      },
    };
  }
  return { status: 405, body: { error: "method_not_allowed" } };
}
