/**
 * CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG v2
 *
 * Classifies and watches items already on the authoritative Sentinel APEX
 * feed. Does not crawl the internet, does not invent advisories, and does
 * not serve a stale feed as a live brief.
 *
 * Prices are a tested mirror of config/commercial-contract.json.
 * Freshness is evaluatePublicIntelligence() from freshness-contract.js
 * (config/public_freshness_contract.json). No second age threshold.
 *
 * Customer mutations go through WatchdogLedger (one Durable Object per
 * authenticated subject). Anonymous brief/offer/health do not write.
 */

import { evaluatePublicIntelligence } from "./freshness-contract.js";

export const WATCHDOG_NAME = "CYBERDUDEBIVASH SENTINEL APEX CYBER WATCHDOG";
export const WATCHDOG_VERSION = "2.0.0";
export const CLASSIFIER_VERSION = "watchdog-lens-v2";
export const EVENT_RETENTION = 200;
export const DELIVERY_RETENTION = 50;
export const MAX_WEBHOOK_TIMEOUT_MS = 5000;

// Mirror of config/commercial-contract.json. The unit test fails on drift.
export const COMMERCIAL_MIRROR = Object.freeze({
  gstin: "21ARKPN8270G1ZP",
  seller_legal: "BIVASHA KUMAR NAYAK",
  seller_trade_name: "CYBERDUDEBIVASH(R)",
  tiers: Object.freeze({
    FREE: Object.freeze({ usd_monthly: 0, inr_monthly: 0 }),
    PRO: Object.freeze({ usd_monthly: 49, inr_monthly: 4100 }),
    ENTERPRISE: Object.freeze({ usd_monthly: 499, inr_monthly: 41600 }),
    MSSP: Object.freeze({ usd_monthly: 999, inr_monthly: 83300 }),
  }),
});

// Feature quotas are not prices. Prices stay in COMMERCIAL_MIRROR only.
const FEATURES = Object.freeze({
  FREE: Object.freeze({ watches: 0, brief_items: 8, poller: false, webhooks: 0, events: false }),
  PRO: Object.freeze({ watches: 25, brief_items: 50, poller: true, webhooks: 0, events: true }),
  ENTERPRISE: Object.freeze({ watches: 200, brief_items: 200, poller: true, webhooks: 3, events: true }),
  MSSP: Object.freeze({ watches: 200, brief_items: 200, poller: true, webhooks: 5, events: true }),
});

const DENY_STATUS = new Set(["cancelled", "refunded", "suspended", "expired"]);
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
  return { revision: 0, subject: null, watches: [], events: [], destinations: [], deliveries: [] };
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
  const row = COMMERCIAL_MIRROR.tiers[tierId];
  if (!row || row.usd_monthly == null) return "Contract";
  if (row.usd_monthly === 0) return "$0";
  return "$" + row.usd_monthly + "/mo | INR " + groupInr(row.inr_monthly) + "/mo";
}

export function effectiveTier(auth) {
  const status = String(auth?.subscription_status || "").toLowerCase();
  const err = String(auth?.error || "");
  if (DENY_STATUS.has(status) || err === "key_expired" || err.startsWith("subscription_")) return "FREE";
  const tier = String(auth?.tier || "FREE").toUpperCase();
  return FEATURES[tier] ? tier : "FREE";
}

export function quotaForTier(tier) {
  const features = FEATURES[tier] || FEATURES.FREE;
  const price = COMMERCIAL_MIRROR.tiers[tier] || COMMERCIAL_MIRROR.tiers.FREE;
  return {
    ...features,
    paid: features.events,
    price_usd_monthly: price.usd_monthly,
    price_inr_monthly: price.inr_monthly,
  };
}

export function watchdogOffer() {
  const seller = {
    legal_name: COMMERCIAL_MIRROR.seller_legal,
    trade_name: COMMERCIAL_MIRROR.seller_trade_name,
    gstin: COMMERCIAL_MIRROR.gstin,
  };
  const plan = (id, name, checkout, note) => {
    const q = quotaForTier(id);
    const price = COMMERCIAL_MIRROR.tiers[id];
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
      plan("PRO", "Pro Defense", "/upgrade.html?plan=pro&feature=cyber-watchdog", "Existing Pro charge. Included. No second invoice. Hosted watches and the brief poller."),
      plan("ENTERPRISE", "Enterprise SOC", "/upgrade.html?plan=enterprise&feature=cyber-watchdog", "Existing Enterprise charge. Includes HTTPS webhook delivery."),
      plan("MSSP", "MSSP", "/upgrade.html?plan=mssp&feature=cyber-watchdog", "Canonical MSSP list price. Includes webhook delivery. Not a second invoice."),
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
      destinations: "GET|POST|DELETE /api/watchdog/destinations",
      deploy: "GET /api/watchdog/deploy",
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
  let freshness_status = "INVALID";
  if (feed == null) freshness_status = "UNAVAILABLE";
  else if (evaluation.reason === "no_intelligence_items") freshness_status = "EMPTY";
  else if (evaluation.reason === "feed_unavailable") freshness_status = "UNAVAILABLE";
  else if (intel.status === "stale" || evaluation.reason === "intelligence_stale") freshness_status = "STALE";
  else if (evaluation.healthy && intel.status === "fresh") freshness_status = "FRESH";
  else freshness_status = "INVALID";
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

function revisionToken(item) {
  return clean(String(item.processed_at || item.published || item.title || ""), 80);
}

export function candidateEvent(watch, item, feedGeneratedAt, nowIso) {
  const hit = matchWatch(watch, item);
  if (!hit.matched) return null;
  const itemId = clean(String(item.id), 128);
  const dedupe = watch.id + "|" + itemId + "|" + revisionToken(item);
  return {
    id: "e_" + dedupe.replace(/[^a-z0-9|:-]/gi, "").slice(0, 80),
    watch_id: watch.id,
    watch_name: watch.name,
    matched_item_id: itemId,
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
    delivery_status: "pending",
  };
}

function publicWatch(w) {
  return {
    id: w.id, name: w.name, logic: w.logic, enabled: w.enabled !== false,
    criteria: w.criteria, created_at: w.created_at, updated_at: w.updated_at,
  };
}

export function applyLedgerMutation(state, op) {
  const base = state && typeof state === "object" ? state : emptyLedgerState();
  const subject = clean(String(op?.subject || ""), 128);
  if (!subject) return { error: "subject_required", status: 400, state: base };
  if (base.subject && base.subject !== subject) return { error: "tenant_mismatch", status: 403, state: base };
  if (op.type === "get") {
    return { readOnly: true, state: base, result: viewState(base) };
  }
  const next = {
    revision: (base.revision || 0) + 1,
    subject,
    watches: Array.isArray(base.watches) ? base.watches.map((w) => ({ ...w })) : [],
    events: Array.isArray(base.events) ? base.events.slice() : [],
    destinations: Array.isArray(base.destinations) ? base.destinations.slice() : [],
    deliveries: Array.isArray(base.deliveries) ? base.deliveries.slice() : [],
  };
  const quota = quotaForTier(op.tier || "FREE");
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
      created_at: op.now, updated_at: op.now,
    };
    if (!watch.id || watch.id === "w_") return { error: "invalid_watch", status: 400, state: base };
    next.watches.push(watch);
    return { state: next, result: { watch: publicWatch(watch), count: next.watches.length, limit: quota.watches } };
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
      updated_at: op.now,
    };
    return { state: next, result: { watch: publicWatch(next.watches[idx]) } };
  }
  if (op.type === "delete_watch") {
    const id = clean(String(op.id || ""), 40);
    const kept = next.watches.filter((w) => w.id !== id);
    if (kept.length === next.watches.length) return { error: "not_found", status: 404, state: base };
    next.watches = kept;
    return { state: next, result: { deleted: id, count: kept.length } };
  }
  if (op.type === "append_events") {
    if (!quota.events) return { error: "tier_required", status: 403, state: base };
    const existing = new Set(next.events.map((e) => e.dedupe_key));
    const inserted = [];
    for (const event of op.events || []) {
      if (!event?.dedupe_key || existing.has(event.dedupe_key)) continue;
      existing.add(event.dedupe_key);
      inserted.push(event);
    }
    next.events = inserted.concat(next.events).slice(0, EVENT_RETENTION);
    return { state: next, result: { inserted, inserted_count: inserted.length } };
  }
  if (op.type === "ack") {
    const ids = new Set(asList(op.ids, 50, 96, (v) => clean(String(v), 96)));
    let n = 0;
    next.events = next.events.map((e) => {
      if (!ids.has(e.id) || e.acknowledged) return e;
      n += 1;
      return { ...e, acknowledged: true, acknowledged_at: op.now };
    });
    return { state: next, result: { acknowledged: n } };
  }
  if (op.type === "set_destination") {
    if (!quota.webhooks) return { error: "tier_required", status: 403, state: base, message: "HTTPS webhook delivery is included with Enterprise SOC or MSSP." };
    const dest = normalizeDestination(op.destination);
    if (dest.error) return { ...dest, status: 400, state: base };
    if (next.destinations.length >= quota.webhooks) return { error: "webhook_limit", status: 403, state: base, limit: quota.webhooks };
    next.destinations.push({ id: "d_" + clean(String(op.id || ""), 24), url: dest.url, created_at: op.now });
    return { state: next, result: { destination: next.destinations[next.destinations.length - 1], count: next.destinations.length } };
  }
  if (op.type === "delete_destination") {
    const id = clean(String(op.id || ""), 40);
    const kept = next.destinations.filter((d) => d.id !== id);
    if (kept.length === next.destinations.length) return { error: "not_found", status: 404, state: base };
    next.destinations = kept;
    return { state: next, result: { deleted: id, count: kept.length } };
  }
  if (op.type === "record_delivery") {
    next.deliveries = [{ ...op.delivery, at: op.now }].concat(next.deliveries).slice(0, DELIVERY_RETENTION);
    const id = op.delivery?.event_id;
    next.events = next.events.map((e) => e.id === id ? { ...e, delivery_status: op.delivery.status } : e);
    return { state: next, result: { recorded: true } };
  }
  return { error: "unsupported_op", status: 400, state: base };
}

function viewState(state) {
  return {
    revision: state.revision || 0,
    watches: (state.watches || []).map(publicWatch),
    events: state.events || [],
    destinations: state.destinations || [],
    deliveries: state.deliveries || [],
  };
}

const BLOCKED_HOSTS = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|metadata\.google\.internal)$/i;

function ipv4Private(parts) {
  const [a, b] = parts;
  return a === 10 || a === 127 || a === 0 || a >= 224
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168);
}

function blockedHost(hostname) {
  const host = String(hostname || "").replace(/^\[|\]$/g, "").toLowerCase();
  if (!host || BLOCKED_HOSTS.test(host) || host.endsWith(".local") || host.endsWith(".internal")) return true;
  if (/^\d+$/.test(host)) return true;
  const v4 = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) return ipv4Private(v4.slice(1).map(Number));
  if (!host.includes(":")) return false;
  if (host === "::" || host === "::1" || host.startsWith("::ffff:")) return true;
  const first = host.split(":").find(Boolean) || "";
  if (/^f[cd]/.test(first) || /^fe[89ab]/.test(first) || /^ff/.test(first)) return true;
  const hextet = Number.parseInt(first, 16);
  if (!Number.isFinite(hextet)) return true;
  return hextet < 0x2000 || hextet > 0x3fff;
}

export function normalizeDestination(input) {
  let url;
  try { url = new URL(String(input?.url || "")); } catch { return { error: "invalid_destination", message: "Webhook URL must be https." }; }
  if (url.protocol !== "https:") return { error: "invalid_destination", message: "Webhook URL must be https." };
  if (url.username || url.password) return { error: "invalid_destination", message: "Webhook URL must not contain credentials." };
  if (blockedHost(url.hostname)) return { error: "invalid_destination", message: "Webhook host is not allowed." };
  return { url: url.origin + url.pathname };
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
  const deliveries = list.map((e) => e.delivery_status).filter((s) => s && s !== "pending");
  const success = deliveries.filter((s) => s === "delivered").length;
  const failed = deliveries.filter((s) => s === "failed").length;
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
    delivery_success_rate: deliveries.length ? Number((success / deliveries.length).toFixed(4)) : null,
    delivery_failure_rate: deliveries.length ? Number((failed / deliveries.length).toFixed(4)) : null,
    delivery_failures: failed,
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

function paidGuard(auth) {
  const tier = effectiveTier(auth);
  const quota = quotaForTier(tier);
  if (!quota.events || !auth?.sub) {
    return { error: { status: 403, body: { error: "tier_required", message: "This Watchdog capability is included with Pro Defense ($49/mo).", checkout: "/upgrade.html?plan=pro&feature=cyber-watchdog" } } };
  }
  return { tier, quota };
}

async function ledger(req, op) {
  if (!req.ledger || typeof req.ledger.mutate !== "function") {
    return { error: "watch_store_unavailable", status: 503, message: "Watch store is temporarily unavailable. Nothing was saved." };
  }
  return req.ledger.mutate({ ...op, subject: req.auth.sub, tier: effectiveTier(req.auth), now: req.now });
}

function publicFailure(out) {
  const body = { error: out?.error || "watch_store_unavailable" };
  if (out?.message) body.message = out.message;
  if (out?.limit != null) body.limit = out.limit;
  return { status: out?.status || 503, body };
}

export function buildWebhookPayload(event) {
  return {
    product: WATCHDOG_NAME,
    watch_id: event.watch_id,
    watch_name: event.watch_name,
    matched_item_id: event.matched_item_id,
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
}

export async function deliverWebhook(url, payload, fetchImpl = fetch, timeoutMs = MAX_WEBHOOK_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, {
      method: "POST",
      redirect: "manual",
      headers: { "Content-Type": "application/json", "User-Agent": "CYBERDUDEBIVASH-SENTINEL-APEX-CYBER-WATCHDOG/2.0" },
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
  const watches = (record.watches || []).filter((w) => w.enabled !== false);
  const items = validItems(req.feed);
  const candidates = [];
  for (const watch of watches) {
    let n = 0;
    for (const item of items) {
      const event = candidateEvent(watch, item, pub.feed_generated_at, req.now);
      if (event) {
        candidates.push(event);
        n += 1;
      }
      if (n >= 20) break;
    }
  }
  const appended = candidates.length
    ? await ledger(req, { type: "append_events", events: candidates })
    : { result: { inserted: [] } };
  return { pub, inserted: appended.result?.inserted || [], error: appended.error ? appended : null };
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
    seller: COMMERCIAL_MIRROR.seller_trade_name,
    entitlement: "PRO+ reads GET /api/watchdog/brief. The poller is not an Enterprise boundary.",
    runtime: "Node.js 18+",
    poll: {
      endpoint: "https://intel.cyberdudebivash.com/api/watchdog/brief",
      auth_header: "X-API-Key",
      interval_seconds: 900,
      package: "deploy/cyber-watchdog/poll.mjs",
    },
    webhooks: quota.webhooks
      ? { endpoint: "POST /api/watchdog/destinations", limit: quota.webhooks }
      : { endpoint: null, message: "HTTPS delivery is included with Enterprise SOC or MSSP." },
    does_not: [
      "The poller does not scan the internet from the customer host.",
      "It pulls the entitled Sentinel APEX brief and writes it locally only when the brief is FRESH.",
    ],
    included_with: tier,
  };
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
        watch_store: req.ledger ? "ok" : "unavailable",
      },
    };
  }

  if (path === "/api/watchdog/brief") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    const lens = req.searchParams?.get?.("lens") || null;
    const q = req.searchParams?.get?.("q") || "";
    const limit = req.searchParams?.get?.("limit");
    const built = buildWatchdogBrief(req.feed, { tier, lens, q, limit, now, nowMs: req.nowMs, subscription_status: req.auth?.subscription_status, error: req.auth?.error });
    return built;
  }

  if (path === "/api/watchdog/deploy") {
    if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
    const body = deployManifest(tier);
    return { status: body.error ? 403 : 200, body };
  }

  if (path === "/api/watchdog/destinations") {
    const guard = paidGuard(req.auth);
    if (guard.error && method !== "GET") return guard.error;
    const quota = quotaForTier(tier);
    if (!quota.webhooks) {
      return { status: 403, body: { error: "tier_required", message: "HTTPS webhook delivery is included with Enterprise SOC ($499/mo) or MSSP. Pro Defense includes the hosted watch and the brief poller only.", checkout: "/upgrade.html?plan=enterprise&feature=cyber-watchdog" } };
    }
    if (!req.auth?.sub) return { status: 403, body: { error: "tier_required" } };
    if (method === "GET" || method === "HEAD") {
      const got = await ledger(req, { type: "get" });
      if (got.error) return publicFailure(got);
      return { status: 200, body: { destinations: got.result.destinations, limit: quota.webhooks } };
    }
    if (method === "POST") {
      const out = await ledger(req, { type: "set_destination", destination: req.body, id: req.id });
      if (out.error) return publicFailure(out);
      return { status: 201, body: out.result };
    }
    if (method === "DELETE") {
      const out = await ledger(req, { type: "delete_destination", id: req.searchParams?.get?.("id") || req.body?.id });
      if (out.error) return publicFailure(out);
      return { status: 200, body: out.result };
    }
    return { status: 405, body: { error: "method_not_allowed" } };
  }

  if (path === "/api/watchdog/watches" || path === "/api/watchdog/matches" || path === "/api/watchdog/events" || path === "/api/watchdog/events/ack") {
    const guard = paidGuard(req.auth);
    if (guard.error) return guard.error;
    if (path === "/api/watchdog/watches" && (method === "GET" || method === "HEAD")) {
      const got = await ledger(req, { type: "get" });
      if (got.error) return publicFailure(got);
      return { status: 200, body: { watches: got.result.watches, limit: guard.quota.watches, tier } };
    }
    if (path === "/api/watchdog/watches" && method === "POST") {
      const out = await ledger(req, { type: "create_watch", watch: req.body, id: req.id });
      if (out.error) return publicFailure(out);
      return { status: 201, body: out.result };
    }
    if (path === "/api/watchdog/watches" && method === "PATCH") {
      const out = await ledger(req, { type: "update_watch", id: req.searchParams?.get?.("id") || req.body?.id, watch: req.body });
      if (out.error) return publicFailure(out);
      return { status: 200, body: out.result };
    }
    if (path === "/api/watchdog/watches" && method === "DELETE") {
      const out = await ledger(req, { type: "delete_watch", id: req.searchParams?.get?.("id") || req.body?.id });
      if (out.error) return publicFailure(out);
      return { status: 200, body: out.result };
    }
    if (path === "/api/watchdog/events/ack" && method === "POST") {
      const out = await ledger(req, { type: "ack", ids: req.body?.ids || [] });
      if (out.error) return publicFailure(out);
      return { status: 200, body: out.result };
    }
    if (path === "/api/watchdog/matches" || path === "/api/watchdog/events") {
      if (method !== "GET" && method !== "HEAD") return { status: 405, body: { error: "method_not_allowed" } };
      const got = await ledger(req, { type: "get" });
      if (got.error) return publicFailure(got);
      const evaluated = await evaluateMatches(req, got.result);
      if (evaluated.degraded) return { status: 503, body: evaluated.degraded };
      const again = evaluated.inserted.length ? await ledger(req, { type: "get" }) : got;
      const quota = quotaForTier(tier);
      if (quota.webhooks && evaluated.inserted.length && (got.result.destinations || []).length && req.fetchImpl) {
        for (const event of evaluated.inserted) {
          for (const dest of got.result.destinations) {
            const sent = await deliverWebhook(dest.url, buildWebhookPayload(event), req.fetchImpl);
            await ledger(req, { type: "record_delivery", delivery: { event_id: event.id, destination_id: dest.id, status: sent.status, http_status: sent.http_status } });
          }
        }
      }
      const finalState = (quota.webhooks && evaluated.inserted.length) ? await ledger(req, { type: "get" }) : again;
      const events = (finalState.result?.events || again.result?.events || got.result.events || []);
      const limit = Math.min(50, Math.max(1, Number(req.searchParams?.get?.("limit")) || 20));
      const offset = Math.min(Math.max(0, Number(req.searchParams?.get?.("offset")) || 0), 500);
      const page = events.slice(offset, offset + limit);
      const analytics = analyticsFromEvents(events, req.nowMs);
      if (path === "/api/watchdog/matches") {
        const byWatch = {};
        for (const watch of got.result.watches) byWatch[watch.id] = { watch_id: watch.id, name: watch.name, hit_count: 0, hits: [] };
        for (const event of events) {
          if (!byWatch[event.watch_id]) continue;
          byWatch[event.watch_id].hit_count += 1;
          if (byWatch[event.watch_id].hits.length < 20) byWatch[event.watch_id].hits.push(event);
        }
        return { status: 200, body: { product: WATCHDOG_NAME, tier, matches: Object.values(byWatch), inserted: evaluated.inserted.length, analytics, freshness_status: evaluated.pub.freshness_status, feed_generated_at: evaluated.pub.feed_generated_at, feed_item_count: evaluated.pub.feed_item_count } };
      }
      return {
        status: 200,
        body: {
          product: WATCHDOG_NAME,
          tier,
          events: page,
          total: events.length,
          limit,
          offset,
          analytics,
          watches_active: got.result.watches.filter((w) => w.enabled !== false).length,
          freshness_status: evaluated.pub.freshness_status,
          feed_generated_at: evaluated.pub.feed_generated_at,
          feed_age_seconds: evaluated.pub.feed_age_seconds,
          freshness_threshold_seconds: evaluated.pub.freshness_threshold_seconds,
          feed_item_count: evaluated.pub.feed_item_count,
        },
      };
    }
    return { status: 405, body: { error: "method_not_allowed" } };
  }

  return { status: 404, body: { error: "not_found", path } };
}
