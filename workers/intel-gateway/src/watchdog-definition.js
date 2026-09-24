/**
 * CYBER WATCHDOG -- Watch Definition v2 (versioned, schema-audited criteria).
 *
 * v1 watches (no `version`) keep the original matcher in cyber-watchdog.js,
 * byte for byte. A v2 watch accepts only criteria backed by fields the live
 * Sentinel APEX feed actually carries (audit: docs/CYBER_WATCHDOG_P3.md
 * section 15), and every hit cites the feed field it came from.
 *
 * Matching discipline:
 *   - Structured identifiers compare exactly (CVE, ATT&CK id, package id,
 *     source, lens, IOC type) or by whole-token sequence (CISA KEV product).
 *     Never substring: "micro" does not match "Microsoft".
 *   - Keywords are the only free-text criterion, and they match whole-token
 *     phrases in title/description, labelled as text.
 *   - Values are NFKC-normalized, case-folded, and stripped of control and
 *     zero-width characters. A homoglyph is a different character and does
 *     not match.
 *
 * Pure and synchronous: no I/O, no eval, no regex built from customer input.
 */
import { DEFINITION_LIMITS } from "./watchdog-policy.js";
import { epssProbability, kevListed } from "./watchdog-priority.js";

export const DEFINITION_VERSION = 2;
export const SEVERITIES = Object.freeze(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]);
const SEVERITY_RANK = { INFO: 1, LOW: 2, MEDIUM: 3, HIGH: 4, CRITICAL: 5 };
const LENSES = ["cybersecurity", "technology", "security_operations"];
const TOP_LEVEL_KEYS = new Set(["version", "name", "enabled", "logic", "criteria", "id"]);
const LIST_CRITERIA = ["keywords", "cves", "vendors", "products", "packages", "sources", "lenses", "techniques", "ioc_types"];
const SCALAR_CRITERIA = ["severity_min", "cvss_min", "epss_min", "kev"];
export const V2_CRITERIA = Object.freeze([...LIST_CRITERIA, ...SCALAR_CRITERIA]);
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;
const PACKAGE_RE = /^[a-z0-9][a-z0-9._-]{0,15}:[^\s:][^\s]{0,118}$/;
const IOC_TYPE_RE = /^[a-z0-9_]{2,24}$/;
// C0/C1 controls, zero-width and other format characters, bidi overrides.
const INVISIBLE_RE = /[\p{Cc}\p{Cf}]/gu;

// 64-bit FNV-1a as 16 hex chars. Deterministic, dependency-free, sync.
export function fnv64(text) {
  let h1 = 0x811c9dc5;
  let h2 = 0xcbf29ce4;
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    h1 = Math.imul(h1 ^ c, 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ c ^ (h1 >>> 7), 0x01000193) >>> 0;
  }
  return h1.toString(16).padStart(8, "0") + h2.toString(16).padStart(8, "0");
}


/** NFKC, invisible characters removed, case-folded, whitespace collapsed. */
export function normText(value) {
  if (typeof value !== "string") return "";
  return value.normalize("NFKC").replace(INVISIBLE_RE, "").toLowerCase().replace(/\s+/g, " ").trim();
}

/** Unicode-aware word tokens of normText(value). */
export function tokens(value) {
  const t = normText(value);
  return t ? t.split(/[^\p{L}\p{N}]+/u).filter(Boolean) : [];
}

/** True when `needle` occurs as a contiguous whole-token run in `hay`. */
export function containsTokens(hay, needle) {
  if (!needle.length || needle.length > hay.length) return false;
  outer: for (let i = 0; i + needle.length <= hay.length; i += 1) {
    for (let j = 0; j < needle.length; j += 1) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

export function startsWithTokens(hay, needle) {
  if (!needle.length || needle.length > hay.length) return false;
  for (let j = 0; j < needle.length; j += 1) if (hay[j] !== needle[j]) return false;
  return true;
}

/** Package identifiers ("ecosystem:name") present in the item's tags. */
export function packagesOf(item) {
  const out = [];
  for (const t of Array.isArray(item?.tags) ? item.tags : []) {
    if (typeof t !== "string") continue;
    const v = t.trim().toLowerCase();
    if (PACKAGE_RE.test(v)) out.push(v);
    if (out.length >= 20) break;
  }
  return out;
}

export function iocTypesOf(item) {
  const set = new Set();
  for (const t of Array.isArray(item?.ioc_types) ? item.ioc_types : []) if (typeof t === "string") set.add(t.toLowerCase());
  for (const i of Array.isArray(item?.iocs) ? item.iocs : []) if (i && typeof i.type === "string") set.add(i.type.toLowerCase());
  return [...set];
}

function fail(error, message, field) {
  const out = { error, message };
  if (field) out.field = field;
  return out;
}

/**
 * Cleans one customer value. Returns the cleaned string, or null when it is
 * not a string, is empty after cleaning, or exceeds `max`.
 */
export function cleanValue(raw, max) {
  if (typeof raw !== "string") return null;
  const v = raw.normalize("NFKC").replace(INVISIBLE_RE, "").replace(/[<>]/g, "").replace(/\s+/g, " ").trim();
  if (!v || v.length > max) return null;
  return v;
}

function listOf(raw, key, perItem, limits) {
  if (raw == null) return { values: [] };
  if (!Array.isArray(raw)) return fail("invalid_criterion", key + " must be a list.", key);
  if (raw.length > limits.values_per_list) return fail("too_many_values", key + " accepts at most " + limits.values_per_list + " values.", key);
  const out = [];
  const seen = new Set();
  for (const r of raw) {
    const v = perItem(r);
    if (v == null) return fail("invalid_value", "Invalid value in " + key + ".", key);
    const k = typeof v === "string" ? v.toLowerCase() : JSON.stringify(v);
    if (!seen.has(k)) { seen.add(k); out.push(v); }
  }
  return { values: out };
}

function numberIn(raw, key, lo, hi) {
  if (raw == null) return { value: null };
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw < lo || raw > hi) {
    return fail("invalid_threshold", key + " must be a number from " + lo + " to " + hi + ".", key);
  }
  return { value: raw };
}

/**
 * Validates and normalizes a v2 watch definition. Unknown top-level fields
 * (owner, subject, tenant, ...) and unknown criteria are refused, never
 * silently dropped.
 */
export function normalizeDefinitionV2(input, limits = DEFINITION_LIMITS) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return fail("invalid_watch", "Watch definition must be an object.");
  for (const k of Object.keys(input)) {
    if (FORBIDDEN_KEYS.has(k) || !TOP_LEVEL_KEYS.has(k)) return fail("unsupported_field", "Unsupported field: " + String(k).slice(0, 40), String(k).slice(0, 40));
  }
  if (input.version !== DEFINITION_VERSION) return fail("unsupported_version", "version must be 2.");
  const name = cleanValue(input.name, limits.name_max);
  if (!name) return fail("invalid_watch", "Name is required (1 to " + limits.name_max + " characters).", "name");
  if (input.enabled != null && typeof input.enabled !== "boolean") return fail("invalid_watch", "enabled must be true or false.", "enabled");
  const logic = input.logic == null ? "AND" : input.logic;
  if (logic !== "AND" && logic !== "OR") return fail("unsupported_operator", "logic must be AND or OR.", "logic");
  const c = input.criteria;
  if (!c || typeof c !== "object" || Array.isArray(c)) return fail("invalid_watch", "criteria must be an object.", "criteria");
  for (const k of Object.keys(c)) {
    if (FORBIDDEN_KEYS.has(k) || !V2_CRITERIA.includes(k)) return fail("unsupported_criterion", "Unsupported watch criterion: " + String(k).slice(0, 40), String(k).slice(0, 40));
  }
  const criteria = {};
  const lists = {
    keywords: (r) => { const v = cleanValue(r, limits.term_max); return v && tokens(v).length ? v : null; },
    cves: (r) => { const v = typeof r === "string" ? r.trim().toUpperCase() : ""; return CVE_RE.test(v) ? v : null; },
    vendors: (r) => { const v = cleanValue(r, limits.term_max); return v && tokens(v).length ? v : null; },
    products: (r) => { const v = cleanValue(r, limits.term_max); return v && tokens(v).length ? v : null; },
    packages: (r) => { const v = typeof r === "string" ? r.trim().toLowerCase() : ""; return v.length <= limits.package_max && PACKAGE_RE.test(v) ? v : null; },
    sources: (r) => cleanValue(r, 80),
    lenses: (r) => (LENSES.includes(r) ? r : null),
    techniques: (r) => { const v = typeof r === "string" ? r.trim().toUpperCase() : ""; return TECHNIQUE_RE.test(v) ? v : null; },
    ioc_types: (r) => { const v = typeof r === "string" ? r.trim().toLowerCase() : ""; return IOC_TYPE_RE.test(v) ? v : null; },
  };
  let total = 0;
  for (const key of LIST_CRITERIA) {
    const got = listOf(c[key], key, lists[key], limits);
    if (got.error) return got;
    if (got.values.length) { criteria[key] = got.values; total += got.values.length; }
  }
  if (total > limits.total_values) return fail("too_many_values", "A watch accepts at most " + limits.total_values + " values in total.");
  if (c.severity_min != null) {
    const s = typeof c.severity_min === "string" ? c.severity_min.trim().toUpperCase() : "";
    if (!SEVERITY_RANK[s]) return fail("invalid_severity", "severity_min must be one of " + SEVERITIES.join(", ") + ".", "severity_min");
    criteria.severity_min = s;
  }
  const cvss = numberIn(c.cvss_min, "cvss_min", 0, 10);
  if (cvss.error) return cvss;
  if (cvss.value != null) criteria.cvss_min = cvss.value;
  const epss = numberIn(c.epss_min, "epss_min", 0, 1);
  if (epss.error) return epss;
  if (epss.value != null) criteria.epss_min = epss.value;
  if (c.kev != null) {
    if (typeof c.kev !== "boolean") return fail("invalid_criterion", "kev must be true, false or null.", "kev");
    criteria.kev = c.kev;
  }
  if (!Object.keys(criteria).length) return fail("invalid_watch", "Provide at least one criterion.");
  return { definition: { version: DEFINITION_VERSION, name, enabled: input.enabled !== false, logic, criteria } };
}

const LABELS = {
  keywords: (v) => "Advisory text mentions \"" + v + "\"",
  cves: (v) => "CVE is " + v,
  vendors: (v) => "CISA KEV vendor is " + v,
  products: (v) => "CISA KEV product includes " + v,
  packages: (v) => "Affected package is " + v,
  sources: (v) => "Source is " + v,
  lenses: (v) => "Watchdog lens is " + v,
  techniques: (v) => "MITRE ATT&CK technique is " + v,
  ioc_types: (v) => "Indicator type is " + v,
};

/** Human-readable rule, one line per criterion, joined by the logic word. */
export function ruleLines(def) {
  const c = (def && def.criteria) || {};
  const lines = [];
  for (const key of LIST_CRITERIA) {
    if (!c[key] || !c[key].length) continue;
    const parts = c[key].map(LABELS[key]);
    lines.push(parts.length > 1 ? "(" + parts.join(" OR ") + ")" : parts[0]);
  }
  if (c.severity_min) lines.push("Severity is " + c.severity_min + " or higher");
  if (c.cvss_min != null) lines.push("CVSS is " + c.cvss_min + " or higher");
  if (c.epss_min != null) lines.push("EPSS is " + Math.round(c.epss_min * 10000) / 100 + "% or higher");
  if (c.kev === true) lines.push("CISA KEV listed = YES");
  if (c.kev === false) lines.push("CISA KEV listed = NO");
  return { logic: def && def.logic === "OR" ? "OR" : "AND", lines };
}

function sevOf(item) {
  const s = typeof item?.severity === "string" ? item.severity.trim().toUpperCase() : "";
  return SEVERITY_RANK[s] ? s : null;
}

function num(v) {
  if (v === null || v === undefined || v === "" || typeof v === "boolean") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * Evaluates a v2 definition. `ctx` carries values the caller already derives
 * with the platform's single implementations: { lenses, cves }.
 * Returns { matched, hits: [{criterion, value, feed_field, feed_value}] }.
 */
export function matchDefinitionV2(def, item, ctx = {}) {
  const c = (def && def.criteria) || {};
  const hits = [];
  const checks = [];
  const check = (criterion, hit) => { checks.push(!!hit); if (hit) hits.push({ criterion, ...hit }); };
  const textTokens = () => tokens([item.title, item.name, item.description, item.summary].filter((v) => typeof v === "string").join(" "));
  let tt = null;
  if (c.keywords) {
    tt = tt || textTokens();
    const k = c.keywords.find((v) => containsTokens(tt, tokens(v)));
    check("keywords", k && { value: k, feed_field: "title/description", feed_value: "text mention" });
  }
  if (c.cves) {
    const have = ctx.cves || [];
    const v = c.cves.find((x) => have.includes(x));
    check("cves", v && { value: v, feed_field: "cve_ids", feed_value: v });
  }
  const kevProduct = typeof item.kev_product === "string" ? item.kev_product : "";
  if (c.vendors) {
    const kp = tokens(kevProduct);
    const v = c.vendors.find((x) => startsWithTokens(kp, tokens(x)));
    check("vendors", v && { value: v, feed_field: "kev_product", feed_value: kevProduct.slice(0, 120) });
  }
  if (c.products) {
    const kp = tokens(kevProduct);
    const v = c.products.find((x) => containsTokens(kp, tokens(x)));
    check("products", v && { value: v, feed_field: "kev_product", feed_value: kevProduct.slice(0, 120) });
  }
  if (c.packages) {
    const have = packagesOf(item);
    const v = c.packages.find((x) => have.includes(x));
    check("packages", v && { value: v, feed_field: "tags", feed_value: v });
  }
  if (c.sources) {
    const src = normText(item.source);
    const v = c.sources.find((x) => normText(x) === src);
    check("sources", v && { value: v, feed_field: "source", feed_value: String(item.source).slice(0, 80) });
  }
  if (c.lenses) {
    const have = ctx.lenses || [];
    const v = c.lenses.find((x) => have.includes(x));
    check("lenses", v && { value: v, feed_field: "lens (classifier)", feed_value: v });
  }
  if (c.techniques) {
    const have = (Array.isArray(item.attck_technique_ids) ? item.attck_technique_ids : []).map((t) => String(t).toUpperCase());
    const v = c.techniques.find((x) => have.includes(x));
    check("techniques", v && { value: v, feed_field: "attck_technique_ids", feed_value: v });
  }
  if (c.ioc_types) {
    const have = iocTypesOf(item);
    const v = c.ioc_types.find((x) => have.includes(x));
    check("ioc_types", v && { value: v, feed_field: "ioc_types", feed_value: v });
  }
  if (c.severity_min) {
    const s = sevOf(item);
    check("severity_min", s && SEVERITY_RANK[s] >= SEVERITY_RANK[c.severity_min] && { value: c.severity_min, feed_field: "severity", feed_value: s });
  }
  if (c.cvss_min != null) {
    const v = num(item.cvss_score);
    check("cvss_min", v != null && v >= 0 && v <= 10 && v >= c.cvss_min && { value: c.cvss_min, feed_field: "cvss_score", feed_value: v });
  }
  if (c.epss_min != null) {
    const p = epssProbability(item);
    check("epss_min", p != null && p >= c.epss_min && { value: c.epss_min, feed_field: "epss_score", feed_value: num(item.epss_score) });
  }
  if (c.kev != null) {
    const k = kevListed(item);
    check("kev", k === c.kev && { value: c.kev, feed_field: "kev", feed_value: k });
  }
  if (!checks.length) return { matched: false, hits: [] };
  const matched = def.logic === "OR" ? checks.some(Boolean) : checks.every(Boolean);
  return { matched, hits: matched ? hits : [] };
}
