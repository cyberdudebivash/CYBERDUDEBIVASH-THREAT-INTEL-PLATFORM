/**
 * CYBER WATCHDOG -- Exposure Profile v1, Customer Relevance, Queue Rank and
 * the per-event Evidence Snapshot.
 *
 * Three concepts, kept separate on purpose:
 *
 *   THREAT PRIORITY (watchdog-priority.js) -- how urgent the intelligence is,
 *     from the feed's own evidence. Never changed by anything here.
 *   CUSTOMER RELEVANCE (this file) -- whether the intelligence matches
 *     technology the customer DECLARED in its exposure profile. A declared-
 *     technology match means only "this intelligence matches technology in
 *     your configured exposure profile". It is not a scan, not asset
 *     discovery and not vulnerability validation.
 *   QUEUE RANK (this file) -- where the event sits in this customer's triage
 *     queue. Combines the two above and is labelled "customer priority",
 *     never severity, CVSS or risk.
 *
 * Structured relevance compares exact identifiers only: the CISA KEV product
 * string (whole-token match) and package identifiers from the feed's tags.
 * A name found only in advisory text is a separate, weaker level
 * (MENTIONED). Nothing is inferred fuzzily.
 */
import { PROFILE_LIMITS } from "./watchdog-policy.js";
import {
  cleanValue, containsTokens, fnv64, normText, packagesOf, startsWithTokens, tokens,
} from "./watchdog-definition.js";
import { kevListed } from "./watchdog-priority.js";

export const PROFILE_VERSION = 1;
export const RELEVANCE_VERSION = "watchdog-relevance-1";
export const QUEUE_RANK_VERSION = "watchdog-queue-rank-1";
export const SNAPSHOT_VERSION = 1;
export const RELEVANCE_LEVELS = Object.freeze(["MATCHED", "MENTIONED", "NOT_MATCHED", "NO_PROFILE"]);

// Customer-facing labels. Wording tests forbid any vulnerability,
// compromise or confirmed-exposure claim.
export const RELEVANCE_LABELS = Object.freeze({
  MATCHED: "Matches your exposure profile",
  MENTIONED: "Mentioned in advisory text",
  NOT_MATCHED: "No exposure-profile match",
  NO_PROFILE: "No exposure profile configured",
  LEGACY: "Recorded before relevance",
});

const PROFILE_KEYS = ["vendors", "products", "packages", "technologies"];
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const PACKAGE_RE = /^[a-z0-9][a-z0-9._-]{0,15}:[^\s:][^\s]{0,118}$/;

function fail(error, message, field) {
  const out = { error, message };
  if (field) out.field = field;
  return out;
}

/**
 * Validates a customer-declared exposure profile. Owner, tenant and subject
 * are never read from the body: any key other than version + the four lists
 * is refused.
 */
export function normalizeProfile(input, limits = PROFILE_LIMITS) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return fail("invalid_profile", "Exposure profile must be an object.");
  for (const k of Object.keys(input)) {
    if (FORBIDDEN_KEYS.has(k) || (k !== "version" && !PROFILE_KEYS.includes(k))) {
      return fail("unsupported_field", "Unsupported field: " + String(k).slice(0, 40), String(k).slice(0, 40));
    }
  }
  if (input.version != null && input.version !== PROFILE_VERSION) return fail("unsupported_version", "version must be 1.");
  const profile = { version: PROFILE_VERSION };
  let total = 0;
  for (const key of PROFILE_KEYS) {
    const raw = input[key];
    if (raw == null) { profile[key] = []; continue; }
    if (!Array.isArray(raw)) return fail("invalid_profile", key + " must be a list.", key);
    if (raw.length > limits.values_per_list) return fail("too_many_values", key + " accepts at most " + limits.values_per_list + " values.", key);
    const seen = new Set();
    const out = [];
    for (const r of raw) {
      let v;
      if (key === "packages") {
        v = typeof r === "string" ? r.trim().toLowerCase() : "";
        if (v.length > limits.package_max || !PACKAGE_RE.test(v)) v = null;
      } else {
        v = cleanValue(r, limits.term_max);
        if (v && !tokens(v).length) v = null;
      }
      if (!v) return fail("invalid_value", "Invalid value in " + key + ".", key);
      const k = normText(v);
      if (!seen.has(k)) { seen.add(k); out.push(v); }
    }
    profile[key] = out;
    total += out.length;
  }
  if (total > limits.total_values) return fail("too_many_values", "An exposure profile accepts at most " + limits.total_values + " values in total.");
  if (!total) return fail("invalid_profile", "Declare at least one vendor, product, package or technology.");
  return { profile };
}

/** Stable reference to the profile content an event was evaluated against. */
export function profileRef(profile) {
  if (!profile) return null;
  return "p" + (profile.revision || 0) + ":" + fnv64(JSON.stringify(PROFILE_KEYS.map((k) => (profile[k] || []).map(normText))));
}

export function profileHasValues(profile) {
  return !!profile && PROFILE_KEYS.some((k) => Array.isArray(profile[k]) && profile[k].length);
}

/**
 * Customer relevance of one projected feed item against a declared profile.
 * Reasons cite the profile value and the feed field it matched.
 */
export function computeRelevance(item, profile) {
  const out = (level, reasons) => ({ version: RELEVANCE_VERSION, level, matched: level === "MATCHED", reasons: reasons.slice(0, 10) });
  if (!profileHasValues(profile)) return out("NO_PROFILE", []);
  const src = item && typeof item === "object" ? item : {};
  const structured = [];
  const text = [];
  const kevProduct = typeof src.kev_product === "string" ? src.kev_product : "";
  const kp = tokens(kevProduct);
  for (const v of profile.vendors || []) {
    if (startsWithTokens(kp, tokens(v))) structured.push({ type: "vendor", basis: "identifier", profile_value: v, feed_field: "kev_product", feed_value: kevProduct.slice(0, 120) });
  }
  for (const v of profile.products || []) {
    if (containsTokens(kp, tokens(v))) structured.push({ type: "product", basis: "identifier", profile_value: v, feed_field: "kev_product", feed_value: kevProduct.slice(0, 120) });
  }
  const pk = packagesOf(src);
  for (const v of profile.packages || []) {
    if (pk.includes(v)) structured.push({ type: "package", basis: "identifier", profile_value: v, feed_field: "tags", feed_value: v });
  }
  const tt = tokens([src.title, src.name, src.description, src.summary].filter((v) => typeof v === "string").join(" "));
  const matchedValues = new Set(structured.map((r) => normText(r.profile_value)));
  for (const key of ["vendors", "products", "technologies"]) {
    for (const v of profile[key] || []) {
      if (matchedValues.has(normText(v))) continue;
      if (containsTokens(tt, tokens(v))) text.push({ type: key === "technologies" ? "technology" : key.slice(0, -1), basis: "text_mention", profile_value: v, feed_field: "title/description", feed_value: "text mention" });
    }
  }
  if (structured.length) return out("MATCHED", structured.concat(text));
  if (text.length) return out("MENTIONED", text);
  return out("NOT_MATCHED", []);
}

const BAND_RANK = { INSUFFICIENT_EVIDENCE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const RELEVANCE_BONUS = { MATCHED: 15, MENTIONED: 5, NOT_MATCHED: 0, NO_PROFILE: 0 };

/**
 * Customer queue rank (watchdog-queue-rank-1). score = 10 x threat band
 * rank + relevance bonus (MATCHED 15, MENTIONED 5). Resulting order:
 *   profile-matched CRITICAL (55) > profile-matched HIGH (45)
 *   = text-mentioned CRITICAL (45) > CRITICAL (40) > profile-matched MEDIUM (35)
 *   = text-mentioned HIGH (35) > HIGH (30) > ...
 * Ties: threat score, then newest first. The threat band itself is never
 * changed; this is only the order of this customer's queue.
 */
export function computeQueueRank(priority, relevance) {
  const band = priority && BAND_RANK[priority.band] != null ? priority.band : "INSUFFICIENT_EVIDENCE";
  const level = relevance && RELEVANCE_BONUS[relevance.level] != null ? relevance.level : "NO_PROFILE";
  return { version: QUEUE_RANK_VERSION, score: BAND_RANK[band] * 10 + RELEVANCE_BONUS[level], basis: { priority_band: band, relevance_level: level } };
}

function s(v, max) { return typeof v === "string" ? v.slice(0, max) : null; }
function n(v) { const x = v === null || v === undefined || v === "" || typeof v === "boolean" ? NaN : Number(v); return Number.isFinite(x) ? x : null; }

/**
 * Bounded evidence snapshot stored on a new event: enough to reproduce why it
 * was created and ranked, without storing the advisory. Worst case is
 * asserted in tests (SNAPSHOT_MAX_BYTES).
 */
export const SNAPSHOT_MAX_BYTES = 4096;
export function buildEvidenceSnapshot({ item, revision, feedGeneratedAt, watch, watchHits, priorityVersion, relevance, queueRank, profile, classifierVersion }) {
  const src = item || {};
  return {
    v: SNAPSHOT_VERSION,
    item: {
      id: s(String(src.id || ""), 128),
      revision: s(revision, 24),
      source: s(src.source, 80),
      severity: s(src.severity, 16),
      cvss: n(src.cvss_score),
      epss_percent: n(src.epss_score),
      kev: kevListed(src),
      kev_product: s(src.kev_product, 120),
      packages: packagesOf(src).slice(0, 3).map((p) => p.slice(0, 120)),
      cves: (Array.isArray(src.cve_ids) ? src.cve_ids : []).filter((c) => typeof c === "string").slice(0, 12).map((c) => c.slice(0, 24)),
    },
    feed_generated_at: s(feedGeneratedAt, 40),
    watch: {
      id: s(watch.id, 40),
      definition_version: watch.version === 2 ? 2 : 1,
      logic: watch.logic === "OR" ? "OR" : "AND",
      hits: (watchHits || []).slice(0, 8).map((h) => (typeof h === "string"
        ? { criterion: h.slice(0, 24) }
        : { criterion: s(h.criterion, 24), value: typeof h.value === "string" ? h.value.slice(0, 48) : h.value, feed_field: s(h.feed_field, 32), feed_value: typeof h.feed_value === "string" ? h.feed_value.slice(0, 48) : h.feed_value })),
    },
    profile: profileHasValues(profile)
      ? { version: profile.version || PROFILE_VERSION, ref: profileRef(profile), hits: (relevance?.reasons || []).slice(0, 6).map((r) => ({ type: s(r.type, 16), basis: s(r.basis, 16), profile_value: s(r.profile_value, 48), feed_field: s(r.feed_field, 32) })) }
      : null,
    versions: {
      watch_definition: watch.version === 2 ? 2 : 1,
      priority: s(priorityVersion, 32),
      relevance: relevance ? relevance.version : null,
      queue_rank: queueRank ? queueRank.version : null,
      classifier: s(classifierVersion, 32),
    },
  };
}
