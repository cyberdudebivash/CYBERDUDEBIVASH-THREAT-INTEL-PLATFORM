/**
 * freshness-contract.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX -- customer-visible freshness contract (Worker side)
 * ==============================================================================
 * JS mirror of scripts/public_freshness_contract.py. Canonical values live in
 * config/public_freshness_contract.json; this repo's Worker bundler cannot
 * import JSON on both of its toolchains (see pricing.js / pricing-data.js for
 * the same constraint), so the values are mirrored here and
 * tests/test_public_freshness_contract.py fails on any drift -- constants,
 * the generated_at pattern, AND every shared vector in
 * config/public_freshness_contract_vectors.json are checked against both
 * implementations.
 *
 * Why this exists (P0, 2026-09-24): /api/health returned HTTP 200
 * {"status":"ok"} while every customer feed endpoint served a manifest
 * generated 2026-08-26 -- four weeks stale. Its freshness classification was
 * only shown to authenticated callers, used its own 6h/24h/72h thresholds
 * (independent of PR #485's MAX_PUBLIC_MANIFEST_AGE_HOURS), treated an R2
 * read failure as generated_at=now (FRESH), and clamped far-future
 * timestamps to age 0 (FRESH).
 *
 * Dependency-free on purpose (same reason as intel-static-proxy.js): node
 * --test can load it without index.js's full import chain.
 */

export const MAX_PUBLIC_MANIFEST_AGE_HOURS = 6;
export const MAX_FUTURE_SKEW_HOURS = 3;
export const GENERATED_AT_PATTERN =
  "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?(Z|[+-]\\d{2}:\\d{2})$";

const GENERATED_AT_RE = new RegExp(GENERATED_AT_PATTERN);
const PARTS_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/;

export const STATES = Object.freeze({
  FRESH: "fresh",
  STALE: "stale",
  FUTURE: "future_timestamp",
  MISSING: "missing_timestamp",
  INVALID: "invalid_timestamp",
});

/**
 * Strict ISO-8601 with explicit offset -> epoch ms, or null. Every calendar
 * component is range-checked instead of trusting Date.parse, which silently
 * rolls "2026-02-30" over to March 2 and accepts hour 24 (Python rejects
 * both; the shared vectors pin this).
 */
export function parseGeneratedAt(raw) {
  if (typeof raw !== "string" || !GENERATED_AT_RE.test(raw)) return null;
  const m = PARTS_RE.exec(raw);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 59 || d < 1) return null;
  const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  if (d > daysInMonth) return null;
  const ms = m[7] ? Number((m[7] + "00").slice(0, 3)) : 0;
  let offsetMin = 0;
  if (m[8] !== "Z") {
    const oh = Number(m[10]);
    const om = Number(m[11]);
    if (oh > 23 || om > 59) return null;
    offsetMin = (m[9] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  return Date.UTC(y, mo - 1, d, h, mi, s, ms) - offsetMin * 60000;
}

/**
 * Same semantics as public_freshness_contract.classify_manifest_freshness():
 * inclusive boundary (age == max is fresh), comparison on exact elapsed
 * time, age_seconds = floor(age) clamped to 0 inside the skew allowance.
 */
export function classifyManifestFreshness(raw, nowMs = Date.now(), maxAgeHours = MAX_PUBLIC_MANIFEST_AGE_HOURS) {
  const maxAgeSeconds = Math.round(maxAgeHours * 3600);
  if (raw === null || raw === undefined || (typeof raw === "string" && raw.trim() === "")) {
    return { state: STATES.MISSING, age_seconds: null, max_age_seconds: maxAgeSeconds };
  }
  const ts = parseGeneratedAt(raw);
  if (ts === null) {
    return { state: STATES.INVALID, age_seconds: null, max_age_seconds: maxAgeSeconds };
  }
  const ageMs = nowMs - ts;
  if (ageMs < -(MAX_FUTURE_SKEW_HOURS * 3600 * 1000)) {
    return { state: STATES.FUTURE, age_seconds: null, max_age_seconds: maxAgeSeconds };
  }
  const ageSeconds = Math.max(0, Math.floor(ageMs / 1000));
  const state = ageMs <= maxAgeHours * 3600 * 1000 ? STATES.FRESH : STATES.STALE;
  return { state, age_seconds: ageSeconds, max_age_seconds: maxAgeSeconds };
}

const REASON_BY_STATE = {
  [STATES.STALE]: "intelligence_stale",
  [STATES.FUTURE]: "generated_at_in_future",
  [STATES.MISSING]: "generated_at_missing",
  [STATES.INVALID]: "generated_at_invalid",
};

/**
 * Evaluates the authoritative customer feed object exactly as read from
 * storage (null = missing or unreadable). Never substitutes a fallback
 * timestamp: absence of evidence is reported as absence, not freshness.
 *
 * Returns { healthy, status, http_status, reason, intelligence, checks }:
 *   status "ok"        -> 200, every mandatory condition holds
 *   status "degraded"  -> 503, intelligence exists and is valid but stale
 *   status "unhealthy" -> 503, intelligence unavailable/empty/invalid
 */
export function evaluatePublicIntelligence(feedData, nowMs = Date.now()) {
  const base = (status, reason, intelligence, checks) => ({
    healthy: status === "ok",
    status,
    http_status: status === "ok" ? 200 : 503,
    reason,
    intelligence,
    checks: { worker_runtime: "ok", ...checks },
  });

  if (feedData === null || feedData === undefined) {
    return base("unhealthy", "feed_unavailable",
      { status: "unavailable", generated_at: null, age_seconds: null, max_age_seconds: Math.round(MAX_PUBLIC_MANIFEST_AGE_HOURS * 3600), advisory_count: 0 },
      { intelligence_available: "unavailable", intelligence_freshness: "unknown", publication_integrity: "unknown" });
  }
  if (typeof feedData !== "object" || Array.isArray(feedData) || !Array.isArray(feedData.items)) {
    return base("unhealthy", "invalid_feed_structure",
      { status: "invalid", generated_at: null, age_seconds: null, max_age_seconds: Math.round(MAX_PUBLIC_MANIFEST_AGE_HOURS * 3600), advisory_count: 0 },
      { intelligence_available: "invalid", intelligence_freshness: "unknown", publication_integrity: "invalid" });
  }

  const items = feedData.items;
  const validCount = items.filter(
    (i) => i && typeof i === "object" && !Array.isArray(i) && typeof i.id === "string" && i.id.trim() !== "",
  ).length;
  const freshness = classifyManifestFreshness(feedData.generated_at, nowMs);
  const generatedAt = typeof feedData.generated_at === "string" ? feedData.generated_at : null;
  const countOk = typeof feedData.count !== "number" || feedData.count === items.length;
  const intelligence = {
    status: freshness.state,
    generated_at: generatedAt,
    age_seconds: freshness.age_seconds,
    max_age_seconds: freshness.max_age_seconds,
    advisory_count: validCount,
  };
  const checks = {
    intelligence_available: validCount > 0 ? "ok" : "empty",
    intelligence_freshness: freshness.state,
    publication_integrity: countOk ? "ok" : "count_mismatch",
  };

  if (validCount === 0) return base("unhealthy", "no_intelligence_items", intelligence, checks);
  if (!countOk) return base("unhealthy", "publication_count_mismatch", intelligence, checks);
  if (freshness.state === STATES.FRESH) return base("ok", null, intelligence, checks);
  if (freshness.state === STATES.STALE) return base("degraded", REASON_BY_STATE[STATES.STALE], intelligence, checks);
  return base("unhealthy", REASON_BY_STATE[freshness.state], intelligence, checks);
}

/**
 * How long a HEALTHY public response may be edge-cached without outliving
 * the freshness boundary: min(capSeconds, seconds until the feed turns
 * stale). 0 for anything not healthy (never cached anyway: only 200s are).
 */
export function healthEdgeTtlSeconds(evaluation, capSeconds) {
  if (!evaluation || !evaluation.healthy) return 0;
  const { age_seconds: age, max_age_seconds: max } = evaluation.intelligence;
  if (typeof age !== "number" || typeof max !== "number") return 0;
  return Math.max(0, Math.min(capSeconds, max - age));
}
