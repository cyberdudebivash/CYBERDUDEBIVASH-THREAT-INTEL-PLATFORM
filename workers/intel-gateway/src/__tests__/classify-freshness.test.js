import assert from "node:assert/strict";
import { test } from "node:test";
import { classifyFreshness } from "../index.js";

// ---------------------------------------------------------------------------
// P0 fix: /api/health's `status: "ok"` has only ever meant "the gateway
// answered a request" -- confirmed live during the 2026-08-26 core-feed
// staleness incident, status:"ok" coexisted with a stats.last_sync roughly
// one week old (production /api/health showed
// last_sync:"2026-08-26T08:50:13Z" while generated_at, the response's own
// timestamp, was 2026-09-02). classifyFreshness() gives /api/health an
// independent freshness signal, so PLATFORM_REACHABLE and DATA_FRESHNESS
// can never be silently conflated into one status field again.
//
// CodeRabbit review finding on this migration (verified and fixed, not
// this test file's concern but noted for context): the handler originally
// passed stats.last_sync (the MAX published/published_at across feed items
// -- source article recency, not sync recency) into classifyFreshness().
// That's a different signal from "when did this platform last successfully
// ingest" -- a broken pipeline whose last successful ingest happened to
// include recently-published source articles would have reported FRESH,
// masking exactly the class of incident this field exists to catch. Fixed
// by passing feedData.generated_at (the pipeline's own "when I last wrote
// this file" timestamp) instead. classifyFreshness() itself is a pure
// function of whatever ISO timestamp it's given, so this test file's own
// coverage is unaffected by which field the caller passes in.
//
// Thresholds match this platform's own known ingestion cadence
// (multi-source-intel.yml + sentinel-apex.yml both run roughly every 4h):
// FRESH < 6h (tolerates one missed cycle), RECENT < 24h, AGING < 72h,
// STALE >= 72h.
// ---------------------------------------------------------------------------

function hoursAgoIso(hours) {
  return new Date(Date.now() - hours * 3600 * 1000).toISOString();
}

test("classifyFreshness: 'N/A' (computeStats' own empty-corpus sentinel) is UNAVAILABLE, not FRESH/STALE", () => {
  const r = classifyFreshness("N/A");
  assert.equal(r.state, "UNAVAILABLE");
  assert.equal(r.age_seconds, null);
});

test("classifyFreshness: empty string is UNAVAILABLE", () => {
  const r = classifyFreshness("");
  assert.equal(r.state, "UNAVAILABLE");
  assert.equal(r.age_seconds, null);
});

test("classifyFreshness: unparseable timestamp is UNAVAILABLE, not silently treated as epoch/now", () => {
  const r = classifyFreshness("not-a-real-date");
  assert.equal(r.state, "UNAVAILABLE");
  assert.equal(r.age_seconds, null);
});

test("classifyFreshness: just now / 2h ago is FRESH", () => {
  assert.equal(classifyFreshness(new Date().toISOString()).state, "FRESH");
  assert.equal(classifyFreshness(hoursAgoIso(2)).state, "FRESH");
});

test("classifyFreshness: boundary just under 6h is FRESH, just over is RECENT", () => {
  assert.equal(classifyFreshness(hoursAgoIso(5.9)).state, "FRESH");
  assert.equal(classifyFreshness(hoursAgoIso(6.1)).state, "RECENT");
});

test("classifyFreshness: CodeRabbit review finding -- sub-second age just under a threshold must not round up across it", () => {
  // An actual elapsed age of 21599.6s (5h59m59.6s) is genuinely < 21600s
  // (6h) and must classify FRESH. Math.round(21599.6) = 21600, which used
  // to fail the "< 6h" check and wrongly return RECENT; Math.floor keeps it
  // on the correct side of the boundary. Same class of off-by-a-rounding
  // bug would apply at the 24h/72h boundaries too, but they share the same
  // fix (one Math.floor call for all three thresholds), so this one case
  // is sufficient to pin the fix rather than repeating it three times.
  const ts = new Date(Date.now() - 21599600).toISOString();
  const r = classifyFreshness(ts);
  assert.equal(r.state, "FRESH");
});

test("classifyFreshness: 12h ago is RECENT", () => {
  assert.equal(classifyFreshness(hoursAgoIso(12)).state, "RECENT");
});

test("classifyFreshness: boundary just under 24h is RECENT, just over is AGING", () => {
  assert.equal(classifyFreshness(hoursAgoIso(23.9)).state, "RECENT");
  assert.equal(classifyFreshness(hoursAgoIso(24.1)).state, "AGING");
});

test("classifyFreshness: 48h ago is AGING", () => {
  assert.equal(classifyFreshness(hoursAgoIso(48)).state, "AGING");
});

test("classifyFreshness: boundary just under 72h is AGING, just over is STALE", () => {
  assert.equal(classifyFreshness(hoursAgoIso(71.9)).state, "AGING");
  assert.equal(classifyFreshness(hoursAgoIso(72.1)).state, "STALE");
});

test("classifyFreshness: the actual incident case (~8 days stale) is STALE", () => {
  const r = classifyFreshness(hoursAgoIso(8 * 24));
  assert.equal(r.state, "STALE");
  assert.ok(r.age_seconds > 7 * 24 * 3600);
});

test("classifyFreshness: age_seconds is never negative even for a clock-skewed future timestamp", () => {
  const future = new Date(Date.now() + 3600 * 1000).toISOString();
  const r = classifyFreshness(future);
  assert.equal(r.age_seconds, 0);
});
