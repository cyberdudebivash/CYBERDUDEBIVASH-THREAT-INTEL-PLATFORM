import assert from "node:assert/strict";
import { test } from "node:test";
import CDB_NORMALIZE from "../metric-normalize.js";

// ---------------------------------------------------------------------------
// PR-E1: Metric Semantic Contracts -- canonical EPSS/KEV/priority normalizer.
//
// Root cause under test: the customer-facing "TOP CVE EXPLOIT PROBABILITY
// (EPSS)" widget rendered risk_score (a 0-10 Sentinel composite) formatted to
// 2 decimals under an EPSS-branded label; three severity-downgrade gates
// treated item.kev's legacy string value "NO" as truthy (`!!"NO" === true`);
// and five `window.computePriority(item) || 'P4'`-style call sites silently
// downgraded a genuinely-unknown priority to P4. See
// PHASE0_SEMANTIC_INTEGRITY_REPORT.md for full live-production evidence.
// ---------------------------------------------------------------------------

test("epss(): 0-1 values are already-probability", () => {
  const r = CDB_NORMALIZE.epss(0.42);
  assert.equal(r.state, "OK");
  assert.equal(r.probability, 0.42);
  assert.equal(r.percent, 42);
});

test("epss(): values in (1,100] are treated as an already-percentage reading", () => {
  const r = CDB_NORMALIZE.epss(42);
  assert.equal(r.state, "OK");
  assert.equal(r.probability, 0.42);
  assert.equal(r.percent, 42);
});

test("epss(): 0 -> 0%", () => {
  const r = CDB_NORMALIZE.epss(0);
  assert.equal(r.state, "OK");
  assert.equal(r.probability, 0);
  assert.equal(r.percent, 0);
});

test("epss(): 1 -> 100%", () => {
  const r = CDB_NORMALIZE.epss(1);
  assert.equal(r.state, "OK");
  assert.equal(r.probability, 1);
  assert.equal(r.percent, 100);
});

test("epss(): 100 -> 100%", () => {
  const r = CDB_NORMALIZE.epss(100);
  assert.equal(r.state, "OK");
  assert.equal(r.probability, 1);
  assert.equal(r.percent, 100);
});

test("epss(): null/undefined/empty-string -> UNKNOWN, never a fabricated number", () => {
  for (const v of [null, undefined, ""]) {
    const r = CDB_NORMALIZE.epss(v);
    assert.equal(r.state, "UNKNOWN");
    assert.equal(r.probability, null);
    assert.equal(r.percent, null);
  }
});

test("epss(): NaN / non-numeric string -> INVALID, never silently clamped", () => {
  const r = CDB_NORMALIZE.epss("not-a-number");
  assert.equal(r.state, "INVALID");
  assert.equal(r.probability, null);
});

test("epss(): partially-numeric strings (e.g. '42invalid') -> INVALID, never truncated to a plausible number", () => {
  // parseFloat("42invalid") === 42, which would silently mark a malformed
  // value OK. Number("42invalid") is NaN, correctly rejecting it.
  const r = CDB_NORMALIZE.epss("42invalid");
  assert.equal(r.state, "INVALID");
  assert.equal(r.probability, null);
});

test("epss(): whitespace-only string -> UNKNOWN, not INVALID and not 0", () => {
  const r = CDB_NORMALIZE.epss("   ");
  assert.equal(r.state, "UNKNOWN");
  assert.equal(r.probability, null);
});

test("epss(): >100 -> INVALID, never silently divided into a plausible-looking value", () => {
  const r = CDB_NORMALIZE.epss(101);
  assert.equal(r.state, "INVALID");
  assert.equal(r.probability, null);
  assert.equal(r.percent, null);
});

test("epss(): negative -> INVALID", () => {
  const r = CDB_NORMALIZE.epss(-1);
  assert.equal(r.state, "INVALID");
});

test("epss(): risk_score-shaped values (9.0127, 9.0073, 8.8806) are NOT silently treated as EPSS by this helper -- caller must pass epss_score, never risk_score", () => {
  // This is a documentation-style test: the normalizer has no way to detect
  // which field it was handed, so the contract is enforced at the call site
  // (js/sentinel-live-feeds.js loadEPSS() must pass c.epss_score, not
  // c.risk_score). Confirmed separately via the browser E2E fixture.
  const r = CDB_NORMALIZE.epss(9.0127);
  // 9.0127 is in (1,100], so it normalizes as an already-percentage EPSS
  // reading (9.01%) -- proving the normalizer's job ends at unit conversion;
  // semantic correctness (which field was passed in) is the caller's job.
  assert.equal(r.state, "OK");
  assert.equal(r.percent.toFixed(2), "9.01");
});

test("kevState(): boolean true/false pass through", () => {
  assert.equal(CDB_NORMALIZE.kevState({ kev_present: true }), true);
  assert.equal(CDB_NORMALIZE.kevState({ kev_present: false }), false);
});

test("kevState(): legacy string values are parsed, not coerced via truthiness", () => {
  assert.equal(CDB_NORMALIZE.kevState({ kev: "YES" }), true);
  assert.equal(CDB_NORMALIZE.kevState({ kev: "TRUE" }), true);
  assert.equal(CDB_NORMALIZE.kevState({ kev: "1" }), true);
  assert.equal(CDB_NORMALIZE.kevState({ kev: "NO" }), false);
  assert.equal(CDB_NORMALIZE.kevState({ kev: "FALSE" }), false);
  assert.equal(CDB_NORMALIZE.kevState({ kev: "0" }), false);
});

test("kevState(): null/undefined/missing -> UNKNOWN, never silently false", () => {
  assert.equal(CDB_NORMALIZE.kevState({ kev: null }), "UNKNOWN");
  assert.equal(CDB_NORMALIZE.kevState({}), "UNKNOWN");
  assert.equal(CDB_NORMALIZE.kevState(null), "UNKNOWN");
});

test("kevState(): kev_present (clean boolean) takes precedence over legacy kev string", () => {
  // Proves the fix for the live regression: an item with kev_present:false
  // and the legacy kev:"NO" string must resolve to false, not true.
  assert.equal(CDB_NORMALIZE.kevState({ kev_present: false, kev: "NO" }), false);
  assert.equal(CDB_NORMALIZE.kevState({ kev_present: true, kev: "NO" }), true);
});

test("kevState(): CRITICAL live-production regression case -- kev:'NO' must not authorize a CRITICAL downgrade bypass", () => {
  // Live evidence: a crypto-js CVE item with severity CRITICAL, no CVSS,
  // kev_present:null, kev:"NO", epss_score:32 (32%). The old `!!(item.kev_present
  // || item.kev)` bug evaluated to true for this exact item, incorrectly
  // preventing the False-CRITICAL downgrade from firing.
  const item = { severity: "CRITICAL", kev_present: null, kev: "NO", cvss_score: null, epss_score: 32, risk_score: 8.5 };
  assert.equal(CDB_NORMALIZE.kevState(item), false);
});

test("priority(): valid sla_priority passes through unchanged for all 5 tiers", () => {
  for (const p of ["P0", "P1", "P2", "P3", "P4"]) {
    assert.equal(CDB_NORMALIZE.priority({ sla_priority: p }), p);
  }
});

test("priority(): apex_ai.soc_priority is a valid fallback when sla_priority is absent", () => {
  assert.equal(CDB_NORMALIZE.priority({ apex_ai: { soc_priority: "P1" } }), "P1");
});

test("priority(): plain .priority field is a fallback when the above are absent", () => {
  assert.equal(CDB_NORMALIZE.priority({ priority: "P2" }), "P2");
});

test("priority(): sla_priority takes precedence over a disagreeing plain priority field", () => {
  assert.equal(CDB_NORMALIZE.priority({ sla_priority: "P0", priority: "P1" }), "P0");
});

test("priority(): unknown/missing priority never becomes 'P4' -- returns 'UNKNOWN'", () => {
  assert.equal(CDB_NORMALIZE.priority({}), "UNKNOWN");
  assert.equal(CDB_NORMALIZE.priority(null), "UNKNOWN");
  assert.equal(CDB_NORMALIZE.priority({ sla_priority: "not-a-priority" }), "UNKNOWN");
});

// Note: the computePriority() fallback branch (used only when the item has
// no sla_priority/apex_ai.soc_priority/priority but DOES carry at least one
// raw signal field -- see the `hasSignal` guard in priority()) can only be
// exercised where window.computePriority is the real index.html-defined
// function, i.e. in the browser E2E test
// (render-test/verify_metric_semantic_contracts.js), not here: this module's
// Node/CJS import path binds `root` to null, so that branch is a guaranteed
// no-op under `node --test`, and priority({}) already covers the "no signal
// at all" UNKNOWN case via the same code path production sees.

test("priority(): malformed sla_priority values are rejected, not passed through", () => {
  assert.equal(CDB_NORMALIZE.priority({ sla_priority: "P9" }), "UNKNOWN");
  assert.equal(CDB_NORMALIZE.priority({ sla_priority: "CRITICAL" }), "UNKNOWN");
});
