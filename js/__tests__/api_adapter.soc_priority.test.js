import assert from "node:assert/strict";
import { test } from "node:test";
import Adapter from "../api_adapter.js";

// ---------------------------------------------------------------------------
// P0 regression suite -- CYBERDUDEBIVASH SENTINEL APEX
//
// Live production investigation (customer intelligence truth/card-integrity
// P0) found every CRITICAL/HIGH intelligence item rendering its SOC priority
// badge as "P4 -- INFORMATIONAL", regardless of true severity. Root cause:
// js/api_adapter.js normalizeIntelItem() read `raw.apex_ai.soc_priority`, a
// field that does not exist anywhere in the current pipeline schema (verified
// against live api/feed.json: `apex_ai` never contains a `soc_priority` key).
// The real, always-correct value is the top-level `sla_priority` field
// (verified live: CRITICAL->P1 6/6, HIGH->P3 12/12, MEDIUM->P3 11/11,
// LOW->P4 10/10 across every item in production). Because `_str(undefined,
// "P4")` returns the fallback, every item silently collapsed to "P4".
//
// These tests exercise the real, exported normalizeIntelItem()/
// normalizeSocPriority() so this cannot silently regress.
// ---------------------------------------------------------------------------

function rawItem(overrides) {
  return Object.assign(
    {
      id: "intel--test",
      severity: "CRITICAL",
      sla_priority: "P1",
      apex_ai: { ai_summary: "test", predictive_risk: 9.0 }, // no soc_priority key -- matches live schema
    },
    overrides
  );
}

test("CRITICAL item with sla_priority=P1 must render P1, never P4", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ severity: "CRITICAL", sla_priority: "P1" }), 0);
  assert.equal(item.apex_ai.soc_priority, "P1");
  assert.notEqual(item.apex_ai.soc_priority, "P4");
});

test("HIGH item with sla_priority=P3 must render P3, never P4", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ severity: "HIGH", sla_priority: "P3" }), 0);
  assert.equal(item.apex_ai.soc_priority, "P3");
  assert.notEqual(item.apex_ai.soc_priority, "P4");
});

test("MEDIUM item with sla_priority=P3 renders P3", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ severity: "MEDIUM", sla_priority: "P3" }), 0);
  assert.equal(item.apex_ai.soc_priority, "P3");
});

test("LOW item with sla_priority=P4 renders P4 (P4 is legitimate for LOW)", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ severity: "LOW", sla_priority: "P4" }), 0);
  assert.equal(item.apex_ai.soc_priority, "P4");
});

test("a 9.0-risk CRITICAL item does not become P4 (exact live-reproduction case)", () => {
  const item = Adapter.normalizeIntelItem(
    rawItem({ severity: "CRITICAL", sla_priority: "P1", risk_score: 9.0474 }),
    0
  );
  assert.equal(item.severity, "CRITICAL");
  assert.equal(item.apex_ai.soc_priority, "P1");
});

test("legacy apex_ai.soc_priority path still works when sla_priority is absent (backward compat)", () => {
  const raw = rawItem({ severity: "HIGH", sla_priority: undefined, apex_ai: { soc_priority: "P2" } });
  delete raw.sla_priority;
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.apex_ai.soc_priority, "P2");
});

// ---------------------------------------------------------------------------
// P0 follow-up (2026-08-11) -- live production found HIGH-severity items
// (OpenPhish-sourced, e.g. intel--53866cd4fffb31f8) rendering as
// "HIGH severity / P4 -- INFORMATIONAL" on the public dashboard -- a direct
// contradiction. Root cause: `sla_priority` is written by the full
// confidence_corroboration_engine.py pipeline, which runs on a much slower
// cadence (3x/day) than the lightweight ingestion pipeline that makes new
// items publicly visible. During that gap, both `raw.sla_priority` and
// `aa.soc_priority` are genuinely absent (not wrong -- not computed yet),
// and blindly defaulting to "P4" regardless of severity produced the
// contradiction. The fix is a severity-aware interim floor
// (fallbackSocPriorityForSeverity) mirroring build_sla_recommendation()'s
// own severity-only floor in confidence_corroboration_engine.py -- it never
// overrides a real sla_priority/soc_priority once one exists (covered by
// every test above, which all supply real values and must keep passing).
// ---------------------------------------------------------------------------

test("item with neither sla_priority nor apex_ai.soc_priority falls back to a severity-aware interim priority, never blindly P4", () => {
  const critical = rawItem({ severity: "CRITICAL", sla_priority: undefined, apex_ai: {} });
  delete critical.sla_priority;
  assert.equal(Adapter.normalizeIntelItem(critical, 0).apex_ai.soc_priority, "P2");

  const high = rawItem({ severity: "HIGH", sla_priority: undefined, apex_ai: {} });
  delete high.sla_priority;
  assert.equal(Adapter.normalizeIntelItem(high, 0).apex_ai.soc_priority, "P3");

  const medium = rawItem({ severity: "MEDIUM", sla_priority: undefined, apex_ai: {} });
  delete medium.sla_priority;
  assert.equal(Adapter.normalizeIntelItem(medium, 0).apex_ai.soc_priority, "P3");

  const low = rawItem({ severity: "LOW", sla_priority: undefined, apex_ai: {} });
  delete low.sla_priority;
  assert.equal(Adapter.normalizeIntelItem(low, 0).apex_ai.soc_priority, "P4");
});

test("exact live production reproduction: HIGH-severity OpenPhish item with no sla_priority never renders P4/INFORMATIONAL", () => {
  // Verbatim shape (trimmed) of a real live api/feed.json item during the
  // pre-enrichment gap -- id intel--53866cd4fffb31f8.
  const raw = {
    id: "intel--53866cd4fffb31f8",
    title: "[OpenPhish] Phishing URL: https://0c3cfe.icefactory.cl/",
    severity: "HIGH",
    risk_score: 7.0883,
    tags: ["openphish", "phishing"],
    apex_ai: { predictive_risk: 7.0883, ai_confidence: 20, locked: true },
  };
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.severity, "HIGH");
  assert.notEqual(item.apex_ai.soc_priority, "P4");
  assert.equal(item.apex_ai.soc_priority, "P3");
});

// ---------------------------------------------------------------------------
// PR-B (Dashboard Truth Contract, 2026-08-11) -- two defects fixed together:
//
// 1. normalizeSocPriority() whitelisted only P1-P4, so the pipeline's KEV-
//    confirmed emergency tier "P0" (confidence_corroboration_engine.py
//    build_sla_recommendation()) silently collapsed to "P4 -- INFORMATIONAL".
//    Confirmed live against api/feed.json item intel--d49e384ea385135d
//    (CRITICAL, kev_present=true, sla_priority="P0").
//
// 2. Separately, ANY unrecognized/malformed value (not just an absent one)
//    also collapsed to "P4" -- silently presenting a broken or future/
//    unknown backend classification as "safely informational". A malformed
//    security classification must never masquerade as low-urgency, so
//    unrecognized input now normalizes to "UNKNOWN" instead.
// ---------------------------------------------------------------------------

test("P0 must never downgrade to P4: normalizeSocPriority preserves P0 exactly", () => {
  assert.equal(Adapter.normalizeSocPriority("P0"), "P0");
  assert.notEqual(Adapter.normalizeSocPriority("P0"), "P4");
});

test("normalizeSocPriority preserves every real priority tier unchanged", () => {
  assert.equal(Adapter.normalizeSocPriority("P0"), "P0");
  assert.equal(Adapter.normalizeSocPriority("P1"), "P1");
  assert.equal(Adapter.normalizeSocPriority("P2"), "P2");
  assert.equal(Adapter.normalizeSocPriority("P3"), "P3");
  assert.equal(Adapter.normalizeSocPriority("P4"), "P4");
  assert.equal(Adapter.normalizeSocPriority("p0"), "P0"); // case-insensitive
});

test("normalizeSocPriority never silently defaults unknown/malformed/absent input to P4", () => {
  assert.equal(Adapter.normalizeSocPriority("not-a-priority"), "UNKNOWN");
  assert.notEqual(Adapter.normalizeSocPriority("not-a-priority"), "P4");
  assert.equal(Adapter.normalizeSocPriority(""), "UNKNOWN");
  assert.notEqual(Adapter.normalizeSocPriority(""), "P4");
  assert.equal(Adapter.normalizeSocPriority(null), "UNKNOWN");
  assert.notEqual(Adapter.normalizeSocPriority(null), "P4");
  assert.equal(Adapter.normalizeSocPriority(undefined), "UNKNOWN");
  assert.notEqual(Adapter.normalizeSocPriority(undefined), "P4");
  assert.equal(Adapter.normalizeSocPriority("P5"), "UNKNOWN"); // out-of-range, not a silent P4
  assert.equal(Adapter.normalizeSocPriority(0), "UNKNOWN");
});

test("CRITICAL/P0 item (KEV-confirmed emergency tier) renders P0 through the full normalizer, never P4", () => {
  const item = Adapter.normalizeIntelItem(
    rawItem({ severity: "CRITICAL", sla_priority: "P0", kev_present: true }),
    0
  );
  assert.equal(item.severity, "CRITICAL");
  assert.equal(item.apex_ai.soc_priority, "P0");
  assert.notEqual(item.apex_ai.soc_priority, "P4");
});

test("getSocPriorityMeta returns a distinct, non-P4 badge for P0", () => {
  const p0Meta = Adapter.getSocPriorityMeta("P0");
  const p4Meta = Adapter.getSocPriorityMeta("P4");
  assert.equal(p0Meta.label.startsWith("P0"), true);
  assert.notEqual(p0Meta.label, p4Meta.label);
  assert.notEqual(p0Meta.color, p4Meta.color);
});

test("getSocPriorityMeta returns a distinct badge for UNKNOWN, never silently reusing the P4 badge", () => {
  const unknownMeta = Adapter.getSocPriorityMeta("garbage-input");
  const p4Meta = Adapter.getSocPriorityMeta("P4");
  assert.notEqual(unknownMeta.label, p4Meta.label);
  assert.notEqual(unknownMeta.color, p4Meta.color);
});

test("generateActionRecommendation treats P0 with at least P1-level urgency (ESCALATE or higher), never MONITOR", () => {
  // kevPresent=false to isolate the soc-priority branch from the kev/epss/cvss PATCH branch.
  const rec = Adapter.generateActionRecommendation("CRITICAL", "P0", null, null, false);
  assert.notEqual(rec.action, "MONITOR");
  assert.ok(["PATCH", "ESCALATE"].includes(rec.action), `expected PATCH or ESCALATE for P0, got ${rec.action}`);
});

test("buildAiVerdict never tells an analyst 'no immediate action required' for P0 or UNKNOWN priority", () => {
  const p0Verdict = Adapter.buildAiVerdict("", "CRITICAL", "P0", "default", 80);
  assert.equal(p0Verdict.includes("No immediate action required"), false);

  const unknownVerdict = Adapter.buildAiVerdict("", "CRITICAL", "not-a-priority", "default", 80);
  assert.equal(unknownVerdict.includes("No immediate action required"), false);
});

test("exact live production item reproduction: Progress LoadMaster CRITICAL/P1", () => {
  // Verbatim shape (trimmed) of a real live api/feed.json item at the time
  // of investigation -- id intel--2e0aa0036ccade3c7131c992.
  const raw = {
    id: "intel--2e0aa0036ccade3c7131c992",
    title: "Critical Progress LoadMaster flaw now actively exploited in attacks",
    severity: "CRITICAL",
    sla_priority: "P1",
    risk_score: 9.0474,
    confidence: 0.25,
    exploit_maturity: "UNPROVEN",
    apex_ai: {
      predictive_risk: 9.0474,
      ai_confidence: 25,
      ai_summary: "The U.S. CISA warned that hackers are exploiting a critical-severity flaw.",
      actor_fingerprint: null,
      kill_chain: null,
      ttp_density: null,
      locked: true,
    },
  };
  const item = Adapter.normalizeIntelItem(raw, 0);
  assert.equal(item.severity, "CRITICAL");
  assert.equal(item.apex_ai.soc_priority, "P1");
  assert.notEqual(item.apex_ai.soc_priority, "P4");
});

// ---------------------------------------------------------------------------
// CodeRabbit finding on PR #168: is_high_priority's predicate checked only
// P1/P2, so a normalized P0 item (the platform's most urgent tier) reported
// is_high_priority:false -- contradicting the requirement that P0 carries at
// least P1-level urgency everywhere it is consumed.
// ---------------------------------------------------------------------------

test("is_high_priority is true for a CRITICAL/P0 item, not just P1/P2", () => {
  const item = Adapter.normalizeIntelItem(
    rawItem({ severity: "CRITICAL", sla_priority: "P0", kev_present: true }),
    0
  );
  assert.equal(item.is_high_priority, true);
});
