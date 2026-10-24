import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Adapter from "../api_adapter.js";
import CardRenderer from "../card_renderer.js";

// ---------------------------------------------------------------------------
// PR-C regression suite -- CYBERDUDEBIVASH SENTINEL APEX
//
// Investigation of the main LIVE intelligence grid (#sapx-card-grid,
// rendered by js/card_renderer.js from js/api_adapter.js's
// normalizeIntelItem() -- confirmed via hermetic Playwright reproduction to
// be the sole customer-visible card grid; #threat-grid stays display:none)
// found three concrete truth-contract defects, each reproduced against real
// production data:
//
//  1. Confidence scale bug: the raw confidence field is stored as a 0-1
//     fraction but was read directly into a value later formatted as a
//     percentage, rendering e.g. "0.2%" for a record whose real confidence
//     was ~20%.
//  2. IOC count / confidence visual-adjacency bug: a bare IOC count number
//     immediately followed by a confidence percentage with only a small gap
//     and no unit label can be misread as one concatenated number (e.g. a
//     count of 4 next to "97% conf" reading as "497% conf").
//  3. validation_status vocabulary bug: buildValidationStatus() only
//     recognized the literal strings "valid"/"invalid"; production emits a
//     wider vocabulary that never matched either, so those records rendered
//     the customer-facing trust badge as "? PENDING" regardless of actual
//     state.
//
// These tests exercise the real, exported normalizeIntelItem()/
// buildValidationStatus() and the real renderIntelCore() card markup so
// none of the three can silently regress.
// ---------------------------------------------------------------------------

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function rawItem(overrides) {
  return Object.assign(
    {
      id: "intel--test",
      severity: "HIGH",
      sla_priority: "P3",
      ioc_count: 4,
      ioc_confidence: 97,
      confidence: 0.2,
      confidence_score: 24.3,
      validation_status: "enriched",
    },
    overrides
  );
}

/* ── Defect B: confidence scale ─────────────────────────────────────────── */

test("confidence_display renders the real percentage, not the raw 0-1 fraction", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ confidence: 0.2, confidence_score: 24.3 }), 0);
  assert.equal(item.confidence, 24.3);
  assert.equal(item.confidence_display, "24.3%");
  assert.notEqual(item.confidence_display, "0.2%");
});

test("confidence_score is preferred over the legacy 0-1 fraction when both are present", () => {
  const a = Adapter.normalizeIntelItem(rawItem({ confidence: 0.25, confidence_score: 21.3 }), 0);
  assert.equal(a.confidence, 21.3);
});

test("confidence falls back to a mixed-scale-normalized raw.confidence when confidence_score is absent", () => {
  const withFraction = Adapter.normalizeIntelItem(rawItem({ confidence: 0.42, confidence_score: undefined }), 0);
  assert.equal(withFraction.confidence, 42);
  assert.equal(withFraction.confidence_display, "42.0%");

  const alreadyPercent = Adapter.normalizeIntelItem(rawItem({ confidence: 63, confidence_score: undefined }), 0);
  assert.equal(alreadyPercent.confidence, 63);
});

test("confidence tier now varies with real confidence instead of always collapsing to LOW", () => {
  const highConf = Adapter.normalizeIntelItem(rawItem({ confidence: 0.95, confidence_score: 95 }), 0);
  assert.equal(highConf.apex_ai.confidence_tier_meta.tier, "CRITICAL");
});

test("a malformed confidence_score (non-finite, negative, or over 100) never reaches the customer as a broken display value", () => {
  const infinite = Adapter.normalizeIntelItem(rawItem({ confidence: 0.3, confidence_score: Infinity }), 0);
  assert.equal(infinite.confidence, 30);
  assert.doesNotMatch(infinite.confidence_display, /Infinity/);

  const negative = Adapter.normalizeIntelItem(rawItem({ confidence: 0, confidence_score: -5 }), 0);
  assert.equal(negative.confidence, 0);

  const overHundred = Adapter.normalizeIntelItem(rawItem({ confidence: 0, confidence_score: 150 }), 0);
  assert.equal(overHundred.confidence, 100);
});

/* ── Defect C: IOC count / confidence visual adjacency ─────────────────── */

test("IOC count renders with an explicit unit suffix so it cannot be misread as leading digits of the confidence percentage", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ ioc_count: 4, ioc_confidence: 97 }), 0);
  const html = CardRenderer.buildCard(item);
  assert.match(html, /4\s*IOCs/);
  assert.doesNotMatch(html, />4<\/span>\s*<span class="sapx-ioc-conf">97/);
});

test("IOC count and confidence are separated by a visible separator, never rendering as one concatenated number like 497", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ ioc_count: 4, ioc_confidence: 97 }), 0);
  const html = CardRenderer.buildCard(item);
  assert.doesNotMatch(html, />497%/);
  assert.match(html, /sapx-ioc-sep/);
});

test("singular IOC count does not render a trailing s (1 IOC, not 1 IOCs)", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ ioc_count: 1, ioc_confidence: 50 }), 0);
  const html = CardRenderer.buildCard(item);
  assert.match(html, /1 IOC(?!s)/);
});

test("zero IOC count renders only the explicit No IOCs state in the INTELLIGENCE CORE cell, never a duplicate count badge alongside it", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ ioc_count: 0, ioc_confidence: 0 }), 0);
  const html = CardRenderer.buildCard(item);
  const iocCell = html.slice(html.indexOf("IOC COUNT"), html.indexOf("IOC COUNT") + 900);
  assert.match(iocCell, /No IOCs/);
  assert.doesNotMatch(iocCell, /sapx-ioc-num/);
});

/* ── Defect E: validation_status vocabulary ─────────────────────────────── */

test("live validation_status value 'ok' renders VALID, not the fabricated PENDING state", () => {
  const vs = Adapter.buildValidationStatus("ok");
  assert.equal(vs.class, "valid");
  assert.equal(vs.label, "✓ VALID");
});

test("live validation_status value 'enriched' renders VALID, not the fabricated PENDING state", () => {
  const vs = Adapter.buildValidationStatus("enriched");
  assert.equal(vs.class, "valid");
});

test("missing/unrecognized validation_status renders UNKNOWN, never the fabricated PENDING implication", () => {
  const missing = Adapter.buildValidationStatus(undefined);
  assert.equal(missing.class, "unknown");
  assert.notEqual(missing.label, "? PENDING");

  const garbage = Adapter.buildValidationStatus("something_new_from_backend");
  assert.equal(garbage.class, "unknown");
});

test("explicit 'valid'/'invalid' backend values are unchanged (pre-existing contract preserved)", () => {
  assert.equal(Adapter.buildValidationStatus("valid").class, "valid");
  assert.equal(Adapter.buildValidationStatus("invalid").class, "invalid");
});

test("end-to-end: a real production-shaped item with validation_status='enriched' never reaches the customer as PENDING", () => {
  const item = Adapter.normalizeIntelItem(rawItem({ validation_status: "enriched" }), 0);
  assert.equal(item.validation_status.class, "valid");
  const html = CardRenderer.buildCard(item);
  assert.doesNotMatch(html, /PENDING/);
});

/* ── CSS hook sanity: .sapx-val-unknown must exist for the UNKNOWN badge ── */

test("css/card_renderer_styles.css defines .sapx-val-unknown (the class buildValidationStatus() now emits for UNKNOWN)", () => {
  const css = fs.readFileSync(path.join(__dirname, "..", "..", "css", "card_renderer_styles.css"), "utf-8");
  assert.match(css, /\.sapx-val-unknown\s*\{/);
});
