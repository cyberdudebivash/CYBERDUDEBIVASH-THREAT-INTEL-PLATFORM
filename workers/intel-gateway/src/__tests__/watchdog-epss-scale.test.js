/**
 * CYBER WATCHDOG -- EPSS scale and KEV string evidence (P0 fix).
 *
 * The platform feed stores EPSS as a PERCENT (0-100): epss_batch_enricher.py
 * and sentinel_blogger.py both multiply FIRST.org's probability by 100. Live
 * production feed on 2026-09-24 carried epss_score values 0.42 ... 98.68 and
 * kev: "NO" strings. watchdog-priority-1 read EPSS as 0..1: 0.86 (0.86%) was
 * over-ranked to HIGH and 86 (86%) was dropped as unknown. These fixtures use
 * the live feed's value shapes.
 */
import assert from "node:assert/strict";
import { test } from "node:test";

import { PRIORITY_VERSION, computeEventPriority, epssProbability, eventPriority } from "../watchdog-priority.js";
import { candidateEvent, matchWatch, materialRevision, projectItem } from "../cyber-watchdog.js";

const LIVE_SHAPE = {
  id: "intel--live-shape-1",
  title: "Medium: A 0-click exploit chain (CVE-2025-54957)",
  severity: "MEDIUM",
  cve_ids: ["CVE-2025-54957"],
  cvss_score: 6.5,
  epss_score: 0.86,
  kev: "NO",
  source: "GitHub Security Advisories",
};

test("epssProbability reads the platform percent scale; out-of-range is not evidence", () => {
  assert.equal(epssProbability({ epss_score: 86 }), 0.86);
  assert.equal(epssProbability({ epss_score: 98.68 }), 0.9868);
  assert.equal(epssProbability({ epss_score: 0.86 }), 0.0086);
  assert.equal(epssProbability({ epss_score: 0 }), 0);
  assert.equal(epssProbability({ epss_score: 100 }), 1);
  for (const bad of [100.01, -1, "abc", null, undefined, "", NaN, Infinity]) {
    assert.equal(epssProbability({ epss_score: bad }), null, String(bad));
  }
  assert.equal(epssProbability(null), null);
});

test("priority v2: 0.86% EPSS is not ranked HIGH; 86% EPSS is evidence and floors HIGH", () => {
  assert.equal(PRIORITY_VERSION, "watchdog-priority-2");
  const low = computeEventPriority(LIVE_SHAPE);
  const e = low.factors.find((f) => f.id === "epss");
  assert.equal(e.known, true);
  assert.ok(e.points < 1, "0.86% EPSS is worth under a point, got " + e.points);
  assert.equal(e.evidence, "epss_score=0.86 (percent)");
  assert.ok(!low.floors_applied.includes("epss_ge_50_percent"));
  assert.notEqual(low.band, "HIGH");
  assert.notEqual(low.band, "CRITICAL");

  const high = computeEventPriority({ ...LIVE_SHAPE, epss_score: 86 });
  assert.equal(high.factors.find((f) => f.id === "epss").points, 17.2);
  assert.ok(high.floors_applied.includes("epss_ge_50_percent"));
  assert.equal(high.band, "HIGH");

  const off = computeEventPriority({ ...LIVE_SHAPE, epss_score: 150 });
  assert.equal(off.factors.find((f) => f.id === "epss").known, false);
});

test("priority v2: kev \"NO\" string is known not-listed evidence; \"YES\" is listed", () => {
  const no = computeEventPriority({ severity: "LOW", kev: "NO" });
  const k = no.factors.find((f) => f.id === "kev");
  assert.equal(k.known, true);
  assert.equal(k.points, 0);
  assert.equal(k.evidence, "Feed reports not KEV-listed");
  assert.equal(computeEventPriority({ kev: " yes " }).band, "HIGH");
  assert.equal(computeEventPriority({ kev: "maybe" }).band, "INSUFFICIENT_EVIDENCE");
  // Boolean flags still win: kev_present true beats a stale "NO" string.
  assert.equal(computeEventPriority({ kev: "NO", kev_present: true }).factors.find((f) => f.id === "kev").points, 30);
});

test("min_epss stays a 0..1 probability and is compared against the percent feed", () => {
  const watch = { id: "w_1", name: "EPSS 50%", logic: "OR", enabled: true, criteria: { min_epss: 0.5 } };
  assert.equal(matchWatch(watch, { ...LIVE_SHAPE, epss_score: 86 }).matched, true);
  assert.equal(matchWatch(watch, { ...LIVE_SHAPE, epss_score: 0.86 }).matched, false, "0.86% must not satisfy a 50% threshold");
  assert.equal(matchWatch(watch, { ...LIVE_SHAPE, epss_score: 50 }).matched, true);
  assert.equal(matchWatch(watch, { ...LIVE_SHAPE, epss_score: 150 }).matched, false);
  assert.equal(matchWatch(watch, { ...LIVE_SHAPE, epss_score: null }).matched, false);
});

test("history is not rewritten: a stored v1 event keeps its own version and explanation", () => {
  const storedV1 = { priority: { v: "watchdog-priority-1", score: 44, band: "HIGH", coverage: 0.6, f: [["epss", 17.2, "epss_score=0.86"]], floors: ["epss_ge_0_5"] } };
  const view = eventPriority(storedV1);
  assert.equal(view.version, "watchdog-priority-1");
  assert.equal(view.band, "HIGH");
  assert.deepEqual(view.floors_applied, ["epss_ge_0_5"]);
});

test("the fix does not change event identity: revision and dedupe are unaffected by kev strings", () => {
  // materialRevision is untouched, so an unchanged advisory never re-alerts.
  assert.equal(materialRevision(LIVE_SHAPE), materialRevision({ ...LIVE_SHAPE, kev: undefined }));
  const watch = { id: "w_2", name: "CVE", logic: "OR", enabled: true, criteria: { cves: ["CVE-2025-54957"] } };
  const ev = candidateEvent(watch, projectItem(LIVE_SHAPE), "2026-09-24T00:00:00Z", "2026-09-24T00:00:00Z");
  assert.equal(ev.priority.v, "watchdog-priority-2");
  assert.ok(ev.id.startsWith("e_"));
});
