import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import vm from "node:vm";

// ---------------------------------------------------------------------------
// P0 regression suite -- CYBERDUDEBIVASH SENTINEL APEX
//
// Forensic investigation (2026-08-11) found index.html running a second,
// independent legacy card/metrics pipeline (loadGOCIntel -> renderCards ->
// {renderTopThreats, computeMetrics, openThreatModal, ...}) alongside the
// canonical js/api_adapter.js -> js/card_renderer.js pipeline. That legacy
// pipeline read raw feed fields directly and re-derived severity, SOC
// priority, and IOC totals independently -- producing up to four different,
// mutually inconsistent priority computations (including a literal
// `ai.soc_priority || ap.priority || 'P4'` reproduction of the exact
// HIGH-severity/P4-badge bug already fixed in the adapter) and an unguarded
// IOC string-concatenation risk in computeMetrics() (the same bug class
// already fixed elsewhere, in eiccEngine()'s _iocContribution(), covered by
// index_html_ioc_total.test.js -- that fix never reached this second,
// independent aggregator).
//
// The fix: loadGOCIntel() now calls window.SentinelApexAdapter.
// normalizeIntelItem() once, at the same point it already reconciles raw
// feed schema differences, and attaches the result as item.__norm. Every
// legacy renderer this file tests now prefers item.__norm.<field> over its
// own local recomputation, with the original recomputation kept only as a
// fallback for items that somehow lack __norm.
//
// These tests extract and execute the real functions straight out of
// index.html (not reimplementations), so they cannot silently drift from
// what the dashboard actually runs.
// ---------------------------------------------------------------------------

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const INDEX_HTML = path.join(__dirname, "..", "..", "index.html");
const SRC = readFileSync(INDEX_HTML, "utf-8");

function extractFnByMarker(startMarker, endMarker) {
  const start = SRC.indexOf(startMarker);
  assert.ok(start !== -1, `marker not found in index.html: ${startMarker}`);
  const end = SRC.indexOf(endMarker, start);
  assert.ok(end !== -1, `end marker not found after ${startMarker}: ${endMarker}`);
  return SRC.slice(start, end + endMarker.length);
}

// ---------------------------------------------------------------------------
// renderTopThreats()'s nested sevInfo()/prio() -- extracted together since
// prio() is declared right after sevInfo() inside the same function scope.
// ---------------------------------------------------------------------------

function loadTopThreatsPriorityFns() {
  const sevInfoSrc = extractFnByMarker(
    "function sevInfo(canonicalSev, s) {",
    "\n    }"
  );
  const prioSrc = extractFnByMarker(
    "function prio(item) {\n        if (item.__norm",
    "\n        return 'P4';\n    }"
  );
  const SEV_TIERS_SRC = extractFnByMarker(
    "const SEV_TIERS = {",
    "\n    };"
  );
  const context = {};
  vm.createContext(context);
  vm.runInContext(
    `${SEV_TIERS_SRC}\n${sevInfoSrc}\n${prioSrc}\nthis.sevInfo = sevInfo; this.prio = prio;`,
    context
  );
  return { sevInfo: context.sevInfo, prio: context.prio };
}

const { sevInfo, prio } = loadTopThreatsPriorityFns();

test("sevInfo: canonical severity from item.__norm wins over the risk-score threshold fallback", () => {
  // A risk_score of 2 would threshold to LOW on its own, but a real
  // CRITICAL classification (e.g. KEV-confirmed with a low current CVSS)
  // must not be downgraded by this display-only heuristic.
  assert.equal(sevInfo("CRITICAL", 2).l, "CRITICAL");
  assert.equal(sevInfo("HIGH", 2).l, "HIGH");
  assert.equal(sevInfo("MEDIUM", 2).l, "MEDIUM");
  assert.equal(sevInfo("LOW", 9).l, "LOW");
});

test("sevInfo: falls back to the risk-score threshold when no canonical severity is available", () => {
  assert.equal(sevInfo(null, 9.5).l, "CRITICAL");
  assert.equal(sevInfo(null, 7.2).l, "HIGH");
  assert.equal(sevInfo(null, 5).l, "MEDIUM");
  assert.equal(sevInfo(null, 1).l, "LOW");
  assert.equal(sevInfo(undefined, 7).l, "HIGH");
});

test("prio: exact live production reproduction -- HIGH severity item with canonical P3 never renders P4", () => {
  // Verbatim shape of the live-reproduction case fixed in js/api_adapter.js
  // (intel--53866cd4fffb31f8): a HIGH-severity item whose kev/epss/cvss
  // fields alone would fall through prio()'s own algorithm to P4, but whose
  // canonical, already-computed priority is P3.
  const item = {
    severity: "HIGH",
    risk_score: 7.0883,
    kev_present: false,
    epss_score: null,
    cvss_score: null,
    __norm: { apex_ai: { soc_priority: "P3" } },
  };
  const result = prio(item);
  assert.equal(result, "P3");
  assert.notEqual(result, "P4");
});

test("prio: canonical priority is used even when it disagrees with the local kev/epss/cvss algorithm", () => {
  const item = {
    kev_present: true, // would force P1 under the local algorithm
    epss_score: 90,
    cvss_score: 9.9,
    risk_score: 9.9,
    __norm: { apex_ai: { soc_priority: "P4" } }, // canonical says otherwise
  };
  assert.equal(prio(item), "P4");
});

test("prio: falls back to the local kev/epss/cvss algorithm when item.__norm is absent", () => {
  assert.equal(prio({ kev_present: true, epss_score: 0, cvss_score: 0, risk_score: 0 }), "P1");
  assert.equal(prio({ kev_present: false, epss_score: 0, cvss_score: 8, risk_score: 0 }), "P2");
  assert.equal(prio({ kev_present: false, epss_score: 0, cvss_score: 6, risk_score: 0 }), "P3");
  assert.equal(prio({ kev_present: false, epss_score: 0, cvss_score: 0, risk_score: 0 }), "P4");
});

test("prio: falls back when __norm exists but has no apex_ai.soc_priority", () => {
  assert.equal(prio({ kev_present: true, epss_score: 0, cvss_score: 0, risk_score: 0, __norm: {} }), "P1");
});

// ---------------------------------------------------------------------------
// PR-B (Dashboard Truth Contract, 2026-08-11) -- prio(item) already prefers
// item.__norm.apex_ai.soc_priority (fixed at js/api_adapter.js's
// normalizeSocPriority()), so once the adapter preserves a real "P0" value,
// prio() correctly returns "P0" on TOP10 too. But prioColor() and the
// action-strip label below each card independently branched on p==='P1'
// only -- a P0 item would keep the correct "P0" text badge but be colored
// (and labeled "MONITOR") identically to a P4/informational item, silently
// re-introducing the same visual contradiction one layer down. These tests
// extract and execute the real functions straight out of index.html.
// ---------------------------------------------------------------------------

function loadTopThreatsColorFns() {
  const prioColorSrc = extractFnByMarker(
    "function prioColor(p) {",
    "\n    }"
  );
  const prioActionLabelSrc = extractFnByMarker(
    "function prioActionLabel(pr, kev, epss) {",
    "\n    }"
  );
  const context = {};
  vm.createContext(context);
  vm.runInContext(
    `${prioColorSrc}\n${prioActionLabelSrc}\nthis.prioColor = prioColor; this.prioActionLabel = prioActionLabel;`,
    context
  );
  return { prioColor: context.prioColor, prioActionLabel: context.prioActionLabel };
}

const { prioColor, prioActionLabel } = loadTopThreatsColorFns();

test("prio: CRITICAL/P0 (KEV-confirmed) item reads P0 from the canonical adapter output on TOP10, never P4", () => {
  const item = { severity: "CRITICAL", kev_present: true, __norm: { apex_ai: { soc_priority: "P0" } } };
  const result = prio(item);
  assert.equal(result, "P0");
  assert.notEqual(result, "P4");
});

test("prioColor: P0 gets its own color, distinct from P4's gray -- never visually equated with informational", () => {
  const p0Color = prioColor("P0");
  const p4Color = prioColor("P4");
  assert.notEqual(p0Color, p4Color);
  assert.notEqual(p0Color, "#6b7280", "P0 must not use P4's gray color");
});

test("prioColor: P1-P4 mappings are unchanged by the P0 fix", () => {
  assert.equal(prioColor("P1"), "#dc2626");
  assert.equal(prioColor("P2"), "#ea580c");
  assert.equal(prioColor("P3"), "#d97706");
  assert.equal(prioColor("P4"), "#6b7280");
});

test("prioActionLabel: a P0 item without kev_present set still gets escalated styling, never the default MONITOR label", () => {
  const label = prioActionLabel("P0", false, 0);
  assert.notEqual(label.text, "MONITOR");
});

test("prioActionLabel: existing P1/P2/other behavior is unchanged", () => {
  assert.equal(prioActionLabel("P1", false, 0).text, "&#9888; PATCH NOW");
  assert.equal(prioActionLabel("P2", false, 0).text, "INVESTIGATE");
  assert.equal(prioActionLabel("P4", false, 0).text, "MONITOR");
  assert.equal(prioActionLabel("P3", true, 0).text, "&#9888; IMMEDIATE ACTION"); // kev always wins
});

// ---------------------------------------------------------------------------
// CodeRabbit finding on PR #168: the original prioColor()/prioActionLabel()
// default branches caught P4 AND 'UNKNOWN' identically -- a malformed
// priority would render with the same gray color and "MONITOR" label as a
// genuinely-low-urgency P4 item, re-introducing the "unknown masquerading as
// informational" anti-pattern this PR exists to eliminate.
// ---------------------------------------------------------------------------

test("prioColor: UNKNOWN gets its own neutral color, distinct from P3's and P4's", () => {
  const unknownColor = prioColor("UNKNOWN");
  assert.notEqual(unknownColor, prioColor("P4"));
  assert.notEqual(unknownColor, prioColor("P3"));
  assert.equal(unknownColor, "#9ca3af");
});

test("prioActionLabel: UNKNOWN never renders as MONITOR -- a malformed priority must not look low-urgency", () => {
  const label = prioActionLabel("UNKNOWN", false, 0);
  assert.notEqual(label.text, "MONITOR");
  assert.equal(label.text, "REVIEW PRIORITY");
  assert.equal(label.color, "#9ca3af");
});

test("prioActionLabel: P3 and P4 both still render MONITOR (unchanged) -- only UNKNOWN and other non-priority values changed", () => {
  assert.equal(prioActionLabel("P3", false, 0).text, "MONITOR");
  assert.equal(prioActionLabel("P4", false, 0).text, "MONITOR");
});

// ---------------------------------------------------------------------------
// computeMetrics() IOC aggregation -- guards against the exact string-
// concatenation regression already fixed once (elsewhere) in this codebase.
// computeMetrics() itself is not cleanly extractable in isolation (it reads
// and writes ~10 DOM elements throughout), so this pins the source pattern
// directly: the vulnerable unguarded `+= d.ioc_count` must not reappear, and
// the numeric-cast fix must be present.
// ---------------------------------------------------------------------------

test("computeMetrics(): the unguarded IOC string-concatenation pattern is not present", () => {
  const fnSrc = extractFnByMarker("function computeMetrics(data) {", "\n            let totalIOCs = 0;");
  assert.doesNotMatch(
    fnSrc.replace(/\n[^\n]*$/, ""), // exclude the boundary line itself
    /totalIOCs \+= d\.ioc_count;(?!.*parseInt)/,
    "computeMetrics() must not accumulate d.ioc_count without a numeric cast"
  );
});

test("computeMetrics(): every totalIOCs accumulation branch casts its input numerically or reads the pre-cast __norm value", () => {
  const start = SRC.indexOf("let totalIOCs = 0;");
  assert.ok(start !== -1, "totalIOCs accumulator not found in index.html");
  const end = SRC.indexOf("\n            });", start);
  const block = SRC.slice(start, end);
  assert.match(block, /d\.__norm && typeof d\.__norm\.ioc_count === 'number'/, "must prefer the adapter's pre-cast ioc_count");
  assert.match(block, /parseInt\(b, 10\) \|\| 0/, "ioc_counts object values must be cast");
  assert.match(block, /parseInt\(d\.ioc_count, 10\) \|\| 0/, "ioc_count must be cast");
  assert.match(block, /parseInt\(d\.indicator_count, 10\) \|\| 0/, "indicator_count must be cast");
});

// ---------------------------------------------------------------------------
// The canonical normalization hook itself -- guards against the wiring
// (not just the individual consumer fixes above) silently regressing.
// ---------------------------------------------------------------------------

test("loadGOCIntel(): the canonical normalization hook is wired at the schema-reconciliation boundary", () => {
  assert.match(
    SRC,
    /window\.SentinelApexAdapter\s*&&\s*typeof window\.SentinelApexAdapter\.normalizeIntelItem === 'function'/,
    "loadGOCIntel() must feature-detect the canonical adapter before using it"
  );
  assert.match(
    SRC,
    /item\.__norm = window\.SentinelApexAdapter\.normalizeIntelItem\(item, idx\);/,
    "loadGOCIntel() must attach the canonical normalized result as item.__norm"
  );
});

test("openThreatModal(): the literal ai.soc_priority || ap.priority || 'P4' pattern is no longer reachable without the canonical value first", () => {
  const occurrences = [...SRC.matchAll(/const prio\s*=[^;]*ai\.soc_priority \|\| ap\.priority \|\| 'P4';/g)];
  assert.ok(occurrences.length >= 2, "expected the two known apex_ai priority panels in index.html");
  for (const m of occurrences) {
    assert.match(
      m[0],
      /item\.__norm && item\.__norm\.apex_ai && item\.__norm\.apex_ai\.soc_priority/,
      "every remaining ai.soc_priority||ap.priority||'P4' fallback chain must be preceded by the canonical item.__norm check"
    );
  }
});

test("openThreatModal(): report-availability is resolved via the single canonical cdbBuildReportUrl(), not a local reimplementation", () => {
  const modalStart = SRC.indexOf("function openThreatModal(item) {");
  assert.ok(modalStart !== -1);
  const modalEnd = SRC.indexOf("\n        function ", modalStart + 40); // next top-level function decl
  assert.ok(modalEnd !== -1, "could not locate the end of openThreatModal() in index.html");
  const modalSrc = SRC.slice(modalStart, modalEnd);
  const reportUrlSites = [...modalSrc.matchAll(/cdbBuildReportUrl\(item\)/g)];
  assert.ok(reportUrlSites.length >= 2, "expected both report-link sites in the modal to call the canonical builder");
});

// ---------------------------------------------------------------------------
// P0 (dashboard truth contract, 2026-08-11) -- the TOP10 list's two report-
// link fallback templates unconditionally labeled an unresolved report link
// "PROCESSING" / "Full report is still processing", regardless of whether
// the item was genuinely still generating, permanently WITHHELD, or
// REJECTED by certification -- cdbBuildReportUrl() returns '' identically
// for all three (documented in its own v187.0 comment), so the frontend
// has no data to distinguish them and must not assert a specific one.
// ---------------------------------------------------------------------------

test('TOP10: the false "still processing" claim is not shown when a report link is unresolved', () => {
  assert.doesNotMatch(
    SRC,
    /Full report is still processing/,
    'no code path may claim a report is "still processing" when cdbBuildReportUrl() cannot distinguish that from a permanent withholding/rejection'
  );
});

test("TOP10: both hasVerifiedReport fallback sites use the honest, state-neutral unavailable label", () => {
  const occurrences = [...SRC.matchAll(/No verified report link is currently available for this item">&#8226; UNAVAILABLE<\/span>/g)];
  assert.equal(occurrences.length, 2, "expected both TOP10 report-link fallback templates (main + minified duplicate) to use the same honest label");
});
