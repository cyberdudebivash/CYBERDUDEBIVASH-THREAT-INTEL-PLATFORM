/**
 * SENTINEL APEX UI system -- status model, page invariants and the two
 * display-data additions (MSSP tenant list on the session, daily match
 * counts). Plain Node: no browser. Browser-level checks (Chromium viewports,
 * DOM XSS, contrast) are documented in docs/SENTINEL_APEX_UI_SYSTEM.md; the
 * Pages render suites in render-test/ still cover index.html end to end.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { MSSP_KEY, PRO_KEY, harness } from "./watchdog-harness.js";
import { analyticsFromEvents } from "../cyber-watchdog.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../../..");
const read = (f) => fs.readFileSync(path.join(REPO, f), "utf8");
const S = createRequire(import.meta.url)(path.join(REPO, "js/apex-status-model.js"));

const WD = read("cyber-watchdog.html");
const HOME = read("index.html");
const CSS = read("css/apex-design-tokens.css");
const SURFACE = HOME.slice(HOME.indexOf('<section id="apex-command-surface"'), HOME.indexOf("CDB LIVE CYBER THREAT MAP v3.0"));
const GREEN = new Set(["ok", "fresh", "active", "delivered", "verified"]);

// ---------------------------------------------------------------------------
// Status model: a state is green only when a response proved it.
// ---------------------------------------------------------------------------

test("status model: unknown, unreadable or failed input is never green", () => {
  for (const input of [null, undefined, {}, { freshness_status: 5 }, "FRESH"]) {
    assert.equal(S.intelligenceState(input).state, "unknown", JSON.stringify(input));
    assert.equal(S.watchdogState(input).state, "unknown", JSON.stringify(input));
  }
  assert.equal(S.apiState(undefined).state, "unknown");
  assert.equal(S.intelligenceState(null, true).state, "offline");
  assert.equal(S.watchdogState(null, true).state, "offline");
  assert.equal(S.apiState(false, true).state, "offline");
  for (const bad of [undefined, "weird", ""]) {
    assert.ok(!GREEN.has(S.destinationState(bad).state));
    assert.ok(!GREEN.has(S.deliveryState(bad).state));
  }
});

test("status model: proven states map to their LED and text", () => {
  assert.deepEqual(S.intelligenceState({ freshness_status: "FRESH" }), { state: "fresh", label: "Intelligence fresh" });
  assert.equal(S.intelligenceState({ freshness_status: "STALE" }).state, "degraded");
  assert.equal(S.intelligenceState({ freshness_status: "EMPTY" }).state, "degraded");
  assert.equal(S.watchdogState({ watch_store: "ok", autonomous_evaluation: "configured" }).state, "active");
  assert.equal(S.watchdogState({ watch_store: "ok", autonomous_evaluation: "unavailable" }).state, "degraded");
  assert.equal(S.watchdogState({ watch_store: "unavailable" }).state, "offline");
  assert.equal(S.apiState(true).state, "ok");
  assert.equal(S.destinationState("active").state, "verified");
  assert.equal(S.destinationState("pending").state, "pending");
  assert.equal(S.destinationState("failed").state, "failed");
  assert.equal(S.deliveryState("partial").state, "failed");
  assert.equal(S.releaseLabel({ platform_version: "201.0" }), "v201.0");
  assert.equal(S.releaseLabel({ platform_version: "latest" }), null, "never an invented release");
  assert.equal(S.triageState("RESOLVED").terminal, true);
  assert.equal(S.triageState("INVESTIGATING").terminal, false);
  assert.equal(S.triageState("bogus").status, "NEW");
});

test("status model: charts only from stored history; draft rule mirrors the definition", () => {
  assert.equal(S.trendSeries({ history: "no_history_yet", daily_7d: [{ date: "2026-09-24", count: 0 }] }), null);
  assert.equal(S.trendSeries({}), null);
  assert.equal(S.trendSeries({ history: "stored-match-events", daily_7d: [{ date: "2026-09-24", count: 3 }] }).length, 1);
  assert.equal(S.priorityDistribution({ by_priority: { CRITICAL: 0, HIGH: 0 } }), null);
  assert.equal(S.priorityDistribution({ by_priority: { CRITICAL: 2 } })[0].count, 2);
  assert.equal(S.draftRule({ criteria: {} }), "");
  assert.equal(S.draftRule({ logic: "OR", criteria: { vendors: ["Microsoft"], severity_min: "HIGH", kev: true, epss_min: 0.5 } }),
    "MATCH\n  KEV vendor is Microsoft\nOR Severity HIGH+\nOR EPSS >= 50%\nOR CISA KEV = YES");
  assert.equal(S.ageText(30), "30s ago");
  assert.equal(S.ageText(-1), null);
  assert.equal(S.severityKey("critical"), "CRITICAL");
  assert.equal(S.severityKey("??"), "UNKNOWN");
});

// ---------------------------------------------------------------------------
// Page invariants
// ---------------------------------------------------------------------------

function ids(html) { return [...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]); }
function scriptOf(html) { return [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]).join("\n"); }

test("watchdog page: landmarks, unique ids, labelled controls, resolvable ARIA references", () => {
  for (const re of [/<nav\b[^>]*aria-label=/, /<main\b[^>]*id="main"/, /<footer\b/, /<dialog\b[^>]*aria-labelledby=/, /href="#main"/]) assert.match(WD, re);
  const all = ids(WD);
  const dupes = all.filter((x, i) => all.indexOf(x) !== i);
  assert.deepEqual(dupes, [], "duplicate ids: " + dupes.join(", "));
  const known = new Set(all.concat(["drawertitle"])); // drawertitle is rendered with the drawer
  for (const m of WD.matchAll(/aria-(?:labelledby|describedby|controls)="([^"]+)"/g)) {
    for (const ref of m[1].split(/\s+/)) assert.ok(known.has(ref), "unresolved ARIA reference " + ref);
  }
  // Every static form control sits in a <label> or carries an accessible name.
  const markup = WD.replace(/<script[\s\S]*?<\/script>/g, "").replace(/<style[\s\S]*?<\/style>/g, "");
  let open = 0; const unlabeled = [];
  for (const m of markup.matchAll(/<(\/?)(label|input|select|textarea)\b([^>]*)>/g)) {
    if (m[2] === "label") { open += m[1] ? -1 : 1; continue; }
    if (m[1]) continue;
    if (open > 0 || /aria-label(?:ledby)?=/.test(m[3]) || /type="hidden"/.test(m[3])) continue;
    const id = (m[3].match(/id="([^"]+)"/) || [])[1];
    if (id && new RegExp('<label[^>]*for="' + id + '"').test(markup)) continue;
    unlabeled.push(id || m[0]);
  }
  assert.deepEqual(unlabeled, []);
});

test("watchdog page: untrusted data never reaches HTML parsing; no stored key", () => {
  const js = scriptOf(WD);
  assert.doesNotMatch(js.replace(/\/\/.*$/gm, ""), /innerHTML|outerHTML|insertAdjacentHTML|document\.write|DOMParser/, "no HTML-string rendering");
  assert.match(js, /document\.createTextNode\(String\(kid\)\)/, "children become text nodes");
  assert.match(js, /if \(k\.startsWith\('on'\)\) continue;/, "event-handler attributes are never set from data");
  assert.match(js, /function safeHref\(u\)/);
  assert.match(WD, /charCodeAt\(0\)/);
  assert.match(WD, /sessionStorage/);
  assert.doesNotMatch(WD, /localStorage\.(get|set)Item/);
  assert.match(WD, /input\.value = ''/);
});

test("watchdog page: status rail starts unknown; LEDs come from the shared model", () => {
  for (const id of ["st-intel", "st-watchdog"]) {
    const m = WD.match(new RegExp('id="' + id + '"><span class="ax-led" data-state="([a-z]+)"'));
    assert.ok(m, id);
    assert.equal(m[1], "unknown", id + " must not render green before a response");
  }
  assert.match(WD, /S\.intelligenceState\(health, failed\)/);
  assert.match(WD, /S\.watchdogState\(health, failed\)/);
  assert.match(WD, /<script src="\/js\/apex-status-model\.js"><\/script>/);
});

const PRICE = /\$\s?\d{2,}|INR\s?[\d,]{3,}|\u20b9\s?\d/;
test("no hardcoded plan prices in the new surfaces (prices come from /api/watchdog/offer)", () => {
  assert.doesNotMatch(WD, PRICE);
  assert.doesNotMatch(SURFACE, PRICE);
  assert.doesNotMatch(CSS, PRICE);
  assert.match(WD, /fetch\('\/api\/watchdog\/offer'/);
});

function certClaims(text) {
  const out = [];
  for (const m of text.matchAll(/certified|certification badge/gi)) {
    const before = text.slice(Math.max(0, m.index - 16), m.index).toLowerCase();
    if (!/\bnot\s*$/.test(before)) out.push(text.slice(Math.max(0, m.index - 40), m.index + 12));
  }
  return out;
}
test("claims: no certification is implied; aligned-not-certified wording stays", () => {
  assert.deepEqual(certClaims(WD), []);
  assert.deepEqual(certClaims(SURFACE), []);
  assert.match(WD, /ISO 27001 \/ SOC 2: aligned, not certified\./);
  assert.match(SURFACE, /ISO 27001 \/ SOC 2: aligned, not certified\./);
});

test("homepage command surface: real data only, one shared brief request, unknown until proven", () => {
  assert.ok(SURFACE.length > 1000, "command surface present before the (simulated) threat map");
  for (const id of ["acs-release", "acs-fresh", "acs-count", "acs-critical", "acs-high", "acs-updated"]) {
    const m = SURFACE.match(new RegExp('<dd id="' + id + '"[^>]*>([\\s\\S]*?)</dd>'));
    assert.ok(m, id);
    assert.doesNotMatch(m[1], /\d/, id + " must not ship a hardcoded number");
  }
  for (const id of ["acs-st-intel", "acs-st-watchdog", "acs-st-api", "acs-st-release"]) {
    assert.match(SURFACE, new RegExp('id="' + id + '"><span class="ax-led" data-state="unknown"'), id);
  }
  assert.match(SURFACE, /window\.APEX_BRIEF = brief;/);
  assert.match(HOME, /\(window\.APEX_BRIEF \|\| fetch\('\/api\/watchdog\/brief\?limit=5'/);
  assert.doesNotMatch(SURFACE, /\.innerHTML\s*=/);
  assert.match(HOME, /<link rel="stylesheet" href="\/css\/apex-design-tokens\.css">/);
});

test("homepage: legacy SOC priority feed escapes feed text and refuses script URLs", () => {
  const fn = HOME.slice(HOME.indexOf("function renderTopThreats(data)"), HOME.indexOf("function renderTopThreats(data)") + 40000);
  assert.match(fn, /const _tt = \(s\) => String\(s == null \? '' : s\)\.replace\(\/\[&<>"'\]\/g/);
  assert.doesNotMatch(fn, /'\+\(item\.title\|\|'Unknown'\)\.substring\(/, "every title goes through _tt()");
  assert.equal((fn.match(/_tt\(\(item\.title\|\|'Unknown'\)\.substring\(/g) || []).length, 3);
  assert.doesNotMatch(fn, /'\+actor\+'|'\+t\+'<\/span>|'\+kcPhase\+'/, "actor, tactic and phase are escaped");
  assert.doesNotMatch(fn, /href="'\+intelUrl2?\+'/, "report links pass the scheme allow-list");
  const card = read("js/card_renderer.js");
  assert.match(card, /const sourceHref = \/\^https\?:\\\/\\\/\/i\.test\(/);
  assert.match(card, /<a href="\$\{esc\(sourceHref\)\}"[^>]*class="sapx-source-link"/);
});

test("homepage: no persistent upgrade bar for any paid tier; tier read from the live session", () => {
  const ctl = HOME.slice(HOME.indexOf("function _updateForTier()"), HOME.indexOf("function _hidePermanent()"));
  assert.match(ctl, /tier === 'PRO' \|\| tier === 'ENTERPRISE' \|\| tier === 'MSSP'\) \{[\s\S]*?_hidePermanent\(\);/);
  assert.match(ctl, /auth\.getUser\(\)/, "tier comes from the session record, where cdbAuth keeps it");
  assert.match(ctl, /auth\.getToken\(\)/, "an expired session counts as free");
  assert.match(HOME, /document\.body\.classList\.add\('cdb-scta-on'\)/, "the free-tier bar reserves its height");
});

test("design system: focus ring, overflow containment, text+shape status, reduced motion", () => {
  assert.match(CSS, /\.ax-app :focus-visible[^{]*\{[^}]*box-shadow: var\(--ax-focus\)/);
  assert.match(CSS, /\.ax-table-wrap \{ overflow: auto; max-width: 100%;/, "wide tables scroll inside their panel");
  assert.match(CSS, /\.ax-main \{ min-width: 0;/, "the main column can shrink below its content width");
  assert.match(CSS, /\.ax-app \[hidden\] \{ display: none !important; \}/);
  assert.match(CSS, /\.ax-led\[data-state="fresh"\][^{]*\{\s*--led: var\(--ax-status-fresh\)/);
  assert.match(CSS, /\.ax-led\[data-state="degraded"\][^{]*\{[^}]*clip-path: polygon/, "degraded is a triangle, not only a colour");
  assert.match(CSS, /\.ax-led\[data-state="unknown"\][^{]*\{\s*background: transparent/, "unknown is a hollow ring");
  assert.match(CSS, /@media \(prefers-reduced-motion: reduce\)/);
  assert.doesNotMatch(CSS, /@import|url\(\s*["']?https?:/, "no remote CSS dependency");
});

// ---------------------------------------------------------------------------
// Display-data additions
// ---------------------------------------------------------------------------

test("session: MSSP sign-in lists the credential's managed tenants; other plans do not", async () => {
  const h = harness();
  const mssp = await h.call("POST", "/api/watchdog/session", { key: MSSP_KEY });
  assert.equal(mssp.status, 200);
  assert.deepEqual(mssp.body.managed_tenants, ["CANARY-A", "CANARY-B"]);
  const pro = await h.call("POST", "/api/watchdog/session", { key: PRO_KEY });
  assert.equal("managed_tenants" in pro.body, false);
  // The list is display data: a tenant request is still authorized per request.
  const other = await h.call("GET", "/api/watchdog/watches?tenant=NOT-MINE", { bearer: mssp.body.token });
  assert.equal(other.status, 403);
});

test("analytics: daily_7d counts stored matches per UTC day, oldest first, bounded to 7 days", () => {
  const now = Date.parse("2026-09-24T12:00:00Z");
  const a = analyticsFromEvents([{ matched_at: "2026-09-24T01:00:00Z" }, { matched_at: "2026-09-22T23:59:00Z" }, { matched_at: "2026-09-10T00:00:00Z" }, { matched_at: "nope" }], now);
  assert.equal(a.daily_7d.length, 7);
  assert.equal(a.daily_7d[0].date, "2026-09-18");
  assert.deepEqual(a.daily_7d.map((d) => d.count), [0, 0, 0, 0, 1, 0, 1]);
  assert.equal(analyticsFromEvents([], now).history, "no_history_yet");
});
