#!/usr/bin/env node
/**
 * Customer dashboard data contract -- negative controls (mutation proof).
 *
 * Copies the dashboard runtime and its tests to a temp directory, requires
 * the unmutated copy to PASS, then applies ONE deliberate defect per control
 * (a fabricated fallback, a stale-as-LIVE label, an unescaped title, a second
 * DOM owner, ...) and requires the dashboard suites to FAIL. A control the
 * tests do not catch exits 1. The working tree is never modified.
 *
 *   node workers/intel-gateway/scripts/dashboard-negative-controls.mjs
 */
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../..");
const COPY = [
  "index.html",
  "service-worker.js",
  "scripts/enterprise_intel_block.html",
  "js",
  "workers/intel-gateway/package.json",
  "workers/intel-gateway/src/index.js",
  "workers/intel-gateway/src/dashboard-contract.js",
  "workers/intel-gateway/src/__tests__/dashboard-contract.test.js",
  "workers/intel-gateway/src/__tests__/dashboard-frontend-contract.test.js",
];
const SUITES = [
  ["workers/intel-gateway", ["--test", "src/__tests__/dashboard-contract.test.js", "src/__tests__/dashboard-frontend-contract.test.js"]],
  [".", ["--test", "js/__tests__/apex-dashboard-snapshot.test.js"]],
];

const LF = "js/sentinel-live-feeds.js";
const SNAP = "js/apex-dashboard-snapshot.js";
const DC = "workers/intel-gateway/src/dashboard-contract.js";
const WI = "workers/intel-gateway/src/index.js";

// [name, file, find, replace]  -- `find` must occur exactly once.
const CONTROLS = [
  ["IOC total falls back to 1749", "index.html",
    "set('eicc-m-iocs', ok ? i.iocs : 'N/A');", "set('eicc-m-iocs', ok ? (i.iocs || '1749') : 'N/A');"],
  ["active feeds fall back to 74", LF,
    'stats.feeds_active != null ? stats.feeds_active : "N/A"', "stats.feeds_active || 74"],
  ["Math.random() heatmap values", "index.html",
    "var val = rows[k], pct = Math.round((val/maxV)*100);", "var val = rows[k] || Math.round(Math.random()*40), pct = Math.round((val/maxV)*100);"],
  ["hardcoded AI forecasts when the tracker is empty", "index.html",
    "                clear(el);\n                if (!rows.length) {",
    "                if (!rows.length) rows = [{ name: 'Ransomware-as-a-Service escalation', value: '87%', pct: 87, sev: 'CRITICAL' }];\n                clear(el);\n                if (!rows.length) {"],
  ["no country data, fake origin countries shown", "index.html",
    "rows = state.intelligence.sources || {};", "rows = {}; ['RU','CN','IR','KP','US','UA'].forEach(function(c){ rows[c] = 1; });"],
  ["feed has 44 items but the ticker renders empty", SNAP,
    "return { mode: 'live', message: null, items: items, count: state.intelligence.total };",
    "return { mode: 'live', message: null, items: [], count: state.intelligence.total };"],
  ["health fresh but Last Sync blank", SNAP,
    "return { text: rel || 'N/A', utc: p ? utcText(p.generated_at) : null, known: !!rel };",
    "return { text: '\u2014', utc: null, known: false };"],
  ["API alive + stale intelligence shown as fully LIVE", SNAP,
    "else if (state.publication.fresh) intel = { state: 'ok', label: 'INTEL \u25CF FRESH' };",
    "else if (state.api.reachable) intel = { state: 'ok', label: 'INTEL \u25CF FRESH' };"],
  ["stale threat level shown as LIVE", LF,
    "if (!pub || !pub.fresh || !Number.isFinite(rawScore)) {", "if (!Number.isFinite(rawScore)) {"],
  ["feed has MITRE tactics but coverage stays all zero", DC,
    "counts.set(t, counts.get(t) + 1);", "counts.set(t, counts.get(t));"],
  ["a CRITICAL vulnerability counted as a campaign", DC,
    "  const ev = [];\n  for (const f of [\"campaign_id\"", "  const ev = [];\n  if (item.severity === \"CRITICAL\") ev.push(\"severity\");\n  for (const f of [\"campaign_id\""],
  ["an actor label alone counted as a campaign", DC,
    '  if (group && ev.length) ev.push("mitre_group:" + group);', '  if (group) ev.push("mitre_group:" + group);'],
  ["no ransomware data, static group list reported active", DC,
    "    active_groups: active.size,", "    active_groups: (groups || []).length,"],
  ["ransomware classified from description prose", DC,
    '  scan("title", _strings(item.title));', '  scan("title", [..._strings(item.title), ..._strings(item.description)]);'],
  ["placeholder actor label classified as ransomware", DC,
    "      .filter((v) => !UNATTRIBUTED_RE.test(v.trim()) && !/unattr/i.test(v))],", "      ],"],
  ["unescaped malicious title in the preview renderer", LF,
    '${esc(item.title || "Untitled Advisory")}', '${item.title || "Untitled Advisory"}'],
  ["EICC ticker writes a title through innerHTML", "index.html",
    "                        ticker.appendChild(wrap);", "                        ticker.innerHTML += '<span>' + it.title + '</span>';"],
  ["a second script writes an EICC metric", LF,
    "    window._apexStats = stats;", "    setText(\"eicc-m-total\", stats.total, true);\n    window._apexStats = stats;"],
  ["frozen GitHub mirror added as a snapshot fallback", SNAP,
    "  var FEED_URL = '/api/feed.json';", "  var FEED_URL = '/api/feed.json';\n  var FALLBACK_URL = 'https://raw.githubusercontent.com/o/r/main/api/feed.json';"],
  ["service worker caches intelligence cache-first", "service-worker.js",
    "  '/manifest.json',", "  '/manifest.json',\n  '/api/feed.json',"],
  ["EICC template drifts from the shipped block", "scripts/enterprise_intel_block.html",
    "(function eiccEngine(){", "(function eiccEngine(){ var LEGACY = 1;"],
  ["stats route falls back to 74 feeds", WI,
    "const liveFeedCount = (await _liveFeedSourceCount(env)) ?? null;\n    const rawFeed",
    "const liveFeedCount = (await _liveFeedSourceCount(env)) ?? _LEGACY_FEED_COUNT_FALLBACK;\n    const rawFeed"],
  ["synthetic empty feed reported as a fresh publication", WI,
    "evaluatePublicIntelligence(feedData && !feedData._synthetic_empty ? feedData : null, Date.now())",
    "evaluatePublicIntelligence(feedData, Date.now())"],
];

function stage() {
  const dir = mkdtempSync(path.join(tmpdir(), "dash-nc-"));
  for (const rel of COPY) {
    const dest = path.join(dir, rel);
    mkdirSync(path.dirname(dest), { recursive: true });
    cpSync(path.join(REPO, rel), dest, { recursive: true });
  }
  return dir;
}

function suitesPass(dir) {
  for (const [cwd, args] of SUITES) {
    const r = spawnSync(process.execPath, args, { cwd: path.join(dir, cwd), encoding: "utf8" });
    if (r.status !== 0) return false;
  }
  return true;
}

let failures = 0;
const base = stage();
try {
  if (!suitesPass(base)) {
    console.error("BASELINE FAILED: the unmutated copy does not pass; controls would be meaningless.");
    process.exit(1);
  }
  console.log("baseline: unmutated dashboard suites PASS");
} finally {
  rmSync(base, { recursive: true, force: true });
}

for (const [name, file, find, replace] of CONTROLS) {
  const dir = stage();
  try {
    const target = path.join(dir, file);
    const src = readFileSync(target, "utf8");
    const count = src.split(find).length - 1;
    if (count !== 1) {
      console.error(`[BROKEN CONTROL] ${name}: anchor found ${count} times in ${file}`);
      failures++;
      continue;
    }
    writeFileSync(target, src.replace(find, replace));
    if (suitesPass(dir)) {
      console.error(`[NOT CAUGHT] ${name}`);
      failures++;
    } else {
      console.log(`[caught] ${name}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

console.log(`\n${CONTROLS.length - failures}/${CONTROLS.length} dashboard negative controls caught`);
process.exit(failures ? 1 : 0);
