// Customer dashboard frontend contract (P0, 2026-09-24).
//
// Static gate over the customer-facing dashboard runtime: no fabricated
// values, one runtime owner per operational DOM node, no unescaped
// intelligence in markup strings, template == shipped block, and a service
// worker that cannot serve stale intelligence or runtime code.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../../..");
const read = (p) => readFileSync(path.join(REPO, p), "utf8");

const INDEX = read("index.html");
const TEMPLATE = read("scripts/enterprise_intel_block.html");
const LIVE_FEEDS = read("js/sentinel-live-feeds.js");
const SNAPSHOT = read("js/apex-dashboard-snapshot.js");
const SW = read("service-worker.js");

const END_MARKER = "        <!-- \u2500\u2500 END ENTERPRISE INTELLIGENCE COMMAND CENTER v184.0 \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500 -->";
function eiccBlock(src) {
  const end = src.indexOf(END_MARKER);
  const start = src.lastIndexOf('<section id="enterprise-intel-command"', end);
  assert.ok(start > -1 && end > start, "EICC section not found");
  return src.slice(start, end);
}
const EICC = eiccBlock(INDEX);
const EICC_SCRIPT = (() => {
  const i = EICC.indexOf("(function eiccEngine(){");
  assert.ok(i > -1, "eiccEngine not found");
  return EICC.slice(i, EICC.indexOf("</script>", i));
})();

// Customer dashboard modules scanned for fabricated operational values.
const MODULES = {
  "index.html#enterprise-intel-command": EICC,
  "scripts/enterprise_intel_block.html": TEMPLATE,
  "js/sentinel-live-feeds.js": LIVE_FEEDS,
  "js/apex-dashboard-snapshot.js": SNAPSHOT,
};

const FORBIDDEN = [
  [/1749/, "hardcoded IOC total fallback"],
  [/(\|\||\?\?)\s*74\b/, "hardcoded feed-count fallback"],
  [/Math\.random\s*\(/, "random dashboard data"],
  [/Ransomware-as-a-Service escalation|Zero-day exploit broker|State-sponsored supply chain attack|AI-assisted phishing campaign surge/i, "hardcoded AI forecast"],
  [/(probability|confidence)\s*\|\|\s*0\.\d/, "defaulted prediction probability"],
  [/\[\s*['"](?:RU|CN|IR|KP)['"]\s*,\s*['"](?:RU|CN|IR|KP|US|UA)['"]/, "fallback attack-origin country list"],
  [/https?:\/\/raw\.githubusercontent\.com/, "frozen GitHub mirror as a dashboard source"],
  [/items\.length\s*\?\s*['"]API\s*\u25CF\s*LIVE/, "API liveness inferred from item count"],
];

for (const [name, src] of Object.entries(MODULES)) {
  test(`zero-fabrication: ${name}`, () => {
    for (const [re, what] of FORBIDDEN) {
      const m = src.match(re);
      assert.ok(!m, `${name}: ${what} (${re}) near: ${m ? JSON.stringify(src.slice(Math.max(0, m.index - 60), m.index + 60)) : ""}`);
    }
  });
}

test("the EICC template is the shipped index.html block, byte for byte", () => {
  const t = eiccBlock(TEMPLATE);
  assert.equal(t, EICC, "scripts/enterprise_intel_block.html drifted from index.html: re-injection would ship different code");
});

test("EICC engine renders from the shared snapshot, with no fetch of its own for intelligence", () => {
  assert.match(EICC, /<script src="\/js\/apex-dashboard-snapshot\.js"><\/script>\s*<script>\s*\(function eiccEngine\(\)\{/);
  assert.match(EICC_SCRIPT, /SNAP\.load\(/);
  assert.doesNotMatch(EICC_SCRIPT, /['"`][^'"`\n]*(feed\.json|latest\.json|feed_manifest)/, "EICC must not fetch a feed artifact itself");
  assert.doesNotMatch(EICC_SCRIPT, /source_country/, "publisher geography is not attack origin");
  assert.doesNotMatch(EICC_SCRIPT, /risk_score\s*\|\|\s*0\)\s*\/\s*10/, "a 0-10 risk score is not a probability");
});

test("EICC engine builds DOM with textContent only (no innerHTML)", () => {
  assert.doesNotMatch(EICC_SCRIPT, /\.innerHTML\s*=/);
});

test("static markup does not claim LIVE or an active phase before data proves it", () => {
  assert.doesNotMatch(EICC, />\s*API\s*\u25CF\s*LIVE\s*</, "API \u25CF LIVE hardcoded in markup");
  const gauge = INDEX.slice(INDEX.indexOf('id="cdb-g-threat-gauge"'), INDEX.indexOf('<!-- GADGET 2'));
  assert.doesNotMatch(gauge, />\s*\u25CF\s*LIVE\s*</, "threat level badge hardcoded LIVE");
  const rw = INDEX.slice(INDEX.indexOf('id="cdb-g-ransomware"'), INDEX.indexOf('<!-- GADGET 8'));
  assert.doesNotMatch(rw, />\s*\u25CF\s*LIVE\s*</, "ransomware badge hardcoded LIVE");
  assert.doesNotMatch(INDEX, /class="cdb-kc-step active"/, "a kill-chain phase is marked active in static markup");
  assert.match(INDEX, /MITRE ATT&amp;CK TACTIC COVERAGE/);
  assert.doesNotMatch(INDEX, /ATTACK KILL CHAIN COVERAGE &mdash; CLICK TO EXPLORE MITRE ATT&CK/, "hybrid taxonomy labelled as MITRE ATT&CK");
});

test("sentinel-live-feeds escapes every intelligence field it interpolates into markup", () => {
  const plain = /\$\{\s*(?!resp\.)[a-z]\w*\.(title|source|country|name|alias|description|hypothesis|actor|severity|risk|status|sector|cve_id|id|nation)\s*(\|\|\s*"[^"]*"\s*)?\}/g;
  const hits = LIVE_FEEDS.match(plain) || [];
  assert.deepEqual(hits, [], "unescaped interpolation: " + hits.join(", "));
  assert.doesNotMatch(LIVE_FEEDS, /onclick="window\.open\('\$\{/, "URL interpolated into an inline handler");
});

test("sentinel-live-feeds never downloads the full feed for a preview container that is not on the page", () => {
  const fn = LIVE_FEEDS.slice(LIVE_FEEDS.indexOf("async function loadThreatFeedPreview()"), LIVE_FEEDS.indexOf("// \u2500\u2500 4. Cyber Warfare Heatmap"));
  assert.ok(fn.indexOf("if (!containers.length) return;") < fn.indexOf("load("), "container check must precede any load");
  const literal = /['"`][^'"`\n]*latest\.json/;
  assert.doesNotMatch(fn, literal);
  assert.doesNotMatch(LIVE_FEEDS.slice(LIVE_FEEDS.indexOf("async function loadStats()"), LIVE_FEEDS.indexOf("// \u2500\u2500 2. Global Threat Level")), literal);
});

test("threat level shows LIVE only for a fresh publication; campaigns only with evidence semantics", () => {
  const tl = LIVE_FEEDS.slice(LIVE_FEEDS.indexOf("async function loadThreatLevel()"), LIVE_FEEDS.indexOf("function setStatEl("));
  assert.match(tl, /if \(!pub \|\| !pub\.fresh \|\| !Number\.isFinite\(rawScore\)\)/);
  assert.match(tl, /THREAT LEVEL STALE/);
  const kc = LIVE_FEEDS.slice(LIVE_FEEDS.indexOf("async function loadKillChain()"), LIVE_FEEDS.indexOf("// \u2500\u2500 10. AI Cyber Brain"));
  assert.match(kc, /const evidenced = !!data\.campaign_semantics;/);
  const rw = LIVE_FEEDS.slice(LIVE_FEEDS.indexOf("async function loadRansomware()"), LIVE_FEEDS.indexOf("// \u2500\u2500 7. APT Actor Radar"));
  assert.match(rw, /NO RANSOMWARE-TAGGED INTELLIGENCE IN CURRENT FEED/);
  assert.match(rw, /MONITOR \u25CF OPERATIONAL/);
});

// -- Single runtime owner per operational DOM node -------------------------
function scriptUnits() {
  const units = [];
  const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g;
  let m;
  while ((m = re.exec(INDEX))) units.push({ name: "index.html:" + INDEX.slice(0, m.index).split("\n").length, src: m[1] });
  for (const f of readdirSync(path.join(REPO, "js"))) {
    if (f.endsWith(".js")) units.push({ name: "js/" + f, src: read("js/" + f) });
  }
  return units;
}
const UNITS = scriptUnits();
const OWNERS = {
  eicc: ["eicc-ticker-inner", "eicc-ticker-count", "eicc-m-total", "eicc-m-critical", "eicc-m-iocs", "eicc-m-risk",
    "eicc-m-feeds", "eicc-m-sync", "eicc-m-sync-utc", "eicc-m-api", "eicc-m-intel", "eicc-feed-preview",
    "eicc-heatmap", "eicc-heatmap-title", "eicc-heatmap-sub", "eicc-heatmap-updated", "eicc-ai-predictions"],
  "js/sentinel-live-feeds.js": ["cdb-gauge-val", "cdb-gauge-label", "cdb-gauge-status", "cdb-gauge-arc", "cdb-gauge-crit",
    "cdb-gauge-kev", "cdb-gauge-age", "cdb-rw-status", "cdb-rw-groups", "cdb-rw-victims", "cdb-rw-list",
    "cdb-kc-campaigns", "cdb-kc-tactics", "cdb-kc-active-label", "nexus-killchain", "nexus-killchain-meta"],
};

for (const [owner, ids] of Object.entries(OWNERS)) {
  for (const id of ids) {
    test(`single owner: #${id}`, () => {
      const lit = new RegExp(`['"\`]${id.replace(/-/g, "\\-")}['"\`]`);
      const refs = UNITS.filter((u) => lit.test(u.src)).map((u) => u.name);
      assert.equal(refs.length, 1, `#${id} is referenced by ${refs.length} script units: ${refs.join(", ")}`);
      if (owner === "eicc") assert.ok(UNITS.find((u) => u.name === refs[0]).src.includes("function eiccEngine()"), `#${id} owner is not the EICC engine`);
      else assert.equal(refs[0], owner);
    });
  }
}

test("single owner: #nexus-rules-count is written only from real detection_pack counts", () => {
  const refs = UNITS.filter((u) => /['"`]nexus-rules-count['"`]/.test(u.src));
  assert.equal(refs.length, 1);
  const writes = refs[0].src.split("getElementById('nexus-rules-count')").length - 1;
  assert.equal(writes, 1, "a second writer of #nexus-rules-count is back");
  assert.doesNotMatch(refs[0].src, /\* 3; \/\/ sigma \+ yara \+ snort/, "invented rules count");
});

// -- Service worker --------------------------------------------------------
test("service worker: runtime code and intelligence are network-only, cache only fixed static assets", () => {
  const staticList = SW.slice(SW.indexOf("const STATIC_ASSETS"), SW.indexOf("]);", SW.indexOf("const STATIC_ASSETS")));
  const entries = staticList.match(/'[^']+'/g) || [];
  assert.ok(entries.length > 0);
  for (const e of entries) {
    assert.ok(e === "'/manifest.json'" || !/\.js'|\.json'|\/api\/|\.html'/.test(e), `runtime code or data in the cache-first list: ${e}`);
  }
  assert.match(SW, /event\.respondWith\(fetch\(request, \{ cache: 'no-store' \}\)\);\s*\}\);\s*$/, "default route must be network-only");
  assert.match(SW, /key\.startsWith\('sentinel-apex-'\) && key !== CACHE_NAME/, "old caches must be purged on activate");
});

test("service worker Last Sync alias keys on a field the stats route now provides", () => {
  assert.match(SW, /payload\.last_feed_sync_utc/);
  const idx = read("workers/intel-gateway/src/index.js");
  const start = idx.indexOf('if (path === "/api/v1/intel/stats"');
  assert.match(idx.slice(start, start + 2200), /last_feed_sync_utc: publication\.generated_at/);
});
