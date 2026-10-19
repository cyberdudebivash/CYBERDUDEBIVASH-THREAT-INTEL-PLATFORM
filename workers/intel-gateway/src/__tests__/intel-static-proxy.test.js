import assert from "node:assert/strict";
import { test } from "node:test";
import { handleIntelStaticProxy, INTEL_STATIC_PROXY, publicTlpJsonVerified, weeklyBriefIsCurrent } from "../intel-static-proxy.js";

// ---------------------------------------------------------------------------
// Stage 4 -- CYBERDUDEBIVASH SENTINEL APEX
//
// Contract tests for handleIntelStaticProxy(), the R2-first proxy backing
// GET /api/v1/intel/ai_index.json and
// GET /api/v1/intel/detection_rules_manifest.json (previously bare relative
// static paths -- data/ai_intelligence/ai_index.json and
// data/intelligence/detection_rules/rule_manifest.json -- that only the
// Pages static origin could serve, requiring a full pipeline run + Pages
// publish to refresh; see the function's own header comment in index.js).
// ---------------------------------------------------------------------------

const AI_INDEX_PATH = "/api/v1/intel/ai_index.json";
const RULES_PATH    = "/api/v1/intel/detection_rules_manifest.json";

function fakeR2(store = {}) {
  return {
    calls: [],
    async get(key) {
      this.calls.push(key);
      if (!(key in store)) return null;
      const value = store[key];
      return { body: JSON.stringify(value) };
    },
  };
}

test("unknown path returns null so the caller's dispatcher keeps routing", async () => {
  const result = await handleIntelStaticProxy({}, "/api/v1/intel/does_not_exist.json", "GET");
  assert.equal(result, null);
});

test("non-GET method is rejected with 405", async () => {
  const resp = await handleIntelStaticProxy({}, AI_INDEX_PATH, "POST");
  assert.equal(resp.status, 405);
  assert.equal(resp.headers.get("Allow"), "GET");
});

test("R2 hit returns R2's content directly, without touching gh-pages", async () => {
  const r2 = fakeR2({ "intelligence/ai_index.json": [{ advisory_id: "intel--abc", title: "R2-sourced record", tlp: "TLP:CLEAR" }] });
  const originalFetch = globalThis.fetch;
  let ghPagesFetched = false;
  globalThis.fetch = async () => { ghPagesFetched = true; throw new Error("must not reach gh-pages when R2 has the object"); };
  try {
    const resp = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
    assert.equal(resp.status, 200);
    const body = await resp.json();
    assert.deepEqual(body, [{ advisory_id: "intel--abc", title: "R2-sourced record", tlp: "TLP:CLEAR" }]);
    assert.equal(ghPagesFetched, false);
    assert.deepEqual(r2.calls, ["intelligence/ai_index.json"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("R2 miss denies access without fetching raw GitHub content", async () => {
  const r2 = fakeR2({});
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; throw new Error("raw fallback forbidden"); };
  try {
    const resp = await handleIntelStaticProxy({ INTEL_R2: r2 }, RULES_PATH, "GET");
    assert.equal(resp.status, 503);
    assert.equal(resp.headers.get("cache-control"), "no-store");
    assert.equal(fetched, false);
  } finally { globalThis.fetch = originalFetch; }
});

test("missing R2 binding fails closed without GitHub fallback", async () => {
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; throw new Error("raw fallback forbidden"); };
  try {
    const resp = await handleIntelStaticProxy({}, AI_INDEX_PATH, "GET");
    assert.equal(resp.status, 503);
    assert.equal(fetched, false);
  } finally { globalThis.fetch = originalFetch; }
});

test("R2 outage fails closed rather than exposing upstream contents", async () => {
  const r2 = { async get() { throw new Error("simulated outage"); } };
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; throw new Error("raw fallback forbidden"); };
  try {
    const resp = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
    assert.equal(resp.status, 503);
    assert.equal(fetched, false);
  } finally { globalThis.fetch = originalFetch; }
});

test("restricted nested TLP in R2 is withheld even when the outer document is CLEAR", async () => {
  const r2 = fakeR2({ "intelligence/ai_index.json": {
    tlp: "TLP:CLEAR", items: [{ id: "intel--red", title: "not public", tlp: "TLP:RED", description: "private" }],
  } });
  const res = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
  assert.equal(res.status, 503);
  assert.equal(JSON.stringify(await res.json()).includes("private"), false);
  assert.equal(res.headers.get("cache-control"), "no-store");
});

test("unlabelled advisory with a report ID is not anonymously authorized", async () => {
  const r2 = fakeR2({ "intelligence/ai_index.json": [{ advisory_id: "intel--unverified", title: "Unverified advisory" }] });
  const resp = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
  assert.equal(resp.status, 503);
});

test("all proxied paths are registered with distinct R2 keys and gh paths", () => {
  assert.equal(Object.keys(INTEL_STATIC_PROXY).length, 8);
  assert.equal(INTEL_STATIC_PROXY[AI_INDEX_PATH].r2Key, "intelligence/ai_index.json");
  assert.equal(INTEL_STATIC_PROXY[RULES_PATH].r2Key, "intelligence/detection_rules_manifest.json");
  const r2Keys = Object.values(INTEL_STATIC_PROXY).map((e) => e.r2Key);
  assert.equal(new Set(r2Keys).size, r2Keys.length, "R2 keys must be unique across all entries");
});

// ---------------------------------------------------------------------------
// P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10): 5 new entries
// serving index.html's ENGINE_URLS (nexus/cortex/quantum/sovereign/genesis),
// each with ghBranch: "main" instead of the original two entries' default
// "gh-pages" -- their fallback content was never in the gh-pages deploy
// bundle (build_dist_artifact.py's INCLUDE_DIRS excludes data/ entirely),
// so falling back to gh-pages for these would 404 even when main has a
// servable (if stale) copy.
// ---------------------------------------------------------------------------
const NEXUS_PATH = "/api/v1/intel/nexus_output.json";

test("legacy gh-pages fallback configuration is inert at public read time", async () => {
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; throw new Error("forbidden"); };
  try {
    const resp = await handleIntelStaticProxy({}, AI_INDEX_PATH, "GET");
    assert.equal(resp.status, 503);
    assert.equal(fetched, false);
  } finally { globalThis.fetch = originalFetch; }
});

test("main branch raw fallback is also prohibited", async () => {
  const originalFetch = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; throw new Error("forbidden"); };
  try {
    const resp = await handleIntelStaticProxy({}, NEXUS_PATH, "GET");
    assert.equal(resp.status, 503);
    assert.equal(fetched, false);
  } finally { globalThis.fetch = originalFetch; }
});

test("nexus_output.json prefers R2 over the main-branch fallback", async () => {
  const r2 = fakeR2({ "data/nexus/nexus_output.json": { generated_at: "fresh-from-r2" } });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error("must not reach main branch when R2 has the object"); };
  try {
    const resp = await handleIntelStaticProxy({ INTEL_R2: r2 }, NEXUS_PATH, "GET");
    assert.deepEqual(await resp.json(), { generated_at: "fresh-from-r2" });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("all 5 new engine routes are registered with ghBranch main and path-mirrored R2 keys", () => {
  for (const [path, r2Key] of [
    ["/api/v1/intel/nexus_output.json", "data/nexus/nexus_output.json"],
    ["/api/v1/intel/genesis_output.json", "data/genesis/genesis_output.json"],
    ["/api/v1/intel/cortex_output.json", "data/cortex/cortex_output.json"],
    ["/api/v1/intel/quantum_output.json", "data/quantum/quantum_output.json"],
    ["/api/v1/intel/sovereign_output.json", "data/sovereign/sovereign_output.json"],
  ]) {
    const entry = INTEL_STATIC_PROXY[path];
    assert.ok(entry, `${path} must be registered`);
    assert.equal(entry.r2Key, r2Key);
    assert.equal(entry.ghPath, r2Key);
    assert.equal(entry.ghBranch, "main");
  }
});

// ---------------------------------------------------------------------------
// Stage 4 deployment-decoupling proof (report Section 13/30): the SAME
// handler, with no code change between calls, must reflect a runtime data
// change immediately -- proving the frontend/API contract does not require
// a git commit or Pages deploy to pick up new intelligence.
// ---------------------------------------------------------------------------
test("DEPLOYMENT-DECOUPLING PROOF: changing R2's stored object changes the response with zero code change", async () => {
  const store = { "intelligence/ai_index.json": [{ advisory_id: "intel--v1", title: "before update", tlp: "TLP:CLEAR" }] };
  const r2 = fakeR2(store);
  const env = { INTEL_R2: r2 };

  const before = await handleIntelStaticProxy(env, AI_INDEX_PATH, "GET");
  assert.deepEqual(await before.json(), [{ advisory_id: "intel--v1", title: "before update", tlp: "TLP:CLEAR" }]);

  // Simulates the real production path: scripts/r2_upload.py's Upload 3c
  // step writing a freshly-generated file straight to R2 -- no git commit,
  // no Pages deploy, same handler code as the call above.
  store["intelligence/ai_index.json"] = [{ advisory_id: "intel--v2", title: "after runtime update, no deploy", tlp: "TLP:CLEAR" }];

  const after = await handleIntelStaticProxy(env, AI_INDEX_PATH, "GET");
  assert.deepEqual(await after.json(), [{ advisory_id: "intel--v2", title: "after runtime update, no deploy", tlp: "TLP:CLEAR" }]);
});


test("invalid, mixed, and legacy classifications never return bytes", async () => {
  for (const tlp of ["TLP:AMBER", "TLP:GREEN", "TLP:AMBER+STRICT", "TLP:WHITE", "TLP:INVALID", null]) {
    const data = [{ id: "test", title: "advisory", advisory_id: "intel--test", tlp }];
    const r2 = fakeR2({ "intelligence/ai_index.json": data });
    const resp = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
    assert.equal(resp.status, 503, String(tlp));
    assert.equal(JSON.stringify(await resp.json()).includes("advisory"), false);
  }
});

test("ambiguous document classification CLEAR and RED is withheld", async () => {
  const r2 = fakeR2({ "intelligence/ai_index.json": {
    classification: "TLP:CLEAR; TLP:RED",
    internal_note: "restricted-information",
  } });
  const resp = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
  assert.equal(resp.status, 503);
  assert.equal(JSON.stringify(await resp.json()).includes("restricted-information"), false);
});

test("invalid or oversized R2 JSON fails closed", async () => {
  const bad = { async get() { return { body: "{invalid" }; } };
  assert.equal((await handleIntelStaticProxy({ INTEL_R2: bad }, AI_INDEX_PATH, "GET")).status, 503);
  const oversize = { async get() { return { size: 1048577, body: "{}" }; } };
  assert.equal((await handleIntelStaticProxy({ INTEL_R2: oversize }, AI_INDEX_PATH, "GET")).status, 503);
});


test("P0 #725: id-only unlabelled advisory cannot bypass the edge gate", async () => {
  const hidden = "opaque-private-evidence";
  const r2 = fakeR2({ "intelligence/ai_index.json": [{ id: "intel--unlabelled", title: "Unknown report", description: hidden }] });
  const response = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
  assert.equal(response.status, 503);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(JSON.stringify(await response.json()).includes(hidden), false);
});

test("P0 #725: conflicting document TLP after an ordinary classification prefix is withheld", async () => {
  for (const classification of ["INTERNAL: TLP:RED", "INFO TLP:CLEAR; TLP:AMBER", "NOTES: TLP:GREEN"]) {
    const r2 = fakeR2({ "intelligence/ai_index.json": { classification, sensitive: "opaque-private-evidence" } });
    const response = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
    assert.equal(response.status, 503, classification);
    assert.equal(JSON.stringify(await response.json()).includes("opaque-private-evidence"), false);
  }
});

test("P0 #725: scalar JSON is not an authorized intelligence document", async () => {
  const r2 = fakeR2({ "intelligence/ai_index.json": "opaque-private-evidence" });
  const response = await handleIntelStaticProxy({ INTEL_R2: r2 }, AI_INDEX_PATH, "GET");
  assert.equal(response.status, 503);
  assert.equal(JSON.stringify(await response.json()).includes("opaque-private-evidence"), false);
});


test("P0 #725: shared report TLP authority requires explicit CLEAR and checks every upstream classification", () => {
  assert.equal(publicTlpJsonVerified({ id: "intel--1", title: "Reviewed", tlp: "TLP:CLEAR" }), true);
  assert.equal(publicTlpJsonVerified({ id: "intel--1", title: "Unknown" }), false);
  assert.equal(publicTlpJsonVerified({ id: "intel--1", title: "Restricted", tlp: "TLP:RED" }), false);
  assert.equal(publicTlpJsonVerified({ id: "intel--1", title: "Mixed", tlp: "TLP:CLEAR",
    evidence_chain: [{ tlp: "TLP:AMBER" }] }), false);
  assert.equal(publicTlpJsonVerified({ id: "intel--1", title: "Conflicted", tlp: "TLP:CLEAR",
    classification: "Internal: TLP:GREEN" }), false);
  assert.equal(publicTlpJsonVerified({ id: "intel--1", title: "Legacy", tlp: "TLP:WHITE" }), false);
  assert.equal(publicTlpJsonVerified({ id: "intel--1", title: "Invalid", tlp: "TLP:CLEAR\u200b" }), false);
  assert.equal(publicTlpJsonVerified(null), false);
  assert.equal(publicTlpJsonVerified("raw secret"), false);
});


test("P0 2026-10-14: real Worker accepts 30k CLEAR leaf visits while preserving classification", async () => {
  const doc = { generated_at: "2026-10-14T06:00:00Z", count: 1,
    items: [{ id: "intel--public", title: "Reviewed", tlp: "TLP:CLEAR",
      auxiliary: Array(30000).fill("x") }] };
  assert.equal(publicTlpJsonVerified(doc), true);
  // The actual R2 proxy should also allow this bounded document.
  const resp = await handleIntelStaticProxy(
    { INTEL_R2: fakeR2({ "intelligence/ai_index.json": doc }) }, AI_INDEX_PATH, "GET");
  assert.equal(resp.status, 200);
});

test("P0 2026-10-14: restricted marker after 30k scalar leaves is never published", async () => {
  const doc = { items: [{ id: "intel--public", title: "Reviewed", tlp: "TLP:CLEAR",
    auxiliary: Array(30000).fill("x"),
    hidden: { id: "intel--restricted", title: "Not for release", tlp: "TLP:GREEN", data: "CDB_PRIVATE_SENTINEL" } }] };
  assert.equal(publicTlpJsonVerified(doc), false);
  const resp = await handleIntelStaticProxy(
    { INTEL_R2: fakeR2({ "intelligence/ai_index.json": doc }) }, AI_INDEX_PATH, "GET");
  assert.equal(resp.status, 503);
  assert.equal(JSON.stringify(await resp.json()).includes("CDB_PRIVATE_SENTINEL"), false);
});

test("P0 2026-10-14: more than 100k visited values still fails closed", () => {
  const doc = [{ id: "intel--public", title: "Reviewed", tlp: "TLP:CLEAR",
    auxiliary: Array(101000).fill("x") }];
  assert.equal(publicTlpJsonVerified(doc), false);
});

test("P0 2026-10-14: max depth and body cap remain fail-closed", async () => {
  let nested = { tlp: "TLP:RED", restricted: true };
  for (let i = 0; i < 42; i++) nested = { child: nested };
  assert.equal(publicTlpJsonVerified({ id: "intel--c", title: "outer", tlp: "TLP:CLEAR", nested }), false);

  const oversized = { items: [{ id: "intel--c", title: "outer", tlp: "TLP:CLEAR",
    blob: "x".repeat(1048576) }] };
  const res = await handleIntelStaticProxy(
    { INTEL_R2: fakeR2({ "intelligence/ai_index.json": oversized }) }, AI_INDEX_PATH, "GET");
  assert.equal(res.status, 503);
});


// P0 19-Oct-2026 \u2014 contract for a completed ISO weekly edition.
// A current main feed cannot confer freshness on a stale weekly artifact.
const WEEKLY_BRIEF_PATH = "/api/v1/intel/weekly_brief.json";
function week42PublicBrief() {
  return {
    _schema: "sentinel-apex-weekly-brief-v1",
    week: "Week 42 2026",
    period: "12 Oct 2026 \u2014 18 Oct 2026",
    generated_at: "2026-10-19T02:30:00Z",
    stats: { total_advisories: 1, critical_count: 0, kev_additions: 0 },
    top_threats: [{
      rank: 1, title: "Verified public weekly item", cve_id: "CVE-2026-1001",
      report_url: "https://intel.cyberdudebivash.com/reports/2026/10/verified.html",
      tlp: "TLP:CLEAR", severity: "MEDIUM", risk_score: 4.0,
    }],
    kev_additions: [],
  };
}
test("weekly route is registered with its canonical, unique R2 key", () => {
  assert.equal(INTEL_STATIC_PROXY[WEEKLY_BRIEF_PATH].r2Key, "api/v1/intel/weekly_brief.json");
});
test("weekly freshness requires the previous completed ISO week and matching period", () => {
  const monday = Date.parse("2026-10-19T04:00:00Z");
  const doc = week42PublicBrief();
  assert.equal(weeklyBriefIsCurrent(doc, monday), true);
  assert.equal(weeklyBriefIsCurrent({...doc, week:"Week 43 2026"}, monday), false);
  assert.equal(weeklyBriefIsCurrent({...doc, period:"19 Oct 2026 \u2014 25 Oct 2026"}, monday), false);
  assert.equal(weeklyBriefIsCurrent({...doc, generated_at:"2026-08-24T03:31:03Z"}, monday), false);
  assert.equal(weeklyBriefIsCurrent({...doc, top_threats:[]}, monday), false);
  assert.equal(weeklyBriefIsCurrent(doc, Date.parse("2026-10-26T00:01:00Z")), false);
});
test("weekly API returns verified public edition and never a historical fallback", async () => {
  const originalNow = Date.now;
  Date.now = () => Date.parse("2026-10-19T04:00:00Z");
  try {
    const r2 = fakeR2({"api/v1/intel/weekly_brief.json":week42PublicBrief()});
    const good = await handleIntelStaticProxy({INTEL_R2:r2}, WEEKLY_BRIEF_PATH, "GET");
    assert.equal(good.status, 200);
    assert.equal((await good.json()).week, "Week 42 2026");
    assert.deepEqual(r2.calls, ["api/v1/intel/weekly_brief.json"]);
    const missing = await handleIntelStaticProxy({INTEL_R2:fakeR2()}, WEEKLY_BRIEF_PATH, "GET");
    assert.equal(missing.status, 503);
    assert.equal(missing.headers.get("cache-control"), "no-store");
    const stale = week42PublicBrief();
    stale.generated_at = "2026-08-24T03:31:03Z";
    const bad = await handleIntelStaticProxy({
      INTEL_R2:fakeR2({"api/v1/intel/weekly_brief.json":stale})
    }, WEEKLY_BRIEF_PATH, "GET");
    assert.equal(bad.status, 503);
    const restricted = week42PublicBrief();
    restricted.top_threats[0].tlp = "TLP:AMBER";
    const denied = await handleIntelStaticProxy({
      INTEL_R2:fakeR2({"api/v1/intel/weekly_brief.json":restricted})
    }, WEEKLY_BRIEF_PATH, "GET");
    assert.equal(denied.status, 503);
    assert.equal(denied.headers.get("cache-control"), "no-store");
  } finally {
    Date.now = originalNow;
  }
});
