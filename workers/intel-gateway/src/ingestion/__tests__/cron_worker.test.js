import assert from "node:assert/strict";
import { test } from "node:test";
import {
  normalizeKEV, normalizeURLhaus, normalizeTorExitNodes,
  computeSentinelRiskScore, mergeIndicators, buildIndicatorSummary,
  runScheduledIngestion, getLiveIndicatorsSummary, getLiveIndicators,
  INDICATORS_R2_KEY, SUMMARY_R2_KEY,
} from "../cron_worker.js";

// ---------------------------------------------------------------------------
// Task 4: ingestion parser validation on mocked upstream feed payloads +
// scoring/merge/TTL logic. No live network calls -- runScheduledIngestion's
// own network dependency is exercised via a monkey-patched global fetch,
// restored after each test that uses it.
// ---------------------------------------------------------------------------

// --- normalizeKEV -----------------------------------------------------------

test("normalizeKEV maps CISA KEV vulnerabilities into the common indicator shape", () => {
  const raw = {
    vulnerabilities: [
      { cveID: "cve-2026-00001", vendorProject: "Acme", product: "Widget", vulnerabilityName: "Acme RCE", dateAdded: "2026-08-01", dueDate: "2026-08-22", knownRansomwareCampaignUse: "Known" },
      { cveID: "CVE-2026-00002", vendorProject: "Foo", product: "Bar", dateAdded: "2026-08-15", knownRansomwareCampaignUse: "Unknown" },
    ],
  };
  const out = normalizeKEV(raw);
  assert.equal(out.length, 2);
  assert.equal(out[0].indicator, "CVE-2026-00001"); // uppercased
  assert.equal(out[0].type, "cve");
  assert.equal(out[0].source, "CISA_KEV");
  assert.ok(out[0].tags.includes("ransomware"));
  assert.ok(out[0].tags.includes("kev"));
  assert.equal(out[1].tags.includes("ransomware"), false);
  assert.equal(out[0].meta.vendor_project, "Acme");
});

test("normalizeKEV tolerates missing/malformed input without throwing", () => {
  assert.deepEqual(normalizeKEV(null), []);
  assert.deepEqual(normalizeKEV({}), []);
  assert.deepEqual(normalizeKEV({ vulnerabilities: [{ vendorProject: "no-cve-id" }] }), []);
});

// --- normalizeURLhaus --------------------------------------------------------

test("normalizeURLhaus handles the id-keyed-array-of-one upstream shape", () => {
  const raw = {
    "12345": [{ id: "12345", url: "http://bad.example.com/payload.exe", date_added: "2026-08-20 10:00:00", threat: "malware_download", url_status: "online", tags: ["elf", "mirai"] }],
  };
  const out = normalizeURLhaus(raw);
  assert.equal(out.length, 1);
  assert.equal(out[0].type, "url");
  assert.equal(out[0].source, "URLHAUS");
  assert.equal(out[0].meta.host, "bad.example.com");
  assert.deepEqual(out[0].tags, ["elf", "mirai"]);
});

test("normalizeURLhaus handles a plain array shape and skips entries with no url", () => {
  const raw = [{ url: "http://x.example/a" }, { id: "no-url-field" }];
  const out = normalizeURLhaus(raw);
  assert.equal(out.length, 1);
  assert.equal(out[0].indicator, "http://x.example/a");
});

test("normalizeURLhaus tolerates malformed URLs without throwing", () => {
  const out = normalizeURLhaus([{ url: "not a valid url" }]);
  assert.equal(out.length, 1);
  assert.equal(out[0].meta.host, "");
});

// --- normalizeTorExitNodes ---------------------------------------------------

test("normalizeTorExitNodes keeps only valid IPv4 lines, drops comments/blank lines", () => {
  const text = "# Tor bulk exit list\n1.2.3.4\n\n# comment\n256.1.1.1\nnot-an-ip\n8.8.8.8\n";
  const out = normalizeTorExitNodes(text);
  const ips = out.map(i => i.indicator);
  assert.deepEqual(ips, ["1.2.3.4", "8.8.8.8"]);
  assert.ok(out.every(i => i.type === "ip" && i.source === "TOR_EXIT_NODE"));
});

test("normalizeTorExitNodes tolerates empty/undefined input", () => {
  assert.deepEqual(normalizeTorExitNodes(""), []);
  assert.deepEqual(normalizeTorExitNodes(undefined), []);
});

// --- deterministic evaluation clock -------------------------------------------
// Every TTL / recency test below pins its own evaluation instant and builds
// timestamps as offsets from it. Calendar literals are deliberately avoided:
// a hard-coded last_seen of 2026-08-25 crossed the 30-day TTL on 2026-09-24
// and turned this suite red on its own (production was correct).
const NOW = Date.UTC(2031, 0, 15, 12, 0, 0); // arbitrary fixed instant
const DAY = 86400000;
const TTL = 30 * DAY; // must match cron_worker.js EXPIRY_MS
const at = (msBeforeNow) => new Date(NOW - msBeforeNow).toISOString();
const tor = (ip, lastSeen, extra = {}) => ({
  indicator: ip, type: "ip", source: "TOR_EXIT_NODE", source_confidence: 0.6,
  first_seen: lastSeen, last_seen: lastSeen, sighting_count: 1, tags: ["tor"], meta: {}, ...extra,
});

// --- computeSentinelRiskScore -------------------------------------------------

test("computeSentinelRiskScore stays within 0-100 and ranks sources/recency sensibly", () => {
  const freshKev = { source: "CISA_KEV", last_seen: at(0), sighting_count: 1, tags: ["kev"] };
  const oldTor   = { source: "TOR_EXIT_NODE", last_seen: at(29 * DAY), sighting_count: 1, tags: ["tor"] };

  const kevScore = computeSentinelRiskScore(freshKev, NOW);
  const torScore = computeSentinelRiskScore(oldTor, NOW);

  assert.ok(kevScore >= 0 && kevScore <= 100);
  assert.ok(torScore >= 0 && torScore <= 100);
  assert.ok(kevScore > torScore, `fresh high-confidence KEV (${kevScore}) should outscore a stale Tor node (${torScore})`);
});

test("computeSentinelRiskScore rewards repeat sightings", () => {
  const single = computeSentinelRiskScore({ source: "URLHAUS", last_seen: at(0), sighting_count: 1, tags: [] }, NOW);
  const repeat = computeSentinelRiskScore({ source: "URLHAUS", last_seen: at(0), sighting_count: 20, tags: [] }, NOW);
  assert.ok(repeat > single);
});

test("computeSentinelRiskScore is a pure function of the pinned instant", () => {
  const ind = { source: "URLHAUS", last_seen: at(10 * DAY), sighting_count: 1, tags: [] };
  assert.equal(computeSentinelRiskScore(ind, NOW), computeSentinelRiskScore(ind, NOW));
  assert.ok(computeSentinelRiskScore(ind, NOW) > computeSentinelRiskScore(ind, NOW + 15 * DAY), "recency decays with evaluation time");
});

// --- mergeIndicators ----------------------------------------------------------

test("mergeIndicators upserts a repeat sighting: bumps sighting_count, refreshes last_seen", () => {
  // (A) repeat sighting inside the TTL
  const previous = [tor("1.2.3.4", at(20 * DAY))];
  const incoming = [tor("1.2.3.4", at(1 * DAY), { tags: ["tor", "anonymization"] })];
  const merged = mergeIndicators(previous, incoming, NOW);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].sighting_count, 2);
  assert.equal(merged[0].last_seen, at(1 * DAY));
  assert.deepEqual(new Set(merged[0].tags), new Set(["tor", "anonymization"]));
  assert.equal(typeof merged[0].risk_score, "number");
  assert.equal(merged[0].risk_score, computeSentinelRiskScore(merged[0], NOW), "scored at the same pinned instant");
  assert.equal(merged[0].expires_at, new Date(NOW - 1 * DAY + TTL).toISOString());
});

test("mergeIndicators TTL boundary: exactly 30 days old is retained", () => {
  // (B) documented semantics: `nowMs - lastSeenMs > EXPIRY_MS` drops, so equality is kept
  const merged = mergeIndicators([tor("5.5.5.5", at(TTL))], [], NOW);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].expires_at, new Date(NOW).toISOString());
});

test("mergeIndicators TTL boundary: 30 days + 1 ms is expired", () => {
  // (C)
  assert.deepEqual(mergeIndicators([tor("6.6.6.6", at(TTL + 1))], [], NOW), []);
});

test("mergeIndicators drops items whose timestamp is malformed", () => {
  // (D)
  const bad = [
    tor("7.7.7.1", "not-a-date"),
    tor("7.7.7.2", "2031-13-45T00:00:00Z"),
    { ...tor("7.7.7.3", at(0)), first_seen: undefined, last_seen: undefined },
  ];
  assert.deepEqual(mergeIndicators(bad, [], NOW), []);
});

test("mergeIndicators retains a newly observed indicator", () => {
  // (E)
  const merged = mergeIndicators([], [tor("8.8.8.8", at(0))], NOW);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].indicator, "8.8.8.8");
  assert.equal(merged[0].sighting_count, 1);
});

test("mergeIndicators refreshes a previously-stale indicator when it is sighted again", () => {
  // (F) production semantics: the fresh sighting replaces last_seen before the TTL check
  const merged = mergeIndicators([tor("9.9.9.9", at(45 * DAY), { sighting_count: 3 })], [tor("9.9.9.9", at(0))], NOW);
  assert.equal(merged.length, 1);
  assert.equal(merged[0].sighting_count, 4);
  assert.equal(merged[0].last_seen, at(0));
});

test("mergeIndicators drops a stale previous indicator that was not sighted again", () => {
  // (G)
  const merged = mergeIndicators([tor("4.4.4.4", at(45 * DAY))], [tor("8.8.4.4", at(0))], NOW);
  assert.deepEqual(merged.map(i => i.indicator), ["8.8.4.4"]);
});

test("mergeIndicators result does not depend on the wall clock once nowMs is pinned", () => {
  const prev = [tor("1.1.1.1", at(29 * DAY)), tor("2.2.2.2", at(31 * DAY))];
  const first = JSON.stringify(mergeIndicators(prev, [], NOW));
  const realNow = Date.now;
  try {
    Date.now = () => NOW + 365 * DAY; // a year later on the wall clock
    assert.equal(JSON.stringify(mergeIndicators(prev, [], NOW)), first);
  } finally {
    Date.now = realNow;
  }
});

test("mergeIndicators sorts the result by risk_score descending", () => {
  const ts = at(0);
  const items = [
    { indicator: "a-cve", type: "cve", source: "TOR_EXIT_NODE", source_confidence: 0.6, first_seen: ts, last_seen: ts, sighting_count: 1, tags: [], meta: {} },
    { indicator: "b-cve", type: "cve", source: "CISA_KEV", source_confidence: 0.95, first_seen: ts, last_seen: ts, sighting_count: 1, tags: ["ransomware"], meta: {} },
  ];
  const merged = mergeIndicators([], items, NOW);
  assert.equal(merged[0].source, "CISA_KEV");
  assert.ok(merged[0].risk_score >= merged[1].risk_score);
});

// --- buildIndicatorSummary -----------------------------------------------------

test("buildIndicatorSummary computes by_source/by_type/high_risk_count correctly", () => {
  const items = [
    { indicator: "a", type: "cve", source: "CISA_KEV", risk_score: 90 },
    { indicator: "b", type: "ip", source: "TOR_EXIT_NODE", risk_score: 50 },
    { indicator: "c", type: "url", source: "URLHAUS", risk_score: 71 },
  ];
  const summary = buildIndicatorSummary(items, [{ name: "CISA_KEV", ok: true, items: [1] }], "2026-08-31T00:00:00.000Z");
  assert.equal(summary.total_indicators, 3);
  assert.equal(summary.high_risk_count, 2); // >= 70
  assert.equal(summary.by_source.CISA_KEV, 1);
  assert.equal(summary.by_type.url, 1);
  assert.equal(summary.top_indicators.length, 3);
});

// --- runScheduledIngestion (I/O layer, fetch + R2 mocked) ----------------------

// CodeQL (Incomplete URL substring sanitization) flagged the earlier
// `url.includes("cisa.gov")`-style routing below: a bare substring check
// can't tell "https://www.cisa.gov/..." apart from an attacker-crafted
// "https://evil.example/?x=cisa.gov". These mock fetches only ever see
// URLs this same test file passes to runScheduledIngestion() -- there is
// no untrusted input here -- but parsing the hostname properly rather
// than substring-matching is strictly more correct and closes the
// finding outright instead of arguing it's a false positive.
function hostnameOf(url) {
  try { return new URL(String(url)).hostname; } catch (_) { return ""; }
}

function makeFakeR2() {
  const store = new Map();
  return {
    store,
    async get(key) {
      if (!store.has(key)) return null;
      const text = store.get(key);
      return { text: async () => text };
    },
    async put(key, value) {
      store.set(key, value);
    },
  };
}

test("runScheduledIngestion writes both R2 keys and degrades gracefully when one source fails", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });

  globalThis.fetch = async (url) => {
    const host = hostnameOf(url);
    if (host === "www.cisa.gov") {
      return { ok: true, json: async () => ({ vulnerabilities: [{ cveID: "CVE-2026-99999", dateAdded: "2026-08-01" }] }) };
    }
    if (host === "urlhaus.abuse.ch") {
      throw new Error("simulated URLhaus outage");
    }
    if (host === "check.torproject.org") {
      return { ok: true, text: async () => "1.1.1.1\n2.2.2.2\n" };
    }
    throw new Error(`unexpected URL in test: ${url}`);
  };

  const env = { INTEL_R2: makeFakeR2() };
  const summary = await runScheduledIngestion(env);

  assert.equal(summary.total_indicators, 3); // 1 KEV + 0 URLhaus (failed) + 2 Tor
  assert.ok(env.INTEL_R2.store.has(INDICATORS_R2_KEY));
  assert.ok(env.INTEL_R2.store.has(SUMMARY_R2_KEY));

  const urlhausResult = summary.sources.find(s => s.name === "URLHAUS");
  assert.equal(urlhausResult.ok, false);
  assert.match(urlhausResult.error, /simulated URLhaus outage/);

  const kevResult = summary.sources.find(s => s.name === "CISA_KEV");
  assert.equal(kevResult.ok, true);
  assert.equal(kevResult.ingested, 1);
});

test("runScheduledIngestion upserts against a previous snapshot already in R2", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = async (url) => {
    const host = hostnameOf(url);
    if (host === "www.cisa.gov") return { ok: true, json: async () => ({ vulnerabilities: [] }) };
    if (host === "urlhaus.abuse.ch") return { ok: true, json: async () => ({}) };
    if (host === "check.torproject.org") return { ok: true, text: async () => "3.3.3.3\n" };
    throw new Error(`unexpected URL: ${url}`);
  };

  const env = { INTEL_R2: makeFakeR2() };
  const nowIso = new Date().toISOString();
  await env.INTEL_R2.put(INDICATORS_R2_KEY, JSON.stringify({
    generated_at: nowIso, count: 1,
    items: [{ indicator: "3.3.3.3", type: "ip", source: "TOR_EXIT_NODE", source_confidence: 0.6, first_seen: nowIso, last_seen: nowIso, sighting_count: 5, tags: ["tor"], meta: {} }],
  }));

  const summary = await runScheduledIngestion(env);
  assert.equal(summary.total_indicators, 1);

  const written = JSON.parse(env.INTEL_R2.store.get(INDICATORS_R2_KEY));
  assert.equal(written.items[0].sighting_count, 6); // upserted, not duplicated
});

// --- getLiveIndicatorsSummary / getLiveIndicators (fail-soft reads) ------------

test("getLiveIndicatorsSummary and getLiveIndicators fail soft with no INTEL_R2 binding", async () => {
  assert.equal(await getLiveIndicatorsSummary({}), null);
  assert.deepEqual(await getLiveIndicators({}), []);
});

test("getLiveIndicatorsSummary fails soft on corrupt JSON in R2", async () => {
  const env = { INTEL_R2: makeFakeR2() };
  await env.INTEL_R2.put(SUMMARY_R2_KEY, "{not valid json");
  assert.equal(await getLiveIndicatorsSummary(env), null);
});

test("getLiveIndicators reads back a written snapshot and respects `limit`", async () => {
  const env = { INTEL_R2: makeFakeR2() };
  await env.INTEL_R2.put(INDICATORS_R2_KEY, JSON.stringify({ items: [{ indicator: "a" }, { indicator: "b" }, { indicator: "c" }] }));
  const limited = await getLiveIndicators(env, { limit: 2 });
  assert.equal(limited.length, 2);
});
