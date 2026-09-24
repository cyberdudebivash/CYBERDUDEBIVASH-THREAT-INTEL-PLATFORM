/**
 * CYBER WATCHDOG PR-B -- Watch Definition v2, Exposure Profile v1, Customer
 * Relevance, Queue Rank and Evidence Snapshots.
 *
 * Drives the real gateway router and the real WatchdogLedger /
 * WatchdogScheduler Durable Object classes via the harness. Source is ASCII
 * only: every non-ASCII test value is written as a \\u escape (the deploy
 * sanitizer rewrites non-ASCII literals in gateway test files).
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  ENT_KEY, MSSP_A_ONLY_KEY, MSSP_KEY, PRO2_KEY, PRO_KEY, craftJwt, feedObject, harness,
} from "./watchdog-harness.js";
import { matchDefinitionV2, normalizeDefinitionV2, ruleLines } from "../watchdog-definition.js";
import {
  RELEVANCE_LABELS, SNAPSHOT_MAX_BYTES, buildEvidenceSnapshot, computeQueueRank, computeRelevance, normalizeProfile,
} from "../watchdog-relevance.js";
import { computeEventPriority } from "../watchdog-priority.js";
import {
  EVENT_RETENTION, applyLedgerMutation, candidateEvent, emptyLedgerState, filterEvents, matchWatch,
  parseInboxQuery, projectItem,
} from "../cyber-watchdog.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, "../../../..");

// Value shapes taken from the live production feed (2026-09-24).
const KEV_MS = {
  id: "intel--kev-ms", title: "Microsoft ADFS flaw actively exploited (CVE-2026-2001)", description: "CISA added the flaw to KEV.",
  severity: "CRITICAL", source: "CISA KEV", cve_ids: ["CVE-2026-2001"], cvss_score: 9.8, epss_score: 86, kev_present: true,
  kev_product: "Microsoft Active Directory Federation Services", processed_at: "2026-09-24T05:00:00Z", tags: ["kev", "cisa"],
};
const F5 = {
  id: "intel--kev-f5", title: "F5 BIG-IP APM heap overflow", description: "Vendor advisory.",
  severity: "HIGH", source: "CISA KEV", cve_ids: ["CVE-2026-2002"], cvss_score: 8.1, kev_present: true,
  kev_product: "F5 BIG-IP APM", processed_at: "2026-09-24T05:01:00Z", tags: [],
};
const NPM = {
  id: "intel--ghsa-npm", title: "elysia has Inefficient Algorithmic Complexity", description: "GitHub advisory for the elysia package.",
  severity: "MEDIUM", source: "GitHub Security Advisories", cve_ids: ["CVE-2026-2003"], cvss_score: 5.3, epss_score: 0.63, kev: "NO",
  processed_at: "2026-09-24T05:02:00Z", tags: ["npm:elysia"],
};
const NEWS = {
  id: "intel--news-ms", title: "Microsoft Patches a Record 570 Security Flaws", description: "Monthly patch round-up.",
  severity: "HIGH", source: "BleepingComputer", cve_ids: [], kev: "NO", processed_at: "2026-09-24T05:03:00Z", tags: ["Security News"],
};
const BLOG = {
  id: "intel--blog", title: "Kubernetes operator best practices", description: "No CVE.", source: "Blog",
  processed_at: "2026-09-24T05:04:00Z", tags: [],
};
const FEED = [KEV_MS, F5, NPM, NEWS, BLOG];

const def = (criteria, logic = "AND", extra = {}) => ({ version: 2, name: "t", logic, criteria, ...extra });
const norm = (criteria, logic, extra) => normalizeDefinitionV2(def(criteria, logic, extra));
const hit = (criteria, item, logic = "AND") => {
  const d = norm(criteria, logic);
  assert.ok(!d.error, JSON.stringify(d));
  return matchWatch({ ...d.definition, id: "w_t" }, projectItem(item)).matched;
};

async function session(h, key, tenant) {
  const q = tenant ? "?tenant=" + encodeURIComponent(tenant) : "";
  const res = await h.call("POST", "/api/watchdog/session" + q, { key });
  assert.equal(res.status, 200, JSON.stringify(res.body));
  return res.body.token;
}

// ---------------------------------------------------------------------------
// Phase 4 / 24: input security
// ---------------------------------------------------------------------------

test("definition v2: refuses owner/tenant/subject spoofing, unsupported and unsafe criteria, prototype keys", () => {
  for (const extra of [{ owner: "cust_pro_2" }, { subject: "x" }, { tenant: "CANARY-B" }, { customer_id: "c" }]) {
    assert.equal(norm({ keywords: ["x"] }, "AND", extra).error, "unsupported_field", JSON.stringify(extra));
  }
  // Fields the schema audit found absent or placeholder-only are not accepted.
  for (const key of ["actors", "malware_families", "sectors", "countries", "exploit_maturity", "vendor"]) {
    assert.equal(norm({ [key]: ["x"] }).error, "unsupported_criterion", key);
  }
  for (const raw of ['{"version":2,"name":"x","criteria":{"__proto__":{"polluted":1}}}', '{"version":2,"name":"x","criteria":{"constructor":["x"]}}', '{"version":2,"name":"x","__proto__":{"a":1},"criteria":{"keywords":["x"]}}']) {
    const out = normalizeDefinitionV2(JSON.parse(raw));
    assert.ok(out.error === "unsupported_criterion" || out.error === "unsupported_field", raw + " -> " + JSON.stringify(out));
  }
  assert.equal({}.polluted, undefined);
  assert.equal(norm({ keywords: ["x"] }, "XOR").error, "unsupported_operator");
  assert.equal(norm({ keywords: ["x"] }, "NOT").error, "unsupported_operator");
  assert.equal(normalizeDefinitionV2({ version: 3, name: "x", criteria: { keywords: ["x"] } }).error, "unsupported_version");
  assert.equal(norm({}).error, "invalid_watch");
});

test("definition v2: bounds and numeric validation (NaN, Infinity, negatives, CVSS > 10, EPSS range, string numbers)", () => {
  assert.equal(norm({ keywords: Array.from({ length: 9 }, (_, i) => "k" + i) }).error, "too_many_values");
  const many = { keywords: Array.from({ length: 8 }, (_, i) => "k" + i), cves: Array.from({ length: 8 }, (_, i) => "CVE-2026-100" + i), vendors: Array.from({ length: 8 }, (_, i) => "v" + i), products: Array.from({ length: 8 }, (_, i) => "p" + i), techniques: Array.from({ length: 8 }, (_, i) => "T100" + i), sources: ["s1"] };
  assert.equal(norm(many).error, "too_many_values");
  assert.equal(normalizeDefinitionV2({ version: 2, name: "x".repeat(81), criteria: { keywords: ["a"] } }).error, "invalid_watch");
  assert.equal(norm({ keywords: ["x".repeat(49)] }).error, "invalid_value");
  assert.equal(norm({ cves: ["CVE-26-1"] }).error, "invalid_value");
  assert.equal(norm({ cves: ["cve-2026-1000"] }).definition.criteria.cves[0], "CVE-2026-1000");
  assert.equal(norm({ severity_min: "SEVERE" }).error, "invalid_severity");
  for (const bad of [NaN, Infinity, -Infinity, -0.1, 10.01, "7", null === 0]) {
    const out = norm({ cvss_min: bad });
    assert.equal(out.error, typeof bad === "boolean" ? "invalid_threshold" : "invalid_threshold", String(bad));
  }
  for (const bad of [1.01, -0.01, NaN, Infinity, "0.5"]) assert.equal(norm({ epss_min: bad }).error, "invalid_threshold", String(bad));
  assert.equal(norm({ kev: "yes" }).error, "invalid_criterion");
  assert.equal(norm({ keywords: "ransomware" }).error, "invalid_criterion");
  assert.equal(norm({ techniques: ["T1566.02"] }).error, "invalid_value");
  assert.equal(norm({ packages: ["elysia"] }).error, "invalid_value", "package ids must be ecosystem:name");
});

test("definition v2: Unicode stays supported; normalization and homoglyphs are safe", () => {
  // Fullwidth "Microsoft" (NFKC -> microsoft) matches the KEV vendor.
  const fullwidth = "\uff2d\uff49\uff43\uff52\uff4f\uff53\uff4f\uff46\uff54";
  assert.equal(hit({ vendors: [fullwidth] }, KEV_MS), true);
  // Zero-width space and a bidi override are stripped, not matched literally.
  assert.equal(hit({ vendors: ["Micro\u200bsoft"] }, KEV_MS), true);
  assert.equal(norm({ keywords: ["\u202e\u202d"] }).error, "invalid_value", "an all-invisible value is empty");
  // A Cyrillic capital EM homoglyph is a different character: no match.
  assert.equal(hit({ vendors: ["\u041cicrosoft"] }, KEV_MS), false);
  // Non-Latin customer values are accepted and match themselves.
  const zurich = { ...BLOG, id: "intel--zurich", title: "Z\u00fcrich Versicherung patches portal" };
  assert.equal(hit({ keywords: ["z\u00fcrich"] }, zurich), true);
  assert.equal(norm({ keywords: ["\u6771\u4eac"] }).definition.criteria.keywords[0], "\u6771\u4eac");
});

test("definition v2: malicious keyword strings are inert text, never code or regex", () => {
  const xss = norm({ keywords: ["<script>alert(1)</script>"] }).definition.criteria.keywords[0];
  assert.ok(!/[<>]/.test(xss), xss);
  assert.equal(norm({ keywords: [".*"] }).error, "invalid_value", "punctuation-only values carry no token");
  // "a|b" is the two tokens a, b -- not an alternation.
  assert.equal(hit({ keywords: ["kubernetes|nothing"] }, BLOG), false);
  assert.equal(hit({ keywords: ["(a+)+$"] }, BLOG), false);
  const src = fs.readFileSync(path.join(HERE, "../watchdog-definition.js"), "utf8");
  assert.doesNotMatch(src, /new RegExp|eval\(|Function\(/, "no dynamic code or regex from customer input");
});

// ---------------------------------------------------------------------------
// Phase 25: adversarial matching
// ---------------------------------------------------------------------------

test("matching: vendor/product are whole-token identifiers, never substrings", () => {
  assert.equal(hit({ vendors: ["Microsoft"] }, KEV_MS), true);
  assert.equal(hit({ vendors: ["MICROSOFT"] }, KEV_MS), true, "case-insensitive");
  assert.equal(hit({ vendors: ["Micro"] }, KEV_MS), false, "partial vendor name");
  assert.equal(hit({ vendors: ["Microsoft Corp"] }, KEV_MS), false, "similar vendor name");
  assert.equal(hit({ vendors: ["Active Directory"] }, KEV_MS), false, "vendor must be the leading tokens");
  assert.equal(hit({ products: ["Federation Services"] }, KEV_MS), true);
  assert.equal(hit({ products: ["Federation Serv"] }, KEV_MS), false);
  assert.equal(hit({ vendors: ["Microsoft"] }, NEWS), false, "a title mention is not a KEV vendor identifier");
  assert.equal(hit({ keywords: ["Microsoft"] }, NEWS), true, "keywords are the explicit text criterion");
  assert.equal(hit({ packages: ["npm:elysia"] }, NPM), true);
  assert.equal(hit({ packages: ["npm:elysi"] }, NPM), false);
  assert.equal(hit({ packages: ["pip:elysia"] }, NPM), false, "ecosystem is part of the identifier");
  assert.equal(hit({ sources: ["GitHub"] }, NPM), false, "source is exact, not substring");
  assert.equal(hit({ sources: ["github security advisories"] }, NPM), true);
});

test("matching: CVE equality, thresholds at their boundaries, KEV tri-state, AND vs OR", () => {
  assert.equal(hit({ cves: ["CVE-2026-2001"] }, KEV_MS), true);
  assert.equal(hit({ cves: ["CVE-2026-20011"] }, KEV_MS), false);
  assert.equal(hit({ severity_min: "CRITICAL" }, KEV_MS), true);
  assert.equal(hit({ severity_min: "CRITICAL" }, F5), false);
  assert.equal(hit({ cvss_min: 9.8 }, KEV_MS), true);
  assert.equal(hit({ cvss_min: 9.81 }, KEV_MS), false);
  assert.equal(hit({ cvss_min: 1 }, BLOG), false, "missing CVSS never satisfies a threshold");
  assert.equal(hit({ epss_min: 0.86 }, KEV_MS), true, "86 percent");
  assert.equal(hit({ epss_min: 0.5 }, NPM), false, "0.63 percent is not 50 percent");
  assert.equal(hit({ kev: true }, KEV_MS), true);
  assert.equal(hit({ kev: true }, NPM), false);
  assert.equal(hit({ kev: false }, NPM), true, "feed says kev NO");
  assert.equal(hit({ kev: false }, BLOG), false, "unknown KEV is neither yes nor no");
  assert.equal(hit({ vendors: ["Microsoft"], severity_min: "HIGH", kev: true }, KEV_MS, "AND"), true);
  assert.equal(hit({ vendors: ["F5"], severity_min: "CRITICAL" }, F5, "AND"), false);
  assert.equal(hit({ vendors: ["F5"], severity_min: "CRITICAL" }, F5, "OR"), true);
});

test("v1 compatibility: legacy watches keep the original matcher (substring semantics unchanged)", () => {
  const v1 = { id: "w_v1", name: "legacy", logic: "OR", enabled: true, criteria: { vendors: ["micro"] } };
  assert.equal(matchWatch(v1, projectItem(KEV_MS)).matched, true, "v1 vendors stay substring, as before");
  const v2 = { ...norm({ vendors: ["micro"] }).definition, id: "w_v2" };
  assert.equal(matchWatch(v2, projectItem(KEV_MS)).matched, false);
});

test("rollback safety: a stored v2 watch is inert for code that predates v2 (never re-interpreted)", () => {
  let state = applyLedgerMutation(emptyLedgerState(), { subject: "s", tier: "PRO", type: "create_watch", id: "abc", now: "2026-09-24T00:00:00Z", watch: { version: 2, name: "KEV or high", logic: "OR", criteria: { kev: true, severity_min: "HIGH", vendors: ["micro"] } } }).state;
  const stored = state.watches[0];
  assert.deepEqual(stored.criteria, {}, "pre-v2 code reads only `criteria`: it must be empty");
  assert.ok(stored.v2_criteria.kev === true);
  // Pre-v2 code has no `version` branch: it runs the v1 matcher on `criteria`.
  const { version: _v, ...asPreV2Sees } = stored;
  for (const item of [KEV_MS, F5, NPM, NEWS, BLOG]) assert.equal(matchWatch(asPreV2Sees, projectItem(item)).matched, false, item.id);
  // Current code still matches it as v2.
  assert.equal(matchWatch(stored, projectItem(F5)).matched, true);
  const pub = applyLedgerMutation(state, { subject: "s", type: "get" }).result.watches[0];
  assert.equal(pub.criteria.kev, true, "the public shape shows the v2 criteria");
  // Enabled-only and full edits keep the inert layout.
  state = applyLedgerMutation(state, { subject: "s", tier: "PRO", type: "update_watch", id: stored.id, now: "2026-09-24T00:01:00Z", watch: { enabled: false } }).state;
  assert.deepEqual(state.watches[0].criteria, {});
  state = applyLedgerMutation(state, { subject: "s", tier: "PRO", type: "update_watch", id: stored.id, now: "2026-09-24T00:02:00Z", watch: { name: "renamed", criteria: { cves: ["CVE-2026-2002"] } } }).state;
  assert.deepEqual(state.watches[0].criteria, {});
  assert.deepEqual(state.watches[0].v2_criteria, { cves: ["CVE-2026-2002"] });
});

test("rule preview text states exactly what will match", () => {
  const d = norm({ vendors: ["Microsoft"], severity_min: "HIGH", kev: true, epss_min: 0.5 }).definition;
  assert.deepEqual(ruleLines(d), { logic: "AND", lines: ["CISA KEV vendor is Microsoft", "Severity is HIGH or higher", "EPSS is 50% or higher", "CISA KEV listed = YES"] });
});

// ---------------------------------------------------------------------------
// Phases 5, 8, 9, 11: profile, relevance, queue rank
// ---------------------------------------------------------------------------

test("exposure profile: validation, bounds, owner spoofing refused", () => {
  assert.equal(normalizeProfile({ owner: "cust_pro_2", vendors: ["Microsoft"] }).error, "unsupported_field");
  assert.equal(normalizeProfile({ tenant: "CANARY-B", vendors: ["Microsoft"] }).error, "unsupported_field");
  assert.equal(normalizeProfile(JSON.parse('{"__proto__":{"x":1},"vendors":["a"]}')).error, "unsupported_field");
  assert.equal(normalizeProfile({}).error, "invalid_profile");
  assert.equal(normalizeProfile({ vendors: Array.from({ length: 26 }, (_, i) => "v" + i) }).error, "too_many_values");
  assert.equal(normalizeProfile({ vendors: Array.from({ length: 25 }, (_, i) => "v" + i), products: Array.from({ length: 25 }, (_, i) => "p" + i), technologies: Array.from({ length: 25 }, (_, i) => "t" + i), packages: Array.from({ length: 25 }, (_, i) => "npm:p" + i + "x") }).error, undefined);
  assert.equal(normalizeProfile({ vendors: Array.from({ length: 25 }, (_, i) => "v" + i), products: Array.from({ length: 25 }, (_, i) => "p" + i), technologies: Array.from({ length: 25 }, (_, i) => "t" + i), packages: Array.from({ length: 25 }, (_, i) => "npm:p" + i + "x") }).profile.vendors.length, 25);
  assert.equal(normalizeProfile({ packages: ["elysia"] }).error, "invalid_value");
  assert.equal(normalizeProfile({ vendors: ["<img src=x onerror=alert(1)>"] }).profile.vendors[0].includes("<"), false);
});

test("relevance: structured identifiers MATCH, text is only MENTIONED, threat priority never changes", () => {
  const profile = normalizeProfile({ vendors: ["Microsoft"], packages: ["npm:elysia"], technologies: ["Kubernetes"] }).profile;
  const ms = computeRelevance(projectItem(KEV_MS), profile);
  assert.equal(ms.level, "MATCHED");
  assert.deepEqual(ms.reasons[0], { type: "vendor", basis: "identifier", profile_value: "Microsoft", feed_field: "kev_product", feed_value: "Microsoft Active Directory Federation Services" });
  assert.equal(computeRelevance(projectItem(NPM), profile).reasons[0].feed_field, "tags");
  const news = computeRelevance(projectItem(NEWS), profile);
  assert.equal(news.level, "MENTIONED", "a title mention is weaker than an identifier");
  assert.equal(news.reasons[0].basis, "text_mention");
  assert.equal(computeRelevance(projectItem(BLOG), profile).level, "MENTIONED");
  assert.equal(computeRelevance(projectItem(F5), profile).level, "NOT_MATCHED");
  assert.equal(computeRelevance(projectItem(KEV_MS), null).level, "NO_PROFILE");
  // Threat priority is computed from the item only.
  assert.deepEqual(computeEventPriority(projectItem(KEV_MS)), computeEventPriority(projectItem(KEV_MS)));
  const ev = candidateEvent({ ...norm({ keywords: ["microsoft"] }).definition, id: "w_1" }, projectItem(NEWS), "g", "2026-09-24T00:00:00Z", "request", profile);
  assert.equal(ev.severity, "HIGH", "upstream severity is never rewritten");
  assert.deepEqual(ev.priority.band, computeEventPriority(projectItem(NEWS)).band);
});

test("queue rank: deterministic customer order; bands stay visible and separate", () => {
  const q = (band, level) => computeQueueRank({ band }, { level }).score;
  const order = [["CRITICAL", "MATCHED"], ["HIGH", "MATCHED"], ["CRITICAL", "NOT_MATCHED"], ["MEDIUM", "MATCHED"], ["HIGH", "NOT_MATCHED"], ["LOW", "MATCHED"], ["MEDIUM", "NOT_MATCHED"]];
  const scores = order.map(([b, l]) => q(b, l));
  assert.deepEqual(scores, [55, 45, 40, 35, 30, 25, 20]);
  assert.equal(q("HIGH", "NO_PROFILE"), q("HIGH", "NOT_MATCHED"), "no profile never penalizes");
  assert.equal(computeQueueRank({ band: "CRITICAL" }, { level: "MATCHED" }).version, "watchdog-queue-rank-1");
});

// ---------------------------------------------------------------------------
// Phases 12-14, 22: snapshot, immutability, versions, storage budget
// ---------------------------------------------------------------------------

test("evidence snapshot: versioned, bounded worst case, cites every decision input", () => {
  const long = "x".repeat(5000);
  const item = { id: "i".repeat(500), source: long, severity: long, cvss_score: 9.8, epss_score: 86, kev: true, kev_product: long, tags: Array.from({ length: 40 }, (_, i) => "npm:" + "p".repeat(100) + i), cve_ids: Array.from({ length: 50 }, (_, i) => "CVE-2026-" + (10000 + i)) };
  const profile = { version: 1, revision: 3, vendors: Array.from({ length: 25 }, () => "v".repeat(64)), products: [], packages: [], technologies: [] };
  const relevance = { version: "watchdog-relevance-1", level: "MATCHED", reasons: Array.from({ length: 30 }, () => ({ type: "vendor", basis: "identifier", profile_value: long, feed_field: "kev_product" })) };
  const snap = buildEvidenceSnapshot({ item, revision: "r" + long, feedGeneratedAt: long, watch: { id: long, version: 2, logic: "AND" }, watchHits: Array.from({ length: 40 }, () => ({ criterion: long, value: long, feed_field: long, feed_value: long })), priorityVersion: long, relevance, queueRank: { version: "watchdog-queue-rank-1" }, profile, classifierVersion: long });
  const bytes = JSON.stringify(snap).length;
  assert.ok(bytes <= SNAPSHOT_MAX_BYTES, "worst-case snapshot " + bytes + " bytes > " + SNAPSHOT_MAX_BYTES);
  assert.deepEqual(Object.keys(snap.versions).sort(), ["classifier", "priority", "queue_rank", "relevance", "watch_definition"]);
  assert.ok(snap.profile.ref.startsWith("p3:"));
});

test("storage budget: measured event sizes and a full 200-event ledger", () => {
  const profile = normalizeProfile({ vendors: ["Microsoft"], packages: ["npm:elysia"], technologies: ["Kubernetes"] }).profile;
  const w2 = { ...norm({ vendors: ["Microsoft"], keywords: ["exploited"] }, "OR").definition, id: "w_2" };
  const w1 = { id: "w_1", name: "legacy", logic: "OR", enabled: true, criteria: { keywords: ["microsoft"] } };
  const v1Event = candidateEvent(w1, projectItem(KEV_MS), "2026-09-24T00:00:00Z", "2026-09-24T00:00:00Z");
  const legacy = { ...v1Event };
  for (const k of ["priority", "relevance", "queue_rank", "evidence", "watch_definition_version", "status", "status_history"]) delete legacy[k];
  const v2Event = candidateEvent(w2, projectItem(KEV_MS), "2026-09-24T00:00:00Z", "2026-09-24T00:00:00Z", "request", profile);
  const sizes = { legacy: JSON.stringify(legacy).length, new_v1_watch: JSON.stringify(v1Event).length, new_v2_watch_with_profile: JSON.stringify(v2Event).length };
  console.log("# watchdog event bytes " + JSON.stringify(sizes));
  assert.ok(sizes.new_v2_watch_with_profile - sizes.legacy < 2500, JSON.stringify(sizes));
  let state = emptyLedgerState();
  const events = [];
  for (let i = 0; i < EVENT_RETENTION; i += 1) events.push(candidateEvent(w2, projectItem({ ...KEV_MS, id: "intel--" + i, title: KEV_MS.title + " " + i }), "2026-09-24T00:00:00Z", "2026-09-24T00:00:00Z", "request", profile));
  state = applyLedgerMutation(state, { subject: "s", tier: "PRO", type: "append_events", events, now: "2026-09-24T00:00:00Z" }).state;
  const total = JSON.stringify(state).length;
  console.log("# watchdog 200-event ledger bytes " + total);
  assert.equal(state.events.length, EVENT_RETENTION);
  assert.ok(total < 1_000_000, "200-event ledger must stay under 1 MB (half the 2 MB value limit), got " + total);
});

// ---------------------------------------------------------------------------
// End to end through the real router and Durable Objects
// ---------------------------------------------------------------------------

test("PRO flow: profile -> advanced watch -> preview (no writes) -> match with relevance, snapshot, customer sort", async () => {
  const h = harness({ feed: feedObject(FEED) });
  const t = await session(h, PRO_KEY);
  const put = await h.call("PUT", "/api/watchdog/profile", { bearer: t, body: { vendors: ["Microsoft"], packages: ["npm:elysia"] } });
  assert.equal(put.status, 200, JSON.stringify(put.body));
  assert.equal(put.body.created, true);
  assert.match(put.body.semantics, /not vulnerability scanning/);
  const got = await h.call("GET", "/api/watchdog/profile", { bearer: t });
  assert.deepEqual(got.body.profile.vendors, ["Microsoft"]);

  const body = { version: 2, name: "KEV or high", logic: "OR", criteria: { kev: true, severity_min: "HIGH" } };
  const storage = h.ledgerStorage("cust_pro_1");
  const writes = storage.writes;
  const gets = h.state.r2Gets;
  const sched = JSON.stringify(h.schedulerState()?.subjects || {});
  const pre = await h.call("POST", "/api/watchdog/watches/preview", { bearer: t, body });
  assert.equal(pre.status, 200, JSON.stringify(pre.body));
  assert.equal(pre.body.matched_count, 3);
  assert.equal(pre.body.feed_items_scanned, 5);
  assert.equal(pre.body.persisted, false);
  assert.deepEqual(pre.body.warnings.map((w) => w.message), ["This rule currently matches 60% of the available feed."]);
  assert.equal(pre.body.sample.find((s) => s.id === "intel--kev-ms").relevance.level, "MATCHED");
  assert.ok(pre.body.sample[0].why_matched.length);
  assert.equal(storage.writes, writes, "preview writes nothing to the ledger");
  assert.equal(h.state.r2Gets - gets, 1, "preview is one feed GET");
  assert.equal(h.state.r2Lists, 0, "no R2 LIST");
  assert.equal(JSON.stringify(h.schedulerState()?.subjects || {}), sched, "preview does not register a scheduler subject");
  assert.equal(h.ledgerState("cust_pro_1").events.length, 0, "preview creates no event");
  assert.equal(h.net.posts.length, 0, "preview sends no webhook");

  const created = await h.call("POST", "/api/watchdog/watches", { bearer: t, body });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  assert.equal(created.body.watch.version, 2);
  assert.deepEqual(created.body.watch.rule.lines, ["Severity is HIGH or higher", "CISA KEV listed = YES"]);

  const ev = await h.call("GET", "/api/watchdog/events?sort=customer", { bearer: t });
  assert.equal(ev.status, 200);
  assert.equal(ev.body.total, 3);
  const top = ev.body.events[0];
  assert.equal(top.matched_item_id, "intel--kev-ms", "profile-matched CRITICAL ranks first");
  assert.equal(top.relevance.level, "MATCHED");
  assert.equal(top.relevance.label, "Matches your exposure profile");
  assert.equal(top.priority.band, "CRITICAL");
  assert.equal(top.severity, "CRITICAL");
  assert.equal(top.evidence_status, "RECORDED");
  assert.equal(top.evidence.item.kev_product, "Microsoft Active Directory Federation Services");
  assert.equal(top.evidence.watch.definition_version, 2);
  assert.deepEqual(top.evidence.versions, { watch_definition: 2, priority: "watchdog-priority-2", relevance: "watchdog-relevance-1", queue_rank: "watchdog-queue-rank-1", classifier: "watchdog-lens-v2" });
  const matchedOnly = await h.call("GET", "/api/watchdog/events?evaluate=0&relevance=MATCHED", { bearer: t });
  assert.equal(matchedOnly.body.matched_total, 1);
  const kevNo = await h.call("GET", "/api/watchdog/events?evaluate=0&kev=no", { bearer: t });
  assert.deepEqual(kevNo.body.events.map((e) => e.matched_item_id), ["intel--news-ms"]);
  const src = await h.call("GET", "/api/watchdog/events?evaluate=0&source=cisa%20kev", { bearer: t });
  assert.equal(src.body.matched_total, 2);
  assert.equal(ev.body.analytics.by_relevance.MATCHED, 1);
  assert.equal((await h.call("GET", "/api/watchdog/events?relevance=HIGH", { bearer: t })).status, 400);
});

test("history is immutable: a profile change never rewrites an event; current context is separate", async () => {
  const h = harness({ feed: feedObject(FEED) });
  const t = await session(h, PRO_KEY);
  await h.call("PUT", "/api/watchdog/profile", { bearer: t, body: { vendors: ["Microsoft"] } });
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { version: 2, name: "ms", criteria: { cves: ["CVE-2026-2001"] } } });
  const first = (await h.call("GET", "/api/watchdog/events", { bearer: t })).body.events[0];
  assert.equal(first.relevance.level, "MATCHED");
  const refBefore = first.evidence.profile.ref;

  await h.call("PUT", "/api/watchdog/profile", { bearer: t, body: { vendors: ["F5"] } });
  const detail = await h.call("GET", "/api/watchdog/events/item?id=" + first.id, { bearer: t });
  assert.equal(detail.body.event.relevance.level, "MATCHED", "ORIGINAL MATCH keeps its recorded relevance");
  assert.equal(detail.body.event.evidence.profile.ref, refBefore);
  assert.equal(detail.body.current_context.relevance.level, "NOT_MATCHED", "CURRENT CONTEXT uses today's profile");
  assert.notEqual(detail.body.current_context.profile_ref, refBefore);

  await h.call("DELETE", "/api/watchdog/profile", { bearer: t });
  assert.equal((await h.call("GET", "/api/watchdog/profile", { bearer: t })).body.profile, null);
  assert.equal(h.ledgerStorage("cust_pro_1").data.has("watchdog_exposure_profile_v1"), false, "delete is deterministic");
  assert.equal((await h.call("GET", "/api/watchdog/events/item?id=" + first.id, { bearer: t })).body.event.relevance.level, "MATCHED");
});

test("legacy events: no snapshot means LEGACY / EVIDENCE_SNAPSHOT_NOT_AVAILABLE, never a reconstruction", () => {
  const legacy = { id: "e_old", watch_id: "w_1", matched_item_id: "x", matched_at: "2026-09-01T00:00:00Z", acknowledged: false };
  let state = { ...emptyLedgerState(), subject: "s", events: [legacy] };
  const view = applyLedgerMutation(state, { subject: "s", type: "get" }).result.events[0];
  assert.equal(view.relevance.level, "LEGACY");
  assert.equal(view.evidence, null);
  assert.equal(view.evidence_status, "EVIDENCE_SNAPSHOT_NOT_AVAILABLE");
  assert.equal(view.priority.band, "INSUFFICIENT_EVIDENCE");
  assert.equal(view.watch_definition_version, 1);
  const { query } = parseInboxQuery(new URLSearchParams("relevance=LEGACY&sort=customer"));
  assert.equal(filterEvents([legacy], query).length, 1);
});

test("MSSP: tenant A and tenant B profiles are isolated; same advisory, different relevance, no leakage", async () => {
  const h = harness({ feed: feedObject(FEED) });
  const ta = await session(h, MSSP_KEY, "CANARY-A");
  const tb = await session(h, MSSP_KEY, "CANARY-B");
  await h.call("PUT", "/api/watchdog/profile", { bearer: ta, body: { vendors: ["Microsoft"] } });
  await h.call("PUT", "/api/watchdog/profile", { bearer: tb, body: { vendors: ["F5"] } });
  const body = { version: 2, name: "all KEV", criteria: { kev: true } };
  await h.call("POST", "/api/watchdog/watches", { bearer: ta, body });
  await h.call("POST", "/api/watchdog/watches", { bearer: tb, body });
  const ea = (await h.call("GET", "/api/watchdog/events", { bearer: ta })).body.events;
  const eb = (await h.call("GET", "/api/watchdog/events", { bearer: tb })).body.events;
  const rel = (list, id) => list.find((e) => e.matched_item_id === id).relevance.level;
  assert.equal(rel(ea, "intel--kev-ms"), "MATCHED");
  assert.equal(rel(eb, "intel--kev-ms"), "NOT_MATCHED");
  assert.equal(rel(ea, "intel--kev-f5"), "NOT_MATCHED");
  assert.equal(rel(eb, "intel--kev-f5"), "MATCHED");
  assert.deepEqual((await h.call("GET", "/api/watchdog/profile", { bearer: tb })).body.profile.vendors, ["F5"]);
  assert.doesNotMatch(JSON.stringify(eb), /Microsoft"\]|"profile_value":"Microsoft"/, "tenant B sees nothing of tenant A's profile");
  // A key that manages only CANARY-A cannot read or write CANARY-B's profile.
  const aOnly = await h.call("POST", "/api/watchdog/session?tenant=CANARY-B", { key: MSSP_A_ONLY_KEY });
  assert.equal(aOnly.status, 403);
  const hdr = await h.call("GET", "/api/watchdog/profile", { key: MSSP_A_ONLY_KEY, headers: { "X-CDB-Watchdog-Tenant": "CANARY-B" } });
  assert.equal(hdr.status, 403);
  // Storage: each tenant profile lives only in its own ledger object.
  assert.deepEqual(h.ledgerState("cust_mssp_1|t:CANARY-A").profile.vendors, ["Microsoft"]);
  assert.deepEqual(h.ledgerState("cust_mssp_1|t:CANARY-B").profile.vendors, ["F5"]);
});

test("isolation and spoofing: body cannot choose the owner; another customer sees only its own profile", async () => {
  const h = harness({ feed: feedObject(FEED) });
  const t1 = await session(h, PRO_KEY);
  const t2 = await session(h, PRO2_KEY);
  assert.equal((await h.call("PUT", "/api/watchdog/profile", { bearer: t1, body: { owner: "cust_pro_2", vendors: ["Microsoft"] } })).body.error, "unsupported_field");
  assert.equal((await h.call("POST", "/api/watchdog/watches", { bearer: t1, body: { version: 2, name: "x", subject: "cust_pro_2", criteria: { kev: true } } })).body.error, "unsupported_field");
  await h.call("PUT", "/api/watchdog/profile", { bearer: t1, body: { vendors: ["Microsoft"] } });
  assert.equal((await h.call("GET", "/api/watchdog/profile", { bearer: t2 })).body.profile, null);
  assert.equal(h.ledgerState("cust_pro_2"), null, "customer 2 ledger never received customer 1 data");
});

test("entitlements: FREE refused; PRO and ENTERPRISE use existing quotas; scopes enforced", async () => {
  const h = harness({ feed: feedObject(FEED) });
  for (const [m, p] of [["GET", "/api/watchdog/profile"], ["PUT", "/api/watchdog/profile"], ["POST", "/api/watchdog/watches/preview"]]) {
    const r = await h.call(m, p, { body: m === "GET" ? undefined : { vendors: ["x"] } });
    assert.ok(r.status === 401 || r.status === 403, m + " " + p + " " + r.status);
  }
  const te = await session(h, ENT_KEY);
  assert.equal((await h.call("PUT", "/api/watchdog/profile", { bearer: te, body: { vendors: ["F5"] } })).status, 200);
  const tp = await session(h, PRO_KEY);
  const watches = await h.call("GET", "/api/watchdog/watches", { bearer: tp });
  assert.equal(watches.body.limit, 25, "PRO watch limit is the canonical policy value");
  const now = Math.floor(Date.now() / 1000);
  const readOnly = await craftJwt({ sub: "cust_pro_1", tier: "PRO", iss: "SENTINEL-APEX", aud: "cdb-watchdog", auth_time: now, jti: "jr", scope: "watchdog:read", iat: now, exp: now + 600 });
  const denied = await h.call("PUT", "/api/watchdog/profile", { bearer: readOnly, body: { vendors: ["x"] } });
  assert.equal(denied.status, 403);
  assert.equal(denied.body.required_scope, "watchdog:watches:write");
  assert.equal((await h.call("GET", "/api/watchdog/profile", { bearer: readOnly })).status, 200);
  assert.equal((await h.call("POST", "/api/watchdog/watches/preview", { bearer: readOnly, body: { version: 2, name: "p", criteria: { kev: true } } })).status, 200);
});

test("stored XSS: watch name and profile values are stored without markup", async () => {
  const h = harness({ feed: feedObject(FEED) });
  const t = await session(h, PRO_KEY);
  const w = await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { version: 2, name: "<img src=x onerror=alert(1)>", criteria: { kev: true } } });
  assert.equal(w.status, 201);
  assert.ok(!/[<>]/.test(w.body.watch.name), w.body.watch.name);
  const p = await h.call("PUT", "/api/watchdog/profile", { bearer: t, body: { technologies: ["<svg onload=alert(1)>"] } });
  assert.ok(!/[<>]/.test(p.body.profile.technologies[0]));
});

test("telemetry: aggregate counts only, no profile or watch content in the scheduler", async () => {
  const h = harness({ feed: feedObject(FEED) });
  const t = await session(h, PRO_KEY);
  await h.call("PUT", "/api/watchdog/profile", { bearer: t, body: { vendors: ["SecretVendorName"] } });
  await h.call("POST", "/api/watchdog/watches/preview", { bearer: t, body: { version: 2, name: "p", criteria: { kev: true } } });
  await h.call("POST", "/api/watchdog/watches", { bearer: t, body: { version: 2, name: "SecretWatchName", criteria: { kev: true } } });
  const ev = (await h.call("GET", "/api/watchdog/events", { bearer: t })).body.events[0];
  await h.call("GET", "/api/watchdog/events/item?id=" + ev.id, { bearer: t });
  await h.call("POST", "/api/watchdog/events/status", { bearer: t, body: { ids: [ev.id], status: "INVESTIGATING", note: "SecretNote" } });
  const ops = await h.call("GET", "/api/watchdog/ops", { admin: "admin-test-secret" });
  assert.equal(ops.status, 200);
  assert.deepEqual(ops.body.product_24h, { signins: 1, previews: 1, watches_created_v2: 1, profiles_saved: 1, profiles_deleted: 0, evidence_views: 1, status_changes: 1 });
  const raw = JSON.stringify(h.schedulerState());
  for (const secret of ["SecretVendorName", "SecretWatchName", "SecretNote", PRO_KEY]) assert.ok(!raw.includes(secret), secret);
});

// ---------------------------------------------------------------------------
// Phase 10: wording safety
// ---------------------------------------------------------------------------

const OVERCLAIMS = /you are vulnerable|you are compromised|affected asset found|breach exposure confirmed|your network is at risk|your asset is exposed|asset is vulnerable|confirmed exposure/i;

test("wording: no vulnerability, compromise or confirmed-exposure claims anywhere a customer reads", () => {
  for (const label of Object.values(RELEVANCE_LABELS)) assert.doesNotMatch(label, OVERCLAIMS, label);
  const html = fs.readFileSync(path.join(REPO, "cyber-watchdog.html"), "utf8");
  assert.doesNotMatch(html, OVERCLAIMS);
  for (const f of ["watchdog-relevance.js", "watchdog-definition.js", "cyber-watchdog.js"]) {
    const src = fs.readFileSync(path.join(HERE, "..", f), "utf8").split("\n").filter((l) => !/^\s*(\/\/|\*)/.test(l)).join("\n");
    assert.doesNotMatch(src, OVERCLAIMS, f);
  }
  assert.match(html, /Matches your exposure profile|exposure profile/i);
});
