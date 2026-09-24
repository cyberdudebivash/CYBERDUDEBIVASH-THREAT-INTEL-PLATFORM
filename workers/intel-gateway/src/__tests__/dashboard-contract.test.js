// Customer dashboard data contract (P0, 2026-09-24): ATT&CK tactic coverage,
// campaign semantics, ransomware classification, geo attribution, and the
// index.js route wiring that exposes them.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ATTACK_TACTICS, normalizeTactic, techniqueIdsOf, buildTechniqueTacticMap, deriveItemTactics,
  deriveAttackTacticCoverage, campaignEvidence, buildCampaignsPayload, classifyRansomware,
  buildRansomwarePayload, geoAttributionCoverage,
} from "../dashboard-contract.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const INDEX = readFileSync(path.join(HERE, "..", "index.js"), "utf8");

const GROUPS = [
  { name: "LockBit 3.0", sector: "Healthcare" }, { name: "BlackCat/ALPHV", sector: "Energy" },
  { name: "Cl0p", sector: "Government" }, { name: "Play", sector: "Legal" }, { name: "Akira", sector: "SMB" },
];

// Shapes copied from the live /api/feed.json items (2026-09-24).
const ITEM_TACTICS = {
  id: "a1", title: "Chrome cookie stealer", severity: "HIGH", risk_score: 7.1,
  mitre_tactics: [{ id: "T1539", name: "Steal Web Session Cookie", tactic: "Credential Access" }],
  attck_technique_ids: ["T1539"], tags: ["T1539"],
};
const ITEM_ATTCK_MULTI = {
  id: "a2", title: "Snipe-IT 2FA bypass", severity: "MEDIUM", risk_score: 5,
  attck_technique_ids: ["T1078", "T1190"],
  attck_techniques: [
    { technique_id: "T1078", tactic: "Defense Evasion / Persistence / Privilege Escalation / Initial Access" },
    { technique_id: "T1190", tactic: "Initial Access" },
  ],
};
const ITEM_IDS_ONLY = { id: "a3", title: "RCE in X", severity: "CRITICAL", risk_score: 9.8, attck_technique_ids: ["T1539"], tags: [] };
const ITEM_CRITICAL_NO_EVIDENCE = { id: "a4", title: "Low Security Vulnerability (CVE-2026-61742)", severity: "CRITICAL", risk_score: 1.85, tags: ["pip:x"] };

test("ATT&CK tactic list is the 14 Enterprise tactics in matrix order", () => {
  assert.equal(ATTACK_TACTICS.length, 14);
  assert.equal(ATTACK_TACTICS[0].name, "Reconnaissance");
  assert.equal(ATTACK_TACTICS[13].name, "Impact");
  assert.equal(normalizeTactic("initial-access"), "Initial Access");
  assert.equal(normalizeTactic("TA0011"), "Command and Control");
  assert.equal(normalizeTactic("Weaponization"), null, "Lockheed kill-chain phases are not ATT&CK tactics");
});

test("technique ids are read from structured fields and T-id tags only", () => {
  assert.deepEqual(techniqueIdsOf({ tags: ["T1190", "pip:foo", "T1059.001"], attck_technique_ids: ["T1203"] }).sort(),
    ["T1059.001", "T1190", "T1203"]);
});

test("tactic derivation precedence: mitre_tactics, attck_techniques, id map, legacy", () => {
  const map = buildTechniqueTacticMap([ITEM_TACTICS, ITEM_ATTCK_MULTI]);
  assert.deepEqual(deriveItemTactics(ITEM_TACTICS, map), { tactics: ["Credential Access"], method: "mitre_tactics" });
  const multi = deriveItemTactics(ITEM_ATTCK_MULTI, map);
  assert.equal(multi.method, "attck_techniques");
  assert.deepEqual(multi.tactics.sort(), ["Defense Evasion", "Initial Access", "Persistence", "Privilege Escalation"]);
  assert.deepEqual(deriveItemTactics(ITEM_IDS_ONLY, map), { tactics: ["Credential Access"], method: "technique_id_map" });
  assert.deepEqual(deriveItemTactics({ kill_chain_phase: "Lateral-Movement" }, map), { tactics: ["Lateral Movement"], method: "legacy_kill_chain" });
});

test("severity never produces a tactic: a CRITICAL item with no ATT&CK evidence contributes nothing", () => {
  const { block } = deriveAttackTacticCoverage([ITEM_CRITICAL_NO_EVIDENCE], "t");
  assert.equal(block.items_with_attack_evidence, 0);
  assert.equal(block.tactics_observed, 0);
  assert.ok(block.tactics.every((t) => t.count === 0));
});

test("feed with MITRE tactics yields non-zero coverage (the all-zero defect)", () => {
  const payload = buildCampaignsPayload([ITEM_TACTICS, ITEM_ATTCK_MULTI, ITEM_IDS_ONLY, ITEM_CRITICAL_NO_EVIDENCE], "2026-09-24T00:00:00Z");
  const at = payload.attack_tactics;
  assert.equal(at.model, "mitre_attack_enterprise_tactics");
  assert.equal(at.items_evaluated, 4);
  assert.equal(at.items_with_attack_evidence, 3);
  assert.equal(at.tactics.find((t) => t.name === "Credential Access").count, 2);
  assert.equal(at.tactics.find((t) => t.name === "Initial Access").count, 1);
  assert.ok(at.tactics_observed > 0);
  assert.ok(payload.total_tactics > 0, "legacy phase counters must not stay zero when ATT&CK evidence exists");
  assert.ok(payload.coverage_pct > 0);
  assert.equal(at.generated_at, "2026-09-24T00:00:00Z");
});

test("legacy /campaigns keys are preserved for existing readers", () => {
  const payload = buildCampaignsPayload([], "t");
  for (const k of ["phases", "coverage_pct", "active_campaigns", "total_tactics", "generated_at"]) assert.ok(k in payload, k);
  assert.deepEqual(Object.keys(payload.phases), ["recon", "weaponize", "deliver", "exploit", "install", "c2", "action"]);
  assert.equal(payload.coverage_pct, 0);
  assert.equal(payload.active_campaigns.length, 0);
});

test("a CRITICAL vulnerability is not a campaign; campaign evidence is", () => {
  assert.deepEqual(campaignEvidence(ITEM_CRITICAL_NO_EVIDENCE), []);
  assert.deepEqual(campaignEvidence({ title: "CVE-2026-1 KEV", severity: "CRITICAL", kev: true, risk_score: 9.9 }), []);
  assert.deepEqual(campaignEvidence({ title: "Fake PDF Files Hide Konni Malware Campaign Targeting Ukraine" }), ["title:campaign"]);
  assert.deepEqual(campaignEvidence({ title: "New Galago Ransomware Operation Emerges" }), ["title:operation"]);
  assert.deepEqual(campaignEvidence({ title: "x", campaign_id: "camp-7" }), ["campaign_id"]);
  assert.deepEqual(campaignEvidence({ title: "x", mitre_group_name: "APT29" }), [], "an actor label alone is not a campaign");
  // Live item (2026-09-24): policy news carrying a heuristic group label.
  assert.deepEqual(campaignEvidence({ title: "New bill would create federal investigative body for AI-driven hacks",
    tags: ["T1203"], threat_type: "Threat Intel", mitre_group_name: "APT-22 / Sea Turtle" }), []);
  assert.deepEqual(campaignEvidence({ title: "APT29 phishing campaign hits embassies", mitre_group_name: "APT29" }),
    ["title:campaign", "mitre_group:APT29"], "a group is kept as supporting evidence");
  assert.deepEqual(campaignEvidence({ title: "x", actor: "CDB-UNATTR-APT", mitre_group_name: "Unattributed APT Cluster" }), [],
    "placeholder attributions are not a named actor");
  const payload = buildCampaignsPayload([ITEM_CRITICAL_NO_EVIDENCE, ITEM_IDS_ONLY], "t");
  assert.equal(payload.active_campaign_count, 0);
  assert.equal(payload.active_campaigns.length, 0);
});

test("ransomware: LockBit and ALPHV advisories classify from structured fields and titles", () => {
  const lockbit = classifyRansomware({ title: "LockBit 3.0 affiliate hits hospital", tags: [] }, GROUPS);
  assert.equal(lockbit.ransomware, true);
  assert.deepEqual(lockbit.groups, ["LockBit 3.0"]);
  const alphv = classifyRansomware({ title: "Advisory", tags: ["alphv"] }, GROUPS);
  assert.equal(alphv.ransomware, true);
  assert.deepEqual(alphv.groups, ["BlackCat/ALPHV"]);
  assert.ok(alphv.evidence.includes("tags:BlackCat/ALPHV"));
  const typed = classifyRansomware({ title: "Advisory", threat_type: "Ransomware" }, GROUPS);
  assert.ok(typed.evidence.includes("threat_type:ransomware"));
});

test("ransomware: description prose, bare 'ransom', 'extort' and 'play' do not classify", () => {
  const historic = { title: "Patch Tuesday fixes 60 flaws", description: "Last year this bug was used in ransomware attacks.", tags: [] };
  assert.equal(classifyRansomware(historic, GROUPS).ransomware, false, "description is never read");
  assert.equal(classifyRansomware({ title: "Man held for ransom of stolen laptop" }, GROUPS).ransomware, false);
  assert.equal(classifyRansomware({ title: "Extortion email scam" }, GROUPS).ransomware, false);
  assert.equal(classifyRansomware({ title: "Google Play app flaw" }, GROUPS).ransomware, false);
  assert.equal(classifyRansomware({ title: "Akiranet library bug" }, GROUPS).ransomware, false, "word boundary");
  assert.equal(classifyRansomware({ title: "Play ransomware claims retailer" }, GROUPS).groups[0], "Play");
});

test("ransomware: a placeholder actor label is not evidence (live false positive, 2026-09-24)", () => {
  // Live R2 item: product-launch news whose pipeline cluster label named ransomware.
  const scoutz = { title: "SCOUTz Prospect Intelligence Platform Launches for MSPs with 30-Day Beta", tags: ["T1566"],
    threat_type: "Threat Intel", actor: "Unattributed Ransomware Actor", actor_tag: "CDB-UNATTR-RAN" };
  assert.equal(classifyRansomware(scoutz, GROUPS).ransomware, false);
  assert.equal(classifyRansomware({ title: "Product launch", mitre_group_name: "Ransomware cluster (unattributed)" }, GROUPS).ransomware, false);
  assert.equal(classifyRansomware({ title: "x", actor: "LockBit 3.0" }, GROUPS).ransomware, true, "a named group actor still counts");
});

test("ransomware payload: no active group from a static list; victims stay unmeasured", () => {
  const none = buildRansomwarePayload([ITEM_TACTICS, ITEM_CRITICAL_NO_EVIDENCE], GROUPS, "t");
  assert.equal(none.active_groups, 0);
  assert.equal(none.ransomware_advisories, 0);
  assert.equal(none.recent_advisories.length, 0);
  assert.deepEqual(none.top_groups, []);
  assert.equal(none.monitor_status, "OPERATIONAL");
  assert.equal(none.new_victims_30d, null);
  assert.equal(none.victims_measured, false);
  const one = buildRansomwarePayload([{ id: "r", title: "Cl0p exploits MOVEit again", tags: [] }], GROUPS, "t");
  assert.equal(one.active_groups, 1);
  assert.equal(one.top_groups[0].victims_30d, null);
  assert.equal(one.top_groups[0].status, "IN_CURRENT_FEED");
});

test("geo attribution counts actor_country only", () => {
  const cov = geoAttributionCoverage([{ actor_country: "RU" }, { actor_country: "Unknown" }, { source_country: "US" }, {}]);
  assert.equal(cov.items_evaluated, 4);
  assert.equal(cov.items_with_country_attribution, 1);
  assert.equal(cov.attribution_field, "actor_country");
});

test("index.js routes delegate to the contract and never apply the 74 fallback", () => {
  assert.match(INDEX, /function computeKillChain\(items\) \{\s*return buildCampaignsPayload\(items, now\(\)\);/);
  assert.match(INDEX, /function computeRansomware\(items\) \{\s*return buildRansomwarePayload\(items, RANSOMWARE_GROUPS, now\(\)\);/);
  assert.doesNotMatch(INDEX, /_LEGACY_FEED_COUNT_FALLBACK\s*=\s*74/);
  assert.doesNotMatch(INDEX, /\?\?\s*_LEGACY_FEED_COUNT_FALLBACK/);
  assert.doesNotMatch(INDEX, /item\.actor_country \|\| item\.source_country/, "publisher geography is not attack origin");
  assert.match(INDEX, /campaigns_detected: kcData\.active_campaign_count/);
});

test("/api/v1/intel/stats exposes the feed generation time and publication state", () => {
  const start = INDEX.indexOf('if (path === "/api/v1/intel/stats"');
  const body = INDEX.slice(start, start + 2200);
  assert.match(body, /last_feed_sync_utc: publication\.generated_at/);
  assert.match(body, /publication,/);
  assert.match(body, /latest_item_published_at: stats\.last_sync/);
});

test("a synthetic empty feed is never reported as a fresh publication", () => {
  assert.match(INDEX, /_synthetic_empty: true/);
  assert.match(INDEX, /evaluatePublicIntelligence\(feedData && !feedData\._synthetic_empty \? feedData : null/);
  assert.match(INDEX, /feedData\._synthetic_empty \? null : \(feedData\.generated_at \|\| null\)/);
});
