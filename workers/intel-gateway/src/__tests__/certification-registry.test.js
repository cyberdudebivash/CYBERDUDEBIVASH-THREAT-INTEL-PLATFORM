import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluatePublicationGate } from "../publication-gate.js";
import {
  classifyCertification, resolveCertification, loadCertificationIndex,
  persistCertificationRecords, CERTIFICATION_INDEX_KEY, CERTIFICATION_POLICY_VERSION,
} from "../certification-registry.js";

// ---------------------------------------------------------------------------
// P0 trust-boundary regression suite -- CYBERDUDEBIVASH SENTINEL APEX
//
// Live production evidence (2026-08-11): of api/reports/latest.json's 50 raw
// candidates, 33 were resolvable against the current rolling feed and were
// correctly REJECTED by evaluatePublicationGate(); the 17 that "survived"
// were ALL unresolvable (NOT_FOUND_IN_FEED), none of them actually
// certified. These tests lock down the fix: an item with no persisted
// certification and no way to resolve it must NEVER be treated as
// customer-ready, regardless of how it got into that state.
// ---------------------------------------------------------------------------

const CUSTOMER_READY_ITEM = {
  id: "intel--goodreport",
  title: "CVE-2026-99999: Critical RCE in Example Product",
  severity: "CRITICAL",
  description: "A".repeat(200),
  cvss_score: 9.8, risk_score: 9.8, kev_present: true, epss_score: 0.85,
  evidence_chain: { reliability_code: "A", source_reliability: "HIGH", source_name: "Vendor Advisory" },
  iocs: [{ value: "192.0.2.1", type: "ip", response_guidance: "Block at firewall" }],
  ioc_count: 1, ttps: ["T1190"], mitre_techniques: ["T1190"],
  detection_bundle: [{ type: "sigma", rule: "title: Example Detection" }],
  executive_summary: "Critical vulnerability requiring immediate patching.",
  exec_summary: "Critical vulnerability requiring immediate patching.",
  source_url: "https://vendor.example.com/advisory/2026-99999",
  confidence: 0.9, apex: { ai_summary: "AI narrative.", kev_listed: true },
};

const REJECTED_ITEM = {
  id: "intel--ba996dad34540150b8ea1b5f",
  title: "Metabase Zero-Day Exploited in the Wild",
  severity: "CRITICAL",
  description: "Short.",
};

// --- classifyCertification -------------------------------------------------

test("classifyCertification: CUSTOMER_READY item -> CERTIFIED / CUSTOMER_READY", () => {
  const gate = evaluatePublicationGate(CUSTOMER_READY_ITEM);
  const c = classifyCertification(gate);
  assert.equal(c.certification_status, "CERTIFIED");
  assert.equal(c.publication_status, "CUSTOMER_READY");
});

test("classifyCertification: P26 REJECTED tier -> BLOCKED / REJECTED (not PENDING_ENRICHMENT)", () => {
  const gate = evaluatePublicationGate(REJECTED_ITEM);
  assert.equal(gate.publication_state, "REJECTED");
  const c = classifyCertification(gate);
  assert.equal(c.certification_status, "BLOCKED");
  assert.equal(c.publication_status, "REJECTED");
});

test("classifyCertification: engine error -> CERTIFICATION_ERROR / WITHHELD, fail closed", () => {
  const poison = { id: "intel--poison", get evidence_chain() { throw new Error("simulated failure"); } };
  const gate = evaluatePublicationGate(poison);
  assert.ok(gate.blocking_gates.includes("CERTIFICATION_ENGINE_ERROR"));
  const c = classifyCertification(gate);
  assert.equal(c.certification_status, "CERTIFICATION_ERROR");
  assert.equal(c.publication_status, "WITHHELD");
});

test("classifyCertification: null/undefined gate result -> CERTIFICATION_ERROR / WITHHELD, never throws", () => {
  assert.equal(classifyCertification(null).publication_status, "WITHHELD");
  assert.equal(classifyCertification(undefined).publication_status, "WITHHELD");
});

test("classifyCertification: blocked but not policy-rejected -> BLOCKED / PENDING_ENRICHMENT (distinct from REJECTED)", () => {
  // Pins the branch directly against a synthetic gate result, independent of
  // evaluatePublicationGate's own thresholds -- a regression that collapses
  // PENDING_ENRICHMENT into REJECTED (or vice versa) must fail this test even
  // if it doesn't happen to flip any real item's engine scores.
  const c = classifyCertification({
    customer_ready: false,
    publication_state: "BLOCKED",
    blocking_gates: ["P23_OPERATIONAL_READINESS_DO_NOT_PUBLISH"],
  });
  assert.equal(c.certification_status, "BLOCKED");
  assert.equal(c.publication_status, "PENDING_ENRICHMENT");
});

// --- resolveCertification: the critical trust invariant --------------------

test("CRITICAL INVARIANT: no persisted record + unresolvable item -> NOT_EVALUATED / WITHHELD, never CUSTOMER_READY", () => {
  const { record, isNew } = resolveCertification(undefined, undefined);
  assert.equal(record.certification_status, "NOT_EVALUATED");
  assert.equal(record.publication_status, "WITHHELD");
  assert.notEqual(record.publication_status, "CUSTOMER_READY");
  // NOT_EVALUATED must never be persisted -- see file-level doc comment for why.
  assert.equal(isNew, false);
});

test("CRITICAL INVARIANT: this is the exact live-production defect reproduced -- item scrolled out of the feed window, no persisted record", () => {
  // Simulates exactly what happened live: 33/50 latest.json candidates were
  // resolvable and correctly rejected; the 17 survivors were unresolvable.
  // Before this fix, the old code's `if (!item) return true;` passed such
  // entries through unfiltered -- the assertion below is what must now hold
  // instead: unresolvable-and-unpersisted can never be customer-ready.
  const unresolvable = resolveCertification(undefined, undefined);
  assert.notEqual(unresolvable.record.publication_status, "CUSTOMER_READY");
  assert.equal(unresolvable.record.certification_status, "NOT_EVALUATED");
});

test("resolveCertification: existing record with a matching content_hash is reused verbatim, never re-evaluated", () => {
  const existing = {
    certification_status: "CERTIFIED", publication_status: "CUSTOMER_READY",
    evaluated_at: "2020-01-01T00:00:00Z",
    content_hash: evaluatePublicationGate(CUSTOMER_READY_ITEM).content_hash,
    policy_version: CERTIFICATION_POLICY_VERSION, blocking_gates: [],
  };
  // Even with a resolvable item present, a matching-content existing record
  // wins -- proves "once certified, never re-evaluated for unchanged content"
  // (Section 5 historical provenance), while still allowing genuinely stale
  // records (next test) to be caught.
  const { record, isNew } = resolveCertification(existing, CUSTOMER_READY_ITEM);
  assert.equal(record, existing);
  assert.equal(isNew, false);
});

test("P0: old approval with no content_hash is not blindly reused even if feed item resolves", () => {
  const legacy = { certification_status: "CERTIFIED", publication_status: "CUSTOMER_READY", evaluated_at: "2020-01-01T00:00:00Z" };
  const { record, isNew } = resolveCertification(legacy, REJECTED_ITEM);
  assert.equal(isNew, true);
  assert.notEqual(record.publication_status, "CUSTOMER_READY");
  assert.notEqual(record, legacy);
});

test("P0: old approval without content_hash cannot authorize an unresolvable historical item", () => {
  const legacy = { certification_status: "CERTIFIED", publication_status: "CUSTOMER_READY" };
  const { record, isNew } = resolveCertification(legacy, undefined);
  assert.equal(record.publication_status, "WITHHELD");
  assert.equal(record.certification_status, "NOT_EVALUATED");
  assert.equal(isNew, false);
});

test("P0: obsolete policy version triggers fresh evaluation if current item is resolvable", () => {
  const approved = resolveCertification(undefined, CUSTOMER_READY_ITEM).record;
  const obsolete = { ...approved, policy_version: "0.9.0" };
  const { record, isNew } = resolveCertification(obsolete, REJECTED_ITEM);
  assert.equal(isNew, true);
  assert.notEqual(record.publication_status, "CUSTOMER_READY");
});

test("P0: a contradictory persisted approval is never trusted", () => {
  const approved = resolveCertification(undefined, CUSTOMER_READY_ITEM).record;
  const contradicting = { ...approved, blocking_gates: ["P26_REJECTED"] };
  const { record, isNew } = resolveCertification(contradicting, undefined);
  assert.equal(record.publication_status, "WITHHELD");
  assert.equal(isNew, false);
});

test("resolveCertification: existing record with a STALE content_hash triggers fresh evaluation, not blind reuse", () => {
  // The item's content has changed since certification (e.g. re-enriched or
  // corrected) -- a persisted verdict computed against the OLD content must
  // not be trusted forever. The fingerprint check is a cheap sync hash over
  // raw fields, not a P20-P26 re-run, so this never reintroduces the
  // per-request full-evaluation cost this module exists to eliminate.
  const stale = {
    certification_status: "BLOCKED", publication_status: "REJECTED",
    evaluated_at: "2020-01-01T00:00:00Z", content_hash: "fp_deadbeef",
  };
  const { record, isNew } = resolveCertification(stale, CUSTOMER_READY_ITEM);
  assert.equal(isNew, true);
  assert.notEqual(record, stale);
  assert.equal(record.certification_status, "CERTIFIED");
  assert.equal(record.publication_status, "CUSTOMER_READY");
  assert.equal(record.content_hash, evaluatePublicationGate(CUSTOMER_READY_ITEM).content_hash);
});

test("resolveCertification: complete current-policy historical proof is preserved after feed rollover", () => {
  const existing = resolveCertification(undefined, CUSTOMER_READY_ITEM).record;
  const { record, isNew } = resolveCertification(existing, undefined);
  assert.equal(record, existing);
  assert.equal(record.publication_status, "CUSTOMER_READY");
  assert.equal(isNew, false);
});

test("resolveCertification: no persisted record but item IS resolvable -> real evaluation happens, result is new", () => {
  const { record, isNew } = resolveCertification(undefined, CUSTOMER_READY_ITEM);
  assert.equal(isNew, true);
  assert.equal(record.certification_status, "CERTIFIED");
  assert.equal(record.publication_status, "CUSTOMER_READY");
  assert.ok(record.evaluated_at);
  assert.ok(record.policy_version);
  assert.ok(record.engines);
  assert.equal(record.engines.P20, evaluatePublicationGate(CUSTOMER_READY_ITEM).P20_SCORE);
});

test("resolveCertification: no persisted record, resolvable item that fails the gate -> real rejection, is new (persisted)", () => {
  const { record, isNew } = resolveCertification(undefined, REJECTED_ITEM);
  assert.equal(isNew, true);
  assert.notEqual(record.publication_status, "CUSTOMER_READY");
  assert.ok(["REJECTED", "PENDING_ENRICHMENT"].includes(record.publication_status));
});

test("historical provenance: once persisted CERTIFIED, an item remains customer-ready even when it can no longer be resolved", () => {
  // Step 1: item is resolvable, gets certified for the first time.
  const first = resolveCertification(undefined, CUSTOMER_READY_ITEM);
  assert.equal(first.isNew, true);
  assert.equal(first.record.publication_status, "CUSTOMER_READY");

  // Step 2: item has scrolled out of the rolling feed (item undefined now),
  // but the persisted record from step 1 is supplied -- must still be
  // CUSTOMER_READY, proving certification survives feed-window departure.
  const second = resolveCertification(first.record, undefined);
  assert.equal(second.isNew, false);
  assert.equal(second.record.publication_status, "CUSTOMER_READY");
});

test("historical provenance: once persisted REJECTED, an item stays withheld even when it can no longer be resolved (no re-litigating a rejection via absence)", () => {
  const first = resolveCertification(undefined, REJECTED_ITEM);
  assert.notEqual(first.record.publication_status, "CUSTOMER_READY");
  const second = resolveCertification(first.record, undefined);
  assert.equal(second.record.publication_status, first.record.publication_status);
  assert.notEqual(second.record.publication_status, "CUSTOMER_READY");
});

// --- persistence layer (in-memory R2 mock) ----------------------------------

function makeMockR2() {
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

test("persistCertificationRecords + loadCertificationIndex: round-trips correctly", async () => {
  const env = { INTEL_R2: makeMockR2() };
  assert.deepEqual(await loadCertificationIndex(env), {});

  await persistCertificationRecords(env, { "intel--a": { certification_status: "CERTIFIED", publication_status: "CUSTOMER_READY" } });
  const idx1 = await loadCertificationIndex(env);
  assert.equal(idx1["intel--a"].publication_status, "CUSTOMER_READY");

  // Merge, not overwrite: a second write must not lose the first record.
  await persistCertificationRecords(env, { "intel--b": { certification_status: "BLOCKED", publication_status: "REJECTED" } });
  const idx2 = await loadCertificationIndex(env);
  assert.equal(idx2["intel--a"].publication_status, "CUSTOMER_READY");
  assert.equal(idx2["intel--b"].publication_status, "REJECTED");
});

test("loadCertificationIndex: missing/corrupt index fails safe to {} (never throws, never fabricates records)", async () => {
  const envMissing = { INTEL_R2: makeMockR2() };
  assert.deepEqual(await loadCertificationIndex(envMissing), {});

  const envCorrupt = { INTEL_R2: makeMockR2() };
  await envCorrupt.INTEL_R2.put(CERTIFICATION_INDEX_KEY, "{not valid json");
  assert.deepEqual(await loadCertificationIndex(envCorrupt), {});
});

test("persistCertificationRecords: a write failure never throws out of the caller (best-effort, response already computed)", async () => {
  const env = { INTEL_R2: { get: async () => null, put: async () => { throw new Error("simulated R2 outage"); } } };
  await assert.doesNotReject(persistCertificationRecords(env, { "intel--x": { publication_status: "CUSTOMER_READY" } }));
});

test("persistCertificationRecords: empty/no records is a no-op, never writes", async () => {
  const env = { INTEL_R2: makeMockR2() };
  await persistCertificationRecords(env, {});
  assert.equal(env.INTEL_R2.store.size, 0);
  await persistCertificationRecords(env, null);
  assert.equal(env.INTEL_R2.store.size, 0);
});
