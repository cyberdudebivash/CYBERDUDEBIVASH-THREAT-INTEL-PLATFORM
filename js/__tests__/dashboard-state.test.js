import assert from "node:assert/strict";
import { test } from "node:test";
import DashboardState from "../dashboard-state.js";

// ---------------------------------------------------------------------------
// Dashboard Truth Contract -- Phase 1 regression suite (CYBERDUDEBIVASH SENTINEL APEX)
//
// js/dashboard-state.js is a purely additive, unwired module -- these tests
// validate its own internal consistency only. They do not test any renderer
// or adapter, since nothing consumes this module yet (see
// DASHBOARD_TRUTH_CONTRACT_PHASE0_FORENSIC_CENSUS.md for the full forensic
// evidence and migration plan).
// ---------------------------------------------------------------------------

const SEVERITIES = new Set(["neutral", "info", "warning", "critical"]);
const GROUPS = new Set(["freshness", "lifecycle", "cross-cutting"]);

test("exports exactly the 12 states required by the mission spec", () => {
  const expected = [
    "LIVE", "FRESH", "STALE", "DEGRADED", "PROCESSING", "PUBLISHED",
    "WITHHELD", "BLOCKED", "REJECTED", "UNAVAILABLE", "ERROR", "UNKNOWN"
  ];
  assert.deepEqual(DashboardState.STATE_VALUES.slice().sort(), expected.slice().sort());
  assert.equal(DashboardState.STATE_VALUES.length, 12);
});

test("every state has all required properties with valid domains", () => {
  for (const key of DashboardState.STATE_VALUES) {
    const s = DashboardState.STATES[key];
    assert.equal(s.value, key, `state ${key} must have value === its own key`);
    assert.equal(typeof s.label, "string");
    assert.ok(s.label.length > 0, `${key}.label must be non-empty`);
    assert.equal(typeof s.explanation, "string");
    assert.ok(s.explanation.length > 10, `${key}.explanation must be a real sentence`);
    assert.ok(SEVERITIES.has(s.severity), `${key}.severity must be one of ${[...SEVERITIES]}`);
    assert.ok(GROUPS.has(s.group), `${key}.group must be one of ${[...GROUPS]}`);
    assert.equal(typeof s.aria, "string");
    assert.ok(s.aria.length > 0, `${key}.aria must be non-empty (accessibility requirement)`);
    assert.equal(typeof s.telemetryEvent, "string");
    assert.ok(s.telemetryEvent.startsWith("state_transition:"), `${key}.telemetryEvent must follow the state_transition: naming convention`);
  }
});

test("no two states share a telemetry event name", () => {
  const events = DashboardState.STATE_VALUES.map((k) => DashboardState.STATES[k].telemetryEvent);
  assert.equal(new Set(events).size, events.length);
});

test("state values overlap with SENTINELS only where intentional (UNAVAILABLE and UNKNOWN mean the same thing in both), never accidentally", () => {
  const sentinelValues = new Set(Object.values(DashboardState.SENTINELS));
  const intentionalOverlap = new Set(["UNAVAILABLE", "UNKNOWN"]);
  for (const key of DashboardState.STATE_VALUES) {
    if (sentinelValues.has(key)) {
      assert.ok(intentionalOverlap.has(key), `state value ${key} unexpectedly collides with a SENTINELS value -- either rename it or add it to intentionalOverlap with justification`);
    }
  }
});

test("PROCESSING and UNAVAILABLE are distinct lifecycle states (the exact conflation this contract exists to prevent)", () => {
  assert.notEqual(DashboardState.STATES.PROCESSING.value, DashboardState.STATES.UNAVAILABLE.value);
  assert.notEqual(DashboardState.STATES.PROCESSING.explanation, DashboardState.STATES.UNAVAILABLE.explanation);
});

test("WITHHELD, BLOCKED, and REJECTED remain three distinct outcomes, not collapsed into one", () => {
  const vals = [DashboardState.STATES.WITHHELD.value, DashboardState.STATES.BLOCKED.value, DashboardState.STATES.REJECTED.value];
  assert.equal(new Set(vals).size, 3);
});

test("isValidState() correctly validates and getState() never throws on unknown input", () => {
  assert.equal(DashboardState.isValidState("PUBLISHED"), true);
  assert.equal(DashboardState.isValidState("NOT_A_REAL_STATE"), false);
  assert.equal(DashboardState.isValidState(null), false);
  assert.equal(DashboardState.isValidState(undefined), false);
  assert.equal(DashboardState.isValidState(42), false);

  assert.equal(DashboardState.getState("PUBLISHED").value, "PUBLISHED");
  assert.equal(DashboardState.getState("garbage-input").value, "UNKNOWN");
  assert.equal(DashboardState.getState(null).value, "UNKNOWN");
});

test("mapPublicationGateResult() maps every certification-registry.js output to a valid state, and unmapped input to UNKNOWN (never fabricates PUBLISHED)", () => {
  assert.equal(DashboardState.mapPublicationGateResult("CUSTOMER_READY"), "PUBLISHED");
  assert.equal(DashboardState.mapPublicationGateResult("WITHHELD"), "WITHHELD");
  assert.equal(DashboardState.mapPublicationGateResult("REJECTED"), "REJECTED");
  assert.equal(DashboardState.mapPublicationGateResult("PENDING_ENRICHMENT"), "PROCESSING");
  assert.equal(DashboardState.mapPublicationGateResult("NOT_EVALUATED"), "UNKNOWN");
  assert.equal(DashboardState.mapPublicationGateResult("something_unrecognized"), "UNKNOWN");
  assert.equal(DashboardState.mapPublicationGateResult(undefined), "UNKNOWN");
});

test("module is frozen -- consumers cannot mutate the shared state vocabulary at runtime", () => {
  assert.throws(() => { DashboardState.STATES.PUBLISHED.severity = "critical"; }, TypeError);
  assert.throws(() => { DashboardState.STATES.NEW_FAKE_STATE = { value: "NEW_FAKE_STATE" }; }, TypeError);
});

test("SENTINELS exposes the three zero-fabrication constants as distinct string values", () => {
  assert.equal(DashboardState.SENTINELS.UNKNOWN, "UNKNOWN");
  assert.equal(DashboardState.SENTINELS.UNAVAILABLE, "UNAVAILABLE");
  assert.equal(DashboardState.SENTINELS.NOT_PROVIDED, "NOT_PROVIDED");
  const vals = Object.values(DashboardState.SENTINELS);
  assert.equal(new Set(vals).size, vals.length, "sentinel values must be pairwise distinct");
});

test("VERSION is a semver-shaped string", () => {
  assert.match(DashboardState.VERSION, /^\d+\.\d+\.\d+$/);
});
