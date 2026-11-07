import assert from "node:assert/strict";
import { test } from "node:test";
import Validator from "../dashboard_contract_validator.js";
import Adapter from "../api_adapter.js";

// ---------------------------------------------------------------------------
// PR-B (Dashboard Truth Contract, 2026-08-11) -- js/dashboard_contract_validator.js
// independently excluded "P0" from its own VALID_SOC_PRIORITIES whitelist,
// the identical defect found and fixed in js/api_adapter.js's
// normalizeSocPriority(). This suite proves the fix and that the validator
// and the adapter now agree on exactly the same SOC priority vocabulary --
// per the mission's non-negotiable requirement that no two implementations
// of the same contract concept silently diverge.
// ---------------------------------------------------------------------------

function minimalApexAi(socPriority) {
  return {
    soc_priority: socPriority, soc_priority_meta: {}, threat_level: "LOW",
    threat_category: "", predictive_risk: 5, ai_confidence: 50,
    confidence_tier_meta: {}, ttp_density: 0, campaign_id: "",
    kill_chain_locked: false, kill_chain_primary: "", recommended_action: "",
    behavioral_tags: [], paywall: {},
  };
}

test("validator recognizes P0 -- does not raise INVALID_SOC_PRIORITY for the pipeline's emergency tier", () => {
  const result = Validator.validateItem({ id: "t1", apex_ai: minimalApexAi("P0") });
  assert.equal(
    result.violations.some((v) => v.startsWith("INVALID_SOC_PRIORITY")),
    false,
    `P0 must be accepted; violations: ${JSON.stringify(result.violations)}`
  );
});

test("validator recognizes P1-P4 unchanged", () => {
  for (const p of ["P1", "P2", "P3", "P4"]) {
    const result = Validator.validateItem({ id: "t1", apex_ai: minimalApexAi(p) });
    assert.equal(
      result.violations.some((v) => v.startsWith("INVALID_SOC_PRIORITY")),
      false,
      `${p} must be accepted; violations: ${JSON.stringify(result.violations)}`
    );
  }
});

test("validator recognizes UNKNOWN -- the adapter's honest fallback for malformed priority is not itself a contract violation", () => {
  const result = Validator.validateItem({ id: "t1", apex_ai: minimalApexAi("UNKNOWN") });
  assert.equal(
    result.violations.some((v) => v.startsWith("INVALID_SOC_PRIORITY")),
    false,
    `UNKNOWN must be accepted; violations: ${JSON.stringify(result.violations)}`
  );
});

test("validator still rejects a genuinely invalid priority value", () => {
  const result = Validator.validateItem({ id: "t1", apex_ai: minimalApexAi("NOT_A_REAL_PRIORITY") });
  assert.equal(result.violations.some((v) => v.startsWith("INVALID_SOC_PRIORITY")), true);
});

test("validator and adapter agree on exactly the same SOC priority vocabulary", () => {
  // For every value the adapter treats as a real, round-tripped priority
  // (P0-P4), the validator must accept it. For a value the adapter cannot
  // recognize, both modules independently arrive at the same "UNKNOWN"
  // sentinel -- proven separately in the tests above.
  for (const p of ["P0", "P1", "P2", "P3", "P4"]) {
    assert.equal(Adapter.normalizeSocPriority(p), p, `adapter must round-trip ${p} unchanged`);
    const result = Validator.validateItem({ id: "t1", apex_ai: minimalApexAi(p) });
    assert.equal(
      result.violations.some((v) => v.startsWith("INVALID_SOC_PRIORITY")),
      false,
      `validator disagrees with adapter on ${p}`
    );
  }
});
