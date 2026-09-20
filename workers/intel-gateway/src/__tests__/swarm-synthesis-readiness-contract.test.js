import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const source = readFileSync("src/index.js", "utf8");

test("SWARM synthesis health reports tier-aware configuration readiness", () => {
  const start = source.indexOf("async function handleSwarmSynthesis");
  assert.ok(start > 0, "handleSwarmSynthesis missing");
  const end = source.indexOf("// =============================================================================", start);
  const fn = source.slice(start, end > start ? end : start + 12000);

  assert.ok(fn.includes("const tierAllowsLLM = tierAllowsSwarmSynthesis(auth.tier)"));
  assert.ok(fn.includes("ready:       LLM_ENABLED && tierAllowsLLM"));
  assert.ok(fn.includes("tier_llm:    tierAllowsLLM"));
  assert.ok(fn.includes('readiness_scope: "configuration"'));
  assert.ok(fn.includes("providers:"));
});

test("synthesis readiness health remains non-generative and does not invoke callLLM", () => {
  const start = source.indexOf('if (method === "GET" && path.includes("/health"))');
  assert.ok(start > 0);
  const end = source.indexOf("if (method !==", start);
  const healthBranch = source.slice(start, end);
  assert.ok(!healthBranch.includes("callLLM("));
});
