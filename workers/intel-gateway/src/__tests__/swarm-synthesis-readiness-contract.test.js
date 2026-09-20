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

test("readiness cannot report READY unless both provider configuration and paid-tier policy allow LLM synthesis", () => {
  const start = source.indexOf("async function handleSwarmSynthesis");
  const end = source.indexOf("// =============================================================================", start);
  const fn = source.slice(start, end > start ? end : start + 12000);

  assert.ok(fn.includes("const LLM_ENABLED = !!(env.DEEPSEEK_API_KEY || env.GROQ_API_KEY || env.OPENROUTER_API_KEY)"));
  assert.ok(fn.includes("const tierAllowsLLM = tierAllowsSwarmSynthesis(auth.tier)"));
  assert.ok(fn.includes("ready:       LLM_ENABLED && tierAllowsLLM"));
  assert.equal(fn.includes("ready:       LLM_ENABLED || tierAllowsLLM"), false);
});

test("current DeepSeek production model identifiers are used by callLLM", () => {
  const start = source.indexOf("async function callLLM");
  const end = source.indexOf("async function handleCopilot", start);

  assert.ok(start > 0);
  assert.ok(end > start);

  const fn = source.slice(start, end);

  assert.ok(fn.includes('"deepseek-flash"'));
  assert.ok(fn.includes('"deepseek-v4-pro"'));

  assert.equal(fn.includes('"deepseek-chat"'), false);
  assert.equal(fn.includes('"deepseek-reasoner"'), false);

  assert.ok(fn.includes("llm_provider_cascade_exhausted"));
});

test("non-reasoning swarm synthesis explicitly disables DeepSeek thinking", () => {
  const start = source.indexOf("async function callLLM");
  const end = source.indexOf("async function handleCopilot", start);

  assert.ok(start > 0);
  assert.ok(end > start);

  const fn = source.slice(start, end);

  assert.ok(fn.includes('"deepseek-flash"'));
  assert.ok(fn.includes('"deepseek-v4-pro"'));

  assert.ok(
    fn.includes('type: useR1 ? "enabled" : "disabled"')
  );

  assert.ok(
    fn.includes('reasoning_effort: useR1 ? "high" : "none"')
  );

  assert.ok(fn.includes('"openai/gpt-oss-120b"'));
  assert.ok(fn.includes('"deepseek/deepseek-v4.1-flash"'));
  assert.ok(fn.includes('"deepseek/deepseek-v4-pro-0813"'));

  assert.ok(fn.includes('"llm_provider_failure"'));
  assert.ok(fn.includes('"llm_provider_success"'));

  // Diagnostic logs must never contain secret values or prompt bodies.
  assert.equal(
    fn.includes("DEEPSEEK_API_KEY,"),
    false
  );

  assert.equal(
    fn.includes("GROQ_API_KEY,"),
    false
  );

  assert.equal(
    fn.includes("OPENROUTER_API_KEY,"),
    false
  );
});
