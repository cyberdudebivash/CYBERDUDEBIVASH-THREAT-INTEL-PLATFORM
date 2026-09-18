import assert from "node:assert/strict";
import { test } from "node:test";
import { tierAllowsSwarmSynthesis, buildSwarmSynthesisPrompt, SWARM_SYNTHESIS_SYSTEM_PROMPT } from "../swarm-synthesis.js";

// ---------------------------------------------------------------------------
// swarm-synthesis.js is a dependency-free module (no KV/network/env access)
// specifically so it is importable directly by `node --test` without going
// through index.js's ESM chain (pricing.js -> pricing-data.json trips
// Node's native loader outside the wrangler/esbuild bundler -- see
// subscription-lifecycle.js's header comment for the full precedent this
// follows). These tests cover the pure prompt-building and tier-gate logic
// that index.js's handleSwarmSynthesis() composes with the existing,
// unchanged callLLM() to build the actual HTTP handler.
// ---------------------------------------------------------------------------

test("tierAllowsSwarmSynthesis grants PRO/ENTERPRISE/MSSP, matching handleCopilot's existing LLM tier gate", () => {
  assert.equal(tierAllowsSwarmSynthesis("PRO"), true);
  assert.equal(tierAllowsSwarmSynthesis("ENTERPRISE"), true);
  assert.equal(tierAllowsSwarmSynthesis("MSSP"), true);
});

test("tierAllowsSwarmSynthesis denies FREE, unknown, and missing tiers", () => {
  assert.equal(tierAllowsSwarmSynthesis("FREE"), false);
  assert.equal(tierAllowsSwarmSynthesis("not_a_real_tier"), false);
  assert.equal(tierAllowsSwarmSynthesis(undefined), false);
  assert.equal(tierAllowsSwarmSynthesis(null), false);
});

test("buildSwarmSynthesisPrompt embeds the IOC, type, verdict, and serialized outcomes", () => {
  const prompt = buildSwarmSynthesisPrompt({
    ioc_value: "8.8.8.8",
    ioc_type: "ipv4",
    verdict: "suspicious",
    outcomes: {
      "cve-intelligence": { basis: "backend_execution", state: "COMPLETED", result: { cves: [{ cve_id: "CVE-2026-11111" }] } },
    },
  });
  assert.match(prompt, /8\.8\.8\.8/);
  assert.match(prompt, /ipv4/);
  assert.match(prompt, /suspicious/);
  assert.match(prompt, /CVE-2026-11111/);
});

test("buildSwarmSynthesisPrompt falls back to honest placeholders on a missing/malformed mission", () => {
  assert.match(buildSwarmSynthesisPrompt({}), /\(unknown\)/);
  assert.match(buildSwarmSynthesisPrompt({}), /auto/);
  assert.match(buildSwarmSynthesisPrompt({}), /unknown/);
  // Never throws on a fully absent mission object -- the same fail-closed-
  // but-graceful discipline the rest of this codebase applies (e.g.
  // persistMission's no-op-without-KV-binding pattern in swarm-live).
  assert.doesNotThrow(() => buildSwarmSynthesisPrompt(undefined));
  assert.doesNotThrow(() => buildSwarmSynthesisPrompt(null));
  assert.doesNotThrow(() => buildSwarmSynthesisPrompt({ outcomes: null }));
});

test("buildSwarmSynthesisPrompt bounds prompt size even for an oversized outcomes payload", () => {
  const huge = { "cve-intelligence": { result: { note: "x".repeat(50_000) } } };
  const prompt = buildSwarmSynthesisPrompt({ ioc_value: "1.2.3.4", outcomes: huge });
  // Same cost/size discipline as handleCopilot's RAG context truncation --
  // a prompt-size guard, not a security control, but it must actually bound
  // the output rather than passing an unbounded payload through to callLLM.
  assert.ok(prompt.length < 10_000, `expected a bounded prompt, got ${prompt.length} chars`);
});

test("SWARM_SYNTHESIS_SYSTEM_PROMPT is a non-empty string that instructs against fabrication", () => {
  assert.equal(typeof SWARM_SYNTHESIS_SYSTEM_PROMPT, "string");
  assert.ok(SWARM_SYNTHESIS_SYSTEM_PROMPT.length > 0);
  assert.match(SWARM_SYNTHESIS_SYSTEM_PROMPT.toLowerCase(), /never fabricat/);
});
