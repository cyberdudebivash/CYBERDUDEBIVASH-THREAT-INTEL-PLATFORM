// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Swarm Synthesis (pure module)
//
// v4.45: the deterministic, side-effect-free pieces of the AI Swarm Synthesis
// feature (a real LLM-generated narrative for a completed SUPER AGENT SWARM
// mission, replacing the risk-synthesizer agent's static recommendation
// string) live here, for the identical reason subscription-lifecycle.js and
// gumroad-lifecycle.js were extracted (see their own header comments):
// index.js transitively imports pricing.js, which imports pricing-data.json
// without a `with {type:'json'}` attribute -- fine for wrangler/esbuild's
// bundler, but Node's native `node --test` ESM loader rejects it outright,
// so a test file importing anything from ../index.js directly could never
// run. This file has ZERO imports of its own -- no KV, no network, no other
// Worker module -- so it is unit-testable in CI and importable by index.js
// unchanged.
//
// index.js's handleSwarmSynthesis() is the only production caller. It
// composes these pure helpers with the ALREADY-EXISTING callLLM() (index.js,
// unchanged -- the same DeepSeek -> GROQ -> OpenRouter cascade
// handleCopilot already uses in production) to build the actual HTTP
// handler. Principle 4 (Reuse Before Build): zero new LLM-calling code,
// zero new provider integration -- this module only builds the prompt and
// decides the tier gate, both pure functions with no side effects.
// =============================================================================

// Same three paid tiers handleCopilot already gates LLM access behind
// (index.js TIERS.PRO/ENTERPRISE/MSSP -- these are that enum's literal
// string values). Compared directly rather than importing TIERS itself,
// the same way every other extracted module in this codebase already
// compares auth.tier to a literal tier string (e.g. api-extensions.js's
// enforceScopeMiddleware, exercised in its tests via auth.tier === "FREE").
const SWARM_SYNTHESIS_LLM_TIERS = new Set(["PRO", "ENTERPRISE", "MSSP"]);

export function tierAllowsSwarmSynthesis(tier) {
  return SWARM_SYNTHESIS_LLM_TIERS.has(tier);
}

export const SWARM_SYNTHESIS_SYSTEM_PROMPT = `You are SENTINEL APEX's SUPER AGENT SWARM Risk Synthesizer -- the final analyst stage of a live, multi-agent CTI correlation mission for CYBERDUDEBIVASH(R) Sentinel APEX, an enterprise threat intelligence platform.

You are given the JSON output of several independent specialist agents that have ALREADY executed real backend queries against a single indicator of compromise (IOC): IOC correlation, CVE intelligence, threat actor attribution, ATT&CK technique mapping, SIEM detection coverage, incident-response guidance, and exposure analysis. Some specialists may show state DENIED (insufficient customer entitlement) or FAILED (transport error) -- treat those as honest coverage gaps, never invent data to fill them.

Write a concise, decision-ready analyst narrative (150-250 words) that:
- States the overall verdict and why, citing only fields actually present in the JSON
- Synthesizes across specialists (do not just restate each one in turn)
- Calls out what a SOC analyst should prioritize first
- Explicitly notes any DENIED or FAILED specialist as a coverage gap, never as a negative finding about the indicator itself
- Never fabricates a CVE ID, actor name, ATT&CK technique, or score that is not present in the input JSON`;

// Keeps the serialized mission JSON bounded -- the same cost/size discipline
// handleCopilot's RAG context already applies (index.js, ragContext build:
// `.slice(0, 1500)` truncation). A prompt-size guard, not a security control.
const MAX_OUTCOMES_JSON_CHARS = 4000;

/**
 * Pure function: builds the user prompt for callLLM() from a swarm
 * mission's canonical IOC/verdict plus its per-agent specialist outcomes.
 * No KV/network/env access -- swarm-live's executeMission() (via a real
 * HTTP call to POST /api/v1/swarm-synthesis) and index.js's
 * handleSwarmSynthesis() are the only production callers.
 * @param {{ioc_value?: string, ioc_type?: string, verdict?: string, outcomes?: Record<string, object>}} mission
 * @returns {string}
 */
export function buildSwarmSynthesisPrompt(mission) {
  const ioc_value = mission?.ioc_value || null;
  const ioc_type = mission?.ioc_type || null;
  const verdict = mission?.verdict || "unknown";
  const outcomes = mission?.outcomes && typeof mission.outcomes === "object" ? mission.outcomes : {};
  const serialized = JSON.stringify(outcomes, null, 2).slice(0, MAX_OUTCOMES_JSON_CHARS);

  return `Mission indicator: ${ioc_value || "(unknown)"} (${ioc_type || "auto"})
Canonical verdict: ${verdict}

Specialist agent outcomes (JSON):
${serialized}

Write the analyst narrative now.`;
}
