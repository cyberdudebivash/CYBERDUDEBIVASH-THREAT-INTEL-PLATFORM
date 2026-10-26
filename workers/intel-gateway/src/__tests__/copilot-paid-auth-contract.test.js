import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

// Source-level zero-cost regression lock. This supplements (does not replace)
// real anonymous/FREE/PRO authenticated production tests for VDP TI-03.
const source = readFileSync('src/index.js', 'utf8');
const start = source.indexOf('async function handleCopilot(request, env, auth, method, path)');
const end = source.indexOf('// =============================================================================', start + 40);
assert.ok(start >= 0 && end > start, 'canonical Copilot handler not found');
const fn = source.slice(start, end);

const required = (text, label) => {
  const i = fn.indexOf(text);
  assert.ok(i >= 0, label + ' missing');
  return i;
};

test('POST Copilot denies missing or invalid API credentials before request parsing', () => {
  const post = required('if (method !== "POST") return jsonResp', 'POST method boundary');
  const auth = required('if (!auth?.key || auth.error) return jsonResp({ error: "Authentication required" }, 401)', '401 auth gate');
  const tier = required('if (!tierAllowsLLM) return jsonResp({ error: "Subscription required" }, 403)', '403 paid-tier gate');
  const parse = required('body = await request.json()', 'request parser');
  assert.ok(post < auth && auth < tier && tier < parse, 'auth/tier validation must precede parsing');
  assert.doesNotMatch(fn.slice(post, auth), /copilotTemplate\(|callLLM\(|await request\.json\(/);
});

test('paid-tier enforcement precedes deterministic fallback AND LLM calls', () => {
  const tier = required('if (!tierAllowsLLM) return jsonResp({ error: "Subscription required" }, 403)', 'paid-tier guard');
  const deterministic = required('if (mode === "ioc_summary" || mode === "mitre_mapping")', 'deterministic modes');
  const template = required('...copilotTemplate(mode, threat, question)', 'template output');
  const llm = required('await callLLM(env, systemPrompt, userPrompt, useR1)', 'generative output');
  assert.ok(tier < deterministic && tier < template && tier < llm);
});

test('only PRO, ENTERPRISE and MSSP can enter paid Copilot routes', () => {
  assert.match(fn, /new Set\(\[TIERS\.PRO, TIERS\.ENTERPRISE, TIERS\.MSSP\]\)/);
  assert.match(fn, /const tierAllowsLLM = LLM_TIERS\.has\(auth\.tier\)/);
  assert.doesNotMatch(fn, /LLM_TIERS\s*=\s*new Set\(\[[^\]]*TIERS\.FREE/);
});

test('public modes expose coarse availability without provider credentials', () => {
  const modes = required('if (method === "GET" && path.includes("/modes"))', 'mode read contract');
  const gate = required('if (!auth?.key || auth.error)', 'query auth gate');
  const publicContract = fn.slice(modes, gate);
  assert.match(publicContract, /llm_enabled:\s*LLM_ENABLED && tierAllowsLLM/);
  assert.doesNotMatch(publicContract, /DEEPSEEK_API_KEY\s*:|GROQ_API_KEY\s*:|OPENROUTER_API_KEY\s*:/);
});

test('the production router invokes canonical Copilot with authenticated context', () => {
  assert.match(source, /if \(path\.startsWith\("\/api\/v1\/copilot"\)\)\s*\{\s*return await handleCopilot\(request, env, auth, method, path\);/);
});
