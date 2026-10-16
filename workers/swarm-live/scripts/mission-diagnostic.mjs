/**
 * P0 bounded failure evidence for authenticated V4.47.
 * Emit only fixed eight-agent identities and terminal states, never IOC values,
 * customer payloads, API keys, raw result bodies, or backend error messages.
 */
const AGENTS = Object.freeze([
  'ioc-hunter', 'cve-intelligence', 'threat-hunter', 'attack-mapper',
  'siem-defender', 'ir-playbook', 'exposure-analyst', 'risk-synthesizer',
]);
const SAFE_STATES = new Set([
  'COMPLETED', 'DEGRADED', 'DENIED', 'UNAVAILABLE', 'FAILED', 'NOT_APPLICABLE',
]);
const SAFE_EVENT_TYPES = new Set([
  'agent.completed', 'agent.degraded', 'agent.denied', 'agent.unavailable',
  'agent.failed', 'agent.not_applicable',
]);

export function summarizeMissionDiagnostic(events, terminal) {
  const observed = new Map();
  for (const event of Array.isArray(events) ? events : []) {
    if (!AGENTS.includes(event?.agent_id)) continue;
    if (!SAFE_EVENT_TYPES.has(event?.event_type)) continue;
    const state = SAFE_STATES.has(event?.state) ? event.state : 'UNKNOWN';
    observed.set(event.agent_id, state);
  }
  const result = terminal?.result;
  return {
    mission_quality: String(terminal?.mission_quality || 'MISSING').slice(0, 32),
    llm_enhanced: result?.llm_enhanced === true,
    ai_mode: result?.ai_mode === 'deterministic_fallback' ? 'deterministic_fallback' : 'other',
    agents: Object.fromEntries(AGENTS.map(id => [id, observed.get(id) || 'NO_TERMINAL_EVENT'])),
  };
}
