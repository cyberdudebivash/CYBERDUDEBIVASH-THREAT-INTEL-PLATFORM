/**
 * P0 bounded failure evidence for authenticated V4.47 certification.
 *
 * Emit ONLY fixed agent identities, terminal state, bounded HTTP status and
 * allowlisted gateway failure codes. Never echo candidate IOC values, lookup
 * parameters, customer payloads, API keys, raw results, backend error messages
 * or arbitrary upstream error strings. This module performs no network I/O.
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
const SAFE_ERROR_CODES = new Set([
  'report_not_found', 'paid_report_unavailable',
  'ir_guidance_failed', 'exposure_analysis_failed',
  'specialist_transport_failed', 'specialist_candidate_exhausted',
  'no_backend_route_configured', 'authentication_required',
  'forbidden', 'scope_required', 'rate_exceeded',
  'internal_error', 'service_unavailable',
]);
const FAILURE_STATES = new Set(['FAILED', 'DENIED', 'UNAVAILABLE', 'DEGRADED']);

function safeHttpStatus(event) {
  // The existing worker emits per-attempt numeric HTTP statuses, not a
  // top-level http_status. Examine only the last bounded attempt; the
  // candidate itself contains potentially restricted report identifiers.
  const attempts = Array.isArray(event?.attempted_candidates)
    ? event.attempted_candidates.slice(0, 4) : [];
  const latest = attempts.length ? attempts[attempts.length - 1] : null;
  const status = latest?.http_status ?? event?.http_status;
  return Number.isInteger(status) && status >= 100 && status <= 599
    ? status : null;
}

function safeErrorCode(event) {
  const raw = event?.detail?.error;
  return typeof raw === 'string' && SAFE_ERROR_CODES.has(raw) ? raw : null;
}

export function summarizeMissionDiagnostic(events, terminal) {
  const observed = new Map();
  const failures = {};
  for (const event of Array.isArray(events) ? events : []) {
    if (!AGENTS.includes(event?.agent_id)) continue;
    if (!SAFE_EVENT_TYPES.has(event?.event_type)) continue;
    const state = SAFE_STATES.has(event?.state) ? event.state : 'UNKNOWN';
    observed.set(event.agent_id, state);
    if (FAILURE_STATES.has(state)) {
      failures[event.agent_id] = {
        state,
        http_status: safeHttpStatus(event),
        error_code: safeErrorCode(event),
      };
    } else {
      delete failures[event.agent_id];
    }
  }

  const result = terminal?.result;
  // Failures retain fixed fleet ordering, never event ordering or any untrusted
  // customer-supplied identity. Terminal mission quality is mapped rather than
  // printing arbitrary strings from an upstream payload.
  const quality = new Set([
    'FULL_FABRIC_COMPLETE', 'COMPLETED_WITH_WARNINGS',
    'PARTIAL_FABRIC_COMPLETE', 'NO_MATCH_COMPLETE',
    'AI_DEGRADED_COMPLETE', 'FAILED',
  ]);
  return {
    mission_quality: quality.has(terminal?.mission_quality)
      ? terminal.mission_quality : 'UNKNOWN',
    llm_enhanced: result?.llm_enhanced === true,
    ai_mode: result?.ai_mode === 'deterministic_fallback'
      ? 'deterministic_fallback' : 'other',
    agents: Object.fromEntries(AGENTS.map(id => [id, observed.get(id) || 'NO_TERMINAL_EVENT'])),
    failures: Object.fromEntries(AGENTS.filter(id => failures[id]).map(id => [id, failures[id]])),
  };
}
