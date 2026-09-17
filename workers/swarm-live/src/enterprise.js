export const ENTERPRISE_PROTOCOL = 'cdb.swarm.v1';

export function sanitizeForCustomer(value, depth = 0) {
  if (depth > 8) return '[TRUNCATED]';
  if (value == null || typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'string') return value.slice(0, 4096);
  if (Array.isArray(value)) return value.slice(0, 256).map((item) => sanitizeForCustomer(item, depth + 1));
  if (typeof value !== 'object') return String(value).slice(0, 4096);

  const deny = /(^|_)(secret|token|password|authorization|api[_-]?key|cookie|credential|signature|hmac|jwt|private[_-]?key)($|_)/i;
  const out = {};
  for (const [key, item] of Object.entries(value).slice(0, 256)) {
    out[key] = deny.test(key) ? '[REDACTED]' : sanitizeForCustomer(item, depth + 1);
  }
  return out;
}

export function missionSummary(events = []) {
  const list = Array.isArray(events) ? events : [];
  const latest = list[list.length - 1] || null;
  const mission = list.find((e) => e?.mission_id)?.mission_id || null;
  const correlation = list.find((e) => e?.correlation_id)?.correlation_id || null;
  const execution = list.find((e) => e?.mesh_execution_id)?.mesh_execution_id ||
    list.find((e) => e?.execution_id)?.execution_id || null;
  const agents = new Map();

  for (const event of list) {
    if (!event?.agent_id) continue;
    const current = agents.get(event.agent_id) || {
      agent_id: event.agent_id,
      agent_name: event.agent_name || event.agent_id,
      capability: event.capability || null,
      state: 'QUEUED',
      started_at: null,
      completed_at: null,
      result: null,
    };
    current.state = event.state || current.state;
    if (event.event_type === 'agent.started' && !current.started_at) current.started_at = event.timestamp || null;
    if (event.event_type === 'agent.completed') {
      current.completed_at = event.timestamp || null;
      current.result = sanitizeForCustomer(event.result ?? null);
    }
    agents.set(event.agent_id, current);
  }

  return {
    protocol: ENTERPRISE_PROTOCOL,
    mission_id: mission,
    correlation_id: correlation,
    execution_id: execution,
    state: latest?.state || 'UNKNOWN',
    mesh_certified: list.some((e) => e?.mesh_certified === true),
    event_count: list.length,
    agents: [...agents.values()],
    result: sanitizeForCustomer(latest?.result ?? null),
    started_at: list[0]?.timestamp || null,
    completed_at: latest?.event_type === 'mission.completed' ? latest.timestamp : null,
  };
}

export function buildMissionReport(summary) {
  const safe = sanitizeForCustomer(summary || {});
  return {
    report_schema: 'cdb.swarm.report.v1',
    generated_at: new Date().toISOString(),
    brand: 'CYBERDUDEBIVASH SENTINEL APEX',
    classification: 'CUSTOMER SECURITY OPERATIONS',
    ...safe,
  };
}

export function validateMissionInput(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'invalid_request';
  if (typeof body.ioc_value !== 'string' || !body.ioc_value.trim()) return 'ioc_value_required';
  if (body.ioc_value.length > 256) return 'ioc_value_too_long';
  if (body.ioc_type !== undefined && typeof body.ioc_type !== 'string') return 'invalid_ioc_type';
  return null;
}
