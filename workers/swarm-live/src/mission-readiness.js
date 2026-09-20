// =============================================================================
// CYBERDUDEBIVASH SENTINEL APEX — SWARM MISSION READINESS / QUALITY CONTRACT
// V4.47.0
//
// Pure, dependency-free logic shared by runtime orchestration, readiness API,
// UI projections, certification, and tests. No network, KV, auth, or DOM I/O.
// =============================================================================

export const SWARM_AGENT_IDS = Object.freeze([
  'ioc-hunter',
  'cve-intelligence',
  'threat-hunter',
  'attack-mapper',
  'siem-defender',
  'ir-playbook',
  'exposure-analyst',
  'risk-synthesizer',
]);

export const AGENT_STATES = Object.freeze({
  READY: 'READY',
  QUEUED: 'QUEUED',
  RUNNING: 'RUNNING',
  COMPLETED: 'COMPLETED',
  NOT_APPLICABLE: 'NOT_APPLICABLE',
  DENIED: 'DENIED',
  UNAVAILABLE: 'UNAVAILABLE',
  DEGRADED: 'DEGRADED',
  FAILED: 'FAILED',
});

export const MISSION_QUALITY = Object.freeze({
  FULL_FABRIC: 'FULL_FABRIC',
  PROFILE_READY: 'PROFILE_READY',
  PARTIAL_FABRIC: 'PARTIAL_FABRIC',
  NO_MATCH: 'NO_MATCH',
  AI_DEGRADED: 'AI_DEGRADED',
  BLOCKED: 'BLOCKED',
  FULL_FABRIC_COMPLETE: 'FULL_FABRIC_COMPLETE',
  PROFILE_COMPLETE: 'PROFILE_COMPLETE',
  PARTIAL_FABRIC_COMPLETE: 'PARTIAL_FABRIC_COMPLETE',
  NO_MATCH_COMPLETE: 'NO_MATCH_COMPLETE',
  AI_DEGRADED_COMPLETE: 'AI_DEGRADED_COMPLETE',
  COMPLETED_WITH_WARNINGS: 'COMPLETED_WITH_WARNINGS',
  FAILED: 'FAILED',
});

function unique(values) {
  return [...new Set(values.filter((v) => typeof v === 'string' && v.trim()).map((v) => v.trim()))];
}

export function correlationMatches(correlation) {
  return Array.isArray(correlation?.matches) ? correlation.matches : [];
}

function techniqueValue(value) {
  if (typeof value === 'string') return value.trim() || null;
  if (!value || typeof value !== 'object') return null;
  const candidate = value.technique_id || value.id || value.name;
  return typeof candidate === 'string' && candidate.trim() ? candidate.trim() : null;
}

/**
 * Return every real dependency candidate present in canonical correlation
 * evidence. Candidate ordering follows canonical correlation ordering; the
 * runtime may try a bounded number of candidates when an earlier candidate
 * yields an empty-but-valid specialist result.
 */
export function buildDependencyCandidates(correlation) {
  const matches = correlationMatches(correlation);
  const reportIds = unique(matches.map((m) => m?.report_id));
  const cves = unique(matches.map((m) => m?.cve_id));
  const actors = unique(matches.map((m) => (
    m?.actor_tag && m.actor_tag !== 'UNATTRIBUTED' ? m.actor_tag : null
  )));
  const techniques = unique(matches.flatMap((m) => (
    Array.isArray(m?.ttps) ? m.ttps.map(techniqueValue) : []
  )));

  return Object.freeze({
    'ioc-hunter': Object.freeze(
      correlation?.ioc?.value ? [String(correlation.ioc.value)] : []
    ),
    'cve-intelligence': Object.freeze(cves),
    'threat-hunter': Object.freeze(actors),
    'attack-mapper': Object.freeze(techniques),
    'siem-defender': Object.freeze(reportIds),
    'ir-playbook': Object.freeze(reportIds),
    'exposure-analyst': Object.freeze(reportIds),
    'risk-synthesizer': Object.freeze(['fusion']),
  });
}

export function normalizeAgentState(state) {
  // Backward compatibility for persisted V4.46.x evidence.
  if (state === 'SKIPPED') return AGENT_STATES.NOT_APPLICABLE;
  return Object.values(AGENT_STATES).includes(state) ? state : state;
}

export function buildMissionReadiness(
  correlation,
  {
    entitlementEligible = true,
    quotaRemaining = null,
    llmReady = null,
    llmProviders = [],
    expectedAgentIds = SWARM_AGENT_IDS,
  } = {},
) {
  const candidates = buildDependencyCandidates(correlation);
  const expected = new Set(
    Array.isArray(expectedAgentIds) && expectedAgentIds.length
      ? expectedAgentIds.filter((id) => SWARM_AGENT_IDS.includes(id))
      : SWARM_AGENT_IDS
  );
  // IOC Hunter + Risk Synthesizer are mandatory control-plane bookends.
  expected.add('ioc-hunter');
  expected.add('risk-synthesizer');
  const matchCount = Number(
    correlation?.match_count ?? correlationMatches(correlation).length ?? 0
  );

  const agents = {};
  agents['ioc-hunter'] = {
    state: AGENT_STATES.READY,
    reason: 'canonical_correlation_available',
    candidates: candidates['ioc-hunter'],
  };

  for (const id of [
    'cve-intelligence',
    'threat-hunter',
    'attack-mapper',
    'siem-defender',
    'ir-playbook',
    'exposure-analyst',
  ]) {
    const values = candidates[id];
    if (!expected.has(id)) {
      agents[id] = {
        state: AGENT_STATES.NOT_APPLICABLE,
        reason: 'mission_profile_excluded',
        candidate_count: values.length,
        candidates: values,
      };
      continue;
    }

    agents[id] = values.length
      ? {
          state: AGENT_STATES.READY,
          reason: 'dependency_available',
          candidate_count: values.length,
          candidates: values,
        }
      : {
          state: AGENT_STATES.NOT_APPLICABLE,
          reason: 'dependency_input_absent',
          candidate_count: 0,
          candidates: [],
        };
  }

  agents['risk-synthesizer'] = llmReady === true
    ? {
        state: AGENT_STATES.READY,
        reason: 'llm_provider_ready',
        llm_ready: true,
        providers: [...llmProviders],
      }
    : llmReady === false
      ? {
          state: AGENT_STATES.DEGRADED,
          reason: 'llm_provider_unavailable_deterministic_fallback',
          llm_ready: false,
          providers: [...llmProviders],
        }
      : {
          state: AGENT_STATES.READY,
          reason: 'llm_readiness_not_probed',
          llm_ready: null,
          providers: [...llmProviders],
        };

  const blocked =
    entitlementEligible !== true ||
    (Number.isFinite(Number(quotaRemaining)) && Number(quotaRemaining) <= 0);

  const specialistIds = [
    'cve-intelligence',
    'threat-hunter',
    'attack-mapper',
    'siem-defender',
    'ir-playbook',
    'exposure-analyst',
  ];
  const expectedSpecialists = specialistIds.filter((id) => expected.has(id));
  const specialistReady = expectedSpecialists.filter((id) => agents[id].state === AGENT_STATES.READY).length;

  const fullProfile = expected.size === SWARM_AGENT_IDS.length;
  const expectedReady = [...expected].filter((id) => agents[id]?.state === AGENT_STATES.READY).length;
  const expectedApplicable = [...expected].filter((id) => (
    agents[id]?.state === AGENT_STATES.READY ||
    agents[id]?.state === AGENT_STATES.DEGRADED
  )).length;
  const allExpectedDependenciesReady =
    expectedSpecialists.every((id) => agents[id].state === AGENT_STATES.READY);

  let missionQuality;
  if (blocked) missionQuality = MISSION_QUALITY.BLOCKED;
  else if (matchCount === 0) missionQuality = MISSION_QUALITY.NO_MATCH;
  else if (fullProfile && allExpectedDependenciesReady && llmReady === false) missionQuality = MISSION_QUALITY.AI_DEGRADED;
  else if (fullProfile && allExpectedDependenciesReady) missionQuality = MISSION_QUALITY.FULL_FABRIC;
  else if (!fullProfile && allExpectedDependenciesReady && llmReady === true) missionQuality = MISSION_QUALITY.PROFILE_READY;
  else missionQuality = MISSION_QUALITY.PARTIAL_FABRIC;

  return Object.freeze({
    status: blocked ? 'blocked' : 'ready',
    mission_quality: missionQuality,
    match_count: matchCount,
    full_fabric: missionQuality === MISSION_QUALITY.FULL_FABRIC,
    profile_ready: missionQuality === MISSION_QUALITY.PROFILE_READY,
    ready_agents: expectedReady,
    applicable_agents: expectedApplicable,
    total_agents: expected.size,
    fleet_agents: SWARM_AGENT_IDS.length,
    expected_agents: Object.freeze([...expected]),
    specialist_ready: specialistReady,
    specialist_total: expectedSpecialists.length,
    entitlement_eligible: entitlementEligible === true,
    quota_remaining: Number.isFinite(Number(quotaRemaining)) ? Number(quotaRemaining) : null,
    llm_ready: llmReady,
    candidates,
    agents: Object.freeze(agents),
  });
}

export function classifyMissionCompletion(outcomes = {}, fused = {}, expectedAgentIds = SWARM_AGENT_IDS) {
  const normalized = Object.fromEntries(
    Object.entries(outcomes).map(([id, outcome]) => [
      id,
      { ...outcome, state: normalizeAgentState(outcome?.state) },
    ])
  );

  const states = Object.values(normalized).map((o) => o?.state);
  const hasFailure = states.some((s) => s === AGENT_STATES.FAILED);
  const hasDenied = states.some((s) => s === AGENT_STATES.DENIED);
  const hasUnavailable = states.some((s) => s === AGENT_STATES.UNAVAILABLE);
  const notApplicable = states.filter((s) => s === AGENT_STATES.NOT_APPLICABLE).length;
  const completed = states.filter((s) => s === AGENT_STATES.COMPLETED).length;
  const matchCount = Number(fused?.match_count || 0);
  const llmEnhanced = fused?.llm_enhanced === true;
  const expected = new Set(
    Array.isArray(expectedAgentIds) && expectedAgentIds.length
      ? expectedAgentIds.filter((id) => SWARM_AGENT_IDS.includes(id))
      : SWARM_AGENT_IDS
  );
  expected.add('ioc-hunter');
  expected.add('risk-synthesizer');
  const expectedStates = [...expected].map((id) => normalized[id]?.state);
  const expectedAllCompleted = expectedStates.every((state) => state === AGENT_STATES.COMPLETED);
  const fullProfile = expected.size === SWARM_AGENT_IDS.length;

  if (hasFailure || hasDenied || hasUnavailable) return MISSION_QUALITY.COMPLETED_WITH_WARNINGS;
  if (matchCount === 0) return MISSION_QUALITY.NO_MATCH_COMPLETE;
  if (fullProfile && expectedAllCompleted && llmEnhanced) return MISSION_QUALITY.FULL_FABRIC_COMPLETE;
  if (!fullProfile && expectedAllCompleted && llmEnhanced) return MISSION_QUALITY.PROFILE_COMPLETE;
  if (!llmEnhanced && expectedAllCompleted) return MISSION_QUALITY.AI_DEGRADED_COMPLETE;
  if (notApplicable > 0) return MISSION_QUALITY.PARTIAL_FABRIC_COMPLETE;
  if (completed === SWARM_AGENT_IDS.length) return MISSION_QUALITY.FULL_FABRIC_COMPLETE;
  return MISSION_QUALITY.COMPLETED_WITH_WARNINGS;
}

export function missionQualityLabel(value) {
  return String(value || '')
    .replaceAll('_', ' ')
    .trim();
}
