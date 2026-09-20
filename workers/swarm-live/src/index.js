import {
  AGENT_STATES,
  buildDependencyCandidates,
  buildMissionReadiness,
  classifyMissionCompletion,
} from './mission-readiness.js';
import { adaptSpecialistResponse } from './specialist-contract.js';
import { buildEvidenceGraph } from './evidence-graph.js';
import {
  listMissionProfiles,
  resolveMissionProfile,
} from './mission-profiles.js';

const PROTOCOL = 'cdb.swarm.v1';
const PRODUCT = 'sentinel-apex';
const MAX_BODY_BYTES = 32 * 1024;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MISSION_TTL_SECONDS = 30 * 24 * 60 * 60;
const MISSION_INDEX_PREFIX = 'sentinel-mission-idx:';
// Far enough out (year 2286) to stay positive for any real Date.now(), used
// only to invert timestamps into a lexicographically-descending sort key.
const INDEX_TS_CEILING = 9999999999999;
const IDEMPOTENCY_PREFIX = 'sentinel-idem:';
// Self-healing window for an in-flight idempotency lock: if a mission's
// own `finally` block is somehow never reached (worker eviction between
// the lock write and executeMission's completion), the caller's next
// retry after this window is treated as a fresh mission rather than
// wedged behind a stale 409 for the full 30-day mission retention period.
const IDEMPOTENCY_LOCK_TTL_SECONDS = 600;

const AGENTS = Object.freeze([
  ['ioc-hunter', 'IOC Hunter', 'ioc.correlation'],
  ['cve-intelligence', 'CVE Intelligence Agent', 'cve.analysis'],
  ['threat-hunter', 'Threat Hunter', 'threat.hunting'],
  ['attack-mapper', 'ATT&CK Mapper', 'attack.mapping'],
  ['siem-defender', 'SIEM Defender', 'siem.defense'],
  ['ir-playbook', 'Incident Response Playbook Agent', 'ir.playbook'],
  ['exposure-analyst', 'Exposure Analyst', 'exposure.analysis'],
  ['risk-synthesizer', 'Risk Synthesizer', 'risk.synthesis'],
].map(([id, name, capability]) => Object.freeze({ id, name, capability })));

const AGENT_VISUALS = Object.freeze({
  'ioc-hunter': Object.freeze({
    mesh: 'IOC',
    accent: '#00E7FF',
    soft: 'rgba(0,231,255,.18)',
    ring: 'rgba(0,231,255,.48)',
  }),
  'cve-intelligence': Object.freeze({
    mesh: 'CVE',
    accent: '#8B5CFF',
    soft: 'rgba(139,92,255,.18)',
    ring: 'rgba(139,92,255,.48)',
  }),
  'threat-hunter': Object.freeze({
    mesh: 'THREAT',
    accent: '#FF8A00',
    soft: 'rgba(255,138,0,.18)',
    ring: 'rgba(255,138,0,.50)',
  }),
  'attack-mapper': Object.freeze({
    mesh: 'ATT&CK',
    accent: '#FF4FD8',
    soft: 'rgba(255,79,216,.18)',
    ring: 'rgba(255,79,216,.48)',
  }),
  'siem-defender': Object.freeze({
    mesh: 'SIEM',
    accent: '#00FFA8',
    soft: 'rgba(0,255,168,.18)',
    ring: 'rgba(0,255,168,.46)',
  }),
  'ir-playbook': Object.freeze({
    mesh: 'IR',
    accent: '#FFD400',
    soft: 'rgba(255,212,0,.18)',
    ring: 'rgba(255,212,0,.48)',
  }),
  'exposure-analyst': Object.freeze({
    mesh: 'EXPOSURE',
    accent: '#5BE1FF',
    soft: 'rgba(91,225,255,.18)',
    ring: 'rgba(91,225,255,.48)',
  }),
  'risk-synthesizer': Object.freeze({
    mesh: 'RISK',
    accent: '#FF4D5A',
    soft: 'rgba(255,77,90,.18)',
    ring: 'rgba(255,77,90,.50)',
  }),
});


// Agents backed by a genuine, distinct, already-routed intel-gateway endpoint
// (Reuse Before Build: these call existing production routes, not new ones).
// ioc-hunter isn't listed here -- its "call" is the canonical correlate
// request executeMission() already makes to gate the whole mission.
const MAX_SPECIALIST_CANDIDATES = 3;

const SPECIALIST_ROUTES = Object.freeze({
  'cve-intelligence': Object.freeze({ id: 'cve-intelligence', path: '/api/cves', paramKey: 'cve_id', pick: firstCveId, emptyReason: 'no CVE identifier present in the correlated matches' }),
  'threat-hunter': Object.freeze({ id: 'threat-hunter', path: '/api/actors', paramKey: 'actor_id', pick: firstActorTag, emptyReason: 'no attributed actor present in the correlated matches' }),
  'siem-defender': Object.freeze({ id: 'siem-defender', path: '/api/v1/detections', paramKey: 'intel_id', pick: firstReportId, emptyReason: 'no matched intelligence report to query detection coverage for' }),
  'attack-mapper': Object.freeze({ id: 'attack-mapper', path: '/api/search', paramKey: 'q', pick: firstTechnique, emptyReason: 'no ATT&CK technique present in the correlated matches' }),
  // Both now backed by real routes (GET /api/intel/ir-guidance,
  // GET /api/intel/exposure) added specifically to close this gap -- each
  // reuses its P23.4/P27.3 engine (_buildIRChecklist/_deriveExposure)
  // unchanged, just shaped as JSON instead of the HTML fragment those
  // engines render into on the report page. No more derived-only specialists.
  'ir-playbook': Object.freeze({ id: 'ir-playbook', path: '/api/intel/ir-guidance', paramKey: 'report_id', pick: firstReportId, emptyReason: 'no matched intelligence report to derive IR guidance from' }),
  'exposure-analyst': Object.freeze({ id: 'exposure-analyst', path: '/api/intel/exposure', paramKey: 'report_id', pick: firstReportId, emptyReason: 'no matched intelligence report to derive exposure analysis from' }),
});

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      ...extra,
    },
  });
}

function safeRequestId(request) {
  const supplied = request.headers.get('x-request-id') || '';
  return ID_RE.test(supplied) ? supplied : `sentinel-swarm-${crypto.randomUUID()}`;
}

function authHeaders(request) {
  const out = new Headers({ accept: 'application/json' });
  for (const name of ['authorization', 'x-api-key', 'x-sentinel-key']) {
    const value = request.headers.get(name);
    if (value) out.set(name, value);
  }
  return out;
}

function hasAuth(headers) {
  return Boolean(
    headers.get('authorization') ||
    headers.get('x-api-key') ||
    headers.get('x-sentinel-key')
  );
}

/**
 * Conservative CTI refanging for analyst-pasted observables.
 * Only well-known defanging delimiters are normalized; hashes are left
 * byte-for-byte unchanged. The canonical backend still performs all real
 * classification/correlation and remains the source of truth.
 */
function normalizeIocValue(value, iocType = 'auto') {
  const original = String(value ?? '').trim();
  const type = String(iocType || 'auto').trim().toLowerCase();
  if (!original || type === 'hash') {
    return { value: original, original, refanged: false };
  }

  let normalized = original
    .replace(/^hxxps(?=[:[])/i, 'https')
    .replace(/^hxxp(?=[:[])/i, 'http')
    .replace(/\[\s*:\s*\/\/\s*\]/g, '://')
    .replace(/\[\s*:\s*\]/g, ':')
    .replace(/\[\s*\.\s*\]/g, '.')
    .replace(/\(\s*\.\s*\)/g, '.')
    .replace(/\{\s*\.\s*\}/g, '.');

  return { value: normalized, original, refanged: normalized !== original };
}

// A stable, non-reversible per-caller storage partition for mission history
// -- NOT an identity or entitlement decision (this worker still never
// derives tenant/tier itself; the canonical route remains the sole
// authority on who is allowed to run anything). Without this, a mission
// LIST endpoint would enumerate every customer's mission metadata to any
// caller holding a valid credential (single-mission-by-id lookup is safe
// today only because a mission_id is an unguessable random UUID -- that
// capability-based protection doesn't extend to a listable index). Hashing
// the caller's own already-forwarded credential gives each distinct
// credential its own isolated history with zero new identity plumbing and
// zero calls to any other service. Same real credential in -> same
// partition out; a different customer's different credential always
// produces a different partition.
async function credentialPartition(headers) {
  const credential = headers.get('authorization') || headers.get('x-api-key') || headers.get('x-sentinel-key');
  if (!credential) return null;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(credential));
  return [...new Uint8Array(digest)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function allMatches(correlation) {
  return Array.isArray(correlation?.matches) ? correlation.matches : [];
}

function firstCveId(correlation) {
  const m = allMatches(correlation).find((x) => x?.cve_id);
  return m?.cve_id || null;
}

function firstActorTag(correlation) {
  const m = allMatches(correlation).find((x) => x?.actor_tag && x.actor_tag !== 'UNATTRIBUTED');
  return m?.actor_tag || null;
}

function firstReportId(correlation) {
  const m = allMatches(correlation)[0];
  return m?.report_id || null;
}

function firstTechnique(correlation) {
  for (const m of allMatches(correlation)) {
    if (Array.isArray(m?.ttps) && m.ttps.length) {
      const t = m.ttps[0];
      const name = typeof t === 'string' ? t : (t?.technique_id || t?.name || t?.id);
      if (name) return String(name);
    }
  }
  return null;
}

function responseSnippet(body) {
  if (!body || typeof body !== 'object') return null;
  return {
    error: body.error || null,
    message: body.message || null,
    reason: body.reason || null,
    request_id: body.request_id || null,
  };
}

async function canonicalGatewayFetch(env, url, init = {}) {
  if (env?.CANONICAL_GATEWAY && typeof env.CANONICAL_GATEWAY.fetch === 'function') {
    const request = url instanceof Request ? url : new Request(String(url), init);
    return env.CANONICAL_GATEWAY.fetch(request);
  }
  // Preserve the platform/browser fetch(url, init) calling convention when
  // the private binding is absent. This keeps local/test compatibility and
  // avoids changing observable fallback semantics just because production
  // prefers the Worker service binding.
  return url instanceof Request ? fetch(url) : fetch(String(url), init);
}

async function handlePreflight(request, env) {
  const auth = authHeaders(request);
  if (!hasAuth(auth)) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }

  const headers = new Headers(auth);
  headers.set('x-request-id', safeRequestId(request));
  const canonicalBase = env.CANONICAL_BASE_URL || 'https://intel.cyberdudebivash.com';

  try {
    const response = await canonicalGatewayFetch(
      env,
      canonicalBase + '/api/v1/swarm/preflight',
      { method: 'GET', headers },
    );
    const raw = await response.text();
    let body;
    try {
      body = raw ? JSON.parse(raw) : {};
    } catch {
      return json({
        error: 'canonical_preflight_invalid_response',
        message: 'The canonical entitlement service returned an invalid response.',
      }, 502);
    }

    const extra = { 'x-cdb-swarm-preflight': 'canonical' };
    const retryAfter = response.headers.get('retry-after');
    if (retryAfter) extra['retry-after'] = retryAfter;
    return json(body, response.status, extra);
  } catch (error) {
    return json({
      error: 'canonical_preflight_unavailable',
      message: 'The canonical entitlement service is temporarily unavailable.',
    }, 503, { 'retry-after': '10' });
  }
}

async function handleMissionReadiness(request, env) {
  const auth = authHeaders(request);
  if (!hasAuth(auth)) {
    return json({
      error: 'authentication_required',
      message: 'Use an existing Sentinel customer API key or bearer token.',
    }, 401);
  }

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
    return json({ error: 'request_too_large' }, 413);
  }

  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: 'invalid_json' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: 'invalid_request' }, 400);
  if (typeof body.ioc_value !== 'string' || !body.ioc_value.trim() || body.ioc_value.length > 256) {
    return json({ error: 'ioc_value_required' }, 400);
  }
  if (body.ioc_type !== undefined && typeof body.ioc_type !== 'string') {
    return json({ error: 'invalid_ioc_type' }, 400);
  }
  if (body.mission_profile !== undefined && typeof body.mission_profile !== 'string') {
    return json({ error: 'invalid_mission_profile' }, 400);
  }
  const missionProfile = resolveMissionProfile(body.mission_profile || 'AUTO');
  if (!missionProfile) {
    return json({
      error: 'invalid_mission_profile',
      allowed: listMissionProfiles().map((p) => p.id),
      mission_dispatch: false,
    }, 400);
  }

  const iocType = String(body.ioc_type || 'auto').trim().slice(0, 32) || 'auto';
  const normalized = normalizeIocValue(body.ioc_value, iocType);
  if (!normalized.value || normalized.value.length > 256) {
    return json({ error: 'invalid_ioc_value' }, 400);
  }

  const canonicalBase = env.CANONICAL_BASE_URL || 'https://intel.cyberdudebivash.com';
  const requestId = `readiness-${crypto.randomUUID()}`;
  const headers = new Headers(auth);
  headers.set('x-request-id', requestId);

  // Authorize with the same canonical entitlement authority used by the
  // console before spending a correlation request.
  let preflightResponse;
  try {
    preflightResponse = await canonicalGatewayFetch(
      env,
      `${canonicalBase}/api/v1/swarm/preflight`,
      { method: 'GET', headers },
    );
  } catch {
    return json({ error: 'canonical_preflight_unavailable' }, 503, { 'retry-after': '10' });
  }

  let preflight = null;
  try { preflight = await preflightResponse.json(); } catch { /* handled below */ }
  if (!preflightResponse.ok || !preflight || preflight.eligible !== true) {
    return json({
      status: 'blocked',
      eligible: false,
      reason: preflight?.reason || preflight?.error || 'entitlement_preflight_failed',
      entitlement: preflight?.entitlement || null,
      quota: preflight?.quota || null,
      mission_dispatch: false,
    }, preflightResponse.status || 403);
  }

  const correlationHeaders = new Headers(auth);
  correlationHeaders.set('content-type', 'application/json');
  correlationHeaders.set('x-request-id', requestId);

  const [correlationResponse, synthesisReadiness] = await Promise.all([
    canonicalGatewayFetch(env, `${canonicalBase}/api/intel/correlate`, {
      method: 'POST',
      headers: correlationHeaders,
      body: JSON.stringify({
        ioc_value: normalized.value,
        ioc_type: iocType,
      }),
    }).catch(() => null),
    getSynthesisReadiness(canonicalBase, auth, requestId, env),
  ]);

  if (!correlationResponse) {
    return json({
      error: 'readiness_correlation_unavailable',
      mission_dispatch: false,
    }, 503, { 'retry-after': '10' });
  }

  const correlationText = await correlationResponse.text();
  let correlation = null;
  try { correlation = correlationText ? JSON.parse(correlationText) : null; } catch { /* handled below */ }

  const meshCertified = correlationResponse.headers.get('x-cdb-mesh-certified') === 'true';
  if (!correlationResponse.ok || !meshCertified || !correlation) {
    return json({
      status: 'blocked',
      error: 'readiness_correlation_failed',
      canonical_status: correlationResponse.status,
      mesh_certified: meshCertified,
      canonical_error: responseSnippet(correlation),
      mission_dispatch: false,
    }, correlationResponse.status || 502);
  }

  const quotaRemaining = preflight?.quota?.daily?.remaining;
  const readiness = buildMissionReadiness(correlation, {
    entitlementEligible: true,
    quotaRemaining,
    llmReady: synthesisReadiness.ready,
    llmProviders: synthesisReadiness.providers,
    expectedAgentIds: missionProfile.agents,
  });

  return json({
    status: 'ok',
    mission_dispatch: false,
    canonical_request_consumed: true,
    note: 'Readiness performs one canonical correlation request but does not dispatch /api/swarm/run.',
    mission_profile: {
      id: missionProfile.id,
      label: missionProfile.label,
      agents: missionProfile.agents,
    },
    ioc: {
      value: normalized.value,
      type: iocType,
      original_value: normalized.refanged ? normalized.original : null,
      refanged: normalized.refanged,
    },
    correlation: {
      verdict: correlation?.verdict || 'unknown',
      match_count: Number(correlation?.match_count ?? allMatches(correlation).length),
      request_id: correlation?.request_id || null,
    },
    synthesis_readiness: synthesisReadiness,
    readiness,
    demo_recommended:
      ['AUTO', 'FULL_CTI_FABRIC'].includes(missionProfile.id) &&
      readiness.mission_quality === 'FULL_FABRIC' &&
      synthesisReadiness.ready === true,
    checked_at: new Date().toISOString(),
  }, 200, { 'x-cdb-swarm-readiness': 'canonical' });
}

// One real, distinct backend call per specialist. Forwards the caller's own
// credentials unchanged (same pattern as the existing canonical correlate
// call) -- this worker never derives tenant/tier/entitlement itself, it
// only reports what the already-authoritative route decides. A scope- or
// tier-denied response becomes an honest DENIED agent state, not a fake
// COMPLETED one.
async function runBackendSpecialist(canonicalBase, auth, correlationId, correlation, route, env = null) {
  const t0 = Date.now();
  const planned = buildDependencyCandidates(correlation);
  const fallback = route.pick?.(correlation);
  const candidates = (planned[route.id]?.length ? planned[route.id] : (fallback ? [fallback] : []))
    .slice(0, MAX_SPECIALIST_CANDIDATES);

  if (!candidates.length) {
    return {
      basis: 'conditional_not_applicable',
      state: AGENT_STATES.NOT_APPLICABLE,
      result: {
        note: `Not applicable: ${route.emptyReason}.`,
        reason: 'dependency_input_absent',
      },
      skip_reason: route.emptyReason,
      attempted_candidates: [],
      evidence_count: 0,
      substantive: false,
      duration_ms: Date.now() - t0,
    };
  }

  const headers = new Headers(auth);
  headers.set('x-request-id', correlationId);
  const attempts = [];

  for (let index = 0; index < candidates.length; index += 1) {
    const value = candidates[index];
    const url = new URL(canonicalBase + route.path);
    url.searchParams.set(route.paramKey, value);
    url.searchParams.set('limit', '5');

    let resp;
    try {
      resp = await canonicalGatewayFetch(env, url.toString(), { headers });
    } catch (error) {
      return {
        basis: 'backend_execution',
        state: AGENT_STATES.FAILED,
        result: null,
        queried: { [route.paramKey]: value },
        attempted_candidates: attempts,
        evidence_count: 0,
        substantive: false,
        detail: { error: 'specialist_transport_failed', message: String(error?.message || error).slice(0, 240) },
        duration_ms: Date.now() - t0,
      };
    }

    let body = null;
    try { body = await resp.json(); } catch { /* adapter rejects invalid body */ }

    const adapted = adaptSpecialistResponse(route.id, body);
    attempts.push({
      candidate: value,
      http_status: resp.status,
      contract: adapted.schema,
      success: adapted.success,
      substantive: adapted.substantive,
      evidence_count: adapted.count,
    });

    if (resp.ok && adapted.success) {
      // A valid but empty result may mean the first correlated report has no
      // evidence while a later correlated report does. Try up to the bounded
      // candidate cap before returning the final honest empty success.
      const hasNext = index + 1 < candidates.length;
      if (!adapted.substantive && hasNext) continue;

      return {
        basis: 'backend_execution',
        state: AGENT_STATES.COMPLETED,
        result: adapted.data,
        queried: { [route.paramKey]: value },
        attempted_candidates: attempts,
        evidence_count: adapted.count,
        substantive: adapted.substantive,
        contract: adapted.schema,
        duration_ms: Date.now() - t0,
      };
    }

    if (resp.status === 401 || resp.status === 403) {
      return {
        basis: 'backend_execution',
        state: AGENT_STATES.DENIED,
        result: null,
        queried: { [route.paramKey]: value },
        attempted_candidates: attempts,
        evidence_count: 0,
        substantive: false,
        http_status: resp.status,
        detail: responseSnippet(body),
        duration_ms: Date.now() - t0,
      };
    }

    if ([429, 502, 503, 504].includes(resp.status)) {
      return {
        basis: 'backend_execution',
        state: AGENT_STATES.UNAVAILABLE,
        result: null,
        queried: { [route.paramKey]: value },
        attempted_candidates: attempts,
        evidence_count: 0,
        substantive: false,
        http_status: resp.status,
        detail: responseSnippet(body),
        duration_ms: Date.now() - t0,
      };
    }

    return {
      basis: 'backend_execution',
      state: AGENT_STATES.FAILED,
      result: null,
      queried: { [route.paramKey]: value },
      attempted_candidates: attempts,
      evidence_count: 0,
      substantive: false,
      http_status: resp.status,
      detail: responseSnippet(body),
      duration_ms: Date.now() - t0,
    };
  }

  return {
    basis: 'backend_execution',
    state: AGENT_STATES.FAILED,
    result: null,
    attempted_candidates: attempts,
    evidence_count: 0,
    substantive: false,
    detail: { error: 'specialist_candidate_exhausted' },
    duration_ms: Date.now() - t0,
  };
}

function iocHunterResult(correlation) {
  return {
    verdict: correlation?.verdict || 'unknown',
    match_count: Number(correlation?.match_count ?? allMatches(correlation).length),
    ioc: correlation?.ioc || null,
    source: 'canonical:/api/intel/correlate',
  };
}

function fuseRiskSynthesis(correlation, outcomes) {
  const entries = Object.entries(outcomes);
  const contributing = entries.filter(([, o]) => o.state === AGENT_STATES.COMPLETED).map(([id]) => id);
  const notApplicable = entries
    .filter(([, o]) => o.state === AGENT_STATES.NOT_APPLICABLE || o.state === 'SKIPPED')
    .map(([id]) => id);
  const denied = entries.filter(([, o]) => o.state === AGENT_STATES.DENIED).map(([id]) => id);
  const unavailable = entries.filter(([, o]) => o.state === AGENT_STATES.UNAVAILABLE).map(([id]) => id);
  const failed = entries.filter(([, o]) => o.state === AGENT_STATES.FAILED).map(([id]) => id);
  const matches = allMatches(correlation);
  const riskScores = matches.map((m) => Number(m?.risk_score || 0)).filter(Number.isFinite);

  const fused = {
    basis: 'fusion',
    verdict: correlation?.verdict || 'unknown',
    max_risk_score: riskScores.length ? Math.max(...riskScores) : 0,
    match_count: matches.length,
    contributing_specialists: contributing,
    not_applicable_specialists: notApplicable,
    // Backward-compatible alias retained for V4.46.x consumers.
    skipped_specialists: notApplicable,
    denied_specialists: denied,
    unavailable_specialists: unavailable,
    failed_specialists: failed,
    recommendation: correlation?.recommendation || 'Review the canonical Sentinel correlation result.',
    source: `fusion of ${contributing.length} completed specialist outcomes (${notApplicable.length} not applicable, ${denied.length} denied, ${unavailable.length} unavailable, ${failed.length} failed)`,
  };

  if (matches.length === 0) {
    fused.negative_intelligence = {
      status: 'NO_CURRENT_INTELLIGENCE_MATCH',
      assessment: 'No evidence in the current canonical Sentinel correlation result supports a known match for this observable.',
      recommendation: correlation?.recommendation || 'Continue monitoring and enrich from additional telemetry if operational context warrants.',
    };
  }

  return fused;
}

// One additional real backend call per mission: asks intel-gateway to
// generate a genuine LLM narrative over this mission's already-real
// specialist outcomes (POST /api/v1/swarm-synthesis, reusing the same
// callLLM provider cascade handleCopilot already uses in production -- see
// that route's own header comment in workers/intel-gateway/src/index.js).
// Forwards the caller's own credentials unchanged, same pattern as
// runBackendSpecialist. Any transport failure, non-2xx, or an honest
// "unavailable" response (FREE tier, no LLM provider configured) degrades
// gracefully to null -- the mission's risk-synthesizer result then keeps
// its existing deterministic-only fusion (llm_enhanced: false), the same
// fail-closed-but-graceful discipline persistMission() already applies for
// a missing KV binding. Never throws, never blocks or fails the mission.
async function synthesizeNarrative(canonicalBase, auth, correlationId, correlation, outcomes, env = null) {
  const headers = new Headers(auth);
  headers.set('content-type', 'application/json');
  headers.set('x-request-id', correlationId);

  let resp;
  try {
    resp = await canonicalGatewayFetch(env, `${canonicalBase}/api/v1/swarm-synthesis`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        ioc_value: correlation?.ioc?.value ?? null,
        ioc_type: correlation?.ioc?.type ?? null,
        verdict: correlation?.verdict || 'unknown',
        outcomes,
      }),
    });
  } catch {
    return null;
  }

  let body = null;
  try { body = await resp.json(); } catch { /* handled by the checks below */ }

  if (!resp.ok || !body || body.status !== 'success' || !body.llm_enhanced || !body.narrative) {
    return null;
  }

  return { text: body.narrative, model: body.llm_model || null };
}

function eventFactory({ missionId, executionId, correlationId }) {
  let sequence = 0;
  return (state, agent, payload = {}) => ({
    protocol: PROTOCOL,
    product: PRODUCT,
    mission_id: missionId,
    execution_id: executionId,
    correlation_id: correlationId,
    sequence: ++sequence,
    timestamp: new Date().toISOString(),
    state,
    agent_id: agent?.id || null,
    agent_name: agent?.name || null,
    capability: agent?.capability || null,
    ...payload,
  });
}

async function emit(writer, encoder, event) {
  await writer.write(encoder.encode(`event: swarm\ndata: ${JSON.stringify(event)}\n\n`));
}

// Best-effort mission record so a mission can be looked up after its SSE
// stream closes. Never stores the caller's credentials. A missing/unbound
// KV namespace (not yet provisioned -- see wrangler.toml) degrades to a
// no-op rather than failing the mission.
//
// `partition` (from credentialPartition(), optional) additionally writes a
// small listable index entry under the caller's own partition so
// handleMissionList() can page through mission history without ever
// reading another caller's missions. Omitting it (existing call sites/tests
// that predate mission history) keeps exactly today's behavior -- only the
// primary by-id record is written, unchanged in shape or key.
async function persistMission(env, record, partition) {
  if (!env.SWARM_MISSIONS_KV) return;
  // Store the one-way credential partition atomically with every new primary
  // mission record. It is an authorization attribute, not customer evidence,
  // and getMissionRecord() strips it before any API/export response.
  const storedRecord = partition ? { ...record, _owner_partition: partition } : record;
  try {
    await env.SWARM_MISSIONS_KV.put(record.mission_id, JSON.stringify(storedRecord), {
      expirationTtl: MISSION_TTL_SECONDS,
    });
  } catch { /* persistence is observability, not a mission-fatal concern */ }

  if (!partition) return;
  try {
    const invertedTs = String(INDEX_TS_CEILING - Date.now()).padStart(13, '0');
    const indexKey = `${MISSION_INDEX_PREFIX}${partition}:${invertedTs}:${record.mission_id}`;
    await env.SWARM_MISSIONS_KV.put(indexKey, '1', {
      expirationTtl: MISSION_TTL_SECONDS,
      metadata: {
        mission_id: record.mission_id,
        status: record.status,
        ioc_value: record.ioc?.ioc_value ?? null,
        ioc_type: record.ioc?.ioc_type ?? null,
        verdict: record.verdict ?? null,
        mission_quality: record.mission_quality ?? null,
        mission_profile: record.mission_profile ?? 'AUTO',
        duration_ms: Number.isFinite(Number(record.duration_ms)) ? Number(record.duration_ms) : null,
        completed_agents: Number(record.metrics?.completed ?? 0),
        not_applicable_agents: Number(record.metrics?.not_applicable ?? 0),
        degraded_agents: Number(record.metrics?.degraded ?? 0),
        denied_agents: Number(record.metrics?.denied ?? 0),
        unavailable_agents: Number(record.metrics?.unavailable ?? 0),
        failed_agents: Number(record.metrics?.failed ?? 0),
        llm_enhanced: record.specialists?.['risk-synthesizer']?.result?.llm_enhanced === true,
        started_at: record.started_at ?? null,
        finished_at: record.finished_at ?? null,
      },
    });
  } catch { /* same best-effort discipline as the primary record write */ }
}

// Idempotency guard: keyed by (credential partition, caller-supplied
// x-request-id) so a retried request with the same header never dispatches
// a second real mission. This is a storage-level guard, not a live-stream
// reattachment -- a stateless Worker invocation has no way to hand a second
// client the same in-flight TransformStream as the first (that would need
// a Durable Object, a real architectural change out of scope for this fix;
// see the PR description). A retry while the original is still RUNNING
// therefore gets an honest 409 pointing at the mission_id to poll, and a
// retry after completion gets the same persisted record replayed verbatim
// -- never a second, duplicate downstream dispatch.
async function getIdempotencyPointer(env, partition, correlationId) {
  if (!env.SWARM_MISSIONS_KV || !partition) return null;
  try {
    const raw = await env.SWARM_MISSIONS_KV.get(`${IDEMPOTENCY_PREFIX}${partition}:${correlationId}`);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

async function setIdempotencyPointer(env, partition, correlationId, missionId, status) {
  if (!env.SWARM_MISSIONS_KV || !partition) return;
  const terminal = status !== 'RUNNING';
  try {
    await env.SWARM_MISSIONS_KV.put(
      `${IDEMPOTENCY_PREFIX}${partition}:${correlationId}`,
      JSON.stringify({ mission_id: missionId, status }),
      { expirationTtl: terminal ? MISSION_TTL_SECONDS : IDEMPOTENCY_LOCK_TTL_SECONDS }
    );
  } catch { /* best-effort, same discipline as persistMission */ }
}

async function getSynthesisReadiness(canonicalBase, auth, correlationId, env = null) {
  const headers = new Headers(auth);
  headers.set('x-request-id', correlationId);

  try {
    const response = await canonicalGatewayFetch(
      env,
      `${canonicalBase}/api/v1/swarm-synthesis/health`,
      { method: 'GET', headers },
    );
    let body = null;
    try { body = await response.json(); } catch { /* fail closed below */ }
    if (!response.ok || !body || body.status !== 'ok') {
      return { ready: false, llm_enabled: false, providers: [], status: 'UNAVAILABLE' };
    }

    const providers = body.providers && typeof body.providers === 'object'
      ? Object.entries(body.providers).filter(([, enabled]) => enabled === true).map(([name]) => name)
      : [];

    const ready = body.ready === true || (body.llm_enabled === true && body.tier_llm !== false);
    return {
      ready,
      llm_enabled: body.llm_enabled === true,
      tier_llm: body.tier_llm ?? null,
      providers,
      engine: body.engine || null,
      status: ready ? 'READY' : 'DEGRADED',
    };
  } catch {
    return { ready: false, llm_enabled: false, providers: [], status: 'UNAVAILABLE' };
  }
}

function summarizeMissionOutcomes(outcomes = {}) {
  const counts = {
    completed: 0,
    not_applicable: 0,
    degraded: 0,
    denied: 0,
    unavailable: 0,
    failed: 0,
  };

  for (const outcome of Object.values(outcomes)) {
    const state = outcome?.state === 'SKIPPED' ? AGENT_STATES.NOT_APPLICABLE : outcome?.state;
    if (state === AGENT_STATES.COMPLETED) counts.completed += 1;
    else if (state === AGENT_STATES.NOT_APPLICABLE) counts.not_applicable += 1;
    else if (state === AGENT_STATES.DEGRADED) counts.degraded += 1;
    else if (state === AGENT_STATES.DENIED) counts.denied += 1;
    else if (state === AGENT_STATES.UNAVAILABLE) counts.unavailable += 1;
    else if (state === AGENT_STATES.FAILED) counts.failed += 1;
  }

  return {
    ...counts,
    total: Object.keys(outcomes).length,
  };
}

async function executeMission({ writer, request, env, body, correlationId, missionId, executionId, idempotencyKeySupplied }) {
  const encoder = new TextEncoder();
  const makeEvent = eventFactory({ missionId, executionId, correlationId });
  const canonicalBase = env.CANONICAL_BASE_URL || 'https://intel.cyberdudebivash.com';
  const auth = authHeaders(request);
  const partition = await credentialPartition(auth);
  const missionStartedMs = Date.now();
  const startedAt = new Date().toISOString();
  const missionProfile = resolveMissionProfile(body.mission_profile || 'AUTO') || resolveMissionProfile('AUTO');
  const selectedAgentIds = new Set(missionProfile.agents);
  const queued = AGENTS.filter((a) => selectedAgentIds.has(a.id) && a.id !== 'risk-synthesizer' && a.id !== 'ioc-hunter');
  const excluded = AGENTS.filter((a) => !selectedAgentIds.has(a.id));
  const iocHunter = AGENTS.find((a) => a.id === 'ioc-hunter');
  const synthesizer = AGENTS.find((a) => a.id === 'risk-synthesizer');
  let readiness = null;

  const finish = async (status, extra = {}) => {
    await persistMission(env, {
      mission_id: missionId,
      execution_id: executionId,
      correlation_id: correlationId,
      product: PRODUCT,
      protocol: PROTOCOL,
      status,
      mission_profile: missionProfile.id,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      duration_ms: Date.now() - missionStartedMs,
      ioc: {
        ioc_value: body.ioc_value,
        ioc_type: body.ioc_type || 'auto',
        original_ioc_value: body.ioc_original_value || null,
        refanged: Boolean(body.ioc_refanged),
      },
      readiness,
      ...extra,
    }, partition);
    if (idempotencyKeySupplied) await setIdempotencyPointer(env, partition, correlationId, missionId, status);
  };

  try {
    await emit(writer, encoder, makeEvent('QUEUED', null, {
      event_type: 'mission.accepted',
      agent_count: missionProfile.agents.length,
      fleet_agent_count: AGENTS.length,
      mission_profile: missionProfile.id,
      mission_profile_label: missionProfile.label,
      input: {
        ioc_value: body.ioc_value,
        ioc_type: body.ioc_type || 'auto',
        original_ioc_value: body.ioc_original_value || null,
        refanged: Boolean(body.ioc_refanged),
      },
    }));

    for (const agent of AGENTS) {
      if (selectedAgentIds.has(agent.id)) {
        await emit(writer, encoder, makeEvent('QUEUED', agent, {
          event_type: 'agent.queued',
          mission_profile: missionProfile.id,
        }));
      } else {
        await emit(writer, encoder, makeEvent(AGENT_STATES.NOT_APPLICABLE, agent, {
          event_type: 'agent.not_applicable',
          basis: 'mission_profile',
          reason: 'mission_profile_excluded',
          mission_profile: missionProfile.id,
          result: {
            reason: 'mission_profile_excluded',
            note: `Agent is outside the selected ${missionProfile.label} mission profile.`,
          },
        }));
      }
    }

    await emit(writer, encoder, makeEvent('RUNNING', iocHunter, {
      event_type: 'agent.started',
      basis: 'backend_execution',
      source: '/api/intel/correlate',
    }));

    const correlateHeaders = new Headers(auth);
    correlateHeaders.set('content-type', 'application/json');
    correlateHeaders.set('x-request-id', correlationId);

    const iocHunterT0 = Date.now();
    const canonicalResponse = await canonicalGatewayFetch(env, `${canonicalBase}/api/intel/correlate`, {
      method: 'POST',
      headers: correlateHeaders,
      body: JSON.stringify({ ioc_value: body.ioc_value, ioc_type: body.ioc_type || 'auto' }),
    });
    const iocHunterDurationMs = Date.now() - iocHunterT0;

    const canonicalText = await canonicalResponse.text();
    let canonical = null;
    try { canonical = canonicalText ? JSON.parse(canonicalText) : null; } catch { /* handled below */ }

    const meshCertified = canonicalResponse.headers.get('x-cdb-mesh-certified') === 'true';
    const meshExecutionId = canonicalResponse.headers.get('x-cdb-mesh-execution');
    const meshCorrelationId = canonicalResponse.headers.get('x-cdb-mesh-correlation');

    if (!canonicalResponse.ok || !meshCertified || !meshExecutionId || meshCorrelationId !== correlationId || !canonical) {
      const state = canonicalResponse.status === 401 || canonicalResponse.status === 403 ? AGENT_STATES.DENIED : AGENT_STATES.FAILED;
      await emit(writer, encoder, makeEvent(state, iocHunter, {
        event_type: state === AGENT_STATES.DENIED ? 'agent.denied' : 'agent.failed',
        basis: 'backend_execution',
        canonical_status: canonicalResponse.status,
        mesh_certified: meshCertified,
        canonical_error: responseSnippet(canonical),
        duration_ms: iocHunterDurationMs,
      }));
      await emit(writer, encoder, makeEvent(state, null, {
        event_type: 'mission.rejected',
        canonical_status: canonicalResponse.status,
        mesh_certified: meshCertified,
        canonical_error: responseSnippet(canonical),
      }));
      await finish(state, {
        mission_quality: 'FAILED',
        canonical_status: canonicalResponse.status,
        mesh_certified: meshCertified,
      });
      return;
    }

    const synthesisReadiness = await getSynthesisReadiness(canonicalBase, auth, correlationId, env);
    readiness = buildMissionReadiness(canonical, {
      entitlementEligible: true,
      llmReady: synthesisReadiness.ready,
      llmProviders: synthesisReadiness.providers,
      expectedAgentIds: missionProfile.agents,
    });

    await emit(writer, encoder, makeEvent('ADMITTED', null, {
      event_type: 'mission.readiness',
      mesh_certified: true,
      mesh_execution_id: meshExecutionId,
      readiness,
      synthesis_readiness: synthesisReadiness,
    }));

    const iocHunterOutcome = {
      basis: 'backend_execution',
      state: AGENT_STATES.COMPLETED,
      result: iocHunterResult(canonical),
      duration_ms: iocHunterDurationMs,
      evidence_count: Number(canonical?.match_count ?? allMatches(canonical).length),
      substantive: Number(canonical?.match_count ?? allMatches(canonical).length) > 0,
    };
    await emit(writer, encoder, makeEvent(AGENT_STATES.COMPLETED, iocHunter, {
      event_type: 'agent.completed',
      basis: 'backend_execution',
      result: iocHunterOutcome.result,
      duration_ms: iocHunterDurationMs,
    }));

    await emit(writer, encoder, makeEvent('ADMITTED', null, {
      event_type: 'mesh.admitted',
      mesh_certified: true,
      mesh_execution_id: meshExecutionId,
    }));

    const outcomes = {
      'ioc-hunter': iocHunterOutcome,
      ...Object.fromEntries(excluded.map((agent) => [agent.id, {
        basis: 'mission_profile',
        state: AGENT_STATES.NOT_APPLICABLE,
        result: {
          reason: 'mission_profile_excluded',
          note: `Agent is outside the selected ${missionProfile.label} mission profile.`,
        },
        evidence_count: 0,
        substantive: false,
        duration_ms: 0,
      }])),
    };
    const dependencyPlan = buildDependencyCandidates(canonical);

    const specialistTasks = queued.map(async (agent) => {
      const route = SPECIALIST_ROUTES[agent.id];
      const candidates = dependencyPlan[agent.id] || [];

      if (route && candidates.length === 0) {
        const outcome = await runBackendSpecialist(canonicalBase, auth, correlationId, canonical, route, env);
        outcomes[agent.id] = outcome;
        await emit(writer, encoder, makeEvent(AGENT_STATES.NOT_APPLICABLE, agent, {
          event_type: 'agent.not_applicable',
          basis: outcome.basis,
          result: outcome.result,
          reason: outcome.skip_reason || route.emptyReason,
          evidence_count: 0,
          duration_ms: outcome.duration_ms ?? null,
        }));
        return outcome;
      }

      await emit(writer, encoder, makeEvent(AGENT_STATES.RUNNING, agent, {
        event_type: 'agent.started',
        basis: route ? 'backend_execution' : 'unconfigured',
        source: route ? `canonical:${route.path}` : null,
        candidate_count: candidates.length,
      }));

      const outcome = route
        ? await runBackendSpecialist(canonicalBase, auth, correlationId, canonical, route, env)
        : {
            basis: 'unconfigured',
            state: AGENT_STATES.FAILED,
            result: null,
            detail: { error: 'no_backend_route_configured', agent: agent.id },
            evidence_count: 0,
            substantive: false,
          };

      outcomes[agent.id] = outcome;

      const eventType =
        outcome.state === AGENT_STATES.COMPLETED ? 'agent.completed'
          : outcome.state === AGENT_STATES.NOT_APPLICABLE ? 'agent.not_applicable'
            : outcome.state === AGENT_STATES.DENIED ? 'agent.denied'
              : outcome.state === AGENT_STATES.UNAVAILABLE ? 'agent.unavailable'
                : outcome.state === AGENT_STATES.DEGRADED ? 'agent.degraded'
                  : 'agent.failed';

      await emit(writer, encoder, makeEvent(outcome.state, agent, {
        event_type: eventType,
        basis: outcome.basis,
        result: outcome.result,
        queried: outcome.queried || undefined,
        attempted_candidates: outcome.attempted_candidates || undefined,
        evidence_count: outcome.evidence_count ?? null,
        substantive: outcome.substantive ?? null,
        contract: outcome.contract || undefined,
        detail: outcome.detail || undefined,
        reason: outcome.skip_reason || undefined,
        duration_ms: outcome.duration_ms ?? null,
      }));
      return outcome;
    });

    await Promise.all(specialistTasks);

    await emit(writer, encoder, makeEvent(AGENT_STATES.RUNNING, synthesizer, {
      event_type: 'agent.started',
      basis: 'fusion',
      inputs: queued.map((a) => a.id),
    }));

    const synthesizerT0 = Date.now();
    const fused = fuseRiskSynthesis(canonical, outcomes);
    const narrative = await synthesizeNarrative(canonicalBase, auth, correlationId, canonical, outcomes, env);
    if (narrative) {
      fused.ai_narrative = narrative.text;
      fused.llm_enhanced = true;
      fused.llm_model = narrative.model;
    } else {
      fused.llm_enhanced = false;
      fused.ai_mode = 'deterministic_fallback';
    }

    const synthesizerDurationMs = Date.now() - synthesizerT0;
    const synthesizerState = narrative ? AGENT_STATES.COMPLETED : AGENT_STATES.DEGRADED;
    outcomes['risk-synthesizer'] = {
      basis: 'fusion',
      state: synthesizerState,
      result: fused,
      duration_ms: synthesizerDurationMs,
      evidence_count: Object.keys(outcomes).length,
      substantive: true,
    };

    const missionQuality = classifyMissionCompletion(outcomes, fused, missionProfile.agents);
    fused.mission_quality = missionQuality;
    const evidenceGraph = buildEvidenceGraph({ correlation: canonical, outcomes });
    const metrics = summarizeMissionOutcomes(outcomes);

    await emit(writer, encoder, makeEvent(synthesizerState, synthesizer, {
      event_type: narrative ? 'agent.completed' : 'agent.degraded',
      basis: 'fusion',
      result: fused,
      duration_ms: synthesizerDurationMs,
    }));

    await emit(writer, encoder, makeEvent('COMPLETED', null, {
      event_type: 'mission.completed',
      mesh_certified: true,
      mesh_execution_id: meshExecutionId,
      canonical_status: canonicalResponse.status,
      canonical_request_id: canonical.request_id || null,
      mission_quality: missionQuality,
      metrics,
      evidence_graph: {
        schema: evidenceGraph.schema,
        node_count: evidenceGraph.node_count,
        edge_count: evidenceGraph.edge_count,
      },
      result: fused,
    }));

    await finish('COMPLETED', {
      mesh_execution_id: meshExecutionId,
      verdict: fused.verdict,
      mission_quality: missionQuality,
      metrics,
      evidence_graph: evidenceGraph,
      specialists: Object.fromEntries(
        Object.entries(outcomes).map(([id, o]) => [id, {
          basis: o.basis,
          state: o.state,
          result: o.result ?? null,
          duration_ms: o.duration_ms ?? null,
          queried: o.queried || null,
          attempted_candidates: o.attempted_candidates || null,
          evidence_count: o.evidence_count ?? null,
          substantive: o.substantive ?? null,
          contract: o.contract || null,
        }])
      ),
    });
  } catch (error) {
    await emit(writer, encoder, makeEvent(AGENT_STATES.FAILED, null, {
      event_type: 'mission.failed',
      error: 'swarm_execution_failed',
      message: String(error?.message || error).slice(0, 240),
    })).catch(() => {});
    await finish('FAILED', {
      mission_quality: 'FAILED',
      error: String(error?.message || error).slice(0, 240),
    }).catch(() => {});
  } finally {
    await writer.close().catch(() => {});
  }
}

async function handleRun(request, env, ctx) {
  const auth = authHeaders(request);
  if (!hasAuth(auth)) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
    return json({ error: 'request_too_large' }, 413);
  }

  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: 'invalid_json' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: 'invalid_request' }, 400);
  if (typeof body.ioc_value !== 'string' || !body.ioc_value.trim() || body.ioc_value.length > 256) {
    return json({ error: 'ioc_value_required' }, 400);
  }
  if (body.ioc_type !== undefined && typeof body.ioc_type !== 'string') return json({ error: 'invalid_ioc_type' }, 400);
  if (body.mission_profile !== undefined && typeof body.mission_profile !== 'string') return json({ error: 'invalid_mission_profile' }, 400);
  const missionProfile = resolveMissionProfile(body.mission_profile || 'AUTO');
  if (!missionProfile) {
    return json({
      error: 'invalid_mission_profile',
      allowed: listMissionProfiles().map((p) => p.id),
    }, 400);
  }
  body.mission_profile = missionProfile.id;

  body.ioc_type = String(body.ioc_type || 'auto').trim().slice(0, 32) || 'auto';
  const normalizedIoc = normalizeIocValue(body.ioc_value, body.ioc_type);
  body.ioc_original_value = normalizedIoc.refanged ? normalizedIoc.original : null;
  body.ioc_refanged = normalizedIoc.refanged;
  body.ioc_value = normalizedIoc.value;
  if (!body.ioc_value || body.ioc_value.length > 256) {
    return json({ error: 'invalid_ioc_value' }, 400);
  }

  const correlationId = safeRequestId(request);
  // Idempotency only applies when the CALLER supplied their own stable
  // request id -- an auto-generated fallback is unique to this call by
  // construction and can never collide with a genuine retry, so it would
  // never match anything in the guard below anyway. Checking this first
  // also skips a wasted KV read on the common (non-retry) case.
  const idempotencyKeySupplied = ID_RE.test(request.headers.get('x-request-id') || '');
  const partition = idempotencyKeySupplied ? await credentialPartition(auth) : null;

  if (idempotencyKeySupplied) {
    const pointer = await getIdempotencyPointer(env, partition, correlationId);
    if (pointer) {
      if (pointer.status === 'RUNNING') {
        return json({
          error: 'mission_in_progress',
          mission_id: pointer.mission_id,
          message: 'An identical request (same x-request-id) is already running. Poll GET /api/swarm/mission/:id or retry once it completes.',
        }, 409);
      }
      // Terminal: replay the same persisted record rather than dispatching
      // a second real mission. If the pointer somehow outlived its record
      // (edge case, not the normal TTL-aligned path), fall through and
      // start a fresh mission instead of erroring the caller out.
      const existing = await getMissionRecord(env, pointer.mission_id, partition);
      if (existing.status === 200) {
        return json({ status: 'ok', idempotent_replay: true, data: existing.record });
      }
    }
  }

  const missionId = `sentinel-mission-${crypto.randomUUID()}`;
  const executionId = `sentinel-swarm-${crypto.randomUUID()}`;
  const stream = new TransformStream();
  const writer = stream.writable.getWriter();

  if (idempotencyKeySupplied) {
    await setIdempotencyPointer(env, partition, correlationId, missionId, 'RUNNING');
  }

  ctx.waitUntil(executeMission({ writer, request, env, body, correlationId, missionId, executionId, idempotencyKeySupplied }));

  return new Response(stream.readable, {
    status: 200,
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-store, must-revalidate',
      'connection': 'keep-alive',
      'x-content-type-options': 'nosniff',
      'x-cdb-swarm-protocol': PROTOCOL,
      'x-cdb-swarm-mission': missionId,
      'x-cdb-swarm-correlation': correlationId,
    },
  });
}

// Single source of truth for "fetch one mission record by id" -- both the
// existing by-id lookup and the new report export call this rather than
// each re-implementing the unavailable/not-found/corrupt handling.
async function getMissionRecord(env, missionId, expectedPartition = null) {
  if (!env.SWARM_MISSIONS_KV) {
    return { status: 503, body: { error: 'mission_store_unavailable', message: 'Mission persistence is not provisioned yet.' } };
  }
  const raw = await env.SWARM_MISSIONS_KV.get(missionId);
  if (!raw) return { status: 404, body: { error: 'mission_not_found' } };
  let stored;
  try { stored = JSON.parse(raw); } catch { return { status: 500, body: { error: 'mission_record_corrupt' } }; }

  // V4.46.6 customer-isolation hardening: all newly persisted missions carry
  // a one-way credential partition. A different authenticated customer gets
  // the same 404 as an unknown mission so existence is not disclosed.
  // Records created before this field existed remain readable for backward
  // compatibility; every new mission is owner-enforced.
  if (stored?._owner_partition && expectedPartition && stored._owner_partition !== expectedPartition) {
    return { status: 404, body: { error: 'mission_not_found' } };
  }

  const { _owner_partition: _internalOwnerPartition, ...record } = stored || {};
  return {
    status: 200,
    record,
    ownership_enforced: Boolean(stored?._owner_partition),
  };
}

async function handleMissionLookup(request, env, missionId) {
  if (!ID_RE.test(missionId)) return json({ error: 'invalid_mission_id' }, 400);
  const headers = authHeaders(request);
  if (!hasAuth(headers)) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }
  const partition = await credentialPartition(headers);
  const result = await getMissionRecord(env, missionId, partition);
  if (result.status !== 200) return json(result.body, result.status);
  return json({ status: 'ok', data: result.record });
}

// GET /api/swarm/missions -- paginated mission history for the calling
// credential only (see credentialPartition()'s header comment for why this
// is scoped per-credential rather than left unscoped). Cloudflare KV's
// list() returns each key's metadata directly, so this never performs a
// per-mission get() -- one list() call serves an entire page.
async function handleMissionList(request, env, url) {
  const headers = authHeaders(request);
  if (!hasAuth(headers)) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }
  if (!env.SWARM_MISSIONS_KV) {
    return json({ error: 'mission_store_unavailable', message: 'Mission persistence is not provisioned yet.' }, 503);
  }

  const limitParam = parseInt(url.searchParams.get('limit') || '20', 10);
  const limit = Number.isFinite(limitParam) ? Math.min(Math.max(limitParam, 1), 100) : 20;
  const cursor = url.searchParams.get('cursor') || undefined;
  const statusFilter = url.searchParams.get('status') || null;
  const partition = await credentialPartition(headers);

  let page;
  try {
    page = await env.SWARM_MISSIONS_KV.list({ prefix: `${MISSION_INDEX_PREFIX}${partition}:`, limit, cursor });
  } catch (error) {
    return json({ error: 'mission_list_failed', message: String(error?.message || error).slice(0, 240) }, 500);
  }

  let missions = page.keys.map((k) => k.metadata).filter(Boolean);
  if (statusFilter) missions = missions.filter((m) => m.status === statusFilter);

  return json({
    status: 'ok',
    data: {
      missions,
      list_complete: Boolean(page.list_complete),
      cursor: page.list_complete ? null : (page.cursor || null),
    },
  });
}

function percentile(values, p) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) return null;
  const rank = Math.max(0, Math.min(sorted.length - 1, Math.ceil(p * sorted.length) - 1));
  return sorted[rank];
}

async function handleMissionMetrics(request, env, url) {
  const headers = authHeaders(request);
  if (!hasAuth(headers)) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }
  if (!env.SWARM_MISSIONS_KV) {
    return json({ error: 'mission_store_unavailable', message: 'Mission persistence is not provisioned yet.' }, 503);
  }

  const rawLimit = parseInt(url.searchParams.get('limit') || '50', 10);
  const limit = Number.isFinite(rawLimit) ? Math.min(Math.max(rawLimit, 1), 100) : 50;
  const partition = await credentialPartition(headers);

  let page;
  try {
    page = await env.SWARM_MISSIONS_KV.list({
      prefix: `${MISSION_INDEX_PREFIX}${partition}:`,
      limit,
    });
  } catch (error) {
    return json({ error: 'mission_metrics_failed', message: String(error?.message || error).slice(0, 240) }, 500);
  }

  const missions = page.keys.map((k) => k.metadata).filter(Boolean);
  const durations = missions.map((m) => Number(m.duration_ms)).filter(Number.isFinite);
  const quality = {};
  const profiles = {};
  const agentStates = {
    completed: 0,
    not_applicable: 0,
    degraded: 0,
    denied: 0,
    unavailable: 0,
    failed: 0,
  };

  let llmEnhanced = 0;
  for (const mission of missions) {
    const q = mission.mission_quality || 'LEGACY_UNCLASSIFIED';
    quality[q] = (quality[q] || 0) + 1;
    const profile = mission.mission_profile || 'AUTO';
    profiles[profile] = (profiles[profile] || 0) + 1;
    if (mission.llm_enhanced === true) llmEnhanced += 1;

    agentStates.completed += Number(mission.completed_agents || 0);
    agentStates.not_applicable += Number(mission.not_applicable_agents || 0);
    agentStates.degraded += Number(mission.degraded_agents || 0);
    agentStates.denied += Number(mission.denied_agents || 0);
    agentStates.unavailable += Number(mission.unavailable_agents || 0);
    agentStates.failed += Number(mission.failed_agents || 0);
  }

  const completedMissions = missions.filter((m) => m.status === 'COMPLETED').length;
  const fullFabric = missions.filter((m) => m.mission_quality === 'FULL_FABRIC_COMPLETE').length;

  return json({
    status: 'ok',
    data: {
      scope: 'credential_owned_latest_missions',
      sample_size: missions.length,
      sample_limit: limit,
      list_complete: Boolean(page.list_complete),
      mission_counts: {
        completed: completedMissions,
        non_completed: missions.length - completedMissions,
        full_fabric_complete: fullFabric,
      },
      mission_quality: quality,
      mission_profiles: profiles,
      latency_ms: {
        p50: percentile(durations, 0.50),
        p95: percentile(durations, 0.95),
        max: durations.length ? Math.max(...durations) : null,
      },
      ai_synthesis: {
        llm_enhanced_missions: llmEnhanced,
        llm_enhanced_rate: missions.length ? Number((llmEnhanced / missions.length).toFixed(4)) : null,
      },
      agent_terminal_states: agentStates,
      measured_at: new Date().toISOString(),
    },
  });
}

// Renders the same real, already-persisted mission record the JSON lookup
// returns into a human-readable evidence transcript -- no new data model,
// no re-fetched or re-derived findings, purely a formatting layer over
// getMissionRecord()'s output.
function missionReportMarkdown(record) {
  const lines = [
    '# CYBERDUDEBIVASH SENTINEL APEX -- SUPER AGENT SWARM Mission Report',
    '',
    `- **Mission ID:** ${record.mission_id}`,
    `- **Execution ID:** ${record.execution_id || '—'}`,
    `- **Correlation ID:** ${record.correlation_id || '—'}`,
    `- **Status:** ${record.status}`,
    `- **IOC:** ${record.ioc?.ioc_value || '—'} (${record.ioc?.ioc_type || 'auto'})`,
    `- **Verdict:** ${record.verdict || '—'}`,
    `- **Mesh Certified:** ${record.mesh_certified ? 'yes' : 'no'}${record.mesh_execution_id ? ` (execution ${record.mesh_execution_id})` : ''}`,
    `- **Started:** ${record.started_at || '—'}`,
    `- **Finished:** ${record.finished_at || '—'}`,
    ...(record.error ? [`- **Error:** ${record.error}`] : []),
    '',
    '## Agent Evidence',
    '',
  ];
  const specialists = record.specialists || {};
  const ids = Object.keys(specialists);
  if (ids.length === 0) lines.push('_No per-agent evidence recorded for this mission._');
  for (const id of ids) {
    const o = specialists[id] || {};
    lines.push(`### ${id}`, `- basis: ${o.basis || '—'}`, `- state: ${o.state || '—'}`, '', '```json', JSON.stringify(o.result ?? null, null, 2), '```', '');
  }
  lines.push('---', `_Generated by CYBERDUDEBIVASH SENTINEL APEX -- SUPER AGENT SWARM (${PROTOCOL})._`);
  return lines.join('\n');
}

// STIX 2.1 export -- mirrors the canonical bundle conventions this platform
// already established in workers/intel-gateway/src/routes/exports.js
// (stixObjectId's `{type}--{UUID}` id format, spec_version 2.1, x_sentinel_*
// custom properties, application/stix+json;version=2.1 content type). This
// worker is a separately deployed Cloudflare Worker with no shared module
// graph with intel-gateway -- its functions can't be imported directly --
// so this mirrors that file's shape deliberately rather than inventing a
// divergent STIX dialect, matching this file's existing convention of
// reusing established shapes across the worker boundary in spirit even
// where direct code reuse isn't architecturally possible.
const STIX_CONTENT_TYPE = 'application/stix+json;version=2.1';

function stixObjectId(type) {
  return `${type}--${crypto.randomUUID()}`;
}

// Same escaping discipline as exports.js's liveIndicatorToStixPattern.
// Resolves the observable type deterministically from the real submitted
// value/type rather than trusting an unhelpful 'auto' label -- an honest
// classification of real input, not a fabricated one.
function detectStixObservableType(iocValue, iocType) {
  const v = String(iocValue);
  if (iocType === 'ipv4' || /^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ipv4';
  if (iocType === 'ipv6' || (v.includes(':') && /^[0-9a-fA-F:]{3,}$/.test(v))) return 'ipv6';
  if (iocType === 'url' || /^https?:\/\//i.test(v)) return 'url';
  if (iocType === 'hash' || /^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(v)) return 'hash';
  if (iocType === 'domain' || /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
  return 'unknown';
}

function hashAlgoFor(value) {
  const len = String(value).length;
  if (len === 32) return 'MD5';
  if (len === 40) return 'SHA-1';
  return 'SHA-256';
}

function missionIocToStixPattern(iocValue, iocType) {
  const escaped = String(iocValue).replace(/['"\\]/g, '');
  switch (detectStixObservableType(iocValue, iocType)) {
    case 'ipv4': return `[ipv4-addr:value = '${escaped}']`;
    case 'ipv6': return `[ipv6-addr:value = '${escaped}']`;
    case 'domain': return `[domain-name:value = '${escaped}']`;
    case 'url': return `[url:value = '${escaped}']`;
    case 'hash': return `[file:hashes.'${hashAlgoFor(escaped)}' = '${escaped}']`;
    // A custom x- SCO rather than silently mislabeling an unrecognized
    // value as e.g. a domain -- honest about what wasn't determined.
    default: return `[x-sentinel:value = '${escaped}']`;
  }
}

// Renders the mission's real, already-persisted evidence as a STIX 2.1
// Bundle: one Indicator for the mission's IOC, one Note per agent carrying
// that agent's own real basis/state/result as its content. No new data
// model -- same source record as the Markdown/JSON exports.
function missionToStixBundle(record) {
  const nowIso = new Date().toISOString();
  const iocValue = record.ioc?.ioc_value || '';
  const iocType = record.ioc?.ioc_type || 'auto';
  const created = record.started_at || nowIso;
  const modified = record.finished_at || created;

  const indicatorId = stixObjectId('indicator');
  const indicator = {
    type: 'indicator', spec_version: '2.1', id: indicatorId,
    created, modified,
    name: `SENTINEL APEX SUPER AGENT SWARM: ${iocValue}`,
    indicator_types: [
      record.verdict === 'malicious' ? 'malicious-activity'
        : record.verdict === 'suspicious' ? 'anomalous-activity'
        : 'unknown',
    ],
    pattern: missionIocToStixPattern(iocValue, iocType),
    pattern_type: 'stix',
    valid_from: created,
    x_sentinel_mission_id: record.mission_id,
    x_sentinel_execution_id: record.execution_id || null,
    x_sentinel_correlation_id: record.correlation_id || null,
    x_sentinel_verdict: record.verdict || null,
    x_sentinel_mesh_certified: Boolean(record.mesh_certified),
  };

  const specialists = record.specialists || {};
  const notes = Object.entries(specialists).map(([agentId, o]) => ({
    type: 'note', spec_version: '2.1', id: stixObjectId('note'),
    created: modified, modified,
    abstract: `SENTINEL APEX ${agentId} -- ${o.state || 'UNKNOWN'}`,
    content: JSON.stringify({ basis: o.basis ?? null, state: o.state ?? null, result: o.result ?? null }, null, 2),
    object_refs: [indicatorId],
    x_sentinel_agent_id: agentId,
    x_sentinel_agent_state: o.state ?? null,
    x_sentinel_agent_basis: o.basis ?? null,
  }));

  return { type: 'bundle', id: stixObjectId('bundle'), objects: [indicator, ...notes] };
}

// GET /api/swarm/mission/:id/report -- an exportable, downloadable evidence
// report for one mission. ?format=json for the raw persisted record, or
// ?format=stix21 for a STIX 2.1 Bundle ready for SIEM/SOAR/TIP ingestion,
// both as downloadable attachments; default is a Markdown transcript.
async function handleMissionReport(request, env, missionId, url) {
  if (!ID_RE.test(missionId)) return json({ error: 'invalid_mission_id' }, 400);
  const headers = authHeaders(request);
  if (!hasAuth(headers)) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }
  const partition = await credentialPartition(headers);
  const result = await getMissionRecord(env, missionId, partition);
  if (result.status !== 200) return json(result.body, result.status);

  const format = (url.searchParams.get('format') || 'md').toLowerCase();
  if (format === 'json') {
    return json({ status: 'ok', data: result.record }, 200, {
      'content-disposition': `attachment; filename="${missionId}.json"`,
    });
  }
  if (format === 'stix21' || format === 'stix') {
    return new Response(JSON.stringify(missionToStixBundle(result.record), null, 2), {
      status: 200,
      headers: {
        'content-type': STIX_CONTENT_TYPE,
        'cache-control': 'no-store',
        'content-disposition': `attachment; filename="${missionId}.stix21.json"`,
        'x-content-type-options': 'nosniff',
      },
    });
  }

  return new Response(missionReportMarkdown(result.record), {
    status: 200,
    headers: {
      'content-type': 'text/markdown; charset=utf-8',
      'cache-control': 'no-store',
      'content-disposition': `attachment; filename="${missionId}.md"`,
      'x-content-type-options': 'nosniff',
    },
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function swarmAppJs() {
  return String.raw`  document.documentElement.dataset.swarmUi='ready';
  window.__CDB_SWARM_UI_READY__=true;
const run=document.getElementById('run'),final=document.getElementById('final'),eventLog=document.getElementById('eventLog');
  const byId=(id)=>document.getElementById(id);
  document.body.dataset.view='technical';
  const viewMode=byId('viewMode');
  if(viewMode)viewMode.onclick=()=>{const executive=document.body.dataset.view!=='executive';document.body.dataset.view=executive?'executive':'technical';viewMode.setAttribute('aria-pressed',executive?'true':'false');viewMode.textContent=executive?'TECHNICAL VIEW':'EXECUTIVE VIEW'};
  function setTone(el,tone){if(!el)return;el.dataset.tone=tone||''}
  function setText(id,value,tone){const el=byId(id);if(!el)return;el.textContent=value;setTone(el,tone)}
  function setMissionState(value,tone){setText('missionState',value,tone);setText('finalBadge',value,tone);const shell=byId('missionShell');if(shell)shell.dataset.mission=value||'READY';updateOpsTelemetry();const led=byId('fabricLed');if(value==='CONNECTING'){setText('fabricStateText','AWAITING ADMISSION','warn');setText('streamState','SSE · CONNECTING','warn');if(led)led.dataset.state='RUNNING'}else if(value==='QUEUED'||value==='ADMITTED'||value==='RUNNING'){setText('fabricStateText','MISSION ACTIVE','ok');setText('streamState','SSE · STREAMING','ok');if(led)led.dataset.state='RUNNING'}else if(value==='COMPLETED'){setText('fabricStateText','MISSION COMPLETE','ok');setText('streamState','SSE · CLOSED','ok');if(led)led.dataset.state='COMPLETED'}else if(value==='FAILED'||value==='REJECTED'||value==='TRANSPORT FAILED'){setText('fabricStateText','MISSION FAILED','warn');setText('streamState','SSE · CLOSED','warn');if(led)led.dataset.state='FAILED'}else if(String(value||'').startsWith('REPLAYED')){setText('fabricStateText','EVIDENCE REPLAY','ok');setText('streamState','SSE · NOT CONNECTED');if(led)led.dataset.state='COMPLETED'}else{setText('fabricStateText','DORMANT');setText('streamState','SSE · DORMANT');if(led)led.dataset.state='IDLE'}}
  const keyInput=byId('key'),iocInput=byId('ioc'),typeInput=byId('type'),profileInput=byId('profile'),preflightPanel=byId('preflightStatus'),assessReadiness=byId('assessReadiness'),readinessPanel=byId('readinessPanel');
  let preflight={eligible:false,key:'',seq:0,controller:null};
  let readiness={valid:false,key:'',ioc:'',type:'',profile:'AUTO',body:null,controller:null,seq:0};
  run.disabled=true;if(assessReadiness)assessReadiness.disabled=true;
  function clearReadiness(detail){readiness.seq++;if(readiness.controller){readiness.controller.abort();readiness.controller=null}readiness.valid=false;readiness.key='';readiness.ioc='';readiness.type='';readiness.profile='AUTO';readiness.body=null;if(readinessPanel)readinessPanel.dataset.state='idle';setText('readinessSummary',detail||'Not assessed. Optional assessment consumes one canonical correlation request and dispatches zero SWARM missions.');setText('readinessQuality','NOT ASSESSED');setText('readinessAgents','— / 8');setText('readinessAi','NOT ASSESSED');setText('readinessMatches','—');const detailEl=byId('readinessAgentsDetail');if(detailEl)detailEl.innerHTML='';if(assessReadiness)assessReadiness.disabled=!(preflight.eligible&&String(iocInput?.value||'').trim())}
  function renderPreflight(state,label,detail,tone){if(preflightPanel)preflightPanel.dataset.state=state;setText('preflightState',label,tone);setText('preflightDetail',detail,tone)}
  function invalidatePreflight(detail){preflight.seq++;if(preflight.controller){preflight.controller.abort();preflight.controller=null}preflight.eligible=false;preflight.key='';run.disabled=true;if(assessReadiness)assessReadiness.disabled=true;clearReadiness('Credential changed. Re-assess mission readiness after access verification.');renderPreflight('unverified','ACCESS NOT VERIFIED',detail||'Complete credential entry to verify SWARM entitlement.','')}
  function preflightFailureDetail(body,status){const reason=(body&&body.reason)||(body&&body.error)||'';if(reason==='key_expired')return'Credential expired. Renew or rotate the key before launch.';if(String(reason).startsWith('subscription_'))return'Subscription access is not active for SWARM execution.';if(reason==='swarm_paid_tier_required')return'Valid credential, but SWARM requires PRO, ENTERPRISE, or MSSP entitlement.';if(reason==='swarm_scope_required')return'Credential does not currently carry the required read:intel capability.';if(reason==='daily_quota_exhausted')return'Daily API quota is exhausted. Launch remains locked until quota reset.';if(reason==='rate_limited'||status===429)return'Admission check is rate limited. Retry after the server-provided interval.';if(status===503)return'Entitlement authority is temporarily unavailable. No mission was started.';return'Credential could not be admitted for SWARM execution.'}
  async function verifySwarmAccess(key){
    const candidate=String(key||'').trim();
    if(!candidate){invalidatePreflight('Enter a Sentinel API key or bearer token.');return false}
    if(candidate.length<16){invalidatePreflight('Credential entry is incomplete. Verification starts only after a complete credential is supplied.');return false}
    const seq=++preflight.seq;if(preflight.controller)preflight.controller.abort();const controller=new AbortController();preflight.controller=controller;preflight.eligible=false;preflight.key='';run.disabled=true;renderPreflight('checking','VERIFYING ACCESS','Checking canonical subscription, SWARM entitlement, scope, and remaining daily quota…','warn');
    try{
      const r=await fetch('/api/swarm/preflight',{method:'GET',headers:{'x-api-key':candidate,'x-request-id':'preflight-'+crypto.randomUUID()},cache:'no-store',signal:controller.signal});
      const body=await r.json().catch(()=>({error:'invalid_preflight_response'}));
      if(seq!==preflight.seq)return false;
      if(r.ok&&body&&body.eligible===true){
        const ent=body.entitlement||{},daily=(body.quota&&body.quota.daily)||{};
        preflight.eligible=true;preflight.key=candidate;
        const quota=daily.available===false?'quota telemetry unavailable':(String(daily.remaining)+' / '+String(daily.limit)+' daily requests remaining');
        const expiry=ent.expires_at?' · expires '+String(ent.expires_at).slice(0,10):'';
        renderPreflight('verified','SWARM ACCESS VERIFIED',(ent.tier||'PAID')+' · '+quota+expiry,'ok');run.disabled=false;if(assessReadiness)assessReadiness.disabled=!String(iocInput?.value||'').trim();return true
      }
      preflight.eligible=false;preflight.key='';run.disabled=true;renderPreflight('denied','ACCESS DENIED',preflightFailureDetail(body,r.status),'warn');return false
    }catch(e){
      if(e&&e.name==='AbortError')return false;
      if(seq!==preflight.seq)return false;
      preflight.eligible=false;preflight.key='';run.disabled=true;renderPreflight('denied','PREFLIGHT UNAVAILABLE','Canonical entitlement verification failed. No mission was started.','warn');return false
    }finally{if(seq===preflight.seq)preflight.controller=null}
  }
  let preflightTimer=null;
  function schedulePreflight(delay){if(preflightTimer)clearTimeout(preflightTimer);preflightTimer=setTimeout(()=>{preflightTimer=null;verifySwarmAccess(keyInput.value)},Math.max(0,Number(delay)||0))}
  keyInput.oninput=()=>invalidatePreflight('Credential changed. Verification is required before launch.');
  keyInput.onpaste=()=>setTimeout(()=>schedulePreflight(0),250);
  keyInput.onchange=()=>schedulePreflight(0);
  function readinessTone(quality){if(quality==='FULL_FABRIC')return'ok';if(quality==='BLOCKED')return'warn';return'warn'}
  function renderReadiness(body){const r=body&&body.readiness;if(!r)return;readiness.valid=true;readiness.body=body;readiness.key=keyInput.value.trim();readiness.ioc=String(iocInput.value||'').trim();readiness.type=String(typeInput.value||'auto');readiness.profile=String(profileInput?.value||'AUTO');const full=r.mission_quality==='FULL_FABRIC'&&body.demo_recommended===true;if(readinessPanel)readinessPanel.dataset.state=full?'ready':(r.status==='blocked'?'blocked':'limited');setText('readinessQuality',String(r.mission_quality||'UNKNOWN').replaceAll('_',' '),readinessTone(r.mission_quality));setText('readinessAgents',String(r.ready_agents??0)+' / '+String(r.total_agents??8),full||r.mission_quality==='PROFILE_READY'?'ok':'warn');setText('readinessAi',body.synthesis_readiness&&body.synthesis_readiness.ready?'READY':'DEGRADED',body.synthesis_readiness&&body.synthesis_readiness.ready?'ok':'warn');setText('readinessMatches',String((body.correlation&&body.correlation.match_count)??0));setText('readinessSummary',full?'Full-fabric readiness confirmed. This assessment dispatched zero SWARM missions.':('Readiness assessed for '+String((body.mission_profile&&body.mission_profile.label)||readiness.profile).replaceAll('_',' ')+'. Mission remains launchable; review NOT APPLICABLE / DEGRADED dependencies before proceeding.'),full?'ok':'warn');const detail=byId('readinessAgentsDetail');if(detail){detail.innerHTML='';Object.entries(r.agents||{}).forEach(([id,a])=>{const chip=document.createElement('span');chip.className='readiness-chip';chip.dataset.state=a.state||'UNKNOWN';chip.textContent=id.replaceAll('-',' ').toUpperCase()+' · '+String(a.state||'UNKNOWN').replaceAll('_',' ');detail.appendChild(chip)})}}
  async function assessMissionReadiness(){const key=keyInput.value.trim(),ioc=String(iocInput.value||'').trim(),type=String(typeInput.value||'auto'),profile=String(profileInput?.value||'AUTO');if(!preflight.eligible||preflight.key!==key){clearReadiness('Verify SWARM access before assessing readiness.');return false}if(!ioc){clearReadiness('Enter an IOC before assessing readiness.');return false}const seq=++readiness.seq;if(readiness.controller)readiness.controller.abort();const controller=new AbortController();readiness.controller=controller;readiness.valid=false;assessReadiness.disabled=true;if(readinessPanel)readinessPanel.dataset.state='checking';setText('readinessSummary','Running one canonical correlation readiness assessment. No SWARM mission will be dispatched.','warn');setText('readinessQuality','ASSESSING','warn');try{const resp=await fetch('/api/swarm/readiness',{method:'POST',headers:{'content-type':'application/json','x-api-key':key,'x-request-id':'readiness-'+crypto.randomUUID()},body:JSON.stringify({ioc_value:ioc,ioc_type:type,mission_profile:profile}),cache:'no-store',signal:controller.signal});const body=await resp.json().catch(()=>({error:'invalid_readiness_response'}));if(seq!==readiness.seq)return false;if(!resp.ok){if(readinessPanel)readinessPanel.dataset.state='blocked';setText('readinessSummary','Readiness unavailable: '+String(body.reason||body.error||('HTTP '+resp.status)),'warn');setText('readinessQuality','BLOCKED','warn');return false}renderReadiness(body);return true}catch(e){if(e&&e.name==='AbortError')return false;if(seq!==readiness.seq)return false;if(readinessPanel)readinessPanel.dataset.state='blocked';setText('readinessSummary','Readiness assessment failed. No SWARM mission was dispatched.','warn');setText('readinessQuality','UNAVAILABLE','warn');return false}finally{if(seq===readiness.seq)readiness.controller=null;if(assessReadiness)assessReadiness.disabled=!(preflight.eligible&&String(iocInput.value||'').trim())}}
  if(assessReadiness)assessReadiness.onclick=assessMissionReadiness;
  const invalidateReadinessInput=()=>clearReadiness('IOC or IOC type changed. Re-assess to refresh projected mission quality.');
  if(iocInput)iocInput.addEventListener('input',invalidateReadinessInput);
  if(typeInput)typeInput.addEventListener('change',invalidateReadinessInput);
  if(profileInput)profileInput.addEventListener('change',()=>clearReadiness('Mission profile changed. Re-assess projected agent readiness for the selected profile.'));
  const browserTimeZone=()=>{try{return Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC'}catch{return 'UTC'}};
  const validTimeZone=(tz)=>{try{new Intl.DateTimeFormat('en-US',{timeZone:tz}).format(new Date());return tz}catch{return 'UTC'}};
  const regionDisplay=(code)=>{if(!code)return'';try{return typeof Intl.DisplayNames==='function'?new Intl.DisplayNames(['en'],{type:'region'}).of(code)||code:code}catch{return code}};
  const clockContext={timeZone:validTimeZone(browserTimeZone()),city:'',region:'',countryCode:'',countryName:'',source:'browser'};
  function clockZoneAlias(date,tz){const fixed={'Asia/Kolkata':'IST','Asia/Calcutta':'IST','UTC':'UTC'};if(fixed[tz])return fixed[tz];try{const parts=new Intl.DateTimeFormat('en-US',{timeZone:tz,timeZoneName:'short'}).formatToParts(date);return(parts.find((p)=>p.type==='timeZoneName')||{}).value||tz}catch{return tz}}
  function updateClock(){const timeEl=byId('clockTime');if(!timeEl)return;const d=new Date(),tz=validTimeZone(clockContext.timeZone);try{timeEl.textContent=new Intl.DateTimeFormat('en-GB',{timeZone:tz,hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false}).format(d)}catch{timeEl.textContent=d.toISOString().slice(11,19)}const dateEl=byId('clockDate');if(dateEl){try{dateEl.textContent=new Intl.DateTimeFormat('en-GB',{timeZone:tz,weekday:'short',day:'2-digit',month:'short',year:'numeric'}).format(d).toUpperCase()}catch{dateEl.textContent=d.toISOString().slice(0,10)}}const zoneEl=byId('clockZone');if(zoneEl)zoneEl.textContent=clockZoneAlias(d,tz)+' · '+tz;const locationEl=byId('clockLocation');if(locationEl){const loc=[clockContext.city,clockContext.region].filter(Boolean).join(' · ');locationEl.textContent=(loc||tz.replaceAll('_',' ')).toUpperCase()}const countryEl=byId('clockCountry');if(countryEl){const country=clockContext.countryName||regionDisplay(clockContext.countryCode);countryEl.textContent=(country||'LOCAL BROWSER TIME').toUpperCase()}const consoleEl=byId('globalClock');if(consoleEl)consoleEl.dataset.synced=clockContext.source==='edge'?'true':'fallback'}
  async function hydrateClockContext(){clockContext.timeZone=validTimeZone(browserTimeZone());updateClock();try{const r=await fetch('/api/swarm/client-context',{headers:{accept:'application/json'},cache:'no-store'});const body=await r.json();if(r.ok&&body&&body.data){const x=body.data;clockContext.timeZone=validTimeZone(x.timezone||clockContext.timeZone);clockContext.city=typeof x.city==='string'?x.city:'';clockContext.region=typeof x.region==='string'?x.region:'';clockContext.countryCode=typeof x.country_code==='string'?x.country_code:'';clockContext.countryName=typeof x.country_name==='string'?x.country_name:'';clockContext.source=x.source==='cloudflare_edge'?'edge':'browser'}}catch{}updateClock()}
  updateClock();setInterval(updateClock,1000);hydrateClockContext();
  function updateOpsTelemetry(){const agents=[...document.querySelectorAll('.agent')];const active=agents.filter((el)=>el.dataset.state==='RUNNING').length;const completed=agents.filter((el)=>el.dataset.state==='COMPLETED').length;const terminal=agents.filter((el)=>['COMPLETED','NOT_APPLICABLE','DEGRADED','DENIED','UNAVAILABLE','FAILED'].includes(el.dataset.state)).length;setText('activeAgents',String(active).padStart(2,'0'));setText('completedAgents',String(completed).padStart(2,'0'));const led=byId('fabricLed');if(led)led.dataset.state=active?'RUNNING':(terminal===agents.length&&agents.length?'COMPLETED':'IDLE')}
  function focusAgentForExecutive(ev){if(document.body.dataset.view!=='executive'||!ev||!ev.agent_id||ev.event_type!=='agent.started')return;document.querySelectorAll('.agent[data-focus=true]').forEach((el)=>delete el.dataset.focus);const el=byId('agent-'+ev.agent_id);if(!el)return;el.dataset.focus='true';if(!prefersReducedMotion)el.scrollIntoView({behavior:'smooth',block:'center'});else el.scrollIntoView({block:'center'})}
  function setMeshNode(agentId,state){const node=byId('mesh-'+agentId);if(node)node.dataset.state=state||'IDLE'}
  const prefersReducedMotion=Boolean(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const cinematicCanvas=byId('cinematicCanvas');
  const cinematicCtx=cinematicCanvas?cinematicCanvas.getContext('2d',{alpha:true,desynchronized:true}):null;
  let fxParticles=[],fxWaves=[],fxBolts=[],fxRaf=0,fxDpr=1;
  function resizeCinematicCanvas(){if(!cinematicCanvas||!cinematicCtx)return;fxDpr=Math.min(window.devicePixelRatio||1,1.5);cinematicCanvas.width=Math.max(1,Math.floor(window.innerWidth*fxDpr));cinematicCanvas.height=Math.max(1,Math.floor(window.innerHeight*fxDpr));cinematicCanvas.style.width=window.innerWidth+'px';cinematicCanvas.style.height=window.innerHeight+'px';cinematicCtx.setTransform(fxDpr,0,0,fxDpr,0,0)}
  function fxAnchor(el){const r=(el&&el.getBoundingClientRect)?el.getBoundingClientRect():{left:window.innerWidth/2,top:window.innerHeight/2,width:0,height:0};return{x:r.left+r.width/2,y:r.top+r.height/2}}
  function fxPalette(kind){if(kind==='FAILURE'||kind==='DENIED'||kind==='FAILED')return['#ff7272','#ff4f8b','#ff9a4f'];if(kind==='SUCCESS'||kind==='COMPLETED')return['#42e0ad','#8bf7d2','#8dff5a','#00e7ff'];if(kind==='RUNNING'||kind==='LAUNCH')return['#ffc857','#ff9a4f','#00e7ff','#9d6bff','#ff4fd8'];if(kind==='QUEUED')return['#75a7ff','#00e7ff','#9d6bff'];return['#00e7ff','#42e0ad','#9d6bff']}
  function ensureFxLoop(){if(prefersReducedMotion||!cinematicCtx||fxRaf)return;fxRaf=requestAnimationFrame(renderCinematicFx)}
  function spawnParticles(kind,el,count){if(prefersReducedMotion||!cinematicCtx)return;const p=fxAnchor(el),palette=fxPalette(kind);for(let i=0;i<count;i+=1){const angle=Math.random()*Math.PI*2;const speed=1.2+Math.random()*4.8;fxParticles.push({x:p.x,y:p.y,vx:Math.cos(angle)*speed,vy:Math.sin(angle)*speed-(kind==='LAUNCH'?1.4:0),r:1+Math.random()*3.2,life:1,decay:.012+Math.random()*.022,color:palette[Math.floor(Math.random()*palette.length)],glow:8+Math.random()*18})}if(fxParticles.length>220)fxParticles=fxParticles.slice(-220);ensureFxLoop()}
  function spawnWave(kind,el,radius){if(prefersReducedMotion||!cinematicCtx)return;const p=fxAnchor(el),palette=fxPalette(kind);fxWaves.push({x:p.x,y:p.y,r:10,max:radius||220,life:1,color:palette[0]});if(fxWaves.length>12)fxWaves=fxWaves.slice(-12);ensureFxLoop()}
  function spawnBolt(kind,el){if(prefersReducedMotion||!cinematicCtx)return;const p=fxAnchor(el),palette=fxPalette(kind),targetAngle=Math.random()*Math.PI*2,targetDistance=Math.min(window.innerWidth,window.innerHeight)*(.16+Math.random()*.18);const ex=p.x+Math.cos(targetAngle)*targetDistance,ey=p.y+Math.sin(targetAngle)*targetDistance,points=[];const segments=9;for(let i=0;i<=segments;i+=1){const t=i/segments;const jitter=i===0||i===segments?0:(Math.random()-.5)*34;points.push({x:p.x+(ex-p.x)*t+jitter,y:p.y+(ey-p.y)*t+jitter})}fxBolts.push({points,life:1,color:palette[Math.floor(Math.random()*palette.length)]});if(fxBolts.length>10)fxBolts=fxBolts.slice(-10);ensureFxLoop()}
  function emitCinematicFx(kind,el,intensity){if(prefersReducedMotion)return;const n=Math.max(8,Math.round(20*(intensity||1)));spawnParticles(kind,el,n);spawnWave(kind,el,kind==='LAUNCH'?320:150);if(kind==='LAUNCH'||kind==='FAILURE'||kind==='SUCCESS')spawnBolt(kind,el)}
  function renderCinematicFx(){fxRaf=0;if(!cinematicCtx)return;cinematicCtx.clearRect(0,0,window.innerWidth,window.innerHeight);cinematicCtx.globalCompositeOperation='lighter';fxParticles=fxParticles.filter((p)=>{p.x+=p.vx;p.y+=p.vy;p.vy+=.025;p.vx*=.992;p.life-=p.decay;if(p.life<=0)return false;cinematicCtx.save();cinematicCtx.globalAlpha=Math.max(0,p.life)*.9;cinematicCtx.fillStyle=p.color;cinematicCtx.shadowColor=p.color;cinematicCtx.shadowBlur=p.glow;cinematicCtx.beginPath();cinematicCtx.arc(p.x,p.y,p.r,0,Math.PI*2);cinematicCtx.fill();cinematicCtx.restore();return true});fxWaves=fxWaves.filter((w)=>{w.r+=8;w.life-=.045;if(w.life<=0||w.r>w.max)return false;cinematicCtx.save();cinematicCtx.globalAlpha=Math.max(0,w.life)*.65;cinematicCtx.strokeStyle=w.color;cinematicCtx.lineWidth=1.5;cinematicCtx.shadowColor=w.color;cinematicCtx.shadowBlur=18;cinematicCtx.beginPath();cinematicCtx.arc(w.x,w.y,w.r,0,Math.PI*2);cinematicCtx.stroke();cinematicCtx.restore();return true});fxBolts=fxBolts.filter((b)=>{b.life-=.09;if(b.life<=0)return false;cinematicCtx.save();cinematicCtx.globalAlpha=b.life*.8;cinematicCtx.strokeStyle=b.color;cinematicCtx.lineWidth=1.3;cinematicCtx.shadowColor=b.color;cinematicCtx.shadowBlur=14;cinematicCtx.beginPath();b.points.forEach((p,i)=>{if(i===0)cinematicCtx.moveTo(p.x,p.y);else cinematicCtx.lineTo(p.x,p.y)});cinematicCtx.stroke();cinematicCtx.restore();return true});cinematicCtx.globalCompositeOperation='source-over';if(fxParticles.length||fxWaves.length||fxBolts.length)ensureFxLoop()}
  function triggerLaunchSequence(){document.body.dataset.launchFx='active';run.classList.add('launching');emitCinematicFx('LAUNCH',run,1.8);const launchPanel=document.querySelector('.launch');window.setTimeout(()=>emitCinematicFx('LAUNCH',launchPanel,1.25),220);window.setTimeout(()=>emitCinematicFx('LAUNCH',document.querySelector('.mesh-fabric'),1.1),620);window.setTimeout(()=>{document.body.dataset.launchFx='idle';run.classList.remove('launching')},1700)}
  function fxForMissionEvent(ev){if(prefersReducedMotion||!ev)return;const el=ev.agent_id?byId('agent-'+ev.agent_id):document.querySelector('.mesh-fabric');if(ev.event_type==='mesh.admitted')emitCinematicFx('SUCCESS',document.querySelector('.mesh-fabric'),.8);else if(ev.event_type==='agent.started')emitCinematicFx('RUNNING',el,.45);else if(ev.event_type==='agent.completed')emitCinematicFx('COMPLETED',el,.38);else if(ev.event_type==='agent.degraded'||ev.event_type==='agent.unavailable')emitCinematicFx('QUEUED',el,.34);else if(ev.event_type==='agent.denied'||ev.event_type==='agent.failed')emitCinematicFx('FAILURE',el,.55);else if(ev.event_type==='mission.completed')emitCinematicFx('SUCCESS',document.querySelector('.hero'),1.15);else if(ev.event_type==='mission.rejected'||ev.event_type==='mission.failed')emitCinematicFx('FAILURE',document.querySelector('.hero'),1.0)}
  if(cinematicCanvas){resizeCinematicCanvas();window.addEventListener('resize',resizeCinematicCanvas,{passive:true})}


  function resetAgents(){document.querySelectorAll('.agent').forEach((el)=>{el.dataset.state='IDLE';el.querySelector('.state').textContent='IDLE';el.querySelector('.basis').textContent='WAITING';el.querySelector('.duration').textContent='—';const p=el.querySelector('pre');p.textContent='Awaiting backend execution.';const n=el.querySelector('.narrative');if(n){n.hidden=true;n.textContent=''};const id=el.id.replace('agent-','');setMeshNode(id,'IDLE')});updateOpsTelemetry()}
  function resetEventLog(){eventLog.innerHTML='<div class="event-empty">Waiting for the production SSE stream…</div>';setText('eventCount','00')}
  function appendEvent(ev){const empty=eventLog.querySelector('.event-empty');if(empty)empty.remove();setText('eventCount',String(ev.sequence||eventLog.querySelectorAll('.event-row').length+1).padStart(2,'0'));const row=document.createElement('div');row.className='event-row';row.dataset.state=ev.state||'EVENT';const seq=document.createElement('span');seq.className='event-seq';seq.textContent='#'+String(ev.sequence||'—').padStart(2,'0');const state=document.createElement('span');state.className='event-state';state.textContent=ev.state||'EVENT';const desc=document.createElement('span');desc.className='event-desc';const when=ev.timestamp?new Date(ev.timestamp).toLocaleTimeString():'—';desc.textContent=when+' · '+(ev.event_type||'swarm.event')+(ev.agent_name?' · '+ev.agent_name:'');row.append(seq,state,desc);eventLog.appendChild(row);eventLog.scrollTop=eventLog.scrollHeight;fxForMissionEvent(ev);focusAgentForExecutive(ev)}
  function renderNarrative(el,result){const n=el.querySelector('.narrative');if(!n)return;n.hidden=false;n.textContent='';const badge=document.createElement('span');badge.className='badge';const body=document.createElement('span');body.className='narrative-body';if(result.llm_enhanced&&result.ai_narrative){badge.dataset.kind='ai';badge.textContent='AI-SYNTHESIZED'+(result.llm_model?' · '+result.llm_model:'');body.textContent=result.ai_narrative}else{badge.dataset.kind='deterministic';badge.textContent='DETERMINISTIC FUSION';body.textContent=result.recommendation||''}n.append(badge,body)}
  function setAgent(ev){if(!ev.agent_id)return;const el=byId('agent-'+ev.agent_id);if(!el)return;const semantic=ev.state==='SKIPPED'?'NOT_APPLICABLE':(ev.state||'IDLE');el.dataset.state=semantic;setMeshNode(ev.agent_id,semantic);el.querySelector('.state').textContent=semantic.replaceAll('_',' ')+(ev.basis==='unconfigured'?' · CONFIG ERROR':'');el.querySelector('.basis').textContent=(ev.basis||ev.event_type||'BACKEND').replaceAll('_',' ');el.querySelector('.duration').textContent=Number.isFinite(ev.duration_ms)?ev.duration_ms+' ms':'—';if(ev.agent_id==='risk-synthesizer'&&ev.result)renderNarrative(el,ev.result);const p=el.querySelector('pre');if(ev.result)p.textContent=JSON.stringify(ev.result,null,2);else if(ev.detail)p.textContent=JSON.stringify(ev.detail,null,2);else if(ev.reason)p.textContent=ev.reason;else if(ev.event_type)p.textContent=ev.event_type;updateOpsTelemetry()}
  function renderPersistedMission(record){setText('mission',record.mission_id||'—');setText('correlation',record.correlation_id||'—');setMissionState(record.status==='COMPLETED'?'REPLAYED · COMPLETED':('REPLAYED · '+(record.status||'UNKNOWN')),record.status==='COMPLETED'?'ok':'warn');setText('mesh',record.mesh_certified?'CERTIFIED':'NOT CERTIFIED',record.mesh_certified?'ok':'warn');setText('missionQuality',String(record.mission_quality||'LEGACY / UNCLASSIFIED').replaceAll('_',' '),record.status==='COMPLETED'?'ok':'warn');const g=record.evidence_graph;setText('evidenceGraphState',g?(String(g.node_count||0)+' NODES · '+String(g.edge_count||0)+' EDGES'):'LEGACY / NONE',g?'ok':'warn');if(record.specialists){Object.entries(record.specialists).forEach(([id,o])=>setAgent({agent_id:id,state:o.state,basis:o.basis,result:o.result,duration_ms:o.duration_ms}))}final.textContent=JSON.stringify(record,null,2);eventLog.innerHTML='<div class="event-empty">Persisted idempotent replay loaded. No duplicate backend dispatch was performed.</div>'}
  async function hydrateHealth(){try{const r=await fetch('/api/swarm/health',{cache:'no-store'});const body=await r.json();if(!r.ok)throw new Error('HTTP '+r.status);setText('runtimeState','LIVE','ok');setTone(byId('runtimePill'),'ok');setText('runtimeKpi','LIVE · '+(body.version||'CURRENT'),'ok');setText('protocol',body.protocol||'cdb.swarm.v1');setText('agentCount',String(body.agents||8)+' AGENTS','ok');const gateway=Boolean(body.production&&body.production.canonical_gateway_bound);const durable=Boolean(body.persistence&&body.persistence.kv_bound);const retry=Boolean(body.capabilities&&body.capabilities.idempotent_retry);const formats=(body.capabilities&&body.capabilities.report_formats)||[];setText('gatewayState',gateway?'BOUND':'UNAVAILABLE',gateway?'ok':'warn');setText('persistenceState',durable?'READY':'UNAVAILABLE',durable?'ok':'warn');setText('retryState',retry?'ENFORCED':'UNKNOWN',retry?'ok':'warn');setText('exportState',formats.includes('stix21')?'READY':'LIMITED',formats.includes('stix21')?'ok':'warn');setText('evidenceStore',durable?'DURABLE KV READY':'UNAVAILABLE',durable?'ok':'warn')}catch(e){setText('runtimeState','UNAVAILABLE','warn');setText('runtimeKpi','HEALTH CHECK FAILED','warn');setText('gatewayState','UNKNOWN','warn');setText('persistenceState','UNKNOWN','warn');setText('retryState','UNKNOWN','warn');setText('exportState','UNKNOWN','warn');setText('evidenceStore','UNKNOWN','warn')}}
  run.onclick=async()=>{const key=byId('key').value.trim(),ioc=byId('ioc').value.trim(),type=byId('type').value,profile=String(byId('profile')?.value||'AUTO');if(!key||!ioc){final.textContent='API key and IOC are required.';setMissionState('INPUT REQUIRED','warn');return}if(!preflight.eligible||preflight.key!==key){final.textContent='SWARM access must be verified before launch.';setMissionState('ACCESS CHECK REQUIRED','warn');schedulePreflight(0);return}triggerLaunchSequence();resetAgents();resetEventLog();run.disabled=true;final.textContent='Connecting to the production swarm…';setText('mission','—');setText('correlation','—');setText('mesh','PENDING','warn');setText('missionQuality',readiness.valid&&readiness.body?String(readiness.body.readiness.mission_quality||'PENDING').replaceAll('_',' '):'PENDING','warn');setText('evidenceGraphState','BUILDING','warn');setMissionState('CONNECTING','warn');try{const rid='ui-'+crypto.randomUUID();const r=await fetch('/api/swarm/run',{method:'POST',headers:{'content-type':'application/json','x-api-key':key,'x-request-id':rid},body:JSON.stringify({ioc_value:ioc,ioc_type:type,mission_profile:profile})});if(!r.ok){setMissionState('REJECTED','warn');final.textContent='Launch failed: HTTP '+r.status+' '+await r.text();return}const contentType=r.headers.get('content-type')||'';if(contentType.includes('application/json')){const replay=await r.json();if(replay&&replay.idempotent_replay&&replay.data){renderPersistedMission(replay.data);return}final.textContent=JSON.stringify(replay,null,2);return}setText('mission',r.headers.get('x-cdb-swarm-mission')||'—');setText('correlation',r.headers.get('x-cdb-swarm-correlation')||rid);const reader=r.body.getReader(),decoder=new TextDecoder();let buf='';while(true){const chunkResult=await reader.read();if(chunkResult.done)break;buf+=decoder.decode(chunkResult.value,{stream:true});let idx;while((idx=buf.indexOf('\n\n'))>=0){const chunk=buf.slice(0,idx);buf=buf.slice(idx+2);const line=chunk.split('\n').find((x)=>x.startsWith('data: '));if(!line)continue;const ev=JSON.parse(line.slice(6));setText('mission',ev.mission_id||'—');setText('correlation',ev.correlation_id||'—');appendEvent(ev);setAgent(ev);if(ev.event_type==='mission.accepted')setMissionState('QUEUED','warn');else if(ev.event_type==='mission.readiness'){if(ev.readiness){const synthetic={status:'ok',readiness:ev.readiness,synthesis_readiness:ev.synthesis_readiness||{},correlation:{match_count:ev.readiness.match_count},demo_recommended:ev.readiness.mission_quality==='FULL_FABRIC'&&ev.synthesis_readiness&&ev.synthesis_readiness.ready===true};renderReadiness(synthetic)}}else if(ev.event_type==='mesh.admitted'){setText('mesh','CERTIFIED · '+(ev.mesh_execution_id||''),'ok');setMissionState('ADMITTED','ok')}else if(ev.event_type==='agent.started')setMissionState('RUNNING','warn');if(ev.mesh_certified)setText('mesh','CERTIFIED · '+(ev.mesh_execution_id||''),'ok');if(ev.event_type==='mission.completed'){setMissionState('COMPLETED','ok');setText('missionQuality',String(ev.mission_quality||'COMPLETED').replaceAll('_',' '),ev.mission_quality&&ev.mission_quality.includes('WARNING')?'warn':'ok');const g=ev.evidence_graph;setText('evidenceGraphState',g?(String(g.node_count||0)+' NODES · '+String(g.edge_count||0)+' EDGES'):'COMPLETE',g?'ok':'');final.textContent=JSON.stringify(ev.result,null,2)}if(ev.event_type==='mission.rejected'||ev.event_type==='mission.failed'){setMissionState('FAILED','warn');setText('missionQuality','FAILED','warn');setText('evidenceGraphState','INCOMPLETE','warn');final.textContent=JSON.stringify(ev,null,2)}}}}catch(e){setMissionState('TRANSPORT FAILED','warn');final.textContent='Mission transport failed: '+e.message}finally{run.disabled=!(preflight.eligible&&preflight.key===byId('key').value.trim());if(assessReadiness)assessReadiness.disabled=!(preflight.eligible&&String(iocInput.value||'').trim())}}
  updateOpsTelemetry();
  hydrateHealth();
  const loadHistoryBtn=document.getElementById('loadHistory'),historyBody=document.getElementById('historyBody'),historyNote=document.getElementById('historyNote');
  function escHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
  loadHistoryBtn.onclick=async()=>{
    const key=document.getElementById('key').value.trim();
    if(!key){historyNote.textContent='Enter your API key above first.';return}
    loadHistoryBtn.disabled=true;historyNote.textContent='Loading…';
    try{
      const r=await fetch('/api/swarm/missions?limit=20',{headers:{'x-api-key':key}});
      const body=await r.json();
      if(!r.ok){historyNote.textContent='History unavailable: '+(body.message||body.error||('HTTP '+r.status));historyBody.innerHTML='';return}
      const missions=(body.data&&body.data.missions)||[];
      if(!missions.length){historyNote.textContent='No missions found yet for this key.';historyBody.innerHTML='';return}
      historyNote.textContent=missions.length+' mission(s)'+((body.data&&body.data.list_complete)?'':' (more available)');
      historyBody.innerHTML='<table><thead><tr><th>Finished</th><th>IOC</th><th>Verdict</th><th>Status</th><th>Evidence</th></tr></thead><tbody>'+missions.map(m=>
        '<tr><td>'+escHtml(m.finished_at||'—')+'</td><td>'+escHtml(m.ioc_value||'—')+'</td><td>'+escHtml(m.verdict||'—')+'</td><td>'+escHtml(m.status||'—')+'</td><td><button type="button" class="dl" data-id="'+escHtml(m.mission_id)+'" data-format="md">report</button> <button type="button" class="dl" data-id="'+escHtml(m.mission_id)+'" data-format="json">json</button> <button type="button" class="dl" data-id="'+escHtml(m.mission_id)+'" data-format="stix21">stix</button></td></tr>'
      ).join('')+'</tbody></table>';
    }catch(e){historyNote.textContent='History request failed: '+e.message}
    finally{loadHistoryBtn.disabled=false}
  };
  historyBody.onclick=async(e)=>{
    const btn=e.target.closest('.dl');if(!btn)return;
    const key=document.getElementById('key').value.trim();
    if(!key){historyNote.textContent='Enter your API key above first.';return}
    const id=btn.dataset.id,format=btn.dataset.format;
    btn.disabled=true;
    try{
      const r=await fetch('/api/swarm/mission/'+encodeURIComponent(id)+'/report?format='+format,{headers:{'x-api-key':key}});
      if(!r.ok){historyNote.textContent='Export failed: HTTP '+r.status;return}
      const cd=r.headers.get('content-disposition')||'',m=cd.match(/filename="([^"]+)"/);
      const blob=await r.blob();
      const a=document.createElement('a');
      a.href=URL.createObjectURL(blob);
      a.download=m?m[1]:(id+'.'+format);
      document.body.appendChild(a);a.click();a.remove();
      URL.revokeObjectURL(a.href);
    }catch(err){historyNote.textContent='Export failed: '+err.message}
    finally{btn.disabled=false}
  };

  window.__CDB_SWARM_INTERACTIVE_READY__=true;
`;
}

function ui() {
  const initialNow = new Date();
  const initialUtcTime = initialNow.toISOString().slice(11, 19);
  const initialUtcDate = initialNow.toISOString().slice(0, 10);
  const visualFor = (id) => AGENT_VISUALS[id] || AGENT_VISUALS['ioc-hunter'];
  const visualStyle = (v) =>
    `--agent-accent:${v.accent};--agent-accent-soft:${v.soft};--agent-accent-ring:${v.ring}`;

  const agents = AGENTS.map((a, index) => {
    const v = visualFor(a.id);
    return `<article class="agent" id="agent-${escapeHtml(a.id)}" data-agent-id="${escapeHtml(a.id)}" data-state="IDLE" style="${visualStyle(v)}"><div class="agent-spectrum"></div><div class="agent-head"><div class="agent-identity"><span class="agent-led" aria-hidden="true"></span><span class="agent-index">${String(index + 1).padStart(2, '0')}</span><div class="agent-title"><strong>${escapeHtml(a.name)}</strong><small>${escapeHtml(a.capability)}</small></div></div><span class="state">IDLE</span></div><div class="agent-meta-line"><span class="basis">WAITING</span><span class="duration">—</span></div>${a.id === 'risk-synthesizer' ? '<p class="narrative" hidden></p>' : ''}<pre>Awaiting backend execution.</pre></article>`;
  }).join('');

  const meshNodes = AGENTS.map((a) => {
    const v = visualFor(a.id);
    return `<div class="mesh-node" id="mesh-${escapeHtml(a.id)}" data-agent-id="${escapeHtml(a.id)}" data-state="IDLE" style="${visualStyle(v)}"><span class="mesh-led" aria-hidden="true"></span><b class="mesh-code">${escapeHtml(v.mesh)}</b><small class="mesh-agent-name">${escapeHtml(a.name)}</small></div>`;
  }).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>CYBERDUDEBIVASH SENTINEL APEX — SUPER AGENT SWARM</title><style>
  :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bg:#04080b;--panel:#07130f;--panel2:#0a1a15;--panel3:#0c211a;--line:#17483b;--line2:#226b56;--text:#f1f8f5;--muted:#8baaa1;--muted2:#64847a;--mint:#42e0ad;--mint2:#8bf7d2;--amber:#ffc857;--red:#ff7272;--blue:#75a7ff;--shadow:0 24px 80px rgba(0,0,0,.34)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;background:radial-gradient(circle at 18% -8%,rgba(38,155,119,.18),transparent 32%),radial-gradient(circle at 84% 12%,rgba(40,96,82,.14),transparent 28%),linear-gradient(180deg,#04090d 0%,#03070a 100%);color:var(--text)}body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.18;background-image:linear-gradient(rgba(74,226,179,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(74,226,179,.045) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 70%)}button,input,select{font:inherit}.wrap{position:relative;z-index:1;max-width:1380px;margin:auto;padding:26px 26px 72px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:6px 2px 20px}.brand-block{display:flex;align-items:center;gap:12px}.brand-mark{width:38px;height:38px;border-radius:11px;border:1px solid var(--line2);display:grid;place-items:center;background:linear-gradient(145deg,#0b2c22,#07110e);box-shadow:inset 0 0 24px rgba(66,224,173,.08);font-weight:900;color:var(--mint2)}.brand{font-weight:900;letter-spacing:.09em;color:var(--mint2);font-size:14px}.brand-sub{display:block;margin-top:3px;color:var(--muted2);font-size:10px;letter-spacing:.13em;text-transform:uppercase}.top-status{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.top-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:rgba(7,19,15,.86);padding:7px 10px;border-radius:999px;color:var(--muted);font-size:10px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}.top-pill .dot{width:7px;height:7px;border-radius:50%;background:#53675f;box-shadow:0 0 0 3px rgba(83,103,95,.1)}.top-pill[data-tone=ok]{color:var(--mint2);border-color:#226b56}.top-pill[data-tone=ok] .dot{background:var(--mint);box-shadow:0 0 14px rgba(66,224,173,.65)}.global-clock{position:relative;min-width:238px;padding:9px 13px 8px;border:1px solid rgba(0,231,255,.36);border-radius:14px;background:linear-gradient(145deg,rgba(1,15,18,.97),rgba(5,8,22,.98));box-shadow:0 0 0 1px rgba(157,107,255,.08),0 0 24px rgba(0,231,255,.08),inset 0 0 24px rgba(0,231,255,.035);overflow:hidden}.global-clock:before{content:"";position:absolute;inset:-1px;background:linear-gradient(105deg,transparent 5%,rgba(0,231,255,.16) 34%,rgba(157,107,255,.14) 58%,transparent 88%);transform:translateX(-120%);animation:clockScan 5.2s ease-in-out infinite;pointer-events:none}.global-clock[data-synced=true]{border-color:rgba(66,224,173,.46);box-shadow:0 0 0 1px rgba(66,224,173,.08),0 0 28px rgba(0,231,255,.11),0 0 46px rgba(66,224,173,.055),inset 0 0 26px rgba(0,231,255,.045)}.clock-led-wrap{position:relative;z-index:1;display:flex;align-items:center;gap:9px}.clock-live-dot{width:8px;height:8px;border-radius:50%;background:#00f5d4;box-shadow:0 0 8px #00f5d4,0 0 18px rgba(0,245,212,.8);animation:clockPulse 1.2s ease-in-out infinite}.clock-led{font-family:"SFMono-Regular",Consolas,"Liberation Mono",ui-monospace,monospace;font-variant-numeric:tabular-nums;font-feature-settings:"tnum" 1,"zero" 1;color:#bafff4;font-size:20px;line-height:1;font-weight:950;letter-spacing:.105em;text-shadow:0 0 4px rgba(186,255,244,.95),0 0 11px rgba(0,231,255,.85),0 0 24px rgba(66,224,173,.58);filter:drop-shadow(0 0 8px rgba(0,231,255,.35));white-space:nowrap}.clock-zone{position:relative;z-index:1;margin:5px 0 4px 17px;color:#76dff0;font-size:8px;font-weight:850;letter-spacing:.08em;white-space:nowrap;text-shadow:0 0 10px rgba(0,231,255,.38)}.clock-meta{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:10px;border-top:1px solid rgba(0,231,255,.12);padding-top:5px}.clock-location,.clock-country{font-size:7px;font-weight:900;letter-spacing:.095em;white-space:nowrap}.clock-location{color:#e7fffb;text-shadow:0 0 9px rgba(66,224,173,.22)}.clock-country{color:#af9cff;text-align:right;text-shadow:0 0 9px rgba(157,107,255,.25)}@keyframes clockPulse{0%,100%{opacity:.58;transform:scale(.86)}50%{opacity:1;transform:scale(1.12)}}@keyframes clockScan{0%,65%{transform:translateX(-120%);opacity:0}75%{opacity:.7}100%{transform:translateX(130%);opacity:0}}.hero{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(320px,.55fr);gap:18px;border:1px solid var(--line);background:linear-gradient(135deg,rgba(7,24,19,.96),rgba(5,14,13,.96));border-radius:24px;padding:34px;box-shadow:var(--shadow);overflow:hidden;position:relative}.hero:after{content:"";position:absolute;right:-120px;top:-150px;width:360px;height:360px;border-radius:50%;border:1px solid rgba(66,224,173,.12);box-shadow:0 0 90px rgba(66,224,173,.05);pointer-events:none}.eyebrow{display:inline-flex;align-items:center;gap:8px;color:var(--mint2);font-size:11px;font-weight:900;letter-spacing:.16em;text-transform:uppercase}.eyebrow:before{content:"";width:24px;height:1px;background:var(--mint)}.hero h1{font-size:clamp(38px,5.4vw,72px);line-height:.98;letter-spacing:-.045em;margin:15px 0 16px;max-width:900px}.hero h1 span{display:block;color:var(--mint2)}.sub{color:#abc4bc;max-width:820px;line-height:1.7;font-size:15px;margin:0}.assurance{align-self:stretch;border:1px solid rgba(66,224,173,.15);background:rgba(3,11,9,.54);border-radius:18px;padding:18px;position:relative;z-index:1}.assurance-title{font-size:11px;font-weight:900;letter-spacing:.13em;text-transform:uppercase;color:var(--muted);margin-bottom:12px}.assurance-grid{display:grid;gap:9px}.assurance-item{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid #12382e;background:#06110e;border-radius:12px;padding:11px 12px}.assurance-item strong{display:block;font-size:12px}.assurance-item small{display:block;color:var(--muted2);font-size:10px;margin-top:3px}.assurance-state{font-size:10px;font-weight:900;letter-spacing:.08em;color:var(--muted);white-space:nowrap}.assurance-state[data-tone=ok]{color:var(--mint)}.launch{margin-top:18px;border:1px solid var(--line);background:rgba(6,17,14,.94);border-radius:20px;padding:22px}.section-kicker{font-size:10px;font-weight:900;letter-spacing:.14em;text-transform:uppercase;color:var(--mint)}.section-title{font-size:20px;margin:5px 0 3px}.section-copy{color:var(--muted);font-size:12px;line-height:1.5;margin:0}.launch-grid{display:grid;grid-template-columns:minmax(240px,1.2fr) minmax(200px,1fr) 135px minmax(170px,.7fr) 180px;gap:10px;margin-top:18px}.field{display:flex;flex-direction:column;gap:7px}.field label{font-size:10px;font-weight:800;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}.field input,.field select{height:48px;background:#04100d;color:var(--text);border:1px solid #28594d;border-radius:11px;padding:0 13px;outline:none;transition:.18s}.field input:focus,.field select:focus{border-color:var(--mint);box-shadow:0 0 0 3px rgba(66,224,173,.08)}.run{align-self:end;height:48px;background:linear-gradient(90deg,#34d6a3,#51e3b5);border:0;color:#02100b;font-weight:950;border-radius:11px;padding:0 18px;cursor:pointer;letter-spacing:.04em;box-shadow:0 8px 24px rgba(66,224,173,.14);transition:.18s}.run:hover{transform:translateY(-1px);box-shadow:0 10px 30px rgba(66,224,173,.22)}.run:disabled{opacity:.55;cursor:not-allowed;transform:none}.preflight-status{margin-top:12px;display:flex;align-items:flex-start;justify-content:space-between;gap:14px;border:1px solid #24493f;background:#06120f;border-radius:12px;padding:11px 13px}.preflight-status strong{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}.preflight-status span{font-size:10px;color:var(--muted2);text-align:right;line-height:1.45}.preflight-status[data-state=checking]{border-color:rgba(255,200,87,.55);box-shadow:inset 0 0 20px rgba(255,200,87,.04)}.preflight-status[data-state=checking] strong{color:var(--amber)}.preflight-status[data-state=verified]{border-color:rgba(66,224,173,.62);box-shadow:inset 0 0 20px rgba(66,224,173,.05)}.preflight-status[data-state=verified] strong{color:var(--mint2)}.preflight-status[data-state=denied]{border-color:rgba(255,114,114,.62);box-shadow:inset 0 0 20px rgba(255,114,114,.05)}.preflight-status[data-state=denied] strong{color:var(--red)}.security-note{display:flex;align-items:center;gap:8px;color:var(--muted2);font-size:11px;margin:12px 0 0}.security-note:before{content:"LOCK";font-size:8px;font-weight:900;letter-spacing:.08em;color:var(--mint);border:1px solid #245947;border-radius:999px;padding:3px 5px}.runtime-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:16px 0}.kpi{border:1px solid #153f34;background:linear-gradient(180deg,#081610,#06100d);border-radius:15px;padding:14px 15px;min-width:0}.kpi-label{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted2);font-weight:900}.kpi-value{font-size:14px;font-weight:850;margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.kpi-value[data-tone=ok]{color:var(--mint2)}.kpi-value[data-tone=warn]{color:var(--amber)}.mission-meta{display:grid;grid-template-columns:1.2fr 1.2fr .8fr .8fr .8fr .8fr;gap:10px;margin-bottom:20px}.meta-card{border:1px solid #143d32;background:#06110e;border-radius:14px;padding:13px 14px;min-width:0}.meta-card span{display:block;color:var(--muted2);font-size:9px;text-transform:uppercase;letter-spacing:.11em;font-weight:900}.meta-card strong{display:block;margin-top:6px;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.agent-section,.evidence-section,.history{margin-top:20px}.section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:12px}.section-head h2{margin:4px 0 0;font-size:20px}.section-head p{max-width:650px;margin:0;color:var(--muted);font-size:11px;line-height:1.5;text-align:right}.agents{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.agent{min-height:220px;background:linear-gradient(180deg,#07130f,#050e0c);border:1px solid #173b32;border-radius:17px;padding:15px;transition:.2s;overflow:hidden}.agent-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.agent-identity{display:flex;align-items:flex-start;gap:10px;min-width:0}.agent-index{flex:0 0 28px;width:28px;height:28px;display:grid;place-items:center;border:1px solid #1b4a3d;background:#091a15;border-radius:9px;color:var(--mint);font-size:9px;font-weight:900}.agent-title{min-width:0}.agent-title strong{display:block;font-size:13px;line-height:1.28;overflow-wrap:anywhere}.agent-title small{display:block;color:var(--muted2);font-size:10px;margin-top:4px}.state{flex:0 0 auto;font-size:9px;font-weight:900;letter-spacing:.06em;border:1px solid #28594d;border-radius:999px;padding:5px 7px;color:var(--muted)}.agent-meta-line{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 0 8px;margin-top:9px;border-top:1px solid #102c25;color:var(--muted2);font-size:9px;text-transform:uppercase;letter-spacing:.07em}.agent[data-state=QUEUED]{border-color:#315e52}.agent[data-state=RUNNING]{border-color:#91752f;box-shadow:inset 0 0 28px rgba(255,200,87,.035)}.agent[data-state=COMPLETED]{border-color:#248f6d;box-shadow:inset 0 0 30px rgba(66,224,173,.035)}.agent[data-state=DENIED],.agent[data-state=FAILED]{border-color:#7b3b3b}.agent[data-state=RUNNING] .state{color:var(--amber);border-color:#6a5827}.agent[data-state=COMPLETED] .state{color:var(--mint);border-color:#226b56}.agent[data-state=DENIED] .state,.agent[data-state=FAILED] .state{color:var(--red);border-color:#6b3737}.agent pre{white-space:pre-wrap;word-break:break-word;color:#91aba3;font-size:10px;line-height:1.45;max-height:110px;overflow:auto;margin:6px 0 0;padding:10px;background:#040b09;border:1px solid #102b24;border-radius:10px}.agent .narrative{margin:8px 0 0;font-size:11px;line-height:1.45;color:var(--text)}.agent .narrative .badge{display:inline-block;font-size:8px;font-weight:900;letter-spacing:.05em;border-radius:999px;padding:3px 7px;margin-bottom:6px;border:1px solid #28594d;color:var(--muted)}.agent .narrative .badge[data-kind=ai]{color:var(--mint);border-color:#37a47f}.agent .narrative .narrative-body{display:block}.evidence-grid{display:grid;grid-template-columns:.8fr 1.2fr;gap:12px}.panel{border:1px solid #173e33;background:#06110e;border-radius:17px;padding:16px;min-width:0}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}.panel-head strong{font-size:13px}.panel-badge{font-size:8px;font-weight:900;letter-spacing:.09em;color:var(--muted);border:1px solid #244f42;border-radius:999px;padding:5px 7px}.event-log{height:300px;overflow:auto;display:flex;flex-direction:column;gap:6px}.event-empty{color:var(--muted2);font-size:11px;padding:12px 4px}.event-row{display:grid;grid-template-columns:48px 82px 1fr;gap:8px;align-items:start;border-bottom:1px solid #102b24;padding:7px 3px;font-size:10px}.event-seq{color:var(--muted2);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.event-state{font-weight:900;color:var(--mint)}.event-desc{color:#a9bdb7;line-height:1.4;overflow-wrap:anywhere}.final{min-height:300px;max-height:300px;overflow:auto;margin:0;border:1px solid #102b24;background:#040b09;border-radius:12px;padding:14px;white-space:pre-wrap;word-break:break-word;color:#a9c0b8;font:10.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.history{border:1px solid var(--line);background:#06110e;border-radius:18px;padding:18px}.history h2{margin:0;font-size:18px}.history .row{display:flex;justify-content:space-between;align-items:center;gap:10px}.load,.dl{background:#071711;border:1px solid #28594d;color:#a8c5bb;border-radius:8px;padding:8px 11px;cursor:pointer;font:inherit;font-size:10px;font-weight:800}.load:hover,.dl:hover{border-color:var(--mint);color:var(--mint2)}.dl{padding:4px 7px}.history table{width:100%;border-collapse:collapse;font-size:11px;margin-top:12px}.history th{text-transform:uppercase;letter-spacing:.08em;color:var(--muted2);font-size:9px}.history th,.history td{text-align:left;padding:9px 8px;border-bottom:1px solid #123128}.truth{font-size:10.5px;color:var(--muted2);margin:10px 0 0}.footer{display:flex;justify-content:space-between;gap:18px;margin-top:18px;padding:0 2px;color:#536f66;font-size:9px;text-transform:uppercase;letter-spacing:.08em}.footer strong{color:#6f9589}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}@media(max-width:1120px){.hero{grid-template-columns:1fr}.agents{grid-template-columns:repeat(2,minmax(0,1fr))}.launch-grid{grid-template-columns:1fr 1fr}.run{align-self:end}.runtime-strip,.mission-meta{grid-template-columns:repeat(2,minmax(0,1fr))}.evidence-grid{grid-template-columns:1fr}}@media(max-width:700px){.wrap{padding:18px 14px 52px}.topbar,.section-head,.footer{align-items:flex-start;flex-direction:column}.top-status{justify-content:flex-start}.hero{padding:22px}.hero h1{font-size:38px}.launch-grid,.runtime-strip,.mission-meta,.agents{grid-template-columns:1fr}.section-head p{text-align:left}.event-log,.final{height:auto;max-height:360px}.history{overflow:auto}}

/* V4.46 ULTRA-HD SOC / CTI CYBERPUNK PRESENTATION LAYER */
:root{--cyan:#00e7ff;--violet:#9d6bff;--magenta:#ff4fd8;--electric:#5d7cff;--lime:#8dff5a;--orange:#ff9a4f;--deep:#02050a;--glass:rgba(5,15,22,.78);--glass2:rgba(7,22,29,.9)}
body{background:
radial-gradient(circle at 10% 0%,rgba(0,231,255,.12),transparent 26%),
radial-gradient(circle at 88% 8%,rgba(157,107,255,.14),transparent 28%),
radial-gradient(circle at 50% 82%,rgba(255,79,216,.07),transparent 34%),
linear-gradient(180deg,#02050a 0%,#03100f 52%,#02050a 100%)}
body:after{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:linear-gradient(180deg,transparent 0%,rgba(0,231,255,.025) 50%,transparent 100%);background-size:100% 7px;animation:scanDrift 8s linear infinite;opacity:.65}
.cyber-ambient{position:fixed;inset:0;pointer-events:none;z-index:0;overflow:hidden}
.cyber-orb{position:absolute;border-radius:50%;filter:blur(42px);opacity:.16;animation:orbFloat 12s ease-in-out infinite alternate}
.cyber-orb.one{width:260px;height:260px;background:var(--cyan);left:-90px;top:15%}.cyber-orb.two{width:320px;height:320px;background:var(--violet);right:-120px;top:6%;animation-delay:-4s}.cyber-orb.three{width:240px;height:240px;background:var(--magenta);left:38%;bottom:-120px;animation-delay:-7s}
.wrap{max-width:1480px}
.topbar{position:sticky;top:0;z-index:20;margin:0 -10px 18px;padding:12px 14px;background:linear-gradient(180deg,rgba(2,8,12,.94),rgba(2,8,12,.76));backdrop-filter:blur(18px);border:1px solid rgba(0,231,255,.12);border-radius:16px;box-shadow:0 18px 60px rgba(0,0,0,.28)}
.brand-mark{position:relative;width:44px;height:44px;border-color:rgba(0,231,255,.5);color:#fff;background:conic-gradient(from 120deg,rgba(0,231,255,.34),rgba(157,107,255,.18),rgba(255,79,216,.24),rgba(66,224,173,.3),rgba(0,231,255,.34));box-shadow:0 0 24px rgba(0,231,255,.22),inset 0 0 18px rgba(0,0,0,.55)}
.brand-mark:after{content:"";position:absolute;inset:4px;border:1px solid rgba(255,255,255,.14);border-radius:8px}
.brand{background:linear-gradient(90deg,#8bf7d2,#00e7ff,#9d6bff,#ff4fd8);background-size:220% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:spectrumShift 9s linear infinite}
.top-pill{background:rgba(3,13,18,.9);box-shadow:inset 0 0 22px rgba(0,231,255,.025)}
.hero,.launch,.history,.panel,.agent,.kpi,.meta-card{backdrop-filter:blur(14px)}
.hero{border-color:rgba(0,231,255,.26);background:linear-gradient(135deg,rgba(4,20,22,.94),rgba(8,8,22,.94) 54%,rgba(16,7,23,.92));box-shadow:0 25px 90px rgba(0,0,0,.42),0 0 50px rgba(0,231,255,.045)}
.hero:before{content:"";position:absolute;inset:0;padding:1px;border-radius:24px;background:linear-gradient(105deg,rgba(0,231,255,.7),transparent 28%,rgba(157,107,255,.55) 62%,rgba(255,79,216,.5));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none}
.hero h1{font-size:clamp(44px,6vw,82px);text-shadow:0 0 34px rgba(0,231,255,.12)}
.hero h1 span{background:linear-gradient(90deg,var(--cyan),var(--mint2),var(--violet),var(--magenta));background-size:220% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;animation:spectrumShift 8s linear infinite}
.soc-ribbon{display:flex;gap:8px;flex-wrap:wrap;margin-top:20px}.soc-chip{display:inline-flex;align-items:center;gap:7px;padding:7px 10px;border:1px solid rgba(0,231,255,.2);background:rgba(1,11,16,.7);border-radius:999px;font-size:9px;font-weight:900;letter-spacing:.1em;text-transform:uppercase;color:#9edee7}.soc-chip i{width:7px;height:7px;border-radius:50%;display:inline-block;background:var(--cyan);box-shadow:0 0 14px currentColor}.soc-chip:nth-child(2) i{background:var(--violet)}.soc-chip:nth-child(3) i{background:var(--magenta)}.soc-chip:nth-child(4) i{background:var(--mint)}
.assurance{border-color:rgba(157,107,255,.2);background:linear-gradient(180deg,rgba(6,16,22,.82),rgba(8,8,20,.76));box-shadow:inset 0 0 36px rgba(157,107,255,.035)}
.assurance-item{position:relative;overflow:hidden;border-color:rgba(0,231,255,.14);background:linear-gradient(90deg,rgba(4,17,20,.94),rgba(10,9,23,.88))}
.assurance-item:before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;background:linear-gradient(var(--cyan),var(--violet));box-shadow:0 0 14px var(--cyan)}
.assurance-state[data-tone=ok]{text-shadow:0 0 12px currentColor}
.led-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:16px 0 0}.led-cell{position:relative;overflow:hidden;min-height:62px;padding:10px 12px;border:1px solid rgba(0,231,255,.16);border-radius:12px;background:linear-gradient(180deg,rgba(3,13,19,.88),rgba(3,9,14,.96))}.led-cell:after{content:"";position:absolute;left:-40%;top:0;width:30%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.06),transparent);animation:ledSweep 4.5s linear infinite}.led-label{font-size:8px;text-transform:uppercase;letter-spacing:.13em;color:#607f8e;font-weight:900}.led-value{margin-top:5px;font:800 14px ui-monospace,SFMono-Regular,Menlo,monospace;color:#c8f8ff}.led-value.cyan{color:var(--cyan);text-shadow:0 0 14px rgba(0,231,255,.42)}.led-value.violet{color:#b9a2ff}.led-value.magenta{color:#ff8ce5}.led-value.mint{color:var(--mint2)}
.launch{position:relative;overflow:hidden;border-color:rgba(0,231,255,.22);background:linear-gradient(120deg,rgba(4,17,20,.94),rgba(7,11,24,.92))}
.launch:before{content:"";position:absolute;inset:0;background:linear-gradient(120deg,transparent 0%,rgba(0,231,255,.03) 40%,rgba(157,107,255,.035) 62%,transparent 100%);transform:translateX(-35%);animation:launchScan 8s ease-in-out infinite;pointer-events:none}
.field input,.field select{background:rgba(1,8,12,.9);border-color:rgba(0,231,255,.25);box-shadow:inset 0 0 20px rgba(0,231,255,.015)}
.field input:focus,.field select:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,231,255,.08),0 0 24px rgba(0,231,255,.08)}
.run{position:relative;overflow:hidden;background:linear-gradient(100deg,var(--mint),var(--cyan),#8c7dff,var(--magenta));background-size:260% 100%;animation:spectrumShift 6s linear infinite;box-shadow:0 0 30px rgba(0,231,255,.18),0 0 40px rgba(255,79,216,.08);color:#02060a}
.run:after{content:"";position:absolute;inset:1px;border-radius:10px;border:1px solid rgba(255,255,255,.2);pointer-events:none}
.runtime-strip{gap:12px}.kpi{position:relative;overflow:hidden;border-color:rgba(0,231,255,.16);background:linear-gradient(155deg,rgba(5,20,23,.94),rgba(7,9,21,.95))}.kpi:after{content:"";position:absolute;right:-28px;bottom:-38px;width:90px;height:90px;border:1px solid rgba(0,231,255,.08);border-radius:50%}
.kpi:nth-child(2){border-color:rgba(157,107,255,.2)}.kpi:nth-child(3){border-color:rgba(255,79,216,.18)}.kpi:nth-child(4){border-color:rgba(141,255,90,.17)}
.kpi-value[data-tone=ok]{text-shadow:0 0 12px currentColor}.meta-card{border-color:rgba(0,231,255,.13);background:linear-gradient(180deg,rgba(5,18,20,.92),rgba(4,10,15,.96))}
.mesh-fabric{margin:18px 0 0;border:1px solid rgba(0,231,255,.18);border-radius:20px;background:linear-gradient(135deg,rgba(2,14,18,.94),rgba(9,7,22,.94));padding:18px;position:relative;overflow:hidden}.mesh-fabric:before{content:"";position:absolute;inset:0;background-image:radial-gradient(circle,rgba(0,231,255,.12) 1px,transparent 1px);background-size:20px 20px;mask-image:linear-gradient(90deg,transparent,black 20%,black 80%,transparent);opacity:.5}.mesh-head{position:relative;z-index:1;display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:15px}.mesh-head strong{font-size:13px}.mesh-head span{font-size:9px;color:#6e93a0;letter-spacing:.09em;text-transform:uppercase}.mesh-core{position:relative;z-index:1;display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:10px;align-items:center}.mesh-node{position:relative;min-height:70px;display:grid;place-items:center;text-align:center;border:1px solid rgba(0,231,255,.16);background:rgba(3,13,18,.85);border-radius:14px;padding:9px 6px;color:#78959d;transition:.25s}.mesh-node:before{content:"";width:11px;height:11px;border-radius:50%;background:#41575e;box-shadow:0 0 0 5px rgba(65,87,94,.08);margin-bottom:5px}.mesh-node b{font-size:8px;letter-spacing:.06em}.mesh-node[data-state=QUEUED]{color:#a8c6ce;border-color:rgba(117,167,255,.35)}.mesh-node[data-state=QUEUED]:before{background:var(--blue);box-shadow:0 0 16px rgba(117,167,255,.6)}.mesh-node[data-state=RUNNING]{color:var(--amber);border-color:rgba(255,200,87,.48);box-shadow:0 0 22px rgba(255,200,87,.06)}.mesh-node[data-state=RUNNING]:before{background:var(--amber);box-shadow:0 0 22px rgba(255,200,87,.75);animation:ledPulse .9s ease-in-out infinite}.mesh-node[data-state=COMPLETED]{color:var(--mint2);border-color:rgba(66,224,173,.42)}.mesh-node[data-state=COMPLETED]:before{background:var(--mint);box-shadow:0 0 20px rgba(66,224,173,.75)}.mesh-node[data-state=DENIED],.mesh-node[data-state=FAILED]{color:#ff9b9b;border-color:rgba(255,114,114,.45)}.mesh-node[data-state=DENIED]:before,.mesh-node[data-state=FAILED]:before{background:var(--red);box-shadow:0 0 20px rgba(255,114,114,.75)}
.fabric-indicator{display:inline-flex;align-items:center;gap:8px}.fabric-led{width:9px;height:9px;border-radius:50%;background:#496067;box-shadow:0 0 0 4px rgba(73,96,103,.08)}.fabric-led[data-state=RUNNING]{background:var(--amber);box-shadow:0 0 18px rgba(255,200,87,.8);animation:ledPulse .9s ease-in-out infinite}.fabric-led[data-state=COMPLETED]{background:var(--mint);box-shadow:0 0 18px rgba(66,224,173,.75)}.fabric-led[data-state=FAILED]{background:var(--red);box-shadow:0 0 18px rgba(255,114,114,.78)}
.agent{position:relative;border-color:rgba(0,231,255,.13);background:linear-gradient(155deg,rgba(4,17,20,.96),rgba(7,8,18,.96));box-shadow:0 16px 40px rgba(0,0,0,.18)}.agent-spectrum{position:absolute;left:0;right:0;top:0;height:2px;background:linear-gradient(90deg,var(--cyan),var(--mint),var(--violet),var(--magenta));opacity:.28}.agent-led{width:8px;height:8px;border-radius:50%;margin-top:8px;background:#3f555b;box-shadow:0 0 0 4px rgba(63,85,91,.08);flex:0 0 auto}.agent[data-state=QUEUED] .agent-led{background:var(--blue);box-shadow:0 0 15px rgba(117,167,255,.65)}.agent[data-state=RUNNING] .agent-led{background:var(--amber);box-shadow:0 0 20px rgba(255,200,87,.85);animation:ledPulse .85s ease-in-out infinite}.agent[data-state=COMPLETED] .agent-led{background:var(--mint);box-shadow:0 0 18px rgba(66,224,173,.75)}.agent[data-state=DENIED] .agent-led,.agent[data-state=FAILED] .agent-led{background:var(--red);box-shadow:0 0 18px rgba(255,114,114,.75)}.agent[data-state=RUNNING]{transform:translateY(-2px);box-shadow:0 20px 50px rgba(255,200,87,.07),inset 0 0 32px rgba(255,200,87,.025)}.agent[data-state=COMPLETED]{box-shadow:0 18px 45px rgba(66,224,173,.045),inset 0 0 30px rgba(66,224,173,.025)}.agent-index{border-color:rgba(0,231,255,.26);background:linear-gradient(145deg,rgba(0,231,255,.08),rgba(157,107,255,.08));color:#c6f9ff}.panel{border-color:rgba(0,231,255,.13);background:linear-gradient(150deg,rgba(4,17,21,.96),rgba(8,8,18,.96))}.event-row{border-bottom-color:rgba(0,231,255,.08)}.event-row[data-state=RUNNING] .event-state{color:var(--amber)}.event-row[data-state=COMPLETED] .event-state{color:var(--mint)}.event-row[data-state=DENIED] .event-state,.event-row[data-state=FAILED] .event-state{color:var(--red)}.final{background:linear-gradient(180deg,#02070a,#030b0c);border-color:rgba(157,107,255,.16);box-shadow:inset 0 0 40px rgba(157,107,255,.025)}.history{border-color:rgba(157,107,255,.17);background:linear-gradient(145deg,rgba(4,16,19,.95),rgba(8,7,18,.95))}.load,.dl{border-color:rgba(0,231,255,.24);background:rgba(3,14,18,.9)}.load:hover,.dl:hover{border-color:var(--cyan);color:#d5fbff;box-shadow:0 0 18px rgba(0,231,255,.09)}
.control-note{margin-top:10px;color:#66858d;font-size:9px;letter-spacing:.04em}.control-note strong{color:#93b9c4}.footer{border-top:1px solid rgba(0,231,255,.08);padding-top:14px}
@keyframes scanDrift{to{background-position:0 140px}}@keyframes orbFloat{to{transform:translate3d(30px,-20px,0) scale(1.08)}}@keyframes spectrumShift{to{background-position:220% 0}}@keyframes ledSweep{to{left:130%}}@keyframes launchScan{0%,100%{transform:translateX(-45%)}50%{transform:translateX(45%)}}@keyframes ledPulse{0%,100%{opacity:.6;transform:scale(.9)}50%{opacity:1;transform:scale(1.12)}}

/* V4.46 CINEMATIC OPS — high-visibility enterprise presentation + decorative state FX */
html{-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;text-rendering:optimizeLegibility}
.cinematic-canvas{position:fixed;inset:0;width:100vw;height:100vh;pointer-events:none;z-index:80;mix-blend-mode:screen;opacity:.94}
.sub,.section-copy,.section-head p,.truth,.security-note,.control-note,.brand-sub,.assurance-item small,.agent-title small,.event-desc{color:#b8d0d6}
.sub{font-size:16px;line-height:1.76;text-shadow:0 1px 12px rgba(0,0,0,.72)}
.section-copy,.section-head p,.truth,.security-note{font-size:12px;line-height:1.62}
.section-kicker,.field label,.kpi-label,.meta-card span,.led-label,.assurance-title{color:#8ff7e0;text-shadow:0 0 14px rgba(66,224,173,.12)}
.section-title,.section-head h2,.history h2,.panel-head strong,.agent-title strong,.assurance-item strong{color:#f7fffd;text-shadow:0 2px 18px rgba(0,0,0,.72)}
.agent pre,.final{color:#d5e7e2;font-size:11px;line-height:1.56}
.event-empty{color:#93b2ba}.event-seq{color:#8bbac8}.footer{color:#78989f}.footer strong{color:#a7d7cb}
.hero,.launch,.mesh-fabric,.agent,.panel,.history,.kpi,.meta-card{box-shadow:0 22px 70px rgba(0,0,0,.30),inset 0 1px 0 rgba(255,255,255,.025)}
.hero,.launch,.mesh-fabric,.history,.panel{isolation:isolate}
.hero:after,.launch:after,.mesh-fabric:after,.history:after,.panel:after{content:"";position:absolute;inset:0;border-radius:inherit;padding:1px;background:linear-gradient(115deg,rgba(0,231,255,.38),transparent 28%,rgba(157,107,255,.26) 60%,rgba(255,79,216,.30));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;pointer-events:none;opacity:.52}
.panel,.history{position:relative;overflow:hidden}.panel:before,.history:before{content:"";position:absolute;inset:-45% auto auto -25%;width:55%;height:140%;background:linear-gradient(90deg,transparent,rgba(0,231,255,.035),transparent);transform:rotate(12deg);animation:panelSweep 10s ease-in-out infinite;pointer-events:none}
.field input,.field select{color:#f4ffff;font-weight:700}.field input::placeholder{color:#81929c;opacity:1}
.run{font-size:14px;letter-spacing:.055em;min-width:190px;outline:none}.run:focus-visible,.load:focus-visible,.dl:focus-visible,.field input:focus-visible,.field select:focus-visible{outline:2px solid #8bf7d2;outline-offset:3px}
.run.launching{animation:launchButtonIgnition .55s ease-in-out infinite alternate,spectrumShift 2.2s linear infinite;box-shadow:0 0 26px rgba(0,231,255,.75),0 0 60px rgba(157,107,255,.44),0 0 90px rgba(255,79,216,.25);transform:translateY(-2px) scale(1.015)}
body[data-launch-fx=active] .launch{animation:launchPanelStorm 1.7s cubic-bezier(.2,.8,.2,1);box-shadow:0 0 42px rgba(0,231,255,.26),0 0 90px rgba(157,107,255,.18),inset 0 0 70px rgba(255,154,79,.055)}
body[data-launch-fx=active] .launch:after{opacity:1;background:conic-gradient(from 180deg,rgba(255,154,79,.8),rgba(255,200,87,.45),rgba(0,231,255,.72),rgba(157,107,255,.7),rgba(255,79,216,.76),rgba(255,154,79,.8));animation:stormBorder 1.4s linear infinite}
body[data-launch-fx=active] .mesh-fabric{animation:meshCharge 1.65s ease-out}
body[data-launch-fx=active] .agent{box-shadow:0 0 22px rgba(0,231,255,.055),inset 0 0 26px rgba(157,107,255,.025)}
.cinematic-hint{display:flex;align-items:center;gap:8px;margin-top:11px;color:#90acb6;font-size:9px;font-weight:850;letter-spacing:.09em;text-transform:uppercase}.cinematic-hint:before{content:"";width:8px;height:8px;border-radius:50%;background:#ff9a4f;box-shadow:0 0 18px rgba(255,154,79,.75);animation:ledPulse 1.4s ease-in-out infinite}
.ops-spectrum{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.ops-spectrum span{border:1px solid rgba(0,231,255,.18);background:rgba(2,11,16,.78);border-radius:8px;padding:5px 8px;color:#a9d5dc;font-size:8px;font-weight:900;letter-spacing:.09em;text-transform:uppercase}.ops-spectrum span:nth-child(2){border-color:rgba(255,79,216,.24);color:#ffc4f1}.ops-spectrum span:nth-child(3){border-color:rgba(157,107,255,.25);color:#c8b8ff}.ops-spectrum span:nth-child(4){border-color:rgba(255,154,79,.24);color:#ffd3ad}
.back-platform{display:inline-flex;align-items:center;justify-content:center;gap:9px;min-height:44px;padding:0 15px;border:1px solid rgba(0,231,255,.42);border-radius:999px;background:linear-gradient(135deg,rgba(0,231,255,.10),rgba(157,107,255,.10));color:#dcffff;text-decoration:none;font-size:9px;font-weight:950;letter-spacing:.09em;text-transform:uppercase;white-space:nowrap;box-shadow:0 0 18px rgba(0,231,255,.08),inset 0 0 18px rgba(157,107,255,.025);transition:border-color .18s ease,box-shadow .18s ease,transform .18s ease,background .18s ease}.back-platform .back-arrow{font-size:15px;line-height:1;color:#8bf7d2;text-shadow:0 0 14px rgba(66,224,173,.58)}.back-platform:hover{border-color:#8bf7d2;background:linear-gradient(135deg,rgba(0,231,255,.16),rgba(157,107,255,.15));box-shadow:0 0 24px rgba(0,231,255,.16),0 0 30px rgba(157,107,255,.07);transform:translateY(-1px)}.back-platform:focus-visible{outline:2px solid #8bf7d2;outline-offset:3px}.back-platform:active{transform:translateY(0) scale(.985)}
@keyframes panelSweep{0%,100%{transform:translateX(-45%) rotate(12deg);opacity:.25}50%{transform:translateX(235%) rotate(12deg);opacity:.65}}
@keyframes launchButtonIgnition{from{filter:saturate(1.1) brightness(1)}to{filter:saturate(1.35) brightness(1.14)}}
@keyframes launchPanelStorm{0%{transform:translateZ(0) scale(1);filter:brightness(1)}28%{transform:translateZ(0) scale(1.003);filter:brightness(1.12)}62%{filter:brightness(1.04)}100%{transform:translateZ(0) scale(1);filter:brightness(1)}}
@keyframes stormBorder{to{filter:hue-rotate(360deg)}}
@keyframes meshCharge{0%{box-shadow:0 0 0 rgba(0,231,255,0)}45%{box-shadow:0 0 55px rgba(0,231,255,.18),inset 0 0 45px rgba(157,107,255,.05)}100%{box-shadow:0 0 0 rgba(0,231,255,0)}}

@media(max-width:1120px){.topbar{align-items:flex-start;flex-wrap:wrap}.top-status{width:100%;justify-content:flex-start}.global-clock{margin-left:auto}.mesh-core{grid-template-columns:repeat(4,minmax(0,1fr))}.led-strip{grid-template-columns:repeat(2,1fr)}}@media(max-width:700px){.mesh-core,.led-strip{grid-template-columns:repeat(2,minmax(0,1fr))}.topbar{position:relative;top:auto}.top-status{display:grid;grid-template-columns:1fr 1fr;width:100%}.back-platform{grid-column:1/-1;width:100%;min-height:48px;font-size:10px}.global-clock{grid-column:1/-1;width:100%;min-width:0;margin:0}.clock-led{font-size:24px}.clock-meta{gap:6px}.clock-location,.clock-country{font-size:7px}.hero h1{font-size:42px}}


/* V4.46.2 — PER-AGENT ULTRA-HD LED FABRIC + MOBILE/TABLET UX */
html,body{width:100%;max-width:100%;overflow-x:hidden}
.wrap{width:100%;min-width:0}
.mesh-fabric,.agent-section,.agents,.agent,.mesh-core,.mesh-node{min-width:0}

/* Every mesh node keeps a persistent individual identity color. */
.mesh-core{
  grid-template-columns:repeat(8,minmax(0,1fr));
  gap:12px;
  align-items:stretch;
}
.mesh-node{
  position:relative;
  min-height:108px;
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  gap:7px;
  padding:13px 8px 11px;
  overflow:hidden;
  isolation:isolate;
  color:#f6fffd;
  border:1px solid var(--agent-accent-ring);
  background:
    radial-gradient(circle at 50% 0%,var(--agent-accent-soft),transparent 58%),
    linear-gradient(155deg,rgba(3,16,22,.97),rgba(5,7,18,.98));
  box-shadow:
    0 0 18px var(--agent-accent-soft),
    inset 0 0 22px rgba(255,255,255,.018);
}
.mesh-node:before{
  content:"";
  position:absolute;
  inset:0;
  width:auto;
  height:auto;
  margin:0;
  border-radius:inherit;
  background:
    linear-gradient(115deg,var(--agent-accent-soft),transparent 34%,transparent 68%,var(--agent-accent-soft));
  box-shadow:none;
  opacity:.8;
  pointer-events:none;
  z-index:-1;
}
.mesh-node:after{
  content:"";
  position:absolute;
  left:15%;
  right:15%;
  bottom:0;
  height:2px;
  border-radius:999px;
  background:var(--agent-accent);
  box-shadow:
    0 0 8px var(--agent-accent),
    0 0 18px var(--agent-accent),
    0 0 28px var(--agent-accent-soft);
  opacity:.88;
}
.mesh-led{
  position:relative;
  z-index:1;
  width:14px;
  height:14px;
  flex:0 0 14px;
  border-radius:50%;
  background:var(--agent-accent);
  border:1px solid rgba(255,255,255,.72);
  box-shadow:
    0 0 7px var(--agent-accent),
    0 0 18px var(--agent-accent),
    0 0 34px var(--agent-accent);
  animation:agentIdentityPulse 2.1s ease-in-out infinite;
}
.mesh-code{
  position:relative;
  z-index:1;
  color:#f8ffff;
  font-size:9px;
  line-height:1.2;
  font-weight:950;
  letter-spacing:.09em;
  text-shadow:
    0 0 7px var(--agent-accent),
    0 0 14px var(--agent-accent-soft);
}
.mesh-agent-name{
  position:relative;
  z-index:1;
  display:block;
  max-width:100%;
  color:#a9c9d1;
  font-size:7px;
  line-height:1.25;
  font-weight:800;
  letter-spacing:.045em;
  text-align:center;
  overflow-wrap:anywhere;
}

/* State remains backend-truth driven; identity color remains visible. */
.mesh-node[data-state=QUEUED]{
  border-color:rgba(117,167,255,.78);
  box-shadow:0 0 26px var(--agent-accent-soft),inset 0 0 25px rgba(117,167,255,.045);
}
.mesh-node[data-state=QUEUED]:before{
  background:linear-gradient(145deg,var(--agent-accent-soft),rgba(117,167,255,.08),transparent);
  box-shadow:none;
}
.mesh-node[data-state=QUEUED] .mesh-led{
  background:#75A7FF;
  box-shadow:0 0 8px #75A7FF,0 0 22px #75A7FF,0 0 36px rgba(117,167,255,.72);
}
.mesh-node[data-state=RUNNING]{
  border-color:rgba(255,200,87,.84);
  box-shadow:0 0 28px var(--agent-accent-soft),0 0 26px rgba(255,200,87,.12),inset 0 0 28px rgba(255,200,87,.055);
}
.mesh-node[data-state=RUNNING]:before{
  background:linear-gradient(145deg,var(--agent-accent-soft),rgba(255,200,87,.09),transparent);
  box-shadow:none;
  animation:none;
}
.mesh-node[data-state=RUNNING] .mesh-led{
  background:#FFC857;
  box-shadow:0 0 9px #FFC857,0 0 24px #FFC857,0 0 42px rgba(255,200,87,.82);
  animation:stateLedPulse .75s ease-in-out infinite;
}
.mesh-node[data-state=COMPLETED]{
  border-color:rgba(66,224,173,.88);
  box-shadow:0 0 28px var(--agent-accent-soft),0 0 26px rgba(66,224,173,.11),inset 0 0 30px rgba(66,224,173,.055);
}
.mesh-node[data-state=COMPLETED]:before{
  background:linear-gradient(145deg,var(--agent-accent-soft),rgba(66,224,173,.08),transparent);
  box-shadow:none;
}
.mesh-node[data-state=COMPLETED] .mesh-led{
  background:#42E0AD;
  box-shadow:0 0 9px #42E0AD,0 0 24px #42E0AD,0 0 42px rgba(66,224,173,.78);
}
.mesh-node[data-state=DENIED],
.mesh-node[data-state=FAILED]{
  border-color:rgba(255,114,114,.88);
  box-shadow:0 0 28px var(--agent-accent-soft),0 0 28px rgba(255,114,114,.12),inset 0 0 28px rgba(255,114,114,.055);
}
.mesh-node[data-state=DENIED]:before,
.mesh-node[data-state=FAILED]:before{
  background:linear-gradient(145deg,var(--agent-accent-soft),rgba(255,114,114,.09),transparent);
  box-shadow:none;
}
.mesh-node[data-state=DENIED] .mesh-led,
.mesh-node[data-state=FAILED] .mesh-led{
  background:#FF7272;
  box-shadow:0 0 9px #FF7272,0 0 24px #FF7272,0 0 42px rgba(255,114,114,.82);
}

/* Real Backend Execution: each card receives its own accent identity. */
.agents{
  grid-template-columns:repeat(4,minmax(0,1fr));
  gap:14px;
}
.agent{
  min-height:244px;
  border:1px solid var(--agent-accent-ring);
  background:
    radial-gradient(circle at 92% 2%,var(--agent-accent-soft),transparent 42%),
    linear-gradient(155deg,rgba(3,16,22,.98),rgba(7,8,19,.985));
  box-shadow:
    0 16px 42px rgba(0,0,0,.24),
    0 0 20px var(--agent-accent-soft),
    inset 0 1px 0 rgba(255,255,255,.025);
}
.agent-spectrum{
  height:3px;
  opacity:1;
  background:
    linear-gradient(90deg,transparent,var(--agent-accent) 18%,var(--agent-accent) 82%,transparent);
  box-shadow:0 0 16px var(--agent-accent);
}
.agent-led{
  width:10px;
  height:10px;
  flex:0 0 10px;
  margin-top:7px;
  background:var(--agent-accent);
  border:1px solid rgba(255,255,255,.7);
  box-shadow:
    0 0 7px var(--agent-accent),
    0 0 17px var(--agent-accent),
    0 0 30px var(--agent-accent-soft);
  animation:agentIdentityPulse 2.1s ease-in-out infinite;
}
.agent-index{
  border-color:var(--agent-accent-ring);
  background:
    linear-gradient(145deg,var(--agent-accent-soft),rgba(255,255,255,.025));
  color:#fff;
  box-shadow:0 0 14px var(--agent-accent-soft);
}
.agent-title strong{
  color:#faffff;
  font-size:14px;
  text-shadow:0 0 13px rgba(255,255,255,.08);
}
.agent-title small{
  color:#a9c7cf;
  font-size:10px;
}
.agent .state{
  border-color:var(--agent-accent-ring);
  background:rgba(2,11,15,.76);
  color:#d9f3f4;
  box-shadow:0 0 12px var(--agent-accent-soft);
}
.agent-meta-line{
  border-color:rgba(255,255,255,.085);
  color:#91b1b8;
}
.agent pre{
  color:#e1f1ef;
  border-color:var(--agent-accent-ring);
  background:rgba(2,10,13,.82);
  box-shadow:inset 0 0 18px rgba(0,0,0,.26);
  font-size:11px;
}

/* Backend state overrides LED/status, but panel identity stays unique. */
.agent[data-state=QUEUED]{
  border-color:rgba(117,167,255,.78);
  box-shadow:0 18px 46px rgba(0,0,0,.25),0 0 24px var(--agent-accent-soft),inset 0 0 28px rgba(117,167,255,.04);
}
.agent[data-state=QUEUED] .agent-led{
  background:#75A7FF;
  box-shadow:0 0 8px #75A7FF,0 0 22px #75A7FF,0 0 34px rgba(117,167,255,.75);
}
.agent[data-state=RUNNING]{
  border-color:rgba(255,200,87,.85);
  box-shadow:0 20px 52px rgba(0,0,0,.28),0 0 26px var(--agent-accent-soft),0 0 30px rgba(255,200,87,.08),inset 0 0 34px rgba(255,200,87,.04);
}
.agent[data-state=RUNNING] .agent-led{
  background:#FFC857;
  box-shadow:0 0 9px #FFC857,0 0 24px #FFC857,0 0 42px rgba(255,200,87,.82);
}
.agent[data-state=COMPLETED]{
  border-color:rgba(66,224,173,.85);
  box-shadow:0 18px 48px rgba(0,0,0,.26),0 0 25px var(--agent-accent-soft),0 0 28px rgba(66,224,173,.08),inset 0 0 32px rgba(66,224,173,.04);
}
.agent[data-state=COMPLETED] .agent-led{
  background:#42E0AD;
  box-shadow:0 0 9px #42E0AD,0 0 24px #42E0AD,0 0 40px rgba(66,224,173,.78);
}
.agent[data-state=DENIED],
.agent[data-state=FAILED]{
  border-color:rgba(255,114,114,.86);
  box-shadow:0 18px 48px rgba(0,0,0,.26),0 0 25px var(--agent-accent-soft),0 0 28px rgba(255,114,114,.09),inset 0 0 32px rgba(255,114,114,.04);
}
.agent[data-state=DENIED] .agent-led,
.agent[data-state=FAILED] .agent-led{
  background:#FF7272;
  box-shadow:0 0 9px #FF7272,0 0 24px #FF7272,0 0 40px rgba(255,114,114,.8);
}

@keyframes agentIdentityPulse{
  0%,100%{opacity:.76;transform:scale(.92)}
  50%{opacity:1;transform:scale(1.08)}
}
@keyframes stateLedPulse{
  0%,100%{opacity:.64;transform:scale(.88)}
  50%{opacity:1;transform:scale(1.14)}
}

/* Tablet landscape / compact desktop. */
@media(max-width:1180px){
  .mesh-core{grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
  .agents{grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}
  .mesh-node{min-height:104px}
}

/* Tablet portrait. */
@media(max-width:860px){
  .wrap{padding-left:16px;padding-right:16px}
  .mesh-core{grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
  .mesh-node{padding:12px 6px}
  .mesh-agent-name{font-size:6.8px}
  .agents{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
  .agent{min-height:230px}
  .section-head{align-items:flex-start}
  .section-head p{max-width:100%}
}

/* Smartphone. */
@media(max-width:700px){
  .wrap{padding-left:max(12px,env(safe-area-inset-left));padding-right:max(12px,env(safe-area-inset-right))}
  .mesh-fabric{padding:14px 12px}
  .mesh-head{align-items:flex-start;flex-direction:column;gap:7px}
  .mesh-head span{font-size:8px;line-height:1.4}
  .mesh-core{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .mesh-node{min-height:102px;padding:12px 8px}
  .mesh-led{width:13px;height:13px;flex-basis:13px}
  .mesh-code{font-size:9px}
  .mesh-agent-name{font-size:7px}
  .agents{grid-template-columns:1fr;gap:12px}
  .agent{min-height:0;padding:14px;border-radius:16px}
  .agent-head{gap:8px}
  .agent-identity{gap:9px}
  .agent-title strong{font-size:15px}
  .agent-title small{font-size:11px}
  .agent .state{font-size:10px;padding:6px 9px}
  .agent pre{max-height:190px;font-size:12px;line-height:1.55;padding:12px}
  .agent-meta-line{font-size:10px}
  .section-head h2{font-size:22px}
  button,.run,.load,.dl,input,select{min-height:44px}
}

/* Narrow smartphone. */
@media(max-width:480px){
  .mesh-core{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
  .mesh-node{min-height:96px;padding:10px 6px}
  .mesh-agent-name{font-size:6.5px}
  .agent{padding:13px}
  .agent-title strong{font-size:14px}
  .agent-title small{font-size:10px}
  .agent-index{width:32px;height:32px;flex-basis:32px}
  .agent .state{font-size:9px}
  .agent pre{font-size:11.5px}
}

.agent[data-state=SKIPPED]{border-color:rgba(117,167,255,.46);box-shadow:0 12px 34px rgba(0,0,0,.22),0 0 18px rgba(117,167,255,.06);opacity:.88}.agent[data-state=SKIPPED] .state{color:#9fc6ff;border-color:rgba(117,167,255,.42)}.agent[data-state=SKIPPED] .agent-led{background:#75A7FF;box-shadow:0 0 12px rgba(117,167,255,.58)}.mesh-node[data-state=SKIPPED]{color:#9fc6ff;border-color:rgba(117,167,255,.38)}.mesh-node[data-state=SKIPPED] .mesh-led{background:#75A7FF;box-shadow:0 0 12px rgba(117,167,255,.58)}.event-row[data-state=SKIPPED] .event-state{color:#9fc6ff}
@media(prefers-contrast:more){:root{--text:#fff;--muted:#d4e7e3;--muted2:#acc8c1}.sub,.section-copy,.section-head p,.truth,.security-note,.control-note,.brand-sub,.assurance-item small,.agent-title small,.event-desc{color:#e2f2ef}.agent pre,.final{color:#f2fffc}.field input,.field select{border-color:#67d8c3}}

/* V4.47 Mission Readiness / Semantic State / Executive View */
.view-toggle,.readiness-btn{border:1px solid rgba(0,231,255,.34);background:rgba(2,14,20,.92);color:#aef9ef;border-radius:999px;padding:8px 11px;font-size:9px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;cursor:pointer;white-space:nowrap}.view-toggle:hover,.readiness-btn:hover:not(:disabled){border-color:var(--cyan);box-shadow:0 0 20px rgba(0,231,255,.12)}.view-toggle[aria-pressed=true]{color:#fff;border-color:rgba(157,107,255,.65);background:rgba(41,21,68,.72);box-shadow:0 0 22px rgba(157,107,255,.14)}.readiness-btn:disabled{opacity:.45;cursor:not-allowed}
.readiness-panel{margin-top:12px;border:1px solid rgba(0,231,255,.18);background:linear-gradient(145deg,rgba(3,17,20,.9),rgba(7,9,21,.88));border-radius:14px;padding:13px}.readiness-panel[data-state=ready]{border-color:rgba(66,224,173,.55);box-shadow:inset 0 0 24px rgba(66,224,173,.035)}.readiness-panel[data-state=limited]{border-color:rgba(255,200,87,.6)}.readiness-panel[data-state=blocked]{border-color:rgba(255,114,114,.6)}.readiness-head{display:flex;align-items:center;justify-content:space-between;gap:14px}.readiness-head>div{min-width:0}.readiness-head strong{display:block;font-size:10px;letter-spacing:.1em;color:#8bf7d2}.readiness-head span{display:block;margin-top:4px;color:var(--muted2);font-size:9px;line-height:1.45}.readiness-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:10px}.readiness-grid>div{border:1px solid rgba(255,255,255,.07);background:rgba(2,10,14,.7);border-radius:10px;padding:9px}.readiness-grid span{display:block;color:var(--muted2);font-size:8px;text-transform:uppercase;letter-spacing:.08em}.readiness-grid strong{display:block;margin-top:5px;font-size:11px;color:#e8fbf8}.readiness-agents{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}.readiness-chip{display:inline-flex;align-items:center;gap:5px;border:1px solid rgba(255,255,255,.09);border-radius:999px;padding:5px 7px;font-size:8px;font-weight:850;letter-spacing:.04em}.readiness-chip[data-state=READY]{color:var(--mint2);border-color:rgba(66,224,173,.36)}.readiness-chip[data-state=NOT_APPLICABLE]{color:#8fa7ad}.readiness-chip[data-state=DEGRADED]{color:var(--amber);border-color:rgba(255,200,87,.35)}
.agent[data-state=NOT_APPLICABLE],.mesh-node[data-state=NOT_APPLICABLE]{border-color:rgba(130,154,162,.36);filter:saturate(.58)}.agent[data-state=NOT_APPLICABLE] .state{color:#9fb2b8;border-color:rgba(159,178,184,.35)}.agent[data-state=NOT_APPLICABLE] .agent-led,.mesh-node[data-state=NOT_APPLICABLE] .mesh-led{background:#7f979e;box-shadow:0 0 10px rgba(127,151,158,.4)}
.agent[data-state=DEGRADED],.mesh-node[data-state=DEGRADED]{border-color:rgba(255,200,87,.7)}.agent[data-state=DEGRADED] .state{color:var(--amber);border-color:rgba(255,200,87,.45)}.agent[data-state=DEGRADED] .agent-led,.mesh-node[data-state=DEGRADED] .mesh-led{background:#ffc857;box-shadow:0 0 10px #ffc857,0 0 25px rgba(255,200,87,.55)}
.agent[data-state=UNAVAILABLE],.mesh-node[data-state=UNAVAILABLE]{border-color:rgba(255,154,79,.65)}.agent[data-state=UNAVAILABLE] .state{color:#ffb67f;border-color:rgba(255,154,79,.4)}.agent[data-state=UNAVAILABLE] .agent-led,.mesh-node[data-state=UNAVAILABLE] .mesh-led{background:#ff9a4f;box-shadow:0 0 10px #ff9a4f,0 0 25px rgba(255,154,79,.5)}
body[data-view=executive] .history,body[data-view=executive] .event-log{display:none}body[data-view=executive] .evidence-grid{grid-template-columns:1fr}body[data-view=executive] .final{max-height:300px}body[data-view=executive] .agent{min-height:180px}body[data-view=executive] .agent pre{max-height:76px}.agent[data-focus=true]{outline:2px solid var(--agent-accent);outline-offset:3px;box-shadow:0 0 38px var(--agent-accent-soft),0 20px 55px rgba(0,0,0,.32)}
@media(max-width:700px){.readiness-head{align-items:stretch;flex-direction:column}.readiness-btn{width:100%;border-radius:10px;height:42px}.readiness-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.mission-meta{grid-template-columns:1fr 1fr}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.001ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}.global-clock:before{display:none}.clock-live-dot{opacity:1;transform:none}}
</style></head><body>
<div class="cyber-ambient" aria-hidden="true"><span class="cyber-orb one"></span><span class="cyber-orb two"></span><span class="cyber-orb three"></span></div>
<canvas id="cinematicCanvas" class="cinematic-canvas" aria-hidden="true"></canvas>
<main class="wrap" id="missionShell">
  <header class="topbar">
    <div class="brand-block"><div class="brand-mark">CDB</div><div><div class="brand">CYBERDUDEBIVASH® SENTINEL APEX™</div><span class="brand-sub">Autonomous Cyber Intelligence Control Plane</span></div></div>
    <div class="top-status"><button type="button" class="view-toggle" id="viewMode" aria-pressed="false">EXECUTIVE VIEW</button><a class="back-platform" id="backToPlatform" href="/" aria-label="Back to CYBERDUDEBIVASH Sentinel APEX platform"><span class="back-arrow" aria-hidden="true">←</span><span>BACK TO PLATFORM</span></a><span class="top-pill" id="runtimePill"><span class="dot"></span><span id="runtimeState" aria-live="polite">CHECKING RUNTIME</span></span><span class="top-pill"><span class="dot"></span>V4.47.0 PRODUCTION</span><section class="global-clock" id="globalClock" data-synced="fallback" aria-label="Current customer location time"><div class="clock-led-wrap"><span class="clock-live-dot" aria-hidden="true"></span><time class="clock-led" id="clockTime" datetime="${initialNow.toISOString()}" aria-live="off">${initialUtcTime}</time></div><div class="clock-zone mono" id="clockZone">UTC · EDGE SYNC</div><div class="clock-meta"><span class="clock-location" id="clockLocation">GLOBAL EDGE · RESOLVING</span><span class="clock-country" id="clockCountry">UTC · ${initialUtcDate}</span></div></section></div>
  </header>

  <section class="hero">
    <div>
      <div class="eyebrow">Production CTI Orchestration</div>
      <h1>SUPER AGENT SWARM <span>LIVE OPERATIONS</span></h1>
      <p class="sub">Execute a real Sentinel correlation mission across eight backend agents. Every visible state is emitted by production execution against the canonical intelligence platform. Admission and final completion are governed by the private APEX mesh — no simulated progress, random percentages, or hard-coded findings.</p>
      <div class="soc-ribbon" aria-label="Control plane capabilities"><span class="soc-chip"><i></i>SOC 2-ALIGNED EVIDENCE UX</span><span class="soc-chip"><i></i>LIVE CTI</span><span class="soc-chip"><i></i>PRIVATE MESH</span><span class="soc-chip"><i></i>STIX 2.1</span><span class="soc-chip"><i></i>RED TEAM INTEL</span><span class="soc-chip"><i></i>AI SECURITY OPS</span></div>
    </div>
    <aside class="assurance">
      <div class="assurance-title">Production Assurance</div>
      <div class="assurance-grid">
        <div class="assurance-item"><div><strong>Private APEX Mesh</strong><small>Canonical mission admission</small></div><span class="assurance-state" id="gatewayState">CHECKING</span></div>
        <div class="assurance-item"><div><strong>Durable Evidence</strong><small>Mission history + read-back</small></div><span class="assurance-state" id="persistenceState">CHECKING</span></div>
        <div class="assurance-item"><div><strong>Retry Safety</strong><small>Idempotent request protection</small></div><span class="assurance-state" id="retryState">CHECKING</span></div>
        <div class="assurance-item"><div><strong>Evidence Portability</strong><small>JSON · Markdown · STIX 2.1</small></div><span class="assurance-state" id="exportState">CHECKING</span></div>
      </div>
    </aside>
  </section>

  <section class="led-strip" aria-label="Live control-plane telemetry">
    <div class="led-cell"><div class="led-label">Event Sequence</div><div class="led-value cyan" id="eventCount">00</div></div>
    <div class="led-cell"><div class="led-label">Active Agents</div><div class="led-value violet" id="activeAgents">00</div></div>
    <div class="led-cell"><div class="led-label">Completed Agents</div><div class="led-value mint" id="completedAgents">00</div></div>
    <div class="led-cell"><div class="led-label">Fabric State</div><div class="led-value magenta"><span class="fabric-indicator"><i class="fabric-led" id="fabricLed" data-state="IDLE"></i><span id="fabricStateText">DORMANT</span></span></div></div>
  </section>

  <section class="launch">
    <div class="section-kicker">Mission Control</div>
    <h2 class="section-title">Launch a live CTI mission</h2>
    <p class="section-copy">Use an existing paid Sentinel API key. The credential stays in browser memory only and is never written to cookies or localStorage.</p>
    <div class="launch-grid">
      <div class="field"><label for="key">Sentinel API Key</label><input id="key" type="password" autocomplete="off" spellcheck="false" placeholder="ENTERPRISE / PRO / MSSP API key"></div>
      <div class="field"><label for="ioc">Observable / IOC</label><input id="ioc" value="8.8.8.8" aria-label="IOC" spellcheck="false"></div>
      <div class="field"><label for="type">IOC Type</label><select id="type"><option value="ipv4">IPv4</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">Hash</option><option value="auto">Auto detect</option></select></div>
      <div class="field"><label for="profile">Mission Profile</label><select id="profile"><option value="AUTO">Auto / Full Fabric</option><option value="FULL_CTI_FABRIC">Full CTI Fabric</option><option value="IOC_TRIAGE">IOC Triage</option><option value="CVE_RESPONSE">CVE Response</option><option value="THREAT_ACTOR_INVESTIGATION">Threat Actor Investigation</option><option value="SOC_DETECTION_ENGINEERING">SOC Detection Engineering</option><option value="INCIDENT_RESPONSE">Incident Response</option><option value="EXPOSURE_ASSESSMENT">Exposure Assessment</option><option value="EXECUTIVE_RISK">Executive Risk</option></select></div>
      <button type="button" class="run" id="run" disabled>RUN LIVE SWARM</button>
    </div>
    <div class="preflight-status" id="preflightStatus" data-state="unverified" role="status" aria-live="polite"><strong id="preflightState">ACCESS NOT VERIFIED</strong><span id="preflightDetail">Paste a paid Sentinel credential or finish entry and leave the field to verify entitlement before launch.</span></div>
    <section class="readiness-panel" id="readinessPanel" data-state="idle" aria-label="Mission readiness">
      <div class="readiness-head"><div><strong>MISSION READINESS</strong><span id="readinessSummary">Not assessed. Optional assessment consumes one canonical correlation request and dispatches zero SWARM missions.</span></div><button type="button" class="readiness-btn" id="assessReadiness" disabled>ASSESS READINESS</button></div>
      <div class="readiness-grid">
        <div><span>Projected Quality</span><strong id="readinessQuality">NOT ASSESSED</strong></div>
        <div><span>Agent Readiness</span><strong id="readinessAgents">— / 8</strong></div>
        <div><span>AI Synthesis</span><strong id="readinessAi">NOT ASSESSED</strong></div>
        <div><span>Evidence Matches</span><strong id="readinessMatches">—</strong></div>
      </div>
      <div class="readiness-agents" id="readinessAgentsDetail" aria-live="polite"></div>
    </section>
    <p class="security-note">Credential storage: none. Mission execution is accepted only through production auth, entitlement and private-mesh controls.</p>
    <div class="cinematic-hint">Cinematic launch visualization is decorative only; backend events remain the sole source of mission truth.</div>
    <div class="ops-spectrum" aria-label="Operational domains"><span>SOC / CTI</span><span>AI SECURITY</span><span>RED TEAM INTELLIGENCE</span><span>CYBER DEFENSE</span></div>
  </section>

  <section class="runtime-strip" aria-label="Production runtime status">
    <div class="kpi"><div class="kpi-label">Runtime</div><div class="kpi-value" id="runtimeKpi">CHECKING</div></div>
    <div class="kpi"><div class="kpi-label">Protocol</div><div class="kpi-value mono" id="protocol">cdb.swarm.v1</div></div>
    <div class="kpi"><div class="kpi-label">Agent Fleet</div><div class="kpi-value" id="agentCount">8 AGENTS</div></div>
    <div class="kpi"><div class="kpi-label">Mission State</div><div class="kpi-value" id="missionState" aria-live="polite">READY</div></div>
  </section>

  <section class="mesh-fabric" aria-label="Live private mesh topology">
    <div class="mesh-head"><div><div class="section-kicker">Private Execution Fabric</div><strong>8-Agent Mesh Topology</strong></div><span>STATE-DRIVEN LED NODES · NO SIMULATED TELEMETRY</span></div>
    <div class="mesh-core">${meshNodes}</div>
  </section>

  <section class="mission-meta">
    <div class="meta-card"><span>Mission ID</span><strong class="mono" id="mission">—</strong></div>
    <div class="meta-card"><span>Correlation ID</span><strong class="mono" id="correlation">—</strong></div>
    <div class="meta-card"><span>Mesh Certification</span><strong id="mesh">PENDING</strong></div>
    <div class="meta-card"><span>Evidence Store</span><strong id="evidenceStore">CHECKING</strong></div>
    <div class="meta-card"><span>Mission Quality</span><strong id="missionQuality">NOT ASSESSED</strong></div>
    <div class="meta-card"><span>Evidence Graph</span><strong id="evidenceGraphState">PENDING</strong></div>
  </section>

  <section class="agent-section">
    <div class="section-head"><div><div class="section-kicker">Real Backend Execution</div><h2>8-Agent Operations Grid</h2></div><p>Each card transitions only when its corresponding backend agent emits a real mission event. No client-side timer drives agent state.</p></div>
    <section class="agents">${agents}</section>
  </section>

  <section class="evidence-section">
    <div class="section-head"><div><div class="section-kicker">Mission Evidence</div><h2>Live event stream & fused intelligence</h2></div><p>Sequence, state and timestamps are read directly from the production SSE stream; final evidence is persisted after mission completion.</p></div>
    <div class="evidence-grid">
      <div class="panel"><div class="panel-head"><strong>Live Mission Events</strong><span class="panel-badge" id="streamState">SSE · DORMANT</span></div><div class="event-log" id="eventLog"><div class="event-empty">No active mission. Stream opens only after authenticated launch.</div></div></div>
      <div class="panel"><div class="panel-head"><strong>Final Intelligence / Terminal Evidence</strong><span class="panel-badge" id="finalBadge">AWAITING MISSION</span></div><pre class="final" id="final">Awaiting a live mission.</pre></div>
    </div>
  </section>

  <section class="history">
    <div class="row"><div><div class="section-kicker">Durable Evidence</div><h2>Mission History & Evidence Export</h2></div><button type="button" class="load" id="loadHistory">LOAD HISTORY</button></div>
    <p class="truth" id="historyNote">Loads only missions scoped to the API key above. Completed missions can be exported as report, JSON evidence, or STIX 2.1.</p>
    <div id="historyBody"></div>
  </section>

  <div class="control-note"><strong>Control/evidence presentation:</strong> SOC 2-aligned operational UX for auditability, traceability, and evidence visibility. This interface does not claim independent SOC 2 certification.</div>
  <footer class="footer"><span>CYBERDUDEBIVASH® SENTINEL APEX™ · SUPER AGENT SWARM</span><span><strong>Production truth model:</strong> backend events only · no simulated telemetry</span></footer>
</main>
<script src="/swarm/app.js" defer></script></body></html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && url.pathname === '/swarm/app.js') {
      return new Response(swarmAppJs(), {
        headers: {
          'content-type': 'text/javascript; charset=utf-8',
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
        },
      });
    }
    if (request.method === 'GET' && (url.pathname === '/swarm' || url.pathname === '/swarm/')) {
      return new Response(ui(), {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
        },
      });
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/client-context') {
      const cf = request.cf || {};
      const clean = (value, max = 96) => typeof value === 'string' ? value.trim().slice(0, max) : '';
      const countryCode = clean(cf.country, 2).toUpperCase();
      return json({
        status: 'ok',
        data: {
          city: clean(cf.city),
          region: clean(cf.region),
          country_code: countryCode,
          country_name: '',
          timezone: clean(cf.timezone) || 'UTC',
          source: (cf.city || cf.country || cf.timezone) ? 'cloudflare_edge' : 'browser_fallback',
        },
      }, 200, {
        'cache-control': 'private, no-store',
        'x-content-type-options': 'nosniff',
      });
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/health') {
      return json({
        status: 'ok',
        service: 'sentinel-apex-swarm-live',
        protocol: PROTOCOL,
        version: env.SWARM_VERSION || '4.46.6',
        agents: AGENTS.length,
        // Real dependency status, not a static ack -- reflects whether
        // mission history/evidence export can actually serve a request
        // right now (see wrangler.toml for why this may be false today).
        persistence: { kv_bound: Boolean(env.SWARM_MISSIONS_KV) },
        production: {
          canonical_gateway_bound: Boolean(env.CANONICAL_GATEWAY),
          private_mesh_required: true,
          customer_console: true,
        },
        // What this deployment can actually do, not usage numbers: per-
        // mission timing/idempotency/export metrics live on the mission
        // record itself (GET /api/swarm/mission/:id, .../report) where
        // they have request context -- aggregating them here would mean
        // either a KV scan on every health check (this platform's own
        // performance baseline treats a health/cached endpoint as a fast
        // path) or fabricated numbers, and this codebase's whole reason
        // for existing is refusing exactly that trade.
        capabilities: {
          mission_history: true,
          idempotent_retry: true,
          report_formats: ['md', 'json', 'stix21'],
          agent_timing: true,
          entitlement_preflight: true,
          mission_readiness: true,
          mission_quality: true,
          evidence_graph: true,
          adaptive_specialists: true,
          agent_semantics_v2: true,
          credential_scoped_metrics: true,
          mission_profiles: true,
        },
        mission_profiles: listMissionProfiles(),
      });
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/preflight') {
      return handlePreflight(request, env);
    }
    if (request.method === 'POST' && url.pathname === '/api/swarm/readiness') {
      return handleMissionReadiness(request, env);
    }
    if (request.method === 'POST' && url.pathname === '/api/swarm/run') {
      return handleRun(request, env, ctx);
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/missions') {
      return handleMissionList(request, env, url);
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/metrics') {
      return handleMissionMetrics(request, env, url);
    }
    if (request.method === 'GET' && url.pathname.startsWith('/api/swarm/mission/')) {
      const rest = url.pathname.slice('/api/swarm/mission/'.length);
      if (rest.endsWith('/report')) {
        return handleMissionReport(request, env, rest.slice(0, -'/report'.length), url);
      }
      return handleMissionLookup(request, env, rest);
    }
    return json({ error: 'not_found' }, 404);
  },
};

export const __test = Object.freeze({
  AGENTS,
  AGENT_VISUALS,
  SPECIALIST_ROUTES,
  authHeaders,
  hasAuth,
  normalizeIocValue,
  safeRequestId,
  firstCveId,
  firstActorTag,
  firstReportId,
  firstTechnique,
  iocHunterResult,
  fuseRiskSynthesis,
  canonicalGatewayFetch,
  handlePreflight,
  handleMissionReadiness,
  getSynthesisReadiness,
  synthesizeNarrative,
  summarizeMissionOutcomes,
  runBackendSpecialist,
  persistMission,
  credentialPartition,
  getMissionRecord,
  handleMissionMetrics,
  percentile,
  listMissionProfiles,
  resolveMissionProfile,
  ui,
  swarmAppJs,
  missionReportMarkdown,
  missionToStixBundle,
  missionIocToStixPattern,
  detectStixObservableType,
  getIdempotencyPointer,
  setIdempotencyPointer,
  MISSION_INDEX_PREFIX,
  IDEMPOTENCY_PREFIX,
});
