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

// Agents backed by a genuine, distinct, already-routed intel-gateway endpoint
// (Reuse Before Build: these call existing production routes, not new ones).
// ioc-hunter isn't listed here -- its "call" is the canonical correlate
// request executeMission() already makes to gate the whole mission.
const SPECIALIST_ROUTES = Object.freeze({
  'cve-intelligence': Object.freeze({ path: '/api/cves', paramKey: 'cve_id', pick: firstCveId, emptyReason: 'no CVE identifier present in the correlated matches' }),
  'threat-hunter': Object.freeze({ path: '/api/actors', paramKey: 'actor_id', pick: firstActorTag, emptyReason: 'no attributed actor present in the correlated matches' }),
  'siem-defender': Object.freeze({ path: '/api/v1/detections', paramKey: 'intel_id', pick: firstReportId, emptyReason: 'no matched intelligence report to query detection coverage for' }),
  'attack-mapper': Object.freeze({ path: '/api/search', paramKey: 'q', pick: firstTechnique, emptyReason: 'no ATT&CK technique present in the correlated matches' }),
  // Both now backed by real routes (GET /api/intel/ir-guidance,
  // GET /api/intel/exposure) added specifically to close this gap -- each
  // reuses its P23.4/P27.3 engine (_buildIRChecklist/_deriveExposure)
  // unchanged, just shaped as JSON instead of the HTML fragment those
  // engines render into on the report page. No more derived-only specialists.
  'ir-playbook': Object.freeze({ path: '/api/intel/ir-guidance', paramKey: 'report_id', pick: firstReportId, emptyReason: 'no matched intelligence report to derive IR guidance from' }),
  'exposure-analyst': Object.freeze({ path: '/api/intel/exposure', paramKey: 'report_id', pick: firstReportId, emptyReason: 'no matched intelligence report to derive exposure analysis from' }),
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

// One real, distinct backend call per specialist. Forwards the caller's own
// credentials unchanged (same pattern as the existing canonical correlate
// call) -- this worker never derives tenant/tier/entitlement itself, it
// only reports what the already-authoritative route decides. A scope- or
// tier-denied response becomes an honest DENIED agent state, not a fake
// COMPLETED one.
async function runBackendSpecialist(canonicalBase, auth, correlationId, correlation, route, env = null) {
  // Real, measured latency of this specialist's own backend call -- not an
  // estimate. The 'derived' no-op path below makes no call at all, so it
  // honestly reports ~0ms rather than a fabricated figure.
  const t0 = Date.now();
  const value = route.pick(correlation);
  if (!value) {
    return { basis: 'derived', state: 'COMPLETED', result: { note: `Skipped live query: ${route.emptyReason}.` }, duration_ms: Date.now() - t0 };
  }

  const headers = new Headers(auth);
  headers.set('x-request-id', correlationId);
  const url = new URL(canonicalBase + route.path);
  url.searchParams.set(route.paramKey, value);
  url.searchParams.set('limit', '5');

  let resp;
  try {
    resp = await canonicalGatewayFetch(env, url.toString(), { headers });
  } catch (error) {
    return {
      basis: 'backend_execution',
      state: 'FAILED',
      result: null,
      queried: { [route.paramKey]: value },
      detail: { error: 'specialist_transport_failed', message: String(error?.message || error).slice(0, 240) },
      duration_ms: Date.now() - t0,
    };
  }

  let body = null;
  try { body = await resp.json(); } catch { /* handled by the ok-check below */ }

  if (resp.ok && body && body.status === 'ok') {
    return { basis: 'backend_execution', state: 'COMPLETED', result: body.data, queried: { [route.paramKey]: value }, duration_ms: Date.now() - t0 };
  }

  const state = resp.status === 401 || resp.status === 403 ? 'DENIED' : 'FAILED';
  return {
    basis: 'backend_execution',
    state,
    result: null,
    queried: { [route.paramKey]: value },
    http_status: resp.status,
    detail: responseSnippet(body),
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
  const contributing = entries.filter(([, o]) => o.state === 'COMPLETED').map(([id]) => id);
  const denied = entries.filter(([, o]) => o.state === 'DENIED').map(([id]) => id);
  const failed = entries.filter(([, o]) => o.state === 'FAILED').map(([id]) => id);
  const matches = allMatches(correlation);
  const riskScores = matches.map((m) => Number(m?.risk_score || 0)).filter(Number.isFinite);

  return {
    basis: 'fusion',
    verdict: correlation?.verdict || 'unknown',
    max_risk_score: riskScores.length ? Math.max(...riskScores) : 0,
    match_count: matches.length,
    contributing_specialists: contributing,
    denied_specialists: denied,
    failed_specialists: failed,
    recommendation: correlation?.recommendation || 'Review the canonical Sentinel correlation result.',
    source: `fusion of ${contributing.length} real specialist executions (${denied.length} denied by scope, ${failed.length} failed)`,
  };
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
  try {
    await env.SWARM_MISSIONS_KV.put(record.mission_id, JSON.stringify(record), {
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

async function executeMission({ writer, request, env, body, correlationId, missionId, executionId, idempotencyKeySupplied }) {
  const encoder = new TextEncoder();
  const makeEvent = eventFactory({ missionId, executionId, correlationId });
  const canonicalBase = env.CANONICAL_BASE_URL || 'https://intel.cyberdudebivash.com';
  const auth = authHeaders(request);
  const partition = await credentialPartition(auth);
  const missionStartedMs = Date.now();
  const startedAt = new Date().toISOString();
  const queued = AGENTS.filter((a) => a.id !== 'risk-synthesizer' && a.id !== 'ioc-hunter');
  const iocHunter = AGENTS.find((a) => a.id === 'ioc-hunter');
  const synthesizer = AGENTS.find((a) => a.id === 'risk-synthesizer');

  const finish = async (status, extra = {}) => {
    await persistMission(env, {
      mission_id: missionId,
      execution_id: executionId,
      correlation_id: correlationId,
      product: PRODUCT,
      protocol: PROTOCOL,
      status,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      duration_ms: Date.now() - missionStartedMs,
      ioc: { ioc_value: body.ioc_value, ioc_type: body.ioc_type || 'auto' },
      ...extra,
    }, partition);
    if (idempotencyKeySupplied) await setIdempotencyPointer(env, partition, correlationId, missionId, status);
  };

  try {
    await emit(writer, encoder, makeEvent('QUEUED', null, {
      event_type: 'mission.accepted',
      agent_count: AGENTS.length,
      input: { ioc_value: body.ioc_value, ioc_type: body.ioc_type || 'auto' },
    }));

    for (const agent of AGENTS) {
      await emit(writer, encoder, makeEvent('QUEUED', agent, { event_type: 'agent.queued' }));
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
      const state = canonicalResponse.status === 401 || canonicalResponse.status === 403 ? 'DENIED' : 'FAILED';
      await emit(writer, encoder, makeEvent(state, iocHunter, {
        event_type: 'agent.denied',
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
      await finish(state, { canonical_status: canonicalResponse.status, mesh_certified: meshCertified });
      return;
    }

    const iocHunterOutcome = { basis: 'backend_execution', state: 'COMPLETED', result: iocHunterResult(canonical), duration_ms: iocHunterDurationMs };
    await emit(writer, encoder, makeEvent('COMPLETED', iocHunter, {
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

    const outcomes = { 'ioc-hunter': iocHunterOutcome };

    const specialistTasks = queued.map(async (agent) => {
      await emit(writer, encoder, makeEvent('RUNNING', agent, {
        event_type: 'agent.started',
        basis: SPECIALIST_ROUTES[agent.id] ? 'backend_execution' : 'unconfigured',
        source: SPECIALIST_ROUTES[agent.id] ? `canonical:${SPECIALIST_ROUTES[agent.id].path}` : null,
      }));

      // Every current agent has a SPECIALIST_ROUTES entry; the fallback below
      // is a fail-closed guard against a future agent being added to AGENTS
      // without one -- it reports a config error, never a fabricated result.
      const outcome = SPECIALIST_ROUTES[agent.id]
        ? await runBackendSpecialist(canonicalBase, auth, correlationId, canonical, SPECIALIST_ROUTES[agent.id], env)
        : { basis: 'unconfigured', state: 'FAILED', result: null, detail: { error: 'no_backend_route_configured', agent: agent.id } };

      outcomes[agent.id] = outcome;
      await emit(writer, encoder, makeEvent(outcome.state, agent, {
        event_type: outcome.state === 'COMPLETED' ? 'agent.completed' : outcome.state === 'DENIED' ? 'agent.denied' : 'agent.failed',
        basis: outcome.basis,
        result: outcome.result,
        queried: outcome.queried || undefined,
        detail: outcome.detail || undefined,
        duration_ms: outcome.duration_ms ?? null,
      }));
      return outcome;
    });

    await Promise.all(specialistTasks);

    await emit(writer, encoder, makeEvent('RUNNING', synthesizer, {
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
    }
    const synthesizerDurationMs = Date.now() - synthesizerT0;
    outcomes['risk-synthesizer'] = { basis: 'fusion', state: 'COMPLETED', result: fused, duration_ms: synthesizerDurationMs };

    await emit(writer, encoder, makeEvent('COMPLETED', synthesizer, {
      event_type: 'agent.completed',
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
      result: fused,
    }));

    await finish('COMPLETED', {
      mesh_execution_id: meshExecutionId,
      verdict: fused.verdict,
      specialists: Object.fromEntries(
        Object.entries(outcomes).map(([id, o]) => [id, { basis: o.basis, state: o.state, result: o.result ?? null, duration_ms: o.duration_ms ?? null }])
      ),
    });
  } catch (error) {
    await emit(writer, encoder, makeEvent('FAILED', null, {
      event_type: 'mission.failed',
      error: 'swarm_execution_failed',
      message: String(error?.message || error).slice(0, 240),
    })).catch(() => {});
    await finish('FAILED', { error: String(error?.message || error).slice(0, 240) }).catch(() => {});
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

  body.ioc_value = body.ioc_value.trim();
  body.ioc_type = String(body.ioc_type || 'auto').trim().slice(0, 32) || 'auto';

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
      const existing = await getMissionRecord(env, pointer.mission_id);
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
async function getMissionRecord(env, missionId) {
  if (!env.SWARM_MISSIONS_KV) {
    return { status: 503, body: { error: 'mission_store_unavailable', message: 'Mission persistence is not provisioned yet.' } };
  }
  const raw = await env.SWARM_MISSIONS_KV.get(missionId);
  if (!raw) return { status: 404, body: { error: 'mission_not_found' } };
  let record;
  try { record = JSON.parse(raw); } catch { return { status: 500, body: { error: 'mission_record_corrupt' } }; }
  return { status: 200, record };
}

async function handleMissionLookup(request, env, missionId) {
  if (!ID_RE.test(missionId)) return json({ error: 'invalid_mission_id' }, 400);
  if (!hasAuth(authHeaders(request))) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }
  const result = await getMissionRecord(env, missionId);
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
    custom_properties: {
      x_sentinel_mission_id: record.mission_id,
      x_sentinel_execution_id: record.execution_id || null,
      x_sentinel_correlation_id: record.correlation_id || null,
      x_sentinel_verdict: record.verdict || null,
      x_sentinel_mesh_certified: Boolean(record.mesh_certified),
    },
  };

  const specialists = record.specialists || {};
  const notes = Object.entries(specialists).map(([agentId, o]) => ({
    type: 'note', spec_version: '2.1', id: stixObjectId('note'),
    created: modified, modified,
    abstract: `SENTINEL APEX ${agentId} -- ${o.state || 'UNKNOWN'}`,
    content: JSON.stringify({ basis: o.basis ?? null, state: o.state ?? null, result: o.result ?? null }, null, 2),
    object_refs: [indicatorId],
    custom_properties: { x_sentinel_agent_id: agentId, x_sentinel_agent_state: o.state ?? null, x_sentinel_agent_basis: o.basis ?? null },
  }));

  return { type: 'bundle', id: stixObjectId('bundle'), spec_version: '2.1', objects: [indicator, ...notes] };
}

// GET /api/swarm/mission/:id/report -- an exportable, downloadable evidence
// report for one mission. ?format=json for the raw persisted record, or
// ?format=stix21 for a STIX 2.1 Bundle ready for SIEM/SOAR/TIP ingestion,
// both as downloadable attachments; default is a Markdown transcript.
async function handleMissionReport(request, env, missionId, url) {
  if (!ID_RE.test(missionId)) return json({ error: 'invalid_mission_id' }, 400);
  if (!hasAuth(authHeaders(request))) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }
  const result = await getMissionRecord(env, missionId);
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

function ui() {
  const agents = AGENTS.map((a, index) =>
    `<article class="agent" id="agent-${escapeHtml(a.id)}" data-state="IDLE"><div class="agent-head"><div class="agent-identity"><span class="agent-index">${String(index + 1).padStart(2, '0')}</span><div class="agent-title"><strong>${escapeHtml(a.name)}</strong><small>${escapeHtml(a.capability)}</small></div></div><span class="state">IDLE</span></div><div class="agent-meta-line"><span class="basis">WAITING</span><span class="duration">—</span></div>${a.id === 'risk-synthesizer' ? '<p class="narrative" hidden></p>' : ''}<pre>Awaiting backend execution.</pre></article>`
  ).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CYBERDUDEBIVASH SENTINEL APEX — SUPER AGENT SWARM</title><style>
  :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bg:#04080b;--panel:#07130f;--panel2:#0a1a15;--panel3:#0c211a;--line:#17483b;--line2:#226b56;--text:#f1f8f5;--muted:#8baaa1;--muted2:#64847a;--mint:#42e0ad;--mint2:#8bf7d2;--amber:#ffc857;--red:#ff7272;--blue:#75a7ff;--shadow:0 24px 80px rgba(0,0,0,.34)}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;background:radial-gradient(circle at 18% -8%,rgba(38,155,119,.18),transparent 32%),radial-gradient(circle at 84% 12%,rgba(40,96,82,.14),transparent 28%),linear-gradient(180deg,#04090d 0%,#03070a 100%);color:var(--text)}body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.18;background-image:linear-gradient(rgba(74,226,179,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(74,226,179,.045) 1px,transparent 1px);background-size:42px 42px;mask-image:linear-gradient(to bottom,black,transparent 70%)}button,input,select{font:inherit}.wrap{position:relative;z-index:1;max-width:1380px;margin:auto;padding:26px 26px 72px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:6px 2px 20px}.brand-block{display:flex;align-items:center;gap:12px}.brand-mark{width:38px;height:38px;border-radius:11px;border:1px solid var(--line2);display:grid;place-items:center;background:linear-gradient(145deg,#0b2c22,#07110e);box-shadow:inset 0 0 24px rgba(66,224,173,.08);font-weight:900;color:var(--mint2)}.brand{font-weight:900;letter-spacing:.09em;color:var(--mint2);font-size:14px}.brand-sub{display:block;margin-top:3px;color:var(--muted2);font-size:10px;letter-spacing:.13em;text-transform:uppercase}.top-status{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}.top-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:rgba(7,19,15,.86);padding:7px 10px;border-radius:999px;color:var(--muted);font-size:10px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}.top-pill .dot{width:7px;height:7px;border-radius:50%;background:#53675f;box-shadow:0 0 0 3px rgba(83,103,95,.1)}.top-pill[data-tone=ok]{color:var(--mint2);border-color:#226b56}.top-pill[data-tone=ok] .dot{background:var(--mint);box-shadow:0 0 14px rgba(66,224,173,.65)}.hero{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(320px,.55fr);gap:18px;border:1px solid var(--line);background:linear-gradient(135deg,rgba(7,24,19,.96),rgba(5,14,13,.96));border-radius:24px;padding:34px;box-shadow:var(--shadow);overflow:hidden;position:relative}.hero:after{content:"";position:absolute;right:-120px;top:-150px;width:360px;height:360px;border-radius:50%;border:1px solid rgba(66,224,173,.12);box-shadow:0 0 90px rgba(66,224,173,.05);pointer-events:none}.eyebrow{display:inline-flex;align-items:center;gap:8px;color:var(--mint2);font-size:11px;font-weight:900;letter-spacing:.16em;text-transform:uppercase}.eyebrow:before{content:"";width:24px;height:1px;background:var(--mint)}.hero h1{font-size:clamp(38px,5.4vw,72px);line-height:.98;letter-spacing:-.045em;margin:15px 0 16px;max-width:900px}.hero h1 span{display:block;color:var(--mint2)}.sub{color:#abc4bc;max-width:820px;line-height:1.7;font-size:15px;margin:0}.assurance{align-self:stretch;border:1px solid rgba(66,224,173,.15);background:rgba(3,11,9,.54);border-radius:18px;padding:18px;position:relative;z-index:1}.assurance-title{font-size:11px;font-weight:900;letter-spacing:.13em;text-transform:uppercase;color:var(--muted);margin-bottom:12px}.assurance-grid{display:grid;gap:9px}.assurance-item{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid #12382e;background:#06110e;border-radius:12px;padding:11px 12px}.assurance-item strong{display:block;font-size:12px}.assurance-item small{display:block;color:var(--muted2);font-size:10px;margin-top:3px}.assurance-state{font-size:10px;font-weight:900;letter-spacing:.08em;color:var(--muted);white-space:nowrap}.assurance-state[data-tone=ok]{color:var(--mint)}.launch{margin-top:18px;border:1px solid var(--line);background:rgba(6,17,14,.94);border-radius:20px;padding:22px}.section-kicker{font-size:10px;font-weight:900;letter-spacing:.14em;text-transform:uppercase;color:var(--mint)}.section-title{font-size:20px;margin:5px 0 3px}.section-copy{color:var(--muted);font-size:12px;line-height:1.5;margin:0}.launch-grid{display:grid;grid-template-columns:minmax(260px,1.3fr) minmax(220px,1fr) 150px 190px;gap:10px;margin-top:18px}.field{display:flex;flex-direction:column;gap:7px}.field label{font-size:10px;font-weight:800;letter-spacing:.08em;color:var(--muted);text-transform:uppercase}.field input,.field select{height:48px;background:#04100d;color:var(--text);border:1px solid #28594d;border-radius:11px;padding:0 13px;outline:none;transition:.18s}.field input:focus,.field select:focus{border-color:var(--mint);box-shadow:0 0 0 3px rgba(66,224,173,.08)}.run{align-self:end;height:48px;background:linear-gradient(90deg,#34d6a3,#51e3b5);border:0;color:#02100b;font-weight:950;border-radius:11px;padding:0 18px;cursor:pointer;letter-spacing:.04em;box-shadow:0 8px 24px rgba(66,224,173,.14);transition:.18s}.run:hover{transform:translateY(-1px);box-shadow:0 10px 30px rgba(66,224,173,.22)}.run:disabled{opacity:.55;cursor:not-allowed;transform:none}.security-note{display:flex;align-items:center;gap:8px;color:var(--muted2);font-size:11px;margin:12px 0 0}.security-note:before{content:"LOCK";font-size:8px;font-weight:900;letter-spacing:.08em;color:var(--mint);border:1px solid #245947;border-radius:999px;padding:3px 5px}.runtime-strip{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:16px 0}.kpi{border:1px solid #153f34;background:linear-gradient(180deg,#081610,#06100d);border-radius:15px;padding:14px 15px;min-width:0}.kpi-label{font-size:9px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted2);font-weight:900}.kpi-value{font-size:14px;font-weight:850;margin-top:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.kpi-value[data-tone=ok]{color:var(--mint2)}.kpi-value[data-tone=warn]{color:var(--amber)}.mission-meta{display:grid;grid-template-columns:1.2fr 1.2fr .8fr .8fr;gap:10px;margin-bottom:20px}.meta-card{border:1px solid #143d32;background:#06110e;border-radius:14px;padding:13px 14px;min-width:0}.meta-card span{display:block;color:var(--muted2);font-size:9px;text-transform:uppercase;letter-spacing:.11em;font-weight:900}.meta-card strong{display:block;margin-top:6px;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.agent-section,.evidence-section,.history{margin-top:20px}.section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:18px;margin-bottom:12px}.section-head h2{margin:4px 0 0;font-size:20px}.section-head p{max-width:650px;margin:0;color:var(--muted);font-size:11px;line-height:1.5;text-align:right}.agents{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.agent{min-height:220px;background:linear-gradient(180deg,#07130f,#050e0c);border:1px solid #173b32;border-radius:17px;padding:15px;transition:.2s;overflow:hidden}.agent-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}.agent-identity{display:flex;align-items:flex-start;gap:10px;min-width:0}.agent-index{flex:0 0 28px;width:28px;height:28px;display:grid;place-items:center;border:1px solid #1b4a3d;background:#091a15;border-radius:9px;color:var(--mint);font-size:9px;font-weight:900}.agent-title{min-width:0}.agent-title strong{display:block;font-size:13px;line-height:1.28;overflow-wrap:anywhere}.agent-title small{display:block;color:var(--muted2);font-size:10px;margin-top:4px}.state{flex:0 0 auto;font-size:9px;font-weight:900;letter-spacing:.06em;border:1px solid #28594d;border-radius:999px;padding:5px 7px;color:var(--muted)}.agent-meta-line{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 0 8px;margin-top:9px;border-top:1px solid #102c25;color:var(--muted2);font-size:9px;text-transform:uppercase;letter-spacing:.07em}.agent[data-state=QUEUED]{border-color:#315e52}.agent[data-state=RUNNING]{border-color:#91752f;box-shadow:inset 0 0 28px rgba(255,200,87,.035)}.agent[data-state=COMPLETED]{border-color:#248f6d;box-shadow:inset 0 0 30px rgba(66,224,173,.035)}.agent[data-state=DENIED],.agent[data-state=FAILED]{border-color:#7b3b3b}.agent[data-state=RUNNING] .state{color:var(--amber);border-color:#6a5827}.agent[data-state=COMPLETED] .state{color:var(--mint);border-color:#226b56}.agent[data-state=DENIED] .state,.agent[data-state=FAILED] .state{color:var(--red);border-color:#6b3737}.agent pre{white-space:pre-wrap;word-break:break-word;color:#91aba3;font-size:10px;line-height:1.45;max-height:110px;overflow:auto;margin:6px 0 0;padding:10px;background:#040b09;border:1px solid #102b24;border-radius:10px}.agent .narrative{margin:8px 0 0;font-size:11px;line-height:1.45;color:var(--text)}.agent .narrative .badge{display:inline-block;font-size:8px;font-weight:900;letter-spacing:.05em;border-radius:999px;padding:3px 7px;margin-bottom:6px;border:1px solid #28594d;color:var(--muted)}.agent .narrative .badge[data-kind=ai]{color:var(--mint);border-color:#37a47f}.agent .narrative .narrative-body{display:block}.evidence-grid{display:grid;grid-template-columns:.8fr 1.2fr;gap:12px}.panel{border:1px solid #173e33;background:#06110e;border-radius:17px;padding:16px;min-width:0}.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:10px}.panel-head strong{font-size:13px}.panel-badge{font-size:8px;font-weight:900;letter-spacing:.09em;color:var(--muted);border:1px solid #244f42;border-radius:999px;padding:5px 7px}.event-log{height:300px;overflow:auto;display:flex;flex-direction:column;gap:6px}.event-empty{color:var(--muted2);font-size:11px;padding:12px 4px}.event-row{display:grid;grid-template-columns:48px 82px 1fr;gap:8px;align-items:start;border-bottom:1px solid #102b24;padding:7px 3px;font-size:10px}.event-seq{color:var(--muted2);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.event-state{font-weight:900;color:var(--mint)}.event-desc{color:#a9bdb7;line-height:1.4;overflow-wrap:anywhere}.final{min-height:300px;max-height:300px;overflow:auto;margin:0;border:1px solid #102b24;background:#040b09;border-radius:12px;padding:14px;white-space:pre-wrap;word-break:break-word;color:#a9c0b8;font:10.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.history{border:1px solid var(--line);background:#06110e;border-radius:18px;padding:18px}.history h2{margin:0;font-size:18px}.history .row{display:flex;justify-content:space-between;align-items:center;gap:10px}.load,.dl{background:#071711;border:1px solid #28594d;color:#a8c5bb;border-radius:8px;padding:8px 11px;cursor:pointer;font:inherit;font-size:10px;font-weight:800}.load:hover,.dl:hover{border-color:var(--mint);color:var(--mint2)}.dl{padding:4px 7px}.history table{width:100%;border-collapse:collapse;font-size:11px;margin-top:12px}.history th{text-transform:uppercase;letter-spacing:.08em;color:var(--muted2);font-size:9px}.history th,.history td{text-align:left;padding:9px 8px;border-bottom:1px solid #123128}.truth{font-size:10.5px;color:var(--muted2);margin:10px 0 0}.footer{display:flex;justify-content:space-between;gap:18px;margin-top:18px;padding:0 2px;color:#536f66;font-size:9px;text-transform:uppercase;letter-spacing:.08em}.footer strong{color:#6f9589}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}@media(max-width:1120px){.hero{grid-template-columns:1fr}.agents{grid-template-columns:repeat(2,minmax(0,1fr))}.launch-grid{grid-template-columns:1fr 1fr}.run{align-self:end}.runtime-strip,.mission-meta{grid-template-columns:repeat(2,minmax(0,1fr))}.evidence-grid{grid-template-columns:1fr}}@media(max-width:700px){.wrap{padding:18px 14px 52px}.topbar,.section-head,.footer{align-items:flex-start;flex-direction:column}.top-status{justify-content:flex-start}.hero{padding:22px}.hero h1{font-size:38px}.launch-grid,.runtime-strip,.mission-meta,.agents{grid-template-columns:1fr}.section-head p{text-align:left}.event-log,.final{height:auto;max-height:360px}.history{overflow:auto}}
</style></head><body>
<main class="wrap">
  <header class="topbar">
    <div class="brand-block"><div class="brand-mark">CDB</div><div><div class="brand">CYBERDUDEBIVASH® SENTINEL APEX™</div><span class="brand-sub">Autonomous Cyber Intelligence Control Plane</span></div></div>
    <div class="top-status"><span class="top-pill" id="runtimePill"><span class="dot"></span><span id="runtimeState">CHECKING RUNTIME</span></span><span class="top-pill"><span class="dot"></span>V4.45 PRODUCTION</span></div>
  </header>

  <section class="hero">
    <div>
      <div class="eyebrow">Production CTI Orchestration</div>
      <h1>SUPER AGENT SWARM <span>LIVE OPERATIONS</span></h1>
      <p class="sub">Execute a real Sentinel correlation mission across eight backend agents. Every visible state is emitted by production execution against the canonical intelligence platform. Admission and final completion are governed by the private APEX mesh — no simulated progress, random percentages, or hard-coded findings.</p>
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

  <section class="launch">
    <div class="section-kicker">Mission Control</div>
    <h2 class="section-title">Launch a live CTI mission</h2>
    <p class="section-copy">Use an existing paid Sentinel API key. The credential stays in browser memory only and is never written to cookies or localStorage.</p>
    <div class="launch-grid">
      <div class="field"><label for="key">Sentinel API Key</label><input id="key" type="password" autocomplete="off" spellcheck="false" placeholder="ENTERPRISE / PRO / MSSP API key"></div>
      <div class="field"><label for="ioc">Observable / IOC</label><input id="ioc" value="8.8.8.8" aria-label="IOC" spellcheck="false"></div>
      <div class="field"><label for="type">IOC Type</label><select id="type"><option value="ipv4">IPv4</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">Hash</option><option value="auto">Auto detect</option></select></div>
      <button class="run" id="run">RUN LIVE SWARM</button>
    </div>
    <p class="security-note">Credential storage: none. Mission execution is accepted only through production auth, entitlement and private-mesh controls.</p>
  </section>

  <section class="runtime-strip" aria-label="Production runtime status">
    <div class="kpi"><div class="kpi-label">Runtime</div><div class="kpi-value" id="runtimeKpi">CHECKING</div></div>
    <div class="kpi"><div class="kpi-label">Protocol</div><div class="kpi-value mono" id="protocol">cdb.swarm.v1</div></div>
    <div class="kpi"><div class="kpi-label">Agent Fleet</div><div class="kpi-value" id="agentCount">8 AGENTS</div></div>
    <div class="kpi"><div class="kpi-label">Mission State</div><div class="kpi-value" id="missionState">READY</div></div>
  </section>

  <section class="mission-meta">
    <div class="meta-card"><span>Mission ID</span><strong class="mono" id="mission">—</strong></div>
    <div class="meta-card"><span>Correlation ID</span><strong class="mono" id="correlation">—</strong></div>
    <div class="meta-card"><span>Mesh Certification</span><strong id="mesh">PENDING</strong></div>
    <div class="meta-card"><span>Evidence Store</span><strong id="evidenceStore">CHECKING</strong></div>
  </section>

  <section class="agent-section">
    <div class="section-head"><div><div class="section-kicker">Real Backend Execution</div><h2>8-Agent Operations Grid</h2></div><p>Each card transitions only when its corresponding backend agent emits a real mission event. No client-side timer drives agent state.</p></div>
    <section class="agents">${agents}</section>
  </section>

  <section class="evidence-section">
    <div class="section-head"><div><div class="section-kicker">Mission Evidence</div><h2>Live event stream & fused intelligence</h2></div><p>Sequence, state and timestamps are read directly from the production SSE stream; final evidence is persisted after mission completion.</p></div>
    <div class="evidence-grid">
      <div class="panel"><div class="panel-head"><strong>Live Mission Events</strong><span class="panel-badge">SSE · REAL TIME</span></div><div class="event-log" id="eventLog"><div class="event-empty">No mission events yet.</div></div></div>
      <div class="panel"><div class="panel-head"><strong>Final Intelligence / Terminal Evidence</strong><span class="panel-badge" id="finalBadge">AWAITING MISSION</span></div><pre class="final" id="final">Awaiting a live mission.</pre></div>
    </div>
  </section>

  <section class="history">
    <div class="row"><div><div class="section-kicker">Durable Evidence</div><h2>Mission History & Evidence Export</h2></div><button class="load" id="loadHistory">LOAD HISTORY</button></div>
    <p class="truth" id="historyNote">Loads only missions scoped to the API key above. Completed missions can be exported as report, JSON evidence, or STIX 2.1.</p>
    <div id="historyBody"></div>
  </section>

  <footer class="footer"><span>CYBERDUDEBIVASH® SENTINEL APEX™ · SUPER AGENT SWARM</span><span><strong>Production truth model:</strong> backend events only · no simulated telemetry</span></footer>
</main>
<script>
  const run=document.getElementById('run'),final=document.getElementById('final'),eventLog=document.getElementById('eventLog');
  const byId=(id)=>document.getElementById(id);
  function setTone(el,tone){if(!el)return;el.dataset.tone=tone||''}
  function setText(id,value,tone){const el=byId(id);if(!el)return;el.textContent=value;setTone(el,tone)}
  function setMissionState(value,tone){setText('missionState',value,tone);setText('finalBadge',value,tone)}
  function resetAgents(){document.querySelectorAll('.agent').forEach((el)=>{el.dataset.state='IDLE';el.querySelector('.state').textContent='IDLE';el.querySelector('.basis').textContent='WAITING';el.querySelector('.duration').textContent='—';const p=el.querySelector('pre');p.textContent='Awaiting backend execution.';const n=el.querySelector('.narrative');if(n){n.hidden=true;n.textContent=''}})}
  function resetEventLog(){eventLog.innerHTML='<div class="event-empty">Waiting for the production SSE stream…</div>'}
  function appendEvent(ev){const empty=eventLog.querySelector('.event-empty');if(empty)empty.remove();const row=document.createElement('div');row.className='event-row';const seq=document.createElement('span');seq.className='event-seq';seq.textContent='#'+String(ev.sequence||'—').padStart(2,'0');const state=document.createElement('span');state.className='event-state';state.textContent=ev.state||'EVENT';const desc=document.createElement('span');desc.className='event-desc';const when=ev.timestamp?new Date(ev.timestamp).toLocaleTimeString():'—';desc.textContent=when+' · '+(ev.event_type||'swarm.event')+(ev.agent_name?' · '+ev.agent_name:'');row.append(seq,state,desc);eventLog.appendChild(row);eventLog.scrollTop=eventLog.scrollHeight}
  function renderNarrative(el,result){const n=el.querySelector('.narrative');if(!n)return;n.hidden=false;n.textContent='';const badge=document.createElement('span');badge.className='badge';const body=document.createElement('span');body.className='narrative-body';if(result.llm_enhanced&&result.ai_narrative){badge.dataset.kind='ai';badge.textContent='AI-SYNTHESIZED'+(result.llm_model?' · '+result.llm_model:'');body.textContent=result.ai_narrative}else{badge.dataset.kind='deterministic';badge.textContent='DETERMINISTIC FUSION';body.textContent=result.recommendation||''}n.append(badge,body)}
  function setAgent(ev){if(!ev.agent_id)return;const el=byId('agent-'+ev.agent_id);if(!el)return;el.dataset.state=ev.state||'IDLE';el.querySelector('.state').textContent=(ev.state||'IDLE')+(ev.basis==='unconfigured'?' · CONFIG ERROR':'');el.querySelector('.basis').textContent=(ev.basis||ev.event_type||'BACKEND').replaceAll('_',' ');el.querySelector('.duration').textContent=Number.isFinite(ev.duration_ms)?ev.duration_ms+' ms':'—';if(ev.agent_id==='risk-synthesizer'&&ev.result)renderNarrative(el,ev.result);const p=el.querySelector('pre');if(ev.result)p.textContent=JSON.stringify(ev.result,null,2);else if(ev.detail)p.textContent=JSON.stringify(ev.detail,null,2);else if(ev.event_type)p.textContent=ev.event_type}
  function renderPersistedMission(record){setText('mission',record.mission_id||'—');setText('correlation',record.correlation_id||'—');setMissionState(record.status==='COMPLETED'?'REPLAYED · COMPLETED':('REPLAYED · '+(record.status||'UNKNOWN')),record.status==='COMPLETED'?'ok':'warn');setText('mesh',record.mesh_certified?'CERTIFIED':'NOT CERTIFIED',record.mesh_certified?'ok':'warn');if(record.specialists){Object.entries(record.specialists).forEach(([id,o])=>setAgent({agent_id:id,state:o.state,basis:o.basis,result:o.result,duration_ms:o.duration_ms}))}final.textContent=JSON.stringify(record,null,2);eventLog.innerHTML='<div class="event-empty">Persisted idempotent replay loaded. No duplicate backend dispatch was performed.</div>'}
  async function hydrateHealth(){try{const r=await fetch('/api/swarm/health',{cache:'no-store'});const body=await r.json();if(!r.ok)throw new Error('HTTP '+r.status);setText('runtimeState','LIVE','ok');setTone(byId('runtimePill'),'ok');setText('runtimeKpi','LIVE · '+(body.version||'CURRENT'),'ok');setText('protocol',body.protocol||'cdb.swarm.v1');setText('agentCount',String(body.agents||8)+' AGENTS','ok');const gateway=Boolean(body.production&&body.production.canonical_gateway_bound);const durable=Boolean(body.persistence&&body.persistence.kv_bound);const retry=Boolean(body.capabilities&&body.capabilities.idempotent_retry);const formats=(body.capabilities&&body.capabilities.report_formats)||[];setText('gatewayState',gateway?'BOUND':'UNAVAILABLE',gateway?'ok':'warn');setText('persistenceState',durable?'READY':'UNAVAILABLE',durable?'ok':'warn');setText('retryState',retry?'ENFORCED':'UNKNOWN',retry?'ok':'warn');setText('exportState',formats.includes('stix21')?'READY':'LIMITED',formats.includes('stix21')?'ok':'warn');setText('evidenceStore',durable?'DURABLE KV READY':'UNAVAILABLE',durable?'ok':'warn')}catch(e){setText('runtimeState','UNAVAILABLE','warn');setText('runtimeKpi','HEALTH CHECK FAILED','warn');setText('gatewayState','UNKNOWN','warn');setText('persistenceState','UNKNOWN','warn');setText('retryState','UNKNOWN','warn');setText('exportState','UNKNOWN','warn');setText('evidenceStore','UNKNOWN','warn')}}
  run.onclick=async()=>{const key=byId('key').value.trim(),ioc=byId('ioc').value.trim(),type=byId('type').value;if(!key||!ioc){final.textContent='API key and IOC are required.';setMissionState('INPUT REQUIRED','warn');return}resetAgents();resetEventLog();run.disabled=true;final.textContent='Connecting to the production swarm…';setText('mission','—');setText('correlation','—');setText('mesh','PENDING','warn');setMissionState('CONNECTING','warn');try{const rid='ui-'+crypto.randomUUID();const r=await fetch('/api/swarm/run',{method:'POST',headers:{'content-type':'application/json','x-api-key':key,'x-request-id':rid},body:JSON.stringify({ioc_value:ioc,ioc_type:type})});if(!r.ok){setMissionState('REJECTED','warn');final.textContent='Launch failed: HTTP '+r.status+' '+await r.text();return}const contentType=r.headers.get('content-type')||'';if(contentType.includes('application/json')){const replay=await r.json();if(replay&&replay.idempotent_replay&&replay.data){renderPersistedMission(replay.data);return}final.textContent=JSON.stringify(replay,null,2);return}setText('mission',r.headers.get('x-cdb-swarm-mission')||'—');setText('correlation',r.headers.get('x-cdb-swarm-correlation')||rid);const reader=r.body.getReader(),decoder=new TextDecoder();let buf='';while(true){const chunkResult=await reader.read();if(chunkResult.done)break;buf+=decoder.decode(chunkResult.value,{stream:true});let idx;while((idx=buf.indexOf('\n\n'))>=0){const chunk=buf.slice(0,idx);buf=buf.slice(idx+2);const line=chunk.split('\n').find((x)=>x.startsWith('data: '));if(!line)continue;const ev=JSON.parse(line.slice(6));setText('mission',ev.mission_id||'—');setText('correlation',ev.correlation_id||'—');appendEvent(ev);setAgent(ev);if(ev.event_type==='mission.accepted')setMissionState('QUEUED','warn');else if(ev.event_type==='mesh.admitted'){setText('mesh','CERTIFIED · '+(ev.mesh_execution_id||''),'ok');setMissionState('ADMITTED','ok')}else if(ev.event_type==='agent.started')setMissionState('RUNNING','warn');if(ev.mesh_certified)setText('mesh','CERTIFIED · '+(ev.mesh_execution_id||''),'ok');if(ev.event_type==='mission.completed'){setMissionState('COMPLETED','ok');final.textContent=JSON.stringify(ev.result,null,2)}if(ev.event_type==='mission.rejected'||ev.event_type==='mission.failed'){setMissionState('FAILED','warn');final.textContent=JSON.stringify(ev,null,2)}}}}catch(e){setMissionState('TRANSPORT FAILED','warn');final.textContent='Mission transport failed: '+e.message}finally{run.disabled=false}}
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
        '<tr><td>'+escHtml(m.finished_at||'—')+'</td><td>'+escHtml(m.ioc_value||'—')+'</td><td>'+escHtml(m.verdict||'—')+'</td><td>'+escHtml(m.status||'—')+'</td><td><button class="dl" data-id="'+escHtml(m.mission_id)+'" data-format="md">report</button> <button class="dl" data-id="'+escHtml(m.mission_id)+'" data-format="json">json</button> <button class="dl" data-id="'+escHtml(m.mission_id)+'" data-format="stix21">stix</button></td></tr>'
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
  </script></body></html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && (url.pathname === '/swarm' || url.pathname === '/swarm/')) {
      return new Response(ui(), {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
        },
      });
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/health') {
      return json({
        status: 'ok',
        service: 'sentinel-apex-swarm-live',
        protocol: PROTOCOL,
        version: env.SWARM_VERSION || '4.44.0',
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
        },
      });
    }
    if (request.method === 'POST' && url.pathname === '/api/swarm/run') {
      return handleRun(request, env, ctx);
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/missions') {
      return handleMissionList(request, env, url);
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
  SPECIALIST_ROUTES,
  authHeaders,
  hasAuth,
  safeRequestId,
  firstCveId,
  firstActorTag,
  firstReportId,
  firstTechnique,
  iocHunterResult,
  fuseRiskSynthesis,
  canonicalGatewayFetch,
  synthesizeNarrative,
  runBackendSpecialist,
  persistMission,
  credentialPartition,
  getMissionRecord,
  ui,
  missionReportMarkdown,
  missionToStixBundle,
  missionIocToStixPattern,
  detectStixObservableType,
  getIdempotencyPointer,
  setIdempotencyPointer,
  MISSION_INDEX_PREFIX,
  IDEMPOTENCY_PREFIX,
});
