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

// One real, distinct backend call per specialist. Forwards the caller's own
// credentials unchanged (same pattern as the existing canonical correlate
// call) -- this worker never derives tenant/tier/entitlement itself, it
// only reports what the already-authoritative route decides. A scope- or
// tier-denied response becomes an honest DENIED agent state, not a fake
// COMPLETED one.
async function runBackendSpecialist(canonicalBase, auth, correlationId, correlation, route) {
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
    resp = await fetch(url.toString(), { headers });
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
async function synthesizeNarrative(canonicalBase, auth, correlationId, correlation, outcomes) {
  const headers = new Headers(auth);
  headers.set('content-type', 'application/json');
  headers.set('x-request-id', correlationId);

  let resp;
  try {
    resp = await fetch(`${canonicalBase}/api/v1/swarm-synthesis`, {
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
    const canonicalResponse = await fetch(`${canonicalBase}/api/intel/correlate`, {
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
        ? await runBackendSpecialist(canonicalBase, auth, correlationId, canonical, SPECIALIST_ROUTES[agent.id])
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
    const narrative = await synthesizeNarrative(canonicalBase, auth, correlationId, canonical, outcomes);
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
  const agents = AGENTS.map((a) =>
    `<article class="agent" id="agent-${escapeHtml(a.id)}"><div><strong>${escapeHtml(a.name)}</strong><small>${escapeHtml(a.capability)}</small></div><span class="state">IDLE</span>${a.id === 'risk-synthesizer' ? '<p class="narrative" hidden></p>' : ''}<pre></pre></article>`
  ).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CYBERDUDEBIVASH SENTINEL APEX — SUPER AGENT SWARM</title><style>
  :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui;background:#05080d;color:#e6edf3}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#0d2a24,#05080d 45%);min-height:100vh}.wrap{max-width:1180px;margin:auto;padding:38px 22px 80px}.brand{font-weight:800;letter-spacing:.08em;color:#72f0c2}.hero{border:1px solid #19483c;background:rgba(6,19,17,.88);border-radius:18px;padding:28px;margin:20px 0}.hero h1{font-size:clamp(28px,5vw,52px);margin:8px 0}.sub{color:#9fb8b0;max-width:850px;line-height:1.55}.form{display:grid;grid-template-columns:1fr 180px;gap:10px;margin-top:22px}.form input,.form select,.key{background:#07110f;color:#e6edf3;border:1px solid #28594d;border-radius:10px;padding:13px;font:inherit}.key{width:100%;margin-top:10px}.run{background:#37d39f;border:0;color:#03100c;font-weight:800;border-radius:10px;padding:13px 18px;cursor:pointer}.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:18px 0}.meta div{background:#07110f;border:1px solid #163a31;border-radius:10px;padding:12px}.meta small,.agent small{display:block;color:#78988f;margin-top:4px}.agents{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.agent{min-height:155px;background:#07110f;border:1px solid #173b32;border-radius:14px;padding:16px;position:relative}.agent .state{position:absolute;right:14px;top:14px;font-size:11px;font-weight:800;border:1px solid #28594d;border-radius:999px;padding:5px 8px}.agent[data-state=RUNNING]{border-color:#e9b949}.agent[data-state=COMPLETED]{border-color:#37d39f}.agent[data-state=DENIED]{border-color:#7d8590}.agent[data-state=FAILED]{border-color:#ff6b6b}.agent pre{white-space:pre-wrap;word-break:break-word;color:#9fb8b0;font-size:11px;max-height:180px;overflow:auto;margin-top:20px}.agent .narrative{margin-top:10px;font-size:12.5px;line-height:1.5;color:#e6edf3}.agent .narrative .badge{display:inline-block;font-size:10px;font-weight:800;letter-spacing:.04em;border-radius:999px;padding:3px 8px;margin-bottom:6px;border:1px solid #28594d;color:#78988f}.agent .narrative .badge[data-kind=ai]{color:#37d39f;border-color:#37d39f}.agent .narrative .narrative-body{display:block}.final{margin-top:16px;border:1px solid #28594d;background:#07110f;border-radius:14px;padding:18px;white-space:pre-wrap}.truth{font-size:12px;color:#78988f;margin-top:12px}.history{margin-top:24px;border:1px solid #28594d;background:#07110f;border-radius:14px;padding:18px}.history h2{margin:0;font-size:16px}.history .row{display:flex;justify-content:space-between;align-items:center;gap:10px}.load,.dl{background:transparent;border:1px solid #28594d;color:#9fb8b0;border-radius:8px;padding:7px 12px;cursor:pointer;font:inherit;font-size:12px}.dl{padding:3px 8px}.history table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:10px}.history th,.history td{text-align:left;padding:6px 8px;border-bottom:1px solid #163a31}@media(max-width:700px){.form{grid-template-columns:1fr}.meta{grid-template-columns:1fr}}
  </style></head><body><main class="wrap"><div class="brand">CYBERDUDEBIVASH® SENTINEL APEX™</div><section class="hero"><h1>SUPER AGENT SWARM — LIVE CTI OPERATIONS</h1><p class="sub">Launch a real paid Sentinel correlation mission. Every agent state below is emitted by its own real backend execution against the canonical Sentinel intelligence platform -- no simulated timers, random percentages, or hard-coded findings. The mission is accepted only when the canonical Sentinel route completes through the private APEX mesh.</p><input class="key" id="key" type="password" autocomplete="off" placeholder="Sentinel API key — held in memory only, never saved"><div class="form"><input id="ioc" value="8.8.8.8" aria-label="IOC"><select id="type"><option value="ipv4">IPv4</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">Hash</option><option value="auto">Auto</option></select><button class="run" id="run">RUN LIVE SWARM</button></div><p class="truth">Credential storage: none. This page does not write the API key to cookies or localStorage.</p></section><section class="meta"><div>Mission<small id="mission">—</small></div><div>Correlation<small id="correlation">—</small></div><div>Mesh Certification<small id="mesh">PENDING</small></div></section><section class="agents">${agents}</section><pre class="final" id="final">Awaiting a live mission.</pre><section class="history"><div class="row"><h2>Mission History</h2><button class="load" id="loadHistory">LOAD HISTORY</button></div><p class="truth" id="historyNote">Loads your own past missions for the API key above. Requires mission persistence to be provisioned (see /api/swarm/health).</p><div id="historyBody"></div></section></main><script>
  const run=document.getElementById('run'),final=document.getElementById('final');
  function renderNarrative(el,result){const n=el.querySelector('.narrative');if(!n)return;n.hidden=false;n.textContent='';const badge=document.createElement('span');badge.className='badge';const body=document.createElement('span');body.className='narrative-body';if(result.llm_enhanced&&result.ai_narrative){badge.dataset.kind='ai';badge.textContent='AI-SYNTHESIZED'+(result.llm_model?' · '+result.llm_model:'');body.textContent=result.ai_narrative}else{badge.dataset.kind='deterministic';badge.textContent='DETERMINISTIC FUSION';body.textContent=result.recommendation||''}n.append(badge,body)}
  function setAgent(ev){if(!ev.agent_id)return;const el=document.getElementById('agent-'+ev.agent_id);if(!el)return;el.dataset.state=ev.state;el.querySelector('.state').textContent=ev.state+(ev.basis==='unconfigured'?' · CONFIG ERROR':'');if(ev.agent_id==='risk-synthesizer'&&ev.result)renderNarrative(el,ev.result);const p=el.querySelector('pre');if(ev.result)p.textContent=JSON.stringify(ev.result,null,2);else if(ev.detail)p.textContent=JSON.stringify(ev.detail,null,2)}
  run.onclick=async()=>{const key=document.getElementById('key').value.trim(),ioc=document.getElementById('ioc').value.trim(),type=document.getElementById('type').value;if(!key||!ioc){final.textContent='API key and IOC are required.';return}run.disabled=true;final.textContent='Connecting to live swarm…';document.getElementById('mesh').textContent='PENDING';try{const rid='ui-'+crypto.randomUUID();const r=await fetch('/api/swarm/run',{method:'POST',headers:{'content-type':'application/json','x-api-key':key,'x-request-id':rid},body:JSON.stringify({ioc_value:ioc,ioc_type:type})});if(!r.ok){final.textContent='Launch failed: HTTP '+r.status+' '+await r.text();return}const reader=r.body.getReader(),decoder=new TextDecoder();let buf='';while(true){const {value,done}=await reader.read();if(done)break;buf+=decoder.decode(value,{stream:true});let idx;while((idx=buf.indexOf('\n\n'))>=0){const chunk=buf.slice(0,idx);buf=buf.slice(idx+2);const line=chunk.split('\n').find(x=>x.startsWith('data: '));if(!line)continue;const ev=JSON.parse(line.slice(6));document.getElementById('mission').textContent=ev.mission_id;document.getElementById('correlation').textContent=ev.correlation_id;setAgent(ev);if(ev.mesh_certified)document.getElementById('mesh').textContent='CERTIFIED · '+(ev.mesh_execution_id||'');if(ev.event_type==='mission.completed')final.textContent=JSON.stringify(ev.result,null,2);if(ev.event_type==='mission.rejected'||ev.event_type==='mission.failed')final.textContent=JSON.stringify(ev,null,2)}}}}catch(e){final.textContent='Mission transport failed: '+e.message}finally{run.disabled=false}}
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
  synthesizeNarrative,
  runBackendSpecialist,
  persistMission,
  credentialPartition,
  getMissionRecord,
  missionReportMarkdown,
  missionToStixBundle,
  missionIocToStixPattern,
  detectStixObservableType,
  getIdempotencyPointer,
  setIdempotencyPointer,
  MISSION_INDEX_PREFIX,
  IDEMPOTENCY_PREFIX,
});
