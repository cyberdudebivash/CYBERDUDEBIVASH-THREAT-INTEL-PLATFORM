#!/usr/bin/env node

import { buildCandidatesFromIocCsv } from './certification-ioc-candidates.mjs';

const DEFAULT_BASE_URL = 'https://intel.cyberdudebivash.com';
const EXPECTED_SERVICE = 'sentinel-apex-swarm-live';
const EXPECTED_PROTOCOL = 'cdb.swarm.v1';
const EXPECTED_VERSION = '4.47.0';
const EXPECTED_AGENTS = new Set([
  'ioc-hunter',
  'cve-intelligence',
  'threat-hunter',
  'attack-mapper',
  'siem-defender',
  'ir-playbook',
  'exposure-analyst',
  'risk-synthesizer',
]);

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return null;
  const value = process.argv[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  return value;
}

function hasFlag(name) {
  return process.argv.includes(name);
}

function cleanBaseUrl(value) {
  const url = new URL(value || DEFAULT_BASE_URL);
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new Error('base URL must use HTTPS (except localhost)');
  }
  return url.toString().replace(/\/$/, '');
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function getText(url, init = {}) {
  const response = await fetch(url, { redirect: 'follow', ...init });
  const text = await response.text();
  return { response, text };
}

async function getJson(url, init = {}) {
  const { response, text } = await getText(url, init);
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`${url} returned non-JSON HTTP ${response.status}`);
  }
  return { response, body };
}

function parseSse(text) {
  const events = [];
  for (const chunk of text.split(/\r?\n\r?\n/)) {
    const dataLines = chunk
      .split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trim());
    if (!dataLines.length) continue;
    const raw = dataLines.join('\n');
    try {
      events.push(JSON.parse(raw));
    } catch {
      throw new Error(`invalid JSON SSE event: ${raw.slice(0, 180)}`);
    }
  }
  return events;
}

function logPass(label, detail = '') {
  console.log(`PASS  ${label}${detail ? ` — ${detail}` : ''}`);
}


async function discoverFullFabricCandidate(baseUrl, apiKey) {
  const exportLimit = Math.max(50, Number(process.env.SENTINEL_SWARM_DISCOVERY_EXPORT_LIMIT || 500));
  const candidateLimit = Math.max(1, Number(process.env.SENTINEL_SWARM_CANDIDATE_LIMIT || 32));
  const exported = await getText(`${baseUrl}/api/export/csv?limit=${Math.min(exportLimit, 5000)}`, {
    headers: {
      accept: 'text/csv',
      'x-api-key': apiKey,
      'x-request-id': `release-ioc-export-${crypto.randomUUID()}`,
    },
  });

  assert(exported.response.status === 200, `authenticated IOC export returned HTTP ${exported.response.status}`);
  assert(
    (exported.response.headers.get('content-type') || '').toLowerCase().includes('text/csv'),
    'authenticated IOC export did not return CSV'
  );

  const candidates = buildCandidatesFromIocCsv(exported.text, candidateLimit);
  assert(candidates.length > 0, 'authenticated IOC export contains no usable certification candidates');

  const attempts = [];
  for (const candidate of candidates) {
    const readiness = await getJson(`${baseUrl}/api/swarm/readiness`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'x-request-id': `release-discovery-${crypto.randomUUID()}`,
      },
      body: JSON.stringify({
        ioc_value: candidate.value,
        ioc_type: candidate.type,
        mission_profile: 'AUTO',
      }),
    });

    attempts.push({
      value: candidate.value,
      type: candidate.type,
      report_id: candidate.report_id,
      structural_score: candidate.structural_score,
      status: readiness.response.status,
      quality: readiness.body?.readiness?.mission_quality || readiness.body?.reason || readiness.body?.error || 'unknown',
      ready_agents: readiness.body?.readiness?.ready_agents ?? null,
      ai_ready: readiness.body?.synthesis_readiness?.ready ?? null,
    });

    if (
      readiness.response.status === 200 &&
      readiness.body?.mission_dispatch === false &&
      readiness.body?.readiness?.mission_quality === 'FULL_FABRIC' &&
      Number(readiness.body?.readiness?.ready_agents) === 8 &&
      readiness.body?.synthesis_readiness?.ready === true &&
      readiness.body?.demo_recommended === true
    ) {
      logPass(
        'full-fabric candidate discovery',
        `${candidate.type} ${candidate.value} · report=${candidate.report_id || 'n/a'} · 8/8 + AI READY`
      );
      return candidate;
    }
  }

  throw new Error(
    `no FULL_FABRIC + AI-ready candidate found after ${attempts.length} authenticated IOC readiness probes: ${JSON.stringify(attempts).slice(0, 2200)}`
  );
}

async function validateHealth(baseUrl) {
  const { response, body } = await getJson(`${baseUrl}/api/swarm/health`);
  assert(response.status === 200, `/api/swarm/health returned HTTP ${response.status}`);
  assert(body?.status === 'ok', 'swarm health status is not ok');
  assert(body?.service === EXPECTED_SERVICE, `unexpected service: ${body?.service}`);
  assert(body?.protocol === EXPECTED_PROTOCOL, `unexpected protocol: ${body?.protocol}`);
  assert(body?.version === EXPECTED_VERSION, `unexpected swarm version: ${body?.version}`);
  assert(body?.production?.canonical_gateway_bound === true, 'CANONICAL_GATEWAY is not bound');
  assert(body?.production?.private_mesh_required === true, 'private mesh requirement is not enabled');
  assert(body?.production?.customer_console === true, 'customer console capability is not enabled');
  assert(body?.capabilities?.idempotent_retry === true, 'idempotent retry capability is not enabled');
  assert(body?.capabilities?.entitlement_preflight === true, 'entitlement preflight capability is not enabled');
  assert(body?.capabilities?.mission_readiness === true, 'mission readiness capability is not enabled');
  assert(body?.capabilities?.mission_quality === true, 'mission quality capability is not enabled');
  assert(body?.capabilities?.evidence_graph === true, 'evidence graph capability is not enabled');
  assert(body?.capabilities?.adaptive_specialists === true, 'adaptive specialist capability is not enabled');
  assert(body?.capabilities?.agent_semantics_v2 === true, 'agent semantics v2 capability is not enabled');
  assert(body?.capabilities?.credential_scoped_metrics === true, 'credential-scoped mission metrics capability is not enabled');
  assert(body?.capabilities?.mission_profiles === true, 'mission profile capability is not enabled');
  assert(Array.isArray(body?.mission_profiles) && body.mission_profiles.some((p) => p.id === 'AUTO'), 'mission profile catalog missing AUTO');
  assert(Array.isArray(body?.capabilities?.report_formats) && body.capabilities.report_formats.includes('stix21'), 'STIX 2.1 evidence export is not advertised');
  assert(Number(body?.agents) === EXPECTED_AGENTS.size, `expected ${EXPECTED_AGENTS.size} agents, got ${body?.agents}`);
  assert(body?.persistence?.kv_bound === true, 'SWARM_MISSIONS_KV is not bound; durable mission lifecycle is NOT production-ready');
  logPass('live health', `service=${body.service} version=${body.version} protocol=${body.protocol} agents=${body.agents} kv_bound=true gateway_bound=true`);
  return body;
}

async function validateUi(baseUrl) {
  const { response, text } = await getText(`${baseUrl}/swarm/`);
  assert(response.status === 200, `/swarm/ returned HTTP ${response.status}`);
  for (const marker of ['SUPER AGENT SWARM', 'Mission History', 'RUN LIVE SWARM', 'Private APEX Mesh', 'Durable Evidence', 'STIX 2.1', '8-Agent Operations Grid', 'V4.47.0 PRODUCTION', 'SOC 2-ALIGNED EVIDENCE UX', '8-Agent Mesh Topology', 'STATE-DRIVEN LED NODES', 'Event Sequence', 'RED TEAM INTEL', 'AI SECURITY OPS', 'Cinematic launch visualization is decorative only', 'CYBER DEFENSE', 'Current customer location time', 'GLOBAL EDGE · RESOLVING']) {
    assert(text.includes(marker), `/swarm/ missing required UI marker: ${marker}`);
  }
  assert(!text.includes('DERIVED VIEW'), '/swarm/ still exposes DERIVED VIEW agents');
  assert(text.includes('<script src="/swarm/app.js" defer></script>'), '/swarm/ is not wired to the external browser controller');
  assert(text.includes('id="cinematicCanvas"'), '/swarm/ missing cinematic canvas layer');
  assert(text.includes('id="globalClock"'), '/swarm/ missing global LED clock');
  assert(text.includes('id="clockTime"'), '/swarm/ missing LED time digits');
  assert(text.includes('id="clockLocation"'), '/swarm/ missing coarse location surface');
  assert(text.includes('id="clockCountry"'), '/swarm/ missing country surface');
  assert(text.includes('id="backToPlatform"'), '/swarm/ missing back-to-platform navigation control');
  assert(text.includes('class="back-platform"'), '/swarm/ missing back-to-platform premium navigation styling');
  assert(text.includes('href="/"'), '/swarm/ back-to-platform navigation does not target the platform root');
  assert(text.includes('BACK TO PLATFORM'), '/swarm/ missing visible back-to-platform label');
  assert(text.includes('id="preflightStatus"'), '/swarm/ missing entitlement preflight status surface');
  assert(text.includes('id="readinessPanel"'), '/swarm/ missing mission readiness surface');
  assert(text.includes('id="assessReadiness"'), '/swarm/ missing explicit readiness control');
  assert(text.includes('id="missionQuality"'), '/swarm/ missing mission quality surface');
  assert(text.includes('id="evidenceGraphState"'), '/swarm/ missing evidence graph surface');
  assert(text.includes('id="viewMode"'), '/swarm/ missing executive/technical view control');
  assert(text.includes('id="profile"'), '/swarm/ missing mission profile selector');
  assert(text.includes('id="run" disabled'), '/swarm/ launch control must be locked until entitlement preflight passes');
  assert(text.includes('id="fabricStateText">DORMANT</span>'), '/swarm/ idle fabric state must be DORMANT');
  assert(text.includes('id="streamState">SSE · DORMANT</span>'), '/swarm/ idle SSE state must be DORMANT');
  assert(!text.includes('SSE · REAL TIME'), '/swarm/ idle UI falsely implies an active SSE stream');
  assert(text.includes('class="mesh-led"'), '/swarm/ missing per-agent mesh LED nodes');
  assert(text.includes('class="mesh-agent-name"'), '/swarm/ missing mesh agent identity labels');
  for (const accent of ['#00E7FF', '#8B5CFF', '#FF8A00', '#FF4FD8', '#00FFA8', '#FFD400', '#5BE1FF', '#FF4D5A']) {
    assert(text.includes(`--agent-accent:${accent}`), `/swarm/ missing unique agent accent ${accent}`);
  }
  assert(text.includes('viewport-fit=cover'), '/swarm/ missing mobile safe-area viewport support');
  assert(text.includes('@media(max-width:1180px)'), '/swarm/ missing compact-desktop/tablet layout');
  assert(text.includes('@media(max-width:860px)'), '/swarm/ missing tablet portrait layout');
  assert(text.includes('@media(max-width:700px)'), '/swarm/ missing smartphone layout');
  assert(text.includes('@media(max-width:480px)'), '/swarm/ missing narrow-smartphone layout');
  assert(text.includes('prefers-reduced-motion:reduce'), '/swarm/ missing reduced-motion CSS fallback');
  assert(text.includes('prefers-contrast:more'), '/swarm/ missing high-contrast accessibility mode');
  assert(!text.includes('SOC 2 CERTIFIED'), '/swarm/ contains an unsupported SOC 2 certification claim');

  const csp = response.headers.get('content-security-policy') || '';
  assert(csp.includes("script-src 'self'"), '/swarm/ CSP does not allow same-origin external JavaScript');
  assert(!csp.includes("script-src 'unsafe-inline'"), '/swarm/ CSP still depends on inline JavaScript');

  const app = await getText(`${baseUrl}/swarm/app.js`);
  assert(app.response.status === 200, `/swarm/app.js returned HTTP ${app.response.status}`);
  assert((app.response.headers.get('content-type') || '').includes('javascript'), '/swarm/app.js has the wrong content type');
  assert(app.text.includes("window.__CDB_SWARM_UI_READY__=true"), '/swarm/app.js missing browser-ready marker');
  assert(app.text.includes("window.__CDB_SWARM_INTERACTIVE_READY__=true"), '/swarm/app.js missing interactive-ready marker');
  assert(app.text.includes("fetch('/api/swarm/preflight'"), '/swarm/app.js is not wired to canonical entitlement preflight');
  assert(app.text.includes("fetch('/api/swarm/readiness'"), '/swarm/app.js is not wired to mission readiness');
  assert(app.text.includes('NOT_APPLICABLE'), '/swarm/app.js missing semantic NOT_APPLICABLE handling');
  assert(app.text.includes('focusAgentForExecutive'), '/swarm/app.js missing event-driven executive auto-focus');
  assert(app.text.includes('!preflight.eligible||preflight.key!==key'), '/swarm/app.js does not enforce verified-key launch locking');
  assert(!app.text.includes('};fxForMissionEvent(ev)'), '/swarm/app.js contains a top-level event FX call that aborts browser bootstrap');
  assert(app.text.includes('hydrateHealth()'), '/swarm/app.js missing runtime hydration');
  assert(app.text.includes('run.onclick=async()=>'), '/swarm/app.js missing live-mission button handler');
  assert(app.text.includes('loadHistoryBtn.onclick=async()=>'), '/swarm/app.js missing mission-history button handler');
  assert(app.text.includes('updateOpsTelemetry()'), '/swarm/app.js missing state-driven operations telemetry');
  assert(app.text.includes('setMeshNode(ev.agent_id'), '/swarm/app.js missing state-driven mesh visualization');
  assert(app.text.includes("setText('eventCount'"), '/swarm/app.js missing real event-sequence telemetry');
  assert(app.text.includes('function triggerLaunchSequence()'), '/swarm/app.js missing cinematic launch controller');
  assert(app.text.includes('function fxForMissionEvent(ev)'), '/swarm/app.js missing real-event cinematic state hook');
  assert(app.text.includes('function emitCinematicFx(kind,el,intensity)'), '/swarm/app.js missing cinematic particle/shockwave renderer');
  assert(app.text.includes("matchMedia('(prefers-reduced-motion: reduce)')"), '/swarm/app.js missing reduced-motion runtime guard');
  assert(app.text.includes("fetch('/api/swarm/client-context'"), '/swarm/app.js missing coarse location hydration');
  assert(app.text.includes('function hydrateClockContext()'), '/swarm/app.js missing global clock context controller');
  assert(app.text.includes('setInterval(updateClock,1000)'), '/swarm/app.js missing one-second LED clock cadence');
  assert(app.text.includes("setText('streamState','SSE · CONNECTING'"), '/swarm/app.js missing explicit SSE connecting state');
  assert(app.text.includes("setText('streamState','SSE · STREAMING'"), '/swarm/app.js missing explicit SSE streaming state');
  assert(app.text.includes("setText('streamState','SSE · CLOSED'"), '/swarm/app.js missing explicit SSE terminal state');
  assert(!app.text.includes('localStorage'), '/swarm/app.js must not persist credentials in localStorage');
  assert(!app.text.includes('sessionStorage'), '/swarm/app.js must not persist credentials in sessionStorage');
  try {
    new Function(app.text);
  } catch (error) {
    throw new Error(`/swarm/app.js browser bundle does not parse: ${error.message}`);
  }

  logPass('customer UI', 'HTML + external browser controller reachable and executable');
}

async function validateClientContext(baseUrl) {
  const { response, text } = await getText(`${baseUrl}/api/swarm/client-context`);
  assert(response.status === 200, `/api/swarm/client-context returned HTTP ${response.status}`);
  let body;
  try { body = JSON.parse(text); } catch { throw new Error('/api/swarm/client-context did not return JSON'); }
  assert(body?.status === 'ok', 'client-context status is not ok');
  assert(body?.data && typeof body.data === 'object', 'client-context data is missing');
  assert(typeof body.data.timezone === 'string' && body.data.timezone.length > 0, 'client-context timezone is missing');
  assert(!Object.prototype.hasOwnProperty.call(body.data, 'ip'), 'client-context must not expose client IP');
  assert(!Object.prototype.hasOwnProperty.call(body.data, 'latitude'), 'client-context must not expose latitude');
  assert(!Object.prototype.hasOwnProperty.call(body.data, 'longitude'), 'client-context must not expose longitude');
  logPass('global clock context', `source=${body.data.source} city=${body.data.city || 'n/a'} country=${body.data.country_code || 'n/a'} timezone=${body.data.timezone}`);
}

async function validateLiveMission(baseUrl, apiKey) {
  assert(apiKey, 'SENTINEL_API_KEY is required with --live-mission');
  const preflight = await getJson(`${baseUrl}/api/swarm/preflight`, {
    headers: { 'X-API-Key': apiKey, 'X-Request-ID': 'release-preflight-' + crypto.randomUUID() },
  });
  assert(preflight.response.status === 200, `paid SWARM preflight returned HTTP ${preflight.response.status}`);
  assert(preflight.body?.eligible === true, `paid SWARM preflight denied launch: ${preflight.body?.reason || preflight.body?.error || 'unknown'}`);
  assert(['PRO', 'ENTERPRISE', 'MSSP'].includes(preflight.body?.entitlement?.tier), `unexpected SWARM entitlement tier: ${preflight.body?.entitlement?.tier}`);
  logPass('paid entitlement preflight', `tier=${preflight.body.entitlement.tier}`);

  let selected = {
    value: process.env.SENTINEL_SWARM_TEST_IOC || '8.8.8.8',
    type: process.env.SENTINEL_SWARM_TEST_IOC_TYPE || 'ipv4',
  };
  if (String(process.env.SENTINEL_SWARM_DISCOVER_FULL_FABRIC || '').toLowerCase() === 'true') {
    selected = await discoverFullFabricCandidate(baseUrl, apiKey);
  }

  const readinessRequestId = `release-readiness-${crypto.randomUUID()}`;
  const readinessIoc = selected.value;
  const readinessType = selected.type;
  const readiness = await getJson(`${baseUrl}/api/swarm/readiness`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'x-request-id': readinessRequestId,
    },
    body: JSON.stringify({ ioc_value: readinessIoc, ioc_type: readinessType, mission_profile: 'AUTO' }),
  });
  assert(readiness.response.status === 200, `mission readiness returned HTTP ${readiness.response.status}`);
  assert(readiness.body?.mission_dispatch === false, 'mission readiness unexpectedly reports mission dispatch');
  assert(readiness.body?.canonical_request_consumed === true, 'mission readiness cost disclosure missing');
  assert(typeof readiness.body?.readiness?.mission_quality === 'string', 'readiness mission_quality missing');
  assert(Number(readiness.body?.readiness?.fleet_agents) === 8, 'readiness fleet size mismatch');
  logPass('paid mission readiness', `quality=${readiness.body.readiness.mission_quality} ready=${readiness.body.readiness.ready_agents}/${readiness.body.readiness.total_agents}`);

  const requestId = `release-${crypto.randomUUID()}`;
  const iocValue = selected.value;
  const iocType = selected.type;

  const { response, text } = await getText(`${baseUrl}/api/swarm/run`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'x-request-id': requestId,
    },
    body: JSON.stringify({ ioc_value: iocValue, ioc_type: iocType, mission_profile: 'AUTO' }),
  });

  assert(response.status === 200, `/api/swarm/run returned HTTP ${response.status}: ${text.slice(0, 240)}`);
  const events = parseSse(text);
  assert(events.length > 0, 'swarm SSE returned no events');

  const terminal = events.find((event) => event.event_type === 'mission.completed');
  if (!terminal) {
    const terminalFailure = [...events].reverse().find((event) =>
      event?.event_type === 'mission.rejected' || event?.event_type === 'mission.failed'
    );
    const observed = [...new Set(events.map((event) => event?.event_type).filter(Boolean))].join(', ');
    const detail = terminalFailure
      ? [
          `event_type=${terminalFailure.event_type}`,
          `state=${terminalFailure.state || 'unknown'}`,
          `canonical_status=${terminalFailure.canonical_status ?? 'n/a'}`,
          `mesh_certified=${terminalFailure.mesh_certified ?? 'n/a'}`,
          `error=${terminalFailure.error || terminalFailure.canonical_error?.error || 'n/a'}`,
          `message=${terminalFailure.message || terminalFailure.canonical_error?.message || 'n/a'}`,
        ].join(' ')
      : `observed_event_types=${observed || 'none'}`;
    throw new Error(`mission.completed was not emitted — ${detail}`);
  }
  assert(terminal.mesh_certified === true, 'mission completed without mesh_certified=true');
  assert(typeof terminal.mission_id === 'string' && terminal.mission_id.length > 0, 'mission_id missing');
  assert(typeof terminal.execution_id === 'string' && terminal.execution_id.length > 0, 'execution_id missing');
  assert(typeof terminal.correlation_id === 'string' && terminal.correlation_id.length > 0, 'correlation_id missing');
  assert(typeof terminal.mission_quality === 'string' && terminal.mission_quality.length > 0, 'mission_quality missing from terminal event');
  if (String(process.env.SENTINEL_SWARM_REQUIRE_FULL_FABRIC || '').toLowerCase() === 'true') {
    assert(terminal.mission_quality === 'FULL_FABRIC_COMPLETE', `expected FULL_FABRIC_COMPLETE, got ${terminal.mission_quality}`);
    assert(terminal.result?.llm_enhanced === true, 'full-fabric certification requires LLM-enhanced synthesis');
  }
  assert(terminal.evidence_graph?.schema === 'cdb.swarm.evidence-graph.v1', 'terminal evidence graph schema missing');
  assert(Number(terminal.evidence_graph?.node_count) > 0, 'terminal evidence graph node count missing');
  assert(Number(terminal.evidence_graph?.edge_count) >= 0, 'terminal evidence graph edge count missing');

  const seenAgents = new Set(events.map((event) => event.agent_id).filter(Boolean));
  for (const agent of EXPECTED_AGENTS) assert(seenAgents.has(agent), `missing live agent events for ${agent}`);
  const badEvents = events.filter((event) => event.state === 'FAILED' || event.basis === 'unconfigured');
  const legacySkipped = events.filter((event) => event.state === 'SKIPPED' || event.event_type === 'agent.skipped');
  assert(legacySkipped.length === 0, 'V4.47 mission emitted legacy SKIPPED semantics');
  assert(badEvents.length === 0, `mission contains FAILED/unconfigured agent events: ${badEvents.map((e) => e.agent_id || e.event_type).join(', ')}`);

  logPass('live mesh-certified mission', `mission=${terminal.mission_id} events=${events.length} agents=${seenAgents.size}`);

  const headers = { 'x-api-key': apiKey };
  const readback = await getJson(`${baseUrl}/api/swarm/mission/${encodeURIComponent(terminal.mission_id)}`, { headers });
  assert(readback.response.status === 200, `mission read-back returned HTTP ${readback.response.status}`);
  const persistedId = readback.body?.data?.mission_id ?? readback.body?.mission_id;
  assert(persistedId === terminal.mission_id, 'persisted mission_id does not match live mission');
  const persisted = readback.body?.data ?? readback.body;
  assert(persisted?.mission_quality === terminal.mission_quality, 'persisted mission quality does not match terminal event');
  assert(persisted?.evidence_graph?.schema === 'cdb.swarm.evidence-graph.v1', 'persisted evidence graph missing');
  logPass('durable mission read-back', terminal.mission_id);

  const jsonReport = await getText(`${baseUrl}/api/swarm/mission/${encodeURIComponent(terminal.mission_id)}/report?format=json`, { headers });
  assert(jsonReport.response.status === 200, `JSON report export returned HTTP ${jsonReport.response.status}`);
  assert((jsonReport.response.headers.get('content-type') || '').includes('json'), 'JSON report has unexpected content-type');
  logPass('JSON evidence export');

  const stixReport = await getText(`${baseUrl}/api/swarm/mission/${encodeURIComponent(terminal.mission_id)}/report?format=stix21`, { headers });
  assert(stixReport.response.status === 200, `STIX 2.1 export returned HTTP ${stixReport.response.status}`);
  const stix = JSON.parse(stixReport.text);
  assert(stix?.type === 'bundle' && Array.isArray(stix?.objects), 'STIX export is not a Bundle');
  assert(!Object.prototype.hasOwnProperty.call(stix, 'spec_version'), 'STIX Bundle must not carry STIX Object spec_version');
  const stixIndicator = stix.objects.find((object) => object?.type === 'indicator');
  assert(stixIndicator?.spec_version === '2.1', 'STIX Indicator is not spec_version 2.1');
  assert(typeof stixIndicator?.x_sentinel_mission_id === 'string', 'STIX Indicator missing top-level x_sentinel mission property');
  assert(!Object.prototype.hasOwnProperty.call(stixIndicator, 'custom_properties'), 'STIX custom properties must not be nested under custom_properties');
  logPass('STIX 2.1 evidence export');
  return {
    mission_id: terminal.mission_id,
    execution_id: terminal.execution_id,
    correlation_id: terminal.correlation_id,
    mission_quality: terminal.mission_quality,
    ioc_value: iocValue,
    ioc_type: iocType,
  };
}

async function validatePreflightContract(baseUrl) {
  const { response, body } = await getJson(`${baseUrl}/api/swarm/preflight`);
  assert(response.status === 401, `unauthenticated /api/swarm/preflight returned HTTP ${response.status}, expected 401`);
  assert(body?.error === 'authentication_required', 'unauthenticated SWARM preflight did not fail closed');

  const readiness = await getJson(`${baseUrl}/api/swarm/readiness`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
  });
  assert(readiness.response.status === 401, `unauthenticated /api/swarm/readiness returned HTTP ${readiness.response.status}, expected 401`);
  assert(readiness.body?.error === 'authentication_required', 'mission readiness did not fail closed on authentication');

  logPass('entitlement/readiness fail-closed contract');
}

async function main() {
  const baseUrl = cleanBaseUrl(argValue('--base-url') || process.env.SENTINEL_SWARM_BASE_URL || DEFAULT_BASE_URL);
  const liveMission = hasFlag('--live-mission');

  console.log('CYBERDUDEBIVASH SENTINEL APEX — SUPER AGENT SWARM production release validation');
  console.log(`Target: ${baseUrl}`);
  console.log(`Live paid mission: ${liveMission ? 'ENABLED' : 'SKIPPED (pass --live-mission + SENTINEL_API_KEY to certify end-to-end)'}`);

  await validateHealth(baseUrl);
  await validateUi(baseUrl);
  await validateClientContext(baseUrl);
  await validatePreflightContract(baseUrl);
  let liveResult = null;
  if (liveMission) liveResult = await validateLiveMission(baseUrl, process.env.SENTINEL_API_KEY);

  const resultPath = String(process.env.SENTINEL_SWARM_RESULT_PATH || '').trim();
  if (resultPath && liveResult) {
    const { writeFile } = await import('node:fs/promises');
    await writeFile(resultPath, JSON.stringify(liveResult, null, 2) + '\n', { encoding: 'utf8' });
    logPass('live certification result artifact', resultPath);
  }

  console.log('RELEASE VALIDATION: PASS');
}

main().catch((error) => {
  console.error(`RELEASE VALIDATION: FAIL — ${error.message}`);
  process.exitCode = 1;
});
