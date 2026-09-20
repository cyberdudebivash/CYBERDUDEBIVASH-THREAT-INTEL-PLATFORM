#!/usr/bin/env node

/**
 * CYBERDUDEBIVASH SENTINEL APEX — V4.47.0 POST-MISSION CERTIFICATION
 *
 * Read-only certification. NEVER dispatches /api/swarm/run.
 * Required immediately after the one filmed mission to prove persistence,
 * ownership, mission quality, evidence graph, history, and all export formats.
 */

const DEFAULT_BASE_URL = 'https://intel.cyberdudebivash.com';
const EXPECTED_VERSION = '4.47.0';
const EXPECTED_AGENT_IDS = Object.freeze([
  'ioc-hunter',
  'cve-intelligence',
  'threat-hunter',
  'attack-mapper',
  'siem-defender',
  'ir-playbook',
  'exposure-analyst',
  'risk-synthesizer',
]);
const HARD_BLOCKED_PATHS = new Set(['/api/swarm/run']);

const baseUrl = cleanBaseUrl(process.env.SWARM_BASE_URL || DEFAULT_BASE_URL);
const apiKey = String(process.env.SENTINEL_API_KEY || '').trim();
const missionId = String(process.env.DEMO_MISSION_ID || '').trim();
const requireFullFabric = String(process.env.POSTDEMO_REQUIRE_FULL_FABRIC || 'true').toLowerCase() !== 'false';

const results = [];
let requestCount = 0;
let missionDispatchCount = 0;

function cleanBaseUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(url.hostname)) {
    throw new Error('SWARM_BASE_URL must use HTTPS except for localhost');
  }
  return url.toString().replace(/\/$/, '');
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function pass(name, detail = '') {
  results.push({ name, status: 'PASS', detail });
  console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`);
}

function fail(name, detail) {
  results.push({ name, status: 'FAIL', detail: String(detail || '') });
  console.error(`FAIL  ${name} — ${detail}`);
}

async function check(name, fn) {
  try {
    const detail = await fn();
    pass(name, detail || '');
    return true;
  } catch (error) {
    fail(name, error?.message || error);
    return false;
  }
}

function headers(extra = {}) {
  return {
    accept: 'application/json',
    'x-api-key': apiKey,
    'x-request-id': `postdemo-${crypto.randomUUID()}`,
    ...extra,
  };
}

async function guardedFetch(path, init = {}) {
  const url = new URL(path, baseUrl);
  const method = String(init.method || 'GET').toUpperCase();
  if (HARD_BLOCKED_PATHS.has(url.pathname)) {
    missionDispatchCount += 1;
    throw new Error(`mission-safety violation: ${method} ${url.pathname}`);
  }
  if (method !== 'GET') throw new Error(`post-demo certification is read-only; blocked ${method} ${url.pathname}`);

  requestCount += 1;
  const started = performance.now();
  const response = await fetch(url, {
    ...init,
    method: 'GET',
    redirect: 'manual',
    cache: 'no-store',
    signal: AbortSignal.timeout(20000),
  });
  const text = await response.text();
  return { response, text, elapsedMs: Math.round(performance.now() - started) };
}

async function getJson(path, init = {}) {
  const out = await guardedFetch(path, init);
  let body;
  try { body = out.text ? JSON.parse(out.text) : {}; }
  catch { throw new Error(`${path} returned non-JSON HTTP ${out.response.status}`); }
  return { ...out, body };
}

function hasNoCredentialEcho(value) {
  return !apiKey || !String(value).includes(apiKey);
}

function specialistState(record, id) {
  return record?.specialists?.[id]?.state || null;
}

async function main() {
  console.log('CYBERDUDEBIVASH SENTINEL APEX — V4.47.0 POST-MISSION CERTIFICATION');
  console.log(`BASE     ${baseUrl}`);
  console.log(`MISSION  ${missionId || '<missing>'}`);
  console.log('MODE     read-only / no mission dispatch\n');

  assert(apiKey, 'SENTINEL_API_KEY is required');
  assert(missionId, 'DEMO_MISSION_ID is required');
  assert(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(missionId), 'DEMO_MISSION_ID has invalid shape');

  let record = null;

  await check('live health/version', async () => {
    const { response, body, elapsedMs } = await getJson('/api/swarm/health');
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(body?.version === EXPECTED_VERSION, `version=${body?.version}`);
    assert(body?.capabilities?.mission_quality === true, 'mission quality capability missing');
    assert(body?.capabilities?.evidence_graph === true, 'evidence graph capability missing');
    return `V${body.version} · ${elapsedMs}ms`;
  });

  await check('owned durable mission read-back', async () => {
    const { response, body, text, elapsedMs } = await getJson(
      `/api/swarm/mission/${encodeURIComponent(missionId)}`,
      { headers: headers() },
    );
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(body?.status === 'ok', `status=${body?.status}`);
    assert(body?.data?.mission_id === missionId, 'mission id mismatch');
    assert(hasNoCredentialEcho(text), 'credential reflected in mission evidence');
    record = body.data;
    assert(record.status === 'COMPLETED', `mission status=${record.status}`);
    assert(record.ioc && typeof record.ioc === 'object', 'persisted IOC missing');
    assert(record.specialists && typeof record.specialists === 'object', 'specialist evidence missing');
    return `${record.mission_quality || 'unclassified'} · ${elapsedMs}ms`;
  });

  await check('mission quality / full-fabric contract', async () => {
    assert(record, 'mission record unavailable');
    assert(typeof record.mission_quality === 'string' && record.mission_quality, 'mission_quality missing');

    const states = Object.fromEntries(
      EXPECTED_AGENT_IDS.map((id) => [id, specialistState(record, id)])
    );
    for (const [id, state] of Object.entries(states)) {
      assert(state, `missing specialist state for ${id}`);
    }

    if (requireFullFabric) {
      assert(record.mission_quality === 'FULL_FABRIC_COMPLETE', `expected FULL_FABRIC_COMPLETE, got ${record.mission_quality}`);
      for (const [id, state] of Object.entries(states)) {
        assert(state === 'COMPLETED', `${id} state=${state}, expected COMPLETED`);
      }
      const synth = record.specialists['risk-synthesizer']?.result;
      assert(synth?.llm_enhanced === true, 'risk synthesizer was not LLM enhanced');
      assert(typeof synth?.ai_narrative === 'string' && synth.ai_narrative.trim().length >= 40, 'AI narrative missing/too short');
    }

    return Object.entries(states).map(([id, state]) => `${id}=${state}`).join(' · ');
  });

  await check('evidence graph provenance', async () => {
    const graph = record?.evidence_graph;
    assert(graph?.schema === 'cdb.swarm.evidence-graph.v1', `graph schema=${graph?.schema}`);
    assert(Number(graph?.node_count) > 0, 'evidence graph nodes missing');
    assert(Number(graph?.edge_count) > 0, 'evidence graph edges missing');
    assert(Array.isArray(graph?.nodes) && graph.nodes.length === graph.node_count, 'evidence graph node count mismatch');
    assert(Array.isArray(graph?.edges) && graph.edges.length === graph.edge_count, 'evidence graph edge count mismatch');
    assert(graph.nodes.some((n) => n?.type === 'observable'), 'observable provenance node missing');
    assert(graph.nodes.some((n) => n?.type === 'agent_execution'), 'agent execution provenance nodes missing');
    return `${graph.node_count} nodes · ${graph.edge_count} edges`;
  });

  await check('mission timing / operational metrics', async () => {
    assert(Number.isFinite(Number(record.duration_ms)) && Number(record.duration_ms) >= 0, 'mission duration missing');
    const metrics = record.metrics;
    assert(metrics && typeof metrics === 'object', 'mission metrics missing');
    assert(Number(metrics.total) === 8, `metrics.total=${metrics.total}`);
    if (requireFullFabric) {
      assert(Number(metrics.completed) === 8, `completed=${metrics.completed}`);
      assert(Number(metrics.failed) === 0, `failed=${metrics.failed}`);
      assert(Number(metrics.denied) === 0, `denied=${metrics.denied}`);
      assert(Number(metrics.unavailable) === 0, `unavailable=${metrics.unavailable}`);
    }
    return `duration=${record.duration_ms}ms · completed=${metrics.completed}/${metrics.total}`;
  });

  await check('mission history contains filmed mission', async () => {
    const { response, body } = await getJson('/api/swarm/missions?limit=100', { headers: headers() });
    assert(response.status === 200, `HTTP ${response.status}`);
    const missions = body?.data?.missions;
    assert(Array.isArray(missions), 'history missions missing');
    assert(missions.some((m) => m?.mission_id === missionId), 'filmed mission missing from credential-scoped history');
    return `${missions.length} mission(s) · filmed mission present`;
  });

  await check('Markdown evidence export', async () => {
    const out = await guardedFetch(
      `/api/swarm/mission/${encodeURIComponent(missionId)}/report`,
      { headers: headers() },
    );
    assert(out.response.status === 200, `HTTP ${out.response.status}`);
    assert((out.response.headers.get('content-type') || '').includes('text/markdown'), 'Markdown content-type wrong');
    assert(out.text.includes(missionId), 'Markdown report missing mission id');
    assert(hasNoCredentialEcho(out.text), 'credential reflected in Markdown report');
    return `${out.text.length} bytes`;
  });

  await check('JSON evidence export', async () => {
    const { response, body, text } = await getJson(
      `/api/swarm/mission/${encodeURIComponent(missionId)}/report?format=json`,
      { headers: headers() },
    );
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(body?.data?.mission_id === missionId, 'JSON export mission id mismatch');
    assert(hasNoCredentialEcho(text), 'credential reflected in JSON export');
    return 'mission identity + credential hygiene PASS';
  });

  await check('STIX 2.1 evidence export', async () => {
    const out = await guardedFetch(
      `/api/swarm/mission/${encodeURIComponent(missionId)}/report?format=stix21`,
      { headers: headers() },
    );
    assert(out.response.status === 200, `HTTP ${out.response.status}`);
    assert((out.response.headers.get('content-type') || '').includes('application/stix+json'), 'STIX content-type wrong');
    const bundle = JSON.parse(out.text);
    assert(bundle?.type === 'bundle', 'STIX object is not a bundle');
    assert(Array.isArray(bundle?.objects) && bundle.objects.length > 0, 'STIX objects missing');
    assert(bundle.objects.some((o) => o?.type === 'indicator'), 'STIX indicator missing');
    assert(hasNoCredentialEcho(out.text), 'credential reflected in STIX export');
    return `${bundle.objects.length} STIX object(s)`;
  });

  assert(missionDispatchCount === 0, 'post-demo certification attempted a mission dispatch');

  const failed = results.filter((r) => r.status === 'FAIL');
  console.log('\n============================================================');
  console.log('POST-MISSION CERTIFICATION SUMMARY');
  console.log('============================================================');
  console.log(`PASS     ${results.length - failed.length}/${results.length}`);
  console.log(`FAIL     ${failed.length}/${results.length}`);
  console.log(`REQUESTS ${requestCount}`);
  console.log(`MISSIONS DISPATCHED ${missionDispatchCount}`);
  console.log('============================================================');

  if (failed.length) {
    console.error('\nHOLD — mission evidence did not satisfy post-demo certification.');
    process.exitCode = 1;
    return;
  }

  console.log('\nPOST-MISSION CERTIFIED — persistence, quality, provenance, history and exports are verified.');
}

main().catch((error) => {
  console.error(`\nFATAL POST-MISSION CERTIFICATION ERROR: ${error?.message || error}`);
  console.error('HOLD — post-mission evidence certification incomplete.');
  process.exitCode = 1;
});
