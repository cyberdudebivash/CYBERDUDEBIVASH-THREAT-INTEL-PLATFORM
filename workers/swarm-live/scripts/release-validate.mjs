#!/usr/bin/env node

const DEFAULT_BASE_URL = 'https://intel.cyberdudebivash.com';
const EXPECTED_SERVICE = 'sentinel-apex-swarm-live';
const EXPECTED_PROTOCOL = 'cdb.swarm.v1';
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

async function validateHealth(baseUrl) {
  const { response, body } = await getJson(`${baseUrl}/api/swarm/health`);
  assert(response.status === 200, `/api/swarm/health returned HTTP ${response.status}`);
  assert(body?.status === 'ok', 'swarm health status is not ok');
  assert(body?.service === EXPECTED_SERVICE, `unexpected service: ${body?.service}`);
  assert(body?.protocol === EXPECTED_PROTOCOL, `unexpected protocol: ${body?.protocol}`);
  assert(Number(body?.agents) === EXPECTED_AGENTS.size, `expected ${EXPECTED_AGENTS.size} agents, got ${body?.agents}`);
  assert(body?.persistence?.kv_bound === true, 'SWARM_MISSIONS_KV is not bound; durable mission lifecycle is NOT production-ready');
  logPass('live health', `service=${body.service} protocol=${body.protocol} agents=${body.agents} kv_bound=true`);
  return body;
}

async function validateUi(baseUrl) {
  const { response, text } = await getText(`${baseUrl}/swarm/`);
  assert(response.status === 200, `/swarm/ returned HTTP ${response.status}`);
  for (const marker of ['SUPER AGENT SWARM', 'Mission History', 'RUN LIVE SWARM']) {
    assert(text.includes(marker), `/swarm/ missing required UI marker: ${marker}`);
  }
  assert(!text.includes('DERIVED VIEW'), '/swarm/ still exposes DERIVED VIEW agents');
  logPass('customer UI', 'reachable and current swarm markers present');
}

async function validateLiveMission(baseUrl, apiKey) {
  assert(apiKey, 'SENTINEL_API_KEY is required with --live-mission');
  const requestId = `release-${crypto.randomUUID()}`;
  const iocValue = process.env.SENTINEL_SWARM_TEST_IOC || '8.8.8.8';
  const iocType = process.env.SENTINEL_SWARM_TEST_IOC_TYPE || 'ipv4';

  const { response, text } = await getText(`${baseUrl}/api/swarm/run`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'x-request-id': requestId,
    },
    body: JSON.stringify({ ioc_value: iocValue, ioc_type: iocType }),
  });

  assert(response.status === 200, `/api/swarm/run returned HTTP ${response.status}: ${text.slice(0, 240)}`);
  const events = parseSse(text);
  assert(events.length > 0, 'swarm SSE returned no events');

  const terminal = events.find((event) => event.event_type === 'mission.completed');
  assert(terminal, 'mission.completed was not emitted');
  assert(terminal.mesh_certified === true, 'mission completed without mesh_certified=true');
  assert(typeof terminal.mission_id === 'string' && terminal.mission_id.length > 0, 'mission_id missing');
  assert(typeof terminal.execution_id === 'string' && terminal.execution_id.length > 0, 'execution_id missing');
  assert(typeof terminal.correlation_id === 'string' && terminal.correlation_id.length > 0, 'correlation_id missing');

  const seenAgents = new Set(events.map((event) => event.agent_id).filter(Boolean));
  for (const agent of EXPECTED_AGENTS) assert(seenAgents.has(agent), `missing live agent events for ${agent}`);
  const badEvents = events.filter((event) => event.state === 'FAILED' || event.basis === 'unconfigured');
  assert(badEvents.length === 0, `mission contains FAILED/unconfigured agent events: ${badEvents.map((e) => e.agent_id || e.event_type).join(', ')}`);

  logPass('live mesh-certified mission', `mission=${terminal.mission_id} events=${events.length} agents=${seenAgents.size}`);

  const headers = { 'x-api-key': apiKey };
  const readback = await getJson(`${baseUrl}/api/swarm/mission/${encodeURIComponent(terminal.mission_id)}`, { headers });
  assert(readback.response.status === 200, `mission read-back returned HTTP ${readback.response.status}`);
  const persistedId = readback.body?.data?.mission_id ?? readback.body?.mission_id;
  assert(persistedId === terminal.mission_id, 'persisted mission_id does not match live mission');
  logPass('durable mission read-back', terminal.mission_id);

  const jsonReport = await getText(`${baseUrl}/api/swarm/mission/${encodeURIComponent(terminal.mission_id)}/report?format=json`, { headers });
  assert(jsonReport.response.status === 200, `JSON report export returned HTTP ${jsonReport.response.status}`);
  assert((jsonReport.response.headers.get('content-type') || '').includes('json'), 'JSON report has unexpected content-type');
  logPass('JSON evidence export');

  const stixReport = await getText(`${baseUrl}/api/swarm/mission/${encodeURIComponent(terminal.mission_id)}/report?format=stix21`, { headers });
  assert(stixReport.response.status === 200, `STIX 2.1 export returned HTTP ${stixReport.response.status}`);
  const stix = JSON.parse(stixReport.text);
  assert(stix?.type === 'bundle' && stix?.spec_version === '2.1', 'STIX export is not a STIX 2.1 bundle');
  logPass('STIX 2.1 evidence export');
}

async function main() {
  const baseUrl = cleanBaseUrl(argValue('--base-url') || process.env.SENTINEL_SWARM_BASE_URL || DEFAULT_BASE_URL);
  const liveMission = hasFlag('--live-mission');

  console.log('CYBERDUDEBIVASH SENTINEL APEX — SUPER AGENT SWARM production release validation');
  console.log(`Target: ${baseUrl}`);
  console.log(`Live paid mission: ${liveMission ? 'ENABLED' : 'SKIPPED (pass --live-mission + SENTINEL_API_KEY to certify end-to-end)'}`);

  await validateHealth(baseUrl);
  await validateUi(baseUrl);
  if (liveMission) await validateLiveMission(baseUrl, process.env.SENTINEL_API_KEY);

  console.log('RELEASE VALIDATION: PASS');
}

main().catch((error) => {
  console.error(`RELEASE VALIDATION: FAIL — ${error.message}`);
  process.exitCode = 1;
});
