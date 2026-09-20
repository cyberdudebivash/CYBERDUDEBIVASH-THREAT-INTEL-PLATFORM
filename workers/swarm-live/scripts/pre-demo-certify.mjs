#!/usr/bin/env node

/**
 * CYBERDUDEBIVASH SENTINEL APEX — SUPER AGENT SWARM
 * P0 PRE-DEMO PRODUCTION CERTIFICATION
 *
 * Mission-safety invariant:
 *   - This script NEVER calls /api/swarm/run.
 *   - It may exercise canonical correlation and synthesis directly so every
 *     backend dependency is proven before the filmed SWARM mission.
 *   - Mission history is snapshotted before/after and must remain unchanged.
 */

const DEFAULT_BASE_URL = 'https://intel.cyberdudebivash.com';
const EXPECTED_VERSION = '4.46.6';
const EXPECTED_PROTOCOL = 'cdb.swarm.v1';
const EXPECTED_SERVICE = 'sentinel-apex-swarm-live';
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
const SAFE_POST_PATHS = new Set([
  '/api/intel/correlate',
  '/api/v1/swarm-synthesis',
]);
const HARD_BLOCKED_PATHS = new Set([
  '/api/swarm/run',
]);
const MIN_DAILY_QUOTA_REMAINING = Number(process.env.PREDEMO_MIN_DAILY_QUOTA || 16);
const PUBLIC_TIMEOUT_MS = Number(process.env.PREDEMO_PUBLIC_TIMEOUT_MS || 12000);
const BACKEND_TIMEOUT_MS = Number(process.env.PREDEMO_BACKEND_TIMEOUT_MS || 25000);

const baseUrl = cleanBaseUrl(process.env.SWARM_BASE_URL || DEFAULT_BASE_URL);
const apiKey = String(process.env.SENTINEL_API_KEY || '').trim();
const publicOnly = process.argv.includes('--public-only');
const strictHistory = !process.argv.includes('--allow-empty-history');

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

function pass(name, detail = '') {
  results.push({ name, status: 'PASS', detail });
  console.log(`PASS  ${name}${detail ? ` — ${detail}` : ''}`);
}

function fail(name, detail) {
  results.push({ name, status: 'FAIL', detail: String(detail || '') });
  console.error(`FAIL  ${name} — ${detail}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
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

function withTimeout(timeoutMs) {
  return AbortSignal.timeout(Math.max(1000, timeoutMs));
}

async function guardedFetch(path, init = {}, timeoutMs = PUBLIC_TIMEOUT_MS) {
  const url = new URL(path, baseUrl);
  const method = String(init.method || 'GET').toUpperCase();

  if (HARD_BLOCKED_PATHS.has(url.pathname)) {
    missionDispatchCount += 1;
    throw new Error(`mission-safety violation: ${method} ${url.pathname} is forbidden in pre-demo certification`);
  }
  if (method !== 'GET' && !SAFE_POST_PATHS.has(url.pathname)) {
    throw new Error(`unsafe pre-demo method/path blocked: ${method} ${url.pathname}`);
  }

  requestCount += 1;
  const started = performance.now();
  const response = await fetch(url, {
    redirect: 'manual',
    cache: 'no-store',
    ...init,
    signal: withTimeout(timeoutMs),
  });
  const elapsedMs = Math.round(performance.now() - started);
  const text = await response.text();
  return { response, text, elapsedMs, url: url.toString() };
}

async function getJson(path, init = {}, timeoutMs = PUBLIC_TIMEOUT_MS) {
  const out = await guardedFetch(path, init, timeoutMs);
  let body;
  try {
    body = out.text ? JSON.parse(out.text) : {};
  } catch {
    throw new Error(`${path} returned non-JSON HTTP ${out.response.status}`);
  }
  return { ...out, body };
}

function paidHeaders(extra = {}) {
  assert(apiKey, 'SENTINEL_API_KEY is required for full pre-demo certification');
  return {
    accept: 'application/json',
    'x-api-key': apiKey,
    'x-request-id': `predemo-${crypto.randomUUID()}`,
    ...extra,
  };
}

function hasNoCredentialEcho(value) {
  return !apiKey || !String(value).includes(apiKey);
}

function getPath(obj, path) {
  return path.split('.').reduce((acc, key) => acc == null ? undefined : acc[key], obj);
}

function flattenStrings(value, out = []) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) flattenStrings(v, out);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) flattenStrings(v, out);
  return out;
}

function firstMatchingString(value, regex) {
  for (const s of flattenStrings(value)) {
    const m = String(s).match(regex);
    if (m) return m[0];
  }
  return null;
}

function pickReportId(item) {
  for (const key of ['report_id', 'intel_id', 'id', 'uid']) {
    const value = item?.[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function pickActor(value) {
  for (const key of ['actor_tag', 'actor', 'threat_actor', 'attribution']) {
    const candidate = value?.[key];
    if (typeof candidate === 'string' && candidate.trim() && candidate !== 'UNATTRIBUTED') return candidate.trim();
  }
  return firstMatchingString(value, /\bAPT\d{1,3}\b/i);
}

function pickTechnique(value) {
  return firstMatchingString(value, /\bT\d{4}(?:\.\d{3})?\b/i);
}

function pickCve(value) {
  return firstMatchingString(value, /\bCVE-\d{4}-\d{4,}\b/i);
}

function isObservable(value) {
  const s = String(value || '').trim();
  if (!s || s.length > 256) return false;
  return (
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(s) ||
    /^https?:\/\//i.test(s) ||
    /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s) ||
    /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(s)
  );
}

function pickObservable(item) {
  const preferredKeys = ['ioc', 'ioc_value', 'indicator', 'observable', 'domain', 'url', 'ip', 'ipv4', 'hash'];
  for (const key of preferredKeys) {
    const value = item?.[key];
    if (typeof value === 'string' && isObservable(value)) return value.trim();
    if (Array.isArray(value)) {
      const found = value.find((v) => typeof v === 'string' && isObservable(v));
      if (found) return found.trim();
    }
  }
  return flattenStrings(item).find(isObservable) || null;
}

function inferIocType(value) {
  const s = String(value || '');
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)) return 'ipv4';
  if (/^https?:\/\//i.test(s)) return 'url';
  if (/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(s)) return 'hash';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) return 'domain';
  return 'auto';
}

function extractCorrelationDependencies(correlation) {
  const matches = Array.isArray(correlation?.matches) ? correlation.matches : [];
  const reportId = matches.map(pickReportId).find(Boolean) || null;
  const cve = matches.map(pickCve).find(Boolean) || null;
  const actor = matches.map(pickActor).find(Boolean) || null;
  const technique = matches.map(pickTechnique).find(Boolean) || null;
  return { reportId, cve, actor, technique };
}

async function snapshotMissionIds() {
  const { response, body } = await getJson('/api/swarm/missions?limit=100', { headers: paidHeaders() });
  assert(response.status === 200, `mission history returned HTTP ${response.status}`);
  assert(body?.status === 'ok', 'mission history status is not ok');
  assert(Array.isArray(body?.data?.missions), 'mission history missions array missing');
  return body.data.missions;
}

async function main() {
  console.log('CYBERDUDEBIVASH SENTINEL APEX — V4.46.6 PRE-DEMO CERTIFICATION');
  console.log(`BASE  ${baseUrl}`);
  console.log('MODE  mission-safe / no /api/swarm/run dispatch\n');

  if (!publicOnly && !apiKey) {
    throw new Error('SENTINEL_API_KEY is required. Use --public-only only for the public subset.');
  }

  let initialMissions = [];

  await check('health/version/dependencies', async () => {
    const { response, body, elapsedMs } = await getJson('/api/swarm/health');
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(body?.status === 'ok', 'health status != ok');
    assert(body?.service === EXPECTED_SERVICE, `service=${body?.service}`);
    assert(body?.protocol === EXPECTED_PROTOCOL, `protocol=${body?.protocol}`);
    assert(body?.version === EXPECTED_VERSION, `version=${body?.version}`);
    assert(body?.agents === 8, `agents=${body?.agents}`);
    assert(body?.persistence?.kv_bound === true, 'SWARM_MISSIONS_KV not bound');
    assert(body?.production?.canonical_gateway_bound === true, 'CANONICAL_GATEWAY not bound');
    assert(body?.production?.private_mesh_required === true, 'private mesh not required');
    assert(body?.production?.customer_console === true, 'customer console disabled');
    assert(body?.capabilities?.mission_history === true, 'mission history capability missing');
    assert(body?.capabilities?.idempotent_retry === true, 'idempotent retry capability missing');
    assert(body?.capabilities?.agent_timing === true, 'agent timing capability missing');
    assert(body?.capabilities?.entitlement_preflight === true, 'entitlement preflight capability missing');
    for (const fmt of ['md', 'json', 'stix21']) {
      assert(body?.capabilities?.report_formats?.includes(fmt), `missing report format ${fmt}`);
    }
    assert(elapsedMs <= PUBLIC_TIMEOUT_MS, `health latency ${elapsedMs}ms exceeds ${PUBLIC_TIMEOUT_MS}ms`);
    return `${elapsedMs}ms · V${body.version} · 8 agents · persistence+gateway bound`;
  });

  let uiText = '';
  await check('customer console/security/mobile contract', async () => {
    const { response, text, elapsedMs } = await guardedFetch('/swarm/');
    uiText = text;
    assert(response.status === 200, `HTTP ${response.status}`);
    assert((response.headers.get('content-type') || '').includes('text/html'), 'wrong content-type');
    assert((response.headers.get('cache-control') || '').includes('no-store'), 'UI is cacheable');
    assert((response.headers.get('x-frame-options') || '').toUpperCase() === 'DENY', 'X-Frame-Options != DENY');
    assert((response.headers.get('x-content-type-options') || '').toLowerCase() === 'nosniff', 'nosniff missing');
    assert((response.headers.get('referrer-policy') || '').toLowerCase() === 'no-referrer', 'referrer policy != no-referrer');
    const csp = response.headers.get('content-security-policy') || '';
    for (const directive of ["default-src 'none'", "script-src 'self'", "connect-src 'self'", "frame-ancestors 'none'"]) {
      assert(csp.includes(directive), `CSP missing ${directive}`);
    }
    assert(text.includes('width=device-width,initial-scale=1,viewport-fit=cover'), 'mobile viewport contract missing');
    for (const bp of ['@media(max-width:1180px)', '@media(max-width:860px)', '@media(max-width:700px)', '@media(max-width:480px)']) {
      assert(text.includes(bp), `responsive breakpoint missing: ${bp}`);
    }
    assert(text.includes('prefers-reduced-motion:reduce'), 'reduced-motion CSS missing');
    assert(text.includes('prefers-contrast:more'), 'high-contrast CSS missing');
    assert(text.includes('id="run" disabled'), 'RUN button not locked by default');
    assert(text.includes('id="preflightStatus"'), 'preflight status UI missing');
    assert(text.includes('id="loadHistory"'), 'history control missing');
    assert(text.includes('id="historyBody"'), 'history body missing');
    assert(text.includes('id="eventLog"'), 'event stream UI missing');
    assert(text.includes('id="final"'), 'terminal evidence UI missing');
    for (const id of EXPECTED_AGENT_IDS) {
      assert(text.includes(`id="agent-${id}"`), `agent card missing: ${id}`);
      assert(text.includes(`id="mesh-${id}"`), `mesh node missing: ${id}`);
    }
    assert(!/SOC\s*2\s*CERTIFIED/i.test(text), 'unsupported SOC 2 certified claim found');
    return `${elapsedMs}ms · responsive/security/8-agent surfaces present`;
  });

  await check('browser controller/credential hygiene', async () => {
    const { response, text, elapsedMs } = await guardedFetch('/swarm/app.js');
    assert(response.status === 200, `HTTP ${response.status}`);
    assert((response.headers.get('content-type') || '').includes('javascript'), 'wrong content-type');
    assert(text.includes("window.__CDB_SWARM_UI_READY__=true"), 'UI-ready marker missing');
    assert(text.includes("window.__CDB_SWARM_INTERACTIVE_READY__=true"), 'interactive-ready marker missing');
    assert(text.includes("fetch('/api/swarm/preflight'"), 'preflight wiring missing');
    assert(text.includes("fetch('/api/swarm/missions?limit=20'"), 'history wiring missing');
    assert(text.includes('run.onclick=async()=>'), 'mission launch controller missing');
    assert(text.includes('!preflight.eligible||preflight.key!==key'), 'verified-key launch guard missing');
    assert(text.includes('AbortController'), 'preflight race cancellation missing');
    assert(!text.includes('localStorage'), 'localStorage credential risk present');
    assert(!text.includes('sessionStorage'), 'sessionStorage credential risk present');
    assert(!text.includes('document.cookie'), 'cookie credential persistence present');
    new Function(text);
    return `${elapsedMs}ms · JS parses · memory-only credential handling`;
  });

  await check('client-context privacy', async () => {
    const { response, body, elapsedMs } = await getJson('/api/swarm/client-context');
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(body?.status === 'ok', 'status != ok');
    const data = body?.data || {};
    for (const forbidden of ['ip', 'latitude', 'longitude', 'postal_code']) {
      assert(!Object.prototype.hasOwnProperty.call(data, forbidden), `client-context exposes ${forbidden}`);
    }
    assert(typeof data.timezone === 'string' && data.timezone, 'timezone missing');
    return `${elapsedMs}ms · coarse edge context only`;
  });

  await check('anonymous fail-closed surfaces', async () => {
    const preflight = await getJson('/api/swarm/preflight');
    assert(preflight.response.status === 401, `preflight HTTP ${preflight.response.status}`);
    assert(preflight.body?.error === 'authentication_required', 'preflight did not fail closed');

    const missions = await getJson('/api/swarm/missions?limit=1');
    assert(missions.response.status === 401, `missions HTTP ${missions.response.status}`);
    assert(missions.body?.error === 'authentication_required', 'history did not fail closed');

    const invalid = await getJson('/api/swarm/mission/not-a-valid-mission-id');
    assert(invalid.response.status === 400, `invalid mission id HTTP ${invalid.response.status}`);

    const unknown = await getJson('/api/swarm/__pre_demo_unknown__');
    assert(unknown.response.status === 404, `unknown route HTTP ${unknown.response.status}`);
    return '401/400/404 boundaries correct';
  });

  if (publicOnly) {
    assert(missionDispatchCount === 0, 'mission dispatch guard was triggered');
    console.log('\nPUBLIC-ONLY CERTIFICATION COMPLETE');
    finalize();
    return;
  }

  await check('paid entitlement/quota preflight', async () => {
    const { response, body, text, elapsedMs } = await getJson('/api/swarm/preflight', { headers: paidHeaders() });
    assert(response.status === 200, `HTTP ${response.status}: ${text.slice(0, 160)}`);
    assert(body?.eligible === true, `eligible=false reason=${body?.reason || 'unknown'}`);
    assert(body?.entitlement?.swarm_enabled === true, 'swarm_enabled != true');
    assert(body?.entitlement?.scope_granted === true, 'required scope not granted');
    assert(['PRO', 'ENTERPRISE', 'MSSP'].includes(body?.entitlement?.tier), `tier=${body?.entitlement?.tier}`);
    assert(['active', 'past_due'].includes(String(body?.entitlement?.subscription_status || '').toLowerCase()), `subscription_status=${body?.entitlement?.subscription_status}`);
    assert(hasNoCredentialEcho(text), 'credential reflected in preflight response');
    const q = body?.quota?.daily;
    assert(q && q.available === true, 'daily quota telemetry unavailable');
    assert(q.exhausted === false, 'daily quota exhausted');
    assert(Number(q.remaining) >= MIN_DAILY_QUOTA_REMAINING, `only ${q.remaining} daily requests remain; need >= ${MIN_DAILY_QUOTA_REMAINING}`);
    return `tier=${body.entitlement.tier} · quota=${q.remaining}/${q.limit} · ${elapsedMs}ms`;
  });

  await check('mission history snapshot before canaries', async () => {
    initialMissions = await snapshotMissionIds();
    if (strictHistory) assert(initialMissions.length > 0, 'no existing mission history for this key; cannot live-certify read-back/export before the first filmed mission');
    return `${initialMissions.length} existing mission(s)`;
  });

  let feedItem = null;
  await check('canonical intel feed/source data', async () => {
    const { response, body, elapsedMs } = await getJson('/api/v1/intel/latest.json', { headers: paidHeaders() }, BACKEND_TIMEOUT_MS);
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(Array.isArray(body?.items) && body.items.length > 0, 'latest intel items missing/empty');
    feedItem = body.items.find((item) => pickReportId(item) && (pickCve(item) || pickActor(item) || pickTechnique(item) || pickObservable(item))) || body.items[0];
    assert(feedItem && typeof feedItem === 'object', 'no usable feed item');
    return `${body.items.length} live intel item(s) · ${elapsedMs}ms`;
  });

  let correlation = null;
  let canaryIoc = null;
  await check('canonical IOC correlation backend', async () => {
    canaryIoc = String(process.env.PREDEMO_IOC || pickObservable(feedItem) || '8.8.8.8').trim();
    const iocType = String(process.env.PREDEMO_IOC_TYPE || inferIocType(canaryIoc));
    const { response, body, text, elapsedMs } = await getJson('/api/intel/correlate', {
      method: 'POST',
      headers: paidHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({ ioc_value: canaryIoc, ioc_type: iocType }),
    }, BACKEND_TIMEOUT_MS);
    assert(response.status === 200, `HTTP ${response.status}: ${text.slice(0, 200)}`);
    assert(body && typeof body === 'object', 'correlation body missing');
    assert(body.status === 'ok' || body.status === 'success', `correlation status=${body.status}`);
    correlation = body.data || body;
    assert(hasNoCredentialEcho(text), 'credential reflected in correlation response');
    return `${iocType} ${canaryIoc} · ${elapsedMs}ms`;
  });

  const specialistOutcomes = {};
  await check('six specialist backend routes', async () => {
    const depsFromCorrelation = extractCorrelationDependencies(correlation);
    const reportId = depsFromCorrelation.reportId || pickReportId(feedItem);
    const cve = depsFromCorrelation.cve || pickCve(feedItem);
    const actor = depsFromCorrelation.actor || pickActor(feedItem);
    const technique = depsFromCorrelation.technique || pickTechnique(feedItem);

    const required = { reportId, cve, actor, technique };
    for (const [name, value] of Object.entries(required)) assert(value, `unable to derive ${name} from live feed/correlation`);

    const probes = [
      {
        agentId: 'cve-intelligence',
        path: `/api/cves?cve_id=${encodeURIComponent(cve)}&limit=5`,
        validate: (body) => body?.status === 'ok' && Array.isArray(body?.data?.cves),
      },
      {
        agentId: 'threat-hunter',
        path: `/api/actors?actor_id=${encodeURIComponent(actor)}&limit=5`,
        validate: (body) => body?.status === 'ok' && Array.isArray(body?.data?.actors),
      },
      {
        agentId: 'attack-mapper',
        path: `/api/search?q=${encodeURIComponent(technique)}&limit=5`,
        validate: (body) => body?.status === 'ok' && Array.isArray(body?.data?.results),
      },
      {
        agentId: 'siem-defender',
        path: `/api/v1/detections?intel_id=${encodeURIComponent(reportId)}&limit=5`,
        validate: (body) => typeof body?.schema_version === 'string' && Array.isArray(body?.data) && body?.pagination,
      },
      {
        agentId: 'ir-playbook',
        path: `/api/intel/ir-guidance?report_id=${encodeURIComponent(reportId)}&limit=5`,
        validate: (body) => body?.status === 'ok' && body?.data?.report_id === reportId,
      },
      {
        agentId: 'exposure-analyst',
        path: `/api/intel/exposure?report_id=${encodeURIComponent(reportId)}&limit=5`,
        validate: (body) => body?.status === 'ok' && body?.data?.report_id === reportId && Array.isArray(body?.data?.dimensions),
      },
    ];

    const details = [];
    for (const probe of probes) {
      const { agentId, path, validate } = probe;
      const { response, body, text, elapsedMs } = await getJson(path, { headers: paidHeaders() }, BACKEND_TIMEOUT_MS);
      assert(response.status === 200, `${agentId} HTTP ${response.status}: ${text.slice(0, 180)}`);
      assert(validate(body), `${agentId} returned an unexpected success schema`);
      assert(hasNoCredentialEcho(text), `${agentId} reflected credential`);
      specialistOutcomes[agentId] = {
        basis: 'pre_demo_backend_canary',
        state: 'COMPLETED',
        result: body.data ?? body,
        duration_ms: elapsedMs,
      };
      details.push(`${agentId}=${elapsedMs}ms`);
    }
    return details.join(' · ');
  });

  await check('risk-synthesizer LLM backend', async () => {
    const { response, body, text, elapsedMs } = await getJson('/api/v1/swarm-synthesis', {
      method: 'POST',
      headers: paidHeaders({ 'content-type': 'application/json' }),
      body: JSON.stringify({
        ioc_value: correlation?.ioc?.value || canaryIoc,
        ioc_type: correlation?.ioc?.type || inferIocType(canaryIoc),
        verdict: correlation?.verdict || 'unknown',
        outcomes: specialistOutcomes,
      }),
    }, BACKEND_TIMEOUT_MS);
    assert(response.status === 200, `HTTP ${response.status}: ${text.slice(0, 180)}`);
    assert(body?.status === 'success', `status=${body?.status}`);
    assert(body?.llm_enhanced === true, 'llm_enhanced != true; filmed AI synthesis would degrade to deterministic fallback');
    assert(typeof body?.narrative === 'string' && body.narrative.trim().length >= 40, 'AI narrative missing/too short');
    assert(hasNoCredentialEcho(text), 'credential reflected in synthesis response');
    return `model=${body.llm_model || 'provider-reported'} · ${elapsedMs}ms`;
  });

  if (initialMissions.length > 0) {
    const completed = initialMissions.find((m) => m?.status === 'COMPLETED' && typeof m?.mission_id === 'string') ||
      initialMissions.find((m) => typeof m?.mission_id === 'string');

    await check('durable mission read-back', async () => {
      assert(completed?.mission_id, 'no persisted mission id available');
      const id = encodeURIComponent(completed.mission_id);
      const { response, body, text, elapsedMs } = await getJson(`/api/swarm/mission/${id}`, { headers: paidHeaders() });
      assert(response.status === 200, `HTTP ${response.status}`);
      assert(body?.status === 'ok', `status=${body?.status}`);
      assert(body?.data?.mission_id === completed.mission_id, 'mission_id mismatch');
      assert(body?.data?.ioc && typeof body.data.ioc === 'object', 'persisted IOC missing');
      assert(body?.data?.specialists && typeof body.data.specialists === 'object', 'persisted specialist evidence missing');
      assert(hasNoCredentialEcho(text), 'credential reflected in mission record');
      return `${completed.mission_id} · ${elapsedMs}ms`;
    });

    await check('Markdown/JSON/STIX 2.1 evidence exports', async () => {
      const id = encodeURIComponent(completed.mission_id);
      const headers = paidHeaders();

      const md = await guardedFetch(`/api/swarm/mission/${id}/report`, { headers });
      assert(md.response.status === 200, `Markdown HTTP ${md.response.status}`);
      assert((md.response.headers.get('content-type') || '').includes('text/markdown'), 'Markdown content-type wrong');
      assert((md.response.headers.get('content-disposition') || '').includes('.md'), 'Markdown attachment filename missing');
      assert(md.text.includes(completed.mission_id), 'Markdown report missing mission id');

      const js = await getJson(`/api/swarm/mission/${id}/report?format=json`, { headers });
      assert(js.response.status === 200, `JSON HTTP ${js.response.status}`);
      assert(js.body?.data?.mission_id === completed.mission_id, 'JSON export mission id mismatch');

      const stixRaw = await guardedFetch(`/api/swarm/mission/${id}/report?format=stix21`, { headers });
      assert(stixRaw.response.status === 200, `STIX HTTP ${stixRaw.response.status}`);
      assert((stixRaw.response.headers.get('content-type') || '').includes('application/stix+json'), 'STIX content-type wrong');
      const stix = JSON.parse(stixRaw.text);
      assert(stix?.type === 'bundle', 'STIX export is not a bundle');
      assert(Array.isArray(stix?.objects) && stix.objects.length >= 1, 'STIX bundle objects missing');
      assert(stix.objects.some((o) => o?.type === 'indicator'), 'STIX Indicator missing');

      return `mission=${completed.mission_id} · md/json/stix21 PASS`;
    });
  }

  await check('mission-history immutability / zero SWARM dispatch', async () => {
    const after = await snapshotMissionIds();
    const beforeIds = initialMissions.map((m) => m?.mission_id).filter(Boolean).sort();
    const afterIds = after.map((m) => m?.mission_id).filter(Boolean).sort();
    assert(JSON.stringify(beforeIds) === JSON.stringify(afterIds), 'mission history changed during pre-demo certification');
    assert(missionDispatchCount === 0, `mission dispatch guard triggered ${missionDispatchCount} time(s)`);
    return `${afterIds.length} mission(s) unchanged · /api/swarm/run calls=0`;
  });

  finalize();
}

function finalize() {
  const failed = results.filter((r) => r.status === 'FAIL');
  const passed = results.length - failed.length;
  console.log('\n============================================================');
  console.log('PRE-DEMO CERTIFICATION SUMMARY');
  console.log('============================================================');
  console.log(`PASS     ${passed}/${results.length}`);
  console.log(`FAIL     ${failed.length}/${results.length}`);
  console.log(`REQUESTS ${requestCount}`);
  console.log(`MISSIONS DISPATCHED ${missionDispatchCount}`);
  console.log('============================================================');

  if (failed.length) {
    console.error('\nHOLD — DO NOT RECORD OR RUN THE LIVE SWARM MISSION.');
    for (const item of failed) console.error(` - ${item.name}: ${item.detail}`);
    process.exitCode = 1;
    return;
  }

  console.log('\nGO — 100% OF THE DEFINED PRE-DEMO ACCEPTANCE MATRIX PASSED.');
  console.log('The next SWARM mission may be used as the filmed live customer demonstration.');
}

main().catch((error) => {
  console.error(`\nFATAL PRE-DEMO CERTIFICATION ERROR: ${error?.message || error}`);
  console.error('HOLD — DO NOT RUN THE LIVE SWARM MISSION.');
  process.exitCode = 1;
});
