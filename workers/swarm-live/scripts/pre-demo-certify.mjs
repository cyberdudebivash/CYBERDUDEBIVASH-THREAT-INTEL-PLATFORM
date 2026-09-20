#!/usr/bin/env node
import { buildDependencyCandidates } from '../src/mission-readiness.js';
import { adaptSpecialistResponse } from '../src/specialist-contract.js';

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
const EXPECTED_VERSION = '4.47.0';
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
  '/api/swarm/readiness',
  '/api/intel/correlate',
  '/api/v1/swarm-synthesis',
]);
const HARD_BLOCKED_PATHS = new Set([
  '/api/swarm/run',
]);
// Full certification consumes ~9 canonical requests (feed + correlate + six specialists + synthesis).
// Reserve a further ~8 for the filmed mission plus safety headroom; the default is deliberately conservative.
const MIN_DAILY_QUOTA_REMAINING = Number(process.env.PREDEMO_MIN_DAILY_QUOTA || 32);
const MIN_LIVE_MISSION_QUOTA_REMAINING = Number(process.env.PREDEMO_MIN_LIVE_MISSION_QUOTA || 16);
const PUBLIC_TIMEOUT_MS = Number(process.env.PREDEMO_PUBLIC_TIMEOUT_MS || 12000);
const BACKEND_TIMEOUT_MS = Number(process.env.PREDEMO_BACKEND_TIMEOUT_MS || 25000);

const baseUrl = cleanBaseUrl(process.env.SWARM_BASE_URL || DEFAULT_BASE_URL);
const apiKey = String(process.env.SENTINEL_API_KEY || '').trim();
const publicOnly = process.argv.includes('--public-only');

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
  for (const key of ['report_id', 'intel_id', 'stix_id', 'id', 'uid']) {
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

function hasUsableDetectionArtifact(item) {
  const sigma = typeof item?.sigma_rule === 'string' ? item.sigma_rule.trim() : '';
  const kql = typeof item?.kql_query === 'string' ? item.kql_query.trim() : '';
  const suricata = typeof item?.suricata_rule === 'string' ? item.suricata_rule.trim() : '';
  const yara = typeof item?.yara_rule === 'string' ? item.yara_rule.trim() : '';

  if (sigma.length >= 20 && /\bdetection:/.test(sigma) && /\bcondition:/.test(sigma)) return true;
  if (kql.length >= 20) return true;
  if (yara.length >= 20) return true;
  if (suricata.length >= 20 && (/^(alert|drop|reject|pass)\s/i.test(suricata) || /\bsid:\s*\d+/.test(suricata))) return true;
  return false;
}

function richDemoCandidate(item) {
  const reportId = pickReportId(item);
  const observable = pickObservable(item);
  const cve = typeof item?.cve_id === 'string' && item.cve_id.trim() ? item.cve_id.trim() : null;
  const actor = typeof item?.actor_tag === 'string' && item.actor_tag.trim() && item.actor_tag !== 'UNATTRIBUTED'
    ? item.actor_tag.trim()
    : null;
  const technique = Array.isArray(item?.ttps) && item.ttps.length ? pickTechnique(item.ttps) : null;
  if (!reportId || !observable || !cve || !actor || !technique || !hasUsableDetectionArtifact(item)) return null;
  return { item, reportId, observable, cve, actor, technique };
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
  // Mirror workers/swarm-live/src/index.js firstReportId/firstCveId/
  // firstActorTag/firstTechnique exactly. The pre-demo canaries must exercise
  // the same dependency values the filmed mission will choose.
  const matches = Array.isArray(correlation?.matches) ? correlation.matches : [];
  const reportId = matches[0]?.report_id || null;
  const cveMatch = matches.find((m) => m?.cve_id);
  const cve = cveMatch?.cve_id || null;
  const actorMatch = matches.find((m) => m?.actor_tag && m.actor_tag !== 'UNATTRIBUTED');
  const actor = actorMatch?.actor_tag || null;

  let technique = null;
  for (const m of matches) {
    if (!Array.isArray(m?.ttps) || !m.ttps.length) continue;
    const t = m.ttps[0];
    const value = typeof t === 'string' ? t : (t?.technique_id || t?.name || t?.id);
    if (value) {
      technique = String(value);
      break;
    }
  }

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
  console.log('CYBERDUDEBIVASH SENTINEL APEX — V4.47.0 PRE-MISSION CERTIFICATION');
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
    assert(body?.capabilities?.mission_readiness === true, 'mission readiness capability missing');
    assert(body?.capabilities?.mission_quality === true, 'mission quality capability missing');
    assert(body?.capabilities?.evidence_graph === true, 'evidence graph capability missing');
    assert(body?.capabilities?.adaptive_specialists === true, 'adaptive specialist capability missing');
    assert(body?.capabilities?.agent_semantics_v2 === true, 'agent semantics v2 capability missing');
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
    assert(text.includes('id="readinessPanel"'), 'mission readiness UI missing');
    assert(text.includes('id="assessReadiness"'), 'mission readiness control missing');
    assert(text.includes('id="missionQuality"'), 'mission quality UI missing');
    assert(text.includes('id="evidenceGraphState"'), 'evidence graph UI missing');
    assert(text.includes('id="viewMode"'), 'executive/technical view control missing');
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

  await check('physical mobile visual sign-off', async () => {
    if (publicOnly) return 'deferred in --public-only mode';
    assert(
      String(process.env.PREDEMO_MOBILE_VISUAL_SIGNOFF || '').toUpperCase() === 'YES',
      'physical mobile sign-off missing. On the actual recording device verify /swarm/: no horizontal page overflow/cutoff; brand/version/clock readable; API key + IOC + type + RUN controls fully visible; ACCESS NOT VERIFIED/preflight status readable; all 8 agent cards reachable; event/final evidence panels readable; history/export controls usable. Then set PREDEMO_MOBILE_VISUAL_SIGNOFF=YES.'
    );
    return 'explicit operator sign-off recorded for the physical recording device';
  });

  await check('anonymous fail-closed surfaces', async () => {
    const preflight = await getJson('/api/swarm/preflight');
    assert(preflight.response.status === 401, `preflight HTTP ${preflight.response.status}`);
    assert(preflight.body?.error === 'authentication_required', 'preflight did not fail closed');

    const missions = await getJson('/api/swarm/missions?limit=1');
    assert(missions.response.status === 401, `missions HTTP ${missions.response.status}`);
    assert(missions.body?.error === 'authentication_required', 'history did not fail closed');

    // "not-a-valid-mission-id" is intentionally NOT used here: hyphens are
    // valid under the production ID_RE contract. Use an encoded space so the
    // path is genuinely malformed and must fail validation before auth.
    const invalid = await getJson('/api/swarm/mission/bad%20mission%20id');
    assert(invalid.response.status === 400, `invalid mission id HTTP ${invalid.response.status}`);
    assert(invalid.body?.error === 'invalid_mission_id', 'malformed mission id did not fail validation');

    // Separately prove auth precedence for a syntactically valid mission id.
    const unauthenticatedValidId = await getJson('/api/swarm/mission/sentinel-mission-probe');
    assert(
      unauthenticatedValidId.response.status === 401,
      `valid-shaped unauthenticated mission id HTTP ${unauthenticatedValidId.response.status}`
    );
    assert(
      unauthenticatedValidId.body?.error === 'authentication_required',
      'valid-shaped mission lookup did not fail closed on authentication'
    );

    const unknown = await getJson('/api/swarm/__pre_demo_unknown__');
    assert(unknown.response.status === 404, `unknown route HTTP ${unknown.response.status}`);
    return '401/400/404 boundaries correct';
  });

  if (publicOnly) {
    assert(missionDispatchCount === 0, 'mission dispatch guard was triggered');
    console.log('\nPUBLIC-ONLY CERTIFICATION COMPLETE');
    finalize(null);
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

  await check('mission history endpoint / pre-mission snapshot', async () => {
    initialMissions = await snapshotMissionIds();
    return initialMissions.length
      ? `${initialMissions.length} existing mission(s); read-back/export will also be revalidated post-mission`
      : 'fresh credential: empty history is correct; read-back/export are mandatory in post-demo certification after the first mission';
  });

  let feedItem = null;
  let demoCandidate = null;
  let candidatePool = [];

  await check('canonical intel feed/source data', async () => {
    const { response, body, elapsedMs } = await getJson('/api/v1/intel/latest.json', { headers: paidHeaders() }, BACKEND_TIMEOUT_MS);
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(Array.isArray(body?.items) && body.items.length > 0, 'latest intel items missing/empty');

    const candidates = [];
    const seen = new Set();
    for (const item of body.items) {
      const observable = pickObservable(item);
      if (!observable || seen.has(observable)) continue;
      seen.add(observable);
      const structuralScore = [
        pickReportId(item),
        pickCve(item),
        pickActor(item),
        pickTechnique(item),
        hasUsableDetectionArtifact(item) ? 'detection' : null,
      ].filter(Boolean).length;
      candidates.push({
        observable,
        type: inferIocType(observable),
        item,
        reportId: pickReportId(item),
        structuralScore,
      });
    }

    if (process.env.PREDEMO_IOC) {
      const forced = String(process.env.PREDEMO_IOC).trim();
      candidates.unshift({
        observable: forced,
        type: String(process.env.PREDEMO_IOC_TYPE || inferIocType(forced)),
        item: null,
        reportId: null,
        structuralScore: 99,
      });
    }

    candidatePool = candidates
      .sort((a, b) => b.structuralScore - a.structuralScore)
      .slice(0, Number(process.env.PREDEMO_CANDIDATE_LIMIT || 8));

    assert(candidatePool.length > 0, 'live feed contains no usable IOC/observable candidates');
    return `${body.items.length} live intel item(s) · ${candidatePool.length} bounded readiness candidate(s) · ${elapsedMs}ms`;
  });

  await check('full-fabric demo candidate discovery via mission readiness', async () => {
    const attempted = [];
    for (const candidate of candidatePool) {
      const { response, body, elapsedMs } = await getJson('/api/swarm/readiness', {
        method: 'POST',
        headers: paidHeaders({ 'content-type': 'application/json' }),
        body: JSON.stringify({ ioc_value: candidate.observable, ioc_type: candidate.type }),
      }, BACKEND_TIMEOUT_MS);

      attempted.push({
        observable: candidate.observable,
        status: response.status,
        quality: body?.readiness?.mission_quality || body?.reason || body?.error || 'unknown',
        ready_agents: body?.readiness?.ready_agents ?? null,
        llm_ready: body?.synthesis_readiness?.ready ?? null,
      });

      if (
        response.status === 200 &&
        body?.mission_dispatch === false &&
        body?.readiness?.mission_quality === 'FULL_FABRIC' &&
        body?.readiness?.ready_agents === 8 &&
        body?.synthesis_readiness?.ready === true &&
        body?.demo_recommended === true
      ) {
        demoCandidate = { ...candidate, readiness: body, readiness_ms: elapsedMs };
        feedItem = candidate.item;
        break;
      }
    }

    assert(
      demoCandidate,
      `no FULL_FABRIC + AI-ready demo candidate found after ${attempted.length} bounded readiness probe(s): ${JSON.stringify(attempted).slice(0, 1200)}`
    );
    return `${demoCandidate.type} ${demoCandidate.observable} · FULL_FABRIC 8/8 · AI READY · readiness=${demoCandidate.readiness_ms}ms`;
  });

  let correlation = null;
  let canaryIoc = null;
  await check('canonical IOC correlation backend', async () => {
    canaryIoc = String(demoCandidate.observable).trim();
    const iocType = String(demoCandidate.type || inferIocType(canaryIoc));
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
    assert(Number(correlation?.match_count || 0) > 0, 'readiness-selected candidate unexpectedly produced zero correlation matches');
    return `${iocType} ${canaryIoc} · matches=${correlation.match_count} · ${elapsedMs}ms`;
  });

  const specialistOutcomes = {
    'ioc-hunter': {
      basis: 'backend_execution',
      state: 'COMPLETED',
      result: {
        verdict: correlation?.verdict || 'unknown',
        match_count: Number(correlation?.match_count || 0),
        ioc: correlation?.ioc || null,
        source: 'canonical:/api/intel/correlate',
      },
      duration_ms: null,
    },
  };
  await check('six specialist backend routes / adaptive evidence execution', async () => {
    const candidatePlan = buildDependencyCandidates(correlation);
    const routeDefs = {
      'cve-intelligence': { path: '/api/cves', key: 'cve_id' },
      'threat-hunter': { path: '/api/actors', key: 'actor_id' },
      'attack-mapper': { path: '/api/search', key: 'q' },
      'siem-defender': { path: '/api/v1/detections', key: 'intel_id' },
      'ir-playbook': { path: '/api/intel/ir-guidance', key: 'report_id' },
      'exposure-analyst': { path: '/api/intel/exposure', key: 'report_id' },
    };

    const details = [];
    for (const [agentId, route] of Object.entries(routeDefs)) {
      const candidates = (candidatePlan[agentId] || []).slice(0, 3);
      assert(candidates.length > 0, `${agentId}: readiness claimed full fabric but no dependency candidate exists`);

      let selected = null;
      const attempts = [];
      for (const value of candidates) {
        const path = `${route.path}?${route.key}=${encodeURIComponent(value)}&limit=5`;
        const { response, body, text, elapsedMs } = await getJson(path, { headers: paidHeaders() }, BACKEND_TIMEOUT_MS);
        assert(response.status === 200, `${agentId} HTTP ${response.status}: ${text.slice(0, 180)}`);
        assert(hasNoCredentialEcho(text), `${agentId} reflected credential`);
        const adapted = adaptSpecialistResponse(agentId, body);
        attempts.push({ value, success: adapted.success, substantive: adapted.substantive, count: adapted.count });
        assert(adapted.success, `${agentId} returned an unexpected canonical contract`);
        if (adapted.substantive) {
          selected = { value, adapted, elapsedMs };
          break;
        }
      }

      assert(selected, `${agentId}: no substantive evidence after bounded candidates ${JSON.stringify(attempts)}`);
      specialistOutcomes[agentId] = {
        basis: 'pre_demo_backend_canary',
        state: 'COMPLETED',
        result: selected.adapted.data,
        evidence_count: selected.adapted.count,
        queried: { [route.key]: selected.value },
        duration_ms: selected.elapsedMs,
      };
      details.push(`${agentId}=${selected.adapted.count} evidence/${selected.elapsedMs}ms`);
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

  if (initialMissions.length === 0) {
    pass(
      'post-mission persistence/export gate',
      'DEFERRED BY DESIGN — fresh credential has no mission yet; npm run post-demo:certify is mandatory immediately after the filmed mission'
    );
  }

  await check('post-canary quota reserve for filmed mission', async () => {
    const { response, body, elapsedMs } = await getJson('/api/swarm/preflight', { headers: paidHeaders() });
    assert(response.status === 200, `HTTP ${response.status}`);
    assert(body?.eligible === true, `eligible=false reason=${body?.reason || 'unknown'}`);
    const q = body?.quota?.daily;
    assert(q && q.available === true, 'post-canary quota telemetry unavailable');
    assert(q.exhausted === false, 'post-canary daily quota exhausted');
    assert(
      Number(q.remaining) >= MIN_LIVE_MISSION_QUOTA_REMAINING,
      `only ${q.remaining} daily requests remain after certification; need >= ${MIN_LIVE_MISSION_QUOTA_REMAINING} for filmed mission reserve`
    );
    return `quota=${q.remaining}/${q.limit} reserved for filmed mission · ${elapsedMs}ms`;
  });

  await check('mission-history immutability / zero SWARM dispatch', async () => {
    const after = await snapshotMissionIds();
    const beforeIds = initialMissions.map((m) => m?.mission_id).filter(Boolean).sort();
    const afterIds = after.map((m) => m?.mission_id).filter(Boolean).sort();
    assert(JSON.stringify(beforeIds) === JSON.stringify(afterIds), 'mission history changed during pre-demo certification');
    assert(missionDispatchCount === 0, `mission dispatch guard triggered ${missionDispatchCount} time(s)`);
    return `${afterIds.length} mission(s) unchanged · /api/swarm/run calls=0`;
  });

  finalize(demoCandidate);
}

function finalize(candidate = null) {
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

  if (publicOnly) {
    console.log('\nPUBLIC-ONLY PASS — public production surfaces are certified.');
    console.log('HOLD — the live SWARM mission is NOT authorized until physical mobile sign-off and full paid pre-demo certification also pass.');
    return;
  }

  console.log('\nPRE-MISSION GO — 100% OF THE PRE-MISSION ACCEPTANCE MATRIX PASSED.');
  if (candidate) {
    console.log(`DEMO IOC CANDIDATE  ${candidate.observable}`);
    console.log(`DEMO IOC TYPE       ${inferIocType(candidate.observable)}`);
    console.log(`DEMO REPORT         ${candidate.reportId}`);
  }
  console.log('The next SWARM mission may be used as the filmed live customer demonstration. Post-mission certification remains mandatory.');
}

main().catch((error) => {
  console.error(`\nFATAL PRE-DEMO CERTIFICATION ERROR: ${error?.message || error}`);
  console.error('HOLD — DO NOT RUN THE LIVE SWARM MISSION.');
  process.exitCode = 1;
});
