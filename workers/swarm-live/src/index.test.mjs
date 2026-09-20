import assert from 'node:assert/strict';
import { test } from 'node:test';
import worker, { __test } from './index.js';

// ---------------------------------------------------------------------------
// No real network calls: every test that exercises fetch-based dispatch
// installs a synchronous, in-process fetch stub for the duration of that
// test and restores the original afterward. Matches this repo's existing
// deterministic-test convention (see intel-gateway/src/__tests__/*).
// ---------------------------------------------------------------------------

function withStubFetch(handler, run) {
  const original = globalThis.fetch;
  globalThis.fetch = handler;
  return Promise.resolve(run()).finally(() => { globalThis.fetch = original; });
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

const CORRELATION_ID = 'test-correlation-1';
const MATCH = Object.freeze({
  report_id: 'intel--abc123',
  title: 'Example report',
  severity: 'high',
  actor_tag: 'FANCY-BEAR',
  risk_score: 8.4,
  cve_id: 'CVE-2026-11111',
  ttps: ['Initial Access'],
});
const CORRELATION = Object.freeze({
  status: 'ok',
  ioc: { value: '8.8.8.8', type: 'ipv4' },
  verdict: 'suspicious',
  match_count: 1,
  matches: [MATCH],
  recommendation: 'investigate related activity',
});

test('firstCveId / firstActorTag / firstReportId / firstTechnique read the first real match', () => {
  assert.equal(__test.firstCveId(CORRELATION), 'CVE-2026-11111');
  assert.equal(__test.firstActorTag(CORRELATION), 'FANCY-BEAR');
  assert.equal(__test.firstReportId(CORRELATION), 'intel--abc123');
  assert.equal(__test.firstTechnique(CORRELATION), 'Initial Access');
});

test('firstActorTag skips UNATTRIBUTED, all pickers return null on zero matches', () => {
  const unattributed = { matches: [{ actor_tag: 'UNATTRIBUTED', cve_id: null }] };
  assert.equal(__test.firstActorTag(unattributed), null);
  const empty = { matches: [] };
  assert.equal(__test.firstCveId(empty), null);
  assert.equal(__test.firstActorTag(empty), null);
  assert.equal(__test.firstReportId(empty), null);
  assert.equal(__test.firstTechnique(empty), null);
});

test('authHeaders forwards only recognized credential headers; hasAuth reflects presence', () => {
  const req = new Request('https://x.test', { headers: { 'x-api-key': 'k', 'x-unrelated': 'y' } });
  const headers = __test.authHeaders(req);
  assert.equal(headers.get('x-api-key'), 'k');
  assert.equal(headers.get('x-unrelated'), null);
  assert.equal(__test.hasAuth(headers), true);
  assert.equal(__test.hasAuth(__test.authHeaders(new Request('https://x.test'))), false);
});

test('normalizeIocValue conservatively refangs common CTI observables and preserves hashes', () => {
  assert.deepEqual(
    __test.normalizeIocValue('1[.]1[.]1[.]1', 'ipv4'),
    { value: '1.1.1.1', original: '1[.]1[.]1[.]1', refanged: true },
  );
  assert.deepEqual(
    __test.normalizeIocValue('hxxps[://]evil[.]example/path', 'url'),
    { value: 'https://evil.example/path', original: 'hxxps[://]evil[.]example/path', refanged: true },
  );
  assert.deepEqual(
    __test.normalizeIocValue('hxxp[:]//evil(.)example', 'auto'),
    { value: 'http://evil.example', original: 'hxxp[:]//evil(.)example', refanged: true },
  );
  const hash = 'd41d8cd98f00b204e9800998ecf8427e';
  assert.deepEqual(__test.normalizeIocValue(hash, 'hash'), { value: hash, original: hash, refanged: false });
});

test('canonicalGatewayFetch prefers the private service binding and preserves method/path/body', async () => {
  let globalFetchCalled = false;
  let observed = null;
  await withStubFetch(
    async () => {
      globalFetchCalled = true;
      throw new Error('public fetch must not be used when service binding exists');
    },
    async () => {
      const env = {
        CANONICAL_GATEWAY: {
          async fetch(request) {
            observed = {
              method: request.method,
              pathname: new URL(request.url).pathname,
              body: await request.text(),
            };
            return jsonResponse({ status: 'ok' });
          },
        },
      };
      const res = await __test.canonicalGatewayFetch(
        env,
        'https://intel.cyberdudebivash.com/api/intel/correlate',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
        },
      );
      assert.equal(res.status, 200);
      assert.equal(globalFetchCalled, false);
      assert.equal(observed.method, 'POST');
      assert.equal(observed.pathname, '/api/intel/correlate');
      assert.deepEqual(JSON.parse(observed.body), { ioc_value: '8.8.8.8', ioc_type: 'ipv4' });
    },
  );
});

test('canonicalGatewayFetch falls back to public fetch(url, init) when no service binding is available', async () => {
  let called = false;
  await withStubFetch(
    async (url, init) => {
      called = true;
      assert.equal(new URL(String(url)).pathname, '/api/health');
      assert.equal(init?.headers?.get?.('x-request-id'), 'fallback-test');
      return jsonResponse({ status: 'ok' });
    },
    async () => {
      const headers = new Headers({ 'x-request-id': 'fallback-test' });
      const res = await __test.canonicalGatewayFetch(
        {},
        'https://intel.cyberdudebivash.com/api/health',
        { headers },
      );
      assert.equal(res.status, 200);
      assert.equal(called, true);
    },
  );
});

test('customer console exposes the production V4.47.0 control-plane capabilities', () => {
  const html = __test.ui();
  for (const marker of [
    'SUPER AGENT SWARM',
    'V4.47.0 PRODUCTION',
    '8-Agent Operations Grid',
    'Private APEX Mesh',
    'Durable Evidence',
    'Retry Safety',
    'STIX 2.1',
    'Live Mission Events',
    'Mission History & Evidence Export',
    'Credential-Scoped Mission Metrics',
    'MISSION READINESS',
    'Mission Profile',
    'EXECUTIVE VIEW',
    'Mission Quality',
    'Evidence Graph',
    'Final Intelligence / Terminal Evidence',
    'SOC 2-ALIGNED EVIDENCE UX',
    '8-Agent Mesh Topology',
    'STATE-DRIVEN LED NODES',
    'Event Sequence',
    'Active Agents',
    'Completed Agents',
    'Current customer location time',
    'GLOBAL EDGE · RESOLVING',
    'clock-led',
    'clockLocation',
    'clockCountry',
    'DORMANT',
    'SSE · DORMANT',
    'No active mission. Stream opens only after authenticated launch.',
  ]) {
    assert.ok(html.includes(marker), 'missing UI marker: ' + marker);
  }
  assert.ok(html.includes('id="gatewayState"'));
  assert.ok(html.includes('id="persistenceState"'));
  assert.ok(html.includes('id="eventLog"'));
  assert.ok(html.includes('id="missionState"'));
  assert.ok(html.includes('id="mesh-ioc-hunter"'));
  assert.ok(html.includes('id="fabricLed"'));
  assert.ok(html.includes('id="eventCount"'));
  assert.ok(html.includes('id="activeAgents"'));
  assert.ok(html.includes('id="completedAgents"'));
  assert.ok(html.includes('id="readinessPanel"'));
  assert.ok(html.includes('id="profile"'));
  assert.ok(html.includes('id="viewMode"'));
  assert.ok(html.includes('id="missionQuality"'));
  assert.ok(html.includes('id="evidenceGraphState"'));
  assert.ok(html.includes('id="loadMetrics"'));
  assert.ok(html.includes('id="executiveSummary"'));
  assert.ok(html.includes('id="fabricStateText">DORMANT</span>'));
  assert.ok(html.includes('id="streamState">SSE · DORMANT</span>'));
  assert.ok(!html.includes('SSE · REAL TIME'), 'idle UI must not imply an active event stream');
  assert.match(
    html,
    /<a class="back-platform" id="backToPlatform" href="\/" aria-label="Back to CYBERDUDEBIVASH Sentinel APEX platform">/,
    'SWARM header must expose a same-origin back-to-platform navigation control',
  );
  assert.ok(html.includes('<span>BACK TO PLATFORM</span>'));
  assert.ok(html.includes('.back-platform{'), 'back-to-platform control must have dedicated production styling');
  assert.ok(html.includes('.back-platform:focus-visible'), 'back-to-platform control must expose a keyboard focus state');
  assert.ok(html.includes('.back-platform{grid-column:1/-1;width:100%;min-height:48px'), 'back-to-platform control must remain touch-friendly on smartphones');
  assert.ok(html.includes('does not claim independent SOC 2 certification'));
  assert.ok(!html.includes('setInterval('), 'customer console HTML must not embed simulated mission timers');
});

test('customer console provides direct navigation back to the Sentinel APEX platform root', () => {
  const html = __test.ui();
  const expected = '<a class="back-platform" id="backToPlatform" href="/" aria-label="Back to CYBERDUDEBIVASH Sentinel APEX platform">';
  assert.ok(html.includes(expected));
  assert.ok(html.includes('<span class="back-arrow" aria-hidden="true">←</span><span>BACK TO PLATFORM</span>'));
  assert.equal((html.match(/id="backToPlatform"/g) || []).length, 1, 'navigation control must be unique');
  assert.ok(!html.includes('target="_blank"'), 'back-to-platform navigation should stay in the same customer tab');
});

test('customer console browser controller is external, same-origin, and syntactically valid', async () => {
  const html = __test.ui();
  assert.ok(html.includes('<script src="/swarm/app.js" defer></script>'));
  assert.ok(!html.includes('<script>'), 'customer console must not rely on an inline script block');

  const js = __test.swarmAppJs();
  assert.doesNotThrow(() => new Function(js));
  assert.ok(js.includes("window.__CDB_SWARM_UI_READY__=true"));
  assert.ok(js.includes('hydrateHealth()'));
  assert.ok(js.includes("run.onclick=async()=>"));
  assert.ok(js.includes("loadHistoryBtn.onclick=async()=>"));
  assert.ok(js.includes('updateOpsTelemetry()'));
  assert.ok(js.includes("setMeshNode(ev.agent_id"));
  assert.ok(js.includes("setText('eventCount'"));
  assert.ok(js.includes('setInterval(updateClock,1000)'));
  assert.ok(js.includes("fetch('/api/swarm/client-context'"));
  assert.ok(js.includes('function hydrateClockContext()'));
  assert.ok(js.includes("Intl.DateTimeFormat('en-GB'"));
  assert.ok(js.includes("Intl.DisplayNames"));
  assert.ok(js.indexOf('updateClock();setInterval(updateClock,1000);hydrateClockContext();') < js.indexOf('const prefersReducedMotion'), 'clock must initialize before cinematic subsystems');

  const res = await worker.fetch(
    new Request('https://intel.cyberdudebivash.com/swarm/app.js'),
    {},
    { waitUntil() {} },
  );
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type') || '', /^text\/javascript/);
  assert.equal(await res.text(), js);
});

test('browser controller executes to interactive-ready and attaches live mission controls', async () => {
  const js = __test.swarmAppJs();

  class StubElement {
    constructor(id = '') {
      this.id = id;
      this.dataset = {};
      this.style = {};
      this.className = '';
      this.classList = { add() {}, remove() {} };
      this.textContent = '';
      this.innerHTML = '';
      this.disabled = false;
      this.value = id === 'ioc' ? '8.8.8.8' : (id === 'type' ? 'ipv4' : '');
      this.scrollTop = 0;
      this.scrollHeight = 0;
    }
    querySelector() { return null; }
    querySelectorAll() { return []; }
    append() {}
    appendChild() {}
    addEventListener() {}
    setAttribute() {}
    scrollIntoView() {}
    remove() {}
    click() {}
    closest() { return null; }
    getBoundingClientRect() { return { left: 0, top: 0, width: 100, height: 40 }; }
  }

  const elements = new Map();
  const getElement = (id) => {
    if (id === 'cinematicCanvas') return null;
    if (!elements.has(id)) elements.set(id, new StubElement(id));
    return elements.get(id);
  };

  const documentStub = {
    documentElement: new StubElement('documentElement'),
    body: new StubElement('body'),
    getElementById: getElement,
    querySelector() { return null; },
    querySelectorAll() { return []; },
    createElement(tag) { return new StubElement(tag); },
  };

  const windowStub = {
    __CDB_SWARM_UI_READY__: false,
    __CDB_SWARM_INTERACTIVE_READY__: false,
    matchMedia() { return { matches: true }; },
    addEventListener() {},
    setTimeout() {},
    devicePixelRatio: 1,
    innerWidth: 1280,
    innerHeight: 720,
  };

  const fetchStub = async (url) => {
    const target = String(url);
    if (target.includes('/api/swarm/client-context')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            status: 'ok',
            data: {
              city: 'Bengaluru',
              region: 'Karnataka',
              country_code: 'IN',
              country_name: '',
              timezone: 'Asia/Kolkata',
              source: 'cloudflare_edge',
            },
          };
        },
      };
    }
    if (target.includes('/api/swarm/health')) {
      return {
        ok: true,
        status: 200,
        async json() {
          return {
            status: 'ok',
            service: 'sentinel-apex-swarm-live',
            protocol: 'cdb.swarm.v1',
            version: '4.47.0',
            agents: 8,
            persistence: { kv_bound: true },
            production: { canonical_gateway_bound: true },
            capabilities: { idempotent_retry: true, report_formats: ['md', 'json', 'stix21'] },
          };
        },
      };
    }
    throw new Error('unexpected bootstrap fetch: ' + target);
  };

  const setIntervalStub = () => 1;
  const execute = new Function('document', 'window', 'fetch', 'setInterval', js);

  assert.doesNotThrow(() => execute(documentStub, windowStub, fetchStub, setIntervalStub));

  // Let hydrateClockContext() and hydrateHealth() continue after their awaits.
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(windowStub.__CDB_SWARM_UI_READY__, true);
  assert.equal(windowStub.__CDB_SWARM_INTERACTIVE_READY__, true);
  assert.equal(typeof getElement('run').onclick, 'function');
  assert.equal(typeof getElement('loadHistory').onclick, 'function');
  assert.equal(typeof getElement('loadMetrics').onclick, 'function');
  assert.equal(typeof getElement('assessReadiness').onclick, 'function');
  assert.equal(typeof getElement('viewMode').onclick, 'function');
  assert.equal(typeof getElement('historyBody').onclick, 'function');
  assert.equal(getElement('runtimeState').textContent, 'LIVE');
  assert.equal(getElement('runtimeKpi').textContent, 'LIVE · 4.47.0');
  assert.equal(getElement('gatewayState').textContent, 'BOUND');
  assert.equal(getElement('persistenceState').textContent, 'READY');
  assert.equal(getElement('evidenceStore').textContent, 'DURABLE KV READY');
});

test('appendEvent keeps cinematic event FX inside the event handler', () => {
  const js = __test.swarmAppJs();
  assert.equal(js.includes('};fxForMissionEvent(ev)'), false, 'top-level ev reference would abort browser bootstrap');
  const start = js.indexOf('function appendEvent(ev)');
  const next = js.indexOf('function renderNarrative', start);
  assert.ok(start >= 0 && next > start);
  const body = js.slice(start, next);
  assert.ok(body.includes('fxForMissionEvent(ev)'), 'appendEvent must invoke cinematic FX from the real event');
  assert.ok(body.includes('focusAgentForExecutive(ev)'), 'appendEvent must drive Executive View focus from the same real event');
  assert.ok(
    body.indexOf('fxForMissionEvent(ev)') < body.lastIndexOf('}'),
    'event FX must execute inside appendEvent before its closing brace',
  );
  assert.ok(
    body.indexOf('focusAgentForExecutive(ev)') < body.lastIndexOf('}'),
    'executive focus must execute inside appendEvent before its closing brace',
  );
  assert.ok(js.includes('window.__CDB_SWARM_INTERACTIVE_READY__=true'));
});

test('cinematic customer console exposes premium visual surfaces without fake mission telemetry', () => {
  const html = __test.ui();
  for (const marker of [
    'cinematicCanvas',
    'RED TEAM INTEL',
    'AI SECURITY OPS',
    'Cinematic launch visualization is decorative only',
    'SOC / CTI',
    'CYBER DEFENSE',
    'V4.47.0 PRODUCTION',
  ]) {
    assert.ok(html.includes(marker), 'missing cinematic UI marker: ' + marker);
  }
  assert.ok(html.includes('prefers-reduced-motion:reduce'));
  assert.ok(html.includes('prefers-contrast:more'));
  assert.ok(!html.includes('SOC 2 CERTIFIED'));
});

test('cinematic browser controller is decorative, reduced-motion aware, and real-event driven', () => {
  const js = __test.swarmAppJs();
  assert.doesNotThrow(() => new Function(js));
  assert.ok(js.includes("matchMedia('(prefers-reduced-motion: reduce)')"));
  assert.ok(js.includes('function triggerLaunchSequence()'));
  assert.ok(js.includes('function fxForMissionEvent(ev)'));
  assert.ok(js.includes('function focusAgentForExecutive(ev)'));
  assert.ok(js.includes('function renderExecutiveSummary(result)'));
  assert.ok(js.includes("fetch('/api/swarm/readiness'"));
  assert.ok(js.includes("fetch('/api/swarm/metrics?limit=50'"));
  assert.ok(js.includes('fxForMissionEvent(ev)'));
  assert.ok(js.includes('function emitCinematicFx(kind,el,intensity)'));
  assert.ok(js.includes('updateOpsTelemetry()'));
  assert.ok(js.includes('triggerLaunchSequence();resetAgents();resetEventLog();'));
  assert.ok(js.indexOf("if(!key||!ioc)") < js.indexOf('triggerLaunchSequence();'), 'launch FX must not fire before required input validation');
  assert.ok(js.includes("ev.event_type==='agent.started'"));
  assert.ok(js.includes("ev.event_type==='mission.completed'"));
  assert.ok(js.includes("ev.event_type==='mission.rejected'"));
  assert.equal(js.includes('localStorage'), false);
  assert.equal(js.includes('sessionStorage'), false);
});

test('global LED clock is server-rendered with visible digits before browser hydration', () => {
  const html = __test.ui();
  assert.ok(html.includes('id="globalClock"'));
  assert.ok(html.includes('id="clockTime"'));
  assert.match(html, /id="clockTime"[^>]*>\d{2}:\d{2}:\d{2}<\/time>/);
  assert.ok(!html.includes('id="utcClock"'));
  assert.ok(html.includes('id="clockLocation"'));
  assert.ok(html.includes('id="clockCountry"'));
  assert.ok(html.includes('@keyframes clockPulse'));
  assert.ok(html.includes('@keyframes clockScan'));
});

test('all eight agents expose unique persistent ultra-HD LED identities', () => {
  const visuals = __test.AGENT_VISUALS;
  assert.equal(Object.keys(visuals).length, 8);

  const accents = __test.AGENTS.map((agent) => {
    assert.ok(visuals[agent.id], 'missing visual identity for ' + agent.id);
    assert.match(visuals[agent.id].accent, /^#[0-9A-F]{6}$/);
    return visuals[agent.id].accent;
  });

  assert.equal(new Set(accents).size, 8, 'every agent must have a distinct LED identity color');

  assert.deepEqual(accents, [
    '#00E7FF',
    '#8B5CFF',
    '#FF8A00',
    '#FF4FD8',
    '#00FFA8',
    '#FFD400',
    '#5BE1FF',
    '#FF4D5A',
  ]);
});

test('customer console renders per-agent LED fabric and production mobile/tablet breakpoints', () => {
  const html = __test.ui();

  for (const marker of [
    'class="mesh-led"',
    'class="mesh-agent-name"',
    'data-agent-id="ioc-hunter"',
    'data-agent-id="risk-synthesizer"',
    '--agent-accent:#00E7FF',
    '--agent-accent:#8B5CFF',
    '--agent-accent:#FF8A00',
    '--agent-accent:#FF4FD8',
    '--agent-accent:#00FFA8',
    '--agent-accent:#FFD400',
    '--agent-accent:#5BE1FF',
    '--agent-accent:#FF4D5A',
    'viewport-fit=cover',
    '@media(max-width:1180px)',
    '@media(max-width:860px)',
    '@media(max-width:700px)',
    '@media(max-width:480px)',
  ]) {
    assert.ok(html.includes(marker), 'missing LED/responsive marker: ' + marker);
  }

  assert.ok(html.includes('.agents{grid-template-columns:1fr'));
  assert.ok(html.includes('.mesh-core{grid-template-columns:repeat(2,minmax(0,1fr))'));
  assert.ok(html.includes('button,.run,.load,.dl,input,select{min-height:44px'));
});

test('customer console CSP allows only same-origin external JavaScript', async () => {
  const res = await worker.fetch(
    new Request('https://intel.cyberdudebivash.com/swarm/'),
    {},
    { waitUntil() {} },
  );
  assert.equal(res.status, 200);
  const csp = res.headers.get('content-security-policy') || '';
  assert.ok(csp.includes("script-src 'self'"));
  assert.ok(!csp.includes("script-src 'unsafe-inline'"));
});

test('safeRequestId accepts a well-formed caller id, rejects and replaces a malformed one', () => {
  const good = new Request('https://x.test', { headers: { 'x-request-id': 'abc.123:def' } });
  assert.equal(__test.safeRequestId(good), 'abc.123:def');
  const bad = new Request('https://x.test', { headers: { 'x-request-id': 'has spaces' } });
  assert.match(__test.safeRequestId(bad), /^sentinel-swarm-/);
});

test('fuseRiskSynthesis classifies contributing vs denied vs failed specialists', () => {
  const outcomes = {
    'ioc-hunter': { basis: 'backend_execution', state: 'COMPLETED' },
    'cve-intelligence': { basis: 'backend_execution', state: 'COMPLETED' },
    'threat-hunter': { basis: 'backend_execution', state: 'DENIED' },
    'attack-mapper': { basis: 'backend_execution', state: 'FAILED' },
    'siem-defender': { basis: 'conditional_skip', state: 'SKIPPED' },
    'ir-playbook': { basis: 'backend_execution', state: 'COMPLETED' },
    'exposure-analyst': { basis: 'backend_execution', state: 'COMPLETED' },
  };
  const fused = __test.fuseRiskSynthesis(CORRELATION, outcomes);
  assert.equal(fused.basis, 'fusion');
  assert.deepEqual(fused.contributing_specialists.sort(), ['cve-intelligence', 'exposure-analyst', 'ioc-hunter', 'ir-playbook']);
  assert.deepEqual(fused.skipped_specialists, ['siem-defender']);
  assert.deepEqual(fused.denied_specialists, ['threat-hunter']);
  assert.deepEqual(fused.failed_specialists, ['attack-mapper']);
  assert.equal(fused.max_risk_score, 8.4);
});

test('fuseRiskSynthesis: an unconfigured specialist (missing SPECIALIST_ROUTES entry) surfaces as failed, never silently dropped', () => {
  const outcomes = {
    'ioc-hunter': { basis: 'backend_execution', state: 'COMPLETED' },
    'cve-intelligence': { basis: 'unconfigured', state: 'FAILED' },
  };
  const fused = __test.fuseRiskSynthesis(CORRELATION, outcomes);
  assert.deepEqual(fused.failed_specialists, ['cve-intelligence']);
});

test('runBackendSpecialist: missing dependency emits honest NOT_APPLICABLE and performs no backend call', async () => {
  let called = false;
  await withStubFetch(() => { called = true; throw new Error('must not be called'); }, async () => {
    const outcome = await __test.runBackendSpecialist('https://x.test', new Headers(), CORRELATION_ID, { matches: [] }, __test.SPECIALIST_ROUTES['cve-intelligence']);
    assert.equal(outcome.basis, 'conditional_not_applicable');
    assert.equal(outcome.state, 'NOT_APPLICABLE');
    assert.equal(outcome.result.reason, 'dependency_input_absent');
    assert.match(outcome.result.note, /no CVE identifier/);
    assert.match(outcome.skip_reason, /no CVE identifier/);
  });
  assert.equal(called, false);
});

test('runBackendSpecialist: a real 2xx response is reported as genuine backend execution', async () => {
  await withStubFetch(
    async (url) => {
      assert.ok(String(url).startsWith('https://x.test/api/cves'));
      assert.ok(String(url).includes('cve_id=CVE-2026-11111'));
      return jsonResponse({ status: 'ok', data: { cves: [{ cve_id: 'CVE-2026-11111', kev: true }] } });
    },
    async () => {
      const outcome = await __test.runBackendSpecialist('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, __test.SPECIALIST_ROUTES['cve-intelligence']);
      assert.equal(outcome.basis, 'backend_execution');
      assert.equal(outcome.state, 'COMPLETED');
      assert.equal(outcome.result.cves[0].kev, true);
    }
  );
});

test('runBackendSpecialist: canonical detection-registry 200 schema completes SIEM Defender', async () => {
  await withStubFetch(
    async (url) => {
      assert.ok(String(url).startsWith('https://x.test/api/v1/detections'));
      assert.ok(String(url).includes('intel_id=intel--abc123'));
      return jsonResponse({
        schema_version: '1.0.0',
        engine_version: 'phase4.1',
        generated_at: new Date().toISOString(),
        count: 1,
        data: [{ intel_id: 'intel--abc123', artifact_type: 'sigma', status: 'DERIVED' }],
        pagination: { limit: 5, next_cursor: null },
      });
    },
    async () => {
      const outcome = await __test.runBackendSpecialist(
        'https://x.test',
        new Headers(),
        CORRELATION_ID,
        CORRELATION,
        __test.SPECIALIST_ROUTES['siem-defender']
      );
      assert.equal(outcome.basis, 'backend_execution');
      assert.equal(outcome.state, 'COMPLETED');
      assert.equal(outcome.result[0].artifact_type, 'sigma');
    }
  );
});

test('SPECIALIST_ROUTES: ir-playbook and exposure-analyst resolve to the new report_id-keyed routes', () => {
  assert.deepEqual(
    { path: __test.SPECIALIST_ROUTES['ir-playbook'].path, paramKey: __test.SPECIALIST_ROUTES['ir-playbook'].paramKey },
    { path: '/api/intel/ir-guidance', paramKey: 'report_id' }
  );
  assert.deepEqual(
    { path: __test.SPECIALIST_ROUTES['exposure-analyst'].path, paramKey: __test.SPECIALIST_ROUTES['exposure-analyst'].paramKey },
    { path: '/api/intel/exposure', paramKey: 'report_id' }
  );
  // Every non-synthesizer, non-ioc-hunter agent must have a route -- this is
  // exactly the invariant that keeps executeMission's 'unconfigured'
  // fail-closed branch unreachable in practice.
  for (const agent of __test.AGENTS) {
    if (agent.id === 'ioc-hunter' || agent.id === 'risk-synthesizer') continue;
    assert.ok(__test.SPECIALIST_ROUTES[agent.id], `missing SPECIALIST_ROUTES entry for ${agent.id}`);
  }
});

test('runBackendSpecialist: ir-guidance and exposure routes are queried by report_id, not the other specialists\' keys', async () => {
  await withStubFetch(
    async (url) => {
      assert.ok(String(url).startsWith('https://x.test/api/intel/ir-guidance'));
      assert.ok(String(url).includes('report_id=intel--abc123'));
      return jsonResponse({ status: 'ok', data: { report_id: 'intel--abc123', applicable: true, checklist: { containment: ['x'] } } });
    },
    async () => {
      const outcome = await __test.runBackendSpecialist('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, __test.SPECIALIST_ROUTES['ir-playbook']);
      assert.equal(outcome.basis, 'backend_execution');
      assert.equal(outcome.state, 'COMPLETED');
      assert.equal(outcome.result.applicable, true);
    }
  );
});

test('synthesizeNarrative: a real llm_enhanced response returns the narrative text and model', async () => {
  await withStubFetch(
    async (url, init) => {
      assert.equal(String(url), 'https://x.test/api/v1/swarm-synthesis');
      assert.equal(init.method, 'POST');
      const sent = JSON.parse(init.body);
      assert.equal(sent.ioc_value, '8.8.8.8');
      assert.equal(sent.ioc_type, 'ipv4');
      assert.equal(sent.verdict, 'suspicious');
      assert.ok(sent.outcomes);
      return jsonResponse({ status: 'success', llm_enhanced: true, narrative: 'Test narrative.', llm_model: 'groq/llama-3.3-70b-versatile' });
    },
    async () => {
      const result = await __test.synthesizeNarrative('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, { 'ioc-hunter': { state: 'COMPLETED' } });
      assert.deepEqual(result, { text: 'Test narrative.', model: 'groq/llama-3.3-70b-versatile' });
    }
  );
});

test('synthesizeNarrative: an honest llm_enhanced:false response (FREE tier / no provider) degrades to null, not a fabricated narrative', async () => {
  await withStubFetch(
    async () => jsonResponse({ status: 'success', llm_enhanced: false, narrative: null, tier_upgrade: 'Upgrade to PRO...' }),
    async () => {
      const result = await __test.synthesizeNarrative('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, {});
      assert.equal(result, null);
    }
  );
});

test('synthesizeNarrative: a non-2xx response degrades to null', async () => {
  await withStubFetch(
    async () => jsonResponse({ error: 'forbidden' }, 403),
    async () => {
      const result = await __test.synthesizeNarrative('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, {});
      assert.equal(result, null);
    }
  );
});

test('synthesizeNarrative: a transport failure degrades to null, never throws', async () => {
  await withStubFetch(
    async () => { throw new TypeError('network down'); },
    async () => {
      await assert.doesNotReject(() => __test.synthesizeNarrative('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, {}));
      const result = await __test.synthesizeNarrative('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, {});
      assert.equal(result, null);
    }
  );
});

test('runBackendSpecialist: a scope-denied 403 is reported as DENIED, never masked as success', async () => {
  await withStubFetch(
    async () => jsonResponse({ error: 'forbidden', reason: 'insufficient_scope', required: 'read:actors' }, 403),
    async () => {
      const outcome = await __test.runBackendSpecialist('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, __test.SPECIALIST_ROUTES['threat-hunter']);
      assert.equal(outcome.state, 'DENIED');
      assert.equal(outcome.result, null);
      assert.equal(outcome.detail.reason, 'insufficient_scope');
    }
  );
});

test('runBackendSpecialist: a transport failure is reported as FAILED, not thrown', async () => {
  await withStubFetch(
    async () => { throw new TypeError('network down'); },
    async () => {
      const outcome = await __test.runBackendSpecialist('https://x.test', new Headers(), CORRELATION_ID, CORRELATION, __test.SPECIALIST_ROUTES['siem-defender']);
      assert.equal(outcome.state, 'FAILED');
      assert.equal(outcome.detail.error, 'specialist_transport_failed');
    }
  );
});

test('end-to-end clean correlation emits NOT_APPLICABLE specialists and NO_MATCH_COMPLETE without fake backend compute', async () => {
  const env = { CANONICAL_BASE_URL: 'https://x.test' };
  const calls = [];
  await withStubFetch(
    async (url, init) => {
      const u = new URL(String(url));
      calls.push(u.pathname);
      if (u.pathname === '/api/intel/correlate') {
        return jsonResponse({
          status: 'ok',
          ioc: { value: '8.8.8.8', type: 'ipv4' },
          verdict: 'clean',
          match_count: 0,
          matches: [],
          recommendation: 'No match found in current feed.',
        }, 200, {
          'x-cdb-mesh-certified': 'true',
          'x-cdb-mesh-execution': 'mesh-skip-1',
          'x-cdb-mesh-correlation': init.headers.get('x-request-id'),
        });
      }
      if (u.pathname === '/api/v1/swarm-synthesis/health') {
        return jsonResponse({ status: 'ok', ready: false, llm_enabled: false, tier_llm: true, providers: {} });
      }
      if (u.pathname === '/api/v1/swarm-synthesis') {
        return jsonResponse({ status: 'success', llm_enhanced: false, narrative: null });
      }
      throw new Error('unexpected specialist backend call: ' + u.pathname);
    },
    async () => {
      let waited;
      const ctx = { waitUntil(p) { waited = p; } };
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'customer-key-123456', 'x-request-id': 'skip-e2e-1' },
          body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
        }),
        env,
        ctx,
      );
      const text = await res.text();
      await waited;

      const events = text
        .split('\n\n')
        .map((chunk) => chunk.split('\n').find((line) => line.startsWith('data: ')))
        .filter(Boolean)
        .map((line) => JSON.parse(line.slice(6)));

      const notApplicable = events.filter((ev) => ev.event_type === 'agent.not_applicable');
      assert.equal(notApplicable.length, 6);
      assert.ok(notApplicable.every((ev) => ev.state === 'NOT_APPLICABLE'));
      assert.ok(notApplicable.every((ev) => ev.result?.reason === 'dependency_input_absent'));

      const startedSpecialists = events.filter(
        (ev) => ev.event_type === 'agent.started' && ev.agent_id !== 'ioc-hunter' && ev.agent_id !== 'risk-synthesizer',
      );
      assert.equal(startedSpecialists.length, 0, 'conditionally skipped specialists must never claim RUNNING');

      assert.deepEqual(calls.sort(), ['/api/intel/correlate', '/api/v1/swarm-synthesis/health', '/api/v1/swarm-synthesis'].sort());
      const completed = events.find((ev) => ev.event_type === 'mission.completed');
      assert.ok(completed);
      assert.equal(completed.result.skipped_specialists.length, 6);
      assert.equal(completed.mission_quality, 'NO_MATCH_COMPLETE');
      const degradedSynth = events.find((ev) => ev.event_type === 'agent.degraded' && ev.agent_id === 'risk-synthesizer');
      assert.ok(degradedSynth);
    },
  );
});

test('runBackendSpecialist: bounded adaptive orchestration tries the next evidence candidate after a valid empty result', async () => {
  const correlation = {
    ...CORRELATION,
    matches: [
      { ...CORRELATION.matches[0], cve_id: 'CVE-2026-EMPTY' },
      { ...CORRELATION.matches[0], report_id: 'intel--second', cve_id: 'CVE-2026-HIT' },
    ],
  };
  const calls = [];
  await withStubFetch(
    async (url) => {
      const u = new URL(String(url));
      const cve = u.searchParams.get('cve_id');
      calls.push(cve);
      if (cve === 'CVE-2026-EMPTY') return jsonResponse({ status: 'ok', data: { cves: [] } });
      return jsonResponse({ status: 'ok', data: { cves: [{ cve_id: cve, kev: true }] } });
    },
    async () => {
      const outcome = await __test.runBackendSpecialist(
        'https://x.test',
        new Headers(),
        CORRELATION_ID,
        correlation,
        __test.SPECIALIST_ROUTES['cve-intelligence']
      );
      assert.equal(outcome.state, 'COMPLETED');
      assert.equal(outcome.queried.cve_id, 'CVE-2026-HIT');
      assert.equal(outcome.evidence_count, 1);
      assert.equal(outcome.substantive, true);
      assert.equal(outcome.attempted_candidates.length, 2);
    }
  );
  assert.deepEqual(calls, ['CVE-2026-EMPTY', 'CVE-2026-HIT']);
});

test('runBackendSpecialist: transient 503 is UNAVAILABLE, not FAILED', async () => {
  await withStubFetch(
    async () => jsonResponse({ error: 'upstream_unavailable' }, 503),
    async () => {
      const outcome = await __test.runBackendSpecialist(
        'https://x.test',
        new Headers(),
        CORRELATION_ID,
        CORRELATION,
        __test.SPECIALIST_ROUTES['cve-intelligence']
      );
      assert.equal(outcome.state, 'UNAVAILABLE');
      assert.equal(outcome.http_status, 503);
    }
  );
});

test('POST /api/swarm/run rejects unknown mission profile before dispatch', async () => {
  const response = await worker.fetch(
    new Request('https://x.test/api/swarm/run', {
      method: 'POST',
      headers: { 'x-api-key': 'enterprise-key' },
      body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4', mission_profile: 'NOT_REAL' }),
    }),
    {},
    { waitUntil() {} },
  );
  assert.equal(response.status, 400);
  const body = await response.json();
  assert.equal(body.error, 'invalid_mission_profile');
  assert.ok(body.allowed.includes('AUTO'));
  assert.ok(body.allowed.includes('SOC_DETECTION_ENGINEERING'));
});

test('POST /api/swarm/readiness returns full-fabric projection without dispatching a SWARM mission', async () => {
  const calls = [];
  await withStubFetch(
    async (url, init = {}) => {
      const u = new URL(String(url));
      calls.push({ path: u.pathname, method: init.method || 'GET' });

      if (u.pathname === '/api/v1/swarm/preflight') {
        return jsonResponse({
          status: 'ok',
          eligible: true,
          entitlement: { tier: 'ENTERPRISE', swarm_enabled: true, scope_granted: true },
          quota: { daily: { available: true, remaining: 100, limit: 50000, exhausted: false } },
        });
      }

      if (u.pathname === '/api/v1/swarm-synthesis/health') {
        return jsonResponse({
          status: 'ok',
          ready: true,
          llm_enabled: true,
          tier_llm: true,
          providers: { deepseek: true, groq: false, openrouter: false },
        });
      }

      if (u.pathname === '/api/intel/correlate') {
        return jsonResponse(CORRELATION, 200, {
          'x-cdb-mesh-certified': 'true',
          'x-cdb-mesh-execution': 'mesh-readiness-1',
          'x-cdb-mesh-correlation': init.headers.get('x-request-id'),
        });
      }

      throw new Error('unexpected readiness call: ' + u.pathname);
    },
    async () => {
      const response = await worker.fetch(
        new Request('https://x.test/api/swarm/readiness', {
          method: 'POST',
          headers: { 'x-api-key': 'enterprise-key' },
          body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
        }),
        { CANONICAL_BASE_URL: 'https://x.test' },
        {}
      );

      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.mission_dispatch, false);
      assert.equal(body.canonical_request_consumed, true);
      assert.equal(body.readiness.mission_quality, 'FULL_FABRIC');
      assert.equal(body.readiness.ready_agents, 8);
      assert.equal(body.demo_recommended, true);
    }
  );

  assert.equal(calls.some((x) => x.path === '/api/swarm/run'), false);
  assert.ok(calls.some((x) => x.path === '/api/intel/correlate' && x.method === 'POST'));
});

test('focused readiness profile reports PROFILE_READY with profile-scoped denominator', async () => {
  await withStubFetch(
    async (url, init = {}) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/v1/swarm/preflight') {
        return jsonResponse({
          status: 'ok',
          eligible: true,
          entitlement: { tier: 'ENTERPRISE', swarm_enabled: true, scope_granted: true },
          quota: { daily: { available: true, remaining: 100, limit: 50000, exhausted: false } },
        });
      }
      if (u.pathname === '/api/v1/swarm-synthesis/health') {
        return jsonResponse({ status: 'ok', ready: true, llm_enabled: true, tier_llm: true, providers: { deepseek: true } });
      }
      if (u.pathname === '/api/intel/correlate') {
        return jsonResponse(CORRELATION, 200, {
          'x-cdb-mesh-certified': 'true',
          'x-cdb-mesh-execution': 'mesh-profile-1',
          'x-cdb-mesh-correlation': init.headers.get('x-request-id'),
        });
      }
      throw new Error('unexpected profile readiness call: ' + u.pathname);
    },
    async () => {
      const response = await worker.fetch(
        new Request('https://x.test/api/swarm/readiness', {
          method: 'POST',
          headers: { 'x-api-key': 'enterprise-key' },
          body: JSON.stringify({
            ioc_value: '8.8.8.8',
            ioc_type: 'ipv4',
            mission_profile: 'SOC_DETECTION_ENGINEERING',
          }),
        }),
        { CANONICAL_BASE_URL: 'https://x.test' },
        {},
      );
      assert.equal(response.status, 200);
      const body = await response.json();
      assert.equal(body.mission_profile.id, 'SOC_DETECTION_ENGINEERING');
      assert.equal(body.readiness.mission_quality, 'PROFILE_READY');
      assert.equal(body.readiness.ready_agents, 4);
      assert.equal(body.readiness.total_agents, 4);
      assert.equal(body.readiness.agents['cve-intelligence'].reason, 'mission_profile_excluded');
      assert.equal(body.demo_recommended, false);
    },
  );
});

test('persistMission is a graceful no-op when no KV binding is provisioned', async () => {
  await assert.doesNotReject(() => __test.persistMission({}, { mission_id: 'sentinel-mission-x' }));
});

test('persistMission writes through the bound KV namespace with a TTL', async () => {
  const store = new Map();
  const env = { SWARM_MISSIONS_KV: { async put(key, value, opts) { store.set(key, { value, opts }); } } };
  await __test.persistMission(env, { mission_id: 'sentinel-mission-y', status: 'COMPLETED' });
  const stored = store.get('sentinel-mission-y');
  assert.ok(stored);
  assert.ok(stored.opts.expirationTtl > 0);
  assert.equal(JSON.parse(stored.value).status, 'COMPLETED');
});

test('GET /api/swarm/health reports protocol and agent count without requiring auth', async () => {
  const res = await worker.fetch(new Request('https://x.test/api/swarm/health'), { SWARM_VERSION: '4.47.0' }, {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.protocol, 'cdb.swarm.v1');
  assert.equal(body.version, '4.47.0');
  assert.equal(body.agents, 8);
  assert.equal(body.capabilities.mission_readiness, true);
  assert.equal(body.capabilities.evidence_graph, true);
  assert.equal(body.capabilities.agent_semantics_v2, true);
});

test('GET /api/swarm/client-context exposes only coarse Cloudflare location metadata', async () => {
  const req = new Request('https://x.test/api/swarm/client-context');
  Object.defineProperty(req, 'cf', {
    value: {
      city: 'Bengaluru',
      region: 'Karnataka',
      country: 'IN',
      timezone: 'Asia/Kolkata',
      colo: 'BLR',
      latitude: '12.9716',
      longitude: '77.5946',
    },
  });
  const res = await worker.fetch(req, {}, {});
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'private, no-store');
  const body = await res.json();
  assert.equal(body.status, 'ok');
  assert.deepEqual(body.data, {
    city: 'Bengaluru',
    region: 'Karnataka',
    country_code: 'IN',
    country_name: '',
    timezone: 'Asia/Kolkata',
    source: 'cloudflare_edge',
  });
  const serialized = JSON.stringify(body);
  assert.equal(serialized.includes('latitude'), false);
  assert.equal(serialized.includes('longitude'), false);
  assert.equal(serialized.includes('colo'), false);
  assert.equal(serialized.includes('ip'), false);
});

test('GET /api/swarm/client-context degrades safely when Cloudflare metadata is unavailable', async () => {
  const res = await worker.fetch(new Request('https://x.test/api/swarm/client-context'), {}, {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.data.source, 'browser_fallback');
  assert.equal(body.data.timezone, 'UTC');
  assert.equal(body.data.city, '');
  assert.equal(body.data.region, '');
  assert.equal(body.data.country_code, '');
});

test('POST /api/swarm/run without credentials is rejected before any mission starts', async () => {
  const res = await worker.fetch(new Request('https://x.test/api/swarm/run', { method: 'POST', body: '{}' }), {}, { waitUntil() {} });
  assert.equal(res.status, 401);
});

test('GET /api/swarm/mission/:id requires auth, validates the id shape, and 404s cleanly when unknown', async () => {
  const env = { SWARM_MISSIONS_KV: { async get() { return null; } } };
  const unauthed = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-abc'), env, {});
  assert.equal(unauthed.status, 401);

  const badId = await worker.fetch(new Request('https://x.test/api/swarm/mission/has space', { headers: { 'x-api-key': 'k' } }), env, {});
  assert.equal(badId.status, 400);

  const missing = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-abc', { headers: { 'x-api-key': 'k' } }), env, {});
  assert.equal(missing.status, 404);
});

test('GET /api/swarm/mission/:id returns the persisted record on a hit', async () => {
  const record = { mission_id: 'sentinel-mission-abc', status: 'COMPLETED' };
  const env = { SWARM_MISSIONS_KV: { async get(key) { return key === 'sentinel-mission-abc' ? JSON.stringify(record) : null; } } };
  const res = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-abc', { headers: { 'x-api-key': 'k' } }), env, {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.deepEqual(body.data, record);
});

test('end-to-end mission: real correlate + all 6 specialists genuinely backend-executed (mixed completed/denied/failed), persisted at the end', async () => {
  const kvStore = new Map();
  const env = {
    CANONICAL_BASE_URL: 'https://x.test',
    SWARM_MISSIONS_KV: { async put(key, value) { kvStore.set(key, value); } },
  };

  await withStubFetch(
    async (url, init) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/intel/correlate') {
        assert.equal(init.method, 'POST');
        return jsonResponse(CORRELATION, 200, {
          'x-cdb-mesh-certified': 'true',
          'x-cdb-mesh-execution': 'mesh-exec-1',
          'x-cdb-mesh-correlation': init.headers.get('x-request-id'),
        });
      }
      if (u.pathname === '/api/cves') return jsonResponse({ status: 'ok', data: { cves: [{ cve_id: 'CVE-2026-11111', kev: true }] } });
      if (u.pathname === '/api/actors') return jsonResponse({ error: 'forbidden', reason: 'insufficient_scope' }, 403);
      if (u.pathname === '/api/v1/detections') return jsonResponse({
        schema_version: '1.0.0',
        data: [{ artifact_type: 'sigma', id: 'sigma-1' }],
        pagination: { total: 1, limit: 5, offset: 0 },
      });
      if (u.pathname === '/api/search') return jsonResponse({ error: 'search_failed' }, 500);
      if (u.pathname === '/api/intel/ir-guidance') return jsonResponse({ status: 'ok', data: { report_id: 'intel--abc123', applicable: true, checklist: { containment: ['isolate host'] } } });
      if (u.pathname === '/api/intel/exposure') return jsonResponse({ status: 'ok', data: { report_id: 'intel--abc123', exposed_count: 3, total_dimensions: 8, dimensions: [] } });
      if (u.pathname === '/api/v1/swarm-synthesis') {
        return jsonResponse({
          status: 'success', llm_enhanced: true,
          narrative: 'Synthesized analyst narrative for 8.8.8.8.',
          llm_model: 'deepseek/deepseek-chat',
          engine: 'CDB-SwarmSynthesis v1.0 (deepseek/deepseek-chat)',
          generated_at: new Date().toISOString(),
        });
      }
      throw new Error(`unexpected fetch to ${u.pathname}`);
    },
    async () => {
      let waited;
      const ctx = { waitUntil(p) { waited = p; } };
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'k', 'x-request-id': CORRELATION_ID },
          body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
        }),
        env,
        ctx
      );
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'text/event-stream; charset=utf-8');

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      const events = [];
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const chunk = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const line = chunk.split('\n').find((l) => l.startsWith('data: '));
          if (line) events.push(JSON.parse(line.slice(6)));
        }
      }
      await waited;

      const byAgentTerminal = Object.fromEntries(
        events.filter((e) => e.agent_id && ['COMPLETED', 'DENIED', 'FAILED'].includes(e.state)).map((e) => [e.agent_id, e])
      );
      assert.equal(byAgentTerminal['ioc-hunter'].state, 'COMPLETED');
      assert.equal(byAgentTerminal['ioc-hunter'].basis, 'backend_execution');
      assert.equal(byAgentTerminal['cve-intelligence'].state, 'COMPLETED');
      assert.equal(byAgentTerminal['threat-hunter'].state, 'DENIED');
      assert.equal(byAgentTerminal['attack-mapper'].state, 'FAILED');
      assert.equal(byAgentTerminal['siem-defender'].state, 'COMPLETED');
      assert.equal(byAgentTerminal['ir-playbook'].basis, 'backend_execution');
      assert.equal(byAgentTerminal['ir-playbook'].state, 'COMPLETED');
      assert.equal(byAgentTerminal['exposure-analyst'].basis, 'backend_execution');
      assert.equal(byAgentTerminal['exposure-analyst'].state, 'COMPLETED');
      assert.equal(byAgentTerminal['risk-synthesizer'].basis, 'fusion');
      assert.equal(byAgentTerminal['risk-synthesizer'].result.llm_enhanced, true);
      assert.equal(byAgentTerminal['risk-synthesizer'].result.ai_narrative, 'Synthesized analyst narrative for 8.8.8.8.');
      assert.equal(byAgentTerminal['risk-synthesizer'].result.llm_model, 'deepseek/deepseek-chat');

      const missionCompleted = events.find((e) => e.event_type === 'mission.completed');
      assert.ok(missionCompleted);
      assert.deepEqual(missionCompleted.result.denied_specialists, ['threat-hunter']);
      assert.deepEqual(missionCompleted.result.failed_specialists, ['attack-mapper']);
      assert.deepEqual(
        missionCompleted.result.contributing_specialists.sort(),
        ['cve-intelligence', 'exposure-analyst', 'ioc-hunter', 'ir-playbook', 'siem-defender']
      );

      const persisted = JSON.parse(kvStore.get(missionCompleted.mission_id));
      assert.equal(persisted.status, 'COMPLETED');
      assert.equal(persisted.specialists['threat-hunter'].state, 'DENIED');
      assert.equal(Array.isArray(persisted.specialists), false);
      assert.deepEqual(Object.keys(persisted.specialists).sort(), __test.AGENTS.map((a) => a.id).sort());
    }
  );
});

test('end-to-end mission: swarm-synthesis unavailable degrades to the existing deterministic fusion, mission still completes', async () => {
  const env = { CANONICAL_BASE_URL: 'https://x.test' };

  await withStubFetch(
    async (url, init) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/intel/correlate') {
        return jsonResponse(CORRELATION, 200, {
          'x-cdb-mesh-certified': 'true',
          'x-cdb-mesh-execution': 'mesh-exec-2',
          'x-cdb-mesh-correlation': init.headers.get('x-request-id'),
        });
      }
      if (u.pathname === '/api/v1/swarm-synthesis/health') {
        return jsonResponse({ status: 'ok', ready: false, llm_enabled: false, tier_llm: true, providers: {} });
      }
      if (u.pathname === '/api/v1/swarm-synthesis') {
        return jsonResponse({ status: 'success', llm_enhanced: false, narrative: null, tier_upgrade: 'Upgrade to PRO...' });
      }
      if (u.pathname === '/api/cves') return jsonResponse({ status: 'ok', data: { cves: [{ cve_id: 'CVE-2026-11111' }] } });
      if (u.pathname === '/api/actors') return jsonResponse({ status: 'ok', data: { actors: [{ actor_tag: 'APT42' }] } });
      if (u.pathname === '/api/search') return jsonResponse({ status: 'ok', data: { results: [{ technique_id: 'T1059' }] } });
      if (u.pathname === '/api/v1/detections') return jsonResponse({
        schema_version: '1.0.0',
        data: [{ artifact_type: 'sigma', id: 'sigma-fallback' }],
        pagination: { total: 1, limit: 5, offset: 0 },
      });
      if (u.pathname === '/api/intel/ir-guidance') return jsonResponse({
        status: 'ok',
        data: { report_id: 'intel--abc123', applicable: true, checklist: { containment: ['isolate'] } },
      });
      if (u.pathname === '/api/intel/exposure') return jsonResponse({
        status: 'ok',
        data: { report_id: 'intel--abc123', exposed_count: 1, dimensions: [{ name: 'internet' }] },
      });
      throw new Error('unexpected deterministic-fallback route: ' + u.pathname);
    },
    async () => {
      let waited;
      const ctx = { waitUntil(p) { waited = p; } };
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'k', 'x-request-id': CORRELATION_ID },
          body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
        }),
        env,
        ctx
      );
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      const events = [];
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const chunk = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const line = chunk.split('\n').find((l) => l.startsWith('data: '));
          if (line) events.push(JSON.parse(line.slice(6)));
        }
      }
      await waited;

      const synthesizerDegraded = events.find((e) =>
        e.agent_id === 'risk-synthesizer' &&
        e.state === 'DEGRADED' &&
        e.event_type === 'agent.degraded'
      );
      assert.ok(synthesizerDegraded);
      assert.equal(synthesizerDegraded.result.llm_enhanced, false);
      assert.equal(synthesizerDegraded.result.ai_narrative, undefined);
      assert.equal(synthesizerDegraded.result.ai_mode, 'deterministic_fallback');
      // Deterministic fusion remains usable evidence, but is never mislabeled
      // as a successful AI-enhanced completion.
      assert.equal(synthesizerDegraded.result.basis, 'fusion');
      assert.equal(typeof synthesizerDegraded.result.recommendation, 'string');

      const missionCompleted = events.find((e) => e.event_type === 'mission.completed');
      assert.ok(missionCompleted);
      assert.equal(missionCompleted.result.llm_enhanced, false);
      assert.equal(missionCompleted.mission_quality, 'AI_DEGRADED_COMPLETE');
    }
  );
});

test('end-to-end mission: canonical correlate denial short-circuits before any specialist runs', async () => {
  await withStubFetch(
    async (url) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/intel/correlate') return jsonResponse({ error: 'forbidden' }, 403);
      throw new Error(`must not call specialists when correlate is denied: ${u.pathname}`);
    },
    async () => {
      const ctx = { waitUntil(p) { this._p = p; } };
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'k' },
          body: JSON.stringify({ ioc_value: '1.2.3.4' }),
        }),
        { CANONICAL_BASE_URL: 'https://x.test' },
        ctx
      );
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let text = '';
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        text += decoder.decode(value, { stream: true });
      }
      await ctx._p;
      assert.match(text, /"event_type":"mission.rejected"/);
      assert.match(text, /"state":"DENIED"/);
    }
  );
});

// ---------------------------------------------------------------------------
// Mission history / evidence export (issue #424 groundwork).
// ---------------------------------------------------------------------------

// A small in-memory approximation of Cloudflare KV's list() semantics
// (lexicographic key order, prefix filter, metadata returned without a
// separate get()) -- enough to exercise handleMissionList's real logic,
// not just mock-call assertions.
function makeKvMock() {
  const store = new Map();
  return {
    async put(key, value, opts = {}) {
      store.set(key, { value, metadata: opts.metadata });
    },
    async get(key) {
      const entry = store.get(key);
      return entry ? entry.value : null;
    },
    async list({ prefix = '', limit = 1000, cursor } = {}) {
      const all = [...store.keys()].filter((k) => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0;
      const page = all.slice(start, start + limit);
      const list_complete = start + limit >= all.length;
      return {
        keys: page.map((name) => ({ name, metadata: store.get(name).metadata })),
        list_complete,
        cursor: list_complete ? undefined : String(start + limit),
      };
    },
    _store: store,
  };
}

test('credentialPartition: same credential yields the same partition, a different credential a different one, no credential null', async () => {
  const a1 = await __test.credentialPartition(new Headers({ 'x-api-key': 'customer-a-key' }));
  const a2 = await __test.credentialPartition(new Headers({ 'x-api-key': 'customer-a-key' }));
  const b = await __test.credentialPartition(new Headers({ 'x-api-key': 'customer-b-key' }));
  const none = await __test.credentialPartition(new Headers());
  assert.equal(a1, a2);
  assert.notEqual(a1, b);
  assert.equal(none, null);
  assert.match(a1, /^[0-9a-f]{16}$/);
});

test('persistMission: without a partition, only the primary record is written (existing behavior unchanged)', async () => {
  const kv = makeKvMock();
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: 'sentinel-mission-z', status: 'COMPLETED' });
  assert.equal(kv._store.size, 1);
  assert.ok(kv._store.has('sentinel-mission-z'));
});

test('persistMission: with a partition, also writes a listable index entry carrying summary metadata', async () => {
  const kv = makeKvMock();
  const record = {
    mission_id: 'sentinel-mission-z2',
    status: 'COMPLETED',
    verdict: 'malicious',
    started_at: '2026-01-01T00:00:00.000Z',
    finished_at: '2026-01-01T00:00:05.000Z',
    ioc: { ioc_value: '1.2.3.4', ioc_type: 'ipv4' },
  };
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, record, 'deadbeefdeadbeef');
  assert.equal(kv._store.size, 2);
  const indexKey = [...kv._store.keys()].find((k) => k.startsWith(__test.MISSION_INDEX_PREFIX));
  assert.ok(indexKey.startsWith(`${__test.MISSION_INDEX_PREFIX}deadbeefdeadbeef:`));
  const meta = kv._store.get(indexKey).metadata;
  assert.equal(meta.mission_id, 'sentinel-mission-z2');
  assert.equal(meta.verdict, 'malicious');
  assert.equal(meta.ioc_value, '1.2.3.4');
});

test('getMissionRecord: unavailable, not found, corrupt, and success', async () => {
  assert.equal((await __test.getMissionRecord({}, 'x')).status, 503);
  assert.equal((await __test.getMissionRecord({ SWARM_MISSIONS_KV: { async get() { return null; } } }, 'x')).status, 404);
  assert.equal((await __test.getMissionRecord({ SWARM_MISSIONS_KV: { async get() { return 'not json'; } } }, 'x')).status, 500);
  const ok = await __test.getMissionRecord({ SWARM_MISSIONS_KV: { async get() { return JSON.stringify({ mission_id: 'x' }); } } }, 'x');
  assert.equal(ok.status, 200);
  assert.equal(ok.record.mission_id, 'x');
});

test('new mission read-back and evidence exports are credential-owner scoped', async () => {
  const kv = makeKvMock();
  const ownerHeaders = new Headers({ 'x-api-key': 'owner-customer-key' });
  const otherHeaders = new Headers({ 'x-api-key': 'different-customer-key' });
  const ownerPartition = await __test.credentialPartition(ownerHeaders);

  const record = {
    mission_id: 'sentinel-mission-owned-1',
    execution_id: 'sentinel-swarm-owned-1',
    correlation_id: 'owned-corr-1',
    status: 'COMPLETED',
    verdict: 'malicious',
    started_at: '2026-09-20T00:00:00.000Z',
    finished_at: '2026-09-20T00:00:03.000Z',
    ioc: { ioc_value: '203.0.113.9', ioc_type: 'ipv4' },
    specialists: { 'ioc-hunter': { basis: 'backend_execution', state: 'COMPLETED', result: { verdict: 'malicious' } } },
  };
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, record, ownerPartition);

  const stored = JSON.parse(kv._store.get(record.mission_id).value);
  assert.equal(stored._owner_partition, ownerPartition);

  const ownerRead = await worker.fetch(
    new Request('https://x.test/api/swarm/mission/sentinel-mission-owned-1', { headers: ownerHeaders }),
    { SWARM_MISSIONS_KV: kv },
    {}
  );
  assert.equal(ownerRead.status, 200);
  const ownerBody = await ownerRead.json();
  assert.equal(ownerBody.data.mission_id, record.mission_id);
  assert.equal(Object.prototype.hasOwnProperty.call(ownerBody.data, '_owner_partition'), false);

  const otherRead = await worker.fetch(
    new Request('https://x.test/api/swarm/mission/sentinel-mission-owned-1', { headers: otherHeaders }),
    { SWARM_MISSIONS_KV: kv },
    {}
  );
  assert.equal(otherRead.status, 404);
  assert.equal((await otherRead.json()).error, 'mission_not_found');

  const otherReport = await worker.fetch(
    new Request('https://x.test/api/swarm/mission/sentinel-mission-owned-1/report?format=json', { headers: otherHeaders }),
    { SWARM_MISSIONS_KV: kv },
    {}
  );
  assert.equal(otherReport.status, 404);

  const ownerReport = await worker.fetch(
    new Request('https://x.test/api/swarm/mission/sentinel-mission-owned-1/report?format=json', { headers: ownerHeaders }),
    { SWARM_MISSIONS_KV: kv },
    {}
  );
  assert.equal(ownerReport.status, 200);
  const ownerReportBody = await ownerReport.json();
  assert.equal(ownerReportBody.data.mission_id, record.mission_id);
  assert.equal(Object.prototype.hasOwnProperty.call(ownerReportBody.data, '_owner_partition'), false);
});

test('legacy mission records without ownership metadata remain backward-compatible', async () => {
  const kv = makeKvMock();
  await kv.put('sentinel-mission-legacy-1', JSON.stringify({
    mission_id: 'sentinel-mission-legacy-1',
    status: 'COMPLETED',
    ioc: { ioc_value: '198.51.100.2', ioc_type: 'ipv4' },
  }));

  const response = await worker.fetch(
    new Request('https://x.test/api/swarm/mission/sentinel-mission-legacy-1', {
      headers: { 'x-api-key': 'any-existing-customer-key' },
    }),
    { SWARM_MISSIONS_KV: kv },
    {}
  );
  assert.equal(response.status, 200);
  assert.equal((await response.json()).data.mission_id, 'sentinel-mission-legacy-1');
});

test('GET /api/swarm/missions: requires auth, 503s when unprovisioned, and scopes strictly to the caller\'s own credential', async () => {
  const kv = makeKvMock();
  const envNoAuth = {};
  const resNoAuth = await worker.fetch(new Request('https://x.test/api/swarm/missions'), envNoAuth, {});
  assert.equal(resNoAuth.status, 401);

  const resUnavailable = await worker.fetch(new Request('https://x.test/api/swarm/missions', { headers: { 'x-api-key': 'k' } }), {}, {});
  assert.equal(resUnavailable.status, 503);

  const partA = await __test.credentialPartition(new Headers({ 'x-api-key': 'customer-a' }));
  const partB = await __test.credentialPartition(new Headers({ 'x-api-key': 'customer-b' }));
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: 'sentinel-mission-a1', status: 'COMPLETED', ioc: { ioc_value: '1.1.1.1' } }, partA);
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: 'sentinel-mission-b1', status: 'COMPLETED', ioc: { ioc_value: '2.2.2.2' } }, partB);

  const resA = await worker.fetch(new Request('https://x.test/api/swarm/missions', { headers: { 'x-api-key': 'customer-a' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(resA.status, 200);
  const bodyA = await resA.json();
  assert.equal(bodyA.data.missions.length, 1);
  assert.equal(bodyA.data.missions[0].mission_id, 'sentinel-mission-a1');

  const resB = await worker.fetch(new Request('https://x.test/api/swarm/missions', { headers: { 'x-api-key': 'customer-b' } }), { SWARM_MISSIONS_KV: kv }, {});
  const bodyB = await resB.json();
  assert.equal(bodyB.data.missions.length, 1);
  assert.equal(bodyB.data.missions[0].mission_id, 'sentinel-mission-b1');
});

test('GET /api/swarm/missions: optional status filter and pagination fields', async () => {
  const kv = makeKvMock();
  const part = await __test.credentialPartition(new Headers({ 'x-api-key': 'customer-c' }));
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: 'sentinel-mission-c1', status: 'COMPLETED' }, part);
  await new Promise((r) => setTimeout(r, 2));
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: 'sentinel-mission-c2', status: 'FAILED' }, part);

  const res = await worker.fetch(new Request('https://x.test/api/swarm/missions?status=FAILED', { headers: { 'x-api-key': 'customer-c' } }), { SWARM_MISSIONS_KV: kv }, {});
  const body = await res.json();
  assert.equal(body.data.missions.length, 1);
  assert.equal(body.data.missions[0].mission_id, 'sentinel-mission-c2');
  assert.equal(typeof body.data.list_complete, 'boolean');
});

test('GET /api/swarm/metrics: computes real credential-scoped observed metrics from index metadata only', async () => {
  const kv = makeKvMock();
  let getCalls = 0;
  const originalGet = kv.get.bind(kv);
  kv.get = async (...args) => { getCalls += 1; return originalGet(...args); };

  const partA = await __test.credentialPartition(new Headers({ 'x-api-key': 'metrics-a' }));
  const partB = await __test.credentialPartition(new Headers({ 'x-api-key': 'metrics-b' }));

  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, {
    mission_id: 'sentinel-mission-metrics-a1',
    status: 'COMPLETED',
    mission_quality: 'FULL_FABRIC_COMPLETE',
    mission_profile: 'AUTO',
    duration_ms: 1000,
    metrics: { completed: 8, not_applicable: 0, degraded: 0, denied: 0, unavailable: 0, failed: 0 },
    specialists: { 'risk-synthesizer': { result: { llm_enhanced: true } } },
    ioc: { ioc_value: 'evil.example', ioc_type: 'domain' },
  }, partA);

  await new Promise((r) => setTimeout(r, 2));

  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, {
    mission_id: 'sentinel-mission-metrics-a2',
    status: 'COMPLETED',
    mission_quality: 'PARTIAL_FABRIC_COMPLETE',
    mission_profile: 'AUTO',
    duration_ms: 3000,
    metrics: { completed: 5, not_applicable: 3, degraded: 0, denied: 0, unavailable: 0, failed: 0 },
    specialists: { 'risk-synthesizer': { result: { llm_enhanced: false } } },
    ioc: { ioc_value: 'example.org', ioc_type: 'domain' },
  }, partA);

  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, {
    mission_id: 'sentinel-mission-metrics-b1',
    status: 'FAILED',
    mission_quality: 'FAILED',
    duration_ms: 9000,
    metrics: { completed: 0, not_applicable: 0, degraded: 0, denied: 0, unavailable: 0, failed: 8 },
  }, partB);

  getCalls = 0;
  const response = await worker.fetch(
    new Request('https://x.test/api/swarm/metrics?limit=50', { headers: { 'x-api-key': 'metrics-a' } }),
    { SWARM_MISSIONS_KV: kv },
    {},
  );

  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.data.scope, 'credential_owned_latest_missions');
  assert.equal(body.data.sample_size, 2);
  assert.equal(body.data.mission_counts.completed, 2);
  assert.equal(body.data.mission_counts.full_fabric_complete, 1);
  assert.equal(body.data.mission_quality.FULL_FABRIC_COMPLETE, 1);
  assert.equal(body.data.mission_quality.PARTIAL_FABRIC_COMPLETE, 1);
  assert.equal(body.data.latency_ms.p50, 1000);
  assert.equal(body.data.latency_ms.p95, 3000);
  assert.equal(body.data.ai_synthesis.llm_enhanced_missions, 1);
  assert.equal(body.data.ai_synthesis.llm_enhanced_rate, 0.5);
  assert.equal(body.data.agent_terminal_states.completed, 13);
  assert.equal(body.data.agent_terminal_states.not_applicable, 3);
  assert.equal(getCalls, 0, 'metrics must use index metadata without per-mission KV get() scans');
});


test('GET /api/swarm/mission/:id/report: validates id, requires auth, and propagates not-found', async () => {
  const badId = await worker.fetch(new Request('https://x.test/api/swarm/mission/has space/report', { headers: { 'x-api-key': 'k' } }), {}, {});
  assert.equal(badId.status, 400);

  const noAuth = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-x/report'), {}, {});
  assert.equal(noAuth.status, 401);

  const kv = { async get() { return null; } };
  const notFound = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-x/report', { headers: { 'x-api-key': 'k' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(notFound.status, 404);
});

test('GET /api/swarm/mission/:id/report: default Markdown export is downloadable and includes mission + agent evidence', async () => {
  const record = {
    mission_id: 'sentinel-mission-r1',
    execution_id: 'sentinel-swarm-r1',
    correlation_id: 'corr-r1',
    status: 'COMPLETED',
    verdict: 'malicious',
    mission_quality: 'COMPLETED_WITH_WARNINGS',
    mission_profile: 'AUTO',
    duration_ms: 5000,
    evidence_graph: { schema: 'cdb.swarm.evidence-graph.v1', node_count: 7, edge_count: 9, nodes: [], edges: [] },
    mesh_certified: true,
    mesh_execution_id: 'mesh-exec-9',
    started_at: '2026-01-01T00:00:00.000Z',
    finished_at: '2026-01-01T00:00:05.000Z',
    ioc: { ioc_value: '9.9.9.9', ioc_type: 'ipv4' },
    specialists: {
      'ioc-hunter': { basis: 'backend_execution', state: 'COMPLETED', result: { verdict: 'malicious' } },
      'threat-hunter': { basis: 'backend_execution', state: 'DENIED', result: null },
    },
  };
  const kv = { async get(key) { return key === 'sentinel-mission-r1' ? JSON.stringify(record) : null; } };
  const res = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-r1/report', { headers: { 'x-api-key': 'k' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'text/markdown; charset=utf-8');
  assert.match(res.headers.get('content-disposition'), /attachment; filename="sentinel-mission-r1\.md"/);
  const text = await res.text();
  assert.match(text, /sentinel-mission-r1/);
  assert.match(text, /9\.9\.9\.9/);
  assert.match(text, /malicious/);
  assert.match(text, /Mission Quality:\*\* COMPLETED_WITH_WARNINGS/);
  assert.match(text, /Mission Profile:\*\* AUTO/);
  assert.match(text, /Duration:\*\* 5000 ms/);
  assert.match(text, /Evidence Graph:\*\* 7 nodes \/ 9 edges/);
  assert.match(text, /### ioc-hunter/);
  assert.match(text, /### threat-hunter/);
  assert.match(text, /- state: DENIED/);
});

test('GET /api/swarm/mission/:id/report?format=json: returns the raw record as a downloadable attachment', async () => {
  const record = { mission_id: 'sentinel-mission-r2', status: 'COMPLETED' };
  const kv = { async get(key) { return key === 'sentinel-mission-r2' ? JSON.stringify(record) : null; } };
  const res = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-r2/report?format=json', { headers: { 'x-api-key': 'k' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-disposition'), /attachment; filename="sentinel-mission-r2\.json"/);
  const body = await res.json();
  assert.deepEqual(body.data, record);
});

test('GET /api/swarm/health reports real persistence status, not a static ack', async () => {
  const unbound = await worker.fetch(new Request('https://x.test/api/swarm/health'), {}, {});
  assert.equal((await unbound.json()).persistence.kv_bound, false);

  const bound = await worker.fetch(new Request('https://x.test/api/swarm/health'), { SWARM_MISSIONS_KV: {} }, {});
  assert.equal((await bound.json()).persistence.kv_bound, true);
});

test('end-to-end: a completed mission is immediately visible in its own caller\'s history and exportable as a report', async () => {
  const kv = makeKvMock();
  const env = { CANONICAL_BASE_URL: 'https://x.test', SWARM_MISSIONS_KV: kv };

  await withStubFetch(
    async (url, init) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/intel/correlate') {
        return jsonResponse(CORRELATION, 200, {
          'x-cdb-mesh-certified': 'true',
          'x-cdb-mesh-execution': 'mesh-exec-e2e',
          'x-cdb-mesh-correlation': init.headers.get('x-request-id'),
        });
      }
      if (u.pathname === '/api/v1/swarm-synthesis') return jsonResponse({ status: 'success', llm_enhanced: false, narrative: null });
      return jsonResponse({ status: 'ok', data: {} });
    },
    async () => {
      let waited;
      const ctx = { waitUntil(p) { waited = p; } };
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'history-customer', 'x-request-id': CORRELATION_ID },
          body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
        }),
        env,
        ctx
      );
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      let missionId;
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n\n')) >= 0) {
          const chunk = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const line = chunk.split('\n').find((l) => l.startsWith('data: '));
          if (line) { const ev = JSON.parse(line.slice(6)); missionId = ev.mission_id; }
        }
      }
      await waited;

      const listRes = await worker.fetch(new Request('https://x.test/api/swarm/missions', { headers: { 'x-api-key': 'history-customer' } }), env, {});
      const listBody = await listRes.json();
      assert.equal(listBody.data.missions.length, 1);
      assert.equal(listBody.data.missions[0].mission_id, missionId);
      assert.equal(listBody.data.missions[0].status, 'COMPLETED');

      // A different credential must see none of this caller's history.
      const otherRes = await worker.fetch(new Request('https://x.test/api/swarm/missions', { headers: { 'x-api-key': 'someone-else' } }), env, {});
      assert.equal((await otherRes.json()).data.missions.length, 0);

      const reportRes = await worker.fetch(new Request(`https://x.test/api/swarm/mission/${missionId}/report`, { headers: { 'x-api-key': 'history-customer' } }), env, {});
      assert.equal(reportRes.status, 200);
      assert.match(await reportRes.text(), new RegExp(missionId));
    }
  );
});

// ---------------------------------------------------------------------------
// STIX 2.1 export.
// ---------------------------------------------------------------------------

test('detectStixObservableType: classifies real input values deterministically, never mislabels the unrecognized case', () => {
  assert.equal(__test.detectStixObservableType('8.8.8.8', 'auto'), 'ipv4');
  assert.equal(__test.detectStixObservableType('2001:db8::1', 'auto'), 'ipv6');
  assert.equal(__test.detectStixObservableType('https://evil.test/x', 'auto'), 'url');
  assert.equal(__test.detectStixObservableType('example.com', 'auto'), 'domain');
  assert.equal(__test.detectStixObservableType('d41d8cd98f00b204e9800998ecf8427e', 'auto'), 'hash'); // 32 hex = MD5-length
  assert.equal(__test.detectStixObservableType('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'auto'), 'hash'); // 40 hex
  assert.equal(__test.detectStixObservableType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'auto'), 'hash'); // 64 hex
  assert.equal(__test.detectStixObservableType('not a recognizable value!!', 'auto'), 'unknown');
});

test('missionIocToStixPattern: produces the correct SCO pattern per detected type and escapes quotes', () => {
  assert.equal(__test.missionIocToStixPattern('8.8.8.8', 'ipv4'), "[ipv4-addr:value = '8.8.8.8']");
  assert.equal(__test.missionIocToStixPattern('example.com', 'domain'), "[domain-name:value = 'example.com']");
  assert.equal(__test.missionIocToStixPattern("evil'.test", 'domain'), "[domain-name:value = 'evil.test']");
  assert.equal(
    __test.missionIocToStixPattern('da39a3ee5e6b4b0d3255bfef95601890afd80709', 'hash'),
    "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']"
  );
  assert.match(__test.missionIocToStixPattern('gibberish', 'auto'), /^\[x-sentinel:value = 'gibberish'\]$/);
});

test('missionToStixBundle: a valid STIX 2.1 Bundle with one Indicator and one Note per agent, correctly cross-referenced', () => {
  const record = {
    mission_id: 'sentinel-mission-stix1',
    execution_id: 'sentinel-swarm-stix1',
    correlation_id: 'corr-stix1',
    verdict: 'malicious',
    mesh_certified: true,
    started_at: '2026-01-01T00:00:00.000Z',
    finished_at: '2026-01-01T00:00:03.000Z',
    ioc: { ioc_value: '8.8.8.8', ioc_type: 'ipv4' },
    specialists: {
      'ioc-hunter': { basis: 'backend_execution', state: 'COMPLETED', result: { verdict: 'malicious' } },
      'threat-hunter': { basis: 'backend_execution', state: 'DENIED', result: null },
    },
  };
  const bundle = __test.missionToStixBundle(record);
  assert.equal(bundle.type, 'bundle');
  assert.equal(Object.prototype.hasOwnProperty.call(bundle, 'spec_version'), false, 'STIX Bundle must not carry STIX Object spec_version');
  assert.match(bundle.id, /^bundle--[0-9a-f-]{36}$/);

  const indicator = bundle.objects.find((o) => o.type === 'indicator');
  assert.ok(indicator);
  assert.match(indicator.id, /^indicator--[0-9a-f-]{36}$/);
  assert.equal(indicator.spec_version, '2.1');
  assert.equal(indicator.pattern, "[ipv4-addr:value = '8.8.8.8']");
  assert.equal(indicator.indicator_types[0], 'malicious-activity');
  assert.equal(indicator.x_sentinel_mission_id, 'sentinel-mission-stix1');
  assert.equal(indicator.x_sentinel_verdict, 'malicious');
  assert.equal(Object.prototype.hasOwnProperty.call(indicator, 'custom_properties'), false);

  const notes = bundle.objects.filter((o) => o.type === 'note');
  assert.equal(notes.length, 2);
  for (const note of notes) {
    assert.match(note.id, /^note--[0-9a-f-]{36}$/);
    assert.deepEqual(note.object_refs, [indicator.id]);
    assert.ok(['ioc-hunter', 'threat-hunter'].includes(note.x_sentinel_agent_id));
    assert.equal(Object.prototype.hasOwnProperty.call(note, 'custom_properties'), false);
  }
  // Every object id in the bundle is unique -- no accidental id reuse.
  assert.equal(new Set(bundle.objects.map((o) => o.id)).size, bundle.objects.length);
});

test('missionToStixBundle keeps custom x_sentinel properties at top level for STIX 2.1 interoperability', () => {
  const bundle = __test.missionToStixBundle({
    mission_id: 'sentinel-mission-custom-props',
    verdict: 'clean',
    mission_quality: 'PARTIAL_FABRIC_COMPLETE',
    mission_profile: 'IOC_TRIAGE',
    duration_ms: 3210,
    evidence_graph: { schema: 'cdb.swarm.evidence-graph.v1', node_count: 4, edge_count: 5, nodes: [], edges: [] },
    ioc: { ioc_value: '1.1.1.1', ioc_type: 'ipv4' },
    specialists: {
      'ioc-hunter': { basis: 'backend_execution', state: 'COMPLETED', result: { verdict: 'clean' } },
      'cve-intelligence': { basis: 'conditional_skip', state: 'SKIPPED', result: { reason: 'dependency_input_absent' } },
    },
  });
  assert.equal(bundle.spec_version, undefined);
  for (const object of bundle.objects) {
    assert.equal(object.custom_properties, undefined);
  }
  const indicator = bundle.objects.find((o) => o.type === 'indicator');
  assert.ok(indicator.x_sentinel_mission_id);
  assert.equal(indicator.x_sentinel_mission_quality, 'PARTIAL_FABRIC_COMPLETE');
  assert.equal(indicator.x_sentinel_mission_profile, 'IOC_TRIAGE');
  assert.equal(indicator.x_sentinel_duration_ms, 3210);
  assert.equal(indicator.x_sentinel_evidence_graph_nodes, 4);
  assert.equal(indicator.x_sentinel_evidence_graph_edges, 5);
  const skippedNote = bundle.objects.find((o) => o.type === 'note' && o.x_sentinel_agent_id === 'cve-intelligence');
  assert.equal(skippedNote.x_sentinel_agent_state, 'SKIPPED');
});

test('GET /api/swarm/mission/:id/report?format=stix21: serves a valid, downloadable STIX 2.1 Bundle', async () => {
  const record = {
    mission_id: 'sentinel-mission-stix2',
    verdict: 'suspicious',
    ioc: { ioc_value: 'evil.example.com', ioc_type: 'domain' },
    specialists: { 'ioc-hunter': { basis: 'backend_execution', state: 'COMPLETED', result: {} } },
  };
  const kv = { async get(key) { return key === 'sentinel-mission-stix2' ? JSON.stringify(record) : null; } };
  const res = await worker.fetch(new Request('https://x.test/api/swarm/mission/sentinel-mission-stix2/report?format=stix21', { headers: { 'x-api-key': 'k' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/stix+json;version=2.1');
  assert.match(res.headers.get('content-disposition'), /attachment; filename="sentinel-mission-stix2\.stix21\.json"/);
  const bundle = await res.json();
  assert.equal(bundle.type, 'bundle');
  assert.equal(Object.prototype.hasOwnProperty.call(bundle, 'spec_version'), false);
  assert.equal(bundle.objects.find((o) => o.type === 'indicator').pattern, "[domain-name:value = 'evil.example.com']");
});

// ---------------------------------------------------------------------------
// Idempotent retry.
// ---------------------------------------------------------------------------

test('getIdempotencyPointer / setIdempotencyPointer: round-trip and graceful no-ops', async () => {
  assert.equal(await __test.getIdempotencyPointer({}, 'p', 'c'), null);
  assert.equal(await __test.getIdempotencyPointer({ SWARM_MISSIONS_KV: {} }, null, 'c'), null);

  const kv = makeKvMock();
  await __test.setIdempotencyPointer({ SWARM_MISSIONS_KV: kv }, 'partA', 'req-1', 'sentinel-mission-i1', 'RUNNING');
  const pointer = await __test.getIdempotencyPointer({ SWARM_MISSIONS_KV: kv }, 'partA', 'req-1');
  assert.deepEqual(pointer, { mission_id: 'sentinel-mission-i1', status: 'RUNNING' });

  await __test.setIdempotencyPointer({ SWARM_MISSIONS_KV: kv }, 'partA', 'req-1', 'sentinel-mission-i1', 'COMPLETED');
  const updated = await __test.getIdempotencyPointer({ SWARM_MISSIONS_KV: kv }, 'partA', 'req-1');
  assert.equal(updated.status, 'COMPLETED');
});

test('POST /api/swarm/run: a retry with the same x-request-id while the original mission is still RUNNING gets 409, never a duplicate dispatch', async () => {
  const kv = makeKvMock();
  const partition = await __test.credentialPartition(new Headers({ 'x-api-key': 'idem-customer' }));
  await __test.setIdempotencyPointer({ SWARM_MISSIONS_KV: kv }, partition, 'retry-key-1', 'sentinel-mission-inflight', 'RUNNING');

  await withStubFetch(
    async (url) => { throw new Error(`must not dispatch a duplicate mission, but fetched: ${url}`); },
    async () => {
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'idem-customer', 'x-request-id': 'retry-key-1' },
          body: JSON.stringify({ ioc_value: '8.8.8.8' }),
        }),
        { SWARM_MISSIONS_KV: kv },
        { waitUntil() {} }
      );
      assert.equal(res.status, 409);
      const body = await res.json();
      assert.equal(body.error, 'mission_in_progress');
      assert.equal(body.mission_id, 'sentinel-mission-inflight');
    }
  );
});

test('POST /api/swarm/run: a retry with the same x-request-id after completion replays the persisted record, never a duplicate dispatch', async () => {
  const kv = makeKvMock();
  const partition = await __test.credentialPartition(new Headers({ 'x-api-key': 'idem-customer-2' }));
  const record = { mission_id: 'sentinel-mission-done', status: 'COMPLETED', verdict: 'clean' };
  await kv.put('sentinel-mission-done', JSON.stringify(record));
  await __test.setIdempotencyPointer({ SWARM_MISSIONS_KV: kv }, partition, 'retry-key-2', 'sentinel-mission-done', 'COMPLETED');

  await withStubFetch(
    async (url) => { throw new Error(`must not dispatch a duplicate mission, but fetched: ${url}`); },
    async () => {
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'idem-customer-2', 'x-request-id': 'retry-key-2' },
          body: JSON.stringify({ ioc_value: '8.8.8.8' }),
        }),
        { SWARM_MISSIONS_KV: kv },
        { waitUntil() {} }
      );
      assert.equal(res.status, 200);
      const body = await res.json();
      assert.equal(body.idempotent_replay, true);
      assert.deepEqual(body.data, record);
    }
  );
});

test('POST /api/swarm/run: a different credential reusing the same x-request-id is never treated as a duplicate (different partition)', async () => {
  const kv = makeKvMock();
  const partitionA = await __test.credentialPartition(new Headers({ 'x-api-key': 'customer-x' }));
  await __test.setIdempotencyPointer({ SWARM_MISSIONS_KV: kv }, partitionA, 'shared-request-id', 'sentinel-mission-x', 'RUNNING');

  await withStubFetch(
    async (url) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/intel/correlate') {
        return jsonResponse({ status: 'ok', ioc: { value: '1.1.1.1', type: 'ipv4' }, verdict: 'clean', match_count: 0, matches: [] }, 200, {
          'x-cdb-mesh-certified': 'true', 'x-cdb-mesh-execution': 'mesh-x', 'x-cdb-mesh-correlation': 'shared-request-id',
        });
      }
      return jsonResponse({ status: 'ok', data: {} });
    },
    async () => {
      let waited;
      const res = await worker.fetch(
        new Request('https://x.test/api/swarm/run', {
          method: 'POST',
          headers: { 'x-api-key': 'customer-y', 'x-request-id': 'shared-request-id' },
          body: JSON.stringify({ ioc_value: '1.1.1.1' }),
        }),
        { SWARM_MISSIONS_KV: kv },
        { waitUntil(p) { waited = p; } }
      );
      assert.equal(res.status, 200);
      assert.equal(res.headers.get('content-type'), 'text/event-stream; charset=utf-8');
      await res.body.cancel();
      await waited;
    }
  );
});

test('end-to-end: an in-flight-then-completed retry cycle never dispatches the downstream correlate call twice', async () => {
  const kv = makeKvMock();
  const env = { CANONICAL_BASE_URL: 'https://x.test', SWARM_MISSIONS_KV: kv };
  let correlateCalls = 0;

  await withStubFetch(
    async (url, init) => {
      const u = new URL(String(url));
      if (u.pathname === '/api/intel/correlate') {
        correlateCalls++;
        return jsonResponse(CORRELATION, 200, {
          'x-cdb-mesh-certified': 'true',
          'x-cdb-mesh-execution': 'mesh-idem-e2e',
          'x-cdb-mesh-correlation': init.headers.get('x-request-id'),
        });
      }
      return jsonResponse({ status: 'ok', data: {} });
    },
    async () => {
      const makeReq = () => new Request('https://x.test/api/swarm/run', {
        method: 'POST',
        headers: { 'x-api-key': 'idem-e2e-customer', 'x-request-id': 'idem-e2e-request' },
        body: JSON.stringify({ ioc_value: '8.8.8.8', ioc_type: 'ipv4' }),
      });

      let waited;
      const first = await worker.fetch(makeReq(), env, { waitUntil(p) { waited = p; } });
      // Drain the SSE stream so executeMission's finally{} (and finish())
      // actually completes before the retry is issued.
      const reader = first.body.getReader();
      while (!(await reader.read()).done) { /* drain */ }
      await waited;

      const secondBeforeCompletion = correlateCalls;
      const retry = await worker.fetch(makeReq(), env, { waitUntil() {} });
      assert.equal(retry.status, 200);
      const retryBody = await retry.json();
      assert.equal(retryBody.idempotent_replay, true);
      assert.equal(retryBody.data.status, 'COMPLETED');
      // The retry must not have triggered a second real correlate call.
      assert.equal(correlateCalls, secondBeforeCompletion);
    }
  );
});

// ---------------------------------------------------------------------------
// Partition isolation under stress / invalid parameters.
// ---------------------------------------------------------------------------

test('GET /api/swarm/missions: limit is clamped into [1, 100] regardless of what is requested', async () => {
  const kv = makeKvMock();
  const part = await __test.credentialPartition(new Headers({ 'x-api-key': 'clamp-customer' }));
  for (let i = 0; i < 5; i++) {
    await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: `sentinel-mission-clamp-${i}`, status: 'COMPLETED' }, part);
  }
  const tooLow = await worker.fetch(new Request('https://x.test/api/swarm/missions?limit=0', { headers: { 'x-api-key': 'clamp-customer' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal((await tooLow.json()).data.missions.length, 1);

  const tooHigh = await worker.fetch(new Request('https://x.test/api/swarm/missions?limit=99999', { headers: { 'x-api-key': 'clamp-customer' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal((await tooHigh.json()).data.missions.length, 5);

  const negative = await worker.fetch(new Request('https://x.test/api/swarm/missions?limit=-5', { headers: { 'x-api-key': 'clamp-customer' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(negative.status, 200);
});

test('GET /api/swarm/missions: a garbage cursor never throws and never crosses into another caller\'s partition', async () => {
  const kv = makeKvMock();
  const partA = await __test.credentialPartition(new Headers({ 'x-api-key': 'stress-a' }));
  const partB = await __test.credentialPartition(new Headers({ 'x-api-key': 'stress-b' }));
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: 'sentinel-mission-sa', status: 'COMPLETED' }, partA);
  await __test.persistMission({ SWARM_MISSIONS_KV: kv }, { mission_id: 'sentinel-mission-sb', status: 'COMPLETED' }, partB);

  const res = await worker.fetch(new Request('https://x.test/api/swarm/missions?cursor=not-a-real-cursor%00%00', { headers: { 'x-api-key': 'stress-a' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(res.status, 200);
  const body = await res.json();
  for (const m of body.data.missions) assert.notEqual(m.mission_id, 'sentinel-mission-sb');
});

test('GET /api/swarm/missions: KV list() throwing degrades to a clean 500, never an unhandled rejection', async () => {
  const kv = { async list() { throw new Error('kv unavailable'); } };
  const res = await worker.fetch(new Request('https://x.test/api/swarm/missions', { headers: { 'x-api-key': 'k' } }), { SWARM_MISSIONS_KV: kv }, {});
  assert.equal(res.status, 500);
  assert.equal((await res.json()).error, 'mission_list_failed');
});


test('SWARM preflight proxy forwards credentials only to the canonical gateway and preserves its decision', async () => {
  const credential = 'sentinel-production-key-material-1234567890';
  let observed = null;
  const env = {
    CANONICAL_BASE_URL: 'https://intel.cyberdudebivash.com',
    CANONICAL_GATEWAY: {
      async fetch(request) {
        observed = {
          method: request.method,
          pathname: new URL(request.url).pathname,
          apiKey: request.headers.get('x-api-key'),
          requestId: request.headers.get('x-request-id'),
        };
        return jsonResponse({
          status: 'ok',
          eligible: true,
          entitlement: {
            tier: 'ENTERPRISE',
            swarm_enabled: true,
            required_scope: 'read:intel',
            scope_granted: true,
          },
          quota: { daily: { available: true, limit: 50000, used: 7, remaining: 49993, exhausted: false } },
        });
      },
    },
  };

  const response = await worker.fetch(
    new Request('https://intel.cyberdudebivash.com/api/swarm/preflight', {
      headers: { 'x-api-key': credential, 'x-request-id': 'preflight-test-1' },
    }),
    env,
    { waitUntil() {} },
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-cdb-swarm-preflight'), 'canonical');
  assert.deepEqual(observed, {
    method: 'GET',
    pathname: '/api/v1/swarm/preflight',
    apiKey: credential,
    requestId: 'preflight-test-1',
  });

  const body = await response.json();
  assert.equal(body.eligible, true);
  assert.equal(body.entitlement.tier, 'ENTERPRISE');
  assert.equal(JSON.stringify(body).includes(credential), false, 'preflight response must never reflect credential material');
});

test('SWARM preflight rejects missing credentials without contacting the canonical gateway', async () => {
  let called = false;
  const response = await worker.fetch(
    new Request('https://intel.cyberdudebivash.com/api/swarm/preflight'),
    {
      CANONICAL_GATEWAY: {
        async fetch() {
          called = true;
          throw new Error('must not be reached');
        },
      },
    },
    { waitUntil() {} },
  );
  assert.equal(response.status, 401);
  assert.equal(called, false);
  assert.equal((await response.json()).error, 'authentication_required');
});

test('customer console locks mission launch behind canonical entitlement preflight', () => {
  const html = __test.ui();
  const js = __test.swarmAppJs();

  assert.ok(html.includes('id="preflightStatus"'));
  assert.ok(html.includes('id="preflightState">ACCESS NOT VERIFIED</'));
  assert.ok(html.includes('id="preflightDetail"'));
  assert.ok(html.includes('id="run" disabled'));
  assert.ok(html.includes('V4.47.0 PRODUCTION'));

  assert.ok(js.includes("fetch('/api/swarm/preflight'"));
  assert.ok(js.includes("keyInput.onpaste"));
  assert.ok(js.includes("keyInput.onchange"));
  assert.ok(js.includes("keyInput.oninput"));
  assert.ok(js.includes("!preflight.eligible||preflight.key!==key"));
  assert.ok(js.includes("SWARM ACCESS VERIFIED"));
  assert.ok(js.includes("daily requests remaining"));
  assert.ok(js.includes("controller.abort()"));
  assert.equal(js.includes('localStorage'), false);
  assert.equal(js.includes('sessionStorage'), false);
});

test('SWARM health truthfully advertises entitlement preflight capability', async () => {
  const response = await worker.fetch(
    new Request('https://intel.cyberdudebivash.com/api/swarm/health'),
    { SWARM_VERSION: '4.47.0', CANONICAL_GATEWAY: { fetch() {} }, SWARM_MISSIONS_KV: {} },
    { waitUntil() {} },
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.version, '4.47.0');
  assert.equal(body.capabilities.entitlement_preflight, true);
});
