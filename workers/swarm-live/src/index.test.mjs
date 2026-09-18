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
    'siem-defender': { basis: 'backend_execution', state: 'COMPLETED' },
    'ir-playbook': { basis: 'backend_execution', state: 'COMPLETED' },
    'exposure-analyst': { basis: 'backend_execution', state: 'COMPLETED' },
  };
  const fused = __test.fuseRiskSynthesis(CORRELATION, outcomes);
  assert.equal(fused.basis, 'fusion');
  assert.deepEqual(fused.contributing_specialists.sort(), ['cve-intelligence', 'exposure-analyst', 'ioc-hunter', 'ir-playbook', 'siem-defender']);
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

test('runBackendSpecialist: skips the live call and returns a derived no-op when there is nothing to query', async () => {
  let called = false;
  await withStubFetch(() => { called = true; throw new Error('must not be called'); }, async () => {
    const outcome = await __test.runBackendSpecialist('https://x.test', new Headers(), CORRELATION_ID, { matches: [] }, __test.SPECIALIST_ROUTES['cve-intelligence']);
    assert.equal(outcome.basis, 'derived');
    assert.equal(outcome.state, 'COMPLETED');
    assert.match(outcome.result.note, /no CVE identifier/);
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
  const res = await worker.fetch(new Request('https://x.test/api/swarm/health'), { SWARM_VERSION: '4.44.0' }, {});
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.protocol, 'cdb.swarm.v1');
  assert.equal(body.agents, 8);
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
      if (u.pathname === '/api/v1/detections') return jsonResponse({ status: 'ok', data: { count: 1, data: [{ id: 'sigma-1' }] } });
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
      if (u.pathname === '/api/v1/swarm-synthesis') {
        return jsonResponse({ status: 'success', llm_enhanced: false, narrative: null, tier_upgrade: 'Upgrade to PRO...' });
      }
      // Every specialist route: a minimal genuine COMPLETED response --
      // this test's focus is the synthesis fallback, not specialist variety
      // (already covered by the main end-to-end test above).
      return jsonResponse({ status: 'ok', data: {} });
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

      const synthesizerCompleted = events.find((e) => e.agent_id === 'risk-synthesizer' && e.state === 'COMPLETED');
      assert.ok(synthesizerCompleted);
      assert.equal(synthesizerCompleted.result.llm_enhanced, false);
      assert.equal(synthesizerCompleted.result.ai_narrative, undefined);
      // The deterministic fields this codebase already depended on before
      // this feature existed are still present and unchanged in shape.
      assert.equal(synthesizerCompleted.result.basis, 'fusion');
      assert.equal(typeof synthesizerCompleted.result.recommendation, 'string');

      const missionCompleted = events.find((e) => e.event_type === 'mission.completed');
      assert.equal(missionCompleted.result.llm_enhanced, false);
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
