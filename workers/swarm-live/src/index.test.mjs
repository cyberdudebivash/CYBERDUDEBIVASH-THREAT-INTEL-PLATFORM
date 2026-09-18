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
  assert.equal(bundle.spec_version, '2.1');
  assert.match(bundle.id, /^bundle--[0-9a-f-]{36}$/);

  const indicator = bundle.objects.find((o) => o.type === 'indicator');
  assert.ok(indicator);
  assert.match(indicator.id, /^indicator--[0-9a-f-]{36}$/);
  assert.equal(indicator.spec_version, '2.1');
  assert.equal(indicator.pattern, "[ipv4-addr:value = '8.8.8.8']");
  assert.equal(indicator.indicator_types[0], 'malicious-activity');
  assert.equal(indicator.custom_properties.x_sentinel_mission_id, 'sentinel-mission-stix1');
  assert.equal(indicator.custom_properties.x_sentinel_verdict, 'malicious');

  const notes = bundle.objects.filter((o) => o.type === 'note');
  assert.equal(notes.length, 2);
  for (const note of notes) {
    assert.match(note.id, /^note--[0-9a-f-]{36}$/);
    assert.deepEqual(note.object_refs, [indicator.id]);
    assert.ok(['ioc-hunter', 'threat-hunter'].includes(note.custom_properties.x_sentinel_agent_id));
  }
  // Every object id in the bundle is unique -- no accidental id reuse.
  assert.equal(new Set(bundle.objects.map((o) => o.id)).size, bundle.objects.length);
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
  assert.equal(bundle.spec_version, '2.1');
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
