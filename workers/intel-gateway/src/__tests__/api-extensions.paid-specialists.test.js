import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildScopeSet, handleIRGuidance, handleExposureAnalysis,
} from '../api-extensions.js';

const PAID = 'api/v1/intel/latest_pro.json';
const PUBLIC = 'api/v1/intel/latest.json';
const BASE = 'https://intel.cyberdudebivash.com';

const report = {
  id: 'intel--synthetic-source',
  stix_id: 'report--synthetic-paid-alias',
  title: 'Synthetic P0 advisory; not a real threat',
  severity: 'CRITICAL',
  cvss_score: 9.1,
  kev_present: false,
  cve_id: 'CVE-2026-10001',
  cve_ids: ['CVE-2026-10001'],
  cve: 'malformed producer scalar',
  ttps: [{ technique_id: 'T1059' }, null, 'T1078'],
  tags: ['Windows', null, { nonsense: true }],
  description: 'Threat observed against Windows endpoints and email services.',
  attack_vector: 'NETWORK',
  iocs: [null, { type: 'ip', value: '192.0.2.20' }],
};
const routes = [
  ['/api/intel/ir-guidance', handleIRGuidance],
  ['/api/intel/exposure', handleExposureAnalysis],
];

function setup(files = {}) {
  const reads = [];
  const env = {
    INTEL_R2: {
      async get(key) {
        reads.push(key);
        return Object.hasOwn(files, key) ? { async json() { return files[key]; } } : null;
      },
    },
    SECURITY_HUB_KV: { async get() { throw Error('public report index must not be used'); } },
  };
  return { env, reads };
}

function auth(tier = 'PRO') {
  return { tier, scopes: buildScopeSet(tier, null) };
}

async function invoke(handler, ctx, id = report.stix_id, caller = auth()) {
  const url = new URL(BASE + (handler === handleIRGuidance ? routes[0][0] : routes[1][0]));
  url.searchParams.set('report_id', id);
  return handler(new Request(url), ctx.env, caller, 'specialist-p0-regression');
}

test('PRO, ENTERPRISE, MSSP: both backend specialists find the same paid STIX alias as canonical correlation', async () => {
  for (const tier of ['PRO', 'ENTERPRISE', 'MSSP']) {
    for (const [, handler] of routes) {
      const ctx = setup({
        [PAID]: { items: [report] },
        [PUBLIC]: { items: [{ id: report.id, iocs: undefined }] },
      });
      const response = await invoke(handler, ctx, report.stix_id, auth(tier));
      assert.equal(response.status, 200, tier);
      const body = await response.json();
      assert.equal(body.status, 'ok');
      assert.equal(body.data.report_id, report.stix_id);
      if (handler === handleIRGuidance) {
        assert.equal(body.data.applicable, true);
        assert.ok(Array.isArray(body.data.checklist.containment));
        assert.ok(body.data.checklist.containment.length >= 1);
      } else {
        assert.ok(Array.isArray(body.data.dimensions));
        assert.ok(body.data.total_dimensions > 0);
      }
      assert.deepEqual(ctx.reads, [PAID]);
    }
  }
});

test('canonical report id alias is accepted when no STIX id is selected', async () => {
  for (const [, handler] of routes) {
    const ctx = setup({ [PAID]: { items: [report] } });
    const response = await invoke(handler, ctx, report.id);
    assert.equal(response.status, 200);
    assert.deepEqual(ctx.reads, [PAID]);
  }
});

test('FREE and PRO without read:intel cannot read the paid manifest or receive source details', async () => {
  for (const [, handler] of routes) {
    for (const caller of [auth('FREE'), { tier: 'PRO', scopes: ['export:csv'] }]) {
      const ctx = setup({ [PAID]: { items: [report] } });
      const response = await invoke(handler, ctx, report.stix_id, caller);
      assert.equal(response.status, 403);
      assert.deepEqual(ctx.reads, []);
      assert.doesNotMatch(await response.text(), /Synthetic P0 advisory|CVE-2026-10001/);
    }
  }
});

test('no paid artifact, malformed paid schema and empty paid inventory fail closed even with public report data', async () => {
  for (const [, handler] of routes) {
    for (const paid of [undefined, null, { items: [] }, { items: 'bad' }]) {
      const files = { [PUBLIC]: { items: [report] } };
      if (paid !== undefined) files[PAID] = paid;
      const ctx = setup(files);
      const response = await invoke(handler, ctx);
      assert.equal(response.status, 503);
      assert.equal((await response.json()).error, 'paid_report_unavailable');
      assert.deepEqual(ctx.reads, [PAID]);
    }
  }
});

test('unknown report in valid paid inventory returns 404 rather than substituting public data', async () => {
  for (const [, handler] of routes) {
    const ctx = setup({ [PAID]: { items: [report] }, [PUBLIC]: { items: [{ ...report, id: 'public-only-id' }] } });
    const response = await invoke(handler, ctx, 'public-only-id');
    assert.equal(response.status, 404);
    assert.equal((await response.json()).error, 'report_not_found');
    assert.deepEqual(ctx.reads, [PAID]);
  }
});

test('malformed optional arrays do not crash or invent IOCs/TTPs', async () => {
  const damaged = { ...report, iocs: [null, 'garbage'], ttps: {}, tags: 'bad', cve_ids: 'bad', cve: 5 };
  for (const [, handler] of routes) {
    const ctx = setup({ [PAID]: { items: [damaged] } });
    const response = await invoke(handler, ctx);
    assert.equal(response.status, 200);
    assert.deepEqual(ctx.reads, [PAID]);
  }
});

test('R2 parser failures do not leak internal diagnostics or read anonymous source', async () => {
  for (const [, handler] of routes) {
    const ctx = setup({ [PUBLIC]: { items: [report] } });
    ctx.env.INTEL_R2.get = async key => {
      ctx.reads.push(key);
      return { async json() { throw Error('PRIVATE_R2_DIAGNOSTIC'); } };
    };
    const response = await invoke(handler, ctx);
    assert.equal(response.status, 500);
    assert.doesNotMatch(await response.text(), /PRIVATE_R2_DIAGNOSTIC/);
    assert.deepEqual(ctx.reads, [PAID]);
  }
});
