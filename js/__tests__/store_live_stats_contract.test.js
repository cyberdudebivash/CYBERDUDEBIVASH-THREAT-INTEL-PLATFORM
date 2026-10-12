import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const STORE = readFileSync(path.join(ROOT, 'store.html'), 'utf8');
const SERVICES = readFileSync(path.join(ROOT, 'services.html'), 'utf8');
const START = '// Store operational counters must be driven by authoritative and FRESH public';
const END = '// ── Category filter ──';
const from = STORE.indexOf(START);
const to = STORE.indexOf(END, from);
assert.ok(from >= 0 && to > from, 'customer store stats runtime not present');
const SOURCE = STORE.slice(from, to);
new vm.Script(SOURCE);

const fresh = {
  intel: {
    publication_state: 'fresh',
    freshness: 'FRESH',
    publication_age_seconds: 1800,
    ioc_count: 56,
    feed_count: 9,
  },
};

async function render(response = fresh, options = {}) {
  const values = {
    'store-live-ioc-count': { textContent: 'VERIFYING' },
    'store-live-source-count': { textContent: 'VERIFYING' },
  };
  const opts = { ok: true, ...options };
  const calls = [];
  const context = {
    document: { getElementById: id => values[id] || null },
    AbortController,
    setTimeout: () => 1,
    clearTimeout: () => {},
    fetch: async (url, init) => {
      calls.push({ url, init });
      if (opts.reject) throw new Error('network blocked');
      return { ok: opts.ok, json: async () => response };
    },
  };
  vm.runInNewContext(SOURCE, context, { timeout: 1000 });
  // Promise chain includes fetch, response.json, display and finally.
  await new Promise(resolve => setImmediate(resolve));
  return { iocs: values['store-live-ioc-count'].textContent,
    sources: values['store-live-source-count'].textContent, calls };
}

test('store boots with honest unknown counts, not a historical static selling counter', () => {
  assert.match(STORE, /id="store-live-ioc-count"[^>]*>VERIFYING<\/span>/);
  assert.match(STORE, /id="store-live-source-count"[^>]*>VERIFYING<\/span>/);
  assert.doesNotMatch(STORE, /794\+<\/span>/);
  assert.doesNotMatch(STORE, /<span class="val">10<\/span><span class="lbl">INTEL FEEDS/);
});

test('fresh authoritative gateway metrics populate the customer store', async () => {
  const out = await render();
  assert.equal(out.iocs, '56');
  assert.equal(out.sources, '9');
  assert.equal(out.calls.length, 1);
  assert.equal(out.calls[0].url, '/api/platform/stats');
  assert.equal(out.calls[0].init.cache, 'no-store');
  assert.equal(out.calls[0].init.credentials, 'omit');
});

test('stale public publication must not advertise active indicators or feeds', async () => {
  const out = await render({intel:{...fresh.intel, publication_state:'stale'}});
  assert.equal(out.iocs, 'UNAVAILABLE');
  assert.equal(out.sources, 'UNAVAILABLE');
});

test('unverified age and expired age both fail closed', async () => {
  for (const age of [null, -1, 21601, 'unknown']) {
    const out = await render({intel:{...fresh.intel, publication_age_seconds:age}});
    assert.equal(out.iocs, 'UNAVAILABLE');
    assert.equal(out.sources, 'UNAVAILABLE');
  }
});

test('http errors and network errors do not retain a fabricated counter', async () => {
  for (const options of [{ok:false}, {reject:true}]) {
    const out = await render(fresh, options);
    assert.equal(out.iocs, 'UNAVAILABLE');
    assert.equal(out.sources, 'UNAVAILABLE');
  }
});

test('malformed or absent source count never falls back to a made-up number', async () => {
  const out = await render({intel:{...fresh.intel, feed_count:undefined, ioc_count:0}});
  assert.equal(out.iocs, '0');
  assert.equal(out.sources, 'UNAVAILABLE');
});

test('store and services avoid unsupported customer sales proof but retain conversion', () => {
  assert.doesNotMatch(STORE, /Integrate in 30 seconds/);
  assert.doesNotMatch(STORE, /all products ship with enterprise-grade quality guarantee/i);
  assert.doesNotMatch(SERVICES, /Top Rated &mdash; Upwork/);
  assert.doesNotMatch(SERVICES, /Verified &mdash; Fiverr/);
  assert.doesNotMatch(SERVICES, /MITRE ATT&CK Expert/);
  assert.match(SERVICES, /www\.upwork\.com\/freelancers/);
  assert.match(SERVICES, /fiverr\.com\/users\//);
  assert.match(STORE, /href="\/upgrade\.html\?plan=pro"/);
});
