import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

import {
  REQUEST_ID_RE,
  resolveRequestId,
  withRequestId,
  withoutRequestId,
} from '../request-id.js';

test('accepts only bounded log-safe caller request IDs', () => {
  const accepted = ['abc', 'req-123', 'SOC.case:42', 'a'.repeat(128)];
  for (const value of accepted) {
    const req = new Request('https://intel.cyberdudebivash.com/api/health', {
      headers: { 'X-Request-ID': value },
    });
    assert.equal(resolveRequestId(req), value);
    assert.equal(REQUEST_ID_RE.test(value), true);
  }

  const rejected = [
    '',
    'has internal space',
    'contains space',
    '<script>',
    'a'.repeat(129),
  ];
  for (const value of rejected) {
    const req = new Request('https://intel.cyberdudebivash.com/api/health', {
      headers: value ? { 'X-Request-ID': value } : {},
    });
    const id = resolveRequestId(req);
    assert.notEqual(id, value);
    assert.match(id, /^sentinel-apex-/);
    assert.equal(REQUEST_ID_RE.test(id), true);
  }
});

test('response correlation is per-request and removable before shared caching', async () => {
  const base = new Response('ok', {
    status: 200,
    headers: { 'Cache-Control': 'public, max-age=300' },
  });
  const correlated = withRequestId(base, 'req-one');
  assert.equal(correlated.headers.get('X-Request-ID'), 'req-one');
  assert.equal(await correlated.clone().text(), 'ok');

  const cacheCopy = withoutRequestId(correlated);
  assert.equal(cacheCopy.headers.get('X-Request-ID'), null);
  assert.equal(cacheCopy.headers.get('Cache-Control'), 'public, max-age=300');
});


test('gateway choke point attaches request IDs and strips them from shared cache writes', () => {
  const source = fs.readFileSync(new URL('../index.js', import.meta.url), 'utf8');
  assert.match(source, /const requestId = resolveRequestId\(request\)/);
  assert.match(source, /headers\.set\("X-Request-ID", requestId\)/);
  // Publication eligibility is pathname-aware before reuse of the shared cache.
  assert.match(source, /if \(cached && .*cachedLiveFeedIsPublishable\(cached, pathname\).*\) return withRequestId\(cached, requestId\)/);
  assert.match(source, /toCache = withoutRequestId\(toCache\)/);
  assert.match(source, /request_id=\$\{requestId\} unhandled error/);
});
