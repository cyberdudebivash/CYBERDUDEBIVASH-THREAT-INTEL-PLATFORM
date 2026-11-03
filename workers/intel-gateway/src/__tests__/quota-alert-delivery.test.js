import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  dispatchQuotaAlertOnce, QUOTA_ALERT_PENDING_SECONDS, QUOTA_ALERT_SENT_SECONDS
} from '../quota-alert-delivery.js';

const KEY = 'alert_sent:80pct:synthetic-customer:2026-11-03';
const queued = () => Response.json({ status: 'triggered', trigger: 'usage_80pct' });
const denied = () => Response.json({ error: 'operator_identity_required' }, { status: 403 });

function kvHarness() {
  let now = 0;
  const records = new Map();
  const writes = [];
  const kv = {
    async get(key) {
      const entry = records.get(key);
      if (!entry || now >= entry.until) return null;
      return entry.value;
    },
    async put(key, value, options) {
      assert.ok(Number.isInteger(options.expirationTtl) && options.expirationTtl >= 60);
      records.set(key, { value, until: now + options.expirationTtl * 1000 });
      writes.push({ key, value, ttl: options.expirationTtl });
    },
  };
  return { kv, records, writes, advance: ms => { now += ms; } };
}

test('success reserves briefly then marks the calendar-day alert only after matching queue receipt', async () => {
  const h = kvHarness();
  let sends = 0;
  const send = () => { sends++; return queued(); };
  const first = await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver: send });
  assert.equal(first.outcome, 'queued');
  assert.deepEqual(h.writes.map(x => [x.value, x.ttl]), [
    ['pending', QUOTA_ALERT_PENDING_SECONDS], ['sent', QUOTA_ALERT_SENT_SECONDS]
  ]);
  const second = await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver: send });
  assert.equal(second.outcome, 'suppressed');
  assert.equal(sends, 1, 'a positive acknowledgment only gets one in-region attempt');
});

test('operator JWT denial does not poison 25-hour dedupe; later request can retry', async () => {
  const h = kvHarness();
  let sends = 0;
  const deliver = () => { sends++; return sends === 1 ? denied() : queued(); };
  assert.equal((await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver })).outcome,
    'retry_after_reservation');
  assert.equal(h.writes.length, 1);
  assert.equal(h.writes[0].ttl, QUOTA_ALERT_PENDING_SECONDS);
  assert.equal((await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver })).outcome,
    'suppressed', 'the short reservation reduces concurrent retry bursts');
  h.advance((QUOTA_ALERT_PENDING_SECONDS + 1) * 1000);
  assert.equal((await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver })).outcome, 'queued');
  assert.equal(sends, 2);
  assert.equal(h.writes.at(-1).ttl, 90000);
});

test('non-200, malformed/misleading success and network failures never become sent', async () => {
  const failureCases = [
    () => Response.json({ error: 'unavailable' }, { status: 503 }),
    () => Response.json({ status: 'triggered', trigger: 'other' }),
    () => Response.json({ status: 'unknown', trigger: 'usage_80pct' }),
    () => new Response('not json', { status: 200 }),
    () => Promise.reject(new Error('network error')),
    () => undefined,
  ];
  for (const deliver of failureCases) {
    const h = kvHarness();
    assert.equal((await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver })).outcome,
      'retry_after_reservation');
    assert.deepEqual(h.writes.map(x => x.ttl), [QUOTA_ALERT_PENDING_SECONDS]);
    h.advance((QUOTA_ALERT_PENDING_SECONDS + 1) * 1000);
    assert.equal((await h.kv.get(KEY)), null);
  }
});

test('prior legacy sent marker remains honored during source migration', async () => {
  const h = kvHarness();
  await h.kv.put(KEY, '1', { expirationTtl: 90000 });
  let sends = 0;
  const result = await dispatchQuotaAlertOnce({
    kv: h.kv, key: KEY, deliver: () => { sends++; return queued(); }
  });
  assert.equal(result.outcome, 'suppressed');
  assert.equal(sends, 0);
});

test('pending marker suppresses overlapping attempts in the same KV view', async () => {
  const h = kvHarness();
  let complete;
  let sends = 0;
  const deliver = () => { sends++; return new Promise(resolve => { complete = resolve; }); };
  const first = dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver });
  // Allow the first attempt to reserve before a second attempt checks the key.
  await new Promise(resolve => setImmediate(resolve));
  const second = await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver });
  assert.equal(second.outcome, 'suppressed');
  assert.equal(sends, 1);
  complete(queued());
  assert.equal((await first).outcome, 'queued');
});

test('missing KV/invalid dedupe key never dispatches and cannot mark sent', async () => {
  let calls = 0;
  const deliver = () => { calls++; return queued(); };
  assert.equal((await dispatchQuotaAlertOnce({ kv: null, key: KEY, deliver })).outcome, 'not_attempted');
  assert.equal((await dispatchQuotaAlertOnce({ kv: kvHarness().kv, key: 'bad-key', deliver })).outcome, 'not_attempted');
  assert.equal(calls, 0);
});

test('failed KV post-ack write remains short reservation; no false sent claim', async () => {
  const h = kvHarness();
  const put = h.kv.put;
  h.kv.put = async (key, value, opts) => {
    if (value === 'sent') throw new Error('KV write failed');
    return put(key, value, opts);
  };
  assert.equal((await dispatchQuotaAlertOnce({ kv: h.kv, key: KEY, deliver: queued })).outcome,
    'retry_after_reservation');
  assert.deepEqual(h.writes.map(x => x.value), ['pending']);
});

test('production gateway invokes helper only after admin secret and recipient checks', () => {
  const source = readFileSync(new URL('../index.js', import.meta.url), 'utf8');
  assert.match(source, /import \{ dispatchQuotaAlertOnce \} from '\.\/quota-alert-delivery\.js'/);
  const start = source.indexOf('async function maybeDispatchQuotaAlert(');
  const end = source.indexOf('// P0 2026-09-03 -- first-party web read plane', start);
  assert.ok(start >= 0 && end > start);
  const fn = source.slice(start, end);
  assert.ok(fn.indexOf('if (!env.REVENUE_ADMIN_SECRET) return;') <
    fn.indexOf('await dispatchQuotaAlertOnce({'));
  assert.ok(fn.indexOf('if (!record?.email) return;') <
    fn.indexOf('await dispatchQuotaAlertOnce({'));
  assert.match(fn, /quotaAlertDedupeKey\(identifier, dateStr\)/);
  assert.ok(fn.indexOf('await env.RATE_LIMIT_KV.get(dedupeKey)') <
    fn.indexOf('await env.API_KEYS_KV?.get(auth.key, "json")'),
    'already-alerted requests must not consume a customer-record KV lookup');
  assert.match(fn, /"X-Admin-Secret": env\.REVENUE_ADMIN_SECRET/);
  assert.doesNotMatch(fn, /expirationTtl: 90000/);
});
