import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BOOK_INR_PER_USD,
  buildWatchdogBrief,
  classifyItem,
  routeWatchdog,
  watchdogOffer,
} from '../cyber-watchdog.js';

const FEED = [
  {
    id: 'adv-1',
    title: 'CVE-2026-1000 exploited ransomware campaign',
    summary: 'KEV-listed vulnerability with ransomware use.',
    severity: 'CRITICAL',
    source: 'CISA KEV',
    published: '2026-09-20T00:00:00Z',
    ioc: 'should-not-leak-to-free',
  },
  {
    id: 'adv-2',
    title: 'Azure Kubernetes supply-chain advisory',
    summary: 'Vendor cloud control-plane note.',
    severity: 'HIGH',
    source: 'Vendor',
    published: '2026-09-21T00:00:00Z',
  },
  {
    id: 'adv-3',
    title: 'Sigma detection for suspicious PowerShell',
    summary: 'SOC triage playbook stub.',
    severity: 'MEDIUM',
    source: 'Detection pack',
    published: '2026-09-22T00:00:00Z',
  },
];

test('book rate stays 83 and plan stickers stay $49 and $499', () => {
  assert.equal(BOOK_INR_PER_USD, 83);
  const offer = watchdogOffer();
  const pro = offer.plans.find((p) => p.id === 'PRO');
  const ent = offer.plans.find((p) => p.id === 'ENTERPRISE');
  assert.equal(pro.price_usd_monthly, 49);
  assert.equal(pro.price_inr_book_monthly, 4067);
  assert.equal(ent.price_usd_monthly, 499);
  assert.equal(ent.price_inr_book_monthly, 41417);
  assert.match(offer.aligned_not_certified, /not certified/);
  assert.equal(offer.seller.legal_name, 'CYBERDUDEBIVASH Pvt. Ltd.');
  const blob = JSON.stringify(offer);
  assert.doesNotMatch(blob, /entire internet is watched|watches the entire world/i);
  assert.match(blob, /Does not watch the entire internet/);
});

test('classifies live-feed items into the three lenses and invents nothing', () => {
  assert.ok(classifyItem(FEED[0]).includes('cybersecurity'));
  assert.ok(classifyItem(FEED[1]).includes('technology'));
  assert.ok(classifyItem(FEED[2]).includes('security_operations'));
  const empty = buildWatchdogBrief([], { tier: 'FREE' });
  assert.equal(empty.count, 0);
  assert.match(empty.empty_reason, /No events were invented/);
});

test('free brief redacts and paid brief keeps CVE ids', () => {
  const free = buildWatchdogBrief(FEED, { tier: 'FREE', limit: 8 });
  assert.equal(free.items[0].cve_ids.length, 0);
  assert.equal(free.items[0].summary, null);
  assert.doesNotMatch(JSON.stringify(free), /should-not-leak/);
  const pro = buildWatchdogBrief(FEED, { tier: 'PRO', lens: 'cybersecurity' });
  assert.equal(pro.items.length, 1);
  assert.deepEqual(pro.items[0].cve_ids, ['CVE-2026-1000']);
});

test('pro can save a watch and match it; free cannot; enterprise gets the poller', async () => {
  const store = new Map();
  const kv = {
    async get(key, type) {
      const raw = store.get(key);
      if (!raw) return null;
      return type === 'json' ? JSON.parse(raw) : raw;
    },
    async put(key, value) { store.set(key, value); },
  };
  const denied = await routeWatchdog({
    path: '/api/watchdog/watches',
    method: 'POST',
    auth: { tier: 'FREE', sub: null },
    body: { name: 'KEV', keywords: ['ransomware'] },
    kv,
  });
  assert.equal(denied.status, 403);

  const created = await routeWatchdog({
    path: '/api/watchdog/watches',
    method: 'POST',
    auth: { tier: 'PRO', sub: 'cust-1' },
    body: { name: 'Ransomware watch', keywords: ['ransomware'], lenses: ['cybersecurity'] },
    kv,
    id: 'abc123',
    now: '2026-09-24T00:00:00Z',
  });
  assert.equal(created.status, 201);

  const matched = await routeWatchdog({
    path: '/api/watchdog/matches',
    method: 'GET',
    auth: { tier: 'PRO', sub: 'cust-1' },
    items: FEED,
    kv,
  });
  assert.equal(matched.status, 200);
  assert.equal(matched.body.matches[0].hit_count, 1);

  const deployFree = await routeWatchdog({
    path: '/api/watchdog/deploy',
    method: 'GET',
    auth: { tier: 'PRO', sub: 'cust-1' },
  });
  assert.equal(deployFree.status, 403);

  const deploy = await routeWatchdog({
    path: '/api/watchdog/deploy',
    method: 'GET',
    auth: { tier: 'ENTERPRISE', sub: 'cust-9' },
  });
  assert.equal(deploy.status, 200);
  assert.match(deploy.body.poll.endpoint, /\/api\/watchdog\/brief$/);
  assert.match(deploy.body.poll.package, /poll\.mjs$/);
});
