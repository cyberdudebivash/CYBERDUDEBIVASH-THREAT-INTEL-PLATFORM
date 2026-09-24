const assert = require('node:assert/strict');
const { test } = require('node:test');
const Snap = require('../apex-dashboard-snapshot.js');

// ---------------------------------------------------------------------------
// P0 customer dashboard data contract (2026-09-24). One snapshot drives the
// EICC ticker, metrics, Last Sync and preview. These tests pin the state
// contract the customer saw broken:
//   - "No current threat intelligence" beside a non-zero advisory count
//   - LAST SYNC "—" under a hardcoded "API ● LIVE"
//   - fetch error, empty feed and stale feed rendered the same way
// ---------------------------------------------------------------------------

const NOW = Date.parse('2026-09-24T20:30:00Z');
const GEN = '2026-09-24T20:08:53Z';

function feedOf(n, extra) {
  const items = [];
  for (let i = 0; i < n; i++) {
    items.push({
      id: 'intel--' + i, title: 'Advisory ' + i,
      severity: i % 4 === 0 ? 'CRITICAL' : i % 4 === 1 ? 'HIGH' : 'MEDIUM',
      risk_score: 5, ioc_count: i % 5 === 0 ? 2 : 0, iocs: [],
      feed_source: i % 2 ? 'https://www.bleepingcomputer.com/feed/' : 'https://vulners.com/rss.xml',
    });
  }
  return { ok: true, data: Object.assign({ generated_at: GEN, count: n, items }, extra || {}) };
}
function health(status, generatedAt) {
  return { ok: true, data: { status: 'ok', intelligence: { status, generated_at: generatedAt === undefined ? GEN : generatedAt, age_seconds: 1049, max_age_seconds: 21600, advisory_count: 44 } } };
}
const FAIL = { ok: false, status: 0, data: null };

test('fresh feed with N items: ticker count == N and ticker renders real items', () => {
  const s = Snap.build(health('fresh'), feedOf(44), NOW);
  assert.equal(s.mode, 'live');
  const t = Snap.tickerView(s, 30);
  assert.equal(t.count, 44);
  assert.equal(t.items.length, 30, 'bounded');
  assert.equal(t.message, null);
  assert.equal(s.intelligence.total, 44);
});

test('cross-surface invariant: ticker, metric total, preview source and health agree', () => {
  const s = Snap.build(health('fresh'), feedOf(44), NOW);
  const t = Snap.tickerView(s);
  assert.equal(t.count, s.intelligence.total);
  assert.equal(s.feed.items.length, s.intelligence.total);
  assert.ok(Snap.previewItems(s, 5).every(i => s.feed.items.includes(i)), 'preview comes from the same snapshot');
});

test('fresh and genuinely empty feed says so; not an error message', () => {
  const s = Snap.build(health('fresh'), feedOf(0), NOW);
  const t = Snap.tickerView(s);
  assert.equal(t.mode, 'empty');
  assert.equal(t.message, 'NO CURRENT ADVISORIES IN THE AUTHORITATIVE FEED');
  assert.equal(t.count, 0);
});

test('stale feed: degraded with the last authoritative update, items still counted', () => {
  const s = Snap.build(health('stale', '2026-09-20T01:00:00Z'), feedOf(12), NOW);
  const t = Snap.tickerView(s);
  assert.equal(t.mode, 'degraded');
  assert.match(t.message, /^INTELLIGENCE DEGRADED — LAST AUTHORITATIVE UPDATE: 2026-09-20 01:00 UTC$/);
  assert.equal(t.count, 12);
});

test('feed fetch failure: unavailable, never "empty", no invented count', () => {
  const s = Snap.build(health('fresh'), FAIL, NOW);
  const t = Snap.tickerView(s);
  assert.equal(t.mode, 'unavailable');
  assert.equal(t.message, 'INTELLIGENCE TEMPORARILY UNAVAILABLE');
  assert.equal(t.count, null);
  assert.equal(s.intelligence.source_count, null);
});

test('empty, stale and error are three different states', () => {
  const modes = [
    Snap.build(health('fresh'), feedOf(0), NOW).mode,
    Snap.build(health('stale'), feedOf(3), NOW).mode,
    Snap.build(health('fresh'), FAIL, NOW).mode,
  ];
  assert.deepEqual(modes, ['empty', 'degraded', 'unavailable']);
});

test('Last Sync is the feed generation time from /api/health, never blank when health is fresh', () => {
  const s = Snap.build(health('fresh'), feedOf(3), NOW);
  const v = Snap.lastSyncView(s);
  assert.equal(v.text, '21m ago');
  assert.equal(v.utc, '2026-09-24 20:08 UTC');
  assert.equal(v.known, true);
  assert.notEqual(v.text, '—');
});

test('Last Sync ignores item publish dates', () => {
  const feed = feedOf(2);
  feed.data.items[0].published_at = '2026-09-24T20:29:00Z';
  const s = Snap.build(health('fresh'), feed, NOW);
  assert.equal(s.publication.generated_at, GEN);
});

test('Last Sync without any generation time says N/A, not a dash or a page time', () => {
  const s = Snap.build(FAIL, { ok: true, data: { items: [{ id: 'a' }] } }, NOW);
  assert.equal(Snap.lastSyncView(s).text, 'N/A');
});

test('API liveness is separate from intelligence freshness', () => {
  const stale = Snap.statusView(Snap.build(health('stale'), feedOf(3), NOW));
  assert.equal(stale.api.label, 'API ● LIVE');
  assert.equal(stale.intel.label, 'INTEL ● DEGRADED');
  const fresh = Snap.statusView(Snap.build(health('fresh'), feedOf(3), NOW));
  assert.equal(fresh.intel.label, 'INTEL ● FRESH');
  const down = Snap.statusView(Snap.build(FAIL, FAIL, NOW));
  assert.equal(down.api.label, 'API ● UNREACHABLE');
  assert.equal(down.intel.label, 'INTEL ● UNAVAILABLE');
});

test('health unavailable: the feed contract fields decide freshness; otherwise UNVERIFIED', () => {
  const viaFeed = Snap.build(FAIL, feedOf(3, { freshness_status: 'FRESH' }), NOW);
  assert.equal(viaFeed.mode, 'live');
  assert.equal(viaFeed.publication.authority, 'feed_contract');
  const unknown = Snap.build(FAIL, feedOf(3), NOW);
  assert.equal(unknown.mode, 'degraded');
  assert.equal(Snap.statusView(unknown).intel.label, 'INTEL ● UNVERIFIED');
});

test('preview prefers Critical/High and falls back to other current items', () => {
  const s = Snap.build(health('fresh'), feedOf(20), NOW);
  const p = Snap.previewItems(s, 5);
  assert.equal(p.length, 5);
  assert.ok(p.every(i => i.severity === 'CRITICAL' || i.severity === 'HIGH'));
  const low = Snap.build(health('fresh'), { ok: true, data: { generated_at: GEN, items: [{ id: 'x', severity: 'LOW' }, { id: 'y', severity: 'MEDIUM' }] } }, NOW);
  assert.deepEqual(Snap.previewItems(low, 5).map(i => i.id), ['x', 'y']);
});

test('IOC total is numeric and source count is distinct hosts in the current feed', () => {
  const s = Snap.build(health('fresh'), feedOf(10), NOW);
  assert.equal(s.intelligence.iocs, 4);
  assert.equal(typeof s.intelligence.iocs, 'number');
  assert.equal(s.intelligence.source_count, 2);
});

test('the snapshot has no fallback URL outside the platform origin', () => {
  assert.equal(Snap.FEED_URL, '/api/feed.json');
  assert.equal(Snap.HEALTH_URL, '/api/health');
});

test('esc() neutralises markup', () => {
  assert.equal(Snap.esc('<img src=x onerror=alert(1)>'), '&lt;img src=x onerror=alert(1)&gt;');
  assert.equal(Snap.esc('"><svg/onload=alert(1)>'), '&quot;&gt;&lt;svg/onload=alert(1)&gt;');
});
