const assert = require('node:assert/strict');
const { test } = require('node:test');
const Snap = require('../apex-dashboard-snapshot.js');

// ---------------------------------------------------------------------------
// 2026-11-14 production incident. The publisher stopped refreshing; once the feed passed the 6 h limit
// the gateway failed closed with HTTP 503 and a structured body on BOTH /api/feed.json and /api/health
// (workers/intel-gateway/src/stale-feed-policy.js). The dashboard dropped every non-2xx body, concluded
// "no data", and told customers "API ● UNREACHABLE / INTELLIGENCE TEMPORARILY UNAVAILABLE / No Threat
// Intelligence Available - Feed is empty or API is offline" while the platform was up and had stated
// exactly how old the intelligence was. The existing tests modelled a stale 200; nothing modelled the
// real 503. These fixtures are the real public bodies captured from https://intel.cyberdudebivash.com
// at 2026-11-14T18:58Z (no credentials, no customer data).
// ---------------------------------------------------------------------------

const NOW = Date.parse('2026-11-14T18:58:23Z');
const REAL_FEED_503 = {"error":"live_intelligence_unavailable","reason":"intelligence_stale","publication_state":"stale","freshness_status":"STALE","freshness_reason":"intelligence_stale","generated_at":"2026-11-14T07:24:11Z","age_seconds":41636,"max_age_seconds":21600,"items":[],"count":0,"live_data_available":false,"message":"No verified fresh threat intelligence is currently available."};
const REAL_HEALTH_503 = {"status":"degraded","service":"sentinel-apex","version":"201.0","reason":"intelligence_stale","advisory_count":118,"critical_count":13,"kev_confirmed":0,"last_sync":"2026-11-14T06:00:08Z","feed_index":"live:118_items","platform_reachable":true,"intelligence_available":true,"intelligence":{"status":"stale","generated_at":"2026-11-14T07:24:11Z","age_seconds":41644,"max_age_seconds":21600,"advisory_count":118},"checks":{"gateway":"ok","worker_runtime":"ok","intelligence_available":"ok","intelligence_freshness":"stale","publication_integrity":"ok","feed_index":"live:118_items"},"generated_at":"2026-11-14T18:58:16.084Z"};

const r503 = (data) => ({ ok: false, status: 503, data });
const NETWORK_ERROR = { ok: false, status: 0, data: null };

test('the real incident: both endpoints answer 503 -> degraded, platform reachable, last update shown', () => {
  const s = Snap.build(r503(REAL_HEALTH_503), r503(REAL_FEED_503), NOW);
  assert.equal(s.mode, 'degraded');
  assert.equal(s.api.reachable, true);
  assert.equal(s.api.health_status, 'degraded');
  assert.equal(s.publication.status, 'stale');
  assert.equal(s.publication.generated_at, '2026-11-14T07:24:11Z');
  assert.equal(s.publication.fresh, false);
  assert.equal(s.feed.state, 'withheld');

  const st = Snap.statusView(s);
  assert.equal(st.api.label, 'API ● LIVE');
  assert.equal(st.intel.label, 'INTEL ● DEGRADED');

  const sync = Snap.lastSyncView(s);
  assert.equal(sync.known, true);
  assert.equal(sync.text, '12h ago');
  assert.equal(sync.utc, '2026-11-14 07:24 UTC');

  const t = Snap.tickerView(s);
  assert.equal(t.mode, 'degraded');
  assert.equal(t.message, 'INTELLIGENCE DEGRADED — LAST AUTHORITATIVE UPDATE: 2026-11-14 07:24 UTC');
  assert.equal(t.count, null);
});

test('no stale number or advisory is ever projected from a fail-closed response', () => {
  const s = Snap.build(r503(REAL_HEALTH_503), r503(REAL_FEED_503), NOW);
  assert.deepEqual(s.feed.items, []);
  assert.equal(s.intelligence.total, null);
  assert.equal(s.intelligence.critical, null);
  assert.equal(s.intelligence.iocs, null);
  assert.equal(s.intelligence.source_count, null);
  assert.deepEqual(Snap.previewItems(s, 5), []);
});

test('only the feed answered 503 (health unreachable): still degraded; the HTTP answer proves the API is up', () => {
  const s = Snap.build(NETWORK_ERROR, r503(REAL_FEED_503), NOW);
  assert.equal(s.mode, 'degraded');
  assert.equal(s.api.reachable, true);
  assert.equal(s.publication.status, 'stale');
  assert.equal(s.publication.authority, 'feed_contract');
});

test('a 503 body can never authorize live data, whatever it claims', () => {
  const lying = Object.assign({}, REAL_FEED_503, {
    freshness_status: 'FRESH', publication_state: 'fresh', generated_at: '2026-11-14T18:57:00Z', age_seconds: 83, live_data_available: false,
    items: [{ id: 'x', title: 'forged current advisory', severity: 'CRITICAL', ioc_count: 9 }], count: 1,
  });
  const lyingHealth = Object.assign({}, REAL_HEALTH_503, { intelligence: { status: 'fresh', generated_at: '2026-11-14T18:57:00Z', age_seconds: 83, max_age_seconds: 21600 } });
  const s = Snap.build(r503(lyingHealth), r503(lying), NOW);
  assert.equal(s.publication.fresh, false, 'a non-2xx response is never a fresh publication');
  assert.deepEqual(s.feed.items, [], 'items from an error response are discarded');
  assert.equal(s.intelligence.total, null);
  assert.notEqual(s.mode, 'live');
});

test('a 503 that is not the gateway contract stays UNAVAILABLE / UNREACHABLE (a real outage is still reported as one)', () => {
  const html = { ok: false, status: 503, data: null };                                  // CDN error page: body is not JSON
  const other = r503({ error: 'something_else', message: 'Service Unavailable' });       // unrelated JSON
  const wrongFlag = r503(Object.assign({}, REAL_FEED_503, { live_data_available: true })); // contradicts the contract
  const arr = r503([REAL_FEED_503]);
  for (const f of [html, other, wrongFlag, arr]) {
    const s = Snap.build(r503({ error: 'x' }), f, NOW);
    assert.equal(s.mode, 'unavailable');
    assert.equal(s.api.reachable, false);
    assert.equal(Snap.statusView(s).api.label, 'API ● UNREACHABLE');
    assert.equal(Snap.tickerView(s).message, 'INTELLIGENCE TEMPORARILY UNAVAILABLE');
  }
});

test('other failure statuses are never read as the contract: 500, 502, 504, 0', () => {
  for (const status of [500, 502, 504, 0, 404]) {
    const s = Snap.build({ ok: false, status, data: REAL_HEALTH_503 }, { ok: false, status, data: REAL_FEED_503 }, NOW);
    assert.equal(s.mode, 'unavailable', 'status ' + status);
    assert.equal(s.api.reachable, false, 'status ' + status);
  }
});

test('network failure on both endpoints is unchanged: unavailable', () => {
  const s = Snap.build(NETWORK_ERROR, NETWORK_ERROR, NOW);
  assert.equal(s.mode, 'unavailable');
  assert.equal(Snap.statusView(s).api.label, 'API ● UNREACHABLE');
  assert.equal(Snap.statusView(s).intel.label, 'INTEL ● UNAVAILABLE');
});

test('a 200 response is unaffected by the contract path (fresh stays live)', () => {
  const gen = '2026-11-14T18:40:00Z';
  const items = [{ id: 'a', title: 'A', severity: 'CRITICAL', ioc_count: 2, feed_source: 'https://vulners.com/rss.xml' }];
  const h = { ok: true, status: 200, data: { status: 'ok', service: 'sentinel-apex', intelligence: { status: 'fresh', generated_at: gen, age_seconds: 1100, max_age_seconds: 21600 } } };
  const f = { ok: true, status: 200, data: { generated_at: gen, count: 1, items, freshness_status: 'FRESH' } };
  const s = Snap.build(h, f, NOW);
  assert.equal(s.mode, 'live');
  assert.equal(s.intelligence.total, 1);
  assert.equal(Snap.statusView(s).intel.label, 'INTEL ● FRESH');
});

test('emptyPanelView: stale, empty and unreachable are three different messages; unknown keeps the legacy copy', () => {
  const stale = Snap.emptyPanelView(Snap.build(r503(REAL_HEALTH_503), r503(REAL_FEED_503), NOW));
  assert.equal(stale.mode, 'degraded');
  assert.match(stale.title, /temporarily withheld/);
  assert.match(stale.detail, /platform is online/);
  assert.match(stale.detail, /last authoritative update: 2026-11-14 07:24 UTC, 12h ago/);
  assert.doesNotMatch(stale.detail, /offline/i);

  const unavailable = Snap.emptyPanelView(Snap.build(NETWORK_ERROR, NETWORK_ERROR, NOW));
  assert.deepEqual([unavailable.mode, unavailable.title, unavailable.detail], ['unavailable', 'No Threat Intelligence Available', 'Feed is empty or API is offline.']);

  const gen = '2026-11-14T18:40:00Z';
  const empty = Snap.emptyPanelView(Snap.build(
    { ok: true, status: 200, data: { status: 'ok', intelligence: { status: 'fresh', generated_at: gen, max_age_seconds: 21600 } } },
    { ok: true, status: 200, data: { generated_at: gen, count: 0, items: [], freshness_status: 'FRESH' } }, NOW));
  assert.equal(empty.mode, 'empty');
  assert.match(empty.title, /No current advisories/);

  assert.deepEqual(Snap.emptyPanelView(null), unavailable);
  assert.deepEqual(Snap.emptyPanelView(undefined), unavailable);
});

test('emptyPanelView output is plain text built only from the validated timestamp (markup in the body cannot reach it)', () => {
  const hostile = Object.assign({}, REAL_FEED_503, { generated_at: '<img src=x onerror=alert(1)>', message: '<script>alert(1)</script>', reason: '<b>x</b>' });
  const h = Object.assign({}, REAL_HEALTH_503, { intelligence: Object.assign({}, REAL_HEALTH_503.intelligence, { generated_at: '<img src=x onerror=alert(1)>' }) });
  const v = Snap.emptyPanelView(Snap.build(r503(h), r503(hostile), NOW));
  assert.doesNotMatch(v.title + v.detail, /[<>]/);
  assert.doesNotMatch(v.detail, /alert\(/);
  assert.equal(Snap.esc('<img src=x>'), '&lt;img src=x&gt;');
});
