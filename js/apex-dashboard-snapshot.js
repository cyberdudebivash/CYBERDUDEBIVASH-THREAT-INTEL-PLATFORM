/*
 * CYBERDUDEBIVASH SENTINEL APEX -- customer dashboard snapshot.
 *
 * One state object for the homepage intelligence widgets (EICC ticker,
 * metrics, Last Sync, feed preview). It is built from two same-origin reads:
 *
 *   /api/health     -- the public freshness contract (intelligence.status,
 *                      generated_at, age_seconds). API liveness is proven
 *                      by this response; data freshness comes from its
 *                      intelligence block. The two are never conflated.
 *   /api/feed.json  -- the authoritative R2 feed the counts come from.
 *
 * There is no raw.githubusercontent.com fallback: that mirror is frozen
 * (see js/feed-state.js) and must never be shown as current intelligence.
 *
 * build() and the *View() helpers are pure and unit-tested in Node
 * (js/__tests__/apex-dashboard-snapshot.test.js). load() de-duplicates
 * concurrent callers so every widget hydrates from the same generation.
 */
(function (root) {
  'use strict';

  var CONTRACT = 'apex-dashboard-snapshot/1.0';
  var HEALTH_URL = '/api/health';
  var FEED_URL = '/api/feed.json';
  var FEED_TIMEOUT_MS = 20000;   // the feed is ~0.9 MB; 10 s was too short on slow links
  var HEALTH_TIMEOUT_MS = 8000;
  var REUSE_MS = 60000;          // callers within a minute share one snapshot

  var MESSAGES = {
    empty: 'NO CURRENT ADVISORIES IN THE AUTHORITATIVE FEED',
    degraded: 'INTELLIGENCE DEGRADED',
    unavailable: 'INTELLIGENCE TEMPORARILY UNAVAILABLE',
  };

  /** HTML-escape for the few places that still build markup strings. */
  function esc(s) {
    if (s === null || s === undefined) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  }

  function itemsOf(data) {
    if (Array.isArray(data)) return data;
    if (!data || typeof data !== 'object') return [];
    if (Array.isArray(data.items)) return data.items;
    return [];
  }

  // Moved from index.html's eiccEngine _iocContribution() (P0 fix: an empty
  // iocs [] is truthy, so `ioc_count||iocs` turned the sum into a string of
  // digits). Numeric ioc_count, else iocs.length, else a numeric scalar.
  function iocContribution(it) {
    if (typeof it.ioc_count === 'number') return it.ioc_count;
    if (Array.isArray(it.iocs)) return it.iocs.length;
    var n = Number(it.iocs);
    return isNaN(n) ? 0 : n;
  }

  function sourceHost(it) {
    var s = String(it.feed_source || '').replace(/^https?:\/\/(www\.)?/, '').split('/')[0].trim();
    return s && !/^unknown$/i.test(s) ? s : '';
  }

  function sev(it) {
    return String(it.severity || it.risk_level || '').toUpperCase();
  }

  /** Publication freshness: /api/health first, then the feed's own contract fields. */
  function publicationFrom(health, feed) {
    var intel = health && health.intelligence;
    if (intel && typeof intel.status === 'string') {
      return {
        status: intel.status.toLowerCase(), generated_at: intel.generated_at || null,
        max_age_seconds: typeof intel.max_age_seconds === 'number' ? intel.max_age_seconds : null,
        authority: 'api_health',
      };
    }
    if (feed && typeof feed.freshness_status === 'string') {
      return {
        status: feed.freshness_status.toLowerCase(), generated_at: feed.generated_at || null,
        max_age_seconds: typeof feed.max_age_seconds === 'number' ? feed.max_age_seconds : null,
        authority: 'feed_contract',
      };
    }
    return { status: 'unknown', generated_at: null, max_age_seconds: null, authority: 'none' };
  }

  /**
   * @param {{ok:boolean,data:*}} healthRes result of GET /api/health
   * @param {{ok:boolean,data:*}} feedRes   result of GET /api/feed.json
   * @param {number} nowMs
   */
  function build(healthRes, feedRes, nowMs) {
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    var health = healthRes && healthRes.ok ? healthRes.data : null;
    var feed = feedRes && feedRes.ok && feedRes.data && typeof feedRes.data === 'object' ? feedRes.data : null;
    var items = feed ? itemsOf(feed).filter(function (i) { return i && typeof i === 'object'; }) : [];

    var pub = publicationFrom(health, feed);
    var genMs = Date.parse(pub.generated_at || '');
    pub.age_seconds = isFinite(genMs) ? Math.max(0, Math.round((now - genMs) / 1000)) : null;
    pub.fresh = pub.status === 'fresh';

    var critical = 0, high = 0, iocs = 0, riskSum = 0, riskN = 0, sources = {};
    items.forEach(function (it) {
      var s = sev(it);
      if (s === 'CRITICAL') critical++;
      if (s === 'HIGH') high++;
      iocs += iocContribution(it);
      var r = parseFloat(it.risk_score);
      if (isFinite(r)) { riskSum += r; riskN++; }
      var h = sourceHost(it);
      if (h) sources[h] = (sources[h] || 0) + 1;
    });

    var feedState = !feed ? 'error' : (items.length ? 'ok' : 'empty');
    var mode;
    if (feedState === 'error') mode = 'unavailable';
    else if (!pub.fresh) mode = 'degraded';
    else mode = feedState === 'ok' ? 'live' : 'empty';

    return {
      contract: CONTRACT,
      mode: mode,
      api: { reachable: !!(health || feed), health_status: health && typeof health.status === 'string' ? health.status : null },
      publication: pub,
      feed: { state: feedState, items: items },
      intelligence: {
        total: items.length, critical: critical, high: high, iocs: iocs,
        avg_risk: riskN ? Math.round((riskSum / riskN) * 10) / 10 : null,
        // Distinct feed_source hosts. Unmeasured (null) when items exist but
        // none names its source; 0 only for a genuinely empty feed.
        source_count: !feed ? null : (Object.keys(sources).length || (items.length ? null : 0)),
        sources: sources,
      },
      built_at: new Date(now).toISOString(),
    };
  }

  function ageText(seconds) {
    if (typeof seconds !== 'number' || !isFinite(seconds) || seconds < 0) return null;
    if (seconds < 90) return Math.round(seconds) + 's ago';
    if (seconds < 5400) return Math.round(seconds / 60) + 'm ago';
    if (seconds < 172800) return Math.round(seconds / 3600) + 'h ago';
    return Math.round(seconds / 86400) + 'd ago';
  }

  function utcText(iso) {
    var t = Date.parse(iso || '');
    if (!isFinite(t)) return null;
    return new Date(t).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }

  /** Last Sync = the authoritative feed generation time, never an item date or page time. */
  function lastSyncView(state) {
    var p = state && state.publication;
    var rel = p ? ageText(p.age_seconds) : null;
    return { text: rel || 'N/A', utc: p ? utcText(p.generated_at) : null, known: !!rel };
  }

  /** API liveness and intelligence freshness, as two separate labels. */
  function statusView(state) {
    var api = state && state.api && state.api.reachable ? { state: 'ok', label: 'API ● LIVE' } : { state: 'offline', label: 'API ● UNREACHABLE' };
    var intel;
    if (!state || state.mode === 'unavailable') intel = { state: 'offline', label: 'INTEL ● UNAVAILABLE' };
    else if (state.publication.fresh) intel = { state: 'ok', label: 'INTEL ● FRESH' };
    else if (state.publication.status === 'unknown') intel = { state: 'unknown', label: 'INTEL ● UNVERIFIED' };
    else intel = { state: 'degraded', label: 'INTEL ● DEGRADED' };
    return { api: api, intel: intel };
  }

  /** Ticker content: bounded real items, or an explicit empty/degraded/unavailable message. */
  function tickerView(state, limit) {
    var n = limit || 30;
    if (!state || state.mode === 'unavailable') return { mode: 'unavailable', message: MESSAGES.unavailable, items: [], count: null };
    var items = state.feed.items.slice(0, n);
    if (state.mode === 'empty') return { mode: 'empty', message: MESSAGES.empty, items: [], count: 0 };
    if (state.mode === 'degraded') {
      var utc = utcText(state.publication.generated_at);
      return {
        mode: 'degraded', items: items, count: state.intelligence.total,
        message: MESSAGES.degraded + ' — LAST AUTHORITATIVE UPDATE: ' + (utc || 'UNKNOWN'),
      };
    }
    return { mode: 'live', message: null, items: items, count: state.intelligence.total };
  }

  /** Preview: up to n current items, Critical/High first, else the newest others. */
  function previewItems(state, n) {
    var max = n || 5;
    var items = state && state.feed ? state.feed.items : [];
    var top = items.filter(function (it) { var s = sev(it); return s === 'CRITICAL' || s === 'HIGH'; }).slice(0, max);
    return top.length ? top : items.slice(0, max);
  }

  // ── Loader (browser only) ────────────────────────────────────────────────
  var inflight = null;
  var last = null;
  var lastAt = 0;
  var listeners = [];

  function fetchJSON(url, timeoutMs) {
    var ctrl = typeof AbortController === 'function' ? new AbortController() : null;
    var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, timeoutMs) : null;
    return fetch(url, { cache: 'no-cache', headers: { Accept: 'application/json' }, signal: ctrl ? ctrl.signal : undefined })
      .then(function (r) {
        if (!r.ok) return { ok: false, status: r.status, data: null };
        return r.json().then(function (d) { return { ok: true, status: r.status, data: d }; },
          function () { return { ok: false, status: r.status, data: null }; });
      }, function () { return { ok: false, status: 0, data: null }; })
      .then(function (res) { if (timer) clearTimeout(timer); return res; });
  }

  function load(opts) {
    var force = opts && opts.force;
    if (!force && last && Date.now() - lastAt < REUSE_MS) return Promise.resolve(last);
    if (inflight) return inflight;
    inflight = Promise.all([fetchJSON(HEALTH_URL, HEALTH_TIMEOUT_MS), fetchJSON(FEED_URL, FEED_TIMEOUT_MS)])
      .then(function (r) {
        last = build(r[0], r[1], Date.now());
        lastAt = Date.now();
        inflight = null;
        listeners.slice().forEach(function (fn) { try { fn(last); } catch (e) { /* one widget must not break the rest */ } });
        return last;
      }, function () { inflight = null; last = build(null, null, Date.now()); lastAt = Date.now(); return last; });
    return inflight;
  }

  function subscribe(fn) { if (typeof fn === 'function') listeners.push(fn); }
  function current() { return last; }

  var api = {
    CONTRACT: CONTRACT, MESSAGES: MESSAGES, HEALTH_URL: HEALTH_URL, FEED_URL: FEED_URL,
    build: build, lastSyncView: lastSyncView, statusView: statusView, tickerView: tickerView,
    previewItems: previewItems, ageText: ageText, utcText: utcText, esc: esc, iocContribution: iocContribution,
    load: load, subscribe: subscribe, current: current,
  };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.ApexDashboardSnapshot = api;
})(typeof window !== 'undefined' ? window : globalThis);
