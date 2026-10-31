/*
 * CYBERDUDEBIVASH SENTINEL APEX -- status model for the command-center UI.
 *
 * Pure functions only: API response in, display state out. Shared by the
 * homepage command surface and Cyber Watchdog, and unit-tested in Node
 * (workers/intel-gateway/src/__tests__/watchdog-apex-ui.test.js).
 *
 * Rule: a state is only "ok"/"fresh"/"active" when a response proved it.
 * Missing, unreadable or not-yet-loaded data is "unknown", never green.
 */
(function (root) {
  'use strict';

  var FRESH = 'FRESH';

  /** Intelligence freshness LED from /api/watchdog/health or /brief. */
  function intelligenceState(payload, fetchFailed) {
    if (fetchFailed) return { state: 'offline', label: 'Intelligence unavailable' };
    if (!payload || typeof payload.freshness_status !== 'string') return { state: 'unknown', label: 'Intelligence status unknown' };
    if (payload.freshness_status === FRESH) return { state: 'fresh', label: 'Intelligence fresh' };
    if (payload.freshness_status === 'STALE') return { state: 'degraded', label: 'Intelligence stale' };
    return { state: 'degraded', label: 'Intelligence degraded' };
  }

  /** Watchdog service LED from /api/watchdog/health. */
  function watchdogState(health, fetchFailed) {
    if (fetchFailed) return { state: 'offline', label: 'Watchdog unreachable' };
    if (!health || typeof health.watch_store !== 'string') return { state: 'unknown', label: 'Watchdog status unknown' };
    if (health.watch_store !== 'ok') return { state: 'offline', label: 'Watchdog store unavailable' };
    if (health.autonomous_evaluation !== 'configured') return { state: 'degraded', label: 'Watchdog degraded' };
    return { state: 'active', label: 'Watchdog active' };
  }

  /** API reachability LED: proven only by a parsed JSON response. */
  function apiState(respondedWithJson, fetchFailed) {
    if (fetchFailed) return { state: 'offline', label: 'API unreachable' };
    if (respondedWithJson === true) return { state: 'ok', label: 'API operational' };
    return { state: 'unknown', label: 'API status unknown' };
  }

  /** Release label from the runtime payload; never a hardcoded version. */
  function releaseLabel(health) {
    var v = health && typeof health.platform_version === 'string' ? health.platform_version : '';
    return /^\d{3}\.\d+$/.test(v) ? 'v' + v : null;
  }

  /** Webhook destination LED. */
  function destinationState(state) {
    if (state === 'active') return { state: 'verified', label: 'Verified' };
    if (state === 'pending') return { state: 'pending', label: 'Pending verification' };
    if (state === 'failed') return { state: 'failed', label: 'Failed' };
    if (state === 'disabled') return { state: 'disabled', label: 'Disabled' };
    return { state: 'unknown', label: 'Unknown' };
  }

  /** Delivery LED for one event delivery or an event's aggregate status. */
  function deliveryState(status) {
    if (status === 'delivered') return { state: 'delivered', label: 'Delivered' };
    if (status === 'pending') return { state: 'pending', label: 'Pending' };
    if (status === 'failed' || status === 'partial') return { state: 'failed', label: status === 'partial' ? 'Partially failed' : 'Failed' };
    if (status === 'no_destinations') return { state: 'disabled', label: 'No destinations' };
    return { state: 'unknown', label: 'Unknown' };
  }

  var TRIAGE = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'IGNORED'];
  var TERMINAL = ['RESOLVED', 'IGNORED'];
  function triageState(status) {
    var s = TRIAGE.indexOf(status) >= 0 ? status : 'NEW';
    var map = { NEW: 'pending', ACKNOWLEDGED: 'info', INVESTIGATING: 'warning', RESOLVED: 'ok', IGNORED: 'disabled' };
    return { status: s, state: map[s], label: s.charAt(0) + s.slice(1).toLowerCase(), terminal: TERMINAL.indexOf(s) >= 0 };
  }

  /** "12m ago" style age from seconds; null when unknown. */
  function ageText(seconds) {
    if (typeof seconds !== 'number' || !isFinite(seconds) || seconds < 0) return null;
    if (seconds < 90) return Math.round(seconds) + 's ago';
    if (seconds < 5400) return Math.round(seconds / 60) + 'm ago';
    if (seconds < 172800) return Math.round(seconds / 3600) + 'h ago';
    return Math.round(seconds / 86400) + 'd ago';
  }

  function ageFromIso(iso, nowMs) {
    var t = Date.parse(iso || '');
    if (!isFinite(t)) return null;
    return ageText(Math.max(0, ((nowMs || Date.now()) - t) / 1000));
  }

  var SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  function severityKey(value) {
    var s = typeof value === 'string' ? value.trim().toUpperCase() : '';
    return SEV.indexOf(s) >= 0 ? s : 'UNKNOWN';
  }

  /**
   * Draft rule text for the builder while typing (display only). The
   * authoritative text comes back from POST /api/watchdog/watches/preview.
   */
  function draftRule(def) {
    var c = (def && def.criteria) || {};
    var lines = [];
    var list = function (key, label) {
      if (c[key] && c[key].length) lines.push(label + ' ' + c[key].join(' or '));
    };
    list('vendors', 'KEV vendor is');
    list('products', 'KEV product includes');
    list('packages', 'Package is');
    list('keywords', 'Text mentions');
    list('cves', 'CVE is');
    list('sources', 'Source is');
    list('techniques', 'ATT&CK technique is');
    list('ioc_types', 'Indicator type is');
    list('lenses', 'Lens is');
    if (c.severity_min) lines.push('Severity ' + c.severity_min + '+');
    if (typeof c.cvss_min === 'number') lines.push('CVSS >= ' + c.cvss_min);
    if (typeof c.epss_min === 'number') lines.push('EPSS >= ' + Math.round(c.epss_min * 10000) / 100 + '%');
    if (c.kev === true) lines.push('CISA KEV = YES');
    if (c.kev === false) lines.push('CISA KEV = NO');
    if (!lines.length) return '';
    return 'MATCH\n  ' + lines.join('\n' + (def && def.logic === 'OR' ? 'OR ' : 'AND '));
  }

  /**
   * Chart series from analytics. Returns null when there is no stored
   * history, so the page shows INSUFFICIENT HISTORY instead of a chart.
   */
  function trendSeries(analytics) {
    if (!analytics || analytics.history !== 'stored-match-events' || !Array.isArray(analytics.daily_7d)) return null;
    var rows = analytics.daily_7d.filter(function (d) { return d && typeof d.date === 'string' && typeof d.count === 'number' && d.count >= 0; });
    return rows.length ? rows.slice(-7) : null;
  }

  function priorityDistribution(analytics) {
    var p = analytics && analytics.by_priority;
    if (!p) return null;
    var order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INSUFFICIENT_EVIDENCE'];
    var rows = order.map(function (k) { return { key: k, count: typeof p[k] === 'number' ? p[k] : 0 }; });
    var total = rows.reduce(function (n, r) { return n + r.count; }, 0);
    return total ? rows : null;
  }

  var api = {
    intelligenceState: intelligenceState, watchdogState: watchdogState, apiState: apiState,
    releaseLabel: releaseLabel, destinationState: destinationState, deliveryState: deliveryState,
    triageState: triageState, ageText: ageText, ageFromIso: ageFromIso, severityKey: severityKey,
    draftRule: draftRule, trendSeries: trendSeries, priorityDistribution: priorityDistribution,
    TRIAGE: TRIAGE, TERMINAL: TERMINAL,
  };
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.ApexStatus = api;
})(typeof window !== 'undefined' ? window : globalThis);
