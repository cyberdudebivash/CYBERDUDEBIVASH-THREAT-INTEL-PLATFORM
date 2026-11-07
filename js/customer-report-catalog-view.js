/* Customer report catalog UI truth boundary.
 * Public advisory freshness is not proof of commercial report availability.
 * Use ONLY Worker-certified customer_ready_* catalogs for report links.
 * Pure browser/Node helper; never requests data or changes customer state.
 */
(function(root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.CDB_REPORT_CATALOG_VIEW = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function() {
  'use strict';
  var ORIGIN = 'https://intel.cyberdudebivash.com';
  var REPORT_PATH = /^\/reports\/20\d{2}\/(?:0[1-9]|1[0-2])\/(intel--[a-f0-9]{16,64})\.html$/;
  var UTC_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
  var DAY_MS = 24 * 60 * 60 * 1000;

  function canonicalUtc(value) {
    if (typeof value !== 'string' || !UTC_TIME.test(value)) return null;
    var ms = Date.parse(value);
    if (!Number.isFinite(ms)) return null;
    return new Date(ms).toISOString().slice(0, 19) === value.slice(0, 19) ? ms : null;
  }
  function approvedLocator(report) {
    if (!report || typeof report !== 'object' || Array.isArray(report) ||
        typeof report.id !== 'string') return null;
    var values = [report.path, report.url].filter(function(value) {
      return value !== null && value !== undefined;
    });
    if (!values.length) return null;
    var paths = [];
    for (var i = 0; i < values.length; i++) {
      var value = values[i];
      if (typeof value !== 'string' || value.length > 300 || /[%\\]/.test(value)) return null;
      var parsed;
      try { parsed = new URL(value, ORIGIN); } catch (_) { return null; }
      var match = REPORT_PATH.exec(parsed.pathname);
      if (!match || parsed.origin !== ORIGIN || parsed.username || parsed.password ||
          parsed.search || parsed.hash || parsed.port || match[1] !== report.id) return null;
      paths.push(parsed.pathname);
    }
    if (paths.some(function(path) { return path !== paths[0]; })) return null;
    return ORIGIN + paths[0];
  }

  function evaluate(data, nowMs) {
    if (nowMs === undefined) nowMs = Date.now();
    var blocked = {
      state: 'UNVERIFIED', ready_count: null, candidate_count: null,
      withheld_count: null, reports: [], view_all: false,
      message: 'Report publication authorization is unverified. No report links are shown.'
    };
    if (!data || typeof data !== 'object' || Array.isArray(data) ||
        data.schema_version !== '2.0.0' ||
        !['customer_ready_catalog', 'customer_ready_latest'].includes(data.feed_type) ||
        !Number.isFinite(nowMs)) return blocked;
    var issued = canonicalUtc(data.generated_at);
    var validated = canonicalUtc(data.validated_at);
    if (issued === null || validated === null || validated < issued ||
        issued > nowMs + 300000 || validated > nowMs + 300000 ||
        nowMs - issued > DAY_MS || nowMs - validated > DAY_MS) return blocked;
    var names = ['total_candidates', 'customer_ready_count', 'withheld_count',
                 'total_reports', 'reports_listed'];
    if (names.some(function(name) {
      return !Number.isSafeInteger(data[name]) || data[name] < 0;
    })) return blocked;
    if (!Array.isArray(data.reports) ||
        data.customer_ready_count + data.withheld_count !== data.total_candidates ||
        data.reports_listed !== data.reports.length ||
        data.reports_listed > data.customer_ready_count ||
        data.total_reports < data.total_candidates) return blocked;
    var selected = [];
    var seen = new Set();
    for (var i = 0; i < data.reports.length; i++) {
      var entry = data.reports[i], url = approvedLocator(entry);
      if (!url || seen.has(url)) return blocked;
      seen.add(url);
      selected.push(Object.assign({}, entry, {url: url}));
    }
    if (data.customer_ready_count > 0 && !selected.length) return blocked;
    var state = data.customer_ready_count === 0 ?
      (data.total_candidates === 0 ? 'NO_CANDIDATES' : 'WITHHELD') : 'READY';
    var message = state === 'WITHHELD' ?
      'No customer-ready reports are published. ' + data.withheld_count +
      ' candidate reports remain withheld by the publication safety gates.' :
      state === 'NO_CANDIDATES' ? 'No customer-ready reports have been generated.' :
      data.customer_ready_count + ' customer-ready reports in the current catalog.';
    return {
      state: state,
      ready_count: data.customer_ready_count,
      candidate_count: data.total_candidates,
      withheld_count: data.withheld_count,
      reports: selected,
      view_all: state === 'READY' && data.customer_ready_count > selected.length,
      message: message
    };
  }
  return { evaluate: evaluate, approvedLocator: approvedLocator };
});
