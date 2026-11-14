/* SENTINEL APEX P0 public contract runtime.
 * Loaded from pages that already include js/metric-normalize.js.
 * Does not invent advisory/IOC counts. Hides unauthenticated ops nav.
 */
(function () {
  'use strict';
  if (typeof window === 'undefined' || window.__APEX_P0_PUBLIC__) return;
  window.__APEX_P0_PUBLIC__ = true;

  var HIDE = [
    'Revenue+', 'Monetize', 'Ops Hub', 'Graph Ops', 'Telemetry Ops',
    'AI Sec Ops', 'Web3 Intel', 'MSSP Console', 'Enterprise Dashboard',
    'SOC V2', 'Orchestration', 'Global Deploy'
  ];

  function isAuthed() {
    try {
      return !!(localStorage.getItem('apex_api_key') || localStorage.getItem('cdb_session') || document.cookie.indexOf('apex_session=') !== -1);
    } catch (e) {
      return false;
    }
  }

  function hideOpsNav() {
    if (isAuthed()) return;
    var nodes = document.querySelectorAll('a, button, [role="link"]');
    for (var i = 0; i < nodes.length; i++) {
      var el = nodes[i];
      var label = (el.textContent || '').replace(/\s+/g, ' ').trim();
      for (var j = 0; j < HIDE.length; j++) {
        if (label === HIDE[j] || label.indexOf(HIDE[j]) === 0) {
          el.style.display = 'none';
          var parent = el.parentElement;
          if (parent && parent.children.length === 1) parent.style.display = 'none';
        }
      }
    }
  }

  function fillMetrics(data) {
    if (!data || typeof data !== 'object') return;
    var map = {
      advisory_count_live: data.advisory_count_live,
      feed_source_count: data.feed_source_count,
      ioc_count_unique_30d: data.ioc_count_unique_30d
    };
    Object.keys(map).forEach(function (key) {
      var val = map[key];
      if (val === null || val === undefined || val === '') return;
      var nodes = document.querySelectorAll('[data-apex-metric="' + key + '"]');
      for (var i = 0; i < nodes.length; i++) {
        nodes[i].textContent = String(val);
      }
    });
  }

  function loadMetrics() {
    var urls = ['/api/metrics', '/metrics/canonical.json'];
    function next(i) {
      if (i >= urls.length) return;
      fetch(urls[i], { credentials: 'omit' }).then(function (res) {
        if (!res.ok) throw new Error('bad');
        return res.json();
      }).then(function (json) {
        fillMetrics(json);
      }).catch(function () {
        next(i + 1);
      });
    }
    next(0);
  }

  function boot() {
    hideOpsNav();
    loadMetrics();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
