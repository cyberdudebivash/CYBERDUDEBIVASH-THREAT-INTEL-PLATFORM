// CDB_NORMALIZE -- canonical metric semantic contract (PR-E1).
// Single source of truth for EPSS/KEV/priority normalization, consumed by
// index.html's inline severity/priority helpers, js/sentinel-live-feeds.js,
// and scripts/ai_brain_patch.js's injected output. Loaded early (before any
// consumer) so window.CDB_NORMALIZE is always defined by the time a
// data-driven renderer actually runs.
//
// P0 2026-09-03: also boots js/p0-public-contract.js when present so public
// nav hide + live metric fill run on every page that already loads this file.
(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory(null);
  } else {
    root.CDB_NORMALIZE = factory(root);
  }
})(typeof window !== 'undefined' ? window : this, function (root) {
  'use strict';

  function normalizeEpss(raw) {
    if (raw === null || raw === undefined) {
      return { probability: null, percent: null, state: 'UNKNOWN' };
    }
    var n;
    if (typeof raw === 'number') {
      n = raw;
    } else if (typeof raw === 'string') {
      var trimmed = raw.trim();
      if (trimmed === '') {
        return { probability: null, percent: null, state: 'UNKNOWN' };
      }
      n = Number(trimmed);
    } else {
      n = NaN;
    }
    if (!Number.isFinite(n) || n < 0 || n > 100) {
      return { probability: null, percent: null, state: 'INVALID' };
    }
    if (n <= 1) {
      return { probability: n, percent: n * 100, state: 'OK' };
    }
    return { probability: n / 100, percent: n, state: 'OK' };
  }

  function normalizeKevValue(raw) {
    if (raw === true) return true;
    if (raw === false) return false;
    if (raw === null || raw === undefined || raw === '') return 'UNKNOWN';
    if (typeof raw === 'number') {
      if (raw === 1) return true;
      if (raw === 0) return false;
      return 'UNKNOWN';
    }
    if (typeof raw === 'string') {
      var s = raw.trim().toUpperCase();
      if (s === 'YES' || s === 'TRUE' || s === '1') return true;
      if (s === 'NO' || s === 'FALSE' || s === '0') return false;
      return 'UNKNOWN';
    }
    return 'UNKNOWN';
  }

  function kevState(item) {
    if (!item) return 'UNKNOWN';
    if (typeof item.kev_present === 'boolean') return item.kev_present;
    return normalizeKevValue(item.kev);
  }

  var PRIORITY_RE = /^P[0-4]$/i;
  function validPriority(v) {
    return typeof v === 'string' && PRIORITY_RE.test(v.trim()) ? v.trim().toUpperCase() : null;
  }

  function priority(item) {
    if (!item) return 'UNKNOWN';
    var fromSla = validPriority(item.sla_priority);
    if (fromSla) return fromSla;
    var fromSoc = item.apex_ai ? validPriority(item.apex_ai.soc_priority) : null;
    if (fromSoc) return fromSoc;
    var fromField = validPriority(item.priority);
    if (fromField) return fromField;
    var hasSignal = item.kev_present !== undefined || item.cvss_score != null
      || item.risk_score != null || item.epss_score != null;
    if (hasSignal && root && typeof root.computePriority === 'function') {
      var computed = validPriority(root.computePriority(item));
      if (computed) return computed;
    }
    return 'UNKNOWN';
  }

  return {
    epss: normalizeEpss,
    kevState: kevState,
    priority: priority,
  };
});

(function loadP0PublicContract() {
  if (typeof document === 'undefined') return;
  var s = document.createElement('script');
  s.src = '/js/p0-public-contract.js';
  s.async = true;
  s.defer = true;
  document.head ? document.head.appendChild(s) : document.documentElement.appendChild(s);
})();
