/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — Capability Discovery Widget v1.0.0
 *  Dynamic frontend consumer for the P41 Live Capability Discovery API
 *
 *  Fetches /api/v1/p41/capabilities (public, unauthenticated -- see
 *  workers/intel-gateway/src/p41-handlers.js file header) and renders an
 *  explicit loading -> success/empty/error state sequence. This is the
 *  frontend half of the "Dynamic Frontend Discovery" mission item: when a
 *  new CUSTOMER_UI page is registered (data/quality/frontend_capability_
 *  registry.json, enforced by capability_registry_gate.py), it becomes
 *  visible here automatically -- no page that embeds this widget needs to
 *  be hand-edited again.
 *
 *  Reuse Before Build: composes window.ApexDataPlane (js/apex-data-plane.js)
 *  for fetch/timeout/failure-classification -- no bespoke fetch/retry logic
 *  here. Falls back to a minimally-equivalent inline fetch if ApexDataPlane
 *  isn't loaded on the host page (matches apex-data-plane.js's own "load
 *  order is not a hard requirement" stance), so this module works even on a
 *  page that doesn't already carry the shared data-plane script.
 *
 *  Rendering safety (mission security requirement -- "treat every API field
 *  as untrusted"): all DOM is built with createElement/textContent, never
 *  innerHTML. Every capability's `frontend_route` is additionally validated
 *  as a same-origin relative path before being used as an href -- rejects
 *  "javascript:"/"data:" schemes and absolute/protocol-relative URLs -- even
 *  though in practice this API only ever serves this repo's own filenames.
 *
 *  Split for testability: this file has NO DOM dependency at module-eval
 *  time, and every function that does not need `document` (isSafeRoute,
 *  statusLabel, buildViewModel, classifyResult) is exported standalone so
 *  js/__tests__/capability-discovery.test.js can exercise them under plain
 *  `node --test` (this repo's existing js/__tests__ convention -- no jsdom
 *  dependency anywhere else in the codebase, so none is introduced here
 *  either). Only `mount()` touches `document`, and is intentionally thin.
 * ═══════════════════════════════════════════════════════════════════════════════
 */
'use strict';

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelApexCapabilityDiscovery = factory();
  }
})(typeof window !== 'undefined' ? window : this, function () {

  const VERSION = '1.0.0';
  const API_PATH = '/api/v1/p41/capabilities';

  const STATUS_LABELS = {
    live: 'Live — dynamic, real-time data',
    live_non_gateway: 'Live — dynamic data',
    static_content: 'Reference / informational',
    orphan: 'Available',
    form_only: 'Available',
    interactive_docs: 'Interactive',
    unclassified: 'Available',
  };

  function statusLabel(status) {
    return STATUS_LABELS[String(status || '')] || 'Available';
  }

  // Same-origin, path-only route: "/", then safe path characters. Rejects
  // "javascript:alert(1)", "data:text/html,...", "//evil.com/x" (protocol-
  // relative), "https://evil.com" (absolute), and anything containing a
  // scheme separator or backslash.
  const SAFE_ROUTE_RE = /^\/[A-Za-z0-9][A-Za-z0-9._~\-\/]*$/;
  function isSafeRoute(route) {
    if (typeof route !== 'string' || !route) return false;
    if (route.indexOf('//') === 0) return false; // protocol-relative
    return SAFE_ROUTE_RE.test(route);
  }

  /**
   * Transforms a raw /api/v1/p41/capabilities response body into a plain,
   * render-ready view-model. Pure function -- no DOM, no fetch. Drops any
   * malformed entry rather than letting one bad record break the whole
   * list (mission "Rendering Resilience" requirement).
   * @param {Object} payload
   * @returns {{ total: number, generatedAt: string|null, items: Array }}
   */
  function buildViewModel(payload) {
    const body = payload && typeof payload === 'object' ? payload : {};
    const raw = Array.isArray(body.capabilities) ? body.capabilities : [];
    const items = [];
    for (const c of raw) {
      if (!c || typeof c !== 'object') continue;
      const id = typeof c.id === 'string' ? c.id : '';
      const route = typeof c.frontend_route === 'string' ? c.frontend_route : '';
      if (!id || !isSafeRoute(route)) continue; // unsafe/missing route -> never rendered as a link
      items.push({
        id: id,
        title: typeof c.title === 'string' && c.title ? c.title : id,
        route: route,
        statusLabel: statusLabel(c.status),
      });
    }
    return {
      total: items.length,
      generatedAt: typeof body.registry_generated_at === 'string' ? body.registry_generated_at : null,
      items: items,
    };
  }

  /**
   * Decides the render state for a completed ApexDataPlane-shaped fetch
   * result ({ok, data, failureClass, message}). Pure function.
   * @returns {{ state: 'success'|'empty'|'error', viewModel: Object|null, message: string|null }}
   */
  function classifyResult(result) {
    if (!result || !result.ok) {
      const failureClass = (result && result.failureClass) || 'unknown';
      const message = (result && result.message) || 'Capability directory is temporarily unavailable.';
      return { state: 'error', viewModel: null, message: message + ' (' + failureClass + ')' };
    }
    const vm = buildViewModel(result.data);
    return vm.total === 0
      ? { state: 'empty', viewModel: vm, message: null }
      : { state: 'success', viewModel: vm, message: null };
  }

  // ── fetch (delegates to ApexDataPlane when present; see file header) ─────
  function _fetchJSON(url) {
    if (typeof window !== 'undefined' && window.ApexDataPlane && typeof window.ApexDataPlane.fetchJSON === 'function') {
      return window.ApexDataPlane.fetchJSON(url, { timeoutMs: 10000 });
    }
    return fetch(url).then(function (res) {
      return res.json().then(
        function (data) {
          return res.ok
            ? { ok: true, status: res.status, data: data, failureClass: null, message: null }
            : { ok: false, status: res.status, data: null, failureClass: res.status >= 500 ? 'http_5xx' : 'http_4xx', message: 'Data unavailable (' + res.status + ').' };
        },
        function () {
          return { ok: false, status: res.status, data: null, failureClass: 'malformed_json', message: 'Data unavailable — received an unexpected response.' };
        }
      );
    }, function () {
      return { ok: false, status: 0, data: null, failureClass: 'network', message: 'Network error. Data temporarily unavailable.' };
    });
  }

  // ── DOM rendering (thin; all logic above is unit-tested without it) ──────
  function _el(tag, attrs, children) {
    const e = document.createElement(tag);
    if (attrs) {
      for (const k in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
        if (k === 'className') e.className = attrs[k];
        else if (k === 'href') e.setAttribute('href', attrs[k]); // caller must pre-validate via isSafeRoute
        else e.setAttribute(k, attrs[k]);
      }
    }
    (children || []).forEach(function (c) {
      if (c === null || c === undefined) return;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return e;
  }

  function _clear(mountEl) {
    while (mountEl.firstChild) mountEl.removeChild(mountEl.firstChild);
  }

  function _render(mountEl, classified) {
    _clear(mountEl);
    if (classified.state === 'error') {
      mountEl.appendChild(_el('div', { className: 'sapx-cap-state sapx-cap-error', role: 'alert' }, [classified.message]));
      return;
    }
    if (classified.state === 'empty') {
      mountEl.appendChild(_el('div', { className: 'sapx-cap-state sapx-cap-empty' }, ['No public capabilities are currently registered.']));
      return;
    }
    const vm = classified.viewModel;
    const metaText = vm.total + ' platform capabilities' + (vm.generatedAt ? ' — catalog as of ' + vm.generatedAt : '');
    mountEl.appendChild(_el('div', { className: 'sapx-cap-meta' }, [metaText]));
    const grid = _el('div', { className: 'sapx-cap-grid' }, []);
    vm.items.forEach(function (item) {
      grid.appendChild(_el('a', { className: 'sapx-cap-card', href: item.route }, [
        _el('div', { className: 'sapx-cap-card-title' }, [item.title]),
        _el('div', { className: 'sapx-cap-card-status' }, [item.statusLabel]),
      ]));
    });
    mountEl.appendChild(grid);
  }

  /**
   * Mounts the live capability directory into `mountEl`.
   * @param {HTMLElement} mountEl
   * @param {Object} [opts]
   * @param {string} [opts.status] - optional ?status= filter (e.g. "live")
   */
  function mount(mountEl, opts) {
    if (!mountEl || typeof document === 'undefined') return;
    const options = opts || {};
    _clear(mountEl);
    mountEl.appendChild(_el('div', { className: 'sapx-cap-state sapx-cap-loading', role: 'status', 'aria-live': 'polite' }, ['Loading platform capabilities…']));

    let url = API_PATH;
    if (options.status) url += '?status=' + encodeURIComponent(options.status);

    _fetchJSON(url).then(function (result) {
      if (!mountEl.isConnected) return; // page navigated away mid-fetch
      _render(mountEl, classifyResult(result));
    }).catch(function () {
      // ApexDataPlane.fetchJSON's documented contract is "never throws", but
      // this is defense-in-depth for the standalone fallback path above --
      // an unhandled rejection must never leave the mount stuck on
      // "Loading…" forever (mission "no infinite spinner" requirement).
      if (mountEl.isConnected) _render(mountEl, { state: 'error', viewModel: null, message: 'Capability directory is temporarily unavailable. (unexpected_error)' });
    });
  }

  return {
    VERSION: VERSION,
    API_PATH: API_PATH,
    statusLabel: statusLabel,
    isSafeRoute: isSafeRoute,
    buildViewModel: buildViewModel,
    classifyResult: classifyResult,
    mount: mount,
  };

});
