/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — Frontend Data Plane v1.0.0
 *  Shared fetch/contract-safety/race-safety primitives for dynamic dashboard widgets
 *
 *  STAGE 2 of the SENTINEL APEX Dynamic Frontend Transformation mandate
 *  (Phase 2 of the pre-existing "Dashboard Truth Contract" mission -- see
 *  DASHBOARD_TRUTH_CONTRACT_PHASE0_FORENSIC_CENSUS.md). That mission's Phase 1
 *  already shipped js/dashboard-state.js (canonical state vocabulary) and
 *  js/dashboard_contract_validator.js (card-shape validator), explicitly
 *  scoped for "a future canonical normalizer, Phase 2+, not part of that PR."
 *  js/api_adapter.js separately already has a solid fetchAndNormalize()
 *  (timeout + AbortController + retry-with-backoff + normalizeApexResponse)
 *  -- but index.html never calls it; the only two live call sites of
 *  window.SentinelApexAdapter in index.html are normalizeIntelItem() calls,
 *  not the fetch orchestrator. All three pieces were built, correct, and
 *  disconnected. This module composes them rather than re-implementing any
 *  of the three (Reuse Before Build):
 *    - request/timeout/retry shape: same proven pattern as
 *      api_adapter.js's fetchAndNormalize() and landing/api.js's apiFetch(),
 *      generalized into a reusable primitive instead of a fourth bespoke copy.
 *    - freshness: delegates to api_adapter.js's freshnessIndicator() where a
 *      published_at-style timestamp exists, rather than inventing a second
 *      threshold scheme.
 *    - state labeling: delegates to window.SentinelApexDashboardState.STATES
 *      (ERROR/UNKNOWN/STALE/DEGRADED) where that module is loaded, instead of
 *      inventing new state strings.
 *
 *  What this module adds that none of the three existing pieces had:
 *    - an explicit failure-class taxonomy exposed to the caller (timeout /
 *      network / http_4xx / http_5xx / malformed_json), not just a null result
 *    - a request-supersession guard so a slow, stale response from an earlier
 *      call can never overwrite a newer one's rendered result (race safety)
 *    - customer-facing message text for each failure class, matching the
 *      mandate's zero-fabrication vocabulary (never "No threats found" for a
 *      network failure)
 *
 *  PURELY ADDITIVE. Not called by any existing code path until a consumer is
 *  wired to it explicitly. Degrades gracefully (inline fallback constants) if
 *  js/dashboard-state.js or js/api_adapter.js are not loaded on the page, so
 *  load order is not a hard requirement -- but should load after both when
 *  both are present, matching index.html's existing "Load order" convention.
 * ═══════════════════════════════════════════════════════════════════════════════
 */
'use strict';

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.ApexDataPlane = factory();
  }
})(typeof window !== 'undefined' ? window : this, function () {

  const VERSION = '1.0.0';
  const DEFAULT_TIMEOUT_MS = 10000;
  const DEFAULT_MAX_RETRY = 1;
  const DEFAULT_RETRY_BACKOFF_MS = 500;

  /* ── Fallback state labels, used only if js/dashboard-state.js isn't loaded
     on this page -- keeps this module usable standalone (e.g. in a test
     harness) without silently inventing a *different* vocabulary when the
     real one is available. ── */
  const FALLBACK_STATES = Object.freeze({
    ERROR: 'ERROR',
    UNKNOWN: 'UNKNOWN',
    STALE: 'STALE',
    DEGRADED: 'DEGRADED',
  });

  function _states() {
    if (typeof window !== 'undefined' && window.SentinelApexDashboardState && window.SentinelApexDashboardState.STATES) {
      return window.SentinelApexDashboardState.STATES;
    }
    const f = {};
    Object.keys(FALLBACK_STATES).forEach(function (k) { f[k] = { value: FALLBACK_STATES[k] }; });
    return f;
  }

  /**
   * Failure classes a caller must be able to distinguish (Stage 2 spec
   * Section 7 -- "must not turn all failures into 'No threats found'").
   */
  const FAILURE_CLASS = Object.freeze({
    TIMEOUT: 'timeout',
    NETWORK: 'network',
    HTTP_4XX: 'http_4xx',
    HTTP_5XX: 'http_5xx',
    MALFORMED_JSON: 'malformed_json',
    ABORTED_SUPERSEDED: 'aborted_superseded',
  });

  /**
   * Customer-facing text per failure class (Stage 2 spec Section 8's exact
   * required vocabulary -- "Data unavailable", "Rate limited", etc., never a
   * fabricated empty-result message). auth (401/403) and rate-limit (429)
   * are their own sub-cases of HTTP_4XX with more specific copy.
   */
  function messageForFailure(failureClass, httpStatus) {
    if (failureClass === FAILURE_CLASS.TIMEOUT) return 'Request timed out. Data unavailable.';
    if (failureClass === FAILURE_CLASS.NETWORK) return 'Network error. Data temporarily unavailable.';
    if (failureClass === FAILURE_CLASS.MALFORMED_JSON) return 'Data unavailable — received an unexpected response.';
    if (failureClass === FAILURE_CLASS.HTTP_4XX) {
      if (httpStatus === 401 || httpStatus === 403) return 'Authentication required.';
      if (httpStatus === 429) return 'Rate limited. Please try again shortly.';
      return 'Data unavailable — request rejected (' + httpStatus + ').';
    }
    if (failureClass === FAILURE_CLASS.HTTP_5XX) return 'Data temporarily unavailable — backend error.';
    return 'Data unavailable.';
  }

  /**
   * Single fetch attempt with timeout + explicit failure classification.
   * Never throws -- always resolves to {ok, status, data, failureClass, message}.
   */
  async function fetchJSON(url, opts) {
    const options = opts || {};
    const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    const externalSignal = options.signal;

    const ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = ctrl ? setTimeout(function () { ctrl.abort(); }, timeoutMs) : null;

    // If the caller supplied an external (request-guard) signal, abort this
    // fetch when EITHER the timeout fires OR the caller supersedes it.
    let externalAbortHandler = null;
    if (ctrl && externalSignal) {
      if (externalSignal.aborted) { ctrl.abort(); }
      else {
        externalAbortHandler = function () { ctrl.abort(); };
        externalSignal.addEventListener('abort', externalAbortHandler);
      }
    }

    try {
      const fetchOpts = Object.assign({}, options.fetchOpts || {}, ctrl ? { signal: ctrl.signal } : {});
      const res = await fetch(url, fetchOpts);
      if (timer) clearTimeout(timer);

      if (!res.ok) {
        const failureClass = res.status >= 500 ? FAILURE_CLASS.HTTP_5XX : FAILURE_CLASS.HTTP_4XX;
        return { ok: false, status: res.status, data: null, failureClass: failureClass, message: messageForFailure(failureClass, res.status) };
      }

      let data;
      try {
        data = await res.json();
      } catch (parseErr) {
        return { ok: false, status: res.status, data: null, failureClass: FAILURE_CLASS.MALFORMED_JSON, message: messageForFailure(FAILURE_CLASS.MALFORMED_JSON) };
      }
      return { ok: true, status: res.status, data: data, failureClass: null, message: null };
    } catch (err) {
      if (timer) clearTimeout(timer);
      if (externalSignal && externalSignal.aborted) {
        return { ok: false, status: 0, data: null, failureClass: FAILURE_CLASS.ABORTED_SUPERSEDED, message: null };
      }
      if (err && err.name === 'AbortError') {
        return { ok: false, status: 0, data: null, failureClass: FAILURE_CLASS.TIMEOUT, message: messageForFailure(FAILURE_CLASS.TIMEOUT) };
      }
      return { ok: false, status: 0, data: null, failureClass: FAILURE_CLASS.NETWORK, message: messageForFailure(FAILURE_CLASS.NETWORK) };
    } finally {
      if (externalSignal && externalAbortHandler) externalSignal.removeEventListener('abort', externalAbortHandler);
    }
  }

  /**
   * fetchJSON with retry-with-backoff, same shape as api_adapter.js's
   * fetchAndNormalize() retry loop (500ms * attempt). Does not retry a
   * request that was superseded (no point retrying work nobody wants) or a
   * 4xx (retrying an auth/validation failure unchanged wastes a round trip).
   */
  async function fetchWithRetry(url, opts) {
    const options = opts || {};
    const maxRetry = options.maxRetry != null ? options.maxRetry : DEFAULT_MAX_RETRY;
    const backoffMs = options.retryBackoffMs || DEFAULT_RETRY_BACKOFF_MS;

    let lastResult = null;
    for (let attempt = 0; attempt <= maxRetry; attempt++) {
      lastResult = await fetchJSON(url, options);
      if (lastResult.ok) return lastResult;
      if (lastResult.failureClass === FAILURE_CLASS.ABORTED_SUPERSEDED) return lastResult;
      if (lastResult.failureClass === FAILURE_CLASS.HTTP_4XX) return lastResult;
      if (attempt < maxRetry) {
        await new Promise(function (r) { setTimeout(r, backoffMs * (attempt + 1)); });
      }
    }
    return lastResult;
  }

  /**
   * Request-supersession guard (race safety, Stage 2 spec Section 11/19):
   * "stale requests overwriting newer results" is a named required defect
   * to prevent. Each call to start() aborts whatever the PREVIOUS start()
   * on this same guard was waiting on, and returns the signal for the new
   * request. A caller that checks `guard.isCurrent(token)` before applying
   * a response to the DOM can also detect + discard a late arrival even in
   * environments without AbortController.
   */
  function createRequestGuard() {
    let currentController = null;
    let currentToken = 0;
    return {
      start: function () {
        if (currentController) { try { currentController.abort(); } catch (e) { /* already settled */ } }
        currentController = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        currentToken += 1;
        return { signal: currentController ? currentController.signal : undefined, token: currentToken };
      },
      isCurrent: function (token) {
        return token === currentToken;
      },
    };
  }

  /**
   * Freshness classification for a response. Delegates to api_adapter.js's
   * freshnessIndicator() (LIVE/RECENT/AGING/STALE, hour-based) when present
   * and a timestamp is supplied -- does not invent a second threshold
   * scheme. Falls back to dashboard-state.js's STALE state generically if
   * api_adapter isn't loaded.
   */
  function resolveFreshness(timestampish) {
    if (typeof window !== 'undefined' && window.SentinelApexAdapter && typeof window.SentinelApexAdapter.freshnessIndicator === 'function') {
      return window.SentinelApexAdapter.freshnessIndicator(timestampish);
    }
    if (!timestampish) return { label: 'UNKNOWN', class: 'freshness-unknown' };
    const d = new Date(timestampish);
    if (isNaN(d.getTime())) return { label: 'UNKNOWN', class: 'freshness-unknown' };
    const ageHrs = (Date.now() - d.getTime()) / 3600000;
    return ageHrs <= 24 ? { label: 'FRESH', class: 'freshness-fresh', ageHrs: ageHrs } : { label: 'STALE', class: 'freshness-stale', ageHrs: ageHrs };
  }

  return {
    VERSION: VERSION,
    FAILURE_CLASS: FAILURE_CLASS,
    messageForFailure: messageForFailure,
    fetchJSON: fetchJSON,
    fetchWithRetry: fetchWithRetry,
    createRequestGuard: createRequestGuard,
    resolveFreshness: resolveFreshness,
  };

});
