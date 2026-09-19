/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — Primary Feed Terminal-State Resolver v1.0.0
 *
 *  P0 incident 2026-09-03. index.html's loadGOCIntel() walks MANIFEST_URLS and,
 *  when every source fails, painted:
 *
 *      SYNC: ⚡ LOADING     +     ⚡ NO DATA
 *
 *  That is a TERMINAL failure state wearing a LOADING label. Nothing further
 *  runs after it, so the customer dashboard sat on "LOADING" indefinitely
 *  while /api/health simultaneously reported 500 healthy advisories. Two
 *  separate truth defects sat in that one branch:
 *
 *    1. An infrastructure denial (HTTP 429 from the API entitlement gate)
 *       was rendered identically to "we are still fetching", and one step
 *       later identically to "there is no intelligence" — so a quota error
 *       masqueraded as an empty feed.
 *    2. When a NON-authoritative fallback source did answer (the
 *       raw.githubusercontent.com mirror, which carries a stale 109-item
 *       snapshot against the authority's 500), the page still displayed
 *       "SYNC: LIVE" and "MANIFEST VERIFIED" — asserting freshness and
 *       verification for data that was neither.
 *
 *  This module is the single pure decision function for what the feed's
 *  terminal state actually is, given what the network returned. It holds no
 *  DOM references and performs no I/O so it can be unit-tested directly with
 *  `node --test` (js/__tests__/, the same convention as api_adapter and
 *  apex-data-plane's tests).
 *
 *  It deliberately reuses the state vocabulary that already exists rather
 *  than inventing a third one: the names below are the canonical dashboard
 *  states (js/dashboard-state.js) plus RATE_LIMITED, which the mandate
 *  requires be distinguishable from EMPTY and which apex-data-plane.js
 *  already treats as its own customer-facing failure message
 *  ("Rate limited. Please try again shortly.", messageForFailure/429).
 *
 *  PURELY ADDITIVE. Loading this file changes nothing on its own; index.html
 *  calls resolveFeedTerminalState() at the single point where it previously
 *  hard-coded the LOADING label.
 *
 *  P0 UPDATE (2026-09-09) — a customer dashboard was found displaying
 *  SYNC: STALE / FALLBACK SOURCE over data 14 DAYS old. Root-caused end to
 *  end: the raw.githubusercontent.com fallback mirror reads api/feed.json
 *  directly from what's committed to `main` in git -- and this platform's
 *  R2 persistence migration (see scripts/r2_state_sync.py, PR #387/#390)
 *  deliberately stopped git-committing that file as part of moving runtime
 *  state authority to R2. That makes the mirror's content permanently
 *  frozen at whatever it was the day the git-commit step was retired --
 *  confirmed live: both api/feed.json and api/v1/intel/latest.json's
 *  committed copies carry generated_at/published_at timestamps from
 *  2026-08-26, the exact date of the branch-ruleset change that root-caused
 *  the 2026-08-26 core-feed staleness incident (PR #387's own subject).
 *  The mirror can never get fresher under the current architecture -- it
 *  is not "a bit behind", it is permanently stuck, and gets a day staler
 *  every day forever.
 *
 *  Before this fix, ANY transient failure of the authoritative source
 *  (rate limiting, a cold start, a brief outage -- all normal, expected,
 *  eventually-recovering events) caused this module to accept that frozen
 *  mirror as a legitimate "STALE" hit, indefinitely -- an ever-worsening,
 *  self-inflating staleness with no mechanism to ever resolve itself, wearing
 *  a label ("STALE / FALLBACK SOURCE", "Showing a cached mirror") that
 *  reads as "a little behind", not "abandoned by the pipeline weeks ago".
 *  For a threat-intelligence product specifically, silently degrading to
 *  weeks-old advisories under a reassuring label is a correctness defect,
 *  not a cosmetic one.
 *
 *  Fix: a fallback hit's OWN content age is now checked against
 *  MAX_USABLE_FALLBACK_AGE_MS (72h -- reusing, not reinventing, the same
 *  STALE threshold workers/intel-gateway/src/index.js's classifyFreshness()
 *  already uses server-side) before it may satisfy fallbackHit. Content
 *  older than that no longer masquerades as a merely-stale-but-useful
 *  answer; resolution falls through to the existing, more honest
 *  RATE_LIMITED/ERROR states instead. Backward compatible by construction:
 *  an attempt with no contentGeneratedAt (the field this fix adds) is
 *  treated exactly as before -- age-unknown does not mean age-rejected.
 * ═══════════════════════════════════════════════════════════════════════════════
 */
'use strict';

(function (root, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelFeedState = factory();
  }
})(typeof window !== 'undefined' ? window : this, function () {

  var VERSION = '1.0.0';

  /**
   * Terminal states the primary feed may end in. LOADING is intentionally
   * ABSENT: it is not a terminal state, and the whole point of this module is
   * that no failure path may end on it.
   */
  var STATES = Object.freeze({
    LIVE:         'LIVE',          // authoritative source answered with items
    STALE:        'STALE',         // a non-authoritative fallback answered
    EMPTY:        'EMPTY',         // authoritative source answered, genuinely 0 items
    RATE_LIMITED: 'RATE_LIMITED',  // denied by an entitlement/quota gate (429)
    ERROR:        'ERROR',         // every source failed for some other reason
    OFFLINE:      'OFFLINE',       // browser reports no network at all
  });

  /**
   * Customer-facing copy per terminal state. Never says "no threat
   * intelligence" for anything that is not a genuine, authoritative empty
   * feed — an infrastructure failure must never be reported as an editorial
   * fact about the threat landscape.
   */
  var COPY = Object.freeze({
    LIVE:         { sync: 'LIVE',         badge: 'MANIFEST VERIFIED',     detail: '' },
    STALE:        { sync: 'STALE',        badge: 'FALLBACK SOURCE',       detail: 'Showing a cached mirror — not the live feed.' },
    EMPTY:        { sync: 'NO ADVISORIES', badge: 'FEED EMPTY',           detail: 'The feed is reachable and currently contains no advisories.' },
    RATE_LIMITED: { sync: 'RATE LIMITED', badge: 'REQUEST LIMIT REACHED', detail: 'Too many requests from this network. Intelligence is available — this view is temporarily throttled.' },
    ERROR:        { sync: 'ERROR',        badge: 'FEED UNAVAILABLE',      detail: 'Could not reach the intelligence feed. This is a delivery fault, not an absence of intelligence.' },
    OFFLINE:      { sync: 'OFFLINE',      badge: 'NO NETWORK',            detail: 'Your browser reports no network connection.' },
  });

  /**
   * True when an HTTP status is an entitlement/quota denial rather than a
   * statement about the data. 429 is the gateway's quota + rate-limit code;
   * 401/403 are auth denials, which are equally not "the feed is empty".
   */
  function isEntitlementDenial(status) {
    return status === 429 || status === 401 || status === 403;
  }

  /**
   * A fallback (non-authoritative) hit whose own content is older than this
   * is no longer treated as a usable "stale but current-ish" answer -- see
   * the 2026-09-09 P0 update in the module docstring. Matches
   * workers/intel-gateway/src/index.js's classifyFreshness() STALE
   * threshold (72h) rather than inventing a second number.
   */
  var MAX_USABLE_FALLBACK_AGE_MS = 72 * 60 * 60 * 1000;

  /**
   * Age of an attempt's own content in ms, or null when unknown (no
   * contentGeneratedAt, unparseable, or in the future). null is the
   * pre-2026-09-09-fix default and is deliberately treated as "usable" by
   * the caller -- unknown age must never be conflated with rejected age.
   */
  function _contentAgeMs(attempt, nowMs) {
    if (!attempt || !attempt.contentGeneratedAt) return null;
    var t = Date.parse(attempt.contentGeneratedAt);
    if (isNaN(t)) return null;
    var age = nowMs - t;
    return age >= 0 ? age : null;
  }

  /**
   * Resolve the terminal state of the primary feed.
   *
   * @param {Object} outcome
   * @param {Array<{url:string, status:number|null, ok:boolean, authoritative:boolean, itemCount:number, contentGeneratedAt?:string}>} outcome.attempts
   *        One entry per MANIFEST_URLS source actually tried, in order.
   *        `status` is the HTTP status, or null when the request never
   *        produced one (network error / timeout / abort).
   *        `authoritative` marks a first-party API source, as opposed to a
   *        third-party mirror. `contentGeneratedAt` (optional, ISO string)
   *        is when the SOURCE'S OWN content was produced -- e.g. an old
   *        git-mirror snapshot -- distinct from when the HTTP request
   *        happened; used only to gate non-authoritative fallback hits.
   * @param {boolean} [outcome.online] navigator.onLine, when available.
   * @returns {{state:string, sync:string, badge:string, detail:string,
   *            httpStatus:number|null, sourceUrl:string|null, itemCount:number,
   *            isTerminalFailure:boolean, rateLimited:boolean}}
   */
  function resolveFeedTerminalState(outcome) {
    var o = outcome || {};
    var attempts = Array.isArray(o.attempts) ? o.attempts : [];
    var online = (o.online === undefined) ? true : !!o.online;
    var nowMs = Date.now();

    // A source that answered with usable items wins, authoritative first.
    var authoritativeHit = null, fallbackHit = null, authoritativeEmpty = null;
    for (var i = 0; i < attempts.length; i++) {
      var a = attempts[i] || {};
      if (!a.ok) continue;
      var n = typeof a.itemCount === 'number' ? a.itemCount : 0;
      if (n > 0) {
        if (a.authoritative) { if (!authoritativeHit) authoritativeHit = a; }
        else if (!fallbackHit) {
          // 2026-09-09 P0 fix: a fallback answering with content this old
          // (age known AND over threshold) is not a usable hit -- fall
          // through so a more honest RATE_LIMITED/ERROR/OFFLINE state has
          // the chance to surface instead of an indefinitely-ageing STALE.
          var age = _contentAgeMs(a, nowMs);
          if (age === null || age <= MAX_USABLE_FALLBACK_AGE_MS) fallbackHit = a;
        }
      } else if (a.authoritative && !authoritativeEmpty) {
        authoritativeEmpty = a;
      }
    }

    if (authoritativeHit) return _build(STATES.LIVE, authoritativeHit);
    // A stale mirror is shown — but it is labelled STALE, never LIVE, and the
    // badge never claims verification. Serving it silently under a "LIVE /
    // MANIFEST VERIFIED" label was the second truth defect in this incident.
    if (fallbackHit) return _build(STATES.STALE, fallbackHit);
    // Only an authoritative source is allowed to assert that the feed is
    // genuinely empty. A fallback returning 0 items proves nothing.
    if (authoritativeEmpty) return _build(STATES.EMPTY, authoritativeEmpty);

    if (!online) return _build(STATES.OFFLINE, null);

    // Nothing usable came back. Distinguish an entitlement denial from a
    // generic failure — a quota error must never be reported as an empty feed.
    var denial = null;
    for (var j = 0; j < attempts.length; j++) {
      if (attempts[j] && isEntitlementDenial(attempts[j].status)) { denial = attempts[j]; break; }
    }
    if (denial) return _build(STATES.RATE_LIMITED, denial);

    var anyStatus = null;
    for (var k = 0; k < attempts.length; k++) {
      if (attempts[k] && attempts[k].status) { anyStatus = attempts[k]; break; }
    }
    return _build(STATES.ERROR, anyStatus);
  }

  function _build(state, attempt) {
    var copy = COPY[state] || COPY.ERROR;
    var terminalFailure = (state === STATES.RATE_LIMITED || state === STATES.ERROR || state === STATES.OFFLINE);
    return {
      state: state,
      sync: copy.sync,
      badge: copy.badge,
      detail: copy.detail,
      httpStatus: attempt && attempt.status != null ? attempt.status : null,
      sourceUrl: attempt && attempt.url ? attempt.url : null,
      itemCount: attempt && typeof attempt.itemCount === 'number' ? attempt.itemCount : 0,
      isTerminalFailure: terminalFailure,
      rateLimited: state === STATES.RATE_LIMITED,
    };
  }

  return {
    VERSION: VERSION,
    STATES: STATES,
    COPY: COPY,
    MAX_USABLE_FALLBACK_AGE_MS: MAX_USABLE_FALLBACK_AGE_MS,
    isEntitlementDenial: isEntitlementDenial,
    resolveFeedTerminalState: resolveFeedTerminalState,
  };
});
