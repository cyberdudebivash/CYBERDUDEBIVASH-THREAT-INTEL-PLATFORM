/**
 * js/apex-track.js
 * CYBERDUDEBIVASH SENTINEL APEX — Conversion Tracking Engine v1.0
 * ================================================================
 * Zero-dependency, privacy-first funnel tracker.
 * Storage: localStorage (session funnel) + sendBeacon (persistence).
 * No PII collected. Events: page_view, cta_click, paywall_hit,
 *   upgrade_page_view, payment_attempt, payment_confirm.
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. CONFIDENTIAL.
 */
(function () {
  'use strict';

  var STORE_KEY = 'apex_funnel_v1';
  var SESSION_KEY = 'apex_session_v1';
  var BEACON_URL = 'https://formspree.io/f/xpzgdkoe'; // reuse existing endpoint

  // ── Session ID ────────────────────────────────────────────────
  function getSession() {
    var s = sessionStorage.getItem(SESSION_KEY);
    if (!s) {
      s = 'sess_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
      sessionStorage.setItem(SESSION_KEY, s);
    }
    return s;
  }

  // ── Load / save funnel store ──────────────────────────────────
  function loadStore() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY)) || {}; }
    catch (_) { return {}; }
  }

  function saveStore(store) {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(store)); }
    catch (_) {}
  }

  // ── Core event emitter ────────────────────────────────────────
  function track(event, meta) {
    var store = loadStore();
    var key = event;
    store[key] = (store[key] || 0) + 1;
    store['last_' + key] = new Date().toISOString();
    store['session'] = getSession();
    store['updated_at'] = new Date().toISOString();
    if (meta) {
      Object.keys(meta).forEach(function (k) { store['meta_' + k] = meta[k]; });
    }
    saveStore(store);

    // Fire-and-forget beacon (non-blocking, no error handling needed)
    try {
      var payload = JSON.stringify({
        _subject: '[APEX-TRACK] ' + event,
        event: event,
        session: getSession(),
        meta: meta || {},
        page: location.pathname,
        referrer: document.referrer,
        ts: new Date().toISOString()
      });
      if (navigator.sendBeacon) {
        var blob = new Blob([payload], { type: 'application/json' });
        navigator.sendBeacon(BEACON_URL, blob);
      }
    } catch (_) {}

    // Console debug (remove in prod if noisy)
    if (window.APEX_DEBUG) {
      console.log('[APEX-TRACK]', event, meta || '');
    }
  }

  // ── Auto-track: page view ─────────────────────────────────────
  track('page_view', { path: location.pathname });

  // ── Auto-track: upgrade page view (high intent) ───────────────
  if (location.pathname.indexOf('upgrade.html') !== -1) {
    var plan = new URLSearchParams(location.search).get('plan') || 'unknown';
    var utm  = new URLSearchParams(location.search).get('utm_source') || 'direct';
    track('upgrade_page_view', { plan: plan, utm_source: utm });
  }

  // ── Expose global API ─────────────────────────────────────────
  window.apxTrack = track;

  window.apxGetFunnel = function () {
    return loadStore();
  };

  window.apxResetFunnel = function () {
    localStorage.removeItem(STORE_KEY);
    sessionStorage.removeItem(SESSION_KEY);
  };

  // ── Wire upgrade modal clicks ─────────────────────────────────
  var _origModal = window.openUpgradeModal;
  if (typeof _origModal === 'function') {
    window.openUpgradeModal = function (plan) {
      track('cta_click', { plan: plan || 'unknown', source: 'modal' });
      _origModal(plan);
    };
  }

  // ── Delegate: track all CTA anchor clicks ─────────────────────
  document.addEventListener('click', function (e) {
    var el = e.target;
    // Walk up to find an <a> with upgrade intent
    for (var i = 0; i < 4 && el; i++, el = el.parentElement) {
      if (el.tagName === 'A') {
        var href = el.href || '';
        if (href.indexOf('upgrade.html') !== -1 || href.indexOf('gumroad.com') !== -1 ||
            href.indexOf('paypal.me') !== -1 || href.indexOf('sentinel-premium') !== -1) {
          track('cta_click', {
            href: href.split('?')[0],
            plan: (new URLSearchParams(href.split('?')[1] || '')).get('plan') || 'unknown',
            source: 'link'
          });
        }
        // Track payment attempt (PayPal / UPI open)
        if (href.indexOf('paypal.me') !== -1) {
          track('payment_attempt', { method: 'paypal' });
        }
        break;
      }
      // Track copy-UPI button
      if (el.tagName === 'BUTTON' && (el.textContent || '').toLowerCase().indexOf('copy') !== -1) {
        if (document.activeElement && document.activeElement.className &&
            document.activeElement.className.indexOf('upi') !== -1) {
          track('payment_attempt', { method: 'upi' });
        }
        break;
      }
    }
  }, true);

  // ── Track paywall hits ────────────────────────────────────────
  var _origPaywall = window.openStixPaywall;
  if (typeof _origPaywall === 'function') {
    window.openStixPaywall = function () {
      track('paywall_hit', { type: 'stix' });
      _origPaywall();
    };
  }

})();
