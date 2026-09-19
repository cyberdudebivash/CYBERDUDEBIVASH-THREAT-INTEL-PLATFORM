/**
 * CYBERDUDEBIVASH(R) SENTINEL APEX -- Checkout UX Enhancements v1.0
 * =============================================================================
 * Small, dependency-free additions layered on top of the existing, already
 * production-hardened checkout flow in pricing.html / upgrade.html. This
 * file does NOT touch payment creation/verification (that stays entirely
 * in upgrade.html's own /api/payment/razorpay/* calls) -- it only adds:
 *
 *   1. detectRegionDefaultCurrency() -- sets the *default* currency toggle
 *      on pricing.html (India -> INR, else USD) without removing or
 *      overriding the page's existing manual USD/INR/EUR/GBP selector.
 *   2. validateTaxId() -- loose optional GSTIN/VAT validation for the
 *      buyer-supplied tax-invoice field on upgrade.html.
 *   3. bindPaymentFailedHandler() -- explicit `payment.failed` messaging
 *      for a declined card, distinct from the existing modal-dismiss path.
 *   4. buildOnboardingSnippets() -- cURL + Python snippets for the
 *      post-payment success state, pre-filled with the real API key.
 *
 * Exposed as a single window.SentinelCheckout namespace so pricing.html /
 * upgrade.html can call into it with one-line hooks from their existing
 * inline scripts, instead of this file reaching into page-specific DOM.
 * =============================================================================
 */
'use strict';
(function () {

  var SentinelCheckout = {};

  // ---------------------------------------------------------------------
  // 1. Region-based default currency (pricing.html)
  // ---------------------------------------------------------------------
  /**
   * Sets the initial currency to INR for visitors who look like they're in
   * India (timezone or browser language), USD otherwise -- matching the
   * task's "Default to INR for India, USD for international" ask. Never
   * overrides a currency the visitor already picked this session via the
   * page's existing manual selector, and never runs at all on a page that
   * has no window.setCurrency (e.g. upgrade.html, which shows INR+USD
   * side by side rather than toggling).
   */
  SentinelCheckout.detectRegionDefaultCurrency = function () {
    try {
      if (typeof window.setCurrency !== 'function') return;
      var stored = null;
      try { stored = sessionStorage.getItem('currency'); } catch (e) {}
      if (stored) return; // explicit user choice this session always wins

      var tz = '';
      try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch (e) {}
      var lang = (navigator.language || navigator.userLanguage || '').toLowerCase();
      var looksIndian = tz === 'Asia/Kolkata' || tz === 'Asia/Calcutta' ||
        lang === 'en-in' || lang === 'hi' || lang.indexOf('hi-') === 0;

      if (looksIndian) window.setCurrency('INR');
    } catch (e) { /* a locale-detection failure must never block page render */ }
  };

  // ---------------------------------------------------------------------
  // 2. Optional buyer GSTIN/VAT validation (upgrade.html)
  // ---------------------------------------------------------------------
  // Only the well-known 15-character Indian GSTIN shape is strictly
  // validated. International VAT numbers vary too widely by country to
  // validate generically -- and this field is optional -- so anything
  // else non-empty is accepted as-is rather than blocking checkout.
  var GSTIN_RE = /^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[A-Z0-9]{1}Z[A-Z0-9]{1}$/;
  SentinelCheckout.validateTaxId = function (value) {
    var v = (value || '').trim().toUpperCase();
    if (!v) return { ok: true, value: '' };
    if (v.length === 15 && !GSTIN_RE.test(v)) {
      return { ok: false, value: v, reason: "Doesn't look like a valid 15-character GSTIN. Double-check it, or leave this blank." };
    }
    return { ok: true, value: v };
  };

  // ---------------------------------------------------------------------
  // 3. Razorpay declined-payment handling (upgrade.html)
  // ---------------------------------------------------------------------
  /**
   * Binds Razorpay's `payment.failed` event (fired for an actual decline --
   * insufficient funds, bank rejection, etc.) on the given checkout
   * instance. Distinct from the pre-existing `modal.ondismiss` handler,
   * which only fires when the buyer closes the modal without attempting
   * payment at all; this covers the "tried to pay, card declined" case
   * with an explicit, actionable message instead of a silent retry.
   */
  SentinelCheckout.bindPaymentFailedHandler = function (rzpInstance, onFailed) {
    if (!rzpInstance || typeof rzpInstance.on !== 'function') return;
    rzpInstance.on('payment.failed', function (resp) {
      var err = (resp && resp.error) || {};
      var msg = 'Payment declined' + (err.description ? ': ' + err.description : '.') +
        ' No charge was made -- please try a different card or payment method.';
      if (typeof onFailed === 'function') onFailed(msg, err);
      else alert(msg);
    });
  };

  // ---------------------------------------------------------------------
  // 4. Onboarding snippets (upgrade.html success state)
  // ---------------------------------------------------------------------
  SentinelCheckout.buildOnboardingSnippets = function (apiKey) {
    var key = apiKey || '<YOUR_API_KEY>';
    var curl = 'curl -H "X-API-Key: ' + key + '" https://intel.cyberdudebivash.com/api/feed';
    var python = [
      'import requests',
      '',
      'resp = requests.get(',
      '    "https://intel.cyberdudebivash.com/api/feed",',
      '    headers={"X-API-Key": "' + key + '"},',
      ')',
      'print(resp.json())',
    ].join('\n');
    return { curl: curl, python: python };
  };

  window.SentinelCheckout = SentinelCheckout;
})();
