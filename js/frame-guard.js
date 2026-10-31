/* Clickjacking guard for pages that act on API keys, sessions or payments.
 *
 * The production static site is served by GitHub Pages behind Cloudflare, so
 * _headers (X-Frame-Options: DENY, CSP frame-ancestors 'none') never reaches a
 * browser, and frame-ancestors in a <meta> CSP is ignored by spec. Until a
 * Cloudflare response-header rule sets those headers
 * (cloudflare/security_headers_transform_rule.json), this is the OWASP
 * frame-busting defence: when framed by another origin, hide the page (so
 * there is nothing to click) and try to navigate the top window to it --
 * browsers may block that navigation without a user gesture, in which case
 * the page simply stays hidden inside the frame. Same-origin framing is left
 * alone. Load synchronously, first thing in <head>.
 */
(function () {
  'use strict';
  var w = window;
  if (w.self === w.top) return;
  try {
    // Readable only when the parent is same-origin.
    if (w.top.location.origin === w.location.origin) return;
  } catch (e) { /* cross-origin parent */ }
  var root = document.documentElement;
  if (root) root.style.setProperty('display', 'none', 'important');
  try { w.top.location.replace(w.location.href); } catch (e) { /* sandboxed: stays hidden */ }
})();
