#!/usr/bin/env node
/**
 * SENTINEL APEX — pages-fast-publish Pre-Deploy Smoke Test
 * ====================================================================
 * Real-browser (headless Chromium) check that the just-built dist/
 * artifact actually renders before pages-fast-publish.yml deploys it
 * to the live gh-pages branch. Closes the gap flagged in the PR #304
 * follow-up: the existing "Verify frontend-critical files are present
 * in dist/" step (and the post-deploy freshness gate) confirm the
 * right files exist and that the deploy landed -- neither confirms
 * the page actually executes without error.
 *
 * Self-contained, same pattern as this directory's other verify_*.js
 * scripts (e.g. verify_enterprise_homepage.js): starts a local static
 * file server, loads the page in headless Chromium, and fails on any
 * uncaught JS error or a 404/5xx on a js/**, css/**, or index.html
 * request -- exactly the file classes pages-fast-publish.yml owns.
 *
 * Deliberately NOT asserting on /api/**, /reports/**, /dashboard/**,
 * /customer/**, /assets/**, or /.well-known/** requests: this
 * workflow's fresh checkout never populates those directories the way
 * the full sentinel-blogger.yml pipeline does (see pages-fast-publish
 * .yml's own clean-exclude comment), so 404s there are expected, not
 * a smoke-test failure. sentinel-live-feeds.js already treats a
 * failed fetch as non-fatal (console.warn + graceful fallback, see
 * apiFetch()), so this script only fails on console.error/pageerror,
 * matching what the app itself treats as an actual bug.
 *
 * All non-local (cross-origin) requests -- the production API when
 * this page isn't served from intel.cyberdudebivash.com, Font
 * Awesome/Google Fonts CDN links, the news-feed CORS proxy -- are
 * deliberately aborted rather than allowed to hit the real network.
 * Confirmed against index.html: the only external <script>/<link>
 * tags are Font Awesome/Google Fonts stylesheets (cosmetic, not
 * JS-blocking), so this doesn't hide a real init failure. It does
 * make the check hermetic and fast: no dependency on third-party
 * uptime, no waiting out apiFetch's 12s per-call timeout, and it
 * exercises the exact "API unreachable" fallback path apiFetch()
 * already exists to handle -- a live-run of this script surfaced a
 * genuine unrelated bug this way (mitre_tactics[0].toUpperCase on a
 * non-string value in renderTopThreats), confirming the signal is
 * real, not just aborted-request noise.
 *
 * Usage:
 *   node render-test/verify_pages_fast_publish_smoke.js [dist-dir]
 *   (defaults to "dist" at the repo root; pages-fast-publish.yml runs
 *   this immediately after scripts/build_dist_artifact.py, before the
 *   deploy step)
 *
 * Requires the same globally-installed `playwright` this directory's
 * other scripts use locally; pages-fast-publish.yml installs it
 * fresh via `npm install --no-save` since it isn't a project
 * dependency (see docs/enterprise-homepage-guide.md, Known
 * Limitations, for why no package.json was added to this repo).
 *
 * Exit code 0 = smoke test passed. Exit code 1 = at least one failure.
 */
'use strict';

const path = require('path');
const { startStaticServer } = require('./lib/static-server');
const http = require('http');
const fs = require('fs');
const { chromium } = require('playwright');

const REPO_ROOT = path.resolve(__dirname, '..');
const DIST_DIR = path.resolve(REPO_ROOT, process.argv[2] || 'dist');
const PORT = 8944; // one above verify_enterprise_homepage.js's 8943 to avoid collision if ever run together
const PAGE_URL = `http://127.0.0.1:${PORT}/index.html`;
const NAV_TIMEOUT_MS = 20_000;
const OWNED_PREFIXES = ['/js/', '/css/'];
const OWNED_EXACT = ['/index.html', '/_headers'];

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.json': 'application/json', '.txt': 'text/plain', '.ico': 'image/x-icon',
};

function isOwnedPath(pathname) {
  return OWNED_EXACT.includes(pathname) || OWNED_PREFIXES.some((p) => pathname.startsWith(p));
}

// Chromium-internal diagnostics that surface as console 'error' messages but
// aren't app bugs: generic failed-resource logging (redundant with the
// response-status check above for owned paths, and expected noise for every
// aborted cross-origin request below) and the well-known, benign
// frame-ancestors-via-meta warning (the real CSP is set via the _headers
// HTTP header; frame-ancestors in the <meta> tag is a defense-in-depth
// no-op the browser is correctly telling us it ignored).
const BENIGN_CONSOLE_PATTERNS = [
  /^Failed to load resource:/,
  /frame-ancestors' is ignored when delivered via a <meta> element/,
];
function isBenignConsoleMessage(text) {
  return BENIGN_CONSOLE_PATTERNS.some((re) => re.test(text));
}

const failures = [];
function fail(detail) { failures.push(detail); }

async function main() {
  if (!fs.existsSync(path.join(DIST_DIR, 'index.html'))) {
    console.error(`[FATAL] ${path.join(DIST_DIR, 'index.html')} does not exist -- nothing to smoke-test.`);
    process.exitCode = 1;
    return;
  }

  const server = await startStaticServer(DIST_DIR, PORT, MIME);
  let browser;
  try {
    browser = await chromium.launch();
    const context = await browser.newContext();
    const page = await context.newPage();
    page.setDefaultTimeout(NAV_TIMEOUT_MS);

    // Abort every non-local request instead of hitting the real network: the
    // production API, CDN stylesheets, and any third-party proxy the page
    // calls out to. Keeps the check hermetic (no dependency on third-party
    // uptime) and fast (no waiting out apiFetch's 12s per-call timeout), and
    // it exercises the app's own "API unreachable" fallback path -- see
    // header comment for why this is safe (no critical external <script>)
    // and what it already caught doing exactly this.
    await page.route('**/*', (route) => {
      const url = new URL(route.request().url());
      if (url.hostname === '127.0.0.1') return route.continue();
      return route.abort();
    });

    page.on('console', (msg) => {
      if (msg.type() === 'error' && !isBenignConsoleMessage(msg.text())) {
        fail(`console.error: ${msg.text()}`);
      }
    });
    page.on('pageerror', (err) => fail(`uncaught page error: ${err}`));
    page.on('response', (resp) => {
      const url = new URL(resp.url());
      if (url.hostname !== '127.0.0.1') return; // ignore any cross-origin/live-API request
      if (resp.status() >= 400 && isOwnedPath(url.pathname)) {
        fail(`HTTP ${resp.status()} on owned path ${url.pathname}`);
      }
    });

    try {
      await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
      // Bounded settle window for async init/render after the load event
      // (widget fetches, DOM population) -- deliberately not 'networkidle':
      // blocked/aborted requests can still trigger retry timers, and this
      // page polls periodically by design (REFRESH_INTERVAL_MS), so network
      // idle isn't a meaningful signal to wait for here.
      await page.waitForTimeout(3000);

      // js/feed-state.js's resolveFeedTerminalState() (index.html's GOC
      // loader) can legitimately resolve to a healthy state (LIVE/STALE/
      // EMPTY) even from its own "terminal failure" code path -- e.g. when
      // this job's fresh dist/ checkout has real local api/feed.json data
      // but the two absolute external fallback URLs this test deliberately
      // aborts (see the page.route() handler above) net-error. It still
      // logs its one-line diagnostic summary via console.error regardless
      // of which state that turned out to be. Rather than guess from the
      // log text, ask the app's own already-computed verdict
      // (window.__FEED_TERMINAL_STATE__.isTerminalFailure, set at the same
      // point the diagnostic line is logged) and drop that one diagnostic
      // from the failure list when the app itself says this wasn't a real
      // failure -- a genuine terminal failure (isTerminalFailure: true)
      // still fails this test exactly as before.
      const termState = await page.evaluate(() => window.__FEED_TERMINAL_STATE__ || null).catch(() => null);
      if (termState && termState.isTerminalFailure === false) {
        const goc = 'console.error: [GOC v201.0] Primary feed terminal state:';
        for (let i = failures.length - 1; i >= 0; i--) {
          if (failures[i].startsWith(goc)) failures.splice(i, 1);
        }
      }
    } catch (navErr) {
      fail(`page failed to load within ${NAV_TIMEOUT_MS}ms: ${navErr.message}`);
    }

    await context.close();
  } finally {
    if (browser) await browser.close();
    server.close();
  }

  console.log('='.repeat(64));
  if (failures.length) {
    console.log(`SMOKE TEST FAILED: ${failures.length} issue(s) found in ${PAGE_URL}`);
    for (const f of failures) console.log(`  - ${f}`);
    console.log('='.repeat(64));
    process.exitCode = 1;
  } else {
    console.log(`SMOKE TEST PASSED: dist/index.html rendered with no console/page errors and no 404s on js/**, css/**.`);
    console.log('='.repeat(64));
    process.exitCode = 0;
  }
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exitCode = 1;
});
