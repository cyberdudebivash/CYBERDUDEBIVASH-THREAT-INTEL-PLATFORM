#!/usr/bin/env node
/**
 * SENTINEL APEX -- EICC Panel Zero-Fabrication State Verification
 * ====================================================================
 * Real-browser (headless Chromium) verification of the Stage 2 fixes to
 * index.html's Enterprise Intelligence Command Center (EICC) panel
 * pipeline (fetchAndRender / buildTicker / fillMetrics / buildFeedPreview /
 * fillAIPredictions).
 *
 * Root cause this addresses: the EICC panel's fetch cascade had two
 * distinct classes of zero-fabrication defect, found auditing the same
 * pipeline that PR #314 (tranche 1) already fixed one instance of in
 * buildHeatmap() (a fabricated-random-value fallback):
 *
 *   1. "Stuck loading" -- buildTicker() and buildFeedPreview() only ever
 *      updated the DOM inside the fetch cascade's success path; on total
 *      cascade exhaustion (both EICC_DATA_URLS failing), nothing called
 *      them at all, leaving the static "Syncing live threat feed..." /
 *      "Loading threat feed..." markup on screen indefinitely -- reads as
 *      "still working on it" when the true state is "this failed".
 *
 *   2. Actual fabrication -- fillAIPredictions() unconditionally showed
 *      "ONLINE" and, whenever the AI tracker fetch failed OR returned no
 *      predictions, rendered 4 hardcoded fake prediction records
 *      (plausible titles, invented probabilities/severities) indistinguishable
 *      from real model output -- a direct violation of "never manufacture
 *      an AI conclusion". fillMetrics() separately fell back to a hardcoded
 *      "74" for the Active Feeds counter and the literal string "LIVE" for
 *      Last Sync whenever the feed response didn't carry those fields --
 *      very likely showing on every real page load, since nothing in this
 *      codebase's real /api/feed.json contract guarantees those fields.
 *
 * The fix routes the cascade through js/apex-data-plane.js (fetch with
 * explicit failure classification + a request-supersession guard) and adds
 * an explicit terminal "unavailable" state to every widget, while removing
 * both fabricated fallback values. This script proves both classes of fix
 * directly against the real page, not just the extracted logic (see
 * js/__tests__/apex-data-plane.test.js for the shared module's own unit
 * tests).
 *
 * STAGE 3 ADDITION: Scenario 4 (rendering security) now also asserts the
 * main threat-grid ticker (#threat-ticker-inner / #cdb-ticker-text) escapes
 * the same malicious title, and that zero uncaught errors occur anywhere on
 * the page -- tightened from Stage 2's KNOWN_PREEXISTING_MAIN_GRID_ERROR
 * carve-out now that renderTicker()/renderMapTicker() are fixed too.
 *
 * Same pattern as this directory's other verify_*.js scripts -- local
 * static server + Playwright, hermetic (non-local requests aborted),
 * record()/exitCode convention.
 *
 * Usage:
 *   node render-test/verify_eicc_zero_fabrication_states.js [dist-dir]
 *   (defaults to "dist" at the repo root)
 *
 * Exit code 0 = all checks passed. Exit code 1 = at least one failed.
 */
'use strict';

const path = require('path');
const http = require('http');
const fs = require('fs');
const { chromium } = require('playwright');

const REPO_ROOT = path.resolve(__dirname, '..');
const ROOT_DIR = path.resolve(REPO_ROOT, process.argv[2] || 'dist');
const PORT = 8975; // next free port after this dir's other scripts (8943/8944/8958/8960/8974)
const PAGE_URL = `http://127.0.0.1:${PORT}/index.html`;
const NAV_TIMEOUT_MS = 20_000;

// Server behavior is switched per-scenario via these module-level flags,
// each test navigates fresh so there is no cross-scenario state leakage.
let feedMode = 'fail';   // 'fail' | 'incomplete' | 'ok'
let aiMode = 'fail';     // 'fail' | 'ok' | 'xss' | 'escalation'

const REAL_ITEM = { id: 'intel--real-1', title: 'REGRESSION-TEST-CANARY-ITEM', severity: 'CRITICAL', risk_score: 9.1, source_country: 'US' };
const XSS_PAYLOAD = '<img src=x onerror="window.__xssFired=true">';

const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };

function startServer(root) {
  const server = http.createServer((req, res) => {
    let urlPath = decodeURIComponent(req.url.split('?')[0].split('#')[0]);

    if (urlPath === '/api/feed.json') {
      if (feedMode === 'fail') { res.writeHead(500); res.end('server error'); return; }
      if (feedMode === 'incomplete') {
        // Valid response, real items -- but deliberately no feed_count,
        // source_count, last_updated, or generated_at, so a customer with
        // this exact response shape must never see a fabricated "74" or "LIVE".
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ items: [REAL_ITEM] }));
        return;
      }
      if (feedMode === 'xss') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ items: [{ id: 'x1', title: XSS_PAYLOAD, severity: 'CRITICAL', risk_score: 9.9 }], feed_count: 1, last_updated: new Date().toISOString() }));
        return;
      }
      if (feedMode === 'geo-mixed') {
        // STAGE 6 FIX regression guard: renderMapTicker() used to pair every
        // item with a canned GEO_PAIRS entry selected by ticker position, so
        // a real advisory with zero attribution (the real current feed's
        // actual state -- 0/109 items carry source_country/actor_country)
        // still rendered a specific, invented country pair. One item here
        // has no geo field at all; the other has a real, distinct
        // source_country, proving the fix renders real attribution and
        // nothing else -- never a fabricated placeholder either way.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          items: [
            { id: 'geo-none', title: 'REGRESSION-TEST-NO-ATTRIBUTION-ITEM', severity: 'CRITICAL', risk_score: 9.5 },
            { id: 'geo-real', title: 'REGRESSION-TEST-REAL-ATTRIBUTION-ITEM', severity: 'HIGH', risk_score: 7.2, source_country: 'DE' },
          ],
          feed_count: 2, last_updated: new Date().toISOString(),
        }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      // FIX (P0, 2026-09-10 follow-up): this fixture used to lean on
      // `feed_count: 42` to populate the Active Feeds metric, but
      // index.html's set('eicc-m-feeds', feeds) (see its own "P0 FIX
      // (2026-09-10)" comment) stopped reading feed_count/source_count
      // entirely in favor of deriving the count from distinct `feed_source`
      // values across real items -- confirmed live (not assumed) not to
      // exist on the real API response shape. This fixture's single
      // REAL_ITEM carries no feed_source, so the derived count silently
      // fell to the honest '—' the day that production change landed,
      // failing this assertion (caught via pages-fast-publish's pre-deploy
      // gate) and blocking every frontend deploy since -- not a fabrication
      // regression itself, but exactly the kind of drift Section 4's own
      // stale-fixture warning (aiMode: 'escalation' above) already exists to
      // catch for the AI side. Two items with two distinct feed_source
      // domains exercise the real derivation this metric now performs.
      res.end(JSON.stringify({
        items: [
          REAL_ITEM,
          { id: 'intel--real-2', title: 'REGRESSION-TEST-CANARY-ITEM-2', severity: 'HIGH', risk_score: 6.4, feed_source: 'https://example-regression-source-a.test/feed' },
          { id: 'intel--real-3', title: 'REGRESSION-TEST-CANARY-ITEM-3', severity: 'HIGH', risk_score: 6.1, feed_source: 'https://example-regression-source-b.test/feed' },
        ],
        last_updated: new Date().toISOString(),
      }));
      return;
    }

    if (urlPath === '/api/ai/tracker.json') {
      if (aiMode === 'fail') { res.writeHead(500); res.end('server error'); return; }
      if (aiMode === 'xss') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ predictions: [{ threat: XSS_PAYLOAD, probability: 0.5, severity: 'HIGH' }] }));
        return;
      }
      if (aiMode === 'escalation') {
        // STAGE 5 FIX regression guard: the real production api/ai/tracker.json
        // shape (confirmed against a live capture) has no top-level `predictions`
        // and no `engine_alpha.top_predicted_threats` -- only `escalation_tracker`,
        // a flat list of {title, risk_score, priority, ...}. fillAIPredictions()
        // silently rendered the honest-but-permanently-empty "AI PREDICTIONS
        // UNAVAILABLE" state against this exact shape for as long as the AI
        // pipeline has produced it, because this file's other two aiMode
        // fixtures ('ok'/'xss') mock the OLD `predictions` shape, which the
        // real generator no longer emits -- masking the drift entirely.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ escalation_tracker: [{ id: 'ESC-001', title: 'REGRESSION-TEST-ESCALATION-PREDICTION', risk_score: 9.4, priority: 'P1' }] }));
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ predictions: [{ threat: 'REGRESSION-TEST-REAL-PREDICTION', probability: 0.5, severity: 'HIGH' }] }));
      return;
    }

    if (urlPath.endsWith('/')) urlPath += 'index.html';
    const filePath = path.join(root, urlPath);
    if (!filePath.startsWith(root)) { res.writeHead(403); res.end(); return; }
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      const ext = path.extname(filePath);
      res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
      res.end(data);
    });
  });
  return new Promise((resolve) => server.listen(PORT, '127.0.0.1', () => resolve(server)));
}

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`[${pass ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
}

async function eiccState(page) {
  return page.evaluate(() => {
    const text = (id) => { const el = document.getElementById(id); return el ? el.textContent : null; };
    const html = (id) => { const el = document.getElementById(id); return el ? el.innerHTML : null; };
    return {
      tickerText: html('eicc-ticker-inner'),
      feedPreviewHtml: html('eicc-feed-preview'),
      heatmapHtml: html('eicc-heatmap'),
      metricsFeeds: text('eicc-m-feeds'),
      metricsSync: text('eicc-m-sync'),
      metricsTotal: text('eicc-m-total'),
      aiStatusHtml: html('eicc-soc-ai-status'),
      aiPredictionsHtml: html('eicc-ai-predictions'),
      socStatusHtml: html('eicc-soc-status'),
      mapTickerHtml: html('cdb-ticker-text'),
      atkCountText: text('cdb-atk-count'),
    };
  });
}

async function freshPage(browser) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  page.setDefaultTimeout(NAV_TIMEOUT_MS);
  const pageErrors = [];
  page.on('pageerror', (err) => pageErrors.push(String((err && err.message) || err)));
  await page.route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (url.hostname === '127.0.0.1') return route.continue();
    return route.abort();
  });
  return { context, page, pageErrors };
}

async function main() {
  if (!fs.existsSync(path.join(ROOT_DIR, 'index.html'))) {
    console.error(`[FATAL] ${ROOT_DIR} is missing index.html -- nothing to test.`);
    process.exitCode = 1;
    return;
  }

  const server = await startServer(ROOT_DIR);
  let browser;
  try {
    browser = await chromium.launch();

    // ── Scenario 1: total feed + AI failure -- must reach honest
    // "unavailable" states everywhere, never fabricate, never stay stuck
    // on the loading shimmer. ──────────────────────────────────────────
    feedMode = 'fail'; aiMode = 'fail';
    {
      const { context, page, pageErrors } = await freshPage(browser);
      await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
      await page.waitForTimeout(2500);
      const s = await eiccState(page);

      record('Total feed failure: ticker reaches an explicit unavailable state, not stuck on "Syncing..."',
        !!s.tickerText && !/syncing live threat feed/i.test(s.tickerText),
        JSON.stringify(s.tickerText));
      record('Total feed failure: feed preview reaches an explicit unavailable state, not stuck on "Loading..."',
        !!s.feedPreviewHtml && !/loading threat feed/i.test(s.feedPreviewHtml),
        JSON.stringify(s.feedPreviewHtml));
      record('Total feed failure: heatmap reaches an explicit unavailable state, not stuck on "Loading region data..."',
        !!s.heatmapHtml && !/loading region data/i.test(s.heatmapHtml),
        JSON.stringify(s.heatmapHtml));
      // 2026-09-24 (P0 dashboard data contract): unknown is now the explicit
      // "N/A" (a permanent "—" read as still loading), still never a zero.
      record('Total feed failure: metrics show explicit N/A, never a fabricated/zeroed value',
        s.metricsTotal === 'N/A' && s.metricsFeeds === 'N/A' && s.metricsSync === 'N/A',
        JSON.stringify({ total: s.metricsTotal, feeds: s.metricsFeeds, sync: s.metricsSync }));
      record('Total AI failure: status shows UNAVAILABLE, never a false ONLINE claim',
        !!s.aiStatusHtml && /unavailable/i.test(s.aiStatusHtml) && !/online/i.test(s.aiStatusHtml),
        JSON.stringify(s.aiStatusHtml));
      record('Total AI failure: zero fabricated prediction records rendered (none of the 4 hardcoded titles appear)',
        !!s.aiPredictionsHtml && !/ransomware-as-a-service escalation|zero-day exploit broker|state-sponsored supply chain|ai-assisted phishing/i.test(s.aiPredictionsHtml),
        JSON.stringify(s.aiPredictionsHtml));
      record('Zero uncaught JS errors on total-failure scenario', pageErrors.length === 0, pageErrors.join(' | '));

      await context.close();
    }

    // ── Scenario 2: feed succeeds but omits feed_count/source_count/
    // last_updated/generated_at -- must show honest "—", never the old
    // hardcoded "74" or the false "LIVE" claim. ────────────────────────
    feedMode = 'incomplete'; aiMode = 'fail';
    {
      const { context, page, pageErrors } = await freshPage(browser);
      await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
      await page.waitForTimeout(2500);
      const s = await eiccState(page);

      record('Incomplete-but-valid feed response: source count is N/A (unmeasured), never the old hardcoded "74" or a false 0',
        s.metricsFeeds === 'N/A',
        JSON.stringify(s.metricsFeeds));
      record('Incomplete-but-valid feed response: Last Sync shows N/A, never falsely claims "LIVE" with no timestamp',
        s.metricsSync === 'N/A',
        JSON.stringify(s.metricsSync));
      record('Incomplete-but-valid feed response: ticker still renders the real item (proves this is not a blanket failure state)',
        !!s.tickerText && /REGRESSION-TEST-CANARY-ITEM/.test(s.tickerText),
        JSON.stringify(s.tickerText));
      record('Zero uncaught JS errors on incomplete-response scenario', pageErrors.length === 0, pageErrors.join(' | '));

      await context.close();
    }

    // ── Scenario 3: everything succeeds -- proves the fixes did not
    // regress the honest-success path (real data renders normally). ────
    feedMode = 'ok'; aiMode = 'ok';
    {
      const { context, page, pageErrors } = await freshPage(browser);
      await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
      await page.waitForTimeout(2500);
      const s = await eiccState(page);

      record('Full success: ticker renders the real item',
        !!s.tickerText && /REGRESSION-TEST-CANARY-ITEM/.test(s.tickerText), JSON.stringify(s.tickerText));
      record('Full success: Active Feeds shows the real measured value (2 distinct feed_source domains), not "—" or "74"',
        s.metricsFeeds === '2', JSON.stringify(s.metricsFeeds));
      record('Full success: AI status shows ONLINE with a real retrieved prediction, not the old hardcoded set',
        !!s.aiStatusHtml && /online/i.test(s.aiStatusHtml) &&
        !!s.aiPredictionsHtml && /REGRESSION-TEST-REAL-PREDICTION/.test(s.aiPredictionsHtml) &&
        !/ransomware-as-a-service escalation/i.test(s.aiPredictionsHtml),
        JSON.stringify({ status: s.aiStatusHtml, preds: s.aiPredictionsHtml }));
      record('Zero uncaught JS errors on full-success scenario', pageErrors.length === 0, pageErrors.join(' | '));
      // STAGE 6 FIX regression guard: the SOC status panel's 5 static rows
      // (all but AI ENGINE) used to hardcode "● ONLINE"/"● ACTIVE" with no
      // backing JS writer anywhere -- claiming real-time integration health
      // no runtime signal ever produced. Now labeled as supported platform
      // capabilities instead.
      record('SOC status panel labels its 5 static capability rows as SUPPORTED, not a fabricated live status',
        !!s.socStatusHtml && (s.socStatusHtml.match(/SUPPORTED/g) || []).length === 5,
        JSON.stringify(s.socStatusHtml));

      await context.close();
    }

    // ── Scenario 4: rendering security -- a malicious title/threat string
    // in otherwise-real feed/AI data must render as inert escaped text, not
    // execute (Section 14: treat report titles / AI output as untrusted
    // input). buildFeedPreview's `title` and fillAIPredictions' `name` both
    // interpolated into innerHTML unescaped before this fix. ─────────────
    feedMode = 'xss'; aiMode = 'xss';
    {
      const { context, page, pageErrors } = await freshPage(browser);
      await page.addInitScript(() => { window.__xssFired = false; });
      await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
      await page.waitForTimeout(2500);
      const s = await eiccState(page);
      const xssFired = await page.evaluate(() => window.__xssFired === true);

      record('Malicious feed-preview title does not execute (onerror handler never fires)',
        !xssFired, `__xssFired=${xssFired}`);
      record('Malicious feed-preview title renders as escaped text, not a raw <img> tag',
        !!s.feedPreviewHtml && s.feedPreviewHtml.includes('&lt;img') && !/<img[^&]/i.test(s.feedPreviewHtml),
        JSON.stringify(s.feedPreviewHtml));
      record('Malicious AI-prediction threat name renders as escaped text, not a raw <img> tag',
        !!s.aiPredictionsHtml && s.aiPredictionsHtml.includes('&lt;img') && !/<img[^&]/i.test(s.aiPredictionsHtml),
        JSON.stringify(s.aiPredictionsHtml));

      // STAGE 3 FIX (was a documented, tolerated KNOWN_PREEXISTING_MAIN_GRID_ERROR
      // carve-out here through Stage 2): the same malicious title, via the
      // same shared api/feed.json response, also reaches the separate main
      // threat-grid pipeline (loadGOCIntel() -> renderTicker()/
      // renderMapTicker()) -- out of Stage 2's scope, root-caused and fixed
      // in Stage 3. renderTicker()'s `id` and renderMapTicker()'s `label`
      // interpolated the raw title (only run through cleanText(), which
      // fixes mojibake/control chars but does not HTML-escape) directly
      // into an innerHTML target, producing ~20 "Invalid or unexpected
      // token" errors (a raw <img onerror=...> element whose broken
      // attribute boundary the browser fails to compile at fire-time) --
      // reproduced and confirmed via a standalone harness before the fix.
      // Both sites now reuse the same _cdbEsc() helper already used
      // correctly elsewhere in this file. This carve-out is intentionally
      // removed rather than kept permissive: leaving it in place after the
      // fix would silently mask a future regression of the exact same
      // class, which the zero-fabrication mandate's "never weaken tests"
      // rule specifically warns against.
      const mainGridTickerHtml = await page.evaluate(() => {
        const t = document.getElementById('threat-ticker-inner');
        const m = document.getElementById('cdb-ticker-text');
        return { ticker: t ? t.innerHTML : null, mapTicker: m ? m.innerHTML : null };
      });
      record('Main-grid threat ticker (#threat-ticker-inner) renders the malicious title as escaped text, not a raw <img> tag',
        !!mainGridTickerHtml.ticker && mainGridTickerHtml.ticker.includes('&lt;img') && !/<img[^&]/i.test(mainGridTickerHtml.ticker),
        JSON.stringify(mainGridTickerHtml.ticker));
      // STAGE 3 FIX (review finding): the original `!mapTicker || (...)`
      // form let a missing #cdb-ticker-text element (e.g. a future
      // regression that stops renderMapTicker() from running at all)
      // vacuously pass this check instead of failing it. Require the
      // element to actually be present before checking its content.
      record('Main-grid map ticker (#cdb-ticker-text) renders the malicious title as escaped text, not a raw <img> tag',
        !!mainGridTickerHtml.mapTicker && mainGridTickerHtml.mapTicker.includes('&lt;img') && !/<img[^&]/i.test(mainGridTickerHtml.mapTicker),
        JSON.stringify(mainGridTickerHtml.mapTicker));
      record('No uncaught JS errors anywhere on the page from the malicious title (main-grid parse-break class is now fixed, not just tolerated)',
        pageErrors.length === 0, pageErrors.join(' | '));

      await context.close();
    }

    // ── Scenario 5: real production AI-tracker schema (escalation_tracker
    // only, no predictions/top_predicted_threats) -- proves the Stage 5 fix
    // renders real current model output instead of silently reaching the
    // honest-but-wrong "unavailable" state on a contract this widget was
    // never updated to match. ──────────────────────────────────────────
    feedMode = 'ok'; aiMode = 'escalation';
    {
      const { context, page, pageErrors } = await freshPage(browser);
      await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
      await page.waitForTimeout(2500);
      const s = await eiccState(page);

      record('Real escalation_tracker-shaped AI response renders ONLINE, not the permanent UNAVAILABLE state',
        !!s.aiStatusHtml && /ONLINE/.test(s.aiStatusHtml) && !/UNAVAILABLE/.test(s.aiStatusHtml),
        JSON.stringify(s.aiStatusHtml));
      record('Real escalation_tracker prediction title renders in the AI predictions panel',
        !!s.aiPredictionsHtml && s.aiPredictionsHtml.includes('REGRESSION-TEST-ESCALATION-PREDICTION'),
        JSON.stringify(s.aiPredictionsHtml));
      // A 0-10 risk score is not a probability: shown as "RISK 9.4/10",
      // never as a "94%" label.
      record('escalation_tracker risk_score 9.4/10 is shown as a risk score, never as a 94% probability',
        !!s.aiPredictionsHtml && s.aiPredictionsHtml.includes('RISK 9.4/10') && !/>[^<]*94%[^<]*</.test(s.aiPredictionsHtml),
        JSON.stringify(s.aiPredictionsHtml));
      record('escalation_tracker priority P1 maps to CRITICAL severity color',
        !!s.aiPredictionsHtml && (s.aiPredictionsHtml.includes('#ef4444') || s.aiPredictionsHtml.includes('rgb(239, 68, 68)')),
        JSON.stringify(s.aiPredictionsHtml));
      record('Zero uncaught JS errors on the real-schema AI response',
        pageErrors.length === 0, pageErrors.join(' | '));

      await context.close();
    }

    // ── Scenario 6: map ticker geo attribution + advisory counter --
    // proves the Stage 6 fix renders only real, per-item geo attribution
    // (never a canned/rotated placeholder) and a real advisory count
    // (never a report-catalog-size number dressed up as "attacks today").
    // ──────────────────────────────────────────────────────────────────
    feedMode = 'geo-mixed'; aiMode = 'fail';
    {
      const { context, page, pageErrors } = await freshPage(browser);
      await page.goto(PAGE_URL, { waitUntil: 'load', timeout: NAV_TIMEOUT_MS });
      await page.waitForTimeout(2500);
      const s = await eiccState(page);

      record('Item with no source_country/actor_country/geo-tag renders its severity with no invented country prefix',
        !!s.mapTickerHtml && s.mapTickerHtml.includes('>CRITICAL</span>'),
        JSON.stringify(s.mapTickerHtml));
      record('Item with a real source_country renders exactly that code, not a canned pair',
        !!s.mapTickerHtml && s.mapTickerHtml.includes('>DE HIGH</span>'),
        JSON.stringify(s.mapTickerHtml));
      record('None of the old canned GEO_PAIRS codes appear anywhere in the ticker',
        !!s.mapTickerHtml && !/RU→US|CN→JP|IR→IL|KP→KR|RU→DE|CN→AU|US→CN|IR→SA|RU→UA|CN→IN/.test(s.mapTickerHtml),
        JSON.stringify(s.mapTickerHtml));
      record('Advisory counter reflects the real item count (2), not a report-catalog-size or synthetic value',
        s.atkCountText === '2',
        JSON.stringify(s.atkCountText));
      record('Zero uncaught JS errors on the geo-mixed scenario', pageErrors.length === 0, pageErrors.join(' | '));

      await context.close();
    }
  } finally {
    if (browser) await browser.close();
    server.close();
  }

  const failed = results.filter((r) => !r.pass);
  console.log('='.repeat(64));
  console.log(`SUMMARY: ${results.length - failed.length}/${results.length} checks passed`);
  console.log('='.repeat(64));
  if (failed.length) {
    console.log('FAILED CHECKS:');
    for (const f of failed) console.log(`  - ${f.name}${f.detail ? ': ' + f.detail : ''}`);
    process.exitCode = 1;
  } else {
    process.exitCode = 0;
  }
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exitCode = 1;
});
