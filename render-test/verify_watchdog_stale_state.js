#!/usr/bin/env node
/**
 * SENTINEL APEX -- P0 2026-09-26: a STALE feed (9h, contract 6h) blanked the
 * homepage and Cyber Watchdog ("CRITICAL / HIGH: NOT AVAILABLE", empty Live
 * Threat Priority, empty Watchdog table) while still badging "SYNC: LIVE".
 *
 * Headless Chromium drives the shipped pages. /api/watchdog/brief is the REAL
 * buildWatchdogBrief() output (workers/intel-gateway/src/cyber-watchdog.js)
 * for a feed generated 9h earlier: 503 degraded + last_authoritative.
 *   stale (9h)   : hero Critical/High are numbers; Live Threat Priority and
 *                  the Watchdog table list the last authoritative items,
 *                  labelled NOT LIVE; freshness reads STALE; SYNC badge is
 *                  not LIVE even though /api/platform/stats says RECENT
 *   too old (49h): nothing is shown as current (NOT AVAILABLE, degraded
 *                  message) -- the 48h ceiling holds
 *   watchdog page: brief table captioned "not live", status NOT LIVE
 *   no page error, no injected markup, in every case
 *
 * Usage: PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers NODE_PATH="$(npm root -g)" \
 *          node render-test/verify_watchdog_stale_state.js [root]   (CI passes dist)
 */
'use strict';

const path = require('path');
const { pathToFileURL } = require('url');
const { startStaticServer } = require('./lib/static-server');
const { chromium } = require('playwright');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const REPO = path.join(__dirname, '..');
const PORT = 8796;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };
const XSS = '<img src=x onerror="window.__pwned=1">';

let failures = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : '  -- ' + detail}`);
  if (!ok) failures++;
}

function feed(generatedAt) {
  const items = [];
  for (let i = 0; i < 12; i++) {
    items.push({
      id: 'intel--stale' + i, title: (i === 0 ? XSS + ' ' : '') + 'CVE-2026-' + (1000 + i) + ' remote code execution in widget ' + i,
      severity: i < 3 ? 'CRITICAL' : i < 7 ? 'HIGH' : 'MEDIUM', source: 'GitHub Security Advisories',
      description: 'Vulnerability ' + i, published: generatedAt, timestamp: generatedAt, cve_ids: ['CVE-2026-' + (1000 + i)],
    });
  }
  return { schema_version: '1.0', generated_at: generatedAt, count: items.length, items };
}

async function scenario(browser, cw, ageHours, pagePath) {
  const nowMs = Date.now();
  const generatedAt = new Date(nowMs - ageHours * 3600e3).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const f = feed(generatedAt);
  const brief = cw.buildWatchdogBrief(f, { tier: 'FREE', nowMs, limit: 5 });
  const health = { freshness_status: 'STALE', feed_generated_at: generatedAt, feed_age_seconds: Math.round(ageHours * 3600), watch_store: 'ok', autonomous_evaluation: 'configured', platform_version: 'v201.0' };
  // Production shape (GET /api/platform/stats, 2026-09-26): {intel:{freshness:"RECENT",...}} at 9h.
  const stats = { intel: { total_advisories: 12, freshness: ageHours < 24 ? 'RECENT' : 'AGING', last_sync: generatedAt, freshness_age_seconds: Math.round(ageHours * 3600) }, api: {} };
  const context = await browser.newContext({ serviceWorkers: 'block', viewport: { width: 1366, height: 900 } });
  await context.route('**/*', (route) => {
    const u = new URL(route.request().url());
    const local = u.hostname === '127.0.0.1';
    if (!local && u.hostname !== 'intel.cyberdudebivash.com') return route.abort();
    const p = u.pathname.replace(/\/+$/, '') || '/';
    if (p === '/api/watchdog/brief') return route.fulfill({ status: brief.status, contentType: 'application/json', body: JSON.stringify(brief.body) });
    if (p === '/api/watchdog/health') return route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify(health) });
    if (p === '/api/platform/stats') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(stats) });
    // The authoritative manifest answers (with 9h-old content): the path that
    // used to badge SYNC: LIVE.
    if (p === '/api/feed.json' || p === '/api/v1/intel/latest.json') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(f) });
    if (p.startsWith('/api/') || !local) return route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"not_found"}' });
    return route.continue();
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(ORIGIN + pagePath, { waitUntil: 'load' });
  await page.waitForTimeout(3500);
  return { context, page, errors, brief };
}

const text = (page, id) => page.evaluate((i) => { const e = document.getElementById(i); return e ? e.textContent.replace(/\s+/g, ' ').trim() : '__MISSING__'; }, id);

(async () => {
  const cw = await import(pathToFileURL(path.join(REPO, 'workers/intel-gateway/src/cyber-watchdog.js')).href);
  const server = await startStaticServer(ROOT, PORT, MIME);
  const browser = await chromium.launch();
  try {
    // --- 9h stale: last authoritative intelligence shown, labelled ---------
    const s = await scenario(browser, cw, 9, '/index.html');
    check('fixture: real brief is 503 degraded with a last_authoritative block',
      s.brief.status === 503 && s.brief.body.items.length === 0 && s.brief.body.last_authoritative && s.brief.body.last_authoritative.live === false);
    const crit = await text(s.page, 'acs-critical');
    const high = await text(s.page, 'acs-high');
    check('hero Critical / High are numbers, not NOT AVAILABLE', /^\d+$/.test(crit) && /^\d+$/.test(high), `critical=${crit} high=${high}`);
    const items = await text(s.page, 'acs-items');
    check('Live Threat Priority lists last authoritative items labelled NOT LIVE', /NOT LIVE/.test(items) && /CVE-2026-100/.test(items), items.slice(0, 200));
    const fresh = await text(s.page, 'acs-fresh');
    check('freshness reads STALE', /STALE/.test(fresh), fresh);
    const cwdStatus = await text(s.page, 'cwd-status');
    const cwdRows = await s.page.evaluate(() => document.querySelectorAll('#cwd-rows tr').length);
    check('Watchdog panel: labelled NOT LIVE with rows', /NOT LIVE/.test(cwdStatus) && cwdRows > 0, `${cwdStatus} rows=${cwdRows}`);
    const sync = await text(s.page, 'sync-val');
    check('SYNC badge is not LIVE for a 9h (RECENT) feed', !/\bLIVE\b/.test(sync) && /STALE/.test(sync), sync);
    const safe = await s.page.evaluate(() => !window.__pwned && !document.querySelector('#acs-items img, #cwd-rows img'));
    check('server strings rendered as text', safe);
    check('stale: no page error', s.errors.length === 0, s.errors.join(' | '));
    await s.context.close();

    // --- 49h: beyond the ceiling, nothing is presented as current ----------
    const o = await scenario(browser, cw, 49, '/index.html');
    check('fixture: no last_authoritative beyond 48h', o.brief.body.last_authoritative === null);
    const oCrit = await text(o.page, 'acs-critical');
    const oItems = await text(o.page, 'acs-items');
    check('49h: Critical is NOT AVAILABLE and the degraded message is shown', /NOT AVAILABLE/.test(oCrit) && /INTELLIGENCE DEGRADED/.test(oItems), `${oCrit} | ${oItems.slice(0, 120)}`);
    check('49h: Watchdog table stays empty', (await o.page.evaluate(() => document.querySelectorAll('#cwd-rows tr').length)) === 0);
    check('49h: no page error', o.errors.length === 0, o.errors.join(' | '));
    await o.context.close();

    // --- Cyber Watchdog page ------------------------------------------------
    const w = await scenario(browser, cw, 9, '/cyber-watchdog.html#intelligence');
    await w.page.waitForTimeout(1000);
    const wStatus = await text(w.page, 'status');
    const wTable = await text(w.page, 'brieftable');
    check('watchdog page: status NOT LIVE, table of last authoritative items', /NOT LIVE/.test(wStatus) && /CVE-2026-100/.test(wTable), `${wStatus} | ${wTable.slice(0, 120)}`);
    check('watchdog page: no page error', w.errors.length === 0, w.errors.join(' | '));
    await w.context.close();
  } finally {
    await browser.close();
    server.close();
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll watchdog stale-state checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
