#!/usr/bin/env node
/**
 * SENTINEL APEX AI THREAT FEED -- homepage panel and Cyber Watchdog section.
 *
 * Headless Chromium drives the shipped pages. /api/ai-feed/live and
 * /api/ai-feed/item/:id answer with the REAL routeAiFeed() output
 * (workers/intel-gateway/src/ai-threat-feed.js) for the tier the request's
 * credential carries:
 *   homepage, FREE, fresh : rows locked, no source URL on the page, CTA is a
 *                           same-site checkout link with the runtime price,
 *                           click shows the lock + upgrade, never a timeline
 *   homepage, STALE 9h    : last authoritative rows labelled NOT LIVE
 *   homepage, 49h         : INTELLIGENCE DEGRADED, no rows
 *   Watchdog, ENTERPRISE  : click opens the item: https source link, timeline
 *   Watchdog, PRO         : detail without timeline, Enterprise upgrade prompt
 *   Watchdog, FREE        : Locked buttons, click -> Unlock with Pro Defense
 *   every case            : no page error, server strings rendered as text
 *
 * Usage: PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers NODE_PATH="$(npm root -g)" \
 *          node render-test/verify_ai_threat_feed.js [root]   (CI passes dist)
 */
'use strict';

const path = require('path');
const { pathToFileURL } = require('url');
const { startStaticServer } = require('./lib/static-server');
const { chromium } = require('playwright');

const ROOT = path.resolve(process.argv[2] || path.join(__dirname, '..'));
const REPO = path.join(__dirname, '..');
const PORT = 8797;
const ORIGIN = `http://127.0.0.1:${PORT}`;
const MIME = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };
const XSS = '<img src=x onerror="window.__pwned=1">';

let failures = 0;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : '  -- ' + detail}`);
  if (!ok) failures++;
}

const HUB = {
  id: 'CDB-AISH-FEED-2026-0926-01', title: XSS + ' MCP server exposes shell tool without auth',
  summary: 'Default config binds the shell tool publicly.', status: 'NEW_PUBLIC', tlp: 'CLEAR', severity: 'CRITICAL',
  source_url: 'https://example.org/mcp-advisory', source_name: 'Example Research', first_seen: '2026-09-26T01:00:00Z',
  hub_ruling: 'Disable the shell tool.', timeline: [{ at: '2026-09-25', event: 'vendor disclosed' }],
  triggers: ['mcp shell tool reachable'], actions: ['rotate MCP tokens'], exploitation: 'NOT_CONFIRMED',
};
const ADV = {
  id: 'intel--ai1', title: 'LiteLLM proxy SSRF reaches internal model endpoints', description: 'SSRF in the LiteLLM proxy.',
  severity: 'HIGH', source: 'GitHub Security Advisories', source_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
  published_at: '2026-09-26T02:00:00Z', processed_at: '2026-09-26T03:00:00Z', cve_ids: ['CVE-2026-11111'],
};

async function scenario(browser, ai, cw, { ageHours = 0.2, pagePath = '/index.html', tier = null, rawLive = null }) {
  const nowMs = Date.now();
  const generatedAt = new Date(nowMs - ageHours * 3600e3).toISOString().replace(/\.\d{3}Z$/, 'Z');
  const feed = { schema_version: '1.0', generated_at: generatedAt, count: 2, items: [ADV, { id: 'intel--x', title: 'Router overflow', severity: 'LOW', source_url: 'https://example.com/r' }] };
  const catalog = { items: [HUB] };
  const context = await browser.newContext({ serviceWorkers: 'block', viewport: { width: 1366, height: 900 } });
  if (tier) {
    await context.addInitScript((t) => {
      sessionStorage.setItem('apex_watchdog_session', JSON.stringify({ token: 'aa.bb.cc', expires_at: new Date(Date.now() + 600e3).toISOString(), tier: t, scopes: ['watchdog:read'] }));
    }, tier);
  }
  const seen = [];
  await context.route('**/*', async (route) => {
    const req = route.request();
    const u = new URL(req.url());
    const local = u.hostname === '127.0.0.1';
    if (!local && u.hostname !== 'intel.cyberdudebivash.com') return route.abort();
    const p = u.pathname.replace(/\/+$/, '') || '/';
    if (rawLive && p === '/api/ai-feed/live') return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(rawLive) });
    if (p.startsWith('/api/ai-feed/')) {
      const bearer = /Bearer /.test(req.headers()['authorization'] || '');
      seen.push({ path: p, bearer });
      const r = await ai.routeAiFeed({ path: p, method: req.method(), auth: { tier: bearer && tier ? tier : 'FREE' }, feed, nowMs, readCatalog: async () => catalog });
      return route.fulfill({ status: r.status, contentType: 'application/json', body: JSON.stringify(r.body) });
    }
    if (p === '/api/watchdog/brief') { const b = cw.buildWatchdogBrief(feed, { tier: 'FREE', nowMs, limit: 5 }); return route.fulfill({ status: b.status, contentType: 'application/json', body: JSON.stringify(b.body) }); }
    if (p.startsWith('/api/') || !local) return route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"not_found"}' });
    return route.continue();
  });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(ORIGIN + pagePath, { waitUntil: 'load' });
  await page.waitForTimeout(3000);
  return { context, page, errors, seen };
}

const text = (page, sel) => page.evaluate((s) => { const e = document.querySelector(s); return e ? e.textContent.replace(/\s+/g, ' ').trim() : '__MISSING__'; }, sel);
const safe = (page) => page.evaluate(() => !window.__pwned && !document.querySelector('#ai-threat-feed-dashboard img, #aifeed img'));

(async () => {
  const ai = await import(pathToFileURL(path.join(REPO, 'workers/intel-gateway/src/ai-threat-feed.js')).href);
  const cw = await import(pathToFileURL(path.join(REPO, 'workers/intel-gateway/src/cyber-watchdog.js')).href);
  const server = await startStaticServer(ROOT, PORT, MIME);
  const browser = await chromium.launch();
  try {
    // --- homepage, FREE, fresh ---------------------------------------------
    const f = await scenario(browser, ai, cw, {});
    const st = await text(f.page, '#aif-status');
    check('homepage: status LIVE / FRESH with counts', /LIVE/.test(st) && /FRESH/.test(st) && /AI items/.test(st), st);
    const rows = await f.page.evaluate(() => [...document.querySelectorAll('#aif-rows .aif-row')].map((b) => b.textContent));
    check('homepage: FREE rows listed and locked', rows.length >= 2 && rows.every((r) => r.includes('\u{1F512}')), JSON.stringify(rows).slice(0, 200));
    const html = await f.page.evaluate(() => document.getElementById('ai-threat-feed-dashboard').innerHTML);
    check('homepage: no source URL, ruling or timeline reaches a FREE page', !/example\.org\/mcp-advisory|github\.com\/advisories|Disable the shell tool|vendor disclosed|rotate MCP tokens/.test(html));
    const cta = await f.page.evaluate(() => { const a = document.getElementById('aif-cta'); return { href: a.getAttribute('href'), text: a.textContent }; });
    const pro = cw.planPrice('PRO');
    check('homepage: CTA is the same-site Pro checkout with the runtime price', cta.href === '/upgrade.html?plan=pro&feature=ai-threat-feed' && cta.text.includes('$' + pro.usd_monthly), JSON.stringify(cta));
    await f.page.click('#aif-rows .aif-row');
    const det = await text(f.page, '#aif-rows .aif-detail:not([hidden])');
    check('homepage: click shows the lock and an upgrade link', /Locked/.test(det) && /Unlock/.test(det), det);
    check('homepage: server strings rendered as text', await safe(f.page));
    check('homepage: no page error', f.errors.length === 0, f.errors.join(' | '));
    await f.context.close();

    // --- homepage, STALE / too old -----------------------------------------
    const s = await scenario(browser, ai, cw, { ageHours: 9 });
    const sst = await text(s.page, '#aif-status');
    const srows = await s.page.evaluate(() => document.querySelectorAll('#aif-rows .aif-row').length);
    check('homepage 9h: NOT LIVE label with last authoritative rows', /NOT LIVE/.test(sst) && /STALE/.test(sst) && srows > 0, `${sst} rows=${srows}`);
    check('homepage 9h: no page error', s.errors.length === 0, s.errors.join(' | '));
    await s.context.close();
    const o = await scenario(browser, ai, cw, { ageHours: 49 });
    const ost = await text(o.page, '#aif-status');
    const orows = await o.page.evaluate(() => document.querySelectorAll('#aif-rows .aif-row').length);
    check('homepage 49h: INTELLIGENCE DEGRADED, no rows', /INTELLIGENCE DEGRADED/.test(ost) && orows === 0, `${ost} rows=${orows}`);
    await o.context.close();

    // --- Cyber Watchdog page, ENTERPRISE -----------------------------------
    const e = await scenario(browser, ai, cw, { pagePath: '/cyber-watchdog.html#intelligence', tier: 'ENTERPRISE' });
    await e.page.waitForSelector('#aif-list button', { timeout: 5000 }).catch(() => {});
    const est = await text(e.page, '#aif-status');
    check('watchdog ENTERPRISE: live list with plan name', /LIVE/.test(est) && /Enterprise SOC/.test(est), est);
    check('watchdog: session token sent to /api/ai-feed/live', e.seen.some((x) => x.path === '/api/ai-feed/live' && x.bearer));
    await e.page.click(`#aif-list button[data-aif-item="${HUB.id}"]`);
    await e.page.waitForTimeout(800);
    const ed = await text(e.page, '#aif-detail');
    const link = await e.page.evaluate(() => { const a = document.querySelector('#aif-detail a[target="_blank"]'); return a ? { href: a.getAttribute('href'), rel: a.getAttribute('rel') } : null; });
    check('watchdog ENTERPRISE: item opens with timeline, triggers and actions', /Timeline/.test(ed) && /vendor disclosed/.test(ed) && /rotate MCP tokens/.test(ed) && /Disable the shell tool/.test(ed), ed.slice(0, 200));
    check('watchdog: source link is the https source, noopener', link && link.href === HUB.source_url && /noopener/.test(link.rel), JSON.stringify(link));
    check('watchdog ENTERPRISE: server strings rendered as text', await safe(e.page));
    check('watchdog ENTERPRISE: no page error', e.errors.length === 0, e.errors.join(' | '));
    await e.context.close();

    // --- Cyber Watchdog page, PRO ------------------------------------------
    const p = await scenario(browser, ai, cw, { pagePath: '/cyber-watchdog.html#intelligence', tier: 'PRO' });
    await p.page.waitForSelector('#aif-list button', { timeout: 5000 }).catch(() => {});
    await p.page.click(`#aif-list button[data-aif-item="${HUB.id}"]`);
    await p.page.waitForTimeout(800);
    const pd = await text(p.page, '#aif-detail');
    check('watchdog PRO: detail with source and ruling, timeline replaced by Enterprise upgrade', /Disable the shell tool/.test(pd) && /included with Enterprise SOC/.test(pd) && !/vendor disclosed/.test(pd) && !/rotate MCP tokens/.test(pd), pd.slice(0, 200));
    const plist = await text(p.page, '#aif-list');
    check('watchdog PRO: upgrade offer names Enterprise and its runtime price', /Enterprise SOC/.test(plist) && plist.includes('$' + cw.planPrice('ENTERPRISE').usd_monthly), plist.slice(-200));
    check('watchdog PRO: no page error', p.errors.length === 0, p.errors.join(' | '));
    await p.context.close();

    // --- defense in depth: markup the server would have stripped ------------
    // routeAiFeed() removes < and > from every string; these responses bypass
    // it (a misbehaving upstream) to prove both pages still render text only.
    const raw = { freshness_status: 'FRESH', feed_generated_at: new Date().toISOString(), count: 1, total_available: 1, tier: 'FREE',
      upgrade: { plan: 'PRO', price_label: XSS, checkout: 'javascript:alert(1)' },
      items: [{ id: XSS, title: XSS, severity: XSS, first_seen: XSS, source_name: XSS, locked: true, checkout: '//evil.example/x' }] };
    for (const pagePath of ['/index.html', '/cyber-watchdog.html#intelligence']) {
      const x = await scenario(browser, ai, cw, { pagePath, rawLive: raw });
      await x.page.waitForTimeout(500);
      await x.page.click(pagePath === '/index.html' ? '#aif-rows .aif-row' : '#aif-list button').catch(() => {});
      await x.page.waitForTimeout(300);
      const bad = await x.page.evaluate(() => ({
        pwned: !!window.__pwned,
        img: !!document.querySelector('#ai-threat-feed-dashboard img, #aifeed img'),
        hrefs: [...document.querySelectorAll('#ai-threat-feed-dashboard a, #aifeed a')].map((a) => a.getAttribute('href')),
      }));
      check(`${pagePath}: raw markup from the API is rendered as text`, !bad.pwned && !bad.img, JSON.stringify(bad));
      check(`${pagePath}: javascript: / protocol-relative checkout links never used`, bad.hrefs.every((h) => h && !/^javascript:/i.test(h) && !h.startsWith('//')), JSON.stringify(bad.hrefs));
      check(`${pagePath}: no page error (raw)`, x.errors.length === 0, x.errors.join(' | '));
      await x.context.close();
    }

    // --- Cyber Watchdog page, signed out (FREE) ----------------------------
    const w = await scenario(browser, ai, cw, { pagePath: '/cyber-watchdog.html#intelligence' });
    await w.page.waitForSelector('#aif-list button', { timeout: 5000 }).catch(() => {});
    const wbtn = await w.page.evaluate(() => [...document.querySelectorAll('#aif-list button')].map((b) => b.textContent));
    check('watchdog FREE: every row is Locked', wbtn.length > 0 && wbtn.every((t) => t === 'Locked'), JSON.stringify(wbtn));
    await w.page.click('#aif-list button');
    const wd = await text(w.page, '#aif-detail');
    const wlink = await w.page.evaluate(() => { const a = document.querySelector('#aif-detail a'); return a ? a.getAttribute('href') : null; });
    check('watchdog FREE: click shows Unlock with Pro Defense, no item request', /Unlock with Pro Defense/.test(wd) && wlink === '/upgrade.html?plan=pro&feature=ai-threat-feed' && !w.seen.some((x) => x.path.startsWith('/api/ai-feed/item/')), `${wd} ${wlink}`);
    check('watchdog FREE: no page error', w.errors.length === 0, w.errors.join(' | '));
    await w.context.close();
  } finally {
    await browser.close();
    server.close();
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : '\nAll AI Threat Feed render checks passed');
  process.exit(failures ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
