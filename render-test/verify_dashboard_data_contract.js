#!/usr/bin/env node
/**
 * SENTINEL APEX -- customer dashboard data contract, real-browser test.
 *
 * P0 (2026-09-24). Headless Chromium against the local homepage with every
 * /api/* route answered by fixtures. The Worker-derived fixtures
 * (/campaigns, /ransomware) are produced by the real Worker module
 * (workers/intel-gateway/src/dashboard-contract.js) from the same feed the
 * page loads, so frontend and backend are checked against one generation.
 *
 * Scenarios:
 *   canonical     production-shaped feed with ATT&CK evidence and a campaign
 *                 (desktop 1440, laptop 1280, mobile 390) + one refresh cycle
 *   zero-evidence no geo, no ransomware, no campaign, no ATT&CK evidence
 *   stale         /api/health says stale: INTEL DEGRADED, threat level STALE
 *   unavailable   /api/feed.json fails: explicit unavailable, never "empty"
 *   xss           hostile titles/sources/countries/actors: nothing executes
 *
 * Usage: NODE_PATH="$(npm root -g)" node render-test/verify_dashboard_data_contract.js [rootDir]
 * Exit 0 = all checks passed.
 */
'use strict';

const path = require('path');
const { pathToFileURL } = require('url');
const { startStaticServer } = require('./lib/static-server');
const { chromium } = require('playwright');

const REPO_ROOT = path.resolve(__dirname, '..');
const ROOT = path.resolve(process.argv[2] || REPO_ROOT);
const PORT = 8962;
const PAGE_URL = `http://127.0.0.1:${PORT}/index.html`;
const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.json': 'application/json', '.ico': 'image/x-icon', '.txt': 'text/plain',
};
const VIEWPORTS = { desktop: { width: 1440, height: 900 }, laptop: { width: 1280, height: 800 }, mobile: { width: 390, height: 844 } };

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  console.log(`[${pass ? 'PASS' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
}

const GROUPS = [{ name: 'LockBit 3.0', sector: 'Healthcare' }, { name: 'Akira', sector: 'SMB' }, { name: 'Cl0p', sector: 'Government' }];
const XSS = '<img src=x onerror="window.__pwned=1">';
const XSS2 = '"><svg/onload=window.__pwned=2>';

function canonicalItems() {
  const items = [];
  const tactic = [
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
    { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
    { id: 'T1539', name: 'Steal Web Session Cookie', tactic: 'Credential Access' },
  ];
  for (let i = 0; i < 44; i++) {
    items.push({
      id: 'intel--c' + i, title: 'Canonical advisory ' + i + ' (CVE-2026-' + (1000 + i) + ')',
      severity: i < 11 ? 'CRITICAL' : i < 25 ? 'HIGH' : 'MEDIUM', risk_score: i < 11 ? 9.1 : 6.2,
      cvss_score: i < 11 ? 9.8 : 7.0, kev: i < 4, kev_present: i < 4, ioc_count: i % 4 === 0 ? 3 : 0, iocs: [],
      feed_source: ['https://vulners.com/rss.xml', 'https://www.bleepingcomputer.com/feed/', 'https://github.com/advisories'][i % 3],
      source: ['Vulners', 'BleepingComputer', 'GitHub Security Advisory'][i % 3], tags: i % 2 ? ['T1190'] : [],
      mitre_tactics: i < 30 ? [tactic[i % 3]] : [], published_at: '2026-09-24T18:00:00Z',
    });
  }
  items[40].title = 'LockBit 3.0 ransomware operation hits hospitals';
  items[41].title = 'Konni malware campaign targets Ukraine';
  return items;
}
function zeroEvidenceItems() {
  const items = [];
  for (let i = 0; i < 12; i++) {
    items.push({ id: 'intel--z' + i, title: 'Plain vulnerability ' + i, severity: i < 3 ? 'CRITICAL' : 'MEDIUM', risk_score: 4.1,
      ioc_count: 0, iocs: [], feed_source: 'https://vulners.com/rss.xml', source: 'Vulners', tags: ['pip:x'] });
  }
  return items;
}
function xssItems() {
  const items = canonicalItems().slice(0, 10);
  items[0] = Object.assign({}, items[0], { title: XSS, source: XSS2, severity: 'CRITICAL', actor_country: XSS2, feed_source: 'https://evil.example/' + XSS });
  items[1] = Object.assign({}, items[1], { title: XSS2 + ' ransomware LockBit 3.0 campaign', severity: 'HIGH' });
  return items;
}

async function buildFixtures(contract, items, opts) {
  const o = opts || {};
  const gen = o.stale ? '2026-09-10T00:00:00Z' : new Date(Date.now() - 23 * 60000).toISOString();
  const status = o.stale ? 'stale' : 'fresh';
  const publication = { status, fresh: status === 'fresh', generated_at: gen, age_seconds: Math.round((Date.now() - Date.parse(gen)) / 1000), max_age_seconds: 21600 };
  const critical = items.filter(i => i.severity === 'CRITICAL').length;
  const kev = items.filter(i => i.kev_present).length;
  const avg = items.length ? items.reduce((n, i) => n + i.risk_score, 0) / items.length : 0;
  const level = Math.min(10, Math.min(avg, 10) + Math.min(kev * 0.15, 1.5) + Math.min(critical * 0.05, 0.5));
  const label = level >= 8.5 ? 'CRITICAL' : level >= 7 ? 'HIGH' : level >= 5 ? 'ELEVATED' : level >= 3 ? 'GUARDED' : 'LOW';
  const now = new Date().toISOString();
  return {
    '/api/health': { status: 'ok', intelligence: { status, generated_at: gen, age_seconds: publication.age_seconds, max_age_seconds: 21600, advisory_count: items.length } },
    '/api/feed.json': { schema_version: '1.0', generated_at: gen, count: items.length, items, freshness_status: status.toUpperCase() },
    '/api/v1/intel/stats': { total: items.length, critical, kev_confirmed: kev, total_iocs: 0, avg_risk_score: +avg.toFixed(2), last_sync: gen, last_feed_sync_utc: gen, publication, feeds_active: null, global_threat_level: +level.toFixed(1), global_threat_label: label },
    '/api/v1/intel/defcon': { level: 3, label: 'DEFCON 3', status: 'ROUND HOUSE', global_threat_level: { level: +level.toFixed(1), label }, stats: { critical, kev_confirmed: kev, total: items.length }, evidence: { critical, kev_confirmed: kev, total: items.length }, formula: { version: 'threat-level/1.0', expression: contract.THREAT_LEVEL_FORMULA }, publication, generated_at: now },
    '/api/v1/intel/campaigns': Object.assign(contract.buildCampaignsPayload(items, now), { publication }),
    '/api/v1/intel/ransomware': Object.assign(contract.buildRansomwarePayload(items, GROUPS, now), { publication }),
    '/api/v1/intel/cybermap': { regions: [], attribution: 'none', note: 'No country tags on the current feed. Origins are not estimated.', coverage: contract.geoAttributionCoverage(items), publication },
    '/api/ai/tracker.json': o.ai === false ? {} : { escalation_tracker: [{ title: o.xss ? XSS : 'Escalating exploitation of CVE-2026-1010', risk_score: 8.8, priority: 'P1' }] },
  };
}

async function routeFixtures(context, fixtures, opts) {
  const o = opts || {};
  const seen = [];
  await context.route('**/*', (route) => {
    const u = new URL(route.request().url());
    if (u.hostname !== '127.0.0.1') { seen.push('EXTERNAL ' + u.hostname + u.pathname); return route.abort(); }
    const p = u.pathname.replace(/^\/+/, '/');
    if (p.startsWith('/api/') || p === '/feed.json') {
      seen.push(p);
      if (o.feedFails && p === '/api/feed.json') return route.fulfill({ status: 503, contentType: 'application/json', body: '{}' });
      if (Object.prototype.hasOwnProperty.call(fixtures, p)) return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(fixtures[p]) });
      return route.fulfill({ status: 404, contentType: 'application/json', body: '{"error":"not_found"}' });
    }
    return route.continue();
  });
  return seen;
}

const IDS = ['eicc-ticker-inner', 'eicc-ticker-count', 'eicc-m-total', 'eicc-m-critical', 'eicc-m-iocs', 'eicc-m-feeds', 'eicc-m-sync',
  'eicc-m-sync-utc', 'eicc-m-api', 'eicc-m-intel', 'eicc-feed-preview', 'eicc-heatmap-title', 'eicc-heatmap-sub', 'eicc-heatmap',
  'eicc-ai-predictions', 'cdb-gauge-val', 'cdb-gauge-label', 'cdb-gauge-status', 'cdb-gauge-crit', 'cdb-gauge-kev', 'cdb-gauge-age',
  'cdb-rw-status', 'cdb-rw-groups', 'cdb-rw-victims', 'cdb-rw-list', 'cdb-kc-campaigns', 'cdb-kc-tactics', 'cdb-kc-active-label',
  'nexus-killchain-meta', 'nexus-killchain'];

async function snapshot(page) {
  return page.evaluate((ids) => {
    const out = {};
    for (const id of ids) { const e = document.getElementById(id); out[id] = e ? (e.textContent || '').replace(/\s+/g, ' ').trim() : '__MISSING__'; }
    out.tickerItems = document.querySelectorAll('#eicc-ticker-inner [data-ticker-item]').length;
    out.tickerMode = (document.getElementById('eicc-ticker-inner') || {}).getAttribute ? document.getElementById('eicc-ticker-inner').getAttribute('data-feed-mode') : null;
    out.previewItems = document.querySelectorAll('#eicc-feed-preview [data-preview-item]').length;
    out.geoMode = document.getElementById('eicc-heatmap').getAttribute('data-geo-mode');
    out.pwned = window.__pwned || 0;
    out.injected = document.querySelectorAll('img[src="x"], svg[onload]').length;
    out.hScroll = document.documentElement.scrollWidth > window.innerWidth + 1;
    return out;
  }, IDS);
}

async function openPage(browser, fixtures, viewport, opts) {
  const context = await browser.newContext({ serviceWorkers: 'block', viewport });
  const seen = await routeFixtures(context, fixtures, opts);
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(PAGE_URL, { waitUntil: 'load' });
  await page.waitForFunction(() => {
    const t = document.getElementById('eicc-ticker-inner');
    const k = document.getElementById('nexus-killchain-meta');
    return t && t.getAttribute('data-feed-mode') && k && !/Loading/.test(k.textContent);
  }, null, { timeout: 30000 }).catch(() => {});
  await page.waitForTimeout(1500);
  return { context, page, errors, seen };
}

async function canonical(browser, contract, vpName) {
  const items = canonicalItems();
  const fx = await buildFixtures(contract, items);
  const { context, page, errors, seen } = await openPage(browser, fx, VIEWPORTS[vpName]);
  const s = await snapshot(page);
  const tag = `[canonical/${vpName}]`;
  record(`${tag} ticker renders real items and count == feed total (44)`, s.tickerMode === 'live' && s.tickerItems === 30 && s['eicc-ticker-count'] === '44', JSON.stringify({ mode: s.tickerMode, items: s.tickerItems, count: s['eicc-ticker-count'] }));
  record(`${tag} metric total == ticker total == health advisory_count`, s['eicc-m-total'] === '44' && s['eicc-m-critical'] === '11' && s['eicc-m-iocs'] === '33', JSON.stringify({ total: s['eicc-m-total'], critical: s['eicc-m-critical'], iocs: s['eicc-m-iocs'] }));
  record(`${tag} Last Sync is the feed generation time, with UTC`, /^2[0-9]m ago$/.test(s['eicc-m-sync']) && /UTC$/.test(s['eicc-m-sync-utc']), JSON.stringify({ sync: s['eicc-m-sync'], utc: s['eicc-m-sync-utc'] }));
  record(`${tag} API and INTEL statuses are separate and both healthy`, s['eicc-m-api'] === 'API ● LIVE' && s['eicc-m-intel'] === 'INTEL ● FRESH', `${s['eicc-m-api']} / ${s['eicc-m-intel']}`);
  record(`${tag} sources = distinct hosts in the current feed`, s['eicc-m-feeds'] === '3', s['eicc-m-feeds']);
  record(`${tag} preview shows 5 current Critical/High items`, s.previewItems === 5 && /CRITICAL/.test(s['eicc-feed-preview']), `preview=${s.previewItems}`);
  record(`${tag} geo panel states attribution coverage, invents no origin`, s.geoMode === 'coverage' && /GEOGRAPHIC ATTRIBUTION COVERAGE/.test(s['eicc-heatmap-title']) && /^0 of 44 advisories/.test(s['eicc-heatmap-sub']) && !/Russia|China|Iran|N\.Korea/.test(s['eicc-heatmap']), s['eicc-heatmap-sub']);
  record(`${tag} threat level is evidence-derived, LIVE, with supporting evidence`, /^\d+\.\d$/.test(s['cdb-gauge-val']) && s['cdb-gauge-status'] === '● LIVE' && s['cdb-gauge-crit'] === '11' && s['cdb-gauge-kev'] === '4' && /ago$/.test(s['cdb-gauge-age']), JSON.stringify({ val: s['cdb-gauge-val'], label: s['cdb-gauge-label'], crit: s['cdb-gauge-crit'], kev: s['cdb-gauge-kev'], age: s['cdb-gauge-age'] }));
  record(`${tag} ransomware: monitor OPERATIONAL, 1 advisory, LockBit named from feed evidence, no victims`, s['cdb-rw-status'] === 'MONITOR ● OPERATIONAL' && s['cdb-rw-victims'] === '1' && s['cdb-rw-groups'] === '1' && /LockBit 3\.0/.test(s['cdb-rw-list']), JSON.stringify({ st: s['cdb-rw-status'], groups: s['cdb-rw-groups'], adv: s['cdb-rw-victims'] }));
  record(`${tag} ATT&CK coverage populated from evidence (3 tactics; 30 mitre_tactics + 7 technique-id tags = 37/44 items)`, /^3 of 14 tactics observed · 37 of 44 advisories carry ATT&CK evidence$/.test(s['nexus-killchain-meta']) && /INITIAL ACCESS\s*17/.test(s['nexus-killchain']), s['nexus-killchain-meta']);
  record(`${tag} campaigns are evidence-based (2: ransomware operation + malware campaign), not the 11 CRITICAL CVEs`, s['cdb-kc-campaigns'] === '2' && s['cdb-kc-tactics'] === '3', JSON.stringify({ campaigns: s['cdb-kc-campaigns'], tactics: s['cdb-kc-tactics'] }));
  record(`${tag} AI tracker shows a risk score, never a probability`, /RISK 8\.8\/10/.test(s['eicc-ai-predictions']) && !/88%/.test(s['eicc-ai-predictions']), s['eicc-ai-predictions'].slice(0, 90));
  record(`${tag} no uncaught errors`, errors.length === 0, errors.slice(0, 3).join(' | '));
  record(`${tag} no frozen GitHub mirror, no duplicate latest.json download`, !seen.some(x => /raw\.githubusercontent\.com.*\/(api\/feed\.json|feed\.json|latest\.json|feed_manifest\.json)$/.test(x)) && !seen.includes('/api/v1/intel/latest.json'), [...new Set(seen)].filter(x => /latest|feed\.json/.test(x)).join(','));
  record(`${tag} one health + feed snapshot shared by the EICC widgets`, seen.filter(x => x === '/api/health').length === 1, `health calls=${seen.filter(x => x === '/api/health').length}`);
  if (vpName === 'mobile') record(`${tag} no horizontal page scroll`, !s.hScroll, '');

  if (vpName === 'desktop') {
    // One refresh cycle: force a new snapshot + gadget refresh, values must hold.
    await page.evaluate(async () => { await window.ApexDashboardSnapshot.load({ force: true }); await window.SentinelLiveFeeds.refresh(); });
    await page.waitForTimeout(1500);
    const r = await snapshot(page);
    const keys = ['eicc-ticker-count', 'eicc-m-total', 'eicc-m-sync-utc', 'eicc-m-intel', 'cdb-gauge-val', 'cdb-rw-victims', 'cdb-kc-campaigns', 'nexus-killchain-meta'];
    const drift = keys.filter(k => r[k] !== s[k]);
    record(`${tag} values stay consistent through one refresh cycle`, drift.length === 0 && r.tickerItems === 30, drift.map(k => `${k}: ${s[k]} -> ${r[k]}`).join('; '));
    record(`${tag} refresh re-used the snapshot contract (no errors)`, errors.length === 0, errors.slice(0, 2).join(' | '));
  }
  await context.close();
}

async function zeroEvidence(browser, contract) {
  const items = zeroEvidenceItems();
  const fx = await buildFixtures(contract, items, { ai: false });
  const { context, page, errors } = await openPage(browser, fx, VIEWPORTS.desktop);
  const s = await snapshot(page);
  const tag = '[zero-evidence]';
  record(`${tag} geo: no attribution stated, no countries invented`, s.geoMode === 'coverage' && /^0 of 12 advisories/.test(s['eicc-heatmap-sub']) && !/Russia|China|Iran|Korea|Ukraine/.test(s['eicc-heatmap']), s['eicc-heatmap-sub']);
  record(`${tag} ransomware: none in feed, monitor still operational`, s['cdb-rw-list'] === 'NO RANSOMWARE-TAGGED INTELLIGENCE IN CURRENT FEED' && s['cdb-rw-groups'] === '0' && s['cdb-rw-victims'] === '0' && s['cdb-rw-status'] === 'MONITOR ● OPERATIONAL', s['cdb-rw-list']);
  record(`${tag} campaigns: zero, even with 3 CRITICAL advisories`, s['cdb-kc-campaigns'] === '0' && /0 evidenced campaigns · no ATT&CK evidence/.test(s['cdb-kc-active-label']), `${s['cdb-kc-campaigns']} / ${s['cdb-kc-active-label']}`);
  record(`${tag} ATT&CK: 0 of 14 observed, stated with the evaluated count`, /^0 of 14 tactics observed · 0 of 12 advisories/.test(s['nexus-killchain-meta']), s['nexus-killchain-meta']);
  record(`${tag} AI: explicit unavailable, no invented forecast`, /PREDICTION DATA UNAVAILABLE/.test(s['eicc-ai-predictions']) && !/%/.test(s['eicc-ai-predictions']), s['eicc-ai-predictions']);
  record(`${tag} ticker still shows the 12 real items`, s.tickerMode === 'live' && s['eicc-ticker-count'] === '12', s['eicc-ticker-count']);
  record(`${tag} no uncaught errors`, errors.length === 0, errors.slice(0, 3).join(' | '));
  await context.close();
}

async function stale(browser, contract) {
  const fx = await buildFixtures(contract, canonicalItems(), { stale: true });
  const { context, page, errors } = await openPage(browser, fx, VIEWPORTS.desktop);
  const s = await snapshot(page);
  const tag = '[stale]';
  record(`${tag} API LIVE but INTEL DEGRADED (never fully LIVE)`, s['eicc-m-api'] === 'API ● LIVE' && s['eicc-m-intel'] === 'INTEL ● DEGRADED', `${s['eicc-m-api']} / ${s['eicc-m-intel']}`);
  record(`${tag} ticker states degradation with the last authoritative update`, s.tickerMode === 'degraded' && /INTELLIGENCE DEGRADED — LAST AUTHORITATIVE UPDATE: 2026-09-10 00:00 UTC/.test(s['eicc-ticker-inner']), s['eicc-ticker-inner'].slice(0, 90));
  record(`${tag} threat level not shown as a LIVE score`, s['cdb-gauge-val'] === '—' && s['cdb-gauge-label'] === 'THREAT LEVEL STALE' && s['cdb-gauge-status'] === '● STALE', JSON.stringify({ v: s['cdb-gauge-val'], l: s['cdb-gauge-label'] }));
  record(`${tag} Last Sync shows the real (old) generation time`, /d ago$/.test(s['eicc-m-sync']) && s['eicc-m-sync-utc'] === '2026-09-10 00:00 UTC', `${s['eicc-m-sync']} / ${s['eicc-m-sync-utc']}`);
  record(`${tag} no uncaught errors`, errors.length === 0, errors.slice(0, 3).join(' | '));
  await context.close();
}

async function unavailable(browser, contract) {
  const fx = await buildFixtures(contract, canonicalItems());
  const { context, page, errors } = await openPage(browser, fx, VIEWPORTS.desktop, { feedFails: true });
  const s = await snapshot(page);
  const tag = '[unavailable]';
  record(`${tag} ticker says unavailable, not "empty"/"no current intelligence"`, s.tickerMode === 'unavailable' && /INTELLIGENCE TEMPORARILY UNAVAILABLE/.test(s['eicc-ticker-inner']) && !/NO CURRENT ADVISORIES/.test(s['eicc-ticker-inner']), s['eicc-ticker-inner']);
  record(`${tag} metrics are N/A, never zero`, s['eicc-m-total'] === 'N/A' && s['eicc-m-critical'] === 'N/A' && s['eicc-ticker-count'] === 'N/A', JSON.stringify({ total: s['eicc-m-total'], count: s['eicc-ticker-count'] }));
  record(`${tag} preview and geo reach an explicit unavailable state`, /INTELLIGENCE TEMPORARILY UNAVAILABLE/.test(s['eicc-feed-preview']) && /INTELLIGENCE TEMPORARILY UNAVAILABLE/.test(s['eicc-heatmap']), '');
  record(`${tag} INTEL status is UNAVAILABLE`, s['eicc-m-intel'] === 'INTEL ● UNAVAILABLE', s['eicc-m-intel']);
  record(`${tag} no uncaught errors`, errors.length === 0, errors.slice(0, 3).join(' | '));
  await context.close();
}

async function xss(browser, contract) {
  const items = xssItems();
  const fx = await buildFixtures(contract, items, { xss: true });
  fx['/api/v1/intel/cybermap'] = { regions: [{ code: 'RU', country: XSS, attacks: 1, pct: 100, risk: XSS2 }], total_attacks_today: 1, attribution: 'country_field', note: '' };
  const { context, page, errors } = await openPage(browser, fx, VIEWPORTS.desktop);
  const s = await snapshot(page);
  const tag = '[xss]';
  record(`${tag} hostile titles/sources/countries/actors never execute`, s.pwned === 0, `window.__pwned=${s.pwned}`);
  record(`${tag} no injected <img src=x> or <svg onload> element`, s.injected === 0, `injected=${s.injected}`);
  record(`${tag} payload rendered as inert text in ticker and preview`, s['eicc-ticker-inner'].includes('<img src=x') && s['eicc-feed-preview'].includes('<img src=x'), '');
  record(`${tag} no uncaught errors`, errors.length === 0, errors.slice(0, 3).join(' | '));
  await context.close();
}

async function main() {
  const contract = await import(pathToFileURL(path.join(REPO_ROOT, 'workers/intel-gateway/src/dashboard-contract.js')).href);
  const server = await startStaticServer(ROOT, PORT, MIME);
  let browser;
  try {
    browser = await chromium.launch();
    for (const vp of Object.keys(VIEWPORTS)) { console.log(`\n--- canonical (${vp}) ---`); await canonical(browser, contract, vp); }
    console.log('\n--- zero-evidence ---'); await zeroEvidence(browser, contract);
    console.log('\n--- stale ---'); await stale(browser, contract);
    console.log('\n--- unavailable ---'); await unavailable(browser, contract);
    console.log('\n--- xss ---'); await xss(browser, contract);
  } finally {
    if (browser) await browser.close();
    server.close();
  }
  const failed = results.filter((r) => !r.pass);
  console.log('\n' + '='.repeat(64));
  console.log(`SUMMARY: ${results.length - failed.length}/${results.length} checks passed`);
  console.log('='.repeat(64));
  process.exit(failed.length ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
