#!/usr/bin/env node
/**
 * SENTINEL APEX — Gadget Runtime Recovery Regression Test (PR-D5)
 * ====================================================================
 * Real-browser (headless Chromium) verification that the six "Cyber
 * Threat Intelligence Gadgets" widgets actually populate from live API
 * data instead of staying stuck in their initial placeholder state
 * forever, and that Ransomware Tracker / APT Actor Radar / Dark Web
 * Monitor no longer display Math.random()-fabricated numbers.
 *
 * Root cause covered: js/sentinel-live-feeds.js correctly fetched real
 * backend endpoints (/api/v1/intel/defcon, epss, pulse, ransomware, apt,
 * darkweb, campaigns) but wrote the results into DOM selectors
 * (.threat-level-value, #defcon-status, .epss-container, #pulse-rate,
 * #ransom-groups, #apt-count, .dw-breaches, etc.) that do not exist
 * anywhere in index.html -- the real ids use a `cdb-*` prefix scheme
 * (#cdb-gauge-val, #cdb-defcon-status, #cdb-epss-list, #cdb-pulse-rate,
 * #cdb-rw-groups, #cdb-apt-count, #cdb-dw-count, ...). Separately,
 * index.html's own initNewGadgets() IIFE DID target the correct
 * #cdb-rw-* / #cdb-apt-* / #cdb-dw-* ids, but gated real-data population on
 * `window.EMBEDDED_INTEL`, a global permanently forced to `[]` elsewhere
 * in the file ("Worker API is authoritative") -- so it always fell
 * through to a `_rand()` fallback that fabricated customer-facing
 * security metrics with no real backend connection and no bounded retry
 * that could ever succeed.
 *
 * Fix under test:
 *   - sentinel-live-feeds.js's loadThreatLevel/loadPulse/loadRansomware/
 *     loadAPT/loadEPSS/loadKillChain/loadDarkweb now write to the real
 *     cdb-* DOM ids, and show an explicit UNAVAILABLE/N/A state (not a
 *     silently-stuck placeholder) when the backend fetch itself fails.
 *   - index.html's initNewGadgets() no longer fabricates _rand() numbers
 *     when EMBEDDED_INTEL is empty (its permanent, by-design state) --
 *     sentinel-live-feeds.js's corrected loaders are the sole source of
 *     truth for these six gadgets.
 *
 * Each scenario launches a FRESH browser context with service workers
 * blocked (index.html registers one, which intercepts fetch() ahead of
 * Playwright's route layer and would otherwise make every mocked
 * endpoint invisible to route interception) and mocks the seven
 * `/api/v1/intel/*` gadget endpoints with real, previously-captured
 * production response shapes.
 *
 * Usage:
 *   NODE_PATH="$(npm root -g)" node render-test/verify_gadget_runtime_recovery.js
 *
 * Exit code 0 = all checks passed. Exit code 1 = at least one failed.
 */
'use strict';

const path = require('path');
const { startStaticServer } = require('./lib/static-server');
const http = require('http');
const fs = require('fs');
const { chromium } = require('playwright');

const REPO_ROOT = path.resolve(__dirname, '..');
const PORT = 8958;
const PAGE_URL = `http://127.0.0.1:${PORT}/index.html`;

const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.json': 'application/json', '.txt': 'text/plain', '.ico': 'image/x-icon',
};

const results = [];
function record(name, pass, detail) {
  results.push({ name, pass, detail });
  const tag = pass ? 'PASS' : 'FAIL';
  console.log(`[${tag}] ${name}${detail ? ' — ' + detail : ''}`);
}

// Real production response shapes (captured 2026-08-12), used as fixtures
// so this test proves real wiring, not coincidence -- assertions below
// check for these exact values.
// 2026-09-24 (P0 dashboard data contract): defcon/ransomware/campaigns carry
// the Worker's contract fields (publication, ransomware_advisories,
// campaign_semantics, attack_tactics). The pre-contract shapes are kept as
// *_legacy to prove the page does not repeat their old semantics.
const FRESH_PUBLICATION = { status: "fresh", fresh: true, generated_at: new Date(Date.now() - 20 * 60000).toISOString(), age_seconds: 1200, max_age_seconds: 21600 };
const FIXTURES = {
  defcon: JSON.stringify({
    level: 1, label: "DEFCON 1", status: "WAR", color: "#ff0000",
    global_threat_level: { level: 7.7, label: "HIGH", generated_at: "2026-08-12T06:17:44Z" },
    stats: { critical: 17, kev_confirmed: 5, total: 182 },
    evidence: { avg_risk_score: 6.1, critical: 17, kev_confirmed: 5, total: 182 },
    formula: { version: "threat-level/1.0", expression: "..." },
    publication: FRESH_PUBLICATION,
    generated_at: "2026-08-12T06:17:44Z",
  }),
  defcon_stale: JSON.stringify({
    level: 1, label: "DEFCON 1", status: "WAR", color: "#ff0000",
    global_threat_level: { level: 7.7, label: "HIGH", generated_at: "2026-08-12T06:17:44Z" },
    stats: { critical: 17, kev_confirmed: 5, total: 182 },
    publication: { status: "stale", fresh: false, generated_at: "2026-08-01T00:00:00Z", age_seconds: 999999 },
    generated_at: "2026-08-12T06:17:44Z",
  }),
  epss: JSON.stringify({
    top_cves: [
      { cve_id: "CVE-2026-72898", title: "Metabase SQL Injection", risk_score: 9.61, epss_score: 0.69, severity: "CRITICAL", kev_present: true, source: "cisa_kev", published: "2026-08-11T22:23:08Z" },
    ],
    total_cves_tracked: 500, kev_count: 5, generated_at: "2026-08-12T06:17:00Z", version: "184.0",
  }),
  pulse: JSON.stringify({ rate_hr: 30, today: 21, total: 182, critical_rate: 3, generated_at: "2026-08-12T06:17:58Z", version: "184.0" }),
  // new_victims_30d:44 is deliberately present: the page must NOT show it
  // (victims_measured is false), only the ransomware advisory count.
  ransomware: JSON.stringify({
    active_groups: 9, monitoring_groups: 40, new_victims_30d: 44, victims_measured: false,
    ransomware_advisories: 2, monitor_status: "OPERATIONAL",
    recent_advisories: [{ title: "LockBit 3.0 hits hospital", severity: "HIGH", source: "BleepingComputer" }, { title: "Akira ransomware update", severity: "HIGH", source: "SecurityWeek" }],
    top_groups: [{ name: "LockBit 3.0", sector: "Healthcare,Finance", status: "IN_CURRENT_FEED", advisories: 1, victims_30d: null }],
    generated_at: "2026-08-12T06:17:00Z", version: "184.0",
  }),
  ransomware_none: JSON.stringify({
    active_groups: 0, monitoring_groups: 0, new_victims_30d: null, victims_measured: false,
    ransomware_advisories: 0, monitor_status: "OPERATIONAL", recent_advisories: [], top_groups: [],
    generated_at: "2026-08-12T06:17:00Z", version: "184.0",
  }),
  apt: JSON.stringify({
    tracked_apts: 10, active_sectors: 14, total_ttps: 179,
    top_actors: [{ id: "APT28", alias: "Fancy Bear", nation: "RU", sector: "Government,Defense", ttps: 18 }],
    generated_at: "2026-08-12T06:17:00Z", version: "184.0",
  }),
  darkweb: JSON.stringify({
    breach_detections_24h: 67, sources_monitored: 127, credentials_exposed: "58K+",
    paste_sites: 43, tor_services: 84, recent_findings: [],
    generated_at: "2026-08-12T06:17:59Z", version: "184.0",
  }),
  campaigns: JSON.stringify({
    phases: { recon: 0, weaponize: 0, deliver: 30, exploit: 20, install: 4, c2: 0, action: 0 },
    coverage_pct: 43, total_tactics: 3,
    active_campaigns: [
      { id: "intel--test1", title: "Konni malware campaign exploits CVE-2026-68443", severity: "HIGH", risk_score: 7.3, source: "CVE Feed", published: "2026-08-12T00:17:44Z", kill_chain: ["Initial Access"], cve_ids: ["CVE-2026-68443"], tags: [], evidence: ["title:campaign"] },
    ],
    active_campaign_count: 1,
    campaign_semantics: { version: "campaign-evidence/1.0", rule: "..." },
    attack_tactics: { model: "mitre_attack_enterprise_tactics", tactics_observed: 3, tactics_total: 14, items_evaluated: 182, items_with_attack_evidence: 40, tactics: [{ id: "TA0043", name: "Reconnaissance", count: 0 }, { id: "TA0042", name: "Resource Development", count: 0 }, { id: "TA0001", name: "Initial Access", count: 30 }, { id: "TA0002", name: "Execution", count: 20 }, { id: "TA0003", name: "Persistence", count: 0 }, { id: "TA0004", name: "Privilege Escalation", count: 0 }, { id: "TA0005", name: "Defense Evasion", count: 0 }, { id: "TA0006", name: "Credential Access", count: 4 }, { id: "TA0007", name: "Discovery", count: 0 }, { id: "TA0008", name: "Lateral Movement", count: 0 }, { id: "TA0009", name: "Collection", count: 0 }, { id: "TA0011", name: "Command and Control", count: 0 }, { id: "TA0010", name: "Exfiltration", count: 0 }, { id: "TA0040", name: "Impact", count: 0 }] },
    generated_at: "2026-08-12T06:17:00Z", version: "184.0",
  }),
  campaigns_empty: JSON.stringify({
    phases: { recon: 0, weaponize: 0, deliver: 0, exploit: 0, install: 0, c2: 0, action: 0 },
    coverage_pct: 0, total_tactics: 0, active_campaigns: [], active_campaign_count: 0,
    campaign_semantics: { version: "campaign-evidence/1.0", rule: "..." },
    attack_tactics: { model: "mitre_attack_enterprise_tactics", tactics_observed: 0, tactics_total: 14, items_evaluated: 182, items_with_attack_evidence: 0, tactics: [] },
    generated_at: "2026-08-12T06:17:00Z", version: "184.0",
  }),
  // Pre-contract Worker: every CRITICAL advisory listed as a campaign.
  campaigns_legacy: JSON.stringify({
    phases: { recon: 0, weaponize: 0, deliver: 0, exploit: 0, install: 0, c2: 0, action: 0 },
    coverage_pct: 0, total_tactics: 3,
    active_campaigns: [
      { id: "intel--test1", title: "CVE-2026-68443 hwmon driver IO exploit chain", severity: "CRITICAL", risk_score: 1.34, source: "CVE Feed", published: "2026-08-12T00:17:44Z", kill_chain: [], cve_ids: ["CVE-2026-68443"], tags: [] },
    ],
    generated_at: "2026-08-12T06:17:00Z", version: "184.0",
  }),
};

// Minimal valid feed so the unrelated main dashboard boot path doesn't error.
const EMPTY_FEED = JSON.stringify({
  schema_version: "2.0.0", generated_at: "2026-08-12T06:00:00Z", version: "184.0",
  count: 0, items: [],
});

async function routeGadgetAPIs(context, overrides) {
  await context.route('**/*', (route) => {
    const url = route.request().url();
    const json = (body) => route.fulfill({ status: 200, contentType: 'application/json', body });
    const fail = () => route.fulfill({ status: 503, contentType: 'application/json', body: '{}' });

    // API-shaped paths must be checked before the localhost passthrough --
    // apiFetch() in sentinel-live-feeds.js uses window.location.origin,
    // which under this hermetic server IS http://127.0.0.1:PORT.
    if (/\/api\/v1\/intel\/defcon/.test(url)) return overrides.defcon === false ? fail() : json(overrides.defcon || FIXTURES.defcon);
    if (/\/api\/v1\/intel\/epss/.test(url)) return overrides.epss === false ? fail() : json(overrides.epss || FIXTURES.epss);
    if (/\/api\/v1\/intel\/pulse/.test(url)) return overrides.pulse === false ? fail() : json(overrides.pulse || FIXTURES.pulse);
    if (/\/api\/v1\/intel\/ransomware/.test(url)) return overrides.ransomware === false ? fail() : json(overrides.ransomware || FIXTURES.ransomware);
    if (/\/api\/v1\/intel\/apt/.test(url)) return overrides.apt === false ? fail() : json(overrides.apt || FIXTURES.apt);
    if (/\/api\/v1\/intel\/darkweb/.test(url)) return overrides.darkweb === false ? fail() : json(overrides.darkweb || FIXTURES.darkweb);
    if (/\/api\/v1\/intel\/campaigns/.test(url)) return overrides.campaigns === false ? fail() : json(overrides.campaigns || FIXTURES.campaigns);
    if (/\/api\/(feed\.json|preview\/?|v1\/intel\/(latest|apex|top10|stats)\.json)/.test(url)) return json(EMPTY_FEED);
    if (/^\/api\//.test(new URL(url).pathname)) return route.abort();

    if (url.startsWith(`http://127.0.0.1:${PORT}/`)) return route.continue();
    return route.abort();
  });
}

async function gadgetState(page) {
  return page.evaluate(() => {
    const txt = (id) => {
      const el = document.getElementById(id);
      return el ? el.textContent.trim() : '__MISSING_ELEMENT__';
    };
    return {
      gaugeVal: txt('cdb-gauge-val'), gaugeLabel: txt('cdb-gauge-label'),
      defconStatus: txt('cdb-defcon-status'),
      epssList: txt('cdb-epss-list'),
      pulseRate: txt('cdb-pulse-rate'), pulseToday: txt('cdb-pulse-today'), pulseTotal: txt('cdb-pulse-total'),
      gaugeStatus: txt('cdb-gauge-status'), gaugeCrit: txt('cdb-gauge-crit'), gaugeKev: txt('cdb-gauge-kev'),
      rwGroups: txt('cdb-rw-groups'), rwVictims: txt('cdb-rw-victims'), rwStatus: txt('cdb-rw-status'), rwList: txt('cdb-rw-list'),
      kcMeta: txt('nexus-killchain-meta'), kcCoverage: txt('nexus-killchain'),
      aptCount: txt('cdb-apt-count'), aptSectors: txt('cdb-apt-sectors'), aptTtps: txt('cdb-apt-ttps'),
      dwCount: txt('cdb-dw-count'), dwSources: txt('cdb-dw-sources'), dwCreds: txt('cdb-dw-creds'),
      kcActiveLabel: txt('cdb-kc-active-label'), kcCampaigns: txt('cdb-kc-campaigns'), kcTactics: txt('cdb-kc-tactics'),
    };
  });
}

async function runHappyPathScenario(browser) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await routeGadgetAPIs(context, {});
  const page = await context.newPage();
  await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(4000);
  const s = await gadgetState(page);
  await context.close();

  record('Global Threat Level gauge shows the real value, not stuck COMPUTING', s.gaugeVal === '7.7' && s.gaugeLabel === 'HIGH' && s.gaugeStatus === '● LIVE', JSON.stringify({ gaugeVal: s.gaugeVal, gaugeLabel: s.gaugeLabel, gaugeStatus: s.gaugeStatus }));
  record('Global Threat Level shows its supporting evidence (critical, KEV)', s.gaugeCrit === '17' && s.gaugeKev === '5', JSON.stringify({ gaugeCrit: s.gaugeCrit, gaugeKev: s.gaugeKev }));
  record('DEFCON status shows the real value, not stuck ASSESSING', s.defconStatus === 'WAR', `defconStatus="${s.defconStatus}"`);
  record('EPSS list shows real CVE data, not stuck LOADING EPSS DATA', s.epssList.includes('CVE-2026-72898') && !s.epssList.includes('LOADING'), `epssList="${s.epssList.slice(0, 60)}..."`);
  record('Live Threat Pulse shows real rate/today/total, not dashes', s.pulseRate === '30' && s.pulseToday === '21' && s.pulseTotal === '182', JSON.stringify({ pulseRate: s.pulseRate, pulseToday: s.pulseToday, pulseTotal: s.pulseTotal }));
  record('Ransomware Tracker shows real counts (9 groups, 2 ransomware advisories) and never the unmeasured 44 victims', s.rwGroups === '9' && s.rwVictims === '2' && !/44/.test(s.rwVictims) && s.rwStatus === 'MONITOR ● OPERATIONAL', JSON.stringify({ rwGroups: s.rwGroups, rwVictims: s.rwVictims, rwStatus: s.rwStatus }));
  record('APT Actor Radar shows the real backend count (10/14/179), not a Math.random() fallback', s.aptCount === '10' && s.aptSectors === '14' && s.aptTtps === '179', JSON.stringify({ aptCount: s.aptCount, aptSectors: s.aptSectors, aptTtps: s.aptTtps }));
  record('Dark Web Monitor shows the real backend count (67 breaches), not a Math.random() fallback', s.dwCount === '67', `dwCount="${s.dwCount}"`);
  record('Kill Chain active-campaign label is populated, not stuck "Analyzing active threat campaigns..."', s.kcActiveLabel.includes('CVE-2026-68443') && !s.kcActiveLabel.includes('Analyzing active threat campaigns'), `kcActiveLabel="${s.kcActiveLabel}"`);
  record('Kill Chain campaign/tactic counts are populated, not dashes', s.kcCampaigns === '1' && s.kcTactics === '3', JSON.stringify({ kcCampaigns: s.kcCampaigns, kcTactics: s.kcTactics }));
  record('MITRE ATT&CK tactic coverage renders the 14 tactics with real counts', /3 of 14 tactics observed/.test(s.kcMeta) && /INITIAL ACCESS\s*30/.test(s.kcCoverage) && /IMPACT\s*0/.test(s.kcCoverage), JSON.stringify({ kcMeta: s.kcMeta }));
}

async function runFailurePathScenario(browser) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await routeGadgetAPIs(context, { defcon: false, epss: false, ransomware: false });
  const page = await context.newPage();
  await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(4000);
  const s = await gadgetState(page);
  await context.close();

  record('A genuinely failed DEFCON fetch shows an explicit UNAVAILABLE state, not a silently-stuck placeholder', /UNAVAILABLE/.test(s.gaugeLabel) || /UNAVAILABLE/.test(s.defconStatus), JSON.stringify({ gaugeLabel: s.gaugeLabel, defconStatus: s.defconStatus }));
  record('A genuinely failed EPSS fetch shows an explicit UNAVAILABLE state, not stuck LOADING', /UNAVAILABLE/.test(s.epssList), `epssList="${s.epssList}"`);
  record('A genuinely failed Ransomware fetch shows N/A, never a fabricated random number', s.rwGroups === 'N/A', `rwGroups="${s.rwGroups}"`);
}

async function runZeroResultScenario(browser) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await routeGadgetAPIs(context, { campaigns: FIXTURES.campaigns_empty });
  const page = await context.newPage();
  await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(4000);
  const s = await gadgetState(page);
  await context.close();

  record('A successful fetch with zero active campaigns renders an honest zero state, not stuck "Analyzing..."', s.kcActiveLabel === '0 evidenced campaigns · no ATT&CK evidence in current feed', `kcActiveLabel="${s.kcActiveLabel}"`);
  record('Zero active campaigns still renders the real numeric zero, not a dash or fabricated number', s.kcCampaigns === '0', `kcCampaigns="${s.kcCampaigns}"`);
}

async function runTruthfulStatesScenario(browser) {
  const context = await browser.newContext({ serviceWorkers: 'block' });
  await routeGadgetAPIs(context, { defcon: FIXTURES.defcon_stale, ransomware: FIXTURES.ransomware_none, campaigns: FIXTURES.campaigns_legacy });
  const page = await context.newPage();
  await page.goto(PAGE_URL, { waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(4000);
  const s = await gadgetState(page);
  await context.close();

  record('A stale publication never shows the threat score as LIVE', s.gaugeVal === '—' && s.gaugeLabel === 'THREAT LEVEL STALE' && s.gaugeStatus === '● STALE', JSON.stringify({ gaugeVal: s.gaugeVal, gaugeLabel: s.gaugeLabel, gaugeStatus: s.gaugeStatus }));
  record('No ransomware intelligence: monitor OPERATIONAL, activity explicitly none', s.rwStatus === 'MONITOR ● OPERATIONAL' && s.rwGroups === '0' && s.rwVictims === '0' && s.rwList === 'NO RANSOMWARE-TAGGED INTELLIGENCE IN CURRENT FEED', JSON.stringify({ rwStatus: s.rwStatus, rwGroups: s.rwGroups, rwList: s.rwList }));
  record('A pre-contract campaigns response (every CRITICAL a campaign) is not presented as campaigns', s.kcCampaigns === 'N/A' && !s.kcActiveLabel.includes('CVE-2026-68443'), JSON.stringify({ kcCampaigns: s.kcCampaigns, kcActiveLabel: s.kcActiveLabel }));
}

async function main() {
  const server = await startStaticServer(REPO_ROOT, PORT, MIME);
  let browser;
  try {
    browser = await chromium.launch();
    console.log('--- Scenario: happy path -- all gadget APIs succeed ---');
    await runHappyPathScenario(browser);
    console.log('\n--- Scenario: failure path -- some gadget APIs fail ---');
    await runFailurePathScenario(browser);
    console.log('\n--- Scenario: zero-result honesty -- campaigns API succeeds with an empty result ---');
    await runZeroResultScenario(browser);
    console.log('\n--- Scenario: truthful states -- stale publication, no ransomware, pre-contract campaigns ---');
    await runTruthfulStatesScenario(browser);
  } finally {
    if (browser) await browser.close();
    server.close();
  }

  const failed = results.filter((r) => !r.pass);
  console.log('\n' + '='.repeat(64));
  console.log(`SUMMARY: ${results.length - failed.length}/${results.length} checks passed`);
  console.log('='.repeat(64));
  if (failed.length) {
    console.log('FAILED CHECKS:');
    for (const f of failed) console.log(`  - ${f.name}: ${f.detail}`);
  }
  process.exitCode = failed.length ? 1 : 0;
}

main().catch((err) => {
  console.error('[FATAL]', err);
  process.exitCode = 1;
});
