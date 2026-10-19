'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const bridge = require('../js/dashboard-evidence-bridge.js');

const NOW = Date.parse('2026-10-19T09:00:00Z');
const stamp = new Date(NOW - 60_000).toISOString();
const source = 'https://security.example.org/advisories/apt-2026';
const entry = (changes = {}) => Object.assign({
  id: 'intel-1', tlp: 'TLP:CLEAR', title: 'APT29 advisory: CVE-2026-55555 exploited',
  source_url: source, source: 'Security Research',
  published_at: stamp, severity: 'HIGH', risk_score: 8.4,
  actor_country: 'Russia', target_country: 'Germany'
}, changes);
const feed = (items) => ({
  schema_version: '1.0', generated_at: stamp, count: items.length, items
});

test('current, explicit CLEAR source-linked CTI is measured from feed records', () => {
  const a = bridge.summarize(feed([
    entry(), entry({id:'intel-2',title:'Generic CVE remediation advisory',source_url:'https://security.example.org/2',
      severity:'MEDIUM',risk_score:3,actor_country:null,target_country:null})
  ]), NOW);
  assert.equal(a.total, 2);
  assert.equal(a.source_linked, 2);
  assert.equal(a.apt_count, 1);
  assert.equal(a.geo_origin_count, 1);
  assert.equal(a.geo_pair_count, 1);
  assert.equal(a.vulnerability_count, 2);
  assert.equal(a.triage_count, 1);
  assert.equal(a.apt_rows[0].id,'intel-1');
});

test('generic critical CVEs never become APT attribution or geography', () => {
  const a = bridge.summarize(feed([entry({
    title:'CVE-2026-77777 critical exploitation', actor_country:'',target_country:'France',
    source_url:'https://security.example.org/3'
  })]), NOW);
  assert.equal(a.apt_count,0);
  assert.equal(a.geo_origin_count,0);
  assert.equal(a.geo_pair_count,0);
  assert.equal(a.triage_count,1);
});

test('restricted or missing TLP and untrusted URLs never appear in public cards', () => {
  const a = bridge.summarize(feed([
    entry({id:'clear'}),
    entry({id:'amber',tlp:'TLP:AMBER',source_url:'https://security.example.org/restricted'}),
    entry({id:'unlabelled',tlp:undefined}),
    entry({id:'javascript',source_url:'javascript:alert(1)'}),
    entry({id:'credentials',source_url:'https://user:secret@security.example.org/x'}),
    entry({id:'http',source_url:'http://security.example.org/not-tls'})
  ]), NOW);
  assert.equal(a.total,6);
  assert.equal(a.source_linked,1);
  assert.equal(a.apt_count,1);
  assert.equal(a.vulnerability_count,1);
  assert.equal(a.triage_count,1);
  assert.equal(bridge.safeSourceUrl('javascript:alert(1)'), '');
  assert.equal(bridge.safeSourceUrl('https://user:pw@example.com'), '');
});

test('no fabricated location pairs from publisher geography or malformed country labels', () => {
  const a=bridge.summarize(feed([
    entry({id:'only-origin',target_country:null}),
    entry({id:'publisher-only',actor_country:null,target_country:null,source_country:'United States'}),
    entry({id:'bad-country',actor_country:'US/UK (criminal)',target_country:'Germany'})
  ]),NOW);
  assert.equal(a.geo_origin_count,1);
  assert.equal(a.geo_pair_count,0);
});

test('empty evidence is measured zero rather than stale, partial or fabricated', () => {
  const a = bridge.summarize(feed([]),NOW);
  assert.equal(a.total,0);
  assert.equal(a.apt_count,0);
  assert.equal(a.triage_count,0);
  assert.equal(a.geo_pair_count,0);
});

test('stale, future-dated, malformed and truncated feeds fail closed', () => {
  const old = feed([entry()]); old.generated_at='2026-10-18T00:00:00Z';
  assert.equal(bridge.summarize(old,NOW),null);
  const future=feed([entry()]); future.generated_at='2026-10-19T09:06:00Z';
  assert.equal(bridge.summarize(future,NOW),null);
  const truncated=feed([entry()]); truncated.count=2;
  assert.equal(bridge.summarize(truncated,NOW),null);
  const missing={generated_at:stamp,items:[entry()]};
  assert.equal(bridge.summarize(missing,NOW),null);
});

test('risk values must be measured, finite, bounded and never guessed from labels', () => {
  const a=bridge.summarize(feed([
    entry({id:'missing',risk_score:null,severity:'UNKNOWN',title:'Routine patch update'}),
    entry({id:'string',risk_score:'9.4',severity:'LOW',title:'Routine patch update'}),
    entry({id:'outlier',risk_score:80,severity:'LOW',title:'Routine patch update'})
  ]),NOW);
  assert.equal(a.triage_count,0);
});

test('homepage mounts read-only bridge into all four impacted sections', () => {
  const html=fs.readFileSync(path.join(__dirname,'../index.html'),'utf8');
  const bridgeScript=fs.readFileSync(path.join(__dirname,'../js/dashboard-evidence-bridge.js'),'utf8');
  assert.match(html, /<script src="\/js\/dashboard-evidence-bridge\.js\?v=p0-20261019"><\/script>/);
  assert.match(html, /id="tipsoar-live-evidence-anchor"/);
  for(const anchor of ['cdb-apt-list','genesis-attack-flows','bughunter-grid','tipsoar-live-evidence-anchor']) {
    assert.ok(bridgeScript.includes("panel('"+anchor+"'"), 'missing bridge anchor: '+anchor);
  }
  assert.match(bridgeScript,/fetch\('\/api\/feed\.json'/);
  assert.match(bridgeScript,/REFRESH_MS = 15 \* 60 \* 1000/);
  assert.doesNotMatch(bridgeScript, /r2 object put|fetch\([^)]*method:\s*['"]POST|executePlaybook\(/i);
});
