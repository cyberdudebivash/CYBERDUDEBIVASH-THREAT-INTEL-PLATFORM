import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
const require = createRequire(import.meta.url);
const { evaluate, approvedLocator } = require('../js/customer-report-catalog-view.js');
const ORIGIN = 'https://intel.cyberdudebivash.com';
const NOW = Date.parse('2026-10-24T06:00:00Z');
const id = 'intel--' + 'a'.repeat(24);
const path = '/reports/2026/10/' + id + '.html';
const report = { id, path, url: ORIGIN + path, title: 'Reviewed report', severity: 'HIGH', risk_score: 7.5 };
const catalog = (override = {}) => ({
  schema_version: '2.0.0', feed_type: 'customer_ready_latest',
  generated_at: '2026-10-24T05:47:52Z', validated_at: '2026-10-24T05:57:09.320Z',
  total_candidates: 28, customer_ready_count: 0, withheld_count: 28,
  total_reports: 28, reports_listed: 0, reports: [],
  ...override
});

test('live-shaped zero ready catalog shows withheld count and zero links', () => {
  const view = evaluate(catalog(), NOW);
  assert.equal(view.state, 'WITHHELD');
  assert.equal(view.ready_count, 0);
  assert.equal(view.withheld_count, 28);
  assert.deepEqual(view.reports, []);
  assert.match(view.message, /No customer-ready reports/);
  assert.equal(view.view_all, false);
});

test('fresh advisory health must not authorize legacy report links', () => {
  const view = evaluate({ ...catalog({reports:[report], reports_listed:1}),
    schema_version:'1.0' }, NOW);
  assert.equal(view.state, 'UNVERIFIED');
  assert.deepEqual(view.reports, []);
  assert.equal(view.ready_count, null);
});

test('fully consistent customer-ready v2 entry permits only its canonical link', () => {
  const view = evaluate(catalog({
    total_candidates:2, customer_ready_count:1, withheld_count:1,
    total_reports:2, reports_listed:1, reports:[report]
  }), NOW);
  assert.equal(view.state, 'READY');
  assert.equal(view.ready_count, 1);
  assert.deepEqual(view.reports.map(r => r.url), [ORIGIN + path]);
  assert.equal(view.view_all, false);
});

test('partial ready catalog can advertise more ready entries but not withheld links', () => {
  const view = evaluate(catalog({
    total_candidates:3, customer_ready_count:2, withheld_count:1,
    total_reports:3, reports_listed:1, reports:[report]
  }), NOW);
  assert.equal(view.state,'READY');
  assert.equal(view.view_all,true);
});

test('reject malformed, external, and ambiguous report locators', () => {
  const bad = [
    {...report, url:'https://attacker.invalid'+path},
    {...report, path:'/reports/2026/10/../'+id+'.html'},
    {...report, path:'/reports/2026/10/%2e%2e.html'},
    {...report, id:'intel--nothex'},
    {...report, url:ORIGIN+path+'?export=paid'},
    {...report, path:'/reports/2026/10/'+id+'.html#x'},
  ];
  bad.forEach(entry => assert.equal(approvedLocator(entry), null));
  bad.forEach(entry => assert.equal(evaluate(catalog({
    total_candidates:1,customer_ready_count:1,withheld_count:0,
    total_reports:1,reports_listed:1,reports:[entry]
  }),NOW).state,'UNVERIFIED'));
});

test('reject duplicate and contradictory count evidence', () => {
  assert.equal(evaluate(catalog({total_candidates:27}),NOW).state,'UNVERIFIED');
  assert.equal(evaluate(catalog({customer_ready_count:1}),NOW).state,'UNVERIFIED');
  assert.equal(evaluate(catalog({
    total_candidates:2,customer_ready_count:2,withheld_count:0,
    total_reports:2,reports_listed:2,reports:[report,report]
  }),NOW).state,'UNVERIFIED');
  assert.equal(evaluate(catalog({reports_listed:1}),NOW).state,'UNVERIFIED');
});

test('reject stale, future, malformed or inverted validation timestamps', () => {
  const variations = [
    {generated_at:'2026-10-22T00:00:00Z'},
    {validated_at:'2026-10-25T00:00:00Z'},
    {generated_at:'2026-02-30T05:47:52Z'},
    {validated_at:'2026-10-24T05:00:00Z'},
    {validated_at:'2026-10-24T05:57:09'},
  ];
  variations.forEach(change =>
    assert.equal(evaluate(catalog(change),NOW).state,'UNVERIFIED'));
});

test('missing and empty catalog cannot produce report links', () => {
  assert.deepEqual(evaluate(null,NOW).reports,[]);
  assert.equal(evaluate(catalog({
    total_candidates:0,withheld_count:0,total_reports:0
  }), NOW).state,'NO_CANDIDATES');
});

test('homepage labels certification, not raw report candidate count, as availability', () => {
  const html=readFileSync(new URL('../index.html',import.meta.url),'utf8');
  assert.ok(html.includes('js/customer-report-catalog-view.js'));
  assert.ok(html.includes('CUSTOMER-READY'));
  assert.ok(html.includes('_cdbReportsView.ready_count'));
  assert.ok(!html.includes('reports are still accessible via direct links'));
});
