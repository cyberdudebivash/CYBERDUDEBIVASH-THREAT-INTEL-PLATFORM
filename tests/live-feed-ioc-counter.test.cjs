const test = require('node:test');
const assert = require('node:assert/strict');
const snapshot = require('../js/apex-dashboard-snapshot.js');
test('IOC counter accepts numeric strings and dictionary-only evidence', () => {
 assert.equal(snapshot.iocContribution({ioc_count:'14'}),14);
 assert.equal(snapshot.iocContribution({iocs:[],ioc_counts:{ipv4:'3',domain:2}}),5);
 assert.equal(snapshot.iocContribution({indicators:[{value:'a'},{value:'b'}]}),2);
});
test('IOC counter preserves verified zero and never double-counts representations', () => {
 assert.equal(snapshot.iocContribution({ioc_count:0,ioc_counts:{domain:7}}),0);
 assert.equal(snapshot.iocContribution({ioc_count:3,iocs:['a','b','c']}),3);
});
test('IOC counter excludes malformed and negative counters', () => {
 for (const value of [null,false,'',-3,Infinity,'bogus',1.5]) {
  assert.equal(snapshot.iocContribution({ioc_count:value,ioc_counts:{domain:2}}),2);
 }
 assert.equal(snapshot.iocContribution({ioc_counts:{domain:-3,ipv4:'2',url:'bad'}}),2);
});
const fs = require('node:fs');
const vm = require('node:vm');
test('footer consumes live shared snapshot rather than a second stats source', () => {
 const html = fs.readFileSync(require('node:path').join(__dirname, '../index.html'), 'utf8');
 const start = html.indexOf('function renderCounts(state)');
 assert.ok(start >= 0);
 const consumer = html.slice(start, html.indexOf('snapshot.load()', start));
 assert.match(consumer, /state.mode !== 'live'/);
 assert.match(consumer, /stats\[1\]\.val\s*=\s*intel.iocs/);
 assert.match(consumer, /snapshot.subscribe\(renderCounts\)/);
});
test('saved recon shows measured counts, absence states and scan provenance', () => {
 const source = fs.readFileSync(require('node:path').join(__dirname, '../js/homepage-dashboard-engine.js'), 'utf8');
 const start = source.indexOf('function bugHunterScanView(data, nowMs)');
 const end = source.indexOf('// ── TIP+SOAR RENDERERS', start);
 const nodes = {};
 for (const id of ['bh-api-count','bh-critical-count','bh-health-badge']) nodes[id] = {style:{}};
 const context = {document:{getElementById:id=>nodes[id]||null, querySelector:()=>null},console,
  Date:class extends Date { static now(){return Date.parse('2026-10-07T05:00:00Z');} }};
 vm.runInNewContext(source.slice(start,end) + ';this.render=renderBugHunterEngine;',context);
 context.render({status:'COMPLETED',metrics:{api_endpoints:0,critical_findings:'3'},timestamp:'2026-10-06T12:00:00Z',domain:'example.test'});
 assert.equal(nodes['bh-api-count'].textContent,'No observations in scan');
 assert.equal(nodes['bh-critical-count'].textContent,'3');
 assert.match(nodes['bh-health-badge'].textContent,/SCAN SNAPSHOT.*2026-10-06/);
 assert.match(nodes['bh-health-badge'].title,/example.test/);
 context.render({status:'COMPLETED',metrics:{api_endpoints:12,critical_findings:3},timestamp:'2026-08-25T18:02:45.017Z'});
 assert.equal(nodes['bh-api-count'].textContent,'Re-scan required');
 assert.equal(nodes['bh-critical-count'].textContent,'Re-scan required');
 assert.match(nodes['bh-health-badge'].textContent,/HISTORICAL.*2026-08-25/);
 for (const value of [null,false,'',-1,'bad']) {
  context.render({metrics:{api_endpoints:value,critical_findings:value}});
  assert.equal(nodes['bh-api-count'].textContent,'Awaiting scan');
  assert.equal(nodes['bh-critical-count'].textContent,'Awaiting scan');
 }
 assert.match(nodes['bh-health-badge'].textContent,/SCAN PROVENANCE REQUIRED/);
});
test('nexus hunts quote measured advisories and do not invent a hypothesis', () => {
 const source = fs.readFileSync(require('node:path').join(__dirname, '../js/homepage-dashboard-engine.js'), 'utf8');
 assert.equal(source.includes('Insufficient high-risk data for hunt generation'), false);
 assert.equal(source.includes('Supply-chain compromise via trusted update mechanisms'), false);
 assert.ok(source.includes('Measured from advisories at risk 7.0 or above. Not a generated hypothesis.'));
 assert.ok(source.includes('No advisory at risk 7.0 or above in this feed.'));
});
