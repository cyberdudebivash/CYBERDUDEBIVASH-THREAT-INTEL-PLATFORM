import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { evaluatePublicationGate } from '../workers/intel-gateway/src/publication-gate.js';
import { resolveCertification, CERTIFICATION_POLICY_VERSION } from
  '../workers/intel-gateway/src/certification-registry.js';
import { FEED_ORDER, replayCertificationSnapshots as replay } from
  '../scripts/certification_registry_replay.mjs';

const id1='intel--'+'a'.repeat(24), id2='intel--'+'b'.repeat(24);
const readyItem={
  id:id1,title:'CVE-2026-99999: Critical RCE in Example Product',
  severity:'CRITICAL',description:'A'.repeat(200),
  cvss_score:9.8,risk_score:9.8,kev_present:true,epss_score:0.85,
  evidence_chain:{reliability_code:'A',source_reliability:'HIGH',source_name:'Vendor Advisory'},
  iocs:[{value:'192.0.2.1',type:'ip',response_guidance:'Block at firewall'}],
  ioc_count:1,ttps:['T1190'],mitre_techniques:['T1190'],
  detection_bundle:[{type:'sigma',rule:'title: Example Detection'}],
  executive_summary:'Critical vulnerability requiring immediate patching.',
  exec_summary:'Critical vulnerability requiring immediate patching.',
  source_url:'https://vendor.example.com/advisory/2026-99999',
  confidence:0.9,apex:{ai_summary:'AI narrative.',kev_listed:true},
};
const lowQuality={id:id2,title:'Under-evidenced report',description:'Short.',severity:'HIGH'};
assert.equal(evaluatePublicationGate(readyItem).customer_ready,true,
  'Fixture must pass real publication engine rather than a fake grade');

const feedSet=(items=[])=>Object.fromEntries(FEED_ORDER.map(name=>[name,{items}]));
const catalog=(ids=[id1])=>({reports:ids.map(id=>({id}))});
const certIndex=(records={})=>({
  schema_version:'1.0.0',policy_version:CERTIFICATION_POLICY_VERSION,records,
});
const perform=(entries=[id1], feeds=feedSet(), records={})=>replay({
  catalog:catalog(entries),certificationIndex:certIndex(records),feeds,
});

test('unresolved entry without valid persisted certificate is NOT_EVALUATED',()=>{
  const result=perform();
  assert.equal(result.verdict,'LOCAL_WITHHELD_OR_NOT_EVALUATED');
  assert.equal(result.outside_feed_windows,1);
  assert.equal(result.publication_status_counts.NOT_EVALUATED,1);
  assert.equal(result.cloudflare_requests,0);
  assert.equal(result.customer_release_certified,false);
});
test('real engine approves complete verified fixture but local replay is not customer delivery',()=>{
  const r=perform([id1],feedSet([readyItem]));
  assert.equal(r.verdict,'LOCAL_ALL_READY_NOT_DELIVERY_CERTIFIED');
  assert.equal(r.publication_status_counts.CUSTOMER_READY,1);
  assert.equal(r.re_evaluated_from_source,1);
  assert.equal(r.report_http_delivery_certified,false);
  assert.equal(r.customer_release_certified,false);
});
test('valid persisted certificate can be reused without matching rolling feed',()=>{
  const original=resolveCertification(undefined,readyItem);
  assert.equal(original.record.publication_status,'CUSTOMER_READY');
  const r=perform([id1],feedSet(),{[id1]:original.record});
  assert.equal(r.persisted_records_reused,1);
  assert.equal(r.persisted_customer_ready_without_feed,1);
  assert.equal(r.outside_feed_windows,1);
  assert.equal(r.production_r2_state_verified,false);
  assert.equal(r.customer_release_certified,false);
});
test('legacy unproven CUSTOMER_READY record does not silently authorize historical report',()=>{
  const forged={certification_status:'CERTIFIED',publication_status:'CUSTOMER_READY'};
  const r=perform([id1],feedSet(),{[id1]:forged});
  assert.equal(r.publication_status_counts.NOT_EVALUATED,1);
  assert.equal(r.persisted_records_reused,0);
});
test('changed content invalidates persisted certified fingerprint; real engine rejects',()=>{
  const approved=resolveCertification(undefined,readyItem).record;
  const changed={...readyItem,description:'Short.',evidence_chain:undefined,
    iocs:[],ioc_count:0,detection_bundle:[],source_url:undefined};
  const r=perform([id1],feedSet([changed]),{[id1]:approved});
  assert.equal(r.persisted_records_reused,0);
  assert.equal(r.re_evaluated_from_source,1);
  assert.equal(r.publication_status_counts.CUSTOMER_READY,0);
  assert.equal(r.customer_release_certified,false);
});
test('first feed source wins even when a later feed contains stronger evidence',()=>{
  const truncated={id:id1,title:'under-evidenced projection',severity:'HIGH',description:'Short.'};
  const feeds=feedSet();
  feeds.latest_pro={items:[truncated]};
  feeds.latest={items:[readyItem]};
  const r=perform([id1],feeds);
  assert.equal(r.first_source_counts.latest_pro,1);
  assert.equal(r.first_source_counts.latest,0);
  assert.equal(r.publication_status_counts.CUSTOMER_READY,0);
});
test('two reports produce distinct NOT_EVALUATED and rejected reason buckets',()=>{
  const feeds=feedSet([lowQuality]);
  const r=perform([id1,id2],feeds);
  assert.equal(r.catalog_candidates,2);
  assert.equal(r.publication_status_counts.NOT_EVALUATED,1);
  assert.equal(r.publication_status_counts.CUSTOMER_READY,0);
});
test('duplicate and malformed catalog IDs are rejected not deduplicated',()=>{
  assert.throws(()=>perform([id1,id1],feedSet()),/INVALID_OR_DUPLICATE/);
  assert.throws(()=>perform(['not-an-id'],feedSet()),/INVALID_OR_DUPLICATE/);
});
test('missing any source or certification index is an incomplete snapshot',()=>{
  const feeds=feedSet(); delete feeds.apex;
  assert.throws(()=>replay({catalog:catalog(),feeds,certificationIndex:certIndex()}),
    /INCOMPLETE_OR_UNTRUSTED/);
  assert.throws(()=>replay({catalog:catalog(),feeds:feedSet(),certificationIndex:{records:{}}}),
    /INCOMPLETE_OR_UNTRUSTED/);
});
test('replay rejects malformed feed rows and empty catalog',()=>{
  const feeds=feedSet();feeds.latest={items:[null]};
  assert.throws(()=>replay({catalog:catalog(),feeds,certificationIndex:certIndex()}),/INVALID_LATEST_ROWS/);
  assert.throws(()=>perform([],feedSet()),/EMPTY_REPORT_CATALOG/);
});
test('CLI no snapshots is BLOCKED, makes zero network requests',()=>{
  const url=new URL('../scripts/certification_registry_replay.mjs',import.meta.url);
  const child=spawnSync(process.execPath,[fileURLToPath(url)],{
    encoding:'utf8',timeout:10000,
  });
  assert.equal(child.status,2);
  const verdict=JSON.parse(child.stdout);
  assert.equal(verdict.verdict,'BLOCKED_INVALID_LOCAL_EVIDENCE');
  assert.equal(verdict.cloudflare_requests,0);
  assert.equal(verdict.customer_release_certified,false);
});
