import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ORIGIN, FEEDS, MAX_STATUS_PROBES,
  classifyAuthoritativeStatus, auditAuthoritativePublicationSample
} from '../scripts/publication_gate_scan.mjs';

const IDS = ['a', 'b', 'c', 'd'].map(v=>'intel--'+v.repeat(24));
const statusPath=id=>'/api/v1/reports/'+id+'/publication-status';
const item=id=>({id, title:'Public summary; premium certification evidence intentionally removed'});
const response=(data,code=200,mime='application/json')=>new Response(JSON.stringify(data),{
  status:code, headers:{'content-type':mime}
});
const status=(id,ready=false)=>({
  report_id:id, state:ready?'CUSTOMER_READY':'REJECTED',
  customer_ready:ready, reason_codes:ready?[]:['P21_BELOW_MINIMUM','P26_REJECTED'],
});
const mocked=(routes,visited)=>async(url,options)=>{
  assert.equal(options.method,'GET');
  assert.equal(options.redirect,'error');
  assert.ok(url.startsWith(ORIGIN+'/'));
  const path=url.slice(ORIGIN.length);
  visited.push(path);
  return routes[path] || response({error:'not found'},404);
};
const routeSet=(ids=IDS.slice(0,2))=>{
  const routes={};
  for(const path of FEEDS) routes[path]=response({items:ids.map(item)});
  for(const id of ids) routes[statusPath(id)]=response(status(id));
  return routes;
};

test('uses independent Worker verdict, not missing redacted fields',async()=>{
  const visited=[];
  const r=await auditAuthoritativePublicationSample({
    fetchFn:mocked(routeSet(),visited)
  });
  assert.equal(r.verdict,'AUTHORITATIVE_SAMPLE_WITHHELD');
  assert.equal(r.exit_code,1);
  assert.equal(r.sample_reason_counts.P21_BELOW_MINIMUM,2);
  assert.equal(r.sample_reason_counts.P26_REJECTED,2);
  assert.equal(r.full_catalog_reasons_verified,false);
  assert.equal(r.customer_release_certified,false);
  assert.equal(r.sampled_statuses_from_worker,true);
  assert.equal(visited.length,FEEDS.length+2);
});
test('a public feed failure never turns remaining samples into known root causes',async()=>{
  const visited=[];
  const routes=routeSet();
  routes[FEEDS[1]]=response({error:'backend failed'},503);
  const r=await auditAuthoritativePublicationSample({fetchFn:mocked(routes,visited)});
  assert.equal(r.exit_code,2);
  assert.equal(r.verdict,'INCONCLUSIVE_AUTHORITY_SAMPLE');
  assert.deepEqual(r.sample_reason_counts,{});
  assert.equal(visited.length,FEEDS.length);
});
test('missing publication authority blocks reason attribution',async()=>{
  const visited=[];
  const routes=routeSet();
  routes[statusPath(IDS[0])]=response({error:'not found'},404);
  const r=await auditAuthoritativePublicationSample({fetchFn:mocked(routes,visited)});
  assert.equal(r.exit_code,2);
  assert.deepEqual(r.sample_reason_counts,{});
  assert.ok(r.issues.includes('PUBLICATION_STATUS_UNAVAILABLE_OR_INVALID'));
});
test('status cannot contradict its authorization state',()=>{
  assert.equal(classifyAuthoritativeStatus({...status(IDS[0]),customer_ready:true},IDS[0]),null);
  assert.equal(classifyAuthoritativeStatus({...status(IDS[0]),reason_codes:[]},IDS[0]),null);
  assert.equal(classifyAuthoritativeStatus({...status(IDS[0]),report_id:IDS[1]},IDS[0]),null);
  assert.equal(classifyAuthoritativeStatus({...status(IDS[0]),reason_codes:['<script>']},IDS[0]),null);
});
test('valid ready sample does not certify paid or complete customer release',async()=>{
  const ids=IDS.slice(0,1),routes=routeSet(ids);
  routes[statusPath(ids[0])]=response(status(ids[0],true));
  const r=await auditAuthoritativePublicationSample({fetchFn:mocked(routes,[])});
  assert.equal(r.verdict,'AUTHORITATIVE_SAMPLE_READY_NOT_RELEASE');
  assert.equal(r.exit_code,0);
  assert.equal(r.customer_release_certified,false);
  assert.equal(r.paid_entitlement_certified,false);
  assert.equal(r.full_catalog_reasons_verified,false);
});
test('fixed request ceiling: three feed GETs and at most three status GETs',async()=>{
  const visited=[];
  const routes=routeSet(IDS);
  const r=await auditAuthoritativePublicationSample({fetchFn:mocked(routes,visited)});
  assert.equal(r.sampled,MAX_STATUS_PROBES);
  assert.ok(visited.length<=FEEDS.length+MAX_STATUS_PROBES);
  assert.ok(visited.every(p=>FEEDS.includes(p)||p.startsWith('/api/v1/reports/')));
  assert.equal(visited.length,FEEDS.length+MAX_STATUS_PROBES);
});
test('malformed or non-JSON status is inconclusive, not quality evidence',async()=>{
  const routes=routeSet(IDS.slice(0,1));
  routes[statusPath(IDS[0])]=response({html:'not JSON'},200,'text/html');
  const r=await auditAuthoritativePublicationSample({fetchFn:mocked(routes,[])});
  assert.equal(r.verdict,'INCONCLUSIVE_AUTHORITY_SAMPLE');
  assert.deepEqual(r.sample_reason_counts,{});
});
test('missing advisory IDs prevent certification, and no status probes run',async()=>{
  const routes=routeSet(IDS.slice(0,1));routes[FEEDS[0]]=response({items:[{}]});
  const seen=[];
  const r=await auditAuthoritativePublicationSample({fetchFn:mocked(routes,seen)});
  assert.equal(r.exit_code,2);
  assert.ok(r.issues.includes('PUBLIC_FEED_ID_UNPROVEN'));
  assert.equal(seen.length,FEEDS.length);
});
