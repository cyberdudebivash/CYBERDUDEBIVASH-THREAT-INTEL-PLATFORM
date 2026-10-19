import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  ORIGIN, CATALOG_PATH, approvedReportPath, evaluatePublicReportCatalog,
  fetchPublic, runPublicReportFetchback
} from '../scripts/customer_report_fetchback_probe.mjs';

const id1='intel--'+'a'.repeat(24), id2='intel--'+'b'.repeat(24);
const one={id:id1,path:'/reports/2026/10/'+id1+'.html',
  url:ORIGIN+'/reports/2026/10/'+id1+'.html'};
const two={id:id2,path:'/reports/2026/10/'+id2+'.html'};
const catalog=()=>({
  schema_version:'2.0.0',feed_type:'customer_ready_catalog',
  generated_at:new Date(Date.now()-60_000).toISOString(), validated_at:new Date().toISOString(),
  policy_version:'1.0.0',total_candidates:3,customer_ready_count:2,
  withheld_count:1,total_reports:3,reports_listed:2,reports:[one,two],
});
const response=(body,status=200,mime='application/json')=>
  new Response(body,{status,headers:{'content-type':mime}});
const fake=(cat, overrides={})=>async (url, opts)=>{
  assert.equal(opts.method,'GET');
  assert.equal(opts.redirect,'error');
  assert.ok(url.startsWith(ORIGIN+'/'));
  const path=new URL(url).pathname;
  if (path===CATALOG_PATH) return response(JSON.stringify(cat));
  if (overrides[path]) return overrides[path];
  return response('<html><body>'+decodeURIComponent(path)+'</body></html>',200,'text/html');
};
test('current live-like 0/52 is BLOCKED, regardless of advisory health',()=>{
 const c=catalog();c.total_candidates=52;c.total_reports=52;c.customer_ready_count=0;c.withheld_count=52;
 c.reports_listed=0;c.reports=[];
 const r=evaluatePublicReportCatalog(c);
 assert.equal(r.verdict,'BLOCKED');
 assert.ok(r.issues.includes('ZERO_CUSTOMER_READY_REPORTS'));
 assert.equal(r.customer_release_certified,false);
});
test('no candidates is never treated as commercial success',()=>{
 const c=catalog();c.total_candidates=0;c.total_reports=0;c.customer_ready_count=0;
 c.withheld_count=0;c.reports_listed=0;c.reports=[];
 assert.ok(evaluatePublicReportCatalog(c).issues.includes('NO_REPORT_CANDIDATES'));
});
test('valid structured ready catalog requires actual URL verification',()=>{
 const r=evaluatePublicReportCatalog(catalog());
 assert.equal(r.verdict,'PUBLIC_REPORT_FETCHBACK_REQUIRED');
 assert.equal(r.exit_code,0);
 assert.equal(r.candidate_paths.length,2);
 assert.equal(r.all_reports_delivered_certified,false);
});
test('counts must be integer, non-negative, and internally reconciled',()=>{
 const c=catalog();c.total_candidates=2.3;c.withheld_count=-1;c.reports_listed=1;
 const r=evaluatePublicReportCatalog(c);
 assert.equal(r.exit_code,2);
 assert.ok(r.issues.some(i=>i.includes('INVALID_CATALOG_COUNT')));
 assert.ok(r.issues.includes('CATALOG_LISTED_COUNT_MISMATCH'));
});
test('ready reports cannot exceed listed evidence',()=>{
 const c=catalog();c.reports_listed=0;c.reports=[];
 const r=evaluatePublicReportCatalog(c);
 assert.ok(r.issues.includes('READY_REPORTS_NOT_LISTED'));
});
test('malformed or cross-domain report URL is never fetched',()=>{
 assert.equal(approvedReportPath({...one,url:'https://evil.example/reports/2026/10/'+id1+'.html'}),null);
 assert.equal(approvedReportPath({...one,path:'/reports/2026/10/'+id1+'.html?x=1'}),null);
 assert.equal(approvedReportPath({...one,id:id2}),null);
 assert.equal(approvedReportPath({...one,path:'/reports/2026/10/../'+id1+'.html'}),null);
 assert.equal(approvedReportPath({...one,path:'/reports/2026/10/%2e%2e.html'}),null);
});
test('duplicates and untrusted entries invalidate entire release probe',()=>{
 const c=catalog();c.reports=[one,one];c.reports_listed=2;
 assert.ok(evaluatePublicReportCatalog(c).issues.includes('INVALID_OR_DUPLICATE_REPORT_LOCATOR'));
});
test('sample budget cannot trigger bulk catalogue crawling',()=>{
 assert.throws(()=>evaluatePublicReportCatalog(catalog(),{sampleSize:4}),RangeError);
 assert.throws(()=>evaluatePublicReportCatalog(catalog(),{sampleSize:0}),RangeError);
});
test('malformed JSON and wrong catalog MIME block without fetching reports',async()=>{
 let count=0;
 const fetchFn=async()=>{count++;return response('{bad');};
 const r=await runPublicReportFetchback({fetchFn});
 assert.equal(count,1);assert.equal(r.exit_code,2);
 assert.equal(r.verdict,'INCONCLUSIVE_CATALOG_UNAVAILABLE');
});
test('a valid report sample demonstrates public fetch-back, NOT customer release',async()=>{
 let count=0;const base=fake(catalog());
 const r=await runPublicReportFetchback({fetchFn:async(...args)=>{count++;return base(...args)}});
 assert.equal(count,3);assert.equal(r.exit_code,0);
 assert.equal(r.verdict,'PUBLIC_REPORT_SAMPLE_PASS_NOT_CUSTOMER_RELEASE');
 assert.equal(r.public_report_sample_certified,true);
 assert.equal(r.customer_release_certified,false);
 assert.equal(r.paid_entitlement_certified,false);
});
test('404 on a customer-ready report fails closed even when health elsewhere is OK',async()=>{
 const r=await runPublicReportFetchback({fetchFn:fake(catalog(),{
  [one.path]:response('not found',404,'text/plain')
 })});
 assert.equal(r.exit_code,2);assert.equal(r.verdict,'BLOCKED_REPORT_FETCHBACK');
 assert.equal(r.probes[0].status,'FAIL');
});
test('200 with false-generic HTML missing canonical report ID does not certify',async()=>{
 const r=await runPublicReportFetchback({fetchFn:fake(catalog(),{
  [one.path]:response('<html>temporary landing page</html>',200,'text/html')
 })});
 assert.equal(r.exit_code,2);assert.equal(r.probes[0].status,'FAIL');
});
test('200 JSON at report URL is not accepted as delivered report HTML',async()=>{
 const r=await runPublicReportFetchback({fetchFn:fake(catalog(),{
  [one.path]:response(JSON.stringify({id:id1}),200,'application/json')
 })});
 assert.equal(r.exit_code,2);assert.equal(r.probes[0].status,'FAIL');
});
test('neither paid endpoints nor arbitrary origins may be probed',async()=>{
 await assert.rejects(fetchPublic('/api/health',fake(catalog())),/UNAPPROVED_PATH/);
 await assert.rejects(fetchPublic('https://evil.example/',fake(catalog())),/UNAPPROVED_PATH/);
});
test('actual empty ready catalog makes only ONE GET and returns BLOCKED',async()=>{
 const c=catalog();c.total_candidates=52;c.total_reports=52;
 c.customer_ready_count=0;c.withheld_count=52;c.reports=[];c.reports_listed=0;
 let calls=0;
 const r=await runPublicReportFetchback({fetchFn:async(...args)=>{calls++;return fake(c)(...args)}});
 assert.equal(calls,1);
 assert.equal(r.verdict,'BLOCKED');
 assert.ok(r.issues.includes('ZERO_CUSTOMER_READY_REPORTS'));
 assert.equal(r.public_report_sample_certified,false);
});

test('stale generated catalog cannot authorize even a reachable report',async()=>{
  const c=catalog(); c.generated_at=new Date(Date.now()-48*3600_000).toISOString();
  const r=evaluatePublicReportCatalog(c);
  assert.equal(r.verdict,'BLOCKED');
  assert.ok(r.issues.includes('CATALOG_GENERATED_STALE'));
  let calls=0;
  const result=await runPublicReportFetchback({fetchFn:async (...args)=>{
    calls++; return fake(c)(...args);
  }});
  assert.equal(calls,1);
  assert.equal(result.public_report_sample_certified,false);
});
test('stale validated timestamp fails closed independently',()=>{
  const c=catalog(); c.validated_at=new Date(Date.now()-48*3600_000).toISOString();
  const r=evaluatePublicReportCatalog(c);
  assert.equal(r.exit_code,2);
  assert.ok(r.issues.includes('CATALOG_VALIDATED_STALE'));
});
test('validation cannot precede catalog generation',()=>{
  const c=catalog();
  const now=Date.now();
  c.generated_at=new Date(now-3600_000).toISOString();
  c.validated_at=new Date(now-2*3600_000).toISOString();
  assert.ok(evaluatePublicReportCatalog(c).issues.includes('CATALOG_VALIDATION_PRECEDES_GENERATION'));
});
test('ambiguous, malformed and future-dated catalog timestamps fail closed',()=>{
  const c=catalog(); c.generated_at='2026-10-19T10:19:08';
  assert.ok(evaluatePublicReportCatalog(c).issues.includes('INVALID_CATALOG_GENERATED_AT'));
  const f=catalog(); f.validated_at=new Date(Date.now()+10*60_000).toISOString();
  assert.ok(evaluatePublicReportCatalog(f).issues.includes('CATALOG_VALIDATED_IN_FUTURE'));
  const x=catalog(); x.generated_at='not-a-timestamp';
  assert.equal(evaluatePublicReportCatalog(x).verdict,'BLOCKED');
});
test('canonical fresh v2 catalog remains a bounded fetch-back candidate',()=>{
  const c=catalog();
  const result=evaluatePublicReportCatalog(c);
  assert.equal(result.verdict,'PUBLIC_REPORT_FETCHBACK_REQUIRED');
  assert.equal(result.customer_release_certified,false);
});
