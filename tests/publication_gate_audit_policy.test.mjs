import test from 'node:test';
import assert from 'node:assert/strict';
import { summarizePublicationGate } from '../scripts/publication_gate_audit_policy.mjs';
const endpoints=['/latest','/top10','/apex'];
const good={ report_id:'intel--aaaaaaaaaaaaaaaa',publication_state:'CUSTOMER_READY',customer_ready:true,blocking_gates:[] };
const rejected={ report_id:'intel--bbbbbbbbbbbbbbbb',publication_state:'REJECTED',customer_ready:false,blocking_gates:['P21_BELOW_MINIMUM','P26_REJECTED'] };
const cfg=(results,successfulEndpoints=endpoints,errors=[])=>({results, successfulEndpoints,expectedEndpoints:endpoints,errors});
test('complete healthy local gate does not assert published-object delivery',()=>{
 const o=summarizePublicationGate(cfg([good]));
 assert.equal(o.verdict,'LOCAL_GATE_PRECHECK_ONLY'); assert.equal(o.exit_code,0); assert.equal(o.report_delivery_certified,false);
});
test('all fetches fail must not silently return successful scan',()=>{
 const o=summarizePublicationGate(cfg([],[],['HTTP 503','HTTP 503','HTTP 503']));
 assert.equal(o.exit_code,2); assert.equal(o.verdict,'INCONCLUSIVE_INCOMPLETE_AUDIT');
 assert.equal(o.endpoints_missing.length,3);
});
test('one endpoint missing causes inconclusive despite a ready record',()=>{
 const o=summarizePublicationGate(cfg([good],['/latest','/top10']));
 assert.equal(o.exit_code,2); assert.deepEqual(o.endpoints_missing,['/apex']);
});
test('complete empty response fails instead of green',()=>{
 assert.equal(summarizePublicationGate(cfg([])).exit_code,2);
});
test('correctly aggregates blocking reasons without fake public URLs',()=>{
 const o=summarizePublicationGate(cfg([good,rejected]));
 assert.equal(o.exit_code,1);assert.equal(o.rejected,1);assert.equal(o.customer_ready,1);
 assert.equal(o.reason_counts.P21_BELOW_MINIMUM,1);assert.equal(o.reason_counts.P26_REJECTED,1);
 assert.equal(o.withheld_samples[0].report_id,rejected.report_id);
 assert.ok(!('publicly_accessible_url' in o.withheld_samples[0]));
});
test('inconsistent customer_ready and state fails closed',()=>{
 const o=summarizePublicationGate(cfg([{...good,customer_ready:false}]));
 assert.equal(o.exit_code,2);assert.equal(o.malformed_or_conflicting,1);
});
test('duplicate IDs are not double-counted or treated as certified',()=>{
 const o=summarizePublicationGate(cfg([good,good]));
 assert.equal(o.exit_code,2);assert.equal(o.malformed_or_conflicting,1);
});
test('missing blockers and invalid blocker shapes fail closed',()=>{
 const o=summarizePublicationGate(cfg([{...rejected,blocking_gates:[]},{...rejected,report_id:'intel--cccccccccccccccc',blocking_gates:['<script>']}]));
 assert.equal(o.exit_code,2);assert.equal(o.malformed_or_conflicting,2);
});
test('missing or invalid input arrays are rejected',()=>{
 assert.throws(()=>summarizePublicationGate({results:{},successfulEndpoints:[],expectedEndpoints:[]}),TypeError);
});
