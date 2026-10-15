const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function harness() {
 const source = fs.readFileSync(require('node:path').join(__dirname, '../js/homepage-dashboard-engine.js'), 'utf8');
 const nodes = {};
 for (const id of ['ts-incident-count','ts-incident-feed','tipsoar-badge','ts-response-count','ts-response-feed','ts-hunt-count','ts-playbook-count','ts-hunt-feed','ts-campaign-feed']) {
  let html = '', text = '';
  nodes[id] = {style:{}, get innerHTML(){return html;}, set innerHTML(v){html=v; text='';}, get textContent(){return text;}, set textContent(v){text=v;html='';}};
 }
 const ctx = {document:{getElementById:id=>nodes[id]}, console:{warn:(...args)=>{throw new Error(String(args));}}};
 vm.runInNewContext(source.slice(source.indexOf('function tipText('), source.indexOf('// ── AI EXECUTION LAYER v103')), ctx);
 return {nodes, ctx};
}
test('all incident, response, hunt and campaign fields escape injected markup',()=>{
 const {nodes,ctx}=harness(); const x='<img src=x onerror="alert(1)">';
 ctx.renderIncidentEngine({total_incidents:1, incidents:[{severity:x,title:x,threat_actor:x}]});
 ctx.renderResponseEngine({total_actions:1,response_actions:[{action_type:x}]});
 ctx.renderHuntEngine({total_hunts:1,hunt_hypotheses:[{priority:x,technique:x,hypothesis:x,confidence:x}],campaign_intelligence:[{campaign_name:x,campaign_id:x,actors_involved:[x],incident_count:x,avg_risk:x,techniques_observed:[x]}]});
 for (const id of ['ts-incident-feed','ts-response-feed','ts-hunt-feed','ts-campaign-feed']) {
  assert.ok(!nodes[id].innerHTML.includes('<img'),id);
  assert.ok(nodes[id].innerHTML.includes('&lt;'),id);
 }
});
test('prototype-named action types remain ordinary safe text with numeric counts',()=>{
 const {nodes,ctx}=harness();ctx.renderResponseEngine({response_actions:[{action_type:'__proto__'},{action_type:'constructor'},{action_type:'toString'},{action_type:'__proto__'}]});
 assert.ok(nodes['ts-response-feed'].innerHTML.includes('CONSTRUCTOR'));
 assert.ok(nodes['ts-response-feed'].innerHTML.includes('>2</span>'));
 assert.ok(!nodes['ts-response-feed'].innerHTML.includes('[object'));
});
test('malformed records are isolated and render work is bounded',()=>{
 const {nodes,ctx}=harness();
 ctx.renderIncidentEngine({incidents:Array.from({length:1000},()=>({title:'safe'}))});
 assert.equal((nodes['ts-incident-feed'].innerHTML.match(/<div /g)||[]).length,12);
 ctx.renderResponseEngine({response_actions:[null,42,[],{}, {action_type:'block_ip'}]});
 assert.ok(nodes['ts-response-feed'].innerHTML.includes('BLOCK IP'));
 ctx.renderHuntEngine({hunt_hypotheses:[null,{}, {hypothesis:44}],campaign_intelligence:[null,{}, {campaign_name:42,actors_involved:42,techniques_observed:{}}]});
 assert.ok(nodes['ts-campaign-feed'].innerHTML.includes('Awaiting attribution'));
});
test('empty refresh clears old records rather than retaining stale customer evidence',()=>{
 const {nodes,ctx}=harness();ctx.renderIncidentEngine({incidents:[{title:'old'}]});ctx.renderIncidentEngine({incidents:{}});
 assert.equal(nodes['ts-incident-feed'].innerHTML,'');
 assert.equal(nodes['ts-incident-feed'].textContent,'Awaiting validated records.');
 ctx.renderResponseEngine({response_actions:[{action_type:'block_ip'}]});ctx.renderResponseEngine({response_actions:[]});
 assert.equal(nodes['ts-response-feed'].innerHTML,'');
 ctx.renderHuntEngine({hunt_hypotheses:[{hypothesis:'old'}]});ctx.renderHuntEngine({hunt_hypotheses:'bad'});
 assert.equal(nodes['ts-hunt-feed'].innerHTML,'');
});
test('legacy completed actions display as proposals and type counts never copy incidents',()=>{
 const {nodes,ctx}=harness();nodes['ts-incident-count'].textContent='999';
 ctx.renderResponseEngine({total_actions:999,response_actions:[{action_type:'block_ip',status:'COMPLETED',automated:true},{action_type:'block_ip'},{action_type:'patch_vulnerability'}]});
 assert.equal(nodes['ts-response-count'].textContent,'3');
 assert.equal(nodes['ts-playbook-count'].textContent,'2');
 ctx.renderHuntEngine({hunt_hypotheses:[]});
 assert.equal(nodes['ts-playbook-count'].textContent,'2');
});
test('a generated_at older than 7 days is not shown as a current hunt, incident or response',()=>{
 const {nodes,ctx}=harness();
 const stale='2020-01-01T00:00:00Z';
 ctx.renderHuntEngine({generated_at:stale,total_hunts:3,hunt_hypotheses:[{priority:'HIGH',technique:'T1547.001',hypothesis:'Remote access trojan persistence',confidence:87}],campaign_intelligence:[{campaign_name:'turla_ops',campaign_id:'CAMP',actors_involved:['Turla'],incident_count:2,avg_risk:8,techniques_observed:['T1003']}]});
 assert.equal(nodes['ts-hunt-count'].textContent,'0');
 assert.match(nodes['ts-hunt-feed'].textContent,/older than 7 days/);
 assert.equal(nodes['ts-hunt-feed'].innerHTML,'');
 assert.match(nodes['ts-campaign-feed'].textContent,/No current campaign measurement/);
 ctx.renderIncidentEngine({generated_at:stale,total_incidents:40,incidents:[{severity:'CRITICAL',title:'old incident',threat_actor:'Turla'}]});
 assert.equal(nodes['ts-incident-count'].textContent,'0');
 assert.equal(nodes['tipsoar-badge'].textContent,'HISTORICAL INCIDENT FILE');
 assert.match(nodes['ts-incident-feed'].textContent,/not shown as current/);
 ctx.renderResponseEngine({generated_at:stale,response_actions:[{action_type:'block_ip'}]});
 assert.equal(nodes['ts-response-count'].textContent,'0');
 assert.equal(nodes['ts-playbook-count'].textContent,'Not current');
 ctx.renderHuntEngine({generated_at:new Date().toISOString(),total_hunts:1,hunt_hypotheses:[{priority:'HIGH',technique:'T1190',hypothesis:'measured title',confidence:80}]});
 assert.match(nodes['ts-hunt-feed'].innerHTML,/CONF 80%/);
});
