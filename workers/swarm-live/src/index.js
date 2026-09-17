const PROTOCOL = 'cdb.swarm.v1';
const PRODUCT = 'sentinel-apex';
const MAX_BODY_BYTES = 32 * 1024;
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const AGENTS = Object.freeze([
  ['ioc-hunter', 'IOC Hunter', 'ioc.correlation'],
  ['cve-intelligence', 'CVE Intelligence Agent', 'cve.analysis'],
  ['threat-hunter', 'Threat Hunter', 'threat.hunting'],
  ['attack-mapper', 'ATT&CK Mapper', 'attack.mapping'],
  ['siem-defender', 'SIEM Defender', 'siem.defense'],
  ['ir-playbook', 'Incident Response Playbook Agent', 'ir.playbook'],
  ['exposure-analyst', 'Exposure Analyst', 'exposure.analysis'],
  ['risk-synthesizer', 'Risk Synthesizer', 'risk.synthesis'],
].map(([id, name, capability]) => Object.freeze({ id, name, capability })));

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      ...extra,
    },
  });
}

function safeRequestId(request) {
  const supplied = request.headers.get('x-request-id') || '';
  return ID_RE.test(supplied) ? supplied : `sentinel-swarm-${crypto.randomUUID()}`;
}

function authHeaders(request) {
  const out = new Headers({ accept: 'application/json' });
  for (const name of ['authorization', 'x-api-key', 'x-sentinel-key']) {
    const value = request.headers.get(name);
    if (value) out.set(name, value);
  }
  return out;
}

function hasAuth(headers) {
  return Boolean(
    headers.get('authorization') ||
    headers.get('x-api-key') ||
    headers.get('x-sentinel-key')
  );
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function allMatches(correlation) {
  return Array.isArray(correlation?.matches) ? correlation.matches : [];
}

export function buildSentinelSpecialistResults(correlation) {
  const matches = allMatches(correlation);
  const cves = unique(matches.map((m) => m?.cve_id));
  const actors = unique(matches.map((m) => m?.actor_tag).filter((v) => v && v !== 'UNATTRIBUTED'));
  const techniques = unique(matches.flatMap((m) =>
    Array.isArray(m?.ttps)
      ? m.ttps.map((t) => typeof t === 'string' ? t : t?.technique_id || t?.id || t?.name)
      : []
  ));
  const severityCounts = matches.reduce((acc, m) => {
    const sev = String(m?.severity || 'unknown').toLowerCase();
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const riskScores = matches.map((m) => Number(m?.risk_score || 0)).filter(Number.isFinite);
  const maxRisk = riskScores.length ? Math.max(...riskScores) : 0;
  const verdict = correlation?.verdict || 'unknown';
  const recommendation = correlation?.recommendation || 'Review the canonical Sentinel correlation result.';

  const response = {
    'ioc-hunter': {
      verdict,
      match_count: Number(correlation?.match_count || matches.length || 0),
      ioc: correlation?.ioc || null,
      source: 'canonical:/api/intel/correlate',
    },
    'cve-intelligence': {
      cves,
      cve_count: cves.length,
      source_reports: unique(matches.filter((m) => m?.cve_id).map((m) => m?.report_id)),
    },
    'threat-hunter': {
      actors,
      actor_count: actors.length,
      matched_reports: unique(matches.map((m) => m?.report_id)),
      severity_distribution: severityCounts,
    },
    'attack-mapper': {
      techniques,
      technique_count: techniques.length,
      source_reports: unique(matches.filter((m) => Array.isArray(m?.ttps) && m.ttps.length).map((m) => m?.report_id)),
    },
    'siem-defender': {
      verdict,
      recommended_action: recommendation,
      matched_report_count: matches.length,
      highest_observed_risk: maxRisk,
    },
    'ir-playbook': {
      priority: verdict === 'malicious' ? 'P1' : verdict === 'suspicious' ? 'P2' : 'MONITOR',
      actions: verdict === 'malicious'
        ? ['contain indicator', 'hunt related observables', 'validate affected assets', 'preserve evidence']
        : verdict === 'suspicious'
          ? ['investigate related activity', 'enrich indicator', 'increase monitoring']
          : ['retain for watchlist correlation'],
      basis: 'canonical Sentinel verdict and matched intelligence',
    },
    'exposure-analyst': {
      max_risk_score: maxRisk,
      severity_distribution: severityCounts,
      affected_intelligence_records: matches.length,
    },
  };

  response['risk-synthesizer'] = {
    verdict,
    max_risk_score: maxRisk,
    cve_count: cves.length,
    actor_count: actors.length,
    technique_count: techniques.length,
    match_count: matches.length,
    recommendation,
    source: 'fusion of real specialist outputs derived from canonical Sentinel correlation',
  };

  return response;
}

function eventFactory({ missionId, executionId, correlationId }) {
  let sequence = 0;
  return (state, agent, payload = {}) => ({
    protocol: PROTOCOL,
    product: PRODUCT,
    mission_id: missionId,
    execution_id: executionId,
    correlation_id: correlationId,
    sequence: ++sequence,
    timestamp: new Date().toISOString(),
    state,
    agent_id: agent?.id || null,
    agent_name: agent?.name || null,
    capability: agent?.capability || null,
    ...payload,
  });
}

async function emit(writer, encoder, event) {
  await writer.write(encoder.encode(`event: swarm\ndata: ${JSON.stringify(event)}\n\n`));
}

function responseSnippet(body) {
  if (!body || typeof body !== 'object') return null;
  return {
    error: body.error || null,
    message: body.message || null,
    request_id: body.request_id || null,
  };
}

async function executeMission({ writer, request, env, body, correlationId, missionId, executionId }) {
  const encoder = new TextEncoder();
  const makeEvent = eventFactory({ missionId, executionId, correlationId });
  const canonicalBase = env.CANONICAL_BASE_URL || 'https://intel.cyberdudebivash.com';
  const auth = authHeaders(request);
  const queued = AGENTS.filter((a) => a.id !== 'risk-synthesizer');
  const synthesizer = AGENTS.find((a) => a.id === 'risk-synthesizer');

  try {
    await emit(writer, encoder, makeEvent('QUEUED', null, {
      event_type: 'mission.accepted',
      agent_count: AGENTS.length,
      input: { ioc_value: body.ioc_value, ioc_type: body.ioc_type || 'auto' },
    }));

    for (const agent of AGENTS) {
      await emit(writer, encoder, makeEvent('QUEUED', agent, { event_type: 'agent.queued' }));
    }

    await emit(writer, encoder, makeEvent('RUNNING', null, {
      event_type: 'canonical.correlation.started',
      source: '/api/intel/correlate',
    }));

    auth.set('content-type', 'application/json');
    auth.set('x-request-id', correlationId);

    const canonicalResponse = await fetch(`${canonicalBase}/api/intel/correlate`, {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({ ioc_value: body.ioc_value, ioc_type: body.ioc_type || 'auto' }),
    });

    const canonicalText = await canonicalResponse.text();
    let canonical = null;
    try { canonical = canonicalText ? JSON.parse(canonicalText) : null; } catch { /* handled below */ }

    const meshCertified = canonicalResponse.headers.get('x-cdb-mesh-certified') === 'true';
    const meshExecutionId = canonicalResponse.headers.get('x-cdb-mesh-execution');
    const meshCorrelationId = canonicalResponse.headers.get('x-cdb-mesh-correlation');

    if (!canonicalResponse.ok || !meshCertified || !meshExecutionId || meshCorrelationId !== correlationId || !canonical) {
      const state = canonicalResponse.status === 401 || canonicalResponse.status === 403 ? 'DENIED' : 'FAILED';
      await emit(writer, encoder, makeEvent(state, null, {
        event_type: 'mission.rejected',
        canonical_status: canonicalResponse.status,
        mesh_certified: meshCertified,
        canonical_error: responseSnippet(canonical),
      }));
      return;
    }

    await emit(writer, encoder, makeEvent('ADMITTED', null, {
      event_type: 'mesh.admitted',
      mesh_certified: true,
      mesh_execution_id: meshExecutionId,
    }));

    const specialistResults = buildSentinelSpecialistResults(canonical);

    const tasks = queued.map(async (agent) => {
      await emit(writer, encoder, makeEvent('RUNNING', agent, {
        event_type: 'agent.started',
        source: 'canonical:/api/intel/correlate',
      }));
      const result = specialistResults[agent.id];
      await emit(writer, encoder, makeEvent('COMPLETED', agent, {
        event_type: 'agent.completed',
        result,
      }));
      return result;
    });

    await Promise.all(tasks);

    await emit(writer, encoder, makeEvent('RUNNING', synthesizer, {
      event_type: 'agent.started',
      inputs: queued.map((a) => a.id),
    }));

    const fused = specialistResults['risk-synthesizer'];

    await emit(writer, encoder, makeEvent('COMPLETED', synthesizer, {
      event_type: 'agent.completed',
      result: fused,
    }));

    await emit(writer, encoder, makeEvent('COMPLETED', null, {
      event_type: 'mission.completed',
      mesh_certified: true,
      mesh_execution_id: meshExecutionId,
      canonical_status: canonicalResponse.status,
      canonical_request_id: canonical.request_id || null,
      result: fused,
    }));
  } catch (error) {
    await emit(writer, encoder, makeEvent('FAILED', null, {
      event_type: 'mission.failed',
      error: 'swarm_execution_failed',
      message: String(error?.message || error).slice(0, 240),
    })).catch(() => {});
  } finally {
    await writer.close().catch(() => {});
  }
}

async function handleRun(request, env, ctx) {
  const auth = authHeaders(request);
  if (!hasAuth(auth)) {
    return json({ error: 'authentication_required', message: 'Use an existing Sentinel customer API key or bearer token.' }, 401);
  }

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
    return json({ error: 'request_too_large' }, 413);
  }

  let body;
  try { body = JSON.parse(raw); } catch { return json({ error: 'invalid_json' }, 400); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return json({ error: 'invalid_request' }, 400);
  if (typeof body.ioc_value !== 'string' || !body.ioc_value.trim() || body.ioc_value.length > 256) {
    return json({ error: 'ioc_value_required' }, 400);
  }
  if (body.ioc_type !== undefined && typeof body.ioc_type !== 'string') return json({ error: 'invalid_ioc_type' }, 400);

  body.ioc_value = body.ioc_value.trim();
  body.ioc_type = String(body.ioc_type || 'auto').trim().slice(0, 32) || 'auto';

  const correlationId = safeRequestId(request);
  const missionId = `sentinel-mission-${crypto.randomUUID()}`;
  const executionId = `sentinel-swarm-${crypto.randomUUID()}`;
  const stream = new TransformStream();
  const writer = stream.writable.getWriter();

  ctx.waitUntil(executeMission({ writer, request, env, body, correlationId, missionId, executionId }));

  return new Response(stream.readable, {
    status: 200,
    headers: {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-store, must-revalidate',
      'connection': 'keep-alive',
      'x-content-type-options': 'nosniff',
      'x-cdb-swarm-protocol': PROTOCOL,
      'x-cdb-swarm-mission': missionId,
      'x-cdb-swarm-correlation': correlationId,
    },
  });
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function ui() {
  const agents = AGENTS.map((a) => `<article class="agent" id="agent-${escapeHtml(a.id)}"><div><strong>${escapeHtml(a.name)}</strong><small>${escapeHtml(a.capability)}</small></div><span class="state">IDLE</span><pre></pre></article>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CYBERDUDEBIVASH SENTINEL APEX — SUPER AGENT SWARM</title><style>
  :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui;background:#05080d;color:#e6edf3}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#0d2a24,#05080d 45%);min-height:100vh}.wrap{max-width:1180px;margin:auto;padding:38px 22px 80px}.brand{font-weight:800;letter-spacing:.08em;color:#72f0c2}.hero{border:1px solid #19483c;background:rgba(6,19,17,.88);border-radius:18px;padding:28px;margin:20px 0}.hero h1{font-size:clamp(28px,5vw,52px);margin:8px 0}.sub{color:#9fb8b0;max-width:850px;line-height:1.55}.form{display:grid;grid-template-columns:1fr 180px;gap:10px;margin-top:22px}.form input,.form select,.key{background:#07110f;color:#e6edf3;border:1px solid #28594d;border-radius:10px;padding:13px;font:inherit}.key{width:100%;margin-top:10px}.run{background:#37d39f;border:0;color:#03100c;font-weight:800;border-radius:10px;padding:13px 18px;cursor:pointer}.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:18px 0}.meta div{background:#07110f;border:1px solid #163a31;border-radius:10px;padding:12px}.meta small,.agent small{display:block;color:#78988f;margin-top:4px}.agents{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.agent{min-height:155px;background:#07110f;border:1px solid #173b32;border-radius:14px;padding:16px;position:relative}.agent .state{position:absolute;right:14px;top:14px;font-size:11px;font-weight:800;border:1px solid #28594d;border-radius:999px;padding:5px 8px}.agent[data-state=RUNNING]{border-color:#e9b949}.agent[data-state=COMPLETED]{border-color:#37d39f}.agent[data-state=FAILED],.agent[data-state=DENIED]{border-color:#ff6b6b}.agent pre{white-space:pre-wrap;word-break:break-word;color:#9fb8b0;font-size:11px;max-height:180px;overflow:auto;margin-top:20px}.final{margin-top:16px;border:1px solid #28594d;background:#07110f;border-radius:14px;padding:18px;white-space:pre-wrap}.truth{font-size:12px;color:#78988f;margin-top:12px}@media(max-width:700px){.form{grid-template-columns:1fr}.meta{grid-template-columns:1fr}}
  </style></head><body><main class="wrap"><div class="brand">CYBERDUDEBIVASH® SENTINEL APEX™</div><section class="hero"><h1>SUPER AGENT SWARM — LIVE CTI OPERATIONS</h1><p class="sub">Launch a real paid Sentinel correlation mission. Every state below is emitted by backend execution. No simulated timers, random percentages, or hard-coded findings. The mission is accepted only when the canonical Sentinel route completes through the private APEX mesh.</p><input class="key" id="key" type="password" autocomplete="off" placeholder="Sentinel API key — held in memory only, never saved"><div class="form"><input id="ioc" value="8.8.8.8" aria-label="IOC"><select id="type"><option value="ipv4">IPv4</option><option value="domain">Domain</option><option value="url">URL</option><option value="hash">Hash</option><option value="auto">Auto</option></select><button class="run" id="run">RUN LIVE SWARM</button></div><p class="truth">Credential storage: none. This page does not write the API key to cookies or localStorage.</p></section><section class="meta"><div>Mission<small id="mission">—</small></div><div>Correlation<small id="correlation">—</small></div><div>Mesh Certification<small id="mesh">PENDING</small></div></section><section class="agents">${agents}</section><pre class="final" id="final">Awaiting a live mission.</pre></main><script>
  const run=document.getElementById('run'),final=document.getElementById('final');
  function setAgent(ev){if(!ev.agent_id)return;const el=document.getElementById('agent-'+ev.agent_id);if(!el)return;el.dataset.state=ev.state;el.querySelector('.state').textContent=ev.state;const p=el.querySelector('pre');if(ev.result)p.textContent=JSON.stringify(ev.result,null,2)}
  run.onclick=async()=>{const key=document.getElementById('key').value.trim(),ioc=document.getElementById('ioc').value.trim(),type=document.getElementById('type').value;if(!key||!ioc){final.textContent='API key and IOC are required.';return}run.disabled=true;final.textContent='Connecting to live swarm…';document.getElementById('mesh').textContent='PENDING';try{const rid='ui-'+crypto.randomUUID();const r=await fetch('/api/swarm/run',{method:'POST',headers:{'content-type':'application/json','x-api-key':key,'x-request-id':rid},body:JSON.stringify({ioc_value:ioc,ioc_type:type})});if(!r.ok){final.textContent='Launch failed: HTTP '+r.status+' '+await r.text();return}const reader=r.body.getReader(),decoder=new TextDecoder();let buf='';while(true){const {value,done}=await reader.read();if(done)break;buf+=decoder.decode(value,{stream:true});let idx;while((idx=buf.indexOf('\n\n'))>=0){const chunk=buf.slice(0,idx);buf=buf.slice(idx+2);const line=chunk.split('\n').find(x=>x.startsWith('data: '));if(!line)continue;const ev=JSON.parse(line.slice(6));document.getElementById('mission').textContent=ev.mission_id;document.getElementById('correlation').textContent=ev.correlation_id;setAgent(ev);if(ev.mesh_certified)document.getElementById('mesh').textContent='CERTIFIED · '+(ev.mesh_execution_id||'');if(ev.event_type==='mission.completed')final.textContent=JSON.stringify(ev.result,null,2);if(ev.event_type==='mission.rejected'||ev.event_type==='mission.failed')final.textContent=JSON.stringify(ev,null,2)}}}}catch(e){final.textContent='Mission transport failed: '+e.message}finally{run.disabled=false}}
  </script></body></html>`;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (request.method === 'GET' && (url.pathname === '/swarm' || url.pathname === '/swarm/')) {
      return new Response(ui(), {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
          'x-frame-options': 'DENY',
          'x-content-type-options': 'nosniff',
          'referrer-policy': 'no-referrer',
        },
      });
    }
    if (request.method === 'GET' && url.pathname === '/api/swarm/health') {
      return json({ status: 'ok', service: 'sentinel-apex-swarm-live', protocol: PROTOCOL, version: env.SWARM_VERSION || '4.44.0', agents: AGENTS.length });
    }
    if (request.method === 'POST' && url.pathname === '/api/swarm/run') {
      return handleRun(request, env, ctx);
    }
    return json({ error: 'not_found' }, 404);
  },
};

export const __test = Object.freeze({ AGENTS, authHeaders, hasAuth, safeRequestId, buildSentinelSpecialistResults });
