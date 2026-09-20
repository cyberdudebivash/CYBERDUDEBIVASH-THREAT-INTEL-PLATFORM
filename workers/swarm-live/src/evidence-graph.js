// =============================================================================
// CYBERDUDEBIVASH SENTINEL APEX — MISSION EVIDENCE GRAPH
// V4.47.0
//
// Pure provenance graph derived only from canonical correlation evidence and
// real specialist outcomes. It never invents nodes or relationships.
// =============================================================================

function safeIdPart(value) {
  return String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9._:-]+/g, '_')
    .slice(0, 180);
}

function pushNode(nodes, seen, node) {
  if (!node?.id || seen.has(node.id)) return;
  seen.add(node.id);
  nodes.push(node);
}

function pushEdge(edges, seen, edge) {
  if (!edge?.source || !edge?.target || !edge?.type) return;
  const key = `${edge.source}|${edge.type}|${edge.target}`;
  if (seen.has(key)) return;
  seen.add(key);
  edges.push(edge);
}

function ttpValue(value) {
  if (typeof value === 'string') return value.trim() || null;
  if (!value || typeof value !== 'object') return null;
  const candidate = value.technique_id || value.id || value.name;
  return typeof candidate === 'string' && candidate.trim() ? candidate.trim() : null;
}

export function buildEvidenceGraph({ correlation, outcomes = {} } = {}) {
  const nodes = [];
  const edges = [];
  const nodeSeen = new Set();
  const edgeSeen = new Set();

  const iocValue = correlation?.ioc?.value || null;
  const iocType = correlation?.ioc?.type || 'auto';
  const iocId = iocValue ? `ioc:${safeIdPart(iocType)}:${safeIdPart(iocValue)}` : null;

  if (iocId) {
    pushNode(nodes, nodeSeen, {
      id: iocId,
      type: 'observable',
      observable_type: iocType,
      value: iocValue,
      source: 'canonical:/api/intel/correlate',
    });
  }

  const matches = Array.isArray(correlation?.matches) ? correlation.matches : [];

  for (const match of matches) {
    const reportId = match?.report_id ? String(match.report_id) : null;
    const reportNodeId = reportId ? `report:${safeIdPart(reportId)}` : null;

    if (reportNodeId) {
      pushNode(nodes, nodeSeen, {
        id: reportNodeId,
        type: 'intel_report',
        report_id: reportId,
        title: match?.title || null,
        severity: match?.severity || null,
        risk_score: Number.isFinite(Number(match?.risk_score)) ? Number(match.risk_score) : null,
        source: 'canonical:/api/intel/correlate',
      });
      if (iocId) {
        pushEdge(edges, edgeSeen, {
          source: iocId,
          target: reportNodeId,
          type: 'correlates_to',
        });
      }
    }

    if (match?.cve_id) {
      const cveId = String(match.cve_id);
      const nodeId = `cve:${safeIdPart(cveId)}`;
      pushNode(nodes, nodeSeen, { id: nodeId, type: 'cve', cve_id: cveId });
      if (reportNodeId) pushEdge(edges, edgeSeen, { source: reportNodeId, target: nodeId, type: 'references_cve' });
    }

    if (match?.actor_tag && match.actor_tag !== 'UNATTRIBUTED') {
      const actor = String(match.actor_tag);
      const nodeId = `actor:${safeIdPart(actor)}`;
      pushNode(nodes, nodeSeen, { id: nodeId, type: 'threat_actor', actor });
      if (reportNodeId) pushEdge(edges, edgeSeen, { source: reportNodeId, target: nodeId, type: 'attributed_to' });
    }

    if (Array.isArray(match?.ttps)) {
      for (const raw of match.ttps) {
        const technique = ttpValue(raw);
        if (!technique) continue;
        const nodeId = `attack:${safeIdPart(technique)}`;
        pushNode(nodes, nodeSeen, { id: nodeId, type: 'attack_technique', technique });
        if (reportNodeId) pushEdge(edges, edgeSeen, { source: reportNodeId, target: nodeId, type: 'uses_technique' });
      }
    }
  }

  for (const [agentId, outcome] of Object.entries(outcomes)) {
    const agentNodeId = `agent:${safeIdPart(agentId)}`;
    pushNode(nodes, nodeSeen, {
      id: agentNodeId,
      type: 'agent_execution',
      agent_id: agentId,
      state: outcome?.state || null,
      basis: outcome?.basis || null,
      duration_ms: Number.isFinite(Number(outcome?.duration_ms)) ? Number(outcome.duration_ms) : null,
      queried: outcome?.queried || null,
      evidence_count: Number.isFinite(Number(outcome?.evidence_count)) ? Number(outcome.evidence_count) : null,
    });

    if (agentId === 'ioc-hunter' && iocId) {
      pushEdge(edges, edgeSeen, { source: iocId, target: agentNodeId, type: 'processed_by' });
    }

    const queried = outcome?.queried || {};
    for (const [key, value] of Object.entries(queried)) {
      if (!value) continue;
      let sourceId = null;
      if (key === 'cve_id') sourceId = `cve:${safeIdPart(value)}`;
      else if (key === 'actor_id') sourceId = `actor:${safeIdPart(value)}`;
      else if (key === 'intel_id' || key === 'report_id') sourceId = `report:${safeIdPart(value)}`;
      else if (key === 'q') sourceId = `attack:${safeIdPart(value)}`;
      if (sourceId && nodeSeen.has(sourceId)) {
        pushEdge(edges, edgeSeen, { source: sourceId, target: agentNodeId, type: 'input_to' });
      }
    }

    if (agentId !== 'risk-synthesizer' && nodeSeen.has('agent:risk-synthesizer')) {
      pushEdge(edges, edgeSeen, { source: agentNodeId, target: 'agent:risk-synthesizer', type: 'contributes_to' });
    }
  }

  // Risk Synthesizer is often added last, so connect existing agent nodes to it
  // after all outcome nodes are known.
  if (nodeSeen.has('agent:risk-synthesizer')) {
    for (const id of Object.keys(outcomes)) {
      if (id === 'risk-synthesizer') continue;
      const source = `agent:${safeIdPart(id)}`;
      if (nodeSeen.has(source)) {
        pushEdge(edges, edgeSeen, { source, target: 'agent:risk-synthesizer', type: 'contributes_to' });
      }
    }
  }

  return Object.freeze({
    schema: 'cdb.swarm.evidence-graph.v1',
    node_count: nodes.length,
    edge_count: edges.length,
    nodes: Object.freeze(nodes),
    edges: Object.freeze(edges),
  });
}
