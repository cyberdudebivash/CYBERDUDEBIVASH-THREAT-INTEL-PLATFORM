import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildEvidenceGraph } from '../evidence-graph.js';

test('evidence graph preserves real IOC -> report -> CVE/actor/ATT&CK provenance', () => {
  const graph = buildEvidenceGraph({
    correlation: {
      ioc: { value: 'evil.example', type: 'domain' },
      matches: [{
        report_id: 'intel--123',
        title: 'Threat',
        cve_id: 'CVE-2026-11111',
        actor_tag: 'APT-X',
        risk_score: 9,
        ttps: [{ technique_id: 'T1059' }],
      }],
    },
    outcomes: {
      'ioc-hunter': { state: 'COMPLETED', basis: 'backend_execution', duration_ms: 20 },
      'cve-intelligence': {
        state: 'COMPLETED',
        basis: 'backend_execution',
        queried: { cve_id: 'CVE-2026-11111' },
        evidence_count: 1,
      },
      'risk-synthesizer': { state: 'COMPLETED', basis: 'fusion' },
    },
  });

  assert.equal(graph.schema, 'cdb.swarm.evidence-graph.v1');
  assert.ok(graph.nodes.some((n) => n.type === 'observable' && n.value === 'evil.example'));
  assert.ok(graph.nodes.some((n) => n.type === 'intel_report' && n.report_id === 'intel--123'));
  assert.ok(graph.nodes.some((n) => n.type === 'cve' && n.cve_id === 'CVE-2026-11111'));
  assert.ok(graph.nodes.some((n) => n.type === 'threat_actor' && n.actor === 'APT-X'));
  assert.ok(graph.nodes.some((n) => n.type === 'attack_technique' && n.technique === 'T1059'));
  assert.ok(graph.edges.some((e) => e.type === 'correlates_to'));
  assert.ok(graph.edges.some((e) => e.type === 'input_to'));
  assert.ok(graph.edges.some((e) => e.type === 'contributes_to'));
});
