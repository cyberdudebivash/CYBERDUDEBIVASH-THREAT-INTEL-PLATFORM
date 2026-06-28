// P36.0 - Enterprise Intelligence Excellence & Competitive Advantage Program
// Additive layer composing from P20/P25/P26 engines - NEVER re-implements their logic.
// Provides: intelligence quality improvement tracking, maturity assessment,
// customer value scoring, competitive advantage analysis, detection excellence,
// platform reliability governance, and commercial readiness certification.

import { computeP20QualityScore }      from './p20-handlers.js';
import { computeEnterpriseTrustScore } from './p25-handlers.js';
import { computeP26Grade }             from './p26-handlers.js';

// --- helpers ------------------------------------------------------------------

function _ts() { return new Date().toISOString(); }
function _json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

async function _loadFeed(env) {
  const raw = await env.THREAT_INTEL_KV.get('feed:latest');
  return raw ? JSON.parse(raw) : [];
}

async function _loadQuality(env, key) {
  const raw = await env.THREAT_INTEL_KV.get(`quality:${key}`);
  return raw ? JSON.parse(raw) : null;
}

// --- maturity scale -----------------------------------------------------------

const MATURITY = { MISSING: 0, EXPERIMENTAL: 1, BASIC: 2, MATURE: 3, ENTERPRISE_READY: 4, WORLD_CLASS: 5 };

function _maturityLabel(score) {
  if (score >= 5) return 'WORLD_CLASS';
  if (score >= 4) return 'ENTERPRISE_READY';
  if (score >= 3) return 'MATURE';
  if (score >= 2) return 'BASIC';
  if (score >= 1) return 'EXPERIMENTAL';
  return 'MISSING';
}

// --- field coverage audit -----------------------------------------------------

function _auditFieldCoverage(feed) {
  const n = feed.length || 1;
  const stats = {
    total: feed.length,
    cvss_present:      feed.filter(x => x.cvss_score && Number(x.cvss_score) > 0).length,
    cve_ids_present:   feed.filter(x => x.cve_ids && x.cve_ids.length > 0).length,
    actor_tag_present: feed.filter(x => x.actor_tag && x.actor_tag.trim()).length,
    confidence_present:feed.filter(x => x.confidence != null && x.confidence !== '').length,
    iocs_present:      feed.filter(x => x.iocs && x.iocs.length > 0).length,
    ttps_present:      feed.filter(x => (x.ttps && x.ttps.length > 0) || x.mitre_tactics).length,
    epss_present:      feed.filter(x => x.epss_score && Number(x.epss_score) > 0).length,
    kev_present:       feed.filter(x => x.kev_present === true).length,
    description_present: feed.filter(x => x.description && x.description.length >= 50).length,
  };
  // compute pct
  const pct = {};
  for (const [k, v] of Object.entries(stats)) {
    if (k !== 'total') pct[k.replace('_present','_pct')] = +(100 * v / n).toFixed(1);
  }
  return { ...stats, ...pct };
}

// --- quality targets ---------------------------------------------------------

const QUALITY_TARGETS = {
  cvss_pct:       { target: 80, label: 'CVSS Score Coverage',      priority: 'P1' },
  cve_ids_pct:    { target: 80, label: 'CVE ID Field Coverage',     priority: 'P1' },
  confidence_pct: { target: 95, label: 'Confidence Field Coverage', priority: 'P1' },
  actor_tag_pct:  { target: 80, label: 'Actor Attribution',         priority: 'P2' },
  iocs_pct:       { target: 90, label: 'IOC Presence',              priority: 'P2' },
  ttps_pct:       { target: 90, label: 'TTP / MITRE Coverage',      priority: 'P2' },
  epss_pct:       { target: 70, label: 'EPSS Score Coverage',       priority: 'P3' },
  kev_pct:        { target: 30, label: 'KEV Membership Annotation', priority: 'P3' },
  description_pct:{ target: 85, label: 'Rich Description (>=50ch)', priority: 'P3' },
};

function _evaluateTargets(coverage) {
  const results = [];
  let met = 0, total = 0;
  for (const [field, spec] of Object.entries(QUALITY_TARGETS)) {
    const actual = coverage[field] ?? 0;
    const pass = actual >= spec.target;
    if (pass) met++;
    total++;
    const gap = pass ? 0 : +(spec.target - actual).toFixed(1);
    results.push({ field, label: spec.label, priority: spec.priority, target: spec.target, actual, pass, gap });
  }
  results.sort((a, b) => {
    const pd = {'P1':0,'P2':1,'P3':2};
    if (pd[a.priority] !== pd[b.priority]) return pd[a.priority] - pd[b.priority];
    return b.gap - a.gap; // largest gap first within priority
  });
  return { targets: results, met, total, pct_met: +(100 * met / total).toFixed(1) };
}

// --- capability maturity matrix -----------------------------------------------

function _assessMaturity(feed, coverage, p35cert) {
  const n = feed.length || 1;
  const capabilities = [
    {
      id: 'CAP-01', name: 'Threat Feed Ingestion', category: 'intelligence',
      score: n >= 100 ? MATURITY.ENTERPRISE_READY : n >= 50 ? MATURITY.MATURE : n >= 10 ? MATURITY.BASIC : MATURITY.EXPERIMENTAL,
      evidence: `${n} items in feed`,
      target: MATURITY.WORLD_CLASS,
    },
    {
      id: 'CAP-02', name: 'CVSS Enrichment', category: 'evidence',
      score: coverage.cvss_pct >= 80 ? MATURITY.ENTERPRISE_READY : coverage.cvss_pct >= 50 ? MATURITY.MATURE : coverage.cvss_pct >= 20 ? MATURITY.BASIC : coverage.cvss_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.cvss_pct}% CVSS coverage`,
      target: MATURITY.ENTERPRISE_READY,
    },
    {
      id: 'CAP-03', name: 'CVE Identification', category: 'evidence',
      score: coverage.cve_ids_pct >= 80 ? MATURITY.ENTERPRISE_READY : coverage.cve_ids_pct >= 50 ? MATURITY.MATURE : coverage.cve_ids_pct >= 20 ? MATURITY.BASIC : coverage.cve_ids_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.cve_ids_pct}% CVE ID coverage`,
      target: MATURITY.ENTERPRISE_READY,
    },
    {
      id: 'CAP-04', name: 'Actor Attribution', category: 'intelligence',
      score: coverage.actor_tag_pct >= 80 ? MATURITY.MATURE : coverage.actor_tag_pct >= 50 ? MATURITY.BASIC : coverage.actor_tag_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.actor_tag_pct}% actor_tag coverage`,
      target: MATURITY.ENTERPRISE_READY,
    },
    {
      id: 'CAP-05', name: 'Confidence Calibration', category: 'scoring',
      score: coverage.confidence_pct >= 95 ? MATURITY.ENTERPRISE_READY : coverage.confidence_pct >= 80 ? MATURITY.MATURE : coverage.confidence_pct >= 50 ? MATURITY.BASIC : coverage.confidence_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.confidence_pct}% confidence coverage`,
      target: MATURITY.WORLD_CLASS,
    },
    {
      id: 'CAP-06', name: 'MITRE ATT&CK Mapping', category: 'detection',
      score: coverage.ttps_pct >= 90 ? MATURITY.ENTERPRISE_READY : coverage.ttps_pct >= 70 ? MATURITY.MATURE : coverage.ttps_pct >= 30 ? MATURITY.BASIC : coverage.ttps_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.ttps_pct}% TTP coverage`,
      target: MATURITY.ENTERPRISE_READY,
    },
    {
      id: 'CAP-07', name: 'IOC Extraction', category: 'detection',
      score: coverage.iocs_pct >= 90 ? MATURITY.ENTERPRISE_READY : coverage.iocs_pct >= 70 ? MATURITY.MATURE : coverage.iocs_pct >= 40 ? MATURITY.BASIC : coverage.iocs_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.iocs_pct}% IOC presence`,
      target: MATURITY.ENTERPRISE_READY,
    },
    {
      id: 'CAP-08', name: 'EPSS Enrichment', category: 'evidence',
      score: coverage.epss_pct >= 70 ? MATURITY.MATURE : coverage.epss_pct >= 30 ? MATURITY.BASIC : coverage.epss_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.epss_pct}% EPSS coverage`,
      target: MATURITY.MATURE,
    },
    {
      id: 'CAP-09', name: 'KEV Annotation', category: 'evidence',
      score: coverage.kev_pct >= 30 ? MATURITY.MATURE : coverage.kev_pct >= 10 ? MATURITY.BASIC : coverage.kev_pct > 0 ? MATURITY.EXPERIMENTAL : MATURITY.MISSING,
      evidence: `${coverage.kev_pct}% KEV annotation`,
      target: MATURITY.MATURE,
    },
    {
      id: 'CAP-10', name: 'P-Layer Certification Chain', category: 'engineering',
      score: p35cert?.release_tier === 'WORLDWIDE_RELEASE' ? MATURITY.ENTERPRISE_READY : MATURITY.BASIC,
      evidence: `P35 tier: ${p35cert?.release_tier ?? 'UNKNOWN'}`,
      target: MATURITY.WORLD_CLASS,
    },
  ];

  for (const cap of capabilities) {
    cap.maturity = _maturityLabel(cap.score);
    cap.target_label = _maturityLabel(cap.target);
    cap.gap = Math.max(0, cap.target - cap.score);
    cap.gap_label = cap.gap === 0 ? 'AT_TARGET' : `${cap.gap} level(s) to ${cap.target_label}`;
  }

  const avg = +(capabilities.reduce((s, c) => s + c.score, 0) / capabilities.length).toFixed(2);
  const missing = capabilities.filter(c => c.score === MATURITY.MISSING).length;
  const at_target = capabilities.filter(c => c.gap === 0).length;

  return { capabilities, avg_maturity_score: avg, avg_maturity_label: _maturityLabel(Math.round(avg)), missing_count: missing, at_target_count: at_target, total: capabilities.length };
}

// --- customer value scoring ---------------------------------------------------

function _computeCustomerValueScores(coverage, maturity) {
  // CVS = (detection_enablement * 0.35) + (risk_reduction * 0.30) + (operational_efficiency * 0.20) + (trust_signal * 0.15)
  const features = [
    {
      id: 'F01', name: 'CVSS-Enriched Threat Feed', category: 'detection_enablement',
      detection_enablement: Math.min(100, coverage.cvss_pct * 1.25),
      risk_reduction: Math.min(100, coverage.cvss_pct),
      operational_efficiency: Math.min(100, coverage.cvss_pct * 0.8),
      trust_signal: Math.min(100, coverage.cvss_pct * 1.1),
      status: coverage.cvss_pct >= 50 ? 'LIVE' : 'GAP',
    },
    {
      id: 'F02', name: 'Actor Attribution Intelligence', category: 'threat_intelligence',
      detection_enablement: Math.min(100, coverage.actor_tag_pct * 1.1),
      risk_reduction: Math.min(100, coverage.actor_tag_pct * 1.2),
      operational_efficiency: Math.min(100, coverage.actor_tag_pct * 0.9),
      trust_signal: Math.min(100, coverage.actor_tag_pct * 1.3),
      status: coverage.actor_tag_pct >= 50 ? 'LIVE' : 'GAP',
    },
    {
      id: 'F03', name: 'MITRE ATT&CK Mapped Detections', category: 'detection_enablement',
      detection_enablement: Math.min(100, coverage.ttps_pct * 1.1),
      risk_reduction: Math.min(100, coverage.ttps_pct),
      operational_efficiency: Math.min(100, coverage.ttps_pct * 0.95),
      trust_signal: Math.min(100, coverage.ttps_pct * 0.9),
      status: coverage.ttps_pct >= 50 ? 'LIVE' : 'GAP',
    },
    {
      id: 'F04', name: 'Confidence-Calibrated Prioritization', category: 'operational_efficiency',
      detection_enablement: Math.min(100, coverage.confidence_pct * 0.85),
      risk_reduction: Math.min(100, coverage.confidence_pct * 0.9),
      operational_efficiency: Math.min(100, coverage.confidence_pct * 1.15),
      trust_signal: Math.min(100, coverage.confidence_pct),
      status: coverage.confidence_pct >= 80 ? 'LIVE' : 'GAP',
    },
    {
      id: 'F05', name: 'IOC-Rich Threat Context', category: 'detection_enablement',
      detection_enablement: Math.min(100, coverage.iocs_pct * 1.2),
      risk_reduction: Math.min(100, coverage.iocs_pct),
      operational_efficiency: Math.min(100, coverage.iocs_pct * 0.8),
      trust_signal: Math.min(100, coverage.iocs_pct * 0.9),
      status: coverage.iocs_pct >= 60 ? 'LIVE' : 'GAP',
    },
    {
      id: 'F06', name: 'KEV-Annotated Exploitability', category: 'risk_reduction',
      detection_enablement: Math.min(100, coverage.kev_pct * 2.5),
      risk_reduction: Math.min(100, coverage.kev_pct * 3),
      operational_efficiency: Math.min(100, coverage.kev_pct * 2),
      trust_signal: Math.min(100, coverage.kev_pct * 2.5),
      status: coverage.kev_pct >= 20 ? 'LIVE' : 'GAP',
    },
  ];

  for (const f of features) {
    f.customer_value_score = +(
      f.detection_enablement * 0.35 +
      f.risk_reduction       * 0.30 +
      f.operational_efficiency * 0.20 +
      f.trust_signal         * 0.15
    ).toFixed(1);
  }
  features.sort((a, b) => b.customer_value_score - a.customer_value_score);

  const avg_cvs = +(features.reduce((s, f) => s + f.customer_value_score, 0) / features.length).toFixed(1);
  const live_count = features.filter(f => f.status === 'LIVE').length;
  return { features, avg_customer_value_score: avg_cvs, live_count, gap_count: features.length - live_count, total: features.length };
}

// --- improvement roadmap ------------------------------------------------------

function _buildRoadmap(targetEval, maturity) {
  const items = [];

  for (const t of targetEval.targets) {
    if (t.pass) continue;
    const cap = maturity.capabilities.find(c => {
      const field = t.field.replace('_pct','');
      return c.evidence.toLowerCase().includes(field) || c.name.toLowerCase().includes(field);
    });
    const effort = t.gap < 20 ? 'LOW' : t.gap < 50 ? 'MEDIUM' : 'HIGH';
    const value  = t.priority === 'P1' ? 'HIGH' : t.priority === 'P2' ? 'MEDIUM' : 'LOW';
    items.push({
      id: `R-${t.field.toUpperCase().slice(0,8)}`,
      label: `Improve ${t.label}`,
      current_pct: t.actual,
      target_pct: t.target,
      gap_pct: t.gap,
      priority: t.priority,
      effort,
      value,
      maturity_current: cap?.maturity ?? 'UNKNOWN',
      maturity_target: cap?.target_label ?? 'ENTERPRISE_READY',
      action: `Run enrichment pipeline to populate ${t.field.replace('_pct','').replace('_',' ')} field across feed items`,
    });
  }

  // sort by priority then value
  const prank = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  items.sort((a, b) => {
    const pd = { P1: 0, P2: 1, P3: 2 };
    return pd[a.priority] - pd[b.priority] || prank[b.value] - prank[a.value];
  });

  return { roadmap: items, total_items: items.length, high_priority: items.filter(i => i.priority === 'P1').length };
}

// --- P36 scorecard ------------------------------------------------------------

function _computeP36Scorecard(feed, coverage, maturity, targetEval, p35cert) {
  // Compose from existing engine: computeP26Grade on synthetic aggregate
  const synth = {
    risk_score: 7.5,
    severity: 'HIGH',
    confidence_score: coverage.confidence_pct,
    source_trust_score: 0.75,
    ttps: coverage.ttps_pct >= 50 ? ['T1059', 'T1190'] : [],
    iocs: coverage.iocs_pct >= 50 ? [{ type: 'ip' }] : [],
    cvss_score: coverage.cvss_pct >= 50 ? 7.5 : 0,
    epss_score: coverage.epss_pct >= 50 ? 0.5 : 0,
    kev_present: coverage.kev_pct >= 20,
  };
  const grade = computeP26Grade(synth);

  const intelligence_quality = +(targetEval.pct_met).toFixed(1);
  const platform_maturity = +(100 * maturity.avg_maturity_score / 5).toFixed(1);
  const certification_health = p35cert?.blocker_count === 0 ? 100 : Math.max(0, 100 - p35cert.blocker_count * 20);

  const overall = +(intelligence_quality * 0.4 + platform_maturity * 0.35 + certification_health * 0.25).toFixed(1);

  return {
    grade: grade.grade ?? 'B',
    composite_pct: overall,
    dimensions: {
      intelligence_quality: { score: intelligence_quality, weight: 0.40, label: 'Intelligence Quality' },
      platform_maturity:    { score: platform_maturity,    weight: 0.35, label: 'Platform Maturity'    },
      certification_health: { score: certification_health, weight: 0.25, label: 'Certification Health' },
    },
    tier: overall >= 90 ? 'WORLD_CLASS' : overall >= 75 ? 'ENTERPRISE_READY' : overall >= 60 ? 'MATURE' : overall >= 40 ? 'BASIC' : 'DEVELOPING',
    p26_grade_input_reused: true,
  };
}

// --- competitive analysis -----------------------------------------------------

function _competitiveAnalysis(coverage, maturity) {
  const benchmarks = [
    { competitor: 'Commercial TI Platform A', cvss_pct: 95, cve_pct: 90, actor_pct: 75, ttp_pct: 80, confidence_pct: 85 },
    { competitor: 'Open Source Feed',          cvss_pct: 60, cve_pct: 70, actor_pct: 20, ttp_pct: 40, confidence_pct: 30 },
    { competitor: 'Enterprise ISAC Feed',      cvss_pct: 85, cve_pct: 88, actor_pct: 65, ttp_pct: 90, confidence_pct: 80 },
  ];

  const us = {
    cvss_pct: coverage.cvss_pct,
    cve_pct: coverage.cve_ids_pct,
    actor_pct: coverage.actor_tag_pct,
    ttp_pct: coverage.ttps_pct,
    confidence_pct: coverage.confidence_pct,
  };

  const fields = ['cvss_pct', 'cve_pct', 'actor_pct', 'ttp_pct', 'confidence_pct'];
  const our_avg = +(fields.reduce((s, f) => s + us[f], 0) / fields.length).toFixed(1);

  const comparisons = benchmarks.map(b => {
    const b_avg = +(fields.reduce((s, f) => s + b[f], 0) / fields.length).toFixed(1);
    const delta = +(our_avg - b_avg).toFixed(1);
    return { ...b, their_avg: b_avg, our_avg, delta, position: delta >= 0 ? 'AHEAD' : 'BEHIND' };
  });

  const ahead_count = comparisons.filter(c => c.position === 'AHEAD').length;
  return { our_avg, comparisons, ahead_of: `${ahead_count}/${comparisons.length} benchmarks`, advantage_areas: fields.filter(f => us[f] >= 70).map(f => f.replace('_pct','')) };
}

// --- detection excellence -----------------------------------------------------

function _detectionExcellence(feed, coverage) {
  const sigma_ready   = feed.filter(x => (x.ttps && x.ttps.length > 0) && x.iocs && x.iocs.length > 0).length;
  const hunt_ready    = feed.filter(x => x.ttps && x.ttps.length > 0).length;
  const enrich_ready  = feed.filter(x => x.cvss_score || x.epss_score).length;

  return {
    sigma_ready_items: sigma_ready,
    hunt_ready_items: hunt_ready,
    enrichment_ready_items: enrich_ready,
    sigma_pct: +(100 * sigma_ready / (feed.length || 1)).toFixed(1),
    hunt_pct:  +(100 * hunt_ready  / (feed.length || 1)).toFixed(1),
    enrich_pct:+(100 * enrich_ready/ (feed.length || 1)).toFixed(1),
    detection_tier: sigma_ready >= 50 ? 'ENTERPRISE_READY' : sigma_ready >= 20 ? 'MATURE' : 'DEVELOPING',
  };
}

// --- reliability metrics ------------------------------------------------------

function _reliabilityMetrics(feed, p35cert, p34cert) {
  const dedup_ids = new Set(feed.map(x => x.id)).size;
  const dup_count = feed.length - dedup_ids;
  const fresh = feed.filter(x => {
    const ts = x.processed_at || x.published_at || x.timestamp;
    if (!ts) return false;
    const age = (Date.now() - new Date(ts).getTime()) / 3600000;
    return age <= 48;
  }).length;

  return {
    feed_item_count: feed.length,
    unique_item_count: dedup_ids,
    duplicate_count: dup_count,
    freshness_48h: fresh,
    freshness_pct: +(100 * fresh / (feed.length || 1)).toFixed(1),
    p35_blockers: p35cert?.blocker_count ?? 'N/A',
    p34_blockers: p34cert?.blocker_count ?? 'N/A',
    p35_passed: p35cert?.passed_count ?? 0,
    p35_total: p35cert?.total_gates ?? 0,
    reliability_tier: dup_count === 0 && (p35cert?.blocker_count ?? 1) === 0 ? 'ENTERPRISE_READY' : 'MATURE',
  };
}

// --- aggregate quality scores via engine composition -------------------------

function _sampleQuality(feed) {
  const sample = feed.slice(0, 30);
  let totalQ = 0, totalT = 0, totalConf = 0;
  for (const item of sample) {
    const q = computeP20QualityScore(item);
    const t = computeEnterpriseTrustScore(item);
    totalQ += q.composite_score ?? q.total ?? 0;
    totalT += t.total ?? t.composite_score ?? 0;
    totalConf += (item.confidence_score ?? item.confidence ?? 0);
  }
  const n = sample.length || 1;
  return {
    avg_p20_quality: +(totalQ / n).toFixed(2),
    avg_p25_trust:   +(totalT / n).toFixed(2),
    avg_confidence:  +(totalConf / n).toFixed(2),
    sample_size: n,
  };
}

// --- exported route handlers --------------------------------------------------

export async function handleP36Quality(request, env) {
  const feed = await _loadFeed(env);
  const coverage = _auditFieldCoverage(feed);
  const targetEval = _evaluateTargets(coverage);
  const sampleQ = _sampleQuality(feed);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'intelligence_quality',
    feed_item_count: feed.length,
    field_coverage: coverage,
    quality_targets: targetEval,
    engine_scores: sampleQ,
    quality_tier: targetEval.pct_met >= 80 ? 'ENTERPRISE_READY' : targetEval.pct_met >= 60 ? 'MATURE' : 'DEVELOPING',
  });
}

export async function handleP36Maturity(request, env) {
  const feed = await _loadFeed(env);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const coverage = _auditFieldCoverage(feed);
  const maturity = _assessMaturity(feed, coverage, p35cert);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'maturity_assessment',
    feed_item_count: feed.length,
    maturity_matrix: maturity,
    scale: { 0:'MISSING', 1:'EXPERIMENTAL', 2:'BASIC', 3:'MATURE', 4:'ENTERPRISE_READY', 5:'WORLD_CLASS' },
  });
}

export async function handleP36Targets(request, env) {
  const feed = await _loadFeed(env);
  const coverage = _auditFieldCoverage(feed);
  const targetEval = _evaluateTargets(coverage);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'quality_targets',
    targets_met: targetEval.met,
    targets_total: targetEval.total,
    pct_met: targetEval.pct_met,
    targets: targetEval.targets,
  });
}

export async function handleP36Gaps(request, env) {
  const feed = await _loadFeed(env);
  const coverage = _auditFieldCoverage(feed);
  const targetEval = _evaluateTargets(coverage);
  const failing = targetEval.targets.filter(t => !t.pass);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'gap_analysis',
    gap_count: failing.length,
    gaps: failing,
    field_coverage: coverage,
    summary: `${failing.length}/${targetEval.total} targets unmet  -  ${failing.filter(f=>f.priority==='P1').length} critical gaps`,
  });
}

export async function handleP36CustomerValue(request, env) {
  const feed = await _loadFeed(env);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const coverage = _auditFieldCoverage(feed);
  const maturity = _assessMaturity(feed, coverage, p35cert);
  const cvs = _computeCustomerValueScores(coverage, maturity);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'customer_value',
    avg_customer_value_score: cvs.avg_customer_value_score,
    live_count: cvs.live_count,
    gap_count: cvs.gap_count,
    features: cvs.features,
  });
}

export async function handleP36Competitive(request, env) {
  const feed = await _loadFeed(env);
  const coverage = _auditFieldCoverage(feed);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const maturity = _assessMaturity(feed, coverage, p35cert);
  const comp = _competitiveAnalysis(coverage, maturity);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'competitive_advantage',
    our_avg_coverage: comp.our_avg,
    ahead_of: comp.ahead_of,
    advantage_areas: comp.advantage_areas,
    benchmarks: comp.comparisons,
  });
}

export async function handleP36Detection(request, env) {
  const feed = await _loadFeed(env);
  const coverage = _auditFieldCoverage(feed);
  const det = _detectionExcellence(feed, coverage);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'detection_excellence',
    feed_item_count: feed.length,
    ...det,
  });
}

export async function handleP36Reliability(request, env) {
  const feed = await _loadFeed(env);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const p34cert = await _loadQuality(env, 'p34_certification_report');
  const rel = _reliabilityMetrics(feed, p35cert, p34cert);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'platform_reliability',
    ...rel,
  });
}

export async function handleP36Metrics(request, env) {
  const feed = await _loadFeed(env);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const p34cert = await _loadQuality(env, 'p34_certification_report');
  const coverage = _auditFieldCoverage(feed);
  const targetEval = _evaluateTargets(coverage);
  const maturity = _assessMaturity(feed, coverage, p35cert);
  const rel = _reliabilityMetrics(feed, p35cert, p34cert);
  const det = _detectionExcellence(feed, coverage);
  const sampleQ = _sampleQuality(feed);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'kpi_dashboard',
    kpis: {
      feed_item_count:        feed.length,
      targets_met_pct:        targetEval.pct_met,
      avg_maturity_score:     maturity.avg_maturity_score,
      avg_maturity_label:     maturity.avg_maturity_label,
      sigma_ready_pct:        det.sigma_pct,
      detection_tier:         det.detection_tier,
      reliability_tier:       rel.reliability_tier,
      avg_p20_quality:        sampleQ.avg_p20_quality,
      avg_p25_trust:          sampleQ.avg_p25_trust,
      p35_tier:               p35cert?.release_tier ?? 'UNKNOWN',
      p35_blockers:           p35cert?.blocker_count ?? 0,
    },
  });
}

export async function handleP36Roadmap(request, env) {
  const feed = await _loadFeed(env);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const coverage = _auditFieldCoverage(feed);
  const targetEval = _evaluateTargets(coverage);
  const maturity = _assessMaturity(feed, coverage, p35cert);
  const roadmap = _buildRoadmap(targetEval, maturity);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'improvement_roadmap',
    ...roadmap,
  });
}

export async function handleP36Dashboard(request, env) {
  const feed = await _loadFeed(env);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const p34cert = await _loadQuality(env, 'p34_certification_report');
  const coverage = _auditFieldCoverage(feed);
  const targetEval = _evaluateTargets(coverage);
  const maturity = _assessMaturity(feed, coverage, p35cert);
  const scorecard = _computeP36Scorecard(feed, coverage, maturity, targetEval, p35cert);
  const det = _detectionExcellence(feed, coverage);
  const rel = _reliabilityMetrics(feed, p35cert, p34cert);
  const cvs = _computeCustomerValueScores(coverage, maturity);
  const roadmap = _buildRoadmap(targetEval, maturity);
  const sampleQ = _sampleQuality(feed);

  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'unified_dashboard',
    scorecard,
    field_coverage: coverage,
    quality_targets: { met: targetEval.met, total: targetEval.total, pct_met: targetEval.pct_met },
    maturity_summary: { avg: maturity.avg_maturity_score, label: maturity.avg_maturity_label, at_target: maturity.at_target_count, total: maturity.total },
    detection: { sigma_pct: det.sigma_pct, hunt_pct: det.hunt_pct, tier: det.detection_tier },
    reliability: { tier: rel.reliability_tier, freshness_pct: rel.freshness_pct, p35_blockers: rel.p35_blockers },
    customer_value: { avg_score: cvs.avg_customer_value_score, live: cvs.live_count, gaps: cvs.gap_count },
    top_roadmap_items: roadmap.roadmap.slice(0, 5),
    engine_scores: sampleQ,
    certification_chain: {
      p35: p35cert?.release_tier ?? 'UNKNOWN',
      p34: p34cert?.release_tier ?? 'UNKNOWN',
    },
  });
}

export async function handleP36Observability(request, env) {
  const feed = await _loadFeed(env);
  const p35cert = await _loadQuality(env, 'p35_certification_report');
  const coverage = _auditFieldCoverage(feed);
  const targetEval = _evaluateTargets(coverage);
  return _json({
    schema_version: 'p36.0', timestamp: _ts(), layer: 'P36',
    capability: 'observability',
    p_layer_version: 'P36.0',
    platform: 'CYBERDUDEBIVASH(R) SENTINEL APEX',
    health: targetEval.pct_met >= 60 ? 'GREEN' : 'AMBER',
    metrics: {
      feed_item_count:   feed.length,
      targets_met_pct:   targetEval.pct_met,
      p35_tier:          p35cert?.release_tier ?? 'UNKNOWN',
    },
    engines_reused: ['computeP20QualityScore', 'computeEnterpriseTrustScore', 'computeP26Grade'],
  });
}
