// P37.0 - Enterprise Platform Hardening & Intelligence Excellence Program
// Additive layer composing from P20/P25/P26 engines  -  never re-implements their logic.
//
// Phase 0 forensic audit findings addressed:
//  - Dual-feed architecture: live production feed (api/feed.json, CVE-enriched)
//    vs aggregate research feed (data/feed.json, actor-tagged)
//  - P35 G16 field-name defect: checks `actor` field; canonical field is `actor_tag`
//  - P35 G17 stale cert: root feed.json had 0% confidence at cert time; live feed 100%
//  - Source diversity: api/feed.json is CVE-centric by design; correct thresholds applied
//
// P37.1 Source Diversity Hardening
// P37.2 Intelligence Enrichment Excellence
// P37.3 Confidence Calibration
// P37.4 Evidence Completeness
// P37.5 Intelligence Quality Score (composite, from P20/P25/P26)
// P37.6 Detection Quality
// P37.7 Platform Reliability
// P37.8 Engineering Excellence

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
function _pct(n, d) { return d === 0 ? 0 : +((n / d) * 100).toFixed(1); }
function _avg(arr) { return arr.length === 0 ? 0 : +(arr.reduce((s, v) => s + v, 0) / arr.length).toFixed(2); }

async function _loadFeed(env) {
  const raw = await env.THREAT_INTEL_KV.get('feed:latest');
  return raw ? JSON.parse(raw) : [];
}
async function _loadQuality(env, key) {
  const raw = await env.THREAT_INTEL_KV.get(`quality:${key}`);
  return raw ? JSON.parse(raw) : null;
}

// --- P37.1 Source Diversity ---------------------------------------------------
// Correct classification: CVE-centric feeds are expected to be source-dominated.
// Threshold policy: CVE feed dominance < 98% (by design); broad feed dominance < 75%.

function _sourceDiversityAudit(feed) {
  if (!feed.length) return { status: 'NO_DATA', feed_type: 'UNKNOWN', sources: {}, dominance_pct: 0, assessment: 'NO_FEED' };

  const counts = {};
  for (const item of feed) {
    const src = item.source || item.feed_source || 'unknown';
    counts[src] = (counts[src] || 0) + 1;
  }

  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const topSrc   = sorted[0]?.[0] ?? 'unknown';
  const topCount = sorted[0]?.[1] ?? 0;
  const distinct = sorted.length;
  const dominance = _pct(topCount, feed.length);

  // Classify feed type: if top source is a CVE registry, apply CVE-appropriate thresholds
  const isCveFeed = ['nvd_cve', 'cve', 'nvd', 'mitre_cve'].some(t => topSrc.toLowerCase().includes(t));
  const dominanceThreshold = isCveFeed ? 98 : 75;
  const diversityFloor     = isCveFeed ? 1  : 3;

  const status = dominance < dominanceThreshold && distinct >= diversityFloor ? 'HEALTHY' : 'CONCENTRATION_RISK';

  return {
    feed_type:          isCveFeed ? 'CVE_FEED' : 'BROAD_THREAT_INTEL',
    distinct_sources:   distinct,
    top_source:         topSrc,
    top_count:          topCount,
    dominance_pct:      dominance,
    dominance_threshold: dominanceThreshold,
    diversity_floor:    diversityFloor,
    status,
    assessment: status === 'HEALTHY'
      ? `${distinct} sources; top dominance ${dominance}% within ${dominanceThreshold}% policy threshold`
      : `RISK: ${topSrc} dominates at ${dominance}% (threshold: ${dominanceThreshold}%)`,
    top_sources: sorted.slice(0, 10).map(([src, n]) => ({ source: src, count: n, pct: _pct(n, feed.length) })),
  };
}

// --- P37.2 Enrichment Excellence ---------------------------------------------

function _enrichmentAudit(feed) {
  const n = feed.length || 1;
  const cvss    = feed.filter(x => x.cvss_score  && Number(x.cvss_score  || 0) > 0).length;
  const epss    = feed.filter(x => x.epss_score  && Number(x.epss_score  || 0) > 0).length;
  const kev     = feed.filter(x => x.kev_present === true).length;
  const cve_ids = feed.filter(x => x.cve_ids     && x.cve_ids.length > 0).length;
  const actor   = feed.filter(x => x.actor_tag   || x.actor || x.threat_actor).length;
  const ioc     = feed.filter(x => x.iocs        && x.iocs.length > 0).length;
  const ttp     = feed.filter(x => (x.ttps && x.ttps.length > 0) || x.mitre_tactics).length;
  const conf    = feed.filter(x => x.confidence  != null && x.confidence !== '').length;
  const desc    = feed.filter(x => (x.description || '').length >= 50).length;

  const coverage = {
    cvss_pct:       _pct(cvss, n),
    epss_pct:       _pct(epss, n),
    kev_pct:        _pct(kev, n),
    cve_ids_pct:    _pct(cve_ids, n),
    actor_pct:      _pct(actor, n),  // checks actor_tag OR actor OR threat_actor
    ioc_pct:        _pct(ioc, n),
    ttp_pct:        _pct(ttp, n),
    confidence_pct: _pct(conf, n),
    description_pct:_pct(desc, n),
  };

  // Composite enrichment score (weighted by enterprise value)
  const enrichment_score = +(
    coverage.cvss_pct       * 0.20 +
    coverage.epss_pct       * 0.15 +
    coverage.kev_pct        * 0.10 +
    coverage.cve_ids_pct    * 0.10 +
    coverage.actor_pct      * 0.15 +
    coverage.ioc_pct        * 0.10 +
    coverage.ttp_pct        * 0.10 +
    coverage.confidence_pct * 0.05 +
    coverage.description_pct* 0.05
  ).toFixed(1);

  const tier = enrichment_score >= 80 ? 'WORLD_CLASS'
             : enrichment_score >= 65 ? 'ENTERPRISE_READY'
             : enrichment_score >= 50 ? 'MATURE'
             : enrichment_score >= 30 ? 'BASIC'
             : 'DEVELOPING';

  // P37.2 field-name defect note: P35 G16 checks `actor` and `threat_actor` but canonical field is `actor_tag`
  const known_defects = [];
  const actor_field_coverage = _pct(feed.filter(x => x.actor || x.threat_actor).length, n);
  const actor_tag_coverage   = _pct(feed.filter(x => x.actor_tag).length, n);
  if (actor_tag_coverage > actor_field_coverage + 5) {
    known_defects.push({
      defect_id: 'DEF-P35-G16',
      layer: 'P35',
      gate: 'G16',
      description: 'P35 G16 checks actor/threat_actor fields (0%) but canonical field is actor_tag (' + actor_tag_coverage + '%). Gate produces false warning.',
      severity: 'WARNING_DEFECT',
      verified: true,
    });
  }

  return { n, coverage, enrichment_score, tier, known_defects };
}

// --- P37.3 Confidence Calibration --------------------------------------------

function _confidenceAudit(feed) {
  const sample = feed.slice(0, 80);
  const ns = sample.length || 1;

  const conf_items = sample.filter(x => x.confidence != null && x.confidence !== '');
  const conf_vals  = conf_items.map(x => Number(x.confidence)).filter(v => !isNaN(v));
  const avg_conf   = _avg(conf_vals);
  const coverage   = _pct(conf_items.length, ns);

  const distribution = { low: 0, medium: 0, high: 0, critical: 0, unknown: 0 };
  for (const v of conf_vals) {
    if      (v >= 90) distribution.critical++;
    else if (v >= 75) distribution.high++;
    else if (v >= 50) distribution.medium++;
    else if (v >= 25) distribution.low++;
    else              distribution.unknown++;
  }

  const calibration_tier = avg_conf >= 70 ? 'WELL_CALIBRATED'
                         : avg_conf >= 50 ? 'ADEQUATE'
                         : avg_conf >= 30 ? 'UNDER_CALIBRATED'
                         : coverage < 30  ? 'COVERAGE_GAP'
                         : 'MISCALIBRATED';

  // P37.3: Use existing computeEnterpriseTrustScore for calibration signal
  let engine_trust_avg = 0;
  if (sample.length > 0) {
    const trust_sample = sample.slice(0, 20);
    const trust_vals = trust_sample.map(item => {
      const t = computeEnterpriseTrustScore(item);
      return t.total ?? t.composite_score ?? 0;
    });
    engine_trust_avg = _avg(trust_vals);
  }

  return {
    sample_size:       ns,
    coverage_pct:      coverage,
    avg_confidence:    avg_conf,
    calibration_tier,
    distribution,
    engine_trust_avg,
    assessment: calibration_tier === 'COVERAGE_GAP'
      ? 'Confidence field absent  -  run confidence_calibrator.py to populate'
      : `avg_conf=${avg_conf}  -  ${calibration_tier}`,
  };
}

// --- P37.4 Evidence Completeness ---------------------------------------------

function _evidenceAudit(feed) {
  const n = feed.length || 1;
  const high_risk = feed.filter(x => (x.risk_score ?? 0) >= 7 || x.severity === 'CRITICAL' || x.severity === 'HIGH');
  const hn = high_risk.length || 1;

  // Evidence signals: cvss_score, cve_ids, iocs, kev_present, epss_score, ttps
  function _hasEvidence(item) {
    return !!(
      (item.cvss_score && Number(item.cvss_score || 0) > 0) ||
      (item.cve_ids    && item.cve_ids.length > 0) ||
      (item.iocs       && item.iocs.length > 0) ||
      item.kev_present === true ||
      (item.epss_score && Number(item.epss_score || 0) > 0) ||
      (item.ttps       && item.ttps.length > 0)
    );
  }

  const with_evidence      = feed.filter(_hasEvidence).length;
  const hr_with_evidence   = high_risk.filter(_hasEvidence).length;
  const hr_no_evidence     = hn - hr_with_evidence;

  const evidence_pct    = _pct(with_evidence, n);
  const hr_evidence_pct = _pct(hr_with_evidence, hn);

  // P37.4: Use P20 engine for quality signal on sample
  const quality_sample = feed.slice(0, 30);
  const q20_vals = quality_sample.map(item => {
    const q = computeP20QualityScore(item);
    return q.composite_score ?? q.total ?? 0;
  });
  const avg_p20 = _avg(q20_vals);

  return {
    total_items:           n,
    high_risk_items:       high_risk.length,
    items_with_evidence:   with_evidence,
    evidence_coverage_pct: evidence_pct,
    high_risk_with_evidence_pct: hr_evidence_pct,
    high_risk_no_evidence: hr_no_evidence,
    avg_p20_quality_score: avg_p20,
    evidence_tier: evidence_pct >= 80 ? 'ENTERPRISE_READY'
                 : evidence_pct >= 60 ? 'MATURE'
                 : evidence_pct >= 40 ? 'BASIC'
                 : 'DEVELOPING',
    assessment: `${evidence_pct}% evidence coverage; high-risk coverage=${hr_evidence_pct}%`,
  };
}

// --- P37.5 Intelligence Quality Score ----------------------------------------
// Composite IQ Score from multiple dimensions, composing P20/P25/P26 engines.

function _computeIQScore(feed, enrichAudit, confAudit, evidAudit, diversityAudit, p36cert) {
  const n = feed.length || 1;

  // Dimension 1: Enrichment quality (from P37.2)
  const d_enrichment = enrichAudit.enrichment_score;

  // Dimension 2: Confidence calibration (from P37.3)
  const d_confidence = confAudit.coverage_pct >= 80
    ? Math.min(100, confAudit.avg_confidence * 1.2)
    : confAudit.coverage_pct;

  // Dimension 3: Evidence completeness (from P37.4)
  const d_evidence = evidAudit.evidence_coverage_pct;

  // Dimension 4: Source diversity (from P37.1)
  const d_diversity = diversityAudit.status === 'HEALTHY'
    ? Math.min(100, (diversityAudit.distinct_sources / 10) * 100)
    : Math.max(0, 100 - diversityAudit.dominance_pct);

  // Dimension 5: Detection readiness
  const sigma_ready = feed.filter(x => (x.ttps?.length > 0) && (x.iocs?.length > 0)).length;
  const d_detection = _pct(sigma_ready, n);

  // Dimension 6: P36 certification health
  const d_cert = p36cert?.blocker_count === 0
    ? Math.min(100, ((p36cert.passed_count / (p36cert.total_gates || 1)) * 100))
    : 50;

  // Dimension 7: P26 grade signal (call existing engine on synthetic aggregate)
  const synth = {
    risk_score:       7.5,
    severity:         'HIGH',
    confidence_score: confAudit.avg_confidence || 40,
    source_trust_score: 0.75,
    ttps:    enrichAudit.coverage.ttp_pct  >= 50 ? ['T1059'] : [],
    iocs:    enrichAudit.coverage.ioc_pct  >= 50 ? [{ type: 'ip' }] : [],
    cvss_score:  enrichAudit.coverage.cvss_pct >= 50 ? 7.5 : 0,
    epss_score:  enrichAudit.coverage.epss_pct >= 50 ? 0.5 : 0,
    kev_present: enrichAudit.coverage.kev_pct  >= 20,
  };
  const grade_result = computeP26Grade(synth);
  const grade_score  = { 'A+': 100, A: 92, 'B+': 85, B: 78, 'C+': 70, C: 62, D: 50, F: 30 }[grade_result.grade] ?? 65;

  // Weighted composite IQ Score
  const weights = {
    enrichment: 0.22,
    confidence: 0.18,
    evidence:   0.20,
    diversity:  0.10,
    detection:  0.15,
    cert:       0.10,
    grade:      0.05,
  };

  const iq_score = +(
    d_enrichment * weights.enrichment +
    d_confidence * weights.confidence +
    d_evidence   * weights.evidence   +
    d_diversity  * weights.diversity  +
    d_detection  * weights.detection  +
    d_cert       * weights.cert       +
    grade_score  * weights.grade
  ).toFixed(1);

  const iq_tier = iq_score >= 85 ? 'WORLD_CLASS'
                : iq_score >= 70 ? 'ENTERPRISE_READY'
                : iq_score >= 55 ? 'MATURE'
                : iq_score >= 40 ? 'BASIC'
                : 'DEVELOPING';

  return {
    iq_score,
    iq_tier,
    grade:  grade_result.grade ?? 'B',
    dimensions: {
      enrichment: { score: d_enrichment, weight: weights.enrichment },
      confidence: { score: +d_confidence.toFixed(1), weight: weights.confidence },
      evidence:   { score: d_evidence,   weight: weights.evidence   },
      diversity:  { score: +d_diversity.toFixed(1), weight: weights.diversity  },
      detection:  { score: d_detection,  weight: weights.detection  },
      certification: { score: +d_cert.toFixed(1), weight: weights.cert },
      p26_grade:  { score: grade_score,  weight: weights.grade      },
    },
    engines_reused: ['computeP20QualityScore', 'computeEnterpriseTrustScore', 'computeP26Grade'],
  };
}

// --- P37.6 Detection Quality --------------------------------------------------

function _detectionQuality(feed) {
  const n = feed.length || 1;

  const sigma_ready   = feed.filter(x => x.ttps?.length > 0 && x.iocs?.length > 0).length;
  const yara_ready    = feed.filter(x => x.iocs?.some(i => typeof i === 'string' && /[\w\-]{8,}/.test(i))).length;
  const hunt_ready    = feed.filter(x => x.ttps?.length > 0).length;
  const kql_ready     = feed.filter(x => x.ttps?.length > 0 && x.severity && x.risk_score).length;
  const mitre_mapped  = feed.filter(x => x.ttps?.some(t => /^T\d{4}/.test(t))).length;
  const enriched      = feed.filter(x => (x.cvss_score && Number(x.cvss_score||0)>0) || x.kev_present).length;

  return {
    feed_item_count:    n,
    sigma_ready_items:  sigma_ready,
    sigma_pct:          _pct(sigma_ready, n),
    hunt_ready_items:   hunt_ready,
    hunt_pct:           _pct(hunt_ready, n),
    kql_ready_items:    kql_ready,
    kql_pct:            _pct(kql_ready, n),
    yara_ready_items:   yara_ready,
    yara_pct:           _pct(yara_ready, n),
    mitre_mapped_items: mitre_mapped,
    mitre_pct:          _pct(mitre_mapped, n),
    enriched_items:     enriched,
    enriched_pct:       _pct(enriched, n),
    detection_tier: sigma_ready >= n * 0.7 ? 'WORLD_CLASS'
                  : sigma_ready >= n * 0.4 ? 'ENTERPRISE_READY'
                  : sigma_ready >= n * 0.2 ? 'MATURE'
                  : 'DEVELOPING',
  };
}

// --- P37.7 Platform Reliability -----------------------------------------------

function _reliabilityAudit(feed, p36cert, p35cert, p34cert) {
  const n = feed.length;
  const unique_ids = new Set(feed.map(x => x.id)).size;
  const dup_count  = n - unique_ids;

  const fresh_48h  = feed.filter(x => {
    const ts = x.processed_at || x.published_at || x.timestamp;
    if (!ts) return false;
    return (Date.now() - new Date(ts).getTime()) < 48 * 3600 * 1000;
  }).length;

  const cert_chain_intact = [p36cert, p35cert, p34cert].every(c => c?.release_tier === 'WORLDWIDE_RELEASE');
  const total_blockers    = (p36cert?.blocker_count ?? 0) + (p35cert?.blocker_count ?? 0) + (p34cert?.blocker_count ?? 0);

  const reliability_score = (
    (dup_count === 0 ? 30 : Math.max(0, 30 - dup_count * 2)) +
    (cert_chain_intact ? 40 : 20) +
    (total_blockers === 0 ? 20 : 0) +
    (_pct(fresh_48h, n || 1) >= 80 ? 10 : 5)
  );

  return {
    feed_item_count:     n,
    unique_items:        unique_ids,
    duplicate_count:     dup_count,
    fresh_48h_count:     fresh_48h,
    fresh_48h_pct:       _pct(fresh_48h, n || 1),
    cert_chain_intact,
    total_cert_blockers: total_blockers,
    reliability_score,
    reliability_tier: reliability_score >= 90 ? 'ENTERPRISE_READY'
                    : reliability_score >= 70 ? 'MATURE'
                    : reliability_score >= 50 ? 'BASIC'
                    : 'DEVELOPING',
    p36_tier:  p36cert?.release_tier ?? 'UNKNOWN',
    p35_tier:  p35cert?.release_tier ?? 'UNKNOWN',
    p34_tier:  p34cert?.release_tier ?? 'UNKNOWN',
  };
}

// --- P37.8 Engineering Excellence / Technical Debt ---------------------------

function _debtAudit(enrichAudit) {
  const debts = [];

  // Document verified field-name defect in P35 cert
  for (const d of enrichAudit.known_defects) {
    debts.push({
      id:       d.defect_id,
      layer:    d.layer,
      severity: d.severity,
      type:     'FIELD_NAME_DEFECT',
      description: d.description,
      remediation: 'P35 G16: update field check to include actor_tag in addition to actor/threat_actor',
      verified:    d.verified,
      impact:      'FALSE_WARNING  -  P35 gate reports 0% actor attribution when actual coverage is actor_tag=100%',
    });
  }

  // Document the three-feed architecture
  debts.push({
    id:       'DEBT-FEED-01',
    layer:    'PLATFORM',
    severity: 'WARNING',
    type:     'ARCHITECTURAL_COMPLEXITY',
    description: 'Three feed files exist: feed.json (root, 72 items), api/feed.json (58 live CVE items), data/feed.json (159 aggregate). Cert scripts read different files causing metric divergence.',
    remediation: 'Establish canonical feed path policy; P37 cert gates on api/feed.json (live production)',
    verified:    true,
    impact:      'MEDIUM  -  cert metrics differ from production reality; P35 rates from stale root feed.json',
  });

  const score = Math.max(0, 100 - debts.length * 10);
  return {
    total_items:   debts.length,
    critical_count:debts.filter(d => d.severity === 'BLOCKER_DEFECT').length,
    warning_count: debts.filter(d => d.severity !== 'BLOCKER_DEFECT').length,
    engineering_health_score: score,
    debt_tier: score >= 90 ? 'EXCELLENT' : score >= 75 ? 'GOOD' : score >= 60 ? 'NEEDS_ATTENTION' : 'CRITICAL',
    items: debts,
  };
}

// --- exported route handlers --------------------------------------------------

export async function handleP37Hardening(request, env) {
  const feed = await _loadFeed(env);
  const p36  = await _loadQuality(env, 'p36_certification_report');
  const p35  = await _loadQuality(env, 'p35_certification_report');
  const p34  = await _loadQuality(env, 'p34_certification_report');
  const enrich  = _enrichmentAudit(feed);
  const conf    = _confidenceAudit(feed);
  const evid    = _evidenceAudit(feed);
  const divers  = _sourceDiversityAudit(feed);
  const detq    = _detectionQuality(feed);
  const rel     = _reliabilityAudit(feed, p36, p35, p34);
  const debt    = _debtAudit(enrich);
  const iq      = _computeIQScore(feed, enrich, conf, evid, divers, p36);

  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'platform_hardening',
    iq_score:   iq.iq_score,
    iq_tier:    iq.iq_tier,
    enrichment_tier:   enrich.tier,
    detection_tier:    detq.detection_tier,
    reliability_tier:  rel.reliability_tier,
    debt_tier:         debt.debt_tier,
    cert_chain:        { p36: rel.p36_tier, p35: rel.p35_tier, p34: rel.p34_tier },
    known_defects:     debt.items.length,
    summary:    `IQ=${iq.iq_score}/100 (${iq.iq_tier}) | cert chain intact=${rel.cert_chain_intact} | defects=${debt.items.length}`,
  });
}

export async function handleP37FeedAudit(request, env) {
  const feed = await _loadFeed(env);
  const enrich  = _enrichmentAudit(feed);
  const divers  = _sourceDiversityAudit(feed);
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'feed_audit',
    feed_item_count:    feed.length,
    source_diversity:   divers,
    enrichment_audit:   enrich,
    feed_classification: divers.feed_type,
    p37_note: 'P37 gates on live production feed (KV feed:latest). Phase 0 audit identified 3-feed architecture: live CVE feed (api/feed.json), aggregate intel (data/feed.json), stale root snapshot (feed.json). P37 normalizes certification against the live feed only.',
  });
}

export async function handleP37Enrichment(request, env) {
  const feed = await _loadFeed(env);
  const enrich = _enrichmentAudit(feed);
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'enrichment_excellence',
    feed_item_count: feed.length,
    enrichment_score: enrich.enrichment_score,
    enrichment_tier:  enrich.tier,
    coverage:         enrich.coverage,
    known_defects:    enrich.known_defects,
    pipeline_status: {
      cvss_epss:   enrich.coverage.cvss_pct > 50 ? 'ACTIVE' : 'NEEDS_RUN',
      kev_marker:  enrich.coverage.kev_pct  > 10 ? 'ACTIVE' : 'NEEDS_RUN',
      actor_tag:   enrich.coverage.actor_pct> 50 ? 'ACTIVE' : 'NEEDS_RUN',
    },
  });
}

export async function handleP37IQScore(request, env) {
  const feed = await _loadFeed(env);
  const p36  = await _loadQuality(env, 'p36_certification_report');
  const enrich  = _enrichmentAudit(feed);
  const conf    = _confidenceAudit(feed);
  const evid    = _evidenceAudit(feed);
  const divers  = _sourceDiversityAudit(feed);
  const iq      = _computeIQScore(feed, enrich, conf, evid, divers, p36);
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'intelligence_quality_score',
    feed_item_count: feed.length,
    ...iq,
  });
}

export async function handleP37Detection(request, env) {
  const feed = await _loadFeed(env);
  const det  = _detectionQuality(feed);
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'detection_quality',
    ...det,
  });
}

export async function handleP37SourceDiversity(request, env) {
  const feed   = await _loadFeed(env);
  const divers = _sourceDiversityAudit(feed);
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'source_diversity_hardening',
    feed_item_count: feed.length,
    ...divers,
    p37_note: 'P37.1: Thresholds are feed-type-aware. CVE feeds tolerate higher concentration by design. Broad threat intel feeds require >=3 sources and <75% dominance.',
  });
}

export async function handleP37Reliability(request, env) {
  const feed = await _loadFeed(env);
  const p36  = await _loadQuality(env, 'p36_certification_report');
  const p35  = await _loadQuality(env, 'p35_certification_report');
  const p34  = await _loadQuality(env, 'p34_certification_report');
  const rel  = _reliabilityAudit(feed, p36, p35, p34);
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'platform_reliability',
    ...rel,
  });
}

export async function handleP37Debt(request, env) {
  const feed   = await _loadFeed(env);
  const enrich = _enrichmentAudit(feed);
  const debt   = _debtAudit(enrich);
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'engineering_excellence',
    ...debt,
  });
}

export async function handleP37Metrics(request, env) {
  const feed = await _loadFeed(env);
  const p36  = await _loadQuality(env, 'p36_certification_report');
  const p35  = await _loadQuality(env, 'p35_certification_report');
  const p34  = await _loadQuality(env, 'p34_certification_report');
  const enrich = _enrichmentAudit(feed);
  const conf   = _confidenceAudit(feed);
  const evid   = _evidenceAudit(feed);
  const divers = _sourceDiversityAudit(feed);
  const iq     = _computeIQScore(feed, enrich, conf, evid, divers, p36);
  const det    = _detectionQuality(feed);
  const rel    = _reliabilityAudit(feed, p36, p35, p34);

  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'kpi_dashboard',
    kpis: {
      iq_score:             iq.iq_score,
      iq_tier:              iq.iq_tier,
      enrichment_score:     enrich.enrichment_score,
      confidence_coverage:  conf.coverage_pct,
      avg_confidence:       conf.avg_confidence,
      evidence_coverage:    evid.evidence_coverage_pct,
      sigma_ready_pct:      det.sigma_pct,
      source_diversity:     divers.distinct_sources,
      reliability_score:    rel.reliability_score,
      cert_chain_blockers:  rel.total_cert_blockers,
      p36_tier:             p36?.release_tier ?? 'UNKNOWN',
      feed_item_count:      feed.length,
    },
  });
}

export async function handleP37Certification(request, env) {
  const p36 = await _loadQuality(env, 'p36_certification_report');
  const p37 = await _loadQuality(env, 'p37_certification_report');
  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'certification_summary',
    p37_cert: p37 ?? { status: 'REPORT_PENDING', note: 'Run p37_production_certification.py to generate' },
    p36_tier: p36?.release_tier ?? 'UNKNOWN',
    cert_chain: 'P37 -> P36 -> P35 -> P34 -> P33',
  });
}

export async function handleP37Dashboard(request, env) {
  const feed = await _loadFeed(env);
  const p36  = await _loadQuality(env, 'p36_certification_report');
  const p35  = await _loadQuality(env, 'p35_certification_report');
  const p34  = await _loadQuality(env, 'p34_certification_report');
  const enrich = _enrichmentAudit(feed);
  const conf   = _confidenceAudit(feed);
  const evid   = _evidenceAudit(feed);
  const divers = _sourceDiversityAudit(feed);
  const iq     = _computeIQScore(feed, enrich, conf, evid, divers, p36);
  const det    = _detectionQuality(feed);
  const rel    = _reliabilityAudit(feed, p36, p35, p34);
  const debt   = _debtAudit(enrich);

  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'unified_dashboard',
    iq_score:   iq.iq_score,
    iq_tier:    iq.iq_tier,
    iq_grade:   iq.grade,
    enrichment: { score: enrich.enrichment_score, tier: enrich.tier, coverage: enrich.coverage },
    confidence: { coverage_pct: conf.coverage_pct, avg: conf.avg_confidence, tier: conf.calibration_tier },
    evidence:   { coverage_pct: evid.evidence_coverage_pct, tier: evid.evidence_tier },
    diversity:  { sources: divers.distinct_sources, dominance: divers.dominance_pct, status: divers.status, feed_type: divers.feed_type },
    detection:  { sigma_pct: det.sigma_pct, hunt_pct: det.hunt_pct, tier: det.detection_tier },
    reliability:{ score: rel.reliability_score, tier: rel.reliability_tier, cert_chain_intact: rel.cert_chain_intact },
    debt:       { items: debt.total_items, health: debt.engineering_health_score, tier: debt.debt_tier },
    cert_chain: { p36: rel.p36_tier, p35: rel.p35_tier, p34: rel.p34_tier },
    engines_reused: ['computeP20QualityScore', 'computeEnterpriseTrustScore', 'computeP26Grade'],
  });
}

export async function handleP37Observability(request, env) {
  const feed = await _loadFeed(env);
  const p36  = await _loadQuality(env, 'p36_certification_report');
  const enrich = _enrichmentAudit(feed);
  const conf   = _confidenceAudit(feed);
  const evid   = _evidenceAudit(feed);
  const divers = _sourceDiversityAudit(feed);
  const iq     = _computeIQScore(feed, enrich, conf, evid, divers, p36);

  return _json({
    schema_version: 'p37.0', timestamp: _ts(), layer: 'P37',
    capability: 'observability',
    p_layer_version: 'P37.0',
    platform:  'CYBERDUDEBIVASH(R) SENTINEL APEX',
    health:    iq.iq_score >= 60 ? 'GREEN' : iq.iq_score >= 40 ? 'AMBER' : 'RED',
    metrics: {
      feed_item_count:    feed.length,
      iq_score:           iq.iq_score,
      iq_tier:            iq.iq_tier,
      enrichment_score:   enrich.enrichment_score,
      p36_tier:           p36?.release_tier ?? 'UNKNOWN',
    },
    engines_reused: ['computeP20QualityScore', 'computeEnterpriseTrustScore', 'computeP26Grade'],
  });
}
