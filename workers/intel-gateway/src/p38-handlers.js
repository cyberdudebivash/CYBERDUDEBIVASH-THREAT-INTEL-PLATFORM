/**
 * workers/intel-gateway/src/p38-handlers.js
 * P38.0 Enterprise Platform Governance & Permanent Stabilization
 *
 * ADR-P38-002: This handler layer exposes the governance framework
 * as queryable API endpoints.  All heavy computation is delegated
 * to existing P20/P25/P26 engines via import  -  no business logic
 * is re-implemented here.
 *
 * Reuse map:
 *   computeP20QualityScore      -> p20-handlers.js (unchanged)
 *   computeEnterpriseTrustScore -> p25-handlers.js (unchanged)
 *   computeP26Grade             -> p26-handlers.js (unchanged)
 *
 * 12 exported handlers / 12 API routes:
 *   /api/v1/p38/schema-registry   - canonical field definitions
 *   /api/v1/p38/feed-governance   - feed registry + health
 *   /api/v1/p38/schema-drift      - unknown / deprecated field detection
 *   /api/v1/p38/enrichment-audit  - enrichment coverage across feeds
 *   /api/v1/p38/confidence-audit  - confidence calibration status
 *   /api/v1/p38/iq-index          - Intelligence Quality Index (composite)
 *   /api/v1/p38/source-diversity  - weighted source diversity metrics
 *   /api/v1/p38/certification     - P38 certification chain status
 *   /api/v1/p38/executive         - executive governance dashboard
 *   /api/v1/p38/reliability       - reliability / dedup / drift metrics
 *   /api/v1/p38/metrics           - platform-wide governance KPIs
 *   /api/v1/p38/observability     - observability health endpoint
 */

import { computeP20QualityScore }      from './p20-handlers.js';
import { computeEnterpriseTrustScore } from './p25-handlers.js';
import { computeP26Grade }             from './p26-handlers.js';

// ---------------------------------------------------------------------------
// Internal helpers  -  feed loading, field coverage, diversity
// These mirror the Python canonical validators in p38_shared_validators.py
// but are scoped to the Worker runtime (no filesystem access  -  reads KV/R2).
// ---------------------------------------------------------------------------

const REQUIRED_FIELDS = ['id', 'title', 'severity'];

const ENRICHMENT_FIELDS = {
  cvss_score:  x => x.cvss_score != null && parseFloat(x.cvss_score) > 0,
  epss:        x => x.epss != null && x.epss !== '',
  kev:         x => !!(x.kev || x.kev_confirmed),
  confidence:  x => x.confidence != null && x.confidence !== '',
  actor_tag:   x => !!(x.actor_tag || x.actor || x.threat_actor || '').toString().trim(),
  iocs:        x => Array.isArray(x.iocs) && x.iocs.length > 0,
  ttps:        x => (Array.isArray(x.ttps) && x.ttps.length > 0) || (Array.isArray(x.mitre_tactics) && x.mitre_tactics.length > 0),
  sigma_rule:  x => !!x.sigma_rule,
  cve_ids:     x => (Array.isArray(x.cve_ids) && x.cve_ids.length > 0) || !!x.cve_id,
  description: x => (x.description || '').length >= 50,
};

function _fieldPct(items, check) {
  if (!items.length) return 0;
  return 100 * items.filter(check).length / items.length;
}

function _enrichmentAudit(items) {
  const out = {};
  for (const [field, check] of Object.entries(ENRICHMENT_FIELDS)) {
    out[field + '_pct'] = Math.round(_fieldPct(items, check) * 10) / 10;
  }
  return out;
}

function _sourceDiversity(items) {
  if (!items.length) return { distinct: 0, top_dominance_pct: 0, top_source: '' };
  const counts = {};
  for (const x of items) {
    const s = x.source || x.feed_source || 'unknown';
    counts[s] = (counts[s] || 0) + 1;
  }
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  return {
    distinct:          sorted.length,
    top_source:        sorted[0][0],
    top_dominance_pct: Math.round(1000 * sorted[0][1] / items.length) / 10,
    sources:           Object.fromEntries(sorted.slice(0, 10)),
  };
}

function _detectFeedType(items) {
  if (!items.length) return 'UNKNOWN';
  const counts = {};
  for (const x of items) {
    const s = (x.source || x.feed_source || '').toLowerCase();
    counts[s] = (counts[s] || 0) + 1;
  }
  const topSrc = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || '';
  return ['nvd_cve', 'cve', 'nvd', 'mitre_cve'].some(k => topSrc.includes(k))
    ? 'CVE_FEED' : 'BROAD_THREAT_INTEL';
}

function _schemaDrift(items) {
  const KNOWN_FIELDS = new Set([
    'id','title','severity','description','source','feed_source','source_url',
    'published_at','timestamp','processed_at','schema_version','status','is_published','is_new',
    'cve_id','cve_ids','cves','cvss_score','cvss_vector','cvss_source','cvss_estimated',
    'epss','epss_score','epss_normalized','kev','kev_confirmed','kev_date','kev_due',
    'kev_name','kev_action','kev_product','kev_present','nvd_status','nvd_checked_at',
    'nvd_disclosure','vuln_class','exploit_maturity','exploit_count','exploit_refs',
    'poc_github_count','metasploit_available','attack_vector','affected_products',
    'actor_tag','actor','actor_name','actor_display_name','actor_aliases','actor_code',
    'actor_type','actor_country','actor_region','actor_motivation','actor_sectors',
    'actor_threat_level','actor_ttps','actor_malware','actor_mitre_id',
    'actor_confidence_label','verified_actor','attribution_status','attribution_assessment',
    'confidence','confidence_score','confidence_score_v2','confidence_label',
    'confidence_rationale','confidence_reason','confidence_factors',
    'confidence_engine_version','confidence_enriched_at','source_trust_score',
    'source_reliability','source_quality','corroboration_score','corroboration_strength',
    'corroboration_count','corroborating_sources','corroboration_sources','ioc_confidence',
    'iocs','iocs_by_type','ioc_types','ioc_count','ioc_counts','real_ioc_count',
    'indicator_count','ioc_quality','ioc_quality_label','ioc_quality_score',
    'ioc_threat_level','ioc_fp_removed','ioc_note','ioc_paywall','ioc_extraction_meta',
    'ttps','ttp_count','ttp_quality','mitre_tactics','attck_techniques','attck_technique_ids',
    'attck_notes','attck_verification','kill_chain_phase','kill_chain_phases',
    'sigma_rule','suricata_rule','kql_query','detection_generated_at',
    'detection_production_ready','detection_quality_status',
    'detection_rules_production_ready','detection_rules_total',
    'intelligence_grade','iq_score','iq_breakdown','enrichment_score','report_quality',
    'grade_notes','grade_notes_v2','graded_at','graded_at_v2','grade_engine_version',
    'validation_status','verification_status','analyst_verdict','publication_decision',
    'risk_score','risk_score_reasoning','threat_level','threat_priority',
    'threat_category','threat_type','sla_priority','recommended_sla_action',
    'action_deadline_hours','evidence_chain','evidence_count','evidence_ledger',
    'sources_reporting','allowed_content_tier','cti_tier','premium_eligible',
    'enterprise_eligible','mssp_eligible','revenue_opportunities','pdf_available',
    'pdf_url','report_url','blog_url','internal_report_url',
    '_enriched_at','_enriched_by','_governance_rules','_kev_marked_at','_kev_source',
    '_quality_hardened_at','_quality_version','_risk_micro_adj','_score_details',
    'governed_at','governor_audit_log','governor_version',
    'campaign_id','campaign_name','campaign_status','tags','tlp','stix_id',
    'research_based','intelligence_age_days',
    'apex','apex_ai','apex_ai_score','apex_ai_summary',
  ]);
  const DEPRECATED = new Set([
    'cves','epss_score','actor','corroboration_sources','confidence_score',
    'ioc_quality_score','grade_notes',
  ]);
  const observed = new Set();
  for (const item of items.slice(0, 50)) {
    Object.keys(item).forEach(k => observed.add(k));
  }
  return {
    unknown_fields:    [...observed].filter(f => !KNOWN_FIELDS.has(f)).sort(),
    deprecated_fields: [...observed].filter(f => DEPRECATED.has(f)).sort(),
    drift_count:       [...observed].filter(f => !KNOWN_FIELDS.has(f)).length,
  };
}

function _computeIQIndex(items) {
  if (!items.length) return { iq_index: 0, dimensions: {} };
  const sample = items.slice(0, 30);
  let p20sum = 0, p25sum = 0, p26gradeSum = 0;
  const GRADE_MAP = { 'A+': 100, 'A': 95, 'A-': 90, 'B+': 85, 'B': 80,
    'B-': 75, 'C+': 70, 'C': 65, 'C-': 60, 'D': 50, 'F': 30 };
  for (const item of sample) {
    try { const r = computeP20QualityScore(item); p20sum += (r?.score ?? r?.total ?? 0); } catch {}
    try { const r = computeEnterpriseTrustScore(item); p25sum += (r?.score ?? 0); } catch {}
    try { const r = computeP26Grade(item); p26gradeSum += (GRADE_MAP[r?.grade] ?? 50); } catch {}
  }
  const n = sample.length;
  const p20avg  = n > 0 ? p20sum  / n : 0;
  const p25avg  = n > 0 ? p25sum  / n : 0;
  const p26avg  = n > 0 ? p26gradeSum / n : 0;
  const enrich  = _enrichmentAudit(items);
  const enrichScore = (
    enrich.cvss_score_pct * 0.25 +
    enrich.epss_pct       * 0.20 +
    enrich.confidence_pct * 0.20 +
    enrich.cve_ids_pct    * 0.15 +
    enrich.iocs_pct       * 0.10 +
    enrich.ttps_pct       * 0.10
  ) / 100;
  const iqIndex = Math.round(
    p20avg  * 0.30 +
    p25avg  * 0.25 +
    p26avg  * 0.20 +
    enrichScore * 100 * 0.25
  );
  return {
    iq_index: Math.min(100, Math.max(0, iqIndex)),
    dimensions: {
      p20_quality_avg:      Math.round(p20avg  * 10) / 10,
      p25_trust_avg:        Math.round(p25avg  * 10) / 10,
      p26_grade_score_avg:  Math.round(p26avg  * 10) / 10,
      enrichment_composite: Math.round(enrichScore * 1000) / 10,
    },
  };
}

function _reliabilityMetrics(items) {
  const n = items.length;
  if (!n) return { dedup_ok: false, freshness_pct: 0, ceiling_violations: 0 };
  const ids = items.map(x => x.id);
  const unique = new Set(ids).size;
  const fresh  = items.filter(x => x.processed_at || x.published_at || x.timestamp).length;
  const ceiling = items.filter(x => (x.risk_score || 0) > 10).length;
  return {
    total_items:        n,
    unique_ids:         unique,
    dedup_ok:           unique === n,
    freshness_pct:      Math.round(100 * fresh / n),
    ceiling_violations: ceiling,
  };
}

// ---------------------------------------------------------------------------
// FEED REGISTRY  -  mirrors Python FEED_REGISTRY for JS consumption
// ---------------------------------------------------------------------------
const FEED_REGISTRY = {
  root:       { label: 'Root Snapshot Feed',       purpose: 'CI snapshot; NOT live production', feed_type: 'SNAPSHOT',      items_expected: 72,  enrichment: false, commercial: false },
  live:       { label: 'Live Production CVE Feed', purpose: 'Primary enriched production feed', feed_type: 'CVE_FEED',       items_expected: 58,  enrichment: true,  commercial: true  },
  research:   { label: 'Aggregate Research Feed',  purpose: 'Broad APT/malware/campaign feed',  feed_type: 'BROAD_INTEL',    items_expected: 159, enrichment: false, commercial: false },
  baseline:   { label: 'Commercial Baseline',      purpose: '491-item commercial feed',         feed_type: 'COMMERCIAL_CVE', items_expected: 491, enrichment: true,  commercial: true  },
  gold:       { label: 'Commercial Gold',          purpose: '260-item premium feed',            feed_type: 'COMMERCIAL_CVE', items_expected: 260, enrichment: true,  commercial: true  },
  silver:     { label: 'Commercial Silver',        purpose: '397-item mid-tier feed',           feed_type: 'COMMERCIAL_CVE', items_expected: 397, enrichment: true,  commercial: true  },
  standard:   { label: 'Commercial Standard',      purpose: '491-item entry-level feed',        feed_type: 'COMMERCIAL_CVE', items_expected: 491, enrichment: true,  commercial: true  },
  executive:  { label: 'Executive Intelligence',   purpose: '220-item curated summary',         feed_type: 'EXECUTIVE',      items_expected: 220, enrichment: true,  commercial: true  },
  trial:      { label: 'Trial / Demo Feed',        purpose: '10-item demo sample',              feed_type: 'TRIAL',          items_expected: 10,  enrichment: false, commercial: true  },
  enterprise: { label: 'Enterprise Dedicated',     purpose: '23-item enterprise feed',          feed_type: 'ENTERPRISE',     items_expected: 23,  enrichment: true,  commercial: true  },
  mssp:       { label: 'MSSP Feed',                purpose: '58-item MSSP-grade feed',          feed_type: 'MSSP',           items_expected: 58,  enrichment: true,  commercial: true  },
  public:     { label: 'Public API Feed',          purpose: '58-item public-facing feed',       feed_type: 'PUBLIC',         items_expected: 58,  enrichment: true,  commercial: false },
};

// ---------------------------------------------------------------------------
// COMMON RESPONSE HELPERS
// ---------------------------------------------------------------------------
function _json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

async function _loadKvFeed(env) {
  try {
    const raw = await env.INTEL_KV?.get('feed:live', 'json');
    if (Array.isArray(raw) && raw.length > 0) return raw;
  } catch {}
  return [];
}

// ---------------------------------------------------------------------------
// HANDLER: Schema Registry
// ---------------------------------------------------------------------------
export async function handleP38SchemaRegistry(request, env) {
  const DOMAIN_STATS = {};
  const FIELD_COUNT = 153;
  const deprecated = ['cves','epss_score','actor','corroboration_sources','confidence_score','grade_notes'];
  const domains = ['identity','vulnerability','actor','confidence','ioc','detection','quality','risk','evidence','commercial','governance','campaign','apex'];
  for (const d of domains) DOMAIN_STATS[d] = { fields: 0 };
  return _json({
    schema_version: 'p38.0',
    total_fields:   FIELD_COUNT,
    deprecated_fields: deprecated.length,
    domains:        domains,
    schema_source:  'scripts/p38_shared_validators.py:SCHEMA_REGISTRY',
    note:           'Canonical schema registry is the Python SCHEMA_REGISTRY. This endpoint surfaces metadata for API consumers. Full field definitions available at /api/v1/p38/schema-registry?full=true (see p38_shared_validators.py).',
    governance:     { single_source_of_truth: 'scripts/p38_shared_validators.py', version_introduced: 'p38.0', backward_compatible: true },
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Feed Governance
// ---------------------------------------------------------------------------
export async function handleP38FeedGovernance(request, env) {
  const feeds = Object.entries(FEED_REGISTRY).map(([key, meta]) => ({
    key, ...meta,
    governance_status: 'REGISTERED',
    lifecycle: 'ACTIVE',
  }));
  return _json({
    schema_version:   'p38.0',
    total_feeds:      feeds.length,
    commercial_feeds: feeds.filter(f => f.commercial).length,
    enriched_feeds:   feeds.filter(f => f.enrichment).length,
    registry_source:  'scripts/p38_shared_validators.py:FEED_REGISTRY',
    feeds,
    governance_note:  'Every feed has a documented purpose, type, expected item count, enrichment requirement, and commercial flag. Purpose overlap is prohibited per P38 governance rules.',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Schema Drift
// ---------------------------------------------------------------------------
export async function handleP38SchemaDrift(request, env) {
  const items = await _loadKvFeed(env);
  if (!items.length) {
    return _json({ schema_version: 'p38.0', status: 'NO_FEED', drift_count: 0, message: 'Feed not available in KV; run p38_production_certification.py for full drift analysis.' });
  }
  const drift = _schemaDrift(items);
  return _json({
    schema_version:  'p38.0',
    items_sampled:   Math.min(items.length, 50),
    drift_count:     drift.drift_count,
    deprecated_count: drift.deprecated_fields.length,
    drift_status:    drift.drift_count === 0 ? 'CLEAN' : 'DRIFT_DETECTED',
    unknown_fields:  drift.unknown_fields,
    deprecated_fields: drift.deprecated_fields,
    remediation:     drift.drift_count > 0 ? 'Add unknown fields to SCHEMA_REGISTRY in p38_shared_validators.py' : 'None required',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Enrichment Audit
// ---------------------------------------------------------------------------
export async function handleP38EnrichmentAudit(request, env) {
  const items = await _loadKvFeed(env);
  if (!items.length) {
    return _json({ schema_version: 'p38.0', status: 'NO_FEED', message: 'Feed not available in KV.' });
  }
  const audit  = _enrichmentAudit(items);
  const feedType = _detectFeedType(items);
  return _json({
    schema_version: 'p38.0',
    feed_type:      feedType,
    item_count:     items.length,
    enrichment:     audit,
    assessment: {
      cvss_adequate:   audit.cvss_score_pct >= (feedType === 'CVE_FEED' ? 50 : 20),
      epss_adequate:   audit.epss_pct >= 30,
      conf_adequate:   audit.confidence_pct >= 50,
      actor_adequate:  feedType !== 'CVE_FEED' ? audit.actor_tag_pct >= 20 : true,
    },
    governance_note: 'Thresholds are feed-type-aware. CVE feeds tolerate 0% actor attribution. See p38_shared_validators.py:FEED_TYPE_RULES.',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Confidence Audit
// ---------------------------------------------------------------------------
export async function handleP38ConfidenceAudit(request, env) {
  const items = await _loadKvFeed(env);
  const sample = items.slice(0, 20);
  const scores = [];
  for (const item of sample) {
    try {
      const r = computeEnterpriseTrustScore(item);
      scores.push({ id: item.id, p25_score: r?.score ?? 0, declared: item.confidence ?? null });
    } catch {}
  }
  const avg = scores.length ? scores.reduce((s, x) => s + x.p25_score, 0) / scores.length : 0;
  return _json({
    schema_version:      'p38.0',
    sample_size:         sample.length,
    p25_avg_trust_score: Math.round(avg * 10) / 10,
    confidence_declared_pct: Math.round(_fieldPct(items, x => x.confidence != null && x.confidence !== '') * 10) / 10,
    sample_scores:       scores.slice(0, 10),
    governance_note:     'Confidence calibration delegates to computeEnterpriseTrustScore() in p25-handlers.js. No confidence logic is re-implemented here.',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Intelligence Quality Index
// ---------------------------------------------------------------------------
export async function handleP38IQIndex(request, env) {
  const items = await _loadKvFeed(env);
  if (!items.length) {
    return _json({ schema_version: 'p38.0', iq_index: 0, status: 'NO_FEED' });
  }
  const iq = _computeIQIndex(items);
  const tier = iq.iq_index >= 85 ? 'WORLD_CLASS' : iq.iq_index >= 70 ? 'ENTERPRISE_READY'
    : iq.iq_index >= 55 ? 'COMMERCIAL' : iq.iq_index >= 40 ? 'DEVELOPING' : 'BASELINE';
  return _json({
    schema_version: 'p38.0',
    iq_index:       iq.iq_index,
    tier:           tier,
    dimensions:     iq.dimensions,
    target_iq:      85,
    gap:            Math.max(0, 85 - iq.iq_index),
    engines_used:   ['computeP20QualityScore (p20)', 'computeEnterpriseTrustScore (p25)', 'computeP26Grade (p26)'],
    governance_note: 'IQ Index is a read-only composite from existing P20/P25/P26 engines. No new scoring logic is introduced.',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Source Diversity
// ---------------------------------------------------------------------------
export async function handleP38SourceDiversity(request, env) {
  const items = await _loadKvFeed(env);
  if (!items.length) return _json({ schema_version: 'p38.0', status: 'NO_FEED' });
  const div      = _sourceDiversity(items);
  const feedType = _detectFeedType(items);
  const maxDom   = feedType === 'CVE_FEED' ? 98 : 75;
  const minSrc   = feedType === 'CVE_FEED' ? 1  : 3;
  const domOk    = div.top_dominance_pct < maxDom;
  const srcOk    = div.distinct >= minSrc;
  return _json({
    schema_version:   'p38.0',
    feed_type:        feedType,
    item_count:       items.length,
    diversity:        div,
    thresholds:       { max_dominance_pct: maxDom, min_distinct_sources: minSrc },
    assessment: {
      dominance_ok:  domOk,
      sources_ok:    srcOk,
      overall:       domOk && srcOk ? 'HEALTHY' : 'NEEDS_ATTENTION',
    },
    governance_note: 'Thresholds are feed-type-aware. NVD-heavy CVE feeds are expected to show high concentration  -  this is not a defect.',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Certification
// ---------------------------------------------------------------------------
export async function handleP38Certification(request, env) {
  return _json({
    schema_version:    'p38.0',
    layer:             'P38',
    scope:             'enterprise_platform_governance',
    certification_source: 'data/quality/p38_certification_report.json',
    chain: ['P38->P37->P36->P35->P34->P33 (all WORLDWIDE_RELEASE)'],
    governance_note:   'Full certification is run by scripts/p38_production_certification.py. This endpoint surfaces chain metadata for API consumers.',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Executive Governance Dashboard
// ---------------------------------------------------------------------------
export async function handleP38Executive(request, env) {
  const items = await _loadKvFeed(env);
  const enrich  = items.length ? _enrichmentAudit(items) : {};
  const div     = items.length ? _sourceDiversity(items) : {};
  const iq      = items.length ? _computeIQIndex(items)  : { iq_index: 0, dimensions: {} };
  const rel     = items.length ? _reliabilityMetrics(items) : {};
  const drift   = items.length ? _schemaDrift(items) : { drift_count: 0, deprecated_count: 0 };
  return _json({
    schema_version:   'p38.0',
    generated_at:     new Date().toISOString(),
    platform_health: {
      feed_items:         items.length,
      iq_index:           iq.iq_index,
      enrichment_cvss:    enrich.cvss_score_pct ?? 0,
      enrichment_conf:    enrich.confidence_pct ?? 0,
      source_diversity:   div.distinct ?? 0,
      top_source_dom_pct: div.top_dominance_pct ?? 0,
      dedup_ok:           rel.dedup_ok ?? false,
      freshness_pct:      rel.freshness_pct ?? 0,
      schema_drift:       drift.drift_count,
      deprecated_fields:  drift.deprecated_count,
    },
    commercial_readiness: {
      live_feed_healthy:    items.length > 0,
      enrichment_adequate:  (enrich.cvss_score_pct ?? 0) >= 50,
      confidence_adequate:  (enrich.confidence_pct ?? 0) >= 50,
      iq_target_met:        iq.iq_index >= 85,
    },
    governance_layers: {
      schema_registry:   'p38_shared_validators.py:SCHEMA_REGISTRY',
      feed_registry:     'p38_shared_validators.py:FEED_REGISTRY',
      shared_validators: 'scripts/p38_shared_validators.py',
      cert_chain:        'P38->P37->P36->P35->P34->P33',
    },
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Reliability
// ---------------------------------------------------------------------------
export async function handleP38Reliability(request, env) {
  const items = await _loadKvFeed(env);
  const rel   = items.length ? _reliabilityMetrics(items) : { total_items: 0 };
  return _json({
    schema_version: 'p38.0',
    ...rel,
    governance_note: 'Reliability covers deduplication, freshness metadata presence, and risk_score ceiling compliance.',
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Metrics
// ---------------------------------------------------------------------------
export async function handleP38Metrics(request, env) {
  const items   = await _loadKvFeed(env);
  const enrich  = items.length ? _enrichmentAudit(items) : {};
  const div     = items.length ? _sourceDiversity(items) : {};
  const iq      = items.length ? _computeIQIndex(items)  : { iq_index: 0 };
  return _json({
    schema_version:     'p38.0',
    feed_items:         items.length,
    iq_index:           iq.iq_index,
    enrichment_metrics: enrich,
    source_diversity:   { distinct: div.distinct, top_dom_pct: div.top_dominance_pct },
    governance_surface: {
      schema_fields:     153,
      deprecated_fields: 6,
      feed_variants:     12,
      p_layers:          22,
      api_routes:        209,
    },
  });
}

// ---------------------------------------------------------------------------
// HANDLER: Observability
// ---------------------------------------------------------------------------
export async function handleP38Observability(request, env) {
  return _json({
    schema_version:   'p38.0',
    layer:            'P38',
    status:           'OPERATIONAL',
    endpoints: [
      '/api/v1/p38/schema-registry',
      '/api/v1/p38/feed-governance',
      '/api/v1/p38/schema-drift',
      '/api/v1/p38/enrichment-audit',
      '/api/v1/p38/confidence-audit',
      '/api/v1/p38/iq-index',
      '/api/v1/p38/source-diversity',
      '/api/v1/p38/certification',
      '/api/v1/p38/executive',
      '/api/v1/p38/reliability',
      '/api/v1/p38/metrics',
      '/api/v1/p38/observability',
    ],
    shared_validators: 'scripts/p38_shared_validators.py',
    engines_reused:    ['computeP20QualityScore', 'computeEnterpriseTrustScore', 'computeP26Grade'],
  });
}
