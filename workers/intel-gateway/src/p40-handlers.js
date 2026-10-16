/**
 * workers/intel-gateway/src/p40-handlers.js
 * P40.0 Global Intelligence Source Fabric  -  Source Registry & Health API
 *
 * ARCHITECTURE NOTE: this layer composes over the canonical Source Registry
 * and Source Health artifacts produced Python-side
 * (scripts/build_source_registry.py, scripts/source_fabric_health.py) and
 * bridged into R2 by scripts/r2_upload.py  -  the same "Python pipeline
 * writes JSON -> R2 -> Worker reads via env.INTEL_R2.get()" pattern already
 * used by p21-handlers.js:_loadFeed and every other P-layer that reads
 * feed data, replicated here rather than introducing a new access pattern.
 *
 * This file computes NO per-item scoring logic and reuses none of
 * computeP20QualityScore / computeEnterpriseTrustScore / computeP26Grade:
 * those score individual intelligence ITEMS, which is a different problem
 * from source-level registry/health data. There is no existing P-layer
 * engine for "is this SOURCE healthy and what does it cost to use"  -  that
 * gap is exactly what the Global Intelligence Source Fabric mission adds.
 * See the P40 Reuse Report in the implementation's final deliverables for
 * why this is a genuine gap, not a missed reuse opportunity.
 *
 * 10 exported handlers / 10 API routes:
 *   /api/v1/p40/source-registry   - full registry listing (filterable by
 *                                   ?status=, ?wave=, ?domain=)
 *   /api/v1/p40/source-detail     - single source by ?id= + its live health
 *   /api/v1/p40/source-health     - full health/observability report
 *   /api/v1/p40/licensing         - licensing governance rollup (Section 23)
 *   /api/v1/p40/coverage          - intelligence-domain coverage matrix +
 *                                   Global CTI Coverage Score (see
 *                                   computeDomainScore's docstring for the
 *                                   scoring model)
 *   /api/v1/p40/waves             - Wave 1-5 rollout status (Section 39)
 *   /api/v1/p40/certification     - P40 certification chain status
 *   /api/v1/p40/metrics           - platform-wide source-fabric KPIs
 *   /api/v1/p40/dashboard         - dashboard-ready composite payload
 *   /api/v1/p40/observability     - observability health endpoint
 */

const P40_VERSION   = '40.0';
const REGISTRY_KEY  = 'intel/source_registry.json';
const HEALTH_KEY    = 'intel/source_fabric_health.json';
const CERT_KEY      = 'intel/p40_certification_report.json';

// ---------------------------------------------------------------------------
// Global CTI Coverage Score  -  documented, deterministic scoring model.
//
// Deliberately NOT `active_sources / total_sources` (meaningless: treats a
// single low-quality source identically to five corroborating authoritative
// ones, and treats every REQUIRES_LICENSE/PLANNED source as equally "not
// covering" when in reality they represent very different activation
// distance). Instead, each source contributes a [0,1] "trust" score:
//
//   contribution = authority_weight * health_weight * quality
//
//   authority_weight  from source.authority_level (registry field, already
//                      populated for all 104 sources)  -  GOVERNMENT_AUTHORITATIVE
//                      counts more than COMMUNITY.
//   health_weight     from the source's live health_status (see
//                      source_fabric_health.py)  -  a HEALTHY source counts
//                      fully, a STALE one partially, a not-yet-live one not
//                      at all. This is what makes the score reflect CURRENT
//                      reality, not registry aspiration.
//   quality           average of registry quality_score/reliability_score
//                      (both 0-100, already tracked per source), normalized
//                      to [0,1].
//
// Per intelligence domain, contributions from every source tagged with that
// domain combine via a noisy-OR model:
//
//   domain_score = 1 - PRODUCT(1 - contribution_i)   for every source i
//                  tagged with that domain
//
// This rewards corroboration (multiple independent healthy sources push a
// domain's score toward 100 with diminishing returns) without letting one
// weak or dead source drag down a domain three good sources already cover
// well  -  the failure mode of a naive average. The global score is the
// unweighted mean of the 9 mission-domain scores (equal weighting is a
// deliberate, documented simplification  -  every domain matters equally to
// the mission; weighting by e.g. customer usage is a natural v2 input once
// that telemetry exists, not fabricated here).
const _AUTHORITY_WEIGHT = {
  GOVERNMENT_AUTHORITATIVE: 1.0,
  VENDOR_AUTHORITATIVE:     0.9,
  RESEARCH_PUBLICATION:     0.75,
  COMMERCIAL_VENDOR:        0.7,
  AGGREGATOR:               0.55,
  COMMUNITY:                0.5,
};

const _HEALTH_WEIGHT = {
  HEALTHY:              1.0,
  DEGRADED:             0.6,
  NO_DATA:              0.3,
  STALE:                0.3,
  AWAITING_CREDENTIALS: 0,
  AWAITING_LICENSE:     0,
  NOT_RUNNING:          0,
  NOT_APPLICABLE:       0,
  DISABLED:             0,
};

// API label -> registry intelligence_domains value(s) it aggregates. See
// data/registry/source_registry.json for the full domain vocabulary;
// infrastructure rolls up several closely related tags per the task's own
// domain list (DNS/ASN/certificates/IP relationships all under
// "Infrastructure").
const _MISSION_DOMAINS = {
  vulnerability:  ['vulnerability'],
  exploit:        ['exploit'],
  malware:        ['malware'],
  ioc:            ['ioc'],
  threat_actor:   ['threat_actor'],
  infrastructure: ['infrastructure', 'passive_dns', 'certificate', 'attack_surface', 'internet_measurement'],
  phishing:       ['phishing'],
  ransomware:     ['ransomware'],
  government:     ['government_cert'],
};

function _sourceContribution(source, healthById) {
  const authorityW = _AUTHORITY_WEIGHT[source.authority_level] ?? 0.5;
  const healthEntry = healthById.get(source.source_id);
  const healthW = healthEntry ? (_HEALTH_WEIGHT[healthEntry.health_status] ?? 0) : 0;
  const quality = ((source.quality_score ?? 0) + (source.reliability_score ?? 0)) / 200;
  return authorityW * healthW * quality;
}

function _computeDomainScore(sources, domainKeys, healthById) {
  const contributing = sources.filter(s => (s.intelligence_domains || []).some(d => domainKeys.includes(d)));
  if (contributing.length === 0) {
    return { score: 0, contributing_sources: 0, positive_contribution_sources: 0 };
  }
  let productOfMisses = 1;
  // Count of sources with contribution > 0 -- NOT the same as strictly
  // HEALTHY: a STALE/NO_DATA source still contributes at a reduced weight
  // (see _HEALTH_WEIGHT), so it's counted here too. Named distinctly from
  // the top-level response's `healthy_sources` field (which IS the strict
  // health_breakdown.HEALTHY count) to avoid conflating the two.
  let positiveContributionCount = 0;
  for (const s of contributing) {
    const c = _sourceContribution(s, healthById);
    if (c > 0) positiveContributionCount += 1;
    productOfMisses *= (1 - c);
  }
  return {
    score: Math.round((1 - productOfMisses) * 100),
    contributing_sources: contributing.length,
    positive_contribution_sources: positiveContributionCount,
  };
}

// ---------------------------------------------------------------------------
// R2 loaders  -  mirrors p21-handlers.js:_loadFeed's env.INTEL_R2?.get() +
// optional-chaining-safe pattern, scoped to this layer's own R2 keys.
// ---------------------------------------------------------------------------

async function _loadR2Json(env, key) {
  try {
    const obj = await env.INTEL_R2?.get(key);
    if (!obj) return null;
    const text = await obj.text();
    if (!text || !text.trim()) return null;
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

// Exported (unlike this file's other _-prefixed helpers) so index.js's new
// /api/metrics route can reuse the same registry read for feed_source_count
// instead of re-implementing the R2 read -- see that route's own comment.
export async function _loadRegistry(env) {
  return await _loadR2Json(env, REGISTRY_KEY);
}

async function _loadHealth(env) {
  return await _loadR2Json(env, HEALTH_KEY);
}

function _json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'X-P40-Version': P40_VERSION },
  });
}

function _registryUnavailable() {
  return _json({
    error: 'Source registry not yet synced to R2',
    hint: 'Run scripts/build_source_registry.py then scripts/r2_upload.py, or check the '
        + 'sentinel-apex.yml P40 CI stage for the last sync attempt.',
    version: P40_VERSION,
  }, 503);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export async function handleP40SourceRegistry(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();

  const url = new URL(request.url);
  const status = url.searchParams.get('status');
  const wave = url.searchParams.get('wave');
  const domain = url.searchParams.get('domain');
  // Ops-oriented filters: reuse this endpoint rather than standing up a
  // second near-identical /api/v1/p40/sources route (Single Source of
  // Truth  -  a duplicate route serving the same registry data would be an
  // architectural violation, not a convenience).
  const healthFilter = url.searchParams.get('health');
  const priorityFilter = url.searchParams.get('priority');   // maps to criticality
  const requiresFilter = url.searchParams.get('requires');   // "credentials" | "license"

  let sources = registry.sources;
  if (status) sources = sources.filter(s => s.implementation_status === status.toUpperCase());
  if (wave) sources = sources.filter(s => String(s.wave) === wave);
  if (domain) sources = sources.filter(s => (s.intelligence_domains || []).includes(domain));
  if (priorityFilter) sources = sources.filter(s => s.criticality === priorityFilter.toUpperCase());
  if (requiresFilter) {
    const wantStatus = requiresFilter.toLowerCase() === 'license' ? 'REQUIRES_LICENSE' : 'REQUIRES_CREDENTIALS';
    sources = sources.filter(s => s.implementation_status === wantStatus);
  }

  let healthById = null;
  if (healthFilter) {
    const health = await _loadHealth(env);
    healthById = new Map((health?.sources || []).map(h => [h.source_id, h]));
    const wanted = healthFilter.toUpperCase();
    sources = sources.filter(s => {
      const h = healthById.get(s.source_id);
      if (!h) return false;
      return h.health_status === wanted || h.state === wanted;
    });
  }

  return _json({
    schema_version: 'p40.0',
    registry_version: registry.registry_version,
    generated_at: registry.generated_at,
    total: sources.length,
    filters_applied: {
      status: status || null, wave: wave || null, domain: domain || null,
      health: healthFilter || null, priority: priorityFilter || null, requires: requiresFilter || null,
    },
    status_breakdown: registry.status_breakdown,
    wave_breakdown: registry.wave_breakdown,
    sources,
  });
}

export async function handleP40SourceDetail(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();

  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return _json({ error: "Missing required query param 'id'", version: P40_VERSION }, 400);

  const source = registry.sources.find(s => s.source_id === id);
  if (!source) return _json({ error: `Unknown source_id: ${id}`, version: P40_VERSION }, 404);

  const health = await _loadHealth(env);
  const healthEntry = health ? (health.sources || []).find(h => h.source_id === id) : null;

  return _json({ schema_version: 'p40.0', source, health: healthEntry || null });
}

export async function handleP40SourceHealth(request, env) {
  const health = await _loadHealth(env);
  if (!health) {
    return _json({
      error: 'Source health report not yet synced to R2',
      hint: 'Run scripts/source_fabric_health.py then scripts/r2_upload.py.',
      version: P40_VERSION,
    }, 503);
  }
  return _json({ schema_version: 'p40.0', ...health });
}

export async function handleP40Licensing(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();

  const sources = registry.sources;
  const byClass = {};
  for (const s of sources) byClass[s.licensing_class] = (byClass[s.licensing_class] || 0) + 1;

  return _json({
    schema_version: 'p40.0',
    total: sources.length,
    redistribution_allowed: sources.filter(s => s.redistribution_allowed).length,
    redistribution_restricted: sources.filter(s => !s.redistribution_allowed).length,
    commercial_use_allowed: sources.filter(s => s.commercial_use_allowed).length,
    attribution_required: sources.filter(s => s.attribution_required).length,
    by_licensing_class: byClass,
    // Governance surface for Section 23  -  "the system must prevent
    // accidental redistribution of restricted data": every non-
    // redistributable source, explicitly enumerated.
    restricted_sources: sources
      .filter(s => !s.redistribution_allowed)
      .map(s => ({
        source_id: s.source_id,
        canonical_name: s.canonical_name,
        licensing_class: s.licensing_class,
        implementation_status: s.implementation_status,
      })),
  });
}

export async function handleP40Coverage(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();
  const health = await _loadHealth(env);

  // Preserved exactly as before -- backward compatible, existing consumers
  // of `domain_coverage` see zero change.
  const coverage = {};
  for (const s of registry.sources) {
    for (const d of (s.intelligence_domains || [])) {
      coverage[d] = coverage[d] || { total: 0, by_status: {} };
      coverage[d].total += 1;
      coverage[d].by_status[s.implementation_status] = (coverage[d].by_status[s.implementation_status] || 0) + 1;
    }
  }

  const healthById = new Map((health?.sources || []).map(h => [h.source_id, h]));
  const dimensions = {};
  const dimensionScores = [];
  for (const [label, domainKeys] of Object.entries(_MISSION_DOMAINS)) {
    const d = _computeDomainScore(registry.sources, domainKeys, healthById);
    dimensions[label] = d;
    dimensionScores.push(d.score);
  }
  const globalScore = dimensionScores.length
    ? Math.round(dimensionScores.reduce((a, b) => a + b, 0) / dimensionScores.length)
    : 0;

  const statusCounts = {};
  for (const s of registry.sources) {
    statusCounts[s.implementation_status] = (statusCounts[s.implementation_status] || 0) + 1;
  }

  return _json({
    schema_version: 'p40.0',
    generated_at: new Date().toISOString(),
    score: globalScore,
    scoring_model: 'noisy_or_corroboration_v1',
    dimensions,
    domain_coverage: coverage,
    source_count: registry.total_sources,
    status_breakdown: statusCounts,
    healthy_sources: health ? (health.health_breakdown?.HEALTHY ?? 0) : null,
    stale_sources: health ? (health.health_breakdown?.STALE ?? 0) : null,
    credential_required: statusCounts.REQUIRES_CREDENTIALS || 0,
    license_required: statusCounts.REQUIRES_LICENSE || 0,
    // Not a numeric confidence score -- an honest statement of what data
    // this computation actually had available, so a caller can tell
    // "computed from live health" apart from "registry only, health report
    // unavailable" (a materially weaker basis, not silently the same).
    confidence: health ? 'DERIVED_FROM_LIVE_HEALTH' : 'REGISTRY_ONLY_NO_HEALTH_DATA',
    trend: {
      current: globalScore,
      '24h': null,
      '7d': null,
      '30d': null,
      // No time-series coverage-score history is persisted anywhere yet --
      // Section 11 is explicit that this must not be fabricated.
      historical_data_available: false,
    },
  });
}

export async function handleP40Waves(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();

  const waves = {};
  for (const s of registry.sources) {
    const w = `wave_${s.wave}`;
    waves[w] = waves[w] || { total: 0, by_status: {} };
    waves[w].total += 1;
    waves[w].by_status[s.implementation_status] = (waves[w].by_status[s.implementation_status] || 0) + 1;
  }
  return _json({ schema_version: 'p40.0', waves });
}

// sentinel-apex.yml  -  the pipeline that regenerates and R2-syncs this
// report  -  runs 3x/day (cron '0 0,8,16 * * *', ~8h cadence). This threshold
// is a generous 2x that cadence, matching source_fabric_health.py's
// staleness philosophy: flag genuine silence, not a run landing a bit late.
const CERT_FRESHNESS_STALE_SECONDS = 16 * 3600;

export async function handleP40Certification(request, env) {
  const cert = await _loadR2Json(env, CERT_KEY);
  if (!cert) {
    return _json({
      error: 'P40 certification report not yet synced to R2',
      hint: 'Run scripts/p40_production_certification.py then scripts/r2_upload.py.',
      version: P40_VERSION,
    }, 503);
  }

  const generatedAtMs = cert.generated_at ? Date.parse(cert.generated_at) : NaN;
  const ageSeconds = Number.isFinite(generatedAtMs)
    ? Math.max(0, Math.floor((Date.now() - generatedAtMs) / 1000))
    : null;
  const freshness = ageSeconds === null
    ? 'UNKNOWN'
    : (ageSeconds > CERT_FRESHNESS_STALE_SECONDS ? 'STALE' : 'FRESH');

  return _json({
    schema_version: 'p40.0',
    ...cert,
    status: cert.release_tier ?? null,
    age_seconds: ageSeconds,
    freshness,
    sync_status: freshness === 'STALE' ? 'LAGGING' : 'SYNCED',
  });
}

export async function handleP40Metrics(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();
  const health = await _loadHealth(env);

  return _json({
    schema_version: 'p40.0',
    total_sources: registry.total_sources,
    status_breakdown: registry.status_breakdown,
    wave_breakdown: registry.wave_breakdown,
    domain_breakdown: registry.domain_breakdown,
    health_breakdown: health ? health.health_breakdown : null,
    live_or_implemented_sources: health ? health.live_or_implemented_sources : null,
    manifest_total_entries: health ? health.manifest_total_entries : null,
  });
}

export async function handleP40Dashboard(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();
  const health = await _loadHealth(env);

  return _json({
    schema_version: 'p40.0',
    generated_at: new Date().toISOString(),
    registry_version: registry.registry_version,
    total_sources: registry.total_sources,
    status_breakdown: registry.status_breakdown,
    wave_breakdown: registry.wave_breakdown,
    domain_breakdown: registry.domain_breakdown,
    health: health ? {
      health_breakdown: health.health_breakdown,
      generated_at: health.generated_at,
      sources: health.sources,
    } : null,
    active_sources: registry.sources
      .filter(s => s.implementation_status === 'ACTIVE')
      .sort((a, b) => a.priority - b.priority)
      .map(s => ({
        source_id: s.source_id, canonical_name: s.canonical_name,
        priority: s.priority, criticality: s.criticality,
        integration_mode: s.integration_mode,
      })),
  });
}

export async function handleP40Observability(request, env) {
  return _json({
    schema_version: 'p40.0',
    layer: 'P40',
    status: 'OPERATIONAL',
    endpoints: [
      '/api/v1/p40/source-registry',
      '/api/v1/p40/source-detail',
      '/api/v1/p40/source-health',
      '/api/v1/p40/licensing',
      '/api/v1/p40/coverage',
      '/api/v1/p40/waves',
      '/api/v1/p40/certification',
      '/api/v1/p40/metrics',
      '/api/v1/p40/dashboard',
      '/api/v1/p40/observability',
    ],
    data_sources: {
      registry: 'data/registry/source_registry.json (R2 key: intel/source_registry.json)',
      health: 'data/quality/source_fabric_health.json (R2 key: intel/source_fabric_health.json)',
      certification: 'data/quality/p40_certification_report.json (R2 key: intel/p40_certification_report.json)',
    },
    generators: [
      'scripts/build_source_registry.py',
      'scripts/source_fabric_health.py',
      'scripts/p40_production_certification.py',
    ],
    engines_reused: [],
    engines_reused_note: 'P40 is source-level (not item-level)  -  see file header for why P20/P25/P26 do not apply here.',
  });
}
