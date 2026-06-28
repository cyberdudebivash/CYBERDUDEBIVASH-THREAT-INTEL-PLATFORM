/**
 * P34  -  Engineering Assurance & Platform Excellence
 * CYBERDUDEBIVASH(R) SENTINEL APEX v1.0.0
 *
 * Scope: unified engineering assurance API surface.
 * This layer does NOT implement intelligence scoring (P20-P33 scope).
 * It surfaces platform health, assurance gate results, security posture,
 * reliability metrics, API contract health, SBOM status, and compliance
 * posture  -  all derived from existing engine outputs in data/.
 *
 * Architecture: additive only. Calls existing data artefacts and engines.
 * No P20-P33 engine logic is re-implemented here.
 */

// --- helpers ----------------------------------------------------------------

function _json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Platform-Layer': 'P34',
    },
  });
}

function _ts() {
  return new Date().toISOString();
}

/**
 * Load the P33 cert report  -  P34 chains from P33.
 * Returns null if absent (non-fatal; gate will warn).
 */
async function _loadP33Cert(env) {
  try {
    const raw = await env.THREAT_INTEL_KV.get('quality:p33_certification_report');
    if (raw) return JSON.parse(raw);
  } catch (_) {}
  return null;
}

/**
 * Load latest feed for size/freshness checks.
 */
async function _loadFeed(env) {
  try {
    const raw = await env.THREAT_INTEL_KV.get('feed:latest');
    return raw ? JSON.parse(raw) : [];
  } catch (_) {
    return [];
  }
}

/**
 * Load a quality report JSON from KV (key = quality:<filename_without_ext>).
 */
async function _loadQualityReport(env, key) {
  try {
    const raw = await env.THREAT_INTEL_KV.get(`quality:${key}`);
    return raw ? JSON.parse(raw) : null;
  } catch (_) {
    return null;
  }
}

// --- assurance gate engine ---------------------------------------------------

/**
 * Evaluate all P34 assurance dimensions against available artefacts.
 * Returns { gates: [...], passed, total, blockers, warnings }
 */
async function _evaluateAssuranceGates(env) {
  const gates = [];
  let passed = 0;
  let blockers = 0;
  let warnings = 0;

  function gate(id, label, severity, result, detail) {
    const status = result ? 'PASS' : (severity === 'BLOCKER' ? 'FAIL_BLOCKER' : 'FAIL_WARNING');
    if (result) passed++;
    else if (severity === 'BLOCKER') blockers++;
    else warnings++;
    gates.push({ id, label, severity, status, detail });
  }

  // A01: P33 cert chain intact
  const p33 = await _loadP33Cert(env);
  gate('A01', 'P33 certification chain intact', 'BLOCKER',
    p33 !== null && p33.blocker_count === 0,
    p33 ? `tier=${p33.release_tier} blockers=${p33.blocker_count}` : 'P33 cert report not found');

  // A02: P33 release tier is WORLDWIDE_RELEASE
  gate('A02', 'P33 release tier = WORLDWIDE_RELEASE', 'BLOCKER',
    p33?.release_tier === 'WORLDWIDE_RELEASE',
    p33 ? `tier=${p33.release_tier}` : 'unavailable');

  // A03: Feed non-empty
  const feed = await _loadFeed(env);
  gate('A03', 'Feed non-empty (>= 1 item)', 'BLOCKER',
    Array.isArray(feed) && feed.length > 0,
    `feed_items=${Array.isArray(feed) ? feed.length : 0}`);

  // A04: Feed items have required fields
  let fieldOk = true;
  let fieldDetail = '';
  if (Array.isArray(feed) && feed.length > 0) {
    const required = ['id', 'title', 'severity'];
    const missing = feed.slice(0, 20).filter(i => required.some(f => !i[f]));
    fieldOk = missing.length === 0;
    fieldDetail = fieldOk ? 'all required fields present' : `${missing.length} items missing required fields`;
  } else {
    fieldOk = false;
    fieldDetail = 'feed empty';
  }
  gate('A04', 'Feed items have required fields (id, title, severity)', 'BLOCKER', fieldOk, fieldDetail);

  // A05: Severity field type stability (must be string or number, not null)
  let sevTypeOk = true;
  if (Array.isArray(feed) && feed.length > 0) {
    const badSev = feed.slice(0, 50).filter(i => i.severity !== undefined && i.severity === null);
    sevTypeOk = badSev.length === 0;
  }
  gate('A05', 'Severity field type stable (no null values)', 'WARNING',
    sevTypeOk, sevTypeOk ? 'OK' : 'null severity detected');

  // A06: No duplicate IDs in feed
  let dupOk = true;
  let dupDetail = 'OK';
  if (Array.isArray(feed) && feed.length > 0) {
    const ids = feed.map(i => i.id).filter(Boolean);
    const unique = new Set(ids);
    dupOk = unique.size === ids.length;
    if (!dupOk) dupDetail = `${ids.length - unique.size} duplicate IDs detected`;
  }
  gate('A06', 'No duplicate item IDs in feed', 'BLOCKER', dupOk, dupDetail);

  // A07: P32 cert chain OK
  const p32 = await _loadQualityReport(env, 'p32_certification_report');
  gate('A07', 'P32 certification chain intact', 'WARNING',
    p32 !== null && (p32.blocker_count ?? 1) === 0,
    p32 ? `tier=${p32.release_tier} blockers=${p32.blocker_count}` : 'P32 cert not found (non-fatal)');

  // A08: P31 cert chain OK
  const p31 = await _loadQualityReport(env, 'p31_certification_report');
  gate('A08', 'P31 certification chain intact', 'WARNING',
    p31 !== null && (p31.blocker_count ?? 1) === 0,
    p31 ? `tier=${p31.release_tier} blockers=${p31.blocker_count}` : 'P31 cert not found (non-fatal)');

  // A09: Feed freshness  -  at least one item with a timestamp-like field
  let freshOk = false;
  if (Array.isArray(feed) && feed.length > 0) {
    const tsFields = ['published', 'updated', 'timestamp', 'date'];
    freshOk = feed.slice(0, 10).some(i => tsFields.some(f => i[f]));
  }
  gate('A09', 'Feed has timestamped items (freshness verifiable)', 'WARNING',
    freshOk, freshOk ? 'Timestamp field found' : 'No timestamp fields detected');

  // A10: TTP field coverage >= 50% of items
  let ttpCoverage = 0;
  if (Array.isArray(feed) && feed.length > 0) {
    const sample = feed.slice(0, 100);
    const withTtps = sample.filter(i => Array.isArray(i.ttps) && i.ttps.length > 0);
    ttpCoverage = sample.length > 0 ? (withTtps.length / sample.length) * 100 : 0;
  }
  gate('A10', 'TTP field coverage >= 50% of feed items', 'WARNING',
    ttpCoverage >= 50,
    `ttp_coverage=${ttpCoverage.toFixed(1)}%`);

  // A11: IOC field coverage >= 30% of items
  let iocCoverage = 0;
  if (Array.isArray(feed) && feed.length > 0) {
    const sample = feed.slice(0, 100);
    const withIocs = sample.filter(i => {
      const iocs = i.iocs || i.indicators;
      return Array.isArray(iocs) && iocs.length > 0;
    });
    iocCoverage = sample.length > 0 ? (withIocs.length / sample.length) * 100 : 0;
  }
  gate('A11', 'IOC field coverage >= 30% of feed items', 'WARNING',
    iocCoverage >= 30,
    `ioc_coverage=${iocCoverage.toFixed(1)}%`);

  // A12: Feed has CRITICAL or HIGH severity items (SOC actionability)
  let hasCritical = false;
  if (Array.isArray(feed) && feed.length > 0) {
    hasCritical = feed.some(i => {
      const s = String(i.severity ?? '').toUpperCase();
      return s === 'CRITICAL' || s === 'HIGH' || Number(i.severity) >= 8;
    });
  }
  gate('A12', 'Feed contains CRITICAL or HIGH severity items', 'WARNING',
    hasCritical, hasCritical ? 'CRITICAL/HIGH items present' : 'No high-severity items detected');

  // A13: P26 cert (composite grade) present
  const p26 = await _loadQualityReport(env, 'p26_certification_report');
  gate('A13', 'P26 composite grade certification present', 'WARNING',
    p26 !== null,
    p26 ? `tier=${p26.release_tier}` : 'P26 cert not found');

  // A14: P25 enterprise trust gate cert present
  const p25 = await _loadQualityReport(env, 'p25_enterprise_trust_gate');
  gate('A14', 'P25 enterprise trust gate certification present', 'WARNING',
    p25 !== null,
    p25 ? `tier=${p25.release_tier}` : 'P25 cert not found');

  // A15: Feed item count >= 10 (minimum viable intelligence corpus)
  const feedCount = Array.isArray(feed) ? feed.length : 0;
  gate('A15', 'Feed item count >= 10 (minimum viable corpus)', 'BLOCKER',
    feedCount >= 10,
    `item_count=${feedCount}`);

  // A16: Actor/threat actor field coverage (campaign intelligence)
  let actorCoverage = 0;
  if (Array.isArray(feed) && feed.length > 0) {
    const sample = feed.slice(0, 100);
    const withActor = sample.filter(i => i.actor || i.threat_actor || i.actor_tag);
    actorCoverage = sample.length > 0 ? (withActor.length / sample.length) * 100 : 0;
  }
  gate('A16', 'Actor field coverage >= 20% of feed items', 'WARNING',
    actorCoverage >= 20,
    `actor_coverage=${actorCoverage.toFixed(1)}%`);

  // A17: Feed items have CVE or KEV references (evidence-based intelligence)
  let cveCoverage = 0;
  if (Array.isArray(feed) && feed.length > 0) {
    const sample = feed.slice(0, 100);
    const withCve = sample.filter(i => {
      const cve = i.cve || i.cve_id || i.cves;
      return cve && (typeof cve === 'string' ? cve.startsWith('CVE-') : Array.isArray(cve) && cve.length > 0);
    });
    cveCoverage = sample.length > 0 ? (withCve.length / sample.length) * 100 : 0;
  }
  gate('A17', 'CVE-referenced items >= 10% of feed (evidence-based)', 'WARNING',
    cveCoverage >= 10,
    `cve_coverage=${cveCoverage.toFixed(1)}%`);

  // A18: MITRE ATT&CK TTP format validity (T#### pattern)
  let mitreValid = true;
  let mitreDetail = 'OK';
  if (Array.isArray(feed) && feed.length > 0) {
    const mitreRe = /^T\d{4}(\.\d{3})?$/;
    const badTtps = [];
    for (const item of feed.slice(0, 50)) {
      for (const t of (item.ttps || [])) {
        if (typeof t === 'string' && t.startsWith('T') && !mitreRe.test(t)) {
          badTtps.push(t);
        }
      }
    }
    mitreValid = badTtps.length === 0;
    if (!mitreValid) mitreDetail = `${badTtps.length} invalid TTP format(s): ${badTtps.slice(0, 3).join(', ')}`;
  }
  gate('A18', 'MITRE ATT&CK TTP format valid (T#### pattern)', 'WARNING', mitreValid, mitreDetail);

  // A19: No items with risk_score > 10 (score ceiling enforcement)
  let scoreCeilOk = true;
  if (Array.isArray(feed) && feed.length > 0) {
    const overCeil = feed.filter(i => Number(i.risk_score ?? 0) > 10);
    scoreCeilOk = overCeil.length === 0;
  }
  gate('A19', 'No items with risk_score > 10 (score ceiling)', 'BLOCKER',
    scoreCeilOk, scoreCeilOk ? 'All scores within ceiling' : 'Items with risk_score > 10 detected');

  // A20: P21 certification report present
  const p21 = await _loadQualityReport(env, 'p21_certification_report');
  gate('A20', 'P21 certification report present', 'WARNING',
    p21 !== null,
    p21 ? `items=${p21.total_items} avg=${p21.average_score}` : 'P21 cert not found');

  // A21: P22 contradiction report present
  const p22 = await _loadQualityReport(env, 'p22_contradiction_report');
  gate('A21', 'P22 contradiction detection report present', 'WARNING',
    p22 !== null,
    p22 ? `checked=${p22.items_checked} contradictions=${p22.total_contradictions}` : 'P22 report not found');

  // A22: P23 patch priority report present
  const p23 = await _loadQualityReport(env, 'p23_patch_priority_report');
  gate('A22', 'P23 patch priority report present', 'WARNING',
    p23 !== null,
    p23 ? `processed=${p23.items_processed} immediate=${p23.immediate_count}` : 'P23 report not found');

  // A23: No items with title length < 10 (quality floor)
  let titleOk = true;
  if (Array.isArray(feed) && feed.length > 0) {
    const badTitle = feed.slice(0, 100).filter(i => !i.title || String(i.title).length < 10);
    titleOk = badTitle.length === 0;
  }
  gate('A23', 'All items have title length >= 10 chars', 'WARNING',
    titleOk, titleOk ? 'OK' : 'Items with short/missing titles detected');

  // A24: Source field coverage >= 80%
  let sourceCoverage = 0;
  if (Array.isArray(feed) && feed.length > 0) {
    const sample = feed.slice(0, 100);
    const withSource = sample.filter(i => i.source || i.source_url || i.feed_source);
    sourceCoverage = sample.length > 0 ? (withSource.length / sample.length) * 100 : 0;
  }
  gate('A24', 'Source field coverage >= 80% of feed items', 'WARNING',
    sourceCoverage >= 80,
    `source_coverage=${sourceCoverage.toFixed(1)}%`);

  // A25: Confidence field present >= 50% of items
  let confCoverage = 0;
  if (Array.isArray(feed) && feed.length > 0) {
    const sample = feed.slice(0, 100);
    const withConf = sample.filter(i => i.confidence !== undefined && i.confidence !== null);
    confCoverage = sample.length > 0 ? (withConf.length / sample.length) * 100 : 0;
  }
  gate('A25', 'Confidence field coverage >= 50% of feed items', 'WARNING',
    confCoverage >= 50,
    `confidence_coverage=${confCoverage.toFixed(1)}%`);

  // A26: Platform observability  -  P33 observability metrics accessible
  gate('A26', 'P33 observability endpoint data accessible (cert chain)', 'WARNING',
    p33 !== null && p33.schema_version !== undefined,
    p33 ? `schema_version=${p33.schema_version}` : 'P33 cert unavailable');

  return { gates, passed, total: gates.length, blockers, warnings };
}

// --- template blocks ---------------------------------------------------------

export function buildP34AssuranceSummaryBlock(assurance) {
  const { passed, total, blockers, warnings } = assurance;
  const tier = blockers === 0 ? 'WORLDWIDE_RELEASE' : 'BLOCKED';
  const color = blockers === 0 ? '#22c55e' : '#ef4444';
  return `
<div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin:8px 0;">
  <div style="font-size:11px;color:#8b949e;letter-spacing:1px;margin-bottom:8px;">P34 ENGINEERING ASSURANCE</div>
  <div style="font-size:20px;font-weight:700;color:${color};">${tier}</div>
  <div style="font-size:12px;color:#8b949e;margin-top:4px;">${passed}/${total} gates passed * ${blockers} blockers * ${warnings} warnings</div>
</div>`;
}

export function buildP34SecurityPostureBlock(feed) {
  const count = Array.isArray(feed) ? feed.length : 0;
  const critical = Array.isArray(feed) ? feed.filter(i => String(i.severity ?? '').toUpperCase() === 'CRITICAL').length : 0;
  const high = Array.isArray(feed) ? feed.filter(i => String(i.severity ?? '').toUpperCase() === 'HIGH').length : 0;
  return `
<div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin:8px 0;">
  <div style="font-size:11px;color:#8b949e;letter-spacing:1px;margin-bottom:8px;">P34 SECURITY POSTURE</div>
  <div style="display:flex;gap:16px;flex-wrap:wrap;">
    <div><span style="font-size:18px;font-weight:700;color:#f97316;">${critical}</span><span style="font-size:11px;color:#8b949e;margin-left:4px;">CRITICAL</span></div>
    <div><span style="font-size:18px;font-weight:700;color:#eab308;">${high}</span><span style="font-size:11px;color:#8b949e;margin-left:4px;">HIGH</span></div>
    <div><span style="font-size:18px;font-weight:700;color:#3b82f6;">${count}</span><span style="font-size:11px;color:#8b949e;margin-left:4px;">TOTAL</span></div>
  </div>
</div>`;
}

export function buildP34ReliabilityBlock(gateResults) {
  const { passed, total, blockers } = gateResults;
  const pct = total > 0 ? Math.round((passed / total) * 100) : 0;
  const color = pct >= 90 ? '#22c55e' : pct >= 70 ? '#eab308' : '#ef4444';
  return `
<div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin:8px 0;">
  <div style="font-size:11px;color:#8b949e;letter-spacing:1px;margin-bottom:8px;">P34 PLATFORM RELIABILITY</div>
  <div style="font-size:28px;font-weight:700;color:${color};">${pct}%</div>
  <div style="font-size:12px;color:#8b949e;">Gate pass rate * ${blockers === 0 ? 'Production-stable' : `${blockers} blocker(s) present`}</div>
</div>`;
}

export function buildP34ObservabilityBlock(p33cert) {
  const tier = p33cert?.release_tier ?? 'UNKNOWN';
  const schema = p33cert?.schema_version ?? 'N/A';
  const color = tier === 'WORLDWIDE_RELEASE' ? '#22c55e' : '#f97316';
  return `
<div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin:8px 0;">
  <div style="font-size:11px;color:#8b949e;letter-spacing:1px;margin-bottom:8px;">P34 OBSERVABILITY CHAIN</div>
  <div style="font-size:16px;font-weight:700;color:${color};">${tier}</div>
  <div style="font-size:12px;color:#8b949e;margin-top:4px;">Cert chain: p33->p32->p31->p30->p29->p28->p25 * schema ${schema}</div>
</div>`;
}

export function buildP34ComplianceBlock(gateResults) {
  const gates = gateResults.gates ?? [];
  const passedGates = gates.filter(g => g.status === 'PASS').length;
  const pct = gates.length > 0 ? Math.round((passedGates / gates.length) * 100) : 0;
  return `
<div style="background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin:8px 0;">
  <div style="font-size:11px;color:#8b949e;letter-spacing:1px;margin-bottom:8px;">P34 COMPLIANCE POSTURE</div>
  <div style="font-size:24px;font-weight:700;color:${pct>=90?'#22c55e':pct>=70?'#eab308':'#ef4444'};">${pct}%</div>
  <div style="font-size:12px;color:#8b949e;">${passedGates}/${gates.length} assurance controls passing</div>
</div>`;
}

// --- route handlers -----------------------------------------------------------

export async function handleP34Assurance(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'engineering_assurance',
    release_tier: gates.blockers === 0 ? 'WORLDWIDE_RELEASE' : 'BLOCKED',
    ...gates,
  });
}

export async function handleP34Security(request, env) {
  const feed = await _loadFeed(env);
  const total = feed.length;
  const bySeverity = {};
  for (const item of feed) {
    const s = String(item.severity ?? 'UNKNOWN').toUpperCase();
    bySeverity[s] = (bySeverity[s] ?? 0) + 1;
  }
  const critical = bySeverity['CRITICAL'] ?? 0;
  const high = bySeverity['HIGH'] ?? 0;
  const medium = bySeverity['MEDIUM'] ?? 0;
  const low = bySeverity['LOW'] ?? 0;

  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'security_posture',
    feed_item_count: total,
    severity_distribution: bySeverity,
    critical_count: critical,
    high_count: high,
    medium_count: medium,
    low_count: low,
    critical_high_ratio: total > 0 ? ((critical + high) / total).toFixed(3) : '0.000',
    posture: critical > 0 ? 'ACTIVE_CRITICAL' : high > 0 ? 'ELEVATED' : 'NOMINAL',
  });
}

export async function handleP34Reliability(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  const pct = gates.total > 0 ? (gates.passed / gates.total) * 100 : 0;
  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'reliability',
    gate_pass_rate_pct: parseFloat(pct.toFixed(2)),
    passed: gates.passed,
    total: gates.total,
    blockers: gates.blockers,
    warnings: gates.warnings,
    sla_status: gates.blockers === 0 ? 'SLA_COMPLIANT' : 'SLA_AT_RISK',
    reliability_tier: pct >= 90 ? 'HIGH' : pct >= 70 ? 'MEDIUM' : 'LOW',
  });
}

export async function handleP34Performance(request, env) {
  const feed = await _loadFeed(env);
  const start = Date.now();
  // Measure KV round-trip latency
  await env.THREAT_INTEL_KV.get('feed:latest');
  const kvLatencyMs = Date.now() - start;

  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'performance',
    feed_item_count: Array.isArray(feed) ? feed.length : 0,
    kv_latency_ms: kvLatencyMs,
    performance_tier: kvLatencyMs < 50 ? 'EXCELLENT' : kvLatencyMs < 200 ? 'GOOD' : 'DEGRADED',
    worker_region: typeof navigator !== 'undefined' ? (navigator.userAgent ?? 'cloudflare-worker') : 'cloudflare-worker',
  });
}

export async function handleP34Compliance(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  const compliance_controls = gates.gates.map(g => ({
    control_id: g.id,
    control_name: g.label,
    severity: g.severity,
    status: g.status,
    detail: g.detail,
  }));
  const pct = gates.total > 0 ? (gates.passed / gates.total) * 100 : 0;
  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'compliance',
    overall_compliance_pct: parseFloat(pct.toFixed(2)),
    passed_controls: gates.passed,
    total_controls: gates.total,
    blocker_count: gates.blockers,
    warning_count: gates.warnings,
    compliance_tier: pct >= 90 ? 'ENTERPRISE_READY' : pct >= 70 ? 'CONDITIONAL' : 'NON_COMPLIANT',
    controls: compliance_controls,
  });
}

export async function handleP34Sbom(request, env) {
  // Surfaces SBOM metadata from KV if present, otherwise returns structural declaration
  const sbomData = await _loadQualityReport(env, 'sbom_summary');
  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'sbom',
    sbom_format: 'SPDX-2.3 / CycloneDX-1.4',
    sbom_status: sbomData ? 'PRESENT' : 'PENDING_GENERATION',
    sbom_data: sbomData ?? null,
    note: 'Full SBOM generated by scripts/enterprise_sbom_generator.py. Run via CI STAGE 3.99.',
  });
}

export async function handleP34Contracts(request, env) {
  const driftReport = await _loadQualityReport(env, 'contract_drift_report');
  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'api_contracts',
    contract_drift_status: driftReport ? (driftReport.breaking_changes === 0 ? 'STABLE' : 'DRIFT_DETECTED') : 'UNCHECKED',
    drift_report: driftReport ?? null,
    note: 'Full contract drift analysis via scripts/api_contract_drift_detector.py.',
  });
}

export async function handleP34Status(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  const feed = await _loadFeed(env);
  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'platform_status',
    overall_status: gates.blockers === 0 ? 'OPERATIONAL' : 'DEGRADED',
    release_tier: gates.blockers === 0 ? 'WORLDWIDE_RELEASE' : 'BLOCKED',
    assurance_gates: { passed: gates.passed, total: gates.total, blockers: gates.blockers, warnings: gates.warnings },
    feed_item_count: Array.isArray(feed) ? feed.length : 0,
    p_layer: 'P34',
    platform: 'CYBERDUDEBIVASH(R) SENTINEL APEX',
  });
}

export async function handleP34Metrics(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  const feed = await _loadFeed(env);
  const feedCount = Array.isArray(feed) ? feed.length : 0;
  const passRate = gates.total > 0 ? parseFloat(((gates.passed / gates.total) * 100).toFixed(2)) : 0;

  // Derive field coverage metrics from feed sample
  const sample = Array.isArray(feed) ? feed.slice(0, 100) : [];
  const sLen = sample.length || 1;
  const ttpCoverage = (sample.filter(i => Array.isArray(i.ttps) && i.ttps.length > 0).length / sLen * 100).toFixed(1);
  const iocCoverage = (sample.filter(i => { const iocs = i.iocs || i.indicators; return Array.isArray(iocs) && iocs.length > 0; }).length / sLen * 100).toFixed(1);
  const sourceCoverage = (sample.filter(i => i.source || i.source_url).length / sLen * 100).toFixed(1);

  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'platform_metrics',
    feed_item_count: feedCount,
    assurance_gate_pass_rate_pct: passRate,
    blocker_count: gates.blockers,
    warning_count: gates.warnings,
    ttp_field_coverage_pct: parseFloat(ttpCoverage),
    ioc_field_coverage_pct: parseFloat(iocCoverage),
    source_field_coverage_pct: parseFloat(sourceCoverage),
    platform_health_score: Math.round(passRate * 0.5 + parseFloat(ttpCoverage) * 0.2 + parseFloat(iocCoverage) * 0.1 + parseFloat(sourceCoverage) * 0.2),
  });
}

export async function handleP34Dashboard(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  const feed = await _loadFeed(env);
  const feedCount = Array.isArray(feed) ? feed.length : 0;
  const bySeverity = {};
  for (const item of (Array.isArray(feed) ? feed : [])) {
    const s = String(item.severity ?? 'UNKNOWN').toUpperCase();
    bySeverity[s] = (bySeverity[s] ?? 0) + 1;
  }
  const passRate = gates.total > 0 ? parseFloat(((gates.passed / gates.total) * 100).toFixed(2)) : 0;

  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'engineering_assurance_dashboard',
    platform: 'CYBERDUDEBIVASH(R) SENTINEL APEX',
    release_tier: gates.blockers === 0 ? 'WORLDWIDE_RELEASE' : 'BLOCKED',
    platform_status: gates.blockers === 0 ? 'OPERATIONAL' : 'DEGRADED',
    assurance: {
      passed: gates.passed,
      total: gates.total,
      blockers: gates.blockers,
      warnings: gates.warnings,
      pass_rate_pct: passRate,
      gates: gates.gates,
    },
    feed_health: {
      item_count: feedCount,
      severity_distribution: bySeverity,
      critical: bySeverity['CRITICAL'] ?? 0,
      high: bySeverity['HIGH'] ?? 0,
    },
    certification_chain: {
      p34: gates.blockers === 0 ? 'PASS' : 'FAIL',
    },
  });
}

export async function handleP34Certification(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  const feed = await _loadFeed(env);
  const tier = gates.blockers === 0 ? 'WORLDWIDE_RELEASE' : 'BLOCKED';

  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'p34_certification',
    release_tier: tier,
    passed_count: gates.passed,
    total_gates: gates.total,
    blocker_count: gates.blockers,
    warning_count: gates.warnings,
    feed_item_count: Array.isArray(feed) ? feed.length : 0,
    gates: gates.gates,
    certification_note: 'P34 Engineering Assurance  -  runtime certification via live KV data.',
  });
}

export async function handleP34Observability(request, env) {
  const gates = await _evaluateAssuranceGates(env);
  const feed = await _loadFeed(env);
  const p33 = await _loadP33Cert(env);
  const passRate = gates.total > 0 ? parseFloat(((gates.passed / gates.total) * 100).toFixed(2)) : 0;

  return _json({
    schema_version: 'p34.0',
    timestamp: _ts(),
    layer: 'P34',
    capability: 'observability',
    platform: 'CYBERDUDEBIVASH(R) SENTINEL APEX',
    p_layer_version: 'P34.0',
    release_tier: gates.blockers === 0 ? 'WORLDWIDE_RELEASE' : 'BLOCKED',
    metrics: {
      feed_item_count: Array.isArray(feed) ? feed.length : 0,
      assurance_pass_rate_pct: passRate,
      blocker_count: gates.blockers,
      warning_count: gates.warnings,
      passed_gates: gates.passed,
      total_gates: gates.total,
      p33_cert_tier: p33?.release_tier ?? 'UNKNOWN',
    },
    health: gates.blockers === 0 ? 'GREEN' : 'RED',
  });
}
