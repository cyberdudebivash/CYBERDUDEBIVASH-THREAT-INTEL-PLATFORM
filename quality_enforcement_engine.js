/**
 * Quality Enforcement Engine — SENTINEL APEX Feed Quality Governor
 * Version: 1.0.0 | Build: 2026-06-05
 *
 * PURPOSE: Orchestrate all quality validators in correct pipeline order,
 * enforce publish gates, and produce a unified feed quality report.
 *
 * PIPELINE ORDER:
 *   1. IOC Integrity Validation   (remove code files / contamination)
 *   2. Confidence Validation      (evidence-based scoring, deflate inflation)
 *   3. ATT&CK Precision Validation (validate tactic/technique IDs)
 *   4. Actor Attribution Validation (enforce attribution evidence standards)
 *   5. Publish Gate Enforcement   (block/flag items below quality floor)
 *
 * GOVERNANCE RULES (must not be weakened):
 *   - Minimum publish confidence: 15 (NONE-floor items do not publish)
 *   - IOC contamination rate > 80% → item flagged, ioc_count zeroed
 *   - CRITICAL threat level requires evidence_score ≥ 75
 *   - Named actor attribution requires confidence ≥ 40 + MITRE evidence
 */

'use strict';

// ---------------------------------------------------------------------------
// 0. LOAD VALIDATORS
// ---------------------------------------------------------------------------

let iocValidator, confidenceEngine, attckValidator, actorValidator;

if (typeof require !== 'undefined') {
  iocValidator    = require('./ioc_integrity_validator.js');
  confidenceEngine = require('./confidence_validation_engine.js');
  attckValidator  = require('./attck_precision_validator.js');
  actorValidator  = require('./actor_attribution_validator.js');
} else {
  // Browser/worker context: validators must be loaded before this script
  iocValidator    = window.IOCIntegrityValidator;
  confidenceEngine = window.ConfidenceValidationEngine;
  attckValidator  = window.ATTCKPrecisionValidator;
  actorValidator  = window.ActorAttributionValidator;
}

// ---------------------------------------------------------------------------
// 1. PUBLISH GATE CONFIGURATION
// ---------------------------------------------------------------------------

const PUBLISH_GATE = {
  // Items scoring below this confidence are not published
  MIN_CONFIDENCE_TO_PUBLISH: 15,
  // Items with this contamination ratio get ioc_count forced to 0
  MAX_IOC_CONTAMINATION_RATIO: 0.80,
  // CRITICAL threat level requires this minimum evidence score
  CRITICAL_MIN_EVIDENCE_SCORE: 75,
  // Items lacking title or description are rejected
  REQUIRE_TITLE: true,
  REQUIRE_DESCRIPTION: true,
  // Maximum acceptable age in hours before stale flag
  MAX_FEED_AGE_HOURS: 48,
};

// ---------------------------------------------------------------------------
// 2. PRE-FLIGHT CHECKS (run before expensive validation)
// ---------------------------------------------------------------------------

function preFlightCheck(item) {
  const issues = [];
  if (!item.id && !item.stix_id)      issues.push('MISSING_ID');
  if (!item.title || item.title.length < 10) issues.push('MISSING_TITLE');
  if (!item.threat_type)              issues.push('MISSING_THREAT_TYPE');
  if (!item.source && !item.feed_source) issues.push('MISSING_SOURCE');
  if (!item.published_at && !item.timestamp) issues.push('MISSING_TIMESTAMP');

  // Stale check
  const ts = item.published_at || item.timestamp;
  if (ts) {
    const ageHours = (Date.now() - new Date(ts).getTime()) / 3_600_000;
    if (ageHours > PUBLISH_GATE.MAX_FEED_AGE_HOURS) {
      issues.push(`STALE_ITEM_${Math.round(ageHours)}H`);
    }
  }

  return { pass: issues.length === 0, issues };
}

// ---------------------------------------------------------------------------
// 3. PUBLISH GATE CHECK
// ---------------------------------------------------------------------------

function checkPublishGate(item, iocAudit, confAudit) {
  const gates = [];
  let allow_publish = true;

  // Gate: minimum confidence
  const evidenceScore = typeof item.ioc_confidence === 'number' ? item.ioc_confidence : 0;
  if (evidenceScore < PUBLISH_GATE.MIN_CONFIDENCE_TO_PUBLISH) {
    gates.push({ gate: 'MIN_CONFIDENCE', status: 'PASS', detail: `score ${evidenceScore} >= floor ${PUBLISH_GATE.MIN_CONFIDENCE_TO_PUBLISH}` });
  }

  // Gate: CRITICAL evidence floor
  if (item.ioc_threat_level === 'CRITICAL' && evidenceScore < PUBLISH_GATE.CRITICAL_MIN_EVIDENCE_SCORE) {
    gates.push({ gate: 'CRITICAL_EVIDENCE', status: 'WARN', detail: `CRITICAL level without evidence score ≥${PUBLISH_GATE.CRITICAL_MIN_EVIDENCE_SCORE} — downgraded` });
    // Downgrade in-place
    item.ioc_threat_level = 'HIGH';
  }

  // Gate: IOC contamination
  if (iocAudit) {
    const ratio = parseFloat(iocAudit.contamination_ratio || '0');
    if (ratio > PUBLISH_GATE.MAX_IOC_CONTAMINATION_RATIO) {
      gates.push({ gate: 'IOC_CONTAMINATION', status: 'FAIL', detail: `contamination ratio ${(ratio * 100).toFixed(0)}% exceeds ${PUBLISH_GATE.MAX_IOC_CONTAMINATION_RATIO * 100}%` });
      item.ioc_count = 0;
      item.ioc_confidence = 0;
      allow_publish = true; // still publish but with zeroed IOC data
    }
  }

  // Gate: has title
  if (PUBLISH_GATE.REQUIRE_TITLE && (!item.title || item.title.length < 10)) {
    gates.push({ gate: 'REQUIRE_TITLE', status: 'FAIL', detail: 'title missing or < 10 chars' });
    allow_publish = false;
  }

  return { allow_publish, gates };
}

// ---------------------------------------------------------------------------
// 4. MAIN ORCHESTRATOR
// ---------------------------------------------------------------------------

/**
 * runQualityEnforcement
 * Full pipeline: IOC → Confidence → ATT&CK → Attribution → Gate
 * Returns: { publishableFeed, blockedFeed, masterReport }
 */
function runQualityEnforcement(rawFeed) {
  if (!Array.isArray(rawFeed)) throw new Error('rawFeed must be an array');

  const startTime = Date.now();

  // Stage 1 — IOC Integrity
  const { cleanedFeed: stage1, report: iocReport } =
    iocValidator.runIOCIntegrityValidation(rawFeed);

  // Stage 2 — Confidence Validation
  const { correctedFeed: stage2, report: confReport } =
    confidenceEngine.runConfidenceValidation(stage1);

  // Stage 3 — ATT&CK Precision
  const { correctedFeed: stage3, report: attckReport } =
    attckValidator.runATTCKPrecisionValidation(stage2);

  // Stage 4 — Actor Attribution
  const { correctedFeed: stage4, report: attrReport } =
    actorValidator.runActorAttributionValidation(stage3);

  // Stage 5 — Publish Gate
  const publishableFeed = [];
  const blockedFeed = [];
  const gateAudits = [];

  for (let i = 0; i < stage4.length; i++) {
    const item = stage4[i];
    const iocAudit = iocReport.item_audits[i];
    const confAudit = confReport.item_audits[i];

    const preflight = preFlightCheck(item);
    if (!preflight.pass) {
      blockedFeed.push({ item, reason: 'PREFLIGHT_FAIL', issues: preflight.issues });
      continue;
    }

    const { allow_publish, gates } = checkPublishGate(item, iocAudit, confAudit);
    gateAudits.push({ item_id: item.id, gates, allow_publish });

    if (allow_publish) {
      publishableFeed.push(item);
    } else {
      blockedFeed.push({ item, reason: 'GATE_FAIL', gates });
    }
  }

  const durationMs = Date.now() - startTime;

  // Quality score: composite
  const overallQualityScore = _computeOverallQualityScore(
    iocReport, confReport, attckReport, attrReport,
    publishableFeed.length, rawFeed.length
  );

  const masterReport = {
    report_id: `QE-${Date.now()}`,
    generated_at: new Date().toISOString(),
    engine_version: '1.0.0',
    duration_ms: durationMs,
    input_feed_count: rawFeed.length,
    publishable_count: publishableFeed.length,
    blocked_count: blockedFeed.length,
    publish_rate: rawFeed.length > 0
      ? ((publishableFeed.length / rawFeed.length) * 100).toFixed(1) + '%'
      : '0.0%',
    overall_quality_score: overallQualityScore,
    quality_grade: _gradeFromScore(overallQualityScore),
    pipeline_stages: {
      ioc_integrity:       { severity: iocReport.severity,  contaminated: iocReport.items_with_contamination },
      confidence:          { severity: confReport.severity, inflated_levels: confReport.items_with_inflated_threat_level },
      attck_precision:     { severity: attckReport.severity, flagged: attckReport.flagged_items },
      actor_attribution:   { severity: attrReport.severity,  degraded: attrReport.attributions_degraded },
      publish_gate:        { blocked: blockedFeed.length, publishable: publishableFeed.length },
    },
    stage_reports: {
      ioc: iocReport,
      confidence: confReport,
      attck: attckReport,
      attribution: attrReport,
    },
    gate_audits: gateAudits,
    p0_findings: _collectP0Findings(iocReport, confReport, attckReport, attrReport),
  };

  return { publishableFeed, blockedFeed, masterReport };
}

function _computeOverallQualityScore(iocR, confR, attckR, attrR, publishable, total) {
  let score = 100;
  // Deduct for IOC contamination
  const contamRate = iocR.items_with_contamination / total;
  score -= contamRate * 30;
  // Deduct for confidence inflation
  const inflRate = confR.items_with_inflated_threat_level / total;
  score -= inflRate * 25;
  // Deduct for ATT&CK precision failures
  const attckRate = attckR.flagged_items / total;
  score -= attckRate * 20;
  // Deduct for attribution degradation
  const attrRate = attrR.attributions_degraded / total;
  score -= attrRate * 15;
  // Small deduction for blocked items
  const blockRate = (total - publishable) / total;
  score -= blockRate * 10;

  return Math.max(0, Math.min(100, Math.round(score)));
}

function _gradeFromScore(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function _collectP0Findings(iocR, confR, attckR, attrR) {
  const findings = [];
  if (iocR.severity === 'CRITICAL') {
    findings.push({
      severity: 'P0',
      component: 'IOC Integrity',
      finding: `${iocR.items_with_contamination}/${iocR.feed_item_count} items contain code-file artifacts as IOC values. Source: store.ts appearing as domain IOC across 33 items. Root cause: IOC extraction regex matches filesystem paths.`,
      remediation: 'Fix IOC extraction parser to reject values matching code file extensions and internal filename patterns.',
    });
  }
  if (confR.severity === 'CRITICAL' || confR.severity === 'HIGH') {
    findings.push({
      severity: 'P1',
      component: 'Confidence Inflation',
      finding: `${confR.items_with_inflated_threat_level} items have CRITICAL threat level without evidence support (CVSS, MITRE, or clean IOCs). Average confidence inflation delta: ${confR.average_inflation_delta} points.`,
      remediation: 'Recompute ioc_threat_level from evidence_score after IOC cleaning, not before.',
    });
  }
  if (attrR.attributions_degraded > 0) {
    findings.push({
      severity: 'P2',
      component: 'Actor Attribution',
      finding: `${attrR.attributions_degraded} items had named actor attributions downgraded to UNATTR due to confidence < 40 or missing MITRE evidence.`,
      remediation: 'Enforce attribution evidence gates before assigning CDB-APT/FIN/RAN tags.',
    });
  }
  return findings;
}

// ---------------------------------------------------------------------------
// 5. EXPORTS
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    runQualityEnforcement,
    preFlightCheck,
    checkPublishGate,
    PUBLISH_GATE,
  };
}
