/**
 * Confidence Validation Engine — SENTINEL APEX Feed Quality Engine
 * Version: 1.0.0 | Build: 2026-06-05
 *
 * PURPOSE: Prevent confidence score inflation, enforce evidence-based scoring,
 * and ensure ioc_threat_level accurately reflects cleaned IOC quality.
 *
 * EVIDENCE TRIGGERING THIS MODULE:
 *   - Items with avg confidence 31.4, yet ioc_confidence reaching 89-100
 *   - ioc_threat_level = CRITICAL on 30/44 items including LOW-confidence CVE stubs
 *   - Confidence assigned independently of MITRE coverage, CVSS, or real IOC presence
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. SCORING THRESHOLDS
// ---------------------------------------------------------------------------

const CONFIDENCE_THRESHOLDS = {
  HIGH:   { min: 70, max: 100, label: 'HIGH' },
  MEDIUM: { min: 40, max: 69,  label: 'MEDIUM' },
  LOW:    { min: 15, max: 39,  label: 'LOW' },
  NONE:   { min: 0,  max: 14,  label: 'NONE' },
};

const IOC_THREAT_LEVEL_THRESHOLDS = {
  CRITICAL: 75,
  HIGH:     55,
  MEDIUM:   35,
  LOW:      15,
  NONE:     0,
};

// Weight matrix: how much each evidence factor contributes to composite confidence
const EVIDENCE_WEIGHTS = {
  source_trust_score:  0.20,  // max 20 pts (0.0–1.0 source trust × 20)
  mitre_coverage:      0.25,  // max 25 pts: >3 tactics = 25, 2 = 18, 1 = 10, 0 = 0
  real_ioc_count:      0.20,  // max 20 pts: >10 clean IOCs=20, 5-10=14, 1-4=8, 0=0
  cvss_score:          0.15,  // max 15 pts: CVSS 9-10=15, 7-8=11, 5-6=7, <5=3, missing=0
  epss_score:          0.10,  // max 10 pts: EPSS >0.7=10, 0.3-0.7=6, <0.3=2, missing=0
  kev_present:         0.10,  // max 10 pts: 10 if KEV, 0 if not
};

// ---------------------------------------------------------------------------
// 2. EVIDENCE SCORING
// ---------------------------------------------------------------------------

function scoreSourceTrust(item) {
  const t = parseFloat(item.source_trust_score);
  if (isNaN(t)) return 0;
  return Math.round(Math.min(1, Math.max(0, t)) * 20);
}

function scoreMitreCoverage(item) {
  const tactics = (item.mitre_tactics || []).length;
  const ttps    = (item.ttps || []).length;
  const total   = tactics + ttps;
  if (total >= 5) return 25;
  if (total >= 3) return 18;
  if (total >= 1) return 10;
  return 0;
}

function scoreRealIOCCount(item) {
  // Use cleaned ioc_count if integrity validation ran; else raw
  const count = typeof item.ioc_count_clean === 'number'
    ? item.ioc_count_clean
    : (item.ioc_count || 0);
  if (count >= 10) return 20;
  if (count >= 5)  return 14;
  if (count >= 1)  return 8;
  return 0;
}

function scoreCVSS(item) {
  const cvss = parseFloat(item.cvss_score);
  if (isNaN(cvss)) return 0;
  if (cvss >= 9.0) return 15;
  if (cvss >= 7.0) return 11;
  if (cvss >= 5.0) return 7;
  return 3;
}

function scoreEPSS(item) {
  const epss = parseFloat(item.epss_score);
  if (isNaN(epss)) return 0;
  if (epss >= 0.7) return 10;
  if (epss >= 0.3) return 6;
  return 2;
}

function scoreKEV(item) {
  return item.kev_present === true ? 10 : 0;
}

/**
 * computeEvidenceConfidence
 * Returns integer 0-100 based on actual evidence fields.
 */
function computeEvidenceConfidence(item) {
  return (
    scoreSourceTrust(item) +
    scoreMitreCoverage(item) +
    scoreRealIOCCount(item) +
    scoreCVSS(item) +
    scoreEPSS(item) +
    scoreKEV(item)
  );
}

// ---------------------------------------------------------------------------
// 3. THREAT LEVEL ASSIGNMENT
// ---------------------------------------------------------------------------

/**
 * computeIOCThreatLevel
 * Derives from evidence-based confidence, NOT from inflated ioc_confidence field.
 */
function computeIOCThreatLevel(evidenceScore) {
  if (evidenceScore >= IOC_THREAT_LEVEL_THRESHOLDS.CRITICAL) return 'CRITICAL';
  if (evidenceScore >= IOC_THREAT_LEVEL_THRESHOLDS.HIGH)     return 'HIGH';
  if (evidenceScore >= IOC_THREAT_LEVEL_THRESHOLDS.MEDIUM)   return 'MEDIUM';
  if (evidenceScore >= IOC_THREAT_LEVEL_THRESHOLDS.LOW)      return 'LOW';
  return 'NONE';
}

function computeConfidenceLabel(score) {
  for (const [, band] of Object.entries(CONFIDENCE_THRESHOLDS)) {
    if (score >= band.min && score <= band.max) return band.label;
  }
  return 'NONE';
}

// ---------------------------------------------------------------------------
// 4. ITEM VALIDATOR
// ---------------------------------------------------------------------------

/**
 * validateItemConfidence
 * Detects inflation, recomputes from evidence, returns corrected item + audit.
 */
function validateItemConfidence(item) {
  const claimed_confidence   = parseFloat(item.confidence_score) || 0;
  const claimed_ioc_conf     = parseFloat(item.ioc_confidence)   || 0;
  const claimed_threat_level = item.ioc_threat_level || 'NONE';

  const evidence_score  = computeEvidenceConfidence(item);
  const correct_level   = computeIOCThreatLevel(evidence_score);
  const correct_label   = computeConfidenceLabel(evidence_score);

  // Inflation flags
  const confidence_inflated =
    claimed_ioc_conf > evidence_score + 25 ||
    (claimed_ioc_conf >= 89 && evidence_score < 40);

  const level_inflated =
    claimed_threat_level === 'CRITICAL' && evidence_score < IOC_THREAT_LEVEL_THRESHOLDS.CRITICAL;

  const audit = {
    item_id: item.id || item.stix_id || 'UNKNOWN',
    claimed_confidence_score: claimed_confidence,
    claimed_ioc_confidence: claimed_ioc_conf,
    claimed_threat_level,
    evidence_score,
    correct_threat_level: correct_level,
    correct_confidence_label: correct_label,
    confidence_inflated,
    level_inflated,
    inflation_delta: Math.round(claimed_ioc_conf - evidence_score),
    evidence_breakdown: {
      source_trust:    scoreSourceTrust(item),
      mitre_coverage:  scoreMitreCoverage(item),
      real_ioc_count:  scoreRealIOCCount(item),
      cvss:            scoreCVSS(item),
      epss:            scoreEPSS(item),
      kev:             scoreKEV(item),
    },
  };

  // Build corrected item — only overwrite inflated fields
  const correctedItem = Object.assign({}, item, {
    ioc_confidence: evidence_score,
    ioc_threat_level: correct_level,
    confidence_label: correct_label,
    confidence_validated: true,
    confidence_validated_at: new Date().toISOString(),
    confidence_engine_version: '1.0.0',
  });

  // Preserve original for audit trail
  if (confidence_inflated || level_inflated) {
    correctedItem._original_ioc_confidence   = claimed_ioc_conf;
    correctedItem._original_ioc_threat_level = claimed_threat_level;
  }

  return { correctedItem, audit };
}

// ---------------------------------------------------------------------------
// 5. FEED-LEVEL RUNNER
// ---------------------------------------------------------------------------

function runConfidenceValidation(feed) {
  if (!Array.isArray(feed)) throw new Error('feed must be an array');

  const correctedFeed = [];
  const audits = [];
  let inflated_confidence_count = 0;
  let inflated_level_count = 0;
  let total_delta = 0;

  for (const item of feed) {
    const { correctedItem, audit } = validateItemConfidence(item);
    correctedFeed.push(correctedItem);
    audits.push(audit);
    if (audit.confidence_inflated) inflated_confidence_count++;
    if (audit.level_inflated) inflated_level_count++;
    if (audit.inflation_delta > 0) total_delta += audit.inflation_delta;
  }

  const avg_delta = feed.length > 0 ? (total_delta / feed.length).toFixed(1) : 0;

  // Distribution of corrected threat levels
  const levelDist = {};
  for (const item of correctedFeed) {
    levelDist[item.ioc_threat_level] = (levelDist[item.ioc_threat_level] || 0) + 1;
  }

  const report = {
    validation_id: `CONF-VAL-${Date.now()}`,
    generated_at: new Date().toISOString(),
    engine_version: '1.0.0',
    feed_item_count: feed.length,
    items_with_inflated_confidence: inflated_confidence_count,
    items_with_inflated_threat_level: inflated_level_count,
    average_inflation_delta: avg_delta,
    corrected_threat_level_distribution: levelDist,
    severity: inflated_level_count > feed.length * 0.5 ? 'CRITICAL' :
              inflated_level_count > 0 ? 'HIGH' : 'CLEAN',
    item_audits: audits,
    findings: _buildFindings(audits, levelDist, inflated_confidence_count, inflated_level_count, feed.length),
  };

  return { correctedFeed, report };
}

function _buildFindings(audits, levelDist, infConf, infLevel, total) {
  const f = [];
  if (infLevel / total > 0.5) {
    f.push(`CRITICAL: ${infLevel}/${total} items have inflated ioc_threat_level (CRITICAL assigned without CVSS, MITRE, or clean IOC evidence).`);
  }
  if (infConf / total > 0.3) {
    f.push(`HIGH: ${infConf}/${total} items have ioc_confidence >25 points above evidence-based score.`);
  }
  if (levelDist['CRITICAL']) {
    f.push(`After correction, CRITICAL items reduced to ${levelDist['CRITICAL']} (was inflated to 30+).`);
  }
  f.push('Recommendation: derive ioc_threat_level from evidence_score at publish time, not from heuristic field assignment.');
  return f;
}

// ---------------------------------------------------------------------------
// 6. EXPORTS
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    computeEvidenceConfidence,
    computeIOCThreatLevel,
    validateItemConfidence,
    runConfidenceValidation,
    CONFIDENCE_THRESHOLDS,
    EVIDENCE_WEIGHTS,
  };
}
