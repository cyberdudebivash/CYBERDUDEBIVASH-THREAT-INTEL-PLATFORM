/**
 * Actor Attribution Validator — SENTINEL APEX Feed Quality Engine
 * Version: 1.0.0 | Build: 2026-06-05
 *
 * PURPOSE: Validate actor attribution for correctness, evidence adequacy,
 * and attribution inflation. Prevent over-attribution to named APT/FIN groups
 * when evidence is insufficient.
 *
 * EVIDENCE TRIGGERING THIS MODULE:
 *   - 35/44 items tagged CDB-UNATTR-CVE (correct for CVE items)
 *   - 3 items tagged CDB-APT-22, CDB-FIN-07, CDB-FIN-09 — no MITRE techniques mapped
 *   - CVE items have actor attribution with confidence 15-30 — below attribution threshold
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. ACTOR TAG TAXONOMY
// ---------------------------------------------------------------------------

// Minimum confidence score to maintain a named attribution
const MIN_ATTRIBUTION_CONFIDENCE = 40;

// Actor families and their expected characteristics
const ACTOR_FAMILIES = {
  'CDB-APT':   { type: 'nation-state', requires_mitre: true, min_confidence: 50 },
  'CDB-FIN':   { type: 'financially-motivated', requires_mitre: true, min_confidence: 45 },
  'CDB-RAN':   { type: 'ransomware', requires_mitre: true, min_confidence: 40 },
  'CDB-HAC':   { type: 'hacktivist', requires_mitre: false, min_confidence: 30 },
  'CDB-CRI':   { type: 'criminal', requires_mitre: false, min_confidence: 30 },
  'CDB-CYB':   { type: 'cybercrime', requires_mitre: false, min_confidence: 30 },
  'CDB-UNATTR': { type: 'unattributed', requires_mitre: false, min_confidence: 0 },
};

// Unattributed tag patterns
const UNATTR_PATTERN = /^CDB-UNATTR-/;

// Valid actor tag format: CDB-FAMILY-NNN
const ACTOR_TAG_RE = /^CDB-[A-Z]+-\d{2,3}$/;
// Unattributed tag: CDB-UNATTR-XXX
const UNATTR_TAG_RE = /^CDB-UNATTR-[A-Z]+$/;

// Attribution evidence requirements
const ATTRIBUTION_EVIDENCE_FIELDS = [
  'mitre_tactics','ttps','kill_chain_phases',
  'campaign_id','iocs',
];

// ---------------------------------------------------------------------------
// 2. VALIDATION FUNCTIONS
// ---------------------------------------------------------------------------

function parseActorTag(tag) {
  if (!tag || typeof tag !== 'string') return { valid: false, reason: 'null or non-string tag' };
  if (UNATTR_TAG_RE.test(tag)) return { valid: true, type: 'unattributed', family: 'CDB-UNATTR' };
  if (!ACTOR_TAG_RE.test(tag)) return { valid: false, reason: `tag does not match CDB-FAMILY-NNN format: "${tag}"` };

  const parts = tag.split('-');
  const family = parts.slice(0, 2).join('-');
  return {
    valid: true,
    type: 'attributed',
    family,
    actor_config: ACTOR_FAMILIES[family] || null,
  };
}

function assessAttributionEvidence(item) {
  const evidence = {
    has_mitre_tactics:   (item.mitre_tactics || []).length > 0,
    has_ttps:            (item.ttps || []).length > 0,
    has_kill_chain:      (item.kill_chain_phases || []).length > 0,
    has_campaign_id:     item.campaign_id && item.campaign_id !== 'UNCLASSIFIED',
    has_clean_iocs:      (item.ioc_count || 0) > 0,
    confidence_score:    parseFloat(item.confidence_score) || 0,
    evidence_count:      0,
  };

  evidence.evidence_count =
    (evidence.has_mitre_tactics ? 1 : 0) +
    (evidence.has_ttps ? 1 : 0) +
    (evidence.has_kill_chain ? 1 : 0) +
    (evidence.has_campaign_id ? 1 : 0) +
    (evidence.has_clean_iocs ? 1 : 0);

  return evidence;
}

// ---------------------------------------------------------------------------
// 3. ITEM-LEVEL VALIDATOR
// ---------------------------------------------------------------------------

function validateItemAttribution(item) {
  const tagResult = parseActorTag(item.actor_tag);
  const evidence  = assessAttributionEvidence(item);
  const flags     = [];

  let corrected_actor_tag = item.actor_tag;
  let attribution_degraded = false;

  if (!tagResult.valid) {
    flags.push({
      severity: 'HIGH',
      code: 'INVALID_ACTOR_TAG_FORMAT',
      message: `Actor tag format violation: ${tagResult.reason}`,
    });
    corrected_actor_tag = _deriveUnattributedTag(item.threat_type);
    attribution_degraded = true;
  } else if (tagResult.type === 'attributed') {
    const config = tagResult.actor_config;

    // Check minimum confidence
    if (evidence.confidence_score < MIN_ATTRIBUTION_CONFIDENCE) {
      flags.push({
        severity: 'HIGH',
        code: 'ATTRIBUTION_CONFIDENCE_INSUFFICIENT',
        message: `Named actor "${item.actor_tag}" requires confidence ≥${MIN_ATTRIBUTION_CONFIDENCE}, found ${evidence.confidence_score.toFixed(1)}`,
      });
      corrected_actor_tag = _deriveUnattributedTag(item.threat_type);
      attribution_degraded = true;
    }

    // Check MITRE requirement
    if (config && config.requires_mitre && !evidence.has_mitre_tactics && !evidence.has_ttps) {
      flags.push({
        severity: 'HIGH',
        code: 'ATTRIBUTION_MISSING_MITRE',
        message: `Actor family ${tagResult.family} requires MITRE evidence; none found for "${item.actor_tag}"`,
      });
      if (!attribution_degraded) {
        corrected_actor_tag = _deriveUnattributedTag(item.threat_type);
        attribution_degraded = true;
      }
    }

    // Check evidence adequacy
    if (config && evidence.evidence_count < 2 && config.min_confidence > 30) {
      flags.push({
        severity: 'MEDIUM',
        code: 'ATTRIBUTION_INSUFFICIENT_EVIDENCE',
        message: `Actor "${item.actor_tag}" has only ${evidence.evidence_count}/5 evidence signals.`,
      });
    }
  }

  const audit = {
    item_id: item.id || item.stix_id || 'UNKNOWN',
    original_actor_tag: item.actor_tag,
    corrected_actor_tag,
    attribution_degraded,
    tag_valid: tagResult.valid,
    tag_type: tagResult.type || 'unknown',
    evidence,
    flags,
    attribution_confidence: evidence.confidence_score,
  };

  const correctedItem = Object.assign({}, item, {
    actor_tag: corrected_actor_tag,
    attribution_validated: true,
    attribution_validated_at: new Date().toISOString(),
    attribution_degraded,
    attribution_validator_version: '1.0.0',
  });

  if (attribution_degraded) {
    correctedItem._original_actor_tag = item.actor_tag;
  }

  return { correctedItem, audit };
}

function _deriveUnattributedTag(threatType) {
  const typeMap = {
    'Vulnerability': 'CDB-UNATTR-CVE',
    'Malware':       'CDB-UNATTR-MAL',
    'Phishing':      'CDB-UNATTR-PHI',
    'Ransomware':    'CDB-UNATTR-RAN',
    'Campaign':      'CDB-UNATTR-CAM',
    'APT':           'CDB-UNATTR-APT',
  };
  return typeMap[threatType] || 'CDB-UNATTR-UNK';
}

// ---------------------------------------------------------------------------
// 4. FEED-LEVEL RUNNER
// ---------------------------------------------------------------------------

function runActorAttributionValidation(feed) {
  if (!Array.isArray(feed)) throw new Error('feed must be an array');

  const correctedFeed = [];
  const audits = [];
  let degradedCount = 0;
  let flaggedCount = 0;

  const actorFreq = {};
  const correctedFreq = {};

  for (const item of feed) {
    const { correctedItem, audit } = validateItemAttribution(item);
    correctedFeed.push(correctedItem);
    audits.push(audit);
    if (audit.attribution_degraded) degradedCount++;
    if (audit.flags.length > 0) flaggedCount++;
    actorFreq[audit.original_actor_tag] = (actorFreq[audit.original_actor_tag] || 0) + 1;
    correctedFreq[audit.corrected_actor_tag] = (correctedFreq[audit.corrected_actor_tag] || 0) + 1;
  }

  const report = {
    validation_id: `ATTR-VAL-${Date.now()}`,
    generated_at: new Date().toISOString(),
    validator_version: '1.0.0',
    feed_item_count: feed.length,
    attributions_degraded: degradedCount,
    flagged_items: flaggedCount,
    original_actor_distribution: actorFreq,
    corrected_actor_distribution: correctedFreq,
    severity: degradedCount > 0 ? 'HIGH' : flaggedCount > 0 ? 'MEDIUM' : 'CLEAN',
    item_audits: audits,
    findings: _buildFindings(audits, degradedCount, feed.length),
  };

  return { correctedFeed, report };
}

function _buildFindings(audits, degradedCount, total) {
  const f = [];
  if (degradedCount > 0) {
    f.push(`${degradedCount}/${total} items had attributed actor tags downgraded to UNATTR due to insufficient evidence.`);
    f.push('Named actor attribution requires: confidence ≥40, MITRE tactics or techniques present, minimum 2 evidence signals.');
  }
  const lowConfAttr = audits.filter(a =>
    a.tag_type === 'attributed' && a.attribution_confidence < MIN_ATTRIBUTION_CONFIDENCE
  );
  if (lowConfAttr.length > 0) {
    f.push(`${lowConfAttr.length} items had named attribution with confidence below minimum threshold ${MIN_ATTRIBUTION_CONFIDENCE}.`);
  }
  return f;
}

// ---------------------------------------------------------------------------
// 5. EXPORTS
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    parseActorTag,
    assessAttributionEvidence,
    validateItemAttribution,
    runActorAttributionValidation,
    ACTOR_FAMILIES,
    MIN_ATTRIBUTION_CONFIDENCE,
  };
}
