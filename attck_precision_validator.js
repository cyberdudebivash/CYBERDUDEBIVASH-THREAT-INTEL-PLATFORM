/**
 * ATT&CK Precision Validator — SENTINEL APEX Feed Quality Engine
 * Version: 1.0.0 | Build: 2026-06-05
 *
 * PURPOSE: Validate that MITRE ATT&CK tactic/technique assignments are
 * legitimate, non-empty, and consistent with item threat_type and kill_chain.
 *
 * EVIDENCE TRIGGERING THIS MODULE:
 *   - 4/44 items have no mitre_tactics at all
 *   - CVE items attributed to APT/FIN groups with no supporting MITRE evidence
 *   - kill_chain_phases empty on items claiming multi-stage attribution
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. MITRE ATT&CK REFERENCE DATA (ICS Enterprise v14 — compact)
// ---------------------------------------------------------------------------

const VALID_TACTIC_IDS = new Set([
  'TA0001','TA0002','TA0003','TA0004','TA0005',
  'TA0006','TA0007','TA0008','TA0009','TA0010',
  'TA0011','TA0040','TA0042','TA0043',
]);

const VALID_TACTIC_NAMES = new Set([
  'initial-access','execution','persistence','privilege-escalation','defense-evasion',
  'credential-access','discovery','lateral-movement','collection','exfiltration',
  'command-and-control','impact','resource-development','reconnaissance',
  // Common aliases
  'initial access','privilege escalation','defense evasion','credential access',
  'lateral movement','command and control','resource development',
]);

// Technique pattern: Txxxx or Txxxx.xxx (sub-technique)
const TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/;

// Kill-chain phase names (STIX 2.1 + Lockheed Martin)
const VALID_KILL_CHAIN_PHASES = new Set([
  'reconnaissance','weaponization','delivery','exploitation',
  'installation','command-and-control','actions-on-objectives',
  'pre-attack','initial-access','execution','persistence',
  'privilege-escalation','defense-evasion','credential-access',
  'discovery','lateral-movement','collection','exfiltration','impact',
]);

// Threat types that reasonably have MITRE coverage
const THREAT_TYPES_REQUIRING_MITRE = new Set([
  'Ransomware','APT','Malware','Phishing','Campaign',
  'Exploit','Backdoor','Trojan','Infostealer','Cryptominer',
]);

// Threat types where empty MITRE is acceptable
const THREAT_TYPES_MITRE_OPTIONAL = new Set([
  'Vulnerability','CVE','Patch','Advisory',
]);

// ---------------------------------------------------------------------------
// 2. VALIDATION FUNCTIONS
// ---------------------------------------------------------------------------

function validateTacticEntry(entry) {
  if (!entry) return { valid: false, reason: 'null tactic' };
  const s = typeof entry === 'string' ? entry : (entry.id || entry.name || '');
  const lower = s.toLowerCase().trim();

  if (VALID_TACTIC_IDS.has(s.toUpperCase().trim())) return { valid: true, normalised: s.toUpperCase().trim() };
  if (VALID_TACTIC_NAMES.has(lower)) return { valid: true, normalised: lower };
  return { valid: false, reason: `unrecognised tactic: "${s}"` };
}

function validateTechniqueEntry(entry) {
  if (!entry) return { valid: false, reason: 'null technique' };
  const s = typeof entry === 'string' ? entry : (entry.id || entry.technique_id || '');
  if (TECHNIQUE_RE.test(s.trim())) return { valid: true, normalised: s.trim() };
  return { valid: false, reason: `invalid technique ID format: "${s}"` };
}

function validateKillChainPhase(phase) {
  if (!phase) return { valid: false, reason: 'null phase' };
  const s = typeof phase === 'string' ? phase : (phase.phase_name || phase.name || '');
  const lower = s.toLowerCase().replace(/\s+/g, '-');
  if (VALID_KILL_CHAIN_PHASES.has(lower)) return { valid: true, normalised: lower };
  return { valid: false, reason: `unrecognised kill-chain phase: "${s}"` };
}

// ---------------------------------------------------------------------------
// 3. ITEM-LEVEL VALIDATOR
// ---------------------------------------------------------------------------

function validateItemATTCK(item) {
  const audit = {
    item_id: item.id || item.stix_id || 'UNKNOWN',
    threat_type: item.threat_type || 'Unknown',
    original_mitre_tactics: item.mitre_tactics || [],
    original_ttps: item.ttps || [],
    original_kill_chain: item.kill_chain_phases || [],
    valid_tactics: [],
    invalid_tactics: [],
    valid_techniques: [],
    invalid_techniques: [],
    valid_kill_chain: [],
    invalid_kill_chain: [],
    flags: [],
  };

  // Validate tactics
  for (const t of (item.mitre_tactics || [])) {
    const r = validateTacticEntry(t);
    if (r.valid) audit.valid_tactics.push(r.normalised);
    else audit.invalid_tactics.push({ value: t, reason: r.reason });
  }

  // Validate TTPs (techniques)
  for (const t of (item.ttps || [])) {
    const r = validateTechniqueEntry(t);
    if (r.valid) audit.valid_techniques.push(r.normalised);
    else audit.invalid_techniques.push({ value: t, reason: r.reason });
  }

  // Validate kill chain phases
  for (const p of (item.kill_chain_phases || [])) {
    const r = validateKillChainPhase(p);
    if (r.valid) audit.valid_kill_chain.push(r.normalised);
    else audit.invalid_kill_chain.push({ value: p, reason: r.reason });
  }

  // Flag: missing MITRE on threat types that need it
  if (
    THREAT_TYPES_REQUIRING_MITRE.has(item.threat_type) &&
    audit.valid_tactics.length === 0 &&
    audit.valid_techniques.length === 0
  ) {
    audit.flags.push({
      severity: 'HIGH',
      code: 'MISSING_MITRE_COVERAGE',
      message: `Threat type "${item.threat_type}" should have MITRE ATT&CK coverage but has none.`,
    });
  }

  // Flag: actor attributed items with no MITRE techniques
  const hasActorAttribution = item.actor_tag &&
    !item.actor_tag.startsWith('CDB-UNATTR');
  if (hasActorAttribution && audit.valid_techniques.length === 0) {
    audit.flags.push({
      severity: 'MEDIUM',
      code: 'ACTOR_ATTRIBUTION_NO_TECHNIQUES',
      message: `Actor "${item.actor_tag}" attributed but no ATT&CK techniques mapped.`,
    });
  }

  // Flag: invalid tactic or technique IDs
  if (audit.invalid_tactics.length > 0) {
    audit.flags.push({
      severity: 'MEDIUM',
      code: 'INVALID_TACTIC_IDS',
      message: `${audit.invalid_tactics.length} invalid tactic ID(s): ${audit.invalid_tactics.map(x => x.value).join(', ')}`,
    });
  }

  audit.mitre_precision_score = _computePrecisionScore(audit);

  // Build corrected item — retain only validated values
  const correctedItem = Object.assign({}, item, {
    mitre_tactics: audit.valid_tactics,
    ttps: audit.valid_techniques,
    kill_chain_phases: audit.valid_kill_chain,
    attck_validated: true,
    attck_validated_at: new Date().toISOString(),
    attck_precision_score: audit.mitre_precision_score,
    attck_validator_version: '1.0.0',
  });

  return { correctedItem, audit };
}

function _computePrecisionScore(audit) {
  // 0–100: reward valid entries, penalise invalid and missing
  let score = 50; // baseline
  score += Math.min(25, audit.valid_tactics.length * 8);
  score += Math.min(15, audit.valid_techniques.length * 3);
  score += Math.min(10, audit.valid_kill_chain.length * 5);
  score -= audit.invalid_tactics.length * 10;
  score -= audit.invalid_techniques.length * 5;
  for (const f of audit.flags) {
    if (f.severity === 'HIGH')   score -= 20;
    if (f.severity === 'MEDIUM') score -= 8;
  }
  return Math.max(0, Math.min(100, score));
}

// ---------------------------------------------------------------------------
// 4. FEED-LEVEL RUNNER
// ---------------------------------------------------------------------------

function runATTCKPrecisionValidation(feed) {
  if (!Array.isArray(feed)) throw new Error('feed must be an array');

  const correctedFeed = [];
  const audits = [];
  let flaggedCount = 0;
  let avgPrecision = 0;

  for (const item of feed) {
    const { correctedItem, audit } = validateItemATTCK(item);
    correctedFeed.push(correctedItem);
    audits.push(audit);
    if (audit.flags.length > 0) flaggedCount++;
    avgPrecision += audit.mitre_precision_score;
  }

  avgPrecision = feed.length > 0 ? (avgPrecision / feed.length).toFixed(1) : 0;

  const report = {
    validation_id: `ATTCK-VAL-${Date.now()}`,
    generated_at: new Date().toISOString(),
    validator_version: '1.0.0',
    feed_item_count: feed.length,
    flagged_items: flaggedCount,
    average_precision_score: avgPrecision,
    severity: flaggedCount > feed.length * 0.5 ? 'HIGH' :
              flaggedCount > 0 ? 'MEDIUM' : 'CLEAN',
    item_audits: audits,
  };

  return { correctedFeed, report };
}

// ---------------------------------------------------------------------------
// 5. EXPORTS
// ---------------------------------------------------------------------------
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    validateTacticEntry,
    validateTechniqueEntry,
    validateItemATTCK,
    runATTCKPrecisionValidation,
    VALID_TACTIC_IDS,
    VALID_TACTIC_NAMES,
  };
}
