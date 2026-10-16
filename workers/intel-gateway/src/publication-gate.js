/**
 * workers/intel-gateway/src/publication-gate.js
 * CUSTOMER PUBLICATION AUTHORIZATION GATE  -  P0 incident remediation.
 *
 * INCIDENT: intel--ba996dad34540150b8ea1b5f was publicly served through
 * /reports/** despite P21=4/100 (BELOW_MINIMUM), P25=28% (BELOW THRESHOLD),
 * P26=29/100 (REJECTED), P23=4/10 (INCOMPLETE  -  DO NOT PUBLISH). Root cause,
 * traced (not guessed):
 *
 *   1. The /reports/** route (index.js) never consulted ANY certification
 *      result before serving. It resolves an item (via findItemBySlug or a
 *      direct R2 hit), generates/serves HTML, and caches it  -  the actual
 *      P20-P26 verdicts only ever appeared as DISPLAY content inside the
 *      generated report, never as a gate on whether to serve it at all.
 *   2. The one function that superficially resembles a "release gate"
 *      (p32-handlers.js:_computeReleaseGate, "P32.13") only treats 4 basic
 *      data-completeness checks as blockers (title/description/severity/
 *      CVSS-or-severity present)  -  genuine quality/trust-score failures are
 *      demoted to non-blocking warnings, so it reports PUBLICATION_APPROVED
 *      even when P21/P25/P26/P23 all reject the same item. It was also
 *      never wired into the serving decision anywhere  -  a display block,
 *      not a gate.
 *   3. Pipeline ordering (.github/workflows/sentinel-apex.yml): STAGE 3.2
 *      (report generation, scripts/report_generator.py) runs BEFORE STAGE
 *      3.93.15d/h/i (P21/P25/P26 certification)  -  confirmed by exact line
 *      numbers in that file. Reports can be generated before certification
 *      has even run.
 *
 * THIS MODULE is the single authoritative publication decision this
 * incident's remediation policy requires: DENY OVERRIDES ALLOW across every
 * existing certification engine, FAIL CLOSED on missing/erroring data, and
 * it reuses the canonical engine functions unchanged (computeP20QualityScore,
 * getP21CertificationLevel, the newly-extracted computeOperationalReadiness,
 * computeEnterpriseTrustScore, computeP26Grade) rather than re-implementing
 * any scoring logic. It does NOT consult P32's release gate at all  -  the
 * most permissive engine must never be allowed to win.
 *
 * SCOPE (documented, not silent): this closes the confirmed, actively
 * exploited path  -  the Worker's /reports/** synthesis + direct R2 serving.
 * It does NOT modify scripts/report_generator.py or
 * scripts/generate_intel_reports.py (the Python-side generators that also
 * write into the same reports/ R2 keyspace, per STAGE 3.6.5's own comment:
 * "no shared ownership model"). Reordering that 50+ stage production
 * pipeline safely requires its own dedicated, carefully-tested change  -  see
 * the incident report's Root Cause / Residual Risk sections.
 */

import { computeP20QualityScore, classifyReportType } from './p20-handlers.js';
import { getP21CertificationLevel } from './p21-handlers.js';
import { computeOperationalReadiness } from './p23-handlers.js';
import { computeEnterpriseTrustScore } from './p25-handlers.js';
import { computeP26Grade } from './p26-handlers.js';

export const PUBLICATION_GATE_VERSION = '1.1.0';

// Below this, P20 is "critically low" per P26's own existing C-P20 warning
// threshold (p26-handlers.js)  -  reused here as a blocking condition, not a
// new number invented for this gate.
const P20_CRITICAL_THRESHOLD = 25;

/**
 * Report-type-aware policy (P0 follow-through, Section 8-9). Two of
 * computeOperationalReadiness()'s 10 named gates ("IR Package", "Patch
 * Priority") are defined purely in terms of CVSS/KEV presence -- structurally
 * impossible for a report that was never about a scored vulnerability (a
 * phishing campaign, a threat-actor profile, a data-breach notice) to
 * satisfy. Counting that absence as a quality FAILURE conflates
 * "not applicable to this report type" with "missing required content."
 *
 * This does NOT touch computeOperationalReadiness() itself (no shared
 * P23 engine logic changes -- Section 26 forbids silently changing scoring),
 * does NOT lower the 50% threshold, and does NOT apply to VULNERABILITY-type
 * items (a CVE advisory with no CVSS/patch data is still genuinely
 * incomplete). It only changes the DENOMINATOR for non-vulnerability items
 * that carry zero CVE/CVSS/KEV signal at all, by excluding gates that could
 * never have passed for that report type -- the same items still need every
 * gate that legitimately applies (Evidence Chain, IOC packages, Detection,
 * P21 Certification, etc.) to reach 50%.
 */
const CVE_SPECIFIC_GATES = new Set(['IR Package', 'Patch Priority']);

// classifyReportType() now lives in p20-handlers.js (moved so
// computeP20QualityScore() can reuse it for its own type-aware IOC-quality
// scoring without a circular import -- p20-handlers.js has no imports of
// its own). Re-exported here unchanged for every existing consumer of this
// module (Section 5 backward compatibility) -- same name, same behavior.
export { classifyReportType };

/**
 * Re-derives P23's pct over only the gates that genuinely apply to this
 * report's type, using computeOperationalReadiness()'s own unmodified gate
 * results -- it filters, it never re-scores. VULNERABILITY items always use
 * the full, unfiltered gate set.
 */
function _typeAdjustedReadiness(p23, reportType) {
  if (reportType === 'VULNERABILITY') {
    return { pct: p23.pct, applicableGates: p23.gates.map(g => g.name), notApplicableGates: [], basis: 'full' };
  }

  const applicable = p23.gates.filter(g => !CVE_SPECIFIC_GATES.has(g.name));
  const notApplicable = p23.gates.filter(g => CVE_SPECIFIC_GATES.has(g.name)).map(g => g.name);
  const passed = applicable.filter(g => g.pass).length;
  const pct = applicable.length ? Math.round((passed / applicable.length) * 100) : p23.pct;

  return { pct, applicableGates: applicable.map(g => g.name), notApplicableGates: notApplicable, basis: 'type_adjusted' };
}

/**
 * Deterministic, synchronous content fingerprint over exactly the fields
 * this gate evaluates (Section 10/11's certification-contract "content_hash").
 * Deliberately NOT a cryptographic hash: evaluatePublicationGate() is called
 * from hot .filter() paths across the Worker (index building, exports) and
 * must stay synchronous -- crypto.subtle.digest is async and making this
 * function async would be a breaking change to every existing call site.
 * It is a stable fingerprint sufficient to detect "certified A, served B"
 * drift; it is not a tamper-proof signature.
 */
export function _contentFingerprint(item) {
  const canonical = JSON.stringify({
    id: item.id, title: item.title, description: item.description,
    severity: item.severity, cvss_score: item.cvss_score, cve_id: item.cve_id,
    evidence_chain: item.evidence_chain, iocs: item.iocs, ioc_count: item.ioc_count,
    ttps: item.ttps, mitre_techniques: item.mitre_techniques,
    detection_bundle: item.detection_bundle,
    executive_summary: item.executive_summary, exec_summary: item.exec_summary,
    source_url: item.source_url, kev_present: item.kev_present, epss_score: item.epss_score,
  });
  let hash = 5381;
  for (let i = 0; i < canonical.length; i++) hash = ((hash << 5) + hash + canonical.charCodeAt(i)) | 0;
  return 'fp_' + (hash >>> 0).toString(16);
}

/**
 * Evaluates the ONE authoritative publication decision for an intelligence
 * item. Fail-closed: any engine erroring, or any single engine rejecting,
 * blocks publication  -  deny overrides allow, unconditionally.
 *
 * Returns:
 *   publication_state:  'CUSTOMER_READY' | 'REJECTED' | 'BLOCKED'
 *   customer_ready:     boolean  -  the ONLY field callers should branch on
 *   blocking_gates:      reason codes, e.g. ['P21_BELOW_MINIMUM','P26_REJECTED']
 *   plus the individual engine scores/tiers for transparency (Section 21  - 
 *   explicit, non-ambiguous names, never a bare "quality: 83").
 */
export function evaluatePublicationGate(item) {
  const evaluatedAt = new Date().toISOString();
  const base = { evaluated_at: evaluatedAt, certification_version: PUBLICATION_GATE_VERSION };

  if (!item || typeof item !== 'object') {
    return { ...base, publication_state: 'BLOCKED', customer_ready: false,
             blocking_gates: ['ITEM_MISSING'] };
  }

  let p20, p21, p23, p25, p26, reportType, readiness, contentHash;
  try {
    p20 = computeP20QualityScore(item);
    p21 = getP21CertificationLevel(p20.total);
    p23 = computeOperationalReadiness(item);
    p25 = computeEnterpriseTrustScore(item);
    p26 = computeP26Grade(item);
    reportType = classifyReportType(item);
    readiness  = _typeAdjustedReadiness(p23, reportType);
    contentHash = _contentFingerprint(item);
  } catch (e) {
    // FAIL CLOSED  -  a certification engine throwing must never be treated
    // as "unknown = approved" (Section 8's explicit prohibition).
    return { ...base, publication_state: 'BLOCKED', customer_ready: false,
             blocking_gates: ['CERTIFICATION_ENGINE_ERROR'],
             error: String((e && e.message) || e) };
  }

  const blockingGates = [];
  if (p21.id === 'BELOW_MINIMUM')            blockingGates.push('P21_BELOW_MINIMUM');
  if (p20.total < P20_CRITICAL_THRESHOLD)    blockingGates.push('P20_QUALITY_CRITICALLY_LOW');
  if (p25.tier === 'BELOW THRESHOLD')        blockingGates.push('P25_BELOW_THRESHOLD');
  // Report-type-aware: for non-VULNERABILITY items with zero CVE/CVSS/KEV
  // signal, CVE-only gates (IR Package, Patch Priority) are excluded from
  // the denominator as NOT_APPLICABLE rather than counted as failures -- the
  // 50% threshold itself is unchanged (Section 8/9, Section 26 forbids
  // lowering thresholds; this only fixes what the pct is computed over).
  if (readiness.pct < 50)                    blockingGates.push('P23_OPERATIONAL_READINESS_DO_NOT_PUBLISH');
  if (p26.certFlags.certTier === 'REJECTED') blockingGates.push('P26_REJECTED');

  const customerReady = blockingGates.length === 0;
  const publicationState = customerReady
    ? 'CUSTOMER_READY'
    : (p26.certFlags.certTier === 'REJECTED' ? 'REJECTED' : 'BLOCKED');

  return {
    ...base,
    publication_state: publicationState,
    customer_ready: customerReady,
    P20_SCORE: p20.total,
    P21_CERTIFICATION: p21.id,
    P23_OPERATIONAL_READINESS_PCT: readiness.pct,
    P23_OPERATIONAL_READINESS_RAW_PCT: p23.pct,
    P23_OPERATIONAL_READINESS_BASIS: readiness.basis,
    P23_NOT_APPLICABLE_GATES: readiness.notApplicableGates,
    P25_TRUST_SCORE: p25.pct,
    P25_TRUST_TIER: p25.tier,
    P26_COMMERCIAL_SCORE: p26.composite,
    P26_GRADE: p26.grade,
    P26_CERT_TIER: p26.certFlags.certTier,
    REPORT_TYPE: reportType,
    content_hash: contentHash,
    blocking_gates: blockingGates,
  };
}

/** Convenience boolean-only check for hot filtering paths (index building). */
export function isCustomerReady(item) {
  return evaluatePublicationGate(item).customer_ready === true;
}

/**
 * v187.0 P0 FIX  -  customer-facing 404 body for a report id that DID resolve
 * to a known item, but that item failed the publication gate (REJECTED /
 * BLOCKED). Single source of truth for this response shape (previously
 * inlined at the /reports/** route in index.js) so it's directly unit-
 * testable: exposes only publication_state, never internal certification
 * scores, and never claims the report "may still be generating" -- a
 * permanent rejection retried by a customer will never resolve.
 */
export function buildGateRejectedResponseBody(gateResult) {
  return {
    error: 'Report unavailable',
    reason: 'publication_gate_rejected',
    status: (gateResult && gateResult.publication_state) || 'REJECTED',
  };
}

/**
 * v187.0 P0 FIX  -  customer-facing 404 body for a report id that could not be
 * resolved to any known item and has no cached HTML artifact. Covers both a
 * genuinely nonexistent id and one still pending/generating (this layer
 * cannot distinguish the two from here -- see publication_gate_rejected
 * above for the case that CAN be distinguished). Never claims the report
 * "may still be generating": per live incident evidence, an unresolvable id
 * is at least as often a permanent rejection as a pending one, and telling
 * a customer to retry a permanent rejection is misleading.
 */
export function buildUnresolvableReportResponseBody(path) {
  return { error: 'Report not found', path, reason: 'unresolvable' };
}
