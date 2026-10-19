/**
 * workers/intel-gateway/src/certification-registry.js
 * Persisted publication-certification state -- P0 trust-boundary fix.
 *
 * PROBLEM (forensic evidence, live production, 2026-08-11): /api/reports/
 * latest.json's publication filter resolved each registry entry against the
 * CURRENT rolling-window feed sources and only ran evaluatePublicationGate()
 * for entries it could resolve there. An entry that had scrolled OUT of that
 * window was "unresolvable" and was passed through UNFILTERED -- so of
 * latest.json's 50 raw candidates, the 33 that WERE resolvable were
 * correctly REJECTED by the gate (P20/P21/P23/P25/P26 all failing --
 * genuinely low-quality, not a miscalibration), while the 17 that "survived"
 * were ALL unresolvable, none of them actually certified. NOT_FOUND_IN_FEED
 * had become a silent CUSTOMER_READY equivalent.
 *
 * FIX: certification is evaluated ONCE per item, at the first opportunity it
 * is resolvable against the rolling feed, and the verdict is PERSISTED here
 * (R2, independent of feed membership). From then on: (a) an item that has
 * already been certified remains verifiable forever, regardless of whether
 * it later scrolls out of the feed -- Section 5's historical-provenance
 * requirement -- and (b) an item that has NEVER been evaluated -- whether
 * because it hasn't been seen yet or because it will never resolve again --
 * is classified NOT_EVALUATED and is NEVER treated as customer-ready. That
 * is the one invariant this module exists to guarantee:
 *
 *   NOT_EVALUATED (including the old "NOT_FOUND_IN_FEED" case) != CUSTOMER_READY
 *
 * evaluatePublicationGate() (publication-gate.js) is reused completely
 * UNCHANGED -- this module only adds persistence and the explicit state-model
 * naming this task's design (Sections 1/3/4) requires around it. No
 * certification engine (P20/P21/P23/P25/P26) is touched, reimplemented, or
 * recalibrated. No secondary scoring logic is introduced.
 */

import { evaluatePublicationGate, _contentFingerprint } from './publication-gate.js';

export const CERTIFICATION_INDEX_KEY = 'certification/index.json';
export const CERTIFICATION_POLICY_VERSION = '1.0.0';

/**
 * Maps the existing gate's verdict onto the explicit state model Section 3
 * defines. Pure, deterministic, no new scoring -- a naming/shape transform
 * only, over fields evaluatePublicationGate() already computes.
 */
export function classifyCertification(gateResult) {
  if (!gateResult || (gateResult.blocking_gates || []).includes('CERTIFICATION_ENGINE_ERROR')) {
    // Fail closed (Section 4): an engine erroring must never be treated as
    // "unknown = approved."
    return { certification_status: 'CERTIFICATION_ERROR', publication_status: 'WITHHELD' };
  }
  if (gateResult.customer_ready) {
    return { certification_status: 'CERTIFIED', publication_status: 'CUSTOMER_READY' };
  }
  // Not customer-ready: distinguish a hard policy rejection (P26 REJECTED
  // tier -- the same tier the documented publication-gate incident hinged
  // on) from an item that simply hasn't accumulated enough enrichment yet
  // (any other blocking gate). Both come from evaluatePublicationGate()'s
  // own existing publication_state field -- not a new judgment call.
  const publicationStatus = gateResult.publication_state === 'REJECTED' ? 'REJECTED' : 'PENDING_ENRICHMENT';
  return { certification_status: 'BLOCKED', publication_status: publicationStatus };
}

async function r2Put(env, key, value) {
  await env.INTEL_R2.put(key, JSON.stringify(value), {
    httpMetadata: { contentType: 'application/json' },
  });
}

/** Never throws. A missing/corrupt index is treated as "no certifications
 * persisted yet" -- the only effect is that more items fall through to
 * fresh evaluation this request, never fewer. That is the safe direction:
 * it can only cause extra (correct) re-evaluation, never a stale or
 * fabricated verdict being trusted. */
export async function loadCertificationIndex(env) {
  try {
    const obj = await env.INTEL_R2.get(CERTIFICATION_INDEX_KEY);
    if (!obj) return {};
    const text = await obj.text();
    if (!text || text.trim() === '') return {};
    const parsed = JSON.parse(text);
    return (parsed && typeof parsed === 'object' && parsed.records && typeof parsed.records === 'object')
      ? parsed.records : {};
  } catch (e) {
    console.error(`[certification-registry] index load failed: ${e && e.message ? e.message : e}`);
    return {};
  }
}

/**
 * Read-modify-write merge. Best-effort; a lost update under concurrent
 * writes only ever causes an item to be re-evaluated (and re-persisted) on
 * its next request -- never a fabricated or stale-but-trusted verdict, since
 * evaluation always re-runs the real gate against the current item data.
 * Persistence failing must never block the response that triggered it -- the
 * freshly-evaluated verdict this request already computed is still used for
 * THIS response regardless of whether the write below succeeds.
 */
export async function persistCertificationRecords(env, newRecords) {
  if (!newRecords || Object.keys(newRecords).length === 0) return;
  try {
    const existing = await loadCertificationIndex(env);
    const merged = { ...existing, ...newRecords };
    await r2Put(env, CERTIFICATION_INDEX_KEY, {
      schema_version: '1.0.0',
      policy_version: CERTIFICATION_POLICY_VERSION,
      updated_at: new Date().toISOString(),
      records: merged,
    });
  } catch (e) {
    console.error(`[certification-registry] persist failed: ${e.message}`);
  }
}

/**
 * Evaluate-or-reuse a single item's certification.
 *   existingRecord -- the persisted verdict if one exists (undefined if not)
 *   item           -- the full intelligence object if resolvable in the
 *                      current feed windows (undefined if not)
 * Returns { record, isNew } -- isNew=true means the caller should persist it.
 */
export function resolveCertification(existingRecord, item) {
  if (existingRecord && typeof existingRecord === 'object' &&
      !Array.isArray(existingRecord)) {
    // A historical approval without current policy provenance, a content
    // fingerprint, or internally consistent state is NOT a reusable approval.
    // Old records may be re-evaluated from the current feed, but cannot grant
    // access when the underlying content is no longer resolvable. This
    // preserves Section 5 historical provenance only for verifiable records.
    const validStatus = (
      (existingRecord.certification_status === 'CERTIFIED' &&
        existingRecord.publication_status === 'CUSTOMER_READY') ||
      (existingRecord.certification_status === 'BLOCKED' &&
        ['REJECTED', 'PENDING_ENRICHMENT'].includes(existingRecord.publication_status)) ||
      (existingRecord.certification_status === 'CERTIFICATION_ERROR' &&
        existingRecord.publication_status === 'WITHHELD')
    );
    const hasProvenance =
      existingRecord.policy_version === CERTIFICATION_POLICY_VERSION &&
      typeof existingRecord.content_hash === 'string' &&
      /^fp_[0-9a-f]{1,8}$/.test(existingRecord.content_hash) &&
      Array.isArray(existingRecord.blocking_gates) &&
      (existingRecord.publication_status !== 'CUSTOMER_READY' ||
        existingRecord.blocking_gates.length === 0);
    if (validStatus && hasProvenance &&
        (!item || existingRecord.content_hash === _contentFingerprint(item))) {
      return { record: existingRecord, isNew: false };
    }
  }

  if (!item) {
    // Cannot resolve AND nothing persisted: NOT_EVALUATED. This is exactly
    // the case that used to silently pass through. It is never persisted --
    // caching a negative for an item we simply haven't seen yet would be
    // indistinguishable from a real rejection, and a future request where it
    // IS resolvable must get a real evaluation, not a permanently-cached
    // "not evaluated" that can never heal.
    return {
      record: { certification_status: 'NOT_EVALUATED', publication_status: 'WITHHELD' },
      isNew: false,
    };
  }

  const gate = evaluatePublicationGate(item);
  const classified = classifyCertification(gate);
  const record = {
    ...classified,
    evaluated_at: gate.evaluated_at,
    policy_version: CERTIFICATION_POLICY_VERSION,
    content_hash: gate.content_hash,
    blocking_gates: gate.blocking_gates || [],
    engines: {
      P20: gate.P20_SCORE, P21: gate.P21_CERTIFICATION,
      P23: gate.P23_OPERATIONAL_READINESS_PCT, P25: gate.P25_TRUST_TIER,
      P26: gate.P26_CERT_TIER,
    },
  };
  return { record, isNew: true };
}
