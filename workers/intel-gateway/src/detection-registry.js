/**
 * workers/intel-gateway/src/detection-registry.js
 * Canonical detection artifact registry -- Phase 4.1 mandate Section 11.
 *
 * ROOT CAUSE (Section 9-10, traced against current main, not assumed):
 * the mandate's premise was that /api/v1/detections is "disconnected from
 * all four real detection generators." Tracing the actual deployment found
 * something sharper -- api/v1_router.py (which defines that route) is not
 * mounted by any running server: nothing imports it except a file-existence
 * audit script, and the Dockerfile's own CMD references agent/api/
 * api_server.py, a module path that does not exist in this repository (the
 * real file is agent/v49_intelligence_api/api_server.py). The confirmed-live
 * production surface -- this Worker, verified directly against
 * intel.cyberdudebivash.com this session -- has no per-item queryable
 * detections endpoint at all; its only "detections" route,
 * /api/v1/premium/detections/{artifact}, serves fixed-enum static bundle
 * files (sigma_rules.yml, kql_queries.kql, ...), not per-item records.
 *
 * SOURCE OF TRUTH: detection_bundle_injector.py -- confirmed live and wired
 * as STAGE 3.1.12/3.1.20 in .github/workflows/sentinel-blogger.yml -- writes
 * sigma_rule / kql_query / suricata_rule / yara_rule fields directly onto
 * each feed item. This registry normalizes THAT already-live output into
 * one canonical shape (Section 11: "Do not necessarily rewrite each
 * generator. Adapt their outputs into one registry.").
 *
 * SCOPE BOUNDARY (Section 10 audit; do not re-litigate without re-reading
 * the source): this platform has (at least) four independently-coded
 * detection-rule generators with zero shared code:
 *   1. detection_bundle_injector.py            -- this registry's source.
 *   2. generate_detection_pack.py               -- premium bundle downloads
 *      via /api/v1/premium/detections/{artifact}; different shape/purpose
 *      (a paid product's static file bundle, not per-item records) --
 *      untouched, still the correct producer for that route.
 *   3. generate_intel_reports.py's detection_engineering_orchestrator.py --
 *      documented consumer was api/v1_router.py, confirmed dead code above.
 *   4. detection-engine.yml's v51_detection_engine -- a wholly separate
 *      workflow/subsystem (agent/detection_forge.py + core/detection/
 *      detection_engine.py).
 * Consolidating all four was explicitly flagged by this repo's own prior
 * engineering note (.github/workflows/sentinel-blogger.yml, STAGE 3.1.21
 * comment, dated 2026-08-05) as needing "the Architecture Preservation
 * Rule's full Compatibility Assessment + Migration Plan and a product
 * decision on which format is canonical... flagged for a dedicated future
 * review, not touched here." This registry respects that prior decision:
 * it wires up the one generator whose output already reaches the live
 * customer feed, closing the confirmed gap (no queryable per-item API
 * existed at all) without re-opening the larger four-way consolidation a
 * prior audit already, correctly, deferred.
 */

export const DETECTION_REGISTRY_VERSION = '1.0.0';

const RULE_FIELD = { sigma: 'sigma_rule', kql: 'kql_query', suricata: 'suricata_rule', yara: 'yara_rule' };
const ARTIFACT_TYPES = Object.keys(RULE_FIELD);

function _cveIdsForItem(item) {
  // Local, evidence_context-only derivation (this Worker's own cve-id
  // canonicalization lives in p20/p21-handlers.js for scoring purposes;
  // this is a display-field convenience, not a scoring input, so it is not
  // worth an inter-module dependency for -- same cve_ids/cve_id/cves
  // precedence as the Python-side canonical accessor added in Checkpoint B
  // (scripts/p38_shared_validators.get_cve_ids), kept in sync by contract,
  // not by shared code, since the two runtimes cannot share a module.
  const ids = [];
  const seen = new Set();
  const push = (v) => {
    const s = String(v || '').trim().toUpperCase();
    if (s && !seen.has(s)) { seen.add(s); ids.push(s); }
  };
  if (Array.isArray(item.cve_ids)) item.cve_ids.forEach(push);
  else if (Array.isArray(item.cves)) item.cves.forEach(push);
  if (item.cve_id) push(item.cve_id);
  return ids;
}

/** Section 17: truthful status, never VERIFIED solely because generation
 * completed. The Sigma rule is the one artifact type whose own YAML
 * self-declares a status line (this generator always emits "experimental"
 * today) -- read it rather than assume. The sibling kql/suricata/yara
 * artifacts from the same generation pass carry no equivalent field and are
 * labeled consistently with their Sigma sibling rather than given
 * unearned confidence a human has not reviewed. */
function _artifactStatus(artifactType, content) {
  if (artifactType === 'sigma') {
    const m = /^status:\s*(\S+)/m.exec(content || '');
    const s = m ? m[1].toLowerCase() : '';
    if (s === 'stable') return 'VERIFIED';
    if (s === 'test') return 'DERIVED';
    return 'EXPERIMENTAL'; // 'experimental', unknown, or unparseable
  }
  return 'EXPERIMENTAL';
}

/** Section 16: format validation where tools exist. A full Sigma-schema /
 * YARA-compile / Suricata-syntax validator is not available in the
 * Worker's isolate runtime (no such library ships here); these are the
 * cheap, deterministic structural checks that ARE possible without one.
 * An artifact that fails is excluded entirely -- never served labeled as
 * production-ready (Section 16: "must not be returned as production-ready
 * ... may be exposed only with an explicit EXPERIMENTAL state where policy
 * allows" -- here it is simply excluded, the more conservative reading,
 * since this registry has no separate "known-invalid" customer-facing
 * surface to place it in instead of silently vanishing from the count). */
function _passesStructuralCheck(artifactType, content) {
  if (typeof content !== 'string') return false;
  const t = content.trim();
  if (t.length < 20) return false;
  if (artifactType === 'sigma') return /\bdetection:/.test(t) && /\bcondition:/.test(t);
  if (artifactType === 'suricata') return /^(alert|drop|reject|pass)\s/i.test(t) || /\bsid:\s*\d+/.test(t);
  return true; // kql / yara: presence + minimum length is the practical bar here
}

/**
 * Normalizes one feed item's rule fields into 0-N canonical
 * DetectionArtifact records. Pure, synchronous, no I/O.
 */
export function extractDetectionArtifacts(item) {
  if (!item || typeof item !== 'object') return [];
  // Preserve the registry's established id-first public intel_id for
  // backward compatibility, but retain every real source identifier as an
  // internal lookup alias. Correlation/report routes use stix_id-first; without
  // aliases a valid correlation report_id can fail to resolve detections when
  // both fields exist and differ.
  const intelId = item.id || item.stix_id;
  if (!intelId) return [];
  const intelAliases = [...new Set([item.id, item.stix_id].filter((v) => typeof v === 'string' && v.trim()))];
  const evidenceContext = {
    cve_ids: _cveIdsForItem(item),
    severity: item.severity || null,
    title: item.title || null,
    actor_tag: item.actor_tag || item.actor_id || null,
  };
  const ts = item.detection_generated_at || item.processed_at || item.timestamp || null;

  const artifacts = [];
  for (const artifactType of ARTIFACT_TYPES) {
    const content = item[RULE_FIELD[artifactType]];
    if (!content) continue;
    if (!_passesStructuralCheck(artifactType, content)) continue;
    artifacts.push({
      artifact_id: `${intelId}:${artifactType}`,
      intel_id: intelId,
      // Internal-only alias set. toPublicArtifact() deliberately omits this
      // field, so the customer-facing response schema remains unchanged.
      _intel_aliases: intelAliases,
      artifact_type: artifactType,
      content,
      generator: 'detection_bundle_injector.py',
      status: _artifactStatus(artifactType, content),
      validation_state: 'STRUCTURAL_CHECK_PASSED',
      evidence_context: evidenceContext,
      created_at: ts,
      updated_at: ts,
      version: DETECTION_REGISTRY_VERSION,
    });
  }
  return artifacts;
}

/** Builds the full registry from a feed. Never throws on a malformed item --
 * one bad item contributes zero artifacts, not a crashed request (mirrors
 * this mandate's Section 20 failure-isolation requirement for the producer
 * side, applied here on the read side too). */
export function buildDetectionRegistry(items) {
  const registry = [];
  for (const item of items || []) {
    try {
      const artifacts = extractDetectionArtifacts(item);
      if (artifacts.length) registry.push(...artifacts);
    } catch (_e) {
      // Skip this item's artifacts; never let one malformed record fail
      // the whole registry build.
      continue;
    }
  }
  return registry;
}

const VALID_STATUSES = new Set(['VERIFIED', 'DERIVED', 'EXPERIMENTAL', 'TEMPLATE']);

/**
 * Filters + paginates a pre-built registry. Section 13: only filters with
 * real underlying support are offered -- every field here is a plain
 * in-memory scan over the already-loaded feed, the same pattern this
 * Worker's other list endpoints (customer_ready_latest, TAXII collections)
 * already use; there is no external index to be unstable without.
 */
export function queryDetectionRegistry(registry, params = {}) {
  let results = registry;

  if (params.intel_id) {
    results = results.filter(a =>
      a.intel_id === params.intel_id ||
      (Array.isArray(a._intel_aliases) && a._intel_aliases.includes(params.intel_id))
    );
  }
  if (params.artifact_type) {
    const want = String(params.artifact_type).toLowerCase();
    if (!ARTIFACT_TYPES.includes(want)) {
      return { error: `Unknown artifact_type: ${params.artifact_type}`, valid_types: ARTIFACT_TYPES };
    }
    results = results.filter(a => a.artifact_type === want);
  }
  if (params.status) {
    const want = String(params.status).toUpperCase();
    if (!VALID_STATUSES.has(want)) {
      return { error: `Unknown status: ${params.status}`, valid_statuses: [...VALID_STATUSES] };
    }
    results = results.filter(a => a.status === want);
  }
  if (params.severity) {
    const want = String(params.severity).toUpperCase();
    results = results.filter(a => (a.evidence_context.severity || '').toUpperCase() === want);
  }
  if (params.cve) {
    const want = String(params.cve).toUpperCase();
    results = results.filter(a => a.evidence_context.cve_ids.includes(want));
  }
  if (params.actor) {
    const want = String(params.actor).toLowerCase();
    results = results.filter(a => (a.evidence_context.actor_tag || '').toLowerCase() === want);
  }
  if (params.since) {
    const sinceMs = Date.parse(params.since);
    if (!Number.isNaN(sinceMs)) {
      results = results.filter(a => a.created_at && Date.parse(a.created_at) >= sinceMs);
    }
  }

  const total = results.length;
  const limit = Math.max(1, Math.min(parseInt(params.limit, 10) || 50, 200));
  let offset = 0;
  if (params.cursor) {
    const parsed = parseInt(Buffer_atob(params.cursor), 10);
    if (Number.isFinite(parsed) && parsed >= 0) offset = parsed;
  }
  const page = results.slice(offset, offset + limit);
  const nextCursor = offset + limit < total ? Buffer_btoa(String(offset + limit)) : null;

  return {
    data: page,
    pagination: { total, limit, offset, next_cursor: nextCursor, returned: page.length },
  };
}

// Workers runtime has global atob/btoa (Web APIs), not Node's Buffer --
// named distinctly so a future contributor porting this to a Node context
// notices the substitution point rather than silently keeping a
// Node-specific import that would not run in the Worker isolate.
function Buffer_atob(s) { try { return atob(s); } catch (_e) { return ''; } }
function Buffer_btoa(s) { return btoa(s); }

/** Section 14: safe customer-facing projection. Never expose internal
 * prompts, provider secrets, debug traces, or raw generation metadata --
 * this registry's records never carried any of those fields to begin with
 * (content is the literal rule text, which IS the product), but this
 * function is the one explicit place that contract is enforced and
 * future fields must pass through, rather than an implicit "the record
 * happens to be safe today." */
export function toPublicArtifact(a) {
  return {
    artifact_id: a.artifact_id,
    intel_id: a.intel_id,
    artifact_type: a.artifact_type,
    content: a.content,
    status: a.status,
    evidence_context: a.evidence_context,
    created_at: a.created_at,
    updated_at: a.updated_at,
  };
}
