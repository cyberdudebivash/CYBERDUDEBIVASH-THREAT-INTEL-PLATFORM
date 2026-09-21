/**
 * workers/intel-gateway/src/p41-handlers.js
 * P41.0 Live Capability Discovery API
 *
 * MISSION: closes the "Dynamic Frontend Discovery" gap identified after
 * PR #340. #340 built data/quality/frontend_capability_registry.json (149
 * top-level pages classified CUSTOMER_UI/ADMIN/INTERNAL) and a blocking CI
 * gate (capability_registry_gate.py, STAGE 3.92d) that keeps it accurate --
 * but the registry itself was never synced to R2 or served live: it is a
 * git/CI-only artifact, unreachable by any browser at runtime. When a new
 * CUSTOMER_UI page is added, the CI gate forces it to be classified, but no
 * mechanism ever surfaced that classification back to a visitor -- every
 * "here's what else you can explore" surface on the platform still had to
 * be hand-edited to know the page existed. This layer is that mechanism.
 *
 * ARCHITECTURE: composes over the EXISTING registry rather than re-deriving
 * classification (Reuse Before Build) -- same "Python pipeline writes JSON
 * -> R2 -> Worker reads via env.INTEL_R2.get()" pattern p40-handlers.js and
 * rx-pub-a0-handlers.js already document and use, replicated here rather
 * than introducing a new access pattern. This file computes NO
 * classification logic of its own; it is a thin, filtered, public-safe view
 * over scripts/build_capability_registry.py's own output.
 *
 * SECURITY (mission-mandated, non-negotiable):
 *   - This endpoint is intentionally PUBLIC (no auth required) -- unlike
 *     P21-P40, which the index.js dispatcher gates behind a valid API
 *     key/JWT (see index.js's `_p17to40Gated` block) because they serve
 *     computed intelligence (quality/trust/actionability scores) with real
 *     commercial value. This layer serves page-inventory metadata only
 *     (id/title/route/status) -- conceptually a live sitemap, not
 *     intelligence -- so requiring a paid key here would defeat its own
 *     purpose (a visitor must be able to discover what the platform offers
 *     BEFORE becoming a customer). index.js's auth-gate regex is NOT
 *     modified to add this exemption -- P41 simply falls outside its
 *     `p(2[1-9]|3\d|40)` pattern already, and index.js documents this
 *     explicitly at the call site rather than relying on silent omission.
 *   - ADMIN and INTERNAL registry entries are unconditionally excluded
 *     server-side, regardless of any query parameter -- there is no
 *     override. This is the mission's "never expose secrets or privileged
 *     APIs through capability discovery" requirement enforced in code, not
 *     just by convention.
 *   - The registry's own `notes` field (free-text engineering/audit
 *     commentary -- e.g. "no CRUD route exists", "hardcoded stat counters")
 *     is deliberately NEVER included in this endpoint's response. It is
 *     useful to a developer reading the JSON file in the repo; it is
 *     internal implementation-gap commentary that has no reason to reach an
 *     anonymous Internet caller. Only id / derived title / route / status
 *     are exposed.
 *
 * 3 exported handlers / 3 API routes:
 *   /api/v1/p41/capabilities  - full public capability listing (filterable
 *                               by ?status=)
 *   /api/v1/p41/capability    - single capability by ?id=
 *   /api/v1/p41/observability - observability health endpoint
 */

// Edge cache for the R2 registry read -- see r2-edge-cache.js for the
// measured latency/cost rationale this addresses.
import { cachedR2Json } from './r2-edge-cache.js';

const P41_VERSION  = '41.0';
const REGISTRY_KEY = 'intel/frontend_capability_registry.json';

// Hard allowlist, not a denylist: only categories explicitly listed here can
// ever leave this endpoint. Adding a new taxonomy category to the registry
// in future (see its own `taxonomy` field) does not automatically become
// public -- it must be added here deliberately.
const PUBLIC_CATEGORIES = new Set(['CUSTOMER_UI']);

// ---------------------------------------------------------------------------
// R2 loader -- mirrors p40-handlers.js's _loadR2Json (itself mirroring
// p21-handlers.js:_loadFeed's env.INTEL_R2?.get() + optional-chaining-safe
// pattern), scoped to this layer's own R2 key.
// ---------------------------------------------------------------------------
async function _loadR2Json(env, key) {
  try {
    // EDGE-CACHED (2026-09-21). This previously did env.INTEL_R2.get() on
    // EVERY request. Measured against live production, five consecutive
    // samples of the public /api/v1/p41/capabilities endpoint returned a
    // 16 KB body with ttfb 2.6-5.5s, while /api/feed served 1.2 MB over the
    // identical path in 0.25-0.32s -- a 16 KB response 10-20x slower than a
    // 1.2 MB one, consistently breaching the platform's own "< 2s p95
    // computed" budget. It also spent one R2 Class B operation per request.
    //
    // The Cache-Control header _json() already sets is only a hint to
    // downstream caches; a Worker-generated response is not edge-cached
    // unless the Worker puts it there, which cachedR2Json now does.
    //
    // Degradation-safe: a cache miss, a cache error, or no Cache API at all
    // falls through to exactly the previous R2 read, so this is never worse
    // than before. The outer try/catch and the null-on-failure contract are
    // unchanged, so every caller behaves identically.
    const parsed = await cachedR2Json(env, key);
    return parsed ?? null;
  } catch (_) {
    return null;
  }
}

async function _loadRegistry(env) {
  return await _loadR2Json(env, REGISTRY_KEY);
}

function _json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-P41-Version': P41_VERSION,
      // Registry changes are rare, human-reviewed edits, not a per-request
      // computation -- safe to cache longer than the P17-P40 intelligence
      // endpoints (which use 300s or no-cache). Matches r2_resync_manifests.py's
      // own cache-control choice for this same file (see that script).
      'Cache-Control': 'public, max-age=300',
    },
  });
}

function _registryUnavailable() {
  return _json({
    error: 'Capability registry not yet synced to R2',
    hint: 'Run scripts/build_capability_registry.py then scripts/r2_resync_manifests.py '
        + '(STAGE 4.1 in sentinel-blogger.yml), or check that pipeline stage\'s last run.',
    version: P41_VERSION,
  }, 503);
}

// Deterministic, mechanical display-name derivation from the real, already-
// public filename -- e.g. "enterprise-quality-center.html" ->
// "Enterprise Quality Center". Not a fabricated description: it is a pure
// string transform of data that is already public (the route itself is
// live and unauthenticated), never an invented fact about the page.
function _titleFromId(id) {
  const base = String(id || '').replace(/\.html?$/i, '');
  const words = base.replace(/[-_]+/g, ' ').trim();
  if (!words) return String(id || 'Untitled');
  return words.replace(/\S+/g, (w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase());
}

// Maps one registry entry to the PUBLIC shape. Deliberately narrow --
// `notes` (internal audit commentary) is never included; see file header.
// Defensive against a malformed entry so one bad record can never break the
// whole listing (mission "Rendering Resilience" requirement, applied
// server-side too).
function _toPublicCapability(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const id = typeof entry.id === 'string' ? entry.id : null;
  const route = typeof entry.frontend_route === 'string' ? entry.frontend_route : null;
  if (!id || !route) return null;
  return {
    id,
    title: _titleFromId(id),
    frontend_route: route,
    status: typeof entry.status === 'string' && entry.status ? entry.status : 'unclassified',
  };
}

function _countByStatus(list) {
  const counts = {};
  for (const c of list) {
    const s = c.status || 'unclassified';
    counts[s] = (counts[s] || 0) + 1;
  }
  return counts;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

export async function handleP41Capabilities(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();

  const url = new URL(request.url);
  const statusFilter = url.searchParams.get('status');

  const rawEntries = Array.isArray(registry.entries) ? registry.entries : [];
  // SECURITY: this filter runs unconditionally, before any query param is
  // applied, and has no override -- ADMIN/INTERNAL/DEPRECATED entries can
  // never reach the response regardless of what a caller requests.
  const publicEntries = rawEntries.filter((e) => e && PUBLIC_CATEGORIES.has(e.category));

  let capabilities = publicEntries.map(_toPublicCapability).filter(Boolean);
  if (statusFilter) {
    const wanted = statusFilter.toLowerCase();
    capabilities = capabilities.filter((c) => c.status.toLowerCase() === wanted);
  }

  return _json({
    schema_version: 'p41.0',
    registry_schema_version: registry.schema_version ?? null,
    // Passed through as-is (not re-derived) so a caller can tell how old the
    // underlying registry is -- honest freshness metadata rather than a
    // fabricated "live" claim. See _registryUnavailable() for the distinct
    // "no data at all" case this is not trying to also express.
    registry_generated_at: registry.generated_at ?? null,
    total: capabilities.length,
    filters_applied: { status: statusFilter || null },
    status_breakdown: _countByStatus(capabilities),
    capabilities,
  });
}

export async function handleP41CapabilityDetail(request, env) {
  const registry = await _loadRegistry(env);
  if (!registry) return _registryUnavailable();

  const url = new URL(request.url);
  const id = url.searchParams.get('id');
  if (!id) return _json({ error: "Missing required query param 'id'", version: P41_VERSION }, 400);

  const rawEntries = Array.isArray(registry.entries) ? registry.entries : [];
  const entry = rawEntries.find((e) => e && e.id === id && PUBLIC_CATEGORIES.has(e.category));
  const capability = entry ? _toPublicCapability(entry) : null;
  if (!capability) {
    return _json({ error: `Unknown or non-public capability id: ${id}`, version: P41_VERSION }, 404);
  }

  return _json({ schema_version: 'p41.0', capability });
}

export async function handleP41Observability(request, env) {
  const registry = await _loadRegistry(env);
  return _json({
    schema_version: 'p41.0',
    layer: 'P41',
    status: registry ? 'OPERATIONAL' : 'DEGRADED',
    degradation_reason: registry ? null : 'capability registry not synced to R2',
    endpoints: [
      '/api/v1/p41/capabilities',
      '/api/v1/p41/capability',
      '/api/v1/p41/observability',
    ],
    data_sources: {
      registry: 'data/quality/frontend_capability_registry.json (R2 key: intel/frontend_capability_registry.json)',
    },
    generators: [
      'scripts/build_capability_registry.py',
      'scripts/frontend_api_coverage_gate.py',
      'scripts/p41_production_certification.py',
    ],
    security: 'Public, unauthenticated by design (page-inventory metadata only, never intelligence '
            + 'data). CUSTOMER_UI category only -- ADMIN/INTERNAL are unconditionally excluded '
            + 'server-side. See file header for the full rationale.',
    engines_reused: [],
    engines_reused_note: 'P41 re-derives no classification logic -- it is a filtered, public-safe '
                        + 'view over the existing #340 capability registry (Single Source of Truth).',
  });
}
