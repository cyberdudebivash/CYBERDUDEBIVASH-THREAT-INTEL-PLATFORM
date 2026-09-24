/**
 * intel-static-proxy.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX -- Stage 4
 * ==============================================
 * R2-first proxy for two files previously reachable only as bare relative
 * static paths that this Worker's route table doesn't match
 * (/api/*, /reports/*, /taxii/*, /auth/* only -- "data/*" falls straight
 * through to the Pages static origin): data/ai_intelligence/ai_index.json
 * and data/intelligence/detection_rules/rule_manifest.json, which back
 * index.html's per-card "AI Record" / "Detection Rules" annotations.
 *
 * Same fix, same pattern as the existing /api/ai/{tracker,health,
 * executive-brief}.json proxy in index.js (issue #274's root-caused fix):
 * R2 checked first (no dependency on git push or Pages deploy timing), raw
 * gh-pages content kept as the fallback (zero regression if the R2 object
 * is ever missing, e.g. before the first pipeline run that writes it via
 * scripts/r2_upload.py's Upload 3c block).
 *
 * Extracted into its own dependency-free module -- same reason as
 * subscription-lifecycle.js / gumroad-lifecycle.js / revenue-enforcement.js
 * (see index.js's own header comments on those exports): index.js's full
 * import chain (via pricing.js's pricing-data.json import) fails Node's
 * native ESM loader outside the wrangler/esbuild bundler, so anything that
 * needs a plain `node --test` contract test has to live outside that chain.
 * CORS_HEADERS/SECURITY_HEADERS/jsonResp() are trivial (a handful of
 * static header entries and a one-line JSON Response constructor) and are
 * duplicated here rather than imported, for the same reason.
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

const PLATFORM_VERSION = "201.0";

// SENTINEL APEX PUBLIC-REPO ZERO-TRUST -- PHASE 3 (2026-09-10): both of this
// file's routes ARE genuinely public (unauthenticated, read-only threat-
// intel metadata -- see this file's own header comment), so wildcard CORS
// here was never the bug; the duplicate local declaration was. index.js's
// withBaselineHeaders() now applies the real policy (cors-policy.js) to
// every response including this file's, and cors-policy.js's own
// PUBLIC_EXACT_PATHS already lists both INTEL_STATIC_PROXY paths below --
// so this stays wildcard-open in production, just from one source instead
// of two. Kept as an empty object rather than removed so the two
// `...CORS_HEADERS` call sites below don't each need an individual edit.
const CORS_HEADERS = {};

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
  "X-Sentinel-Version": PLATFORM_VERSION,
  "X-Sentinel-Platform": "CYBERDUDEBIVASH-SENTINEL-APEX",
};

function jsonResp(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", ...extra },
  });
}

// New endpoints only -- the original data/ai_intelligence/ai_index.json and
// data/intelligence/detection_rules/rule_manifest.json static paths are
// untouched and keep serving their git-committed content unchanged, so any
// existing consumer of those exact URLs sees no behavior change.
//
// ghBranch (optional, per entry): which branch handleIntelStaticProxy()
// falls back to when R2 is empty/errors. Defaults to "gh-pages" below --
// unchanged for these first two entries. The 5 P0 RUNTIME INTELLIGENCE
// STATE RECOVERY entries added underneath explicitly set "main": their
// fallback content (data/{nexus,cortex,quantum,sovereign,genesis}/
// *_output.json) was never included in the gh-pages deploy bundle
// (scripts/build_dist_artifact.py's INCLUDE_DIRS excludes data/ entirely --
// confirmed, not assumed), so falling back to gh-pages for these would 404
// even when main has a servable (if stale) copy. Falling back to the exact
// raw-GitHub-main URL index.html already reads today keeps zero regression:
// R2 becomes the fresh primary source, and the pre-existing fallback content
// (frozen, but already what every consumer sees pre-migration) is neither
// removed nor relocated -- only demoted from "the only source" to "the
// fallback", per this mission's explicit "no removal of GitHub Raw runtime
// fallbacks" constraint.
const INTEL_STATIC_PROXY = {
  "/api/v1/intel/ai_index.json": {
    r2Key:  "intelligence/ai_index.json",
    ghPath: "data/ai_intelligence/ai_index.json",
  },
  "/api/v1/intel/detection_rules_manifest.json": {
    r2Key:  "intelligence/detection_rules_manifest.json",
    ghPath: "data/intelligence/detection_rules/rule_manifest.json",
  },
  "/api/v1/intel/nexus_output.json": {
    r2Key:  "data/nexus/nexus_output.json",
    ghPath: "data/nexus/nexus_output.json",
    ghBranch: "main",
  },
  "/api/v1/intel/genesis_output.json": {
    r2Key:  "data/genesis/genesis_output.json",
    ghPath: "data/genesis/genesis_output.json",
    ghBranch: "main",
  },
  "/api/v1/intel/cortex_output.json": {
    r2Key:  "data/cortex/cortex_output.json",
    ghPath: "data/cortex/cortex_output.json",
    ghBranch: "main",
  },
  "/api/v1/intel/quantum_output.json": {
    r2Key:  "data/quantum/quantum_output.json",
    ghPath: "data/quantum/quantum_output.json",
    ghBranch: "main",
  },
  "/api/v1/intel/sovereign_output.json": {
    r2Key:  "data/sovereign/sovereign_output.json",
    ghPath: "data/sovereign/sovereign_output.json",
    ghBranch: "main",
  },
};

/**
 * @param {Object} env - Worker env bindings (INTEL_R2 expected)
 * @param {string} path - request pathname
 * @param {string} method - request HTTP method
 * @returns {Promise<Response|null>} a Response if `path` is one of
 *   INTEL_STATIC_PROXY's registered paths, otherwise null so the caller's
 *   dispatcher knows to keep routing.
 */
async function handleIntelStaticProxy(env, path, method) {
  const entry = INTEL_STATIC_PROXY[path];
  if (!entry) return null;

  if (method !== "GET") {
    return jsonResp({ error: "method_not_allowed", allowed: ["GET"], request_id: crypto.randomUUID() }, 405, { "Allow": "GET" });
  }
  const { r2Key, ghPath, ghBranch = "gh-pages" } = entry;

  if (env.INTEL_R2) {
    try {
      const r2Obj = await env.INTEL_R2.get(r2Key);
      if (r2Obj) {
        return new Response(r2Obj.body, {
          status: 200,
          headers: { ...CORS_HEADERS, ...SECURITY_HEADERS, "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
        });
      }
    } catch (r2Err) {
      console.error(`[intel-static proxy] R2 read failed for ${r2Key}, falling back to gh-pages: ${r2Err && r2Err.message ? r2Err.message : r2Err}`);
    }
  }

  const upstreamUrl = `https://raw.githubusercontent.com/cyberdudebivash-pvt-ltd/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/${ghBranch}/${ghPath}`;
  try {
    const resp = await fetch(upstreamUrl, {
      cf: { cacheEverything: true, cacheTtl: 300 },
      headers: { "User-Agent": `SENTINEL-APEX/${PLATFORM_VERSION} (+https://intel.cyberdudebivash.com)` },
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) {
      console.error(`[intel-static proxy] ${ghPath}: upstream returned ${resp.status}`);
      return jsonResp({ error: "upstream_unavailable", path, request_id: crypto.randomUUID() }, 502, { "Cache-Control": "no-store" });
    }
    const data = await resp.json();
    return jsonResp(data, 200, { "Cache-Control": "public, max-age=300" });
  } catch (e) {
    console.error(`[intel-static proxy] ${ghPath}: ${e && e.message ? e.message : e}`);
    return jsonResp({ error: "upstream_unavailable", path, request_id: crypto.randomUUID() }, 502, { "Cache-Control": "no-store" });
  }
}

export { handleIntelStaticProxy, INTEL_STATIC_PROXY };
