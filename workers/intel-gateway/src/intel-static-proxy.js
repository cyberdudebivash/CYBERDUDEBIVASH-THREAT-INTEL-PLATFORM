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
 * P0 #725: R2 is the ONLY public read authority. A raw GitHub fallback
 * can bypass the source's TLP publication gate after a denied item was
 * withheld from R2. Missing/unavailable R2 returns 503, never stale raw
 * upstream content. Every R2 JSON payload is checked before emission.
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


// P0 #725: deny-only edge backstop, not a second publication authority.
// The Python tlp_policy.py remains the authorizing producer-side policy.
// A Worker must NOT turn an unverified object or source-less advisory into
// public content when R2 contains old, pre-gate bytes. Intentional false
// negatives are unacceptable; on ambiguity, retry after verified regeneration.
const MAX_PUBLIC_BODY_BYTES = 1024 * 1024;
const MAX_PUBLIC_NODES = 25000;
const MAX_PUBLIC_DEPTH = 40;
const ADVISORY_KEYS = ["id", "advisory_id", "intel_id", "report_url", "internal_report_url", "cve_id", "stix_id", "cve_ids", "threat_id"];

// Fail closed on ambiguous compound TLP classifications. In particular,
// "TLP:CLEAR / RED" carries TWO markings even though the second does not
// repeat "TLP:"; matching only explicit TLP: tokens would let it through.
// This is a deny-only edge backstop to the Python publication authority.
function publicClassificationVerified(raw) {
  if (typeof raw !== "string") return false;
  // Canonicalize formatting obfuscation before examining any marking.
  const value = raw.normalize("NFKC").replace(/\p{Cf}/gu, "");
  const markers = [...value.matchAll(/\bTLP\b/gi)];
  if (!markers.length) return true; // Non-TLP metadata classifications are allowed.
  for (const marker of markers) {
    if (!/^TLP\s*[:\-]\s*CLEAR\b/i.test(value.slice(marker.index))) return false;
  }
  // Joined labels after CLEAR (including bare RED/AMBER) are ambiguous or
  // restricted. These must not be authorized by the first CLEAR token.
  const joined = /\bTLP\s*[:\-]\s*CLEAR\b\s*(?:[\/,;|&+\-\u2013\u2014]|\b(?:and|or|then)\b)\s*(?:TLP\s*[:\-]\s*)?(?:CLEAR|WHITE|GREEN|AMBER(?:\s*\+\s*STRICT)?|RED)\b/i;
  return !joined.test(value);
}

function publicTlpJsonVerified(doc) {
  let nodes = 0;
  function walk(node, depth) {
    if (++nodes > MAX_PUBLIC_NODES || depth > MAX_PUBLIC_DEPTH) return false;
    if (node === null || typeof node !== "object") return true;
    if (Array.isArray(node)) return node.every(item => walk(item, depth + 1));
    const hasTlp = Object.hasOwn(node, "tlp") || Object.hasOwn(node, "tlp_label");
    for (const key of ["tlp", "tlp_label"]) {
      if (Object.hasOwn(node, key)) {
        if (typeof node[key] !== "string" || node[key].trim().toUpperCase() !== "TLP:CLEAR") return false;
      }
    }
    if (Object.hasOwn(node, "classification") &&
        !publicClassificationVerified(node.classification)) return false;
    // Metadata can be unlabeled; an individual advisory cannot be
    // anonymously authorized without an explicit classification. An
    // untrusted source URL is not evidence that a collector approved it.
    if (!hasTlp && typeof node.title === "string" && ADVISORY_KEYS.some(k => Object.hasOwn(node, k))) return false;
    return Object.values(node).every(value => walk(value, depth + 1));
  }
  // Scalar or null JSON has no verifiable public intelligence schema.
  if (doc === null || typeof doc !== "object") return false;
  return walk(doc, 0);
}

// Static proxy routing remains unchanged, but original raw GitHub branch/path
// values below are retained only as inert metadata for backwards-compatible
// route registration. The public handler NEVER performs a GitHub fetch.
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
  const { r2Key } = entry;

  if (!env?.INTEL_R2 || typeof env.INTEL_R2.get !== "function") {
    return jsonResp({ error: "verified_intelligence_unavailable" }, 503,
      { "Cache-Control": "no-store", "Retry-After": "60" });
  }
  let obj;
  try {
    obj = await env.INTEL_R2.get(r2Key);
  } catch {
    // Never disclose storage details, and never fall back to raw GitHub.
    return jsonResp({ error: "verified_intelligence_unavailable" }, 503,
      { "Cache-Control": "no-store", "Retry-After": "60" });
  }
  if (!obj) {
    return jsonResp({ error: "verified_intelligence_unavailable" }, 503,
      { "Cache-Control": "no-store", "Retry-After": "60" });
  }
  try {
    if (Number.isFinite(obj.size) && obj.size > MAX_PUBLIC_BODY_BYTES) {
      throw new Error("oversize");
    }
    const raw = await new Response(obj.body).text();
    if (new TextEncoder().encode(raw).byteLength > MAX_PUBLIC_BODY_BYTES) throw new Error("oversize");
    const doc = JSON.parse(raw);
    if (!publicTlpJsonVerified(doc)) throw new Error("unverified_public_classification");
    return jsonResp(doc, 200, { "Cache-Control": "public, max-age=120" });
  } catch {
    // Restricted/invalid data never appears in diagnostics or access logs.
    return jsonResp({ error: "verified_intelligence_unavailable" }, 503,
      { "Cache-Control": "no-store", "Retry-After": "60" });
  }
}

export { handleIntelStaticProxy, INTEL_STATIC_PROXY, publicTlpJsonVerified };
