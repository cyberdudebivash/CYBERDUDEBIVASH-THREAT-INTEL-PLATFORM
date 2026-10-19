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
// R2 public intelligence is hard-bounded to 1 MiB and 40 levels below.
// Incident 2026-10-14: a fresh, all-CLEAR 100-advisory latest.json exceeded
// the former 25,000-value traversal limit and customer APIs returned 503.
// Permit up to 100,000 visits (including scalar leaves) WITHOUT changing the
// strict TLP semantics or relaxing body/depth ceilings. Above that, deny.
// Diagnostic MUST import these exports instead of mirroring constants.
const MAX_PUBLIC_BODY_BYTES = 1024 * 1024;
const MAX_PUBLIC_NODES = 100000;
const MAX_PUBLIC_DEPTH = 40;
const ADVISORY_KEYS = ["id", "advisory_id", "intel_id", "report_url", "internal_report_url", "cve_id", "stix_id", "cve_ids", "threat_id"];

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
    if (typeof node.classification === "string" && /TLP\s*[:\-]/i.test(node.classification)) {
      const tokens = [...node.classification.matchAll(/TLP\s*[:\-]\s*(?:AMBER\s*\+\s*STRICT|[A-Z]+)/gi)];
      if (!tokens.length || tokens.some(([v]) => v.replace(/\s+/g, "").replace(/TLP-/i, "TLP:").toUpperCase() !== "TLP:CLEAR")) return false;
    }
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
  "/api/v1/intel/weekly_brief.json": {
    r2Key: "api/v1/intel/weekly_brief.json",
    ghPath: "api/v1/intel/weekly_brief.json", // inert; R2 is the sole source
  },
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

const WEEK_MS = 7 * 86400000;
const BRIEF_MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
function weeklyBriefIsCurrent(doc, currentMs = Date.now()) {
  if (!doc || doc._schema !== "sentinel-apex-weekly-brief-v1" ||
      !doc.stats || !Number.isInteger(doc.stats.total_advisories) ||
      doc.stats.total_advisories < 1 || !Array.isArray(doc.top_threats) ||
      doc.top_threats.length < 1 || !Number.isFinite(currentMs)) return false;
  const date = new Date(currentMs);
  const thisMonday = Date.UTC(date.getUTCFullYear(), date.getUTCMonth(),
    date.getUTCDate() - ((date.getUTCDay() + 6) % 7));
  const weekStart = new Date(thisMonday - WEEK_MS);
  const weekEnd = new Date(thisMonday - 86400000);
  const thursday = new Date(weekStart.getTime() + 3 * 86400000);
  const isoYear = thursday.getUTCFullYear();
  const jan4 = new Date(Date.UTC(isoYear, 0, 4));
  const firstMonday = Date.UTC(isoYear, 0, 4 - ((jan4.getUTCDay() + 6) % 7));
  const isoWeek = Math.floor((weekStart.getTime() - firstMonday) / WEEK_MS) + 1;
  const format = d => String(d.getUTCDate()).padStart(2, "0") + " " +
    BRIEF_MONTHS[d.getUTCMonth()] + " " + d.getUTCFullYear();
  const generatedAt = Date.parse(doc.generated_at);
  return doc.week === "Week " + isoWeek + " " + isoYear &&
    doc.period === format(weekStart) + " \u2014 " + format(weekEnd) &&
    Number.isFinite(generatedAt) &&
    generatedAt <= currentMs + 300000 && currentMs - generatedAt <= 8 * 86400000;
}

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
    // Week rollover or a missing weekly publisher must never yield 200
    // containing an old edition (no inherited freshness from the live feed).
    if (path === "/api/v1/intel/weekly_brief.json" && !weeklyBriefIsCurrent(doc)) {
      throw new Error("weekly_brief_stale_or_invalid");
    }
    return jsonResp(doc, 200, { "Cache-Control": "public, max-age=120" });
  } catch {
    // Restricted/invalid data never appears in diagnostics or access logs.
    return jsonResp({ error: "verified_intelligence_unavailable" }, 503,
      { "Cache-Control": "no-store", "Retry-After": "60" });
  }
}

export { handleIntelStaticProxy, INTEL_STATIC_PROXY, publicTlpJsonVerified,
  MAX_PUBLIC_BODY_BYTES, MAX_PUBLIC_NODES, MAX_PUBLIC_DEPTH, weeklyBriefIsCurrent };
