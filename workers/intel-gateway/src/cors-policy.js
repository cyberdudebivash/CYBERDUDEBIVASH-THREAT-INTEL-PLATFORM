/**
 * cors-policy.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX -- Zero-Trust Cross-Origin Policy
 * ===================================================================
 * SENTINEL APEX PUBLIC-REPO ZERO-TRUST -- PHASE 3: AUTHENTICATED CORS +
 * CROSS-ORIGIN TRUST-BOUNDARY HARDENING.
 *
 * Single source of truth for every Access-Control-* decision this Worker
 * makes. Before this file, `Access-Control-Allow-Origin: "*"` was declared
 * independently in 14 files across intel-gateway (index.js's own
 * CORS_HEADERS/withBaselineHeaders(), plus a duplicate inline copy in each
 * of premium-reports.js, credit-system.js, dark-web-monitor.js,
 * api-extensions.js, revenue-enforcement.js, intel-static-proxy.js, and
 * p16/p17/p18/p19/p30/p31/p32-handlers.js) -- unconditionally, for every
 * response including admin (/api/admin/*), premium ($49/report
 * /api/reports/premium), billing/quota (402 responses), and MISP/CSV
 * commercial exports. index.js's withBaselineHeaders() already overwrites
 * whatever any individual handler sets (Headers.set() at the one true
 * fetch() choke point), so those 13 duplicates were already dead for the
 * actual response -- but a future edit to withBaselineHeaders() alone
 * would silently un-mask them, and a reader has no way to tell "dead
 * wildcard" from "live wildcard" without tracing the whole call chain.
 * This module is the fix for both: real behavior now comes from here, and
 * the 13 duplicates are removed at their source (see this PR's diff).
 *
 * Model, deliberately the smallest one that satisfies every mission trust
 * class without a bespoke code path per class:
 *
 *   PUBLIC   -- Access-Control-Allow-Origin: * unconditionally. Reserved
 *               for routes proven (via this platform's own self-documented
 *               404 "available_endpoints" list, or an explicit "public by
 *               design" comment at the route) to be read-only, non-tiered,
 *               non-customer-specific threat intelligence. GET/HEAD only.
 *               Mission class A.
 *
 *   BROWSER  -- Access-Control-Allow-Origin: <exact Origin> only when the
 *               Origin is on PRODUCTION_BROWSER_ORIGINS; omitted (never
 *               reflected, never wildcarded) for every other Origin,
 *               INCLUDING an absent Origin (a curl/PowerShell/Python/SIEM/
 *               SOAR/TAXII/server-to-server caller is not a browser and is
 *               never denied for lacking one -- see resolveCorsForRoute()).
 *               This is the default for everything under /api, /auth, and
 *               /taxii that isn't explicitly PUBLIC or INTERNAL: dashboard
 *               data, P16-P41 endpoints, premium reports, alerts, SLA,
 *               exports, brand/vendor-risk/geopolitical intel, NLQ/
 *               Copilot, auth/login (the dashboard's own login modal --
 *               see index.js's "/api/auth/* aliases" comment), SSO,
 *               payment/checkout. AuthN/AuthZ/entitlement (resolveAuth(),
 *               resolveEntitlement()) already gate what these return; this
 *               module only ever decides whether a *browser* is allowed to
 *               *read* that response cross-origin. It never blocks the
 *               request itself, so no non-browser caller is ever affected
 *               by an Origin header it doesn't send. Mission classes B/C/E
 *               (machine-to-machine gets identical treatment: no wildcard,
 *               no reflection, absent-Origin unaffected -- there is no
 *               separate code path because the mission's own spec asks
 *               for the same three behaviors for both).
 *
 *   INTERNAL -- No Access-Control-Allow-Origin, ever, for any Origin
 *               (including the approved browser origin). Reserved for
 *               /api/admin/* (X-Admin-Key/X-Admin-Secret-gated; no
 *               evidenced browser caller of any kind -- see index.js's
 *               handleAdmin() dispatch) and /api/webhooks/* (signature-
 *               verified provider callbacks, never browser-invoked).
 *               Mission classes D/F. Existing auth is unaffected either
 *               way -- see Section 10 of the mission spec: an approved
 *               Origin is not an authenticated identity, and CORS is
 *               never a substitute for X-Admin-Secret/API-key/signature
 *               verification.
 *
 * No Access-Control-Allow-Credentials is ever emitted (see
 * assertNoCredentialsHeader() below) -- intel-gateway authenticates via
 * explicit headers (X-API-Key/X-Sentinel-Key/Authorization/X-Admin-Key/
 * X-Admin-Secret) and a `?api_key=` query param, never cookies, so there
 * is no browser-ambient credential a cross-site page could have silently
 * attached in the first place; PRODUCTION_BROWSER_ORIGINS's exact-match
 * requirement is defense in depth on top of that, not a substitute for it.
 *
 * Dependency-free by design, matching subscription-lifecycle.js/
 * gumroad-lifecycle.js/intel-static-proxy.js's own established pattern
 * (see intel-static-proxy.js's header comment): index.js's full import
 * chain (via pricing.js's pricing-data.json import) fails Node's native
 * ESM loader outside the wrangler/esbuild bundler, so anything that needs
 * a plain `node --test` contract test -- this file's own tests included --
 * has to live outside that chain. No imports in this file, ever.
 */

// Proven via workers/revenue-engine/src/index.js's own already-shipped
// REVENUE_ALLOWED_ORIGINS (isAllowedRevenueOrigin) -- the one production
// browser origin already trusted to call a *different* CYBERDUDEBIVASH
// Worker cross-origin. intel-gateway itself is routed at
// intel.cyberdudebivash.com/{api,reports,taxii,auth}/* (wrangler.toml),
// the same origin index.html itself is served from, so most of its own
// dashboard traffic is same-origin (CORS never applies) -- this allowlist
// exists for the requests that do carry an Origin header regardless (some
// same-origin fetches still send one) and for any future cross-origin
// browser caller of this exact, evidenced production domain. No other
// domain is added here without the same kind of direct evidence: a
// repo-wide search for a second real fetch() caller (see this PR's
// description) found none, so none is invented per the mission's explicit
// "do not invent domains" instruction.
const PRODUCTION_BROWSER_ORIGINS = new Set([
  "https://intel.cyberdudebivash.com",
]);

function isApprovedBrowserOrigin(origin) {
  // Exact Set membership only -- never a prefix/suffix/substring check, so
  // https://intel.cyberdudebivash.com.evil.example and
  // https://evil-intel.cyberdudebivash.com can never match (mission Case 16).
  return typeof origin === "string" && PRODUCTION_BROWSER_ORIGINS.has(origin);
}

// -----------------------------------------------------------------------
// Route classification
// -----------------------------------------------------------------------
// Exact paths only (not prefixes) -- deliberately explicit rather than a
// broad prefix match, so a new route added under /api/v1/intel/ tomorrow
// does NOT silently inherit wildcard-public status; it must be added here
// on purpose. Sourced from index.js's own self-documented 404 handler's
// "available_endpoints" list (the platform's own authoritative statement
// of which endpoints carry no tier/entitlement restriction), cross-checked
// against each route's handler for the absence of an auth/entitlement
// gate, plus intel-static-proxy.js's two routes (INTEL_STATIC_PROXY,
// confirmed unauthenticated GET-only) and the two non-JSON discovery
// routes noted individually below.
//
// Every entry: read-only, no customer/API-key/entitlement/billing/admin
// data, no mutation. GET/HEAD only (enforced in classifyRoute(), not
// re-stated per entry).
const PUBLIC_EXACT_PATHS = new Set([
  "/api/health", "/api/health/",
  "/api/platform/stats",
  "/api/pricing",
  "/api/preview", "/api/preview/",
  "/api/feed", "/api/feed.json",
  "/api/v1/news/feed",
  "/api/v1/intel/latest.json",
  "/api/v1/intel/apex.json",
  "/api/v1/intel/ai_summary.json",
  "/api/v1/intel/top10.json",
  "/api/v1/intel/stats",
  "/api/v1/intel/campaigns",
  "/api/v1/intel/ransomware",
  "/api/v1/intel/apt",
  "/api/v1/intel/epss",
  "/api/v1/intel/defcon",
  "/api/v1/intel/pulse",
  "/api/v1/intel/darkweb",
  "/api/v1/intel/cybermap",
  "/api/v1/intel/ai_index.json",                 // intel-static-proxy.js
  "/api/v1/intel/detection_rules_manifest.json", // intel-static-proxy.js
  "/api/v1/intel/nexus_output.json",             // intel-static-proxy.js
  "/api/v1/intel/genesis_output.json",           // intel-static-proxy.js
  "/api/v1/intel/cortex_output.json",            // intel-static-proxy.js
  "/api/v1/intel/quantum_output.json",           // intel-static-proxy.js
  "/api/v1/intel/sovereign_output.json",         // intel-static-proxy.js
  "/api/v1/ioc/lookup",
  "/api/v1/cve/live",
  "/api/v1/cve/stats",
  "/api/v1/cve/detail",
  "/api/reports/index.json",
  "/api/reports/latest.json",
  "/api/reports/stats.json",
  // P41 capability-discovery surface. Unauthenticated by design -- all three
  // return 200 with no credential of any kind, and p41-handlers.js reads no
  // auth header, tier, or API key, so the body is byte-identical regardless
  // of WHO asks. PUBLIC_CATEGORIES is a hard server-side allowlist
  // (CUSTOMER_UI only): ADMIN/INTERNAL/DEPRECATED entries can never leave
  // these routes whatever a caller requests. Page-inventory metadata only,
  // never intelligence data -- see p41-handlers.js's own header.
  //
  // This classification also makes them edge-cacheable, which is the point:
  // isEdgeCacheableRequest() keys off this bucket, so a BROWSER-bucket route
  // is skipped by index.js's whole-response cache. That coupling is correct
  // and deliberate -- a BROWSER response carries a per-Origin
  // Access-Control-Allow-Origin, and Cloudflare's cache does not vary on
  // arbitrary headers, so caching one would serve one origin's CORS grant to
  // every other origin. A PUBLIC response carries "*", which is
  // origin-invariant and therefore safe to store.
  //
  // /capability is ?id=-driven, which is safe here: index.js caches on the
  // FULL request (path + query, per its own cache-key comment), so two ids
  // never collide, and only status 200 is ever stored -- the 400 (missing
  // id) and 404 (unknown/non-public id) paths are never cached.
  "/api/v1/p41/capabilities",
  "/api/v1/p41/capability",
  "/api/v1/p41/observability",
]);

// Bare TAXII 2.1 server-discovery root only -- per index.js's own comment
// at its auth-error-skip list: "handleTAXII's own server-discovery route,
// public per the TAXII 2.1 spec -- only /taxii/collections/... and beyond
// require PRO/ENTERPRISE." Deliberately NOT a prefix match against
// "/taxii" alone, so /taxii/collections/* (tiered) never matches this.
const PUBLIC_TAXII_ROOTS = new Set(["/taxii", "/taxii/"]);

// Bare HTML intelligence report pages (serveHtmlIntelReport(), routed at
// index.js's `path.startsWith("/reports/")`) -- distinct from the
// /api/reports/* JSON API above. Confirmed public: the repo's own root
// _headers file marks this exact path prefix "X-Intel-Classification:
// TLP-CLEAR" (Traffic Light Protocol "Clear" = intended for public
// release) with public caching, and it's a customer-facing marketing/SEO
// surface, not an authenticated API. GET only (HTML page serving).
const PUBLIC_REPORTS_PREFIX = "/reports/";

// /api/admin/* -- every sub-route (audit, cache/bust[-prefix], health,
// keys, publication-audit) dispatches through index.js's single
// handleAdmin(path.startsWith("/api/admin")), gated by X-Admin-Key/
// X-Admin-Secret + timingSafeEqual(), never by Origin. No evidenced
// browser-dashboard caller anywhere in this repo (confirmed by this PR's
// own repo-wide audit). Mission Section 3D: "Admin routes should not be
// generally browser-cross-origin accessible ... unless a proven
// production browser caller requires it" -- none is proven, so none is
// granted, even for PRODUCTION_BROWSER_ORIGINS.
const INTERNAL_PREFIXES = ["/api/admin"];

// Payment-provider webhook callbacks -- signature-verified
// (X-Razorpay-Signature HMAC / Gumroad ?secret= timingSafeEqual against
// GUMROAD_WEBHOOK_SECRET), server-to-server only, never browser-invoked.
// Mission Section 3F: webhook security must never depend on or expose
// browser CORS authorization.
const INTERNAL_EXACT_PATHS = new Set([
  "/api/webhooks/razorpay",
  "/api/webhooks/gumroad",
]);

const READ_ONLY_METHODS = new Set(["GET", "HEAD"]);

/**
 * @param {string} path
 * @param {string} method
 * @returns {{bucket: "PUBLIC"|"BROWSER"|"INTERNAL"}}
 */
function classifyRoute(path, method) {
  if (INTERNAL_EXACT_PATHS.has(path) || INTERNAL_PREFIXES.some((p) => path.startsWith(p))) {
    return { bucket: "INTERNAL" };
  }
  if (PUBLIC_TAXII_ROOTS.has(path) || path.startsWith(PUBLIC_REPORTS_PREFIX)) {
    return READ_ONLY_METHODS.has(method) ? { bucket: "PUBLIC" } : { bucket: "BROWSER" };
  }
  if (PUBLIC_EXACT_PATHS.has(path)) {
    // A public route only stays wildcard-open for the read methods it's
    // documented for -- an unexpected POST/PUT/DELETE against one of
    // these (none currently accept one; defense in depth if that ever
    // changes) falls back to the exact-origin-or-nothing policy instead
    // of silently inheriting "*" for a method nobody classified.
    return READ_ONLY_METHODS.has(method) ? { bucket: "PUBLIC" } : { bucket: "BROWSER" };
  }
  return { bucket: "BROWSER" };
}

// -----------------------------------------------------------------------
// Preflight method/header advertisement
// -----------------------------------------------------------------------
// Mission Section 5: "Only advertise methods actually supported by the
// target route/trust class... Do not globally advertise DELETE, PUT,
// Authorization, X-Admin-Key, X-Admin-Secret unless the target route
// genuinely requires them." intel-gateway's BROWSER-class surface spans
// hundreds of routes with heterogeneous methods (confirmed via repo-wide
// method literal search: GET/POST/PUT/DELETE/PATCH all appear), so a
// single fixed list is the practical middle ground at this scale -- but it
// already excludes X-Admin-Key/X-Admin-Secret (INTERNAL-class routes never
// reach this function at all; see buildPreflightResponse()) and PATCH
// (no BROWSER-class route in intel-gateway uses it -- confirmed via
// repo-wide grep; only revenue-engine's separate CRM surface does).
const BROWSER_METHODS = ["GET", "POST", "PUT", "DELETE"];
const BROWSER_HEADERS = ["Content-Type", "Authorization", "X-API-Key", "X-Sentinel-Key"];
const PUBLIC_METHODS = ["GET", "HEAD"];
const PUBLIC_HEADERS = ["Content-Type"];

function methodAllowed(list, method) {
  return typeof method === "string" && list.includes(method.toUpperCase());
}

function headersAllowed(requested, allowedList) {
  if (!requested) return true;
  const allowedLower = new Set(allowedList.map((h) => h.toLowerCase()));
  return requested
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean)
    .every((h) => allowedLower.has(h));
}

// Headers.append() always adds a new value, even if the exact token is
// already present -- calling this twice on the same response (index.js's
// own POST-MERGE FIX comment on withBaselineHeaders() documents exactly
// how that happened live: an OPTIONS response already carrying "Vary:
// Origin" from buildPreflightResponse() got run through applyCorsPolicy()
// a second time) would otherwise produce "Vary: Origin, Origin". Fixed at
// the root cause there (that second call no longer happens), but this
// function is kept idempotent as defense in depth -- correct no matter how
// many times, or in what order, it's ever called on the same response.
function addVaryOrigin(headers) {
  const existing = headers.get("Vary");
  if (!existing) {
    headers.set("Vary", "Origin");
    return;
  }
  const tokens = existing.split(",").map((t) => t.trim());
  if (!tokens.includes("Origin")) headers.append("Vary", "Origin");
}

/**
 * The final, authoritative Access-Control-Allow-Origin / Vary decision for
 * a non-OPTIONS response. Never used to gate whether the route's own
 * business logic runs -- see this file's header comment and mission
 * Section 10: CORS decides browser readability of a response that auth/
 * entitlement/quota logic already decided how to answer.
 *
 * @returns {{acao: string|null, vary: boolean}}
 */
function resolveCorsForRoute(request, path, method) {
  const trust = classifyRoute(path, method);
  if (trust.bucket === "PUBLIC") {
    return { acao: "*", vary: false };
  }
  if (trust.bucket === "INTERNAL") {
    return { acao: null, vary: false };
  }
  const origin = request.headers.get("Origin");
  if (isApprovedBrowserOrigin(origin)) {
    return { acao: origin, vary: true };
  }
  // No Origin (machine client) or an unapproved Origin: no cross-origin
  // grant either way, but Vary: Origin is still correct here -- a cache
  // sitting in front of this response must not serve one Origin's
  // (non-)grant to a different Origin that would have qualified.
  return { acao: null, vary: true };
}

/**
 * Applies the single authoritative CORS decision to an already-built
 * response, without touching any other header (Content-Type, Cache-
 * Control, X-Sentinel-* etc. are left exactly as the handler set them).
 * Call this once, at the outermost response choke point -- see index.js's
 * withBaselineHeaders(), the only call site.
 */
function applyCorsPolicy(response, request, path, method) {
  const { acao, vary } = resolveCorsForRoute(request, path, method);
  const headers = new Headers(response.headers);
  if (acao) headers.set("Access-Control-Allow-Origin", acao);
  else headers.delete("Access-Control-Allow-Origin");
  // Never emitted by this platform (no cookie/credentialed fetch anywhere
  // in intel-gateway -- see this file's header comment); deleted rather
  // than merely "never set" so a future accidental addition anywhere
  // upstream of this function can never survive to the actual response.
  headers.delete("Access-Control-Allow-Credentials");
  if (vary) addVaryOrigin(headers);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

/**
 * Strict, route-aware preflight (OPTIONS) response. Never executes any
 * route business logic -- this is the entire handler for an OPTIONS
 * request (see index.js's "CORS preflight" branch, the only call site).
 *
 * Denial is a plain 403 with no Access-Control-* headers at all, for
 * every failure mode (unapproved/absent-on-a-browser-class-route Origin,
 * unsupported method, unsupported header, INTERNAL-class route) --
 * deterministic and uniform rather than leaking which specific check
 * failed.
 */
function buildPreflightResponse(request, path) {
  const origin = request.headers.get("Origin");
  const requestedMethod = request.headers.get("Access-Control-Request-Method");
  const requestedHeaders = request.headers.get("Access-Control-Request-Headers");

  // classifyRoute()'s method argument only affects the PUBLIC-vs-BROWSER
  // split for routes that are read-only-only (see its own comment) --
  // pass the *requested* cross-origin method here (falling back to GET)
  // so a route that's public for GET but would reject POST is classified
  // by what the caller is actually asking to send, not by "OPTIONS".
  const trust = classifyRoute(path, requestedMethod || "GET");

  if (trust.bucket === "INTERNAL") {
    return new Response(null, { status: 403 });
  }

  if (trust.bucket === "PUBLIC") {
    if (requestedMethod && !methodAllowed(PUBLIC_METHODS, requestedMethod)) {
      return new Response(null, { status: 403 });
    }
    if (!headersAllowed(requestedHeaders, PUBLIC_HEADERS)) {
      return new Response(null, { status: 403 });
    }
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": PUBLIC_METHODS.join(", "),
        "Access-Control-Allow-Headers": PUBLIC_HEADERS.join(", "),
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // BROWSER bucket: only an exact approved Origin, with a method and
  // header set the route's trust class actually supports, gets a grant.
  if (!isApprovedBrowserOrigin(origin)) {
    return new Response(null, { status: 403, headers: { Vary: "Origin" } });
  }
  if (requestedMethod && !methodAllowed(BROWSER_METHODS, requestedMethod)) {
    return new Response(null, { status: 403, headers: { Vary: "Origin" } });
  }
  if (!headersAllowed(requestedHeaders, BROWSER_HEADERS)) {
    return new Response(null, { status: 403, headers: { Vary: "Origin" } });
  }
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": BROWSER_METHODS.join(", "),
      "Access-Control-Allow-Headers": BROWSER_HEADERS.join(", "),
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    },
  });
}

export {
  PRODUCTION_BROWSER_ORIGINS,
  isApprovedBrowserOrigin,
  classifyRoute,
  resolveCorsForRoute,
  applyCorsPolicy,
  buildPreflightResponse,
};
