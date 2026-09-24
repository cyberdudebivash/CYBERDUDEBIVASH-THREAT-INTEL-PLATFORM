import assert from "node:assert/strict";
import { test } from "node:test";
import {
  isApprovedBrowserOrigin,
  classifyRoute,
  resolveCorsForRoute,
  applyCorsPolicy,
  buildPreflightResponse,
} from "../cors-policy.js";

// ---------------------------------------------------------------------------
// SENTINEL APEX PUBLIC-REPO ZERO-TRUST -- PHASE 3: authenticated CORS +
// cross-origin trust-boundary hardening. Mission test matrix (16 cases),
// each case labeled with its number below. cors-policy.js is dependency-
// free by design (see its own header comment) specifically so this suite
// can run under plain `node --test` without pulling in index.js's full
// import chain -- it tests the CORS decision layer in isolation from
// auth/entitlement, which is the point: mission Section 10 requires CORS
// and AuthN/AuthZ to be independent, composable controls, so this file
// never constructs an `auth` object or asserts on response bodies/status
// codes decided by authentication -- only on Access-Control-*/Vary.
// ---------------------------------------------------------------------------

const APPROVED = "https://intel.cyberdudebivash.com";
const EVIL = "https://evil.example";

function req(url, headers = {}) {
  return new Request(url, { headers });
}

function okResponse(body = { ok: true }) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

// -- Case 1: public anonymous GET, arbitrary legitimate Internet origin -----
test("Case 1: public route + arbitrary origin -> documented public wildcard policy", () => {
  const r = req("https://intel.cyberdudebivash.com/api/feed.json", { Origin: "https://some-random-site.example" });
  const { acao, vary } = resolveCorsForRoute(r, "/api/feed.json", "GET");
  assert.equal(acao, "*");
  assert.equal(vary, false); // wildcard doesn't depend on Origin -- no cache-poisoning surface to Vary against
  assert.equal(classifyRoute("/api/feed.json", "GET").bucket, "PUBLIC");
});

// -- Case 2: authenticated/customer endpoint, approved origin ---------------
test("Case 2: customer endpoint + approved origin -> exact ACAO, Vary: Origin present", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", { Origin: APPROVED });
  const { acao, vary } = resolveCorsForRoute(r, "/api/v1/p33/dashboard", "GET");
  assert.equal(acao, APPROVED);
  assert.equal(vary, true);
  const applied = applyCorsPolicy(okResponse(), r, "/api/v1/p33/dashboard", "GET");
  assert.equal(applied.headers.get("Access-Control-Allow-Origin"), APPROVED);
  assert.equal(applied.headers.get("Vary"), "Origin");
});

// -- Case 3: authenticated/customer endpoint, hostile origin ----------------
test("Case 3: customer endpoint + evil.example -> denied, never wildcard, never reflected", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", { Origin: EVIL });
  const { acao } = resolveCorsForRoute(r, "/api/v1/p33/dashboard", "GET");
  assert.equal(acao, null);
  assert.notEqual(acao, "*");
  assert.notEqual(acao, EVIL);
});

// -- Case 4: authenticated machine client, no Origin, valid API key ---------
test("Case 4: no Origin header at all (curl/PowerShell/Python/SIEM/SOAR/TAXII) -> unaffected, not denied", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard"); // no Origin header
  const { acao } = resolveCorsForRoute(r, "/api/v1/p33/dashboard", "GET");
  assert.equal(acao, null); // no CORS grant needed -- but critically:
  const applied = applyCorsPolicy(okResponse({ data: "real" }), r, "/api/v1/p33/dashboard", "GET");
  assert.equal(applied.status, 200); // request itself is NEVER rejected for lacking Origin
  assert.equal(applied.headers.get("Access-Control-Allow-Origin"), null); // no grant, but also no denial
});

// -- Case 5: invalid API key, approved Origin -- CORS must never bypass AuthN
test("Case 5: CORS grant is independent of auth outcome -- approved Origin still gets exact ACAO regardless", () => {
  // cors-policy.js has no concept of "valid" or "invalid" API key -- it
  // only ever looks at path/method/Origin. This is the point: whatever
  // index.js's resolveAuth()/resolveEntitlement() decide about the
  // credential (a 401 body, a 200 body) is untouched by this module: it
  // still receives the exact same CORS treatment either way, proving one
  // can never substitute for or weaken the other (mission Section 10).
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", { Origin: APPROVED, "X-API-Key": "not-a-real-key" });
  const { acao } = resolveCorsForRoute(r, "/api/v1/p33/dashboard", "GET");
  assert.equal(acao, APPROVED);
  const unauthorizedBody = new Response(JSON.stringify({ error: "invalid_key" }), { status: 401 });
  const applied = applyCorsPolicy(unauthorizedBody, r, "/api/v1/p33/dashboard", "GET");
  assert.equal(applied.status, 401); // CORS did not change the auth outcome
  assert.equal(applied.headers.get("Access-Control-Allow-Origin"), APPROVED); // but still applies its own policy
});

// -- Case 6: admin endpoint, untrusted origin --------------------------------
test("Case 6: admin endpoint + untrusted origin -> denied, no cross-origin authorization", () => {
  const r = req("https://intel.cyberdudebivash.com/api/admin/keys", { Origin: EVIL });
  assert.equal(classifyRoute("/api/admin/keys", "POST").bucket, "INTERNAL");
  const { acao } = resolveCorsForRoute(r, "/api/admin/keys", "POST");
  assert.equal(acao, null);
});

// -- Case 7: admin endpoint, no Origin + valid authorized machine request ---
test("Case 7: admin endpoint + no Origin -> existing auth semantics preserved, CORS layer inert", () => {
  const r = req("https://intel.cyberdudebivash.com/api/admin/health"); // no Origin
  const applied = applyCorsPolicy(okResponse({ status: "ok" }), r, "/api/admin/health", "GET");
  assert.equal(applied.status, 200);
  assert.equal(applied.headers.get("Access-Control-Allow-Origin"), null);
});

// -- Case 7b: admin endpoint + the APPROVED browser origin -- still denied --
test("Case 7b: admin endpoint never grants ACAO even to the approved production origin (Section 3D)", () => {
  const r = req("https://intel.cyberdudebivash.com/api/admin/audit", { Origin: APPROVED });
  const { acao } = resolveCorsForRoute(r, "/api/admin/audit", "GET");
  assert.equal(acao, null); // INTERNAL bucket: no evidenced browser caller, so no grant at all
});

// -- Case 8: webhook, no Origin, valid signature/test fixture ---------------
test("Case 8: webhook + no Origin -> normal server-to-server processing unaffected", () => {
  const r = req("https://intel.cyberdudebivash.com/api/webhooks/razorpay"); // no Origin
  assert.equal(classifyRoute("/api/webhooks/razorpay", "POST").bucket, "INTERNAL");
  const applied = applyCorsPolicy(okResponse({ received: true }), r, "/api/webhooks/razorpay", "POST");
  assert.equal(applied.status, 200);
});

// -- Case 9: webhook, browser Origin -----------------------------------------
test("Case 9: webhook + browser Origin -> no accidental generic browser authorization", () => {
  const r = req("https://intel.cyberdudebivash.com/api/webhooks/gumroad", { Origin: EVIL });
  const { acao } = resolveCorsForRoute(r, "/api/webhooks/gumroad", "POST");
  assert.equal(acao, null);
  const rApproved = req("https://intel.cyberdudebivash.com/api/webhooks/gumroad", { Origin: APPROVED });
  assert.equal(resolveCorsForRoute(rApproved, "/api/webhooks/gumroad", "POST").acao, null); // not even the approved origin
});

// -- Case 10: preflight, approved origin + valid method/header --------------
test("Case 10: preflight, approved origin + supported method/header -> 204 with exact-origin grant", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", {
    Origin: APPROVED,
    "Access-Control-Request-Method": "GET",
    "Access-Control-Request-Headers": "x-api-key, content-type",
  });
  const res = buildPreflightResponse(r, "/api/v1/p33/dashboard");
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("Access-Control-Allow-Origin"), APPROVED);
  assert.match(res.headers.get("Access-Control-Allow-Methods") || "", /GET/);
});

// -- Case 11: preflight, unapproved origin -----------------------------------
test("Case 11: preflight, unapproved origin -> fail closed (403, no ACAO)", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", {
    Origin: EVIL,
    "Access-Control-Request-Method": "GET",
  });
  const res = buildPreflightResponse(r, "/api/v1/p33/dashboard");
  assert.equal(res.status, 403);
  assert.equal(res.headers.get("Access-Control-Allow-Origin"), null);
});

// -- Case 12: preflight, unsupported method ----------------------------------
test("Case 12: preflight requesting an unsupported method -> deny even for the approved origin", () => {
  const r = req("https://intel.cyberdudebivash.com/api/admin/keys", {
    Origin: APPROVED,
    "Access-Control-Request-Method": "TRACE",
  });
  const res = buildPreflightResponse(r, "/api/admin/keys"); // INTERNAL bucket denies regardless
  assert.equal(res.status, 403);

  // /api/feed.json is only classified PUBLIC for its documented GET/HEAD
  // methods (see classifyRoute()'s own comment) -- requesting PATCH here
  // reclassifies it into the BROWSER bucket instead, and PATCH isn't in
  // that bucket's advertised method list either, so it's still denied,
  // even for the approved origin.
  const r2 = req("https://intel.cyberdudebivash.com/api/feed.json", {
    Origin: APPROVED,
    "Access-Control-Request-Method": "PATCH",
  });
  const res2 = buildPreflightResponse(r2, "/api/feed.json");
  assert.equal(res2.status, 403);
});

// -- Case 13: preflight, unauthorized header ---------------------------------
test("Case 13: preflight requesting a disallowed header -> deny (e.g. X-Admin-Secret on a customer route)", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", {
    Origin: APPROVED,
    "Access-Control-Request-Method": "GET",
    "Access-Control-Request-Headers": "x-admin-secret",
  });
  const res = buildPreflightResponse(r, "/api/v1/p33/dashboard");
  assert.equal(res.status, 403);
});

// -- Case 14: Origin: null ----------------------------------------------------
test("Case 14: Origin: null (sandboxed iframe / file: context) -> deny, no evidenced reason to support it", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", { Origin: "null" });
  assert.equal(isApprovedBrowserOrigin("null"), false);
  const { acao } = resolveCorsForRoute(r, "/api/v1/p33/dashboard", "GET");
  assert.equal(acao, null);
});

// -- Case 15: malformed Origin ------------------------------------------------
test("Case 15: malformed Origin values -> deny", () => {
  for (const bad of ["not-a-url", "intel.cyberdudebivash.com", "http:/intel.cyberdudebivash.com", ""]) {
    assert.equal(isApprovedBrowserOrigin(bad), false, `expected "${bad}" to be rejected`);
  }
});

// -- Case 16: hostname-suffix / spoof attempts -- exact URL-origin equality --
test("Case 16: suffix/prefix spoof attempts on the approved domain -> deny via exact-match, never substring", () => {
  const spoofs = [
    "https://intel.cyberdudebivash.com.evil.example",
    "https://evil-intel.cyberdudebivash.com",
    "https://intel.cyberdudebivash.com:8443", // different origin (port is part of the origin tuple)
    "http://intel.cyberdudebivash.com", // different scheme
    "https://INTEL.CYBERDUDEBIVASH.COM", // case: browsers always send lowercase, but never trust case-folding here
  ];
  for (const spoof of spoofs) {
    assert.equal(isApprovedBrowserOrigin(spoof), false, `expected "${spoof}" to be rejected`);
  }
  assert.equal(isApprovedBrowserOrigin(APPROVED), true); // sanity: the real origin still matches
});

// -- Additional coverage: credentials, method-scoping, route-default --------
test("Access-Control-Allow-Credentials is never emitted, even if an upstream response somehow set it", () => {
  const upstream = new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Credentials": "true" },
  });
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", { Origin: APPROVED });
  const applied = applyCorsPolicy(upstream, r, "/api/v1/p33/dashboard", "GET");
  assert.equal(applied.headers.get("Access-Control-Allow-Credentials"), null);
});

test("a public route only stays wildcard for its documented read methods -- POST falls back to exact-origin policy", () => {
  const r = req("https://intel.cyberdudebivash.com/api/feed.json", { Origin: APPROVED });
  assert.equal(classifyRoute("/api/feed.json", "POST").bucket, "BROWSER");
  assert.equal(resolveCorsForRoute(r, "/api/feed.json", "POST").acao, APPROVED);
});

test("an unrecognized /api path defaults to the restrictive BROWSER bucket, never PUBLIC or a silent pass-through", () => {
  // Mission: "No route may silently fall through into a generic permissive
  // policy." A brand-new route nobody has classified yet must default to
  // the safe (exact-origin-or-nothing) bucket, not wildcard.
  const bucket = classifyRoute("/api/v1/p99/some-future-route", "GET").bucket;
  assert.equal(bucket, "BROWSER");
});

test("bare TAXII discovery root is public, but /taxii/collections/* (PRO/ENTERPRISE) is not", () => {
  assert.equal(classifyRoute("/taxii/", "GET").bucket, "PUBLIC");
  assert.equal(classifyRoute("/taxii/collections/", "GET").bucket, "BROWSER");
});

// -- Post-merge fix: applyCorsPolicy() must be idempotent on Vary ----------
// Found via this PR's own required live-production verification: index.js's
// OPTIONS branch (buildPreflightResponse()) already sets "Vary: Origin",
// and withBaselineHeaders() used to unconditionally re-run applyCorsPolicy()
// on every response including that one, producing a live
// "Vary: Origin, Origin". Fixed at the root cause in index.js (OPTIONS
// responses no longer get a second pass), but applyCorsPolicy() itself is
// also hardened here so calling it twice on the same response -- by
// accident, or from a future call site -- can never reproduce the bug.
test("applyCorsPolicy() calling twice on the same response never duplicates the Vary token", () => {
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", { Origin: APPROVED });
  const once = applyCorsPolicy(okResponse(), r, "/api/v1/p33/dashboard", "GET");
  assert.equal(once.headers.get("Vary"), "Origin");
  const twice = applyCorsPolicy(once, r, "/api/v1/p33/dashboard", "GET");
  assert.equal(twice.headers.get("Vary"), "Origin"); // not "Origin, Origin"
});

test("applyCorsPolicy() preserves an unrelated existing Vary token instead of overwriting it", () => {
  const withAcceptVary = new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { "Content-Type": "application/json", "Vary": "Accept-Encoding" },
  });
  const r = req("https://intel.cyberdudebivash.com/api/v1/p33/dashboard", { Origin: APPROVED });
  const applied = applyCorsPolicy(withAcceptVary, r, "/api/v1/p33/dashboard", "GET");
  const tokens = applied.headers.get("Vary").split(",").map((t) => t.trim());
  assert.ok(tokens.includes("Accept-Encoding"));
  assert.ok(tokens.includes("Origin"));
  assert.equal(tokens.length, 2); // each token exactly once
});

// ---------------------------------------------------------------------------
// P41 capability-discovery surface -- PUBLIC classification.
//
// These three routes were BROWSER-bucketed, which had a measurable production
// cost: isEdgeCacheableRequest() keys off this bucket, so index.js's
// whole-response edge cache skipped them entirely. Live samples put
// /api/v1/p41/capabilities (16 KB) at a ~0.81s median TTFB against /api/feed
// (1.2 MB) at 0.25s over the identical path.
//
// They are genuinely public: 200 unauthenticated, no auth header/tier/API key
// read anywhere in p41-handlers.js, and PUBLIC_CATEGORIES hard-filters to
// CUSTOMER_UI server-side. See the allowlist comment in cors-policy.js.
// ---------------------------------------------------------------------------

const P41_PUBLIC_ROUTES = [
  "/api/v1/p41/capabilities",
  "/api/v1/p41/capability",
  "/api/v1/p41/observability",
];

test("P41 discovery routes classify PUBLIC for their documented read methods", () => {
  for (const path of P41_PUBLIC_ROUTES) {
    assert.equal(classifyRoute(path, "GET").bucket, "PUBLIC", `${path} GET`);
    assert.equal(classifyRoute(path, "HEAD").bucket, "PUBLIC", `${path} HEAD`);
  }
});

test("P41 discovery routes serve an origin-invariant wildcard -- the property that makes them safe to edge-cache", () => {
  for (const path of P41_PUBLIC_ROUTES) {
    const r = req(`https://intel.cyberdudebivash.com${path}`, { Origin: EVIL });
    const { acao, vary } = resolveCorsForRoute(r, path, "GET");
    // Wildcard, not a reflected origin: one cached response is correct for
    // every caller. A reflected ACAO here would make caching unsafe.
    assert.equal(acao, "*", `${path} ACAO`);
    assert.equal(vary, false, `${path} Vary`);
    const applied = applyCorsPolicy(okResponse(), r, path, "GET");
    assert.equal(applied.headers.get("Access-Control-Allow-Origin"), "*");
    // A wildcard must never pair with credentials.
    assert.equal(applied.headers.get("Access-Control-Allow-Credentials"), null);
  }
});

test("P41 discovery routes fall back to BROWSER for non-read methods", () => {
  for (const path of P41_PUBLIC_ROUTES) {
    assert.equal(classifyRoute(path, "POST").bucket, "BROWSER", `${path} POST`);
    assert.equal(classifyRoute(path, "DELETE").bucket, "BROWSER", `${path} DELETE`);
  }
});

test("the P41 allowlist is exact, not a /api/v1/p41 prefix -- an unlisted sibling stays BROWSER", () => {
  // Regression guard: if these entries are ever converted to a prefix match,
  // a future /api/v1/p41/* route would be silently born PUBLIC and
  // edge-cacheable without anyone classifying it.
  assert.equal(classifyRoute("/api/v1/p41/admin", "GET").bucket, "BROWSER");
  assert.equal(classifyRoute("/api/v1/p41/capabilities/internal", "GET").bucket, "BROWSER");
});

test("this change is scoped to P41 only -- other P-layer routes are untouched", () => {
  // P40's source-fabric is auth-gated (returns 401 unauthenticated) and must
  // not have been swept into PUBLIC alongside P41.
  assert.equal(classifyRoute("/api/v1/p40/source-fabric", "GET").bucket, "BROWSER");
  assert.equal(classifyRoute("/api/v1/p40/observability", "GET").bucket, "BROWSER");
  assert.equal(classifyRoute("/api/v1/p33/dashboard", "GET").bucket, "BROWSER");
});

test("Cyber Watchdog offer is public; the tiered brief is not", () => {
  assert.equal(classifyRoute("/api/watchdog/offer", "GET").bucket, "PUBLIC");
  assert.equal(classifyRoute("/api/watchdog/health", "GET").bucket, "PUBLIC");
  assert.equal(classifyRoute("/api/watchdog/brief", "GET").bucket, "BROWSER");
  assert.equal(classifyRoute("/api/watchdog/watches", "GET").bucket, "BROWSER");
  assert.equal(classifyRoute("/api/watchdog/events", "GET").bucket, "BROWSER");
  assert.equal(classifyRoute("/api/watchdog/destinations", "POST").bucket, "BROWSER");
  assert.equal(classifyRoute("/api/watchdog/deploy", "GET").bucket, "BROWSER");
});
