// =============================================================================
// CYBERDUDEBIVASH SENTINEL APEX -- First-Party Web Read Plane
//
// Small, dependency-free module (same reason daily-quota.js and
// subscription-lifecycle.js are ones: index.js's full import chain fails
// Node's native ESM loader outside the wrangler/esbuild bundler via
// pricing.js's pricing-data.json import) so this pure decision logic can be
// unit-tested directly with `node --test`.
//
// -----------------------------------------------------------------------------
// WHY THIS EXISTS -- P0 incident 2026-09-03
// -----------------------------------------------------------------------------
// Before this module the gateway had exactly ONE entitlement plane. Every
// request that was not /api/health passed through checkRateLimit() (FREE =
// 30/minute, RATE_LIMITS at index.js:184) and checkDailyQuota() (FREE =
// 50/day, DAILY_QUOTAS in daily-quota.js), both keyed by
// `auth.key || ip` -- which for an anonymous browser is the raw client IP.
//
// The public customer dashboard at https://intel.cyberdudebivash.com/ is
// itself an anonymous, unauthenticated consumer of that same plane. A single
// render of the homepage issues 27 requests to /api/* (measured in a real
// Chromium against production -- see
// docs/incidents/P0-PRODUCTION-REQUEST-MATRIX.md). So:
//
//   * 27 of the FREE tier's 30 requests/minute are spent rendering the page
//     ONCE. A refresh, the built-in auto-refresh, or a second browser tab
//     within the same minute exceeds the per-minute limit.
//   * 27 of the FREE tier's 50 requests/day are spent per render. The SECOND
//     page view of the day (54 > 50) exhausts the daily quota, and every
//     subsequent request from that IP is denied with
//     `daily_quota_exceeded` until the next UTC midnight.
//   * Every anonymous visitor behind one NAT/corporate egress shares one IP,
//     so they share -- and collectively exhaust -- a single 50/day budget.
//
// The dashboard then had no authoritative intelligence to render, and its
// frontend collapsed that infrastructure denial into an empty feed. The
// customer-visible result was "SYNC: LOADING / NO DATA / LIVE 0" while
// /api/health simultaneously reported 500 healthy advisories -- /api/health
// being the one path the gate exempts.
//
// -----------------------------------------------------------------------------
// THE SEPARATION
// -----------------------------------------------------------------------------
// Commercial API quotas are legitimate product controls and are NOT disabled
// or raised by this module. Instead the two trust domains that were being
// conflated are separated:
//
//   COMMERCIAL API PLANE  -- any request carrying a credential (X-API-Key,
//     Authorization: Bearer, ?api_key=, X-Sentinel-Key). Unchanged: the
//     existing per-tier RATE_LIMITS and DAILY_QUOTAS apply exactly as before.
//     A FREE-tier API customer still gets 30/min and 50/day. This is the
//     plane the pricing page sells.
//
//   FIRST-PARTY WEB READ PLANE -- an anonymous (no credential presented),
//     GET/HEAD request for one of the specific public, read-only endpoints
//     the first-party dashboard needs in order to render itself. These get
//     their own dedicated anonymous-web budget (WEB_PLANE_LIMITS below),
//     sized for a human browsing a web page rather than for an application
//     consuming an API product.
//
// Presenting a credential always routes a request to the commercial plane,
// including on these paths -- so no API customer can reach the web plane's
// budget by calling a dashboard endpoint, and quota enforcement for
// credentialed FREE/PRO/ENTERPRISE callers is bit-for-bit unchanged.
//
// This is a dedicated anonymous web quota, not an exemption: abuse and DDoS
// protection are preserved, just at a ceiling appropriate to page rendering.
// At 27 requests per render, WEB_PLANE_LIMITS permits roughly 8 renders per
// minute and roughly 74 per UTC day from a single IP, after which the web
// plane throttles exactly like the commercial one.
//
// -----------------------------------------------------------------------------
// WHY AN EXPLICIT PATH SET AND NOT A PREFIX
// -----------------------------------------------------------------------------
// Membership is an exact-match allowlist, deliberately not a `/api/v1/intel/`
// prefix. A prefix would silently enrol any future route added under it into
// the web plane -- including a premium one -- which is precisely the kind of
// implicit entitlement drift that caused this incident. Failing closed to the
// existing commercial behavior for anything not listed is the secure default
// (Principle 9). The cost is that a genuinely new dashboard endpoint must be
// added here explicitly; `/api/observability/first-party-plane` exposes the
// live set so that drift is observable rather than silent.
//
// Note on the two PREMIUM_INTEL_PATHS entries (/api/v1/intel/apex.json and
// /api/v1/intel/ai_summary.json) that appear in this set: membership here
// governs ONLY which rate-limit/quota plane the request is metered against.
// It does not touch tier masking -- those routes' own premium-field masking
// runs downstream, unchanged, and an anonymous caller keeps receiving exactly
// the masked free view it received before.
// =============================================================================

/**
 * Dedicated anonymous-web budget. Deliberately expressed in the same shape as
 * RATE_LIMITS (per minute) and DAILY_QUOTAS (per UTC day) so the two planes
 * stay directly comparable when read side by side.
 *
 * Sizing rationale -- one measured dashboard render costs 27 requests:
 *   perMinute 240  -> ~8 renders/minute from one IP (covers a hard refresh,
 *                     the page's own auto-refresh, several open tabs, and a
 *                     modest NAT'd office) before throttling.
 *   perDay   2000  -> ~74 renders/day from one IP. A shared corporate egress
 *                     stays comfortably inside this; a scripted scraper does
 *                     not.
 */
export const WEB_PLANE_LIMITS = Object.freeze({
  perMinute: 240,
  perDay: 2000,
});

/**
 * The exact public, read-only endpoints the first-party dashboard requests in
 * order to render itself. Derived from a real-Chromium capture of every
 * request https://intel.cyberdudebivash.com/ issues during startup -- see
 * docs/incidents/P0-PRODUCTION-REQUEST-MATRIX.md for the full matrix and the
 * consuming script for each entry.
 *
 * Every path here is already publicly readable without a credential today;
 * this set does not grant access to anything that was not already reachable
 * anonymously. It only decides which budget the request is metered against.
 */
export const FIRST_PARTY_READ_PATHS = Object.freeze(new Set([
  // --- primary intelligence feed (index.html loadGOCIntel MANIFEST_URLS) ---
  "/api/feed.json",
  "/api/preview",
  "/api/preview/",
  "/api/v1/intel/latest.json",
  "/api/v1/intel/apex.json",
  // --- KPI / metric strip ---
  "/api/v1/intel/stats",
  "/api/metrics",
  "/api/platform/stats",
  "/api/status.json",
  // --- dashboard widgets (js/sentinel-live-feeds.js) ---
  "/api/v1/intel/ai_summary.json",
  "/api/v1/intel/ai_index.json",
  "/api/v1/intel/detection_rules_manifest.json",
  "/api/v1/intel/defcon",
  "/api/v1/intel/cybermap",
  "/api/v1/intel/pulse",
  "/api/v1/intel/ransomware",
  "/api/v1/intel/apt",
  "/api/v1/intel/epss",
  "/api/v1/intel/campaigns",
  "/api/v1/intel/darkweb",
  "/api/v1/ioc/lookup",
  // --- CVE tracker ---
  "/api/v1/cve/live",
  "/api/v1/cve/detail",
  // --- news + reports strips ---
  "/api/v1/news/feed",
  "/api/news/feed",
  "/api/ai/tracker.json",
  "/api/reports/index.json",
  "/api/reports/latest.json",
  "/api/reports/stats.json",
  // --- capability discovery (js/capability-discovery.js) ---
  "/api/capabilities",
  // Cyber Watchdog public read. Anonymous brief is redacted. A credentialed
  // caller is not on this plane (isFirstPartyRead requires no credential).
  "/api/watchdog/offer",
  "/api/watchdog/brief",
  "/api/watchdog/health",
]));

/**
 * Normalize a pathname for membership testing: strips a single trailing
 * slash so `/api/v1/intel/stats/` matches `/api/v1/intel/stats`, while
 * leaving the two entries that are genuinely registered both ways
 * (`/api/preview` and `/api/preview/`) working either way. Bare "/" is
 * returned unchanged rather than collapsed to "".
 */
export function normalizePlanePath(path) {
  if (typeof path !== "string" || path === "") return "";
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

/**
 * Decide whether a request belongs to the first-party web read plane.
 *
 * All four conditions must hold. Any one of them failing routes the request
 * to the existing commercial plane with its behavior completely unchanged:
 *
 *   1. No credential was presented. A credentialed caller is an API customer
 *      and is metered against the tier they pay for, on every path.
 *   2. The method is GET or HEAD. The web plane is read-only; nothing that
 *      mutates state can reach it.
 *   3. The path is in FIRST_PARTY_READ_PATHS (exact match after trailing-slash
 *      normalization). Anything else falls through, closed, to commercial.
 *
 * @param {{path: string, method: string, hasCredential: boolean}} req
 * @returns {boolean}
 */
export function isFirstPartyRead(req) {
  if (!req || typeof req !== "object") return false;
  if (req.hasCredential) return false;
  const method = String(req.method || "").toUpperCase();
  if (method !== "GET" && method !== "HEAD") return false;
  return FIRST_PARTY_READ_PATHS.has(normalizePlanePath(req.path));
}

/**
 * KV key for the web plane's per-minute counter. The `web:` prefix keeps the
 * two planes' counters in separate keyspaces, so anonymous page rendering can
 * never consume -- or be consumed by -- a commercial caller's budget. Mirrors
 * checkRateLimit()'s existing `rl:{ip}:{minute}` shape.
 */
export function webPlaneRateKey(ip, minute) {
  return `rl:web:${ip}:${minute}`;
}

/**
 * KV key for the web plane's per-UTC-day counter. Mirrors daily-quota.js's
 * `quota:daily:{identifier}:{date}` shape, under its own prefix for the same
 * keyspace-isolation reason as above.
 */
export function webPlaneDailyKey(ip, dateStr) {
  return `quota:web:${ip}:${dateStr}`;
}

/**
 * Pure decision function for the web plane's daily budget, mirroring
 * daily-quota.js's evaluateDailyQuota() contract: `countAfterIncrement`
 * already includes the current request, and `exceeded` means this request
 * itself should be denied.
 */
export function evaluateWebPlaneDaily(countAfterIncrement) {
  const limit = WEB_PLANE_LIMITS.perDay;
  return {
    limit,
    remaining: Math.max(0, limit - countAfterIncrement),
    exceeded: countAfterIncrement > limit,
  };
}

/**
 * Observability payload for /api/observability/first-party-plane. Exposing
 * the live plane membership and its budgets is what makes entitlement drift
 * detectable instead of silent -- the failure mode this whole module exists
 * to prevent (Principle 7).
 */
export function firstPartyPlaneObservability() {
  return {
    plane: "first_party_web_read",
    version: "1.0.0",
    limits: { per_minute: WEB_PLANE_LIMITS.perMinute, per_day: WEB_PLANE_LIMITS.perDay },
    path_count: FIRST_PARTY_READ_PATHS.size,
    paths: Array.from(FIRST_PARTY_READ_PATHS).sort(),
    admission: {
      credential: "must be absent -- any credential routes to the commercial plane",
      methods: ["GET", "HEAD"],
      match: "exact path, after trailing-slash normalization",
    },
    commercial_plane_unchanged: true,
  };
}
