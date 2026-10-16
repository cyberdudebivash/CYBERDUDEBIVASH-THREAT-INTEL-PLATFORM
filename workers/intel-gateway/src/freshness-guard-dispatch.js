// =============================================================================
// CYBERDUDEBIVASH SENTINEL APEX -- freshness guard dispatch (DORMANT)
//
// Why (P0 2026-09-30, C04): /api/health answered 503 at 15:06Z because the
// public feed was 7h15m old (contract 6h, config/public_freshness_contract.
// json). The publisher (sentinel-apex.yml) and its self-heal
// (intel-freshness-guard.yml, cron every 30 min) both depend on GitHub
// cron, and GitHub delivers this repository's schedules roughly every
// 2.4-8.5 hours (guard: ~5 runs/day for 48 scheduled; SLA heartbeat: ~5 of
// 144). The guard last ran at 08:57Z (feed fresh) and next at 15:51Z, so
// nothing re-dispatched the publisher when the 07:51:55Z generation aged
// past 4h. A 503 on a stale feed is the correct answer; the defect is that
// the cure never ran.
//
// What: on the Worker's EXISTING 15-minute cron (no new trigger), every :00 and
// :30 tick sends one workflow_dispatch for intel-freshness-guard.yml. The
// guard keeps the only decision logic (scripts/intel_freshness_guard.py:
// dispatch the publisher only when the feed is >= 4h old, no publisher run
// is active or queued, and its own cooldown allows). Dispatching by FILE
// name survives the v201.0-style workflow display-name renames that broke
// every name-based workflow_run chain in this repository.
//
// Dormant: does nothing unless FRESHNESS_GUARD_DISPATCH_ENABLED is exactly
// "true" AND the FRESHNESS_GUARD_DISPATCH_TOKEN secret is set.
// config/cloudflare_pre_revenue_guard.json requires explicit founder
// approval for any new recurring Cloudflare workload, so wrangler.toml ships
// "false" and tests/test_cloudflare_pre_revenue_guard.py pins it. Usage when
// enabled: 48 outbound GitHub API calls/day from an existing cron (no new
// invocation), plus the guard's own ~48 GETs/day of /api/health. See
// docs/CUSTOMER_RELEASE_LEDGER.md (R01) for the activation runbook.
//
// The token is sent only to api.github.com, never logged, and no response
// body is read. Dependency-free so node --test can load it directly.
// =============================================================================

export const FRESHNESS_GUARD_REPOSITORY = "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM";
export const FRESHNESS_GUARD_WORKFLOW = "intel-freshness-guard.yml";
export const FRESHNESS_GUARD_REF = "main";
export const FRESHNESS_GUARD_DISPATCH_URL =
  `https://api.github.com/repos/${FRESHNESS_GUARD_REPOSITORY}/actions/workflows/${FRESHNESS_GUARD_WORKFLOW}/dispatches`;

export function freshnessGuardDispatchEnabled(env) {
  const token = env?.FRESHNESS_GUARD_DISPATCH_TOKEN;
  return env?.FRESHNESS_GUARD_DISPATCH_ENABLED === "true"
    && typeof token === "string" && token.trim() !== "";
}

// The 15-minute cron fires at :00 :15 :30 :45 UTC; dispatch on :00 and :30 only.
export function isGuardDispatchTick(scheduledTime) {
  const minute = new Date(scheduledTime).getUTCMinutes();
  return Number.isInteger(minute) && minute % 30 < 15;
}

/**
 * Never throws. Returns { status } where status is one of
 * "disabled" | "not_this_tick" | "dispatched" | "rejected" | "error".
 */
export async function dispatchFreshnessGuard(env, scheduledTime, fetchImpl = fetch) {
  if (!freshnessGuardDispatchEnabled(env)) return { status: "disabled" };
  if (!isGuardDispatchTick(scheduledTime)) return { status: "not_this_tick" };
  let res;
  try {
    res = await fetchImpl(FRESHNESS_GUARD_DISPATCH_URL, {
      method: "POST",
      headers: {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + env.FRESHNESS_GUARD_DISPATCH_TOKEN.trim(),
        "Content-Type": "application/json",
        "User-Agent": "cdb-sentinel-apex-gateway/freshness-guard-dispatch",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({ ref: FRESHNESS_GUARD_REF }),
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    return { status: "error", error: String((err && err.name) || "fetch_failed").slice(0, 40) };
  }
  // GitHub answers 204 No Content to an accepted workflow_dispatch.
  if (res.status === 204) return { status: "dispatched" };
  return { status: "rejected", http_status: res.status };
}
