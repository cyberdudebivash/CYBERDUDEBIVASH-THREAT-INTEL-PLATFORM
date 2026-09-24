// ==============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- SLA Monitor Engine v201.0
// Real-time uptime tracking + SLA compliance proof for Enterprise subscribers
//
// Endpoints:
//   GET  /api/sla/status      -- public: current uptime + SLA health
//   GET  /api/sla/report      -- Enterprise: 30-day SLA compliance report
//   GET  /api/sla/incidents   -- Enterprise: incident log
//   POST /api/sla/ping        -- internal: heartbeat recorder (called by cron)
//   GET  /api/sla/certificate -- Enterprise: downloadable SLA compliance cert data
//
// SLA Targets:
//   Enterprise: 99.9% uptime / month (~44 min downtime allowed)
//   Pro:        99.5% uptime / month (~3.6 hrs downtime allowed)
//   Free:       best-effort (no SLA)
// ==============================================================================

const safe    = (v, fb = "UNKNOWN") => (v == null ? fb : String(v));
const safeNum = (v, fb = 0)        => (typeof v === "number" && isFinite(v) ? v : Number(v) || fb);
const safeArr = (v)                => (Array.isArray(v) ? v : []);

// Constant-time string comparison for shared-secret checks -- same
// implementation as index.js's timingSafeEqual; duplicated locally (rather
// than imported) because index.js imports from this module, so an
// index.js -> this file -> index.js import would be circular. Same pattern
// already used in revenue-enforcement.js.
function timingSafeEqual(a, b) {
  const bufA = new TextEncoder().encode(String(a ?? ""));
  const bufB = new TextEncoder().encode(String(b ?? ""));
  const len  = Math.max(bufA.length, bufB.length);
  let diff   = bufA.length ^ bufB.length;
  for (let i = 0; i < len; i++) {
    diff |= (bufA[i] ?? 0) ^ (bufB[i] ?? 0);
  }
  return diff === 0;
}

// PRODUCTION-VERIFICATION FIX (2026-08-24): this file was never reachable
// from index.js's router (confirmed: no import of sla-monitor.js existed),
// and even if wired it would have crashed/misbehaved for every real caller:
//   - `auth.valid`, `auth.key_id`, `auth.email` do not exist on the real
//     resolveAuth() return shape ({tier, key, sub, jwt?, kv?, error?} --
//     index.js:324). Every "if (!auth.valid)" check here was always true,
//     so real Enterprise customers with a genuine key would still get 401.
//   - Tier values compared here ("enterprise") are lowercase; the real
//     auth.tier is always uppercase (TIERS.ENTERPRISE = "ENTERPRISE"),
//     confirmed by index.js:317 and documented as the exact same class of
//     bug already fixed once in revenue-enforcement.js (see that file's
//     REVENUE_CONFIG comment). The comparison could never match.
//   - env.KV is not a bound namespace (wrangler.toml binds API_KEYS_KV,
//     RATE_LIMIT_KV, ANALYTICS_KV, SECURITY_HUB_KV only) -- every ping/
//     incident read or write was silently a no-op against `undefined`.
// Fixed to the real contract; storage moved to the existing SECURITY_HUB_KV
// binding (same "reuse an existing binding, no new infra" pattern already
// used by credit-system.js and api-extensions.js's abuse/webhook state).
const SLA_PING_KEY      = "sla:pings";
const SLA_INCIDENT_KEY  = "sla:incidents";
const SLA_WINDOW_DAYS   = 30;
const PING_TTL          = 60 * 60 * 24 * 35; // 35-day retention
const ENTERPRISE_SLA    = 99.9;
const PRO_SLA           = 99.5;

/* ===========================================================================
   handleSLAStatus  -- GET /api/sla/status  (public)
   =========================================================================== */
export async function handleSLAStatus(request, env, rid) {
  const pings = await _loadPings(env);
  const now   = Date.now();
  const windowMs = SLA_WINDOW_DAYS * 24 * 60 * 60 * 1000;

  const recent = pings.filter(p => (now - p.ts) <= windowMs);
  const upPings = recent.filter(p => p.ok).length;
  const total   = recent.length;
  const uptimePct = total > 0 ? ((upPings / total) * 100) : 100;

  // Check last ping freshness (stale = potential outage)
  const lastPing = pings[pings.length - 1];
  const lastPingAge = lastPing ? Math.round((now - lastPing.ts) / 1000) : null;
  const isLikelyUp  = !lastPingAge || lastPingAge < 300; // <5min = healthy

  const incidents = await _loadIncidents(env);
  const recentIncidents = incidents.filter(i => (now - new Date(i.start).getTime()) <= windowMs);

  const totalDownMs = recentIncidents.reduce((acc, i) => {
    const dur = i.duration_ms || 0;
    return acc + dur;
  }, 0);
  const windowTotalMs    = SLA_WINDOW_DAYS * 24 * 60 * 60 * 1000;
  const calculatedUptime = Math.min(100, ((windowTotalMs - totalDownMs) / windowTotalMs) * 100);

  // CodeRabbit review finding (PR #237): this previously defaulted to a
  // fabricated 100% uptime whenever total <= 10 -- including total === 0,
  // i.e. a Worker that has never received a single /api/sla/ping heartbeat
  // would still report "operational" / 100% / sla_met_enterprise: true to
  // paying Enterprise customers with zero actual monitoring evidence behind
  // it. This endpoint has never been reachable before this PR (no prior
  // customer integration to stay compatible with), so there is no cost to
  // reporting real absence-of-data honestly instead.
  const hasData = total > 0;
  const displayUptime = hasData ? Math.max(uptimePct, calculatedUptime) : null;

  return _json(200, {
    status:           !hasData ? "insufficient_data" : (isLikelyUp ? "operational" : "degraded"),
    uptime_pct_30d:   hasData ? parseFloat(displayUptime.toFixed(4)) : null,
    sla_target_enterprise: ENTERPRISE_SLA,
    sla_target_pro:        PRO_SLA,
    sla_met_enterprise:    hasData ? displayUptime >= ENTERPRISE_SLA : null,
    sla_met_pro:           hasData ? displayUptime >= PRO_SLA : null,
    total_pings_30d:       total,
    successful_pings_30d:  upPings,
    last_ping_age_seconds: lastPingAge,
    incidents_30d:         recentIncidents.length,
    total_downtime_seconds: Math.round(totalDownMs / 1000),
    // PRODUCTION-TRUTH FIX (post-launch platform audit): the 4 entries below
    // "intel-gateway" were hardcoded operational/99.9x%+ uptime figures with
    // no ping mechanism ever recording per-component data for any of them --
    // nothing calls POST /api/sla/ping with component "stix-feed"/"ai-engine"/
    // "dark-web-monitor"/"premium-reports" anywhere in this codebase (checked:
    // no cron, no workflow, no admin script). "intel-gateway" alone reflects
    // real measured data (displayUptime, computed above from actual pings/
    // incidents). "dark-web-monitor" specifically claimed 99.95% uptime for a
    // feature whose routes return 503 unavailable on every call (see index.js
    // dark-web-monitor.js route registration) -- reported honestly as disabled
    // rather than fabricated-operational.
    components: {
      "intel-gateway":    { status: !hasData ? "insufficient_data" : (isLikelyUp ? "operational" : "degraded"), uptime: displayUptime },
      "stix-feed":        { status: "not_separately_monitored", uptime: null },
      "ai-engine":        { status: "not_separately_monitored", uptime: null },
      "dark-web-monitor": { status: "disabled", uptime: null, note: "Simulated-data endpoints intentionally disabled pending real data-source integration -- see dark-web-monitor.js" },
      "premium-reports":  { status: "not_separately_monitored", uptime: null },
    },
    version: "201.0",
    ts:      new Date().toISOString(),
    rid,
  });
}

/* ===========================================================================
   handleSLAReport  -- GET /api/sla/report  (Enterprise)
   =========================================================================== */
// v185.2 FIX (Fortune-500 audit, entitlement inventory): all three gates in
// this file checked only auth.tier !== "ENTERPRISE", excluding MSSP -- every
// other Enterprise-tier gate in the codebase (enforceTierGate's isEnt,
// requireEnterprise in enterprise-endpoints.js, the ~6 inline
// TIERS.ENTERPRISE||TIERS.MSSP checks in index.js) treats MSSP as
// Enterprise-or-above. This denied the platform's top-paying tier access to
// SLA reports, incidents, and certificates that ENTERPRISE customers get.
export async function handleSLAReport(request, env, auth, rid) {
  if (!auth || (!auth.key && !auth.jwt)) return _jsonErr(401, "Authentication required.", rid);
  if (auth.tier !== "ENTERPRISE" && auth.tier !== "MSSP") {
    return _jsonErr(403, "SLA compliance reports require Enterprise tier. Upgrade at /upgrade.html", rid);
  }

  const pings    = await _loadPings(env);
  const incidents = await _loadIncidents(env);
  const now      = Date.now();
  const windowMs = SLA_WINDOW_DAYS * 24 * 60 * 60 * 1000;

  // Build daily uptime breakdown (last 30 days)
  const dailyStats = [];
  for (let d = 0; d < SLA_WINDOW_DAYS; d++) {
    const dayStart = now - (d + 1) * 86400000;
    const dayEnd   = now - d * 86400000;
    const dayPings = pings.filter(p => p.ts >= dayStart && p.ts < dayEnd);
    const dayUp    = dayPings.filter(p => p.ok).length;
    const dayTotal = dayPings.length;
    const dayDate  = new Date(dayStart).toISOString().split("T")[0];
    dailyStats.unshift({
      date:       dayDate,
      uptime_pct: dayTotal > 0 ? parseFloat(((dayUp / dayTotal) * 100).toFixed(2)) : 100,
      pings:      dayTotal,
      incidents:  incidents.filter(i => {
        const iStart = new Date(i.start).getTime();
        return iStart >= dayStart && iStart < dayEnd;
      }).length,
    });
  }

  const recentPings    = pings.filter(p => (now - p.ts) <= windowMs);
  const upCount        = recentPings.filter(p => p.ok).length;
  const hasData        = recentPings.length > 0;
  const uptimePct      = hasData ? ((upCount / recentPings.length) * 100) : null;
  const recentIncidents = incidents.filter(i => (now - new Date(i.start).getTime()) <= windowMs);
  const totalDownMs    = recentIncidents.reduce((acc, i) => acc + (i.duration_ms || 0), 0);

  return _json(200, {
    report_type:         "enterprise_sla_30d",
    account:             safe(auth.sub, ""),
    generated_at:        new Date().toISOString(),
    period:              `${new Date(now - windowMs).toISOString().split("T")[0]} to ${new Date().toISOString().split("T")[0]}`,
    sla_target:          ENTERPRISE_SLA,
    // CodeRabbit review finding (PR #237): previously defaulted to a
    // fabricated 100%/"MET" when there was zero ping data. See
    // handleSLAStatus's matching fix note above for full rationale.
    actual_uptime_pct:   hasData ? parseFloat(uptimePct.toFixed(4)) : null,
    sla_status:          !hasData ? "INSUFFICIENT_DATA" : (uptimePct >= ENTERPRISE_SLA ? "MET CHECK" : "BREACHED FAIL"),
    total_downtime_min:  parseFloat((totalDownMs / 60000).toFixed(2)),
    allowed_downtime_min: parseFloat(((100 - ENTERPRISE_SLA) / 100 * SLA_WINDOW_DAYS * 24 * 60).toFixed(2)),
    incidents_count:     recentIncidents.length,
    incidents:           recentIncidents.slice(-20),
    daily_breakdown:     dailyStats,
    // PRODUCTION-TRUTH FIX: same fabricated-per-component-uptime issue as
    // handleSLAStatus above (see that function's matching comment) -- no
    // real per-component ping data exists for these 4 entries.
    components: {
      "intel-gateway":    { sla: ENTERPRISE_SLA, actual: hasData ? Math.min(100, uptimePct) : null },
      "stix-feed":        { sla: ENTERPRISE_SLA, actual: null, status: "not_separately_monitored" },
      "ai-engine":        { sla: ENTERPRISE_SLA, actual: null, status: "not_separately_monitored" },
      "dark-web-monitor": { sla: 99.5,           actual: null, status: "disabled" },
      "premium-reports":  { sla: ENTERPRISE_SLA, actual: null, status: "not_separately_monitored" },
    },
    credit_policy: "SLA credit of 10% per day of breach, up to 30% of monthly fee. Contact bivash@cyberdudebivash.com with this report to claim.",
    certifier:     "CYBERDUDEBIVASH SENTINEL APEX -- v201.0 GOD-MODE",
    gstin:         "21ARKPN8270G1ZP",
    rid,
  });
}

/* ===========================================================================
   handleSLAIncidents  -- GET /api/sla/incidents  (Enterprise)
   =========================================================================== */
export async function handleSLAIncidents(request, env, auth, rid) {
  if (!auth || (!auth.key && !auth.jwt)) return _jsonErr(401, "Authentication required.", rid);
  if (auth.tier !== "ENTERPRISE" && auth.tier !== "MSSP") return _jsonErr(403, "Enterprise tier required.", rid);

  const incidents = await _loadIncidents(env);
  const url = new URL(request.url);
  const limit = Math.min(100, safeNum(parseInt(url.searchParams.get("limit") || "50"), 50));

  return _json(200, {
    incidents: incidents.slice(-limit),
    total:     incidents.length,
    rid,
  });
}

/* ===========================================================================
   handleSLAPing  -- POST /api/sla/ping  (internal cron/admin)
   Records a heartbeat. Called by Cloudflare Cron Trigger every 5 minutes.
   =========================================================================== */
export async function handleSLAPing(request, env, rid) {
  const secret = request.headers.get("X-Admin-Secret") || "";
  const envSecret = env.WORKER_ADMIN_SECRET || "";
  if (!envSecret || !timingSafeEqual(secret, envSecret)) {
    return _jsonErr(403, "Admin secret required for SLA ping.", rid);
  }

  let body;
  try { body = await request.json(); } catch { body = {}; }

  const ping = {
    ts:       Date.now(),
    ok:       body.ok !== false,
    latency:  safeNum(body.latency_ms, 0),
    component: safe(body.component, "intel-gateway"),
    region:   safe(body.region || (request.cf?.colo) || "unknown"),
    note:     safe(body.note || "", ""),
  };

  const pings = await _loadPings(env);
  pings.push(ping);

  // Keep only last 35 days of pings (trim aggressively to control KV size)
  const cutoff = Date.now() - 35 * 86400000;
  const trimmed = pings.filter(p => p.ts > cutoff).slice(-10000);

  // Detect incident: 3+ consecutive failures
  if (!ping.ok) {
    const last3 = trimmed.slice(-3);
    if (last3.length >= 3 && last3.every(p => !p.ok)) {
      await _recordIncident(env, {
        start:       new Date(last3[0].ts).toISOString(),
        component:   ping.component,
        severity:    "P2",
        description: "3+ consecutive health check failures detected.",
        duration_ms: Date.now() - last3[0].ts,
        auto_detected: true,
      });
    }
  }

  if (env.SECURITY_HUB_KV) {
    await env.SECURITY_HUB_KV.put(SLA_PING_KEY, JSON.stringify(trimmed), { expirationTtl: PING_TTL });
  }

  return _json(200, { recorded: true, ts: new Date(ping.ts).toISOString(), ok: ping.ok, rid });
}

/* ===========================================================================
   handleSLACertificate  -- GET /api/sla/certificate  (Enterprise)
   Returns SLA compliance certificate as JSON (can be rendered to PDF)
   =========================================================================== */
// PRODUCTION-TRUTH FIX (post-launch platform audit): this certificate --
// the one formal document an Enterprise customer can hand to their OWN
// auditors as compliance evidence -- hardcoded sla_status: "COMPLIANT"
// unconditionally. It never called _loadPings/_loadIncidents, the same real
// data handleSLAStatus and handleSLAReport (both fixed for this exact class
// of bug in PR #237 -- "previously defaulted to a fabricated 100%/'MET'
// when there was zero ping data") already load two functions above. A
// customer requesting this certificate during a real outage, or before any
// monitoring history existed at all, still received a signed-looking
// "COMPLIANT" document. Fixed to compute the same real uptime/incident
// data as its siblings and report INSUFFICIENT_DATA honestly, matching
// their established precedent, rather than issue a certificate with no
// verification behind it.
export async function handleSLACertificate(request, env, auth, rid) {
  if (!auth || (!auth.key && !auth.jwt)) return _jsonErr(401, "Authentication required.", rid);
  if (auth.tier !== "ENTERPRISE" && auth.tier !== "MSSP") return _jsonErr(403, "Enterprise tier required.", rid);

  const now = new Date();
  const periodEnd   = now.toISOString().split("T")[0];
  const periodStart = new Date(now - SLA_WINDOW_DAYS * 86400000).toISOString().split("T")[0];

  const pings    = await _loadPings(env);
  const incidents = await _loadIncidents(env);
  const nowMs    = now.getTime();
  const windowMs = SLA_WINDOW_DAYS * 24 * 60 * 60 * 1000;

  const recentPings = pings.filter(p => (nowMs - p.ts) <= windowMs);
  const upCount      = recentPings.filter(p => p.ok).length;
  const hasData      = recentPings.length > 0;
  const pingUptime   = hasData ? (upCount / recentPings.length) * 100 : null;

  const recentIncidents = incidents.filter(i => (nowMs - new Date(i.start).getTime()) <= windowMs);
  const totalDownMs     = recentIncidents.reduce((acc, i) => acc + (i.duration_ms || 0), 0);
  const incidentUptime  = Math.min(100, ((windowMs - totalDownMs) / windowMs) * 100);

  // Same "take the more conservative real signal" combination handleSLAStatus
  // uses -- an incident can be recorded (and thus count against uptime) even
  // in a window with sparse ping coverage.
  const actualUptime = hasData ? Math.max(pingUptime, incidentUptime) : null;
  const slaStatus = !hasData
    ? "INSUFFICIENT_DATA"
    : (actualUptime >= ENTERPRISE_SLA ? "COMPLIANT" : "BREACHED");

  return _json(200, {
    certificate: {
      title:          "SENTINEL APEX Enterprise SLA Compliance Certificate",
      issued_to:      safe(auth.sub, "Enterprise Subscriber"),
      issued_by:      "CYBERDUDEBIVASH SENTINEL APEX",
      gstin:          "21ARKPN8270G1ZP",
      period:         `${periodStart} to ${periodEnd}`,
      sla_target:     `${ENTERPRISE_SLA}% uptime`,
      sla_status:     slaStatus,
      measured_uptime_pct: hasData ? parseFloat(actualUptime.toFixed(4)) : null,
      incidents_in_period: recentIncidents.length,
      monitoring_basis:    hasData
        ? `${recentPings.length} health check(s) + ${recentIncidents.length} recorded incident(s) over the period`
        : "No monitoring data recorded for this period -- compliance cannot be verified.",
      platform_url:   "https://intel.cyberdudebivash.com",
      support_email:  "bivash@cyberdudebivash.com",
      version:        "201.0 GOD-MODE",
      issued_at:      now.toISOString(),
      cert_id:        `APEX-CERT-${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${Date.now().toString(36).toUpperCase()}`,
    },
    rid,
  });
}

/* -- Internal helpers --------------------------------------------------------- */
async function _loadPings(env) {
  if (!env.SECURITY_HUB_KV) return [];
  try { return JSON.parse(await env.SECURITY_HUB_KV.get(SLA_PING_KEY) || "[]"); } catch { return []; }
}

async function _loadIncidents(env) {
  if (!env.SECURITY_HUB_KV) return [];
  try { return JSON.parse(await env.SECURITY_HUB_KV.get(SLA_INCIDENT_KEY) || "[]"); } catch { return []; }
}

async function _recordIncident(env, incident) {
  if (!env.SECURITY_HUB_KV) return;
  try {
    const incidents = await _loadIncidents(env);
    incidents.push({ ...incident, id: `INC-${Date.now().toString(36).toUpperCase()}` });
    const trimmed = incidents.slice(-500); // keep last 500 incidents
    await env.SECURITY_HUB_KV.put(SLA_INCIDENT_KEY, JSON.stringify(trimmed), { expirationTtl: PING_TTL });
  } catch {}
}

function _json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "X-Sentinel-Version": "201.0" },
  });
}

function _jsonErr(status, message, rid) {
  return _json(status, { error: true, message, rid, version: "201.0" });
}
