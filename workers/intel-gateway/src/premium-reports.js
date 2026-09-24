// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- Premium Threat Report Engine v201.0
// Routes: POST /api/reports/premium  .  GET /api/reports/list  .  GET /api/reports/:id
// Sellable Asset: $49/report  |  $149/mo unlimited  |  Included in Enterprise
// Architecture:
//   - JSON report generation (structured intelligence package)
//   - PDF generation metadata (served as downloadable JSON until PDF render service wired)
//   - Full CVE summary, MITRE ATT&CK coverage, actor attribution, IOC table
//   - Stored in R2 for persistent retrieval (90-day retention)
//   - Revenue tracked in ANALYTICS_KV per report generation
// =============================================================================

// -- Tier & Pricing Config -----------------------------------------------------
const REPORT_CONFIG = {
  VERSION: "201.0",
  PRICE_PER_REPORT_USD:   49,
  PRICE_PER_REPORT_INR:   3999,
  MONTHLY_UNLIMITED_USD:  149,
  MONTHLY_UNLIMITED_INR:  11999,
  MAX_ITEMS_FREE:         0,    // free: no reports
  MAX_ITEMS_PRO:          50,   // pro: up to 50 items per report
  MAX_ITEMS_ENTERPRISE:   500,  // enterprise: full feed
  REPORT_TTL_DAYS:        90,
  R2_PREFIX:              "reports/premium/",
};

// -- Helpers -------------------------------------------------------------------
function safeStr(v, maxLen = 256) {
  if (!v || typeof v !== "string") return "";
  return v.replace(/[\x00-\x1F\x7F<>"'`\\]/g, "").slice(0, maxLen).trim();
}

function safeInt(v, def = 0, min = 0, max = 9999) {
  const n = parseInt(v);
  return isNaN(n) ? def : Math.max(min, Math.min(max, n));
}

function _json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type":                "application/json; charset=utf-8",
      "Cache-Control":               "no-store",
      // Access-Control-Allow-Origin intentionally not set here -- SENTINEL
      // APEX PUBLIC-REPO ZERO-TRUST PHASE 3: this is a $49/report PRO+
      // commercial route (index.js's own route comment), never genuinely
      // public -- index.js's withBaselineHeaders() applies the real,
      // origin-aware decision via cors-policy.js to every response
      // including this one; see that file's header comment.
      "X-Sentinel-Module":           "premium-reports/201.0",
      ...extra,
    },
  });
}

async function sha256hex(text) {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function genReportId() {
  const b = crypto.getRandomValues(new Uint8Array(8));
  return "rpt_" + Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
}

// -- MITRE ATT&CK Coverage Analyser -------------------------------------------
function analyseMitreCoverage(items) {
  const tacticMap  = {};
  const techniqueSet = new Set();

  for (const item of items) {
    const tactics = Array.isArray(item.mitre_tactics) ? item.mitre_tactics : [];
    const ttps    = Array.isArray(item.ttps) ? item.ttps : [];

    for (const tactic of tactics) {
      const t = safeStr(String(tactic || ""), 50);
      if (t) tacticMap[t] = (tacticMap[t] || 0) + 1;
    }
    for (const ttp of ttps) {
      const id = typeof ttp === "object" ? (ttp.id || ttp.technique_id || "") : String(ttp || "");
      if (id) techniqueSet.add(safeStr(id, 20));
    }
  }

  const topTactics = Object.entries(tacticMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tactic, count]) => ({ tactic, count }));

  const coverageScore = Math.min(100, Math.round((techniqueSet.size / 193) * 100)); // 193 = ATT&CK Enterprise technique count

  return {
    unique_techniques:    techniqueSet.size,
    top_tactics:          topTactics,
    coverage_score_pct:   coverageScore,
    coverage_label:       coverageScore >= 60 ? "COMPREHENSIVE" : coverageScore >= 30 ? "MODERATE" : "LIMITED",
    techniques_list:      [...techniqueSet].slice(0, 50),
    enterprise_matrix_url:"https://attack.mitre.org/techniques/enterprise/",
  };
}

// -- CVE Summary Builder -------------------------------------------------------
function buildCVESummary(items) {
  const cves = {};
  let kev_count = 0, critical_count = 0, high_count = 0;

  for (const item of items) {
    const cveId = safeStr(item.cve_id || "", 30);
    if (cveId) {
      cves[cveId] = {
        id:          cveId,
        title:       safeStr(item.title || "", 200),
        cvss_score:  typeof item.cvss_score  === "number" ? item.cvss_score  : null,
        epss_score:  typeof item.epss_score  === "number" ? item.epss_score  : null,
        severity:    safeStr(item.severity || "UNKNOWN", 20),
        kev_present: item.kev_present === true,
        actor_tag:   safeStr(item.actor_tag || "UNATTRIBUTED", 60),
        exploit_available: item.exploit_available === true,
        source:      safeStr(item.source || item.feed_source || "", 100),
        processed_at:item.processed_at || item.timestamp || null,
      };
      if (item.kev_present)                       kev_count++;
      if ((item.severity || "").toUpperCase() === "CRITICAL") critical_count++;
      if ((item.severity || "").toUpperCase() === "HIGH")     high_count++;
    }
  }

  const cveList = Object.values(cves)
    .sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));

  return {
    total_cves:       cveList.length,
    kev_count,
    critical_count,
    high_count,
    top_cves:         cveList.slice(0, 20),
    exploitation_risk: kev_count > 0 ? "CRITICAL -- CISA KEV entries require immediate patching" : "MODERATE",
  };
}

// -- Actor Intelligence Summary ------------------------------------------------
function buildActorIntelligence(items) {
  const actorMap = {};

  for (const item of items) {
    const actor = safeStr(item.actor_tag || "UNATTRIBUTED", 80);
    if (!actorMap[actor]) {
      actorMap[actor] = {
        actor_tag:    actor,
        advisory_count: 0,
        max_risk:     0,
        severities:   {},
        campaigns:    new Set(),
        ioc_count:    0,
        ttp_count:    0,
        first_seen:   item.processed_at || item.timestamp || null,
        last_seen:    item.processed_at || item.timestamp || null,
      };
    }
    const a = actorMap[actor];
    a.advisory_count++;
    const risk = typeof item.risk_score === "number" ? item.risk_score : 0;
    if (risk > a.max_risk) a.max_risk = risk;
    const sev = (item.severity || "UNKNOWN").toUpperCase();
    a.severities[sev] = (a.severities[sev] || 0) + 1;
    const campaign = safeStr((item.apex && item.apex.campaign_id) || "", 60);
    if (campaign && campaign !== "UNCLASSIFIED") a.campaigns.add(campaign);
    a.ioc_count += Array.isArray(item.iocs) ? item.iocs.length : (item.ioc_count || 0);
    a.ttp_count += Array.isArray(item.ttps) ? item.ttps.length : (item.ttp_count || 0);
    if (item.processed_at > (a.last_seen || "")) a.last_seen = item.processed_at;
  }

  return Object.values(actorMap)
    .map(a => ({ ...a, campaigns: [...a.campaigns] }))
    .sort((a, b) => b.advisory_count - a.advisory_count)
    .slice(0, 20);
}

// -- IOC Table Builder ---------------------------------------------------------
function buildIOCTable(items, maxItems = 200) {
  const iocs = [];
  const seen = new Set();

  for (const item of items) {
    const rawIocs = Array.isArray(item.iocs) ? item.iocs : [];
    for (const ioc of rawIocs) {
      if (iocs.length >= maxItems) break;
      // CodeRabbit finding (PR #246): typeof null === "object" in JS, so a
      // malformed entry like iocs: [null] passed the old type check and then
      // crashed on ioc.value below, 500ing the whole report. Plain-string
      // IOC entries are still valid and handled by the branch below.
      if (ioc === null) continue;
      const val = safeStr(typeof ioc === "object" ? (ioc.value || ioc.indicator || "") : String(ioc || ""), 512);
      const key = val.toLowerCase();
      if (!val || seen.has(key)) continue;
      seen.add(key);
      iocs.push({
        value:      val,
        type:       safeStr(typeof ioc === "object" ? (ioc.type || "unknown") : "unknown", 30),
        confidence: typeof ioc === "object" && typeof ioc.confidence === "number" ? ioc.confidence : 50,
        source:     safeStr(item.source || item.feed_source || "", 80),
        context:    safeStr(item.title || "", 120),
        severity:   safeStr(item.severity || "UNKNOWN", 20),
        actor_tag:  safeStr(item.actor_tag || "UNATTRIBUTED", 60),
      });
    }
    if (iocs.length >= maxItems) break;
  }

  return {
    total_iocs:   iocs.length,
    ioc_table:    iocs,
    types_summary: iocs.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {}),
  };
}

// -- Executive Summary Generator -----------------------------------------------
function buildExecutiveSummary(items, mitre, cve, actors, reportPeriod) {
  const totalAdvisories   = items.length;
  const criticalCount     = items.filter(i => (i.severity || "").toUpperCase() === "CRITICAL").length;
  const highCount         = items.filter(i => (i.severity || "").toUpperCase() === "HIGH").length;
  const kevCount          = items.filter(i => i.kev_present).length;
  const avgRisk           = items.length > 0
    ? parseFloat((items.reduce((s, i) => s + (typeof i.risk_score === "number" ? i.risk_score : 0), 0) / items.length).toFixed(2))
    : 0;

  const threatLandscape = criticalCount > 5
    ? "ELEVATED -- Multiple critical-severity threats active in current intelligence cycle"
    : criticalCount > 0
    ? "HIGH -- Critical threats identified requiring immediate SOC response"
    : highCount > 10
    ? "MODERATE-HIGH -- Significant high-severity advisory volume detected"
    : "MODERATE -- Standard threat activity within normal baseline";

  return {
    report_period:       reportPeriod,
    total_advisories:    totalAdvisories,
    critical_count:      criticalCount,
    high_count:          highCount,
    kev_confirmed:       kevCount,
    avg_risk_score:      avgRisk,
    threat_landscape:    threatLandscape,
    mitre_coverage:      `${mitre.unique_techniques} techniques across ${Object.keys(mitre.top_tactics.reduce((a, t) => { a[t.tactic] = 1; return a; }, {})).length} tactics`,
    top_actor:           actors[0] ? `${actors[0].actor_tag} (${actors[0].advisory_count} advisories)` : "UNATTRIBUTED",
    cve_exposure:        cve.total_cves > 0 ? `${cve.total_cves} CVEs identified -- ${cve.kev_count} CISA KEV confirmed` : "No CVEs in scope",
    key_recommendations: [
      kevCount > 0   ? `CRITICAL: Patch ${kevCount} CISA KEV-confirmed CVE(s) immediately` : null,
      criticalCount > 0 ? `Deploy detection rules for ${criticalCount} CRITICAL-severity threat(s)` : null,
      mitre.unique_techniques > 10 ? `Review MITRE coverage gaps -- ${mitre.unique_techniques} techniques active in this period` : null,
      avgRisk > 6    ? "Activate incident response workflow -- average risk score exceeds HIGH threshold" : null,
      "Subscribe to real-time webhook push for immediate alert delivery",
    ].filter(Boolean),
  };
}

// -- Main Report Handler -------------------------------------------------------

export async function handlePremiumReport(request, env, auth, rid) {
  const tier = (auth.tier || "free").toLowerCase();
  // ZERO-TRUST HARDENING FIX (2026-08-24): was missing .toLowerCase() --
  // real auth.tier is always uppercase (TIERS.FREE/PRO/ENTERPRISE/MSSP,
  // index.js:317), so every tier === "free"/"enterprise" comparison below
  // silently never matched for a real customer. Same bug class fixed
  // repeatedly elsewhere this session (revenue-enforcement.js, sla-monitor.js,
  // alert-engine.js). CORRECTION (post-#369 production assurance audit):
  // this file's routes were wired live into index.js's router by commit
  // 5004465c (PR #313, 2026-09-01) -- POST /api/reports/premium and GET
  // /api/reports/list/{id} are real, tier-gated, revenue-generating
  // endpoints (see index.js's "premium-reports.js routes" block), not
  // dead code. This fix was therefore already live-exploitable before
  // this correction; treat every defect found in this file as real and
  // customer-facing, not latent.

  // Tier gate -- free users get upsell
  if (tier === "free") {
    return _json({
      error:      "tier_required",
      feature:    "premium_reports",
      message:    "Premium Threat Intelligence Reports require Pro tier ($29/mo) or individual purchase ($49/report).",
      pricing: {
        per_report_usd:     REPORT_CONFIG.PRICE_PER_REPORT_USD,
        per_report_inr:     REPORT_CONFIG.PRICE_PER_REPORT_INR,
        monthly_unlimited:  REPORT_CONFIG.MONTHLY_UNLIMITED_USD,
      },
      upgrade_url: "/upgrade.html?plan=pro&feature=reports",
      store_url:   "/store.html?product=threat-report",
      request_id:  rid,
    }, 403);
  }

  if (request.method === "GET") {
    return handleReportList(request, env, auth, rid);
  }

  if (request.method !== "POST") {
    return _json({ error: "method_not_allowed", allowed: ["GET", "POST"], request_id: rid }, 405);
  }

  // Parse report request
  let body = {};
  try { body = await request.json(); } catch { /* optional body */ }

  const reportType  = ["weekly", "monthly", "custom", "cve_focused", "actor_focused"].includes(body.type)
    ? body.type : "weekly";
  const reportTitle = safeStr(body.title || `SENTINEL APEX Threat Intelligence Report -- ${reportType.toUpperCase()}`, 200);
  const maxItems    = tier === "enterprise" ? REPORT_CONFIG.MAX_ITEMS_ENTERPRISE : REPORT_CONFIG.MAX_ITEMS_PRO;
  const severityFilter = body.severity_filter
    ? (Array.isArray(body.severity_filter) ? body.severity_filter.map(s => safeStr(s, 20).toUpperCase()) : [])
    : [];

  // Load feed from R2 (primary) or KV cache (fallback)
  let feedItems = [];
  try {
    if (env?.INTEL_R2) {
      // PRODUCTION-VERIFICATION FIX (2026-08-24): "feeds/feed.json" is a
      // dead R2 key nothing ever writes -- see p18-handlers.js's matching
      // _loadFeed fix note for the full cross-file root cause. Redirected
      // to the live, continuously updated key.
      const r2obj = await env.INTEL_R2.get("api/v1/intel/latest.json");
      if (r2obj) {
        const raw = await r2obj.json();
        feedItems = Array.isArray(raw)
          ? raw
          : Array.isArray(raw?.advisories)
          ? raw.advisories
          : Array.isArray(raw?.items)
          ? raw.items
          : [];
      }
    }
  } catch (e) {
    // Non-fatal -- proceed with empty feed, report will still generate structure
  }

  // PRODUCTION-VERIFICATION FIX (2026-08-24): isCustomerReady() runs the
  // narrative-report certification chain (P20+P21+P23+P25+P26) built for the
  // free, public /reports/** HTML surface (P0 incident scope -- see
  // publication-gate.js header). Live-verified this session against the
  // production feed: 0/474 current items clear that bar, so this filter
  // silently produced an EMPTY report for every paying premium-reports
  // customer ($49/report, $149/mo) regardless of tier. A premium report is a
  // curated digest of raw feed data the customer already has paid API access
  // to (via /api/feed) -- it does not need the same narrative certification
  // as the polished public HTML page, and publication-gate.js's own docs
  // forbid lowering that gate's thresholds to make it pass. Filtering on
  // real underlying signal instead (title plus at least one of
  // severity/cve_id/iocs) keeps out empty stub items without imposing
  // certification thresholds this endpoint was never designed to need.
  feedItems = feedItems.filter(i => i.title && (i.severity || i.cve_id || (Array.isArray(i.iocs) && i.iocs.length > 0)));

  // Apply filters
  let filtered = feedItems;
  if (severityFilter.length > 0) {
    filtered = filtered.filter(i => severityFilter.includes((i.severity || "").toUpperCase()));
  }
  if (reportType === "cve_focused") {
    filtered = filtered.filter(i => !!i.cve_id);
  }
  if (reportType === "actor_focused" && body.actor) {
    const actor = safeStr(body.actor, 80).toLowerCase();
    filtered = filtered.filter(i => (i.actor_tag || "").toLowerCase().includes(actor));
  }
  filtered = filtered.slice(0, maxItems);

  // Determine report period
  const now = new Date();
  const periodEnd   = now.toISOString().slice(0, 10);
  const periodStart = reportType === "monthly"
    ? new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10)
    : new Date(now.getTime() - 7 * 86400000).toISOString().slice(0, 10);
  const reportPeriod = `${periodStart} to ${periodEnd}`;

  // Build report sections
  const mitre   = analyseMitreCoverage(filtered);
  const cve     = buildCVESummary(filtered);
  const actors  = buildActorIntelligence(filtered);
  const iocTable= buildIOCTable(filtered, tier === "enterprise" ? 500 : 100);
  const execSum = buildExecutiveSummary(filtered, mitre, cve, actors, reportPeriod);

  const reportId = genReportId();
  const report = {
    report_id:        reportId,
    report_type:      reportType,
    report_title:     reportTitle,
    generated_at:     now.toISOString(),
    generated_by:     "CYBERDUDEBIVASH(R) SENTINEL APEX v201.0",
    report_period:    reportPeriod,
    classification:   "TLP:AMBER -- Restricted to authorised recipients",
    tier:             tier,
    advisories_count: filtered.length,

    // Section 1 -- Executive Summary
    executive_summary: execSum,

    // Section 2 -- CVE Intelligence
    cve_intelligence: cve,

    // Section 3 -- MITRE ATT&CK Coverage
    mitre_attack_coverage: mitre,

    // Section 4 -- Threat Actor Intelligence
    actor_intelligence: {
      total_actors: actors.length,
      actors,
    },

    // Section 5 -- IOC Table
    ioc_intelligence: iocTable,

    // Section 6 -- Raw advisories (limited)
    advisories: filtered.slice(0, tier === "enterprise" ? 500 : 50).map(item => ({
      id:          item.id,
      title:       safeStr(item.title || "", 200),
      severity:    item.severity,
      risk_score:  item.risk_score,
      cve_id:      item.cve_id || null,
      actor_tag:   item.actor_tag || "UNATTRIBUTED",
      kev_present: item.kev_present || false,
      source:      item.source || item.feed_source,
      processed_at:item.processed_at || item.timestamp,
      apex_ai: item.apex_ai ? {
        soc_priority:    item.apex_ai.soc_priority,
        threat_level:    item.apex_ai.threat_level,
        predictive_risk: item.apex_ai.predictive_risk,
        ai_summary:      item.apex_ai.ai_summary,
      } : null,
    })),

    // Section 7 -- Metadata
    metadata: {
      platform:         "CYBERDUDEBIVASH(R) SENTINEL APEX",
      platform_version: "201.0",
      dashboard_url:    "https://intel.cyberdudebivash.com",
      api_docs_url:     "https://intel.cyberdudebivash.com/api-docs.html",
      pricing_url:      "https://intel.cyberdudebivash.com/pricing.html",
      report_ttl_days:  REPORT_CONFIG.REPORT_TTL_DAYS,
      pdf_download_url: `https://intel.cyberdudebivash.com/api/reports/${reportId}/pdf`,
      csv_download_url: `https://intel.cyberdudebivash.com/api/reports/${reportId}/csv`,
      json_download_url:`https://intel.cyberdudebivash.com/api/reports/${reportId}`,
      export_formats:   ["json", "csv", "pdf"],
      contact:          "root@cyberdudebivash.in",
      copyright:        `(C) ${now.getFullYear()} CYBERDUDEBIVASH(R) -- All rights reserved. TLP:AMBER.`,
    },

    request_id: rid,
    gateway:    "SENTINEL-APEX/201.0",
  };

  // Store in R2 (if available)
  try {
    if (env?.INTEL_R2) {
      await env.INTEL_R2.put(
        `${REPORT_CONFIG.R2_PREFIX}${reportId}.json`,
        JSON.stringify(report),
        {
          httpMetadata: { contentType: "application/json" },
          customMetadata: {
            report_id:    reportId,
            report_type:  reportType,
            generated_at: now.toISOString(),
            tier:         tier,
            // TENANT-ISOLATION FIX (CodeRabbit, PR #242 pre-merge review):
            // was `auth.key_id`, a field that does not exist anywhere on the
            // object resolveAuth() returns (index.js:328-382 -- only tier,
            // key, sub, jwt, kv, error). Every report was therefore stored
            // with key_id: "", and since (auth.key_id || "") also always
            // evaluated to "" for every real request, handleReportList's and
            // handleReportGet's ownership checks below both matched "" === ""
            // for any authenticated PRO/ENTERPRISE customer -- full
            // cross-tenant read access to every other customer's reports.
            // Caught before this route was ever wired into index.js's
            // router (PR #242), so no real customer traffic was exposed.
            // auth.sub is the correct per-customer identity (customer_id for
            // API-key auth, JWT sub for JWT auth) -- same field already used
            // for tenant scoping and audit logging elsewhere in this file
            // (getUsageSummary(env, auth.sub, ...) equivalents) and in
            // index.js's own auditLog(..., sub: auth.sub) call sites.
            key_id:       auth.sub || "",
          },
        }
      );
    }
  } catch { /* Non-fatal -- report is still returned in response */ }

  // Track revenue event in KV
  try {
    if (env?.ANALYTICS_KV) {
      const revKey   = `report_generated:${now.toISOString().slice(0, 10)}`;
      const existing = (await env.ANALYTICS_KV.get(revKey, { type: "json" }).catch(() => null)) || { count: 0, tier_breakdown: {} };
      existing.count++;
      existing.tier_breakdown[tier] = (existing.tier_breakdown[tier] || 0) + 1;
      await env.ANALYTICS_KV.put(revKey, JSON.stringify(existing), { expirationTtl: 86400 * 90 });
    }
  } catch { /* Non-fatal */ }

  return _json(report, 201, {
    "X-Report-ID":   reportId,
    "X-Report-Type": reportType,
  });
}

// -- GET /api/reports/list -----------------------------------------------------
export async function handleReportList(request, env, auth, rid) {
  const tier = (auth.tier || "free").toLowerCase();
  // ZERO-TRUST HARDENING FIX (2026-08-24): was missing .toLowerCase() --
  // real auth.tier is always uppercase (TIERS.FREE/PRO/ENTERPRISE/MSSP,
  // index.js:317), so every tier === "free"/"enterprise" comparison below
  // silently never matched for a real customer. Same bug class fixed
  // repeatedly elsewhere this session (revenue-enforcement.js, sla-monitor.js,
  // alert-engine.js). CORRECTION (post-#369 production assurance audit):
  // this file's routes were wired live into index.js's router by commit
  // 5004465c (PR #313, 2026-09-01) -- POST /api/reports/premium and GET
  // /api/reports/list/{id} are real, tier-gated, revenue-generating
  // endpoints (see index.js's "premium-reports.js routes" block), not
  // dead code. This fix was therefore already live-exploitable before
  // this correction; treat every defect found in this file as real and
  // customer-facing, not latent.

  if (tier === "free") {
    return _json({
      error:      "tier_required",
      message:    "Report listing requires Pro tier or above.",
      upgrade_url:"/upgrade.html?plan=pro&feature=reports",
      request_id: rid,
    }, 403);
  }

  const reports = [];
  try {
    if (env?.INTEL_R2) {
      // LIVE-VERIFICATION FIX (post-merge, PR #242): R2Bucket.list() does not
      // return customMetadata by default -- it must be explicitly requested
      // via `include`. Without it, obj.customMetadata was always {} for
      // every listed object, so meta.key_id below was always undefined --
      // the ownership filter correctly failed closed (no cross-tenant leak),
      // but that also meant NO customer, including the true owner, ever saw
      // any report in their own list. Caught live immediately after deploy:
      // customer A generated a report (confirmed via direct GET
      // /api/reports/{id}) but their own /api/reports/list came back empty.
      const list = await env.INTEL_R2.list({ prefix: REPORT_CONFIG.R2_PREFIX, limit: 50, include: ["customMetadata"] });
      for (const obj of (list.objects || [])) {
        const meta = obj.customMetadata || {};
        // TENANT-ISOLATION FIX (CodeRabbit, PR #242 pre-merge review): was
        // `meta.key_id === (auth.key_id || "")` -- auth.key_id does not
        // exist on resolveAuth()'s return object, so this always compared
        // "" === "" and matched every report for every customer. Require a
        // real, non-empty match against auth.sub (the correct per-customer
        // identity -- see the matching fix note where key_id is written,
        // above in handlePremiumReport). A report with no recorded owner
        // (key_id: "", e.g. any generated before this fix) now matches no
        // one rather than everyone -- fails closed, not open.
        if (auth.is_admin || (meta.key_id && auth.sub && meta.key_id === auth.sub)) {
          reports.push({
            report_id:    meta.report_id || obj.key.split("/").pop().replace(".json", ""),
            report_type:  meta.report_type || "unknown",
            generated_at: meta.generated_at || obj.uploaded.toISOString(),
            tier:         meta.tier || "unknown",
            size_bytes:   obj.size,
            download_url: `https://intel.cyberdudebivash.com/api/reports/${meta.report_id}`,
            pdf_url:      `https://intel.cyberdudebivash.com/api/reports/${meta.report_id}/pdf`,
          });
        }
      }
    }
  } catch { /* Return empty list on error */ }

  return _json({
    status:  "ok",
    count:   reports.length,
    reports: reports.sort((a, b) => b.generated_at.localeCompare(a.generated_at)),
    request_id: rid,
    gateway: "SENTINEL-APEX/201.0",
  });
}

// -- GET /api/reports/:id ------------------------------------------------------
export async function handleReportGet(request, env, auth, rid, reportId) {
  const tier = (auth.tier || "free").toLowerCase();
  // ZERO-TRUST HARDENING FIX (2026-08-24): was missing .toLowerCase() --
  // real auth.tier is always uppercase (TIERS.FREE/PRO/ENTERPRISE/MSSP,
  // index.js:317), so every tier === "free"/"enterprise" comparison below
  // silently never matched for a real customer. Same bug class fixed
  // repeatedly elsewhere this session (revenue-enforcement.js, sla-monitor.js,
  // alert-engine.js). CORRECTION (post-#369 production assurance audit):
  // this file's routes were wired live into index.js's router by commit
  // 5004465c (PR #313, 2026-09-01) -- POST /api/reports/premium and GET
  // /api/reports/list/{id} are real, tier-gated, revenue-generating
  // endpoints (see index.js's "premium-reports.js routes" block), not
  // dead code. This fix was therefore already live-exploitable before
  // this correction; treat every defect found in this file as real and
  // customer-facing, not latent.
  const safeId = safeStr(reportId || "", 30);

  if (!safeId || !/^rpt_[a-f0-9]{16}$/.test(safeId)) {
    return _json({ error: "invalid_report_id", request_id: rid }, 400);
  }

  if (tier === "free") {
    return _json({ error: "tier_required", upgrade_url: "/upgrade.html?plan=pro", request_id: rid }, 403);
  }

  try {
    if (env?.INTEL_R2) {
      const obj = await env.INTEL_R2.get(`${REPORT_CONFIG.R2_PREFIX}${safeId}.json`);
      if (obj) {
        // TENANT-ISOLATION FIX (CodeRabbit, PR #242 pre-merge review): two
        // compounded bugs here -- (1) `auth.key_id` does not exist on
        // resolveAuth()'s return object (index.js:328-382), so this
        // ownership check never activated for any real request; (2) even
        // with the field name fixed, the old code read `data.metadata.key_id`
        // -- the report BODY's own `metadata` object (platform_version,
        // dashboard_url, pdf_download_url, etc.) -- which never had a
        // key_id field at all; the real owner was only ever written to the
        // R2 OBJECT's customMetadata (a separate side-channel from the JSON
        // body), in handlePremiumReport above. Fixed to read
        // obj.customMetadata.key_id and compare against auth.sub (the
        // correct per-customer identity), and to fail closed: a report
        // with no recorded owner, or a requester that doesn't match it, is
        // treated as not found rather than allowed through.
        const ownerId = obj.customMetadata?.key_id || "";
        if (!auth.is_admin && (!ownerId || ownerId !== (auth.sub || ""))) {
          return _json({ error: "not_found", request_id: rid }, 404);
        }
        const data = await obj.json();
        return _json(data);
      }
    }
  } catch { /* Fall through to 404 */ }

  return _json({ error: "report_not_found", report_id: safeId, request_id: rid }, 404);
}
