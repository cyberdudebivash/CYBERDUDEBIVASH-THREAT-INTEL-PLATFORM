// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX -- API Extensions v134.0.0
// Missing endpoints: /api/search . /api/actors . /api/cves . /api/export/misp
// Scopes system: read:intel . read:stix . export:misp . read:actors . admin:keys
// Abuse detection . Request fingerprinting . Advanced filtering
//
// HOW TO WIRE INTO index.js:
//   import { handleSearch, handleActors, handleCVEs, handleMISPExport,
//            enforceScopeMiddleware, fingerprintRequest, buildScopeSet } from "./api-extensions.js";
//
//   In the authenticated route block, add before the 404 fallback:
//     if (pathname === "/api/search")              return handleSearch(request, env, auth, rid);
//     if (pathname === "/api/actors")              return handleActors(request, env, auth, rid);
//     if (pathname.startsWith("/api/cves"))        return handleCVEs(request, env, auth, rid);
//     if (pathname === "/api/export/misp")         return handleMISPExport(request, env, auth, rid);
//     if (pathname === "/api/export/csv")          return handleCSVExport(request, env, auth, rid);
//     if (pathname === "/api/intel/correlate")     return handleCorrelate(request, env, auth, rid);
// =============================================================================

// 
// SCOPES SYSTEM
// JWT payload carries: { scopes: ["read:intel","read:stix","export:misp"] }
// API key record carries: scopes array
// Default scopes by tier:
//   free:       ["read:intel:preview"]
//   premium:    ["read:intel","read:stix","read:actors","export:csv"]
//   enterprise: ["read:intel","read:stix","read:actors","export:misp","export:csv","admin:webhooks"]
// 

export const SCOPE_DEFINITIONS = {
  "read:intel:preview": { tier: "free",       desc: "Public feed preview (10 items)"                        },
  "read:intel":         { tier: "premium",     desc: "Full authenticated feed access"                        },
  "read:stix":          { tier: "premium",     desc: "STIX 2.1 bundle metadata access"                      },
  "read:stix:full":     { tier: "enterprise",  desc: "Full STIX 2.1 bundle export"                          },
  "read:actors":        { tier: "premium",     desc: "Threat actor profiles + TTPs"                         },
  "read:cves":          { tier: "premium",     desc: "CVE deep-dive with EPSS + KEV + NVD"                  },
  "export:misp":        { tier: "enterprise",  desc: "MISP JSON event export"                               },
  "export:csv":         { tier: "premium",     desc: "IOC CSV bulk export"                                  },
  "export:stix:full":   { tier: "enterprise",  desc: "Raw STIX bundle download"                             },
  "admin:webhooks":     { tier: "enterprise",  desc: "SIEM webhook management"                              },
  "admin:keys":         { tier: "enterprise",  desc: "Sub-key issuance for team"                            },
  //  v134.0.0: AI Intelligence scopes 
  "read:ai:predict":    { tier: "premium",     desc: "AI threat prediction -- CVSS+EPSS+KEV+TTP scoring"     },
  "read:ai:campaigns":  { tier: "premium",     desc: "DBSCAN campaign clustering -- grouped threat actors"   },
  "read:ai:anomalies":  { tier: "premium",     desc: "Isolation Forest anomaly detection + zero-day flags"  },
  "read:intel:graph":   { tier: "premium",     desc: "IOC intelligence graph -- PageRank authority scores"   },
  "read:intel:graph:full": { tier: "enterprise", desc: "Full IOC graph -- all nodes + attribution edges"    },
};

export const TIER_DEFAULT_SCOPES = {
  free:       ["read:intel:preview"],
  premium:    ["read:intel","read:stix","read:actors","read:cves","export:csv",
               "read:ai:predict","read:ai:campaigns","read:ai:anomalies","read:intel:graph"],
  enterprise: ["read:intel","read:stix","read:stix:full","read:actors","read:cves",
               "export:misp","export:csv","export:stix:full","admin:webhooks",
               "read:ai:predict","read:ai:campaigns","read:ai:anomalies",
               "read:intel:graph","read:intel:graph:full"],
};

export function buildScopeSet(tier, explicitScopes) {
  const defaults = TIER_DEFAULT_SCOPES[(tier||"free").toLowerCase()] || TIER_DEFAULT_SCOPES.free;
  if (Array.isArray(explicitScopes) && explicitScopes.length) {
    // Explicit scopes cannot exceed tier defaults -- intersect
    return explicitScopes.filter(s => defaults.includes(s));
  }
  return defaults;
}

//  Scope enforcement middleware 
// Returns null (allowed) or a Response (rejected)
export function enforceScopeMiddleware(auth, requiredScope, rid) {
  const userScopes = auth.scopes || buildScopeSet(auth.tier, null);
  if (userScopes.includes(requiredScope)) return null;
  return extJson({
    error:        "forbidden",
    reason:       "insufficient_scope",
    required:     requiredScope,
    your_scopes:  userScopes,
    upgrade_url:  "https://intel.cyberdudebivash.com/upgrade",
    message:      `Scope '${requiredScope}' required. Your plan: ${auth.tier}. Upgrade to unlock.`,
    request_id:   rid,
  }, 403);
}

// =============================================================================
// ENDPOINT: GET /api/search
// Full-text + field search across the intelligence feed
// Params: q, severity, since, until, cve, actor, type, limit, page
// Scope: read:intel
// =============================================================================
export async function handleSearch(request, env, auth, rid) {
  const scopeErr = enforceScopeMiddleware(auth, "read:intel", rid);
  if (scopeErr) return scopeErr;

  const url     = new URL(request.url);
  const q       = sanitizeParam(url.searchParams.get("q") || "", 128);
  const severity= validateEnum(url.searchParams.get("severity"), ["critical","high","medium","low","info","unknown"], null);
  const since   = url.searchParams.get("since") || null;
  const until   = url.searchParams.get("until") || null;
  const cveFilter = sanitizeParam(url.searchParams.get("cve") || "", 24);
  const actorFilter = sanitizeParam(url.searchParams.get("actor") || "", 64);
  const typeFilter  = validateEnum(url.searchParams.get("type"), ["ransomware","apt","vulnerability","phishing","malware","supply_chain","credential","ddos"], null);
  const limit   = Math.min(parseInt(url.searchParams.get("limit") || "25") || 25, 100);
  const page    = Math.max(parseInt(url.searchParams.get("page")  || "1")  || 1, 1);

  if (!q && !severity && !cveFilter && !actorFilter && !typeFilter) {
    return extJson({ error: "search_requires_param", message: "At least one of: q, severity, cve, actor, type required.", request_id: rid }, 400);
  }

  try {
    const index = await fetchReportsIndexExt(env);
    if (!index?.reports?.length) return extJson({ error: "feed_unavailable" }, 503);

    let results = index.reports;

    // Full-text search across key fields
    if (q) {
      const terms = q.toLowerCase().split(/\s+/).filter(t => t.length > 1);
      results = results.filter(item => {
        const searchable = [
          item.title, item.description, item.summary,
          item.actor_tag, item.cve_id, item.threat_type,
          (item.iocs || []).map(i => i.value).join(" "),
          (item.ttps  || []).map(t => t.technique_id + " " + t.name).join(" "),
        ].filter(Boolean).join(" ").toLowerCase();
        return terms.every(t => searchable.includes(t));
      });
    }

    // CVE filter -- exact + partial match
    if (cveFilter) {
      const cveLow = cveFilter.toLowerCase();
      results = results.filter(item =>
        (item.cve_id || "").toLowerCase().includes(cveLow) ||
        (item.description || "").toLowerCase().includes(cveLow)
      );
    }

    // Severity filter
    if (severity) {
      results = results.filter(item =>
        (item.severity || item.risk_level || "").toLowerCase() === severity
      );
    }

    // Actor filter
    if (actorFilter) {
      const aLow = actorFilter.toLowerCase();
      results = results.filter(item =>
        (item.actor_tag || "").toLowerCase().includes(aLow) ||
        (item.description || "").toLowerCase().includes(aLow)
      );
    }

    // Threat type filter
    if (typeFilter) {
      results = results.filter(item =>
        (item.threat_type || item.category || "").toLowerCase().includes(typeFilter)
      );
    }

    // Date range filter
    if (since || until) {
      const sinceMs = since ? new Date(since).getTime() : 0;
      const untilMs = until ? new Date(until).getTime() : Infinity;
      results = results.filter(item => {
        const ts = new Date(item.processed_at || item.timestamp || 0).getTime();
        return ts >= sinceMs && ts <= untilMs;
      });
    }

    // Sort by risk score desc, then by date
    results.sort((a, b) => {
      const ra = typeof a.risk_score === "number" ? a.risk_score : 0;
      const rb = typeof b.risk_score === "number" ? b.risk_score : 0;
      if (rb !== ra) return rb - ra;
      return new Date(b.processed_at || 0) - new Date(a.processed_at || 0);
    });

    const total     = results.length;
    const offset    = (page - 1) * limit;
    const pageItems = results.slice(offset, offset + limit).map(item => applySearchTierGate(item, auth.tier));

    return extJson({
      status:     "ok",
      query: { q, severity, cve: cveFilter, actor: actorFilter, type: typeFilter, since, until },
      data: {
        results:    pageItems,
        pagination: { page, limit, total, total_pages: Math.ceil(total / limit) || 1, has_next: page < Math.ceil(total / limit) },
      },
      request_id: rid,
    });
  } catch (e) {
    return extJson({ error: "search_failed", message: e.message, request_id: rid }, 500);
  }
}

// =============================================================================
// ENDPOINT: GET /api/actors
// Aggregated threat actor profiles from feed data
// Params: actor_id, limit, since
// Scope: read:actors
// =============================================================================
export async function handleActors(request, env, auth, rid) {
  const scopeErr = enforceScopeMiddleware(auth, "read:actors", rid);
  if (scopeErr) return scopeErr;

  const url      = new URL(request.url);
  const actorId  = sanitizeParam(url.searchParams.get("actor_id") || url.searchParams.get("id") || "", 64);
  const limit    = Math.min(parseInt(url.searchParams.get("limit") || "50") || 50, 200);
  const since    = url.searchParams.get("since") || null;

  try {
    const index = await fetchReportsIndexExt(env);
    if (!index?.reports?.length) return extJson({ error: "feed_unavailable" }, 503);

    // Build actor profiles by aggregating across all feed items
    const actorMap = new Map();
    for (const item of index.reports) {
      const tag = item.actor_tag || item.apex?.actor_tag || "UNATTRIBUTED";
      if (tag === "UNATTRIBUTED") continue;

      // Date filter
      if (since) {
        const ts = new Date(item.processed_at || item.timestamp || 0).getTime();
        if (ts < new Date(since).getTime()) continue;
      }

      if (!actorMap.has(tag)) {
        actorMap.set(tag, {
          actor_id:          slugify(tag),
          name:              tag,
          first_seen:        item.processed_at || item.timestamp || "",
          last_seen:         item.processed_at || item.timestamp || "",
          activity_count:    0,
          max_risk_score:    0,
          avg_risk_score:    0,
          risk_scores:       [],
          severity_counts:   { critical: 0, high: 0, medium: 0, low: 0 },
          ttps:              new Set(),
          ioc_types:         new Set(),
          cves:              new Set(),
          target_sectors:    new Set(),
          campaigns:         new Set(),
          threat_types:      new Set(),
          sample_reports:    [],
        });
      }

      const actor = actorMap.get(tag);
      actor.activity_count++;

      // Track date range
      const ts = item.processed_at || item.timestamp || "";
      if (ts && (!actor.first_seen || ts < actor.first_seen)) actor.first_seen = ts;
      if (ts && (!actor.last_seen  || ts > actor.last_seen))  actor.last_seen  = ts;

      // Risk scoring
      const rs = typeof item.risk_score === "number" ? item.risk_score : 0;
      actor.risk_scores.push(rs);
      if (rs > actor.max_risk_score) actor.max_risk_score = rs;

      // Severity distribution
      const sev = (item.severity || "low").toLowerCase();
      if (actor.severity_counts[sev] !== undefined) actor.severity_counts[sev]++;

      // TTPs
      (item.ttps || []).forEach(t => actor.ttps.add(t.technique_id || t.name || ""));

      // IOC types
      (item.iocs || []).forEach(i => actor.ioc_types.add(i.type || ""));

      // CVEs
      if (item.cve_id) actor.cves.add(item.cve_id);

      // Threat types
      if (item.threat_type) actor.threat_types.add(item.threat_type);

      // Campaign IDs
      if (item.apex?.campaign_id) actor.campaigns.add(item.apex.campaign_id);

      // Sample reports (max 5)
      if (actor.sample_reports.length < 5) {
        actor.sample_reports.push({
          id:        item.stix_id || item.id,
          title:     (item.title || "").slice(0, 120),
          severity:  item.severity || "unknown",
          date:      item.processed_at?.slice(0, 10) || "",
          risk_score: rs,
        });
      }
    }

    // Finalize actor profiles
    let actors = [...actorMap.values()].map(a => {
      const avg = a.risk_scores.length ? (a.risk_scores.reduce((s, v) => s + v, 0) / a.risk_scores.length) : 0;
      return {
        actor_id:          a.actor_id,
        name:              a.name,
        first_seen:        a.first_seen?.slice(0, 10) || "unknown",
        last_seen:         a.last_seen?.slice(0, 10) || "unknown",
        activity_count:    a.activity_count,
        max_risk_score:    parseFloat(a.max_risk_score.toFixed(1)),
        avg_risk_score:    parseFloat(avg.toFixed(1)),
        severity_profile:  a.severity_counts,
        ttps:              [...a.ttps].filter(Boolean).slice(0, 20),
        ttp_count:         a.ttps.size,
        ioc_types:         [...a.ioc_types].filter(Boolean),
        cves:              [...a.cves].filter(Boolean).slice(0, 15),
        threat_types:      [...a.threat_types].filter(Boolean),
        campaigns:         [...a.campaigns].filter(Boolean),
        sample_reports:    a.sample_reports,
        // Enterprise-gated: full TTP breakdown
        ttp_detail:        auth.tier === "enterprise"
          ? [...a.ttps].filter(Boolean)
          : null,
        locked:            auth.tier !== "enterprise",
      };
    });

    // Filter by actor_id if provided
    if (actorId) {
      actors = actors.filter(a =>
        a.actor_id === actorId || a.name.toLowerCase() === actorId.toLowerCase()
      );
    }

    // Sort by activity count desc
    actors.sort((a, b) => b.activity_count - a.activity_count);
    actors = actors.slice(0, limit);

    return extJson({
      status:  "ok",
      data: {
        actors,
        total:        actors.length,
        coverage:     `${actorMap.size} distinct actors tracked in feed`,
      },
      tier:       auth.tier,
      request_id: rid,
    });
  } catch (e) {
    return extJson({ error: "actors_failed", message: e.message, request_id: rid }, 500);
  }
}

// =============================================================================
// ENDPOINT: GET /api/cves[?cve_id=CVE-XXXX-YYYY&severity=&kev_only=&limit=]
// CVE deep-dive: CVSS + EPSS + KEV status + affected reports + IOC correlation
// Scope: read:cves
// =============================================================================
export async function handleCVEs(request, env, auth, rid) {
  const scopeErr = enforceScopeMiddleware(auth, "read:cves", rid);
  if (scopeErr) return scopeErr;

  const url      = new URL(request.url);
  const cveId    = sanitizeParam(url.searchParams.get("cve_id") || url.searchParams.get("id") || "", 24).toUpperCase();
  const severity = validateEnum(url.searchParams.get("severity"), ["critical","high","medium","low"], null);
  const kevOnly  = url.searchParams.get("kev_only") === "true";
  const minEpss  = parseFloat(url.searchParams.get("min_epss") || "0") || 0;
  const limit    = Math.min(parseInt(url.searchParams.get("limit") || "50") || 50, 200);
  const page     = Math.max(parseInt(url.searchParams.get("page") || "1") || 1, 1);

  try {
    const index = await fetchReportsIndexExt(env);
    if (!index?.reports?.length) return extJson({ error: "feed_unavailable" }, 503);

    // Build CVE registry from all feed items
    const cveMap = new Map();
    for (const item of index.reports) {
      const cves = [];
      if (item.cve_id)          cves.push(item.cve_id.toUpperCase());
      if (Array.isArray(item.iocs)) {
        item.iocs.filter(i => i.type === "cve").forEach(i => cves.push(i.value.toUpperCase()));
      }
      // Extract CVEs from title/description
      const text = (item.title + " " + (item.description || "")).toUpperCase();
      const cveMatches = [...text.matchAll(/CVE-\d{4}-\d{4,7}/g)].map(m => m[0]);
      cves.push(...cveMatches);

      for (const cve of [...new Set(cves)]) {
        if (!cve.startsWith("CVE-")) continue;
        if (!cveMap.has(cve)) {
          cveMap.set(cve, {
            cve_id:          cve,
            cvss_score:      item.cvss_score || item.risk_score || null,
            cvss_vector:     item.cvss_vector || null,
            cvss_severity:   item.cvss_severity || item.severity || null,
            epss_score:      item.epss_score   || null,
            epss_percentile: item.epss_percentile || null,
            kev:             item.kev_present === true,
            cisa_kev_date:   item.cisa_kev_date || null,
            affected_products: item.affected_products || [],
            exploit_maturity: item.exploit_maturity || deriveExploitMaturity(item),
            reports:         [],
            ioc_count:       0,
            first_seen:      item.processed_at || item.timestamp || "",
            last_seen:       item.processed_at || item.timestamp || "",
            actor_tags:      new Set(),
          });
        }
        const entry = cveMap.get(cve);
        const ts = item.processed_at || item.timestamp || "";
        if (ts && ts > (entry.last_seen || "")) entry.last_seen = ts;
        if (ts && ts < (entry.first_seen || "9999")) entry.first_seen = ts;

        // Update scores if higher confidence
        if (item.epss_score && (!entry.epss_score || item.epss_score > entry.epss_score)) {
          entry.epss_score = item.epss_score;
        }
        if (item.kev_present === true) entry.kev = true;
        if (item.actor_tag && item.actor_tag !== "UNATTRIBUTED") entry.actor_tags.add(item.actor_tag);
        entry.ioc_count += Array.isArray(item.iocs) ? item.iocs.length : 0;

        if (entry.reports.length < 10) {
          entry.reports.push({
            id:         item.stix_id || item.id,
            title:      (item.title || "").slice(0, 100),
            date:       ts?.slice(0, 10) || "",
            severity:   item.severity || "unknown",
            risk_score: item.risk_score || 0,
          });
        }
      }
    }

    // Finalize CVE entries
    let cves = [...cveMap.values()].map(c => ({
      ...c,
      actor_tags: [...c.actor_tags],
      report_count: c.reports.length,
      // Calculated priority score for sorting
      _priority: ((c.cvss_score || 0) * 0.35) + ((c.epss_score || 0) * 0.25) + (c.kev ? 3.0 : 0),
    }));

    // Apply filters
    if (cveId) {
      cves = cves.filter(c => c.cve_id === cveId || c.cve_id.includes(cveId));
    }
    if (severity) {
      cves = cves.filter(c => (c.cvss_severity || "").toLowerCase() === severity);
    }
    if (kevOnly) {
      cves = cves.filter(c => c.kev === true);
    }
    if (minEpss > 0) {
      cves = cves.filter(c => (c.epss_score || 0) >= minEpss);
    }

    // Sort by priority score
    cves.sort((a, b) => b._priority - a._priority);

    const total  = cves.length;
    const offset = (page - 1) * limit;
    const paged  = cves.slice(offset, offset + limit).map(c => {
      const { _priority, ...clean } = c;
      // Pro-gate: full IOC correlation
      if (auth.tier === "free") {
        clean.reports = clean.reports.slice(0, 2);
        clean.ioc_count = null;
        clean.locked = true;
        clean.upgrade = { message: "Full CVE intel requires Pro.", url: "https://intel.cyberdudebivash.com/upgrade?plan=pro" };
      }
      return clean;
    });

    return extJson({
      status: "ok",
      data: {
        cves:       paged,
        total,
        kev_count:  cves.filter(c => c.kev).length,
        pagination: { page, limit, total, total_pages: Math.ceil(total/limit)||1 },
      },
      request_id: rid,
    });
  } catch (e) {
    return extJson({ error: "cves_failed", message: e.message, request_id: rid }, 500);
  }
}

// =============================================================================
// ENDPOINT: GET /api/export/misp?report_id=&since=&limit=
// MISP JSON Event export -- Enterprise only
// Scope: export:misp
// =============================================================================
export async function handleMISPExport(request, env, auth, rid) {
  const scopeErr = enforceScopeMiddleware(auth, "export:misp", rid);
  if (scopeErr) return scopeErr;

  const url       = new URL(request.url);
  const reportId  = sanitizeParam(url.searchParams.get("report_id") || url.searchParams.get("id") || "", 128);
  const since     = url.searchParams.get("since") || null;
  const limit     = Math.min(parseInt(url.searchParams.get("limit") || "25") || 25, 100);

  try {
    const index = await fetchReportsIndexExt(env);
    if (!index?.reports?.length) return extJson({ error: "feed_unavailable" }, 503);

    let items = index.reports;

    if (reportId) {
      items = items.filter(i => (i.stix_id || i.id || "") === reportId || (i.title || "").toLowerCase().includes(reportId.toLowerCase()));
    }
    if (since) {
      const sinceMs = new Date(since).getTime();
      items = items.filter(i => new Date(i.processed_at || i.timestamp || 0).getTime() >= sinceMs);
    }
    items = items.slice(0, limit);

    // Build MISP Event array
    const mispEvents = await Promise.all(items.map(async (item, idx) => buildMISPEvent(item, idx)));

    // Return as MISP-compatible JSON
    const exportPayload = {
      response: mispEvents,
      meta: {
        generated_at: new Date().toISOString(),
        count:        mispEvents.length,
        source:       "CYBERDUDEBIVASH(R) SENTINEL APEX",
        format:       "MISP 2.4",
        export_scope: "export:misp",
        request_id:   rid,
      },
    };

    return new Response(JSON.stringify(exportPayload, null, 2), {
      status: 200,
      headers: {
        "Content-Type":                "application/json",
        "Content-Disposition":         `attachment; filename="sentinel-apex-misp-${new Date().toISOString().slice(0,10)}.json"`,
        "Cache-Control":               "no-cache, no-store",
        "Access-Control-Allow-Origin": "*",
        "X-Export-Format":             "MISP-2.4",
        "X-Record-Count":              String(mispEvents.length),
      },
    });
  } catch (e) {
    return extJson({ error: "misp_export_failed", message: e.message, request_id: rid }, 500);
  }
}

//  MISP Event Builder 
async function buildMISPEvent(item, idx) {
  const uuid     = item.stix_id?.replace("indicator--", "") || await miniHash(item.title + idx);
  const orgId    = "1";
  const now      = new Date().toISOString().slice(0, 10);
  const ts       = Math.floor(new Date(item.processed_at || item.timestamp || new Date()).getTime() / 1000);
  const severity = (item.severity || "unknown").toLowerCase();
  const threatLevel = severity === "critical" ? "1" : severity === "high" ? "2" : severity === "medium" ? "3" : "4";

  const attributes = [];
  let aid = 100 + idx * 100;

  // Title -> comment
  attributes.push({
    id: String(aid++), uuid: await miniHash("title" + uuid), type: "comment",
    category: "External analysis", value: item.title || "Untitled",
    comment: "Threat title from SENTINEL APEX", to_ids: false,
  });

  // IOCs -> MISP attributes
  for (const ioc of (item.iocs || []).slice(0, 30)) {
    const mispType = iocTypeToMISP(ioc.type);
    if (!mispType) continue;
    attributes.push({
      id: String(aid++), uuid: await miniHash(ioc.value + uuid), type: mispType,
      category: iocCategoryMISP(ioc.type),
      value: ioc.value, comment: `IOC from SENTINEL APEX -- confidence: ${ioc.confidence || 0.7}`,
      to_ids: shouldFlagForIDS(ioc.type),
    });
  }

  // CVE -> vulnerability attribute
  if (item.cve_id) {
    attributes.push({
      id: String(aid++), uuid: await miniHash("cve" + item.cve_id), type: "vulnerability",
      category: "External analysis", value: item.cve_id, to_ids: false,
      comment: `CVSS: ${item.cvss_score || "N/A"} | EPSS: ${item.epss_score || "N/A"} | KEV: ${item.kev_present || false}`,
    });
  }

  // Threat actor
  if (item.actor_tag && item.actor_tag !== "UNATTRIBUTED") {
    attributes.push({
      id: String(aid++), uuid: await miniHash("actor" + item.actor_tag), type: "threat-actor",
      category: "Attribution", value: item.actor_tag, to_ids: false,
    });
  }

  // TTPs -> MITRE ATT&CK attribute
  for (const ttp of (item.ttps || []).slice(0, 10)) {
    if (ttp.technique_id) {
      attributes.push({
        id: String(aid++), uuid: await miniHash("ttp" + ttp.technique_id + uuid), type: "text",
        category: "Attribution", value: `${ttp.technique_id}: ${ttp.name || ""}`, to_ids: false,
        comment: "MITRE ATT&CK technique from SENTINEL APEX",
      });
    }
  }

  return {
    Event: {
      id:            String(1000 + idx),
      uuid,
      info:          item.title || "Sentinel APEX Threat",
      date:          item.processed_at?.slice(0, 10) || now,
      threat_level_id: threatLevel,
      analysis:      "2", // completed
      distribution:  "1", // community
      orgc_id:       orgId,
      org_id:        orgId,
      Attribute:     attributes,
      Tag: [
        { name: `sentinel-apex:severity="${severity}"`, colour: severityColor(severity) },
        { name: `sentinel-apex:source="SENTINEL APEX v134"`, colour: "#0099cc" },
        ...(item.cve_id ? [{ name: `cve:${item.cve_id}`, colour: "#ff4444" }] : []),
        ...(item.kev_present ? [{ name: "cisa:kev", colour: "#ff8c00" }] : []),
        ...(item.actor_tag && item.actor_tag !== "UNATTRIBUTED" ? [{ name: `threat-actor:${item.actor_tag}`, colour: "#9932cc" }] : []),
      ],
      timestamp:    String(ts),
      published:    true,
      locked:       false,
      SharingGroup: {},
      extends_uuid: "",
    },
  };
}

// =============================================================================
// ENDPOINT: GET /api/export/csv
// IOC bulk CSV export -- Pro+
// Scope: export:csv
// =============================================================================
export async function handleCSVExport(request, env, auth, rid) {
  const scopeErr = enforceScopeMiddleware(auth, "export:csv", rid);
  if (scopeErr) return scopeErr;

  const url    = new URL(request.url);
  const since  = url.searchParams.get("since") || null;
  const types  = (url.searchParams.get("types") || "").split(",").filter(Boolean);
  const limit  = Math.min(parseInt(url.searchParams.get("limit") || "500") || 500, 5000);

  try {
    const index = await fetchReportsIndexExt(env);
    if (!index?.reports?.length) return extJson({ error: "feed_unavailable" }, 503);

    let items = index.reports;
    if (since) {
      const sinceMs = new Date(since).getTime();
      items = items.filter(i => new Date(i.processed_at || 0).getTime() >= sinceMs);
    }

    const rows = [
      "ioc_type,ioc_value,confidence,source_report_id,source_title,cve_id,actor_tag,severity,risk_score,processed_at,kev,epss"
    ];

    let count = 0;
    for (const item of items) {
      for (const ioc of (item.iocs || [])) {
        if (types.length && !types.includes(ioc.type)) continue;
        if (count >= limit) break;
        rows.push([
          esc(ioc.type), esc(ioc.value), esc(ioc.confidence || "0.7"),
          esc(item.stix_id || ""), esc(item.title || ""),
          esc(item.cve_id || ""), esc(item.actor_tag || ""),
          esc(item.severity || ""), esc(item.risk_score || "0"),
          esc(item.processed_at?.slice(0, 10) || ""),
          esc(item.kev_present || false), esc(item.epss_score || ""),
        ].join(","));
        count++;
      }
      if (count >= limit) break;
    }

    return new Response(rows.join("\n"), {
      status: 200,
      headers: {
        "Content-Type":                "text/csv",
        "Content-Disposition":         `attachment; filename="sentinel-apex-iocs-${new Date().toISOString().slice(0,10)}.csv"`,
        "Cache-Control":               "no-cache, no-store",
        "Access-Control-Allow-Origin": "*",
        "X-Record-Count":              String(count),
      },
    });
  } catch (e) {
    return extJson({ error: "csv_export_failed", message: e.message, request_id: rid }, 500);
  }
}

// =============================================================================
// ENDPOINT: POST /api/intel/correlate
// Correlate a user-provided IOC against the full feed
// Body: { ioc_value, ioc_type }
// Scope: read:intel
// =============================================================================
export async function handleCorrelate(request, env, auth, rid) {
  const scopeErr = enforceScopeMiddleware(auth, "read:intel", rid);
  if (scopeErr) return scopeErr;

  let body;
  try { body = await request.json(); } catch { return extJson({ error: "invalid_json" }, 400); }

  const iocValue = sanitizeParam(body.ioc_value || "", 256);
  const iocType  = body.ioc_type || "auto";
  if (!iocValue) return extJson({ error: "ioc_value_required" }, 400);

  try {
    const index = await fetchReportsIndexExt(env);
    const matches = [];
    for (const item of (index?.reports || [])) {
      const found = (item.iocs || []).some(i =>
        i.value?.toLowerCase() === iocValue.toLowerCase() ||
        (iocType !== "auto" && i.type === iocType && i.value?.toLowerCase().includes(iocValue.toLowerCase()))
      );
      if (found) {
        matches.push({
          report_id:    item.stix_id || item.id,
          title:        item.title?.slice(0, 120) || "",
          severity:     item.severity || "unknown",
          actor_tag:    item.actor_tag || "UNATTRIBUTED",
          risk_score:   item.risk_score || 0,
          date:         item.processed_at?.slice(0, 10) || "",
          cve_id:       item.cve_id || null,
          ttps:         (item.ttps || []).slice(0, 5),
        });
      }
    }

    const verdict = matches.length === 0 ? "clean"
      : matches.some(m => (m.risk_score || 0) >= 8) ? "malicious"
      : "suspicious";

    return extJson({
      status:          "ok",
      ioc:             { value: iocValue, type: iocType },
      verdict,
      match_count:     matches.length,
      matches:         matches.slice(0, 20),
      recommendation:  verdict === "malicious"
        ? "Block immediately. Seen in critical/high severity threats."
        : verdict === "suspicious"
        ? "Investigate. Seen in medium severity activity."
        : "No match found in current feed.",
      request_id:      rid,
    });
  } catch (e) {
    return extJson({ error: "correlate_failed", message: e.message, request_id: rid }, 500);
  }
}

// =============================================================================
// ABUSE DETECTION MIDDLEWARE
// Call at the TOP of every request, before auth check
// Tracks: rapid requests, key brute force, scanner patterns
// =============================================================================
export async function detectAbuse(request, env, rid) {
  const ip     = request.headers.get("cf-connecting-ip") || "unknown";
  const ua     = request.headers.get("user-agent") || "";
  const path   = new URL(request.url).pathname;

  if (!env?.SECURITY_HUB_KV || ip === "unknown") return null;

  try {
    const minute  = new Date().toISOString().slice(0, 16); // YYYY-MM-DDTHH:MM
    const ipKey   = `abuse:ip:${ip}:${minute}`;
    const cnt     = parseInt(await env.SECURITY_HUB_KV.get(ipKey) || "0") + 1;

    // Hard limit: 200 req/min per IP
    if (cnt > 200) {
      await env.SECURITY_HUB_KV.put(`abuse:ban:${ip}`, "1", { expirationTtl: 3600 });
      await trackAbuseEvent(env, "ip_rate_exceeded", { ip, count: cnt, ua: ua.slice(0, 100) });
      return extJson({
        error:      "rate_exceeded",
        message:    "Too many requests. Your IP has been temporarily blocked.",
        retry_after: 3600,
        request_id: rid,
      }, 429);
    }
    await env.SECURITY_HUB_KV.put(ipKey, String(cnt), { expirationTtl: 120 });

    // Check ban
    const banned = await env.SECURITY_HUB_KV.get(`abuse:ban:${ip}`);
    if (banned) {
      return extJson({ error: "blocked", message: "IP temporarily blocked due to abuse.", request_id: rid }, 403);
    }

    // Scanner detection: known bad UAs
    const BAD_UAS = ["sqlmap","nikto","nmap","masscan","zgrab","nuclei","dirbuster","hydra","metasploit"];
    if (BAD_UAS.some(b => ua.toLowerCase().includes(b))) {
      await trackAbuseEvent(env, "scanner_detected", { ip, ua: ua.slice(0, 100) });
      return extJson({ error: "forbidden", message: "Automated scanning not permitted.", request_id: rid }, 403);
    }

    // Auth brute force: track failed auth attempts
    if (path.startsWith("/auth/") || path.startsWith("/api/auth/")) {
      const authKey  = `abuse:auth:${ip}`;
      const authFail = parseInt(await env.SECURITY_HUB_KV.get(authKey) || "0");
      if (authFail >= 20) {
        await trackAbuseEvent(env, "auth_brute_force", { ip, attempts: authFail });
        return extJson({ error: "too_many_attempts", message: "Too many authentication attempts. Wait 15 minutes.", retry_after: 900, request_id: rid }, 429);
      }
    }

    return null; // Allowed
  } catch {
    return null; // Non-critical -- let request through on error
  }
}

// Track failed auth for brute force detection
export async function trackAuthFailure(env, ip) {
  if (!env?.SECURITY_HUB_KV || !ip) return;
  try {
    const k   = `abuse:auth:${ip}`;
    const cnt = parseInt(await env.SECURITY_HUB_KV.get(k) || "0") + 1;
    await env.SECURITY_HUB_KV.put(k, String(cnt), { expirationTtl: 900 }); // 15min window
  } catch {}
}

async function trackAbuseEvent(env, type, meta) {
  if (!env?.SECURITY_HUB_KV) return;
  try {
    const day = new Date().toISOString().slice(0, 10);
    const k   = `abuse:events:${day}`;
    const rec = await env.SECURITY_HUB_KV.get(k, { type: "json" }) || { events: [] };
    rec.events.push({ ts: new Date().toISOString(), type, ...meta });
    if (rec.events.length > 500) rec.events = rec.events.slice(-500);
    await env.SECURITY_HUB_KV.put(k, JSON.stringify(rec), { expirationTtl: 86400 * 7 });
  } catch {}
}

// GET /api/admin/abuse -- abuse dashboard (admin only)
export async function handleAbuseReport(request, env, rid) {
  const day = new URL(request.url).searchParams.get("date") || new Date().toISOString().slice(0, 10);
  const rec = await env.SECURITY_HUB_KV?.get(`abuse:events:${day}`, { type: "json" }) || { events: [] };
  const bans = await env.SECURITY_HUB_KV?.list({ prefix: "abuse:ban:" });
  return extJson({
    date:         day,
    event_count:  rec.events.length,
    active_bans:  bans?.keys?.length || 0,
    recent_events: rec.events.slice(-50),
    request_id:   rid,
  });
}

// =============================================================================
// ENTERPRISE WEBHOOK PUSH ENGINE
// Called after each R2 sync (from Cloudflare Cron or R2 event trigger)
// Delivers real-time threat notifications to registered SIEM endpoints
// =============================================================================
export async function pushWebhookNotifications(env, newItems) {
  if (!env?.SECURITY_HUB_KV || !newItems?.length) return { pushed: 0, failed: 0 };

  const webhookList = await env.SECURITY_HUB_KV.list({ prefix: "webhook:" });
  if (!webhookList?.keys?.length) return { pushed: 0, skipped: "no_webhooks" };

  let pushed = 0, failed = 0;
  const MAX_CONCURRENT = 10;

  // Filter critical/high items for immediate push
  const urgentItems = newItems.filter(item => {
    const sev = (item.severity || "").toLowerCase();
    return sev === "critical" || sev === "high" || (item.risk_score || 0) >= 7.5;
  });

  const itemsToPush = urgentItems.length > 0 ? urgentItems : newItems.slice(0, 5);

  // Batch webhook deliveries
  const batches = chunkArray(webhookList.keys, MAX_CONCURRENT);
  for (const batch of batches) {
    await Promise.all(batch.map(async (key) => {
      try {
        const wh = await env.SECURITY_HUB_KV.get(key.name, { type: "json" });
        if (!wh?.url || !wh?.active) return;

        const payload = buildWebhookPayload(wh.format || "generic", itemsToPush, wh);
        const sig     = await buildWebhookSignature(JSON.stringify(payload), wh.secret || "");

        const res = await fetch(wh.url, {
          method:  "POST",
          headers: {
            "Content-Type":            "application/json",
            "X-Sentinel-Signature":    sig,
            "X-Sentinel-Version":      "123.0.0",
            "X-Sentinel-Event":        "threat_intelligence_update",
            "User-Agent":              "SENTINEL-APEX-WEBHOOK/123.0",
          },
          body:    JSON.stringify(payload),
          signal:  AbortSignal.timeout(10000),
        });

        if (res.ok) {
          pushed++;
          // Update last push timestamp
          wh.last_push = new Date().toISOString();
          wh.push_count = (wh.push_count || 0) + 1;
          await env.SECURITY_HUB_KV.put(key.name, JSON.stringify(wh), { expirationTtl: 86400 * 365 });
        } else {
          failed++;
          wh.last_error = `HTTP ${res.status}`;
          wh.error_count = (wh.error_count || 0) + 1;
          await env.SECURITY_HUB_KV.put(key.name, JSON.stringify(wh), { expirationTtl: 86400 * 365 });
        }
      } catch (e) {
        failed++;
      }
    }));
  }

  return { pushed, failed, items_sent: itemsToPush.length };
}

function buildWebhookPayload(format, items, wh) {
  const base = {
    source:       "CYBERDUDEBIVASH(R) SENTINEL APEX",
    version:      "123.0.0",
    generated_at: new Date().toISOString(),
    webhook_id:   wh.id || "unknown",
    event:        "threat_intelligence_update",
    item_count:   items.length,
  };

  switch (format) {
    case "splunk": return {
      ...base,
      events: items.map(item => ({
        sourcetype: "_json", source: "sentinel-apex",
        event: { ...formatSplunkEvent(item), _time: new Date(item.processed_at || Date.now()).getTime() / 1000 },
      })),
    };

    case "sentinel": return {
      ...base,
      value: items.map(item => ({
        TimeGenerated:       item.processed_at || new Date().toISOString(),
        ThreatType:          item.threat_type || "Unknown",
        ThreatName:          item.title || "",
        Severity:            item.severity || "unknown",
        ConfidenceScore:     Math.floor((item.confidence || 0.5) * 100),
        RiskScore:           item.risk_score || 0,
        CVE:                 item.cve_id || "",
        ActorTag:            item.actor_tag || "",
        IOCCount:            Array.isArray(item.iocs) ? item.iocs.length : 0,
        IndicatorType:       "ThreatIntelligence",
        ExternalId:          item.stix_id || item.id || "",
      })),
    };

    case "qradar": return {
      ...base,
      events: items.map(item => ({
        "Start Time": new Date(item.processed_at || Date.now()).getTime(),
        "Event Name": item.title || "Threat Intelligence",
        "Severity":   qradarSeverity(item.severity),
        "Source IP":  (item.iocs || []).find(i => i.type === "ipv4")?.value || "0.0.0.0",
        "Category":   "THREAT_INTELLIGENCE",
      })),
    };

    default: return {
      ...base,
      threats: items.map(item => ({
        id:          item.stix_id || item.id,
        title:       item.title,
        severity:    item.severity || "unknown",
        risk_score:  item.risk_score || 0,
        cve_id:      item.cve_id || null,
        actor_tag:   item.actor_tag || "UNATTRIBUTED",
        ioc_count:   Array.isArray(item.iocs) ? item.iocs.length : 0,
        ttps:        (item.ttps || []).slice(0, 5),
        timestamp:   item.processed_at || new Date().toISOString(),
        stix_id:     item.stix_id || null,
      })),
    };
  }
}

async function buildWebhookSignature(body, secret) {
  if (!secret) return "unsigned";
  const enc  = new TextEncoder();
  const key  = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig  = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  return "sha256=" + Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// =============================================================================
// REQUEST FINGERPRINTING -- for analytics + abuse correlation
// =============================================================================
export async function fingerprintRequest(request, env, auth, rid) {
  if (!env?.ANALYTICS_KV) return;
  try {
    const fp = {
      rid,
      key_id:    auth?.key_id || "anon",
      tier:      auth?.tier   || "anon",
      path:      new URL(request.url).pathname,
      method:    request.method,
      country:   request.headers.get("cf-ipcountry") || "unknown",
      ray_id:    request.headers.get("cf-ray") || "",
      ts:        new Date().toISOString(),
    };
    const day   = fp.ts.slice(0, 10);
    const key   = `fingerprint:${day}:${auth?.key_id || "anon"}`;
    const existing = await env.ANALYTICS_KV.get(key, { type: "json" }) || { calls: [], count: 0 };
    existing.count++;
    if (existing.calls.length < 100) existing.calls.push(fp);
    await env.ANALYTICS_KV.put(key, JSON.stringify(existing), { expirationTtl: 86400 * 30 });
  } catch {}
}

// =============================================================================
// HELPERS
// =============================================================================

async function fetchReportsIndexExt(env) {
  // Try KV cache first
  if (env?.SECURITY_HUB_KV) {
    const cached = await env.SECURITY_HUB_KV.get("idx:reports", { type: "json" }).catch(() => null);
    if (cached?.reports?.length) return cached;
  }
  // R2 fallback
  if (env?.INTEL_R2) {
    const obj = await env.INTEL_R2.get("feed_manifest.json").catch(() => null);
    if (obj) {
      const text = await obj.text();
      return JSON.parse(text);
    }
  }
  return null;
}

function applySearchTierGate(item, tier) {
  if (tier === "enterprise" || tier === "premium") return item;
  return {
    ...item,
    iocs: [],
    ioc_count: Array.isArray(item.iocs) ? item.iocs.length : 0,
    stix_bundle: null,
    description: (item.description || "").slice(0, 200) + (item.description?.length > 200 ? "..." : ""),
    locked: true,
  };
}

function deriveExploitMaturity(item) {
  const desc = ((item.title || "") + " " + (item.description || "")).toLowerCase();
  if (desc.includes("actively exploit") || desc.includes("in the wild") || desc.includes("ransomware")) return "active";
  if (desc.includes("poc") || desc.includes("proof-of-concept") || desc.includes("exploit code")) return "poc";
  if (desc.includes("weaponized") || desc.includes("exploit kit") || desc.includes("crimeware")) return "weaponized";
  if (item.kev_present) return "active";
  return "theoretical";
}

function iocTypeToMISP(type) {
  const map = {
    ipv4: "ip-dst", ipv6: "ip-dst", domain: "domain",
    url: "url", email: "email-src", sha256: "sha256",
    md5: "md5", sha1: "sha1", cve: "vulnerability",
  };
  return map[type] || null;
}

function iocCategoryMISP(type) {
  if (["ipv4","ipv6"].includes(type)) return "Network activity";
  if (type === "domain") return "Network activity";
  if (type === "url") return "Network activity";
  if (["sha256","md5","sha1"].includes(type)) return "Payload delivery";
  if (type === "cve") return "External analysis";
  return "Other";
}

function shouldFlagForIDS(type) {
  return ["ipv4","ipv6","domain","url","sha256","md5"].includes(type);
}

function severityColor(sev) {
  return sev === "critical" ? "#ff0000" : sev === "high" ? "#ff8c00" : sev === "medium" ? "#ffd700" : "#00cc00";
}

function qradarSeverity(sev) {
  return sev === "critical" ? 10 : sev === "high" ? 7 : sev === "medium" ? 5 : 3;
}

function formatSplunkEvent(item) {
  return {
    title: item.title, severity: item.severity, risk_score: item.risk_score,
    cve: item.cve_id, actor: item.actor_tag, ioc_count: (item.iocs||[]).length,
  };
}

function sanitizeParam(v, maxLen) {
  return (v || "").replace(/[\x00-\x1F\x7F<>]/g, "").slice(0, maxLen).trim();
}

function validateEnum(val, allowed, fallback) {
  return allowed.includes((val||"").toLowerCase()) ? (val||"").toLowerCase() : fallback;
}

function slugify(str) {
  return (str || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function esc(v) {
  const s = String(v || "");
  return s.includes(",") || s.includes('"') || s.includes("\n")
    ? `"${s.replace(/"/g, '""')}"` : s;
}

function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) chunks.push(arr.slice(i, i + size));
  return chunks;
}

async function miniHash(str) {
  const data = new TextEncoder().encode(String(str));
  const hash = await crypto.subtle.digest("SHA-256", data);
  const hex  = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,"0")).join("");
  // Return in UUID v4 format (for MISP compatibility)
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-4${hex.slice(13,16)}-${hex.slice(16,20)}-${hex.slice(20,32)}`;
}

function extJson(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type":                "application/json",
      "Cache-Control":               "no-cache, no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

// =============================================================================
// 
// AI INTELLIGENCE ENDPOINTS  v134.0.0
// PHASE 2+4: /api/predict . /api/campaigns . /api/anomalies
//            /api/intelligence/graph . /api/intelligence/relations
// 
// =============================================================================

// 
// INTERNAL: fetch the feed manifest from R2 (cached in KV)
// 
async function fetchManifestForAI(env) {
  // Try KV cache first
  if (env.INTEL_KV) {
    try {
      const cached = await env.INTEL_KV.get("ai:manifest_cache", "json");
      if (cached) return cached;
    } catch (_) {}
  }
  // Fall back to R2
  if (env.INTEL_BUCKET) {
    try {
      const obj  = await env.INTEL_BUCKET.get("data/stix/feed_manifest.json");
      if (obj) {
        const data = await obj.json();
        if (env.INTEL_KV) {
          await env.INTEL_KV.put("ai:manifest_cache", JSON.stringify(data), { expirationTtl: 120 });
        }
        return data;
      }
    } catch (_) {}
  }
  return null;
}

// 
// TIER GATE HELPER -- uniform upgrade response
// 
function aiTierReject(tier, endpoint, rid) {
  const upgradePlan = tier === "free" ? "pro" : "enterprise";
  return extJson({
    error:       "tier_restriction",
    endpoint,
    your_tier:   tier,
    required:    tier === "free" ? "pro" : "enterprise",
    message:     `${endpoint} requires ${upgradePlan.toUpperCase()} tier. Upgrade to unlock AI intelligence.`,
    upgrade_url: `https://intel.cyberdudebivash.com/upgrade?plan=${upgradePlan}`,
    request_id:  rid,
  }, 403);
}

// =============================================================================
// ENDPOINT: GET /api/predict
// AI threat prediction for a single intel item or CVE ID
// Tier: PRO + ENTERPRISE (full); FREE -> 403
// Params: cve, title, cvss, epss, kev, sector, actor, ttps (comma-sep)
// =============================================================================
export async function handlePredict(request, env, auth, rid) {
  const tier = (auth.tier || "free").toLowerCase();

  // Scope enforcement
  const scopeErr = enforceScopeMiddleware(auth, "read:intel", rid);
  if (scopeErr) return scopeErr;

  // Tier gate -- FREE blocked
  if (tier === "free") return aiTierReject(tier, "/api/predict", rid);

  const url = new URL(request.url);

  // Accept JSON body or query params
  let params = {};
  if (request.method === "POST") {
    try { params = await request.json(); } catch (_) {}
  } else {
    const sp = url.searchParams;
    params = {
      cve:    sp.get("cve")    || "",
      title:  sp.get("title")  || "",
      cvss:   parseFloat(sp.get("cvss")  || "0"),
      epss:   parseFloat(sp.get("epss")  || "0"),
      kev:    sp.get("kev") === "true",
      sector: sp.get("sector") || "unknown",
      actor:  sp.get("actor")  || "unknown",
      ttps:   (sp.get("ttps") || "").split(",").filter(Boolean),
    };
  }

  // Load manifest to find item by CVE if provided
  let manifestItem = null;
  if (params.cve) {
    try {
      const manifest = await fetchManifestForAI(env);
      if (manifest?.reports) {
        manifestItem = manifest.reports.find(r =>
          (r.iocs?.cve || []).some(c => c.toLowerCase() === params.cve.toLowerCase())
        );
      }
    } catch (_) {}
  }

  // Build prediction response from manifest data + params
  const cvss   = parseFloat(params.cvss || manifestItem?.cvss_score || 0);
  const epss   = parseFloat(params.epss || manifestItem?.epss_score || 0);
  const kev    = params.kev || manifestItem?.kev_present || false;
  const ttps   = params.ttps?.length ? params.ttps : (manifestItem?.mitre_tactics || []);
  const sector = params.sector || manifestItem?.sector || "unknown";
  const actor  = params.actor  || manifestItem?.actor_tag || "unknown";

  // Rule-based prediction (mirrors ThreatPredictor heuristics for Worker context)
  const riskScore   = _computeEdgeRiskScore(cvss, epss, kev, ttps, actor, sector);
  const predicted   = _mapRiskToSeverity(riskScore);
  const trajectory  = _computeTrajectory(cvss, epss, kev);
  const exploit30d  = Math.min(1.0, epss * 0.5 + (kev ? 0.25 : 0) + (cvss / 10) * 0.25);
  const confidence  = _computePredictConfidence(cvss, epss, kev, ttps, manifestItem);

  // ENTERPRISE gets additional signals from stored AI outputs
  let storedPrediction = null;
  if (tier === "enterprise" && manifestItem) {
    storedPrediction = {
      stored_predicted_severity:  manifestItem.predicted_severity  || null,
      stored_risk_trajectory:     manifestItem.risk_trajectory     || null,
      stored_exploitation_30d:    manifestItem.exploitation_30d_prob || null,
      zero_day_probability:       manifestItem.zero_day_probability || 0,
      novelty_score:              manifestItem.novelty_score        || 0,
      anomaly_type:               manifestItem.anomaly_type         || "normal",
    };
  }

  return extJson({
    platform:           "CYBERDUDEBIVASH SENTINEL APEX",
    endpoint:           "/api/predict",
    version:            "123.0.0",
    request_id:         rid,
    tier,
    input: { cve: params.cve, cvss, epss, kev, sector, actor, ttp_count: ttps.length },
    prediction: {
      predicted_severity:           predicted,
      confidence:                   parseFloat(confidence.toFixed(4)),
      risk_trajectory:              trajectory,
      next_30d_exploitation_prob:   parseFloat(exploit30d.toFixed(4)),
      risk_score:                   parseFloat(riskScore.toFixed(2)),
    },
    ...(storedPrediction ? { ai_enrichment: storedPrediction } : {}),
    manifest_item_found: !!manifestItem,
    generated_at:        new Date().toISOString(),
    upgrade_note: tier === "premium"
      ? "Upgrade to Enterprise for full AI enrichment + zero-day signals."
      : null,
  });
}

// =============================================================================
// ENDPOINT: GET /api/campaigns
// Returns detected threat campaigns from the intelligence feed
// Tier: PRO + ENTERPRISE (full); FREE -> 403
// Params: limit, severity, actor, since
// =============================================================================
export async function handleCampaigns(request, env, auth, rid) {
  const tier = (auth.tier || "free").toLowerCase();

  const scopeErr = enforceScopeMiddleware(auth, "read:intel", rid);
  if (scopeErr) return scopeErr;

  if (tier === "free") return aiTierReject(tier, "/api/campaigns", rid);

  const url = new URL(request.url);
  const limit    = Math.min(parseInt(url.searchParams.get("limit") || "25") || 25, tier === "enterprise" ? 500 : 100);
  const severity = url.searchParams.get("severity") || null;
  const actor    = url.searchParams.get("actor")    || null;
  const since    = url.searchParams.get("since")    || null;

  // Try to fetch stored campaigns from R2
  let campaigns = [];
  try {
    if (env.INTEL_BUCKET) {
      const obj = await env.INTEL_BUCKET.get("data/ai/campaigns.json");
      if (obj) {
        const data = await obj.json();
        campaigns = data.campaigns || [];
      }
    }
  } catch (_) {}

  // Fallback: derive campaigns from manifest ai fields
  if (!campaigns.length) {
    try {
      const manifest = await fetchManifestForAI(env);
      const reports  = manifest?.reports || [];
      const byId     = {};
      for (const r of reports) {
        if (!r.campaign_id) continue;
        if (!byId[r.campaign_id]) {
          byId[r.campaign_id] = {
            campaign_id:     r.campaign_id,
            campaign_name:   r.campaign_name || r.campaign_id,
            threat_level:    r.severity?.toLowerCase() || "medium",
            actor_hypothesis: r.actor_tag || "unknown",
            item_count:      0,
            member_titles:   [],
            common_ttps:     [],
            confidence:      0,
          };
        }
        byId[r.campaign_id].item_count++;
        byId[r.campaign_id].member_titles.push((r.title || "").slice(0, 80));
        for (const t of (r.mitre_tactics || [])) {
          if (!byId[r.campaign_id].common_ttps.includes(t)) byId[r.campaign_id].common_ttps.push(t);
        }
        byId[r.campaign_id].confidence = Math.max(byId[r.campaign_id].confidence, r.confidence_score || 0);
      }
      campaigns = Object.values(byId);
    } catch (_) {}
  }

  // Filter
  if (severity) campaigns = campaigns.filter(c => c.threat_level === severity.toLowerCase());
  if (actor)    campaigns = campaigns.filter(c => (c.actor_hypothesis || "").toLowerCase().includes(actor.toLowerCase()));
  if (since) {
    const sinceTs = new Date(since).getTime();
    campaigns = campaigns.filter(c => !c.start_date || new Date(c.start_date).getTime() >= sinceTs);
  }

  campaigns.sort((a, b) => (b.item_count || 0) - (a.item_count || 0));
  const page_data = campaigns.slice(0, limit);

  // Free fields for PRO; enterprise gets full member_titles
  if (tier !== "enterprise") {
    page_data.forEach(c => { c.member_titles = c.member_titles?.slice(0, 3); });
  }

  return extJson({
    platform:     "CYBERDUDEBIVASH SENTINEL APEX",
    endpoint:     "/api/campaigns",
    request_id:   rid,
    tier,
    total:        campaigns.length,
    returned:     page_data.length,
    campaigns:    page_data,
    generated_at: new Date().toISOString(),
    upgrade_note: tier === "premium"
      ? "Enterprise unlocks full member lists, STIX campaign export, and webhook push."
      : null,
  });
}

// =============================================================================
// ENDPOINT: GET /api/anomalies
// Returns anomalous / zero-day candidate items flagged by AnomalyDetector
// Tier: PRO + ENTERPRISE; FREE -> 403
// Params: limit, type, min_zd_prob, min_novelty
// =============================================================================
export async function handleAnomalies(request, env, auth, rid) {
  const tier = (auth.tier || "free").toLowerCase();

  const scopeErr = enforceScopeMiddleware(auth, "read:intel", rid);
  if (scopeErr) return scopeErr;

  if (tier === "free") return aiTierReject(tier, "/api/anomalies", rid);

  const url = new URL(request.url);
  const limit       = Math.min(parseInt(url.searchParams.get("limit") || "25") || 25, tier === "enterprise" ? 500 : 100);
  const typeFilter  = url.searchParams.get("type") || null;   // potential_zero_day, critical_velocity, etc.
  const minZdProb   = parseFloat(url.searchParams.get("min_zd_prob") || "0");
  const minNovelty  = parseFloat(url.searchParams.get("min_novelty") || "0");

  // Fetch anomalies from manifest
  let anomalies = [];
  try {
    const manifest = await fetchManifestForAI(env);
    const reports  = manifest?.reports || [];
    for (const r of reports) {
      if (!r.is_anomaly) continue;
      anomalies.push({
        intel_id:             r.intel_id || r.stix_id || "",
        title:                (r.title || "").slice(0, 120),
        anomaly_type:         r.anomaly_type    || "pattern_deviation",
        anomaly_score:        r.anomaly_score   || 0,
        zero_day_probability: r.zero_day_probability || 0,
        novelty_score:        r.novelty_score   || 0,
        severity:             r.severity        || "unknown",
        risk_score:           r.risk_score      || 0,
        cvss_score:           r.cvss_score,
        epss_score:           r.epss_score,
        kev_present:          r.kev_present     || false,
        actor_tag:            r.actor_tag       || "unknown",
        feed_source:          r.feed_source     || "",
        timestamp:            r.timestamp       || "",
        zero_day_indicators:  tier === "enterprise" ? (r.zero_day_indicators || []) : undefined,
        recommended_action:   tier === "enterprise" ? _zdRecommendation(r.zero_day_probability || 0) : undefined,
      });
    }
  } catch (_) {}

  // Apply filters
  if (typeFilter)   anomalies = anomalies.filter(a => a.anomaly_type === typeFilter);
  if (minZdProb)    anomalies = anomalies.filter(a => a.zero_day_probability >= minZdProb);
  if (minNovelty)   anomalies = anomalies.filter(a => a.novelty_score >= minNovelty);

  // Sort by zero_day_probability DESC, then novelty_score DESC
  anomalies.sort((a, b) =>
    (b.zero_day_probability - a.zero_day_probability) || (b.novelty_score - a.novelty_score)
  );
  const page_data = anomalies.slice(0, limit);

  return extJson({
    platform:     "CYBERDUDEBIVASH SENTINEL APEX",
    endpoint:     "/api/anomalies",
    request_id:   rid,
    tier,
    total:        anomalies.length,
    returned:     page_data.length,
    anomalies:    page_data,
    temporal_spike_detected: false,  // populated from KV when pipeline runs
    generated_at: new Date().toISOString(),
    upgrade_note: tier === "premium"
      ? "Enterprise unlocks zero-day indicators, recommended actions, and SIEM webhook for real-time anomaly push."
      : null,
  });
}

// =============================================================================
// ENDPOINT: GET /api/intelligence/graph
// Returns the IOC relationship graph summary + top nodes
// Tier: ENTERPRISE only; PRO gets summary; FREE -> 403
// =============================================================================
export async function handleIntelGraph(request, env, auth, rid) {
  const tier = (auth.tier || "free").toLowerCase();

  const scopeErr = enforceScopeMiddleware(auth, "read:intel", rid);
  if (scopeErr) return scopeErr;

  if (tier === "free") return aiTierReject(tier, "/api/intelligence/graph", rid);

  const url   = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50") || 50, tier === "enterprise" ? 1000 : 100);

  // Fetch stored graph data from R2
  let graphData = null;
  try {
    if (env.INTEL_BUCKET) {
      const obj = await env.INTEL_BUCKET.get("data/ai/intel_graph.json");
      if (obj) graphData = await obj.json();
    }
  } catch (_) {}

  // Fallback: derive graph summary from manifest IOCs
  if (!graphData) {
    try {
      const manifest = await fetchManifestForAI(env);
      const reports  = manifest?.reports || [];
      const iocIndex = {};
      let totalEdges = 0;

      for (const r of reports) {
        const iocs_flat = _flattenManifestIOCs(r.ioc_counts || {});
        for (const ioc of iocs_flat) {
          if (!iocIndex[ioc]) iocIndex[ioc] = { value: ioc, sources: [], confidence: 0, tags: [] };
          iocIndex[ioc].sources.push(r.feed_source || "unknown");
          iocIndex[ioc].confidence = Math.max(iocIndex[ioc].confidence, r.confidence_score || 0);
          if (r.actor_tag && !iocIndex[ioc].tags.includes(r.actor_tag)) iocIndex[ioc].tags.push(r.actor_tag);
        }
        totalEdges += iocs_flat.length;
      }

      graphData = {
        node_count:           Object.keys(iocIndex).length,
        edge_count:           totalEdges,
        high_confidence_nodes: Object.values(iocIndex).filter(n => n.confidence >= 75).length,
        sources_active:       ["manifest_feed"],
        generated_at:         new Date().toISOString(),
        nodes:                tier === "enterprise"
          ? Object.values(iocIndex).slice(0, limit)
          : null,
      };
    } catch (_) {
      graphData = { node_count: 0, edge_count: 0, error: "graph_unavailable" };
    }
  }

  // PRO gets summary only; ENTERPRISE gets full node list
  const response = {
    platform:     "CYBERDUDEBIVASH SENTINEL APEX",
    endpoint:     "/api/intelligence/graph",
    request_id:   rid,
    tier,
    graph_summary: {
      node_count:            graphData.node_count || 0,
      edge_count:            graphData.edge_count || 0,
      high_confidence_nodes: graphData.high_confidence_nodes || 0,
      sources_active:        graphData.sources_active || [],
    },
    generated_at: new Date().toISOString(),
  };

  if (tier === "enterprise") {
    response.nodes = (graphData.nodes || []).slice(0, limit);
    response.node_type_breakdown = graphData.node_type_breakdown || {};
    response.avg_confidence = graphData.avg_confidence || 0;
    response.graph_path = graphData.graph_path || null;
  } else {
    response.upgrade_note = "Enterprise unlocks full graph node export, edge relationships, and actor attribution paths.";
  }

  return extJson(response);
}

// =============================================================================
// ENDPOINT: GET /api/intelligence/relations
// Returns relationships for a specific IOC (BFS traversal from intel graph)
// Tier: ENTERPRISE only; PRO -> summary; FREE -> 403
// Params: ioc (required), depth (1-3)
// =============================================================================
export async function handleIntelRelations(request, env, auth, rid) {
  const tier = (auth.tier || "free").toLowerCase();

  const scopeErr = enforceScopeMiddleware(auth, "read:intel", rid);
  if (scopeErr) return scopeErr;

  if (tier === "free") return aiTierReject(tier, "/api/intelligence/relations", rid);

  const url   = new URL(request.url);
  const ioc   = url.searchParams.get("ioc") || "";
  const depth = Math.min(parseInt(url.searchParams.get("depth") || "2") || 2, tier === "enterprise" ? 3 : 2);

  if (!ioc) {
    return extJson({ error: "missing_param", message: "'ioc' query parameter required.", request_id: rid }, 400);
  }

  // Fetch from stored graph or derive from manifest
  let relations = [];
  let attribution = null;
  try {
    if (env.INTEL_BUCKET) {
      const obj = await env.INTEL_BUCKET.get("data/ai/intel_graph.json");
      if (obj) {
        const gd  = await obj.json();
        const nodes = gd.nodes || {};
        // Find the IOC node
        const iocLower = ioc.toLowerCase();
        const matchedNodes = Object.values(nodes).filter(n =>
          (n.value || "").toLowerCase() === iocLower
        );
        if (matchedNodes.length) {
          // Return its direct edges (simplified -- full graph traversal is server-side)
          const edges = gd.edges || [];
          const matchedIds = matchedNodes.map(n => n.id);
          relations = edges.filter(e =>
            matchedIds.includes(e.source_id) || matchedIds.includes(e.target_id)
          ).slice(0, 50);
          attribution = matchedNodes[0];
        }
      }
    }
  } catch (_) {}

  // Fallback: search manifest for IOC co-occurrences
  if (!relations.length) {
    try {
      const manifest  = await fetchManifestForAI(env);
      const reports   = manifest?.reports || [];
      const iocLower  = ioc.toLowerCase();
      const coItems   = reports.filter(r => {
        const counts = r.ioc_counts || {};
        const flat   = Object.values(counts).flat ? Object.values(counts).flat() : [];
        return JSON.stringify(r).toLowerCase().includes(iocLower);
      }).slice(0, 10);

      for (const r of coItems) {
        relations.push({
          type:        "FOUND_IN",
          intel_id:    r.intel_id || r.stix_id,
          title:       (r.title || "").slice(0, 80),
          actor:       r.actor_tag || "unknown",
          severity:    r.severity  || "unknown",
          timestamp:   r.timestamp || "",
          campaign_id: r.campaign_id || null,
        });
      }
    } catch (_) {}
  }

  return extJson({
    platform:    "CYBERDUDEBIVASH SENTINEL APEX",
    endpoint:    "/api/intelligence/relations",
    request_id:  rid,
    tier,
    ioc,
    depth,
    relation_count: relations.length,
    relations:   tier === "enterprise" ? relations : relations.slice(0, 5),
    attribution: tier === "enterprise" ? attribution : null,
    generated_at: new Date().toISOString(),
    upgrade_note: tier === "premium"
      ? "Enterprise unlocks full BFS graph traversal, actor attribution paths, and raw STIX relationship objects."
      : null,
  });
}

// =============================================================================
// INTERNAL HELPERS -- Edge-side computation (mirrors Python AI heuristics)
// =============================================================================

function _computeEdgeRiskScore(cvss, epss, kev, ttps, actor, sector) {
  const KNOWN_HIGH_ACTORS = ["apt28","apt29","apt41","lazarus","fin7","sandworm","lockbit","blackcat","revil","turla"];
  const CRITICAL_SECTORS  = ["healthcare","finance","energy","government","defense","critical_infrastructure"];

  let score = 0;
  score += (cvss  / 10.0) * 3.0;     // 0-3 pts from CVSS
  score += epss   * 2.0;              // 0-2 pts from EPSS
  score += kev    ? 2.0 : 0;         // 2 pts if KEV
  score += Math.min(ttps.length, 10) * 0.15;  // 0-1.5 pts from TTP count

  const actorLow = (actor || "").toLowerCase();
  if (KNOWN_HIGH_ACTORS.some(a => actorLow.includes(a))) score += 0.8;

  const sectorLow = (sector || "").toLowerCase();
  if (CRITICAL_SECTORS.some(s => sectorLow.includes(s))) score += 0.5;

  return Math.min(10.0, score);
}

function _mapRiskToSeverity(riskScore) {
  if (riskScore >= 9.0) return "critical";
  if (riskScore >= 7.0) return "high_risk";
  if (riskScore >= 4.0) return "medium_risk";
  return "low_risk";
}

function _computeTrajectory(cvss, epss, kev) {
  if (kev && cvss >= 9.0 && epss >= 0.70) return "rapidly_escalating";
  if (cvss >= 7.0 && epss >= 0.40)        return "escalating";
  if (cvss < 4.0 && epss < 0.05)          return "declining";
  return "stable";
}

function _computePredictConfidence(cvss, epss, kev, ttps, manifestItem) {
  let conf = 0.50;
  if (cvss > 0)  conf += 0.10;
  if (epss > 0)  conf += 0.08;
  if (kev)       conf += 0.15;
  conf += Math.min(ttps.length * 0.02, 0.10);
  if (manifestItem) conf += 0.12;
  return Math.min(0.97, conf);
}

function _zdRecommendation(zdProb) {
  if (zdProb >= 0.85) return "IMMEDIATE: Treat as probable zero-day. Activate threat hunting, isolate exposed assets, escalate to CISO.";
  if (zdProb >= 0.55) return "HIGH PRIORITY: Monitor for CVE assignment. Apply IOC-based blocking. Increase logging verbosity.";
  if (zdProb >= 0.20) return "WATCH: Track for CVE publication. Review vendor advisories. Apply least-privilege controls.";
  return "ROUTINE: Standard triage and prioritisation procedures apply.";
}

function _flattenManifestIOCs(iocCounts) {
  // iocCounts is a dict of {type: count} -- we return placeholder values for graph
  // In production this would reference actual IOC values stored separately
  return Object.keys(iocCounts).filter(k => iocCounts[k] > 0);
}
