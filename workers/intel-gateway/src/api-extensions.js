// =============================================================================
// CYBERDUDEBIVASH® SENTINEL APEX — API Extensions v123.2.0
// Missing endpoints: /api/search · /api/actors · /api/cves · /api/export/misp
// Scopes system: read:intel · read:stix · export:misp · read:actors · admin:keys
// Abuse detection · Request fingerprinting · Advanced filtering
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

// ─────────────────────────────────────────────────────────────────────────────
// SCOPES SYSTEM
// JWT payload carries: { scopes: ["read:intel","read:stix","export:misp"] }
// API key record carries: scopes array
// Default scopes by tier:
//   free:       ["read:intel:preview"]
//   premium:    ["read:intel","read:stix","read:actors","export:csv"]
//   enterprise: ["read:intel","read:stix","read:actors","export:misp","export:csv","admin:webhooks"]
// ─────────────────────────────────────────────────────────────────────────────

export const SCOPE_DEFINITIONS = {
  "read:intel:preview": { tier: "free",       desc: "Public feed preview (10 items)"          },
  "read:intel":         { tier: "premium",     desc: "Full authenticated feed access"          },
  "read:stix":          { tier: "premium",     desc: "STIX 2.1 bundle metadata access"        },
  "read:stix:full":     { tier: "enterprise",  desc: "Full STIX 2.1 bundle export"            },
  "read:actors":        { tier: "premium",     desc: "Threat actor profiles + TTPs"           },
  "read:cves":          { tier: "premium",     desc: "CVE deep-dive with EPSS + KEV + NVD"    },
  "export:misp":        { tier: "enterprise",  desc: "MISP JSON event export"                 },
  "export:csv":         { tier: "premium",     desc: "IOC CSV bulk export"                    },
  "export:stix:full":   { tier: "enterprise",  desc: "Raw STIX bundle download"               },
  "admin:webhooks":     { tier: "enterprise",  desc: "SIEM webhook management"                },
  "admin:keys":         { tier: "enterprise",  desc: "Sub-key issuance for team"              },
};

export const TIER_DEFAULT_SCOPES = {
  free:       ["read:intel:preview"],
  premium:    ["read:intel","read:stix","read:actors","read:cves","export:csv"],
  enterprise: ["read:intel","read:stix","read:stix:full","read:actors","read:cves","export:misp","export:csv","export:stix:full","admin:webhooks"],
};

export function buildScopeSet(tier, explicitScopes) {
  const defaults = TIER_DEFAULT_SCOPES[(tier||"free").toLowerCase()] || TIER_DEFAULT_SCOPES.free;
  if (Array.isArray(explicitScopes) && explicitScopes.length) {
    // Explicit scopes cannot exceed tier defaults — intersect
    return explicitScopes.filter(s => defaults.includes(s));
  }
  return defaults;
}

// ─── Scope enforcement middleware ─────────────────────────────────────────────
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

    // CVE filter — exact + partial match
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
// MISP JSON Event export — Enterprise only
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
        source:       "CYBERDUDEBIVASH® SENTINEL APEX",
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

// ─── MISP Event Builder ────────────────────────────────────────────────────────
async function buildMISPEvent(item, idx) {
  const uuid     = item.stix_id?.replace("indicator--", "") || await miniHash(item.title + idx);
  const orgId    = "1";
  const now      = new Date().toISOString().slice(0, 10);
  const ts       = Math.floor(new Date(item.processed_at || item.timestamp || new Date()).getTime() / 1000);
  const severity = (item.severity || "unknown").toLowerCase();
  const threatLevel = severity === "critical" ? "1" : severity === "high" ? "2" : severity === "medium" ? "3" : "4";

  const attributes = [];
  let aid = 100 + idx * 100;

  // Title → comment
  attributes.push({
    id: String(aid++), uuid: await miniHash("title" + uuid), type: "comment",
    category: "External analysis", value: item.title || "Untitled",
    comment: "Threat title from SENTINEL APEX", to_ids: false,
  });

  // IOCs → MISP attributes
  for (const ioc of (item.iocs || []).slice(0, 30)) {
    const mispType = iocTypeToMISP(ioc.type);
    if (!mispType) continue;
    attributes.push({
      id: String(aid++), uuid: await miniHash(ioc.value + uuid), type: mispType,
      category: iocCategoryMISP(ioc.type),
      value: ioc.value, comment: `IOC from SENTINEL APEX — confidence: ${ioc.confidence || 0.7}`,
      to_ids: shouldFlagForIDS(ioc.type),
    });
  }

  // CVE → vulnerability attribute
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

  // TTPs → MITRE ATT&CK attribute
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
        { name: `sentinel-apex:source="SENTINEL APEX v123"`, colour: "#0099cc" },
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
// IOC bulk CSV export — Pro+
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
    return null; // Non-critical — let request through on error
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

// GET /api/admin/abuse — abuse dashboard (admin only)
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
    source:       "CYBERDUDEBIVASH® SENTINEL APEX",
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
// REQUEST FINGERPRINTING — for analytics + abuse correlation
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
