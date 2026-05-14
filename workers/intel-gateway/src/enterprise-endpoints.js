// =============================================================================
// CYBERDUDEBIVASH(R) SENTINEL APEX  -  Enterprise API Endpoints v149.0.0
// =============================================================================
// NEW ENTERPRISE FEATURES:
//   /api/taxii/*              TAXII 2.1 protocol (ENTERPRISE tier)
//   /api/misp/export          MISP JSON export (ENTERPRISE tier)
//   /api/sigma/bulk           Bulk Sigma rules download (PRO + ENTERPRISE)
//   /api/yara/bulk            Bulk YARA rules download (ENTERPRISE tier)
//   /api/scoring              Enterprise intelligence scoring API
//   /api/scoring/kev          KEV-prioritised scoring feed
//   /api/scoring/ransomware   Ransomware affinity scoring feed
//   /api/scoring/velocity     Threat velocity feed
//   /api/webhooks/*           Webhook subscription management (ENTERPRISE)
//   /api/siem/splunk          Splunk-ready IOC/event feed
//   /api/siem/sentinel        Microsoft Sentinel watchlist format
//   /api/siem/qradar          IBM QRadar reference set format
//   /api/stream               Server-Sent Events threat streaming (ENTERPRISE)
//   /api/mssp/*               MSSP multi-tenant intelligence routing
// =============================================================================

const ENTERPRISE_VERSION = "149.0.0";

// -----------------------------------------------------------------------------
// TIER GATES
// -----------------------------------------------------------------------------

function requireEnterprise(tier) {
  return tier === "enterprise";
}

function requireProOrEnterprise(tier) {
  return tier === "pro" || tier === "premium" || tier === "enterprise";
}

function enterpriseDenied(endpoint, req_id) {
  return new Response(JSON.stringify({
    error: "tier_insufficient",
    message: "This endpoint requires an ENTERPRISE API subscription.",
    endpoint,
    tier_required: "ENTERPRISE",
    acquire_key: "https://intel.cyberdudebivash.com/upgrade.html?plan=enterprise",
    upgrade_url: "/upgrade.html?plan=enterprise",
    docs: "https://intel.cyberdudebivash.com/api-docs",
    request_id: req_id,
  }), {
    status: 403,
    headers: { "Content-Type": "application/json", "X-Request-ID": req_id },
  });
}

function proDenied(endpoint, req_id) {
  return new Response(JSON.stringify({
    error: "tier_insufficient",
    message: "This endpoint requires a PRO or ENTERPRISE API subscription.",
    endpoint,
    tier_required: "PRO",
    acquire_key: "https://intel.cyberdudebivash.com/upgrade.html?plan=pro",
    upgrade_url: "/upgrade.html?plan=pro",
    docs: "https://intel.cyberdudebivash.com/api-docs",
    request_id: req_id,
  }), {
    status: 403,
    headers: { "Content-Type": "application/json", "X-Request-ID": req_id },
  });
}

// -----------------------------------------------------------------------------
// TAXII 2.1  -  THREAT INTELLIGENCE SHARING PROTOCOL
// Spec: https://docs.oasis-open.org/cti/taxii/v2.1/
// -----------------------------------------------------------------------------

/**
 * GET /api/taxii/
 * TAXII 2.1 Server Discovery endpoint.
 * Returns server capabilities and available API roots.
 */
export async function handleTaxiiDiscovery(req, env, ctx, tier, req_id) {
  if (!requireProOrEnterprise(tier)) {
    return proDenied("/api/taxii/", req_id);
  }
  const discovery = {
    title: "CYBERDUDEBIVASH(R) SENTINEL APEX TAXII 2.1 Server",
    description: "Enterprise cyber threat intelligence via TAXII 2.1 protocol. " +
      "Compatible with OpenCTI, MISP, Splunk, Microsoft Sentinel, and IBM QRadar.",
    contact: "enterprise@cyberdudebivash.in",
    default: "/api/taxii/root/",
    api_roots: [
      "https://intel.cyberdudebivash.com/api/taxii/root/",
    ],
    spec_version: "2.1",
    _sentinel_apex_version: ENTERPRISE_VERSION,
  };
  return new Response(JSON.stringify(discovery), {
    status: 200,
    headers: {
      "Content-Type": "application/taxii+json;version=2.1",
      "X-TAXII-Date-Added-First": new Date().toISOString(),
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/taxii/root/
 * TAXII 2.1 API Root information.
 */
export async function handleTaxiiRoot(req, env, ctx, tier, req_id) {
  if (!requireProOrEnterprise(tier)) {
    return proDenied("/api/taxii/root/", req_id);
  }
  const root = {
    title: "SENTINEL APEX Threat Intelligence",
    description: "Live threat feed: 100+ advisories/day, IOCs, TTPs, STIX 2.1 bundles.",
    versions: ["taxii-2.1"],
    max_content_length: 67108864,
    _sentinel_apex_version: ENTERPRISE_VERSION,
  };
  return new Response(JSON.stringify(root), {
    status: 200,
    headers: {
      "Content-Type": "application/taxii+json;version=2.1",
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/taxii/root/collections/
 * TAXII 2.1 Collections listing.
 */
export async function handleTaxiiCollections(req, env, ctx, tier, req_id) {
  if (!requireProOrEnterprise(tier)) {
    return proDenied("/api/taxii/root/collections/", req_id);
  }
  const collections = {
    collections: [
      {
        id: "sentinel-apex-full",
        title: "SENTINEL APEX Full Intelligence Feed",
        description: "Complete threat intelligence: CVEs, APT campaigns, malware, ransomware, IOCs, TTPs.",
        can_read: true,
        can_write: false,
        media_types: ["application/stix+json;version=2.1"],
        _tier: requireEnterprise(tier) ? "enterprise" : "pro",
      },
      {
        id: "sentinel-apex-kev",
        title: "SENTINEL APEX KEV-Confirmed Feed",
        description: "CISA KEV-confirmed exploitation only. Highest-priority emergency patching feed.",
        can_read: true,
        can_write: false,
        media_types: ["application/stix+json;version=2.1"],
        _tier: "enterprise",
        _requires_enterprise: !requireEnterprise(tier),
      },
      {
        id: "sentinel-apex-critical",
        title: "SENTINEL APEX Critical Severity Feed",
        description: "CRITICAL severity advisories only. Zero-day, RCE, and auth bypass focus.",
        can_read: true,
        can_write: false,
        media_types: ["application/stix+json;version=2.1"],
        _tier: requireEnterprise(tier) ? "enterprise" : "pro",
      },
      {
        id: "sentinel-apex-ransomware",
        title: "SENTINEL APEX Ransomware Intelligence Feed",
        description: "Ransomware group activity, RaaS campaigns, double-extortion IOCs.",
        can_read: requireEnterprise(tier),
        can_write: false,
        media_types: ["application/stix+json;version=2.1"],
        _tier: "enterprise",
        _requires_enterprise: !requireEnterprise(tier),
      },
      {
        id: "sentinel-apex-apt",
        title: "SENTINEL APEX APT / Nation-State Feed",
        description: "Nation-state actor TTPs, campaigns, and attribution intelligence.",
        can_read: requireEnterprise(tier),
        can_write: false,
        media_types: ["application/stix+json;version=2.1"],
        _tier: "enterprise",
        _requires_enterprise: !requireEnterprise(tier),
      },
    ],
    _sentinel_apex_version: ENTERPRISE_VERSION,
    _generated_at: new Date().toISOString(),
  };
  return new Response(JSON.stringify(collections), {
    status: 200,
    headers: {
      "Content-Type": "application/taxii+json;version=2.1",
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/taxii/root/collections/:collection_id/objects/
 * TAXII 2.1 Objects from a specific collection.
 */
export async function handleTaxiiObjects(req, env, ctx, tier, collection_id, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied(`/api/taxii/root/collections/${collection_id}/objects/`, req_id);
  }

  const url = new URL(req.url);
  const added_after = url.searchParams.get("added_after") || "";
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 1000);

  // Load STIX data from R2
  let stixBundle = null;
  try {
    const r2Obj = await env.SENTINEL_R2?.get("stix/bundle_latest.json");
    if (r2Obj) {
      stixBundle = await r2Obj.json();
    }
  } catch (_) {}

  if (!stixBundle) {
    // Return minimal valid STIX 2.1 envelope
    stixBundle = { type: "bundle", id: "bundle--apex-empty", spec_version: "2.1", objects: [] };
  }

  let objects = stixBundle.objects || [];

  // Filter by added_after if provided
  if (added_after) {
    try {
      const afterDate = new Date(added_after);
      objects = objects.filter(o => {
        const ts = o.created || o.modified || o.valid_from;
        return ts && new Date(ts) > afterDate;
      });
    } catch (_) {}
  }

  // Filter by collection type
  if (collection_id === "sentinel-apex-kev") {
    objects = objects.filter(o => o.labels && o.labels.includes("kev-confirmed"));
  } else if (collection_id === "sentinel-apex-critical") {
    objects = objects.filter(o => o.labels && o.labels.includes("critical"));
  } else if (collection_id === "sentinel-apex-ransomware") {
    objects = objects.filter(o => o.labels && (
      o.labels.includes("ransomware") || o.labels.includes("ransom")
    ));
  } else if (collection_id === "sentinel-apex-apt") {
    objects = objects.filter(o => o.labels && (
      o.labels.includes("apt") || o.labels.includes("nation-state")
    ));
  }

  const page_objects = objects.slice(0, limit);

  const response = {
    type: "bundle",
    id: `bundle--apex-${collection_id}-${Date.now()}`,
    spec_version: "2.1",
    objects: page_objects,
    _meta: {
      total_count: objects.length,
      returned: page_objects.length,
      collection: collection_id,
      more: objects.length > limit,
      next_added_after: page_objects.length > 0
        ? (page_objects[page_objects.length - 1].created || new Date().toISOString())
        : new Date().toISOString(),
    },
  };

  return new Response(JSON.stringify(response), {
    status: 200,
    headers: {
      "Content-Type": "application/stix+json;version=2.1",
      "X-TAXII-Date-Added-First": objects.length > 0 ? (objects[0].created || "") : "",
      "X-TAXII-Date-Added-Last": objects.length > 0 ? (objects[objects.length - 1].created || "") : "",
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// MISP JSON EXPORT
// -----------------------------------------------------------------------------

/**
 * GET /api/misp/export
 * Export current feed as MISP-compatible JSON event collection.
 * Compatible with MISP 2.4+ direct import.
 */
export async function handleMISPExport(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/misp/export", req_id);
  }

  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 200);
  const severity_filter = (url.searchParams.get("severity") || "").toUpperCase();

  let filtered = items || [];
  if (severity_filter && ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(severity_filter)) {
    filtered = filtered.filter(i => (i.severity || "").toUpperCase() === severity_filter);
  }
  const page = filtered.slice(0, limit);

  const now_epoch = Math.floor(Date.now() / 1000);

  const misp_events = page.map((item, idx) => {
    const sev = (item.severity || "medium").toLowerCase();
    const threat_level_map = { critical: "1", high: "2", medium: "3", low: "4" };
    const threat_level = threat_level_map[sev] || "3";

    const attributes = [];

    // Add IOC attributes
    const iocs = item.iocs || [];
    for (const ioc of iocs) {
      const val = typeof ioc === "string" ? ioc : (ioc.value || ioc.indicator || "");
      if (!val) continue;

      // Classify type for MISP
      let misp_type = "other";
      let misp_cat = "External analysis";
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(val)) {
        misp_type = "ip-dst"; misp_cat = "Network activity";
      } else if (/^[0-9a-fA-F]{64}$/.test(val)) {
        misp_type = "sha256"; misp_cat = "Payload delivery";
      } else if (/^[0-9a-fA-F]{40}$/.test(val)) {
        misp_type = "sha1"; misp_cat = "Payload delivery";
      } else if (/^[0-9a-fA-F]{32}$/.test(val)) {
        misp_type = "md5"; misp_cat = "Payload delivery";
      } else if (/^https?:\/\//.test(val)) {
        misp_type = "url"; misp_cat = "Network activity";
      } else if (/^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(val)) {
        misp_type = "domain"; misp_cat = "Network activity";
      }

      attributes.push({
        uuid: `attr-${item.id || idx}-${attributes.length}`,
        type: misp_type,
        category: misp_cat,
        value: val,
        to_ids: true,
        distribution: "3",
        comment: (typeof ioc === "object" ? (ioc.context || "") : ""),
      });
    }

    // Add CVE attribute
    const cves = item.cve_ids || [];
    for (const cve of cves) {
      attributes.push({
        uuid: `cve-${item.id || idx}-${attributes.length}`,
        type: "vulnerability",
        category: "External analysis",
        value: cve,
        to_ids: false,
        distribution: "3",
      });
    }

    return {
      Event: {
        uuid: item.stix_id || item.id || `event-${idx}`,
        info: item.title || "SENTINEL APEX Advisory",
        threat_level_id: threat_level,
        analysis: "2",  // completed
        date: (item.published_at || new Date().toISOString()).split("T")[0],
        distribution: "3",  // All communities
        timestamp: String(now_epoch),
        Org: { name: "CYBERDUDEBIVASH SENTINEL APEX", uuid: "apex-org-uuid" },
        Orgc: { name: "CYBERDUDEBIVASH SENTINEL APEX", uuid: "apex-org-uuid" },
        Attribute: attributes,
        Tag: [
          { name: `sentinel-apex:severity="${sev}"`, colour: sev === "critical" ? "#ff0000" : "#ff9900" },
          { name: `sentinel-apex:source="${item.source || "APEX"}"` },
          ...(item.tags || []).map(t => ({ name: `mitre-attack:${t}` })),
        ],
        _apex_meta: {
          stix_id: item.stix_id,
          risk_score: item.risk_score,
          kev_present: item.kev_present,
          apex_score: item.apex_score,
        },
      },
    };
  });

  const export_obj = {
    response: misp_events,
    _meta: {
      exported_at: new Date().toISOString(),
      total_items: filtered.length,
      returned: page.length,
      format: "MISP JSON 2.4",
      source: "CYBERDUDEBIVASH SENTINEL APEX",
      version: ENTERPRISE_VERSION,
    },
  };

  return new Response(JSON.stringify(export_obj, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="sentinel-apex-misp-${Date.now()}.json"`,
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// SIGMA BULK EXPORT
// -----------------------------------------------------------------------------

/**
 * GET /api/sigma/bulk
 * Export all Sigma detection rules as a ZIP-ready NDJSON bundle.
 * PRO: latest 50 rules. ENTERPRISE: all rules.
 */
export async function handleSigmaBulk(req, env, ctx, tier, items, req_id) {
  if (!requireProOrEnterprise(tier)) {
    return proDenied("/api/sigma/bulk", req_id);
  }

  const url = new URL(req.url);
  const fmt = (url.searchParams.get("format") || "ndjson").toLowerCase();
  const severity_filter = (url.searchParams.get("severity") || "").toUpperCase();
  const limit = requireEnterprise(tier) ? 2000 : 50;

  let filtered = (items || []).filter(i => i.sigma_rule || (i.detection_rules && i.detection_rules.sigma));
  if (severity_filter) {
    filtered = filtered.filter(i => (i.severity || "").toUpperCase() === severity_filter);
  }
  const page = filtered.slice(0, limit);

  if (fmt === "yaml" || fmt === "sigma") {
    // Return concatenated YAML rules separated by ---
    const rules = page.map(item => {
      const rule = item.sigma_rule || (item.detection_rules && item.detection_rules.sigma) || "";
      return rule.trim();
    }).filter(Boolean).join("\n---\n");

    return new Response(rules, {
      status: 200,
      headers: {
        "Content-Type": "text/yaml",
        "Content-Disposition": `attachment; filename="sentinel-apex-sigma-rules-${Date.now()}.yml"`,
        "X-Sigma-Rules-Count": String(page.length),
        "X-Request-ID": req_id,
      },
    });
  }

  // Default: NDJSON  -  one JSON object per line for streaming ingestion
  const lines = page.map(item => JSON.stringify({
    id: item.id || item.stix_id,
    title: item.title,
    severity: item.severity,
    sigma_rule: item.sigma_rule || (item.detection_rules && item.detection_rules.sigma) || "",
    ttps: item.ttps || [],
    cve_ids: item.cve_ids || [],
    published_at: item.published_at,
    _apex: {
      risk_score: item.risk_score,
      kev: item.kev_present,
      apex_score: item.apex_score,
    },
  }));

  return new Response(lines.join("\n"), {
    status: 200,
    headers: {
      "Content-Type": "application/x-ndjson",
      "Content-Disposition": `attachment; filename="sentinel-apex-sigma-${Date.now()}.ndjson"`,
      "X-Sigma-Rules-Count": String(page.length),
      "X-Tier": tier,
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// YARA BULK EXPORT
// -----------------------------------------------------------------------------

/**
 * GET /api/yara/bulk
 * Bulk YARA rules download. ENTERPRISE only.
 */
export async function handleYaraBulk(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/yara/bulk", req_id);
  }

  const filtered = (items || []).filter(i =>
    i.yara_rule || (i.detection_rules && i.detection_rules.yara)
  );

  const rules = filtered.map(item => {
    return item.yara_rule || (item.detection_rules && item.detection_rules.yara) || "";
  }).filter(Boolean).join("\n\n");

  const header = `// CYBERDUDEBIVASH(R) SENTINEL APEX  -  YARA Intelligence Rules
// Generated: ${new Date().toISOString()}
// Rules: ${filtered.length}
// Platform: SENTINEL APEX v${ENTERPRISE_VERSION}
// License: ENTERPRISE  -  Authorised use only
// Contact: enterprise@cyberdudebivash.in\n\n`;

  return new Response(header + rules, {
    status: 200,
    headers: {
      "Content-Type": "text/plain",
      "Content-Disposition": `attachment; filename="sentinel-apex-yara-${Date.now()}.yar"`,
      "X-YARA-Rules-Count": String(filtered.length),
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// ENTERPRISE INTELLIGENCE SCORING API
// -----------------------------------------------------------------------------

/**
 * GET /api/scoring
 * Full enterprise scoring feed  -  all advisories with 10-dimension scores.
 */
export async function handleScoringFeed(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/scoring", req_id);
  }

  const url = new URL(req.url);
  const min_score = parseInt(url.searchParams.get("min_score") || "0");
  const soc_priority = (url.searchParams.get("soc_priority") || "").toUpperCase();
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 1000);

  let filtered = (items || []).filter(i => i.apex_score);
  if (min_score > 0) {
    filtered = filtered.filter(i => (i.apex_score.apex_enterprise_score || 0) >= min_score);
  }
  if (soc_priority) {
    filtered = filtered.filter(i =>
      (i.apex_score.soc_priority || "").startsWith(soc_priority)
    );
  }

  // Sort by composite enterprise score descending
  filtered.sort((a, b) =>
    (b.apex_score.apex_enterprise_score || 0) - (a.apex_score.apex_enterprise_score || 0)
  );

  const page = filtered.slice(0, limit);

  return new Response(JSON.stringify({
    total: filtered.length,
    returned: page.length,
    tier,
    generated_at: new Date().toISOString(),
    items: page.map(i => ({
      id: i.id,
      stix_id: i.stix_id,
      title: i.title,
      severity: i.severity,
      risk_score: i.risk_score,
      kev_present: i.kev_present,
      apex_score: i.apex_score,
      published_at: i.published_at,
    })),
    _engine: `APEX Scoring Engine v${ENTERPRISE_VERSION}`,
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Scoring-Engine": ENTERPRISE_VERSION,
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/scoring/kev
 * KEV-prioritised scoring  -  sorted by KEV priority score.
 */
export async function handleScoringKEV(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/scoring/kev", req_id);
  }

  const kev_items = (items || [])
    .filter(i => i.kev_present && i.apex_score)
    .sort((a, b) =>
      (b.apex_score.kev_priority_score || 0) - (a.apex_score.kev_priority_score || 0)
    )
    .slice(0, 100)
    .map(i => ({
      id: i.id,
      title: i.title,
      severity: i.severity,
      risk_score: i.risk_score,
      kev_priority_score: i.apex_score?.kev_priority_score || 0,
      patch_urgency_label: i.apex_score?.patch_urgency_label || "Unknown",
      soc_priority: i.apex_score?.soc_priority || "P4",
      patch_urgency_score: i.apex_score?.patch_urgency_score || 0,
      published_at: i.published_at,
    }));

  return new Response(JSON.stringify({
    total_kev_items: kev_items.length,
    generated_at: new Date().toISOString(),
    tier,
    items: kev_items,
    _note: "Sorted by APEX KEV Priority Score (highest first). Emergency patch items at top.",
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-KEV-Items": String(kev_items.length),
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/scoring/ransomware
 * Ransomware affinity scoring feed.
 */
export async function handleScoringRansomware(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/scoring/ransomware", req_id);
  }

  const min_affinity = parseInt(new URL(req.url).searchParams.get("min_affinity") || "30");

  const rw_items = (items || [])
    .filter(i => i.apex_score && (i.apex_score.ransomware_affinity_score || 0) >= min_affinity)
    .sort((a, b) =>
      (b.apex_score.ransomware_affinity_score || 0) - (a.apex_score.ransomware_affinity_score || 0)
    )
    .slice(0, 100)
    .map(i => ({
      id: i.id,
      title: i.title,
      severity: i.severity,
      risk_score: i.risk_score,
      ransomware_affinity_score: i.apex_score?.ransomware_affinity_score || 0,
      ransomware_risk_level: i.apex_score?.ransomware_risk_level || "UNKNOWN",
      business_disruption_score: i.apex_score?.business_disruption_score || 0,
      threat_actor_tier: i.apex_score?.threat_actor_tier || "UNATTRIBUTED",
      soc_priority: i.apex_score?.soc_priority || "P4",
      published_at: i.published_at,
    }));

  return new Response(JSON.stringify({
    total_ransomware_threats: rw_items.length,
    min_affinity_threshold: min_affinity,
    generated_at: new Date().toISOString(),
    tier,
    items: rw_items,
    _note: "Sorted by APEX Ransomware Affinity Score. High scores indicate strong ransomware group linkage.",
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Ransomware-Items": String(rw_items.length),
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/scoring/velocity
 * Threat velocity feed  -  fastest-spreading threats first.
 */
export async function handleScoringVelocity(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/scoring/velocity", req_id);
  }

  const velocity_items = (items || [])
    .filter(i => i.apex_score)
    .sort((a, b) =>
      (b.apex_score.threat_velocity_score || 0) - (a.apex_score.threat_velocity_score || 0)
    )
    .slice(0, 50)
    .map(i => ({
      id: i.id,
      title: i.title,
      severity: i.severity,
      threat_velocity_score: i.apex_score?.threat_velocity_score || 0,
      exploitability_confidence_score: i.apex_score?.exploitability_confidence_score || 0,
      exploit_maturity_score: i.apex_score?.exploit_maturity_score || 0,
      kev_present: i.kev_present,
      ioc_count: i.ioc_count,
      soc_priority: i.apex_score?.soc_priority || "P4",
      published_at: i.published_at,
    }));

  return new Response(JSON.stringify({
    total: velocity_items.length,
    generated_at: new Date().toISOString(),
    tier,
    items: velocity_items,
    _note: "Sorted by APEX Threat Velocity Score. Top items are fastest-spreading/most actively exploited.",
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// SIEM INTEGRATION ENDPOINTS
// -----------------------------------------------------------------------------

/**
 * GET /api/siem/splunk
 * Splunk-ready JSON feed for direct HTTP Event Collector (HEC) ingestion.
 */
export async function handleSiemSplunk(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/siem/splunk", req_id);
  }

  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "100"), 500);
  const page = (items || []).slice(0, limit);

  // Splunk HEC format: one JSON object per event line
  const events = page.map(item => ({
    time: Math.floor(new Date(item.published_at || Date.now()).getTime() / 1000),
    source: "sentinel-apex",
    sourcetype: "sentinel:apex:threat_intel",
    index: "threat_intel",
    event: {
      id: item.id,
      title: item.title,
      severity: item.severity,
      risk_score: item.risk_score,
      cvss_score: item.cvss_score,
      epss_score: item.epss_score,
      kev_present: item.kev_present,
      cve_ids: item.cve_ids || [],
      ttps: (item.ttps || []).slice(0, 10),
      ioc_count: item.ioc_count,
      iocs: (item.iocs || []).slice(0, 20).map(i =>
        typeof i === "string" ? i : (i.value || i.indicator || "")
      ),
      source_feed: item.source,
      actor: item.actor_tag || item.actor_cluster || item.primary_actor,
      sigma_rule_id: item.sigma_rule_id,
      stix_id: item.stix_id,
      apex_enterprise_score: item.apex_score?.apex_enterprise_score,
      soc_priority: item.apex_score?.soc_priority,
      patch_urgency: item.apex_score?.patch_urgency_label,
      threat_velocity: item.apex_score?.threat_velocity_score,
      ransomware_affinity: item.apex_score?.ransomware_affinity_score,
    },
  }));

  const ndjson = events.map(e => JSON.stringify(e)).join("\n");
  return new Response(ndjson, {
    status: 200,
    headers: {
      "Content-Type": "application/x-ndjson",
      "Content-Disposition": `attachment; filename="apex-splunk-hec-${Date.now()}.ndjson"`,
      "X-Event-Count": String(events.length),
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/siem/sentinel
 * Microsoft Sentinel Watchlist-compatible CSV for TI Import.
 */
export async function handleSiemSentinel(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/siem/sentinel", req_id);
  }

  const limit = Math.min(parseInt(new URL(req.url).searchParams.get("limit") || "500"), 2000);
  const page = (items || []).slice(0, limit);

  // Sentinel Threat Intelligence format
  const rows = [
    "IndicatorType,Value,ConfidenceScore,Severity,Description,ThreatType,Tags,ExpirationDateTime,Action,TlpLevel"
  ];

  for (const item of page) {
    const iocs = item.iocs || [];
    const severity = item.severity || "MEDIUM";
    const confidence = Math.min(Math.round((item.apex_score?.exploitability_confidence_score || 50)), 100);
    const tags = `sentinel-apex,${severity.toLowerCase()},${item.source || "apex"}`;
    const expiry = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
    const tlp = item.tlp || "Green";
    const desc = (item.title || "").replace(/,/g, ";").slice(0, 200);

    for (const ioc of iocs.slice(0, 10)) {
      const val = typeof ioc === "string" ? ioc : (ioc.value || ioc.indicator || "");
      if (!val) continue;

      let ioc_type = "Other";
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(val)) ioc_type = "NetworkIP";
      else if (/^[0-9a-fA-F]{64}$/.test(val)) ioc_type = "FileSha256";
      else if (/^[0-9a-fA-F]{40}$/.test(val)) ioc_type = "FileSha1";
      else if (/^[0-9a-fA-F]{32}$/.test(val)) ioc_type = "FileMd5";
      else if (/^https?:\/\//.test(val)) ioc_type = "Url";
      else if (/^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(val)) ioc_type = "DomainName";

      rows.push([ioc_type, val, confidence, severity, desc, item.threat_type || "ThreatIntelligence",
                 tags, expiry, "Block", tlp].map(v => `"${String(v).replace(/"/g, "'")}"`).join(","));
    }
  }

  return new Response(rows.join("\n"), {
    status: 200,
    headers: {
      "Content-Type": "text/csv",
      "Content-Disposition": `attachment; filename="apex-sentinel-watchlist-${Date.now()}.csv"`,
      "X-Row-Count": String(rows.length - 1),
      "X-Request-ID": req_id,
    },
  });
}

/**
 * GET /api/siem/qradar
 * IBM QRadar Reference Set format for IOC ingestion.
 */
export async function handleSiemQRadar(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/siem/qradar", req_id);
  }

  const page = (items || []).slice(0, 500);

  // Collect IOCs by type for QRadar reference sets
  const ip_set = [], domain_set = [], hash_set = [], url_set = [];

  for (const item of page) {
    for (const ioc of (item.iocs || []).slice(0, 20)) {
      const val = typeof ioc === "string" ? ioc : (ioc.value || ioc.indicator || "");
      if (!val) continue;
      if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(val)) ip_set.push(val);
      else if (/^[0-9a-fA-F]{64}$/.test(val)) hash_set.push(val);
      else if (/^https?:\/\//.test(val)) url_set.push(val);
      else if (/^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$/.test(val)) domain_set.push(val);
    }
  }

  return new Response(JSON.stringify({
    sentinel_apex_qradar_export: true,
    generated_at: new Date().toISOString(),
    version: ENTERPRISE_VERSION,
    reference_sets: {
      "SENTINEL-APEX-MALICIOUS-IPs": {
        element_type: "IP",
        elements: [...new Set(ip_set)].slice(0, 2000),
      },
      "SENTINEL-APEX-MALICIOUS-DOMAINS": {
        element_type: "ALN",
        elements: [...new Set(domain_set)].slice(0, 2000),
      },
      "SENTINEL-APEX-MALWARE-HASHES": {
        element_type: "ALN",
        elements: [...new Set(hash_set)].slice(0, 2000),
      },
      "SENTINEL-APEX-MALICIOUS-URLS": {
        element_type: "ALN",
        elements: [...new Set(url_set)].slice(0, 2000),
      },
    },
    _integration_guide: "https://intel.cyberdudebivash.com/api-docs#qradar",
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="apex-qradar-${Date.now()}.json"`,
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// SERVER-SENT EVENTS  -  LIVE THREAT STREAMING
// -----------------------------------------------------------------------------

/**
 * GET /api/stream
 * Server-Sent Events streaming of new threats as they arrive.
 * ENTERPRISE only. Maximum 60-second connection window on Cloudflare Workers.
 */
export async function handleStream(req, env, ctx, tier, items, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied("/api/stream", req_id);
  }

  const url = new URL(req.url);
  const min_severity = (url.searchParams.get("min_severity") || "HIGH").toUpperCase();
  const sev_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const min_idx = sev_order.indexOf(min_severity);

  // Get the 20 most recent qualifying items to stream as initial payload
  const stream_items = (items || [])
    .filter(i => sev_order.indexOf((i.severity || "LOW").toUpperCase()) >= min_idx)
    .sort((a, b) => new Date(b.published_at || 0) - new Date(a.published_at || 0))
    .slice(0, 20);

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();

  ctx.waitUntil((async () => {
    try {
      // Send initial connection event
      await writer.write(encoder.encode(
        `event: connected\ndata: ${JSON.stringify({
          message: "SENTINEL APEX Stream Connected",
          tier,
          min_severity,
          version: ENTERPRISE_VERSION,
          timestamp: new Date().toISOString(),
        })}\n\n`
      ));

      // Stream initial items
      for (const item of stream_items) {
        const payload = {
          id: item.id,
          title: item.title,
          severity: item.severity,
          risk_score: item.risk_score,
          kev_present: item.kev_present,
          ioc_count: item.ioc_count,
          ttps: (item.ttps || []).slice(0, 5),
          apex_enterprise_score: item.apex_score?.apex_enterprise_score,
          soc_priority: item.apex_score?.soc_priority,
          published_at: item.published_at,
        };
        await writer.write(encoder.encode(
          `event: threat\ndata: ${JSON.stringify(payload)}\nid: ${item.id}\n\n`
        ));
      }

      // Keepalive comment every 15s (Workers timeout ~30s on idle SSE)
      await new Promise(resolve => setTimeout(resolve, 15000));
      await writer.write(encoder.encode(`: keepalive ${new Date().toISOString()}\n\n`));

      // Close with summary
      await writer.write(encoder.encode(
        `event: complete\ndata: ${JSON.stringify({
          items_streamed: stream_items.length,
          timestamp: new Date().toISOString(),
        })}\n\n`
      ));
    } catch (_) {}
    finally {
      await writer.close().catch(() => {});
    }
  })());

  return new Response(readable, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection": "keep-alive",
      "X-Accel-Buffering": "no",
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// MSSP MULTI-TENANT ROUTING
// -----------------------------------------------------------------------------

/**
 * GET /api/mssp/tenants/:tenant_id/feed
 * Tenant-scoped threat feed for MSSP multi-customer deployments.
 */
export async function handleMSSPFeed(req, env, ctx, tier, items, tenant_id, req_id) {
  if (!requireEnterprise(tier)) {
    return enterpriseDenied(`/api/mssp/tenants/${tenant_id}/feed`, req_id);
  }

  const url = new URL(req.url);
  const severity = (url.searchParams.get("severity") || "").toUpperCase();
  const industry = (url.searchParams.get("industry") || "").toLowerCase();
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 200);

  let filtered = items || [];
  if (severity) {
    filtered = filtered.filter(i => (i.severity || "").toUpperCase() === severity);
  }
  if (industry) {
    // Filter by sector/industry tags if available
    filtered = filtered.filter(i => {
      const tags = JSON.stringify(i.tags || []).toLowerCase();
      const tt = (i.threat_type || "").toLowerCase();
      return tags.includes(industry) || tt.includes(industry);
    });
  }

  const page = filtered.slice(0, limit);

  return new Response(JSON.stringify({
    tenant_id,
    generated_at: new Date().toISOString(),
    tier: "mssp-enterprise",
    total_available: filtered.length,
    returned: page.length,
    filters_applied: { severity, industry },
    items: page,
    _apex_version: ENTERPRISE_VERSION,
    _mssp_note: "Tenant-scoped feed. Configure industry and severity filters for relevant intelligence.",
  }), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "X-Tenant-ID": tenant_id,
      "X-Request-ID": req_id,
    },
  });
}

// -----------------------------------------------------------------------------
// ROUTER  -  called from main index.js
// -----------------------------------------------------------------------------

/**
 * Route enterprise endpoint requests.
 * Call from index.js handleRequest() routing section.
 *
 * @param {string} pathname   - URL pathname
 * @param {Request} req       - Original request
 * @param {object} env        - Worker env bindings
 * @param {object} ctx        - Execution context
 * @param {string} tier       - Authenticated tier ('free'|'pro'|'enterprise')
 * @param {Array}  items      - Feed items from manifest
 * @param {string} req_id     - Request ID for correlation
 * @returns {Response|null}   - Response or null if no match
 */
export async function routeEnterpriseEndpoint(pathname, req, env, ctx, tier, items, req_id) {
  // TAXII 2.1
  if (pathname === "/api/taxii" || pathname === "/api/taxii/") {
    return handleTaxiiDiscovery(req, env, ctx, tier, req_id);
  }
  if (pathname === "/api/taxii/root" || pathname === "/api/taxii/root/") {
    return handleTaxiiRoot(req, env, ctx, tier, req_id);
  }
  if (pathname === "/api/taxii/root/collections" || pathname === "/api/taxii/root/collections/") {
    return handleTaxiiCollections(req, env, ctx, tier, req_id);
  }
  const taxii_obj_match = pathname.match(/^\/api\/taxii\/root\/collections\/([^\/]+)\/objects\/?$/);
  if (taxii_obj_match) {
    return handleTaxiiObjects(req, env, ctx, tier, taxii_obj_match[1], req_id);
  }

  // MISP
  if (pathname === "/api/misp/export") {
    return handleMISPExport(req, env, ctx, tier, items, req_id);
  }

  // Sigma bulk
  if (pathname === "/api/sigma/bulk") {
    return handleSigmaBulk(req, env, ctx, tier, items, req_id);
  }

  // YARA bulk
  if (pathname === "/api/yara/bulk") {
    return handleYaraBulk(req, env, ctx, tier, items, req_id);
  }

  // Scoring endpoints
  if (pathname === "/api/scoring") {
    return handleScoringFeed(req, env, ctx, tier, items, req_id);
  }
  if (pathname === "/api/scoring/kev") {
    return handleScoringKEV(req, env, ctx, tier, items, req_id);
  }
  if (pathname === "/api/scoring/ransomware") {
    return handleScoringRansomware(req, env, ctx, tier, items, req_id);
  }
  if (pathname === "/api/scoring/velocity") {
    return handleScoringVelocity(req, env, ctx, tier, items, req_id);
  }

  // SIEM connectors
  if (pathname === "/api/siem/splunk") {
    return handleSiemSplunk(req, env, ctx, tier, items, req_id);
  }
  if (pathname === "/api/siem/sentinel") {
    return handleSiemSentinel(req, env, ctx, tier, items, req_id);
  }
  if (pathname === "/api/siem/qradar") {
    return handleSiemQRadar(req, env, ctx, tier, items, req_id);
  }

  // Stream
  if (pathname === "/api/stream") {
    return handleStream(req, env, ctx, tier, items, req_id);
  }

  // MSSP tenants
  const mssp_match = pathname.match(/^\/api\/mssp\/tenants\/([^\/]+)\/feed$/);
  if (mssp_match) {
    return handleMSSPFeed(req, env, ctx, tier, items, mssp_match[1], req_id);
  }

  // No match
  return null;
}
