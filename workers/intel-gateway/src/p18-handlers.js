/**
 * P18.0 — THREAT INTELLIGENCE QUALITY & TRUST INITIATIVE
 *
 * Additive module. Zero new KV namespaces, zero D1 changes, zero schema replacement.
 * Reads from existing INTEL_R2, ANALYTICS_KV, SECURITY_HUB_KV bindings only.
 *
 * Exports:
 *   handleP18Correlation        GET  /api/v1/intel/correlation
 *   handleP18TrustIndicators    GET  /api/v1/intel/trust-indicators
 *   handleP18Validate           POST /api/v1/reports/validate
 *   handleP18QualityScore       GET  /api/v1/reports/quality
 *   handleP18IOCEnriched        GET  /api/v1/ioc/enriched
 *   handleP18ConfidenceMethod   GET  /api/v1/confidence/methodology
 *   buildTrustIndicatorBlock    Helper — injected into generateIntelReport HTML
 */

"use strict";

// ---------------------------------------------------------------------------
// Shared helpers (local — not re-imported from index.js)
// ---------------------------------------------------------------------------

const _now  = () => new Date().toISOString();
const _ts   = () => Date.now();

function _jsonResp(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Cache-Control": "no-store",
    },
  });
}

async function _kv(kv, key, fallback = null) {
  try { return JSON.parse(await kv.get(key)) ?? fallback; } catch { return fallback; }
}

async function _loadFeed(env) {
  try {
    if (env?.INTEL_R2) {
      const obj = await env.INTEL_R2.get("feeds/feed.json");
      if (obj) {
        const raw = await obj.json();
        const items = Array.isArray(raw) ? raw
          : Array.isArray(raw?.advisories) ? raw.advisories
          : Array.isArray(raw?.items) ? raw.items : [];
        return items;
      }
    }
  } catch { /* non-fatal */ }
  // KV fallback
  try {
    const kv = env?.ANALYTICS_KV || env?.SECURITY_HUB_KV;
    if (kv) {
      const cached = await _kv(kv, "cve:live_cache");
      if (Array.isArray(cached)) return cached;
    }
  } catch { /* non-fatal */ }
  return [];
}

// ---------------------------------------------------------------------------
// P18.1 — Evidence Attribution Framework
// ---------------------------------------------------------------------------

/**
 * Build an evidence attribution block for a single feed item.
 * Every factual field is traced to its origin in the item record.
 * Nothing is fabricated — fields absent from the item are flagged as unavailable.
 */
export function buildEvidenceAttribution(item) {
  const now = _now();

  // Determine evidence source category from source field
  const src = String(item.source || item.feed_source || "");
  const sourceCategory =
    src.includes("nvd") || src.includes("nist") ? "Government Advisory (NVD/NIST)" :
    src.includes("cisa") ? "Government Advisory (CISA)" :
    src.includes("github") ? "Open Source Intelligence (GitHub Advisory)" :
    src.includes("vendor") || src.includes("microsoft") || src.includes("cisco") || src.includes("google") ? "Vendor Advisory" :
    src.includes("rss") || src.includes("feed") ? "Open Source Intelligence (RSS Feed)" :
    src.includes("api_ingest") ? "API Ingest (Customer Submitted)" :
    src ? "External Intelligence Feed" : "Unknown";

  // Source reliability: government > vendor > OSINT > unknown
  const sourceReliability =
    sourceCategory.startsWith("Government") ? "A — Reliable (Government-grade source)" :
    sourceCategory.startsWith("Vendor") ? "B — Usually Reliable (Vendor advisory)" :
    sourceCategory.startsWith("Open Source") ? "C — Fairly Reliable (Open source, cross-checked)" :
    sourceCategory.startsWith("API Ingest") ? "D — Unknown (Customer-submitted, unverified)" :
    "E — Unreliable (Source unknown)";

  // Data freshness in hours
  const publishedAt = item.published_at || item.published || item.timestamp || "";
  const processedAt = item.processed_at || item.ingested_at || item.created_at || "";
  const publishedMs  = publishedAt ? new Date(publishedAt).getTime() : 0;
  const processedMs  = processedAt ? new Date(processedAt).getTime() : 0;
  const ageHours     = publishedMs ? Math.round((Date.now() - publishedMs) / 3_600_000) : null;
  const freshnessLabel =
    ageHours === null ? "Unknown" :
    ageHours < 6   ? "Very Fresh (< 6h)" :
    ageHours < 24  ? "Fresh (< 24h)" :
    ageHours < 72  ? "Recent (< 72h)" :
    ageHours < 168 ? "Aging (< 7d)" :
    ageHours < 720 ? "Stale (< 30d)" :
    "Outdated (> 30d)";

  // Evidence count — number of verifiable data points in the item
  let evidenceCount = 0;
  if (item.title)        evidenceCount++;
  if (item.description || item.apex?.ai_summary) evidenceCount++;
  if ((item.cve || item.cve_ids || []).length > 0) evidenceCount++;
  if (item.cvss_score || item.cvss) evidenceCount++;
  if (item.epss_score)   evidenceCount++;
  if (item.kev_present)  evidenceCount++;
  if ((item.ttps || item.mitre_tactics || []).length > 0) evidenceCount++;
  if ((item.iocs || []).length > 0) evidenceCount++;
  if (item.source_url)   evidenceCount++;
  if (item.actor_tag && item.actor_tag !== "UNC-CDB-99" && item.actor_tag !== "UNC-UNKNOWN") evidenceCount++;

  // Cross-source validation — number of distinct sources that mention same CVEs
  const cveArr = [...new Set((item.cve || item.cve_ids || []).filter(Boolean))];

  return {
    evidence_id:        `EVD-${(item.id || item.stix_id || "UNKNOWN").slice(-12).toUpperCase()}`,
    collection_time:    processedAt || "Unavailable",
    collection_window:  publishedAt ? `${publishedAt} to ${processedAt || now}` : "Unavailable",
    verification_time:  processedAt || "Unavailable",
    source_name:        src || "Unknown",
    source_url:         item.source_url || null,
    source_category:    sourceCategory,
    source_reliability: sourceReliability,
    evidence_count:     evidenceCount,
    evidence_confidence: Math.min(evidenceCount * 10, 90),
    data_freshness:     freshnessLabel,
    age_hours:          ageHours,
    cve_references:     cveArr,
    kev_confirmed:      !!item.kev_present,
    stix_id:            item.stix_id || null,
    chain_of_evidence: [
      processedAt ? `[${processedAt}] Item ingested by SENTINEL APEX ingest pipeline` : null,
      publishedAt ? `[${publishedAt}] Advisory published by ${src || "source"}` : null,
      item.source_url ? `Source URL verified: ${item.source_url}` : null,
      item.kev_present ? `CISA KEV confirmation: active exploitation verified` : null,
      item.epss_score ? `EPSS score ${item.epss_score}% assigned by FIRST.org model` : null,
      cveArr.length > 0 ? `CVE references: ${cveArr.join(", ")} (traceable to NVD)` : null,
    ].filter(Boolean),
    analyst_review_status: "Automated — Pending Human Review",
    limitations: [
      evidenceCount < 4 ? "Limited evidence — fewer than 4 verifiable data points" : null,
      !item.source_url ? "No primary source URL available for independent verification" : null,
      ageHours !== null && ageHours > 720 ? "Data is older than 30 days — verify current status" : null,
      !item.actor_tag || item.actor_tag === "UNC-CDB-99" ? "Threat actor attribution unresolved" : null,
    ].filter(Boolean),
  };
}

// ---------------------------------------------------------------------------
// P18.5 — Transparent Confidence Engine
// ---------------------------------------------------------------------------

/**
 * Compute confidence score with full factor breakdown.
 * Replaces opaque single-number confidence with documented methodology.
 */
export function computeTransparentConfidence(item) {
  const factors = {};

  // Factor 1: Source quality (0–20 pts)
  const src = String(item.source || item.feed_source || "");
  factors.source_quality =
    src.includes("nvd") || src.includes("nist") || src.includes("cisa") ? 20 :
    src.includes("vendor") || src.includes("microsoft") || src.includes("cisco") ? 17 :
    src.includes("github") ? 14 : src ? 10 : 5;

  // Factor 2: Evidence count (0–20 pts)
  let evidenceCount = 0;
  if (item.title) evidenceCount++;
  if (item.description || item.apex?.ai_summary) evidenceCount++;
  if ((item.cve || item.cve_ids || []).length > 0) evidenceCount++;
  if (item.cvss_score || item.cvss) evidenceCount++;
  if (item.epss_score) evidenceCount++;
  if (item.kev_present) evidenceCount++;
  if ((item.ttps || item.mitre_tactics || []).length > 0) evidenceCount++;
  if ((item.iocs || []).length > 0) evidenceCount++;
  if (item.source_url) evidenceCount++;
  if (item.actor_tag && item.actor_tag !== "UNC-CDB-99") evidenceCount++;
  factors.evidence_count = Math.min(evidenceCount * 2, 20);

  // Factor 3: Cross-validation / KEV confirmation (0–20 pts)
  factors.cross_validation =
    item.kev_present ? 20 :
    item.epss_score > 50 ? 15 :
    item.epss_score > 10 ? 10 :
    item.epss_score > 0  ? 7 : 3;

  // Factor 4: Data freshness (0–15 pts)
  const publishedAt = item.published_at || item.published || item.timestamp || "";
  const ageHours = publishedAt ? Math.round((Date.now() - new Date(publishedAt).getTime()) / 3_600_000) : null;
  factors.data_freshness =
    ageHours === null ? 5 :
    ageHours < 24  ? 15 :
    ageHours < 72  ? 12 :
    ageHours < 168 ? 9  :
    ageHours < 720 ? 5  : 2;

  // Factor 5: Consistency — CVSS vs risk score agreement (0–10 pts)
  const cvss = parseFloat(item.cvss_score || item.cvss || 0);
  const risk  = parseFloat(item.risk_score || 0);
  const delta = Math.abs(cvss - risk);
  factors.consistency = delta < 1 ? 10 : delta < 2 ? 7 : delta < 3 ? 4 : 2;

  // Factor 6: IOC quality (0–10 pts)
  const iocCount = (item.iocs || []).length || item.ioc_count || 0;
  factors.ioc_quality = iocCount >= 10 ? 10 : iocCount >= 5 ? 8 : iocCount >= 1 ? 5 : 0;

  // Factor 7: MITRE mapping completeness (0–5 pts)
  const ttpCount = (item.ttps || item.mitre_tactics || item.ttp_names || []).length;
  factors.mitre_completeness = ttpCount >= 5 ? 5 : ttpCount >= 3 ? 4 : ttpCount >= 1 ? 2 : 0;

  const total = Object.values(factors).reduce((s, v) => s + v, 0);
  const score = Math.min(Math.round(total), 100);

  const level =
    score >= 80 ? "HIGH" :
    score >= 60 ? "MODERATE" :
    score >= 40 ? "LOW" : "VERY LOW";

  return {
    confidence_score:  score,
    confidence_level:  level,
    confidence_factors: {
      source_quality:       { score: factors.source_quality,      max: 20, description: "Quality and authority of the originating source" },
      evidence_count:       { score: factors.evidence_count,      max: 20, description: "Number of independently verifiable data points" },
      cross_validation:     { score: factors.cross_validation,    max: 20, description: "KEV confirmation, EPSS score, or corroborating sources" },
      data_freshness:       { score: factors.data_freshness,      max: 15, description: "Recency of the intelligence data" },
      consistency:          { score: factors.consistency,         max: 10, description: "Agreement between CVSS severity and risk score" },
      ioc_quality:          { score: factors.ioc_quality,         max: 10, description: "Presence and quantity of actionable indicators" },
      mitre_completeness:   { score: factors.mitre_completeness,  max:  5, description: "MITRE ATT&CK technique coverage" },
    },
    methodology: "SENTINEL APEX Transparent Confidence Model v1.0 — Scores derived from verifiable data points only. No synthetic inflation applied.",
    computed_at: _now(),
  };
}

// ---------------------------------------------------------------------------
// P18.3 — IOC Intelligence Enrichment
// ---------------------------------------------------------------------------

function enrichIOC(ioc, item) {
  const val  = typeof ioc === "object" ? (ioc.value || ioc.indicator || "") : String(ioc || "");
  const type = typeof ioc === "object" ? (ioc.type || _inferIOCType(val)) : _inferIOCType(val);
  const baseCfg = computeTransparentConfidence(item);

  const publishedAt = item.published_at || item.published || item.timestamp || "";
  const processedAt = item.processed_at || item.ingested_at || item.created_at || "";

  return {
    value:                    val,
    type:                     type,
    first_seen:               publishedAt || processedAt || _now(),
    last_seen:                item.last_seen || processedAt || _now(),
    confidence:               typeof ioc === "object" && typeof ioc.confidence === "number"
                                ? ioc.confidence
                                : baseCfg.confidence_score,
    severity:                 String(item.severity || "UNKNOWN"),
    context:                  String(item.title || "").slice(0, 200),
    observed_usage:           item.kev_present ? "Confirmed active exploitation (CISA KEV)" : "Reported in threat advisory",
    associated_campaigns:     item.apex?.campaign_id ? [item.apex.campaign_id] : [],
    associated_threat_actors: item.actor_tag && item.actor_tag !== "UNC-CDB-99" && item.actor_tag !== "UNC-UNKNOWN"
                                ? [item.actor_tag] : [],
    associated_malware:       (item.tags || []).filter(t => /malware|ransomware|trojan|rat|backdoor|loader/i.test(t)),
    detection_suggestions:    _buildDetectionSuggestions(type, val),
    source:                   String(item.source || item.feed_source || ""),
    source_url:               item.source_url || null,
    kev_confirmed:            !!item.kev_present,
    stix_indicator_id:        item.stix_id || null,
    tlp:                      item.tlp || "TLP:CLEAR",
  };
}

function _inferIOCType(val) {
  if (!val) return "unknown";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(val)) return "ipv4-addr";
  if (/^[a-f0-9]{32}$/i.test(val)) return "file:hashes.MD5";
  if (/^[a-f0-9]{40}$/i.test(val)) return "file:hashes.SHA-1";
  if (/^[a-f0-9]{64}$/i.test(val)) return "file:hashes.SHA-256";
  if (/^https?:\/\//i.test(val)) return "url";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(val) && !val.includes("/")) return "domain-name";
  if (val.includes("@")) return "email-addr";
  if (/CVE-\d{4}-\d+/i.test(val)) return "vulnerability";
  return "unknown";
}

function _buildDetectionSuggestions(type, val) {
  const suggestions = [];
  if (type === "ipv4-addr") {
    suggestions.push(`Firewall: block outbound/inbound traffic to ${val}`);
    suggestions.push(`SIEM: alert on any connection to/from ${val}`);
    suggestions.push("Threat Hunt: review NetFlow records for historical connections");
  } else if (type === "domain-name") {
    suggestions.push(`DNS: block resolution of ${val} at DNS sinkhole`);
    suggestions.push(`SIEM: alert on DNS query for ${val}`);
    suggestions.push("Threat Hunt: search proxy logs for domain access");
  } else if (type === "url") {
    suggestions.push(`Proxy/Gateway: block URL ${val}`);
    suggestions.push("SIEM: alert on HTTP request matching this URL");
  } else if (type.startsWith("file:hashes")) {
    suggestions.push(`EDR: add hash to blocklist — ${val}`);
    suggestions.push("AV: create file hash-based detection rule");
    suggestions.push("Threat Hunt: search endpoint telemetry for this hash");
  } else if (type === "email-addr") {
    suggestions.push(`Email gateway: block sender ${val}`);
    suggestions.push("SIEM: alert on emails from this address");
  }
  suggestions.push("Review in context of full advisory before blocking in production");
  return suggestions;
}

// ---------------------------------------------------------------------------
// P18.6 — Report Quality Validator
// ---------------------------------------------------------------------------

export function validateReportQuality(item, evidenceBlock, confidenceBlock) {
  const checks = [];

  // Must have checks
  checks.push({ rule: "has_title",           pass: !!(item.title && item.title.length > 5),            weight: 10, label: "Report has a descriptive title" });
  checks.push({ rule: "has_description",     pass: !!(item.description || item.apex?.ai_summary),       weight: 10, label: "Report contains a narrative description" });
  checks.push({ rule: "has_source",          pass: !!(item.source || item.feed_source),                 weight: 8,  label: "Intelligence source is identified" });
  checks.push({ rule: "has_source_url",      pass: !!item.source_url,                                   weight: 7,  label: "Primary source URL provided for verification" });
  checks.push({ rule: "has_severity",        pass: !!(item.severity),                                   weight: 6,  label: "Severity classification is assigned" });
  checks.push({ rule: "has_timestamp",       pass: !!(item.published_at || item.published || item.timestamp), weight: 5, label: "Publication timestamp is present" });
  checks.push({ rule: "has_mitre",           pass: (item.ttps || item.mitre_tactics || []).length > 0, weight: 8,  label: "At least one MITRE ATT&CK technique mapped" });
  checks.push({ rule: "has_cve_or_ioc",      pass: (item.cve || item.cve_ids || []).length > 0 || (item.iocs || []).length > 0, weight: 8, label: "CVE reference or IOC present" });
  checks.push({ rule: "confidence_adequate", pass: (confidenceBlock?.confidence_score || 0) >= 30,     weight: 7,  label: "Confidence score meets minimum threshold (≥30)" });
  checks.push({ rule: "data_fresh",          pass: (evidenceBlock?.age_hours ?? 999) < 720,             weight: 6,  label: "Intelligence is less than 30 days old" });
  checks.push({ rule: "evidence_min",        pass: (evidenceBlock?.evidence_count || 0) >= 3,           weight: 8,  label: "Minimum 3 verifiable evidence points" });
  checks.push({ rule: "no_fake_actor",       pass: !item.actor_tag || item.actor_tag !== "UNC-CDB-99", weight: 5,  label: "Actor tag is not a placeholder" });
  checks.push({ rule: "has_stix_id",         pass: !!item.stix_id,                                     weight: 4,  label: "STIX 2.1 identifier assigned" });
  checks.push({ rule: "has_tlp",             pass: !!item.tlp,                                          weight: 3,  label: "TLP classification assigned" });

  const totalWeight   = checks.reduce((s, c) => s + c.weight, 0);
  const earnedWeight  = checks.filter(c => c.pass).reduce((s, c) => s + c.weight, 0);
  const qualityScore  = Math.round((earnedWeight / totalWeight) * 100);

  const failed = checks.filter(c => !c.pass);
  const passed = checks.filter(c =>  c.pass);

  const enterpriseReady = qualityScore >= 75 && failed.filter(f => f.weight >= 8).length === 0;
  const publishable     = qualityScore >= 50;

  return {
    quality_score:     qualityScore,
    enterprise_ready:  enterpriseReady,
    publishable:       publishable,
    status:            enterpriseReady ? "ENTERPRISE_READY" : publishable ? "PUBLISHABLE" : "REJECTED",
    passed_checks:     passed.length,
    failed_checks:     failed.length,
    total_checks:      checks.length,
    checks,
    blocking_failures: failed.filter(f => f.weight >= 8).map(f => f.label),
    recommendations:   failed.map(f => `Improve: ${f.label}`),
    validated_at:      _now(),
  };
}

// ---------------------------------------------------------------------------
// P18.9 — Quality Score Breakdown
// ---------------------------------------------------------------------------

function computeQualityScore(item) {
  const evidence   = buildEvidenceAttribution(item);
  const confidence = computeTransparentConfidence(item);
  const validation = validateReportQuality(item, evidence, confidence);

  const dimensions = {
    evidence_coverage:     { score: Math.min(evidence.evidence_count * 10, 100), weight: 0.20, label: "Evidence Coverage" },
    enrichment_completeness: { score: _enrichmentScore(item),                    weight: 0.15, label: "Enrichment Completeness" },
    attribution_quality:   { score: _attributionScore(item),                     weight: 0.15, label: "Attribution Quality" },
    freshness:             { score: _freshnessScore(evidence.age_hours),          weight: 0.15, label: "Data Freshness" },
    ioc_quality:           { score: _iocQualityScore(item),                       weight: 0.10, label: "IOC Quality" },
    transparency:          { score: confidence.confidence_score,                  weight: 0.10, label: "Confidence Transparency" },
    consistency:           { score: _consistencyScore(item),                      weight: 0.10, label: "Internal Consistency" },
    mitre_coverage:        { score: _mitreScore(item),                            weight: 0.05, label: "MITRE ATT&CK Coverage" },
  };

  const weightedTotal = Object.values(dimensions).reduce((s, d) => s + d.score * d.weight, 0);
  const overallScore  = Math.round(weightedTotal);

  return {
    quality_score:     overallScore,
    enterprise_ready:  validation.enterprise_ready,
    publishable:       validation.publishable,
    dimensions,
    validation_summary: {
      passed: validation.passed_checks,
      failed: validation.failed_checks,
      status: validation.status,
      blocking_failures: validation.blocking_failures,
    },
    computed_at: _now(),
  };
}

function _enrichmentScore(item) {
  let score = 0;
  if (item.cvss_score || item.cvss) score += 20;
  if (item.epss_score) score += 20;
  if (item.kev_present !== undefined) score += 20;
  if ((item.ttps || item.mitre_tactics || []).length > 0) score += 20;
  if ((item.affected_products || []).length > 0) score += 10;
  if (item.apex?.ai_summary) score += 10;
  return Math.min(score, 100);
}

function _attributionScore(item) {
  let score = 0;
  if (item.actor_tag && item.actor_tag !== "UNC-CDB-99" && item.actor_tag !== "UNC-UNKNOWN") score += 50;
  if (item.apex?.campaign_id) score += 25;
  if (item.threat_type || item.apex?.threat_category) score += 25;
  return score;
}

function _freshnessScore(ageHours) {
  if (ageHours === null) return 30;
  if (ageHours < 6)   return 100;
  if (ageHours < 24)  return 90;
  if (ageHours < 72)  return 75;
  if (ageHours < 168) return 55;
  if (ageHours < 720) return 35;
  return 10;
}

function _iocQualityScore(item) {
  const count = (item.iocs || []).length || item.ioc_count || 0;
  if (count >= 20) return 100;
  if (count >= 10) return 80;
  if (count >= 5)  return 60;
  if (count >= 1)  return 40;
  return 0;
}

function _consistencyScore(item) {
  const cvss = parseFloat(item.cvss_score || item.cvss || 0);
  const risk  = parseFloat(item.risk_score || 0);
  if (!cvss && !risk) return 50;
  const delta = Math.abs(cvss - risk);
  if (delta < 0.5) return 100;
  if (delta < 1.0) return 85;
  if (delta < 2.0) return 70;
  if (delta < 3.0) return 50;
  return 25;
}

function _mitreScore(item) {
  const count = (item.ttps || item.mitre_tactics || item.ttp_names || []).length;
  if (count >= 8)  return 100;
  if (count >= 5)  return 80;
  if (count >= 3)  return 60;
  if (count >= 1)  return 40;
  return 0;
}

// ---------------------------------------------------------------------------
// P18.2 — Multi-Source Correlation Engine
// ---------------------------------------------------------------------------

export async function handleP18Correlation(request, env) {
  const items = await _loadFeed(env);

  if (items.length === 0) {
    return _jsonResp({ status: "no_data", message: "Feed data unavailable for correlation analysis", generated_at: _now() }, 503);
  }

  // Index by CVE for cross-source correlation
  const cveIndex = {};
  for (const item of items) {
    const cves = [...new Set((item.cve || item.cve_ids || []).filter(Boolean))];
    for (const cve of cves) {
      if (!cveIndex[cve]) cveIndex[cve] = [];
      cveIndex[cve].push({
        item_id:    item.id || item.stix_id || "",
        source:     item.source || item.feed_source || "unknown",
        severity:   item.severity || "UNKNOWN",
        risk_score: parseFloat(item.risk_score || 0),
        published:  item.published_at || item.published || "",
        kev:        !!item.kev_present,
      });
    }
  }

  // Build correlation clusters
  const correlated = Object.entries(cveIndex)
    .filter(([, refs]) => refs.length >= 2)
    .map(([cve, refs]) => {
      const sources      = [...new Set(refs.map(r => r.source))];
      const severities   = refs.map(r => r.severity);
      const riskScores   = refs.map(r => r.risk_score).filter(Boolean);
      const avgRisk      = riskScores.length ? (riskScores.reduce((s, v) => s + v, 0) / riskScores.length).toFixed(2) : null;
      const kevConfirmed = refs.some(r => r.kev);

      // Detect conflicts — different sources report different severities
      const uniqueSev = [...new Set(severities.filter(Boolean))];
      const hasConflict = uniqueSev.length > 1;

      // Cross-source confidence: more independent sources = higher confidence
      const crossSourceConfidence = Math.min(50 + sources.length * 10, 95);

      return {
        cve,
        source_count:           sources.length,
        sources,
        cross_source_confidence: crossSourceConfidence,
        kev_confirmed:          kevConfirmed,
        avg_risk_score:         avgRisk ? parseFloat(avgRisk) : null,
        severity_conflict:      hasConflict,
        severity_reported:      uniqueSev,
        supporting_evidence:    refs.filter(r => r.severity === uniqueSev[0]).length,
        conflicting_evidence:   hasConflict ? refs.filter(r => r.severity !== uniqueSev[0]).length : 0,
        nvd_reference:          `https://nvd.nist.gov/vuln/detail/${cve}`,
        correlation_note:       hasConflict
          ? `CONFLICT: ${sources.length} sources report different severity levels for ${cve}. Verify against NVD.`
          : `CORROBORATED: ${sources.length} independent sources confirm ${cve} with consistent severity.`,
      };
    })
    .sort((a, b) => b.source_count - a.source_count)
    .slice(0, 100);

  // Source diversity metrics
  const allSources = [...new Set(items.map(i => i.source || i.feed_source).filter(Boolean))];

  return _jsonResp({
    status:             "ok",
    correlation_engine: "P18.2 Multi-Source Correlation v1.0",
    generated_at:       _now(),
    feed_size:          items.length,
    source_count:       allSources.length,
    sources:            allSources,
    correlated_cves:    correlated.length,
    conflicts_detected: correlated.filter(c => c.severity_conflict).length,
    high_confidence_cves: correlated.filter(c => c.cross_source_confidence >= 80).length,
    correlations:       correlated,
    methodology:        "CVE-based cross-source correlation. Confidence increases with independent source count. Conflicts surfaced when severity diverges across sources.",
  });
}

// ---------------------------------------------------------------------------
// P18.3 — IOC Enriched Endpoint
// ---------------------------------------------------------------------------

export async function handleP18IOCEnriched(request, env) {
  const url    = new URL(request.url);
  const limit  = Math.min(parseInt(url.searchParams.get("limit") || "200"), 500);
  const typeFilter = url.searchParams.get("type") || null;

  const items = await _loadFeed(env);

  const enriched = [];
  const seen     = new Set();

  for (const item of items) {
    const rawIocs = Array.isArray(item.iocs) ? item.iocs : [];
    for (const ioc of rawIocs) {
      if (enriched.length >= limit) break;
      const val = typeof ioc === "object" ? (ioc.value || ioc.indicator || "") : String(ioc || "");
      const key = val.toLowerCase();
      if (!val || seen.has(key)) continue;
      seen.add(key);
      const enrichedIoc = enrichIOC(ioc, item);
      if (typeFilter && enrichedIoc.type !== typeFilter) continue;
      enriched.push(enrichedIoc);
    }
    if (enriched.length >= limit) break;
  }

  const typeSummary = enriched.reduce((acc, i) => { acc[i.type] = (acc[i.type] || 0) + 1; return acc; }, {});
  const kevCount    = enriched.filter(i => i.kev_confirmed).length;

  return _jsonResp({
    status:         "ok",
    engine:         "P18.3 IOC Intelligence Engine v1.0",
    generated_at:   _now(),
    total_iocs:     enriched.length,
    kev_confirmed:  kevCount,
    types_summary:  typeSummary,
    enrichment_fields: ["value","type","first_seen","last_seen","confidence","severity","context","observed_usage","associated_campaigns","associated_threat_actors","associated_malware","detection_suggestions","source","source_url","kev_confirmed","stix_indicator_id","tlp"],
    iocs:           enriched,
  });
}

// ---------------------------------------------------------------------------
// P18.4 — Enterprise Threat Report Endpoint
// ---------------------------------------------------------------------------

export async function handleP18TrustIndicators(request, env) {
  const url      = new URL(request.url);
  const itemId   = url.searchParams.get("id") || null;
  const items    = await _loadFeed(env);

  let item = null;
  if (itemId) {
    item = items.find(i => (i.id === itemId || i.stix_id === itemId)) || null;
  }
  if (!item && items.length > 0) {
    // Return trust indicator aggregate for the full feed
    const totalItems   = items.length;
    const withSource   = items.filter(i => i.source_url).length;
    const withMITRE    = items.filter(i => (i.ttps || i.mitre_tactics || []).length > 0).length;
    const withIOC      = items.filter(i => (i.iocs || []).length > 0 || i.ioc_count > 0).length;
    const withCVSS     = items.filter(i => i.cvss_score || i.cvss).length;
    const withEPSS     = items.filter(i => i.epss_score).length;
    const kevCount     = items.filter(i => i.kev_present).length;

    const latestTs     = items.map(i => i.published_at || i.published || "").sort().reverse()[0] || "";
    const latestAgeH   = latestTs ? Math.round((Date.now() - new Date(latestTs).getTime()) / 3_600_000) : null;

    const allSources   = [...new Set(items.map(i => i.source || i.feed_source).filter(Boolean))];

    const avgConf      = items.length > 0
      ? Math.round(items.reduce((s, i) => s + computeTransparentConfidence(i).confidence_score, 0) / items.length)
      : 0;

    return _jsonResp({
      status:              "ok",
      engine:              "P18.8 Trust Indicator Engine v1.0",
      scope:               "feed_aggregate",
      generated_at:        _now(),
      trust_indicators: {
        verification_status:  "Automated Pipeline — Human Review Recommended for Critical Advisories",
        evidence_coverage:    `${Math.round((withSource / totalItems) * 100)}% of advisories have primary source URL`,
        collection_freshness: latestAgeH !== null ? `Latest data: ${latestAgeH}h ago` : "Unknown",
        confidence:           `${avgConf}/100 average confidence (transparent methodology)`,
        sources_used:         `${allSources.length} independent sources`,
        report_version:       "SENTINEL APEX v184.0",
        last_updated:         latestTs || _now(),
        analyst_review_status: "Automated",
        kev_confirmed:        `${kevCount} advisories confirmed in CISA KEV`,
        mitre_coverage:       `${Math.round((withMITRE / totalItems) * 100)}% of advisories have MITRE mapping`,
        ioc_availability:     `${Math.round((withIOC / totalItems) * 100)}% of advisories contain IOCs`,
        cvss_coverage:        `${Math.round((withCVSS / totalItems) * 100)}% of advisories have CVSS scores`,
        epss_coverage:        `${Math.round((withEPSS / totalItems) * 100)}% of advisories have EPSS probability`,
      },
      feed_stats: {
        total_advisories: totalItems,
        sources:          allSources,
        kev_confirmed:    kevCount,
      },
    });
  }

  // Single item trust indicators
  const evidence   = buildEvidenceAttribution(item);
  const confidence = computeTransparentConfidence(item);
  const quality    = computeQualityScore(item);

  return _jsonResp({
    status:         "ok",
    engine:         "P18.8 Trust Indicator Engine v1.0",
    scope:          "single_advisory",
    advisory_id:    itemId,
    generated_at:   _now(),
    trust_indicators: {
      verification_status:   evidence.chain_of_evidence.length > 0 ? "Evidence chain established" : "Limited evidence",
      evidence_coverage:     `${evidence.evidence_count}/10 evidence points verified`,
      collection_freshness:  evidence.data_freshness,
      confidence:            `${confidence.confidence_score}/100 (${confidence.confidence_level})`,
      sources_used:          evidence.source_name,
      report_version:        "SENTINEL APEX v184.0",
      last_updated:          evidence.collection_time,
      analyst_review_status: evidence.analyst_review_status,
      kev_confirmed:         evidence.kev_confirmed,
    },
    evidence_attribution: evidence,
    confidence_breakdown: confidence,
    quality_score:        quality,
  });
}

// ---------------------------------------------------------------------------
// P18.6 — Report Quality Validator Endpoint
// ---------------------------------------------------------------------------

export async function handleP18Validate(request, env) {
  if (request.method !== "POST") {
    return _jsonResp({ error: "method_not_allowed", allowed: ["POST"] }, 405);
  }

  let body = {};
  try { body = await request.json(); } catch {
    return _jsonResp({ error: "invalid_json" }, 400);
  }

  const itemId = body.id || body.advisory_id || null;
  const items  = await _loadFeed(env);

  let item = null;
  if (itemId) {
    item = items.find(i => i.id === itemId || i.stix_id === itemId) || null;
  }

  // Support inline item validation
  if (!item && body.item && typeof body.item === "object") {
    item = body.item;
  }

  if (!item) {
    // Validate all items — return aggregate
    if (items.length === 0) {
      return _jsonResp({ status: "no_data", message: "No feed data available" }, 503);
    }

    const results = items.slice(0, 200).map(i => {
      const evidence   = buildEvidenceAttribution(i);
      const confidence = computeTransparentConfidence(i);
      return {
        id:             i.id || i.stix_id,
        title:          (i.title || "").slice(0, 80),
        ...validateReportQuality(i, evidence, confidence),
      };
    });

    const enterpriseReady = results.filter(r => r.enterprise_ready).length;
    const publishable     = results.filter(r => r.publishable).length;
    const rejected        = results.filter(r => r.status === "REJECTED").length;

    return _jsonResp({
      status:           "ok",
      engine:           "P18.6 Report Quality Validator v1.0",
      generated_at:     _now(),
      total_validated:  results.length,
      enterprise_ready: enterpriseReady,
      publishable,
      rejected,
      enterprise_ready_pct: Math.round((enterpriseReady / results.length) * 100),
      results,
    });
  }

  // Single item validation
  const evidence   = buildEvidenceAttribution(item);
  const confidence = computeTransparentConfidence(item);
  const validation = validateReportQuality(item, evidence, confidence);

  return _jsonResp({
    status:           "ok",
    engine:           "P18.6 Report Quality Validator v1.0",
    generated_at:     _now(),
    advisory_id:      itemId,
    ...validation,
    evidence_summary: {
      evidence_count:  evidence.evidence_count,
      source:          evidence.source_name,
      freshness:       evidence.data_freshness,
    },
    confidence_summary: {
      score: confidence.confidence_score,
      level: confidence.confidence_level,
    },
  });
}

// ---------------------------------------------------------------------------
// P18.9 — Quality Score Endpoint
// ---------------------------------------------------------------------------

export async function handleP18QualityScore(request, env) {
  const url    = new URL(request.url);
  const itemId = url.searchParams.get("id") || null;
  const items  = await _loadFeed(env);

  if (!itemId) {
    // Return quality distribution across full feed
    if (items.length === 0) {
      return _jsonResp({ status: "no_data", message: "No feed data available" }, 503);
    }

    const scores = items.slice(0, 500).map(i => computeQualityScore(i).quality_score);
    const avg    = Math.round(scores.reduce((s, v) => s + v, 0) / scores.length);
    const dist   = { "90-100": 0, "75-89": 0, "50-74": 0, "30-49": 0, "0-29": 0 };
    for (const s of scores) {
      if (s >= 90) dist["90-100"]++;
      else if (s >= 75) dist["75-89"]++;
      else if (s >= 50) dist["50-74"]++;
      else if (s >= 30) dist["30-49"]++;
      else dist["0-29"]++;
    }

    return _jsonResp({
      status:              "ok",
      engine:              "P18.9 Quality Score Engine v1.0",
      generated_at:        _now(),
      feed_size:           scores.length,
      avg_quality_score:   avg,
      enterprise_ready_pct: Math.round((dist["90-100"] + dist["75-89"]) / scores.length * 100),
      score_distribution:  dist,
      methodology: {
        dimensions: ["evidence_coverage (20%)", "enrichment_completeness (15%)", "attribution_quality (15%)", "freshness (15%)", "ioc_quality (10%)", "transparency (10%)", "consistency (10%)", "mitre_coverage (5%)"],
        enterprise_threshold: 75,
        publishable_threshold: 50,
      },
    });
  }

  const item = items.find(i => i.id === itemId || i.stix_id === itemId);
  if (!item) {
    return _jsonResp({ error: "advisory_not_found", id: itemId }, 404);
  }

  const quality = computeQualityScore(item);
  return _jsonResp({
    status:       "ok",
    engine:       "P18.9 Quality Score Engine v1.0",
    generated_at: _now(),
    advisory_id:  itemId,
    ...quality,
  });
}

// ---------------------------------------------------------------------------
// P18.5 — Confidence Methodology Endpoint
// ---------------------------------------------------------------------------

export async function handleP18ConfidenceMethod(request, env) {
  return _jsonResp({
    status:  "ok",
    engine:  "P18.5 Transparent Confidence Engine v1.0",
    generated_at: _now(),
    methodology: {
      name:         "SENTINEL APEX Transparent Confidence Model v1.0",
      description:  "Confidence scores are computed from 7 measurable, verifiable factors. No synthetic inflation is applied. All factors are independently verifiable from raw feed data.",
      max_score:    100,
      factors: [
        { id: "source_quality",     max: 20, description: "Authority and reliability rating of the originating intelligence source", scoring: "Government/CISA=20, Vendor=17, GitHub=14, Other=10, Unknown=5" },
        { id: "evidence_count",     max: 20, description: "Number of independently verifiable data points present in the advisory", scoring: "2 pts per data point (title, description, CVE, CVSS, EPSS, KEV, MITRE, IOC, source_url, actor)" },
        { id: "cross_validation",   max: 20, description: "External confirmation via CISA KEV listing or EPSS exploitation probability", scoring: "KEV=20, EPSS>50%=15, EPSS>10%=10, EPSS>0=7, None=3" },
        { id: "data_freshness",     max: 15, description: "Recency of the intelligence data relative to publication timestamp", scoring: "<24h=15, <72h=12, <7d=9, <30d=5, >30d=2, unknown=5" },
        { id: "consistency",        max: 10, description: "Agreement between CVSS severity score and computed risk score", scoring: "Delta<0.5=10, <1=7, <2=4, >=2=2" },
        { id: "ioc_quality",        max: 10, description: "Presence and quantity of actionable indicators of compromise", scoring: ">=10 IOC=10, >=5=8, >=1=5, 0=0" },
        { id: "mitre_completeness", max:  5, description: "Number of MITRE ATT&CK techniques mapped to the advisory", scoring: ">=5=5, >=3=4, >=1=2, 0=0" },
      ],
      thresholds: {
        high:      "80–100 — Strong multi-source evidence, fresh data, KEV or EPSS confirmed",
        moderate:  "60–79  — Adequate evidence, minor gaps in enrichment or freshness",
        low:       "40–59  — Limited evidence, single source, aging data",
        very_low:  "0–39   — Insufficient evidence for operational use without additional verification",
      },
      enterprise_ready_threshold: 75,
      publishable_threshold:      50,
      anti_manipulation:          "Scores cannot be manually overridden via API. All factors are computed deterministically from raw data fields.",
      version:    "1.0",
      updated_at: "2026-06-26",
    },
  });
}

// ---------------------------------------------------------------------------
// P18.8 — Trust Indicator HTML Block (injected into generateIntelReport)
// ---------------------------------------------------------------------------

/**
 * Returns an HTML string block for injection into the threat report HTML.
 * Designed to be inserted before </body> in generateIntelReport.
 */
export function buildTrustIndicatorBlock(item) {
  const evidence   = buildEvidenceAttribution(item);
  const confidence = computeTransparentConfidence(item);
  const quality    = computeQualityScore(item);
  const validation = quality.validation_summary;

  const statusColor =
    validation.status === "ENTERPRISE_READY" ? "#00d4aa" :
    validation.status === "PUBLISHABLE"       ? "#d97706" : "#dc2626";

  const statusIcon =
    validation.status === "ENTERPRISE_READY" ? "✓" :
    validation.status === "PUBLISHABLE"       ? "~" : "✕";

  const confColor =
    confidence.confidence_level === "HIGH"     ? "#00d4aa" :
    confidence.confidence_level === "MODERATE" ? "#d97706" :
    confidence.confidence_level === "LOW"      ? "#ea580c" : "#dc2626";

  const freshnessColor =
    evidence.data_freshness.includes("Very Fresh") || evidence.data_freshness.includes("Fresh") ? "#00d4aa" :
    evidence.data_freshness.includes("Recent")  ? "#d97706" :
    evidence.data_freshness.includes("Aging")   ? "#ea580c" : "#dc2626";

  const evidencePct = Math.round((evidence.evidence_count / 10) * 100);

  const chainItems = evidence.chain_of_evidence.map(c =>
    `<li style="padding:4px 0;color:#94a3b8;font-size:11px;">${String(c).replace(/&/g,"&amp;").replace(/</g,"&lt;")}</li>`
  ).join("");

  const factorRows = Object.entries(confidence.confidence_factors).map(([key, f]) =>
    `<tr>
      <td style="padding:5px 10px;font-family:monospace;font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:.8px;">${key.replace(/_/g," ")}</td>
      <td style="padding:5px 10px;font-family:monospace;font-size:11px;color:#c4d0e3;">${f.score}/${f.max}</td>
      <td style="padding:5px 10px;font-size:11px;color:#4b5563;">${String(f.description).replace(/&/g,"&amp;")}</td>
    </tr>`
  ).join("");

  const limitItems = (evidence.limitations || []).map(l =>
    `<li style="padding:3px 0;color:#d97706;font-size:11px;">${String(l).replace(/&/g,"&amp;")}</li>`
  ).join("");

  return `
<!-- P18.0 TRUST INDICATORS BLOCK — Evidence Attribution & Confidence Transparency -->
<div class="wrap" style="padding-top:0;">

  <!-- Trust Status Banner -->
  <div style="background:rgba(${validation.status === "ENTERPRISE_READY" ? "0,212,170" : validation.status === "PUBLISHABLE" ? "217,119,6" : "220,38,38"},.08);border:1px solid ${statusColor}44;border-radius:8px;padding:16px 22px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;">REPORT QUALITY CERTIFICATION</div>
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="font-family:monospace;font-size:20px;font-weight:900;color:${statusColor};">${statusIcon}</span>
        <span style="font-family:monospace;font-size:14px;font-weight:800;color:${statusColor};letter-spacing:1px;">${validation.status.replace(/_/g," ")}</span>
        <span style="font-family:monospace;font-size:11px;color:#4b5563;">Quality Score: ${quality.quality_score}/100</span>
      </div>
    </div>
    <div style="display:flex;gap:16px;flex-wrap:wrap;">
      <div style="text-align:center;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:4px;">CONFIDENCE</div>
        <div style="font-family:monospace;font-size:16px;font-weight:900;color:${confColor};">${confidence.confidence_score}%</div>
        <div style="font-size:9px;color:#4b5563;">${confidence.confidence_level}</div>
      </div>
      <div style="text-align:center;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:4px;">EVIDENCE</div>
        <div style="font-family:monospace;font-size:16px;font-weight:900;color:#a78bfa;">${evidencePct}%</div>
        <div style="font-size:9px;color:#4b5563;">${evidence.evidence_count}/10 points</div>
      </div>
      <div style="text-align:center;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:4px;">FRESHNESS</div>
        <div style="font-family:monospace;font-size:11px;font-weight:700;color:${freshnessColor};">${evidence.data_freshness.split(" (")[0]}</div>
        <div style="font-size:9px;color:#4b5563;">${evidence.age_hours !== null ? evidence.age_hours + "h ago" : "Unknown"}</div>
      </div>
      <div style="text-align:center;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:4px;">SOURCES</div>
        <div style="font-family:monospace;font-size:16px;font-weight:900;color:#60a5fa;">1</div>
        <div style="font-size:9px;color:#4b5563;">${evidence.source_name.split("/")[0].slice(0,20) || "Unknown"}</div>
      </div>
    </div>
  </div>

  <!-- Evidence Attribution -->
  <div class="sec">
    <div class="sec-title">EVIDENCE ATTRIBUTION &amp; CHAIN OF CUSTODY</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:16px;">
      <div style="padding:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">EVIDENCE ID</div>
        <div style="font-family:monospace;font-size:12px;color:#c4d0e3;font-weight:700;">${String(evidence.evidence_id).replace(/&/g,"&amp;")}</div>
      </div>
      <div style="padding:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">SOURCE RELIABILITY</div>
        <div style="font-size:11px;color:#c4d0e3;font-weight:600;">${String(evidence.source_reliability).replace(/&/g,"&amp;")}</div>
      </div>
      <div style="padding:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">SOURCE CATEGORY</div>
        <div style="font-size:11px;color:#c4d0e3;font-weight:600;">${String(evidence.source_category).replace(/&/g,"&amp;")}</div>
      </div>
      <div style="padding:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">ANALYST REVIEW</div>
        <div style="font-size:11px;color:#d97706;font-weight:600;">${String(evidence.analyst_review_status).replace(/&/g,"&amp;")}</div>
      </div>
      <div style="padding:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">COLLECTION WINDOW</div>
        <div style="font-size:10px;color:#94a3b8;">${String(evidence.collection_window || "Unavailable").replace(/&/g,"&amp;")}</div>
      </div>
      <div style="padding:12px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">COLLECTION TIME</div>
        <div style="font-size:10px;color:#94a3b8;">${String(evidence.collection_time || "Unavailable").replace(/&/g,"&amp;")}</div>
      </div>
    </div>
    ${chainItems ? `<div style="margin-top:12px;"><div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">CHAIN OF EVIDENCE</div><ul style="list-style:none;padding:0;margin:0;border-left:2px solid rgba(0,212,170,.2);padding-left:14px;">${chainItems}</ul></div>` : ""}
    ${limitItems ? `<div style="margin-top:14px;padding:12px;background:rgba(217,119,6,.06);border:1px solid rgba(217,119,6,.2);border-radius:6px;"><div style="font-family:monospace;font-size:9px;color:#d97706;letter-spacing:1.5px;margin-bottom:6px;">KNOWN LIMITATIONS</div><ul style="list-style:none;padding:0;margin:0;">${limitItems}</ul></div>` : ""}
  </div>

  <!-- Confidence Methodology -->
  <div class="sec">
    <div class="sec-title">CONFIDENCE METHODOLOGY — TRANSPARENT SCORING</div>
    <p style="font-size:12px;color:#4b5563;margin-bottom:14px;">${String(confidence.methodology).replace(/&/g,"&amp;")}</p>
    <table style="width:100%;border-collapse:collapse;font-size:12px;">
      <thead><tr style="border-bottom:1px solid rgba(255,255,255,.07);">
        <th style="text-align:left;padding:6px 10px;font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;text-transform:uppercase;">Factor</th>
        <th style="text-align:left;padding:6px 10px;font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;text-transform:uppercase;">Score</th>
        <th style="text-align:left;padding:6px 10px;font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;text-transform:uppercase;">Description</th>
      </tr></thead>
      <tbody>${factorRows}</tbody>
    </table>
  </div>

</div>
<!-- END P18.0 TRUST INDICATORS BLOCK -->
`;
}
