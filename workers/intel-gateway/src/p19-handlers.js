/**
 * P19.0 — Enterprise Threat Intelligence Report Excellence Program
 *
 * Additive module. Zero new KV namespaces. Zero D1 changes. Zero schema replacement.
 * Reads from existing INTEL_R2, ANALYTICS_KV, SECURITY_HUB_KV bindings only.
 * Reuses buildEvidenceAttribution, computeTransparentConfidence, validateReportQuality from p18-handlers.
 *
 * Exports (API handlers):
 *   handleP19Certify      GET  /api/v1/reports/certify
 *   handleP19Scorecard    GET  /api/v1/reports/scorecard
 *
 * Exports (HTML section builders — injected into generateIntelReport):
 *   buildSOCBlock         SOC triage, immediate actions, hunt queries
 *   buildExecutiveBlock   Business/regulatory/board/CISO impact
 *   buildAnalystBlock     Analyst summary, certification, version history, limitations
 *   buildDetectionBlock   Sigma rules, YARA, hunt queries, MITRE detection coverage
 *   buildIOCDetailBlock   Enriched IOC table with values (replaces count-only display)
 *   buildMitreTechBlock   MITRE technique chips with T-IDs and descriptions
 */

"use strict";

import { buildEvidenceAttribution, computeTransparentConfidence, validateReportQuality } from './p18-handlers.js';

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

const _now = () => new Date().toISOString();

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

async function _loadFeed(env) {
  try {
    if (env?.INTEL_R2) {
      const obj = await env.INTEL_R2.get("feeds/feed.json");
      if (obj) {
        const raw = await obj.json();
        return Array.isArray(raw) ? raw
          : Array.isArray(raw?.advisories) ? raw.advisories
          : Array.isArray(raw?.items) ? raw.items : [];
      }
    }
  } catch { /* non-fatal */ }
  return [];
}

function _esc(s) {
  return String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ---------------------------------------------------------------------------
// P19 Certification Level Engine
// ---------------------------------------------------------------------------

const CERT_LEVELS = [
  { id: "PRODUCTION_CERTIFIED", label: "Production Certified",  minScore: 92, color: "#00ffc6", description: "Meets all enterprise quality gates. Suitable for customer-facing intelligence products." },
  { id: "PREMIUM_INTELLIGENCE", label: "Premium Intelligence",  minScore: 85, color: "#00d4aa", description: "High-confidence intelligence with strong evidence. Recommended for executive briefings." },
  { id: "ENTERPRISE_READY",     label: "Enterprise Ready",      minScore: 75, color: "#3b82f6", description: "Passes enterprise quality threshold. Suitable for SOC and analyst consumption." },
  { id: "ANALYST_VERIFIED",     label: "Analyst Verified",      minScore: 65, color: "#a78bfa", description: "Sufficient evidence for analyst review. Requires analyst sign-off before distribution." },
  { id: "EVIDENCE_VERIFIED",    label: "Evidence Verified",     minScore: 55, color: "#d97706", description: "Primary evidence chain established. Not yet ready for enterprise distribution." },
  { id: "INTERNAL_REVIEW",      label: "Internal Review",       minScore: 45, color: "#ea580c", description: "Under internal review. Evidence gaps must be resolved before publication." },
  { id: "DRAFT",                label: "Draft",                 minScore: 0,  color: "#dc2626", description: "Draft stage. Multiple quality gates failing. Not suitable for distribution." },
];

export function computeCertificationLevel(qualityScore, validationResult) {
  const blockingFailures = (validationResult?.blocking_failures || []).length;

  // Blocking failures cap the maximum certification level
  const effectiveScore = blockingFailures >= 3 ? Math.min(qualityScore, 44)
    : blockingFailures >= 2 ? Math.min(qualityScore, 54)
    : blockingFailures >= 1 ? Math.min(qualityScore, 64)
    : qualityScore;

  const level = CERT_LEVELS.find(l => effectiveScore >= l.minScore) || CERT_LEVELS[CERT_LEVELS.length - 1];

  return {
    certification_id:    level.id,
    certification_label: level.label,
    certification_color: level.color,
    certification_description: level.description,
    quality_score:       qualityScore,
    effective_score:     effectiveScore,
    blocking_failures:   blockingFailures,
    customer_deliverable: ["PRODUCTION_CERTIFIED","PREMIUM_INTELLIGENCE","ENTERPRISE_READY"].includes(level.id),
    rationale: blockingFailures > 0
      ? `Score reduced from ${qualityScore} to ${effectiveScore} due to ${blockingFailures} blocking quality failure(s). Resolve: ${(validationResult?.blocking_failures || []).join("; ")}`
      : `Score ${qualityScore}/100 satisfies ${level.label} threshold (≥${level.minScore}).`,
    certified_at: _now(),
  };
}

// ---------------------------------------------------------------------------
// P19.1 — Wire dead routes: tier normalizer (lowercase → uppercase adapter)
// Used at call sites so enterprise-endpoints.js tier checks work correctly
// ---------------------------------------------------------------------------

export function normalizeTierForEE(tier) {
  // enterprise-endpoints.js uses lowercase: "enterprise", "pro", "premium"
  // index.js TIERS uses uppercase: "ENTERPRISE", "PRO", "FREE", "MSSP"
  return (tier || "free").toLowerCase();
}

// ---------------------------------------------------------------------------
// P19.2 — HTML: SOC Triage Block
// ---------------------------------------------------------------------------

export function buildSOCBlock(item) {
  const sev       = (item.severity || "UNKNOWN").toUpperCase();
  const risk      = parseFloat(item.risk_score || 0);
  const kev       = !!item.kev_present;
  const ttps      = (item.ttps || item.mitre_tactics || item.ttp_names || []).filter(Boolean).slice(0, 8);
  const cveArr    = [...new Set((item.cve || item.cve_ids || []).filter(Boolean))].slice(0, 5);
  const iocCount  = (item.iocs || []).length || item.ioc_count || 0;
  const actor     = item.actor_tag && item.actor_tag !== "UNC-CDB-99" && item.actor_tag !== "UNC-UNKNOWN"
    ? item.actor_tag : null;

  // SOC Priority
  const socPriority =
    kev ? "P1 — CRITICAL (0–4h)" :
    sev === "CRITICAL" || risk >= 9 ? "P1 — CRITICAL (0–4h)" :
    sev === "HIGH"     || risk >= 7 ? "P2 — HIGH (4–24h)" :
    sev === "MEDIUM"   || risk >= 5 ? "P3 — MEDIUM (24–72h)" :
    "P4 — LOW (72h+)";

  const priorityColor =
    socPriority.startsWith("P1") ? "#dc2626" :
    socPriority.startsWith("P2") ? "#ea580c" :
    socPriority.startsWith("P3") ? "#d97706" : "#3b82f6";

  // Immediate SOC actions based on severity/type
  const immediateActions = [];
  if (kev) {
    immediateActions.push({ window: "0–4h", action: "Identify all affected assets in your environment matching vulnerable product/version" });
    immediateActions.push({ window: "0–4h", action: "Apply vendor patch immediately — CISA KEV mandates federal agencies remediate within defined deadlines" });
    immediateActions.push({ window: "0–4h", action: `Block known-bad IOCs (${iocCount} indicators) at perimeter, DNS, and EDR` });
  } else if (sev === "CRITICAL" || risk >= 9) {
    immediateActions.push({ window: "0–4h", action: "Identify and inventory affected systems immediately" });
    immediateActions.push({ window: "0–4h", action: "Escalate to IR lead and CISO — CRITICAL severity requires immediate executive awareness" });
    immediateActions.push({ window: "4–24h", action: "Deploy detection rules and increase monitoring on affected asset classes" });
  } else if (sev === "HIGH" || risk >= 7) {
    immediateActions.push({ window: "4–24h", action: "Triage affected assets and confirm exposure surface" });
    immediateActions.push({ window: "4–24h", action: "Deploy available detection rules to SIEM and EDR" });
    immediateActions.push({ window: "24–72h", action: "Apply vendor patch in next maintenance window or apply compensating control" });
  } else {
    immediateActions.push({ window: "24–72h", action: "Review advisory and assess applicability to your environment" });
    immediateActions.push({ window: "72h+", action: "Schedule patching in routine maintenance cycle" });
  }

  if (iocCount > 0) {
    immediateActions.push({ window: "Detection", action: `Export ${iocCount} IOCs to threat intelligence platform — use /api/v1/ioc/enriched for enriched format` });
  }
  if (ttps.length > 0) {
    immediateActions.push({ window: "Hunting", action: `Execute threat hunt for MITRE techniques: ${ttps.slice(0,3).map(t => _esc(t)).join(", ")}` });
  }

  // Hunt queries
  const huntQueries = [];
  const sigmaRule = item.sigma_rule || (item.detection_rules && item.detection_rules.sigma) || null;
  const huntQuery  = item.threat_hunt_query || item.hunting_query || null;

  if (cveArr.length > 0) {
    huntQueries.push({ platform: "SIEM", query: `search index=* (${cveArr.map(c => `"${_esc(c)}"`).join(" OR ")}) | stats count by host,src_ip,dest_ip` });
  }
  if (actor) {
    huntQueries.push({ platform: "EDR", query: `actor:"${_esc(actor)}" OR campaign:"${_esc(item.apex?.campaign_id || "")}"` });
  }
  if (huntQuery) {
    huntQueries.push({ platform: "Custom", query: _esc(String(huntQuery).slice(0, 500)) });
  }

  const actionRows = immediateActions.map(a =>
    `<tr>
      <td style="padding:8px 12px;font-family:monospace;font-size:10px;color:#94a3b8;white-space:nowrap;border-bottom:1px solid rgba(255,255,255,.04);">${_esc(a.window)}</td>
      <td style="padding:8px 12px;font-size:12px;color:#c4d0e3;border-bottom:1px solid rgba(255,255,255,.04);">${_esc(a.action)}</td>
    </tr>`
  ).join("");

  const huntRows = huntQueries.length > 0 ? huntQueries.map(q =>
    `<div style="margin-top:10px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">${_esc(q.platform)} HUNT QUERY</div>
      <pre style="font-family:monospace;font-size:11px;color:#94a3b8;background:rgba(0,0,0,.3);border:1px solid rgba(255,255,255,.07);border-radius:5px;padding:10px 14px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">${_esc(q.query)}</pre>
    </div>`
  ).join("") : `<div style="padding:10px 14px;background:rgba(255,255,255,.02);border-radius:5px;font-size:12px;color:#374151;">Use <a href="/api/v1/ioc/enriched" style="color:#00d4aa;">/api/v1/ioc/enriched</a> and <a href="/api/sigma/bulk" style="color:#00d4aa;">/api/sigma/bulk</a> (PRO+) for machine-readable detection content.</div>`;

  const sigmaBlock = sigmaRule ? `
    <div style="margin-top:14px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:5px;">SIGMA DETECTION RULE</div>
      <pre style="font-family:monospace;font-size:10.5px;color:#a78bfa;background:rgba(139,92,246,.05);border:1px solid rgba(139,92,246,.15);border-radius:5px;padding:12px 14px;overflow-x:auto;white-space:pre-wrap;max-height:300px;">${_esc(sigmaRule)}</pre>
    </div>` : "";

  return `
  <!-- P19: SOC TRIAGE BLOCK -->
  <div class="sec" style="border-color:rgba(${priorityColor.replace("#","").match(/../g).map(h=>parseInt(h,16)).join(",")},0.25);">
    <div class="sec-title" style="color:${priorityColor};">SOC TRIAGE &amp; OPERATIONAL RESPONSE</div>
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;flex-wrap:wrap;">
      <div style="padding:10px 18px;background:rgba(${priorityColor.replace("#","").match(/../g).map(h=>parseInt(h,16)).join(",")},0.1);border:1px solid ${priorityColor}44;border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:4px;">SOC PRIORITY</div>
        <div style="font-family:monospace;font-size:14px;font-weight:900;color:${priorityColor};">${_esc(socPriority)}</div>
      </div>
      <div style="font-size:12px;color:#64748b;line-height:1.6;">Respond within the indicated window. Escalate if affected assets are confirmed in environment.</div>
    </div>
    <div style="margin-bottom:16px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">IMMEDIATE ACTIONS</div>
      <table style="width:100%;border-collapse:collapse;">
        <thead><tr style="border-bottom:1px solid rgba(255,255,255,.07);">
          <th style="text-align:left;padding:6px 12px;font-family:monospace;font-size:9px;color:#374151;letter-spacing:1px;white-space:nowrap;">WINDOW</th>
          <th style="text-align:left;padding:6px 12px;font-family:monospace;font-size:9px;color:#374151;letter-spacing:1px;">ACTION</th>
        </tr></thead>
        <tbody>${actionRows}</tbody>
      </table>
    </div>
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:6px;">THREAT HUNTING &amp; DETECTION</div>
      ${huntRows}
      ${sigmaBlock}
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// P19.3 — HTML: Enriched IOC Detail Block (replaces count-only display)
// ---------------------------------------------------------------------------

export function buildIOCDetailBlock(item) {
  const iocs = Array.isArray(item.iocs) ? item.iocs : [];
  if (iocs.length === 0 && !item.ioc_count) return "";

  const seen = new Set();
  const enriched = [];

  for (const ioc of iocs.slice(0, 25)) {
    const val  = typeof ioc === "object" ? (ioc.value || ioc.indicator || "") : String(ioc || "");
    const key  = val.toLowerCase();
    if (!val || seen.has(key)) continue;
    seen.add(key);

    const type = typeof ioc === "object" ? (ioc.type || _inferType(val)) : _inferType(val);
    const conf = typeof ioc === "object" && typeof ioc.confidence === "number" ? ioc.confidence : 50;

    enriched.push({
      value:    val,
      type:     type,
      confidence: conf,
      severity: item.severity || "UNKNOWN",
      context:  item.title || "",
      kev:      !!item.kev_present,
      source:   item.source || item.feed_source || "",
    });
  }

  if (enriched.length === 0) return "";

  const typeColors = {
    "ipv4-addr": "#dc2626",
    "domain-name": "#a78bfa",
    "url": "#3b82f6",
    "file:hashes.SHA-256": "#00d4aa",
    "file:hashes.MD5": "#00d4aa",
    "file:hashes.SHA-1": "#00d4aa",
    "email-addr": "#d97706",
    "vulnerability": "#ea580c",
    "unknown": "#64748b",
  };

  const rows = enriched.map(ioc => {
    const typeColor = typeColors[ioc.type] || "#64748b";
    const confColor = ioc.confidence >= 70 ? "#00d4aa" : ioc.confidence >= 40 ? "#d97706" : "#64748b";
    return `<tr style="border-bottom:1px solid rgba(255,255,255,.04);">
      <td style="padding:8px 10px;font-family:monospace;font-size:9px;color:${typeColor};white-space:nowrap;">${_esc(ioc.type)}</td>
      <td style="padding:8px 10px;font-family:monospace;font-size:11px;color:#c4d0e3;word-break:break-all;max-width:320px;">${_esc(ioc.value)}</td>
      <td style="padding:8px 10px;font-family:monospace;font-size:11px;color:${confColor};white-space:nowrap;text-align:center;">${ioc.confidence}%</td>
      <td style="padding:8px 10px;font-size:10px;color:#4b5563;">${_esc(ioc.source.split("/")[0].slice(0,20))}</td>
    </tr>`;
  }).join("");

  const extraCount = (item.ioc_count || iocs.length) - enriched.length;

  return `
  <!-- P19: IOC DETAIL TABLE -->
  <div class="sec">
    <div class="sec-title">INDICATORS OF COMPROMISE — ENRICHED</div>
    <p style="font-size:12px;color:#4b5563;margin-bottom:14px;">Displaying ${enriched.length} of ${item.ioc_count || iocs.length} extracted indicators. Copy values for use in your threat intelligence platform, SIEM, or EDR.</p>
    <div style="overflow-x:auto;">
      <table style="width:100%;border-collapse:collapse;font-size:12px;">
        <thead><tr style="border-bottom:1px solid rgba(255,255,255,.1);">
          <th style="text-align:left;padding:7px 10px;font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;white-space:nowrap;">TYPE</th>
          <th style="text-align:left;padding:7px 10px;font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;">INDICATOR VALUE</th>
          <th style="text-align:center;padding:7px 10px;font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;white-space:nowrap;">CONF</th>
          <th style="text-align:left;padding:7px 10px;font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;">SOURCE</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    ${extraCount > 0 ? `<div style="margin-top:10px;font-size:11px;color:#4b5563;font-family:monospace;">+${extraCount} additional indicators available via <a href="/api/v1/ioc/enriched" style="color:#00d4aa;">/api/v1/ioc/enriched</a> (enriched, 16-field format) or <a href="/api/exports/feed.stix.json" style="color:#a78bfa;">/api/exports/feed.stix.json</a></div>` : ""}
    <div style="margin-top:10px;padding:8px 12px;background:rgba(0,0,0,.2);border-radius:5px;font-family:monospace;font-size:10px;color:#374151;">Machine-readable: <a href="/api/v1/ioc/enriched" style="color:#00d4aa;">/api/v1/ioc/enriched</a> &nbsp;·&nbsp; STIX 2.1: <a href="/api/exports/feed.stix.json" style="color:#a78bfa;">/api/exports/feed.stix.json</a> &nbsp;·&nbsp; MISP: <a href="/api/misp/export" style="color:#d97706;">/api/misp/export</a> (PRO+)</div>
  </div>`;
}

function _inferType(val) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(val)) return "ipv4-addr";
  if (/^[a-f0-9]{64}$/i.test(val)) return "file:hashes.SHA-256";
  if (/^[a-f0-9]{40}$/i.test(val)) return "file:hashes.SHA-1";
  if (/^[a-f0-9]{32}$/i.test(val)) return "file:hashes.MD5";
  if (/^https?:\/\//i.test(val)) return "url";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(val) && !val.includes("/")) return "domain-name";
  if (val.includes("@")) return "email-addr";
  if (/CVE-\d{4}-\d+/i.test(val)) return "vulnerability";
  return "unknown";
}

// ---------------------------------------------------------------------------
// P19.4 — HTML: Detection Package Block
// ---------------------------------------------------------------------------

export function buildDetectionBlock(item) {
  const sigmaRule  = item.sigma_rule || (item.detection_rules && item.detection_rules.sigma) || null;
  const yaraRule   = item.yara_rule  || (item.detection_rules && item.detection_rules.yara)  || null;
  const ttps       = (item.ttps || item.mitre_tactics || item.ttp_names || []).filter(Boolean).slice(0, 8);
  const cveArr     = [...new Set((item.cve || item.cve_ids || []).filter(Boolean))].slice(0, 5);

  // Detection coverage based on available content
  const detectionCoverage = [];
  if (sigmaRule)          detectionCoverage.push({ type: "Sigma Rule",           status: "available", color: "#00d4aa" });
  else                    detectionCoverage.push({ type: "Sigma Rule",           status: "pending", color: "#374151" });
  if (yaraRule)           detectionCoverage.push({ type: "YARA Rule",            status: "available", color: "#00d4aa" });
  else if (item.iocs?.some(i => (i.type||"").includes("file:hashes")))
                          detectionCoverage.push({ type: "YARA Rule",            status: "hash-based possible", color: "#d97706" });
  else                    detectionCoverage.push({ type: "YARA Rule",            status: "N/A", color: "#374151" });
  if (ttps.length > 0)    detectionCoverage.push({ type: "MITRE ATT&CK Mapping", status: `${ttps.length} techniques`, color: "#a78bfa" });
  else                    detectionCoverage.push({ type: "MITRE ATT&CK Mapping", status: "pending", color: "#374151" });
  if (cveArr.length > 0)  detectionCoverage.push({ type: "CVE Detection",        status: `${cveArr.length} CVE(s)`, color: "#60a5fa" });

  const coverageChips = detectionCoverage.map(d =>
    `<div style="padding:8px 14px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);border-radius:6px;display:flex;align-items:center;gap:8px;">
      <div style="width:7px;height:7px;border-radius:50%;background:${d.color};flex-shrink:0;"></div>
      <div>
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;">${_esc(d.type)}</div>
        <div style="font-size:11px;color:${d.color};font-weight:600;">${_esc(d.status)}</div>
      </div>
    </div>`
  ).join("");

  const sigmaSection = sigmaRule ? `
    <div style="margin-top:16px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;display:flex;align-items:center;gap:8px;">SIGMA DETECTION RULE <span style="background:rgba(0,212,170,.1);color:#00d4aa;padding:2px 8px;border-radius:3px;font-size:9px;">PRODUCTION READY</span></div>
      <pre style="font-family:'JetBrains Mono',monospace,monospace;font-size:11px;color:#a78bfa;background:rgba(139,92,246,.05);border:1px solid rgba(139,92,246,.2);border-radius:6px;padding:14px;overflow-x:auto;white-space:pre-wrap;max-height:400px;line-height:1.6;">${_esc(sigmaRule)}</pre>
      <div style="margin-top:8px;font-size:11px;color:#374151;">Deploy via <a href="/api/sigma/bulk" style="color:#a78bfa;">/api/sigma/bulk</a> (PRO+) for bulk Sigma export to your SIEM.</div>
    </div>` : `
    <div style="margin-top:16px;padding:14px;background:rgba(255,255,255,.02);border:1px solid rgba(255,255,255,.06);border-radius:6px;">
      <div style="font-family:monospace;font-size:9px;color:#374151;letter-spacing:1.5px;margin-bottom:6px;">SIGMA RULE</div>
      <div style="font-size:12px;color:#4b5563;">Sigma detection rule not yet generated for this advisory. Use AI Copilot (<code style="color:#a78bfa;">/api/v1/copilot/query</code> with <code style="color:#a78bfa;">mode=detection_write</code>, PRO+) to generate a custom Sigma rule for this threat.</div>
    </div>`;

  const yaraSection = yaraRule ? `
    <div style="margin-top:14px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">YARA RULE</div>
      <pre style="font-family:monospace;font-size:11px;color:#d97706;background:rgba(217,119,6,.04);border:1px solid rgba(217,119,6,.15);border-radius:6px;padding:14px;overflow-x:auto;white-space:pre-wrap;max-height:300px;">${_esc(yaraRule)}</pre>
    </div>` : "";

  const defRecommendations = [
    cveArr.length > 0 ? `Patch management: verify ${cveArr.join(", ")} remediation status across all in-scope assets` : null,
    ttps.length > 0 ? `MITRE coverage: validate detection coverage for ${ttps.slice(0,3).map(t=>_esc(t)).join(", ")}` : null,
    item.kev_present ? "CISA KEV: prioritize patching — confirmed active exploitation in the wild" : null,
    item.epss_score > 10 ? `EPSS: ${item.epss_score}% exploitation probability — accelerate patch schedule` : null,
    "Review and test all detection rules in staging environment before production deployment",
    "Enable enhanced EDR telemetry on affected asset classes during active exploitation window",
  ].filter(Boolean);

  return `
  <!-- P19: DETECTION PACKAGE BLOCK -->
  <div class="sec">
    <div class="sec-title">ENTERPRISE DETECTION PACKAGE</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;margin-bottom:18px;">
      ${coverageChips}
    </div>
    ${sigmaSection}
    ${yaraSection}
    <div style="margin-top:16px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:10px;">DEFENSIVE RECOMMENDATIONS</div>
      <ol style="padding-left:0;list-style:none;margin:0;">
        ${defRecommendations.map((r,i) => `<li style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid rgba(255,255,255,.04);"><span style="font-family:monospace;font-size:10px;color:#374151;flex-shrink:0;min-width:20px;">${i+1}.</span><span style="font-size:12px;color:#94a3b8;">${_esc(r)}</span></li>`).join("")}
      </ol>
    </div>
    <div style="margin-top:14px;display:flex;gap:10px;flex-wrap:wrap;">
      <a href="/api/sigma/bulk" style="padding:8px 14px;background:rgba(139,92,246,.08);border:1px solid rgba(139,92,246,.2);border-radius:5px;font-family:monospace;font-size:10px;color:#a78bfa;font-weight:700;">SIGMA BULK (PRO+)</a>
      <a href="/api/yara/bulk" style="padding:8px 14px;background:rgba(217,119,6,.08);border:1px solid rgba(217,119,6,.2);border-radius:5px;font-family:monospace;font-size:10px;color:#d97706;font-weight:700;">YARA BULK (ENT)</a>
      <a href="/api/siem/splunk" style="padding:8px 14px;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);border-radius:5px;font-family:monospace;font-size:10px;color:#60a5fa;font-weight:700;">SPLUNK FEED (PRO+)</a>
      <a href="/api/siem/sentinel" style="padding:8px 14px;background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.2);border-radius:5px;font-family:monospace;font-size:10px;color:#60a5fa;font-weight:700;">MS SENTINEL (PRO+)</a>
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// P19.5 — HTML: MITRE Technique Chips with T-IDs
// ---------------------------------------------------------------------------

export function buildMitreTechBlock(item) {
  const ttps = (item.ttps || item.mitre_tactics || item.ttp_names || []).filter(Boolean).slice(0, 12);
  if (ttps.length === 0) return "";

  // Known MITRE technique IDs for common TTP names
  const MITRE_IDS = {
    "Initial Access": "TA0001", "Execution": "TA0002", "Persistence": "TA0003",
    "Privilege Escalation": "TA0004", "Defense Evasion": "TA0005", "Credential Access": "TA0006",
    "Discovery": "TA0007", "Lateral Movement": "TA0008", "Collection": "TA0009",
    "Command and Control": "TA0011", "Exfiltration": "TA0010", "Impact": "TA0040",
    "Phishing": "T1566", "Spearphishing": "T1566.001", "Exploitation": "T1203",
    "Remote Services": "T1021", "Valid Accounts": "T1078", "Ransomware": "T1486",
    "Data Encrypted for Impact": "T1486", "Scheduled Task": "T1053",
    "PowerShell": "T1059.001", "Command Line": "T1059", "Registry": "T1112",
    "Process Injection": "T1055", "DLL Hijacking": "T1574.001",
    "Obfuscation": "T1027", "Mimikatz": "T1003", "Credential Dumping": "T1003",
    "Brute Force": "T1110", "Supply Chain": "T1195", "Watering Hole": "T1189",
    "Drive-by Compromise": "T1189", "Living off the Land": "T1218",
  };

  const chips = ttps.map((ttp, i) => {
    const techId = MITRE_IDS[ttp] || (ttp.match(/^T\d{4}/) ? ttp.split(" ")[0] : null);
    const label  = _esc(ttp);
    const url    = techId ? `https://attack.mitre.org/${techId.startsWith("TA") ? "tactics" : "techniques"}/${techId.replace(".","/")}` : `https://attack.mitre.org/techniques/`;
    return `<a href="${url}" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;padding:7px 12px;background:rgba(139,92,246,.1);border:1px solid rgba(139,92,246,.22);border-radius:5px;text-decoration:none;flex-shrink:0;">
      ${techId ? `<span style="font-family:monospace;font-size:9px;color:#7c3aed;font-weight:800;">${_esc(techId)}</span>` : ""}
      <span style="font-size:11px;color:#a78bfa;font-weight:600;">${label}</span>
    </a>${i < ttps.length - 1 ? '<span style="color:rgba(139,92,246,.4);font-size:14px;padding:0 2px;">›</span>' : ""}`;
  }).join("");

  return `
  <!-- P19: MITRE TECHNIQUE CHIPS -->
  <div style="margin-top:14px;">
    <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:10px;">MITRE ATT&amp;CK TECHNIQUES — CLICK TO VIEW FRAMEWORK</div>
    <div style="display:flex;align-items:center;flex-wrap:wrap;gap:6px;">${chips}</div>
    <div style="margin-top:10px;font-size:11px;color:#374151;">Coverage: <span style="color:#a78bfa;font-weight:600;">${ttps.length} technique${ttps.length !== 1 ? "s" : ""}</span> mapped. View full framework at <a href="https://attack.mitre.org" target="_blank" rel="noopener" style="color:#a78bfa;">attack.mitre.org</a></div>
  </div>`;
}

// ---------------------------------------------------------------------------
// P19.6 — HTML: Executive Value Block
// ---------------------------------------------------------------------------

export function buildExecutiveBlock(item) {
  const sev     = (item.severity || "UNKNOWN").toUpperCase();
  const risk    = parseFloat(item.risk_score || 0);
  const cvss    = parseFloat(item.cvss_score || item.cvss || 0);
  const kev     = !!item.kev_present;
  const epss    = parseFloat(item.epss_score || 0);
  const cveArr  = [...new Set((item.cve || item.cve_ids || []).filter(Boolean))].slice(0, 3);
  const products = (item.affected_products || []).filter(Boolean).slice(0, 5);
  const actor   = item.actor_tag && item.actor_tag !== "UNC-CDB-99" && item.actor_tag !== "UNC-UNKNOWN" ? item.actor_tag : null;

  // Business impact assessment
  const businessImpact =
    kev     ? "CRITICAL — Confirmed active exploitation. Immediate executive action required." :
    sev === "CRITICAL" || risk >= 9  ? "HIGH — Critical-severity vulnerability with significant breach potential." :
    sev === "HIGH"     || risk >= 7  ? "HIGH — Elevated risk requiring prioritized remediation within one business cycle." :
    sev === "MEDIUM"   || risk >= 5  ? "MODERATE — Standard risk requiring scheduled remediation." :
    "LOW — Minimal immediate business impact. Routine patching applies.";

  const financialImpact =
    kev     ? "Active exploitation risk. Breach scenario costs typically $4M+ (IBM Cost of Data Breach 2024). Incident response retainer activation recommended." :
    risk >= 8 ? "High-severity vulnerability. Unpatched systems carry significant breach cost exposure. Prioritize remediation before end of business cycle." :
    risk >= 6 ? "Medium financial exposure. Prioritize in next patching cycle. Compensating controls reduce risk." :
    "Low direct financial exposure. Standard operational risk mitigation applies.";

  const regulatoryImpact = [];
  const threatType = (item.threat_type || item.apex?.threat_category || "").toLowerCase();
  if (kev || risk >= 8) {
    regulatoryImpact.push("NIS2 Art.21: Significant incidents may require notification to national authority within 24h");
    regulatoryImpact.push("DORA Art.19: Financial entities must assess ICT-related incidents against reporting thresholds");
  }
  if (threatType.includes("data") || threatType.includes("breach") || threatType.includes("ransomware")) {
    regulatoryImpact.push("GDPR Art.33: Personal data breach notification within 72h of becoming aware");
    regulatoryImpact.push("SEC (US): Material cybersecurity incidents require 8-K disclosure within 4 business days");
  }
  if (regulatoryImpact.length === 0) {
    regulatoryImpact.push("Review against your applicable regulatory framework (NIS2, DORA, SOC 2, ISO 27001)");
  }

  // Executive talking points (board-level language)
  const talkingPoints = [
    `A ${_esc(sev.toLowerCase())}-severity ${_esc(item.threat_type || "security")} vulnerability has been identified affecting ${products.length > 0 ? products.slice(0,2).map(_esc).join(" and ") : "widely deployed infrastructure"}.`,
    kev ? "This vulnerability is confirmed to be actively exploited by threat actors in the wild, which elevates operational urgency." : null,
    epss > 10 ? `The exploitation probability model assigns ${epss.toFixed(1)}% probability of exploitation within 30 days, placing this above baseline risk.` : null,
    actor ? `Adversary group ${_esc(actor)} has been associated with this threat category based on available intelligence.` : null,
    cveArr.length > 0 ? `Tracked as ${cveArr.map(_esc).join(", ")} in the National Vulnerability Database.` : null,
  ].filter(Boolean);

  // Top 5 executive actions
  const execActions = [
    kev ? "IMMEDIATE: Direct IT Security to apply vendor patch or implement network isolation for affected systems" : `PRIORITY: Schedule remediation of ${_esc(sev)}-severity finding within ${risk >= 7 ? "one business cycle" : "standard maintenance window"}`,
    "Confirm your organization's exposure — identify all systems running affected software versions",
    kev || risk >= 8 ? "Brief CISO and Legal on breach risk profile and regulatory notification thresholds" : "Monitor vendor advisory for patch availability and updated severity assessments",
    "Verify cyber insurance policy coverage is current and incident response retainer is activated",
    "Request post-remediation confirmation from IT Security confirming all affected assets have been patched",
  ];

  const talkingRows = talkingPoints.map(p =>
    `<li style="padding:7px 0;border-bottom:1px solid rgba(255,255,255,.04);font-size:12.5px;color:#c4d0e3;line-height:1.65;">${_esc(p)}</li>`
  ).join("");

  const execActionRows = execActions.map((a, i) =>
    `<li style="display:flex;gap:10px;padding:9px 0;border-bottom:1px solid rgba(255,255,255,.04);">
      <span style="font-family:monospace;font-size:11px;color:#00d4aa;font-weight:900;flex-shrink:0;min-width:22px;">${i + 1}</span>
      <span style="font-size:12.5px;color:#c4d0e3;line-height:1.6;">${_esc(a)}</span>
    </li>`
  ).join("");

  const regRows = regulatoryImpact.map(r =>
    `<li style="padding:5px 0;font-size:11.5px;color:#94a3b8;">${_esc(r)}</li>`
  ).join("");

  const impactColor =
    kev || sev === "CRITICAL" || risk >= 9 ? "#dc2626" :
    sev === "HIGH" || risk >= 7 ? "#ea580c" : "#d97706";

  return `
  <!-- P19: EXECUTIVE VALUE BLOCK -->
  <div class="sec">
    <div class="sec-title">EXECUTIVE INTELLIGENCE BRIEF</div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px;margin-bottom:18px;">
      <div style="padding:14px 18px;background:rgba(${impactColor.replace("#","").match(/../g).map(h=>parseInt(h,16)).join(",")},0.06);border:1px solid ${impactColor}33;border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:6px;">BUSINESS IMPACT</div>
        <div style="font-size:13px;color:${impactColor};font-weight:700;line-height:1.5;">${_esc(businessImpact)}</div>
      </div>
      <div style="padding:14px 18px;background:rgba(100,116,139,.06);border:1px solid rgba(100,116,139,.15);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:6px;">FINANCIAL EXPOSURE</div>
        <div style="font-size:12px;color:#94a3b8;line-height:1.6;">${_esc(financialImpact)}</div>
      </div>
    </div>
    <div style="margin-bottom:16px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:10px;">BOARD TALKING POINTS</div>
      <ul style="list-style:none;padding:0;margin:0;">${talkingRows}</ul>
    </div>
    <div style="margin-bottom:16px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:10px;">TOP 5 EXECUTIVE ACTIONS</div>
      <ol style="list-style:none;padding:0;margin:0;">${execActionRows}</ol>
    </div>
    <div style="padding:14px 18px;background:rgba(59,130,246,.04);border:1px solid rgba(59,130,246,.12);border-radius:6px;">
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">REGULATORY CONSIDERATIONS</div>
      <ul style="list-style:none;padding:0;margin:0;">${regRows}</ul>
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// P19.7 — HTML: Analyst Block (certification, version, limitations)
// ---------------------------------------------------------------------------

export function buildAnalystBlock(item) {
  const evidence   = buildEvidenceAttribution(item);
  const confidence = computeTransparentConfidence(item);
  const validation = validateReportQuality(item, evidence, confidence);
  const certLevel  = computeCertificationLevel(validation.quality_score, validation);

  const aiSummary    = item.apex?.ai_summary || item.description || "";
  const analystNotes = item.analyst_notes || item.apex?.analyst_notes || null;

  // Analyst summary — structured paragraph with analyst-grade language
  const analystSummary = aiSummary
    ? `${aiSummary.slice(0, 600)}${aiSummary.length > 600 ? "..." : ""}`
    : `Advisory processed by SENTINEL APEX automated analysis pipeline. Manual analyst review recommended for ${evidence.evidence_count < 4 ? "this advisory due to limited evidence points" : "critical deployments"}. Source reliability: ${evidence.source_reliability.split(" — ")[0]}.`;

  const certColor = certLevel.certification_color;

  const failedCheckRows = validation.checks
    .filter(c => !c.pass)
    .map(c => `<li style="padding:4px 0;font-size:11px;color:#ea580c;">${_esc(c.label)} (weight: ${c.weight})</li>`)
    .join("");

  const passedCount  = validation.passed_checks;
  const failedCount  = validation.failed_checks;

  return `
  <!-- P19: ANALYST BLOCK -->
  <div class="sec">
    <div class="sec-title">ANALYST ASSESSMENT &amp; REPORT CERTIFICATION</div>
    <div style="display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:18px;">
      <div style="padding:14px 20px;background:rgba(${certColor.replace("#","").match(/../g).map(h=>parseInt(h,16)).join(",")},0.1);border:2px solid ${certColor}44;border-radius:8px;min-width:220px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;margin-bottom:6px;">CERTIFICATION LEVEL</div>
        <div style="font-family:monospace;font-size:15px;font-weight:900;color:${certColor};margin-bottom:4px;">${_esc(certLevel.certification_label)}</div>
        <div style="font-size:10px;color:#4b5563;line-height:1.5;">${_esc(certLevel.certification_description)}</div>
        <div style="margin-top:10px;display:flex;gap:12px;">
          <div><div style="font-family:monospace;font-size:9px;color:#374151;margin-bottom:2px;">QUALITY</div><div style="font-family:monospace;font-size:16px;font-weight:900;color:${certColor};">${certLevel.quality_score}</div></div>
          <div><div style="font-family:monospace;font-size:9px;color:#374151;margin-bottom:2px;">PASSED</div><div style="font-family:monospace;font-size:16px;font-weight:900;color:#00d4aa;">${passedCount}</div></div>
          <div><div style="font-family:monospace;font-size:9px;color:#374151;margin-bottom:2px;">FAILED</div><div style="font-family:monospace;font-size:16px;font-weight:900;color:${failedCount > 0 ? "#dc2626" : "#00d4aa"};">${failedCount}</div></div>
        </div>
      </div>
      <div style="flex:1;min-width:240px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">ANALYST SUMMARY</div>
        <p style="font-size:13px;color:#a8b8cc;line-height:1.75;margin:0;">${_esc(analystSummary)}</p>
        ${analystNotes ? `<div style="margin-top:12px;padding:10px 14px;background:rgba(0,212,170,.04);border-left:3px solid rgba(0,212,170,.3);border-radius:0 5px 5px 0;"><div style="font-family:monospace;font-size:9px;color:#00d4aa;letter-spacing:1px;margin-bottom:4px;">ANALYST NOTES</div><p style="font-size:12px;color:#94a3b8;margin:0;">${_esc(analystNotes)}</p></div>` : ""}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;">
      <div style="padding:12px 16px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">CERTIFICATION RATIONALE</div>
        <div style="font-size:11.5px;color:#94a3b8;line-height:1.6;">${_esc(certLevel.rationale)}</div>
      </div>
      <div style="padding:12px 16px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;">REVIEW STATUS</div>
        <div style="font-size:11.5px;color:#d97706;">${_esc(evidence.analyst_review_status)}</div>
        <div style="margin-top:8px;font-family:monospace;font-size:9px;color:#4b5563;">Customer deliverable: <span style="color:${certLevel.customer_deliverable ? "#00d4aa" : "#dc2626"};">${certLevel.customer_deliverable ? "YES" : "NO — quality gates must pass"}</span></div>
      </div>
      ${failedCheckRows ? `<div style="padding:12px 16px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.07);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#dc2626;letter-spacing:1.5px;margin-bottom:8px;">OPEN QUALITY ISSUES (${failedCount})</div>
        <ul style="list-style:none;padding:0;margin:0;">${failedCheckRows}</ul>
      </div>` : ""}
      ${evidence.limitations.length > 0 ? `<div style="padding:12px 16px;background:rgba(217,119,6,.04);border:1px solid rgba(217,119,6,.15);border-radius:6px;">
        <div style="font-family:monospace;font-size:9px;color:#d97706;letter-spacing:1.5px;margin-bottom:8px;">KNOWN LIMITATIONS</div>
        <ul style="list-style:none;padding:0;margin:0;">${evidence.limitations.map(l => `<li style="padding:3px 0;font-size:11px;color:#94a3b8;">${_esc(l)}</li>`).join("")}</ul>
      </div>` : ""}
    </div>
    <div style="margin-top:14px;padding:10px 14px;background:rgba(255,255,255,.02);border-radius:5px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;">
      <span style="font-family:monospace;font-size:9px;color:#374151;">REPORT VERSION: 1.0</span>
      <span style="font-family:monospace;font-size:9px;color:#374151;">CERTIFIED AT: ${_esc(certLevel.certified_at.replace("T"," ").slice(0,19))} UTC</span>
      <span style="font-family:monospace;font-size:9px;color:#374151;">ENGINE: SENTINEL APEX P19.0</span>
      <a href="/api/v1/reports/certify?id=${_esc(item.id || item.stix_id || "")}" style="font-family:monospace;font-size:9px;color:#00d4aa;">CERTIFICATION API →</a>
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// P19.10 — Certify API Handler
// ---------------------------------------------------------------------------

export async function handleP19Certify(request, env) {
  const url    = new URL(request.url);
  const itemId = url.searchParams.get("id") || null;
  const items  = await _loadFeed(env);

  if (!itemId) {
    return _jsonResp({ error: "id_required", message: "Provide ?id= advisory ID or STIX ID" }, 400);
  }

  const item = items.find(i => i.id === itemId || i.stix_id === itemId);
  if (!item) {
    return _jsonResp({ error: "advisory_not_found", id: itemId }, 404);
  }

  const evidence   = buildEvidenceAttribution(item);
  const confidence = computeTransparentConfidence(item);
  const validation = validateReportQuality(item, evidence, confidence);
  const certLevel  = computeCertificationLevel(validation.quality_score, validation);

  return _jsonResp({
    status:          "ok",
    engine:          "P19.10 Enterprise Certification Engine v1.0",
    generated_at:    _now(),
    advisory_id:     itemId,
    title:           (item.title || "").slice(0, 200),
    ...certLevel,
    quality_gate:    validation,
    evidence_summary: {
      evidence_count:  evidence.evidence_count,
      source_reliability: evidence.source_reliability,
      data_freshness:  evidence.data_freshness,
      chain_length:    evidence.chain_of_evidence.length,
      limitations:     evidence.limitations,
    },
    confidence_summary: {
      score: confidence.confidence_score,
      level: confidence.confidence_level,
    },
    certification_levels: CERT_LEVELS.map(l => ({
      id: l.id, label: l.label, min_score: l.minScore, description: l.description,
    })),
  });
}

// ---------------------------------------------------------------------------
// P19.11 — Scorecard API Handler
// ---------------------------------------------------------------------------

export async function handleP19Scorecard(request, env) {
  const items = await _loadFeed(env);

  if (items.length === 0) {
    return _jsonResp({ status: "no_data", message: "Feed data unavailable" }, 503);
  }

  const sample = items.slice(0, 500);

  const certDist = Object.fromEntries(CERT_LEVELS.map(l => [l.id, 0]));
  let totalScore = 0;
  let enterpriseReady = 0;
  let customerDeliverable = 0;

  const details = sample.map(item => {
    const evidence   = buildEvidenceAttribution(item);
    const confidence = computeTransparentConfidence(item);
    const validation = validateReportQuality(item, evidence, confidence);
    const certLevel  = computeCertificationLevel(validation.quality_score, validation);

    totalScore += certLevel.quality_score;
    if (certLevel.customer_deliverable) customerDeliverable++;
    if (certLevel.certification_id === "ENTERPRISE_READY" || certLevel.certification_id === "PREMIUM_INTELLIGENCE" || certLevel.certification_id === "PRODUCTION_CERTIFIED") enterpriseReady++;
    certDist[certLevel.certification_id] = (certDist[certLevel.certification_id] || 0) + 1;

    return {
      id:                  item.id || item.stix_id,
      title:               (item.title || "").slice(0, 80),
      severity:            item.severity,
      quality_score:       certLevel.quality_score,
      certification:       certLevel.certification_label,
      customer_deliverable: certLevel.customer_deliverable,
    };
  });

  const avgScore = Math.round(totalScore / sample.length);

  return _jsonResp({
    status:                  "ok",
    engine:                  "P19.11 Intelligence Scorecard Engine v1.0",
    generated_at:            _now(),
    feed_size:               sample.length,
    avg_quality_score:       avgScore,
    enterprise_ready_count:  enterpriseReady,
    enterprise_ready_pct:    Math.round((enterpriseReady / sample.length) * 100),
    customer_deliverable_pct: Math.round((customerDeliverable / sample.length) * 100),
    certification_distribution: certDist,
    certification_levels:    CERT_LEVELS.map(l => ({
      id: l.id, label: l.label, min_score: l.minScore, count: certDist[l.id] || 0,
      pct: Math.round(((certDist[l.id] || 0) / sample.length) * 100),
    })),
    commercial_assessment: {
      customer_deliverable_count: customerDeliverable,
      avg_quality_score:          avgScore,
      recommendation:
        avgScore >= 80 ? "Feed quality is enterprise-grade. Advisories are suitable for customer delivery." :
        avgScore >= 65 ? "Feed quality is adequate. Increase evidence enrichment and source diversity to improve." :
        "Feed quality requires improvement. Prioritize source expansion, MITRE mapping, and IOC enrichment.",
    },
    advisories: details,
  });
}
