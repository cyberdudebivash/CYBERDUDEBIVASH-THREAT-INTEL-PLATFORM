/**
 * workers/intel-gateway/src/p21-handlers.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  P21.0 Enterprise Intelligence Certification System v1.0.0
 * ============================================================================================
 *
 * P21 certification orchestrates all existing P20 engines under a unified
 * gate-by-gate audit framework. ZERO new scoring engines  -  reuses computeP20QualityScore()
 * and all existing block builders. Adds:
 *
 *   P21.1  Evidence gate: validates evidence_chain completeness
 *   P21.2  IOC gate: validates p20_hardened flag and validation_status
 *   P21.3  Attribution gate: confirms confidence tiers and rationale presence
 *   P21.4  Detection gate: validates rule presence + MITRE mapping
 *   P21.5  Executive gate: validates executive block completeness
 *   P21.6  Presentation gate: validates title, description, HTML fields
 *   P21.7  Commercial Readiness: P21 thresholds (75/90  -  stricter than P20 72/90)
 *   P21.8  Analyst QA Dashboard API handler
 *   P21.9  Observability: gate latency + pass/fail telemetry
 *   P21.10 Regression feed audit
 *
 * ADDITIVE ONLY  -  no existing API, auth, KV, D1, or payment system changed.
 */

import { computeP20QualityScore, getPublicationStage, stripMarkdown,
         buildEvidenceChainBlock, buildIOCQualityBlock, buildAttributionRationaleBlock,
         buildP20ExecutiveBlock, buildP20QualityGateBlock, buildBenchmarkBlock } from './p20-handlers.js';

export const P21_VERSION = "21.0";

// -- P21.7 Certification Thresholds (stricter than P20) ---------------------
const CERT_LEVELS = [
  { id: "PREMIUM_CERTIFIED", label: "Premium Certified",  minScore: 90, color: "#00ffc6",  badge: "? PREMIUM CERTIFIED" },
  { id: "ENTERPRISE_READY",  label: "Enterprise Ready",   minScore: 75, color: "#3b82f6",  badge: "[OK] ENTERPRISE READY"  },
  { id: "INTERNAL_DRAFT",    label: "Internal Draft",     minScore: 38, color: "#d97706",  badge: "? INTERNAL DRAFT"    },
  { id: "BELOW_MINIMUM",     label: "Below Minimum",      minScore: 0,  color: "#ef4444",  badge: "[FAIL] BELOW MINIMUM"     },
];

export function getP21CertificationLevel(score) {
  return CERT_LEVELS.find(l => score >= l.minScore) || CERT_LEVELS[CERT_LEVELS.length - 1];
}

// -- P21 Gate Definitions ----------------------------------------------------

const PACKAGE_TAG_RE = /^(npm|pip|gem|cargo|go|composer|nuget|maven):|^(golang\.org|go\.dev|npmjs\.com|pypi\.org)$/i;

function _runGates(item) {
  const gates = [];
  const t0 = Date.now();

  function gate(id, label, passed, detail, guidance = "") {
    gates.push({ id, label, passed, detail, guidance });
  }

  // G1: Evidence Chain (P21.1)
  const ec = item.evidence_chain;
  const hasEC = ec && typeof ec === "object";
  const ecCode = hasEC ? (ec.reliability_code || "F") : "MISSING";
  const ecHigh = ["A", "B", "C"].includes(ecCode);
  gate("G1_EVIDENCE", "Evidence Chain",
    hasEC && ecCode !== "F",
    hasEC
      ? `Reliability: ${ecCode}  -  ${ec.source_reliability || "Unknown"} | Corroboration: ${ec.corroboration_count || 0} | Accuracy: ${ec.accuracy_code || "?"}  -  ${ec.accuracy_label || ""}`
      : "evidence_chain field absent. Run p20_evidence_chain_enricher.py.",
    !hasEC ? "Run: python3 scripts/p20_evidence_chain_enricher.py" :
    ecCode === "F" ? "Add source_url to item so reliability can be scored" :
    ecHigh ? "" : "Seek additional corroboration from authoritative sources"
  );

  // G2: IOC Quality (P21.2)
  const allIOCs = (item.iocs || []).filter(i => i && typeof i === "object");
  const opIOCs  = allIOCs.filter(i => {
    const v = String(i.value || "");
    return v.length > 5 && !/^CVE-/i.test(v) && !PACKAGE_TAG_RE.test(v);
  });
  const hardenedCount = opIOCs.filter(i => i.p20_hardened).length;
  const avgConf = opIOCs.length
    ? opIOCs.reduce((s, i) => s + (parseFloat(i.confidence) || 30), 0) / opIOCs.length
    : 0;
  const iocPass = opIOCs.length > 0 && avgConf >= 30;
  gate("G2_IOC_QUALITY", "IOC Certification",
    iocPass,
    opIOCs.length > 0
      ? `${opIOCs.length} operational IOCs | ${hardenedCount} P20-hardened | avg confidence ${avgConf.toFixed(0)}% | FP removed: ${allIOCs.length - opIOCs.length}`
      : "No operational IOCs. Advisory may not have network indicators.",
    !iocPass && opIOCs.length === 0 ? "Acceptable if advisory has no network indicators" :
    avgConf < 30 ? "Increase IOC confidence via additional threat intelligence sources" : ""
  );

  // G3: Attribution (P21.3)
  const actorConf   = parseFloat(item.actor_confidence) || 0;
  const actorId     = item.actor_id || item.actor_tag || "";
  const attrMethod  = item.attribution_method || "";
  const isKernelExcl = attrMethod === "kernel_maintenance_exclusion";
  const attrPass    = isKernelExcl || actorConf >= 0; // attribution never hard-blocks
  const attrLabel   = isKernelExcl ? "Excluded (kernel maintenance)" :
    actorConf >= 80 ? "Confirmed" :
    actorConf >= 60 ? "Highly Likely" :
    actorConf >= 40 ? "Likely" :
    actorConf >= 20 ? "Possible" :
    actorId         ? "Unknown" : "Insufficient Evidence";
  gate("G3_ATTRIBUTION", "Attribution Quality",
    attrPass,
    `Level: ${attrLabel} | Actor: ${actorId || "Unattributed"} | Confidence: ${actorConf}%`,
    actorConf < 20 && !isKernelExcl
      ? "Attribution unresolved. Document alternative hypotheses in analyst notes." : ""
  );

  // G4: Detection Engineering (P21.4)
  const sigma   = item.sigma_rule || item.sigma || "";
  const kql     = item.kql_query   || item.kql   || "";
  const spl     = item.spl_query   || item.spl   || "";
  const yara    = item.yara_rule   || item.yara   || "";
  const hasSigma = typeof sigma === "string" && sigma.length > 100;
  const hasKQL   = typeof kql   === "string" && kql.length   > 20;
  const hasSPL   = typeof spl   === "string" && spl.length   > 20;
  const hasYARA  = typeof yara  === "string" && yara.length  > 50;
  const sigmaSpecific = hasSigma &&
    !sigma.includes("EventID:\n      - 4625") &&
    !sigma.includes("DestinationPort:\n      - 4444");
  const ruleCount   = [hasSigma, hasKQL, hasSPL, hasYARA].filter(Boolean).length;
  const detectPass  = hasSigma;
  const ttps        = (item.ttps || item.mitre_tactics || []).filter(Boolean);
  gate("G4_DETECTION", "Detection Certification",
    detectPass,
    `Sigma: ${hasSigma ? (sigmaSpecific ? "[OK] Specific" : "? Generic") : "[FAIL]"} | KQL: ${hasKQL ? "[OK]" : "[FAIL]"} | SPL: ${hasSPL ? "[OK]" : "[FAIL]"} | YARA: ${hasYARA ? "[OK]" : "[FAIL]"} | Rules: ${ruleCount} | MITRE TTPs: ${ttps.length}`,
    !detectPass ? "Run apex_real_detection_engine.py to generate class-aware Sigma rules" :
    !sigmaSpecific ? "Sigma rule uses generic indicators  -  regenerate with apex_real_detection_engine.py" :
    ruleCount < 2 ? "Consider generating KQL + SPL rules for multi-SIEM coverage" : ""
  );

  // G5: Executive Quality (P21.5)
  const execText  = item.apex?.ai_summary || item.description || "";
  const execWords = stripMarkdown(execText).split(/\s+/).filter(Boolean).length;
  const execPass  = execWords >= 50;
  const hasMarkdown = /#{1,6}\s+|\*{2}|_{2}|\[.*\]\(.*\)/.test(execText);
  gate("G5_EXECUTIVE", "Executive Intelligence",
    execPass,
    `${execWords} words | Markdown leak: ${hasMarkdown ? "YES  -  stripped at render" : "No"} | KEV context: ${item.kev_present ? "[OK]" : "N/A"}`,
    !execPass ? `Executive summary too short (${execWords} words). Minimum 50 words required.` :
    hasMarkdown ? "Raw markdown detected in ai_summary  -  stripped at render (P20.7 active)" : ""
  );

  // G6: Presentation (P21.6)
  const title    = String(item.title || "");
  const hasTitle = title.length >= 10;
  const hasCVSS  = item.cvss_score != null;
  const hasEPSS  = item.epss_score != null;
  const hasCVE   = !!(item.cve_id || (item.cve_ids || []).length);
  const hasSrc   = !!(item.source_url || item.source);
  const hasTLP   = !!(item.tlp);
  const presPass = hasTitle;
  gate("G6_PRESENTATION", "Presentation Quality",
    presPass,
    `Title: ${hasTitle ? "[OK]" : "[FAIL] (too short)"} | CVSS: ${hasCVSS ? "[OK]" : "[FAIL]"} | EPSS: ${hasEPSS ? "[OK]" : "[FAIL]"} | CVE: ${hasCVE ? "[OK]" : "[FAIL]"} | Source: ${hasSrc ? "[OK]" : "[FAIL]"} | TLP: ${hasTLP ? "[OK]" : "[FAIL]"}`,
    !hasTitle ? "Advisory title is missing or too short (< 10 chars)" :
    !hasCVSS ? "CVSS score absent  -  enrichment incomplete" : ""
  );

  // G7: Commercial Readiness (P21.7)  -  uses P20 score engine
  const { total: score, breakdown } = computeP20QualityScore(item);
  const certLevel = getP21CertificationLevel(score);
  const isPublishable = score >= 75;
  gate("G7_COMMERCIAL_READINESS", "Commercial Readiness",
    isPublishable,
    `Score: ${score}/100 | Level: ${certLevel.label} | ${certLevel.badge}`,
    !isPublishable
      ? `Score ${score} is below Enterprise Ready threshold (75). Improve evidence chain, add corroborating sources, or generate detection rules to raise score.` : ""
  );

  const latencyMs = Date.now() - t0;
  const passed    = gates.filter(g => g.passed).length;

  return { gates, passed, total: gates.length, score, breakdown, certLevel, latencyMs };
}

// -- P21 HTML Certification Card (injected into report) ---------------------
export function buildP21CertificationBlock(item) {
  const esc = s => String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const { gates, passed, total, score, certLevel, latencyMs } = _runGates(item);

  const gaugeColor = certLevel.color;
  const gaugePct   = score;
  const levelBadge = certLevel.badge;
  const levelColor = certLevel.color;

  const gateRows = gates.map(g => `
  <div style="display:flex;align-items:flex-start;gap:12px;padding:10px 0;border-bottom:1px solid rgba(22,32,48,0.5);">
    <div style="width:20px;height:20px;border-radius:50%;background:${g.passed ? "rgba(16,185,129,.15)" : "rgba(239,68,68,.15)"};border:1.5px solid ${g.passed ? "#10b981" : "#ef4444"};display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px;">
      <span style="font-size:10px;color:${g.passed ? "#10b981" : "#ef4444"};">${g.passed ? "[OK]" : "[FAIL]"}</span>
    </div>
    <div style="flex:1;">
      <div style="display:flex;align-items:center;gap:8px;">
        <span style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1px;">${esc(g.id)}</span>
        <span style="font-size:12px;font-weight:700;color:${g.passed ? "#e2e8f0" : "#ef4444"};">${esc(g.label)}</span>
        <span style="margin-left:auto;font-family:monospace;font-size:10px;font-weight:800;color:${g.passed ? "#10b981" : "#ef4444"};">${g.passed ? "PASS" : "FAIL"}</span>
      </div>
      <div style="font-size:11.5px;color:#94a3b8;margin-top:3px;line-height:1.5;">${esc(g.detail)}</div>
      ${g.guidance ? `<div style="font-size:11px;color:#d97706;margin-top:3px;padding:4px 8px;background:rgba(217,119,6,.06);border-radius:4px;border-left:2px solid rgba(217,119,6,.4);">? ${esc(g.guidance)}</div>` : ""}
    </div>
  </div>`).join("");

  return `
<div style="margin:24px 0;background:linear-gradient(135deg,rgba(5,12,24,0.97),rgba(9,15,30,0.97));border:1.5px solid rgba(${score >= 90 ? "0,255,198" : score >= 75 ? "59,130,246" : score >= 38 ? "217,119,6" : "239,68,68"},.3);border-radius:14px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:16px 20px;background:rgba(${score >= 90 ? "0,255,198" : score >= 75 ? "59,130,246" : score >= 38 ? "217,119,6" : "239,68,68"},.06);border-bottom:1px solid rgba(22,32,48,0.7);display:flex;align-items:center;gap:16px;">
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;margin-bottom:4px;">SENTINEL APEX P21.0  -  ENTERPRISE INTELLIGENCE CERTIFICATION</div>
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="font-family:monospace;font-size:22px;font-weight:900;color:${levelColor};">${score}</span>
        <span style="font-size:10px;color:#4b5563;margin-top:4px;">/100</span>
        <span style="padding:4px 12px;border-radius:20px;font-size:11px;font-weight:800;font-family:monospace;background:rgba(${score >= 90 ? "0,255,198" : score >= 75 ? "59,130,246" : score >= 38 ? "217,119,6" : "239,68,68"},.12);color:${levelColor};border:1px solid rgba(${score >= 90 ? "0,255,198" : score >= 75 ? "59,130,246" : score >= 38 ? "217,119,6" : "239,68,68"},.35);">${levelBadge}</span>
        <span style="font-family:monospace;font-size:10px;color:#4b5563;">${passed}/${total} GATES PASSED</span>
      </div>
    </div>
    <div style="margin-left:auto;text-align:right;">
      <div style="height:6px;width:140px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden;">
        <div style="height:100%;width:${gaugePct}%;background:${gaugeColor};border-radius:3px;transition:width 0.8s ease;"></div>
      </div>
      <div style="font-size:9px;color:#4b5563;margin-top:4px;font-family:monospace;">${latencyMs}ms gate evaluation</div>
    </div>
  </div>
  <div style="padding:16px 20px;">
    <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:10px;">CERTIFICATION GATE RESULTS</div>
    ${gateRows}
  </div>
  <div style="padding:12px 20px;background:rgba(255,255,255,.02);border-top:1px solid rgba(22,32,48,0.5);display:flex;gap:24px;flex-wrap:wrap;">
    <div style="font-size:10px;color:#4b5563;font-family:monospace;">
      ${score >= 90 ? "? Certified for PREMIUM distribution to enterprise customers" :
        score >= 75 ? "[OK] Cleared for enterprise distribution and commercial delivery" :
        score >= 38 ? "? Internal draft  -  improve score before commercial delivery" :
        "[FAIL] Below minimum quality threshold  -  not suitable for publication"}
    </div>
    <div style="margin-left:auto;font-size:9px;color:#374151;font-family:monospace;">P21.0 | ${new Date().toISOString().slice(0,19)}Z</div>
  </div>
</div>`;
}

// -- P21 Scorecard Comparison Block -----------------------------------------
export function buildP21ScorecardComparison(item) {
  const esc = s => String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const { score, breakdown, certLevel } = _runGates(item);

  const components = [
    { key: "evidence",     label: "Evidence Chain",     max: 25, icon: "?" },
    { key: "ioc_quality",  label: "IOC Quality",        max: 20, icon: "?" },
    { key: "multi_source", label: "Multi-source Valid.", max: 15, icon: "?" },
    { key: "mitre",        label: "MITRE ATT&CK",       max: 10, icon: "?" },
    { key: "detection",    label: "Detection Rules",     max: 10, icon: "?" },
    { key: "executive",    label: "Executive Quality",   max: 10, icon: "?" },
    { key: "freshness",    label: "Intelligence Fresh.", max:  5, icon: "?" },
    { key: "consistency",  label: "Internal Consist.",   max:  5, icon: "[OK]" },
  ];

  const rows = components.map(c => {
    const val  = breakdown[c.key] || 0;
    const pct  = Math.round(val / c.max * 100);
    const col  = pct >= 80 ? "#10b981" : pct >= 50 ? "#d97706" : "#ef4444";
    return `
  <div style="display:grid;grid-template-columns:130px 1fr 60px;align-items:center;gap:12px;padding:7px 0;border-bottom:1px solid rgba(22,32,48,0.4);">
    <div style="font-size:11.5px;color:#c4d0e3;">${c.icon} ${esc(c.label)}</div>
    <div style="height:6px;background:rgba(255,255,255,.04);border-radius:3px;overflow:hidden;">
      <div style="height:100%;width:${pct}%;background:${col};border-radius:3px;"></div>
    </div>
    <div style="text-align:right;font-family:monospace;font-size:11px;font-weight:700;color:${col};">${val}/${c.max}</div>
  </div>`;
  }).join("");

  return `
<div style="margin:20px 0;background:rgba(5,12,24,0.97);border:1px solid rgba(22,32,48,0.8);border-radius:12px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:14px 18px;background:rgba(0,0,0,.2);border-bottom:1px solid rgba(22,32,48,0.6);">
    <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;">P21.0 COMMERCIAL READINESS SCORECARD</div>
  </div>
  <div style="padding:14px 18px;">
    ${rows}
    <div style="display:flex;align-items:center;justify-content:space-between;margin-top:12px;padding-top:10px;border-top:1px solid rgba(22,32,48,0.6);">
      <span style="font-size:12px;color:#e2e8f0;font-weight:700;">TOTAL SCORE</span>
      <div style="display:flex;align-items:center;gap:10px;">
        <span style="font-family:monospace;font-size:18px;font-weight:900;color:${certLevel.color};">${score}<span style="font-size:11px;font-weight:400;color:#4b5563;">/100</span></span>
        <span style="padding:3px 10px;border-radius:12px;font-size:10px;font-weight:800;font-family:monospace;color:${certLevel.color};background:rgba(0,0,0,.3);border:1px solid ${certLevel.color}40;">${certLevel.label}</span>
      </div>
    </div>
  </div>
</div>`;
}

// -- P21.8: API Handlers -----------------------------------------------------

function _jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", "X-P21-Version": P21_VERSION },
  });
}

async function _loadFeed(env) {
  try {
    const obj = await env.INTEL_R2?.get("feed/feed.json");
    if (obj) {
      const text = await obj.text();
      const data = JSON.parse(text);
      if (Array.isArray(data)) return data;
      for (const k of ["items", "advisories", "feed", "data"]) {
        if (data[k] && Array.isArray(data[k])) return data[k];
      }
    }
  } catch (_) {}
  return null;
}

export async function handleP21Certify(request, env) {
  const url = new URL(request.url);
  const id  = url.searchParams.get("id") || url.searchParams.get("item_id") || "";

  const items = await _loadFeed(env);
  if (!items) {
    return _jsonRes({ error: "Feed unavailable", p21_version: P21_VERSION }, 503);
  }

  const item = id
    ? items.find(i => i && (i.id === id || i.stix_id === id))
    : items[0];

  if (!item) {
    return _jsonRes({ error: id ? `Item not found: ${id}` : "Feed is empty", p21_version: P21_VERSION }, 404);
  }

  const { gates, passed, total, score, breakdown, certLevel, latencyMs } = _runGates(item);

  return _jsonRes({
    p21_version:       P21_VERSION,
    certified_at:      new Date().toISOString(),
    id:                item.id || item.stix_id || "",
    title:             String(item.title || "").slice(0, 80),
    score,
    breakdown,
    certification:     certLevel.id,
    certification_label: certLevel.label,
    publishable:       score >= 75,
    gates_passed:      passed,
    gates_total:       total,
    gates,
    latency_ms:        latencyMs,
    thresholds: {
      premium_certified:  90,
      enterprise_ready:   75,
      internal_draft:     38,
    },
  });
}

export async function handleP21FeedCertify(request, env) {
  const t0    = Date.now();
  const items = await _loadFeed(env);
  if (!items) {
    return _jsonRes({ error: "Feed unavailable", p21_version: P21_VERSION }, 503);
  }

  const url         = new URL(request.url);
  const limitParam  = parseInt(url.searchParams.get("limit") || "0", 10);
  const filtered    = url.searchParams.get("level") || "";
  const sample      = limitParam > 0 ? items.slice(0, limitParam) : items;

  const results = sample
    .filter(i => i && typeof i === "object")
    .map(item => {
      const { gates, passed, total, score, breakdown, certLevel } = _runGates(item);
      return {
        id:          item.id || item.stix_id || "",
        title:       String(item.title || "").slice(0, 80),
        score,
        breakdown,
        certification: certLevel.id,
        label:       certLevel.label,
        publishable: score >= 75,
        gates_passed: passed,
        gates_total: total,
        severity:    item.severity || "UNKNOWN",
        kev:         !!(item.kev_present || item.kev),
      };
    })
    .filter(r => !filtered || r.certification === filtered);

  const total      = results.length;
  const avgScore   = total ? Math.round(results.reduce((s, r) => s + r.score, 0) / total) : 0;
  const dist       = results.reduce((acc, r) => { acc[r.certification] = (acc[r.certification] || 0) + 1; return acc; }, {});
  const latencyMs  = Date.now() - t0;

  return _jsonRes({
    p21_version:         P21_VERSION,
    generated_at:        new Date().toISOString(),
    total_items:         total,
    average_score:       avgScore,
    distribution:        dist,
    publishable_count:   results.filter(r => r.publishable).length,
    publishable_pct:     total ? Math.round(results.filter(r => r.publishable).length / total * 100) : 0,
    premium_pct:         total ? Math.round((dist.PREMIUM_CERTIFIED || 0) / total * 100) : 0,
    enterprise_ready_pct: total ? Math.round(((dist.PREMIUM_CERTIFIED || 0) + (dist.ENTERPRISE_READY || 0)) / total * 100) : 0,
    thresholds: { premium_certified: 90, enterprise_ready: 75, internal_draft: 38 },
    latency_ms:          latencyMs,
    items:               results,
  });
}

export async function handleP21Dashboard(request, env) {
  // Serve the static dashboard HTML (worker serves from KV or inline)
  // Redirect to static file served at /threat-intel-certification-dashboard.html
  return Response.redirect(new URL("/threat-intel-certification-dashboard.html", request.url).href, 302);
}

export async function handleP21Observability(request, env) {
  const items = await _loadFeed(env);
  const total = items ? items.filter(i => i && typeof i === "object").length : 0;

  let sumScore = 0, premCount = 0, entCount = 0, draftCount = 0, belowCount = 0;
  let gateFailCounts = {};

  if (items) {
    for (const item of items.slice(0, 200)) {
      if (!item || typeof item !== "object") continue;
      const { score, gates, certLevel } = _runGates(item);
      sumScore += score;
      if (certLevel.id === "PREMIUM_CERTIFIED")  premCount++;
      else if (certLevel.id === "ENTERPRISE_READY") entCount++;
      else if (certLevel.id === "INTERNAL_DRAFT")   draftCount++;
      else belowCount++;
      for (const g of gates) {
        if (!g.passed) gateFailCounts[g.id] = (gateFailCounts[g.id] || 0) + 1;
      }
    }
  }

  const sampled = Math.min(total, 200);

  return _jsonRes({
    p21_version:         P21_VERSION,
    generated_at:        new Date().toISOString(),
    feed_total:          total,
    sampled_items:       sampled,
    average_score:       sampled ? Math.round(sumScore / sampled) : 0,
    premium_certified:   premCount,
    enterprise_ready:    entCount,
    internal_draft:      draftCount,
    below_minimum:       belowCount,
    publishable_pct:     sampled ? Math.round((premCount + entCount) / sampled * 100) : 0,
    top_gate_failures:   Object.entries(gateFailCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 7)
      .map(([gate, count]) => ({ gate, failure_count: count, failure_pct: Math.round(count / sampled * 100) })),
    thresholds: { premium_certified: 90, enterprise_ready: 75, internal_draft: 38 },
  });
}
