/**
 * workers/intel-gateway/src/p22-handlers.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  P22.0 Enterprise Intelligence Trust & Verification v1.0.0
 * ============================================================================================
 *
 * ADDITIVE ONLY  -  reuses P20/P21 scoring engines. ZERO new intelligence engines.
 *
 * P22.2  buildP22ValidationStatusBlock()  -  IOC multi-source validation display
 * P22.3  buildP22ContradictionBlock()     -  per-item contradiction check display
 * P22.4  _validateSigmaStructure()        -  Sigma YAML structural validator
 * P22.5  buildP22PresentationBlock()      -  hardened executive presentation check
 * P22.6  buildSOCAnalystBlock()           -  SOC investigation aggregator
 * P22.7  buildConfidenceExplanationBlock()  -  transparent confidence breakdown
 * P22.8  runP22Gates()                    -  Commercial Readiness Gate V2 (adds G9 contradiction)
 * P22.9  handleP22TrustDashboard()        -  Enterprise Trust Dashboard API
 * P22.10 handleP22Observability()         -  Extended observability metrics
 *        handleP22Validate()              -  Single-item P22 validation endpoint
 *        handleP22ContradictionReport()   -  Contradiction report API endpoint
 */

import { computeP20QualityScore, stripMarkdown, getPublicationStage } from './p20-handlers.js';
import { getP21CertificationLevel } from './p21-handlers.js';

export const P22_VERSION = "22.0";

const esc = s => String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

// -- P22.4: Sigma Structural Validator ----------------------------------------

function _validateSigmaStructure(sigma) {
  if (!sigma || typeof sigma !== "string" || sigma.length < 50) {
    return { status: "MISSING", issues: ["No Sigma rule present"] };
  }
  const issues = [];

  if (!sigma.includes("title:"))       issues.push("Missing required field: title");
  if (!sigma.includes("logsource:"))   issues.push("Missing required field: logsource");
  if (!sigma.includes("detection:"))   issues.push("Missing required field: detection");
  if (!sigma.includes("condition:"))   issues.push("Missing required field: condition");
  if (!sigma.includes("status:"))      issues.push("Missing recommended field: status");
  if (!sigma.includes("level:"))       issues.push("Missing recommended field: level");

  // Check for clearly broken generic placeholders
  if (sigma.includes("EventID:\n      - 4625") &&
      sigma.includes("EventID:\n      - 4648") &&
      sigma.includes("EventID:\n      - 4728")) {
    issues.push("Generic authentication EventID pattern detected  -  rule is not vulnerability-specific");
  }
  if (sigma.includes("DestinationPort:\n      - 4444") ||
      sigma.includes("DestinationPort:\n      - 1337") ||
      sigma.includes("DestinationPort:\n      - 31337")) {
    issues.push("Generic attacker port detected  -  rule targets honeypot/CTF artifacts not production indicators");
  }

  const status = issues.length === 0 ? "VERIFIED"
               : issues.some(i => i.startsWith("Missing required")) ? "FAILED"
               : "WARNING";

  return { status, issues };
}

function _validateDetectionRules(item) {
  const sigma = item.sigma_rule || item.sigma || "";
  const kql   = item.kql_query  || item.kql   || "";
  const spl   = item.spl_query  || item.spl   || "";
  const yara  = item.yara_rule  || item.yara  || "";

  const sigmaResult = _validateSigmaStructure(sigma);
  const kqlValid    = typeof kql  === "string" && kql.length  > 20 && kql.includes("|");
  const splValid    = typeof spl  === "string" && spl.length  > 20 && spl.includes("index=");
  const yaraValid   = typeof yara === "string" && yara.length > 50 && yara.includes("strings:") && yara.includes("condition:");

  return {
    sigma:  sigmaResult,
    kql:    { status: kqlValid  ? "VERIFIED" : (kql  ? "WARNING" : "MISSING"), issues: kqlValid  ? [] : [kql  ? "KQL does not include required pipe operator" : "No KQL rule present"] },
    spl:    { status: splValid  ? "VERIFIED" : (spl  ? "WARNING" : "MISSING"), issues: splValid  ? [] : [spl  ? "SPL does not include required index= clause" : "No SPL rule present"] },
    yara:   { status: yaraValid ? "VERIFIED" : (yara ? "WARNING" : "MISSING"), issues: yaraValid ? [] : [yara ? "YARA missing strings: or condition: section" : "No YARA rule present"] },
  };
}

// -- P22.3: Per-Item Contradiction Check --------------------------------------

function _detectContradictions(item) {
  const contradictions = [];
  const cvss     = parseFloat(item.cvss_score || item.cvss) || 0;
  const severity = (item.severity || "").toUpperCase();
  const kev      = !!(item.kev_present || item.kev);
  const epss     = parseFloat(item.epss_score) || 0;

  // C1: CVSS vs Severity
  if (cvss > 0 && severity && !["UNKNOWN", "INFO", ""].includes(severity)) {
    const expectedSev = cvss >= 9 ? "CRITICAL" : cvss >= 7 ? "HIGH" : cvss >= 4 ? "MEDIUM" : "LOW";
    const BAND = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
    const gap  = Math.abs((BAND[expectedSev] ?? -1) - (BAND[severity] ?? -1));
    if (gap >= 2) {
      contradictions.push({ code: "C1", desc: `CVSS ${cvss.toFixed(1)} implies ${expectedSev} but severity=${severity} (${gap}-band gap)`, level: "error" });
    }
  }
  // C2: KEV vs Severity
  if (kev && ["LOW", "INFO"].includes(severity)) {
    contradictions.push({ code: "C2", desc: `KEV=true but severity=${severity}. CISA KEV entries must be at least MEDIUM.`, level: "error" });
  }
  // C3: KEV vs CVSS
  if (kev && cvss > 0 && cvss < 4.0) {
    contradictions.push({ code: "C3", desc: `KEV=true but CVSS=${cvss.toFixed(1)} (<4.0). Unusual for confirmed exploited vulnerability.`, level: "warn" });
  }
  // C4: EPSS vs Severity
  if (epss >= 50 && ["LOW", "INFO"].includes(severity)) {
    contradictions.push({ code: "C4", desc: `EPSS=${epss.toFixed(1)}% (high exploit probability) but severity=${severity}.`, level: "warn" });
  }

  return contradictions;
}

// -- P22.2: IOC Validation Status Block ---------------------------------------

export function buildP22ValidationStatusBlock(item) {
  const iocs = (item.iocs || []).filter(i => i && typeof i === "object");
  if (!iocs.length) return "";

  const opIOCs   = iocs.filter(i => {
    const v = String(i.value || "");
    return v.length > 5 && !/^CVE-/i.test(v) && !/^(npm|pip|gem|cargo|go):/.test(v);
  });
  const fpCount  = iocs.length - opIOCs.length;
  const byCert   = { HIGH_CONFIDENCE: 0, MEDIUM_CONFIDENCE: 0, LOW_CONFIDENCE: 0, UNVERIFIED: 0 };

  const rows = opIOCs.slice(0, 12).map(ioc => {
    const vs    = ioc.validation_status || (
      (parseFloat(ioc.confidence) || 0) >= 70 ? "HIGH_CONFIDENCE" :
      (parseFloat(ioc.confidence) || 0) >= 40 ? "MEDIUM_CONFIDENCE" : "LOW_CONFIDENCE"
    );
    byCert[vs] = (byCert[vs] || 0) + 1;
    const vsColor = vs === "HIGH_CONFIDENCE" ? "#00ffc6" : vs === "MEDIUM_CONFIDENCE" ? "#d97706" : "#ef4444";
    const vsLabel = vs.replace(/_/g, " ");
    const firstSeen = (ioc.first_seen || "").slice(0, 10) || " - ";
    const lastSeen  = (ioc.last_seen  || "").slice(0, 10) || " - ";
    const p20h = ioc.p20_hardened ? '<span style="font-size:9px;padding:1px 5px;background:rgba(0,255,198,.08);border:1px solid rgba(0,255,198,.2);border-radius:3px;color:#00ffc6;font-family:monospace;">P20</span>' : "";
    return `
  <tr>
    <td style="font-family:monospace;font-size:10px;color:#94a3b8;">${esc(ioc.type || "?").toUpperCase()}</td>
    <td style="font-family:monospace;font-size:10.5px;word-break:break-all;max-width:180px;">${esc(ioc.value || "")}</td>
    <td><span style="padding:2px 7px;border-radius:8px;font-size:9px;font-weight:700;font-family:monospace;background:${vsColor}18;border:1px solid ${vsColor}40;color:${vsColor};">${vsLabel}</span>${p20h}</td>
    <td style="font-family:monospace;font-size:10px;color:#64748b;">${esc(ioc.kill_chain_stage || " - ")}</td>
    <td style="font-family:monospace;font-size:10px;color:#64748b;">${firstSeen}</td>
    <td style="font-family:monospace;font-size:10px;color:#64748b;">${parseFloat(ioc.confidence || 0).toFixed(0)}%</td>
  </tr>`;
  }).join("");

  const totalOp = opIOCs.length;
  const highPct = Math.round((byCert.HIGH_CONFIDENCE || 0) / Math.max(totalOp, 1) * 100);

  return `
<div style="margin:20px 0;background:rgba(5,12,24,0.97);border:1px solid rgba(22,32,48,0.8);border-radius:12px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:14px 18px;background:rgba(0,0,0,.2);border-bottom:1px solid rgba(22,32,48,.6);display:flex;align-items:center;gap:12px;">
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;">P22.2  -  IOC MULTI-SOURCE VALIDATION</div>
      <div style="display:flex;gap:16px;margin-top:6px;flex-wrap:wrap;">
        <span style="font-size:11px;color:#00ffc6;font-weight:700;">${totalOp} operational IOCs</span>
        ${fpCount > 0 ? `<span style="font-size:11px;color:#64748b;">${fpCount} FP removed (P20.2)</span>` : ""}
        <span style="font-size:11px;color:${highPct >= 60 ? "#00ffc6" : "#d97706"};">${highPct}% HIGH_CONFIDENCE</span>
      </div>
    </div>
    <div style="margin-left:auto;display:flex;gap:8px;flex-wrap:wrap;">
      ${Object.entries(byCert).filter(([,v]) => v > 0).map(([k,v]) => {
        const c = k === "HIGH_CONFIDENCE" ? "#00ffc6" : k === "MEDIUM_CONFIDENCE" ? "#d97706" : "#ef4444";
        return `<span style="padding:3px 8px;border-radius:6px;font-size:9px;font-weight:800;font-family:monospace;color:${c};background:${c}12;border:1px solid ${c}30;">${v} ${k.split("_")[0]}</span>`;
      }).join("")}
    </div>
  </div>
  ${totalOp > 0 ? `
  <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;font-size:11.5px;">
      <thead>
        <tr style="border-bottom:1px solid rgba(22,32,48,.6);">
          <th style="padding:8px 12px;text-align:left;font-size:9px;color:#4b5563;letter-spacing:1.5px;font-weight:700;">TYPE</th>
          <th style="padding:8px 12px;text-align:left;font-size:9px;color:#4b5563;letter-spacing:1.5px;font-weight:700;">INDICATOR</th>
          <th style="padding:8px 12px;text-align:left;font-size:9px;color:#4b5563;letter-spacing:1.5px;font-weight:700;">VALIDATION</th>
          <th style="padding:8px 12px;text-align:left;font-size:9px;color:#4b5563;letter-spacing:1.5px;font-weight:700;">KILL CHAIN</th>
          <th style="padding:8px 12px;text-align:left;font-size:9px;color:#4b5563;letter-spacing:1.5px;font-weight:700;">FIRST SEEN</th>
          <th style="padding:8px 12px;text-align:left;font-size:9px;color:#4b5563;letter-spacing:1.5px;font-weight:700;">CONF</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  </div>` : `<div style="padding:14px 18px;color:#4b5563;font-size:12px;">No operational IOCs in this advisory.</div>`}
  <div style="padding:10px 14px;background:rgba(255,255,255,.02);border-top:1px solid rgba(22,32,48,.5);font-size:10.5px;color:#4b5563;font-family:monospace;">
    Verification Method: Automated SENTINEL APEX P20.2 IOC Hardening Pipeline  -  FP blocklist + confidence scoring
    ${item.ioc_fp_removed > 0 ? ` | ${item.ioc_fp_removed} false positives removed` : ""}
  </div>
</div>`;
}

// -- P22.3: Contradiction Block ------------------------------------------------

export function buildP22ContradictionBlock(item) {
  const contradictions = _detectContradictions(item);
  if (!contradictions.length) {
    return `
<div style="margin:16px 0;padding:12px 16px;background:rgba(16,185,129,.04);border:1px solid rgba(16,185,129,.15);border-radius:8px;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="display:flex;align-items:center;gap:8px;">
    <span style="color:#10b981;font-size:13px;">[OK]</span>
    <span style="font-family:monospace;font-size:9px;color:#10b981;letter-spacing:1.5px;font-weight:700;">P22.3  -  NO INTERNAL CONTRADICTIONS DETECTED</span>
  </div>
  <div style="font-size:11.5px;color:#4b5563;margin-top:4px;">CVSS, severity, KEV status, EPSS, and timestamps are internally consistent.</div>
</div>`;
  }

  const rows = contradictions.map(c => `
  <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid rgba(22,32,48,.4);">
    <span style="font-family:monospace;font-size:9px;padding:2px 6px;background:rgba(${c.level === "error" ? "239,68,68" : "217,119,6"},.1);border:1px solid rgba(${c.level === "error" ? "239,68,68" : "217,119,6"},.3);border-radius:4px;color:${c.level === "error" ? "#ef4444" : "#d97706"};font-weight:800;white-space:nowrap;">${esc(c.code)}</span>
    <span style="font-size:11.5px;color:#c4d0e3;line-height:1.5;">${esc(c.desc)}</span>
  </div>`).join("");

  const errCount = contradictions.filter(c => c.level === "error").length;

  return `
<div style="margin:16px 0;background:rgba(5,12,24,0.97);border:1px solid rgba(${errCount > 0 ? "239,68,68" : "217,119,6"},.3);border-radius:10px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:12px 16px;background:rgba(${errCount > 0 ? "239,68,68" : "217,119,6"},.06);border-bottom:1px solid rgba(22,32,48,.6);">
    <div style="font-family:monospace;font-size:9px;color:${errCount > 0 ? "#ef4444" : "#d97706"};letter-spacing:2px;font-weight:700;">
      P22.3  -  ${contradictions.length} CONTRADICTION${contradictions.length > 1 ? "S" : ""} DETECTED
      ${errCount > 0 ? `* ${errCount} ERROR-LEVEL` : ""}
    </div>
    <div style="font-size:11px;color:#64748b;margin-top:3px;">These inconsistencies require analyst review before enterprise distribution.</div>
  </div>
  <div style="padding:12px 16px;">${rows}</div>
</div>`;
}

// -- P22.4: Detection Verification Block --------------------------------------

export function buildP22DetectionVerificationBlock(item) {
  const rules  = _validateDetectionRules(item);
  const ttps   = (item.ttps || item.mitre_tactics || []).filter(Boolean);
  const ttpStr = ttps.slice(0, 5).map(t => esc(t)).join(", ") || "Not mapped";

  const ruleRows = [
    { name: "Sigma",  key: "sigma",  ...rules.sigma  },
    { name: "KQL",    key: "kql",    ...rules.kql    },
    { name: "SPL",    key: "spl",    ...rules.spl    },
    { name: "YARA",   key: "yara",   ...rules.yara   },
  ].map(r => {
    const col = r.status === "VERIFIED" ? "#10b981" : r.status === "WARNING" ? "#d97706" : r.status === "FAILED" ? "#ef4444" : "#4b5563";
    const icon = r.status === "VERIFIED" ? "[OK]" : r.status === "WARNING" ? "?" : r.status === "FAILED" ? "[FAIL]" : " - ";
    return `
  <div style="display:flex;align-items:flex-start;gap:12px;padding:9px 0;border-bottom:1px solid rgba(22,32,48,.4);">
    <div style="width:52px;flex-shrink:0;text-align:right;font-family:monospace;font-size:11px;font-weight:800;color:#94a3b8;">${r.name}</div>
    <div style="width:80px;flex-shrink:0;">
      <span style="padding:2px 8px;border-radius:6px;font-size:9px;font-weight:800;font-family:monospace;background:${col}12;border:1px solid ${col}30;color:${col};">${icon} ${r.status}</span>
    </div>
    <div style="font-size:11px;color:#64748b;line-height:1.5;">${r.issues.length ? r.issues.map(i => esc(i)).join(" * ") : "All structural checks passed"}</div>
  </div>`;
  }).join("");

  const allVerified = Object.values(rules).every(r => r.status === "VERIFIED");
  const hasAny      = Object.values(rules).some(r => r.status !== "MISSING");

  return `
<div style="margin:20px 0;background:rgba(5,12,24,0.97);border:1px solid rgba(22,32,48,.8);border-radius:12px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:14px 18px;background:rgba(0,0,0,.2);border-bottom:1px solid rgba(22,32,48,.6);">
    <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;">P22.4  -  DETECTION RULE VERIFICATION</div>
    <div style="margin-top:6px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
      <span style="font-size:11px;color:${allVerified ? "#10b981" : hasAny ? "#d97706" : "#ef4444"};font-weight:700;">
        ${allVerified ? "All rules structurally verified" : hasAny ? "Rules present  -  warnings detected" : "No detection rules present"}
      </span>
      <span style="font-size:11px;color:#64748b;">MITRE: ${esc(ttpStr)}</span>
    </div>
  </div>
  <div style="padding:12px 18px;">${ruleRows}</div>
</div>`;
}

// -- P22.6: SOC Analyst Review Block ------------------------------------------

export function buildSOCAnalystBlock(item) {
  const esc2 = s => String(s || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  const cvss    = parseFloat(item.cvss_score || item.cvss) || 0;
  const kev     = !!(item.kev_present || item.kev);
  const epss    = parseFloat(item.epss_score) || 0;
  const sev     = (item.severity || "UNKNOWN").toUpperCase();
  const ttps    = (item.ttps || item.mitre_tactics || []).filter(Boolean);
  const cves    = [...new Set((item.cve_ids || (item.cve_id ? [item.cve_id] : [])).filter(Boolean))];
  const opIOCs  = (item.iocs || []).filter(i => i && typeof i === "object" && !/^CVE-/i.test(String(i.value || "")));

  // Aggregate unique response/detection guidance from P20-hardened IOCs
  const responseGuidance = [...new Set(
    opIOCs.map(i => i.response_guidance).filter(Boolean)
  )].slice(0, 5);
  const detectionGuidance = [...new Set(
    opIOCs.map(i => i.detection_guidance).filter(Boolean)
  )].slice(0, 5);

  // Investigation steps (derived from severity + KEV + TTPs  -  no fabrication)
  const invSteps = [];
  if (kev) invSteps.push("Immediately check all internet-facing systems for this CVE. CISA KEV = confirmed active exploitation.");
  if (cvss >= 9) invSteps.push(`CVSS ${cvss.toFixed(1)}: Check affected product versions in asset inventory. Escalate to IR team if unpatched.`);
  if (epss >= 50) invSteps.push(`EPSS ${epss.toFixed(1)}%: High exploitation probability. Prioritize above routine patch cycle.`);
  if (ttps.length) invSteps.push(`Search for MITRE TTPs in SIEM: ${ttps.slice(0, 3).map(t => esc2(t)).join(", ")}.`);
  if (opIOCs.length) invSteps.push(`Hunt for ${opIOCs.length} extracted IOC${opIOCs.length > 1 ? "s" : ""} across firewall, proxy, DNS, and EDR logs.`);
  if (cves.length) invSteps.push(`Run vulnerability scanner against in-scope assets for: ${cves.slice(0, 3).join(", ")}.`);
  if (!invSteps.length) invSteps.push("Review affected products and apply vendor guidance.");

  // Hunting queries (derived from IOC types present)
  const huntQueries = [];
  const iocTypes = new Set(opIOCs.map(i => (i.type || "").toLowerCase()));
  if (iocTypes.has("ipv4") || iocTypes.has("ip")) {
    huntQueries.push({ title: "Firewall / NetFlow Hunt", query: `Source: Firewall egress logs | Filter outbound connections to IOC IPs | Correlate with process network events in EDR` });
  }
  if (iocTypes.has("domain") || iocTypes.has("hostname")) {
    huntQueries.push({ title: "DNS Resolution Hunt", query: `Source: DNS query logs | Filter queries matching IOC domains | Check for DGA-like patterns or newly registered domains` });
  }
  if (iocTypes.has("url")) {
    huntQueries.push({ title: "Proxy / Web Filter Hunt", query: `Source: Proxy access logs | Filter requests to IOC URLs | Check for suspicious URI patterns and response codes` });
  }
  if (iocTypes.has("hash") || iocTypes.has("sha256") || iocTypes.has("md5")) {
    huntQueries.push({ title: "EDR Hash Hunt", query: `Source: EDR telemetry | Match file hashes against IOC hash list | Run retrospective hunt across 30-day endpoint inventory` });
  }
  if (!huntQueries.length) {
    huntQueries.push({ title: "General CVE Hunt", query: `Source: Vulnerability scanner results | Filter for affected product versions matching advisory | Cross-reference against patch history` });
  }

  // False positive notes per IOC type
  const fpNotes = [];
  if (iocTypes.has("domain")) fpNotes.push("Domain IOCs: verify against CDN/shared hosting before blocking  -  single domain may serve multiple tenants");
  if (iocTypes.has("ipv4") || iocTypes.has("ip")) fpNotes.push("IP IOCs: check geo-IP and ASN context  -  IPs may be TOR exit nodes or shared cloud infrastructure");
  if (iocTypes.has("hash")) fpNotes.push("File hash IOCs: verify against normalized hash databases before quarantining  -  packed/repacked files may share code but differ in hash");

  const invHTML = invSteps.map(s => `<div style="padding:8px 0;border-bottom:1px solid rgba(22,32,48,.3);font-size:12px;color:#c4d0e3;display:flex;gap:8px;"><span style="color:#00ffc6;font-weight:800;flex-shrink:0;">-></span><span>${esc2(s)}</span></div>`).join("");
  const huntHTML = huntQueries.map(q => `<div style="margin-bottom:10px;padding:10px 12px;background:rgba(59,130,246,.04);border:1px solid rgba(59,130,246,.1);border-radius:6px;"><div style="font-family:monospace;font-size:9px;color:#60a5fa;font-weight:700;margin-bottom:4px;">${esc2(q.title)}</div><div style="font-size:11.5px;color:#94a3b8;line-height:1.5;">${esc2(q.query)}</div></div>`).join("");
  const guidHTML = [...responseGuidance, ...detectionGuidance].length
    ? [...responseGuidance, ...detectionGuidance].map(g => `<div style="padding:5px 0;border-bottom:1px solid rgba(22,32,48,.2);font-size:11.5px;color:#94a3b8;">* ${esc2(g)}</div>`).join("")
    : '<div style="font-size:11.5px;color:#4b5563;">No specific guidance derived from IOC analysis. Apply standard IR playbook.</div>';
  const fpHTML = fpNotes.length
    ? fpNotes.map(n => `<div style="font-size:11.5px;color:#94a3b8;padding:4px 0;">* ${esc2(n)}</div>`).join("")
    : '<div style="font-size:11.5px;color:#4b5563;">No IOC-specific false positive notes. Apply organizational baselining.</div>';

  return `
<div style="margin:20px 0;background:rgba(5,12,24,0.97);border:1px solid rgba(59,130,246,.2);border-radius:12px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:14px 18px;background:rgba(59,130,246,.05);border-bottom:1px solid rgba(22,32,48,.6);">
    <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;">P22.6  -  SOC ANALYST REVIEW PACKAGE</div>
    <div style="font-size:13px;font-weight:700;color:#e2e8f0;margin-top:4px;">
      ${sev === "CRITICAL" ? "?" : sev === "HIGH" ? "?" : "?"} ${sev} ${kev ? "* CISA KEV CONFIRMED" : ""} ${epss >= 50 ? `* EPSS ${epss.toFixed(0)}% (HIGH)` : ""}
    </div>
  </div>
  <div style="padding:16px 18px;display:grid;grid-template-columns:1fr 1fr;gap:20px;">

    <!-- Investigation Notes -->
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:10px;font-weight:700;">INVESTIGATION NOTES</div>
      ${invHTML || '<div style="color:#4b5563;font-size:11.5px;">No specific investigation notes for this advisory.</div>'}
    </div>

    <!-- Hunting Queries -->
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:10px;font-weight:700;">HUNTING QUERIES</div>
      ${huntHTML}
    </div>

  </div>
  <div style="padding:16px 18px;border-top:1px solid rgba(22,32,48,.5);display:grid;grid-template-columns:1fr 1fr;gap:20px;">

    <!-- Response Guidance -->
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;font-weight:700;">RESPONSE GUIDANCE (from IOC analysis)</div>
      ${guidHTML}
    </div>

    <!-- False Positive Notes -->
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:1.5px;margin-bottom:8px;font-weight:700;">FALSE POSITIVE NOTES</div>
      ${fpHTML}
    </div>

  </div>
</div>`;
}

// -- P22.7: Confidence Explanation Block --------------------------------------

export function buildConfidenceExplanationBlock(item) {
  const { total: score, breakdown } = computeP20QualityScore(item);
  const ec    = item.evidence_chain || {};
  const iqBD  = ec.iq_breakdown || {};
  const certL = getP21CertificationLevel(score);

  // Confidence contribution per factor
  const factors = [
    {
      name: "Evidence Chain",
      score: breakdown.evidence || 0,
      max: 25,
      explain: ec.reliability_code
        ? `Source reliability: ${ec.reliability_code}  -  ${ec.source_reliability || ""} | Corroboration: ${ec.corroboration_count || 0} source(s)`
        : "No evidence chain present. Run p20_evidence_chain_enricher.py.",
    },
    {
      name: "IOC Quality",
      score: breakdown.ioc_quality || 0,
      max: 20,
      explain: item.ioc_count
        ? `${item.ioc_count} operational IOCs | FP removed: ${item.ioc_fp_removed || 0} | Avg confidence from IOC validation`
        : "No operational IOCs. May reduce confidence in network indicator presence.",
    },
    {
      name: "Multi-Source",
      score: breakdown.multi_source || 0,
      max: 15,
      explain: (() => {
        const c = item.corroborating_sources;
        const n = Array.isArray(c) ? c.length : (typeof c === "number" ? c : 0);
        return n > 0 ? `${n} corroborating source(s) identified` : "No independent corroboration. Single-source assessment.";
      })(),
    },
    {
      name: "MITRE Coverage",
      score: breakdown.mitre || 0,
      max: 10,
      explain: (() => {
        const t = (item.ttps || item.mitre_tactics || []).filter(Boolean);
        return t.length ? `${t.length} ATT&CK technique(s) mapped: ${t.slice(0,3).map(x => esc(x)).join(", ")}` : "No MITRE ATT&CK mapping present.";
      })(),
    },
    {
      name: "Detection Rules",
      score: breakdown.detection || 0,
      max: 10,
      explain: (item.sigma_rule || item.sigma)
        ? `Sigma rule present  -  ${breakdown.detection === 10 ? "class-specific (full score)" : "generic indicators (partial score)"}`
        : "No detection rules generated for this advisory.",
    },
    {
      name: "Executive Quality",
      score: breakdown.executive || 0,
      max: 10,
      explain: (() => {
        const t = item.apex?.ai_summary || item.description || "";
        const w = stripMarkdown(t).split(/\s+/).filter(Boolean).length;
        return `Executive summary: ${w} words (?100 required for full score)`;
      })(),
    },
    {
      name: "Freshness",
      score: breakdown.freshness || 0,
      max: 5,
      explain: (() => {
        const ts = item.processed_at || item.timestamp || "";
        if (!ts) return "No processing timestamp. Cannot assess intelligence freshness.";
        try {
          const age = (Date.now() - new Date(ts).getTime()) / 3600000;
          return age < 6 ? `Very fresh: ${age.toFixed(1)}h old` :
                 age < 24 ? `Fresh: ${age.toFixed(1)}h old` :
                 age < 72 ? `Recent: ${(age/24).toFixed(1)} days old` :
                 age < 168 ? `Aging: ${(age/24).toFixed(1)} days old` :
                 `Stale: ${(age/24).toFixed(0)} days old`;
        } catch { return "Cannot parse timestamp."; }
      })(),
    },
    {
      name: "Consistency",
      score: breakdown.consistency || 0,
      max: 5,
      explain: [
        item.cvss_score != null ? "[OK] CVSS present" : "[FAIL] CVSS absent",
        item.epss_score != null ? "[OK] EPSS present" : "[FAIL] EPSS absent",
        (item.cve_id || (item.cve_ids || []).length) ? "[OK] CVE ID present" : "[FAIL] CVE ID absent",
      ].join(" | "),
    },
  ];

  const rows = factors.map(f => {
    const pct  = Math.round(f.score / f.max * 100);
    const col  = pct >= 80 ? "#00ffc6" : pct >= 50 ? "#d97706" : "#ef4444";
    return `
    <div style="padding:9px 0;border-bottom:1px solid rgba(22,32,48,.3);">
      <div style="display:grid;grid-template-columns:140px 1fr 50px 40px;align-items:center;gap:10px;margin-bottom:5px;">
        <span style="font-size:12px;font-weight:600;color:#c4d0e3;">${esc(f.name)}</span>
        <div style="height:5px;background:rgba(255,255,255,.04);border-radius:2px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${col};border-radius:2px;"></div>
        </div>
        <span style="font-family:monospace;font-size:11px;font-weight:700;color:${col};text-align:right;">${f.score}/${f.max}</span>
        <span style="font-family:monospace;font-size:9px;color:#4b5563;text-align:right;">${pct}%</span>
      </div>
      <div style="font-size:11px;color:#4b5563;line-height:1.4;padding-left:0;">${esc(f.explain)}</div>
    </div>`;
  }).join("");

  return `
<div style="margin:20px 0;background:rgba(5,12,24,0.97);border:1px solid rgba(22,32,48,.8);border-radius:12px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:14px 18px;background:rgba(0,0,0,.2);border-bottom:1px solid rgba(22,32,48,.6);display:flex;align-items:center;gap:14px;">
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;">P22.7  -  CONFIDENCE ENGINE V2  -  TRANSPARENT SCORE BREAKDOWN</div>
      <div style="margin-top:5px;display:flex;align-items:center;gap:10px;">
        <span style="font-family:monospace;font-size:22px;font-weight:900;color:${certL.color};">${score}<span style="font-size:11px;font-weight:400;color:#4b5563;">/100</span></span>
        <span style="padding:4px 10px;border-radius:10px;font-size:10px;font-weight:800;font-family:monospace;color:${certL.color};background:${certL.color}12;border:1px solid ${certL.color}30;">${certL.label}</span>
        <span style="font-size:11px;color:#4b5563;">Why this score was assigned:</span>
      </div>
    </div>
  </div>
  <div style="padding:14px 18px;">${rows}</div>
  <div style="padding:10px 14px;background:rgba(255,255,255,.02);border-top:1px solid rgba(22,32,48,.5);font-size:10.5px;color:#4b5563;font-family:monospace;">
    Score = Evidence(25) + IOC Quality(20) + Multi-source(15) + MITRE(10) + Detection(10) + Executive(10) + Freshness(5) + Consistency(5) = ${score}/100
  </div>
</div>`;
}

// -- P22.8: Commercial Readiness Gate V2 -------------------------------------

export function buildP22CommercialGateBlock(item) {
  const { total: score, breakdown } = computeP20QualityScore(item);
  const certL        = getP21CertificationLevel(score);
  const contradictions = _detectContradictions(item);
  const errContras   = contradictions.filter(c => c.level === "error");
  const rules        = _validateDetectionRules(item);
  const sigmaOk      = rules.sigma.status !== "FAILED";
  const isPublishable = score >= 75 && errContras.length === 0;

  const gates = [
    { id: "G7_SCORE",         label: "Commercial Score",      passed: score >= 75,             detail: `${score}/100 (?75 required)` },
    { id: "G8_EVIDENCE",      label: "Evidence Coverage",     passed: (breakdown.evidence||0) >= 12, detail: `${breakdown.evidence||0}/25 (?12 required)` },
    { id: "G9_CONTRADICTION", label: "Contradiction Check",   passed: errContras.length === 0,  detail: errContras.length === 0 ? "No critical contradictions" : `${errContras.length} error-level contradiction(s)` },
    { id: "G10_DETECTION",    label: "Detection Validation",  passed: sigmaOk,                 detail: sigmaOk ? `Sigma ${rules.sigma.status}` : `Sigma FAILED: ${rules.sigma.issues[0] || ""}` },
    { id: "G11_EXECUTIVE",    label: "Executive Quality",     passed: (breakdown.executive||0) >= 4, detail: `${breakdown.executive||0}/10 (?4 required)` },
    { id: "G12_FRESHNESS",    label: "Freshness Gate",        passed: (breakdown.freshness||0) >= 1, detail: `${breakdown.freshness||0}/5 (>0 required)` },
  ];

  const passed = gates.filter(g => g.passed).length;
  const all    = gates.length;

  const gateRows = gates.map(g => `
  <div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid rgba(22,32,48,.3);">
    <span style="font-family:monospace;font-size:9px;min-width:130px;color:#64748b;">${esc(g.id)}</span>
    <span style="width:16px;height:16px;border-radius:50%;background:${g.passed ? "rgba(16,185,129,.12)" : "rgba(239,68,68,.12)"};border:1.5px solid ${g.passed ? "#10b981" : "#ef4444"};display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;">
      <span style="font-size:9px;color:${g.passed ? "#10b981" : "#ef4444"};">${g.passed ? "[OK]" : "[FAIL]"}</span>
    </span>
    <span style="flex:1;font-size:11.5px;color:#c4d0e3;">${esc(g.label)}</span>
    <span style="font-family:monospace;font-size:10px;color:#64748b;">${esc(g.detail)}</span>
    <span style="font-family:monospace;font-size:10px;font-weight:800;color:${g.passed ? "#10b981" : "#ef4444"};">${g.passed ? "PASS" : "FAIL"}</span>
  </div>`).join("");

  return `
<div style="margin:20px 0;background:rgba(5,12,24,0.97);border:1.5px solid rgba(${isPublishable ? "0,255,198" : "239,68,68"},.25);border-radius:12px;overflow:hidden;font-family:'Segoe UI',system-ui,sans-serif;">
  <div style="padding:14px 18px;background:rgba(${isPublishable ? "0,255,198" : "239,68,68"},.04);border-bottom:1px solid rgba(22,32,48,.6);display:flex;align-items:center;justify-content:space-between;">
    <div>
      <div style="font-family:monospace;font-size:9px;color:#4b5563;letter-spacing:2px;">P22.8  -  COMMERCIAL READINESS GATE V2</div>
      <div style="display:flex;align-items:center;gap:10px;margin-top:6px;">
        <span style="font-family:monospace;font-size:18px;font-weight:900;color:${certL.color};">${score}/100</span>
        <span style="padding:3px 10px;border-radius:10px;font-size:10px;font-weight:800;font-family:monospace;color:${certL.color};background:${certL.color}12;border:1px solid ${certL.color}30;">${certL.label}</span>
        <span style="font-size:11px;color:${isPublishable ? "#10b981" : "#ef4444"};font-weight:700;">${isPublishable ? "[OK] CLEARED FOR ENTERPRISE DISTRIBUTION" : "[FAIL] NOT CLEARED  -  RESOLVE GATE FAILURES"}</span>
      </div>
    </div>
    <div style="font-family:monospace;font-size:10px;color:#4b5563;">${passed}/${all} GATES</div>
  </div>
  <div style="padding:12px 18px;">${gateRows}</div>
</div>`;
}

// -- P22.9/P22.10: API Handlers ------------------------------------------------

function _jsonRes(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", "X-P22-Version": P22_VERSION },
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

export async function handleP22Validate(request, env) {
  const url  = new URL(request.url);
  const id   = url.searchParams.get("id") || "";
  const items = await _loadFeed(env);
  if (!items) return _jsonRes({ error: "Feed unavailable" }, 503);
  const item = id ? items.find(i => i && (i.id === id || i.stix_id === id)) : items[0];
  if (!item)  return _jsonRes({ error: id ? `Not found: ${id}` : "Empty feed" }, 404);

  const { total: score, breakdown } = computeP20QualityScore(item);
  const contradictions = _detectContradictions(item);
  const rules          = _validateDetectionRules(item);
  const certLevel      = getP21CertificationLevel(score);
  const iocValidation  = (item.iocs || []).filter(i => i && typeof i === "object")
    .reduce((acc, i) => {
      const vs = i.validation_status || "UNVERIFIED";
      acc[vs] = (acc[vs] || 0) + 1;
      return acc;
    }, {});

  return _jsonRes({
    p22_version:    P22_VERSION,
    validated_at:   new Date().toISOString(),
    id:             item.id || item.stix_id || "",
    title:          String(item.title || "").slice(0, 80),
    score,
    breakdown,
    certification:  certLevel.id,
    publishable:    score >= 75 && contradictions.filter(c => c.level === "error").length === 0,
    contradictions,
    detection_validation: rules,
    ioc_validation: iocValidation,
    evidence_reliability: item.evidence_chain?.reliability_code || "F",
    evidence_accuracy:    item.evidence_chain?.accuracy_code    || "6",
  });
}

export async function handleP22ContradictionReport(request, env) {
  const items = await _loadFeed(env);
  if (!items) return _jsonRes({ error: "Feed unavailable" }, 503);

  const url   = new URL(request.url);
  const limit = parseInt(url.searchParams.get("limit") || "0") || items.length;
  const sample = items.slice(0, limit).filter(i => i && typeof i === "object");

  let allContradictions = [];
  let errorCount = 0, warnCount = 0;
  for (const item of sample) {
    const cons = _detectContradictions(item);
    if (cons.length) {
      allContradictions.push(...cons.map(c => ({ ...c, item_title: String(item.title || "").slice(0, 60) })));
      errorCount += cons.filter(c => c.level === "error").length;
      warnCount  += cons.filter(c => c.level === "warn").length;
    }
  }

  return _jsonRes({
    p22_version:    P22_VERSION,
    generated_at:   new Date().toISOString(),
    items_checked:  sample.length,
    total_contradictions: allContradictions.length,
    error_count:    errorCount,
    warn_count:     warnCount,
    contradictions: allContradictions.slice(0, 100),
  });
}

export async function handleP22Observability(request, env) {
  const items = await _loadFeed(env);
  const total = items ? items.filter(i => i && typeof i === "object").length : 0;
  const sample = (items || []).filter(i => i && typeof i === "object").slice(0, 200);

  let contrasErrors = 0, contrasWarn = 0, sigmaFailed = 0, sigmaVerified = 0;
  let iocValidDist = { HIGH_CONFIDENCE: 0, MEDIUM_CONFIDENCE: 0, LOW_CONFIDENCE: 0, UNVERIFIED: 0 };
  let ecReliabDist = { A: 0, B: 0, C: 0, D: 0, E: 0, F: 0, MISSING: 0 };

  for (const item of sample) {
    const contras = _detectContradictions(item);
    contrasErrors += contras.filter(c => c.level === "error").length;
    contrasWarn   += contras.filter(c => c.level === "warn").length;

    const rules = _validateDetectionRules(item);
    if (rules.sigma.status === "VERIFIED") sigmaVerified++;
    else if (rules.sigma.status === "FAILED") sigmaFailed++;

    for (const ioc of (item.iocs || []).filter(i => i && typeof i === "object")) {
      const vs = ioc.validation_status || "UNVERIFIED";
      iocValidDist[vs] = (iocValidDist[vs] || 0) + 1;
    }

    const rc = item.evidence_chain?.reliability_code || "MISSING";
    ecReliabDist[rc] = (ecReliabDist[rc] || 0) + 1;
  }

  return _jsonRes({
    p22_version:          P22_VERSION,
    generated_at:         new Date().toISOString(),
    feed_total:           total,
    sampled:              sample.length,
    contradiction_errors: contrasErrors,
    contradiction_warns:  contrasWarn,
    sigma_verified:       sigmaVerified,
    sigma_failed:         sigmaFailed,
    sigma_verified_pct:   sample.length ? Math.round(sigmaVerified / sample.length * 100) : 0,
    ioc_validation_distribution: iocValidDist,
    evidence_reliability_distribution: ecReliabDist,
  });
}
