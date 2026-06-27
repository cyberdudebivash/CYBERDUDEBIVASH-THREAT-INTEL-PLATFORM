/**
 * workers/intel-gateway/src/p23-handlers.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX  -  P23.0 Enterprise Actionable Intelligence Framework
 * =====================================================================================
 * Transforms every threat intelligence report into an enterprise operational intelligence
 * package that a SOC analyst can immediately deploy.
 *
 * Components (all additive  -  P1-P22 unchanged):
 *   P23.3   -  Threat Hunting Package
 *   P23.4   -  Incident Response Package
 *   P23.5   -  Risk-Based Patch Prioritization
 *   P23.7   -  Compliance Intelligence Mapping
 *   P23.8   -  Detection Coverage Analysis
 *   P23.10  -  Operational Readiness Gate
 *   P23.11  -  Enterprise Actionability Score
 *   API     -  handleP23Actionability, handleP23OperationalReadiness, handleP23Observability
 *
 * ZERO FABRICATION  -  all intelligence derived from existing item field data.
 * ADDITIVE ONLY    -  no existing schema, API, KV, or handler modified.
 */

import { computeP20QualityScore } from './p20-handlers.js';
import { getP21CertificationLevel } from './p21-handlers.js';

export const P23_VERSION = "P23.0";

// -- Shared HTML escape --------------------------------------------------------
function esc(s) {
  return String(s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// -- Block container wrapper ---------------------------------------------------
function _block(id, title, color, body) {
  return `
<div id="${id}" style="margin:24px 0;padding:20px 24px;background:#0d1117;border:1px solid ${color}33;border-left:3px solid ${color};border-radius:6px;font-family:'Courier New',monospace;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px;">
    <span style="color:${color};font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;">${esc(title)}</span>
    <span style="color:#333;font-size:10px;">P23.0 * SENTINEL APEX</span>
  </div>
  ${body}
</div>`;
}

// -- Badge ---------------------------------------------------------------------
function _badge(text, color, bg) {
  return `<span style="display:inline-block;padding:2px 8px;background:${bg || color + '22'};color:${color};border:1px solid ${color}55;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:.08em;">${esc(text)}</span>`;
}

// -- Mini progress bar ---------------------------------------------------------
function _bar(pct, color) {
  return `<div style="background:#1a1f2e;border-radius:2px;height:4px;width:100%;margin:4px 0;">
    <div style="background:${color};height:4px;border-radius:2px;width:${Math.min(100, Math.max(0, pct))}%;"></div>
  </div>`;
}

// -- Row helper ----------------------------------------------------------------
function _row(label, value, color) {
  return `<div style="display:flex;justify-content:space-between;align-items:flex-start;padding:5px 0;border-bottom:1px solid #1a1f2e;">
    <span style="color:#8b949e;font-size:11px;">${esc(label)}</span>
    <span style="color:${color || '#e6edf3'};font-size:11px;font-weight:600;text-align:right;max-width:60%;">${esc(String(value))}</span>
  </div>`;
}

// -----------------------------------------------------------------------------
// P23.5  -  Risk-Based Patch Prioritization
// -----------------------------------------------------------------------------

function _computePatchPriority(item) {
  const cvss    = parseFloat(item.cvss_score || item.cvss || 0);
  const epss    = parseFloat(item.epss_score || 0);
  const kev     = !!(item.kev_present || item.kev);
  const exploit = item.exploit_maturity || item.has_exploit || item.exploit_available;
  const hasPoc  = String(exploit || "").match(/poc|exploited|public|wild/i);

  let score = 0;
  const reasons = [];

  if (kev)        { score += 40; reasons.push("Listed in CISA KEV  -  confirmed active exploitation in the wild"); }
  if (cvss >= 9)  { score += 25; reasons.push(`CVSS ${cvss.toFixed(1)}  -  Critical severity (network-exploitable, no authentication required)`); }
  else if (cvss >= 7) { score += 15; reasons.push(`CVSS ${cvss.toFixed(1)}  -  High severity`); }
  else if (cvss >= 4) { score +=  8; reasons.push(`CVSS ${cvss.toFixed(1)}  -  Medium severity`); }
  if (epss >= 50) { score += 20; reasons.push(`EPSS ${epss.toFixed(1)}%  -  High probability of exploitation within 30 days`); }
  else if (epss >= 10) { score += 10; reasons.push(`EPSS ${epss.toFixed(1)}%  -  Elevated exploitation probability`); }
  if (hasPoc)     { score += 15; reasons.push("Public exploit code or PoC available  -  exploitation barrier is low"); }

  let priority, timeframe, color, rationale;
  if (kev || score >= 55) {
    priority = "PATCH IMMEDIATELY";     timeframe = "Within 24 hours";   color = "#ef4444";
    rationale = "Immediate patch deployment is mandatory. Delays create unacceptable operational risk.";
  } else if (score >= 35) {
    priority = "PATCH WITHIN 24 HOURS"; timeframe = "Within 24 hours";  color = "#f97316";
    rationale = "Treat as emergency change. Schedule out-of-band patching with change management approval.";
  } else if (score >= 20) {
    priority = "PATCH WITHIN 7 DAYS";  timeframe = "Within 7 days";     color = "#eab308";
    rationale = "Patch in next security maintenance window. Apply compensating controls until patched.";
  } else if (score >= 10) {
    priority = "PATCH THIS MONTH";      timeframe = "Within 30 days";   color = "#3b82f6";
    rationale = "Schedule in next planned maintenance cycle. Monitor for exploitation uptick.";
  } else if (cvss > 0) {
    priority = "MONITOR";               timeframe = "Track for changes"; color = "#6b7280";
    rationale = "No immediate patch required. Monitor KEV and EPSS for escalation.";
  } else {
    priority = "NO IMMEDIATE ACTION";   timeframe = "Standard review cycle"; color = "#4b5563";
    rationale = "Insufficient scoring data. Assess manually if asset exposure is relevant.";
  }

  return { priority, timeframe, color, score, reasons, rationale };
}

export function buildPatchPriorityBlock(item) {
  if (!item || typeof item !== 'object') return '';
  const cvss = parseFloat(item.cvss_score || item.cvss || 0);
  if (cvss === 0 && !item.kev_present && !item.kev) return '';

  const p = _computePatchPriority(item);
  const cve = item.cve_id || (item.cve_ids || [])[0] || null;

  const reasonsHtml = p.reasons.map(r =>
    `<li style="color:#8b949e;font-size:11px;margin:4px 0;">[OK] ${esc(r)}</li>`
  ).join("") || `<li style="color:#4b5563;font-size:11px;">No explicit risk factors scored</li>`;

  const body = `
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:16px;">
      <div style="padding:8px 16px;background:${p.color}18;border:1px solid ${p.color};border-radius:4px;">
        <div style="color:${p.color};font-size:13px;font-weight:700;letter-spacing:.1em;">${esc(p.priority)}</div>
        <div style="color:#8b949e;font-size:10px;margin-top:2px;">${esc(p.timeframe)}</div>
      </div>
      <div style="flex:1;">
        <div style="color:#e6edf3;font-size:11px;margin-bottom:4px;">${esc(p.rationale)}</div>
        ${cve ? `<div style="color:#8b949e;font-size:10px;">CVE: <span style="color:#3b82f6;">${esc(cve)}</span></div>` : ''}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;">
      ${_row("Priority Score", `${p.score}/100`, p.color)}
      ${_row("CVSS Score", cvss > 0 ? cvss.toFixed(1) : "N/A", cvss >= 9 ? "#ef4444" : cvss >= 7 ? "#f97316" : "#eab308")}
      ${_row("EPSS", item.epss_score ? `${parseFloat(item.epss_score).toFixed(1)}%` : "N/A", parseFloat(item.epss_score || 0) >= 50 ? "#ef4444" : "#8b949e")}
      ${_row("CISA KEV", (item.kev_present || item.kev) ? "YES  -  Active Exploitation" : "Not Listed", (item.kev_present || item.kev) ? "#ef4444" : "#6b7280")}
    </div>
    <div style="margin-top:12px;">
      <div style="color:#8b949e;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:6px;">Risk Factors</div>
      <ul style="margin:0;padding-left:0;list-style:none;">${reasonsHtml}</ul>
    </div>`;

  return _block("p23-patch", "P23.5  -  Risk-Based Patch Prioritization", p.color, body);
}

// -----------------------------------------------------------------------------
// P23.7  -  Compliance Intelligence Mapping
// -----------------------------------------------------------------------------

const _COMPLIANCE_RULES = [
  {
    frameworks: ["NIST CSF 2.0  -  RS.MI (Mitigation)", "NIST CSF 2.0  -  DE.CM (Continuous Monitoring)", "NIST CSF 2.0  -  PR.IP (Information Protection)"],
    condition: () => true,
    reason: "All threat intelligence triggers NIST CSF Identify/Protect/Detect/Respond/Recover functions requiring risk assessment, monitoring updates, and documented response procedures.",
  },
  {
    frameworks: ["NIST SP 800-53 Rev5  -  SI-2 (Flaw Remediation)", "NIST SP 800-53 Rev5  -  RA-5 (Vulnerability Monitoring)", "NIST SP 800-53 Rev5  -  IR-4 (Incident Handling)"],
    condition: () => true,
    reason: "NIST 800-53 mandates flaw remediation (SI-2), continuous vulnerability monitoring (RA-5), and documented incident handling procedures (IR-4) for all federal and FedRAMP systems.",
  },
  {
    frameworks: ["CIS Control 7  -  Continuous Vulnerability Management", "CIS Control 17  -  Incident Response Management"],
    condition: () => true,
    reason: "CIS Controls require systematic vulnerability identification, prioritized remediation, and maintained incident response capability.",
  },
  {
    frameworks: ["ISO/IEC 27001:2022  -  A.8.8 (Technical Vulnerability Management)", "ISO/IEC 27001:2022  -  A.5.25 (Information Security Incident Response)"],
    condition: () => true,
    reason: "ISO 27001 Annex A mandates timely identification and remediation of technical vulnerabilities and a documented incident response process.",
  },
  {
    frameworks: ["SOC 2 Type II  -  CC7.1 (Threat & Vulnerability Management)", "SOC 2 Type II  -  CC7.2 (Monitoring for Malicious Activity)", "SOC 2 Type II  -  CC7.4 (Response to Identified Security Events)"],
    condition: () => true,
    reason: "SOC 2 Common Criteria require identification and response to vulnerabilities and security events affecting the trust service categories.",
  },
  {
    frameworks: ["PCI DSS 4.0  -  Req 6.3 (Security Vulnerability Management)", "PCI DSS 4.0  -  Req 11.3 (External & Internal Penetration Testing)"],
    condition: (item) => (parseFloat(item.cvss_score || 0) >= 7 || item.kev || item.kev_present),
    reason: "PCI DSS 4.0 Requirement 6.3 mandates timely remediation of critical and high vulnerabilities for all entities handling cardholder data.",
  },
  {
    frameworks: ["DORA (EU 2022/2554)  -  Art. 10 (ICT Incident Classification)", "DORA  -  Art. 13 (Digital Operational Resilience Testing)", "DORA  -  Art. 17 (ICT Incident Management Process)"],
    condition: (item) => String(item.severity || "").match(/CRITICAL|HIGH/i) || item.kev || item.kev_present,
    reason: "DORA mandates EU financial entities classify, manage, and report ICT-related incidents. High severity or KEV-confirmed vulnerabilities qualify as major incidents requiring NCA notification.",
  },
  {
    frameworks: ["NIS2 Directive (EU 2022/2555)  -  Art. 21 (Cybersecurity Risk-Management)", "NIS2  -  Art. 23 (Significant Incident Reporting  -  24h initial / 72h detailed)"],
    condition: (item) => String(item.severity || "").match(/CRITICAL|HIGH/i),
    reason: "NIS2 requires essential and important entities to implement risk-management measures and report significant incidents. High/Critical advisories may trigger mandatory notification obligations.",
  },
];

function _buildComplianceMappings(item) {
  const mappings = [];
  for (const rule of _COMPLIANCE_RULES) {
    try {
      if (rule.condition(item)) mappings.push({ frameworks: rule.frameworks, reason: rule.reason });
    } catch (_) {}
  }

  // MITRE ATT&CK
  const mitres = item.mitre_techniques || item.apex?.mitre_techniques || [];
  if (mitres.length > 0) {
    const techList = mitres.slice(0, 5).map(t =>
      `MITRE ATT&CK  -  ${typeof t === 'string' ? t : (t.technique_id || t.id || JSON.stringify(t))}`
    );
    mappings.push({
      frameworks: techList,
      reason: "Threat actor TTPs in this advisory map directly to MITRE ATT&CK Enterprise framework techniques, enabling technique-based detection engineering and control gap analysis.",
    });
  }

  return mappings;
}

export function buildComplianceBlock(item) {
  if (!item || typeof item !== 'object') return '';

  const mappings = _buildComplianceMappings(item);
  if (!mappings.length) return '';

  const rows = mappings.map(m => `
    <div style="margin:10px 0;padding:10px 12px;background:#0f1318;border-radius:4px;border-left:2px solid #3b82f6;">
      <div style="margin-bottom:6px;">${m.frameworks.map(f => _badge(f, "#3b82f6")).join(' ')}</div>
      <div style="color:#8b949e;font-size:11px;line-height:1.5;">${esc(m.reason)}</div>
    </div>`).join("");

  const body = `
    <div style="color:#8b949e;font-size:11px;margin-bottom:14px;">
      ${mappings.reduce((n, m) => n + m.frameworks.length, 0)} framework controls mapped across ${mappings.length} regulatory domains.
    </div>
    ${rows}`;

  return _block("p23-compliance", "P23.7  -  Compliance Intelligence Mapping", "#3b82f6", body);
}

// -----------------------------------------------------------------------------
// P23.3  -  Threat Hunting Package
// -----------------------------------------------------------------------------

function _buildHuntObjectives(item) {
  const kev    = !!(item.kev_present || item.kev);
  const cve    = item.cve_id || (item.cve_ids || [])[0] || null;
  const actor  = item.actor || item.actor_id || item.actor_tag || null;
  const iocs   = item.iocs || [];
  const mitres = item.mitre_techniques || item.apex?.mitre_techniques || [];
  const epss   = parseFloat(item.epss_score || 0);

  const objectives = [];
  if (kev)    objectives.push("Confirm whether this actively exploited vulnerability has been triggered in your environment  -  check all ingress and exploitation logs for indicators");
  if (cve)    objectives.push(`Identify all systems affected by ${cve}  -  cross-reference asset inventory with affected versions and deployment scope`);
  if (actor)  objectives.push(`Hunt for presence indicators of threat actor ${actor}  -  pivot on known infrastructure, TTPs, and campaign artifacts`);
  objectives.push("Identify post-exploitation lateral movement, persistence mechanisms, and data exfiltration patterns following initial compromise");
  objectives.push("Validate that patch deployment is complete and effective across all affected asset classes and business units");
  if (iocs.length > 0) objectives.push(`Sweep all endpoint and network telemetry for ${iocs.length} associated indicators  -  include historical lookback of 90 days`);
  if (epss >= 20) objectives.push(`EPSS ${epss.toFixed(1)}% indicates elevated exploitation probability  -  proactively hunt for pre-compromise scanning or reconnaissance activity`);

  const logSources = [];
  const iocTypes = new Set(iocs.map(i => (i.type || "").toLowerCase()).filter(Boolean));
  if (iocTypes.has("ip") || iocTypes.has("domain") || iocTypes.has("url")) {
    logSources.push("Firewall/proxy logs  -  outbound connection attempts to listed IP/domain/URL indicators");
    logSources.push("DNS query logs  -  suspicious resolution patterns, DGA activity, unusual TLD queries");
  }
  if (iocTypes.has("hash") || iocTypes.has("md5") || iocTypes.has("sha256") || iocTypes.has("sha1")) {
    logSources.push("EDR/AV telemetry  -  file hash matches on endpoint devices and email gateways");
  }
  logSources.push("Windows Security Events  -  4624/4625 (auth), 4648 (explicit creds), 4672 (priv assign), 4688 (process creation)");
  logSources.push("SIEM correlation alerts  -  retrospective review against existing detection rules");
  if (String(item.threat_type || "").match(/web|api|sql|xss|injection/i)) {
    logSources.push("WAF and application logs  -  HTTP request patterns, status 4xx/5xx spikes, unusual parameter encoding");
  }
  if (mitres.some(t => String(t).match(/T1055|T1059|T1078|T1086|T1105/))) {
    logSources.push("PowerShell / WMI / command interpreter logs  -  unusual parent-child process relationships");
    logSources.push("Memory forensics  -  process injection, reflective loading, LSASS access");
  }
  logSources.push("Cloud audit logs (AWS CloudTrail / Azure Activity / GCP Audit)  -  IAM changes, unusual API calls");
  logSources.push("Email gateway logs  -  phishing delivery, malicious attachments, credential harvesting URLs");

  const pivots = [];
  iocs.slice(0, 6).forEach(ioc => {
    const v = String(ioc.value || "");
    if (ioc.type === "ip")     pivots.push(`IP ${esc(v)} -> expand to /24 subnet, reverse DNS, ASN lookup, BGP history`);
    else if (ioc.type === "domain") pivots.push(`Domain ${esc(v)} -> registrar, NS records, WHOIS history, passive DNS, certificate transparency`);
    else if (ioc.type === "hash")   pivots.push(`Hash ${v.substring(0, 20)}... -> VirusTotal, similar hashes, parent/child process tree, file signer`);
    else if (ioc.type === "url")    pivots.push(`URL -> extract host + path pattern, check URL shortener history, referrer chains`);
    else if (ioc.type === "email")  pivots.push(`Email ${esc(v)} -> sender infrastructure, registrar, mail exchange records, spoofing indicators`);
  });
  if (actor)  pivots.push(`Actor ${esc(actor)} -> known infrastructure clusters, published campaigns, MITRE group profile`);
  if (cve)    pivots.push(`${esc(cve)} -> scan asset inventory for vulnerable versions, cross-reference with patch management data`);

  return { objectives, logSources, pivots, mitres };
}

export function buildThreatHuntingBlock(item) {
  if (!item || typeof item !== 'object') return '';
  const iocs   = item.iocs || [];
  const mitres = item.mitre_techniques || item.apex?.mitre_techniques || [];
  if (!iocs.length && !mitres.length && !(item.kev_present || item.kev) && !item.cve_id) return '';

  const hunt = _buildHuntObjectives(item);

  const objHtml = hunt.objectives.map(o =>
    `<li style="color:#e6edf3;font-size:11px;margin:5px 0;padding-left:4px;">${esc(o)}</li>`
  ).join("");

  const srcHtml = hunt.logSources.map(s =>
    `<li style="color:#8b949e;font-size:11px;margin:3px 0;">-> ${esc(s)}</li>`
  ).join("");

  const pivotHtml = hunt.pivots.map(p =>
    `<li style="color:#8b949e;font-size:11px;margin:3px 0;">? ${esc(p)}</li>`
  ).join("");

  const mitreHtml = hunt.mitres.slice(0, 6).map(t => {
    const tid = typeof t === 'string' ? t : (t.technique_id || t.id || "");
    const tname = typeof t === 'object' ? (t.technique_name || t.name || "") : "";
    return _badge(tid + (tname ? `  -  ${tname.substring(0, 30)}` : ""), "#a78bfa");
  }).join(" ");

  const body = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">
      <div>
        <div style="color:#00ffc6;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px;">Hunt Objectives</div>
        <ol style="margin:0;padding-left:16px;">${objHtml}</ol>
      </div>
      <div>
        <div style="color:#00ffc6;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px;">Required Log Sources</div>
        <ul style="margin:0;padding:0;list-style:none;">${srcHtml}</ul>
      </div>
    </div>
    ${hunt.pivots.length ? `
    <div style="margin-top:16px;padding-top:14px;border-top:1px solid #1a1f2e;">
      <div style="color:#00ffc6;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px;">Pivot Strategy</div>
      <ul style="margin:0;padding:0;list-style:none;">${pivotHtml}</ul>
    </div>` : ''}
    ${mitreHtml ? `
    <div style="margin-top:16px;padding-top:14px;border-top:1px solid #1a1f2e;">
      <div style="color:#00ffc6;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px;">ATT&amp;CK Technique Coverage</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;">${mitreHtml}</div>
    </div>` : ''}`;

  return _block("p23-hunting", "P23.3  -  Threat Hunting Package", "#00ffc6", body);
}

// -----------------------------------------------------------------------------
// P23.4  -  Incident Response Package
// -----------------------------------------------------------------------------

function _buildIRChecklist(item) {
  const severity = (item.severity || "").toUpperCase();
  const kev      = !!(item.kev_present || item.kev);
  const cve      = item.cve_id || (item.cve_ids || [])[0] || null;
  const iocs     = item.iocs || [];
  const ipIocs   = iocs.filter(i => i.type === "ip").length;
  const isCrit   = severity === "CRITICAL";

  const containment = [];
  if (kev) containment.push("EMERGENCY ACTION: Apply available patch or vendor-recommended workaround immediately  -  CISA KEV confirms active exploitation");
  containment.push("Isolate confirmed or suspected compromised systems from production network via VLAN, ACL, or physical disconnect");
  containment.push("Block all identified IOC indicators at perimeter  -  firewall rules, proxy blacklist, DNS sinkhole");
  containment.push("Revoke and rotate all potentially compromised credentials including service accounts, API keys, and privileged users");
  if (ipIocs > 0) containment.push(`Block ${ipIocs} IP indicator(s) at network egress  -  apply immediately to all perimeter devices`);
  containment.push("Suspend affected service accounts in Active Directory / IdP pending forensic review");
  containment.push("Activate incident response team and assign incident commander");

  const isolation = [
    "Network: Apply VLAN quarantine or zero-trust microsegmentation to affected segments",
    "Endpoint: Deploy EDR isolation policy to all confirmed compromised hosts",
    "Identity: Disable affected user accounts and revoke active SSO/OAuth sessions",
    "Cloud: Apply emergency NSG/Security Group rules to restrict lateral movement from affected instances",
    "Application: Place vulnerable service behind WAF emergency rule or take offline if exploitation is confirmed",
    "Email: Block sender domains and quarantine related messages across mailbox fleet",
  ];

  const recovery = [];
  if (cve) recovery.push(`Apply vendor patch for ${cve}  -  verify patch authenticity via checksum before deployment`);
  recovery.push("Rebuild compromised systems from verified clean baseline images  -  do not attempt in-place disinfection of rootkitted hosts");
  recovery.push("Restore data from pre-incident backups  -  verify backup integrity and chain of custody before restoration");
  recovery.push("Re-enable services with enhanced logging and monitoring active before returning to production");
  recovery.push("Deploy updated detection rules and IOC blocks in SIEM/EDR before service restoration");
  recovery.push("Run authenticated vulnerability scan post-patch to confirm remediation effectiveness");
  recovery.push("Conduct 24-hour enhanced monitoring period after restoration with on-call incident responder coverage");

  const evidence = [
    "Capture full disk images from compromised endpoints prior to remediation  -  preserve for legal/forensic chain of custody",
    "Export SIEM/SOC logs for authentication, network, and process execution  -  minimum 30-day window",
    "Preserve firewall and proxy logs with full source/destination IP and timestamp intact",
    "Export EDR telemetry: process trees, file activity, registry changes, network connections",
    "Record all PCAP network captures if available  -  focus on C2 beacon traffic and data exfiltration paths",
    "Document all forensic evidence with chain of custody forms before sharing with legal or insurance",
    "Screenshot all attacker-controlled infrastructure before takedown requests are initiated",
  ];

  const communication = [];
  if (isCrit || kev) {
    communication.push("Notify CISO, CTO, and CEO within 1 hour of confirmed compromise  -  provide factual incident briefing only");
    communication.push("Engage legal counsel immediately  -  assess breach notification obligations under GDPR, CCPA, state laws");
    communication.push("NIS2/DORA (EU): Submit initial incident notification to NCA within 24 hours if essential entity");
    communication.push("GDPR: File supervisory authority notification within 72 hours if personal data is compromised");
    communication.push("Prepare board-level summary for next scheduled board meeting or emergency session if material");
  } else {
    communication.push("Notify security leadership within 4 hours of confirmed impact");
    communication.push("Update incident tracking ticket with containment and investigation status every 2 hours");
    communication.push("Brief CISO once scope and impact are understood  -  provide written incident summary");
  }
  communication.push("Prepare customer/partner communication template  -  do not disclose details without legal review and executive sign-off");
  communication.push("Coordinate with cyber insurance carrier if policy triggers are met");

  const postIncident = [
    "Conduct blameless post-incident review within 5 business days",
    "Document root cause, contributing factors, and timeline",
    "Identify control gaps that enabled the incident to occur and escalate",
    "Update detection rules and playbooks based on observed attacker TTPs",
    "Review and update patch management SLAs based on incident timeline",
    "Test backup restoration procedures to confirm recovery time objectives are achievable",
  ];

  return { containment, isolation, recovery, evidence, communication, postIncident };
}

export function buildIRPackageBlock(item) {
  if (!item || typeof item !== 'object') return '';
  const cvss = parseFloat(item.cvss_score || item.cvss || 0);
  const kev  = !!(item.kev_present || item.kev);
  if (cvss < 4 && !kev && !(item.severity || "").match(/HIGH|CRITICAL/i)) return '';

  const ir = _buildIRChecklist(item);
  const severity = (item.severity || "UNKNOWN").toUpperCase();
  const urgencyColor = kev ? "#ef4444" : severity === "CRITICAL" ? "#ef4444" : severity === "HIGH" ? "#f97316" : "#eab308";

  function _checkList(items, color) {
    return `<ul style="margin:0;padding:0;list-style:none;">${items.map(i =>
      `<li style="color:#8b949e;font-size:11px;margin:4px 0;display:flex;gap:8px;">
        <span style="color:${color};flex-shrink:0;">?</span><span>${esc(i)}</span>
      </li>`).join("")}</ul>`;
  }

  const sections = [
    { title: "Containment", items: ir.containment, color: "#ef4444" },
    { title: "Isolation", items: ir.isolation, color: "#f97316" },
    { title: "Recovery", items: ir.recovery, color: "#00ffc6" },
    { title: "Evidence Preservation", items: ir.evidence, color: "#a78bfa" },
    { title: "Communication", items: ir.communication, color: "#3b82f6" },
    { title: "Post-Incident Actions", items: ir.postIncident, color: "#6b7280" },
  ];

  const body = `
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
      ${sections.map(s => `
        <div style="padding:12px;background:#0f1318;border-radius:4px;border-top:2px solid ${s.color};">
          <div style="color:${s.color};font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px;">${esc(s.title)}</div>
          ${_checkList(s.items, s.color)}
        </div>`).join("")}
    </div>`;

  return _block("p23-ir", "P23.4  -  Incident Response Package", urgencyColor, body);
}

// -----------------------------------------------------------------------------
// P23.8  -  Detection Coverage Analysis
// -----------------------------------------------------------------------------

function _computeDetectionCoverage(item) {
  const detections = item.detection_bundle || item.apex?.sigma_rules || item.apex?.detections || [];
  const mitres     = item.mitre_techniques || item.apex?.mitre_techniques || [];
  const iocs       = item.iocs || [];
  const iocTypes   = new Set(iocs.map(i => (i.type || "").toLowerCase()).filter(Boolean));

  const dims = [
    { name: "Network IOC Detection",    covered: iocTypes.has("ip") || iocTypes.has("domain") || iocTypes.has("url"),   missing: "Network-level IOC firewall/DNS detection rules" },
    { name: "Endpoint IOC Detection",   covered: iocTypes.has("hash") || iocTypes.has("md5") || iocTypes.has("sha256"), missing: "EDR file-hash and signature detection rules" },
    { name: "Behavioral Detection (Sigma)", covered: Array.isArray(detections) && detections.length > 0,               missing: "Sigma behavioral detection rules" },
    { name: "SIEM Query Coverage",      covered: Array.isArray(detections) && detections.some(d => d && (d.kql || d.spl || d.type === "kql" || d.type === "spl")), missing: "KQL/SPL SIEM detection queries" },
    { name: "MITRE ATT&CK Mapping",    covered: mitres.length > 0,                                                      missing: "MITRE technique-based detection coverage" },
    { name: "Threat Hunt Coverage",     covered: iocs.length > 0 && mitres.length > 0,                                  missing: "Structured threat hunting hypotheses with IOC pivots" },
    { name: "IOC Response Guidance",    covered: iocs.some(i => i.response_guidance || i.detection_guidance),           missing: "Per-IOC analyst response and detection guidance" },
  ];

  const covered = dims.filter(d => d.covered).length;
  const total   = dims.length;
  const pct     = Math.round((covered / total) * 100);

  let label, color;
  if (pct >= 80) { label = "STRONG";   color = "#00ffc6"; }
  else if (pct >= 60) { label = "ADEQUATE"; color = "#3b82f6"; }
  else if (pct >= 40) { label = "PARTIAL";  color = "#eab308"; }
  else               { label = "WEAK";    color = "#ef4444"; }

  return { dims, covered, total, pct, label, color };
}

export function buildDetectionCoverageBlock(item) {
  if (!item || typeof item !== 'object') return '';

  const cov = _computeDetectionCoverage(item);
  const blindSpots  = cov.dims.filter(d => !d.covered).map(d => d.missing);
  const coveredDims = cov.dims.filter(d => d.covered).map(d => d.name);

  const body = `
    <div style="display:flex;align-items:center;gap:20px;margin-bottom:16px;">
      <div style="text-align:center;min-width:80px;">
        <div style="font-size:28px;font-weight:700;color:${cov.color};">${cov.pct}%</div>
        <div style="color:${cov.color};font-size:10px;font-weight:700;">${esc(cov.label)}</div>
      </div>
      <div style="flex:1;">
        ${_bar(cov.pct, cov.color)}
        <div style="color:#8b949e;font-size:11px;margin-top:6px;">${cov.covered} of ${cov.total} detection dimensions covered</div>
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
      ${coveredDims.length ? `
      <div>
        <div style="color:#00ffc6;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px;">Covered</div>
        <ul style="margin:0;padding:0;list-style:none;">${coveredDims.map(n =>
          `<li style="color:#8b949e;font-size:11px;margin:3px 0;">[OK] ${esc(n)}</li>`).join("")}
        </ul>
      </div>` : ''}
      ${blindSpots.length ? `
      <div>
        <div style="color:#ef4444;font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px;">Blind Spots</div>
        <ul style="margin:0;padding:0;list-style:none;">${blindSpots.map(n =>
          `<li style="color:#8b949e;font-size:11px;margin:3px 0;">[FAIL] ${esc(n)}</li>`).join("")}
        </ul>
      </div>` : ''}
    </div>`;

  return _block("p23-coverage", "P23.8  -  Detection Coverage Analysis", cov.color, body);
}

// -----------------------------------------------------------------------------
// P23.11  -  Enterprise Actionability Score
// -----------------------------------------------------------------------------

export function computeActionabilityScore(item) {
  if (!item || typeof item !== 'object') return { total: 0, label: "N/A", color: "#4b5563", dims: [] };

  const { total: p20total } = computeP20QualityScore(item);
  const p21level = getP21CertificationLevel(item);
  const iocs      = item.iocs || [];
  const detects   = item.detection_bundle || item.apex?.sigma_rules || item.apex?.detections || [];
  const mitres    = item.mitre_techniques || item.apex?.mitre_techniques || [];
  const kev       = !!(item.kev_present || item.kev);
  const cvss      = parseFloat(item.cvss_score || item.cvss || 0);
  const epss      = parseFloat(item.epss_score || 0);
  const ec        = item.evidence_chain;
  const hasGuidance = iocs.some(i => i.response_guidance || i.detection_guidance);
  const hasNarrative = !!(item.apex?.ai_summary || item.description);

  // 9 dimensions  -  weights sum to 100
  const dims = [
    {
      name: "Evidence Quality",
      score: Math.round(Math.min(p20total, 100) * 0.12),
      max: 12,
      note: p20total >= 70 ? "Strong evidence chain with multiple sources" : "Limited evidence basis",
    },
    {
      name: "IOC Package Quality",
      score: iocs.length >= 5 ? 11 : iocs.length >= 3 ? 8 : iocs.length >= 1 ? 5 : 0,
      max: 11,
      note: `${iocs.length} indicator${iocs.length !== 1 ? 's' : ''}  -  ${hasGuidance ? 'with response guidance' : 'no response guidance'}`,
    },
    {
      name: "Detection Readiness",
      score: detects.length >= 3 ? 12 : detects.length >= 1 ? 7 : 0,
      max: 12,
      note: detects.length > 0 ? `${detects.length} detection rule${detects.length !== 1 ? 's' : ''} available` : "No detection rules  -  manual implementation required",
    },
    {
      name: "SOC Package Usefulness",
      score: hasGuidance && iocs.length > 0 ? 11 : iocs.length > 0 ? 6 : 2,
      max: 11,
      note: hasGuidance ? "IOC-level response and detection guidance available" : "Generic SOC guidance only",
    },
    {
      name: "Executive Package Usefulness",
      score: hasNarrative && cvss > 0 ? 11 : hasNarrative ? 7 : 3,
      max: 11,
      note: hasNarrative ? "Executive narrative with risk quantification" : "No executive narrative available",
    },
    {
      name: "Incident Response Readiness",
      score: kev ? 11 : cvss >= 7 ? 9 : cvss >= 4 ? 6 : 3,
      max: 11,
      note: kev ? "IR package critical  -  KEV-confirmed active exploitation" : cvss >= 7 ? "Full IR package applicable" : "Standard IR guidance applicable",
    },
    {
      name: "Compliance Intelligence",
      score: (kev || cvss >= 7) ? 11 : cvss >= 4 ? 8 : 5,
      max: 11,
      note: "Multi-framework regulatory mapping generated (NIST/PCI/DORA/NIS2/ISO/SOC2)",
    },
    {
      name: "Automation Readiness",
      score: iocs.length > 0 && detects.length > 0 ? 11 : iocs.length > 0 ? 7 : detects.length > 0 ? 5 : 2,
      max: 11,
      note: (iocs.length > 0 && detects.length > 0) ? "IOCs and detection rules enable automated SOAR playbook" : "Partial automation possible",
    },
    {
      name: "Deployment & Patch Readiness",
      score: (cvss > 0 || kev || epss > 0) ? 10 : 3,
      max: 10,
      note: kev ? "Immediate deployment required  -  risk score calibrated" : cvss > 0 ? "Risk-based deployment timeline generated" : "No deployment scoring data",
    },
  ];

  const total = dims.reduce((s, d) => s + d.score, 0);

  let label, color;
  if (total >= 85)      { label = "OPERATIONALLY EXCELLENT"; color = "#00ffc6"; }
  else if (total >= 70) { label = "ENTERPRISE READY";       color = "#3b82f6"; }
  else if (total >= 50) { label = "SOC READY";              color = "#eab308"; }
  else if (total >= 30) { label = "ANALYST REVIEW NEEDED";  color = "#f97316"; }
  else                  { label = "INSUFFICIENT INTEL";     color = "#ef4444"; }

  return { total, label, color, dims };
}

export function buildActionabilityScoreBlock(item) {
  if (!item || typeof item !== 'object') return '';

  const as = computeActionabilityScore(item);

  const dimRows = as.dims.map(d => `
    <div style="margin:6px 0;">
      <div style="display:flex;justify-content:space-between;margin-bottom:2px;">
        <span style="color:#8b949e;font-size:11px;">${esc(d.name)}</span>
        <span style="color:${as.color};font-size:11px;font-weight:600;">${d.score}/${d.max}</span>
      </div>
      ${_bar((d.score / d.max) * 100, d.score / d.max >= 0.7 ? "#00ffc6" : d.score / d.max >= 0.4 ? "#eab308" : "#ef4444")}
      <div style="color:#4b5563;font-size:10px;margin-top:1px;">${esc(d.note)}</div>
    </div>`).join("");

  const body = `
    <div style="display:flex;align-items:center;gap:24px;margin-bottom:20px;">
      <div style="text-align:center;min-width:90px;">
        <div style="font-size:32px;font-weight:700;color:${as.color};">${as.total}</div>
        <div style="color:#8b949e;font-size:10px;">out of 100</div>
      </div>
      <div style="flex:1;">
        ${_bar(as.total, as.color)}
        <div style="margin-top:8px;">${_badge(as.label, as.color)}</div>
        <div style="color:#8b949e;font-size:11px;margin-top:6px;">
          Composite score across 9 operational readiness dimensions.
          A score ?70 indicates the report is deployable in a production SOC environment.
        </div>
      </div>
    </div>
    <div>${dimRows}</div>`;

  return _block("p23-actionability", "P23.11  -  Enterprise Actionability Score", as.color, body);
}

// -----------------------------------------------------------------------------
// P23.10  -  Operational Readiness Gate
// -----------------------------------------------------------------------------

export function buildOperationalReadinessGateBlock(item) {
  if (!item || typeof item !== 'object') return '';

  const iocs     = item.iocs || [];
  const detects  = item.detection_bundle || item.apex?.sigma_rules || item.apex?.detections || [];
  const mitres   = item.mitre_techniques || item.apex?.mitre_techniques || [];
  const hasExec  = !!(item.apex?.ai_summary || item.description);
  const hasGuid  = iocs.some(i => i.response_guidance || i.detection_guidance);
  const ec       = item.evidence_chain;
  const p20score = computeP20QualityScore(item).total;
  const p21cert  = getP21CertificationLevel(item);
  const cvss     = parseFloat(item.cvss_score || 0);
  const kev      = !!(item.kev_present || item.kev);

  const gates = [
    { name: "Executive Package",       pass: hasExec,               desc: "AI narrative and executive summary available" },
    { name: "SOC Package",             pass: iocs.length > 0,       desc: `${iocs.length} IOC indicators available` },
    { name: "IOC Response Guidance",   pass: hasGuid,               desc: hasGuid ? "Per-IOC response and detection guidance" : "Missing  -  SOC deployment limited" },
    { name: "Detection Package",       pass: detects.length > 0,    desc: detects.length > 0 ? `${detects.length} detection rules available` : "Missing  -  manual detection required" },
    { name: "Threat Hunting Package",  pass: iocs.length > 0 && mitres.length > 0, desc: "IOCs and MITRE techniques available for hunting" },
    { name: "IR Package",             pass: cvss >= 4 || kev,       desc: kev ? "IR critical  -  KEV active exploitation" : cvss >= 4 ? "IR package applicable" : "Severity below IR threshold" },
    { name: "Compliance Mapping",      pass: true,                  desc: "Multi-framework compliance mapping generated" },
    { name: "Patch Priority",         pass: cvss > 0 || kev,        desc: cvss > 0 ? `CVSS ${cvss.toFixed(1)}  -  risk score available` : kev ? "KEV-confirmed  -  immediate action" : "No CVSS data available" },
    { name: "Evidence Chain",          pass: !!(ec && ec.source_reliability), desc: ec ? `Evidence from ${ec.source_name || 'verified source'}` : "No formal evidence chain" },
    { name: "P21 Certification",       pass: p21cert.level !== "BELOW_MINIMUM", desc: `${p21cert.level}  -  score ${p21cert.score}/100` },
  ];

  const passed  = gates.filter(g => g.pass).length;
  const total   = gates.length;
  const pct     = Math.round((passed / total) * 100);
  const allPass = passed === total;

  const gateColor = allPass ? "#00ffc6" : pct >= 70 ? "#3b82f6" : pct >= 50 ? "#eab308" : "#ef4444";
  const gateLabel = allPass ? "OPERATIONALLY CERTIFIED" : pct >= 70 ? "CONDITIONALLY DEPLOYABLE" : pct >= 50 ? "REVIEW REQUIRED" : "INCOMPLETE  -  DO NOT PUBLISH";

  const gateRows = gates.map(g => `
    <div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid #1a1f2e;">
      <span style="color:${g.pass ? '#00ffc6' : '#ef4444'};font-size:12px;flex-shrink:0;">${g.pass ? '[OK]' : '[FAIL]'}</span>
      <div style="flex:1;">
        <span style="color:${g.pass ? '#e6edf3' : '#8b949e'};font-size:11px;font-weight:600;">${esc(g.name)}</span>
        <span style="color:#4b5563;font-size:11px;margin-left:8px;">${esc(g.desc)}</span>
      </div>
    </div>`).join("");

  const body = `
    <div style="display:flex;align-items:center;gap:20px;margin-bottom:16px;">
      <div style="text-align:center;min-width:80px;">
        <div style="font-size:24px;font-weight:700;color:${gateColor};">${passed}/${total}</div>
        <div style="color:#8b949e;font-size:10px;">gates passed</div>
      </div>
      <div style="flex:1;">
        ${_bar(pct, gateColor)}
        <div style="margin-top:8px;">${_badge(gateLabel, gateColor)}</div>
      </div>
    </div>
    <div>${gateRows}</div>`;

  return _block("p23-readiness", "P23.10  -  Operational Readiness Gate", gateColor, body);
}

// -----------------------------------------------------------------------------
// API Handlers
// -----------------------------------------------------------------------------

export async function handleP23Actionability(request, env) {
  const url     = new URL(request.url);
  const stixId  = url.searchParams.get("id");
  const feedKey = "feed.json";

  let items = [];
  try {
    const obj = await env.INTEL_R2.get(feedKey);
    if (obj) {
      const raw  = await obj.text();
      const data = JSON.parse(raw);
      items = Array.isArray(data) ? data : (data.items || data.feed || data.data || []);
    }
  } catch (_) {}

  if (stixId) {
    const item = items.find(i => (i.stix_id || i.id) === stixId);
    if (!item) return new Response(JSON.stringify({ error: "Item not found" }), { status: 404, headers: { "Content-Type": "application/json" } });

    const as      = computeActionabilityScore(item);
    const patch   = _computePatchPriority(item);
    const cov     = _computeDetectionCoverage(item);
    const p21     = getP21CertificationLevel(item);

    return new Response(JSON.stringify({
      version: P23_VERSION,
      id: stixId,
      title: item.title,
      actionability: as,
      patch_priority: { priority: patch.priority, timeframe: patch.timeframe, score: patch.score, reasons: patch.reasons },
      detection_coverage: { pct: cov.pct, label: cov.label, blind_spots: cov.dims.filter(d => !d.covered).map(d => d.missing) },
      p21_certification: { level: p21.level, score: p21.score },
      generated_at: new Date().toISOString(),
    }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  }

  // Aggregate all items
  const results = items.slice(0, 100).map(item => {
    const as    = computeActionabilityScore(item);
    const patch = _computePatchPriority(item);
    return {
      id: item.stix_id || item.id,
      title: String(item.title || "").substring(0, 80),
      actionability_score: as.total,
      actionability_label: as.label,
      patch_priority: patch.priority,
      severity: item.severity,
      kev: !!(item.kev_present || item.kev),
    };
  });

  const avg   = results.length ? Math.round(results.reduce((s, r) => s + r.actionability_score, 0) / results.length) : 0;
  const excel = results.filter(r => r.actionability_score >= 85).length;
  const ready = results.filter(r => r.actionability_score >= 70).length;

  return new Response(JSON.stringify({
    version: P23_VERSION,
    generated_at: new Date().toISOString(),
    total_items: results.length,
    average_actionability: avg,
    operationally_excellent: excel,
    enterprise_ready: ready,
    immediate_patch_required: results.filter(r => r.patch_priority === "PATCH IMMEDIATELY").length,
    items: results,
  }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

export async function handleP23OperationalReadiness(request, env) {
  const url    = new URL(request.url);
  const stixId = url.searchParams.get("id");

  let items = [];
  try {
    const obj = await env.INTEL_R2.get("feed.json");
    if (obj) {
      const raw  = await obj.text();
      const data = JSON.parse(raw);
      items = Array.isArray(data) ? data : (data.items || data.feed || data.data || []);
    }
  } catch (_) {}

  if (stixId) {
    const item = items.find(i => (i.stix_id || i.id) === stixId);
    if (!item) return new Response(JSON.stringify({ error: "Item not found" }), { status: 404, headers: { "Content-Type": "application/json" } });

    const iocs    = item.iocs || [];
    const detects = item.detection_bundle || item.apex?.sigma_rules || [];
    const mitres  = item.mitre_techniques || item.apex?.mitre_techniques || [];
    const hasGuid = iocs.some(i => i.response_guidance || i.detection_guidance);
    const ec      = item.evidence_chain;
    const cvss    = parseFloat(item.cvss_score || 0);
    const kev     = !!(item.kev_present || item.kev);
    const p21     = getP21CertificationLevel(item);

    const gates = [
      { gate: "G1_EXECUTIVE",    pass: !!(item.apex?.ai_summary || item.description) },
      { gate: "G2_SOC",         pass: iocs.length > 0 },
      { gate: "G3_IOC_GUIDANCE", pass: hasGuid },
      { gate: "G4_DETECTION",   pass: detects.length > 0 },
      { gate: "G5_HUNTING",     pass: iocs.length > 0 && mitres.length > 0 },
      { gate: "G6_IR",          pass: cvss >= 4 || kev },
      { gate: "G7_COMPLIANCE",  pass: true },
      { gate: "G8_PATCH",       pass: cvss > 0 || kev },
      { gate: "G9_EVIDENCE",    pass: !!(ec && ec.source_reliability) },
      { gate: "G10_P21_CERT",   pass: p21.level !== "BELOW_MINIMUM" },
    ];

    const passed = gates.filter(g => g.pass).length;
    return new Response(JSON.stringify({
      version: P23_VERSION,
      id: stixId,
      gates,
      passed,
      total: gates.length,
      pct: Math.round((passed / gates.length) * 100),
      publish_eligible: passed >= 8,
      generated_at: new Date().toISOString(),
    }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  }

  // Aggregate
  const results = items.slice(0, 200).map(item => {
    const iocs    = item.iocs || [];
    const detects = item.detection_bundle || item.apex?.sigma_rules || [];
    const cvss    = parseFloat(item.cvss_score || 0);
    const kev     = !!(item.kev_present || item.kev);
    const gates   = [
      !!(item.apex?.ai_summary || item.description),
      iocs.length > 0,
      iocs.some(i => i.response_guidance || i.detection_guidance),
      detects.length > 0,
      iocs.length > 0 && (item.mitre_techniques || item.apex?.mitre_techniques || []).length > 0,
      cvss >= 4 || kev,
      true,
      cvss > 0 || kev,
      !!(item.evidence_chain?.source_reliability),
      getP21CertificationLevel(item).level !== "BELOW_MINIMUM",
    ];
    const passed = gates.filter(Boolean).length;
    return { id: item.stix_id || item.id, passed, total: 10, publish_eligible: passed >= 8 };
  });

  return new Response(JSON.stringify({
    version: P23_VERSION,
    generated_at: new Date().toISOString(),
    total_items: results.length,
    publish_eligible: results.filter(r => r.publish_eligible).length,
    blocked: results.filter(r => !r.publish_eligible).length,
    avg_gates_passed: results.length ? (results.reduce((s, r) => s + r.passed, 0) / results.length).toFixed(1) : 0,
    items: results,
  }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

export async function handleP23Observability(request, env) {
  let items = [];
  try {
    const obj = await env.INTEL_R2.get("feed.json");
    if (obj) {
      const data = JSON.parse(await obj.text());
      items = Array.isArray(data) ? data : (data.items || data.feed || data.data || []);
    }
  } catch (_) {}

  const actionScores = items.map(i => computeActionabilityScore(i).total);
  const avg          = actionScores.length ? Math.round(actionScores.reduce((a, b) => a + b, 0) / actionScores.length) : 0;

  const patchCounts = { "PATCH IMMEDIATELY": 0, "PATCH WITHIN 24 HOURS": 0, "PATCH WITHIN 7 DAYS": 0, "PATCH THIS MONTH": 0, "MONITOR": 0, "NO IMMEDIATE ACTION": 0 };
  const covSums = { total: 0, count: 0 };
  const actionDist = { OPERATIONALLY_EXCELLENT: 0, ENTERPRISE_READY: 0, SOC_READY: 0, ANALYST_REVIEW: 0, INSUFFICIENT: 0 };

  items.forEach(item => {
    const patch = _computePatchPriority(item);
    if (patchCounts[patch.priority] !== undefined) patchCounts[patch.priority]++;

    const cov = _computeDetectionCoverage(item);
    covSums.total += cov.pct; covSums.count++;

    const as = computeActionabilityScore(item);
    if (as.total >= 85)      actionDist.OPERATIONALLY_EXCELLENT++;
    else if (as.total >= 70) actionDist.ENTERPRISE_READY++;
    else if (as.total >= 50) actionDist.SOC_READY++;
    else if (as.total >= 30) actionDist.ANALYST_REVIEW++;
    else                     actionDist.INSUFFICIENT++;
  });

  return new Response(JSON.stringify({
    version: P23_VERSION,
    generated_at: new Date().toISOString(),
    total_items: items.length,
    average_actionability_score: avg,
    actionability_distribution: actionDist,
    patch_priority_distribution: patchCounts,
    average_detection_coverage_pct: covSums.count ? Math.round(covSums.total / covSums.count) : 0,
    immediate_action_required: patchCounts["PATCH IMMEDIATELY"],
  }, null, 2), { headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}
