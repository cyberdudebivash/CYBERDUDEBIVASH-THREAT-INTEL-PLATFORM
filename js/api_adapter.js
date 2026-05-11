/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — API ADAPTER v147.0.0
 *  Strict 1:1 API → UI field mapping layer — ENTERPRISE EDITION
 *  Author: CYBERDUDEBIVASH SENTINEL APEX Platform
 *  Pipeline Safety: READ-ONLY transform — never mutates source data
 *  Zero undefined values — every field has a typed safe fallback
 *
 *  NEW in v144:
 *   + generateActionRecommendation() — auto PATCH/MONITOR/ESCALATE/INVESTIGATE
 *   + buildImpactContext()           — attack type, target surface, potential impact
 *   + freshnessIndicator()           — LIVE / RECENT / STALE badge
 *   + buildAiVerdict()               — structured human-readable AI verdict string
 *   + buildPaywallFeatures()         — value-prop feature list for CTA
 * ═══════════════════════════════════════════════════════════════════════════════
 */

"use strict";

(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelApexAdapter = factory();
  }
})(typeof window !== "undefined" ? window : this, function () {

  /* ── SAFE ACCESSORS ────────────────────────────────────────────────────── */
  function _str(val, fallback)  { if (val === null || val === undefined || val === "") return fallback !== undefined ? String(fallback) : ""; return String(val); }
  function _num(val, fallback)  { const n = parseFloat(val); return isNaN(n) ? (fallback !== undefined ? Number(fallback) : 0) : n; }
  function _int(val, fallback)  { const n = parseInt(val, 10); return isNaN(n) ? (fallback !== undefined ? parseInt(fallback, 10) : 0) : n; }
  function _bool(val, fallback) { if (val === null || val === undefined) return fallback !== undefined ? Boolean(fallback) : false; return Boolean(val); }
  function _arr(val)  { if (!val || !Array.isArray(val)) return []; return val; }
  function _obj(val)  { if (!val || typeof val !== "object" || Array.isArray(val)) return {}; return val; }
  function _nullableNum(val) { if (val === null || val === undefined) return null; const n = parseFloat(val); return isNaN(n) ? null : n; }

  /* ── SEVERITY SYSTEM ───────────────────────────────────────────────────── */
  const SEVERITY_MAP = { CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW", INFO: "INFO" };

  function normalizeSeverity(raw) {
    if (!raw) return "LOW";
    const upper = String(raw).toUpperCase().trim();
    return SEVERITY_MAP[upper] || "LOW";
  }

  const SEVERITY_COLORS = {
    CRITICAL: { primary: "#ff1a1a", glow: "rgba(255,26,26,0.55)",   dim: "rgba(220,38,38,0.14)",   border: "rgba(220,38,38,0.45)",  text: "#ff6b6b", class: "sev-critical", label: "CRITICAL" },
    HIGH:     { primary: "#ff6600", glow: "rgba(255,102,0,0.48)",   dim: "rgba(234,88,12,0.11)",   border: "rgba(234,88,12,0.38)",  text: "#fb923c", class: "sev-high",     label: "HIGH"     },
    MEDIUM:   { primary: "#f59e0b", glow: "rgba(245,158,11,0.38)",  dim: "rgba(217,119,6,0.09)",   border: "rgba(217,119,6,0.32)",  text: "#fbbf24", class: "sev-medium",   label: "MEDIUM"   },
    LOW:      { primary: "#00d4ff", glow: "rgba(0,212,255,0.28)",   dim: "rgba(0,212,255,0.07)",   border: "rgba(0,212,255,0.22)",  text: "#38bdf8", class: "sev-low",      label: "LOW"      },
    INFO:     { primary: "#6b7280", glow: "rgba(107,114,128,0.22)", dim: "rgba(107,114,128,0.06)", border: "rgba(107,114,128,0.2)", text: "#9ca3af", class: "sev-info",     label: "INFO"     },
  };

  function getSeverityColors(sev) { return SEVERITY_COLORS[normalizeSeverity(sev)] || SEVERITY_COLORS["LOW"]; }

  /* ── SOC PRIORITY SYSTEM ───────────────────────────────────────────────── */
  function normalizeSocPriority(raw) {
    if (!raw) return "P4";
    const upper = String(raw).toUpperCase().trim();
    if (["P1","P2","P3","P4"].includes(upper)) return upper;
    return "P4";
  }

  const SOC_PRIORITY_MAP = {
    P1: { label: "P1 — CRITICAL RESPONSE", shortLabel: "CRITICAL RESPONSE", color: "#ff1a1a", bg: "rgba(220,38,38,0.16)", border: "rgba(220,38,38,0.45)", badge: "🔴", order: 0 },
    P2: { label: "P2 — URGENT RESPONSE",   shortLabel: "URGENT RESPONSE",   color: "#ff6600", bg: "rgba(234,88,12,0.13)", border: "rgba(234,88,12,0.32)", badge: "🟠", order: 1 },
    P3: { label: "P3 — ACTIVE MONITORING", shortLabel: "ACTIVE MONITORING", color: "#f59e0b", bg: "rgba(217,119,6,0.11)", border: "rgba(217,119,6,0.28)", badge: "🟡", order: 2 },
    P4: { label: "P4 — INFORMATIONAL",     shortLabel: "INFORMATIONAL",     color: "#00d4ff", bg: "rgba(0,212,255,0.08)", border: "rgba(0,212,255,0.20)", badge: "🔵", order: 3 },
  };

  function getSocPriorityMeta(priority) { return SOC_PRIORITY_MAP[normalizeSocPriority(priority)] || SOC_PRIORITY_MAP["P4"]; }

  /* ── ACTION RECOMMENDATION ENGINE ─────────────────────────────────────── */
  const ACTION_DEFS = {
    PATCH:       { label: "PATCH IMMEDIATELY",      icon: "🛡",  color: "#ff1a1a", bg: "rgba(220,38,38,0.16)", border: "rgba(220,38,38,0.4)", urgency: "CRITICAL" },
    ESCALATE:    { label: "ESCALATE TO IR TEAM",    icon: "🚨",  color: "#ff6600", bg: "rgba(234,88,12,0.13)", border: "rgba(234,88,12,0.35)", urgency: "HIGH" },
    INVESTIGATE: { label: "INVESTIGATE EXPOSURE",   icon: "🔍",  color: "#f59e0b", bg: "rgba(217,119,6,0.11)", border: "rgba(217,119,6,0.3)", urgency: "MEDIUM" },
    MONITOR:     { label: "MONITOR & LOG",           icon: "👁",  color: "#00d4ff", bg: "rgba(0,212,255,0.08)", border: "rgba(0,212,255,0.22)", urgency: "LOW" },
  };

  function generateActionRecommendation(severity, socPriority, epss, cvss, kevPresent) {
    const sev = normalizeSeverity(severity);
    const soc = normalizeSocPriority(socPriority);
    const epssVal = epss ? _num(epss.raw, 0) : 0;
    const cvssVal = cvss ? _num(cvss.raw, 0) : 0;

    // PATCH: KEV confirmed, or near-certain exploit, or critical CVSS
    if (kevPresent || epssVal >= 15 || cvssVal >= 9.5) {
      return { action: "PATCH", ...ACTION_DEFS.PATCH };
    }
    // ESCALATE: P1 response or critical severity with high EPSS
    if (soc === "P1" || (sev === "CRITICAL" && epssVal >= 5)) {
      return { action: "ESCALATE", ...ACTION_DEFS.ESCALATE };
    }
    // INVESTIGATE: P2 / HIGH severity / notable EPSS
    if (soc === "P2" || sev === "HIGH" || (sev === "CRITICAL") || epssVal >= 1 || cvssVal >= 7) {
      return { action: "INVESTIGATE", ...ACTION_DEFS.INVESTIGATE };
    }
    // MONITOR: default
    return { action: "MONITOR", ...ACTION_DEFS.MONITOR };
  }

  /* ── BUSINESS IMPACT ENGINE ────────────────────────────────────────────── */
  /* Maps threat category + severity → quantified business risk fields.       */
  const BUSINESS_IMPACT_MAP = {
    "Remote Code Execution": {
      CRITICAL: { financial: "$2M–$15M breach cost exposure", operational: "Complete service disruption possible within hours of exploitation", compliance: "GDPR Art. 33 72-hr notification likely; PCI-DSS incident response mandatory", customer: "Customer data at imminent risk; breach notification obligations triggered", infrastructure: "Full infrastructure takeover pathway — pivoting to cloud, backups, DR systems" },
      HIGH:     { financial: "$500K–$5M breach cost exposure", operational: "Significant service degradation; lateral movement across production environment", compliance: "GDPR/PCI-DSS reporting thresholds likely exceeded on successful exploitation", customer: "Possible customer data exposure; privilege escalation to sensitive stores", infrastructure: "Affected systems require emergency isolation; patch deployment critical" },
      MEDIUM:   { financial: "$50K–$500K breach cost exposure", operational: "Localized service impact; contained with patch deployment", compliance: "Compliance review recommended; document risk acceptance if not patching", customer: "Limited customer impact; monitor for signs of active exploitation", infrastructure: "Patch within standard change window; increase monitoring coverage" },
      LOW:      { financial: "$5K–$50K estimated risk exposure", operational: "Minimal operational disruption expected", compliance: "Standard vulnerability disclosure compliance maintained", customer: "Low customer impact; informational tracking recommended", infrastructure: "Schedule patch in next maintenance cycle" },
    },
    "Supply Chain Attack": {
      CRITICAL: { financial: "$5M–$50M exposure across customer base", operational: "Trusted software delivery chain poisoned — mass compromise of downstream systems", compliance: "SEC cybersecurity disclosure rules triggered; GDPR breach notifications required", customer: "All customers consuming affected packages potentially compromised", infrastructure: "Entire build pipeline must be treated as compromised and rebuilt" },
      HIGH:     { financial: "$1M–$10M exposure estimate", operational: "Software distribution integrity compromised; rollback and verification required", compliance: "Supply chain security attestation failures — SOC 2 impact likely", customer: "Customer systems at risk via trusted update channel", infrastructure: "Audit all pipeline components; verify checksums and signing chains" },
      MEDIUM:   { financial: "$100K–$1M exposure estimate", operational: "Targeted dependency compromise; scope assessment required", compliance: "SBOM review and attestation update recommended", customer: "Downstream customer risk pending exploitation confirmation", infrastructure: "Dependency audit and version pinning required" },
      LOW:      { financial: "Under $100K estimated exposure", operational: "Low-confidence supply chain indicator; monitoring recommended", compliance: "Proactive SBOM documentation recommended", customer: "No confirmed customer impact at this time", infrastructure: "Review dependency manifests for suspicious entries" },
    },
    "Ransomware": {
      CRITICAL: { financial: "$10M–$100M+ total incident cost (ransom + recovery + downtime)", operational: "Business operations halted; recovery timeline 2–8 weeks", compliance: "Data Protection Authority notification required; potential HIPAA/PCI breach", customer: "Customer data encrypted or exfiltrated; trust and continuity at risk", infrastructure: "Backup systems compromised; bare-metal recovery may be required" },
      HIGH:     { financial: "$1M–$10M total incident cost estimate", operational: "Significant operational disruption; critical systems at risk of encryption", compliance: "Incident response plan activation required; regulatory notification thresholds likely met", customer: "Customer data at elevated risk; proactive communication recommended", infrastructure: "Network segmentation and backup verification critical pre-incident" },
      MEDIUM:   { financial: "$100K–$2M estimated impact", operational: "Ransomware precursor activity detected; preparation window still open", compliance: "Document detection and containment actions for regulatory compliance", customer: "Customer data risk contingent on lateral movement success", infrastructure: "EDR tuning and network segmentation recommended immediately" },
      LOW:      { financial: "Under $500K if contained early", operational: "Low-level ransomware indicator; standard security hygiene response", compliance: "Document and monitor; no immediate regulatory action required", customer: "No immediate customer impact", infrastructure: "Scan endpoints; verify backup integrity" },
    },
    "Phishing": {
      CRITICAL: { financial: "$500K–$5M from credential compromise and BEC fraud", operational: "Executive credentials or privileged access tokens compromised", compliance: "MFA bypass + credential theft may trigger SOC 2 audit findings", customer: "Customer impersonation or invoice fraud risk if accounts compromised", infrastructure: "Assume privileged account compromise; initiate credential rotation" },
      HIGH:     { financial: "$100K–$1M exposure from BEC and account takeover", operational: "Multiple user accounts at risk; lateral movement via compromised sessions", compliance: "Account security controls review required; MFA enforcement mandated", customer: "Customer-facing accounts at risk; session invalidation recommended", infrastructure: "Email gateway rule tightening and MFA enforcement required" },
      MEDIUM:   { financial: "$10K–$100K estimated phishing campaign exposure", operational: "Targeted credential harvesting; limited to non-privileged accounts likely", compliance: "Phishing simulation and awareness training documentation recommended", customer: "Low direct customer risk; monitor for account abuse", infrastructure: "Email filtering update and user awareness communication recommended" },
      LOW:      { financial: "Under $10K estimated exposure", operational: "Low-sophistication phishing attempt; standard response", compliance: "Routine phishing incident; document and close", customer: "No direct customer risk identified", infrastructure: "Report to email security vendor; update blocklists" },
    },
    "Vulnerability": {
      CRITICAL: { financial: "$1M–$20M breach cost exposure on exploitation", operational: "Critical vulnerability with active exploitation pathway; emergency patching required", compliance: "CISA KEV listing may require 2-week patch deadline for federal entities; PCI-DSS evidence", customer: "All customers on affected version at direct risk", infrastructure: "Emergency patch deployment required; consider temporary mitigation/WAF rule" },
      HIGH:     { financial: "$200K–$2M risk exposure", operational: "High-severity vulnerability requiring priority patching within SLA window", compliance: "Vulnerability management policy compliance; document risk acceptance timeline", customer: "Customers on unpatched versions at elevated risk", infrastructure: "Patch within 30-day vulnerability SLA; compensating controls in place" },
      MEDIUM:   { financial: "$20K–$200K estimated risk exposure", operational: "Moderate vulnerability; patch within standard change schedule", compliance: "Standard vulnerability management process applies", customer: "Limited direct customer risk at current exploitation probability", infrastructure: "Patch in next scheduled maintenance window" },
      LOW:      { financial: "Under $20K estimated risk", operational: "Low-severity vulnerability; informational tracking", compliance: "Maintain vulnerability registry entry; no immediate action required", customer: "No direct customer impact expected", infrastructure: "Schedule patch at next opportunity" },
    },
    "Malware": {
      CRITICAL: { financial: "$2M–$30M from data destruction, exfiltration, and recovery", operational: "Active malware with C2 connectivity; full incident response activation", compliance: "Breach notification obligations likely; forensic evidence preservation required", customer: "Customer data at risk if malware reached data stores", infrastructure: "Infected systems must be isolated immediately; forensic imaging required" },
      HIGH:     { financial: "$500K–$5M estimated malware incident cost", operational: "High-sophistication malware with persistence; lateral movement risk", compliance: "Incident response documentation required; consider GDPR data breach assessment", customer: "Potential customer data access if malware persists on production systems", infrastructure: "EDR-assisted hunting across estate; network traffic analysis for C2 beacons" },
      MEDIUM:   { financial: "$50K–$500K estimated cost", operational: "Moderate malware activity; containment likely achievable with EDR response", compliance: "Document detection and response timeline for audit trail", customer: "Limited customer impact if contained to non-data systems", infrastructure: "EDR quarantine and full scan; review network connections from affected host" },
      LOW:      { financial: "Under $50K estimated exposure", operational: "Low-confidence malware indicator; monitoring and scanning recommended", compliance: "Routine security incident documentation", customer: "No direct customer impact expected", infrastructure: "Scan affected systems; verify AV signatures are current" },
    },
    "default": {
      CRITICAL: { financial: "$1M+ estimated breach cost", operational: "Critical threat with immediate business impact potential", compliance: "Activate incident response plan; assess regulatory notification obligations", customer: "Customer data and service continuity at elevated risk", infrastructure: "Emergency response team activation recommended" },
      HIGH:     { financial: "$100K–$2M estimated exposure", operational: "Significant threat requiring urgent response", compliance: "Review compliance posture; document response actions", customer: "Customers potentially impacted pending scope determination", infrastructure: "Priority response and enhanced monitoring required" },
      MEDIUM:   { financial: "$10K–$200K estimated exposure", operational: "Moderate threat; standard response procedures apply", compliance: "Document incident in security registry", customer: "Limited customer impact at current stage", infrastructure: "Enhanced monitoring and patch review recommended" },
      LOW:      { financial: "Under $10K estimated exposure", operational: "Low-level threat; informational tracking", compliance: "Routine security documentation", customer: "No direct customer impact", infrastructure: "Monitor and maintain standard vigilance" },
    },
  };

  function buildBusinessImpact(threatCategory, threatType, severity) {
    const sev   = normalizeSeverity(severity);
    const type  = _str(threatType, threatCategory);
    const cat   = _str(threatCategory, "default");

    // Try exact type, then category, then default
    const map   = BUSINESS_IMPACT_MAP[type]
               || BUSINESS_IMPACT_MAP[cat]
               || BUSINESS_IMPACT_MAP["default"];

    const sevImpact = map[sev] || map["MEDIUM"] || map["LOW"];
    return {
      financial_risk:       sevImpact.financial      || "Exposure under assessment",
      operational_impact:   sevImpact.operational    || "Impact under investigation",
      compliance_exposure:  sevImpact.compliance     || "Review compliance posture",
      customer_impact:      sevImpact.customer       || "Customer impact being assessed",
      infrastructure_risk:  sevImpact.infrastructure || "Infrastructure risk being evaluated",
      severity:             sev,
    };
  }

  /* ── IMPACT & CONTEXT BUILDER ──────────────────────────────────────────── */
  const ATTACK_TYPE_META = {
    "Remote Code Execution": { icon: "💻", impact: "Full system compromise possible. Attacker gains remote shell/execution capabilities.", surface: "Internet-facing services, web applications, APIs" },
    "Supply Chain Attack":   { icon: "📦", impact: "Trusted software delivery compromised. Widespread infection via legitimate update channels.", surface: "Software build systems, package managers, CI/CD pipelines" },
    "Zero Day Exploit":      { icon: "⚡", impact: "No patch available. Active exploitation before vendor awareness. Immediate exposure risk.", surface: "All systems running affected software version" },
    "Phishing":              { icon: "🎣", impact: "Credential theft and initial access vector. Enables lateral movement.", surface: "Email gateways, users, authentication systems" },
    "Ransomware":            { icon: "🔐", impact: "Data encryption and extortion. Business disruption and data loss.", surface: "Endpoints, file servers, backup systems" },
    "Data Exfiltration":     { icon: "📤", impact: "Sensitive data theft. Regulatory and reputational consequences.", surface: "Databases, cloud storage, email archives" },
    "Malware":               { icon: "🦠", impact: "Persistent backdoor or destructive payload on infected systems.", surface: "Endpoints, email attachments, web downloads" },
    "Vulnerability":         { icon: "🔓", impact: "Security control bypass enabling unauthorized access or code execution.", surface: "Applications and services matching affected version" },
    "Threat Intelligence":   { icon: "🕵", impact: "Threat actor activity tracked. Monitoring and detection recommended.", surface: "Network perimeter, detection systems" },
    "default":               { icon: "⚠",  impact: "Threat actor activity with potential for system compromise.", surface: "Network perimeter and exposed assets" },
  };

  function buildImpactContext(threatCategory, threatType, severity) {
    const cat   = _str(threatCategory, "Threat Intelligence");
    const type  = _str(threatType, cat);
    const meta  = ATTACK_TYPE_META[type] || ATTACK_TYPE_META[cat] || ATTACK_TYPE_META["default"];
    const sev   = normalizeSeverity(severity);

    const severityImpactPrefix = {
      CRITICAL: "⚠ CRITICAL: ",
      HIGH:     "⚠ HIGH: ",
      MEDIUM:   "⚡ MODERATE: ",
      LOW:      "ℹ LOW: ",
      INFO:     "ℹ INFO: ",
    };

    return {
      attack_type:      type,
      attack_icon:      meta.icon,
      potential_impact: (severityImpactPrefix[sev] || "") + meta.impact,
      target_surface:   meta.surface,
      display_category: cat !== type ? cat : type,
    };
  }

  /* ── FRESHNESS INDICATOR ───────────────────────────────────────────────── */
  function freshnessIndicator(publishedAt) {
    if (!publishedAt) return { label: "UNKNOWN", class: "freshness-unknown", color: "#6b7280", icon: "⏸" };
    try {
      const d = new Date(publishedAt);
      if (isNaN(d.getTime())) return { label: "UNKNOWN", class: "freshness-unknown", color: "#6b7280", icon: "⏸" };
      const ageHrs = (Date.now() - d.getTime()) / 3600000;
      if (ageHrs <= 6)  return { label: "LIVE",   class: "freshness-live",   color: "#22c55e", icon: "🟢", ageHrs };
      if (ageHrs <= 24) return { label: "RECENT", class: "freshness-recent", color: "#f59e0b", icon: "🟡", ageHrs };
      if (ageHrs <= 72) return { label: "AGING",  class: "freshness-aging",  color: "#ef4444", icon: "🟠", ageHrs };
      return                     { label: "STALE", class: "freshness-stale",  color: "#64748b", icon: "⚫", ageHrs };
    } catch (e) {
      return { label: "UNKNOWN", class: "freshness-unknown", color: "#6b7280", icon: "⏸" };
    }
  }

  /* ── AI VERDICT BUILDER (v145 — Analyst-Grade Prose) ──────────────────── */
  /* Produces Recorded Future / GreyNoise quality human-readable verdicts.    */
  const VERDICT_NARRATIVE = {
    "Remote Code Execution": {
      CRITICAL: "This advisory presents a critical-severity remote code execution pathway with confirmed exploitation indicators. The attack surface includes internet-facing services and web APIs. Adversary access at this tier typically enables full system compromise within hours of initial foothold.",
      HIGH:     "A high-severity remote code execution vulnerability has been identified with credible exploitation signals. Successful exploitation grants an attacker arbitrary code execution and likely privilege escalation on affected hosts.",
      MEDIUM:   "This vulnerability presents a moderate exploitation pathway for remote code execution. Current exploitation probability is limited by prerequisite conditions, though proof-of-concept code is publicly accessible for most vulnerabilities of this class.",
      LOW:      "A low-severity code execution pathway has been identified. Active exploitation is unlikely without additional prerequisites; however, monitoring for exploitation attempts is recommended.",
    },
    "Ransomware": {
      CRITICAL: "Active ransomware deployment with confirmed double-extortion indicators. This campaign demonstrates sophisticated pre-positioning, lateral movement capability, and shadow copy deletion — the hallmarks of an operationally mature threat group. Recovery complexity is high.",
      HIGH:     "High-confidence ransomware activity with network propagation capabilities detected. Threat actor TTPs align with established ransomware-as-a-service (RaaS) operational patterns. Backup systems and domain controllers are likely primary targets.",
      MEDIUM:   "Moderate-confidence ransomware precursor activity. Observed TTPs suggest reconnaissance and staging phase; full ransomware deployment is contingent on successful lateral movement.",
      LOW:      "Low-confidence ransomware indicator. Current evidence insufficient to confirm active deployment; defensive posture review and backup integrity verification recommended.",
    },
    "Supply Chain Attack": {
      CRITICAL: "Critical-severity supply chain compromise with confirmed downstream infection vectors. Trusted build infrastructure or software distribution channels are affected. All systems consuming affected packages must be treated as potentially compromised.",
      HIGH:     "High-confidence supply chain attack targeting software distribution or build infrastructure. The adversary leverage legitimate trust relationships to achieve widespread initial access without triggering standard detection controls.",
      MEDIUM:   "Moderate-severity supply chain compromise indicator. Scope assessment is ongoing; affected package versions should be audited and pinned pending vendor remediation confirmation.",
      LOW:      "Low-confidence supply chain anomaly. Preliminary indicators suggest potential dependency tampering; SBOM review and hash verification recommended.",
    },
    "Phishing": {
      CRITICAL: "Highly targeted credential harvesting campaign with spear-phishing indicators. The adversary demonstrates organizational knowledge suggesting prior reconnaissance. BEC or executive account compromise is the likely objective.",
      HIGH:     "High-volume phishing campaign with active credential theft infrastructure. Multiple authentication bypass techniques observed; MFA fatigue attacks are a probable secondary vector.",
      MEDIUM:   "Moderate-confidence phishing activity targeting organizational credentials. Campaign infrastructure indicates an organized threat actor with defined objectives beyond opportunistic credential harvesting.",
      LOW:      "Low-sophistication phishing attempt consistent with commodity credential harvesting operations. Standard email security controls are likely to contain the threat.",
    },
    "Malware": {
      CRITICAL: "Active malware deployment with C2 infrastructure connectivity confirmed. The malware demonstrates advanced evasion capability, persistence mechanisms, and potential data exfiltration functionality. Immediate containment is required.",
      HIGH:     "High-confidence malware detection with persistence and lateral movement capabilities. The threat exhibits characteristics consistent with an advanced persistent threat (APT) toolset rather than commodity malware.",
      MEDIUM:   "Moderate-confidence malware indicator with limited lateral movement observed. The malware exhibits post-exploitation behavior suggesting targeted deployment rather than indiscriminate infection.",
      LOW:      "Low-severity malware detection. Current behavioral profile is consistent with limited-capability commodity malware; standard endpoint response procedures are applicable.",
    },
    "Vulnerability": {
      CRITICAL: "Critical vulnerability with confirmed or near-confirmed active exploitation in the wild. Patch availability and exploitation timeline place this in the highest operational priority category for any affected organization. Treat as zero-day until patches are universally deployed.",
      HIGH:     "High-severity vulnerability with a credible exploitation pathway. Proof-of-concept code is publicly available or likely to emerge within days. Exploitation requires minimal prerequisite conditions on affected systems.",
      MEDIUM:   "Moderate-severity vulnerability requiring patch prioritization within standard SLA windows. Current exploitation probability is limited by prerequisite conditions or low attacker interest, but this status may change rapidly.",
      LOW:      "Low-severity vulnerability with limited exploitation potential under normal circumstances. Patch as part of routine maintenance; compensating controls are sufficient in the interim.",
    },
    "APT": {
      CRITICAL: "Nation-state threat actor activity with advanced persistent access confirmed. This campaign demonstrates the hallmarks of a long-term intelligence-collection or sabotage operation: living-off-the-land binaries, custom implants, and zero-day capability.",
      HIGH:     "High-confidence APT activity with targeting consistent with nation-state intelligence objectives. The threat actor demonstrates operational security discipline and custom tooling indicative of a well-resourced adversary.",
      MEDIUM:   "Moderate-confidence APT-attributed activity. TTPs align with documented nation-state threat groups; attribution confidence is bounded by limited direct indicators.",
      LOW:      "Low-confidence APT indicator. Behavioral signals are ambiguous; monitoring and additional collection recommended before definitive attribution.",
    },
    "default": {
      CRITICAL: "Critical-severity threat intelligence confirmed. The threat demonstrates high operational maturity and poses an immediate risk to organizational security posture. Immediate escalation to the security operations team is required.",
      HIGH:     "High-severity threat with credible impact potential. The adversary demonstrates both capability and intent consistent with targeted attack operations. Priority response is warranted.",
      MEDIUM:   "Moderate-severity threat advisory. Current evidence suggests limited impact potential, though the threat landscape can shift rapidly as additional exploitation techniques emerge.",
      LOW:      "Low-severity informational advisory. This indicator is being tracked as part of the broader threat landscape; no immediate action is required beyond standard monitoring.",
    },
  };

  function buildAiVerdict(aiSummary, severity, socPriority, threatCategory, aiConfidence) {
    const sev  = normalizeSeverity(severity);
    const soc  = normalizeSocPriority(socPriority);
    const cat  = _str(threatCategory, "default");
    const type = _str(threatCategory, "default");
    const conf = _int(aiConfidence, 0);

    // Pick the analyst narrative for this category+severity
    const narrativeMap = VERDICT_NARRATIVE[type] || VERDICT_NARRATIVE["default"];
    const narrative    = narrativeMap[sev]        || narrativeMap["MEDIUM"] || narrativeMap["LOW"];

    // Action recommendation suffix keyed to SOC priority
    const socSuffix = {
      P1: "Immediate incident response activation required. Escalate to CISO. Implement emergency mitigations now.",
      P2: "Urgent investigation required within 4 hours. Assign incident owner. Implement compensating controls pending patch.",
      P3: "Active monitoring and detection tuning advised. Schedule patch within 30-day SLA. Review exposure in affected systems.",
      P4: "Log, monitor, and track. No immediate action required. Include in next vulnerability management cycle.",
    };
    const actionSuffix = socSuffix[soc] || socSuffix["P4"];

    // Confidence context
    const confContext = conf >= 80 ? "High-confidence intelligence basis."
                      : conf >= 50 ? "Moderate-confidence intelligence basis — further validation advised."
                      : "Limited intelligence signals — treat as early-warning indicator.";

    return `${narrative} ${confContext} ${actionSuffix}`;
  }

  /* ── PAYWALL FEATURE LIST ──────────────────────────────────────────────── */
  function buildPaywallFeatures(iocCount, ttpCount) {
    const iocText = iocCount > 0 ? `Complete IOC list (${iocCount} indicators)` : "Full IOC dataset";
    return [
      { icon: "✔", text: iocText },
      { icon: "✔", text: "Kill chain analysis & actor attribution" },
      { icon: "✔", text: "Detection rules (Sigma, YARA, Snort)" },
      { icon: "✔", text: "SOC playbook & response procedures" },
      { icon: "✔", text: ttpCount > 0 ? `Full TTP mapping (${ttpCount} techniques)` : "MITRE ATT&CK coverage map" },
      { icon: "✔", text: "Threat actor fingerprint & campaign intel" },
    ];
  }

  /* ── TIMESTAMP FORMATTERS ──────────────────────────────────────────────── */
  function formatTimestamp(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "—";
      return d.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    } catch (e) { return "—"; }
  }

  function relativeTime(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "—";
      const diffMins = Math.floor((Date.now() - d.getTime()) / 60000);
      if (diffMins < 1)  return "just now";
      if (diffMins < 60) return diffMins + "m ago";
      const diffHrs = Math.floor(diffMins / 60);
      if (diffHrs < 24)  return diffHrs + "h ago";
      return Math.floor(diffHrs / 24) + "d ago";
    } catch (e) { return "—"; }
  }

  /* ── CONFIDENCE TIER NORMALIZER ────────────────────────────────────────── */
  const CONFIDENCE_TIERS = {
    LOW:      { label: "◇ LOW",      color: "#64748b", glow: "rgba(100,116,139,0.3)" },
    MODERATE: { label: "◆ MODERATE", color: "#f59e0b", glow: "rgba(245,158,11,0.3)" },
    HIGH:     { label: "▲ HIGH",     color: "#ef4444", glow: "rgba(239,68,68,0.35)"  },
    CRITICAL: { label: "⬛ CRITICAL", color: "#dc2626", glow: "rgba(220,38,38,0.4)"  },
  };

  function normalizeConfidence(val) {
    const n = _num(val, 0);
    if (n >= 90) return { tier: "CRITICAL", label: CONFIDENCE_TIERS.CRITICAL.label, color: CONFIDENCE_TIERS.CRITICAL.color, glow: CONFIDENCE_TIERS.CRITICAL.glow };
    if (n >= 70) return { tier: "HIGH",     label: CONFIDENCE_TIERS.HIGH.label,     color: CONFIDENCE_TIERS.HIGH.color,     glow: CONFIDENCE_TIERS.HIGH.glow     };
    if (n >= 40) return { tier: "MODERATE", label: CONFIDENCE_TIERS.MODERATE.label, color: CONFIDENCE_TIERS.MODERATE.color, glow: CONFIDENCE_TIERS.MODERATE.glow };
    return               { tier: "LOW",     label: CONFIDENCE_TIERS.LOW.label,      color: CONFIDENCE_TIERS.LOW.color,      glow: CONFIDENCE_TIERS.LOW.glow      };
  }

  /* ── EPSS / CVSS HELPERS ───────────────────────────────────────────────── */
  function buildEpssScore(raw) {
    if (raw === null || raw === undefined) return null;
    const n = parseFloat(raw);
    if (isNaN(n)) return null;
    const pct = n * 100;
    let risk = "LOW";
    if (pct >= 10) risk = "CRITICAL";
    else if (pct >= 1) risk = "HIGH";
    else if (pct >= 0.1) risk = "MODERATE";
    return { raw: n, display: pct.toFixed(2) + "%", risk: risk + " EXPLOITATION PROBABILITY",
             color: pct >= 10 ? "#ff1a1a" : pct >= 1 ? "#ff6600" : pct >= 0.1 ? "#f59e0b" : "#00d4ff" };
  }

  function buildCvssScore(raw) {
    if (raw === null || raw === undefined) return null;
    const n = parseFloat(raw);
    if (isNaN(n)) return null;
    let rating = "INFORMATIONAL", color = "#6b7280";
    if (n >= 9.0)      { rating = "CRITICAL"; color = "#ff1a1a"; }
    else if (n >= 7.0) { rating = "HIGH";     color = "#ff6600"; }
    else if (n >= 4.0) { rating = "MEDIUM";   color = "#f59e0b"; }
    else if (n >= 0.1) { rating = "LOW";      color = "#00d4ff"; }
    return { raw: n, display: n.toFixed(1), rating, color };
  }

  /* ── RISK SCORE HELPER ─────────────────────────────────────────────────── */
  function buildRiskScore(raw, severityColors) {
    const n   = _num(raw, 0);
    const pct = Math.round(Math.min(n / 10, 1) * 100);
    return { raw: n, display: n.toFixed(1), percent: pct, color: severityColors ? severityColors.primary : "#6b7280" };
  }

  /* ── SOURCE HOST EXTRACTOR ─────────────────────────────────────────────── */
  function extractHost(url) {
    if (!url) return "";
    try { const m = String(url).match(/^https?:\/\/([^/?#]+)/i); return m ? m[1].replace(/^www\./, "") : ""; }
    catch (e) { return ""; }
  }

  /* ── VALIDATION STATUS ─────────────────────────────────────────────────── */
  function buildValidationStatus(raw) {
    const s = _str(raw, "").toLowerCase();
    if (s === "valid")   return { label: "✓ VALID",   color: "#22c55e", class: "valid"   };
    if (s === "invalid") return { label: "✗ INVALID", color: "#ef4444", class: "invalid" };
    return                      { label: "? PENDING", color: "#f59e0b", class: "pending" };
  }

  /* ── MAIN ITEM NORMALIZER ──────────────────────────────────────────────── */
  function normalizeIntelItem(raw, idx) {
    if (!raw || typeof raw !== "object") {
      const _sc = getSeverityColors("LOW");
      return {
        id: "PARSE_ERROR_" + (idx || 0), stix_id: "", stix_id_short: "",
        title: "⚠ Data Parse Error", description: "", threat_type: "", tags: [],
        severity: "LOW", severity_colors: _sc, risk_score: buildRiskScore(0, _sc),
        confidence: 0, confidence_display: "0%",
        epss_score: null, cvss_score: null, has_epss: false, has_cvss: false, kev_present: false,
        action_rec: generateActionRecommendation("LOW","P4",null,null,false),
        impact_context: buildImpactContext("","","LOW"),
        freshness: freshnessIndicator(null),
        ai_verdict: buildAiVerdict("","LOW","P4","",0),
        paywall_features: buildPaywallFeatures(0,0),
        business_impact: buildBusinessImpact("","","LOW"),
        actor_tag:"", ioc_count:0, ioc_confidence:0, ioc_threat_level:"",
        ttps:[], ttp_count:0, mitre_tactics:[],
        ioc_paywall:{ locked:true, count:0, confidence:0, threat_level:"", upgrade_url:"", message:"" },
        published_at:"", published_at_fmt:"—", published_at_rel:"—",
        processed_at:"", processed_at_fmt:"—", processed_at_rel:"—",
        timestamp:"", timestamp_fmt:"—",
        source:"", source_url:"", source_host:"", report_url:"",
        stix_bundle_url:"", stix_bundle_locked:false, stix_bundle_upgrade_url:"",
        apex_ai:{
          soc_priority:"P4", soc_priority_meta:getSocPriorityMeta("P4"),
          threat_level:"LOW", threat_category:"", predictive_risk:0, ai_confidence:0,
          threat_confidence_tier:"LOW", threat_confidence_label:"", confidence_tier_meta:normalizeConfidence(0),
          ttp_density:0, campaign_id:"", actor_fingerprint:"", kill_chain:"", kill_chain_primary:"",
          ai_summary:"", recommended_action:"", behavioral_tags:[],
          paywall:{ locked_fields:[], upgrade_url:"", message:"", urgency:"" },
          kill_chain_locked:false,
        },
        apex:{}, validation_status:buildValidationStatus(""), stix_object_count:0,
        is_high_priority:false, paywall_active:false, has_ai_intel:false, has_ttps:false,
      };
    }

    const stixId    = _str(raw.stix_id, "intel--" + _str(raw.id, "unknown"));
    const stixShort = stixId.substring(0, 16);
    const sev       = normalizeSeverity(raw.severity);
    const sevColors = getSeverityColors(sev);
    const conf      = _num(raw.confidence, 0);
    const confTier  = normalizeConfidence(conf);
    const aa        = _obj(raw.apex_ai);
    const apexObj   = _obj(raw.apex);
    const socPri    = normalizeSocPriority(_str(aa.soc_priority, "P4"));
    const socMeta   = getSocPriorityMeta(socPri);
    const aiConf    = _int(aa.ai_confidence, Math.round(conf));
    const aiCat     = _str(aa.threat_category, _str(raw.threat_type, ""));
    const predRisk  = _num(aa.predictive_risk, 0);
    const killChain = _str(aa.kill_chain, "");
    const killLocked = killChain === "PRO_REQUIRED" || killChain === "LOCKED";
    const pw        = _obj(aa.paywall);
    const lockedFields  = _arr(pw.locked_fields);
    const upgradeUrl    = _str(pw.upgrade_url, "/upgrade.html?plan=pro");
    const stixBundleRaw = _str(raw.stix_bundle, "");
    const stixBundleLocked     = lockedFields.includes("stix_bundle");
    const stixBundleUrl        = stixBundleLocked ? "" : stixBundleRaw;
    const stixBundleUpgradeUrl = stixBundleLocked
      ? upgradeUrl + "&source=stix-bundle&severity=" + encodeURIComponent(sev)
        + "&utm_source=card-stix-gate&utm_medium=card&utm_campaign=stix-lock"
      : "";
    const iocPw = (raw.ioc_paywall && typeof raw.ioc_paywall === "object")
      ? { locked: _bool(raw.ioc_paywall.locked,true), count:_int(raw.ioc_paywall.count,0),
          confidence:_num(raw.ioc_paywall.confidence,0), threat_level:_str(raw.ioc_paywall.threat_level,""),
          upgrade_url:_str(raw.ioc_paywall.upgrade_url,upgradeUrl), message:_str(raw.ioc_paywall.message,"") }
      : { locked:true, count:0, confidence:0, threat_level:"", upgrade_url:upgradeUrl, message:"" };
    const epssRaw  = raw.epss_score !== undefined ? raw.epss_score : _nullableNum(apexObj.epss);
    const cvssRaw  = raw.cvss_score !== undefined ? raw.cvss_score : _nullableNum(apexObj.cvss3);
    const epssObj  = buildEpssScore(epssRaw);
    const cvssObj  = buildCvssScore(cvssRaw);
    const kev      = _bool(raw.kev_present, false);
    const actionRec = generateActionRecommendation(sev, socPri, epssObj, cvssObj, kev);
    const rawTtps  = _arr(raw.ttps);
    const ttps = rawTtps.map(function(t) {
      if (!t || typeof t !== "object") return null;
      const tid = _str(t.id, "");
      return { id:tid, name:_str(t.name,""), tactic:_str(t.tactic,""), justification:_str(t.justification,""),
               url: tid ? "https://attack.mitre.org/techniques/" + tid + "/" : "" };
    }).filter(Boolean);
    const paywallActive = lockedFields.length > 0 || iocPw.locked;
    const bi        = buildBusinessImpact(aiCat, _str(raw.threat_type,""), sev);
    const aiVerdict = buildAiVerdict(_str(aa.ai_summary,""), sev, socPri, aiCat, aiConf);

    return {
      id:               _str(raw.id, "intel-" + (idx || 0)),
      stix_id:          stixId,
      stix_id_short:    stixShort,
      title:            _str(raw.title, "Untitled Intelligence Report"),
      description:      _str(raw.description, ""),
      threat_type:      _str(raw.threat_type, aiCat),
      tags:             _arr(raw.tags),
      severity:         sev,
      severity_colors:  sevColors,
      risk_score:       buildRiskScore(_num(raw.risk_score, _num(apexObj.predictive_score,0)), sevColors),
      confidence:         conf,
      confidence_display: conf.toFixed(1) + "%",
      epss_score:  epssObj,
      cvss_score:  cvssObj,
      has_epss:    epssObj !== null,
      has_cvss:    cvssObj !== null,
      kev_present: kev,
      action_rec:     actionRec,
      impact_context: buildImpactContext(aiCat, _str(raw.threat_type,""), sev),
      freshness:      freshnessIndicator(raw.published_at || raw.timestamp),
      ai_verdict:     aiVerdict,
      paywall_features: buildPaywallFeatures(_int(raw.ioc_count,0), _int(raw.ttp_count,0)),
      business_impact:  bi,
      actor_tag:        _str(raw.actor_tag, ""),
      ioc_count:        _int(raw.ioc_count, 0),
      ioc_confidence:   _num(raw.ioc_confidence, 0),
      ioc_threat_level: _str(raw.ioc_threat_level, ""),
      ttps:             ttps,
      ttp_count:        _int(raw.ttp_count, ttps.length),
      mitre_tactics:    _arr(raw.mitre_tactics),
      ioc_paywall:      iocPw,
      published_at:     _str(raw.published_at, ""),
      published_at_fmt: formatTimestamp(raw.published_at),
      published_at_rel: relativeTime(raw.published_at),
      processed_at:     _str(raw.processed_at, ""),
      processed_at_fmt: formatTimestamp(raw.processed_at),
      processed_at_rel: relativeTime(raw.processed_at),
      timestamp:        _str(raw.timestamp, ""),
      timestamp_fmt:    formatTimestamp(raw.timestamp),
      source:      _str(raw.source, ""),
      source_url:  _str(raw.source_url, ""),
      source_host: extractHost(raw.source_url) || _str(raw.source, ""),
      report_url:  _str(raw.report_url, ""),
      stix_bundle_url:         stixBundleUrl,
      stix_bundle_locked:      stixBundleLocked,
      stix_bundle_upgrade_url: stixBundleUpgradeUrl,
      apex_ai: {
        soc_priority:            socPri,
        soc_priority_meta:       socMeta,
        threat_level:            _str(aa.threat_level, ""),
        threat_category:         aiCat,
        predictive_risk:         predRisk,
        ai_confidence:           aiConf,
        threat_confidence_tier:  _str(aa.threat_confidence_tier, confTier.tier),
        threat_confidence_label: _str(aa.threat_confidence_label, confTier.label),
        confidence_tier_meta:    confTier,
        ttp_density:             _num(aa.ttp_density, 0),
        campaign_id:             _str(aa.campaign_id, ""),
        actor_fingerprint:       _str(aa.actor_fingerprint, ""),
        kill_chain:              killChain,
        kill_chain_primary:      _str(aa.kill_chain_primary, ""),
        ai_summary:              _str(aa.ai_summary, ""),
        recommended_action:      _str(aa.recommended_action, ""),
        behavioral_tags:         _arr(aa.behavioral_tags),
        paywall: { locked_fields:lockedFields, upgrade_url:upgradeUrl, message:_str(pw.message,""), urgency:_str(pw.urgency,"") },
        kill_chain_locked: killLocked,
      },
      apex: apexObj,
      validation_status: buildValidationStatus(raw.validation_status),
      stix_object_count: _int(raw.stix_object_count, 0),
      is_high_priority:  (sev === "CRITICAL" || sev === "HIGH") && (socPri === "P1" || socPri === "P2"),
      paywall_active:    paywallActive,
      has_ai_intel:      aiConf > 0 || _str(aa.ai_summary,"").length > 5,
      has_ttps:          ttps.length > 0,
    };
  }

  /* ── BATCH RESPONSE NORMALIZER ─────────────────────────────────────────── */
  function normalizeApexResponse(data) {
    if (!data || typeof data !== "object") {
      return { status:"error", items:[], total_in_feed:0, generated_at:"", stats:{ total:0, by_severity:{}, total_iocs:0, high_priority:0 } };
    }
    const preview  = _obj(data.preview);
    const rawItems = _arr(preview.items);
    const items    = rawItems.map(function(item, i) { return normalizeIntelItem(item, i); });
    const bySev = {}; let totalIocs = 0, highPri = 0;
    items.forEach(function(item) {
      bySev[item.severity] = (bySev[item.severity] || 0) + 1;
      totalIocs += item.ioc_count;
      if (item.is_high_priority) highPri++;
    });
    const genAt = _str(preview.generated_at, "");
    return {
      status:        _str(data.status, "ok"),
      gateway:       _str(data.gateway, ""),
      request_id:    _str(data.request_id, ""),
      items:         items,
      total_in_feed: _int(preview.total_in_feed, items.length),
      total_preview: _int(preview.total_preview, items.length),
      generated_at:  genAt,
      generated_at_fmt: genAt ? formatTimestamp(genAt) : "—",
      stats: { total:items.length, by_severity:bySev, total_iocs:totalIocs, high_priority:highPri },
    };
  }

  /* ── FETCH AND NORMALIZE ───────────────────────────────────────────────── */
  /* Required by card_renderer_integration.js.                               */
  /* Fetches the given URL, parses the JSON, and returns { normalized, error, cached }. */
  async function fetchAndNormalize(url, opts) {
    const options = opts || {};
    const timeoutMs = options.timeoutMs || 10000;
    const maxRetry  = options.maxRetry  || 1;

    for (let attempt = 0; attempt <= maxRetry; attempt++) {
      try {
        const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
        const timer = controller ? setTimeout(function() { controller.abort(); }, timeoutMs) : null;
        const fetchOpts = controller ? { signal: controller.signal } : {};
        const res = await fetch(url + (url.includes("?") ? "&" : "?") + "_t=" + Date.now(), fetchOpts);
        if (timer) clearTimeout(timer);
        if (!res.ok) throw new Error("HTTP " + res.status);
        const json = await res.json();
        const normalized = normalizeApexResponse(json);
        if (normalized.items.length === 0 && attempt < maxRetry) continue;
        return { normalized, error: null, cached: false };
      } catch (e) {
        if (attempt >= maxRetry) {
          // Last resort: try window.EMBEDDED_INTEL as offline cache
          if (typeof window !== "undefined" && window.EMBEDDED_INTEL && window.EMBEDDED_INTEL.length) {
            const items = window.EMBEDDED_INTEL.map(function(item, i) { return normalizeIntelItem(item, i); });
            const bySev = {}; let totalIocs = 0, highPri = 0;
            items.forEach(function(it) {
              bySev[it.severity] = (bySev[it.severity] || 0) + 1;
              totalIocs += it.ioc_count;
              if (it.is_high_priority) highPri++;
            });
            return {
              normalized: {
                status: "ok", items: items, total_in_feed: items.length, total_preview: items.length,
                generated_at: new Date().toISOString(), generated_at_fmt: "EMBEDDED CACHE",
                stats: { total: items.length, by_severity: bySev, total_iocs: totalIocs, high_priority: highPri },
              },
              error: e,
              cached: true,
            };
          }
          return { normalized: null, error: e, cached: false };
        }
        await new Promise(function(r) { setTimeout(r, 500 * (attempt + 1)); });
      }
    }
    return { normalized: null, error: new Error("All retries exhausted"), cached: false };
  }

  /* ── PUBLIC API ─────────────────────────────────────────────────────────── */
  return {
    VERSION: "147.0.0",

    /* Core normalizers */
    normalizeIntelItem:           normalizeIntelItem,
    normalizeApiResponse:         normalizeApexResponse,
    fetchAndNormalize:            fetchAndNormalize,

    /* Individual builders (exposed for testing) */
    buildAiVerdict:               buildAiVerdict,
    buildBusinessImpact:          buildBusinessImpact,
    buildImpactContext:           buildImpactContext,
    buildPaywallFeatures:         buildPaywallFeatures,
    generateActionRecommendation: generateActionRecommendation,
    freshnessIndicator:           freshnessIndicator,
    normalizeSeverity:            normalizeSeverity,
    getSeverityColors:            getSeverityColors,
    normalizeSocPriority:         normalizeSocPriority,
    getSocPriorityMeta:           getSocPriorityMeta,
    normalizeConfidence:          normalizeConfidence,
    formatTimestamp:              formatTimestamp,
    relativeTime:                 relativeTime,
  };

});
