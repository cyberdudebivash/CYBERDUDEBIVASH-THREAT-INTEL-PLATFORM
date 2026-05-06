/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — API ADAPTER v144.0.0
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

  /* ── AI VERDICT BUILDER ────────────────────────────────────────────────── */
  function buildAiVerdict(aiSummary, severity, socPriority, threatCategory, aiConfidence) {
    const sev  = normalizeSeverity(severity);
    const soc  = normalizeSocPriority(socPriority);
    const cat  = _str(threatCategory, "threat");
    const conf = _int(aiConfidence, 0);

    // Strip internal prefixes like "[VERIFIED]", "[HIGH]", etc.
    const cleanSummary = _str(aiSummary, "")
      .replace(/^\[[\w\s]+\]\s*/i, "")
      .replace(/\s*PRO TIER REQUIRED.*$/i, "")
      .trim();

    // Confidence qualifier
    const confQual = conf >= 80 ? "High-confidence"
                   : conf >= 50 ? "Moderate-confidence"
                   : "Low-confidence";

    // Action suffix based on SOC priority
    const actionSuffix = soc === "P1" ? "Immediate incident response required."
                       : soc === "P2" ? "Urgent investigation recommended."
                       : soc === "P3" ? "Active monitoring and detection tuning advised."
                       : "Log and monitor for further activity.";

    // If we have a real AI summary, use it cleaned up. Otherwise generate.
    if (cleanSummary && cleanSummary.length > 20) {
      return `${confQual} ${sev.toLowerCase()}-severity ${cat.toLowerCase()} detected. ${cleanSummary} ${actionSuffix}`;
    }

    return `${confQual} ${sev.toLowerCase()}-severity ${cat.toLowerCase()} threat. ${actionSuffix}`;
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

  function normalizeConfidenceTier(tier) {
    const key = _str(tier, "LOW").toUpperCase();
    return CONFIDENCE_TIERS[key] || CONFIDENCE_TIERS["LOW"];
  }

  /* ── SCORING FORMATTERS ────────────────────────────────────────────────── */
  function formatRiskScore(score) {
    const n = _num(score, 0);
    return {
      raw:      n,
      display:  n.toFixed(1),
      outOf:    "10",
      percent:  Math.min(100, (n / 10) * 100),
      color:    n >= 8 ? "#ff1a1a" : n >= 6 ? "#ff6600" : n >= 4 ? "#f59e0b" : "#00d4ff",
      category: n >= 8 ? "CRITICAL" : n >= 6 ? "HIGH" : n >= 4 ? "MEDIUM" : "LOW",
    };
  }

  function formatEpssScore(score) {
    const n = _nullableNum(score);
    if (n === null) return null;
    return {
      raw:     n,
      display: n.toFixed(2) + "%",
      percent: Math.min(100, n),
      risk:    n >= 10 ? "CRITICAL EXPLOIT RISK" : n >= 1 ? "HIGH EXPLOIT RISK" : n >= 0.1 ? "MODERATE EXPLOIT RISK" : "LOW EXPLOIT RISK",
      color:   n >= 10 ? "#ff1a1a" : n >= 1 ? "#ff6600" : n >= 0.1 ? "#f59e0b" : "#64748b",
    };
  }

  function formatCvssScore(score) {
    const n = _nullableNum(score);
    if (n === null) return null;
    return {
      raw:     n,
      display: n.toFixed(1),
      outOf:   "10",
      rating:  n >= 9 ? "CRITICAL" : n >= 7 ? "HIGH" : n >= 4 ? "MEDIUM" : "LOW",
      color:   n >= 9 ? "#ff1a1a" : n >= 7 ? "#ff6600" : n >= 4 ? "#f59e0b" : "#00d4ff",
    };
  }

  /* ── TTP ADAPTER ───────────────────────────────────────────────────────── */
  function adaptTtps(ttps) {
    return _arr(ttps).map(function (t) {
      if (typeof t === "string") return { id: t, name: "Technique " + t, tactic: "Unknown", justification: "", url: "https://attack.mitre.org/techniques/" + t.replace(".", "/") };
      return {
        id:            _str(t.id || t.technique_id, "UNKNOWN"),
        name:          _str(t.name || t.technique_name, "Unknown Technique"),
        tactic:        _str(t.tactic, "Unknown"),
        justification: _str(t.justification, ""),
        url:           "https://attack.mitre.org/techniques/" + _str(t.id || t.technique_id, "").replace(".", "/"),
      };
    }).filter(function (t) { return t.id !== "UNKNOWN"; });
  }

  /* ── IOC PAYWALL ADAPTER ───────────────────────────────────────────────── */
  function adaptIocPaywall(raw) {
    const pw = _obj(raw);
    return {
      locked:        _bool(pw.locked, true),
      count:         _int(pw.count, 0),
      confidence:    _num(pw.confidence, 0),
      threat_level:  _str(pw.threat_level, "LOW"),
      primary_types: _arr(pw.primary_types),
      upgrade_url:   _str(pw.upgrade_url, "/upgrade.html?plan=pro&utm_source=card-paywall"),
      message:       _str(pw.message, "IOC dataset locked — upgrade to Pro tier to access."),
    };
  }

  /* ── APEX AI PAYWALL ADAPTER ───────────────────────────────────────────── */
  function adaptApexAiPaywall(raw) {
    const pw = _obj(raw);
    return {
      locked_fields: _arr(pw.locked_fields),
      upgrade_url:   _str(pw.upgrade_url, "/upgrade.html?plan=pro&utm_source=card-ai-paywall"),
      message:       _str(pw.message, "Full actor attribution and kill chain locked."),
      urgency:       _str(pw.urgency, "Active threat — upgrade to unlock complete intelligence."),
    };
  }

  /* ── APEX AI ADAPTER ───────────────────────────────────────────────────── */
  function adaptApexAi(raw) {
    const ai = _obj(raw);
    const confidenceTier = normalizeConfidenceTier(_str(ai.threat_confidence_tier, "LOW"));
    return {
      soc_priority:            normalizeSocPriority(_str(ai.soc_priority, "P4")),
      soc_priority_meta:       getSocPriorityMeta(_str(ai.soc_priority, "P4")),
      threat_level:            normalizeSeverity(_str(ai.threat_level, "LOW")),
      threat_category:         _str(ai.threat_category, "Threat Intelligence"),
      predictive_risk:         _num(ai.predictive_risk, 0),
      ai_confidence:           _int(ai.ai_confidence, 0),
      threat_confidence_tier:  _str(ai.threat_confidence_tier, "LOW"),
      threat_confidence_label: _str(ai.threat_confidence_label, "◇ LOW – Limited signals, threat monitoring recommended"),
      confidence_tier_meta:    confidenceTier,
      ttp_density:             _num(ai.ttp_density, 0),
      campaign_id:             _str(ai.campaign_id, "UNCLASSIFIED"),
      actor_fingerprint:       _str(ai.actor_fingerprint, ""),
      kill_chain:              _str(ai.kill_chain, "PRO_REQUIRED"),
      kill_chain_primary:      _str(ai.kill_chain_primary, "PRO_REQUIRED"),
      ai_summary:              _str(ai.ai_summary, ""),
      recommended_action:      _str(ai.recommended_action, ""),
      behavioral_tags:         _arr(ai.behavioral_tags),
      paywall:                 adaptApexAiPaywall(_obj(ai.paywall)),
      kill_chain_locked:       _str(ai.kill_chain, "PRO_REQUIRED") === "PRO_REQUIRED",
    };
  }

  /* ── APEX ADAPTER ──────────────────────────────────────────────────────── */
  function adaptApex(raw) {
    const apex = _obj(raw);
    return {
      priority:         normalizeSocPriority(_str(apex.priority, "P4")),
      threat_level:     normalizeSeverity(_str(apex.threat_level, "LOW")),
      threat_category:  _str(apex.threat_category, "Threat Intelligence"),
      predictive_score: _num(apex.predictive_score, 0),
      campaign_id:      _str(apex.campaign_id, "UNCLASSIFIED"),
    };
  }

  /* ── HELPER UTILITIES ──────────────────────────────────────────────────── */
  function extractHostname(url) {
    if (!url) return "";
    try { return new URL(url).hostname.replace("www.", ""); }
    catch (e) { return _str(url).replace(/^https?:\/\/(www\.)?/, "").split("/")[0]; }
  }

  function formatStixId(stixId) {
    const s = _str(stixId);
    if (!s) return "—";
    const parts = s.split("--");
    if (parts.length >= 2) return parts[0] + "--" + parts[1].substring(0, 8) + "…";
    return s.length > 16 ? s.substring(0, 16) + "…" : s;
  }

  function normalizeValidationStatus(raw) {
    const s = _str(raw, "unknown").toLowerCase();
    if (s === "valid")   return { label: "✓ VALID",   color: "#22c55e", class: "valid" };
    if (s === "invalid") return { label: "✗ INVALID", color: "#ef4444", class: "invalid" };
    return                      { label: "? UNKNOWN", color: "#6b7280", class: "unknown" };
  }

  /* ── MAIN NORMALIZER ───────────────────────────────────────────────────── */
  function normalizeIntelItem(raw) {
    if (!raw || typeof raw !== "object") return _buildEmptyIntelItem();

    const sevNorm    = normalizeSeverity(_str(raw.severity));
    const sevColors  = getSeverityColors(sevNorm);
    const riskScore  = formatRiskScore(raw.risk_score);
    const epss       = formatEpssScore(raw.epss_score);
    const cvss       = formatCvssScore(raw.cvss_score);
    const ttps       = adaptTtps(_arr(raw.ttps));
    const mitreTacs  = adaptTtps(_arr(raw.mitre_tactics));
    const apexAi     = adaptApexAi(_obj(raw.apex_ai));
    const apex       = adaptApex(_obj(raw.apex));
    const iocPaywall = adaptIocPaywall(_obj(raw.ioc_paywall));
    const valStatus  = normalizeValidationStatus(_str(raw.validation_status));
    const sourceHost = extractHostname(_str(raw.source_url));

    // ── Computed/derived fields ────────────────────────────────────────────
    const kevPresent      = _bool(raw.kev_present, false);
    const iocCount        = _int(raw.ioc_count, 0);
    const ttpCount        = _int(raw.ttp_count, ttps.length);
    const actionRec       = generateActionRecommendation(sevNorm, apexAi.soc_priority, epss, cvss, kevPresent);
    const impactCtx       = buildImpactContext(apexAi.threat_category, _str(raw.threat_type, apexAi.threat_category), sevNorm);
    const freshness       = freshnessIndicator(_str(raw.published_at, raw.timestamp || ""));
    const aiVerdict       = buildAiVerdict(apexAi.ai_summary, sevNorm, apexAi.soc_priority, apexAi.threat_category, apexAi.ai_confidence);
    const paywallFeatures = buildPaywallFeatures(iocCount, ttpCount);

    return {
      /* CORE IDENTITY */
      id:                  _str(raw.id || raw.stix_id, "unknown--" + Math.random().toString(36).slice(2)),
      stix_id:             _str(raw.stix_id, ""),
      stix_id_short:       formatStixId(_str(raw.stix_id, "")),
      title:               _str(raw.title, "Untitled Intelligence Report"),
      description:         _str(raw.description, ""),
      threat_type:         _str(raw.threat_type, "Threat Intelligence"),
      tags:                _arr(raw.tags),

      /* SEVERITY */
      severity:            sevNorm,
      severity_colors:     sevColors,

      /* SCORING */
      risk_score:          riskScore,
      confidence:          _num(raw.confidence, 0),
      confidence_display:  _num(raw.confidence, 0).toFixed(1) + "%",
      epss_score:          epss,
      cvss_score:          cvss,
      has_epss:            epss !== null,
      has_cvss:            cvss !== null,
      kev_present:         kevPresent,

      /* ACTION RECOMMENDATION */
      action_rec:          actionRec,

      /* IMPACT & CONTEXT */
      impact_context:      impactCtx,

      /* FRESHNESS */
      freshness:           freshness,

      /* AI VERDICT */
      ai_verdict:          aiVerdict,

      /* PAYWALL FEATURES */
      paywall_features:    paywallFeatures,

      /* THREAT INTEL */
      actor_tag:           _str(raw.actor_tag, "UNKNOWN"),
      ioc_count:           iocCount,
      ioc_confidence:      _num(raw.ioc_confidence, 0),
      ioc_threat_level:    _str(raw.ioc_threat_level, "LOW"),
      ttps:                ttps,
      ttp_count:           ttpCount,
      mitre_tactics:       mitreTacs,

      /* IOC PAYWALL */
      ioc_paywall:         iocPaywall,

      /* TIMELINE */
      published_at:        _str(raw.published_at, ""),
      published_at_fmt:    formatTimestamp(_str(raw.published_at, "")),
      published_at_rel:    relativeTime(_str(raw.published_at, "")),
      processed_at:        _str(raw.processed_at, ""),
      processed_at_fmt:    formatTimestamp(_str(raw.processed_at, "")),
      processed_at_rel:    relativeTime(_str(raw.processed_at, "")),
      timestamp:           _str(raw.timestamp, ""),
      timestamp_fmt:       formatTimestamp(_str(raw.timestamp, "")),

      /* SOURCE */
      source:              _str(raw.source, "Unknown Source"),
      source_url:          _str(raw.source_url, "#"),
      source_host:         sourceHost || _str(raw.source, "Unknown"),
      report_url:          _str(raw.report_url, "#"),
      stix_bundle_url:     _str(raw.stix_bundle, ""),

      /* APEX AI */
      apex_ai:             apexAi,

      /* APEX CORE */
      apex:                apex,

      /* SYSTEM */
      validation_status:   valStatus,
      stix_object_count:   _int(raw.stix_object_count, 0),

      /* COMPUTED FLAGS */
      is_high_priority:    sevNorm === "CRITICAL" || sevNorm === "HIGH" || apexAi.soc_priority === "P1" || apexAi.soc_priority === "P2",
      paywall_active:      iocPaywall.locked || apexAi.paywall.locked_fields.length > 0,
      has_ai_intel:        true,
      has_ttps:            ttps.length > 0 || mitreTacs.length > 0,
    };
  }

  function _buildEmptyIntelItem() {
    return normalizeIntelItem({
      id: "error--" + Date.now(), stix_id: "", title: "⚠ Data Parse Error",
      severity: "LOW", risk_score: 0, confidence: 0, threat_type: "Unknown",
      actor_tag: "UNKNOWN", ioc_count: 0, ttp_count: 0, ttps: [], mitre_tactics: [],
      source: "Unknown", validation_status: "invalid", stix_object_count: 0,
    });
  }

  /* ── BATCH NORMALIZER ──────────────────────────────────────────────────── */
  function normalizeApiResponse(apiResponse) {
    if (!apiResponse || typeof apiResponse !== "object") return _buildEmptyResponse();
    const preview  = _obj(apiResponse.preview);
    const rawItems = _arr(preview.items || apiResponse.items || []);
    const items    = rawItems.map(function (item, idx) {
      try { return normalizeIntelItem(item); }
      catch (e) { console.warn("[SentinelApexAdapter] Item " + idx + " failed:", e); return _buildEmptyIntelItem(); }
    });
    return {
      status:           _str(apiResponse.status, "unknown"),
      gateway:          _str(apiResponse.gateway, "SENTINEL-APEX"),
      request_id:       _str(apiResponse.request_id, ""),
      items:            items,
      total_preview:    _int(preview.total_preview || items.length, items.length),
      total_in_feed:    _int(preview.total_in_feed, items.length),
      generated_at:     _str(preview.generated_at, ""),
      generated_at_fmt: formatTimestamp(_str(preview.generated_at, "")),
      note:             _str(preview.note, ""),
      get_api_key_url:  _str(apiResponse.get_api_key, "/upgrade.html"),
      docs_url:         _str(apiResponse.docs, "/api-docs.html"),
      cached:           _bool(apiResponse.cached, false),
      stats:            _computeStats(items),
    };
  }

  function _buildEmptyResponse() {
    return { status: "error", gateway: "SENTINEL-APEX", request_id: "", items: [],
             total_preview: 0, total_in_feed: 0, generated_at: "", generated_at_fmt: "—",
             note: "", cached: false, get_api_key_url: "/upgrade.html", docs_url: "/api-docs.html",
             stats: _computeStats([]) };
  }

  function _computeStats(items) {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    let totalRisk = 0, totalConf = 0, totalIocs = 0;
    items.forEach(function (item) {
      counts[item.severity] = (counts[item.severity] || 0) + 1;
      totalRisk += item.risk_score.raw;
      totalConf += item.confidence;
      totalIocs += item.ioc_count;
    });
    const n = items.length || 1;
    return {
      by_severity:    counts,
      total:          items.length,
      avg_risk:       (totalRisk / n).toFixed(1),
      avg_confidence: (totalConf / n).toFixed(1),
      total_iocs:     totalIocs,
      high_priority:  items.filter(function (i) { return i.is_high_priority; }).length,
      paywall_items:  items.filter(function (i) { return i.paywall_active; }).length,
    };
  }

  /* ── SAFE FETCH ─────────────────────────────────────────────────────────── */
  async function safeFetch(url, options) {
    const opts = options || {};
    const maxRetry  = opts.maxRetry  !== undefined ? opts.maxRetry  : 2;
    const timeoutMs = opts.timeoutMs !== undefined ? opts.timeoutMs : 8000;
    const baseMs    = opts.baseMs    !== undefined ? opts.baseMs    : 1000;
    let lastErr;
    for (let attempt = 0; attempt <= maxRetry; attempt++) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(function () { controller.abort(); }, timeoutMs);
        const resp = await fetch(url + (url.includes("?") ? "&" : "?") + "_t=" + Date.now(), {
          cache: "no-store", signal: controller.signal,
        });
        clearTimeout(timer);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const json = await resp.json();
        return { data: json, error: null, cached: false };
      } catch (err) {
        lastErr = err;
        if (attempt < maxRetry) await new Promise(function (r) { setTimeout(r, baseMs * Math.pow(2, attempt)); });
      }
    }
    try {
      const cacheKey = "sapx_feed_" + btoa(url).substring(0, 32);
      const cached = sessionStorage.getItem(cacheKey);
      if (cached) return { data: JSON.parse(cached), error: null, cached: true };
    } catch (e) { /* non-fatal */ }
    return { data: null, error: lastErr, cached: false };
  }

  async function fetchAndNormalize(url, options) {
    const result = await safeFetch(url, options);
    if (!result.data) return { normalized: _buildEmptyResponse(), raw: null, error: result.error, cached: false };
    try {
      const cacheKey = "sapx_feed_" + btoa(url).substring(0, 32);
      sessionStorage.setItem(cacheKey, JSON.stringify(result.data));
    } catch (e) { /* non-fatal */ }
    return { normalized: normalizeApiResponse(result.data), raw: result.data, error: null, cached: result.cached };
  }

  /* ── PUBLIC API ─────────────────────────────────────────────────────────── */
  return {
    normalizeIntelItem:       normalizeIntelItem,
    normalizeApiResponse:     normalizeApiResponse,
    safeFetch:                safeFetch,
    fetchAndNormalize:        fetchAndNormalize,
    normalizeSeverity:        normalizeSeverity,
    getSeverityColors:        getSeverityColors,
    getSocPriorityMeta:       getSocPriorityMeta,
    normalizeSocPriority:     normalizeSocPriority,
    generateActionRecommendation: generateActionRecommendation,
    buildImpactContext:       buildImpactContext,
    freshnessIndicator:       freshnessIndicator,
    buildAiVerdict:           buildAiVerdict,
    buildPaywallFeatures:     buildPaywallFeatures,
    formatTimestamp:          formatTimestamp,
    relativeTime:             relativeTime,
    formatRiskScore:          formatRiskScore,
    formatEpssScore:          formatEpssScore,
    formatCvssScore:          formatCvssScore,
    normalizeConfidenceTier:  normalizeConfidenceTier,
    extractHostname:          extractHostname,
    formatStixId:             formatStixId,
    VERSION: "144.0.0",
    BUILD:   "SENTINEL-APEX-ADAPTER-ENTERPRISE",
  };

}); // end factory

if (typeof window !== "undefined") {
  window.dispatchEvent(new CustomEvent("SentinelApexAdapterReady", { detail: { version: "144.0.0" } }));
  console.info("[SENTINEL APEX] Adapter v144.0.0 loaded ✓");
}
