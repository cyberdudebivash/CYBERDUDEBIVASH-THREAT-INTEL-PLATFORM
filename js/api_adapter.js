/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — API ADAPTER v143.0.0
 *  Strict 1:1 API → UI field mapping layer
 *  Author: CYBERDUDEBIVASH SENTINEL APEX Platform
 *  Pipeline Safety: READ-ONLY transform — never mutates source data
 *  Zero undefined values — every field has a typed safe fallback
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

  /* ─────────────────────────────────────────────────────────────
   *  INTERNAL HELPERS — safe accessors with typed fallbacks
   * ───────────────────────────────────────────────────────────── */

  function _str(val, fallback) {
    if (val === null || val === undefined || val === "") return fallback !== undefined ? String(fallback) : "";
    return String(val);
  }

  function _num(val, fallback) {
    const n = parseFloat(val);
    return isNaN(n) ? (fallback !== undefined ? Number(fallback) : 0) : n;
  }

  function _int(val, fallback) {
    const n = parseInt(val, 10);
    return isNaN(n) ? (fallback !== undefined ? parseInt(fallback, 10) : 0) : n;
  }

  function _bool(val, fallback) {
    if (val === null || val === undefined) return fallback !== undefined ? Boolean(fallback) : false;
    return Boolean(val);
  }

  function _arr(val) {
    if (!val || !Array.isArray(val)) return [];
    return val;
  }

  function _obj(val) {
    if (!val || typeof val !== "object" || Array.isArray(val)) return {};
    return val;
  }

  function _nullableNum(val) {
    if (val === null || val === undefined) return null;
    const n = parseFloat(val);
    return isNaN(n) ? null : n;
  }

  /* ─────────────────────────────────────────────────────────────
   *  SEVERITY NORMALIZER
   * ───────────────────────────────────────────────────────────── */

  const SEVERITY_MAP = {
    CRITICAL: "CRITICAL",
    HIGH:     "HIGH",
    MEDIUM:   "MEDIUM",
    LOW:      "LOW",
    INFO:     "INFO",
  };

  function normalizeSeverity(raw) {
    if (!raw) return "LOW";
    const upper = String(raw).toUpperCase().trim();
    return SEVERITY_MAP[upper] || "LOW";
  }

  /* ─────────────────────────────────────────────────────────────
   *  SOC PRIORITY NORMALIZER
   * ───────────────────────────────────────────────────────────── */

  function normalizeSocPriority(raw) {
    if (!raw) return "P4";
    const upper = String(raw).toUpperCase().trim();
    if (upper === "P1" || upper === "P2" || upper === "P3" || upper === "P4") return upper;
    return "P4";
  }

  /* ─────────────────────────────────────────────────────────────
   *  TIMESTAMP FORMATTERS
   * ───────────────────────────────────────────────────────────── */

  function formatTimestamp(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "—";
      return d.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    } catch (e) {
      return "—";
    }
  }

  function relativeTime(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "—";
      const diffMs = Date.now() - d.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      if (diffMins < 1) return "just now";
      if (diffMins < 60) return diffMins + "m ago";
      const diffHrs = Math.floor(diffMins / 60);
      if (diffHrs < 24) return diffHrs + "h ago";
      const diffDays = Math.floor(diffHrs / 24);
      return diffDays + "d ago";
    } catch (e) {
      return "—";
    }
  }

  /* ─────────────────────────────────────────────────────────────
   *  THREAT CONFIDENCE TIER NORMALIZER
   * ───────────────────────────────────────────────────────────── */

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

  /* ─────────────────────────────────────────────────────────────
   *  SEVERITY COLOR MAP — neon palette
   * ───────────────────────────────────────────────────────────── */

  const SEVERITY_COLORS = {
    CRITICAL: { primary: "#ff1a1a", glow: "rgba(255,26,26,0.5)",   dim: "rgba(220,38,38,0.12)",  border: "rgba(220,38,38,0.4)",  text: "#ff6b6b", class: "sev-critical" },
    HIGH:     { primary: "#ff6600", glow: "rgba(255,102,0,0.45)",  dim: "rgba(234,88,12,0.10)",  border: "rgba(234,88,12,0.35)", text: "#fb923c", class: "sev-high"     },
    MEDIUM:   { primary: "#f59e0b", glow: "rgba(245,158,11,0.35)", dim: "rgba(217,119,6,0.08)",  border: "rgba(217,119,6,0.30)", text: "#fbbf24", class: "sev-medium"   },
    LOW:      { primary: "#00d4ff", glow: "rgba(0,212,255,0.25)",  dim: "rgba(0,212,255,0.06)",  border: "rgba(0,212,255,0.20)", text: "#38bdf8", class: "sev-low"      },
    INFO:     { primary: "#6b7280", glow: "rgba(107,114,128,0.2)", dim: "rgba(107,114,128,0.05)", border: "rgba(107,114,128,0.2)", text: "#9ca3af", class: "sev-info"   },
  };

  function getSeverityColors(sev) {
    return SEVERITY_COLORS[normalizeSeverity(sev)] || SEVERITY_COLORS["LOW"];
  }

  /* ─────────────────────────────────────────────────────────────
   *  SOC PRIORITY COLORS
   * ───────────────────────────────────────────────────────────── */

  const SOC_PRIORITY_MAP = {
    P1: { label: "P1 — CRITICAL RESPONSE", color: "#ff1a1a", bg: "rgba(220,38,38,0.15)", border: "rgba(220,38,38,0.4)", badge: "🔴" },
    P2: { label: "P2 — URGENT RESPONSE",   color: "#ff6600", bg: "rgba(234,88,12,0.12)", border: "rgba(234,88,12,0.3)", badge: "🟠" },
    P3: { label: "P3 — ACTIVE MONITORING", color: "#f59e0b", bg: "rgba(217,119,6,0.10)", border: "rgba(217,119,6,0.25)", badge: "🟡" },
    P4: { label: "P4 — INFORMATIONAL",     color: "#00d4ff", bg: "rgba(0,212,255,0.07)", border: "rgba(0,212,255,0.18)", badge: "🔵" },
  };

  function getSocPriorityMeta(priority) {
    return SOC_PRIORITY_MAP[normalizeSocPriority(priority)] || SOC_PRIORITY_MAP["P4"];
  }

  /* ─────────────────────────────────────────────────────────────
   *  TTP ADAPTER — normalizes TTP/MITRE arrays
   * ───────────────────────────────────────────────────────────── */

  function adaptTtps(ttps) {
    const arr = _arr(ttps);
    return arr.map(function (t) {
      if (typeof t === "string") {
        return { id: t, name: "Technique " + t, tactic: "Unknown", justification: "" };
      }
      return {
        id:            _str(t.id || t.technique_id, "UNKNOWN"),
        name:          _str(t.name || t.technique_name, "Unknown Technique"),
        tactic:        _str(t.tactic, "Unknown"),
        justification: _str(t.justification, ""),
        url:           "https://attack.mitre.org/techniques/" + _str(t.id || t.technique_id, "").replace(".", "/"),
      };
    }).filter(function (t) { return t.id !== "UNKNOWN"; });
  }

  /* ─────────────────────────────────────────────────────────────
   *  IOC PAYWALL ADAPTER
   * ───────────────────────────────────────────────────────────── */

  function adaptIocPaywall(raw) {
    const pw = _obj(raw);
    return {
      locked:        _bool(pw.locked, true),
      count:         _int(pw.count, 0),
      confidence:    _num(pw.confidence, 0),
      threat_level:  _str(pw.threat_level, "LOW"),
      primary_types: _arr(pw.primary_types),
      upgrade_url:   _str(pw.upgrade_url, "/upgrade.html?plan=pro"),
      message:       _str(pw.message, "IOCs locked — upgrade to Pro tier to access."),
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  APEX AI PAYWALL ADAPTER
   * ───────────────────────────────────────────────────────────── */

  function adaptApexAiPaywall(raw) {
    const pw = _obj(raw);
    return {
      locked_fields: _arr(pw.locked_fields),
      upgrade_url:   _str(pw.upgrade_url, "/upgrade.html?plan=pro"),
      message:       _str(pw.message, "Full actor attribution locked — upgrade to Pro."),
      urgency:       _str(pw.urgency, "Upgrade to unlock complete intelligence package."),
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  APEX AI ADAPTER — full apex_ai object normalization
   * ───────────────────────────────────────────────────────────── */

  function adaptApexAi(raw) {
    const ai = _obj(raw);
    const confidenceTier = normalizeConfidenceTier(_str(ai.threat_confidence_tier, "LOW"));
    return {
      soc_priority:             normalizeSocPriority(_str(ai.soc_priority, "P4")),
      soc_priority_meta:        getSocPriorityMeta(_str(ai.soc_priority, "P4")),
      threat_level:             normalizeSeverity(_str(ai.threat_level, "LOW")),
      threat_category:          _str(ai.threat_category, "Threat Intelligence"),
      predictive_risk:          _num(ai.predictive_risk, 0),
      ai_confidence:            _int(ai.ai_confidence, 0),
      threat_confidence_tier:   _str(ai.threat_confidence_tier, "LOW"),
      threat_confidence_label:  _str(ai.threat_confidence_label, "◇ LOW – Limited signals, threat monitoring recommended"),
      confidence_tier_meta:     confidenceTier,
      ttp_density:              _num(ai.ttp_density, 0),
      campaign_id:              _str(ai.campaign_id, "UNCLASSIFIED"),
      actor_fingerprint:        _str(ai.actor_fingerprint, "UNKNOWN"),
      kill_chain:               _str(ai.kill_chain, "PRO_REQUIRED"),
      kill_chain_primary:       _str(ai.kill_chain_primary, "PRO_REQUIRED"),
      ai_summary:               _str(ai.ai_summary, "Intelligence summary unavailable."),
      recommended_action:       _str(ai.recommended_action, "Review and monitor threat indicators."),
      behavioral_tags:          _arr(ai.behavioral_tags),
      paywall:                  adaptApexAiPaywall(_obj(ai.paywall)),
      // Kill chain locked?
      kill_chain_locked:        _str(ai.kill_chain, "PRO_REQUIRED") === "PRO_REQUIRED",
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  APEX ADAPTER — core apex object normalization
   * ───────────────────────────────────────────────────────────── */

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

  /* ─────────────────────────────────────────────────────────────
   *  RISK SCORE FORMATTER — normalized display
   * ───────────────────────────────────────────────────────────── */

  function formatRiskScore(score) {
    const n = _num(score, 0);
    return {
      raw:       n,
      display:   n.toFixed(1),
      outOf:     "10",
      percent:   Math.min(100, (n / 10) * 100),
      color:     n >= 8 ? "#ff1a1a" : n >= 6 ? "#ff6600" : n >= 4 ? "#f59e0b" : "#00d4ff",
      category:  n >= 8 ? "CRITICAL" : n >= 6 ? "HIGH" : n >= 4 ? "MEDIUM" : "LOW",
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  EPSS SCORE FORMATTER
   * ───────────────────────────────────────────────────────────── */

  function formatEpssScore(score) {
    const n = _nullableNum(score);
    if (n === null) return null;
    return {
      raw:      n,
      display:  n.toFixed(2) + "%",
      percent:  Math.min(100, n),
      risk:     n >= 10 ? "CRITICAL" : n >= 1 ? "HIGH" : n >= 0.1 ? "MODERATE" : "LOW",
      color:    n >= 10 ? "#ff1a1a" : n >= 1 ? "#ff6600" : n >= 0.1 ? "#f59e0b" : "#64748b",
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  CVSS SCORE FORMATTER
   * ───────────────────────────────────────────────────────────── */

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

  /* ─────────────────────────────────────────────────────────────
   *  HOSTNAME EXTRACTOR
   * ───────────────────────────────────────────────────────────── */

  function extractHostname(url) {
    if (!url) return "";
    try {
      return new URL(url).hostname.replace("www.", "");
    } catch (e) {
      return _str(url).replace(/^https?:\/\/(www\.)?/, "").split("/")[0];
    }
  }

  /* ─────────────────────────────────────────────────────────────
   *  STIX ID DISPLAY — short format
   * ───────────────────────────────────────────────────────────── */

  function formatStixId(stixId) {
    const s = _str(stixId);
    if (!s) return "—";
    // e.g. "intel--59e6f1cf42270e51349fe064" → "intel--59e6f1cf"
    const parts = s.split("--");
    if (parts.length >= 2) {
      return parts[0] + "--" + parts[1].substring(0, 8) + "…";
    }
    return s.length > 16 ? s.substring(0, 16) + "…" : s;
  }

  /* ─────────────────────────────────────────────────────────────
   *  VALIDATION STATUS NORMALIZER
   * ───────────────────────────────────────────────────────────── */

  function normalizeValidationStatus(raw) {
    const s = _str(raw, "unknown").toLowerCase();
    if (s === "valid") return { label: "✓ VALID", color: "#22c55e", class: "valid" };
    if (s === "invalid") return { label: "✗ INVALID", color: "#ef4444", class: "invalid" };
    return { label: "? UNKNOWN", color: "#6b7280", class: "unknown" };
  }

  /* ─────────────────────────────────────────────────────────────
   *  MAIN ADAPTER — normalizeIntelItem
   *  Maps full API response item → clean UI-ready IntelItem
   * ───────────────────────────────────────────────────────────── */

  function normalizeIntelItem(raw) {
    if (!raw || typeof raw !== "object") {
      return _buildEmptyIntelItem();
    }

    const sevNorm     = normalizeSeverity(_str(raw.severity));
    const sevColors   = getSeverityColors(sevNorm);
    const riskScore   = formatRiskScore(raw.risk_score);
    const epss        = formatEpssScore(raw.epss_score);
    const cvss        = formatCvssScore(raw.cvss_score);
    const ttps        = adaptTtps(_arr(raw.ttps));
    const mitreTacs   = adaptTtps(_arr(raw.mitre_tactics));
    const apexAi      = adaptApexAi(_obj(raw.apex_ai));
    const apex        = adaptApex(_obj(raw.apex));
    const iocPaywall  = adaptIocPaywall(_obj(raw.ioc_paywall));
    const valStatus   = normalizeValidationStatus(_str(raw.validation_status));
    const sourceHost  = extractHostname(_str(raw.source_url));

    return {
      /* ─── CORE IDENTITY ─── */
      id:                  _str(raw.id || raw.stix_id, "unknown--" + Math.random().toString(36).slice(2)),
      stix_id:             _str(raw.stix_id, ""),
      stix_id_short:       formatStixId(_str(raw.stix_id, "")),
      title:               _str(raw.title, "Untitled Intelligence Report"),
      description:         _str(raw.description, ""),
      threat_type:         _str(raw.threat_type, "Threat Intelligence"),
      tags:                _arr(raw.tags),

      /* ─── SEVERITY ─── */
      severity:            sevNorm,
      severity_colors:     sevColors,

      /* ─── RISK SCORING ─── */
      risk_score:          riskScore,
      confidence:          _num(raw.confidence, 0),
      confidence_display:  _num(raw.confidence, 0).toFixed(1) + "%",

      /* ─── EXPLOIT SCORING ─── */
      epss_score:          epss,
      cvss_score:          cvss,
      has_epss:            epss !== null,
      has_cvss:            cvss !== null,

      /* ─── THREAT INTEL ─── */
      actor_tag:           _str(raw.actor_tag, "UNKNOWN"),
      ioc_count:           _int(raw.ioc_count, 0),
      ioc_confidence:      _num(raw.ioc_confidence, 0),
      ioc_threat_level:    _str(raw.ioc_threat_level, "LOW"),
      ttps:                ttps,
      ttp_count:           _int(raw.ttp_count, ttps.length),
      mitre_tactics:       mitreTacs,
      kev_present:         _bool(raw.kev_present, false),

      /* ─── IOC PAYWALL ─── */
      ioc_paywall:         iocPaywall,

      /* ─── TIMELINE ─── */
      published_at:        _str(raw.published_at, ""),
      published_at_fmt:    formatTimestamp(_str(raw.published_at, "")),
      published_at_rel:    relativeTime(_str(raw.published_at, "")),
      processed_at:        _str(raw.processed_at, ""),
      processed_at_fmt:    formatTimestamp(_str(raw.processed_at, "")),
      processed_at_rel:    relativeTime(_str(raw.processed_at, "")),
      timestamp:           _str(raw.timestamp, ""),
      timestamp_fmt:       formatTimestamp(_str(raw.timestamp, "")),

      /* ─── SOURCE ─── */
      source:              _str(raw.source, "Unknown Source"),
      source_url:          _str(raw.source_url, "#"),
      source_host:         sourceHost || _str(raw.source, "Unknown"),
      report_url:          _str(raw.report_url, "#"),
      stix_bundle_url:     _str(raw.stix_bundle, ""),

      /* ─── APEX AI INTELLIGENCE ─── */
      apex_ai:             apexAi,

      /* ─── APEX CORE ─── */
      apex:                apex,

      /* ─── SYSTEM ─── */
      validation_status:   valStatus,
      stix_object_count:   _int(raw.stix_object_count, 0),

      /* ─── COMPUTED CONVENIENCE FLAGS ─── */
      is_high_priority:    sevNorm === "CRITICAL" || sevNorm === "HIGH" || apexAi.soc_priority === "P1" || apexAi.soc_priority === "P2",
      paywall_active:      iocPaywall.locked || apexAi.paywall.locked_fields.length > 0,
      has_ai_intel:        apexAi.ai_summary !== "Intelligence summary unavailable.",
      has_ttps:            ttps.length > 0 || mitreTacs.length > 0,
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  EMPTY INTEL ITEM — safe fallback for malformed data
   * ───────────────────────────────────────────────────────────── */

  function _buildEmptyIntelItem() {
    return normalizeIntelItem({
      id: "error--" + Date.now(),
      stix_id: "",
      title: "⚠ Data Parse Error",
      severity: "LOW",
      risk_score: 0,
      confidence: 0,
      threat_type: "Unknown",
      actor_tag: "UNKNOWN",
      ioc_count: 0,
      ttp_count: 0,
      ttps: [],
      mitre_tactics: [],
      source: "Unknown",
      validation_status: "invalid",
      stix_object_count: 0,
    });
  }

  /* ─────────────────────────────────────────────────────────────
   *  BATCH ADAPTER — normalizes full API preview response
   * ───────────────────────────────────────────────────────────── */

  function normalizeApiResponse(apiResponse) {
    if (!apiResponse || typeof apiResponse !== "object") {
      return _buildEmptyResponse();
    }

    // Support both direct items array and nested preview structure
    const preview = _obj(apiResponse.preview);
    const rawItems = _arr(preview.items || apiResponse.items || []);

    const items = rawItems.map(function (item, idx) {
      try {
        return normalizeIntelItem(item);
      } catch (e) {
        console.warn("[SentinelApexAdapter] Failed to normalize item " + idx + ":", e);
        return _buildEmptyIntelItem();
      }
    });

    return {
      status:          _str(apiResponse.status, "unknown"),
      gateway:         _str(apiResponse.gateway, "SENTINEL-APEX"),
      request_id:      _str(apiResponse.request_id, ""),
      items:           items,
      total_preview:   _int(preview.total_preview || items.length, items.length),
      total_in_feed:   _int(preview.total_in_feed, items.length),
      generated_at:    _str(preview.generated_at, ""),
      generated_at_fmt: formatTimestamp(_str(preview.generated_at, "")),
      note:            _str(preview.note, ""),
      get_api_key_url: _str(apiResponse.get_api_key, "/upgrade.html"),
      docs_url:        _str(apiResponse.docs, "/api-docs.html"),
      cached:          _bool(apiResponse.cached, false),
      // Stats for header display
      stats: _computeStats(items),
    };
  }

  function _buildEmptyResponse() {
    return {
      status: "error", gateway: "SENTINEL-APEX", request_id: "",
      items: [], total_preview: 0, total_in_feed: 0,
      generated_at: "", generated_at_fmt: "—", note: "", cached: false,
      get_api_key_url: "/upgrade.html", docs_url: "/api-docs.html",
      stats: _computeStats([]),
    };
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
      by_severity:     counts,
      total:           items.length,
      avg_risk:        (totalRisk / n).toFixed(1),
      avg_confidence:  (totalConf / n).toFixed(1),
      total_iocs:      totalIocs,
      high_priority:   items.filter(function (i) { return i.is_high_priority; }).length,
      paywall_items:   items.filter(function (i) { return i.paywall_active; }).length,
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  SAFE FETCH — with timeout, retry, and fallback
   * ───────────────────────────────────────────────────────────── */

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
          cache: "no-store",
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const json = await resp.json();
        return { data: json, error: null, cached: false };
      } catch (err) {
        lastErr = err;
        if (attempt < maxRetry) {
          await new Promise(function (r) { setTimeout(r, baseMs * Math.pow(2, attempt)); });
        }
      }
    }

    // Fallback: try session-cached data
    try {
      const cacheKey = "sapx_feed_" + btoa(url).substring(0, 32);
      const cached = sessionStorage.getItem(cacheKey);
      if (cached) {
        return { data: JSON.parse(cached), error: null, cached: true };
      }
    } catch (e) { /* non-fatal */ }

    return { data: null, error: lastErr, cached: false };
  }

  /* ─────────────────────────────────────────────────────────────
   *  FETCH AND NORMALIZE — combined convenience method
   * ───────────────────────────────────────────────────────────── */

  async function fetchAndNormalize(url, options) {
    const result = await safeFetch(url, options);
    if (!result.data) {
      return {
        normalized: _buildEmptyResponse(),
        raw: null,
        error: result.error,
        cached: false,
      };
    }
    // Cache on success
    try {
      const cacheKey = "sapx_feed_" + btoa(url).substring(0, 32);
      sessionStorage.setItem(cacheKey, JSON.stringify(result.data));
    } catch (e) { /* non-fatal */ }

    return {
      normalized: normalizeApiResponse(result.data),
      raw: result.data,
      error: null,
      cached: result.cached,
    };
  }

  /* ─────────────────────────────────────────────────────────────
   *  PUBLIC API
   * ───────────────────────────────────────────────────────────── */

  return {
    // Core normalizers
    normalizeIntelItem:     normalizeIntelItem,
    normalizeApiResponse:   normalizeApiResponse,

    // Fetch helpers
    safeFetch:              safeFetch,
    fetchAndNormalize:      fetchAndNormalize,

    // Utility formatters (exported for card renderer use)
    normalizeSeverity:      normalizeSeverity,
    getSeverityColors:      getSeverityColors,
    getSocPriorityMeta:     getSocPriorityMeta,
    normalizeSocPriority:   normalizeSocPriority,
    formatTimestamp:        formatTimestamp,
    relativeTime:           relativeTime,
    formatRiskScore:        formatRiskScore,
    formatEpssScore:        formatEpssScore,
    formatCvssScore:        formatCvssScore,
    normalizeConfidenceTier: normalizeConfidenceTier,
    extractHostname:        extractHostname,
    formatStixId:           formatStixId,

    // Version
    VERSION: "143.0.0",
    BUILD:   "SENTINEL-APEX-ADAPTER-PROD",
  };

}); // end factory

// Auto-register availability signal
if (typeof window !== "undefined") {
  window.dispatchEvent(new CustomEvent("SentinelApexAdapterReady", {
    detail: { version: "143.0.0" }
  }));
}
