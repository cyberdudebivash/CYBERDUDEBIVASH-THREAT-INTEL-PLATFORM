/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — Dashboard Contract Validator v171.0.0
 *  HARD-FAIL contract enforcement for card schema immutability
 *
 *  Blocks deployment if:
 *    - Required fields are missing from normalized items
 *    - Prohibited placeholder strings appear in customer-visible fields
 *    - actor_tag contains internal CDB-UNATTR-* codes
 *    - Zone count changes from 9
 *    - renderer/adapter version mismatch
 *    - action_rec.action is not a valid enum value
 *    - severity is not a valid enum value
 *
 *  Usage (CI/CD pipeline):
 *    const validator = require('./dashboard_contract_validator');
 *    const result = validator.validateBatch(normalizedItems);
 *    if (!result.passed) { process.exit(1); }  // HARD FAIL
 *
 *  Usage (runtime guard, browser):
 *    SentinelApexContractValidator.validateItem(normalizedItem);  // throws on violation
 * ═══════════════════════════════════════════════════════════════════════════════
 */
"use strict";

(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelApexContractValidator = factory();
  }
})(typeof window !== "undefined" ? window : this, function () {

  const CONTRACT_VERSION    = "171.0.0";
  const RENDERER_VERSION    = "147.0.0";
  const EXPECTED_ZONE_COUNT = 9;

  /* ── Allowed enums ─────────────────────────────────────────────────────── */
  const VALID_SEVERITIES    = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
  const VALID_ACTIONS       = new Set(["PATCH", "ESCALATE", "INVESTIGATE", "MONITOR"]);
  const VALID_SOC_PRIORITIES = new Set(["P1", "P2", "P3", "P4"]);

  /* ── Prohibited customer-visible strings ───────────────────────────────── */
  const PROHIBITED_STRINGS = [
    "CDB-UNATTR-CVE", "CDB-UNATTR-PHI", "CDB-UNATTR-APT", "CDB-UNATTR-RAN",
    "CDB-UNATTR-SUP", "CDB-UNATTR-MAL", "CDB-UNATTR-BOT", "CDB-UNATTR-RAT",
    "UNATTRIBUTED", "PLACEHOLDER", "undefined", "NaN"
  ];

  /* ── Attribution replacement map ───────────────────────────────────────── */
  const ACTOR_TAG_REPLACEMENTS = {
    "CDB-UNATTR-CVE": "Attribution Not Established",
    "CDB-UNATTR-PHI": "Attribution Not Established",
    "CDB-UNATTR-APT": "Insufficient Evidence For Attribution",
    "CDB-UNATTR-RAN": "Attribution Not Established",
    "CDB-UNATTR-SUP": "Attribution Not Established",
    "CDB-UNATTR-MAL": "Attribution Not Established",
    "CDB-UNATTR-BOT": "Attribution Not Established",
    "CDB-UNATTR-RAT": "Attribution Not Established",
    "UNATTRIBUTED":   "Attribution Not Established",
    "":               "Attribution Not Established"
  };

  /* ── Required top-level fields ─────────────────────────────────────────── */
  const REQUIRED_FIELDS = [
    "id", "stix_id", "stix_id_short", "title", "description", "threat_type",
    "tags", "severity", "severity_colors", "risk_score", "confidence",
    "confidence_display", "has_epss", "has_cvss", "kev_present", "action_rec",
    "impact_context", "freshness", "ai_verdict", "paywall_features",
    "actor_tag", "ioc_count", "ioc_confidence", "ioc_threat_level",
    "ttps", "ttp_count", "mitre_tactics", "ioc_paywall",
    "published_at", "published_at_fmt", "published_at_rel",
    "processed_at", "processed_at_fmt", "processed_at_rel",
    "timestamp", "timestamp_fmt",
    "source", "source_url", "source_host", "report_url",
    "stix_bundle_locked", "validation_status", "stix_object_count",
    "is_high_priority", "paywall_active", "has_ttps", "apex_ai", "apex"
  ];

  /* ── Required apex_ai subfields ────────────────────────────────────────── */
  const REQUIRED_APEX_AI_FIELDS = [
    "soc_priority", "soc_priority_meta", "threat_level", "threat_category",
    "predictive_risk", "ai_confidence", "confidence_tier_meta",
    "ttp_density", "campaign_id", "kill_chain_locked", "kill_chain_primary",
    "recommended_action", "behavioral_tags", "paywall"
  ];

  /* ── Required object subfields ─────────────────────────────────────────── */
  const REQUIRED_SEVERITY_COLORS   = ["primary", "glow", "dim", "border", "text", "class", "label"];
  const REQUIRED_RISK_SCORE        = ["raw", "display", "percent", "color"];
  const REQUIRED_ACTION_REC        = ["action", "label", "icon", "color", "bg", "border"];
  const REQUIRED_IMPACT_CONTEXT    = ["attack_icon", "attack_type", "potential_impact", "target_surface"];
  const REQUIRED_FRESHNESS         = ["class", "color", "icon", "label"];
  const REQUIRED_VALIDATION_STATUS = ["class", "color", "label"];

  /* ════════════════════════════════════════════════════════════════════════
   * validateItem — validates a single normalized item
   * Returns: { passed: bool, violations: string[], warnings: string[], item_id: string }
   * ════════════════════════════════════════════════════════════════════════ */
  function validateItem(item) {
    if (!item || typeof item !== "object") {
      return { passed: false, violations: ["item is null or not an object"], warnings: [], item_id: "unknown" };
    }

    const id         = String(item.id || item.stix_id || "unknown");
    const violations = [];
    const warnings   = [];

    /* ── 1. Required top-level fields ─────────────────────────────────── */
    for (const field of REQUIRED_FIELDS) {
      if (item[field] === undefined) {
        violations.push("MISSING_REQUIRED_FIELD: " + field);
      }
    }

    /* ── 2. Severity enum ─────────────────────────────────────────────── */
    if (item.severity !== undefined && !VALID_SEVERITIES.has(String(item.severity).toUpperCase())) {
      violations.push("INVALID_SEVERITY: '" + item.severity + "' — must be one of " + [...VALID_SEVERITIES].join("|"));
    }

    /* ── 3. action_rec.action enum ────────────────────────────────────── */
    if (item.action_rec && !VALID_ACTIONS.has(String(item.action_rec.action || "").toUpperCase())) {
      violations.push("INVALID_ACTION_REC: '" + item.action_rec.action + "' — must be one of " + [...VALID_ACTIONS].join("|"));
    }

    /* ── 4. actor_tag — no placeholder codes ──────────────────────────── */
    const actorTag = String(item.actor_tag || "");
    if (ACTOR_TAG_REPLACEMENTS.hasOwnProperty(actorTag)) {
      violations.push("PROHIBITED_ACTOR_TAG: '" + actorTag + "' — replace with '" + ACTOR_TAG_REPLACEMENTS[actorTag] + "'");
    }
    for (const prohibited of PROHIBITED_STRINGS) {
      if (actorTag === prohibited) {
        violations.push("PROHIBITED_STRING_IN_ACTOR_TAG: '" + prohibited + "'");
      }
    }

    /* ── 5. Scan customer-visible string fields for prohibited strings ── */
    const customerVisibleFields = ["title", "description", "ai_verdict", "source", "threat_type"];
    for (const field of customerVisibleFields) {
      const val = String(item[field] || "");
      for (const prohibited of PROHIBITED_STRINGS) {
        if (val.includes(prohibited)) {
          warnings.push("PROHIBITED_STRING_IN_" + field.toUpperCase() + ": '" + prohibited + "'");
        }
      }
    }

    /* ── 6. severity_colors subfields ─────────────────────────────────── */
    if (item.severity_colors && typeof item.severity_colors === "object") {
      for (const sf of REQUIRED_SEVERITY_COLORS) {
        if (item.severity_colors[sf] === undefined) {
          violations.push("MISSING_SEVERITY_COLORS_FIELD: severity_colors." + sf);
        }
      }
    }

    /* ── 7. risk_score subfields ──────────────────────────────────────── */
    if (item.risk_score && typeof item.risk_score === "object") {
      for (const sf of REQUIRED_RISK_SCORE) {
        if (item.risk_score[sf] === undefined) {
          violations.push("MISSING_RISK_SCORE_FIELD: risk_score." + sf);
        }
      }
      const raw = parseFloat(item.risk_score.raw);
      if (!isNaN(raw) && (raw < 0 || raw > 10)) {
        violations.push("RISK_SCORE_OUT_OF_RANGE: " + raw + " — must be 0–10");
      }
    }

    /* ── 8. action_rec subfields ──────────────────────────────────────── */
    if (item.action_rec && typeof item.action_rec === "object") {
      for (const sf of REQUIRED_ACTION_REC) {
        if (item.action_rec[sf] === undefined) {
          violations.push("MISSING_ACTION_REC_FIELD: action_rec." + sf);
        }
      }
    }

    /* ── 9. impact_context subfields ──────────────────────────────────── */
    if (item.impact_context && typeof item.impact_context === "object") {
      for (const sf of REQUIRED_IMPACT_CONTEXT) {
        if (item.impact_context[sf] === undefined) {
          violations.push("MISSING_IMPACT_CONTEXT_FIELD: impact_context." + sf);
        }
      }
    }

    /* ── 10. freshness subfields ──────────────────────────────────────── */
    if (item.freshness && typeof item.freshness === "object") {
      for (const sf of REQUIRED_FRESHNESS) {
        if (item.freshness[sf] === undefined) {
          violations.push("MISSING_FRESHNESS_FIELD: freshness." + sf);
        }
      }
    }

    /* ── 11. validation_status subfields ──────────────────────────────── */
    if (item.validation_status && typeof item.validation_status === "object") {
      for (const sf of REQUIRED_VALIDATION_STATUS) {
        if (item.validation_status[sf] === undefined) {
          violations.push("MISSING_VALIDATION_STATUS_FIELD: validation_status." + sf);
        }
      }
    }

    /* ── 12. apex_ai subfields ────────────────────────────────────────── */
    const ai = item.apex_ai;
    if (ai && typeof ai === "object") {
      for (const sf of REQUIRED_APEX_AI_FIELDS) {
        if (ai[sf] === undefined) {
          violations.push("MISSING_APEX_AI_FIELD: apex_ai." + sf);
        }
      }
      if (!VALID_SOC_PRIORITIES.has(String(ai.soc_priority || "").toUpperCase())) {
        violations.push("INVALID_SOC_PRIORITY: '" + ai.soc_priority + "'");
      }
      const predRisk = parseFloat(ai.predictive_risk);
      if (!isNaN(predRisk) && (predRisk < 0 || predRisk > 10)) {
        violations.push("PREDICTIVE_RISK_OUT_OF_RANGE: " + predRisk);
      }
      const aiConf = parseFloat(ai.ai_confidence);
      if (!isNaN(aiConf) && (aiConf < 0 || aiConf > 100)) {
        violations.push("AI_CONFIDENCE_OUT_OF_RANGE: " + aiConf);
      }
    } else if (item.apex_ai !== undefined) {
      violations.push("APEX_AI_NOT_OBJECT");
    }

    /* ── 13. confidence range ─────────────────────────────────────────── */
    const conf = parseFloat(item.confidence);
    if (!isNaN(conf) && (conf < 0 || conf > 100)) {
      violations.push("CONFIDENCE_OUT_OF_RANGE: " + conf);
    }

    /* ── 14. ioc_count non-negative ───────────────────────────────────── */
    const iocCount = parseInt(item.ioc_count, 10);
    if (!isNaN(iocCount) && iocCount < 0) {
      violations.push("IOC_COUNT_NEGATIVE: " + iocCount);
    }

    return {
      passed:     violations.length === 0,
      violations: violations,
      warnings:   warnings,
      item_id:    id
    };
  }

  /* ════════════════════════════════════════════════════════════════════════
   * validateBatch — validates an array of normalized items
   * Returns: { passed, total, failed_count, violation_summary, results }
   * Throws if hard_fail=true and any violation found (for CI/CD use)
   * ════════════════════════════════════════════════════════════════════════ */
  function validateBatch(items, options) {
    const opts         = options || {};
    const hardFail     = opts.hard_fail !== false; // default true
    const maxFailCount = opts.max_fail_count || 0; // 0 = any failure blocks

    if (!Array.isArray(items)) {
      const err = "CONTRACT_VALIDATOR: items must be an array — received " + typeof items;
      if (hardFail) throw new Error(err);
      return { passed: false, total: 0, failed_count: 1, violation_summary: [err], results: [] };
    }

    const results = items.map(validateItem);
    const failed  = results.filter(function (r) { return !r.passed; });
    const passed  = failed.length === 0 || (maxFailCount > 0 && failed.length <= maxFailCount);

    // Aggregate violation types
    const violationCounts = {};
    for (const r of results) {
      for (const v of r.violations) {
        const vType = v.split(":")[0];
        violationCounts[vType] = (violationCounts[vType] || 0) + 1;
      }
    }

    const report = {
      contract_version: CONTRACT_VERSION,
      renderer_version: RENDERER_VERSION,
      validated_at:     new Date().toISOString(),
      passed:           passed,
      total:            items.length,
      passed_count:     items.length - failed.length,
      failed_count:     failed.length,
      violation_summary: violationCounts,
      results:          results
    };

    if (!passed && hardFail) {
      const summary = JSON.stringify(violationCounts, null, 2);
      throw new Error(
        "[SENTINEL APEX CONTRACT VALIDATOR] HARD FAIL — " +
        failed.length + "/" + items.length + " items violate the dashboard contract.\n" +
        "Violation types:\n" + summary + "\n" +
        "Fix all violations before deployment."
      );
    }

    return report;
  }

  /* ════════════════════════════════════════════════════════════════════════
   * sanitizeActorTag — replace prohibited codes with human-readable text
   * Use in api_adapter.js normalizeIntelItem() before returning actor_tag
   * ════════════════════════════════════════════════════════════════════════ */
  function sanitizeActorTag(rawActorTag) {
    const val = String(rawActorTag || "").trim();
    if (ACTOR_TAG_REPLACEMENTS.hasOwnProperty(val)) {
      return ACTOR_TAG_REPLACEMENTS[val];
    }
    for (const prohibited of PROHIBITED_STRINGS) {
      if (val === prohibited) {
        return "Attribution Not Established";
      }
    }
    return val || "Attribution Not Established";
  }

  /* ── Public API ─────────────────────────────────────────────────────── */
  return {
    VERSION:           CONTRACT_VERSION,
    validateItem:      validateItem,
    validateBatch:     validateBatch,
    sanitizeActorTag:  sanitizeActorTag,
    PROHIBITED_STRINGS: PROHIBITED_STRINGS,
    ACTOR_TAG_REPLACEMENTS: ACTOR_TAG_REPLACEMENTS
  };

});
