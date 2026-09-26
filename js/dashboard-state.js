/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — Dashboard Truth Contract: Canonical State Vocabulary v1.0.0
 *
 *  Phase 1 deliverable of the Dashboard Truth Contract mission (see
 *  DASHBOARD_TRUTH_CONTRACT_PHASE0_FORENSIC_CENSUS.md at the repo root for the
 *  full forensic evidence this vocabulary is built from).
 *
 *  PURELY ADDITIVE. This module is not imported by index.html, js/api_adapter.js,
 *  js/card_renderer.js, or any CI workflow. It has zero side effects and cannot
 *  change production behavior. It exists so a future canonical normalizer
 *  (Phase 2+, not part of this PR) has one place to import a state vocabulary
 *  from, instead of every rendering surface inventing its own ad hoc
 *  true/false/''/null collapse of a real, multi-valued backend state.
 *
 *  The forensic census found NO canonical state-machine implementation
 *  anywhere in the codebase: report/publication state is inferred from
 *  report_url presence/absence at 6 independently-coded call sites in
 *  index.html, freshness state is computed with 6+ mutually disagreeing
 *  threshold definitions across workers/intel-gateway/src/p18/p29/p30/p35/
 *  p40-handlers.js, and a correctly-canonical freshness function
 *  (js/api_adapter.js freshnessIndicator()) is computed and attached to every
 *  item but never read by any renderer. This module defines the target
 *  vocabulary; it does not itself close any of those gaps.
 *
 *  Relationship to existing contract files (do not duplicate their role):
 *    - js/dashboard_contract_validator.js validates the SHAPE of an already-
 *      normalized card item (required fields, a few value enums). It does not
 *      define lifecycle/publication/freshness STATES. This module does.
 *    - scripts/api_dashboard_contract_validator.py + dashboard_contract.json
 *      is the validator actually wired into CI (sentinel-blogger.yml,
 *      deploy-worker.yml, sync-dashboard.yml) and checks per-zone field
 *      presence only, no value-domain or state semantics.
 * ═══════════════════════════════════════════════════════════════════════════════
 */
"use strict";

(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelApexDashboardState = factory();
  }
})(typeof window !== "undefined" ? window : this, function () {

  const CONTRACT_VERSION = "1.0.0";

  /**
   * Zero-fabrication sentinels (mission Phase 10). A future normalizer should
   * import these instead of ad hoc '', null, '—', or 'PROCESSING' strings, so
   * "we don't know" and "we know it's absent" stay textually distinguishable
   * from a real value everywhere in the codebase.
   */
  const SENTINELS = Object.freeze({
    UNKNOWN: "UNKNOWN",         // the field's true value cannot currently be determined
    UNAVAILABLE: "UNAVAILABLE", // the field's true value is known to not exist / not apply
    NOT_PROVIDED: "NOT_PROVIDED" // the backend contract does not supply this field at all
  });

  /**
   * The 12 canonical states (mission Phase 5 / Phase 6). Every state carries:
   *   value           - the machine-readable enum value
   *   label           - customer-visible short label
   *   explanation     - one-sentence customer-visible explanation of what it means
   *   severity        - "neutral" | "info" | "warning" | "critical" (for badge styling)
   *   aria            - screen-reader text; must not rely on color alone
   *   telemetryEvent  - the event name a future observability layer should emit
   *                     on transition into this state (mission Phase 15/16)
   *
   * These states intentionally span two different concerns that today's
   * codebase conflates (mission background, confirmed live by the census):
   *   - data freshness   : LIVE, FRESH, STALE, DEGRADED
   *   - publication/report lifecycle : PROCESSING, PUBLISHED, WITHHELD,
   *                                    BLOCKED, REJECTED, UNAVAILABLE
   *   - cross-cutting    : ERROR, UNKNOWN
   * A given card can be in exactly one freshness state AND exactly one
   * lifecycle state simultaneously -- they are not mutually exclusive with
   * each other, only within their own group. Grouping is documented per
   * entry below so a future normalizer does not conflate them the way
   * cdbBuildReportUrl() currently conflates "no URL yet" with "processing".
   */
  const STATES = Object.freeze({
    LIVE: Object.freeze({
      value: "LIVE", group: "freshness",
      label: "Live",
      explanation: "Reflects the most recent successful data synchronization.",
      severity: "info",
      aria: "Live data, up to date",
      telemetryEvent: "state_transition:freshness:live"
    }),
    FRESH: Object.freeze({
      value: "FRESH", group: "freshness",
      label: "Recent",
      explanation: "Synchronized recently and within the acceptable freshness window.",
      severity: "neutral",
      aria: "Recently synchronized data",
      telemetryEvent: "state_transition:freshness:fresh"
    }),
    STALE: Object.freeze({
      value: "STALE", group: "freshness",
      label: "Stale",
      explanation: "Older than the acceptable freshness window; a newer sync has not yet completed.",
      severity: "warning",
      aria: "Stale data, warning",
      telemetryEvent: "state_transition:freshness:stale"
    }),
    DEGRADED: Object.freeze({
      value: "DEGRADED", group: "freshness",
      label: "Degraded",
      explanation: "The platform is serving cached or partial data because a live source is currently unavailable.",
      severity: "critical",
      aria: "Degraded data, reduced reliability",
      telemetryEvent: "state_transition:freshness:degraded"
    }),
    PROCESSING: Object.freeze({
      value: "PROCESSING", group: "lifecycle",
      label: "Processing",
      explanation: "This item has not yet completed enrichment or certification. It may become available shortly.",
      severity: "neutral",
      aria: "Processing, not yet available",
      telemetryEvent: "state_transition:lifecycle:processing"
    }),
    PUBLISHED: Object.freeze({
      value: "PUBLISHED", group: "lifecycle",
      label: "Published",
      explanation: "This item has passed all quality and certification gates and is customer-ready.",
      severity: "info",
      aria: "Published and customer-ready",
      telemetryEvent: "state_transition:lifecycle:published"
    }),
    WITHHELD: Object.freeze({
      value: "WITHHELD", group: "lifecycle",
      label: "Withheld",
      explanation: "This item exists but has not yet met the evidence bar required for publication.",
      severity: "warning",
      aria: "Withheld pending further evidence",
      telemetryEvent: "state_transition:lifecycle:withheld"
    }),
    BLOCKED: Object.freeze({
      value: "BLOCKED", group: "lifecycle",
      label: "Blocked",
      explanation: "This item is currently blocked by a governance or certification check and is not publishable in its present form.",
      severity: "warning",
      aria: "Blocked by a governance check",
      telemetryEvent: "state_transition:lifecycle:blocked"
    }),
    REJECTED: Object.freeze({
      value: "REJECTED", group: "lifecycle",
      label: "Rejected",
      explanation: "This item did not meet the certification bar and will not be published.",
      severity: "critical",
      aria: "Rejected, will not be published",
      telemetryEvent: "state_transition:lifecycle:rejected"
    }),
    UNAVAILABLE: Object.freeze({
      value: "UNAVAILABLE", group: "lifecycle",
      label: "Unavailable",
      explanation: "No verified resource currently exists for this item.",
      severity: "neutral",
      aria: "Unavailable, no verified resource",
      telemetryEvent: "state_transition:lifecycle:unavailable"
    }),
    ERROR: Object.freeze({
      value: "ERROR", group: "cross-cutting",
      label: "Error",
      explanation: "State could not be determined because a request or processing step failed.",
      severity: "critical",
      aria: "Error determining state",
      telemetryEvent: "state_transition:cross-cutting:error"
    }),
    UNKNOWN: Object.freeze({
      value: "UNKNOWN", group: "cross-cutting",
      label: "Unknown",
      explanation: "The true state of this item cannot currently be determined from available data.",
      severity: "neutral",
      aria: "Unknown state",
      telemetryEvent: "state_transition:cross-cutting:unknown"
    })
  });

  const STATE_VALUES = Object.freeze(Object.keys(STATES));

  function isValidState(value) {
    return typeof value === "string" && Object.prototype.hasOwnProperty.call(STATES, value);
  }

  function getState(value) {
    return isValidState(value) ? STATES[value] : STATES.UNKNOWN;
  }

  /**
   * Documents (does not execute) how a future backend `publication_status`
   * field -- once exposed on the public feed manifests, per the census
   * finding that evaluatePublicationGate()'s classification is today
   * computed and then discarded before the response is built (index.js:656
   * vs :701) -- would map onto the lifecycle group above. Not wired to any
   * live call; provided so Phase 2's normalizer has an agreed mapping to
   * implement rather than inventing one at migration time.
   * @param {string} publicationStatus - e.g. "CUSTOMER_READY" | "WITHHELD" |
   *   "REJECTED" | "PENDING_ENRICHMENT" | "NOT_EVALUATED" (certification-registry.js)
   * @returns {string} one of STATE_VALUES
   */
  function mapPublicationGateResult(publicationStatus) {
    switch (publicationStatus) {
      case "CUSTOMER_READY": return STATES.PUBLISHED.value;
      case "WITHHELD": return STATES.WITHHELD.value;
      case "REJECTED": return STATES.REJECTED.value;
      case "PENDING_ENRICHMENT": return STATES.PROCESSING.value;
      case "NOT_EVALUATED": return STATES.UNKNOWN.value;
      default: return STATES.UNKNOWN.value;
    }
  }

  return {
    VERSION: CONTRACT_VERSION,
    SENTINELS: SENTINELS,
    STATES: STATES,
    STATE_VALUES: STATE_VALUES,
    isValidState: isValidState,
    getState: getState,
    mapPublicationGateResult: mapPublicationGateResult
  };

});
