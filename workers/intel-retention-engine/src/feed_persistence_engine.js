/**
 * feed_persistence_engine.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
 * Feed Persistence Engine
 * ========================
 * Ensures every pipeline run ADDS to the intelligence corpus.
 * No advisory is ever lost because of a newer workflow execution.
 *
 * Pipeline contract:
 *   1. ingest(newItems)      — validate + fingerprint new feed
 *   2. deduplicate(items)    — remove exact duplicates
 *   3. merge(items, repo)    — merge into persistent repository
 *   4. updateIndexes()       — rebuild dashboard indexes
 *   5. preserveHistory()     — snapshot current run state
 *
 * STRICTLY FORBIDDEN:
 *   - overwrite() on repository
 *   - delete() on any advisory
 *   - truncate() on repository
 *   - reset() on dashboard history
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

import { DedupeEngine, dedupeHash } from "./dedupe_engine.js";
import { RetentionPolicyEngine, STATE } from "./retention_policy_engine.js";

// ── Validation rules ──────────────────────────────────────────────────────
const REQUIRED_FIELDS = ["title"];
const MIN_ITEMS = 0; // Allow empty feeds (don't hard-fail CI on empty runs)

function validateItem(item) {
  if (!item || typeof item !== "object") return { valid: false, reason: "not_object" };
  for (const field of REQUIRED_FIELDS) {
    if (!item[field]) return { valid: false, reason: `missing_${field}` };
  }
  if (String(item.title || "").length < 3) return { valid: false, reason: "title_too_short" };
  return { valid: true, reason: null };
}

class FeedPersistenceEngine {
  /**
   * @param {Object} options
   * @param {Object} options.retentionRegistry - existing retention registry from disk
   * @param {Object} options.historyRegistry   - existing historical feed registry from disk
   */
  constructor(options = {}) {
    this.dedupe   = new DedupeEngine();
    this.policy   = new RetentionPolicyEngine();
    this.runTs    = new Date().toISOString();
    this.runId    = `run-${Date.now()}`;

    // Seed dedupe engine from existing registry (prevents re-ingesting known items)
    if (options.retentionRegistry) {
      this.dedupe.seedFromRegistry(options.retentionRegistry);
    }

    this.stats = {
      run_id:         this.runId,
      run_ts:         this.runTs,
      ingested:       0,
      validated:      0,
      invalid:        0,
      new_accepted:   0,
      duplicates:     0,
      retention_applied: 0,
      merged:         0,
      errors:         [],
    };
  }

  /**
   * Step 1: Ingest and validate a raw feed array.
   * @param {Array} rawItems
   * @returns {Array} validated items
   */
  ingest(rawItems) {
    this.stats.ingested = Array.isArray(rawItems) ? rawItems.length : 0;
    if (!Array.isArray(rawItems)) {
      this.stats.errors.push("ingest: rawItems is not an array");
      return [];
    }

    const valid = [];
    for (const item of rawItems) {
      const check = validateItem(item);
      if (check.valid) {
        valid.push(item);
        this.stats.validated++;
      } else {
        this.stats.invalid++;
      }
    }

    return valid;
  }

  /**
   * Step 2: Deduplicate items.
   * @param {Array} validatedItems
   * @returns {{ newItems: Array, duplicates: Array }}
   */
  deduplicate(validatedItems) {
    const result = this.dedupe.filter(validatedItems);
    this.stats.new_accepted = result.accepted.length;
    this.stats.duplicates   = result.rejected.length;
    return { newItems: result.accepted, duplicates: result.rejected };
  }

  /**
   * Step 3: Apply retention policy to new items.
   * @param {Array} newItems
   * @returns {Array} items enriched with retention_meta
   */
  applyRetention(newItems) {
    const enriched = this.policy.applyBatch(newItems);
    this.stats.retention_applied = enriched.length;
    return enriched;
  }

  /**
   * Step 4: Merge new items into the persistent repository.
   * NEVER overwrites existing entries.
   *
   * @param {Array}  newItems   - new items (already deduped + retention applied)
   * @param {Object} repository - existing repository {advisories: {id: meta}, total: N}
   * @returns {Object} updated repository (new entries appended)
   */
  merge(newItems, repository) {
    const repo = repository || { advisories: {}, total: 0, last_updated: null };

    if (!repo.advisories) repo.advisories = {};

    let mergedCount = 0;
    for (const item of newItems) {
      const intelId = item._intel_id || item.stix_id || item.id || ("intel--" + dedupeHash(item));

      // NEVER overwrite an existing entry — append only
      if (repo.advisories[intelId]) {
        // Only update last_seen
        repo.advisories[intelId].last_seen = this.runTs;
        continue;
      }

      repo.advisories[intelId] = {
        intel_id:       intelId,
        title:          String(item.title || "").slice(0, 500),
        severity:       String(item.severity || "MEDIUM").toUpperCase(),
        risk_score:     parseFloat(item.risk_score || 5.0),
        confidence:     parseFloat(item.confidence || 50),
        source:         String(item.source || "SENTINEL_APEX").slice(0, 100),
        source_url:     String(item.source_url || item.link || ""),
        blog_url:       String(item.blog_url || ""),
        published_at:   String(item.published_at || item.timestamp || this.runTs),
        created_at:     String(item.published_at || item.timestamp || this.runTs),
        last_seen:      this.runTs,
        tags:           Array.isArray(item.tags) ? item.tags.slice(0, 20) : [],
        actor_tag:      String(item.actor_tag || ""),
        is_kev:         Boolean(item.is_kev || item.kev),
        lifecycle_state: item.retention_meta?.lifecycle_state || STATE.ACTIVE,
        retention_until: item.retention_meta?.retention_until || null,
        is_permanent:   item.retention_meta?.is_permanent || false,
        dedupe_hash:    item._dedupe_hash || dedupeHash(item),
      };
      mergedCount++;
    }

    repo.total        = Object.keys(repo.advisories).length;
    repo.last_updated = this.runTs;
    repo.last_run_id  = this.runId;

    this.stats.merged = mergedCount;
    return repo;
  }

  /**
   * Step 5: Build updated dashboard index from repository.
   * Dashboard reads this — NEVER the raw feed.
   *
   * @param {Object} repository
   * @param {Object} existingIndex - previous index (accumulate, never reset)
   * @returns {Object} updated dashboard index
   */
  updateDashboardIndex(repository, existingIndex) {
    const advisories = Object.values(repository.advisories || {});
    const total      = advisories.length;

    const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
    const stateCounts = { [STATE.ACTIVE]: 0, [STATE.MONITORING]: 0, [STATE.ARCHIVED]: 0 };
    let kevCount = 0;
    let permCount = 0;

    for (const adv of advisories) {
      const sev = String(adv.severity || "UNKNOWN").toUpperCase();
      if (sev in sevCounts) sevCounts[sev]++; else sevCounts.UNKNOWN++;
      const state = adv.lifecycle_state || STATE.ACTIVE;
      if (state in stateCounts) stateCounts[state]++;
      if (adv.is_kev) kevCount++;
      if (adv.is_permanent) permCount++;
    }

    return {
      schema_version:  "2.0.0",
      generated_at:    this.runTs,
      last_run:        this.runTs,
      repository: {
        total_advisories: total,
        severity_breakdown: sevCounts,
        lifecycle_breakdown: stateCounts,
        kev_count: kevCount,
        permanent_count: permCount,
      },
      dashboard: {
        // These are the STABLE values the dashboard should display
        total_advisories:    total,
        critical_advisories: sevCounts.CRITICAL,
        high_advisories:     sevCounts.HIGH,
        kev_advisories:      kevCount,
        permanent_advisories: permCount,
        data_source:         "intelligence_repository",
        note:                "Cumulative totals — stable across pipeline runs",
        // Previous run preserved for trend tracking
        previous_total:      existingIndex?.repository?.total_advisories || 0,
      },
      feed_history: {
        total_runs:   (existingIndex?.feed_history?.total_runs || 0) + 1,
        last_run:     this.runTs,
        last_new_count: this.stats.new_accepted,
      },
    };
  }

  /**
   * Step 6: Record this run in the historical feed registry.
   * @param {Object} historyRegistry - existing registry from disk
   * @param {Object} feedInfo        - {feed_count, apex_count, latest_count}
   * @returns {Object} updated registry
   */
  recordRun(historyRegistry, feedInfo = {}) {
    const reg = historyRegistry || { runs: [], total_runs: 0 };
    if (!Array.isArray(reg.runs)) reg.runs = [];

    reg.runs.push({
      run_id:        this.runId,
      run_ts:        this.runTs,
      new_items:     this.stats.new_accepted,
      duplicates:    this.stats.duplicates,
      feed_count:    feedInfo.feed_count || 0,
      apex_count:    feedInfo.apex_count || 0,
      errors:        this.stats.errors.length,
      pipeline_step: "feed_persistence_engine",
    });

    // Keep last 1000 run records
    if (reg.runs.length > 1000) {
      reg.runs = reg.runs.slice(-1000);
    }

    reg.total_runs     = reg.runs.length;
    reg.last_run       = this.runTs;
    reg.last_run_id    = this.runId;
    reg.cumulative_new = (reg.cumulative_new || 0) + this.stats.new_accepted;

    return reg;
  }

  /**
   * Full pipeline: ingest -> dedupe -> apply retention -> merge -> update index.
   * @param {Array}  rawItems     - new feed items from pipeline
   * @param {Object} repository   - existing repository from disk
   * @param {Object} dashIndex    - existing dashboard index from disk
   * @param {Object} histRegistry - existing run history from disk
   * @param {Object} feedInfo     - {feed_count, apex_count}
   * @returns {{ repository, dashboardIndex, historyRegistry, stats }}
   */
  run(rawItems, repository, dashIndex, histRegistry, feedInfo = {}) {
    // 1. Validate
    const validated = this.ingest(rawItems);

    // 2. Deduplicate
    const { newItems } = this.deduplicate(validated);

    // 3. Retention policy
    const enriched = this.applyRetention(newItems);

    // 4. Merge into repository
    const updatedRepo = this.merge(enriched, repository);

    // 5. Update dashboard index
    const updatedIndex = this.updateDashboardIndex(updatedRepo, dashIndex);

    // 6. Record run
    const updatedHistory = this.recordRun(histRegistry, feedInfo);

    return {
      repository:      updatedRepo,
      dashboardIndex:  updatedIndex,
      historyRegistry: updatedHistory,
      stats:           this.getStats(),
    };
  }

  getStats() {
    return {
      ...this.stats,
      dedupe_stats:    this.dedupe.getStats(),
      retention_stats: this.policy.getStats(),
    };
  }
}

export { FeedPersistenceEngine };
