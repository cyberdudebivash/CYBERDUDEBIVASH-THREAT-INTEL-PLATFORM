/**
 * retention_engine.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
 * Intelligence Retention Engine — Main Orchestrator
 * ===================================================
 * Top-level orchestrator for the Intel Retention Worker.
 * Coordinates: FeedPersistenceEngine + HistoricalFeedMerger +
 * RepositoryBuilder + RetentionPolicyEngine + DedupeEngine
 *
 * Entry points:
 *   runRetentionCycle(newItems, repoState, options)
 *   getRepositoryStats(repoState)
 *   getDashboardMetrics(repoState)
 *   validateRepository(repoState)
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

import { FeedPersistenceEngine } from "./feed_persistence_engine.js";
import { HistoricalFeedMerger }  from "./historical_feed_merger.js";
import { RepositoryBuilder }     from "./repository_builder.js";
import { RetentionPolicyEngine } from "./retention_policy_engine.js";
import { DedupeEngine }          from "./dedupe_engine.js";

const ENGINE_VERSION = "171.0";

/**
 * Run a full retention cycle for an incoming feed batch.
 *
 * @param {Array}  newItems  - incoming feed items
 * @param {Object} repoState - full repository state from disk:
 *   {
 *     repository, retentionRegistry, lifecycleRegistry,
 *     historyRegistry, dashboardIndex, historicalCorpus
 *   }
 * @param {Object} options   - { feedInfo: {feed_count, apex_count} }
 * @returns {Object} updated state + stats
 */
function runRetentionCycle(newItems, repoState, options = {}) {
  const runTs = new Date().toISOString();

  // ── Phase 1: Feed Persistence ─────────────────────────────────────────────
  const persistence = new FeedPersistenceEngine({
    retentionRegistry: repoState.retentionRegistry,
    historyRegistry:   repoState.historyRegistry,
  });

  const persistResult = persistence.run(
    newItems,
    repoState.repository,
    repoState.dashboardIndex,
    repoState.historyRegistry,
    options.feedInfo || {},
  );

  // ── Phase 2: Historical Corpus Merge ──────────────────────────────────────
  const merger = new HistoricalFeedMerger({
    corpus:  repoState.historicalCorpus,
    history: repoState.history,
  });

  merger.mergeFeed(newItems);
  const mergeResult = merger.finalize();

  // ── Phase 3: Dashboard Index ──────────────────────────────────────────────
  const dashIndex = persistResult.dashboardIndex;

  // Enrich dashboard index with window data
  dashIndex.historical_windows = {};
  for (const [windowKey, windowData] of Object.entries(mergeResult.windows || {})) {
    dashIndex.historical_windows[windowKey] = windowData.count;
  }

  // ── Phase 4: Validation ───────────────────────────────────────────────────
  const integrity = mergeResult.integrity;

  return {
    // Repository state to write back to disk
    repository:         persistResult.repository,
    retentionRegistry:  persistResult.repository?._retentionRegistry || repoState.retentionRegistry,
    lifecycleRegistry:  repoState.lifecycleRegistry,
    historyRegistry:    persistResult.historyRegistry,
    dashboardIndex:     dashIndex,
    historicalCorpus:   mergeResult.corpus,
    history:            mergeResult.history,

    // Summary for CI logging
    summary: {
      engine_version:  ENGINE_VERSION,
      run_ts:          runTs,
      total_advisories: persistResult.dashboardIndex?.repository?.total_advisories || 0,
      new_this_run:    persistResult.stats?.new_accepted || 0,
      duplicates:      persistResult.stats?.duplicates   || 0,
      corpus_total:    mergeResult.corpus?.total || 0,
      integrity_valid: integrity?.valid || false,
      integrity_issues: integrity?.issues?.length || 0,
    },
  };
}

/**
 * Get stable dashboard metrics from repository state.
 * This is what the dashboard MUST read — never the raw feed.
 */
function getDashboardMetrics(repoState) {
  const index = repoState.dashboardIndex || {};
  const repo  = index.repository || {};
  const hist  = index.historical_windows || {};

  return {
    // Stable cumulative counts
    total_advisories:    repo.total_advisories || 0,
    critical_advisories: repo.severity_breakdown?.CRITICAL || 0,
    high_advisories:     repo.severity_breakdown?.HIGH || 0,
    medium_advisories:   repo.severity_breakdown?.MEDIUM || 0,
    kev_advisories:      repo.kev_count || 0,
    permanent_advisories: repo.permanent_count || 0,

    // Lifecycle breakdown
    active_advisories:   repo.lifecycle_breakdown?.ACTIVE || 0,
    monitoring:          repo.lifecycle_breakdown?.MONITORING || 0,
    archived:            repo.lifecycle_breakdown?.ARCHIVED || 0,

    // Historical windows
    "30d_count":  hist["30d"]  || 0,
    "90d_count":  hist["90d"]  || 0,
    "180d_count": hist["180d"] || 0,
    "365d_count": hist["365d"] || 0,

    // Metadata
    data_source:    "intelligence_repository",
    last_updated:   index.generated_at || index.last_run || new Date().toISOString(),
    total_runs:     index.feed_history?.total_runs || 0,
    note:           "Cumulative totals — never decreasing",
  };
}

/**
 * Validate repository state.
 */
function validateRepository(repoState) {
  const issues = [];

  const repo = repoState.repository || {};
  const total = Object.keys(repo.advisories || {}).length;

  if (repo.total !== undefined && repo.total !== total) {
    issues.push({ type: "count_mismatch", declared: repo.total, actual: total });
  }

  if (total === 0) {
    issues.push({ type: "empty_repository", severity: "WARNING" });
  }

  const ret = repoState.retentionRegistry || {};
  const retTotal = Object.keys(ret.registry || {}).length;
  if (retTotal < total * 0.9) {
    issues.push({
      type: "retention_coverage_low",
      advisories: total,
      retention_entries: retTotal,
    });
  }

  return {
    valid:           issues.filter(i => i.severity !== "WARNING").length === 0,
    total_advisories: total,
    retention_coverage: retTotal,
    issues,
  };
}

/**
 * Get repository stats summary.
 */
function getRepositoryStats(repoState) {
  const index = repoState.dashboardIndex || {};
  const repo  = index.repository || {};
  const hist  = repoState.historyRegistry || {};

  return {
    engine_version:  ENGINE_VERSION,
    total_advisories: repo.total_advisories || 0,
    severity:         repo.severity_breakdown || {},
    lifecycle:        repo.lifecycle_breakdown || {},
    kev_count:        repo.kev_count || 0,
    permanent_count:  repo.permanent_count || 0,
    total_runs:       hist.total_runs || 0,
    last_run:         hist.last_run || null,
    cumulative_new:   hist.cumulative_new || 0,
  };
}

export {
  runRetentionCycle,
  getDashboardMetrics,
  validateRepository,
  getRepositoryStats,
  ENGINE_VERSION,
};
