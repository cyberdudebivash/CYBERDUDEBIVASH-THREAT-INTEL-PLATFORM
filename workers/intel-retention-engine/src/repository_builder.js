/**
 * repository_builder.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
 * Intelligence Repository Builder
 * ==================================
 * Builds and maintains the Intelligence Repository from multiple
 * feed sources.  Handles paginated monthly chunks.
 *
 * Repository layout:
 *   data/intelligence_repository/
 *     intelligence_index.json          — master index + dashboard metrics
 *     advisory_registry.json           — advisory metadata index
 *     intel_retention_registry.json    — per-item retention policy
 *     intel_lifecycle_registry.json    — lifecycle state tracking
 *     historical_feed_registry.json    — per-run pipeline history
 *     advisories/
 *       registry_YYYYMM.json           — monthly advisory chunks (append-only)
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

import { DedupeEngine, dedupeHash } from "./dedupe_engine.js";
import { RetentionPolicyEngine } from "./retention_policy_engine.js";

const REPO_VERSION = "2.0.0";

class RepositoryBuilder {
  constructor(options = {}) {
    this.dedupe  = new DedupeEngine();
    this.policy  = new RetentionPolicyEngine();
    this.runTs   = new Date().toISOString();

    // Existing repository state (loaded from disk by caller)
    this.repository         = options.repository        || { advisories: {}, total: 0 };
    this.retentionRegistry  = options.retentionRegistry || { registry: {}, total: 0 };
    this.lifecycleRegistry  = options.lifecycleRegistry || { registry: {}, stats: {} };
    this.historyRegistry    = options.historyRegistry   || { runs: [], total_runs: 0 };
    this.monthlyChunks      = options.monthlyChunks     || {};  // ym -> Set of ids

    // Seed dedupe from existing retention registry
    this.dedupe.seedFromRegistry(this.retentionRegistry);

    this.stats = {
      total_before: Object.keys(this.repository.advisories || {}).length,
      new_added:    0,
      duplicates:   0,
      chunk_writes: 0,
    };
  }

  /**
   * Add a single item to the repository.
   * @param {Object} item - feed advisory
   * @returns {{ added: boolean, intelId: string, reason: string }}
   */
  add(item) {
    if (!item || !item.title) return { added: false, intelId: null, reason: "invalid" };

    const dh      = dedupeHash(item);
    const check   = this.dedupe.check(item);

    if (check.isDuplicate) {
      this.stats.duplicates++;
      // Update last_seen for existing entry
      if (this.retentionRegistry.registry?.[dh]) {
        this.retentionRegistry.registry[dh].last_seen = this.runTs;
      }
      return { added: false, intelId: null, reason: check.reason };
    }

    const publishedDate = item.published_at || item.timestamp || item.created_at || this.runTs;
    const retMeta = this.policy.buildRetentionMeta(item, publishedDate);
    const intelId = item.stix_id || item.id || `intel--${dh}`;
    const ym      = new Date(publishedDate).toISOString().slice(0, 7).replace("-", "");

    // Register in dedupe engine
    this.dedupe.register(item, intelId, dh);

    // Add to advisory repository
    if (!this.repository.advisories) this.repository.advisories = {};
    this.repository.advisories[intelId] = {
      intel_id:       intelId,
      title:          String(item.title || "").slice(0, 500),
      severity:       String(item.severity || "MEDIUM").toUpperCase(),
      risk_score:     parseFloat(item.risk_score || 5.0) || 5.0,
      confidence:     parseFloat(item.confidence || 50) || 50,
      source:         String(item.source || "SENTINEL_APEX"),
      source_url:     String(item.source_url || item.link || ""),
      blog_url:       String(item.blog_url || ""),
      published_at:   String(publishedDate).slice(0, 32),
      created_at:     String(publishedDate).slice(0, 32),
      last_seen:      this.runTs,
      tags:           Array.isArray(item.tags) ? item.tags.slice(0, 20) : [],
      actor_tag:      String(item.actor_tag || ""),
      is_kev:         Boolean(item.is_kev || item.kev),
      lifecycle_state: retMeta.lifecycle_state,
      retention_until: retMeta.retention_until,
      is_permanent:    retMeta.is_permanent,
      dedupe_hash:     dh,
      year_month:      ym,
    };

    // Add to retention registry
    if (!this.retentionRegistry.registry) this.retentionRegistry.registry = {};
    this.retentionRegistry.registry[dh] = {
      intel_id:       intelId,
      dedupe_hash:    dh,
      severity:       String(item.severity || "MEDIUM").toUpperCase(),
      is_permanent:   retMeta.is_permanent,
      is_kev:         Boolean(item.is_kev || item.kev),
      retention_until: retMeta.retention_until,
      retention_days: retMeta.retention_days,
      created_at:     String(publishedDate).slice(0, 32),
      last_seen:      this.runTs,
    };

    // Add to lifecycle registry
    if (!this.lifecycleRegistry.registry) this.lifecycleRegistry.registry = {};
    this.lifecycleRegistry.registry[intelId] = {
      intel_id:    intelId,
      status:      retMeta.lifecycle_state,
      created_at:  String(publishedDate).slice(0, 32),
      last_seen:   this.runTs,
      severity:    String(item.severity || "MEDIUM").toUpperCase(),
    };

    // Track monthly chunk
    if (!this.monthlyChunks[ym]) this.monthlyChunks[ym] = new Set();
    this.monthlyChunks[ym].add(intelId);

    this.stats.new_added++;
    return { added: true, intelId, reason: "accepted" };
  }

  /**
   * Add multiple items in bulk.
   * @param {Array} items
   */
  addBatch(items) {
    if (!Array.isArray(items)) return;
    for (const item of items) {
      this.add(item);
    }
  }

  /**
   * Finalize and return all updated repository data.
   */
  finalize() {
    const total = Object.keys(this.repository.advisories || {}).length;

    // Update totals
    this.repository.total        = total;
    this.repository.last_updated = this.runTs;
    this.repository.schema_version = REPO_VERSION;

    this.retentionRegistry.total        = Object.keys(this.retentionRegistry.registry || {}).length;
    this.retentionRegistry.last_updated = this.runTs;
    this.retentionRegistry.schema_version = REPO_VERSION;

    // Lifecycle stats
    const stateCounts = { ACTIVE: 0, MONITORING: 0, ARCHIVED: 0 };
    for (const entry of Object.values(this.lifecycleRegistry.registry || {})) {
      const s = entry.status || "ACTIVE";
      if (s in stateCounts) stateCounts[s]++;
    }
    this.lifecycleRegistry.stats      = stateCounts;
    this.lifecycleRegistry.total      = Object.keys(this.lifecycleRegistry.registry || {}).length;
    this.lifecycleRegistry.last_updated = this.runTs;
    this.lifecycleRegistry.schema_version = REPO_VERSION;

    // Monthly chunk payloads
    const monthlyChunkPayloads = {};
    for (const [ym, ids] of Object.entries(this.monthlyChunks)) {
      monthlyChunkPayloads[ym] = {
        year_month: ym,
        ids:        [...ids],
        count:      ids.size || ids.length,
        updated:    this.runTs,
      };
    }

    this.stats.total_after = total;
    this.stats.run_ts      = this.runTs;

    return {
      repository:         this.repository,
      retentionRegistry:  this.retentionRegistry,
      lifecycleRegistry:  this.lifecycleRegistry,
      historyRegistry:    this.historyRegistry,
      monthlyChunks:      monthlyChunkPayloads,
      stats:              { ...this.stats },
    };
  }

  getStats() {
    return { ...this.stats };
  }
}

export { RepositoryBuilder, REPO_VERSION };
