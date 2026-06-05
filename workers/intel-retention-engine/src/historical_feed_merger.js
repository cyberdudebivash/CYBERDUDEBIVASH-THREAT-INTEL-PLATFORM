/**
 * historical_feed_merger.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
 * Historical Feed Merger
 * =======================
 * Merges incoming feed data with the persistent historical corpus.
 * Ensures no regression in advisory counts across pipeline runs.
 *
 * Merge strategy:
 *   - New items are APPENDED to the corpus
 *   - Existing items are NEVER removed
 *   - Counts only increase or stay the same
 *   - Historical snapshots are preserved as-is
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

import { dedupeHash } from "./dedupe_engine.js";

const HISTORY_WINDOWS = {
  "30d":  30,
  "90d":  90,
  "180d": 180,
  "365d": 365,
};

class HistoricalFeedMerger {
  constructor(options = {}) {
    this.runTs   = new Date().toISOString();
    this.corpus  = options.corpus  || { advisories: {}, total: 0 };
    this.history = options.history || { snapshots: [], windows: {} };

    this.stats = {
      before_total: this.corpus.total || Object.keys(this.corpus.advisories || {}).length,
      merged:       0,
      already_present: 0,
      errors:       [],
    };
  }

  /**
   * Merge a new feed batch into the historical corpus.
   * APPEND-ONLY: never removes existing entries.
   *
   * @param {Array} newItems - validated, deduped feed items
   * @returns {number} count of actually new items merged
   */
  mergeFeed(newItems) {
    if (!Array.isArray(newItems)) {
      this.stats.errors.push("mergeFeed: newItems is not array");
      return 0;
    }

    if (!this.corpus.advisories) this.corpus.advisories = {};

    let newCount = 0;
    for (const item of newItems) {
      const intelId = item._intel_id || item.stix_id || item.id || `intel--${dedupeHash(item)}`;

      if (this.corpus.advisories[intelId]) {
        // Only update last_seen — never overwrite any field
        this.corpus.advisories[intelId].last_seen = this.runTs;
        this.stats.already_present++;
        continue;
      }

      this.corpus.advisories[intelId] = {
        intel_id:     intelId,
        title:        String(item.title || "").slice(0, 300),
        severity:     String(item.severity || "MEDIUM").toUpperCase(),
        risk_score:   parseFloat(item.risk_score || 5.0) || 5.0,
        source:       String(item.source || "SENTINEL_APEX"),
        published_at: String(item.published_at || item.timestamp || this.runTs),
        created_at:   String(item.published_at || item.timestamp || this.runTs),
        last_seen:    this.runTs,
        is_kev:       Boolean(item.is_kev || item.kev),
        is_permanent: Boolean(item.retention_meta?.is_permanent),
        lifecycle_state: item.lifecycle_state || "ACTIVE",
      };
      newCount++;
      this.stats.merged++;
    }

    this.corpus.total        = Object.keys(this.corpus.advisories).length;
    this.corpus.last_updated = this.runTs;

    return newCount;
  }

  /**
   * Build time-window views for historical dashboard.
   * Returns counts for 30/90/180/365 day windows.
   */
  buildWindowViews() {
    const now = Date.now();
    const views = {};

    for (const [windowName, days] of Object.entries(HISTORY_WINDOWS)) {
      const cutoff = new Date(now - days * 24 * 60 * 60 * 1000).toISOString();
      let count = 0;
      const sample = [];

      for (const adv of Object.values(this.corpus.advisories || {})) {
        const pub = adv.published_at || adv.created_at || "";
        if (pub >= cutoff) {
          count++;
          if (sample.length < 10) {
            sample.push({
              intel_id: adv.intel_id,
              title:    adv.title,
              severity: adv.severity,
              pub:      pub.slice(0, 10),
            });
          }
        }
      }

      views[windowName] = {
        window:  windowName,
        days:    days,
        cutoff:  cutoff.slice(0, 10),
        count:   count,
        sample:  sample,
      };
    }

    this.history.windows   = views;
    this.history.last_built = this.runTs;
    return views;
  }

  /**
   * Record a snapshot of current corpus state.
   * Snapshots are append-only — never removed.
   */
  recordSnapshot() {
    const total = this.corpus.total || Object.keys(this.corpus.advisories || {}).length;

    const snapshot = {
      run_ts:        this.runTs,
      total:         total,
      new_this_run:  this.stats.merged,
      windows:       Object.fromEntries(
        Object.entries(this.history.windows || {}).map(([k, v]) => [k, v.count])
      ),
    };

    if (!Array.isArray(this.history.snapshots)) this.history.snapshots = [];
    this.history.snapshots.push(snapshot);

    // Keep last 365 snapshots (1 per day for a year)
    if (this.history.snapshots.length > 365) {
      this.history.snapshots = this.history.snapshots.slice(-365);
    }

    this.history.total_snapshots = this.history.snapshots.length;
    return snapshot;
  }

  /**
   * Get time-series data for trend charts.
   * Returns data points that always show non-decreasing counts.
   */
  getTrendData(limit = 30) {
    const snapshots = (this.history.snapshots || []).slice(-limit);
    return snapshots.map(s => ({
      date:  s.run_ts.slice(0, 10),
      total: s.total,
      new:   s.new_this_run || 0,
    }));
  }

  /**
   * Get severity distribution over a time window.
   */
  getSeverityDistribution(windowDays = 30) {
    const now    = Date.now();
    const cutoff = new Date(now - windowDays * 24 * 60 * 60 * 1000).toISOString();
    const dist   = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

    for (const adv of Object.values(this.corpus.advisories || {})) {
      const pub = adv.published_at || adv.created_at || "";
      if (pub >= cutoff) {
        const sev = String(adv.severity || "MEDIUM").toUpperCase();
        if (sev in dist) dist[sev]++;
      }
    }

    return dist;
  }

  /**
   * Validate corpus integrity.
   * Returns list of issues found.
   */
  validateIntegrity() {
    const issues = [];
    const advisories = this.corpus.advisories || {};
    const total = Object.keys(advisories).length;

    if (this.corpus.total !== total) {
      issues.push({ type: "count_mismatch", declared: this.corpus.total, actual: total });
      this.corpus.total = total; // auto-correct
    }

    // Verify no entries are missing required fields
    let missing_title = 0;
    for (const [id, adv] of Object.entries(advisories)) {
      if (!adv.title) missing_title++;
    }
    if (missing_title > 0) {
      issues.push({ type: "missing_title", count: missing_title });
    }

    return { valid: issues.length === 0, issues, total };
  }

  finalize() {
    const windows  = this.buildWindowViews();
    const snapshot = this.recordSnapshot();
    const integrity = this.validateIntegrity();

    return {
      corpus:    this.corpus,
      history:   this.history,
      windows,
      snapshot,
      integrity,
      stats:     { ...this.stats },
    };
  }
}

export { HistoricalFeedMerger, HISTORY_WINDOWS };
