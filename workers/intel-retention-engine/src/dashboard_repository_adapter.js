/**
 * dashboard_repository_adapter.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v171.0
 * Dashboard Repository Adapter
 * ==============================
 * Intercepts dashboard metric requests and routes them to the
 * persistent Intelligence Repository instead of the raw feed.
 *
 * PROBLEM SOLVED:
 *   Before: Dashboard reads latest.json -> count fluctuates each run
 *   After:  Dashboard reads repository index -> count is ALWAYS cumulative
 *
 * Usage (Cloudflare Worker):
 *   import { DashboardRepositoryAdapter } from "./dashboard_repository_adapter.js";
 *   const adapter = new DashboardRepositoryAdapter(env);
 *   const metrics = await adapter.getMetrics();
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

// Repository paths (relative to R2 bucket / GitHub repo root)
const REPO_PATHS = {
  index:     "data/intelligence_repository/intelligence_index.json",
  retention: "data/intelligence_repository/intel_retention_registry.json",
  lifecycle: "data/intelligence_repository/intel_lifecycle_registry.json",
  history:   "data/intelligence_repository/historical_feed_registry.json",
  advisory:  "data/intelligence_repository/advisory_registry.json",
};

// Cache TTL for repository data (seconds)
const CACHE_TTL = 300; // 5 minutes

class DashboardRepositoryAdapter {
  /**
   * @param {Object} env      - Cloudflare Worker env bindings
   * @param {Object} options
   * @param {string} options.githubRawBase - GitHub raw content base URL
   */
  constructor(env, options = {}) {
    this.env     = env;
    this.options = options;
    this._cache  = {};
    this._cacheTs = {};
    this.ADAPTER_VERSION = "171.0";
  }

  /**
   * Fetch repository index (with cache).
   */
  async _fetchIndex() {
    const cacheKey = "index";
    const now = Date.now();

    if (this._cache[cacheKey] && (now - (this._cacheTs[cacheKey] || 0)) < CACHE_TTL * 1000) {
      return this._cache[cacheKey];
    }

    let data = null;

    // Try R2 first (fastest path)
    if (this.env?.INTEL_R2) {
      try {
        const obj = await this.env.INTEL_R2.get(REPO_PATHS.index);
        if (obj) {
          data = await obj.json();
        }
      } catch (e) {
        // Fall through to GitHub
      }
    }

    // Fallback: GitHub raw
    if (!data && this.options.githubRawBase) {
      try {
        const url = `${this.options.githubRawBase}/${REPO_PATHS.index}`;
        const res = await fetch(url, { headers: { "Cache-Control": "no-cache" } });
        if (res.ok) data = await res.json();
      } catch (e) {
        // Ignore
      }
    }

    if (data) {
      this._cache[cacheKey]  = data;
      this._cacheTs[cacheKey] = now;
    }

    return data;
  }

  /**
   * Get stable dashboard metrics.
   * Returns repository-sourced counts that never decrease.
   */
  async getMetrics() {
    const index = await this._fetchIndex();

    if (!index) {
      return this._fallbackMetrics();
    }

    const repo = index.repository || {};
    const dash = index.dashboard  || {};
    const hist = index.feed_history || {};
    const hw   = index.historical_windows || {};

    return {
      // Core repository counts (STABLE — cumulative)
      total_advisories:     dash.total_advisories    || repo.total_advisories || 0,
      critical_advisories:  repo.severity_breakdown?.CRITICAL || 0,
      high_advisories:      repo.severity_breakdown?.HIGH     || 0,
      medium_advisories:    repo.severity_breakdown?.MEDIUM   || 0,
      low_advisories:       repo.severity_breakdown?.LOW      || 0,
      kev_advisories:       repo.kev_count     || 0,
      permanent_advisories: repo.permanent_count || 0,

      // Lifecycle
      active_advisories:   repo.lifecycle_breakdown?.ACTIVE     || 0,
      monitoring:          repo.lifecycle_breakdown?.MONITORING  || 0,
      archived:            repo.lifecycle_breakdown?.ARCHIVED    || 0,

      // Time-window counts
      "30d":  hw["30d"]  || 0,
      "90d":  hw["90d"]  || 0,
      "180d": hw["180d"] || 0,
      "365d": hw["365d"] || 0,

      // Run metadata
      total_pipeline_runs: hist.total_runs || 0,
      last_updated:        index.last_run  || index.generated_at || new Date().toISOString(),

      // Source metadata (for transparency)
      data_source:    "intelligence_repository_v2",
      adapter_version: this.ADAPTER_VERSION,
      note:           "Cumulative totals — stable across runs",
    };
  }

  /**
   * Get historical trend data for dashboard charts.
   */
  async getTrends() {
    const histData = await this._fetchFile("history");
    if (!histData) return { runs: [], trend: [] };

    const runs = (histData.runs || []).slice(-90);  // last 90 runs
    return {
      runs: runs.map(r => ({
        date:       r.run_ts?.slice(0, 10) || "",
        new_items:  r.new_items  || 0,
        total:      r.total_repo || 0,
      })),
      trend: runs.map((r, i) => ({
        x: i,
        date:  r.run_ts?.slice(0, 10) || "",
        total: r.total_repo || 0,
      })),
    };
  }

  /**
   * Get advisories for a specific time window.
   */
  async getWindowAdvisories(window = "30d") {
    const index    = await this._fetchIndex();
    const windows  = index?.historical_windows || {};
    const windowMs = { "30d": 30, "90d": 90, "180d": 180, "365d": 365 };
    const days     = windowMs[window] || 30;

    return {
      window,
      days,
      count: windows[window] || 0,
      note:  "Full advisory list available via /api/v1/intel/repository endpoint",
    };
  }

  /**
   * Build API response for dashboard stats endpoint.
   */
  async buildStatsResponse() {
    const metrics = await this.getMetrics();
    const trends  = await this.getTrends();

    return {
      status:  "ok",
      source:  "intelligence_repository",
      metrics,
      trends:  trends.trend.slice(-30),
      timestamp: new Date().toISOString(),
    };
  }

  async _fetchFile(key) {
    const cacheKey = key;
    const now = Date.now();
    if (this._cache[cacheKey] && (now - (this._cacheTs[cacheKey] || 0)) < CACHE_TTL * 1000) {
      return this._cache[cacheKey];
    }

    const path = REPO_PATHS[key];
    if (!path) return null;

    let data = null;
    if (this.env?.INTEL_R2) {
      try {
        const obj = await this.env.INTEL_R2.get(path);
        if (obj) data = await obj.json();
      } catch (e) {}
    }

    if (!data && this.options.githubRawBase) {
      try {
        const res = await fetch(`${this.options.githubRawBase}/${path}`);
        if (res.ok) data = await res.json();
      } catch (e) {}
    }

    if (data) {
      this._cache[cacheKey]  = data;
      this._cacheTs[cacheKey] = now;
    }
    return data;
  }

  _fallbackMetrics() {
    return {
      total_advisories:    0,
      critical_advisories: 0,
      high_advisories:     0,
      kev_advisories:      0,
      data_source:         "fallback",
      note:                "Repository index not available — falling back to zero",
      adapter_version:     this.ADAPTER_VERSION,
    };
  }
}

export { DashboardRepositoryAdapter, REPO_PATHS, CACHE_TTL };
