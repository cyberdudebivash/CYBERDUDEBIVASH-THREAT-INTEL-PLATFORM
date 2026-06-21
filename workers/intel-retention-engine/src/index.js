/**
 * index.js
 * CYBERDUDEBIVASH(R) SENTINEL APEX v182.0
 * Intel Retention Engine — Cloudflare Worker Entry Point
 * =======================================================
 * Exposes the Intelligence Repository as a stable metrics API.
 * Dashboard reads from this worker instead of raw feed to get
 * CUMULATIVE, never-decreasing advisory counts.
 *
 * Routes served:
 *   GET /api/v2/repository/health   — health check
 *   GET /api/v2/repository/metrics  — stable dashboard metrics
 *   GET /api/v2/repository/stats    — full stats + trends
 *   GET /api/v2/repository/trends   — historical trend data (last 90 runs)
 *
 * Bindings required:
 *   INTEL_R2 — R2 bucket "sentinel-apex-data" (same as intel-gateway)
 *
 * (c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
 */

import { DashboardRepositoryAdapter } from "./dashboard_repository_adapter.js";

const ENGINE_VERSION = "182.0";
const GITHUB_RAW_BASE =
  "https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Cache-Control":                "public, max-age=60, s-maxage=60",
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
  });
}

function errorResponse(message, status = 500) {
  return jsonResponse({ status: "error", message, engine_version: ENGINE_VERSION }, status);
}

export default {
  async fetch(request, env, _ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== "GET") {
      return errorResponse("Method not allowed", 405);
    }

    const url  = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, ""); // strip trailing slash

    const adapter = new DashboardRepositoryAdapter(env, { githubRawBase: GITHUB_RAW_BASE });

    try {
      // ── /api/v2/repository/health ────────────────────────────────────────
      if (path.endsWith("/health")) {
        return jsonResponse({
          status:         "ok",
          worker:         "intel-retention-engine",
          engine_version: ENGINE_VERSION,
          timestamp:      new Date().toISOString(),
          r2_bound:       Boolean(env.INTEL_R2),
        });
      }

      // ── /api/v2/repository/metrics ───────────────────────────────────────
      if (path.endsWith("/metrics")) {
        const metrics = await adapter.getMetrics();
        return jsonResponse({ status: "ok", engine_version: ENGINE_VERSION, ...metrics });
      }

      // ── /api/v2/repository/trends ────────────────────────────────────────
      if (path.endsWith("/trends")) {
        const trends = await adapter.getTrends();
        return jsonResponse({ status: "ok", engine_version: ENGINE_VERSION, ...trends });
      }

      // ── /api/v2/repository/stats (full: metrics + trends combined) ───────
      if (path.endsWith("/stats") || path.endsWith("/repository")) {
        const stats = await adapter.buildStatsResponse();
        return jsonResponse({ ...stats, engine_version: ENGINE_VERSION });
      }

      return errorResponse("Endpoint not found. Valid paths: /health /metrics /trends /stats", 404);

    } catch (err) {
      console.error("[intel-retention-engine] fetch error:", err);
      return errorResponse(String(err));
    }
  },

  // Cron: runs every 4 hours aligned with sentinel-blogger schedule.
  // Warms the R2 cache so next dashboard request is instant.
  async scheduled(_event, env, _ctx) {
    console.log("[intel-retention-engine] Scheduled cache warm — triggered");
    try {
      const adapter = new DashboardRepositoryAdapter(env, { githubRawBase: GITHUB_RAW_BASE });
      const metrics = await adapter.getMetrics();
      console.log(
        `[intel-retention-engine] Cache warm complete — total_advisories=${metrics.total_advisories}`,
      );
    } catch (err) {
      console.error("[intel-retention-engine] Scheduled warm error:", err);
    }
  },
};
