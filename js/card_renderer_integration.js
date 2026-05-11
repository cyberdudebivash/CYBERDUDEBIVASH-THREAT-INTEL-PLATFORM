/**
 * =============================================================================
 *  SENTINEL APEX -- CARD RENDERER INTEGRATION v147.0.0
 *  Drop-in integration for the CYBERDUDEBIVASH SENTINEL APEX dashboard
 *
 *  LOAD ORDER (before </body>):
 *    <link rel="stylesheet" href="/css/card_renderer_styles.css">
 *    <script src="/js/api_adapter.js"></script>
 *    <script src="/js/card_renderer.js"></script>
 *    <script src="/js/card_renderer_integration.js"></script>
 *
 *  PIPELINE SAFETY:
 *    - Only API data updates trigger re-render
 *    - UI component code is version-locked (VERSION = 145.0.0)
 *    - CI/CD must never overwrite card_renderer.js or api_adapter.js
 *    - Falls back to EMBEDDED_INTEL if live API is unreachable
 *
 *  P0 FIX (v145):
 *    - _bootFromEmbedded() renders cards instantly from window.EMBEDDED_INTEL
 *      (injected by pipeline STAGE 3.93) -- zero network dependency
 *    - fetchAndNormalize() added to api_adapter.js public API
 *    - Cards are ALWAYS visible immediately on page load
 * =============================================================================
 */

"use strict";

(function () {

  /* -------------------------------------------------------------------------
   *  CONFIGURATION
   * ---------------------------------------------------------------------- */
  var CONFIG = {
    API_URL:       "https://intel.cyberdudebivash.com/api/preview/",
    FALLBACK_URLS: [
      "https://intel.cyberdudebivash.com/api/preview",
      "/api/feed.json",
    ],
    CONTAINER_SELECTORS: [
      "#sapx-card-grid",
      "#advisory-grid",
      "#intel-card-grid",
      "#feed-container",
      ".intel-feed",
      "#advisory-list",
      "#v70-advisory-list",
      "#intel-list",
    ],
    AUTO_REFRESH_MS: 0,
    MAX_CARDS:       30,
    VERSION:         "147.0.0",
    LOADING_COUNT:   4,
  };

  /* -------------------------------------------------------------------------
   *  DEPENDENCY CHECK
   * ---------------------------------------------------------------------- */
  function _checkDependencies() {
    var missing = [];
    if (typeof window.SentinelApexAdapter === "undefined")      missing.push("js/api_adapter.js");
    if (typeof window.SentinelApexCardRenderer === "undefined") missing.push("js/card_renderer.js");
    if (missing.length > 0) {
      console.error("[SAPX] Missing dependencies:", missing.join(", "));
      return false;
    }
    return true;
  }

  /* -------------------------------------------------------------------------
   *  CONTAINER DISCOVERY  -- god-mode fallback chain
   *
   *  Priority:
   *   1. #sapx-card-grid   -- static anchor in index.html inside #cdb-panel-live
   *   2. Other known IDs / classes
   *   3. Create #sapx-card-grid as next sibling of #threat-grid
   *   4. Append to #cdb-panel-live
   *   5. Append to known section selectors
   *   6. LAST RESORT: appendChild to body (NEVER insertBefore(firstChild))
   * ---------------------------------------------------------------------- */
  function _findContainer() {
    var el;

    el = document.getElementById("sapx-card-grid");
    if (el) { console.info("[SAPX] Container: #sapx-card-grid (static anchor)"); return el; }

    var knownSelectors = ["#advisory-grid","#intel-card-grid","#feed-container",
                          ".intel-feed","#advisory-list","#v70-advisory-list","#intel-list"];
    for (var i = 0; i < knownSelectors.length; i++) {
      el = document.querySelector(knownSelectors[i]);
      if (el) { console.info("[SAPX] Container:", knownSelectors[i]); return el; }
    }

    var container = document.createElement("div");
    container.id = "sapx-card-grid";

    var threatGrid = document.getElementById("threat-grid");
    if (threatGrid && threatGrid.parentNode) {
      threatGrid.parentNode.insertBefore(container, threatGrid.nextSibling);
      console.info("[SAPX] Created #sapx-card-grid after #threat-grid");
      return container;
    }

    var livePanel = document.getElementById("cdb-panel-live");
    if (livePanel) { livePanel.appendChild(container); return container; }

    var intelSection = document.querySelector(
      "#live-feed-section, #intel-section, .threat-cards-section, .content-area"
    );
    if (intelSection) { intelSection.appendChild(container); return container; }

    document.body.appendChild(container);
    console.warn("[SAPX] WARNING: appended #sapx-card-grid to body (check dashboard DOM).");
    return container;
  }

  /* -------------------------------------------------------------------------
   *  INSTANT BOOT FROM EMBEDDED_INTEL  (P0 FIX v145)
   *
   *  Renders enterprise cards immediately on page load using the 25 items
   *  injected into window.EMBEDDED_INTEL by pipeline STAGE 3.93.
   *  This guarantees cards are visible before any network request completes,
   *  and provides a permanent offline fallback if the API is unreachable.
   * ---------------------------------------------------------------------- */
  function _bootFromEmbedded(container) {
    if (typeof window === "undefined") return false;
    var embedded = window.EMBEDDED_INTEL;
    if (!embedded || !embedded.length) return false;
    var Adapter  = window.SentinelApexAdapter;
    var Renderer = window.SentinelApexCardRenderer;
    try {
      var items = embedded.map(function(item, i) {
        return Adapter.normalizeIntelItem(item, i);
      });
      if (!items.length) return false;
      Renderer.renderGrid(container, items, { maxCards: CONFIG.MAX_CARDS });
      container.dataset.sapxSource = "embedded";
      console.info("[SAPX] Instant boot from EMBEDDED_INTEL:", items.length, "cards rendered");
      return true;
    } catch (e) {
      console.warn("[SAPX] Embedded boot error:", e);
      return false;
    }
  }

  /* -------------------------------------------------------------------------
   *  FETCH WITH FALLBACK CHAIN
   * ---------------------------------------------------------------------- */
  async function _fetchWithFallbackChain() {
    var Adapter = window.SentinelApexAdapter;
    var urls = [CONFIG.API_URL].concat(CONFIG.FALLBACK_URLS);

    for (var i = 0; i < urls.length; i++) {
      var url = urls[i];
      console.info("[SAPX] Trying URL:", url);
      try {
        var result = await Adapter.fetchAndNormalize(url, { maxRetry: 1, timeoutMs: 8000 });
        if (result.normalized && result.normalized.items.length > 0) {
          console.info("[SAPX] Success from:", url, "| Items:", result.normalized.items.length);
          return result;
        }
      } catch (e) {
        console.warn("[SAPX] URL failed:", url, e.message);
      }
    }

    // All network sources failed -- return embedded cache if available
    if (window.EMBEDDED_INTEL && window.EMBEDDED_INTEL.length) {
      console.info("[SAPX] Returning embedded cache as normalized data");
      var Adapter2 = window.SentinelApexAdapter;
      var cachedItems = window.EMBEDDED_INTEL.map(function(item, i) {
        return Adapter2.normalizeIntelItem(item, i);
      });
      return {
        normalized: {
          status: "ok", items: cachedItems, total_in_feed: cachedItems.length,
          total_preview: cachedItems.length, generated_at: new Date().toISOString(),
          generated_at_fmt: "EMBEDDED CACHE",
          stats: { total: cachedItems.length, by_severity: {}, total_iocs: 0, high_priority: 0 },
        },
        error: null,
        cached: true,
      };
    }

    console.warn("[SAPX] All endpoints failed -- no data available.");
    return { normalized: null, error: new Error("All endpoints failed"), cached: false };
  }

  /* -------------------------------------------------------------------------
   *  HEADER STATS INJECTION
   * ---------------------------------------------------------------------- */
  function _injectHeaderStats(normalized) {
    if (!normalized || !normalized.stats) return;
    var stats = normalized.stats;
    var updates = [
      // Selectors cover both SAPX canonical IDs and dashboard native IDs (#m-*)
      { selectors: ["#total-advisories","#m-total",".stat-total-count","[data-stat='total']"],       val: normalized.total_in_feed || stats.total },
      { selectors: ["#critical-count","#m-critical",".stat-critical","[data-stat='critical']"],      val: stats.by_severity.CRITICAL || 0 },
      { selectors: ["#high-count","#m-high",".stat-high","[data-stat='high']"],                      val: stats.by_severity.HIGH || 0 },
      { selectors: ["#medium-count",".stat-medium","[data-stat='medium']"],                          val: stats.by_severity.MEDIUM || 0 },
      { selectors: ["#avg-risk","#m-avg-risk",".stat-avg-risk","[data-stat='avg-risk']"],            val: stats.avg_risk },
      { selectors: ["#total-iocs","#m-iocs",".stat-total-iocs","[data-stat='total-iocs']"],          val: stats.total_iocs },
      { selectors: ["#high-priority-count","[data-stat='high-priority']"],                           val: stats.high_priority },
    ];
    updates.forEach(function(upd) {
      upd.selectors.forEach(function(sel) {
        var el = document.querySelector(sel);
        if (el && !el.dataset.sapxManaged) {
          el.dataset.sapxManaged = "1";
          el.textContent = upd.val;
        }
      });
    });
    var syncEls = document.querySelectorAll(".sync-time, #sync-time, #m-last-sync, [data-stat='sync-time'], #last-sync");
    syncEls.forEach(function(el) {
      if (!el.dataset.sapxManaged) {
        el.dataset.sapxManaged = "1";
        el.textContent = normalized.generated_at_fmt || normalized.generated_at;
      }
    });
  }

  /* -------------------------------------------------------------------------
   *  FILTER BAR WIRING
   * ---------------------------------------------------------------------- */
  function _wireFilterControls(container) {
    var Renderer = window.SentinelApexCardRenderer;
    document.querySelectorAll("[data-filter]").forEach(function(btn) {
      btn.addEventListener("click", function() {
        var sev = btn.dataset.filter === "all" ? "" : btn.dataset.filter;
        Renderer.filterCards(container, { severity: sev });
        document.querySelectorAll("[data-filter]").forEach(function(b) { b.classList.remove("active"); });
        btn.classList.add("active");
      });
    });
    document.querySelectorAll("[data-sort]").forEach(function(el) {
      el.addEventListener("change", function() { Renderer.sortCards(container, el.value); });
      el.addEventListener("click",  function() { if (el.dataset.sort) Renderer.sortCards(container, el.dataset.sort); });
    });
    var searchInput = document.querySelector("#threat-search, .search-input, [data-action='search']");
    if (searchInput) {
      var debounceTimer;
      searchInput.addEventListener("input", function() {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(function() {
          Renderer.filterCards(container, { search: searchInput.value });
        }, 300);
      });
    }
  }

  /* -------------------------------------------------------------------------
   *  MAIN RENDER CYCLE
   * ---------------------------------------------------------------------- */
  async function render(container) {
    var Renderer = window.SentinelApexCardRenderer;

    // INSTANT RENDER: show embedded cards immediately, no spinner needed
    var hasEmbedded = _bootFromEmbedded(container);
    if (!hasEmbedded) {
      // Show loading state only if we have nothing to display yet
      Renderer.showLoadingState(container, CONFIG.LOADING_COUNT);
    }

    // Fetch live data (upgrades the embedded cards with freshest intel)
    var result = await _fetchWithFallbackChain();

    if (!result.normalized || result.normalized.items.length === 0) {
      if (!hasEmbedded) {
        container.innerHTML = [
          '<div style="text-align:center;padding:48px 24px;color:#64748b;">',
          '  <div style="font-size:36px;margin-bottom:12px;opacity:0.4;">&#x1F6E1;</div>',
          '  <div style="font-size:14px;font-weight:700;margin-bottom:6px;">No Threat Intelligence Available</div>',
          '  <div style="font-size:12px;">Feed is empty or API is offline.</div>',
          '</div>'
        ].join("");
      }
      return null;
    }

    // Re-render with live data (replaces embedded cards with fresh data)
    Renderer.renderGrid(container, result.normalized.items, { maxCards: CONFIG.MAX_CARDS });
    container.dataset.sapxSource = result.cached ? "cache" : "live";

    _injectHeaderStats(result.normalized);
    _wireFilterControls(container);

    window.dispatchEvent(new CustomEvent("SentinelApexCardsReady", {
      detail: { normalized: result.normalized, cached: result.cached, version: CONFIG.VERSION }
    }));

    console.info("[SAPX] Rendered", result.normalized.items.length, "cards",
      result.cached ? "(cached)" : "(live)", "| v" + CONFIG.VERSION);

    return result.normalized;
  }

  /* -------------------------------------------------------------------------
   *  AUTO-REFRESH
   * ---------------------------------------------------------------------- */
  var _refreshTimer = null;

  function _startAutoRefresh(container) {
    if (!CONFIG.AUTO_REFRESH_MS || CONFIG.AUTO_REFRESH_MS < 30000) return;
    _refreshTimer = setInterval(function() {
      console.info("[SAPX] Auto-refresh triggered");
      render(container);
    }, CONFIG.AUTO_REFRESH_MS);
  }

  function _stopAutoRefresh() {
    if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
  }

  /* -------------------------------------------------------------------------
   *  INIT -- waits for dependencies then bootstraps
   * ---------------------------------------------------------------------- */
  async function init() {
    var retries = 0;
    while (!_checkDependencies() && retries < 20) {
      await new Promise(function(r) { setTimeout(r, 100); });
      retries++;
    }
    if (!_checkDependencies()) {
      console.error("[SAPX] Dependencies not available after 2s. Aborting.");
      return;
    }

    var container = _findContainer();
    if (!container) {
      console.error("[SAPX] No suitable container found. Aborting.");
      return;
    }

    await render(container);
    _startAutoRefresh(container);

    window.SAPX = {
      refresh:     function() { return render(container); },
      filterCards: function(filters) { window.SentinelApexCardRenderer.filterCards(container, filters); },
      sortCards:   function(by) { window.SentinelApexCardRenderer.sortCards(container, by); },
      stopRefresh: _stopAutoRefresh,
      config:      CONFIG,
      version:     CONFIG.VERSION,
    };

    console.info("[SAPX] Initialized v" + CONFIG.VERSION + " | window.SAPX available");
  }


  /* -------------------------------------------------------------------------
   *  BOOT
   * ---------------------------------------------------------------------- */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    setTimeout(init, 0);
  }

})();
