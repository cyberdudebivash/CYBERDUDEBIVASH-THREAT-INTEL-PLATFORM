/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — CARD RENDERER INTEGRATION PATCH v143.0.0
 *  Drop-in integration for the CYBERDUDEBIVASH SENTINEL APEX dashboard
 *
 *  LOAD ORDER (in <head> or before </body>):
 *    <link rel="stylesheet" href="/css/card_renderer_styles.css">
 *    <script src="/js/api_adapter.js"></script>
 *    <script src="/js/card_renderer.js"></script>
 *    <script src="/js/card_renderer_integration.js"></script>
 *
 *  PIPELINE SAFETY:
 *    - Only API data updates are allowed to trigger re-render
 *    - UI component code is version-locked (VERSION = 143.0.0)
 *    - CI/CD must never overwrite card_renderer.js or api_adapter.js
 *    - Falls back to cached intelligence if live API is unreachable
 *
 *  INTEGRATION POINTS:
 *    - Hooks into existing #feed-container / .intel-feed / #advisory-list
 *    - Fires SentinelApexCardsReady event with normalized data for other modules
 *    - Exposes window.SAPX for manual control
 * ═══════════════════════════════════════════════════════════════════════════════
 */

"use strict";

(function () {

  /* ─────────────────────────────────────────────────────────────
   *  CONFIGURATION — update API URL here only
   * ───────────────────────────────────────────────────────────── */
  var CONFIG = {
    // Primary API endpoint (matches existing dashboard)
    API_URL:       "https://intel.cyberdudebivash.com/api/preview/",
    // Fallback endpoints (tried in order if primary fails)
    FALLBACK_URLS: [
      "https://intel.cyberdudebivash.com/api/preview",
      "/api/feed.json",
    ],
    // Container selectors — legacy list kept for _findContainer() Priority 2
    // Primary discovery is now handled in _findContainer() directly.
    // #sapx-card-grid is the canonical target (static anchor in index.html,
    // inside #cdb-panel-live after #threat-grid).
    CONTAINER_SELECTORS: [
      "#sapx-card-grid",           // ← static anchor planted in index.html (canonical)
      "#advisory-grid",
      "#intel-card-grid",
      "#feed-container",
      ".intel-feed",
      "#advisory-list",
      "#v70-advisory-list",
      "#intel-list",
    ],
    // Auto-refresh interval (ms) — 0 = disabled
    AUTO_REFRESH_MS:   0,
    // Max cards to render
    MAX_CARDS:         30,
    // Version lock — DO NOT CHANGE
    VERSION:          "143.1.0",
    // Loading card count
    LOADING_COUNT:    4,
  };

  /* ─────────────────────────────────────────────────────────────
   *  DEPENDENCY CHECK
   * ───────────────────────────────────────────────────────────── */
  function _checkDependencies() {
    var missing = [];
    if (typeof window.SentinelApexAdapter === "undefined")      missing.push("js/api_adapter.js");
    if (typeof window.SentinelApexCardRenderer === "undefined") missing.push("js/card_renderer.js");
    if (missing.length > 0) {
      console.error("[SAPX Integration] Missing dependencies:", missing.join(", "));
      console.error("[SAPX Integration] Load order: api_adapter.js → card_renderer.js → card_renderer_integration.js");
      return false;
    }
    return true;
  }

  /* ─────────────────────────────────────────────────────────────
   *  CONTAINER DISCOVERY  (god-mode fallback chain v143.1.0)
   *
   *  Priority order — first match wins:
   *   1. #sapx-card-grid  — static anchor planted in index.html
   *                          inside #cdb-panel-live, after #threat-grid
   *   2. Other known direct containers (by ID or class)
   *   3. Create #sapx-card-grid as next sibling of #threat-grid
   *      (inside #cdb-panel-live — the live intel tab panel)
   *   4. Append to #cdb-panel-live
   *   5. Append to #live-feed-section / #intel-section / etc.
   *   6. LAST RESORT: appendChild to body
   *      ⚠ NEVER insertBefore(body.firstChild) — that puts cards
   *        above the hero section (the regression we fixed).
   * ───────────────────────────────────────────────────────────── */
  function _findContainer() {
    var el;

    // ── Priority 1: static anchor planted in HTML ────────────────
    el = document.getElementById("sapx-card-grid");
    if (el) {
      console.info("[SAPX Integration] Container: #sapx-card-grid (static anchor)");
      return el;
    }

    // ── Priority 2: other known direct container IDs/classes ─────
    var knownSelectors = [
      "#advisory-grid",
      "#intel-card-grid",
      "#feed-container",
      ".intel-feed",
      "#advisory-list",
      "#v70-advisory-list",
      "#intel-list",
    ];
    for (var i = 0; i < knownSelectors.length; i++) {
      el = document.querySelector(knownSelectors[i]);
      if (el) {
        console.info("[SAPX Integration] Container:", knownSelectors[i]);
        return el;
      }
    }

    // ── Create dedicated container — insert at correct position ───
    var container = document.createElement("div");
    container.id = "sapx-card-grid";

    // ── Priority 3: insert as next sibling of #threat-grid ────────
    //    This places cards below the existing threat grid, still
    //    inside the #cdb-panel-live tab — the live intel section.
    var threatGrid = document.getElementById("threat-grid");
    if (threatGrid && threatGrid.parentNode) {
      threatGrid.parentNode.insertBefore(container, threatGrid.nextSibling);
      console.info("[SAPX Integration] Created #sapx-card-grid after #threat-grid (inside live intel panel)");
      return container;
    }

    // ── Priority 4: append inside the live intel tab panel ────────
    var livePanel = document.getElementById("cdb-panel-live");
    if (livePanel) {
      livePanel.appendChild(container);
      console.info("[SAPX Integration] Created #sapx-card-grid inside #cdb-panel-live");
      return container;
    }

    // ── Priority 5: append to a known intel section ───────────────
    var intelSection = document.querySelector(
      "#live-feed-section, #intel-section, .threat-cards-section, .content-area"
    );
    if (intelSection) {
      intelSection.appendChild(container);
      console.info("[SAPX Integration] Created #sapx-card-grid inside", intelSection.id || intelSection.className);
      return container;
    }

    // ── Priority 6: absolute last resort — APPEND, never prepend ──
    //    insertBefore(body.firstChild) caused the above-hero regression.
    //    appendChild is the safe fallback.
    document.body.appendChild(container);
    console.warn("[SAPX Integration] WARNING: Could not find live intel section. Appended to end of body. Check dashboard DOM.");
    return container;
  }

  /* ─────────────────────────────────────────────────────────────
   *  FETCH WITH FALLBACK CHAIN
   * ───────────────────────────────────────────────────────────── */
  async function _fetchWithFallbackChain() {
    var Adapter = window.SentinelApexAdapter;
    var urls = [CONFIG.API_URL].concat(CONFIG.FALLBACK_URLS);

    for (var i = 0; i < urls.length; i++) {
      var url = urls[i];
      console.info("[SAPX Integration] Trying URL:", url);
      var result = await Adapter.fetchAndNormalize(url, {
        maxRetry:  1,
        timeoutMs: 8000,
      });
      if (result.normalized && result.normalized.items.length > 0) {
        console.info("[SAPX Integration] Success from:", url, "| Items:", result.normalized.items.length);
        return result;
      }
    }

    console.warn("[SAPX Integration] All endpoints failed — showing empty state.");
    return { normalized: null, error: new Error("All endpoints failed"), cached: false };
  }

  /* ─────────────────────────────────────────────────────────────
   *  HEADER STATS INJECTION
   *  Updates existing dashboard stat counters with live API data
   * ───────────────────────────────────────────────────────────── */
  function _injectHeaderStats(normalized) {
    if (!normalized || !normalized.stats) return;
    var stats = normalized.stats;

    // Map of data attribute → value from stats
    var updates = [
      { selectors: ["#total-advisories", ".stat-total-count", "[data-stat='total']"],      val: normalized.total_in_feed || stats.total },
      { selectors: ["#critical-count", ".stat-critical", "[data-stat='critical']"],         val: stats.by_severity.CRITICAL || 0 },
      { selectors: ["#high-count", ".stat-high", "[data-stat='high']"],                     val: stats.by_severity.HIGH || 0 },
      { selectors: ["#medium-count", ".stat-medium", "[data-stat='medium']"],               val: stats.by_severity.MEDIUM || 0 },
      { selectors: ["#avg-risk", ".stat-avg-risk", "[data-stat='avg-risk']"],               val: stats.avg_risk },
      { selectors: ["#total-iocs", ".stat-total-iocs", "[data-stat='total-iocs']"],         val: stats.total_iocs },
      { selectors: ["#high-priority-count", "[data-stat='high-priority']"],                 val: stats.high_priority },
    ];

    updates.forEach(function (upd) {
      upd.selectors.forEach(function (sel) {
        var el = document.querySelector(sel);
        if (el && !el.dataset.sapxManaged) {
          el.dataset.sapxManaged = "1";
          el.textContent = upd.val;
        }
      });
    });

    // Update sync timestamp displays
    var syncTime = normalized.generated_at_fmt;
    var syncEls = document.querySelectorAll(".sync-time, #sync-time, [data-stat='sync-time'], #last-sync");
    syncEls.forEach(function (el) {
      if (!el.dataset.sapxManaged) {
        el.dataset.sapxManaged = "1";
        el.textContent = syncTime;
      }
    });
  }

  /* ─────────────────────────────────────────────────────────────
   *  FILTER BAR WIRING
   *  Connects existing dashboard filter controls to card renderer
   * ───────────────────────────────────────────────────────────── */
  function _wireFilterControls(container) {
    var Renderer = window.SentinelApexCardRenderer;

    // Severity filter buttons (existing: .filter-btn[data-filter])
    document.querySelectorAll("[data-filter]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var sev = btn.dataset.filter === "all" ? "" : btn.dataset.filter;
        Renderer.filterCards(container, { severity: sev });
        // Update active state
        document.querySelectorAll("[data-filter]").forEach(function (b) { b.classList.remove("active"); });
        btn.classList.add("active");
      });
    });

    // Sort controls
    document.querySelectorAll("[data-sort]").forEach(function (el) {
      el.addEventListener("change", function () {
        Renderer.sortCards(container, el.value);
      });
      el.addEventListener("click", function () {
        if (el.dataset.sort) Renderer.sortCards(container, el.dataset.sort);
      });
    });

    // Search input (existing: #threat-search, .search-input)
    var searchInput = document.querySelector("#threat-search, .search-input, [data-action='search']");
    if (searchInput) {
      var debounceTimer;
      searchInput.addEventListener("input", function () {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(function () {
          Renderer.filterCards(container, { search: searchInput.value });
        }, 300);
      });
    }
  }

  /* ─────────────────────────────────────────────────────────────
   *  MAIN RENDER CYCLE
   * ───────────────────────────────────────────────────────────── */
  async function render(container) {
    var Renderer = window.SentinelApexCardRenderer;

    // Show loading state
    Renderer.showLoadingState(container, CONFIG.LOADING_COUNT);

    // Fetch data
    var result = await _fetchWithFallbackChain();

    if (!result.normalized || result.normalized.items.length === 0) {
      container.innerHTML = [
        '<div style="text-align:center;padding:48px 24px;color:#64748b;">',
        '  <div style="font-size:36px;margin-bottom:12px;opacity:0.4;">🛡</div>',
        '  <div style="font-size:14px;font-weight:700;margin-bottom:6px;">No Threat Intelligence Available</div>',
        '  <div style="font-size:12px;">' + (result.cached ? "Displaying cached data — live feed unavailable." : "Feed is empty or API is offline.") + '</div>',
        '</div>'
      ].join("");
      return null;
    }

    // Render cards
    Renderer.renderGrid(container, result.normalized.items, {
      maxCards: CONFIG.MAX_CARDS,
    });

    // Inject stats into existing header widgets
    _injectHeaderStats(result.normalized);

    // Wire filter controls
    _wireFilterControls(container);

    // Fire event for other modules
    window.dispatchEvent(new CustomEvent("SentinelApexCardsReady", {
      detail: {
        normalized: result.normalized,
        cached:     result.cached,
        version:    CONFIG.VERSION,
      }
    }));

    console.info(
      "[SAPX Integration] Rendered " + result.normalized.items.length + " cards" +
      (result.cached ? " (cached)" : " (live)") +
      " | API v" + CONFIG.VERSION
    );

    return result.normalized;
  }

  /* ─────────────────────────────────────────────────────────────
   *  AUTO-REFRESH LOOP
   * ───────────────────────────────────────────────────────────── */
  var _refreshTimer = null;

  function _startAutoRefresh(container) {
    if (!CONFIG.AUTO_REFRESH_MS || CONFIG.AUTO_REFRESH_MS < 30000) return;
    _refreshTimer = setInterval(function () {
      console.info("[SAPX Integration] Auto-refresh triggered");
      render(container);
    }, CONFIG.AUTO_REFRESH_MS);
  }

  function _stopAutoRefresh() {
    if (_refreshTimer) {
      clearInterval(_refreshTimer);
      _refreshTimer = null;
    }
  }

  /* ─────────────────────────────────────────────────────────────
   *  INIT — waits for dependencies then bootstraps
   * ───────────────────────────────────────────────────────────── */
  async function init() {
    // Wait for both dependencies if they haven't loaded yet
    var retries = 0;
    while (!_checkDependencies() && retries < 20) {
      await new Promise(function (r) { setTimeout(r, 100); });
      retries++;
    }

    if (!_checkDependencies()) {
      console.error("[SAPX Integration] Dependencies not available after 2s. Aborting.");
      return;
    }

    var container = _findContainer();
    if (!container) {
      console.error("[SAPX Integration] No suitable container found and could not create one.");
      return;
    }

    // Initial render
    await render(container);

    // Auto-refresh
    _startAutoRefresh(container);

    // Expose manual control API
    window.SAPX = {
      refresh:        function () { return render(container); },
      filterCards:    function (filters) { window.SentinelApexCardRenderer.filterCards(container, filters); },
      sortCards:      function (by) { window.SentinelApexCardRenderer.sortCards(container, by); },
      stopRefresh:    _stopAutoRefresh,
      config:         CONFIG,
      version:        CONFIG.VERSION,
    };

    console.info("[SAPX Integration] Initialized v" + CONFIG.VERSION + " | SAPX object available on window");
  }

  /* ─────────────────────────────────────────────────────────────
   *  BOOT
   * ───────────────────────────────────────────────────────────── */
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    // DOMContentLoaded already fired
    setTimeout(init, 0);
  }

})();
