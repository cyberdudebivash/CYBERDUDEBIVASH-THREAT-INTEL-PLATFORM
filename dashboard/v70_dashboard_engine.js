/**
 * SENTINEL APEX v70 — Dashboard Intelligence Engine
 * ====================================================
 * Drop-in enhancement for existing dashboard (index.html).
 * Inject via <script src="dashboard/v70_dashboard_engine.js"></script>
 *
 * Features:
 *   - Retry fetch (3 attempts with exponential backoff)
 *   - LocalStorage cache fallback (previous data)
 *   - Client-side deduplication
 *   - Filtering (CVE, actor, severity, threat type)
 *   - Full-text search
 *   - Confidence & threat score visualization
 *   - Correlation indicators (linked threats)
 *   - Never renders empty dashboard
 *
 * ZERO REGRESSION: Only adds new capabilities; does not remove existing.
 */

(function () {
  "use strict";

  const V70_CONFIG = {
    MANIFEST_URL: "data/feed_manifest.json",
    CACHE_KEY: "sentinel_apex_v70_manifest_cache",
    CACHE_TS_KEY: "sentinel_apex_v70_cache_ts",
    MAX_RETRY: 3,
    RETRY_BASE_MS: 1000,
    CACHE_MAX_AGE_MS: 3600000, // 1 hour
    DEDUP_ENABLED: true,
    DEFAULT_SORT: "threat_score_desc",
  };

  // ─── State ───
  let _allAdvisories = [];
  let _filteredAdvisories = [];
  let _filters = {
    severity: "",
    threatType: "",
    cve: "",
    actor: "",
    search: "",
  };
  let _sortBy = V70_CONFIG.DEFAULT_SORT;

  // ─── Retry Fetch with Backoff ───
  async function fetchWithRetry(url, maxRetry, baseMs) {
    let lastError = null;
    for (let attempt = 1; attempt <= maxRetry; attempt++) {
      try {
        const resp = await fetch(url + "?t=" + Date.now(), {
          cache: "no-store",
        });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        if (data && data.advisories && Array.isArray(data.advisories)) {
          // Cache on success
          try {
            localStorage.setItem(
              V70_CONFIG.CACHE_KEY,
              JSON.stringify(data)
            );
            localStorage.setItem(
              V70_CONFIG.CACHE_TS_KEY,
              Date.now().toString()
            );
          } catch (e) {
            /* localStorage quota — non-fatal */
          }
          return data;
        }
        throw new Error("Invalid manifest structure");
      } catch (err) {
        lastError = err;
        console.warn(
          `[SENTINEL v70] Fetch attempt ${attempt}/${maxRetry} failed: ${err.message}`
        );
        if (attempt < maxRetry) {
          const delay = baseMs * Math.pow(2, attempt - 1);
          await new Promise((r) => setTimeout(r, delay));
        }
      }
    }
    // All retries failed — try cache
    console.warn("[SENTINEL v70] All fetch attempts failed. Trying cache...");
    return loadFromCache();
  }

  function loadFromCache() {
    try {
      const cached = localStorage.getItem(V70_CONFIG.CACHE_KEY);
      if (!cached) return null;
      const data = JSON.parse(cached);
      if (data && data.advisories && Array.isArray(data.advisories)) {
        console.info("[SENTINEL v70] Loaded from cache fallback");
        return data;
      }
    } catch (e) {
      /* corrupt cache — ignore */
    }
    return null;
  }

  // ─── Client-Side Deduplication ───
  function deduplicateAdvisories(advisories) {
    if (!V70_CONFIG.DEDUP_ENABLED) return advisories;
    const seen = new Map();
    const result = [];
    for (const adv of advisories) {
      // Primary key: dedup_key (if present), else title+source hash
      let key = adv.dedup_key || "";
      if (!key) {
        const raw = (adv.title || "").toLowerCase().trim() + "|" + (adv.link || adv.source_url || "");
        key = simpleHash(raw);
      }
      if (seen.has(key)) {
        // Merge: keep higher score version
        const existing = seen.get(key);
        if ((adv.threat_score || 0) > (existing.threat_score || 0)) {
          seen.set(key, mergeAdvisory(adv, existing));
          // Replace in result
          const idx = result.indexOf(existing);
          if (idx >= 0) result[idx] = seen.get(key);
        } else {
          seen.set(key, mergeAdvisory(existing, adv));
        }
      } else {
        seen.set(key, adv);
        result.push(adv);
      }
    }
    return result;
  }

  function mergeAdvisory(primary, secondary) {
    // Merge IOCs, CVEs, actors
    const merged = Object.assign({}, primary);
    if (secondary.cves) {
      merged.cves = [...new Set([...(primary.cves || []), ...secondary.cves])];
    }
    if (secondary.iocs) {
      const existingVals = new Set((primary.iocs || []).map((i) => (typeof i === "string" ? i : i.value || "")));
      for (const ioc of secondary.iocs || []) {
        const val = typeof ioc === "string" ? ioc : ioc.value || "";
        if (!existingVals.has(val)) {
          merged.iocs = merged.iocs || [];
          merged.iocs.push(ioc);
        }
      }
    }
    if (secondary.actors) {
      merged.actors = [...new Set([...(primary.actors || []), ...(secondary.actors || [])])];
    }
    return merged;
  }

  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    return "h" + Math.abs(hash).toString(36);
  }

  // ─── Filtering ───
  function applyFilters(advisories) {
    let result = advisories;

    if (_filters.severity) {
      result = result.filter(
        (a) => (a.severity || "").toLowerCase() === _filters.severity.toLowerCase()
      );
    }
    if (_filters.threatType) {
      result = result.filter(
        (a) => (a.threat_type || "").toLowerCase() === _filters.threatType.toLowerCase()
      );
    }
    if (_filters.cve) {
      const cveLower = _filters.cve.toUpperCase();
      result = result.filter((a) =>
        (a.cves || []).some((c) => c.toUpperCase().includes(cveLower))
      );
    }
    if (_filters.actor) {
      const actorLower = _filters.actor.toLowerCase();
      result = result.filter((a) =>
        (a.actors || []).some((ac) => ac.toLowerCase().includes(actorLower))
      );
    }
    if (_filters.search) {
      const q = _filters.search.toLowerCase();
      result = result.filter(
        (a) =>
          (a.title || "").toLowerCase().includes(q) ||
          (a.description || "").toLowerCase().includes(q) ||
          (a.ai_summary || "").toLowerCase().includes(q) ||
          (a.cves || []).some((c) => c.toLowerCase().includes(q)) ||
          (a.actors || []).some((ac) => ac.toLowerCase().includes(q))
      );
    }

    return result;
  }

  // ─── Sorting ───
  function sortAdvisories(advisories) {
    const arr = [...advisories];
    switch (_sortBy) {
      case "threat_score_desc":
        return arr.sort((a, b) => (b.threat_score || 0) - (a.threat_score || 0));
      case "threat_score_asc":
        return arr.sort((a, b) => (a.threat_score || 0) - (b.threat_score || 0));
      case "confidence_desc":
        return arr.sort((a, b) => (b.confidence || 0) - (a.confidence || 0));
      case "date_desc":
        return arr.sort((a, b) => new Date(b.published || 0) - new Date(a.published || 0));
      case "date_asc":
        return arr.sort((a, b) => new Date(a.published || 0) - new Date(b.published || 0));
      default:
        return arr;
    }
  }

  // ─── Severity Color ───
  function sevColor(sev) {
    const colors = {
      critical: "#dc2626",
      high: "#ea580c",
      medium: "#ca8a04",
      low: "#2563eb",
      info: "#6b7280",
    };
    return colors[(sev || "").toLowerCase()] || "#6b7280";
  }

  function confidenceBadge(conf) {
    if (conf >= 85) return '<span style="color:#16a34a;font-weight:bold;">CONFIRMED</span>';
    if (conf >= 65) return '<span style="color:#2563eb;font-weight:bold;">HIGH</span>';
    if (conf >= 40) return '<span style="color:#ca8a04;font-weight:bold;">MODERATE</span>';
    if (conf >= 15) return '<span style="color:#ea580c;font-weight:bold;">LOW</span>';
    return '<span style="color:#6b7280;font-weight:bold;">UNVERIFIED</span>';
  }

  // ─── Render Filter Bar ───
  function renderFilterBar(container) {
    const bar = document.createElement("div");
    bar.id = "v70-filter-bar";
    bar.style.cssText =
      "display:flex;flex-wrap:wrap;gap:8px;padding:12px;background:rgba(0,0,0,0.3);border-radius:8px;margin-bottom:16px;align-items:center;";

    bar.innerHTML = `
      <input type="text" id="v70-search" placeholder="🔍 Search advisories..."
        style="flex:1;min-width:200px;padding:8px 12px;border:1px solid #444;border-radius:4px;background:#1a1a2e;color:#e0e0e0;font-size:0.9em;">
      <select id="v70-filter-severity"
        style="padding:8px;border:1px solid #444;border-radius:4px;background:#1a1a2e;color:#e0e0e0;">
        <option value="">All Severities</option>
        <option value="critical">🔴 Critical</option>
        <option value="high">🟠 High</option>
        <option value="medium">🟡 Medium</option>
        <option value="low">🔵 Low</option>
        <option value="info">⚪ Info</option>
      </select>
      <select id="v70-filter-type"
        style="padding:8px;border:1px solid #444;border-radius:4px;background:#1a1a2e;color:#e0e0e0;">
        <option value="">All Types</option>
        <option value="vulnerability">Vulnerability</option>
        <option value="malware">Malware</option>
        <option value="campaign">Campaign</option>
        <option value="threat-report">Threat Report</option>
      </select>
      <input type="text" id="v70-filter-cve" placeholder="CVE-YYYY-NNNNN"
        style="width:140px;padding:8px;border:1px solid #444;border-radius:4px;background:#1a1a2e;color:#e0e0e0;font-size:0.85em;">
      <select id="v70-sort"
        style="padding:8px;border:1px solid #444;border-radius:4px;background:#1a1a2e;color:#e0e0e0;">
        <option value="threat_score_desc">Score ↓</option>
        <option value="threat_score_asc">Score ↑</option>
        <option value="confidence_desc">Confidence ↓</option>
        <option value="date_desc">Newest</option>
        <option value="date_asc">Oldest</option>
      </select>
      <span id="v70-count" style="color:#aaa;font-size:0.85em;margin-left:8px;"></span>
    `;

    container.prepend(bar);

    // Event listeners
    const debounce = (fn, ms) => {
      let t;
      return (...a) => {
        clearTimeout(t);
        t = setTimeout(() => fn(...a), ms);
      };
    };

    document.getElementById("v70-search").addEventListener(
      "input",
      debounce((e) => {
        _filters.search = e.target.value;
        refreshDisplay();
      }, 300)
    );
    document.getElementById("v70-filter-severity").addEventListener("change", (e) => {
      _filters.severity = e.target.value;
      refreshDisplay();
    });
    document.getElementById("v70-filter-type").addEventListener("change", (e) => {
      _filters.threatType = e.target.value;
      refreshDisplay();
    });
    document.getElementById("v70-filter-cve").addEventListener(
      "input",
      debounce((e) => {
        _filters.cve = e.target.value;
        refreshDisplay();
      }, 300)
    );
    document.getElementById("v70-sort").addEventListener("change", (e) => {
      _sortBy = e.target.value;
      refreshDisplay();
    });
  }

  function updateCount() {
    const el = document.getElementById("v70-count");
    if (el) {
      el.textContent = `${_filteredAdvisories.length} / ${_allAdvisories.length} advisories`;
    }
  }

  // ─── Render Advisory Card (Enhanced) ───
  function renderAdvisoryCard(adv) {
    const sev = (adv.severity || "info").toLowerCase();
    const color = sevColor(sev);
    const score = adv.threat_score || 0;
    const conf = adv.confidence || 0;
    const related = adv.related_advisories || [];
    const cves = (adv.cves || []).slice(0, 5);
    const techniques = (adv.mitre_techniques || []).slice(0, 4);
    const actors = (adv.actors || []).slice(0, 3);
    const tags = (adv.tags || []).slice(0, 5);
    const riskLevel = adv.risk_level || sev.toUpperCase();
    const aiSummary = adv.ai_summary || adv.description || "";
    const clusterBadge = adv.ai_cluster_id && !adv.ai_cluster_id.includes("singleton")
      ? `<span style="background:#3b0764;color:#c084fc;padding:2px 6px;border-radius:3px;font-size:0.75em;">📎 Cluster: ${escHtml(adv.ai_cluster_id)}</span>`
      : "";

    // Score bar
    const scoreBarColor = score >= 80 ? "#dc2626" : score >= 60 ? "#ea580c" : score >= 35 ? "#ca8a04" : "#2563eb";

    const card = document.createElement("div");
    card.className = "v70-advisory-card";
    card.style.cssText = `
      border-left:4px solid ${color};padding:16px;margin-bottom:12px;
      background:rgba(0,0,0,0.25);border-radius:6px;
      transition:background 0.2s;cursor:pointer;
    `;
    card.addEventListener("mouseenter", () => card.style.background = "rgba(0,0,0,0.4)");
    card.addEventListener("mouseleave", () => card.style.background = "rgba(0,0,0,0.25)");

    let cveHtml = cves.map((c) => `<a href="https://nvd.nist.gov/vuln/detail/${escHtml(c)}" target="_blank" style="color:#60a5fa;text-decoration:none;font-size:0.85em;">${escHtml(c)}</a>`).join(" ");
    let techHtml = techniques.map((t) => `<span style="background:#1e3a5f;color:#93c5fd;padding:1px 5px;border-radius:3px;font-size:0.75em;">${escHtml(t)}</span>`).join(" ");
    let actorHtml = actors.map((a) => `<span style="background:#3b1d0e;color:#fdba74;padding:1px 5px;border-radius:3px;font-size:0.75em;">🎭 ${escHtml(a)}</span>`).join(" ");
    let tagHtml = tags.map((t) => `<span style="background:#1a2e1a;color:#86efac;padding:1px 5px;border-radius:3px;font-size:0.75em;">${escHtml(t)}</span>`).join(" ");
    let relatedHtml = related.length > 0
      ? `<span style="color:#a78bfa;font-size:0.8em;">🔗 ${related.length} related</span>`
      : "";

    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;">
        <div style="flex:1;">
          <h4 style="margin:0 0 6px 0;color:#f0f0f0;font-size:1em;">${escHtml(adv.title || "Untitled")}</h4>
          <p style="margin:0 0 8px 0;color:#aaa;font-size:0.85em;line-height:1.4;">
            ${escHtml(aiSummary.substring(0, 250))}${aiSummary.length > 250 ? "..." : ""}
          </p>
          <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:6px;">
            ${cveHtml} ${techHtml} ${actorHtml}
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:4px;">
            ${tagHtml} ${clusterBadge} ${relatedHtml}
          </div>
        </div>
        <div style="min-width:120px;text-align:right;">
          <div style="font-size:1.4em;font-weight:bold;color:${scoreBarColor};">${score}</div>
          <div style="font-size:0.7em;color:#888;">THREAT SCORE</div>
          <div style="width:100%;height:4px;background:#333;border-radius:2px;margin:4px 0;">
            <div style="width:${Math.min(score, 100)}%;height:100%;background:${scoreBarColor};border-radius:2px;"></div>
          </div>
          <div style="font-size:0.8em;margin-top:4px;">${confidenceBadge(conf)}</div>
          <div style="font-size:0.7em;color:#888;">${conf.toFixed(1)}% confidence</div>
          <div style="margin-top:4px;padding:2px 8px;background:${color}22;color:${color};border-radius:3px;font-size:0.75em;font-weight:bold;display:inline-block;">${riskLevel}</div>
        </div>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;padding-top:8px;border-top:1px solid #333;">
        <span style="color:#666;font-size:0.8em;">${escHtml(adv.source || adv.source_name || "")} · ${escHtml(adv.published || adv.published_date || "")}</span>
        ${adv.link || adv.source_url ? `<a href="${escHtml(adv.link || adv.source_url)}" target="_blank" style="color:#60a5fa;font-size:0.8em;">View Source →</a>` : ""}
      </div>
    `;

    return card;
  }

  function escHtml(str) {
    const div = document.createElement("div");
    div.textContent = str || "";
    return div.innerHTML;
  }

  // ─── Stats Banner ───
  function renderStatsBanner(container, manifest) {
    const advisories = manifest.advisories || [];
    const totalCves = new Set(advisories.flatMap((a) => a.cves || [])).size;
    const totalIocs = advisories.reduce((s, a) => s + (a.iocs || []).length, 0);
    const critCount = advisories.filter((a) => (a.severity || "").toLowerCase() === "critical").length;
    const highCount = advisories.filter((a) => (a.severity || "").toLowerCase() === "high").length;
    const avgScore = advisories.length > 0
      ? (advisories.reduce((s, a) => s + (a.threat_score || 0), 0) / advisories.length).toFixed(1)
      : "0";

    const banner = document.createElement("div");
    banner.id = "v70-stats-banner";
    banner.style.cssText = "display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:16px;";
    const stats = [
      { label: "Advisories", value: advisories.length, color: "#818cf8" },
      { label: "CVEs Tracked", value: totalCves, color: "#60a5fa" },
      { label: "IOCs Extracted", value: totalIocs, color: "#34d399" },
      { label: "Critical", value: critCount, color: "#dc2626" },
      { label: "High", value: highCount, color: "#ea580c" },
      { label: "Avg Score", value: avgScore, color: "#fbbf24" },
    ];

    banner.innerHTML = stats
      .map(
        (s) => `
      <div style="background:rgba(0,0,0,0.3);padding:12px;border-radius:6px;text-align:center;">
        <div style="font-size:1.6em;font-weight:bold;color:${s.color};">${s.value}</div>
        <div style="font-size:0.8em;color:#888;">${s.label}</div>
      </div>`
      )
      .join("");

    container.appendChild(banner);
  }

  // ─── Main Render ───
  function refreshDisplay() {
    _filteredAdvisories = applyFilters(_allAdvisories);
    _filteredAdvisories = sortAdvisories(_filteredAdvisories);
    updateCount();

    const container = document.getElementById("v70-advisory-list");
    if (!container) return;
    container.innerHTML = "";

    if (_filteredAdvisories.length === 0) {
      container.innerHTML = `
        <div style="text-align:center;padding:40px;color:#888;">
          <p style="font-size:1.2em;">No advisories match current filters.</p>
          <p style="font-size:0.9em;">Try adjusting your search or filter criteria.</p>
        </div>`;
      return;
    }

    for (const adv of _filteredAdvisories) {
      container.appendChild(renderAdvisoryCard(adv));
    }
  }

  // ─── Initialize ───
  async function initV70Dashboard() {
    console.info("[SENTINEL v70] Dashboard Intelligence Engine initializing...");

    const manifest = await fetchWithRetry(
      V70_CONFIG.MANIFEST_URL,
      V70_CONFIG.MAX_RETRY,
      V70_CONFIG.RETRY_BASE_MS
    );

    if (!manifest || !manifest.advisories || manifest.advisories.length === 0) {
      console.error("[SENTINEL v70] No data available — cannot render.");
      // DO NOT render empty — show last cached or error
      const cached = loadFromCache();
      if (cached && cached.advisories && cached.advisories.length > 0) {
        console.info("[SENTINEL v70] Using stale cache as emergency fallback");
        return bootstrapDashboard(cached);
      }
      // Absolute fallback: show error state
      const main = document.querySelector("main") || document.body;
      const errDiv = document.createElement("div");
      errDiv.style.cssText = "padding:40px;text-align:center;color:#ef4444;";
      errDiv.innerHTML = `<h3>⚠️ Threat Feed Temporarily Unavailable</h3><p>Data sync in progress. Please refresh in a few minutes.</p>`;
      main.appendChild(errDiv);
      return;
    }

    bootstrapDashboard(manifest);
  }

  function bootstrapDashboard(manifest) {
    // Deduplicate
    _allAdvisories = deduplicateAdvisories(manifest.advisories);
    console.info(
      `[SENTINEL v70] Loaded ${manifest.advisories.length} → ${_allAdvisories.length} after dedup`
    );

    // Find or create container
    let container = document.getElementById("v70-dashboard-root");
    if (!container) {
      container = document.createElement("div");
      container.id = "v70-dashboard-root";
      const main = document.querySelector("main") || document.body;
      main.appendChild(container);
    }

    // Render stats
    renderStatsBanner(container, { advisories: _allAdvisories });

    // Render filter bar
    renderFilterBar(container);

    // Advisory list container
    let listContainer = document.getElementById("v70-advisory-list");
    if (!listContainer) {
      listContainer = document.createElement("div");
      listContainer.id = "v70-advisory-list";
      container.appendChild(listContainer);
    }

    // Initial render
    refreshDisplay();

    // Update sync time
    const syncEl = document.getElementById("v70-sync-time");
    if (syncEl) {
      syncEl.textContent = new Date().toISOString();
    }

    console.info("[SENTINEL v70] Dashboard Intelligence Engine ready ✓");
  }

  // ─── Auto-Initialize ───
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initV70Dashboard);
  } else {
    initV70Dashboard();
  }

  // Export for external use
  window.SentinelV70 = {
    refresh: initV70Dashboard,
    getAdvisories: () => _allAdvisories,
    getFiltered: () => _filteredAdvisories,
    setFilter: (key, val) => {
      _filters[key] = val;
      refreshDisplay();
    },
    setSort: (s) => {
      _sortBy = s;
      refreshDisplay();
    },
  };
})();
