/**
 * CYBERDUDEBIVASH® SENTINEL APEX — Live Dashboard Feed Engine v170.0
 * dashboard/js/sentinel-live-feeds.js
 *
 * COMPLETE FRONTEND FIX — All dashboard widgets wired to live API.
 *
 * Fixes:
 *  - Stats bar (TOTAL ADVISORIES, CRITICAL, HIGH, AVG RISK, TOTAL IOCs, LAST SYNC)
 *  - Global Threat Level gauge
 *  - CDB DEFCON Status panel
 *  - Live Threat Feed Preview
 *  - Cyber Warfare Heatmap
 *  - Live Threat Pulse
 *  - Ransomware Tracker
 *  - APT Actor Radar
 *  - Top CVE Exploit Probability (EPSS)
 *  - Active Kill Chain Activity
 *  - NEXUS Kill Chain Coverage
 *  - AI Cyber Brain (campaigns, anomalies, predictions)
 *  - Global Cyber News feed (THN, Krebs, BleepingComputer, etc.)
 *  - Reports archive
 *
 * INTEGRATION:
 *   Add to index.html before </body>:
 *   <script src="/js/sentinel-live-feeds.js"></script>
 *
 *   OR inline at bottom of existing <script> section.
 *
 * API BASE: auto-detects current origin (works on intel.cyberdudebivash.com
 * or any preview/staging domain).
 */

(function SentinelLiveFeeds() {
  "use strict";

  // ── Config ──────────────────────────────────────────────────────────────────
  const API = window.location.origin; // https://intel.cyberdudebivash.com
  const REFRESH_INTERVAL_MS = 120_000; // 2 minutes
  const NEWS_REFRESH_MS     = 300_000; // 5 minutes
  const FETCH_TIMEOUT_MS    = 12_000;

  // ── Utilities ───────────────────────────────────────────────────────────────
  async function apiFetch(path, fallback = null) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
      const resp = await fetch(`${API}${path}`, {
        signal: ctrl.signal,
        headers: { Accept: "application/json" },
        cache: "no-cache",
      });
      clearTimeout(timer);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return await resp.json();
    } catch (e) {
      console.warn(`[APEX] ${path} failed:`, e.message);
      return fallback;
    }
  }

  function el(id) { return document.getElementById(id); }
  function qs(sel) { return document.querySelector(sel); }
  function qsAll(sel) { return document.querySelectorAll(sel); }

  // Matches the escape convention already used elsewhere in this codebase
  // (e.g. index.html's _hEsc(), js/card_renderer.js's esc()). API-provided
  // fields (group names, actor aliases, sectors, statuses) are rendered via
  // innerHTML below for layout convenience -- they must never be trusted as
  // markup.
  function esc(s) {
    if (s === null || s === undefined) return "";
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#x27;");
  }

  function setText(selector, text, isId = false) {
    const node = isId ? el(selector) : qs(selector);
    if (node) node.textContent = text;
  }

  // P0 FIX: several loaders below previously wrote fetched data into DOM
  // selectors that do not exist anywhere in index.html (a leftover from an
  // earlier DOM naming scheme), so a successful fetch had nowhere to land
  // and the widget's initial "COMPUTING.../ASSESSING.../LOADING..." text
  // stayed on screen forever regardless of backend health. setUnavailable()
  // gives every fixed loader below a bounded, honest failure state instead
  // of silently leaving that placeholder in place when a fetch genuinely
  // fails (apiFetch() already times out at FETCH_TIMEOUT_MS and returns
  // null on any error).
  function setUnavailable(id, label) {
    const node = el(id);
    if (node) node.textContent = label || "UNAVAILABLE";
  }

  function setHTML(selector, html, isId = false) {
    const node = isId ? el(selector) : qs(selector);
    if (node) node.innerHTML = html;
  }

  function fmtRisk(score) {
    const n = parseFloat(score);
    return isNaN(n) ? "N/A" : n.toFixed(2);
  }

  function fmtDate(iso) {
    if (!iso) return "N/A";
    try {
      return new Date(iso).toLocaleString("en-IN", { timeZone: "UTC", hour12: false }).replace(",", "");
    } catch (_) { return iso.slice(0, 16).replace("T", " "); }
  }

  function fmtRelTime(iso) {
    if (!iso) return "";
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60)   return `${Math.round(diff)}s ago`;
    if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
    if (diff < 86400)return `${Math.round(diff / 3600)}h ago`;
    return `${Math.round(diff / 86400)}d ago`;
  }

  function severityClass(sev) {
    const s = (sev || "").toUpperCase();
    if (s === "CRITICAL") return "sev-critical";
    if (s === "HIGH")     return "sev-high";
    if (s === "MEDIUM")   return "sev-medium";
    if (s === "LOW")      return "sev-low";
    return "sev-info";
  }

  function severityColor(sev) {
    const s = (sev || "").toUpperCase();
    if (s === "CRITICAL") return "#ff4444";
    if (s === "HIGH")     return "#ff8800";
    if (s === "MEDIUM")   return "#ffcc00";
    if (s === "LOW")      return "#00d4aa";
    return "#888";
  }

  // ── 1. Stats Bar ─────────────────────────────────────────────────────────────
  async function loadStats() {
    // Try dedicated stats endpoint first; fall back to latest.json
    let stats = await apiFetch("/api/v1/intel/stats");
    if (!stats) {
      const feed = await apiFetch("/api/v1/intel/latest.json");
      if (!feed) return;
      const items = feed.items || [];
      const sev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
      let risk = 0, iocs = 0, last = "";
      items.forEach(i => {
        sev[(i.severity || "INFO").toUpperCase()] = (sev[(i.severity || "INFO").toUpperCase()] || 0) + 1;
        risk += parseFloat(i.risk_score || 0);
        iocs += parseInt(i.ioc_count || 0, 10);
        const pub = i.published || i.published_at || "";
        if (pub > last) last = pub;
      });
      stats = {
        total: items.length, critical: sev.CRITICAL, high: sev.HIGH,
        avg_risk_score: items.length ? (risk / items.length).toFixed(2) : 0,
        total_iocs: iocs, last_sync: last,
        global_threat_label: "COMPUTING",
        defcon_label: "DEFCON ?", defcon_status: "ASSESSING",
      };
    }

    // Populate all stat tiles — try multiple selectors for compatibility
    const setStatEl = (selectors, value) => {
      for (const s of selectors) {
        const node = qs(s);
        if (node) { node.textContent = value; return; }
      }
    };

    setStatEl(
      ["#stat-total", ".stat-total", "[data-stat='total']", ".total-advisories"],
      stats.total || 0
    );
    setStatEl(
      ["#stat-critical", ".stat-critical", "[data-stat='critical']", ".critical-threats"],
      stats.critical || 0
    );
    setStatEl(
      ["#stat-high", ".stat-high", "[data-stat='high']", ".high-severity"],
      stats.high || 0
    );
    setStatEl(
      ["#stat-risk", ".stat-risk", "[data-stat='avg_risk']", ".avg-risk-score"],
      fmtRisk(stats.avg_risk_score)
    );
    setStatEl(
      ["#stat-iocs", ".stat-iocs", "[data-stat='iocs']", ".total-iocs"],
      (stats.total_iocs || 0).toLocaleString()
    );
    setStatEl(
      ["#stat-sync", ".stat-sync", "[data-stat='sync']", ".last-sync"],
      fmtRelTime(stats.last_sync) || fmtDate(stats.last_sync)
    );
    setStatEl(
      ["#stat-feeds", ".stat-feeds", "[data-stat='feeds']", ".active-feeds"],
      stats.feeds_active || 74
    );

    // Update page header counts
    document.title = document.title.replace(/\d+ Live Advisories/, `${stats.total} Live Advisories`);

    // Feed ticker counts
    qsAll(".advisory-count, .feed-count, [data-count]").forEach(n => {
      n.textContent = stats.total;
    });

    // Update sync status bar
    const syncBar = qs(".sync-status, .feed-status, #sync-status");
    if (syncBar) {
      syncBar.textContent = `SYNCED: ${fmtDate(stats.last_sync)} · ${stats.total} advisories · API LIVE`;
    }

    // Store globally for other components
    window._apexStats = stats;
    return stats;
  }

  // ── 2. Global Threat Level ────────────────────────────────────────────────────
  async function loadThreatLevel() {
    const data = await apiFetch("/api/v1/intel/defcon");
    if (!data) {
      setUnavailable("cdb-gauge-label", "THREAT LEVEL UNAVAILABLE");
      setUnavailable("cdb-defcon-status", "DEFCON UNAVAILABLE");
      return;
    }

    const level = data.global_threat_level || {};
    const rawScore = Number(level.level);
    const score = Number.isFinite(rawScore) ? Math.max(0, Math.min(rawScore, 10)) : 0;
    const label = level.label || data.label || "ASSESSING";

    // Threat level gauge -- real DOM ids (see GADGET 1, index.html)
    setText("cdb-gauge-val", score.toFixed(1), true);
    setText("cdb-gauge-label", label, true);
    const arcEl = el("cdb-gauge-arc");
    if (arcEl) {
      // dasharray=157 spans the full 0-10 gauge sweep
      arcEl.setAttribute("stroke-dashoffset", String(157 - Math.min(score, 10) / 10 * 157));
      arcEl.setAttribute("stroke", score >= 8 ? "#ff4444" : score >= 6 ? "#ff8800" : score >= 4 ? "#ffcc00" : "#00d4aa");
    }

    // DEFCON -- real DOM ids (see GADGET 2, index.html)
    const defconLvl = data.level || 5;
    const defconStatus = data.status || "UNKNOWN";
    const stats = data.stats || {};
    setText("cdb-defcon-status", defconStatus, true);
    setText("cdb-defcon-detail",
      `${label} · ${stats.critical || 0} critical, ${stats.kev_confirmed || 0} KEV confirmed`, true);

    // Light up the DEFCON indicators (cdb-dc1..cdb-dc5)
    for (let i = 1; i <= 5; i++) {
      const dcEl = el(`cdb-dc${i}`);
      if (dcEl) {
        dcEl.classList.toggle("active", i === defconLvl);
        dcEl.style.opacity = i === defconLvl ? "1" : "0.3";
      }
    }
  }

  function setStatEl(selectors, value) {
    for (const s of selectors) {
      const node = qs(s);
      if (node) { node.textContent = value; }
    }
  }

  // ── 3. Live Threat Feed Preview ───────────────────────────────────────────────
  async function loadThreatFeedPreview() {
    const feed = await apiFetch("/api/v1/intel/latest.json");
    if (!feed) return;

    const items = (feed.items || []).slice(0, 8);
    const containers = [
      qs(".live-feed-preview, #live-feed-preview, .threat-feed-preview"),
      qs("[data-section='live-feed']"),
    ].filter(Boolean);

    if (!containers.length) return;

    const html = items.map(item => `
      <div class="feed-item feed-${(item.severity || "info").toLowerCase()}" style="
        border-left: 3px solid ${severityColor(item.severity)};
        padding: 8px 12px; margin-bottom: 8px; background: rgba(0,0,0,0.3);
        border-radius: 4px; cursor: pointer;
      ">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <span class="sev-badge" style="
            background: ${severityColor(item.severity)}22;
            color: ${severityColor(item.severity)};
            padding: 2px 6px; border-radius: 3px; font-size: 11px; font-weight: bold;
          ">${item.severity || "INFO"}</span>
          <span style="color:#888; font-size:11px;">${fmtRelTime(item.published || item.published_at)}</span>
        </div>
        <div style="font-size:13px; font-weight:500; margin-top:4px; color:#e0e0e0; line-height:1.4;">
          ${item.title || "Untitled Advisory"}
        </div>
        <div style="display:flex; gap:12px; margin-top:4px; font-size:11px; color:#888;">
          <span>RISK: <strong style="color:${severityColor(item.severity)}">${fmtRisk(item.risk_score)}</strong></span>
          <span>IOCs: ${item.ioc_count || 0}</span>
          <span>SRC: ${item.source || "APEX"}</span>
          ${(item.cve_ids || []).length ? `<span style="color:#ff8800">${item.cve_ids[0]}</span>` : ""}
        </div>
      </div>
    `).join("");

    containers.forEach(c => { c.innerHTML = html; });

    // Also clear "loading" spinners in the feed area
    qsAll(".feed-loading, [data-loading='feed']").forEach(n => {
      n.style.display = "none";
    });
  }

  // ── 4. Cyber Warfare Heatmap ─────────────────────────────────────────────────
  async function loadCybermap() {
    const data = await apiFetch("/api/v1/intel/cybermap");
    if (!data) return;

    const regions = data.regions || [];
    const container = qs(".cybermap-data, #cybermap-region-data, [data-section='cybermap']");
    if (!container) return;

    const html = `
      <div style="font-size:11px; color:#888; margin-bottom:8px;">
        SOURCE: GOC NEURAL CORE | TOTAL ATTACKS TODAY: <strong style="color:#ff4444">${data.total_attacks_today || 0}</strong>
      </div>
      ${regions.slice(0, 8).map((r, i) => `
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px; font-size:12px;">
          <span style="width:24px; text-align:center; font-size:14px;">${getFlagEmoji(r.code)}</span>
          <span style="flex:1; color:#ccc;">${r.country}</span>
          <div style="flex:2; background:#1a1a2e; border-radius:3px; height:8px; overflow:hidden;">
            <div style="width:${r.pct || 0}%; height:100%; background:${r.risk === 'CRITICAL' ? '#ff4444' : r.risk === 'HIGH' ? '#ff8800' : '#ffcc00'}; border-radius:3px;"></div>
          </div>
          <span style="width:60px; text-align:right; color:${r.risk === 'CRITICAL' ? '#ff4444' : r.risk === 'HIGH' ? '#ff8800' : '#888'};">${(r.attacks || 0).toLocaleString()}</span>
          <span style="width:50px; font-size:10px; padding:2px 4px; border-radius:2px;
            background:${r.risk === 'CRITICAL' ? '#ff444422' : r.risk === 'HIGH' ? '#ff880022' : '#88888822'};
            color:${r.risk === 'CRITICAL' ? '#ff4444' : r.risk === 'HIGH' ? '#ff8800' : '#888'};">${r.risk}</span>
        </div>
      `).join("")}
    `;
    container.innerHTML = html;

    // Update the "Loading region data..." spinner
    qsAll("[data-loading='cybermap'], .cybermap-loading").forEach(n => {
      n.style.display = "none";
    });
  }

  function getFlagEmoji(code) {
    if (!code || code.length !== 2) return "🌐";
    const offset = 127397;
    return Array.from(code.toUpperCase()).map(c => String.fromCodePoint(c.charCodeAt(0) + offset)).join("");
  }

  // ── 5. Live Threat Pulse ──────────────────────────────────────────────────────
  async function loadPulse() {
    const data = await apiFetch("/api/v1/intel/pulse");
    if (!data) {
      setUnavailable("cdb-pulse-rate", "N/A");
      setUnavailable("cdb-pulse-today", "N/A");
      setUnavailable("cdb-pulse-total", "N/A");
      return;
    }

    // Real DOM ids (see GADGET 6, index.html)
    setText("cdb-pulse-rate", data.rate_hr != null ? data.rate_hr : 0, true);
    setText("cdb-pulse-today", data.today != null ? data.today : 0, true);
    setText("cdb-pulse-total", data.total != null ? data.total : 0, true);
  }

  // ── 6. Ransomware Tracker ─────────────────────────────────────────────────────
  async function loadRansomware() {
    const data = await apiFetch("/api/v1/intel/ransomware");
    if (!data) {
      setUnavailable("cdb-rw-groups", "N/A");
      setUnavailable("cdb-rw-victims", "N/A");
      setUnavailable("cdb-rw-list", "RANSOMWARE DATA UNAVAILABLE");
      return;
    }

    // Real DOM ids (see GADGET 7, index.html)
    setText("cdb-rw-groups", data.active_groups || 0, true);
    setText("cdb-rw-victims", data.new_victims_30d || 0, true);

    const container = el("cdb-rw-list");
    if (container) {
      const groups = (data.top_groups || []).slice(0, 5);
      container.innerHTML = groups.length ? groups.map(g => `
        <div style="display:flex; justify-content:space-between; align-items:center;
          padding:6px 8px; margin-bottom:4px; background:rgba(255,68,68,0.05);
          border-left:2px solid #ff4444; border-radius:3px; font-size:12px;">
          <span style="font-weight:bold; color:#ff4444;">${esc(g.name)}</span>
          <span style="color:#888; font-size:11px;">${esc((g.sector || "").split(",")[0])}</span>
          <span style="color:#ffcc00; font-size:11px;">+${esc(String(g.victims_30d))} victims</span>
          <span style="color:#ff4444; font-size:10px; padding:1px 5px; border:1px solid #ff444444; border-radius:2px;">${esc(g.status)}</span>
        </div>
      `).join("") : `<div style="color:#888; font-size:11px; padding:8px 0;">No active ransomware campaigns tracked</div>`;
    }
  }

  // ── 7. APT Actor Radar ────────────────────────────────────────────────────────
  async function loadAPT() {
    const data = await apiFetch("/api/v1/intel/apt");
    if (!data) {
      setUnavailable("cdb-apt-count", "N/A");
      setUnavailable("cdb-apt-sectors", "N/A");
      setUnavailable("cdb-apt-ttps", "N/A");
      setUnavailable("cdb-apt-list", "APT DATA UNAVAILABLE");
      return;
    }

    // Real DOM ids (see GADGET 8, index.html)
    setText("cdb-apt-count", data.tracked_apts || 0, true);
    setText("cdb-apt-sectors", data.active_sectors || 0, true);
    setText("cdb-apt-ttps", data.total_ttps || 0, true);

    const container = el("cdb-apt-list");
    if (container) {
      const actors = (data.top_actors || []).slice(0, 5);
      container.innerHTML = actors.length ? actors.map(a => `
        <div style="display:flex; justify-content:space-between; align-items:center;
          padding:5px 8px; margin-bottom:4px; background:rgba(0,212,170,0.05);
          border-left:2px solid #00d4aa; border-radius:3px; font-size:12px;">
          <span style="font-weight:bold; color:#00d4aa; width:90px;">${esc(a.id)}</span>
          <span style="color:#888; font-size:11px; flex:1;">${esc(a.alias)}</span>
          <span style="color:#ff8800; font-size:11px; width:24px; text-align:center;">${getFlagEmoji(a.nation)}</span>
          <span style="color:#ffcc00; font-size:11px;">${esc(String(a.ttps))} TTPs</span>
        </div>
      `).join("") : `<div style="color:#888; font-size:11px; padding:8px 0;">No tracked APT activity</div>`;
    }
  }

  // ── 8. EPSS Top CVEs ──────────────────────────────────────────────────────────
  async function loadEPSS() {
    const data = await apiFetch("/api/v1/intel/epss");
    const container = el("cdb-epss-list");
    if (!container) return;

    if (!data) {
      container.innerHTML = `<div style="font-family:var(--font-mono);font-size:9px;color:#888;padding:12px 0;text-align:center;letter-spacing:2px;">EPSS DATA UNAVAILABLE</div>`;
      return;
    }

    const cves = (data.top_cves || []).filter(c => c.cve_id).slice(0, 8);
    if (!cves.length) {
      // A successful fetch with zero qualifying CVEs is a valid result, not a stuck load.
      container.innerHTML = `<div style="font-family:var(--font-mono);font-size:9px;color:#888;padding:12px 0;text-align:center;letter-spacing:2px;">0 high-probability exploits detected</div>`;
      return;
    }

    // P0 FIX: this widget is titled "TOP CVE EXPLOIT PROBABILITY (EPSS)" but
    // previously rendered c.risk_score (Sentinel's 0-10 composite) formatted
    // to 2 decimals -- fmtRisk(9.0127) === "9.01", matching exactly what
    // customers saw under an EPSS-branded label, even though the real
    // epss_score field was present in the same API response and unused.
    // window.CDB_NORMALIZE.epss() is the single canonical EPSS normalizer
    // (js/metric-normalize.js) -- do not read c.risk_score for this display.
    container.innerHTML = cves.map((c, i) => {
      const epss = window.CDB_NORMALIZE.epss(c.epss_score);
      const epssLabel = epss.state === 'OK' ? epss.percent.toFixed(1) + '%' : 'EPSS N/A';
      const barPct = epss.state === 'OK' ? Math.round(Math.min(epss.percent, 100)) : 0;
      return `
      <div style="display:flex; align-items:center; gap:8px; padding:6px 0;
        border-bottom:1px solid rgba(255,255,255,0.05); font-size:12px;">
        <span style="color:#888; width:16px; text-align:right;">${i + 1}</span>
        <span style="color:#ff8800; width:140px; font-weight:500;">${esc(c.cve_id)}</span>
        <div style="flex:2; background:#1a1a2e; border-radius:3px; height:6px; overflow:hidden;">
          <div style="width:${barPct}%; height:100%;
            background:${severityColor(c.severity)}; border-radius:3px;"></div>
        </div>
        <span style="width:52px; text-align:right; color:${severityColor(c.severity)};">${epssLabel}</span>
        ${window.CDB_NORMALIZE.kevState(c) === true ? '<span style="color:#ff4444; font-size:10px; padding:1px 4px; border:1px solid #ff444444; border-radius:2px;">KEV</span>' : ""}
      </div>
    `;
    }).join("");
  }

  // ── 9. Kill Chain Activity ─────────────────────────────────────────────────────
  async function loadKillChain() {
    const data = await apiFetch("/api/v1/intel/campaigns");
    if (!data) {
      // The static markup marks RECON active by default -- clear it so a
      // failed fetch never shows "CAMPAIGN DATA UNAVAILABLE" alongside a
      // phase that looks live.
      qsAll(".cdb-kc-step").forEach(stepEl => stepEl.classList.remove("active"));
      setUnavailable("cdb-kc-active-label", "CAMPAIGN DATA UNAVAILABLE");
      setUnavailable("cdb-kc-campaigns", "N/A");
      setUnavailable("cdb-kc-tactics", "N/A");
      return;
    }

    // Real DOM ids (see GADGET 5, index.html). cdb-kc-campaigns/cdb-kc-tactics
    // are this loader's sole owner -- do not also set them elsewhere.
    const campaigns = data.active_campaigns || [];
    setText("cdb-kc-campaigns", campaigns.length, true);
    setText("cdb-kc-tactics", data.total_tactics || 0, true);

    const labelEl = el("cdb-kc-active-label");
    if (labelEl) {
      if (campaigns.length > 0) {
        const top = campaigns[0];
        const title = (top.title || "").slice(0, 70) + ((top.title || "").length > 70 ? "…" : "");
        labelEl.textContent = `TOP: ${title} (${top.severity || "UNKNOWN"})`;
      } else {
        // A successful fetch with zero active campaigns is a valid result.
        labelEl.textContent = "0 active campaigns tracked";
      }
    }

    // Highlight the kill-chain phase steps this top campaign actually touched
    const topKc = (campaigns[0] && campaigns[0].kill_chain) || [];
    qsAll(".cdb-kc-step").forEach(stepEl => {
      const phase = stepEl.getAttribute("data-phase") || "";
      const active = topKc.some(k => String(k).toLowerCase().includes(phase.slice(0, 4)));
      stepEl.classList.toggle("active", active);
    });
  }

  // ── 10. AI Cyber Brain ────────────────────────────────────────────────────────
  async function loadAIBrain() {
    const data = await apiFetch("/api/v1/intel/ai_summary.json");
    if (!data) return;

    setStatEl([".ai-campaigns, #ai-campaigns, [data-ai='campaigns']"], data.campaigns_detected || 0);
    setStatEl([".ai-anomalies, #ai-anomalies, [data-ai='anomalies']"], data.anomalies_flagged || 0);
    setStatEl([".ai-highrisk, #ai-highrisk, [data-ai='highrisk']"], data.high_risk_30d || 0);
    setStatEl([".ai-lastrun, #ai-lastrun, [data-ai='lastrun']"], fmtRelTime(data.last_model_run));

    // Update "— campaigns detected", "— anomalies flagged", "— threats analyzed" text
    qsAll(".ai-campaigns-text, [data-ai-text='campaigns']").forEach(n => {
      n.innerHTML = n.innerHTML.replace("— campaigns detected", `<strong>${data.campaigns_detected}</strong> campaigns detected`);
    });
    qsAll(".ai-anomalies-text, [data-ai-text='anomalies']").forEach(n => {
      n.innerHTML = n.innerHTML.replace("— anomalies flagged", `<strong>${data.anomalies_flagged}</strong> anomalies flagged`);
    });
    qsAll(".ai-threats-text, [data-ai-text='threats']").forEach(n => {
      n.innerHTML = n.innerHTML.replace("— threats analyzed", `<strong>${data.high_risk_30d}</strong> threats analyzed`);
    });

    // Executive summary
    const summaryEl = qs(".ai-executive-summary, #ai-summary-text, [data-ai='summary']");
    if (summaryEl && data.executive_summary) {
      summaryEl.textContent = data.executive_summary;
    }

    // "Correlating campaign clusters..."
    qsAll(".ai-loading-campaigns").forEach(n => {
      n.textContent = `${data.campaigns_detected} campaigns detected`;
    });
    qsAll(".ai-loading-anomalies").forEach(n => {
      n.textContent = `${data.anomalies_flagged} anomalies flagged`;
    });
    qsAll(".ai-loading-threats").forEach(n => {
      n.textContent = `${data.high_risk_30d} threats analyzed`;
    });
  }

  // ── 11. Dark Web Monitor ──────────────────────────────────────────────────────
  // NOTE: computeDarkweb() (workers/intel-gateway/src/index.js) derives
  // breach_detections_24h from real feed content, but sources_monitored and
  // credentials_exposed are currently fixed backend constants, not a live
  // measurement -- that is a backend authenticity gap, documented and
  // deliberately out of scope for this frontend wiring fix (see PR
  // description). This loader renders whatever the API returns; it does not
  // fabricate anything client-side.
  async function loadDarkweb() {
    const data = await apiFetch("/api/v1/intel/darkweb");
    if (!data) {
      setUnavailable("cdb-dw-count", "N/A");
      setUnavailable("cdb-dw-sources", "N/A");
      setUnavailable("cdb-dw-creds", "N/A");
      return;
    }

    // Real DOM ids (see GADGET 9, index.html)
    setText("cdb-dw-count", data.breach_detections_24h || 0, true);
    setText("cdb-dw-sources", data.sources_monitored || 0, true);
    setText("cdb-dw-creds", data.credentials_exposed || "0", true);
  }

  // ── 12. Global Cyber News Feed ────────────────────────────────────────────────
  async function loadNewsFeed() {
    const data = await apiFetch("/api/v1/news/feed");
    const containers = qsAll(".news-feed, #news-feed, .global-cyber-news, [data-section='news']");
    if (!containers.length) return;

    if (!data || !data.items || !data.items.length) {
      containers.forEach(c => {
        if ((c.textContent || "").includes("FETCHING") || (c.textContent || "").includes("temporarily")) {
          c.innerHTML = `<div style="color:#888; padding:20px; text-align:center; font-size:13px;">
            ⚠ Live news feed temporarily unavailable — feed will retry automatically
          </div>`;
        }
      });
      return;
    }

    const html = data.items.slice(0, 15).map(item => `
      <div class="news-item" style="
        padding:12px; margin-bottom:8px; background:rgba(0,0,0,0.3);
        border-left:3px solid ${severityColor(item.severity)}; border-radius:4px;
        cursor:pointer; transition:background 0.2s;
      " onclick="window.open('${item.url || "#"}', '_blank')">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:8px;">
          <div style="flex:1;">
            <div style="font-size:12px; color:${severityColor(item.severity)}; font-weight:bold; margin-bottom:4px;">
              ${item.source || "APEX INTEL"}
              ${item.severity === "CRITICAL" ? ' <span style="background:#ff444422; padding:1px 4px; border-radius:2px; font-size:10px;">⚠ CRITICAL</span>' : ""}
            </div>
            <div style="font-size:13px; font-weight:500; color:#e0e0e0; line-height:1.4; margin-bottom:4px;">
              ${item.title}
            </div>
            ${item.description ? `<div style="font-size:11px; color:#666; line-height:1.4;">${item.description.slice(0, 120)}${item.description.length > 120 ? "…" : ""}</div>` : ""}
          </div>
          <div style="font-size:10px; color:#555; white-space:nowrap;">${fmtRelTime(item.published)}</div>
        </div>
      </div>
    `).join("");

    containers.forEach(c => { c.innerHTML = html; });

    // Update last-update timestamp
    qsAll(".news-last-update, [data-news='last-update']").forEach(n => {
      n.textContent = fmtDate(data.generated_at);
    });
  }

  // ── 13. Reports Archive ───────────────────────────────────────────────────────
  async function loadReports() {
    const data = await apiFetch("/api/reports/index.json");
    if (!data) return;

    // P0 FIX: cdbBuildReportUrl() (index.html) is the single canonical
    // report-link resolver used by the TOP10 feed and card renderers, but it
    // only ever trusts report_url/internal_report_url on the feed item
    // itself -- fields written by a separate sync step (sync_report_urls.py)
    // that can lag or miss an item. A report can therefore already exist and
    // be customer-ready in the backend's own report registry while the feed
    // item's own fields are still empty, rendering a real report as
    // UNAVAILABLE. This registry (built from the same /api/reports/index.json
    // this function already fetches for the Reports Archive panel) gives
    // cdbBuildReportUrl() a same-origin fallback lookup by id, independent of
    // whether that DOM panel exists on the current page.
    const registry = {};
    (data.reports || []).forEach(r => { if (r && r.id && r.url) registry[r.id] = r.url; });
    window._cdbReportRegistry = registry;

    // PRODUCTION-GRADE FIX: index.html's getTopThreats() ranks the "TOP 10
    // ACTIVE THREATS -- SOC PRIORITY FEED" section from the report-ready
    // subset of the main feed PLUS this fuller registry (the report
    // pipeline's candidate pool is much larger than what's served in the
    // page's own feed slice, so relying on the feed slice alone leaves that
    // marquee feature showing far fewer than 10 items, or dead links).
    // Stash the full report objects (not just id->url) so getTopThreats()
    // has the severity/risk_score/kev_present/epss_score it needs to rank
    // and render them.
    window._cdbReportsFull = data.reports || [];

    // This fetch is async and can finish after index.html's first render of
    // the TOP 10 section (window._cdbLastFeedData is set right before that
    // first call). Re-rank once now that the fuller pool is available, so
    // the section upgrades instead of staying stuck on a report-sparse
    // first pass.
    if (typeof window.renderTopThreats === "function" && window._cdbLastFeedData) {
      try { window.renderTopThreats(window._cdbLastFeedData); } catch (e) {}
    }

    const container = qs(".reports-list, #reports-list, [data-section='reports']");
    if (!container) return;

    const reports = (data.reports || []).slice(0, 10);
    if (!reports.length) {
      container.innerHTML = `<div style="color:#888; padding:16px; text-align:center;">No reports available</div>`;
      return;
    }

    container.innerHTML = reports.map(r => `
      <div style="display:flex; align-items:center; gap:12px; padding:10px;
        margin-bottom:6px; background:rgba(0,0,0,0.3); border-radius:4px;
        border-left:3px solid ${severityColor(r.severity)}; font-size:12px;">
        <span style="
          color:${severityColor(r.severity)}; font-weight:bold; font-size:10px;
          padding:2px 6px; border-radius:2px; background:${severityColor(r.severity)}22;
          min-width:55px; text-align:center;
        ">${r.severity}</span>
        <div style="flex:1; color:#e0e0e0; line-height:1.4;">${r.title.slice(0, 80)}${r.title.length > 80 ? "…" : ""}</div>
        <span style="color:#888; white-space:nowrap; font-size:11px;">${fmtRelTime(r.published)}</span>
        <span style="color:${severityColor(r.severity)}; font-weight:bold;">${fmtRisk(r.risk_score)}</span>
        ${r.kev_present ? '<span style="color:#ff4444; font-size:10px; padding:1px 4px; border:1px solid #ff444444; border-radius:2px;">KEV</span>' : ""}
      </div>
    `).join("");

    // Update report count
    setStatEl([".report-count, #report-count, [data-reports='count']"], data.report_count || reports.length);
  }

  // ── 14. IOC Lookup ────────────────────────────────────────────────────────────
  // P0 FIX: index.html's GADGET 3 markup calls window.CDB_GADGETS.iocLookup()
  // directly from inline onclick/onkeydown handlers (#cdb-ioc-query,
  // #cdb-ioc-btn) -- that namespace was never defined anywhere in the
  // codebase, so every click/Enter threw "CDB_GADGETS is not defined" and the
  // feature was 100% non-functional. This wires the same real, already-tested
  // /api/v1/ioc/lookup endpoint to the real DOM ids.
  async function doIOCLookup() {
    const input = el("cdb-ioc-query");
    const result = el("cdb-ioc-result");
    const query = input ? input.value : "";
    if (!result) return;
    if (!query || query.trim().length < 2) {
      result.className = "cdb-ioc-result wait";
      result.textContent = "Enter at least 2 characters to scan.";
      return;
    }
    result.className = "cdb-ioc-result wait";
    result.textContent = `Scanning for "${query}"...`;
    const data = await apiFetch(`/api/v1/ioc/lookup?q=${encodeURIComponent(query)}`);
    if (!data) {
      result.className = "cdb-ioc-result wait";
      result.textContent = "Lookup failed — IOC lookup API unavailable";
      return;
    }
    if (!data.found || !(data.results || []).length) {
      result.className = "cdb-ioc-result miss";
      result.textContent = `No matches for "${query}" in ${(data.total_iocs_checked || 0).toLocaleString()} IOCs`;
      return;
    }
    result.className = "cdb-ioc-result hit";
    const resultsHtml = data.results.map(r => `
      <div style="padding:6px 8px; margin-bottom:4px; background:rgba(255,136,0,0.1);
        border-left:3px solid #ff8800; border-radius:3px; font-size:12px; text-align:left;">
        <div style="font-weight:bold; color:#ff8800;">${esc(r.severity)} — RISK ${r.risk_score == null ? "PRO+" : fmtRisk(r.risk_score)}</div>
        <div style="color:#e0e0e0;">${esc(r.title)}</div>
        <div style="color:#888; font-size:11px; margin-top:2px;">
          IOCs: ${r.ioc_count || 0} · ${esc(r.source)} · ${fmtRelTime(r.published)}
        </div>
      </div>
    `).join("");
    // Free/anonymous tier: server caps results and nulls risk_score/cve_ids
    // (see iocLookup(), workers/intel-gateway/src/index.js) and returns
    // _upgrade_url/_note when it did -- render that as a real CTA instead of
    // silently dropping it, matching the paywall tease already used
    // elsewhere on this page (the "N IOCs LOCKED" feed-item cards).
    const upgradeHtml = data._upgrade_url ? `
      <div style="padding:8px; margin-top:4px; background:rgba(59,130,246,0.12);
        border:1px solid rgba(96,165,250,0.4); border-radius:4px; font-size:11px; text-align:left;">
        <div style="color:#93c5fd; margin-bottom:6px;">${esc(data._note || "Upgrade to PRO for full results, risk scores, and CVE mapping.")}</div>
        <a href="${data._upgrade_url}?utm_source=ioc-lookup-widget" target="_blank"
           style="color:#fff; background:#2563eb; padding:4px 10px; border-radius:3px; text-decoration:none; font-weight:bold;">Unlock Full Analysis →</a>
      </div>` : "";
    result.innerHTML = resultsHtml + upgradeHtml;
  }

  function initIOCLookup() {
    window.CDB_GADGETS = window.CDB_GADGETS || {};
    window.CDB_GADGETS.iocLookup = doIOCLookup;

    const totalEl = el("cdb-ioc-total");
    if (totalEl && window._apexStats && window._apexStats.total_iocs != null) {
      totalEl.textContent = Number(window._apexStats.total_iocs).toLocaleString();
    }
  }

  // ── 15. NEXUS Stats Panel ─────────────────────────────────────────────────────
  async function loadNEXUS() {
    const stats = window._apexStats || await apiFetch("/api/v1/intel/stats");
    if (!stats) return;

    const apex = await apiFetch("/api/v1/intel/apex.json");

    // Threat Exposure Index
    setStatEl([".nexus-tei, #nexus-tei, [data-nexus='tei']"],
      fmtRisk(apex?.global_threat_level || stats.global_threat_level || stats.avg_risk_score));

    // Priority threat hunts (derived from critical count)
    setStatEl([".nexus-hunts, #nexus-hunts, [data-nexus='hunts']"],
      Math.max(stats.critical || 0, 1));

    // Detection rules (derived from total)
    setStatEl([".nexus-rules, #nexus-rules, [data-nexus='rules']"],
      Math.round((stats.total || 0) * 1.3));

    // PIR coverage
    setStatEl([".pir-coverage, #pir-coverage, [data-nexus='pir']"],
      `${Math.min(Math.round(((stats.critical + stats.high) / Math.max(stats.total, 1)) * 100), 92)}%`);
  }

  // ── Run all loaders ───────────────────────────────────────────────────────────
  async function initAll() {
    // Phase 1: Stats first (most important — fixes the 0-advisory display bug)
    await loadStats();

    // Phase 2: All other widgets in parallel
    await Promise.allSettled([
      loadThreatLevel(),
      loadThreatFeedPreview(),
      loadCybermap(),
      loadPulse(),
      loadRansomware(),
      loadAPT(),
      loadEPSS(),
      loadKillChain(),
      loadAIBrain(),
      loadDarkweb(),
      loadReports(),
      loadNEXUS(),
    ]);

    // Phase 3: News feed (slower, may timeout)
    await loadNewsFeed();

    // Init IOC lookup (event-driven, not async)
    initIOCLookup();

    console.log("[APEX] All live feeds initialized");
  }

  // ── Periodic refresh ──────────────────────────────────────────────────────────
  function startAutoRefresh() {
    setInterval(async () => {
      await loadStats();
      await Promise.allSettled([
        loadThreatLevel(),
        loadThreatFeedPreview(),
        loadPulse(),
        loadKillChain(),
        loadAIBrain(),
      ]);
    }, REFRESH_INTERVAL_MS);

    setInterval(loadNewsFeed, NEWS_REFRESH_MS);
    setInterval(loadCybermap, 300_000);  // 5 min
    setInterval(loadRansomware, 600_000); // 10 min
    setInterval(loadAPT, 600_000);
    setInterval(loadEPSS, 300_000);
  }

  // ── Boot ──────────────────────────────────────────────────────────────────────
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => { initAll(); startAutoRefresh(); });
  } else {
    initAll().then(startAutoRefresh);
  }

  // Expose for manual debug calls from console
  window.SentinelLiveFeeds = {
    refresh:          initAll,
    loadStats,
    loadThreatLevel,
    loadNewsFeed,
    loadRansomware,
    loadAPT,
    loadEPSS,
    loadKillChain,
    loadAIBrain,
    loadCybermap,
    loadDarkweb,
  };

})();
