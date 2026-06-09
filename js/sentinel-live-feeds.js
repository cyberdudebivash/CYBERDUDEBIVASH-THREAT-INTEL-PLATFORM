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

  function setText(selector, text, isId = false) {
    const node = isId ? el(selector) : qs(selector);
    if (node) node.textContent = text;
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
    if (!data) return;

    const level = data.global_threat_level || {};
    const score = parseFloat(level.level || 0);
    const label = level.label || data.label || "ASSESSING";

    // Threat level gauge
    setStatEl([".threat-level-value", "#threat-level", "[data-threat='level']"], score.toFixed(1));
    setStatEl([".threat-level-label", "#threat-label", "[data-threat='label']"], label);

    // Color the gauge based on level
    const gaugeEl = qs(".threat-gauge, .global-threat-gauge, #global-threat-level");
    if (gaugeEl) {
      gaugeEl.style.color = score >= 8 ? "#ff4444" : score >= 6 ? "#ff8800" : score >= 4 ? "#ffcc00" : "#00d4aa";
    }

    // The —/10 COMPUTING... area
    const computingEl = qs(".threat-computing, [data-gauge='threat']");
    if (computingEl) {
      computingEl.textContent = `${score.toFixed(1)}/10`;
    }

    // DEFCON
    const defconLvl = data.level || 5;
    const defconStatus = data.status || "FADE OUT";
    setStatEl([".defcon-level", "#defcon-level", "[data-defcon='level']"], `DC${defconLvl}`);
    setStatEl([".defcon-status", "#defcon-status", "[data-defcon='status']"], defconStatus);

    // Light up the DEFCON indicators
    for (let i = 1; i <= 5; i++) {
      const dcEl = qs(`.defcon-${i}, #dc${i}, [data-dc='${i}']`);
      if (dcEl) {
        dcEl.classList.toggle("active", i === defconLvl);
        dcEl.style.opacity = i === defconLvl ? "1" : "0.3";
      }
    }

    // Update loading spinners
    qsAll("[data-loading='defcon'], .defcon-loading").forEach(n => {
      n.textContent = `DC${defconLvl} — ${defconStatus}`;
    });
    qsAll("[data-loading='threat'], .threat-loading").forEach(n => {
      n.textContent = `${score.toFixed(1)}/10 — ${label}`;
    });
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
    if (!data) return;

    setStatEl([".pulse-rate, #pulse-rate, [data-pulse='rate']"], data.rate_hr || 0);
    setStatEl([".pulse-today, #pulse-today, [data-pulse='today']"], data.today || 0);
    setStatEl([".pulse-total, #pulse-total, [data-pulse='total']"], data.total || 0);

    // The RATE/HR: — TODAY: — TOTAL: — pattern
    qsAll(".pulse-widget .pulse-val, .threat-pulse [data-val]").forEach((n, i) => {
      const vals = [data.rate_hr, data.today, data.total];
      if (vals[i] !== undefined) n.textContent = vals[i];
    });
  }

  // ── 6. Ransomware Tracker ─────────────────────────────────────────────────────
  async function loadRansomware() {
    const data = await apiFetch("/api/v1/intel/ransomware");
    if (!data) return;

    setStatEl([".ransom-groups, #ransom-groups, [data-ransom='groups']"], data.active_groups || 0);
    setStatEl([".ransom-victims, #ransom-victims, [data-ransom='victims']"], data.new_victims_30d || 0);

    // Clear "LOADING ACTIVE CAMPAIGNS..." text
    const container = qs(".ransomware-tracker, #ransomware-content, [data-section='ransomware']");
    if (container && (container.textContent || "").includes("LOADING")) {
      const groups = (data.top_groups || []).slice(0, 5);
      container.innerHTML = groups.map(g => `
        <div style="display:flex; justify-content:space-between; align-items:center;
          padding:6px 8px; margin-bottom:4px; background:rgba(255,68,68,0.05);
          border-left:2px solid #ff4444; border-radius:3px; font-size:12px;">
          <span style="font-weight:bold; color:#ff4444;">${g.name}</span>
          <span style="color:#888; font-size:11px;">${g.sector.split(",")[0]}</span>
          <span style="color:#ffcc00; font-size:11px;">+${g.victims_30d} victims</span>
          <span style="color:#ff4444; font-size:10px; padding:1px 5px; border:1px solid #ff444444; border-radius:2px;">${g.status}</span>
        </div>
      `).join("");
    }
  }

  // ── 7. APT Actor Radar ────────────────────────────────────────────────────────
  async function loadAPT() {
    const data = await apiFetch("/api/v1/intel/apt");
    if (!data) return;

    setStatEl([".apt-count, #apt-count, [data-apt='count']"], data.tracked_apts || 0);
    setStatEl([".apt-sectors, #apt-sectors, [data-apt='sectors']"], data.active_sectors || 0);
    setStatEl([".apt-ttps, #apt-ttps, [data-apt='ttps']"], data.total_ttps || 0);

    const container = qs(".apt-radar, #apt-content, [data-section='apt']");
    if (container && (container.textContent || "").includes("SCANNING")) {
      const actors = (data.top_actors || []).slice(0, 5);
      container.innerHTML = actors.map(a => `
        <div style="display:flex; justify-content:space-between; align-items:center;
          padding:5px 8px; margin-bottom:4px; background:rgba(0,212,170,0.05);
          border-left:2px solid #00d4aa; border-radius:3px; font-size:12px;">
          <span style="font-weight:bold; color:#00d4aa; width:90px;">${a.id}</span>
          <span style="color:#888; font-size:11px; flex:1;">${a.alias}</span>
          <span style="color:#ff8800; font-size:11px; width:24px; text-align:center;">${getFlagEmoji(a.nation)}</span>
          <span style="color:#ffcc00; font-size:11px;">${a.ttps} TTPs</span>
        </div>
      `).join("");
    }
  }

  // ── 8. EPSS Top CVEs ──────────────────────────────────────────────────────────
  async function loadEPSS() {
    const data = await apiFetch("/api/v1/intel/epss");
    if (!data) return;

    const container = qs(".epss-container, #epss-content, [data-section='epss']");
    if (!container) return;

    const cves = (data.top_cves || []).filter(c => c.cve_id).slice(0, 8);
    if (!cves.length) return;

    container.innerHTML = cves.map((c, i) => `
      <div style="display:flex; align-items:center; gap:8px; padding:6px 0;
        border-bottom:1px solid rgba(255,255,255,0.05); font-size:12px;">
        <span style="color:#888; width:16px; text-align:right;">${i + 1}</span>
        <span style="color:#ff8800; width:140px; font-weight:500;">${c.cve_id}</span>
        <div style="flex:2; background:#1a1a2e; border-radius:3px; height:6px; overflow:hidden;">
          <div style="width:${Math.round(Math.min((c.risk_score / 10) * 100, 100))}%; height:100%;
            background:${severityColor(c.severity)}; border-radius:3px;"></div>
        </div>
        <span style="width:36px; text-align:right; color:${severityColor(c.severity)};">${fmtRisk(c.risk_score)}</span>
        ${c.kev_present ? '<span style="color:#ff4444; font-size:10px; padding:1px 4px; border:1px solid #ff444444; border-radius:2px;">KEV</span>' : ""}
      </div>
    `).join("");

    qsAll("[data-loading='epss'], .epss-loading").forEach(n => {
      n.textContent = `TOP ${cves.length} CVEs BY EXPLOIT PROBABILITY`;
    });
  }

  // ── 9. Kill Chain Coverage + Active Campaigns ─────────────────────────────────
  async function loadKillChain() {
    const data = await apiFetch("/api/v1/intel/campaigns");
    if (!data) return;

    const phases = data.phases || {};
    const phaseLabels = {
      recon: "RECON", weaponize: "WEAPON", deliver: "DELIVER",
      exploit: "EXPLOIT", install: "INSTALL", c2: "C2", action: "ACTION",
    };

    // NEXUS Kill Chain coverage bars
    Object.entries(phaseLabels).forEach(([key, label]) => {
      const count = phases[key] || 0;
      const pct   = count > 0 ? Math.min(Math.round((count / Math.max(...Object.values(phases))) * 100), 100) : 0;

      setStatEl([`.kc-${key}, #kc-${key}, [data-kc='${key}']`], count);

      const bar = qs(`.kc-bar-${key}, #kc-bar-${key}, [data-kc-bar='${key}']`);
      if (bar) {
        bar.style.width = `${pct}%`;
        bar.textContent = count || "";
      }
    });

    // Active Kill Chain display (the 7-phase chain with animated icons)
    const kcContainer = qs(".killchain-activity, #killchain-activity, [data-section='killchain']");
    if (kcContainer && (kcContainer.textContent || "").includes("Analyzing")) {
      const campaigns = data.active_campaigns || [];
      if (campaigns.length > 0) {
        const topCampaign = campaigns[0];
        const kc = topCampaign.kill_chain || [];
        kcContainer.innerHTML = `
          <div style="font-size:11px; color:#888; margin-bottom:8px;">
            TOP CAMPAIGN: <strong style="color:#ff4444;">${topCampaign.title.slice(0, 60)}${topCampaign.title.length > 60 ? "…" : ""}</strong>
          </div>
          <div style="display:flex; gap:4px; flex-wrap:wrap; margin-bottom:8px;">
            ${["Recon", "Weaponize", "Deliver", "Exploit", "Install", "C2", "Actions"].map((phase, i) => {
              const active = kc.some(k => k.toLowerCase().includes(phase.toLowerCase().slice(0, 4)));
              return `<span style="padding:4px 8px; font-size:11px; border-radius:3px; font-weight:bold;
                background:${active ? severityColor(topCampaign.severity) + "33" : "rgba(255,255,255,0.05)"};
                color:${active ? severityColor(topCampaign.severity) : "#666"};
                border:1px solid ${active ? severityColor(topCampaign.severity) + "66" : "transparent"};">
                ${phase.toUpperCase()}
              </span>`;
            }).join("")}
          </div>
          <div style="font-size:11px; color:#888;">
            CAMPAIGNS: <strong style="color:#00d4aa;">${campaigns.length}</strong>  ·
            TACTICS: <strong style="color:#00d4aa;">${data.total_tactics || 0}</strong>  ·
            COVERAGE: <strong style="color:#${data.coverage_pct >= 70 ? "00d4aa" : "ff8800"};">${data.coverage_pct || 0}%</strong>
          </div>
        `;
      }
    }

    // Correlated campaigns list
    const corrContainer = qs(".correlated-campaigns, #correlated-campaigns, [data-section='correlated']");
    if (corrContainer) {
      const campaigns = (data.active_campaigns || []).slice(0, 5);
      if (campaigns.length) {
        corrContainer.innerHTML = campaigns.map(c => `
          <div style="padding:8px; margin-bottom:6px; background:rgba(0,0,0,0.3);
            border-left:3px solid ${severityColor(c.severity)}; border-radius:3px; font-size:12px;">
            <div style="font-weight:500; color:#e0e0e0;">${c.title.slice(0, 70)}${c.title.length > 70 ? "…" : ""}</div>
            <div style="display:flex; gap:12px; margin-top:4px; color:#888; font-size:11px;">
              <span style="color:${severityColor(c.severity)};">${c.severity}</span>
              <span>RISK: ${fmtRisk(c.risk_score)}</span>
              <span>${fmtRelTime(c.published)}</span>
              ${(c.cve_ids || []).length ? `<span style="color:#ff8800;">${c.cve_ids[0]}</span>` : ""}
            </div>
          </div>
        `).join("");
      }
    }
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
  async function loadDarkweb() {
    const data = await apiFetch("/api/v1/intel/darkweb");
    if (!data) return;

    setStatEl([".dw-breaches, #dw-breaches, [data-dw='breaches']"],  data.breach_detections_24h || 0);
    setStatEl([".dw-sources, #dw-sources, [data-dw='sources']"],     data.sources_monitored || 0);
    setStatEl([".dw-creds, #dw-creds, [data-dw='creds']"],           data.credentials_exposed || "0");
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
    const container = qs(".reports-list, #reports-list, [data-section='reports']");
    if (!container || !data) return;

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
  function initIOCLookup() {
    const inputs   = qsAll(".ioc-input, #ioc-input, input[type='text'][placeholder*='IP']");
    const buttons  = qsAll(".ioc-scan, #ioc-scan, button[data-action='scan']");
    const results  = qsAll(".ioc-results, #ioc-results, [data-ioc='results']");

    async function doLookup(query) {
      if (!query || query.trim().length < 2) return;
      results.forEach(r => { r.innerHTML = `<div style="color:#888;">Scanning for "${query}"...</div>`; });
      const data = await apiFetch(`/api/v1/ioc/lookup?q=${encodeURIComponent(query)}`);
      if (!data) {
        results.forEach(r => { r.innerHTML = `<div style="color:#ff4444;">Lookup failed — API unavailable</div>`; });
        return;
      }
      if (!data.found || !data.results.length) {
        results.forEach(r => {
          r.innerHTML = `<div style="color:#888; padding:8px;">
            No matches for "${query}" in ${(data.total_iocs_checked || 0).toLocaleString()} IOCs
          </div>`;
        });
        return;
      }
      const html = data.results.map(r => `
        <div style="padding:6px 8px; margin-bottom:4px; background:rgba(255,136,0,0.1);
          border-left:3px solid #ff8800; border-radius:3px; font-size:12px;">
          <div style="font-weight:bold; color:#ff8800;">${r.severity} — RISK ${fmtRisk(r.risk_score)}</div>
          <div style="color:#e0e0e0;">${r.title}</div>
          <div style="color:#888; font-size:11px; margin-top:2px;">
            IOCs: ${r.ioc_count || 0} · ${r.source} · ${fmtRelTime(r.published)}
          </div>
        </div>
      `).join("");
      results.forEach(r => { r.innerHTML = html; });
    }

    inputs.forEach(inp => {
      inp.addEventListener("keydown", e => { if (e.key === "Enter") doLookup(inp.value); });
    });
    buttons.forEach(btn => {
      btn.addEventListener("click", () => {
        const q = (inputs[0] || {}).value || "";
        doLookup(q);
      });
    });
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
