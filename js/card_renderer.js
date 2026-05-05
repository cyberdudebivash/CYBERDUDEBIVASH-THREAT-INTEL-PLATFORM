/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — ENTERPRISE CARD RENDERER v143.0.0
 *  Full 8-Zone Intelligence Card Architecture
 *  Author: CYBERDUDEBIVASH SENTINEL APEX Platform
 *
 *  ZONES:
 *   [1] HEADER / DECISION ZONE      — severity, title, risk score, confidence
 *   [2] SOC PRIORITY STRIP          — P1/P2/P3/P4, threat level, predictive score
 *   [3] INTELLIGENCE CORE           — actor, IOC count, TTP count, MITRE tags
 *   [4] AI INTELLIGENCE PANEL       — AI summary, threat confidence, predictive risk
 *   [5] EXPLOIT + SCORING           — EPSS, CVSS, KEV indicator
 *   [6] TIMELINE BLOCK              — published, processed, last updated
 *   [7] PAYWALL CONVERSION BLOCK    — locked message, CTA, urgency
 *   [8] FOOTER                      — source, STIX ID, validation, report CTA
 *
 *  PIPELINE SAFETY: Never overwrites pipeline-injected data.
 *  Depends on: js/api_adapter.js (SentinelApexAdapter)
 * ═══════════════════════════════════════════════════════════════════════════════
 */

"use strict";

(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory(require("./api_adapter"));
  } else {
    root.SentinelApexCardRenderer = factory(root.SentinelApexAdapter);
  }
})(typeof window !== "undefined" ? window : this, function (Adapter) {

  /* ─────────────────────────────────────────────────────────────
   *  HTML ESCAPE UTILITY
   * ───────────────────────────────────────────────────────────── */
  function esc(str) {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(str || "").replace(/[&<>"']/g, function (m) { return map[m]; });
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 1: HEADER / DECISION ZONE
   * ───────────────────────────────────────────────────────────── */
  function renderHeaderZone(item) {
    const sc = item.severity_colors;
    const rs = item.risk_score;
    const sevLabel = item.severity;
    const isHighPrio = item.is_high_priority;

    return `
    <div class="sapx-zone sapx-zone-header" data-severity="${esc(sevLabel)}">
      <div class="sapx-header-row">
        <div class="sapx-header-left">
          <div class="sapx-sev-badge sapx-sev-${esc(sevLabel.toLowerCase())}"
               style="background:${esc(sc.dim)};color:${esc(sc.text)};border:1px solid ${esc(sc.border)};">
            ${isHighPrio ? '<span class="sapx-pulse-dot"></span>' : ""}
            ${esc(sevLabel)}
          </div>
          <div class="sapx-threat-type">${esc(item.threat_type)}</div>
          ${item.kev_present ? '<div class="sapx-kev-badge">🏛️ KEV CONFIRMED</div>' : ""}
        </div>
        <div class="sapx-header-right">
          <div class="sapx-risk-score-block" style="color:${esc(rs.color)};">
            <span class="sapx-risk-num">${esc(rs.display)}</span>
            <span class="sapx-risk-label">/ 10 RISK</span>
          </div>
          <div class="sapx-risk-bar-wrap">
            <div class="sapx-risk-bar" style="width:${esc(rs.percent)}%;background:${esc(rs.color)};box-shadow:0 0 8px ${esc(rs.color)}80;"></div>
          </div>
          <div class="sapx-conf-row">
            <span class="sapx-conf-label">CONF</span>
            <span class="sapx-conf-val" style="color:${esc(sc.text)};">${esc(item.confidence_display)}</span>
          </div>
        </div>
      </div>
      <h3 class="sapx-title" title="${esc(item.title)}">${esc(item.title)}</h3>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 2: SOC PRIORITY STRIP
   * ───────────────────────────────────────────────────────────── */
  function renderSocPriorityZone(item) {
    const ai = item.apex_ai;
    const apex = item.apex;
    const socMeta = ai.soc_priority_meta;
    const predScore = ai.predictive_risk;
    const predApex  = apex.predictive_score;

    return `
    <div class="sapx-zone sapx-zone-soc"
         style="background:${esc(socMeta.bg)};border-top:1px solid ${esc(socMeta.border)};border-bottom:1px solid ${esc(socMeta.border)};">
      <div class="sapx-soc-inner">
        <div class="sapx-soc-priority" style="color:${esc(socMeta.color)};border:1px solid ${esc(socMeta.border)};background:${esc(socMeta.bg)};">
          <span class="sapx-soc-badge">${esc(socMeta.badge)}</span>
          <span class="sapx-soc-pcode">${esc(ai.soc_priority)}</span>
        </div>
        <div class="sapx-soc-label">${esc(socMeta.label)}</div>
        <div class="sapx-soc-spacer"></div>
        <div class="sapx-soc-threat-tier">
          <span class="sapx-soc-tier-label">THREAT LEVEL</span>
          <span class="sapx-soc-tier-val" style="color:${esc(item.severity_colors.text)};">${esc(ai.threat_level)}</span>
        </div>
        <div class="sapx-soc-pred">
          <span class="sapx-soc-tier-label">PREDICTIVE SCORE</span>
          <span class="sapx-soc-pred-val" style="color:${predScore >= 7 ? "#ff1a1a" : predScore >= 5 ? "#ff6600" : predScore >= 3 ? "#f59e0b" : "#00d4ff"};">
            ${predApex > 0 ? esc(predApex.toFixed(1)) : esc(predScore.toFixed(1))} / 10
          </span>
        </div>
        <div class="sapx-soc-category">
          <span class="sapx-soc-cat-pill">${esc(ai.threat_category)}</span>
        </div>
      </div>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 3: INTELLIGENCE CORE
   * ───────────────────────────────────────────────────────────── */
  function renderIntelCoreZone(item) {
    const ttpsToShow = (item.ttps.length ? item.ttps : item.mitre_tactics).slice(0, 6);

    const ttpTags = ttpsToShow.map(function (t) {
      return `<a href="${esc(t.url || "https://attack.mitre.org/techniques/" + t.id.replace(".", "/"))}"
                 target="_blank" rel="noopener"
                 class="sapx-ttp-tag" title="${esc(t.name)} — ${esc(t.tactic)}">${esc(t.id)}</a>`;
    }).join("");

    const moreCount = (item.ttp_count || 0) - ttpsToShow.length;
    const moreBadge = moreCount > 0
      ? `<span class="sapx-ttp-more">+${moreCount} more</span>`
      : "";

    return `
    <div class="sapx-zone sapx-zone-intel-core">
      <div class="sapx-intel-grid">
        <div class="sapx-intel-cell">
          <div class="sapx-intel-cell-label">ACTOR</div>
          <div class="sapx-intel-cell-val sapx-actor-tag">
            <span class="sapx-actor-icon">🎭</span>${esc(item.actor_tag)}
          </div>
        </div>
        <div class="sapx-intel-cell">
          <div class="sapx-intel-cell-label">IOC COUNT</div>
          <div class="sapx-intel-cell-val sapx-ioc-count">
            <span class="sapx-ioc-num">${esc(String(item.ioc_count))}</span>
            ${item.ioc_count > 0
              ? `<span class="sapx-ioc-conf">${esc(item.ioc_confidence.toFixed(0))}% conf</span>`
              : '<span class="sapx-ioc-none">No IOCs</span>'}
          </div>
        </div>
        <div class="sapx-intel-cell">
          <div class="sapx-intel-cell-label">TTP COUNT</div>
          <div class="sapx-intel-cell-val sapx-ttp-count">
            <span class="sapx-ttp-num">${esc(String(item.ttp_count))}</span>
            <span class="sapx-ttp-density">density ${esc(item.apex_ai.ttp_density.toFixed(1))}</span>
          </div>
        </div>
        <div class="sapx-intel-cell">
          <div class="sapx-intel-cell-label">CAMPAIGN</div>
          <div class="sapx-intel-cell-val sapx-campaign">
            ${esc(item.apex_ai.campaign_id !== "UNCLASSIFIED" && item.apex_ai.campaign_id !== "PRO_REQUIRED"
              ? item.apex_ai.campaign_id
              : item.apex_ai.campaign_id === "PRO_REQUIRED"
                ? "🔒 PRO"
                : "UNCLASSIFIED")}
          </div>
        </div>
      </div>
      ${ttpsToShow.length > 0
        ? `<div class="sapx-mitre-row">
             <span class="sapx-mitre-label">⚔ MITRE ATT&CK</span>
             <div class="sapx-ttp-tags">${ttpTags}${moreBadge}</div>
           </div>`
        : ""}
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 4: AI INTELLIGENCE PANEL (expandable)
   * ───────────────────────────────────────────────────────────── */
  function renderAiIntelZone(item, cardId) {
    const ai = item.apex_ai;
    const confTier = ai.confidence_tier_meta;
    const aiConfColor = ai.ai_confidence >= 70 ? "#ef4444"
                      : ai.ai_confidence >= 50 ? "#f59e0b"
                      : "#64748b";

    return `
    <div class="sapx-zone sapx-zone-ai" id="sapx-ai-${esc(cardId)}">
      <div class="sapx-ai-header" onclick="SentinelApexCardRenderer.togglePanel('sapx-ai-body-${esc(cardId)}', this)">
        <div class="sapx-ai-title-row">
          <span class="sapx-ai-icon">🤖</span>
          <span class="sapx-ai-title">AI INTELLIGENCE</span>
          <span class="sapx-ai-conf-badge" style="background:${aiConfColor}22;color:${aiConfColor};border:1px solid ${aiConfColor}44;">
            AI CONF ${esc(String(ai.ai_confidence))}%
          </span>
          <span class="sapx-conf-tier-badge" style="color:${confTier.color};">
            ${esc(ai.threat_confidence_label)}
          </span>
        </div>
        <span class="sapx-expand-chevron">▼</span>
      </div>
      <div class="sapx-ai-body sapx-panel-collapsed" id="sapx-ai-body-${esc(cardId)}">
        <div class="sapx-ai-summary">
          <div class="sapx-ai-summary-label">🧠 AI SUMMARY</div>
          <p class="sapx-ai-summary-text">${esc(ai.ai_summary)}</p>
        </div>
        <div class="sapx-ai-metrics">
          <div class="sapx-ai-metric">
            <div class="sapx-ai-metric-label">PREDICTIVE RISK</div>
            <div class="sapx-ai-metric-val" style="color:${ai.predictive_risk >= 7 ? "#ff1a1a" : ai.predictive_risk >= 5 ? "#ff6600" : "#f59e0b"};">
              ${esc(ai.predictive_risk.toFixed(2))} / 10
            </div>
          </div>
          <div class="sapx-ai-metric">
            <div class="sapx-ai-metric-label">AI CONFIDENCE</div>
            <div class="sapx-ai-metric-val">${esc(String(ai.ai_confidence))}%</div>
          </div>
          <div class="sapx-ai-metric">
            <div class="sapx-ai-metric-label">TTP DENSITY</div>
            <div class="sapx-ai-metric-val">${esc(ai.ttp_density.toFixed(2))}</div>
          </div>
          <div class="sapx-ai-metric">
            <div class="sapx-ai-metric-label">ACTOR FINGERPRINT</div>
            <div class="sapx-ai-metric-val sapx-blurred-${esc(String(ai.kill_chain_locked))}">
              ${esc(ai.actor_fingerprint)}
            </div>
          </div>
        </div>
        <div class="sapx-ai-action">
          <div class="sapx-ai-action-label">⚡ RECOMMENDED ACTION</div>
          <div class="sapx-ai-action-text ${ai.kill_chain_locked ? "sapx-action-blur" : ""}">
            ${esc(ai.recommended_action)}
          </div>
        </div>
        ${ai.kill_chain_locked
          ? `<div class="sapx-kill-chain-lock">
               <span class="sapx-lock-icon">🔒</span>
               <span>Kill Chain · Actor Attribution · SOC Playbook → <strong>PRO REQUIRED</strong></span>
             </div>`
          : `<div class="sapx-kill-chain-live">
               <span class="sapx-chain-icon">⚔</span>
               Kill Chain: <span class="sapx-chain-val">${esc(ai.kill_chain_primary)}</span>
             </div>`}
      </div>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 5: EXPLOIT + SCORING
   * ───────────────────────────────────────────────────────────── */
  function renderExploitScoringZone(item) {
    const hasAnyScore = item.has_epss || item.has_cvss || item.kev_present;
    if (!hasAnyScore) return "";

    let epssHtml = "";
    if (item.has_epss) {
      const e = item.epss_score;
      epssHtml = `
        <div class="sapx-score-cell">
          <div class="sapx-score-label">EPSS EXPLOIT PROB.</div>
          <div class="sapx-score-val" style="color:${esc(e.color)};">${esc(e.display)}</div>
          <div class="sapx-score-sub sapx-score-risk-${esc(e.risk.toLowerCase())}">${esc(e.risk)} EXPLOIT RISK</div>
          <div class="sapx-epss-bar-wrap">
            <div class="sapx-epss-bar" style="width:${esc(String(Math.min(100, e.percent)))}%;background:${esc(e.color)};"></div>
          </div>
        </div>`;
    }

    let cvssHtml = "";
    if (item.has_cvss) {
      const c = item.cvss_score;
      cvssHtml = `
        <div class="sapx-score-cell">
          <div class="sapx-score-label">CVSS v3 SCORE</div>
          <div class="sapx-score-val" style="color:${esc(c.color)};">${esc(c.display)} / 10</div>
          <div class="sapx-score-sub sapx-score-risk-${esc(c.rating.toLowerCase())}">${esc(c.rating)}</div>
        </div>`;
    }

    let kevHtml = "";
    if (item.kev_present) {
      kevHtml = `
        <div class="sapx-score-cell sapx-kev-cell">
          <div class="sapx-score-label">CISA KEV</div>
          <div class="sapx-score-val sapx-kev-active">🏛️ ACTIVE</div>
          <div class="sapx-score-sub">Actively Exploited</div>
        </div>`;
    }

    return `
    <div class="sapx-zone sapx-zone-exploit">
      <div class="sapx-exploit-header">
        <span class="sapx-exploit-icon">💥</span>
        <span class="sapx-exploit-title">EXPLOIT & SCORING</span>
      </div>
      <div class="sapx-scores-row">
        ${epssHtml}${cvssHtml}${kevHtml}
      </div>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 6: TIMELINE BLOCK (expandable)
   * ───────────────────────────────────────────────────────────── */
  function renderTimelineZone(item, cardId) {
    return `
    <div class="sapx-zone sapx-zone-timeline">
      <div class="sapx-timeline-header" onclick="SentinelApexCardRenderer.togglePanel('sapx-tl-body-${esc(cardId)}', this)">
        <span class="sapx-timeline-icon">🕐</span>
        <span class="sapx-timeline-title">TIMELINE</span>
        <span class="sapx-tl-rel-time">${esc(item.published_at_rel)}</span>
        <span class="sapx-expand-chevron">▼</span>
      </div>
      <div class="sapx-timeline-body sapx-panel-collapsed" id="sapx-tl-body-${esc(cardId)}">
        <div class="sapx-tl-grid">
          <div class="sapx-tl-row">
            <span class="sapx-tl-label">📅 PUBLISHED</span>
            <span class="sapx-tl-val">${esc(item.published_at_fmt)}</span>
            <span class="sapx-tl-rel">${esc(item.published_at_rel)}</span>
          </div>
          <div class="sapx-tl-row">
            <span class="sapx-tl-label">⚙ PROCESSED</span>
            <span class="sapx-tl-val">${esc(item.processed_at_fmt)}</span>
            <span class="sapx-tl-rel">${esc(item.processed_at_rel)}</span>
          </div>
          ${item.timestamp && item.timestamp !== item.published_at
            ? `<div class="sapx-tl-row">
                 <span class="sapx-tl-label">🔄 LAST UPDATED</span>
                 <span class="sapx-tl-val">${esc(item.timestamp_fmt)}</span>
                 <span class="sapx-tl-rel">${esc(relativeTime(item.timestamp))}</span>
               </div>`
            : ""}
          <div class="sapx-tl-row">
            <span class="sapx-tl-label">🗂 STIX OBJECTS</span>
            <span class="sapx-tl-val">${esc(String(item.stix_object_count))} objects</span>
            <span class="sapx-tl-rel sapx-val-${esc(item.validation_status.class)}">${esc(item.validation_status.label)}</span>
          </div>
        </div>
      </div>
    </div>`;
  }

  function relativeTime(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "—";
      const diffMs = Date.now() - d.getTime();
      const diffMins = Math.floor(diffMs / 60000);
      if (diffMins < 1) return "just now";
      if (diffMins < 60) return diffMins + "m ago";
      const diffHrs = Math.floor(diffMins / 60);
      if (diffHrs < 24) return diffHrs + "h ago";
      return Math.floor(diffHrs / 24) + "d ago";
    } catch (e) { return "—"; }
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 7: PAYWALL CONVERSION BLOCK
   * ───────────────────────────────────────────────────────────── */
  function renderPaywallZone(item) {
    if (!item.paywall_active) return "";

    const iocPw  = item.ioc_paywall;
    const aiPw   = item.apex_ai.paywall;
    const socMeta = item.apex_ai.soc_priority_meta;

    // Determine urgency tier
    const isUrgent = item.is_high_priority;
    const pwClass  = isUrgent ? "sapx-pw-urgent" : "sapx-pw-standard";

    return `
    <div class="sapx-zone sapx-zone-paywall ${pwClass}">
      <div class="sapx-pw-inner">
        <div class="sapx-pw-lock-icon">🔒</div>
        <div class="sapx-pw-content">
          ${iocPw.locked
            ? `<div class="sapx-pw-ioc-msg">
                 <span class="sapx-pw-ioc-badge">${esc(String(iocPw.count))} IOC${iocPw.count !== 1 ? "s" : ""}</span>
                 ${esc(iocPw.message)}
               </div>`
            : ""}
          <div class="sapx-pw-ai-msg">${esc(aiPw.message)}</div>
          ${isUrgent
            ? `<div class="sapx-pw-urgency"
                    style="color:${esc(socMeta.color)};background:${esc(socMeta.bg)};border:1px solid ${esc(socMeta.border)};">
                 ⚡ ${esc(aiPw.urgency)}
               </div>`
            : ""}
        </div>
        <a href="${esc(aiPw.upgrade_url || iocPw.upgrade_url)}"
           class="sapx-pw-cta ${isUrgent ? "sapx-pw-cta-urgent" : ""}"
           target="_blank" rel="noopener">
          🔓 Unlock Full Intelligence
          <span class="sapx-pw-cta-arrow">→</span>
        </a>
      </div>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  ZONE 8: FOOTER
   * ───────────────────────────────────────────────────────────── */
  function renderFooterZone(item) {
    return `
    <div class="sapx-zone sapx-zone-footer">
      <div class="sapx-footer-left">
        <a href="${esc(item.source_url)}" target="_blank" rel="noopener" class="sapx-source-link">
          <span class="sapx-source-dot">●</span>
          <span class="sapx-source-name">${esc(item.source_host)}</span>
        </a>
        <span class="sapx-stix-id" title="${esc(item.stix_id)}">${esc(item.stix_id_short)}</span>
        <span class="sapx-val-badge sapx-val-${esc(item.validation_status.class)}"
              style="color:${esc(item.validation_status.color)};">
          ${esc(item.validation_status.label)}
        </span>
      </div>
      <div class="sapx-footer-right">
        ${item.stix_bundle_url
          ? `<a href="${esc(item.stix_bundle_url)}" target="_blank" rel="noopener" class="sapx-stix-link">
               📦 STIX 2.1
             </a>`
          : ""}
        <a href="${esc(item.report_url)}" target="_blank" rel="noopener" class="sapx-report-link">
          📄 VIEW REPORT ↗
        </a>
      </div>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  CARD ASSEMBLER — composes all 8 zones
   * ───────────────────────────────────────────────────────────── */
  function buildCard(item) {
    if (!item || typeof item !== "object") return "";

    // Generate stable card ID from stix_id or random
    const cardId = (item.stix_id || item.id || "").replace(/[^a-z0-9]/gi, "").slice(-12)
                   || "card" + Math.random().toString(36).slice(2, 8);

    const sc = item.severity_colors;

    const zones = [
      renderHeaderZone(item),
      renderSocPriorityZone(item),
      renderIntelCoreZone(item),
      renderAiIntelZone(item, cardId),
      renderExploitScoringZone(item),   // conditional — only renders if EPSS/CVSS/KEV present
      renderTimelineZone(item, cardId),
      renderPaywallZone(item),           // conditional — only renders if paywall active
      renderFooterZone(item),
    ].filter(Boolean).join("");

    return `
    <article class="sapx-card ${esc(sc.class)} ${item.is_high_priority ? "sapx-card-priority" : ""}"
             data-id="${esc(item.id)}"
             data-severity="${esc(item.severity)}"
             data-soc-priority="${esc(item.apex_ai.soc_priority)}"
             data-risk="${esc(item.risk_score.raw)}"
             data-threat-type="${esc(item.threat_type)}"
             style="--sapx-sev-color:${esc(sc.primary)};--sapx-sev-glow:${esc(sc.glow)};--sapx-sev-dim:${esc(sc.dim)};--sapx-sev-border:${esc(sc.border)};--sapx-sev-text:${esc(sc.text)};">
      ${zones}
    </article>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  FALLBACK / ERROR CARD
   * ───────────────────────────────────────────────────────────── */
  function buildErrorCard(message) {
    return `
    <article class="sapx-card sev-low sapx-card-error">
      <div class="sapx-zone sapx-zone-header">
        <div class="sapx-header-row">
          <div class="sapx-sev-badge sapx-sev-low">⚠ ERROR</div>
        </div>
        <h3 class="sapx-title">${esc(message || "Failed to render intelligence card")}</h3>
      </div>
      <div class="sapx-zone sapx-zone-footer">
        <div class="sapx-footer-left">
          <span style="color:#64748b;font-size:11px;">Check API connectivity and reload.</span>
        </div>
      </div>
    </article>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  LOADING SKELETON
   * ───────────────────────────────────────────────────────────── */
  function buildLoadingCard() {
    return `
    <article class="sapx-card sapx-card-skeleton">
      <div class="sapx-zone sapx-zone-header">
        <div class="sapx-header-row">
          <div class="sapx-skeleton sapx-sk-badge"></div>
          <div class="sapx-skeleton sapx-sk-score"></div>
        </div>
        <div class="sapx-skeleton sapx-sk-title"></div>
        <div class="sapx-skeleton sapx-sk-title sapx-sk-title-short"></div>
      </div>
      <div class="sapx-zone sapx-zone-soc">
        <div class="sapx-skeleton sapx-sk-soc"></div>
      </div>
      <div class="sapx-zone sapx-zone-intel-core">
        <div class="sapx-intel-grid">
          <div class="sapx-skeleton sapx-sk-cell"></div>
          <div class="sapx-skeleton sapx-sk-cell"></div>
          <div class="sapx-skeleton sapx-sk-cell"></div>
          <div class="sapx-skeleton sapx-sk-cell"></div>
        </div>
      </div>
    </article>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  RENDER GRID — renders array of normalized items
   * ───────────────────────────────────────────────────────────── */
  function renderGrid(container, normalizedItems, options) {
    if (!container) {
      console.error("[SentinelApexCardRenderer] Container element not found.");
      return;
    }

    const opts = options || {};
    const maxCards = opts.maxCards || 50;

    if (!normalizedItems || normalizedItems.length === 0) {
      container.innerHTML = buildEmptyState();
      return;
    }

    const itemsToRender = normalizedItems.slice(0, maxCards);
    const html = itemsToRender.map(function (item) {
      try {
        return buildCard(item);
      } catch (e) {
        console.warn("[SentinelApexCardRenderer] Card build error:", e, item);
        return buildErrorCard("Card render failed: " + (e.message || "Unknown error"));
      }
    }).join("");

    container.innerHTML = html;
    _attachCardEvents(container);
  }

  /* ─────────────────────────────────────────────────────────────
   *  RENDER FROM API RESPONSE — convenience method
   * ───────────────────────────────────────────────────────────── */
  function renderFromApiResponse(container, apiResponse, options) {
    if (!Adapter) {
      console.error("[SentinelApexCardRenderer] SentinelApexAdapter not found. Load js/api_adapter.js first.");
      return;
    }

    // Show loading state
    showLoadingState(container, options && options.loadingCount || 3);

    try {
      const normalized = Adapter.normalizeApiResponse(apiResponse);
      renderGrid(container, normalized.items, options);
      return normalized;
    } catch (e) {
      console.error("[SentinelApexCardRenderer] API response render failed:", e);
      container.innerHTML = buildEmptyState("API data processing error. Check console.");
    }
  }

  /* ─────────────────────────────────────────────────────────────
   *  FETCH AND RENDER — all-in-one convenience method
   * ───────────────────────────────────────────────────────────── */
  async function fetchAndRender(container, url, options) {
    if (!Adapter) {
      console.error("[SentinelApexCardRenderer] SentinelApexAdapter not loaded.");
      return null;
    }

    showLoadingState(container, (options && options.loadingCount) || 3);

    const result = await Adapter.fetchAndNormalize(url, options);

    if (result.error || !result.normalized || result.normalized.items.length === 0) {
      container.innerHTML = buildEmptyState(
        result.cached
          ? "⚠ Displaying cached intelligence — live feed temporarily unavailable."
          : "⚠ Could not load threat intelligence feed. API may be offline."
      );
      return null;
    }

    renderGrid(container, result.normalized.items, options);
    return result.normalized;
  }

  /* ─────────────────────────────────────────────────────────────
   *  LOADING STATE
   * ───────────────────────────────────────────────────────────── */
  function showLoadingState(container, count) {
    if (!container) return;
    const skeletons = Array(count || 3).fill(buildLoadingCard()).join("");
    container.innerHTML = `<div class="sapx-loading">${skeletons}</div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  EMPTY STATE
   * ───────────────────────────────────────────────────────────── */
  function buildEmptyState(message) {
    return `
    <div class="sapx-empty-state">
      <div class="sapx-empty-icon">🛡</div>
      <div class="sapx-empty-title">No Threat Intelligence Available</div>
      <div class="sapx-empty-msg">${esc(message || "Feed is empty or filters returned no results.")}</div>
    </div>`;
  }

  /* ─────────────────────────────────────────────────────────────
   *  PANEL TOGGLE (for AI / Timeline expandables)
   * ───────────────────────────────────────────────────────────── */
  function togglePanel(panelId, headerEl) {
    const panel = document.getElementById(panelId);
    if (!panel) return;
    const isCollapsed = panel.classList.contains("sapx-panel-collapsed");
    panel.classList.toggle("sapx-panel-collapsed", !isCollapsed);
    panel.classList.toggle("sapx-panel-expanded", isCollapsed);
    if (headerEl) {
      const chev = headerEl.querySelector(".sapx-expand-chevron");
      if (chev) chev.style.transform = isCollapsed ? "rotate(180deg)" : "";
    }
  }

  /* ─────────────────────────────────────────────────────────────
   *  CARD EVENTS — attach interactive behavior post-render
   * ───────────────────────────────────────────────────────────── */
  function _attachCardEvents(container) {
    // Hover glow effect via CSS variables — handled in CSS
    // Copy STIX ID on click
    container.querySelectorAll(".sapx-stix-id").forEach(function (el) {
      el.style.cursor = "pointer";
      el.title = "Click to copy full STIX ID";
      el.addEventListener("click", function () {
        const fullId = el.getAttribute("data-full-id") || el.textContent;
        try {
          navigator.clipboard.writeText(fullId);
          el.textContent = "✓ Copied!";
          setTimeout(function () { el.textContent = el.getAttribute("data-short-id") || fullId; }, 1500);
        } catch (e) { /* clipboard not available */ }
      });
    });

    // TTP tag analytics
    container.querySelectorAll(".sapx-ttp-tag").forEach(function (el) {
      el.addEventListener("click", function (e) {
        // Allow default link navigation
        if (typeof window.SentinelApexAnalytics !== "undefined") {
          window.SentinelApexAnalytics.track("ttp_click", { id: el.textContent.trim() });
        }
      });
    });

    // Paywall CTA tracking
    container.querySelectorAll(".sapx-pw-cta").forEach(function (el) {
      el.addEventListener("click", function () {
        if (typeof window.SentinelApexAnalytics !== "undefined") {
          window.SentinelApexAnalytics.track("paywall_cta_click", { url: el.href });
        }
      });
    });
  }

  /* ─────────────────────────────────────────────────────────────
   *  FILTER CARDS — client-side filter by severity/type/search
   * ───────────────────────────────────────────────────────────── */
  function filterCards(container, filters) {
    if (!container) return;
    const cards = container.querySelectorAll(".sapx-card");
    let visible = 0;
    cards.forEach(function (card) {
      let show = true;
      if (filters.severity && card.dataset.severity !== filters.severity.toUpperCase()) show = false;
      if (filters.socPriority && card.dataset.socPriority !== filters.socPriority.toUpperCase()) show = false;
      if (filters.search) {
        const text = card.textContent.toLowerCase();
        if (!text.includes(filters.search.toLowerCase())) show = false;
      }
      card.style.display = show ? "" : "none";
      if (show) visible++;
    });
    return visible;
  }

  /* ─────────────────────────────────────────────────────────────
   *  SORT CARDS — client-side sort by risk/date
   * ───────────────────────────────────────────────────────────── */
  function sortCards(container, sortBy) {
    if (!container) return;
    const cards = Array.from(container.querySelectorAll(".sapx-card"));
    cards.sort(function (a, b) {
      switch (sortBy) {
        case "risk_desc": return parseFloat(b.dataset.risk || 0) - parseFloat(a.dataset.risk || 0);
        case "risk_asc":  return parseFloat(a.dataset.risk || 0) - parseFloat(b.dataset.risk || 0);
        case "priority":
          const pOrder = { P1: 0, P2: 1, P3: 2, P4: 3 };
          return (pOrder[a.dataset.socPriority] || 3) - (pOrder[b.dataset.socPriority] || 3);
        default: return 0;
      }
    });
    cards.forEach(function (c) { container.appendChild(c); });
  }

  /* ─────────────────────────────────────────────────────────────
   *  DROP-IN INTEGRATION — replaces existing card containers
   *  that use the old v70 schema on page load
   * ───────────────────────────────────────────────────────────── */
  function integrateWithExistingDashboard(containerSelector, apiUrl, options) {
    const container = document.querySelector(containerSelector);
    if (!container) {
      console.warn("[SentinelApexCardRenderer] Container not found:", containerSelector);
      return;
    }
    fetchAndRender(container, apiUrl, options).then(function (normalized) {
      if (normalized) {
        // Fire event for other dashboard components to consume
        window.dispatchEvent(new CustomEvent("SentinelApexCardsReady", {
          detail: { normalized: normalized }
        }));
      }
    });
  }

  /* ─────────────────────────────────────────────────────────────
   *  PUBLIC API
   * ───────────────────────────────────────────────────────────── */
  const PublicAPI = {
    // Build
    buildCard:                buildCard,
    buildErrorCard:           buildErrorCard,
    buildLoadingCard:         buildLoadingCard,

    // Render
    renderGrid:               renderGrid,
    renderFromApiResponse:    renderFromApiResponse,
    fetchAndRender:           fetchAndRender,
    showLoadingState:         showLoadingState,

    // Interact
    togglePanel:              togglePanel,
    filterCards:              filterCards,
    sortCards:                sortCards,

    // Integration
    integrateWithExistingDashboard: integrateWithExistingDashboard,

    // Version
    VERSION: "143.0.0",
    BUILD:   "SENTINEL-APEX-CARD-RENDERER-PROD",
  };

  // Expose togglePanel globally for onclick handlers in card HTML
  if (typeof window !== "undefined") {
    window.SentinelApexCardRenderer = PublicAPI;
  }

  return PublicAPI;

}); // end factory

// Signal ready
if (typeof window !== "undefined") {
  window.dispatchEvent(new CustomEvent("SentinelApexCardRendererReady", {
    detail: { version: "143.0.0" }
  }));
  console.info("[SENTINEL APEX] Card Renderer v143.0.0 loaded ✓");
}
