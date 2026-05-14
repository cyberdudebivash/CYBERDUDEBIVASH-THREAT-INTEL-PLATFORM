/**
 * ═══════════════════════════════════════════════════════════════════════════════
 *  SENTINEL APEX — ENTERPRISE CARD RENDERER v147.0.0
 *  Decision-First SOC Intelligence Cards + Conversion-Optimized Revenue Units
 *  Author: CYBERDUDEBIVASH SENTINEL APEX Platform
 *
 *  9-ZONE ARCHITECTURE:
 *   [1] 🔴 DECISION HEADER        — severity, risk score, confidence, SOC priority
 *   [2] ⚡ SOC DECISION STRIP     — threat level, predictive risk, action rec
 *   [3] 🧠 AI VERDICT PANEL       — structured AI insight, confidence, human verdict
 *   [4] 🎯 IMPACT & CONTEXT       — attack type, target surface, potential impact
 *   [5] 📊 INTELLIGENCE CORE      — actor, IOC, TTP count, MITRE ATT&CK tags
 *   [6] 💥 EXPLOIT & SCORING      — EPSS, CVSS, KEV indicator
 *   [7] ⏱  TIMELINE INTELLIGENCE  — published, processed, freshness indicator
 *   [8] 🔒 PAYWALL + MONETIZATION — value prop list, urgency, PRO CTA ($49/mo)
 *   [9] 🟢 TRUST + VALIDATION     — source, STIX verified, MITRE mapped, report CTA
 *
 *  Design: Recorded Future / GreyNoise / VirusTotal Intelligence standard
 *  Pipeline Safety: NEVER overwritten by CI/CD. Static UI layer.
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

  /* ── HTML ESCAPE ─────────────────────────────────────────────────────────── */
  function esc(str) {
    const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(str || "").replace(/[&<>"']/g, function (m) { return map[m]; });
  }

  function relativeTime(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return "—";
      const diffMins = Math.floor((Date.now() - d.getTime()) / 60000);
      if (diffMins < 1)  return "just now";
      if (diffMins < 60) return diffMins + "m ago";
      const diffHrs = Math.floor(diffMins / 60);
      if (diffHrs < 24)  return diffHrs + "h ago";
      return Math.floor(diffHrs / 24) + "d ago";
    } catch (e) { return "—"; }
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 1: 🔴 DECISION HEADER (TOP PRIORITY ZONE)
   *  Answers "What is this?" and "How serious?" in < 1 second.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderDecisionHeader(item) {
    const sc     = item.severity_colors;
    const rs     = item.risk_score;
    const ai     = item.apex_ai;
    const socMeta = ai.soc_priority_meta;
    const isPrio = item.is_high_priority;

    const predScore = item.apex.predictive_score > 0 ? item.apex.predictive_score : ai.predictive_risk;

    return `
    <div class="sapx-zone sapx-zone-header" data-severity="${esc(item.severity)}">
      <div class="sapx-hdr-top-row">
        <div class="sapx-hdr-left">
          <div class="sapx-sev-badge sapx-sev-${esc(item.severity.toLowerCase())}"
               style="background:${esc(sc.dim)};color:${esc(sc.text)};border:1px solid ${esc(sc.border)};box-shadow:0 0 12px ${esc(sc.glow)};">
            ${isPrio ? '<span class="sapx-pulse-dot"></span>' : ""}
            ${esc(item.severity)}
          </div>
          <div class="sapx-threat-type-pill">${esc(item.threat_type)}</div>
          ${item.kev_present ? `<div class="sapx-kev-badge">🏛 KEV</div>` : ""}
        </div>
        <div class="sapx-hdr-right">
          <div class="sapx-soc-mini" style="color:${esc(socMeta.color)};background:${esc(socMeta.bg)};border:1px solid ${esc(socMeta.border)};">
            ${esc(socMeta.badge)} ${esc(ai.soc_priority)}
          </div>
        </div>
      </div>

      <h3 class="sapx-title" title="${esc(item.title)}">${esc(item.title)}</h3>

      <div class="sapx-hdr-metrics-row">
        <div class="sapx-risk-block" style="--risk-color:${esc(rs.color)};">
          <span class="sapx-risk-num" style="color:${esc(rs.color)};text-shadow:0 0 18px ${esc(rs.color)}80;">${esc(rs.display)}</span>
          <span class="sapx-risk-denom">/ 10</span>
          <span class="sapx-risk-label">RISK</span>
          <div class="sapx-risk-bar-track">
            <div class="sapx-risk-bar-fill" style="width:${esc(String(rs.percent))}%;background:${esc(rs.color)};box-shadow:0 0 8px ${esc(rs.color)}90;"></div>
          </div>
        </div>
        <div class="sapx-hdr-divider"></div>
        <div class="sapx-conf-block">
          <div class="sapx-conf-val" style="color:${esc(sc.text)};">${esc(item.confidence_display)}</div>
          <div class="sapx-conf-label">CONFIDENCE</div>
        </div>
        <div class="sapx-hdr-divider"></div>
        <div class="sapx-pred-block">
          <div class="sapx-pred-val" style="color:${predScore >= 7 ? "#ff1a1a" : predScore >= 5 ? "#ff6600" : "#f59e0b"};">
            ${esc(predScore.toFixed(1))}<span class="sapx-pred-denom">/10</span>
          </div>
          <div class="sapx-pred-label">PREDICTIVE</div>
        </div>
      </div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 2: ⚡ SOC DECISION STRIP (CRITICAL ACTION ZONE)
   *  Answers "Do I need to act?" immediately.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderSocDecisionStrip(item) {
    const ai      = item.apex_ai;
    const socMeta = ai.soc_priority_meta;
    const rec     = item.action_rec;
    const isPrio  = item.is_high_priority;

    return `
    <div class="sapx-zone sapx-zone-soc-strip"
         style="background:${esc(socMeta.bg)};border-top:2px solid ${esc(socMeta.border)};border-bottom:1px solid ${esc(socMeta.border)};">
      <div class="sapx-soc-strip-inner">
        <div class="sapx-soc-priority-badge" style="color:${esc(socMeta.color)};border:1px solid ${esc(socMeta.border)};background:${esc(socMeta.bg)};">
          <span class="sapx-soc-emoji">${esc(socMeta.badge)}</span>
          <div class="sapx-soc-text">
            <span class="sapx-soc-code">${esc(ai.soc_priority)}</span>
            <span class="sapx-soc-sublabel">${esc(socMeta.shortLabel)}</span>
          </div>
        </div>

        <div class="sapx-soc-strip-divider"></div>

        <div class="sapx-threat-level-block">
          <span class="sapx-tl-label">THREAT LEVEL</span>
          <span class="sapx-tl-val" style="color:${esc(item.severity_colors.text)};">${esc(ai.threat_level)}</span>
        </div>

        <div class="sapx-soc-strip-divider"></div>

        <div class="sapx-action-rec-block ${isPrio ? "sapx-action-urgent" : ""}"
             style="background:${esc(rec.bg)};border:1px solid ${esc(rec.border)};color:${esc(rec.color)};">
          <span class="sapx-action-icon">${esc(rec.icon)}</span>
          <div class="sapx-action-text">
            <span class="sapx-action-prefix">⚠ ACTION REQUIRED:</span>
            <span class="sapx-action-label">${esc(rec.label)}</span>
          </div>
        </div>
      </div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 3: 🧠 AI VERDICT PANEL (CONVERSION DRIVER)
   *  Human-readable structured insight. Drives "I need this data" feeling.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderAiVerdictPanel(item, cardId) {
    const ai        = item.apex_ai;
    const confTier  = ai.confidence_tier_meta;
    const aiConf    = ai.ai_confidence;
    const aiConfClr = aiConf >= 80 ? "#ef4444" : aiConf >= 50 ? "#f59e0b" : "#64748b";
    const verdict   = item.ai_verdict;

    return `
    <div class="sapx-zone sapx-zone-ai-verdict">
      <div class="sapx-av-header" onclick="SentinelApexCardRenderer.togglePanel('sapx-av-body-${esc(cardId)}', this)"
           role="button" aria-expanded="false">
        <div class="sapx-av-header-left">
          <span class="sapx-av-icon">🤖</span>
          <span class="sapx-av-title">AI INTELLIGENCE</span>
          <span class="sapx-av-category-pill">${esc(ai.threat_category)}</span>
        </div>
        <div class="sapx-av-header-right">
          <span class="sapx-av-conf-badge" style="background:${esc(aiConfClr)}22;color:${esc(aiConfClr)};border:1px solid ${esc(aiConfClr)}55;">
            AI ${esc(String(aiConf))}% CONF
          </span>
          <span class="sapx-conf-tier" style="color:${esc(confTier.color)};text-shadow:0 0 8px ${esc(confTier.glow)};">
            ${esc(confTier.label)}
          </span>
          <span class="sapx-expand-chevron">▼</span>
        </div>
      </div>

      <div class="sapx-av-verdict-strip">
        <span class="sapx-av-verdict-icon">🧠</span>
        <p class="sapx-av-verdict-text">${esc(verdict)}</p>
      </div>

      <div class="sapx-av-body sapx-panel-collapsed" id="sapx-av-body-${esc(cardId)}">
        <div class="sapx-av-metrics-grid">
          <div class="sapx-av-metric">
            <div class="sapx-av-metric-label">PREDICTIVE RISK</div>
            <div class="sapx-av-metric-val" style="color:${ai.predictive_risk >= 7 ? "#ff1a1a" : ai.predictive_risk >= 5 ? "#ff6600" : "#f59e0b"};">
              ${esc(ai.predictive_risk.toFixed(2))} <span style="font-size:10px;opacity:0.6;">/ 10</span>
            </div>
          </div>
          <div class="sapx-av-metric">
            <div class="sapx-av-metric-label">AI CONFIDENCE</div>
            <div class="sapx-av-metric-val" style="color:${esc(aiConfClr)};">${esc(String(aiConf))}%</div>
          </div>
          <div class="sapx-av-metric">
            <div class="sapx-av-metric-label">TTP DENSITY</div>
            <div class="sapx-av-metric-val">${esc(ai.ttp_density.toFixed(2))}</div>
          </div>
          <div class="sapx-av-metric">
            <div class="sapx-av-metric-label">CAMPAIGN</div>
            <div class="sapx-av-metric-val sapx-campaign-val">${esc(ai.campaign_id === "UNCLASSIFIED" ? "—" : ai.campaign_id)}</div>
          </div>
        </div>

        <div class="sapx-av-threat-label-row">
          <span class="sapx-av-tl-label">THREAT CONFIDENCE:</span>
          <span class="sapx-av-tl-val" style="color:${esc(confTier.color)};">${esc(ai.threat_confidence_label)}</span>
        </div>

        ${ai.recommended_action && !ai.kill_chain_locked
          ? `<div class="sapx-av-action-block">
               <div class="sapx-av-action-hdr">⚡ RECOMMENDED ACTION</div>
               <div class="sapx-av-action-body">${esc(ai.recommended_action)}</div>
             </div>`
          : ""}

        ${ai.kill_chain_locked
          ? `<div class="sapx-av-killchain-lock">
               <span class="sapx-lock-icon">🔒</span>
               <span>Kill Chain · Actor Attribution · SOC Playbook</span>
               <span class="sapx-pro-tag">PRO REQUIRED</span>
             </div>`
          : ai.kill_chain_primary && ai.kill_chain_primary !== "PRO_REQUIRED"
            ? `<div class="sapx-av-killchain-live">
                 <span class="sapx-chain-icon">⚔</span>
                 <span class="sapx-chain-label">KILL CHAIN:</span>
                 <span class="sapx-chain-val">${esc(ai.kill_chain_primary)}</span>
               </div>`
            : ""}
      </div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 4: 🎯 IMPACT & CONTEXT BLOCK
   *  Explains WHY this matters to the specific environment.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderImpactContext(item) {
    const ctx = item.impact_context;
    const bi  = item.business_impact || {};
    const sc  = item.severity_colors;

    // Business impact rows — only render if we have the field
    const biRows = [
      { label: "💰 FINANCIAL RISK",    val: bi.financial_risk },
      { label: "⚙️ OPERATIONAL",       val: bi.operational_impact },
      { label: "📋 COMPLIANCE",        val: bi.compliance_exposure },
      { label: "👥 CUSTOMER IMPACT",   val: bi.customer_impact },
      { label: "🏗 INFRASTRUCTURE",    val: bi.infrastructure_risk },
    ].filter(function (r) { return r.val; });

    const biHtml = biRows.length > 0
      ? `<div class="sapx-bi-section">
           <div class="sapx-bi-header">📊 BUSINESS IMPACT ASSESSMENT</div>
           ${biRows.map(function (r) {
             return `<div class="sapx-bi-row">
               <span class="sapx-bi-label">${esc(r.label)}</span>
               <span class="sapx-bi-val">${esc(r.val)}</span>
             </div>`;
           }).join("")}
         </div>`
      : "";

    return `
    <div class="sapx-zone sapx-zone-impact">
      <div class="sapx-impact-header">
        <span class="sapx-impact-icon">${esc(ctx.attack_icon)}</span>
        <span class="sapx-impact-title">IMPACT &amp; CONTEXT</span>
        <span class="sapx-attack-type-pill" style="color:${esc(sc.text)};background:${esc(sc.dim)};border:1px solid ${esc(sc.border)};">
          ${esc(ctx.attack_type)}
        </span>
      </div>
      <div class="sapx-impact-body">
        <div class="sapx-impact-row">
          <span class="sapx-impact-row-label">⚡ POTENTIAL IMPACT</span>
          <span class="sapx-impact-row-val">${esc(ctx.potential_impact)}</span>
        </div>
        <div class="sapx-impact-row">
          <span class="sapx-impact-row-label">🎯 TARGET SURFACE</span>
          <span class="sapx-impact-row-val">${esc(ctx.target_surface)}</span>
        </div>
        ${biHtml}
      </div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 5: 📊 INTELLIGENCE CORE
   *  Raw threat intelligence metrics — actor, IOC, TTP, MITRE.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderIntelCore(item) {
    const ttpsToShow = (item.ttps.length ? item.ttps : item.mitre_tactics).slice(0, 8);
    const moreCount  = Math.max(0, (item.ttp_count || 0) - ttpsToShow.length);

    const ttpTags = ttpsToShow.map(function (t) {
      return `<a href="${esc(t.url)}" target="_blank" rel="noopener"
                 class="sapx-ttp-tag" title="${esc(t.name)} — ${esc(t.tactic)}">${esc(t.id)}</a>`;
    }).join("");

    return `
    <div class="sapx-zone sapx-zone-intel-core">
      <div class="sapx-ic-header">
        <span class="sapx-ic-title">📊 INTELLIGENCE CORE</span>
      </div>
      <div class="sapx-intel-grid">
        <div class="sapx-intel-cell">
          <div class="sapx-ic-label">ACTOR</div>
          <div class="sapx-ic-val sapx-actor">
            <span class="sapx-actor-icon">🎭</span>${esc(item.actor_tag)}
          </div>
        </div>
        <div class="sapx-intel-cell">
          <div class="sapx-ic-label">IOC COUNT</div>
          <div class="sapx-ic-val">
            <span class="sapx-ioc-num">${esc(String(item.ioc_count))}</span>
            ${item.ioc_count > 0
              ? `<span class="sapx-ioc-conf">${esc(item.ioc_confidence.toFixed(0))}% conf</span>`
              : `<span class="sapx-ioc-none">No IOCs</span>`}
          </div>
        </div>
        <div class="sapx-intel-cell">
          <div class="sapx-ic-label">TTP COUNT</div>
          <div class="sapx-ic-val">
            <span class="sapx-ttp-num">${esc(String(item.ttp_count))}</span>
            <span class="sapx-ttp-density">density ${esc(item.apex_ai.ttp_density.toFixed(1))}</span>
          </div>
        </div>
        <div class="sapx-intel-cell">
          <div class="sapx-ic-label">THREAT LEVEL</div>
          <div class="sapx-ic-val">
            <span class="sapx-ioc-threat sapx-sev-text-${esc(item.apex_ai.threat_level.toLowerCase())}">${esc(item.apex_ai.threat_level)}</span>
          </div>
        </div>
      </div>
      ${ttpsToShow.length > 0
        ? `<div class="sapx-mitre-row">
             <span class="sapx-mitre-label">⚔ MITRE ATT&amp;CK</span>
             <div class="sapx-ttp-tags">
               ${ttpTags}
               ${moreCount > 0 ? `<span class="sapx-ttp-more">+${moreCount} more</span>` : ""}
             </div>
           </div>`
        : `<div class="sapx-mitre-empty">No MITRE ATT&amp;CK techniques mapped</div>`}
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 6: 💥 EXPLOIT & SCORING
   *  EPSS, CVSS, KEV — rendered only when data is present.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderExploitScoring(item) {
    const hasAnyScore = item.has_epss || item.has_cvss || item.kev_present;
    if (!hasAnyScore) return "";

    let epssHtml = "", cvssHtml = "", kevHtml = "";

    if (item.has_epss) {
      const e = item.epss_score;
      epssHtml = `
      <div class="sapx-score-cell">
        <div class="sapx-score-label">EPSS EXPLOIT PROBABILITY</div>
        <div class="sapx-score-val" style="color:${esc(e.color)};">${esc(e.display)}</div>
        <div class="sapx-score-risk sapx-risk-${esc(e.risk.split(" ")[0].toLowerCase())}">${esc(e.risk)}</div>
        <div class="sapx-epss-track">
          <div class="sapx-epss-fill" style="width:${esc(String(Math.min(100, e.percent)))}%;background:${esc(e.color)};box-shadow:0 0 6px ${esc(e.color)}80;"></div>
        </div>
      </div>`;
    }

    if (item.has_cvss) {
      const c = item.cvss_score;
      cvssHtml = `
      <div class="sapx-score-cell">
        <div class="sapx-score-label">CVSS v3 SCORE</div>
        <div class="sapx-score-val" style="color:${esc(c.color)};">${esc(c.display)} <span style="opacity:0.5;font-size:11px;">/ 10</span></div>
        <div class="sapx-score-risk sapx-risk-${esc(c.rating.toLowerCase())}">${esc(c.rating)}</div>
      </div>`;
    }

    if (item.kev_present) {
      kevHtml = `
      <div class="sapx-score-cell sapx-kev-cell">
        <div class="sapx-score-label">CISA KEV STATUS</div>
        <div class="sapx-score-val sapx-kev-active">🏛 ACTIVELY EXPLOITED</div>
        <div class="sapx-score-risk sapx-risk-critical">PATCH IMMEDIATELY</div>
      </div>`;
    }

    return `
    <div class="sapx-zone sapx-zone-exploit">
      <div class="sapx-exploit-hdr">
        <span class="sapx-exploit-icon">💥</span>
        <span class="sapx-exploit-title">EXPLOIT &amp; SCORING</span>
      </div>
      <div class="sapx-scores-row">${epssHtml}${cvssHtml}${kevHtml}</div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 7: ⏱ TIMELINE INTELLIGENCE
   *  Temporal context + freshness indicator.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderTimeline(item, cardId) {
    const fresh = item.freshness;
    const vs    = item.validation_status;

    return `
    <div class="sapx-zone sapx-zone-timeline">
      <div class="sapx-tl-header" onclick="SentinelApexCardRenderer.togglePanel('sapx-tl-body-${esc(cardId)}', this)"
           role="button" aria-expanded="false">
        <div class="sapx-tl-hdr-left">
          <span class="sapx-tl-icon">⏱</span>
          <span class="sapx-tl-title">TIMELINE INTELLIGENCE</span>
        </div>
        <div class="sapx-tl-hdr-right">
          <span class="sapx-freshness-badge ${esc(fresh.class)}"
                style="color:${esc(fresh.color)};border:1px solid ${esc(fresh.color)}66;background:${esc(fresh.color)}15;">
            ${esc(fresh.icon)} ${esc(fresh.label)}
          </span>
          <span class="sapx-tl-rel-time">${esc(item.published_at_rel)}</span>
          <span class="sapx-expand-chevron">▼</span>
        </div>
      </div>
      <div class="sapx-tl-body sapx-panel-collapsed" id="sapx-tl-body-${esc(cardId)}">
        <div class="sapx-tl-grid">
          <div class="sapx-tl-row">
            <span class="sapx-tl-row-label">📅 PUBLISHED</span>
            <span class="sapx-tl-row-val">${esc(item.published_at_fmt)}</span>
            <span class="sapx-tl-row-rel">${esc(item.published_at_rel)}</span>
          </div>
          <div class="sapx-tl-row">
            <span class="sapx-tl-row-label">⚙ PROCESSED</span>
            <span class="sapx-tl-row-val">${esc(item.processed_at_fmt)}</span>
            <span class="sapx-tl-row-rel">${esc(item.processed_at_rel)}</span>
          </div>
          ${item.timestamp && item.timestamp !== item.published_at
            ? `<div class="sapx-tl-row">
                 <span class="sapx-tl-row-label">🔄 LAST UPDATED</span>
                 <span class="sapx-tl-row-val">${esc(item.timestamp_fmt)}</span>
                 <span class="sapx-tl-row-rel">${esc(relativeTime(item.timestamp))}</span>
               </div>`
            : ""}
          <div class="sapx-tl-row">
            <span class="sapx-tl-row-label">📦 STIX OBJECTS</span>
            <span class="sapx-tl-row-val">${esc(String(item.stix_object_count))} objects in bundle</span>
            <span class="sapx-tl-row-rel sapx-val-${esc(vs.class)}" style="color:${esc(vs.color)};">${esc(vs.label)}</span>
          </div>
        </div>
      </div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 8: 🔒 PAYWALL + MONETIZATION (MANDATORY)
   *  Full value proposition. Converts intelligence gaps into revenue.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderPaywall(item) {
    if (!item.paywall_active) return "";

    const iocPw    = item.ioc_paywall;
    const aiPw     = item.apex_ai.paywall;
    const socMeta  = item.apex_ai.soc_priority_meta;
    const features = item.paywall_features;
    const isUrgent = item.is_high_priority;
    const ctaUrl   = aiPw.upgrade_url || iocPw.upgrade_url || "/upgrade.html?plan=pro&utm_source=card-cta";

    const featureListHtml = features.map(function (f) {
      return `<li class="sapx-pw-feature-item">
                <span class="sapx-pw-feature-check">${esc(f.icon)}</span>
                <span class="sapx-pw-feature-text">${esc(f.text)}</span>
              </li>`;
    }).join("");

    return `
    <div class="sapx-zone sapx-zone-paywall ${isUrgent ? "sapx-pw-urgent" : "sapx-pw-standard"}">
      <div class="sapx-pw-top">
        <div class="sapx-pw-title-row">
          <span class="sapx-pw-lock-icon">🔒</span>
          <span class="sapx-pw-title">FULL INTELLIGENCE LOCKED</span>
        </div>
        ${iocPw.locked && iocPw.count > 0
          ? `<div class="sapx-pw-ioc-row">
               <span class="sapx-pw-ioc-badge">${esc(String(iocPw.count))} IOC${iocPw.count !== 1 ? "s" : ""}</span>
               <span class="sapx-pw-ioc-msg">${esc(iocPw.message)}</span>
             </div>`
          : ""}
        ${isUrgent
          ? `<div class="sapx-pw-urgency-banner"
                  style="border-color:${esc(socMeta.border)};background:${esc(socMeta.bg)};color:${esc(socMeta.color)};">
               ${esc(socMeta.badge)} ${esc(aiPw.urgency)}
             </div>`
          : ""}
      </div>

      <div class="sapx-pw-unlock-label">Unlock with PRO:</div>
      <ul class="sapx-pw-features-list">${featureListHtml}</ul>

      <a href="${esc(ctaUrl)}"
         class="sapx-pw-cta ${isUrgent ? "sapx-pw-cta-urgent" : ""}"
         target="_blank" rel="noopener"
         onclick="if(typeof window.SentinelApexAnalytics!=='undefined')window.SentinelApexAnalytics.track('paywall_cta',{severity:'${esc(item.severity)}',soc:'${esc(item.apex_ai.soc_priority)}'});">
        👉 Upgrade to PRO — $49/month
        <span class="sapx-pw-cta-arrow">→</span>
      </a>
      <div class="sapx-pw-note">Cancel anytime · Instant access · No setup fee</div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  ZONE 9: 🟢 TRUST + VALIDATION FOOTER
   *  Source credibility, STIX/MITRE verification, report CTA.
   * ═══════════════════════════════════════════════════════════════════════════ */
  function renderTrustFooter(item) {
    const vs     = item.validation_status;
    const hasTtps = item.has_ttps;

    return `
    <div class="sapx-zone sapx-zone-footer">
      <div class="sapx-footer-top">
        <a href="${esc(item.source_url)}" target="_blank" rel="noopener" class="sapx-source-link">
          <span class="sapx-source-dot">●</span>
          <span class="sapx-source-name">${esc(item.source_host)}</span>
        </a>
        <div class="sapx-trust-badges">
          <span class="sapx-trust-badge sapx-trust-stix" title="STIX 2.1 Verified Bundle">
            ✓ STIX 2.1
          </span>
          ${hasTtps
            ? `<span class="sapx-trust-badge sapx-trust-mitre" title="MITRE ATT&CK Mapped">
                 ✓ MITRE MAPPED
               </span>`
            : ""}
          <span class="sapx-trust-badge sapx-trust-val sapx-val-${esc(vs.class)}"
                style="color:${esc(vs.color)};" title="Validation Status">
            ${esc(vs.label)}
          </span>
        </div>
      </div>
      <div class="sapx-footer-bottom">
        <span class="sapx-stix-id" data-full-id="${esc(item.stix_id)}" data-short-id="${esc(item.stix_id_short)}"
              title="${esc(item.stix_id)} — click to copy" onclick="SentinelApexCardRenderer.copyStixId(this)">
          ${esc(item.stix_id_short)}
        </span>
        <div class="sapx-footer-ctas">
          ${item.stix_bundle_locked
            ? `<a href="${esc(item.stix_bundle_upgrade_url)}" target="_blank" rel="noopener"
                  class="sapx-stix-bundle-locked"
                  title="STIX Bundle is a PRO-only feature — upgrade to access structured threat data">
                 🔒 STIX Bundle <span class="sapx-stix-pro-badge">PRO</span> →
               </a>`
            : item.stix_bundle_url
              ? `<a href="${esc(item.stix_bundle_url)}" target="_blank" rel="noopener" class="sapx-stix-bundle-link">
                   📦 STIX Bundle
                 </a>`
              : ""}
          ${item.report_url
            ? `<a href="${esc(item.report_url)}" target="_blank" rel="noopener" class="sapx-report-cta">
                 📄 VIEW REPORT ↗
               </a>`
            : ""}
        </div>
      </div>
    </div>`;
  }

  /* ════════════════════════════════════════════════════════════════════════════
   *  CARD ASSEMBLER — composes all 9 zones into one article element
   * ═══════════════════════════════════════════════════════════════════════════ */
  function buildCard(item) {
    if (!item || typeof item !== "object") return "";

    const cardId = (item.stix_id || item.id || "").replace(/[^a-z0-9]/gi, "").slice(-12)
                   || "cx" + Math.random().toString(36).slice(2, 10);
    const sc = item.severity_colors;

    const zones = [
      renderDecisionHeader(item),
      renderSocDecisionStrip(item),
      renderAiVerdictPanel(item, cardId),
      renderImpactContext(item),
      renderIntelCore(item),
      renderExploitScoring(item),
      renderTimeline(item, cardId),
      renderPaywall(item),
      renderTrustFooter(item),
    ].filter(Boolean).join("");

    return `
    <article class="sapx-card ${esc(sc.class)} ${item.is_high_priority ? "sapx-card-priority" : ""}"
             data-id="${esc(item.id)}"
             data-severity="${esc(item.severity)}"
             data-soc-priority="${esc(item.apex_ai.soc_priority)}"
             data-risk="${esc(String(item.risk_score.raw))}"
             data-threat-type="${esc(item.threat_type)}"
             data-action="${esc(item.action_rec.action)}"
             style="--sapx-sev-color:${esc(sc.primary)};--sapx-sev-glow:${esc(sc.glow)};--sapx-sev-dim:${esc(sc.dim)};--sapx-sev-border:${esc(sc.border)};--sapx-sev-text:${esc(sc.text)};">
      ${zones}
    </article>`;
  }

  /* ── SKELETON LOADING CARD ───────────────────────────────────────────────── */
  function buildLoadingCard() {
    return `
    <article class="sapx-card sapx-card-skeleton">
      <div class="sapx-zone sapx-zone-header">
        <div class="sapx-hdr-top-row">
          <div class="sapx-sk sapx-sk-badge"></div>
          <div class="sapx-sk sapx-sk-soc-mini"></div>
        </div>
        <div class="sapx-sk sapx-sk-title"></div>
        <div class="sapx-sk sapx-sk-title sapx-sk-title-sm"></div>
        <div class="sapx-hdr-metrics-row">
          <div class="sapx-sk sapx-sk-metric"></div>
          <div class="sapx-sk sapx-sk-metric"></div>
          <div class="sapx-sk sapx-sk-metric"></div>
        </div>
      </div>
      <div class="sapx-zone sapx-zone-soc-strip">
        <div class="sapx-sk sapx-sk-strip"></div>
      </div>
      <div class="sapx-zone sapx-zone-ai-verdict">
        <div class="sapx-sk sapx-sk-verdict"></div>
      </div>
      <div class="sapx-zone sapx-zone-intel-core">
        <div class="sapx-intel-grid">
          <div class="sapx-sk sapx-sk-cell"></div>
          <div class="sapx-sk sapx-sk-cell"></div>
          <div class="sapx-sk sapx-sk-cell"></div>
          <div class="sapx-sk sapx-sk-cell"></div>
        </div>
      </div>
    </article>`;
  }

  /* ── ERROR CARD ──────────────────────────────────────────────────────────── */
  function buildErrorCard(message) {
    return `
    <article class="sapx-card sev-low sapx-card-error">
      <div class="sapx-zone sapx-zone-header">
        <div class="sapx-hdr-top-row">
          <div class="sapx-sev-badge sapx-sev-low">⚠ ERROR</div>
        </div>
        <h3 class="sapx-title">${esc(message || "Failed to render intelligence card")}</h3>
      </div>
      <div class="sapx-zone sapx-zone-footer">
        <div class="sapx-footer-top">
          <span style="color:#64748b;font-size:11px;font-family:var(--font-mono,monospace);">Check API connectivity and reload the dashboard.</span>
        </div>
      </div>
    </article>`;
  }

  /* ── EMPTY STATE ─────────────────────────────────────────────────────────── */
  function buildEmptyState(message) {
    return `
    <div class="sapx-empty-state">
      <div class="sapx-empty-icon">🛡</div>
      <div class="sapx-empty-title">No Threat Intelligence Available</div>
      <div class="sapx-empty-msg">${esc(message || "Feed is empty or filters returned no results.")}</div>
    </div>`;
  }

  /* ── RENDER GRID ─────────────────────────────────────────────────────────── */
  function renderGrid(container, normalizedItems, options) {
    if (!container) { console.error("[SAPX Renderer] No container element."); return; }
    const opts     = options || {};
    const maxCards = opts.maxCards || 50;
    if (!normalizedItems || normalizedItems.length === 0) {
      container.innerHTML = buildEmptyState();
      return;
    }
    const html = normalizedItems.slice(0, maxCards).map(function (item) {
      try   { return buildCard(item); }
      catch (e) { console.warn("[SAPX Renderer] Card build error:", e); return buildErrorCard(e.message || "Render failed"); }
    }).join("");
    container.innerHTML = html;
    _attachCardEvents(container);
  }

  /* ── LOADING STATE ───────────────────────────────────────────────────────── */
  function showLoadingState(container, count) {
    if (!container) return;
    const skeletons = Array(Math.max(1, count || 3)).fill(buildLoadingCard()).join("");
    container.innerHTML = `<div class="sapx-loading-wrap">${skeletons}</div>`;
  }

  /* ── PANEL TOGGLE ────────────────────────────────────────────────────────── */
  function togglePanel(panelId, headerEl) {
    const panel = document.getElementById(panelId);
    if (!panel) return;
    const isCollapsed = panel.classList.contains("sapx-panel-collapsed");
    panel.classList.toggle("sapx-panel-collapsed", !isCollapsed);
    panel.classList.toggle("sapx-panel-expanded",  isCollapsed);
    if (headerEl) {
      const chev = headerEl.querySelector(".sapx-expand-chevron");
      if (chev) chev.style.transform = isCollapsed ? "rotate(180deg)" : "";
      headerEl.setAttribute("aria-expanded", String(isCollapsed));
    }
  }

  /* ── COPY STIX ID ────────────────────────────────────────────────────────── */
  function copyStixId(el) {
    const fullId    = el.getAttribute("data-full-id") || el.textContent.trim();
    const shortId   = el.getAttribute("data-short-id") || fullId;
    const origText  = el.textContent;
    try {
      navigator.clipboard.writeText(fullId).then(function () {
        el.textContent = "✓ Copied!";
        el.style.color = "#22c55e";
        setTimeout(function () { el.textContent = shortId; el.style.color = ""; }, 1800);
      });
    } catch (e) {
      el.textContent = fullId;
      setTimeout(function () { el.textContent = shortId; }, 3000);
    }
  }

  /* ── CARD EVENT WIRING ───────────────────────────────────────────────────── */
  function _attachCardEvents(container) {
    // TTP tag analytics
    container.querySelectorAll(".sapx-ttp-tag").forEach(function (el) {
      el.addEventListener("click", function () {
        if (typeof window.SentinelApexAnalytics !== "undefined")
          window.SentinelApexAnalytics.track("ttp_click", { id: el.textContent.trim() });
      });
    });
    // Paywall CTA analytics
    container.querySelectorAll(".sapx-pw-cta").forEach(function (el) {
      el.addEventListener("click", function () {
        if (typeof window.SentinelApexAnalytics !== "undefined")
          window.SentinelApexAnalytics.track("paywall_cta_click", { url: el.href });
      });
    });
  }

  /* ── CLIENT-SIDE FILTER ──────────────────────────────────────────────────── */
  function filterCards(container, filters) {
    if (!container) return 0;
    const f = filters || {};
    let visible = 0;
    container.querySelectorAll(".sapx-card").forEach(function (card) {
      let show = true;
      if (f.severity  && card.dataset.severity   !== f.severity.toUpperCase())  show = false;
      if (f.socPriority && card.dataset.socPriority !== f.socPriority.toUpperCase()) show = false;
      if (f.action    && card.dataset.action     !== f.action.toUpperCase())    show = false;
      if (f.search) {
        if (!card.textContent.toLowerCase().includes(f.search.toLowerCase())) show = false;
      }
      card.style.display = show ? "" : "none";
      if (show) visible++;
    });
    return visible;
  }

  /* ── CLIENT-SIDE SORT ────────────────────────────────────────────────────── */
  function sortCards(container, sortBy) {
    if (!container) return;
    const pOrder = { P1: 0, P2: 1, P3: 2, P4: 3 };
    const cards  = Array.from(container.querySelectorAll(".sapx-card"));
    cards.sort(function (a, b) {
      switch (sortBy) {
        case "risk_desc":  return parseFloat(b.dataset.risk || 0) - parseFloat(a.dataset.risk || 0);
        case "risk_asc":   return parseFloat(a.dataset.risk || 0) - parseFloat(b.dataset.risk || 0);
        case "priority":   return (pOrder[a.dataset.socPriority] || 3) - (pOrder[b.dataset.socPriority] || 3);
        case "severity":
          const sevOrd = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
          return (sevOrd[a.dataset.severity] || 4) - (sevOrd[b.dataset.severity] || 4);
        default: return 0;
      }
    });
    cards.forEach(function (c) { container.appendChild(c); });
  }

  /* ── CONVENIENCE METHODS ─────────────────────────────────────────────────── */
  function renderFromApiResponse(container, apiResponse, options) {
    if (!Adapter) { console.error("[SAPX Renderer] SentinelApexAdapter not loaded."); return; }
    showLoadingState(container, (options && options.loadingCount) || 4);
    try {
      const normalized = Adapter.normalizeApiResponse(apiResponse);
      renderGrid(container, normalized.items, options);
      return normalized;
    } catch (e) {
      console.error("[SAPX Renderer] Response render failed:", e);
      container.innerHTML = buildEmptyState("API data processing error.");
    }
  }

  async function fetchAndRender(container, url, options) {
    if (!Adapter) { console.error("[SAPX Renderer] SentinelApexAdapter not loaded."); return null; }
    showLoadingState(container, (options && options.loadingCount) || 4);
    const result = await Adapter.fetchAndNormalize(url, options);
    if (result.error || !result.normalized || result.normalized.items.length === 0) {
      container.innerHTML = buildEmptyState(
        result.cached ? "⚠ Displaying cached intelligence — live feed temporarily unavailable."
                      : "⚠ Could not load threat intelligence feed. API may be offline."
      );
      return null;
    }
    renderGrid(container, result.normalized.items, options);
    return result.normalized;
  }

  /* ── PUBLIC API ─────────────────────────────────────────────────────────── */
  return {
    VERSION: "147.0.0",

    /* Card builders */
    buildCard:           buildCard,
    buildLoadingCard:    buildLoadingCard,
    buildErrorCard:      buildErrorCard,
    buildEmptyState:     buildEmptyState,

    /* Grid rendering */
    renderGrid:          renderGrid,
    showLoadingState:    showLoadingState,
    renderFromApiResponse: renderFromApiResponse,

    /* Card interaction */
    togglePanel:         togglePanel,
    copyStixId:          copyStixId,

    /* Filter / Sort */
    filterCards:         filterCards,
    sortCards:           sortCards,
  };

});
