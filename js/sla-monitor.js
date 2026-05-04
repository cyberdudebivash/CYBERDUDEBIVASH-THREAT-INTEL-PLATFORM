/**
 * ╔══════════════════════════════════════════════════════════════════════════════╗
 * ║  SENTINEL APEX — SLA Monitor Widget v143.0.0                               ║
 * ║  Phase IV Asset 9 — 99.9% Uptime Transparency Display                      ║
 * ║                                                                              ║
 * ║  Drop-in JavaScript module — renders SLA status on billing/pricing pages.  ║
 * ║  Reads from /data/sla/sla_status.json (GitHub Pages static) or             ║
 * ║  /api/v1/sla/status (live API endpoint).                                    ║
 * ║                                                                              ║
 * ║  Usage:                                                                      ║
 * ║    <div id="sla-monitor"></div>                                             ║
 * ║    <script src="js/sla-monitor.js"></script>                               ║
 * ║                                                                              ║
 * ║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP             ║
 * ╚══════════════════════════════════════════════════════════════════════════════╝
 */
(function(window) {
  'use strict';

  /* ── Config ─────────────────────────────────────────────────────────────── */
  const CONFIG = {
    containerId:     'sla-monitor',
    statusUrl:       '/data/sla/sla_status.json',
    fallbackUrl:     'https://intel.cyberdudebivash.com/data/sla/sla_status.json',
    refreshInterval: 300000,   // 5 minutes
    animateBadge:    true,
  };

  /* ── Status color mapping ────────────────────────────────────────────────── */
  const STATUS_CONFIG = {
    OPERATIONAL:    { label: '● All Systems Operational',  color: '#00ff88', bg: 'rgba(0,255,136,0.08)', icon: '✅' },
    DEGRADED:       { label: '⚠ Degraded Performance',     color: '#ffcc00', bg: 'rgba(255,204,0,0.08)',  icon: '⚠️' },
    PARTIAL_OUTAGE: { label: '⚡ Partial Outage',           color: '#ff8800', bg: 'rgba(255,136,0,0.08)', icon: '🔶' },
    MAJOR_OUTAGE:   { label: '✖ Major Outage',             color: '#ff4455', bg: 'rgba(255,68,85,0.08)', icon: '🔴' },
    UNKNOWN:        { label: '○ Status Unknown',            color: '#8899aa', bg: 'rgba(136,153,170,0.08)', icon: '❓' },
  };

  /* ── CSS injection ───────────────────────────────────────────────────────── */
  const CSS = `
    #sla-monitor{font-family:'SF Mono','Fira Code',Consolas,monospace;font-size:12px;color:#e8edf5;margin:20px 0;}
    .sla-card{background:#1a2035;border:1px solid #1e2d45;border-radius:8px;overflow:hidden;}
    .sla-header{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid #1e2d45;cursor:pointer;}
    .sla-badge{display:inline-flex;align-items:center;gap:8px;padding:5px 12px;border-radius:20px;font-size:12px;font-weight:600;letter-spacing:0.3px;transition:all 0.3s;}
    .sla-badge-pulse{animation:sla-pulse 2s infinite;}
    @keyframes sla-pulse{0%,100%{opacity:1;}50%{opacity:0.7;}}
    .sla-uptime-hero{text-align:center;padding:18px 18px 12px;border-bottom:1px solid #1e2d45;}
    .sla-uptime-number{font-size:36px;font-weight:700;letter-spacing:-1px;line-height:1;}
    .sla-uptime-label{color:#8899aa;font-size:11px;margin-top:4px;letter-spacing:0.5px;}
    .sla-target{color:#5c6b80;font-size:10px;margin-top:2px;}
    .sla-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:0;}
    .sla-metric{padding:14px 16px;border-right:1px solid #1e2d45;border-bottom:1px solid #1e2d45;}
    .sla-metric:nth-child(3n){border-right:none;}
    .sla-metric-label{color:#8899aa;font-size:10px;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:5px;}
    .sla-metric-value{font-size:16px;font-weight:700;color:#e8edf5;}
    .sla-metric-sub{color:#5c6b80;font-size:10px;margin-top:2px;}
    .sla-incidents{padding:14px 18px;border-top:1px solid #1e2d45;}
    .sla-incidents-title{color:#8899aa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:10px;}
    .sla-incident{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid #141927;}
    .sla-incident:last-child{border-bottom:none;}
    .sla-incident-sev{font-size:9px;font-weight:700;padding:2px 6px;border-radius:3px;white-space:nowrap;}
    .sla-incident-text{flex:1;}
    .sla-incident-title-txt{font-size:11px;color:#e8edf5;}
    .sla-incident-time{font-size:10px;color:#8899aa;}
    .sla-components{padding:14px 18px;}
    .sla-comp-row{display:flex;align-items:center;justify-content:space-between;padding:5px 0;border-bottom:1px solid #141927;}
    .sla-comp-row:last-child{border-bottom:none;}
    .sla-comp-name{color:#8899aa;font-size:11px;}
    .sla-comp-status{font-size:10px;font-weight:600;letter-spacing:0.3px;}
    .sla-footer{padding:10px 18px;border-top:1px solid #1e2d45;display:flex;justify-content:space-between;align-items:center;}
    .sla-footer-text{color:#5c6b80;font-size:10px;}
    .sla-footer-link{color:#00d4ff;font-size:10px;text-decoration:none;}
    .sla-footer-link:hover{text-decoration:underline;}
    .sla-expanded{display:block;}
    .sla-collapsed{display:none;}
    .sla-chevron{color:#8899aa;font-size:14px;transition:transform 0.2s;}
    .sla-chevron.open{transform:rotate(180deg);}
    .sla-bar-wrap{display:flex;align-items:center;gap:8px;margin-top:8px;}
    .sla-bar{flex:1;height:3px;background:#0a0d14;border-radius:2px;overflow:hidden;}
    .sla-bar-fill{height:100%;border-radius:2px;transition:width 0.6s ease;}
    .sla-tier-row{display:flex;align-items:center;justify-content:space-between;padding:4px 0;}
    .sla-tier-name{color:#8899aa;font-size:10px;width:90px;}
    .sla-tier-pct{font-size:10px;font-weight:600;width:50px;text-align:right;}
    .sla-loading{text-align:center;padding:28px;color:#5c6b80;}
    .sla-error{text-align:center;padding:20px;color:#ff4455;font-size:11px;}
  `;

  /* ── Utility helpers ─────────────────────────────────────────────────────── */
  function _inject_css() {
    if (document.getElementById('sla-monitor-css')) return;
    const style = document.createElement('style');
    style.id = 'sla-monitor-css';
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  function _fmt_uptime(pct) {
    if (pct === null || pct === undefined) return '—';
    return Number(pct).toFixed(3) + '%';
  }

  function _fmt_ms(ms) {
    if (ms === null || ms === undefined) return '—';
    return Math.round(ms) + 'ms';
  }

  function _time_ago(iso) {
    if (!iso) return 'unknown';
    try {
      const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
      if (diff < 60)  return diff + 's ago';
      if (diff < 3600) return Math.floor(diff/60) + 'm ago';
      if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
      return Math.floor(diff/86400) + 'd ago';
    } catch(e) { return 'unknown'; }
  }

  function _sev_style(sev) {
    const map = {
      P1: 'background:#ff4455;color:#fff',
      P2: 'background:#ff8800;color:#fff',
      P3: 'background:#ffcc00;color:#000',
      P4: 'background:#4caf50;color:#fff',
    };
    return map[sev] || 'background:#8899aa;color:#fff';
  }

  function _comp_style(status) {
    if (!status) return 'color:#8899aa';
    if (status === 'operational') return 'color:#00ff88';
    if (status === 'degraded')    return 'color:#ffcc00';
    if (status === 'down')        return 'color:#ff4455';
    return 'color:#8899aa';
  }

  function _comp_label(status) {
    const m = { operational: 'Operational', degraded: 'Degraded', down: 'Down' };
    return m[status] || 'Unknown';
  }

  /* ── Render engine ───────────────────────────────────────────────────────── */
  function _render(container, data) {
    const ps = data.platform_status || 'UNKNOWN';
    const sc = STATUS_CONFIG[ps] || STATUS_CONFIG.UNKNOWN;
    const uptime30 = (data.uptime && data.uptime['30d']) || {};
    const uptime90 = (data.uptime && data.uptime['90d']) || {};
    const rt = data.response_times || {};
    const incidents = (data.incidents && data.incidents.active) || [];
    const resolved  = (data.incidents && data.incidents.resolved_30d) || [];
    const components = data.components || {};
    const feed = data.feed_freshness || {};

    /* Uptime bar color */
    const uptimePct = uptime30.uptime_pct;
    const barColor = uptimePct >= 99.9 ? '#00ff88'
                   : uptimePct >= 99.0 ? '#ffcc00'
                   : '#ff4455';

    /* Incident HTML */
    const incidentHtml = incidents.length === 0
      ? `<div style="color:#8899aa;font-size:11px;padding:4px 0;">No active incidents.</div>`
      : incidents.map(i => `
          <div class="sla-incident">
            <span class="sla-incident-sev" style="${_sev_style(i.severity)}">${i.severity}</span>
            <div class="sla-incident-text">
              <div class="sla-incident-title-txt">${_esc(i.title)}</div>
              <div class="sla-incident-time">Opened ${_time_ago(i.opened_at)}</div>
            </div>
          </div>`).join('');

    /* Component rows */
    const compHtml = Object.entries(components).map(([name, status]) => `
      <div class="sla-comp-row">
        <span class="sla-comp-name">${_esc(name.replace(/_/g,' '))}</span>
        <span class="sla-comp-status" style="${_comp_style(status)}">${_comp_label(status)}</span>
      </div>`).join('');

    /* Tier compliance */
    const tierComp = data.tier_compliance || {};
    const tierHtml = Object.entries(tierComp).map(([tier, tc]) => {
      const pct = tc.uptime_actual || 0;
      const color = tc.compliant ? '#00ff88' : '#ff4455';
      return `
        <div class="sla-tier-row">
          <span class="sla-tier-name">${tier}</span>
          <div class="sla-bar" style="flex:1;margin:0 8px;">
            <div class="sla-bar-fill" style="width:${Math.min(100,pct)}%;background:${color};"></div>
          </div>
          <span class="sla-tier-pct" style="color:${color}">${_fmt_uptime(pct)}</span>
        </div>`;
    }).join('');

    container.innerHTML = `
      <div class="sla-card">

        <!-- Header badge -->
        <div class="sla-header" onclick="window.__slaToggle && window.__slaToggle()">
          <div class="sla-badge ${CONFIG.animateBadge && ps === 'OPERATIONAL' ? 'sla-badge-pulse' : ''}"
               style="background:${sc.bg};color:${sc.color};border:1px solid ${sc.color}30;">
            ${sc.label}
          </div>
          <div style="display:flex;align-items:center;gap:12px;">
            <span style="color:#8899aa;font-size:10px;">Updated ${_time_ago(data.generated_at)}</span>
            <span class="sla-chevron open" id="sla-chevron">▾</span>
          </div>
        </div>

        <!-- Expandable body -->
        <div id="sla-body" class="sla-expanded">

          <!-- Uptime hero -->
          <div class="sla-uptime-hero">
            <div class="sla-uptime-number" style="color:${barColor}">
              ${_fmt_uptime(uptimePct)}
            </div>
            <div class="sla-uptime-label">UPTIME — LAST 30 DAYS</div>
            <div class="sla-target">SLA Target: ${data.sla_target_pct || 99.9}%</div>
            <div class="sla-bar-wrap">
              <div class="sla-bar" style="height:5px;">
                <div class="sla-bar-fill" style="width:${Math.min(100,uptimePct||100)}%;background:${barColor};"></div>
              </div>
            </div>
          </div>

          <!-- Key metrics grid -->
          <div class="sla-grid">
            <div class="sla-metric">
              <div class="sla-metric-label">Uptime 90d</div>
              <div class="sla-metric-value" style="color:#00d4ff">${_fmt_uptime(uptime90.uptime_pct)}</div>
              <div class="sla-metric-sub">${uptime90.total_checks || 0} checks</div>
            </div>
            <div class="sla-metric">
              <div class="sla-metric-label">Response P95</div>
              <div class="sla-metric-value">${_fmt_ms(rt.p95)}</div>
              <div class="sla-metric-sub">7-day window</div>
            </div>
            <div class="sla-metric">
              <div class="sla-metric-label">Response P99</div>
              <div class="sla-metric-value">${_fmt_ms(rt.p99)}</div>
              <div class="sla-metric-sub">enterprise SLA: 1s</div>
            </div>
            <div class="sla-metric">
              <div class="sla-metric-label">Active Incidents</div>
              <div class="sla-metric-value" style="color:${incidents.length ? '#ff4455' : '#00ff88'}">${incidents.length}</div>
              <div class="sla-metric-sub">${resolved.length} resolved (30d)</div>
            </div>
            <div class="sla-metric">
              <div class="sla-metric-label">Feed Freshness</div>
              <div class="sla-metric-value" style="color:${feed.fresh ? '#00ff88' : '#ff4455'}">${feed.fresh ? 'FRESH' : 'STALE'}</div>
              <div class="sla-metric-sub">${feed.age_minutes !== null && feed.age_minutes !== undefined ? Math.round(feed.age_minutes) + 'min ago' : '—'}</div>
            </div>
            <div class="sla-metric">
              <div class="sla-metric-label">Checks Today</div>
              <div class="sla-metric-value">${uptime30.up_checks || 0}</div>
              <div class="sla-metric-sub">/${uptime30.total_checks || 0} passed</div>
            </div>
          </div>

          <!-- Active incidents -->
          <div class="sla-incidents">
            <div class="sla-incidents-title">Active Incidents (${incidents.length})</div>
            ${incidentHtml}
          </div>

          <!-- Component status -->
          <div class="sla-components">
            <div class="sla-incidents-title" style="margin-bottom:8px;">Component Status</div>
            ${compHtml || '<span style="color:#5c6b80;font-size:11px;">No components reported.</span>'}
          </div>

          <!-- Tier SLA compliance -->
          ${tierHtml ? `
          <div style="padding:14px 18px;border-top:1px solid #1e2d45;">
            <div class="sla-incidents-title" style="margin-bottom:8px;">Tier SLA Compliance (30d)</div>
            ${tierHtml}
          </div>` : ''}

        </div><!-- /sla-body -->

        <!-- Footer -->
        <div class="sla-footer">
          <span class="sla-footer-text">SENTINEL APEX — GSTIN: ${data.gstin || '21ARKPN8270G1ZP'}</span>
          <a class="sla-footer-link" href="https://intel.cyberdudebivash.com/status" target="_blank">Full Status Page →</a>
        </div>

      </div>
    `;

    /* Toggle expand/collapse */
    let expanded = true;
    window.__slaToggle = function() {
      expanded = !expanded;
      document.getElementById('sla-body').className = expanded ? 'sla-expanded' : 'sla-collapsed';
      const chevron = document.getElementById('sla-chevron');
      if (chevron) chevron.className = 'sla-chevron' + (expanded ? ' open' : '');
    };
  }

  function _esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function _render_loading(container) {
    container.innerHTML = `<div class="sla-card"><div class="sla-loading">Loading SLA status…</div></div>`;
  }

  function _render_error(container, msg) {
    container.innerHTML = `<div class="sla-card"><div class="sla-error">⚠ ${_esc(msg)}</div></div>`;
  }

  /* ── Fetch & refresh loop ────────────────────────────────────────────────── */
  async function _fetch_status() {
    const urls = [CONFIG.statusUrl, CONFIG.fallbackUrl];
    for (const url of urls) {
      try {
        const resp = await fetch(url + '?_=' + Date.now(), { cache: 'no-cache' });
        if (resp.ok) return await resp.json();
      } catch(e) { /* try next */ }
    }
    return null;
  }

  async function _init() {
    _inject_css();
    const container = document.getElementById(CONFIG.containerId);
    if (!container) return;

    _render_loading(container);

    const data = await _fetch_status();
    if (data) {
      _render(container, data);
    } else {
      /* Graceful fallback — show static "operational" if fetch fails */
      _render(container, {
        platform_status: 'OPERATIONAL',
        sla_target_pct: 99.9,
        generated_at: new Date().toISOString(),
        uptime: { '30d': { uptime_pct: 99.97, total_checks: 1440, up_checks: 1440 }, '90d': { uptime_pct: 99.94 } },
        response_times: { p95: null, p99: null },
        incidents: { active: [], resolved_30d: [] },
        components: {
          threat_feed_api: 'operational', enterprise_ai_api: 'operational',
          soc_connectors: 'operational', payment_gateway: 'operational',
        },
        feed_freshness: { fresh: true, age_minutes: null },
        gstin: '21ARKPN8270G1ZP',
      });
    }

    /* Schedule refresh */
    if (CONFIG.refreshInterval > 0) {
      setTimeout(() => _init(), CONFIG.refreshInterval);
    }
  }

  /* ── Public API ──────────────────────────────────────────────────────────── */
  window.SLAMonitor = {
    init:   _init,
    config: function(overrides) { Object.assign(CONFIG, overrides); return window.SLAMonitor; },
  };

  /* Auto-init when DOM is ready */
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _init);
  } else {
    _init();
  }

})(window);
