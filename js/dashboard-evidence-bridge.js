/*
 * SENTINEL APEX — P0 current-intelligence evidence bridge.
 * Read-only public /api/feed.json; supplements (never replaces) scan, incident,
 * APT-attribution or geolocated-flow evidence. No synthetic events or actions.
 * One request on page load, then at most once per 15 minutes while visible.
 */
(function (root) {
  'use strict';
  var MAX_AGE_MS = 6 * 60 * 60 * 1000;
  var REFRESH_MS = 15 * 60 * 1000;
  var MAX_ROWS = 4;

  function url(value) {
    if (typeof value !== 'string') return '';
    try {
      var u = new URL(value);
      return u.protocol === 'https:' && !u.username && !u.password ? u.href : '';
    } catch (_) { return ''; }
  }
  function name(value) {
    if (typeof value !== 'string') return '';
    var v = value.trim();
    return /^[A-Za-z][A-Za-z .'-]{2,39}$/.test(v) &&
      !/^(unknown|unattributed|none|unspecified|n\/a)$/i.test(v) &&
      !/criminal|speaking|operation|ransomware|hacker/i.test(v) ? v : '';
  }
  function sourceTime(item) {
    return item.published_at || item.published || item.timestamp || '';
  }
  function score(item) {
    return typeof item.risk_score === 'number' &&
      Number.isFinite(item.risk_score) && item.risk_score >= 0 &&
      item.risk_score <= 10 ? item.risk_score : null;
  }
  function isAptRelated(item) {
    var parts = [item.title, item.threat_type, item.actor_type, item.threat_actor_type];
    if (Array.isArray(item.tags)) parts = parts.concat(item.tags);
    return /\bAPT[- ]?\d*\b|nation[- ]state|state[- ]sponsored|\bLazarus\b|\bSandworm\b|\bFancy Bear\b|\bCozy Bear\b|\b(?:Volt|Salt) Typhoon\b/i.test(
      parts.filter(function (s) { return typeof s === 'string'; }).join(' '));
  }
  function isVulnerability(item) {
    return /\bCVE-\d{4}-\d{4,}\b|vulnerabilit|exploited|security flaw|remote code execution/i.test(String(item.title || '')) ||
      /^CVE-\d{4}-\d{4,}$/.test(String(item.cve_id || '')) ||
      (Array.isArray(item.cve_ids) && item.cve_ids.some(function (v) { return /^CVE-\d{4}-\d{4,}$/.test(String(v)); }));
  }
  function validatePublication(data, nowMs) {
    var current = typeof nowMs === 'number' ? nowMs : Date.now();
    var at = data && Date.parse(data.generated_at || '');
    return !!(data && data.schema_version === '1.0' &&
      Array.isArray(data.items) && data.items.length <= 1000 &&
      Number.isSafeInteger(data.count) && data.count === data.items.length &&
      Number.isFinite(at) && at <= current + 300000 &&
      current - at >= -300000 && current - at <= MAX_AGE_MS);
  }
  function summarize(data, nowMs) {
    if (!validatePublication(data, nowMs)) return null;
    var records = data.items.filter(function (item) {
      return item && typeof item === 'object' && item.tlp === 'TLP:CLEAR' &&
        typeof item.title === 'string' && item.title.trim().length > 0 &&
        !!url(item.source_url);
    });
    var byRisk = records.slice().sort(function (a, b) {
      return (score(b) === null ? -1 : score(b)) - (score(a) === null ? -1 : score(a));
    });
    var apt = records.filter(isAptRelated);
    var geoOrigin = records.filter(function (item) { return !!name(item.actor_country); });
    var geoPairs = geoOrigin.filter(function (item) {
      return !!name(item.target_country || item.victim_country);
    });
    var vulnerability = byRisk.filter(isVulnerability);
    var triage = byRisk.filter(function (item) {
      return (score(item) !== null && score(item) >= 7) ||
        /^(CRITICAL|HIGH)$/i.test(String(item.severity || ''));
    });
    return {
      generated_at: data.generated_at,
      total: data.items.length,
      source_linked: records.length,
      apt_count: apt.length,
      geo_origin_count: geoOrigin.length,
      geo_pair_count: geoPairs.length,
      vulnerability_count: vulnerability.length,
      triage_count: triage.length,
      apt_rows: apt.slice(0, MAX_ROWS),
      geo_rows: geoPairs.slice(0, MAX_ROWS),
      vulnerability_rows: vulnerability.slice(0, MAX_ROWS),
      triage_rows: triage.slice(0, MAX_ROWS),
      general_rows: byRisk.slice(0, MAX_ROWS)
    };
  }

  function textNode(tag, value) {
    var element = document.createElement(tag);
    element.textContent = String(value);
    return element;
  }
  function panel(anchorId, panelId, heading, explanation) {
    var anchor = document.getElementById(anchorId);
    if (!anchor || !anchor.parentNode) return null;
    var existing = document.getElementById(panelId);
    if (existing) return existing;
    var el = document.createElement('aside');
    el.id = panelId;
    el.setAttribute('aria-live', 'polite');
    el.style.cssText = 'margin:12px 0;padding:13px;border:1px solid #334155;border-radius:5px;background:#0b1424;color:#e2e8f0;font-size:12px;line-height:1.6;';
    var headingEl = textNode('strong', heading);
    headingEl.style.cssText = 'display:block;color:#67e8f9;letter-spacing:.08em;font-size:11px;margin-bottom:4px;';
    var expl = textNode('p', explanation);
    expl.style.cssText = 'margin:0 0 7px;color:#a8b7c9;font-size:11px;';
    var body = document.createElement('div');
    body.setAttribute('data-evidence-body', '');
    el.appendChild(headingEl);
    el.appendChild(expl);
    el.appendChild(body);
    anchor.parentNode.insertBefore(el, anchor.nextSibling);
    return el;
  }
  function appendRows(target, rows, emptyLabel) {
    if (!rows.length) {
      var empty = textNode('p', emptyLabel);
      empty.style.cssText = 'color:#cbd5e1;margin:6px 0;';
      target.appendChild(empty);
      return;
    }
    rows.forEach(function (item) {
      var href = url(item.source_url);
      if (!href) return;
      var row = document.createElement('div');
      row.style.cssText = 'padding:6px 0;border-top:1px solid #24364d;';
      var link = textNode('a', item.title.slice(0, 140));
      link.href = href;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.style.cssText = 'color:#7dd3fc;overflow-wrap:anywhere;';
      row.appendChild(link);
      var meta = textNode('div', [
        item.source || item.feed_source || 'Public source',
        String(item.severity || 'unrated').toUpperCase(),
        score(item) === null ? 'risk unmeasured' : 'risk ' + score(item).toFixed(1) + '/10',
        sourceTime(item) ? String(sourceTime(item)).slice(0, 10) : ''
      ].filter(Boolean).join(' · '));
      meta.style.cssText = 'font-size:10px;color:#a3b5c9;';
      row.appendChild(meta);
      target.appendChild(row);
    });
  }
  function paint(id, info, rows, empty, summary) {
    var el = document.getElementById(id);
    if (!el) return;
    var body = el.querySelector('[data-evidence-body]');
    if (!body) return;
    body.replaceChildren();
    var stamp = summary ? ' | Feed: ' + summary.generated_at : '';
    var detail = textNode('div', info + stamp);
    detail.style.cssText = 'font-size:10px;color:#fbbf24;margin-bottom:5px;overflow-wrap:anywhere;';
    body.appendChild(detail);
    appendRows(body, rows, empty);
  }
  function ensurePanels() {
    panel('cdb-apt-list', 'cdb-apt-cti-evidence', 'CURRENT SOURCE-LINKED CTI · APT COVERAGE',
      'APT-attributed activity is counted only from actual evidence. Other security reports below do not imply nation-state attribution.');
    panel('genesis-attack-flows', 'cdb-g11-cti-evidence', 'G11 · CURRENT GEOGRAPHIC EVIDENCE',
      'A mapped flow requires actor and victim/target countries on the same advisory; publisher countries and general CTI are not flows.');
    panel('bughunter-grid', 'cdb-recon-cti-evidence', 'LATEST VULNERABILITY REPORTING · NOT SCAN FINDINGS',
      'Fresh source-linked disclosures are separate from an authorized, completed reconnaissance scan. Existing re-scan warnings remain authoritative.');
    panel('tipsoar-badge', 'cdb-soc-cti-evidence', 'CURRENT SOC ANALYST TRIAGE · NOT CONFIRMED INCIDENTS',
      'High-risk source-linked advisories for analyst review; not verified customer incidents, executed SOAR responses or completed hunts.');
  }
  function render(data) {
    ensurePanels();
    if (!data) {
      [
        'cdb-apt-cti-evidence', 'cdb-g11-cti-evidence',
        'cdb-recon-cti-evidence', 'cdb-soc-cti-evidence'
      ].forEach(function (id) {
        paint(id, 'CURRENT CTI UNAVAILABLE OR STALE', [],
          'Do not infer current activity from saved scan or response files.', null);
      });
      return;
    }
    paint('cdb-apt-cti-evidence',
      data.apt_count + ' APT-related source reports / ' + data.source_linked + ' source-linked CTI reports',
      data.apt_rows.length ? data.apt_rows : data.general_rows,
      data.apt_rows.length ? 'No source links available.' : 'No APT-classified report in this feed window.',
      data);
    if (!data.apt_rows.length) {
      var el = document.getElementById('cdb-apt-cti-evidence');
      if (el) {
        var n = textNode('p', 'Below: general CTI context only — NOT APT attribution.');
        n.style.cssText = 'font-size:10px;color:#fbbf24;margin:5px 0;';
        el.querySelector('[data-evidence-body]').insertBefore(n, el.querySelector('[data-evidence-body]').children[1] || null);
      }
    }
    paint('cdb-g11-cti-evidence',
      data.geo_pair_count + ' paired-country records / ' + data.geo_origin_count +
      ' actor-country records / ' + data.total + ' feed advisories',
      data.geo_rows,
      'No verified origin–target country pairs in this feed. A zero attack-flow count is accurate.',
      data);
    paint('cdb-recon-cti-evidence',
      data.vulnerability_count + ' vulnerability/exploitation reports in current CTI',
      data.vulnerability_rows,
      'No source-linked vulnerability reporting in this publication window.',
      data);
    paint('cdb-soc-cti-evidence',
      data.triage_count + ' high-risk advisory triage candidates · 0 incident executions inferred',
      data.triage_rows,
      'No high-risk source-linked CTI advisory meets the triage threshold.',
      data);
  }
  async function refresh() {
    try {
      var response = await fetch('/api/feed.json', {
        method: 'GET', credentials: 'omit', cache: 'no-cache',
        headers: { 'Accept': 'application/json' }
      });
      if (!response.ok) throw new Error('intelligence endpoint unavailable');
      var data = await response.json();
      render(summarize(data));
    } catch (_) { render(null); }
  }
  function start() {
    if (!document.getElementById('tipsoar-section')) return;
    refresh();
    setInterval(function () {
      if (document.visibilityState === 'visible') refresh();
    }, REFRESH_MS);
  }
  var api = { validatePublication: validatePublication, summarize: summarize, safeSourceUrl: url };
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root && typeof document !== 'undefined') {
    root.CDBEvidenceBridge = api;
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();
  }
})(typeof window !== 'undefined' ? window : null);
