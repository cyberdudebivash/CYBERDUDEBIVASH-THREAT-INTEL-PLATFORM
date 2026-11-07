/*
 * js/feed-topic-view.js -- CYBERDUDEBIVASH(R) SENTINEL APEX
 *
 * Renders the advisories of one topic (malware, AI security, ...) from the
 * live feed (/api/feed.json) into a topic page. Topic pages used to show
 * fixed or randomly generated "live" numbers; this is the one shared, data-driven
 * replacement, so every figure a topic page shows is read from the feed when
 * the page loads.
 *
 * Usage (element ids are optional; missing ones are skipped):
 *   FeedTopicView.render({
 *     pattern: /\b(llm|prompt injection)\b/i,   // matched on title + summary
 *     ids: { total, matched, hot, updated, badge, rows },
 *     emptyHtml: 'No ... in the current feed window.'
 *   });
 */
(function (global) {
  'use strict';

  var SEV_COLOR = { CRITICAL: '#ff3355', HIGH: '#f97316', MEDIUM: '#ffd700', LOW: '#00ff88' };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function safeUrl(u) { return /^https?:\/\//i.test(u || '') ? u : null; }
  function el(id) { return id ? document.getElementById(id) : null; }
  function set(id, v) { var e = el(id); if (e) e.textContent = v; }

  function matches(pattern, item) {
    return pattern.test((item.title || '') + ' ' + String(item.description || '').slice(0, 600));
  }

  function row(i) {
    var sev = String(i.severity || '').toUpperCase();
    var url = safeUrl(i.source_url);
    var when = String(i.published_at || i.timestamp || '').slice(0, 10);
    return '<tr>' +
      '<td>' + esc(i.title) + '</td>' +
      '<td><span style="color:' + (SEV_COLOR[sev] || '#8899aa') + '">' + esc(sev || '—') + '</span></td>' +
      '<td>' + esc(when || '—') + '</td>' +
      '<td>' + (url
        ? '<a href="' + esc(url) + '" target="_blank" rel="noopener noreferrer" style="color:var(--accent-cyan);">' + esc(i.source || 'source') + '</a>'
        : esc(i.source || '—')) + '</td>' +
      '</tr>';
  }

  function message(ids, html, badge) {
    set(ids.badge, badge);
    var tbody = el(ids.rows);
    if (tbody) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:18px;color:var(--text-muted,#8899aa);">' + html + '</td></tr>';
  }

  function render(opts) {
    var ids = opts.ids || {};
    return fetch(opts.feedUrl || '/api/feed.json', { headers: { 'Accept': 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (d) {
        var items = Array.isArray(d.items) ? d.items : [];
        var hits = items.filter(function (i) { return matches(opts.pattern, i); });
        var hot = hits.filter(function (i) { return /^(CRITICAL|HIGH)$/i.test(i.severity || ''); });
        set(ids.total, items.length);
        set(ids.matched, hits.length);
        set(ids.hot, hot.length);
        set(ids.updated, d.generated_at ? String(d.generated_at).replace('T', ' ').slice(0, 16) : '—');
        if (!hits.length) { message(ids, opts.emptyHtml || 'Nothing on this topic in the current feed window.', '0 IN FEED'); return hits; }
        set(ids.badge, hits.length + ' IN FEED');
        var tbody = el(ids.rows);
        if (tbody) tbody.innerHTML = hits.map(row).join('');
        return hits;
      })
      .catch(function () {
        message(ids, 'The live feed could not be loaded. Please try again shortly.', 'UNAVAILABLE');
        return [];
      });
  }

  global.FeedTopicView = { render: render, matches: matches, esc: esc };
})(window);
