/*
 * CYBERDUDEBIVASH SENTINEL APEX -- SOC Operations Center data model.
 *
 * Pure functions only: the live feed (/api/v1/intel/latest.json) and the
 * freshness authority (/api/watchdog/health) in, display figures out. Every
 * figure is counted from feed items; nothing is estimated, sampled or
 * randomised, and a field the feed does not carry is reported as unknown,
 * never as zero. Shared by soc-operations-center.html and unit-tested in Node
 * (workers/intel-gateway/src/__tests__/soc-ops-model.test.js).
 *
 * Replaces the page's previous in-browser simulation (2026-09-28): a random
 * event stream, random 24h heatmap and source counts, and hardcoded IOC,
 * sensor, replay and coverage figures.
 */
(function (root) {
  'use strict';

  // Same ceiling as Cyber Watchdog's last-authoritative block: a STALE feed
  // may be shown, labelled NOT LIVE, for at most 48h.
  var LAST_AUTHORITATIVE_MAX_AGE_SECONDS = 48 * 3600;
  var SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  var TECHNIQUE_RE = /^T\d{4}(\.\d{3})?$/i;
  var EXPLOIT_RE = /^(POC|FUNCTIONAL|WEAPONIZED|ACTIVE|HIGH)/i;

  /**
   * What may be shown, from /api/watchdog/health.
   * live: FRESH. stale: STALE within 48h (shown, labelled NOT LIVE).
   * down: anything else -- no intelligence is shown.
   */
  function publication(health, fetchFailed) {
    if (fetchFailed || !health || typeof health.freshness_status !== 'string') {
      return { mode: 'down', label: fetchFailed ? 'INTELLIGENCE UNAVAILABLE' : 'INTELLIGENCE STATUS UNKNOWN' };
    }
    var age = Number(health.feed_age_seconds);
    if (health.freshness_status === 'FRESH') return { mode: 'live', label: 'LIVE', feed_generated_at: health.feed_generated_at, age_seconds: age };
    if (health.freshness_status === 'STALE' && isFinite(age) && age >= 0 && age <= LAST_AUTHORITATIVE_MAX_AGE_SECONDS) {
      return { mode: 'stale', label: 'LAST AUTHORITATIVE INTELLIGENCE - NOT LIVE', feed_generated_at: health.feed_generated_at, age_seconds: age };
    }
    return { mode: 'down', label: 'INTELLIGENCE DEGRADED - LAST AUTHORITATIVE UPDATE ' + (health.feed_generated_at || 'unknown') };
  }

  function items(feed) {
    var list = feed && (Array.isArray(feed.items) ? feed.items : Array.isArray(feed.advisories) ? feed.advisories : Array.isArray(feed) ? feed : null);
    return (list || []).filter(function (i) { return i && typeof i === 'object' && typeof i.title === 'string' && i.title.trim(); });
  }

  function severity(item) {
    var s = String(item.severity || '').trim().toUpperCase();
    return SEVERITIES.indexOf(s) >= 0 ? s : 'UNKNOWN';
  }

  /** Publication time in ms, or null when the item carries no parseable date. */
  function publishedMs(item) {
    var keys = ['published_at', 'published', 'timestamp', 'processed_at'];
    for (var k = 0; k < keys.length; k++) {
      var v = item[keys[k]];
      if (typeof v === 'string' && v) { var t = Date.parse(v); if (isFinite(t)) return t; }
    }
    return null;
  }

  function cves(item) {
    var out = [];
    var add = function (c) { if (typeof c === 'string' && /^CVE-\d{4}-\d{4,}$/i.test(c.trim())) { c = c.trim().toUpperCase(); if (out.indexOf(c) < 0) out.push(c); } };
    add(item.cve_id);
    if (Array.isArray(item.cve_ids)) item.cve_ids.slice(0, 50).forEach(add);
    return out;
  }

  /** CISA KEV: true / false as the feed states it; null when the feed does not say. */
  function kev(item) {
    var v = item.kev_present;
    if (v === true || v === false) return v;
    if (typeof v === 'string') { var w = v.trim().toUpperCase(); if (w === 'YES' || w === 'TRUE') return true; if (w === 'NO' || w === 'FALSE') return false; }
    return null;
  }

  function exploitEvidence(item) {
    if (item.metasploit_available === true || item.exploit_available === true) return true;
    if (EXPLOIT_RE.test(String(item.exploit_maturity || ''))) return true;
    return Number(item.poc_github_count) > 0 || Number(item.exploit_count) > 0;
  }

  /** Only an https source link is ever rendered. */
  function httpsUrl(v) {
    if (typeof v !== 'string' || v.length > 2048) return null;
    try { var u = new URL(v); return u.protocol === 'https:' ? u.toString() : null; } catch (e) { return null; }
  }

  function kpis(list) {
    var bySev = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, UNKNOWN: 0 };
    var kevYes = 0, kevKnown = 0, exploit = 0, withCve = 0;
    list.forEach(function (i) {
      bySev[severity(i)] += 1;
      var k = kev(i); if (k !== null) { kevKnown += 1; if (k) kevYes += 1; }
      if (exploitEvidence(i)) exploit += 1;
      if (cves(i).length) withCve += 1;
    });
    return {
      advisories: list.length, by_severity: bySev,
      kev_listed: kevYes, kev_stated_on: kevKnown,
      exploit_evidence: exploit, with_cve: withCve,
    };
  }

  /** Advisories published in each of the last 24 hours (oldest first). Undated items are counted separately. */
  function hourly(list, nowMs) {
    var hourMs = 3600000;
    var end = Math.floor(nowMs / hourMs) * hourMs + hourMs; // end of the current hour
    var buckets = [];
    for (var h = 23; h >= 0; h--) buckets.push({ start: end - (h + 1) * hourMs, count: 0, critical: 0 });
    var undated = 0, older = 0;
    list.forEach(function (i) {
      var t = publishedMs(i);
      if (t === null) { undated += 1; return; }
      var idx = Math.floor((t - buckets[0].start) / hourMs);
      if (idx < 0) { older += 1; return; }
      if (idx > 23) idx = 23; // a timestamp a few minutes in the future lands in the current hour
      buckets[idx].count += 1;
      if (severity(i) === 'CRITICAL') buckets[idx].critical += 1;
    });
    var total = buckets.reduce(function (n, b) { return n + b.count; }, 0);
    return { buckets: buckets, last_24h: total, older: older, undated: undated };
  }

  function countBy(list, keyFn, limit) {
    var m = {};
    list.forEach(function (i) { var k = keyFn(i); if (k) m[k] = (m[k] || 0) + 1; });
    return Object.keys(m).map(function (k) { return { name: k, count: m[k] }; })
      .sort(function (a, b) { return b.count - a.count || a.name.localeCompare(b.name); })
      .slice(0, limit);
  }

  function sources(list) {
    return countBy(list, function (i) { return String(i.source || i.feed_source || '').trim().slice(0, 60); }, 12);
  }

  /** ATT&CK tactics the feed items cite (object entries' tactic; technique-id strings are not tactics). */
  function tactics(list) {
    var m = {};
    var techniques = {};
    list.forEach(function (i) {
      var seen = {};
      (Array.isArray(i.mitre_tactics) ? i.mitre_tactics : []).forEach(function (t) {
        var obj = t !== null && typeof t === 'object';
        var name = String(obj ? (t.tactic || '') : (t || '')).trim().slice(0, 40);
        var tid = String(obj ? (t.id || '') : (t || '')).trim().toUpperCase();
        if (TECHNIQUE_RE.test(tid)) techniques[tid] = true;
        if (name && !TECHNIQUE_RE.test(name) && !seen[name]) { seen[name] = true; m[name] = (m[name] || 0) + 1; }
      });
    });
    var rows = Object.keys(m).map(function (k) { return { name: k, advisories: m[k] }; })
      .sort(function (a, b) { return b.advisories - a.advisories || a.name.localeCompare(b.name); });
    return { tactics: rows, techniques: Object.keys(techniques).sort() };
  }

  /** The advisory stream: newest first, fields as the feed states them. */
  function stream(list, limit) {
    return list.map(function (i, n) { return { i: i, n: n, t: publishedMs(i) }; })
      .sort(function (a, b) { return (b.t === null ? -Infinity : b.t) - (a.t === null ? -Infinity : a.t) || a.n - b.n; })
      .slice(0, limit || 40)
      .map(function (r) {
        var i = r.i;
        return {
          id: String(i.id || '').slice(0, 128) || null,
          title: String(i.title).trim().slice(0, 240),
          severity: severity(i),
          source: String(i.source || i.feed_source || '').trim().slice(0, 80) || null,
          published: r.t === null ? null : new Date(r.t).toISOString(),
          cves: cves(i).slice(0, 4),
          kev: kev(i),
          exploit: exploitEvidence(i),
          url: httpsUrl(i.source_url),
        };
      });
  }

  function model(feed, nowMs) {
    var list = items(feed);
    return {
      feed_generated_at: feed && typeof feed.generated_at === 'string' ? feed.generated_at : null,
      kpis: kpis(list),
      hourly: hourly(list, nowMs),
      sources: sources(list),
      attack: tactics(list),
      stream: stream(list, 40),
    };
  }

  var api = {
    LAST_AUTHORITATIVE_MAX_AGE_SECONDS: LAST_AUTHORITATIVE_MAX_AGE_SECONDS,
    publication: publication, model: model,
    kpis: kpis, hourly: hourly, sources: sources, tactics: tactics, stream: stream,
    publishedMs: publishedMs, kev: kev, exploitEvidence: exploitEvidence, httpsUrl: httpsUrl,
  };
  root.SocOpsModel = api;
  if (typeof module === 'object' && module.exports) module.exports = api;
}(typeof window !== 'undefined' ? window : globalThis));
